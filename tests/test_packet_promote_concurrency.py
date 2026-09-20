"""Synthetic concurrency regression for the host packet-ask promotion transaction."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import subprocess
import signal
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from adapters import packet_promote
from adapters import packet_transaction
import agentbelt as g


WHEEL_BYTES = b'synthetic concurrent packet wheel bytes'
WHEEL_SHA = hashlib.sha256(WHEEL_BYTES).hexdigest()


def fake_fetch(url):
    if url.endswith('/packet-ask/json'):
        releases = {}
        for version in ('0.13.0', '0.14.0'):
            filename = f'packet_ask-{version}-py3-none-any.whl'
            releases[version] = [{'filename': filename, 'url': 'https://files.pythonhosted.org/' + filename,
                                  'digests': {'sha256': WHEEL_SHA}}]
        return {'releases': releases}
    if '/integrity/' in url:
        return {'attestation_bundles': [{'publisher': dict(packet_promote.PINNED_PUBLISHER)}]}
    raise AssertionError('unexpected URL: ' + url)


class PromotionConcurrencyTests(unittest.TestCase):
    def test_guard_capability_allows_only_transaction_scoped_candidate_consumers(self):
        with tempfile.TemporaryDirectory(prefix='promote-capability-', dir=Path.home()) as raw:
            (Path(raw) / 'state').mkdir()
            state = Path(raw) / 'state/packet-ask-version.json'
            state.write_text(json.dumps({'version': '0.12.0'}))
            self.assertNotIn(packet_transaction.CAPABILITY_ENV, os.environ)
            with packet_transaction.promotion(state, '0.13.0') as authority:
                environment = authority.guard_environment({
                    'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                    'LANG': 'en_US.UTF-8',
                })
                code = (
                    'import sys; sys.path.insert(0, sys.argv[1]); '
                    'from adapters import packet_transaction as t; '
                    'state=sys.argv[2]; '
                    'cm=t.consumer(state); cm.__enter__(); '
                    'print(t.candidate_version(state)); cm.__exit__(None,None,None)'
                )
                result = subprocess.run([sys.executable, '-c', code, str(ROOT), str(state)],
                                        env=environment, capture_output=True, text=True, timeout=3)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, '0.13.0'), result.stderr)
                self.assertEqual(json.loads(state.read_text()), {'version': '0.12.0'})
                with patch.object(g, 'ROOT', Path(raw)), patch.dict(os.environ, environment, clear=True):
                    _, _, sandbox_environment = g.prepare_packet_request(['inspect'])
                self.assertEqual(sandbox_environment['AGENTBELT_PACKET_ASK_VERSION'], '0.13.0')
                self.assertNotIn(packet_transaction.CAPABILITY_ENV, sandbox_environment)
            self.assertNotIn(packet_transaction.CAPABILITY_ENV, os.environ)

    def test_consumer_waits_until_candidate_validation_and_publication_finish(self):
        with tempfile.TemporaryDirectory(prefix='promote-consumer-', dir=Path.home()) as raw:
            root = Path(raw)
            package = root / 'site-packages/packet_ask'
            package.mkdir(parents=True)
            for name in packet_promote.ADAPTER_FILES:
                content = '# unchanged adapter\n'
                if name == 'paths.py':
                    content += 'def set_confined_env_hooks(child=None, git=None):\n    pass\n'
                (package / name).write_text(content)
            installed = package / 'installed-version.txt'
            installed.write_text('0.12.0\n')
            state = root / 'packet-ask-version.json'
            state.write_text(json.dumps({'version': '0.12.0'}))
            validating = threading.Event()
            release_validation = threading.Event()
            consumer_entered = threading.Event()
            observed = []

            def install(version, wheel=None):
                installed.write_text(version + '\n')

            def validate():
                validating.set()
                if not release_validation.wait(5):
                    raise TimeoutError('test did not release validation')
                return True

            promotion = threading.Thread(target=lambda: packet_promote.promote(
                '0.13.0', fetch=fake_fetch, install=install, run_tests=validate,
                install_skills=lambda: None, package_dir=package, state_file=state,
                audit_file=root / 'promotions.jsonl', fetch_bytes=lambda url: WHEEL_BYTES))

            def consume():
                with packet_transaction.consumer(state):
                    consumer_entered.set()
                    observed.append((installed.read_text().strip(), json.loads(state.read_text())['version']))

            promotion.start()
            self.assertTrue(validating.wait(5), 'promotion did not reach candidate validation')
            consumer = threading.Thread(target=consume)
            consumer.start()
            self.assertFalse(consumer_entered.wait(0.25), 'consumer entered while the candidate was unapproved')
            release_validation.set()
            promotion.join(10)
            consumer.join(10)
            self.assertFalse(promotion.is_alive() or consumer.is_alive())
            self.assertEqual(observed, [('0.13.0', '0.13.0')])

    def test_successful_promotions_leave_the_install_and_pin_in_sync(self):
        with tempfile.TemporaryDirectory(prefix='promote-race-', dir=Path.home()) as raw:
            root = Path(raw)
            package = root / 'site-packages/packet_ask'
            package.mkdir(parents=True)
            for name in packet_promote.ADAPTER_FILES:
                content = '# unchanged adapter\n'
                if name == 'paths.py':
                    content += 'def set_confined_env_hooks(child=None, git=None):\n    pass\n'
                (package / name).write_text(content)
            (package / 'installed-version.txt').write_text('0.12.0\n')
            state = root / 'packet-ask-version.json'
            state.write_text(json.dumps({'version': '0.12.0'}))
            audit = root / 'promotions.jsonl'

            a_installed = threading.Event()
            release_a = threading.Event()
            b_pinned = threading.Event()
            a_done = threading.Event()
            outcomes = {}

            def install_a(version, wheel=None):
                self.assertEqual((version, wheel is not None), ('0.13.0', True))
                (package / 'installed-version.txt').write_text(version + '\n')
                a_installed.set()
                if not release_a.wait(5):
                    raise TimeoutError('test did not release promotion A')

            def install_b(version, wheel=None):
                self.assertEqual((version, wheel is not None), ('0.14.0', True))
                (package / 'installed-version.txt').write_text(version + '\n')

            def tests_a():
                return True

            def tests_b():
                b_pinned.set()
                if not a_done.wait(5):
                    raise TimeoutError('promotion A did not finish')
                return True

            def run(label, version, install, tests, finished=None):
                try:
                    outcomes[label] = ('success', packet_promote.promote(
                        version, fetch=fake_fetch, install=install, run_tests=tests,
                        install_skills=lambda: None, package_dir=package, state_file=state,
                        audit_file=audit, fetch_bytes=lambda url: WHEEL_BYTES))
                except BaseException as error:
                    outcomes[label] = ('error', type(error).__name__, str(error))
                finally:
                    if finished is not None:
                        finished.set()

            thread_a = threading.Thread(target=run, args=('A', '0.13.0', install_a, tests_a, a_done))
            thread_a.start()
            self.assertTrue(a_installed.wait(5), 'promotion A did not install')
            thread_b = threading.Thread(target=run, args=('B', '0.14.0', install_b, tests_b))
            thread_b.start()

            # On the vulnerable implementation B pins while A is paused. With
            # the transaction lock B waits before fetching or installing.
            b_pinned.wait(1)
            release_a.set()
            thread_a.join(10)
            thread_b.join(10)
            self.assertFalse(thread_a.is_alive() or thread_b.is_alive())
            self.assertEqual(outcomes['A'][0], 'success', outcomes)
            self.assertEqual(outcomes['B'][0], 'success', outcomes)
            installed = (package / 'installed-version.txt').read_text().strip()
            pinned = json.loads(state.read_text())['version']
            self.assertEqual((installed, pinned), ('0.14.0', '0.14.0'))


class PromotionProcessTests(unittest.TestCase):
    def test_timeout_kills_descendant_after_process_group_leader_exits(self):
        with tempfile.TemporaryDirectory(prefix='promote-process-group-', dir=Path.home()) as raw:
            pid_file = Path(raw) / 'child.pid'
            child_code = 'import time; time.sleep(30)'
            leader_code = (
                'import pathlib, subprocess, sys; '
                'child=subprocess.Popen([sys.executable,"-c",sys.argv[2]]); '
                'pathlib.Path(sys.argv[1]).write_text(str(child.pid))'
            )
            child_pid = None
            try:
                with self.assertRaises(g.GuardError):
                    packet_promote._run_owned(
                        [sys.executable, '-c', leader_code, str(pid_file), child_code], timeout=0.2)
                child_pid = int(pid_file.read_text())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    status = subprocess.run(['/bin/ps', '-p', str(child_pid), '-o', 'stat='],
                                            capture_output=True, text=True).stdout.strip()
                    if not status or status.startswith('Z'):
                        break
                    time.sleep(0.02)
                self.assertTrue(not status or status.startswith('Z'), 'promotion descendant survived timeout cleanup')
            finally:
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
