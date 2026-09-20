"""Regression for the path where the supervisor promotes packet-ask at the sandboxed agent's request."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import signal
import subprocess
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g
from adapters import packet_promote
from adapters import packet_relay

GOOD_PUBLISHER = {'kind': 'GitHub', 'repository': 'ictechgy/packet-ask', 'workflow': 'release.yml'}
import hashlib
WHEEL_BYTES = b'synthetic wheel bytes'
WHEEL_SHA = hashlib.sha256(WHEEL_BYTES).hexdigest()


def fake_fetch_factory(version, publisher=GOOD_PUBLISHER, files=('whl', 'tar')):
    """Imitate the PyPI JSON and integrity responses."""
    def fetch(url):
        if url.endswith('/packet-ask/json'):
            return {'info': {'version': version}, 'releases': {version: [
                {'filename': f'packet_ask-{version}-py3-none-any.whl', 'url': 'https://files.pythonhosted.org/w.whl', 'digests': {'sha256': WHEEL_SHA}},
                {'filename': f'packet_ask-{version}.tar.gz', 'url': 'https://files.pythonhosted.org/s.tar.gz', 'digests': {'sha256': 'b' * 64}}]}}
        if '/integrity/' in url:
            return {'attestation_bundles': [{'publisher': publisher, 'attestations': [{}]}]}
        raise AssertionError('unexpected url ' + url)
    return fetch


class ReleaseCheckTests(unittest.TestCase):
    def test_accepts_newer_version_from_the_pinned_publisher(self):
        info = packet_promote.check_release('0.13.0', current='0.12.0', fetch=fake_fetch_factory('0.13.0'))
        self.assertEqual(info['files'], ['packet_ask-0.13.0-py3-none-any.whl', 'packet_ask-0.13.0.tar.gz'])

    def test_refuses_other_publishers_and_non_newer_versions(self):
        with self.assertRaises(g.GuardError):
            packet_promote.check_release('0.13.0', current='0.12.0',
                                         fetch=fake_fetch_factory('0.13.0', publisher=dict(GOOD_PUBLISHER, repository='someone/packet-ask')))
        with self.assertRaises(g.GuardError):
            packet_promote.check_release('0.12.0', current='0.12.0', fetch=fake_fetch_factory('0.12.0'))
        with self.assertRaises(g.GuardError):
            packet_promote.check_release('0.11.0', current='0.12.0', fetch=fake_fetch_factory('0.11.0'))
        with self.assertRaises(g.GuardError):
            packet_promote.check_release('0.13.0', current='0.12.0', fetch=fake_fetch_factory('0.14.0'))  # not on PyPI
        with self.assertRaises(g.GuardError):
            packet_promote.check_release('0.13.0; rm -rf', current='0.12.0', fetch=fake_fetch_factory('0.13.0'))


class PromoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='promote-', dir=Path.home())
        base = Path(self.tmp.name)
        self.package = base / 'site-packages/packet_ask'
        self.package.mkdir(parents=True)
        for name in packet_promote.ADAPTER_FILES:
            (self.package / name).write_text('# adapter ' + name + '\n')
        (self.package / 'paths.py').write_text('def set_confined_env_hooks(child=None, git=None):\n    pass\n')
        (self.package / 'version_info.py').write_text('# cli v0.12.0\n')
        self.state = base / 'packet-ask-version.json'
        self.state.write_text(json.dumps({'version': '0.12.0'}))
        self.installed = ['0.12.0']
        self.tests_run = 0
        self.skills_run = 0
        self.tests_ok = True
        self.mutate = None

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, version, wheel=None):
        self.installed.append(version)
        (self.package / 'version_info.py').write_text('# cli v' + version + '\n')
        if version == '0.12.0':
            for name in packet_promote.ADAPTER_FILES:
                (self.package / name).write_text('# adapter ' + name + '\n')
            (self.package / 'paths.py').write_text('def set_confined_env_hooks(child=None, git=None):\n    pass\n')
        if self.mutate and version != '0.12.0':
            self.mutate(self.package)

    def run_tests(self):
        self.tests_run += 1
        return self.tests_ok

    def install_skills(self):
        self.skills_run += 1

    def promote(self, version='0.13.0'):
        return packet_promote.promote(version, fetch=fake_fetch_factory(version), install=self.install,
                                      run_tests=self.run_tests, install_skills=self.install_skills,
                                      package_dir=self.package, state_file=self.state,
                                      audit_file=Path(self.tmp.name) / 'audit.jsonl', fetch_bytes=lambda url: WHEEL_BYTES)

    def test_happy_path_installs_pins_tests_and_reinstalls_skills(self):
        report = self.promote()
        self.assertEqual(json.loads(self.state.read_text())['version'], '0.13.0')
        self.assertEqual(self.installed[-1], '0.13.0')
        self.assertEqual(self.tests_run, 1)
        self.assertEqual(self.skills_run, 1)
        self.assertIn('0.13.0', report)
        audit = (Path(self.tmp.name) / 'audit.jsonl').read_text()
        self.assertIn('"0.13.0"', audit)

    def test_adapter_change_rolls_back_and_refuses(self):
        self.mutate = lambda pkg: (pkg / 'launch.py').write_text('# changed\n')
        with self.assertRaises(g.GuardError) as caught:
            self.promote()
        self.assertIn('launch.py', str(caught.exception))
        self.assertEqual(self.installed[-1], '0.12.0')  # rolled back
        self.assertEqual(json.loads(self.state.read_text())['version'], '0.12.0')
        self.assertEqual(self.tests_run, 0)
        self.assertEqual(self.skills_run, 0)

    def test_missing_hook_surface_counts_as_adapter_change(self):
        self.mutate = lambda pkg: (pkg / 'paths.py').write_text('# hook gone\n')
        with self.assertRaises(g.GuardError):
            self.promote()
        self.assertEqual(self.installed[-1], '0.12.0')

    def test_export_redaction_and_host_credential_code_changes_require_review(self):
        for name in ('cli.py', 'redact.py', 'receipt.py', 'keysource.py'):
            with self.subTest(name=name):
                self.mutate = lambda package, name=name: (package / name).write_text('# changed privacy boundary\n')
                with self.assertRaises(g.GuardError):
                    self.promote()
                self.assertEqual(json.loads(self.state.read_text())['version'], '0.12.0')
                self.assertEqual(self.tests_run, 0)
                self.assertEqual(self.skills_run, 0)

    def test_failing_guard_suite_rolls_back_the_pin(self):
        self.tests_ok = False
        with self.assertRaises(g.GuardError):
            self.promote()
        self.assertEqual(self.installed[-1], '0.12.0')
        self.assertEqual(json.loads(self.state.read_text())['version'], '0.12.0')
        self.assertEqual(self.skills_run, 0)

    def test_partial_install_failure_rolls_back_the_install_and_pin(self):
        def partial_install(version, wheel=None):
            self.installed.append(version)
            (self.package / 'version_info.py').write_text('# cli v' + version + '\n')
            if version == '0.13.0':
                raise RuntimeError('synthetic installer failed after changing files')

        with self.assertRaises(g.GuardError) as caught:
            packet_promote.promote('0.13.0', fetch=fake_fetch_factory('0.13.0'), install=partial_install,
                                   run_tests=self.run_tests, install_skills=self.install_skills,
                                   package_dir=self.package, state_file=self.state,
                                   audit_file=Path(self.tmp.name) / 'audit.jsonl', fetch_bytes=lambda url: WHEEL_BYTES)
        self.assertIn('reinstalled 0.12.0', str(caught.exception))
        self.assertEqual(self.installed[-1], '0.12.0')
        self.assertEqual(json.loads(self.state.read_text())['version'], '0.12.0')
        self.assertEqual((self.package / 'version_info.py').read_text(), '# cli v0.12.0\n')
        self.assertIn('rolled-back-RuntimeError', (Path(self.tmp.name) / 'audit.jsonl').read_text())

    def test_failed_rollback_is_reported_and_audited(self):
        calls = []

        def install(version, wheel=None):
            calls.append(version)
            (self.package / 'version_info.py').write_text('# cli v' + version + '\n')
            if version == '0.12.0':
                raise RuntimeError('synthetic rollback failure')

        self.tests_ok = False
        audit = Path(self.tmp.name) / 'audit.jsonl'
        with self.assertRaises(g.GuardError) as caught:
            packet_promote.promote('0.13.0', fetch=fake_fetch_factory('0.13.0'), install=install,
                                   run_tests=self.run_tests, install_skills=self.install_skills,
                                   package_dir=self.package, state_file=self.state,
                                   audit_file=audit, fetch_bytes=lambda url: WHEEL_BYTES)
        self.assertIn('rollback failed: install rollback failed: RuntimeError', str(caught.exception))
        self.assertEqual(calls, ['0.13.0', '0.12.0'])
        self.assertNotIn('version', json.loads(self.state.read_text()))
        record = json.loads(audit.read_text())
        self.assertEqual(record['outcome'], 'rollback-failed-GuardError')
        self.assertEqual(record['details'], ['install rollback failed: RuntimeError'])

    def test_stale_old_metadata_does_not_republish_pin_when_modules_were_not_restored(self):
        phase = {'version': '0.12.0'}

        def install(version, wheel=None):
            phase['version'] = version
            if version == '0.13.0':
                (self.package / 'version_info.py').write_text('# candidate modules remain\n')
            # The synthetic rollback reports success and resets metadata, but leaves
            # the candidate module tree in place.

        self.tests_ok = False
        with self.assertRaises(g.GuardError) as caught:
            packet_promote.promote('0.13.0', fetch=fake_fetch_factory('0.13.0'), install=install,
                                   run_tests=self.run_tests, install_skills=self.install_skills,
                                   package_dir=self.package, state_file=self.state,
                                   audit_file=Path(self.tmp.name) / 'audit.jsonl',
                                   fetch_bytes=lambda url: WHEEL_BYTES,
                                   installed_version=lambda: phase['version'])
        self.assertIn('installed files do not match the pre-promotion snapshot', str(caught.exception))
        self.assertNotIn('version', json.loads(self.state.read_text()))

    def test_pin_write_does_not_unlink_a_stale_temporary_file(self):
        stale = self.state.with_name(self.state.name + '.tmp')
        stale.write_text('stale transaction marker')
        packet_promote.write_pin(self.state, '0.13.0')
        self.assertEqual(stale.read_text(), 'stale transaction marker')
        self.assertEqual(json.loads(self.state.read_text())['version'], '0.13.0')


class RelayIntegrationTests(unittest.TestCase):
    SUPERVISOR_SCRIPT = r'''
import hashlib
import json
from pathlib import Path
import sys
import time

repo, root = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(repo))
from adapters import packet_promote, packet_relay
import agentbelt

wheel_bytes = b'synthetic signal promotion wheel'
wheel_sha = hashlib.sha256(wheel_bytes).hexdigest()
work = root / 'work'; work.mkdir()
home = root / 'home'; home.mkdir()
package = root / 'site-packages/packet_ask'; package.mkdir(parents=True)
for name in packet_promote.ADAPTER_FILES:
    content = '# unchanged adapter\n'
    if name == 'paths.py':
        content += 'def set_confined_env_hooks(child=None, git=None):\n    pass\n'
    (package / name).write_text(content)
(package / 'installed-version.txt').write_text('0.12.0\n')
state = root / 'packet-ask-version.json'
state.write_text(json.dumps({'version': '0.12.0'}))

def fetch(url):
    if url.endswith('/packet-ask/json'):
        name = 'packet_ask-0.13.0-py3-none-any.whl'
        return {'releases': {'0.13.0': [{'filename': name,
                'url': 'https://files.pythonhosted.org/' + name,
                'digests': {'sha256': wheel_sha}}]}}
    if '/integrity/' in url:
        return {'attestation_bundles': [{'publisher': dict(packet_promote.PINNED_PUBLISHER)}]}
    raise AssertionError(url)

def install(version, wheel=None):
    (package / 'installed-version.txt').write_text(version + '\n')
    if version == '0.13.0':
        (root / 'install-started').write_text('started\n')
        while not (root / 'release-install').exists():
            time.sleep(0.02)

def runner(provider, prepared, workspace):
    try:
        report = packet_promote.promote(
            prepared['version'], fetch=fetch, install=install, run_tests=lambda: True,
            install_skills=lambda: None, package_dir=package, state_file=state,
            audit_file=root / 'audit.jsonl', fetch_bytes=lambda url: wheel_bytes)
        return 0, report, ''
    except agentbelt.GuardError as problem:
        return 1, '', str(problem)

relay = packet_relay.PacketRelay(work, home, runner=runner, settings={'pollSeconds': 0.01})
relay.prepare(home, {'PATH': ''})
(relay.requests / 'promotion.json').write_text(json.dumps({'promote': '0.13.0'}))
with relay:
    while True:
        time.sleep(1)
'''

    def start_signal_supervisor(self, root):
        return subprocess.Popen(
            [sys.executable, '-c', self.SUPERVISOR_SCRIPT, str(ROOT), str(root)],
            env={'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait_for_path(self, path, process, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if path.exists():
                return
            if process.poll() is not None:
                out, err = process.communicate()
                self.fail('supervisor exited early: ' + out[-500:] + err[-1000:])
            time.sleep(0.02)
        self.fail('timed out waiting for ' + str(path))

    def test_sigterm_waits_for_active_promotion_then_exits(self):
        with tempfile.TemporaryDirectory(prefix='promote-sigterm-', dir=Path.home()) as tmp:
            root = Path(tmp)
            process = self.start_signal_supervisor(root)
            try:
                self.wait_for_path(root / 'install-started', process)
                self.assertNotIn('version', json.loads((root / 'packet-ask-version.json').read_text()))
                process.send_signal(signal.SIGTERM)
                time.sleep(0.3)
                self.assertIsNone(process.poll(), 'SIGTERM bypassed relay transaction cleanup')
                (root / 'release-install').write_text('release\n')
                process.wait(timeout=5)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                self.assertEqual(json.loads((root / 'packet-ask-version.json').read_text()), {'version': '0.13.0'})
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_sigterm_during_existing_cleanup_cannot_abandon_promotion(self):
        with tempfile.TemporaryDirectory(prefix='promote-closing-', dir=Path.home()) as tmp:
            root = Path(tmp)
            script = self.SUPERVISOR_SCRIPT.replace(
                'with relay:\n    while True:\n        time.sleep(1)',
                "with relay:\n    while not (root / 'install-started').exists():\n        time.sleep(0.01)\n"
                "    (root / 'closing').write_text('closing')")
            process = subprocess.Popen([sys.executable, '-c', script, str(ROOT), str(root)],
                                       env={'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'},
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.wait_for_path(root / 'closing', process)
                time.sleep(0.2)
                process.send_signal(signal.SIGTERM)
                time.sleep(0.2)
                self.assertIsNone(process.poll(), 'termination interrupted an existing cleanup wait')
                (root / 'release-install').write_text('release')
                process.wait(timeout=5)
                self.assertEqual(json.loads((root / 'packet-ask-version.json').read_text()), {'version': '0.13.0'})
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_forced_kill_leaves_the_pin_invalid_during_mutation(self):
        with tempfile.TemporaryDirectory(prefix='promote-sigkill-', dir=Path.home()) as tmp:
            root = Path(tmp)
            process = self.start_signal_supervisor(root)
            try:
                self.wait_for_path(root / 'install-started', process)
                process.kill()
                process.wait(timeout=5)
                self.assertLess(process.returncode, 0)
                self.assertNotIn('version', json.loads((root / 'packet-ask-version.json').read_text()))
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_relay_restores_the_previous_sigterm_handler(self):
        with tempfile.TemporaryDirectory(prefix='relay-signal-handler-', dir=Path.home()) as tmp:
            root = Path(tmp)
            previous = signal.getsignal(signal.SIGTERM)
            sentinel = lambda signum, frame: None
            signal.signal(signal.SIGTERM, sentinel)
            try:
                relay = packet_relay.PacketRelay(root, root, runner=lambda *args: (0, '', ''),
                                                 settings={'pollSeconds': 0.01})
                with relay:
                    self.assertIsNot(signal.getsignal(signal.SIGTERM), sentinel)
                self.assertIs(signal.getsignal(signal.SIGTERM), sentinel)
            finally:
                signal.signal(signal.SIGTERM, previous)

    def test_promote_request_flows_through_the_relay(self):
        with tempfile.TemporaryDirectory(prefix='promote-relay-', dir=Path.home()) as tmp:
            work = Path(tmp) / 'work'; work.mkdir()
            home = Path(tmp) / 'home'; home.mkdir()
            seen = []

            def fake_runner(provider, prepared, workspace):
                seen.append((provider, prepared))
                return 0, 'PROMOTED ' + prepared['version'], ''
            relay = packet_relay.PacketRelay(work, home, runner=fake_runner, settings={'pollSeconds': 0.05})
            with relay:
                relay.prepare(home, {'PATH': ''})
                self.assertTrue((home / 'bin/packet-promote').is_file())
                requests = home / 'tmp/packet-requests'
                (requests / 'p1.json').write_text(json.dumps({'promote': '0.13.0'}))
                (requests / 'p2.json').write_text(json.dumps({'promote': '0.13.0; rm -rf /'}))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not ((requests / 'p1.result.md').exists() and (requests / 'p2.error.txt').exists()):
                    time.sleep(0.05)
                self.assertEqual((requests / 'p1.result.md').read_text(), 'PROMOTED 0.13.0')
                self.assertIn('version', (requests / 'p2.error.txt').read_text())
            self.assertEqual(seen[0][0], 'promote')
            self.assertIn('bin/packet-promote', relay.read_only_home_paths())
            self.assertIn('packet-promote', relay.notice())

    def test_shutdown_waits_for_an_active_promotion_transaction(self):
        with tempfile.TemporaryDirectory(prefix='promote-shutdown-', dir=Path.home()) as tmp:
            root = Path(tmp)
            work = root / 'work'; work.mkdir()
            home = root / 'home'; home.mkdir()
            package = root / 'site-packages/packet_ask'; package.mkdir(parents=True)
            for name in packet_promote.ADAPTER_FILES:
                content = '# unchanged adapter\n'
                if name == 'paths.py':
                    content += 'def set_confined_env_hooks(child=None, git=None):\n    pass\n'
                (package / name).write_text(content)
            state = root / 'packet-ask-version.json'
            state.write_text(json.dumps({'version': '0.12.0'}))
            install_started = threading.Event()
            release_install = threading.Event()
            session_started = threading.Event()
            end_session = threading.Event()
            shutdown_done = threading.Event()

            def install(version, wheel=None):
                if version == '0.13.0':
                    install_started.set()
                    if not release_install.wait(10):
                        raise TimeoutError('test did not release install')

            def runner(provider, prepared, workspace):
                try:
                    report = packet_promote.promote(
                        prepared['version'], fetch=fake_fetch_factory(prepared['version']), install=install,
                        run_tests=lambda: True, install_skills=lambda: None, package_dir=package,
                        state_file=state, audit_file=root / 'audit.jsonl', fetch_bytes=lambda url: WHEEL_BYTES)
                    return 0, report, ''
                except g.GuardError as problem:
                    return 1, '', str(problem)

            relay = packet_relay.PacketRelay(work, home, runner=runner, settings={'pollSeconds': 0.01})
            relay.prepare(home, {'PATH': ''})
            def run_session():
                with relay:
                    session_started.set()
                    end_session.wait()
                shutdown_done.set()
            shutdown = threading.Thread(target=run_session)
            shutdown.start()
            try:
                self.assertTrue(session_started.wait(2))
                (relay.requests / 'promotion.json').write_text(json.dumps({'promote': '0.13.0'}))
                self.assertTrue(install_started.wait(5), 'promotion install did not start')
                end_session.set()
                self.assertFalse(shutdown_done.wait(5.25), 'relay returned while its promotion was still mutating the venv')
                release_install.set()
                shutdown.join(5)
                self.assertFalse(shutdown.is_alive())
                self.assertEqual(json.loads(state.read_text())['version'], '0.13.0')
            finally:
                release_install.set()
                end_session.set()
                relay.stop.set()
                relay.thread.join(5)
                shutdown.join(5)


if __name__ == '__main__':
    unittest.main()
