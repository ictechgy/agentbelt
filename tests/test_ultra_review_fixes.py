"""Regression for 2 CRITICAL and 7 HIGH findings from the 2026-09-10 four-track review. Allowing pub.dev hard-link writes is deferred (by design)."""
import base64
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g
from adapters import packet_relay
from adapters import packet_promote


class SafeWriteTests(unittest.TestCase):
    """When the supervisor writes into a child-owned tree it must not follow links."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='safewrite-', dir=Path.home())
        self.base = Path(self.tmp.name)
        self.home = self.base / 'home'; self.home.mkdir(mode=0o700)
        self.outside = self.base / 'victim.txt'; self.outside.write_text('KEEP')
        self.outside_dir = self.base / 'victim-dir'; self.outside_dir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_a_private_file_and_creates_intermediate_directories(self):
        g.write_private_file(self.home, '.zcode/AGENTS.md', 'hello')
        target = self.home / '.zcode/AGENTS.md'
        self.assertEqual(target.read_text(), 'hello')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.home / '.zcode').stat().st_mode), 0o700)

    def test_final_symlink_is_replaced_not_followed(self):
        os.symlink(str(self.outside), str(self.home / 'AGENTBELT_ENVIRONMENT.md'))
        g.write_private_file(self.home, 'AGENTBELT_ENVIRONMENT.md', 'notice')
        self.assertEqual(self.outside.read_text(), 'KEEP')
        self.assertFalse((self.home / 'AGENTBELT_ENVIRONMENT.md').is_symlink())
        self.assertEqual((self.home / 'AGENTBELT_ENVIRONMENT.md').read_text(), 'notice')

    def test_intermediate_symlink_is_refused(self):
        os.symlink(str(self.outside_dir), str(self.home / '.zcode'))
        with self.assertRaises(g.GuardError):
            g.write_private_file(self.home, '.zcode/AGENTS.md', 'notice')
        self.assertEqual(list(self.outside_dir.iterdir()), [])

    def test_relative_path_cannot_escape(self):
        for bad in ['../x', '/etc/x', '.zcode/../../x']:
            with self.assertRaises(g.GuardError):
                g.write_private_file(self.home, bad, 'x')

    def test_clean_environment_does_not_follow_planted_links(self):
        os.symlink(str(self.outside), str(self.home / '.git-credentials'))
        os.symlink(str(self.outside_dir / 'npmrc-victim'), str(self.home / '.npmrc'))
        env = g.clean_environment(self.home, 'SYNTHETIC_GITHUB_TOKEN_0123456789')
        self.assertEqual(self.outside.read_text(), 'KEEP')
        self.assertFalse((self.outside_dir / 'npmrc-victim').exists())
        self.assertFalse((self.home / '.git-credentials').is_symlink())
        self.assertIn('SYNTHETIC_GITHUB_TOKEN', (self.home / '.git-credentials').read_text())
        self.assertNotIn('GH_TOKEN', env)

    def test_gh_config_is_neither_written_nor_removed_through_planted_links(self):
        # A planted ~/.config link must not carry the token out, nor let cleanup delete a host file.
        victim = self.outside_dir / 'gh'
        victim.mkdir()
        (victim / 'hosts.yml').write_text('KEEP')
        os.symlink(str(self.outside_dir), str(self.home / '.config'))
        with self.assertRaises(g.GuardError):
            g.clean_environment(self.home, 'SYNTHETIC_GITHUB_TOKEN_0123456789')
        self.assertEqual((victim / 'hosts.yml').read_text(), 'KEEP')
        with self.assertRaises(g.GuardError):
            g.clean_environment(self.home, None)
        self.assertEqual((victim / 'hosts.yml').read_text(), 'KEEP')

    def test_relay_result_write_does_not_follow_planted_tmp_link(self):
        relay = packet_relay.PacketRelay(self.base, self.home, runner=lambda *a: (0, 'REVIEW', ''))
        relay.prepare(self.home, {'PATH': ''})
        requests = self.home / 'tmp/packet-requests'
        os.symlink(str(self.outside), str(requests / 'r1.result.md.tmp'))  # A link planted by the child.
        relay._write(requests / 'r1.result.md', 'REVIEW')
        self.assertEqual(self.outside.read_text(), 'KEEP')
        self.assertEqual((requests / 'r1.result.md').read_text(), 'REVIEW')

    def test_relay_helper_seeding_does_not_chmod_a_planted_link(self):
        (self.home / 'bin').mkdir(mode=0o700)
        self.outside.chmod(0o644)
        os.symlink(str(self.outside), str(self.home / 'bin/packet-review'))
        relay = packet_relay.PacketRelay(self.base, self.home, runner=lambda *a: (0, '', ''))
        relay.prepare(self.home, {'PATH': ''})
        self.assertEqual(stat.S_IMODE(self.outside.stat().st_mode), 0o644)
        self.assertEqual(self.outside.read_text(), 'KEEP')
        self.assertFalse((self.home / 'bin/packet-review').is_symlink())


class RequestHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='reqhard-', dir=Path.home())
        self.base = Path(self.tmp.name)
        self.work = self.base / 'work'; self.work.mkdir(); (self.work / 'a.py').write_text('x')
        (self.work / '--diff').write_text('x')
        self.home = self.base / 'home'; self.home.mkdir(mode=0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dash_prefixed_file_names_are_rejected(self):
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'files': ['--diff'], 'question': 'q'}, self.work, {})
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'files': ['a.py', '-x'], 'question': 'q'}, self.work, {})

    def wait_for(self, path, seconds=6):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if path.exists():
                return path.read_text()
            time.sleep(0.05)
        self.fail('no file ' + str(path))

    def test_watcher_survives_fifo_symlink_and_oversized_requests(self):
        relay = packet_relay.PacketRelay(self.work, self.home, runner=lambda p, r, w: (0, 'OK', ''),
                                         settings={'pollSeconds': 0.05})
        with relay:
            relay.prepare(self.home, {'PATH': ''})
            requests = self.home / 'tmp/packet-requests'
            os.mkfifo(str(requests / 'fifo.json'))
            os.symlink(str(self.base / 'secret.json'), str(requests / 'link.json'))
            (self.base / 'secret.json').write_text('{"files": ["a.py"], "question": "q"}')
            (requests / 'big.json').write_text('{"files": ["a.py"], "question": "' + 'x' * (70 * 1024) + '"}')
            (requests / 'ok.json').write_text(json.dumps({'files': ['a.py'], 'question': 'q'}))
            self.assertIn('regular file', self.wait_for(requests / 'fifo.error.txt'))
            self.assertIn('regular file', self.wait_for(requests / 'link.error.txt'))
            self.assertIn('too large', self.wait_for(requests / 'big.error.txt'))
            self.assertEqual(self.wait_for(requests / 'ok.result.md'), 'OK')


class RiskgateGateTests(unittest.TestCase):
    def test_zcode_shell_fails_closed_for_unexpected_verdicts(self):
        import riskgate_bridge
        with tempfile.TemporaryDirectory(prefix='riskgate-', dir=Path.home()) as tmp:
            encoded = base64.b64encode(b'git status').decode()
            calls = []
            with patch.object(g, 'run_confined', lambda *a, **k: calls.append(a) or 0), \
                 patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}):
                for verdict in [None, 'error', 'DENY', {'verdict': 'allow'}]:
                    with patch.object(riskgate_bridge, 'riskgate_decision', lambda payload, v=verdict: v):
                        with self.assertRaises(g.GuardError, msg=repr(verdict)):
                            g.main(['zcode-shell', tmp, encoded])
                self.assertEqual(calls, [])
                for verdict in ['allow', 'ask']:
                    with patch.object(riskgate_bridge, 'riskgate_decision', lambda payload, v=verdict: v):
                        self.assertEqual(g.main(['zcode-shell', tmp, encoded]), 0)
                self.assertEqual(len(calls), 2)


class ZcodeIntegrityTests(unittest.TestCase):
    def test_missing_compatibility_manifest_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='compat-', dir=Path.home()) as tmp:
            with patch.object(g, 'compatibility_manifest', lambda: Path(tmp) / 'absent.json'):
                with self.assertRaises(g.GuardError):
                    g.verify_zcode_binary()
            without_zcode = Path(tmp) / 'no-zcode.json'; without_zcode.write_text(json.dumps({'opencode': {}}))
            with patch.object(g, 'compatibility_manifest', lambda: without_zcode):
                with self.assertRaises(g.GuardError):
                    g.verify_zcode_binary()


GOOD_PUBLISHER = {'kind': 'GitHub', 'repository': 'ictechgy/packet-ask', 'workflow': 'release.yml'}


def fake_fetch(version, digest='a' * 64):
    def fetch(url):
        if url.endswith('/packet-ask/json'):
            return {'info': {'version': version}, 'releases': {version: [
                {'filename': f'packet_ask-{version}-py3-none-any.whl', 'url': 'https://files.pythonhosted.org/x.whl', 'digests': {'sha256': digest}},
                {'filename': f'packet_ask-{version}.tar.gz', 'url': 'https://files.pythonhosted.org/x.tar.gz', 'digests': {'sha256': 'b' * 64}}]}}
        if '/integrity/' in url:
            return {'attestation_bundles': [{'publisher': GOOD_PUBLISHER, 'attestations': [{}]}]}
        raise AssertionError(url)
    return fetch


class PromoteTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='promote2-', dir=Path.home())
        base = Path(self.tmp.name)
        self.package = base / 'site-packages/packet_ask'; self.package.mkdir(parents=True)
        for name in packet_promote.ADAPTER_FILES:
            (self.package / name).write_text('# adapter\n')
        (self.package / 'paths.py').write_text('def set_confined_env_hooks(child=None, git=None):\n    pass\n')
        self.state = base / 'packet-ask-version.json'; self.state.write_text(json.dumps({'version': '0.12.0'}))
        self.installed = []
        self.wheel_bytes = b'synthetic wheel'
        import hashlib
        self.digest = hashlib.sha256(self.wheel_bytes).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def promote(self, run_tests=lambda: True, install_skills=lambda: None, digest=None, fetch_bytes=None):
        install = lambda version, wheel=None: self.installed.append((version, wheel))
        return packet_promote.promote('0.13.0', fetch=fake_fetch('0.13.0', digest or self.digest), install=install,
                                      run_tests=run_tests, install_skills=install_skills, package_dir=self.package,
                                      state_file=self.state, audit_file=Path(self.tmp.name) / 'audit.jsonl',
                                      fetch_bytes=fetch_bytes or (lambda url: self.wheel_bytes))

    def pinned(self):
        return json.loads(self.state.read_text())['version']

    def test_installs_only_a_wheel_whose_hash_matches_the_verified_catalog(self):
        report = self.promote()
        self.assertEqual(self.pinned(), '0.13.0')
        version, wheel = self.installed[-1]
        self.assertEqual(version, '0.13.0')
        self.assertTrue(str(wheel).endswith('.whl'))
        with self.assertRaises(g.GuardError):
            self.promote(digest='f' * 64)
        self.assertNotEqual(self.installed[-1][0], '0.13.0') if len(self.installed) > 1 else None

    def test_exception_in_tests_rolls_back_install_and_pin(self):
        def boom():
            raise RuntimeError('synthetic test crash')
        with self.assertRaises(g.GuardError):
            self.promote(run_tests=boom)
        self.assertEqual(self.pinned(), '0.12.0')
        self.assertEqual(self.installed[-1][0], '0.12.0')

    def test_failing_skill_install_rolls_back(self):
        def boom():
            raise g.GuardError('skills failed')
        with self.assertRaises(g.GuardError):
            self.promote(install_skills=boom)
        self.assertEqual(self.pinned(), '0.12.0')
        self.assertEqual(self.installed[-1][0], '0.12.0')

    def test_pin_is_written_without_a_missing_file_window(self):
        seen = []
        original = os.replace
        def spy(src, dst):
            seen.append(Path(dst).exists()); original(src, dst)
        with patch.object(packet_promote.os, 'replace', spy):
            self.promote()
        self.assertTrue(seen and all(seen))
        self.assertEqual(self.pinned(), '0.13.0')


class LockedAncestorTests(unittest.TestCase):
    def test_policy_locks_ancestors_of_locked_files_and_sandbox_cannot_rename_them(self):
        with tempfile.TemporaryDirectory(prefix='lockanc-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'p.sh').write_text(
                'mv "$HOME/.zcode" "$HOME/.zcode2" 2>/dev/null && echo PARENT_RENAMED || echo PARENT_LOCKED\n'
                'mkdir "$HOME/.zcode/scratch" 2>/dev/null && echo CHILD_MKDIR_OK || echo CHILD_MKDIR_BLOCKED\n'
                'mv "$HOME/AGENTBELT_ENVIRONMENT.md" "$HOME/x.md" 2>/dev/null && echo NOTICE_RENAMED || echo NOTICE_LOCKED\n'
                'echo hi > "$HOME/.zcode/scratch/free.txt" && echo FREE_WRITE_OK\n')
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')], ephemeral=True,
                                        instruction_files=['.zcode/AGENTS.md'], stdout=out)
                out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('PARENT_LOCKED', text)
        self.assertIn('CHILD_MKDIR_OK', text)
        self.assertIn('NOTICE_LOCKED', text)
        self.assertIn('FREE_WRITE_OK', text)


class RunnerZcodeConfigTests(unittest.TestCase):
    def test_runner_refuses_a_planted_symlink_parent_for_the_zcode_config(self):
        with tempfile.TemporaryDirectory(prefix='runnerlink-', dir=Path.home()) as tmp:
            outside = Path(tmp) / 'victim'; outside.mkdir()
            def prepare(home, env):
                os.symlink(str(outside), str(home / '.zcode'))
                env.update({'AGENTBELT_BOOTSTRAP': 'zcode'})
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', Path(tmp), ['/bin/echo', 'RAN'], ephemeral=True, prepare_home=prepare,
                                        extra_reads=[ROOT / 'state/zcode-agent-config.json'], stdout=out)
                out.seek(0); text = out.read().decode(errors='replace')
            self.assertNotEqual(status, 0)
            self.assertNotIn('RAN', text)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
