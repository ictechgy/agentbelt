"""Regression for the path where the supervisor promotes packet-ask at the sandboxed agent's request."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g
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
        (self.package / 'cli.py').write_text('# cli v0.12.0\n')
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
        (self.package / 'cli.py').write_text('# cli v' + version + '\n')
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

    def test_failing_guard_suite_rolls_back_the_pin(self):
        self.tests_ok = False
        with self.assertRaises(g.GuardError):
            self.promote()
        self.assertEqual(self.installed[-1], '0.12.0')
        self.assertEqual(json.loads(self.state.read_text())['version'], '0.12.0')
        self.assertEqual(self.skills_run, 0)


class RelayIntegrationTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
