"""Regression for usage mode, which runs the Token Plan usage CLI (bl) in isolation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g
from adapters import usage_cli


class ProfileTests(unittest.TestCase):
    def test_default_profile_names_only_international_gateways(self):
        profile = usage_cli.default_profile()
        self.assertIn('bailian-singapore-cs.alibabacloud.com:443', profile['domains'])
        self.assertNotIn('bailian-cs.console.aliyun.com:443', profile['domains'])
        self.assertNotIn('registry.npmjs.org:443', profile['domains'])
        self.assertEqual(profile['consoleSite'], 'international')
        self.assertEqual(profile['consoleRegion'], 'ap-southeast-1')
        self.assertRegex(profile['cliVersion'], r'^\d+\.\d+\.\d+$')

    def test_workspace_and_home_are_guard_owned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(usage_cli, 'ROOT', root):
                self.assertEqual(usage_cli.usage_workspace().parent, root / 'state')
                self.assertEqual(usage_cli.usage_home().parents[1], root / 'state/homes')


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.host_calls = []

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            self.calls.append(dict(kwargs, mode=mode, workspace=workspace, command=command, positional=args))
            return 0

        def fake_call(command, **kwargs):
            self.host_calls.append(dict(kwargs, command=command))
            return 0
        # Write a synthetic entry file so the wiring can be checked even when bl is not installed in the real isolated home.
        self.entry_dir = tempfile.TemporaryDirectory(prefix='usage-wiring-', dir=Path.home())
        root = Path(self.entry_dir.name)
        entry = Path(self.entry_dir.name) / 'bailian-cli/dist/bailian.mjs'
        entry.parent.mkdir(parents=True)
        entry.write_text('// synthetic\n')
        self.patches = [patch.object(g, 'run_confined', fake_run_confined),
                        patch.object(g.subprocess, 'call', fake_call),
                        patch.object(usage_cli, 'ROOT', root),
                        patch.object(usage_cli, 'load_profile', usage_cli.default_profile),
                        patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': sorted(g.PUBLIC_PACKAGE_DOMAINS)}),
                        patch.object(usage_cli, 'bl_entry', lambda home: entry)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.entry_dir.cleanup()

    def test_plain_usage_queries_token_plan_inside_the_sandbox(self):
        self.assertEqual(g.main(['usage']), 0)
        self.assertEqual(len(self.calls), 1)
        call = self.calls[0]
        self.assertEqual(call['mode'], 'usage')
        self.assertEqual(call['workspace'], usage_cli.usage_workspace())
        self.assertEqual(call['command'][0], str(g.NODE))
        self.assertTrue(str(call['command'][1]).endswith('bailian-cli/dist/bailian.mjs'))
        self.assertEqual(call['command'][2:4], ['usage', 'token-plan'])
        self.assertIn('--console-site', call['command'])
        domains = call['positional'][0] if call['positional'] else call['domains']
        self.assertIn('bailian-singapore-cs.alibabacloud.com:443', domains)
        self.assertNotIn('registry.npmjs.org:443', domains)
        self.assertEqual(self.host_calls, [])

    def test_query_carries_the_host_time_zone(self):
        """The sandbox cannot read zoneinfo, so it printed UTC. Passing just the TZ name lets Node handle it with the built-in ICU."""
        self.assertEqual(g.main(['usage']), 0)
        extra = self.calls[0].get('extra_env') or {}
        self.assertEqual(extra.get('TZ'), usage_cli.host_time_zone())
        self.assertRegex(usage_cli.host_time_zone(), r'^[A-Za-z_]+/[A-Za-z_]+$|^UTC$')

    def test_query_suppresses_node_experimental_warnings(self):
        """bl printed two UNDICI-EHPA warning lines on every run, obscuring the result."""
        self.assertEqual(g.main(['usage']), 0)
        self.assertIn('--no-warnings', (self.calls[0].get('extra_env') or {}).get('NODE_OPTIONS', ''))

    def test_expired_console_session_points_at_our_login_command(self):
        """bl recommends `bl auth login --console`, but it must be token-usage login for it to be saved in the isolated home."""
        import io
        with patch.object(g, 'run_confined', lambda *a, **k: 3), patch('sys.stderr', new_callable=io.StringIO) as err:
            self.assertEqual(g.main(['usage']), 3)
        self.assertIn('token-usage login', err.getvalue())

    def test_passthrough_arguments_stay_sandboxed(self):
        self.assertEqual(g.main(['usage', '--', 'auth', 'status']), 0)
        self.assertEqual(self.calls[0]['command'][2:], ['auth', 'status'])

    def test_setup_installs_then_logs_in_inside_the_same_isolation(self):
        self.assertEqual(g.main(['usage', 'setup']), 0)
        install = self.calls[0]
        domains = install['positional'][0] if install['positional'] else install['domains']
        self.assertIn('registry.npmjs.org:443', domains)
        joined = ' '.join(map(str, install['command']))
        self.assertIn('bailian-cli@' + usage_cli.default_profile()['cliVersion'], joined)
        self.assertEqual(self.host_calls, [])
        self.assertEqual(len(self.calls), 2)
        login = self.calls[1]
        self.assertEqual(login['command'][2:5], ['auth', 'login', '--console'])
        home = usage_cli.usage_home()
        self.assertEqual(login['mode'], 'usage')
        self.assertEqual(login['extra_env']['BAILIAN_CONFIG_DIR'], str(home / '.bailian'))
        self.assertTrue(login['loopback_port'])
        self.assertFalse(login['github'])
        self.assertFalse(install['github'])
        self.assertFalse(login.get('loopback_all', False))

    def test_query_before_setup_explains_what_to_run(self):
        with patch.object(usage_cli, 'bl_entry', lambda home: home / 'missing.mjs'):
            with self.assertRaises(g.GuardError) as caught:
                g.main(['usage'])
        self.assertIn('usage setup', str(caught.exception))


class BoundaryTests(unittest.TestCase):
    def test_usage_sandbox_sees_only_its_home_and_gateways(self):
        script = (
            'ls ' + str(Path.home()) + '/.bailian >/dev/null 2>&1 && echo OPEN || echo BLOCKED\n'
            'ls ' + str(Path.home()) + '/.claude >/dev/null 2>&1 && echo OPEN || echo BLOCKED\n'
            'ls ' + str(ROOT / 'state/opencode-auth.json') + ' >/dev/null 2>&1 && echo OPEN || echo BLOCKED\n'
            'curl -sS -m 10 -o /dev/null -w "npm:%{http_code}\\n" https://registry.npmjs.org/ 2>&1 | tail -1\n'
            'curl -sS -m 15 -o /dev/null -w "gateway:%{http_code}\\n" https://bailian-singapore-cs.alibabacloud.com/ 2>&1 | tail -1\n')
        with tempfile.TemporaryDirectory(prefix='usage-boundary-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'p.sh').write_text(script)
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('usage-test', work, ['/bin/bash', str(work / 'p.sh')],
                                        domains=usage_cli.default_profile()['domains'], ephemeral=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertEqual(text.count('BLOCKED'), 3, text)
        self.assertNotIn('npm:200', text)
        self.assertRegex(text, r'gateway:[1-5]\d\d')


if __name__ == '__main__':
    unittest.main()
