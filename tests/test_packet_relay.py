"""Regression for the relay where the safecode supervisor runs packet-ask on behalf of the sandbox."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g
from adapters import packet_relay


class VersionGateTests(unittest.TestCase):
    def test_pinned_version_lives_only_in_the_state_file(self):
        """When the gate was a source constant, every promotion required editing guard code, and once 0.9.0 was left behind and it failed."""
        pinned = json.loads((ROOT / 'state/packet-ask-version.json').read_text())['version']
        self.assertRegex(pinned, r'^\d+\.\d+\.\d+$')
        self.assertEqual(g.packet_ask_pinned_version(), pinned)
        self.assertNotRegex((ROOT / 'agentbelt.py').read_text(), r"PACKET_ASK_VERSION = '\d")
        entry = (ROOT / 'packet_entry.py').read_text()
        self.assertNotRegex(entry, r"!= '\d+\.\d+\.\d+'")
        self.assertIn('AGENTBELT_PACKET_ASK_VERSION', entry)

    def test_packet_launch_hands_the_pinned_version_to_the_entry(self):
        arguments, domains, env = g.prepare_packet_request(['inspect', 'review', '--files', 'a.py'])
        self.assertEqual(env['AGENTBELT_PACKET_ASK_VERSION'], g.packet_ask_pinned_version())

    def test_entry_refuses_without_the_supervisor_version(self):
        """Without the environment variable it is closed. Running it directly as a bypass does not load the adapter."""
        import runpy
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('AGENTBELT_PACKET_ASK_VERSION', None)
            with self.assertRaises(SystemExit):
                runpy.run_path(str(ROOT / 'packet_entry.py'), run_name='__main__')


class RequestValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='relay-validate-', dir=Path.home())
        self.workspace = Path(self.tmp.name)
        (self.workspace / 'a.py').write_text('print(1)\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_accepts_workspace_files_and_builds_the_packet_ask_arguments(self):
        request = packet_relay.validate_request(
            {'files': ['a.py'], 'question': 'q', 'effort': 'high'}, self.workspace, {'maxQuestionBytes': 100})
        self.assertEqual(request['arguments'][:4], ['--use-keychain', 'review', '--provider', 'glm'])
        self.assertIn('--question-stdin', request['arguments'])
        self.assertEqual(request['arguments'][request['arguments'].index('--files') + 1], 'a.py')

    def test_rejects_paths_that_leave_the_workspace(self):
        for bad in ['../a.py', '/etc/hosts', str(Path.home() / '.zshrc')]:
            with self.assertRaises(g.GuardError):
                packet_relay.validate_request({'files': [bad], 'question': 'q'}, self.workspace, {})

    def test_rejects_oversized_or_malformed_requests(self):
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'files': ['a.py'], 'question': 'x' * 200}, self.workspace, {'maxQuestionBytes': 100})
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'files': ['a.py'], 'question': 'q', 'effort': 'ultra'}, self.workspace, {})
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'question': 'q'}, self.workspace, {})
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'files': ['a.py'], 'question': 'q', 'diff': 'x; rm -rf /'}, self.workspace, {})


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='relay-provider-', dir=Path.home())
        self.workspace = Path(self.tmp.name)
        (self.workspace / 'a.py').write_text('print(1)\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_provider_is_glm_and_qwen_builds_a_read_only_prompt(self):
        glm = packet_relay.validate_request({'files': ['a.py'], 'question': 'q'}, self.workspace, {})
        self.assertEqual(glm['provider'], 'glm')
        qwen = packet_relay.validate_request({'files': ['a.py'], 'question': 'why?', 'provider': 'qwen'}, self.workspace, {})
        self.assertEqual(qwen['provider'], 'qwen')
        self.assertIn('a.py', qwen['prompt'])
        self.assertIn('why?', qwen['prompt'])
        self.assertNotIn('arguments', qwen)
        with self.assertRaises(g.GuardError):
            packet_relay.validate_request({'files': ['a.py'], 'question': 'q', 'provider': 'gpt'}, self.workspace, {})

    def test_review_text_is_extracted_from_opencode_json_events(self):
        lines = '\n'.join([
            json.dumps({'type': 'step_start', 'part': {'type': 'step-start'}}),
            json.dumps({'type': 'text', 'part': {'type': 'text', 'text': 'first'}}),
            json.dumps({'type': 'text', 'part': {'type': 'text', 'text': 'second'}}),
            'not json at all',
            json.dumps({'type': 'step_finish', 'part': {'type': 'step-finish'}})])
        self.assertEqual(packet_relay.extract_review_text(lines), 'first\nsecond')

    def test_review_config_disables_every_mutating_tool(self):
        base = {'permission': {'*': 'ask', 'read': 'allow'}, 'enabled_providers': ['x'], 'plugin': [], 'mcp': {}}
        config = g.review_config(base)
        tools = config['agent']['review']['tools']
        for name in ['bash', 'edit', 'write', 'patch', 'webfetch', 'websearch', 'task', 'todowrite', 'skill']:
            self.assertIs(tools.get(name), False, name)
        self.assertEqual(config['permission'], base['permission'])
        self.assertEqual(config['enabled_providers'], ['x'])
        self.assertEqual(config['agent']['review']['model'], g.DEFAULT_REVIEW_MODEL)
        for name in ['read', 'glob', 'grep', 'list']:
            self.assertEqual(config['agent']['review']['permission'][name], 'allow', name)
        self.assertEqual(g.review_config(base, 'p/m')['agent']['review']['model'], 'p/m')
        with self.assertRaises(g.GuardError):
            g.review_config(base, 'bad model; rm')

    def test_opencode_review_mode_launches_the_read_only_agent_in_its_own_home(self):
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, mode=mode, workspace=workspace, command=command, positional=args)
            return 0

        with patch.object(g, 'run_confined', fake_run_confined), \
             patch.object(g, 'verify_opencode_binary', lambda: None), \
             patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
             patch('sys.stdin', __import__('io').StringIO('review this please')):
            (ROOT / 'state/opencode-auth.json').is_file() or self.skipTest('no opencode auth fixture')
            self.assertEqual(g.main(['opencode-review', str(self.workspace)]), 0)
        # A second run must not fail even when the config file already exists (O_EXCL regression).
        with patch.object(g, 'run_confined', fake_run_confined), \
             patch.object(g, 'verify_opencode_binary', lambda: None), \
             patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
             patch('sys.stdin', __import__('io').StringIO('review this please')):
            self.assertEqual(g.main(['opencode-review', str(self.workspace)]), 0)
        self.assertEqual(captured['mode'], 'opencode-review')
        self.assertEqual(captured['command'][-6:-1], ['run', '--agent', 'review', '--format', 'json'])
        self.assertEqual(captured['command'][-1], 'review this please')
        self.assertTrue(captured['protect_opencode_config'])
        extra_env = captured['positional'][1] if len(captured['positional']) > 1 else captured['extra_env']
        self.assertTrue(extra_env['OPENCODE_CONFIG'].endswith('opencode-review-config.json'))
        self.assertNotIn('--auto', captured['command'])


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='relay-channel-', dir=Path.home())
        self.workspace = Path(self.tmp.name) / 'work'
        self.workspace.mkdir()
        (self.workspace / 'a.py').write_text('print(1)\n')
        self.home = Path(self.tmp.name) / 'home'
        self.home.mkdir()
        self.seen = []

    def tearDown(self):
        self.tmp.cleanup()

    def fake_runner(self, provider, prepared, workspace):
        self.seen.append((provider, prepared, workspace))
        question = prepared.get('question') or prepared.get('prompt')
        if question == 'fail':
            return 2, '', 'synthetic provider failure'
        return 0, 'REVIEW(' + provider + '): ' + question, ''

    def relay(self, **settings):
        return packet_relay.PacketRelay(self.workspace, self.home, runner=self.fake_runner,
                                        settings=dict({'maxPerHour': 3, 'pollSeconds': 0.05}, **settings))

    def wait_for(self, path, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if path.exists():
                return path.read_text()
            time.sleep(0.05)
        self.fail('no file ' + str(path))

    def test_prepare_seeds_helper_and_request_directory(self):
        with self.relay() as relay:
            env = {'PATH': '/usr/bin:/bin'}
            relay.prepare(self.home, env)
            helper = self.home / 'bin/packet-review'
            self.assertTrue(helper.is_file())
            self.assertEqual(helper.stat().st_mode & 0o777, 0o500)
            self.assertTrue(env['PATH'].startswith(str(self.home / 'bin') + ':'))
            self.assertEqual(env['AGENTBELT_PACKET_REVIEW'], '1')
            self.assertTrue((self.home / 'tmp/packet-requests').is_dir())
            self.assertIn('bin/packet-review', relay.read_only_home_paths())

    def test_request_file_round_trips_through_the_host_runner(self):
        with self.relay() as relay:
            relay.prepare(self.home, {'PATH': ''})
            requests = self.home / 'tmp/packet-requests'
            (requests / 'r1.json').write_text(json.dumps({'files': ['a.py'], 'question': 'hello', 'effort': 'high'}))
            text = self.wait_for(requests / 'r1.result.md')
        self.assertEqual(text, 'REVIEW(glm): hello')
        provider, prepared, workspace = self.seen[0]
        self.assertEqual(provider, 'glm')
        self.assertEqual(prepared['question'], 'hello')
        self.assertEqual(workspace, self.workspace)
        self.assertIn('--use-keychain', prepared['arguments'])

    def test_failures_and_bad_requests_produce_error_files_not_results(self):
        with self.relay() as relay:
            relay.prepare(self.home, {'PATH': ''})
            requests = self.home / 'tmp/packet-requests'
            (requests / 'bad.json').write_text('{not json')
            (requests / 'out.json').write_text(json.dumps({'files': ['../x'], 'question': 'q'}))
            (requests / 'boom.json').write_text(json.dumps({'files': ['a.py'], 'question': 'fail'}))
            self.assertIn('JSON', self.wait_for(requests / 'bad.error.txt'))
            self.assertIn('workspace', self.wait_for(requests / 'out.error.txt'))
            self.assertIn('synthetic provider failure', self.wait_for(requests / 'boom.error.txt'))
            self.assertFalse((requests / 'boom.result.md').exists())

    def test_rate_limit_refuses_extra_requests_within_the_hour(self):
        with self.relay(maxPerHour=1) as relay:
            relay.prepare(self.home, {'PATH': ''})
            requests = self.home / 'tmp/packet-requests'
            (requests / 'one.json').write_text(json.dumps({'files': ['a.py'], 'question': 'a'}))
            self.wait_for(requests / 'one.result.md')
            (requests / 'two.json').write_text(json.dumps({'files': ['a.py'], 'question': 'b'}))
            self.assertIn('limit', self.wait_for(requests / 'two.error.txt'))
        self.assertEqual(len(self.seen), 1)

    def test_helper_script_works_from_inside_the_real_sandbox(self):
        with self.relay() as relay:
            (self.workspace / 'p.sh').write_text(
                'set -e\n'
                'out=$(printf "please review" | packet-review --files a.py --effort high --question-stdin)\n'
                'echo "GOT:$out"\n'
                'packet-review --files ../x --question q 2>&1 | head -5 || true\n')
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('relay-test', self.workspace, ['/bin/bash', str(self.workspace / 'p.sh')],
                                        prepare_home=relay.prepare, read_only_home_paths=relay.read_only_home_paths(),
                                        ephemeral=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('GOT:REVIEW(glm): please review', text)
        self.assertIn('workspace', text)


class SafecodeWiringTests(unittest.TestCase):
    def test_safecode_attaches_the_relay_when_opted_in(self):
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, mode=mode, workspace=workspace)
            return 0

        with tempfile.TemporaryDirectory(prefix='relay-wiring-', dir=Path.home()) as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'verify_opencode_binary', lambda: None), \
                     patch.object(g, 'orca_integration', lambda: None), \
                     patch.object(g, 'packet_relay_settings', lambda: {'enabled': True, 'maxPerHour': 2}), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}):
                    (ROOT / 'state/opencode-auth.json').is_file() or self.skipTest('no opencode auth fixture')
                    self.assertEqual(g.main(['safecode']), 0)
                self.assertEqual(captured['mode'], 'opencode')
                self.assertIn('bin/packet-review', captured['read_only_home_paths'])
                self.assertIn('packet-review', captured['notice_extra'])
                home = Path(tmp) / 'synthetic-home'
                home.mkdir()
                env = {'PATH': '/usr/bin'}
                captured['prepare_home'](home, env)
                self.assertTrue((home / 'bin/packet-review').is_file())
                self.assertTrue(env['PATH'].startswith(str(home / 'bin') + ':'))
            finally:
                os.chdir(previous)


class ZcodeWiringTests(unittest.TestCase):
    def test_zcode_backend_attaches_the_relay_when_opted_in(self):
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, mode=mode, workspace=workspace)
            return 0

        with tempfile.TemporaryDirectory(prefix='relay-zcode-', dir=Path.home()) as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'verify_zcode_binary', lambda: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                     patch.object(g, 'packet_relay_settings', lambda: {'enabled': True}), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}):
                    self.assertEqual(g.main(['zcode-backend', 'app-server', '--stdio']), 0)
                self.assertEqual(captured['mode'], 'zcode')
                self.assertIn('bin/packet-review', captured['read_only_home_paths'])
                self.assertIn('.zcode/cli/config.json', captured['read_only_home_paths'])
                self.assertIn('packet-review', captured['notice_extra'])
                home = Path(tmp) / 'synthetic-home'
                home.mkdir()
                env = {'PATH': '/usr/bin'}
                captured['prepare_home'](home, env)
                self.assertTrue((home / 'bin/packet-review').is_file())
                self.assertTrue(env['PATH'].startswith(str(home / 'bin') + ':'))
                self.assertEqual(env['AGENTBELT_BOOTSTRAP'], 'zcode')
            finally:
                os.chdir(previous)

    def test_riskgate_lets_the_helper_run_without_a_prompt(self):
        from riskgate_bridge import riskgate_decision
        with tempfile.TemporaryDirectory(prefix='relay-riskgate-', dir=Path.home()) as tmp:
            for command in ['packet-review --files a.py --question "q"',
                            'printf "%s" "q" | packet-review --files a.py --provider qwen --question-stdin',
                            'packet-promote 0.13.0']:
                verdict = riskgate_decision({'tool_input': {'command': command}, 'cwd': tmp})
                self.assertEqual(verdict, 'allow', command)


if __name__ == '__main__':
    unittest.main()
