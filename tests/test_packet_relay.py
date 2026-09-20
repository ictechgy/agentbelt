"""Regression for the relay where the safecode supervisor runs packet-ask on behalf of the sandbox."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
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
        # Guard tests may inspect a candidate under the private promotion
        # capability while the canonical public pin remains unavailable.
        pinned = g.packet_ask_pinned_version()
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
        with self.assertRaisesRegex(g.GuardError, 'cannot combine'):
            packet_relay.validate_request({'files': ['a.py'], 'question': 'q', 'diff': 'HEAD~1..HEAD'}, self.workspace, {})

    def test_diff_only_request_is_preserved_for_the_collector(self):
        request = packet_relay.validate_request(
            {'question': 'what changed?', 'diff': 'HEAD~1..HEAD', 'timeout': 30,
             'json': True},
            self.workspace,
            {},
        )
        self.assertEqual(request['arguments'][:4], ['--use-keychain', 'review', '--provider', 'glm'])
        self.assertIn('--diff', request['arguments'])
        self.assertNotIn('--files', request['arguments'])
        self.assertIn('--timeout', request['arguments'])
        self.assertIn('--json', request['arguments'])

    def test_file_relay_rejects_progress_with_direct_cli_guidance(self):
        with self.assertRaisesRegex(g.GuardError, 'packet-ask-safe'):
            packet_relay.validate_request(
                {'files': ['a.py'], 'question': 'review', 'progress': True},
                self.workspace,
                {},
            )


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='relay-provider-', dir=Path.home())
        self.workspace = Path(self.tmp.name)
        (self.workspace / 'a.py').write_text('print(1)\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_provider_is_glm_and_qwen_uses_the_same_collector_shape(self):
        glm = packet_relay.validate_request({'files': ['a.py'], 'question': 'q'}, self.workspace, {})
        self.assertEqual(glm['provider'], 'glm')
        qwen = packet_relay.validate_request({'files': ['a.py'], 'question': 'why?', 'provider': 'qwen'}, self.workspace, {})
        self.assertEqual(qwen['provider'], 'qwen')
        self.assertIn('a.py', qwen['arguments'])
        self.assertEqual(qwen['question'], 'why?')
        self.assertIn('prompt', qwen)
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
        self.assertEqual(config['permission'], {'*': 'deny'})
        self.assertEqual(config['enabled_providers'], ['x'])
        self.assertEqual(config['agent']['review']['model'], g.DEFAULT_REVIEW_MODEL)
        for name in ['read', 'glob', 'grep', 'list']:
            self.assertIs(config['agent']['review']['tools'].get(name), False, name)
        self.assertEqual(config['agent']['review']['permission'], {'*': 'deny'})
        self.assertEqual(g.review_config(base, 'p/m')['agent']['review']['model'], 'p/m')
        with self.assertRaises(g.GuardError):
            g.review_config(base, 'bad model; rm')

    def test_qwen_host_runner_uses_the_shared_staged_pipeline(self):
        from adapters import packet_pipeline
        events = []
        prepared = {
            'arguments': ['--use-keychain', 'review', '--provider', 'glm', '--files', 'a.py', '--question-stdin',
                          '--timeout', '30'],
            'question': 'review this please',
        }

        def fake_pipeline(*args, **kwargs):
            events.append('pipeline')
            if '--json' in args[0]:
                kwargs['stdout'].write('{"part":{"type":"text","text":"synthetic qwen review"}}\n'.encode())
            else:
                kwargs['stdout'].write('synthetic qwen review'.encode())
            return 0

        with patch.object(packet_pipeline, 'run', side_effect=fake_pipeline) as execute:
            status, output, error = packet_relay.host_runner('qwen', prepared, self.workspace)
        self.assertEqual((status, output, error), (0, 'synthetic qwen review', ''))
        self.assertEqual(events, ['pipeline'])
        execute.assert_called_once()
        self.assertEqual(execute.call_args.kwargs['provider'], 'qwen')
        self.assertTrue(execute.call_args.kwargs['use_keychain'])
        self.assertEqual(execute.call_args.kwargs['question'], 'review this please')
        self.assertEqual(execute.call_args.kwargs['operation_timeout'], 30)
        self.assertIsNotNone(execute.call_args.kwargs['deadline'])
        self.assertEqual(
            execute.call_args.kwargs['transaction_state_file'],
            packet_relay.ROOT / 'state/packet-ask-version.json')

        prepared_json = dict(prepared, arguments=prepared['arguments'] + ['--json'])
        with patch.object(packet_pipeline, 'run', side_effect=fake_pipeline):
            status, output, error = packet_relay.host_runner('qwen', prepared_json, self.workspace)
        self.assertEqual((status, output, error), (0, '{"part":{"type":"text","text":"synthetic qwen review"}}\n', ''))

    def test_review_timeout_includes_wait_for_active_promotion(self):
        from adapters import packet_pipeline, packet_transaction
        with tempfile.TemporaryDirectory(prefix='relay-lock-timeout-') as raw:
            root = Path(raw)
            (root / 'state').mkdir()
            state = root / 'state/packet-ask-version.json'
            state.write_text('{"version":"0.12.0"}\n')
            entered, release = threading.Event(), threading.Event()

            def hold_promotion():
                with packet_transaction.promotion(state, '0.13.0'):
                    entered.set()
                    release.wait(5)

            holder = threading.Thread(target=hold_promotion)
            holder.start()
            self.assertTrue(entered.wait(2))
            prepared = {
                'arguments': ['review', '--files', 'a.py', '--question-stdin', '--timeout', '1'],
                'question': 'review this please',
            }
            started = time.monotonic()
            try:
                with patch.object(packet_relay, 'ROOT', root), \
                     patch.object(packet_pipeline, '_collector', side_effect=AssertionError('collector entered')):
                    status, output, error = packet_relay.host_runner('glm', prepared, root)
            finally:
                release.set()
                holder.join(2)
            self.assertEqual((status, output), (124, ''))
            self.assertIn('waiting for packet promotion', error)
            self.assertLess(time.monotonic() - started, 2)

    def test_cancel_interrupts_wait_for_active_promotion(self):
        from adapters import packet_pipeline, packet_transaction
        with tempfile.TemporaryDirectory(prefix='relay-lock-cancel-') as raw:
            root = Path(raw)
            (root / 'state').mkdir()
            state = root / 'state/packet-ask-version.json'
            state.write_text('{"version":"0.12.0"}\n')
            entered, release, cancel = threading.Event(), threading.Event(), threading.Event()

            def hold_promotion():
                with packet_transaction.promotion(state, '0.13.0'):
                    entered.set()
                    release.wait(5)

            holder = threading.Thread(target=hold_promotion)
            holder.start()
            self.assertTrue(entered.wait(2))
            prepared = {
                'arguments': ['review', '--files', 'a.py', '--question-stdin', '--timeout', '30'],
                'question': 'review this please',
            }
            timer = threading.Timer(0.1, cancel.set)
            timer.start()
            started = time.monotonic()
            try:
                with patch.object(packet_relay, 'ROOT', root), \
                     patch.object(packet_pipeline, '_collector', side_effect=AssertionError('collector entered')):
                    status, output, error = packet_relay.host_runner(
                        'glm', prepared, root, cancel_event=cancel)
            finally:
                timer.cancel()
                release.set()
                holder.join(2)
            self.assertEqual((status, output, error), (130, '', 'packet-review was cancelled'))
            self.assertLess(time.monotonic() - started, 2)

    def test_host_runner_rejects_timeout_beyond_relay_lifetime_before_pipeline(self):
        from adapters import packet_pipeline
        prepared = {
            'arguments': ['--use-keychain', 'review', '--provider', 'glm', '--files', 'a.py',
                          '--question-stdin', '--timeout', str(packet_relay.DEFAULT_SETTINGS['timeoutSeconds'] + 1)],
            'question': 'review this please',
        }
        with patch.object(packet_pipeline, 'run', side_effect=AssertionError('pipeline entered')):
            status, output, error = packet_relay.host_runner('glm', prepared, self.workspace)
        self.assertEqual(status, 1)
        self.assertEqual(output, '')
        self.assertIn('1800-second limit', error)

    def test_shared_transaction_blocks_promotion_until_pipeline_returns(self):
        from adapters import packet_pipeline, packet_transaction
        prepared = {
            'arguments': ['--use-keychain', 'review', '--provider', 'glm', '--files', 'a.py', '--question-stdin'],
            'question': 'review this please',
        }
        attempted = threading.Event()
        promoted = threading.Event()
        threads = []
        with tempfile.TemporaryDirectory(prefix='relay-transaction-') as raw:
            root = Path(raw)
            (root / 'state').mkdir()
            state = root / 'state/packet-ask-version.json'
            state.write_text('{"version":"0.12.0"}\n')
            state.chmod(0o600)

            def fake_pipeline(*args, **kwargs):
                with packet_transaction.consumer(kwargs['transaction_state_file']):
                    kwargs['stdout'].write('{"part":{"type":"text","text":"synthetic review"}}\n'.encode())

                    def promote():
                        attempted.set()
                        with packet_transaction.promotion(state, '0.13.0'):
                            promoted.set()

                    worker = threading.Thread(target=promote)
                    threads.append(worker)
                    worker.start()
                    self.assertTrue(attempted.wait(1))
                    time.sleep(0.05)
                    self.assertFalse(promoted.is_set())
                return 0

            with patch.object(packet_relay, 'ROOT', root), \
                 patch.object(packet_pipeline, 'run', side_effect=fake_pipeline):
                status, output, error = packet_relay.host_runner('qwen', prepared, self.workspace)
            for worker in threads:
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual((status, output, error), (0, '{"part":{"type":"text","text":"synthetic review"}}\n', ''))
        self.assertTrue(promoted.is_set())


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
        if question == 'initfail':
            return 125, '', 'synthetic supervisor init failure'
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

    def test_sandbox_init_failure_does_not_spend_the_hourly_budget(self):
        with self.relay(maxPerHour=1) as relay:
            relay.prepare(self.home, {'PATH': ''})
            requests = self.home / 'tmp/packet-requests'
            (requests / 'one.json').write_text(json.dumps({'files': ['a.py'], 'question': 'initfail'}))
            self.assertIn('exited 125', self.wait_for(requests / 'one.error.txt'))
            (requests / 'two.json').write_text(json.dumps({'files': ['a.py'], 'question': 'b'}))
            self.assertEqual('REVIEW(glm): b', self.wait_for(requests / 'two.result.md'))

    def test_shutdown_cancels_an_active_ordinary_review(self):
        from adapters import packet_pipeline
        started = threading.Event()

        def cancellable_pipeline(*args, **kwargs):
            started.set()
            self.assertTrue(kwargs['cancel_event'].wait(3), 'shutdown did not cancel review')
            return 130

        relay = packet_relay.PacketRelay(
            self.workspace, self.home, settings={'maxPerHour': 3, 'pollSeconds': 0.01})
        began = time.monotonic()
        with patch.object(packet_pipeline, 'run', side_effect=cancellable_pipeline):
            with relay:
                relay.prepare(self.home, {'PATH': ''})
                (relay.requests / 'cancel.json').write_text(json.dumps({
                    'files': ['a.py'], 'question': 'cancel me', 'timeout': 1800}))
                self.assertTrue(started.wait(2), 'ordinary review did not start')
        self.assertLess(time.monotonic() - began, 2.5)
        self.assertFalse(relay.thread.is_alive())

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
                     patch.object(g, 'stage_opencode_binary', lambda: g.OPENCODE), \
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
                     patch.object(g, 'stage_opencode_binary', lambda: g.OPENCODE), \
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
