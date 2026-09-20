"""Reviewers receive one provider, no tools, and no raw-workspace CLI route."""
import unittest
from unittest.mock import patch

import agentbelt as g
from adapters import configure_existing, kimi_cli


class ReviewProviderScopeTests(unittest.TestCase):
    def test_review_launch_uses_private_selected_auth_and_stdin_then_cleans_up(self):
        import json
        from pathlib import Path
        import tempfile
        captured = {}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state'
            state.mkdir(mode=0o700)
            (state / 'opencode-config.json').write_text('{}')
            (state / 'opencode-auth.json').write_text(json.dumps({
                'alibaba-token-plan': {'type': 'api', 'key': 'SYNTHETIC_SELECTED'},
                'deepseek': {'type': 'api', 'key': 'SYNTHETIC_EXCLUDED'}}))
            def run(mode, workspace, command, domains, env, reads, **kwargs):
                captured.update(command=command, domains=domains, kwargs=kwargs,
                                config=Path(env['OPENCODE_CONFIG']), auth=Path(reads[1]))
                self.assertEqual(set(json.loads(captured['auth'].read_text())), {'alibaba-token-plan'})
                self.assertEqual(kwargs['stdin'].read(), b'SYNTHETIC_SCRUBBED_PROMPT')
                return 17
            with patch.object(g, 'ROOT', root), patch.object(g, 'verify_opencode_binary'), \
                 patch.object(g, 'stage_opencode_binary', return_value=root / 'clone/opencode'), \
                 patch.object(g, 'packet_relay_settings', return_value=None), \
                 patch.object(configure_existing, 'load_extra_models', return_value={}), \
                 patch.object(g, 'run_confined', side_effect=run):
                self.assertEqual(g.run_opencode_review(root / 'staging', 'SYNTHETIC_SCRUBBED_PROMPT'), 17)
                with patch.object(g.time, 'monotonic', return_value=20), \
                     patch.object(g, 'run_confined', side_effect=AssertionError('late model launch')):
                    with self.assertRaisesRegex(g.GuardError, 'deadline expired'):
                        g.run_opencode_review(root / 'staging', 'SYNTHETIC_SCRUBBED_PROMPT', deadline=10)
            self.assertFalse(captured['config'].exists())
            self.assertFalse(captured['auth'].exists())
        self.assertTrue(captured['kwargs']['ephemeral'])
        self.assertTrue(captured['kwargs']['read_only_workspace'])
        self.assertNotIn('SYNTHETIC_SCRUBBED_PROMPT', captured['command'])
        self.assertEqual(captured['domains'], ['token-plan.ap-southeast-1.maas.aliyuncs.com:443'])

    def test_helper_environment_does_not_read_or_copy_host_git_identity(self):
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(g, 'host_git_identity', side_effect=AssertionError('host identity read')):
            env = g.clean_environment(Path(temporary), copy_git_identity=False)
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], '/dev/null')

    def test_only_selected_provider_credential_and_domain_are_retained(self):
        auth = {'alibaba-token-plan': {'type': 'api', 'key': 'SYNTHETIC_SELECTED'},
                'deepseek': {'type': 'api', 'key': 'SYNTHETIC_UNRELATED'}}
        with patch.object(configure_existing, 'load_extra_models', return_value={}):
            config, selected, domains = g.review_provider_assets({}, auth, g.DEFAULT_REVIEW_MODEL)
        self.assertEqual(set(selected), {'alibaba-token-plan'})
        self.assertEqual(config['enabled_providers'], ['alibaba-token-plan'])
        self.assertEqual(domains, ['token-plan.ap-southeast-1.maas.aliyuncs.com:443'])
        self.assertEqual(config['permission'], {'*': 'deny'})
        self.assertEqual(config['agent']['review']['permission'], {'*': 'deny'})
        self.assertTrue(all(value is False for value in config['agent']['review']['tools'].values()))
        self.assertNotIn('SYNTHETIC_UNRELATED', str(selected))

    def test_unknown_or_missing_provider_fails_without_fallback(self):
        for model in ['unknown/model', 'deepseek/model', 'bad model']:
            with self.subTest(model=model), self.assertRaises(g.GuardError):
                g.review_provider_assets({}, {}, model)


class OpenCodeStageTests(unittest.TestCase):
    def test_changed_source_never_replaces_verified_clone(self):
        import hashlib
        import json
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'state').mkdir()
            original = root / 'original'
            original.write_bytes(b'SYNTHETIC_REVIEWED_BINARY')
            digest = hashlib.sha256(original.read_bytes()).hexdigest()
            (root / 'state/compatibility.json').write_text(json.dumps({'opencode': {'sha256': digest, 'version': 'fixture'}}))
            with patch.object(g, 'ROOT', root), patch.object(g, 'OPENCODE', original):
                staged = g.stage_opencode_binary()
                original.write_bytes(b'SYNTHETIC_REPLACEMENT')
                self.assertEqual(staged.read_bytes(), b'SYNTHETIC_REVIEWED_BINARY')
                self.assertEqual(staged.stat().st_mode & 0o777, 0o500)
                g.discard_staged_binary(staged)
                self.assertFalse(staged.parent.exists())
                with self.assertRaisesRegex(g.GuardError, 'changed while staging'):
                    g.stage_opencode_binary()
                self.assertEqual(list((root / 'state/opencode-runtime').iterdir()), [])


class KimiRegionTests(unittest.TestCase):
    def test_declared_region_cannot_enable_another_regions_api(self):
        import json
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'profile.json'
            path.write_text(json.dumps({'region': 'global', 'domains': ['api.kimi.com:443']}))
            with patch.object(kimi_cli, 'PROFILE_PATH', path), self.assertRaises(g.GuardError):
                kimi_cli.load_profile()

    def test_preload_path_with_spaces_is_one_node_option_argument(self):
        import shlex
        from pathlib import Path
        script = Path('/synthetic/root with spaces/watch.cjs')
        with patch.object(kimi_cli, 'WATCH_BOOTSTRAP', script):
            env = kimi_cli.kimi_environment(Path('/synthetic/home'))
        self.assertEqual(shlex.split(env['NODE_OPTIONS']), ['--require', str(script)])


if __name__ == '__main__':
    unittest.main()
