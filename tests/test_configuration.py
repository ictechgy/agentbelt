import importlib.util
from pathlib import Path
import unittest
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('configure_existing', ROOT / 'configure_existing.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
guard_spec = importlib.util.spec_from_file_location('agent_guard', ROOT / 'agent_guard.py')
guard = importlib.util.module_from_spec(guard_spec)
guard_spec.loader.exec_module(guard)


class ConfigurationTests(unittest.TestCase):
    def test_only_requested_credentials_are_copied(self):
        original = {'alibaba-coding-plan': {'type': 'api', 'key': 'SYNTHETIC_A'},
                    'deepseek': {'type': 'api', 'key': 'SYNTHETIC_D'},
                    'unrelated-provider': {'type': 'api', 'key': 'SYNTHETIC_NEVER_COPY'}}
        runtime, auth, profile = config.opencode_assets(original, {'plugin': ['untrusted-plugin']},
            {'alibaba-coding-plan': 'https://coding-intl.dashscope.aliyuncs.com/v1',
             'deepseek': 'https://api.deepseek.com'})
        self.assertEqual(set(auth), {'alibaba-coding-plan', 'deepseek'})
        self.assertEqual(runtime['plugin'], [])
        self.assertEqual(profile['domains'], ['api.deepseek.com:443', 'coding-intl.dashscope.aliyuncs.com:443'])
        self.assertIn('unrelated-provider', original)

    def test_unsafe_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            config.opencode_assets({'deepseek': {'type': 'api', 'key': 'SYNTHETIC'}}, {},
                                   {'deepseek': 'http://127.0.0.1:1234'})

    def test_alibaba_token_plan_preserves_shared_model_provider_only(self):
        original = {'alibaba-token-plan': {'type': 'api', 'key': 'SYNTHETIC_TOKEN_PLAN'},
                    'openai': {'type': 'oauth', 'access': 'SYNTHETIC_EXCLUDE'}}
        runtime, auth, profile = config.opencode_assets(original, {},
            {'alibaba-token-plan': 'https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'})
        self.assertEqual(runtime['enabled_providers'], ['alibaba-token-plan'])
        self.assertEqual(set(auth), {'alibaba-token-plan'})
        self.assertEqual(profile['domains'], ['token-plan.ap-southeast-1.maas.aliyuncs.com:443'])

    def test_zai_coding_plan_is_an_allowed_provider_on_its_reviewed_host(self):
        """safecode 에 GLM(Z.AI Coding Plan)을 붙이려면 허용 목록과 검토된 호스트가 있어야 한다."""
        original = {'alibaba-token-plan': {'type': 'api', 'key': 'SYNTHETIC_TOKEN_PLAN'},
                    'zai-coding-plan': {'type': 'api', 'key': 'SYNTHETIC_GLM'},
                    'openai': {'type': 'api', 'key': 'SYNTHETIC_UNRELATED'}}
        runtime, auth, profile = config.opencode_assets(original, {},
            {'alibaba-token-plan': 'https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
             'zai-coding-plan': 'https://api.z.ai/api/coding/paas/v4'})
        self.assertEqual(runtime['enabled_providers'], ['alibaba-token-plan', 'zai-coding-plan'])
        self.assertEqual(set(auth), {'alibaba-token-plan', 'zai-coding-plan'})
        self.assertIn('api.z.ai:443', profile['domains'])
        with self.assertRaises(ValueError):
            config.opencode_assets({'zai-coding-plan': {'type': 'api', 'key': 'SYNTHETIC'}}, {},
                                   {'zai-coding-plan': 'https://evil.example/api/coding/paas/v4'})

    def test_opencode_go_is_pinned_to_its_go_base_url_not_the_whole_host(self):
        """OpenCode Go(2026-09-16). 같은 호스트의 Zen 경로(`/zen/v1`)나 다른 경로로 라우팅을 바꾸는 baseURL 은 거부한다."""
        auth = {'opencode-go': {'type': 'api', 'key': 'SYNTHETIC_GO'}}
        runtime, scoped, profile = config.opencode_assets(auth, {}, {'opencode-go': 'https://opencode.ai/zen/go/v1'})
        self.assertEqual(runtime['enabled_providers'], ['opencode-go'])
        self.assertEqual(profile['domains'], ['opencode.ai:443'])
        import configure_existing as module
        self.assertEqual(set(module.PROVIDER_ENDPOINTS), set(module.PROVIDER_HOSTS))  # 두 표는 짝으로 늘린다
        for bad in ('https://opencode.ai/zen/v1', 'https://opencode.ai/zen/go/v1/../v1', 'https://opencode.ai/'):
            with self.assertRaises(ValueError, msg=bad):
                config.opencode_assets(auth, {'provider': {'opencode-go': {'options': {'baseURL': bad}}}},
                                       {'opencode-go': 'https://opencode.ai/zen/go/v1'})
            with self.assertRaises(ValueError, msg=bad):
                config.opencode_assets(auth, {}, {'opencode-go': bad})

    def test_imported_provider_definitions_cannot_carry_headers_substitutions_or_routing(self):
        """호스트 설정의 공급자 정의는 헤더·`{env:}`/`{file:}` 치환·`api`·모델별 SDK/라우팅을 실어 나르지 못한다(리뷰 HIGH)."""
        auth = {'opencode-go': {'type': 'api', 'key': 'SYNTHETIC_GO'}}
        endpoints = {'opencode-go': 'https://opencode.ai/zen/go/v1'}
        good = {'provider': {'opencode-go': {'name': 'Go', 'options': {'baseURL': 'https://opencode.ai/zen/go/v1', 'timeout': 30},
                                             'models': {'glm-5.3': {'name': 'GLM 5.3', 'limit': {'context': 200000, 'output': 8192}}}}}}
        runtime, _, _ = config.opencode_assets(auth, good, endpoints)
        self.assertEqual(runtime['provider']['opencode-go']['options'], {'baseURL': 'https://opencode.ai/zen/go/v1', 'timeout': 30})
        self.assertEqual(set(runtime['provider']['opencode-go']['models']), {'glm-5.3'})
        for label, definition in [
            ('options.headers', {'options': {'headers': {'X-GitHub': 'literal'}}}),
            ('env substitution in options', {'options': {'timeout': '{env:GH_TOKEN}'}}),
            ('file substitution in name', {'name': '{file:~/.ssh/id_ed25519}'}),
            ('provider api', {'api': 'https://opencode.ai/zen/v1'}),
            ('unreviewed npm', {'npm': '@evil/sdk'}),
            ('model headers', {'models': {'m': {'name': 'm', 'headers': {'a': 'b'}}}}),
            ('model provider override', {'models': {'m': {'name': 'm', 'provider': {'api': 'https://opencode.ai/zen/v1'}}}}),
            ('model npm override', {'models': {'m': {'name': 'm', 'npm': '@evil/sdk'}}}),
            ('model id override', {'models': {'m': {'name': 'm', 'id': 'other-upstream'}}}),
            ('options apiKey with fetch', {'options': {'fetch': 'x'}}),
        ]:
            with self.assertRaises(ValueError, msg=label):
                config.opencode_assets(auth, {'provider': {'opencode-go': definition}}, endpoints)
        # apiKey 는 조용히 제거된다(격리 auth 저장소가 공급).
        runtime, _, _ = config.opencode_assets(auth, {'provider': {'opencode-go': {'options': {'apiKey': 'SYNTHETIC_DROP'}}}}, endpoints)
        self.assertNotIn('SYNTHETIC_DROP', __import__('json').dumps(runtime))

    def test_hook_install_preserves_existing_settings_and_is_idempotent(self):
        source = {'model': {'synthetic': True}, 'hooks': {'events': {'Stop': [{'hooks': []}]}},
                  'permission': {'disallowedTools': ['ExistingDeny']}}
        changed = config.add_zcode_hook(source)
        self.assertEqual(changed['model'], source['model'])
        self.assertEqual(changed['hooks']['events']['Stop'], source['hooks']['events']['Stop'])
        self.assertIn('ExistingDeny', changed['permission']['disallowedTools'])
        self.assertEqual(config.add_zcode_hook(changed), changed)
        self.assertNotIn('enabled', source['hooks'])

    def test_jsonc_preserves_urls_and_string_contents(self):
        self.assertEqual(config.parse_jsonc('{/*comment*/"url":"https://test.invalid/a//b",}'),
                         {'url': 'https://test.invalid/a//b'})

    def test_auth_link_refuses_a_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            home = base / 'home'
            home.mkdir(mode=0o700)
            outside = base / 'outside'
            outside.mkdir(mode=0o700)
            (home / '.local').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                guard.link_opencode_auth(home, base / 'synthetic-auth.json')
            self.assertEqual(list(outside.iterdir()), [])

    def test_auth_link_is_idempotent_and_not_a_credential_copy(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            home = base / 'home'
            home.mkdir(mode=0o700)
            auth = base / 'synthetic-auth.json'
            auth.write_text('{}')
            guard.link_opencode_auth(home, auth)
            guard.link_opencode_auth(home, auth)
            self.assertEqual((home / '.local/share/opencode/auth.json').readlink(), auth)

    def test_safe_app_does_not_replace_a_running_zcode_session(self):
        with patch.object(guard, 'runtime_status'), patch.object(guard, 'verify_zcode_binary'), \
             patch.object(guard.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
             patch.object(guard.os, 'execve') as execute:
            with self.assertRaises(guard.GuardError):
                guard.launch_zcode_app()
            execute.assert_not_called()

    def test_safe_app_does_not_inherit_unrelated_environment_secrets(self):
        with patch.object(guard, 'runtime_status'), patch.object(guard, 'verify_zcode_binary'), \
             patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY': 'SYNTHETIC_ONLY'}), \
             patch.object(guard.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='synthetic-start')), \
             patch.object(guard.os, 'execve', side_effect=RuntimeError('synthetic exec boundary')) as execute:
            with self.assertRaises(RuntimeError):
                guard.launch_zcode_app()
            target, argv, env = execute.call_args.args
            self.assertEqual(target, '/Applications/ZCode.app/Contents/MacOS/ZCode')
            self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
            self.assertEqual(env['ZCODE_AGENT_SERVER_COMMAND'],
                             str(guard.OWNER_HOME / '.local/bin/zcode-backend-safe'))

    def test_packet_preview_never_reads_keychain_even_with_opt_in(self):
        with patch.object(guard, 'read_packet_glm_keychain') as reader:
            args, domains, env = guard.prepare_packet_request(['review', '--provider', 'glm', '--preview'], True)
            reader.assert_not_called()
            self.assertEqual(domains, [])
            self.assertNotIn('PACKET_ASK_GLM_KEY', env)

    def test_packet_only_passes_dedicated_glm_credential(self):
        with patch.dict(os.environ, {'PACKET_ASK_GLM_KEY': 'SYNTHETIC_GLM_ONLY',
                                    'AWS_SECRET_ACCESS_KEY': 'SYNTHETIC_NEVER_PASS'}, clear=True):
            args, domains, env = guard.prepare_packet_request(['review', '--provider', 'glm'])
        self.assertEqual(env['PACKET_ASK_GLM_KEY'], 'SYNTHETIC_GLM_ONLY')
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
        self.assertEqual(domains, ['api.z.ai:443'])
        self.assertEqual(args[-2:], ['--credential-source', 'env'])

    def test_packet_requires_opt_in_before_keychain_read(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(guard, 'read_packet_glm_keychain') as reader:
            with self.assertRaises(guard.GuardError):
                guard.prepare_packet_request(['review', '--provider', 'glm'])
            reader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
