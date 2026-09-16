"""검토된 추가 모델(`state/opencode-models.json`)이 safecode 파생 설정에 병합되는지 확인하는 회귀.

OpenCode 1.18.29 의 내장 카탈로그에 없는 새 모델(예: 알리바바 Token Plan 의 deepseek-v4.1-flash)을 가드 소유 파일로
정의한다. 호스트 설정을 다시 가져와도 사라지지 않아야 하고, 허용 목록 밖 공급자·이상한 ID·낯선 키는 거부한다.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import configure_existing as configure

MODEL = {'name': 'DeepSeek V4.1 Flash', 'limit': {'context': 1000000, 'output': 393216}, 'tool_call': True,
         'reasoning': False, 'attachment': True, 'temperature': True,
         'cost': {'input': 0, 'output': 0, 'cache_read': 0, 'cache_write': 0}, 'options': {}}


class MergeTests(unittest.TestCase):
    def test_extra_models_are_merged_under_the_enabled_provider(self):
        config = {'enabled_providers': ['alibaba-token-plan', 'zai-coding-plan'], 'permission': {'*': 'ask'}}
        merged = configure.merge_extra_models(config, {'alibaba-token-plan': {'deepseek-v4.1-flash': MODEL}})
        self.assertEqual(merged['provider']['alibaba-token-plan']['models']['deepseek-v4.1-flash'], MODEL)
        self.assertNotIn('zai-coding-plan', merged['provider'])
        self.assertEqual(merged['permission'], {'*': 'ask'})
        self.assertNotIn('provider', config)  # 입력은 바꾸지 않는다

    def test_existing_provider_definition_and_models_are_preserved(self):
        config = {'enabled_providers': ['alibaba-token-plan'],
                  'provider': {'alibaba-token-plan': {'options': {'baseURL': 'https://x'}, 'models': {'old': {'name': 'Old'}}}}}
        merged = configure.merge_extra_models(config, {'alibaba-token-plan': {'deepseek-v4.1-flash': MODEL}})
        provider = merged['provider']['alibaba-token-plan']
        self.assertEqual(provider['options'], {'baseURL': 'https://x'})
        self.assertEqual(sorted(provider['models']), ['deepseek-v4.1-flash', 'old'])

    def test_disabled_providers_are_skipped_and_bad_entries_are_rejected(self):
        config = {'enabled_providers': ['alibaba-token-plan']}
        merged = configure.merge_extra_models(config, {'zai-coding-plan': {'glm-9': MODEL}})
        self.assertNotIn('provider', merged)
        for extras in [{'evil-provider': {'m': MODEL}},
                       {'alibaba-token-plan': {'../x': MODEL}},
                       {'alibaba-token-plan': {'Bad Model': MODEL}},
                       {'alibaba-token-plan': {'ok-model': dict(MODEL, npm='@evil/sdk')}},
                       {'alibaba-token-plan': {'ok-model': dict(MODEL, options={'baseURL': 'https://evil'})}},
                       {'alibaba-token-plan': {'ok-model': dict(MODEL, limit={'context': 'big'})}},
                       {'alibaba-token-plan': {'ok-model': 'DeepSeek'}}]:
            with self.assertRaises(ValueError, msg=extras):
                configure.merge_extra_models(config, extras)


class RefreshTests(unittest.TestCase):
    def test_refresh_rewrites_the_derived_config_without_touching_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); state = root / 'state'; state.mkdir(mode=0o700)
            (state / 'opencode-config.json').write_text(json.dumps({'enabled_providers': ['alibaba-token-plan'], 'share': 'disabled'}))
            (state / 'opencode-auth.json').write_text('{"alibaba-token-plan": {"type": "api", "key": "SYNTHETIC"}}')
            (state / 'opencode-models.json').write_text(json.dumps({'alibaba-token-plan': {'deepseek-v4.1-flash': MODEL}}))
            with patch.object(configure, 'ROOT', root):
                configure.refresh_models()
                configure.refresh_models()  # 재실행해도 같다
            config = json.loads((state / 'opencode-config.json').read_text())
            self.assertEqual(config['provider']['alibaba-token-plan']['models']['deepseek-v4.1-flash'], MODEL)
            self.assertEqual(config['share'], 'disabled')
            self.assertEqual((state / 'opencode-auth.json').read_text(), '{"alibaba-token-plan": {"type": "api", "key": "SYNTHETIC"}}')

    def test_import_merges_extra_models_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); state = root / 'state'; state.mkdir(mode=0o700)
            (state / 'opencode-models.json').write_text(json.dumps({'alibaba-token-plan': {'deepseek-v4.1-flash': MODEL}}))
            auth = {'alibaba-token-plan': {'type': 'api', 'key': 'SYNTHETIC'}}
            with patch.object(configure, 'ROOT', root):
                config, scoped, profile = configure.opencode_assets(auth, {}, {'alibaba-token-plan': 'https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'})
            self.assertIn('deepseek-v4.1-flash', config['provider']['alibaba-token-plan']['models'])
            self.assertEqual(profile['domains'], ['token-plan.ap-southeast-1.maas.aliyuncs.com:443'])


if __name__ == '__main__':
    unittest.main()
