#!/usr/bin/python3
"""Explicitly authorized import of selected model settings; never prints values."""
import argparse
import copy
import fcntl
import json
import os
import pwd
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # 계정 DB 의 홈(환경변수 아님)
PROVIDER_HOSTS = {
    'alibaba': 'dashscope-intl.aliyuncs.com',
    'alibaba-cn': 'dashscope.aliyuncs.com',
    'alibaba-coding-plan': 'coding-intl.dashscope.aliyuncs.com',
    'alibaba-coding-plan-cn': 'coding.dashscope.aliyuncs.com',
    'alibaba-token-plan': 'token-plan.ap-southeast-1.maas.aliyuncs.com',
    'deepseek': 'api.deepseek.com',
    # GLM Coding Plan. Zcode 와 packet-ask 가 이미 쓰는 z.ai 호스트의 OpenAI 호환 코딩 엔드포인트.
    'zai-coding-plan': 'api.z.ai',
    # OpenCode Go($10 구독, 오픈 가중치 모델 묶음). 요청은 OpenCode 게이트웨이 `opencode.ai/zen/go/v1` 로 가고 업스트림
    # 모델 제공자에게 중계된다(2026-09-16 사용자 결정). 같은 호스트의 `opencode`(Zen) 공급자는 별도 검토 전까지 넣지 않는다.
    'opencode-go': 'opencode.ai',
}
PROVIDERS = set(PROVIDER_HOSTS)
# 공급자별 검토된 base URL 전체(경로 포함). 호스트만 비교하면 같은 호스트의 다른 API(`opencode.ai/zen/v1` Zen 등)로
# 라우팅을 바꿀 수 있다(2026-09-16 리뷰 HIGH). 바이너리 내장값·사용자 baseURL 모두 이 값과 정확히 같아야 한다.
PROVIDER_ENDPOINTS = {
    'alibaba': {'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'},
    'alibaba-cn': {'https://dashscope.aliyuncs.com/compatible-mode/v1'},
    'alibaba-coding-plan': {'https://coding-intl.dashscope.aliyuncs.com/v1'},
    'alibaba-coding-plan-cn': {'https://coding.dashscope.aliyuncs.com/v1'},
    'alibaba-token-plan': {'https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'},
    # DeepSeek 은 내장값이 루트이고 문서상 `/v1` 도 같은 OpenAI 호환 API 다(기존 사용자 override 를 유지).
    'deepseek': {'https://api.deepseek.com', 'https://api.deepseek.com/v1'},
    'zai-coding-plan': {'https://api.z.ai/api/coding/paas/v4'},
    'opencode-go': {'https://opencode.ai/zen/go/v1'},
}
# 가져오는 공급자 정의에서 허용하는 최상위 키. `api`·`headers`·중첩 SDK 지정은 라우팅·자격 증명 경로를 바꾸므로 받지 않는다.
PROVIDER_DEFINITION_KEYS = {'name', 'npm', 'options', 'models'}
# `{env:…}`·`{file:…}` 치환은 세션 환경(GH_TOKEN 등)이나 파일 내용을 요청에 실을 수 있다. 정의 어디에도 두지 않는다.
SUBSTITUTION = re.compile(r'\{(env|file):')
# 검토된 추가 모델 정의(`state/opencode-models.json`)에 허용하는 키. OpenCode 는 낯선 키에 엄격하고,
# `npm`·`options.baseURL` 같은 키는 공급자 경로를 바꿀 수 있어 받지 않는다.
EXTRA_MODEL_KEYS = {'name', 'limit', 'tool_call', 'reasoning', 'attachment', 'temperature', 'cost', 'options', 'modalities'}
EXTRA_MODEL_ID = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')


def parse_jsonc(text):
    token = r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/'
    text = re.sub(token, lambda m: m.group() if m.group().startswith('"') else '', text)
    text = re.sub(r'("(?:\\.|[^"\\])*")|,(\s*[}\]])',
                  lambda m: m.group(1) if m.group(1) else m.group(2), text)
    return json.loads(text)


def embedded_endpoints(binary):
    endpoints = {}
    for provider in PROVIDERS:
        match = re.search(rb'id:"' + re.escape(provider.encode()) +
                          rb'",env:\[[^\]]*\],npm:"[^"]+",api:"([^"]+)"', binary)
        if match:
            endpoints[provider] = match.group(1).decode('ascii')
    return endpoints


def load_extra_models():
    """가드 소유 `state/opencode-models.json`. 없으면 빈 사전. 형식은 {공급자: {모델ID: 정의}}."""
    path = ROOT / 'state/opencode-models.json'
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError('opencode-models.json must be an object keyed by provider')
    return data


def validate_extra_model(model_id, definition):
    """모델 ID 와 정의를 검사한다. 통과하면 깊은 복사본을 돌려준다."""
    if not isinstance(model_id, str) or not EXTRA_MODEL_ID.match(model_id):
        raise ValueError('Extra model id must be a short lowercase identifier')
    if not isinstance(definition, dict) or not isinstance(definition.get('name'), str):
        raise ValueError('Extra model definition must be an object with a name')
    unknown = set(definition) - EXTRA_MODEL_KEYS
    if unknown:
        raise ValueError('Extra model definition has unreviewed keys: ' + ', '.join(sorted(unknown)))
    limit = definition.get('limit', {})
    if not isinstance(limit, dict) or any(type(limit.get(k, 0)) is not int or limit.get(k, 0) < 0 for k in ('context', 'input', 'output')):
        raise ValueError('Extra model limit values must be non-negative integers')
    options = definition.get('options', {})
    if not isinstance(options, dict) or any(k.lower() in {'baseurl', 'apikey', 'headers', 'fetch'} for k in options):
        raise ValueError('Extra model options may not change the endpoint or credentials')
    return copy.deepcopy(definition)


def merge_extra_models(config, extras):
    """활성 공급자에 한해 추가 모델을 `provider.<id>.models` 에 병합한 설정 사본. 기존 정의는 유지한다."""
    merged = copy.deepcopy(config)
    enabled = set(merged.get('enabled_providers') or [])
    for provider, models in (extras or {}).items():
        if provider not in PROVIDERS:
            raise ValueError('Extra models reference an unreviewed provider')
        if provider not in enabled:
            continue
        if not isinstance(models, dict):
            raise ValueError('Extra models for a provider must be an object keyed by model id')
        definition = merged.setdefault('provider', {}).setdefault(provider, {})
        target = definition.setdefault('models', {})
        for model_id, model in models.items():
            target[model_id] = validate_extra_model(model_id, model)
    return merged


def refresh_models():
    """파생 설정만 다시 쓴다. 자격 증명·호스트 설정은 읽지 않는다."""
    state = ROOT / 'state'
    path = state / 'opencode-config.json'
    if not path.is_file():
        raise ValueError('opencode-config.json is missing; run the authorized import first')
    config = merge_extra_models(json.loads(path.read_text()), load_extra_models())
    publish_settings({path: config})


def opencode_assets(auth, source, endpoints):
    selected = {k: copy.deepcopy(v) for k, v in auth.items() if k in PROVIDERS}
    if not selected:
        raise ValueError('No requested provider credentials found')
    domains = []
    for key, value in selected.items():
        if not isinstance(value, dict) or value.get('type') != 'api' or not isinstance(value.get('key'), str):
            raise ValueError('Requested provider requires an unsupported credential flow')
        # Do not carry unrelated account metadata or fields into the protected profile.
        selected[key] = {'type': 'api', 'key': value['key']}
        endpoint = source.get('provider', {}).get(key, {}).get('options', {}).get('baseURL') or endpoints.get(key)
        parsed = urlsplit(endpoint or '')
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Provider endpoint must be reviewed before use')
        if parsed.hostname != PROVIDER_HOSTS[key] or parsed.port not in {None, 443}:
            raise ValueError('Provider endpoint must be reviewed before use')
        if (endpoint or '').rstrip('/') not in PROVIDER_ENDPOINTS[key]:
            raise ValueError('Provider endpoint must be reviewed before use')
        domains.append(parsed.hostname + ':443')
    config = {'$schema': 'https://opencode.ai/config.json', 'enabled_providers': sorted(selected),
              'share': 'disabled', 'plugin': [], 'mcp': {},
              'permission': {'*': 'ask', 'read': 'allow', 'external_directory': 'deny',
                             'webfetch': 'deny', 'websearch': 'deny'}}
    for field in ['model', 'small_model']:
        model = source.get(field)
        if isinstance(model, str) and model.split('/', 1)[0] in selected:
            config[field] = model
    definitions = {}
    for name in selected:
        definition = source.get('provider', {}).get(name)
        if definition:
            definitions[name] = sanitize_provider_definition(definition)
    if definitions:
        config['provider'] = definitions
    config = merge_extra_models(config, load_extra_models())
    return config, selected, {'domains': sorted(set(domains)), 'providers': sorted(selected)}


def contains_substitution(value):
    """정의 트리 어디든 `{env:` / `{file:` 문자열이 있으면 True."""
    if isinstance(value, str):
        return bool(SUBSTITUTION.search(value))
    if isinstance(value, dict):
        return any(contains_substitution(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_substitution(v) for v in value)
    return False


def sanitize_provider_definition(definition):
    """호스트 설정의 공급자 정의를 검토된 형태로만 옮긴다.

    왜. 정의는 사용자 소유지만 OpenCode 는 `options.headers`·모델별 `headers`·`provider.api`·중첩 `npm` 을 그대로 요청과
    SDK 로딩에 쓰고 `{env:GH_TOKEN}` 치환도 한다. 그대로 복사하면 세션의 GitHub 토큰이 헤더로 게이트웨이에 가거나
    검토 밖 SDK 가 샌드박스 안에서 실행된다(2026-09-16 리뷰 HIGH). 자격 증명은 격리 auth 저장소로만 준다.
    """
    if not isinstance(definition, dict):
        raise ValueError('Provider definition must be an object')
    unknown = set(definition) - PROVIDER_DEFINITION_KEYS
    if unknown:
        raise ValueError('Provider definition has unreviewed keys: ' + ', '.join(sorted(unknown)))
    if definition.get('npm') not in {None, '@ai-sdk/openai-compatible', '@ai-sdk/openai'}:
        raise ValueError('Custom provider SDK must be reviewed')
    if contains_substitution(definition):
        raise ValueError('Provider definition may not use env/file substitution')
    result = {}
    if 'name' in definition:
        if not isinstance(definition['name'], str):
            raise ValueError('Provider name must be a string')
        result['name'] = definition['name']
    if 'npm' in definition:
        result['npm'] = definition['npm']
    options = definition.get('options', {})
    if not isinstance(options, dict):
        raise ValueError('Provider options must be an object')
    kept = {k: copy.deepcopy(v) for k, v in options.items() if k != 'apiKey'}
    if any(k.lower() in {'headers', 'fetch', 'apikey'} for k in kept):
        raise ValueError('Provider options may not carry headers, fetch hooks or credentials')
    if kept:
        result['options'] = kept
    models = definition.get('models', {})
    if not isinstance(models, dict):
        raise ValueError('Provider models must be an object keyed by model id')
    if models:
        result['models'] = {model_id: validate_extra_model(model_id, model) for model_id, model in models.items()}
    return result


def add_zcode_hook(source):
    result = copy.deepcopy(source)
    hooks = result.setdefault('hooks', {})
    hooks['enabled'] = True
    events = hooks.setdefault('events', {})
    event = {'matcher': '*', 'hooks': [{'type': 'process', 'command': '/usr/bin/python3',
             'args': ['-I', str(ROOT / 'zcode_hook.py')], 'enabled': True, 'timeoutMs': 10000}]}
    current = events.setdefault('PreToolUse', [])
    # Replace our own declarations, including disabled hooks and narrow matchers.
    # Preserve unrelated hooks even when they share an event with ours.
    preserved = []
    for existing in current:
        remaining = [h for h in existing.get('hooks', [])
                     if str(ROOT / 'zcode_hook.py') not in h.get('args', [])]
        if remaining or not existing.get('hooks'):
            preserved.append(dict(existing, hooks=remaining))
    events['PreToolUse'] = [event, *preserved]
    permission = result.setdefault('permission', {})
    denied = permission.setdefault('disallowedTools', [])
    for name in ['js', 'js_reset', 'js_add_node_module_dir', 'CronCreate', 'CronUpdate']:
        if name not in denied:
            denied.append(name)
    return result


def stage_bytes(path, data):
    fd, temp = tempfile.mkstemp(prefix='.guard-config-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(temp)
        raise
    return Path(temp)


def publish_settings(updates):
    """Stage all files; restore the previous set on a recoverable write failure.

    This is exception rollback, not a cross-filesystem crash-atomic transaction.
    Callers serialize imports. Never discard recovery copies if rollback fails.
    """
    staged, backups, published = {}, {}, []
    keep_backups = False
    try:
        for path, value in updates.items():
            if path.is_symlink():
                raise ValueError('Refusing a symlink at a settings destination')
            if path.exists():
                backups[path] = stage_bytes(path, path.read_bytes())
            else:
                backups[path] = None
            staged[path] = stage_bytes(path, (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode())
        for path, temp in staged.items():
            os.replace(temp, path)
            published.append(path)
    except BaseException:
        restore_errors = []
        for path in reversed(published):
            try:
                if backups[path] is None:
                    path.unlink()
                else:
                    os.replace(backups[path], path)
            except OSError as error:
                restore_errors.append(error)
        if restore_errors:
            keep_backups = True
            raise RuntimeError('Settings rollback failed; private recovery copies were retained.') from None
        raise
    finally:
        for temp in [*staged.values(), *(backups.values() if not keep_backups else [])]:
            if temp is not None and temp.exists():
                temp.unlink()


def import_settings():
    # No shell startup files are evaluated. Only these explicitly named stores are read.
    auth_file = HOME / '.local/share/opencode/auth.json'
    opencode_file = HOME / '.config/opencode/opencode.jsonc'
    zcode_file = HOME / '.zcode/cli/config.json'
    auth = json.loads(auth_file.read_text())
    source = parse_jsonc(opencode_file.read_text())
    original_zcode = json.loads(zcode_file.read_text())
    config, scoped_auth, profile = opencode_assets(auth, source,
        embedded_endpoints((HOME / '.opencode/bin/opencode').read_bytes()))
    updated_zcode = add_zcode_hook(original_zcode)
    state = ROOT / 'state'
    backups = state / 'backups'
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backups / 'zcode-cli-config.before-guard.json'
    if not backup.exists():
        fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(original_zcode, out)
            out.write('\n')
    publish_settings({state / 'opencode-config.json': config,
                      state / 'opencode-auth.json': scoped_auth,
                      state / 'opencode-profile.json': profile,
                      zcode_file: updated_zcode})
    print('Selected OpenCode provider count:', len(scoped_auth))
    print('Zcode hook installed; credential values were not printed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--authorized-live-settings', action='store_true')
    group.add_argument('--refresh-models', action='store_true',
                       help='Re-merge state/opencode-models.json into the derived config without reading credentials.')
    options = parser.parse_args()
    state = ROOT / 'state'
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(state / '.settings-import.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if options.refresh_models:
            refresh_models()
            print('Derived OpenCode config refreshed with reviewed extra models.')
        else:
            import_settings()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Config parser exceptions can include fragments of credentials.
        raise SystemExit('Settings import failed; no credential values are shown. Inspect the local setup before retrying.')
