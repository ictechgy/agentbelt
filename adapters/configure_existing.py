#!/usr/bin/python3
"""Explicitly authorized import of selected model settings; never prints values."""
import argparse
import copy
import fcntl
import json
import os
import sys
import pwd
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # The home from the account database (not the environment variable)
PROVIDER_HOSTS = {
    'alibaba': 'dashscope-intl.aliyuncs.com',
    'alibaba-cn': 'dashscope.aliyuncs.com',
    'alibaba-coding-plan': 'coding-intl.dashscope.aliyuncs.com',
    'alibaba-coding-plan-cn': 'coding.dashscope.aliyuncs.com',
    'alibaba-token-plan': 'token-plan.ap-southeast-1.maas.aliyuncs.com',
    'deepseek': 'api.deepseek.com',
    # GLM Coding Plan. The OpenAI-compatible coding endpoint on the z.ai host that Zcode and packet-ask already use.
    'zai-coding-plan': 'api.z.ai',
    # OpenCode Go ($10 subscription, a bundle of open-weight models). Requests go to the OpenCode gateway `opencode.ai/zen/go/v1`
    # and are relayed to the upstream model provider (user decision 2026-09-16). The `opencode` (Zen) provider on the same host is not added until it is reviewed separately.
    'opencode-go': 'opencode.ai',
}
PROVIDERS = set(PROVIDER_HOSTS)
# The full reviewed base URL for each provider (path included). Comparing only the host would allow routing to be switched to a
# different API on the same host (Zen at `opencode.ai/zen/v1` and the like) (review HIGH 2026-09-16). Both the value built into the binary and the user's baseURL must be exactly this value.
PROVIDER_ENDPOINTS = {
    'alibaba': {'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'},
    'alibaba-cn': {'https://dashscope.aliyuncs.com/compatible-mode/v1'},
    'alibaba-coding-plan': {'https://coding-intl.dashscope.aliyuncs.com/v1'},
    'alibaba-coding-plan-cn': {'https://coding.dashscope.aliyuncs.com/v1'},
    'alibaba-token-plan': {'https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'},
    # For DeepSeek the built-in value is the root and, per the documentation, `/v1` is the same OpenAI-compatible API (this keeps an existing user override).
    'deepseek': {'https://api.deepseek.com', 'https://api.deepseek.com/v1'},
    'zai-coding-plan': {'https://api.z.ai/api/coding/paas/v4'},
    'opencode-go': {'https://opencode.ai/zen/go/v1'},
}
# The top-level keys allowed in an imported provider definition. `api`, `headers` and a nested SDK selection are not accepted because they change routing and credential paths.
PROVIDER_DEFINITION_KEYS = {'name', 'npm', 'options', 'models'}
# `{env:...}` and `{file:...}` substitution can put the session environment (GH_TOKEN and the like) or file contents into a request. They are allowed nowhere in a definition.
SUBSTITUTION = re.compile(r'\{(env|file):')
# The keys allowed in the reviewed extra model definitions (`state/opencode-models.json`). OpenCode is strict about unfamiliar
# keys, and keys such as `npm` and `options.baseURL` are not accepted because they can change the provider path.
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
    """The guard-owned `state/opencode-models.json`. An empty dictionary if it is missing. The format is {provider: {model id: definition}}."""
    path = ROOT / 'state/opencode-models.json'
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError('opencode-models.json must be an object keyed by provider')
    return data


def validate_extra_model(model_id, definition):
    """Validate the model id and the definition. If they pass, return a deep copy."""
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
    """A copy of the config with the extra models merged into `provider.<id>.models`, for enabled providers only. Existing definitions are kept."""
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
    """Rewrite only the derived configuration. Credentials and host settings are not read."""
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
    """True if the string `{env:` or `{file:` appears anywhere in the definition tree."""
    if isinstance(value, str):
        return bool(SUBSTITUTION.search(value))
    if isinstance(value, dict):
        return any(contains_substitution(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_substitution(v) for v in value)
    return False


def sanitize_provider_definition(definition):
    """Carry the provider definition from the host configuration over only in its reviewed form.

    Why. The definition belongs to the user, but OpenCode uses `options.headers`, per-model `headers`, `provider.api` and
    a nested `npm` directly for requests and SDK loading, and it also performs `{env:GH_TOKEN}` substitution. Copying it
    as is would send the session's GitHub token to the gateway as a header, or run an unreviewed SDK inside the sandbox
    (review HIGH 2026-09-16). Credentials are supplied only through the isolated auth store.
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


def opencode_binary():
    """The OpenCode binary as resolved by agent_guard (config.json override included). Lazy import: host-only path."""
    sys.path.insert(0, str(ROOT))
    import agent_guard
    return agent_guard.OPENCODE


def import_settings():
    # No shell startup files are evaluated. Only these explicitly named stores are read.
    auth_file = HOME / '.local/share/opencode/auth.json'
    opencode_file = HOME / '.config/opencode/opencode.jsonc'
    zcode_file = HOME / '.zcode/cli/config.json'
    auth = json.loads(auth_file.read_text())
    source = parse_jsonc(opencode_file.read_text())
    original_zcode = json.loads(zcode_file.read_text())
    config, scoped_auth, profile = opencode_assets(auth, source,
        embedded_endpoints(opencode_binary().read_bytes()))
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
