"""Offline candidate verification. No model request or credential import."""
import hashlib
import json
import re
import os
from pathlib import Path
import plistlib
import pwd
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
APP = Path('/Applications/ZCode.app')
OPENCODE = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.opencode/bin/opencode'
AUTOCLAW_APP = Path('/Applications/AutoClaw.app')
KIMI = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.kimi-code/bin/kimi'


def guard_paths():
    """The executable paths as resolved by agentbelt (config.json overrides included). Imported lazily because it is host only."""
    sys.path.insert(0, str(ROOT))
    import agentbelt
    return agentbelt


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


_MAX_JS_MODULES = 64
_MAX_JS_BYTES = 32 * 1024 * 1024
_JS_TRIVIA = re.compile(r'(?:\s+|//[^\r\n]*|/\*[\s\S]*?\*/)*')
_JS_BINDING = r'[A-Za-z_$][\w$]*'
_JS_NAMED = r'\{[^{};]*\}'
_JS_NAMESPACE = r'\*\s*as\s+' + _JS_BINDING
_JS_IMPORT = re.compile(
    r'''import(?=[\s{'"*])\s*(?:'''
    + r'(?:' + _JS_NAMED + '|' + _JS_NAMESPACE + r')\s*from\s*|'
    + _JS_BINDING + r'\s+from\s*|'
    + _JS_BINDING + r'\s*,\s*(?:' + _JS_NAMED + '|' + _JS_NAMESPACE + r')\s*from\s*'
    + r''')?(?P<quote>['"])(?P<specifier>[^'"\\\r\n]+)(?P=quote)[ \t]*(?:;|(?=\r?\n|\Z))''')
_JS_STRICT = re.compile(r'''(['"])use strict\1[ \t]*(?:;|(?=\r?\n|\Z))''')
_JS_RELATIVE = re.compile(r'\./(?:[A-Za-z0-9_$.-]+/)*[A-Za-z0-9_$.-]+\.js')


def _asar_index(stream):
    header = stream.read(16)
    if len(header) != 16:
        raise ValueError('invalid application index')
    tag, header_size, payload_size, size = struct.unpack('<4I', header)
    start, end = 8 + header_size, os.fstat(stream.fileno()).st_size
    if (tag != 4 or size > 32 * 1024 * 1024 or payload_size + 4 != header_size
            or not 0 <= start - 16 - size <= 3 or start > end):
        raise ValueError('invalid application index')
    return json.loads(stream.read(size)), start, end


def _asar_text(stream, index, start, end, path):
    node = index
    try:
        for name in path.split('/'):
            node = node['files'][name]
        size, offset = node['size'], node['offset']
    except (KeyError, TypeError):
        raise ValueError('unexpected application entry') from None
    if (node.get('unpacked') or 'link' in node or type(size) is not int
            or not 0 <= size <= 16 * 1024 * 1024 or not isinstance(offset, str)
            or not re.fullmatch(r'[0-9]{1,20}', offset)):
        raise ValueError('unexpected application entry')
    offset = int(offset)
    if start + offset + size > end:
        raise ValueError('unexpected application entry')
    stream.seek(start + offset)
    body = stream.read(size)
    if len(body) != size:
        raise ValueError('truncated application entry')
    return body.decode('utf-8')


def asar_text(path, app=None):
    app = Path(app) if app is not None else APP
    with (app / 'Contents/Resources/app.asar').open('rb') as stream:
        return _asar_text(stream, *_asar_index(stream), path)


def _module_imports(text):
    """Read the bundler's leading static ESM imports, not arbitrary JS strings.

    Unsupported syntax is left for manual review when required markers cannot
    be found. This is a compatibility heuristic, not a JavaScript evaluator.
    """
    cursor = 0
    while True:
        cursor = _JS_TRIVIA.match(text, cursor).end()
        directive = _JS_STRICT.match(text, cursor)
        if directive:
            cursor = directive.end()
            continue
        match = _JS_IMPORT.match(text, cursor)
        if not match:
            return
        cursor = match.end()
        specifier = match.group('specifier')
        if not specifier.startswith('.'):
            continue  # Built-in and package imports are not ASAR chunk evidence.
        if not _JS_RELATIVE.fullmatch(specifier) or any(p in {'.', '..'} for p in specifier[2:].split('/')):
            raise ValueError('unexpected application module import')
        yield specifier[2:]


def _bundled_texts(app, entry):
    """Follow only linked, packed JS in the entry's component, with finite limits."""
    texts, pending, discovered, total = [], [entry], {entry}, 0
    if _MAX_JS_MODULES < 1:
        raise ValueError('application module budget exceeded')
    with (app / 'Contents/Resources/app.asar').open('rb') as stream:
        index, start, end = _asar_index(stream)
        while pending:
            path = pending.pop()
            text = _asar_text(stream, index, start, end, path)
            total += len(text.encode('utf-8'))
            if total > _MAX_JS_BYTES:
                raise ValueError('application module budget exceeded')
            texts.append(text)
            parent = path.rsplit('/', 1)[0]
            for name in _module_imports(text):
                target = parent + '/' + name
                if target not in discovered:
                    if len(discovered) >= _MAX_JS_MODULES:
                        raise ValueError('application module budget exceeded')
                    discovered.add(target)
                    pending.append(target)
    return texts


def autoclaw_candidate(app=AUTOCLAW_APP):
    """If it is installed, the AutoClaw app version and the version and hash of the bundled Zcode CLI. None if it is not (optional install).

    The hash is taken from the fixed path the guard actually executes (darwin-arm64/zcode). If the
    manifest points at a different file, that file is not what was reviewed, so it is refused.
    """
    app = Path(app)
    if not (app / 'Contents/Info.plist').is_file():
        return None
    with (app / 'Contents/Info.plist').open('rb') as stream:
        version = plistlib.load(stream)['CFBundleShortVersionString']
    manifest = json.loads((app / 'Contents/Resources/zcode/manifest.json').read_text())
    if manifest['artifacts']['darwin-arm64']['file'] != 'darwin-arm64/zcode':
        raise ValueError('AutoClaw manifest names an unexpected Zcode binary')
    executable = app / 'Contents/Resources/zcode/darwin-arm64/zcode'
    return {'version': version, 'zcodeCliVersion': manifest['zcodeCliVersion'], 'zcodeSha256': digest(executable)}


def kimi_candidate(binary=None):
    """If it is installed, the version and hash of Kimi Code. None if it is not (optional install).

    The version probe runs with a temporary HOME and with telemetry and auto-update turned off. `--version` only prints the built-in build information and exits.
    """
    binary = Path(binary) if binary is not None else guard_paths().KIMI
    if not binary.is_file():
        return None
    # Running a not-yet-reviewed candidate on the host as is would let that binary read the clipboard and host files before it is
    # checked (review HIGH). The probe also runs inside the guard policy: no network, the one binary file as the only read, stdout only.
    sys.path.insert(0, str(ROOT))
    import agentbelt
    with tempfile.TemporaryDirectory(prefix='guard-kimi-version-', dir=Path.home()) as work, tempfile.TemporaryFile() as out:
        status = agentbelt.run_confined('kimi-probe', Path(work), [str(binary), '--version'], domains=[], ephemeral=True,
                                          # If stderr is a file outside the sandbox, Node aborts with fstat EPERM (REPAIRS 2026-09-16). Pinned to /dev/null.
                                          extra_reads=[binary], stdout=out, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          extra_env={'KIMI_DISABLE_TELEMETRY': '1', 'KIMI_CODE_NO_AUTO_UPDATE': '1',
                                                     'KIMI_CLI_NO_AUTO_UPDATE': '1'})
        out.seek(0)
        version = out.read(4096).decode(errors='replace').strip()
    if status or not version or len(version) > 50 or any(c not in '0123456789.-abcdefghijklmnopqrstuvwxyz' for c in version):
        raise ValueError('Kimi Code version probe failed')
    return {'version': version, 'sha256': digest(binary)}


def merged_baseline(current, saved):
    """Preserve the saved optional entries on top of the new candidate. If the baseline were cleared just because the app is momentarily absent, a reinstall would bless any hash."""
    merged = dict(current)
    for optional in ('opencode', 'zcode', 'mobile', 'autoclaw', 'kimi'):
        if optional not in merged and optional in (saved or {}):
            merged[optional] = saved[optional]
    return merged


def opencode_candidate():
    """Version and hash of the installed OpenCode binary, or None when it is not installed."""
    binary = guard_paths().OPENCODE
    if not binary.is_file():
        return None
    with tempfile.TemporaryDirectory(prefix='guard-version-') as home:
        run = subprocess.run([str(binary), '--version'], cwd=home, capture_output=True,
                             text=True, timeout=15, env={
            'HOME': home, 'PATH': '/usr/bin:/bin', 'OPENCODE_DISABLE_AUTOUPDATE': 'true',
            'OPENCODE_DISABLE_MODELS_FETCH': 'true', 'OPENCODE_DISABLE_PROJECT_CONFIG': 'true'})
    version = run.stdout.strip()
    if run.returncode or not version or len(version) > 50 or any(c not in '0123456789.-abcdefghijklmnopqrstuvwxyz' for c in version):
        raise ValueError('OpenCode version probe failed')
    return {'version': version, 'sha256': digest(binary)}


def zcode_candidate(app=None):
    """Version and hashes of the installed Zcode desktop app, or None when it is not installed.

    Required markers must remain together in an entry or its linked static chunks.
    Full archive/CLI hashes still determine whether the reviewed baseline matches.
    """
    app = Path(app) if app is not None else APP
    if not (app / 'Contents/Info.plist').is_file():
        return None
    with (app / 'Contents/Info.plist').open('rb') as stream:
        zcode_version = plistlib.load(stream)['CFBundleShortVersionString']
    host = _bundled_texts(app, 'out/host/index.js')
    desktop = _bundled_texts(app, 'out/main/index.js')
    if not any(all(value in text for value in ['ZCODE_AGENT_SERVER_COMMAND', 'ZCODE_AGENT_SERVER_ARGS_JSON',
                                              'resolveDefaultZCodeAgentCommand', 'workspacePath']) for text in host):
        raise ValueError('Zcode backend routing needs review')
    if not any(all(value in text for value in ['createWebRemoteControlManager', 'relayWsUrl']) for text in desktop):
        raise ValueError('Zcode mobile relay routing needs review')
    return {'version': zcode_version,
            'asarSha256': digest(app / 'Contents/Resources/app.asar'),
            'agentSha256': digest(app / 'Contents/Resources/glm/zcode.cjs')}


def candidate():
    """Baseline entries for every installed agent. Each integration is optional; an empty result means no agent is installed."""
    result = {}
    opencode = opencode_candidate()
    if opencode is not None:
        result['opencode'] = opencode
    zcode = zcode_candidate()
    if zcode is not None:
        result['zcode'] = zcode
        result['mobile'] = 'desktop relay code present; phone pairing requires a device check'
    autoclaw = autoclaw_candidate()
    if autoclaw is not None:
        result['autoclaw'] = autoclaw
    kimi = kimi_candidate()
    if kimi is not None:
        result['kimi'] = kimi
    return result


def main():
    before = candidate()
    if not before:
        raise ValueError('No supported agent is installed; nothing to verify')
    env = {'HOME': pwd.getpwuid(os.getuid()).pw_dir, 'PATH': '/usr/bin:/bin',
           'DEVELOPER_DIR': '/Library/Developer/CommandLineTools', 'LANG': 'en_US.UTF-8'}
    run = subprocess.run(['/usr/bin/python3', '-m', 'unittest', 'discover', '-s', 'tests'],
                         cwd=ROOT, env=env, timeout=240)
    if run.returncode:
        raise ValueError('Compatibility tests failed; baseline unchanged')
    after = candidate()
    if before != after:
        raise ValueError('An application changed during verification; baseline unchanged')
    # Reuse staged publication and failure restoration for the two non-secret profiles.
    sys.path.insert(0, str(ROOT))
    from adapters.configure_existing import publish_settings
    baseline_path = ROOT / 'state/compatibility.json'
    saved = json.loads(baseline_path.read_text()) if baseline_path.is_file() else {}
    before = merged_baseline(before, saved)
    updates = {baseline_path: before}
    profile_path = ROOT / 'state/zcode-profile.json'
    if 'zcode' in before and profile_path.is_file():
        profile = json.loads(profile_path.read_text())
        profile['reviewedDesktopVersion'] = before['zcode']['version']
        updates[profile_path] = profile
    autoclaw_profile_path = ROOT / 'state/autoclaw-profile.json'
    if 'autoclaw' in before and autoclaw_profile_path.is_file():
        autoclaw_profile = json.loads(autoclaw_profile_path.read_text())
        autoclaw_profile['reviewedAppVersion'] = before['autoclaw']['version']
        autoclaw_profile['zcodeCliVersion'] = before['autoclaw']['zcodeCliVersion']
        updates[autoclaw_profile_path] = autoclaw_profile
    publish_settings(updates)
    print('Offline compatibility checks passed; installed versions recorded.')
    print('Phone pairing and live model permissions were not tested.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Compatibility verification failed; do not bypass the existing version gate.')
