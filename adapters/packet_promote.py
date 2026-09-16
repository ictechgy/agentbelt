"""Host-only module in which the supervisor promotes packet-ask at the sandboxed agent's request.

It moves a procedure people used to carry out by hand into code, but enforces the invariants more strictly than a person would.
1. The PyPI release exists and the provenance publisher of both files (wheel and sdist) is exactly the pinned value.
2. The requested version is higher than the currently pinned version.
3. After installation the four files the adapter uses are byte identical to the previous install and the hook surface is still there.
4. The full guard test suite passes.
If even one of them does not hold, the previous version is installed again, the pinned version is restored and the refusal reason is returned.
A promotion in which the adapter surface changed is exactly what a person has to look at, so only then does it go to a person.
The trust boundary is the pinned publisher (the user's GitHub release workflow).
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agentbelt  # noqa: E402

# Any release that is not from this publisher is refused. The user's release workflow is the trust boundary.
PINNED_PUBLISHER = {'kind': 'GitHub', 'repository': 'ictechgy/packet-ask', 'workflow': 'release.yml'}
# The files the isolation adapter (packet_entry.py) depends on. If they change, a person has to review the adapter again.
ADAPTER_FILES = ('scope.py', 'launch.py', 'doctor.py', 'paths.py')
HOOK_MARKER = 'def set_confined_env_hooks('
UV = agentbelt.OWNER_HOME / '.local/bin/uv'
PACKET_ASK_BIN = agentbelt.PACKET_VENV / 'bin/packet-ask'
AUDIT_FILE = ROOT / 'state/packet-relay/promotions.jsonl'


def parse_version(text):
    """Only x.y.z is allowed. A shell metacharacter or a suffix is not a version."""
    parts = str(text).split('.')
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise agentbelt.GuardError('version must be plain x.y.z, got ' + repr(str(text))[:40])
    return tuple(int(part) for part in parts)


def fetch_json(url):
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.pypi.integrity.v1+json, application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def check_release(version, current, fetch=fetch_json):
    """Check existence on PyPI, the publisher and the version ordering, and return the file list (name, URL, sha256)."""
    requested, pinned = parse_version(version), parse_version(current)
    if requested <= pinned:
        raise agentbelt.GuardError('requested ' + version + ' is not newer than the pinned ' + current)
    catalog = fetch('https://pypi.org/pypi/packet-ask/json')
    entries = catalog.get('releases', {}).get(version, [])
    if not entries:
        raise agentbelt.GuardError('packet-ask ' + version + ' is not on PyPI')
    artifacts = []
    for entry in entries:
        name = entry.get('filename'); url = entry.get('url'); digest = (entry.get('digests') or {}).get('sha256')
        if not isinstance(name, str) or not name or '/' in name or not name.startswith('packet_ask-'):
            raise agentbelt.GuardError('unexpected release file name on PyPI')
        if not isinstance(url, str) or not url.startswith('https://files.pythonhosted.org/'):
            raise agentbelt.GuardError('unexpected release file host for ' + name)
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise agentbelt.GuardError('missing sha256 digest for ' + name)
        bundles = fetch('https://pypi.org/integrity/packet-ask/' + version + '/' + name + '/provenance').get('attestation_bundles', [])
        publishers = [{key: (bundle.get('publisher') or {}).get(key) for key in PINNED_PUBLISHER} for bundle in bundles]
        if not publishers or any(publisher != PINNED_PUBLISHER for publisher in publishers):
            raise agentbelt.GuardError('provenance publisher for ' + name + ' is not the pinned release workflow')
        artifacts.append({'filename': name, 'url': url, 'sha256': digest})
    return {'version': version, 'files': [a['filename'] for a in artifacts], 'artifacts': artifacts}


def fetch_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def download_verified_wheel(info, fetch_bytes=fetch_bytes, directory=None):
    """Download the exact wheel whose provenance was checked, compare its sha256 and return the local path.

    If uv resolves PyPI independently, the file that was checked and the file that gets installed can differ (review HIGH).
    Installing by handing over a local wheel binds verification and installation to the same bytes.
    """
    wheels = [a for a in info['artifacts'] if a['filename'].endswith('.whl')]
    if len(wheels) != 1:
        raise agentbelt.GuardError('expected exactly one wheel for packet-ask ' + info['version'])
    wheel = wheels[0]
    data = fetch_bytes(wheel['url'])
    if hashlib.sha256(data).hexdigest() != wheel['sha256']:
        raise agentbelt.GuardError('downloaded wheel does not match the PyPI sha256 for ' + wheel['filename'])
    target = Path(directory or tempfile.mkdtemp(prefix='packet-ask-wheel-')) / wheel['filename']
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
    return target


def installed_package_dir():
    """The packet_ask package directory of the host uv tool."""
    result = subprocess.run([str(agentbelt.PACKET_PYTHON), '-I', '-c', 'import packet_ask, os; print(os.path.dirname(packet_ask.__file__))'],
                            stdout=subprocess.PIPE, text=True, timeout=30)
    if result.returncode or not result.stdout.strip():
        raise agentbelt.GuardError('could not locate the installed packet_ask package')
    return Path(result.stdout.strip())


def uv_install(version, wheel=None):
    """Install on the host. If a wheel is given, use that verified file; otherwise (rollback) use the pinned version from PyPI."""
    parse_version(version)
    spec = str(wheel) if wheel is not None else 'packet-ask==' + version
    result = subprocess.run([str(UV), 'tool', 'install', spec, '--force', '--refresh'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
    if result.returncode:
        raise agentbelt.GuardError('uv tool install failed: ' + result.stdout[-800:])


def run_guard_tests():
    """The full guard suite. The promotion hangs on this result."""
    result = subprocess.run(['/usr/bin/python3', '-m', 'unittest', 'discover', '-s', 'tests'], cwd=str(ROOT),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    return result.returncode == 0 and '\nOK' in result.stdout


def reinstall_skills():
    result = subprocess.run([str(PACKET_ASK_BIN), 'install-skills', '--force'], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=120)
    if result.returncode:
        raise agentbelt.GuardError('install-skills failed: ' + result.stdout[-500:])


def snapshot(package_dir, destination):
    shutil.copytree(str(package_dir), str(destination), ignore=shutil.ignore_patterns('__pycache__'))
    return destination


def changed_adapter_files(before, after):
    """Return which adapter files changed and, if the hook surface has disappeared, that fact as a name."""
    changed = [name for name in ADAPTER_FILES
               if not (after / name).is_file() or (before / name).read_bytes() != (after / name).read_bytes()]
    if (after / 'paths.py').is_file() and HOOK_MARKER not in (after / 'paths.py').read_text():
        changed.append('paths.py:' + HOOK_MARKER.strip('('))
    return changed


def write_pin(state_file, version):
    """Write the pinned version to a temporary file and then rename it. This removes the window between unlink and write in which the file does not exist."""
    temporary = state_file.with_name(state_file.name + '.tmp')
    if temporary.exists():
        temporary.unlink()
    agentbelt.write_private_json(temporary, {'version': version})
    os.replace(str(temporary), str(state_file))


def promote(version, fetch=fetch_json, install=uv_install, run_tests=run_guard_tests, install_skills=reinstall_skills,
            package_dir=None, state_file=None, audit_file=AUDIT_FILE, fetch_bytes=fetch_bytes):
    """The whole promotion procedure. Any failure after installation reinstalls the previous version and restores the pin, then raises GuardError."""
    state_file = Path(state_file) if state_file else agentbelt.PACKET_ASK_VERSION_FILE
    current = json.loads(state_file.read_text())['version']
    info = check_release(version, current, fetch=fetch)
    package_dir = Path(package_dir) if package_dir else installed_package_dir()
    with tempfile.TemporaryDirectory(prefix='packet-ask-prev-') as tmp:
        before = snapshot(package_dir, Path(tmp) / 'before')
        wheel = download_verified_wheel(info, fetch_bytes=fetch_bytes, directory=Path(tmp))
        install(version, wheel)
        try:
            changed = changed_adapter_files(before, package_dir)
            if changed:
                raise agentbelt.GuardError('adapter surface changed in ' + version + ': ' + ', '.join(changed)
                                             + '. Reinstalled ' + current + '; a human must review the adapter.')
            write_pin(state_file, version)
            if not run_tests():
                raise agentbelt.GuardError('guard test suite failed on ' + version + '; reinstalled ' + current + '.')
            install_skills()
        except BaseException as problem:
            # Every failure after installation takes the same rollback, including a test timeout, a file error or a failed skill install.
            write_pin(state_file, current)
            install(current)
            outcome = 'refused-adapter-changed' if 'adapter surface changed' in str(problem) else 'rolled-back-' + type(problem).__name__
            _audit(audit_file, current, version, outcome, [])
            if isinstance(problem, agentbelt.GuardError):
                raise
            raise agentbelt.GuardError('promotion of ' + version + ' failed (' + type(problem).__name__
                                         + '); reinstalled ' + current + '.') from None
    _audit(audit_file, current, version, 'promoted', [])
    return ('packet-ask promoted ' + current + ' -> ' + version + '\n'
            '- provenance publisher: ' + PINNED_PUBLISHER['repository'] + ' ' + PINNED_PUBLISHER['workflow'] + '\n'
            '- adapter files unchanged: ' + ', '.join(ADAPTER_FILES) + '\n'
            '- guard test suite: OK\n- skills reinstalled\n- files: ' + ', '.join(info['files']) + '\n')


def _audit(audit_file, current, version, outcome, details):
    agentbelt.private_dir(Path(audit_file).parent)
    descriptor = os.open(str(audit_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, 'a') as stream:
        stream.write(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%S'), 'from': current, 'to': version,
                                 'outcome': outcome, 'details': details}) + '\n')
