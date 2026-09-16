"""샌드박스 에이전트의 요청으로 감독자가 packet-ask 를 승격하는 호스트 전용 모듈.

사람이 손으로 하던 절차를 코드로 옮기되, 불변 조건은 사람보다 엄격하게 강제한다.
1. PyPI 릴리스가 존재하고 두 파일(wheel·sdist)의 provenance 게시자가 고정값과 정확히 같다.
2. 요청 버전이 현재 고정 버전보다 높다.
3. 설치 뒤 어댑터가 쓰는 네 파일이 이전 설치본과 바이트 동일하고 훅 표면이 남아 있다.
4. 가드 전체 테스트가 통과한다.
하나라도 어긋나면 이전 버전을 다시 설치하고 고정 버전을 되돌린 뒤 거부 사유를 돌려준다.
어댑터 표면이 바뀐 승격이야말로 사람이 봐야 하므로 그때만 사람에게 넘어간다.
신뢰 경계는 고정 게시자(사용자의 GitHub 릴리스 워크플로)다.
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

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import agent_guard  # noqa: E402

# 이 게시자가 아닌 릴리스는 무엇이든 거부한다. 사용자의 릴리스 워크플로가 신뢰 경계다.
PINNED_PUBLISHER = {'kind': 'GitHub', 'repository': 'ictechgy/packet-ask', 'workflow': 'release.yml'}
# 격리 어댑터(packet_entry.py)가 의존하는 파일. 바뀌면 사람이 어댑터를 다시 검토해야 한다.
ADAPTER_FILES = ('scope.py', 'launch.py', 'doctor.py', 'paths.py')
HOOK_MARKER = 'def set_confined_env_hooks('
UV = agent_guard.OWNER_HOME / '.local/bin/uv'
PACKET_ASK_BIN = agent_guard.PACKET_VENV / 'bin/packet-ask'
AUDIT_FILE = ROOT / 'state/packet-relay/promotions.jsonl'


def parse_version(text):
    """x.y.z 만 허용한다. 셸 메타문자나 접미사는 버전이 아니다."""
    parts = str(text).split('.')
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise agent_guard.GuardError('version must be plain x.y.z, got ' + repr(str(text))[:40])
    return tuple(int(part) for part in parts)


def fetch_json(url):
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.pypi.integrity.v1+json, application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def check_release(version, current, fetch=fetch_json):
    """PyPI 존재·게시자·버전 순서를 검사하고 파일 목록(이름·URL·sha256)을 돌려준다."""
    requested, pinned = parse_version(version), parse_version(current)
    if requested <= pinned:
        raise agent_guard.GuardError('requested ' + version + ' is not newer than the pinned ' + current)
    catalog = fetch('https://pypi.org/pypi/packet-ask/json')
    entries = catalog.get('releases', {}).get(version, [])
    if not entries:
        raise agent_guard.GuardError('packet-ask ' + version + ' is not on PyPI')
    artifacts = []
    for entry in entries:
        name = entry.get('filename'); url = entry.get('url'); digest = (entry.get('digests') or {}).get('sha256')
        if not isinstance(name, str) or not name or '/' in name or not name.startswith('packet_ask-'):
            raise agent_guard.GuardError('unexpected release file name on PyPI')
        if not isinstance(url, str) or not url.startswith('https://files.pythonhosted.org/'):
            raise agent_guard.GuardError('unexpected release file host for ' + name)
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise agent_guard.GuardError('missing sha256 digest for ' + name)
        bundles = fetch('https://pypi.org/integrity/packet-ask/' + version + '/' + name + '/provenance').get('attestation_bundles', [])
        publishers = [{key: (bundle.get('publisher') or {}).get(key) for key in PINNED_PUBLISHER} for bundle in bundles]
        if not publishers or any(publisher != PINNED_PUBLISHER for publisher in publishers):
            raise agent_guard.GuardError('provenance publisher for ' + name + ' is not the pinned release workflow')
        artifacts.append({'filename': name, 'url': url, 'sha256': digest})
    return {'version': version, 'files': [a['filename'] for a in artifacts], 'artifacts': artifacts}


def fetch_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def download_verified_wheel(info, fetch_bytes=fetch_bytes, directory=None):
    """provenance 를 검사한 바로 그 wheel 을 받아 sha256 을 대조한 뒤 로컬 경로를 돌려준다.

    uv 가 PyPI 를 독립적으로 해석하면 검사한 파일과 설치되는 파일이 달라질 수 있다(리뷰 HIGH).
    로컬 wheel 을 넘겨 설치하면 검증과 설치가 같은 바이트에 묶인다.
    """
    wheels = [a for a in info['artifacts'] if a['filename'].endswith('.whl')]
    if len(wheels) != 1:
        raise agent_guard.GuardError('expected exactly one wheel for packet-ask ' + info['version'])
    wheel = wheels[0]
    data = fetch_bytes(wheel['url'])
    if hashlib.sha256(data).hexdigest() != wheel['sha256']:
        raise agent_guard.GuardError('downloaded wheel does not match the PyPI sha256 for ' + wheel['filename'])
    target = Path(directory or tempfile.mkdtemp(prefix='packet-ask-wheel-')) / wheel['filename']
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
    return target


def installed_package_dir():
    """호스트 uv 도구의 packet_ask 패키지 디렉터리."""
    result = subprocess.run([str(agent_guard.PACKET_PYTHON), '-I', '-c', 'import packet_ask, os; print(os.path.dirname(packet_ask.__file__))'],
                            stdout=subprocess.PIPE, text=True, timeout=30)
    if result.returncode or not result.stdout.strip():
        raise agent_guard.GuardError('could not locate the installed packet_ask package')
    return Path(result.stdout.strip())


def uv_install(version, wheel=None):
    """호스트에 설치한다. wheel 이 주어지면 검증된 그 파일을, 아니면(롤백) PyPI 의 고정 버전을 쓴다."""
    parse_version(version)
    spec = str(wheel) if wheel is not None else 'packet-ask==' + version
    result = subprocess.run([str(UV), 'tool', 'install', spec, '--force', '--refresh'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
    if result.returncode:
        raise agent_guard.GuardError('uv tool install failed: ' + result.stdout[-800:])


def run_guard_tests():
    """가드 전체 스위트. 승격은 이 결과에 걸려 있다."""
    result = subprocess.run(['/usr/bin/python3', '-m', 'unittest', 'discover', '-s', 'tests'], cwd=str(ROOT),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    return result.returncode == 0 and '\nOK' in result.stdout


def reinstall_skills():
    result = subprocess.run([str(PACKET_ASK_BIN), 'install-skills', '--force'], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=120)
    if result.returncode:
        raise agent_guard.GuardError('install-skills failed: ' + result.stdout[-500:])


def snapshot(package_dir, destination):
    shutil.copytree(str(package_dir), str(destination), ignore=shutil.ignore_patterns('__pycache__'))
    return destination


def changed_adapter_files(before, after):
    """어댑터 파일 중 바뀐 것과, 훅 표면이 사라졌으면 그 사실을 이름으로 돌려준다."""
    changed = [name for name in ADAPTER_FILES
               if not (after / name).is_file() or (before / name).read_bytes() != (after / name).read_bytes()]
    if (after / 'paths.py').is_file() and HOOK_MARKER not in (after / 'paths.py').read_text():
        changed.append('paths.py:' + HOOK_MARKER.strip('('))
    return changed


def write_pin(state_file, version):
    """고정 버전을 임시 파일에 쓴 뒤 rename 한다. unlink→쓰기 사이에 파일이 없는 창을 없앤다."""
    temporary = state_file.with_name(state_file.name + '.tmp')
    if temporary.exists():
        temporary.unlink()
    agent_guard.write_private_json(temporary, {'version': version})
    os.replace(str(temporary), str(state_file))


def promote(version, fetch=fetch_json, install=uv_install, run_tests=run_guard_tests, install_skills=reinstall_skills,
            package_dir=None, state_file=None, audit_file=AUDIT_FILE, fetch_bytes=fetch_bytes):
    """승격 절차 전체. 설치 이후 어떤 실패든 이전 버전 재설치·고정 복원 뒤 GuardError 를 낸다."""
    state_file = Path(state_file) if state_file else agent_guard.PACKET_ASK_VERSION_FILE
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
                raise agent_guard.GuardError('adapter surface changed in ' + version + ': ' + ', '.join(changed)
                                             + '. Reinstalled ' + current + '; a human must review the adapter.')
            write_pin(state_file, version)
            if not run_tests():
                raise agent_guard.GuardError('guard test suite failed on ' + version + '; reinstalled ' + current + '.')
            install_skills()
        except BaseException as problem:
            # 설치 이후의 모든 실패는 같은 롤백을 탄다. 테스트 시간 초과·파일 오류·스킬 설치 실패도 포함.
            write_pin(state_file, current)
            install(current)
            outcome = 'refused-adapter-changed' if 'adapter surface changed' in str(problem) else 'rolled-back-' + type(problem).__name__
            _audit(audit_file, current, version, outcome, [])
            if isinstance(problem, agent_guard.GuardError):
                raise
            raise agent_guard.GuardError('promotion of ' + version + ' failed (' + type(problem).__name__
                                         + '); reinstalled ' + current + '.') from None
    _audit(audit_file, current, version, 'promoted', [])
    return ('packet-ask promoted ' + current + ' -> ' + version + '\n'
            '- provenance publisher: ' + PINNED_PUBLISHER['repository'] + ' ' + PINNED_PUBLISHER['workflow'] + '\n'
            '- adapter files unchanged: ' + ', '.join(ADAPTER_FILES) + '\n'
            '- guard test suite: OK\n- skills reinstalled\n- files: ' + ', '.join(info['files']) + '\n')


def _audit(audit_file, current, version, outcome, details):
    agent_guard.private_dir(Path(audit_file).parent)
    descriptor = os.open(str(audit_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, 'a') as stream:
        stream.write(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%S'), 'from': current, 'to': version,
                                 'outcome': outcome, 'details': details}) + '\n')
