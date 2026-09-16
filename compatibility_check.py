"""Offline candidate verification. No model request or credential import."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
APP = Path('/Applications/ZCode.app')
OPENCODE = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.opencode/bin/opencode'
AUTOCLAW_APP = Path('/Applications/AutoClaw.app')
KIMI = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.kimi-code/bin/kimi'


def guard_paths():
    """agent_guard 가 해석한 실행 파일 경로(config.json 재정의 포함). 호스트 전용이라 지연 import 한다."""
    sys.path.insert(0, str(ROOT))
    import agent_guard
    return agent_guard


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def asar_text(path):
    with (APP / 'Contents/Resources/app.asar').open('rb') as stream:
        header = stream.read(16)
        size = struct.unpack('<I', header[12:16])[0]
        if size > 32 * 1024 * 1024:
            raise ValueError('invalid application index')
        index = json.loads(stream.read(size))
        node = index
        for name in path.split('/'):
            node = node['files'][name]
        if node.get('unpacked') or node['size'] > 16 * 1024 * 1024:
            raise ValueError('unexpected application entry')
        stream.seek(8 + struct.unpack('<I', header[4:8])[0] + int(node['offset']))
        return stream.read(node['size']).decode('utf-8')


def autoclaw_candidate(app=AUTOCLAW_APP):
    """설치돼 있으면 AutoClaw 앱 버전과 번들 Zcode CLI 의 버전·해시. 없으면 None(선택 설치).

    해시는 가드가 실제로 실행하는 고정 경로(darwin-arm64/zcode)에서 구한다. 매니페스트가 다른 파일을
    가리키면 검토 대상이 아니므로 거부한다.
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
    """설치돼 있으면 Kimi Code 의 버전·해시. 없으면 None(선택 설치).

    버전 프로브는 임시 HOME 과 텔레메트리·자동 갱신 끔으로 돈다. `--version` 은 내장 빌드 정보만 찍고 끝난다.
    """
    binary = Path(binary) if binary is not None else guard_paths().KIMI
    if not binary.is_file():
        return None
    # 아직 검토되지 않은 후보를 호스트에서 그대로 실행하면 그 바이너리가 검사 전에 클립보드·호스트 파일을 읽을 수 있다
    # (리뷰 HIGH). 프로브도 가드 정책 안에서 돌린다: 네트워크 없음, 읽기는 바이너리 한 파일, stdout 만 받는다.
    sys.path.insert(0, str(ROOT))
    import agent_guard
    with tempfile.TemporaryDirectory(prefix='guard-kimi-version-', dir=Path.home()) as work, tempfile.TemporaryFile() as out:
        status = agent_guard.run_confined('kimi-probe', Path(work), [str(binary), '--version'], domains=[], ephemeral=True,
                                          # stderr 가 샌드박스 밖 파일이면 Node 가 fstat EPERM 으로 abort 한다(REPAIRS 2026-09-16). /dev/null 로 고정.
                                          extra_reads=[binary], stdout=out, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          extra_env={'KIMI_DISABLE_TELEMETRY': '1', 'KIMI_CODE_NO_AUTO_UPDATE': '1',
                                                     'KIMI_CLI_NO_AUTO_UPDATE': '1'})
        out.seek(0)
        version = out.read(4096).decode(errors='replace').strip()
    if status or not version or len(version) > 50 or any(c not in '0123456789.-abcdefghijklmnopqrstuvwxyz' for c in version):
        raise ValueError('Kimi Code version probe failed')
    return {'version': version, 'sha256': digest(binary)}


def merged_baseline(current, saved):
    """새 후보 위에 저장된 선택 항목(autoclaw)을 보존한다. 앱이 잠시 없다고 기준선을 지우면 재설치가 아무 해시나 축복한다."""
    merged = dict(current)
    for optional in ('autoclaw', 'kimi'):
        if optional not in merged and optional in (saved or {}):
            merged[optional] = saved[optional]
    return merged


def candidate():
    with (APP / 'Contents/Info.plist').open('rb') as stream:
        zcode_version = plistlib.load(stream)['CFBundleShortVersionString']
    host = asar_text('out/host/index.js')
    desktop = asar_text('out/main/index.js')
    if not all(value in host for value in ['ZCODE_AGENT_SERVER_COMMAND', 'ZCODE_AGENT_SERVER_ARGS_JSON',
                                          'resolveDefaultZCodeAgentCommand', 'workspacePath']):
        raise ValueError('Zcode backend routing needs review')
    if not all(value in desktop for value in ['createWebRemoteControlManager', 'relayWsUrl']):
        raise ValueError('Zcode mobile relay routing needs review')
    with tempfile.TemporaryDirectory(prefix='guard-version-') as home:
        run = subprocess.run([str(guard_paths().OPENCODE), '--version'], cwd=home, capture_output=True,
                             text=True, timeout=15, env={
            'HOME': home, 'PATH': '/usr/bin:/bin', 'OPENCODE_DISABLE_AUTOUPDATE': 'true',
            'OPENCODE_DISABLE_MODELS_FETCH': 'true', 'OPENCODE_DISABLE_PROJECT_CONFIG': 'true'})
    version = run.stdout.strip()
    if run.returncode or not version or len(version) > 50 or any(c not in '0123456789.-abcdefghijklmnopqrstuvwxyz' for c in version):
        raise ValueError('OpenCode version probe failed')
    return {'opencode': {'version': version, 'sha256': digest(guard_paths().OPENCODE)},
            'zcode': {'version': zcode_version,
                      'asarSha256': digest(APP / 'Contents/Resources/app.asar'),
                      'agentSha256': digest(APP / 'Contents/Resources/glm/zcode.cjs')},
            'mobile': 'desktop relay code present; phone pairing requires a device check',
            **({'autoclaw': autoclaw} if (autoclaw := autoclaw_candidate()) is not None else {}),
            **({'kimi': kimi} if (kimi := kimi_candidate()) is not None else {})}


def main():
    before = candidate()
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
    from configure_existing import publish_settings
    profile_path = ROOT / 'state/zcode-profile.json'
    profile = json.loads(profile_path.read_text())
    profile['reviewedDesktopVersion'] = before['zcode']['version']
    baseline_path = ROOT / 'state/compatibility.json'
    saved = json.loads(baseline_path.read_text()) if baseline_path.is_file() else {}
    before = merged_baseline(before, saved)
    updates = {baseline_path: before, profile_path: profile}
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
