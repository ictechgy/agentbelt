#!/usr/bin/python3
"""Fail-closed macOS launchers. No shell startup files or ambient credentials."""
import argparse
import base64
import hashlib
import json
import os
import plistlib
import pwd
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent


def owner_account():
    """실행 계정의 passwd 항목. HOME 환경변수가 아니라 계정 DB 를 쓴다.

    왜. 샌드박스 안의 훅(zcode_hook)도 이 모듈을 import 하는데 그곳의 HOME 은 격리 홈이다. HOME 으로 소유자
    홈을 정하면 워크스페이스 경계 판정(`workspace_path`)이 격리 홈 기준으로 틀어진다. 계정 DB 조회는
    Seatbelt 가 허용하는 opendirectoryd libinfo 로 양쪽에서 같은 답을 준다.
    """
    return pwd.getpwuid(os.getuid())


def load_path_config():
    """`ROOT/config.json` 의 경로 재정의(설치기가 쓴다). 없거나 못 읽으면(샌드박스 안) 빈 사전.

    키: ownerHome, node, opencode, claude, packetAskVenv, kimi, autoclawApp. 값은 절대 경로 문자열.
    """
    try:
        data = json.loads((ROOT / 'config.json').read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def newest_nvm_node(home):
    """설정이 없을 때의 Node 후보: nvm 의 가장 높은 버전, 없으면 Homebrew. 실행 시점에 없으면 run_confined 가 닫힌다."""
    candidates = list((home / '.nvm/versions/node').glob('v*/bin/node'))
    if candidates:
        def version(path):
            return tuple(int(part) for part in path.parents[1].name.lstrip('v').split('.') if part.isdigit())
        return max(candidates, key=version)
    for candidate in ('/opt/homebrew/bin/node', '/usr/local/bin/node'):
        if Path(candidate).is_file():
            return Path(candidate)
    return home / '.nvm/versions/node/current/bin/node'


_PATHS = load_path_config()
OWNER_ACCOUNT = owner_account()
OWNER_HOME = Path(_PATHS.get('ownerHome') or OWNER_ACCOUNT.pw_dir)
OWNER_USER = OWNER_ACCOUNT.pw_name
NODE = Path(_PATHS.get('node') or newest_nvm_node(OWNER_HOME))
OPENCODE = Path(_PATHS.get('opencode') or OWNER_HOME / '.opencode/bin/opencode')
# AutoClaw(z.ai) 는 자체 Zcode CLI 를 번들한다. 코딩 턴마다 이 바이너리를 우리 격리 안에서 띄운다.
AUTOCLAW_APP = Path(_PATHS.get('autoclawApp') or '/Applications/AutoClaw.app')
AUTOCLAW_ZCODE = AUTOCLAW_APP / 'Contents/Resources/zcode/darwin-arm64/zcode'
# Zcode CLI 는 워크스페이스의 `.zcode/config.json`·`zcode.json`(훅·MCP 포함)과 `.agents/mcp.json` 을 읽는다.
# 자식이 이걸 심으면 PreToolUse 훅을 끌 수 있으므로 두 모드 모두 쓰기를 막는다.
ZCODE_WORKSPACE_CONFIG_PATHS = ['.zcode', 'zcode.json', '.agents/mcp.json']
PACKET_VENV = Path(_PATHS.get('packetAskVenv') or OWNER_HOME / '.local/share/uv/tools/packet-ask')
PACKET_PYTHON = PACKET_VENV / 'bin/python'
CLAUDE = Path(_PATHS.get('claude') or OWNER_HOME / '.local/bin/claude')
# Kimi Code CLI(Moonshot). Node SEA 단일 바이너리이며 네이티브 클립보드 바인딩을 번들한다.
# kimi 모드는 이 경로만 읽기 허용에 넣고, 실행 전 state/compatibility.json 의 해시와 대조한다.
KIMI = Path(_PATHS.get('kimi') or OWNER_HOME / '.kimi-code/bin/kimi')
# 검토된 packet-ask 버전은 소스가 아니라 state/packet-ask-version.json 한 곳에만 둔다.
# 승격 중계가 상태 파일만 바꾸면 되고, 가드 코드는 호스트에서만 바뀐다.
PACKET_ASK_VERSION_FILE = ROOT / 'state/packet-ask-version.json'


def packet_ask_pinned_version():
    """검토된 packet-ask 버전. 파일이 없거나 형식이 다르면 실행을 거부한다(닫힘)."""
    try:
        value = json.loads(PACKET_ASK_VERSION_FILE.read_text()).get('version')
    except (OSError, ValueError, AttributeError):
        raise GuardError('state/packet-ask-version.json is missing; the packet-ask adapter has no reviewed version.') from None
    if not isinstance(value, str) or not all(part.isdigit() for part in value.split('.')) or value.count('.') != 2:
        raise GuardError('state/packet-ask-version.json must hold a plain x.y.z version.')
    return value
SECRET_NAMES = [
    '.env*', '.ENV*', '*.env', '*.env.*', '*.pem', '*.key', '*.p12', '*.pfx', '*.keystore',
    'id_rsa*', 'id_ed25519*', 'auth.json', 'credentials', 'credentials.*',
    'secrets', 'secrets.*', '.ssh', '.aws', '.azure', '.kube', '.gnupg',
    '.npmrc', '.netrc', '.pypirc', '*.sqlite', '*.sqlite3', '*.db', '*.dump',
]


class GuardError(Exception):
    pass


def private_dir(path):
    if path.is_symlink():
        raise GuardError('Refusing a symlink at a guard-owned directory.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise GuardError('Guard-owned directories must be owned by you and mode 700.')
    return path


def write_private_json(path, value):
    data = (json.dumps(value, indent=2) + '\n').encode()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def write_private_file(root, relative, text, mode=0o600):
    """감독자가 자식이 쓸 수 있는 트리(격리 홈) 안에 파일을 쓸 때의 유일한 경로.

    왜 필요한가. 이전 세션의 에이전트가 격리 홈에 심볼릭 링크를 심어 두면, 비격리 감독자가
    O_CREAT|O_TRUNC 로 여는 순간 호스트 임의 파일이 잘리거나 토큰이 그 파일에 기록된다(네
    트랙 리뷰 CRITICAL). root 는 감독자 소유 경로여야 하고, 그 아래는 O_NOFOLLOW 디렉터리
    fd 로 한 컴포넌트씩 내려가며 링크·타인 소유를 거부한다. 최종 이름이 이미 있으면 링크
    자체를 unlink 하고 O_CREAT|O_EXCL|O_NOFOLLOW 로 새로 만든다.
    """
    relative = Path(relative)
    parts = relative.parts
    if relative.is_absolute() or not parts or any(part in ('.', '..') for part in parts):
        raise GuardError('Refusing to write outside the isolated tree: ' + str(relative))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(str(root), flags)
    except OSError:
        raise GuardError('Isolated tree root is missing or is a link: ' + str(root)) from None
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError:
                raise GuardError('Refusing to write through a link or non-directory in the isolated home: ' + part) from None
            os.close(descriptor)
            descriptor = child
            if os.fstat(descriptor).st_uid != os.getuid():
                raise GuardError('Isolated home directory is not owned by you: ' + part)
        name = parts[-1]
        try:
            os.lstat(name, dir_fd=descriptor)
            exists = True
        except FileNotFoundError:
            exists = False
        if exists:
            try:
                os.unlink(name, dir_fd=descriptor)  # 링크라면 링크 자체만 지운다
            except OSError:
                raise GuardError('Refusing to replace a non-file at ' + str(relative)) from None
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=descriptor)
        with os.fdopen(out, 'w') as stream:
            stream.write(text)
    finally:
        os.close(descriptor)


def link_opencode_auth(home, source):
    """Use fd-relative, no-follow operations beneath an owned isolated home."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(str(home), flags)
    try:
        for part in ['.local', 'share', 'opencode']:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise GuardError('Isolated OpenCode data directories must be private.')
        try:
            os.symlink(str(source), 'auth.json', dir_fd=descriptor)
        except FileExistsError:
            if not stat.S_ISLNK(os.stat('auth.json', dir_fd=descriptor, follow_symlinks=False).st_mode):
                raise GuardError('Unexpected auth store in the isolated OpenCode home; refusing to replace it.')
            if os.readlink('auth.json', dir_fd=descriptor) != str(source):
                raise GuardError('Unexpected auth store in the isolated OpenCode home; refusing to replace it.')
    finally:
        os.close(descriptor)


def workspace_path(raw, scan_hardlinks=True):
    path = Path(raw).expanduser().resolve(strict=True)
    if any(c in str(path) for c in '*?[]{}\\') or any(ord(c) < 32 for c in str(path)):
        raise GuardError('Workspace names cannot contain sandbox glob metacharacters or control characters.')
    if not path.is_dir():
        raise GuardError('Workspace must be a directory.')
    if path == OWNER_HOME or OWNER_HOME not in path.parents:
        raise GuardError('Choose one project directory inside your home, not the home itself.')
    relative = path.relative_to(OWNER_HOME)
    if relative.parts[0].startswith('.'):
        raise GuardError('Hidden home directories cannot be used as workspaces.')
    if relative.as_posix().casefold() in {'desktop', 'documents', 'downloads', 'library', 'pictures', 'movies', 'music', 'public'}:
        raise GuardError('Choose a project subdirectory, not an entire personal folder.')
    if relative.parts[0].casefold() == 'library':
        raise GuardError('Library cannot be used as a workspace.')
    # Existing hardlinks can expose an inode via an otherwise allowed pathname.
    # Never follow symlinks; the kernel enforces their resolved target at access time.
    def scan_error(error):
        raise GuardError('Cannot inspect the complete workspace; restore directory access before launching.') from None

    # 하드링크는 다른 경로(특히 워크스페이스 밖)의 inode 를 노출할 수 있어 검사한다. 링크 수만큼의
    # 경로가 전부 워크스페이스 안에서 발견되면 노출이 없으므로 허용한다(OMC 가 체크포인트와 claim
    # 마커를 같은 폴더에 하드링크 쌍으로 만든다). 하나라도 밖에 있으면 거부한다.
    linked = {}
    for directory, dirs, files in os.walk(path, followlinks=False, onerror=scan_error) if scan_hardlinks else []:
        for name in files:
            entry = Path(directory) / name
            try:
                info = entry.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                scan_error(error)
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                seen, expected = linked.get((info.st_dev, info.st_ino), (0, info.st_nlink))
                linked[(info.st_dev, info.st_ino)] = (seen + 1, expected)
    if any(seen < expected for seen, expected in linked.values()):
        raise GuardError('Workspace contains files hardlinked from outside it; use an independent work copy.')
    return path


def host_git_identity():
    """호스트 전역 gitconfig 의 user.name/user.email. 둘 다 한 줄짜리 평범한 값일 때만 돌려준다.

    커밋 작성자 신원은 이미 모든 커밋에 공개되는 값이라 격리 홈에 복사해도 새어 나가는 비밀이 아니다.
    """
    values = []
    for key in ('user.name', 'user.email'):
        result = subprocess.run(['/usr/bin/git', 'config', '--global', '--get', key], capture_output=True, text=True,
                                env={'HOME': str(OWNER_HOME), 'PATH': '/usr/bin:/bin'})
        value = result.stdout.strip() if result.returncode == 0 else ''
        if not value or '\n' in value or len(value) > 200 or any(ord(c) < 32 for c in value) or '[' in value or ']' in value:
            return None
        values.append(value)
    return tuple(values)


def clean_environment(home, github=None):
    tmp = private_dir(home / 'tmp')
    # 빈 .npmrc 로 호스트의 실제 ~/.npmrc 를 무시한다. 매 실행 링크 안전하게 다시 만든다.
    write_private_file(home, '.npmrc', '')
    # 격리 홈에는 전역 gitconfig 가 없어 작성자가 `사용자@호스트명` 이 된다. 호스트 신원의 이름·이메일만 심고
    # 자식이 못 바꾸게 잠근다(run_confined 의 denyWrite). 나머지 전역·시스템 설정은 계속 /dev/null 이다.
    identity = host_git_identity()
    git_config_global = '/dev/null'
    if identity:
        write_private_file(home, '.gitconfig', '[user]\n\tname = ' + identity[0] + '\n\temail = ' + identity[1] + '\n')
        git_config_global = str(home / '.gitconfig')
    else:
        stale = home / '.gitconfig'
        if stale.is_symlink() or stale.exists():
            os.unlink(str(stale))
    env = {
        'HOME': str(home),
        'PATH': ':'.join([str(NODE.parent), '/opt/homebrew/bin', '/Library/Developer/CommandLineTools/usr/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
        'SHELL': '/bin/bash', 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
        'DEVELOPER_DIR': '/Library/Developer/CommandLineTools',
        'TMPDIR': str(tmp), 'CLAUDE_CODE_TMPDIR': str(tmp),
        # clang/swift 의 기본 모듈 캐시는 /var/folders 아래라 막힌다. 캐시가 없으면 swift 가 stdlib 를
        # 인터페이스에서 다시 빌드하다 "SDK not supported by the compiler" 로 죽는다(툴체인 고장 아님).
        'CLANG_MODULE_CACHE_PATH': str(tmp / 'clang-module-cache'),
        'XDG_CONFIG_HOME': str(home / '.config'),
        'XDG_DATA_HOME': str(home / '.local/share'),
        'XDG_CACHE_HOME': str(home / '.cache'),
        'XDG_STATE_HOME': str(home / '.local/state'),
        # Dart looks in ~/.pub-cache; point it at the isolated home so the real
        # one stays closed and each project fetches its own.
        'PUB_CACHE': str(home / '.pub-cache'),
        'GIT_CONFIG_GLOBAL': git_config_global, 'GIT_CONFIG_SYSTEM': '/dev/null',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1',
        'OPENSSL_CONF': '/dev/null',
        # npm refuses to start when both paths name the same file ("double-loading
        # config"). An empty file in the isolated home ignores the operator's real
        # ~/.npmrc just as effectively.
        'NPM_CONFIG_USERCONFIG': str(home / '.npmrc'), 'NPM_CONFIG_GLOBALCONFIG': '/dev/null',
        'PIP_CONFIG_FILE': '/dev/null', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
        # JVM 은 user.home 을 계정 DB 에서, java.io.tmpdir 을 Darwin 임시 디렉터리에서 얻어 둘 다 닫힌 경로에
        # 쓴다(Gradle 래퍼가 실제 ~/.gradle 에, Kotlin 데몬이 /var/folders/…/T 에 쓰다 EPERM). 격리 홈으로 돌린다.
        # 샌드박스 런타임은 자기 프록시 에이전트 플래그를 이 값 앞에 덧붙인다(보존됨).
        'JAVA_TOOL_OPTIONS': '-Duser.home=' + str(home) + ' -Djava.io.tmpdir=' + str(tmp),
        'MAVEN_OPTS': '-Duser.home=' + str(home) + ' -Djava.io.tmpdir=' + str(tmp),
        'GRADLE_USER_HOME': str(home / '.gradle'),
        # Gradle 의 FSEvents 파일 감시는 샌드박스에서 시작되지 않아 경고만 낸다. 꺼서 조용히 한다.
        'GRADLE_OPTS': '-Dorg.gradle.vfs.watch=false',
        'DISABLE_AUTOUPDATER': '1', 'DISABLE_TELEMETRY': '1',
        'DISABLE_ERROR_REPORTING': '1', 'DO_NOT_TRACK': '1',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1',
        'CLAUDE_CODE_DISABLE_AUTO_MEMORY': '1', 'ENABLE_CLAUDEAI_MCP_SERVERS': 'false',
        'OPENCODE_DISABLE_AUTOUPDATE': 'true',
        'OPENCODE_DISABLE_MODELS_FETCH': 'true',
        'OPENCODE_DISABLE_PROJECT_CONFIG': 'true',
        'OPENCODE_DISABLE_CLAUDE_CODE': 'true',
        'OPENCODE_DISABLE_DEFAULT_PLUGINS': 'true',
        'OPENCODE_DISABLE_EXTERNAL_SKILLS': 'true',
        'OPENCODE_DISABLE_LSP_DOWNLOAD': 'true',
        'OPENCODE_DISABLE_SHARE': 'true',
    }
    if not github:
        # 토큰을 주지 않는 실행에서는 앞선 실행이 남긴 자격 증명 파일도 지운다(지속 격리 홈 공유 방지).
        stale = home / '.git-credentials'
        if stale.is_symlink() or stale.exists():
            os.unlink(str(stale))
    if github:
        # The scoped token reaches git through the isolated home only. Global and
        # system git config stay at /dev/null, so nothing else can supply it.
        store = home / '.git-credentials'
        write_private_file(home, '.git-credentials', 'https://x-access-token:' + github + '@github.com\n')
        env.update({'GH_TOKEN': github, 'GITHUB_TOKEN': github,
                    'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'credential.helper',
                    'GIT_CONFIG_VALUE_0': 'store --file ' + str(store)})
    for name in ['TERM', 'COLORTERM', 'COLUMNS', 'LINES']:
        value = os.environ.get(name)
        if value and len(value) < 100 and all(c.isalnum() or c in '-_.' for c in value):
            env[name] = value
    # Derive terminal capabilities from inherited descriptors, never a caller's
    # environment. The supervisor verifies device identity before granting ioctl.
    terminals = set()
    for descriptor in (0, 1, 2):
        if os.isatty(descriptor):
            terminals.add(os.ttyname(descriptor))
    env['AGENT_GUARD_TTY_PATHS'] = json.dumps(sorted(terminals))
    return env


def darwin_temporary_items():
    """Foundation 이 원자적 쓰기에 쓰는 Darwin 사용자 임시 디렉터리의 TemporaryItems.

    SwiftPM·llbuild 는 output-file-map 과 manifest 를 원자적으로 쓴다. 이 폴더에 쓰기만 열면 되고
    읽기는 열지 않는다(스크린샷 같은 사용자 임시 파일이 여기 잠시 머문다). Foundation 은 TMPDIR 을
    무시하고 confstr 로 이 경로를 얻는다.
    """
    # Python 의 confstr 는 이 이름을 모른다. getconf 가 같은 libc 호출을 한다.
    result = subprocess.run(['/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR'], stdout=subprocess.PIPE, text=True, timeout=10)
    base = result.stdout.strip()
    if result.returncode or not base.startswith('/var/folders/') or any(c in base for c in '*?[]{}\\'):
        raise GuardError('Could not determine the Darwin user temporary directory.')
    return str(Path(base) / 'TemporaryItems')


def darwin_temp_directories():
    """NSTemporaryDirectory() 아래에 읽기·쓰기를 열어 줄 하위 디렉터리 이름(옵트인).

    cartograph 처럼 TMPDIR 을 무시하고 confstr 임시 디렉터리에 캐시를 두는 도구를 위한 것이다.
    이름은 평범한 폴더 이름만 허용한다. `xcrun_db-*` 같은 호스트 도구 해석 캐시는 넣지 말 것:
    샌드박스가 쓴 값이 호스트 xcrun 을 속일 수 있다.
    """
    names = development_options().get('darwinTempDirectories', [])
    if not isinstance(names, list):
        raise GuardError('darwinTempDirectories must be a list of folder names.')
    base = Path(darwin_temporary_items()).parent
    paths = []
    for name in names:
        if not isinstance(name, str) or not name or name.startswith('.') or not all(c.isalnum() or c in '-_' for c in name):
            raise GuardError('darwinTempDirectories entries must be plain folder names, got ' + repr(name)[:40])
        paths.append(str(base / name))
    return paths


def sandbox_policy(workspace, home, domains, extra_reads=()):
    system_reads = [
        '/System/Library', '/usr/lib', '/usr/share', '/usr/bin', '/bin', '/sbin', '/usr/sbin',
        '/Library/Developer/CommandLineTools',
        '/Library/Apple/usr/libexec/oah/libRosettaRuntime',
        '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom', '/dev/tty',
        '/private/etc/hosts', '/private/etc/resolv.conf', '/private/var/run/resolv.conf',
        '/private/etc/services', '/private/etc/protocols', '/private/etc/localtime',
        '/private/etc/ssl/cert.pem', '/private/etc/ssl/openssl.cnf',
    ]
    # The node bin directory carries npm and friends; one binary is not enough.
    # Homebrew holds development tools the operator already installed (dart, gh) and
    # is read-only here, so it grants tooling, not data.
    executable_reads = [NODE.parent, NODE.resolve(), OPENCODE.resolve(), CLAUDE.resolve(),
                        PACKET_VENV.resolve(), PACKET_PYTHON.resolve().parents[1],
                        ROOT / 'packet_entry.py', NODE.parent.parent / 'lib/node_modules',
                        Path('/opt/homebrew')]
    # uv can use an intermediate runtime alias as well as the resolved binary.
    # Relative venv links must be interpreted from bin/, not the current directory.
    if PACKET_PYTHON.is_symlink():
        try:
            linked_python = (PACKET_PYTHON.parent / PACKET_PYTHON.readlink()).absolute()
        except OSError:
            raise GuardError('The packet Python link could not be resolved.') from None
        executable_reads.append(linked_python.parents[1])
    deny_secrets = [str(workspace / '**' / name) for name in SECRET_NAMES]
    temp_directories = darwin_temp_directories()
    # Homebrew 는 도구(bin·Cellar·opt)를 위해 열지만 `var` 는 서비스 데이터(postgresql@16 DB·redis dump·로그)라 닫는다
    # (2026-09-16 리뷰 HIGH, 사용자 승인). `etc` 는 ca-certificates·openssl 설정이라 Homebrew 도구의 TLS 에 필요해 유지.
    deny_homebrew_data = ['/opt/homebrew/var']
    return {
        'network': {'allowedDomains': list(domains), 'deniedDomains': [],
                    'allowLocalBinding': False, 'allowUnixSockets': [], 'allowAllUnixSockets': False},
        'filesystem': {
            'denyRead': ['/', *deny_secrets, *deny_homebrew_data],
            'allowRead': [*system_reads, *map(str, executable_reads), str(workspace), str(home),
                          *map(str, extra_reads), *temp_directories],
            # TemporaryItems 는 쓰기만. Foundation 원자적 쓰기가 여기서 임시 파일을 만든다.
            # 옵트인 임시 하위 디렉터리(cartograph 캐시 등)는 읽기·쓰기 모두.
            'allowWrite': [str(workspace), str(home), darwin_temporary_items(), *temp_directories],
            'denyWrite': [*deny_secrets, str(workspace / '.git/hooks'), str(workspace / '.git/config'),
                          str(workspace / '.git/config.worktree'), str(workspace / '.git/info/attributes'),
                          '/tmp/claude', '/private/tmp/claude'],
        },
        'allowPty': False, 'allowAppleEvents': False,
        'enableWeakerNetworkIsolation': False, 'enableWeakerNestedSandbox': False,
    }


def runtime_status(name, value):
    directory = private_dir(ROOT / 'state/runtime')
    fd, temporary = tempfile.mkstemp(prefix='.status-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
        os.replace(temporary, directory / name)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def process_started_at(pid):
    """Pair a pid with its start time so a recycled pid is never mistaken for the owner."""
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, text=True)
    return result.stdout.strip()


def reap_control_directories(state):
    """Remove control directories whose owning launcher is provably gone.

    A directory without an owner marker predates this bookkeeping or belongs to a
    launcher that is still running, so it is left in place; reclaiming disk is
    never worth deleting a live isolated home. Reaping failures never block a
    launch.
    """
    for directory in state.glob('control-*'):
        try:
            owner = json.loads((directory / 'owner.json').read_text())
            if process_started_at(owner['pid']) == owner['started']:
                continue
            shutil.rmtree(directory)
        except (OSError, ValueError, KeyError):
            continue


def free_loopback_port():
    """호스트에서 지금 비어 있는 127.0.0.1 포트 하나. 세션 시작 뒤 충돌 가능성은 남지만 드물다."""
    import socket
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def short_temp_directory(mode, workspace):
    """모드·워크스페이스별 짧은 가드 소유 임시 디렉터리(`state/t/<7hex>`). 소켓 경로 한도 안에 들어야 한다.

    한도 계산: sun_path 104 바이트 - `/znr-<uuid>.sock`(46) = 57 자. 설치 경로 50 자 + 7 hex = 57.
    """
    identity = hashlib.sha256((mode + '\0' + str(workspace)).encode()).hexdigest()[:7]
    directory = private_dir(private_dir(private_dir(ROOT / 'state') / 't') / identity)
    if len(str(directory)) > 57:
        raise GuardError('The guard install path is too long for a unix socket temp directory.')
    return directory


def persistent_home(mode, workspace):
    """모드·워크스페이스별 지속 격리 홈. run_confined 와 중계기가 같은 경로를 봐야 한다."""
    identity = hashlib.sha256(str(workspace).encode()).hexdigest()[:20]
    state = private_dir(ROOT / 'state')
    return private_dir(private_dir(private_dir(state / 'homes') / mode) / identity)


def run_confined(mode, workspace, command, domains=(), extra_env=None, extra_reads=(), ephemeral=False,
                 prepare_home=None, private_sockets=False, read_only_home_paths=(), dev_ports=(), stdout=None, stdin=None,
                 protect_opencode_config=False, opencode_plugins=(), instruction_files=(), notice_extra='',
                 loopback_port=False, config_credentials=(), github=True, read_only_workspace_paths=(),
                 short_tmpdir=False, loopback_all=False, allow_gradle_keystore=False, stderr=None):
    if sys.platform != 'darwin' or not Path('/usr/bin/sandbox-exec').exists():
        raise GuardError('This launcher requires macOS Seatbelt; there is no unsandboxed fallback.')
    if not NODE.is_file() or not (ROOT / 'runtime/node_modules/@anthropic-ai/sandbox-runtime/package.json').is_file():
        raise GuardError('Pinned sandbox runtime is missing; refusing to launch.')
    state = private_dir(ROOT / 'state')
    reap_control_directories(state)
    control = Path(tempfile.mkdtemp(prefix='control-', dir=state))
    short_tmp = None
    try:
        # Record the owner before anything else can fail. Every later step, and an
        # abrupt kill of this launcher, must still leave a directory the next run
        # can reclaim.
        write_private_json(control / 'owner.json',
                           {'pid': os.getpid(), 'started': process_started_at(os.getpid())})
        home = private_dir(control / 'home') if ephemeral else persistent_home(mode, workspace)
        # AutoClaw 처럼 승인 UI 없이 자동 승인으로 도는 런타임에는 GitHub 토큰을 주지 않는다.
        env = clean_environment(home, github_token() if github else None)
        if short_tmpdir:
            # 유닉스 소켓 경로는 sun_path 한도(104바이트)를 넘으면 EINVAL 이다. 격리 홈 tmp 는 88자라
            # `$TMPDIR/znr-<uuid>.sock`(46자) 같은 소켓을 못 만든다. 짧은 가드 소유 tmp 를 대신 준다.
            short_tmp = short_temp_directory(mode, workspace)
            env.update({'TMPDIR': str(short_tmp), 'CLAUDE_CODE_TMPDIR': str(short_tmp),
                        'CLANG_MODULE_CACHE_PATH': str(short_tmp / 'clang-module-cache')})
        env.update(extra_env or {})
        if any(type(port) is not int or not 1024 <= port <= 65535 for port in dev_ports):
            raise GuardError('Development ports must be integers from 1024 to 65535.')
        dev_ports = list(dev_ports)
        if loopback_port:
            # 에이전트 세션마다 전용 루프백 포트 하나. dart 커버리지의 VM 서비스처럼 로컬 포트가
            # 꼭 필요한 도구가 무작위 포트 대신 이 포트를 쓰게 한다. 무작위 바인드는 계속 막힌다.
            env['AGENT_GUARD_LOOPBACK_PORT'] = str(free_loopback_port())
            dev_ports.append(int(env['AGENT_GUARD_LOOPBACK_PORT']))
        env['AGENT_GUARD_DEV_PORTS'] = json.dumps(sorted(set(dev_ports)))
        if prepare_home:
            prepare_home(home, env)
        configuration_home = None
        config_directory = None
        if protect_opencode_config:
            # Keep session data/cache in the persistent XDG paths, but never load
            # configuration planted in a previous session's writable HOME.
            configuration_home = private_dir(control / 'runtime-home')
            config_root = private_dir(configuration_home / '.config')
            config_directory = private_dir(config_root / 'opencode')
            legacy_directory = private_dir(configuration_home / '.opencode')
            # The pinned OpenCode build initializes this file before loading config.
            # Seed it on the host so startup needs no write to protected directories.
            for directory in (config_directory, legacy_directory):
                descriptor = os.open(str(directory / '.gitignore'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    stream.write('node_modules\npackage.json\npackage-lock.json\nbun.lock\n.gitignore\n')
            # Seeded by the trusted supervisor before Seatbelt starts; the child
            # cannot add or replace plugins because the directory stays read-only.
            for plugin in opencode_plugins:
                shutil.copyfile(str(plugin), str(private_dir(config_directory / 'plugin') / Path(plugin).name))
            env.update({'HOME': str(configuration_home), 'XDG_CONFIG_HOME': str(config_root),
                        'OPENCODE_CONFIG_DIR': str(config_directory)})
        # 자식이 실제로 읽는 config 디렉터리에 자격 증명을 하드링크한다. XDG_CONFIG_HOME 은
        # 보호 모드면 runtime-home 으로 바뀌므로 여기서(확정 후) 링크해야 한다.
        for relative, source in config_credentials:
            if relative == 'dart/pub-credentials.json':
                link_pub_credentials(env['XDG_CONFIG_HOME'], source)
            else:
                hardlink_credential(source, Path(env['XDG_CONFIG_HOME']) / relative)
        if loopback_all:
            # 워크스페이스별 옵트인: 임의 루프백 포트 바인드·수신·자기 접속을 연다(JVM 빌드용).
            env['AGENT_GUARD_LOOPBACK_ALL'] = '1'
        if allow_gradle_keystore:
            # 워크스페이스별 옵트인: 파일명 `gradle.keystore` 만 시크릿 deny 예외(Gradle TestKit·config-cache 오탐).
            # sandbox_runner 가 SRT 규칙 뒤에 그 파일명만 re-allow 하는 규칙을 붙인다(SBPL 마지막 매칭이 이긴다).
            # denyWrite 는 allowWrite 를 이기므로 policy 로는 못 열고, 이 append 만 통한다. 다른 keystore 는 계속 deny.
            env['AGENT_GUARD_GRADLE_KEYSTORE_ROOT'] = str(Path(workspace).resolve())
        policy = sandbox_policy(workspace, home, domains, extra_reads)
        if loopback_all:
            policy['network']['allowLocalBinding'] = True
        # 옵트인 Darwin 임시 하위 폴더는 정책이 그 안만 열어 주고 `T/` 자체는 닫혀 있다. 호스트가 폴더를
        # 정리해 없어지면 자식이 만들 수 없으니(cartograph 가 그 자리에서 죽는다) 감독자가 실행 전에 만든다.
        for directory in darwin_temp_directories():
            candidate = Path(directory)
            if candidate.is_symlink():
                raise GuardError('A Darwin temp directory entry is a symlink; refusing to prepare it.')
            candidate.mkdir(mode=0o700, exist_ok=True)
        if short_tmp is not None:
            policy['filesystem']['allowRead'].append(str(short_tmp))
            policy['filesystem']['allowWrite'].append(str(short_tmp))
        policy['filesystem']['denyWrite'].extend(str(home / p) for p in read_only_home_paths)
        policy['filesystem']['denyWrite'].append(str(home / '.gitconfig'))
        # 워크스페이스 안이라도 에이전트 자신의 설정 파일(훅·MCP)은 자식이 만들거나 바꾸지 못한다.
        policy['filesystem']['denyWrite'].extend(str(Path(workspace) / p) for p in read_only_workspace_paths)
        if configuration_home is not None:
            policy['filesystem']['allowRead'].append(str(configuration_home))
            policy['filesystem']['allowWrite'].append(str(configuration_home))
            policy['filesystem']['denyWrite'].extend(str(configuration_home / p) for p in ['.config/opencode', '.opencode'])
        if private_sockets:
            policy['network']['allowUnixSockets'] = [str(home / 'tmp')] + ([str(short_tmp)] if short_tmp is not None else [])
        # 세션이 자기 경계를 알도록 실제 정책 값으로 안내문을 만들고 잠근다.
        # 매 실행마다 덮어써서 이전 세션이 남긴 조작본이 로드되지 않게 한다.
        # 샌드박스 안의 훅도 이 모듈을 import 하므로 호스트 전용 의존성은 여기서만 읽는다.
        sys.path.insert(0, str(ROOT))
        import environment_notice
        notice_targets = [(home, environment_notice.NOTICE_FILE_NAME),
                          *((home, relative) for relative in instruction_files)]
        if config_directory is not None:
            # 자식의 $HOME 은 runtime-home 이므로 그곳에도 같은 안내문을 둔다.
            notice_targets.append((configuration_home, environment_notice.NOTICE_FILE_NAME))
            notice_targets.append((configuration_home, '.config/opencode/AGENTS.md'))
        write_environment_notice(notice_targets,
                                 environment_notice.render_environment_notice(workspace, home, env, policy, notice_extra))
        policy['filesystem']['denyWrite'].extend(str(Path(root) / relative) for root, relative in notice_targets)
        config = control / 'policy.json'
        write_private_json(config, policy)
        if mode == 'zcode' and any(str(part).endswith('/glm/zcode.cjs') for part in command):
            runtime_status('zcode-start.json', {'pid': os.getpid(), 'workspace_id': hashlib.sha256(str(workspace).encode()).hexdigest()[:20], 'stage': 'supervisor-start'})
        status = subprocess.call([str(NODE), str(ROOT / 'sandbox_runner.mjs'), str(config), '--', *command],
                                 cwd=workspace, env=env, umask=0o077, stdout=stdout, stdin=stdin, stderr=stderr)
        if mode == 'zcode' and any(str(part).endswith('/glm/zcode.cjs') for part in command):
            runtime_status('zcode-exit.json', {'pid': os.getpid(), 'workspace_id': hashlib.sha256(str(workspace).encode()).hexdigest()[:20], 'stage': 'supervisor-exit', 'exit_code': status})
        return status
    finally:
        # Only the private temporary control directory created by this invocation.
        shutil.rmtree(control)
        if ephemeral and short_tmp is not None:
            shutil.rmtree(short_tmp, ignore_errors=True)


def write_environment_notice(targets, text):
    """안내문을 (격리 루트, 상대 경로) 쌍마다 링크 안전하게 0600 으로 다시 쓴다."""
    for root, relative in targets:
        write_private_file(root, relative, text)


def compatibility_manifest():
    """검토된 바이너리 해시 매니페스트. 없으면 모든 백엔드가 닫힌다. 호출 시점의 ROOT 를 쓴다."""
    return ROOT / 'state/compatibility.json'


def verify_opencode_binary():
    manifest = compatibility_manifest()
    if not manifest.is_file():
        raise GuardError('OpenCode compatibility baseline is missing; run local verification before use.')
    baseline = json.loads(manifest.read_text())['opencode']
    digest = hashlib.sha256()
    with OPENCODE.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != baseline['sha256']:
        raise GuardError('OpenCode changed; run agent-guard verify-updates before using safecode.')
    return baseline['version']


def verify_kimi_binary():
    """Kimi Code 바이너리가 검토된 해시와 같을 때만 버전을 돌려준다. 기준선이 없으면 닫힌다.

    왜 해시인가. `~/.kimi-code/bin/kimi` 는 자동 갱신 대상이라 내용이 바뀔 수 있다. 바뀐 바이너리는
    클립보드·네트워크 동작이 다를 수 있으므로 `agent-guard verify-updates` 로 다시 검토한 뒤에만 띄운다.
    """
    manifest = compatibility_manifest()
    if not manifest.is_file():
        raise GuardError('Kimi Code compatibility baseline is missing; run agent-guard verify-updates before use.')
    baseline = json.loads(manifest.read_text()).get('kimi')
    if not isinstance(baseline, dict) or not isinstance(baseline.get('sha256'), str):
        raise GuardError('Kimi Code compatibility baseline has no kimi entry; run agent-guard verify-updates before use.')
    if not KIMI.is_file():
        raise GuardError('Kimi Code is not installed at ' + str(KIMI) + '.')
    digest = hashlib.sha256()
    with KIMI.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != baseline['sha256']:
        raise GuardError('Kimi Code changed; run agent-guard verify-updates before using safekimi.')
    return baseline.get('version')


def verify_zcode_binary():
    application = Path('/Applications/ZCode.app')
    with (application / 'Contents/Info.plist').open('rb') as stream:
        version = plistlib.load(stream).get('CFBundleShortVersionString')
    profile = json.loads((ROOT / 'state/zcode-profile.json').read_text())
    if version != profile['reviewedDesktopVersion']:
        raise GuardError('Zcode changed version; re-verify backend routing before launching.')
    manifest = compatibility_manifest()
    if not manifest.is_file():
        raise GuardError('Zcode compatibility baseline is missing; run local verification before launching the backend.')
    baseline = json.loads(manifest.read_text()).get('zcode')
    if baseline is None:
        raise GuardError('Zcode compatibility baseline has no zcode entry; run local verification before launching the backend.')
    paths = {'asarSha256': Path('/Applications/ZCode.app/Contents/Resources/app.asar'),
             'agentSha256': Path('/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs')}
    for field, path in paths.items():
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != baseline[field]:
            raise GuardError('Zcode changed; run agent-guard verify-updates before starting a new backend.')


def autoclaw_profile():
    """검토된 AutoClaw 앱 버전·번들 CLI 버전·허용 도메인. 없으면 백엔드가 닫힌다."""
    path = ROOT / 'state/autoclaw-profile.json'
    if not path.is_file():
        raise GuardError('AutoClaw guard profile is missing; run install_autoclaw.py first.')
    return json.loads(path.read_text())


def file_sha256(path):
    """큰 바이너리를 블록 단위로 읽어 sha256 을 구한다."""
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_autoclaw_binary():
    """AutoClaw 앱 버전과 번들 Zcode CLI 를 기록된 기준선과 대조한다. 검토된 CLI 버전을 돌려준다.

    AutoClaw 는 플러그인 `command` 가 설정되면 자체 해시 검사를 건너뛴다. 그 검사를 여기서 대신 하되,
    앱이 갱신되면 매니페스트도 함께 바뀌므로 매니페스트가 아니라 우리 기준선(compatibility.json)이 기준이다.
    """
    profile = autoclaw_profile()
    with (AUTOCLAW_APP / 'Contents/Info.plist').open('rb') as stream:
        version = plistlib.load(stream).get('CFBundleShortVersionString')
    if version != profile['reviewedAppVersion']:
        raise GuardError('AutoClaw changed version; re-verify the bundled coding runtime before launching.')
    manifest = compatibility_manifest()
    if not manifest.is_file():
        raise GuardError('AutoClaw compatibility baseline is missing; run local verification before launching.')
    baseline = json.loads(manifest.read_text()).get('autoclaw')
    if baseline is None:
        raise GuardError('AutoClaw compatibility baseline has no autoclaw entry; run install_autoclaw.py first.')
    bundled = json.loads((AUTOCLAW_APP / 'Contents/Resources/zcode/manifest.json').read_text())
    cli_version = profile['zcodeCliVersion']
    if bundled.get('zcodeCliVersion') != cli_version or baseline.get('zcodeCliVersion') != cli_version:
        raise GuardError('AutoClaw bundles a different Zcode CLI version; re-verify before launching.')
    artifact = bundled.get('artifacts', {}).get('darwin-arm64', {})
    # 매니페스트는 앱 디렉터리 안의 사용자 쓰기 가능 파일이다. 해시할 파일을 매니페스트가 고르게 두면
    # 실행될 바이너리와 다른 파일을 검증하게 된다. 실제로 실행하는 고정 경로만 대조한다.
    if artifact.get('file') != 'darwin-arm64/zcode':
        raise GuardError('AutoClaw manifest names a different Zcode binary; re-verify before launching.')
    digest = file_sha256(autoclaw_bundled_binary())
    if digest != baseline['zcodeSha256'] or digest != artifact.get('sha256'):
        raise GuardError('AutoClaw Zcode CLI changed; run agent-guard verify-updates before starting a new backend.')
    return cli_version


def autoclaw_bundled_binary():
    """검증·복제 대상인 번들 CLI 의 고정 경로. 매니페스트가 아니라 앱 경로에서만 파생한다."""
    return AUTOCLAW_APP / 'Contents/Resources/zcode/darwin-arm64/zcode'


def stage_autoclaw_binary():
    """번들 CLI 를 가드 소유 경로로 복제하고 복제본의 해시를 기준선과 대조한 뒤 그 경로를 돌려준다.

    검증과 실행 사이에 앱 디렉터리(사용자 쓰기 가능)의 파일이 바뀌어도 실행되는 것은 이 복제본이다.
    APFS clonefile(`cp -c`)이라 199 MB 여도 즉시 끝나고, 복제본은 원본 쓰기의 영향을 받지 않는다.
    """
    baseline = json.loads(compatibility_manifest().read_text()).get('autoclaw') or {}
    # 실행마다 전용 디렉터리: 동시 실행이 서로의 검증된 복제본을 지우거나 바꿔치기하지 못한다.
    runtime = private_dir(ROOT / 'state/autoclaw-runtime')
    reap_dead_launch_directories(runtime)
    directory = Path(tempfile.mkdtemp(prefix='launch-' + str(os.getpid()) + '-', dir=str(runtime)))
    staged = directory / 'zcode'
    source = str(autoclaw_bundled_binary())
    copy = subprocess.run(['/bin/cp', '-c', source, str(staged)], capture_output=True)
    if copy.returncode != 0:
        copy = subprocess.run(['/bin/cp', source, str(staged)], capture_output=True)
    if copy.returncode != 0 or staged.is_symlink() or not staged.is_file():
        shutil.rmtree(directory, ignore_errors=True)
        raise GuardError('Could not stage the AutoClaw Zcode CLI for a guarded launch.')
    if file_sha256(staged) != baseline.get('zcodeSha256'):
        shutil.rmtree(directory, ignore_errors=True)
        raise GuardError('AutoClaw Zcode CLI changed while staging; run agent-guard verify-updates before launching.')
    staged.chmod(0o500)
    return staged


def reap_dead_launch_directories(runtime):
    """소유 프로세스가 사라진 `launch-<pid>-*` 디렉터리를 치운다. SIGTERM 으로 finally 없이 끝난 실행의 잔재다."""
    for entry in runtime.iterdir():
        parts = entry.name.split('-')
        if entry.is_symlink() or not entry.is_dir() or len(parts) < 3 or parts[0] != 'launch' or not parts[1].isdigit():
            continue
        pid = int(parts[1])
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            shutil.rmtree(entry, ignore_errors=True)
        except PermissionError:
            continue


def stage_kimi_binary():
    """Kimi 바이너리를 가드 소유 경로로 복제하고 복제본 해시를 기준선과 대조한 뒤 그 경로를 돌려준다.

    `verify_kimi_binary` 의 해시 검사와 실행 사이에 `~/.kimi-code/bin/kimi`(자동 갱신 대상, 사용자 쓰기 가능)가
    바뀌면 검토되지 않은 바이너리가 뜬다(리뷰 MEDIUM). AutoClaw 와 같은 방식으로 APFS clonefile 복제본을 검증하고
    그 복제본만 실행한다. 실행 뒤 `discard_staged_binary` 로 치운다.
    """
    baseline = json.loads(compatibility_manifest().read_text()).get('kimi') or {}
    runtime = private_dir(ROOT / 'state/kimi-runtime')
    reap_dead_launch_directories(runtime)
    directory = Path(tempfile.mkdtemp(prefix='launch-' + str(os.getpid()) + '-', dir=str(runtime)))
    staged = directory / 'kimi'
    copy = subprocess.run(['/bin/cp', '-c', str(KIMI), str(staged)], capture_output=True)
    if copy.returncode != 0:
        copy = subprocess.run(['/bin/cp', str(KIMI), str(staged)], capture_output=True)
    if copy.returncode != 0 or staged.is_symlink() or not staged.is_file():
        shutil.rmtree(directory, ignore_errors=True)
        raise GuardError('Could not stage the Kimi Code binary for a guarded launch.')
    if file_sha256(staged) != baseline.get('sha256'):
        shutil.rmtree(directory, ignore_errors=True)
        raise GuardError('Kimi Code changed while staging; run agent-guard verify-updates before launching.')
    staged.chmod(0o500)
    return staged


def discard_staged_binary(staged):
    """실행이 끝난 복제본과 그 전용 디렉터리를 치운다(AutoClaw·Kimi 런타임 디렉터리만)."""
    directory = Path(staged).parent
    if directory.parent in (ROOT / 'state/autoclaw-runtime', ROOT / 'state/kimi-runtime'):
        shutil.rmtree(directory, ignore_errors=True)


def executable_path(pid):
    """커널이 아는 실행 파일 경로(proc_pidpath). ps 의 comm 은 프로세스가 제목으로 바꿀 수 있어 쓰지 않는다."""
    import ctypes
    library = ctypes.CDLL('/usr/lib/libproc.dylib')
    buffer = ctypes.create_string_buffer(4096)
    length = library.proc_pidpath(ctypes.c_int(pid), buffer, ctypes.c_uint32(len(buffer)))
    return buffer.raw[:length].decode('utf-8', 'replace') if length > 0 else ''


def listener_pids_from_netstat(text, port):
    """`netstat -anv -p tcp` 출력에서 이 포트를 LISTEN 하는 프로세스 PID(어느 주소든). 정렬된 고유 목록."""
    pids = set()
    suffix = '.' + str(port)
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or not fields[0].startswith('tcp') or fields[5] != 'LISTEN':
            continue
        if not fields[3].endswith(suffix):
            continue
        for field in fields[6:]:
            name, _, pid = field.rpartition(':')
            if name and pid.isdigit():
                pids.add(int(pid))
                break
    return sorted(pids)


def listener_executables(port):
    """이 포트를 듣는 프로세스들의 실행 파일 경로. 조회가 실패하거나 시간을 넘기면 [''](닫힘).

    lsof 는 모든 프로세스의 fd 를 훑어 JVM 같은 큰 프로세스가 있으면 수십 초가 걸릴 수 있다. netstat 은 커널
    테이블을 바로 읽어 0.01초다. 주소 필터 없이 포트 전체를 본다(0.0.0.0/::1 리스너도 같은 포트를 받는다).
    """
    try:
        listing = subprocess.run(['/usr/sbin/netstat', '-anv', '-p', 'tcp'], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ['']
    if listing.returncode != 0:
        return ['']
    # 경로를 못 구한 프로세스는 빈 문자열로 남긴다. 호출자가 그것을 보고 닫아야지, 조용히 버리면 안 된다.
    return [executable_path(pid) for pid in listener_pids_from_netstat(listing.stdout, port)]


def verify_broker_owner(port):
    """브로커 포트의 리스너가 AutoClaw 앱 안의 실행 파일일 때만 그 포트를 연다.

    URL 모양 검사만으로는 호스트 설정이 가리키는 임의의 로컬 서비스(SOCKS 프록시 등)를 열어 줄 수 있다.
    """
    owners = listener_executables(port)
    prefix = str(AUTOCLAW_APP) + '/'
    if not owners or any('/../' in owner or not owner.startswith(prefix) for owner in owners):
        raise GuardError('The AutoClaw model broker port is not owned by AutoClaw; refusing to open it.')


def autoclaw_broker_port(env):
    """게이트웨이가 넘긴 모델 브로커 URL 두 개에서 루프백 포트 하나를 얻는다.

    플러그인이 요구하는 형태(http, 127.0.0.1, 고정 경로)를 그대로 검사하고 두 URL 의 포트가 같아야 한다.
    이 포트만 격리 정책의 outbound 허용에 들어간다.
    """
    from urllib.parse import urlsplit
    expected = {'AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL': '/internal/model-proxy/v1',
                'AUTOCLAW_MODEL_BROKER_ANTHROPIC_BASE_URL': '/internal/model-proxy/anthropic/v1'}
    ports = set()
    for name, path in expected.items():
        value = env.get(name, '')
        parts = urlsplit(value)
        try:
            port = parts.port
        except ValueError:
            port = None
        if (parts.scheme != 'http' or parts.hostname != '127.0.0.1' or parts.path != path
                or parts.query or parts.fragment or parts.username or parts.password or not port):
            raise GuardError('The AutoClaw model broker address is missing or not a loopback URL; '
                             'add the AUTOCLAW_MODEL_BROKER_* variables to the plugin envPassthrough.')
        if not 1024 <= port <= 65535:
            raise GuardError('The AutoClaw model broker port is outside the accepted range.')
        ports.add(port)
    if len(ports) != 1:
        raise GuardError('The AutoClaw model broker URLs disagree on the port; refusing to open two ports.')
    return ports.pop()


AUTOCLAW_NOTICE = ('## AutoClaw 코딩 런타임\n\n'
                   '이 세션은 AutoClaw(z.ai) 데스크톱의 코딩 기능이 띄운 Zcode CLI 이며 Zcode Safe 와 같은 격리 안에 있다. '
                   '모델 호출은 AutoClaw 의 로컬 모델 브로커(루프백 포트)로만 나가고 API 키는 이 환경에 없다. '
                   'AutoClaw 는 승인 프롬프트 없이 자동 승인하므로 riskgate 의 `deny` 만 실제로 막힌다. '
                   '저장소 범위로 제한된 GitHub 토큰이 `GH_TOKEN` 과 격리 홈 `.git-credentials` 로 들어 있어 push·PR 이 되지만, '
                   '확인 절차가 없으니 push·PR·force-push 는 사용자가 그 턴에 명시적으로 시켰을 때만 한다.\n\n')


def doctor():
    sys.path.insert(0, str(ROOT))
    from compatibility_check import candidate
    current = candidate()
    saved = json.loads((ROOT / 'state/compatibility.json').read_text())
    result = {'opencode': {'version': current['opencode']['version'], 'verified': current['opencode'] == saved.get('opencode')},
              'zcode': {'version': current['zcode']['version'], 'verified': current['zcode'] == saved.get('zcode')},
              'autoclaw': ({'version': current['autoclaw']['version'],
                            'verified': current['autoclaw'] == saved.get('autoclaw')}
                           if 'autoclaw' in current else None),
              'kimi': ({'version': current['kimi']['version'], 'verified': current['kimi'] == saved.get('kimi')}
                       if 'kimi' in current else None),
              'riskgate': {'policy_available': riskgate_policy().is_file()},
              'development': development_options(),
              'mobile': current['mobile'],
              'claude_skill': (OWNER_HOME / '.claude/skills/packet-ask-safe/SKILL.md').is_file()}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    autoclaw_ok = result['autoclaw'] is None or result['autoclaw']['verified']
    kimi_ok = result['kimi'] is None or result['kimi']['verified']
    return 0 if result['opencode']['verified'] and result['zcode']['verified'] and autoclaw_ok and kimi_ok else 2


def development_options():
    path = ROOT / 'state/development.json'
    data = json.loads(path.read_text()) if path.exists() else {'devPorts': [], 'packageDomains': []}
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in data['devPorts']):
        raise GuardError('Invalid development port settings.')
    reviewed = {'registry.npmjs.org:443', 'pypi.org:443', 'files.pythonhosted.org:443',
                'github.com:443', 'codeload.github.com:443', 'api.github.com:443',
                'objects.githubusercontent.com:443', 'raw.githubusercontent.com:443',
                # GitHub 릴리스 자산은 이제 이 호스트로 리다이렉트된다. OpenCode 의 ripgrep 다운로드가 여기서 막혀
                # 모든 세션의 glob·grep 도구가 실패했다.
                'release-assets.githubusercontent.com:443',
                'pub.dev:443', 'storage.googleapis.com:443',
                # Gradle/Maven(JVM). 배포판은 services.gradle.org → github 릴리스, mavenCentral() 은 repo.maven.apache.org,
                # 플러그인 포털, google() 은 dl.google.com/maven.google.com.
                'services.gradle.org:443', 'repo.maven.apache.org:443', 'repo1.maven.org:443',
                'plugins.gradle.org:443', 'plugins-artifacts.gradle.org:443', 'dl.google.com:443', 'maven.google.com:443'}
    if not set(data['packageDomains']) <= reviewed:
        raise GuardError('An unreviewed package download destination was configured.')
    return data


def riskgate_policy():
    manifest = json.loads((ROOT / 'state/riskgate.json').read_text())
    path = OWNER_HOME / '.config/riskgate/riskgate.yaml'
    if manifest.get('enabled') is not True or manifest.get('policy') != str(path):
        raise GuardError('The required riskgate integration is not configured.')
    if path.is_symlink() or not path.is_file():
        raise GuardError('The riskgate policy is missing or symlinked; refusing an unguarded backend.')
    return path


def prompt_telemetry_enabled():
    """Opt-in: record which commands actually prompt, to find missing rules."""
    manifest = ROOT / 'state/telemetry.json'
    if not manifest.is_file():
        return False
    return json.loads(manifest.read_text()).get('promptedCommands') is True


# 리뷰어 기본 모델. 새 격리 홈에는 선택된 모델이 없어 공급자 기본값이 잡히는데, 그 모델은
# system 역할을 거부해 400 이 났다. safecode 에서 실제 쓰는 모델을 명시한다.
DEFAULT_REVIEW_MODEL = 'alibaba-token-plan/qwen3.8-max'


def review_config(base, model=DEFAULT_REVIEW_MODEL):
    """가드 소유 OpenCode 설정에 읽기 전용 `review` 에이전트를 더한 리뷰어 설정.

    도구를 모두 끄면 모델이 워크스페이스를 읽기만 할 수 있다. 원본 설정 파일은 바꾸지 않는다.
    """
    if not isinstance(model, str) or model.count('/') != 1 or not all(c.isalnum() or c in './_-' for c in model):
        raise GuardError('reviewModel must look like provider/model.')
    config = json.loads(json.dumps(base))
    disabled = ['bash', 'edit', 'write', 'patch', 'webfetch', 'websearch', 'task', 'todowrite', 'skill']
    config.setdefault('agent', {})['review'] = {
        'description': 'Read-only code reviewer used by packet-review',
        'mode': 'primary',
        'model': model,
        'tools': {name: False for name in disabled},
        # 비대화형 run 에서는 권한 요청이 자동 거부되므로 읽기 도구만 미리 허용한다.
        'permission': {'read': 'allow', 'glob': 'allow', 'grep': 'allow', 'list': 'allow'},
        'prompt': 'You are a meticulous code reviewer. You may only read files. Never modify, create, or run anything.',
    }
    return config


def run_opencode_review(workspace, prompt, stdout=None):
    """별도 격리 홈에서 읽기 전용 Qwen 리뷰어를 비대화형으로 돌린다. 출력은 JSON 이벤트 줄이다."""
    verify_opencode_binary()
    development = development_options()
    profile = load_opencode_profile()
    base = ROOT / 'state/opencode-config.json'
    auth_file = ROOT / 'state/opencode-auth.json'
    if not auth_file.is_file():
        raise GuardError('Selected OpenCode credentials have not been imported yet.')
    config_file = ROOT / 'state/opencode-review-config.json'
    # 실행마다 기본 설정에서 다시 만든다. write_private_json 은 O_EXCL 이라 먼저 지운다.
    if config_file.exists():
        config_file.unlink()
    settings = packet_relay_settings() or {}
    write_private_json(config_file, review_config(json.loads(base.read_text()),
                                                  settings.get('reviewModel', DEFAULT_REVIEW_MODEL)))
    def prepare(home, env):
        link_opencode_auth(home, auth_file)
    return run_confined('opencode-review', workspace,
                        [str(OPENCODE), 'run', '--agent', 'review', '--format', 'json', prompt],
                        sorted(set(profile['domains'] + development['packageDomains'])),
                        {'OPENCODE_CONFIG': str(config_file)}, [config_file, auth_file],
                        prepare_home=prepare, read_only_home_paths=['.local/share/opencode/auth.json'],
                        protect_opencode_config=True, stdout=stdout)


# pub.dev 는 macOS 에서 $HOME/Library/Application Support/dart 의 OAuth 자격 증명을 읽는다.
PUB_CREDENTIALS = OWNER_HOME / 'Library/Application Support/dart/pub-credentials.json'
# 업로드는 pub.dev 와 storage.googleapis.com, 만료된 액세스 토큰 갱신은 Google OAuth 엔드포인트.
PUB_PUBLISH_DOMAINS = ['pub.dev:443', 'storage.googleapis.com:443', 'accounts.google.com:443', 'oauth2.googleapis.com:443']


def pub_publish_settings():
    """옵트인 pub 게시 설정. 파일이 없거나 형식이 다르면 None."""
    manifest = ROOT / 'state/pub-publish.json'
    if not manifest.is_file():
        return None
    settings = json.loads(manifest.read_text())
    return settings if isinstance(settings, dict) else None


def pub_publish_grant(workspace):
    """이 워크스페이스에 pub 게시가 허용됐으면 설정을, 아니면 None.

    자격 증명은 계정 단위라 패키지별로 좁힐 수 없으므로 워크스페이스 목록으로 범위를 정한다.
    """
    settings = pub_publish_settings()
    if not settings or settings.get('enabled') is not True:
        return None
    allowed = settings.get('workspaces')
    if not isinstance(allowed, list):
        return None
    resolved = str(Path(workspace).resolve())
    return settings if any(isinstance(entry, str) and str(Path(entry).expanduser().resolve()) == resolved for entry in allowed) else None


def loopback_grant(workspace):
    """이 워크스페이스에 루프백 전체 개방이 허가됐는가(`state/loopback-grants.json`, 옵트인).

    Gradle 같은 JVM 빌드는 데몬·파일 잠금·컴파일 데몬·테스트 워커가 임의 루프백 포트로 통신하고 Seatbelt 는
    포트 범위를 받지 않는다. 그래서 워크스페이스 단위로만 연다. 열린 세션은 같은 사용자의 다른 로컬
    서비스에도 접속할 수 있으므로 안내문이 이를 알린다.
    """
    manifest = ROOT / 'state/loopback-grants.json'
    if not manifest.is_file():
        return False
    settings = json.loads(manifest.read_text())
    if not isinstance(settings, dict) or settings.get('enabled') is not True or not isinstance(settings.get('workspaces'), list):
        return False
    resolved = str(Path(workspace).resolve())
    return any(isinstance(entry, str) and str(Path(entry).expanduser().resolve()) == resolved for entry in settings['workspaces'])


def gradle_keystore_grant(workspace):
    """이 워크스페이스에서 파일명 `gradle.keystore` 만 시크릿 deny 예외로 허가됐는가(`state/gradle-keystore-grants.json`, 옵트인).

    Gradle TestKit·configuration-cache 는 무결성 검증용 `gradle.keystore` 를 워크스페이스 안 build 아래에 만드는데,
    그 이름이 SECRET_NAMES 의 `*.keystore` 에 걸려 오탐으로 막힌다. 진짜 서명 키스토어(release.keystore·*.jks 등)와
    다른 시크릿은 계속 보호하려고 파일명 하나만, 워크스페이스 단위로만 연다.
    """
    manifest = ROOT / 'state/gradle-keystore-grants.json'
    if not manifest.is_file():
        return False
    settings = json.loads(manifest.read_text())
    if not isinstance(settings, dict) or settings.get('enabled') is not True or not isinstance(settings.get('workspaces'), list):
        return False
    resolved = str(Path(workspace).resolve())
    return any(isinstance(entry, str) and str(Path(entry).expanduser().resolve()) == resolved for entry in settings['workspaces'])


def hardlink_credential(source, target):
    """호스트 자격 증명 파일을 격리 홈 경로에 하드링크한다.

    왜 하드링크인가. 클라이언트가 토큰을 갱신하면 같은 파일을 제자리에서 다시 쓴다. 심볼릭 링크는
    호스트 경로로 풀려 샌드박스 쓰기 정책에 막히고, 복사본은 호스트와 갈라진다. 같은 inode 를 격리
    홈 경로로 두면 갱신이 양쪽에 반영된다. 내용은 읽지 않는다. source 는 0600·본인 소유여야 한다.
    """
    source, target = Path(source), Path(target)
    if not source.is_file() or source.is_symlink():
        raise GuardError('Credential file is missing or is a link: ' + str(source))
    info = source.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise GuardError('Credential file must be private to you (chmod 600 ' + str(source) + ').')
    private_dir(target.parent)
    if target.exists() or target.is_symlink():
        if target.is_symlink() or target.stat().st_ino != info.st_ino:
            raise GuardError('Unexpected credential file in the isolated home; refusing to replace it.')
        return
    try:
        os.link(str(source), str(target))
    except OSError:
        raise GuardError('Could not hardlink the credential into the isolated home (same volume required).') from None


def link_pub_credentials(config_home, source=None):
    """pub.dev 자격 증명을 자식의 config 디렉터리(`$XDG_CONFIG_HOME/dart`)에 하드링크한다.

    dart 는 XDG_CONFIG_HOME 이 설정되면 macOS 기본 경로 대신 그것을 쓴다. 샌드박스는 항상 이를
    설정하므로 여기에 두어야 pub 이 로컬 소켓 OAuth 대신 저장된 토큰으로 게시한다.
    """
    source = Path(source) if source is not None else PUB_CREDENTIALS
    if not source.is_file() or source.is_symlink():
        raise GuardError('pub.dev credentials are missing; run `dart pub login` in Terminal first.')
    hardlink_credential(source, Path(config_home) / 'dart/pub-credentials.json')


def packet_relay_settings():
    """옵트인 packet-ask 중계 설정. 켜져 있지 않으면 None."""
    manifest = ROOT / 'state/packet-relay.json'
    if not manifest.is_file():
        return None
    settings = json.loads(manifest.read_text())
    return settings if isinstance(settings, dict) and settings.get('enabled') is True else None


def orca_integration():
    """Opt-in status relay. Returns Orca's plugin and endpoint, or None."""
    manifest = ROOT / 'state/orca-integration.json'
    if not manifest.is_file() or json.loads(manifest.read_text()).get('enabled') is not True:
        return None
    hooks = os.environ.get('ORCA_OPENCODE_CONFIG_DIR', '')
    if not hooks:
        return None  # Not launched from an Orca terminal.
    sys.path.insert(0, str(ROOT))  # -I keeps the script directory off sys.path.
    from orca_broker import host_coordinates, usable
    plugin = Path(hooks) / 'plugins/orca-opencode-status.js'
    coordinates = host_coordinates()
    if not plugin.is_file() or not usable(coordinates):
        return None
    return plugin, coordinates


def load_opencode_profile():
    profile = ROOT / 'state/opencode-profile.json'
    if not profile.is_file():
        raise GuardError('OpenCode provider profile is not configured yet. Run setup before using opencode-safe.')
    with profile.open() as stream:
        data = json.load(stream)
    return data


def inside_zcode_sandbox():
    """A trusted marker plus an actual denied open of our NON-secret canary file."""
    if os.environ.get('AGENT_GUARD_BACKEND') != 'zcode-v1':
        return False
    try:
        descriptor = os.open(str(ROOT / 'state/original-permissions.json'), os.O_RDONLY)
    except PermissionError:
        return True
    except OSError:
        return False
    else:
        os.close(descriptor)
        return False


def live_zcode_status():
    import ctypes
    rows = []
    output = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,ucomm='], capture_output=True, text=True, check=True).stdout
    for line in output.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3:
            rows.append((int(fields[0]), int(fields[1]), fields[2]))
    roots = {pid for pid, parent, name in rows if name == 'ZCode'}
    family = set(roots)
    for _ in range(12):
        family |= {pid for pid, parent, name in rows if parent in family}
    guards = set()
    for pid, parent, name in rows:
        if pid not in family or name not in {'Python', 'python3'}:
            continue
        command = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'command='], capture_output=True, text=True).stdout
        if str(ROOT / 'agent_guard.py') + ' zcode-backend' in command:
            guards.add(pid)
    protected = set(guards)
    for _ in range(12):
        protected |= {pid for pid, parent, name in rows if parent in protected}
    sandboxed = 0
    try:
        library = ctypes.CDLL('/usr/lib/libsandbox.1.dylib')
        library.sandbox_check.restype = ctypes.c_int
        sandboxed = sum(library.sandbox_check(pid, None, 0) == 1 for pid in protected)
    except OSError:
        pass
    receipt_valid = False
    receipt_path = ROOT / 'state/runtime/zcode-gui.json'
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_text())
        if receipt.get('pid') in roots:
            started = subprocess.run(['/bin/ps', '-p', str(receipt['pid']), '-o', 'lstart='], capture_output=True, text=True).stdout.strip()
            receipt_valid = bool(started) and started == receipt.get('started')
    return {'gui_running': bool(roots), 'gui_pid': min(roots) if roots else None, 'safe_launch': receipt_valid,
            'backend_count': len(guards), 'sandboxed_children': sandboxed}


def launch_zcode_app():
    verify_zcode_binary()
    application = Path('/Applications/ZCode.app')
    running = subprocess.run(['/usr/bin/pgrep', '-u', str(os.getuid()), '-x', 'ZCode'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if running.returncode == 0:
        subprocess.run(['/usr/bin/osascript', '-e',
                        'display alert "Zcode Safe" message "Zcode를 완전히 종료한 뒤 이 실행기를 다시 열어 주세요. 기존 세션은 자동 종료하지 않습니다."'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise GuardError('Quit the existing Zcode application before starting Zcode Safe.')
    if running.returncode != 1:
        raise GuardError('Could not check existing Zcode processes; refusing to launch.')
    # Keep the familiar desktop profile, but replace the agent's entry point.
    # The GUI itself is not claimed to be inside the agent's Seatbelt policy.
    env = {'HOME': str(OWNER_HOME), 'USER': OWNER_USER, 'LOGNAME': OWNER_USER,
           'PATH': ':'.join([str(NODE.parent), '/opt/homebrew/bin', '/Library/Developer/CommandLineTools/usr/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
           'SHELL': '/bin/zsh', 'LANG': 'en_US.UTF-8',
           'ZCODE_AGENT_SERVER_COMMAND': str(OWNER_HOME / '.local/bin/zcode-backend-safe'),
           'ZCODE_AGENT_SERVER_ARGS_JSON': '["app-server","--stdio"]',
           'ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT': '1'}
    executable = str(application / 'Contents/MacOS/ZCode')
    started = subprocess.run(['/bin/ps', '-p', str(os.getpid()), '-o', 'lstart='], capture_output=True, text=True).stdout.strip()
    runtime_status('zcode-gui.json', {'pid': os.getpid(), 'started': started})
    os.execve(executable, [executable], env)


def github_token_path():
    return ROOT / 'state/github-auth.json'


def setup_github_token():
    """Read a scoped token from the operator's terminal, never from a chat."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise GuardError('Run agent-guard setup-github-token in macOS Terminal. '
                         'Never paste the token into the agent chat.')
    import getpass
    token = getpass.getpass('GitHub fine-grained token (입력은 표시되지 않습니다): ').strip()
    if not token or len(token) < 20 or any(c.isspace() for c in token):
        raise GuardError('That does not look like a token; nothing was written.')
    private_dir(ROOT / 'state')
    path = github_token_path()
    if path.exists():
        path.unlink()
    write_private_json(path, {'token': token})
    print('Stored for the guarded launchers only. Revoke it on GitHub to undo.', file=sys.stderr)
    return 0


def github_token():
    """The scoped token, if the operator registered one."""
    path = github_token_path()
    if not path.is_file():
        return None
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise GuardError('The GitHub token store must be private to you.')
    return json.loads(path.read_text()).get('token') or None


def packet_setup_key():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise GuardError('Run packet-ask-safe setup-key in macOS Terminal, then use --use-keychain. Never paste the key into the agent chat.')
    code = ('from importlib.metadata import version; import sys; '
            'assert version("packet-ask") == "' + packet_ask_pinned_version() + '"; '
            'from packet_ask.cli import main; sys.exit(main())')
    # security -w prompts itself. The key is never a command argument or chat input.
    return subprocess.call([str(PACKET_PYTHON), '-I', '-c', code,
                            'credentials', 'set', 'glm', '--access', 'command'],
                           env={'HOME': str(OWNER_HOME), 'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'})


def packet_provider_status(arguments):
    if arguments[0] == 'providers':
        data = {'provider': 'glm', 'guard_supported': True,
                'credential_sources': ['dedicated-env', 'dedicated-keychain']}
        if '--json' in arguments:
            print(json.dumps([data]))
        else:
            print('glm | guard-supported | dedicated GLM env/keychain credential')
            print('Claude Code can be MAIN; the protected SUB provider is glm, not claude.')
        return 0
    with tempfile.TemporaryDirectory(prefix='packet-safe-doctor-', dir=OWNER_HOME) as workspace, tempfile.TemporaryFile() as output:
        status = run_confined('packet-doctor', Path(workspace),
                              [str(PACKET_PYTHON), '-I', str(ROOT / 'packet_entry.py'), 'doctor'],
                              extra_env={'PACKET_ASK_CLAUDE_BIN': str(CLAUDE.resolve())},
                              ephemeral=True, stdout=output)
        output.seek(0)
        lines = output.read(1024 * 1024).decode(errors='replace').splitlines()
    line = next((line for line in lines if line.startswith('glm |')), '')
    ready = status == 0 and 'installed=True' in line and '| launch |' in line
    if '--json' in arguments:
        print(json.dumps({'provider': 'glm', 'launchable': ready, 'guard_started': status == 0,
                          'provider_probe': 'help-flags-only', 'key_value_read': False}))
    else:
        print(line or 'glm | provider probe failed')
        print('packet-ask-safe: provider=glm; OS guard started=' + str(status == 0) + '; key value not read.')
        print('Missing key: run packet-ask-safe setup-key in Terminal, then pass --use-keychain.')
    return 0 if ready else 2


def read_packet_glm_keychain():
    """Only called after the operator explicitly supplies --use-keychain."""
    code = ('from importlib.metadata import version; import sys; '
            'assert version("packet-ask") == "' + packet_ask_pinned_version() + '"; '
            'from packet_ask.keysource import resolve_provider_key; '
            'sys.stdout.write(resolve_provider_key("glm", "keychain"))')
    result = subprocess.run([str(PACKET_PYTHON), '-I', '-c', code],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env={'HOME': str(OWNER_HOME), 'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'},
                            text=True, timeout=35)
    if result.returncode or not result.stdout.strip():
        raise GuardError('Could not obtain the dedicated packet-ask-glm credential.')
    return result.stdout.strip()


def prepare_packet_request(arguments, use_keychain=False):
    # 어댑터(packet_entry.py)는 샌드박스 안에서 파일을 읽지 않고 이 값과 설치본을 대조한다.
    env = {'PACKET_ASK_CLAUDE_BIN': str(CLAUDE.resolve()),
           'AGENT_GUARD_PACKET_ASK_VERSION': packet_ask_pinned_version()}
    if arguments[0] in {'inspect', 'providers', 'doctor'}:
        return arguments, [], env
    if arguments[0] not in {'review', 'research'}:
        raise GuardError('Use review/research or offline inspect/providers/doctor with this launcher.')
    providers = []
    for index, value in enumerate(arguments):
        if value == '--provider' and index + 1 < len(arguments):
            providers.append(arguments[index + 1])
        elif value.startswith('--provider='):
            providers.append(value.partition('=')[2])
    if len(providers) != 1 or providers[0] != 'glm':
        raise GuardError('Use --provider glm for the protected SUB. Claude Code is the MAIN caller, not --provider claude.')
    if '--preview' in arguments or '--dry-run' in arguments:
        return arguments, [], env
    if any(a == '--credential-source' or a.startswith('--credential-source=') for a in arguments):
        raise GuardError('Use the dedicated environment key or --use-keychain instead of --credential-source.')
    key = os.environ.get('PACKET_ASK_GLM_KEY', '')
    if not key and use_keychain:
        key = read_packet_glm_keychain()
    if not key or len(key) < 8 or len(key) > 4096 or any(c.isspace() for c in key):
        raise GuardError('Supply PACKET_ASK_GLM_KEY or use --use-keychain for the dedicated packet-ask-glm item.')
    env['PACKET_ASK_GLM_KEY'] = key
    return [*arguments, '--credential-source', 'env'], ['api.z.ai:443'], env


LAUNCH_LOG_LIMIT = 200 * 1024
LAUNCH_LOG_TAIL = 16 * 1024


def record_launch_stage(name, cwd):
    """시도별 단계 기록(append). 마지막 시도가 덮어쓰는 영수증과 달리 실패한 시도의 마지막 단계가 남는다.

    200 KB 를 넘으면 마지막 16 KB 만 남기고 줄인다 — 통째로 비우면 같은 기동의 런처 셸 `sh-start` 줄이 사라져
    "python-start 는 있는데 sh-start 없음" 으로 오독된다. cwd 의 제어문자는 이스케이프해 한 레코드가 한 줄이 되게 한다
    (`python-start` 는 workspace_path 검사 이전에 기록된다). 로그 자리가 FIFO 면 열기에서 멈추지 않고(O_NONBLOCK) 건너뛴다.
    """
    directory = private_dir(ROOT / 'state/runtime')
    path = directory / 'autoclaw-launches.log'
    if path.is_symlink():
        return
    tail = b''
    if path.exists() and path.stat().st_size > LAUNCH_LOG_LIMIT:
        tail = path.read_bytes()[-LAUNCH_LOG_TAIL:]
        tail = tail[tail.find(b'\n') + 1:]
        os.unlink(str(path))
    try:
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError:
        return
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        return
    safe_cwd = ''.join(c if c.isprintable() else repr(c)[1:-1] for c in cwd)
    line = time.strftime('%Y-%m-%dT%H:%M:%S') + ' pid=' + str(os.getpid()) + ' stage=' + name + ' cwd=' + safe_cwd + '\n'
    with os.fdopen(descriptor, 'ab') as stream:
        stream.write(tail + line.encode())


def record_autoclaw_stage(name):
    """AutoClaw 기동 단계를 영수증(마지막 실행)과 시도별 로그 둘 다에 남긴다.

    핸드셰이크 한도 안에 못 뜨면 어느 단계에서 멈췄는지 이걸로 본다. 순서는 런처 셸의 `sh-start` →
    `python-start`(argparse 이전) → `started` → verified → broker-checked → workspace-checked → staged → launching.
    """
    runtime_status('autoclaw-stage.json', {'pid': os.getpid(), 'stage': name, 'at': time.time()})
    record_launch_stage(name, os.getcwd())


def is_autoclaw_agent_server_call(arguments):
    """런처가 넘긴 인자가 `autoclaw-backend agent-server` 호출인지. version 프로브는 단계를 기록하지 않는다.

    런처 셸의 `[ "$1" = agent-server ]` 와 같은 기준(첫 인자만)이어야 한다 — 다르면 `sh-start` 없는 `python-start` 를
    셸 단계 손실로 오독한다.
    """
    return arguments[:2] == ['autoclaw-backend', 'agent-server']


def run_autoclaw_backend(remaining):
    """AutoClaw zcode-runtime 플러그인이 부르는 두 진입점.

    `version`: 번들 CLI 를 실행하지 않고 해시 검증을 통과한 검토 버전을 출력한다(플러그인은 마지막 토큰만 본다).
    `agent-server`: cwd 를 워크스페이스로 검사하고 번들 CLI 를 Zcode 백엔드와 같은 격리로 띄운다.
    """
    if remaining == ['version']:
        print(verify_autoclaw_binary())
        return 0
    if remaining != ['agent-server']:
        raise GuardError('Unexpected AutoClaw runtime arguments; refusing a custom launch.')

    stage = record_autoclaw_stage
    stage('started')
    verify_autoclaw_binary()
    stage('verified')
    broker_port = autoclaw_broker_port(os.environ)
    verify_broker_owner(broker_port)
    stage('broker-checked')
    development = development_options()
    riskgate = riskgate_policy()
    workspace = workspace_path(os.getcwd())
    stage('workspace-checked')
    base_config = ROOT / 'state/zcode-agent-config.json'
    if not base_config.is_file():
        raise GuardError('Zcode guard settings have not been installed.')
    domains = autoclaw_profile().get('domains', [])
    relay_settings = packet_relay_settings()
    relay = None
    if relay_settings is not None:
        sys.path.insert(0, str(ROOT))
        from packet_relay import PacketRelay
        relay = PacketRelay(workspace, persistent_home('autoclaw', workspace), settings=relay_settings)

    def prepare_autoclaw(home, env):
        private_dir(private_dir(home / '.zcode') / 'cli')
        if relay is not None:
            relay.prepare(home, env)
        # 번들 CLI 는 설정을 HOME 기준으로 찾는다. ZCODE_HOME 은 zcode-backend 와의 일관성용이다.
        env.update({'ZCODE_HOME': str(home / '.zcode'),
                    'AGENT_GUARD_BACKEND': 'zcode-v1', 'AGENT_GUARD_BOOTSTRAP': 'zcode',
                    'AGENT_GUARD_PROMPT_TELEMETRY': '1' if prompt_telemetry_enabled() else '0'})
    # 앱 디렉터리 전체가 아니라 가드가 복제·검증한 바이너리 하나만 읽게 한다.
    staged = stage_autoclaw_binary()
    stage('staged')
    reads = [staged, ROOT / 'agent_guard.py', ROOT / 'zcode_hook.py', base_config,
             ROOT / 'riskgate_bridge.py', ROOT / 'vendor', ROOT / 'state/riskgate.json', riskgate]
    workspace_id = hashlib.sha256(str(workspace).encode()).hexdigest()[:20]

    def launch():
        stage('launching')
        runtime_status('autoclaw-start.json', {'pid': os.getpid(), 'workspace_id': workspace_id, 'stage': 'supervisor-start'})
        status = 'error'
        try:
            status = run_confined('autoclaw', workspace, [str(staged), 'agent-server'],
                                  sorted(set(domains + development['packageDomains'])),
                                  extra_env={'AGENT_GUARD_BROKER_PORT': str(broker_port)},
                                  extra_reads=reads, prepare_home=prepare_autoclaw, private_sockets=True,
                                  read_only_home_paths=['.zcode/cli/config.json'] + (relay.read_only_home_paths() if relay else []),
                                  dev_ports=development['devPorts'], instruction_files=['.zcode/AGENTS.md'],
                                  notice_extra=AUTOCLAW_NOTICE + (relay.notice() if relay else ''),
                                  loopback_port=True, github=True, read_only_workspace_paths=ZCODE_WORKSPACE_CONFIG_PATHS,
                                  short_tmpdir=True, loopback_all=loopback_grant(workspace), allow_gradle_keystore=gradle_keystore_grant(workspace))
        finally:
            # 예외로 끝나도 영수증과 정리는 남긴다. AutoClaw 가 죽은 세션을 살아 있다고 보지 않게 한다.
            discard_staged_binary(staged)
            runtime_status('autoclaw-exit.json', {'pid': os.getpid(), 'workspace_id': workspace_id, 'stage': 'supervisor-exit', 'exit_code': status})
        return status
    if relay is None:
        return launch()
    with relay:
        return launch()


def main(argv=None):
    if is_autoclaw_agent_server_call(sys.argv[1:] if argv is None else list(argv)):
        # 런처 셸의 `sh-start` 와 `started` 사이(python3 셔틀·인터프리터 기동·argparse)에서 멈추는지 가른다.
        record_autoclaw_stage('python-start')
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    for name in ['exec', 'opencode']:
        item = sub.add_parser(name)
        item.add_argument('workspace')
        item.add_argument('args', nargs=argparse.REMAINDER)
    current_project = sub.add_parser('safecode', help='Run protected OpenCode in the current directory.')
    current_project.add_argument('args', nargs=argparse.REMAINDER)
    review = sub.add_parser('opencode-review', help='Run the read-only review agent on a workspace; prompt on stdin.')
    review.add_argument('workspace')
    usage = sub.add_parser('usage', help='Show Token Plan usage with bl confined to its own isolated home.')
    usage.add_argument('args', nargs=argparse.REMAINDER)
    kimi = sub.add_parser('kimi', help='Run Kimi Code confined to the current directory; the clipboard stays closed.')
    kimi.add_argument('args', nargs=argparse.REMAINDER)
    packet = sub.add_parser('packet-ask')
    packet.add_argument('--use-keychain', action='store_true',
                        help='Allow reading only the dedicated packet-ask-glm Keychain item when needed.')
    packet.add_argument('args', nargs=argparse.REMAINDER)
    shell = sub.add_parser('zcode-shell')
    shell.add_argument('workspace')
    shell.add_argument('encoded_command')
    backend = sub.add_parser('zcode-backend')
    backend.add_argument('args', nargs=argparse.REMAINDER)
    autoclaw = sub.add_parser('autoclaw-backend', help='AutoClaw zcode-runtime command: version probe or agent-server.')
    autoclaw.add_argument('args', nargs=argparse.REMAINDER)
    sub.add_parser('zcode-app')
    sub.add_parser('setup-github-token')
    sub.add_parser('doctor')
    sub.add_parser('live-status')
    sub.add_parser('check-zcode')
    record = sub.add_parser('record-zcode-launch')
    record.add_argument('pid', type=int)
    sub.add_parser('restore-open-history')
    history = sub.add_parser('restore-history')
    history.add_argument('workspace')
    sub.add_parser('verify-updates')
    args = parser.parse_args(argv)
    if args.mode == 'check-zcode':
        verify_zcode_binary()
        riskgate_policy()
        return 0
    if args.mode == 'record-zcode-launch':
        name = subprocess.run(['/bin/ps', '-p', str(args.pid), '-o', 'ucomm='], capture_output=True, text=True).stdout.strip()
        started = subprocess.run(['/bin/ps', '-p', str(args.pid), '-o', 'lstart='], capture_output=True, text=True).stdout.strip()
        if name != 'ZCode' or not started:
            raise GuardError('The newly launched Zcode process could not be verified.')
        runtime_status('zcode-gui.json', {'pid': args.pid, 'started': started})
        return 0
    if args.mode == 'live-status':
        print(json.dumps(live_zcode_status()))
        return 0
    if args.mode == 'restore-open-history':
        sys.path.insert(0, str(ROOT))
        from restore_history import registered_workspaces, restore_registered_workspace
        total = 0
        count = 0
        for work in registered_workspaces():
            result = restore_registered_workspace(workspace_path(str(work)))
            total += result.get('session', 0)
            count += 1
        print(json.dumps({'workspaces': count, 'imported_sessions': total}))
        return 0
    if args.mode == 'restore-history':
        sys.path.insert(0, str(ROOT))
        from restore_history import restore_registered_workspace
        print(json.dumps(restore_registered_workspace(workspace_path(args.workspace))))
        return 0
    if args.mode == 'setup-github-token':
        return setup_github_token()
    if args.mode == 'doctor':
        return doctor()
    if args.mode == 'verify-updates':
        return subprocess.call(['/usr/bin/python3', '-I', str(ROOT / 'compatibility_check.py')],
                               env={'HOME': str(OWNER_HOME), 'PATH': '/usr/bin:/bin', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'})
    if args.mode == 'opencode-review':
        prompt = sys.stdin.read()
        if not prompt.strip() or len(prompt) > 64 * 1024:
            raise GuardError('Provide the review prompt on stdin (under 64KB).')
        return run_opencode_review(workspace_path(args.workspace), prompt)
    if args.mode == 'zcode-app':
        return launch_zcode_app()
    if args.mode == 'zcode-shell':
        development = development_options()
        command = base64.b64decode(args.encoded_command, validate=True).decode('utf-8')
        if '\x00' in command or len(command) > 1024 * 1024:
            raise GuardError('Invalid shell command.')
        workspace = workspace_path(args.workspace)
        sys.path.insert(0, str(ROOT))
        try:
            from riskgate_bridge import riskgate_decision
            verdict = riskgate_decision({'tool_input': {'command': command}, 'cwd': str(workspace)})
        except Exception:
            raise GuardError('riskgate 검증에 실패하여 셸 실행을 차단했습니다.') from None
        if verdict == 'deny':
            raise GuardError('riskgate 정책이 이 명령을 차단했습니다.')
        if verdict not in ('allow', 'ask'):
            # 알 수 없는 판정은 닫힌다. 'deny' 문자열만 막으면 None·오류 객체가 그대로 실행됐다.
            raise GuardError('riskgate 판정을 해석할 수 없어 셸 실행을 차단했습니다.')
        return run_confined('zcode-shell', workspace,
                            ['/bin/bash', '--noprofile', '--norc', '-c', command], ephemeral=True,
                            domains=development['packageDomains'], dev_ports=development['devPorts'],
                            loopback_all=loopback_grant(workspace), allow_gradle_keystore=gradle_keystore_grant(workspace))
    remaining = args.args
    if remaining[:1] == ['--']:
        remaining = remaining[1:]
    if args.mode == 'usage':
        # 호스트 전용 모듈. 샌드박스 안의 훅이 agent_guard 를 import 하므로 여기서만 읽는다.
        sys.path.insert(0, str(ROOT))
        import usage_cli
        return usage_cli.run_usage(remaining)
    if args.mode == 'kimi':
        # 호스트 전용 모듈. 최상단 import 는 샌드박스 훅을 전부 deny 로 만든다(HANDOFF 13).
        sys.path.insert(0, str(ROOT))
        import kimi_cli
        return kimi_cli.run_kimi(remaining)
    if args.mode == 'exec':
        if not remaining:
            raise GuardError('A command is required after --.')
        return run_confined('exec', workspace_path(args.workspace), remaining, ephemeral=True)
    if args.mode in {'opencode', 'safecode'}:
        workspace = workspace_path(os.getcwd() if args.mode == 'safecode' else args.workspace)
        verify_opencode_binary()
        development = development_options()
        profile = load_opencode_profile()
        # Provider config is guard-owned and read-only from inside the sandbox.
        # Original host plugins/MCP/agent instructions are deliberately not loaded.
        config_file = ROOT / 'state/opencode-config.json'
        auth_file = ROOT / 'state/opencode-auth.json'
        if not auth_file.is_file():
            raise GuardError('Selected OpenCode credentials have not been imported yet.')
        # 옵트인 packet-ask 중계. 감독자가 자식 대신 GLM 리뷰를 실행해 준다.
        relay_settings = packet_relay_settings()
        relay = None
        if relay_settings is not None:
            sys.path.insert(0, str(ROOT))
            from packet_relay import PacketRelay
            relay = PacketRelay(workspace, persistent_home('opencode', workspace), settings=relay_settings)
        publish = pub_publish_grant(workspace)
        publish_creds = [('dart/pub-credentials.json', PUB_CREDENTIALS)] if publish is not None else []
        def prepare_opencode(home, env):
            link_opencode_auth(home, auth_file)
            if relay is not None:
                relay.prepare(home, env)
        publish_notice = ('## pub.dev 게시\n\n이 워크스페이스는 `dart pub publish` 가 허용돼 있다. 자격 증명은 '
                          '`$XDG_CONFIG_HOME/dart/pub-credentials.json` 에 있고 pub 이 알아서 읽는다. '
                          '`dart pub login` 은 브라우저가 필요해 여기서는 안 되니 시도하지 마라. '
                          '게시 전 `dart pub publish --dry-run` 으로 검증하고, 실제 게시는 사용자가 지시했을 때만 한다.\n'
                          if publish is not None else '')
        def launch(extra, plugins):
            locked = ['.local/share/opencode/auth.json'] + (relay.read_only_home_paths() if relay else [])
            return run_confined('opencode', workspace, [str(OPENCODE), *remaining],
                                sorted(set(profile['domains'] + development['packageDomains']
                                           + (PUB_PUBLISH_DOMAINS if publish is not None else []))),
                                dict({'OPENCODE_CONFIG': str(config_file)}, **extra), [config_file, auth_file],
                                prepare_home=prepare_opencode,
                                read_only_home_paths=locked, dev_ports=development['devPorts'],
                                protect_opencode_config=True, opencode_plugins=plugins,
                                notice_extra=(relay.notice() if relay else '') + publish_notice, loopback_port=True,
                                config_credentials=publish_creds, loopback_all=loopback_grant(workspace), allow_gradle_keystore=gradle_keystore_grant(workspace))
        integration = orca_integration()
        if integration is None:
            if relay is None:
                return launch({}, ())
            with relay:
                return launch({}, ())
        plugin, coordinates = integration
        # Orca's port, token and launch token stay out of the sandbox; the child
        # is given this broker instead, and the broker rewrites the identity.
        sys.path.insert(0, str(ROOT))
        from orca_broker import StatusBroker
        with StatusBroker(coordinates) as broker:
            if relay is None:
                return launch(dict(broker.child_environment(),
                                   AGENT_GUARD_BROKER_PORT=str(broker.port)), [plugin])
            with relay:
                return launch(dict(broker.child_environment(),
                                   AGENT_GUARD_BROKER_PORT=str(broker.port)), [plugin])
    if args.mode == 'zcode-backend':
        verify_zcode_binary()
        development = development_options()
        riskgate = riskgate_policy()
        if remaining not in [['app-server', '--stdio'], ['app-server', '--stdio', '--surface', 'desktop']]:
            raise GuardError('Unexpected Zcode backend arguments; refusing a custom launch.')
        workspace = workspace_path(os.getcwd())
        base_config = ROOT / 'state/zcode-agent-config.json'
        if not base_config.is_file():
            raise GuardError('Zcode guard settings have not been installed.')
        profile = ROOT / 'state/zcode-profile.json'
        domains = json.loads(profile.read_text())['domains'] if profile.is_file() else []
        relay_settings = packet_relay_settings()
        relay = None
        if relay_settings is not None:
            sys.path.insert(0, str(ROOT))
            from packet_relay import PacketRelay
            relay = PacketRelay(workspace, persistent_home('zcode', workspace), settings=relay_settings)
        def prepare_zcode(home, env):
            private_dir(private_dir(home / '.zcode') / 'cli')
            if relay is not None:
                relay.prepare(home, env)
            env.update({'ZCODE_HOME': str(private_dir(home / '.zcode')),
                        'AGENT_GUARD_BACKEND': 'zcode-v1', 'AGENT_GUARD_BOOTSTRAP': 'zcode',
                        'AGENT_GUARD_PROMPT_TELEMETRY': '1' if prompt_telemetry_enabled() else '0',
                        # Providers built on Node's global fetch ignore the agent's own
                        # proxy settings and resolve DNS directly, which cannot work here.
                        'NODE_OPTIONS': '--import ' + (ROOT / 'proxy_bootstrap.mjs').as_uri()})
        reads = ['/Applications/ZCode.app', ROOT / 'agent_guard.py', ROOT / 'zcode_hook.py',
                 base_config, ROOT / 'riskgate_bridge.py', ROOT / 'vendor', ROOT / 'state/riskgate.json', riskgate,
                 ROOT / 'proxy_bootstrap.mjs', ROOT / 'runtime/node_modules/undici']
        def launch_zcode():
            return run_confined('zcode', workspace,
                                [str(NODE), '/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs',
                                 'app-server', '--stdio', '--surface', 'desktop'],
                                sorted(set(domains + development['packageDomains'])), extra_reads=reads, prepare_home=prepare_zcode, private_sockets=True,
                                read_only_home_paths=['.zcode/cli/config.json'] + (relay.read_only_home_paths() if relay else []),
                                dev_ports=development['devPorts'], instruction_files=['.zcode/AGENTS.md'],
                                notice_extra=relay.notice() if relay else '', loopback_port=True,
                                read_only_workspace_paths=ZCODE_WORKSPACE_CONFIG_PATHS, loopback_all=loopback_grant(workspace), allow_gradle_keystore=gradle_keystore_grant(workspace))
        if relay is None:
            return launch_zcode()
        with relay:
            return launch_zcode()
    if args.mode == 'autoclaw-backend':
        return run_autoclaw_backend(remaining)
    if not remaining:
        raise GuardError('Supply packet-ask arguments, for example: inspect review --files src/main.py --question-stdin')
    if remaining[0] == 'setup-key':
        if len(remaining) != 1:
            raise GuardError('Use packet-ask-safe setup-key without key values or extra arguments.')
        return packet_setup_key()
    if remaining[0] in {'providers', 'doctor'}:
        if remaining[1:] not in [[], ['--json']]:
            raise GuardError('Use providers/doctor with an optional --json flag.')
        return packet_provider_status(remaining)
    remaining, domains, env = prepare_packet_request(remaining, args.use_keychain)
    return run_confined('packet-ask', workspace_path(os.getcwd()),
                        [str(PACKET_PYTHON), '-I', str(ROOT / 'packet_entry.py'), *remaining],
                        domains=domains, extra_env=env)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Exception values from config/providers might contain credentials.
        message = str(error) if isinstance(error, GuardError) else 'Local setup failed; no provider was launched.'
        print('agent-guard: ' + message, file=sys.stderr)
        raise SystemExit(2)
