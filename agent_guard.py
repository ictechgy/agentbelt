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
    """The passwd entry of the running account. Uses the account database, not the HOME environment variable.

    Why. The hook inside the sandbox (zcode_hook) imports this module too, and its HOME is the isolated home. Deciding the
    owner home from HOME would skew the workspace boundary check (`workspace_path`) toward the isolated home. Querying the
    account database goes through opendirectoryd libinfo, which Seatbelt allows, so both sides give the same answer.
    """
    return pwd.getpwuid(os.getuid())


def load_path_config():
    """Path overrides from `ROOT/config.json` (written by the installer). Empty dict if missing or unreadable (in the sandbox).

    Keys: ownerHome, node, opencode, claude, packetAskVenv, kimi, autoclawApp. Values are absolute path strings.
    """
    try:
        data = json.loads((ROOT / 'config.json').read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def newest_nvm_node(home):
    """Node candidate when no config is set: the highest nvm version, else Homebrew. If absent at launch, run_confined closes."""
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
# AutoClaw(z.ai) bundles its own Zcode CLI. Every coding turn launches this binary inside our isolation.
AUTOCLAW_APP = Path(_PATHS.get('autoclawApp') or '/Applications/AutoClaw.app')
AUTOCLAW_ZCODE = AUTOCLAW_APP / 'Contents/Resources/zcode/darwin-arm64/zcode'
# The Zcode CLI reads the workspace `.zcode/config.json` / `zcode.json` (hooks and MCP included) and `.agents/mcp.json`.
# If the child plants these it can turn off the PreToolUse hook, so both modes deny writes to them.
ZCODE_WORKSPACE_CONFIG_PATHS = ['.zcode', 'zcode.json', '.agents/mcp.json']
PACKET_VENV = Path(_PATHS.get('packetAskVenv') or OWNER_HOME / '.local/share/uv/tools/packet-ask')
PACKET_PYTHON = PACKET_VENV / 'bin/python'
CLAUDE = Path(_PATHS.get('claude') or OWNER_HOME / '.local/bin/claude')
# Kimi Code CLI (Moonshot). A single Node SEA binary that bundles native clipboard bindings.
# kimi mode puts only this path on the read allowance and compares it with the hash in state/compatibility.json first.
KIMI = Path(_PATHS.get('kimi') or OWNER_HOME / '.kimi-code/bin/kimi')
# The reviewed packet-ask version lives in exactly one place, state/packet-ask-version.json, not in the source.
# The promotion relay only has to change the state file, and guard code changes only on the host.
PACKET_ASK_VERSION_FILE = ROOT / 'state/packet-ask-version.json'


def packet_ask_pinned_version():
    """The reviewed packet-ask version. Refuses to run if the file is missing or has a different format (fail-closed)."""
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
    """The only path by which the supervisor writes a file inside a tree the child can write to (the isolated home).

    Why this is needed. If an agent from a previous session planted a symlink in the isolated home, the moment the
    unsandboxed supervisor opens it with O_CREAT|O_TRUNC an arbitrary host file is truncated or a token is written into
    that file (four-track review CRITICAL). root must be a supervisor-owned path, and below it we descend one component
    at a time with O_NOFOLLOW directory fds, refusing links and ownership by others. If the final name already exists,
    the link itself is unlinked and it is recreated with O_CREAT|O_EXCL|O_NOFOLLOW.
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
                os.unlink(name, dir_fd=descriptor)  # if it is a link, delete only the link itself
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

    # Hardlinks can expose an inode of another path (especially outside the workspace), so they are inspected. If as many
    # paths as the link count are all found inside the workspace there is no exposure, so it is allowed (OMC creates the
    # checkpoint and the claim marker as a hardlink pair in the same folder). If even one is outside, refuse.
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
    """user.name/user.email from the host global gitconfig. Returned only when both are plain single-line values.

    The commit author identity is already published in every commit, so copying it into the isolated home leaks no secret.
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
    # An empty .npmrc makes the real ~/.npmrc of the host be ignored. Recreated link-safely on every run.
    write_private_file(home, '.npmrc', '')
    # The isolated home has no global gitconfig, so the author becomes `user@hostname`. Plant only the host identity name
    # and email and lock them against the child (denyWrite in run_confined). Other global/system settings stay /dev/null.
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
        # The default module cache of clang/swift lives under /var/folders, which is blocked. Without a cache, swift
        # rebuilds stdlib from its interface and dies with "SDK not supported by the compiler" (not a broken toolchain).
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
        # The JVM takes user.home from the account database and java.io.tmpdir from the Darwin temp directory, and writes
        # to both closed paths (the Gradle wrapper into the real ~/.gradle, the Kotlin daemon into /var/folders/.../T,
        # EPERM). Point them at the isolated home. The sandbox runtime prepends its own proxy agent flags (preserved).
        'JAVA_TOOL_OPTIONS': '-Duser.home=' + str(home) + ' -Djava.io.tmpdir=' + str(tmp),
        'MAVEN_OPTS': '-Duser.home=' + str(home) + ' -Djava.io.tmpdir=' + str(tmp),
        'GRADLE_USER_HOME': str(home / '.gradle'),
        # The Gradle FSEvents file watcher cannot start in the sandbox and only emits warnings. Turn it off to be quiet.
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
        # On runs without a token, also delete a credential file left by an earlier run (no sharing via the persistent home).
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
    """TemporaryItems in the Darwin user temporary directory, which Foundation uses for atomic writes.

    SwiftPM and llbuild write the output-file-map and the manifest atomically. Only writes have to be opened for this
    folder; reads are not opened (user temporary files such as screenshots briefly stay here). Foundation ignores TMPDIR
    and obtains this path through confstr.
    """
    # The confstr of Python does not know this name. getconf makes the same libc call.
    result = subprocess.run(['/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR'], stdout=subprocess.PIPE, text=True, timeout=10)
    base = result.stdout.strip()
    if result.returncode or not base.startswith('/var/folders/') or any(c in base for c in '*?[]{}\\'):
        raise GuardError('Could not determine the Darwin user temporary directory.')
    return str(Path(base) / 'TemporaryItems')


def darwin_temp_directories():
    """Names of subdirectories under NSTemporaryDirectory() to open for reading and writing (opt-in).

    This is for tools such as cartograph that ignore TMPDIR and keep their cache in the confstr temporary directory.
    Only plain folder names are allowed. Do not add host tool resolution caches such as `xcrun_db-*`: a value written by
    the sandbox could fool the host xcrun.
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
    # Homebrew is opened for tools (bin, Cellar, opt) but `var` is service data (postgresql@16 DB, redis dump, logs), closed
    # (2026-09-16 review HIGH, user approved). `etc` is ca-certificates/openssl config, needed for TLS in Homebrew tools.
    deny_homebrew_data = ['/opt/homebrew/var']
    return {
        'network': {'allowedDomains': list(domains), 'deniedDomains': [],
                    'allowLocalBinding': False, 'allowUnixSockets': [], 'allowAllUnixSockets': False},
        'filesystem': {
            'denyRead': ['/', *deny_secrets, *deny_homebrew_data],
            'allowRead': [*system_reads, *map(str, executable_reads), str(workspace), str(home),
                          *map(str, extra_reads), *temp_directories],
            # TemporaryItems is write-only. Foundation atomic writes create temporary files here.
            # Opt-in temporary subdirectories (the cartograph cache and the like) get both read and write.
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
    """One 127.0.0.1 port that is free on the host right now. A collision after the session starts stays possible but rare."""
    import socket
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def short_temp_directory(mode, workspace):
    """A short guard-owned temporary directory per mode and workspace (`state/t/<7hex>`). It must fit the socket path limit.

    Limit arithmetic: sun_path 104 bytes - `/znr-<uuid>.sock` (46) = 57 characters. Install path 50 characters + 7 hex = 57.
    """
    identity = hashlib.sha256((mode + '\0' + str(workspace)).encode()).hexdigest()[:7]
    directory = private_dir(private_dir(private_dir(ROOT / 'state') / 't') / identity)
    if len(str(directory)) > 57:
        raise GuardError('The guard install path is too long for a unix socket temp directory.')
    return directory


def persistent_home(mode, workspace):
    """The persistent isolated home per mode and workspace. run_confined and the relay must see the same path."""
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
        # Runtimes that run on auto-approval with no approval UI, such as AutoClaw, are not given the GitHub token.
        env = clean_environment(home, github_token() if github else None)
        if short_tmpdir:
            # A unix socket path over the sun_path limit (104 bytes) gives EINVAL. The isolated home tmp is 88 characters,
            # so a socket like `$TMPDIR/znr-<uuid>.sock` (46 characters) cannot be created. Give it a short guard-owned tmp.
            short_tmp = short_temp_directory(mode, workspace)
            env.update({'TMPDIR': str(short_tmp), 'CLAUDE_CODE_TMPDIR': str(short_tmp),
                        'CLANG_MODULE_CACHE_PATH': str(short_tmp / 'clang-module-cache')})
        env.update(extra_env or {})
        if any(type(port) is not int or not 1024 <= port <= 65535 for port in dev_ports):
            raise GuardError('Development ports must be integers from 1024 to 65535.')
        dev_ports = list(dev_ports)
        if loopback_port:
            # One dedicated loopback port per agent session. Tools that really need a local port, such as the VM service
            # of dart coverage, use this port instead of a random one. Random binds stay blocked.
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
        # Hardlink the credentials into the config directory the child actually reads. In protected mode XDG_CONFIG_HOME
        # becomes runtime-home, so the link has to be made here, after it is final.
        for relative, source in config_credentials:
            if relative == 'dart/pub-credentials.json':
                link_pub_credentials(env['XDG_CONFIG_HOME'], source)
            else:
                hardlink_credential(source, Path(env['XDG_CONFIG_HOME']) / relative)
        if loopback_all:
            # Per-workspace opt-in: opens bind, listen and self-connect on arbitrary loopback ports (for JVM builds).
            env['AGENT_GUARD_LOOPBACK_ALL'] = '1'
        if allow_gradle_keystore:
            # Per-workspace opt-in: only the file name `gradle.keystore` is exempt from the secret deny (Gradle TestKit and
            # config-cache false positives). sandbox_runner appends a rule re-allowing just that file name after the SRT
            # rules (the last SBPL match wins). denyWrite beats allowWrite, so the policy cannot open it and only this
            # append gets through. Other keystores stay denied.
            env['AGENT_GUARD_GRADLE_KEYSTORE_ROOT'] = str(Path(workspace).resolve())
        policy = sandbox_policy(workspace, home, domains, extra_reads)
        if loopback_all:
            policy['network']['allowLocalBinding'] = True
        # For opt-in Darwin temp subfolders the policy opens only their interior and `T/` itself stays closed. If the host
        # cleans the folder away the child cannot create it (cartograph dies right there), so the supervisor creates it
        # before launching.
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
        # Even inside the workspace, the child cannot create or change the configuration files of the agent itself (hooks, MCP).
        policy['filesystem']['denyWrite'].extend(str(Path(workspace) / p) for p in read_only_workspace_paths)
        if configuration_home is not None:
            policy['filesystem']['allowRead'].append(str(configuration_home))
            policy['filesystem']['allowWrite'].append(str(configuration_home))
            policy['filesystem']['denyWrite'].extend(str(configuration_home / p) for p in ['.config/opencode', '.opencode'])
        if private_sockets:
            policy['network']['allowUnixSockets'] = [str(home / 'tmp')] + ([str(short_tmp)] if short_tmp is not None else [])
        # Build the notice from the actual policy values and lock it, so the session knows its own boundaries.
        # Overwrite it on every run so a tampered copy left by a previous session is never loaded.
        # The hook inside the sandbox imports this module too, so host-only dependencies are read only here.
        sys.path.insert(0, str(ROOT))
        import environment_notice
        notice_targets = [(home, environment_notice.NOTICE_FILE_NAME),
                          *((home, relative) for relative in instruction_files)]
        if config_directory is not None:
            # The $HOME of the child is runtime-home, so the same notice is placed there as well.
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
    """Rewrite the notice link-safely with mode 0600 for every (isolated root, relative path) pair."""
    for root, relative in targets:
        write_private_file(root, relative, text)


def compatibility_manifest():
    """The reviewed binary hash manifest. Without it every backend closes. Uses ROOT as of the time of the call."""
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
    """Returns the version only when the Kimi Code binary matches the reviewed hash. Without a baseline it closes.

    Why a hash. `~/.kimi-code/bin/kimi` is subject to auto-update, so its contents can change. A changed binary may behave
    differently around the clipboard and the network, so it is launched only after `agent-guard verify-updates` has
    reviewed it again.
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
    """The reviewed AutoClaw app version, bundled CLI version and allowed domains. Without it the backend closes."""
    path = ROOT / 'state/autoclaw-profile.json'
    if not path.is_file():
        raise GuardError('AutoClaw guard profile is missing; run adapters/install_autoclaw.py first.')
    return json.loads(path.read_text())


def file_sha256(path):
    """Reads a large binary block by block to compute its sha256."""
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_autoclaw_binary():
    """Compares the AutoClaw app version and bundled Zcode CLI with the recorded baseline. Returns the reviewed CLI version.

    AutoClaw skips its own hash check when the plugin `command` is configured. That check is done here instead, but since
    the manifest changes together with the app when it updates, the reference is our baseline (compatibility.json), not
    the manifest.
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
        raise GuardError('AutoClaw compatibility baseline has no autoclaw entry; run adapters/install_autoclaw.py first.')
    bundled = json.loads((AUTOCLAW_APP / 'Contents/Resources/zcode/manifest.json').read_text())
    cli_version = profile['zcodeCliVersion']
    if bundled.get('zcodeCliVersion') != cli_version or baseline.get('zcodeCliVersion') != cli_version:
        raise GuardError('AutoClaw bundles a different Zcode CLI version; re-verify before launching.')
    artifact = bundled.get('artifacts', {}).get('darwin-arm64', {})
    # The manifest is a user-writable file inside the app directory. Letting the manifest choose which file to hash would
    # verify a file other than the binary that will run. Only the fixed path that actually runs is compared.
    if artifact.get('file') != 'darwin-arm64/zcode':
        raise GuardError('AutoClaw manifest names a different Zcode binary; re-verify before launching.')
    digest = file_sha256(autoclaw_bundled_binary())
    if digest != baseline['zcodeSha256'] or digest != artifact.get('sha256'):
        raise GuardError('AutoClaw Zcode CLI changed; run agent-guard verify-updates before starting a new backend.')
    return cli_version


def autoclaw_bundled_binary():
    """The fixed path of the bundled CLI that is verified and cloned. Derived only from the app path, not the manifest."""
    return AUTOCLAW_APP / 'Contents/Resources/zcode/darwin-arm64/zcode'


def stage_autoclaw_binary():
    """Clones the bundled CLI into a guard-owned path, compares the hash of the clone with the baseline, returns that path.

    Even if the file in the app directory (user-writable) changes between verification and execution, what runs is this
    clone. Because it is an APFS clonefile (`cp -c`) it finishes instantly even at 199 MB, and the clone is unaffected by
    writes to the original.
    """
    baseline = json.loads(compatibility_manifest().read_text()).get('autoclaw') or {}
    # A dedicated directory per launch: concurrent launches cannot delete or swap each other verified clone.
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
    """Cleans up `launch-<pid>-*` directories whose owner process is gone: leftovers of runs ended by SIGTERM without finally."""
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
    """Clones the Kimi binary into a guard-owned path, compares the hash of the clone with the baseline, returns that path.

    If `~/.kimi-code/bin/kimi` (subject to auto-update, user-writable) changes between the hash check of
    `verify_kimi_binary` and execution, an unreviewed binary comes up (review MEDIUM). As with AutoClaw, an APFS clonefile
    clone is verified and only that clone is executed. Afterwards it is cleaned up by `discard_staged_binary`.
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
    """Cleans up the clone of a finished run and its dedicated directory (AutoClaw and Kimi runtime directories only)."""
    directory = Path(staged).parent
    if directory.parent in (ROOT / 'state/autoclaw-runtime', ROOT / 'state/kimi-runtime'):
        shutil.rmtree(directory, ignore_errors=True)


def executable_path(pid):
    """The executable path the kernel knows (proc_pidpath). The comm of ps is not used: a process can change it to a title."""
    import ctypes
    library = ctypes.CDLL('/usr/lib/libproc.dylib')
    buffer = ctypes.create_string_buffer(4096)
    length = library.proc_pidpath(ctypes.c_int(pid), buffer, ctypes.c_uint32(len(buffer)))
    return buffer.raw[:length].decode('utf-8', 'replace') if length > 0 else ''


def listener_pids_from_netstat(text, port):
    """PIDs of processes LISTENing on this port (on any address) from `netstat -anv -p tcp` output. A sorted unique list."""
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
    """Executable paths of the processes listening on this port. On a failed or timed-out lookup, [''] (fail-closed).

    lsof scans the fds of every process and can take tens of seconds when a large process such as a JVM is around. netstat
    reads the kernel table directly and takes 0.01 s. The whole port is looked at without an address filter (0.0.0.0 and
    ::1 listeners receive the same port).
    """
    try:
        listing = subprocess.run(['/usr/sbin/netstat', '-anv', '-p', 'tcp'], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ['']
    if listing.returncode != 0:
        return ['']
    # A process whose path could not be obtained is left as an empty string. The caller has to see that and close; it must
    # not be silently dropped.
    return [executable_path(pid) for pid in listener_pids_from_netstat(listing.stdout, port)]


def verify_broker_owner(port):
    """Opens the broker port only when the listener on it is an executable inside the AutoClaw app.

    Checking the URL shape alone could open an arbitrary local service the host configuration points at (a SOCKS proxy).
    """
    owners = listener_executables(port)
    prefix = str(AUTOCLAW_APP) + '/'
    if not owners or any('/../' in owner or not owner.startswith(prefix) for owner in owners):
        raise GuardError('The AutoClaw model broker port is not owned by AutoClaw; refusing to open it.')


def autoclaw_broker_port(env):
    """Obtains a single loopback port from the two model broker URLs handed over by the gateway.

    The shape the plugin requires (http, 127.0.0.1, a fixed path) is checked as is, and the two URLs must agree on the port.
    Only this port enters the outbound allowance of the isolation policy.
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


AUTOCLAW_NOTICE = ('## AutoClaw coding runtime\n\n'
                   'This session is the Zcode CLI launched by the coding feature of the AutoClaw (z.ai) desktop app, and '
                   'it sits in the same isolation as Zcode Safe. '
                   'Model calls go out only through the local model broker of AutoClaw (a loopback port) and no API key '
                   'exists in this environment. '
                   'AutoClaw auto-approves without an approval prompt, so only `deny` from riskgate actually blocks. '
                   'A repository-scoped GitHub token is present in `GH_TOKEN` and in the isolated home `.git-credentials`, '
                   'so push and PR work, but there is no confirmation step, so do push, PR and force-push only when the '
                   'user explicitly asked for it in that turn.\n\n')


def doctor():
    sys.path.insert(0, str(ROOT))
    from adapters.compatibility_check import candidate
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
                # GitHub release assets are now redirected to this host. The ripgrep download of OpenCode was blocked
                # here, which made the glob and grep tools of every session fail.
                'release-assets.githubusercontent.com:443',
                'pub.dev:443', 'storage.googleapis.com:443',
                # Gradle/Maven (JVM). Distributions come from services.gradle.org -> github releases, mavenCentral()
                # from repo.maven.apache.org, the plugin portal, and google() from dl.google.com/maven.google.com.
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


# Default reviewer model. A fresh isolated home has no selected model, so the provider default was picked, and that model
# rejected the system role and returned 400. State the model that safecode actually uses.
DEFAULT_REVIEW_MODEL = 'alibaba-token-plan/qwen3.8-max'


def review_config(base, model=DEFAULT_REVIEW_MODEL):
    """The reviewer configuration: the guard-owned OpenCode config plus a read-only `review` agent.

    With every tool turned off the model can only read the workspace. The original configuration file is not changed.
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
        # In a non-interactive run permission requests are auto-denied, so only the read tools are allowed up front.
        'permission': {'read': 'allow', 'glob': 'allow', 'grep': 'allow', 'list': 'allow'},
        'prompt': 'You are a meticulous code reviewer. You may only read files. Never modify, create, or run anything.',
    }
    return config


def run_opencode_review(workspace, prompt, stdout=None):
    """Runs the read-only Qwen reviewer non-interactively in a separate isolated home. Output is JSON event lines."""
    verify_opencode_binary()
    development = development_options()
    profile = load_opencode_profile()
    base = ROOT / 'state/opencode-config.json'
    auth_file = ROOT / 'state/opencode-auth.json'
    if not auth_file.is_file():
        raise GuardError('Selected OpenCode credentials have not been imported yet.')
    config_file = ROOT / 'state/opencode-review-config.json'
    # Rebuilt from the base configuration on every run. write_private_json is O_EXCL, so it is deleted first.
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


# On macOS, pub.dev reads the OAuth credentials in $HOME/Library/Application Support/dart.
PUB_CREDENTIALS = OWNER_HOME / 'Library/Application Support/dart/pub-credentials.json'
# Uploads go to pub.dev and storage.googleapis.com; refreshing an expired access token goes to the Google OAuth endpoints.
PUB_PUBLISH_DOMAINS = ['pub.dev:443', 'storage.googleapis.com:443', 'accounts.google.com:443', 'oauth2.googleapis.com:443']


def pub_publish_settings():
    """Opt-in pub publishing settings. None if the file is missing or has a different format."""
    manifest = ROOT / 'state/pub-publish.json'
    if not manifest.is_file():
        return None
    settings = json.loads(manifest.read_text())
    return settings if isinstance(settings, dict) else None


def pub_publish_grant(workspace):
    """The settings if pub publishing is allowed for this workspace, otherwise None.

    The credentials are per account and cannot be narrowed per package, so the scope is set by a workspace list.
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
    """Whether full loopback opening is granted for this workspace (`state/loopback-grants.json`, opt-in).

    In JVM builds such as Gradle the daemon, file locks, the compile daemon and test workers talk over arbitrary loopback
    ports, and Seatbelt does not accept port ranges. So it is opened per workspace only. An opened session can also reach
    other local services of the same user, so the notice announces this.
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
    """Whether the file name `gradle.keystore` alone is granted as a secret-deny exception in this workspace
    (`state/gradle-keystore-grants.json`, opt-in).

    Gradle TestKit and configuration-cache create a `gradle.keystore` for integrity verification under build inside the
    workspace, and that name is caught by `*.keystore` in SECRET_NAMES and blocked as a false positive. To keep protecting
    real signing keystores (release.keystore, *.jks and so on) and other secrets, only one file name is opened, and only
    per workspace.
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
    """Hardlinks a host credential file to a path in the isolated home.

    Why a hardlink. When the client refreshes the token it rewrites the same file in place. A symlink resolves to the host
    path and is blocked by the sandbox write policy, and a copy diverges from the host. Placing the same inode at a path
    in the isolated home makes the refresh visible on both sides. The contents are not read. source must be 0600 and owned
    by you.
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
    """Hardlinks the pub.dev credentials into the config directory of the child (`$XDG_CONFIG_HOME/dart`).

    When XDG_CONFIG_HOME is set, dart uses it instead of the macOS default path. The sandbox always sets it, so the
    credentials have to go here for pub to publish with the stored token instead of local-socket OAuth.
    """
    source = Path(source) if source is not None else PUB_CREDENTIALS
    if not source.is_file() or source.is_symlink():
        raise GuardError('pub.dev credentials are missing; run `dart pub login` in Terminal first.')
    hardlink_credential(source, Path(config_home) / 'dart/pub-credentials.json')


def packet_relay_settings():
    """Opt-in packet-ask relay settings. None if it is not enabled."""
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
    from adapters.orca_broker import host_coordinates, usable
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
                        'display alert "Zcode Safe" message "Quit Zcode completely, then reopen this launcher. Existing sessions are not closed automatically."'],
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
    token = getpass.getpass('GitHub fine-grained token (input is not displayed): ').strip()
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
    # The adapter (packet_entry.py) does not read the file inside the sandbox; it compares this value with the installation.
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
    """Per-attempt stage record (append). Unlike the receipt, which the last attempt overwrites, the last stage of a
    failed attempt survives here.

    Past 200 KB it is trimmed to the last 16 KB only - emptying it completely would drop the `sh-start` line of the
    launcher shell of the same startup and be misread as "python-start is there but sh-start is missing". Control
    characters in cwd are escaped so that one record is one line (`python-start` is recorded before the workspace_path
    check). If the log slot is a FIFO, opening does not block (O_NONBLOCK) and it is skipped.
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
    """Records an AutoClaw startup stage both in the receipt (the last run) and in the per-attempt log.

    If it does not come up within the handshake limit, this is what shows which stage it stopped at. The order is
    `sh-start` of the launcher shell -> `python-start` (before argparse) -> `started` -> verified -> broker-checked ->
    workspace-checked -> staged -> launching.
    """
    runtime_status('autoclaw-stage.json', {'pid': os.getpid(), 'stage': name, 'at': time.time()})
    record_launch_stage(name, os.getcwd())


def is_autoclaw_agent_server_call(arguments):
    """Whether the arguments handed over by the launcher are an `autoclaw-backend agent-server` call. A version probe
    records no stage.

    It has to use the same criterion as `[ "$1" = agent-server ]` of the launcher shell (the first argument only) -
    otherwise a `python-start` without `sh-start` is misread as a lost shell stage.
    """
    return arguments[:2] == ['autoclaw-backend', 'agent-server']


def run_autoclaw_backend(remaining):
    """The two entry points the AutoClaw zcode-runtime plugin calls.

    `version`: prints the reviewed version that passed hash verification, without running the bundled CLI (the plugin
    looks at the last token only).
    `agent-server`: checks cwd as a workspace and launches the bundled CLI in the same isolation as the Zcode backend.
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
        from adapters.packet_relay import PacketRelay
        relay = PacketRelay(workspace, persistent_home('autoclaw', workspace), settings=relay_settings)

    def prepare_autoclaw(home, env):
        private_dir(private_dir(home / '.zcode') / 'cli')
        if relay is not None:
            relay.prepare(home, env)
        # The bundled CLI looks for its configuration relative to HOME. ZCODE_HOME is for consistency with zcode-backend.
        env.update({'ZCODE_HOME': str(home / '.zcode'),
                    'AGENT_GUARD_BACKEND': 'zcode-v1', 'AGENT_GUARD_BOOTSTRAP': 'zcode',
                    'AGENT_GUARD_PROMPT_TELEMETRY': '1' if prompt_telemetry_enabled() else '0'})
    # Only the single binary that the guard cloned and verified is readable, not the whole app directory.
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
            # Even when it ends in an exception the receipt and the cleanup remain, so AutoClaw does not consider a dead
            # session alive.
            discard_staged_binary(staged)
            runtime_status('autoclaw-exit.json', {'pid': os.getpid(), 'workspace_id': workspace_id, 'stage': 'supervisor-exit', 'exit_code': status})
        return status
    if relay is None:
        return launch()
    with relay:
        return launch()


def main(argv=None):
    if is_autoclaw_agent_server_call(sys.argv[1:] if argv is None else list(argv)):
        # Tells apart a stall between `sh-start` of the launcher shell and `started` (python3 shuttle, interpreter
        # startup, argparse).
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
        from adapters.restore_history import registered_workspaces, restore_registered_workspace
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
        from adapters.restore_history import restore_registered_workspace
        print(json.dumps(restore_registered_workspace(workspace_path(args.workspace))))
        return 0
    if args.mode == 'setup-github-token':
        return setup_github_token()
    if args.mode == 'doctor':
        return doctor()
    if args.mode == 'verify-updates':
        return subprocess.call(['/usr/bin/python3', '-I', str(ROOT / 'adapters/compatibility_check.py')],
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
            raise GuardError('riskgate verification failed, so the shell execution was blocked.') from None
        if verdict == 'deny':
            raise GuardError('The riskgate policy blocked this command.')
        if verdict not in ('allow', 'ask'):
            # An unknown verdict closes. Blocking only the string 'deny' let None and error objects run as they were.
            raise GuardError('The riskgate verdict could not be interpreted, so the shell execution was blocked.')
        return run_confined('zcode-shell', workspace,
                            ['/bin/bash', '--noprofile', '--norc', '-c', command], ephemeral=True,
                            domains=development['packageDomains'], dev_ports=development['devPorts'],
                            loopback_all=loopback_grant(workspace), allow_gradle_keystore=gradle_keystore_grant(workspace))
    remaining = args.args
    if remaining[:1] == ['--']:
        remaining = remaining[1:]
    if args.mode == 'usage':
        # Host-only module. The hook inside the sandbox imports agent_guard, so it is read only here.
        sys.path.insert(0, str(ROOT))
        from adapters import usage_cli
        return usage_cli.run_usage(remaining)
    if args.mode == 'kimi':
        # Host-only module. A top-level import would make every sandbox hook deny (HANDOFF 13).
        sys.path.insert(0, str(ROOT))
        from adapters import kimi_cli
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
        # Opt-in packet-ask relay. The supervisor runs the GLM review on behalf of the child.
        relay_settings = packet_relay_settings()
        relay = None
        if relay_settings is not None:
            sys.path.insert(0, str(ROOT))
            from adapters.packet_relay import PacketRelay
            relay = PacketRelay(workspace, persistent_home('opencode', workspace), settings=relay_settings)
        publish = pub_publish_grant(workspace)
        publish_creds = [('dart/pub-credentials.json', PUB_CREDENTIALS)] if publish is not None else []
        def prepare_opencode(home, env):
            link_opencode_auth(home, auth_file)
            if relay is not None:
                relay.prepare(home, env)
        publish_notice = ('## pub.dev publishing\n\nThis workspace is allowed to run `dart pub publish`. The credentials '
                          'are in `$XDG_CONFIG_HOME/dart/pub-credentials.json` and pub reads them on its own. '
                          '`dart pub login` needs a browser and cannot be done here, so do not try it. '
                          'Verify with `dart pub publish --dry-run` before publishing, and publish for real only when the '
                          'user has instructed it.\n'
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
        from adapters.orca_broker import StatusBroker
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
            from adapters.packet_relay import PacketRelay
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
