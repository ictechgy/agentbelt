"""Per-agent `external` baselines (schema 2) and sensitive-name exceptions (schema 3). Host-only, not wired.

The external rules are a translation of the read/write roots agentbelt already grants each
mode under Seatbelt (`sandbox_policy()` and the mode's `run_confined()` arguments in
agentbelt.py, plus the literals appended by sandbox_runner.mjs), so a future ES policy does
not drift from the reviewed Seatbelt profile. Each rule records why it exists and where its
Seatbelt counterpart comes from; tests/test_task_profiles.py parses those sources and fails
when they change without this table.

Pure functions only: no filesystem, clock, process or environment reads. Launch-time paths
(the verified clone, the isolated home, TMPDIR, the Node runtime) are passed in by the
caller, already resolved; `resolved_launch_path` takes an injected lookup for that.

agentbelt.py must not import this module (ARCHITECTURE.md: it is imported inside the
sandbox, where sibling host modules must not become top-level imports).
"""
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import re
from typing import FrozenSet, Optional, Tuple

import task_policy
from environment_notice import NOTICE_FILE_NAME


RX = frozenset({'read', 'execute'})
R = frozenset({'read'})
RW = frozenset({'read', 'write'})
RWX = frozenset({'read', 'write', 'execute'})
W = frozenset({'write'})

# Trees no external tree rule may equal or contain (compared case-insensitively, since APFS
# is). Each is user data, host configuration or a mutable prefix. Containing one of them is
# what makes a rule "broad": this refuses '/', '/System' (contains /System/Volumes),
# '/usr' (/usr/local), '/opt/homebrew' (its var/etc), '/private', '/Library' and '/Users'.
BROAD_ANCHORS = (
    '/Users', '/Volumes', '/Applications', '/usr/local', '/opt/homebrew/var', '/opt/homebrew/etc',
    '/private/var', '/private/tmp', '/private/etc', '/Library/Keychains', '/Library/Preferences',
    '/Library/Application Support', '/System/Volumes',
)
# Symlinked spellings of /private/*. ES reports the resolved path, so a rule below one of
# these would be dead under ES and a second spelling for a lexical checker. Only the
# symlink vnodes themselves (RUNNER_SYMLINK_READS) may be named.
SYMLINK_ALIASES = ('/var', '/tmp', '/etc')
# The only trees a rule may grant inside the guard installation (a protected root), besides
# the launch's writable roots: vendored hook libraries, the proxy-aware fetch and the
# private Zcode bundle. Everything else there (state/*-auth.json, other workspaces' homes,
# state/zcode-private/user-data) is reachable by exact rules only.
GUARD_TREES = ('vendor', 'runtime/node_modules/undici', 'state/zcode-private/ZCode.app')
# A writable root shallower than this is a user home or a system prefix, never a
# per-launch isolated home or TMPDIR (those live below state/homes/<mode>/<id> or
# /private/tmp/agentbelt-<uid>/<token>).
MIN_WRITABLE_DEPTH = 3
# The shapes agentbelt gives a launch's writable roots, below a protected guard root:
# persistent_home() (sha256 prefix of the workspace), run_confined's control-*/home and
# control-*/runtime-home, and short_temp_directory() (token_urlsafe(16)). The last shape,
# short_temp_directory's fallback, is the only one allowed without a guard root (the probe).
# Anything else (~/Library, another project, state/homes itself) is not an isolated root.
GUARDED_WRITABLE_SHAPES = (r'/state/homes/[a-z0-9-]+/[0-9a-f]{20}', r'/state/control-[A-Za-z0-9_]+/(home|runtime-home)',
                           r'/state/t/[A-Za-z0-9_-]{22}')
TEMPORARY_WRITABLE_SHAPE = r'/private/tmp/agentbelt-[0-9]+/[A-Za-z0-9_.-]+'
# The only writes allowed outside the writable roots: exact data sinks/sources and the
# terminal. Never a /dev tree, so disks (/dev/disk*) and other devices stay closed.
DEVICE_WRITES = ('/dev/null', '/dev/zero', '/dev/tty')
# The private PTY terminal_proxy hands the child, when the caller names it.
TTY_PATH = re.compile(r'/dev/ttys[0-9]{1,4}')

# Schema-3 exceptions to the sensitive-name exclusion, as the operator decided:
# 1. Trust-store files: exact, read only. Both are Seatbelt reads (system_reads and the
#    Homebrew executable_reads); `*.pem` would otherwise deny every file CA bundle.
TRUST_STORE_FILES = ('/private/etc/ssl/cert.pem', '/opt/homebrew/etc/ca-certificates/cert.pem')
# 2. The agent's own login/state inside its isolated home, relative to the home, with
#    scope and the most operations it may lift. The tree exceptions are rooted at the
#    sensitive name itself, never above it, and lift every sensitive name beneath it.
AGENT_STATE_EXCEPTIONS = (
    ('.local/share/opencode/auth.json', 'exact', R),  # OpenCode login; hard link to guard state
    ('.kimi-code/credentials', 'tree', RW),           # Kimi login tokens (KIMI_CODE_HOME)
    ('.zcode', 'tree', RW),                           # ZCODE_HOME: CLI config, provider files, db.sqlite
    ('.npmrc', 'exact', R),                           # empty guard-created npm user config
)
# 3. The workspace repository, per task (build_contract repository_read/repository_write).
REPOSITORY = '.git'
# git_lock.mjs (appended by sandbox_runner) inside the repository: host git would execute or
# obey these, so they stay read-only even when repository_write is granted. commondir,
# modules and worktrees redirect git to another config (measured 2026-09-24). The drift
# test requires the same list as git_lock.mjs LOCKED.
REPOSITORY_LOCKED = ('.git/config', '.git/config.worktree', '.git/hooks', '.git/info/attributes',
                     '.git/commondir', '.git/modules', '.git/worktrees')
# 4. Package managers' own git checkouts (agentbelt.py git_tool_caches; git_lock.mjs
#    gitToolRules undoes the git lock only there). The package directory below each cache
#    is not known in advance, so these are name-scoped tree exceptions that lift only
#    `.git` below the cache root, never another sensitive name. The drift test requires
#    the same relative paths as git_tool_caches.
GIT_TOOL_WORKSPACE_CACHE = '.build/checkouts'           # SwiftPM, relative to the workspace
GIT_TOOL_HOME_CACHES = ('.pub-cache/git', '.cargo/git')  # dart pub, cargo; relative to the launch home
GIT_TOOL_CACHE_NAMES = frozenset({REPOSITORY})

# sandbox_policy() `system_reads` (agentbelt.py), translated entry by entry. The drift test
# requires this set of paths to equal that list. Operations: execute is added only where
# code is exec'd or mmapped PROT_EXEC (ES AUTH_MMAP maps that to execute).
SEATBELT_SYSTEM_READS = (
    ('/System/Library', 'tree', RX, 'frameworks and system dylibs are loaded and mmapped executable'),
    ('/usr/lib', 'tree', RX, 'dyld, libSystem and other dylibs'),
    ('/usr/share', 'tree', R, 'zoneinfo, terminfo, locale and ICU data; nothing here needs execute'),
    ('/usr/bin', 'tree', RX, 'shell tools the agent runs (git shim, python3 shim, env, ...)'),
    ('/bin', 'tree', RX, 'bash (SHELL and KIMI_SHELL_PATH), sh and core utilities'),
    ('/sbin', 'tree', RX, 'on the child PATH (clean_environment)'),
    ('/usr/sbin', 'tree', RX, 'on the child PATH (clean_environment)'),
    ('/Library/Developer/CommandLineTools', 'tree', RX, 'DEVELOPER_DIR: git, clang, swift and the python3 the shims exec'),
    ('/Library/Apple/usr/libexec/oah/libRosettaRuntime', 'exact', RX, 'Rosetta runtime for x86_64 tools'),
    ('/dev/null', 'exact', RW, 'data sink; shells redirect to it constantly'),
    ('/dev/zero', 'exact', RW, 'zero source; writes are discarded'),
    ('/dev/random', 'exact', R, 'entropy'),
    ('/dev/urandom', 'exact', R, 'entropy'),
    ('/dev/tty', 'exact', RW, 'controlling terminal; terminal_proxy owns the real device'),
    ('/private/etc/hosts', 'exact', R, 'name resolution'),
    ('/private/etc/resolv.conf', 'exact', R, 'name resolution'),
    ('/private/var/run/resolv.conf', 'exact', R, 'name resolution (target of the /etc link)'),
    ('/private/etc/services', 'exact', R, 'getservbyname'),
    ('/private/etc/protocols', 'exact', R, 'getprotobyname'),
    ('/private/etc/localtime', 'exact', R, 'time zone link; its zoneinfo target is an open decision'),
    ('/private/etc/ssl/cert.pem', 'exact', R, 'system CA bundle for TLS clients'),
    ('/private/etc/ssl/openssl.cnf', 'exact', R, 'OpenSSL default configuration'),
)
# sandbox_runner.mjs: "(allow file-read-data file-read-metadata (literal ...))" for the
# system symlink vnodes only, never their directory trees.
RUNNER_SYMLINK_READS = (
    ('/etc', 'exact', R, 'symlink vnode to /private/etc, read to resolve it'),
    ('/var', 'exact', R, 'symlink vnode to /private/var'),
    ('/tmp', 'exact', R, 'symlink vnode to /private/tmp'),
    ('/private/var/select/sh', 'exact', R, 'selects the shell /bin/sh re-execs'),
)
# No sandbox_policy() counterpart: under Seatbelt the dyld shared cache is mapped without
# a policy grant, but ES reports the open/mmap. Same tree as the R3 probe fixture
# (native/guard/R3Probes/.../Contract.swift `runtimeTrees`).
DYLD_SHARED_CACHE = ('/System/Volumes/Preboot/Cryptexes/OS', 'tree', RX,
                     'dyld shared cache (macOS 13+); not /System, which contains the data volume alias')
# sandbox_policy() `executable_reads`, Homebrew part, relative to the prefix. Runtime
# trees and two exact trust-store files; never the prefix itself, etc/ or Caskroom.
HOMEBREW_READS = (
    ('bin', 'tree', RX, 'Homebrew tools on the child PATH'),
    ('opt', 'tree', RX, 'stable links to installed formulae and their dylibs'),
    ('Cellar', 'tree', RX, 'installed formula payloads the opt links point into'),
    ('Library/Homebrew', 'tree', RX, 'brew itself (bin/brew execs its shell entry point)'),
    ('etc/ca-certificates/cert.pem', 'exact', R, 'Homebrew OpenSSL CA bundle'),
    ('etc/openssl@3/openssl.cnf', 'exact', R, 'Homebrew OpenSSL configuration'),
)
# sandbox_policy() `deny_homebrew_data`: formula databases and service state stay closed.
HOMEBREW_DENY = ('var',)
# The Zcode CLI's workspace configuration (agentbelt.py ZCODE_WORKSPACE_CONFIG_PATHS);
# guarded Zcode modes block reads and writes of it (run_confined blocked_workspace_paths).
ZCODE_WORKSPACE_CONFIG_PATHS = ('.zcode', 'zcode.json', '.agents/mcp.json')
# Home files every mode locks (run_confined denyWrite): the planted git identity and the
# environment notice. Relative to the isolated home.
LOCKED_HOME_PATHS = ('.gitconfig', NOTICE_FILE_NAME)


class ProfileError(task_policy.PolicyError):
    """A profile would widen the Seatbelt baseline; messages never interpolate paths."""


def _require(condition, message):
    if not condition:
        raise ProfileError(message)


@dataclass(frozen=True)
class ProfileRule:
    """One external or deny rule plus its review record (not part of the contract)."""
    path: str
    scope: str
    operations: FrozenSet[str]
    why: str = field(compare=False)
    # Where agentbelt grants the Seatbelt equivalent; 'none' marks an ES-only addition.
    source: str = field(compare=False)
    # Name-scoped exceptions only (task_policy.PathRule.names).
    names: Optional[FrozenSet[str]] = None

    def __post_init__(self):
        self.path_rule()  # Canonical spelling, scope and operations, as task_policy checks them.

    def path_rule(self):
        return task_policy.PathRule(self.path, self.scope, frozenset(self.operations), self.names)


@dataclass(frozen=True)
class ModeProfile:
    """A mode's external baseline, bound to one launch's resolved paths.

    `writable_roots` are the only trees write may be granted in (isolated home, TMPDIR,
    OpenCode's runtime home); `isolated_homes` are the subset agent state exceptions may
    lie in. `protected_roots` may not be covered by a tree rule (the guard installation
    holds credentials and every other workspace's home). `exceptions` lift the
    sensitive-name ban (schema 3) only as TRUST_STORE_FILES, AGENT_STATE_EXCEPTIONS and
    GIT_TOOL_HOME_CACHES allow. `sensitive_conflicts` are paths the agent needs that stay denied by name; they
    are listed for review, never emitted as rules. `isolated_homes[0]` is the launch home
    (run_confined `home`), the only one holding package-manager git caches.
    `workspace_git_caches` are workspace-relative trees that get a name-scoped `.git`
    exception when the workspace is writable (GIT_TOOL_WORKSPACE_CACHE only).
    """
    mode: str
    external: Tuple[ProfileRule, ...]
    writable_roots: Tuple[str, ...]
    protected_roots: Tuple[str, ...] = ()
    deny: Tuple[ProfileRule, ...] = ()
    workspace_blocked: Tuple[str, ...] = ()
    sensitive_conflicts: Tuple[str, ...] = ()
    isolated_homes: Tuple[str, ...] = ()
    exceptions: Tuple[ProfileRule, ...] = ()
    workspace_git_caches: Tuple[str, ...] = ()


def is_sensitive(path):
    """The same component check task_policy.evaluate applies before any grant."""
    return any(fnmatchcase(component.casefold(), pattern)
               for component in path.split('/') for pattern in task_policy.SENSITIVE_COMPONENTS)


def resolved_launch_path(path, *, realpath):
    """Resolve a launch path with an injected lookup (e.g. os.path.realpath).

    ES reports resolved spellings (/private/var/..., not /var/...), so rule paths must be
    resolved before they are written into a contract. The lookup is injected so this module
    itself performs no I/O.
    """
    resolved = realpath(path)
    _require(task_policy._path(resolved) and resolved != '/', 'launch path does not resolve to a canonical path')
    return resolved


class _Builder:
    """Collects rules in order; a rule already fully covered by an earlier one is dropped."""

    def __init__(self):
        self.rules, self.conflicts, self.exceptions = [], [], []

    def add(self, path, scope, operations, why, source):
        if is_sensitive(path):
            if path not in TRUST_STORE_FILES:
                # A rule here would be dead: the sensitive-name check runs first in evaluate.
                self.conflicts.append(path)
                return
            self.except_(path, scope, R, 'trust store: exact read only', source)
        rule = ProfileRule(path, scope, frozenset(operations), why, source)
        if not any(task_policy._covers(old.path_rule(), rule.path_rule()) and rule.operations <= old.operations
                   for old in self.rules):
            self.rules.append(rule)

    def except_(self, path, scope, operations, why, source, names=None):
        """Lift the name ban for a path an external rule already grants (schema 3)."""
        self.exceptions.append(ProfileRule(path, scope, frozenset(operations), why, source, names))

    def extend(self, entries, source, prefix=''):
        for path, scope, operations, why in entries:
            self.add(prefix + '/' + path if prefix else path, scope, operations, why, source)


def _agent_state(builder, home, relative, operations, why):
    scope = next(scope for name, scope, _ in AGENT_STATE_EXCEPTIONS if name == relative)
    builder.except_(home + '/' + relative, scope, operations, why, 'agent state in the isolated home (schema 3)')


def _npm_user_config(builder, home):
    # clean_environment plants an empty <home>/.npmrc (NPM_CONFIG_USERCONFIG) so npm ignores
    # the host's; npm must read it. Writes stay denied by name.
    _agent_state(builder, home, '.npmrc', R, 'empty npm user config created by the supervisor')


def _git_tool_caches(builder, home):
    # Seatbelt lets dart pub and cargo create repositories here (git_tool_caches); ES would
    # otherwise deny every `<cache>/<package>/.git` by name.
    for relative in GIT_TOOL_HOME_CACHES:
        builder.except_(home + '/' + relative, 'tree', RW, 'package manager git checkouts: only .git below is lifted',
                        'agentbelt.py git_tool_caches (git_lock.mjs gitToolRules)', GIT_TOOL_CACHE_NAMES)


def _writable(builder, home, tmpdir, extra_homes=()):
    """Read+write+execute trees for the isolated home(s) and a separate TMPDIR.

    Execute: the Gradle wrapper, npx and pub caches, and test binaries built into TMPDIR
    are executed from here, as Seatbelt allows. Write is granted nowhere else.
    """
    roots = [home, *extra_homes]
    builder.add(home, 'tree', RWX, 'isolated home: HOME, XDG dirs and tool caches', 'run_confined allowRead/allowWrite (home)')
    for extra in extra_homes:
        builder.add(extra, 'tree', RWX, 'runtime HOME seeded by the supervisor', 'run_confined configuration_home')
    if tmpdir is not None and not any(task_policy._within(tmpdir, root) for root in roots):
        # Default TMPDIR is <home>/tmp (clean_environment) and needs no rule of its own.
        roots.append(tmpdir)
        builder.add(tmpdir, 'tree', RWX, 'per-launch short TMPDIR for unix socket paths', 'run_confined short_tmpdir')
    return tuple(roots)


def _runtime(builder, *, node_binary=None, node_prefix=None, homebrew_prefix=None, tty_path=None):
    """System, runner, dyld cache, Node and Homebrew rules shared by the coding modes."""
    builder.extend(SEATBELT_SYSTEM_READS, 'agentbelt.py sandbox_policy system_reads')
    if tty_path is not None:
        _require(type(tty_path) is str and TTY_PATH.fullmatch(tty_path) is not None, 'invalid terminal device')
        builder.add(tty_path, 'exact', RW, 'private PTY from terminal_proxy', 'sandbox_runner.mjs AGENTBELT_TTY_PATHS')
    builder.extend(RUNNER_SYMLINK_READS, 'sandbox_runner.mjs symlink literals')
    builder.extend((DYLD_SHARED_CACHE,), 'none (R3 probe fixture runtimeTrees)')
    if homebrew_prefix is not None:
        builder.extend(HOMEBREW_READS, 'agentbelt.py sandbox_policy executable_reads (/opt/homebrew/...)',
                       prefix=homebrew_prefix)
    if node_prefix is not None:
        # NODE.parent (bin: node, npm, npx links) and NODE.parent.parent/lib/node_modules.
        builder.add(node_prefix + '/bin', 'tree', RX, 'pinned Node and its npm/npx links on PATH',
                    'agentbelt.py sandbox_policy executable_reads (NODE.parent)')
        builder.add(node_prefix + '/lib/node_modules', 'tree', RX, 'npm and global packages npm/npx exec',
                    'agentbelt.py sandbox_policy executable_reads (lib/node_modules)')
    if node_binary is not None:
        # Dropped when bin/ above already covers it (nvm); kept for a Homebrew Cellar target.
        builder.add(node_binary, 'exact', RX, 'resolved pinned Node binary',
                    'agentbelt.py sandbox_policy executable_reads (NODE.resolve())')


def _home_denials(home, relatives, source):
    return tuple(ProfileRule(home + '/' + relative, 'tree', W, 'supervisor-seeded file the child may not replace', source)
                 for relative in relatives)


def _finish(mode, builder, writable_roots, protected_roots=(), deny=(), homebrew_prefix=None,
            workspace_blocked=(), extra_conflicts=(), isolated_homes=(), workspace_git_caches=()):
    if homebrew_prefix is not None:
        deny = deny + tuple(ProfileRule(homebrew_prefix + '/' + relative, 'tree', RWX, 'Homebrew data stays closed',
                                        'agentbelt.py sandbox_policy deny_homebrew_data') for relative in HOMEBREW_DENY)
    return ModeProfile(mode, tuple(builder.rules), writable_roots, tuple(protected_roots), deny,
                       tuple(workspace_blocked), tuple(builder.conflicts) + tuple(extra_conflicts),
                       tuple(isolated_homes), tuple(builder.exceptions), tuple(workspace_git_caches))


def probe_profile(*, binary, home, tmpdir=None):
    """Generic probe: the R3 fixture's narrow runtime plus an isolated home.

    No agent runtime, PATH tools or trust store: exact rules for the binary and /bin/sh
    only (Contract.swift externalRules).
    """
    builder = _Builder()
    builder.add(binary, 'exact', RX, 'the verified probe binary', 'R3 probe fixture probeBinary')
    builder.add('/bin/sh', 'exact', RX, 'interpreter of the #! script probe', 'R3 probe fixture scriptInterpreter')
    for path in ('/usr/lib', '/System/Library'):
        builder.add(path, 'tree', RX, 'dyld, libSystem and frameworks', 'R3 probe fixture runtimeTrees')
    builder.extend((DYLD_SHARED_CACHE,), 'R3 probe fixture runtimeTrees')
    roots = _writable(builder, home, tmpdir)
    return _finish('probe', builder, roots, isolated_homes=(home,))


def opencode_profile(*, binary, home, runtime_home, config_file, auth_file, guard_root, tmpdir=None,
                     node_binary=None, node_prefix=None, homebrew_prefix=None, tty_path=None, read_only_home_paths=()):
    """`agentbelt opencode` / `safecode`.

    binary: the staged clone (state/opencode-runtime/launch-*/opencode), not ~/.opencode.
    runtime_home: the per-launch control-*/runtime-home that protect_opencode_config makes HOME.
    read_only_home_paths: launch extras, e.g. the packet relay's locked paths.
    """
    builder = _Builder()
    builder.add(binary, 'exact', RX, 'verified OpenCode clone; the only OpenCode image executed',
                'main() opencode: extra_reads staged / stage_opencode_binary')
    builder.add(config_file, 'exact', R, 'guard-owned provider config (OPENCODE_CONFIG)', 'main() opencode: extra_reads config_file')
    builder.add(auth_file, 'exact', R, 'selected provider credentials, hard-linked into the home', 'main() opencode: extra_reads auth_file')
    builder.add(guard_root, 'exact', R, 'directory vnode only, for module lookup', 'sandbox_runner.mjs moduleRoot literal')
    _runtime(builder, node_binary=node_binary, node_prefix=node_prefix, homebrew_prefix=homebrew_prefix,
             tty_path=tty_path)
    roots = _writable(builder, home, tmpdir, extra_homes=(runtime_home,))
    # Read only: the file is a hard link to the guard-owned state/opencode-auth.json, so
    # the Seatbelt write lock (read_only_home_paths) is kept as an explicit denial.
    _agent_state(builder, home, '.local/share/opencode/auth.json', R, 'OpenCode provider login')
    _npm_user_config(builder, home)
    _git_tool_caches(builder, home)
    locked = ('.local/share/opencode/auth.json', *read_only_home_paths)
    deny = (_home_denials(home, LOCKED_HOME_PATHS + locked, 'main() opencode read_only_home_paths; run_confined denyWrite')
            + _home_denials(runtime_home, ('.config/opencode', '.opencode', NOTICE_FILE_NAME),
                            'run_confined configuration_home denyWrite'))
    return _finish('opencode', builder, roots, (guard_root,), deny, homebrew_prefix,
                   isolated_homes=(home, runtime_home), workspace_git_caches=(GIT_TOOL_WORKSPACE_CACHE,))


def kimi_profile(*, binary, home, watch_bootstrap, guard_root, tmpdir=None, node_binary=None, node_prefix=None,
                 homebrew_prefix=None, tty_path=None, read_only_home_paths=()):
    """`agentbelt kimi` (adapters/kimi_cli.launch_kimi).

    binary: the staged, hardened clone (state/kimi-runtime/launch-*/kimi).
    watch_bootstrap: <guard_root>/kimi_watch_bootstrap.cjs, loaded with NODE_OPTIONS --require.
    """
    builder = _Builder()
    builder.add(binary, 'exact', RX, 'verified, hardened Kimi SEA clone', 'kimi_cli.launch_kimi extra_reads binary')
    builder.add(watch_bootstrap, 'exact', R, 'polling watcher preload (no FSEvents)', 'kimi_cli.launch_kimi extra_reads WATCH_BOOTSTRAP')
    builder.add(guard_root, 'exact', R, 'directory vnode only, for module lookup', 'sandbox_runner.mjs moduleRoot literal')
    _runtime(builder, node_binary=node_binary, node_prefix=node_prefix, homebrew_prefix=homebrew_prefix,
             tty_path=tty_path)
    roots = _writable(builder, home, tmpdir)
    _agent_state(builder, home, '.kimi-code/credentials', RW, 'Kimi login tokens (login and refresh write them)')
    _npm_user_config(builder, home)
    _git_tool_caches(builder, home)
    locked = LOCKED_HOME_PATHS + ('.kimi-code/region', '.kimi-code/AGENTS.md', *read_only_home_paths)
    deny = _home_denials(home, locked, 'kimi_cli.launch_kimi read_only_home_paths/instruction_files; run_confined denyWrite')
    return _finish('kimi', builder, roots, (guard_root,), deny, homebrew_prefix,
                   isolated_homes=(home,), workspace_git_caches=(GIT_TOOL_WORKSPACE_CACHE,))


def zcode_backend_profile(*, application, home, guard_root, riskgate_policy, node_binary, node_prefix, tmpdir=None,
                          homebrew_prefix=None, tty_path=None, read_only_home_paths=()):
    """`agentbelt zcode-backend` / `zcode-private-backend` (node glm/zcode.cjs app-server).

    application: /Applications/ZCode.app or the verified private clone's app_path.
    riskgate_policy: the path riskgate_policy() returned for this launch.
    """
    builder = _Builder()
    builder.add(application, 'tree', RX, 'app bundle: zcode.cjs, native .node modules and bundled tools',
                'main() zcode: reads application')
    for relative in ('agentbelt.py', 'zcode_hook.py', 'riskgate_bridge.py', 'proxy_bootstrap.mjs',
                     'state/zcode-agent-config.json', 'state/riskgate.json'):
        builder.add(guard_root + '/' + relative, 'exact', R, 'hook, bridge, fetch preload and guard settings',
                    'main() zcode: reads')
    for relative in ('vendor', 'runtime/node_modules/undici'):
        builder.add(guard_root + '/' + relative, 'tree', R, 'vendored hook libraries and the proxy-aware fetch',
                    'main() zcode: reads')
    builder.add(riskgate_policy, 'exact', R, 'riskgate policy the hook evaluates', 'main() zcode: reads riskgate')
    builder.add(guard_root, 'exact', R, 'directory vnode only, for module lookup', 'sandbox_runner.mjs moduleRoot literal')
    _runtime(builder, node_binary=node_binary, node_prefix=node_prefix, homebrew_prefix=homebrew_prefix,
             tty_path=tty_path)
    roots = _writable(builder, home, tmpdir)
    # ZCODE_HOME: '.zcode' (and db.sqlite below it) are sensitive names; without this the
    # backend cannot start. The seeded config and instructions stay write-denied below.
    _agent_state(builder, home, '.zcode', RW, 'ZCODE_HOME: CLI config, provider files, session database')
    _npm_user_config(builder, home)
    _git_tool_caches(builder, home)
    locked = LOCKED_HOME_PATHS + ('.zcode/cli/config.json', '.zcode/AGENTS.md', *read_only_home_paths)
    deny = _home_denials(home, locked, 'main() zcode read_only_home_paths/instruction_files; run_confined denyWrite')
    return _finish('zcode', builder, roots, (guard_root,), deny, homebrew_prefix, ZCODE_WORKSPACE_CONFIG_PATHS,
                   isolated_homes=(home,), workspace_git_caches=(GIT_TOOL_WORKSPACE_CACHE,))


def _related(first, second):
    """Either path contains the other; case-insensitive because APFS is."""
    first, second = first.casefold(), second.casefold()
    return task_policy._within(first, second) or task_policy._within(second, first)


def _covers_casefold(ancestor, path):
    return task_policy._within(path.casefold(), ancestor.casefold())


def _isolated_root(root, guard_roots):
    if re.fullmatch(TEMPORARY_WRITABLE_SHAPE, root):
        return True
    return any(re.fullmatch(re.escape(guard) + shape, root) for guard in guard_roots for shape in GUARDED_WRITABLE_SHAPES)


def validate_profile(profile, workspace):
    """Refuse a profile that would be broader than its Seatbelt baseline.

    Checked: rule count; no '/', no data volume alias (either direction); nothing at, above
    or inside the workspace; no tree over a broad anchor, a protected root or another
    launch's writable root; inside a protected root only GUARD_TREES and the writable
    roots as trees; write only inside the launch's writable roots (plus DEVICE_WRITES and
    one TTY_PATH device, exact), which must themselves be deep, disjoint from the
    workspace, not above the guard root and shaped as an isolated launch root
    (GUARDED_WRITABLE_SHAPES, TEMPORARY_WRITABLE_SHAPE); no duplicate or overlapping rules; no rules
    on sensitive names unless an allowed exception names them; exceptions only as
    TRUST_STORE_FILES, AGENT_STATE_EXCEPTIONS and the git tool caches permit.
    """
    _require(type(profile) is ModeProfile, 'invalid mode profile')
    _require(task_policy._path(workspace) and workspace != '/', 'invalid workspace')
    external = profile.external
    _require(0 < len(external) <= task_policy.MAX_RULES, 'external rule count out of range')
    _require(len(profile.deny) + len(profile.workspace_blocked) <= task_policy.MAX_RULES, 'deny rule count out of range')
    for root in profile.writable_roots:
        _require(task_policy._path(root) and len(root.split('/')) - 1 >= MIN_WRITABLE_DEPTH,
                 'writable root is too shallow')
        _require(_isolated_root(root, profile.protected_roots), 'writable root is not an isolated launch root')
        _require(not _related(root, workspace), 'writable root overlaps the workspace')
        _require(not any(_covers_casefold(root, protected) for protected in profile.protected_roots),
                 'writable root covers a protected root')
    for rule in external:
        _require(type(rule) is ProfileRule, 'invalid profile rule')
        _require(rule.path != '/', 'external rule covers the filesystem root')
        _require(not task_policy._data_volume_overlap(rule.path), 'external rule overlaps the data volume alias')
        _require(not _related(rule.path, workspace), 'external rule overlaps the workspace')
        _require(not any(_covers_casefold(alias, rule.path) and rule.path.casefold() != alias
                         for alias in SYMLINK_ALIASES), 'external rule uses a symlinked spelling')
        _require(not is_sensitive(rule.path) or rule.path in {exception.path for exception in profile.exceptions},
                 'external rule is shadowed by a sensitive name')
        if rule.scope == 'tree':
            for anchor in BROAD_ANCHORS + profile.protected_roots:
                _require(not _covers_casefold(rule.path, anchor), 'external tree rule is too broad')
            for root in profile.writable_roots:
                _require(rule.path == root or not _covers_casefold(rule.path, root),
                         'external tree rule covers a writable root')
            for protected in profile.protected_roots:
                _require(not _covers_casefold(protected, rule.path) or rule.path in profile.writable_roots
                         or rule.path in tuple(protected + '/' + tree for tree in GUARD_TREES),
                         'external tree rule inside the guard installation is not allowlisted')
        if 'write' in rule.operations:
            device = rule.scope == 'exact' and (rule.path in DEVICE_WRITES or TTY_PATH.fullmatch(rule.path) is not None)
            _require(device or any(task_policy._within(rule.path, root) for root in profile.writable_roots),
                     'external write outside the isolated home or TMPDIR')
    for index, rule in enumerate(external):
        for other in external[index + 1:]:
            _require(not (task_policy._covers(rule.path_rule(), other.path_rule())
                          or task_policy._covers(other.path_rule(), rule.path_rule())),
                     'duplicate or overlapping external rules')
    _validate_exceptions(profile)


def _validate_exceptions(profile):
    """Exceptions follow the operator's policy; coverage by grants is task_policy's check."""
    _require(len(profile.exceptions) <= task_policy.MAX_RULES, 'exception count out of range')
    homes = profile.isolated_homes
    _require(all(root in profile.writable_roots for root in homes), 'isolated home is not a writable root')
    _require(set(profile.workspace_git_caches) <= {GIT_TOOL_WORKSPACE_CACHE}, 'workspace git cache outside the approved set')
    for exception in profile.exceptions:
        _require(type(exception) is ProfileRule and exception.operations <= RW, 'invalid exception')
        if exception.names is not None:
            # Name-scoped: exactly `.git` below a git tool cache of the launch home.
            _require(homes and exception.scope == 'tree' and exception.names == GIT_TOOL_CACHE_NAMES
                     and exception.path in tuple(homes[0] + '/' + relative for relative in GIT_TOOL_HOME_CACHES),
                     'exception outside the approved git tool caches')
            continue
        # Rooted at the sensitive name, so a tree never lifts the ban above it.
        _require(is_sensitive(exception.path.rsplit('/', 1)[-1]), 'exception is not rooted at a sensitive name')
        trust_store = (exception.path in TRUST_STORE_FILES and exception.scope == 'exact'
                       and exception.operations == R)
        agent_state = any(exception.path == home + '/' + relative and exception.scope == scope
                          and exception.operations <= limit
                          for home in homes for relative, scope, limit in AGENT_STATE_EXCEPTIONS)
        _require(trust_store or agent_state, 'exception outside the approved trust-store and agent-state set')


def build_contract(task_id, revision, workspace, valid_from_ns, expires_at_ns, *, mode_profile,
                   workspace_allow=None, deny=(), repository_read=True, repository_write=False):
    """A contract document that task_policy.contract_from_dict accepts.

    Schema 3 when any exception is present (trust store, agent state, repository), else 2.
    workspace_allow: PathRules inside the workspace; the default mirrors Seatbelt's
    read+write workspace root, plus execute because v2 has no exec exception. It must
    cover the repository operations requested, or the contract is refused.
    repository_read / repository_write: per-task exception for <workspace>/.git. Hooks,
    config and redirections (REPOSITORY_LOCKED) and the entry itself stay write-denied, as
    under Seatbelt. The profile's workspace git caches get a name-scoped `.git` exception
    when workspace_allow grants read and write there (a read-only workspace gets none).
    Every other sensitive name stays denied.
    deny: extra PathRules; the profile's home/Homebrew denials and blocked workspace
    configuration are always added.
    """
    validate_profile(mode_profile, workspace)
    _require(type(repository_read) is bool and type(repository_write) is bool, 'invalid repository flags')
    if workspace_allow is None:
        workspace_allow = (task_policy.PathRule(workspace, 'tree', RWX),)
    workspace_allow = tuple(workspace_allow)
    blocked = tuple(task_policy.PathRule(workspace + '/' + relative, 'tree', RWX)
                    for relative in mode_profile.workspace_blocked)
    locked = tuple(task_policy.PathRule(workspace + '/' + relative, 'tree', W) for relative in REPOSITORY_LOCKED)
    # The entry itself cannot be replaced by a gitdir file or link (git_lock.mjs create/unlink deny).
    # Nested `.git` entries need no rule: the sensitive name denies them, except below the
    # name-scoped git tool caches, where package managers keep their own repositories (as
    # git_lock.mjs gitToolRules allows under Seatbelt).
    locked += (task_policy.PathRule(workspace + '/' + REPOSITORY, 'exact', W),)
    denials = []
    for rule in tuple(rule.path_rule() for rule in mode_profile.deny) + blocked + locked + tuple(deny):
        if rule not in denials:
            denials.append(rule)
    exceptions = tuple(rule.path_rule() for rule in mode_profile.exceptions)
    repository = (R if repository_read else frozenset()) | (W if repository_write else frozenset())
    if repository:
        exceptions += (task_policy.PathRule(workspace + '/' + REPOSITORY, 'tree', repository),)
    for relative in mode_profile.workspace_git_caches:
        cache = task_policy.PathRule(workspace + '/' + relative, 'tree', RW, GIT_TOOL_CACHE_NAMES)
        if all(any(type(rule) is task_policy.PathRule and operation in rule.operations
                   and task_policy._covers(rule, cache) for rule in workspace_allow) for operation in RW):
            exceptions += (cache,)
    contract = task_policy.TaskContract(
        3 if exceptions else 2, task_id, revision, workspace, valid_from_ns, expires_at_ns, tuple(workspace_allow),
        tuple(denials), tuple(rule.path_rule() for rule in mode_profile.external), exceptions)
    return task_policy.contract_to_dict(contract)
