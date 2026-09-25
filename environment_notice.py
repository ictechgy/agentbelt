"""Generate the isolated environment description document.

The agent must know from the start of the session that it is inside an isolated environment. In past
sessions the root of misdiagnoses such as "dart is missing", "the CLT is broken", or "the network is
blocked" was that the agent invented a cause without knowing what it cannot see. The supervisor builds
this document from the real policy values and rewrites it every session; the child can only read it.
Never put token values in it.
"""
from pathlib import Path

# Name of the description file the agent can read directly inside the isolated home.
NOTICE_FILE_NAME = 'AGENTBELT_ENVIRONMENT.md'


def _bullet_lines(values):
    """Turn a list of strings into Markdown bullets. When empty, return the single line '(none)'."""
    return '\n'.join('- `' + str(value) + '`' for value in values) if values else '- (none)'


def _readable_roots(policy, workspace, home):
    """Pick only the tool and system paths from the allowRead of the policy, dropping the workspace, the home, and device files."""
    skip = {str(workspace), str(home)}
    return [path for path in policy['filesystem']['allowRead']
            if path not in skip and not path.startswith('/dev/') and not path.startswith('/private/')]


def _jvm_domains_line(policy):
    """State the JVM registry domains only when this installation actually allows them."""
    domains = set(policy['network']['allowedDomains'])
    if {'services.gradle.org:443', 'repo.maven.apache.org:443'} <= domains:
        return ('- The Gradle distribution, Maven Central, the Plugin Portal, and Google Maven are allowed domains. '
                'The first run takes a few minutes to download.\n')
    return '- Gradle/Maven registry domains are not in the allow list of this session; dependency downloads will fail.\n'


def _inline_names(values):
    """Comma-separated backticked names for an inline sentence; '(none granted)' when empty."""
    return ', '.join('`' + str(value) + '`' for value in values) if values else '(none granted)'


def _darwin_temp_names(policy):
    """Names of the opt-in subdirectories under NSTemporaryDirectory() taken from the policy, so the notice never
    advertises a folder that this installation did not grant."""
    names = []
    for path in policy['filesystem']['allowRead']:
        parts = Path(path).parts
        if '/var/folders/' in path and len(parts) >= 2 and parts[-2] == 'T' and parts[-1] != 'TemporaryItems':
            names.append(parts[-1])
    return names


def _data_home_line(home, env):
    """Report the location only when the HOME of the child differs from the persistent data home (OpenCode protected mode)."""
    if env.get('HOME', str(home)) == str(home):
        return ''
    return f'- Per-project persistent data such as conversations, caches, and state: `{home}` (XDG_DATA_HOME/CACHE_HOME/STATE_HOME)\n'


def _external_review_line(env):
    """Guidance for external model review. A session with relaying on goes through packet-review, otherwise it is handed to the user.

    When both notices were present the agent followed the earlier one (handing it to the user). Keep only one.
    """
    if env.get('AGENTBELT_PACKET_REVIEW') == '1':
        return ('- Delegate external model review to the supervisor with the `packet-review` command below. Do not build packet files\n'
                '  yourself and do not ask the user to run them on the host. Dropping files into `tmp/packet-requests` by hand is not processed.\n')
    return ('- If external model review is needed, save the packet file (diff and questions) in the workspace, present the\n'
            '  `packet-ask-safe` command for the user to run on the host terminal, and then stop. Do not explore retries or workarounds.\n')


def _loopback_section(env):
    """When a session-only loopback port exists, explain how to use it; otherwise state only that a random bind is blocked."""
    if env.get('AGENTBELT_LOOPBACK_ALL') == '1':
        return ('- This workspace has **loopback fully open** (JVM build grant). Binding, listening on, and self-connecting to any local port works.\n'
                '  Other local services of the same user (other agent servers, app ports) are reachable too, but they are unrelated to the project, so do not connect to them.\n')
    port = env.get('AGENTBELT_LOOPBACK_PORT', '')
    if not port:
        return '- Binding a local port outside the allow list is EPERM. Do not use options that turn on the VM service or a debugger.\n'
    return (f'- Binding a random local port is EPERM. If a local port is truly needed, only this session-only port `{port}`'
            ' (`$AGENTBELT_LOOPBACK_PORT`) may be used. Both binding and self-connecting work.\n'
            '- Dart coverage needs a VM service port, so run it like this:\n'
            '  `dart --enable-vm-service=$AGENTBELT_LOOPBACK_PORT --no-dds --disable-service-auth-codes test --coverage=coverage`\n'
            '  (Typing only `dart test --coverage` opens a random port and hangs.)\n')


def render_environment_notice(workspace, home, env, policy, extra=''):
    """Build the isolated environment description Markdown that is injected into the session.

    workspace/home are the real paths, env is the environment passed to the child, and policy is the sandbox_policy result.
    Only the presence of GH_TOKEN is recorded. If the value entered the document it would leak into logs and model input.
    """
    home = Path(home)
    has_github = bool(env.get('GH_TOKEN') or env.get('GITHUB_TOKEN'))
    github_line = ('GitHub authentication is injected through the `GH_TOKEN`/`GITHUB_TOKEN` environment variables and the '
                   '`.git-credentials` file in the isolated home. `gh` and `git push` can be used as they are.' if has_github else
                   'No GitHub token is injected. A `gh` authentication failure is not an environment defect but a missing setup.')
    return f"""# agentbelt isolated environment notice

This session is running inside a macOS Seatbelt sandbox. The supervisor generated the facts below from the
real policy values at session start. If the environment looks wrong, re-read this document before guessing:
`cat "$HOME/{NOTICE_FILE_NAME}"`

## Paths

- HOME is not the real user home but the isolated home: `{env.get('HOME', home)}`
{_data_home_line(home, env)}- Workspace (writable): `{workspace}`
- Always create temporary files in `$TMPDIR`: `{env.get('TMPDIR', '')}`
- `/tmp`, the real user home, and other project directories are blocked for both reading and writing.
- The Dart package cache is `$PUB_CACHE`: `{env.get('PUB_CACHE', '')}`. The `~/.pub-cache` of the host is
  blocked on purpose and `~` is the isolated home, so do not use that path. `dart pub get` downloads from
  pub.dev straight into this cache. There is no need to copy dependencies from the host.

## Readable tool and system paths

{_bullet_lines(_readable_roots(policy, workspace, home))}

PATH: `{env.get('PATH', '')}`

Executables outside the list above (for example `~/.local/bin`, other version managers) are not visible. That is not a
missing installation but something outside the boundary. `dart`, `gh`, `node`, and `npm` already installed on the host
can be used through the paths above.

## Network

Only the domains below are reachable, through the supervisor proxy. Anything outside the list fails at DNS.

{_bullet_lines(policy['network']['allowedDomains'])}

## What cannot run in here

- Nested `sandbox-exec` is refused by the kernel. Protected launchers such as `packet-ask`, `packet-ask-safe`,
  and `agentbelt.py` therefore do not run inside this session and must run on the host. That is by design, not a failure.
{_external_review_line(env)}
## Swift

- `swift file.swift` and `swiftc` work as they are. If you see "this SDK is not supported by the compiler", it is not a broken
  toolchain but a module cache problem, and since `CLANG_MODULE_CACHE_PATH` is already set it does not appear in a new session.
- Always run SwiftPM like this. Its own sandbox-exec is refused because nesting is denied, and `.build/build.db` inside the
  workspace is blocked by the secret file rule (`*.db`), so put scratch under `$TMPDIR`:
  `swift build --build-system native --disable-sandbox --scratch-path "$TMPDIR/swiftpm-build" --cache-path "$TMPDIR/swiftpm-cache"`
  (`swift test` and `swift run` take the same flags.) `--build-system native` is required: `swiftbuild`, the default since CLT 27,
  launches the linker-stage swiftc without TMPDIR and fails with `error: permissionDenied` while writing temporary files into the
  closed `/var/folders/.../T` (not a broken toolchain). Ignore deprecated warnings. If an index store is needed, use `-Xswiftc -index-store-path -Xswiftc "$TMPDIR/index"`.
- `NSTemporaryDirectory()` (= `/var/folders/.../T/`) differs from TMPDIR and is blocked by default. Subfolders opened as exceptions:
  {_inline_names(_darwin_temp_names(policy))} (read and write), `TemporaryItems` (write only). If another tool tries to put its
  cache there, that tool is ignoring TMPDIR, so look for an option on the tool side or ask the user to allow the folder name.

## Local ports

{_loopback_section(env)}
## JVM (Gradle, Maven, Kotlin)

- `java` uses the Homebrew JDK, not the `/usr/bin/java` stub. First `export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`
  (use `openjdk@21` and so on to match the version the project requires), then `export PATH="$JAVA_HOME/bin:$PATH"`. `/usr/libexec/java_home` cannot find a JDK here.
- `user.home`, `java.io.tmpdir`, and `GRADLE_USER_HOME` are already pinned to the isolated home (`JAVA_TOOL_OPTIONS`). Do not clear these values.
{_jvm_domains_line(policy)}- The Gradle daemon, the Kotlin daemon, and test workers need arbitrary loopback ports. If the "Local ports" section above does not say
  "loopback fully open", Gradle cannot run in this workspace, so ask the user for a `state/loopback-grants.json` grant and stop.
- The file watching warning "Could not start the FSEvents stream" is harmless and is already turned off with `org.gradle.vfs.watch=false`.

## Authentication

- {github_line}
- `~/.config/gh` is intentionally empty. Do not judge the login state from it.
- The git author identity is already in `$GIT_CONFIG_GLOBAL` (isolated home, locked). `git config user.name/email` fails because `.git/config` is locked.
  If a different identity is truly needed, pass it once with `git -c user.name=... -c user.email=...` or the `GIT_AUTHOR_*` environment variables.
- No `.git` can be created, replaced or removed in the workspace, the home or `$TMPDIR`, so `git init`, `git clone`, `git submodule add` and `git worktree add` fail, and the config, hooks, `commondir`, `modules` and `worktrees` of an existing repository are read-only (the host's git would otherwise obey them). Commit, branch, checkout and stash work. Git dependencies of SwiftPM (`.build/checkouts`), dart pub and cargo still work; tools that make their own checkout elsewhere (npm `git+` dependencies, `pip install git+...`, uv or Bundler git sources) fail, so use a released package or a source archive instead of retrying. To read another project's code, download a source archive instead of cloning.
- Access to the macOS Keychain and to the credentials in the real home is blocked.

## Do not

- When a tool is missing or a permission error appears, suspect the **sandbox boundary** first. Do not recommend or attempt
  `sudo`, `rm -rf`, reinstalling the Command Line Tools, or changing system settings. The system is fine.
- If access outside the boundary is truly needed, report to the user what is needed and why, then stop.

## Diagnostic commands

```sh
echo "HOME=$HOME"; echo "TMPDIR=$TMPDIR"; echo "PATH=$PATH"
cat "$HOME/{NOTICE_FILE_NAME}"
```
{extra}"""
