# Architecture

## One launch, end to end

1. A wrapper (`safecode`, `safekimi`, ...) runs `/usr/bin/python3 -I agentbelt.py <mode> ...`.
   `-I` ignores `PYTHON*` variables and user site-packages, so the supervisor's imports are its own.
2. `workspace_path()` resolves the project directory and refuses the home itself, hidden
   directories, personal folders, and any tree that contains hard links pointing outside it.
3. The mode verifies the agent binary against `state/compatibility.json` (SHA-256). For binaries the
   operator's tools can update in place, the mode clones the file to a guard-owned directory,
   re-hashes the clone and executes only the clone.
4. `run_confined()` builds:
   - a **persistent isolated home** per (mode, workspace) under `state/homes/`, or an ephemeral one;
   - a **clean environment** (`clean_environment`): `HOME`, `TMPDIR`, XDG dirs, package caches,
     telemetry-off flags, explicitly granted scoped GitHub token, terminal capability list derived from the
     supervisor's own descriptors (never from the caller's environment);
   - a **policy** (`sandbox_policy`) for sandbox-runtime: default-deny read of `/`, explicit read
     roots, write roots (workspace + home), `denyWrite` for secret globs and agent config, network
     allowlist, no local binding unless granted;
   - the **environment notice** written into the home and locked read-only.
5. `terminal_proxy.py` owns a new session and substitutes a private PTY for every
   terminal descriptor, including stdin. It mediates terminal output and updates the
   TTY capability list; non-terminal output pipes remain separate but also pass through
   the filter. A fresh exec helper owns the session/TTY, avoiding Python preexec callbacks
   in the multi-threaded relay parent. Fully redirected children have no controlling TTY.
   `sandbox_runner.mjs` (trusted, unsandboxed Node) asks sandbox-runtime for the SBPL profile and
   appends the rules sandbox-runtime does not express: pasteboard, Keychain, Apple Events,
   LaunchServices and preference daemons denied by mach name; `trustd` allowed; TTY ioctls limited
   to the private terminal; `TIOCSTI` denied; writable roots protected from rename; the workspace
   git lock (`git_lock.mjs`); per-launch loopback ports; per-workspace opt-ins. It then execs `sandbox-exec -p <profile> ...`.
6. The child runs. Anything that must happen outside the sandbox on the child's behalf (external
   model review, publishing, status relay) goes through a **file-channel relay** or a
   **loopback broker** owned by the supervisor, which holds the real credentials and rewrites identity.

The Kimi execution copy receives an exact-build, equal-length SEA source patch before
ad-hoc signing and strict signature verification. Diagnostic feedback, remote banners,
and non-loopback web startup are disabled in that copy; removing preload environment
variables does not restore them. Unknown builds fail closed; the original is unchanged.
The separate preload retains its directory-watching compatibility role. Neither replaces
OS egress policy or turns arbitrary code into a trusted network client. Homebrew access covers
installed runtime trees and exact trust-store files, not the entire installation prefix.

## Invariants worth keeping

- **GUI and backend protection are separate.** Original Zcode desktop launch and activation stay
  blocked. The optional private-copy route uses a version-locked, hash- and generation-verified
  clone, but the desktop GUI itself is not OS-confined; `safe_launch` remains `false` and a
  backend receipt never establishes GUI file/network confinement. Direct protected backends
  remain usable and the original vendor application is not modified.
  Desktop DB preparation uses the verified private bundle's Worker with the fixed
  `--prepare-storage` arguments. It runs with the GUI's privileges and exits before
  provider or tool initialization; model sessions still use the guarded Agent command.
- **Packet collection and review use different sandboxes.** An offline, keyless, read-only
  collector exports the public packet-ask dry-run JSON contract. The model sees only a verified
  scrubbed staging packet and gets one provider's credentials and domain. Qwen has no tools or
  raw-workspace fallback. Review homes are ephemeral and do not copy the host Git identity.
- **Short temporary paths are fresh per launch.** Exclusive random directory creation replaces
  the reusable 28-bit workspace hash. Even persistent-home sessions clean up their short TMPDIR.
- **Preexisting agent configuration is untrusted.** Guarded Zcode modes deny reads as well as
  writes to project `.zcode`, `zcode.json` and `.agents/mcp.json` settings.
- **Hook logging cannot wait on a child-created FIFO.** Audit files are opened nonblocking and
  must be owned private regular files with one link before a verdict is appended.
- **`agentbelt.py` must not import sibling modules at top level.** `zcode_hook.py` imports it from
  inside the sandbox; any import failure there is translated into a `deny` decision, so a new
  top-level import that is unreadable inside the sandbox silently denies every tool call.
  Host-only modules live in `adapters/` and are imported lazily inside `main()` / `run_confined()`;
  `environment_notice` stays at the root but is also imported lazily.
- **Owner home comes from the account database, not `$HOME`.** Inside the sandbox `$HOME` is the
  isolated home; `workspace_path()` would otherwise judge boundaries against the wrong root.
- **Supervisor writes into child-writable trees use held no-follow directory descriptors.** `write_private_file` descends with
  `O_DIRECTORY|O_NOFOLLOW` directory descriptors, refuses links and foreign ownership, and creates
  the final file with `O_CREAT|O_EXCL|O_NOFOLLOW`. The packet queue also keeps directory descriptors
  for reads, atomic response publication and request deletion. A previous session may have planted symlinks.
- **Repository credentials default absent.** Coding modes explicitly opt in; usage, review,
  history writers and candidate probes do not receive the GitHub token.
- **No child-writable executable returns to host authority.** Usage login remains confined; its
  scoped preload maps random loopback binding onto the single supervisor-granted callback port.
  The operator opens the printed browser URL. Gemini host review is disabled until independently confined.
- **Candidate probes run on protected copies.** OpenCode and Kimi versions and hashes come from
  the same copied bytes, with no network or repository credentials and a bounded process lifetime.
- **Promotion is one global transaction.** A guard-owned file lock spans the current-version read,
  installation, adapter checks, tests, skills, pin publication, rollback and audit. Consumers take a
  shared lock for their whole operation. Only guard-test subprocesses receive a private capability
  for the unpublished candidate; it is not passed to sandbox children. Installer failure attempts
  rollback, checks restored metadata and package bytes, and leaves the pin invalid if restoration
  is uncertain. Normal shutdown and SIGTERM wait for active relay work; force-killing a promoter
  leaves the pre-invalidated pin closed.
- **Review deadlines include lock acquisition.** Live packet pipelines take a cancellable
  shared lock against the current guard root. Ordinary shutdown cancels credential preparation,
  collector and model processes; an active promotion or rollback still finishes durably.
- **Screenshot HTML is untrusted.** `shot_queue.py` pins directories and opens inputs without
  following links; errors, logs and screenshots cannot redirect host writes through queue paths.
  The HTTP service enforces secret-name exclusions and also acts as a non-forwarding proxy.
  Private Chrome profiles retain their native sandbox and use isolated driver sessions, fixed CDP,
  restrictive browser policies and proxy settings that include loopback requests.
- **Relay work is bounded per poll.** The cursor examines at most 128 entries, consumes completed
  requests, expires responses after 24 hours, and counts malformed requests against the rate budget.
- **`denyWrite` beats `allowWrite`; specific operations beat wildcards.** Re-allowing one file that
  a secret glob catches (`gradle.keystore`) requires appending a rule that lists the same concrete
  operations after the generated profile.
- **Host git must not obey state the child wrote.** Host git trusts every gitdir it discovers.
  Measured (git 2.54, 2026-09-24): an unsandboxed `git status` ran a child-chosen `core.fsmonitor`
  through `.git/commondir`, `.git/modules/*/config`, a nested repository registered as a gitlink,
  or a `.git` replaced by a link or `gitdir:` file. `git_lock.mjs` therefore denies creating,
  replacing or removing any `.git` entry below every write root (workspace, home, TMPDIR, so a
  repository cannot be built elsewhere and moved in), and every write to `config`,
  `config.worktree`, `hooks`, `info/attributes`, `commondir`, `modules` and `worktrees` inside any
  gitdir. The deny must list `file-write-create`/`file-write-unlink` explicitly: SRT re-allows
  those two as concrete operations for write roots, which beat a wildcard deny. Package managers'
  checkout trees stay open (`<workspace>/.build/checkouts`, `<home>/.pub-cache/git`,
  `<home>/.cargo/git`); `git_audit.py` compares the workspace before and after each session and
  warns about new nested repositories outside those trees and new gitlinks in the index. Commit,
  branch, checkout, stash and gc still work; clone, init, submodule and worktree creation do not.
- **Never allow `com.apple.FSEvents`.** Measured: a sandboxed client receives file-name events for
  read-denied paths. Directory watchers get a preload that returns an inert watcher plus polling.
- **Provider allowlists are exact.** `PROVIDER_HOSTS` and `PROVIDER_ENDPOINTS` are extended
  together; the imported definition is reduced to `{type, key}` plus a sanitized model list, never
  headers, `{env:}` substitutions, `api` or SDK overrides.
- **Baselines close, they do not warn.** A changed binary refuses to launch until
  `verify-updates` re-runs the suite. Tests must not skip on a baseline mismatch, or the update
  path certifies an untested candidate.
- **Control directories carry an owner marker** (`owner.json`: pid + start time). Reaping removes
  only directories whose owner is provably gone; an orphan without a marker is left alone.

## Bootstrap of a fresh installation

`install.sh` copies code, pins Node and builds the launcher. `agentbelt init` then creates the state a fresh
machine lacks, and only what is missing: the reviewed package-registry list (`state/development.json`), an
example riskgate policy when the operator has none, Zcode profiles and the Safe app when Zcode is installed,
the packet-ask version gate when packet-ask is installed, and a hash baseline for every installed agent.
That baseline is trust-on-first-install; later changes normally use `verify-updates`. The explicit
AutoClaw installer `--rebaseline` option is an additional operator-controlled path.
Every integration is optional: `doctor` reports `null` for absent agents and fails only when a present one
does not match its baseline.

## Optional private Zcode copy

The private desktop route is optional. Its installer is a Python API rather than a standalone CLI;
close both the original and private Zcode apps before calling it:

```sh
/usr/bin/python3 -I <<'PY'
import sys
from pathlib import Path
root = Path.home() / '.local/share/agentbelt'
sys.path.insert(0, str(root))
from adapters.zcode_privacy import install
install(root)
PY
```

Use Zcode Safe.app to open the verified private copy; the legacy original GUI gates remain blocked.
The private app lives at `<install>/state/zcode-private/ZCode.app`; each publication gets a new
generation. The upgraded manager handles `zcode://` through bundle ID
`local.agentbelt.zcode.safe-launcher`. The operator records the previous handler before changing
that association; see the README for registration commands.

The clone is locked to desktop version `3.14.3`, uses bundle ID
`local.agentbelt.zcode.snapshot-blocked`, and is placed under the guard root. The
`check-zcode-private` contract verifies the manifest and executable hash, returns the clone path,
protected environment, and a 32-character lowercase generation, and the native manager accepts
only generation-bound backend arguments and the exact private profile/session directories.
Snapshot uploads and automatic updates must be reported blocked. In the reviewed 3.14.3
distribution, the former repository snapshot sidecar is absent. Exact ASAR and CLI hashes
bind that upstream change. HOST retains the bundled storage-only Worker. HOST and SCHEDULER
each contain a conversation-share service, and both require publish stubs. The clone's updater
and startup protocol registration remain disabled; the manager's explicit `zcode://` route may forward to
the verified clone without putting OAuth values in argv, logs, or files. The private copy shares
`~/.zcode`; private Chromium user-data and session directories are under
`<install>/state/zcode-private/user-data` and `<install>/state/zcode-private/session`.

The backend still uses the existing Seatbelt launch path. Because the GUI is not OS-confined,
the manager must not report `safe_launch=true`. The legacy GUI gates (`check-zcode`,
`check-zcode-gui`, `record-zcode-launch`, and `zcode-app`) remain blocked. Real account and model
execution and OAuth flows are outside the current verification scope. Manual uploads and telemetry
outside the snapshot patch are not covered. A strict offline GUI-window test was unavailable because
both the original and private copy abort under the CLI sandbox; that does not establish GUI
confinement.

## Where things live

| Path | Contents |
| --- | --- |
| `<install>/state/homes/<mode>/<sha(workspace)[:20]>` | isolated home per project: agent config, sessions, caches, `tmp/` |
| `<install>/state/control-*` | per-launch control dir: `owner.json`, `policy.json`, protected runtime home |
| `<install>/state/compatibility.json` | reviewed binary hashes and versions |
| `<install>/state/*-profile.json` | per-mode network/provider policy |
| `<install>/state/*-grants.json` | per-workspace opt-ins (loopback, keystore, pub publish) |
| `<install>/state/opencode-auth.json` | imported provider keys, 0600, linked read-only into homes |
| `<install>/config.json` | operator path overrides (pinned `node`, tool binaries) |
| `<install>/installation.json` | successfully installed root/bin paths; no credentials |

`state/` is the only place with secrets or user data and is never part of the repository.

## Testing philosophy

A boundary claim is accepted only with a kernel-level observation: run a probe inside the real
profile and read what the kernel returned. Pure unit tests cover wiring (which mode passes which
option) and parsing; they do not stand in for the probe. When a test needs a Node child, its
stderr is a pipe, never a file outside the sandbox (see the `fstat` abort in the README).
