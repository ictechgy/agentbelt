# Architecture

## One launch, end to end

1. A wrapper (`safecode`, `safekimi`, ...) runs `/usr/bin/python3 -I agent_guard.py <mode> ...`.
   `-I` ignores `PYTHON*` variables and user site-packages, so the supervisor's imports are its own.
2. `workspace_path()` resolves the project directory and refuses the home itself, hidden
   directories, personal folders, and any tree that contains hard links pointing outside it.
3. The mode verifies the agent binary against `state/compatibility.json` (SHA-256). For binaries the
   operator's tools can update in place, the mode clones the file to a guard-owned directory,
   re-hashes the clone and executes only the clone.
4. `run_confined()` builds:
   - a **persistent isolated home** per (mode, workspace) under `state/homes/`, or an ephemeral one;
   - a **clean environment** (`clean_environment`): `HOME`, `TMPDIR`, XDG dirs, package caches,
     telemetry-off flags, optional scoped GitHub token, terminal capability list derived from the
     supervisor's own descriptors (never from the caller's environment);
   - a **policy** (`sandbox_policy`) for sandbox-runtime: default-deny read of `/`, explicit read
     roots, write roots (workspace + home), `denyWrite` for secret globs and agent config, network
     allowlist, no local binding unless granted;
   - the **environment notice** written into the home and locked read-only.
5. `sandbox_runner.mjs` (trusted, unsandboxed Node) asks sandbox-runtime for the SBPL profile and
   appends the rules sandbox-runtime does not express: pasteboard, Keychain, Apple Events,
   LaunchServices and preference daemons denied by mach name; `trustd` allowed; TTY ioctls limited
   to the inherited terminal; `TIOCSTI` denied; writable roots protected from rename; per-launch
   loopback ports; per-workspace opt-ins. It then execs `sandbox-exec -p <profile> ...`.
6. The child runs. Anything that must happen outside the sandbox on the child's behalf (external
   model review, publishing, status relay) goes through a **file-channel relay** or a
   **loopback broker** owned by the supervisor, which holds the real credentials and rewrites identity.

## Invariants worth keeping

- **`agent_guard.py` must not import sibling modules at top level.** `zcode_hook.py` imports it from
  inside the sandbox; any import failure there is translated into a `deny` decision, so a new
  top-level import that is unreadable inside the sandbox silently denies every tool call.
  Host-only modules (`kimi_cli`, `usage_cli`, `environment_notice`, `packet_relay`) are imported
  lazily inside `main()` / `run_confined()`.
- **Owner home comes from the account database, not `$HOME`.** Inside the sandbox `$HOME` is the
  isolated home; `workspace_path()` would otherwise judge boundaries against the wrong root.
- **Supervisor writes into child-writable trees only via `write_private_file`.** It descends with
  `O_DIRECTORY|O_NOFOLLOW` directory descriptors, refuses links and foreign ownership, and creates
  the final file with `O_CREAT|O_EXCL|O_NOFOLLOW`. A previous session may have planted symlinks.
- **`denyWrite` beats `allowWrite`; specific operations beat wildcards.** Re-allowing one file that
  a secret glob catches (`gradle.keystore`) requires appending a rule that lists the same concrete
  operations after the generated profile.
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

## Where things live

| Path | Contents |
| --- | --- |
| `<install>/state/homes/<mode>/<sha(workspace)[:20]>` | isolated home per project: agent config, sessions, caches, `tmp/` |
| `<install>/state/control-*` | per-launch control dir: `owner.json`, `policy.json`, protected runtime home |
| `<install>/state/compatibility.json` | reviewed binary hashes and versions |
| `<install>/state/*-profile.json` | per-mode network/provider policy |
| `<install>/state/*-grants.json` | per-workspace opt-ins (loopback, keystore, pub publish) |
| `<install>/state/opencode-auth.json` | imported provider keys, 0600, hard-linked into homes |
| `<install>/config.json` | operator path overrides (pinned `node`, tool binaries) |

`state/` is the only place with secrets or user data and is never part of the repository.

## Testing philosophy

A boundary claim is accepted only with a kernel-level observation: run a probe inside the real
profile and read what the kernel returned. Pure unit tests cover wiring (which mode passes which
option) and parsing; they do not stand in for the probe. When a test needs a Node child, its
stderr is a pipe, never a file outside the sandbox (see the `fstat` abort in the README).
