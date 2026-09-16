# agent-guard

Run third-party AI coding agents on macOS **confined to one project directory**, with the
boundary enforced by the kernel (Seatbelt) and verified by tests that actually try to cross it.

`agent-guard` is a supervisor. It launches an agent CLI (OpenCode, Kimi Code, the Zcode desktop
backend, AutoClaw's bundled runtime) inside `sandbox-exec` with a policy generated per launch:

- **Filesystem:** read access to the workspace, a per-project isolated `HOME`, and the tool
  binaries the agent needs; everything else, including the operator's real home, is invisible.
  Secret-looking files inside the workspace (`.env`, keys, keystores, SQLite DBs) stay unreadable.
- **Network:** only an allowlist of provider and package-registry hosts, through a supervisor-owned
  HTTPS proxy. Telemetry, auto-update and CDN hosts are not on it.
- **Desktop services:** clipboard (pasteboard), Keychain, Apple Events, LaunchServices and FSEvents
  are denied by mach-service name. The agent cannot read what you copied, and cannot watch file
  names change outside its workspace.
- **Terminal:** only the inherited TTY, with `TIOCSTI` input injection denied.
- **Credentials:** provider keys are imported once from the host tool's own auth store, only for
  reviewed providers, into a guard-owned file that is linked into each isolated home. A repo-scoped
  GitHub token can be injected per session.
- **Self-description:** every session starts with a generated `AGENT_GUARD_ENVIRONMENT.md` that
  tells the agent exactly what it can and cannot reach, so it does not misdiagnose the sandbox as a
  broken machine.

The interesting knowledge is in the tests: 300+ regressions, most of which run a real Seatbelt
profile and check the kernel's answer (clipboard probe reads 0 types, FSEvents stream fails to
start, `pbpaste` exits 1, symlink escapes are refused, the auth file cannot be replaced, ...).

## Status

Extracted from a single operator's daily setup (September 2026). It works, it is tested, and it is
opinionated. Expect:

- macOS only, Apple Silicon tested. It depends on `/usr/bin/sandbox-exec` and on
  [`@anthropic-ai/sandbox-runtime`](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) 0.0.75
  (Apache-2.0), pinned via `runtime/package-lock.json`.
- Adapters are pinned to reviewed binary hashes. When OpenCode or Kimi updates itself, launches
  are refused until `agent-guard verify-updates` re-runs the suite and records the new baseline.
  That is deliberate.
- Comments and the design notes under `docs/` are in Korean; the code identifiers and this README
  are English. Translation is in progress.

## Modes

| Wrapper | Agent | Notes |
| --- | --- | --- |
| `safecode` | [OpenCode](https://opencode.ai) TUI in the current directory | protected config, provider allowlist, packet-review relay |
| `opencode-safe <path>` | OpenCode with an explicit workspace | same policy as `safecode` |
| `safekimi` | [Kimi Code](https://www.kimi.com/code) CLI in the current directory | clipboard denied at the kernel, device-code login inside the sandbox, watcher preload (see below) |
| `token-usage` | Alibaba Token Plan usage CLI (`bl`) | isolated install, host login once |
| Zcode Safe.app | Zcode desktop with a confined agent backend | Dock launcher built from `ZcodeSafe.swift` |
| `autoclaw-backend` | AutoClaw's bundled Zcode CLI | installed by `install_autoclaw.py`; yolo mode, no host exec |

Run `agent-guard doctor` to see which baselines are verified.

## Install

```sh
git clone https://github.com/<you>/agent-guard
cd agent-guard
./install.sh              # copies code to ~/.local/share/agent-guard, pins node, npm ci, builds the launcher
agent-guard doctor
cd ~/.local/share/agent-guard && /usr/bin/python3 -m unittest discover -s tests
```

Then import credentials for the providers you use (only allowlisted providers are copied, and
only `{type, key}`):

```sh
cd ~/.local/share/agent-guard
/usr/bin/python3 configure_existing.py --authorized-live-settings
cd ~/my-project && safecode
```

`install.sh` never touches `state/` (isolated homes, credentials, baselines) and never overwrites an
existing `config.json`, so re-running it upgrades the code in place.

## Why not just trust the agent's own permission prompts?

Because prompts run inside the process you are trying to contain. A hook or permission UI can be
disabled by the agent editing its own config. Here the policy is applied by the kernel before the
agent starts, the agent's config directory is read-only inside the sandbox, and the supervisor
writes into child-writable trees only through `O_NOFOLLOW`, directory-fd-relative code paths so a
symlink planted by a previous session cannot redirect a trusted write.

## Things we learned the hard way

Short versions; the tests and `docs/` carry the details.

- `sandbox-exec` cannot be nested. Anything that needs its own sandbox (our own review tool,
  SwiftPM's sandbox) must be relayed by the supervisor or run with sandboxing disabled inside.
- Seatbelt rule precedence: `denyWrite` beats `allowWrite`; a rule naming specific operations beats
  a wildcard `file-write*`; regex has no negative lookahead; `/tmp` is a symlink, so test with real
  paths.
- Removing a `deny` line from a default-deny profile is not an `allow`. Go and Dart use the macOS
  trust evaluator, so `com.apple.trustd.agent` needs an explicit allow or TLS never completes.
- **FSEvents leaks.** Allowing `com.apple.FSEvents` to a sandboxed client delivers change events
  for paths the client cannot read (other apps' caches, temp files). We keep it denied. libuv reports
  the failed stream as `EMFILE`, which is not descriptor exhaustion; Node agents that watch
  directories need a preload (`kimi_watch_bootstrap.cjs`) plus polling (`CHOKIDAR_USEPOLLING=1`).
- Node aborts at startup (`SIGABRT` in `InitializeOncePerProcessInternal`) when an inherited
  stdio descriptor points at a file the sandbox cannot `fstat`. A test runner redirecting stderr to
  a log outside the sandbox triggers it; a TTY or pipe does not.
- Agents misdiagnose the sandbox ("CLT is broken", "gh is not installed", "network is down") unless
  told what they are inside. The generated environment notice removed most of those reports.
- OSC 52 clipboard *reads* are a terminal feature, not a kernel one. Check whether your terminal
  answers `ESC ] 52 ; c ; ? BEL`; the one used here (Orca) does not.

## Layout

```
agent_guard.py          supervisor: policy, run_confined, mode dispatch
sandbox_runner.mjs      trusted wrapper around sandbox-runtime; appends the extra SBPL rules
environment_notice.py   per-session environment description for the agent
kimi_cli.py             Kimi Code mode      configure_existing.py  OpenCode provider import
usage_cli.py            Token Plan mode     compatibility_check.py binary baselines
zcode_hook.py           in-sandbox tool hook (riskgate policy) for Zcode
packet_relay.py         supervisor-side review relay (agent cannot nest sandboxes)
install_autoclaw.py     AutoClaw integration installer
ZcodeSafe.swift         Dock launcher for the Zcode desktop integration
tests/                  regressions; most exercise a real Seatbelt profile
vendor/riskgate         vendored policy engine (MIT)
docs/ko/                Korean operator docs; docs/design/ko/ design notes and review records
```

## License

MIT. `vendor/riskgate` is MIT; `@anthropic-ai/sandbox-runtime` is Apache-2.0 and installed from npm.
