# agentbelt

Run AI coding agents on macOS **confined to one project directory**. The boundary is enforced by the
kernel (Seatbelt) and verified by tests that actually try to cross it.

한국어 안내: [docs/ko/README.md](docs/ko/README.md)

## What it does

agentbelt is a supervisor. It launches an agent CLI inside `sandbox-exec` with a policy generated
for that one launch. Inside the sandbox the agent sees:

| Resource | What the agent gets |
| --- | --- |
| Files | The project directory, a per-project isolated `HOME`, and the tool binaries it needs. Your real home, other projects, Keychain and `/opt/homebrew/var` are invisible. Secret-looking files inside the project (`.env`, keys, keystores, SQLite DBs) stay unreadable. |
| Network | Only an allowlist of provider and package-registry hosts, through a supervisor-owned HTTPS proxy. Telemetry, auto-update and CDN hosts are not on it. |
| Desktop services | Clipboard, Keychain, Apple Events, LaunchServices and FSEvents are denied by service name. The agent cannot read what you copied and cannot watch file names change outside its project. |
| Terminal | Only the inherited TTY. Input injection (`TIOCSTI`) is denied. |
| Credentials | Provider keys are imported once from the agent's own auth store, only for reviewed providers, into a supervisor-owned file linked into each isolated home. A repository-scoped GitHub token can be injected per session. |
| Self-description | A generated `AGENTBELT_ENVIRONMENT.md` in every session says exactly what is reachable, so the agent does not misdiagnose the sandbox as a broken machine. |

The agent's own permission prompts keep working; agentbelt sits underneath them. A prompt or hook
runs inside the process you are trying to contain, so the agent can switch it off by editing its own
config. The Seatbelt policy is applied before the agent starts and cannot be widened from inside.

## Supported agents

| Command | Agent | Notes |
| --- | --- | --- |
| `safecode` | [OpenCode](https://opencode.ai) TUI in the current directory | protected config directory, provider allowlist, supervisor-side review relay |
| `opencode-safe <path>` | OpenCode with an explicit project path | same policy as `safecode` |
| `safekimi` | [Kimi Code](https://www.kimi.com/code) CLI in the current directory | clipboard denied in the kernel, device-code login inside the sandbox, directory watching without FSEvents |
| `token-usage` | Alibaba Token Plan usage CLI | isolated install; the one-time console login runs on the host |
| Zcode Safe.app | Zcode desktop with a confined agent backend | Dock launcher built from `ZcodeSafe.swift`; per-tool policy via riskgate |
| `autoclaw-backend` | AutoClaw's bundled Zcode CLI | installed by `adapters/install_autoclaw.py`; no host `exec` for the outer agent |

Every integration is optional. `agentbelt doctor` reports which ones are installed and whether their
binaries still match the reviewed hashes.

## Requirements

- macOS with `/usr/bin/sandbox-exec`. Developed and tested on macOS 26 / Apple Silicon; older
  releases and Intel Homebrew layouts are untested.
- Xcode Command Line Tools (`/usr/bin/python3`, `clang`; `swiftc` only for the Zcode Dock launcher).
- Node 22 or newer for the supervisor runtime. The chosen binary is pinned in `config.json` so a later
  `nvm install` or `brew upgrade` cannot swap it silently.
- At least one of the agents above, installed from its official source before you run `agentbelt init`.

## Install

```sh
git clone https://github.com/ictechgy/agentbelt
cd agentbelt
./install.sh        # copies code to ~/.local/share/agentbelt, pins node, npm ci, builds the launcher
agentbelt init      # creates the state files this machine is missing and records agent hashes
agentbelt doctor    # which agents are present, and whether each matches its recorded hash
```

The commands land in `~/.local/bin`; make sure it is on your `PATH`.

For OpenCode, import the provider keys you use. Only allowlisted providers are copied, and only the
`{type, key}` fields:

```sh
/usr/bin/python3 ~/.local/share/agentbelt/adapters/configure_existing.py --authorized-live-settings
cd ~/my-project && safecode
```

For Kimi Code there is nothing to import: `cd ~/my-project && safekimi`, then `/login` inside the
session. The device-code URL is printed; open it in your browser. The token stays in that project's
isolated home.

Re-running `install.sh` upgrades the code in place. It never touches `state/` (isolated homes,
credentials, baselines) and never overwrites an existing `config.json`. `init` only fills in what is
missing and never overwrites a file it finds.

### Trust on first install

`init` records the hash of every installed agent binary as its baseline. From then on a changed
binary refuses to launch until `agentbelt verify-updates` re-runs the test suite and records the new
hash. That is deliberate: an agent that updates itself is also an agent whose clipboard, network and
file behavior may have changed.

## Known limits

These are documented boundaries, not oversights:

- **Network allowlists are per host, not per path.** An agent allowed to reach `api.example.com` can
  reach every path on that host. A path-level broker is future work.
- **The terminal is outside the sandbox.** If your terminal answers OSC 52 clipboard *read* queries,
  any child process can read the clipboard through it. Check yours; the one used during development
  does not answer.
- **The agent's own config is writable across sessions** for agents that need it at login time (Kimi
  Code). A session can plant configuration that the next session in the same project reads. The
  effect stays inside the sandbox.
- **A GitHub token, when injected, is visible to the session.** The model never sees it directly, but
  an agent that prints its environment puts it in context. Inject it only for projects where you
  want the agent to push.
- **`/opt/homebrew` is readable except `var`.** Tool binaries need it; configuration under `etc` and
  the Cellar are visible.
- **Prompts inside the sandbox are not proof of a human.** Anything that needs a real approval
  happens on the host, before launch, as policy.

## Things we learned the hard way

The tests and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) carry the details.

- `sandbox-exec` cannot be nested. Tools that bring their own sandbox (SwiftPM, our review helper)
  must run with it disabled inside, or be relayed by the supervisor.
- Seatbelt precedence: `denyWrite` beats `allowWrite`; a rule naming specific operations beats a
  wildcard `file-write*`; regexes have no negative lookahead; `/tmp` is a symlink, so test with real
  paths.
- Removing a `deny` line from a default-deny profile is not an `allow`. Go and Dart use the macOS
  trust evaluator; without an explicit allow for `com.apple.trustd.agent` TLS never completes.
- **FSEvents leaks.** A sandboxed client that is allowed `com.apple.FSEvents` receives file-name
  change events for paths it cannot read. It stays denied. libuv reports the failed stream as
  `EMFILE`, which has nothing to do with descriptor limits; Node agents that watch directories get a
  preload that returns an inert watcher, plus stat polling.
- Node aborts at startup when an inherited stdio descriptor points at a file the sandbox cannot
  `fstat`. A test runner redirecting stderr to a log outside the sandbox triggers it; a TTY or pipe
  does not.
- Agents invent causes for what they cannot see ("the toolchain is broken", "gh is not installed").
  Telling them what the sandbox is, at session start, removed most of those reports.

## Repository layout

```
agentbelt.py            supervisor: policy, run_confined, mode dispatch
sandbox_runner.mjs      trusted wrapper around sandbox-runtime; appends the extra SBPL rules
environment_notice.py   per-session environment description for the agent
zcode_hook.py           in-sandbox tool hook for Zcode (riskgate policy)
packet_entry.py         in-sandbox entry for the packet-ask review adapter
*_bootstrap.{mjs,cjs}   Node preloads injected into confined agents
adapters/               host-side only: kimi_cli, usage_cli, configure_existing, compatibility_check,
                        bootstrap (init), packet_relay, orca_broker, install_autoclaw, ...
ZcodeSafe.swift         Dock launcher for the Zcode desktop integration
examples/riskgate.yaml  policy installed by `init` when you have none
tests/                  319 regressions; most run a real Seatbelt profile and read the kernel's answer
vendor/riskgate         vendored policy engine (MIT)
docs/                   ARCHITECTURE.md, design notes (docs/design), Korean docs (docs/ko)
```

Runtime state lives in `~/.local/share/agentbelt/state/` and is never part of the repository. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the launch sequence, the invariants that must not
be broken, and the testing rule (a boundary claim needs a kernel-level observation).

## Status

Extracted in September 2026 from one operator's daily setup and hardened for other machines since:
no personal paths, an `init` that works with any subset of agents, and an installer that validates
its destinations. Findings from independent Codex reviews have been folded in. CI runs the self-contained kernel
tests on GitHub's macOS runners; tests that need the agent binaries run on an operator machine via
`agentbelt verify-updates`.

Depends on [`@anthropic-ai/sandbox-runtime`](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime)
0.0.75 (Apache-2.0), pinned via `runtime/package-lock.json`.

## License

MIT. `vendor/riskgate` is MIT.
