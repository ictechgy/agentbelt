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
| Terminal | A private PTY and filtered stdout/stderr. Input injection (`TIOCSTI`) is denied. |
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
| `safekimi` | [Kimi Code](https://www.kimi.com/code) CLI in the current directory | native/terminal clipboard access blocked, diagnostic uploads and banners disabled, loopback-only web, device-code login |
| `token-usage` | Alibaba Token Plan usage CLI | installation, login and queries stay confined; open the printed login URL in your browser |
| Zcode Safe.app | Original desktop launch blocked | Optional verified private copy; the guarded CLI backend remains available |
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

`token-usage setup` installs its CLI inside its isolated home, then starts a confined console login.
Open the printed URL in your browser; only the allocated loopback callback port is reachable.
Use `token-usage login` to renew the console session. Usage and verification helpers do not receive
repository GitHub credentials.

### Optional screenshot queue

With Google Chrome and `agent-browser` installed, guarded Kimi/OpenCode sessions start
a renderer for `shots/<name>.html` and return `shots/<name>.png`. Keep styles, fonts,
and images local to the project; external resources are unavailable. The host file
server rejects secret and agent-configuration paths, links and directory listings. Each watcher uses its own
browser profile and driver session, with a non-forwarding local proxy and Chrome's
native sandbox. Queue writes use pinned directory descriptors so a replaced path
cannot redirect output to host files.

Re-running `install.sh` upgrades the code in place. It never touches `state/` (isolated homes,
credentials, baselines) and never overwrites an existing `config.json`. `init` only fills in what is
missing and never overwrites a file it finds. If Zcode Safe.app is already installed, update its
managed launcher explicitly after installing the code:

```sh
/usr/bin/python3 ~/.local/share/agentbelt/adapters/install_profiles.py --upgrade-launcher
```

`installation.json` records the selected root/bin only after installation succeeds. The Safe app
records its root in the bundle for status and history operations, including customized installations.
It does not launch or reactivate the original Zcode GUI. When the verified private copy is installed,
the Safe manager opens that copy instead. Backend confinement cannot block the GUI's separate
repository uploader. Existing desktop sessions are not terminated; close both Zcode apps before
installing or upgrading the private copy.
Launching the original Zcode application directly remains outside agentbelt's protection.

### Private Zcode snapshot-blocked copy (optional)

The native Safe manager has a separate private-copy route for repositories that need a desktop
window. The installer is a Python API; there is no standalone private-copy CLI. Close both the
original and private Zcode apps before installing:

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

After upgrading the Safe app, register its bundle and select it as the `zcode://` handler.
The first command shows the former handler so it can be recorded for rollback:

```sh
"$HOME/Applications/Zcode Safe.app/Contents/MacOS/launch" --protocol-status
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$HOME/Applications/Zcode Safe.app"
"$HOME/Applications/Zcode Safe.app/Contents/MacOS/launch" --register-zcode-protocol
```

Then open Zcode Safe.app to launch the verified private copy. The legacy original GUI gates
remain blocked. Each installation creates a new generation; do not copy a manifest between roots.

The copy is version-locked to `3.12.3`, uses bundle ID
`local.agentbelt.zcode.snapshot-blocked`, and lives below the guard root. `check-zcode-private`
verifies its manifest and executable hash and returns a 32-character lowercase `generation`; the
manager accepts only the matching app path, generation-bound backend argv, private profile/session
directories, and the explicit flags that snapshot uploads and automatic updates are blocked. The
updater and the clone's startup protocol registration stay disabled.

The backend continues through the existing Seatbelt path. The desktop GUI itself is not OS
sandboxed, so `safe_launch` remains `false` and a backend receipt does not establish GUI
confinement. The private copy shares `~/.zcode`; its private Chromium user-data and session
directories are under `<install>/state/zcode-private/user-data` and
`<install>/state/zcode-private/session`. The manager can handle the `zcode://` route and forward
URLs to the verified private copy by explicit app path; OAuth values are not placed in argv, logs,
or files. Manual uploads and telemetry other than the snapshot patch remain outside this boundary.
Existing `check-zcode`, `check-zcode-gui`, `record-zcode-launch`, and `zcode-app` GUI gates remain
blocked. Real account, model, and OAuth execution have not been tested. A strict offline GUI-window
test was unavailable because both the original and private copy abort under the CLI sandbox; that
does not establish GUI confinement.

### Packet review privacy

`packet-ask-safe` and the GLM/Qwen `packet-review` relay separate collection from model execution.
The collector has read-only access to the original workspace, no network, no model credentials,
and an ephemeral home. Its bounded, scrubbed export becomes the only file in a fresh staging
workspace. The reviewer receives that staging workspace read-only and its own ephemeral home.
Qwen receives only the selected provider credential and domain, with tools disabled. Collector
or export verification failure stops the request before model credentials are obtained.

The ordinary upstream `packet-ask` command is still a separate text-scrubbing CLI, without an OS
sandbox. Use the protected entry points for this boundary. Scrubbing removes recognized patterns;
source code and unrecognized confidential text in the selected packet still reach the chosen
model API. There is no separate packet-ask service. Provider-side storage and training are outside
this local tool's control. `--preview` and `--dry-run` never launch the model.

### Trust on first install

`init` records the hash of every installed agent binary as its baseline. From then on a changed
binary refuses to launch until `agentbelt verify-updates` re-runs the test suite and records the new
hash. That is deliberate: an agent that updates itself is also an agent whose clipboard, network and
file behavior may have changed.

OpenCode and Kimi version probes execute protected copies inside Seatbelt with no network or
repository credentials. Packet-ask promotions are serialized across sessions and roll back if
installation or verification fails. Other packet operations wait until the installation is stable.
An interrupted promotion or failed rollback leaves packet execution blocked until the host install
is repaired; an uncertain installation is never accepted by restoring only its version label.
Normal OpenCode and Kimi launches also execute the verified copy, so replacing the original
binary between verification and execution cannot change the running version.

## Known limits

These are documented boundaries, not oversights:

- **Network allowlists are per host, not per path.** An agent allowed to reach `api.example.com` can
  reach every path on that host. A path-level broker is future work.
- **Terminal access goes through a private PTY.** All outgoing text, including
  piped/redirected stdout and stderr, passes through the host filter. It removes OSC 52 and
  unreviewed OSC/DCS/APC strings, including tmux passthrough. Native pasteboard access
  remains denied. UTF-8 text, normal styling, input, resize and signals are preserved;
  terminal image/passthrough protocols are unavailable. Text you paste is still input.
  Write binary exports to workspace files rather than these text output streams.
- **Kimi's verified execution copy disables diagnostic feedback and remote banners,
  and refuses non-loopback web binding.** These restrictions survive re-execution
  without `NODE_OPTIONS`. The original binary is unchanged; unknown builds fail closed
  until their privacy patch is reviewed. This is not an HTTPS firewall against arbitrary code.
- **Homebrew reads are limited to runtime roots and exact CA/OpenSSL files.** The
  general `etc`, `var` and `Caskroom` trees are outside the read allowance.
- **The agent's own config is writable across sessions** for agents that need it at login time (Kimi
  Code). A session can plant configuration that the next session in the same project reads. The
  effect stays inside the sandbox.
- **A GitHub token, when injected, is visible to the session.** The model never sees it directly, but
  an agent that prints its environment puts it in context. Inject it only for projects where you
  want the agent to push.
- **Prompts inside the sandbox are not proof of a human.** Anything that needs a real approval
  happens on the host, before launch, as policy.

- **The Gemini/agy review relay is disabled.** Its host agent had no enforced confinement.
  Use `packet-review --provider glm` or `--provider qwen`.

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
tests/                  regressions, including real Seatbelt boundary and synthetic failure tests
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
