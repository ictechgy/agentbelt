# Native guard skeleton and authenticated control transport — R2

Status: a buildable skeleton with tests on the host. `native/guard` contains:

- a container app, which will also act as the approver;
- an Endpoint Security system extension (File Guard);
- a native launch supervisor;
- the GuardKit Swift package they share.

Only the unsigned build and host tests have been run. Nothing was signed, installed or
activated, and no Endpoint Security client was created. In a build made before the
review fixes, `es_new_client` returned `ERR_NOT_PRIVILEGED`, as expected. The current
unsigned build stops earlier, at configuration. Apple ES approval is still unconfirmed.

The roles and rules come from the [task registry model](task-registry.md). This document
covers how those roles become processes and how they authenticate each other.

## Checks

```sh
swift test --package-path native/guard/GuardKit
cd native/guard && xcodegen generate && \
  xcodebuild -project AgentbeltGuard.xcodeproj -scheme AgentbeltGuard -configuration Debug \
    -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
```

GuardKit tests use synthetic signers, an in-process anonymous XPC listener and
`/bin/sleep` children. No agent, credential or network is involved.

## Components

| Target | Product | Role in the registry model | Entitlement declared | Approval status |
| --- | --- | --- | --- | --- |
| `AgentbeltGuard` | Container app | Installs and removes File Guard on explicit user action. Planned approver signer | `com.apple.developer.system-extension.install` | Not signed; profile not checked |
| `FileGuard` | System extension | Owns the registry and the ES client; serves the control Mach service | `com.apple.developer.endpoint-security.client` | Capability request reported submitted; approval not confirmed |
| `agentbelt-supervisor` | Command-line tool | Supervisor signer. Performs the gated launch | None; hardened runtime | Not signed |
| `GuardKit` | Swift package | GuardCore (protocol, trust, role gate), GuardTransport (XPC, code identity), SpawnGate (C launch gate) | — | Host tests only |

The entitlement files were copied from the request templates. Declaring an entitlement is
not the same as having it granted. An unsigned build carries neither. A signed build is
valid only with a provisioning profile that includes the approved capability.

`Config/Signing.xcconfig` holds placeholders (`invalid.agentbelt.unconfigured`, an empty
Team ID). Real values go in the untracked `Config/Signing.local.xcconfig`, followed by
`xcodegen generate`. The generation step is needed because the system extension's bundle
file name must equal its bundle identifier, and XcodeGen fixes product paths when it
generates the project.

## Fail-closed behavior verified on the host

| Situation | Observed |
| --- | --- |
| File Guard built with placeholder values | Exits `EX_CONFIG` (78) before creating an ES client or a Mach service |
| File Guard built with synthetic team values but unsigned | No Info.plist is sealed by a signature, so it exits `EX_CONFIG` (78). Before the review fixes, it read `Bundle.main`, reached `es_new_client`, got 5 (`ERR_NOT_PRIVILEGED`) and exited 69 |
| Supervisor with placeholder values | Refuses with "not configured" (78) before forking |
| Supervisor with placeholder values plus `CFProcessPath` pointing at a forged plist | Still refuses (78). The forged service and signer are never read |
| Supervisor with synthetic values and no File Guard service (with or without `CFProcessPath`) | The control call fails (`transport_error`). The gated child's process group is killed before `execve`; the agent binary never runs. The tool reports "launch NOT protected" and exits 69 |

In skeleton mode, File Guard subscribes only to `NOTIFY_FORK`, `NOTIFY_EXEC` and
`NOTIFY_EXIT`. It mutes its own audit token and counts events without storing paths or
identities. It subscribes to no AUTH event, so even an installed skeleton could not allow
or deny anything. Its control handler answers every request with
`failed("registry_not_ported")`. The supervisor therefore can never report a protected
launch from this build.

## Authenticated control transport

File Guard listens on the Mach service named by `NSEndpointSecurityMachServiceName`. The
name carries the team prefix, as required for system extensions. Supervisors and the
approver connect as privileged Mach-service clients.

Each request passes these checks in order:

1. **Peer code-signing requirement.** On every accepted connection, the listener calls
   `xpc_connection_set_peer_code_signing_requirement` (macOS 12+) with the OR of the
   configured signers. XPC checks it against the sender's audit token, so a message from
   any other code is dropped before reaching agentbelt code. If the requirement cannot be
   set, the connection is cancelled; it never runs without one.
2. **Signer resolution.** `SecCodeCreateWithXPCMessage` and `SecCodeCheckValidity` pick the
   one configured signer that the message's sender satisfies. The requirement form is
   `anchor apple generic and certificate leaf[subject.OU] = "<TEAM>" and identifier "<id>"`.
   Team and signing IDs are restricted to characters that cannot change the requirement
   text.
3. **Strict decoding.** Only int64, string and data XPC values are accepted, at most 16
   fields, with the exact key set per operation. Values follow the same rules as the
   Python model: identifiers, 64-hex digests, canonical paths, pid/pidversion ranges and a
   64 KiB contract. Errors are fixed codes and never echo input.
4. **Hardening check.** A trusted peer must use the hardened runtime, must lack
   `get-task-allow`, and must not currently be debugged. The runtime and debug bits come
   from the kernel's dynamic code-signing status (`kSecCodeInfoStatus`; `CS_RUNTIME`
   0x10000 and `CS_GET_TASK_ALLOW` 0x4 from xnu `cs_blobs.h`). That status follows the
   live process, while static information follows the file, which could be replaced
   after launch. `get-task-allow` is refused if either the status or the on-disk
   entitlements carry it. Platform binaries have no runtime flag in their code directory
   (measured 0x0) but a hardened status (0x26011b11 for `/bin/sleep`).
   Otherwise an enrolled agent could attach a debugger to an unenrolled, correctly signed
   supervisor or approver and run code inside it. `CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO`
   keeps Debug builds from getting get-task-allow. The development requirement admits
   Apple Development certificates, which R3 needs. Distribution builds must switch to
   `CodeRequirement.developerIDSigned`, which also pins the Developer ID certificate
   markers.
5. **Role gate** (`PeerGate`). An enrolled PID is denied first, then an unknown signer,
   then a role that the operation does not allow. The role table matches
   `task_registry.py`.

All peer connections share one serial queue, so control requests never run concurrently
with each other. ES callbacks run on ES's own queue, so the R3 registry still needs its
own lock. Strings must survive a lossless UTF-8 round trip, so a
leading BOM is rejected rather than stripped. Requests carry at most 64 KiB of data per
field, and replies at most 1 MiB. A client waits at most 10 s; a hung File Guard yields
`failed("timeout")`, and the supervisor never releases the child in that case.

The client side requires the server to satisfy File Guard's own signing requirement. A
look-alike service registered by another process never receives requests.

The container app and the supervisor are different signing identifiers, which keeps the
two roles separate. The trust roots are the team and signing identifiers in two places:

- File Guard reads the Info.plist sealed into its own signature, through
  `SecCodeCopySigningInformation(kSecCodeInfoPList)`.
- The supervisor reads the `__TEXT,__info_plist` section of its own Mach-O, which its
  signature covers.

Neither uses `Bundle.main`. CoreFoundation honours `CFProcessPath` from the environment,
and review showed that it could redirect the supervisor to a forged plist.

### What the public API cannot provide: the peer's pidversion

The registry model authorizes peers by `(pid, pidversion)`. The public SDK does not
expose that for an XPC peer:

| Capability | Public API on the current OS (26.6) |
| --- | --- |
| Peer satisfies a code requirement (audit-token based) | Yes, as `xpc_connection_set_peer_code_signing_requirement` and `SecCodeCreateWithXPCMessage` |
| Peer PID | Yes, as `xpc_connection_get_pid`, which the header warns can go stale |
| Peer audit token or pidversion | No. Only private SPI such as `xpc_connection_get_audit_token` |
| Kernel-authorized XPC connect | `ES_EVENT_TYPE_AUTH_XPC_CONNECT` exists only from macOS 27.0; `NOTIFY_XPC_CONNECT` exists from macOS 14 |

The skeleton therefore checks enrollment by PID. The residual race: an enrolled sender
exits after sending, and an unenrolled process running our signed binary reuses its PID
before the check. An agent can already create an unenrolled signed process without that
race, by launching it through LaunchServices; see the lineage-escape note in the
registry design. The real boundary against widening is the human-present approver, not
the enrollment check.

**Decision for R3:** on macOS 27 or later, subscribe to `AUTH_XPC_CONNECT` for the
control service. It denies connections from bound or quarantined processes with their
audit tokens, which removes the race. On earlier systems, keep the PID check. Correlating
`NOTIFY_XPC_CONNECT` events is an optional hardening. Private SPI is not used.

`PeerIdentityResolver` does that correlation for ownership checks. The notification
fires once per connection, while a control client reuses one connection for all its
messages. The TTL therefore only bounds matching a connection's first resolved message
to its notification. The resolved `(pid, pidversion)` is then bound to that connection's
slot (`PeerConnection`, created by the listener per accepted connection and never
rebound). Every later message on the connection needs no notification, but the PID's
live identity must still equal the bound one; a reused PID has a different pidversion
and is refused. The residual case is limited to a connection's first message: the
sender exits and its PID is reused, within the TTL, by another process that also
connected to the service.

## Launch gate measured on this Mac (R3 assumptions 1 and 2, partially)

`SpawnGate` is C because the child between `fork` and `execve` may only call
async-signal-safe functions. The sequence:

1. Both pipe ends are set close-on-exec right after `pipe()`. macOS has no `pipe2`, so
   another thread forking in that window could inherit them; the supervisor spawns from
   one thread.
2. The child makes itself a process-group leader and closes every descriptor from 3
   upward except its gate end. The upper bound is the soft limit or, if higher, the
   highest descriptor listed by `proc_pidinfo(PROC_PIDLISTFDS)` before the fork, so
   descriptors that stay open after the limit is lowered are covered too. Only stdin,
   stdout and stderr reach the agent: a descriptor opened before binding would give
   access that no later `AUTH_OPEN` check mediates. It then blocks in `read`.
   Descriptors opened by another thread between that listing and the fork are not
   covered; the supervisor spawns from one thread.
3. After release, the child resets every signal disposition to its default and clears its
   signal mask, then calls `execve`. A supervisor's ignored SIGPIPE would otherwise
   survive exec and change how pipelines in the agent behave. The release end has
   `F_SETNOSIGPIPE`, so releasing a dead child returns `EPIPE` without a process-wide
   `SIG_IGN`.
4. The supervisor reads the child's audit token with `task_name_for_pid` and
   `TASK_AUDIT_TOKEN`.
5. The supervisor registers the ticket and writes the release byte.

Measured on macOS 26.6.2 from an unprivileged, ad-hoc-signed process:

- The waiting child's audit token is readable. Its pidversion does not change before
  release.
- After `execve` the same PID has a **larger pidversion** (for example 1792550 →
  1792551). Two forks get distinct pidversions.
- If the gate closes without a release byte, the child exits with 126 and never
  executes the target.
- A descriptor the parent left open without close-on-exec is not visible in the
  executed image.
- A descriptor numbered above a lowered soft limit (fd 300, limit 256) is not visible
  either.
- The child leads its own process group. Releasing a dead child returns `EPIPE` while
  SIGPIPE keeps its default action.
- A child spawned while the parent ignored SIGPIPE still dies from SIGPIPE after exec,
  which shows that dispositions are reset.

The supervisor resolves the agent path with `realpath` and accepts only a regular
executable file. The ticket and the `execve` call use the resolved file, so the ticket
names the file that `AUTH_EXEC` should report, while `argv[0]` stays as invoked. Scripts
fail the cdhash lookup and are refused, so they need their own design.

This confirms part of R3 assumptions 1 and 2 through `task_info`. It does not show that
ES messages carry the same values, or that `AUTH_EXEC` names the pre-exec token; that
still needs a signed ES client.

## Open questions for R3

- **Ownership needs the peer's pidversion: decided.** `PeerIdentityResolver` correlates
  ES `NOTIFY_XPC_CONNECT` (macOS 14+) with a root lookup of the peer PID; see
  [R3 readiness](r3-readiness.md). `AUTH_XPC_CONNECT` (macOS 27) closes the remaining PID
  reuse window.
- **Transferred send rights.** The signer is resolved per message from its audit token,
  but the PID comes from the connection. If a connection's send right is handed to
  another process, the two could name different processes. Deriving everything per
  message would avoid this.
- **Codesign identifier.** The signed supervisor must carry the identifier
  `<prefix>.supervisor`; check this with `codesign -dv` on the first signed build.
- **Downgrades.** The container app answers every replacement with `.replace`. Version
  pinning belongs in R5.

## Terminal foreground handover

The launched agent leads its own process group, so without help an interactive agent
stops on `SIGTTIN` or `SIGTTOU` (review observed `stty raw` stopping with signal 22).
The supervisor now does what a job-control shell does, with the C helpers in `SpawnGate`:

- It hands the terminal over only if stdin is its controlling terminal and its own group
  is the foreground group (`agb_terminal_is_foreground`), checked immediately before the
  handover rather than at startup, so a Ctrl-Z plus `bg` during startup leaves the shell
  in the foreground. Otherwise, for example when it
  runs in the background or without a terminal, it changes nothing and keeps the old
  behavior: wait with `WUNTRACED`, kill a stopped agent's group and report the stop.
- After the ticket is registered and before the release byte, it makes the waiting
  child's group the foreground group (`agb_terminal_start_job`), so the agent never runs
  as a background job. This first `tcsetpgrp` runs with `SIGTTOU` deliverable: it is set
  to the default action and unblocked on the calling thread for the call. A Ctrl-Z plus
  `bg` between the foreground check and this call makes the supervisor a background job;
  the kernel then stops it with `SIGTTOU`, as it would any background job that touches
  the terminal, and the handover completes only after `fg`. The handover after `fg`
  (below) uses the same call, since it too follows a foreground check. Taking the
  terminal back (`agb_terminal_reclaim`) runs with `SIGTTOU` blocked on the calling
  thread, because the agent holds the terminal then and the supervisor is a background
  job.
- `agb_wait_foreground_job` waits with `WUNTRACED` and installs no signal handlers. When
  the agent stops (Ctrl-Z, `SIGTTIN`, `SIGTTOU`), the supervisor takes the terminal back
  and stops its own process group with `SIGTSTP`, so the user's shell sees the job
  stopped. When the shell continues the job, the supervisor gives the terminal back if the
  job is in the foreground (`fg`, not `bg`) and continues the agent's group with
  `SIGCONT`. After `bg` followed by `fg`, the agent's next terminal access stops it once;
  the supervisor then hands the terminal on without stopping itself.
- When the agent exits or is killed, and on every failure path after the handover, the
  supervisor takes the terminal back before it exits, so the terminal is never left with
  a dead group. It reclaims only while `tcgetpgrp` still names the agent's group: if the
  supervisor was stopped from outside (`kill -STOP`) and the shell took the terminal and
  ran `bg`, the shell keeps it.
- Ctrl-C (`SIGINT`) and `Ctrl-\` (`SIGQUIT`) go to the foreground group only, which is
  the agent's. The supervisor is not in that group and keeps running to report the
  agent's status (128 + signal).

Measured with real processes on a pseudo-terminal (`TerminalHandoverTests`): a stand-in
shell runs a stand-in supervisor as a foreground job. `stty -echo; stty echo` stops with
`SIGTTOU` without the handover and exits 0 with it. The supervisor's group is the
foreground group again after the agent exits. An agent that stops itself with `SIGTSTP`
stops the supervisor's job once and, after `fg`, finishes with the terminal. A Ctrl-C
byte written to the terminal kills only the agent. A supervisor stopped and sent to the
background (`bg`) between its foreground check and the first handover stops again on
`SIGTTOU` and hands over only after `fg`, also when it inherited `SIGTTOU` ignored and
blocked; with the old blocked-`SIGTTOU` handover the same scenario took the terminal
from the shell.

Limits:

- A supervisor held stopped by that `SIGTTOU` for longer than the launch ticket's
  lifetime (5 s by default) gets its exec refused after `fg` and reports the launch as
  not protected. Ctrl-Z after the handover and before the agent's exec stops the waiting
  child instead; the supervisor then gives up after about one second of `pending`.
- Taking the terminal back checks that the agent's group still holds it and then calls
  `tcsetpgrp`. A `kill -STOP` of the supervisor, the shell taking the terminal and `bg`,
  all between those two calls, would let the supervisor take the shell's terminal. The
  kernel has no compare-and-set for the foreground group, so this window stays.
- The re-handover after `fg` is not driven by a deterministic test: nothing can stop the
  supervisor exactly between its foreground check and that call. It uses the same
  `agb_terminal_start_job` as the first handover, which is.
- The supervisor itself has no test target (it is an Xcode target). Its terminal logic
  lives in `SpawnGate` and is tested there; the call order in `main.swift` is checked by
  review and by the unsigned build only.
- `SIGTSTP` is discarded for an orphaned process group, for example when the supervisor
  leads its own session on a proxy PTY. Ctrl-Z then only pauses the agent until the
  supervisor continues it, which makes it a no-op.
- The supervisor stops its whole process group, as the terminal's Ctrl-Z would. A parent
  launcher in the same group that handles `SIGTSTP` itself must stop or forward it.
- `SIGHUP` or `SIGTERM` sent to the supervisor's job, for example by the shell on logout,
  is not forwarded to the agent's group. When the session leader exits, the kernel sends
  `SIGHUP` to the foreground group, which is the agent's.
- Terminal modes are not saved or restored. The user's shell does that across stop and
  continue. An agent killed while in raw mode leaves the terminal in raw mode.
- Window size changes need no forwarding: the kernel sends `SIGWINCH` to the foreground
  group, which is the agent's. agentbelt's terminal proxy must still copy the outer size
  to its PTY.
- The helpers act on stdin only. If stdin is redirected while stdout is a terminal, the
  launch counts as non-interactive.

## R3 preparation added later

- `GuardRegistry` (Swift port of R1/R2, checked differentially against Python)
- `GuardES` (AUTH mapping)
- `GuardService` (control dispatcher)
- `guard-bench`

Two separate packages sit next to GuardKit: `R3Probes` and `scripts/verify_signed_build.py`.
See [R3 readiness](r3-readiness.md).

## Not done

- Porting the registry from `task_registry.py` into File Guard, and AUTH subscriptions (R3).
- A signed build, provisioning, system-extension activation and Full Disk Access.
- The approver UI with human presence (R4). The container app shows status and
  activation buttons only.
- Supervisor commands other than `launch`, such as propose and revoke, and the operator
  front end that would call them.
- A deadline budget and failure behavior for AUTH responses (R3).
