# R3 readiness — what exists before Endpoint Security is approved

Status: preparation only. Apple has not confirmed the ES capability, and no ES client
has been created. Everything below was built and tested without one: the Swift registry,
the AUTH mapping, latency measurements, the boundary probes and the signing checker. None
of it shows that the OS enforces anything. R3 is the step that produces that evidence.

## What R3 now has

| Piece | Where | Evidence |
| --- | --- | --- |
| Swift port of R1 policy and R2 registry | `native/guard/GuardKit/Sources/GuardRegistry` | Differential replay against `task_policy.py`/`task_registry.py`: 120 scenarios (about 20,000 steps) in every test run, plus one-off runs of 2,000 scenarios (about 330,000 steps) on two seeds. All matched on results, error messages and the canonical JSON of the full durable state. The contract loader matched Python on a 450-document corpus, with one documented exception. 14 deliberate defects in the port were each caught by the replay |
| Schema 2 contracts (`external` rules) | `task_policy.py`, `Policy.swift` | Python tests plus differential replay (see below) |
| ES AUTH mapping and verdict | `GuardKit/Sources/GuardES` | Synthetic `es_message_t` tests (12) through the real registry |
| Control dispatcher (XPC request → registry) | `GuardKit/Sources/GuardService` | Unit tests (3) |
| Decision latency | `swift run -c release guard-bench` | Table below |
| Boundary probes for the acceptance tests | `native/guard/R3Probes` | 56 probes, baseline run verified, 38 tests; enforced verification requires guard records inside per-probe marker windows |
| Signed-build checker | `native/guard/scripts/verify_signed_build.py` | 94 tests; requirement-based identity, signature blobs read directly, profile certificate membership; rejects the current unsigned build |

## Contract schema 2: `external` rules

Contract v1 allows only paths inside the workspace, but a real process must also:

- load dyld and system libraries;
- execute its runtime;
- write its isolated home.

With `AUTH_OPEN` enforced and a v1 contract, an agent could not even start. Schema 2
therefore adds an `external` list. It holds path rules outside the workspace, approved
with the rest of the contract digest.

- `external` exists only in schema 2 and is required there; v1 documents are unchanged,
  so their digests are unchanged too.
- A rule may not be `/`. Sensitive names and explicit denials still win over it.
- A child task's `external` rules must be covered by the parent's `allow` or `external`.
- Grants remain in-workspace only.
- Schema 3 adds `exceptions`: approver-visible, read/write-only lifts of the
  sensitive-name ban, each covered by `allow` or `external`. They exist for the trust
  store, the agent's login state inside its isolated home, and the workspace `.git`. They
  were added after the per-agent baselines showed that OpenCode, Kimi and Zcode could not
  run otherwise (see task-policy.md). Device writes are exact external rules for
  `/dev/null`, `/dev/zero`, `/dev/tty` and the session's own tty only.
- Under schema 2, an exec outside every lineage workspace needs an `execute` rule. The
  schema 1 exception `exec_outside_contract` does not apply to v2 contracts.
- A child's schema version may not be lower than its parent's. Otherwise a v1 child would
  regain the runtime-exec exception its v2 parent lacks.
- No `allow` or `external` rule may cover `/System/Volumes/Data` or sit inside it, and no
  workspace may lie inside it. That firmlink is a second spelling of every user file, so
  rules name `/System/Library` or `/System/Volumes/Preboot/Cryptexes` instead of `/System`.

Which paths go into `external` is a supervisor profile decision, not code. The natural
source is the read-root list agentbelt already derives for its Seatbelt profiles, reviewed
per agent: `/usr`, `/System`, the agent's runtime tree, and its isolated home for writes.
`r3-probes contract` emits the probe fixture's schema-2 contract. Its external rules are
exact for the probe binary and narrow for the runtime (`/usr/lib`, `/System/Library`, the
dyld shared-cache cryptex). The command refuses any rule that would cover the fixture
root, `outside/` or `projectB/`.

## AUTH event mapping

| ES event | Registry call | Operations |
| --- | --- | --- |
| `AUTH_EXEC` | `on_exec(process, parent, target, image, script)`; image = target path + cdhash; script = `exec.script` (message version 2+) | ticket launch, or `execute` on the image and on the #! script |
| `AUTH_OPEN` | file | `FREAD` → read; `FWRITE` or `O_TRUNC` → write; neither → read |
| `AUTH_CREATE` | file (existing file, or directory + name) | write |
| `AUTH_UNLINK`, `AUTH_TRUNCATE`, `AUTH_SETEXTATTR`, `AUTH_DELETEEXTATTR`, `AUTH_SETMODE`, `AUTH_SETFLAGS`, `AUTH_SETOWNER`, `AUTH_SETACL`, `AUTH_UTIMES` | file | write |
| `AUTH_RENAME` | source and destination, both as subtrees | write, write |
| `AUTH_LINK` | source (subtree) and new name | write, write (a new name for any file is an alias) |
| `AUTH_CLONE` | source (subtree), target | read, write |
| `AUTH_COPYFILE` | source, target | read, write |
| `AUTH_SETATTRLIST` | file | write |
| `AUTH_GETEXTATTR`, `AUTH_LISTEXTATTR`, `AUTH_FSGETPATH`, `AUTH_SEARCHFS`, `AUTH_CHDIR`, `AUTH_CHROOT` | file | read |
| `AUTH_UIPC_BIND` | directory + name | write |
| `AUTH_UIPC_CONNECT` | socket file | write (the server acts on the agent's behalf) |
| `AUTH_GET_TASK`, `AUTH_GET_TASK_READ`, `AUTH_SIGNAL` (actor = instigator from message version 9), `AUTH_PROC_SUSPEND_RESUME` | `authorize_process(process, parent, target, operation)` | allowed only on itself or a process bound to the same task (`same_task`); anything else `process_outside_task` |
| `AUTH_EXCHANGEDATA` | both files | write, write |
| `AUTH_READDIR`, `AUTH_READLINK`, `AUTH_GETATTRLIST` | file | read |
| `AUTH_MMAP` | file | read; + execute with `PROT_EXEC`; + write with `PROT_WRITE` and `MAP_SHARED` |

**Subtree operations.** A rename, clone or link of a directory carries everything below it
to a new name. A deny rule at `/w/a/docs/private` would otherwise stop applying after
`rename /w/a/docs /w/a/docs2`. These operations are therefore also denied
(`explicit_deny_below`) when any deny rule of the task sits at or below the path. Review
found this bypass in both implementations. Both were fixed, and the differential
generator now exercises it.

How the mapping handles edge cases:

- An event that touches several paths is allowed only if every touch is allowed. The
  first denial decides.
- A path that cannot be used becomes an invalid path, which denies enrolled processes and
  passes unrelated ones. This covers truncated paths, non-UTF-8 bytes, and a file name
  containing `/`.
- A subscribed event type without a mapping takes the same fail-closed path.
- An event without a usable process identity (pid 0) cannot come from an enrolled process
  and passes. A wrapped, negative pidversion stays a valid identity, so an enrolled
  process never drops out of enforcement after 2^31 processes.
- The parent identity comes from `parent_audit_token` (message version 4+). The SDK
  describes this as the current parent; only `original_ppid`, a bare PID, survives
  reparenting. After reparenting, the missed-fork check therefore sees launchd.
- The registry now rejects an exec whose target PID differs from the process PID, because
  the kernel never produces one. Both implementations enforce this.

**Responses.** `AUTH_OPEN` answers with `UINT32_MAX` or `0` authorized flags; every other
event with allow or deny. `cache` is always false.

**One clock, one lock.** File Guard calls the registry only through `ClockedRegistry`. It
reads the monotonic clock inside the lock, so concurrent XPC and ES threads cannot hand the
registry an out-of-order time. Out-of-order times would be refused as `clock_regression`.

### Every SDK AUTH event, classified

| Handling | Events |
| --- | --- |
| Mapped (table above) | EXEC, OPEN, CREATE, UNLINK, TRUNCATE, RENAME, LINK, CLONE, COPYFILE, EXCHANGEDATA, SETEXTATTR, DELETEEXTATTR, SETMODE, SETFLAGS, SETOWNER, SETACL, UTIMES, SETATTRLIST, READDIR, READLINK, GETATTRLIST, GETEXTATTR, LISTEXTATTR, FSGETPATH, SEARCHFS, CHDIR, CHROOT, MMAP, UIPC_BIND, UIPC_CONNECT, GET_TASK, GET_TASK_READ, SIGNAL, PROC_SUSPEND_RESUME |
| Not mapped: information only | PROC_CHECK (process listing and info). Denying it would break `ps` and `top`; it reveals metadata but grants no control |
| Delegation outside lineage | FILE_PROVIDER_MATERIALIZE/UPDATE, XPC_CONNECT (macOS 27), BOOTSTRAP_CHECK_IN (macOS 27) |
| Residual, not closable by path mapping | MPROTECT: it carries addresses, not files, so a later `mprotect` can add `PROT_EXEC` to a mapping judged at `AUTH_MMAP` time. FCNTL |
| Host or kernel, not agent file access | KEXTLOAD, MOUNT, REMOUNT, SETTIME, IOKIT_OPEN |

**Processes outside the task.** A task port, even the read-only one, lets its holder read
or rewrite another process. Otherwise an enrolled agent could reach into an unconfined
process through a debugger. An enrolled process may therefore take a task port of,
signal, or suspend only itself and processes bound to its own task. Everything else is
denied: unrelated apps, the supervisor, other tasks, and targets the kernel does not
name. Unrelated callers pass. Both implementations enforce this, and the differential
generator exercises it.

## Why caching and muting cannot reduce the load

| Option | Problem |
| --- | --- |
| ES result cache | Keyed by executable and file, not by task. An allow given to an unrelated `/bin/sh` would reach an agent's `/bin/sh` |
| Inverted process muting (only listed processes) | A child can make its first AUTH call before its fork notification unmutes it. That call is then never seen |
| Muting executable paths | An agent can execute any muted binary and escape |
| `es_new_descendants_client` | Would solve lineage at the kernel level. It needs macOS 27; the current runtime is 26.6 |

File Guard therefore answers every AUTH event system-wide, uncached, and mutes only
itself. The speed of the unrelated-process path decides the cost for the whole machine.

## Decision latency (initial measurement, this Mac)

`swift run -c release guard-bench`: macOS 26.6.2, 12 cores. Nanoseconds per call, single
thread unless stated. The ES rows use the production entry point
`AuthDecider.decide(_:clocked:)`, lock and clock read included.

| Case | p50 | p99 |
| --- | --- | --- |
| Unrelated process, registry only | 125 | 166 |
| ES map + decide `AUTH_OPEN`, unrelated, through `ClockedRegistry` (paid by every event on the machine) | 250 | 291 |
| Enrolled file, allowed, 4 rules | 1,541 | 1,875 |
| Enrolled file, denied outside, 4 rules | 1,500 | 1,833 |
| Enrolled file, 128 rules, last rule matches | 7,875 | 8,875 |
| ES map + decide `AUTH_OPEN`, enrolled, through `ClockedRegistry` | 1,791 | 2,125 |
| Fork + exec + exit of an enrolled child | 2,416 | 3,000 |
| Throughput: 4 threads of unrelated events through `ClockedRegistry`, real clock | 299 ns wall per call | — |

Samples are quantized to about 42 ns (`mach_absolute_time` on Apple silicon). Review
found that tombstone eviction was O(n) under the lock: with a full tombstone set, fork plus
exit took about 36 µs. Eviction is now O(1).

The first profile measured about 29.7 µs per enrolled decision. Most of it came from the
sensitive-name check, which ran twice per decision and allocated its patterns each time,
and from an O(n) record buffer. After optimization the differential replay still matches
exactly.

These numbers cover only in-process work. ES delivery, response IPC and deadline
behavior are R3 measurements. No deadline budget is claimed yet, and no result from
the deadline-miss-mode API (macOS 27) is claimed.

## Execution checklist once approval arrives

1. **Confirm the approval.** Check the approved capability and its distribution channel
   with the user. Register an App ID for each target and build with profiles.
2. **Check the signed build.** Run `verify_signed_build.py --expect-team <TEAM>
   --distribution development`, and fix every FAIL before installing anything.
3. **Build the AUTH path in File Guard.** Replace the skeleton handler: subscribe to
   `ESMapper.authEvents`, answer with `AuthDecider`, and feed NOTIFY lineage events into
   the registry. Make muting itself fatal for an AUTH client. Wire control requests
   through `ControlDispatcher`, with a peer resolver and the macOS 27 `AUTH_XPC_CONNECT`
   decision (see native-guard.md).
4. **Activate on a test Mac.** Activate through the container app with explicit consent
   and grant Full Disk Access. Do not disable SIP.
5. **Measure the R3 assumptions** in task-registry.md: pidversion on exec in ES messages,
   `AUTH_EXEC` ordering, fork-before-first-AUTH, original parent, unrelated-process cost,
   delegation paths, and path case/normalization.
6. **Run the probes enforced.** Run R3Probes under the contract from `r3-probes contract`,
   baseline first, then enforced. Enforced `verify` requires File Guard's action records
   (`--guard-records`). It accepts a denial only as EPERM at the probe's own step, with a
   matching guard denial for the fixture's unique task ID. That denial must also fall
   between the probe's marker read and the next probe's marker, ordered by record
   `sequence`. So a Seatbelt or hand-written EPERM does not count, and neither does a
   startup read or a record from an earlier run. File Guard must export every action
   record: the registry keeps only the last 1,024, and a dropped marker fails its probe.
   The probe binary reads a few files outside the workspace at startup (see the R3Probes
   README). The contract must allow them exactly, or the run must tolerate those denials. Record every mismatch and residual (inherited descriptor, SCM_RIGHTS), and
   the roadmap rows that `verify` lists as uncovered.
7. **Test failure modes.** Stop File Guard, kill it, overload it and restart it. Record
   what happens to AUTH events while it is down, and verify the restart quarantine.
   Measure the write-ahead save inside `AUTH_EXEC` (full snapshot or journal append)
   against the deadline, and kill File Guard between `register_launch` and the exec.

## Still open

- **Peer pidversion for ownership checks: decided.** `PeerIdentityResolver` (GuardService)
  takes the connecting client's full identity from ES `NOTIFY_XPC_CONNECT` (macOS 14+)
  for our service name. It accepts a control message only when that identity equals the
  PID's current identity from a root lookup, and waits briefly because the notification
  may arrive after the message. The TTL applies only to a connection's first message;
  after that the identity is bound to the connection (`PeerConnection`), and each later
  message only has to match the live lookup, so long-lived connections keep working and
  a reused PID (new pidversion) is refused. The residual case is the sender exiting and
  its PID being reused, within the TTL, by another process that also connected to the
  service. `AUTH_XPC_CONNECT` (macOS 27) removes it.
- **Transferred XPC send rights.** The signer is resolved per message but the PID per
  connection.
- **Unsaved bindings after a restart: decided (write-ahead).** The registry saves through
  its `persist` hook before `register_launch` returns and before an `AUTH_EXEC` that binds
  a process is answered; a failed save denies (`state_not_saved`). Tickets are part of the
  durable document (version 2). Still open: the cost of the save inside the ES deadline
  (snapshot or journal), and fork bindings, which `NOTIFY_FORK` cannot wait for; see
  task-registry.md "Restart".
- **Terminal foreground handover: implemented.** The supervisor hands the terminal over
  like a shell job and handles Ctrl-Z, `fg` and `bg`; see native-guard.md. Orphaned
  process groups and the terminal-proxy PTY remain to check.
- **Contents of the `external` baseline per agent: decided.** `task_profiles.py` derives
  them from the same roots agentbelt grants under Seatbelt, with drift tests. Exceptions
  and device rules follow the schema 3 policy above.
- **Case-insensitive APFS: partly decided.** Deny rules and the subtree check fold A-Z
  (`PathRule.denies`), so `.git/HOOKS` meets the `.git/hooks` denial. Allow and exception
  rules stay exact, which can only deny more. Still to measure: which case ES reports
  (on-disk or as requested) and non-ASCII case variants. Seatbelt matched case variants
  of both existing and new names on macOS 26.
- **Package managers' git checkouts under ES: decided.** The ES baseline lifts `.git` in the
  same three trees Seatbelt opens (`<workspace>/.build/checkouts`, `<home>/.pub-cache/git`,
  `<home>/.cargo/git`) with name-scoped schema-3 exceptions (`names: [".git"]`, read+write;
  see task-policy.md). Every other sensitive name below them stays denied, and denials
  still win. A directory moved out of a cache carries its `.git` along without a
  sensitive-named path in the request, so neither layer blocks the move; `git_audit.py`
  reports such repositories after the session, and the supervisor runs it regardless of
  the enforcement layer. Accepted, as under Seatbelt: host SwiftPM, pub or cargo running
  git inside a cache obey hooks and config the agent wrote there. Still to measure: the
  cache roots sit in agent-writable trees, so a cache root replaced with a link must not
  lift the link's target. That holds only if ES reports resolved paths (Seatbelt already
  matches resolved paths); see the path-spelling item below.
- **ptrace.** ES has no AUTH event for it, only `NOTIFY_TRACE`. Whether a bound agent can
  attach to non-hardened processes of the same user and stop or kill them without
  `AUTH_SIGNAL` needs a measurement. What today's Seatbelt profile allows here has not
  been checked either.
- **Reading another process's arguments and environment: measured, not blockable by Seatbelt.**
  In an installed `run_confined` session (2026-09-25) a confined process read a synthetic
  host process's arguments and environment through `sysctl(KERN_PROCARGS2)`, while `ps`,
  signals and `ptrace` attach were denied. None of the SBPL rules tried stopped the sysctl:
  `sysctl-read` denials (all, `kern.procargs2`, prefix `kern.proc`), `process-info*` with
  `(target others)`, or a global `process-info*` deny re-allowed for `self`/`same-sandbox`.
  Exposure: the arguments and environment of the user's other processes, including another
  confined session's scoped GitHub token. Options: `AUTH_PROC_CHECK` under ES (which
  flavours it reports needs the R3 measurement), and handing agent tokens over something
  other than the environment.
- **Which path spelling ES reports** for firmlinked (`/System/Volumes/Data/...`) and
  hardlinked files, and for paths through a symlinked directory (a package cache root
  the agent replaced with a link), which name-scoped exceptions depend on.
- **Restart between `register_launch` and exec: decided.** The ticket is saved before
  `register_launch` returns. After a same-boot restart it is `revoked`, so the waiting
  child's exec is denied (`launch_ticket_closed`) instead of running `not_enrolled`.
- **Task ports: decided** (same-task only; see above).
