# Task registry and launch binding — R2 model

Status: a pure Python reference model with synthetic event tests. `task_registry.py`
is not connected to a launcher, a local transport, the Zcode Safe app or an Endpoint
Security client. Passing its tests establishes semantics, not OS enforcement. Apple ES
approval is unconfirmed, so no event in the tests came from the kernel.

R1 ([task policy](task-policy.md)) answers "given this contract, binding and access,
allow or deny?". R2 decides **who may create those inputs and when a process gets
them**: the task lifecycle, launch binding before the first instruction, process
lineage, restart behavior, grants and the action record.

## Run the checks

```sh
/usr/bin/python3 -I -m unittest discover -s tests -p 'test_task_*.py' -v
```

The registry tests use fabricated process identities, code digests, signers and clock
values. Store tests write only inside a private temporary directory. No agent is
launched and no credential, network or real home file is used.

## Components and trust boundary

```text
operator ──(approval UI, human presence)──┐
                                          ▼
agentbelt supervisor ──propose / launch──► task registry ◄──fork/exec/exit/file── ES client
   (signed native binary)                 (root service or           (kernel-reported
                                           system extension)          audit tokens)
                                          │
                                          └─► R1 evaluate() ─► allow / deny + record
```

| Role | Who it is | What it may do |
| --- | --- | --- |
| Registry | The authority. Planned to live in the ES system extension or a root service it trusts | Owns tasks, bindings, quarantine, grants, requests and records |
| Event source | ES client inside the same authority | Reports fork, exec (AUTH), exit and file access (AUTH) with kernel identities |
| Supervisor | Signed native helper, Team ID + signing ID in `RegistryConfig.supervisors` | Propose tasks, child tasks and revisions it owns; open launch tickets for its own fork children; revoke |
| Approver | Separate signed UI binary in `RegistryConfig.approvers` | Read pending proposals and requests; confirm or reject; approve or reject requests; revoke |
| Enrolled process | Any process bound to a task, or quarantined | Nothing on the control plane, whatever binary it runs |

Transport authentication is an adapter this model assumes: it turns an incoming
message into a `Peer` from the connection's audit token and a verified code signature.
Nothing in a message body (task ID, PID, signer, environment) becomes a `Peer`.

Findings that constrain the native design:

- **The current Python supervisor cannot be a registry peer.** `agentbelt.py` runs as
  `/usr/bin/python3`, whose code identity is Apple's interpreter. Any script can present
  it. The authorized supervisor must be a dedicated native binary signed with our Team
  ID, using the hardened runtime without `get-task-allow`, so another process running as
  the same user cannot inject code into it. Python agentbelt can remain an operator
  front end, but it does not hold registry authority.
- **A valid signature is not sufficient.** An agent can execute the signed supervisor or
  approver binary from its workspace. The registry rejects any peer whose process is
  bound or quarantined, so the lineage check outranks the signature.
- **Supervisors cannot widen authority by themselves.** A task becomes active only when an
  approver confirms an exact SHA-256 digest. The digest covers the contract, the parent
  task and the proposing supervisor instance, because ownership decides who may launch
  and revise. This prevents the failure that sank the rejected install transaction, where
  the approval was not bound to what ran. Duplicate pending digests are refused.
- **The approver reads proposals from the registry.** `pending_proposals()` returns the
  canonical contract, parent and proposer behind each digest, so the UI does not have to
  trust content relayed by a supervisor. A single signer cannot hold both roles.
- **The approver must require human presence.** An agent can escape lineage through
  LaunchServices, for example with `open -a`, and then drive a UI with Apple Events or
  accessibility. The approver therefore accepts no approval through URL, argv, AppleEvents or
  synthetic input. R4 must prove this; the model only enforces the role.
- **Supervisor instances are separated for widening only.** Only the owner may revise a
  task, launch into it or propose a child task under it. Proposals are capped per
  supervisor (16), and so are pending tickets (8). Any supervisor or approver may revoke
  any task, which only narrows authority.

## Launch binding before the first instruction

The model rejects "NSWorkspace launch, then register the PID". That leaves a gap in
which the process runs unbound, and a LaunchServices child is parented by launchd, not
by the supervisor.

`posix_spawn` with `POSIX_SPAWN_START_SUSPENDED` does not close the gap either. The exec
is authorized inside the spawn call, before the supervisor learns the child's identity.
So a ticket could only name the supervisor, and review showed that a late exec from an
earlier child would then take the next ticket and swap tasks.

The model therefore ties each ticket to one exact child:

1. The supervisor authenticates, so the registry knows this supervisor instance, and its
   task is active and owned by it.
2. The supervisor calls `fork()`. The child keeps running the supervisor's own code and
   waits on a pipe. The ES `NOTIFY_FORK` records it as a fork child of that instance.
3. The supervisor obtains the child's audit token and calls
   `register_launch(task, image, child)`. The image is the executable path plus its code
   identity; the native adapter uses the cdhash. The child must be an unexec'd fork child
   of the caller, with no ticket yet. Tickets expire after `ticket_ttl_ns` (5 s by default).
4. The supervisor releases the child, and the child calls `execve` directly on the agent
   executable, without LaunchServices.
5. The ES `AUTH_EXEC` names the pre-exec process, its parent and the post-exec identity.
   The registry answers only after its checks:
   - The ticket is still pending, the clock is sane, the parent is the ticket's spawner
     and the image matches.
   - The task is still active and inside its validity window.
   - If all checks pass, both identities are bound before the answer. The new image
     cannot run before then, so there is no unbound interval.
   - If any check fails, the exec is denied and the ticket closes, including on retry:
     `launch_ticket_mismatch`, `launch_ticket_expired`, `launch_ticket_closed`,
     `task_not_active` or `clock_regression`.
   - A ticketed child never runs its new image unbound.
6. Revising or revoking the task, or the supervisor's exit, closes pending tickets.
7. `ticket_status(child)` reports `pending`, `bound`, `denied`, `expired`, `revoked` or
   `none`. For anything but `bound`, the supervisor kills the child and reports the
   launch as unprotected.

A supervisor child that execs without a ticket, such as a helper, is `not_enrolled`. The
supervisor must not release a launch child before `register_launch` succeeds.
Environment variables, argv and MCP metadata are not inputs to any registry call, and the
event API has no task field.

## Process identity and lineage

`ProcessIdentity(pid, generation)` is expected to carry the audit-token PID and
pidversion. Every bound or quarantined identity belongs to an **exec chain**: one live
process and its earlier images. The table shows how events map to state:

| Event | Effect |
| --- | --- |
| `on_fork(parent, child)` (NOTIFY) | Child starts a new chain in the parent's task, or in quarantine. A late or duplicate fork never reassigns an identity already bound or quarantined |
| `on_exec` by a bound process (AUTH) | An executable inside the workspace of the task or any ancestor task: R1 `execute` rule decides. Outside all of them: a schema 1 contract allows it as `exec_outside_contract`; a schema 2 contract needs an `execute` rule in `allow` or `external`. If allowed, the new image joins the chain. An exec whose target PID differs from the process PID is `invalid` |
| Script exec (a bound process executes an interpreter with a #! script) | Both the interpreter image and the script path must pass the execute decision; the first denial is reported |
| Subtree file operation (`authorize_file(..., subtree=True)`: rename, clone or link of a possible directory) | Also denied as `explicit_deny_below` when any deny rule sits at or below the path, so a moved directory cannot leave a deny rule behind |
| `on_exit(process)` (NOTIFY) | Only an exit of a tracked identity releases its chain. Released identities are kept as per-boot tombstones (at most 65,536; evictions counted in `dropped_retired`). An exit for any other identity that shares the PID, such as a stale event, releases nothing |
| Exit, PID-matched narrowing | Pending tickets spawned by that PID are revoked, its proposals are dropped, and tasks it owned become `interrupted`. A stale exit can only reduce authority |
| Parent exits | No event is needed. Binding follows lineage, not the current PPID |
| PID reuse | A new pidversion is a new identity and is `not_enrolled` |
| Unknown process whose reported parent is bound, quarantined or tombstoned | Quarantined, `unattributed_descendant`. A lost fork notification never assigns a task, even after the parent has exited |
| Unknown process with an unrelated or malformed parent | `not_enrolled`: the ES adapter allows it untouched |

The in-workspace `execute` rule is not a code-execution boundary. A runtime outside
the contract, such as `/bin/sh` or `python3`, can interpret any readable workspace file.
Controlling that needs a runtime allowlist, which contract v2 would have to add.

`not_enrolled` is a routing answer, not a policy verdict. A global ES client uses it to
avoid blocking host applications, and unrelated processes with malformed paths also
pass through. The same malformed input fails closed (`invalid_input`) for an enrolled
process. Only an invalid process identity or clock returns `invalid`.

## Task lifecycle

| State | Entered by | Meaning for bound processes |
| --- | --- | --- |
| proposed | `propose` (supervisor) | Not a task yet. Held in memory only; dropped when the proposer exits |
| `active` | `confirm` (approver) of the exact digest | R1 evaluation with the current revision |
| `revoked` | `revoke` (supervisor or approver); parent revoked; parent revision no longer covers the child | Denied `revoked`. Terminal; interruption never downgrades it |
| `interrupted` | Owning supervisor exits; parent interrupted; registry restart | Denied `interrupted`. Terminal: a new task is required |

- **New tasks** start at revision 1.
- **Revisions**: the owning supervisor instance proposes the next revision. It must be
  exactly `current + 1` and must be confirmed. It then applies to every bound process at
  once: bindings follow the task, so no binding keeps an old revision.
- **Effects of a confirmed revision**:
  - The grants, pending requests and launch tickets of the task and all its descendants
    are dropped, because descendant grants were checked against the old parent.
  - Active child tasks that are no longer `is_attenuation(parent, child)` are revoked
    transitively.
- **Child tasks** must be attenuations of an active parent that the proposer owns. This
  is checked when the child is proposed and again when it is confirmed.
- **Pruning**: when the task table (1024) is full, terminal tasks with no bindings, child
  tasks or tickets are pruned. Large contracts can still push a snapshot past the 4 MiB
  store limit. Saving then fails closed: with write-ahead (see Restart), `register_launch`
  raises and every exec that would bind a process, in every task, is denied
  `state_not_saved`. Tombstones (up to 65,536) grow with the forks and exits of bound
  processes, so an agent can push the snapshot toward the limit itself. That is an
  availability problem for all tasks on the host, never a widening.

## Clock

The registry takes a trusted monotonic `now_ns` from its own adapter, in the same epoch
as the contract lifetimes. A regressing clock returns `clock_regression` for enrolled
processes, rejects control calls and denies a launch exec. Unrelated processes are not
affected.

## Requests and grants

A denied access becomes a pending `AccessRequest` only when all of these hold:

- R1 denied it as `outside_allow_scope`.
- The path lies inside the task workspace; contract v1 cannot express grants outside it.
- There is room in the per-task queue (default 32). Duplicate requests are collapsed, and
  overflow is counted in `dropped_requests`.

Sensitive names and explicit denials never produce a request. The request's path and
operations are those of the access the kernel reported, not a free-form claim. The agent
still chooses what it attempts, so the approval UI must present every request as
agent-initiated.

An approver approves one request with an expiry no later than the contract's expiry. The
grant is an `exact` rule for the same path and operations, tied to the current revision.
For a child task, every ancestor contract must already allow those operations on that
path. The registry evaluates the grant by re-running R1 with the live grants appended to
`allow`. The sensitive-name and explicit-deny checks run first, so a grant cannot
override them. Grants never apply to another task. They disappear on expiry, on a
revision of the task or any ancestor, on revocation and on interruption.

The retry is cooperative. The tool whose access was denied tries again after approval.
Nothing waits for a human inside an ES callback. Retries by ordinary GUI I/O are not
assumed.

## Restart

`to_document()` (document version 2) persists these:

- tasks
- bindings and quarantine, each with its exec chain
- launch tickets, with their state
- tombstones
- records and loss counters

Proposals, grants and requests are intentionally not persisted. `restore()` is fail
closed:

| Case | Result |
| --- | --- |
| Same boot session | Non-revoked tasks become `interrupted`. Every saved bound identity is quarantined (`tracking_lost`), because it may have forked or exec'd while nothing was watching. Unknown children of quarantined processes are quarantined on sight. Every ticket except a `bound` one is kept as `revoked`: its child is not running a bound image (a denied exec leaves the child alive before exec), so any exec by it is denied (`launch_ticket_closed`), including a retry, and `ticket_status` tells the supervisor to kill it. `bound` tickets are dropped, so `ticket_status` answers `none`, never `bound`, for a launch the registry lost track of. A clock earlier than the saved `last_now_ns` refuses the load |
| New boot session | Non-revoked tasks become `interrupted`. Old identities, tickets and tombstones are discarded because their PIDs now name unrelated processes |

Version 1 documents are refused (`unsupported registry document`); nothing deployed
wrote them.

**Write-ahead.** A restart restores the last saved document, so state that lets a
process run bound must be saved before the call that creates it answers. The registry
takes a `persist` hook (Swift: `persist:`), called with `to_document()` at two points:

| Point | Saved before | If the save fails |
| --- | --- | --- |
| `register_launch` opens a ticket | the call returns | The ticket becomes `revoked` and the call raises `registry state could not be saved`; the supervisor kills the child |
| `AUTH_EXEC` binds a process (a ticketed launch, or an allowed exec of a bound process) | the exec is answered | The new bindings are put back exactly as they were and the exec is denied `state_not_saved`. A launch ticket becomes `denied` (it is `denied` in the saved document too, until the binding is saved); a bound process keeps running its current image |

Without the first point, a restart between `register_launch` and the exec left the
waiting child unticketed, and its exec ran `not_enrolled` (its parent is the supervisor,
which is not enrolled). Without the second, a restart after an agent's exec lost the new
image's binding, with the same result. Any exception from the hook counts as unsaved;
in Python, an exception that is not an `Exception` (such as `KeyboardInterrupt`) still
rolls the new state back before it propagates.

Rules for the store:

- **One writer.** With a hook, every save goes through it. The host's periodic save is
  `checkpoint()`, which calls the hook under the same lock. A second writer could
  snapshot, lose the race, and replace a newer write-ahead document with an older one;
  a crash then restores a document without the latest binding. `save_registry` /
  `saveRegistry` therefore refuse a registry that has a hook.
- **No calls back.** The hook runs inside the call that triggered it. The Swift port holds
  its lock then (and `ClockedRegistry`'s, when called through it), so calling back into
  the registry deadlocks. The hook stores the document it was handed, with
  `save_document` / `saveDocument`, which also enforce the 4 MiB limit.
- **Failure causes.** The registry reports only that a save failed (`state_not_saved`, or
  the raised error). The hook should log why. A save that fails after the new file was
  already moved into place (the directory sync fails) is reported as unsaved: the store
  then holds a binding that memory rolled back, which a restart only quarantines.

A full snapshot per exec is the simplest store that meets this rule. It costs deadline
budget in the ES callback: a snapshot can reach 4 MiB, and each save syncs a file and
its directory. An append-only journal of bindings and tickets would meet the same rule
more cheaply. The R3 measurement decides which one the native store uses.

**Residual gaps, not solved by the model:**

- **Unsaved fork bindings and quarantine.** `NOTIFY_FORK` cannot wait for a save. A child
  bound by fork after the last save is unknown after a restart. It is quarantined on
  sight while its parent is still known, but its own child reports an unknown parent
  and is `not_enrolled`. The same holds for a process quarantined on sight after the last
  save.
- **Tickets of children that died during an outage.** A restored `revoked` ticket is removed
  when its child exits. A child that exited while the registry was down never reports
  that, so its ticket stays, and keeps its terminal task from being pruned, until the
  next boot. Each restart adds at most the tickets that were then open or closed without
  a bound child.
- **Outage descendants.** During an outage, a quarantined process can fork a child, and
  that child a grandchild. If the child exits before the registry sees it, the grandchild
  reports an unknown parent and is `not_enrolled`.

Either way, after a restart the supervisor must terminate every process group it launched
and report that protection was lost. The native design must also decide what the ES
client does while the registry is unavailable (R3: failure mode, deadline miss).

`save_registry` and `load_registry` require a state directory that the effective user
owns and that group and others cannot write.

- **Save:** the directory is held open with `O_DIRECTORY|O_NOFOLLOW`. The state is
  written to a new temporary file (`O_EXCL|O_NOFOLLOW`, mode 0600), synced, and moved
  into place with `renameat`.
- **Load:** the file must be a regular file with mode 0600, one link, the right owner and
  at most 4 MiB. Duplicate JSON keys and unknown fields are rejected.

This does not prevent a same-owner rollback to an older valid file. The deployed store
belongs in a root-owned location of the authority.

## Action record

Each enforced decision and lifecycle change appends an `ActionRecord` with these fields:

- sequence
- event: `file`, `exec`, `launch` or `lifecycle`
- task ID and revision
- allowed, reason and operations
- a sanitized target

The target is a workspace-relative path. It is replaced with `withheld` for sensitive
names and explicit denials, with `outside_workspace` outside the workspace, and with
`unattributed` for quarantine. Records contain no absolute paths, process tokens or
content. `not_enrolled` events are not recorded. The buffer is bounded
(`max_records`) and losses are counted in `dropped_records`.

## Assumptions R3 must verify on the real OS

The model depends on these platform facts. Each needs an experiment with a signed ES
client before any protection claim.

1. The audit-token pidversion changes on exec as well as on fork, and it is unique within
   a boot session. If exec keeps the same pidversion, the adapter needs its own exec
   generation.
2. The supervisor can obtain the audit token of its own waiting fork child before the
   exec, for example with `task_name_for_pid` and `TASK_AUDIT_TOKEN`, or the child can
   report it over the authenticated channel. A `fork`+`execve` from that child delivers
   `AUTH_EXEC` with the pre-exec identity and the supervisor as parent. The new image does
   not run before the response.
3. ES delivers a child's fork notification before any AUTH event from that child. If not,
   the `unattributed_descendant` path denies it, which must be measured for false denials.
4. The event's parent field is the original parent, not the post-reparent PPID. The
   tombstone rule depends on it when the fork notification was missed and the parent
   has exited.
5. Unrelated processes that the adapter answers as `not_enrolled` can be muted or
   answered fast enough not to stall the host. Result caching must not leak between tasks
   (R1 `cacheable=False`).
6. LaunchServices, XPC services and other daemons act on an agent's behalf outside its
   lineage. The model does not attribute them. R3/R4 must measure the delegation paths
   the target app uses.
7. Paths reach R1 in one canonical spelling. R1 matches rule roots case-sensitively, but
   APFS is usually case-insensitive. `/projects/a/PRIVATE/x` could therefore avoid a
   `/projects/a/private` deny rule unless the adapter reports the on-disk spelling or
   resolved object identity.

## What R2 has not done yet

- Native container app and ES system-extension project skeleton, including entitlement
  declarations kept separate from confirmed approval.
- The authenticated transport (XPC with audit-token and code-requirement checks) and the
  approver UI.
- Wiring into `agentbelt.py`, Zcode Safe or any live launch. `safe_launch` and
  `gui_egress_confined` are unchanged.
- An ES deadline budget. This Python model is a semantic reference, not code for an
  authorization callback.
