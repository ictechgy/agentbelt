# Design notes

The Korean originals under `ko/` are kept as the record of decisions, including the ones that were
rejected. Summaries in English:

## 2026-09-22 task policy prototype (R1)

[Task policy](task-policy.md) implements an immutable, versioned contract and pure
authorization decisions with synthetic tests. It is preparation for agentbelt's own
ES engine, with no OS hooks or launcher integration. Trusted runtime approvals remain
a future design; the existing launch-time policy behavior below is unchanged.

## 2026-09-24 task registry and launch binding (R2 model)

[Task registry](task-registry.md) models who may create R1's inputs. A signed supervisor
proposes a contract, and only a separate approver activates it, by confirming the exact
contract digest. A process gets a task only inside the exec authorization. That
authorization must consume the launch ticket the supervisor opened for that exact,
waiting fork child. From then on, exec chains carry the task through fork and exec. Bound or quarantined processes cannot use the control plane, even when
they run a signed binary. A restart interrupts every task and quarantines known
processes. Denied in-workspace accesses become requests that only the approver can turn
into exact, expiring grants. Sensitive names and explicit denials cannot be granted.

This is a narrow exception to the principle below that nothing inside the sandbox can
request a wider policy. The agent never writes a request. The only input it controls is
the access it attempts. Nothing widens until a separate, human-present approver acts.
The model has no OS hooks. Transport, native projects and ES verification remain open.

## 2026-09-24 R3 readiness

[R3 readiness](r3-readiness.md) covers everything that can be prepared before Endpoint
Security is approved:

- a Swift registry whose results match the Python model exactly under differential
  replay;
- schema 2 contracts with `external` rules for runtimes and isolated state;
- the ES AUTH mapping;
- latency measurements, about 1.5 µs per enrolled decision;
- boundary probes and a signed-build checker.

It also explains why neither ES caching nor muting can safely reduce the load.

## 2026-09-24 native guard skeleton (R2)

[Native guard](native-guard.md) adds a buildable skeleton in `native/guard`:

- a container app, which is the planned approver;
- an ES system extension that subscribes to NOTIFY lineage events only and refuses every
  control request;
- a native supervisor that performs the gated launch.

Control messages are authenticated with XPC peer code-signing requirements, then
strictly decoded and checked by the same role table as the Python model. Two findings
matter for the design:

- The public API cannot report an XPC peer's pidversion, so enrollment is checked by PID
  until `AUTH_XPC_CONNECT` (macOS 27) is available.
- A gated fork lets the supervisor read the child's audit token before `execve`. On this
  Mac, the child's pidversion changes on exec.

Nothing was signed, installed or activated.

## 2026-09-07 agent-gate design (rejected)

Proposal: let an LLM act as the authorizer for commands and installs that fall outside the
sandbox policy, deciding per request whether to widen the boundary.

Three independent reviews (Codex, Antigravity, Grok) rejected it for the same reason. The
acceptance test is: *replace the judge with an adversarial implementation that always answers
"allow"; can the agent obtain anything outside the authorized set?* The design fails it. The
command string is itself an injection channel (splitting it into JSON fields does not help), and
approving an install is granting a network permission that the session does not have, on the
strength of an LLM judgement. That contradicts the principle the rest of the system is built on:
the kernel-applied policy is the authority, and nothing inside the sandbox can widen it.

What replaced it: a reviewed allowlist of package-registry domains that every session gets, plus
per-workspace opt-in grants (loopback, keystore, publishing) that the operator sets on the host.

## 2026-09-07 install transaction v1 / v2 (rejected)

Proposal: a human-approved "install transaction" so an agent could request a dependency install,
the operator approves a plan, and the supervisor executes exactly that plan.

v1 was rejected because the workspace manifest ended up stronger than the approved plan. v2
narrowed the scope but the approval was still not bound to the execution, and its
"add one coordinate" versus "replace the whole generation" semantics could silently drop existing
dependencies. Every approval channel considered (host TTY, native dialog, Orca decision gate,
the agent's own permission UI) failed for a mobile-remote operator or could not distinguish a
human from the agent.

What replaced it: package registries are reachable from inside the sandbox, so installs need no
approval step; the boundary is on *where* the install can write (workspace and isolated home
only), not on *whether* it may happen.

## Standing principles these notes established

- Authorization decisions are made on the host by the operator, before launch, and expressed as
  policy. Nothing inside the sandbox can request a wider policy at runtime.
- A claim about the boundary is accepted only with a kernel-level observation.
- Agent self-diagnosis is unreliable; the session notice exists so the agent knows what it cannot
  see instead of inventing a cause.
