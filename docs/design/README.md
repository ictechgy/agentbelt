# Design notes

The Korean originals under `ko/` are kept as the record of decisions, including the ones that were
rejected. Summaries in English:

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
