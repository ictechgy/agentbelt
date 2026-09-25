# agentbelt Guard — native skeleton (R2)

This directory holds the Endpoint Security side of agentbelt's own engine. **It enforces
nothing yet.** File Guard subscribes only to NOTIFY lineage events and refuses every
control request, so the supervisor can never report a protected launch. Design and
evidence are in [native-guard.md](../../docs/design/native-guard.md).

| Path | Contents |
| --- | --- |
| `GuardKit/` | Swift package. `GuardCore`: control protocol, trust policy, role gate. `GuardTransport`: XPC listener and client, code identity. `SpawnGate`: C launch gate, audit tokens. `GuardRegistry`: Swift port of the Python policy and registry, checked differentially. `GuardES`: AUTH mapping. `GuardService`: control dispatcher. `guard-bench`: latency benchmark |
| `R3Probes/` | Boundary probes for the R3 acceptance tests (baseline mode today) |
| `scripts/` | `verify_signed_build.py`, which checks a signed build before installation |
| `FileGuard/` | System extension: ES client in skeleton mode plus the control Mach service |
| `App/` | Container app: activates or deactivates File Guard on explicit user action |
| `Supervisor/` | `agentbelt-supervisor launch --task <id> -- /agent ...` gated launch |
| `Config/Signing.xcconfig` | Placeholder bundle prefix and Team ID; real values go in untracked `Signing.local.xcconfig` |
| `project.yml` | XcodeGen spec; the generated `.xcodeproj` is not committed |

```sh
swift test --package-path GuardKit
xcodegen generate
xcodebuild -project AgentbeltGuard.xcodeproj -scheme AgentbeltGuard -configuration Debug \
  -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
```

Do not install or activate this build as a protection mechanism. A signed build requires
an App ID for each target and a provisioning profile that includes the approved ES
capability. Neither has been confirmed.
