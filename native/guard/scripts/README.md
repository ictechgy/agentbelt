# native/guard/scripts

## verify_signed_build.py

R3 needs a signed build whose provisioning profile really carries the Endpoint Security
capability. This tool checks a built product before anyone installs it. It runs only
`codesign -d`, `codesign --verify` (with `-R` requirements) and `security cms -D`, and it
reads plists and Mach-O signature blobs directly. It never signs, installs, activates,
uses the network or reads keychains.

```sh
/usr/bin/python3 -I native/guard/scripts/verify_signed_build.py \
  --app <Products>/AgentbeltGuard.app --supervisor <Products>/agentbelt-supervisor \
  --expect-team TEAMID [--distribution development|developer-id] [--json]
```

Each check prints PASS, FAIL or SKIP with a reason. The exit status is 0 only when every
required check passes; a required check that could not run (SKIP) counts as a failure.
`--expect-team` is required so that a build from the wrong team cannot pass by default.

### Where trust comes from

`codesign -dvvv` echoes attacker-chosen names (paths, identifiers) verbatim, so a file name
with newlines can forge whole lines of its output. The tool therefore:

- binds identity with Security requirement evaluation:
  `anchor apple generic and identifier "<id>" and certificate leaf[subject.OU] = "<TEAM>"`,
  plus Apple's WWDR marker for `development` or the Developer ID intermediate and leaf
  markers for `developer-id`;
- reads the identifier, team, flags and entitlements from the CodeDirectory and
  entitlements blobs of every architecture slice, and requires the slices to agree;
- only cross-checks the codesign text, refusing it outright when a key repeats;
- rejects control, format and line-separator characters in input paths, bundle names and
  `CFBundleExecutable`.

### Checks

| Group | Checks |
| --- | --- |
| Each of app, sysext, supervisor | strict signature (`--deep` for bundles), requirement satisfied, signature blob matches codesign, not ad-hoc, team, hardened runtime (0x10000), no `get-task-allow`, signing identifier, Info.plist bound; with `--distribution`, leaf certificate kind and, for Developer ID, a secure timestamp |
| Identifiers | app = its `CFBundleIdentifier` (not `invalid.*`); sysext = app + `.fileguard`; supervisor = app + `.supervisor` (an open question in the design doc) |
| Team | same team for all three, equal to `--expect-team` |
| Entitlements | app has `system-extension.install`, sysext has `endpoint-security.client`; both carry `com.apple.application-identifier = <TEAM>.<id>` and `com.apple.developer.team-identifier = <TEAM>`; supervisor has none |
| Profiles (app, sysext) | present, decodes, team, the signing leaf certificate is one of its `DeveloperCertificates` (SHA-256 of DER), explicit App ID, team identifier, grants the required capability, grants every signed entitlement with a matching value, not expired, type matches `--distribution` |
| Nested code | every other Mach-O in each bundle satisfies the team requirement, is not ad-hoc, has the team, has no `get-task-allow`; nested executables also need hardened runtime (libraries do not, since the runtime flag is a process property) |
| Trust roots | sysext bundle name = its id + `.systemextension`; `NSEndpointSecurityMachServiceName` starts with `<team>.`; `AGB*` keys equal the team and signing identifiers; the supervisor's `__TEXT,__info_plist` names the same Mach service, File Guard identifier and team |

The report shows a profile's device count and whether the signing certificate is listed,
never certificates, their digests, device IDs or signer names. Certificates are extracted
into a private (0700) temporary directory that is removed afterwards.

Limits: `security cms -D` decodes a profile without judging its certificate trust, which
the system evaluates at launch. The `development` marker OID and the profile-type rule
(devices listed vs. `ProvisionsAllDevices`) have not been checked against a real signed
agentbelt build yet.

## Tests

```sh
/usr/bin/python3 -I -m unittest discover -s native/guard/scripts -p 'test_*.py' -v
```

Unit tests use synthetic bundles, canned command output (including forged, duplicated and
newline-injected codesign text) and Mach-O images with signature blobs built in the test.
The integration test runs against the unsigned build in
`native/guard/build/Build/Products/Debug` when it exists, requires the tool to reject it,
and requires the blob reader to agree with the real codesign on those binaries.
