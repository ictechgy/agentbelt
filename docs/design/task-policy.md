# Task policy prototype — R1

Status: pure policy logic and synthetic tests, implemented before Apple ES approval.
`task_policy.py` is not connected to a launcher, GUI, authorization service or Endpoint
Security client. No result from it establishes OS enforcement. Existing Seatbelt
behavior and GUI protection flags are unchanged.

The intended product is an agentbelt-owned engine connecting the authority granted
for an AI task to its observed file operations. Santa is a comparison/reference;
this implementation has no Santa dependency.

## Run the checks

From the source checkout, with Python 3.9 or newer:

```sh
/usr/bin/python3 -I -m unittest discover -s tests -p test_task_policy.py -v
```

The suite uses synthetic paths, process identifiers and times. It does not open the
paths in access requests, launch agents, use credentials, contact a provider or
activate a system extension. CI runs it before installation. The existing install
script copies root Python modules, tests and examples; copying this module does not
activate it.

## Authority boundary

`evaluate(state, binding, access, now_ns=...)` is deterministic and performs no I/O.
The future trusted supervisor must provide all authoritative inputs:

| Input | Required source |
| --- | --- |
| `TaskState.contract` | Current operator-authorized contract, obtained from a supervisor-owned registry |
| `TaskState.revoked` | Current lifecycle state, including any ancestor revocation when delegation exists |
| `ProcessBinding` | Supervisor mapping between an OS execution instance, task ID and policy revision |
| `FileAccess.process` | OS-observed process instance, never a child-supplied PID or task ID |
| `FileAccess.path` / `operations` | Validated event adapter output; lexical paths alone do not prove object identity |
| `now_ns` | Trusted nondecreasing clock in the same epoch as the contract's lifetime |

`FileAccess.claimed_task_id` is ignored for authorization. Environment variables,
MCP descriptions, model answers and tool declarations cannot create a binding.
The process `generation` is an opaque placeholder for boot/start/exec distinctions;
R1 does not obtain those distinctions from macOS or authenticate them.

Constructors and JSON parsing validate shape, not provenance. An attacker who can
call the engine with fabricated state or process identities can fabricate decisions.
R2 must build the authenticated control boundary before any real launch uses this
module. There is no wire protocol accepting child-provided contracts or bindings.

No state is stored or cached here. Revocation, expiry and revision checks apply to
the supplied current snapshot on every call. This module cannot detect a supervisor
that replays an old snapshot or moves its clock backwards. Restart/boot invalidation,
durable revision ordering and atomic lifecycle changes remain R2 responsibilities.

## Version 1 contract

[The synthetic example](../../examples/task-policy.json) is executable input to
`load_contract(text)` or `contract_from_dict(document)`. It uses fake clock values;
it is not a live configuration to install.

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1`; booleans and unknown versions are rejected |
| `task_id` | Opaque identifier, 1–128 ASCII letters/digits/`._:-`, beginning with a letter/digit |
| `revision` | Positive integer; a binding to a different revision is denied |
| `workspace` | Absolute canonical path spelling, excluding `/` |
| `valid_from_ns`, `expires_at_ns` | Integers in `[0, 2^63−1]`, start strictly before expiry; interval is `[start, expiry)` |
| `allow`, `deny` | Required arrays of at most 128 rules each; empty `allow` grants nothing |

A rule contains exactly `path`, `scope` (`exact` or `tree`) and a nonempty, duplicate-free
`operations` array selected from `read`, `write`, `execute`. `tree` includes its root
and descendants separated by `/`; `/project/a` does not match `/project/ab`.
Allows must stay inside the workspace. Denials may be broader so a restricted child
can retain its parent's exclusions. External runtime/app-state grants are not part
of v1 and need an explicit later design.

Paths must be absolute UTF-8 strings of at most 4096 bytes, with no control characters,
empty components, `.`/`..`, duplicate separators or trailing slash (except `/`). The
engine rejects ambiguous spelling; it never calls `resolve`, `stat` or opens a target.
No case folding or Unicode normalization is applied to permission roots. Sensitive
name exclusions are matched case-insensitively on every component.

The strict decoder rejects unknown/missing fields, type coercion, duplicate JSON
keys, nonfinite numbers and input larger than 64 KiB. Rules and contracts are frozen
and use immutable tuples/frozensets. Decoding and serialization do not retain mutable
references to caller-owned document containers. Error text does not echo input values.

## Schema 2: external rules

Schema 2 has the same fields as schema 1, plus a required `external` array of rules. It
is the only way to allow paths outside the workspace, such as runtime trees and an
agent's isolated home.

- An `external` rule may not be `/`.
- It grants only the operations it lists.
- It is checked after the sensitive-name and explicit-deny checks, so both still win.
- For a child contract, every `allow` and `external` operation must be covered by the
  parent's `allow` or `external`.

A child contract's schema version may not be lower than its parent's. No `allow` or
`external` rule may cover `/System/Volumes/Data` or lie inside it, and no workspace may
lie inside it, because that firmlink is a second spelling of every user file.

A schema 1 document with an `external` key is rejected, and so is a schema 2 document
without one. Schema 1 documents and their proposal digests are unchanged. See
[R3 readiness](r3-readiness.md).

## Per-agent external baselines

Status: `task_profiles.py` builds the contract document, and `tests/test_task_profiles.py`
tests it. The module is host-only and is not connected to a launcher. `agentbelt.py`
does not import it.

The `external` list for each mode is a translation of the roots agentbelt already grants
that mode under Seatbelt. Those roots come from `sandbox_policy()` (`system_reads`,
`executable_reads`, `deny_homebrew_data`, and the `.git` entries of `denyWrite`), from
the mode's `run_confined()` arguments, and from the literals that `sandbox_runner.mjs`
appends. Every rule records why it exists and which Seatbelt grant it mirrors. The drift
tests parse those sources and fail when an entry changes there but not in the profile
table.

```python
profile = task_profiles.kimi_profile(binary=staged, home=home, watch_bootstrap=..., guard_root=ROOT,
                                     node_binary=..., node_prefix=..., homebrew_prefix='/opt/homebrew',
                                     tty_path='/dev/ttys012')
document = task_profiles.build_contract(task_id, revision, workspace, valid_from_ns, expires_at_ns,
                                        mode_profile=profile, repository_write=False)
task_policy.contract_from_dict(document)  # accepts it
```

The document is schema 3 when it carries any [exception](#schema-3-exceptions-to-the-sensitive-name-exclusion).
Otherwise it stays schema 2, for example a probe built with `repository_read=False`.

The module reads no files, clocks or environment. The caller passes paths it has already
resolved, because ES reports resolved spellings (`/private/var/...`).
`resolved_launch_path(path, realpath=...)` takes the lookup as an injected function.
`workspace_allow` defaults to a read+write+execute workspace tree. Seatbelt allows
execution there, and schema 2 has no exec exception.

### Rules per mode

R = read, X = execute, W = write. "Tree" rules cover the path and everything below it.

| Rule | Scope, ops | probe | opencode | kimi | zcode | Seatbelt source |
| --- | --- | --- | --- | --- | --- | --- |
| Agent image (verified clone) | exact RX | binary | `state/opencode-runtime/launch-*/opencode` | `state/kimi-runtime/launch-*/kimi` | pinned Node binary | `stage_*_binary`, `extra_reads` |
| `/bin/sh` | exact RX | yes | (in `/bin`) | (in `/bin`) | (in `/bin`) | probe fixture |
| `/usr/lib`, `/System/Library` | tree RX | yes | yes | yes | yes | `system_reads` |
| `/System/Volumes/Preboot/Cryptexes/OS` | tree RX | yes | yes | yes | yes | none (dyld shared cache, probe fixture) |
| `/usr/bin`, `/bin`, `/sbin`, `/usr/sbin`, CommandLineTools | tree RX | — | yes | yes | yes | `system_reads` |
| `/usr/share` | tree R | — | yes | yes | yes | `system_reads` |
| Rosetta runtime | exact RX | — | yes | yes | yes | `system_reads` |
| `/dev/null`, `/dev/zero`, `/dev/tty` | exact RW | — | yes | yes | yes | `system_reads` (+ device write decision) |
| Private PTY `/dev/ttys<N>` (validated `/dev/ttys[0-9]{1,4}`) | exact RW | — | if given | if given | if given | `AGENTBELT_TTY_PATHS` |
| `/dev/random`, `/dev/urandom`, resolver, services, protocols, localtime, `openssl.cnf` | exact R | — | yes | yes | yes | `system_reads` |
| `/private/etc/ssl/cert.pem` | exact R + exception | — | yes | yes | yes | `system_reads` |
| `/etc`, `/var`, `/tmp`, `/private/var/select/sh` (link vnodes) | exact R | — | yes | yes | yes | `sandbox_runner.mjs` |
| Guard root directory vnode | exact R | — | yes | yes | yes | `sandbox_runner.mjs` moduleRoot |
| Node `<prefix>/bin`, `<prefix>/lib/node_modules` | tree RX | — | optional | optional | required | `executable_reads` |
| Homebrew `bin`, `opt`, `Cellar`, `Library/Homebrew` | tree RX | — | optional | optional | optional | `executable_reads` |
| Homebrew `etc/openssl@3/openssl.cnf` | exact R | — | optional | optional | optional | `executable_reads` |
| `/opt/homebrew/etc/ca-certificates/cert.pem` | exact R + exception | — | optional | optional | optional | `executable_reads` |
| Mode files | exact R | — | `state/opencode-config.json`, `state/opencode-auth.json` | `kimi_watch_bootstrap.cjs` | hook, bridge, fetch preload, guard settings, riskgate policy | mode `extra_reads` |
| Mode trees | tree R(X) | — | — | — | app bundle RX; `vendor`, `runtime/node_modules/undici` R | zcode `reads` |
| Isolated home (+ OpenCode runtime home) | tree RWX | yes | yes | yes | yes | `allowWrite` home |
| Separate short TMPDIR | tree RWX | if given | if given | if given | if given | `short_tmpdir` |

Exceptions (schema 3) emitted per mode:

| Exception | Scope, ops | probe | opencode | kimi | zcode |
| --- | --- | --- | --- | --- | --- |
| `/private/etc/ssl/cert.pem`, `/opt/homebrew/etc/ca-certificates/cert.pem` | exact R | — | yes | yes | yes |
| `<home>/.local/share/opencode/auth.json` | exact R | — | yes | — | — |
| `<home>/.kimi-code/credentials` | tree RW | — | — | yes | — |
| `<home>/.zcode` (`ZCODE_HOME`) | tree RW | — | — | — | yes |
| `<home>/.npmrc` (empty file from `clean_environment`) | exact R | — | yes | yes | yes |
| `<workspace>/.git` | tree R, + W with `repository_write=True` | per task | per task | per task | per task |
| `<home>/.pub-cache/git`, `<home>/.cargo/git`, names `.git` | tree RW, name-scoped | — | yes | yes | yes |
| `<workspace>/.build/checkouts`, names `.git` | tree RW, name-scoped | — | if the workspace is writable | if the workspace is writable | if the workspace is writable |

OpenCode's `auth.json` gets read only. It is a hard link to the guard-owned
`state/opencode-auth.json`, so Seatbelt write-locks it (`read_only_home_paths`), and
the explicit write denial stays in the contract. `.npmrc` is also read only: npm reads
the empty file through `NPM_CONFIG_USERCONFIG`, and a write is still denied by name.

**Tree exceptions.** A tree exception lifts the ban on every sensitive name beneath it,
not only on its root. Zcode needs this: `ZCODE_HOME` holds `cli/db/db.sqlite` and
similar files, and `*.sqlite` is itself a sensitive name. For the same reason, a `.env`
inside `<workspace>/.git` or `<home>/.zcode` is readable when the exception grants read.
Tree exceptions are therefore limited to two kinds of path:

- the agent-state directories in the launch's own isolated home (`.kimi-code/credentials`
  and `.zcode`);
- the workspace `.git`.

Every other exception is exact, apart from the name-scoped package caches below. No exception adds `execute`, and explicit denials still
win below a tree exception, so `.zcode/cli/config.json` and `.git/hooks` stay
write-locked. The approver sees the exceptions as a separate `exceptions` list in the
contract whose digest it confirms, next to `allow`, `external` and `deny`. Each
`ProfileRule` also carries its review record (`why`, `source`).

**Package managers' git checkouts.** Under Seatbelt, SwiftPM, dart pub and cargo may create
repositories in `<workspace>/.build/checkouts`, `<home>/.pub-cache/git` and
`<home>/.cargo/git` (`git_tool_caches` in agentbelt.py, `gitToolRules` in git_lock.mjs).
The package directory below each cache is not known in advance, so the ES baseline uses
[name-scoped exceptions](#name-scoped-tree-exceptions) with `names: [".git"]` and read+write:
`<cache>/<package>/.git/...` is lifted, `<cache>/<package>/.env` is not. The home caches
are emitted only in the launch home (`run_confined`'s `home`, the profile's first isolated
home), as under Seatbelt, so OpenCode's runtime home gets none. `build_contract` adds the
workspace cache only when `workspace_allow` grants read and write on it, so a read-only
workspace gets none. The probe has no Seatbelt launch and gets neither. The drift test
requires the same relative paths as `git_tool_caches`.

Deny rules added to every contract:

- Supervisor-seeded home files the child cannot replace: write. These are `.gitconfig`,
  the environment notice, the mode's instruction and region files, Zcode's
  `.zcode/cli/config.json`, OpenCode's `auth.json` link and the relay's locked paths.
- OpenCode's runtime-home `.config/opencode` and `.opencode`: write.
- `<workspace>/.git/{config,config.worktree,hooks,info/attributes,commondir,modules,worktrees}`:
  write, and the `<workspace>/.git` entry itself: write (exact). These are the paths
  `git_lock.mjs` locks under Seatbelt, and they stay locked with `repository_write=True`.
  `commondir`, `modules` and `worktrees` redirect git to another config, and a replaced
  `.git` entry (a `gitdir:` file or a link) points it at a child-written directory; host
  git would then run a child-chosen `core.fsmonitor` (measured 2026-09-24). Nested `.git`
  entries need no rule: the sensitive name denies them.
- `/opt/homebrew/var` (when Homebrew is granted): every operation.
- For Zcode, the workspace `.zcode`, `zcode.json` and `.agents/mcp.json`: every operation.

Rule counts (external / deny) with Homebrew and Node: opencode 42/15, kimi 39/13,
zcode 48/16. These are well below `MAX_RULES`.

### What `validate_profile` refuses

- `/`, and any rule on `/System/Volumes/Data` or inside it (case-insensitive).
- Any rule at, above or inside the workspace.
- A tree that equals or contains a broad anchor, compared case-insensitively:
  `/Users`, `/Volumes`, `/Applications`, `/usr/local`, `/opt/homebrew/{var,etc}`,
  `/private/{var,tmp,etc}`, the Keychains, Preferences and Application Support folders of
  `/Library`, or `/System/Volumes`. This rules out `/System`, `/usr`, `/opt/homebrew`,
  `/private` and `/Library`.
- Anything below `/var`, `/tmp` or `/etc`. These are symlinked spellings, and ES reports
  the resolved `/private/...` path.
- Inside the guard installation, a tree that is neither a writable root nor one of
  `vendor`, `runtime/node_modules/undici` or `state/zcode-private/ZCode.app`. Such a tree
  could reach other workspaces' homes, the stored credentials or the private Zcode
  profile. Exact rules there are allowed.
- Write outside the launch's writable roots: the isolated home, the OpenCode runtime home
  and a separate TMPDIR. The only exceptions are the exact devices `/dev/null`,
  `/dev/zero`, `/dev/tty` and one `/dev/ttys<N>`. No `/dev` tree is ever writable, so
  `/dev/disk*` stays closed. A writable root must be at least three components deep. It
  may not overlap the workspace or contain the guard root.
- A writable root that is not shaped like a root agentbelt creates for one launch:
  below the guard root, `state/homes/<mode>/<20 hex>`, `state/control-*/{home,runtime-home}`
  or `state/t/<22-character token>`; anywhere, `/private/tmp/agentbelt-<uid>/<name>`. This
  refuses `~/Library`, another project, `~/Documents`, `state/homes` itself (every other
  workspace's home) and `/private/var/folders` as TMPDIR. The probe profile has no guard
  root, so only the last shape applies to it.
- Duplicate or overlapping rules, and more than `MAX_RULES` rules.
- A rule on a sensitive name, unless an allowed exception names the same path. Without
  one, the rule would never take effect, because the sensitive-name check runs first.
- An exception outside the approved set:
  - a trust store other than an exact, read-only file in `TRUST_STORE_FILES`;
  - agent state other than an `AGENT_STATE_EXCEPTIONS` entry in the launch's own
    isolated home, with its fixed scope and at most its fixed operations (R for
    `auth.json` and `.npmrc`);
  - any exception granting `execute`;
  - any exception not rooted at the sensitive name itself. A tree above `.ssh` or a
    `.kimi-code` tree is refused, and so is another workspace's home;
  - a name-scoped exception other than `names: [".git"]` on the launch home's
    `.pub-cache/git` or `.cargo/git` tree, and a workspace git cache other than
    `.build/checkouts`.

`task_policy` itself refuses an exception that no `allow` or `external` rule covers.
One example is `repository_write=True` when the workspace allow is read-only.

### Sensitive names still win

`.ssh`, `.env*`, `*.pem`, `credentials`, `*.key`, `.aws`, `.npmrc` and the other
`SENSITIVE_COMPONENTS` stay absolutely denied outside the exceptions above. This covers
another home's `credentials`, `/private/etc/ssl/private.pem`, and `.env` or `*.key` in
the workspace.

A tree exception lifts the name ban for everything below it. For example, a `.env`
inside `<workspace>/.git` or `<home>/.zcode` is readable when the exception grants read.
The exception never adds execute.

`ModeProfile.sensitive_conflicts` is empty for every mode. A workspace `.npmrc` and any
other home's `.npmrc` stay denied.

### Known only at launch

These paths cannot be derived statically. The caller supplies each one after resolving it:

- The staged clone path (`launch-<pid>-<random>`).
- The persistent home's workspace hash.
- The OpenCode `control-*/runtime-home`.
- The short TMPDIR token.
- The private PTY name.
- The pinned Node location (nvm version or Homebrew Cellar target).
- The riskgate policy path.
- The private Zcode `app_path`.
- The relay's locked home paths.

`darwin_temporary_items()` (`getconf DARWIN_USER_TEMP_DIR`) and the opt-in
`darwinTempDirectories` are also per user and per launch. Seatbelt makes the first
write-only and the second read+write. The baseline deliberately leaves both out, because
they lie outside the home and TMPDIR (see the open decisions below).

### Decided

- **Sensitive-name conflicts** are resolved with schema 3 exceptions, limited to trust
  stores (exact read), agent login and state in the isolated home (including the
  read-only `.npmrc`), the workspace `.git` per task, and `.git` below the package
  managers' git caches (name-scoped).
- **Device writes** are allowed only as exact rules on `/dev/null`, `/dev/zero`,
  `/dev/tty` and a validated `/dev/ttys<N>`.

### Open decisions

1. **Darwin TemporaryItems.** SwiftPM's atomic writes need a write-only root, and the
   contract cannot express write without read. `TMPDIR` redirection does not cover
   Foundation.
2. **Link targets.** `/private/etc/localtime` points into `/private/var/db/timezone`, and
   `/private/var/select/sh` points at a shell. Which spelling ES reports for a followed
   link needs the R3 measurement. Only the link vnodes are granted now.
3. **Who is enrolled.** The trusted `node sandbox_runner.mjs` and `sandbox-exec` run
   before the agent. If enrollment starts earlier, the runner's own reads must be
   covered too. They are not in this baseline.
4. **Execute on writable roots.** The home and TMPDIR are RWX, as under Seatbelt. A
   stricter baseline would drop X there and break the Gradle wrapper and `go test`.
5. **Tree exceptions.** A `.env` inside `.git` or `.zcode` is readable when the exception
   grants read. This is broader than Seatbelt inside the workspace: `sandbox_policy()`
   denies `<workspace>/**/.env*` and the other secret names there, `.git` included.
   (Seatbelt applies no secret names to the home, so `.zcode` matches.) Narrowing this
   would need per-name exceptions below the tree.

## Schema 3: exceptions to the sensitive-name exclusion

Schema 3 has the same fields as schema 2, plus a required `exceptions` array. Under ES
enforcement some sensitive names are needed by the agent itself:

- a TLS trust store (`*.pem`);
- the agent's own login state in its isolated home (`auth.json`, `credentials`, `.zcode`);
- the workspace `.git`.

An exception lifts the sensitive-name ban for exactly its path, scope and operations.
Every exception must:

- use only `read` and/or `write`, never `execute`;
- end in a sensitive component (`.../.git`, `.../cert.pem`), so a tree exception never lifts
  the names below an ordinary directory (a workspace inside `secrets/`, or `.git/objects`).
  Name-scoped exceptions (below) are the one exemption;
- stay clear of `/` and `/System/Volumes/Data`;
- be covered, operation by operation, by `allow` or `external` rules. It never widens a
  path grant; it only stops the name from blocking what is already granted.

Explicit denials still win over exceptions, and they match ASCII case-insensitively
(`PathRule.denies`): on case-insensitive APFS `.git/HOOKS` is `.git/hooks`, and inside a
tree exception the denial is the only protection. Only A-Z fold, so the Swift port agrees
byte for byte; non-ASCII case variants depend on the spelling ES reports (an R3
measurement). Allow and exception paths stay exact, which can only deny more. A request is lifted only if every requested
operation is covered by an exception for that path, and the result then carries the
reason `allowed_by_exception`. Records keep such targets `withheld`. A child's exceptions
must be covered by its parent's, so delegation cannot add one. The approver sees
exceptions as a separate list in the contract whose digest it confirms. Sensitive names
that no exception covers stay absolutely denied. Schema 1 and 2 documents and digests are
unchanged.

### Name-scoped tree exceptions

A rooted exception cannot express a package manager's git cache: the repositories sit at
`<cache>/<package>/.git`, and the package directory is not known when the contract is
approved. An exception rule may therefore carry an optional `names` field:

```json
{"path": "/w/a/.build/checkouts", "scope": "tree", "operations": ["read", "write"], "names": [".git"]}
```

- `names` is allowed only on `exceptions` rules with scope `tree`. On an `allow`, `deny`
  or `external` rule the document is refused (`invalid document fields`); on an exact
  exception, too (`names only on tree exceptions`).
- It is a non-empty list of at most 8 distinct strings. Each must be one literal path
  component in printable ASCII (0x21–0x7E), in lower case, without `/` or `*`
  (`exception name is not a lowercase ASCII component`), and itself a sensitive name
  (`.git`, `.env`, `x.pem`; `exception name is not sensitive`). Names are compared with
  the casefolded component. Python's `str.casefold` and Foundation's folding disagree on
  some non-ASCII scalars (Cherokee `ꭰ`, U+AB70, among others), so a non-ASCII name would
  decide differently in the two implementations. `.GIT`, `ß.pem` or a pattern such as
  `*.pem` could never match a casefolded component, so they are refused as well.
- The rule's own path must contain no sensitive component at all
  (`scoped exception path is sensitive`). It is exempt from the rooted-at-a-sensitive-name
  requirement instead. Coverage by `allow`/`external` and the no-execute rule still apply.

A name-scoped exception lifts a requested path when the path lies in its tree and every
sensitive component of the path lies strictly below the root and casefolds to one of
`names`. `<cache>/dep/.git/config`, `<cache>/dep/.GIT/HEAD` and `<cache>/.git` are lifted;
`<cache>/dep/.env` and `<cache>/dep/.git/.env` stay `sensitive_path`. Unscoped exceptions
keep their meaning, and explicit denials still win (ASCII case-insensitively, as above).

A child's name-scoped exception must be covered by a parent name-scoped exception that
covers its path, includes each of its operations and lists every one of its names. An
unscoped parent exception does not cover a scoped child, and a scoped parent does not
cover an unscoped child: the unscoped child would lift every name below its root.

`contract_to_dict` emits `names`, sorted, only on rules that have it, so every existing
v1, v2 and v3 document and its proposal digest is unchanged (golden digests in
`tests/test_task_policy.py`).

Limits of this design:

- **Links inside agent-writable trees.** The cache roots lie inside trees the agent can
  write (the workspace and the isolated home). If the agent replaces
  `.build/checkouts` with a link to, say, the workspace `.git`, a lexical match on
  `<cache>/x/.git/...` would lift a path whose real target is locked. This is safe only
  if ES reports resolved paths, which is on the R3 measurement list
  ([R3 readiness](r3-readiness.md)). Seatbelt already matches resolved paths.
- **Host tools inside the caches (accepted risk).** When SwiftPM, dart pub or cargo run
  git on the host inside these caches, git obeys hooks and config the agent may have
  written there. The deployed Seatbelt layer made the same decision (`gitToolRules`
  undoes the git lock in those trees). `git_audit.py` reports only repositories that
  leave the caches, not the contents of the ones inside.
- **OpenCode protected mode.** HOME is the runtime home there, so cargo's default
  `$HOME/.cargo/git` lies in the runtime home and is not lifted in either layer (dart pub
  keeps `PUB_CACHE` in the launch home). Parity with Seatbelt is kept.

## Decision semantics

1. Reject invalid/unbound inputs, mismatched process generation, task or revision.
2. Reject revoked, not-yet-valid and expired contracts.
3. Reject sensitive names and agent-control paths, even under an allow rule.
4. Reject any matching explicit denial for any requested operation.
5. Allow only if every requested operation has a matching allow rule.

Read does not imply write or execute. A read+write request needs both. Denials win
regardless of rule order. Conservative name exclusions include credential/key stores,
`.env*`, databases and agent configuration; public keys are also excluded. They are
not content-based secret detection and cannot be overridden in this prototype.

`Decision` contains only `allowed`, a fixed reason, the policy revision,
`cacheable=False` and `enforcement='policy_only'`. It excludes paths and process tokens.
These are policy results, not records of successful I/O. The future ES adapter must
also avoid sharing OS-cached results between sessions; this flag alone does not
configure an ES cache. Detailed user-facing action records remain future work.

Unknown bindings deny within this policy model. An ES adapter must independently
identify enrolled processes and route unrelated host events; installing this decision
function as a global deny handler would block unrelated apps.

`is_attenuation(parent, child)` checks that a child has a different task ID, a contained
workspace, a shorter/equal lifetime, contained allow rules and preserved/stronger
denials. It is intentionally conservative. It is not a delegation API and does not
track parent liveness, revision changes or revocation propagation.

## Remaining proof before OS use

- R2: trusted launch registration before first access, authenticated local transport,
  real process generations, children/exec/reparent events and authoritative lifecycle.
  The semantics are modelled in [task registry](task-registry.md); transport, native
  projects and real events remain open.
- R3: event mapping for AUTH versus NOTIFY, ES flags and deadlines, OS cache behavior,
  failure/restart/overload handling, path aliases and actual file object identity.
- Symlinks, hardlinks, case/Unicode aliases, path replacement, rename source/destination,
  open descriptors, descriptor transfer, mmap and IPC proxies need real OS experiments.
  Mapping all of these to a lexical `write` check would be incorrect.
- R4: actual visible ZCode GUI and required helpers with Chromium's sandbox preserved;
  narrow runtime/state access, trusted approval UI and cooperative retries.
- Human approval cannot wait inside an ES callback. No additional-grant mechanism is
  implemented here. Network, clipboard, Keychain and other GUI channels need their own
  coverage evidence. No GUI confinement flag is promoted by passing these tests.

The Python module is a reference policy contract, not a decision to execute Python or
perform cross-process RPC in an ES authorization callback. Native execution and policy
distribution must meet the actual deadline and isolation requirements measured later.
