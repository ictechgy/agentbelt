# agentbelt Guard — R3 boundary probes

Probes for the R3 acceptance tests: a confined "agent" process under a task contract for
project A tries to cross the boundary, and each attempt's outcome is recorded. **This
package enforces nothing and proves no Endpoint Security behavior.** Today it runs only in
baseline mode (no enforcement), which shows that every probe works. Enforced mode needs
the signed File Guard build, which depends on Apple's unconfirmed ES approval.

| Path | Contents |
| --- | --- |
| `Sources/R3ProbesKit/Catalog.swift` | Probe list, expectation table and guard records (the source for the table below) |
| `Sources/R3ProbesKit/Fixture.swift` | Synthetic fixture layout, manifest, lstat integrity check |
| `Sources/R3ProbesKit/Contract.swift` | Schema-2 task contract and its external-rule refusals |
| `Sources/R3ProbesKit/Probes.swift` | Probe runner and the unconfined `fd-server` helper |
| `Sources/R3ProbesKit/Verify.swift`, `GuardRecords.swift` | Comparison of results with expectations and guard records |
| `Sources/R3ProbesKit/RootSafety.swift` | Root refusal rules |
| `Sources/ProbeSys/` | C helpers: `clonefile`, `copyfile`, `renamex_np`, ACL, `getattrlist`, `mmap`, `SCM_RIGHTS`, `fork`, `posix_spawn` |
| `Sources/R3ProbesCLI/` | The `r3-probes` executable |

## Baseline run

```sh
swift test --package-path native/guard/R3Probes
cd native/guard/R3Probes && swift build
R=$(.build/debug/r3-probes setup | sed -n 's/^root: //p')    # fresh mkdtemp root under $TMPDIR
.build/debug/r3-probes fd-server --root "$R" &              # unconfined helper, serves 4 fds
.build/debug/r3-probes run --root "$R" --inherited-fd 3 --json "$R.results.json" 3<"$R/outside/victim.txt"
.build/debug/r3-probes verify --root "$R" --results "$R.results.json" --mode baseline
```

The shell's `3<` stands in for a launcher that opened the victim before exec. `run` exits 0
when every probe was attempted. `verify` exits 1 on any mismatch, prints a table, then
lists the roadmap rows no probe covers. `r3-probes expectations --json` prints the table
below as data. `sub-probe` is internal: the child probes re-execute the binary with it.

Every command except `setup` takes the root exactly as `setup` prints it (see Safety).

## Planned enforced run (R3, not yet possible)

1. `setup` and `fd-server` run unconfined, as above.
2. `r3-probes contract --root <root> --probe-binary <path>` prints the schema-2 contract.
   Replace its placeholder lifetime with real clock values.
3. The supervisor launches `r3-probes run --root <root> --inherited-fd 3 --json -` under
   that contract, with the victim open as fd 3 before the launch. The launcher closes fds
   >= 3, so `fd.inherited-read` expects `EBADF` at `fstat`; without `--inherited-fd` it is
   *unavailable* and fails. The contract denies writes outside the workspace, so results
   go to stdout, redirected by the unconfined shell.
4. Export the guard's action records for the run (the `_record_to_dict` shape: a JSON
   array, or an object with a `records` array).
5. `verify --root <root> --results <file> --mode enforced --guard-records <file>`.

The confined `run` resolves no paths. It checks the root with one `lstat` per component,
checks the fixture with `lstat` (and `readlink` only inside the workspace), and uses the
executable path it was started with.

**Startup reads (R3 item).** Before any probe, every `r3-probes` process (the run and
each `sub-probe` child) reads files outside the workspace. Observed so far:

- `~/.CFUserTextEncoding`
- the `.build` Products directory and an `Info.plist` next to the binary
- `/dev/autofs_nowait`
- `/Library/Preferences/Logging/com.apple.diagnosticd.filter.plist`

Under the contract these are about 15 `file [read] outside_workspace` denials. R3 must
decide whether the contract gets exact read rules for them or the run tolerates the
denials, and must confirm that the binary starts at all (dyld, the shared cache).
`otool -L` shows only `/usr/lib` and `/System/Library` dependencies today. The same kind
of reads happen at exit (result encoding, logging preferences). `verify` does not count
any of them as probe evidence: see the marker windows below.

## Fixture

`setup` creates, inside the root:

- `projectA/` (the workspace), containing:
  - `src/`, `tests/`, `ipc/`, `README.md`, `.env`, `private/secret.txt` and
    `privé/note.txt` (NFC)
  - `bin/allowed-tool` and `bin/denied-tool` (copies of `/usr/bin/true`, a signed
    Mach-O) and `bin/script-tool` (a `#!/bin/sh` script)
  - in `src/`: a symlink to the outside victim, a directory symlink to `outside/`, and a
    hardlink to the victim. All three are made at setup, before any session exists.
- `projectB/notes.txt`
- `outside/`: the victim, a symlink to it, a Mach-O copy for the `PROT_EXEC` mapping, a
  file with an extended attribute, and files that the write, rename, swap, truncate and
  unlink probes use
- `external/`: `granted.txt`, `.env`, `denied/secret.txt` and `runtime-tool` (Mach-O),
  for the schema-2 probes
- `projectA/src/.marks/<probe id>` and `<probe id>.end`: start and end marker files per
  probe (see `verify` below)

All file contents are fixed synthetic text or the copied `/usr/bin/true`. `fd-server`
creates `projectA/ipc/fd.sock` (it hands out descriptors) and `outside/listen.sock` (it
listens there but never accepts).

`r3-fixture.json` records the root, a task ID unique to this setup
(`r3-probes-project-a-` plus 64 random bits in hex), whether the volume is case-sensitive,
the entries, aliases and the policy relative to the root. The aliases are
`projectA/PRIVATE` (case) and `projectA/prive` + U+0301 (NFD). Neither is created; they
resolve only through the volume's case and normalization insensitivity.

A run consumes the fixture: a second `run` on the same root is refused.

## Contract

`contract` emits a schema-2 contract ([task policy](../../../docs/design/task-policy.md),
"Schema 2: external rules") with the manifest's task ID:

- `allow`: read on the `projectA` tree; write on `src`, `tests` and `ipc`; execute on
  `bin/allowed-tool` only.
- `deny`: `projectA/private`, `projectA/privé` and `external/denied`.
- `external`: exact read+execute on the resolved probe binary and on `/bin/sh` (the
  script probe's interpreter, so that probe can only be denied by the script's own
  missing execute rule); read+execute trees `/usr/lib`, `/System/Library` and
  `/System/Volumes/Preboot/Cryptexes/OS` (dyld shared cache); read on `external/`.

`contract` refuses an external rule that is `/` or not canonical, that lies in or above
`/System/Volumes/Data` (an alias of every user path, so `/System` itself is refused),
that lies inside the root other than under `external/`, or a tree rule covering the root,
`outside/` or `projectB/`. It also refuses a probe binary inside the root. The
lifetime is a placeholder the R3 launcher must replace.

## Expectations

Rows describe what one supervised session can show. They map to the acceptance table in
AGENTBELT-ENGINE-ROADMAP.md, section 5, only as far as their labels say:

- `project-b-paths`: one project-A session is denied project-B paths (no A/B cache-leak test)
- `exec-children`: exec, spawned and forked children (no reparenting or PID reuse)
- `path-aliases`: symlink, hardlink, rename/swap, clone/copy, case and NFD aliases (no replacement races)
- `descriptors`: inherited and SCM_RIGHTS descriptors, mmap, unix sockets (no XPC or other IPC proxies)
- `file-scope`: file operations inside and outside the workspace (part of the R3 exit condition)
- `external-rules`: schema-2 external-rule semantics (not a roadmap row)

In baseline mode, every probe must succeed. The alias probes may instead be *n/a* only
when the run reports a case-sensitive volume, and `outside.acl-set` only when the volume
rejects ACLs. The enforced column states what R3 must observe; the guard record is the
denial record `verify` requires. These are requirements to measure, not verified
properties.

| Probe | Row | Enforced | Guard record | Rationale |
| --- | --- | --- | --- | --- |
| `workspace.read` | file-scope | allowed | - | read is allowed on the projectA tree |
| `workspace.write` | file-scope | allowed | - | write is allowed on projectA/src |
| `workspace.create` | file-scope | allowed | - | O_CREAT inside projectA/src is a write the contract allows |
| `workspace.write-readonly` | file-scope | denied | `file [write] README.md` | projectA root is read-only; read does not imply write |
| `workspace.create-readonly` | file-scope | denied | `file [write] probe-created.txt` | O_CREAT outside the write subtrees but inside the workspace |
| `workspace.read-deny-rule` | file-scope | denied | `file [read] withheld` | explicit deny on projectA/private wins over the tree read allow |
| `workspace.read-dotenv` | file-scope | denied | `file [read] withheld` | .env is a sensitive name; R1 denies it even under an allow rule |
| `alias.case-variant` | path-aliases | denied | `file [read] withheld` | PRIVATE resolves to the private deny directory on case-insensitive APFS (R2 assumption 7) |
| `alias.nfd-variant` | path-aliases | denied | `file [read] withheld` | NFD spelling of the NFC deny directory; R1 does no normalization, so the adapter must |
| `projectB.read` | project-b-paths | denied | `file [read] outside_workspace` | another project is outside the task workspace |
| `projectB.create` | project-b-paths | denied | `file [write] outside_workspace` | no write grant exists outside the workspace |
| `outside.read` | file-scope | denied | `file [read] outside_workspace` | direct open of a file outside every allow rule |
| `outside.open-rdwr` | file-scope | denied | `file [read,write] outside_workspace` | O_RDWR is FREAD\|FWRITE: AUTH_OPEN read and write |
| `outside.open-trunc` | file-scope | denied | `file [write] outside_workspace` | O_WRONLY\|O_TRUNC is FWRITE: AUTH_OPEN write |
| `outside.readdir` | file-scope | denied | `file [read] outside_workspace` | listing a directory outside the workspace: AUTH_OPEN or AUTH_READDIR read |
| `outside.readlink` | file-scope | denied | `file [read] outside_workspace` | AUTH_READLINK read on a symlink outside the workspace |
| `outside.getattrlist` | file-scope | denied | `file [read] outside_workspace` | AUTH_GETATTRLIST read outside the workspace |
| `outside.getxattr` | file-scope | denied | `file [read] outside_workspace` | AUTH_GETEXTATTR read (planned subscription) |
| `outside.listxattr` | file-scope | denied | `file [read] outside_workspace` | AUTH_LISTEXTATTR read (planned subscription) |
| `link.symlink-read` | path-aliases | denied | `file [read] outside_workspace` | the opened object is the outside victim; AUTH_OPEN is expected to carry the resolved path |
| `link.dir-symlink-read` | path-aliases | denied | `file [read] outside_workspace` | a directory symlink inside the workspace resolves outside it |
| `link.preexisting-hardlink-read` | path-aliases | expected_gap | - | known gap: the event path is the workspace name and object identity (nlink>1) is not implemented |
| `exec.allowed` | exec-children | allowed | - | bin/allowed-tool (a Mach-O copy of /usr/bin/true) has an exact execute rule |
| `exec.not-allowed` | exec-children | denied | `exec [execute] bin/denied-tool` | bin/denied-tool (Mach-O) is readable but has no execute rule |
| `exec.script-not-allowed` | exec-children | denied | `exec [execute] bin/script-tool` | a #! script: /bin/sh has execute, the script path has none (planned script execute check) |
| `child.read-workspace` | exec-children | allowed | - | a spawned child inherits the task binding and its allows |
| `child.read-outside` | exec-children | denied | `file [read] outside_workspace` | a spawned child inherits the binding; its own open is still mediated |
| `fork.read-outside` | exec-children | denied | `file [read] outside_workspace` | a forked child without exec shares the binding; its open is mediated |
| `external.read` | external-rules | allowed | - | the external/ tree rule grants read |
| `external.write` | external-rules | denied | `file [write] outside_workspace` | an external rule grants only its listed operations (read, not write) |
| `external.read-sensitive` | external-rules | denied | `file [read] withheld` | a sensitive name beats an external rule |
| `external.read-deny-rule` | external-rules | denied | `file [read] withheld` | an explicit deny beats an external rule |
| `external.exec-runtime` | external-rules | denied | `exec [execute] outside_workspace` | a runtime outside the workspace with read but no execute rule cannot be executed |
| `ipc.connect-outside` | descriptors | denied | `file [write] outside_workspace` | AUTH_UIPC_CONNECT is a write on a socket path outside the project (planned subscription) |
| `fd.inherited-read` | descriptors | not_mediated_by_ES | - | reads on a descriptor opened before binding raise no AUTH_OPEN; the gated launch closes fds >= 3 (EBADF at fstat) |
| `mmap.outside-open` | descriptors | denied | `file [read] outside_workspace` | a descriptor opened after launch: the open is denied before any mmap |
| `fd.scm-rights-read` | descriptors | not_mediated_by_ES | - | an unconfined helper opened it and passed it over projectA/ipc; reads raise no AUTH event |
| `fd.scm-rights-mmap` | descriptors | measured | - | residual measurement: AUTH_MMAP names the file even for a received descriptor |
| `mmap.received-exec` | descriptors | denied | `file [execute,read] outside_workspace` | AUTH_MMAP with PROT_EXEC adds execute on an outside file |
| `mmap.received-shared-write` | descriptors | denied | `file [read,write] outside_workspace` | AUTH_MMAP with PROT_WRITE and MAP_SHARED adds write on an outside file |
| `outside.chmod` | file-scope | denied | `file [write] outside_workspace` | AUTH_SETMODE write outside the workspace |
| `outside.chflags` | file-scope | denied | `file [write] outside_workspace` | AUTH_SETFLAGS write outside the workspace |
| `outside.acl-set` | file-scope | denied | `file [write] outside_workspace` | AUTH_SETACL write outside the workspace |
| `outside.utimes` | file-scope | denied | `file [write] outside_workspace` | AUTH_UTIMES (or AUTH_SETATTRLIST) write outside the workspace |
| `outside.setxattr` | file-scope | denied | `file [write] outside_workspace` | AUTH_SETEXTATTR write outside the workspace |
| `outside.removexattr` | file-scope | denied | `file [write] outside_workspace` | AUTH_DELETEEXTATTR write outside the workspace |
| `link.create-hardlink` | path-aliases | denied | `file [write] outside_workspace` | AUTH_LINK source is outside the workspace; a new name would launder it inside |
| `rename.outside-to-workspace` | path-aliases | denied | `file [write] outside_workspace` | AUTH_RENAME source lies outside the write scope |
| `rename.workspace-to-outside` | path-aliases | denied | `file [write] outside_workspace` | AUTH_RENAME destination lies outside the write scope |
| `rename.swap` | path-aliases | denied | `file [write] outside_workspace` | renamex_np(RENAME_SWAP) exchanges a workspace file with an outside one |
| `clone.outside-to-workspace` | path-aliases | denied | `file [read] outside_workspace` | AUTH_CLONE source is outside every read allow |
| `copyfile.outside-to-workspace` | path-aliases | denied | `file [read] outside_workspace` | copyfile(3) opens the outside source for reading (AUTH_OPEN) |
| `outside.create` | file-scope | denied | `file [write] outside_workspace` | AUTH_CREATE outside the workspace |
| `outside.truncate` | file-scope | denied | `file [write] outside_workspace` | open(O_NOFOLLOW) for write, then ftruncate: AUTH_OPEN or AUTH_TRUNCATE write |
| `outside.unlink` | file-scope | denied | `file [write] outside_workspace` | AUTH_UNLINK outside the workspace |
| `outside.mkdir` | file-scope | denied | `file [write] outside_workspace` | AUTH_CREATE of a directory outside the workspace |

`verify --mode enforced` applies these rules:

- `--guard-records` is required. Without it, `verify` refuses to run.
- The results root must equal the root given with `--root` and the one in its manifest,
  and the volume case sensitivity must match.
- *allowed* must succeed.
- *denied* must fail with `EPERM` at the probe's own operation step (for example `open`
  for a read, `mmap` for a mapping, `spawn` only for exec probes). `EACCES`, `ENOENT`, or
  an `EPERM` at another step (a helper connect, a child spawn) is a mismatch.
- A *denied* probe also needs a guard record with `allowed: false`, the manifest's task
  ID, and the listed event, operations and target, inside the probe's own window. Right
  before each probe, the runner opens its start marker `src/.marks/<probe id>`, and right
  after the probe's own operation, before any JSON or Foundation work, its end marker
  `src/.marks/<probe id>.end`. Both are allowed reads that leave `file [read]` records.
  The window runs, by `sequence`, from the probe's last start marker record to its first
  end marker record after that. A child probe's `sub-probe` opens both markers itself,
  after its startup and before it encodes its result and exits. Startup and exit reads,
  other probes' records and records of another run's task ID therefore never count. A
  probe without both marker records fails. A record stream with a gap in `sequence`
  (lost records) is refused as a whole, since a lost marker could widen a window.
- *not_mediated_by_ES* and *measured* pass either way. A success is printed as
  `RESIDUAL`; a failure is printed with its errno and step. For `fd.inherited-read`,
  `EBADF` at `fstat` is printed as closed by the launcher, which closes fds >= 3.
- *expected_gap* passes either way; a success is printed as `KNOWN GAP`.
- *unavailable*, *failed*, missing, duplicate and unknown results always fail.

Assumptions about the planned guard: the script probe's record names the script
(`bin/script-tool`), and `AUTH_UIPC_CONNECT`, `AUTH_GETEXTATTR` and `AUTH_LISTEXTATTR`
are recorded as `file` events. Adjust `Catalog.swift` if the guard records them
differently.

## Safety

- **Root location.** `setup` resolves the root (`realpath`), which must lie strictly
  inside `/private/tmp`, `/private/var/folders` or `/tmp`. Later commands take the
  canonical spelling setup prints and refuse any symlinked, empty, `.` or `..` component.
- **Root state.** `setup` accepts only a new, or an empty and private, directory. Later
  commands require a directory owned by the user that group and others cannot write.
- **Output files.** `--json` files must also be in those temporary areas.
- **No root.** The tool refuses to run as root.
- **Fixture integrity.** Before probing, every fixture entry is checked with `lstat`.
  Workspace symlink targets must match exactly, so a replaced link cannot lead a probe
  out of the root. Truncation uses `open(O_NOFOLLOW)` and `ftruncate`.
- **Descriptors.** An inherited or received descriptor is used only if it is the expected
  fixture file's inode.
- **Output.** Results carry byte counts, errno names and steps, never file contents.
  `verify` escapes control and bidirectional characters from results files.
- **Children.** Spawned children get an empty environment and only fds 0–2. The forked
  child only opens, reads and reports.

## Not covered

`verify` prints these roadmap rows after every table:

- Forged task ID, environment or MCP description (R1-R3)
- Reparenting and PID reuse (R2-R3)
- Task end, grant expiry, revoke and policy revision change, including the two-phase revision switch (R1-R4)
- Same binary in two concurrently supervised sessions: no allow result or cache leaks from A to B (R1, R3)
- Unrelated process and ordinary terminal with the guard active: not blocked by task policy (R3-R4)
- Guard or supervisor delay, kill, restart and overload: measured, loss of protection never shown as success (R3, R5)
- File replacement races (TOCTOU) on the path-alias probes (R3)
- Visible GUI, helpers and Chromium sandbox; extra approvals and retries; action records under load (R4-R5)

Also not covered: object identity for pre-existing hardlinks (`expected_gap`), IPC proxies
other than one SCM_RIGHTS helper (XPC, LaunchServices), and network, clipboard and GUI
channels.
