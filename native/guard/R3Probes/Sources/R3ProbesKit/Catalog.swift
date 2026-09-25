import Foundation

/// What the probes provide evidence for. Labels name only what one supervised session
/// can show; the roadmap rows these probes do not reach are in `Catalog.uncoveredRows`.
public enum AcceptanceRow: String, Codable, CaseIterable {
    case projectBPaths = "project-b-paths"
    case execChildren = "exec-children"
    case pathAliases = "path-aliases"
    case descriptors
    case fileScope = "file-scope"
    case externalRules = "external-rules"

    public var title: String {
        switch self {
        case .projectBPaths:
            return "One project-A session is denied project-B paths (no A/B cache-leak test)"
        case .execChildren:
            return "Exec, spawned and forked children (no reparenting or PID reuse)"
        case .pathAliases:
            return "Symlink, hardlink, rename/swap, clone/copy, case and NFD aliases (no replacement races)"
        case .descriptors:
            return "Inherited and SCM_RIGHTS descriptors, mmap, unix sockets (no XPC or other IPC proxies)"
        case .fileScope:
            return "File operations inside and outside the workspace (part of the R3 exit condition)"
        case .externalRules:
            return "Schema-2 external rules (contract semantics, not a roadmap row)"
        }
    }
}

/// What R3 must observe for a probe once File Guard enforces the fixture contract.
public enum EnforcedExpectation: String, Codable {
    case allowed
    /// EPERM at the probe's own operation step, plus a matching guard denial record.
    case denied
    /// ES has no AUTH event for the access itself; the probe records whether the path is
    /// open (a residual bypass) or closed by something else.
    case notMediatedByES = "not_mediated_by_ES"
    /// A residual measurement: the outcome is recorded, not asserted.
    case measured
    /// A known gap in the planned guard: the outcome is recorded, and success is expected.
    case expectedGap = "expected_gap"
}

/// When an `n/a` result is acceptable.
public enum NotApplicableCondition: String, Codable {
    /// The alias resolves only on a case-insensitive volume, so `n/a` is accepted only
    /// when the run reports a case-sensitive one.
    case caseSensitiveVolume = "case_sensitive_volume"
    /// The volume rejects ACLs (ENOTSUP); unprivileged ACL changes are otherwise possible.
    case aclUnsupported = "acl_unsupported"
}

/// The guard action record (task_registry `_record_to_dict`) a denied probe must leave:
/// event kind, sorted operations and target (workspace-relative, `outside_workspace` or
/// `withheld` for sensitive names and explicit denials).
public struct GuardDenial: Codable, Equatable {
    public let event: String
    public let operations: [String]
    public let target: String

    public static let outside = "outside_workspace"
    public static let withheld = "withheld"

    public init(event: String, operations: [String], target: String) {
        self.event = event
        self.operations = operations.sorted()
        self.target = target
    }

    static func file(_ operations: [String], _ target: String) -> GuardDenial {
        GuardDenial(event: "file", operations: operations, target: target)
    }

    static func exec(_ target: String) -> GuardDenial {
        GuardDenial(event: "exec", operations: ["execute"], target: target)
    }

    var summary: String { "\(event) [\(operations.joined(separator: ","))] \(target)" }
}

/// Descriptors the unconfined fd-server hands out, by request byte.
enum HelperRequest: Character {
    /// The victim, opened read-only.
    case victim = "R"
    /// `outside/mmap-shared.txt`, opened read-write.
    case sharedMap = "W"
    /// `outside/map-exec-tool`, a Mach-O, opened read-only.
    case executableMap = "X"

    var fixturePath: String {
        switch self {
        case .victim: return FixturePath.victim
        case .sharedMap: return FixturePath.sharedMapTarget
        case .executableMap: return FixturePath.executableMapTarget
        }
    }
}

/// How a received descriptor is used.
enum ReceivedUse {
    case read
    /// r3_mmap_fd mode: 0 read-only private, 1 shared writable, 2 executable page.
    case map(Int32)
}

enum OpenMode {
    case readWrite
    case writeTruncate
}

/// The operation a probe performs. Paths are fixture-relative.
enum ProbeAction {
    case read(String, followSymlink: Bool)
    case append(String)
    case create(String)
    case open(String, OpenMode)
    case makeDirectory(String)
    case truncate(String)
    case unlink(String)
    case hardlink(from: String, to: String)
    case rename(from: String, to: String)
    case swap(String, String)
    case clone(from: String, to: String)
    case copyData(from: String, to: String)
    case changeMode(String)
    case changeFlags(String)
    case setACL(String)
    case setTimes(String)
    case setXattr(String)
    case removeXattr(String)
    case getXattr(String)
    case listXattr(String)
    case readDirectory(String)
    case readLink(String)
    case getAttributes(String)
    case openAndMap(String)
    case exec(String)
    case inheritedRead
    case received(HelperRequest, ReceivedUse)
    case connect(String)
    /// Runs another (non-child) probe in a spawned copy of this binary.
    case child(String)
    /// fork() without exec; the child reads the file.
    case forkRead(String)

    /// Steps at which an ES denial of this probe's own operation surfaces. A denial at
    /// any other step (spawning a helper child, connecting to the fd-server) does not
    /// count as this probe being denied.
    var denialSteps: Set<String> {
        switch self {
        case .read, .append, .create, .open, .forkRead: return ["open"]
        case .makeDirectory: return ["mkdir"]
        case .truncate: return ["open", "ftruncate"]
        case .unlink: return ["unlink"]
        case .hardlink: return ["link"]
        case .rename: return ["rename"]
        case .swap: return ["renamex_np"]
        case .clone: return ["clonefile"]
        case .copyData: return ["copyfile"]
        case .changeMode: return ["chmod"]
        case .changeFlags: return ["chflags"]
        case .setACL: return ["acl_set"]
        case .setTimes: return ["utimensat"]
        case .setXattr: return ["setxattr"]
        case .removeXattr: return ["removexattr"]
        case .getXattr: return ["getxattr"]
        case .listXattr: return ["listxattr"]
        case .readDirectory: return ["open", "readdir"]
        case .readLink: return ["readlink"]
        case .getAttributes: return ["getattrlist"]
        case .openAndMap: return ["open", "mmap"]
        case .exec: return ["spawn"]
        case .inheritedRead: return []
        case .received(_, .read): return ["read"]
        case .received(_, .map): return ["mmap"]
        case .connect: return ["connect"]
        case let .child(target): return Catalog.spec(target)?.action.denialSteps ?? []
        }
    }

    var helperRequest: HelperRequest? {
        if case let .received(request, _) = self { return request }
        return nil
    }
}

public struct ProbeSpec {
    public let id: String
    public let row: AcceptanceRow
    public let expected: EnforcedExpectation
    public let rationale: String
    public let notApplicable: NotApplicableCondition?
    /// Required for `denied`: the guard record that must accompany the EPERM.
    public let guardDenial: GuardDenial?
    let action: ProbeAction

    init(_ id: String, _ row: AcceptanceRow, _ expected: EnforcedExpectation, _ action: ProbeAction,
         _ rationale: String, record guardDenial: GuardDenial? = nil, notApplicable: NotApplicableCondition? = nil) {
        self.id = id
        self.row = row
        self.expected = expected
        self.action = action
        self.rationale = rationale
        self.guardDenial = guardDenial
        self.notApplicable = notApplicable
    }

    public var denialSteps: Set<String> { action.denialSteps }

    /// The probe a child probe runs in a spawned copy of this binary.
    public var childTarget: String? {
        if case let .child(target) = action { return target }
        return nil
    }
}

/// The expectation table. Order is execution order: reads, executions and descriptor
/// probes first, then the probes that change or consume fixture entries. Baseline (no
/// enforcement) expects every probe to succeed, except where `notApplicable` allows n/a.
public enum Catalog {
    private static let outside = GuardDenial.outside
    private static let withheld = GuardDenial.withheld

    public static let probes: [ProbeSpec] = workspaceProbes + outsideReadProbes + processProbes
        + externalProbes + descriptorProbes + mutationProbes

    private static let workspaceProbes: [ProbeSpec] = [
        ProbeSpec("workspace.read", .fileScope, .allowed, .read(FixturePath.srcFile, followSymlink: false),
                  "read is allowed on the projectA tree"),
        ProbeSpec("workspace.write", .fileScope, .allowed, .append(FixturePath.srcFile),
                  "write is allowed on projectA/src"),
        ProbeSpec("workspace.create", .fileScope, .allowed, .create(FixturePath.workspaceCreated),
                  "O_CREAT inside projectA/src is a write the contract allows"),
        ProbeSpec("workspace.write-readonly", .fileScope, .denied, .append(FixturePath.readme),
                  "projectA root is read-only; read does not imply write", record: .file(["write"], "README.md")),
        ProbeSpec("workspace.create-readonly", .fileScope, .denied, .create(FixturePath.readOnlyCreated),
                  "O_CREAT outside the write subtrees but inside the workspace",
                  record: .file(["write"], "probe-created.txt")),
        ProbeSpec("workspace.read-deny-rule", .fileScope, .denied, .read(FixturePath.secret, followSymlink: false),
                  "explicit deny on projectA/private wins over the tree read allow", record: .file(["read"], withheld)),
        ProbeSpec("workspace.read-dotenv", .fileScope, .denied, .read(FixturePath.dotEnv, followSymlink: false),
                  ".env is a sensitive name; R1 denies it even under an allow rule", record: .file(["read"], withheld)),
        ProbeSpec("alias.case-variant", .pathAliases, .denied, .read(FixturePath.secretCaseVariant, followSymlink: false),
                  "PRIVATE resolves to the private deny directory on case-insensitive APFS (R2 assumption 7)",
                  record: .file(["read"], withheld), notApplicable: .caseSensitiveVolume),
        ProbeSpec("alias.nfd-variant", .pathAliases, .denied, .read(FixturePath.noteNFD, followSymlink: false),
                  "NFD spelling of the NFC deny directory; R1 does no normalization, so the adapter must",
                  record: .file(["read"], withheld), notApplicable: .caseSensitiveVolume),
    ]

    private static let outsideReadProbes: [ProbeSpec] = [
        ProbeSpec("projectB.read", .projectBPaths, .denied, .read(FixturePath.projectBFile, followSymlink: false),
                  "another project is outside the task workspace", record: .file(["read"], outside)),
        ProbeSpec("projectB.create", .projectBPaths, .denied, .create(FixturePath.projectBCreated),
                  "no write grant exists outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.read", .fileScope, .denied, .read(FixturePath.victim, followSymlink: false),
                  "direct open of a file outside every allow rule", record: .file(["read"], outside)),
        ProbeSpec("outside.open-rdwr", .fileScope, .denied, .open(FixturePath.readWriteTarget, .readWrite),
                  "O_RDWR is FREAD|FWRITE: AUTH_OPEN read and write", record: .file(["read", "write"], outside)),
        ProbeSpec("outside.open-trunc", .fileScope, .denied, .open(FixturePath.openTruncateTarget, .writeTruncate),
                  "O_WRONLY|O_TRUNC is FWRITE: AUTH_OPEN write", record: .file(["write"], outside)),
        ProbeSpec("outside.readdir", .fileScope, .denied, .readDirectory("outside"),
                  "listing a directory outside the workspace: AUTH_OPEN or AUTH_READDIR read",
                  record: .file(["read"], outside)),
        ProbeSpec("outside.readlink", .fileScope, .denied, .readLink(FixturePath.victimLink),
                  "AUTH_READLINK read on a symlink outside the workspace", record: .file(["read"], outside)),
        ProbeSpec("outside.getattrlist", .fileScope, .denied, .getAttributes(FixturePath.victim),
                  "AUTH_GETATTRLIST read outside the workspace", record: .file(["read"], outside)),
        ProbeSpec("outside.getxattr", .fileScope, .denied, .getXattr(FixturePath.attributesTarget),
                  "AUTH_GETEXTATTR read (planned subscription)", record: .file(["read"], outside)),
        ProbeSpec("outside.listxattr", .fileScope, .denied, .listXattr(FixturePath.attributesTarget),
                  "AUTH_LISTEXTATTR read (planned subscription)", record: .file(["read"], outside)),
        ProbeSpec("link.symlink-read", .pathAliases, .denied, .read(FixturePath.symlinkToVictim, followSymlink: true),
                  "the opened object is the outside victim; AUTH_OPEN is expected to carry the resolved path",
                  record: .file(["read"], outside)),
        ProbeSpec("link.dir-symlink-read", .pathAliases, .denied,
                  .read(FixturePath.directorySymlink + "/victim.txt", followSymlink: true),
                  "a directory symlink inside the workspace resolves outside it", record: .file(["read"], outside)),
        ProbeSpec("link.preexisting-hardlink-read", .pathAliases, .expectedGap,
                  .read(FixturePath.hardlinkToVictim, followSymlink: false),
                  "known gap: the event path is the workspace name and object identity (nlink>1) is not implemented"),
    ]

    private static let processProbes: [ProbeSpec] = [
        ProbeSpec("exec.allowed", .execChildren, .allowed, .exec(FixturePath.allowedTool),
                  "bin/allowed-tool (a Mach-O copy of /usr/bin/true) has an exact execute rule"),
        ProbeSpec("exec.not-allowed", .execChildren, .denied, .exec(FixturePath.deniedTool),
                  "bin/denied-tool (Mach-O) is readable but has no execute rule",
                  record: .exec("bin/denied-tool")),
        ProbeSpec("exec.script-not-allowed", .execChildren, .denied, .exec(FixturePath.scriptTool),
                  "a #! script: /bin/sh has execute, the script path has none (planned script execute check)",
                  record: .exec("bin/script-tool")),
        ProbeSpec("child.read-workspace", .execChildren, .allowed, .child("workspace.read"),
                  "a spawned child inherits the task binding and its allows"),
        ProbeSpec("child.read-outside", .execChildren, .denied, .child("outside.read"),
                  "a spawned child inherits the binding; its own open is still mediated",
                  record: .file(["read"], outside)),
        ProbeSpec("fork.read-outside", .execChildren, .denied, .forkRead(FixturePath.victim),
                  "a forked child without exec shares the binding; its open is mediated",
                  record: .file(["read"], outside)),
    ]

    private static let externalProbes: [ProbeSpec] = [
        ProbeSpec("external.read", .externalRules, .allowed, .read(FixturePath.externalFile, followSymlink: false),
                  "the external/ tree rule grants read"),
        ProbeSpec("external.write", .externalRules, .denied, .append(FixturePath.externalFile),
                  "an external rule grants only its listed operations (read, not write)",
                  record: .file(["write"], outside)),
        ProbeSpec("external.read-sensitive", .externalRules, .denied, .read(FixturePath.externalDotEnv, followSymlink: false),
                  "a sensitive name beats an external rule", record: .file(["read"], withheld)),
        ProbeSpec("external.read-deny-rule", .externalRules, .denied,
                  .read(FixturePath.externalSecret, followSymlink: false),
                  "an explicit deny beats an external rule", record: .file(["read"], withheld)),
        ProbeSpec("external.exec-runtime", .externalRules, .denied, .exec(FixturePath.externalTool),
                  "a runtime outside the workspace with read but no execute rule cannot be executed",
                  record: .exec(outside)),
    ]

    private static let descriptorProbes: [ProbeSpec] = [
        ProbeSpec("ipc.connect-outside", .descriptors, .denied, .connect(FixturePath.outsideSocket),
                  "AUTH_UIPC_CONNECT is a write on a socket path outside the project (planned subscription)",
                  record: .file(["write"], outside)),
        ProbeSpec("fd.inherited-read", .descriptors, .notMediatedByES, .inheritedRead,
                  "reads on a descriptor opened before binding raise no AUTH_OPEN; the gated launch closes fds >= 3 (EBADF at fstat)"),
        ProbeSpec("mmap.outside-open", .descriptors, .denied, .openAndMap(FixturePath.victim),
                  "a descriptor opened after launch: the open is denied before any mmap",
                  record: .file(["read"], outside)),
        ProbeSpec("fd.scm-rights-read", .descriptors, .notMediatedByES, .received(.victim, .read),
                  "an unconfined helper opened it and passed it over projectA/ipc; reads raise no AUTH event"),
        ProbeSpec("fd.scm-rights-mmap", .descriptors, .measured, .received(.victim, .map(0)),
                  "residual measurement: AUTH_MMAP names the file even for a received descriptor"),
        ProbeSpec("mmap.received-exec", .descriptors, .denied, .received(.executableMap, .map(2)),
                  "AUTH_MMAP with PROT_EXEC adds execute on an outside file", record: .file(["execute", "read"], outside)),
        ProbeSpec("mmap.received-shared-write", .descriptors, .denied, .received(.sharedMap, .map(1)),
                  "AUTH_MMAP with PROT_WRITE and MAP_SHARED adds write on an outside file",
                  record: .file(["read", "write"], outside)),
    ]

    private static let mutationProbes: [ProbeSpec] = [
        ProbeSpec("outside.chmod", .fileScope, .denied, .changeMode(FixturePath.attributesTarget),
                  "AUTH_SETMODE write outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.chflags", .fileScope, .denied, .changeFlags(FixturePath.attributesTarget),
                  "AUTH_SETFLAGS write outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.acl-set", .fileScope, .denied, .setACL(FixturePath.attributesTarget),
                  "AUTH_SETACL write outside the workspace", record: .file(["write"], outside),
                  notApplicable: .aclUnsupported),
        ProbeSpec("outside.utimes", .fileScope, .denied, .setTimes(FixturePath.attributesTarget),
                  "AUTH_UTIMES (or AUTH_SETATTRLIST) write outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.setxattr", .fileScope, .denied, .setXattr(FixturePath.attributesTarget),
                  "AUTH_SETEXTATTR write outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.removexattr", .fileScope, .denied, .removeXattr(FixturePath.attributesTarget),
                  "AUTH_DELETEEXTATTR write outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("link.create-hardlink", .pathAliases, .denied,
                  .hardlink(from: FixturePath.victim, to: FixturePath.newHardlink),
                  "AUTH_LINK source is outside the workspace; a new name would launder it inside",
                  record: .file(["write"], outside)),
        ProbeSpec("rename.outside-to-workspace", .pathAliases, .denied,
                  .rename(from: FixturePath.moveInSource, to: FixturePath.movedIn),
                  "AUTH_RENAME source lies outside the write scope", record: .file(["write"], outside)),
        ProbeSpec("rename.workspace-to-outside", .pathAliases, .denied,
                  .rename(from: FixturePath.moveOutSource, to: FixturePath.movedOut),
                  "AUTH_RENAME destination lies outside the write scope", record: .file(["write"], outside)),
        ProbeSpec("rename.swap", .pathAliases, .denied, .swap(FixturePath.swapInside, FixturePath.swapOutside),
                  "renamex_np(RENAME_SWAP) exchanges a workspace file with an outside one",
                  record: .file(["write"], outside)),
        ProbeSpec("clone.outside-to-workspace", .pathAliases, .denied,
                  .clone(from: FixturePath.victim, to: FixturePath.cloneDestination),
                  "AUTH_CLONE source is outside every read allow", record: .file(["read"], outside)),
        ProbeSpec("copyfile.outside-to-workspace", .pathAliases, .denied,
                  .copyData(from: FixturePath.victim, to: FixturePath.copyDestination),
                  "copyfile(3) opens the outside source for reading (AUTH_OPEN)", record: .file(["read"], outside)),
        ProbeSpec("outside.create", .fileScope, .denied, .create(FixturePath.outsideCreated),
                  "AUTH_CREATE outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.truncate", .fileScope, .denied, .truncate(FixturePath.truncateTarget),
                  "open(O_NOFOLLOW) for write, then ftruncate: AUTH_OPEN or AUTH_TRUNCATE write",
                  record: .file(["write"], outside)),
        ProbeSpec("outside.unlink", .fileScope, .denied, .unlink(FixturePath.unlinkTarget),
                  "AUTH_UNLINK outside the workspace", record: .file(["write"], outside)),
        ProbeSpec("outside.mkdir", .fileScope, .denied, .makeDirectory(FixturePath.outsideDirectory),
                  "AUTH_CREATE of a directory outside the workspace", record: .file(["write"], outside)),
    ]

    public static func spec(_ id: String) -> ProbeSpec? { probes.first { $0.id == id } }

    /// fd-server connections one run makes.
    public static var helperConnections: Int { probes.filter { $0.action.helperRequest != nil }.count }

    /// Rows of the acceptance table (AGENTBELT-ENGINE-ROADMAP.md, section 5) that these
    /// probes do not cover. `verify` prints them so a passing run is not read as more.
    public static let uncoveredRows = [
        "Forged task ID, environment or MCP description (R1-R3)",
        "Reparenting and PID reuse (R2-R3)",
        "Task end, grant expiry, revoke and policy revision change, including the two-phase revision switch (R1-R4)",
        "Same binary in two concurrently supervised sessions: no allow result or cache leaks from A to B (R1, R3)",
        "Unrelated process and ordinary terminal with the guard active: not blocked by task policy (R3-R4)",
        "Guard or supervisor delay, kill, restart and overload: measured, loss of protection never shown as success (R3, R5)",
        "File replacement races (TOCTOU) on the path-alias probes (R3)",
        "Visible GUI, helpers and Chromium sandbox; extra approvals and retries; action records under load (R4-R5)",
    ]
}

/// The expectation table as data, for `r3-probes expectations --json`.
public struct ExpectationRecord: Codable, Equatable {
    public let id: String
    public let row: String
    public let baseline: String
    public let expectedWhenEnforced: String
    public let guardDenial: GuardDenial?
    public let denialSteps: [String]
    public let rationale: String
}

extension Catalog {
    public static var expectationTable: [ExpectationRecord] {
        probes.map {
            ExpectationRecord(id: $0.id, row: $0.row.rawValue,
                              baseline: $0.notApplicable.map { "success_or_n/a_if_\($0.rawValue)" } ?? "success",
                              expectedWhenEnforced: $0.expected.rawValue, guardDenial: $0.guardDenial,
                              denialSteps: $0.expected == .denied ? $0.denialSteps.sorted() : [],
                              rationale: $0.rationale)
        }
    }

    public static func expectationJSON() throws -> Data {
        try JSONCoding.encoder.encode(expectationTable)
    }
}
