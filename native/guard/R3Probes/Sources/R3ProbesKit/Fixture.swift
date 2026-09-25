import Darwin
import Foundation

/// Fixture paths, relative to the root. Setup and the probes share these constants, so
/// the confined `run` never has to read the manifest, which lies outside its workspace.
public enum FixturePath {
    public static let workspace = "projectA"
    static let src = "projectA/src"
    static let tests = "projectA/tests"
    static let bin = "projectA/bin"
    /// Holds the fd-server socket; the contract grants write here so the probes can reach
    /// the helper (AUTH_UIPC_CONNECT is a write on the socket path).
    static let ipc = "projectA/ipc"
    static let deniedDirectory = "projectA/private"
    /// A deny-rule directory whose name is not ASCII, spelled in NFC in the contract.
    static let deniedDirectoryNFC = "projectA/priv\u{00E9}"
    /// Outside the workspace, covered by a schema-2 `external` read rule.
    static let external = "external"
    static let externalDenied = "external/denied"

    static let srcFile = "projectA/src/main.txt"
    static let testsFile = "projectA/tests/test_main.txt"
    static let readme = "projectA/README.md"
    static let secret = "projectA/private/secret.txt"
    static let noteNFC = "projectA/priv\u{00E9}/note.txt"
    static let dotEnv = "projectA/.env"
    /// Mach-O copies of /usr/bin/true.
    static let allowedTool = "projectA/bin/allowed-tool"
    static let deniedTool = "projectA/bin/denied-tool"
    /// A `#!/bin/sh` script with no execute rule.
    static let scriptTool = "projectA/bin/script-tool"
    static let symlinkToVictim = "projectA/src/victim-symlink.txt"
    static let symlinkToVictimTarget = "../../outside/victim.txt"
    static let directorySymlink = "projectA/src/outside-dir"
    static let directorySymlinkTarget = "../../outside"
    static let hardlinkToVictim = "projectA/src/victim-hardlink.txt"
    static let moveOutSource = "projectA/src/move-out.txt"
    static let swapInside = "projectA/src/swap.txt"
    static let socket = "projectA/ipc/fd.sock"
    static let projectBFile = "projectB/notes.txt"
    static let victim = "outside/victim.txt"
    static let victimLink = "outside/victim-link"
    static let victimLinkTarget = "victim.txt"
    static let readWriteTarget = "outside/rw.txt"
    static let openTruncateTarget = "outside/trunc-open.txt"
    static let attributesTarget = "outside/attrs.txt"
    static let swapOutside = "outside/swap.txt"
    static let sharedMapTarget = "outside/mmap-shared.txt"
    static let executableMapTarget = "outside/map-exec-tool"
    static let moveInSource = "outside/move-in.txt"
    static let truncateTarget = "outside/truncate-me.txt"
    static let unlinkTarget = "outside/unlink-me.txt"
    /// Listened on by fd-server but never accepted: a connect target outside the project.
    static let outsideSocket = "outside/listen.sock"
    static let externalFile = "external/granted.txt"
    static let externalDotEnv = "external/.env"
    static let externalSecret = "external/denied/secret.txt"
    static let externalTool = "external/runtime-tool"
    /// One marker file per probe. The runner opens `<markers>/<probe id>` (an allowed
    /// read) right before each probe, so the guard's records show where each probe starts.
    static let markers = "projectA/src/.marks"

    /// Suffix of the end marker, opened right after the probe's own operation.
    static let endSuffix = ".end"

    static func marker(_ probeId: String, end: Bool = false) -> String {
        markers + "/" + probeId + (end ? endSuffix : "")
    }
    /// The marker as a guard record target (workspace-relative).
    static func markerTarget(_ probeId: String, end: Bool = false) -> String {
        String(marker(probeId, end: end).dropFirst(workspace.count + 1))
    }

    /// Spellings the probes use but setup never creates.
    static let secretCaseVariant = "projectA/PRIVATE/secret.txt"
    static let noteNFD = "projectA/prive\u{0301}/note.txt"

    /// Created by probes. `workspaceCreated` doubles as the "fixture already used" marker,
    /// because it is created by an allowed probe in every mode.
    static let workspaceCreated = "projectA/src/probe-created.txt"
    static let readOnlyCreated = "projectA/probe-created.txt"
    static let projectBCreated = "projectB/probe-created.txt"
    static let outsideCreated = "outside/probe-created.txt"
    static let outsideDirectory = "outside/probe-mkdir"
    static let newHardlink = "projectA/src/probe-hardlink.txt"
    static let movedIn = "projectA/src/moved-in.txt"
    static let movedOut = "outside/moved-out.txt"
    static let cloneDestination = "projectA/src/probe-clone.txt"
    static let copyDestination = "projectA/src/probe-copy.txt"

    /// The extended attribute setup puts on `attributesTarget`, and the one a probe adds.
    static let existingAttribute = "com.agentbelt.r3-probe"
    static let newAttribute = "com.agentbelt.r3-probe.added"
}

public struct FixtureEntry: Codable, Equatable {
    public enum Kind: String, Codable {
        case directory, file, symlink, hardlink
        /// `#!/bin/sh` script.
        case script
        /// Copy of /usr/bin/true (a signed Mach-O executable).
        case machO = "mach_o"
    }
    public var path: String
    public var kind: Kind
    /// Symlink target as stored, or the path a hardlink shares its inode with.
    public var target: String?
    /// True when a probe renames or unlinks it, so it only exists before a run.
    public var consumedByRun: Bool
}

/// Names the probes use that resolve to an existing entry only through case folding or
/// Unicode normalization.
public struct FixtureAlias: Codable, Equatable {
    public var spelling: String
    public var aliasOf: String
    public var kind: String
}

public struct PolicyRule: Codable, Equatable {
    public var path: String
    public var scope: String
    public var operations: [String]
}

public struct FixtureManifest: Codable, Equatable {
    public var harness = RunReport.harnessName
    public var fixtureVersion = 2
    /// The resolved root setup created; `verify` refuses results from any other root.
    public var root: String
    /// Unique per setup, so guard records of another run or fixture never match.
    public var taskId: String
    public var workspace = FixturePath.workspace
    public var volumeCaseSensitive: Bool
    public var entries: [FixtureEntry]
    public var aliases: [FixtureAlias]
    /// The intended task policy, relative to the root. `r3-probes contract` emits it as a
    /// schema-2 contract with absolute paths.
    public var allow: [PolicyRule]
    public var deny: [PolicyRule]

    public static func decode(_ data: Data) throws -> FixtureManifest {
        let manifest = try JSONCoding.decoder.decode(FixtureManifest.self, from: data)
        guard manifest.harness == RunReport.harnessName, manifest.fixtureVersion == 2 else {
            throw HarnessError("not an \(RunReport.harnessName) v2 fixture manifest; run setup again")
        }
        return manifest
    }
}

public enum Fixture {
    public static let manifestName = "r3-fixture.json"
    public static let taskIdPrefix = "r3-probes-project-a-"

    /// A fresh task ID: the prefix plus 64 random bits in hex. Fits task_policy's
    /// identifier rule.
    public static func newTaskId() -> String {
        var generator = SystemRandomNumberGenerator()
        return taskIdPrefix + String(format: "%016llx", generator.next() as UInt64)
    }
    /// Source of the Mach-O fixture executables. Setup reads it; nothing writes to it.
    static let machOSource = "/usr/bin/true"

    static let entries: [FixtureEntry] = {
        func entry(_ path: String, _ kind: FixtureEntry.Kind, _ target: String? = nil, consumed: Bool = false) -> FixtureEntry {
            FixtureEntry(path: path, kind: kind, target: target, consumedByRun: consumed)
        }
        return [
            entry("projectA", .directory), entry(FixturePath.src, .directory), entry(FixturePath.tests, .directory),
            entry(FixturePath.bin, .directory), entry(FixturePath.ipc, .directory),
            entry(FixturePath.deniedDirectory, .directory), entry(FixturePath.deniedDirectoryNFC, .directory),
            entry("projectB", .directory), entry("outside", .directory),
            entry(FixturePath.external, .directory), entry(FixturePath.externalDenied, .directory),
            entry(FixturePath.srcFile, .file), entry(FixturePath.testsFile, .file), entry(FixturePath.readme, .file),
            entry(FixturePath.secret, .file), entry(FixturePath.noteNFC, .file), entry(FixturePath.dotEnv, .file),
            entry(FixturePath.allowedTool, .machO), entry(FixturePath.deniedTool, .machO),
            entry(FixturePath.scriptTool, .script), entry(FixturePath.swapInside, .file),
            entry(FixturePath.projectBFile, .file), entry(FixturePath.victim, .file),
            entry(FixturePath.readWriteTarget, .file), entry(FixturePath.openTruncateTarget, .file),
            entry(FixturePath.attributesTarget, .file), entry(FixturePath.swapOutside, .file),
            entry(FixturePath.sharedMapTarget, .file), entry(FixturePath.executableMapTarget, .machO),
            entry(FixturePath.truncateTarget, .file),
            entry(FixturePath.externalFile, .file), entry(FixturePath.externalDotEnv, .file),
            entry(FixturePath.externalSecret, .file), entry(FixturePath.externalTool, .machO),
            entry(FixturePath.moveOutSource, .file, consumed: true), entry(FixturePath.moveInSource, .file, consumed: true),
            entry(FixturePath.unlinkTarget, .file, consumed: true),
            entry(FixturePath.symlinkToVictim, .symlink, FixturePath.symlinkToVictimTarget),
            entry(FixturePath.directorySymlink, .symlink, FixturePath.directorySymlinkTarget),
            entry(FixturePath.victimLink, .symlink, FixturePath.victimLinkTarget),
            // Created at setup, before any session exists: a later open through it shows
            // the workspace path although the inode is the outside victim.
            entry(FixturePath.hardlinkToVictim, .hardlink, FixturePath.victim),
            entry(FixturePath.markers, .directory),
        ] + Catalog.probes.flatMap {
            [entry(FixturePath.marker($0.id), .file), entry(FixturePath.marker($0.id, end: true), .file)]
        }
    }()

    static let aliases = [
        FixtureAlias(spelling: FixturePath.secretCaseVariant, aliasOf: FixturePath.secret, kind: "case"),
        FixtureAlias(spelling: FixturePath.noteNFD, aliasOf: FixturePath.noteNFC, kind: "unicode-nfd"),
    ]

    /// Same shape as examples/task-policy.json, plus a second non-ASCII deny directory,
    /// the helper socket directory and one exact execute rule.
    static let allow = [
        PolicyRule(path: FixturePath.workspace, scope: "tree", operations: ["read"]),
        PolicyRule(path: FixturePath.src, scope: "tree", operations: ["write"]),
        PolicyRule(path: FixturePath.tests, scope: "tree", operations: ["write"]),
        PolicyRule(path: FixturePath.ipc, scope: "tree", operations: ["write"]),
        PolicyRule(path: FixturePath.allowedTool, scope: "exact", operations: ["execute"]),
    ]
    static let deny = [
        PolicyRule(path: FixturePath.deniedDirectory, scope: "tree", operations: ["execute", "read", "write"]),
        PolicyRule(path: FixturePath.deniedDirectoryNFC, scope: "tree", operations: ["execute", "read", "write"]),
        PolicyRule(path: FixturePath.externalDenied, scope: "tree", operations: ["execute", "read", "write"]),
    ]

    /// Creates the synthetic fixture in an empty, already validated root.
    public static func create(root: String) throws -> FixtureManifest {
        let machO = try Data(contentsOf: URL(fileURLWithPath: machOSource))
        for item in entries {
            try createEntry(item, root: root, machO: machO)
        }
        let attribute = Array("synthetic".utf8)
        guard setxattr(root + "/" + FixturePath.attributesTarget, FixturePath.existingAttribute, attribute,
                       attribute.count, 0, XATTR_NOFOLLOW) == 0 else {
            throw HarnessError("setup failed at \(FixturePath.attributesTarget) xattr: \(ErrnoName.of(errno))")
        }
        let manifest = FixtureManifest(root: root, taskId: newTaskId(), volumeCaseSensitive: volumeCaseSensitive(root: root),
                                       entries: entries, aliases: aliases, allow: allow, deny: deny)
        try write(JSONCoding.encoder.encode(manifest), to: root + "/" + manifestName)
        return manifest
    }

    /// pathconf only; the run records the same value in its report.
    public static func volumeCaseSensitive(root: String) -> Bool {
        pathconf(root + "/" + FixturePath.workspace, _PC_CASE_SENSITIVE) == 1
    }

    /// Reads the manifest of a validated root.
    public static func manifest(root: String) throws -> FixtureManifest {
        let path = root + "/" + manifestName
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            throw HarnessError("no fixture manifest at \(path)")
        }
        return try FixtureManifest.decode(Data(contentsOf: URL(fileURLWithPath: path)))
    }

    private static func createEntry(_ item: FixtureEntry, root: String, machO: Data) throws {
        let path = root + "/" + item.path
        let status: Int32
        switch item.kind {
        case .directory:
            status = mkdir(path, 0o700)
        case .file:
            // Synthetic, fixed text; never copied from a real file.
            try write(Data("synthetic r3-probes fixture: \(item.path)\n".utf8), to: path)
            status = chmod(path, 0o600)
        case .script:
            try write(Data("#!/bin/sh\nexit 0\n".utf8), to: path)
            status = chmod(path, 0o700)
        case .machO:
            try write(machO, to: path)
            status = chmod(path, 0o700)
        case .symlink:
            status = symlink(item.target!, path)
        case .hardlink:
            status = link(root + "/" + item.target!, path)
        }
        guard status == 0 else { throw HarnessError("setup failed at \(item.path): \(ErrnoName.of(errno))") }
    }

    private static func write(_ data: Data, to path: String) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw HarnessError("cannot create \(path): \(ErrnoName.of(errno))") }
        defer { close(fd) }
        let written = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        guard written == data.count else { throw HarnessError("short write to \(path)") }
    }

    /// Checks, with lstat (and readlink inside the workspace) only, that every entry still
    /// has the shape setup gave it. This keeps the probes from following a replaced
    /// symlink out of the root. Symlinks outside the workspace are never followed by a
    /// probe and readlink there is itself a probed operation, so only their type and
    /// length are checked. `beforeRun` also requires the consumed entries and forbids a
    /// previous run's marker.
    public static func check(root: String, beforeRun: Bool) throws {
        var info = stat()
        if beforeRun, lstat(root + "/" + FixturePath.workspaceCreated, &info) == 0 || errno != ENOENT {
            throw HarnessError("fixture already used by a run; run setup on a new root")
        }
        for item in entries where beforeRun || !item.consumedByRun {
            try checkEntry(item, root: root)
        }
    }

    private static func checkEntry(_ item: FixtureEntry, root: String) throws {
        let path = root + "/" + item.path
        var info = stat()
        guard lstat(path, &info) == 0 else { throw HarnessError("fixture entry missing: \(item.path)") }
        let type = info.st_mode & S_IFMT
        let shapeMatches: Bool
        switch item.kind {
        case .directory: shapeMatches = type == S_IFDIR
        case .file: shapeMatches = type == S_IFREG
        case .script, .machO: shapeMatches = type == S_IFREG && info.st_mode & S_IXUSR != 0
        case .symlink:
            if item.path.hasPrefix(FixturePath.workspace + "/") {
                shapeMatches = type == S_IFLNK && readLink(path) == item.target
            } else {
                shapeMatches = type == S_IFLNK && Int(info.st_size) == item.target!.utf8.count
            }
        case .hardlink:
            var original = stat()
            shapeMatches = type == S_IFREG && lstat(root + "/" + item.target!, &original) == 0
                && original.st_ino == info.st_ino && original.st_dev == info.st_dev
        }
        guard shapeMatches else { throw HarnessError("fixture entry changed: \(item.path)") }
    }

    private static func readLink(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = readlink(path, &buffer, buffer.count - 1)
        guard count >= 0 else { return nil }
        return String(decoding: buffer[0..<count].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
