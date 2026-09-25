import Foundation
import GuardCore

// Swift port of task_policy.py (R1). Semantics, reason codes and error messages are
// kept identical so the differential tests can compare both implementations.
// Paths are compared by UTF-8 bytes throughout: Swift String equality and hasPrefix
// treat canonically equivalent spellings as equal, and the policy must not.

public struct PolicyError: Error, Equatable, CustomStringConvertible {
    public let reason: String
    init(_ reason: String) { self.reason = reason }
    public var description: String { "PolicyError(\(reason))" }
}

func policyRequire(_ condition: Bool, _ message: String) throws {
    if !condition { throw PolicyError(message) }
}

public enum PolicyLimits {
    public static let maxRules = 128
    /// Upper bound on the `names` of one name-scoped exception (task_policy.MAX_EXCEPTION_NAMES).
    public static let maxExceptionNames = 8
    public static let maxJSONBytes = 65536
    public static let maxInteger = Int64.max
}

/// APFS firmlink alias of the whole user data volume (task_policy.DATA_VOLUME).
public let dataVolume = "/System/Volumes/Data"

public enum FileOperation: String, CaseIterable, Sendable {
    case read, write, execute
}

/// Conservative name exclusions; no grant or rule can re-allow them (task_policy.py).
public let sensitiveComponents = [
    ".env*", "*.env", "*.env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore",
    "id_rsa*", "id_ed25519*", "auth.json", "credentials", "credentials.*",
    "secrets", "secrets.*", ".ssh", ".aws", ".azure", ".kube", ".gnupg",
    ".npmrc", ".netrc", ".pypirc", "*.sqlite", "*.sqlite3", "*.db", "*.dump",
    ".git", ".agents", ".zcode", "zcode.json",
]

enum PathBytes {
    static func equal(_ lhs: String, _ rhs: String) -> Bool { lhs.utf8.elementsEqual(rhs.utf8) }

    /// task_policy._within: the root itself or a descendant separated by "/".
    /// Allocation-free: it runs for every rule on every authorization.
    static func within(_ path: String, _ root: String) -> Bool {
        if equal(path, root) { return true }
        let rootBytes = root.utf8
        var rootEnd = rootBytes.endIndex
        while rootEnd > rootBytes.startIndex, rootBytes[rootBytes.index(before: rootEnd)] == UInt8(ascii: "/") {
            rootEnd = rootBytes.index(before: rootEnd)
        }
        let trimmed = rootBytes[rootBytes.startIndex..<rootEnd]
        let pathBytes = path.utf8
        guard pathBytes.starts(with: trimmed) else { return false }
        let separator = pathBytes.index(pathBytes.startIndex, offsetBy: trimmed.count)
        return separator < pathBytes.endIndex && pathBytes[separator] == UInt8(ascii: "/")
    }

    static func less(_ lhs: String, _ rhs: String) -> Bool {
        lhs.unicodeScalars.lexicographicallyPrecedes(rhs.unicodeScalars)
    }
}

/// fnmatch.fnmatchcase for the patterns above, which only use "*". It runs on UTF-8
/// bytes: the literal pattern characters are ASCII, so they can never match inside a
/// multi-byte sequence, and "*" spans whole scalars either way.
func globMatch(_ text: [UInt8], _ pattern: [UInt8]) -> Bool {
    var textIndex = 0, patternIndex = 0, starIndex = -1, resume = 0
    while textIndex < text.count {
        if patternIndex < pattern.count, pattern[patternIndex] != star, pattern[patternIndex] == text[textIndex] {
            textIndex += 1; patternIndex += 1
        } else if patternIndex < pattern.count, pattern[patternIndex] == star {
            starIndex = patternIndex; resume = textIndex; patternIndex += 1
        } else if starIndex >= 0 {
            patternIndex = starIndex + 1; resume += 1; textIndex = resume
        } else {
            return false
        }
    }
    while patternIndex < pattern.count, pattern[patternIndex] == star { patternIndex += 1 }
    return patternIndex == pattern.count
}

private let star = UInt8(ascii: "*")
private let sensitivePatterns: [[UInt8]] = sensitiveComponents.map { Array($0.utf8) }

/// Python str.casefold() as UTF-8: ASCII lowercases directly; anything else uses full
/// Unicode case folding (e.g. "ß" -> "ss", "ſ" -> "s").
func casefold(_ component: ArraySlice<UInt8>) -> [UInt8] {
    if component.allSatisfy({ $0 < 0x80 }) {
        return component.map { (0x41...0x5A).contains($0) ? $0 | 0x20 : $0 }
    }
    let text = String(decoding: component, as: UTF8.self)
    return Array(text.folding(options: [.caseInsensitive], locale: nil).utf8)
}

/// task_policy._ascii_fold: A-Z only, so denials match on case-insensitive APFS. Kept to
/// ASCII because Foundation's Unicode folding differs from str.casefold.
func asciiFold(_ path: String) -> String {
    guard path.utf8.contains(where: { (0x41...0x5A).contains($0) }) else { return path }
    return String(decoding: path.utf8.map { (0x41...0x5A).contains($0) ? $0 | 0x20 : $0 }, as: UTF8.self)
}

/// task_policy._data_volume_overlap: case-insensitive, since APFS resolves
/// /system/volumes/data to the same firmlink.
func dataVolumeOverlap(_ path: String, insideOnly: Bool = false) -> Bool {
    let folded = String(decoding: casefold(ArraySlice(path.utf8)), as: UTF8.self)
    let volume = String(decoding: casefold(ArraySlice(dataVolume.utf8)), as: UTF8.self)
    return PathBytes.within(folded, volume) || (!insideOnly && PathBytes.within(volume, folded))
}

func isSensitive(_ path: String) -> Bool {
    let bytes = Array(path.utf8)
    return bytes.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false).contains { component in
        sensitiveFolded(casefold(component))
    }
}

/// task_policy._literal_name: printable ASCII (0x21-0x7E) in lower case, without "/" or "*".
func literalName(_ name: String) -> Bool {
    name.utf8.allSatisfy { (0x21...0x7E).contains($0) && !(0x41...0x5A).contains($0) && $0 != UInt8(ascii: "/")
        && $0 != UInt8(ascii: "*") }
}

/// One already casefolded component against the sensitive patterns.
func sensitiveFolded(_ folded: [UInt8]) -> Bool {
    sensitivePatterns.contains { globMatch(folded, $0) }
}

func policyInteger(_ value: Int64, minimum: Int64 = 0) -> Bool { value >= minimum }

public enum RuleScope: String, Sendable {
    case exact, tree
}

public struct PathRule: Equatable, Sendable {
    public let path: String
    public let scope: RuleScope
    public let operations: Set<FileOperation>
    /// Schema 3, exceptions only: the sensitive names a tree exception may lift below its
    /// root (name-scoped), sorted as Python sorts strings. nil is an ordinary rule.
    public let names: [String]?
    /// `path` through asciiFold, computed once so deny checks do not allocate per decision.
    let foldedPath: String
    /// `names` as UTF-8, compared with casefolded components.
    let nameBytes: [[UInt8]]?

    public init(path: String, scope: RuleScope, operations: Set<FileOperation>, names: [String]? = nil) throws {
        try policyRequire(Validate.canonicalPath(path), "invalid rule path")
        try policyRequire(!operations.isEmpty, "invalid rule operations")
        if let names {
            try policyRequire((1...PolicyLimits.maxExceptionNames).contains(names.count), "invalid exception names")
            // Byte comparison: Swift String equality would merge canonically equivalent names.
            let bytes = names.map { Array($0.utf8) }
            try policyRequire(Set(bytes).count == bytes.count, "duplicate exception name")
            try policyRequire(scope == .tree, "names only on tree exceptions")
            // A literal component compared with casefolded ones, so it must be printable ASCII in
            // lower case: str.casefold and Foundation's folding differ on non-ASCII, and any other
            // spelling could never be lifted.
            try policyRequire(names.allSatisfy(literalName), "exception name is not a lowercase ASCII component")
            try policyRequire(names.allSatisfy(isSensitive), "exception name is not sensitive")
        }
        self.path = path
        self.foldedPath = asciiFold(path)
        self.scope = scope
        self.operations = operations
        self.names = names?.sorted(by: PathBytes.less)
        self.nameBytes = self.names?.map { Array($0.utf8) }
    }

    public static func == (lhs: PathRule, rhs: PathRule) -> Bool {
        PathBytes.equal(lhs.path, rhs.path) && lhs.scope == rhs.scope && lhs.operations == rhs.operations
            && lhs.nameBytes == rhs.nameBytes
    }

    func matches(_ path: String) -> Bool {
        scope == .exact ? PathBytes.equal(path, self.path) : PathBytes.within(path, self.path)
    }

    /// task_policy.PathRule.lifts: whether this exception lifts the sensitive-name ban on
    /// `path`. A name-scoped one lifts only sensitive components below its root that
    /// casefold to one of its names; its root holds no sensitive component (TaskContract).
    func lifts(_ path: String) -> Bool {
        guard matches(path) else { return false }
        guard let nameBytes, !PathBytes.equal(path, self.path) else { return true }
        // Canonical paths end in "/" only as the root itself (task_policy: path.rstrip('/')).
        let rootCount = PathBytes.equal(self.path, "/") ? 0 : self.path.utf8.count
        let below = Array(path.utf8.dropFirst(rootCount + 1))
        return below.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false).allSatisfy { component in
            let folded = casefold(component)
            return !sensitiveFolded(folded) || nameBytes.contains(folded)
        }
    }

    /// task_policy.PathRule.denies: `matches` for a deny rule, ASCII case-insensitive.
    /// `folded` is the requested path already passed through asciiFold.
    func denies(folded: String) -> Bool {
        scope == .exact ? PathBytes.equal(folded, foldedPath) : PathBytes.within(folded, foldedPath)
    }
}

public struct TaskContract: Equatable, Sendable {
    public let schemaVersion: Int64
    public let taskID: String
    public let revision: Int64
    public let workspace: String
    public let validFromNs: Int64
    public let expiresAtNs: Int64
    public let allow: [PathRule]
    public let deny: [PathRule]
    /// Schema 2: operator-approved access outside the workspace (runtime trees, isolated state).
    public let external: [PathRule]
    /// Schema 3: approver-visible exceptions to the sensitive-name ban (task_policy.py). They
    /// only lift the ban where allow/external grant the operations; never execute.
    public let exceptions: [PathRule]

    public init(schemaVersion: Int64 = 1, taskID: String, revision: Int64, workspace: String,
                validFromNs: Int64, expiresAtNs: Int64, allow: [PathRule], deny: [PathRule],
                external: [PathRule] = [], exceptions: [PathRule] = []) throws {
        try policyRequire((1...3).contains(schemaVersion), "unsupported schema version")
        try policyRequire(Validate.identifier(taskID), "invalid task identifier")
        try policyRequire(policyInteger(revision, minimum: 1), "invalid policy revision")
        try policyRequire(Validate.canonicalPath(workspace) && workspace != "/" && !dataVolumeOverlap(workspace, insideOnly: true),
                          "invalid workspace")
        try policyRequire(policyInteger(validFromNs) && policyInteger(expiresAtNs) && validFromNs < expiresAtNs,
                          "invalid policy lifetime")
        try policyRequire([allow, deny, external, exceptions].allSatisfy { $0.count <= PolicyLimits.maxRules },
                          "invalid policy rules")
        try policyRequire(schemaVersion >= 2 || external.isEmpty, "external rules need schema 2")
        try policyRequire(schemaVersion == 3 || exceptions.isEmpty, "exceptions need schema 3")
        try policyRequire((allow + deny + external).allSatisfy { $0.names == nil }, "names only on tree exceptions")
        try policyRequire(external.allSatisfy { !PathBytes.equal($0.path, "/") }, "external rule covers the filesystem root")
        try policyRequire(!(allow + external).contains { dataVolumeOverlap($0.path) }, "rule covers the data volume alias")
        try policyRequire(allow.allSatisfy { PathBytes.within($0.path, workspace) }, "allow rule outside workspace")
        let granting = allow + external
        for exception in exceptions {
            try policyRequire(exception.operations.isSubset(of: [.read, .write]), "exception grants execute")
            try policyRequire(!PathBytes.equal(exception.path, "/") && !dataVolumeOverlap(exception.path),
                              "rule covers the data volume alias")
            if exception.names == nil {
                // Rooted at the sensitive name, so an exception never lifts names below an ordinary directory.
                let last = exception.path.utf8.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false).last ?? []
                try policyRequire(isSensitive(String(decoding: last, as: UTF8.self)), "exception not rooted at a sensitive name")
            } else {
                // Name-scoped: an ordinary root (a package cache) whose entries are not known in
                // advance. Its names are lifted strictly below it, so the root itself stays clean.
                try policyRequire(!isSensitive(exception.path), "scoped exception path is sensitive")
            }
            try policyRequire(exception.operations.allSatisfy { operation in
                granting.contains { $0.operations.contains(operation) && covers($0, exception) }
            }, "exception outside granted scope")
        }
        self.schemaVersion = schemaVersion
        self.taskID = taskID
        self.revision = revision
        self.workspace = workspace
        self.validFromNs = validFromNs
        self.expiresAtNs = expiresAtNs
        self.allow = allow
        self.deny = deny
        self.external = external
        self.exceptions = exceptions
    }

    public static func == (lhs: TaskContract, rhs: TaskContract) -> Bool {
        lhs.schemaVersion == rhs.schemaVersion && lhs.taskID == rhs.taskID && lhs.revision == rhs.revision
            && PathBytes.equal(lhs.workspace, rhs.workspace) && lhs.validFromNs == rhs.validFromNs
            && lhs.expiresAtNs == rhs.expiresAtNs && lhs.allow == rhs.allow && lhs.deny == rhs.deny
            && lhs.external == rhs.external && lhs.exceptions == rhs.exceptions
    }

    func replacingAllow(_ allow: [PathRule]) throws -> TaskContract {
        try TaskContract(schemaVersion: schemaVersion, taskID: taskID, revision: revision, workspace: workspace,
                         validFromNs: validFromNs, expiresAtNs: expiresAtNs, allow: allow, deny: deny,
                         external: external, exceptions: exceptions)
    }
}

public struct Decision: Equatable, Sendable {
    public let allowed: Bool
    public let reason: String
    public let revision: Int64?
    public var cacheable: Bool { false }
    public var enforcement: String { "policy_only" }
}

/// task_policy.evaluate for one normalized request. The caller has already matched the
/// process to its binding; `revoked` is the task's current lifecycle state.
func evaluate(contract: TaskContract, revoked: Bool, path: String, operations: Set<FileOperation>,
              nowNs: Int64) -> Decision {
    func deny(_ reason: String) -> Decision { Decision(allowed: false, reason: reason, revision: contract.revision) }
    if revoked { return deny("revoked") }
    if nowNs < contract.validFromNs { return deny("not_yet_valid") }
    if nowNs >= contract.expiresAtNs { return deny("expired") }
    var excepted = false
    if isSensitive(path) {
        // Every requested operation must be covered by a schema-3 exception for this path.
        excepted = operations.allSatisfy { operation in
            contract.exceptions.contains { $0.operations.contains(operation) && $0.lifts(path) }
        }
        if !excepted { return deny("sensitive_path") }
    }
    let folded = contract.deny.isEmpty ? path : asciiFold(path)
    if contract.deny.contains(where: { $0.denies(folded: folded) && !$0.operations.isDisjoint(with: operations) }) {
        return deny("explicit_deny")
    }
    let allowed = operations.allSatisfy { operation in
        contract.allow.contains { $0.operations.contains(operation) && $0.matches(path) }
            || contract.external.contains { $0.operations.contains(operation) && $0.matches(path) }
    }
    guard allowed else { return deny("outside_allow_scope") }
    return Decision(allowed: true, reason: excepted ? "allowed_by_exception" : "allowed", revision: contract.revision)
}

/// Conservative containment of literal exact/tree scopes (task_policy._covers).
func covers(_ outer: PathRule, _ inner: PathRule) -> Bool {
    if outer.scope == .exact { return inner.scope == .exact && PathBytes.equal(inner.path, outer.path) }
    return PathBytes.within(inner.path, outer.path)
}

/// task_policy._names_cover: an unscoped exception covers only unscoped ones, a scoped one
/// only scoped ones whose names it includes.
func namesCover(_ outer: PathRule, _ inner: PathRule) -> Bool {
    guard let outerNames = outer.nameBytes, let innerNames = inner.nameBytes else {
        return outer.names == nil && inner.names == nil
    }
    return innerNames.allSatisfy { outerNames.contains($0) }
}

/// Static child-policy restriction (task_policy.is_attenuation).
public func isAttenuation(parent: TaskContract, child: TaskContract) -> Bool {
    // A v1 child would regain the v1 runtime-exec exception its v2 parent does not have.
    if child.schemaVersion < parent.schemaVersion { return false }
    if parent.taskID == child.taskID || !PathBytes.within(child.workspace, parent.workspace)
        || child.validFromNs < parent.validFromNs || child.expiresAtNs > parent.expiresAtNs {
        return false
    }
    let parentGranting = parent.allow + parent.external
    for childRule in child.allow + child.external {
        for operation in childRule.operations
        where !parentGranting.contains(where: { $0.operations.contains(operation) && covers($0, childRule) }) {
            return false
        }
    }
    // A child may not lift a sensitive name its parent keeps banned.
    for childRule in child.exceptions {
        for operation in childRule.operations
        where !parent.exceptions.contains(where: {
            $0.operations.contains(operation) && covers($0, childRule) && namesCover($0, childRule)
        }) {
            return false
        }
    }
    for parentRule in parent.deny {
        for operation in parentRule.operations
        where !child.deny.contains(where: { $0.operations.contains(operation) && covers($0, parentRule) }) {
            return false
        }
    }
    return true
}

// MARK: - v1 contract documents

enum ContractCodec {
    static let fields: Set<String> = ["schema_version", "task_id", "revision", "workspace",
                                      "valid_from_ns", "expires_at_ns", "allow", "deny"]
    static let fieldsV2 = fields.union(["external"])
    static let fieldsV3 = fieldsV2.union(["exceptions"])

    /// task_policy.contract_from_dict: exact keys, exact types. Python evaluates the rule
    /// lists before the TaskContract constructor runs, so rule errors are reported first.
    static func decode(_ value: JSONValue) throws -> TaskContract {
        let version = value.objectValue?["schema_version"]
        let expected = version == .int(3) ? fieldsV3 : version == .int(2) ? fieldsV2 : fields
        guard let object = value.objectValue, Set(object.keys) == expected else {
            throw PolicyError("invalid document fields")
        }
        let exceptions = version == .int(3) ? try rules(object["exceptions"]!, exceptions: true) : []
        let external = version == .int(2) || version == .int(3) ? try rules(object["external"]!) : []
        let allow = try rules(object["allow"]!)
        let deny = try rules(object["deny"]!)
        guard case let .int(schema) = object["schema_version"]!, (1...3).contains(schema) else {
            throw PolicyError("unsupported schema version")
        }
        guard let taskID = object["task_id"]!.stringValue, Validate.identifier(taskID) else {
            throw PolicyError("invalid task identifier")
        }
        guard let revision = object["revision"]!.intValue, revision >= 1 else { throw PolicyError("invalid policy revision") }
        guard let workspace = object["workspace"]!.stringValue, Validate.canonicalPath(workspace), workspace != "/",
              !dataVolumeOverlap(workspace, insideOnly: true) else {
            throw PolicyError("invalid workspace")
        }
        guard let validFrom = object["valid_from_ns"]!.intValue, let expires = object["expires_at_ns"]!.intValue,
              validFrom >= 0, expires >= 0, validFrom < expires else { throw PolicyError("invalid policy lifetime") }
        return try TaskContract(schemaVersion: schema, taskID: taskID, revision: revision, workspace: workspace,
                                validFromNs: validFrom, expiresAtNs: expires, allow: allow, deny: deny,
                                external: external, exceptions: exceptions)
    }

    private static let ruleFields: Set<String> = ["path", "scope", "operations"]

    private static func rules(_ value: JSONValue, exceptions: Bool = false) throws -> [PathRule] {
        guard let items = value.arrayValue, items.count <= PolicyLimits.maxRules else { throw PolicyError("invalid rule list") }
        return try items.map { item in
            // Only an exception may carry `names`; without it the rule keeps the v1 shape.
            guard let object = item.objectValue, Set(object.keys) == ruleFields
                    || (exceptions && Set(object.keys) == ruleFields.union(["names"])) else {
                throw PolicyError("invalid document fields")
            }
            guard let operations = object["operations"]?.arrayValue, (1...3).contains(operations.count) else {
                throw PolicyError("invalid rule operations")
            }
            let names = try operations.map { entry -> FileOperation in
                guard let text = entry.stringValue, let operation = FileOperation(rawValue: text) else {
                    throw PolicyError("invalid rule operations")
                }
                return operation
            }
            try policyRequire(Set(names).count == names.count, "duplicate rule operation")
            var exceptionNames: [String]?
            if let value = object["names"] {
                guard let entries = value.arrayValue, (1...PolicyLimits.maxExceptionNames).contains(entries.count) else {
                    throw PolicyError("invalid exception names")
                }
                exceptionNames = try entries.map { entry in
                    guard let text = entry.stringValue else { throw PolicyError("invalid exception names") }
                    return text
                }
                let bytes = exceptionNames!.map { Array($0.utf8) }
                try policyRequire(Set(bytes).count == bytes.count, "duplicate exception name")
            }
            guard let path = object["path"]?.stringValue else { throw PolicyError("invalid rule path") }
            guard let scopeText = object["scope"]?.stringValue, let scope = RuleScope(rawValue: scopeText) else {
                throw PolicyError("invalid rule scope")
            }
            return try PathRule(path: path, scope: scope, operations: Set(names), names: exceptionNames)
        }
    }

    /// task_policy.contract_to_dict, with operations sorted as Python sorts strings.
    static func encode(_ contract: TaskContract) -> JSONValue {
        func rules(_ items: [PathRule]) -> JSONValue {
            .array(items.map { rule in
                var object: [String: JSONValue] = [
                    "path": .string(rule.path), "scope": .string(rule.scope.rawValue),
                    "operations": .array(rule.operations.map(\.rawValue).sorted().map { .string($0) })]
                // Only when present, so existing documents and their digests are unchanged.
                if let names = rule.names { object["names"] = .array(names.map { .string($0) }) }
                return .object(object)
            })
        }
        var document: [String: JSONValue] = [
            "schema_version": .int(contract.schemaVersion), "task_id": .string(contract.taskID),
            "revision": .int(contract.revision), "workspace": .string(contract.workspace),
            "valid_from_ns": .int(contract.validFromNs), "expires_at_ns": .int(contract.expiresAtNs),
            "allow": rules(contract.allow), "deny": rules(contract.deny)]
        if contract.schemaVersion >= 2 { document["external"] = rules(contract.external) }
        if contract.schemaVersion == 3 { document["exceptions"] = rules(contract.exceptions) }
        return .object(document)
    }

    /// task_policy.load_contract: bounded strict JSON, then the strict decoder.
    static func load(_ data: Data) throws -> TaskContract {
        // Python checks characters first, then UTF-8 bytes (the latter inside its JSON guard).
        if data.count > PolicyLimits.maxJSONBytes {
            let characters = String(decoding: data, as: UTF8.self).unicodeScalars.count
            throw PolicyError(characters > PolicyLimits.maxJSONBytes ? "invalid document size or type" : "invalid contract JSON")
        }
        let value: JSONValue
        do { value = try StrictJSON.parse(data) } catch { throw PolicyError("invalid contract JSON") }
        return try decode(value)
    }
}

public extension TaskContract {
    static func load(json data: Data) throws -> TaskContract { try ContractCodec.load(data) }
    var jsonValue: JSONValue { ContractCodec.encode(self) }
}
