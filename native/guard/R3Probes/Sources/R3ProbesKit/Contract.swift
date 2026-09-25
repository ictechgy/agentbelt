import Darwin
import Foundation

/// The schema-2 task contract for the fixture (docs/design/task-policy.md, "Schema 2:
/// external rules"). `external` stays narrow: exact rules for the probe binary and the
/// script interpreter, runtime trees, and the fixture's own `external/` tree. A rule that
/// would cover the root, `outside/` or `projectB/` is refused, because it would make the
/// denied probes meaningless.
public enum SchemaTwoContract {
    /// Runtime trees the probe binary and the Mach-O fixture tools load from: dyld and
    /// libSystem live in /usr/lib, frameworks in /System/Library, and the dyld shared
    /// cache (macOS 13+) in the OS cryptex. Not /System itself: it contains
    /// /System/Volumes/Data, an alias of every user path, including the fixture root.
    public static let runtimeTrees = ["/usr/lib", "/System/Library", "/System/Volumes/Preboot/Cryptexes/OS"]
    /// The data volume firmlink root; task_policy refuses rules inside or above it.
    public static let dataVolume = "/System/Volumes/Data"
    /// Interpreter of the `#!` script probe. It gets execute so that a denial of that
    /// probe can only come from the script's own missing execute rule.
    public static let scriptInterpreter = "/bin/sh"

    /// Absolute external rules for `root` and the resolved probe binary.
    public static func externalRules(root: String, probeBinary: String) -> [PolicyRule] {
        [
            PolicyRule(path: probeBinary, scope: "exact", operations: ["execute", "read"]),
            PolicyRule(path: scriptInterpreter, scope: "exact", operations: ["execute", "read"]),
        ] + runtimeTrees.map { PolicyRule(path: $0, scope: "tree", operations: ["execute", "read"]) }
            + [PolicyRule(path: root + "/" + FixturePath.external, scope: "tree", operations: ["read"])]
    }

    /// Refuses any external rule that is `/`, not canonical, inside or above the data
    /// volume alias, inside the root other than under `external/`, or a tree rule covering
    /// the root, `outside/` or `projectB/`.
    /// `resolve` maps a rule path to its resolved form when it exists (realpath), so a
    /// symlinked spelling such as /var cannot hide an ancestor of the root.
    public static func validate(_ rules: [PolicyRule], root: String,
                                resolve: (String) -> String? = resolvedPath) throws {
        let protected = [root, root + "/outside", root + "/projectB"]
        let externalTree = root + "/" + FixturePath.external
        for rule in rules {
            guard isCanonical(rule.path), rule.path != "/" else {
                throw HarnessError("external rule path is not canonical or is /: \(rule.path)")
            }
            guard rule.scope == "exact" || rule.scope == "tree" else {
                throw HarnessError("external rule scope must be exact or tree: \(rule.path)")
            }
            for spelling in Set([rule.path, resolve(rule.path) ?? rule.path]) {
                if within(spelling, dataVolume) || within(dataVolume, spelling) {
                    throw HarnessError("external rule covers or lies in the data volume alias: \(rule.path)")
                }
                if within(spelling, root), !within(spelling, externalTree) {
                    throw HarnessError("external rule lies inside the fixture root: \(rule.path)")
                }
                if rule.scope == "tree", protected.contains(where: { within($0, spelling) }) {
                    throw HarnessError("external tree rule covers the root, outside/ or projectB/: \(rule.path)")
                }
            }
        }
    }

    /// The contract document. The lifetime is a placeholder the R3 launcher must replace
    /// with real clock values.
    public static func document(root: String, taskId: String, probeBinary: String) throws -> Data {
        let external = externalRules(root: root, probeBinary: probeBinary)
        try validate(external, root: root)
        func absolute(_ rules: [PolicyRule]) -> [[String: Any]] {
            rules.map { ["path": root + "/" + $0.path, "scope": $0.scope, "operations": $0.operations] }
        }
        func plain(_ rules: [PolicyRule]) -> [[String: Any]] {
            rules.map { ["path": $0.path, "scope": $0.scope, "operations": $0.operations] }
        }
        let contract: [String: Any] = [
            "schema_version": 2,
            "task_id": taskId,
            "revision": 1,
            "workspace": root + "/" + FixturePath.workspace,
            "valid_from_ns": 0,
            "expires_at_ns": Int64.max,
            "allow": absolute(Fixture.allow),
            "deny": absolute(Fixture.deny),
            "external": plain(external),
        ]
        return try JSONSerialization.data(withJSONObject: contract, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    /// Resolves and checks the probe binary: a regular executable file outside the root.
    public static func probeBinary(_ spelling: String, root: String) throws -> String {
        guard spelling.hasPrefix("/"), let resolved = resolvedPath(spelling) else {
            throw HarnessError("--probe-binary must be an absolute path to an existing file")
        }
        var info = stat()
        guard lstat(resolved, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_mode & S_IXUSR != 0 else {
            throw HarnessError("--probe-binary is not an executable regular file: \(resolved)")
        }
        guard !within(resolved, root) else {
            throw HarnessError("--probe-binary must not lie inside the fixture root")
        }
        return resolved
    }

    /// realpath for the unconfined `contract` command only; nil when the path is missing.
    public static func resolvedPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    static func within(_ path: String, _ ancestor: String) -> Bool {
        path == ancestor || path.hasPrefix(ancestor + "/")
    }

    private static func isCanonical(_ path: String) -> Bool {
        guard path.hasPrefix("/") else { return false }
        if path == "/" { return true }
        return path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
            && !path.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7f }
    }
}
