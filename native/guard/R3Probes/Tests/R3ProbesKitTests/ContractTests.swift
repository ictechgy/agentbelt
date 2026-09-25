// The schema-2 contract: narrow external rules, and refusal of rules that would cover the
// fixture root, outside/ or projectB/.
import Darwin
import XCTest
@testable import R3ProbesKit

final class ContractTests: XCTestCase {
    private let root = "/private/var/folders/ab/cd/T/r3-probes.x"
    private func tree(_ path: String) -> PolicyRule { PolicyRule(path: path, scope: "tree", operations: ["read"]) }
    private func exact(_ path: String) -> PolicyRule { PolicyRule(path: path, scope: "exact", operations: ["read"]) }
    private func validate(_ rules: [PolicyRule], resolve: @escaping (String) -> String? = { _ in nil }) throws {
        try SchemaTwoContract.validate(rules, root: root, resolve: resolve)
    }

    func testDefaultExternalRulesAreAccepted() throws {
        try validate(SchemaTwoContract.externalRules(root: root, probeBinary: "/private/tmp/build/r3-probes"))
        XCTAssertNoThrow(try validate([tree("/usr/lib"), tree(root + "/external"), exact("/bin/sh")]))
    }

    func testRulesCoveringTheRootOrItsProtectedTreesAreRefused() {
        for path in ["/private", "/private/var", "/private/var/folders", root, root + "/outside", root + "/projectB"] {
            XCTAssertThrowsError(try validate([tree(path)]), path)
        }
        // /System contains /System/Volumes/Data, an alias of every user path.
        XCTAssertThrowsError(try validate([tree("/System")]))
        XCTAssertThrowsError(try validate([tree("/System/Volumes")]))
        XCTAssertThrowsError(try validate([exact("/System/Volumes/Data/private/tmp/x")]))
        XCTAssertThrowsError(try validate([tree("/")]))
        XCTAssertThrowsError(try validate([exact(root + "/outside/victim.txt")]), "exact rule inside the root")
        XCTAssertThrowsError(try validate([exact(root + "/projectA/src/main.txt")]))
        XCTAssertThrowsError(try validate([tree("/usr//lib")]), "non-canonical spelling")
        XCTAssertThrowsError(try validate([tree("/usr/lib/..")]))
        XCTAssertThrowsError(try validate([PolicyRule(path: "/usr/lib", scope: "prefix", operations: ["read"])]))
    }

    func testResolvedSpellingIsCheckedToo() {
        // A symlinked spelling that resolves to an ancestor of the root is refused.
        XCTAssertThrowsError(try validate([tree("/var")]) { $0 == "/var" ? "/private/var" : nil })
        XCTAssertNoThrow(try validate([tree("/usr/lib")]) { $0 })
    }

    func testDocumentIsSchemaTwoWithTheFixturePolicy() throws {
        let data = try SchemaTwoContract.document(root: root, taskId: "r3-probes-project-a-0123456789abcdef",
                                                  probeBinary: "/private/tmp/build/r3-probes")
        let document = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(document.keys), ["schema_version", "task_id", "revision", "workspace", "valid_from_ns",
                                            "expires_at_ns", "allow", "deny", "external"])
        XCTAssertEqual(document["schema_version"] as? Int, 2)
        XCTAssertEqual(document["task_id"] as? String, "r3-probes-project-a-0123456789abcdef")
        XCTAssertEqual(document["workspace"] as? String, root + "/projectA")
        let external = try XCTUnwrap(document["external"] as? [[String: Any]])
        let binary = try XCTUnwrap(external.first { $0["path"] as? String == "/private/tmp/build/r3-probes" })
        XCTAssertEqual(binary["scope"] as? String, "exact")
        XCTAssertEqual(binary["operations"] as? [String], ["execute", "read"])
        XCTAssertFalse(external.contains { ($0["path"] as? String) == "/System" })
        let externalTree = try XCTUnwrap(external.first { $0["path"] as? String == root + "/external" })
        XCTAssertEqual(externalTree["operations"] as? [String], ["read"], "external/ must not grant write or execute")
    }

    func testTaskIdsAreUniqueAndValidIdentifiers() {
        let first = Fixture.newTaskId()
        XCTAssertNotEqual(first, Fixture.newTaskId())
        XCTAssertTrue(first.hasPrefix(Fixture.taskIdPrefix))
        XCTAssertNotNil(first.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", options: .regularExpression))
    }

    func testProbeBinaryMustBeAnExecutableOutsideTheRoot() throws {
        let scratch = try RootSafety.makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(atPath: scratch) }
        XCTAssertThrowsError(try SchemaTwoContract.probeBinary("relative/r3-probes", root: scratch))
        XCTAssertThrowsError(try SchemaTwoContract.probeBinary(scratch + "/missing", root: scratch))
        let inside = scratch + "/tool"
        XCTAssertTrue(FileManager.default.createFile(atPath: inside, contents: Data("#!/bin/sh\n".utf8)))
        XCTAssertEqual(chmod(inside, 0o700), 0)
        XCTAssertThrowsError(try SchemaTwoContract.probeBinary(inside, root: scratch))
        XCTAssertEqual(try SchemaTwoContract.probeBinary("/bin/sh", root: scratch), "/bin/sh")
    }
}
