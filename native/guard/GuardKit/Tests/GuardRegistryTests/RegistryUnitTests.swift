// Swift-only behaviour that the differential generator cannot express.
import Foundation
import XCTest
import GuardCore
@testable import GuardRegistry

final class RegistryUnitTests: XCTestCase {
    private let supervisor = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
    private let approver = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.approver")

    private func registryWithTask(_ taskID: String,
                                  persist: ((JSONValue) throws -> Void)? = nil) throws -> (Registry, Peer) {
        let registry = try Registry(config: try RegistryConfig(supervisors: [supervisor], approvers: [approver]),
                                    bootID: "boot-1", nowNs: 1, persist: persist)
        let contract = try TaskContract(taskID: taskID, revision: 1, workspace: "/w/a", validFromNs: 0,
                                        expiresAtNs: 1000, allow: [], deny: [])
        let owner = Peer(process: try ProcessIdentity(pid: 500, pidVersion: 1), signer: supervisor)
        let digest = try registry.propose(owner, contract: contract, nowNs: 2)
        try registry.confirm(Peer(process: try ProcessIdentity(pid: 600, pidVersion: 1), signer: approver),
                             digest: digest, nowNs: 3)
        return (registry, owner)
    }

    func testCanonicallyEquivalentIdentifiersDoNotMatchAnotherTask() throws {
        // U+212A KELVIN SIGN is canonically equivalent to "K" in Swift String comparison.
        let (registry, owner) = try registryWithTask("K1")
        XCTAssertThrowsError(try registry.revoke(owner, taskID: "\u{212A}1", nowNs: 4)) { error in
            XCTAssertEqual(error as? RegistryError, RegistryError("unknown task"))
        }
        XCTAssertNoThrow(try registry.revoke(owner, taskID: "K1", nowNs: 5))
    }

    func testWrappedNegativePidversionSurvivesSaveAndRestore() throws {
        let (registry, owner) = try registryWithTask("ta")
        let wrapped = try ProcessIdentity(pid: 3000, pidVersion: Int32.min)
        registry.onFork(parent: owner.process, child: wrapped, nowNs: 10)
        _ = registry.authorizeFile(process: try ProcessIdentity(pid: 3001, pidVersion: 1), parent: wrapped,
                                   path: "/x", operations: ["read"], nowNs: 11)
        let document = try StrictJSON.parse(Data(CanonicalJSON.encode(registry.toDocument()).utf8))
        XCTAssertNoThrow(try Registry.restore(document, config: registry.config, bootID: "boot-1", nowNs: 12))
    }

    func testPersistHookStoresThroughSaveDocumentUnderTheRegistryLock() throws {
        // The hook runs with the registry locked; saveDocument never reads the registry.
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("agentbelt-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.resolvingSymlinksInPath().appendingPathComponent("registry.json").path
        let (registry, owner) = try registryWithTask("ta", persist: { try saveDocument(path: path, document: $0) })
        let child = try ProcessIdentity(pid: 3000, pidVersion: 1)
        registry.onFork(parent: owner.process, child: child, nowNs: 4)
        try registry.registerLaunch(owner, taskID: "ta", image: try ExecutableImage(path: "/opt/agent", digest: "cd-agent"),
                                    child: child, nowNs: 5)
        let loaded = try loadRegistry(path: path, config: registry.config, bootID: "boot-1", nowNs: 6)
        XCTAssertEqual(try loaded.ticketStatus(owner, child: child, nowNs: 7), "revoked")
        XCTAssertThrowsError(try saveRegistry(path: path, registry: registry)) { error in
            XCTAssertEqual(error as? RegistryError, RegistryError("registry saves through its persist hook"))
        }
        let unhooked = try Registry(config: registry.config, bootID: "boot-1", nowNs: 1)
        XCTAssertThrowsError(try unhooked.checkpoint()) { error in
            XCTAssertEqual(error as? RegistryError, RegistryError("registry has no persist hook"))
        }
    }

    func testDataVolumeCheckIgnoresCase() {
        XCTAssertTrue(dataVolumeOverlap("/system/volumes/data/Users"))
        XCTAssertTrue(dataVolumeOverlap("/SYSTEM"))
        XCTAssertFalse(dataVolumeOverlap("/System/Library"))
        XCTAssertThrowsError(try TaskContract(taskID: "t", revision: 1, workspace: "/system/volumes/data/w",
                                              validFromNs: 0, expiresAtNs: 1, allow: [], deny: []))
    }

    func testDenialsFoldOnlyASCII() throws {
        // Byte-identical to task_policy._ascii_fold; Foundation's Unicode folding would diverge.
        XCTAssertEqual(asciiFold("/W/Stra\u{00DF}e/\u{00C9}"), "/w/stra\u{00DF}e/\u{00C9}")
        let rule = try PathRule(path: "/w/a/Docs/\u{00C9}t\u{00E9}", scope: .exact, operations: [.write])
        XCTAssertTrue(rule.denies(folded: asciiFold("/w/a/DOCS/\u{00C9}T\u{00E9}")))
        XCTAssertFalse(rule.denies(folded: asciiFold("/w/a/docs/\u{00E9}t\u{00E9}")))
        let tree = try PathRule(path: "/w/a/.git/hooks", scope: .tree, operations: [.write])
        XCTAssertTrue(tree.denies(folded: asciiFold("/w/a/.GIT/Hooks/pre-commit")))
        XCTAssertFalse(tree.denies(folded: asciiFold("/w/a/.git/hooksx")))
    }

    func testNamesOnlyOnExceptionsWhenConstructedDirectly() throws {
        // Documents reject `names` outside exceptions at the field level; direct construction
        // reaches the contract check instead (task_policy: 'names only on tree exceptions').
        let scoped = try PathRule(path: "/w/a/.build", scope: .tree, operations: [.read], names: [".git"])
        let allow = try PathRule(path: "/w/a", scope: .tree, operations: [.read])
        for (allowRules, denyRules, externalRules) in [([allow, scoped], [], []), ([allow], [scoped], []), ([allow], [], [scoped])] {
            XCTAssertThrowsError(try TaskContract(schemaVersion: 3, taskID: "t", revision: 1, workspace: "/w/a",
                                                  validFromNs: 0, expiresAtNs: 1, allow: allowRules, deny: denyRules,
                                                  external: externalRules)) { error in
                XCTAssertEqual(error as? PolicyError, PolicyError("names only on tree exceptions"))
            }
        }
        XCTAssertNoThrow(try TaskContract(schemaVersion: 3, taskID: "t", revision: 1, workspace: "/w/a", validFromNs: 0,
                                          expiresAtNs: 1, allow: [allow], deny: [], exceptions: [scoped]))
    }

    func testExceptionNamesAreLiteralLowercaseASCII() throws {
        // A frozenset in Python cannot hold duplicates; an array can.
        XCTAssertThrowsError(try PathRule(path: "/w/a/c", scope: .tree, operations: [.read], names: [".git", ".git"])) { error in
            XCTAssertEqual(error as? PolicyError, PolicyError("duplicate exception name"))
        }
        // Foundation folding differs from str.casefold on non-ASCII (U+AB70 folds to itself
        // here, to U+13A0 in Python), so only lowercase ASCII names are comparable.
        for name in ["\u{AB70}.pem", "\u{13A0}.pem", "\u{00E9}.pem", ".GIT", "*.pem", ".env\t", "a/.git"] {
            XCTAssertThrowsError(try PathRule(path: "/w/a/c", scope: .tree, operations: [.read], names: [name])) { error in
                XCTAssertEqual(error as? PolicyError, PolicyError("exception name is not a lowercase ASCII component"))
            }
        }
        let pem = try PathRule(path: "/w/a/c", scope: .tree, operations: [.read], names: ["x.pem"])
        XCTAssertTrue(pem.lifts("/w/a/c/d/X.PEM"))
        XCTAssertFalse(pem.lifts("/w/a/c/d/\u{AB70}.pem"))
        XCTAssertFalse(pem.lifts("/w/a/c/d/.git"))
        let sorted = try PathRule(path: "/w/a/c", scope: .tree, operations: [.read], names: [".git", "x.pem", ".env"])
        XCTAssertEqual(sorted.names, [".env", ".git", "x.pem"])
    }

    func testCountersSaturateInsteadOfTrapping() {
        XCTAssertEqual(saturatingAdd(Int64.max, 1), Int64.max)
        XCTAssertEqual(saturatingAdd(Int64.max - 5, 5_000_000_000), Int64.max)
        XCTAssertEqual(saturatingAdd(1, 2), 3)
    }

    func testRetiredSetEvictsOldestFirstAndKeepsPositions() throws {
        var set = RetiredSet()
        let ids = try (1...5).map { try ProcessIdentity(pid: Int32($0), pidVersion: 1) }
        ids.forEach { set.insert($0) }
        set.insert(ids[0])  // already present: keeps its original position
        set.evictOldest()
        XCTAssertFalse(set.contains(ids[0]))
        XCTAssertEqual(set.ordered, Array(ids[1...]))
        for index in 0..<10_000 { set.insert(try ProcessIdentity(pid: 100 + Int32(index), pidVersion: 1)); set.evictOldest() }
        XCTAssertEqual(set.count, 4)
    }
}
