import Foundation
import XCTest
import GuardCore
@testable import GuardService

final class PeerIdentityResolverTests: XCTestCase {
    private let signer = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
    private func id(_ pid: Int32, _ version: Int32) -> ProcessIdentity { try! ProcessIdentity(pid: pid, pidVersion: version) }

    private func resolver(live: [Int32: ProcessIdentity]) -> PeerIdentityResolver {
        PeerIdentityResolver(serviceName: "TEAM000001.dev.agentbelt.fileguard.control", ttlNs: 1_000,
                             current: { live[$0] })
    }

    func testResolvesOnlyWhenTheConnectEventAndTheLiveProcessAgree() {
        let resolver = resolver(live: [500: id(500, 7)])
        resolver.noteConnect(client: id(500, 7), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 10)
        XCTAssertEqual(resolver.resolve(PeerCredential(pid: 500, signer: signer), nowNs: { 20 }, wait: 0), id(500, 7))
    }

    func testReusedPidOrStaleOrForeignServiceIsRefused() {
        let reused = resolver(live: [500: id(500, 8)])  // the PID now belongs to another process
        reused.noteConnect(client: id(500, 7), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 10)
        XCTAssertNil(reused.resolve(PeerCredential(pid: 500, signer: signer), nowNs: { 20 }, wait: 0))

        let stale = resolver(live: [500: id(500, 7)])
        stale.noteConnect(client: id(500, 7), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 10)
        XCTAssertNil(stale.resolve(PeerCredential(pid: 500, signer: signer), nowNs: { 5_000 }, wait: 0))

        let foreign = resolver(live: [500: id(500, 7)])
        foreign.noteConnect(client: id(500, 7), service: "com.example.other", nowNs: 10)
        XCTAssertNil(foreign.resolve(PeerCredential(pid: 500, signer: signer), nowNs: { 20 }, wait: 0))

        let gone = resolver(live: [:])  // the sender exited before resolution
        gone.noteConnect(client: id(500, 7), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 10)
        XCTAssertNil(gone.resolve(PeerCredential(pid: 500, signer: signer), nowNs: { 20 }, wait: 0))
    }

    func testResolvedConnectionOutlivesTheTTLButNotAReusedPid() {
        let live = LiveIdentities([500: id(500, 7)])
        let resolver = PeerIdentityResolver(serviceName: "TEAM000001.dev.agentbelt.fileguard.control", ttlNs: 1_000,
                                            current: { live.identity($0) })
        let connection = PeerConnection()
        let credential = PeerCredential(pid: 500, signer: signer, connection: connection)
        resolver.noteConnect(client: id(500, 7), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 10)
        XCTAssertEqual(resolver.resolve(credential, nowNs: { 20 }, wait: 0), id(500, 7))
        XCTAssertEqual(connection.identity, id(500, 7))
        // Long after the TTL, on the same connection: no new notification is needed.
        XCTAssertEqual(resolver.resolve(credential, nowNs: { 1_000_000 }, wait: 0), id(500, 7))
        // A new connection from the same PID still needs its own fresh notification.
        XCTAssertNil(resolver.resolve(PeerCredential(pid: 500, signer: signer, connection: PeerConnection()),
                                      nowNs: { 1_000_000 }, wait: 0))
        // The PID now names another process instance, even with a fresh notification for it.
        live.set(500, id(500, 8))
        resolver.noteConnect(client: id(500, 8), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 1_000_000)
        XCTAssertNil(resolver.resolve(credential, nowNs: { 1_000_001 }, wait: 0))
        XCTAssertEqual(connection.identity, id(500, 7))  // the binding is never replaced
    }

    func testWaitsForANotificationThatArrivesAfterTheMessage() {
        let resolver = resolver(live: [500: id(500, 7)])
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) {
            resolver.noteConnect(client: self.id(500, 7), service: "TEAM000001.dev.agentbelt.fileguard.control", nowNs: 10)
        }
        XCTAssertEqual(resolver.resolve(PeerCredential(pid: 500, signer: signer), nowNs: { 20 }, wait: 1), id(500, 7))
        let never = self.resolver(live: [501: id(501, 1)])
        XCTAssertNil(never.resolve(PeerCredential(pid: 501, signer: signer), nowNs: { 20 }, wait: 0.05))
    }
}

/// PID table the test can change between resolutions.
private final class LiveIdentities: @unchecked Sendable {
    private let lock = NSLock()
    private var table: [Int32: ProcessIdentity]

    init(_ table: [Int32: ProcessIdentity]) { self.table = table }

    func identity(_ pid: Int32) -> ProcessIdentity? { lock.lock(); defer { lock.unlock() }; return table[pid] }
    func set(_ pid: Int32, _ identity: ProcessIdentity) { lock.lock(); table[pid] = identity; lock.unlock() }
}
