// The control plane end to end without XPC: typed requests -> dispatcher -> registry.
import Foundation
import XCTest
import GuardCore
import GuardRegistry
import GuardTransport
@testable import GuardService

private let supervisor = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
private let approver = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.approver")

private final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int64 = 100
    func next() -> Int64 { lock.lock(); defer { lock.unlock() }; value += 1; return value }
}

final class ControlDispatcherTests: XCTestCase {
    private var registry: Registry!
    private var dispatcher: ControlDispatcher!
    private let clock = Clock()
    private let supervisorPeer = PeerCredential(pid: 500, signer: supervisor)
    private let approverPeer = PeerCredential(pid: 600, signer: approver)
    private let contract = Data("""
        {"schema_version":2,"task_id":"ta","revision":1,"workspace":"/w/a","valid_from_ns":0,"expires_at_ns":100000,
         "allow":[{"path":"/w/a","scope":"tree","operations":["read"]}],"deny":[],
         "external":[{"path":"/usr","scope":"tree","operations":["execute","read"]}]}
        """.utf8)

    override func setUpWithError() throws {
        registry = try Registry(config: try RegistryConfig(supervisors: [supervisor], approvers: [approver]),
                                bootID: "boot-1", nowNs: 100)
        let clock = self.clock
        // Test resolver: fixed pidversion 1 for every PID.
        dispatcher = ControlDispatcher(clocked: ClockedRegistry(registry: registry, clock: { clock.next() }),
                                       resolve: { try? ProcessIdentity(pid: $0.pid, pidVersion: 1) })
    }

    private func payload(_ reply: ControlReply) throws -> String {
        guard case let .ok(data) = reply else { throw GuardError("unexpected reply \(reply)") }
        return String(decoding: data, as: UTF8.self)
    }

    func testProposeConfirmLaunchFlowThroughTheDispatcher() throws {
        let digest = try payload(dispatcher.handle(supervisorPeer, .propose(contract: contract, parentTaskID: nil)))
        XCTAssertTrue(Validate.sha256Hex(digest))
        let pending = try payload(dispatcher.handle(approverPeer, .pendingProposals))
        XCTAssertTrue(pending.contains(digest) && pending.contains("\"external\""))
        XCTAssertEqual(dispatcher.handle(approverPeer, .confirm(digest: digest)), .ok(Data()))
        let child = try ProcessIdentity(pid: 3000, pidVersion: 1)
        registry.onFork(parent: try ProcessIdentity(pid: 500, pidVersion: 1), child: child, nowNs: clock.next())
        let image = try ExecutableImage(path: "/opt/agent", digest: "cd")
        XCTAssertEqual(dispatcher.handle(supervisorPeer, .registerLaunch(taskID: "ta", image: image, child: child)),
                       .ok(Data()))
        XCTAssertEqual(try payload(dispatcher.handle(supervisorPeer, .ticketStatus(child: child))), "pending")
    }

    func testRegistryRefusalsBecomeFixedDenials() {
        XCTAssertEqual(dispatcher.handle(supervisorPeer, .confirm(digest: String(repeating: "a", count: 64))),
                       .denied("peer not authorized"))
        XCTAssertEqual(dispatcher.handle(approverPeer, .confirm(digest: String(repeating: "a", count: 64))),
                       .denied("unknown proposal"))
        XCTAssertEqual(dispatcher.handle(supervisorPeer, .propose(contract: Data("{}".utf8), parentTaskID: nil)),
                       .invalid("invalid_contract"))
    }

    func testConcurrentControlAndEventsNeverSeeARegressedClock() throws {
        // A real monotonic clock, read by many threads: ordering is fixed by ClockedRegistry.
        let clocked = ClockedRegistry(registry: registry, clock: { Int64(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) })
        let concurrent = ControlDispatcher(clocked: clocked, resolve: { try? ProcessIdentity(pid: $0.pid, pidVersion: 1) })
        let failures = Counter()
        DispatchQueue.concurrentPerform(iterations: 8) { thread in
            for index in 0..<500 {
                if thread % 2 == 0 {
                    if concurrent.handle(self.approverPeer, .pendingRequests) != .ok(Data("[]".utf8)) { failures.add() }
                } else {
                    let outcome = clocked.run { registry, now in
                        registry.authorizeFile(process: try! ProcessIdentity(pid: 9000 + Int32(thread), pidVersion: Int32(index)),
                                               parent: nil, path: "/tmp/x", operations: ["read"], nowNs: now)
                    }
                    if outcome.reason == "clock_regression" { failures.add() }
                }
            }
        }
        XCTAssertEqual(failures.value, 0)
    }

    func testUnresolvablePeerIdentityIsDenied() {
        let clocked = ClockedRegistry(registry: registry, clock: { 1 })
        let blind = ControlDispatcher(clocked: clocked, resolve: { _ in nil })
        XCTAssertEqual(blind.handle(supervisorPeer, .pendingRequests), .denied("peer_identity_unavailable"))
        let mismatched = ControlDispatcher(clocked: clocked, resolve: { _ in try? ProcessIdentity(pid: 9, pidVersion: 1) })
        XCTAssertEqual(mismatched.handle(supervisorPeer, .pendingRequests), .denied("peer_identity_unavailable"))
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var value = 0
    func add() { lock.lock(); value += 1; lock.unlock() }
}
