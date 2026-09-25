// In-process XPC round trips over an anonymous listener. The test binary is ad-hoc
// signed, so "trusted" signers are expressed as requirements on its own cdhash.
import Foundation
import XCTest
import XPC
import GuardCore
@testable import GuardTransport

private struct NoEnrollment: EnrollmentOracle {
    let enrolled: Set<Int32>
    func isEnrolled(pid: Int32) -> Bool { enrolled.contains(pid) }
}

final class GuardTransportTests: XCTestCase {
    private let supervisor = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
    private let approver = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.approver")
    private let unreachable = "identifier \"dev.agentbelt.never\" and anchor apple generic"

    private func listener(selfIs signer: Signer?, enrolled: Set<Int32> = [], hardened: Bool = false,
                          reply: @escaping @Sendable (Role) -> ControlReply = { .ok(Data($0.rawValue.utf8)) },
                          seen: @escaping @Sendable (PeerCredential, Role, ControlRequest) -> Void = { _, _, _ in })
        throws -> ControlListener {
        let own = "cdhash H\"\(try CodeIdentity.cdhashOfSelf())\""
        let unreachable = self.unreachable
        let gate = PeerGate(policy: try TrustPolicy(supervisors: [supervisor], approvers: [approver]),
                            oracle: NoEnrollment(enrolled: enrolled))
        // The ad-hoc test runner has no hardened runtime, so most tests relax that check.
        let listener = ControlListener.anonymous(gate: gate, requirement: { $0 == signer ? own : unreachable },
                                                 requireHardenedPeers: hardened) { peer, role, request in
            seen(peer, role, request)
            return reply(role)
        }
        listener.start()
        return listener
    }

    private func client(_ listener: ControlListener, serverRequirement: String? = nil) throws -> ControlClient {
        let requirement = try serverRequirement ?? "cdhash H\"\(CodeIdentity.cdhashOfSelf())\""
        return try ControlClient(endpoint: listener.endpoint, serverRequirement: requirement)
    }

    func testTrustedPeerReachesTheHandlerWithTransportDerivedIdentity() throws {
        let received = Captured()
        let server = try listener(selfIs: supervisor, seen: { peer, role, request in received.set(peer, role, request) })
        defer { server.cancel() }
        let reply = try client(server).send(.revoke(taskID: "task-a"))
        XCTAssertEqual(reply, .ok(Data("supervisor".utf8)))
        let (peer, role, request) = try XCTUnwrap(received.value)
        XCTAssertEqual(peer.pid, getpid())
        XCTAssertEqual(peer.signer, supervisor)
        XCTAssertEqual(role, .supervisor)
        XCTAssertEqual(request, .revoke(taskID: "task-a"))
    }

    func testEachConnectionKeepsOneSlotAcrossItsMessages() throws {
        let received = Captured()
        let server = try listener(selfIs: supervisor, seen: { peer, role, request in received.set(peer, role, request) })
        defer { server.cancel() }
        let first = try client(server)
        _ = first.send(.revoke(taskID: "task-a"))
        let slot = try XCTUnwrap(received.value?.0.connection)
        _ = first.send(.revoke(taskID: "task-a"))
        XCTAssertTrue(try XCTUnwrap(received.value?.0.connection) === slot)
        _ = try client(server).send(.revoke(taskID: "task-a"))
        XCTAssertFalse(try XCTUnwrap(received.value?.0.connection) === slot)
    }

    func testRoleIsCheckedAfterSignerResolution() throws {
        let server = try listener(selfIs: supervisor)
        defer { server.cancel() }
        XCTAssertEqual(try client(server).send(.confirm(digest: String(repeating: "a", count: 64))),
                       .denied("role_not_permitted"))
    }

    func testUntrustedPeerIsDroppedByXPCBeforeAnyHandler() throws {
        let received = Captured()
        let server = try listener(selfIs: nil, seen: { peer, role, request in received.set(peer, role, request) })
        defer { server.cancel() }
        // How the refusal reaches the client differs by OS: macOS 26 reports a connection error,
        // while the macOS 15 CI runner never answered (timeout). Either way it must fail and
        // the handler must never see the request.
        let reply = try client(server).send(.revoke(taskID: "task-a"), timeout: .seconds(3))
        XCTAssertTrue([.failed("transport_error"), .failed("timeout")].contains(reply), "\(reply)")
        XCTAssertNil(received.value)
    }

    func testEnrolledPidIsDeniedEvenWithATrustedSignature() throws {
        let server = try listener(selfIs: approver, enrolled: [getpid()])
        defer { server.cancel() }
        XCTAssertEqual(try client(server).send(.pendingRequests), .denied("enrolled_peer"))
    }

    func testMalformedMessagesAreRejectedWithoutEcho() throws {
        let server = try listener(selfIs: supervisor)
        defer { server.cancel() }
        let connection = xpc_connection_create_from_endpoint(server.endpoint)
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_resume(connection)
        defer { xpc_connection_cancel(connection) }
        let marker = "SYNTHETIC-PRIVATE-MARKER"
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "v", 1)
        xpc_dictionary_set_string(message, "op", "revoke")
        xpc_dictionary_set_string(message, "task", marker + " x")
        let reply = xpc_connection_send_message_with_reply_sync(connection, message)
        let fields = try XCTUnwrap(XPCFields.decode(reply))
        XCTAssertEqual(ControlReply(fields: fields), .invalid("malformed_request"))
        let boolMessage = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(boolMessage, "v", true)
        let boolReply = try XCTUnwrap(XPCFields.decode(xpc_connection_send_message_with_reply_sync(connection, boolMessage)))
        XCTAssertEqual(ControlReply(fields: boolReply), .invalid("malformed_message"))
    }

    func testClientRefusesAServerThatDoesNotMatchItsRequirement() throws {
        let received = Captured()
        let server = try listener(selfIs: supervisor, seen: { peer, role, request in received.set(peer, role, request) })
        defer { server.cancel() }
        let reply = try client(server, serverRequirement: unreachable).send(.revoke(taskID: "task-a"))
        XCTAssertEqual(reply, .failed("transport_error"))
    }

    func testUnhardenedPeerIsDeniedWhenHardeningIsRequired() throws {
        XCTAssertEqual(CodeIdentity.hardeningViolationOfSelf(), .noHardenedRuntime)
        let received = Captured()
        let server = try listener(selfIs: supervisor, hardened: true,
                                  seen: { peer, role, request in received.set(peer, role, request) })
        defer { server.cancel() }
        XCTAssertEqual(try client(server).send(.revoke(taskID: "task-a")), .denied("no_hardened_runtime"))
        XCTAssertNil(received.value)
    }

    func testHardenedPlatformBinaryPassesTheHardeningCheck() throws {
        let sleeper = Process()
        sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleeper.arguments = ["5"]
        try sleeper.run()
        defer { sleeper.terminate(); sleeper.waitUntilExit() }
        usleep(100_000)
        XCTAssertNil(CodeIdentity.hardeningViolation(ofPid: sleeper.processIdentifier))
    }

    func testLeadingByteOrderMarkIsRejectedNotStripped() throws {
        let server = try listener(selfIs: supervisor)
        defer { server.cancel() }
        let connection = xpc_connection_create_from_endpoint(server.endpoint)
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_resume(connection)
        defer { xpc_connection_cancel(connection) }
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "v", 1)
        xpc_dictionary_set_string(message, "op", "\u{FEFF}revoke")
        xpc_dictionary_set_string(message, "task", "task-a")
        let fields = try XCTUnwrap(XPCFields.decode(xpc_connection_send_message_with_reply_sync(connection, message)))
        XCTAssertEqual(ControlReply(fields: fields), .invalid("malformed_request"))
    }

    func testRepliesLargerThanOneContractArriveIntact() throws {
        let payload = Data(repeating: 7, count: 300_000)
        let server = try listener(selfIs: approver, reply: { _ in .ok(payload) })
        defer { server.cancel() }
        XCTAssertEqual(try client(server).send(.pendingProposals), .ok(payload))
    }

    func testClientTimesOutInsteadOfHanging() throws {
        let server = try listener(selfIs: supervisor, reply: { _ in usleep(500_000); return .ok(Data()) })
        defer { server.cancel() }
        XCTAssertEqual(try client(server).send(.revoke(taskID: "task-a"), timeout: .milliseconds(100)),
                       .failed("timeout"))
    }

    func testHandlersNeverRunConcurrently() throws {
        let tracker = ConcurrencyTracker()
        let server = try listener(selfIs: supervisor, reply: { _ in
            tracker.enter(); usleep(30_000); tracker.leave(); return .ok(Data())
        })
        defer { server.cancel() }
        let clients = try (0..<4).map { _ in try client(server) }
        DispatchQueue.concurrentPerform(iterations: clients.count) { index in
            _ = clients[index].send(.revoke(taskID: "task-a"))
        }
        XCTAssertEqual(tracker.maximum, 1)
    }

    func testCdhashOfPlatformBinary() throws {
        let hash = try CodeIdentity.cdhash(ofExecutableAt: "/bin/ls")
        XCTAssertEqual(hash.count, 40)
        XCTAssertTrue(hash.allSatisfy { $0.isHexDigit })
        XCTAssertThrowsError(try CodeIdentity.cdhash(ofExecutableAt: "/nonexistent/agentbelt"))
    }
}

private final class Captured: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: (PeerCredential, Role, ControlRequest)?
    var value: (PeerCredential, Role, ControlRequest)? { lock.lock(); defer { lock.unlock() }; return stored }
    func set(_ peer: PeerCredential, _ role: Role, _ request: ControlRequest) {
        lock.lock(); stored = (peer, role, request); lock.unlock()
    }
}

private final class ConcurrencyTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var current = 0
    private(set) var maximum = 0
    func enter() { lock.lock(); current += 1; maximum = max(maximum, current); lock.unlock() }
    func leave() { lock.lock(); current -= 1; lock.unlock() }
}
