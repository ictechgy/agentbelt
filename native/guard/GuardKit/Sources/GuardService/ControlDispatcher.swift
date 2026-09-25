import Foundation
import GuardCore
import GuardRegistry
import GuardTransport

/// Maps a transport-verified control request onto the registry (R3 preparation).
///
/// The registry authorizes by full process identity (pid + pidversion), while XPC gives
/// File Guard only the peer's PID. `resolve` supplies the pidversion; the default in File
/// Guard will read it with task_name_for_pid (root), which carries the PID-reuse race
/// described in docs/design/native-guard.md until AUTH_XPC_CONNECT (macOS 27) removes it.
public struct ControlDispatcher: Sendable {
    public let clocked: ClockedRegistry
    public let resolve: @Sendable (PeerCredential) -> ProcessIdentity?

    public init(clocked: ClockedRegistry, resolve: @escaping @Sendable (PeerCredential) -> ProcessIdentity?) {
        self.clocked = clocked
        self.resolve = resolve
    }

    public func handle(_ credential: PeerCredential, _ request: ControlRequest) -> ControlReply {
        guard let process = resolve(credential), process.pid == credential.pid else { return .denied("peer_identity_unavailable") }
        let peer = Peer(process: process, signer: credential.signer)
        do {
            // Decode outside the registry lock: every ES event waits on that lock, and a
            // 64 KiB contract takes on the order of a millisecond to parse. A malformed one
            // is refused for any signed peer, which reveals nothing about tasks.
            var contract: TaskContract?
            if case let .propose(data, _) = request { contract = try TaskContract.load(json: data) }
            return .ok(try clocked.run { registry, now in try perform(registry, peer, request, contract, now) })
        } catch let error as RegistryError {
            return .denied(error.reason)  // fixed registry messages, never echoed input
        } catch is PolicyError {
            return .invalid("invalid_contract")
        } catch {
            return .failed("internal_error")
        }
    }

    private func perform(_ registry: Registry, _ peer: Peer, _ request: ControlRequest, _ contract: TaskContract?,
                         _ now: Int64) throws -> Data {
        switch request {
        case let .propose(_, parent):
            return Data(try registry.propose(peer, contract: contract!, parentTaskID: parent, nowNs: now).utf8)
        case let .confirm(digest):
            try registry.confirm(peer, digest: digest, nowNs: now)
        case let .rejectProposal(digest):
            try registry.rejectProposal(peer, digest: digest, nowNs: now)
        case let .revoke(taskID):
            try registry.revoke(peer, taskID: taskID, nowNs: now)
        case let .registerLaunch(taskID, image, child):
            try registry.registerLaunch(peer, taskID: taskID, image: image, child: child, nowNs: now)
        case let .ticketStatus(child):
            return Data(try registry.ticketStatus(peer, child: child, nowNs: now).utf8)
        case .pendingProposals:
            let items = try registry.pendingProposals(peer).map { view -> JSONValue in
                .object(["digest": .string(view.digest), "contract": view.contract.jsonValue,
                         "parent_task_id": view.parentTaskID.map { .string($0) } ?? .null,
                         "proposer_pid": .int(Int64(view.proposer.pid))])
            }
            return Data(CanonicalJSON.encode(.array(items)).utf8)
        case .pendingRequests:
            let items = try registry.pendingRequests(peer).map { request -> JSONValue in
                .object(["request_id": .string(request.requestID), "task_id": .string(request.taskID),
                         "revision": .int(request.revision), "path": .string(request.path),
                         "operations": .array(request.operations.map(\.rawValue).sorted().map { .string($0) })])
            }
            return Data(CanonicalJSON.encode(.array(items)).utf8)
        case let .approveRequest(requestID, expiresAtNs):
            try registry.approveRequest(peer, requestID: requestID, expiresAtNs: expiresAtNs, nowNs: now)
        case let .rejectRequest(requestID):
            try registry.rejectRequest(peer, requestID: requestID, nowNs: now)
        }
        return Data()
    }
}
