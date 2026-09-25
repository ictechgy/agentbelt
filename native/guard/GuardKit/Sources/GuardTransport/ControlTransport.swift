import Foundation
import GuardCore
import XPC

/// Result of one control request. Reasons are fixed codes, never echoed input.
public enum ControlReply: Equatable, Sendable {
    case ok(Data)
    case denied(String)
    case invalid(String)
    case failed(String)

    var fields: [String: FieldValue] {
        switch self {
        case let .ok(payload): return ["status": .string("ok"), "payload": .data(payload)]
        case let .denied(reason): return ["status": .string("denied"), "reason": .string(reason)]
        case let .invalid(reason): return ["status": .string("invalid"), "reason": .string(reason)]
        case let .failed(reason): return ["status": .string("failed"), "reason": .string(reason)]
        }
    }

    init(fields: [String: FieldValue]) {
        switch (fields["status"], fields["payload"], fields["reason"]) {
        case (.string("ok"), .data(let payload)?, nil) where fields.count == 2: self = .ok(payload)
        case (.string("denied"), nil, .string(let reason)?) where fields.count == 2: self = .denied(reason)
        case (.string("invalid"), nil, .string(let reason)?) where fields.count == 2: self = .invalid(reason)
        case (.string("failed"), nil, .string(let reason)?) where fields.count == 2: self = .failed(reason)
        default: self = .failed("malformed_reply")
        }
    }
}

/// Registry side of the control plane. Runs inside the authority (system extension).
///
/// Every peer connection carries an XPC code-signing requirement satisfied by at least
/// one configured signer, so XPC itself drops other senders using the audit token.
/// Each accepted message is then mapped to exactly one signer and a PID, checked by
/// PeerGate, and only then handed to the registry handler.
public final class ControlListener: @unchecked Sendable {
    public typealias Handler = @Sendable (PeerCredential, Role, ControlRequest) -> ControlReply

    private let listener: xpc_connection_t
    private let gate: PeerGate
    private let requirement: @Sendable (Signer) -> String
    private let requireHardenedPeers: Bool
    private let handler: Handler
    private let queue: DispatchQueue

    /// Mach service owned by the system extension (NSEndpointSecurityMachServiceName).
    public convenience init(machServiceName: String, gate: PeerGate,
                            requirement: @escaping @Sendable (Signer) -> String = { CodeRequirement.developerSigned($0) },
                            handler: @escaping Handler) {
        let queue = DispatchQueue(label: "agentbelt.guard.control")
        let connection = xpc_connection_create_mach_service(machServiceName, queue,
                                                            UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        self.init(listener: connection, queue: queue, gate: gate, requirement: requirement,
                  requireHardenedPeers: true, handler: handler)
    }

    /// In-process anonymous listener for tests; clients connect through `endpoint`.
    /// Only tests may relax the hardening check, because the test runner is ad-hoc signed.
    public static func anonymous(gate: PeerGate, requirement: @escaping @Sendable (Signer) -> String,
                                 requireHardenedPeers: Bool = true,
                                 handler: @escaping Handler) -> ControlListener {
        let queue = DispatchQueue(label: "agentbelt.guard.control.anonymous")
        return ControlListener(listener: xpc_connection_create(nil, queue), queue: queue, gate: gate,
                               requirement: requirement, requireHardenedPeers: requireHardenedPeers,
                               handler: handler)
    }

    private init(listener: xpc_connection_t, queue: DispatchQueue, gate: PeerGate,
                 requirement: @escaping @Sendable (Signer) -> String, requireHardenedPeers: Bool,
                 handler: @escaping Handler) {
        self.listener = listener
        self.queue = queue
        self.gate = gate
        self.requirement = requirement
        self.requireHardenedPeers = requireHardenedPeers
        self.handler = handler
    }

    public var endpoint: xpc_endpoint_t { xpc_endpoint_create(listener) }

    public func start() {
        let combined = gate.policy.combinedRequirement(requirement)
        xpc_connection_set_event_handler(listener) { [weak self] peer in
            guard let self, xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
            self.accept(peer, requirement: combined)
        }
        xpc_connection_resume(listener)
    }

    public func cancel() { xpc_connection_cancel(listener) }

    private func accept(_ peer: xpc_connection_t, requirement combined: String) {
        guard xpc_connection_set_peer_code_signing_requirement(peer, combined) == 0 else {
            // An invalid requirement must never mean "no requirement".
            xpc_connection_cancel(peer)
            return
        }
        // One serial queue for every peer: the registry behind the handler is not re-entrant.
        xpc_connection_set_target_queue(peer, queue)
        // Lives as long as the peer's event handler, i.e. the connection.
        let connection = PeerConnection()
        xpc_connection_set_event_handler(peer) { [weak self] message in
            guard let self, xpc_get_type(message) == XPC_TYPE_DICTIONARY else { return }
            let reply = self.handle(message, from: peer, connection: connection)
            guard let response = xpc_dictionary_create_reply(message) else { return }
            for (key, value) in reply.fields {
                switch value {
                case let .string(text): xpc_dictionary_set_string(response, key, text)
                case let .data(payload):
                    payload.withUnsafeBytes { buffer in
                        xpc_dictionary_set_data(response, key, buffer.baseAddress ?? UnsafeRawPointer(bitPattern: 1)!, buffer.count)
                    }
                case let .int64(number): xpc_dictionary_set_int64(response, key, number)
                }
            }
            xpc_connection_send_message(peer, response)
        }
        xpc_connection_resume(peer)
    }

    func handle(_ message: xpc_object_t, from peer: xpc_connection_t, connection: PeerConnection) -> ControlReply {
        guard let code = CodeIdentity.sender(of: message),
              let signer = CodeIdentity.signer(of: code, candidates: gate.policy.allSigners,
                                               requirement: requirement) else {
            return .denied("unknown_signer")
        }
        if requireHardenedPeers, let violation = CodeIdentity.hardeningViolation(of: code) {
            return .denied(violation.rawValue)
        }
        let credential = PeerCredential(pid: xpc_connection_get_pid(peer), signer: signer, connection: connection)
        guard let fields = XPCFields.decode(message) else { return .invalid("malformed_message") }
        let request: ControlRequest
        do { request = try ControlRequest.parse(fields) } catch { return .invalid("malformed_request") }
        switch gate.authorize(credential, request.operation) {
        case let .deny(reason): return .denied(reason)
        case let .allow(role): return handler(credential, role, request)
        }
    }
}

/// Supervisor or approver side. The server must satisfy `serverRequirement`, so a
/// look-alike service registered by another process cannot receive requests.
public final class ControlClient: @unchecked Sendable {
    private let connection: xpc_connection_t

    public convenience init(machServiceName: String, serverRequirement: String) throws {
        let connection = xpc_connection_create_mach_service(machServiceName, nil,
                                                            UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        try self.init(connection: connection, serverRequirement: serverRequirement)
    }

    public convenience init(endpoint: xpc_endpoint_t, serverRequirement: String) throws {
        try self.init(connection: xpc_connection_create_from_endpoint(endpoint), serverRequirement: serverRequirement)
    }

    private init(connection: xpc_connection_t, serverRequirement: String) throws {
        guard xpc_connection_set_peer_code_signing_requirement(connection, serverRequirement) == 0 else {
            throw GuardError("invalid server requirement")
        }
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_resume(connection)
        self.connection = connection
    }

    /// Waits at most `timeout`; a hung File Guard yields `failed("timeout")`, never a hang.
    public func send(_ request: ControlRequest, timeout: DispatchTimeInterval = .seconds(10)) -> ControlReply {
        let box = ReplyBox()
        let done = DispatchSemaphore(value: 0)
        xpc_connection_send_message_with_reply(connection, XPCFields.encode(request.fields()), nil) { reply in
            if xpc_get_type(reply) == XPC_TYPE_DICTIONARY,
               let fields = XPCFields.decode(reply, maxDataBytes: XPCFields.maxReplyDataBytes) {
                box.set(ControlReply(fields: fields))
            } else {
                box.set(.failed("transport_error"))
            }
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else { return .failed("timeout") }
        return box.value ?? .failed("transport_error")
    }

    public func cancel() { xpc_connection_cancel(connection) }
}

private final class ReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: ControlReply?
    var value: ControlReply? { lock.lock(); defer { lock.unlock() }; return stored }
    func set(_ reply: ControlReply) { lock.lock(); stored = reply; lock.unlock() }
}
