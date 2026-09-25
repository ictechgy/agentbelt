import Foundation

/// Kernel process instance: audit-token PID plus pidversion (a new pidversion on fork and exec).
/// The pidversion is opaque: after 2^31 processes in one boot it reads negative as Int32,
/// and rejecting it then would drop an enrolled process out of enforcement.
public struct ProcessIdentity: Hashable, Sendable {
    public let pid: Int32
    public let pidVersion: Int32

    public init(pid: Int32, pidVersion: Int32) throws {
        guard pid > 0 else { throw GuardError("invalid process identity") }
        self.pid = pid
        self.pidVersion = pidVersion
    }
}

/// Executable path plus its code identity (the cdhash in the native adapter).
///
/// Equality and hashing use the UTF-8 bytes of the path. Swift's String equality treats
/// canonically equivalent spellings (NFC/NFD) as equal; the policy model does not.
public struct ExecutableImage: Hashable, Sendable {
    public let path: String
    public let digest: String

    public static func == (lhs: ExecutableImage, rhs: ExecutableImage) -> Bool {
        lhs.path.utf8.elementsEqual(rhs.path.utf8) && lhs.digest.utf8.elementsEqual(rhs.digest.utf8)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(Array(path.utf8))
        hasher.combine(Array(digest.utf8))
    }

    public init(path: String, digest: String) throws {
        guard Validate.canonicalPath(path), Validate.identifier(digest) else {
            throw GuardError("invalid executable image")
        }
        self.path = path
        self.digest = digest
    }
}

public enum ControlLimits {
    public static let version: Int64 = 1
    public static let maxContractBytes = 65536
}

/// Typed XPC dictionary value. Anything else in a message is rejected by the transport.
public enum FieldValue: Equatable, Sendable {
    case string(String)
    case int64(Int64)
    case data(Data)
}

public enum ControlOperation: String, CaseIterable, Sendable {
    case propose, confirm, rejectProposal = "reject_proposal", revoke
    case registerLaunch = "register_launch", ticketStatus = "ticket_status"
    case pendingProposals = "pending_proposals", pendingRequests = "pending_requests"
    case approveRequest = "approve_request", rejectRequest = "reject_request"

    /// Mirrors task_registry.py: supervisors propose and launch; approvers confirm and grant.
    public var permittedRoles: Set<Role> {
        switch self {
        case .propose, .registerLaunch, .ticketStatus: return [.supervisor]
        case .revoke: return [.supervisor, .approver]
        case .confirm, .rejectProposal, .pendingProposals, .pendingRequests, .approveRequest, .rejectRequest:
            return [.approver]
        }
    }
}

/// One control-plane request. It carries no peer identity: the transport supplies that.
public enum ControlRequest: Equatable, Sendable {
    case propose(contract: Data, parentTaskID: String?)
    case confirm(digest: String)
    case rejectProposal(digest: String)
    case revoke(taskID: String)
    case registerLaunch(taskID: String, image: ExecutableImage, child: ProcessIdentity)
    case ticketStatus(child: ProcessIdentity)
    case pendingProposals
    case pendingRequests
    case approveRequest(requestID: String, expiresAtNs: Int64)
    case rejectRequest(requestID: String)

    public var operation: ControlOperation {
        switch self {
        case .propose: return .propose
        case .confirm: return .confirm
        case .rejectProposal: return .rejectProposal
        case .revoke: return .revoke
        case .registerLaunch: return .registerLaunch
        case .ticketStatus: return .ticketStatus
        case .pendingProposals: return .pendingProposals
        case .pendingRequests: return .pendingRequests
        case .approveRequest: return .approveRequest
        case .rejectRequest: return .rejectRequest
        }
    }

    public func fields() -> [String: FieldValue] {
        var fields: [String: FieldValue] = ["v": .int64(ControlLimits.version), "op": .string(operation.rawValue)]
        switch self {
        case let .propose(contract, parent):
            fields["contract"] = .data(contract)
            if let parent { fields["parent"] = .string(parent) }
        case let .confirm(digest), let .rejectProposal(digest):
            fields["digest"] = .string(digest)
        case let .revoke(task):
            fields["task"] = .string(task)
        case let .registerLaunch(task, image, child):
            fields["task"] = .string(task)
            fields["image_path"] = .string(image.path)
            fields["image_digest"] = .string(image.digest)
            fields.merge(Self.childFields(child)) { $1 }
        case let .ticketStatus(child):
            fields.merge(Self.childFields(child)) { $1 }
        case .pendingProposals, .pendingRequests:
            break
        case let .approveRequest(request, expires):
            fields["request"] = .string(request)
            fields["expires_ns"] = .int64(expires)
        case let .rejectRequest(request):
            fields["request"] = .string(request)
        }
        return fields
    }

    private static func childFields(_ child: ProcessIdentity) -> [String: FieldValue] {
        ["child_pid": .int64(Int64(child.pid)), "child_pidversion": .int64(Int64(child.pidVersion))]
    }

    /// Strict decoding: exact key set per operation, exact types, bounded sizes.
    public static func parse(_ fields: [String: FieldValue]) throws -> ControlRequest {
        let reader = FieldReader(fields)
        guard try reader.int64("v") == ControlLimits.version else { throw GuardError("unsupported version") }
        guard let operation = ControlOperation(rawValue: try reader.string("op")) else {
            throw GuardError("unknown operation")
        }
        let request = try decode(operation, reader)
        try reader.requireConsumedAll()
        return request
    }

    private static func decode(_ operation: ControlOperation, _ reader: FieldReader) throws -> ControlRequest {
        switch operation {
        case .propose:
            let contract = try reader.data("contract")
            guard (1...ControlLimits.maxContractBytes).contains(contract.count) else { throw GuardError("invalid contract size") }
            return .propose(contract: contract, parentTaskID: try reader.optionalIdentifier("parent"))
        case .confirm: return .confirm(digest: try reader.digest("digest"))
        case .rejectProposal: return .rejectProposal(digest: try reader.digest("digest"))
        case .revoke: return .revoke(taskID: try reader.identifier("task"))
        case .registerLaunch:
            let image = try ExecutableImage(path: try reader.string("image_path"), digest: try reader.string("image_digest"))
            return .registerLaunch(taskID: try reader.identifier("task"), image: image, child: try reader.child())
        case .ticketStatus: return .ticketStatus(child: try reader.child())
        case .pendingProposals: return .pendingProposals
        case .pendingRequests: return .pendingRequests
        case .approveRequest:
            let expires = try reader.int64("expires_ns")
            guard expires >= 0 else { throw GuardError("invalid expiry") }
            return .approveRequest(requestID: try reader.identifier("request"), expiresAtNs: expires)
        case .rejectRequest: return .rejectRequest(requestID: try reader.identifier("request"))
        }
    }
}

/// Tracks which keys were read so unknown or extra keys are rejected.
private final class FieldReader {
    private let fields: [String: FieldValue]
    private var consumed: Set<String> = []

    init(_ fields: [String: FieldValue]) { self.fields = fields }

    private func value(_ key: String) throws -> FieldValue {
        guard let value = fields[key] else { throw GuardError("missing field") }
        consumed.insert(key)
        return value
    }

    func string(_ key: String) throws -> String {
        guard case let .string(value) = try value(key) else { throw GuardError("mistyped field") }
        return value
    }

    func int64(_ key: String) throws -> Int64 {
        guard case let .int64(value) = try value(key) else { throw GuardError("mistyped field") }
        return value
    }

    func data(_ key: String) throws -> Data {
        guard case let .data(value) = try value(key) else { throw GuardError("mistyped field") }
        return value
    }

    func identifier(_ key: String) throws -> String {
        let value = try string(key)
        guard Validate.identifier(value) else { throw GuardError("invalid identifier") }
        return value
    }

    func optionalIdentifier(_ key: String) throws -> String? {
        fields[key] == nil ? nil : try identifier(key)
    }

    func digest(_ key: String) throws -> String {
        let value = try string(key)
        guard Validate.sha256Hex(value) else { throw GuardError("invalid digest") }
        return value
    }

    func child() throws -> ProcessIdentity {
        let pid = try int64("child_pid"), version = try int64("child_pidversion")
        guard let pid32 = Int32(exactly: pid), let version32 = Int32(exactly: version) else {
            throw GuardError("invalid process identity")
        }
        return try ProcessIdentity(pid: pid32, pidVersion: version32)
    }

    func requireConsumedAll() throws {
        guard Set(fields.keys) == consumed else { throw GuardError("unexpected field") }
    }
}
