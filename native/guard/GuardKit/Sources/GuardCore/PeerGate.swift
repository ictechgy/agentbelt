import Foundation

/// Caller facts produced by the transport, never by message contents.
///
/// The public XPC API exposes the peer's code signature (checked against its audit
/// token) and its PID, but not its pidversion. The enrollment check below is
/// therefore PID-based; see docs/design/native-guard.md for the residual race.
public struct PeerCredential: Equatable, Sendable {
    public let pid: Int32
    public let signer: Signer
    /// The XPC connection the message arrived on; nil outside the transport.
    public let connection: PeerConnection?

    public init(pid: Int32, signer: Signer, connection: PeerConnection? = nil) {
        self.pid = pid
        self.signer = signer
        self.connection = connection
    }

    public static func == (lhs: PeerCredential, rhs: PeerCredential) -> Bool {
        lhs.pid == rhs.pid && lhs.signer == rhs.signer && lhs.connection === rhs.connection
    }
}

/// One slot per accepted XPC peer connection, created by the transport and released with
/// the connection. NOTIFY_XPC_CONNECT fires once per connection, so the peer's full
/// identity is bound here on the first resolved message and reused for later ones.
public final class PeerConnection: @unchecked Sendable {
    private let lock = NSLock()
    private var bound: ProcessIdentity?

    public init() {}

    public var identity: ProcessIdentity? {
        lock.lock()
        defer { lock.unlock() }
        return bound
    }

    /// The first binding wins: a connection belongs to one process instance for its life.
    public func bind(_ identity: ProcessIdentity) {
        lock.lock()
        if bound == nil { bound = identity }
        lock.unlock()
    }
}

/// Answers whether a live bound or quarantined process currently holds this PID.
public protocol EnrollmentOracle: Sendable {
    func isEnrolled(pid: Int32) -> Bool
}

public enum GateDecision: Equatable, Sendable {
    case allow(Role)
    case deny(String)
}

/// Role check shared by the system extension and tests. Mirrors Registry._authorize.
public struct PeerGate: Sendable {
    public let policy: TrustPolicy
    public let oracle: any EnrollmentOracle

    public init(policy: TrustPolicy, oracle: any EnrollmentOracle) {
        self.policy = policy
        self.oracle = oracle
    }

    public func authorize(_ peer: PeerCredential, _ operation: ControlOperation) -> GateDecision {
        guard peer.pid > 0 else { return .deny("invalid_peer") }
        // Lineage outranks signature: an agent may execute our signed binaries.
        if oracle.isEnrolled(pid: peer.pid) { return .deny("enrolled_peer") }
        guard let role = policy.role(of: peer.signer) else { return .deny("unknown_signer") }
        return operation.permittedRoles.contains(role) ? .allow(role) : .deny("role_not_permitted")
    }
}
