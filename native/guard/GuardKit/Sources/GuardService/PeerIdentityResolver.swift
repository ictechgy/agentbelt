import Foundation
import GuardCore

/// Full identity (pid + pidversion) of an XPC control peer, before macOS 27.
///
/// XPC tells File Guard only the peer's PID. Endpoint Security's NOTIFY_XPC_CONNECT
/// (macOS 14+) names the connecting process by audit token. A peer is resolved only when
/// the identity ES reported for a connection to our service equals the identity that PID
/// has right now (a root task_name_for_pid lookup). A PID reused by an unrelated process
/// yields a different pidversion and is refused.
///
/// The notification fires once per connection, and a client keeps one connection for
/// many messages. The TTL therefore only bounds matching a connection's first resolved
/// message to its notification; that identity is then bound to the connection's
/// `PeerConnection` slot. Later messages on it need no notification, but the PID's live
/// identity must still equal the bound one, so a reused PID is refused there too.
///
/// Residual: the original sender exits and its PID is reused, within the TTL, by another
/// process that also connected to this service, before that connection's first message
/// is resolved. That case needs AUTH_XPC_CONNECT (macOS 27), which decides on the
/// connection itself.
public final class PeerIdentityResolver: @unchecked Sendable {
    private let serviceName: String
    private let ttlNs: Int64
    private let current: @Sendable (Int32) -> ProcessIdentity?
    private let condition = NSCondition()
    private var seen: [Int32: (identity: ProcessIdentity, atNs: Int64)] = [:]

    /// - Parameters:
    ///   - current: the identity a PID has now (File Guard: agb_audit_identity as root).
    ///   - ttlNs: how long a connect notification may be used, e.g. 30 s.
    public init(serviceName: String, ttlNs: Int64, current: @escaping @Sendable (Int32) -> ProcessIdentity?) {
        self.serviceName = serviceName
        self.ttlNs = ttlNs
        self.current = current
    }

    /// From the ES NOTIFY_XPC_CONNECT handler. Connections to other services are ignored.
    public func noteConnect(client: ProcessIdentity, service: String, nowNs: Int64) {
        guard service.utf8.elementsEqual(serviceName.utf8) else { return }
        condition.lock()
        seen[client.pid] = (client, nowNs)
        pruneLocked(nowNs)
        condition.broadcast()
        condition.unlock()
    }

    /// A connection with a bound identity is re-checked against the live PID only.
    /// Otherwise waits up to `wait` for the notification, which ES may deliver after the
    /// XPC message, and binds the result to the connection.
    public func resolve(_ credential: PeerCredential, nowNs: @Sendable () -> Int64,
                        wait: TimeInterval = 0.25) -> ProcessIdentity? {
        if let bound = credential.connection?.identity {
            guard bound.pid == credential.pid, let live = current(credential.pid), live == bound else { return nil }
            return live
        }
        let deadline = Date(timeIntervalSinceNow: wait)
        condition.lock()
        defer { condition.unlock() }
        while true {
            if let noted = seen[credential.pid], nowNs() - noted.atNs <= ttlNs {
                // Both sources must name the same process instance.
                guard let live = current(credential.pid), live == noted.identity else { return nil }
                credential.connection?.bind(live)
                return live
            }
            if !condition.wait(until: deadline) { return nil }
        }
    }

    private func pruneLocked(_ nowNs: Int64) {
        if seen.count > 4096 { seen = seen.filter { nowNs - $0.value.atNs <= ttlNs } }
    }
}
