import EndpointSecurity
import Foundation
import GuardCore
import SpawnGate

/// One lineage fact from a kernel event, in the registry's process-identity terms.
enum LineageEvent: Equatable {
    case fork(parent: ProcessIdentity, child: ProcessIdentity)
    case exec(process: ProcessIdentity, target: ProcessIdentity)
    case exit(process: ProcessIdentity)
}

enum ESAdapter {
    static func identity(_ token: audit_token_t) -> ProcessIdentity? {
        var token = token
        var pid: Int32 = 0, version: Int32 = 0
        agb_token_identity(&token, &pid, &version)
        return try? ProcessIdentity(pid: pid, pidVersion: version)
    }

    /// Maps the NOTIFY events the skeleton subscribes to. For exec, message.process is
    /// the pre-exec image and event.exec.target the new one (R3 assumption 2 checks this).
    static func lineageEvent(_ message: UnsafePointer<es_message_t>) -> LineageEvent? {
        let event = message.pointee
        guard let subject = identity(event.process.pointee.audit_token) else { return nil }
        switch event.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            return identity(event.event.fork.child.pointee.audit_token).map { .fork(parent: subject, child: $0) }
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            return identity(event.event.exec.target.pointee.audit_token).map { .exec(process: subject, target: $0) }
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return .exit(process: subject)
        default:
            return nil
        }
    }
}

/// Skeleton sink: counts lineage events and keeps nothing else. No path, argv,
/// environment or process identity is stored, per the ES development brief.
final class LineageObserver: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]

    func observe(_ message: UnsafePointer<es_message_t>) {
        guard let event = ESAdapter.lineageEvent(message) else { return }
        let key: String
        switch event {
        case .fork: key = "fork"
        case .exec: key = "exec"
        case .exit: key = "exit"
        }
        lock.lock()
        counts[key, default: 0] += 1
        lock.unlock()
    }
}

/// The registry is not ported to Swift yet, so nothing is enrolled and every control
/// request is refused by the handler in main.swift.
struct NoRegistryYet: EnrollmentOracle {
    func isEnrolled(pid: Int32) -> Bool { false }
}
