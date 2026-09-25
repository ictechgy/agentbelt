import Foundation
import GuardCore

// Swift port of task_registry.py (R2). Method order, reason codes, error messages and
// record sequences follow the Python reference so the differential tests can replay
// the same scenario through both. Every public entry point takes one lock: File Guard
// calls the event plane from the ES callback queue and the control plane from XPC.

public struct RegistryError: Error, Equatable, CustomStringConvertible {
    public let reason: String
    init(_ reason: String) { self.reason = reason }
    public var description: String { "RegistryError(\(reason))" }
}

func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw RegistryError(message) }
}

public enum RegistryLimits {
    public static let schema = "agentbelt.task-registry"
    public static let maxProposalsPerSupervisor = 16
    public static let maxTicketsPerSupervisor = 8
    public static let maxTasks = 1024
    public static let maxProcesses = 65536
    public static let maxRetired = 65536
    public static let maxStateBytes = 4 * 1024 * 1024
    public static let documentVersion: Int64 = 2
}

public enum TaskState: String, Sendable {
    case active, revoked, interrupted
}

public struct Peer: Equatable, Sendable {
    public let process: ProcessIdentity
    public let signer: Signer
    public init(process: ProcessIdentity, signer: Signer) {
        self.process = process
        self.signer = signer
    }
}

public struct RegistryConfig: Sendable {
    public let supervisors: Set<Signer>
    public let approvers: Set<Signer>
    public let ticketTTLNs: Int64
    public let maxPendingRequests: Int
    public let maxRecords: Int

    public init(supervisors: Set<Signer>, approvers: Set<Signer>, ticketTTLNs: Int64 = 5_000_000_000,
                maxPendingRequests: Int = 32, maxRecords: Int = 1024) throws {
        try require(!supervisors.isEmpty && !approvers.isEmpty, "invalid signer set")
        try require(supervisors.isDisjoint(with: approvers), "supervisor and approver signers overlap")
        try require(ticketTTLNs >= 1 && maxPendingRequests >= 1 && maxRecords >= 1, "invalid limits")
        self.supervisors = supervisors
        self.approvers = approvers
        self.ticketTTLNs = ticketTTLNs
        self.maxPendingRequests = maxPendingRequests
        self.maxRecords = maxRecords
    }
}

/// route: enforced, not_enrolled (unrelated host process) or invalid.
public struct Outcome: Equatable, Sendable {
    public let route: String
    public let allowed: Bool
    public let reason: String
    public let taskID: String?
    public let revision: Int64?
    public var cacheable: Bool { false }
    public var enforcement: String { route == "enforced" ? "policy_only" : "none" }

    init(_ route: String, _ allowed: Bool, _ reason: String, _ taskID: String? = nil, _ revision: Int64? = nil) {
        self.route = route
        self.allowed = allowed
        self.reason = reason
        self.taskID = taskID
        self.revision = revision
    }

    static let notEnrolled = Outcome("not_enrolled", true, "not_enrolled")
    static let invalid = Outcome("invalid", false, "invalid_input")
}

public struct ProposalView: Equatable, Sendable {
    public let digest: String
    public let contract: TaskContract
    public let parentTaskID: String?
    public let proposer: ProcessIdentity
}

public struct AccessRequest: Equatable, Sendable {
    public let requestID: String
    public let taskID: String
    public let revision: Int64
    public let path: String
    public let operations: Set<FileOperation>

    public static func == (lhs: AccessRequest, rhs: AccessRequest) -> Bool {
        lhs.requestID == rhs.requestID && lhs.taskID == rhs.taskID && lhs.revision == rhs.revision
            && PathBytes.equal(lhs.path, rhs.path) && lhs.operations == rhs.operations
    }
}

public struct ActionRecord: Equatable, Sendable {
    public let sequence: Int64
    public let event: String
    public let taskID: String?
    public let revision: Int64?
    public let allowed: Bool
    public let reason: String
    public let operations: [String]
    public let target: String
}

final class RegistryTask {
    var contract: TaskContract
    let parentTaskID: String?
    var state: TaskState
    let owner: ProcessIdentity

    init(contract: TaskContract, parentTaskID: String?, state: TaskState, owner: ProcessIdentity) {
        self.contract = contract
        self.parentTaskID = parentTaskID
        self.state = state
        self.owner = owner
    }
}

struct Grant {
    let revision: Int64
    let rule: PathRule
    let expiresAtNs: Int64
}

final class Ticket {
    let taskID: String
    let image: ExecutableImage
    let spawner: ProcessIdentity
    let expiresAtNs: Int64
    var state: String

    init(taskID: String, image: ExecutableImage, spawner: ProcessIdentity, expiresAtNs: Int64, state: String) {
        self.taskID = taskID
        self.image = image
        self.spawner = spawner
        self.expiresAtNs = expiresAtNs
        self.state = state
    }
}

/// Insertion-ordered map, standing in for Python's dict where iteration order is observable.
struct OrderedMap<Key: Hashable, Value> {
    private(set) var keys: [Key] = []
    private var storage: [Key: Value] = [:]

    subscript(key: Key) -> Value? {
        get { storage[key] }
        set {
            if let newValue {
                if storage.updateValue(newValue, forKey: key) == nil { keys.append(key) }
            } else {
                removeValue(forKey: key)
            }
        }
    }

    @discardableResult
    mutating func removeValue(forKey key: Key) -> Value? {
        guard let value = storage.removeValue(forKey: key) else { return nil }
        keys.removeAll { $0 == key }
        return value
    }

    var values: [Value] { keys.map { storage[$0]! } }
    var count: Int { storage.count }
    var first: Key? { keys.first }

    mutating func removeAll(where predicate: (Key, Value) -> Bool) {
        for key in keys where predicate(key, storage[key]!) { removeValue(forKey: key) }
    }
}

func identityKey(_ process: ProcessIdentity) -> (Int32, String) { (process.pid, String(process.pidVersion)) }

func identityLess(_ lhs: ProcessIdentity, _ rhs: ProcessIdentity) -> Bool {
    let (a, b) = (identityKey(lhs), identityKey(rhs))
    return a.0 != b.0 ? a.0 < b.0 : PathBytes.less(a.1, b.1)
}

/// Canonical JSON digest over contract, parent and proposer (task_registry._proposal_digest).
func proposalDigest(_ contract: TaskContract, _ parentTaskID: String?, _ proposer: ProcessIdentity) -> String {
    let document: JSONValue = .object([
        "contract": contract.jsonValue,
        "parent_task_id": parentTaskID.map { .string($0) } ?? .null,
        "proposer": identityJSON(proposer),
    ])
    return sha256Hex(Data(CanonicalJSON.encode(document).utf8))
}

func ruleCovered(_ parent: TaskContract, _ rule: PathRule) -> Bool {
    let granting = parent.allow + parent.external
    return rule.operations.allSatisfy { operation in
        granting.contains { $0.operations.contains(operation) && covers($0, rule) }
    }
}

public final class Registry: @unchecked Sendable {
    let lock = NSLock()
    let config: RegistryConfig
    let bootID: String
    var now: Int64
    var sequence: Int64 = 0
    var requestCounter = 0
    var droppedRecords: Int64 = 0
    var droppedRequests: Int64 = 0
    var droppedRetired: Int64 = 0
    var tasks: [String: RegistryTask] = [:]
    var bindings: [ProcessIdentity: String] = [:]
    var quarantine: Set<ProcessIdentity> = []
    var chains = OrderedMap<ProcessIdentity, ProcessIdentity>()
    var proposals = OrderedMap<String, ProposalView>()
    var tickets: [ProcessIdentity: Ticket] = [:]
    var grants: [String: [Grant]] = [:]
    var requests = OrderedMap<String, AccessRequest>()
    var supervisorProcesses: Set<ProcessIdentity> = []
    var spawned: [ProcessIdentity: ProcessIdentity] = [:]
    /// Exited enrolled identities of this boot. pidversions are unique per boot, so no
    /// unrelated process can name one of them as its parent.
    var retired = RetiredSet()
    var recordRing = RecordRing([])
    /// Write-ahead hook of the durable store (task_registry.Registry `persist`). It receives
    /// the document whenever a launch ticket opens or an exec binds a process, before that
    /// call answers; a thrown error means "not saved" and the call then fails closed. It
    /// runs under the registry lock (and ClockedRegistry's, when called through it), so it
    /// must not call back into this registry: store the document with saveDocument, never
    /// saveRegistry. With a hook, every save goes through it (checkpoint() for periodic
    /// saves), since a second writer could replace a newer document with an older one.
    /// The hook should log why a save failed; the registry only reports that it did.
    let persist: ((JSONValue) throws -> Void)?

    public init(config: RegistryConfig, bootID: String, nowNs: Int64,
                persist: ((JSONValue) throws -> Void)? = nil) throws {
        try require(Validate.identifier(bootID) && policyInteger(nowNs), "invalid boot session or clock")
        self.config = config
        self.bootID = bootID
        self.now = nowNs
        self.persist = persist
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    // MARK: clock, peers and chains

    func advance(_ nowNs: Int64) -> Bool {
        if nowNs < now { return false }
        now = nowNs
        return true
    }

    func controlClock(_ nowNs: Int64) throws {
        try require(policyInteger(nowNs) && advance(nowNs), "invalid or regressed clock")
    }

    func enrolled(_ process: ProcessIdentity) -> Bool { bindings[process] != nil || quarantine.contains(process) }

    func enrolledLineage(_ process: ProcessIdentity) -> Bool { enrolled(process) || retired.contains(process) }

    func retire(_ identity: ProcessIdentity) {
        if retired.count >= RegistryLimits.maxRetired {
            // Eviction reopens the missed-fork-after-parent-exit gap for the oldest entry.
            retired.evictOldest()
            droppedRetired = saturatingAdd(droppedRetired, 1)
        }
        retired.insert(identity)
    }

    func authorize(_ peer: Peer, _ signers: Set<Signer>, _ nowNs: Int64) throws {
        // A signed binary run from inside a task (or lost lineage) is still that task.
        try require(signers.contains(peer.signer) && !enrolled(peer.process), "peer not authorized")
        try controlClock(nowNs)
        if config.supervisors.contains(peer.signer) { supervisorProcesses.insert(peer.process) }
    }

    func bind(_ process: ProcessIdentity, _ taskID: String, _ chain: ProcessIdentity) {
        bindings[process] = taskID
        chains[process] = chain
    }

    func isolate(_ process: ProcessIdentity, _ chain: ProcessIdentity) {
        quarantine.insert(process)
        chains[process] = chain
    }

    /// Write-ahead: hands the current state to the store; false when it was not saved.
    func saved() -> Bool {
        guard let persist else { return true }
        do {
            try persist(document())
            return true
        } catch {
            // Any store failure (I/O, size, encoding) counts as unsaved; callers then deny.
            return false
        }
    }

    /// Binds (process, task, chain) entries only if the store accepts the new state. On
    /// failure they are put back exactly as they were, so a denied exec leaves no binding
    /// behind that the durable state does not have either.
    func bindSaved(_ entries: [(ProcessIdentity, String, ProcessIdentity)]) -> Bool {
        let previous = entries.map { ($0.0, bindings[$0.0], chains[$0.0]) }
        for (process, taskID, chain) in entries { bind(process, taskID, chain) }
        if saved() { return true }
        for (process, taskID, chain) in previous.reversed() {
            bindings[process] = taskID
            chains[process] = chain
        }
        return false
    }

    /// The host's periodic save, through the same hook as write-ahead.
    public func checkpoint() throws {
        try locked {
            try require(persist != nil, "registry has no persist hook")
            try require(saved(), "registry state could not be saved")
        }
    }

    // MARK: control plane: proposals and lifecycle

    public func propose(_ peer: Peer, contract: TaskContract, parentTaskID: String? = nil, nowNs: Int64) throws -> String {
        try locked {
            try authorize(peer, config.supervisors, nowNs)
            try require(parentTaskID.map(Validate.identifier) ?? true, "invalid parent task")
            _ = try checkProposal(contract, parentTaskID, peer.process)
            let digest = proposalDigest(contract, parentTaskID, peer.process)
            try require(proposals[digest] == nil, "duplicate proposal")
            let mine = proposals.values.filter { $0.proposer == peer.process }.count
            try require(mine < RegistryLimits.maxProposalsPerSupervisor, "too many pending proposals")
            proposals[digest] = ProposalView(digest: digest, contract: contract, parentTaskID: parentTaskID,
                                             proposer: peer.process)
            return digest
        }
    }

    func checkProposal(_ contract: TaskContract, _ parentTaskID: String?, _ proposer: ProcessIdentity) throws -> String? {
        let parentID: String?
        if let existing = tasks[contract.taskID] {
            try require(existing.state == .active && existing.owner == proposer, "task not revisable")
            try require(parentTaskID == nil || parentTaskID == existing.parentTaskID, "parent cannot change")
            try require(contract.revision == existing.contract.revision + 1, "revision must advance by one")
            // A lower schema drops v2 rules and regains v1's runtime-exec exception.
            try require(contract.schemaVersion >= existing.contract.schemaVersion, "schema cannot be lowered")
            parentID = existing.parentTaskID
        } else {
            pruneTerminalTasks()
            try require(contract.revision == 1 && tasks.count < RegistryLimits.maxTasks, "invalid new task")
            parentID = parentTaskID
        }
        if let parentID {
            let parent = tasks[parentID]
            try require(parent != nil && parent!.state == .active && parent!.owner == proposer, "parent task not available")
            try require(isAttenuation(parent: parent!.contract, child: contract), "child task exceeds parent")
        }
        return parentID
    }

    public func pendingProposals(_ peer: Peer) throws -> [ProposalView] {
        try locked {
            try checkReader(peer)
            return proposals.values
        }
    }

    public func confirm(_ peer: Peer, digest: String, nowNs: Int64) throws {
        try locked {
            try authorize(peer, config.approvers, nowNs)
            let proposal = Validate.sha256Hex(digest) ? proposals.removeValue(forKey: digest) : nil
            try require(proposal != nil, "unknown proposal")
            let contract = proposal!.contract
            let parentID = try checkProposal(contract, proposal!.parentTaskID, proposal!.proposer)
            if let existing = tasks[contract.taskID] {
                existing.contract = contract
                // Descendant grants were checked against the old parent; drop them conservatively.
                dropTaskAuthority(withDescendants(contract.taskID))
                revokeUncoveredChildren(contract.taskID)
            } else {
                tasks[contract.taskID] = RegistryTask(contract: contract, parentTaskID: parentID, state: .active,
                                                      owner: proposal!.proposer)
            }
            recordLifecycle(contract.taskID, "confirmed")
        }
    }

    public func rejectProposal(_ peer: Peer, digest: String, nowNs: Int64) throws {
        try locked {
            try authorize(peer, config.approvers, nowNs)
            try require(Validate.sha256Hex(digest) && proposals.removeValue(forKey: digest) != nil, "unknown proposal")
        }
    }

    public func revoke(_ peer: Peer, taskID: String, nowNs: Int64) throws {
        try locked {
            try authorize(peer, config.supervisors.union(config.approvers), nowNs)
            // Identifiers are ASCII; checking them keeps Swift's canonical-equivalence
            // lookups (U+212A == "K") from matching a different task.
            try require(Validate.identifier(taskID) && tasks[taskID] != nil, "unknown task")
            setState(withDescendants(taskID), .revoked)
        }
    }

    func withDescendants(_ taskID: String) -> Set<String> {
        var found: Set<String> = [taskID]
        var frontier = [taskID]
        while let current = frontier.popLast() {
            let children = tasks.filter { $0.value.parentTaskID == current && !found.contains($0.key) }.map(\.key)
            found.formUnion(children)
            frontier.append(contentsOf: children)
        }
        return found
    }

    /// The task and its ancestors, nearest first; cycle-safe for restored documents.
    func ancestors(_ taskID: String) -> [RegistryTask] {
        var chain: [String] = []
        var current: String? = taskID
        while let id = current, let task = tasks[id], !chain.contains(id) {
            chain.append(id)
            current = task.parentTaskID
        }
        return chain.map { tasks[$0]! }
    }

    func setState(_ taskIDs: Set<String>, _ state: TaskState) {
        // Interruption never downgrades a revocation.
        for taskID in taskIDs.sorted(by: PathBytes.less) {
            let task = tasks[taskID]!
            if task.state != .revoked && task.state != state {
                task.state = state
                recordLifecycle(taskID, state.rawValue)
            }
        }
        dropTaskAuthority(taskIDs)
    }

    /// Grants, requests and pending launches never outlive the revision they were made for.
    func dropTaskAuthority(_ taskIDs: Set<String>) {
        for taskID in taskIDs { grants.removeValue(forKey: taskID) }
        requests.removeAll { _, request in taskIDs.contains(request.taskID) }
        for ticket in tickets.values where taskIDs.contains(ticket.taskID) && ticket.state == "pending" {
            ticket.state = "revoked"
        }
    }

    func revokeUncoveredChildren(_ parentID: String) {
        let parent = tasks[parentID]!
        for childID in tasks.keys.sorted(by: PathBytes.less) {
            let child = tasks[childID]!
            if child.parentTaskID == parentID && child.state == .active
                && !isAttenuation(parent: parent.contract, child: child.contract) {
                setState(withDescendants(childID), .revoked)
            }
        }
    }

    /// Forget ended tasks nothing refers to, so the task table cannot fill up for good.
    func pruneTerminalTasks() {
        while tasks.count >= RegistryLimits.maxTasks {
            var referenced = Set(bindings.values).union(tasks.values.compactMap(\.parentTaskID))
            referenced.formUnion(tickets.values.map(\.taskID))
            let prunable = tasks.keys.sorted(by: PathBytes.less)
                .filter { tasks[$0]!.state != .active && !referenced.contains($0) }
            if prunable.isEmpty { return }
            for taskID in prunable { tasks.removeValue(forKey: taskID) }
        }
    }

    // MARK: control plane: launches

    public func registerLaunch(_ peer: Peer, taskID: String, image: ExecutableImage, child: ProcessIdentity,
                               nowNs: Int64) throws {
        try locked {
            try authorize(peer, config.supervisors, nowNs)
            let task = Validate.identifier(taskID) ? tasks[taskID] : nil
            try require(task != nil && task!.state == .active && task!.owner == peer.process
                        && task!.contract.validFromNs <= now && now < task!.contract.expiresAtNs, "task not launchable")
            try require(spawned[child] == peer.process && tickets[child] == nil && !enrolled(child),
                        "child not launchable")
            let mine = tickets.values.filter { $0.spawner == peer.process && $0.state == "pending" }.count
            try require(mine < RegistryLimits.maxTicketsPerSupervisor, "too many pending launches")
            let ticket = Ticket(taskID: taskID, image: image, spawner: peer.process,
                                expiresAtNs: saturatingAdd(now, config.ticketTTLNs), state: "pending")
            tickets[child] = ticket
            if !saved() {
                // Unsaved, a restart would forget the ticket and let the waiting child run unbound.
                ticket.state = "revoked"
                throw RegistryError("registry state could not be saved")
            }
        }
    }

    /// none, pending, bound, denied, expired or revoked for one child of this supervisor.
    public func ticketStatus(_ peer: Peer, child: ProcessIdentity, nowNs: Int64) throws -> String {
        try locked {
            try authorize(peer, config.supervisors, nowNs)
            guard let ticket = tickets[child], ticket.spawner == peer.process else { return "none" }
            if ticket.state == "pending" && now >= ticket.expiresAtNs { return "expired" }
            return ticket.state
        }
    }

    // MARK: control plane: access requests and grants

    func checkReader(_ peer: Peer) throws {
        try require(config.approvers.contains(peer.signer) && !enrolled(peer.process), "peer not authorized")
    }

    public func pendingRequests(_ peer: Peer) throws -> [AccessRequest] {
        try locked {
            try checkReader(peer)
            return requests.values
        }
    }

    public func approveRequest(_ peer: Peer, requestID: String, expiresAtNs: Int64, nowNs: Int64) throws {
        try locked {
            try authorize(peer, config.approvers, nowNs)
            let request = Validate.identifier(requestID) ? requests[requestID] : nil
            try require(request != nil, "unknown request")
            let task = tasks[request!.taskID]!
            try require(task.state == .active && task.contract.revision == request!.revision, "task not active")
            try require(policyInteger(expiresAtNs) && now < expiresAtNs && expiresAtNs <= task.contract.expiresAtNs,
                        "invalid grant lifetime")
            let rule = try! PathRule(path: request!.path, scope: .exact, operations: request!.operations)
            // A delegated task's grant may not exceed what every ancestor contract allows.
            let parents = ancestors(request!.taskID).dropFirst()
            try require(parents.allSatisfy { ruleCovered($0.contract, rule) }, "grant exceeds parent task")
            let live = liveGrants(request!.taskID, request!.revision)
            try require(task.contract.allow.count + live.count < PolicyLimits.maxRules, "too many grants")
            grants[request!.taskID] = live + [Grant(revision: request!.revision, rule: rule, expiresAtNs: expiresAtNs)]
            requests.removeValue(forKey: requestID)
            recordLifecycle(request!.taskID, "grant_approved")
        }
    }

    public func rejectRequest(_ peer: Peer, requestID: String, nowNs: Int64) throws {
        try locked {
            try authorize(peer, config.approvers, nowNs)
            try require(Validate.identifier(requestID) && requests.removeValue(forKey: requestID) != nil, "unknown request")
        }
    }

    func liveGrants(_ taskID: String, _ revision: Int64) -> [Grant] {
        (grants[taskID] ?? []).filter { $0.revision == revision && now < $0.expiresAtNs }
    }

    /// Only in-workspace denials are grantable in contract v1; duplicates collapse.
    func queueRequest(_ task: RegistryTask, _ path: String, _ operations: Set<FileOperation>) {
        let contract = task.contract
        guard PathBytes.within(path, contract.workspace) else { return }
        let pending = requests.values.filter { $0.taskID == contract.taskID }
        if pending.contains(where: { PathBytes.equal($0.path, path) && $0.operations == operations }) { return }
        if pending.count >= config.maxPendingRequests {
            droppedRequests = saturatingAdd(droppedRequests, 1)
            return
        }
        requestCounter += 1
        let requestID = "req-\(requestCounter)"
        requests[requestID] = AccessRequest(requestID: requestID, taskID: contract.taskID, revision: contract.revision,
                                            path: path, operations: operations)
    }

    // MARK: event plane

    /// NOTIFY fork: the child inherits the parent's task or quarantine, nothing else.
    public func onFork(parent: ProcessIdentity?, child: ProcessIdentity?, nowNs: Int64) {
        locked {
            guard let parent, let child, policyInteger(nowNs) else { return }
            _ = advance(nowNs)
            if enrolled(child) { return }  // A late or duplicated fork never re-assigns a judged identity.
            if let taskID = bindings[parent] {
                bind(child, taskID, child)
            } else if quarantine.contains(parent) {
                isolate(child, child)
            } else if supervisorProcesses.contains(parent) {
                spawned[child] = parent
            }
        }
    }

    /// AUTH exec. `process` is the pre-exec identity, `target` the identity after exec.
    /// `script` is the #! script when `image` is its interpreter; a bound process needs
    /// execute on both. Ticketed launches ignore it: the supervisor refuses scripts.
    public func onExec(process: ProcessIdentity?, parent: ProcessIdentity?, target: ProcessIdentity?,
                       image: ExecutableImage?, script: String? = nil, nowNs: Int64) -> Outcome {
        locked {
            // exec keeps the PID; a differing target cannot come from the kernel.
            guard let process, let target, process.pid == target.pid, policyInteger(nowNs) else { return .invalid }
            let clockOK = advance(nowNs)
            if bindings[process] != nil { return execBound(process, target, image, script, clockOK) }
            if let ticket = tickets[process] { return execLaunch(process, parent, target, image, ticket, clockOK) }
            let outcome = routeUnbound(process, parent, "exec")
            if outcome == .notEnrolled { spawned.removeValue(forKey: process) }
            return outcome
        }
    }

    /// Bind inside the exec authorization, before the new image runs its first instruction.
    func execLaunch(_ process: ProcessIdentity, _ parent: ProcessIdentity?, _ target: ProcessIdentity,
                    _ image: ExecutableImage?, _ ticket: Ticket, _ clockOK: Bool) -> Outcome {
        let task = tasks[ticket.taskID]
        let refusal = launchRefusal(parent, image, ticket, task, clockOK)
        let revision = task?.contract.revision
        let outcome: Outcome
        if let refusal {
            if ticket.state == "pending" { ticket.state = refusal == "launch_ticket_expired" ? "expired" : "denied" }
            outcome = Outcome("enforced", false, refusal, ticket.taskID, revision)
        } else {
            ticket.state = "denied"  // until the binding is saved; a restart drops it either way
            if bindSaved([(process, ticket.taskID, process), (target, ticket.taskID, process)]) {
                ticket.state = "bound"
                spawned.removeValue(forKey: process)
                outcome = Outcome("enforced", true, "launch_bound", ticket.taskID, revision)
            } else {
                outcome = Outcome("enforced", false, "state_not_saved", ticket.taskID, revision)
            }
        }
        record("launch", outcome, [], ".")
        return outcome
    }

    /// Every failed check denies the exec: a ticketed child never runs unbound.
    func launchRefusal(_ parent: ProcessIdentity?, _ image: ExecutableImage?, _ ticket: Ticket,
                       _ task: RegistryTask?, _ clockOK: Bool) -> String? {
        if ticket.state != "pending" { return "launch_ticket_closed" }
        if !clockOK { return "clock_regression" }
        if now >= ticket.expiresAtNs { return "launch_ticket_expired" }
        if parent != ticket.spawner || image != ticket.image { return "launch_ticket_mismatch" }
        guard let task, task.state == .active, task.contract.validFromNs <= now, now < task.contract.expiresAtNs else {
            return "task_not_active"
        }
        return nil
    }

    func execBound(_ process: ProcessIdentity, _ target: ProcessIdentity, _ image: ExecutableImage?,
                   _ script: String?, _ clockOK: Bool) -> Outcome {
        let taskID = bindings[process]!
        let task = tasks[taskID]!
        guard let image else {
            let outcome = Outcome("enforced", false, "invalid_input", taskID, task.contract.revision)
            record("exec", outcome, ["execute"], "invalid")
            return outcome
        }
        var outcome = execDecision(process, taskID, image.path, clockOK)
        var path = image.path
        if outcome.allowed, let script {
            // The interpreter is allowed; the script it will run needs execute as well.
            let scriptOutcome = execDecision(process, taskID, script, clockOK)
            if !scriptOutcome.allowed { (outcome, path) = (scriptOutcome, script) }
        }
        if outcome.allowed && !bindSaved([(target, taskID, chains[process]!)]) {
            outcome = Outcome("enforced", false, "state_not_saved", taskID, task.contract.revision)
        }
        record("exec", outcome, ["execute"], recordTarget(task, path, outcome))
        return outcome
    }

    func execDecision(_ process: ProcessIdentity, _ taskID: String, _ path: String, _ clockOK: Bool) -> Outcome {
        let task = tasks[taskID]!
        let outcome = decide(process, taskID, path, ["execute"], clockOK)
        if outcome.reason == "outside_allow_scope" && task.contract.schemaVersion == 1
            && outsideLineageWorkspaces(taskID, path) {
            // Contract v1 cannot name runtime executables; v2 must allow them via `external`.
            return Outcome("enforced", true, "exec_outside_contract", outcome.taskID, outcome.revision)
        }
        return outcome
    }

    func outsideLineageWorkspaces(_ taskID: String, _ path: String) -> Bool {
        // A child must not execute parent-workspace files the parent's own rules refuse.
        !ancestors(taskID).contains { PathBytes.within(path, $0.contract.workspace) }
    }

    /// NOTIFY exit: release the exiting identity's exec chain; narrow what it owned.
    public func onExit(process: ProcessIdentity?, nowNs: Int64) {
        locked {
            guard let process, policyInteger(nowNs) else { return }
            _ = advance(nowNs)
            if let chain = chains[process] { releaseChain(chain) }
            tickets.removeValue(forKey: process)
            spawned.removeValue(forKey: process)
            supervisorProcesses.remove(process)
            narrowForExit(process.pid)
        }
    }

    func releaseChain(_ chain: ProcessIdentity) {
        let members = chains.keys.filter { chains[$0] == chain }
        for identity in members {
            chains.removeValue(forKey: identity)
            retire(identity)
            bindings.removeValue(forKey: identity)
            quarantine.remove(identity)
            tickets.removeValue(forKey: identity)
            spawned.removeValue(forKey: identity)
        }
    }

    /// PID-matched and therefore only ever narrowing: a stale exit cannot grant anything.
    func narrowForExit(_ pid: Int32) {
        for ticket in tickets.values where ticket.spawner.pid == pid && ticket.state == "pending" {
            ticket.state = "revoked"
        }
        proposals.removeAll { _, proposal in proposal.proposer.pid == pid }
        let owned = tasks.filter { $0.value.owner.pid == pid && $0.value.state == .active }.map(\.key)
        for taskID in owned.sorted(by: PathBytes.less) { setState(withDescendants(taskID), .interrupted) }
    }

    /// AUTH file access. Only bound processes are evaluated; the rest are routed.
    /// `operations` holds raw names so that unknown ones reach the invalid-input path.
    /// `subtree` marks operations that carry everything below `path` along (rename, clone
    /// or link of a possible directory); they are also denied when a deny rule sits at or
    /// below `path`, which moving the directory would otherwise leave behind.
    public func authorizeFile(process: ProcessIdentity?, parent: ProcessIdentity?, path: String,
                              operations: Set<String>, subtree: Bool = false, nowNs: Int64) -> Outcome {
        locked {
            guard let process, policyInteger(nowNs) else { return .invalid }
            let clockOK = advance(nowNs)
            guard let taskID = bindings[process] else { return routeUnbound(process, parent, "file") }
            let task = tasks[taskID]!
            var outcome = decide(process, taskID, path, operations, clockOK)
            if outcome.allowed && subtree
                && task.contract.deny.contains(where: { [folded = asciiFold(path)] in PathBytes.within($0.foldedPath, folded) }) {
                outcome = Outcome("enforced", false, "explicit_deny_below", outcome.taskID, outcome.revision)
            }
            let parsed = FileAccessOperations(operations)
            if outcome.reason == "outside_allow_scope", let parsed { queueRequest(task, path, parsed) }
            record("file", outcome, parsed.map { $0.map(\.rawValue) } ?? [], recordTarget(task, path, outcome))
            return outcome
        }
    }

    /// Operations on another process (task_registry.PROCESS_OPERATIONS). A task port lets the
    /// holder read or rewrite that process, so an enrolled process may act only on itself and
    /// on processes of its own task. A nil target (none named by the kernel) is outside.
    public static let processOperations: Set<String> = ["task_port", "task_read", "signal", "suspend_resume"]

    public func authorizeProcess(process: ProcessIdentity?, parent: ProcessIdentity?, target: ProcessIdentity?,
                                 operation: String, nowNs: Int64) -> Outcome {
        locked {
            guard let process, Registry.processOperations.contains(operation), policyInteger(nowNs) else { return .invalid }
            _ = advance(nowNs)
            guard let taskID = bindings[process] else { return routeUnbound(process, parent, "process") }
            let revision = tasks[taskID]!.contract.revision
            let outcome = target == process || (target.map { bindings[$0] == taskID } ?? false)
                ? Outcome("enforced", true, "same_task", taskID, revision)
                : Outcome("enforced", false, "process_outside_task", taskID, revision)
            record("process", outcome, [], "process")
            return outcome
        }
    }

    func routeUnbound(_ process: ProcessIdentity, _ parent: ProcessIdentity?, _ event: String) -> Outcome {
        let outcome: Outcome
        if quarantine.contains(process) {
            outcome = Outcome("enforced", false, "tracking_lost")
        } else if let parent, enrolledLineage(parent) {
            // The fork notification was lost or reordered, possibly before the parent exited.
            isolate(process, process)
            outcome = Outcome("enforced", false, "unattributed_descendant")
        } else {
            return .notEnrolled
        }
        record(event, outcome, [], "unattributed")
        return outcome
    }

    func decide(_ process: ProcessIdentity, _ taskID: String, _ path: String, _ operations: Set<String>,
                _ clockOK: Bool) -> Outcome {
        let task = tasks[taskID]!
        let revision = task.contract.revision
        if !clockOK { return Outcome("enforced", false, "clock_regression", taskID, revision) }
        if task.state == .interrupted { return Outcome("enforced", false, "interrupted", taskID, revision) }
        guard Validate.canonicalPath(path), let parsed = FileAccessOperations(operations) else {
            return Outcome("enforced", false, "invalid_input", taskID, revision)
        }
        let revoked = task.state == .revoked
        let decision = evaluate(contract: task.contract, revoked: revoked, path: path, operations: parsed, nowNs: now)
        if decision.reason == "outside_allow_scope" && granted(task, revoked, path, parsed) {
            return Outcome("enforced", true, "granted", taskID, revision)
        }
        return Outcome("enforced", decision.allowed, decision.reason, taskID, revision)
    }

    /// Re-run R1 with live exact grants appended, so sensitive/deny checks still win.
    func granted(_ task: RegistryTask, _ revoked: Bool, _ path: String, _ operations: Set<FileOperation>) -> Bool {
        let rules = liveGrants(task.contract.taskID, task.contract.revision).map(\.rule)
        guard !rules.isEmpty, let widened = try? task.contract.replacingAllow(task.contract.allow + rules) else {
            return false  // approveRequest bounds grants; an invalid combination denies.
        }
        return evaluate(contract: widened, revoked: revoked, path: path, operations: operations, nowNs: now).allowed
    }

    // MARK: records

    /// Reasons that R1 returns only for paths without a sensitive name. ("allowed_by_exception"
    /// and "granted" can name one, so they are checked.)
    static let checkedNotSensitive: Set<String> = ["explicit_deny", "outside_allow_scope", "allowed"]

    func recordTarget(_ task: RegistryTask, _ path: String, _ outcome: Outcome) -> String {
        guard Validate.canonicalPath(path) else { return "invalid" }
        if ["sensitive_path", "explicit_deny", "explicit_deny_below"].contains(outcome.reason) { return "withheld" }
        if !Registry.checkedNotSensitive.contains(outcome.reason) && isSensitive(path) { return "withheld" }
        let workspace = task.contract.workspace
        if PathBytes.equal(path, workspace) { return "." }
        guard PathBytes.within(path, workspace) else { return "outside_workspace" }
        return String(decoding: path.utf8.dropFirst(workspace.utf8.count + 1), as: UTF8.self)
    }

    func record(_ event: String, _ outcome: Outcome, _ operations: [String], _ target: String) {
        if recordRing.count == config.maxRecords { droppedRecords = saturatingAdd(droppedRecords, 1) }
        sequence = saturatingAdd(sequence, 1)
        recordRing.append(ActionRecord(sequence: sequence, event: event, taskID: outcome.taskID,
                                       revision: outcome.revision, allowed: outcome.allowed, reason: outcome.reason,
                                       operations: operations.sorted(), target: target), capacity: config.maxRecords)
    }

    var recordBuffer: [ActionRecord] {
        get { recordRing.ordered }
        set { recordRing = RecordRing(newValue) }
    }

    func recordLifecycle(_ taskID: String, _ reason: String) {
        record("lifecycle", Outcome("enforced", true, reason, taskID, tasks[taskID]?.contract.revision), [], ".")
    }

    public func records() -> [ActionRecord] { locked { recordBuffer } }
}

/// Parses raw operation names; nil unless non-empty and all known (task_policy._operations).
func FileAccessOperations(_ names: Set<String>) -> Set<FileOperation>? {
    let parsed = names.compactMap(FileOperation.init(rawValue:))
    guard !names.isEmpty, parsed.count == names.count else { return nil }
    return Set(parsed)
}

/// Bounded record buffer with O(1) append; the oldest record is overwritten when full
/// (Python's deque(maxlen=...)).
struct RecordRing {
    private var storage: [ActionRecord]
    private var start = 0

    init(_ records: [ActionRecord]) { storage = records }

    var count: Int { storage.count }

    mutating func append(_ record: ActionRecord, capacity: Int) {
        if storage.count < capacity {
            storage.append(record)
        } else {
            storage[start] = record
            start = (start + 1) % storage.count
        }
    }

    var ordered: [ActionRecord] { Array(storage[start...] + storage[..<start]) }
}

func saturatingAdd(_ lhs: Int64, _ rhs: Int64) -> Int64 {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? Int64.max : sum
}

/// Insertion-ordered set that only ever evicts its oldest member, in O(1).
struct RetiredSet {
    private var order: [ProcessIdentity?] = []
    private var head = 0
    private var members: Set<ProcessIdentity> = []

    var count: Int { members.count }
    func contains(_ identity: ProcessIdentity) -> Bool { members.contains(identity) }

    /// Python dict semantics: re-inserting a present member keeps its original position.
    mutating func insert(_ identity: ProcessIdentity) {
        guard members.insert(identity).inserted else { return }
        order.append(identity)
    }

    mutating func evictOldest() {
        while head < order.count {
            defer { head += 1 }
            if let oldest = order[head] {
                order[head] = nil
                members.remove(oldest)
                break
            }
        }
        if head > 4096 && head * 2 > order.count {
            order.removeFirst(head)
            head = 0
        }
    }

    var ordered: [ProcessIdentity] { order[head...].compactMap { $0 } }
}
