import CryptoKit
import Darwin
import Foundation
import GuardCore

// Durable snapshot and fail-closed restore (task_registry.to_document / restore), plus
// the private state file. Process identities serialize as [pid, "<pidversion>"]: the
// Python model uses an opaque generation string, and the canonical decimal spelling of
// the pidversion is what both implementations agree on. Other generation spellings are
// rejected here although Python would accept them.

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func identityJSON(_ process: ProcessIdentity) -> JSONValue {
    .array([.int(Int64(process.pid)), .string(String(process.pidVersion))])
}

func identityFrom(_ value: JSONValue) throws -> ProcessIdentity {
    guard let items = value.arrayValue, items.count == 2 else { throw RegistryError("invalid process identity") }
    guard case let .int(pid) = items[0], pid > 0, pid <= Int64(Int32.max),
          let generation = items[1].stringValue, let version = Int32(generation),
          String(version) == generation, let identity = try? ProcessIdentity(pid: Int32(pid), pidVersion: version) else {
        throw PolicyError("invalid process identity")
    }
    return identity
}

let documentFields: Set<String> = ["schema", "version", "boot_id", "sequence", "last_now_ns", "tasks", "bindings",
                                   "quarantine", "tickets", "retired", "records", "dropped_records",
                                   "dropped_requests", "dropped_retired"]
let ticketFields: Set<String> = ["child", "task_id", "image", "spawner", "expires_at_ns", "state"]
let ticketStates: Set<String> = ["pending", "bound", "denied", "expired", "revoked"]
/// Tickets kept (as revoked) across a restart: every child that is not running a bound image.
/// A denied exec leaves its child alive before exec, so a retry must stay closed.
let restoredTicketStates: Set<String> = ["pending", "denied", "expired", "revoked"]
let recordFields: Set<String> = ["sequence", "event", "task_id", "revision", "allowed", "reason", "operations", "target"]

extension ActionRecord {
    var jsonValue: JSONValue {
        .object(["sequence": .int(sequence), "event": .string(event), "task_id": taskID.map { .string($0) } ?? .null,
                 "revision": revision.map { .int($0) } ?? .null, "allowed": .bool(allowed), "reason": .string(reason),
                 "operations": .array(operations.map { .string($0) }), "target": .string(target)])
    }

    init(json value: JSONValue) throws {
        guard let object = value.objectValue, Set(object.keys) == recordFields,
              let operations = object["operations"]!.arrayValue,
              operations.allSatisfy({ $0.stringValue.flatMap(FileOperation.init(rawValue:)) != nil }),
              let sequence = object["sequence"]!.intValue, sequence >= 0,
              case let .bool(allowed) = object["allowed"]!,
              let event = object["event"]!.stringValue, let reason = object["reason"]!.stringValue,
              let target = object["target"]!.stringValue else { throw RegistryError("invalid record entry") }
        let taskID = object["task_id"]!, revision = object["revision"]!
        guard taskID.isNull || (taskID.stringValue.map(Validate.identifier) ?? false),
              revision.isNull || (revision.intValue.map { $0 >= 1 } ?? false) else {
            throw RegistryError("invalid record entry")
        }
        self.init(sequence: sequence, event: event, taskID: taskID.stringValue, revision: revision.intValue,
                  allowed: allowed, reason: reason, operations: operations.map { $0.stringValue! }, target: target)
    }
}

extension Registry {
    /// Durable snapshot. Proposals, grants and requests are deliberately absent. Tickets are
    /// kept so that a child waiting between registerLaunch and its exec is still known after
    /// a restart: its exec is then refused instead of running unbound.
    public func toDocument() -> JSONValue {
        lock.lock()
        defer { lock.unlock() }
        return document()
    }

    /// The snapshot itself; the caller holds the lock (the write-ahead hook runs under it).
    func document() -> JSONValue {
        let taskItems: [JSONValue] = tasks.keys.sorted(by: PathBytes.less).map { taskID in
            let task = tasks[taskID]!
            return .object(["contract": task.contract.jsonValue,
                            "parent_task_id": task.parentTaskID.map { .string($0) } ?? .null,
                            "state": .string(task.state.rawValue), "owner": identityJSON(task.owner)])
        }
        let bindingItems: [JSONValue] = bindings.keys.sorted(by: identityLess).map { process in
            .object(["process": identityJSON(process), "chain": identityJSON(chains[process]!),
                     "task_id": .string(bindings[process]!)])
        }
        let quarantineItems: [JSONValue] = quarantine.sorted(by: identityLess).map { process in
            .object(["process": identityJSON(process), "chain": identityJSON(chains[process]!)])
        }
        let ticketItems: [JSONValue] = tickets.keys.sorted(by: identityLess).map { child in
            let ticket = tickets[child]!
            return .object(["child": identityJSON(child), "task_id": .string(ticket.taskID),
                            "image": .array([.string(ticket.image.path), .string(ticket.image.digest)]),
                            "spawner": identityJSON(ticket.spawner), "expires_at_ns": .int(ticket.expiresAtNs),
                            "state": .string(ticket.state)])
        }
        return .object([
            "schema": .string(RegistryLimits.schema), "version": .int(RegistryLimits.documentVersion),
            "boot_id": .string(bootID), "sequence": .int(sequence), "last_now_ns": .int(now),
            "tasks": .array(taskItems), "bindings": .array(bindingItems), "quarantine": .array(quarantineItems),
            "tickets": .array(ticketItems),
            "retired": .array(retired.ordered.map(identityJSON)), "records": .array(recordBuffer.map(\.jsonValue)),
            "dropped_records": .int(droppedRecords), "dropped_requests": .int(droppedRequests),
            "dropped_retired": .int(droppedRetired),
        ])
    }

    /// Fail-closed restart: no task stays active and no lineage is trusted as current.
    /// Same boot: every saved bound identity becomes quarantined and every waiting launch
    /// ticket is revoked. New boot: both are discarded. `persist` is the new registry's
    /// write-ahead hook.
    public static func restore(_ document: JSONValue, config: RegistryConfig, bootID: String,
                               nowNs: Int64, persist: ((JSONValue) throws -> Void)? = nil) throws -> Registry {
        do {
            return try restoreChecked(document, config, bootID, nowNs, persist)
        } catch is PolicyError {
            throw RegistryError("invalid registry document")
        }
    }

    private static func restoreChecked(_ document: JSONValue, _ config: RegistryConfig, _ bootID: String,
                                       _ nowNs: Int64, _ persist: ((JSONValue) throws -> Void)?) throws -> Registry {
        let registry = try Registry(config: config, bootID: bootID, nowNs: nowNs, persist: persist)
        guard let object = document.objectValue, Set(object.keys) == documentFields else {
            throw RegistryError("invalid registry document")
        }
        guard object["schema"]!.stringValue == RegistryLimits.schema,
              object["version"]!.intValue == RegistryLimits.documentVersion else {
            throw RegistryError("unsupported registry document")
        }
        guard let savedBoot = object["boot_id"]!.stringValue, Validate.identifier(savedBoot),
              let lastNow = object["last_now_ns"]!.intValue, lastNow >= 0,
              let savedSequence = object["sequence"]!.intValue, savedSequence >= 0 else {
            throw RegistryError("invalid registry document")
        }
        let sameBoot = savedBoot.utf8.elementsEqual(bootID.utf8)
        try require(!sameBoot || nowNs >= lastNow, "clock regression across restart")
        try registry.restoreTasks(object["tasks"]!)
        try registry.restoreProcesses(object["bindings"]!, object["quarantine"]!, sameBoot)
        try registry.restoreTickets(object["tickets"]!, sameBoot)
        try registry.restoreRetired(object["retired"]!, sameBoot)
        try registry.restoreRecords(object, savedSequence)
        registry.record("lifecycle", Outcome("enforced", true, "registry_restored"), [], ".")
        return registry
    }

    func restoreTasks(_ value: JSONValue) throws {
        guard let items = value.arrayValue, items.count <= RegistryLimits.maxTasks else {
            throw RegistryError("invalid task list")
        }
        for item in items {
            guard let object = item.objectValue, Set(object.keys) == ["contract", "parent_task_id", "state", "owner"] else {
                throw RegistryError("invalid task entry")
            }
            let contract = try ContractCodec.decode(object["contract"]!)
            let parent = object["parent_task_id"]!
            guard tasks[contract.taskID] == nil, let stateText = object["state"]!.stringValue,
                  let state = TaskState(rawValue: stateText),
                  parent.isNull || (parent.stringValue.map(Validate.identifier) ?? false) else {
                throw RegistryError("invalid task entry")
            }
            tasks[contract.taskID] = RegistryTask(contract: contract, parentTaskID: parent.stringValue,
                                                  state: state == .revoked ? .revoked : .interrupted,
                                                  owner: try identityFrom(object["owner"]!))
        }
        try require(tasks.values.allSatisfy { $0.parentTaskID.map { tasks[$0] != nil } ?? true }, "unknown parent task")
    }

    func restoreProcesses(_ bindingsValue: JSONValue, _ quarantineValue: JSONValue, _ sameBoot: Bool) throws {
        guard let bindingItems = bindingsValue.arrayValue, let quarantineItems = quarantineValue.arrayValue,
              bindingItems.count + quarantineItems.count <= RegistryLimits.maxProcesses else {
            throw RegistryError("invalid process list")
        }
        var entries: [[String: JSONValue]] = []
        for item in bindingItems {
            guard let object = item.objectValue, Set(object.keys) == ["process", "chain", "task_id"],
                  let taskID = object["task_id"]!.stringValue, Validate.identifier(taskID), tasks[taskID] != nil else {
                throw RegistryError("invalid binding entry")
            }
            entries.append(object)
        }
        for item in quarantineItems {
            guard let object = item.objectValue, Set(object.keys) == ["process", "chain"] else {
                throw RegistryError("invalid quarantine entry")
            }
            entries.append(object)
        }
        let identities = try entries.map { (try identityFrom($0["process"]!), try identityFrom($0["chain"]!)) }
        if sameBoot {
            for (process, chain) in identities { isolate(process, chain) }
        }
    }

    /// Keeps every ticket but bound ones, revoked: each refuses its child's exec from now on.
    /// Bound tickets are dropped, so ticketStatus never reports a launch as bound once the
    /// registry lost track of it.
    func restoreTickets(_ value: JSONValue, _ sameBoot: Bool) throws {
        guard let items = value.arrayValue, items.count <= RegistryLimits.maxProcesses else {
            throw RegistryError("invalid ticket list")
        }
        var restored: [ProcessIdentity: Ticket] = [:]
        var seen: Set<ProcessIdentity> = []
        for item in items {
            guard let object = item.objectValue, Set(object.keys) == ticketFields,
                  let taskID = object["task_id"]!.stringValue, Validate.identifier(taskID), tasks[taskID] != nil,
                  let state = object["state"]!.stringValue, ticketStates.contains(state),
                  let expiresAtNs = object["expires_at_ns"]!.intValue, expiresAtNs >= 0,
                  let image = object["image"]!.arrayValue, image.count == 2,
                  let path = image[0].stringValue, let digest = image[1].stringValue else {
                throw RegistryError("invalid ticket entry")
            }
            let child = try identityFrom(object["child"]!)
            try require(seen.insert(child).inserted, "invalid ticket entry")
            guard let executable = try? ExecutableImage(path: path, digest: digest) else {
                throw RegistryError("invalid executable image")
            }
            let ticket = Ticket(taskID: taskID, image: executable, spawner: try identityFrom(object["spawner"]!),
                                expiresAtNs: expiresAtNs, state: "revoked")
            if restoredTicketStates.contains(state) { restored[child] = ticket }
        }
        if sameBoot { tickets.merge(restored) { _, new in new } }
    }

    func restoreRetired(_ value: JSONValue, _ sameBoot: Bool) throws {
        guard let items = value.arrayValue, items.count <= RegistryLimits.maxRetired else {
            throw RegistryError("invalid retired list")
        }
        let identities = try items.map(identityFrom)
        if sameBoot {
            for identity in identities { retire(identity) }
        }
    }

    func restoreRecords(_ object: [String: JSONValue], _ savedSequence: Int64) throws {
        guard let items = object["records"]!.arrayValue, items.count <= config.maxRecords else {
            throw RegistryError("invalid record list")
        }
        recordBuffer = try items.map(ActionRecord.init(json:))
        var counters: [Int64] = []
        for key in ["dropped_records", "dropped_requests", "dropped_retired"] {
            guard let counter = object[key]!.intValue, counter >= 0 else { throw RegistryError("invalid counter") }
            counters.append(counter)
        }
        (droppedRecords, droppedRequests, droppedRetired) = (counters[0], counters[1], counters[2])
        sequence = savedSequence
    }
}

// MARK: - private state file

/// Holds the parent directory; it must be ours and not writable by group or others.
private func openStoreDirectory(_ path: String) throws -> (Int32, String) {
    try require(Validate.canonicalPath(path) && path != "/", "invalid state path")
    let url = URL(fileURLWithPath: path)
    let directory = url.deletingLastPathComponent().path, name = url.lastPathComponent
    let descriptor = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try require(descriptor >= 0, "state directory unavailable")
    var info = stat()
    guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
          info.st_mode & 0o022 == 0 else {
        close(descriptor)
        throw RegistryError("state directory is not private")
    }
    return (descriptor, name)
}

/// Saves a registry that has no persist hook; one with a hook saves through checkpoint().
public func saveRegistry(path: String, registry: Registry) throws {
    try require(registry.persist == nil, "registry saves through its persist hook")
    try saveDocument(path: path, document: registry.toDocument())
}

/// Atomically replaces the state file through a held directory descriptor. This is what a
/// persist hook calls: it takes the document it was handed and never reads the registry.
public func saveDocument(path: String, document: JSONValue) throws {
    let data = Data(CanonicalJSON.encode(document).utf8)
    try require(data.count <= RegistryLimits.maxStateBytes, "registry state too large")
    let (directory, name) = try openStoreDirectory(path)
    defer { close(directory) }
    let temporary = ".\(name).\(UUID().uuidString).tmp"
    let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    try require(file >= 0, "registry state could not be saved")
    let written = data.withUnsafeBytes { buffer -> Bool in
        var offset = 0
        while offset < buffer.count {
            let count = write(file, buffer.baseAddress! + offset, buffer.count - offset)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return false }
            offset += count
        }
        return fsync(file) == 0
    }
    close(file)
    guard written, renameat(directory, temporary, directory, name) == 0, fsync(directory) == 0 else {
        unlinkat(directory, temporary, 0)  // best effort: the failure is reported below
        throw RegistryError("registry state could not be saved")
    }
}

public func loadRegistry(path: String, config: RegistryConfig, bootID: String, nowNs: Int64,
                         persist: ((JSONValue) throws -> Void)? = nil) throws -> Registry {
    let (directory, name) = try openStoreDirectory(path)
    defer { close(directory) }
    let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    try require(file >= 0, "registry state could not be read")
    defer { close(file) }
    var info = stat()
    try require(fstat(file, &info) == 0 && info.st_mode & S_IFMT == S_IFREG && info.st_uid == geteuid()
                && info.st_nlink == 1 && info.st_mode & 0o7777 == 0o600
                && info.st_size <= RegistryLimits.maxStateBytes, "registry state file is not private")
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 65536)
    while true {
        let count = read(file, &buffer, buffer.count)
        if count < 0 && errno == EINTR { continue }
        try require(count >= 0, "registry state could not be read")
        if count == 0 { break }
        data.append(buffer, count: count)
        try require(data.count <= RegistryLimits.maxStateBytes, "registry state too large")
    }
    let document: JSONValue
    do { document = try StrictJSON.parse(data) } catch { throw RegistryError("invalid registry state encoding") }
    return try Registry.restore(document, config: config, bootID: bootID, nowNs: nowNs, persist: persist)
}
