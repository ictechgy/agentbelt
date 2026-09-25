import Darwin
import EndpointSecurity
import GuardCore
import GuardRegistry
import SpawnGate

// R3 preparation: translate Endpoint Security AUTH messages into registry calls.
// Nothing here creates an ES client; File Guard owns the client and the responses.
// The mapping is a pure function of the message so it can be tested with synthetic
// es_message_t values before the entitlement exists.

/// One path an operation touches and what it does to it (read/write/execute).
public struct FileTouch: Equatable, Sendable {
    public let path: String
    public let operations: Set<String>
    /// The operation carries everything below `path` along (rename, clone, link).
    public var subtree = false

    public init(path: String, operations: Set<String>, subtree: Bool = false) {
        self.path = path
        self.operations = operations
        self.subtree = subtree
    }
}

public enum AuthMapping: Equatable, Sendable {
    /// `script` is the #! script when the image is its interpreter (message version 2+).
    case exec(process: ProcessIdentity, parent: ProcessIdentity?, target: ProcessIdentity, image: ExecutableImage?,
              script: String?)
    case files(process: ProcessIdentity, parent: ProcessIdentity?, touches: [FileTouch])
    /// Task port, read-only task port, signal or suspend/resume aimed at another process.
    case process(process: ProcessIdentity, parent: ProcessIdentity?, target: ProcessIdentity?, operation: String)
    /// No usable process identity (e.g. pid 0). It cannot be enrolled, so it passes.
    case invalid
}

public enum ESMapper {
    /// A path that can never validate: truncated or non-UTF-8 paths become invalid input,
    /// which denies for enrolled processes and passes through for unrelated ones.
    static let unusablePath = "\u{0}"

    /// Kernel file flags on AUTH_OPEN (sys/fcntl.h FREAD/FWRITE).
    static let fread: Int32 = 0x0001
    static let fwrite: Int32 = 0x0002
    /// O_TRUNC destroys contents even with FREAD alone.
    static let ftrunc: Int32 = 0x0400

    public static func map(_ message: UnsafePointer<es_message_t>) -> AuthMapping {
        let event = message.pointee
        guard let process = identity(event.process.pointee.audit_token) else { return .invalid }
        let parent = parentIdentity(event.process.pointee, version: event.version)
        func files(_ touches: [FileTouch]) -> AuthMapping { .files(process: process, parent: parent, touches: touches) }
        switch event.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            let target = event.event.exec.target.pointee
            guard let targetIdentity = identity(target.audit_token) else { return .invalid }
            let image = try? ExecutableImage(path: path(target.executable), digest: cdhashHex(target.cdhash))
            let script = event.version >= 2 ? event.event.exec.script.map(path) : nil
            return .exec(process: process, parent: parent, target: targetIdentity, image: image, script: script)
        case ES_EVENT_TYPE_AUTH_OPEN:
            return files([touch(event.event.open.file, openOperations(event.event.open.fflag))])
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            return .process(process: process, parent: parent,
                            target: identity(event.event.get_task.target.pointee.audit_token), operation: "task_port")
        case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
            return .process(process: process, parent: parent,
                            target: identity(event.event.get_task_read.target.pointee.audit_token), operation: "task_read")
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            // From message version 9 the instigator names who asked for the signal (e.g.
            // through launchctl); the delivering process is then only an intermediary. Its
            // parent is the instigator's too, so a delegated signal from a descendant whose
            // fork was missed meets the same unattributed-descendant check as a direct one.
            let signal = event.event.signal
            let instigator = event.version >= 9 ? signal.instigator?.pointee : nil
            guard let instigator, let actor = identity(instigator.audit_token) else {
                return .process(process: process, parent: parent,
                                target: identity(signal.target.pointee.audit_token), operation: "signal")
            }
            return .process(process: actor, parent: parentIdentity(instigator, version: event.version),
                            target: identity(signal.target.pointee.audit_token), operation: "signal")
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            let target = event.event.proc_suspend_resume.target.flatMap { identity($0.pointee.audit_token) }
            return .process(process: process, parent: parent, target: target, operation: "suspend_resume")
        case ES_EVENT_TYPE_AUTH_CREATE:
            let create = event.event.create
            let target = create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE
                ? path(create.destination.existing_file)
                : join(create.destination.new_path.dir, create.destination.new_path.filename)
            return files([FileTouch(path: target, operations: ["write"])])
        case ES_EVENT_TYPE_AUTH_UNLINK:
            return files([touch(event.event.unlink.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return files([touch(event.event.truncate.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_RENAME:
            let rename = event.event.rename
            let destination = rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE
                ? path(rename.destination.existing_file)
                : join(rename.destination.new_path.dir, rename.destination.new_path.filename)
            // Moving changes both names; both sides need write, and a moved directory must
            // not carry a deny rule's subject away from its path.
            return files([touch(rename.source, ["write"], subtree: true),
                          FileTouch(path: destination, operations: ["write"], subtree: true)])
        case ES_EVENT_TYPE_AUTH_LINK:
            let link = event.event.link
            // A hard link gives the source a new name: treat it as writing both, so a
            // workspace alias of an outside file cannot be made from inside a task.
            return files([touch(link.source, ["write"], subtree: true),
                          FileTouch(path: join(link.target_dir, link.target_filename), operations: ["write"])])
        case ES_EVENT_TYPE_AUTH_CLONE:
            let clone = event.event.clone
            // clonefile(2) copies a directory recursively: both sides are judged as subtrees,
            // so a clone cannot create files under a deny path that does not exist yet.
            return files([touch(clone.source, ["read"], subtree: true),
                          FileTouch(path: join(clone.target_dir, clone.target_name), operations: ["write"], subtree: true)])
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let copy = event.event.copyfile
            let target = copy.target_file.map(path) ?? join(copy.target_dir, copy.target_name)
            return files([touch(copy.source, ["read"]), FileTouch(path: target, operations: ["write"])])
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            return files([touch(event.event.exchangedata.file1, ["write"]), touch(event.event.exchangedata.file2, ["write"])])
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            return files([touch(event.event.setextattr.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            return files([touch(event.event.deleteextattr.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_SETMODE:
            return files([touch(event.event.setmode.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            return files([touch(event.event.setflags.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            return files([touch(event.event.setowner.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_SETACL:
            return files([touch(event.event.setacl.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_UTIMES:
            return files([touch(event.event.utimes.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
            return files([touch(event.event.setattrlist.target, ["write"])])
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            return files([touch(event.event.getextattr.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
            return files([touch(event.event.listextattr.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            return files([touch(event.event.fsgetpath.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_SEARCHFS:
            return files([touch(event.event.searchfs.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_CHDIR:
            return files([touch(event.event.chdir.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_CHROOT:
            return files([touch(event.event.chroot.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
            // Creating a socket file is a write to that name.
            return files([FileTouch(path: join(event.event.uipc_bind.dir, event.event.uipc_bind.filename),
                                    operations: ["write"])])
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            // Connecting hands requests to whoever serves the socket (IPC delegation).
            return files([touch(event.event.uipc_connect.file, ["write"])])
        case ES_EVENT_TYPE_AUTH_READDIR:
            return files([touch(event.event.readdir.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_READLINK:
            return files([touch(event.event.readlink.source, ["read"])])
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            return files([touch(event.event.getattrlist.target, ["read"])])
        case ES_EVENT_TYPE_AUTH_MMAP:
            let mmap = event.event.mmap
            var operations: Set<String> = ["read"]
            if mmap.protection & PROT_EXEC != 0 { operations.insert("execute") }
            // A shared writable mapping writes the file; a private one does not.
            if mmap.protection & PROT_WRITE != 0 && mmap.flags & MAP_SHARED != 0 { operations.insert("write") }
            return files([touch(mmap.source, operations)])
        default:
            // Not a mapped event: an unusable path makes enrolled processes fail closed.
            return files([FileTouch(path: unusablePath, operations: ["read"])])
        }
    }

    /// The event types `map` understands; File Guard subscribes to exactly these.
    public static let authEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_SETEXTATTR,
        ES_EVENT_TYPE_AUTH_DELETEEXTATTR, ES_EVENT_TYPE_AUTH_SETMODE, ES_EVENT_TYPE_AUTH_SETFLAGS,
        ES_EVENT_TYPE_AUTH_SETOWNER, ES_EVENT_TYPE_AUTH_SETACL, ES_EVENT_TYPE_AUTH_UTIMES, ES_EVENT_TYPE_AUTH_READDIR,
        ES_EVENT_TYPE_AUTH_READLINK, ES_EVENT_TYPE_AUTH_GETATTRLIST, ES_EVENT_TYPE_AUTH_MMAP,
        ES_EVENT_TYPE_AUTH_SETATTRLIST, ES_EVENT_TYPE_AUTH_GETEXTATTR, ES_EVENT_TYPE_AUTH_LISTEXTATTR,
        ES_EVENT_TYPE_AUTH_FSGETPATH, ES_EVENT_TYPE_AUTH_SEARCHFS, ES_EVENT_TYPE_AUTH_CHDIR, ES_EVENT_TYPE_AUTH_CHROOT,
        ES_EVENT_TYPE_AUTH_UIPC_BIND, ES_EVENT_TYPE_AUTH_UIPC_CONNECT,
        ES_EVENT_TYPE_AUTH_GET_TASK, ES_EVENT_TYPE_AUTH_GET_TASK_READ, ES_EVENT_TYPE_AUTH_SIGNAL,
        ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
    ]

    /// NOTIFY_XPC_CONNECT (macOS 14+): the connecting client's full identity and the
    /// service it reached. File Guard uses it to learn a control peer's pidversion.
    public static func xpcConnect(_ message: UnsafePointer<es_message_t>) -> (client: ProcessIdentity, service: String)? {
        let event = message.pointee
        guard event.event_type == ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
              let client = identity(event.process.pointee.audit_token),
              let service = string(event.event.xpc_connect.pointee.service_name) else { return nil }
        return (client, service)
    }

    static func openOperations(_ fflag: Int32) -> Set<String> {
        var operations: Set<String> = []
        if fflag & fread != 0 { operations.insert("read") }
        if fflag & fwrite != 0 || fflag & ftrunc != 0 { operations.insert("write") }
        // An open that neither reads nor writes (e.g. O_EVTONLY) still names the file.
        return operations.isEmpty ? ["read"] : operations
    }

    static func identity(_ token: audit_token_t) -> ProcessIdentity? {
        var token = token
        var pid: Int32 = 0, version: Int32 = 0
        agb_token_identity(&token, &pid, &version)
        return try? ProcessIdentity(pid: pid, pidVersion: version)
    }

    /// `parent_audit_token` exists from message version 4 (macOS 13). The SDK describes it
    /// as the current parent; only `original_ppid` survives reparenting, and it is a bare
    /// PID. After reparenting the missed-fork check therefore sees launchd (R3 assumption 4).
    /// Earlier message versions give no parent identity at all.
    static func parentIdentity(_ process: es_process_t, version: UInt32) -> ProcessIdentity? {
        version >= 4 ? identity(process.parent_audit_token) : nil
    }

    static func string(_ token: es_string_token_t) -> String? {
        guard token.length > 0, let data = token.data else { return token.length == 0 ? "" : nil }
        let bytes = UnsafeRawBufferPointer(start: data, count: token.length)
        let text = String(decoding: bytes, as: UTF8.self)
        // Reject rather than repair: a replaced byte could alias another real path.
        return text.utf8.elementsEqual(bytes) ? text : nil
    }

    static func path(_ file: UnsafeMutablePointer<es_file_t>) -> String {
        guard !file.pointee.path_truncated, let text = string(file.pointee.path) else { return unusablePath }
        return text
    }

    static func join(_ directory: UnsafeMutablePointer<es_file_t>, _ name: es_string_token_t) -> String {
        let base = path(directory)
        guard base != unusablePath, let leaf = string(name), !leaf.isEmpty, !leaf.contains("/") else { return unusablePath }
        return base == "/" ? "/" + leaf : base + "/" + leaf
    }

    static func touch(_ file: UnsafeMutablePointer<es_file_t>, _ operations: Set<String>, subtree: Bool = false)
        -> FileTouch {
        FileTouch(path: path(file), operations: operations, subtree: subtree)
    }

    static func cdhashHex(_ cdhash: es_cdhash_t) -> String {
        withUnsafeBytes(of: cdhash) { bytes in bytes.map { String(format: "%02x", $0) }.joined() }
    }
}

/// Combined answer for one AUTH message. `outcomes` keeps each registry answer for records.
public struct AuthVerdict: Equatable, Sendable {
    public let allow: Bool
    public let outcomes: [Outcome]

    /// AUTH_OPEN answers with authorized flags; every other AUTH event with allow/deny.
    /// Results are never cached: ES caches per executable and file, not per task.
    public var openFlags: UInt32 { allow ? UInt32.max : 0 }
    public var cache: Bool { false }
}

public enum AuthDecider {
    /// The entry point for File Guard: the time is read inside ClockedRegistry's lock, so
    /// concurrent callers can never hand the registry an out-of-order clock.
    public static func decide(_ mapping: AuthMapping, clocked: ClockedRegistry) -> AuthVerdict {
        clocked.run { registry, now in decide(mapping, registry: registry, nowNs: now) }
    }

    /// Every touched path must be allowed; the first denial decides. For tests and
    /// single-threaded replay; production code uses the ClockedRegistry overload.
    public static func decide(_ mapping: AuthMapping, registry: Registry, nowNs: Int64) -> AuthVerdict {
        switch mapping {
        case .invalid:
            return AuthVerdict(allow: true, outcomes: [])
        case let .exec(process, parent, target, image, script):
            let outcome = registry.onExec(process: process, parent: parent, target: target, image: image,
                                          script: script, nowNs: nowNs)
            return AuthVerdict(allow: outcome.allowed, outcomes: [outcome])
        case let .process(process, parent, target, operation):
            let outcome = registry.authorizeProcess(process: process, parent: parent, target: target,
                                                    operation: operation, nowNs: nowNs)
            return AuthVerdict(allow: outcome.allowed, outcomes: [outcome])
        case let .files(process, parent, touches):
            var outcomes: [Outcome] = []
            for touch in touches {
                let outcome = registry.authorizeFile(process: process, parent: parent, path: touch.path,
                                                     operations: touch.operations, subtree: touch.subtree, nowNs: nowNs)
                outcomes.append(outcome)
                if !outcome.allowed { return AuthVerdict(allow: false, outcomes: outcomes) }
            }
            return AuthVerdict(allow: true, outcomes: outcomes)
        }
    }
}
