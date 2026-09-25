// Synthetic es_message_t values fed through the mapping and the Swift registry.
// No ES client is created; the structures are built in zeroed memory.
import Darwin
import EndpointSecurity
import XCTest
import GuardCore
@testable import GuardES
@testable import GuardRegistry

/// Builds ES structures in zeroed memory and frees them at the end of a test.
final class MessageBuilder {
    private var allocations: [UnsafeMutableRawPointer] = []

    deinit { allocations.forEach { $0.deallocate() } }

    func zeroed<T>(_ type: T.Type, extra: Int = 0) -> UnsafeMutablePointer<T> {
        let size = MemoryLayout<T>.size + extra
        let raw = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<T>.alignment)
        raw.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        allocations.append(raw)
        return raw.bindMemory(to: T.self, capacity: 1)
    }

    /// ES string tokens are not NUL-terminated; mimic that.
    func token(_ bytes: [UInt8]) -> es_string_token_t {
        let raw = UnsafeMutableRawPointer.allocate(byteCount: max(bytes.count, 1), alignment: 1)
        allocations.append(raw)
        raw.copyMemory(from: bytes, byteCount: bytes.count)
        return es_string_token_t(length: bytes.count, data: raw.assumingMemoryBound(to: CChar.self))
    }

    func token(_ text: String) -> es_string_token_t { token(Array(text.utf8)) }

    func file(_ path: String, truncated: Bool = false) -> UnsafeMutablePointer<es_file_t> {
        let file = zeroed(es_file_t.self)
        file.pointee.path = token(path)
        file.pointee.path_truncated = truncated
        return file
    }

    func auditToken(pid: Int32, version: Int32) -> audit_token_t {
        var token = audit_token_t()
        token.val.5 = UInt32(bitPattern: pid)
        token.val.7 = UInt32(bitPattern: version)
        return token
    }

    func process(_ identity: ProcessIdentity, parent: ProcessIdentity? = nil, executable: String = "/opt/agent",
                 cdhash: UInt8 = 0xab) -> UnsafeMutablePointer<es_process_t> {
        let process = zeroed(es_process_t.self)
        process.pointee.audit_token = auditToken(pid: identity.pid, version: identity.pidVersion)
        if let parent { process.pointee.parent_audit_token = auditToken(pid: parent.pid, version: parent.pidVersion) }
        process.pointee.executable = file(executable)
        withUnsafeMutableBytes(of: &process.pointee.cdhash) { bytes in
            for index in bytes.indices { bytes[index] = cdhash }
        }
        return process
    }

    func message(_ type: es_event_type_t, _ process: UnsafeMutablePointer<es_process_t>, version: UInt32 = 8)
        -> UnsafeMutablePointer<es_message_t> {
        let message = zeroed(es_message_t.self, extra: 256)
        message.pointee.version = version
        message.pointee.event_type = type
        message.pointee.action_type = ES_ACTION_TYPE_AUTH
        message.pointee.process = process
        return message
    }
}

private let supervisorSigner = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
private let approverSigner = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.approver")
private func pid(_ pid: Int32, _ version: Int32) -> ProcessIdentity { try! ProcessIdentity(pid: pid, pidVersion: version) }

final class ESMappingTests: XCTestCase {
    private let build = MessageBuilder()
    private var registry: Registry!
    private var clock: Int64 = 100
    private let supervisor = pid(500, 1)
    private let child = pid(3000, 1)
    private let agent = pid(3000, 2)
    private let agentHash = String(repeating: "ab", count: 20)

    private func tick() -> Int64 { clock += 1; return clock }

    override func setUpWithError() throws {
        registry = try Registry(config: try RegistryConfig(supervisors: [supervisorSigner], approvers: [approverSigner]),
                                bootID: "boot-1", nowNs: clock)
        let contract = try TaskContract.load(json: Data("""
            {"schema_version":1,"task_id":"ta","revision":1,"workspace":"/w/a","valid_from_ns":0,"expires_at_ns":100000,
             "allow":[{"path":"/w/a","scope":"tree","operations":["read"]},
                      {"path":"/w/a/src","scope":"tree","operations":["read","write"]}],
             "deny":[{"path":"/w/a/private","scope":"tree","operations":["read","write","execute"]}]}
            """.utf8))
        let supervisorPeer = Peer(process: supervisor, signer: supervisorSigner)
        let digest = try registry.propose(supervisorPeer, contract: contract, nowNs: tick())
        try registry.confirm(Peer(process: pid(600, 1), signer: approverSigner), digest: digest, nowNs: tick())
        registry.onFork(parent: supervisor, child: child, nowNs: tick())
        try registry.registerLaunch(supervisorPeer, taskID: "ta",
                                    image: try ExecutableImage(path: "/opt/agent", digest: agentHash), child: child,
                                    nowNs: tick())
        // The launch itself arrives as an ES AUTH_EXEC message.
        let message = build.message(ES_EVENT_TYPE_AUTH_EXEC, build.process(child, parent: supervisor))
        message.pointee.event.exec.target = build.process(agent, parent: supervisor, executable: "/opt/agent")
        let verdict = AuthDecider.decide(ESMapper.map(message), registry: registry, nowNs: tick())
        XCTAssertEqual(verdict.outcomes.map(\.reason), ["launch_bound"])
    }

    private func decide(_ message: UnsafeMutablePointer<es_message_t>) -> AuthVerdict {
        AuthDecider.decide(ESMapper.map(message), registry: registry, nowNs: tick())
    }

    private func open(_ path: String, flags: Int32, by process: ProcessIdentity? = nil, truncated: Bool = false)
        -> UnsafeMutablePointer<es_message_t> {
        let message = build.message(ES_EVENT_TYPE_AUTH_OPEN, build.process(process ?? agent, parent: supervisor))
        message.pointee.event.open.fflag = flags
        message.pointee.event.open.file = build.file(path, truncated: truncated)
        return message
    }

    func testExecTargetCarriesPathAndCdhashAsTheImage() {
        let message = build.message(ES_EVENT_TYPE_AUTH_EXEC, build.process(child, parent: supervisor))
        message.pointee.event.exec.target = build.process(agent, executable: "/opt/agent", cdhash: 0xab)
        XCTAssertEqual(ESMapper.map(message),
                       .exec(process: child, parent: supervisor, target: agent,
                             image: try! ExecutableImage(path: "/opt/agent", digest: agentHash), script: nil))
    }

    func testInterpretedScriptNeedsExecuteBesidesItsInterpreter() {
        func exec(_ script: String, pid: Int32) -> UnsafeMutablePointer<es_message_t> {
            let child = ESMappingTests.pidOf(pid, 1)
            registry.onFork(parent: agent, child: child, nowNs: tick())
            let message = build.message(ES_EVENT_TYPE_AUTH_EXEC, build.process(child, parent: agent))
            message.pointee.event.exec.target = build.process(ESMappingTests.pidOf(pid, 2), executable: "/bin/sh")
            message.pointee.event.exec.script = build.file(script)
            return message
        }
        // v1 contract: the interpreter outside the workspace is allowed; the script is judged
        // by the same rules (no execute rule in the workspace here).
        XCTAssertEqual(decide(exec("/usr/local/bin/tool.sh", pid: 3100)).outcomes.map(\.reason), ["exec_outside_contract"])
        XCTAssertEqual(decide(exec("/w/a/src/run.sh", pid: 3101)).outcomes.map(\.reason), ["outside_allow_scope"])
        XCTAssertEqual(decide(exec("/w/a/private/run.sh", pid: 3102)).outcomes.map(\.reason), ["explicit_deny"])
    }

    static func pidOf(_ pid: Int32, _ version: Int32) -> ProcessIdentity { try! ProcessIdentity(pid: pid, pidVersion: version) }

    func testAdditionalFileEventsAreMapped() {
        func operations(_ type: es_event_type_t, _ fill: (UnsafeMutablePointer<es_message_t>) -> Void) -> [FileTouch] {
            let message = build.message(type, build.process(agent))
            fill(message)
            if case let .files(_, _, touches) = ESMapper.map(message) { return touches }
            return []
        }
        let outside = build.file("/Users/victim/doc")
        XCTAssertEqual(operations(ES_EVENT_TYPE_AUTH_SETATTRLIST) { $0.pointee.event.setattrlist.target = outside },
                       [FileTouch(path: "/Users/victim/doc", operations: ["write"])])
        XCTAssertEqual(operations(ES_EVENT_TYPE_AUTH_GETEXTATTR) { $0.pointee.event.getextattr.target = outside },
                       [FileTouch(path: "/Users/victim/doc", operations: ["read"])])
        XCTAssertEqual(operations(ES_EVENT_TYPE_AUTH_CHDIR) { $0.pointee.event.chdir.target = outside },
                       [FileTouch(path: "/Users/victim/doc", operations: ["read"])])
        XCTAssertEqual(operations(ES_EVENT_TYPE_AUTH_UIPC_CONNECT) { $0.pointee.event.uipc_connect.file = outside },
                       [FileTouch(path: "/Users/victim/doc", operations: ["write"])])
        XCTAssertEqual(operations(ES_EVENT_TYPE_AUTH_UIPC_BIND) {
            $0.pointee.event.uipc_bind.dir = self.build.file("/w/a/src")
            $0.pointee.event.uipc_bind.filename = self.build.token("sock")
        }, [FileTouch(path: "/w/a/src/sock", operations: ["write"])])
    }

    func testTruncatingOpenIsAWriteEvenWithoutFWRITE() {
        XCTAssertEqual(ESMapper.openOperations(ESMapper.fread | ESMapper.ftrunc), ["read", "write"])
        XCTAssertFalse(decide(open("/w/a/README", flags: ESMapper.fread | ESMapper.ftrunc)).allow)
    }

    func testRenameCloneAndLinkSourcesAreJudgedAsSubtrees() {
        let rename = build.message(ES_EVENT_TYPE_AUTH_RENAME, build.process(agent))
        rename.pointee.event.rename.source = build.file("/w/a/src")
        rename.pointee.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        rename.pointee.event.rename.destination.new_path.dir = build.file("/w/a")
        rename.pointee.event.rename.destination.new_path.filename = build.token("src2")
        guard case let .files(_, _, touches) = ESMapper.map(rename) else { return XCTFail("unexpected mapping") }
        XCTAssertEqual(touches.map(\.subtree), [true, true])
        let clone = build.message(ES_EVENT_TYPE_AUTH_CLONE, build.process(agent))
        clone.pointee.event.clone.source = build.file("/w/a")
        clone.pointee.event.clone.target_dir = build.file("/w/a/src")
        clone.pointee.event.clone.target_name = build.token("copy")
        // /w/a holds the deny rule /w/a/private: cloning the tree would carry it away.
        XCTAssertEqual(decide(clone).outcomes.map(\.reason), ["explicit_deny_below"])
        // A clone target at or above a deny path that does not exist yet is refused as well.
        let staged = build.message(ES_EVENT_TYPE_AUTH_CLONE, build.process(agent))
        staged.pointee.event.clone.source = build.file("/w/a/src/staged")
        staged.pointee.event.clone.target_dir = build.file("/w/a")
        staged.pointee.event.clone.target_name = build.token("private")
        XCTAssertEqual(decide(staged).outcomes.map(\.reason), ["allowed", "explicit_deny"])
        let parentOfDeny = build.message(ES_EVENT_TYPE_AUTH_CLONE, build.process(agent))
        parentOfDeny.pointee.event.clone.source = build.file("/w/a/src/staged")
        parentOfDeny.pointee.event.clone.target_dir = build.file("/w/a/src")
        parentOfDeny.pointee.event.clone.target_name = build.token("out")
        XCTAssertTrue(decide(parentOfDeny).allow)
    }

    func testEventsWithoutAUsableIdentityPassAsUnrelated() {
        let kernel = build.message(ES_EVENT_TYPE_AUTH_OPEN, build.process(ESMappingTests.pidOf(1, 1)))
        kernel.pointee.process.pointee.audit_token = build.auditToken(pid: 0, version: 0)
        kernel.pointee.event.open.fflag = ESMapper.fread
        kernel.pointee.event.open.file = build.file("/etc/hosts")
        XCTAssertEqual(ESMapper.map(kernel), .invalid)
        XCTAssertTrue(decide(kernel).allow)
    }

    func testProcessTargetedEventsStayInsideTheTask() {
        let unrelated = ESMappingTests.pidOf(9500, 1)
        let getTask = build.message(ES_EVENT_TYPE_AUTH_GET_TASK, build.process(agent))
        getTask.pointee.event.get_task.target = build.process(unrelated)
        XCTAssertEqual(decide(getTask).outcomes.map(\.reason), ["process_outside_task"])
        let selfTask = build.message(ES_EVENT_TYPE_AUTH_GET_TASK_READ, build.process(agent))
        selfTask.pointee.event.get_task_read.target = build.process(agent)
        XCTAssertEqual(decide(selfTask).outcomes.map(\.reason), ["same_task"])
        // Signal via an intermediary (message version 9+): the instigator is judged.
        let signal = build.message(ES_EVENT_TYPE_AUTH_SIGNAL, build.process(ESMappingTests.pidOf(1, 1)), version: 9)
        signal.pointee.event.signal.target = build.process(unrelated)
        signal.pointee.event.signal.instigator = build.process(agent)
        XCTAssertEqual(decide(signal).outcomes.map(\.reason), ["process_outside_task"])
        let suspend = build.message(ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, build.process(agent))
        XCTAssertEqual(decide(suspend).outcomes.map(\.reason), ["process_outside_task"])  // no target named
        let bystander = build.message(ES_EVENT_TYPE_AUTH_GET_TASK, build.process(unrelated))
        bystander.pointee.event.get_task.target = build.process(agent)
        XCTAssertTrue(decide(bystander).allow)
    }

    func testDelegatedSignalFromAMissedForkIsJudgedLikeADirectOne() {
        let victim = ESMappingTests.pidOf(9500, 1)
        // Descendants of the agent whose NOTIFY_FORK was lost; separate ones, because the
        // first decision quarantines its process.
        let direct = build.message(ES_EVENT_TYPE_AUTH_SIGNAL, build.process(pid(4000, 7), parent: agent), version: 9)
        direct.pointee.event.signal.target = build.process(victim)
        // Delivered by launchd (parent: none) on behalf of the lost descendant.
        let lost = pid(4001, 8)
        let delegated = build.message(ES_EVENT_TYPE_AUTH_SIGNAL, build.process(pid(1, 1)), version: 9)
        delegated.pointee.event.signal.target = build.process(victim)
        delegated.pointee.event.signal.instigator = build.process(lost, parent: agent)
        guard case let .process(actor, parent, _, _) = ESMapper.map(delegated) else { return XCTFail("unexpected mapping") }
        XCTAssertEqual(actor, lost)
        XCTAssertEqual(parent, agent)
        let directVerdict = decide(direct)
        let delegatedVerdict = decide(delegated)
        XCTAssertEqual(directVerdict.outcomes.map(\.reason), ["unattributed_descendant"])
        XCTAssertEqual(delegatedVerdict.outcomes.map(\.reason), directVerdict.outcomes.map(\.reason))
        XCTAssertEqual(delegatedVerdict.allow, directVerdict.allow)
    }

    func testXPCConnectNotificationGivesTheClientIdentity() {
        let message = build.message(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, build.process(agent))
        let event = build.zeroed(es_event_xpc_connect_t.self)
        event.pointee.service_name = build.token("TEAM000001.dev.agentbelt.fileguard.control")
        message.pointee.event.xpc_connect = event
        let result = ESMapper.xpcConnect(message)
        XCTAssertEqual(result?.client, agent)
        XCTAssertEqual(result?.service, "TEAM000001.dev.agentbelt.fileguard.control")
    }

    func testOpenFlagsMapToReadAndWrite() {
        XCTAssertEqual(ESMapper.openOperations(ESMapper.fread), ["read"])
        XCTAssertEqual(ESMapper.openOperations(ESMapper.fwrite), ["write"])
        XCTAssertEqual(ESMapper.openOperations(ESMapper.fread | ESMapper.fwrite), ["read", "write"])
        XCTAssertEqual(ESMapper.openOperations(0), ["read"])
        XCTAssertTrue(decide(open("/w/a/README", flags: ESMapper.fread)).allow)
        XCTAssertFalse(decide(open("/w/a/README", flags: ESMapper.fread | ESMapper.fwrite)).allow)
        XCTAssertTrue(decide(open("/w/a/src/x", flags: ESMapper.fread | ESMapper.fwrite)).allow)
        XCTAssertFalse(decide(open("/etc/hosts", flags: ESMapper.fread)).allow)
    }

    func testResponsesAreNeverCachedAndOpenUsesFlags() {
        let allowed = decide(open("/w/a/README", flags: ESMapper.fread))
        XCTAssertEqual(allowed.openFlags, UInt32.max)
        XCTAssertFalse(allowed.cache)
        XCTAssertEqual(decide(open("/etc/hosts", flags: ESMapper.fread)).openFlags, 0)
    }

    func testUnusablePathsFailClosedOnlyForEnrolledProcesses() {
        let truncated = decide(open("/w/a/README", flags: ESMapper.fread, truncated: true))
        XCTAssertEqual(truncated.outcomes.map(\.reason), ["invalid_input"])
        let invalidUTF8 = build.message(ES_EVENT_TYPE_AUTH_OPEN, build.process(agent))
        invalidUTF8.pointee.event.open.fflag = ESMapper.fread
        let file = build.file("x")
        file.pointee.path = build.token([0x2f, 0x77, 0xff])
        invalidUTF8.pointee.event.open.file = file
        XCTAssertEqual(decide(invalidUTF8).outcomes.map(\.reason), ["invalid_input"])
        let unrelated = decide(open("/w/a/README", flags: ESMapper.fread, by: pid(9000, 1), truncated: true))
        XCTAssertEqual(unrelated.outcomes.map(\.route), ["not_enrolled"])
        XCTAssertTrue(unrelated.allow)
    }

    func testCreateAndRenameJoinDirectoryAndName() {
        let create = build.message(ES_EVENT_TYPE_AUTH_CREATE, build.process(agent))
        create.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        create.pointee.event.create.destination.new_path.dir = build.file("/w/a/src")
        create.pointee.event.create.destination.new_path.filename = build.token("new.txt")
        XCTAssertEqual(ESMapper.map(create), .files(process: agent, parent: nil,
                                                    touches: [FileTouch(path: "/w/a/src/new.txt", operations: ["write"])]))
        XCTAssertTrue(decide(create).allow)
        let rename = build.message(ES_EVENT_TYPE_AUTH_RENAME, build.process(agent))
        rename.pointee.event.rename.source = build.file("/w/a/src/new.txt")
        rename.pointee.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        rename.pointee.event.rename.destination.new_path.dir = build.file("/tmp")
        rename.pointee.event.rename.destination.new_path.filename = build.token("exfil.txt")
        let verdict = decide(rename)
        XCTAssertFalse(verdict.allow)
        XCTAssertEqual(verdict.outcomes.map(\.reason), ["allowed", "outside_allow_scope"])
    }

    func testFileNamesContainingSlashesAreUnusable() {
        let create = build.message(ES_EVENT_TYPE_AUTH_CREATE, build.process(agent))
        create.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        create.pointee.event.create.destination.new_path.dir = build.file("/w/a/src")
        create.pointee.event.create.destination.new_path.filename = build.token("../../../etc/x")
        XCTAssertEqual(decide(create).outcomes.map(\.reason), ["invalid_input"])
    }

    func testHardLinkAliasOfAnOutsideFileIsDenied() {
        let link = build.message(ES_EVENT_TYPE_AUTH_LINK, build.process(agent))
        link.pointee.event.link.source = build.file("/Users/victim/secret.txt")
        link.pointee.event.link.target_dir = build.file("/w/a/src")
        link.pointee.event.link.target_filename = build.token("alias.txt")
        XCTAssertFalse(decide(link).allow)
    }

    func testCloneAndCopyfileReadTheSourceAndWriteTheTarget() {
        let clone = build.message(ES_EVENT_TYPE_AUTH_CLONE, build.process(agent))
        clone.pointee.event.clone.source = build.file("/Users/victim/secret.txt")
        clone.pointee.event.clone.target_dir = build.file("/w/a/src")
        clone.pointee.event.clone.target_name = build.token("copy.txt")
        XCTAssertEqual(decide(clone).outcomes.map(\.reason), ["outside_allow_scope"])
        let copy = build.message(ES_EVENT_TYPE_AUTH_COPYFILE, build.process(agent))
        copy.pointee.event.copyfile.source = build.file("/w/a/README")
        copy.pointee.event.copyfile.target_dir = build.file("/w/a/src")
        copy.pointee.event.copyfile.target_name = build.token("readme-copy")
        XCTAssertTrue(decide(copy).allow)
        copy.pointee.event.copyfile.target_file = build.file("/w/a/private/over")
        XCTAssertEqual(decide(copy).outcomes.map(\.reason), ["allowed", "explicit_deny"])
    }

    func testMmapProtectionSelectsOperations() {
        func mapping(_ protection: Int32, _ flags: Int32) -> AuthMapping {
            let message = build.message(ES_EVENT_TYPE_AUTH_MMAP, build.process(agent))
            message.pointee.event.mmap.source = build.file("/w/a/src/lib.dylib")
            message.pointee.event.mmap.protection = protection
            message.pointee.event.mmap.flags = flags
            return ESMapper.map(message)
        }
        func operations(_ mapping: AuthMapping) -> Set<String> {
            if case let .files(_, _, touches) = mapping { return touches[0].operations }
            return []
        }
        XCTAssertEqual(operations(mapping(PROT_READ, MAP_PRIVATE)), ["read"])
        XCTAssertEqual(operations(mapping(PROT_READ | PROT_EXEC, MAP_PRIVATE)), ["read", "execute"])
        XCTAssertEqual(operations(mapping(PROT_READ | PROT_WRITE, MAP_PRIVATE)), ["read"])
        XCTAssertEqual(operations(mapping(PROT_READ | PROT_WRITE, MAP_SHARED)), ["read", "write"])
    }

    func testParentIdentityRequiresMessageVersionFour() {
        let old = build.message(ES_EVENT_TYPE_AUTH_OPEN, build.process(agent, parent: supervisor), version: 3)
        old.pointee.event.open.fflag = ESMapper.fread
        old.pointee.event.open.file = build.file("/w/a/README")
        guard case let .files(_, parent, _) = ESMapper.map(old) else { return XCTFail("unexpected mapping") }
        XCTAssertNil(parent)
    }

    func testUnmappedEventsDenyEnrolledAndPassUnrelated() {
        let enrolled = build.message(ES_EVENT_TYPE_AUTH_KEXTLOAD, build.process(agent))
        XCTAssertFalse(decide(enrolled).allow)
        let unrelated = build.message(ES_EVENT_TYPE_AUTH_KEXTLOAD, build.process(pid(9001, 1)))
        XCTAssertTrue(decide(unrelated).allow)
    }

    func testSubscribedEventsAreUniqueAndMapped() {
        XCTAssertEqual(Set(ESMapper.authEvents.map(\.rawValue)).count, ESMapper.authEvents.count)
        XCTAssertFalse(ESMapper.authEvents.contains(ES_EVENT_TYPE_AUTH_KEXTLOAD))
    }
}
