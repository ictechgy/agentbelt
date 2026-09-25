import Darwin
import Foundation
import ProbeSys

/// Performs probes from the current process, which R3 launches as the confined agent.
/// Outcomes record byte counts and errno names only; read buffers are discarded.
public struct ProbeRunner {
    public let root: String
    public let inheritedFd: Int32?
    /// False when `inheritedFd` was already closed as the run started (a launcher that
    /// closes fds >= 3). Checked before anything else can reuse the number.
    public let inheritedFdOpenAtStart: Bool
    /// This binary, for the child probes. Nil when unknown (children are then unavailable).
    public let executablePath: String?

    public init(root: String, inheritedFd: Int32?, inheritedFdOpenAtStart: Bool = true, executablePath: String?) {
        self.root = root
        self.inheritedFd = inheritedFd
        self.inheritedFdOpenAtStart = inheritedFdOpenAtStart
        self.executablePath = executablePath
    }

    /// Runs every probe, each right after its marker read.
    public func runAll() -> [ProbeResult] {
        Catalog.probes.map { spec in markThenRun(spec.id, spec) }
    }

    /// Opens the start marker of `markId` (an allowed read inside the workspace), runs
    /// `spec`, then opens the end marker before any JSON or Foundation work. The two
    /// guard records bound the sequence window in which `verify` looks for this probe's
    /// denial; startup and exit reads outside it cannot count.
    public func markThenRun(_ markId: String, _ spec: ProbeSpec) -> ProbeResult {
        if let failure = openMarker(markId, end: false, spec.id) { return failure }
        let result = run(spec)
        return openMarker(markId, end: true, spec.id) ?? result
    }

    private func openMarker(_ markId: String, end: Bool, _ id: String) -> ProbeResult? {
        let fd = open(path(FixturePath.marker(markId, end: end)), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            return ProbeResult(id: id, status: .failed, step: "marker",
                               detail: "\(end ? "end" : "start") marker read failed: \(ErrnoName.of(errno))")
        }
        close(fd)
        return nil
    }

    public func run(_ spec: ProbeSpec) -> ProbeResult {
        let result = perform(spec.action, id: spec.id)
        guard result.status == .error, let condition = spec.notApplicable else { return result }
        switch condition {
        case .caseSensitiveVolume where result.errno == "ENOENT":
            return ProbeResult(id: spec.id, status: .notApplicable, detail: "alias does not resolve on this volume")
        case .aclUnsupported where result.errno == "ENOTSUP" || result.errno == "EOPNOTSUPP":
            return ProbeResult(id: spec.id, status: .notApplicable, detail: "volume does not support ACLs")
        default:
            return result
        }
    }

    private func path(_ relative: String) -> String { root + "/" + relative }

    private func perform(_ action: ProbeAction, id: String) -> ProbeResult {
        switch action {
        case let .read(file, followSymlink):
            return readFile(id, path(file), flags: followSymlink ? 0 : O_NOFOLLOW)
        case let .append(file):
            return append(id, path(file))
        case let .create(file):
            return openAndClose(id, path(file), O_WRONLY | O_CREAT | O_EXCL)
        case let .open(file, mode):
            return openAndClose(id, path(file), mode == .readWrite ? O_RDWR : O_WRONLY | O_TRUNC)
        case let .makeDirectory(directory):
            return syscall(id, "mkdir", mkdir(path(directory), 0o700))
        case let .truncate(file):
            return truncateFile(id, path(file))
        case let .unlink(file):
            return syscall(id, "unlink", Darwin.unlink(path(file)))
        case let .hardlink(source, destination):
            return syscall(id, "link", link(path(source), path(destination)))
        case let .rename(source, destination):
            return syscall(id, "rename", Darwin.rename(path(source), path(destination)))
        case let .swap(first, second):
            return errnoResult(id, "renamex_np", r3_rename_swap(path(first), path(second)))
        case let .clone(source, destination):
            return errnoResult(id, "clonefile", r3_clonefile(path(source), path(destination)))
        case let .copyData(source, destination):
            return errnoResult(id, "copyfile", r3_copyfile_data(path(source), path(destination)))
        case .changeMode, .changeFlags, .setACL, .setTimes, .setXattr, .removeXattr, .getXattr, .listXattr,
             .readLink, .getAttributes:
            return metadata(action, id: id)
        case let .readDirectory(directory):
            var entries = 0
            var failedAtOpen: Int32 = 0
            let status = r3_read_directory(path(directory), &entries, &failedAtOpen)
            return status == 0 ? ProbeResult(id: id, status: .ok, bytes: entries)
                : errnoResult(id, failedAtOpen != 0 ? "open" : "readdir", status)
        case let .openAndMap(file):
            let fd = open(path(file), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { return failure(id, "open") }
            defer { close(fd) }
            return map(id, fd, mode: 0)
        case let .exec(file):
            return execute(id, path(file), arguments: [])
        case .inheritedRead:
            return withInheritedVictim(id) { readDescriptor(id, $0) }
        case let .received(request, use):
            return withReceived(id, request) { fd in
                switch use {
                case .read: return readDescriptor(id, fd)
                case let .map(mode): return map(id, fd, mode: mode)
                }
            }
        case let .connect(socketPath):
            return connectOnly(id, path(socketPath))
        case let .child(probe):
            return childProbe(id, probe)
        case let .forkRead(file):
            var bytes = 0
            var failedAtOpen: Int32 = 0
            let status = r3_fork_read(path(file), &bytes, &failedAtOpen)
            if failedAtOpen < 0 {
                return ProbeResult(id: id, status: .failed, step: "fork", detail: "fork child failed: \(ErrnoName.of(status))")
            }
            return status == 0 ? ProbeResult(id: id, status: .ok, bytes: bytes)
                : errnoResult(id, failedAtOpen != 0 ? "open" : "read", status)
        }
    }

    // MARK: Plain file operations

    private func readFile(_ id: String, _ file: String, flags: Int32) -> ProbeResult {
        let fd = open(file, O_RDONLY | O_CLOEXEC | flags)
        guard fd >= 0 else { return failure(id, "open") }
        defer { close(fd) }
        return readDescriptor(id, fd)
    }

    /// Reads at most 1 MiB with pread (the offset of a shared fd is left alone) and keeps
    /// only the count.
    private func readDescriptor(_ id: String, _ fd: Int32) -> ProbeResult {
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        var total = 0
        while total < 1 << 20 {
            let count = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, off_t(total)) }
            if count < 0 { return failure(id, "read") }
            if count == 0 { break }
            total += count
        }
        return ProbeResult(id: id, status: .ok, bytes: total)
    }

    private func append(_ id: String, _ file: String) -> ProbeResult {
        let fd = open(file, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return failure(id, "open") }
        defer { close(fd) }
        let line = Array("appended by r3-probes\n".utf8)
        let written = line.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        return written == line.count ? ProbeResult(id: id, status: .ok, bytes: written) : failure(id, "write")
    }

    private func openAndClose(_ id: String, _ file: String, _ flags: Int32) -> ProbeResult {
        let fd = open(file, flags | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return failure(id, "open") }
        close(fd)
        return ProbeResult(id: id, status: .ok)
    }

    /// open(O_NOFOLLOW) + ftruncate, so a replaced symlink is never followed.
    private func truncateFile(_ id: String, _ file: String) -> ProbeResult {
        let fd = open(file, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return failure(id, "open") }
        defer { close(fd) }
        return syscall(id, "ftruncate", ftruncate(fd, 0))
    }

    /// Attribute and link operations; none of them follows a final symlink.
    private func metadata(_ action: ProbeAction, id: String) -> ProbeResult {
        switch action {
        case let .changeMode(file):
            return syscall(id, "chmod", fchmodat(AT_FDCWD, path(file), 0o600, AT_SYMLINK_NOFOLLOW))
        case let .changeFlags(file):
            var info = stat()
            guard lstat(path(file), &info) == 0 else { return failure(id, "lstat") }
            return syscall(id, "chflags", lchflags(path(file), info.st_flags))
        case let .setACL(file):
            return errnoResult(id, "acl_set", r3_acl_set_empty(path(file)))
        case let .setTimes(file):
            return syscall(id, "utimensat", utimensat(AT_FDCWD, path(file), nil, AT_SYMLINK_NOFOLLOW))
        case let .setXattr(file):
            let value = Array("probe".utf8)
            return syscall(id, "setxattr", setxattr(path(file), FixturePath.newAttribute, value, value.count, 0, XATTR_NOFOLLOW))
        case let .removeXattr(file):
            return syscall(id, "removexattr", removexattr(path(file), FixturePath.existingAttribute, XATTR_NOFOLLOW))
        case let .getXattr(file):
            var buffer = [UInt8](repeating: 0, count: 256)
            let count = getxattr(path(file), FixturePath.existingAttribute, &buffer, buffer.count, 0, XATTR_NOFOLLOW)
            return count >= 0 ? ProbeResult(id: id, status: .ok, bytes: count) : failure(id, "getxattr")
        case let .listXattr(file):
            var buffer = [CChar](repeating: 0, count: 1024)
            let count = listxattr(path(file), &buffer, buffer.count, XATTR_NOFOLLOW)
            return count >= 0 ? ProbeResult(id: id, status: .ok, bytes: count) : failure(id, "listxattr")
        case let .readLink(file):
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let count = readlink(path(file), &buffer, buffer.count - 1)
            return count >= 0 ? ProbeResult(id: id, status: .ok, bytes: count) : failure(id, "readlink")
        case let .getAttributes(file):
            return errnoResult(id, "getattrlist", r3_getattrlist_type(path(file)))
        default:
            return ProbeResult(id: id, status: .failed, detail: "not a metadata probe")
        }
    }

    private func map(_ id: String, _ fd: Int32, mode: Int32) -> ProbeResult {
        var length = 0
        var step: Int32 = 0
        let status = r3_mmap_fd(fd, mode, &length, &step)
        guard status != 0 else { return ProbeResult(id: id, status: .ok, bytes: length) }
        let steps: [Int32: String] = [Int32(R3_STEP_FSTAT): "fstat", Int32(R3_STEP_CODESIG): "codesig",
                                      Int32(R3_STEP_MMAP): "mmap"]
        return errnoResult(id, steps[step] ?? "mmap", status)
    }

    private func syscall(_ id: String, _ step: String, _ status: Int32) -> ProbeResult {
        status == 0 ? ProbeResult(id: id, status: .ok) : failure(id, step)
    }

    private func failure(_ id: String, _ step: String) -> ProbeResult {
        errnoResult(id, step, errno)
    }

    private func errnoResult(_ id: String, _ step: String, _ code: Int32) -> ProbeResult {
        code == 0 ? ProbeResult(id: id, status: .ok)
            : ProbeResult(id: id, status: .error, errno: ErrnoName.of(code), step: step)
    }

    // MARK: Processes

    /// Spawns with an empty environment and waits. A denied exec surfaces as the
    /// posix_spawn errno; a nonzero exit is a harness failure, not a denial.
    private func execute(_ id: String, _ file: String, arguments: [String], stdoutFd: Int32 = -1) -> ProbeResult {
        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = ([file] + arguments).map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        let status = argv.withUnsafeBufferPointer { r3_spawn(file, $0.baseAddress!, stdoutFd, &pid) }
        guard status == 0 else { return errnoResult(id, "spawn", status) }
        var waitStatus: Int32 = 0
        let waited = r3_wait(pid, &waitStatus)
        guard waited == 0 else { return errnoResult(id, "wait", waited) }
        guard waitStatus & 0x7f == 0, (waitStatus >> 8) & 0xff == 0 else {
            return ProbeResult(id: id, status: .failed, step: "wait", detail: "child wait status \(waitStatus)")
        }
        return ProbeResult(id: id, status: .ok)
    }

    /// Runs `probe` in a spawned copy of this binary; the child reports one JSON result
    /// on a pipe and this process relays its outcome under `id`.
    private func childProbe(_ id: String, _ probe: String) -> ProbeResult {
        guard let executable = executablePath else {
            return ProbeResult(id: id, status: .unavailable, detail: "executable path unknown")
        }
        var pipeEnds: [Int32] = [-1, -1]
        guard pipe(&pipeEnds) == 0 else { return failure(id, "pipe") }
        _ = fcntl(pipeEnds[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(pipeEnds[1], F_SETFD, FD_CLOEXEC)
        // The child marks again after its own startup, so the startup reads of the new
        // process fall before the window that `verify` searches.
        let spawned = execute(id, executable, arguments: ["sub-probe", "--root", root, "--probe", probe, "--mark", id],
                              stdoutFd: pipeEnds[1])
        close(pipeEnds[1])
        defer { close(pipeEnds[0]) }
        let output = drain(pipeEnds[0])
        guard spawned.status == .ok || spawned.step == "wait" else { return spawned }
        guard let reported = try? JSONCoding.decoder.decode(ProbeResult.self, from: output), reported.id == probe else {
            return ProbeResult(id: id, status: .failed, step: "child", detail: "child reported no result")
        }
        var relayed = reported
        relayed.id = id
        return relayed
    }

    private func drain(_ fd: Int32) -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count < 64 * 1024 {
            let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { break }
            data.append(contentsOf: buffer[0..<count])
        }
        return data
    }

    // MARK: Descriptors

    /// Accepts the inherited descriptor only if it is the fixture victim, so a mistaken
    /// `--inherited-fd` cannot point the probe at an unrelated file. A descriptor that was
    /// already closed at start is reported as EBADF at fstat: closed by the launcher.
    private func withInheritedVictim(_ id: String, _ body: (Int32) -> ProbeResult) -> ProbeResult {
        guard let fd = inheritedFd else {
            return ProbeResult(id: id, status: .unavailable, detail: "no --inherited-fd given")
        }
        guard inheritedFdOpenAtStart else {
            return ProbeResult(id: id, status: .error, errno: "EBADF", step: "fstat", detail: "closed before the run started")
        }
        var info = stat()
        guard fstat(fd, &info) == 0 else { return failure(id, "fstat") }
        guard isFixture(info, FixturePath.victim) else {
            return ProbeResult(id: id, status: .failed, step: "fstat", detail: "inherited fd is not the fixture victim")
        }
        return body(fd)
    }

    private func isFixture(_ info: stat, _ relative: String) -> Bool {
        var expected = stat()
        return lstat(path(relative), &expected) == 0 && expected.st_ino == info.st_ino && expected.st_dev == info.st_dev
    }

    /// Connects, retrying briefly while the fd-server starts. ENOENT and ECONNREFUSED
    /// after the retries mean no helper is listening.
    private func connectWithRetry(_ socketPath: String, _ socket: inout Int32) -> Int32 {
        var status = r3_unix_connect(socketPath, &socket)
        for _ in 0..<50 where status == ENOENT || status == ECONNREFUSED {
            usleep(100_000)
            status = r3_unix_connect(socketPath, &socket)
        }
        return status
    }

    /// Connects to a socket outside the project and closes it; fd-server listens there but
    /// never accepts, so a connect that is not denied succeeds from the backlog.
    private func connectOnly(_ id: String, _ socketPath: String) -> ProbeResult {
        var socket: Int32 = -1
        let status = connectWithRetry(socketPath, &socket)
        if status == ENOENT || status == ECONNREFUSED {
            return ProbeResult(id: id, status: .unavailable, step: "connect", detail: "no fd-server listening")
        }
        guard status == 0 else { return errnoResult(id, "connect", status) }
        close(socket)
        return ProbeResult(id: id, status: .ok)
    }

    /// Asks the fd-server (over `projectA/ipc/fd.sock`) for one descriptor, checks that it
    /// is the requested fixture file and hands it to `body`.
    private func withReceived(_ id: String, _ request: HelperRequest, _ body: (Int32) -> ProbeResult) -> ProbeResult {
        var socket: Int32 = -1
        let status = connectWithRetry(path(FixturePath.socket), &socket)
        if status == ENOENT || status == ECONNREFUSED {
            return ProbeResult(id: id, status: .unavailable, step: "connect", detail: "no fd-server listening")
        }
        guard status == 0 else { return errnoResult(id, "connect", status) }
        defer { close(socket) }
        var byte = CChar(bitPattern: request.rawValue.asciiValue!)
        guard write(socket, &byte, 1) == 1 else { return failure(id, "send") }
        var received: Int32 = -1
        let receiveStatus = r3_recv_fd(socket, &received)
        guard receiveStatus == 0 else { return errnoResult(id, "recvmsg", receiveStatus) }
        defer { close(received) }
        var info = stat()
        guard fstat(received, &info) == 0 else { return failure(id, "fstat") }
        guard isFixture(info, request.fixturePath) else {
            return ProbeResult(id: id, status: .failed, step: "fstat", detail: "received fd is not the requested fixture file")
        }
        return body(received)
    }
}

/// The unconfined helper for the received-descriptor probes: it opens the requested
/// fixture file itself and hands the descriptor to whoever connects to
/// `projectA/ipc/fd.sock`. It also listens, without accepting, on `outside/listen.sock`
/// as the connect target outside the project.
public enum FdServer {
    public static func serve(root: String, connections: Int, timeoutSeconds: Int, ready: () -> Void) throws {
        let serving = try listen(root + "/" + FixturePath.socket)
        defer { stop(serving) }
        let outside = try listen(root + "/" + FixturePath.outsideSocket)
        defer { stop(outside) }
        ready()
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        for _ in 0..<connections {
            let remaining = Int32(max(0, deadline.timeIntervalSinceNow * 1000))
            var connection: Int32 = -1
            let accepted = r3_accept_timeout(serving.fd, remaining, &connection)
            guard accepted == 0 else { throw HarnessError("accept failed: \(ErrnoName.of(accepted))") }
            defer { close(connection) }
            try answer(connection, root: root)
        }
    }

    private static func answer(_ connection: Int32, root: String) throws {
        var byte: CChar = 0
        let status = r3_read_byte_timeout(connection, 5000, &byte)
        guard status == 0 else { throw HarnessError("no request byte: \(ErrnoName.of(status))") }
        let character = Character(Unicode.Scalar(UInt8(bitPattern: byte)))
        guard let request = HelperRequest(rawValue: character) else { throw HarnessError("unknown helper request") }
        let flags = request == .sharedMap ? O_RDWR : O_RDONLY
        let fd = open(root + "/" + request.fixturePath, flags | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HarnessError("cannot open \(request.fixturePath): \(ErrnoName.of(errno))") }
        defer { close(fd) }
        let sent = r3_send_fd(connection, fd)
        guard sent == 0 else { throw HarnessError("sendmsg failed: \(ErrnoName.of(sent))") }
    }

    private struct Listener {
        let fd: Int32
        let path: String
    }

    private static func listen(_ socketPath: String) throws -> Listener {
        var info = stat()
        if lstat(socketPath, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFSOCK, Darwin.unlink(socketPath) == 0 else {
                throw HarnessError("\(socketPath) exists and is not a stale socket")
            }
        }
        var listener: Int32 = -1
        let status = r3_unix_listen(socketPath, &listener)
        guard status == 0 else { throw HarnessError("listen failed: \(ErrnoName.of(status))") }
        return Listener(fd: listener, path: socketPath)
    }

    private static func stop(_ listener: Listener) {
        close(listener.fd)
        Darwin.unlink(listener.path)
    }
}
