// agentbelt-supervisor — native launch supervisor, R2 skeleton.
//
// Implements the launch-binding sequence from docs/design/task-registry.md:
//   fork a gated child -> read its audit identity -> register_launch for exactly that
//   child -> release it to execve -> require ticket_status == "bound".
// Any other outcome kills the child's process group and reports the launch as
// unprotected. When the supervisor is the foreground job of its terminal, the agent's
// group gets the terminal before release and gives it back when it stops or ends, as
// with a shell's job control. Until the registry is ported (R3), File Guard refuses register_launch,
// so this tool always stops before the agent runs. It never falls back to an
// unprotected launch.
import Darwin
import Foundation
import GuardCore
import GuardTransport
import MachO
import SpawnGate

struct Failure: Error { let message: String }

struct LaunchArguments {
    let taskID: String
    let argv: [String]

    /// Usage: agentbelt-supervisor launch --task <task-id> -- /absolute/agent [args...]
    static func parse(_ arguments: [String]) throws -> LaunchArguments {
        guard arguments.count >= 5, arguments[0] == "launch", arguments[1] == "--task", arguments[3] == "--" else {
            throw Failure(message: "usage: agentbelt-supervisor launch --task <task-id> -- /absolute/agent [args...]")
        }
        return LaunchArguments(taskID: arguments[2], argv: Array(arguments[4...]))
    }
}

/// The Info.plist the linker embedded in this binary's __TEXT segment. Those pages are
/// covered by the code signature; unlike Bundle.main, CFProcessPath cannot redirect them.
func embeddedInfo() throws -> [String: Any] {
    var size: UInt = 0
    let header = UnsafeRawPointer(#dsohandle).assumingMemoryBound(to: mach_header_64.self)
    guard let section = getsectiondata(header, "__TEXT", "__info_plist", &size), size > 0,
          let info = try PropertyListSerialization.propertyList(from: Data(bytes: section, count: Int(size)),
                                                                format: nil) as? [String: Any] else {
        throw Failure(message: "supervisor is not configured")
    }
    return info
}

/// Resolves links so the ticket names the file AUTH_EXEC will report, and refuses
/// anything but a regular executable (scripts and links are an R3 design item).
func resolvedExecutable(_ path: String) throws -> String {
    guard path.hasPrefix("/"), let resolved = realpath(path, nil) else {
        throw Failure(message: "agent path must be an existing absolute path")
    }
    defer { free(resolved) }
    var info = stat()
    let text = String(cString: resolved)
    guard stat(text, &info) == 0, info.st_mode & S_IFMT == S_IFREG, access(text, X_OK) == 0 else {
        throw Failure(message: "agent path is not a regular executable")
    }
    return text
}

/// Minimal fixed environment; building the real session environment stays agentbelt's job.
let childEnvironment = ["PATH=/usr/bin:/bin", "LANG=C"]

func spawnGated(path: String, argv: [String]) throws -> agb_gated_child {
    var child = agb_gated_child(pid: 0, release_fd: -1)
    let cArguments = argv.map { strdup($0) } + [nil]
    let cEnvironment = childEnvironment.map { strdup($0) } + [nil]
    defer { (cArguments + cEnvironment).forEach { free($0) } }
    let status = cArguments.withUnsafeBufferPointer { arguments in
        cEnvironment.withUnsafeBufferPointer { environment in
            agb_spawn_gated(path, arguments.baseAddress!, environment.baseAddress!, &child)
        }
    }
    guard status == 0 else { throw Failure(message: "could not fork launch child (errno \(status))") }
    return child
}

/// Pass `terminal` while the supervisor holds it or has handed it to the child: it is taken
/// back first, so it is never left with a dying group. Only from the child's group: if the
/// shell took it meanwhile (the supervisor was stopped from outside), it stays there.
func stop(_ child: inout agb_gated_child, terminal: Int32 = -1, reason: String) -> Never {
    agb_abort(&child)
    var note = ""
    if terminal >= 0 && tcgetpgrp(terminal) == child.pid {
        let error = agb_terminal_reclaim(terminal)
        if error != 0 { note = "; terminal not taken back (errno \(error))" }
    }
    // The child leads its own group, so descendants of a briefly released agent die too.
    killpg(child.pid, SIGKILL)
    var status: Int32 = 0
    while waitpid(child.pid, &status, 0) < 0 && errno == EINTR {}
    FileHandle.standardError.write(Data("agentbelt-supervisor: launch NOT protected: \(reason)\(note)\n".utf8))
    exit(EX_UNAVAILABLE)
}

func awaitBound(_ client: ControlClient, _ identity: ProcessIdentity) -> Bool {
    for _ in 0..<50 {
        if case let .ok(payload) = client.send(.ticketStatus(child: identity)) {
            let state = String(decoding: payload, as: UTF8.self)
            if state == "bound" { return true }
            if state != "pending" { return false }
        } else {
            return false
        }
        usleep(20_000)
    }
    return false
}

func run() throws -> Never {
    let arguments = try LaunchArguments.parse(Array(CommandLine.arguments.dropFirst()))
    let configuration = try ClientConfiguration.parse(signedInfo: try embeddedInfo())
    let executable = try resolvedExecutable(arguments.argv[0])
    let image = try ExecutableImage(path: executable, digest: try CodeIdentity.cdhash(ofExecutableAt: executable))
    let client = try ControlClient(machServiceName: configuration.machServiceName,
                                   serverRequirement: CodeRequirement.developerSigned(configuration.fileGuard))
    // execve uses the resolved file; argv[0] stays as invoked for name-sensitive tools.
    var child = try spawnGated(path: executable, argv: arguments.argv)
    var pid: Int32 = 0, version: Int32 = 0
    guard agb_audit_identity(child.pid, &pid, &version) == 0,
          let identity = try? ProcessIdentity(pid: pid, pidVersion: version) else {
        stop(&child, reason: "child identity unavailable")
    }
    let registered = client.send(.registerLaunch(taskID: arguments.taskID, image: image, child: identity))
    guard case .ok = registered else { stop(&child, reason: "launch ticket refused (\(registered))") }
    // Standard input's terminal if the supervisor is its foreground job, else -1. Only then
    // is the terminal handed to the agent; a background or non-terminal launch leaves it
    // alone. Checked here, not at startup: Ctrl-Z and `bg` meanwhile make this a
    // background job, which must not seize the terminal from the shell.
    let terminal: Int32 = agb_terminal_is_foreground(STDIN_FILENO) ? STDIN_FILENO : -1
    // The agent must never run as a background job, so the terminal changes hands first.
    // Ctrl-Z and `bg` can still land between the check above and this call; then the
    // supervisor stops on SIGTTOU here and hands over only after `fg`. If that takes
    // longer than the ticket's lifetime, the exec is refused and the launch fails closed.
    if terminal >= 0 {
        let error = agb_terminal_start_job(terminal, child.pid)
        guard error == 0 else {
            stop(&child, terminal: terminal, reason: "could not hand the terminal to the agent (errno \(error))")
        }
    }
    guard agb_release(&child) == 0 else { stop(&child, terminal: terminal, reason: "could not release child") }
    guard awaitBound(client, identity) else { stop(&child, terminal: terminal, reason: "ticket was not bound") }
    var status: Int32 = 0
    if terminal >= 0 {
        var finished = false
        let error = agb_wait_foreground_job(terminal, child.pid, &status, &finished)
        // The wait already took the terminal back where this job may: after `bg` it must not.
        guard finished else { stop(&child, reason: "lost job control of the agent (errno \(error))") }
        if error != 0 {
            FileHandle.standardError.write(Data("agentbelt-supervisor: terminal not taken back (errno \(error))\n".utf8))
        }
        exit(exitCode(status))
    }
    while waitpid(child.pid, &status, WUNTRACED) < 0 && errno == EINTR {}
    if status & 0xff == 0x7f {
        // Stopped, typically SIGTTIN/SIGTTOU: the supervisor was started in the background
        // or without a terminal, so nothing handed one over. Never hang silently.
        let stopSignal = (status >> 8) & 0xff  // read before the reap below overwrites status
        killpg(child.pid, SIGKILL)
        while waitpid(child.pid, &status, 0) < 0 && errno == EINTR {}
        FileHandle.standardError.write(Data("agentbelt-supervisor: agent stopped (signal \(stopSignal)); supervisor is not the terminal's foreground job\n".utf8))
        exit(EX_SOFTWARE)
    }
    exit(exitCode(status))
}

/// Shell convention: the agent's exit code, or 128 plus the signal that killed it.
func exitCode(_ status: Int32) -> Int32 {
    (status & 0x7f) == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
}

do {
    try run()
} catch let failure as Failure {
    FileHandle.standardError.write(Data("agentbelt-supervisor: \(failure.message)\n".utf8))
    exit(EX_USAGE)
} catch let error as GuardError {
    // Configuration or validation refusal: nothing was forked.
    FileHandle.standardError.write(Data("agentbelt-supervisor: refused: \(error.reason)\n".utf8))
    exit(EX_CONFIG)
} catch {
    FileHandle.standardError.write(Data("agentbelt-supervisor: \(error)\n".utf8))
    exit(EX_SOFTWARE)
}
