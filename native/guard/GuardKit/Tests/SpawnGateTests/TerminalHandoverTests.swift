// Real-process measurements of the terminal foreground handover. Each test opens a
// pseudo-terminal and forks a stand-in login shell that owns it as a new session. The
// shell starts a stand-in supervisor as a foreground job, and the supervisor gated-spawns
// /bin/sh as the agent. Only /bin/sh, /bin/stty and /bin/sleep run; no agent, ES client,
// credential or network is used.
//
// The forked stand-ins run in a copy of the multithreaded test process, so they make
// async-signal-safe C calls only: no allocation, no XCTest, no Swift generics (not even a
// `for` over a range). The stand-in shell closes its inherited descriptors, which keeps
// agb_spawn_gated's descriptor listing on the stack. Results travel back as exit codes;
// see SessionCode and SupervisorCode.
import Darwin
import SpawnGate
import XCTest

/// fork() is unavailable from Swift; the stand-ins need it to become separate jobs.
private let forkProcess = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork"),
                                        to: (@convention(c) () -> pid_t).self)

/// Exit codes of the stand-in login shell when a check of its own fails.
private enum SessionCode: Int32 {
    case loginTTYFailed = 80, forkFailed, notTakenBackBeforeStop, unexpectedStopCount, supervisorSignalled
    case agentNeverHeldTerminal, terminalNotWithShell
}

/// Exit codes of the stand-in supervisor. 0 means every check held.
private enum SupervisorCode: Int32 {
    case notForeground = 60, spawnFailed, handOverFailed, releaseFailed, waitFailed
    case unexpectedForeground, unexpectedAgentStatus, signalStateNotRestored
}

/// How the stand-in shell answers a stop of the supervisor's job.
private enum StopAnswer {
    /// `fg`: the shell hands the terminal to the job and continues it.
    case foreground
    /// `bg`: the shell keeps the terminal and continues the job.
    case background
    /// The shell stops the supervisor itself (kill -STOP) while the agent holds the
    /// terminal, takes the terminal back as shells do, and then answers with `bg`...
    case stopFromOutsideThenBackground
    /// ...or with `fg`, which gives the terminal to the supervisor's group, not the agent's.
    case stopFromOutsideThenForeground
    /// `bg` for the first stop, `fg` for every later one. The first stop comes before the
    /// supervisor handed the terminal over, so the shell already holds it at the second.
    case backgroundThenForeground

    var stopsFromOutside: Bool {
        switch self {
        case .stopFromOutsideThenBackground, .stopFromOutsideThenForeground: return true
        case .foreground, .background, .backgroundThenForeground: return false
        }
    }

    /// Whether the job ends in the background, with the terminal left to the shell.
    var endsInBackground: Bool {
        switch self {
        case .background, .stopFromOutsideThenBackground: return true
        case .foreground, .stopFromOutsideThenForeground, .backgroundThenForeground: return false
        }
    }
}

/// Everything the forked stand-ins need, prepared before fork.
private struct Scenario {
    let argv: UnsafePointer<UnsafeMutablePointer<CChar>?>
    let envp: UnsafePointer<UnsafeMutablePointer<CChar>?>
    /// Whether the supervisor hands the terminal to the agent before release.
    let handsOver: Bool
    /// Whether the supervisor's job is stopped (Ctrl-Z) after its foreground check and
    /// before its first handover: the window in which `bg` makes it a background job.
    let stopsBeforeHandOver: Bool
    /// Whether the supervisor runs with SIGTTOU ignored and blocked, as a launcher may have
    /// left it. Either one alone would let tcsetpgrp succeed from the background.
    let mutesSIGTTOU: Bool
    /// Raw wait status the agent must end with (handover) or stop with (control case).
    let expectedAgentStatus: Int32
    /// How often the supervisor's job must stop.
    let expectedSupervisorStops: Int32
    let answer: StopAnswer
    /// Descriptors below this are closed by the stand-in shell; computed before fork.
    let descriptorLimit: Int32
}

final class TerminalHandoverTests: XCTestCase {
    /// Upper bound for one scenario; the stand-ins' own alarms are later, as a backstop.
    private static let scenarioSeconds = 10

    /// Runs `script` under the stand-ins on a fresh pseudo-terminal and returns the stand-in
    /// shell's exit code. `whileRunning` gets the terminal's master side.
    private func runScenario(_ script: String, handsOver: Bool, expectedAgentStatus: Int32,
                             expectedSupervisorStops: Int32 = 0, answer: StopAnswer = .foreground,
                             stopsBeforeHandOver: Bool = false, mutesSIGTTOU: Bool = false,
                             whileRunning: (Int32) -> Void = { _ in }) throws -> Int32 {
        var master: Int32 = -1, slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        defer { close(master) }
        var terminalInfo = stat()
        XCTAssertEqual(fstat(slave, &terminalInfo), 0)
        let argv: [UnsafeMutablePointer<CChar>?] = ["/bin/sh", "-c", script].map { strdup($0) } + [nil]
        let envp: [UnsafeMutablePointer<CChar>?] = [nil]
        defer { argv.forEach { free($0) } }
        let session: pid_t = argv.withUnsafeBufferPointer { argvBuffer in
            envp.withUnsafeBufferPointer { envpBuffer in
                let scenario = Scenario(argv: argvBuffer.baseAddress!, envp: envpBuffer.baseAddress!,
                                        handsOver: handsOver, stopsBeforeHandOver: stopsBeforeHandOver,
                                        mutesSIGTTOU: mutesSIGTTOU,
                                        expectedAgentStatus: expectedAgentStatus,
                                        expectedSupervisorStops: expectedSupervisorStops, answer: answer,
                                        descriptorLimit: getdtablesize())
                let pid = forkProcess()
                if pid == 0 {
                    close(master)
                    _exit(Self.actAsLoginShell(slave, scenario))
                }
                return pid
            }
        }
        close(slave)
        XCTAssertGreaterThan(session, 0)
        whileRunning(master)
        let status = Self.reap(session, master: master, terminal: terminalInfo.st_rdev)
        XCTAssertTrue(status.map { $0 & 0x7f == 0 } ?? false,
                      "stand-in shell did not exit normally (status \(String(describing: status)))")
        return status.map { ($0 >> 8) & 0xff } ?? -1
    }

    /// Waits up to scenarioSeconds for the session leader, draining the terminal's output:
    /// an exiting session leader waits in the kernel until that output is read. On timeout,
    /// kills every process on the terminal while the session still exists, so the test
    /// leaves none behind, and returns nil.
    private static func reap(_ session: pid_t, master: Int32, terminal: dev_t) -> Int32? {
        let deadline = scenarioSeconds * 100
        var status: Int32 = 0
        for tick in 0..<(deadline * 2) {
            if tick == deadline {
                killProcesses(onTerminal: terminal)
                kill(session, SIGKILL)
            }
            if waitpid(session, &status, WNOHANG) == session { return tick < deadline ? status : nil }
            discardOutput(master)
            usleep(10_000)
        }
        return nil
    }

    private static func discardOutput(_ master: Int32) {
        var buffer = [UInt8](repeating: 0, count: 256)
        var descriptor = pollfd(fd: master, events: Int16(POLLIN), revents: 0)
        while poll(&descriptor, 1, 0) > 0 && descriptor.revents & Int16(POLLIN) != 0 {
            guard Darwin.read(master, &buffer, buffer.count) > 0 else { return }
        }
    }

    private static func killProcesses(onTerminal terminal: dev_t) {
        var pids = [pid_t](repeating: 0, count: 64)
        let bytes = proc_listpids(UInt32(PROC_TTY_ONLY), UInt32(bitPattern: terminal),
                                  &pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        for pid in pids.prefix(Int(max(bytes, 0)) / MemoryLayout<pid_t>.size) where pid > 0 {
            kill(pid, SIGKILL)
        }
    }

    // MARK: Forked stand-ins (C calls only)

    /// A minimal job-control shell: owns the terminal as session leader, runs the supervisor
    /// as a foreground job, and answers every stop of that job as `scenario.answer` says.
    private static func actAsLoginShell(_ slave: Int32, _ scenario: Scenario) -> Int32 {
        var empty = sigset_t()
        sigemptyset(&empty)
        sigprocmask(SIG_SETMASK, &empty, nil)
        guard login_tty(slave) == 0 else { return SessionCode.loginTTYFailed.rawValue }
        var descriptor: Int32 = 3
        while descriptor < scenario.descriptorLimit { close(descriptor); descriptor += 1 }
        alarm(20)  // backstop after the parent's 10-second bound; a literal, since the fork runs no lazy initializers
        let supervisor = forkProcess()
        if supervisor < 0 { return SessionCode.forkFailed.rawValue }
        if supervisor == 0 { _exit(actAsSupervisor(scenario)) }
        // Both sides set the group and the foreground, as shells do, so neither order races.
        setpgid(supervisor, supervisor)
        _ = agb_terminal_hand_over(0, supervisor)
        if scenario.answer.stopsFromOutside {
            guard waitForAgentToHoldTerminal(supervisor: supervisor) else {
                killpg(supervisor, SIGKILL)
                return SessionCode.agentNeverHeldTerminal.rawValue
            }
            kill(supervisor, SIGSTOP)
        }
        var stops: Int32 = 0
        var status: Int32 = 0
        while true {
            if waitpid(supervisor, &status, WUNTRACED) < 0 {
                if errno == EINTR { continue }
                return SessionCode.forkFailed.rawValue
            }
            guard status & 0xff == 0x7f else { break }
            stops += 1
            if scenario.answer.stopsFromOutside {
                // The agent still holds the terminal; the shell takes it anyway, then `bg` or `fg`.
                _ = agb_terminal_reclaim(0)
                if !scenario.answer.endsInBackground { _ = agb_terminal_hand_over(0, supervisor) }
                killpg(supervisor, SIGCONT)
                continue
            }
            if case .backgroundThenForeground = scenario.answer {
                // Before any handover the supervisor itself holds the terminal; after `bg`
                // the shell does. Either way the shell takes it, then answers.
                _ = agb_terminal_reclaim(0)
                if stops > 1 { _ = agb_terminal_hand_over(0, supervisor) }
                killpg(supervisor, SIGCONT)
                continue
            }
            // The supervisor must have taken the terminal back from the agent first.
            guard tcgetpgrp(0) == supervisor else {
                killpg(supervisor, SIGKILL)
                return SessionCode.notTakenBackBeforeStop.rawValue
            }
            _ = agb_terminal_reclaim(0)  // the shell shows its prompt, then the user types `fg` or `bg`
            if case .foreground = scenario.answer { _ = agb_terminal_hand_over(0, supervisor) }
            killpg(supervisor, SIGCONT)
        }
        guard status & 0x7f == 0 else { return SessionCode.supervisorSignalled.rawValue }
        let code = (status >> 8) & 0xff
        if code == 0 && stops != scenario.expectedSupervisorStops { return SessionCode.unexpectedStopCount.rawValue }
        // After `bg` the terminal stayed with the shell, and nothing may have taken it since.
        if code == 0 && scenario.answer.endsInBackground && tcgetpgrp(0) != getpgrp() {
            return SessionCode.terminalNotWithShell.rawValue
        }
        return code
    }

    /// Polls until neither the shell's nor the supervisor's group is in the foreground, i.e.
    /// the supervisor has handed the terminal to the agent. At most about five seconds.
    private static func waitForAgentToHoldTerminal(supervisor: pid_t) -> Bool {
        var polls: Int32 = 0
        while polls < 5_000 {
            let foreground = tcgetpgrp(0)
            if foreground > 0 && foreground != supervisor && foreground != getpgrp() { return true }
            usleep(1_000)
            polls += 1
        }
        return false
    }

    private static func actAsSupervisor(_ scenario: Scenario) -> Int32 {
        setpgid(0, 0)
        if scenario.mutesSIGTTOU {
            var ignore = sigaction()
            ignore.__sigaction_u.__sa_handler = SIG_IGN
            sigaction(SIGTTOU, &ignore, nil)
            var ttou = sigset_t()
            sigemptyset(&ttou)
            sigaddset(&ttou, SIGTTOU)
            sigprocmask(SIG_BLOCK, &ttou, nil)
        }
        guard agb_terminal_hand_over(0, getpgrp()) == 0, agb_terminal_is_foreground(0) else {
            return SupervisorCode.notForeground.rawValue
        }
        var child = agb_gated_child(pid: 0, release_fd: -1)
        guard agb_spawn_gated(scenario.argv[0], scenario.argv, scenario.envp, &child) == 0 else {
            return SupervisorCode.spawnFailed.rawValue
        }
        // Ctrl-Z right after the foreground check, as it can reach a real supervisor.
        if scenario.stopsBeforeHandOver { kill(0, SIGTSTP) }
        if scenario.handsOver && agb_terminal_start_job(0, child.pid) != 0 {
            agb_abort(&child)
            killpg(child.pid, SIGKILL)
            return SupervisorCode.handOverFailed.rawValue
        }
        // agb_terminal_start_job lifts SIGTTOU's disposition and mask only for its call.
        if scenario.mutesSIGTTOU && !sigTTOUStillMuted() {
            agb_abort(&child)
            killpg(child.pid, SIGKILL)
            return SupervisorCode.signalStateNotRestored.rawValue
        }
        guard agb_release(&child) == 0 else {
            killpg(child.pid, SIGKILL)
            return SupervisorCode.releaseFailed.rawValue
        }
        var status: Int32 = 0
        if scenario.handsOver {
            var finished = false
            guard agb_wait_foreground_job(0, child.pid, &status, &finished) == 0, finished else {
                killpg(child.pid, SIGKILL)
                return SupervisorCode.waitFailed.rawValue
            }
            // Only a job that was never sent to the background gets the terminal back.
            guard agb_terminal_is_foreground(0) != scenario.answer.endsInBackground else {
                return SupervisorCode.unexpectedForeground.rawValue
            }
            return status == scenario.expectedAgentStatus ? 0 : SupervisorCode.unexpectedAgentStatus.rawValue
        }
        // Control case: nothing hands the terminal over.
        while waitpid(child.pid, &status, WUNTRACED) < 0 && errno == EINTR {}
        let observed = status
        killpg(child.pid, SIGKILL)
        while waitpid(child.pid, &status, 0) < 0 && errno == EINTR {}
        return observed == scenario.expectedAgentStatus ? 0 : SupervisorCode.unexpectedAgentStatus.rawValue
    }

    /// Whether SIGTTOU is still ignored and blocked, as the muted stand-in set it up.
    private static func sigTTOUStillMuted() -> Bool {
        var current = sigaction()
        sigaction(SIGTTOU, nil, &current)
        var mask = sigset_t()
        sigprocmask(SIG_BLOCK, nil, &mask)
        // SIG_IGN is the handler value 1.
        return unsafeBitCast(current.__sigaction_u.__sa_handler, to: Int.self) == 1 && sigismember(&mask, SIGTTOU) == 1
    }

    // MARK: Tests

    /// `stty` changes terminal attributes, which a background group may not do.
    private let changesTerminalModes = "/bin/stty -echo; /bin/stty echo; exit 0"

    func testWithoutHandoverTheAgentStopsOnSIGTTOU() throws {
        // Raw wait status of a process stopped by SIGTTOU.
        let stoppedBySIGTTOU = (SIGTTOU << 8) | 0x7f
        XCTAssertEqual(try runScenario(changesTerminalModes, handsOver: false, expectedAgentStatus: stoppedBySIGTTOU), 0)
    }

    func testHandedOverAgentChangesTerminalModesAndTheTerminalComesBack() throws {
        // Exit code 0 also means the supervisor was the foreground group again afterwards.
        XCTAssertEqual(try runScenario(changesTerminalModes, handsOver: true, expectedAgentStatus: 0), 0)
    }

    func testStoppedAgentStopsTheJobAndResumesInTheForegroundOnContinue() throws {
        // The agent stops itself like Ctrl-Z would; after `fg` it must still own the terminal.
        let script = "kill -s TSTP $$; " + changesTerminalModes
        XCTAssertEqual(try runScenario(script, handsOver: true, expectedAgentStatus: 0,
                                       expectedSupervisorStops: 1), 0)
    }

    func testAgentFinishingAfterBgLeavesTheTerminalWithTheShell() throws {
        // Ctrl-Z, then `bg`: the agent is continued in the background and exits without
        // touching the terminal. Neither the supervisor nor the agent may take it back.
        let code = try runScenario("kill -s TSTP $$; exit 0", handsOver: true, expectedAgentStatus: 0,
                                   expectedSupervisorStops: 1, answer: .background)
        XCTAssertEqual(code, 0)
    }

    func testSupervisorStoppedFromOutsideDoesNotTakeTheTerminalAfterBg() throws {
        // kill -STOP while the agent holds the terminal; the shell takes the terminal and
        // later answers with `bg`. The agent's exit must not give the supervisor the terminal.
        let code = try runScenario("/bin/sleep 1; exit 0", handsOver: true, expectedAgentStatus: 0,
                                   expectedSupervisorStops: 1, answer: .stopFromOutsideThenBackground)
        XCTAssertEqual(code, 0)
    }

    func testSupervisorStoppedFromOutsideHandsTheTerminalOnAfterFg() throws {
        // As above, but `fg`: the agent's next terminal access stops it once, and the
        // supervisor hands the terminal on without stopping its job a second time.
        let code = try runScenario("/bin/sleep 1; " + changesTerminalModes, handsOver: true, expectedAgentStatus: 0,
                                   expectedSupervisorStops: 1, answer: .stopFromOutsideThenForeground)
        XCTAssertEqual(code, 0)
    }

    func testSupervisorSentToBackgroundBeforeHandoverWaitsForFg() throws {
        // Ctrl-Z and `bg` between the foreground check and the first handover: the
        // supervisor is then a background job and must not take the terminal from the
        // shell. It stops on SIGTTOU (stop 2) and hands over only after `fg`.
        let code = try runScenario(changesTerminalModes, handsOver: true, expectedAgentStatus: 0,
                                   expectedSupervisorStops: 2, answer: .backgroundThenForeground,
                                   stopsBeforeHandOver: true)
        XCTAssertEqual(code, 0)
    }

    func testSupervisorWithMutedSIGTTOUStillWaitsForFg() throws {
        // An inherited SIG_IGN or blocked mask would let tcsetpgrp succeed from the background.
        let code = try runScenario(changesTerminalModes, handsOver: true, expectedAgentStatus: 0,
                                   expectedSupervisorStops: 2, answer: .backgroundThenForeground,
                                   stopsBeforeHandOver: true, mutesSIGTTOU: true)
        XCTAssertEqual(code, 0)
    }

    func testCtrlCReachesOnlyTheAgent() throws {
        // The stand-in supervisor survives the interrupt and gets the terminal back.
        let code = try runScenario("echo ready; exec /bin/sleep 30", handsOver: true,
                                   expectedAgentStatus: SIGINT) { master in
            XCTAssertTrue(Self.read(master, until: "ready"), "agent did not start")
            var interrupt: UInt8 = 0x03  // VINTR in the default terminal settings
            XCTAssertEqual(write(master, &interrupt, 1), 1)
        }
        XCTAssertEqual(code, 0)
    }

    func testNonTerminalDescriptorsAreNeverForeground() throws {
        let null = open("/dev/null", O_RDWR)
        XCTAssertGreaterThanOrEqual(null, 0)
        defer { close(null) }
        XCTAssertFalse(agb_terminal_is_foreground(null))
        XCTAssertEqual(agb_terminal_hand_over(null, getpgrp()), ENOTTY)
        XCTAssertEqual(agb_terminal_hand_over(-1, getpgrp()), EINVAL)
        XCTAssertEqual(agb_terminal_start_job(null, getpgrp()), ENOTTY)
        XCTAssertEqual(agb_terminal_start_job(-1, getpgrp()), EINVAL)
        var status: Int32 = 0
        var finished = true
        XCTAssertEqual(agb_wait_foreground_job(null, 0, &status, &finished), EINVAL)
    }

    /// Reads the terminal's output until `marker` appears, for at most scenarioSeconds.
    private static func read(_ master: Int32, until marker: String) -> Bool {
        var output = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 256)
        for _ in 0..<(scenarioSeconds * 10) {
            var descriptor = pollfd(fd: master, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, 100) >= 0 else { return false }
            guard descriptor.revents & Int16(POLLIN) != 0 else { continue }
            let count = Darwin.read(master, &buffer, buffer.count)
            guard count > 0 else { return false }
            output += buffer.prefix(count)
            if String(decoding: output, as: UTF8.self).contains(marker) { return true }
        }
        return false
    }
}
