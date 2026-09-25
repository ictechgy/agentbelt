// Real-process measurements of the launch gate. Children run /bin/sleep only; no
// agent, ES client, credential or network is used.
import Darwin
import XCTest
import SpawnGate

final class SpawnGateTests: XCTestCase {
    private func spawn(_ arguments: [String]) throws -> agb_gated_child {
        var child = agb_gated_child(pid: 0, release_fd: -1)
        let argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) } + [nil]
        let envp: [UnsafeMutablePointer<CChar>?] = [nil]
        defer { argv.forEach { free($0) } }
        let status = argv.withUnsafeBufferPointer { argvBuffer in
            envp.withUnsafeBufferPointer { envpBuffer in
                agb_spawn_gated(arguments[0], argvBuffer.baseAddress!, envpBuffer.baseAddress!, &child)
            }
        }
        XCTAssertEqual(status, 0)
        return child
    }

    private func spawnSleep(_ seconds: String = "5") throws -> agb_gated_child {
        try spawn(["/bin/sleep", seconds])
    }

    private func identity(_ pid: pid_t) -> (Int32, Int32)? {
        var pidOut: Int32 = 0, version: Int32 = 0
        return agb_audit_identity(pid, &pidOut, &version) == 0 ? (pidOut, version) : nil
    }

    private func reap(_ pid: pid_t) -> Int32 {
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        return status
    }

    func testWaitingChildHasStableIdentityAndExecGetsANewPidversion() throws {
        var child = try spawnSleep()
        let waiting = try XCTUnwrap(identity(child.pid))
        usleep(200_000)
        // Still the same image: nothing ran before release.
        XCTAssertEqual(try XCTUnwrap(identity(child.pid)).1, waiting.1)
        XCTAssertEqual(agb_release(&child), 0)
        var executed: (Int32, Int32)?
        for _ in 0..<50 {
            usleep(20_000)
            if let now = identity(child.pid), now.1 != waiting.1 { executed = now; break }
        }
        let after = try XCTUnwrap(executed, "pidversion did not change after exec")
        XCTAssertEqual(after.0, child.pid)
        XCTAssertGreaterThan(after.1, waiting.1)
        kill(child.pid, SIGTERM)
        _ = reap(child.pid)
    }

    func testAbortedGateExitsWithoutExecuting() throws {
        var child = try spawnSleep()
        agb_abort(&child)
        let status = reap(child.pid)
        XCTAssertTrue(status & 0x7f == 0, "child was signalled")
        XCTAssertEqual((status >> 8) & 0xff, 126)
        XCTAssertEqual(agb_release(&child), EINVAL)
    }

    func testDistinctForksGetDistinctPidversions() throws {
        var first = try spawnSleep(), second = try spawnSleep()
        let a = try XCTUnwrap(identity(first.pid)), b = try XCTUnwrap(identity(second.pid))
        XCTAssertNotEqual(a.1, b.1)
        agb_abort(&first); agb_abort(&second)
        _ = reap(first.pid); _ = reap(second.pid)
    }

    func testSelfTokenMatchesTheTaskNameLookup() throws {
        var token = audit_token_t()
        XCTAssertEqual(agb_self_audit_token(&token), 0)
        var pid: Int32 = 0, version: Int32 = 0
        agb_token_identity(&token, &pid, &version)
        let looked = try XCTUnwrap(identity(getpid()))
        XCTAssertEqual(pid, getpid())
        XCTAssertEqual(looked.0, pid)
        XCTAssertEqual(looked.1, version)
    }

    func testInheritedDescriptorsAreClosedBeforeExec() throws {
        let leaked = open("/etc/hosts", O_RDONLY)  // deliberately not close-on-exec
        XCTAssertGreaterThan(leaked, 2)
        defer { close(leaked) }
        var child = try spawn(["/bin/sh", "-c", "test -e /dev/fd/\(leaked) && exit 7; exit 0"])
        XCTAssertEqual(agb_release(&child), 0)
        let status = reap(child.pid)
        XCTAssertEqual((status >> 8) & 0xff, 0, "descriptor \(leaked) reached the executed image")
    }

    func testChildLeadsItsOwnProcessGroup() throws {
        var child = try spawnSleep()
        XCTAssertEqual(getpgid(child.pid), child.pid)
        XCTAssertNotEqual(getpgid(child.pid), getpgrp())
        agb_abort(&child)
        _ = reap(child.pid)
    }

    func testReleaseToADeadChildIsReportedWithoutSigpipe() throws {
        // Default SIGPIPE disposition: without F_SETNOSIGPIPE this would kill the test runner.
        var child = try spawnSleep()
        kill(child.pid, SIGKILL)
        _ = reap(child.pid)
        XCTAssertEqual(agb_release(&child), EPIPE)
    }

    func testAgentStartsWithDefaultSignalDispositions() throws {
        let previous = signal(SIGPIPE, SIG_IGN)
        defer { signal(SIGPIPE, previous) }
        var child = try spawn(["/bin/sh", "-c", "kill -PIPE $$; exit 0"])
        XCTAssertEqual(agb_release(&child), 0)
        let status = reap(child.pid)
        XCTAssertEqual(status & 0x7f, SIGPIPE, "SIGPIPE stayed ignored in the executed image")
    }

    func testDescriptorsAboveTheSoftLimitAreClosedToo() throws {
        try checkDescriptorAboveTheSoftLimitIsClosed()
    }

    func testDescriptorsAboveTheSoftLimitAreClosedWhenTooManyForTheStackListing() throws {
        // More open descriptors than agb_spawn_gated lists on the stack: the heap listing.
        let extras = (0..<80).map { _ in open("/etc/hosts", O_RDONLY) }
        defer { extras.forEach { close($0) } }
        XCTAssertTrue(extras.allSatisfy { $0 >= 0 })
        try checkDescriptorAboveTheSoftLimitIsClosed()
    }

    private func checkDescriptorAboveTheSoftLimitIsClosed() throws {
        let original = open("/etc/hosts", O_RDONLY)
        defer { close(original) }
        let high: Int32 = 300
        XCTAssertEqual(dup2(original, high), high)
        defer { close(high) }
        var limit = rlimit()
        XCTAssertEqual(getrlimit(RLIMIT_NOFILE, &limit), 0)
        let saved = limit
        limit.rlim_cur = 256
        XCTAssertEqual(setrlimit(RLIMIT_NOFILE, &limit), 0)
        var child: agb_gated_child
        do {
            child = try spawn(["/bin/sh", "-c", "test -e /dev/fd/\(high) && exit 7; exit 0"])
        } catch {
            var restore = saved
            setrlimit(RLIMIT_NOFILE, &restore)
            throw error
        }
        var restore = saved
        XCTAssertEqual(setrlimit(RLIMIT_NOFILE, &restore), 0)
        XCTAssertEqual(agb_release(&child), 0)
        XCTAssertEqual((reap(child.pid) >> 8) & 0xff, 0, "descriptor \(high) reached the executed image")
    }

    func testInvalidInputsAreRejected() {
        var pidOut: Int32 = 0, version: Int32 = 0
        XCTAssertEqual(agb_audit_identity(0, &pidOut, &version), EINVAL)
        var child = agb_gated_child(pid: 0, release_fd: -1)
        XCTAssertEqual(agb_spawn_gated(nil, nil, nil, &child), EINVAL)
    }
}
