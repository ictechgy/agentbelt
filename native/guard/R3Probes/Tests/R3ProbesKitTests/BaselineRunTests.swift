// End to end without enforcement: setup, fd-server, run and verify as separate processes
// of the built r3-probes binary, all inside a fresh temporary root.
import Darwin
import XCTest
@testable import R3ProbesKit

final class BaselineRunTests: XCTestCase {
    private var scratch = ""
    private var root: String { scratch + "/fixture" }

    private var binary: String {
        Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("r3-probes").path
    }

    override func setUpWithError() throws {
        scratch = try RootSafety.makeTemporaryRoot()
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: binary), "r3-probes binary not built")
    }

    override func tearDownWithError() throws {
        if RootSafety.isAllowed(resolved: scratch) { try? FileManager.default.removeItem(atPath: scratch) }
    }

    @discardableResult
    private func launch(_ executable: String, _ arguments: [String], output: Pipe? = nil) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = [:]
        process.standardOutput = output ?? FileHandle.nullDevice
        try process.run()
        return process
    }

    private func exitStatus(_ executable: String, _ arguments: [String]) throws -> Int32 {
        let process = try launch(executable, arguments)
        process.waitUntilExit()
        return process.terminationStatus
    }

    /// The shell stands in for the unconfined launcher: `3<` opens the victim before exec.
    private func runProbes(results: String) throws -> Int32 {
        let script = #"exec "$0" run --root "$1" --inherited-fd 3 --json "$2" 3<"$1/outside/victim.txt""#
        return try exitStatus("/bin/sh", ["-c", script, binary, root, results])
    }

    private func verify(_ results: String, _ mode: String, extra: [String] = [], root: String? = nil) throws -> Int32 {
        try exitStatus(binary, ["verify", "--root", root ?? self.root, "--results", results, "--mode", mode] + extra)
    }

    func testBaselineRunSucceedsForEveryProbeAndVerifies() throws {
        XCTAssertEqual(try exitStatus(binary, ["setup", "--root", root]), 0)
        let manifest = try Fixture.manifest(root: root)
        XCTAssertEqual(manifest.root, root)

        let ready = Pipe()
        let server = try launch(binary, ["fd-server", "--root", root, "--timeout", "60"], output: ready)
        defer { if server.isRunning { server.terminate() } }
        let line = String(decoding: ready.fileHandleForReading.availableData, as: UTF8.self)
        XCTAssertEqual(line.trimmingCharacters(in: .whitespacesAndNewlines), "ready")

        let results = scratch + "/results.json"
        XCTAssertEqual(try runProbes(results: results), 0)
        server.waitUntilExit()
        XCTAssertEqual(server.terminationStatus, 0, "fd-server did not serve exactly the helper connections")

        let report = try RunReport.decode(Data(contentsOf: URL(fileURLWithPath: results)))
        XCTAssertEqual(report.results.map(\.id), Catalog.probes.map(\.id))
        XCTAssertEqual(report.volumeCaseSensitive, manifest.volumeCaseSensitive)
        for result in report.results {
            let spec = try XCTUnwrap(Catalog.spec(result.id))
            let acceptable: Set<ProbeResult.Status> = spec.notApplicable != nil ? [.ok, .notApplicable] : [.ok]
            XCTAssertTrue(acceptable.contains(result.status), "\(result.id): \(result.summary)")
        }
        XCTAssertEqual(try verify(results, "baseline"), 0)
        // Enforced verification refuses to run without the guard's action records.
        XCTAssertEqual(try verify(results, "enforced"), 77)
        // With records, the same unenforced results fail: nothing was denied.
        let records = scratch + "/records.json"
        XCTAssertTrue(FileManager.default.createFile(atPath: records, contents: Data("[]".utf8)))
        XCTAssertEqual(try verify(results, "enforced", extra: ["--guard-records", records]), 1)
        XCTAssertEqual(try verify(results, "baseline", extra: ["--guard-records", records]), 77)
        // Results of this root are refused against another fixture.
        let other = scratch + "/other"
        XCTAssertEqual(try exitStatus(binary, ["setup", "--root", other]), 0)
        XCTAssertEqual(try verify(results, "baseline", root: other), 77)

        // Probes consumed fixture entries, so a second run on the same root is refused.
        XCTAssertNotEqual(try runProbes(results: scratch + "/second.json"), 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: scratch + "/second.json"))
    }

    func testContractCommandEmitsSchemaTwo() throws {
        XCTAssertEqual(try exitStatus(binary, ["setup", "--root", root]), 0)
        let output = Pipe()
        let process = try launch(binary, ["contract", "--root", root, "--probe-binary", binary], output: output)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let document = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(document["schema_version"] as? Int, 2)
        // The probe binary may not live inside the fixture.
        XCTAssertEqual(try exitStatus(binary, ["contract", "--root", root, "--probe-binary",
                                               root + "/projectA/bin/allowed-tool"]), 77)
    }

    func testSetupAndRunRefuseRootsOutsideTemporaryAreas() throws {
        let home = NSHomeDirectory() + "/r3-probes-refusal-\(getpid())"
        XCTAssertEqual(try exitStatus(binary, ["setup", "--root", home]), 77)
        XCTAssertFalse(FileManager.default.fileExists(atPath: home))
        XCTAssertEqual(try exitStatus(binary, ["run", "--root", NSHomeDirectory()]), 77)
        XCTAssertEqual(try exitStatus(binary, ["fd-server", "--root", "/private/tmp"]), 77)
    }

    func testRunRefusesATamperedSymlink() throws {
        XCTAssertEqual(try exitStatus(binary, ["setup", "--root", root]), 0)
        let link = root + "/projectA/src/victim-symlink.txt"
        XCTAssertEqual(unlink(link), 0)
        // Retargeted at another fixture file; the check must refuse any change of target.
        XCTAssertEqual(symlink("../../projectB/notes.txt", link), 0)
        XCTAssertEqual(try exitStatus(binary, ["run", "--root", root]), 77)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root + "/projectA/src/probe-created.txt"))
    }
}
