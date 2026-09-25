// r3-probes — boundary probes for the R3 acceptance tests. Measures outcomes only; it
// enforces nothing and claims nothing about Endpoint Security.
import Darwin
import Foundation
import ProbeSys
import R3ProbesKit

let usage = """
usage:
  r3-probes setup [--root <new empty dir>]
  r3-probes contract --root <dir> --probe-binary <path>
  r3-probes fd-server --root <dir> [--count <n>] [--timeout <seconds>]
  r3-probes run --root <dir> [--inherited-fd <n>] [--json <file>|-]
  r3-probes verify --root <dir> --results <file> --mode baseline|enforced [--guard-records <file>]
  r3-probes expectations [--json]
Roots must lie under /private/tmp, /private/var/folders or /tmp. Every command except
setup needs the canonical root spelling that setup prints.
"""

struct UsageError: Error { let message: String }

/// `--flag value` pairs only; every flag must be known to the command.
func options(_ arguments: ArraySlice<String>, allowed: Set<String>, switches: Set<String> = []) throws -> [String: String] {
    var parsed: [String: String] = [:]
    var index = arguments.startIndex
    while index < arguments.endIndex {
        let flag = arguments[index]
        if switches.contains(flag) {
            parsed[flag] = ""
            index += 1
            continue
        }
        guard allowed.contains(flag), index + 1 < arguments.endIndex, parsed[flag] == nil else {
            throw UsageError(message: "unexpected or incomplete argument: \(flag)")
        }
        parsed[flag] = arguments[index + 1]
        index += 2
    }
    return parsed
}

func required(_ parsed: [String: String], _ flag: String) throws -> String {
    guard let value = parsed[flag], !value.isEmpty else { throw UsageError(message: "missing \(flag)") }
    return value
}

func integer(_ parsed: [String: String], _ flag: String, default fallback: Int, range: ClosedRange<Int>) throws -> Int {
    guard let text = parsed[flag] else { return fallback }
    guard let value = Int(text), range.contains(value) else { throw UsageError(message: "\(flag) out of range") }
    return value
}

/// The path this binary was started with, unresolved: realpath would stat every ancestor
/// directory, which a confined run may not do. A relative path still works for the child
/// probes, because nothing changes the working directory.
func executablePath() -> String? {
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
    guard r3_self_path(&buffer, buffer.count) == 0 else { return nil }
    return String(cString: buffer)
}

func printError(_ message: String) {
    FileHandle.standardError.write(Data(("r3-probes: " + message + "\n").utf8))
}

func setup(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: ["--root"])
    let root = try parsed["--root"].map(RootSafety.prepareNewRoot) ?? RootSafety.makeTemporaryRoot()
    let manifest = try Fixture.create(root: root)
    print("root: \(root)")
    print("manifest: \(root)/\(Fixture.manifestName) (\(manifest.entries.count) entries)")
    print("volume case-sensitive: \(manifest.volumeCaseSensitive)")
    return 0
}

func contract(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: ["--root", "--probe-binary"])
    let root = try RootSafety.existingRoot(try required(parsed, "--root"))
    let binary = try SchemaTwoContract.probeBinary(try required(parsed, "--probe-binary"), root: root)
    let manifest = try Fixture.manifest(root: root)
    let document = try SchemaTwoContract.document(root: root, taskId: manifest.taskId, probeBinary: binary)
    FileHandle.standardOutput.write(document + Data("\n".utf8))
    return 0
}

func run(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: ["--root", "--inherited-fd", "--json"])
    let inherited = try parsed["--inherited-fd"].map { _ in Int32(try integer(parsed, "--inherited-fd", default: 3, range: 3...1023)) }
    // Checked first, before any open can reuse the number of a descriptor the launcher closed.
    let inheritedOpen = inherited.map { fcntl($0, F_GETFD) != -1 } ?? true
    let root = try RootSafety.existingRoot(try required(parsed, "--root"))
    let output = try parsed["--json"].map { $0 == "-" ? "-" : try RootSafety.outputFile($0) }
    try Fixture.check(root: root, beforeRun: true)
    let runner = ProbeRunner(root: root, inheritedFd: inherited, inheritedFdOpenAtStart: inheritedOpen,
                             executablePath: executablePath())
    let report = RunReport(root: root, inheritedFd: inherited, volumeCaseSensitive: Fixture.volumeCaseSensitive(root: root),
                           results: runner.runAll())
    let data = try report.encoded()
    if output == "-" {
        FileHandle.standardOutput.write(data + Data("\n".utf8))
        return 0
    }
    if let output {
        try data.write(to: URL(fileURLWithPath: output), options: .atomic)
    }
    print(report.results.map { "\($0.id): \($0.summary)" }.joined(separator: "\n"))
    return 0
}

func subProbe(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: ["--root", "--probe", "--mark"])
    let root = try RootSafety.existingRoot(try required(parsed, "--root"))
    guard let spec = Catalog.spec(try required(parsed, "--probe")), !spec.id.hasPrefix("child."),
          let parent = Catalog.spec(try required(parsed, "--mark")), parent.childTarget == spec.id else {
        throw UsageError(message: "unknown or unsupported sub-probe")
    }
    try Fixture.check(root: root, beforeRun: false)
    let result = ProbeRunner(root: root, inheritedFd: nil, executablePath: nil).markThenRun(parent.id, spec)
    FileHandle.standardOutput.write(try JSONEncoder().encode(result))
    return 0
}

func fdServer(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: ["--root", "--count", "--timeout"])
    let root = try RootSafety.existingRoot(try required(parsed, "--root"))
    try Fixture.check(root: root, beforeRun: false)
    try FdServer.serve(root: root, connections: try integer(parsed, "--count", default: Catalog.helperConnections, range: 1...16),
                       timeoutSeconds: try integer(parsed, "--timeout", default: 120, range: 1...3600)) {
        print("ready")
        fflush(stdout)
    }
    return 0
}

func verify(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: ["--root", "--results", "--mode", "--guard-records"])
    guard let mode = VerifyMode(rawValue: try required(parsed, "--mode")) else {
        throw UsageError(message: "--mode must be baseline or enforced")
    }
    let root = try RootSafety.existingRoot(try required(parsed, "--root"))
    let manifest = try Fixture.manifest(root: root)
    let report = try RunReport.decode(try Data(contentsOf: URL(fileURLWithPath: try required(parsed, "--results"))))
    let records = try parsed["--guard-records"].map { try GuardRecord.parse(Data(contentsOf: URL(fileURLWithPath: $0))) }
    let rows = try Verifier.verify(report, manifest: manifest, root: root, mode: mode, guardRecords: records)
    let failures = rows.filter { !$0.verdict.passed }.count
    print(Verifier.table(rows))
    print("\n\(rows.count) probes, \(failures) mismatches (mode: \(mode.rawValue))")
    print("\n" + Verifier.uncoveredSummary)
    return failures == 0 ? 0 : 1
}

func expectations(_ arguments: ArraySlice<String>) throws -> Int32 {
    let parsed = try options(arguments, allowed: [], switches: ["--json"])
    if parsed["--json"] != nil {
        FileHandle.standardOutput.write(try Catalog.expectationJSON() + Data("\n".utf8))
    } else {
        for record in Catalog.expectationTable {
            print("\(record.id)\t\(record.row)\t\(record.expectedWhenEnforced)\t\(record.rationale)")
        }
    }
    return 0
}

func main() -> Int32 {
    // Probes must measure an ordinary user process; root would bypass the file checks
    // under test and widen the damage of any mistake.
    guard geteuid() != 0 else {
        printError("refusing to run as root")
        return 77
    }
    let arguments = CommandLine.arguments.dropFirst()
    let commands: [String: (ArraySlice<String>) throws -> Int32] = [
        "setup": setup, "contract": contract, "run": run, "sub-probe": subProbe, "fd-server": fdServer,
        "verify": verify, "expectations": expectations,
    ]
    guard let name = arguments.first, let command = commands[name] else {
        printError("\n" + usage)
        return 64
    }
    do {
        return try command(arguments.dropFirst())
    } catch let error as UsageError {
        printError(error.message + "\n" + usage)
        return 64
    } catch let error as HarnessError {
        printError(error.description)
        return 77
    } catch {
        printError("\(error)")
        return 70
    }
}

exit(main())
