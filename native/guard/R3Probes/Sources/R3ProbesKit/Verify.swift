import Foundation

public enum VerifyMode: String, CaseIterable {
    /// No enforcement: proves the probes themselves work.
    case baseline
    /// A run confined by File Guard under the fixture contract.
    case enforced
}

public struct Verdict: Equatable {
    public let passed: Bool
    public let note: String
}

public struct VerificationRow {
    public let id: String
    public let row: String
    public let expected: String
    public let outcome: String
    public let verdict: Verdict
}

public enum Verifier {
    /// The errno an ES AUTH denial surfaces as. EACCES comes from ordinary permission
    /// checks (mode bits, sandbox), so it is not evidence of a guard denial.
    static let denialErrno = "EPERM"

    public static func judge(_ spec: ProbeSpec, _ result: ProbeResult?, mode: VerifyMode,
                             volumeCaseSensitive: Bool) -> Verdict {
        guard let result else { return Verdict(passed: false, note: "missing result") }
        switch result.status {
        case .failed: return Verdict(passed: false, note: "harness failure")
        case .unavailable: return Verdict(passed: false, note: "not measured")
        case .notApplicable: return judgeNotApplicable(spec, volumeCaseSensitive: volumeCaseSensitive)
        case .ok, .error: break
        }
        let succeeded = result.status == .ok
        if mode == .baseline {
            return succeeded ? Verdict(passed: true, note: "ok") : Verdict(passed: false, note: "baseline must succeed")
        }
        let failedAt = "\(result.errno ?? "?") at \(result.step ?? "?")"
        switch spec.expected {
        case .allowed:
            return succeeded ? Verdict(passed: true, note: "allowed") : Verdict(passed: false, note: "expected allowed")
        case .denied:
            if succeeded { return Verdict(passed: false, note: "NOT DENIED") }
            guard result.errno == denialErrno else {
                return Verdict(passed: false, note: "\(result.errno ?? "?") is not an ES denial (EPERM)")
            }
            guard spec.denialSteps.contains(result.step ?? "") else {
                return Verdict(passed: false, note: "denied at \(result.step ?? "?"), not at the probe's own operation")
            }
            return Verdict(passed: true, note: "denied")
        case .notMediatedByES:
            // A measurement, not an assertion: both answers are recorded for the report.
            if succeeded { return Verdict(passed: true, note: "RESIDUAL: path open") }
            if case .inheritedRead = spec.action, result.errno == "EBADF", result.step == "fstat" {
                return Verdict(passed: true, note: "closed by launcher (EBADF)")
            }
            return Verdict(passed: true, note: "closed: \(failedAt)")
        case .measured:
            return Verdict(passed: true, note: succeeded ? "RESIDUAL: succeeded" : "closed: \(failedAt)")
        case .expectedGap:
            return Verdict(passed: true, note: succeeded ? "KNOWN GAP: not denied" : "gap closed? \(failedAt)")
        }
    }

    private static func judgeNotApplicable(_ spec: ProbeSpec, volumeCaseSensitive: Bool) -> Verdict {
        switch spec.notApplicable {
        case .caseSensitiveVolume?:
            return volumeCaseSensitive ? Verdict(passed: true, note: "n/a on a case-sensitive volume")
                : Verdict(passed: false, note: "n/a on a case-insensitive volume: the alias must resolve")
        case .aclUnsupported?:
            return Verdict(passed: true, note: "n/a: volume does not support ACLs")
        case nil:
            return Verdict(passed: false, note: "not applicable is not expected here")
        }
    }

    /// Checks that the results belong to this fixture, then compares them. Enforced mode
    /// refuses to run without the guard's action records.
    public static func verify(_ report: RunReport, manifest: FixtureManifest, root: String, mode: VerifyMode,
                              guardRecords: [GuardRecord]?) throws -> [VerificationRow] {
        guard manifest.root == root, report.root == manifest.root else {
            throw HarnessError("results root \(printable(report.root)) does not match the fixture manifest root \(printable(manifest.root))")
        }
        guard report.volumeCaseSensitive == manifest.volumeCaseSensitive else {
            throw HarnessError("results report a different volume case sensitivity than the fixture manifest")
        }
        switch (mode, guardRecords) {
        case (.enforced, nil):
            throw HarnessError("enforced verification needs --guard-records <file>: the guard's action records for this run. "
                + "An EPERM alone does not show that the guard denied the operation.")
        case (.baseline, _?):
            throw HarnessError("--guard-records applies only to --mode enforced")
        default:
            return rows(for: report, mode: mode, guardRecords: guardRecords ?? [], taskId: manifest.taskId)
        }
    }

    /// Per-probe rows. In enforced mode every passing `denied` probe also needs a guard
    /// denial record (this run's task, the probe's event, operations and target) inside
    /// its own sequence window: after its last start marker record and before its first
    /// end marker record after that. Startup and exit reads, other probes' records and
    /// other tasks' records therefore cannot stand in for it.
    public static func rows(for report: RunReport, mode: VerifyMode, guardRecords: [GuardRecord] = [],
                            taskId: String) -> [VerificationRow] {
        let records = guardRecords.sorted { $0.sequence < $1.sequence }
        let windows = markerWindows(records, taskId: taskId)
        var rows = Catalog.probes.map { spec -> VerificationRow in
            let matches = report.results.filter { $0.id == spec.id }
            var verdict = matches.count > 1 ? Verdict(passed: false, note: "duplicate result")
                : judge(spec, matches.first, mode: mode, volumeCaseSensitive: report.volumeCaseSensitive)
            if mode == .enforced, spec.expected == .denied, verdict.passed, let denial = spec.guardDenial {
                if let window = windows[spec.id] {
                    if let index = window.first(where: { records[$0].isDenial(matching: denial, taskId: taskId) }) {
                        verdict = Verdict(passed: true, note: "denied (record \(records[index].sequence))")
                    } else {
                        verdict = Verdict(passed: false, note: "no guard denial in this probe's window: \(denial.summary)")
                    }
                } else {
                    verdict = Verdict(passed: false, note: "no start and end marker records for this probe")
                }
            }
            return VerificationRow(id: spec.id, row: spec.row.rawValue,
                                   expected: mode == .baseline ? "success" : spec.expected.rawValue,
                                   outcome: matches.first?.summary ?? "-", verdict: verdict)
        }
        for result in report.results where Catalog.spec(result.id) == nil {
            rows.append(VerificationRow(id: result.id, row: "-", expected: "-", outcome: result.summary,
                                        verdict: Verdict(passed: false, note: "unknown probe id")))
        }
        return rows
    }

    /// Record index ranges per probe, in probe order: from the probe's last start marker
    /// (a child probe's `sub-probe` repeats it after its startup) before any later probe's
    /// start marker, to the probe's first end marker after that (written right after the
    /// operation, before the result is encoded or the child exits).
    static func markerWindows(_ records: [GuardRecord], taskId: String) -> [String: Range<Int>] {
        let markers = records.map { $0.marker(taskId: taskId) }
        func isStart(_ index: Int, _ ids: Set<String>) -> Bool {
            markers[index].map { !$0.end && ids.contains($0.probeId) } ?? false
        }
        let ids = Catalog.probes.map(\.id)
        var windows: [String: Range<Int>] = [:]
        var cursor = 0
        for (position, id) in ids.enumerated() {
            let later = Set(ids[(position + 1)...])
            guard let first = (cursor..<records.count).first(where: { isStart($0, [id]) }) else { continue }
            let next = ((first + 1)..<records.count).first(where: { isStart($0, later) }) ?? records.count
            let start = (first..<next).last(where: { isStart($0, [id]) })!
            cursor = next
            guard let end = ((start + 1)..<next).first(where: { markers[$0].map { $0.end && $0.probeId == id } ?? false })
            else { continue }
            windows[id] = (start + 1)..<end
        }
        return windows
    }

    public static func table(_ rows: [VerificationRow]) -> String {
        let header = ["PROBE", "ROW", "EXPECTED", "OUTCOME", "VERDICT"]
        let cells = rows.map {
            [$0.id, $0.row, $0.expected, $0.outcome, ($0.verdict.passed ? "PASS " : "FAIL ") + $0.verdict.note].map(printable)
        }
        return TextTable.render(header: header, rows: cells)
    }

    /// Roadmap rows no probe covers, printed after every verification.
    public static var uncoveredSummary: String {
        (["Not covered by these probes (roadmap section 5):"] + Catalog.uncoveredRows.map { "  - " + $0 })
            .joined(separator: "\n")
    }
}

enum TextTable {
    static func render(header: [String], rows: [[String]]) -> String {
        let widths = header.indices.map { column in
            ([header] + rows).map { $0[column].count }.max() ?? 0
        }
        func line(_ cells: [String]) -> String {
            zip(cells, widths).map { $0.padding(toLength: $1, withPad: " ", startingAt: 0) }
                .joined(separator: "  ").trimmingTrailingSpaces()
        }
        return ([line(header)] + rows.map(line)).joined(separator: "\n")
    }
}

private extension String {
    func trimmingTrailingSpaces() -> String {
        var text = self
        while text.hasSuffix(" ") { text.removeLast() }
        return text
    }
}
