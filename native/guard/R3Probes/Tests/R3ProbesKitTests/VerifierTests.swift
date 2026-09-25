// Expectation and verify logic on synthetic results; nothing touches the filesystem.
import XCTest
@testable import R3ProbesKit

final class VerifierTests: XCTestCase {
    private func spec(_ expected: EnforcedExpectation, _ action: ProbeAction = .read("x", followSymlink: false),
                      notApplicable: NotApplicableCondition? = nil) -> ProbeSpec {
        ProbeSpec("synthetic", .fileScope, expected, action, "test",
                  record: expected == .denied ? .file(["read"], GuardDenial.outside) : nil, notApplicable: notApplicable)
    }

    private let ok = ProbeResult(id: "synthetic", status: .ok, bytes: 3)
    private func denied(_ code: String, at step: String = "open") -> ProbeResult {
        ProbeResult(id: "synthetic", status: .error, errno: code, step: step)
    }

    private func judge(_ spec: ProbeSpec, _ result: ProbeResult?, _ mode: VerifyMode, caseSensitive: Bool = false) -> Verdict {
        Verifier.judge(spec, result, mode: mode, volumeCaseSensitive: caseSensitive)
    }

    func testBaselineRequiresSuccessWhateverTheEnforcedExpectation() {
        for expected in [EnforcedExpectation.allowed, .denied, .notMediatedByES, .measured, .expectedGap] {
            XCTAssertTrue(judge(spec(expected), ok, .baseline).passed)
            XCTAssertFalse(judge(spec(expected), denied("EPERM"), .baseline).passed)
        }
    }

    func testEnforcedDeniedAcceptsOnlyEPERMAtTheProbesOwnStep() {
        XCTAssertTrue(judge(spec(.denied), denied("EPERM"), .enforced).passed)
        // EACCES comes from mode bits or a sandbox, not from an ES denial.
        XCTAssertFalse(judge(spec(.denied), denied("EACCES"), .enforced).passed)
        // ENOENT means the probe never reached a decision.
        XCTAssertFalse(judge(spec(.denied), denied("ENOENT"), .enforced).passed)
        XCTAssertEqual(judge(spec(.denied), ok, .enforced).note, "NOT DENIED")
        // A denial of some other step (a helper connect, a spawn) is not this probe's denial.
        XCTAssertFalse(judge(spec(.denied), denied("EPERM", at: "connect"), .enforced).passed)
        XCTAssertFalse(judge(spec(.denied), denied("EPERM", at: "spawn"), .enforced).passed)
        XCTAssertTrue(judge(spec(.denied, .exec("x")), denied("EPERM", at: "spawn"), .enforced).passed)
        XCTAssertTrue(judge(spec(.denied, .received(.victim, .map(2))), denied("EPERM", at: "mmap"), .enforced).passed)
        XCTAssertFalse(judge(spec(.denied, .received(.victim, .map(2))), denied("EPERM", at: "connect"), .enforced).passed)
    }

    func testChildProbesAcceptOnlyTheTargetsStepNotTheSpawn() throws {
        let child = try XCTUnwrap(Catalog.spec("child.read-outside"))
        XCTAssertTrue(judge(child, ProbeResult(id: child.id, status: .error, errno: "EPERM", step: "open"), .enforced).passed)
        XCTAssertFalse(judge(child, ProbeResult(id: child.id, status: .error, errno: "EPERM", step: "spawn"), .enforced).passed)
    }

    func testEnforcedAllowedRequiresSuccess() {
        XCTAssertTrue(judge(spec(.allowed), ok, .enforced).passed)
        XCTAssertFalse(judge(spec(.allowed), denied("EPERM"), .enforced).passed)
    }

    func testMeasurementsAreRecordedEitherWay() {
        let open = judge(spec(.notMediatedByES), ok, .enforced)
        XCTAssertTrue(open.passed)
        XCTAssertTrue(open.note.hasPrefix("RESIDUAL"))
        let closed = judge(spec(.notMediatedByES), denied("EPERM", at: "connect"), .enforced)
        XCTAssertTrue(closed.passed)
        XCTAssertEqual(closed.note, "closed: EPERM at connect")
        let launcher = judge(spec(.notMediatedByES, .inheritedRead), denied("EBADF", at: "fstat"), .enforced)
        XCTAssertEqual(launcher, Verdict(passed: true, note: "closed by launcher (EBADF)"))
        XCTAssertTrue(judge(spec(.measured), ok, .enforced).note.hasPrefix("RESIDUAL"))
        XCTAssertTrue(judge(spec(.expectedGap), ok, .enforced).note.hasPrefix("KNOWN GAP"))
        XCTAssertTrue(judge(spec(.expectedGap), denied("EPERM"), .enforced).passed)
    }

    func testUnmeasuredOrBrokenProbesNeverPass() {
        let unavailable = ProbeResult(id: "synthetic", status: .unavailable, detail: "no helper")
        let failed = ProbeResult(id: "synthetic", status: .failed, detail: "broken")
        for mode in VerifyMode.allCases {
            for expected in [EnforcedExpectation.allowed, .denied, .notMediatedByES, .measured, .expectedGap] {
                XCTAssertFalse(judge(spec(expected), unavailable, mode).passed)
                XCTAssertFalse(judge(spec(expected), failed, mode).passed)
                XCTAssertFalse(judge(spec(expected), nil, mode).passed)
            }
        }
    }

    func testNotApplicableOnlyWhereItsConditionHolds() {
        let result = ProbeResult(id: "synthetic", status: .notApplicable, detail: "no alias")
        let alias = spec(.denied, notApplicable: .caseSensitiveVolume)
        XCTAssertTrue(judge(alias, result, .baseline, caseSensitive: true).passed)
        XCTAssertTrue(judge(alias, result, .enforced, caseSensitive: true).passed)
        // On a case-insensitive volume the alias resolves, so n/a is a harness problem.
        XCTAssertFalse(judge(alias, result, .baseline, caseSensitive: false).passed)
        XCTAssertTrue(judge(spec(.denied, notApplicable: .aclUnsupported), result, .baseline).passed)
        XCTAssertFalse(judge(spec(.denied), result, .baseline, caseSensitive: true).passed)
    }

    private func report(_ results: [ProbeResult], root: String = "/private/tmp/x") -> RunReport {
        RunReport(root: root, inheritedFd: 3, volumeCaseSensitive: false, results: results)
    }

    func testRowsFlagMissingDuplicateAndUnknownResults() {
        let all = Catalog.probes.map { ProbeResult(id: $0.id, status: .ok) }
        let complete = Verifier.rows(for: report(all), mode: .baseline, taskId: taskId)
        XCTAssertEqual(complete.filter { !$0.verdict.passed }.count, 0)

        var altered = Array(all.dropFirst())
        altered.append(all[1])
        altered.append(ProbeResult(id: "made.up", status: .ok))
        let rows = Verifier.rows(for: report(altered), mode: .baseline, taskId: taskId)
        let failures = Dictionary(uniqueKeysWithValues: rows.filter { !$0.verdict.passed }.map { ($0.id, $0.verdict.note) })
        XCTAssertEqual(failures[all[0].id], "missing result")
        XCTAssertEqual(failures[all[1].id], "duplicate result")
        XCTAssertEqual(failures["made.up"], "unknown probe id")
        XCTAssertEqual(failures.count, 3)
    }

    // MARK: Guard records

    /// An idealized enforced run: every probe gets the outcome its expectation names.
    private func enforcedResults() -> [ProbeResult] {
        Catalog.probes.map { spec in
            switch spec.expected {
            case .denied:
                return ProbeResult(id: spec.id, status: .error, errno: "EPERM", step: spec.denialSteps.sorted().first!)
            default:
                return ProbeResult(id: spec.id, status: .ok)
            }
        }
    }

    private let taskId = "r3-probes-project-a-0123456789abcdef"

    /// Builds a synthetic record stream, as the guard would export it.
    private struct Stream {
        let taskId: String
        var items: [[String: Any]] = []

        mutating func add(_ event: String, _ operations: [String], _ target: String, allowed: Bool, task: String? = nil) {
            items.append(["sequence": items.count + 1, "event": event, "task_id": task ?? taskId, "revision": 1,
                          "allowed": allowed, "reason": allowed ? "allowed" : "outside_allow_scope",
                          "operations": operations, "target": target])
        }

        mutating func marker(_ probeId: String, end: Bool = false) {
            add("file", ["read"], "src/.marks/" + probeId + (end ? ".end" : ""), allowed: true)
        }

        /// The startup reads every r3-probes process makes outside the workspace.
        mutating func startupNoise() {
            for _ in 0..<15 { add("file", ["read"], GuardDenial.outside, allowed: false) }
        }

        mutating func denial(_ denial: GuardDenial, task: String? = nil) {
            add(denial.event, denial.operations, denial.target, allowed: false, task: task)
        }

        var data: Data { try! JSONSerialization.data(withJSONObject: ["records": items]) }
    }

    /// A complete enforced stream: startup noise, then per probe its start marker (a child
    /// probe: parent marker, child startup noise, child marker), its denial and its end
    /// marker (a child probe: child end marker, the child's exit noise, parent end marker).
    private func stream(dropping skipped: String? = nil, misplacing misplaced: String? = nil,
                        replacing replaced: String? = nil, dropMarker: String? = nil,
                        dropEndMarker: String? = nil) -> Stream {
        var stream = Stream(taskId: taskId)
        stream.startupNoise()
        for spec in Catalog.probes {
            if spec.id != dropMarker { stream.marker(spec.id) }
            if spec.childTarget != nil {
                stream.startupNoise()
                stream.marker(spec.id)
            }
            defer {
                if spec.id != dropEndMarker { stream.marker(spec.id, end: true) }
                if spec.childTarget != nil {
                    // Exit reads of the child (result encoding, logging preferences).
                    stream.add("file", ["read"], GuardDenial.outside, allowed: false)
                    stream.marker(spec.id, end: true)
                }
            }
            guard let denial = spec.guardDenial, spec.id != skipped else { continue }
            if spec.id == replaced {
                // Right shape, but from an earlier fixture's task.
                stream.denial(denial, task: "r3-probes-project-a-ffffffffffffffff")
            } else if spec.id == misplaced {
                // The denial happened, but before every marker: it cannot be this probe's.
                stream.denial(denial)
                stream.items.insert(stream.items.removeLast(), at: 0)
                stream.items = stream.items.enumerated().map { var item = $0.element; item["sequence"] = $0.offset + 1; return item }
            } else {
                stream.denial(denial)
            }
        }
        return stream
    }

    private func failures(_ records: Data) throws -> [String: String] {
        let rows = Verifier.rows(for: report(enforcedResults()), mode: .enforced,
                                 guardRecords: try GuardRecord.parse(records), taskId: taskId)
        return Dictionary(uniqueKeysWithValues: rows.filter { !$0.verdict.passed }.map { ($0.id, $0.verdict.note) })
    }

    private var deniedIds: Set<String> { Set(Catalog.probes.filter { $0.expected == .denied }.map(\.id)) }

    func testEnforcedDenialsNeedARecordInTheirOwnWindow() throws {
        XCTAssertEqual(try failures(stream().data), [:])
        // A missing record fails exactly that probe, although identical records surround it.
        let missing = try failures(stream(dropping: "outside.chmod").data)
        XCTAssertEqual(missing.keys.sorted(), ["outside.chmod"])
        XCTAssertTrue(missing["outside.chmod"]!.hasPrefix("no guard denial in this probe's window"))
        XCTAssertEqual(try failures(stream(dropping: "exec.not-allowed").data).keys.sorted(), ["exec.not-allowed"])
        // A matching record before the probe's marker does not count.
        XCTAssertEqual(try failures(stream(misplacing: "projectB.read").data).keys.sorted(), ["projectB.read"])
        // A record from another (stale) task does not count.
        XCTAssertEqual(try failures(stream(replacing: "outside.read").data).keys.sorted(), ["outside.read"])
        // Without its start or end marker, a probe has no window.
        XCTAssertEqual(try failures(stream(dropMarker: "outside.mkdir").data)["outside.mkdir"],
                       "no start and end marker records for this probe")
        XCTAssertEqual(try failures(stream(dropEndMarker: "outside.read").data)["outside.read"],
                       "no start and end marker records for this probe")
    }

    func testStartupNoiseAndStaleTasksNeverSatisfyDenials() throws {
        // Only noise: the ~15 startup denials look like outside reads but precede every marker.
        var noise = Stream(taskId: taskId)
        noise.startupNoise()
        for spec in Catalog.probes {
            noise.marker(spec.id)
            noise.marker(spec.id, end: true)
        }
        XCTAssertEqual(Set(try failures(noise.data).keys), deniedIds)
        // A complete run recorded under an earlier fixture's task ID matches nothing.
        var stale = stream()
        stale.items = stale.items.map { var item = $0; item["task_id"] = "r3-probes-project-a-ffffffffffffffff"; return item }
        XCTAssertEqual(Set(try failures(stale.data).keys), deniedIds)
    }

    func testChildStartupAndExitNoiseFallOutsideTheChildsWindow() throws {
        // The child's startup reads come after the parent's marker but before the child's
        // own start marker, and its exit reads come after its end marker; without the
        // child's denial neither may satisfy the probe.
        let failed = try failures(stream(dropping: "child.read-outside").data)
        XCTAssertEqual(failed.keys.sorted(), ["child.read-outside"])
        let windows = Verifier.markerWindows(try GuardRecord.parse(stream().data), taskId: taskId)
        XCTAssertEqual(windows.count, Catalog.probes.count)
    }

    func testExitNoiseAfterTheEndMarkerDoesNotSatisfyAProbe() throws {
        // outside.read's own denial is missing; an identical denial right after its end
        // marker (exit or encoding work) must not stand in for it.
        var records = stream(dropping: "outside.read")
        let end = try XCTUnwrap(records.items.firstIndex { $0["target"] as? String == "src/.marks/outside.read.end" })
        records.items.insert(["event": "file", "task_id": taskId, "revision": 1, "allowed": false,
                              "reason": "outside_allow_scope", "operations": ["read"], "target": GuardDenial.outside],
                             at: end + 1)
        records.items = records.items.enumerated().map { var item = $0.element; item["sequence"] = $0.offset + 1; return item }
        XCTAssertEqual(try failures(records.data).keys.sorted(), ["outside.read"])
    }

    func testGuardRecordParsingIsStrict() throws {
        let valid: [String: Any] = ["sequence": 1, "event": "file", "task_id": NSNull(), "revision": NSNull(),
                                    "allowed": false, "reason": "tracking_lost", "operations": [], "target": "unattributed"]
        XCTAssertEqual(try GuardRecord.parse(JSONSerialization.data(withJSONObject: [valid])).count, 1)
        func rejects(_ change: (inout [String: Any]) -> Void) {
            var item = valid
            change(&item)
            XCTAssertThrowsError(try GuardRecord.parse(JSONSerialization.data(withJSONObject: [item])))
        }
        rejects { $0["extra"] = 1 }
        rejects { $0.removeValue(forKey: "target") }
        rejects { $0["allowed"] = 0 }
        rejects { $0["sequence"] = true }
        rejects { $0["sequence"] = 1.5 }
        rejects { $0["operations"] = ["delete"] }
        rejects { $0["operations"] = ["read", "read"] }
        rejects { $0["revision"] = 0 }
        rejects { $0["task_id"] = 7 }
        XCTAssertThrowsError(try GuardRecord.parse(JSONSerialization.data(withJSONObject: [valid, valid])),
                             "repeated sequence accepted")
        XCTAssertThrowsError(try GuardRecord.parse(Data("{\"entries\": []}".utf8)))
        // Lost records (a sequence gap) could widen a marker window: refuse the stream.
        var third = valid
        third["sequence"] = 3
        XCTAssertThrowsError(try GuardRecord.parse(JSONSerialization.data(withJSONObject: [valid, third])),
                             "sequence gap accepted")
        var second = valid
        second["sequence"] = 2
        XCTAssertEqual(try GuardRecord.parse(JSONSerialization.data(withJSONObject: [third, valid, second])).count, 3)
    }

    // MARK: Provenance

    private func manifest(root: String, caseSensitive: Bool = false) -> FixtureManifest {
        FixtureManifest(root: root, taskId: taskId, volumeCaseSensitive: caseSensitive, entries: [], aliases: [],
                        allow: [], deny: [])
    }

    func testVerifyRefusesForeignResultsAndEnforcedRunsWithoutRecords() throws {
        let root = "/private/tmp/fixture"
        let results = report(enforcedResults(), root: root)
        XCTAssertThrowsError(try Verifier.verify(report(enforcedResults(), root: "/private/tmp/other"),
                                                 manifest: manifest(root: root), root: root, mode: .baseline, guardRecords: nil))
        XCTAssertThrowsError(try Verifier.verify(results, manifest: manifest(root: "/private/tmp/other"), root: root,
                                                 mode: .baseline, guardRecords: nil))
        XCTAssertThrowsError(try Verifier.verify(results, manifest: manifest(root: root, caseSensitive: true), root: root,
                                                 mode: .baseline, guardRecords: nil))
        XCTAssertThrowsError(try Verifier.verify(results, manifest: manifest(root: root), root: root,
                                                 mode: .enforced, guardRecords: nil)) { error in
            XCTAssertTrue("\(error)".contains("--guard-records"))
        }
        XCTAssertThrowsError(try Verifier.verify(results, manifest: manifest(root: root), root: root,
                                                 mode: .baseline, guardRecords: []))
        let rows = try Verifier.verify(results, manifest: manifest(root: root), root: root, mode: .enforced,
                                       guardRecords: GuardRecord.parse(stream().data))
        XCTAssertEqual(rows.filter { !$0.verdict.passed }.count, 0)
    }

    func testPrintedStringsEscapeControlCharacters() {
        XCTAssertEqual(printable("a\u{1b}[2Jb\nc\u{202e}d"), "a\\u{1b}[2Jb\\u{a}c\\u{202e}d")
        let crafted = ProbeResult(id: "evil\u{1b}]0;x\u{07}", status: .ok)
        let text = Verifier.table(Verifier.rows(for: report([crafted]), mode: .baseline, taskId: taskId))
        XCTAssertFalse(text.unicodeScalars.contains { $0.value == 0x1b || $0.value == 0x07 })
    }

    func testReportRoundTripAndForeignDocumentsAreRejected() throws {
        let original = report([ok])
        XCTAssertEqual(try RunReport.decode(original.encoded()), original)
        var foreign = original
        foreign.harness = "something-else"
        XCTAssertThrowsError(try RunReport.decode(foreign.encoded()))
        foreign = original
        foreign.formatVersion = 1
        XCTAssertThrowsError(try RunReport.decode(foreign.encoded()))
    }

    // MARK: Catalog

    func testCatalogIsConsistent() {
        let ids = Catalog.probes.map(\.id)
        XCTAssertEqual(Set(ids).count, ids.count, "duplicate probe id")
        for spec in Catalog.probes {
            XCTAssertFalse(spec.rationale.isEmpty)
            XCTAssertFalse(spec.id.hasSuffix(".end"), "probe id collides with an end marker name")
            // Every denial names the guard record and at least one step it may surface at.
            XCTAssertEqual(spec.guardDenial != nil, spec.expected == .denied, spec.id)
            if spec.expected == .denied { XCTAssertFalse(spec.denialSteps.isEmpty, spec.id) }
            if let denial = spec.guardDenial { XCTAssertEqual(denial.operations, denial.operations.sorted()) }
            if case let .child(target) = spec.action {
                let child = Catalog.spec(target)
                XCTAssertNotNil(child)
                XCTAssertEqual(child?.expected, spec.expected, "child probe expectation differs from its target")
            }
        }
        XCTAssertEqual(Catalog.spec("link.preexisting-hardlink-read")?.expected, .expectedGap)
        for row in AcceptanceRow.allCases {
            XCTAssertTrue(Catalog.probes.contains { $0.row == row }, row.rawValue)
        }
        XCTAssertFalse(Catalog.uncoveredRows.isEmpty)
        XCTAssertEqual(Catalog.helperConnections, 4)
    }

    func testReadmeDocumentsEveryProbe() throws {
        let readme = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("README.md")
        let text = try String(contentsOf: readme, encoding: .utf8)
        for record in Catalog.expectationTable {
            XCTAssertTrue(text.contains("| `\(record.id)` | \(record.row) | \(record.expectedWhenEnforced) |"),
                          "README row missing or stale for \(record.id)")
        }
        for row in Catalog.uncoveredRows {
            XCTAssertTrue(text.contains(row), "README misses uncovered row: \(row)")
        }
    }
}
