import Foundation

/// One guard action record, as task_registry `_record_to_dict` writes it.
public struct GuardRecord: Equatable {
    public let sequence: Int
    public let event: String
    public let taskId: String?
    public let revision: Int?
    public let allowed: Bool
    public let reason: String
    public let operations: [String]
    /// Workspace-relative path, `.`, `outside_workspace`, `withheld`, `unattributed` or
    /// `invalid`.
    public let target: String

    public init(sequence: Int, event: String, taskId: String?, revision: Int?, allowed: Bool, reason: String,
                operations: [String], target: String) {
        self.sequence = sequence
        self.event = event
        self.taskId = taskId
        self.revision = revision
        self.allowed = allowed
        self.reason = reason
        self.operations = operations
        self.target = target
    }

    static let fields: Set<String> = ["sequence", "event", "task_id", "revision", "allowed", "reason", "operations", "target"]
    static let operationNames: Set<String> = ["read", "write", "execute"]

    /// Strict parse: a JSON array of records, or an object whose `records` key holds one
    /// (the registry snapshot). Unknown or missing fields, wrong types, unknown operations
    /// and repeated sequence numbers are refused.
    public static func parse(_ data: Data) throws -> [GuardRecord] {
        let document = try JSONSerialization.jsonObject(with: data)
        let list: Any? = (document as? [Any]) ?? (document as? [String: Any])?["records"]
        guard let items = list as? [Any] else { throw HarnessError("guard records: expected an array or {\"records\": [...]}") }
        let records = try items.enumerated().map { try record($0.element, index: $0.offset) }
        guard Set(records.map(\.sequence)).count == records.count else {
            throw HarnessError("guard records: repeated sequence number")
        }
        let sorted = records.sorted { $0.sequence < $1.sequence }
        // A gap means lost records (e.g. a buffer overflow). A missing marker record could
        // then widen a probe's window, so the whole stream is refused as evidence.
        for (previous, next) in zip(sorted, sorted.dropFirst()) where next.sequence != previous.sequence + 1 {
            throw HarnessError("guard records: sequence gap after \(previous.sequence); records were lost")
        }
        return sorted
    }

    private static func record(_ item: Any, index: Int) throws -> GuardRecord {
        func invalid(_ field: String) -> HarnessError { HarnessError("guard records: entry \(index) has an invalid \(field)") }
        guard let object = item as? [String: Any], Set(object.keys) == fields else { throw invalid("field set") }
        guard let sequence = integer(object["sequence"]), sequence >= 0 else { throw invalid("sequence") }
        guard let event = object["event"] as? String else { throw invalid("event") }
        let taskId = object["task_id"] as? String
        guard taskId != nil || object["task_id"] is NSNull else { throw invalid("task_id") }
        let revision = integer(object["revision"])
        guard (revision ?? 1) >= 1, revision != nil || object["revision"] is NSNull else { throw invalid("revision") }
        guard let allowed = boolean(object["allowed"]) else { throw invalid("allowed") }
        guard let reason = object["reason"] as? String else { throw invalid("reason") }
        guard let operations = object["operations"] as? [String], Set(operations).isSubset(of: operationNames),
              Set(operations).count == operations.count else { throw invalid("operations") }
        guard let target = object["target"] as? String else { throw invalid("target") }
        return GuardRecord(sequence: sequence, event: event, taskId: taskId, revision: revision, allowed: allowed,
                           reason: reason, operations: operations.sorted(), target: target)
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              CFNumberIsFloatType(number) == false else { return nil }
        return number.intValue
    }

    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    /// The probe ID and kind when this is an allowed marker read the runner makes right
    /// before (start) or right after (end) a probe's own operation.
    func marker(taskId expectedTaskId: String) -> (probeId: String, end: Bool)? {
        let prefix = FixturePath.markerTarget("")
        guard allowed, taskId == expectedTaskId, event == "file", operations == ["read"], target.hasPrefix(prefix) else {
            return nil
        }
        let name = String(target.dropFirst(prefix.count))
        return name.hasSuffix(FixturePath.endSuffix)
            ? (String(name.dropLast(FixturePath.endSuffix.count)), true) : (name, false)
    }

    func isDenial(matching denial: GuardDenial, taskId expectedTaskId: String) -> Bool {
        !allowed && taskId == expectedTaskId && event == denial.event && operations == denial.operations
            && target == denial.target
    }
}
