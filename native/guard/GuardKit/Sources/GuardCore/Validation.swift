import Foundation

/// Rejected input. Messages are fixed strings and never interpolate the rejected value.
public struct GuardError: Error, Equatable, CustomStringConvertible {
    public let reason: String
    public init(_ reason: String) { self.reason = reason }
    public var description: String { "GuardError(\(reason))" }
}

/// Shared validators. Semantics follow task_policy.py so both implementations agree.
public enum Validate {
    /// Same alphabet as task_policy._identifier: 1-128 of [A-Za-z0-9._:-], alphanumeric first.
    public static func identifier(_ value: String) -> Bool {
        let scalars = Array(value.unicodeScalars)
        guard (1...128).contains(scalars.count), let first = scalars.first, isAlphanumeric(first) else { return false }
        return scalars.allSatisfy { isAlphanumeric($0) || $0 == "." || $0 == "_" || $0 == ":" || $0 == "-" }
    }

    /// Canonical absolute spelling, as task_policy._path: no resolution, no empty/./.. parts.
    /// Scans UTF-8 bytes without allocating: this runs on every ES authorization. Byte-level
    /// checks equal the Python code-point checks because "/", ".", controls and DEL are
    /// ASCII and never occur inside a multi-byte sequence.
    public static func canonicalPath(_ value: String) -> Bool {
        var count = 0
        var componentLength = 0
        var dots = 0
        var first = true
        for byte in value.utf8 {
            count += 1
            if count > 4096 || byte < 0x20 || byte == 0x7F { return false }
            if first {
                if byte != UInt8(ascii: "/") { return false }
                first = false
                continue
            }
            if byte == UInt8(ascii: "/") {
                if componentLength == 0 || componentLength == dots && dots <= 2 { return false }
                componentLength = 0
                dots = 0
            } else {
                componentLength += 1
                if byte == UInt8(ascii: ".") { dots += 1 }
            }
        }
        if first { return false }
        if count == 1 { return true }
        return componentLength > 0 && !(componentLength == dots && dots <= 2)
    }

    public static func sha256Hex(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    public static func isAlphanumeric(_ scalar: Unicode.Scalar) -> Bool {
        (48...57).contains(scalar.value) || (65...90).contains(scalar.value) || (97...122).contains(scalar.value)
    }
}
