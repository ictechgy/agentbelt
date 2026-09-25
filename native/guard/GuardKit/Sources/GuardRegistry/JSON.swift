import Foundation

/// JSON value with the distinctions the policy schema relies on: booleans are not
/// integers, and integers are not floats (Python's `type(value) is int`).
public enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case let (.bool(a), .bool(b)): return a == b
        case let (.int(a), .int(b)): return a == b
        case let (.double(a), .double(b)): return a == b
        case let (.string(a), .string(b)): return a.utf8.elementsEqual(b.utf8)
        case let (.array(a), .array(b)): return a == b
        case let (.object(a), .object(b)):
            return a.count == b.count && a.allSatisfy { key, value in b[key].map { $0 == value } ?? false }
        default: return false
        }
    }

    var objectValue: [String: JSONValue]? {
        if case let .object(value) = self { return value }
        return nil
    }

    var arrayValue: [JSONValue]? {
        if case let .array(value) = self { return value }
        return nil
    }

    var stringValue: String? {
        if case let .string(value) = self { return value }
        return nil
    }

    var intValue: Int64? {
        if case let .int(value) = self { return value }
        return nil
    }

    var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

public struct JSONError: Error, Equatable {
    public let reason: String
}

/// Strict decoder matching the Python loaders: duplicate keys, NaN/Infinity, raw control
/// characters, invalid UTF-8, lone surrogates, trailing data and deep nesting are rejected.
/// Integers outside Int64 are rejected (every schema field is bounded by 2^63-1).
public enum StrictJSON {
    /// Python's decoder stops near its recursion limit (about 1000 levels); 512 keeps the
    /// same outcome for realistic documents and bounds the Swift recursion.
    public static let maxDepth = 512

    public static func parse(_ data: Data) throws -> JSONValue {
        var parser = Parser(bytes: Array(data))
        parser.skipWhitespace()
        let value = try parser.value(depth: 0)
        parser.skipWhitespace()
        guard parser.index == parser.bytes.count else { throw JSONError(reason: "trailing data") }
        return value
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0

        mutating func skipWhitespace() {
            while index < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) { index += 1 }
        }

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth < StrictJSON.maxDepth else { throw JSONError(reason: "nesting too deep") }
            guard index < bytes.count else { throw JSONError(reason: "unexpected end") }
            switch bytes[index] {
            case UInt8(ascii: "{"): return try object(depth: depth)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            default: return try number()
            }
        }

        mutating func literal(_ word: String) throws {
            let expected = Array(word.utf8)
            guard index + expected.count <= bytes.count, Array(bytes[index..<index + expected.count]) == expected else {
                throw JSONError(reason: "invalid literal")
            }
            index += expected.count
        }

        mutating func object(depth: Int) throws -> JSONValue {
            index += 1
            var result: [String: JSONValue] = [:]
            var seen = Set<[UInt8]>()
            skipWhitespace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(result) }
            while true {
                skipWhitespace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else { throw JSONError(reason: "expected key") }
                let key = try string()
                // Duplicates are judged on code units, not on Swift's canonical-equivalence equality.
                guard seen.insert(Array(key.utf8)).inserted, result[key] == nil else {
                    throw JSONError(reason: "duplicate key")
                }
                skipWhitespace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { throw JSONError(reason: "expected colon") }
                index += 1
                skipWhitespace()
                result[key] = try value(depth: depth + 1)
                skipWhitespace()
                guard index < bytes.count else { throw JSONError(reason: "unexpected end") }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if bytes[index] == UInt8(ascii: "}") { index += 1; return .object(result) }
                throw JSONError(reason: "expected comma")
            }
        }

        mutating func array(depth: Int) throws -> JSONValue {
            index += 1
            var result: [JSONValue] = []
            skipWhitespace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(result) }
            while true {
                skipWhitespace()
                result.append(try value(depth: depth + 1))
                skipWhitespace()
                guard index < bytes.count else { throw JSONError(reason: "unexpected end") }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if bytes[index] == UInt8(ascii: "]") { index += 1; return .array(result) }
                throw JSONError(reason: "expected comma")
            }
        }

        mutating func string() throws -> String {
            index += 1
            var scalars = String.UnicodeScalarView()
            var raw: [UInt8] = []
            func flushRaw() throws {
                guard !raw.isEmpty else { return }
                // Lossless round trip only: Foundation's decoder would drop a leading BOM.
                let text = String(decoding: raw, as: UTF8.self)
                guard text.utf8.elementsEqual(raw) else { throw JSONError(reason: "invalid UTF-8") }
                scalars.append(contentsOf: text.unicodeScalars)
                raw.removeAll()
            }
            while true {
                guard index < bytes.count else { throw JSONError(reason: "unterminated string") }
                let byte = bytes[index]
                if byte == UInt8(ascii: "\"") {
                    index += 1
                    try flushRaw()
                    return String(scalars)
                }
                if byte < 0x20 { throw JSONError(reason: "control character in string") }
                if byte == UInt8(ascii: "\\") {
                    try flushRaw()
                    scalars.append(try escape())
                    continue
                }
                raw.append(byte)
                index += 1
            }
        }

        mutating func escape() throws -> Unicode.Scalar {
            index += 1
            guard index < bytes.count else { throw JSONError(reason: "unterminated escape") }
            let byte = bytes[index]
            index += 1
            switch byte {
            case UInt8(ascii: "\""): return "\""
            case UInt8(ascii: "\\"): return "\\"
            case UInt8(ascii: "/"): return "/"
            case UInt8(ascii: "b"): return "\u{08}"
            case UInt8(ascii: "f"): return "\u{0C}"
            case UInt8(ascii: "n"): return "\n"
            case UInt8(ascii: "r"): return "\r"
            case UInt8(ascii: "t"): return "\t"
            case UInt8(ascii: "u"):
                let high = try hex4()
                if (0xD800...0xDBFF).contains(high) {
                    guard index + 1 < bytes.count, bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u") else {
                        throw JSONError(reason: "lone surrogate")
                    }
                    index += 2
                    let low = try hex4()
                    guard (0xDC00...0xDFFF).contains(low) else { throw JSONError(reason: "lone surrogate") }
                    let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                    return Unicode.Scalar(combined)!
                }
                guard let scalar = Unicode.Scalar(high) else { throw JSONError(reason: "lone surrogate") }
                return scalar
            default: throw JSONError(reason: "invalid escape")
            }
        }

        mutating func hex4() throws -> UInt32 {
            guard index + 4 <= bytes.count else { throw JSONError(reason: "short unicode escape") }
            var value: UInt32 = 0
            for byte in bytes[index..<index + 4] {
                guard let digit = hexDigit(byte) else { throw JSONError(reason: "invalid unicode escape") }
                value = value * 16 + digit
            }
            index += 4
            return value
        }

        func hexDigit(_ byte: UInt8) -> UInt32? {
            switch byte {
            case 48...57: return UInt32(byte - 48)
            case 65...70: return UInt32(byte - 55)
            case 97...102: return UInt32(byte - 87)
            default: return nil
            }
        }

        mutating func number() throws -> JSONValue {
            let start = index
            if index < bytes.count, bytes[index] == UInt8(ascii: "-") { index += 1 }
            guard index < bytes.count, (48...57).contains(bytes[index]) else { throw JSONError(reason: "invalid value") }
            if bytes[index] == 48 {
                index += 1
            } else {
                while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
            }
            var isInteger = true
            if index < bytes.count, bytes[index] == UInt8(ascii: ".") {
                isInteger = false
                index += 1
                guard index < bytes.count, (48...57).contains(bytes[index]) else { throw JSONError(reason: "invalid number") }
                while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
            }
            if index < bytes.count, bytes[index] == UInt8(ascii: "e") || bytes[index] == UInt8(ascii: "E") {
                isInteger = false
                index += 1
                if index < bytes.count, bytes[index] == UInt8(ascii: "+") || bytes[index] == UInt8(ascii: "-") { index += 1 }
                guard index < bytes.count, (48...57).contains(bytes[index]) else { throw JSONError(reason: "invalid number") }
                while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
            }
            let text = String(decoding: bytes[start..<index], as: UTF8.self)
            if isInteger {
                guard let value = Int64(text) else { throw JSONError(reason: "integer out of range") }
                return .int(value)
            }
            guard let value = Double(text), value.isFinite else { throw JSONError(reason: "invalid number") }
            return .double(value)
        }
    }
}

/// Canonical encoding identical to Python's
/// `json.dumps(value, sort_keys=True, separators=(',', ':'))` (ensure_ascii=True):
/// the proposal digest must be the same in both implementations.
public enum CanonicalJSON {
    public static func encode(_ value: JSONValue) -> String {
        var output = ""
        write(value, into: &output)
        return output
    }

    private static func write(_ value: JSONValue, into output: inout String) {
        switch value {
        case .null: output += "null"
        case let .bool(flag): output += flag ? "true" : "false"
        case let .int(number): output += String(number)
        case let .double(number): output += String(number)  // never produced by the schema encoders
        case let .string(text): writeString(text, into: &output)
        case let .array(items):
            output += "["
            for (offset, item) in items.enumerated() {
                if offset > 0 { output += "," }
                write(item, into: &output)
            }
            output += "]"
        case let .object(fields):
            output += "{"
            // Python sorts keys by code point; compare scalar sequences, not Swift String order.
            let keys = fields.keys.sorted { $0.unicodeScalars.lexicographicallyPrecedes($1.unicodeScalars) }
            for (offset, key) in keys.enumerated() {
                if offset > 0 { output += "," }
                writeString(key, into: &output)
                output += ":"
                write(fields[key]!, into: &output)
            }
            output += "}"
        }
    }

    private static func writeString(_ text: String, into output: inout String) {
        output += "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": output += "\\\""
            case "\\": output += "\\\\"
            case "\n": output += "\\n"
            case "\r": output += "\\r"
            case "\t": output += "\\t"
            case "\u{08}": output += "\\b"
            case "\u{0C}": output += "\\f"
            default:
                if (0x20...0x7E).contains(scalar.value) {
                    output.unicodeScalars.append(scalar)
                } else if scalar.value > 0xFFFF {
                    let offset = scalar.value - 0x10000
                    output += unicodeEscape(0xD800 + (offset >> 10)) + unicodeEscape(0xDC00 + (offset & 0x3FF))
                } else {
                    output += unicodeEscape(scalar.value)
                }
            }
        }
        output += "\""
    }

    private static func unicodeEscape(_ value: UInt32) -> String {
        let hex = String(value, radix: 16)
        return "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
    }
}
