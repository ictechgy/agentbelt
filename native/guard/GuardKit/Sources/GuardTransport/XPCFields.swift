import Foundation
import GuardCore
import XPC

/// Conversion between XPC dictionaries and GuardCore fields. Only string, int64 and
/// data values exist in the protocol; any other XPC type makes the message invalid.
enum XPCFields {
    static let maxFields = 16
    /// Replies may carry several contracts (pending proposals), so they get a larger cap.
    static let maxReplyDataBytes = 1 << 20

    static func decode(_ dictionary: xpc_object_t, maxDataBytes: Int = ControlLimits.maxContractBytes)
        -> [String: FieldValue]? {
        guard xpc_get_type(dictionary) == XPC_TYPE_DICTIONARY, xpc_dictionary_get_count(dictionary) <= maxFields else {
            return nil
        }
        var fields: [String: FieldValue] = [:]
        var valid = true
        xpc_dictionary_apply(dictionary) { key, value in
            guard let name = String(validatingUTF8: key), let decoded = decodeValue(value, maxDataBytes) else {
                valid = false
                return false
            }
            fields[name] = decoded
            return true
        }
        return valid ? fields : nil
    }

    private static func decodeValue(_ value: xpc_object_t, _ maxDataBytes: Int) -> FieldValue? {
        let type = xpc_get_type(value)
        if type == XPC_TYPE_INT64 { return .int64(xpc_int64_get_value(value)) }
        if type == XPC_TYPE_STRING {
            guard let pointer = xpc_string_get_string_ptr(value) else { return nil }
            let length = xpc_string_get_length(value)
            let bytes = UnsafeRawBufferPointer(start: pointer, count: length)
            // Reject invalid UTF-8 rather than repairing it: a lossless round trip only.
            // (Foundation's String(bytes:encoding:) would silently drop a leading BOM.)
            let string = String(decoding: bytes, as: UTF8.self)
            guard string.utf8.elementsEqual(bytes) else { return nil }
            return .string(string)
        }
        if type == XPC_TYPE_DATA {
            let length = xpc_data_get_length(value)
            guard length <= maxDataBytes else { return nil }
            guard length > 0, let pointer = xpc_data_get_bytes_ptr(value) else { return .data(Data()) }
            return .data(Data(bytes: pointer, count: length))
        }
        return nil
    }

    static func encode(_ fields: [String: FieldValue]) -> xpc_object_t {
        let dictionary = xpc_dictionary_create(nil, nil, 0)
        for (key, value) in fields.sorted(by: { $0.key < $1.key }) {
            switch value {
            case let .string(string): xpc_dictionary_set_string(dictionary, key, string)
            case let .int64(number): xpc_dictionary_set_int64(dictionary, key, number)
            case let .data(data):
                data.withUnsafeBytes { buffer in
                    xpc_dictionary_set_data(dictionary, key, buffer.baseAddress ?? UnsafeRawPointer(bitPattern: 1)!, buffer.count)
                }
            }
        }
        return dictionary
    }
}
