import Darwin
import Foundation

public enum ErrnoName {
    private static let names: [Int32: String] = [
        EPERM: "EPERM", ENOENT: "ENOENT", ESRCH: "ESRCH", EINTR: "EINTR", EIO: "EIO", ENXIO: "ENXIO",
        E2BIG: "E2BIG", ENOEXEC: "ENOEXEC", EBADF: "EBADF", ECHILD: "ECHILD", ENOMEM: "ENOMEM",
        EACCES: "EACCES", EFAULT: "EFAULT", EBUSY: "EBUSY", EEXIST: "EEXIST", EXDEV: "EXDEV",
        ENOTDIR: "ENOTDIR", EISDIR: "EISDIR", EINVAL: "EINVAL", EMFILE: "EMFILE", ETXTBSY: "ETXTBSY",
        EFBIG: "EFBIG", ENOSPC: "ENOSPC", EROFS: "EROFS", EMLINK: "EMLINK", EPIPE: "EPIPE",
        EAGAIN: "EAGAIN", ENOTSOCK: "ENOTSOCK", ENOTSUP: "ENOTSUP", ECONNRESET: "ECONNRESET",
        ECONNREFUSED: "ECONNREFUSED", ETIMEDOUT: "ETIMEDOUT", ELOOP: "ELOOP", ENAMETOOLONG: "ENAMETOOLONG",
        ENOTEMPTY: "ENOTEMPTY", EBADMSG: "EBADMSG", EOPNOTSUPP: "EOPNOTSUPP", ENOATTR: "ENOATTR",
        ERANGE: "ERANGE", ENOTCONN: "ENOTCONN",
    ]

    public static func of(_ code: Int32) -> String { names[code] ?? "errno:\(code)" }
}

/// One probe's outcome. It never carries file contents: only a byte count, an errno name
/// and the step that produced it.
public struct ProbeResult: Codable, Equatable {
    public enum Status: String, Codable {
        /// The operation completed.
        case ok
        /// The operation failed with `errno` at `step`.
        case error
        /// A precondition was missing (no inherited fd, no fd-server); the probe did not run.
        case unavailable
        /// The alias does not exist on this volume (for example a case-sensitive volume).
        case notApplicable = "not_applicable"
        /// The harness itself misbehaved; never a valid measurement.
        case failed
    }

    public var id: String
    public var status: Status
    public var errno: String?
    public var step: String?
    public var bytes: Int?
    public var detail: String?

    public init(id: String, status: Status, errno: String? = nil, step: String? = nil,
                bytes: Int? = nil, detail: String? = nil) {
        self.id = id
        self.status = status
        self.errno = errno
        self.step = step
        self.bytes = bytes
        self.detail = detail
    }

    public var summary: String {
        switch status {
        case .ok: return bytes.map { "ok (\($0) B)" } ?? "ok"
        case .error: return "\(errno ?? "?") at \(step ?? "?")"
        case .unavailable: return "unavailable: \(detail ?? "")"
        case .notApplicable: return "n/a: \(detail ?? "")"
        case .failed: return "harness failure: \(detail ?? "")"
        }
    }
}

public struct RunReport: Codable, Equatable {
    public static let harnessName = "agentbelt-r3-probes"
    public static let formatVersion = 2

    public var harness: String
    public var formatVersion: Int
    public var root: String
    public var inheritedFd: Int32?
    /// pathconf(_PC_CASE_SENSITIVE) on the workspace at run time; decides whether `n/a`
    /// is acceptable for the alias probes.
    public var volumeCaseSensitive: Bool
    public var results: [ProbeResult]

    public init(root: String, inheritedFd: Int32?, volumeCaseSensitive: Bool, results: [ProbeResult]) {
        self.harness = Self.harnessName
        self.formatVersion = Self.formatVersion
        self.root = root
        self.inheritedFd = inheritedFd
        self.volumeCaseSensitive = volumeCaseSensitive
        self.results = results
    }

    public func encoded() throws -> Data { try JSONCoding.encoder.encode(self) }

    public static func decode(_ data: Data) throws -> RunReport {
        let report = try JSONCoding.decoder.decode(RunReport.self, from: data)
        guard report.harness == harnessName, report.formatVersion == formatVersion else {
            throw HarnessError("results are not an \(harnessName) v\(formatVersion) report")
        }
        return report
    }
}

/// Makes a string from a results or records file safe to print: control characters,
/// C1 controls and bidirectional overrides become `\u{..}` escapes, so a crafted file
/// cannot rewrite the terminal or reorder the table.
public func printable(_ text: String) -> String {
    var output = ""
    for scalar in text.unicodeScalars {
        let value = scalar.value
        if value < 0x20 || (0x7f...0x9f).contains(value) || (0x202a...0x202e).contains(value)
            || (0x2066...0x2069).contains(value) || value == 0x200e || value == 0x200f {
            output += "\\u{" + String(value, radix: 16) + "}"
        } else {
            output.unicodeScalars.append(scalar)
        }
    }
    return output
}

enum JSONCoding {
    static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }
}
