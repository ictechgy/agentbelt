import Darwin
import Foundation

public struct HarnessError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Every side effect of the harness happens under one fixture root. The root must be a
/// fresh directory in a temporary area, so a mistyped or hostile `--root` can never make
/// the probes rename, truncate or unlink real user files.
public enum RootSafety {
    /// Prefixes of resolved roots. `/tmp` and `/var` are symlinks into `/private` on
    /// macOS, so `setup` applies the check to the `realpath` result and later commands
    /// require the canonical spelling.
    public static let allowedPrefixes = ["/private/tmp/", "/private/var/folders/", "/tmp/"]

    /// `<root>/projectA/ipc/fd.sock` plus its NUL must fit in `sockaddr_un.sun_path` (104 bytes).
    static let maximumRootLength = 103 - 1 - FixturePath.socket.utf8.count

    public static func isAllowed(resolved path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("/../"), !path.hasSuffix("/..") else { return false }
        return allowedPrefixes.contains { path.hasPrefix($0) && path.count > $0.count }
    }

    /// Creates the root for `setup`, or accepts an existing empty directory.
    public static func prepareNewRoot(_ spelling: String) throws -> String {
        guard spelling.hasPrefix("/") else { throw HarnessError("root must be an absolute path") }
        let url = URL(fileURLWithPath: spelling)
        let name = url.lastPathComponent
        guard !name.isEmpty, name != ".", name != "..", name != "/" else {
            throw HarnessError("root must name a new directory")
        }
        let parent = try resolve(url.deletingLastPathComponent().path)
        let candidate = parent + "/" + name
        try requireAllowed(candidate)
        var info = stat()
        if lstat(candidate, &info) == 0 {
            try requireOwnedDirectory(candidate, info)
            guard info.st_mode & 0o022 == 0 else { throw HarnessError("root is writable by group or others") }
            let entries = try FileManager.default.contentsOfDirectory(atPath: candidate)
            guard entries.isEmpty else { throw HarnessError("root exists and is not empty; use a new directory") }
        } else {
            guard errno == ENOENT else { throw HarnessError("cannot inspect root: \(ErrnoName.of(errno))") }
            guard mkdir(candidate, 0o700) == 0 else { throw HarnessError("cannot create root: \(ErrnoName.of(errno))") }
        }
        return try resolve(candidate)
    }

    /// A fresh root from mkdtemp under $TMPDIR, used when `setup` gets no `--root`.
    public static func makeTemporaryRoot() throws -> String {
        var template = Array((NSTemporaryDirectory() + "r3-probes.XXXXXX").utf8CString)
        guard template.withUnsafeMutableBufferPointer({ mkdtemp($0.baseAddress!) }) != nil else {
            throw HarnessError("mkdtemp failed: \(ErrnoName.of(errno))")
        }
        let root = try resolve(String(cString: template))
        try requireAllowed(root)
        return root
    }

    /// Validates the root of an existing fixture for `run`, `fd-server`, `sub-probe`,
    /// `verify` and `contract`. No realpath: it stats (getattrlist) every ancestor, which
    /// a confined run may not do. The root must be spelled canonically, as `setup` prints it.
    public static func existingRoot(_ spelling: String) throws -> String {
        let root = try canonicalDirectory(spelling)
        try requireAllowed(root)
        var info = stat()
        guard lstat(root, &info) == 0 else { throw HarnessError("cannot inspect root: \(ErrnoName.of(errno))") }
        try requireOwnedDirectory(root, info)
        guard info.st_mode & 0o022 == 0 else { throw HarnessError("root is writable by group or others") }
        return root
    }

    /// Output files (results JSON) obey the same rule: their directory must be temporary
    /// and spelled canonically.
    public static func outputFile(_ spelling: String) throws -> String {
        guard spelling.hasPrefix("/") else { throw HarnessError("output path must be absolute") }
        // Split the original bytes at the last "/": URL would renormalize the name (NFD),
        // and mixing byte and Character counts would cut the path in the wrong place.
        let bytes = Array(spelling.utf8)
        let slash = bytes.lastIndex(of: UInt8(ascii: "/"))!
        let name = String(decoding: bytes[(slash + 1)...], as: UTF8.self)
        guard !name.isEmpty, name != ".", name != ".." else { throw HarnessError("output path must name a file") }
        let parent = slash == 0 ? "/" : String(decoding: bytes[..<slash], as: UTF8.self)
        let path = try canonicalDirectory(parent) + "/" + name
        guard isAllowed(resolved: path) else {
            throw HarnessError("refusing output outside \(allowedPrefixes.joined(separator: ", ")): \(path)")
        }
        return path
    }

    /// Checks, with one lstat per component, that `spelling` is absolute, has no empty,
    /// `.` or `..` component, and that every component is a real directory (no symlink).
    /// lstat raises no Endpoint Security AUTH event, unlike realpath's getattrlist calls.
    static func canonicalDirectory(_ spelling: String) throws -> String {
        guard spelling.hasPrefix("/"), spelling.count > 1 else { throw HarnessError("path must be absolute") }
        let components = spelling.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw HarnessError("path must be canonical (no empty, '.' or '..' components)")
        }
        var current = ""
        for component in components {
            current += "/" + component
            var info = stat()
            guard lstat(current, &info) == 0 else {
                throw HarnessError("cannot inspect \(current): \(ErrnoName.of(errno))")
            }
            guard info.st_mode & S_IFMT == S_IFDIR else {
                throw HarnessError("\(current) is not a directory (a symlink?); spell the root as setup prints it")
            }
        }
        return spelling
    }

    static func resolve(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else {
            throw HarnessError("cannot resolve path: \(ErrnoName.of(errno))")
        }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func requireAllowed(_ path: String) throws {
        guard isAllowed(resolved: path) else {
            throw HarnessError("refusing root outside \(allowedPrefixes.joined(separator: ", ")): \(path)")
        }
        guard path.utf8.count <= maximumRootLength else {
            throw HarnessError("root path longer than \(maximumRootLength) bytes; the fd-server socket would not fit")
        }
    }

    private static func requireOwnedDirectory(_ path: String, _ info: stat) throws {
        guard info.st_mode & S_IFMT == S_IFDIR else { throw HarnessError("root is not a directory (or is a symlink)") }
        guard info.st_uid == getuid() else { throw HarnessError("root is not owned by the current user") }
    }
}
