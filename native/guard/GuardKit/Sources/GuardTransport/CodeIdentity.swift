import Foundation
import GuardCore
import Security
import XPC

/// Code-signing lookups used by the transport and the supervisor.
public enum CodeIdentity {
    /// cdhash (hex) of an executable on disk: the ExecutableImage digest for launch tickets.
    public static func cdhash(ofExecutableAt path: String) throws -> String {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { throw GuardError("code object unavailable") }
        return try cdhash(of: staticCode)
    }

    /// cdhash of the running process; used by tests to build a requirement it satisfies.
    public static func cdhashOfSelf() throws -> String {
        var code: SecCode?
        var staticCode: SecStaticCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw GuardError("self code unavailable")
        }
        return try cdhash(of: staticCode)
    }

    private static func cdhash(of staticCode: SecStaticCode) throws -> String {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, [], &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let unique = dictionary[kSecCodeInfoUnique as String] as? Data else {
            throw GuardError("code has no cdhash")
        }
        return unique.map { String(format: "%02x", $0) }.joined()
    }

    /// The Info.plist sealed into this process's own code signature, or nil when the
    /// code is unsigned or binds no Info.plist. Unlike `Bundle.main`, it cannot be
    /// redirected through `CFProcessPath`.
    public static func signedInfoOfSelf() -> [String: Any]? {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, [], &information) == errSecSuccess,
              let dictionary = information as? [String: Any] else { return nil }
        return dictionary[kSecCodeInfoPList as String] as? [String: Any]
    }

    public enum HardeningViolation: String, Equatable, Sendable {
        case unavailable = "signing_information_unavailable"
        case noHardenedRuntime = "no_hardened_runtime"
        case debuggable = "get_task_allow"
        case beingDebugged = "debugged"
    }

    /// Kernel code-signing status bits of the running process (xnu <kern/cs_blobs.h>;
    /// not named in the public SDK). The dynamic status follows the live process, while
    /// static information follows the file on disk, which could be replaced after launch.
    private static let csGetTaskAllow: UInt32 = 0x0000_0004
    private static let csRuntime: UInt32 = 0x0001_0000

    /// A trusted peer must not be open to code injection by another same-user process:
    /// hardened runtime, no get-task-allow, not currently debugged. get-task-allow is
    /// refused if either the live kernel status or the on-disk entitlements carry it.
    public static func hardeningViolation(of code: SecCode) -> HardeningViolation? {
        var staticCode: SecStaticCode?
        var staticInformation: CFDictionary?
        var dynamicInformation: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &staticInformation) == errSecSuccess,
              let staticDictionary = staticInformation as? [String: Any],
              // A SecCode is a SecStaticCode subtype in CoreFoundation; dynamic status needs the live one.
              SecCodeCopySigningInformation(unsafeBitCast(code, to: SecStaticCode.self),
                                            SecCSFlags(rawValue: kSecCSDynamicInformation),
                                            &dynamicInformation) == errSecSuccess,
              let dynamicDictionary = dynamicInformation as? [String: Any] else { return .unavailable }
        guard let status = (dynamicDictionary[kSecCodeInfoStatus as String] as? NSNumber)?.uint32Value else {
            return .unavailable
        }
        // Runtime hardening is judged from the kernel status only: platform binaries have
        // no runtime flag in their code directory (measured: 0x0) yet run hardened.
        guard status & csRuntime != 0 else { return .noHardenedRuntime }
        let entitlements = staticDictionary[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        if status & csGetTaskAllow != 0 || entitlements["com.apple.security.get-task-allow"] as? Bool == true {
            return .debuggable
        }
        if status & SecCodeStatus.debugged.rawValue != 0 { return .beingDebugged }
        return nil
    }

    static func hardeningViolation(ofPid pid: pid_t) -> HardeningViolation? {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
            return .unavailable
        }
        return hardeningViolation(of: code)
    }

    static func hardeningViolationOfSelf() -> HardeningViolation? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return .unavailable }
        return hardeningViolation(of: code)
    }

    /// Which configured signer sent this message, judged from the message's audit token.
    ///
    /// The listener already dropped peers that satisfy none of the signers; this picks
    /// the one that matches so the gate can derive the role.
    static func sender(of message: xpc_object_t) -> SecCode? {
        var code: SecCode?
        guard SecCodeCreateWithXPCMessage(message, [], &code) == errSecSuccess else { return nil }
        return code
    }

    static func signer(of code: SecCode, candidates: [Signer], requirement: (Signer) -> String) -> Signer? {
        candidates.first { signer in
            var compiled: SecRequirement?
            guard SecRequirementCreateWithString(requirement(signer) as CFString, [], &compiled) == errSecSuccess,
                  let compiled else { return false }
            return SecCodeCheckValidity(code, [], compiled) == errSecSuccess
        }
    }
}
