import Foundation

/// Reads trust roots from an Info dictionary that the caller obtained from its own code
/// signature, never from `Bundle.main`: CoreFoundation lets `CFProcessPath` in the
/// environment redirect the main bundle to an arbitrary plist.
enum InfoValues {
    static func value(_ info: [String: Any], _ key: String) throws -> String {
        guard let text = info[key] as? String, !text.isEmpty, !text.hasPrefix("invalid."),
              !text.contains(".invalid.") else { throw GuardError("not configured") }
        return text
    }

    /// System-extension Mach services must carry the team prefix.
    static func machService(_ info: [String: Any], _ key: String, team: String) throws -> String {
        let service = try value(info, key)
        guard service.hasPrefix(team + "."), service.count > team.count + 1 else {
            throw GuardError("mach service lacks team prefix")
        }
        return service
    }
}

/// File Guard's view: which signers may call it, and the service it serves.
public struct GuardConfiguration: Sendable {
    public let machServiceName: String
    public let policy: TrustPolicy

    public static func parse(signedInfo info: [String: Any]) throws -> GuardConfiguration {
        let team = try InfoValues.value(info, "AGBTeamIdentifier")
        let supervisor = try Signer(teamID: team, signingID: try InfoValues.value(info, "AGBSupervisorSigningIdentifier"))
        let approver = try Signer(teamID: team, signingID: try InfoValues.value(info, "AGBApproverSigningIdentifier"))
        return GuardConfiguration(
            machServiceName: try InfoValues.machService(info, "NSEndpointSecurityMachServiceName", team: team),
            policy: try TrustPolicy(supervisors: [supervisor], approvers: [approver]))
    }
}

/// A client's view: where File Guard listens and which signer it must be.
public struct ClientConfiguration: Sendable {
    public let machServiceName: String
    public let fileGuard: Signer

    public static func parse(signedInfo info: [String: Any]) throws -> ClientConfiguration {
        let team = try InfoValues.value(info, "AGBTeamIdentifier")
        return ClientConfiguration(
            machServiceName: try InfoValues.machService(info, "AGBMachServiceName", team: team),
            fileGuard: try Signer(teamID: team, signingID: try InfoValues.value(info, "AGBFileGuardSigningIdentifier")))
    }
}
