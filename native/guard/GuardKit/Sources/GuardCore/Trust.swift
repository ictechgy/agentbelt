import Foundation

/// Code-signing identity (Team ID + signing identifier) that the transport verified for a peer.
public struct Signer: Hashable, Sendable, CustomStringConvertible {
    public let teamID: String
    public let signingID: String

    /// Both parts are restricted so they can be embedded in requirement text without quoting issues.
    public init(teamID: String, signingID: String) throws {
        let team = teamID.utf8
        guard team.count == 10, team.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }) else {
            throw GuardError("invalid team identifier")
        }
        let scalars = Array(signingID.unicodeScalars)
        guard (1...255).contains(scalars.count), let first = scalars.first, Validate.isAlphanumeric(first),
              scalars.allSatisfy({ Validate.isAlphanumeric($0) || $0 == "." || $0 == "-" }) else {
            throw GuardError("invalid signing identifier")
        }
        self.teamID = teamID
        self.signingID = signingID
    }

    public var description: String { "\(teamID):\(signingID)" }
}

public enum CodeRequirement {
    /// Apple-anchored certificate from our team plus the exact signing identifier (TN3127 form).
    /// It holds for Apple Development and Developer ID certificates of that team, so it is
    /// the development-phase requirement; peers must also pass the hardening check.
    public static func developerSigned(_ signer: Signer) -> String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(signer.teamID)\" "
            + "and identifier \"\(signer.signingID)\""
    }

    /// Distribution requirement: additionally pins the Developer ID intermediate and leaf
    /// markers, excluding Apple Development certificates (and their debuggable builds).
    public static func developerIDSigned(_ signer: Signer) -> String {
        developerSigned(signer)
            + " and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]"
    }
}

public enum Role: String, Sendable {
    case supervisor
    case approver
}

/// Operator-installed trust roots. Supervisors propose and launch; only approvers widen authority.
public struct TrustPolicy: Sendable {
    public let supervisors: Set<Signer>
    public let approvers: Set<Signer>

    public init(supervisors: Set<Signer>, approvers: Set<Signer>) throws {
        guard !supervisors.isEmpty, !approvers.isEmpty else { throw GuardError("empty signer set") }
        // Separation of duties: one binary must not both propose and approve.
        guard supervisors.isDisjoint(with: approvers) else { throw GuardError("signer holds both roles") }
        self.supervisors = supervisors
        self.approvers = approvers
    }

    public var allSigners: [Signer] {
        (supervisors.union(approvers)).sorted { $0.description < $1.description }
    }

    public func role(of signer: Signer) -> Role? {
        if supervisors.contains(signer) { return .supervisor }
        if approvers.contains(signer) { return .approver }
        return nil
    }

    /// One requirement for the listener: a peer must satisfy at least one configured signer.
    public func combinedRequirement(_ requirement: (Signer) -> String) -> String {
        allSigners.map { "(\(requirement($0)))" }.joined(separator: " or ")
    }
}
