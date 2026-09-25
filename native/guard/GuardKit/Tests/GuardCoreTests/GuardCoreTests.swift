// Synthetic checks of the control-plane contract; no XPC, ES, signing identity or network.
import Foundation
import XCTest
@testable import GuardCore

private let supervisor = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
private let approver = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.approver")
private let stranger = try! Signer(teamID: "TEAM999999", signingID: "com.example.tool")

private struct FixedOracle: EnrollmentOracle {
    let enrolled: Set<Int32>
    func isEnrolled(pid: Int32) -> Bool { enrolled.contains(pid) }
}

final class SignerAndRequirementTests: XCTestCase {
    func testRequirementTextPinsTeamAndIdentifier() throws {
        XCTAssertEqual(CodeRequirement.developerSigned(supervisor),
                       "anchor apple generic and certificate leaf[subject.OU] = \"TEAM000001\" "
                       + "and identifier \"dev.agentbelt.supervisor\"")
    }

    func testDeveloperIDRequirementAddsCertificateMarkers() {
        let text = CodeRequirement.developerIDSigned(supervisor)
        XCTAssertTrue(text.hasPrefix(CodeRequirement.developerSigned(supervisor)))
        XCTAssertTrue(text.contains("certificate 1[field.1.2.840.113635.100.6.2.6]"))
        XCTAssertTrue(text.contains("certificate leaf[field.1.2.840.113635.100.6.1.13]"))
    }

    func testSignerRejectsValuesThatCouldAlterRequirementText() {
        let cases: [(String, String)] = [
            ("TEAM00000", "dev.agentbelt.x"), ("team000001", "dev.agentbelt.x"), ("TEAM0000011", "dev.agentbelt.x"),
            ("TEAM000001", ""), ("TEAM000001", "dev\" or anchor apple"), ("TEAM000001", "dev agentbelt"),
            ("TEAM000001", "dev.agentbelt.\u{0}"), ("TEAM000001", String(repeating: "a", count: 256)),
            ("TEAM000001", "-leading"),
        ]
        for (team, identifier) in cases {
            XCTAssertThrowsError(try Signer(teamID: team, signingID: identifier), "\(team) \(identifier.debugDescription)")
        }
    }

    func testTrustPolicySeparatesDuties() {
        XCTAssertThrowsError(try TrustPolicy(supervisors: [supervisor], approvers: [supervisor]))
        XCTAssertThrowsError(try TrustPolicy(supervisors: [], approvers: [approver]))
        XCTAssertThrowsError(try TrustPolicy(supervisors: [supervisor], approvers: []))
        XCTAssertNoThrow(try TrustPolicy(supervisors: [supervisor], approvers: [approver]))
    }

    func testCombinedRequirementAcceptsOnlyConfiguredSigners() throws {
        let policy = try TrustPolicy(supervisors: [supervisor], approvers: [approver])
        let combined = policy.combinedRequirement(CodeRequirement.developerSigned)
        XCTAssertTrue(combined.contains("\"dev.agentbelt.supervisor\""))
        XCTAssertTrue(combined.contains("\"dev.agentbelt.approver\""))
        XCTAssertFalse(combined.contains("com.example.tool"))
        XCTAssertTrue(combined.hasPrefix("(") && combined.contains(") or ("))
    }
}

final class ControlRequestTests: XCTestCase {
    private let child = try! ProcessIdentity(pid: 4242, pidVersion: 17)
    private let image = try! ExecutableImage(path: "/opt/agents/agent", digest: "cdhash-0123")

    private var samples: [ControlRequest] {
        [.propose(contract: Data("{}".utf8), parentTaskID: nil),
         .propose(contract: Data("{}".utf8), parentTaskID: "task-a"),
         .confirm(digest: String(repeating: "a", count: 64)),
         .rejectProposal(digest: String(repeating: "0", count: 64)),
         .revoke(taskID: "task-a"),
         .registerLaunch(taskID: "task-a", image: image, child: child),
         .ticketStatus(child: child),
         .pendingProposals, .pendingRequests,
         .approveRequest(requestID: "req-1", expiresAtNs: 500),
         .rejectRequest(requestID: "req-1")]
    }

    func testEveryOperationRoundTripsThroughFields() throws {
        XCTAssertEqual(Set(samples.map(\.operation)), Set(ControlOperation.allCases))
        for request in samples {
            XCTAssertEqual(try ControlRequest.parse(request.fields()), request)
        }
    }

    func testRejectsUnknownMissingExtraAndMistypedFields() throws {
        let valid = ControlRequest.revoke(taskID: "task-a").fields()
        var cases: [[String: FieldValue]] = []
        var unknownOp = valid; unknownOp["op"] = .string("widen"); cases.append(unknownOp)
        var badVersion = valid; badVersion["v"] = .int64(2); cases.append(badVersion)
        var missing = valid; missing["task"] = nil; cases.append(missing)
        var extra = valid; extra["task_granted_by_model"] = .string("yes"); cases.append(extra)
        var mistyped = valid; mistyped["task"] = .int64(1); cases.append(mistyped)
        var stringVersion = valid; stringVersion["v"] = .string("1"); cases.append(stringVersion)
        for fields in cases {
            XCTAssertThrowsError(try ControlRequest.parse(fields), "\(fields)")
        }
    }

    func testFieldValuesAreValidatedLikeThePythonModel() {
        let digestCases = [String(repeating: "A", count: 64), String(repeating: "a", count: 63), "../" + String(repeating: "a", count: 61)]
        for digest in digestCases {
            XCTAssertThrowsError(try ControlRequest.parse(ControlRequest.confirm(digest: digest).fields()))
        }
        for task in ["", "../task", "-task", String(repeating: "a", count: 129), "task a"] {
            XCTAssertThrowsError(try ControlRequest.parse(ControlRequest.revoke(taskID: task).fields()))
        }
        XCTAssertThrowsError(try ControlRequest.parse(
            ControlRequest.approveRequest(requestID: "req-1", expiresAtNs: -1).fields()))
        XCTAssertThrowsError(try ControlRequest.parse(
            ControlRequest.propose(contract: Data(), parentTaskID: nil).fields()))
        XCTAssertThrowsError(try ControlRequest.parse(
            ControlRequest.propose(contract: Data(count: ControlLimits.maxContractBytes + 1), parentTaskID: nil).fields()))
    }

    func testProcessIdentityAndImageValidation() {
        XCTAssertThrowsError(try ProcessIdentity(pid: 0, pidVersion: 1))
        XCTAssertThrowsError(try ProcessIdentity(pid: -5, pidVersion: 1))
        XCTAssertNoThrow(try ProcessIdentity(pid: 5, pidVersion: -1))  // wrapped pidversion stays usable
        for path in ["relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb", "/" + String(repeating: "a", count: 4096),
                     "/a/../\u{301}b", "/a//\u{301}b", "/a\u{600}/../b"] {
            XCTAssertThrowsError(try ExecutableImage(path: path, digest: "d"), path.debugDescription)
        }
        var fields = ControlRequest.ticketStatus(child: child).fields()
        fields["child_pid"] = .int64(Int64(Int32.max) + 1)
        XCTAssertThrowsError(try ControlRequest.parse(fields))
    }

    func testErrorsDoNotEchoInputs() {
        let marker = "SYNTHETIC-PRIVATE-MARKER"
        var fields = ControlRequest.revoke(taskID: "task-a").fields()
        fields["task"] = .string(marker + " x")
        do {
            _ = try ControlRequest.parse(fields)
            XCTFail("accepted invalid task")
        } catch {
            XCTAssertFalse(String(describing: error).contains(marker))
        }
    }
}

final class PeerGateTests: XCTestCase {
    private func gate(enrolled: Set<Int32> = []) throws -> PeerGate {
        PeerGate(policy: try TrustPolicy(supervisors: [supervisor], approvers: [approver]),
                 oracle: FixedOracle(enrolled: enrolled))
    }

    func testRolesReachOnlyTheirOperations() throws {
        let gate = try gate()
        let supervisorPeer = PeerCredential(pid: 500, signer: supervisor)
        let approverPeer = PeerCredential(pid: 600, signer: approver)
        for operation in ControlOperation.allCases {
            let expectSupervisor = [.propose, .registerLaunch, .ticketStatus, .revoke].contains(operation)
            let expectApprover = [.confirm, .rejectProposal, .pendingProposals, .pendingRequests,
                                  .approveRequest, .rejectRequest, .revoke].contains(operation)
            XCTAssertEqual(gate.authorize(supervisorPeer, operation) == .allow(.supervisor), expectSupervisor, "\(operation)")
            XCTAssertEqual(gate.authorize(approverPeer, operation) == .allow(.approver), expectApprover, "\(operation)")
        }
    }

    func testUnknownSignerAndEnrolledPeersAreDenied() throws {
        XCTAssertEqual(try gate().authorize(PeerCredential(pid: 700, signer: stranger), .revoke), .deny("unknown_signer"))
        // An agent that executes the signed supervisor binary is still enrolled by lineage.
        let enrolled = try gate(enrolled: [800])
        XCTAssertEqual(enrolled.authorize(PeerCredential(pid: 800, signer: supervisor), .propose), .deny("enrolled_peer"))
        XCTAssertEqual(enrolled.authorize(PeerCredential(pid: 800, signer: approver), .confirm), .deny("enrolled_peer"))
        XCTAssertEqual(try gate().authorize(PeerCredential(pid: 0, signer: supervisor), .propose), .deny("invalid_peer"))
    }
}

final class ConfigurationTests: XCTestCase {
    private let guardInfo: [String: Any] = [
        "AGBTeamIdentifier": "TEAM000001",
        "AGBSupervisorSigningIdentifier": "dev.agentbelt.supervisor",
        "AGBApproverSigningIdentifier": "dev.agentbelt",
        "NSEndpointSecurityMachServiceName": "TEAM000001.dev.agentbelt.fileguard.control",
    ]
    private let clientInfo: [String: Any] = [
        "AGBTeamIdentifier": "TEAM000001",
        "AGBFileGuardSigningIdentifier": "dev.agentbelt.fileguard",
        "AGBMachServiceName": "TEAM000001.dev.agentbelt.fileguard.control",
    ]

    func testConfiguredValuesParse() throws {
        let guardConfiguration = try GuardConfiguration.parse(signedInfo: guardInfo)
        XCTAssertEqual(guardConfiguration.machServiceName, "TEAM000001.dev.agentbelt.fileguard.control")
        XCTAssertEqual(guardConfiguration.policy.role(of: supervisor), .supervisor)
        XCTAssertEqual(try ClientConfiguration.parse(signedInfo: clientInfo).fileGuard.signingID, "dev.agentbelt.fileguard")
    }

    func testPlaceholdersMissingValuesAndUnprefixedServicesFailClosed() {
        let mutations: [(String, Any?)] = [
            ("AGBTeamIdentifier", ""), ("AGBTeamIdentifier", nil), ("AGBTeamIdentifier", 7),
            ("AGBSupervisorSigningIdentifier", "invalid.agentbelt.unconfigured.supervisor"),
            ("AGBApproverSigningIdentifier", "invalid.agentbelt.unconfigured"),
            ("NSEndpointSecurityMachServiceName", ".invalid.agentbelt.unconfigured.fileguard.control"),
            ("NSEndpointSecurityMachServiceName", "OTHERTEAM1.dev.agentbelt.fileguard.control"),
            ("NSEndpointSecurityMachServiceName", "TEAM000001."),
            ("NSEndpointSecurityMachServiceName", "TEAM000001.invalid.agentbelt.unconfigured.fileguard.control"),
        ]
        for (key, value) in mutations {
            var info = guardInfo
            info[key] = value
            XCTAssertThrowsError(try GuardConfiguration.parse(signedInfo: info), "\(key)")
        }
        var client = clientInfo
        client["AGBMachServiceName"] = "com.attacker.fileguard"
        XCTAssertThrowsError(try ClientConfiguration.parse(signedInfo: client))
        // Same signer in both roles must be refused, as TrustPolicy requires.
        var overlap = guardInfo
        overlap["AGBApproverSigningIdentifier"] = "dev.agentbelt.supervisor"
        XCTAssertThrowsError(try GuardConfiguration.parse(signedInfo: overlap))
    }
}
