// swift-tools-version:5.9
// GuardKit: host-side building blocks for the agentbelt Endpoint Security engine (R2 skeleton).
// Nothing here enforces anything; see ../README.md for what is and is not verified.
import PackageDescription

let package = Package(
    name: "GuardKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GuardCore", targets: ["GuardCore"]),
        .library(name: "GuardTransport", targets: ["GuardTransport"]),
        .library(name: "SpawnGate", targets: ["SpawnGate"]),
        .library(name: "GuardRegistry", targets: ["GuardRegistry"]),
        .library(name: "GuardES", targets: ["GuardES"]),
        .library(name: "GuardService", targets: ["GuardService"]),
    ],
    targets: [
        .target(name: "GuardCore"),
        .target(name: "SpawnGate", linkerSettings: [.linkedLibrary("bsm")]),
        .target(name: "GuardTransport", dependencies: ["GuardCore"]),
        // Swift port of task_policy.py and task_registry.py, checked against them differentially.
        .target(name: "GuardRegistry", dependencies: ["GuardCore"]),
        // ES message mapping; links libEndpointSecurity but never creates a client.
        .target(name: "GuardES", dependencies: ["GuardCore", "GuardRegistry", "SpawnGate"],
                linkerSettings: [.linkedLibrary("EndpointSecurity")]),
        .target(name: "GuardService", dependencies: ["GuardCore", "GuardRegistry", "GuardTransport"]),
        .executableTarget(name: "guard-bench", dependencies: ["GuardCore", "GuardRegistry", "GuardES", "GuardService"]),
        .testTarget(name: "GuardCoreTests", dependencies: ["GuardCore"]),
        .testTarget(name: "GuardTransportTests", dependencies: ["GuardCore", "GuardTransport"]),
        .testTarget(name: "SpawnGateTests", dependencies: ["SpawnGate"]),
        .testTarget(name: "GuardRegistryTests", dependencies: ["GuardCore", "GuardRegistry"],
                    exclude: ["generate_vectors.py"]),
        .testTarget(name: "GuardESTests", dependencies: ["GuardCore", "GuardRegistry", "GuardES"]),
        .testTarget(name: "GuardServiceTests", dependencies: ["GuardCore", "GuardRegistry", "GuardTransport", "GuardService"]),
    ]
)
