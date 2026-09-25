// swift-tools-version:5.9
// R3Probes: boundary probes for the R3 acceptance tests. The probes only measure what
// happens; they enforce nothing. See README.md.
import PackageDescription

let package = Package(
    name: "R3Probes",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "r3-probes", targets: ["R3ProbesCLI"]),
    ],
    targets: [
        .target(name: "ProbeSys"),
        .target(name: "R3ProbesKit", dependencies: ["ProbeSys"]),
        .executableTarget(name: "R3ProbesCLI", dependencies: ["R3ProbesKit"]),
        // Depends on the executable so `swift test` builds the r3-probes binary that the
        // baseline test launches as a separate process.
        .testTarget(name: "R3ProbesKitTests", dependencies: ["R3ProbesKit", "R3ProbesCLI"]),
    ]
)
