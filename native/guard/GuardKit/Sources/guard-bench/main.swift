// Decision-latency benchmark for the Swift registry and ES mapping (R3 deadline budget).
// Synthetic registry and messages only; no ES client, no file access.
// Run: swift run -c release guard-bench
import Darwin
import EndpointSecurity
import Foundation
import GuardCore
import GuardES
import GuardRegistry
import GuardService

let supervisorSigner = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.supervisor")
let approverSigner = try! Signer(teamID: "TEAM000001", signingID: "dev.agentbelt.approver")
func identity(_ pid: Int32, _ version: Int32) -> ProcessIdentity { try! ProcessIdentity(pid: pid, pidVersion: version) }

/// A registry with one launched agent whose contract has `rules` allow rules.
func makeRegistry(rules: Int) -> (Registry, ProcessIdentity) {
    let registry = try! Registry(config: try! RegistryConfig(supervisors: [supervisorSigner], approvers: [approverSigner]),
                                 bootID: "bench", nowNs: 1)
    var allow = [try! PathRule(path: "/w/a", scope: .tree, operations: [.read])]
    for index in 1..<rules { allow.append(try! PathRule(path: "/w/a/d\(index)", scope: .tree, operations: [.write])) }
    let contract = try! TaskContract(taskID: "ta", revision: 1, workspace: "/w/a", validFromNs: 0,
                                     expiresAtNs: Int64.max, allow: allow,
                                     deny: [try! PathRule(path: "/w/a/private", scope: .tree, operations: [.read, .write])])
    let supervisor = Peer(process: identity(500, 1), signer: supervisorSigner)
    let digest = try! registry.propose(supervisor, contract: contract, nowNs: 2)
    try! registry.confirm(Peer(process: identity(600, 1), signer: approverSigner), digest: digest, nowNs: 3)
    registry.onFork(parent: supervisor.process, child: identity(3000, 1), nowNs: 4)
    let image = try! ExecutableImage(path: "/opt/agent", digest: "cd")
    try! registry.registerLaunch(supervisor, taskID: "ta", image: image, child: identity(3000, 1), nowNs: 5)
    _ = registry.onExec(process: identity(3000, 1), parent: supervisor.process, target: identity(3000, 2),
                        image: image, nowNs: 6)
    return (registry, identity(3000, 2))
}

/// Nanosecond percentiles of `body` over `iterations` calls, measured per call.
func measure(_ name: String, iterations: Int = 200_000, _ body: (Int) -> Void) -> [String: Any] {
    var samples = [UInt64](repeating: 0, count: iterations)
    var timebase = mach_timebase_info_data_t()
    mach_timebase_info(&timebase)
    for index in 0..<iterations {
        let start = mach_absolute_time()
        body(index)
        samples[index] = (mach_absolute_time() - start) * UInt64(timebase.numer) / UInt64(timebase.denom)
    }
    samples.sort()
    func percentile(_ p: Double) -> UInt64 { samples[min(samples.count - 1, Int(Double(samples.count) * p))] }
    return ["case": name, "iterations": iterations, "p50_ns": percentile(0.50), "p95_ns": percentile(0.95),
            "p99_ns": percentile(0.99), "p999_ns": percentile(0.999), "max_ns": samples.last!]
}

var results: [[String: Any]] = []
let (small, agent) = makeRegistry(rules: 4)
let unrelated = identity(9000, 1)
var clock: Int64 = 10
func tick() -> Int64 { clock += 1; return clock }

results.append(measure("not_enrolled file (unrelated process)") { _ in
    _ = small.authorizeFile(process: unrelated, parent: identity(1, 1), path: "/usr/lib/libSystem.B.dylib",
                            operations: ["read"], nowNs: tick())
})
results.append(measure("enrolled file allowed (4 rules)") { _ in
    _ = small.authorizeFile(process: agent, parent: nil, path: "/w/a/src/main.swift", operations: ["read"], nowNs: tick())
})
results.append(measure("enrolled file denied outside (4 rules)") { _ in
    _ = small.authorizeFile(process: agent, parent: nil, path: "/Users/someone/notes.txt", operations: ["read"],
                            nowNs: tick())
})
let (large, largeAgent) = makeRegistry(rules: 128)
results.append(measure("enrolled file allowed (128 rules, last match)") { _ in
    _ = large.authorizeFile(process: largeAgent, parent: nil, path: "/w/a/d127/file", operations: ["write"],
                            nowNs: tick())
})
results.append(measure("enrolled fork + exec outside contract + exit", iterations: 50_000) { index in
    // A realistic child: the agent forks, the child execs a runtime (same PID), then exits.
    let child = identity(4000 + Int32(index % 1000), Int32(index))
    small.onFork(parent: agent, child: child, nowNs: tick())
    _ = small.onExec(process: child, parent: agent, target: identity(child.pid, child.pidVersion + 1),
                     image: try? ExecutableImage(path: "/bin/sh", digest: "cd"), nowNs: tick())
    small.onExit(process: identity(child.pid, child.pidVersion + 1), nowNs: tick())
})

// ES mapping on a synthetic AUTH_OPEN message.
let message = UnsafeMutablePointer<es_message_t>.allocate(capacity: 2)
let process = UnsafeMutablePointer<es_process_t>.allocate(capacity: 1)
let file = UnsafeMutablePointer<es_file_t>.allocate(capacity: 1)
for (pointer, size) in [(UnsafeMutableRawPointer(message), MemoryLayout<es_message_t>.size * 2),
                        (UnsafeMutableRawPointer(process), MemoryLayout<es_process_t>.size),
                        (UnsafeMutableRawPointer(file), MemoryLayout<es_file_t>.size)] {
    pointer.initializeMemory(as: UInt8.self, repeating: 0, count: size)
}
let path = strdup("/w/a/src/main.swift")!
file.pointee.path = es_string_token_t(length: strlen(path), data: path)
process.pointee.audit_token.val.5 = UInt32(agent.pid)
process.pointee.audit_token.val.7 = UInt32(agent.pidVersion)
process.pointee.executable = file
message.pointee.version = 8
message.pointee.event_type = ES_EVENT_TYPE_AUTH_OPEN
message.pointee.process = process
message.pointee.event.open.fflag = 1
message.pointee.event.open.file = file
let probe = AuthDecider.decide(ESMapper.map(message), registry: small, nowNs: tick())
// Release builds trap silently on precondition; fail loudly so a wrong setup is never timed.
if probe.outcomes.map(\.reason) != ["allowed"] {
    FileHandle.standardError.write(Data("guard-bench: synthetic message was not enrolled: \(probe.outcomes)\n".utf8))
    exit(1)
}
// Production path: File Guard decides through ClockedRegistry (lock + clock read included).
let clockedSmall = ClockedRegistry(registry: small, clock: { Int64(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) })
results.append(measure("ES map + decide AUTH_OPEN (enrolled, ClockedRegistry)") { _ in
    _ = AuthDecider.decide(ESMapper.map(message), clocked: clockedSmall)
})
// Every event on the machine pays this path, mapping included.
process.pointee.audit_token.val.5 = UInt32(unrelated.pid)
process.pointee.audit_token.val.7 = UInt32(unrelated.pidVersion)
results.append(measure("ES map + decide AUTH_OPEN (unrelated, ClockedRegistry)") { _ in
    _ = AuthDecider.decide(ESMapper.map(message), clocked: clockedSmall)
})

// Throughput (not latency): 4 threads through the ClockedRegistry File Guard uses, with a
// real monotonic clock read inside its lock, so no thread ever sees time go backwards.
let (shared, _) = makeRegistry(rules: 4)
let clocked = ClockedRegistry(registry: shared, clock: { Int64(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) })
var timebase = mach_timebase_info_data_t()
mach_timebase_info(&timebase)
let perThread = 100_000
let start = mach_absolute_time()
DispatchQueue.concurrentPerform(iterations: 4) { thread in
    for _ in 0..<perThread {
        _ = clocked.run { registry, now in
            registry.authorizeFile(process: identity(9100 + Int32(thread), 1), parent: nil, path: "/usr/lib/x",
                                   operations: ["read"], nowNs: now)
        }
    }
}
let elapsed = (mach_absolute_time() - start) * UInt64(timebase.numer) / UInt64(timebase.denom)
results.append(["case": "throughput: 4 threads x \(perThread) unrelated via ClockedRegistry",
                "wall_ns_per_call": elapsed / UInt64(4 * perThread)])

let host = ProcessInfo.processInfo
let report: [String: Any] = ["os": host.operatingSystemVersionString, "cpus": host.activeProcessorCount, "results": results]
let data = try! JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
print(String(decoding: data, as: UTF8.self))
