// agentbelt Guard container app — R2 skeleton.
//
// Planned roles: install/remove the File Guard system extension with explicit user
// consent, show protection status, and act as the approver signer. The approval UI
// is intentionally absent: it must prove human presence (no URL, argv, AppleEvent or
// synthetic-input approvals) before it may exist; see docs/design/task-registry.md.
import SwiftUI

@main
struct AgentbeltGuardApp: App {
    var body: some Scene {
        WindowGroup("agentbelt Guard") {
            StatusView()
        }
    }
}

struct StatusView: View {
    @StateObject private var activator = ExtensionActivator()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("File Guard (skeleton)").font(.headline)
            Text("Observes process lineage only. It does not allow or deny file access.")
            Text("Extension: \(activator.status)")
            HStack {
                Button("Activate") { activator.submit(activate: true) }
                Button("Deactivate") { activator.submit(activate: false) }
            }
            Divider()
            Text("Approvals: not implemented (requires a human-presence design, R4).")
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(minWidth: 420)
    }
}
