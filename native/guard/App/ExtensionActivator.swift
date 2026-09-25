import Foundation
import SystemExtensions

/// Submits activation/deactivation requests only when the user presses a button.
/// macOS then asks for approval in System Settings; nothing is installed silently.
@MainActor
final class ExtensionActivator: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    @Published private(set) var status = "not requested"

    private var extensionIdentifier: String? {
        Bundle.main.bundleIdentifier.map { $0 + ".fileguard" }
    }

    func submit(activate: Bool) {
        guard let identifier = extensionIdentifier else {
            status = "missing bundle identifier"
            return
        }
        let request = activate
            ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: identifier, queue: .main)
        request.delegate = self
        status = activate ? "activation requested" : "deactivation requested"
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in self.status = "waiting for approval in System Settings" }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let text = result == .completed ? "completed" : "completed after reboot"
        Task { @MainActor in self.status = text }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        // Show the domain/code only; the localized text can include paths.
        let code = (error as NSError).code
        Task { @MainActor in self.status = "failed (code \(code))" }
    }
}
