import AppKit
import Foundation
import CoreFoundation
import CoreServices

// Paths are derived from the account. A hard-coded user path would make installation impossible on another account.
let homeDirectory = NSHomeDirectory()
let userName = NSUserName()
let defaultGuardRoot = homeDirectory + "/.local/share/agentbelt"
let privateBundleIdentifier = "local.agentbelt.zcode.snapshot-blocked"
let safeLauncherBundleIdentifier = "local.agentbelt.zcode.safe-launcher"
let zcodeURLScheme = "zcode"
let privateApplicationName = "ZCode Snapshot Blocked"

struct VerifiedPrivateLaunch {
    let appPath: String
    let environment: [String: String]
    let generation: String
    let privatePID: Int?
}

func isValidInstalledPath(_ path: String) -> Bool {
    guard !path.isEmpty, path.first == "/", !path.contains("\0"), path != "/",
          !path.unicodeScalars.contains(where: { $0.value < 0x20 }) else { return false }
    let components = path.split(separator: "/", omittingEmptySubsequences: true)
    return !components.contains { $0 == "." || $0 == ".." }
}

/// A present bundle setting is trusted only after strict path validation. A missing key keeps old bundles on the default.
func resolveInstalledPath(_ value: Any?, key: String, fallback: String) -> String {
    guard let value else { return fallback }
    guard let path = value as? String, isValidInstalledPath(path) else {
        fatalError("invalid installed path metadata for " + key)
    }
    return path
}

func installedPath(_ key: String, fallback: String) -> String {
    resolveInstalledPath(Bundle.main.object(forInfoDictionaryKey: key), key: key, fallback: fallback)
}

func backendEnvironment(root: String) -> [String: String] {
    let arguments = ["-I", root + "/agentbelt.py", "zcode-backend", "app-server", "--stdio"]
    guard let data = try? JSONSerialization.data(withJSONObject: arguments) else {
        fatalError("could not encode the protected backend arguments")
    }
    return ["ZCODE_AGENT_SERVER_COMMAND": "/usr/bin/python3",
            "ZCODE_AGENT_SERVER_ARGS_JSON": String(decoding: data, as: UTF8.self)]
}

func isSafePrivateAppPath(_ path: String, root: String) -> Bool {
    guard isValidInstalledPath(path) else { return false }
    return path == root + "/state/zcode-private/ZCode.app"
}

func isSafeEnvironmentValue(_ value: String, maxLength: Int = 4096) -> Bool {
    !value.isEmpty && value.count <= maxLength && !value.unicodeScalars.contains(where: { $0.value < 0x20 })
}

func verifiedPrivateLaunch(from data: Data, status: Int32, root: String) -> VerifiedPrivateLaunch? {
    guard status == 0,
          let result = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          result["snapshot_uploads_blocked"] as? Bool == true,
          result["auto_updates_blocked"] as? Bool == true,
          result["gui_egress_confined"] as? Bool == false,
          result["bundle_id"] as? String == privateBundleIdentifier,
          let generation = result["generation"] as? String,
          generation.count == 32,
          generation.unicodeScalars.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102) }),
          let appPath = result["app_path"] as? String,
          isSafePrivateAppPath(appPath, root: root),
          let rawEnvironment = result["environment"] as? [String: Any] else { return nil }
    let privatePID: Int?
    if let rawPID = result["private_gui_pid"], !(rawPID is NSNull) {
        guard let pid = rawPID as? Int, pid > 0 else { return nil }
        privatePID = pid
    } else {
        privatePID = nil
    }

    let requiredKeys = ["ZCODE_AGENT_SERVER_COMMAND", "ZCODE_AGENT_SERVER_ARGS_JSON",
                        "ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT", "ZCODE_DESKTOP_APPLICATION_NAME",
                        "ZCODE_DESKTOP_USER_DATA_DIR", "ZCODE_DESKTOP_SESSION_DATA_DIR"]
    guard Set(rawEnvironment.keys) == Set(requiredKeys) else { return nil }
    var environment = [String: String]()
    for key in requiredKeys {
        guard let value = rawEnvironment[key] as? String, isSafeEnvironmentValue(value) else { return nil }
        environment[key] = value
    }
    guard environment["ZCODE_AGENT_SERVER_COMMAND"] == "/usr/bin/python3",
          environment["ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT"] == "1",
          environment["ZCODE_DESKTOP_APPLICATION_NAME"] == privateApplicationName,
          isValidInstalledPath(environment["ZCODE_DESKTOP_USER_DATA_DIR"]!),
          isValidInstalledPath(environment["ZCODE_DESKTOP_SESSION_DATA_DIR"]!),
          environment["ZCODE_DESKTOP_USER_DATA_DIR"] == root + "/state/zcode-private/user-data",
          environment["ZCODE_DESKTOP_SESSION_DATA_DIR"] == root + "/state/zcode-private/session" else { return nil }
    guard let argsData = environment["ZCODE_AGENT_SERVER_ARGS_JSON"]!.data(using: .utf8),
          let args = try? JSONSerialization.jsonObject(with: argsData) as? [String],
          args == ["-I", root + "/agentbelt.py", "zcode-private-backend", "--generation", generation, "app-server", "--stdio"] else { return nil }
    return VerifiedPrivateLaunch(appPath: appPath, environment: environment, generation: generation, privatePID: privatePID)
}

func privateOpenConfiguration(_ launch: VerifiedPrivateLaunch) -> NSWorkspace.OpenConfiguration {
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = true
    configuration.createsNewApplicationInstance = false
    let environment = launch.environment
    configuration.environment = [
        "HOME": homeDirectory, "USER": userName, "LOGNAME": userName,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
        "ZCODE_AGENT_SERVER_COMMAND": environment["ZCODE_AGENT_SERVER_COMMAND"]!,
        "ZCODE_AGENT_SERVER_ARGS_JSON": environment["ZCODE_AGENT_SERVER_ARGS_JSON"]!,
        "ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT": environment["ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT"]!,
        "ZCODE_DESKTOP_APPLICATION_NAME": environment["ZCODE_DESKTOP_APPLICATION_NAME"]!,
        "ZCODE_DESKTOP_USER_DATA_DIR": environment["ZCODE_DESKTOP_USER_DATA_DIR"]!,
        "ZCODE_DESKTOP_SESSION_DATA_DIR": environment["ZCODE_DESKTOP_SESSION_DATA_DIR"]!
    ]
    return configuration
}

func protocolHandler() -> String? {
    LSCopyDefaultHandlerForURLScheme(zcodeURLScheme as CFString)?.takeRetainedValue() as String?
}

func protocolStatus() -> [String: Any] {
    ["scheme": zcodeURLScheme, "handler": protocolHandler() ?? NSNull(),
     "manager_bundle_id": safeLauncherBundleIdentifier,
     "registered": protocolHandler() == safeLauncherBundleIdentifier]
}

func protocolRegistrationArguments() -> [String] {
    [zcodeURLScheme, safeLauncherBundleIdentifier]
}

func registerZcodeProtocol() throws {
    let arguments = protocolRegistrationArguments()
    guard LSSetDefaultHandlerForURLScheme(arguments[0] as CFString, arguments[1] as CFString) == noErr else {
        throw NSError(domain: "SafeProtocol", code: 1)
    }
    let data = try JSONSerialization.data(withJSONObject: protocolStatus(), options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}

let guardRoot = installedPath("AgentbeltRoot", fallback: defaultGuardRoot)
let guardScript = guardRoot + "/agentbelt.py"
let safeAppPath = homeDirectory + "/Applications/Zcode Safe.app"
let dockBackupPath = guardRoot + "/state/backups/dock-before-safe.plist"

/// The bin directory of the Node the installer pinned in `config.json`. It goes in front of PATH in the Zcode app environment. If there is none, only the system PATH is given.
func pinnedNodeBinDirectory() -> String? {
    guard let data = FileManager.default.contents(atPath: guardRoot + "/config.json"),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let node = object["node"] as? String, node.hasPrefix("/") else { return nil }
    return (node as NSString).deletingLastPathComponent
}

func runGuard(_ arguments: [String]) -> (Int32, Data) {
    let task = Process(), output = Pipe()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    task.arguments = ["-I", guardScript] + arguments
    task.environment = ["HOME": homeDirectory, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"]
    task.standardOutput = output
    task.standardError = FileHandle.nullDevice
    do {
        try task.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return (task.terminationStatus, data)
    } catch { return (125, Data()) }
}

func checkedPrivateLaunch() -> VerifiedPrivateLaunch? {
    let (status, data) = runGuard(["check-zcode-private"])
    return verifiedPrivateLaunch(from: data, status: status, root: guardRoot)
}

func safeIcon() -> NSImage {
    let image = NSImage(size: NSSize(width: 1024, height: 1024))
    image.lockFocus()
    NSColor(calibratedRed: 0.04, green: 0.43, blue: 0.32, alpha: 1).setFill()
    NSBezierPath(roundedRect: NSRect(x: 24, y: 24, width: 976, height: 976), xRadius: 210, yRadius: 210).fill()
    if let symbol = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "Safe")?.withSymbolConfiguration(.init(paletteColors: [.white])) {
        symbol.draw(in: NSRect(x: 260, y: 320, width: 504, height: 550))
    }
    let text = NSAttributedString(string: "SAFE", attributes: [.font: NSFont.systemFont(ofSize: 145, weight: .bold), .foregroundColor: NSColor.white])
    text.draw(at: NSPoint(x: (1024 - text.size().width) / 2, y: 125))
    image.unlockFocus()
    return image
}

func makeIconset(_ directory: String) throws {
    try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    let image = safeIcon()
    for size in [16, 32, 128, 256, 512] {
        for scale in [1, 2] {
            let pixels = size * scale
            let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
            image.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
            NSGraphicsContext.restoreGraphicsState()
            let suffix = scale == 2 ? "@2x" : ""
            try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: directory).appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
        }
    }
}

func pinDock() throws {
    let domain = "com.apple.dock" as CFString, key = "persistent-apps" as CFString
    guard let existing = CFPreferencesCopyAppValue(key, domain) as? [[String: Any]] else { throw NSError(domain: "SafeDockRead", code: 1) }
    let backup = URL(fileURLWithPath: dockBackupPath)
    if !FileManager.default.fileExists(atPath: backup.path) {
        try FileManager.default.createDirectory(at: backup.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let bytes = try PropertyListSerialization.data(fromPropertyList: existing, format: .binary, options: 0)
        guard FileManager.default.createFile(atPath: backup.path, contents: bytes, attributes: [.posixPermissions: 0o600]) else {
            throw NSError(domain: "SafeDockBackup", code: 1)
        }
    }
    var tiles: [[String: Any]] = [], insertion: Int? = nil
    for tile in existing {
        let data = tile["tile-data"] as? [String: Any]
        let file = data?["file-data"] as? [String: Any]
        let raw = file?["_CFURLString"] as? String ?? ""
        let path = URL(string: raw)?.standardizedFileURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")) ?? ""
        if path == safeAppPath.trimmingCharacters(in: CharacterSet(charactersIn: "/")) || path == "Applications/ZCode.app" {
            if insertion == nil { insertion = tiles.count }
        } else { tiles.append(tile) }
    }
    let tile: [String: Any] = ["tile-type": "file-tile", "tile-data": ["file-label": "Zcode Safe", "file-type": 41, "file-data": ["_CFURLString": URL(fileURLWithPath: safeAppPath, isDirectory: true).absoluteString, "_CFURLStringType": 15]]]
    tiles.insert(tile, at: min(insertion ?? tiles.count, tiles.count))
    CFPreferencesSetAppValue(key, tiles as CFPropertyList, domain)
    guard CFPreferencesAppSynchronize(domain) else { throw NSError(domain: "SafeDock", code: 1) }
}

final class SafeDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    let status = NSTextField(wrappingLabelWithString: "보호 실행 상태를 확인합니다.")
    private var hasFinishedLaunching = false
    private var pendingURLs = [URL]()
    private var launchInProgress = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.applicationIconImage = safeIcon()
        let menu = NSMenu(), appItem = NSMenuItem(), appMenu = NSMenu()
        appMenu.addItem(withTitle: "Zcode Safe 상태", action: #selector(showStatus), keyEquivalent: "s").target = self
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Zcode Safe 종료", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu; menu.addItem(appItem); NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 250), styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Zcode Safe"; window.isReleasedWhenClosed = false
        let title = NSTextField(labelWithString: "Zcode Safe")
        title.font = .systemFont(ofSize: 25, weight: .semibold)
        title.frame = NSRect(x: 26, y: 193, width: 425, height: 35)
        status.frame = NSRect(x: 26, y: 105, width: 425, height: 78)
        let open = NSButton(title: "보호된 Zcode 열기", target: self, action: #selector(openZcode))
        open.frame = NSRect(x: 24, y: 60, width: 135, height: 32); open.bezelStyle = .rounded
        let check = NSButton(title: "상태 확인", target: self, action: #selector(showStatus))
        check.frame = NSRect(x: 172, y: 60, width: 125, height: 32); check.bezelStyle = .rounded
        let restore = NSButton(title: "기존 대화 복원", target: self, action: #selector(restoreHistory))
        restore.frame = NSRect(x: 306, y: 60, width: 150, height: 32); restore.bezelStyle = .rounded
        let copy = NSButton(title: "GLM 키 등록 명령 복사", target: self, action: #selector(copyKeyCommand))
        copy.frame = NSRect(x: 24, y: 16, width: 230, height: 32); copy.bezelStyle = .rounded
        for view in [title, status, open, check, restore, copy] { window.contentView?.addSubview(view) }
        window.center(); hasFinishedLaunching = true
        if pendingURLs.isEmpty { openZcode() } else { forwardPendingURLs() }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { openZcode(); return true }
    func application(_ application: NSApplication, open urls: [URL]) {
        let accepted = urls.filter { url in
            guard url.scheme?.lowercased() == zcodeURLScheme, url.absoluteString.count <= 8192 else { return false }
            return !url.absoluteString.unicodeScalars.contains(where: { $0.value < 0x20 })
        }
        if pendingURLs.count + accepted.count <= 8 { pendingURLs.append(contentsOf: accepted) }
        if hasFinishedLaunching { forwardPendingURLs() }
    }
    @objc func showStatus() {
        guard let launch = checkedPrivateLaunch() else {
            status.stringValue = "보호된 비공개 Zcode 복제본을 확인하지 못했습니다. 원본 GUI는 실행하지 않습니다."
            window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return
        }
        if launch.privatePID != nil {
            status.stringValue = "스냅샷 업로드와 자동 업데이트가 차단된 보호된 비공개 복제본이 실행 중입니다. GUI 자체는 OS 샌드박스로 격리되지 않습니다."
        } else {
            status.stringValue = "보호된 비공개 복제본을 시작할 수 있습니다. GUI 자체는 OS 샌드박스로 격리되지 않습니다."
        }
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    @objc func openZcode() {
        guard let launch = checkedPrivateLaunch() else {
            status.stringValue = "보호된 비공개 Zcode 복제본을 확인하지 못했습니다. 원본 GUI는 실행하지 않습니다."
            window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return
        }
        if let rawPID = launch.privatePID,
           let app = NSRunningApplication(processIdentifier: pid_t(rawPID)) {
            app.activate(options: [.activateIgnoringOtherApps]); forwardPendingURLs(); return
        }
        launchPrivateClone(launch)
    }
    private func launchPrivateClone(_ launch: VerifiedPrivateLaunch) {
        guard !launchInProgress else { return }
        launchInProgress = true
        status.stringValue = "스냅샷 업로드와 자동 업데이트가 차단된 보호된 백엔드를 사용하는 비공개 복제본을 시작합니다. GUI 자체는 OS 샌드박스로 격리되지 않습니다."
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: launch.appPath),
                                            configuration: privateOpenConfiguration(launch)) { [weak self] app, error in
            DispatchQueue.main.async {
                self?.launchInProgress = false
                guard let app, error == nil else {
                    self?.status.stringValue = "보호된 비공개 복제본을 시작하지 못했습니다. Terminal에서 agentbelt doctor로 확인하세요."
                    self?.window.makeKeyAndOrderFront(nil); return
                }
                let result = runGuard(["record-zcode-private-launch", String(app.processIdentifier), "--generation", launch.generation])
                self?.status.stringValue = result.0 == 0 ? "보호된 비공개 Zcode 복제본을 열었습니다." : "복제본은 열렸지만 보호 실행 기록을 확인하지 못했습니다."
                if result.0 == 0 {
                    app.activate(options: [.activateIgnoringOtherApps])
                    self?.forwardPendingURLs()
                }
            }
        }
    }
    private func forwardPendingURLs() {
        guard hasFinishedLaunching, !pendingURLs.isEmpty, !launchInProgress else { return }
        guard let launch = checkedPrivateLaunch() else {
            status.stringValue = "비공개 복제본을 확인하지 못해 링크를 전달하지 않았습니다."
            return
        }
        guard launch.privatePID != nil else {
            launchPrivateClone(launch)
            return
        }
        let urls = pendingURLs; pendingURLs.removeAll()
        NSWorkspace.shared.open(urls, withApplicationAt: URL(fileURLWithPath: launch.appPath),
                                configuration: privateOpenConfiguration(launch)) { [weak self] _, error in
            if error != nil {
                DispatchQueue.main.async {
                    self?.pendingURLs.insert(contentsOf: urls, at: 0)
                    self?.status.stringValue = "보호된 비공개 복제본으로 링크를 전달하지 못했습니다."
                }
            }
        }
    }
    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        let menu = NSMenu()
        menu.addItem(withTitle: "보호된 Zcode 열기", action: #selector(openZcode), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Safe 상태", action: #selector(showStatus), keyEquivalent: "").target = self
        menu.addItem(withTitle: "기존 대화 복원", action: #selector(restoreHistory), keyEquivalent: "").target = self
        return menu
    }
    @objc func restoreHistory() {
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        status.stringValue = "Safe에서 연 프로젝트의 기존 대화를 확인하고 있습니다."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let (code, data) = runGuard(["restore-open-history"])
            let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            let count = value?["imported_sessions"] as? Int ?? 0
            DispatchQueue.main.async {
                self?.status.stringValue = code == 0 ? "대화 \(count)개를 추가로 복원했습니다. Zcode에서 대화를 다시 선택하세요. 원본과 이미 있는 Safe 대화는 유지합니다." : "복원을 완료하지 못했습니다. 원본은 유지되었습니다. Terminal에서 agentbelt restore-history와 프로젝트 경로로 확인하세요."
            }
        }
    }
    @objc func copyKeyCommand() {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString("packet-ask-safe setup-key", forType: .string)
        status.stringValue = "명령을 복사했습니다. macOS Terminal에 붙여 넣어 GLM 키를 등록하세요. 키는 채팅창에 입력하지 마세요."
    }
}

if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--make-icon" {
    try makeIconset(CommandLine.arguments[2])
} else if CommandLine.arguments.dropFirst() == ["--protocol-status"] {
    let data = try JSONSerialization.data(withJSONObject: protocolStatus(), options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
} else if CommandLine.arguments.dropFirst() == ["--register-zcode-protocol"] {
    try registerZcodeProtocol()
} else if CommandLine.arguments.dropFirst() == ["--dock-status"] {
    let tiles = CFPreferencesCopyAppValue("persistent-apps" as CFString, "com.apple.dock" as CFString) as? [[String: Any]] ?? []
    let paths = tiles.compactMap { tile -> String? in
        guard let data = tile["tile-data"] as? [String: Any], let file = data["file-data"] as? [String: Any], let raw = file["_CFURLString"] as? String else { return nil }
        return URL(string: raw)?.standardizedFileURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
    let status: [String: Any] = ["entries": tiles.count, "safePinned": paths.contains(safeAppPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))), "plainPinned": paths.contains("Applications/ZCode.app")]
    let data = try JSONSerialization.data(withJSONObject: status, options: [.sortedKeys]); print(String(data: data, encoding: .utf8)!)
} else if CommandLine.arguments.dropFirst() == ["--pin-dock"] {
    try pinDock(); print("Safe Dock entry configured.")
} else {
    let application = NSApplication.shared
    let delegate = SafeDelegate(); application.delegate = delegate
    application.setActivationPolicy(.regular); application.run()
}
