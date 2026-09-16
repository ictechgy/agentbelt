import AppKit
import Foundation
import CoreFoundation

// Paths are derived from the account. A hard-coded user path would make installation impossible on another account.
let homeDirectory = NSHomeDirectory()
let userName = NSUserName()
let guardRoot = homeDirectory + "/.local/share/agent-guard"
let guardScript = guardRoot + "/agent_guard.py"
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
    var launching = false
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
        let open = NSButton(title: "Zcode 열기", target: self, action: #selector(openZcode))
        open.frame = NSRect(x: 24, y: 60, width: 135, height: 32); open.bezelStyle = .rounded
        let check = NSButton(title: "상태 확인", target: self, action: #selector(showStatus))
        check.frame = NSRect(x: 172, y: 60, width: 125, height: 32); check.bezelStyle = .rounded
        let restore = NSButton(title: "기존 대화 복원", target: self, action: #selector(restoreHistory))
        restore.frame = NSRect(x: 306, y: 60, width: 150, height: 32); restore.bezelStyle = .rounded
        let copy = NSButton(title: "GLM 키 등록 명령 복사", target: self, action: #selector(copyKeyCommand))
        copy.frame = NSRect(x: 24, y: 16, width: 230, height: 32); copy.bezelStyle = .rounded
        for view in [title, status, open, check, restore, copy] { window.contentView?.addSubview(view) }
        window.center(); openZcode()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { openZcode(); return true }
    @objc func showStatus() {
        let (code, data) = runGuard(["live-status"])
        if code == 0, let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if value["safe_launch"] as? Bool == true {
                let count = value["sandboxed_children"] as? Int ?? 0
                status.stringValue = count > 0 ? "Safe 실행 경로와 보호된 백엔드를 확인했습니다.\n실제 작업 창의 이름은 Zcode로 표시됩니다." : "Safe 실행 경로입니다. 프로젝트를 열면 보호 백엔드가 시작됩니다."
            } else { status.stringValue = value["gui_running"] as? Bool == true ? "일반 Zcode가 실행 중이거나 보호 경로를 확인할 수 없습니다. 작업을 저장하고 Zcode를 종료한 뒤 Safe로 여세요." : "Zcode가 종료되어 있습니다. 아래 버튼으로 보호 실행하세요." }
        } else { status.stringValue = "상태를 확인하지 못했습니다. Terminal에서 agent-guard doctor를 실행하세요." }
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    @objc func openZcode() {
        let (_, data) = runGuard(["live-status"])
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { showStatus(); return }
        if value["gui_running"] as? Bool == true {
            guard value["safe_launch"] as? Bool == true else { showStatus(); return }
            if let pid = value["gui_pid"] as? Int, let app = NSRunningApplication(processIdentifier: pid_t(pid)) { app.activate(options: [.activateIgnoringOtherApps]) }
            return
        }
        if launching { return }
        guard runGuard(["check-zcode"]).0 == 0 else {
            status.stringValue = "설치 버전 또는 보호 설정 확인에 실패했습니다. Terminal에서 agent-guard doctor를 실행하세요."
            window.makeKeyAndOrderFront(nil); return
        }
        launching = true
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.createsNewApplicationInstance = true
        let searchPath = ([pinnedNodeBinDirectory()].compactMap { $0 } + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]).joined(separator: ":")
        configuration.environment = [
            "HOME": homeDirectory, "USER": userName, "LOGNAME": userName,
            "PATH": searchPath,
            "LANG": "en_US.UTF-8",
            "ZCODE_AGENT_SERVER_COMMAND": homeDirectory + "/.local/bin/zcode-backend-safe",
            "ZCODE_AGENT_SERVER_ARGS_JSON": "[\"app-server\",\"--stdio\"]",
            "ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT": "1"
        ]
        status.stringValue = "보호된 Zcode를 시작합니다."
        // LaunchServices gives the work window its own application identity;
        // quitting this Dock manager must not quit the user's Zcode session.
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/Applications/ZCode.app"), configuration: configuration) { [weak self] app, error in
            DispatchQueue.main.async {
                self?.launching = false
                guard error == nil, let app = app else {
                    self?.status.stringValue = "Zcode를 시작하지 못했습니다. agent-guard doctor로 확인하세요."
                    self?.window.makeKeyAndOrderFront(nil); return
                }
                let result = runGuard(["record-zcode-launch", String(app.processIdentifier)])
                self?.status.stringValue = result.0 == 0 ? "보호 실행 경로로 Zcode를 열었습니다." : "실행된 앱의 보호 상태를 다시 확인하세요."
                app.activate(options: [.activateIgnoringOtherApps])
            }
        }
    }
    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        let menu = NSMenu()
        menu.addItem(withTitle: "Zcode 열기", action: #selector(openZcode), keyEquivalent: "").target = self
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
                self?.status.stringValue = code == 0 ? "대화 \(count)개를 추가로 복원했습니다. Zcode에서 대화를 다시 선택하세요. 원본과 이미 있는 Safe 대화는 유지합니다." : "복원을 완료하지 못했습니다. 원본은 유지되었습니다. Terminal에서 agent-guard restore-history와 프로젝트 경로로 확인하세요."
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
