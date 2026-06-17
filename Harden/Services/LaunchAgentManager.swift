import Foundation

enum LaunchAgentManager {

    private static let label = "com.subversivesoftware.harden.agent"

    private static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    static func install(intervalHours: Int) {
        let binaryPath = Bundle.main.executablePath ?? "/Applications/Harden.app/Contents/MacOS/Harden"
        let intervalSeconds = intervalHours * 3600

        let reportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Harden", isDirectory: true)
        try? FileManager.default.createDirectory(at: reportDir, withIntermediateDirectories: true)
        let reportPath = reportDir.appendingPathComponent("latest-scan.json").path

        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [binaryPath, "--agent", "--output", reportPath],
            "StartInterval": intervalSeconds,
            "RunAtLoad": true,
            "StandardErrorPath": reportDir.appendingPathComponent("agent.log").path,
        ]

        let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try? data?.write(to: plistURL)

        // Load immediately
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["load", plistURL.path]
        try? process.run()
        process.waitUntilExit()
    }

    static func uninstall() {
        // Unload first
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload", plistURL.path]
        try? process.run()
        process.waitUntilExit()

        try? FileManager.default.removeItem(at: plistURL)
    }
}
