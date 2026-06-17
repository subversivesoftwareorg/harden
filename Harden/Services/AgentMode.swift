import Foundation
import UserNotifications

enum AgentMode {

    static func run() {
        Task { @MainActor in
            await execute()
            exit(0)
        }
        dispatchMain()
    }

    @MainActor
    private static func execute() async {
        let scanner = SecurityScanner()
        let checks = await scanner.scan()
        let device = await DeviceIdentity.current()
        let scanDate = Date()

        let previousStatuses = loadPreviousStatuses()
        let changes = detectChanges(previous: previousStatuses, current: checks)

        let outputPath = parseOutputPath()
        let json = buildJSON(checks: checks, device: device, scanDate: scanDate)

        if let path = outputPath {
            try? json.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
            printErr("Report written to \(path)")
        } else {
            print(json)
        }

        saveCurrentStatuses(checks)

        if !changes.isEmpty {
            await postNotification(changes: changes, checks: checks)
        }

        let passed = checks.filter { $0.status == .pass }.count
        printErr("Scan complete: \(passed)/\(checks.count) checks passing")
        if !changes.isEmpty {
            printErr("\(changes.count) change\(changes.count == 1 ? "" : "s") since last scan")
        }
    }

    // MARK: - JSON Output

    private static func buildJSON(checks: [SecurityCheck], device: DeviceIdentity, scanDate: Date) -> String {
        let scoreable = checks.filter { $0.severity != .info && $0.status != .unknown }
        var earned = 0, maximum = 0
        for check in scoreable {
            let w = check.severity.weight
            maximum += w
            switch check.status {
            case .pass: earned += w
            case .warning: earned += w / 2
            case .fail, .info, .unknown: break
            }
        }
        let score = maximum > 0 ? (earned * 100) / maximum : 100

        let exported = checks.map { check in
            ExportedCheck(
                id: check.id, name: check.name, category: check.category.rawValue,
                severity: check.severity.label, status: check.status.rawValue,
                details: check.details, recommendation: check.recommendation,
                stigReferences: check.stigReferences, cisReferences: check.cisReferences
            )
        }
        let wrapper = ExportWrapper(
            device: device, scanDate: scanDate, score: score,
            totalChecks: checks.count, checks: exported
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(wrapper),
              let str = String(data: data, encoding: .utf8) else { return "{}" }
        return str
    }

    // MARK: - Change Detection

    private static let statusFilePath: URL = {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = appSupport.appendingPathComponent("Harden", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("agent_last_scan.json")
    }()

    private static func loadPreviousStatuses() -> [String: String] {
        guard let data = try? Data(contentsOf: statusFilePath),
              let map = try? JSONDecoder().decode([String: String].self, from: data) else { return [:] }
        return map
    }

    private static func saveCurrentStatuses(_ checks: [SecurityCheck]) {
        let map = Dictionary(uniqueKeysWithValues: checks.map { ($0.id, $0.status.rawValue) })
        if let data = try? JSONEncoder().encode(map) {
            try? data.write(to: statusFilePath)
        }
    }

    struct Change {
        let checkID: String
        let name: String
        let oldStatus: String
        let newStatus: String
        var isRegression: Bool {
            let order = ["pass": 4, "info": 3, "warning": 2, "unknown": 1, "fail": 0]
            return (order[newStatus] ?? 0) < (order[oldStatus] ?? 0)
        }
    }

    private static func detectChanges(previous: [String: String], current: [SecurityCheck]) -> [Change] {
        guard !previous.isEmpty else { return [] }
        var changes: [Change] = []
        for check in current {
            if let old = previous[check.id], old != check.status.rawValue {
                changes.append(Change(
                    checkID: check.id, name: check.name,
                    oldStatus: old, newStatus: check.status.rawValue
                ))
            }
        }
        return changes
    }

    // MARK: - Notifications

    private static func postNotification(changes: [Change], checks: [SecurityCheck]) async {
        let center = UNUserNotificationCenter.current()

        let settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
        }

        let regressions = changes.filter(\.isRegression)
        let improvements = changes.filter { !$0.isRegression }

        if !regressions.isEmpty {
            let content = UNMutableNotificationContent()
            content.title = "Harden: New Security Issues"
            if regressions.count == 1 {
                content.body = "\(regressions[0].name) changed from \(regressions[0].oldStatus) to \(regressions[0].newStatus)."
            } else {
                content.body = "\(regressions.count) checks regressed since last scan."
            }
            content.sound = .default
            let request = UNNotificationRequest(identifier: "harden-regression", content: content, trigger: nil)
            try? await center.add(request)
        }

        if !improvements.isEmpty && regressions.isEmpty {
            let content = UNMutableNotificationContent()
            content.title = "Harden: Security Improved"
            content.body = "\(improvements.count) check\(improvements.count == 1 ? "" : "s") improved since last scan."
            let request = UNNotificationRequest(identifier: "harden-improvement", content: content, trigger: nil)
            try? await center.add(request)
        }
    }

    // MARK: - Helpers

    private static func parseOutputPath() -> String? {
        let args = CommandLine.arguments
        guard let idx = args.firstIndex(of: "--output"), idx + 1 < args.count else { return nil }
        return args[idx + 1]
    }

    private static func printErr(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}
