import Foundation

@Observable
@MainActor
final class SecurityStore {
    var checks: [SecurityCheck] = []
    var isScanning = false
    var lastScanDate: Date?
    var device: DeviceIdentity?

    // Snooze state: checkID -> expiry date
    private(set) var snoozedItems: [String: Date] = [:]

    // Scan history: score snapshots over time
    private(set) var scanHistory: [ScanSnapshot] = []

    // Checks that changed status since last scan
    private(set) var changedChecks: [CheckChange] = []

    private let snoozePath: URL = {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = appSupport.appendingPathComponent("Harden", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("snoozed.json")
    }()

    private var historyPath: URL {
        snoozePath.deletingLastPathComponent().appendingPathComponent("scan_history.json")
    }

    init() {
        loadSnoozeState()
        loadScanHistory()
    }

    // MARK: - Computed Properties

    var score: Int {
        let scoreable = checks.filter { $0.severity != .info && $0.status != .unknown }
        guard !scoreable.isEmpty else { return 100 }
        var earned = 0
        var maximum = 0
        for check in scoreable {
            let w = check.severity.weight
            maximum += w
            switch check.status {
            case .pass: earned += w
            case .warning: earned += w / 2
            case .fail, .info, .unknown: break
            }
        }
        guard maximum > 0 else { return 100 }
        return (earned * 100) / maximum
    }

    var actionItems: [SecurityCheck] {
        let now = Date()
        return checks
            .filter { $0.status == .fail || $0.status == .warning }
            .filter { !isItemSnoozed($0.id, at: now) }
            .sorted { $0.severity < $1.severity }
    }

    var categorySummaries: [CategorySummary] {
        CheckCategory.allCases.map { cat in
            let catChecks = checks.filter { $0.category == cat }
            return CategorySummary(
                category: cat,
                total: catChecks.count,
                passed: catChecks.filter { $0.status == .pass }.count,
                warnings: catChecks.filter { $0.status == .warning }.count,
                failures: catChecks.filter { $0.status == .fail }.count
            )
        }.filter { $0.total > 0 }
    }

    // MARK: - Scanning

    func runScan(using scanner: SecurityScanner) async {
        isScanning = true
        let previousChecks = checks
        async let results = scanner.scan()
        async let deviceInfo = DeviceIdentity.current()
        checks = await results
        device = await deviceInfo
        lastScanDate = Date()
        isScanning = false
        purgeExpiredSnoozes()

        // Detect changes from previous scan
        if !previousChecks.isEmpty {
            changedChecks = detectChanges(from: previousChecks, to: checks)
        }

        // Record history snapshot
        let snapshot = ScanSnapshot(date: Date(), score: score, total: checks.count,
                                     passed: checks.filter { $0.status == .pass }.count,
                                     failed: checks.filter { $0.status == .fail }.count,
                                     warnings: checks.filter { $0.status == .warning }.count)
        scanHistory.append(snapshot)
        if scanHistory.count > 100 { scanHistory.removeFirst(scanHistory.count - 100) }
        saveScanHistory()
    }

    // MARK: - Snooze Management

    func snooze(_ checkID: String, until date: Date) {
        snoozedItems[checkID] = date
        saveSnoozeState()
    }

    func snooze(_ checkID: String, for duration: SnoozeDuration) {
        let expiry: Date
        switch duration {
        case .oneDay: expiry = Date().addingTimeInterval(86400)
        case .oneWeek: expiry = Date().addingTimeInterval(604800)
        case .oneMonth: expiry = Calendar.current.date(byAdding: .month, value: 1, to: Date()) ?? Date()
        case .forever: expiry = Date.distantFuture
        }
        snooze(checkID, until: expiry)
    }

    func unsnooze(_ checkID: String) {
        snoozedItems.removeValue(forKey: checkID)
        saveSnoozeState()
    }

    func isItemSnoozed(_ checkID: String, at date: Date = Date()) -> Bool {
        guard let expiry = snoozedItems[checkID] else { return false }
        return date < expiry
    }

    private func purgeExpiredSnoozes() {
        let now = Date()
        let expired = snoozedItems.filter { now >= $0.value }
        if !expired.isEmpty {
            for key in expired.keys { snoozedItems.removeValue(forKey: key) }
            saveSnoozeState()
        }
    }

    // MARK: - Persistence

    private func saveSnoozeState() {
        let mapped = snoozedItems.mapValues { $0.timeIntervalSince1970 }
        if let data = try? JSONEncoder().encode(mapped) {
            try? data.write(to: snoozePath)
        }
    }

    private func loadSnoozeState() {
        guard let data = try? Data(contentsOf: snoozePath),
              let mapped = try? JSONDecoder().decode([String: TimeInterval].self, from: data) else { return }
        snoozedItems = mapped.mapValues { Date(timeIntervalSince1970: $0) }
        purgeExpiredSnoozes()
    }

    // MARK: - Scan History

    private func saveScanHistory() {
        if let data = try? JSONEncoder().encode(scanHistory) {
            try? data.write(to: historyPath)
        }
    }

    private func loadScanHistory() {
        guard let data = try? Data(contentsOf: historyPath),
              let history = try? JSONDecoder().decode([ScanSnapshot].self, from: data) else { return }
        scanHistory = history
    }

    // MARK: - Change Detection

    private func detectChanges(from old: [SecurityCheck], to new: [SecurityCheck]) -> [CheckChange] {
        let oldMap = Dictionary(uniqueKeysWithValues: old.map { ($0.id, $0.status) })
        var changes: [CheckChange] = []
        for check in new {
            if let oldStatus = oldMap[check.id], oldStatus != check.status {
                changes.append(CheckChange(checkID: check.id, name: check.name,
                                           oldStatus: oldStatus, newStatus: check.status))
            }
        }
        return changes
    }

    // MARK: - Export

    func exportJSON() -> Data? {
        let export = checks.map { check in
            ExportedCheck(
                id: check.id, name: check.name, category: check.category.rawValue,
                severity: check.severity.label, status: check.status.rawValue,
                details: check.details, recommendation: check.recommendation,
                stigReferences: check.stigReferences,
                cisReferences: check.cisReferences
            )
        }
        let wrapper = ExportWrapper(
            device: device,
            scanDate: lastScanDate ?? Date(), score: score,
            totalChecks: checks.count, checks: export
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try? encoder.encode(wrapper)
    }
}

// MARK: - Supporting Types

struct CategorySummary: Identifiable {
    let category: CheckCategory
    let total: Int
    let passed: Int
    let warnings: Int
    let failures: Int

    var id: String { category.id }

    var score: Int {
        guard total > 0 else { return 100 }
        return (passed * 100) / total
    }
}

struct ScanSnapshot: Codable, Identifiable {
    let date: Date
    let score: Int
    let total: Int
    let passed: Int
    let failed: Int
    let warnings: Int

    var id: Date { date }
}

struct CheckChange: Identifiable {
    let checkID: String
    let name: String
    let oldStatus: CheckStatus
    let newStatus: CheckStatus

    var id: String { checkID }

    var improved: Bool {
        let statusOrder: [CheckStatus] = [.fail, .warning, .unknown, .info, .pass]
        let oldIndex = statusOrder.firstIndex(of: oldStatus) ?? 0
        let newIndex = statusOrder.firstIndex(of: newStatus) ?? 0
        return newIndex > oldIndex
    }
}

struct ExportedCheck: Codable {
    let id: String
    let name: String
    let category: String
    let severity: String
    let status: String
    let details: String
    let recommendation: String
    let stigReferences: [STIGReference]
    let cisReferences: [CISReference]
}

struct ExportWrapper: Codable {
    let device: DeviceIdentity?
    let scanDate: Date
    let score: Int
    let totalChecks: Int
    let checks: [ExportedCheck]
}

enum SnoozeDuration: String, CaseIterable, Identifiable {
    case oneDay = "1 Day"
    case oneWeek = "1 Week"
    case oneMonth = "1 Month"
    case forever = "Forever"

    var id: String { rawValue }
}
