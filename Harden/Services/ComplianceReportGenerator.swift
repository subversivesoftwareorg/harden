import Foundation

enum ComplianceReportGenerator {

    static func generateCSV(checks: [SecurityCheck], device: DeviceIdentity?) -> Data? {
        var rows: [String] = []
        rows.append("Check ID,Name,Category,Severity,Status,Details,Recommendation,STIG IDs,CIS IDs,Hardware UUID,Hostname")

        let uuid = device?.hardwareUUID ?? ""
        let host = device?.hostname ?? ""

        for check in checks {
            let stigIDs = check.stigReferences.map(\.id).joined(separator: "; ")
            let cisIDs = check.cisReferences.map(\.id).joined(separator: "; ")
            let row = [
                check.id,
                check.name,
                check.category.rawValue,
                check.severity.label,
                check.status.rawValue,
                check.details,
                check.recommendation,
                stigIDs,
                cisIDs,
                uuid,
                host,
            ].map { csvEscape($0) }.joined(separator: ",")
            rows.append(row)
        }

        return rows.joined(separator: "\n").data(using: .utf8)
    }

    private static func csvEscape(_ field: String) -> String {
        if field.contains(",") || field.contains("\"") || field.contains("\n") {
            return "\"" + field.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return field
    }

    static func generateHTML(checks: [SecurityCheck], score: Int, scanDate: Date, device: DeviceIdentity?) -> Data? {
        let dateStr = scanDate.formatted(date: .long, time: .shortened)
        let hostname = device?.hostname ?? ProcessInfo.processInfo.hostName
        let osVersion = device.map { "\($0.osVersion) (\($0.osBuild))" } ?? ProcessInfo.processInfo.operatingSystemVersionString

        let totalChecks = checks.count
        let passed = checks.filter { $0.status == .pass }.count
        let failed = checks.filter { $0.status == .fail }.count
        let warnings = checks.filter { $0.status == .warning }.count

        let stigEntries = buildSTIGEntries(from: checks)
        let cisEntries = buildCISEntries(from: checks)

        let stigPassing = stigEntries.filter { $0.status == .pass }.count
        let cisPassing = cisEntries.filter { $0.status == .pass }.count

        var html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Harden Compliance Report</title>
        <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'SF Pro', system-ui, sans-serif; color: #1d1d1f; line-height: 1.5; max-width: 960px; margin: 0 auto; padding: 24px; }
        h1 { font-size: 28px; font-weight: 700; margin-bottom: 4px; }
        h2 { font-size: 20px; font-weight: 600; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #d2d2d7; }
        h3 { font-size: 16px; font-weight: 600; margin: 20px 0 8px; }
        .meta { color: #86868b; font-size: 13px; margin-bottom: 24px; }
        .summary { display: flex; gap: 16px; margin: 16px 0 24px; flex-wrap: wrap; }
        .card { background: #f5f5f7; border-radius: 12px; padding: 16px 20px; flex: 1; min-width: 120px; text-align: center; }
        .card .number { font-size: 32px; font-weight: 700; }
        .card .label { font-size: 12px; color: #86868b; text-transform: uppercase; }
        .card.score .number { color: \(score >= 80 ? "#34c759" : score >= 60 ? "#ff9500" : "#ff3b30"); }
        .card.pass .number { color: #34c759; }
        .card.warn .number { color: #ff9500; }
        .card.fail .number { color: #ff3b30; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; font-size: 13px; }
        th { text-align: left; padding: 8px 12px; background: #f5f5f7; font-weight: 600; border-bottom: 2px solid #d2d2d7; }
        td { padding: 8px 12px; border-bottom: 1px solid #e8e8ed; vertical-align: top; }
        tr:hover td { background: #fafafa; }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
        .status-pass { background: #34c759; }
        .status-fail { background: #ff3b30; }
        .status-warning { background: #ff9500; }
        .status-info { background: #007aff; }
        .status-unknown { background: #8e8e93; }
        .badge { display: inline-block; font-size: 10px; font-family: 'SF Mono', monospace; padding: 1px 6px; border-radius: 3px; margin-right: 4px; }
        .badge-stig { background: #ff950020; color: #ff9500; }
        .badge-cis { background: #30b0c720; color: #30b0c7; }
        .badge-l1 { background: #007aff20; color: #007aff; }
        .badge-l2 { background: #af52de20; color: #af52de; }
        .recommendation { color: #007aff; font-size: 12px; margin-top: 4px; }
        .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #d2d2d7; color: #86868b; font-size: 12px; text-align: center; }
        @media (prefers-color-scheme: dark) {
            body { background: #1c1c1e; color: #f5f5f7; }
            .card { background: #2c2c2e; }
            th { background: #2c2c2e; border-color: #3a3a3c; }
            td { border-color: #3a3a3c; }
            tr:hover td { background: #2c2c2e; }
            h2 { border-color: #3a3a3c; }
            .footer { border-color: #3a3a3c; }
        }
        </style>
        </head>
        <body>
        <h1>Harden Compliance Report</h1>
        <div class="meta">\(dateStr) &mdash; \(hostname) &mdash; macOS \(osVersion)</div>

        <div class="summary">
            <div class="card score"><div class="number">\(score)</div><div class="label">Security Score</div></div>
            <div class="card pass"><div class="number">\(passed)</div><div class="label">Passed</div></div>
            <div class="card warn"><div class="number">\(warnings)</div><div class="label">Warnings</div></div>
            <div class="card fail"><div class="number">\(failed)</div><div class="label">Failed</div></div>
            <div class="card"><div class="number">\(totalChecks)</div><div class="label">Total Checks</div></div>
        </div>

        """

        // Device identity section
        if let dev = device {
            html += """
            <h2>Device Identity</h2>
            <table>
            <tbody>
            <tr><td><strong>Hardware UUID</strong></td><td><code>\(escapeHTML(dev.hardwareUUID))</code></td></tr>
            <tr><td><strong>Serial Number</strong></td><td>\(escapeHTML(dev.serialNumber))</td></tr>
            <tr><td><strong>Model</strong></td><td>\(escapeHTML(dev.model))</td></tr>
            <tr><td><strong>Hostname</strong></td><td>\(escapeHTML(dev.hostname))</td></tr>
            <tr><td><strong>macOS Version</strong></td><td>\(escapeHTML(dev.osVersion)) (\(escapeHTML(dev.osBuild)))</td></tr>
            <tr><td><strong>Primary MAC</strong></td><td><code>\(escapeHTML(dev.primaryMAC))</code></td></tr>
            </tbody>
            </table>

            """
        }

        // STIG compliance section
        html += """
        <h2>DISA STIG Compliance</h2>
        <p>\(STIGMapping.stigVersion) &mdash; \(stigPassing)/\(stigEntries.count) rules compliant (\(stigEntries.isEmpty ? 0 : stigPassing * 100 / stigEntries.count)%)</p>
        <table>
        <thead><tr><th>Status</th><th>STIG ID</th><th>Description</th><th>Severity</th></tr></thead>
        <tbody>
        """
        for entry in stigEntries {
            html += "<tr><td><span class=\"status status-\(entry.status.rawValue)\"></span>\(entry.status.rawValue.capitalized)</td>"
            html += "<td><span class=\"badge badge-stig\">\(entry.id)</span></td>"
            html += "<td>\(escapeHTML(entry.title))</td>"
            html += "<td>\(escapeHTML(entry.severity))</td></tr>\n"
        }
        html += "</tbody></table>\n"

        // CIS compliance section
        html += """
        <h2>CIS Benchmark Compliance</h2>
        <p>\(CISMapping.cisVersion) &mdash; \(cisPassing)/\(cisEntries.count) rules compliant (\(cisEntries.isEmpty ? 0 : cisPassing * 100 / cisEntries.count)%)</p>
        <table>
        <thead><tr><th>Status</th><th>CIS #</th><th>Description</th><th>Level</th></tr></thead>
        <tbody>
        """
        for entry in cisEntries {
            let levelClass = entry.level == "L1" ? "badge-l1" : "badge-l2"
            html += "<tr><td><span class=\"status status-\(entry.status.rawValue)\"></span>\(entry.status.rawValue.capitalized)</td>"
            html += "<td>\(escapeHTML(entry.id))</td>"
            html += "<td>\(escapeHTML(entry.title))</td>"
            html += "<td><span class=\"badge \(levelClass)\">\(entry.level)</span></td></tr>\n"
        }
        html += "</tbody></table>\n"

        // Full check listing
        html += "<h2>All Security Checks</h2>\n"
        for category in CheckCategory.allCases {
            let catChecks = checks.filter { $0.category == category }
            guard !catChecks.isEmpty else { continue }
            let catPassed = catChecks.filter { $0.status == .pass }.count
            html += "<h3>\(escapeHTML(category.rawValue)) (\(catPassed)/\(catChecks.count) passed)</h3>\n"
            html += "<table><thead><tr><th>Status</th><th>Check</th><th>Details</th><th>Frameworks</th></tr></thead><tbody>\n"
            for check in catChecks {
                var badges = ""
                for stig in check.stigReferences {
                    badges += "<span class=\"badge badge-stig\">\(stig.id)</span>"
                }
                for cis in check.cisReferences {
                    badges += "<span class=\"badge badge-cis\">CIS \(cis.id)</span>"
                }
                html += "<tr><td><span class=\"status status-\(check.status.rawValue)\"></span>\(check.status.rawValue.capitalized)</td>"
                html += "<td>\(escapeHTML(check.name))</td>"
                html += "<td>\(escapeHTML(check.details))"
                if !check.recommendation.isEmpty && (check.status == .fail || check.status == .warning) {
                    html += "<div class=\"recommendation\">\(escapeHTML(check.recommendation))</div>"
                }
                html += "</td><td>\(badges)</td></tr>\n"
            }
            html += "</tbody></table>\n"
        }

        html += """
        <div class="footer">
            Generated by Harden &mdash; subversivesoftware.org<br>
            STIG source: DISA (public.cyber.mil) &mdash; CIS source: CIS Benchmarks (cisecurity.org)
        </div>
        </body></html>
        """

        return html.data(using: .utf8)
    }

    // MARK: - Helpers

    private static func escapeHTML(_ string: String) -> String {
        string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }

    private struct FrameworkEntry {
        let id: String
        let title: String
        let severity: String
        let level: String
        let status: CheckStatus
    }

    private static func buildSTIGEntries(from checks: [SecurityCheck]) -> [FrameworkEntry] {
        let checkMap = Dictionary(uniqueKeysWithValues: checks.map { ($0.id, $0) })
        var entries: [FrameworkEntry] = []
        var seen: Set<String> = []

        for (checkID, refs) in STIGMapping.catalog.sorted(by: { $0.key < $1.key }) {
            let check = checkMap[checkID]
            for ref in refs {
                guard !seen.contains(ref.id) else { continue }
                seen.insert(ref.id)
                entries.append(FrameworkEntry(
                    id: ref.id, title: ref.title, severity: ref.severity,
                    level: "", status: check?.status ?? .unknown
                ))
            }
        }
        return entries.sorted { $0.id < $1.id }
    }

    private static func buildCISEntries(from checks: [SecurityCheck]) -> [FrameworkEntry] {
        let checkMap = Dictionary(uniqueKeysWithValues: checks.map { ($0.id, $0) })
        var entries: [FrameworkEntry] = []
        var seen: Set<String> = []

        for (checkID, refs) in CISMapping.catalog.sorted(by: { $0.key < $1.key }) {
            let check = checkMap[checkID]
            for ref in refs {
                guard !seen.contains(ref.id) else { continue }
                seen.insert(ref.id)
                entries.append(FrameworkEntry(
                    id: ref.id, title: ref.title, severity: "",
                    level: ref.level, status: check?.status ?? .unknown
                ))
            }
        }
        return entries.sorted { a, b in
            let aParts = a.id.split(separator: ".").compactMap { Int($0) }
            let bParts = b.id.split(separator: ".").compactMap { Int($0) }
            for i in 0..<min(aParts.count, bParts.count) {
                if aParts[i] != bParts[i] { return aParts[i] < bParts[i] }
            }
            return aParts.count < bParts.count
        }
    }
}
