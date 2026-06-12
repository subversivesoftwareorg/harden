import SwiftUI

struct STIGReportView: View {
    @Environment(SecurityStore.self) private var store

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if store.checks.isEmpty && store.isScanning {
                VStack {
                    Spacer()
                    ProgressView("Scanning...")
                    Spacer()
                }
            } else if store.checks.isEmpty {
                VStack {
                    Spacer()
                    Text("Run a scan to see STIG compliance.")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
            } else {
                reportBody
            }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("STIG Compliance")
                    .font(.title2)
                    .fontWeight(.bold)
                Text(STIGMapping.stigVersion)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if !store.checks.isEmpty {
                complianceSummary
            }
        }
        .padding()
    }

    private var complianceSummary: some View {
        let entries = stigEntries
        let passing = entries.filter { $0.status == .pass }.count
        let failing = entries.filter { $0.status == .fail }.count
        let warning = entries.filter { $0.status == .warning }.count
        let total = entries.count
        let pct = total > 0 ? (passing * 100) / total : 0

        return HStack(spacing: 16) {
            summaryPill(count: passing, label: "Pass", color: .green)
            summaryPill(count: warning, label: "Warning", color: .orange)
            summaryPill(count: failing, label: "Fail", color: .red)

            Text("\(pct)%")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundStyle(pct >= 80 ? .green : pct >= 60 ? .orange : .red)

            Text("\(passing)/\(total) rules")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func summaryPill(count: Int, label: String, color: Color) -> some View {
        VStack(spacing: 2) {
            Text("\(count)")
                .font(.system(size: 18, weight: .semibold, design: .rounded))
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 9))
                .foregroundStyle(.secondary)
        }
        .frame(width: 50)
    }

    // MARK: - Report Body

    private var reportBody: some View {
        let entries = stigEntries
        let catI = entries.filter { $0.severity == "CAT I" }
        let catII = entries.filter { $0.severity == "CAT II" }

        return ScrollView {
            LazyVStack(alignment: .leading, spacing: 16) {
                if !catI.isEmpty {
                    severitySection("CAT I — High Severity", entries: catI, color: .red)
                }
                if !catII.isEmpty {
                    severitySection("CAT II — Medium Severity", entries: catII, color: .orange)
                }
            }
            .padding()
        }
    }

    private func severitySection(_ title: String, entries: [STIGEntry], color: Color) -> some View {
        let passing = entries.filter { $0.status == .pass }.count

        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Circle()
                    .fill(color)
                    .frame(width: 10, height: 10)
                Text(title)
                    .font(.title3)
                    .fontWeight(.semibold)
                Spacer()
                Text("\(passing)/\(entries.count) compliant")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(entries) { entry in
                stigRow(entry)
            }
        }
    }

    private func stigRow(_ entry: STIGEntry) -> some View {
        HStack(spacing: 10) {
            statusIcon(entry.status)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(entry.stigID)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text(entry.title)
                        .font(.body)
                        .fontWeight(.medium)
                        .lineLimit(1)
                }

                if !entry.details.isEmpty {
                    Text(entry.details)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }

            Spacer()

            Text(entry.checkID)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.tertiary)
        }
        .padding(10)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func statusIcon(_ status: CheckStatus) -> some View {
        Group {
            switch status {
            case .pass:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .fail:
                Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
            case .warning:
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            case .info:
                Image(systemName: "info.circle.fill").foregroundStyle(.blue)
            case .unknown:
                Image(systemName: "questionmark.circle.fill").foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Data

    private var stigEntries: [STIGEntry] {
        let checkMap = Dictionary(uniqueKeysWithValues: store.checks.map { ($0.id, $0) })
        var entries: [STIGEntry] = []
        var seenStigIDs: Set<String> = []

        for (checkID, refs) in STIGMapping.catalog.sorted(by: { $0.key < $1.key }) {
            let check = checkMap[checkID]
            for ref in refs {
                guard !seenStigIDs.contains(ref.id) else { continue }
                seenStigIDs.insert(ref.id)

                entries.append(STIGEntry(
                    stigID: ref.id,
                    title: ref.title,
                    severity: ref.severity,
                    checkID: checkID,
                    status: check?.status ?? .unknown,
                    details: check?.details ?? ""
                ))
            }
        }

        return entries.sorted { a, b in
            if a.severity != b.severity {
                return severityOrder(a.severity) < severityOrder(b.severity)
            }
            return a.stigID < b.stigID
        }
    }

    private func severityOrder(_ severity: String) -> Int {
        switch severity {
        case "CAT I": return 0
        case "CAT II": return 1
        case "CAT III": return 2
        default: return 3
        }
    }
}

struct STIGEntry: Identifiable {
    let stigID: String
    let title: String
    let severity: String
    let checkID: String
    let status: CheckStatus
    let details: String

    var id: String { stigID }
}
