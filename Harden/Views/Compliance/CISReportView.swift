import SwiftUI

struct CISReportView: View {
    @Environment(SecurityStore.self) private var store
    @State private var searchText = ""

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
                    Text("Run a scan to see CIS compliance.")
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
                Text("CIS Benchmark Compliance")
                    .font(.title2)
                    .fontWeight(.bold)
                Text(CISMapping.cisVersion)
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
        let entries = filteredEntries
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
        let entries = filteredEntries
        let sections: [(String, String, [CISEntry])] = [
            ("1", "Software Updates", entries.filter { $0.cisID.hasPrefix("1.") }),
            ("2", "System Settings", entries.filter { $0.cisID.hasPrefix("2.") }),
            ("3", "Logging & Auditing", entries.filter { $0.cisID.hasPrefix("3.") }),
            ("4", "Network", entries.filter { $0.cisID.hasPrefix("4.") }),
            ("5", "Authentication & Authorization", entries.filter { $0.cisID.hasPrefix("5.") }),
            ("6", "Applications", entries.filter { $0.cisID.hasPrefix("6.") }),
        ]

        return VStack(spacing: 0) {
            HStack {
                Spacer()
                TextField("Search", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
                    .padding(.horizontal)
                    .padding(.vertical, 8)
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    ForEach(sections, id: \.0) { num, title, sectionEntries in
                        if !sectionEntries.isEmpty {
                            cisSection("\(num). \(title)", entries: sectionEntries)
                        }
                    }
                }
                .padding()
            }
        }
    }

    private func cisSection(_ title: String, entries: [CISEntry]) -> some View {
        let passing = entries.filter { $0.status == .pass }.count

        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title)
                    .font(.title3)
                    .fontWeight(.semibold)
                Spacer()
                Text("\(passing)/\(entries.count) compliant")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(entries) { entry in
                cisRow(entry)
            }
        }
    }

    private func cisRow(_ entry: CISEntry) -> some View {
        HStack(spacing: 10) {
            statusIcon(entry.status)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(entry.cisID)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text(entry.level)
                        .font(.system(size: 9, weight: .medium))
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(entry.level == "L1" ? Color.blue.opacity(0.15) : Color.purple.opacity(0.15))
                        .foregroundStyle(entry.level == "L1" ? .blue : .purple)
                        .clipShape(RoundedRectangle(cornerRadius: 3))
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

    private var filteredEntries: [CISEntry] {
        let all = cisEntries
        guard !searchText.isEmpty else { return all }
        let query = searchText.lowercased()
        return all.filter {
            $0.cisID.lowercased().contains(query)
            || $0.title.lowercased().contains(query)
            || $0.checkID.lowercased().contains(query)
        }
    }

    private var cisEntries: [CISEntry] {
        let checkMap = Dictionary(uniqueKeysWithValues: store.checks.map { ($0.id, $0) })
        var entries: [CISEntry] = []
        var seenCISIDs: Set<String> = []

        for (checkID, refs) in CISMapping.catalog.sorted(by: { $0.key < $1.key }) {
            let check = checkMap[checkID]
            for ref in refs {
                guard !seenCISIDs.contains(ref.id) else { continue }
                seenCISIDs.insert(ref.id)

                entries.append(CISEntry(
                    cisID: ref.id,
                    title: ref.title,
                    level: ref.level,
                    checkID: checkID,
                    status: check?.status ?? .unknown,
                    details: check?.details ?? ""
                ))
            }
        }

        return entries.sorted { a, b in
            let aParts = a.cisID.split(separator: ".").compactMap { Int($0) }
            let bParts = b.cisID.split(separator: ".").compactMap { Int($0) }
            for i in 0..<min(aParts.count, bParts.count) {
                if aParts[i] != bParts[i] { return aParts[i] < bParts[i] }
            }
            return aParts.count < bParts.count
        }
    }
}

struct CISEntry: Identifiable {
    let cisID: String
    let title: String
    let level: String
    let checkID: String
    let status: CheckStatus
    let details: String

    var id: String { cisID }
}
