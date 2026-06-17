import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct CheckDetailView: View {
    @Environment(SecurityStore.self) private var store
    @Environment(SecurityScanner.self) private var scanner
    @State private var searchText = ""
    @State private var filterStatus: CheckStatus?

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if store.checks.isEmpty && store.isScanning {
                VStack {
                    Spacer()
                    ProgressView("Scanning...")
                    Spacer()
                }
            } else {
                checkList
            }
        }
    }

    private var toolbar: some View {
        HStack {
            Text("All Checks")
                .font(.title2)
                .fontWeight(.bold)

            Spacer()

            Picker("Status", selection: $filterStatus) {
                Text("All Statuses").tag(CheckStatus?.none)
                Divider()
                Label("Pass", systemImage: "checkmark.circle.fill").tag(CheckStatus?.some(.pass))
                Label("Warning", systemImage: "exclamationmark.triangle.fill").tag(CheckStatus?.some(.warning))
                Label("Fail", systemImage: "xmark.circle.fill").tag(CheckStatus?.some(.fail))
                Label("Info", systemImage: "info.circle.fill").tag(CheckStatus?.some(.info))
                Label("Unknown", systemImage: "questionmark.circle.fill").tag(CheckStatus?.some(.unknown))
            }
            .frame(width: 150)

            TextField("Search", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .frame(width: 200)

            Button {
                exportResults()
            } label: {
                Label("Export", systemImage: "square.and.arrow.up")
            }
            .disabled(store.checks.isEmpty)

            Button {
                Task { await store.runScan(using: scanner) }
            } label: {
                Label("Re-scan", systemImage: "arrow.clockwise")
            }
            .disabled(store.isScanning)
        }
        .padding()
    }

    private func exportResults() {
        guard let data = store.exportJSON() else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "harden-scan-\(Date().formatted(.iso8601.year().month().day())).json"
        panel.begin { response in
            if response == .OK, let url = panel.url {
                try? data.write(to: url)
            }
        }
    }

    private var filteredChecks: [SecurityCheck] {
        var result = store.checks
        if let status = filterStatus {
            result = result.filter { $0.status == status }
        }
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            result = result.filter {
                $0.name.lowercased().contains(query)
                || $0.description.lowercased().contains(query)
                || $0.details.lowercased().contains(query)
                || $0.stigReferences.contains { $0.id.lowercased().contains(query) }
                || $0.cisReferences.contains { $0.id.lowercased().contains(query) }
            }
        }
        return result
    }

    private var checkList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 16) {
                ForEach(CheckCategory.allCases) { category in
                    let categoryChecks = filteredChecks.filter { $0.category == category }
                    if !categoryChecks.isEmpty {
                        categorySection(category, checks: categoryChecks)
                    }
                }
            }
            .padding()
        }
    }

    private func categorySection(_ category: CheckCategory, checks: [SecurityCheck]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: category.icon)
                    .foregroundStyle(category.color)
                Text(category.rawValue)
                    .font(.title3)
                    .fontWeight(.semibold)
                Spacer()
                let passed = checks.filter { $0.status == .pass }.count
                Text("\(passed)/\(checks.count) passed")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(checks) { check in
                checkRow(check)
            }
        }
    }

    private func checkRow(_ check: SecurityCheck) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                statusIcon(check.status)
                Text(check.name)
                    .font(.body)
                    .fontWeight(.medium)
                Spacer()
                ForEach(check.stigReferences) { stig in
                    Text(stig.id)
                        .font(.system(size: 9, design: .monospaced))
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(stigColor(stig.severity).opacity(0.15))
                        .foregroundStyle(stigColor(stig.severity))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .help("\(stig.title) (\(stig.severity))")
                }
                ForEach(check.cisReferences) { cis in
                    Text("CIS \(cis.id)")
                        .font(.system(size: 9, design: .monospaced))
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(Color.teal.opacity(0.15))
                        .foregroundStyle(.teal)
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .help("\(cis.title) (\(cis.level))")
                }
                Text(check.severity.label)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if store.isItemSnoozed(check.id) {
                    Image(systemName: "bell.slash.fill")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
            }

            Text(check.details.isEmpty ? check.description : check.details)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)

            HStack(spacing: 8) {
                if !check.recommendation.isEmpty && (check.status == .fail || check.status == .warning) {
                    Text(check.recommendation)
                        .font(.caption)
                        .foregroundStyle(.blue)
                        .lineLimit(2)
                }
                if let url = check.settingsURL, check.status != .pass {
                    Spacer()
                    Button {
                        NSWorkspace.shared.open(url)
                    } label: {
                        Image(systemName: "gear")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .help("Open in System Settings")
                }
            }
        }
        .padding(10)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func stigColor(_ severity: String) -> Color {
        switch severity {
        case "CAT I": return .red
        case "CAT II": return .orange
        case "CAT III": return .yellow
        default: return .secondary
        }
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
}
