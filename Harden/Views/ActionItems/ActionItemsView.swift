import SwiftUI

struct ActionItemsView: View {
    @Environment(SecurityStore.self) private var store
    @Environment(SecurityScanner.self) private var scanner
    @Environment(RemediationRunner.self) private var remediator
    @State private var expandedItem: String?
    @State private var filterCategory: CheckCategory?
    @State private var showSnoozed = false
    @State private var confirmingFix: SecurityCheck?
    @State private var showFixResult = false

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if filteredItems.isEmpty {
                emptyState
            } else {
                itemList
            }
        }
        .alert("Apply Fix?", isPresented: Binding(
            get: { confirmingFix != nil },
            set: { if !$0 { confirmingFix = nil } }
        )) {
            Button("Cancel", role: .cancel) { confirmingFix = nil }
            Button("Apply") {
                guard let check = confirmingFix,
                      let remediation = Remediation.catalog[check.id] else { return }
                confirmingFix = nil
                Task {
                    let success = await remediator.execute(remediation, for: check.id)
                    showFixResult = true
                    if success {
                        // Re-scan to reflect changes
                        try? await Task.sleep(for: .milliseconds(500))
                        await store.runScan(using: scanner)
                    }
                }
            }
        } message: {
            if let check = confirmingFix, let remediation = Remediation.catalog[check.id] {
                Text("\(remediation.confirmation)\n\n\(remediation.requiresSudo ? "You will be prompted for your administrator password." : "")")
            }
        }
        .alert(remediator.lastResult?.success == true ? "Fix Applied" : "Fix Failed",
               isPresented: $showFixResult) {
            Button("OK") { showFixResult = false }
        } message: {
            Text(remediator.lastResult?.message ?? "")
        }
    }

    private var toolbar: some View {
        HStack {
            Text("Action Items")
                .font(.title2)
                .fontWeight(.bold)

            Spacer()

            Picker("Category", selection: $filterCategory) {
                Text("All Categories").tag(CheckCategory?.none)
                Divider()
                ForEach(CheckCategory.allCases) { cat in
                    Label(cat.rawValue, systemImage: cat.icon).tag(CheckCategory?.some(cat))
                }
            }
            .frame(width: 180)

            Toggle("Show Snoozed", isOn: $showSnoozed)
                .toggleStyle(.checkbox)

            Button {
                Task { await store.runScan(using: scanner) }
            } label: {
                Label("Re-scan", systemImage: "arrow.clockwise")
            }
            .disabled(store.isScanning)
        }
        .padding()
    }

    private var filteredItems: [SecurityCheck] {
        var items = showSnoozed ? allActionableChecks : store.actionItems
        if let cat = filterCategory {
            items = items.filter { $0.category == cat }
        }
        return items
    }

    private var allActionableChecks: [SecurityCheck] {
        store.checks
            .filter { $0.status == .fail || $0.status == .warning }
            .sorted { $0.severity < $1.severity }
    }

    private var itemList: some View {
        ScrollView {
            LazyVStack(spacing: 8) {
                ForEach(filteredItems) { check in
                    actionItemRow(check)
                }
            }
            .padding()
        }
    }

    private func actionItemRow(_ check: SecurityCheck) -> some View {
        let isSnoozed = store.isItemSnoozed(check.id)
        let isExpanded = expandedItem == check.id

        return VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                severityIcon(check.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(check.name)
                        .font(.headline)
                        .opacity(isSnoozed ? 0.5 : 1.0)
                    HStack(spacing: 8) {
                        Label(check.category.rawValue, systemImage: check.category.icon)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(check.severity.label)
                            .font(.caption)
                            .fontWeight(.medium)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(severityColor(check.severity).opacity(0.15))
                            .foregroundStyle(severityColor(check.severity))
                            .clipShape(Capsule())
                        if isSnoozed {
                            Text("Snoozed")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                }
                Spacer()
                snoozeMenu(for: check, isSnoozed: isSnoozed)
                Button {
                    withAnimation { expandedItem = isExpanded ? nil : check.id }
                } label: {
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(isExpanded ? 90 : 0))
                        .animation(.easeInOut(duration: 0.2), value: isExpanded)
                }
                .buttonStyle(.plain)
            }

            // Expanded details
            if isExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    Divider()
                    Text(check.details)
                        .font(.body)
                    if !check.recommendation.isEmpty {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "lightbulb.fill")
                                .foregroundStyle(.yellow)
                            Text(check.recommendation)
                                .font(.callout)
                        }
                        .padding(8)
                        .background(.yellow.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                    HStack(spacing: 12) {
                        if let remediation = Remediation.catalog[check.id] {
                            Button {
                                confirmingFix = check
                            } label: {
                                Label(remediation.label, systemImage: remediation.requiresSudo ? "lock.shield" : "wrench.fill")
                                    .font(.callout)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.blue)
                            .disabled(remediator.isRunning)
                        }
                        if let url = check.settingsURL {
                            Button {
                                NSWorkspace.shared.open(url)
                            } label: {
                                Label("Open in System Settings", systemImage: "gear")
                                    .font(.callout)
                            }
                        }
                    }
                }
                .padding(.top, 8)
            }
        }
        .padding()
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private func snoozeMenu(for check: SecurityCheck, isSnoozed: Bool) -> some View {
        Menu {
            if isSnoozed {
                Button("Unsnooze") { store.unsnooze(check.id) }
            } else {
                ForEach(SnoozeDuration.allCases) { duration in
                    Button("Snooze for \(duration.rawValue)") {
                        store.snooze(check.id, for: duration)
                    }
                }
            }
        } label: {
            Image(systemName: isSnoozed ? "bell.slash.fill" : "bell.slash")
                .foregroundStyle(isSnoozed ? .orange : .secondary)
        }
        .menuStyle(.borderlessButton)
        .frame(width: 30)
    }

    private func severityIcon(_ severity: CheckSeverity) -> some View {
        Image(systemName: severity == .critical || severity == .high
              ? "exclamationmark.circle.fill"
              : "exclamationmark.triangle.fill")
            .foregroundStyle(severityColor(severity))
            .font(.title2)
    }

    private func severityColor(_ severity: CheckSeverity) -> Color {
        switch severity {
        case .critical: .red
        case .high: .orange
        case .medium: .yellow
        case .low: .blue
        case .info: .secondary
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(.green)
            Text("All Clear")
                .font(.title2)
                .fontWeight(.bold)
            Text("No action items to address. Your Mac is looking good!")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding()
    }
}
