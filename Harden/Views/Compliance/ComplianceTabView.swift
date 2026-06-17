import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ComplianceTabView: View {
    @Environment(SecurityStore.self) private var store
    @State private var selectedFramework = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Framework", selection: $selectedFramework) {
                    Text("DISA STIG").tag(0)
                    Text("CIS Benchmark").tag(1)
                }
                .pickerStyle(.segmented)
                .frame(width: 250)

                Spacer()

                Menu {
                    Button("Export JSON Report") { exportReport(format: .json) }
                    Button("Export HTML Report") { exportReport(format: .html) }
                    Button("Export CSV Report") { exportReport(format: .csv) }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .disabled(store.checks.isEmpty)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            if selectedFramework == 0 {
                STIGReportView()
            } else {
                CISReportView()
            }
        }
    }

    private func exportReport(format: ReportFormat) {
        let data: Data?
        let contentType: UTType
        let fileExtension: String

        switch format {
        case .json:
            data = store.exportJSON()
            contentType = .json
            fileExtension = "json"
        case .html:
            data = ComplianceReportGenerator.generateHTML(
                checks: store.checks,
                score: store.score,
                scanDate: store.lastScanDate ?? Date(),
                device: store.device
            )
            contentType = .html
            fileExtension = "html"
        case .csv:
            data = ComplianceReportGenerator.generateCSV(
                checks: store.checks,
                device: store.device
            )
            contentType = .commaSeparatedText
            fileExtension = "csv"
        }

        guard let data else { return }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [contentType]
        panel.nameFieldStringValue = "harden-compliance-\(Date().formatted(.iso8601.year().month().day())).\(fileExtension)"
        panel.begin { response in
            if response == .OK, let url = panel.url {
                try? data.write(to: url)
            }
        }
    }

    enum ReportFormat {
        case json, html, csv
    }
}
