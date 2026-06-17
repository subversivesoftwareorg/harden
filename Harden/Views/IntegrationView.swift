import SwiftUI

struct IntegrationView: View {
    @Environment(SecurityStore.self) private var store

    @AppStorage("integrationServerURL") private var serverURL = ""
    @AppStorage("integrationAccountID") private var accountID = ""
    @AppStorage("integrationAutoReport") private var autoReport = false

    @State private var secretKey = ""
    @State private var testStatus: TestStatus?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                Divider()
                configSection
                Divider()
                statusSection
                Spacer()
            }
            .padding()
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Fleet Integration", systemImage: "server.rack")
                .font(.title2)
                .fontWeight(.bold)
            Text("Connect Harden to your organization's compliance server to automatically report security posture across your fleet.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Config

    private var configSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Server Configuration")
                .font(.headline)

            VStack(alignment: .leading, spacing: 12) {
                configField(
                    label: "Server URL",
                    placeholder: "https://compliance.yourcompany.com/api/v1/report",
                    text: $serverURL,
                    icon: "link"
                )

                configField(
                    label: "Account ID",
                    placeholder: "org-abc123",
                    text: $accountID,
                    icon: "person.badge.key"
                )

                VStack(alignment: .leading, spacing: 4) {
                    Label("Secret Key", systemImage: "key")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    SecureField("sk-...", text: $secretKey)
                        .textFieldStyle(.roundedBorder)
                }

                Toggle("Automatically report after each scan", isOn: $autoReport)
                    .disabled(!isConfigured)
            }

            HStack(spacing: 12) {
                Button {
                    testConnection()
                } label: {
                    Label("Test Connection", systemImage: "antenna.radiowaves.left.and.right")
                }
                .disabled(!isConfigured)

                Button {
                    sendReport()
                } label: {
                    Label("Send Report Now", systemImage: "paperplane")
                }
                .disabled(!isConfigured || store.checks.isEmpty)
            }
        }
    }

    private func configField(label: String, placeholder: String, text: Binding<String>, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(label, systemImage: icon)
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    private var isConfigured: Bool {
        !serverURL.isEmpty && !accountID.isEmpty && !secretKey.isEmpty
    }

    // MARK: - Status

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Status")
                .font(.headline)

            if let status = testStatus {
                HStack(spacing: 8) {
                    Image(systemName: status.icon)
                        .foregroundStyle(status.color)
                    Text(status.message)
                        .font(.body)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(status.color.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            } else {
                HStack(spacing: 8) {
                    Image(systemName: "circle.dotted")
                        .foregroundStyle(.secondary)
                    Text("Not connected. Configure your server details above to enable fleet reporting.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.regularMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            comingSoonNote
        }
    }

    private var comingSoonNote: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Coming Soon", systemImage: "sparkles")
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundStyle(.blue)

            Text("""
            Fleet integration will allow organizations to:

            \u{2022} Aggregate security posture across all managed Macs
            \u{2022} Track compliance trends over time per device
            \u{2022} Set policy baselines (STIG, CIS Level 1/2) and alert on drift
            \u{2022} Identify devices that need attention — without MDM
            \u{2022} Export fleet-wide compliance reports for auditors
            """)
            .font(.caption)
            .foregroundStyle(.secondary)

            Text("Interested in fleet reporting? Contact us at fleet@subversivesoftware.org")
                .font(.caption)
                .foregroundStyle(.blue)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.blue.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Actions (placeholder)

    private func testConnection() {
        testStatus = TestStatus(
            icon: "info.circle.fill",
            color: .orange,
            message: "Fleet integration is not yet available. This feature is coming soon."
        )
    }

    private func sendReport() {
        testStatus = TestStatus(
            icon: "info.circle.fill",
            color: .orange,
            message: "Fleet integration is not yet available. Reports can be exported locally via the Compliance tab."
        )
    }

    struct TestStatus {
        let icon: String
        let color: Color
        let message: String
    }
}
