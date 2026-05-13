import SwiftUI

struct SettingsView: View {
    @AppStorage("scanOnLaunch") private var scanOnLaunch = true
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false

    var body: some View {
        Form {
            Section("Scanning") {
                Toggle("Scan automatically when Harden launches", isOn: $scanOnLaunch)
            }

            Section("Data") {
                Button("Reset Onboarding") {
                    hasCompletedOnboarding = false
                }
                .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 400, height: 200)
    }
}
