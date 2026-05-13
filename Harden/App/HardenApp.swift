import SwiftUI

@main
struct HardenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @State private var showHelp = false

    var body: some Scene {
        WindowGroup {
            MainTabView()
                .sheet(isPresented: $showHelp) { HelpView() }
        }
        .defaultSize(width: 900, height: 650)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Harden") {
                    appDelegate.showAboutPanel(nil)
                }
            }

            CommandGroup(replacing: .help) {
                Button("Harden Security Guide") {
                    showHelp = true
                }
            }
        }

        Settings {
            SettingsView()
        }
    }
}
