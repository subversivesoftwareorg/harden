import SwiftUI
import Sparkle

@main
enum AppEntry {
    static func main() {
        if CommandLine.arguments.contains("--agent") {
            AgentMode.run()
        } else {
            HardenApp.main()
        }
    }
}

struct HardenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @State private var showHelp = false
    private let updaterController = SPUStandardUpdaterController(
        startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil
    )

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

            CommandGroup(after: .appInfo) {
                CheckForUpdatesView(updater: updaterController.updater)
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
