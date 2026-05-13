import AppKit

class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.applicationIconImage = makeHardenIcon(size: 512)
    }

    @objc func showAboutPanel(_ sender: Any?) {
        let creditsText = """
        Take control of your Mac's security.

        Harden reveals how well your Mac is configured against common threats \
        — checking your firewall, encryption, sharing services, and more. \
        Inspired by tools security professionals trust, designed for everyone.

        Subversive Software builds tools that put power back in people's hands.

        \u{00A9} 2026 subversivesoftware.org
        """

        let credits = NSAttributedString(
            string: creditsText,
            attributes: [
                .font: NSFont.systemFont(ofSize: 11),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
        )

        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"

        let icon = makeHardenIcon(size: 128)

        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "Harden",
            .applicationIcon: icon,
            .applicationVersion: version,
            .version: build,
            .credits: credits
        ])
    }
}
