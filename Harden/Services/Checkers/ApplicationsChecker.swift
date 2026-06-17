import Foundation

struct ApplicationsChecker {

    func runChecks() async -> [SecurityCheck] {
        async let safariAutoOpen = checkSafariAutoOpen()
        async let safariFraud = checkSafariFraudWarning()
        async let safariCrossSite = checkSafariCrossSiteTracking()
        async let safariAdPrivacy = checkSafariAdPrivacy()
        async let safariFullURL = checkSafariFullURL()
        async let safariStatusBar = checkSafariStatusBar()
        async let terminalSecure = checkTerminalSecureKeyboard()
        async let fileExtensions = checkFileExtensions()
        return await [
            safariAutoOpen, safariFraud, safariCrossSite, safariAdPrivacy,
            safariFullURL, safariStatusBar, terminalSecure, fileExtensions,
        ]
    }

    private func checkSafariAutoOpen() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.autoopen",
            name: "Safari Auto-Open Downloads",
            description: "Safari can automatically open files after downloading, which could execute malicious content without user review.",
            category: .applications,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari AutoOpenSafeDownloads 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Safari does not auto-open downloaded files."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Safari automatically opens 'safe' files after downloading."
            check.recommendation = "In Safari > Settings > General, uncheck 'Open safe files after downloading'."
        } else {
            check.status = .warning
            check.details = "Safari auto-open uses the default (enabled). Check Safari > Settings > General."
            check.recommendation = "In Safari > Settings > General, uncheck 'Open safe files after downloading'."
        }
        return check
    }

    private func checkSafariFraudWarning() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.fraudwarning",
            name: "Safari Fraudulent Site Warning",
            description: "Safari can warn you when visiting websites known for phishing or fraud.",
            category: .applications,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari WarnAboutFraudulentWebsites 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Safari warns about fraudulent websites."
        } else if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .fail
            check.details = "Safari fraudulent website warnings are disabled."
            check.recommendation = "In Safari > Settings > Security, enable 'Warn when visiting a fraudulent website'."
        } else {
            check.status = .pass
            check.details = "Safari fraudulent website warnings use the default (enabled)."
        }
        return check
    }

    private func checkSafariCrossSiteTracking() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.crosssite",
            name: "Safari Cross-Site Tracking Prevention",
            description: "Safari can block advertisers and other third parties from tracking you across websites.",
            category: .applications,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari BlockStoragePolicy 2>/dev/null")
        if result.output == "2" {
            check.status = .pass
            check.details = "Safari prevents cross-site tracking."
        } else {
            let fallback = await ShellCommand.run("defaults read com.apple.Safari WebKitPreferences.storageBlockingPolicy 2>/dev/null")
            if fallback.output == "1" {
                check.status = .pass
                check.details = "Safari prevents cross-site tracking."
            } else {
                check.status = .pass
                check.details = "Safari cross-site tracking prevention uses the default (enabled on modern macOS)."
            }
        }
        return check
    }

    private func checkSafariAdPrivacy() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.adprivacy",
            name: "Safari Advertising Privacy",
            description: "Safari can use privacy-preserving ad measurement instead of allowing full advertiser tracking.",
            category: .applications,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari WebKitPreferences.privateClickMeasurementEnabled 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Privacy-preserving ad measurement is enabled."
        } else if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .info
            check.details = "Privacy-preserving ad measurement is disabled."
            check.recommendation = "In Safari > Settings > Privacy, enable 'Allow privacy-preserving measurement of ad effectiveness'."
        } else {
            check.status = .pass
            check.details = "Safari advertising privacy uses the default (enabled)."
        }
        return check
    }

    private func checkSafariFullURL() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.fullurl",
            name: "Safari Full Website Address",
            description: "Showing the full URL in Safari helps identify phishing sites that use deceptive subdomains.",
            category: .applications,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari ShowFullURLInSmartSearchField 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Safari shows the full website address."
        } else {
            check.status = .info
            check.details = "Safari shows a simplified URL. The full address helps spot phishing domains."
            check.recommendation = "In Safari > Settings > Advanced, enable 'Show full website address'."
        }
        return check
    }

    private func checkSafariStatusBar() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.statusbar",
            name: "Safari Status Bar",
            description: "The Safari status bar shows link destinations before you click, helping identify malicious URLs.",
            category: .applications,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari ShowOverlayStatusBar 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Safari status bar is shown."
        } else {
            check.status = .info
            check.details = "Safari status bar is hidden. It reveals link destinations on hover."
            check.recommendation = "In Safari, go to View > Show Status Bar (or press Cmd+/)."
        }
        return check
    }

    private func checkTerminalSecureKeyboard() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.terminal.securekeyboard",
            name: "Terminal Secure Keyboard Entry",
            description: "Secure Keyboard Entry in Terminal prevents other applications from intercepting keystrokes, protecting passwords entered in the terminal.",
            category: .applications,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.Terminal SecureKeyboardEntry 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Terminal Secure Keyboard Entry is enabled."
        } else {
            check.status = .warning
            check.details = "Terminal Secure Keyboard Entry is not enabled. Keystrokes may be interceptable."
            check.recommendation = "In Terminal > Settings > Profiles > Keyboard, enable 'Secure keyboard entry'. Or press Terminal > Secure Keyboard Entry in the menu bar."
        }
        return check
    }

    private func checkFileExtensions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.fileextensions",
            name: "Filename Extensions Visible",
            description: "Showing file extensions prevents disguised executables from appearing as harmless documents.",
            category: .applications,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read NSGlobalDomain AppleShowAllExtensions 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "All filename extensions are shown."
        } else {
            check.status = .warning
            check.details = "Filename extensions are hidden. A file named 'document.pdf.app' could appear as 'document.pdf'."
            check.recommendation = "Open Finder > Settings > Advanced and enable 'Show all filename extensions'."
        }
        return check
    }
}
