import Foundation

struct ApplicationsChecker {

    func runChecks() async -> [SecurityCheck] {
        let safari = SafariSettings.load()
        async let safariAutoOpen = checkSafariAutoOpen(safari)
        async let safariFraud = checkSafariFraudWarning(safari)
        async let safariCrossSite = checkSafariCrossSiteTracking(safari)
        async let safariAdPrivacy = checkSafariAdPrivacy(safari)
        async let safariFullURL = checkSafariFullURL(safari)
        async let safariStatusBar = checkSafariStatusBar(safari)
        async let terminalSecure = checkTerminalSecureKeyboard()
        async let fileExtensions = checkFileExtensions()
        return await [
            safariAutoOpen, safariFraud, safariCrossSite, safariAdPrivacy,
            safariFullURL, safariStatusBar, terminalSecure, fileExtensions,
        ]
    }

    /// Safari is sandboxed, so its settings live in its container rather than the
    /// `com.apple.Safari` domain that `defaults read` sees. Reading the container
    /// needs Full Disk Access.
    private enum SafariSettings {
        case loaded([String: Int])
        case unreadable

        static func load() -> SafariSettings {
            let url = FileManager.default.homeDirectoryForCurrentUser
                .appending(path: "Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist")
            do {
                let data = try Data(contentsOf: url)
                let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] ?? [:]
                return .loaded(plist.compactMapValues { ($0 as? NSNumber)?.intValue })
            } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
                // Safari has never saved a setting, so everything is at its default.
                return .loaded([:])
            } catch {
                return .unreadable
            }
        }

        var isReadable: Bool {
            if case .loaded = self { return true }
            return false
        }

        /// The setting's value (Booleans read as 0 or 1), or nil when Safari uses its default.
        func value(_ key: String) -> Int? {
            guard case .loaded(let settings) = self else { return nil }
            return settings[key]
        }
    }

    private func safariUnreadable(_ check: SecurityCheck) -> SecurityCheck {
        var check = check
        check.status = .unknown
        check.details = "Harden needs Full Disk Access to read Safari's settings."
        check.recommendation = "Open System Settings > Privacy & Security > Full Disk Access, turn on Harden, then scan again."
        return check
    }

    private func checkSafariAutoOpen(_ safari: SafariSettings) async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.autoopen",
            name: "Safari Auto-Open Downloads",
            description: "Safari can automatically open files after downloading, which could execute malicious content without user review.",
            category: .applications,
            severity: .medium
        )
        guard safari.isReadable else { return safariUnreadable(check) }
        let value = safari.value("AutoOpenSafeDownloads")
        if value == 0 {
            check.status = .pass
            check.details = "Safari does not auto-open downloaded files."
        } else if value == 1 {
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

    private func checkSafariFraudWarning(_ safari: SafariSettings) async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.fraudwarning",
            name: "Safari Fraudulent Site Warning",
            description: "Safari can warn you when visiting websites known for phishing or fraud.",
            category: .applications,
            severity: .medium
        )
        guard safari.isReadable else { return safariUnreadable(check) }
        let value = safari.value("WarnAboutFraudulentWebsites")
        if value == 1 {
            check.status = .pass
            check.details = "Safari warns about fraudulent websites."
        } else if value == 0 {
            check.status = .fail
            check.details = "Safari fraudulent website warnings are disabled."
            check.recommendation = "In Safari > Settings > Security, enable 'Warn when visiting a fraudulent website'."
        } else {
            check.status = .pass
            check.details = "Safari fraudulent website warnings use the default (enabled)."
        }
        return check
    }

    private func checkSafariCrossSiteTracking(_ safari: SafariSettings) async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.crosssite",
            name: "Safari Cross-Site Tracking Prevention",
            description: "Safari can block advertisers and other third parties from tracking you across websites.",
            category: .applications,
            severity: .medium
        )
        guard safari.isReadable else { return safariUnreadable(check) }
        if safari.value("BlockStoragePolicy") == 2 || safari.value("WebKitPreferences.storageBlockingPolicy") == 1 {
            check.status = .pass
            check.details = "Safari prevents cross-site tracking."
        } else {
            check.status = .pass
            check.details = "Safari cross-site tracking prevention uses the default (enabled on modern macOS)."
        }
        return check
    }

    private func checkSafariAdPrivacy(_ safari: SafariSettings) async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.adprivacy",
            name: "Safari Advertising Privacy",
            description: "Safari can use privacy-preserving ad measurement instead of allowing full advertiser tracking.",
            category: .applications,
            severity: .low
        )
        guard safari.isReadable else { return safariUnreadable(check) }
        let value = safari.value("WebKitPreferences.privateClickMeasurementEnabled")
        if value == 1 {
            check.status = .pass
            check.details = "Privacy-preserving ad measurement is enabled."
        } else if value == 0 {
            check.status = .info
            check.details = "Privacy-preserving ad measurement is disabled."
            check.recommendation = "In Safari > Settings > Privacy, enable 'Allow privacy-preserving measurement of ad effectiveness'."
        } else {
            check.status = .pass
            check.details = "Safari advertising privacy uses the default (enabled)."
        }
        return check
    }

    private func checkSafariFullURL(_ safari: SafariSettings) async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.fullurl",
            name: "Safari Full Website Address",
            description: "Showing the full URL in Safari helps identify phishing sites that use deceptive subdomains.",
            category: .applications,
            severity: .low
        )
        guard safari.isReadable else { return safariUnreadable(check) }
        if safari.value("ShowFullURLInSmartSearchField") == 1 {
            check.status = .pass
            check.details = "Safari shows the full website address."
        } else {
            check.status = .info
            check.details = "Safari shows a simplified URL. The full address helps spot phishing domains."
            check.recommendation = "In Safari > Settings > Advanced, enable 'Show full website address'."
        }
        return check
    }

    private func checkSafariStatusBar(_ safari: SafariSettings) async -> SecurityCheck {
        var check = SecurityCheck(
            id: "apps.safari.statusbar",
            name: "Safari Status Bar",
            description: "The Safari status bar shows link destinations before you click, helping identify malicious URLs.",
            category: .applications,
            severity: .low
        )
        guard safari.isReadable else { return safariUnreadable(check) }
        if safari.value("ShowOverlayStatusBar") == 1 {
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
