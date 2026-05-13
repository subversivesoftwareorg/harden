import Foundation

struct PrivacyChecker {

    func runChecks() async -> [SecurityCheck] {
        async let analyticsCheck = checkCrashAnalytics()
        async let safariSearchCheck = checkSafariSearchSuggestions()
        async let siriCheck = checkSiriEnabled()
        async let lockdownCheck = checkLockdownMode()
        async let tccCheck = checkTCCPermissions()
        return await [analyticsCheck, safariSearchCheck, siriCheck, lockdownCheck, tccCheck]
    }

    private func checkCrashAnalytics() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.analytics",
            name: "Crash & Usage Analytics",
            description: "macOS can send diagnostic and usage data to Apple and app developers.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run(
            "defaults read '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit 2>/dev/null"
        )
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Diagnostic data sharing is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Diagnostic and usage data is being shared with Apple."
            check.recommendation = "Open System Settings > Privacy & Security > Analytics & Improvements and disable sharing."
        } else {
            check.status = .info
            check.details = "Could not determine analytics sharing status. Check System Settings > Privacy & Security > Analytics & Improvements."
        }
        return check
    }

    private func checkSiriEnabled() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.siri",
            name: "Siri",
            description: "Siri sends voice and text data to Apple servers for processing. Disabling it reduces data shared with Apple.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.assistant.support 'Assistant Enabled' 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Siri is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "Siri is enabled. Voice and text queries are processed by Apple."
            check.recommendation = "If you don't use Siri, disable it in System Settings > Siri & Spotlight."
        } else {
            check.status = .info
            check.details = "Could not determine Siri status."
        }
        return check
    }

    private func checkSafariSearchSuggestions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.safari.suggestions",
            name: "Safari Search Suggestions",
            description: "Safari sends search queries to Apple for suggestions, which may expose browsing intent.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.Safari SuppressSearchSuggestions 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Safari search suggestions are suppressed."
        } else {
            check.status = .info
            check.details = "Safari search suggestions may be enabled. This sends partial queries to Apple as you type."
            check.recommendation = "In Safari > Settings > Search, disable 'Include search engine suggestions'."
        }
        return check
    }

    private func checkLockdownMode() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.lockdown",
            name: "Lockdown Mode",
            description: "Lockdown Mode is an extreme, optional protection for users who may be targeted by sophisticated attacks. It limits certain features to reduce attack surface.",
            category: .privacy,
            severity: .info
        )
        // Check user-level setting
        let userResult = await ShellCommand.run("defaults read .GlobalPreferences LDMGlobalEnabled 2>/dev/null")
        // Check managed/system-level
        let managedResult = await ShellCommand.run(
            "defaults read '/Library/Managed Preferences/.GlobalPreferences' LDMGlobalEnabled 2>/dev/null"
        )
        if userResult.output == "1" || managedResult.output == "1" {
            check.status = .pass
            check.details = "Lockdown Mode is enabled."
        } else {
            // Check if macOS version supports it (13.0+)
            let versionResult = await ShellCommand.run("sw_vers -productVersion")
            let components = versionResult.output.split(separator: ".").compactMap { Int($0) }
            if let major = components.first, major >= 13 {
                check.status = .info
                check.details = "Lockdown Mode is available but not enabled. This is appropriate for most users."
                check.recommendation = "If you face sophisticated threats, enable it in System Settings > Privacy & Security > Lockdown Mode. This limits some functionality."
            } else {
                check.status = .info
                check.details = "Lockdown Mode is not available on this macOS version (requires Ventura 13.0 or later)."
            }
        }
        return check
    }

    private func checkTCCPermissions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.tcc",
            name: "Sensitive Permission Grants",
            description: "macOS tracks which apps have been granted access to your camera, microphone, screen recording, and full disk access.",
            category: .privacy,
            severity: .medium
        )
        // Query system TCC database for granted permissions on sensitive services
        let services = ["kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceScreenCapture", "kTCCServiceSystemPolicyAllFiles"]
        let friendlyNames = ["Camera", "Microphone", "Screen Recording", "Full Disk Access"]
        var grants: [String] = []
        for (i, service) in services.enumerated() {
            let result = await ShellCommand.run(
                "sqlite3 '/Library/Application Support/com.apple.TCC/TCC.db' \"SELECT client FROM access WHERE service='\(service)' AND auth_value=2\" 2>/dev/null"
            )
            if !result.output.isEmpty {
                let apps = result.output.components(separatedBy: "\n").filter { !$0.isEmpty }
                if !apps.isEmpty {
                    grants.append("\(friendlyNames[i]): \(apps.count) app\(apps.count == 1 ? "" : "s")")
                }
            }
        }
        // Also check user-level TCC
        let userResult = await ShellCommand.run(
            "sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db \"SELECT service, COUNT(*) FROM access WHERE auth_value=2 GROUP BY service\" 2>/dev/null"
        )
        if grants.isEmpty && userResult.output.isEmpty {
            check.status = .pass
            check.details = "No unusual system-level permission grants detected."
        } else if grants.isEmpty {
            check.status = .info
            check.details = "Could not read system TCC database (this is normal without Full Disk Access). Review permissions in System Settings > Privacy & Security."
        } else {
            check.status = .info
            check.details = "System-level grants: \(grants.joined(separator: "; "))."
            check.recommendation = "Review these in System Settings > Privacy & Security and revoke access for apps you no longer use or trust."
        }
        return check
    }
}
