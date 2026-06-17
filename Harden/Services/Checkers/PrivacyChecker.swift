import Foundation

struct PrivacyChecker {

    func runChecks() async -> [SecurityCheck] {
        async let analyticsCheck = checkCrashAnalytics()
        async let safariSearchCheck = checkSafariSearchSuggestions()
        async let siriCheck = checkSiriEnabled()
        async let lockdownCheck = checkLockdownMode()
        async let tccCheck = checkTCCPermissions()
        async let externalAICheck = checkExternalAIExtensions()
        async let writingToolsCheck = checkWritingTools()
        async let mailSummaryCheck = checkMailSummary()
        async let notesTranscriptionCheck = checkNotesTranscription()
        async let dictationCheck = checkOnDeviceDictation()
        async let siriImproveCheck = checkSiriDictationSharing()
        async let assistiveVoiceCheck = checkAssistiveVoiceSharing()
        async let advertisingCheck = checkPersonalizedAdvertising()
        async let searchSharingCheck = checkSearchDataSharing()
        return await [analyticsCheck, safariSearchCheck, siriCheck, lockdownCheck, tccCheck,
                      externalAICheck, writingToolsCheck, mailSummaryCheck, notesTranscriptionCheck,
                      dictationCheck, siriImproveCheck, assistiveVoiceCheck, advertisingCheck,
                      searchSharingCheck]
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

    // MARK: - Apple Intelligence Checks

    private func checkExternalAIExtensions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.ai.external",
            name: "External AI Extensions",
            description: "External Intelligence/AI extensions can send data to third-party AI services.",
            category: .privacy,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.applicationaccess allowExternalIntelligenceIntegration 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "External AI extensions are disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "External AI extensions are allowed. Data may be sent to third-party AI services."
            check.recommendation = "Disable in System Settings > Apple Intelligence & Siri > External Intelligence Extensions."
        } else {
            check.status = .info
            check.details = "Could not determine external AI extension status. Setting may not be configured."
            check.recommendation = "Disable in System Settings > Apple Intelligence & Siri > External Intelligence Extensions."
        }
        return check
    }

    private func checkWritingTools() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.ai.writingtools",
            name: "Writing Tools",
            description: "Apple's AI writing tools process text content which may be sent to Apple servers.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.applicationaccess allowWritingTools 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Writing Tools are disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "Writing Tools are enabled. Text content may be processed by Apple servers."
            check.recommendation = "Disable in System Settings > Apple Intelligence & Siri > Writing Tools."
        } else {
            check.status = .info
            check.details = "Could not determine Writing Tools status. Setting may not be configured."
            check.recommendation = "Disable in System Settings > Apple Intelligence & Siri > Writing Tools."
        }
        return check
    }

    private func checkMailSummary() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.ai.mailsummary",
            name: "Mail Summary",
            description: "AI-generated email summaries may process sensitive email content.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.mail MailSummaryEnabled 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Mail AI summaries are disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "Mail AI summaries are enabled. Sensitive email content may be processed by AI."
        } else {
            check.status = .info
            check.details = "Could not determine Mail summary status. Setting may not be configured."
        }
        return check
    }

    private func checkNotesTranscription() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.ai.transcription",
            name: "Notes Transcription",
            description: "AI transcription in Notes may process spoken content.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.notes NotesTranscriptionEnabled 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Notes AI transcription is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "Notes AI transcription is enabled. Spoken content may be processed by AI."
        } else {
            check.status = .info
            check.details = "Could not determine Notes transcription status. Setting may not be configured."
        }
        return check
    }

    // MARK: - Telemetry & Privacy Checks

    private func checkOnDeviceDictation() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.dictation",
            name: "On-Device Dictation",
            description: "Dictation should process speech on-device rather than sending audio to Apple servers.",
            category: .privacy,
            severity: .low
        )
        let onDeviceResult = await ShellCommand.run(
            "defaults read com.apple.speech.recognition.AppleSpeechRecognition.prefs DictationIMUseOnDeviceRecognition 2>/dev/null"
        )
        let dictationResult = await ShellCommand.run(
            "defaults read com.apple.assistant.support 'Dictation Enabled' 2>/dev/null"
        )
        if dictationResult.output == "0" || dictationResult.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Dictation is disabled."
        } else if onDeviceResult.output == "1" || onDeviceResult.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Dictation is set to on-device processing."
        } else {
            check.status = .warning
            check.details = "Dictation may be sending audio to Apple servers for processing."
            check.recommendation = "Enable on-device dictation in System Settings > Keyboard > Dictation."
        }
        return check
    }

    private func checkSiriDictationSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.siri.improve",
            name: "Improve Siri & Dictation Sharing",
            description: "Apple can collect and review Siri audio to improve its services.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.assistant.support 'Siri Data Sharing Opt-In Status' 2>/dev/null")
        if result.output == "0" {
            check.status = .pass
            check.details = "Siri & Dictation data sharing is opted out."
        } else if result.output == "2" {
            check.status = .warning
            check.details = "Siri & Dictation audio may be shared with Apple for review and improvement."
            check.recommendation = "Opt out in System Settings > Privacy & Security > Analytics & Improvements > Improve Siri & Dictation."
        } else {
            check.status = .info
            check.details = "Could not determine Siri data sharing status."
        }
        return check
    }

    private func checkAssistiveVoiceSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.assistivevoice",
            name: "Assistive Voice Data Sharing",
            description: "Sharing voice data helps Apple improve assistive features but sends audio samples.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.assistant.support 'Assistive Voice Opt-In Status' 2>/dev/null")
        if result.output == "0" {
            check.status = .pass
            check.details = "Assistive voice data sharing is opted out."
        } else if result.output == "2" {
            check.status = .warning
            check.details = "Voice data is being shared with Apple to improve assistive features."
            check.recommendation = "Opt out in System Settings > Privacy & Security > Analytics & Improvements."
        } else {
            check.status = .info
            check.details = "Could not determine assistive voice data sharing status."
        }
        return check
    }

    private func checkPersonalizedAdvertising() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.advertising",
            name: "Personalized Advertising",
            description: "Apple can use your data to serve targeted ads in Apple apps.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.AdLib allowApplePersonalizedAdvertising 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Personalized advertising is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Personalized advertising is enabled. Apple may use your data to serve targeted ads."
            check.recommendation = "Disable in System Settings > Privacy & Security > Apple Advertising > Personalized Ads."
        } else {
            check.status = .info
            check.details = "Could not determine personalized advertising status."
        }
        return check
    }

    private func checkSearchDataSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "privacy.search.improve",
            name: "Search Data Sharing",
            description: "Spotlight and Safari search queries can be shared with Apple to improve suggestions.",
            category: .privacy,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.assistant.support 'Search Queries Data Sharing Status' 2>/dev/null")
        if result.output == "0" {
            check.status = .pass
            check.details = "Search data sharing is disabled."
        } else if result.output == "2" {
            check.status = .warning
            check.details = "Search queries are being shared with Apple to improve suggestions."
            check.recommendation = "Disable in System Settings > Privacy & Security > Analytics & Improvements."
        } else {
            check.status = .info
            check.details = "Could not determine search data sharing status."
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
