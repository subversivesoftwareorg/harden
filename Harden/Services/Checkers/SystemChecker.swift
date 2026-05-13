import Foundation

struct SystemChecker {

    func runChecks() async -> [SecurityCheck] {
        async let sipCheck = checkSIP()
        async let gatekeeperCheck = checkGatekeeper()
        async let autoUpdateCheck = checkAutoUpdates()
        async let autoDownloadCheck = checkAutoDownload()
        async let autoInstallCheck = checkAutoInstallUpdates()
        async let criticalUpdateCheck = checkCriticalUpdates()
        async let configDataCheck = checkConfigDataInstall()
        async let appStoreUpdateCheck = checkAppStoreAutoUpdates()
        async let versionCheck = checkMacOSVersion()
        async let findMyCheck = checkFindMyMac()
        async let extensionsCheck = checkSystemExtensions()
        async let uptimeCheck = checkSystemUptime()
        async let ntpCheck = checkNTPSync()
        async let malwareCheck = checkMalwareScanner()
        async let xprotectCheck = checkXProtect()
        async let secureBootCheck = checkSecureBoot()
        async let rsrCheck = checkRapidSecurityResponse()
        return await [
            sipCheck, gatekeeperCheck, autoUpdateCheck, autoDownloadCheck, autoInstallCheck,
            criticalUpdateCheck, configDataCheck, appStoreUpdateCheck, versionCheck, findMyCheck,
            extensionsCheck, uptimeCheck, ntpCheck, malwareCheck,
            xprotectCheck, secureBootCheck, rsrCheck,
        ]
    }

    private func checkSIP() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.sip",
            name: "System Integrity Protection",
            description: "SIP protects critical system files and directories from being modified, even by the root user.",
            category: .systemProtection,
            severity: .critical
        )
        let result = await ShellCommand.run("csrutil status")
        if result.output.contains("enabled") {
            check.status = .pass
            check.details = "System Integrity Protection is enabled."
        } else if result.output.contains("disabled") {
            check.status = .fail
            check.details = "System Integrity Protection is disabled."
            check.recommendation = "Restart into Recovery Mode (hold Command+R) and run 'csrutil enable' in Terminal."
        } else {
            check.status = .unknown
            check.details = "Could not determine SIP status."
        }
        return check
    }

    private func checkGatekeeper() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.gatekeeper",
            name: "Gatekeeper",
            description: "Gatekeeper ensures only trusted software runs on your Mac by verifying apps are signed and notarized.",
            category: .systemProtection,
            severity: .high
        )
        let result = await ShellCommand.run("spctl --status")
        if result.output.contains("enabled") || result.output.contains("assessments enabled") {
            check.status = .pass
            check.details = "Gatekeeper is enabled."
        } else if result.output.contains("disabled") {
            check.status = .fail
            check.details = "Gatekeeper is disabled. Unverified apps can run without warning."
            check.recommendation = "Open System Settings > Privacy & Security and set 'Allow apps from' to 'App Store and identified developers'."
        } else {
            check.status = .unknown
            check.details = "Could not determine Gatekeeper status."
        }
        return check
    }

    private func checkAutoUpdates() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.autoupdate.check",
            name: "Automatic Update Checks",
            description: "Your Mac can automatically check for available software updates.",
            category: .systemProtection,
            severity: .high
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled")
        if result.output == "1" {
            check.status = .pass
            check.details = "Automatic update checking is enabled."
        } else if result.output == "0" {
            check.status = .fail
            check.details = "Automatic update checking is disabled."
            check.recommendation = "Open System Settings > General > Software Update and enable automatic checks."
        } else {
            check.status = .pass
            check.details = "Automatic update checking appears to be using the default (enabled)."
        }
        return check
    }

    private func checkAutoDownload() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.autoupdate.download",
            name: "Automatic Update Downloads",
            description: "Your Mac can automatically download updates in the background so they're ready to install.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload")
        if result.output == "1" {
            check.status = .pass
            check.details = "Automatic update downloads are enabled."
        } else if result.output == "0" {
            check.status = .warning
            check.details = "Automatic update downloads are disabled."
            check.recommendation = "Open System Settings > General > Software Update > Automatic Updates and enable 'Download new updates when available'."
        } else {
            check.status = .pass
            check.details = "Automatic update downloads appear to be using the default (enabled)."
        }
        return check
    }

    private func checkCriticalUpdates() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.autoupdate.critical",
            name: "Automatic Security Updates",
            description: "Critical security patches and XProtect data can be installed automatically without waiting for a full macOS update.",
            category: .systemProtection,
            severity: .high
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null")
        if result.output == "1" {
            check.status = .pass
            check.details = "Automatic security updates are enabled."
        } else if result.output == "0" {
            check.status = .fail
            check.details = "Automatic security updates are disabled."
            check.recommendation = "Open System Settings > General > Software Update > Automatic Updates and enable 'Install Security Responses and system files'."
        } else {
            check.status = .pass
            check.details = "Automatic security updates appear to be using the default (enabled)."
        }
        return check
    }

    private func checkConfigDataInstall() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.autoupdate.configdata",
            name: "Automatic Config Data Updates",
            description: "System data files including XProtect malware definitions are kept up to date automatically.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null")
        if result.output == "1" {
            check.status = .pass
            check.details = "Automatic config data installation is enabled."
        } else if result.output == "0" {
            check.status = .warning
            check.details = "Automatic config data installation is disabled."
            check.recommendation = "Open System Settings > General > Software Update > Automatic Updates and enable 'Install Security Responses and system files'."
        } else {
            check.status = .pass
            check.details = "Config data installation appears to be using the default (enabled)."
        }
        return check
    }

    private func checkAppStoreAutoUpdates() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.autoupdate.appstore",
            name: "App Store Auto-Updates",
            description: "Apps installed from the App Store can be updated automatically to get the latest security fixes.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null")
        if result.output == "1" {
            check.status = .pass
            check.details = "App Store auto-updates are enabled."
        } else if result.output == "0" {
            check.status = .warning
            check.details = "App Store auto-updates are disabled."
            check.recommendation = "Open System Settings > General > Software Update > Automatic Updates and enable 'Install app updates from the App Store'."
        } else {
            check.status = .pass
            check.details = "App Store auto-updates appear to be using the default (enabled)."
        }
        return check
    }

    private func checkMacOSVersion() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.osversion",
            name: "macOS Version",
            description: "Running the latest macOS version ensures you have the newest security patches and features.",
            category: .systemProtection,
            severity: .high
        )
        let result = await ShellCommand.run("sw_vers -productVersion")
        let version = result.output
        let components = version.split(separator: ".").compactMap { Int($0) }
        guard components.count >= 2 else {
            check.status = .unknown
            check.details = "Could not determine macOS version."
            return check
        }
        let major = components[0]
        // As of mid-2026, macOS 26 (Tahoe) is current, 15 (Sequoia) is previous
        // We check against major version to flag significantly outdated systems
        check.details = "Running macOS \(version)."
        if major >= 26 {
            check.status = .pass
        } else if major >= 15 {
            check.status = .warning
            check.details = "Running macOS \(version). A newer major version is available."
            check.recommendation = "Open System Settings > General > Software Update to check for the latest macOS version."
        } else {
            check.status = .fail
            check.details = "Running macOS \(version). This version is significantly outdated and may no longer receive security updates."
            check.recommendation = "Open System Settings > General > Software Update and upgrade to the latest macOS."
        }
        return check
    }

    private func checkFindMyMac() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.findmymac",
            name: "Find My Mac",
            description: "Find My Mac helps you locate, lock, or erase your Mac remotely if it's lost or stolen.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("nvram -p 2>/dev/null | grep -c fmm-mobileme-token-FMM")
        let count = Int(result.output) ?? 0
        if count > 0 {
            check.status = .pass
            check.details = "Find My Mac appears to be enabled."
        } else {
            check.status = .warning
            check.details = "Find My Mac does not appear to be enabled."
            check.recommendation = "Open System Settings > [your name] > iCloud > Find My Mac and turn it on."
        }
        return check
    }

    private func checkAutoInstallUpdates() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.autoupdate.install",
            name: "Automatic macOS Updates",
            description: "Your Mac can automatically install macOS updates to keep your system protected.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates")
        if result.output == "1" {
            check.status = .pass
            check.details = "Automatic macOS updates are enabled."
        } else if result.output == "0" {
            check.status = .warning
            check.details = "Automatic macOS updates are disabled."
            check.recommendation = "Open System Settings > General > Software Update > Automatic Updates and enable 'Install macOS updates'."
        } else {
            check.status = .info
            check.details = "Automatic macOS update installation uses the system default."
        }
        return check
    }

    private func checkSystemExtensions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.extensions",
            name: "Third-Party System Extensions",
            description: "Third-party kernel extensions or system extensions can introduce instability and security risks.",
            category: .systemProtection,
            severity: .medium
        )
        // Check modern system extensions
        let sysext = await ShellCommand.run("systemextensionsctl list 2>/dev/null | grep -v '^---' | grep -v '^$' | grep -cv 'com.apple'")
        let sysextCount = Int(sysext.output) ?? 0
        // Check legacy kexts
        let kext = await ShellCommand.run("kextstat 2>/dev/null | grep -cv com.apple")
        let kextCount = max((Int(kext.output) ?? 1) - 1, 0)  // subtract header line
        let total = sysextCount + kextCount
        if total == 0 {
            check.status = .pass
            check.details = "No third-party kernel or system extensions loaded."
        } else {
            check.status = .info
            check.details = "\(total) third-party extension\(total == 1 ? "" : "s") loaded. Review these to ensure they are from trusted vendors."
            check.recommendation = "Run 'systemextensionsctl list' and 'kextstat | grep -v com.apple' in Terminal to see which extensions are loaded."
        }
        return check
    }

    private func checkSystemUptime() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.uptime",
            name: "System Uptime",
            description: "Long uptime means your Mac hasn't been restarted to apply kernel-level security patches.",
            category: .systemProtection,
            severity: .low
        )
        let result = await ShellCommand.run("sysctl -n kern.boottime 2>/dev/null")
        // Output format: { sec = 1234567890, usec = 0 } ...
        if let secRange = result.output.range(of: "sec = "),
           let commaRange = result.output.range(of: ",", range: secRange.upperBound..<result.output.endIndex),
           let bootEpoch = Double(result.output[secRange.upperBound..<commaRange.lowerBound].trimmingCharacters(in: .whitespaces)) {
            let uptimeDays = Int(Date().timeIntervalSince1970 - bootEpoch) / 86400
            if uptimeDays <= 14 {
                check.status = .pass
                check.details = "System was last restarted \(uptimeDays) day\(uptimeDays == 1 ? "" : "s") ago."
            } else if uptimeDays <= 30 {
                check.status = .warning
                check.details = "System has been running for \(uptimeDays) days without a restart."
                check.recommendation = "Restart your Mac periodically to apply kernel-level security updates. Go to Apple menu > Restart."
            } else {
                check.status = .fail
                check.details = "System has been running for \(uptimeDays) days. Security patches requiring a restart have not been applied."
                check.recommendation = "Restart your Mac now to apply pending security updates. Go to Apple menu > Restart."
            }
        } else {
            check.status = .unknown
            check.details = "Could not determine system uptime."
        }
        return check
    }

    private func checkNTPSync() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.ntp",
            name: "Network Time Synchronization",
            description: "Accurate system time is essential for certificate validation, Kerberos authentication, and log accuracy.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("systemsetup -getusingnetworktime 2>/dev/null")
        if result.output.lowercased().contains("on") {
            check.status = .pass
            check.details = "Network time synchronization is enabled."
        } else if result.output.lowercased().contains("off") {
            check.status = .warning
            check.details = "Network time synchronization is disabled."
            check.recommendation = "Open System Settings > General > Date & Time and enable 'Set time and date automatically'."
        } else {
            check.status = .info
            check.details = "Could not determine NTP status. Check System Settings > General > Date & Time."
        }
        return check
    }

    private func checkMalwareScanner() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.malware",
            name: "Malware Scanner",
            description: "A dedicated malware scanner provides an additional layer of protection beyond macOS's built-in XProtect.",
            category: .systemProtection,
            severity: .info
        )
        let knownScanners: [(name: String, process: String)] = [
            ("CrowdStrike Falcon", "falcond"),
            ("SentinelOne", "sentineld"),
            ("Sophos", "SophosScanD"),
            ("Microsoft Defender", "mdatp"),
            ("ClamXav", "ClamXav"),
            ("Malwarebytes", "Malwarebytes"),
            ("Norton", "Norton"),
            ("Kaspersky", "kav"),
        ]
        let result = await ShellCommand.run("ps -eo comm= 2>/dev/null")
        var found: [String] = []
        for scanner in knownScanners {
            if result.output.contains(scanner.process) {
                found.append(scanner.name)
            }
        }
        if !found.isEmpty {
            check.status = .pass
            check.details = "Malware scanner detected: \(found.joined(separator: ", "))."
        } else {
            check.status = .info
            check.details = "No third-party malware scanner detected. macOS includes built-in XProtect and MRT."
        }
        return check
    }

    private func checkXProtect() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.xprotect",
            name: "XProtect Malware Definitions",
            description: "XProtect is macOS's built-in malware detection. Its definitions should be recent to protect against new threats.",
            category: .systemProtection,
            severity: .high
        )
        // Check XProtect bundle version
        let versionResult = await ShellCommand.run(
            "/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist 2>/dev/null"
        )
        // Check when XProtect was last updated
        let dateResult = await ShellCommand.run(
            "stat -f '%m' /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist 2>/dev/null"
        )
        if let epoch = Double(dateResult.output) {
            let lastUpdate = Date(timeIntervalSince1970: epoch)
            let daysSince = Int(Date().timeIntervalSince(lastUpdate)) / 86400
            let versionStr = versionResult.output.isEmpty ? "" : " (version \(versionResult.output))"
            if daysSince <= 30 {
                check.status = .pass
                check.details = "XProtect definitions\(versionStr) were updated \(daysSince) day\(daysSince == 1 ? "" : "s") ago."
            } else if daysSince <= 90 {
                check.status = .warning
                check.details = "XProtect definitions\(versionStr) were last updated \(daysSince) days ago."
                check.recommendation = "Ensure automatic security updates are enabled in System Settings > General > Software Update > Automatic Updates."
            } else {
                check.status = .fail
                check.details = "XProtect definitions\(versionStr) are \(daysSince) days old — significantly outdated."
                check.recommendation = "Run 'sudo softwareupdate --background' in Terminal to force an update, or check System Settings > General > Software Update."
            }
        } else if !versionResult.output.isEmpty {
            check.status = .info
            check.details = "XProtect version \(versionResult.output) is installed, but could not determine update date."
        } else {
            check.status = .unknown
            check.details = "Could not determine XProtect status."
        }
        return check
    }

    private func checkSecureBoot() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.secureboot",
            name: "Startup Security",
            description: "Apple Silicon and T2 Macs support Secure Boot, which ensures only trusted operating system software loads at startup.",
            category: .systemProtection,
            severity: .high
        )
        // Check if this is Apple Silicon
        let archResult = await ShellCommand.run("uname -m")
        let isAppleSilicon = archResult.output.contains("arm64")

        if isAppleSilicon {
            // On Apple Silicon, check the boot policy
            let bootPolicy = await ShellCommand.run("bputil -d 2>/dev/null")
            if bootPolicy.output.lowercased().contains("full security") {
                check.status = .pass
                check.details = "Startup security is set to Full Security."
            } else if bootPolicy.output.lowercased().contains("reduced security") {
                check.status = .warning
                check.details = "Startup security is set to Reduced Security."
                check.recommendation = "Set to Full Security in Recovery Mode: restart holding power button, then Options > Startup Security Utility."
            } else if bootPolicy.output.lowercased().contains("permissive") {
                check.status = .fail
                check.details = "Startup security is set to Permissive Security — the least secure option."
                check.recommendation = "Set to Full Security in Recovery Mode: restart holding power button, then Options > Startup Security Utility."
            } else {
                // bputil may require admin or may not be available — fall back to csrutil
                let ssv = await ShellCommand.run("csrutil authenticated-root status 2>/dev/null")
                if ssv.output.lowercased().contains("enabled") {
                    check.status = .pass
                    check.details = "Authenticated root volume is enabled (Secure Boot active)."
                } else if ssv.output.lowercased().contains("disabled") {
                    check.status = .warning
                    check.details = "Authenticated root volume is disabled."
                    check.recommendation = "Re-enable in Recovery Mode for full startup security."
                } else {
                    check.status = .info
                    check.details = "Could not determine Secure Boot policy. This Mac appears to be Apple Silicon."
                }
            }
        } else {
            // Intel Mac — check for T2 chip
            let t2Result = await ShellCommand.run("system_profiler SPiBridgeDataType 2>/dev/null | grep -c 'T2'")
            let hasT2 = (Int(t2Result.output) ?? 0) > 0
            if hasT2 {
                check.status = .info
                check.details = "T2 chip detected. Startup security can be configured via Startup Security Utility in Recovery Mode."
            } else {
                check.status = .info
                check.details = "This Mac does not have Apple Silicon or a T2 chip. Hardware Secure Boot is not available."
            }
        }
        return check
    }

    private func checkRapidSecurityResponse() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.rsr",
            name: "Rapid Security Responses",
            description: "Rapid Security Responses deliver critical security fixes between regular macOS updates, without a restart.",
            category: .systemProtection,
            severity: .medium
        )
        // RSR is controlled by the same CriticalUpdateInstall pref, but let's also check if any have been applied
        let result = await ShellCommand.run("sw_vers -productVersion")
        let version = result.output
        // RSR versions have a letter suffix like "14.1.2 (a)"
        if version.contains("(") {
            check.status = .pass
            check.details = "Rapid Security Response applied — running macOS \(version)."
        } else {
            // Check if RSR is enabled
            let critResult = await ShellCommand.run("defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null")
            if critResult.output == "0" {
                check.status = .warning
                check.details = "Rapid Security Responses may be disabled."
                check.recommendation = "Open System Settings > General > Software Update > Automatic Updates and enable 'Install Security Responses and system files'."
            } else {
                check.status = .pass
                check.details = "Rapid Security Responses are enabled. Running macOS \(version)."
            }
        }
        return check
    }
}
