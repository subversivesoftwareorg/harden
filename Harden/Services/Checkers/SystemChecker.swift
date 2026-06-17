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
        async let auditdCheck = checkAuditDaemon()
        async let auditFlagsCheck = checkAuditFlags()
        async let auditPermsCheck = checkAuditLogPermissions()
        async let amfiCheck = checkAMFI()
        async let worldWritableCheck = checkWorldWritableFolders()
        async let sudoTimeoutCheck = checkSudoTimeout()
        async let sudoLoggingCheck = checkSudoLogging()
        async let rootDisabledCheck = checkRootDisabled()
        return await [
            sipCheck, gatekeeperCheck, autoUpdateCheck, autoDownloadCheck, autoInstallCheck,
            criticalUpdateCheck, configDataCheck, appStoreUpdateCheck, versionCheck, findMyCheck,
            extensionsCheck, uptimeCheck, ntpCheck, malwareCheck,
            xprotectCheck, secureBootCheck, rsrCheck,
            auditdCheck, auditFlagsCheck, auditPermsCheck,
            amfiCheck, worldWritableCheck, sudoTimeoutCheck, sudoLoggingCheck, rootDisabledCheck,
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

    private func checkAuditDaemon() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.auditd",
            name: "Security Auditing",
            description: "The macOS audit daemon (auditd) logs security-relevant events such as logins, privilege escalations, and file access.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("launchctl list 2>/dev/null | grep -c com.apple.auditd")
        let running = (Int(result.output) ?? 0) > 0
        if running {
            check.status = .pass
            check.details = "Security auditing (auditd) is running."
        } else {
            check.status = .fail
            check.details = "Security auditing (auditd) is not running."
            check.recommendation = "Enable auditing with: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
        }
        return check
    }

    private func checkAuditFlags() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.auditflags",
            name: "Audit Control Flags",
            description: "The audit system should be configured to log key events: login/logout, administrative actions, file deletion, and file attribute modification.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("grep '^flags:' /etc/security/audit_control 2>/dev/null")
        if result.output.isEmpty || result.exitCode != 0 {
            check.status = .warning
            check.details = "Could not read audit configuration."
            check.recommendation = "Verify /etc/security/audit_control exists and contains appropriate flags (e.g., lo,ad,fd,fm,-all)."
            return check
        }
        let flags = result.output.replacingOccurrences(of: "flags:", with: "").trimmingCharacters(in: .whitespaces)
        let requiredFlags = ["lo", "ad", "fd", "fm"]
        var missing: [String] = []
        for flag in requiredFlags {
            if !flags.contains(flag) {
                missing.append(flag)
            }
        }
        if missing.isEmpty {
            check.status = .pass
            check.details = "Audit flags configured: \(flags)"
        } else {
            check.status = .warning
            check.details = "Audit flags \(flags) are missing: \(missing.joined(separator: ", "))."
            check.recommendation = "Edit /etc/security/audit_control to include flags: lo,ad,fd,fm,-all"
        }
        return check
    }

    private func checkAuditLogPermissions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.auditperms",
            name: "Audit Log Permissions",
            description: "Audit log files and their directory should have restrictive permissions to prevent tampering.",
            category: .systemProtection,
            severity: .medium
        )
        let dirResult = await ShellCommand.run("stat -f '%Lp %Su %Sg' /var/audit 2>/dev/null")
        if dirResult.output.isEmpty || dirResult.exitCode != 0 {
            check.status = .info
            check.details = "Could not check audit log directory permissions (may require elevated privileges)."
            return check
        }
        let parts = dirResult.output.split(separator: " ")
        guard parts.count >= 3 else {
            check.status = .unknown
            check.details = "Could not parse audit directory permissions."
            return check
        }
        let mode = String(parts[0])
        let owner = String(parts[1])
        let group = String(parts[2])
        var issues: [String] = []
        if let modeInt = Int(mode), modeInt > 700 {
            issues.append("directory permissions \(mode) are too permissive (should be 700 or stricter)")
        }
        if owner != "root" {
            issues.append("owned by \(owner) instead of root")
        }
        if group != "wheel" {
            issues.append("group is \(group) instead of wheel")
        }
        let aclResult = await ShellCommand.run("ls -lde /var/audit 2>/dev/null | grep -c '^ [0-9]'")
        if (Int(aclResult.output) ?? 0) > 0 {
            issues.append("directory has ACLs that should be removed")
        }
        if issues.isEmpty {
            check.status = .pass
            check.details = "Audit log directory has correct permissions (\(mode), \(owner):\(group))."
        } else {
            check.status = .warning
            check.details = "Audit log issues: \(issues.joined(separator: "; "))."
            check.recommendation = "Fix with: sudo chmod 700 /var/audit && sudo chown root:wheel /var/audit"
        }
        return check
    }

    private func checkAMFI() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.amfi",
            name: "Mobile File Integrity",
            description: "AMFI ensures only properly signed code runs, preventing unauthorized code injection.",
            category: .systemProtection,
            severity: .high
        )
        let result = await ShellCommand.run("nvram -p 2>/dev/null | grep -c 'amfi_get_out_of_my_way=1'")
        let count = Int(result.output) ?? 0
        if count == 0 {
            check.status = .pass
            check.details = "Mobile File Integrity (AMFI) is enabled."
        } else {
            check.status = .fail
            check.details = "Mobile File Integrity (AMFI) has been disabled via NVRAM."
            check.recommendation = "Re-enable AMFI by running: sudo nvram -d amfi_get_out_of_my_way"
        }
        return check
    }

    private func checkWorldWritableFolders() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.worldwritable",
            name: "World-Writable System Folders",
            description: "World-writable directories in system paths allow any user to modify system files.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("find /System/Volumes/Data/System -type d -perm -0002 -not -path '*/Caches/*' 2>/dev/null | head -5")
        if result.output.isEmpty {
            check.status = .pass
            check.details = "No world-writable system folders found."
        } else {
            let folders = result.output.components(separatedBy: "\n").filter { !$0.isEmpty }
            check.status = .warning
            check.details = "Found \(folders.count) world-writable system folder\(folders.count == 1 ? "" : "s")."
            check.recommendation = "Review and fix permissions with: sudo chmod o-w <folder_path>"
        }
        return check
    }

    private func checkSudoTimeout() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.sudo.timeout",
            name: "Sudo Session Timeout",
            description: "A long sudo timeout means elevated privileges persist after use, increasing risk if the terminal is left unattended.",
            category: .systemProtection,
            severity: .low
        )
        let vResult = await ShellCommand.run("sudo -V 2>/dev/null | grep 'Authentication timestamp timeout'")
        let grepResult = await ShellCommand.run("grep -r 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
        if !grepResult.output.isEmpty {
            // Custom timeout configured in sudoers
            if grepResult.output.contains("timestamp_timeout=0") || grepResult.output.contains("timestamp_timeout = 0") {
                check.status = .pass
                check.details = "Sudo always prompts for a password (timeout is 0)."
            } else if let range = grepResult.output.range(of: "\\d+", options: .regularExpression),
                      let timeout = Int(grepResult.output[range]) {
                if timeout > 10 {
                    check.status = .warning
                    check.details = "Sudo session timeout is \(timeout) minutes — longer than recommended."
                    check.recommendation = "Reduce the sudo timeout by adding 'Defaults timestamp_timeout=0' to /etc/sudoers via visudo."
                } else {
                    check.status = .pass
                    check.details = "Sudo session timeout is \(timeout) minutes."
                }
            } else {
                check.status = .info
                check.details = "Custom sudo timeout is configured."
            }
        } else if !vResult.output.isEmpty {
            check.status = .info
            check.details = "Sudo uses the default session timeout. \(vResult.output.trimmingCharacters(in: .whitespacesAndNewlines))"
        } else {
            check.status = .info
            check.details = "Sudo uses the default session timeout (typically 5 minutes)."
        }
        return check
    }

    private func checkSudoLogging() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.sudo.logging",
            name: "Sudo Command Logging",
            description: "Sudo should log all commands executed with elevated privileges for audit purposes.",
            category: .systemProtection,
            severity: .low
        )
        let result = await ShellCommand.run("grep -r 'log_output\\|Defaults.*logfile\\|Defaults.*log_input' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
        if !result.output.isEmpty {
            check.status = .pass
            check.details = "Sudo command logging is configured."
        } else {
            check.status = .info
            check.details = "Sudo uses default logging. Explicit command logging is not configured."
            check.recommendation = "For enhanced auditing, add 'Defaults log_input, log_output' to /etc/sudoers via visudo."
        }
        return check
    }

    private func checkRootDisabled() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "system.rootdisabled",
            name: "Root Account",
            description: "The root account should be disabled to prevent direct root login.",
            category: .systemProtection,
            severity: .medium
        )
        let result = await ShellCommand.run("dscl . -read /Users/root AuthenticationAuthority 2>/dev/null")
        if result.exitCode != 0 {
            check.status = .pass
            check.details = "Root account is disabled (no authentication authority)."
        } else if result.output.contains("DisabledUser") {
            check.status = .pass
            check.details = "Root account is explicitly disabled."
        } else {
            check.status = .fail
            check.details = "Root account appears to be enabled."
            check.recommendation = "Disable the root account with: dsenableroot -d, or open Directory Utility > Edit > Disable Root User."
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
