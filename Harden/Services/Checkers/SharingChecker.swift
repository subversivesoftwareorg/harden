import Foundation

struct SharingChecker {

    func runChecks() async -> [SecurityCheck] {
        async let remoteLoginCheck = checkRemoteLogin()
        async let screenSharingCheck = checkScreenSharing()
        async let fileSharingCheck = checkFileSharing()
        async let remoteManagementCheck = checkRemoteManagement()
        async let printerSharingCheck = checkPrinterSharing()
        async let bluetoothSharingCheck = checkBluetoothSharing()
        async let airdropCheck = checkAirDrop()
        async let insecureServicesCheck = checkInsecureServices()
        async let sshHardeningCheck = checkSSHHardening()
        async let remoteAppleEventsCheck = checkRemoteAppleEvents()
        async let internetSharingCheck = checkInternetSharing()
        async let mediaSharingCheck = checkMediaSharing()
        async let airplayReceiverCheck = checkAirPlayReceiver()
        async let contentCachingCheck = checkContentCaching()
        return await [
            remoteLoginCheck, screenSharingCheck, fileSharingCheck,
            remoteManagementCheck, printerSharingCheck, bluetoothSharingCheck,
            airdropCheck, insecureServicesCheck, sshHardeningCheck,
            remoteAppleEventsCheck, internetSharingCheck, mediaSharingCheck,
            airplayReceiverCheck, contentCachingCheck,
        ]
    }

    private func checkRemoteLogin() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.remotelogin",
            name: "Remote Login (SSH)",
            description: "Remote Login allows other users to access your Mac using SSH.",
            category: .sharing,
            severity: .high
        )
        let result = await ShellCommand.run("systemsetup -getremotelogin 2>/dev/null || echo 'unknown'")
        if result.output.lowercased().contains("off") {
            check.status = .pass
            check.details = "Remote Login (SSH) is disabled."
        } else if result.output.lowercased().contains("on") {
            check.status = .warning
            check.details = "Remote Login (SSH) is enabled. Other users can access your Mac remotely."
            check.recommendation = "Unless you need SSH access, disable it in System Settings > General > Sharing > Remote Login."
        } else {
            check.status = .unknown
            check.details = "Could not determine Remote Login status."
        }
        return check
    }

    private func checkScreenSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.screensharing",
            name: "Screen Sharing",
            description: "Screen Sharing allows other users to view and control your Mac remotely.",
            category: .sharing,
            severity: .high
        )
        let result = await ShellCommand.run("launchctl list 2>/dev/null | grep -c com.apple.screensharing")
        let running = (Int(result.output) ?? 0) > 0
        if running {
            check.status = .warning
            check.details = "Screen Sharing appears to be active."
            check.recommendation = "Unless you need remote access, disable it in System Settings > General > Sharing > Screen Sharing."
        } else {
            check.status = .pass
            check.details = "Screen Sharing is not active."
        }
        return check
    }

    private func checkFileSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.filesharing",
            name: "File Sharing (SMB)",
            description: "File Sharing allows other users on your network to access shared folders on your Mac.",
            category: .sharing,
            severity: .medium
        )
        let result = await ShellCommand.run("launchctl list 2>/dev/null | grep -c com.apple.smbd")
        let running = (Int(result.output) ?? 0) > 0
        if running {
            check.status = .warning
            check.details = "File Sharing (SMB) appears to be active."
            check.recommendation = "Unless you need to share files, disable it in System Settings > General > Sharing > File Sharing."
        } else {
            check.status = .pass
            check.details = "File Sharing is not active."
        }
        return check
    }

    private func checkRemoteManagement() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.remotemanagement",
            name: "Remote Management",
            description: "Remote Management allows administrators to control your Mac using Apple Remote Desktop.",
            category: .sharing,
            severity: .high
        )
        let result = await ShellCommand.run("launchctl list 2>/dev/null | grep -c com.apple.RemoteDesktop.agent")
        let running = (Int(result.output) ?? 0) > 0
        if running {
            check.status = .warning
            check.details = "Remote Management appears to be active."
            check.recommendation = "Unless managed by IT, disable it in System Settings > General > Sharing > Remote Management."
        } else {
            check.status = .pass
            check.details = "Remote Management is not active."
        }
        return check
    }

    private func checkPrinterSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.printersharing",
            name: "Printer Sharing",
            description: "Printer Sharing allows other users on your network to use printers connected to your Mac.",
            category: .sharing,
            severity: .low
        )
        let result = await ShellCommand.run("cupsctl 2>/dev/null | grep '_share_printers' || echo 'unknown'")
        if result.output.contains("_share_printers=0") {
            check.status = .pass
            check.details = "Printer Sharing is disabled."
        } else if result.output.contains("_share_printers=1") {
            check.status = .warning
            check.details = "Printer Sharing is enabled."
            check.recommendation = "Unless needed, disable it in System Settings > General > Sharing > Printer Sharing."
        } else {
            check.status = .pass
            check.details = "Printer Sharing appears to be disabled."
        }
        return check
    }

    private func checkAirDrop() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.airdrop",
            name: "AirDrop Discoverability",
            description: "AirDrop lets nearby devices send files to your Mac. Setting it to 'Contacts Only' or 'Off' prevents strangers from sending unwanted content.",
            category: .sharing,
            severity: .medium
        )
        let disabledResult = await ShellCommand.run("defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null")
        if disabledResult.output == "1" || disabledResult.output.lowercased() == "true" {
            check.status = .pass
            check.details = "AirDrop is disabled."
            return check
        }
        // Check if set to Everyone vs Contacts Only
        let browseResult = await ShellCommand.run("defaults read com.apple.NetworkBrowser BrowseAllInterfaces 2>/dev/null")
        if browseResult.output == "1" {
            check.status = .warning
            check.details = "AirDrop is set to receive from Everyone."
            check.recommendation = "Set AirDrop to 'Contacts Only' in Finder > AirDrop, or disable it entirely."
        } else {
            check.status = .pass
            check.details = "AirDrop is set to Contacts Only or is using the default."
        }
        return check
    }

    private func checkInsecureServices() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.insecure",
            name: "Legacy Insecure Services",
            description: "Legacy services like finger and FTP are insecure and should not be running.",
            category: .sharing,
            severity: .high
        )
        var running: [String] = []
        let fingerd = await ShellCommand.run("launchctl list com.apple.fingerd 2>/dev/null")
        if fingerd.exitCode == 0 && !fingerd.output.isEmpty {
            running.append("fingerd")
        }
        let ftp = await ShellCommand.run("launchctl list com.apple.ftp-proxy 2>/dev/null")
        if ftp.exitCode == 0 && !ftp.output.isEmpty {
            running.append("ftp-proxy")
        }
        let telnet = await ShellCommand.run("launchctl list com.apple.telnetd 2>/dev/null")
        if telnet.exitCode == 0 && !telnet.output.isEmpty {
            running.append("telnetd")
        }
        if running.isEmpty {
            check.status = .pass
            check.details = "No legacy insecure services are running."
        } else {
            check.status = .fail
            check.details = "Insecure services running: \(running.joined(separator: ", "))."
            check.recommendation = "Disable these services. They transmit data unencrypted and are not needed on modern systems."
        }
        return check
    }

    private func checkBluetoothSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.bluetooth",
            name: "Bluetooth Sharing",
            description: "Bluetooth Sharing allows other devices to send files to your Mac via Bluetooth.",
            category: .sharing,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Bluetooth Sharing is enabled."
            check.recommendation = "Disable it in System Settings > General > Sharing > Bluetooth Sharing."
        } else {
            check.status = .pass
            check.details = "Bluetooth Sharing is disabled."
        }
        return check
    }

    private func checkRemoteAppleEvents() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.remoteappleevents",
            name: "Remote Apple Events",
            description: "Remote Apple Events allows other computers to send Apple Events to your Mac, which can be used to control applications remotely.",
            category: .sharing,
            severity: .medium
        )
        let result = await ShellCommand.run("systemsetup -getremoteappleevents 2>/dev/null")
        if result.output.lowercased().contains("off") {
            check.status = .pass
            check.details = "Remote Apple Events is disabled."
        } else if result.output.lowercased().contains("on") {
            check.status = .warning
            check.details = "Remote Apple Events is enabled."
            check.recommendation = "Disable via: sudo systemsetup -setremoteappleevents off"
        } else {
            check.status = .pass
            check.details = "Remote Apple Events appears to be disabled (default)."
        }
        return check
    }

    private func checkInternetSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.internetsharing",
            name: "Internet Sharing",
            description: "Internet Sharing turns your Mac into a network router, sharing its internet connection with other devices. This expands the attack surface.",
            category: .sharing,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null")
        if result.exitCode != 0 || result.output.contains("does not exist") || result.output.isEmpty {
            check.status = .pass
            check.details = "Internet Sharing is not configured."
        } else if result.output.contains("Enabled = 1") {
            check.status = .warning
            check.details = "Internet Sharing is enabled."
            check.recommendation = "Disable it in System Settings > General > Sharing > Internet Sharing."
        } else {
            check.status = .pass
            check.details = "Internet Sharing is disabled."
        }
        return check
    }

    private func checkMediaSharing() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.mediasharing",
            name: "Media Sharing",
            description: "Media Sharing allows other devices on your network to access your shared media libraries.",
            category: .sharing,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.amp.mediasharingd home-sharing-enabled 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Media Sharing is enabled."
            check.recommendation = "Disable it in System Settings > General > Sharing > Media Sharing."
        } else {
            check.status = .pass
            check.details = "Media Sharing is disabled."
        }
        return check
    }

    private func checkAirPlayReceiver() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.airplayreceiver",
            name: "AirPlay Receiver",
            description: "AirPlay Receiver allows other Apple devices to stream content to your Mac. This opens a network service.",
            category: .sharing,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.controlcenter AirplayRecieverEnabled 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "AirPlay Receiver is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "AirPlay Receiver is enabled. Other devices can stream content to this Mac."
            check.recommendation = "If not needed, disable in System Settings > General > AirDrop & Handoff > AirPlay Receiver."
        } else {
            check.status = .info
            check.details = "AirPlay Receiver status could not be determined. Check System Settings > General > AirDrop & Handoff."
        }
        return check
    }

    private func checkContentCaching() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.contentcaching",
            name: "Content Caching",
            description: "Content Caching stores Apple software updates and iCloud content locally to reduce bandwidth. It runs a local web server.",
            category: .sharing,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.AssetCache.plist Activated 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "Content Caching is enabled."
            check.recommendation = "Unless needed for multiple Apple devices on this network, disable in System Settings > General > Sharing > Content Caching."
        } else {
            check.status = .pass
            check.details = "Content Caching is not active."
        }
        return check
    }

    private func checkSSHHardening() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "sharing.ssh.hardening",
            name: "SSH Configuration Hardening",
            description: "If Remote Login is enabled, the SSH server should be configured securely.",
            category: .sharing,
            severity: .medium
        )
        // First check if SSH is even on
        let sshStatus = await ShellCommand.run("systemsetup -getremotelogin 2>/dev/null || echo 'unknown'")
        guard sshStatus.output.lowercased().contains("on") else {
            check.status = .pass
            check.details = "Remote Login is disabled — SSH hardening not applicable."
            return check
        }
        // SSH is on — check config
        let configResult = await ShellCommand.run("cat /etc/ssh/sshd_config 2>/dev/null")
        guard !configResult.output.isEmpty else {
            check.status = .unknown
            check.details = "Could not read SSH configuration."
            return check
        }
        let config = configResult.output
        var issues: [String] = []
        // Check PermitRootLogin
        if config.contains("PermitRootLogin yes") {
            issues.append("PermitRootLogin is set to yes")
        }
        // Check PasswordAuthentication
        if config.contains("PasswordAuthentication yes") || (!config.contains("PasswordAuthentication no") && !config.contains("PasswordAuthentication")) {
            // Default is yes if not specified — only flag if explicitly yes
            if config.contains("PasswordAuthentication yes") {
                issues.append("PasswordAuthentication is enabled (keys are safer)")
            }
        }
        // Check X11Forwarding
        if config.contains("X11Forwarding yes") {
            issues.append("X11Forwarding is enabled")
        }
        if issues.isEmpty {
            check.status = .pass
            check.details = "SSH is enabled with reasonable configuration."
        } else {
            check.status = .warning
            check.details = "SSH issues: \(issues.joined(separator: "; "))."
            check.recommendation = "Edit /etc/ssh/sshd_config to set: PermitRootLogin no, PasswordAuthentication no (use keys), X11Forwarding no."
        }
        return check
    }
}
