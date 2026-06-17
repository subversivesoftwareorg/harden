import SwiftUI

struct HelpView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .padding(8)
                .keyboardShortcut(.cancelAction)
            }

            TabView(selection: $selectedTab) {
                overviewTab
                    .tabItem { Label("Overview", systemImage: "questionmark.circle") }
                    .tag(0)

                SecurityGuideView()
                    .tabItem { Label("Check Reference", systemImage: "book") }
                    .tag(1)
            }
        }
        .frame(width: 680, height: 600)
    }

    private var overviewTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Harden Security Guide")
                    .font(.title)
                    .fontWeight(.bold)

                section("What Harden Checks",
                    "Harden runs 93 security checks across 8 categories: Firewall, Encryption, System Protection, Sharing Services, Authentication, Network, Privacy, and Applications. Many checks align with STIG and CIS benchmarks — see the Compliance tab for a mapped view. Each check queries your Mac's actual configuration using the same commands security professionals use.")

                section("Understanding Your Score",
                    "Your Security Score (0-100) is a weighted average. Critical checks (like FileVault and SIP) count more than low-severity checks (like firewall logging). A score of 90+ means your Mac is well-configured. Below 75, there are meaningful improvements to make.")

                section("Action Items & Fixing Issues",
                    "The Action Items tab shows checks that failed or returned warnings, sorted by severity. Many issues can be fixed directly with the Fix button — for items that need sudo, you'll see the standard macOS password dialog. For items that can't be automated, the 'Open in System Settings' button takes you to the right place. The Integration tab provides fleet reporting endpoints for enterprise use.")

                section("Snoozing",
                    "Snooze hides an action item for 1 day, 1 week, 1 month, or forever. Snoozed items still count toward your score — snoozing is about managing your attention, not hiding problems.")

                section("Severity Levels",
                    """
                    \u{2022} Critical — Must fix. Serious risk if left unaddressed (e.g., FileVault off, SIP disabled).
                    \u{2022} High — Should fix. Significant security gap (e.g., Gatekeeper off, outdated macOS).
                    \u{2022} Medium — Worth fixing. Moderate improvement to your security posture.
                    \u{2022} Low — Nice to have. Minor hardening improvement.
                    \u{2022} Info — Informational only. No action needed.
                    """)

                section("Exporting Results",
                    "Use the Export button in the All Checks tab to save scan results as HTML, CSV, or JSON for compliance documentation or sharing with your IT team.")
            }
            .padding(24)
        }
    }

    private func section(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.headline)
            Text(body)
                .font(.body)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Comprehensive Check Reference

struct SecurityGuideView: View {
    @State private var searchText = ""
    @State private var expandedCategory: CheckCategory?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Check Reference")
                    .font(.title2)
                    .fontWeight(.bold)
                Spacer()
                TextField("Search checks...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }
            .padding()
            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    ForEach(CheckCategory.allCases) { category in
                        let entries = filteredEntries(for: category)
                        if !entries.isEmpty {
                            categorySection(category, entries: entries)
                        }
                    }
                }
                .padding()
            }
        }
    }

    private func filteredEntries(for category: CheckCategory) -> [CheckGuideEntry] {
        let entries = CheckGuideEntry.all.filter { $0.category == category }
        if searchText.isEmpty { return entries }
        let query = searchText.lowercased()
        return entries.filter {
            $0.name.lowercased().contains(query)
            || $0.whatItChecks.lowercased().contains(query)
            || $0.whyItMatters.lowercased().contains(query)
        }
    }

    private func categorySection(_ category: CheckCategory, entries: [CheckGuideEntry]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation {
                    expandedCategory = expandedCategory == category ? nil : category
                }
            } label: {
                HStack {
                    Image(systemName: category.icon)
                        .foregroundStyle(category.color)
                    Text(category.rawValue)
                        .font(.title3)
                        .fontWeight(.semibold)
                        .foregroundStyle(.primary)
                    Text("(\(entries.count))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(expandedCategory == category ? 90 : 0))
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if expandedCategory == category || !searchText.isEmpty {
                ForEach(entries) { entry in
                    entryCard(entry)
                }
            }
        }
    }

    private func entryCard(_ entry: CheckGuideEntry) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(entry.name)
                    .font(.headline)
                Spacer()
                Text(entry.severity)
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(severityColor(entry.severity).opacity(0.15))
                    .foregroundStyle(severityColor(entry.severity))
                    .clipShape(Capsule())
            }

            VStack(alignment: .leading, spacing: 6) {
                guideRow("magnifyingglass", "What it checks", entry.whatItChecks)
                guideRow("exclamationmark.shield", "Why it matters", entry.whyItMatters)
                guideRow("wrench", "How to fix", entry.howToFix)
                if let command = entry.command {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "terminal")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(width: 16)
                        Text(command)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }

            if Remediation.catalog[entry.id] != nil {
                HStack(spacing: 4) {
                    Image(systemName: "wrench.fill")
                        .font(.caption2)
                    Text("Auto-fixable from Action Items")
                        .font(.caption)
                }
                .foregroundStyle(.blue)
            }
        }
        .padding(12)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func guideRow(_ icon: String, _ label: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption)
                    .fontWeight(.medium)
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity {
        case "Critical": .red
        case "High": .orange
        case "Medium": .yellow
        case "Low": .blue
        default: .secondary
        }
    }
}

// MARK: - Guide Entry Data

struct CheckGuideEntry: Identifiable {
    let id: String
    let name: String
    let category: CheckCategory
    let severity: String
    let whatItChecks: String
    let whyItMatters: String
    let howToFix: String
    let command: String?

    static let all: [CheckGuideEntry] = [
        // ── Firewall ────────────────────────────────────────────────
        CheckGuideEntry(id: "firewall.enabled", name: "Application Firewall", category: .firewall, severity: "Critical",
            whatItChecks: "Whether the macOS Application Firewall is enabled via socketfilterfw.",
            whyItMatters: "Without a firewall, any application can accept incoming connections from the network, increasing exposure to attacks.",
            howToFix: "System Settings > Network > Firewall > Turn On. Or use the Fix button in Action Items.",
            command: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"),
        CheckGuideEntry(id: "firewall.stealth", name: "Stealth Mode", category: .firewall, severity: "Medium",
            whatItChecks: "Whether the firewall's stealth mode prevents responding to ICMP probes.",
            whyItMatters: "Stealth mode makes your Mac invisible to port scanners and ping sweeps on untrusted networks.",
            howToFix: "Use the Fix button, or run the terminal command.",
            command: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"),
        CheckGuideEntry(id: "firewall.logging", name: "Firewall Logging", category: .firewall, severity: "Low",
            whatItChecks: "Whether the firewall logs blocked connection attempts.",
            whyItMatters: "Logging helps you detect repeated intrusion attempts and troubleshoot connectivity issues.",
            howToFix: "Use the Fix button, or run the terminal command.",
            command: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on"),
        CheckGuideEntry(id: "firewall.outbound", name: "Outbound Firewall", category: .firewall, severity: "Info",
            whatItChecks: "Whether a third-party outbound firewall (Little Snitch, LuLu, etc.) is running.",
            whyItMatters: "macOS only filters incoming connections. An outbound firewall detects apps sending data without your knowledge.",
            howToFix: "Install LuLu (free, open source) from objective-see.org or Little Snitch from obdev.at.",
            command: nil),
        CheckGuideEntry(id: "firewall.pf", name: "Packet Filter (pf)", category: .firewall, severity: "Info",
            whatItChecks: "Whether the BSD packet filter firewall is enabled.",
            whyItMatters: "pf provides fine-grained network filtering at the kernel level, beyond what the Application Firewall offers.",
            howToFix: "Edit /etc/pf.conf and enable with: sudo pfctl -e -f /etc/pf.conf. Advanced users only.",
            command: "sudo pfctl -e -f /etc/pf.conf"),

        // ── Encryption ──────────────────────────────────────────────
        CheckGuideEntry(id: "encryption.filevault", name: "FileVault Disk Encryption", category: .encryption, severity: "Critical",
            whatItChecks: "Whether FileVault 2 full-disk encryption is enabled on the startup volume.",
            whyItMatters: "Without FileVault, anyone with physical access to your Mac can read your files by booting from external media.",
            howToFix: "System Settings > Privacy & Security > FileVault > Turn On FileVault. You'll set a recovery key and your Mac will encrypt in the background.",
            command: nil),
        CheckGuideEntry(id: "encryption.timemachine", name: "Time Machine Encryption", category: .encryption, severity: "Medium",
            whatItChecks: "Whether Time Machine backup destinations are encrypted.",
            whyItMatters: "Unencrypted backups contain copies of all your files. A stolen backup drive exposes everything.",
            howToFix: "Remove the backup destination in System Settings > General > Time Machine, then re-add it with 'Encrypt Backups' checked.",
            command: nil),

        // ── System Protection ───────────────────────────────────────
        CheckGuideEntry(id: "system.sip", name: "System Integrity Protection", category: .systemProtection, severity: "Critical",
            whatItChecks: "Whether SIP is enabled, protecting system files from modification.",
            whyItMatters: "SIP prevents even root from modifying critical system files, blocking a major class of malware and rootkits.",
            howToFix: "Restart into Recovery Mode (hold Command+R on Intel, or power button on Apple Silicon), open Terminal, run: csrutil enable",
            command: nil),
        CheckGuideEntry(id: "system.gatekeeper", name: "Gatekeeper", category: .systemProtection, severity: "High",
            whatItChecks: "Whether Gatekeeper verifies that apps are signed and notarized before running.",
            whyItMatters: "Gatekeeper is your first defense against malware distributed outside the App Store.",
            howToFix: "System Settings > Privacy & Security > set 'Allow apps from' to 'App Store and identified developers'.",
            command: nil),
        CheckGuideEntry(id: "system.osversion", name: "macOS Version", category: .systemProtection, severity: "High",
            whatItChecks: "Whether you're running a current, supported macOS version.",
            whyItMatters: "Older macOS versions stop receiving security updates, leaving known vulnerabilities unpatched.",
            howToFix: "System Settings > General > Software Update > upgrade to the latest macOS.",
            command: nil),
        CheckGuideEntry(id: "system.autoupdate.check", name: "Automatic Update Checks", category: .systemProtection, severity: "High",
            whatItChecks: "Whether macOS automatically checks for available updates.",
            whyItMatters: "Without automatic checks, you won't know about critical security patches until you manually look.",
            howToFix: "System Settings > General > Software Update > Automatic Updates. Or use the Fix button.",
            command: "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"),
        CheckGuideEntry(id: "system.autoupdate.download", name: "Auto-Download Updates", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether updates are downloaded automatically in the background.",
            whyItMatters: "Pre-downloading updates means they're ready to install immediately when you choose to.",
            howToFix: "System Settings > General > Software Update > Automatic Updates > enable downloads.",
            command: "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true"),
        CheckGuideEntry(id: "system.autoupdate.install", name: "Auto-Install macOS Updates", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether macOS updates are installed automatically.",
            whyItMatters: "Automatic installation ensures security patches are applied without requiring you to remember.",
            howToFix: "System Settings > General > Software Update > Automatic Updates > enable macOS updates.",
            command: "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true"),
        CheckGuideEntry(id: "system.autoupdate.critical", name: "Auto Security Updates", category: .systemProtection, severity: "High",
            whatItChecks: "Whether critical security patches are installed automatically without waiting for full updates.",
            whyItMatters: "Security patches fix actively exploited vulnerabilities. Delaying them leaves you exposed.",
            howToFix: "System Settings > General > Software Update > Automatic Updates > 'Install Security Responses and system files'.",
            command: "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true"),
        CheckGuideEntry(id: "system.autoupdate.configdata", name: "Config Data Updates", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether system data files (including XProtect malware definitions) update automatically.",
            whyItMatters: "These background updates keep malware definitions and certificate revocations current.",
            howToFix: "Same setting as security updates — enable 'Install Security Responses and system files'.",
            command: "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true"),
        CheckGuideEntry(id: "system.autoupdate.appstore", name: "App Store Auto-Updates", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether App Store apps update automatically.",
            whyItMatters: "Outdated apps may have known security vulnerabilities that updates would fix.",
            howToFix: "System Settings > General > Software Update > Automatic Updates > enable app updates.",
            command: "sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true"),
        CheckGuideEntry(id: "system.findmymac", name: "Find My Mac", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether Find My Mac is enabled via iCloud.",
            whyItMatters: "Find My Mac lets you locate, lock, or remotely erase your Mac if it's lost or stolen.",
            howToFix: "System Settings > [your name] > iCloud > Find My Mac > Turn On.",
            command: nil),
        CheckGuideEntry(id: "system.extensions", name: "System Extensions", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether third-party kernel extensions or system extensions are loaded.",
            whyItMatters: "Third-party extensions run with elevated privileges and can compromise system stability and security.",
            howToFix: "Review loaded extensions with 'systemextensionsctl list' in Terminal. Remove any you don't recognize.",
            command: "systemextensionsctl list"),
        CheckGuideEntry(id: "system.uptime", name: "System Uptime", category: .systemProtection, severity: "Low",
            whatItChecks: "How long since your Mac was last restarted.",
            whyItMatters: "Some security updates require a restart to take effect. Long uptime means kernel patches may not be applied.",
            howToFix: "Apple menu > Restart. Do this periodically, especially after updates.",
            command: nil),
        CheckGuideEntry(id: "system.ntp", name: "Network Time Sync", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether your Mac synchronizes its clock with network time servers.",
            whyItMatters: "Accurate time is essential for TLS certificate validation, Kerberos authentication, and log forensics.",
            howToFix: "System Settings > General > Date & Time > enable 'Set time and date automatically'.",
            command: "sudo systemsetup -setusingnetworktime on"),
        CheckGuideEntry(id: "system.malware", name: "Malware Scanner", category: .systemProtection, severity: "Info",
            whatItChecks: "Whether a third-party malware scanner (CrowdStrike, Defender, etc.) is running.",
            whyItMatters: "A dedicated scanner adds defense-in-depth beyond macOS's built-in XProtect.",
            howToFix: "macOS includes XProtect by default. Third-party scanners are optional but recommended for high-value targets.",
            command: nil),
        CheckGuideEntry(id: "system.xprotect", name: "XProtect Definitions", category: .systemProtection, severity: "High",
            whatItChecks: "How recently XProtect malware definitions were updated.",
            whyItMatters: "XProtect is macOS's built-in malware blocker. Stale definitions miss newly discovered threats.",
            howToFix: "Ensure automatic security updates are enabled. Force update with: sudo softwareupdate --background",
            command: "sudo softwareupdate --background"),
        CheckGuideEntry(id: "system.secureboot", name: "Startup Security", category: .systemProtection, severity: "High",
            whatItChecks: "Whether Secure Boot is set to Full Security on Apple Silicon or T2 Macs.",
            whyItMatters: "Full Security ensures only trusted, signed operating systems can boot, preventing bootkits and evil maid attacks.",
            howToFix: "Restart into Recovery Mode > Options > Startup Security Utility > set to Full Security.",
            command: nil),
        CheckGuideEntry(id: "system.rsr", name: "Rapid Security Response", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether Rapid Security Responses are enabled for between-update patches.",
            whyItMatters: "RSR delivers critical fixes faster than full macOS updates, often without requiring a restart.",
            howToFix: "Enabled via the same setting as critical updates in Software Update preferences.",
            command: nil),
        CheckGuideEntry(id: "system.auditd", name: "Security Auditing", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether the auditd daemon is running to record security events.",
            whyItMatters: "Security auditing provides forensic evidence of system activity, essential for incident investigation.",
            howToFix: "Enable the audit daemon via launchctl.",
            command: "sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"),
        CheckGuideEntry(id: "system.auditflags", name: "Audit Control Flags", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether audit flags in /etc/security/audit_control are configured to capture security-relevant events.",
            whyItMatters: "Proper audit flags ensure login attempts, privilege escalation, and file access are logged.",
            howToFix: "Edit /etc/security/audit_control to include appropriate flags (lo, ad, fd, fm, -all).",
            command: nil),
        CheckGuideEntry(id: "system.auditperms", name: "Audit Log Permissions", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether /var/audit directory permissions prevent unauthorized access.",
            whyItMatters: "Loose permissions on audit logs allow attackers to read or tamper with forensic evidence.",
            howToFix: "Restrict audit directory permissions to root only.",
            command: "sudo chmod 700 /var/audit"),
        CheckGuideEntry(id: "system.amfi", name: "Mobile File Integrity", category: .systemProtection, severity: "High",
            whatItChecks: "Whether Apple Mobile File Integrity (AMFI) is enabled and not disabled via NVRAM.",
            whyItMatters: "AMFI prevents unsigned and untrusted code from executing. Disabling it opens the door to malware.",
            howToFix: "Boot into Recovery Mode and reset NVRAM boot arguments to re-enable AMFI.",
            command: nil),
        CheckGuideEntry(id: "system.worldwritable", name: "World-Writable Folders", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether any directories in /System are world-writable.",
            whyItMatters: "World-writable system directories allow any user or process to plant or modify files, enabling tampering.",
            howToFix: "Remove world-writable permission from affected directories.",
            command: "sudo chmod o-w <path>"),
        CheckGuideEntry(id: "system.sudo.timeout", name: "Sudo Session Timeout", category: .systemProtection, severity: "Low",
            whatItChecks: "Whether the sudo timestamp timeout is configured to a short duration.",
            whyItMatters: "A long sudo timeout leaves elevated privileges open, increasing risk if your session is hijacked.",
            howToFix: "Edit /etc/sudoers to set a short timeout (e.g., Defaults timestamp_timeout=0).",
            command: nil),
        CheckGuideEntry(id: "system.sudo.logging", name: "Sudo Command Logging", category: .systemProtection, severity: "Low",
            whatItChecks: "Whether sudo is configured to log all commands executed with elevated privileges.",
            whyItMatters: "Logging sudo commands provides an audit trail of administrative actions on the system.",
            howToFix: "Add logging directives to /etc/sudoers (e.g., Defaults logfile=/var/log/sudo.log).",
            command: nil),
        CheckGuideEntry(id: "system.rootdisabled", name: "Root Account", category: .systemProtection, severity: "Medium",
            whatItChecks: "Whether the root account is disabled to prevent direct root login.",
            whyItMatters: "An enabled root account allows direct login with full system privileges, bypassing accountability.",
            howToFix: "Disable the root account shell.",
            command: "sudo dscl . -create /Users/root UserShell /usr/bin/false"),

        // ── Sharing ─────────────────────────────────────────────────
        CheckGuideEntry(id: "sharing.remotelogin", name: "Remote Login (SSH)", category: .sharing, severity: "High",
            whatItChecks: "Whether SSH remote access is enabled.",
            whyItMatters: "SSH allows full command-line access to your Mac from anywhere on the network. If compromised, an attacker has shell access.",
            howToFix: "System Settings > General > Sharing > disable Remote Login. Or use the Fix button.",
            command: "sudo systemsetup -setremotelogin off"),
        CheckGuideEntry(id: "sharing.screensharing", name: "Screen Sharing", category: .sharing, severity: "High",
            whatItChecks: "Whether macOS Screen Sharing (VNC) is active.",
            whyItMatters: "Screen Sharing allows remote viewing and control of your Mac. It should only be on when actively needed.",
            howToFix: "System Settings > General > Sharing > disable Screen Sharing.",
            command: nil),
        CheckGuideEntry(id: "sharing.filesharing", name: "File Sharing (SMB)", category: .sharing, severity: "Medium",
            whatItChecks: "Whether SMB file sharing is active.",
            whyItMatters: "File sharing exposes your folders to the network. SMB has a history of security vulnerabilities.",
            howToFix: "System Settings > General > Sharing > disable File Sharing.",
            command: nil),
        CheckGuideEntry(id: "sharing.remotemanagement", name: "Remote Management", category: .sharing, severity: "High",
            whatItChecks: "Whether Apple Remote Desktop agent is active.",
            whyItMatters: "Remote Management gives full remote control capabilities. Unless managed by IT, it should be off.",
            howToFix: "System Settings > General > Sharing > disable Remote Management.",
            command: nil),
        CheckGuideEntry(id: "sharing.printersharing", name: "Printer Sharing", category: .sharing, severity: "Low",
            whatItChecks: "Whether printers connected to your Mac are shared on the network.",
            whyItMatters: "Low risk, but unnecessary services increase attack surface.",
            howToFix: "System Settings > General > Sharing > disable Printer Sharing.",
            command: nil),
        CheckGuideEntry(id: "sharing.bluetooth", name: "Bluetooth Sharing", category: .sharing, severity: "Medium",
            whatItChecks: "Whether Bluetooth file transfer is enabled.",
            whyItMatters: "Bluetooth sharing allows nearby devices to send files to your Mac without your explicit consent.",
            howToFix: "System Settings > General > Sharing > disable Bluetooth Sharing. Or use the Fix button.",
            command: "defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"),
        CheckGuideEntry(id: "sharing.airdrop", name: "AirDrop", category: .sharing, severity: "Medium",
            whatItChecks: "Whether AirDrop is set to receive from Everyone.",
            whyItMatters: "AirDrop set to Everyone allows strangers to send you files, which can be used for social engineering.",
            howToFix: "Finder > AirDrop > set to 'Contacts Only'. Or use the Fix button to disable entirely.",
            command: "defaults write com.apple.NetworkBrowser DisableAirDrop -bool true"),
        CheckGuideEntry(id: "sharing.insecure", name: "Legacy Insecure Services", category: .sharing, severity: "High",
            whatItChecks: "Whether finger, FTP proxy, or telnet daemons are running.",
            whyItMatters: "These protocols transmit data (including passwords) in plain text and have no place on modern systems.",
            howToFix: "These services should not be running on a modern Mac. If they are, investigate what enabled them.",
            command: nil),
        CheckGuideEntry(id: "sharing.ssh.hardening", name: "SSH Configuration", category: .sharing, severity: "Medium",
            whatItChecks: "If SSH is enabled, whether sshd_config follows hardening best practices.",
            whyItMatters: "Default SSH config may allow root login and password auth, both of which increase brute-force risk.",
            howToFix: "Edit /etc/ssh/sshd_config: set PermitRootLogin no, PasswordAuthentication no, X11Forwarding no.",
            command: nil),
        CheckGuideEntry(id: "sharing.remoteappleevents", name: "Remote Apple Events", category: .sharing, severity: "Medium",
            whatItChecks: "Whether Remote Apple Events is disabled.",
            whyItMatters: "Remote Apple Events allows other computers to send AppleScript commands to your Mac, enabling remote control.",
            howToFix: "Disable Remote Apple Events via systemsetup.",
            command: "sudo systemsetup -setremoteappleevents off"),
        CheckGuideEntry(id: "sharing.internetsharing", name: "Internet Sharing", category: .sharing, severity: "Medium",
            whatItChecks: "Whether Internet Sharing is turned off.",
            whyItMatters: "Internet Sharing turns your Mac into a router, potentially exposing your network to untrusted devices.",
            howToFix: "System Settings > General > Sharing > disable Internet Sharing.",
            command: nil),
        CheckGuideEntry(id: "sharing.mediasharing", name: "Media Sharing", category: .sharing, severity: "Low",
            whatItChecks: "Whether media sharing is disabled.",
            whyItMatters: "Media sharing exposes your music, movies, and photo libraries to other devices on the network.",
            howToFix: "System Settings > General > Sharing > disable Media Sharing.",
            command: nil),
        CheckGuideEntry(id: "sharing.airplayreceiver", name: "AirPlay Receiver", category: .sharing, severity: "Low",
            whatItChecks: "Whether the AirPlay Receiver service is disabled.",
            whyItMatters: "AirPlay Receiver opens a network service that allows other devices to stream content to your Mac.",
            howToFix: "System Settings > General > AirDrop & Handoff > disable AirPlay Receiver.",
            command: nil),
        CheckGuideEntry(id: "sharing.contentcaching", name: "Content Caching", category: .sharing, severity: "Low",
            whatItChecks: "Whether Content Caching is disabled.",
            whyItMatters: "Content Caching runs a local web server to cache Apple content for other devices on your network.",
            howToFix: "System Settings > General > Sharing > disable Content Caching.",
            command: nil),

        // ── Authentication ──────────────────────────────────────────
        CheckGuideEntry(id: "auth.autologin", name: "Automatic Login", category: .authentication, severity: "Critical",
            whatItChecks: "Whether a user account is configured to log in automatically without a password.",
            whyItMatters: "Auto-login means anyone who opens your Mac has immediate full access to your account.",
            howToFix: "System Settings > Users & Groups > disable automatic login.",
            command: nil),
        CheckGuideEntry(id: "auth.password.sleep", name: "Password After Sleep", category: .authentication, severity: "High",
            whatItChecks: "Whether a password is required after sleep or screensaver.",
            whyItMatters: "Without this, anyone can access your Mac by simply opening the lid or moving the mouse.",
            howToFix: "System Settings > Lock Screen > 'Require password after screen saver begins'. Or use the Fix button.",
            command: "defaults write com.apple.screensaver askForPassword -int 1"),
        CheckGuideEntry(id: "auth.guest", name: "Guest Account", category: .authentication, severity: "Medium",
            whatItChecks: "Whether the guest account is enabled.",
            whyItMatters: "The guest account provides unrestricted physical access to a temporary session on your Mac.",
            howToFix: "System Settings > Users & Groups > disable Guest User. Note: Find My Mac works better with guest enabled.",
            command: "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"),
        CheckGuideEntry(id: "auth.lockdelay", name: "Screen Lock Delay", category: .authentication, severity: "Medium",
            whatItChecks: "The delay between screensaver activation and password requirement.",
            whyItMatters: "A long delay gives someone a window to access your Mac after you walk away.",
            howToFix: "System Settings > Lock Screen > set to 'Immediately'. Or use the Fix button.",
            command: "defaults write com.apple.screensaver askForPasswordDelay -int 0"),
        CheckGuideEntry(id: "auth.idle.timeout", name: "Screensaver Timeout", category: .authentication, severity: "Medium",
            whatItChecks: "How long your Mac sits idle before the screensaver activates.",
            whyItMatters: "A short timeout ensures the screen locks promptly when you step away.",
            howToFix: "System Settings > Lock Screen > 'Start Screen Saver when inactive' > 5 minutes or less.",
            command: "defaults write com.apple.screensaver idleTime -int 300"),
        CheckGuideEntry(id: "auth.loginwindow.style", name: "Login Window Display", category: .authentication, severity: "Low",
            whatItChecks: "Whether the login window shows a user list or name/password fields.",
            whyItMatters: "A user list reveals which accounts exist, giving attackers a head start on credential guessing.",
            howToFix: "Use the Fix button, or run the terminal command.",
            command: "sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true"),
        CheckGuideEntry(id: "auth.homedir.permissions", name: "Home Directory Permissions", category: .authentication, severity: "Medium",
            whatItChecks: "Whether your home directory is readable by other users on the system.",
            whyItMatters: "Permissive home directory permissions let other local users browse your files.",
            howToFix: "Use the Fix button, or run: chmod 750 ~",
            command: "chmod 750 ~"),
        CheckGuideEntry(id: "auth.passwordpolicy", name: "Password Policy", category: .authentication, severity: "Medium",
            whatItChecks: "Whether a custom password policy enforces minimum length and complexity.",
            whyItMatters: "Without a policy, users can set weak passwords like '1234' that are trivially guessable.",
            howToFix: "Set a policy with: sudo pwpolicy -setglobalpolicy 'minChars=8'",
            command: "sudo pwpolicy -setglobalpolicy 'minChars=8'"),
        CheckGuideEntry(id: "auth.filevaultautologin", name: "FileVault Auto-Login", category: .authentication, severity: "High",
            whatItChecks: "Whether FileVault auto-login is disabled, requiring authentication at the pre-boot screen.",
            whyItMatters: "FileVault auto-login bypasses pre-boot authentication, letting anyone boot straight into your desktop.",
            howToFix: "Disable FDE auto-login via defaults.",
            command: "sudo defaults write com.apple.loginwindow DisableFDEAutoLogin -bool true"),
        CheckGuideEntry(id: "auth.hotcorners", name: "Hot Corner Security", category: .authentication, severity: "Medium",
            whatItChecks: "Whether any hot corner is configured to disable the screen saver.",
            whyItMatters: "A hot corner that disables the screen saver provides a quick way to bypass the lock screen.",
            howToFix: "System Settings > Desktop & Dock > Hot Corners > ensure no corner is set to disable screen saver.",
            command: nil),
        CheckGuideEntry(id: "auth.consolelogin", name: "Console Login", category: .authentication, severity: "Low",
            whatItChecks: "Whether console login is disabled at the login window.",
            whyItMatters: "Console login can bypass login window security controls and policies.",
            howToFix: "Disable console login access.",
            command: "sudo defaults write /Library/Preferences/com.apple.loginwindow DisableConsoleAccess -bool true"),
        CheckGuideEntry(id: "auth.applewatch", name: "Apple Watch Auto-Unlock", category: .authentication, severity: "Low",
            whatItChecks: "Whether Apple Watch is used for automatic Mac unlock.",
            whyItMatters: "Proximity-based unlock means your Mac unlocks whenever your watch is nearby, even unintentionally.",
            howToFix: "System Settings > Touch ID & Password > disable 'Use Apple Watch to unlock'.",
            command: nil),
        CheckGuideEntry(id: "auth.guest.smb", name: "Guest SMB Access", category: .authentication, severity: "Medium",
            whatItChecks: "Whether guest access to SMB file shares is disabled.",
            whyItMatters: "Guest SMB access allows unauthenticated users to browse shared folders on your Mac.",
            howToFix: "Disable guest access in sharing preferences for each shared folder.",
            command: nil),
        CheckGuideEntry(id: "auth.passwordhints", name: "Password Hints", category: .authentication, severity: "Low",
            whatItChecks: "Whether login window password hints are disabled.",
            whyItMatters: "Password hints displayed at the login window help attackers guess your password.",
            howToFix: "Disable password hints on the login window.",
            command: "sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"),
        CheckGuideEntry(id: "auth.guest.homefolder", name: "Guest Home Folder", category: .authentication, severity: "Low",
            whatItChecks: "Whether the /Users/Guest home directory exists.",
            whyItMatters: "A persistent guest home folder can retain data from guest sessions, creating a privacy risk.",
            howToFix: "Remove the guest home folder if the guest account is disabled.",
            command: "sudo rm -rf /Users/Guest"),
        CheckGuideEntry(id: "auth.systemprefs.password", name: "System Settings Password", category: .authentication, severity: "Medium",
            whatItChecks: "Whether an admin password is required to change system-wide preferences.",
            whyItMatters: "Without this, any user at the keyboard can change security-sensitive system settings.",
            howToFix: "System Settings > Privacy & Security > require admin password for system-wide preferences.",
            command: nil),

        // ── Network ─────────────────────────────────────────────────
        CheckGuideEntry(id: "network.dns", name: "DNS Configuration", category: .network, severity: "Medium",
            whatItChecks: "Whether custom DNS servers are configured instead of ISP defaults.",
            whyItMatters: "Your ISP can log every domain you visit. Privacy-focused DNS (Cloudflare, Quad9) prevents this.",
            howToFix: "System Settings > Network > Wi-Fi > Details > DNS > add 1.1.1.1 and 9.9.9.9.",
            command: nil),
        CheckGuideEntry(id: "network.wifi.security", name: "Wi-Fi Security", category: .network, severity: "High",
            whatItChecks: "Whether your current Wi-Fi connection uses WPA2 or WPA3 encryption.",
            whyItMatters: "Open or WEP networks transmit your traffic unencrypted — anyone nearby can read it.",
            howToFix: "Connect to a WPA2/WPA3 network. If your router uses WEP, upgrade its security settings.",
            command: nil),
        CheckGuideEntry(id: "network.wifi.open", name: "Saved Open Wi-Fi", category: .network, severity: "Medium",
            whatItChecks: "Whether you have saved (remembered) open Wi-Fi networks that your Mac will auto-join.",
            whyItMatters: "Your Mac will automatically connect to remembered open networks, which can be spoofed by attackers.",
            howToFix: "System Settings > Network > Wi-Fi > Advanced > remove any open networks.",
            command: nil),
        CheckGuideEntry(id: "network.wakeonlan", name: "Wake on LAN", category: .network, severity: "Low",
            whatItChecks: "Whether your Mac can be woken remotely via network magic packet.",
            whyItMatters: "Wake-on-LAN extends the window during which your Mac is accessible to network attacks.",
            howToFix: "System Settings > Energy > disable 'Wake for network access'. Or use the Fix button.",
            command: "sudo pmset -a womp 0"),
        CheckGuideEntry(id: "network.sysctl", name: "Network Stack Hardening", category: .network, severity: "Medium",
            whatItChecks: "Whether BSD-level network parameters are set to secure values (IP forwarding, ICMP redirects, blackhole).",
            whyItMatters: "These kernel parameters control how your Mac handles unexpected network traffic at the lowest level.",
            howToFix: "Use the Fix button to set all parameters at once. Changes persist until restart.",
            command: "sudo sysctl -w net.inet.ip.forwarding=0 net.inet.ip.redirect=0 net.inet.tcp.blackhole=2 net.inet.udp.blackhole=1"),
        CheckGuideEntry(id: "network.promiscuous", name: "Promiscuous Interface", category: .network, severity: "High",
            whatItChecks: "Whether any network interface is in promiscuous mode (capturing all traffic).",
            whyItMatters: "Promiscuous mode means something is sniffing all network traffic — this is either intentional (packet capture tool) or a sign of compromise.",
            howToFix: "Check what's running with: lsof -i | grep PROMISC. Stop any packet capture tools you don't recognize.",
            command: nil),
        CheckGuideEntry(id: "network.httpd", name: "HTTP Server", category: .network, severity: "Medium",
            whatItChecks: "Whether the built-in Apache HTTP server is running.",
            whyItMatters: "A running web server exposes your Mac to HTTP-based attacks and serves content to the network.",
            howToFix: "Stop and disable the Apache HTTP server.",
            command: "sudo launchctl unload -w /System/Library/LaunchDaemons/org.apache.httpd.plist"),
        CheckGuideEntry(id: "network.nfsd", name: "NFS Server", category: .network, severity: "Medium",
            whatItChecks: "Whether the NFS server daemon is running.",
            whyItMatters: "NFS exports parts of your filesystem to the network, often without strong authentication.",
            howToFix: "Stop the NFS server.",
            command: "sudo nfsd stop"),
        CheckGuideEntry(id: "network.powernap", name: "Power Nap", category: .network, severity: "Low",
            whatItChecks: "Whether Power Nap is disabled.",
            whyItMatters: "Power Nap periodically wakes your Mac to check for updates and email, increasing the window for network attacks.",
            howToFix: "Disable Power Nap via power management settings.",
            command: "sudo pmset -a powernap 0"),

        // ── Privacy ─────────────────────────────────────────────────
        CheckGuideEntry(id: "privacy.analytics", name: "Crash & Usage Analytics", category: .privacy, severity: "Low",
            whatItChecks: "Whether diagnostic and usage data is shared with Apple.",
            whyItMatters: "Analytics data includes information about your usage patterns and crash reports.",
            howToFix: "System Settings > Privacy & Security > Analytics & Improvements > disable all sharing.",
            command: nil),
        CheckGuideEntry(id: "privacy.safari.suggestions", name: "Safari Suggestions", category: .privacy, severity: "Low",
            whatItChecks: "Whether Safari sends partial search queries to Apple as you type.",
            whyItMatters: "Every keystroke in the search bar is sent to Apple's servers for suggestion processing.",
            howToFix: "Safari > Settings > Search > disable 'Include search engine suggestions'. Or use the Fix button.",
            command: "defaults write com.apple.Safari SuppressSearchSuggestions -bool true"),
        CheckGuideEntry(id: "privacy.siri", name: "Siri", category: .privacy, severity: "Low",
            whatItChecks: "Whether Siri is enabled.",
            whyItMatters: "Siri sends voice and text data to Apple servers for processing. Disabling it reduces data sharing.",
            howToFix: "System Settings > Siri & Spotlight > disable Siri. Or use the Fix button.",
            command: "defaults write com.apple.assistant.support 'Assistant Enabled' -bool false"),
        CheckGuideEntry(id: "privacy.lockdown", name: "Lockdown Mode", category: .privacy, severity: "Info",
            whatItChecks: "Whether Lockdown Mode is enabled (macOS 13+).",
            whyItMatters: "Lockdown Mode dramatically reduces attack surface by disabling complex features exploited in targeted attacks.",
            howToFix: "System Settings > Privacy & Security > Lockdown Mode > Turn On. Only for users facing sophisticated threats.",
            command: nil),
        CheckGuideEntry(id: "privacy.tcc", name: "TCC Permission Grants", category: .privacy, severity: "Medium",
            whatItChecks: "Which apps have been granted access to camera, microphone, screen recording, and full disk access.",
            whyItMatters: "Accumulated permission grants from old or untrusted apps can expose sensitive data.",
            howToFix: "System Settings > Privacy & Security > review Camera, Microphone, Screen Recording, Full Disk Access. Remove apps you no longer use.",
            command: nil),
        CheckGuideEntry(id: "privacy.ai.external", name: "External AI Extensions", category: .privacy, severity: "Medium",
            whatItChecks: "Whether external third-party AI integrations are disabled.",
            whyItMatters: "External AI extensions can send your data to third-party services for processing.",
            howToFix: "System Settings > Apple Intelligence & Siri > disable external AI extensions.",
            command: nil),
        CheckGuideEntry(id: "privacy.ai.writingtools", name: "Writing Tools", category: .privacy, severity: "Low",
            whatItChecks: "Whether Apple Writing Tools are disabled.",
            whyItMatters: "Writing Tools process your text via Apple servers, sending document content off-device.",
            howToFix: "System Settings > Apple Intelligence & Siri > disable Writing Tools.",
            command: nil),
        CheckGuideEntry(id: "privacy.ai.mailsummary", name: "Mail Summary", category: .privacy, severity: "Low",
            whatItChecks: "Whether Mail AI summaries are disabled.",
            whyItMatters: "AI mail summaries process your email content, which may include sensitive information.",
            howToFix: "Mail > Settings > disable AI summary features.",
            command: nil),
        CheckGuideEntry(id: "privacy.ai.transcription", name: "Notes Transcription", category: .privacy, severity: "Low",
            whatItChecks: "Whether Notes AI transcription is disabled.",
            whyItMatters: "AI transcription processes spoken content from your notes, sending audio data for analysis.",
            howToFix: "Notes > Settings > disable AI transcription features.",
            command: nil),
        CheckGuideEntry(id: "privacy.dictation", name: "On-Device Dictation", category: .privacy, severity: "Low",
            whatItChecks: "Whether dictation uses on-device processing instead of sending audio to Apple.",
            whyItMatters: "Off-device dictation sends your voice recordings to Apple servers for transcription.",
            howToFix: "System Settings > Keyboard > Dictation > ensure on-device processing is enabled.",
            command: nil),
        CheckGuideEntry(id: "privacy.siri.improve", name: "Siri Data Sharing", category: .privacy, severity: "Low",
            whatItChecks: "Whether Siri audio sharing is opted out.",
            whyItMatters: "When opted in, Apple employees may review your Siri voice recordings for quality improvement.",
            howToFix: "System Settings > Privacy & Security > Analytics & Improvements > disable 'Improve Siri & Dictation'.",
            command: nil),
        CheckGuideEntry(id: "privacy.assistivevoice", name: "Assistive Voice Sharing", category: .privacy, severity: "Low",
            whatItChecks: "Whether assistive voice data sharing is opted out.",
            whyItMatters: "Voice data sharing sends audio samples to Apple for accessibility feature improvement.",
            howToFix: "System Settings > Privacy & Security > Analytics & Improvements > disable voice sharing.",
            command: nil),
        CheckGuideEntry(id: "privacy.advertising", name: "Personalized Advertising", category: .privacy, severity: "Low",
            whatItChecks: "Whether personalized Apple advertising is disabled.",
            whyItMatters: "Apple uses your data to target ads in the App Store, News, and Stocks apps.",
            howToFix: "Disable personalized ads via Apple Advertising settings.",
            command: "defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false"),
        CheckGuideEntry(id: "privacy.search.improve", name: "Search Data Sharing", category: .privacy, severity: "Low",
            whatItChecks: "Whether Spotlight and Safari search queries are shared with Apple.",
            whyItMatters: "Search queries sent to Apple reveal your interests and browsing intent.",
            howToFix: "System Settings > Privacy & Security > Analytics & Improvements > disable search sharing.",
            command: nil),

        // ── Applications ────────────────────────────────────────────
        CheckGuideEntry(id: "apps.safari.autoopen", name: "Safari Auto-Open Downloads", category: .applications, severity: "Medium",
            whatItChecks: "Whether Safari's auto-open safe downloads feature is disabled.",
            whyItMatters: "Auto-opening downloads could execute malicious content disguised as safe file types.",
            howToFix: "Safari > Settings > General > uncheck 'Open safe files after downloading'.",
            command: nil),
        CheckGuideEntry(id: "apps.safari.fraudwarning", name: "Safari Fraud Warning", category: .applications, severity: "Medium",
            whatItChecks: "Whether Safari's fraudulent website warning is enabled.",
            whyItMatters: "Fraud warnings protect you from phishing sites that imitate legitimate services.",
            howToFix: "Safari > Settings > Security > enable 'Warn when visiting a fraudulent website'.",
            command: nil),
        CheckGuideEntry(id: "apps.safari.crosssite", name: "Safari Cross-Site Tracking", category: .applications, severity: "Medium",
            whatItChecks: "Whether Safari prevents cross-site tracking.",
            whyItMatters: "Cross-site tracking allows advertisers to follow your browsing activity across websites.",
            howToFix: "Safari > Settings > Privacy > enable 'Prevent cross-site tracking'.",
            command: nil),
        CheckGuideEntry(id: "apps.safari.adprivacy", name: "Safari Ad Privacy", category: .applications, severity: "Low",
            whatItChecks: "Whether privacy-preserving ad measurement is configured.",
            whyItMatters: "Ad measurement allows websites to track ad conversions, which can reveal browsing patterns.",
            howToFix: "Safari > Settings > Privacy > review ad privacy measurement settings.",
            command: nil),
        CheckGuideEntry(id: "apps.safari.fullurl", name: "Safari Full URL", category: .applications, severity: "Low",
            whatItChecks: "Whether Safari shows the full URL in the address bar.",
            whyItMatters: "Seeing the full URL helps you detect phishing sites with misleading subdomains.",
            howToFix: "Safari > Settings > Advanced > enable 'Show full website address'.",
            command: nil),
        CheckGuideEntry(id: "apps.safari.statusbar", name: "Safari Status Bar", category: .applications, severity: "Low",
            whatItChecks: "Whether Safari's status bar is visible to show link destinations.",
            whyItMatters: "The status bar reveals where links actually point before you click them, helping detect malicious URLs.",
            howToFix: "Safari > View > Show Status Bar.",
            command: nil),
        CheckGuideEntry(id: "apps.terminal.securekeyboard", name: "Terminal Secure Keyboard", category: .applications, severity: "Medium",
            whatItChecks: "Whether Terminal's secure keyboard entry is enabled.",
            whyItMatters: "Without secure keyboard entry, other apps can intercept keystrokes typed into Terminal, including passwords.",
            howToFix: "Terminal > Settings > Keyboard > enable 'Secure keyboard entry'. Or use Terminal > Secure Keyboard Entry in the menu bar.",
            command: nil),
        CheckGuideEntry(id: "apps.fileextensions", name: "Filename Extensions", category: .applications, severity: "Low",
            whatItChecks: "Whether all filename extensions are visible in Finder.",
            whyItMatters: "Hidden extensions let malicious files disguise themselves (e.g., 'document.pdf.app' appears as 'document.pdf').",
            howToFix: "Finder > Settings > Advanced > enable 'Show all filename extensions'.",
            command: nil),
    ]
}
