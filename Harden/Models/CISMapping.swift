import Foundation

/// Central catalog mapping Harden check IDs to CIS Benchmark references.
///
/// All rule IDs verified against CIS Apple macOS 15.0 Sequoia
/// Benchmark v1.1.0 (2025-06-02).
///
/// Source: Center for Internet Security (CIS).
/// Licensed under CC BY-NC-SA 4.0 — titles below are original
/// paraphrases, not verbatim CIS text.
///
/// - CIS Benchmarks: https://www.cisecurity.org/benchmark/apple_os
enum CISMapping {

    static let cisVersion = "CIS Apple macOS 15.0 Sequoia Benchmark v1.1.0"

    static let catalog: [String: [CISReference]] = [
        // ── Section 1 · Updates ───────────────────────────────────
        "system.osversion": [
            CISReference(id: "1.1", title: "Verify all Apple-supplied software is up to date", level: "L1"),
        ],
        "system.autoupdate.check": [
            CISReference(id: "1.2", title: "Turn on automatic checking for software updates", level: "L1"),
        ],
        "system.autoupdate.download": [
            CISReference(id: "1.3", title: "Enable automatic download of new updates", level: "L1"),
        ],
        "system.autoupdate.install": [
            CISReference(id: "1.4", title: "Enable automatic installation of macOS updates", level: "L1"),
        ],
        "system.autoupdate.appstore": [
            CISReference(id: "1.5", title: "Enable automatic App Store update installation", level: "L1"),
        ],
        "system.autoupdate.critical": [
            CISReference(id: "1.6", title: "Enable automatic installation of security responses and system data files", level: "L1"),
        ],
        "system.autoupdate.configdata": [
            CISReference(id: "1.6", title: "Enable automatic installation of security responses and system data files", level: "L1"),
        ],

        // ── Section 2 · System Settings ──────────────────────────
        // 2.2 – Firewall
        "firewall.enabled": [
            CISReference(id: "2.2.1", title: "Enable the built-in application firewall", level: "L1"),
        ],
        "firewall.stealth": [
            CISReference(id: "2.2.2", title: "Enable firewall stealth mode to ignore unsolicited requests", level: "L1"),
        ],

        // 2.3 – General / Sharing
        "sharing.airdrop": [
            CISReference(id: "2.3.1.1", title: "Disable AirDrop when not actively transferring files", level: "L1"),
        ],
        "sharing.airplayreceiver": [
            CISReference(id: "2.3.1.2", title: "Disable the AirPlay Receiver service", level: "L1"),
        ],
        "system.ntp": [
            CISReference(id: "2.3.2.1", title: "Synchronize the clock with a network time server", level: "L1"),
        ],
        "sharing.screensharing": [
            CISReference(id: "2.3.3.1", title: "Disable the Screen Sharing service", level: "L1"),
        ],
        "sharing.filesharing": [
            CISReference(id: "2.3.3.2", title: "Disable the File Sharing service", level: "L1"),
        ],
        "sharing.printersharing": [
            CISReference(id: "2.3.3.3", title: "Disable Printer Sharing", level: "L1"),
        ],
        "sharing.remotelogin": [
            CISReference(id: "2.3.3.4", title: "Disable the Remote Login (SSH) service", level: "L1"),
        ],
        "sharing.remotemanagement": [
            CISReference(id: "2.3.3.5", title: "Disable the Remote Management service", level: "L1"),
        ],
        "sharing.remoteappleevents": [
            CISReference(id: "2.3.3.6", title: "Disable Remote Apple Events", level: "L1"),
        ],
        "sharing.internetsharing": [
            CISReference(id: "2.3.3.7", title: "Disable Internet Sharing", level: "L1"),
        ],
        "sharing.contentcaching": [
            CISReference(id: "2.3.3.8", title: "Disable the Content Caching service", level: "L2"),
        ],
        "sharing.mediasharing": [
            CISReference(id: "2.3.3.9", title: "Disable Media Sharing", level: "L2"),
        ],
        "sharing.bluetooth": [
            CISReference(id: "2.3.3.10", title: "Disable Bluetooth Sharing", level: "L1"),
        ],

        // 2.3.4 – Time Machine
        "encryption.timemachine": [
            CISReference(id: "2.3.4.2", title: "Enable encryption on Time Machine backups", level: "L1"),
        ],

        // 2.5 – Apple Intelligence & Siri
        "privacy.ai.external": [
            CISReference(id: "2.5.1.1", title: "Disable external AI model requests for Apple Intelligence", level: "L1"),
        ],
        "privacy.ai.writingtools": [
            CISReference(id: "2.5.1.2", title: "Disable AI-powered Writing Tools", level: "L1"),
        ],
        "privacy.ai.mailsummary": [
            CISReference(id: "2.5.1.3", title: "Disable AI-generated Mail message summaries", level: "L1"),
        ],
        "privacy.ai.transcription": [
            CISReference(id: "2.5.1.4", title: "Disable AI-powered notification transcription", level: "L1"),
        ],
        "privacy.siri": [
            CISReference(id: "2.5.2.1", title: "Disable the Siri voice assistant", level: "L1"),
        ],

        // 2.6 – Security & Privacy
        "privacy.analytics": [
            CISReference(id: "2.6.3.1", title: "Disable sharing diagnostics and usage data with Apple", level: "L1"),
        ],
        "privacy.siri.improve": [
            CISReference(id: "2.6.3.2", title: "Disable sharing data to improve Siri and Dictation", level: "L1"),
        ],
        "privacy.assistivevoice": [
            CISReference(id: "2.6.3.3", title: "Disable sharing data to improve Assistive Voice features", level: "L1"),
        ],
        "privacy.advertising": [
            CISReference(id: "2.6.4", title: "Limit personalized advertising and tracking", level: "L1"),
        ],
        "system.gatekeeper": [
            CISReference(id: "2.6.5", title: "Restrict application sources to App Store and identified developers", level: "L1"),
        ],
        "encryption.filevault": [
            CISReference(id: "2.6.6", title: "Enable FileVault full-disk encryption", level: "L1"),
        ],
        "privacy.lockdown": [
            CISReference(id: "2.6.7", title: "Enable Lockdown Mode for high-risk environments", level: "L1"),
        ],
        "auth.systemprefs.password": [
            CISReference(id: "2.6.8", title: "Require an administrator password to change system-wide settings", level: "L1"),
        ],

        // 2.7 – Desktop & Screen Saver
        "auth.hotcorners": [
            CISReference(id: "2.7.1", title: "Prevent hot corners from disabling the screen saver", level: "L2"),
        ],

        // 2.9 – Spotlight / Search
        "privacy.search.improve": [
            CISReference(id: "2.9.1", title: "Disable sending search queries to Apple for suggestions", level: "L1"),
        ],

        // 2.10 – Energy
        "network.powernap": [
            CISReference(id: "2.10.2", title: "Disable Power Nap network activity during sleep", level: "L1"),
        ],
        "network.wakeonlan": [
            CISReference(id: "2.10.3", title: "Disable Wake for Network Access", level: "L1"),
        ],

        // 2.11 – Lock Screen
        "auth.idle.timeout": [
            CISReference(id: "2.11.1", title: "Set the screen saver inactivity timeout to a reasonable interval", level: "L1"),
        ],
        "auth.lockdelay": [
            CISReference(id: "2.11.2", title: "Require a password promptly after the screen locks", level: "L1"),
        ],
        "auth.loginwindow.style": [
            CISReference(id: "2.11.4", title: "Configure the login window to show a name and password prompt", level: "L1"),
        ],
        "auth.passwordhints": [
            CISReference(id: "2.11.5", title: "Disable display of password hints at the login window", level: "L1"),
        ],

        // 2.13 – Users & Groups
        "auth.guest": [
            CISReference(id: "2.13.1", title: "Disable the guest user account", level: "L1"),
        ],
        "auth.guest.smb": [
            CISReference(id: "2.13.2", title: "Disable guest access to SMB shared folders", level: "L1"),
        ],
        "auth.autologin": [
            CISReference(id: "2.13.3", title: "Disable automatic login", level: "L1"),
        ],

        // 2.18 – Keyboard
        "privacy.dictation": [
            CISReference(id: "2.18.1", title: "Disable cloud-based Dictation", level: "L1"),
        ],

        // ── Section 3 · Logging and Auditing ─────────────────────
        "system.auditd": [
            CISReference(id: "3.1", title: "Enable the security audit subsystem", level: "L1"),
        ],
        "system.auditflags": [
            CISReference(id: "3.2", title: "Configure comprehensive security audit flags", level: "L2"),
        ],
        "system.auditperms": [
            CISReference(id: "3.5", title: "Restrict permissions on audit log files and folders", level: "L1"),
        ],

        // ── Section 4 · Network ──────────────────────────────────
        "network.httpd": [
            CISReference(id: "4.2", title: "Disable the built-in Apache web server", level: "L1"),
        ],
        "network.nfsd": [
            CISReference(id: "4.3", title: "Disable the NFS daemon", level: "L1"),
        ],

        // ── Section 5 · System Access, Authentication and Authorization ──
        "auth.homedir.permissions": [
            CISReference(id: "5.1.1", title: "Secure home directory permissions", level: "L1"),
        ],
        "system.sip": [
            CISReference(id: "5.1.2", title: "Verify System Integrity Protection is enabled", level: "L1"),
        ],
        "system.amfi": [
            CISReference(id: "5.1.3", title: "Verify Apple Mobile File Integrity is enabled", level: "L1"),
        ],
        "system.secureboot": [
            CISReference(id: "5.1.4", title: "Verify Secure Boot is set to full security", level: "L1"),
        ],
        "system.worldwritable": [
            CISReference(id: "5.1.6", title: "Audit and remediate world-writable files in system directories", level: "L1"),
        ],
        "auth.passwordpolicy": [
            CISReference(id: "5.2.1", title: "Configure account lockout after repeated failed login attempts", level: "L1"),
            CISReference(id: "5.2.2", title: "Enforce a minimum password length", level: "L1"),
        ],
        "system.sudo.timeout": [
            CISReference(id: "5.4", title: "Reduce the sudo authentication timeout period", level: "L1"),
        ],
        "system.sudo.logging": [
            CISReference(id: "5.11", title: "Enable detailed logging for sudo commands", level: "L1"),
        ],
        "system.rootdisabled": [
            CISReference(id: "5.6", title: "Verify the root account is disabled", level: "L1"),
        ],
        "auth.guest.homefolder": [
            CISReference(id: "5.9", title: "Remove the guest home folder if it exists", level: "L1"),
        ],
        "system.malware": [
            CISReference(id: "5.10", title: "Verify XProtect malware definitions are current", level: "L1"),
        ],

        // ── Section 6 · Applications ─────────────────────────────
        "apps.fileextensions": [
            CISReference(id: "6.1.1", title: "Show all file extensions in Finder", level: "L1"),
        ],
        "apps.safari.autoopen": [
            CISReference(id: "6.3.1", title: "Disable automatic opening of downloaded files in Safari", level: "L1"),
        ],
        "apps.safari.fraudwarning": [
            CISReference(id: "6.3.3", title: "Enable Safari fraudulent website warnings", level: "L1"),
        ],
        "apps.safari.crosssite": [
            CISReference(id: "6.3.4", title: "Enable cross-site tracking prevention in Safari", level: "L1"),
        ],
        "apps.safari.adprivacy": [
            CISReference(id: "6.3.6", title: "Enable privacy-preserving ad measurement in Safari", level: "L1"),
        ],
        "apps.safari.fullurl": [
            CISReference(id: "6.3.7", title: "Show the full URL in the Safari address bar", level: "L1"),
        ],
        "apps.safari.statusbar": [
            CISReference(id: "6.3.10", title: "Display the status bar in Safari to reveal link destinations", level: "L1"),
        ],
        "apps.terminal.securekeyboard": [
            CISReference(id: "6.4.1", title: "Enable Secure Keyboard Entry in Terminal", level: "L1"),
        ],
    ]
}
