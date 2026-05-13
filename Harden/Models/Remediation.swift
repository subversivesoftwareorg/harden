import Foundation

struct Remediation {
    let label: String
    let command: String
    let requiresSudo: Bool
    let confirmation: String

    /// All known remediations keyed by check ID.
    static let catalog: [String: Remediation] = [
        // ── Firewall ────────────────────────────────────────────────
        "firewall.enabled": Remediation(
            label: "Enable Firewall",
            command: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            requiresSudo: true,
            confirmation: "This will enable the macOS Application Firewall to block unauthorized incoming connections."
        ),
        "firewall.stealth": Remediation(
            label: "Enable Stealth Mode",
            command: "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            requiresSudo: true,
            confirmation: "This will stop your Mac from responding to ping and port scan probes."
        ),
        "firewall.logging": Remediation(
            label: "Enable Firewall Logging",
            command: "/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on",
            requiresSudo: true,
            confirmation: "This will enable logging of blocked connection attempts."
        ),

        // ── System Protection ───────────────────────────────────────
        "system.autoupdate.check": Remediation(
            label: "Enable Update Checks",
            command: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
            requiresSudo: true,
            confirmation: "This will enable automatic checking for software updates."
        ),
        "system.autoupdate.download": Remediation(
            label: "Enable Auto-Download",
            command: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
            requiresSudo: true,
            confirmation: "This will enable automatic downloading of available updates."
        ),
        "system.autoupdate.install": Remediation(
            label: "Enable Auto-Install",
            command: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true",
            requiresSudo: true,
            confirmation: "This will enable automatic installation of macOS updates."
        ),
        "system.autoupdate.critical": Remediation(
            label: "Enable Security Updates",
            command: "defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true",
            requiresSudo: true,
            confirmation: "This will enable automatic installation of critical security patches."
        ),
        "system.autoupdate.configdata": Remediation(
            label: "Enable Config Data Updates",
            command: "defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true",
            requiresSudo: true,
            confirmation: "This will enable automatic installation of system data files and security updates like XProtect definitions."
        ),
        "system.autoupdate.appstore": Remediation(
            label: "Enable App Store Updates",
            command: "defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true",
            requiresSudo: true,
            confirmation: "This will enable automatic updates for apps installed from the App Store."
        ),
        "system.ntp": Remediation(
            label: "Enable Network Time",
            command: "systemsetup -setusingnetworktime on",
            requiresSudo: true,
            confirmation: "This will synchronize your Mac's clock with Apple's time servers."
        ),

        // ── Sharing ─────────────────────────────────────────────────
        "sharing.remotelogin": Remediation(
            label: "Disable Remote Login",
            command: "systemsetup -setremotelogin off",
            requiresSudo: true,
            confirmation: "This will disable SSH access to your Mac. You will no longer be able to connect remotely via Terminal."
        ),
        "sharing.bluetooth": Remediation(
            label: "Disable Bluetooth Sharing",
            command: "defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false",
            requiresSudo: false,
            confirmation: "This will prevent other devices from sending files to your Mac via Bluetooth."
        ),
        "sharing.airdrop": Remediation(
            label: "Disable AirDrop",
            command: "defaults write com.apple.NetworkBrowser DisableAirDrop -bool true",
            requiresSudo: false,
            confirmation: "This will disable AirDrop so nearby devices cannot send you files."
        ),

        // ── Authentication ──────────────────────────────────────────
        "auth.password.sleep": Remediation(
            label: "Require Password After Sleep",
            command: "defaults write com.apple.screensaver askForPassword -int 1",
            requiresSudo: false,
            confirmation: "This will require your password immediately when waking from sleep or screensaver."
        ),
        "auth.lockdelay": Remediation(
            label: "Set Immediate Lock",
            command: "defaults write com.apple.screensaver askForPasswordDelay -int 0",
            requiresSudo: false,
            confirmation: "This will remove the delay before a password is required, making the lock immediate."
        ),
        "auth.idle.timeout": Remediation(
            label: "Set 5-Minute Screensaver",
            command: "defaults write com.apple.screensaver idleTime -int 300",
            requiresSudo: false,
            confirmation: "This will set the screensaver to activate after 5 minutes of inactivity."
        ),
        "auth.guest": Remediation(
            label: "Disable Guest Account",
            command: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false",
            requiresSudo: true,
            confirmation: "This will disable the guest account. Note: if you use Find My Mac, Apple recommends keeping the guest account enabled."
        ),
        "auth.loginwindow.style": Remediation(
            label: "Hide User List at Login",
            command: "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true",
            requiresSudo: true,
            confirmation: "This will show a name and password field at the login window instead of a list of user accounts."
        ),
        "auth.homedir.permissions": Remediation(
            label: "Tighten Home Permissions",
            command: "chmod 750 ~",
            requiresSudo: false,
            confirmation: "This will set your home directory to owner + group read only, preventing other users from browsing your files."
        ),

        // ── Network ─────────────────────────────────────────────────
        "network.wakeonlan": Remediation(
            label: "Disable Wake on LAN",
            command: "pmset -a womp 0",
            requiresSudo: true,
            confirmation: "This will prevent your Mac from being woken remotely over the network."
        ),
        "network.sysctl": Remediation(
            label: "Harden Network Stack",
            command: "sysctl -w net.inet.ip.forwarding=0 net.inet.ip.redirect=0 net.inet.tcp.blackhole=2 net.inet.udp.blackhole=1",
            requiresSudo: true,
            confirmation: "This will disable IP forwarding, ignore ICMP redirects, and enable TCP/UDP blackhole mode. These changes persist until restart."
        ),

        // ── Privacy ─────────────────────────────────────────────────
        "privacy.siri": Remediation(
            label: "Disable Siri",
            command: "defaults write com.apple.assistant.support 'Assistant Enabled' -bool false",
            requiresSudo: false,
            confirmation: "This will disable Siri. Voice and text data will no longer be sent to Apple for processing."
        ),
        "privacy.safari.suggestions": Remediation(
            label: "Disable Safari Suggestions",
            command: "defaults write com.apple.Safari SuppressSearchSuggestions -bool true",
            requiresSudo: false,
            confirmation: "This will stop Safari from sending partial search queries to Apple as you type."
        ),
    ]
}
