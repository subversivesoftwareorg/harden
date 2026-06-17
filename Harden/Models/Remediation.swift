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
        "system.rootdisabled": Remediation(
            label: "Disable Root Account",
            command: "dscl . -create /Users/root UserShell /usr/bin/false",
            requiresSudo: true,
            confirmation: "This will disable the root account, preventing direct root login."
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
        "sharing.remoteappleevents": Remediation(
            label: "Disable Remote Apple Events",
            command: "systemsetup -setremoteappleevents off",
            requiresSudo: true,
            confirmation: "This will prevent other computers from sending Apple Events to your Mac."
        ),
        "sharing.mediasharing": Remediation(
            label: "Disable Media Sharing",
            command: "defaults write com.apple.amp.mediasharingd home-sharing-enabled -bool false",
            requiresSudo: false,
            confirmation: "This will stop sharing your media libraries on the network."
        ),
        "sharing.airplayreceiver": Remediation(
            label: "Disable AirPlay Receiver",
            command: "defaults write com.apple.controlcenter AirplayRecieverEnabled -bool false",
            requiresSudo: false,
            confirmation: "This will prevent other devices from streaming to this Mac."
        ),
        "sharing.contentcaching": Remediation(
            label: "Disable Content Caching",
            command: "AssetCacheManagerUtil deactivate 2>/dev/null || defaults write /Library/Preferences/com.apple.AssetCache.plist Activated -bool false",
            requiresSudo: true,
            confirmation: "This will stop caching Apple content on this Mac."
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
        "auth.filevaultautologin": Remediation(
            label: "Disable FileVault Auto-Login",
            command: "defaults write com.apple.loginwindow DisableFDEAutoLogin -bool true",
            requiresSudo: true,
            confirmation: "This will require password entry at the FileVault pre-boot screen."
        ),
        "auth.consolelogin": Remediation(
            label: "Disable Console Login",
            command: "defaults write /Library/Preferences/com.apple.loginwindow DisableConsoleAccess -bool true",
            requiresSudo: true,
            confirmation: "This will prevent switching to a text console at the login window."
        ),
        "auth.passwordhints": Remediation(
            label: "Disable Password Hints",
            command: "defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0",
            requiresSudo: true,
            confirmation: "This will prevent password hints from appearing at the login window."
        ),
        "auth.guest.smb": Remediation(
            label: "Disable Guest SMB Access",
            command: "defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false",
            requiresSudo: true,
            confirmation: "This will prevent unauthenticated users from accessing shared folders."
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
        "network.powernap": Remediation(
            label: "Disable Power Nap",
            command: "pmset -a powernap 0",
            requiresSudo: true,
            confirmation: "This will stop your Mac from waking periodically to check email and updates."
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
        "privacy.advertising": Remediation(
            label: "Disable Personalized Ads",
            command: "defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false",
            requiresSudo: false,
            confirmation: "This will opt out of Apple's personalized advertising."
        ),
        "privacy.analytics": Remediation(
            label: "Disable Diagnostics Sharing",
            command: "defaults write '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit -bool false",
            requiresSudo: true,
            confirmation: "This will stop sharing diagnostic and usage data with Apple."
        ),

        // ── Applications ───────────────────────────────────────────
        "apps.terminal.securekeyboard": Remediation(
            label: "Enable Secure Keyboard Entry",
            command: "defaults write com.apple.Terminal SecureKeyboardEntry -bool true",
            requiresSudo: false,
            confirmation: "This will prevent other applications from intercepting keystrokes in Terminal."
        ),
        "apps.fileextensions": Remediation(
            label: "Show All File Extensions",
            command: "defaults write NSGlobalDomain AppleShowAllExtensions -bool true",
            requiresSudo: false,
            confirmation: "This will show filename extensions for all files in Finder."
        ),
        "apps.safari.autoopen": Remediation(
            label: "Disable Safari Auto-Open",
            command: "defaults write com.apple.Safari AutoOpenSafeDownloads -bool false",
            requiresSudo: false,
            confirmation: "This will stop Safari from automatically opening downloaded files."
        ),
    ]
}
