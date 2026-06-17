import Foundation

struct STIGReference: Codable, Identifiable {
    let id: String
    let title: String
    let severity: String
}

struct CISReference: Codable, Identifiable {
    let id: String
    let title: String
    let level: String
}

enum CheckStatus: String, Codable {
    case pass
    case fail
    case warning
    case info
    case unknown
}

enum CheckSeverity: Int, Codable, Comparable {
    case critical = 0
    case high = 1
    case medium = 2
    case low = 3
    case info = 4

    static func < (lhs: CheckSeverity, rhs: CheckSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .critical: "Critical"
        case .high: "High"
        case .medium: "Medium"
        case .low: "Low"
        case .info: "Info"
        }
    }

    var weight: Int {
        switch self {
        case .critical: 25
        case .high: 15
        case .medium: 10
        case .low: 5
        case .info: 0
        }
    }
}

struct SecurityCheck: Identifiable {
    let id: String
    let name: String
    let description: String
    let category: CheckCategory
    let severity: CheckSeverity
    var status: CheckStatus = .unknown
    var details: String = ""
    var recommendation: String = ""
    var stigReferences: [STIGReference] = []
    var cisReferences: [CISReference] = []

    /// Deep link to the relevant System Settings pane, if available.
    var settingsURL: URL? {
        let mapping: [String: String] = [
            // Firewall
            "firewall.enabled": "x-apple.systempreferences:com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension",
            "firewall.stealth": "x-apple.systempreferences:com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension",
            // Encryption
            "encryption.filevault": "x-apple.systempreferences:com.apple.preference.security?FileVault",
            // System Protection
            "system.gatekeeper": "x-apple.systempreferences:com.apple.preference.security?General",
            "system.autoupdate.check": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
            "system.autoupdate.download": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
            "system.autoupdate.install": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
            "system.autoupdate.critical": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
            "system.autoupdate.configdata": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
            "system.autoupdate.appstore": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
            "system.findmymac": "x-apple.systempreferences:com.apple.preferences.AppleIDPrefPane",
            // Sharing
            "sharing.remotelogin": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.screensharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.filesharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.remotemanagement": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.printersharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.bluetooth": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            // Authentication
            "auth.autologin": "x-apple.systempreferences:com.apple.preferences.users",
            "auth.password.sleep": "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension",
            "auth.lockdelay": "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension",
            "auth.idle.timeout": "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension",
            "auth.guest": "x-apple.systempreferences:com.apple.preferences.users",
            // Privacy
            "privacy.analytics": "x-apple.systempreferences:com.apple.preference.security?Privacy_Diagnostics",
            "privacy.siri": "x-apple.systempreferences:com.apple.Siri-Settings.extension",
            "privacy.lockdown": "x-apple.systempreferences:com.apple.preference.security?Privacy",
            "privacy.tcc": "x-apple.systempreferences:com.apple.preference.security?Privacy",
            // Network
            "network.dns": "x-apple.systempreferences:com.apple.wifi-settings-extension",
            // STIG additions
            "sharing.remoteappleevents": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.internetsharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.mediasharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "sharing.airplayreceiver": "x-apple.systempreferences:com.apple.AirDrop-Handoff-Settings.extension",
            "sharing.contentcaching": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
            "auth.filevaultautologin": "x-apple.systempreferences:com.apple.preference.security?FileVault",
            "auth.hotcorners": "x-apple.systempreferences:com.apple.Desktop-Settings.extension",
            "auth.consolelogin": "x-apple.systempreferences:com.apple.preferences.users",
            "auth.applewatch": "x-apple.systempreferences:com.apple.Touch-ID-Settings.extension",
        ]
        guard let urlString = mapping[id] else { return nil }
        return URL(string: urlString)
    }
}
