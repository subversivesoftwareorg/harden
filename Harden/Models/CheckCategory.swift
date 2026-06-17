import SwiftUI

enum CheckCategory: String, CaseIterable, Identifiable {
    case firewall = "Firewall"
    case encryption = "Encryption"
    case systemProtection = "System Protection"
    case sharing = "Sharing Services"
    case authentication = "Authentication"
    case network = "Network"
    case privacy = "Privacy"
    case applications = "Applications"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .firewall: "flame.fill"
        case .encryption: "lock.shield.fill"
        case .systemProtection: "checkmark.shield.fill"
        case .sharing: "shareplay"
        case .authentication: "person.badge.key.fill"
        case .network: "network"
        case .privacy: "eye.slash.fill"
        case .applications: "app.badge.checkmark"
        }
    }

    var color: Color {
        switch self {
        case .firewall: .orange
        case .encryption: .blue
        case .systemProtection: .purple
        case .sharing: .green
        case .authentication: .red
        case .network: .cyan
        case .privacy: .indigo
        case .applications: .mint
        }
    }
}
