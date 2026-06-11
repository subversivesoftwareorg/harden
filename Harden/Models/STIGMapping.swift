import Foundation

/// Central catalog mapping Harden check IDs to DISA STIG references.
///
/// All STIG IDs verified against Apple macOS 15 (Sequoia) STIG V1R7
/// via stigaview.com (2026-04-07).
///
/// Source: Defense Information Systems Agency (DISA).
/// Shell-based compliance checks informed by the NIST macOS Security
/// Compliance Project (mSCP).
///
/// - DISA STIG Downloads: https://public.cyber.mil/stigs/downloads/
/// - NIST mSCP: https://github.com/usnistgov/macos_security
/// - STIG Viewer: https://stigaview.com/products/macos15/
enum STIGMapping {

    static let stigVersion = "Apple macOS 15 Sequoia STIG V1R7"

    static let catalog: [String: [STIGReference]] = [
        // ── System Protection ──────────────────────────────────────
        "system.sip": [
            STIGReference(id: "APPL-15-005001", title: "Ensure System Integrity Protection is enabled", severity: "CAT I"),
        ],
        "system.gatekeeper": [
            STIGReference(id: "APPL-15-002064", title: "Enable Gatekeeper", severity: "CAT I"),
            STIGReference(id: "APPL-15-002060", title: "Block applications from unidentified developers", severity: "CAT I"),
        ],
        "system.secureboot": [
            STIGReference(id: "APPL-15-005100", title: "Ensure Secure Boot level is set to full", severity: "CAT II"),
        ],
        "system.ntp": [
            STIGReference(id: "APPL-15-000014", title: "Enforce time synchronization", severity: "CAT II"),
        ],
        "system.autoupdate.configdata": [
            STIGReference(id: "APPL-15-005130", title: "Enforce installation of XProtect Remediator and Gatekeeper updates automatically", severity: "CAT II"),
        ],
        "system.xprotect": [
            STIGReference(id: "APPL-15-005130", title: "Enforce installation of XProtect Remediator and Gatekeeper updates automatically", severity: "CAT II"),
        ],
        "system.auditd": [
            STIGReference(id: "APPL-15-001003", title: "Enable security auditing", severity: "CAT II"),
        ],
        "system.auditflags": [
            STIGReference(id: "APPL-15-001001", title: "Audit all administrative action events", severity: "CAT II"),
        ],
        "system.auditperms": [
            STIGReference(id: "APPL-15-000030", title: "Configure audit log files to not contain ACLs", severity: "CAT II"),
            STIGReference(id: "APPL-15-000031", title: "Configure the audit log folder to not contain ACLs", severity: "CAT II"),
        ],

        // ── Firewall ───────────────────────────────────────────────
        "firewall.enabled": [
            STIGReference(id: "APPL-15-005050", title: "Enable macOS Application Firewall", severity: "CAT II"),
        ],
        // Note: firewall.stealth has no macOS 15 STIG rule
        // Note: firewall.logging has no macOS 15 STIG rule

        // ── Encryption ─────────────────────────────────────────────
        "encryption.filevault": [
            STIGReference(id: "APPL-15-005020", title: "Enforce FileVault", severity: "CAT I"),
        ],

        // ── Sharing Services ───────────────────────────────────────
        "sharing.remotelogin": [
            STIGReference(id: "APPL-15-001100", title: "Disable root login for SSH", severity: "CAT II"),
            STIGReference(id: "APPL-15-001150", title: "Disable password authentication for SSH", severity: "CAT I"),
        ],
        "sharing.screensharing": [
            STIGReference(id: "APPL-15-002050", title: "Disable Screen Sharing and Apple Remote Desktop", severity: "CAT II"),
        ],
        "sharing.filesharing": [
            STIGReference(id: "APPL-15-002001", title: "Disable Server Message Block sharing", severity: "CAT II"),
        ],
        "sharing.remotemanagement": [
            STIGReference(id: "APPL-15-002250", title: "Disable Remote Management", severity: "CAT II"),
        ],
        "sharing.printersharing": [
            STIGReference(id: "APPL-15-002240", title: "Disable Printer Sharing", severity: "CAT II"),
        ],
        "sharing.bluetooth": [
            STIGReference(id: "APPL-15-002110", title: "Disable Bluetooth Sharing", severity: "CAT II"),
        ],
        "sharing.airdrop": [
            STIGReference(id: "APPL-15-002009", title: "Disable AirDrop", severity: "CAT II"),
        ],
        "sharing.insecure": [
            STIGReference(id: "APPL-15-002038", title: "Disable Trivial File Transfer Protocol service", severity: "CAT I"),
        ],
        "sharing.ssh.hardening": [
            STIGReference(id: "APPL-15-000051", title: "Configure SSHD ClientAliveInterval to 900", severity: "CAT II"),
            STIGReference(id: "APPL-15-000052", title: "Configure SSHD ClientAliveCountMax to 1", severity: "CAT II"),
            STIGReference(id: "APPL-15-001100", title: "Disable root login for SSH", severity: "CAT II"),
            STIGReference(id: "APPL-15-001150", title: "Disable password authentication for SSH", severity: "CAT I"),
        ],
        "sharing.remoteappleevents": [
            STIGReference(id: "APPL-15-002022", title: "Disable Remote Apple Events", severity: "CAT II"),
        ],
        "sharing.internetsharing": [
            STIGReference(id: "APPL-15-002007", title: "Disable Internet Sharing", severity: "CAT II"),
        ],
        "sharing.mediasharing": [
            STIGReference(id: "APPL-15-002100", title: "Disable Media Sharing", severity: "CAT II"),
        ],
        "sharing.airplayreceiver": [
            STIGReference(id: "APPL-15-002080", title: "Disable Airplay Receiver", severity: "CAT II"),
        ],
        "sharing.contentcaching": [
            STIGReference(id: "APPL-15-002140", title: "Disable Content Caching service", severity: "CAT II"),
        ],

        // ── Authentication ─────────────────────────────────────────
        "auth.autologin": [
            STIGReference(id: "APPL-15-002066", title: "Disable unattended or automatic login to the system", severity: "CAT I"),
        ],
        "auth.password.sleep": [
            STIGReference(id: "APPL-15-000002", title: "Screen saver must require password to unlock", severity: "CAT II"),
        ],
        "auth.lockdelay": [
            STIGReference(id: "APPL-15-000003", title: "Password delay after screen saver must be 5 seconds or less", severity: "CAT II"),
        ],
        "auth.idle.timeout": [
            STIGReference(id: "APPL-15-000070", title: "Screen saver timeout must not exceed 900 seconds", severity: "CAT II"),
        ],
        "auth.guest": [
            STIGReference(id: "APPL-15-002063", title: "Disable the guest account", severity: "CAT II"),
        ],
        "auth.passwordpolicy": [
            STIGReference(id: "APPL-15-003010", title: "Minimum password length must be configured", severity: "CAT II"),
            STIGReference(id: "APPL-15-003007", title: "Passwords contain a minimum of one numeric character", severity: "CAT II"),
            STIGReference(id: "APPL-15-003011", title: "Passwords contain a minimum of one special character", severity: "CAT II"),
            STIGReference(id: "APPL-15-003060", title: "Passwords contain one lowercase and one uppercase character", severity: "CAT II"),
            STIGReference(id: "APPL-15-000022", title: "Limit consecutive failed login attempts to three", severity: "CAT II"),
            STIGReference(id: "APPL-15-000060", title: "Set account lockout time to 15 minutes", severity: "CAT II"),
        ],
        "auth.filevaultautologin": [
            STIGReference(id: "APPL-15-000033", title: "Disable FileVault automatic login", severity: "CAT II"),
        ],
        "auth.hotcorners": [
            STIGReference(id: "APPL-15-000007", title: "Hot corners must not disable the screen saver", severity: "CAT II"),
        ],
        "auth.consolelogin": [
            STIGReference(id: "APPL-15-000090", title: "Login to other user sessions must be disabled", severity: "CAT II"),
        ],
        "auth.applewatch": [
            STIGReference(id: "APPL-15-000001", title: "Apple Watch must not be allowed to unlock the session", severity: "CAT II"),
        ],
        "auth.homedir.permissions": [
            STIGReference(id: "APPL-15-002068", title: "Secure users' home folders", severity: "CAT II"),
        ],
        "auth.loginwindow.style": [
            STIGReference(id: "APPL-15-005052", title: "Configure login window to prompt for username and password", severity: "CAT II"),
        ],

        // ── Privacy ────────────────────────────────────────────────
        "privacy.siri": [
            STIGReference(id: "APPL-15-002020", title: "Disable Siri", severity: "CAT II"),
        ],
        "privacy.analytics": [
            STIGReference(id: "APPL-15-002021", title: "Disable sending diagnostic and usage data to Apple", severity: "CAT II"),
        ],
    ]
}
