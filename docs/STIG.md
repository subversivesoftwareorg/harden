# STIG Compliance Reference

Harden maps its security checks to the **DISA Security Technical Implementation Guide (STIG) for Apple macOS 15 (Sequoia)**, the U.S. Department of Defense standard for hardening macOS endpoints.

All STIG IDs verified against V1R7 (2026-04-07) via stigaview.com.

## What is a STIG?

A STIG (Security Technical Implementation Guide) is a configuration standard published by the Defense Information Systems Agency (DISA) that provides prescriptive security guidance for information systems. STIGs are derived from NIST SP 800-53 Rev 5 security controls and are mandatory for U.S. federal systems, but widely adopted as a security benchmark across industries.

The macOS 15 STIG contains ~162 rules covering system integrity, authentication, sharing services, encryption, auditing, network configuration, and privacy.

## STIG Version

| Field | Value |
|-------|-------|
| **Title** | Apple macOS 15 (Sequoia) STIG |
| **Version** | V1R7 |
| **Release Date** | 2026-04-07 |
| **Publisher** | Defense Information Systems Agency (DISA) |
| **STIG ID Prefix** | APPL-15-XXXXXX |
| **Verification** | stigaview.com/products/macos15/v1r7/ |

## Severity Categories

DISA classifies STIG rules into three severity categories:

| Category | Label | Impact |
|----------|-------|--------|
| **CAT I** | High | Exploitation could directly cause loss of confidentiality, integrity, or availability |
| **CAT II** | Medium | Exploitation could lead to degradation of security posture |
| **CAT III** | Low | Exploitation could slightly degrade security measures |

## Coverage Summary

- **39 of 64 checks** are mapped to at least one STIG rule
- **47 unique STIG rule IDs** covered across those 39 checks
- **8 CAT I (High)** references across system integrity, encryption, authentication, sharing, and SSH
- **42 CAT II (Medium)** references across all categories
- **25 checks** have no STIG mapping (best-practice checks from Lynis, Stethoscope, or the macOS security community)

The remaining ~115 STIG rules not covered require MDM/configuration profiles, smart card/PIV infrastructure, DoD-specific banners, iCloud service restrictions, or certificate/PKI management — none of which apply to consumer/prosumer unmanaged Macs.

## Check Mapping

### CAT I (High Severity)

| Harden Check ID | STIG ID | Description |
|-----------------|---------|-------------|
| `system.sip` | APPL-15-005001 | Ensure System Integrity Protection is enabled |
| `system.gatekeeper` | APPL-15-002064 | Enable Gatekeeper |
| `system.gatekeeper` | APPL-15-002060 | Block applications from unidentified developers |
| `encryption.filevault` | APPL-15-005020 | Enforce FileVault |
| `sharing.insecure` | APPL-15-002038 | Disable Trivial File Transfer Protocol service |
| `sharing.remotelogin` | APPL-15-001150 | Disable password authentication for SSH |
| `sharing.ssh.hardening` | APPL-15-001150 | Disable password authentication for SSH |
| `auth.autologin` | APPL-15-002066 | Disable unattended or automatic login to the system |

### CAT II (Medium Severity) — System Protection

| Harden Check ID | STIG ID | Description |
|-----------------|---------|-------------|
| `system.secureboot` | APPL-15-005100 | Ensure Secure Boot level is set to full |
| `system.ntp` | APPL-15-000014 | Enforce time synchronization |
| `system.autoupdate.configdata` | APPL-15-005130 | Enforce installation of XProtect Remediator and Gatekeeper updates automatically |
| `system.xprotect` | APPL-15-005130 | Enforce installation of XProtect Remediator and Gatekeeper updates automatically |
| `system.auditd` | APPL-15-001003 | Enable security auditing |
| `system.auditflags` | APPL-15-001001 | Audit all administrative action events |
| `system.auditperms` | APPL-15-000030 | Configure audit log files to not contain ACLs |
| `system.auditperms` | APPL-15-000031 | Configure the audit log folder to not contain ACLs |

### CAT II (Medium Severity) — Firewall

| Harden Check ID | STIG ID | Description |
|-----------------|---------|-------------|
| `firewall.enabled` | APPL-15-005050 | Enable macOS Application Firewall |

### CAT II (Medium Severity) — Sharing Services

| Harden Check ID | STIG ID | Description |
|-----------------|---------|-------------|
| `sharing.remotelogin` | APPL-15-001100 | Disable root login for SSH |
| `sharing.screensharing` | APPL-15-002050 | Disable Screen Sharing and Apple Remote Desktop |
| `sharing.filesharing` | APPL-15-002001 | Disable Server Message Block sharing |
| `sharing.remotemanagement` | APPL-15-002250 | Disable Remote Management |
| `sharing.printersharing` | APPL-15-002240 | Disable Printer Sharing |
| `sharing.bluetooth` | APPL-15-002110 | Disable Bluetooth Sharing |
| `sharing.airdrop` | APPL-15-002009 | Disable AirDrop |
| `sharing.ssh.hardening` | APPL-15-000051 | Configure SSHD ClientAliveInterval to 900 |
| `sharing.ssh.hardening` | APPL-15-000052 | Configure SSHD ClientAliveCountMax to 1 |
| `sharing.ssh.hardening` | APPL-15-001100 | Disable root login for SSH |
| `sharing.remoteappleevents` | APPL-15-002022 | Disable Remote Apple Events |
| `sharing.internetsharing` | APPL-15-002007 | Disable Internet Sharing |
| `sharing.mediasharing` | APPL-15-002100 | Disable Media Sharing |
| `sharing.airplayreceiver` | APPL-15-002080 | Disable Airplay Receiver |
| `sharing.contentcaching` | APPL-15-002140 | Disable Content Caching service |

### CAT II (Medium Severity) — Authentication

| Harden Check ID | STIG ID | Description |
|-----------------|---------|-------------|
| `auth.password.sleep` | APPL-15-000002 | Screen saver must require password to unlock |
| `auth.lockdelay` | APPL-15-000003 | Password delay after screen saver must be 5 seconds or less |
| `auth.idle.timeout` | APPL-15-000070 | Screen saver timeout must not exceed 900 seconds |
| `auth.guest` | APPL-15-002063 | Disable the guest account |
| `auth.passwordpolicy` | APPL-15-003010 | Minimum password length must be configured |
| `auth.passwordpolicy` | APPL-15-003007 | Passwords contain a minimum of one numeric character |
| `auth.passwordpolicy` | APPL-15-003011 | Passwords contain a minimum of one special character |
| `auth.passwordpolicy` | APPL-15-003060 | Passwords contain one lowercase and one uppercase character |
| `auth.passwordpolicy` | APPL-15-000022 | Limit consecutive failed login attempts to three |
| `auth.passwordpolicy` | APPL-15-000060 | Set account lockout time to 15 minutes |
| `auth.filevaultautologin` | APPL-15-000033 | Disable FileVault automatic login |
| `auth.hotcorners` | APPL-15-000007 | Hot corners must not disable the screen saver |
| `auth.consolelogin` | APPL-15-000090 | Login to other user sessions must be disabled |
| `auth.applewatch` | APPL-15-000001 | Apple Watch must not be allowed to unlock the session |
| `auth.homedir.permissions` | APPL-15-002068 | Secure users' home folders |
| `auth.loginwindow.style` | APPL-15-005052 | Configure login window to prompt for username and password |

### CAT II (Medium Severity) — Privacy

| Harden Check ID | STIG ID | Description |
|-----------------|---------|-------------|
| `privacy.siri` | APPL-15-002020 | Disable Siri |
| `privacy.analytics` | APPL-15-002021 | Disable sending diagnostic and usage data to Apple |

## Non-STIG Checks

The following Harden checks are not mapped to a STIG rule but represent security best practices from Lynis, Netflix Stethoscope, or the macOS security community:

- `firewall.stealth` — Firewall stealth mode (no macOS 15 STIG rule)
- `firewall.logging` — Firewall logging
- `firewall.outbound` — Outbound firewall detection
- `firewall.pf` — Packet filter (pf) status
- `encryption.timemachine` — Time Machine backup encryption
- `system.osversion` — macOS version freshness
- `system.autoupdate.check` — Automatic update checking
- `system.autoupdate.download` — Automatic update downloads
- `system.autoupdate.install` — Automatic macOS update installation
- `system.autoupdate.critical` — Automatic security updates
- `system.autoupdate.appstore` — App Store auto-updates
- `system.findmymac` — Find My Mac (STIG APPL-15-002180 says *disable*; Harden recommends *enable* for theft recovery — a deliberate policy divergence)
- `system.extensions` — Third-party system extensions
- `system.uptime` — System uptime / reboot freshness
- `system.malware` — Malware scanner detection
- `system.rsr` — Rapid Security Responses
- `sharing.insecure` — Legacy insecure services (partially covered by TFTP STIG)
- `auth.loginwindow.style` — Login window display style
- `network.dns` — DNS configuration
- `network.wifi.security` — Current Wi-Fi encryption
- `network.wifi.open` — Saved open Wi-Fi networks
- `network.wakeonlan` — Wake on network access
- `network.sysctl` — Network stack hardening (sysctl)
- `network.promiscuous` — Promiscuous network interface
- `privacy.safari.suggestions` — Safari search suggestions
- `privacy.lockdown` — Lockdown Mode
- `privacy.tcc` — TCC permissions audit

### Notable Policy Divergence

**Find My Mac** (`system.findmymac`): STIG rule APPL-15-002180 requires disabling the Find My service to prevent Apple from having device tracking capabilities. Harden recommends *enabling* Find My Mac for theft recovery and remote wipe. This is a deliberate divergence — the STIG is written for DoD environments where device tracking by a third party is a security concern, while consumer users benefit from the theft-recovery capability.

## Sources and Attribution

Security checks in Harden are based on:

1. **DISA STIG for Apple macOS 15 (Sequoia)** — Published by the Defense Information Systems Agency.
   - Download: https://public.cyber.mil/stigs/downloads/
   - NIST NCP Checklist: https://ncp.nist.gov/checklist/1257
   - Viewer: https://stigaview.com/products/macos15/

2. **NIST macOS Security Compliance Project (mSCP)** — The authoritative open-source implementation of macOS security baselines, jointly maintained by NIST, NASA, DISA, LANL, and Apple.
   - Repository: https://github.com/usnistgov/macos_security
   - Apple endorsement: https://support.apple.com/guide/certifications/macos-security-compliance-project-apc322685bb2/web
   - Methodology: NIST SP 800-219

3. **NIST SP 800-53 Rev 5** — The underlying security controls framework.
   - https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

4. **Lynis** — Unix/Linux/macOS security auditing tool (GPL-3.0).
   - https://github.com/cisofy/lynis

5. **Netflix Stethoscope** — Device health assessment tool.
   - https://github.com/Netflix-Skunkworks/stethoscope-app
