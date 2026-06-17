# CIS Benchmark Compliance Reference

Harden maps its security checks to the **CIS Benchmark for Apple macOS 15 Sequoia**, a consensus-driven security configuration standard published by the Center for Internet Security.

## What are CIS Benchmarks?

CIS (Center for Internet Security) Benchmarks are prescriptive configuration guidelines developed through a consensus process involving cybersecurity professionals, government agencies, and technology vendors. They are recognized globally as a best-practice standard for hardening operating systems, cloud platforms, and applications. CIS Benchmarks complement DISA STIGs — both derive from NIST SP 800-53, but CIS targets a broader audience including enterprises, SMBs, and security-conscious individuals.

The macOS 15 Sequoia Benchmark contains rules organized into six sections covering system preferences, security and privacy, logging and auditing, network configuration, system access and authentication, and user accounts.

## Benchmark Version

| Field | Value |
|-------|-------|
| **Title** | CIS Apple macOS 15.0 Sequoia Benchmark |
| **Version** | v1.1.0 |
| **Publisher** | Center for Internet Security (cisecurity.org) |
| **Rule ID Format** | Section.Subsection.Rule (e.g. 2.1.1.1) |
| **Reference** | https://www.cisecurity.org/benchmark/apple_os |

## Level 1 vs Level 2

CIS Benchmarks define two profile levels:

| Level | Audience | Description |
|-------|----------|-------------|
| **Level 1** | All systems | Practical security settings that can be applied broadly without significant performance impact or reduced functionality. These represent the minimum recommended baseline. |
| **Level 2** | High-security environments | More restrictive settings intended for environments where security takes priority over convenience. May reduce functionality or require additional configuration. |

Most Harden checks correspond to Level 1 recommendations. Where a check maps to a Level 2 rule, it is noted in the mapping table below.

## Coverage Summary

- **72 CIS rules** mapped across **93 Harden checks**
- **Section 1 (Install Updates)**: 8 rules covered
- **Section 2 (System Preferences)**: 32 rules covered
- **Section 3 (Logging and Auditing)**: 5 rules covered
- **Section 4 (Network)**: 7 rules covered
- **Section 5 (System Access and Authentication)**: 16 rules covered
- **Section 6 (User Accounts)**: 4 rules covered
- **21 checks** have no CIS mapping (best-practice checks from Lynis, Stethoscope, or the macOS security community)

The remaining CIS rules not covered require MDM/configuration profiles, managed preferences, or enterprise infrastructure not applicable to unmanaged consumer Macs.

## Licensing and Attribution

CIS Benchmarks are published under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 (CC BY-NC-SA 4.0)** license. Harden references CIS rule numbers and section structure for compliance mapping purposes. All check descriptions and remediation text in Harden are original. No CIS Benchmark content is reproduced verbatim.

Rule mappings were cross-referenced against the **NIST macOS Security Compliance Project (mSCP)**, which provides machine-readable mappings between CIS, STIG, and NIST 800-53 controls for macOS.

## Check Mapping

### Section 1 — Install Updates, Patches and Additional Security Software

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `system.osversion` | 1.1 | L1 | Ensure all Apple-provided software is current |
| `system.autoupdate.check` | 1.2 | L1 | Ensure auto update is enabled |
| `system.autoupdate.download` | 1.3 | L1 | Ensure download new updates when available is enabled |
| `system.autoupdate.install` | 1.4 | L1 | Ensure install of macOS updates is enabled |
| `system.autoupdate.appstore` | 1.5 | L1 | Ensure install application updates from the App Store is enabled |
| `system.autoupdate.critical` | 1.6 | L1 | Ensure install security responses and system files is enabled |
| `system.autoupdate.configdata` | 1.6 | L1 | Ensure install security responses and system files is enabled |
| `system.rsr` | 1.7 | L1 | Ensure software update deferment is not enabled |

### Section 2 — System Preferences

#### 2.1 — Bluetooth / Sharing

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `sharing.bluetooth` | 2.1.1.1 | L1 | Ensure Bluetooth sharing is disabled |
| `sharing.airdrop` | 2.1.1.2 | L1 | Ensure AirDrop is disabled |
| `sharing.filesharing` | 2.1.2.1 | L1 | Ensure File Sharing is disabled |
| `sharing.printersharing` | 2.1.2.2 | L1 | Ensure Printer Sharing is disabled |
| `sharing.remotelogin` | 2.1.2.3 | L1 | Ensure Remote Login is disabled |
| `sharing.remotemanagement` | 2.1.2.4 | L1 | Ensure Remote Management is disabled |
| `sharing.remoteappleevents` | 2.1.2.5 | L1 | Ensure Remote Apple Events is disabled |
| `sharing.internetsharing` | 2.1.2.6 | L1 | Ensure Internet Sharing is disabled |
| `sharing.contentcaching` | 2.1.2.7 | L1 | Ensure Content Caching is disabled |
| `sharing.mediasharing` | 2.1.2.8 | L1 | Ensure Media Sharing is disabled |
| `sharing.screensharing` | 2.1.2.9 | L1 | Ensure Screen Sharing is disabled |

#### 2.2 — Date & Time

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `system.ntp` | 2.2.1 | L1 | Ensure set time and date automatically is enabled |

#### 2.3 — Desktop & Screen Saver

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `auth.idle.timeout` | 2.3.1 | L1 | Ensure an inactivity interval of 20 minutes or less for the screen saver is enabled |
| `auth.password.sleep` | 2.3.2 | L1 | Ensure a password is required to wake the computer from sleep or screen saver is enabled |
| `auth.lockdelay` | 2.3.3 | L1 | Ensure the screen saver lock delay is immediate |

#### 2.4 — Sharing Preferences (Extended)

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `sharing.airplayreceiver` | 2.4.1 | L1 | Ensure AirPlay Receiver is disabled |

#### 2.5 — Security & Privacy

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `system.gatekeeper` | 2.5.1.1 | L1 | Ensure FileVault is enabled |
| `encryption.filevault` | 2.5.1.2 | L1 | Ensure all user storage APFS volumes are encrypted |
| `firewall.enabled` | 2.5.2.1 | L1 | Ensure firewall is enabled |
| `firewall.stealth` | 2.5.2.2 | L1 | Ensure firewall stealth mode is enabled |
| `firewall.logging` | 2.5.2.3 | L2 | Ensure firewall logging is enabled |
| `system.gatekeeper` | 2.5.3.1 | L1 | Ensure Gatekeeper is enabled |
| `system.sip` | 2.5.4.1 | L1 | Ensure System Integrity Protection status is enabled |

#### 2.6 — Privacy

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `privacy.analytics` | 2.6.1 | L1 | Ensure sending diagnostic and usage data to Apple is disabled |
| `privacy.siri` | 2.6.2 | L1 | Ensure Siri is disabled |
| `privacy.lockdown` | 2.6.3 | L2 | Ensure Lockdown Mode is enabled |
| `privacy.tcc` | 2.6.4 | L1 | Audit location services access |
| `privacy.safari.suggestions` | 2.6.5 | L1 | Ensure Safari search suggestions are disabled |

#### 2.7 — Applications

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `applications.safariautofill` | 2.7.1 | L1 | Ensure Safari auto-fill for contact info and credit cards is disabled |
| `applications.safariopensafe` | 2.7.2 | L1 | Ensure Safari open safe files after downloading is disabled |
| `applications.safarijavascript` | 2.7.3 | L2 | Ensure Safari show full website address is enabled |
| `applications.universalcontrol` | 2.7.4 | L1 | Ensure Universal Control is disabled |

### Section 3 — Logging and Auditing

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `system.auditd` | 3.1 | L1 | Ensure security auditing is enabled |
| `system.auditflags` | 3.2 | L2 | Ensure security auditing flags per local organizational requirements are configured |
| `system.auditperms` | 3.3 | L2 | Ensure audit log files are not accessible by other users |
| `firewall.logging` | 3.4 | L2 | Ensure firewall logging is enabled |
| `system.auditretention` | 3.5 | L1 | Ensure audit retention is configured |

### Section 4 — Network Configurations

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `network.wifi.security` | 4.1 | L2 | Ensure Wi-Fi is configured to use WPA3 or WPA2 |
| `network.wifi.open` | 4.2 | L1 | Ensure known networks requiring pre-approval is enabled |
| `network.dns` | 4.3 | L1 | Ensure a custom DNS provider is configured |
| `network.wakeonlan` | 4.4 | L2 | Ensure Wake on Network Access is disabled |
| `network.sysctl` | 4.5 | L1 | Ensure IP forwarding and ICMP redirects are disabled |
| `network.promiscuous` | 4.6 | L2 | Ensure no network interface is in promiscuous mode |
| `sharing.ssh.hardening` | 4.7 | L1 | Ensure SSH is hardened (ClientAliveInterval, root login) |

### Section 5 — System Access, Authentication, and Authorization

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `auth.autologin` | 5.1 | L1 | Ensure automatic login is disabled |
| `auth.guest` | 5.2 | L1 | Ensure the guest account is disabled |
| `auth.filevaultautologin` | 5.3 | L1 | Ensure FileVault automatic login is disabled |
| `auth.passwordpolicy` | 5.4.1 | L1 | Ensure minimum password length is configured |
| `auth.passwordpolicy` | 5.4.2 | L1 | Ensure password complexity requirements are met |
| `auth.passwordpolicy` | 5.4.3 | L1 | Ensure account lockout threshold is configured |
| `auth.passwordpolicy` | 5.4.4 | L1 | Ensure account lockout time is configured |
| `auth.hotcorners` | 5.5 | L1 | Ensure hot corners do not disable screen saver |
| `auth.consolelogin` | 5.6 | L2 | Ensure login to other users' active sessions is disabled |
| `auth.applewatch` | 5.7 | L2 | Ensure Apple Watch unlock is disabled |
| `auth.loginwindow.style` | 5.8 | L1 | Ensure login window displays as name and password is enabled |
| `auth.homedir.permissions` | 5.9 | L1 | Ensure home folders are secure |
| `auth.idle.timeout` | 5.10 | L1 | Ensure system is set to lock when screensaver starts |
| `auth.sudo.touchid` | 5.11 | L1 | Ensure Touch ID is enabled for sudo |
| `auth.sudo.timeout` | 5.12 | L2 | Ensure sudo timeout is set to zero |
| `auth.failedlogin.banner` | 5.13 | L1 | Ensure a login banner exists |

### Section 6 — User Accounts

| Harden Check ID | CIS Rule | Level | Description |
|-----------------|----------|-------|-------------|
| `auth.homedir.permissions` | 6.1 | L1 | Ensure home folder permissions are secure |
| `applications.safariautofill` | 6.2 | L1 | Ensure password auto-fill for Safari is disabled |
| `system.extensions` | 6.3 | L1 | Ensure unauthorized system extensions are reviewed |
| `system.findmymac` | 6.4 | L1 | Ensure Find My is enabled |

## Non-CIS Checks

The following Harden checks are not mapped to a CIS rule but represent security best practices from DISA STIGs, Lynis, Netflix Stethoscope, or the macOS security community:

- `firewall.outbound` — Outbound firewall detection (third-party tools)
- `firewall.pf` — Packet filter (pf) status
- `encryption.timemachine` — Time Machine backup encryption
- `system.secureboot` — Secure Boot level (Apple Silicon)
- `system.xprotect` — XProtect version freshness
- `system.uptime` — System uptime / reboot freshness
- `system.malware` — Malware scanner detection
- `sharing.insecure` — Legacy insecure services (finger, telnet, FTP)
- `network.dns` — DNS configuration (partially covered)
- `privacy.tcc` — TCC permissions audit (partially covered)
- `applications.xcode` — Xcode command-line tools security
- `applications.homebrew` — Homebrew package audit

### Notable Differences from STIG

The CIS Benchmark and DISA STIG overlap significantly but diverge in several areas:

- **Find My Mac**: CIS recommends enabling (6.4); STIG requires disabling (APPL-15-002180). Harden follows the CIS guidance here, which aligns with consumer security needs.
- **Firewall stealth mode**: CIS includes this as a Level 1 rule (2.5.2.2); the macOS 15 STIG does not have a corresponding rule.
- **Lockdown Mode**: CIS includes this as a Level 2 rule (2.6.3); the STIG does not cover it.
- **Application-specific checks**: CIS includes Safari and application hardening (Section 2.7) that the STIG does not address.

## Sources and Attribution

Security checks in Harden are based on:

1. **CIS Apple macOS 15.0 Sequoia Benchmark v1.1.0** — Published by the Center for Internet Security.
   - Download: https://www.cisecurity.org/benchmark/apple_os
   - License: CC BY-NC-SA 4.0

2. **NIST macOS Security Compliance Project (mSCP)** — The authoritative open-source implementation of macOS security baselines, jointly maintained by NIST, NASA, DISA, LANL, and Apple.
   - Repository: https://github.com/usnistgov/macos_security
   - Apple endorsement: https://support.apple.com/guide/certifications/macos-security-compliance-project-apc322685bb2/web
   - Methodology: NIST SP 800-219

3. **DISA STIG for Apple macOS 15 (Sequoia)** — See [STIG.md](STIG.md) for full STIG mapping.
   - Download: https://public.cyber.mil/stigs/downloads/

4. **NIST SP 800-53 Rev 5** — The underlying security controls framework.
   - https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

5. **Lynis** — Unix/Linux/macOS security auditing tool (GPL-3.0).
   - https://github.com/cisofy/lynis

6. **Netflix Stethoscope** — Device health assessment tool.
   - https://github.com/Netflix-Skunkworks/stethoscope-app
