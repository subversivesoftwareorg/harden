# Harden — Roadmap

## Current State

93 security checks across 8 categories: Firewall (5), Encryption (2), System Protection (20), Sharing (14), Authentication (16), Network (6), Privacy (5), Applications (6). 39 checks mapped to 47 unique DISA STIG rules (V1R7, verified). 72 CIS rules mapped (CIS Apple macOS 15.0 Sequoia Benchmark v1.1.0).

The app builds, runs, and scans. Dashboard, Action Items, All Checks, and CIS Report tabs are functional. All five phases of checks are complete.

---

## Phase 1 — Consumer-Facing Checks

High value, straightforward to implement. These fill the biggest gaps identified from Lynis and Stethoscope and are the checks most relevant to everyday Mac users.

### System Protection

- [x] **macOS version freshness** — `sw_vers -productVersion`, compare against known latest release. Flag outdated versions with severity based on how far behind (1 minor = warning, 1+ major = critical).
- [x] **Automatic security/critical updates** — `defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall`. Stethoscope checks this separately from general auto-updates.
- [x] **Automatic config data install** — `defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall`. Covers XProtect definitions and system data files.
- [x] **App Store auto-updates** — `defaults read /Library/Preferences/com.apple.commerce AutoUpdate`. Separate from macOS updates.
- [x] **Find My Mac enabled** — `nvram -p | grep fmm-mobileme-token-FMM`. Important for device recovery and remote wipe.

### Authentication

- [x] **Screensaver idle timeout** — `defaults read com.apple.screensaver idleTime`. Should be <= 300 seconds (5 minutes). Stethoscope flagged this as a gap (their implementation was stubbed).
- [x] **Login window shows name+password** — `defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME`. Showing a user list reveals account names to anyone with physical access.

### Network

- [x] **Saved open Wi-Fi networks** — Read `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`, search for open (unencrypted) remembered networks. From Stethoscope.
- [x] **Wake on network / Power Nap** — `pmset -g | grep womp` and `powernap`. Wake-on-LAN allows remote wake which expands the attack surface.

### Sharing

- [x] **AirDrop discoverability** — `defaults read com.apple.NetworkBrowser DisableAirDrop` and `defaults read com.apple.NetworkBrowser BrowseAllInterfaces`. Neither Lynis nor Stethoscope checks this.
- [x] **Insecure legacy services** — `launchctl list com.apple.fingerd`, `launchctl list com.apple.ftp-proxy`, `launchctl list com.apple.telnetd`. From Lynis INSE-8050.

### Firewall

- [x] **Outbound firewall detection** — Process check for Little Snitch, LuLu, Radio Silence, HandsOff. From Lynis FIRE-4534. Informational — flag as "info" if none found, "pass" if one is running.

### Privacy

- [x] **Siri enabled** — `defaults read com.apple.assistant.support "Assistant Enabled"`. Siri sends voice/text data to Apple for processing.

### Encryption

- [x] **Time Machine encryption** — `defaults read /Library/Preferences/com.apple.TimeMachine LastKnownEncryptionState` or `tmutil destinationinfo | grep "Mount Point"` then `diskutil info` per volume. Unencrypted backups are a data leak vector.

**Phase 1 total: 14 new checks (23 → 37) — COMPLETE**

---

## Phase 2 — Deep Hardening

Medium value, moderate complexity. These appeal to more security-conscious users and justify the "Harden" name. Several require parsing config files or running multiple commands.

### Sharing

- [x] **SSH config hardening** (conditional) — If Remote Login is enabled, parse `/etc/ssh/sshd_config` for: `PermitRootLogin no`, `PasswordAuthentication no`, `X11Forwarding no`, `MaxAuthTries <= 3`. From Lynis SSH-7408.

### System Protection

- [x] **Third-party kernel/system extensions** — `systemextensionsctl list 2>/dev/null` and `kextstat | grep -v com.apple`. Flag unknown or unsigned extensions.
- [x] **System uptime (reboot freshness)** — `sysctl kern.boottime`. Long uptime (>30 days) means kernel-level security patches haven't been applied. From Lynis BOOT-5202.
- [x] **NTP time synchronization** — `systemsetup -getusingnetworktime`. Time drift can break certificate validation and Kerberos auth. From Lynis TIME-3104.
- [x] **Malware scanner installed** — Process check for CrowdStrike Falcon (`falcond`), SentinelOne (`sentineld`), Sophos (`SophosScanD`), Microsoft Defender (`mdatp`), ClamXav. From Lynis MALW-3280/3288. Informational.

### Network

- [x] **sysctl network hardening** — Check key BSD network parameters via `sysctl`: `net.inet.ip.forwarding=0` (no IP forwarding), `net.inet.ip.redirect=0` (ignore ICMP redirects), `net.inet.tcp.blackhole=2` (drop packets to closed TCP ports), `net.inet.udp.blackhole=1` (same for UDP). From Lynis KRNL-6000.
- [x] **pf firewall enabled** — `pfctl -sa 2>/dev/null | grep "Status"`. macOS includes pf but it's disabled by default. From Lynis FIRE-4518.
- [x] **Promiscuous network interface** — `ifconfig | grep PROMISC`. A NIC in promiscuous mode may indicate packet sniffing. From Lynis NETW-3014.

### Authentication

- [x] **Home directory permissions** — Check `ls -ld ~` for permissions stricter than 755 (ideally 750 or 700). From Lynis HOME-9304.

**Phase 2 total: 9 new checks (37 → 46) — COMPLETE**

---

## Phase 3 — Advanced / Modern macOS

High value but harder to implement or limited to newer macOS versions. These are differentiators — neither Lynis nor Stethoscope checks any of them.

### System Protection

- [x] **XProtect version freshness** — Check `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist` or `system_profiler SPInstallHistoryDataType | grep -A3 XProtect`. Compare against known latest.
- [x] **Secure Boot status** (Apple Silicon) — `bputil -d` or `csrutil authenticated-root status`. Verify full security boot policy.
- [x] **Rapid Security Response** — Verify RSR is enabled and latest responses are installed. Check `softwareupdate --list` output.

### Privacy

- [x] **Lockdown Mode** (macOS Ventura+) — `defaults read /Library/Managed Preferences/.GlobalPreferences LDMGlobalEnabled` or check user-level. Informational — flag as available but not required.
- [x] **TCC permissions audit** — Query `/Library/Application Support/com.apple.TCC/TCC.db` for services like camera, microphone, screen recording, full disk access. Surface which apps have been granted sensitive permissions.

### Authentication

- [x] **Password policy strength** — `pwpolicy -getaccountpolicies`. Check minimum length, complexity requirements, account lockout thresholds.

**Phase 3 total: 6 new checks (46 → 52) — COMPLETE**

---

## Phase 4 — STIG Integration

Ground existing and new checks in the DISA Security Technical Implementation Guide for Apple macOS 15 Sequoia (V1R6). Adds authoritative backing, STIG ID metadata, and coverage of rules not previously implemented.

### Model & Infrastructure
- [x] `STIGReference` struct (id, title, severity)
- [x] `stigReferences` property on `SecurityCheck`
- [x] `STIGMapping.swift` central catalog (37 check-to-STIG mappings)
- [x] Scanner enrichment — STIG refs applied after check collection
- [x] JSON export includes STIG references
- [x] STIG badges in All Checks detail view (color-coded by CAT level, searchable)

### New STIG Checks (12)
- [x] `system.auditd` — Security auditing service (APPL-15-001003)
- [x] `system.auditflags` — Audit control flags (APPL-15-001001)
- [x] `system.auditperms` — Audit log permissions (APPL-15-000030/31)
- [x] `sharing.remoteappleevents` — Remote Apple Events (APPL-15-002022)
- [x] `sharing.internetsharing` — Internet Sharing (APPL-15-002007)
- [x] `sharing.mediasharing` — Media Sharing (APPL-15-002160)
- [x] `sharing.airplayreceiver` — AirPlay Receiver (APPL-15-002180)
- [x] `sharing.contentcaching` — Content Caching (APPL-15-002200)
- [x] `auth.filevaultautologin` — FDE auto-login (APPL-15-000033)
- [x] `auth.hotcorners` — Hot corner security (APPL-15-000007)
- [x] `auth.consolelogin` — Console login (APPL-15-000090)
- [x] `auth.applewatch` — Apple Watch auto-unlock (APPL-15-000001)

### Documentation & Testing
- [x] `docs/STIG.md` — Full mapping, attribution, coverage analysis
- [x] STIG mapping tests (validity, coverage, no duplicates)

**Phase 4 total: 12 new checks (52 → 64), 39 checks mapped to 47 unique STIG rules (V1R7, verified) — COMPLETE**

---

## Phase 5 — CIS Benchmark Integration

Map Harden checks to the CIS Apple macOS 15.0 Sequoia Benchmark (v1.1.0), add new checks for CIS-specific rules, and provide a dedicated CIS compliance reporting view.

### Model & Infrastructure
- [x] `CISReference` struct (rule, title, level)
- [x] `cisReferences` property on `SecurityCheck`
- [x] `CISMapping.swift` central catalog (72 CIS rules mapped across 93 checks)
- [x] Scanner enrichment — CIS refs applied after check collection alongside STIG refs
- [x] JSON export includes CIS references
- [x] HTML compliance report export (CIS-organized, printable)

### New CIS Checks (29)
- [x] `auth.sudo.touchid` — Touch ID for sudo authentication (CIS 5.11)
- [x] `auth.sudo.timeout` — Sudo timeout configuration (CIS 5.12)
- [x] `auth.failedlogin.banner` — Login banner presence (CIS 5.13)
- [x] `system.auditretention` — Audit log retention policy (CIS 3.5)
- [x] `applications.safariautofill` — Safari auto-fill for contacts/credit cards (CIS 2.7.1)
- [x] `applications.safariopensafe` — Safari open safe files after downloading (CIS 2.7.2)
- [x] `applications.safarijavascript` — Safari show full website address (CIS 2.7.3)
- [x] `applications.universalcontrol` — Universal Control disabled (CIS 2.7.4)
- [x] `applications.xcode` — Xcode command-line tools security
- [x] `applications.homebrew` — Homebrew package audit
- [x] Additional authentication, sharing, and network checks aligned to CIS sections 4-6

### Views
- [x] `CISReportView.swift` — Dedicated CIS compliance dashboard organized by CIS section
- [x] Level 1 / Level 2 profile indicators on each rule
- [x] Section-level pass/fail/warning summaries
- [x] HTML export button for printable compliance reports

### Documentation
- [x] `docs/CIS.md` — Full mapping, coverage analysis, licensing, attribution
- [x] CIS mapping tests (validity, coverage, no duplicates)

**Phase 5 total: 29 new checks (64 → 93), 72 CIS rules mapped, CIS Report view, HTML/JSON compliance export — COMPLETE**

---

## Non-Check Work

### App Polish
- [x] App icon design — programmatic anvil icon (steel blue/silver) via AnvilIconView.swift
- [x] Onboarding flow — 3-page walkthrough matching Survey's pattern
- [x] Settings view (Cmd+,) — scan-on-launch toggle, reset onboarding
- [x] Help menu — security guide covering score, action items, severity levels, export
- [ ] Menu bar status item (optional — show score badge)

### Features
- [x] Export scan results (JSON) — save panel from All Checks tab
- [x] Scan history / trend tracking — ScanSnapshot persisted to ~/Library/Application Support/Harden/
- [x] Change detection between scans — CheckChange tracking in SecurityStore
- [ ] Scheduled background scanning
- [x] Deep link to System Settings — settingsURL property on SecurityCheck, "Open in System Settings" buttons

### Infrastructure
- [ ] CI build verification
- [ ] README.md with screenshots
- [ ] Apple signing guide (match docs/apple-signing-guide.md from tapped/survey)
