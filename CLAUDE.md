# Harden

**Take control of your Mac's security.** Harden checks your Mac's configuration against security best practices — firewall, encryption, sharing services, authentication, network settings, privacy, and app settings — then shows you what to fix and how.

Inspired by [Lynis](https://github.com/cisofy/lynis) (system auditing) and [Netflix Stethoscope](https://github.com/Netflix-Skunkworks/stethoscope-app) (device health), but designed as a native macOS app that regular users can understand.

Part of the Subversive Software family. See [SUBVERSIVE_MACOS_ARCH.md](../SUBVERSIVE_MACOS_ARCH.md) for shared architecture conventions.

## Quick Reference

```
Bundle ID:    com.subversivesoftware.Harden
Platform:     macOS 14.0+
Swift:        5.0 language mode, swift-tools-version 6.3
Build:        swift build / swift run Harden
Test:         swift test
Xcode:        open Harden.xcodeproj
DMG:          ./Scripts/create-dmg.sh
Headless:     Harden --agent [--output path.json]
Dependencies: Sparkle 2.10.x (only third-party dependency)
```

## Project Layout

```
Harden/
  App/
    HardenApp.swift              # @main AppEntry (--agent dispatch), HardenApp scene, menu commands, Sparkle updater
    AppDelegate.swift            # Standard About panel
  Models/
    SecurityCheck.swift          # SecurityCheck struct, STIGReference, CISReference, CheckStatus, CheckSeverity
    CheckCategory.swift          # CheckCategory enum (8 categories with icons/colors)
    STIGMapping.swift            # DISA STIG check-ID-to-rule catalog
    CISMapping.swift             # CIS Benchmark check-ID-to-rule catalog
    Remediation.swift            # Auto-fix commands keyed by check ID (38 entries)
    DeviceIdentity.swift         # Hardware UUID, serial, model, hostname, OS, MAC, current user
  Services/
    SecurityScanner.swift        # Orchestrator: runs all checkers in parallel, attaches STIG/CIS refs, ShellCommand helper
    RemediationRunner.swift      # Executes Remediation commands, elevating via osascript when needed
    AgentMode.swift              # Headless --agent scan: JSON report, change detection, notifications
    LaunchAgentManager.swift     # Installs/removes ~/Library/LaunchAgents/com.subversivesoftware.harden.agent.plist
    ComplianceReportGenerator.swift # HTML and CSV compliance reports
    Checkers/
      FirewallChecker.swift      # (5)  Application firewall, stealth, logging, outbound firewall, pf
      EncryptionChecker.swift    # (2)  FileVault, Time Machine encryption
      SystemChecker.swift        # (25) SIP, Gatekeeper, XProtect, updates, auditing, AMFI, sudo, root
      SharingChecker.swift       # (14) SSH, screen/file/printer/Bluetooth sharing, AirDrop, AirPlay, remote mgmt
      AuthenticationChecker.swift # (16) Auto-login, lock/screensaver, guest, login window, password policy
      NetworkChecker.swift       # (9)  DNS, Wi-Fi security, sysctl, wake-on-LAN, HTTP/NFS servers
      PrivacyChecker.swift       # (14) Analytics, Siri, Lockdown Mode, TCC, Apple Intelligence features
      ApplicationsChecker.swift  # (8)  Safari settings, filename extensions, Terminal secure keyboard entry
  Store/
    SecurityStore.swift          # Main state: checks[], score, actionItems, snooze + history persistence, JSON export
  Views/
    MainTabView.swift            # 5-tab root + OnboardingView; scan-on-launch (off by default)
    SettingsView.swift           # Settings scene: scan on launch, reset onboarding
    HelpView.swift               # Help sheet + SecurityGuideView; CheckGuideEntry.all documents every check
    IntegrationView.swift        # Scheduled scanning (live) + fleet server config (stub, "Coming Soon")
    Dashboard/
      DashboardView.swift        # Score gauge + category cards + Scan Now
      ScoreGaugeView.swift       # Circular arc gauge (0-100)
      CategoryCardView.swift     # Per-category summary card
    ActionItems/
      ActionItemsView.swift      # Sorted fail/warning list with snooze controls
    Details/
      CheckDetailView.swift      # All checks grouped by category, searchable/filterable
    Compliance/
      ComplianceTabView.swift    # STIG/CIS switcher, JSON/HTML/CSV export
      STIGReportView.swift       # STIG compliance view
      CISReportView.swift        # CIS compliance view by section, Level 1/2
    Components/
      CheckForUpdatesView.swift  # "Check for Updates..." menu item
  Resources/
    Assets.xcassets/             # App icon (hammer-and-anvil artwork)
HardenTests/
  HardenTests.swift              # Model, snooze, STIG and CIS catalog tests (Swift Testing)
```

## How It Works

### Security Checks

Each checker is a struct with a `runChecks() async -> [SecurityCheck]` method. Checks run real macOS shell commands via `ShellCommand.run()`, which wraps `Process` in async/await. The `SecurityScanner` orchestrator runs all 8 checkers in parallel with `async let`.

Commands used include `defaults read`, `fdesetup status`, `csrutil status`, `spctl --status`, `socketfilterfw`, `launchctl print-disabled system`, `systemsetup`, `networksetup`, `cupsctl`, and `ipconfig getsummary`. Avoid the `airport` utility: Apple removed it in macOS 14.4. `ipconfig getsummary <wifi-device>` still reports the link's security type with SSID/BSSID redacted.

Checks run without root, which rules out some obvious commands:
- `launchctl list` only lists the current user's jobs. System daemons never appear in it, and per-user agents with similar names always do. `launchctl print system/<label>` needs root. Use `LaunchdOverrides` (in `SecurityScanner.swift`), which reads `launchctl print-disabled system`: the sharing services ship disabled, so `=> enabled` means the user turned one on. For a daemon that runs whenever it is enabled, `pgrep -x <name>` also works.
- `systemsetup -get...` prints "You need administrator access" and exits 0.
- Match command output exactly rather than with `contains("on")`. Apple rewords these messages between releases, and usage or error text can contain the word being matched.

Two checks don't shell out. `network.wifi.open` uses CoreWLAN (`CWNetworkProfile.security`): saved networks moved to the root-only `/Library/Preferences/com.apple.wifi.known-networks.plist`, and no unprivileged command reads their security type. The app is not sandboxed, so CoreWLAN works in both the GUI and `--agent` mode. The Safari checks read Safari's container plist directly, because Safari is sandboxed and `defaults read com.apple.Safari` doesn't see its settings. That read needs Full Disk Access; without it the Safari checks report unknown.

After all checkers run, the `SecurityScanner` enriches each check with STIG references from `STIGMapping.catalog` and CIS references from `CISMapping.catalog`. This keeps compliance metadata centralized rather than scattered across checkers.

### Adding a New Check

1. Add a `private func checkSomething() async -> SecurityCheck` to the appropriate checker
2. Wire it into that checker's `runChecks()` method (use `async let` for parallelism)
3. Pick the right `CheckCategory` and `CheckSeverity`
4. Write a clear `recommendation` string with the System Settings path or terminal command
5. Add a `CheckGuideEntry` with the same ID to `CheckGuideEntry.all` in `HelpView.swift`
6. Optional: add an auto-fix to `Remediation.catalog`, and STIG/CIS rules to `STIGMapping`/`CISMapping`
7. Update the check counts in README.md
8. The check automatically appears in Dashboard, Action Items, All Checks, and (if mapped) Compliance — no view changes needed

### Adding a New Checker (new category)

1. Add a case to `CheckCategory` enum with icon and color
2. Create `Harden/Services/Checkers/NewChecker.swift`
3. Add `async let newChecks = NewChecker().runChecks()` to `SecurityScanner.scan()`
4. Add the file to the Xcode project's Sources build phase

### Scoring

Score = weighted pass rate across all non-info, non-unknown checks:
- Critical: 25 pts, High: 15 pts, Medium: 10 pts, Low: 5 pts, Info: 0 (excluded)
- Pass earns full weight, Warning earns half, Fail earns zero
- Score = (earned / maximum) * 100

### Snooze Persistence

Snoozed action items are stored as `{checkID: expiryTimestamp}` in `~/Library/Application Support/Harden/snoozed.json`. Expired snoozes are purged on each scan. Score snapshots live alongside in `scan_history.json`.

### Headless Agent Mode and Scheduled Scanning

`AppEntry.main()` checks for `--agent` before starting SwiftUI. In agent mode, `AgentMode` runs a full scan and writes a JSON report (device identity, score, every check with STIG/CIS refs) to stdout or the `--output` path. It then compares statuses with the previous agent run and posts a notification if any changed.

The Integration tab's "Scheduled Scanning" uses `LaunchAgentManager` to install a LaunchAgent that runs `Harden --agent --output ~/Library/Application Support/Harden/latest-scan.json` every 1/4/8/24 hours (`StartInterval`). The fleet server fields on that tab are a UI stub: Test Connection and Send Report only show a "not yet available" message.

## UI Tabs

| Tab | Purpose | Key features |
|-----|---------|-------------|
| **Dashboard** | At-a-glance security posture | Scan Now button, circular score gauge (0-100), category breakdown cards with pass/fail/warning counts and progress bars |
| **Action Items** | What to fix, sorted by priority | Sorted by severity (critical first), expandable details with remediation steps, snooze menu (1 day/week/month/forever), category filter, badge count |
| **All Checks** | Full audit detail | Every check grouped by category, status icons (pass/fail/warning/info/unknown), search and status filter, recommendations inline |
| **Compliance** | STIG and CIS reporting | Per-framework compliance views, export as JSON, HTML, or CSV |
| **Integration** | Background and fleet | Scheduled scanning via LaunchAgent; fleet server configuration (stub) |

## Terminology

- Use "Security Score" not "compliance score" — this is for consumers, not auditors
- Use "Action Items" not "violations" or "findings"
- Recommendations should say "Open System Settings > ..." not "Run this terminal command" (include terminal as secondary option for advanced users)
- Severity labels: Critical, High, Medium, Low, Info

## Auto-Update (Sparkle)

Uses [Sparkle](https://sparkle-project.org/) (MIT) for auto-update. Key files:
- `Info.plist` — `SUFeedURL` (appcast URL) and `SUPublicEDKey` (EdDSA public key)
- `Harden/App/HardenApp.swift` — `SPUStandardUpdaterController` instance
- `Harden/Views/Components/CheckForUpdatesView.swift` — "Check for Updates..." menu item
- `Scripts/create-dmg.sh` — produces zip archive for Sparkle alongside the DMG, and runs `generate_appcast`

Sparkle is pinned in **two** `Package.resolved` files that must stay in sync:
- `Package.resolved` (SPM) — supplies `.build/artifacts/sparkle/Sparkle/bin/generate_appcast`, used by the release script
- `Harden.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved` (Xcode) — decides which `Sparkle.framework` is embedded in the shipped app

To upgrade, run `swift package update`, then update the Xcode pin to the same version and revision. The `originHash` is the same in both files and does not change.

Appcast feed: `https://subversivesoftware.org/updates/harden/appcast.xml`

See [SUBVERSIVE_MACOS_ARCH.md](../SUBVERSIVE_MACOS_ARCH.md) for the shared Sparkle conventions.

## STIG Compliance

39 of 93 checks are mapped to 47 unique rules from the DISA STIG for Apple macOS 15 Sequoia (V1R7). All STIG IDs verified against stigaview.com. STIG IDs appear as color-coded badges in the All Checks view and are included in JSON exports. See [docs/STIG.md](docs/STIG.md) for the full mapping, coverage analysis, and source attribution.

## CIS Benchmark Compliance

72 CIS rules from the CIS Apple macOS 15.0 Sequoia Benchmark (v1.1.0) are mapped across 93 Harden checks. The CIS Report view provides a dedicated compliance dashboard organized by CIS section, with Level 1/Level 2 profile indicators. Scan results can be exported as HTML and CSV compliance reports, and as JSON for integration with other tools. See [docs/CIS.md](docs/CIS.md) for the full mapping, coverage analysis, and licensing details.

## Roadmap

See [TODO.md](TODO.md) for the phased check expansion plan.
