# Harden

**Take control of your Mac's security.** Harden checks your Mac's configuration against security best practices — firewall, encryption, sharing services, authentication, network settings, and privacy — then shows you what to fix and how.

Inspired by [Lynis](https://github.com/cisofy/lynis) (system auditing) and [Netflix Stethoscope](https://github.com/Netflix-Skunkworks/stethoscope-app) (device health), but designed as a native macOS app that regular users can understand.

Part of the Subversive Software family. See [SUBVERSIVE_MACOS_ARCH.md](../SUBVERSIVE_MACOS_ARCH.md) for shared architecture conventions.

## Quick Reference

```
Bundle ID:    com.subversivesoftware.Harden
Platform:     macOS 14.0+
Swift:        5.0 language mode
Build:        swift build / swift run Harden
Test:         swift test
Xcode:        open Harden.xcodeproj
DMG:          ./Scripts/create-dmg.sh
```

## Project Layout

```
Harden/
  App/
    HardenApp.swift              # @main entry, About panel menu command
    AppDelegate.swift            # Standard About panel
  Models/
    SecurityCheck.swift          # SecurityCheck struct, STIGReference, CheckStatus, CheckSeverity
    CheckCategory.swift          # CheckCategory enum (7 categories with icons/colors)
    STIGMapping.swift            # DISA STIG check-ID-to-rule catalog
  Services/
    SecurityScanner.swift        # Orchestrator: runs all checkers in parallel, ShellCommand helper
    Checkers/
      FirewallChecker.swift      # Application firewall, stealth mode, logging
      EncryptionChecker.swift    # FileVault status
      SystemChecker.swift        # SIP, Gatekeeper, auto-update settings
      SharingChecker.swift       # SSH, screen sharing, file sharing, remote mgmt, printers, bluetooth
      AuthenticationChecker.swift # Auto-login, password after sleep, guest account, lock delay
      NetworkChecker.swift       # DNS config, Wi-Fi security
      PrivacyChecker.swift       # Analytics sharing, Safari suggestions
  Store/
    SecurityStore.swift          # Main state: checks[], score, actionItems, snooze persistence
  Views/
    MainTabView.swift            # 3-tab root: Dashboard, Action Items, All Checks
    Dashboard/
      DashboardView.swift        # Score gauge + category cards
      ScoreGaugeView.swift       # Circular arc gauge (0-100)
      CategoryCardView.swift     # Per-category summary card
    ActionItems/
      ActionItemsView.swift      # Sorted fail/warning list with snooze controls
    Details/
      CheckDetailView.swift      # All checks grouped by category, searchable/filterable
  Resources/
    Assets.xcassets/             # App icon (placeholder — needs artwork)
HardenTests/
  HardenTests.swift              # Model and enum tests
```

## How It Works

### Security Checks

Each checker is a struct with a `runChecks() async -> [SecurityCheck]` method. Checks run real macOS shell commands via `ShellCommand.run()`, which wraps `Process` in async/await. The `SecurityScanner` orchestrator runs all 7 checkers in parallel with `async let`.

Commands used include `defaults read`, `fdesetup status`, `csrutil status`, `spctl --status`, `socketfilterfw`, `launchctl list`, `systemsetup`, `networksetup`, `cupsctl`, and the `airport` utility.

After all checkers run, the `SecurityScanner` enriches each check with STIG references from `STIGMapping.catalog`. This keeps STIG metadata centralized rather than scattered across checkers.

### Adding a New Check

1. Add a `private func checkSomething() async -> SecurityCheck` to the appropriate checker
2. Wire it into that checker's `runChecks()` method (use `async let` for parallelism)
3. Pick the right `CheckCategory` and `CheckSeverity`
4. Write a clear `recommendation` string with the System Settings path or terminal command
5. The check automatically appears in all three tabs — no view changes needed

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

Snoozed action items are stored as `{checkID: expiryTimestamp}` in `~/Library/Application Support/Harden/snoozed.json`. Expired snoozes are purged on each scan.

## UI Tabs

| Tab | Purpose | Key features |
|-----|---------|-------------|
| **Dashboard** | At-a-glance security posture | Circular score gauge (0-100), category breakdown cards with pass/fail/warning counts and progress bars |
| **Action Items** | What to fix, sorted by priority | Sorted by severity (critical first), expandable details with remediation steps, snooze menu (1 day/week/month/forever), category filter, badge count |
| **All Checks** | Full audit detail | Every check grouped by category, status icons (pass/fail/warning/info/unknown), search and status filter, recommendations inline |

## Terminology

- Use "Security Score" not "compliance score" — this is for consumers, not auditors
- Use "Action Items" not "violations" or "findings"
- Recommendations should say "Open System Settings > ..." not "Run this terminal command" (include terminal as secondary option for advanced users)
- Severity labels: Critical, High, Medium, Low, Info

## STIG Compliance

39 of 64 checks are mapped to 47 unique rules from the DISA STIG for Apple macOS 15 Sequoia (V1R7). All STIG IDs verified against stigaview.com. STIG IDs appear as color-coded badges in the All Checks view and are included in JSON exports. See [docs/STIG.md](docs/STIG.md) for the full mapping, coverage analysis, and source attribution.

## Roadmap

See [TODO.md](TODO.md) for the phased check expansion plan.
