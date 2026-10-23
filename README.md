# Harden

A macOS security hardening tool that checks your Mac's configuration against best practices and helps you fix what it finds. Inspired by [Lynis](https://github.com/cisofy/lynis) and [Netflix Stethoscope](https://github.com/Netflix-Skunkworks/stethoscope-app), built as a native SwiftUI app that regular users can understand.

## What it does

Your Mac has dozens of security settings spread across System Settings, terminal commands, and kernel parameters. Most people never touch them, and the defaults aren't always the most secure. Harden checks all of them at once and tells you what to fix — in plain language, with buttons that fix it for you.

**93 security checks** across 8 categories:

| Category | Checks | Examples |
|----------|--------|----------|
| **Firewall** (5) | Application firewall, stealth mode, logging, outbound firewall detection, pf packet filter | Is your firewall on? Is anything watching outbound traffic? |
| **Encryption** (2) | FileVault, Time Machine encryption | Is your disk encrypted? Are your backups? |
| **System Protection** (25) | SIP, Gatekeeper, XProtect freshness, Startup Security, auto-updates (6 sub-checks), macOS version, Find My Mac, system extensions, uptime, NTP, malware scanner, Rapid Security Response, security auditing (auditd, flags, log permissions), AMFI, world-writable folders, sudo timeout and logging, root account | Is your OS up to date? Are security patches applying automatically? Is activity being audited? |
| **Sharing** (14) | SSH, screen sharing, file sharing, remote management, remote Apple events, printers, Bluetooth sharing, AirDrop, AirPlay receiver, Internet sharing, content caching, media sharing, insecure legacy services, SSH config hardening | Are you exposing services you don't need? |
| **Authentication** (16) | Auto-login, FileVault auto-login, password after sleep, lock delay, screensaver timeout, hot corners, guest account (3 checks), login window display and password hints, console login, Apple Watch unlock, System Settings password, home directory permissions, password policy | How easy is it for someone to walk up and use your Mac? |
| **Network** (9) | DNS configuration, Wi-Fi security, saved open networks, wake-on-LAN, Power Nap, sysctl hardening, promiscuous interface detection, HTTP server, NFS server | Is your network stack hardened? |
| **Privacy** (14) | Analytics and diagnostics sharing, Siri and dictation sharing, personalized ads, Safari suggestions, Siri, Lockdown Mode, TCC permissions audit, Apple Intelligence features (Writing Tools, Mail summaries, Notes transcription, external AI extensions) | What data is your Mac sharing? |
| **Applications** (8) | Safari fraud warnings, cross-site tracking, ad privacy, auto-open downloads, full address and status bar; filename extensions; Terminal Secure Keyboard Entry | Are your everyday apps configured safely? |

## Features

- **Dashboard** — Security score (0–100) weighted by severity, with per-category breakdown cards. Scans start from **Scan Now**; scan-on-launch can be turned on in Settings
- **Action Items** — Failed and warning checks sorted by priority, with snooze (1 day/week/month/forever) and auto-fix buttons
- **Auto-Fix** — 38 checks can be fixed with one click. User defaults apply instantly; system settings trigger the standard macOS admin password dialog via `osascript`
- **System Settings deep links** — "Open in System Settings" buttons for checks that can't be automated
- **All Checks** — Every check grouped by category with search, status filter, and JSON export
- **Compliance** — DISA STIG and CIS Benchmark report views, exportable as HTML, CSV, or JSON (see [STIG and CIS mappings](#compliance-mappings))
- **Scheduled scanning** — One-click LaunchAgent that rescans in the background every 1, 4, 8, or 24 hours and sends a notification when any check's status changes
- **Device identity** — Reports include hardware UUID, serial number, model, hostname, OS version, and current user, for attribution and deduplication across machines
- **Check Reference** — Help menu guide documenting what each of the 93 checks does, why it matters, and how to fix it
- **Scan history** — Score snapshots persisted between sessions; change detection highlights what improved or regressed
- **Automatic updates** — Delivered via [Sparkle](https://sparkle-project.org/)
- **Onboarding** — 3-page walkthrough on first launch

The **Integration** tab also has configuration fields for reporting to a fleet compliance server. That reporting is not live yet; the tab says so, and results can be exported locally from the Compliance tab in the meantime.

## Headless mode

The app binary doubles as a command-line scanner. The scheduled-scanning LaunchAgent uses this mode.

```bash
/Applications/Harden.app/Contents/MacOS/Harden --agent                       # JSON report to stdout
/Applications/Harden.app/Contents/MacOS/Harden --agent --output report.json  # JSON report to a file
```

The report contains the device identity, score, and every check with its STIG and CIS references. Progress messages go to stderr. If any check changed status since the previous agent run, Harden posts a notification.

## Compliance mappings

- **DISA STIG** — 39 checks map to 47 rules from the STIG for Apple macOS 15 Sequoia (V1R7). See [docs/STIG.md](docs/STIG.md).
- **CIS Benchmark** — 72 rules from the CIS Apple macOS 15.0 Sequoia Benchmark (v1.1.0), with Level 1/Level 2 profile indicators. See [docs/CIS.md](docs/CIS.md).

## Requirements

- macOS 14.0 (Sonoma) or later
- To build from source: Xcode with Swift 6.3 or later (`Package.swift` uses `swift-tools-version: 6.3`)

## Getting started

```bash
git clone https://github.com/subversivesoftwareorg/harden.git
cd harden
swift build
swift run Harden
swift test
```

Or open in Xcode:

```bash
open Harden.xcodeproj
```

## Building a release

```bash
./Scripts/create-dmg.sh --skip-notarize   # build + sign only
./Scripts/create-dmg.sh                    # build + sign + notarize
```

Prerequisites:

- `brew install create-dmg`
- A Developer ID Application certificate in your keychain
- `swift package resolve`, which provides Sparkle's `generate_appcast` tool
- A clean working tree (the script refuses to run otherwise)

The script builds a universal (arm64 + x86_64) app and signs Sparkle's embedded helpers and the app. It then produces a DMG and a Sparkle update zip and generates the appcast. Next, it auto-increments the build number, commits `Info.plist`, creates an annotated tag, and **pushes the commit and tag**. It then creates a GitHub Release with the DMG and zip attached. Finally, it stages `appcast.xml` into `../www/static/updates/harden/` and prints the command to deploy the website.

## Architecture

Built with the same patterns as [Tapped](https://github.com/subversivesoftwareorg/tapped) and [Survey](https://github.com/subversivesoftwareorg/survey):

- **SwiftUI** with `@Observable` (Swift 5.9 Observation framework)
- **One third-party dependency:** [Sparkle](https://github.com/sparkle-project/Sparkle) (MIT) for auto-update. Everything else uses Apple frameworks
- Services injected via `.environment()`, stores are `@Observable @MainActor`
- Security checks run real shell commands (`defaults read`, `csrutil status`, `fdesetup`, `socketfilterfw`, `sysctl`, etc.) via `Process` wrapped in `async/await`
- All 8 checkers run in parallel via `async let`; STIG and CIS references are attached centrally after the scan
- Dual build system: Swift Package Manager and Xcode project

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including how to add new checks.

## Project structure

```
Harden/
  App/           — Entry point (--agent dispatch), AppDelegate, menu commands
  Models/        — SecurityCheck, CheckCategory, Remediation, DeviceIdentity, STIG/CIS mappings
  Services/
    Checkers/    — 8 checker structs (one per category)
    SecurityScanner.swift            — Orchestrator + ShellCommand helper
    RemediationRunner.swift          — Executes fixes with optional admin privileges
    AgentMode.swift                  — Headless --agent scan, JSON output, notifications
    LaunchAgentManager.swift         — Installs/removes the scheduled-scan LaunchAgent
    ComplianceReportGenerator.swift  — HTML and CSV compliance reports
  Store/         — SecurityStore (scores, history, snooze, export)
  Views/
    Dashboard/   — Score gauge, category cards
    ActionItems/ — Sorted issues with fix/snooze/settings buttons
    Details/     — Full check list with search, filter, export
    Compliance/  — STIG and CIS report views
    Components/  — Check for Updates menu item
    HelpView, IntegrationView, SettingsView, MainTabView
HardenTests/     — Model, snooze, STIG and CIS catalog tests
docs/            — STIG.md, CIS.md
Scripts/         — create-dmg.sh release pipeline
```

## License

© 2026 [Subversive Software](https://subversivesoftware.org)
