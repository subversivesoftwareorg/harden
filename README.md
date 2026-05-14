# Harden

A macOS security hardening tool that checks your Mac's configuration against best practices and helps you fix what it finds. Inspired by [Lynis](https://github.com/cisofy/lynis) and [Netflix Stethoscope](https://github.com/Netflix-Skunkworks/stethoscope-app), built as a native SwiftUI app that regular users can understand.

## What it does

Your Mac has dozens of security settings spread across System Settings, terminal commands, and kernel parameters. Most people never touch them, and the defaults aren't always the most secure. Harden checks all of them at once and tells you what to fix — in plain language, with buttons that fix it for you.

**52 security checks** across 7 categories:

| Category | Checks | Examples |
|----------|--------|----------|
| **Firewall** (5) | Application firewall, stealth mode, logging, outbound firewall detection, pf packet filter | Is your firewall on? Is anything watching outbound traffic? |
| **Encryption** (2) | FileVault, Time Machine encryption | Is your disk encrypted? Are your backups? |
| **System Protection** (17) | SIP, Gatekeeper, XProtect freshness, Secure Boot, auto-updates (5 sub-checks), macOS version, Find My Mac, system extensions, uptime, NTP, malware scanner, Rapid Security Response | Is your OS up to date? Are security patches applying automatically? |
| **Sharing** (9) | SSH, screen sharing, file sharing, remote management, printers, Bluetooth sharing, AirDrop, insecure legacy services, SSH config hardening | Are you exposing services you don't need? |
| **Authentication** (8) | Auto-login, password after sleep, guest account, lock delay, screensaver timeout, login window, home directory permissions, password policy | How easy is it for someone to walk up and use your Mac? |
| **Network** (6) | DNS configuration, Wi-Fi security, saved open networks, wake-on-LAN, sysctl hardening, promiscuous interface detection | Is your network stack hardened? |
| **Privacy** (5) | Analytics sharing, Safari suggestions, Siri, Lockdown Mode, TCC permissions audit | What data is your Mac sharing? |

## Features

- **Dashboard** — Security score (0–100) weighted by severity, with per-category breakdown cards
- **Action Items** — Failed and warning checks sorted by priority, with snooze (1 day/week/month/forever) and auto-fix buttons
- **Auto-Fix** — 25 checks can be fixed with one click. User defaults apply instantly; system settings trigger the standard macOS admin password dialog via `osascript`
- **System Settings deep links** — "Open in System Settings" buttons for checks that can't be automated
- **All Checks** — Every check grouped by category with search, status filter, and JSON export
- **Check Reference** — Comprehensive guide documenting what each check does, why it matters, and how to fix it (Help menu)
- **Scan history** — Score snapshots persisted between sessions; change detection highlights what improved or regressed
- **Onboarding** — 3-page walkthrough on first launch

## Requirements

- macOS 14.0 (Sonoma) or later
- Xcode 15+ (for building from source)

## Getting started

```bash
git clone <repo>
cd harden
swift build
swift run Harden
```

Or open in Xcode:

```bash
open Harden.xcodeproj
```

Build and run. The app scans automatically on launch and shows your results across three tabs.

## Building a DMG

```bash
./Scripts/create-dmg.sh --skip-notarize   # build + sign only
./Scripts/create-dmg.sh                    # build + sign + notarize
```

Requires `brew install create-dmg` and a Developer ID Application certificate in your keychain. The script auto-increments the build number, creates an annotated git tag, and reminds you to push.

## Architecture

Built with the same patterns as [Tapped](https://github.com/subversivesoftwareorg/tapped) and [Survey](https://github.com/subversivesoftwareorg/survey):

- **SwiftUI** with `@Observable` (Swift 5.9 Observation framework)
- **Zero third-party dependencies** — Apple frameworks only
- Services injected via `.environment()`, stores are `@Observable @MainActor`
- Security checks run real shell commands (`defaults read`, `csrutil status`, `fdesetup`, `socketfilterfw`, `sysctl`, etc.) via `Process` wrapped in `async/await`
- All 7 checkers run in parallel via `async let`
- Dual build system: Swift Package Manager and Xcode project

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including how to add new checks.

## Project structure

```
Harden/
  App/           — Entry point, AppDelegate (About panel, app icon)
  Models/        — SecurityCheck, CheckCategory, Remediation
  Services/
    Checkers/    — 7 checker structs (one per category)
    SecurityScanner.swift    — Orchestrator + ShellCommand helper
    RemediationRunner.swift  — Executes fixes with optional sudo
  Store/         — SecurityStore (scores, history, snooze, export)
  Views/
    Dashboard/   — Score gauge, category cards
    ActionItems/ — Sorted issues with fix/snooze/settings buttons
    Details/     — Full check list with search, filter, export
    Components/  — Programmatic anvil icon
```

## License

© 2026 [Subversive Software](https://subversivesoftware.org)
