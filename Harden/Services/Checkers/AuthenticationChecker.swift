import Foundation

struct AuthenticationChecker {

    func runChecks() async -> [SecurityCheck] {
        async let autoLoginCheck = checkAutoLogin()
        async let passwordAfterSleepCheck = checkPasswordAfterSleep()
        async let guestAccountCheck = checkGuestAccount()
        async let lockDelayCheck = checkScreenLockDelay()
        async let idleTimeoutCheck = checkScreensaverIdleTimeout()
        async let loginWindowCheck = checkLoginWindowStyle()
        async let homeDirCheck = checkHomeDirectoryPermissions()
        async let passwordPolicyCheck = checkPasswordPolicy()
        async let fdeAutoLoginCheck = checkFileVaultAutoLogin()
        async let hotCornersCheck = checkHotCorners()
        async let consoleLoginCheck = checkConsoleLogin()
        async let appleWatchCheck = checkAppleWatchUnlock()
        async let guestSMBCheck = checkGuestSMBAccess()
        async let passwordHintsCheck = checkPasswordHints()
        async let guestHomeFolderCheck = checkGuestHomeFolder()
        async let systemPrefsPasswordCheck = checkSystemPrefsPassword()
        return await [
            autoLoginCheck, passwordAfterSleepCheck, guestAccountCheck,
            lockDelayCheck, idleTimeoutCheck, loginWindowCheck, homeDirCheck,
            passwordPolicyCheck,
            fdeAutoLoginCheck, hotCornersCheck, consoleLoginCheck, appleWatchCheck,
            guestSMBCheck, passwordHintsCheck, guestHomeFolderCheck, systemPrefsPasswordCheck,
        ]
    }

    private func checkAutoLogin() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.autologin",
            name: "Automatic Login",
            description: "Automatic login allows anyone with physical access to use your Mac without a password.",
            category: .authentication,
            severity: .critical
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null")
        if result.exitCode != 0 || result.output.contains("does not exist") {
            check.status = .pass
            check.details = "Automatic login is disabled."
        } else {
            check.status = .fail
            check.details = "Automatic login is enabled for user: \(result.output)"
            check.recommendation = "Open System Settings > Users & Groups and disable automatic login."
        }
        return check
    }

    private func checkPasswordAfterSleep() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.password.sleep",
            name: "Password After Sleep",
            description: "Requiring a password after sleep or screen saver prevents unauthorized access when you step away.",
            category: .authentication,
            severity: .high
        )
        let result = await ShellCommand.run("defaults read com.apple.screensaver askForPassword 2>/dev/null")
        if result.output == "1" {
            check.status = .pass
            check.details = "Password is required after sleep or screen saver."
        } else if result.output == "0" {
            check.status = .fail
            check.details = "Password is not required after sleep or screen saver."
            check.recommendation = "Open System Settings > Lock Screen and enable 'Require password after screen saver begins or display is turned off'."
        } else {
            check.status = .info
            check.details = "Password requirement uses the system default. Check System Settings > Lock Screen to verify."
        }
        return check
    }

    private func checkGuestAccount() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.guest",
            name: "Guest Account",
            description: "The guest account allows anyone to use your Mac without a password, creating a temporary session.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Guest account is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Guest account is enabled."
            check.recommendation = "Unless needed for Find My Mac, disable the guest account in System Settings > Users & Groups."
        } else {
            check.status = .pass
            check.details = "Guest account appears to be disabled (default)."
        }
        return check
    }

    private func checkScreensaverIdleTimeout() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.idle.timeout",
            name: "Screensaver Idle Timeout",
            description: "The screensaver should activate after a short idle period to protect your Mac when you step away.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.screensaver idleTime 2>/dev/null")
        if let seconds = Int(result.output) {
            if seconds > 0 && seconds <= 300 {
                check.status = .pass
                check.details = "Screensaver activates after \(seconds / 60) minute\(seconds == 60 ? "" : "s")."
            } else if seconds > 300 && seconds <= 600 {
                check.status = .warning
                check.details = "Screensaver activates after \(seconds / 60) minutes."
                check.recommendation = "Set to 5 minutes or less in System Settings > Lock Screen > 'Start Screen Saver when inactive'."
            } else if seconds > 600 {
                check.status = .fail
                check.details = "Screensaver activates after \(seconds / 60) minutes — this is too long."
                check.recommendation = "Set to 5 minutes or less in System Settings > Lock Screen > 'Start Screen Saver when inactive'."
            } else {
                check.status = .warning
                check.details = "Screensaver appears to be disabled (timeout is 0)."
                check.recommendation = "Enable screen saver in System Settings > Lock Screen > 'Start Screen Saver when inactive' and set to 5 minutes or less."
            }
        } else {
            check.status = .info
            check.details = "Could not determine screensaver timeout. Check System Settings > Lock Screen."
        }
        return check
    }

    private func checkLoginWindowStyle() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.loginwindow.style",
            name: "Login Window Display",
            description: "Showing a name and password field instead of a user list prevents revealing account names to anyone with physical access.",
            category: .authentication,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Login window shows name and password fields (user list hidden)."
        } else {
            check.status = .info
            check.details = "Login window shows the user list. This reveals which accounts exist on this Mac."
            check.recommendation = "To hide the user list, run: sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true"
        }
        return check
    }

    private func checkScreenLockDelay() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.lockdelay",
            name: "Screen Lock Delay",
            description: "The delay before a password is required after sleep should be as short as possible.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null")
        if let delay = Int(result.output) {
            if delay == 0 {
                check.status = .pass
                check.details = "Password is required immediately (no delay)."
            } else if delay <= 5 {
                check.status = .pass
                check.details = "Password required after \(delay) second delay."
            } else if delay <= 60 {
                check.status = .warning
                check.details = "Password required after \(delay) second delay."
                check.recommendation = "Reduce the delay in System Settings > Lock Screen. Immediate (0 seconds) is recommended."
            } else {
                check.status = .fail
                check.details = "Password required after \(delay) second delay — this is too long."
                check.recommendation = "Set to 'Immediately' in System Settings > Lock Screen."
            }
        } else {
            check.status = .info
            check.details = "Screen lock delay uses the system default. Verify in System Settings > Lock Screen."
        }
        return check
    }

    private func checkHomeDirectoryPermissions() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.homedir.permissions",
            name: "Home Directory Permissions",
            description: "Your home directory should not be world-readable. Restrictive permissions prevent other users on the system from browsing your files.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("stat -f '%Lp' ~ 2>/dev/null")
        if let mode = Int(result.output) {
            if mode <= 700 {
                check.status = .pass
                check.details = "Home directory permissions are \(result.output) (owner only)."
            } else if mode <= 750 {
                check.status = .pass
                check.details = "Home directory permissions are \(result.output) (owner + group read)."
            } else if mode <= 755 {
                check.status = .warning
                check.details = "Home directory permissions are \(result.output) — world-readable."
                check.recommendation = "Tighten permissions with: chmod 750 ~"
            } else {
                check.status = .fail
                check.details = "Home directory permissions are \(result.output) — too permissive."
                check.recommendation = "Tighten permissions with: chmod 750 ~"
            }
        } else {
            check.status = .unknown
            check.details = "Could not determine home directory permissions."
        }
        return check
    }

    private func checkFileVaultAutoLogin() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.filevaultautologin",
            name: "FileVault Auto-Login",
            description: "When FileVault is enabled, auto-login can bypass the pre-boot authentication, defeating the purpose of full-disk encryption.",
            category: .authentication,
            severity: .high
        )
        let fdeResult = await ShellCommand.run("fdesetup status 2>/dev/null")
        guard fdeResult.output.contains("On") else {
            check.status = .pass
            check.details = "FileVault is not enabled — FDE auto-login check not applicable."
            return check
        }
        let result = await ShellCommand.run("defaults read com.apple.loginwindow DisableFDEAutoLogin 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "FileVault auto-login is disabled. Pre-boot authentication is required."
        } else {
            check.status = .fail
            check.details = "FileVault auto-login is not explicitly disabled."
            check.recommendation = "Disable with: sudo defaults write com.apple.loginwindow DisableFDEAutoLogin -bool true"
        }
        return check
    }

    private func checkHotCorners() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.hotcorners",
            name: "Hot Corner Security",
            description: "Hot corners that disable the screen saver can be used to bypass the lock screen, allowing unauthorized access.",
            category: .authentication,
            severity: .medium
        )
        let corners = ["wvous-tl-corner", "wvous-tr-corner", "wvous-bl-corner", "wvous-br-corner"]
        let cornerNames = ["top-left", "top-right", "bottom-left", "bottom-right"]
        var insecure: [String] = []
        for (i, corner) in corners.enumerated() {
            let result = await ShellCommand.run("defaults read com.apple.dock \(corner) 2>/dev/null")
            if let value = Int(result.output), value == 6 {
                insecure.append(cornerNames[i])
            }
        }
        if insecure.isEmpty {
            check.status = .pass
            check.details = "No hot corners are configured to disable the screen saver."
        } else {
            check.status = .warning
            check.details = "Hot corner\(insecure.count == 1 ? "" : "s") set to disable screen saver: \(insecure.joined(separator: ", "))."
            check.recommendation = "Change in System Settings > Desktop & Dock > Hot Corners. Avoid 'Disable Screen Saver' as it can bypass the lock screen."
        }
        return check
    }

    private func checkConsoleLogin() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.consolelogin",
            name: "Console Login",
            description: "The \">console\" login allows switching to a text-based login from the graphical login window, which can bypass certain security controls.",
            category: .authentication,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.loginwindow DisableConsoleAccess 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .pass
            check.details = "Console login access is disabled."
        } else {
            check.status = .info
            check.details = "Console login access is not explicitly disabled."
            check.recommendation = "To disable, run: sudo defaults write /Library/Preferences/com.apple.loginwindow DisableConsoleAccess -bool true"
        }
        return check
    }

    private func checkAppleWatchUnlock() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.applewatch",
            name: "Apple Watch Auto-Unlock",
            description: "Apple Watch can automatically unlock your Mac when nearby, which may allow unintended access if the watch wearer is close but not actively using the Mac.",
            category: .authentication,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read com.apple.applicationaccess allowAutoUnlock 2>/dev/null")
        if result.output == "0" || result.output.lowercased() == "false" {
            check.status = .pass
            check.details = "Apple Watch auto-unlock is disabled."
        } else if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .info
            check.details = "Apple Watch auto-unlock is enabled. Your Mac can be unlocked by proximity to your Apple Watch."
            check.recommendation = "If not desired, disable in System Settings > Touch ID & Password > Apple Watch."
        } else {
            check.status = .info
            check.details = "Apple Watch auto-unlock uses the system default. Check System Settings > Touch ID & Password."
        }
        return check
    }

    private func checkGuestSMBAccess() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.guest.smb",
            name: "Guest SMB Share Access",
            description: "Guest access to file shares allows unauthenticated users to access shared folders.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null")
        if result.output == "1" || result.output.lowercased() == "true" {
            check.status = .warning
            check.details = "Guest access to SMB file shares is enabled."
            check.recommendation = "Disable guest SMB access with: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false"
        } else {
            check.status = .pass
            check.details = "Guest access to SMB file shares is disabled."
        }
        return check
    }

    private func checkPasswordHints() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.passwordhints",
            name: "Login Window Password Hints",
            description: "Password hints visible at the login window can help an attacker guess passwords.",
            category: .authentication,
            severity: .low
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint 2>/dev/null")
        if let retries = Int(result.output) {
            if retries == 0 {
                check.status = .pass
                check.details = "Password hints are disabled at the login window."
            } else {
                check.status = .warning
                check.details = "Password hints are shown after \(retries) failed login attempt\(retries == 1 ? "" : "s")."
                check.recommendation = "Disable password hints with: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"
            }
        } else {
            check.status = .pass
            check.details = "Password hints appear to be disabled (default)."
        }
        return check
    }

    private func checkGuestHomeFolder() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.guest.homefolder",
            name: "Guest Home Folder",
            description: "The guest home folder should be removed when the guest account is disabled to prevent data persistence.",
            category: .authentication,
            severity: .low
        )
        let result = await ShellCommand.run("ls -d /Users/Guest 2>/dev/null")
        if result.exitCode != 0 || result.output.isEmpty {
            check.status = .pass
            check.details = "Guest home folder does not exist."
        } else {
            check.status = .info
            check.details = "Guest home folder exists at /Users/Guest."
            check.recommendation = "If the guest account is disabled, remove the folder with: sudo rm -rf /Users/Guest"
        }
        return check
    }

    private func checkSystemPrefsPassword() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.systemprefs.password",
            name: "System Settings Password",
            description: "Changing system-wide preferences should require an administrator password.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("security authorizationdb read system.preferences 2>/dev/null | grep -c 'authenticate-admin-nonshared'")
        let count = Int(result.output) ?? 0
        if count > 0 {
            check.status = .pass
            check.details = "An administrator password is required to change system-wide preferences."
        } else {
            check.status = .warning
            check.details = "System-wide preferences may not require an administrator password."
            check.recommendation = "Open System Settings > Privacy & Security and ensure 'Require administrator password to access system-wide preferences' is enabled."
        }
        return check
    }

    private func checkPasswordPolicy() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "auth.passwordpolicy",
            name: "Password Policy",
            description: "A strong password policy enforces minimum length, complexity, and account lockout to protect against brute-force attacks.",
            category: .authentication,
            severity: .medium
        )
        let result = await ShellCommand.run("pwpolicy -getaccountpolicies 2>/dev/null")
        if result.output.contains("minLength") || result.output.contains("policyAttributePassword") {
            // Parse out minimum length if present
            var details: [String] = []
            if let range = result.output.range(of: "minLength"),
               let numRange = result.output.range(of: "\\d+", options: .regularExpression, range: range.upperBound..<result.output.endIndex),
               let minLen = Int(result.output[numRange]) {
                details.append("minimum length: \(minLen)")
                if minLen < 8 {
                    check.status = .warning
                    check.recommendation = "Increase minimum password length to at least 8 characters."
                } else {
                    check.status = .pass
                }
            }
            if result.output.contains("requiresMixedCase") || result.output.contains("requiresAlpha") {
                details.append("complexity requirements set")
            }
            if result.output.contains("maxFailedLoginAttempts") || result.output.contains("policyAttributeFailedAuthentications") {
                details.append("account lockout configured")
            }
            let detailStr = details.isEmpty ? "Custom password policy is configured." : "Policy: \(details.joined(separator: ", "))."
            if check.status == .unknown { check.status = .pass }
            check.details = detailStr
        } else if result.output.isEmpty || result.exitCode != 0 {
            check.status = .info
            check.details = "Using the default macOS password policy. No custom policy configured."
            check.recommendation = "For stronger security, set a password policy via: pwpolicy -setglobalpolicy 'minChars=8'. System Settings > Users & Groups also allows some password requirements."
        } else {
            check.status = .info
            check.details = "Password policy could not be fully parsed."
        }
        return check
    }
}
