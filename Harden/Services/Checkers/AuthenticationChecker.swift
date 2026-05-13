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
        return await [
            autoLoginCheck, passwordAfterSleepCheck, guestAccountCheck,
            lockDelayCheck, idleTimeoutCheck, loginWindowCheck, homeDirCheck,
            passwordPolicyCheck,
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
