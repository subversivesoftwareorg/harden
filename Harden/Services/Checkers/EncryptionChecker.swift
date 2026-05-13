import Foundation

struct EncryptionChecker {

    func runChecks() async -> [SecurityCheck] {
        async let fileVaultCheck = checkFileVault()
        async let timeMachineCheck = checkTimeMachineEncryption()
        return await [fileVaultCheck, timeMachineCheck]
    }

    private func checkTimeMachineEncryption() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "encryption.timemachine",
            name: "Time Machine Encryption",
            description: "Time Machine backups should be encrypted to protect your data if the backup drive is lost or stolen.",
            category: .encryption,
            severity: .medium
        )
        // Check if Time Machine is configured at all
        let tmResult = await ShellCommand.run("defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null")
        if tmResult.output == "0" {
            check.status = .info
            check.details = "Time Machine is not enabled. No backup encryption to check."
            return check
        }
        // Check destination info for encryption
        let destResult = await ShellCommand.run("tmutil destinationinfo 2>/dev/null")
        if destResult.output.isEmpty || destResult.output.contains("No destinations") {
            check.status = .info
            check.details = "No Time Machine backup destination configured."
            return check
        }
        if destResult.output.contains("Not Encrypted") {
            check.status = .warning
            check.details = "Time Machine backup destination is not encrypted."
            check.recommendation = "In System Settings > General > Time Machine, remove the destination and re-add it with 'Encrypt Backups' enabled."
        } else if destResult.output.contains("Encrypted") {
            check.status = .pass
            check.details = "Time Machine backup is encrypted."
        } else {
            check.status = .info
            check.details = "Could not determine Time Machine encryption status."
        }
        return check
    }

    private func checkFileVault() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "encryption.filevault",
            name: "FileVault Disk Encryption",
            description: "FileVault encrypts your entire startup disk, protecting data if your Mac is lost or stolen.",
            category: .encryption,
            severity: .critical
        )
        let result = await ShellCommand.run("fdesetup status")
        if result.output.contains("On") {
            check.status = .pass
            check.details = "FileVault is enabled."
            if result.output.contains("Encryption in progress") {
                check.details = "FileVault is enabled and encryption is in progress."
            }
        } else if result.output.contains("Off") {
            check.status = .fail
            check.details = "FileVault is not enabled. Your disk is not encrypted."
            check.recommendation = "Open System Settings > Privacy & Security > FileVault and turn it on."
        } else {
            check.status = .unknown
            check.details = "Could not determine FileVault status."
        }
        return check
    }
}
