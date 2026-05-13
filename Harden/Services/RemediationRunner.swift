import Foundation

@Observable
@MainActor
final class RemediationRunner {
    var isRunning = false
    var lastResult: RemediationResult?

    struct RemediationResult {
        let checkID: String
        let success: Bool
        let message: String
    }

    func execute(_ remediation: Remediation, for checkID: String) async -> Bool {
        isRunning = true
        defer { isRunning = false }

        let result: ShellCommand.Result
        if remediation.requiresSudo {
            result = await runWithPrivileges(remediation.command)
        } else {
            result = await ShellCommand.run(remediation.command)
        }

        let success = result.exitCode == 0
        lastResult = RemediationResult(
            checkID: checkID,
            success: success,
            message: success ? "Fix applied successfully." : "Fix failed: \(result.output)"
        )
        return success
    }

    private func runWithPrivileges(_ command: String) async -> ShellCommand.Result {
        // Escape single quotes in the command for AppleScript
        let escaped = command.replacingOccurrences(of: "'", with: "'\\''")
        let script = "osascript -e 'do shell script \"\(escaped)\" with administrator privileges' 2>&1"
        return await ShellCommand.run(script)
    }
}
