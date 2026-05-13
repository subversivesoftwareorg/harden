import Foundation

/// Runs a shell command and returns the output and exit code.
enum ShellCommand {
    struct Result {
        let output: String
        let exitCode: Int32
    }

    static func run(_ command: String) async -> Result {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", command]
            process.standardOutput = pipe
            process.standardError = pipe
            process.terminationHandler = { proc in
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                continuation.resume(returning: Result(output: output, exitCode: proc.terminationStatus))
            }
            do {
                try process.run()
            } catch {
                continuation.resume(returning: Result(output: "", exitCode: -1))
            }
        }
    }
}

/// Orchestrates all security checkers and aggregates results.
@Observable
@MainActor
final class SecurityScanner {
    var isScanning = false

    func scan() async -> [SecurityCheck] {
        isScanning = true
        defer { isScanning = false }

        async let firewallChecks = FirewallChecker().runChecks()
        async let encryptionChecks = EncryptionChecker().runChecks()
        async let systemChecks = SystemChecker().runChecks()
        async let sharingChecks = SharingChecker().runChecks()
        async let authChecks = AuthenticationChecker().runChecks()
        async let networkChecks = NetworkChecker().runChecks()
        async let privacyChecks = PrivacyChecker().runChecks()

        let allChecks = await firewallChecks + encryptionChecks + systemChecks
            + sharingChecks + authChecks + networkChecks + privacyChecks

        return allChecks
    }
}
