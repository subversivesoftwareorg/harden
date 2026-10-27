import Foundation

/// Runs a shell command and returns the output and exit code.
enum ShellCommand {
    struct Result {
        let output: String
        let exitCode: Int32
    }

    static func run(_ command: String, timeout: TimeInterval = 10) async -> Result {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            let guard_ = ContinuationGuard(continuation)

            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", command]
            process.standardOutput = pipe
            process.standardError = pipe
            process.terminationHandler = { proc in
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                guard_.resume(with: Result(output: output, exitCode: proc.terminationStatus))
            }
            do {
                try process.run()
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                    guard process.isRunning else { return }
                    process.terminate()
                    guard_.resume(with: Result(output: "", exitCode: -1))
                }
            } catch {
                guard_.resume(with: Result(output: "", exitCode: -1))
            }
        }
    }

    private final class ContinuationGuard: @unchecked Sendable {
        private var continuation: CheckedContinuation<Result, Never>?
        private let lock = NSLock()

        init(_ continuation: CheckedContinuation<Result, Never>) {
            self.continuation = continuation
        }

        func resume(with result: Result) {
            lock.lock()
            let cont = continuation
            continuation = nil
            lock.unlock()
            cont?.resume(returning: result)
        }
    }
}

/// Reads launchd's enable/disable overrides for system services.
///
/// `launchctl list` only sees the current user's jobs, and `launchctl print system/...`
/// needs root, but anyone can run `launchctl print-disabled system`. The sharing
/// services Harden checks ship with `Disabled = true`, so they run only when the
/// override list says `=> enabled`. This is also how the CIS Benchmark audits them.
enum LaunchdOverrides {
    /// Label to enabled state for every overridden system service, or nil if launchctl failed.
    static func system() async -> [String: Bool]? {
        let result = await ShellCommand.run("launchctl print-disabled system")
        guard result.exitCode == 0 else { return nil }
        return parse(result.output)
    }

    /// Whether a system service that ships disabled has been turned on, or nil if launchctl failed.
    static func isEnabled(_ label: String) async -> Bool? {
        guard let overrides = await system() else { return nil }
        return overrides[label] == true
    }

    /// Parses lines like `"com.openssh.sshd" => enabled`. Older macOS versions
    /// print `=> false` for enabled and `=> true` for disabled.
    static func parse(_ output: String) -> [String: Bool] {
        var overrides: [String: Bool] = [:]
        for line in output.split(separator: "\n") {
            let parts = line.components(separatedBy: "=>")
            guard parts.count == 2 else { continue }
            let label = parts[0].trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            switch parts[1].trimmingCharacters(in: .whitespaces) {
            case "enabled", "false": overrides[label] = true
            case "disabled", "true": overrides[label] = false
            default: continue
            }
        }
        return overrides
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
        async let appsChecks = ApplicationsChecker().runChecks()

        let allChecks = await firewallChecks + encryptionChecks + systemChecks
            + sharingChecks + authChecks + networkChecks + privacyChecks + appsChecks

        return allChecks.map { check in
            var enriched = check
            enriched.stigReferences = STIGMapping.catalog[check.id] ?? []
            enriched.cisReferences = CISMapping.catalog[check.id] ?? []
            return enriched
        }
    }
}
