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
