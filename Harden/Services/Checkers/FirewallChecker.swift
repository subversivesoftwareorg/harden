import Foundation

struct FirewallChecker {

    func runChecks() async -> [SecurityCheck] {
        async let firewallCheck = checkFirewallEnabled()
        async let stealthCheck = checkStealthMode()
        async let loggingCheck = checkFirewallLogging()
        async let outboundCheck = checkOutboundFirewall()
        async let pfCheck = checkPFFirewall()
        return await [firewallCheck, stealthCheck, loggingCheck, outboundCheck, pfCheck]
    }

    private func checkFirewallEnabled() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "firewall.enabled",
            name: "Application Firewall",
            description: "The built-in application firewall controls incoming connections to your Mac.",
            category: .firewall,
            severity: .critical
        )
        let result = await ShellCommand.run("defaults read /Library/Preferences/com.apple.alf globalstate")
        if let value = Int(result.output) {
            if value >= 1 {
                check.status = .pass
                check.details = value == 2
                    ? "Firewall is enabled and blocking all incoming connections."
                    : "Firewall is enabled for specific services."
            } else {
                check.status = .fail
                check.details = "Firewall is disabled."
                check.recommendation = "Open System Settings > Network > Firewall and turn it on."
            }
        } else {
            check.status = .unknown
            check.details = "Could not determine firewall status."
        }
        return check
    }

    private func checkStealthMode() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "firewall.stealth",
            name: "Stealth Mode",
            description: "Stealth mode prevents your Mac from responding to probing requests like ICMP ping.",
            category: .firewall,
            severity: .medium
        )
        let result = await ShellCommand.run("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode")
        if result.output.lowercased().contains("enabled") {
            check.status = .pass
            check.details = "Stealth mode is enabled."
        } else if result.output.lowercased().contains("disabled") {
            check.status = .warning
            check.details = "Stealth mode is disabled."
            check.recommendation = "Enable via: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
        } else {
            check.status = .unknown
            check.details = "Could not determine stealth mode status."
        }
        return check
    }

    private func checkOutboundFirewall() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "firewall.outbound",
            name: "Outbound Firewall",
            description: "macOS's built-in firewall only blocks incoming connections. An outbound firewall like LuLu or Little Snitch can detect apps phoning home.",
            category: .firewall,
            severity: .info
        )
        let knownFirewalls: [(name: String, process: String)] = [
            ("Little Snitch", "Little Snitch Daemon"),
            ("LuLu", "LuLu"),
            ("Radio Silence", "Radio Silence"),
            ("HandsOff", "HandsOffDaemon"),
        ]
        var found: [String] = []
        let result = await ShellCommand.run("ps -eo comm= 2>/dev/null")
        let processes = result.output
        for fw in knownFirewalls {
            if processes.contains(fw.process) {
                found.append(fw.name)
            }
        }
        if !found.isEmpty {
            check.status = .pass
            check.details = "Outbound firewall detected: \(found.joined(separator: ", "))."
        } else {
            check.status = .info
            check.details = "No outbound firewall detected. macOS only filters incoming connections by default."
            check.recommendation = "Consider installing a free outbound firewall like LuLu (objective-see.org/products/lulu.html) for additional visibility."
        }
        return check
    }

    private func checkFirewallLogging() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "firewall.logging",
            name: "Firewall Logging",
            description: "Firewall logging records connection attempts that are blocked by the firewall.",
            category: .firewall,
            severity: .low
        )
        let result = await ShellCommand.run("/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode")
        if result.output.lowercased().contains("on") || result.output.lowercased().contains("enabled") {
            check.status = .pass
            check.details = "Firewall logging is enabled."
        } else if result.output.lowercased().contains("off") || result.output.lowercased().contains("disabled") {
            check.status = .warning
            check.details = "Firewall logging is disabled."
            check.recommendation = "Enable via: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on"
        } else {
            check.status = .unknown
            check.details = "Could not determine logging status."
        }
        return check
    }

    private func checkPFFirewall() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "firewall.pf",
            name: "Packet Filter (pf)",
            description: "macOS includes pf, a powerful packet filter firewall. It's disabled by default but provides fine-grained network filtering when enabled.",
            category: .firewall,
            severity: .info
        )
        let result = await ShellCommand.run("pfctl -sa 2>/dev/null | grep -i '^Status'")
        if result.output.lowercased().contains("enabled") {
            check.status = .pass
            check.details = "The pf packet filter firewall is enabled."
        } else if result.output.lowercased().contains("disabled") {
            check.status = .info
            check.details = "The pf packet filter is disabled (default). The Application Firewall provides basic protection."
            check.recommendation = "For advanced network filtering, pf can be enabled via /etc/pf.conf. This is optional for most users."
        } else {
            check.status = .info
            check.details = "Could not determine pf status."
        }
        return check
    }
}
