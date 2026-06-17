import Foundation

struct NetworkChecker {

    func runChecks() async -> [SecurityCheck] {
        async let dnsCheck = checkDNS()
        async let wifiCheck = checkWiFiSecurity()
        async let openWifiCheck = checkSavedOpenWiFi()
        async let wakeOnNetworkCheck = checkWakeOnNetwork()
        async let sysctlCheck = checkSysctlHardening()
        async let promiscCheck = checkPromiscuousInterface()
        async let httpdCheck = checkHTTPServer()
        async let nfsdCheck = checkNFSServer()
        async let powerNapCheck = checkPowerNap()
        return await [dnsCheck, wifiCheck, openWifiCheck, wakeOnNetworkCheck, sysctlCheck, promiscCheck,
                      httpdCheck, nfsdCheck, powerNapCheck]
    }

    private func checkDNS() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.dns",
            name: "DNS Configuration",
            description: "Using a privacy-focused DNS provider prevents your ISP from logging every site you visit.",
            category: .network,
            severity: .medium
        )
        // Try the active network service — Wi-Fi first, then any other
        let wifiResult = await ShellCommand.run("networksetup -getdnsservers Wi-Fi 2>/dev/null")
        let output = wifiResult.output

        if output.contains("There aren't any DNS Servers set") {
            check.status = .warning
            check.details = "Using your ISP's default DNS servers."
            check.recommendation = "Consider setting a privacy-focused DNS like 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9), or 8.8.8.8 (Google). Go to System Settings > Network > Wi-Fi > Details > DNS."
        } else if !output.isEmpty && wifiResult.exitCode == 0 {
            let servers = output.components(separatedBy: "\n").filter { !$0.isEmpty }
            let knownPrivate = ["1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                                "8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220"]
            let usingPrivate = servers.contains { knownPrivate.contains($0) }
            if usingPrivate {
                check.status = .pass
                check.details = "Custom DNS servers configured: \(servers.joined(separator: ", "))"
            } else {
                check.status = .info
                check.details = "Custom DNS servers configured: \(servers.joined(separator: ", "))"
            }
        } else {
            check.status = .info
            check.details = "Could not determine DNS configuration."
        }
        return check
    }

    private func checkSavedOpenWiFi() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.wifi.open",
            name: "Saved Open Wi-Fi Networks",
            description: "Remembered open (unencrypted) Wi-Fi networks are a risk — your Mac may auto-join them, exposing your traffic.",
            category: .network,
            severity: .medium
        )
        let result = await ShellCommand.run(
            "defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences KnownNetworks 2>/dev/null | grep -c 'SecurityType = Open'"
        )
        let count = Int(result.output) ?? 0
        if count == 0 {
            check.status = .pass
            check.details = "No saved open Wi-Fi networks found."
        } else {
            check.status = .warning
            check.details = "Found \(count) saved open (unencrypted) Wi-Fi network\(count == 1 ? "" : "s")."
            check.recommendation = "Open System Settings > Network > Wi-Fi > Advanced and remove any open networks you don't need."
        }
        return check
    }

    private func checkWakeOnNetwork() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.wakeonlan",
            name: "Wake on Network Access",
            description: "Wake-on-LAN allows your Mac to be woken remotely, which increases the window of opportunity for attacks.",
            category: .network,
            severity: .low
        )
        let result = await ShellCommand.run("pmset -g 2>/dev/null | grep ' womp' | awk '{print $2}'")
        if result.output == "0" {
            check.status = .pass
            check.details = "Wake on network access is disabled."
        } else if result.output == "1" {
            check.status = .warning
            check.details = "Wake on network access is enabled."
            check.recommendation = "Unless you use Wake-on-LAN, disable it in System Settings > Energy > 'Wake for network access'."
        } else {
            check.status = .info
            check.details = "Could not determine Wake-on-LAN status."
        }
        return check
    }

    private func checkWiFiSecurity() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.wifi.security",
            name: "Wi-Fi Network Security",
            description: "Your current Wi-Fi connection should use WPA2 or WPA3 encryption.",
            category: .network,
            severity: .high
        )
        // Use the system_profiler to get WiFi security info
        let result = await ShellCommand.run("""
            /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | grep -i 'link auth'
            """)
        let output = result.output.lowercased()
        if output.contains("wpa3") {
            check.status = .pass
            check.details = "Connected to a WPA3-secured Wi-Fi network."
        } else if output.contains("wpa2") {
            check.status = .pass
            check.details = "Connected to a WPA2-secured Wi-Fi network."
        } else if output.contains("wep") {
            check.status = .fail
            check.details = "Connected to a WEP-secured network. WEP is broken and trivially crackable."
            check.recommendation = "Switch to a WPA2/WPA3 network or upgrade your router's security settings."
        } else if output.contains("open") || output.contains("none") {
            check.status = .fail
            check.details = "Connected to an open (unencrypted) Wi-Fi network."
            check.recommendation = "Avoid open networks or use a VPN. Switch to a WPA2/WPA3 network."
        } else if output.isEmpty {
            check.status = .info
            check.details = "No Wi-Fi connection detected or could not determine security type."
        } else {
            check.status = .info
            check.details = "Wi-Fi security: \(result.output)"
        }
        return check
    }

    private func checkSysctlHardening() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.sysctl",
            name: "Network Stack Hardening",
            description: "BSD-level network parameters can be hardened to drop unexpected traffic and prevent IP spoofing.",
            category: .network,
            severity: .medium
        )
        let params: [(key: String, expected: String, desc: String)] = [
            ("net.inet.ip.forwarding", "0", "IP forwarding disabled"),
            ("net.inet.ip.redirect", "0", "ICMP redirects ignored"),
            ("net.inet.tcp.blackhole", "2", "TCP blackhole enabled"),
            ("net.inet.udp.blackhole", "1", "UDP blackhole enabled"),
        ]
        var failures: [String] = []
        for param in params {
            let result = await ShellCommand.run("sysctl -n \(param.key) 2>/dev/null")
            if result.output != param.expected {
                failures.append("\(param.key) is \(result.output) (expected \(param.expected))")
            }
        }
        if failures.isEmpty {
            check.status = .pass
            check.details = "All \(params.count) network hardening parameters are set correctly."
        } else {
            check.status = .warning
            check.details = "\(failures.count) of \(params.count) parameters need attention: \(failures.joined(separator: "; "))."
            check.recommendation = "These can be set via sysctl, e.g.: sudo sysctl -w net.inet.ip.forwarding=0. For persistence, add entries to /etc/sysctl.conf."
        }
        return check
    }

    private func checkHTTPServer() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.httpd",
            name: "HTTP Server",
            description: "The built-in Apache HTTP server should not be running unless explicitly needed.",
            category: .network,
            severity: .medium
        )
        let result = await ShellCommand.run("launchctl list 2>/dev/null | grep -c 'org.apache.httpd'")
        let count = Int(result.output) ?? 0
        if count == 0 {
            check.status = .pass
            check.details = "The built-in HTTP server is not running."
        } else {
            check.status = .warning
            check.details = "The built-in Apache HTTP server is running."
            check.recommendation = "If not needed, disable with: sudo launchctl unload -w /System/Library/LaunchDaemons/org.apache.httpd.plist"
        }
        return check
    }

    private func checkNFSServer() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.nfsd",
            name: "NFS Server",
            description: "The NFS server should not be running as it exposes the filesystem over the network.",
            category: .network,
            severity: .medium
        )
        let result = await ShellCommand.run("launchctl list 2>/dev/null | grep -c 'com.apple.nfsd'")
        let count = Int(result.output) ?? 0
        if count == 0 {
            check.status = .pass
            check.details = "The NFS server is not running."
        } else {
            check.status = .warning
            check.details = "The NFS server is running, exposing the filesystem over the network."
            check.recommendation = "If not needed, disable with: sudo nfsd stop && sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.nfsd.plist"
        }
        return check
    }

    private func checkPowerNap() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.powernap",
            name: "Power Nap",
            description: "Power Nap wakes the Mac periodically to check email, updates, and iCloud, which expands the attack surface.",
            category: .network,
            severity: .low
        )
        let result = await ShellCommand.run("pmset -g 2>/dev/null | grep ' powernap' | awk '{print $2}'")
        if result.output == "0" {
            check.status = .pass
            check.details = "Power Nap is disabled."
        } else if result.output == "1" {
            check.status = .info
            check.details = "Power Nap is enabled. Your Mac wakes periodically for background tasks."
            check.recommendation = "If not needed, disable in System Settings > Energy (or Battery) > Power Nap."
        } else {
            check.status = .info
            check.details = "Could not determine Power Nap status."
        }
        return check
    }

    private func checkPromiscuousInterface() async -> SecurityCheck {
        var check = SecurityCheck(
            id: "network.promiscuous",
            name: "Promiscuous Network Interface",
            description: "A network interface in promiscuous mode captures all traffic, not just traffic destined for this Mac. This may indicate packet sniffing.",
            category: .network,
            severity: .high
        )
        let result = await ShellCommand.run("ifconfig 2>/dev/null | grep -c PROMISC")
        let count = Int(result.output) ?? 0
        if count == 0 {
            check.status = .pass
            check.details = "No network interfaces are in promiscuous mode."
        } else {
            check.status = .warning
            check.details = "\(count) network interface\(count == 1 ? " is" : "s are") in promiscuous mode."
            check.recommendation = "Unless you are running a packet capture tool intentionally, investigate which process is sniffing traffic."
        }
        return check
    }
}
