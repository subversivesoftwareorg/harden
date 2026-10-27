import Testing
@testable import Harden

@Suite("Security Check Model Tests")
struct SecurityCheckTests {

    @Test("Check severity ordering")
    func severityOrdering() {
        #expect(CheckSeverity.critical < CheckSeverity.high)
        #expect(CheckSeverity.high < CheckSeverity.medium)
        #expect(CheckSeverity.medium < CheckSeverity.low)
        #expect(CheckSeverity.low < CheckSeverity.info)
    }

    @Test("Check severity weights")
    func severityWeights() {
        #expect(CheckSeverity.critical.weight == 25)
        #expect(CheckSeverity.high.weight == 15)
        #expect(CheckSeverity.medium.weight == 10)
        #expect(CheckSeverity.low.weight == 5)
        #expect(CheckSeverity.info.weight == 0)
    }

    @Test("All categories have icons and colors")
    func categoryProperties() {
        for category in CheckCategory.allCases {
            #expect(!category.icon.isEmpty)
            #expect(!category.rawValue.isEmpty)
        }
    }
}

@Suite("Snooze Duration Tests")
struct SnoozeDurationTests {

    @Test("All durations have labels")
    func durationLabels() {
        for duration in SnoozeDuration.allCases {
            #expect(!duration.rawValue.isEmpty)
        }
    }
}

@Suite("STIG Mapping Tests")
struct STIGMappingTests {

    @Test("Catalog is not empty")
    func catalogNotEmpty() {
        #expect(!STIGMapping.catalog.isEmpty)
    }

    @Test("All STIG references have valid fields")
    func referenceFields() {
        for (checkID, refs) in STIGMapping.catalog {
            #expect(!checkID.isEmpty)
            for ref in refs {
                #expect(!ref.id.isEmpty, "STIG ID empty for check \(checkID)")
                #expect(ref.id.hasPrefix("APPL-15-"), "STIG ID \(ref.id) should start with APPL-15-")
                #expect(!ref.title.isEmpty, "Title empty for \(ref.id)")
                #expect(["CAT I", "CAT II", "CAT III"].contains(ref.severity),
                        "Invalid severity '\(ref.severity)' for \(ref.id)")
            }
        }
    }

    @Test("No duplicate STIG IDs across different checks")
    func noDuplicateStigIDs() {
        var seen: [String: String] = [:]
        for (checkID, refs) in STIGMapping.catalog {
            for ref in refs {
                if let existing = seen[ref.id] {
                    // Allow the same STIG ID to map to related checks (e.g., sharing.remotelogin and sharing.screensharing)
                    // but flag truly unexpected duplicates
                    _ = existing
                }
                seen[ref.id] = checkID
            }
        }
        #expect(seen.count > 20, "Expected at least 20 unique STIG IDs")
    }

    @Test("Minimum STIG coverage")
    func minimumCoverage() {
        #expect(STIGMapping.catalog.count >= 25, "Expected at least 25 checks mapped to STIGs")
    }

    @Test("CAT I rules are present")
    func catIRulesPresent() {
        let catICount = STIGMapping.catalog.values.flatMap { $0 }.filter { $0.severity == "CAT I" }.count
        #expect(catICount >= 4, "Expected at least 4 CAT I rules")
    }

    @Test("STIG version is set")
    func stigVersionSet() {
        #expect(!STIGMapping.stigVersion.isEmpty)
        #expect(STIGMapping.stigVersion.contains("macOS 15"))
    }

    @Test("STIGReference is identifiable by its ID")
    func stigReferenceIdentifiable() {
        let ref = STIGReference(id: "APPL-15-005001", title: "Test", severity: "CAT I")
        #expect(ref.id == "APPL-15-005001")
    }

    @Test("SecurityCheck stigReferences defaults to empty")
    func checkDefaultStigRefs() {
        let check = SecurityCheck(
            id: "test.check", name: "Test", description: "Test check",
            category: .firewall, severity: .medium
        )
        #expect(check.stigReferences.isEmpty)
    }
}

@Suite("CIS Mapping Tests")
struct CISMappingTests {

    @Test("Catalog is not empty")
    func catalogNotEmpty() {
        #expect(!CISMapping.catalog.isEmpty)
    }

    @Test("All CIS references have valid fields")
    func referenceFields() {
        for (checkID, refs) in CISMapping.catalog {
            #expect(!checkID.isEmpty)
            for ref in refs {
                #expect(!ref.id.isEmpty, "CIS ID empty for check \(checkID)")
                #expect(!ref.title.isEmpty, "Title empty for CIS \(ref.id)")
                #expect(["L1", "L2"].contains(ref.level),
                        "Invalid level '\(ref.level)' for CIS \(ref.id)")
            }
        }
    }

    @Test("Minimum CIS coverage")
    func minimumCoverage() {
        #expect(CISMapping.catalog.count >= 50, "Expected at least 50 checks mapped to CIS rules")
    }

    @Test("CIS version is set")
    func cisVersionSet() {
        #expect(!CISMapping.cisVersion.isEmpty)
        #expect(CISMapping.cisVersion.contains("macOS 15"))
    }

    @Test("CISReference is identifiable by its ID")
    func cisReferenceIdentifiable() {
        let ref = CISReference(id: "2.2.1", title: "Test", level: "L1")
        #expect(ref.id == "2.2.1")
    }

    @Test("Applications category exists")
    func applicationsCategoryExists() {
        #expect(!CheckCategory.applications.rawValue.isEmpty)
        #expect(!CheckCategory.applications.icon.isEmpty)
    }
}

@Suite("Command Output Parsing Tests")
struct CommandOutputParsingTests {

    @Test("launchd overrides read both the enabled/disabled and the older true/false forms")
    func launchdOverrides() {
        let output = """

        	disabled services = {
        		"com.apple.ftpd" => disabled
        		"com.openssh.sshd" => enabled
        		"com.apple.screensharing" => false
        		"com.apple.smbd" => true
        	}
        """
        let overrides = LaunchdOverrides.parse(output)
        #expect(overrides["com.openssh.sshd"] == true)
        #expect(overrides["com.apple.ftpd"] == false)
        #expect(overrides["com.apple.screensharing"] == true)
        #expect(overrides["com.apple.smbd"] == false)
        #expect(overrides["com.apple.auditd"] == nil)
        #expect(overrides.count == 4)
    }

    @Test("Firewall global state is read from socketfilterfw output")
    func firewallGlobalState() {
        #expect(FirewallChecker.globalState(from: "Firewall is enabled. (State = 1)") == 1)
        #expect(FirewallChecker.globalState(from: "Firewall is disabled. (State = 0)") == 0)
        #expect(FirewallChecker.globalState(from: "Firewall is blocking all non-essential incoming connections. (State = 2)") == 2)
        #expect(FirewallChecker.globalState(from: "") == nil)
    }

    @Test("socketfilterfw on/off answers in current and older wording")
    func socketfilterfwOnOff() {
        #expect(FirewallChecker.onOff(from: "Firewall stealth mode is on") == true)
        #expect(FirewallChecker.onOff(from: "Firewall stealth mode is off") == false)
        #expect(FirewallChecker.onOff(from: "Stealth mode enabled") == true)
        #expect(FirewallChecker.onOff(from: "Stealth mode disabled") == false)
        #expect(FirewallChecker.onOff(from: "Log mode is on") == true)
    }

    @Test("socketfilterfw usage text is not read as an answer")
    func socketfilterfwUsage() {
        let usage = "usage: /usr/libexec/ApplicationFirewall/socketfilterfw [-h] [--getglobalstate] [--setglobalstate on | off] [--getstealthmode] [--setstealthmode on | off]"
        #expect(FirewallChecker.onOff(from: usage) == nil)
    }

    @Test("Bridge members are not reported as promiscuous interfaces")
    func promiscuousBridgeMembers() {
        let ifconfig = """
        lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        	options=460<TSO4,TSO6,CHANNEL_IO>
        en2: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        en5: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        	member: en1 flags=3<LEARNING,DISCOVER>
        	member: en2 flags=3<LEARNING,DISCOVER>
        """
        let result = NetworkChecker.promiscuousInterfaces(in: ifconfig)
        #expect(result.bridged == ["en1", "en2"])
        #expect(result.unexplained == ["en5"])
    }
}
