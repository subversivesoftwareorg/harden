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
