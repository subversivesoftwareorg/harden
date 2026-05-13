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
