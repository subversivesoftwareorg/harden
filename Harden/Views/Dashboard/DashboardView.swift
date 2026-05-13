import SwiftUI

struct DashboardView: View {
    @Environment(SecurityStore.self) private var store

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection
                categoryGrid
                if let date = store.lastScanDate {
                    Text("Last scan: \(date.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
        }
        .overlay {
            if store.isScanning && store.checks.isEmpty {
                VStack(spacing: 12) {
                    ProgressView()
                        .controlSize(.large)
                    Text("Scanning your Mac...")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var headerSection: some View {
        VStack(spacing: 16) {
            ScoreGaugeView(score: store.score)
                .frame(width: 200, height: 200)

            Text(scoreLabel)
                .font(.title3)
                .fontWeight(.medium)
                .foregroundStyle(scoreColor)

            if store.actionItems.count > 0 {
                Text("\(store.actionItems.count) item\(store.actionItems.count == 1 ? "" : "s") to review")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 8)
    }

    private var categoryGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: 16)], spacing: 16) {
            ForEach(store.categorySummaries) { summary in
                CategoryCardView(summary: summary)
            }
        }
    }

    private var scoreLabel: String {
        switch store.score {
        case 90...100: "Excellent"
        case 75..<90: "Good"
        case 50..<75: "Needs Attention"
        default: "At Risk"
        }
    }

    private var scoreColor: Color {
        switch store.score {
        case 90...100: .green
        case 75..<90: .blue
        case 50..<75: .orange
        default: .red
        }
    }
}
