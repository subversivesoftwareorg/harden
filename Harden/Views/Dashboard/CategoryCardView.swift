import SwiftUI

struct CategoryCardView: View {
    let summary: CategorySummary

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: summary.category.icon)
                    .foregroundStyle(summary.category.color)
                    .font(.title3)
                Text(summary.category.rawValue)
                    .font(.headline)
                Spacer()
                statusBadge
            }

            HStack(spacing: 12) {
                if summary.passed > 0 {
                    Label("\(summary.passed)", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                }
                if summary.warnings > 0 {
                    Label("\(summary.warnings)", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption)
                }
                if summary.failures > 0 {
                    Label("\(summary.failures)", systemImage: "xmark.circle.fill")
                        .foregroundStyle(.red)
                        .font(.caption)
                }
            }

            // Progress bar
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color.secondary.opacity(0.15))
                    RoundedRectangle(cornerRadius: 3)
                        .fill(barColor)
                        .frame(width: geometry.size.width * barProgress)
                        .animation(.easeInOut(duration: 0.6), value: summary.score)
                }
            }
            .frame(height: 6)
        }
        .padding()
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var barProgress: CGFloat {
        CGFloat(summary.score) / 100.0
    }

    private var barColor: Color {
        switch summary.score {
        case 90...100: .green
        case 75..<90: .blue
        case 50..<75: .orange
        default: .red
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        if summary.failures > 0 {
            Image(systemName: "exclamationmark.circle.fill")
                .foregroundStyle(.red)
        } else if summary.warnings > 0 {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        } else {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
        }
    }
}
