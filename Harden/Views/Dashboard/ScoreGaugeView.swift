import SwiftUI

struct ScoreGaugeView: View {
    let score: Int

    private var progress: Double { Double(score) / 100.0 }

    private var color: Color {
        switch score {
        case 90...100: .green
        case 75..<90: .blue
        case 50..<75: .orange
        default: .red
        }
    }

    var body: some View {
        ZStack {
            // Background track
            Circle()
                .trim(from: 0.0, to: 0.75)
                .stroke(Color.secondary.opacity(0.2), style: StrokeStyle(lineWidth: 16, lineCap: .round))
                .rotationEffect(.degrees(135))

            // Score arc
            Circle()
                .trim(from: 0.0, to: progress * 0.75)
                .stroke(color, style: StrokeStyle(lineWidth: 16, lineCap: .round))
                .rotationEffect(.degrees(135))
                .animation(.easeInOut(duration: 0.8), value: score)

            // Score text
            VStack(spacing: 4) {
                Text("\(score)")
                    .font(.system(size: 48, weight: .bold, design: .rounded))
                    .contentTransition(.numericText())
                    .animation(.easeInOut(duration: 0.8), value: score)
                Text("Security Score")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
