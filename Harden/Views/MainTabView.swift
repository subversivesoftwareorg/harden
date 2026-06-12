import SwiftUI

struct MainTabView: View {
    @State private var store = SecurityStore()
    @State private var scanner = SecurityScanner()
    @State private var remediator = RemediationRunner()
    @State private var selectedTab = 0
    @State private var showOnboarding = false

    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @AppStorage("scanOnLaunch") private var scanOnLaunch = true

    var body: some View {
        TabView(selection: $selectedTab) {
            DashboardView()
                .tabItem { Label("Dashboard", systemImage: "gauge.with.dots.needle.33percent") }
                .tag(0)

            ActionItemsView()
                .tabItem {
                    Label("Action Items", systemImage: "checklist")
                }
                .badge(store.actionItems.count)
                .tag(1)

            CheckDetailView()
                .tabItem { Label("All Checks", systemImage: "list.bullet.rectangle") }
                .tag(2)

            STIGReportView()
                .tabItem { Label("STIG Report", systemImage: "shield.checkered") }
                .tag(3)
        }
        .environment(store)
        .environment(scanner)
        .environment(remediator)
        .frame(minWidth: 700, minHeight: 500)
        .sheet(isPresented: $showOnboarding) {
            OnboardingView(isPresented: $showOnboarding)
        }
        .onAppear {
            if !hasCompletedOnboarding {
                showOnboarding = true
            }
            if scanOnLaunch && store.checks.isEmpty {
                Task { await store.runScan(using: scanner) }
            }
        }
    }
}

// MARK: - Onboarding

struct OnboardingView: View {
    @Binding var isPresented: Bool
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var currentPage = 0

    private let pages: [(icon: String, title: String, description: String)] = [
        ("shield.checkered", "Welcome to Harden",
         "See how well your Mac is configured against common threats — and what you can do to improve it."),
        ("gauge.with.dots.needle.33percent", "Your Security Score",
         "Harden checks your firewall, encryption, sharing services, authentication, network settings, and privacy. Your score shows how well-protected you are."),
        ("checklist", "Actionable Recommendations",
         "Every issue comes with a clear fix. Snooze items you're not ready to address — they'll come back when you are."),
    ]

    var body: some View {
        VStack(spacing: 24) {
            let page = pages[currentPage]
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: page.icon)
                    .font(.system(size: 64))
                    .foregroundStyle(.blue)

                Text(page.title)
                    .font(.title2)
                    .fontWeight(.bold)
                    .multilineTextAlignment(.center)

                Text(page.description)
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                Spacer()
            }

            HStack(spacing: 8) {
                ForEach(0..<pages.count, id: \.self) { i in
                    Circle()
                        .fill(i == currentPage ? Color.blue : Color.gray.opacity(0.4))
                        .frame(width: 8, height: 8)
                }
            }

            Button {
                if currentPage < pages.count - 1 {
                    withAnimation { currentPage += 1 }
                } else {
                    hasCompletedOnboarding = true
                    isPresented = false
                }
            } label: {
                Text(currentPage < pages.count - 1 ? "Next" : "Get Started")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 24)
            .padding(.bottom, 24)
        }
        .frame(width: 480, height: 380)
        .interactiveDismissDisabled()
    }
}
