import SwiftUI

@main
struct MyDNSApp: App {

    @StateObject private var tunnel = TunnelController()
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(tunnel)
                .environmentObject(model)
                .task {
                    // First launch: pull filter lists so there's something to block.
                    if !BlocklistStore.shared.hasCompiledRules {
                        await model.refreshFilters(tunnel: tunnel)
                    }
                }
        }
    }
}

@MainActor
final class AppModel: ObservableObject {

    @Published var stats = StatsSnapshot()
    @Published var sources = BlocklistStore.shared.sources
    @Published var upstream = BlocklistStore.shared.upstream
    @Published var blockMode = BlocklistStore.shared.blockMode

    @Published var isRefreshing = false
    @Published var refreshMessage: String?
    @Published var ruleCount = BlocklistStore.shared.compiledRuleCount
    @Published var lastUpdated = BlocklistStore.shared.lastUpdated

    private let store = BlocklistStore.shared

    func reloadStats() {
        if let snapshot = StatsRecorder.read() { stats = snapshot }
    }

    func refreshFilters(tunnel: TunnelController) async {
        guard !isRefreshing else { return }
        isRefreshing = true
        refreshMessage = "Starting…"

        store.sources = sources

        do {
            let count = try await store.refresh { [weak self] message in
                Task { @MainActor in self?.refreshMessage = message }
            }
            ruleCount = count
            lastUpdated = store.lastUpdated
            refreshMessage = nil
            await tunnel.reloadRules()
        } catch {
            refreshMessage = error.localizedDescription
        }

        isRefreshing = false
    }

    func setUpstream(_ config: UpstreamConfig, tunnel: TunnelController) async {
        upstream = config
        store.upstream = config
        await tunnel.send(.setUpstream(config))
    }

    func setBlockMode(_ mode: DNSMessage.BlockMode, tunnel: TunnelController) async {
        blockMode = mode
        store.blockMode = mode
        await tunnel.send(.setBlockMode(mode))
    }

    func addUserRule(_ domain: String, block: Bool, tunnel: TunnelController) async {
        let cleaned = domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? ""

        guard cleaned.contains("."), !cleaned.isEmpty else { return }

        store.addUserRule(block ? "||\(cleaned)^" : "@@||\(cleaned)^")
        await refreshFilters(tunnel: tunnel)
    }

    func resetStats(tunnel: TunnelController) async {
        await tunnel.send(.resetStats)
        StatsRecorder.clear()
        stats = StatsSnapshot()
    }
}
