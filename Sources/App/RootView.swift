import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            DashboardView()
                .tabItem { Label("Protection", systemImage: "shield.fill") }
            LogView()
                .tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
            FiltersView()
                .tabItem { Label("Filters", systemImage: "line.3.horizontal.decrease.circle") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}

// MARK: - Dashboard

struct DashboardView: View {

    @EnvironmentObject private var tunnel: TunnelController
    @EnvironmentObject private var model: AppModel
    @State private var pulse = false

    private let timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 28) {
                    shieldButton
                    statusLine
                    statCards
                    if !model.stats.topBlocked.isEmpty { topBlockedSection }
                }
                .padding(.bottom, 32)
            }
            .navigationTitle("MyDNS")
            .onReceive(timer) { _ in model.reloadStats() }
            .onAppear { model.reloadStats() }
        }
    }

    private var shieldButton: some View {
        Button {
            Task { await tunnel.toggle() }
        } label: {
            ZStack {
                Circle()
                    .fill(tunnel.isRunning ? Color.green.opacity(0.14) : Color.secondary.opacity(0.10))
                    .frame(width: 200, height: 200)

                Circle()
                    .strokeBorder(tunnel.isRunning ? Color.green : Color.secondary.opacity(0.5),
                                  lineWidth: 3)
                    .frame(width: 200, height: 200)
                    .scaleEffect(pulse && tunnel.isRunning ? 1.04 : 1.0)
                    .opacity(pulse && tunnel.isRunning ? 0.5 : 1.0)

                VStack(spacing: 10) {
                    Image(systemName: tunnel.isRunning ? "shield.fill" : "shield.slash")
                        .font(.system(size: 56, weight: .light))
                    Text(tunnel.isRunning ? "ON" : "OFF")
                        .font(.title3.weight(.bold))
                }
                .foregroundStyle(tunnel.isRunning ? Color.green : Color.secondary)

                if tunnel.isBusy || tunnel.isInstalling {
                    ProgressView().controlSize(.large)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(tunnel.isBusy || tunnel.isInstalling)
        .padding(.top, 28)
        .onAppear {
            withAnimation(.easeInOut(duration: 1.6).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
    }

    private var statusLine: some View {
        VStack(spacing: 6) {
            Text(tunnel.statusText)
                .font(.title3.weight(.semibold))

            Text(tunnel.isRunning
                 ? "Filtering \(model.ruleCount.formatted()) rules on this device"
                 : "Tap the shield to start blocking")
                .font(.footnote)
                .foregroundStyle(.secondary)

            if let error = tunnel.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .padding(.top, 4)
            }
        }
    }

    private var statCards: some View {
        HStack(spacing: 12) {
            StatCard(title: "Blocked", value: model.stats.blocked.formatted(), tint: .red)
            StatCard(title: "Allowed", value: model.stats.allowed.formatted(), tint: .blue)
            StatCard(title: "Block rate",
                     value: model.stats.blockRate.formatted(.percent.precision(.fractionLength(0))),
                     tint: .purple)
        }
        .padding(.horizontal)
    }

    private var topBlockedSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Most blocked")
                .font(.headline)
                .padding(.horizontal)

            VStack(spacing: 0) {
                ForEach(Array(model.stats.topBlocked
                    .sorted { $0.value > $1.value }
                    .prefix(8)), id: \.key) { domain, count in
                    HStack {
                        Text(domain)
                            .font(.subheadline)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Text(count.formatted())
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 10)
                    Divider().padding(.leading)
                }
            }
            .background(Color.secondary.opacity(0.06),
                        in: RoundedRectangle(cornerRadius: 14))
            .padding(.horizontal)
        }
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let tint: Color

    var body: some View {
        VStack(spacing: 6) {
            Text(value)
                .font(.title2.weight(.bold).monospacedDigit())
                .foregroundStyle(tint)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .background(Color.secondary.opacity(0.08),
                    in: RoundedRectangle(cornerRadius: 14))
    }
}

// MARK: - Activity log

struct LogView: View {

    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var tunnel: TunnelController
    @State private var showBlockedOnly = false

    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    private var entries: [StatsSnapshot.LogEntry] {
        showBlockedOnly ? model.stats.recent.filter(\.blocked) : model.stats.recent
    }

    var body: some View {
        NavigationStack {
            List {
                if entries.isEmpty {
                    ContentUnavailableView(
                        "No activity yet",
                        systemImage: "list.bullet.rectangle",
                        description: Text("Turn on protection and browse — queries appear here.")
                    )
                } else {
                    ForEach(entries) { entry in
                        HStack(spacing: 12) {
                            Image(systemName: entry.blocked ? "xmark.shield.fill" : "checkmark.shield")
                                .foregroundStyle(entry.blocked ? .red : .green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.domain)
                                    .font(.subheadline)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Text(entry.at, style: .time)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(entry.blocked ? "Allow" : "Block") {
                                Task {
                                    await model.addUserRule(entry.domain,
                                                            block: !entry.blocked,
                                                            tunnel: tunnel)
                                }
                            }
                            .font(.caption)
                            .buttonStyle(.bordered)
                        }
                    }
                }
            }
            .navigationTitle("Activity")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Toggle("Blocked only", isOn: $showBlockedOnly)
                        Button("Reset statistics", role: .destructive) {
                            Task { await model.resetStats(tunnel: tunnel) }
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .onReceive(timer) { _ in model.reloadStats() }
        }
    }
}

// MARK: - Filters

struct FiltersView: View {

    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var tunnel: TunnelController
    @State private var newDomain = ""
    @State private var addAsBlock = true

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach($model.sources) { $source in
                        Toggle(isOn: $source.enabled) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(source.name)
                                Text(source.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("Blocklists")
                } footer: {
                    Text("Changes apply after you update filters below.")
                }

                Section("Your own rules") {
                    HStack {
                        TextField("example.com", text: $newDomain)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                        Picker("", selection: $addAsBlock) {
                            Text("Block").tag(true)
                            Text("Allow").tag(false)
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 130)
                    }

                    Button("Add rule") {
                        let domain = newDomain
                        newDomain = ""
                        Task { await model.addUserRule(domain, block: addAsBlock, tunnel: tunnel) }
                    }
                    .disabled(!newDomain.contains("."))

                    ForEach(BlocklistStore.shared.userRules, id: \.self) { rule in
                        Text(rule).font(.caption.monospaced())
                    }
                    .onDelete { offsets in
                        let rules = BlocklistStore.shared.userRules
                        offsets.forEach { BlocklistStore.shared.removeUserRule(rules[$0]) }
                    }
                }

                Section {
                    Button {
                        Task { await model.refreshFilters(tunnel: tunnel) }
                    } label: {
                        HStack {
                            Text(model.isRefreshing ? "Updating…" : "Update filters now")
                            if model.isRefreshing {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(model.isRefreshing)

                    LabeledContent("Rules loaded", value: model.ruleCount.formatted())

                    if let updated = model.lastUpdated {
                        LabeledContent("Last updated",
                                       value: updated.formatted(.relative(presentation: .named)))
                    }
                } footer: {
                    if let message = model.refreshMessage {
                        Text(message).foregroundStyle(model.isRefreshing ? .secondary : .red)
                    }
                }
            }
            .navigationTitle("Filters")
            .onChange(of: model.sources) { _, new in
                BlocklistStore.shared.sources = new
            }
        }
    }
}

// MARK: - Settings

struct SettingsView: View {

    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var tunnel: TunnelController

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(UpstreamConfig.presets, id: \.self) { preset in
                        Button {
                            Task { await model.setUpstream(preset, tunnel: tunnel) }
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(preset.name).foregroundStyle(.primary)
                                    Text(preset.kind.rawValue.uppercased())
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if model.upstream == preset {
                                    Image(systemName: "checkmark").foregroundStyle(.tint)
                                }
                            }
                        }
                    }
                } header: {
                    Text("Upstream resolver")
                } footer: {
                    Text("Allowed queries are forwarded here over encrypted DNS. Blocked queries never leave your device.")
                }

                Section("Blocking response") {
                    Picker("Respond with", selection: Binding(
                        get: { model.blockMode },
                        set: { mode in Task { await model.setBlockMode(mode, tunnel: tunnel) } }
                    )) {
                        ForEach(DNSMessage.BlockMode.allCases, id: \.self) { mode in
                            Text(mode.label).tag(mode)
                        }
                    }
                }

                Section("VPN profile") {
                    LabeledContent("Status", value: tunnel.statusText)
                    Button("Remove VPN profile", role: .destructive) {
                        Task { await tunnel.removeProfile() }
                    }
                }

                Section {
                    LabeledContent("Version", value: appVersion)
                } footer: {
                    Text("MyDNS uses a local VPN to filter DNS on-device. No data is collected, logged, or transmitted to any server we control.")
                }
            }
            .navigationTitle("Settings")
        }
    }

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(version) (\(build))"
    }
}
