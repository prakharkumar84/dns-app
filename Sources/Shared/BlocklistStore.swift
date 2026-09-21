import Foundation

public struct FilterSource: Codable, Identifiable, Hashable {
    public var id: String
    public var name: String
    public var detail: String
    public var url: String
    public var enabled: Bool

    public init(id: String, name: String, detail: String, url: String, enabled: Bool) {
        self.id = id; self.name = name; self.detail = detail
        self.url = url; self.enabled = enabled
    }

    public static let catalog: [FilterSource] = [
        .init(id: "adguard-base", name: "AdGuard DNS Filter",
              detail: "General ads and trackers",
              url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
              enabled: true),
        .init(id: "oisd-small", name: "OISD Small",
              detail: "Balanced, low breakage",
              url: "https://small.oisd.nl/", enabled: true),
        .init(id: "oisd-big", name: "OISD Big",
              detail: "Aggressive, larger list",
              url: "https://big.oisd.nl/", enabled: false),
        .init(id: "hagezi-pro", name: "HaGeZi Multi Pro",
              detail: "Ads, tracking, telemetry",
              url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
              enabled: false),
        .init(id: "malware", name: "Malware & Phishing",
              detail: "Known malicious domains",
              url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
              enabled: true),
        .init(id: "adult", name: "Adult Content",
              detail: "Blocks pornographic sites",
              url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt",
              enabled: false)
    ]
}

public struct UpstreamConfig: Codable, Equatable, Hashable {
    public enum Kind: String, Codable { case doh, dot, udp }

    public var kind: Kind
    public var name: String
    public var address: String       // DoH URL, or hostname/IP for DoT/UDP

    public init(kind: Kind, name: String, address: String) {
        self.kind = kind; self.name = name; self.address = address
    }

    public static let cloudflare = UpstreamConfig(
        kind: .doh, name: "Cloudflare", address: "https://cloudflare-dns.com/dns-query")
    public static let quad9 = UpstreamConfig(
        kind: .doh, name: "Quad9", address: "https://dns.quad9.net/dns-query")
    public static let google = UpstreamConfig(
        kind: .doh, name: "Google", address: "https://dns.google/dns-query")
    public static let adguard = UpstreamConfig(
        kind: .doh, name: "AdGuard DNS", address: "https://dns.adguard-dns.com/dns-query")

    public static let presets: [UpstreamConfig] = [.cloudflare, .quad9, .google, .adguard]
}

/// Storage shared between the container app and the tunnel extension.
/// The app downloads and compiles filter lists; the extension only reads them.
public final class BlocklistStore {

    public static let shared = BlocklistStore()

    private let defaults = AppConfig.sharedDefaults
    private let container = AppConfig.sharedContainer

    private init() {}

    // MARK: - File locations

    private var compiledURL: URL? {
        container?.appendingPathComponent("compiled-rules.txt")
    }
    private var userRulesURL: URL? {
        container?.appendingPathComponent("user-rules.txt")
    }

    // MARK: - Settings

    public var sources: [FilterSource] {
        get {
            guard let data = defaults.data(forKey: "filterSources"),
                  let decoded = try? JSONDecoder().decode([FilterSource].self, from: data)
            else { return FilterSource.catalog }
            return decoded
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: "filterSources") }
    }

    public var upstream: UpstreamConfig {
        get {
            guard let data = defaults.data(forKey: "upstream"),
                  let decoded = try? JSONDecoder().decode(UpstreamConfig.self, from: data)
            else { return .cloudflare }
            return decoded
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: "upstream") }
    }

    public var blockMode: DNSMessage.BlockMode {
        get {
            guard let raw = defaults.string(forKey: "blockMode"),
                  let mode = DNSMessage.BlockMode(rawValue: raw) else { return .nxdomain }
            return mode
        }
        set { defaults.set(newValue.rawValue, forKey: "blockMode") }
    }

    public var lastUpdated: Date? {
        get { defaults.object(forKey: "lastUpdated") as? Date }
        set { defaults.set(newValue, forKey: "lastUpdated") }
    }

    public var compiledRuleCount: Int {
        get { defaults.integer(forKey: "compiledRuleCount") }
        set { defaults.set(newValue, forKey: "compiledRuleCount") }
    }

    // MARK: - User rules

    public var userRules: [String] {
        guard let url = userRulesURL,
              let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }

    public func addUserRule(_ rule: String) {
        guard let url = userRulesURL else { return }
        var rules = userRules
        guard !rules.contains(rule) else { return }
        rules.append(rule)
        try? rules.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    public func removeUserRule(_ rule: String) {
        guard let url = userRulesURL else { return }
        let rules = userRules.filter { $0 != rule }
        try? rules.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    // MARK: - Download & compile (app side)

    public enum RefreshError: LocalizedError {
        case noContainer
        case allSourcesFailed

        public var errorDescription: String? {
            switch self {
            case .noContainer:
                return "App Group container unavailable. Check the App Groups capability."
            case .allSourcesFailed:
                return "Could not download any filter list. Check your connection."
            }
        }
    }

    @discardableResult
    public func refresh(progress: ((String) -> Void)? = nil) async throws -> Int {
        guard let compiledURL else { throw RefreshError.noContainer }

        var merged = String()
        merged.reserveCapacity(8 * 1024 * 1024)
        var succeeded = 0

        for source in sources where source.enabled {
            guard let url = URL(string: source.url) else { continue }
            progress?("Downloading \(source.name)…")
            do {
                var request = URLRequest(url: url)
                request.timeoutInterval = 30
                request.setValue("MyDNS/1.0", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { continue }
                guard let text = String(data: data, encoding: .utf8) else { continue }
                merged += "\n"
                merged += text
                succeeded += 1
            } catch {
                continue   // one bad list should not fail the whole refresh
            }
        }

        guard succeeded > 0 else { throw RefreshError.allSourcesFailed }

        progress?("Adding your rules…")
        merged += "\n"
        merged += userRules.joined(separator: "\n")

        progress?("Compiling…")
        try merged.write(to: compiledURL, atomically: true, encoding: .utf8)

        // Count rules by compiling once here so the UI can display a number.
        let engine = BlocklistEngine()
        engine.replaceAll(with: merged)
        compiledRuleCount = engine.ruleCount
        lastUpdated = Date()

        return engine.ruleCount
    }

    // MARK: - Load (extension side)

    public func loadCompiled(into engine: BlocklistEngine) {
        guard let compiledURL,
              let text = try? String(contentsOf: compiledURL, encoding: .utf8)
        else { return }
        engine.replaceAll(with: text)
    }

    public var hasCompiledRules: Bool {
        guard let compiledURL else { return false }
        return FileManager.default.fileExists(atPath: compiledURL.path)
    }
}
