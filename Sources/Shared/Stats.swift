import Foundation

public struct StatsSnapshot: Codable {
    public var blocked: Int = 0
    public var allowed: Int = 0
    public var topBlocked: [String: Int] = [:]
    public var recent: [LogEntry] = []
    public var updated: Date = .init()

    public struct LogEntry: Codable, Identifiable, Hashable {
        public var id: UUID = UUID()
        public var domain: String
        public var blocked: Bool
        public var at: Date
    }

    public var total: Int { blocked + allowed }
    public var blockRate: Double {
        total == 0 ? 0 : Double(blocked) / Double(total)
    }
}

/// Counters kept in memory inside the extension and flushed to the App Group
/// on a timer. Packet tunnel extensions run under a tight memory budget, so
/// bounds here are deliberately small.
public final class StatsRecorder {

    private var snapshot = StatsSnapshot()
    private let lock = NSLock()
    private var lastFlush = Date.distantPast
    private let flushInterval: TimeInterval = 5
    private let maxTopEntries = 120
    private let maxRecentEntries = 60

    public init() {
        // Resume from whatever the previous session left behind.
        if let existing = StatsRecorder.read() {
            snapshot = existing
            snapshot.recent = []
        }
    }

    public func record(domain: String, blocked: Bool) {
        lock.lock()

        if blocked {
            snapshot.blocked += 1
            snapshot.topBlocked[domain, default: 0] += 1
            if snapshot.topBlocked.count > maxTopEntries * 2 { trimTopLocked() }
        } else {
            snapshot.allowed += 1
        }

        snapshot.recent.insert(
            .init(domain: domain, blocked: blocked, at: Date()), at: 0)
        if snapshot.recent.count > maxRecentEntries {
            snapshot.recent.removeLast(snapshot.recent.count - maxRecentEntries)
        }

        let shouldFlush = Date().timeIntervalSince(lastFlush) > flushInterval
        lock.unlock()

        if shouldFlush { flush() }
    }

    private func trimTopLocked() {
        snapshot.topBlocked = Dictionary(
            uniqueKeysWithValues: snapshot.topBlocked
                .sorted { $0.value > $1.value }
                .prefix(maxTopEntries)
        )
    }

    public func flush() {
        lock.lock()
        snapshot.updated = Date()
        trimTopLocked()
        let data = try? JSONEncoder().encode(snapshot)
        lock.unlock()

        lastFlush = Date()
        AppConfig.sharedDefaults.set(data, forKey: "stats")
    }

    public func encodedSnapshot() -> Data? {
        lock.lock(); defer { lock.unlock() }
        return try? JSONEncoder().encode(snapshot)
    }

    public func reset() {
        lock.lock()
        snapshot = StatsSnapshot()
        lock.unlock()
        flush()
    }

    // MARK: - App-side reading

    public static func read() -> StatsSnapshot? {
        guard let data = AppConfig.sharedDefaults.data(forKey: "stats"),
              let decoded = try? JSONDecoder().decode(StatsSnapshot.self, from: data)
        else { return nil }
        return decoded
    }

    public static func clear() {
        AppConfig.sharedDefaults.removeObject(forKey: "stats")
    }
}

/// Messages passed between the container app and the running extension.
public enum TunnelCommand: Codable {
    case reloadRules
    case setUpstream(UpstreamConfig)
    case setBlockMode(DNSMessage.BlockMode)
    case fetchStats
    case resetStats
}
