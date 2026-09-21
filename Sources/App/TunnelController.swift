import Foundation
import NetworkExtension
import Combine

@MainActor
final class TunnelController: ObservableObject {

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published var errorMessage: String?
    @Published private(set) var isInstalling = false

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    var isRunning: Bool { status == .connected }
    var isBusy: Bool { status == .connecting || status == .disconnecting || status == .reasserting }

    var statusText: String {
        switch status {
        case .connected:     return "Protected"
        case .connecting:    return "Connecting…"
        case .disconnecting: return "Stopping…"
        case .reasserting:   return "Reconnecting…"
        case .invalid:       return "Not configured"
        default:             return "Not protected"
        }
    }

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let manager = self.manager else { return }
                self.status = manager.connection.status
            }
        }
        Task { await load() }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    // MARK: - Setup

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                manager = existing
                status = existing.connection.status
            } else {
                manager = nil
                status = .invalid
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Creates the VPN profile. iOS presents a system permission sheet the first time.
    @discardableResult
    func install() async -> Bool {
        isInstalling = true
        defer { isInstalling = false }

        let target = manager ?? NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleID
        // Shown under Settings > VPN. Not a real server — filtering is local.
        proto.serverAddress = "On-device filtering"
        proto.providerConfiguration = [:]
        proto.disconnectOnSleep = false

        target.protocolConfiguration = proto
        target.localizedDescription = "MyDNS Protection"
        target.isEnabled = true

        // Keep protection on across network changes.
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        target.onDemandRules = [rule]
        target.isOnDemandEnabled = true

        do {
            try await target.saveToPreferences()
            // Reload so the connection object becomes valid.
            try await target.loadFromPreferences()
            manager = target
            status = target.connection.status
            errorMessage = nil
            return true
        } catch {
            errorMessage = friendlyMessage(for: error)
            return false
        }
    }

    // MARK: - Control

    func start() async {
        if manager == nil || manager?.protocolConfiguration == nil {
            guard await install() else { return }
        }
        guard let manager else { return }

        do {
            try manager.connection.startVPNTunnel()
            errorMessage = nil
        } catch {
            errorMessage = friendlyMessage(for: error)
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    func toggle() async {
        if isRunning { stop() } else { await start() }
    }

    func removeProfile() async {
        guard let manager else { return }
        do {
            try await manager.removeFromPreferences()
            self.manager = nil
            status = .invalid
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Messaging the extension

    @discardableResult
    func send(_ command: TunnelCommand) async -> Data? {
        guard isRunning,
              let session = manager?.connection as? NETunnelProviderSession,
              let payload = try? JSONEncoder().encode(command)
        else { return nil }

        return await withCheckedContinuation { continuation in
            var resumed = false
            do {
                try session.sendProviderMessage(payload) { response in
                    guard !resumed else { return }
                    resumed = true
                    continuation.resume(returning: response)
                }
            } catch {
                if !resumed {
                    resumed = true
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    func reloadRules() async { await send(.reloadRules) }

    // MARK: - Errors

    private func friendlyMessage(for error: Error) -> String {
        let nsError = error as NSError
        if nsError.domain == NEVPNErrorDomain {
            switch NEVPNError.Code(rawValue: nsError.code) {
            case .configurationInvalid:
                return "VPN configuration is invalid. Check that the extension bundle ID matches AppConfig.tunnelBundleID."
            case .configurationDisabled:
                return "The VPN configuration is disabled in Settings."
            case .configurationReadWriteFailed:
                return "Permission denied. Allow the VPN configuration when iOS asks."
            case .configurationStale:
                return "Configuration changed elsewhere. Reopen the app and try again."
            default:
                break
            }
        }
        return error.localizedDescription
    }
}
