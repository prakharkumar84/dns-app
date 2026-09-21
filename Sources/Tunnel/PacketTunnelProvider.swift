import NetworkExtension
import os.log

/// Local-only VPN: no remote server. We claim a small private subnet, advertise
/// a virtual resolver inside it, and route ONLY that address into the tunnel.
/// Real traffic never enters our code path — we see DNS and nothing else.
final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = Logger(subsystem: "com.mydns.app.tunnel", category: "tunnel")

    private let engine = BlocklistEngine()
    private let resolver = UpstreamResolver()
    private let stats = StatsRecorder()
    private let store = BlocklistStore.shared

    private var blockMode: DNSMessage.BlockMode = .nxdomain
    private var isPaused = false

    // MARK: - Lifecycle

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {

        store.loadCompiled(into: engine)
        resolver.configure(with: store.upstream)
        blockMode = store.blockMode

        log.info("Tunnel starting with \(self.engine.ruleCount, privacy: .public) rules")

        setTunnelNetworkSettings(makeSettings()) { [weak self] error in
            guard let self else { return }
            if let error {
                self.log.error("Failed to apply settings: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }
            self.readPackets()
            completionHandler(nil)
        }
    }

    private func makeSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: AppConfig.Network.virtualDNS)

        let ipv4 = NEIPv4Settings(addresses: [AppConfig.Network.virtualAddress],
                                  subnetMasks: [AppConfig.Network.virtualNetmask])
        // Critical: only the virtual resolver is routed through the tunnel.
        // Everything else keeps using the normal network path.
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: AppConfig.Network.virtualDNS,
                        subnetMask: "255.255.255.255")
        ]
        ipv4.excludedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [AppConfig.Network.virtualDNS])
        dns.matchDomains = [""]               // intercept every domain
        settings.dnsSettings = dns
        settings.mtu = AppConfig.Network.mtu

        return settings
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("Tunnel stopping, reason \(reason.rawValue, privacy: .public)")
        stats.flush()
        resolver.shutdown()
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        stats.flush()
        completionHandler()
    }

    // MARK: - App messaging

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        guard let command = try? JSONDecoder().decode(TunnelCommand.self, from: messageData) else {
            completionHandler?(nil)
            return
        }

        switch command {
        case .reloadRules:
            store.loadCompiled(into: engine)
            log.info("Reloaded \(self.engine.ruleCount, privacy: .public) rules")
            completionHandler?(nil)

        case .setUpstream(let config):
            resolver.configure(with: config)
            completionHandler?(nil)

        case .setBlockMode(let mode):
            blockMode = mode
            completionHandler?(nil)

        case .fetchStats:
            completionHandler?(stats.encodedSnapshot())

        case .resetStats:
            stats.reset()
            completionHandler?(nil)
        }
    }

    // MARK: - Packet loop

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }

            for (index, packet) in packets.enumerated() {
                let family = protocols[index].int32Value
                guard family == AF_INET || family == AF_INET6 else { continue }
                self.handle(packet: packet, family: family)
            }

            self.readPackets()   // keep draining
        }
    }

    private func handle(packet: Data, family: Int32) {
        guard let datagram = UDPDatagram(packet: packet),
              datagram.destinationPort == 53,
              let question = DNSMessage.firstQuestion(in: datagram.payload)
        else { return }

        let verdict = isPaused ? .allow : engine.verdict(for: question.name)

        switch verdict {
        case .block:
            stats.record(domain: question.name, blocked: true)
            guard let response = DNSMessage.blockedResponse(for: datagram.payload,
                                                            question: question,
                                                            mode: blockMode)
            else { return }
            write(response, replyingTo: datagram, family: family)

        case .allow:
            stats.record(domain: question.name, blocked: false)
            resolver.resolve(datagram.payload) { [weak self] answer in
                guard let self, let answer else { return }
                self.write(answer, replyingTo: datagram, family: family)
            }
        }
    }

    private func write(_ dnsPayload: Data, replyingTo request: UDPDatagram, family: Int32) {
        let reply = request.makeReply(payload: dnsPayload)
        packetFlow.writePackets([reply], withProtocols: [NSNumber(value: family)])
    }
}
