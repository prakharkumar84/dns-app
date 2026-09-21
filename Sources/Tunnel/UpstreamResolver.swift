import Foundation
import Network

/// Forwards allowed queries to a real resolver and caches the answers.
final class UpstreamResolver {

    private let queue = DispatchQueue(label: "mydns.resolver", qos: .userInitiated)
    private let session: URLSession
    private let cache = ResponseCache()

    private var config: UpstreamConfig = .cloudflare

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 6
        configuration.timeoutIntervalForResource = 8
        configuration.httpMaximumConnectionsPerHost = 10
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.waitsForConnectivity = false
        configuration.allowsCellularAccess = true
        session = URLSession(configuration: configuration)
    }

    func configure(with newConfig: UpstreamConfig) {
        queue.sync {
            guard newConfig != config else { return }
            config = newConfig
            cache.purge()
        }
    }

    func shutdown() {
        session.invalidateAndCancel()
        cache.purge()
    }

    func resolve(_ query: Data, completion: @escaping (Data?) -> Void) {
        if let cached = cache.response(for: query) {
            completion(DNSMessage.rewriteTransactionID(of: cached, toMatch: query))
            return
        }

        let current = queue.sync { config }

        switch current.kind {
        case .doh:
            resolveDoH(query, config: current, completion: completion)
        case .dot:
            resolveStream(query, config: current, useTLS: true, completion: completion)
        case .udp:
            resolveDatagram(query, config: current, completion: completion)
        }
    }

    // MARK: - DoH (RFC 8484)

    private func resolveDoH(_ query: Data,
                            config: UpstreamConfig,
                            completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: config.address) else { return completion(nil) }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = query

        session.dataTask(with: request) { [weak self] data, response, _ in
            guard let data,
                  let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  data.count >= 12
            else { return completion(nil) }

            self?.cache.store(response: data, for: query)
            completion(data)
        }.resume()
    }

    // MARK: - DoT (TCP + TLS, 2-byte length prefix)

    private func resolveStream(_ query: Data,
                               config: UpstreamConfig,
                               useTLS: Bool,
                               completion: @escaping (Data?) -> Void) {
        let host = NWEndpoint.Host(config.address)
        let port: NWEndpoint.Port = useTLS ? 853 : 53
        let parameters: NWParameters = useTLS ? .tls : .tcp

        let connection = NWConnection(host: host, port: port, using: parameters)

        var completed = false
        let finish: (Data?) -> Void = { [weak self] result in
            guard !completed else { return }
            completed = true
            connection.cancel()
            if let result { self?.cache.store(response: result, for: query) }
            completion(result)
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                var framed = Data([UInt8((query.count >> 8) & 0xFF),
                                   UInt8(query.count & 0xFF)])
                framed.append(query)

                connection.send(content: framed, completion: .contentProcessed { error in
                    if error != nil { finish(nil) }
                })

                // Read the 2-byte length prefix, then the body.
                connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { header, _, _, _ in
                    guard let header, header.count == 2 else { return finish(nil) }
                    let bytes = [UInt8](header)
                    let expected = Int(bytes[0]) << 8 | Int(bytes[1])
                    guard expected > 0, expected <= 8192 else { return finish(nil) }

                    connection.receive(minimumIncompleteLength: expected,
                                       maximumLength: expected) { body, _, _, _ in
                        guard let body, body.count >= 12 else { return finish(nil) }
                        finish(body)
                    }
                }

            case .failed, .cancelled:
                finish(nil)

            default:
                break
            }
        }

        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 6) { finish(nil) }
    }

    // MARK: - Plain UDP

    private func resolveDatagram(_ query: Data,
                                 config: UpstreamConfig,
                                 completion: @escaping (Data?) -> Void) {
        let host = NWEndpoint.Host(config.address)
        let connection = NWConnection(host: host, port: 53, using: .udp)

        var completed = false
        let finish: (Data?) -> Void = { [weak self] result in
            guard !completed else { return }
            completed = true
            connection.cancel()
            if let result { self?.cache.store(response: result, for: query) }
            completion(result)
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: query, completion: .contentProcessed { error in
                    if error != nil { finish(nil) }
                })
                connection.receiveMessage { data, _, _, _ in
                    guard let data, data.count >= 12 else { return finish(nil) }
                    finish(data)
                }
            case .failed, .cancelled:
                finish(nil)
            default:
                break
            }
        }

        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }
}

// MARK: - Cache

private final class ResponseCache {

    private struct Entry {
        let data: Data
        let expires: Date
    }

    private var storage: [String: Entry] = [:]
    private var insertionOrder: [String] = []
    private let lock = NSLock()
    private let limit = 1_500

    private func key(for query: Data) -> String? {
        guard let question = DNSMessage.firstQuestion(in: query) else { return nil }
        return "\(question.name)|\(question.type)"
    }

    func response(for query: Data) -> Data? {
        guard let key = key(for: query) else { return nil }
        lock.lock(); defer { lock.unlock() }

        guard let entry = storage[key] else { return nil }
        guard entry.expires > Date() else {
            storage.removeValue(forKey: key)
            return nil
        }
        return entry.data
    }

    func store(response: Data, for query: Data) {
        guard let key = key(for: query), response.count >= 12 else { return }
        lock.lock(); defer { lock.unlock() }

        if storage[key] == nil {
            insertionOrder.append(key)
        }
        storage[key] = Entry(data: response,
                             expires: Date().addingTimeInterval(minTTL(in: response)))

        // Simple FIFO eviction — cheap and predictable under memory pressure.
        while insertionOrder.count > limit {
            let oldest = insertionOrder.removeFirst()
            storage.removeValue(forKey: oldest)
        }
    }

    /// Honour the record TTL rather than a flat guess, clamped to sane bounds.
    private func minTTL(in response: Data) -> TimeInterval {
        let bytes = [UInt8](response)
        guard bytes.count > 12 else { return 60 }
        let answerCount = Int(bytes[6]) << 8 | Int(bytes[7])
        guard answerCount > 0,
              let question = DNSMessage.firstQuestion(in: bytes)
        else { return 60 }

        var offset = question.endOffset
        var lowest: UInt32 = .max

        for _ in 0..<answerCount {
            // Skip the name (pointer or sequence of labels).
            guard offset < bytes.count else { break }
            if bytes[offset] & 0xC0 == 0xC0 {
                offset += 2
            } else {
                while offset < bytes.count, bytes[offset] != 0 {
                    offset += Int(bytes[offset]) + 1
                }
                offset += 1
            }
            guard offset + 10 <= bytes.count else { break }
            let ttl = UInt32(bytes[offset + 4]) << 24 | UInt32(bytes[offset + 5]) << 16
                    | UInt32(bytes[offset + 6]) << 8  | UInt32(bytes[offset + 7])
            lowest = min(lowest, ttl)
            let rdLength = Int(bytes[offset + 8]) << 8 | Int(bytes[offset + 9])
            offset += 10 + rdLength
        }

        guard lowest != .max else { return 60 }
        return TimeInterval(min(max(lowest, 30), 3600))
    }

    func purge() {
        lock.lock()
        storage.removeAll(keepingCapacity: false)
        insertionOrder.removeAll(keepingCapacity: false)
        lock.unlock()
    }
}
