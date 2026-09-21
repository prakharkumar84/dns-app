import Foundation

/// On-device domain matcher backed by a reverse-label trie.
/// Lookup is O(number of labels), independent of list size — 1M+ rules is fine.
///
/// Supported syntax (subset of AdGuard DNS filtering rules):
///   ||example.org^     block domain and all subdomains
///   @@||example.org^   allowlist exception (always wins)
///   0.0.0.0 example.org  /etc/hosts style
///   example.org        domains-only style
///   # or !             comment
public final class BlocklistEngine {

    private final class Node {
        var children: [String: Node] = [:]
        var isTerminal = false        // matches this exact domain
        var coversSubdomains = false  // ||...^ — also matches everything below
    }

    private let blockRoot = Node()
    private let allowRoot = Node()
    private let lock = NSLock()

    public private(set) var ruleCount = 0
    public private(set) var skippedCount = 0

    public init() {}

    // MARK: - Loading

    /// Replaces all currently loaded rules.
    public func replaceAll(with text: String) {
        lock.lock()
        blockRoot.children.removeAll()
        allowRoot.children.removeAll()
        ruleCount = 0
        skippedCount = 0
        lock.unlock()
        load(rules: text)
    }

    /// Merges additional rules into the existing set.
    public func load(rules text: String) {
        lock.lock()
        defer { lock.unlock() }
        text.enumerateLines { line, _ in
            self.ingestLocked(line)
        }
    }

    public func addUserBlock(_ domain: String) {
        lock.lock(); ingestLocked("||\(domain)^"); lock.unlock()
    }

    public func addUserAllow(_ domain: String) {
        lock.lock(); ingestLocked("@@||\(domain)^"); lock.unlock()
    }

    // MARK: - Parsing (caller must hold lock)

    private func ingestLocked(_ rawLine: String) {
        var line = rawLine.trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix("!") else { return }

        // Strip trailing comments.
        if let hash = line.firstIndex(of: "#") {
            line = String(line[line.startIndex..<hash]).trimmingCharacters(in: .whitespaces)
        }
        guard !line.isEmpty else { return }

        var isAllow = false
        var coversSubdomains = false

        if line.hasPrefix("@@") {
            isAllow = true
            line.removeFirst(2)
        }

        // Rule modifiers ($important, $dnstype=, $client=, $denyallow=) change
        // matching semantics we do not implement. Detect them BEFORE trimming at
        // "^", otherwise the marker is stripped and the rule is silently applied
        // as an unconditional block — which over-blocks.
        if line.contains("$") {
            skippedCount += 1
            return
        }

        if line.hasPrefix("||") {
            coversSubdomains = true
            line.removeFirst(2)
            if let separator = line.firstIndex(where: { $0 == "^" || $0 == "/" }) {
                line = String(line[line.startIndex..<separator])
            }
        } else if line.contains(" ") || line.contains("\t") {
            // /etc/hosts style: "0.0.0.0 example.org"
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count >= 2 else { skippedCount += 1; return }
            let ip = String(parts[0])
            guard ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" || ip == "::1" else {
                skippedCount += 1
                return
            }
            line = String(parts[1])
        }

        // Advanced syntax we deliberately do not emulate — skipping is safer
        // than approximating and over-blocking.
        guard !line.hasPrefix("/"),
              !line.contains("$"),
              !line.contains("*"),
              !line.contains("|")
        else { skippedCount += 1; return }

        let domain = line.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: ".^|/ "))

        guard isPlausibleDomain(domain) else { skippedCount += 1; return }

        insertLocked(domain,
                     into: isAllow ? allowRoot : blockRoot,
                     coversSubdomains: coversSubdomains)
        ruleCount += 1
    }

    private func isPlausibleDomain(_ domain: String) -> Bool {
        guard domain.count >= 3, domain.count <= 253, domain.contains(".") else { return false }
        guard !domain.hasPrefix("."), !domain.hasSuffix(".") else { return false }
        // Reject anything with characters that can't appear in a hostname.
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-._")
        return domain.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private func insertLocked(_ domain: String, into root: Node, coversSubdomains: Bool) {
        var node = root
        for label in domain.split(separator: ".").reversed() {
            let key = String(label)
            if let next = node.children[key] {
                node = next
            } else {
                let next = Node()
                node.children[key] = next
                node = next
            }
        }
        node.isTerminal = true
        if coversSubdomains { node.coversSubdomains = true }
    }

    // MARK: - Matching

    public enum Verdict { case allow, block }

    public func verdict(for queryName: String) -> Verdict {
        let domain = queryName.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !domain.isEmpty else { return .allow }

        lock.lock()
        defer { lock.unlock() }

        if matchesLocked(domain, in: allowRoot) { return .allow }
        return matchesLocked(domain, in: blockRoot) ? .block : .allow
    }

    private func matchesLocked(_ domain: String, in root: Node) -> Bool {
        var node = root
        let labels = domain.split(separator: ".").reversed().map(String.init)
        guard !labels.isEmpty else { return false }

        for (index, label) in labels.enumerated() {
            guard let next = node.children[label] else { return false }
            node = next

            // A parent marked with || matches every subdomain beneath it.
            if node.coversSubdomains { return true }

            // Exact match only when we've consumed the whole name.
            if index == labels.count - 1 && node.isTerminal { return true }
        }
        return false
    }
}
