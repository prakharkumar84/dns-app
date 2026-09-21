import Foundation

/// Minimal DNS wire-format reader/writer.
///
/// IMPORTANT: every entry point converts `Data` to `[UInt8]` first. `Data`
/// produced by `subdata(in:)` keeps non-zero start indices, so indexing it with
/// literal offsets (payload[0]) traps at runtime. Working on an array sidesteps
/// that entire class of crash.
public enum DNSMessage {

    public struct Question {
        public let name: String
        public let type: UInt16
        public let klass: UInt16
        /// Offset just past the question section, relative to message start.
        public let endOffset: Int
    }

    public static let typeA: UInt16 = 1
    public static let typeAAAA: UInt16 = 28
    public static let typeHTTPS: UInt16 = 65

    // MARK: - Parsing

    public static func firstQuestion(in payload: Data) -> Question? {
        firstQuestion(in: [UInt8](payload))
    }

    public static func firstQuestion(in bytes: [UInt8]) -> Question? {
        guard bytes.count > 12 else { return nil }

        // Reject responses and non-standard opcodes; we only proxy queries.
        let isResponse = (bytes[2] & 0x80) != 0
        guard !isResponse else { return nil }

        let qdCount = UInt16(bytes[4]) << 8 | UInt16(bytes[5])
        guard qdCount >= 1 else { return nil }

        var offset = 12
        var labels: [String] = []
        var totalLength = 0

        while offset < bytes.count {
            let len = Int(bytes[offset])
            if len == 0 { offset += 1; break }

            // Compression pointers are illegal in a question section.
            guard len < 64 else { return nil }
            guard offset + 1 + len <= bytes.count else { return nil }

            totalLength += len + 1
            guard totalLength <= 255 else { return nil }

            let slice = Array(bytes[(offset + 1)..<(offset + 1 + len)])
            guard let label = String(bytes: slice, encoding: .utf8) else { return nil }
            labels.append(label)
            offset += 1 + len
        }

        guard offset + 4 <= bytes.count, !labels.isEmpty else { return nil }

        let type  = UInt16(bytes[offset])     << 8 | UInt16(bytes[offset + 1])
        let klass = UInt16(bytes[offset + 2]) << 8 | UInt16(bytes[offset + 3])

        return Question(name: labels.joined(separator: "."),
                        type: type,
                        klass: klass,
                        endOffset: offset + 4)
    }

    // MARK: - Blocked response synthesis

    public enum BlockMode: String, Codable, CaseIterable {
        case nxdomain
        case zeroIP

        public var label: String {
            switch self {
            case .nxdomain: return "NXDOMAIN (fastest)"
            case .zeroIP:   return "0.0.0.0 (most compatible)"
            }
        }
    }

    public static func blockedResponse(for query: Data,
                                       question: Question,
                                       mode: BlockMode = .nxdomain) -> Data? {
        let bytes = [UInt8](query)
        guard bytes.count >= question.endOffset, question.endOffset > 12 else { return nil }

        var out = [UInt8]()
        out.reserveCapacity(question.endOffset + 32)

        out.append(bytes[0]); out.append(bytes[1])        // transaction ID
        let recursionDesired = bytes[2] & 0x01

        var answerCount: UInt16 = 0

        switch mode {
        case .nxdomain:
            out.append(0x80 | recursionDesired)            // QR=1, copy RD
            out.append(0x83)                               // RA=1, RCODE=3 (NXDOMAIN)

        case .zeroIP:
            let answerable = question.type == typeA || question.type == typeAAAA
            out.append(0x80 | recursionDesired)            // QR=1, copy RD
            out.append(0x80)                               // RA=1, RCODE=0 (NOERROR)
            answerCount = answerable ? 1 : 0
        }

        out.append(0x00); out.append(0x01)                 // QDCOUNT = 1
        out.append(UInt8(answerCount >> 8)); out.append(UInt8(answerCount & 0xFF))
        out.append(contentsOf: [0, 0, 0, 0])               // NSCOUNT, ARCOUNT

        // Echo the original question section verbatim.
        out.append(contentsOf: bytes[12..<question.endOffset])

        if answerCount == 1 {
            out.append(contentsOf: [0xC0, 0x0C])           // name pointer -> offset 12
            out.append(UInt8(question.type >> 8)); out.append(UInt8(question.type & 0xFF))
            out.append(contentsOf: [0x00, 0x01])           // class IN
            out.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL 60

            if question.type == typeA {
                out.append(contentsOf: [0x00, 0x04])
                out.append(contentsOf: [0, 0, 0, 0])       // 0.0.0.0
            } else {
                out.append(contentsOf: [0x00, 0x10])
                out.append(contentsOf: [UInt8](repeating: 0, count: 16)) // ::
            }
        }

        return Data(out)
    }

    /// Rewrites the transaction ID of a cached response to match a new query.
    public static func rewriteTransactionID(of response: Data, toMatch query: Data) -> Data {
        var bytes = [UInt8](response)
        let queryBytes = [UInt8](query)
        guard bytes.count >= 2, queryBytes.count >= 2 else { return response }
        bytes[0] = queryBytes[0]
        bytes[1] = queryBytes[1]
        return Data(bytes)
    }
}
