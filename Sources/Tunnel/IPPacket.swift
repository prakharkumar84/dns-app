import Foundation

/// Parses IPv4/IPv6 + UDP packets off the tunnel and rebuilds correctly
/// checksummed reply packets going the opposite direction.
struct UDPDatagram {

    enum IPVersion { case v4, v6 }

    let version: IPVersion
    let sourceAddress: [UInt8]      // 4 bytes for v4, 16 for v6
    let destinationAddress: [UInt8]
    let sourcePort: UInt16
    let destinationPort: UInt16
    let payload: Data

    // MARK: - Parse

    init?(packet: Data) {
        let bytes = [UInt8](packet)
        guard let first = bytes.first else { return nil }

        switch first >> 4 {
        case 4:  self.init(v4: bytes)
        case 6:  self.init(v6: bytes)
        default: return nil
        }
    }

    private init?(v4 bytes: [UInt8]) {
        guard bytes.count >= 28 else { return nil }

        let ihl = Int(bytes[0] & 0x0F) * 4
        guard ihl >= 20, bytes.count >= ihl + 8 else { return nil }
        guard bytes[9] == 17 else { return nil }              // 17 = UDP

        // Fragmented packets can't be parsed standalone.
        let fragmentOffset = (UInt16(bytes[6] & 0x1F) << 8) | UInt16(bytes[7])
        guard fragmentOffset == 0 else { return nil }

        version = .v4
        sourceAddress      = Array(bytes[12..<16])
        destinationAddress = Array(bytes[16..<20])
        sourcePort      = UInt16(bytes[ihl])     << 8 | UInt16(bytes[ihl + 1])
        destinationPort = UInt16(bytes[ihl + 2]) << 8 | UInt16(bytes[ihl + 3])

        let udpLength = Int(UInt16(bytes[ihl + 4]) << 8 | UInt16(bytes[ihl + 5]))
        guard udpLength >= 8 else { return nil }

        let start = ihl + 8
        let end = min(bytes.count, ihl + udpLength)
        guard end > start else { return nil }
        payload = Data(bytes[start..<end])
    }

    private init?(v6 bytes: [UInt8]) {
        guard bytes.count >= 48 else { return nil }
        guard bytes[6] == 17 else { return nil }              // next header = UDP

        version = .v6
        sourceAddress      = Array(bytes[8..<24])
        destinationAddress = Array(bytes[24..<40])
        sourcePort      = UInt16(bytes[40]) << 8 | UInt16(bytes[41])
        destinationPort = UInt16(bytes[42]) << 8 | UInt16(bytes[43])

        let udpLength = Int(UInt16(bytes[44]) << 8 | UInt16(bytes[45]))
        guard udpLength >= 8 else { return nil }

        let start = 48
        let end = min(bytes.count, 40 + udpLength)
        guard end > start else { return nil }
        payload = Data(bytes[start..<end])
    }

    // MARK: - Build reply

    /// Swaps source/destination so the packet flows back to the querying app.
    func makeReply(payload responsePayload: Data) -> Data {
        switch version {
        case .v4: return makeV4Reply(responsePayload)
        case .v6: return makeV6Reply(responsePayload)
        }
    }

    private func makeV4Reply(_ responsePayload: Data) -> Data {
        let udpLength = 8 + responsePayload.count
        let totalLength = 20 + udpLength

        var packet = [UInt8]()
        packet.reserveCapacity(totalLength)

        packet.append(0x45)                                   // v4, IHL=5
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00])               // identification
        packet.append(contentsOf: [0x40, 0x00])               // don't fragment
        packet.append(64)                                     // TTL
        packet.append(17)                                     // UDP
        packet.append(contentsOf: [0x00, 0x00])               // checksum placeholder
        packet.append(contentsOf: destinationAddress)         // src = original dst
        packet.append(contentsOf: sourceAddress)              // dst = original src

        let ipChecksum = Self.onesComplementSum(Array(packet[0..<20]))
        packet[10] = UInt8((ipChecksum >> 8) & 0xFF)
        packet[11] = UInt8(ipChecksum & 0xFF)

        packet.append(contentsOf: udpHeader(length: udpLength))
        packet.append(contentsOf: [UInt8](responsePayload))

        // UDP checksum is optional over IPv4; zero means "not computed".
        return Data(packet)
    }

    private func makeV6Reply(_ responsePayload: Data) -> Data {
        let udpLength = 8 + responsePayload.count

        var packet = [UInt8]()
        packet.reserveCapacity(40 + udpLength)

        packet.append(0x60)                                   // v6
        packet.append(contentsOf: [0x00, 0x00, 0x00])         // traffic class / flow label
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(17)                                     // next header = UDP
        packet.append(64)                                     // hop limit
        packet.append(contentsOf: destinationAddress)
        packet.append(contentsOf: sourceAddress)

        var udp = udpHeader(length: udpLength)
        udp.append(contentsOf: [UInt8](responsePayload))

        // UDP checksum is MANDATORY over IPv6.
        let checksum = Self.udpChecksumV6(source: destinationAddress,
                                          destination: sourceAddress,
                                          udp: udp)
        udp[6] = UInt8((checksum >> 8) & 0xFF)
        udp[7] = UInt8(checksum & 0xFF)

        packet.append(contentsOf: udp)
        return Data(packet)
    }

    private func udpHeader(length: Int) -> [UInt8] {
        [
            UInt8((destinationPort >> 8) & 0xFF), UInt8(destinationPort & 0xFF),
            UInt8((sourcePort >> 8) & 0xFF),      UInt8(sourcePort & 0xFF),
            UInt8((length >> 8) & 0xFF),          UInt8(length & 0xFF),
            0x00, 0x00
        ]
    }

    // MARK: - Checksums

    private static func onesComplementSum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }

    private static func udpChecksumV6(source: [UInt8],
                                      destination: [UInt8],
                                      udp: [UInt8]) -> UInt16 {
        var pseudo = [UInt8]()
        pseudo.append(contentsOf: source)
        pseudo.append(contentsOf: destination)
        let length = UInt32(udp.count)
        pseudo.append(UInt8((length >> 24) & 0xFF))
        pseudo.append(UInt8((length >> 16) & 0xFF))
        pseudo.append(UInt8((length >> 8) & 0xFF))
        pseudo.append(UInt8(length & 0xFF))
        pseudo.append(contentsOf: [0, 0, 0, 17])
        pseudo.append(contentsOf: udp)

        let result = onesComplementSum(pseudo)
        // A computed zero must be transmitted as 0xFFFF over IPv6.
        return result == 0 ? 0xFFFF : result
    }
}
