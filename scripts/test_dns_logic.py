#!/usr/bin/env python3
"""
Ports the Swift DNS + trie logic to Python and tests it against real DNS packets
built with dnslib-style manual construction. This catches wire-format and
matching bugs before you ever open Xcode.
"""

import struct
import sys

failures = []


def check(cond, msg):
    print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
    if not cond:
        failures.append(msg)


# ---------------------------------------------------------------- DNS parsing
# Mirrors Sources/Shared/DNSMessage.swift

def encode_name(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_query(name, qtype=1, txid=0x1234, rd=True):
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, 1)


def first_question(data):
    """Returns (name, qtype, qclass, end_offset) or None."""
    if len(data) <= 12:
        return None
    if data[2] & 0x80:            # response, not a query
        return None
    qdcount = struct.unpack(">H", data[4:6])[0]
    if qdcount < 1:
        return None

    offset = 12
    labels = []
    total = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length >= 64:
            return None
        if offset + 1 + length > len(data):
            return None
        total += length + 1
        if total > 255:
            return None
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "strict"))
        offset += 1 + length

    if offset + 4 > len(data) or not labels:
        return None
    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    return (".".join(labels), qtype, qclass, offset + 4)


def blocked_response(query, question, mode="nxdomain"):
    name, qtype, qclass, end = question
    out = bytearray()
    out += query[0:2]
    rd = query[2] & 0x01

    answer_count = 0
    if mode == "nxdomain":
        out.append(0x80 | rd)
        out.append(0x83)
    else:
        out.append(0x80 | rd)
        out.append(0x80)
        answer_count = 1 if qtype in (1, 28) else 0

    out += struct.pack(">HHHH", 1, answer_count, 0, 0)
    out += query[12:end]

    if answer_count == 1:
        out += b"\xC0\x0C"
        out += struct.pack(">HHI", qtype, 1, 60)
        if qtype == 1:
            out += struct.pack(">H", 4) + b"\x00" * 4
        else:
            out += struct.pack(">H", 16) + b"\x00" * 16
    return bytes(out)


# ------------------------------------------------------------------ IP/UDP
# Mirrors Sources/Tunnel/IPPacket.swift

def ip_checksum(data):
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if len(data) % 2:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_v4_udp(src_ip, dst_ip, sport, dport, payload):
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    hdr = bytearray()
    hdr += bytes([0x45, 0x00])
    hdr += struct.pack(">H", total_len)
    hdr += b"\x00\x00" + b"\x40\x00"
    hdr += bytes([64, 17])
    hdr += b"\x00\x00"
    hdr += bytes(int(x) for x in src_ip.split("."))
    hdr += bytes(int(x) for x in dst_ip.split("."))
    cs = ip_checksum(bytes(hdr))
    hdr[10] = cs >> 8
    hdr[11] = cs & 0xFF
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0)
    return bytes(hdr) + udp + payload


def parse_v4_udp(packet):
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8 or packet[9] != 17:
        return None
    frag = ((packet[6] & 0x1F) << 8) | packet[7]
    if frag != 0:
        return None
    src = packet[12:16]
    dst = packet[16:20]
    sport, dport, udp_len, _ = struct.unpack(">HHHH", packet[ihl:ihl + 8])
    if udp_len < 8:
        return None
    start = ihl + 8
    end = min(len(packet), ihl + udp_len)
    return dict(src=src, dst=dst, sport=sport, dport=dport, payload=packet[start:end])


def make_v4_reply(parsed, payload):
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    hdr = bytearray()
    hdr += bytes([0x45, 0x00])
    hdr += struct.pack(">H", total_len)
    hdr += b"\x00\x00" + b"\x40\x00"
    hdr += bytes([64, 17])
    hdr += b"\x00\x00"
    hdr += parsed["dst"]          # swapped
    hdr += parsed["src"]
    cs = ip_checksum(bytes(hdr))
    hdr[10] = cs >> 8
    hdr[11] = cs & 0xFF
    udp = struct.pack(">HHHH", parsed["dport"], parsed["sport"], udp_len, 0)
    return bytes(hdr) + udp + payload


# -------------------------------------------------------------------- Trie
# Mirrors Sources/Shared/BlocklistEngine.swift

class Node:
    __slots__ = ("children", "terminal", "covers")

    def __init__(self):
        self.children = {}
        self.terminal = False
        self.covers = False


class Engine:
    def __init__(self):
        self.block = Node()
        self.allow = Node()
        self.count = 0
        self.skipped = 0

    def load(self, text):
        for line in text.splitlines():
            self._ingest(line)

    def _ingest(self, raw):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            return
        if "#" in line:
            line = line.split("#")[0].strip()
        if not line:
            return

        is_allow = False
        covers = False

        if line.startswith("@@"):
            is_allow = True
            line = line[2:]

        # Modifiers must be detected BEFORE trimming at "^".
        if "$" in line:
            self.skipped += 1
            return

        if line.startswith("||"):
            covers = True
            line = line[2:]
            for ch in ("^", "/"):
                if ch in line:
                    line = line.split(ch)[0]
        elif " " in line or "\t" in line:
            parts = line.split()
            if len(parts) < 2:
                self.skipped += 1
                return
            if parts[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                self.skipped += 1
                return
            line = parts[1]

        if line.startswith("/") or "$" in line or "*" in line or "|" in line:
            self.skipped += 1
            return

        domain = line.lower().strip(".^|/ ")
        if not self._plausible(domain):
            self.skipped += 1
            return

        self._insert(domain, self.allow if is_allow else self.block, covers)
        self.count += 1

    @staticmethod
    def _plausible(d):
        if not (3 <= len(d) <= 253) or "." not in d:
            return False
        if d.startswith(".") or d.endswith("."):
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-._")
        return all(c in allowed for c in d)

    @staticmethod
    def _insert(domain, root, covers):
        node = root
        for label in reversed(domain.split(".")):
            node = node.children.setdefault(label, Node())
        node.terminal = True
        if covers:
            node.covers = True

    def verdict(self, name):
        d = name.lower().strip(".")
        if not d:
            return "allow"
        if self._matches(d, self.allow):
            return "allow"
        return "block" if self._matches(d, self.block) else "allow"

    @staticmethod
    def _matches(domain, root):
        node = root
        labels = list(reversed(domain.split(".")))
        for i, label in enumerate(labels):
            if label not in node.children:
                return False
            node = node.children[label]
            if node.covers:
                return True
            if i == len(labels) - 1 and node.terminal:
                return True
        return False


# ------------------------------------------------------------------- Tests

def test_dns_parsing():
    print("\n=== DNS question parsing ===")

    q = build_query("ads.example.com", 1)
    parsed = first_question(q)
    check(parsed is not None, "parses a basic A query")
    check(parsed[0] == "ads.example.com", f"extracts name (got {parsed[0]})")
    check(parsed[1] == 1, "extracts qtype A")
    check(parsed[3] == len(q), "end offset lands at packet end")

    q6 = build_query("tracker.test.org", 28)
    p6 = first_question(q6)
    check(p6[1] == 28, "extracts qtype AAAA")

    long_label = "a" * 63
    ql = build_query(f"{long_label}.example.com", 1)
    check(first_question(ql) is not None, "accepts max-length label (63)")

    # A response must be rejected — we only proxy queries.
    resp = bytearray(build_query("x.example.com"))
    resp[2] |= 0x80
    check(first_question(bytes(resp)) is None, "rejects DNS responses")

    check(first_question(b"\x00" * 8) is None, "rejects truncated packet")
    check(first_question(b"") is None, "rejects empty packet")

    # qdcount = 0
    bad = struct.pack(">HHHHHH", 1, 0x0100, 0, 0, 0, 0) + encode_name("a.com")
    check(first_question(bad) is None, "rejects qdcount=0")


def test_blocked_responses():
    print("\n=== Blocked response synthesis ===")

    q = build_query("ads.example.com", 1, txid=0xABCD)
    question = first_question(q)

    nx = blocked_response(q, question, "nxdomain")
    check(nx[0:2] == q[0:2], "NXDOMAIN preserves transaction ID")
    check(nx[2] & 0x80 != 0, "NXDOMAIN sets QR=1 (is a response)")
    check(nx[3] & 0x0F == 3, "NXDOMAIN sets RCODE=3")
    check(struct.unpack(">H", nx[4:6])[0] == 1, "NXDOMAIN QDCOUNT=1")
    check(struct.unpack(">H", nx[6:8])[0] == 0, "NXDOMAIN ANCOUNT=0")
    check(nx[12:question[3]] == q[12:question[3]], "NXDOMAIN echoes question verbatim")
    check(first_question(nx) is None, "NXDOMAIN is recognised as a response")

    zero = blocked_response(q, question, "zeroIP")
    check(zero[3] & 0x0F == 0, "zeroIP sets RCODE=0 (NOERROR)")
    check(struct.unpack(">H", zero[6:8])[0] == 1, "zeroIP ANCOUNT=1 for A query")
    check(zero[-4:] == b"\x00\x00\x00\x00", "zeroIP answer payload is 0.0.0.0")
    check(zero[question[3]:question[3] + 2] == b"\xC0\x0C",
          "zeroIP uses compression pointer to offset 12")

    q6 = build_query("ads.example.com", 28)
    z6 = blocked_response(q6, first_question(q6), "zeroIP")
    check(z6[-16:] == b"\x00" * 16, "zeroIP answers :: for AAAA")

    # A non-address query type must not get a fabricated A record.
    qmx = build_query("ads.example.com", 15)
    zmx = blocked_response(qmx, first_question(qmx), "zeroIP")
    check(struct.unpack(">H", zmx[6:8])[0] == 0, "zeroIP gives no answer for MX")

    # RD bit must be echoed back.
    qnord = build_query("x.example.com", 1, rd=False)
    nxnord = blocked_response(qnord, first_question(qnord), "nxdomain")
    check(nxnord[2] & 0x01 == 0, "RD=0 preserved in response")


def test_ip_layer():
    print("\n=== IPv4/UDP round trip ===")

    dns = build_query("ads.example.com", 1)
    packet = build_v4_udp("10.7.0.2", "10.7.0.53", 54321, 53, dns)

    parsed = parse_v4_udp(packet)
    check(parsed is not None, "parses IPv4/UDP packet")
    check(parsed["dport"] == 53, "destination port is 53")
    check(parsed["sport"] == 54321, "source port preserved")
    check(parsed["payload"] == dns, "DNS payload extracted intact")
    check(first_question(parsed["payload"])[0] == "ads.example.com",
          "question readable from extracted payload")

    response = blocked_response(dns, first_question(dns))
    reply = make_v4_reply(parsed, response)

    rp = parse_v4_udp(reply)
    check(rp is not None, "reply packet is parseable")
    check(rp["src"] == parsed["dst"], "reply source = original destination")
    check(rp["dst"] == parsed["src"], "reply destination = original source")
    check(rp["sport"] == 53, "reply source port is 53")
    check(rp["dport"] == 54321, "reply destination port = original source port")
    check(rp["payload"] == response, "reply carries the synthesized response")

    check(ip_checksum(reply[0:20]) == 0,
          "reply IPv4 header checksum validates to zero")

    total_len = struct.unpack(">H", reply[2:4])[0]
    check(total_len == len(reply), f"IP total length matches packet ({total_len})")
    udp_len = struct.unpack(">H", reply[24:26])[0]
    check(udp_len == len(reply) - 20, f"UDP length field correct ({udp_len})")

    # Fragmented packets must be rejected rather than mis-parsed.
    frag = bytearray(packet)
    frag[6] = 0x00
    frag[7] = 0x08
    cs = ip_checksum(bytes(frag[0:20]))
    check(parse_v4_udp(bytes(frag)) is None, "rejects fragmented packets")

    # TCP must be ignored.
    tcp = bytearray(packet)
    tcp[9] = 6
    check(parse_v4_udp(bytes(tcp)) is None, "ignores non-UDP protocols")


def test_matching():
    print("\n=== Blocklist matching ===")

    engine = Engine()
    engine.load("""
! Title: test list
# a comment
||doubleclick.net^
||ads.example.com^
@@||safe.ads.example.com^
0.0.0.0 tracker.evil.com
127.0.0.1 beacon.evil.com
plain-domain.net
/regex.*pattern/
||wildcard*.com^
||modifier.com^$important
192.168.1.1 internal.host
""")

    cases = [
        # (query, expected, reason)
        ("doubleclick.net", "block", "exact match on || rule"),
        ("ad.doubleclick.net", "block", "subdomain of || rule"),
        ("a.b.c.doubleclick.net", "block", "deep subdomain of || rule"),
        ("notdoubleclick.net", "allow", "similar name is not a subdomain"),
        ("doubleclick.net.evil.com", "allow", "suffix trick does not match"),
        ("ads.example.com", "block", "second || rule"),
        ("safe.ads.example.com", "allow", "allowlist beats blocklist"),
        ("deep.safe.ads.example.com", "allow", "allowlist covers subdomains"),
        ("other.ads.example.com", "block", "sibling still blocked"),
        ("example.com", "allow", "parent of blocked domain stays allowed"),
        ("tracker.evil.com", "block", "hosts-style 0.0.0.0 rule"),
        ("sub.tracker.evil.com", "allow", "hosts rule is exact-match only"),
        ("beacon.evil.com", "block", "hosts-style 127.0.0.1 rule"),
        ("evil.com", "allow", "hosts rule does not block parent"),
        ("plain-domain.net", "block", "domains-only rule"),
        ("www.plain-domain.net", "allow", "domains-only is exact-match only"),
        ("internal.host", "allow", "non-null-IP hosts entry is not a block"),
        ("random.org", "allow", "unlisted domain"),
        ("", "allow", "empty query name"),
    ]

    for query, expected, reason in cases:
        got = engine.verdict(query)
        check(got == expected, f"{reason}: {query or '(empty)'} -> {got}")

    print(f"\n  loaded {engine.count} rules, skipped {engine.skipped} unsupported")
    check(engine.skipped >= 3, "unsupported syntax (regex/wildcard/modifier) skipped")
    check(engine.verdict("wildcard123.com") == "allow",
          "wildcard rule was skipped, not mis-applied")
    check(engine.verdict("modifier.com") == "allow",
          "modifier rule was skipped, not mis-applied")


def test_scale():
    print("\n=== Scale ===")
    import random
    import time

    engine = Engine()
    rules = "\n".join(f"||ads{i}.tracker{i % 977}.com^" for i in range(200_000))

    t0 = time.time()
    engine.load(rules)
    load_time = time.time() - t0
    check(engine.count == 200_000, f"loaded 200k rules (got {engine.count})")
    print(f"  load time: {load_time:.2f}s")

    queries = [f"sub.ads{random.randint(0, 199999)}.tracker{random.randint(0,976)}.com"
               for _ in range(20_000)]
    t0 = time.time()
    for q in queries:
        engine.verdict(q)
    lookup_time = time.time() - t0
    per_query_us = (lookup_time / len(queries)) * 1_000_000
    print(f"  {len(queries)} lookups in {lookup_time:.3f}s "
          f"({per_query_us:.1f} us/query in Python)")
    check(per_query_us < 100,
          f"lookup stays sub-100us even in Python ({per_query_us:.1f} us)")


def main():
    test_dns_parsing()
    test_blocked_responses()
    test_ip_layer()
    test_matching()
    test_scale()

    print("\n" + "=" * 56)
    if failures:
        print(f"{len(failures)} TEST(S) FAILED")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL DNS LOGIC TESTS PASSED")
    print("=" * 56)


if __name__ == "__main__":
    main()
