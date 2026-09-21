# MyDNS

A self-contained, on-device DNS ad blocker for iPhone. No server, no account,
no subscription. All filtering happens inside a local VPN tunnel on your phone.

## Getting it on your iPhone

**You need a Mac for the easy path.** iOS code signing only runs on macOS.
Three options, in order of how much pain they involve:

### Option A — You have a Mac (best)

```bash
./scripts/setup.sh com.yourname.mydns
open MyDNS.xcodeproj
```

In Xcode: select both targets → **Signing & Capabilities** → check
*Automatically manage signing* → pick your Apple ID team. Plug in your iPhone,
select it as the run destination, press **Run**.

A free Apple ID works. The app expires after **7 days** and you re-run to renew.
A paid account ($99/yr) extends that to a year.

First launch on the device: **Settings → General → VPN & Device Management →**
trust your developer certificate.

### Option B — No Mac, use GitHub Actions (free)

Push this repo to GitHub and run the **Build iOS App** workflow. It compiles on
a macOS runner and uploads an **unsigned** `.ipa` as an artifact.

Then sign and install it from Windows with **Sideloadly** or **AltStore**:
1. Install [Sideloadly](https://sideloadly.io) on Windows.
2. Plug in your iPhone, drag in `MyDNS-unsigned.ipa`.
3. Enter your Apple ID — Sideloadly signs it with a free provisioning profile.
4. Trust the certificate on-device as above.

Same 7-day expiry. AltStore can auto-refresh over Wi-Fi to avoid manual renewal.

> Caveat worth knowing: free Apple IDs are limited to 3 sideloaded apps and
> 10 App IDs per week. Network Extension entitlements sometimes fail to
> provision under a free account — if the VPN won't install, that's why, and a
> paid account fixes it.

### Option C — Rent a Mac

MacinCloud or MacStadium, roughly $20–30/month. Same as Option A afterwards.

## Configuration

`scripts/setup.sh` rewrites every identifier consistently — entitlements,
Info.plists, Swift fallbacks, logger subsystem, and the generated project.
Do not edit bundle IDs by hand; they must match in five places or the tunnel
silently fails to launch.

| Setting | Value |
|---|---|
| App bundle ID | `com.yourname.mydns` |
| Extension bundle ID | `com.yourname.mydns.tunnel` (must be a child of the app's) |
| App Group | `group.com.yourname.mydns` |
| Minimum iOS | 16.0 |

## How it works

```
App queries DNS
      ↓
iOS routes it to 10.7.0.53 — a virtual resolver inside our tunnel
      ↓
PacketTunnelProvider reads the raw IPv4/IPv6 + UDP packet
      ↓
Parse the DNS question name
      ↓
  ┌───┴────┐
BLOCKED  ALLOWED
  │         │
NXDOMAIN  forward over DoH to Cloudflare/Quad9
built     cache the answer
locally   inject reply back into the tunnel
```

The important detail is in `PacketTunnelProvider.makeSettings()`:
`includedRoutes` contains **only** the virtual resolver address, and
`excludedRoutes` contains the default route. Real traffic never enters the
tunnel — we see DNS and nothing else. That's what keeps battery cost negligible
and means no user data passes through app code.

## Project layout

| Path | Target | Purpose |
|---|---|---|
| `Sources/Shared/AppConfig.swift` | both | Identifiers and network constants |
| `Sources/Shared/BlocklistEngine.swift` | both | Reverse-label trie matcher |
| `Sources/Shared/DNSMessage.swift` | both | DNS wire parse + response synthesis |
| `Sources/Shared/BlocklistStore.swift` | both | App Group storage, list download |
| `Sources/Shared/Stats.swift` | both | Counters and IPC command enum |
| `Sources/Tunnel/PacketTunnelProvider.swift` | extension | Tunnel setup, packet loop |
| `Sources/Tunnel/IPPacket.swift` | extension | IPv4/IPv6 + UDP parse and reply |
| `Sources/Tunnel/UpstreamResolver.swift` | extension | DoH/DoT/UDP forwarding, TTL cache |
| `Sources/App/MyDNSApp.swift` | app | Entry point, app model |
| `Sources/App/TunnelController.swift` | app | VPN profile lifecycle, IPC |
| `Sources/App/RootView.swift` | app | Dashboard, activity log, filters, settings |

Everything in `Sources/Shared/` compiles into **both** targets — the validator
enforces this.

## Tests

```bash
python3 scripts/validate_project.py   # project structure, 50 checks
python3 scripts/test_dns_logic.py     # DNS + trie logic, 60 checks
```

`test_dns_logic.py` ports the Swift logic to Python and runs it against real
DNS packets. It covers question parsing, NXDOMAIN and 0.0.0.0 synthesis,
IPv4/UDP round-tripping with checksum verification, and rule-matching edge
cases. Current results: all pass, 200k rules load and lookups run ~6 µs each
in Python (Swift will be far faster).

Two real bugs were caught this way and are already fixed:
- `Data.subdata()` keeps non-zero start indices, so literal offsets like
  `payload[0]` crash. All parsing now goes through `[UInt8]`.
- `||domain^$important` was truncated at `^` before the modifier check ran, so
  modifier rules were silently applied as unconditional blocks. Modifiers are
  now detected first and skipped.

## Known limits

- **Memory**: packet tunnel extensions get roughly 15 MB. ~200k rules is
  comfortable; loading several million-rule lists at once will get you jetsammed.
  Enable HaGeZi Pro *or* OISD Big, not both.
- **Apps with hardcoded DoH** (some browsers) bypass system DNS entirely and
  cannot be filtered this way.
- **No cosmetic filtering.** DNS blocking removes the request, not the page
  element, so you'll see blank gaps. Add a Safari Content Blocker target if that
  bothers you.
- **IPv6 UDP checksums** are computed (mandatory on v6) but have had less
  real-world testing than the v4 path.

## Privacy

No analytics, no telemetry, no network calls except downloading public filter
lists and forwarding allowed DNS queries to your chosen public resolver. Blocked
queries never leave the device. Statistics live in your App Group container and
go nowhere.
