#!/usr/bin/env bash
# One-shot setup: rewrites every identifier to yours, regenerates the project,
# and validates it. Run this before opening Xcode.
#
#   ./scripts/setup.sh com.yourname.mydns [TEAMID]

set -euo pipefail

BUNDLE_ID="${1:-}"
TEAM_ID="${2:-}"

if [ -z "$BUNDLE_ID" ]; then
  echo "Usage: ./scripts/setup.sh com.yourname.mydns [TEAMID]"
  echo
  echo "The bundle ID must be globally unique. Use your own reverse-domain"
  echo "prefix, e.g. com.prakhar.mydns"
  exit 1
fi

cd "$(dirname "$0")/.."

APP_GROUP="group.${BUNDLE_ID}"
TUNNEL_ID="${BUNDLE_ID}.tunnel"

echo "Configuring:"
echo "  App       : ${BUNDLE_ID}"
echo "  Extension : ${TUNNEL_ID}"
echo "  App Group : ${APP_GROUP}"
echo

# Portable in-place sed (works on both macOS and Linux).
sed_i() {
  if sed --version >/dev/null 2>&1; then
    sed -i "$@"
  else
    sed -i '' "$@"
  fi
}

# 1. Entitlements — app group on both targets.
for f in MyDNS/MyDNS.entitlements MyDNSTunnel/MyDNSTunnel.entitlements; do
  sed_i "s|<string>group\.[^<]*</string>|<string>${APP_GROUP}</string>|g" "$f"
done

# 2. Info.plists — the tunnel plist hardcodes the group for extension use.
sed_i "s|<string>group\.[^<]*</string>|<string>${APP_GROUP}</string>|g" \
  MyDNSTunnel/Info.plist

# 3. Swift fallbacks in AppConfig.
sed_i "s|return \"group\.[^\"]*\"|return \"${APP_GROUP}\"|" \
  Sources/Shared/AppConfig.swift
sed_i "s|return \"[a-zA-Z0-9._]*\.tunnel\"|return \"${TUNNEL_ID}\"|" \
  Sources/Shared/AppConfig.swift

# 4. Logger subsystem in the provider.
sed_i "s|subsystem: \"[^\"]*\"|subsystem: \"${TUNNEL_ID}\"|" \
  Sources/Tunnel/PacketTunnelProvider.swift

# 5. Regenerate the project.
python3 scripts/generate_xcodeproj.py \
  --bundle-id "${BUNDLE_ID}" \
  ${TEAM_ID:+--team "${TEAM_ID}"}

echo
python3 scripts/validate_project.py

echo
echo "Done. Next:"
echo "  open MyDNS.xcodeproj"
echo "  Select the MyDNS scheme + your iPhone, then press Run."
