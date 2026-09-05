#!/bin/sh
set -eu
INSTALL_DIR="/Library/Application Support/SentinelAgent"
PREVIOUS_DIR="$INSTALL_DIR/previous"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do
  if [ ! -f "$PREVIOUS_DIR/$name" ]; then echo "Previous version is incomplete: $name" >&2; exit 1; fi
done
if [ ! -f "$PREVIOUS_DIR/CHECKSUMS.sha256" ]; then echo "Previous version checksum manifest is missing" >&2; exit 1; fi
MANIFEST_NAMES="$(awk 'NF==2 {print $2}' "$PREVIOUS_DIR/CHECKSUMS.sha256" | LC_ALL=C sort | tr '\n' ' ')"
if [ "$MANIFEST_NAMES" != "sentinel-policy.json sentinel-security-baseline.md sentinel_agent.py " ] || [ "$(awk 'NF {count++} END {print count+0}' "$PREVIOUS_DIR/CHECKSUMS.sha256")" -ne 3 ] || [ "$(awk 'NF==2 {count++} END {print count+0}' "$PREVIOUS_DIR/CHECKSUMS.sha256")" -ne 3 ]; then echo "Previous version checksum manifest has an unexpected file set" >&2; exit 1; fi
(cd "$PREVIOUS_DIR" && shasum -a 256 -c CHECKSUMS.sha256)
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do cp -p "$PREVIOUS_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
chmod 600 "$INSTALL_DIR/sentinel-policy.json" "$INSTALL_DIR/sentinel-security-baseline.md"
(cd "$INSTALL_DIR" && shasum -a 256 -c "$PREVIOUS_DIR/CHECKSUMS.sha256")
launchctl bootstrap system "$PLIST"
echo "Sentinel Agent restored to the previous verified installation."
