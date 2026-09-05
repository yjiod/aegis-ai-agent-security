#!/bin/sh
set -eu
BASE_URL="https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads"
INSTALL_DIR="/Library/Application Support/SentinelAgent"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
if ! command -v python3 >/dev/null 2>&1; then echo "python3 is required" >&2; exit 1; fi
mkdir -p "$INSTALL_DIR/reports" "$INSTALL_DIR/previous"
chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/reports" "$INSTALL_DIR/previous"
STAGE_DIR="$INSTALL_DIR/.stage.$$"
mkdir -m 700 "$STAGE_DIR"
trap 'find "$STAGE_DIR" -type f -delete 2>/dev/null || true; rmdir "$STAGE_DIR" 2>/dev/null || true' EXIT HUP INT TERM
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do curl --fail --silent --show-error "$BASE_URL/$name" -o "$STAGE_DIR/$name"; done
echo "c7f03459b7dc42eb94600c60cd107653c1fde30ee4a6dd3ee2e00b202938cf63  $STAGE_DIR/sentinel_agent.py" | shasum -a 256 -c -
echo "431a156f48208bcbc2c44dd92f8b2383be6a04df9294631f6386a9a6d48ac64d  $STAGE_DIR/sentinel-policy.json" | shasum -a 256 -c -
echo "0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c  $STAGE_DIR/sentinel-security-baseline.md" | shasum -a 256 -c -
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do if [ -f "$INSTALL_DIR/$name" ]; then cp -p "$INSTALL_DIR/$name" "$INSTALL_DIR/previous/$name"; fi; done
if [ -f "$INSTALL_DIR/previous/sentinel_agent.py" ] && [ -f "$INSTALL_DIR/previous/sentinel-policy.json" ] && [ -f "$INSTALL_DIR/previous/sentinel-security-baseline.md" ]; then (cd "$INSTALL_DIR/previous" && shasum -a 256 sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md > CHECKSUMS.sha256); fi
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do mv -f "$STAGE_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
chmod 600 "$INSTALL_DIR/sentinel-policy.json" "$INSTALL_DIR/sentinel-security-baseline.md"
/bin/cat > "$PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.company.sentinel-agent</string><key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/Library/Application Support/SentinelAgent/sentinel_agent.py</string><string>/Users</string><string>--auto-enroll</string><string>--output</string><string>/Library/Application Support/SentinelAgent/reports/latest.json</string></array><key>StartInterval</key><integer>14400</integer><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>/var/log/sentinel-agent.log</string><key>StandardErrorPath</key><string>/var/log/sentinel-agent.err</string></dict></plist>
PLIST
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
echo "Sentinel Agent installed for Intune macOS deployment."
