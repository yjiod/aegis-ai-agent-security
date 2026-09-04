#!/bin/sh
set -eu
BASE_URL="https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads"
INSTALL_DIR="/Library/Application Support/SentinelAgent"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
if ! command -v python3 >/dev/null 2>&1; then echo "python3 is required" >&2; exit 1; fi
mkdir -p "$INSTALL_DIR/reports"
curl --fail --silent --show-error "$BASE_URL/sentinel_agent.py" -o "$INSTALL_DIR/sentinel_agent.py"
curl --fail --silent --show-error "$BASE_URL/sentinel-policy.json" -o "$INSTALL_DIR/sentinel-policy.json"
curl --fail --silent --show-error "$BASE_URL/sentinel-security-baseline.md" -o "$INSTALL_DIR/sentinel-security-baseline.md"
echo "111c58a4066e783bf5dbe6227aa23b4fd94a77b9bdd61ad7f111685e8770e3c1  $INSTALL_DIR/sentinel_agent.py" | shasum -a 256 -c -
echo "230357ac50b6ac41c967667a3cb29765e2c58ad58ed17088aa867940e40e5203  $INSTALL_DIR/sentinel-policy.json" | shasum -a 256 -c -
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
/bin/cat > "$PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.company.sentinel-agent</string><key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/Library/Application Support/SentinelAgent/sentinel_agent.py</string><string>/Users/Shared</string><string>--output</string><string>/Library/Application Support/SentinelAgent/reports/latest.json</string></array><key>StartInterval</key><integer>14400</integer><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>/var/log/sentinel-agent.log</string><key>StandardErrorPath</key><string>/var/log/sentinel-agent.err</string></dict></plist>
PLIST
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
echo "Sentinel Agent installed for Intune macOS deployment."
