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
echo "ee20f7f019c70e527a73f1982e05215665782f914fdb94f914c2775739c0e3eb  $INSTALL_DIR/sentinel_agent.py" | shasum -a 256 -c -
echo "1d0061ce2cb8cdc420f9304f739f088b166b2e9f07f1169ec3515bfa1560cfe1  $INSTALL_DIR/sentinel-policy.json" | shasum -a 256 -c -
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
/bin/cat > "$PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.company.sentinel-agent</string><key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/Library/Application Support/SentinelAgent/sentinel_agent.py</string><string>/Users</string><string>--auto-enroll</string><string>--output</string><string>/Library/Application Support/SentinelAgent/reports/latest.json</string></array><key>StartInterval</key><integer>14400</integer><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>/var/log/sentinel-agent.log</string><key>StandardErrorPath</key><string>/var/log/sentinel-agent.err</string></dict></plist>
PLIST
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
echo "Sentinel Agent installed for Intune macOS deployment."
