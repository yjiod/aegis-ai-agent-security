#!/bin/sh
set -eu
PLIST=/Library/LaunchDaemons/com.yjiod.aegis-agent.plist
chown -R root:wheel "/Library/Application Support/AegisAgent" "$PLIST"
chmod 700 "/Library/Application Support/AegisAgent/run-aegis.sh" "/Library/Application Support/AegisAgent/aegis_agent.py"
chmod 600 "/Library/Application Support/AegisAgent/reporting.json" "/Library/Application Support/AegisAgent/aegis-policy.json" "/Library/Application Support/AegisAgent/aegis-security-baseline.md"
chmod 644 "$PLIST"
launchctl bootout system/com.yjiod.aegis-agent >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
launchctl kickstart -k system/com.yjiod.aegis-agent
exit 0
