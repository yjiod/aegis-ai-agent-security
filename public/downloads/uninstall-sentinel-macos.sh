#!/bin/sh
set -eu
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
rm -f "$PLIST"
rm -rf "/Library/Application Support/SentinelAgent"
echo "Sentinel runtime removed. Repository rule files remain under source control."
