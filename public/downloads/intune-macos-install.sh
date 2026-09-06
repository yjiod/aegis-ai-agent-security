#!/bin/sh
set -eu
BASE_URL="https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads"
INSTALL_DIR="/Library/Application Support/SentinelAgent"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then echo "python3 is required" >&2; exit 1; fi
mkdir -p "$INSTALL_DIR/reports" "$INSTALL_DIR/previous"
chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/reports" "$INSTALL_DIR/previous"
STAGE_DIR="$INSTALL_DIR/.stage.$$"
mkdir -m 700 "$STAGE_DIR"
trap 'find "$STAGE_DIR" -type f -delete 2>/dev/null || true; rmdir "$STAGE_DIR" 2>/dev/null || true' EXIT HUP INT TERM
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do curl --fail --silent --show-error --connect-timeout 15 --max-time 120 "$BASE_URL/$name" -o "$STAGE_DIR/$name"; done
echo "071eb7881c0dab474eb92e74ffd090dc6f49032e466991b78cbeeddcf8fea13b  $STAGE_DIR/sentinel_agent.py" | shasum -a 256 -c -
echo "0f87d2ecdc801505d825c647ef8eced290bc9ba9e0bd17b4abe9b6a7a4d14423  $STAGE_DIR/sentinel-policy.json" | shasum -a 256 -c -
echo "e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e  $STAGE_DIR/sentinel-security-baseline.md" | shasum -a 256 -c -
CURRENT_COMPLETE=1
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do if [ ! -f "$INSTALL_DIR/$name" ]; then CURRENT_COMPLETE=0; fi; done
if [ "$CURRENT_COMPLETE" -eq 1 ]; then
  PREVIOUS_STAGE="$INSTALL_DIR/.previous-stage.$$"; PREVIOUS_OLD="$INSTALL_DIR/.previous-old.$$"
  mkdir -m 700 "$PREVIOUS_STAGE"
  for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do cp -p "$INSTALL_DIR/$name" "$PREVIOUS_STAGE/$name"; done
  (cd "$PREVIOUS_STAGE" && shasum -a 256 sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md > CHECKSUMS.sha256)
  mv "$INSTALL_DIR/previous" "$PREVIOUS_OLD"
  if ! mv "$PREVIOUS_STAGE" "$INSTALL_DIR/previous"; then mv "$PREVIOUS_OLD" "$INSTALL_DIR/previous"; exit 1; fi
  find "$PREVIOUS_OLD" -type f -delete 2>/dev/null || true; rmdir "$PREVIOUS_OLD" 2>/dev/null || true
fi
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do mv -f "$STAGE_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
chmod 600 "$INSTALL_DIR/sentinel-policy.json" "$INSTALL_DIR/sentinel-security-baseline.md"
/bin/cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.company.sentinel-agent</string><key>ProgramArguments</key><array><string>$PYTHON_BIN</string><string>/Library/Application Support/SentinelAgent/sentinel_agent.py</string><string>/Users</string><string>--auto-enroll</string><string>--output</string><string>/Library/Application Support/SentinelAgent/reports/latest.json</string></array><key>StartInterval</key><integer>14400</integer><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>/var/log/sentinel-agent.log</string><key>StandardErrorPath</key><string>/var/log/sentinel-agent.err</string></dict></plist>
PLIST
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
echo "Sentinel Agent installed for Intune macOS deployment."
