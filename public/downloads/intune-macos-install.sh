#!/bin/sh
set -eu
BASE_URL="https://aegis-agent-security.yjiod2022.chatgpt.site/downloads"
INSTALL_DIR="/Library/Application Support/AegisAgent"
PLIST="/Library/LaunchDaemons/com.company.aegis-agent.plist"
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then echo "python3 is required" >&2; exit 1; fi
mkdir -p "$INSTALL_DIR/reports" "$INSTALL_DIR/previous"
chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/reports" "$INSTALL_DIR/previous"
STAGE_DIR="$INSTALL_DIR/.stage.$$"
mkdir -m 700 "$STAGE_DIR"
trap 'find "$STAGE_DIR" -type f -delete 2>/dev/null || true; rmdir "$STAGE_DIR" 2>/dev/null || true' EXIT HUP INT TERM
for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do curl --fail --silent --show-error --connect-timeout 15 --max-time 120 "$BASE_URL/$name" -o "$STAGE_DIR/$name"; done
echo "8fa59eb0366e9368ddb6c65f6b4c3095521d70fcc32c6e6b0f38ac322aa848e2  $STAGE_DIR/aegis_agent.py" | shasum -a 256 -c -
echo "2c3058c3f768a22ca4621bb4eedc69c943202e98f02bb7c79888ef724e262535  $STAGE_DIR/aegis-policy.json" | shasum -a 256 -c -
echo "5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806  $STAGE_DIR/aegis-security-baseline.md" | shasum -a 256 -c -
CURRENT_COMPLETE=1
for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do if [ ! -f "$INSTALL_DIR/$name" ]; then CURRENT_COMPLETE=0; fi; done
if [ "$CURRENT_COMPLETE" -eq 1 ]; then
  PREVIOUS_STAGE="$INSTALL_DIR/.previous-stage.$$"; PREVIOUS_OLD="$INSTALL_DIR/.previous-old.$$"
  mkdir -m 700 "$PREVIOUS_STAGE"
  for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do cp -p "$INSTALL_DIR/$name" "$PREVIOUS_STAGE/$name"; done
  (cd "$PREVIOUS_STAGE" && shasum -a 256 aegis_agent.py aegis-policy.json aegis-security-baseline.md > CHECKSUMS.sha256)
  mv "$INSTALL_DIR/previous" "$PREVIOUS_OLD"
  if ! mv "$PREVIOUS_STAGE" "$INSTALL_DIR/previous"; then mv "$PREVIOUS_OLD" "$INSTALL_DIR/previous"; exit 1; fi
  find "$PREVIOUS_OLD" -type f -delete 2>/dev/null || true; rmdir "$PREVIOUS_OLD" 2>/dev/null || true
fi
for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do mv -f "$STAGE_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/aegis_agent.py"
chmod 600 "$INSTALL_DIR/aegis-policy.json" "$INSTALL_DIR/aegis-security-baseline.md"
/bin/cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.company.aegis-agent</string><key>ProgramArguments</key><array><string>$PYTHON_BIN</string><string>/Library/Application Support/AegisAgent/aegis_agent.py</string><string>/Users</string><string>--auto-enroll</string><string>--output</string><string>/Library/Application Support/AegisAgent/reports/latest.json</string></array><key>StartInterval</key><integer>14400</integer><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>/var/log/aegis-agent.log</string><key>StandardErrorPath</key><string>/var/log/aegis-agent.err</string></dict></plist>
PLIST
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
echo "Aegis Agent installed for Intune macOS deployment."
