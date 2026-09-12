#!/bin/sh
set -eu
BASE_URL="${AEGIS_BASE_URL:-https://aegis-agent-security.yjiod2022.chatgpt.site/downloads}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/.aegis-agent}"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/previous"
chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/previous"
STAGE_DIR="$INSTALL_DIR/.stage.$$"
mkdir -m 700 "$STAGE_DIR"
trap 'find "$STAGE_DIR" -type f -delete 2>/dev/null || true; rmdir "$STAGE_DIR" 2>/dev/null || true' EXIT HUP INT TERM
for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do curl --fail --silent --show-error --connect-timeout 15 --max-time 120 "$BASE_URL/$name" -o "$STAGE_DIR/$name"; done
verify_sha256() { if command -v shasum >/dev/null 2>&1; then echo "$1  $2" | shasum -a 256 -c -; else echo "$1  $2" | sha256sum -c -; fi; }
verify_sha256 "48528f1820bab5fd14fbaa63ee44f356ddbf83df322024b8112115c8516f9c1c" "$STAGE_DIR/aegis_agent.py"
verify_sha256 "9b5dd46b4fdcfeb3472ea008b61e202fd0077f5fa76759bfd10cd7aac36942ff" "$STAGE_DIR/aegis-policy.json"
verify_sha256 "5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806" "$STAGE_DIR/aegis-security-baseline.md"
CURRENT_COMPLETE=1
for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do if [ ! -f "$INSTALL_DIR/$name" ]; then CURRENT_COMPLETE=0; fi; done
if [ "$CURRENT_COMPLETE" -eq 1 ]; then
  PREVIOUS_STAGE="$INSTALL_DIR/.previous-stage.$$"; PREVIOUS_OLD="$INSTALL_DIR/.previous-old.$$"
  mkdir -m 700 "$PREVIOUS_STAGE"
  for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do cp -p "$INSTALL_DIR/$name" "$PREVIOUS_STAGE/$name"; done
  (cd "$PREVIOUS_STAGE" && if command -v shasum >/dev/null 2>&1; then shasum -a 256 aegis_agent.py aegis-policy.json aegis-security-baseline.md > CHECKSUMS.sha256; else sha256sum aegis_agent.py aegis-policy.json aegis-security-baseline.md > CHECKSUMS.sha256; fi)
  mv "$INSTALL_DIR/previous" "$PREVIOUS_OLD"
  if ! mv "$PREVIOUS_STAGE" "$INSTALL_DIR/previous"; then mv "$PREVIOUS_OLD" "$INSTALL_DIR/previous"; exit 1; fi
  find "$PREVIOUS_OLD" -type f -delete 2>/dev/null || true; rmdir "$PREVIOUS_OLD" 2>/dev/null || true
fi
for name in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do mv -f "$STAGE_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/aegis_agent.py"
chmod 600 "$INSTALL_DIR/aegis-policy.json" "$INSTALL_DIR/aegis-security-baseline.md"
printf '%s\n' "Aegis 已安装到 $INSTALL_DIR"
printf '%s\n' "首次只读扫描：python3 $INSTALL_DIR/aegis_agent.py <项目目录> --output aegis-report.json"
printf '%s\n' "自动启动需由企业 MDM/EDR 下发；此脚本不会自行注册系统服务。"
