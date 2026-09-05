#!/bin/sh
set -eu
BASE_URL="${SENTINEL_BASE_URL:-https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads}"
INSTALL_DIR="${SENTINEL_INSTALL_DIR:-$HOME/.sentinel-agent}"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/previous"
chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/previous"
STAGE_DIR="$INSTALL_DIR/.stage.$$"
mkdir -m 700 "$STAGE_DIR"
trap 'find "$STAGE_DIR" -type f -delete 2>/dev/null || true; rmdir "$STAGE_DIR" 2>/dev/null || true' EXIT HUP INT TERM
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do curl --fail --silent --show-error "$BASE_URL/$name" -o "$STAGE_DIR/$name"; done
verify_sha256() { if command -v shasum >/dev/null 2>&1; then echo "$1  $2" | shasum -a 256 -c -; else echo "$1  $2" | sha256sum -c -; fi; }
verify_sha256 "0ef3774a08ce830e8a317c6ee5cf19dff031752092493d6800b3f4bc6ce5f571" "$STAGE_DIR/sentinel_agent.py"
verify_sha256 "f093a50aab82c99ac282d8608df505cf8ac9d22e257fb20d38f6c0e9f47eedab" "$STAGE_DIR/sentinel-policy.json"
verify_sha256 "e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e" "$STAGE_DIR/sentinel-security-baseline.md"
CURRENT_COMPLETE=1
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do if [ ! -f "$INSTALL_DIR/$name" ]; then CURRENT_COMPLETE=0; fi; done
if [ "$CURRENT_COMPLETE" -eq 1 ]; then
  PREVIOUS_STAGE="$INSTALL_DIR/.previous-stage.$$"; PREVIOUS_OLD="$INSTALL_DIR/.previous-old.$$"
  mkdir -m 700 "$PREVIOUS_STAGE"
  for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do cp -p "$INSTALL_DIR/$name" "$PREVIOUS_STAGE/$name"; done
  (cd "$PREVIOUS_STAGE" && if command -v shasum >/dev/null 2>&1; then shasum -a 256 sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md > CHECKSUMS.sha256; else sha256sum sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md > CHECKSUMS.sha256; fi)
  mv "$INSTALL_DIR/previous" "$PREVIOUS_OLD"
  if ! mv "$PREVIOUS_STAGE" "$INSTALL_DIR/previous"; then mv "$PREVIOUS_OLD" "$INSTALL_DIR/previous"; exit 1; fi
  find "$PREVIOUS_OLD" -type f -delete 2>/dev/null || true; rmdir "$PREVIOUS_OLD" 2>/dev/null || true
fi
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do mv -f "$STAGE_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
chmod 600 "$INSTALL_DIR/sentinel-policy.json" "$INSTALL_DIR/sentinel-security-baseline.md"
printf '%s\n' "Sentinel 已安装到 $INSTALL_DIR"
printf '%s\n' "首次只读扫描：python3 $INSTALL_DIR/sentinel_agent.py <项目目录> --output sentinel-report.json"
printf '%s\n' "自动启动需由企业 MDM/EDR 下发；此脚本不会自行注册系统服务。"
