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
verify_sha256 "21766c8da570da4e0ca64660d3f16c171d8b0f62ac9782ac58bbcd2233ab7406" "$STAGE_DIR/sentinel_agent.py"
verify_sha256 "8445ffbaf792cd4c92702d4359e1a853b9c35fb80c8862c81a7c46f184469cb1" "$STAGE_DIR/sentinel-policy.json"
verify_sha256 "0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c" "$STAGE_DIR/sentinel-security-baseline.md"
for name in sentinel_agent.py sentinel-policy.json sentinel-security-baseline.md; do if [ -f "$INSTALL_DIR/$name" ]; then cp -p "$INSTALL_DIR/$name" "$INSTALL_DIR/previous/$name"; fi; mv -f "$STAGE_DIR/$name" "$INSTALL_DIR/$name"; done
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
chmod 600 "$INSTALL_DIR/sentinel-policy.json" "$INSTALL_DIR/sentinel-security-baseline.md"
printf '%s\n' "Sentinel 已安装到 $INSTALL_DIR"
printf '%s\n' "首次只读扫描：python3 $INSTALL_DIR/sentinel_agent.py <项目目录> --output sentinel-report.json"
printf '%s\n' "自动启动需由企业 MDM/EDR 下发；此脚本不会自行注册系统服务。"
