#!/bin/sh
set -eu
BASE_URL="${SENTINEL_BASE_URL:-https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads}"
INSTALL_DIR="${SENTINEL_INSTALL_DIR:-$HOME/.sentinel-agent}"
mkdir -p "$INSTALL_DIR"
curl --fail --silent --show-error "$BASE_URL/sentinel_agent.py" -o "$INSTALL_DIR/sentinel_agent.py"
curl --fail --silent --show-error "$BASE_URL/sentinel-policy.json" -o "$INSTALL_DIR/sentinel-policy.json"
chmod 700 "$INSTALL_DIR/sentinel_agent.py"
printf '%s\n' "Sentinel 已安装到 $INSTALL_DIR"
printf '%s\n' "首次只读扫描：python3 $INSTALL_DIR/sentinel_agent.py <项目目录> --output sentinel-report.json"
printf '%s\n' "自动启动需由企业 MDM/EDR 下发；此脚本不会自行注册系统服务。"
