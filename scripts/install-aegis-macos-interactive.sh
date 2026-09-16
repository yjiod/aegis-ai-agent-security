#!/bin/sh
# install-aegis-macos-interactive.sh — 交互式安装：提示输入控制台地址，写入预留覆盖文件后安装 pkg。
# 用法: sudo sh install-aegis-macos-interactive.sh [pkg路径]
# 安装后仍可随时编辑 <Agent目录>/server-override.json 切换控制台（全自动，无需重装）。
set -eu
PKG="${1:-$(dirname "$0")/../public/downloads/aegis-agent-macos.pkg}"
[ -f "$PKG" ] || { echo "未找到 pkg: $PKG" >&2; exit 1; }
printf '请输入控制台地址（https://<主机>）: '
read -r SERVER
SERVER=$(printf '%s' "$SERVER" | sed 's#/*$##')
case "$SERVER" in
  https://*) : ;;
  "") echo "已取消。"; exit 0 ;;
  *) echo "控制台地址必须是 https:// 开头。" >&2; exit 1 ;;
esac
mkdir -p /Library/Preferences
printf '{"schema":"aegis.server/v1","server_url":"%s"}\n' "$SERVER" > /Library/Preferences/aegis-server.json
chmod 644 /Library/Preferences/aegis-server.json
echo "已写入 /Library/Preferences/aegis-server.json，开始安装…"
installer -pkg "$PKG" -target /
echo "安装完成。如需改控制台，编辑 <Agent安装目录>/server-override.json 即可全自动切换。"
