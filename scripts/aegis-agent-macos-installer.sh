#!/bin/sh
# ═══════════════════════════════════════════════════════════
# Aegis Agent for macOS v0.30.0 — 自包含安装器
#
# 用法:
#   sudo sh aegis-agent-macos.run [选项]
#
# 选项:
#   --collector URL    Collector 地址 (默认: http://10.100.1.98:8931)
#   --token TOKEN      Bearer 认证令牌
#   --device-id ID     设备标识 (默认: MAC-<hostname>)
#   --interval SEC     扫描间隔秒数 (默认: 3600)
#   --uninstall        卸载 Agent
#   --help             显示帮助
#
# 部署方式: MDM Shell Script / 手动 sudo / MDM 推送
# ═══════════════════════════════════════════════════════════
set -eu

VERSION="0.30.0"
INSTALL_DIR="/Library/Application Support/AegisAgent"
PLIST_PATH="/Library/LaunchDaemons/com.aegis.agent.plist"
COLLECTOR_URL="${AEGIS_COLLECTOR_URL:-http://10.100.1.98:8931}"
COLLECTOR_TOKEN="${AEGIS_COLLECTOR_TOKEN:-a53819be19f0bfffc15c0d38735e8f7322db7841e22488b33b10ee56b0fbea10}"
DEVICE_ID="${AEGIS_DEVICE_ID:-}"
SCAN_INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"
DO_UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --collector) COLLECTOR_URL="$2"; shift 2 ;;
    --token) COLLECTOR_TOKEN="$2"; shift 2 ;;
    --device-id) DEVICE_ID="$2"; shift 2 ;;
    --interval) SCAN_INTERVAL="$2"; shift 2 ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    --help|-h)
      echo "用法: sudo sh aegis-agent-macos.run [--collector URL] [--token TOKEN] [--device-id ID] [--interval SEC] [--uninstall]"
      exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

if [ -z "$DEVICE_ID" ]; then
  DEVICE_ID="MAC-$(hostname | cut -c1-12 | tr '[:lower:]' '[:upper:]' | tr ' ' '-')"
fi

# ─── Uninstall ─────────────────────────────────────────────
if [ "$DO_UNINSTALL" = "1" ]; then
  echo "═══ 卸载 Aegis Agent ═══"
  launchctl bootout system /Library/LaunchDaemons/com.aegis.agent.plist 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.aegis.agent.plist
  rm -rf "/Library/Application Support/AegisAgent"
  echo "✓ 已卸载。用户基线标记保留在各 Agent 指令文件中。"
  echo "  手动清理: 删除 <!-- aegis-managed-user-baseline:start/end --> 块"
  exit 0
fi

# ─── Preflight ─────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "错误: 需要 root 权限。请使用: sudo sh $0"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "错误: 需要 python3。请先安装 Xcode Command Line Tools。"
  exit 1
fi

echo "═══ Aegis Agent for macOS v${VERSION} ═══"
echo "  Collector:  ${COLLECTOR_URL}"
echo "  Device ID:  ${DEVICE_ID}"
echo "  扫描间隔:   ${SCAN_INTERVAL}s"
echo "  安装目录:   ${INSTALL_DIR}"
echo ""

# ─── Install files ─────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

# Extract embedded payload (tar.gz after __PAYLOAD__ marker)
PAYLOAD_LINE=$(awk '/^__PAYLOAD__$/{print NR + 1; exit 0; }' "$0")
tail -n+"$PAYLOAD_LINE" "$0" | tar xzf - -C "$INSTALL_DIR"

if [ ! -f "$INSTALL_DIR/aegis_agent.py" ]; then
  echo "错误: 解压失败"
  exit 1
fi
chmod 755 "$INSTALL_DIR/aegis_agent.py"
echo "  ✓ 核心文件已解压"

# ─── Config ────────────────────────────────────────────────
cat > "$INSTALL_DIR/config.json" << CFGEOF
{
  "collectorURL": "${COLLECTOR_URL}",
  "reportURL": "${COLLECTOR_URL}/v1/reports",
  "deviceId": "${DEVICE_ID}",
  "token": "${COLLECTOR_TOKEN}",
  "hmacSecret": "",
  "scanIntervalSeconds": ${SCAN_INTERVAL},
  "scanRoot": null
}
CFGEOF
chmod 600 "$INSTALL_DIR/config.json"

cat > "$INSTALL_DIR/reporting.json" << RPTEOF
{"schema":"aegis.reporting/v1","report_url":"${COLLECTOR_URL}/v1/reports","report_token":"${COLLECTOR_TOKEN}","signing_secret":""}
RPTEOF
chmod 600 "$INSTALL_DIR/reporting.json"
echo "  ✓ 配置已写入"

# ─── LaunchDaemon ──────────────────────────────────────────
cat > /Library/LaunchDaemons/com.aegis.agent.plist << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Library/Application Support/AegisAgent/aegis_agent.py</string>
        <string>/Users</string>
        <string>--policy</string>
        <string>/Library/Application Support/AegisAgent/aegis-policy.json</string>
        <string>--output</string>
        <string>/Library/Application Support/AegisAgent/last-report.json</string>
        <string>--auto-enroll</string>
        <string>--report-config</string>
        <string>/Library/Application Support/AegisAgent/reporting.json</string>
        <string>--watch</string>
        <string>--interval</string>
        <string>${SCAN_INTERVAL}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Application Support/AegisAgent/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Application Support/AegisAgent/agent-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AEGIS_REPORT_TOKEN</key>
        <string>${COLLECTOR_TOKEN}</string>
    </dict>
</dict>
</plist>
PLISTEOF

launchctl bootout system /Library/LaunchDaemons/com.aegis.agent.plist 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.aegis.agent.plist 2>/dev/null || launchctl load /Library/LaunchDaemons/com.aegis.agent.plist 2>/dev/null || true
echo "  ✓ LaunchDaemon 已加载"

# ─── Initial scan ──────────────────────────────────────────
echo "  执行首次扫描与基线注入..."
AEGIS_REPORT_TOKEN="$COLLECTOR_TOKEN" /usr/bin/python3 "$INSTALL_DIR/aegis_agent.py" /Users \
  --policy "$INSTALL_DIR/aegis-policy.json" \
  --output "$INSTALL_DIR/last-report.json" \
  --auto-enroll \
  --report-url "${COLLECTOR_URL}/v1/reports" >/dev/null 2>&1 || true
echo "  ✓ 首次扫描完成"

echo ""
echo "═══ 安装完成 ═══"
echo ""
echo "验证:"
echo "  grep -l 'aegis-managed-user-baseline' ~/.codex/AGENTS.md ~/.workbuddy/AGENTS.md ~/.qwenworkcn/AGENTS.md 2>/dev/null"
echo "  python3 -m json.tool '/Library/Application Support/AegisAgent/last-report.json' | grep agent_baseline"
echo ""
echo "卸载: sudo sh $0 --uninstall"
exit 0

__PAYLOAD__
