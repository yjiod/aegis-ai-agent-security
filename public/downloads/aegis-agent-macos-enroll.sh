#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# aegis-agent-macos-enroll.sh — 用户级 macOS 终端入网 / 重入网（无需 sudo）。
#
# 与需要 root 的 LaunchDaemon 安装器不同，本脚本把 Agent 装到用户目录并注册
# **用户级 LaunchAgent**（~/Library/LaunchAgents），普通用户即可运行，适合：
#   - 新机器快速接入；
#   - 令牌轮转 / Collector 地址变更后给已掉线终端"重入网"。
#
# 它做四件事：
#   1) 从 BASE_URL 下载 Agent 运行时并用 CHECKSUMS.sha256 校验完整性；
#   2) 写入上报配置 config.json / reporting.json（0600），report_url 指向
#      公网 HTTPS 入口 ${COLLECTOR_URL}/v1/reports（nginx 反代 /aegis/*→Collector）；
#   3) 安装用户级 LaunchAgent，开机自启 + 周期上报；
#   4) 立即跑一次首报，确认能连通 Collector。
#
# 令牌是敏感凭据：只经环境变量 AEGIS_COLLECTOR_TOKEN 传入，绝不写进脚本/日志。
# 管理员从控制台或服务器 /etc/aegis/.collector-token-current(0600) 取得当前令牌。
#
# 用法：
#   AEGIS_COLLECTOR_TOKEN='<令牌>' sh aegis-agent-macos-enroll.sh
#   # 可选覆盖： AEGIS_COLLECTOR_URL(默认 https://aegis.example.com/aegis)
#   #           AEGIS_BASE_URL(默认 https://aegis.example.com/downloads)
#   #           AEGIS_SCAN_INTERVAL(秒,默认3600) AEGIS_DEVICE_ID
#   # 卸载： AEGIS_ENROLL_UNINSTALL=1 sh aegis-agent-macos-enroll.sh
# ═══════════════════════════════════════════════════════════════════════
set -eu

BASE_URL="${AEGIS_BASE_URL:-https://aegis.example.com/downloads}"
COLLECTOR_URL="${AEGIS_COLLECTOR_URL:-https://aegis.example.com/aegis}"
TOKEN="${AEGIS_COLLECTOR_TOKEN:-}"
# Agent 的 load_reporting_config 强制 signing_secret 为 32+ 字符且不同于 token，否则
# 本轮拒绝上报。生产 Collector 处于 pilot 显式允许未签名模式（AEGIS_ALLOW_UNSIGNED_REPORTS=1
# 且未配置 AEGIS_REPORT_SIGNING_SECRETS），它只校验 Bearer 令牌、忽略报告签名，因此这里
# 用 CSPRNG 生成本机独立的 signing_secret 即可满足契约。若日后 Collector 启用强制验签
# （配置 AEGIS_REPORT_SIGNING_SECRETS 且关闭 allow-unsigned），改用 AEGIS_REPORT_SIGNING_SECRET
# 传入与服务端一致密钥即可。
SIGNING_SECRET="${AEGIS_REPORT_SIGNING_SECRET:-$(python3 -c 'import secrets;print(secrets.token_hex(32))')}"
INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"
DEVICE_ID="${AEGIS_DEVICE_ID:-MAC-$(hostname | cut -c1-12 | tr '[:lower:]' '[:upper:]' | tr ' ' '-')}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/Library/Application Support/AegisAgent}"
PLIST="$HOME/Library/LaunchAgents/com.aegis.agent.plist"
PYTHON_BIN="$(command -v python3 || true)"
RUNTIME_FILES="aegis_agent.py aegis-policy.json aegis-security-baseline.md"

# ─── 卸载分支（用户级，无需 sudo）─────────────────────────────────────
if [ "${AEGIS_ENROLL_UNINSTALL:-0}" = "1" ]; then
  launchctl bootout "gui/$(id -u)/com.aegis.agent" 2>/dev/null || true
  [ -f "$PLIST" ] && mv -f "$PLIST" "$HOME/.Trash/" 2>/dev/null || true
  echo "已卸载用户级 LaunchAgent；运行时目录保留在 $INSTALL_DIR（如需清理请手动移入废纸篓）。"
  exit 0
fi

if [ -z "$TOKEN" ]; then
  echo "错误: 需要 AEGIS_COLLECTOR_TOKEN。管理员从控制台或服务器 /etc/aegis/.collector-token-current 获取。" >&2
  exit 1
fi
if [ -z "$PYTHON_BIN" ]; then echo "错误: 需要 python3" >&2; exit 1; fi

echo "═══ Aegis 终端入网（用户级，无需 sudo）═══"
echo "  设备 ID    : $DEVICE_ID"
echo "  Collector  : $COLLECTOR_URL"
echo "  安装目录   : $INSTALL_DIR"

mkdir -p "$INSTALL_DIR" "$HOME/Library/LaunchAgents"
chmod 700 "$INSTALL_DIR"

echo "═══ 1. 下载并校验 Agent 运行时 ═══"
curl --fail --silent --show-error --connect-timeout 15 --max-time 120 "$BASE_URL/CHECKSUMS.sha256" -o "$INSTALL_DIR/CHECKSUMS.sha256"
for name in $RUNTIME_FILES; do
  curl --fail --silent --show-error --connect-timeout 15 --max-time 120 "$BASE_URL/$name" -o "$INSTALL_DIR/$name"
done
# 用发布的 CHECKSUMS 校验三个运行时文件（仅校验本目录内的这三项）。
( cd "$INSTALL_DIR" && grep -E "($(echo "$RUNTIME_FILES" | tr ' ' '|'))\$" CHECKSUMS.sha256 > .verify.sha256 \
  && if command -v shasum >/dev/null 2>&1; then shasum -a 256 -c .verify.sha256; else sha256sum -c .verify.sha256; fi )
chmod 700 "$INSTALL_DIR/aegis_agent.py"
chmod 600 "$INSTALL_DIR/aegis-policy.json" "$INSTALL_DIR/aegis-security-baseline.md"
echo "  ✓ 运行时已校验"

echo "═══ 2. 写入上报配置（0600）═══"
umask 077
cat > "$INSTALL_DIR/config.json" <<CFGEOF
{
  "collectorURL": "${COLLECTOR_URL}",
  "reportURL": "${COLLECTOR_URL}/v1/reports",
  "deviceId": "${DEVICE_ID}",
  "token": "${TOKEN}",
  "hmacSecret": "${SIGNING_SECRET}",
  "scanIntervalSeconds": ${INTERVAL},
  "scanRoot": null
}
CFGEOF
cat > "$INSTALL_DIR/reporting.json" <<RPTEOF
{"schema":"aegis.reporting/v1","report_url":"${COLLECTOR_URL}/v1/reports","report_token":"${TOKEN}","signing_secret":"${SIGNING_SECRET}"}
RPTEOF
chmod 600 "$INSTALL_DIR/config.json" "$INSTALL_DIR/reporting.json"
echo "  ✓ config.json / reporting.json 已写入"

echo "═══ 3. 安装用户级 LaunchAgent ═══"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.aegis.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON_BIN}</string>
        <string>${INSTALL_DIR}/aegis_agent.py</string>
        <string>${HOME}</string>
        <string>--policy</string><string>${INSTALL_DIR}/aegis-policy.json</string>
        <string>--report-config</string><string>${INSTALL_DIR}/reporting.json</string>
        <string>--output</string><string>${INSTALL_DIR}/last-report.json</string>
        <string>--auto-enroll</string>
        <string>--watch</string><string>--interval</string><string>${INTERVAL}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>${INSTALL_DIR}/agent.log</string>
    <key>StandardErrorPath</key><string>${INSTALL_DIR}/agent-error.log</string>
    <key>EnvironmentVariables</key>
    <dict><key>AEGIS_REPORT_TOKEN</key><string>${TOKEN}</string></dict>
</dict>
</plist>
PLISTEOF
chmod 600 "$PLIST"
launchctl bootout "gui/$(id -u)/com.aegis.agent" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
echo "  ✓ LaunchAgent 已加载（开机自启 + 每 ${INTERVAL}s 上报）"

echo "═══ 4. 立即首报并确认连通 ═══"
# 不带 --watch 即单次扫描并上报（--watch 才进入周期循环，交给 LaunchAgent 负责）。
AEGIS_REPORT_TOKEN="$TOKEN" "$PYTHON_BIN" "$INSTALL_DIR/aegis_agent.py" "$HOME" \
  --policy "$INSTALL_DIR/aegis-policy.json" \
  --report-config "$INSTALL_DIR/reporting.json" \
  --output "$INSTALL_DIR/last-report.json" --auto-enroll 2>&1 | tail -6 || echo "  （首报返回非零，见 $INSTALL_DIR/agent-error.log）"
echo "═══ 完成。控制台顶栏应很快显示该终端在线。═══"
