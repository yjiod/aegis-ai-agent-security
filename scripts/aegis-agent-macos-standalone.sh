#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# aegis-agent-macos-standalone.sh — 自包含 macOS 终端安装器（用户级，无需 sudo）。
#
# 这是"独立的包"的安装器头部：运行时(aegis_agent.py / aegis-policy.json /
# aegis-security-baseline.md)以 tar.gz 形式内嵌在本文件 __PAYLOAD__ 标记之后，
# 由 scripts/build-macos-standalone.sh 打包成单文件 aegis-agent-macos-standalone.run。
# 安装时**不联网下载运行时**（只在上报时连 Collector），因此可拷到任意机器离线安装，
# 不依赖 MDM / EDR / 任何下发系统。
#
# 直接对接 Aegis 安全中心：report_url 默认 https://aegis.example.com/aegis/v1/reports
# （nginx 反代 /aegis/*→Collector）。安装后注册用户级 LaunchAgent，开机自启+周期上报。
#
# 用法（先下载本 .run，再运行；不要用 curl|sh，自解压需要读取文件本身）：
#   AEGIS_COLLECTOR_TOKEN='<64位令牌>' sh aegis-agent-macos-standalone.run
#   可选： --collector URL  --token T  --device-id ID  --interval SEC  --uninstall
# 令牌是敏感凭据，只经环境变量/参数传入，绝不写进包内或日志。
# ═══════════════════════════════════════════════════════════════════════
set -eu

COLLECTOR_URL="${AEGIS_COLLECTOR_URL:-https://aegis.example.com/aegis}"
TOKEN="${AEGIS_COLLECTOR_TOKEN:-}"
INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"
DEVICE_ID="${AEGIS_DEVICE_ID:-MAC-$(hostname | cut -c1-12 | tr '[:lower:]' '[:upper:]' | tr ' ' '-')}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/Library/Application Support/AegisAgent}"
PLIST="$HOME/Library/LaunchAgents/com.aegis.agent.plist"
PYTHON_BIN="$(command -v python3 || true)"
DO_UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --collector) COLLECTOR_URL="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --device-id) DEVICE_ID="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [ "$DO_UNINSTALL" = "1" ]; then
  launchctl bootout "gui/$(id -u)/com.aegis.agent" 2>/dev/null || true
  [ -f "$PLIST" ] && mv -f "$PLIST" "$HOME/.Trash/" 2>/dev/null || true
  echo "已卸载用户级 LaunchAgent；运行时目录保留在 $INSTALL_DIR（如需清理请手动移入废纸篓）。"
  exit 0
fi

# 令牌前置校验：Agent 上报契约要求 32–4096 字符。占位符/过短直接拦下并给明确提示，
# 而不是写坏 reporting.json 让 Agent 回一句晦涩的"上报配置契约无效"。
if [ -z "$TOKEN" ]; then
  echo "错误: 需要令牌。请用 AEGIS_COLLECTOR_TOKEN='<令牌>' 或 --token 传入。" >&2
  echo "      管理员从服务器 /etc/aegis/.collector-token-current(0600) 获取 64 位令牌。" >&2
  exit 1
fi
case "$TOKEN" in
  *"<"*">"*|*'TOKEN'*) echo "错误: 令牌看起来是占位符（如 '<令牌>'），请填入真实的 64 位十六进制令牌。" >&2; exit 1 ;;
esac
if [ "${#TOKEN}" -lt 32 ] || [ "${#TOKEN}" -gt 4096 ]; then
  echo "错误: 令牌长度 ${#TOKEN} 不在 32–4096 之间（很可能把示例里的 '<令牌>' 原样粘进来了）。" >&2; exit 1
fi
if [ -z "$PYTHON_BIN" ]; then echo "错误: 需要 python3" >&2; exit 1; fi

echo "═══ Aegis 终端安装（自包含 / 用户级 / 无需 sudo）═══"
echo "  设备 ID    : $DEVICE_ID"
echo "  Collector  : $COLLECTOR_URL"
echo "  安装目录   : $INSTALL_DIR"

mkdir -p "$INSTALL_DIR" "$HOME/Library/LaunchAgents"
chmod 700 "$INSTALL_DIR"

echo "═══ 1. 解包内嵌运行时（不联网下载）═══"
PAYLOAD_LINE=$(awk '/^__PAYLOAD__$/{print NR + 1; exit 0;}' "$0")
[ -n "$PAYLOAD_LINE" ] || { echo "错误: 包内未找到 __PAYLOAD__ 标记（请用完整 .run 文件运行，勿用 curl|sh）。" >&2; exit 1; }
tail -n+"$PAYLOAD_LINE" "$0" | tar xzf - -C "$INSTALL_DIR"
for f in aegis_agent.py aegis-policy.json aegis-security-baseline.md; do
  [ -f "$INSTALL_DIR/$f" ] || { echo "错误: 解包缺少 $f" >&2; exit 1; }
done
chmod 700 "$INSTALL_DIR/aegis_agent.py"
chmod 600 "$INSTALL_DIR/aegis-policy.json" "$INSTALL_DIR/aegis-security-baseline.md"
echo "  ✓ 运行时已就位"

# Agent 强制 reporting.json 的 signing_secret 为 32+ 字符且不同于 token，否则拒绝上报。
# 生产 Collector 处于显式允许未签名模式（只验 Bearer 令牌、忽略报告签名），故本机用
# CSPRNG 生成独立 signing_secret 满足契约；若服务端启用强制验签，用 AEGIS_REPORT_SIGNING_SECRET 传入一致密钥。
SIGNING_SECRET="${AEGIS_REPORT_SIGNING_SECRET:-$("$PYTHON_BIN" -c 'import secrets;print(secrets.token_hex(32))')}"

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
AEGIS_REPORT_TOKEN="$TOKEN" "$PYTHON_BIN" "$INSTALL_DIR/aegis_agent.py" "$HOME" \
  --policy "$INSTALL_DIR/aegis-policy.json" \
  --report-config "$INSTALL_DIR/reporting.json" \
  --output "$INSTALL_DIR/last-report.json" --auto-enroll 2>&1 | tail -6 || echo "  （首报返回非零，见 $INSTALL_DIR/agent-error.log）"
echo "═══ 完成。Aegis 安全中心顶栏应很快显示该终端在线。═══"
exit 0
__PAYLOAD__
