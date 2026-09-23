#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# aegis-agent-macos-standalone.sh — 自包含 macOS 终端安装器（用户级，无需 sudo）。
#
# "独立的包"：运行时(aegis_agent.py / aegis-policy.json / aegis-security-baseline.md)
# 以 tar.gz 内嵌在本文件 __PAYLOAD__ 标记之后，由 scripts/build-macos-standalone.sh
# 打成单文件 aegis-agent-macos-standalone.run。安装时不联网下载运行时，可离线安装，
# 不依赖 MDM / EDR。直接对接 Aegis 安全中心（默认占位 https://aegis.example.com；
# 安装时用 AEGIS_SERVER_URL 或 --server 指定真实控制台地址——真实主机绝不入库）。
#
# 零接触自动入网：不带令牌运行时，自动向 ${SERVER}/api/enroll 申请——拿回上报令牌、
# 每设备独立 signing_secret、以及当前已发布策略（去签名，经 TLS 信任加载），写入本地后
# 立即上报。无需管理员手动下发令牌。也可用 AEGIS_COLLECTOR_TOKEN 手动指定令牌。
#
# 用法（先下载 .run 再运行；勿用 curl|sh，自解压需读取文件本身）：
#   AEGIS_SERVER_URL=https://你的控制台 sh aegis-agent-macos-standalone.run        # 零接触自动入网（推荐）
#   AEGIS_SERVER_URL=https://你的控制台 AEGIS_COLLECTOR_TOKEN='<令牌>' sh aegis-agent-macos-standalone.run
#   可选： --server URL --collector URL --token T --device-id ID --interval SEC --uninstall
# ═══════════════════════════════════════════════════════════════════════
set -eu

SERVER_SET=0
if [ -n "${AEGIS_SERVER_URL:-}" ]; then SERVER_SET=1; fi
SERVER="${AEGIS_SERVER_URL:-https://aegis.example.com}"
COLLECTOR_URL="${AEGIS_COLLECTOR_URL:-${SERVER%/}/aegis}"
ENROLL_URL="${AEGIS_ENROLL_URL:-${SERVER%/}/api/enroll}"
TOKEN="${AEGIS_COLLECTOR_TOKEN:-}"
INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"
# 设备 ID 优先硬件序列（稳定，不随 hostname/升级变化），与 agent hardware_device_id() 一致：
# sha256("aegis-hw:"+serial)[:12]；无序列时回落 sha256(hostname)[:12]（旧行为）。
_hw_serial="$(ioreg -c IOPlatformExpert 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')"
[ -z "$_hw_serial" ] && _hw_serial="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number \(system\)/{gsub(/ /,"",$2); print $2; exit}')"
if [ -n "$_hw_serial" ]; then
  _default_id="$(printf 'aegis-hw:%s' "$_hw_serial" | shasum -a 256 | cut -c1-12)"
else
  _default_id="$(hostname | tr -d '\n' | shasum -a 256 | cut -c1-12)"
fi
DEVICE_ID="${AEGIS_DEVICE_ID:-$_default_id}"
OWNER="${AEGIS_DEVICE_OWNER:-}"
if [ -n "$OWNER" ]; then
  OWNER_ENV_BLOCK="<key>EnvironmentVariables</key><dict><key>AEGIS_DEVICE_OWNER</key><string>${OWNER}</string></dict>"
else
  OWNER_ENV_BLOCK=""
fi
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/Library/Application Support/AegisAgent}"
PLIST="${AEGIS_PLIST:-$HOME/Library/LaunchAgents/com.aegis.agent.plist}"
LABEL="${AEGIS_LABEL:-com.aegis.agent}"
PYTHON_BIN="$(command -v python3 || true)"
DO_UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; SERVER_SET=1; COLLECTOR_URL="${SERVER%/}/aegis"; ENROLL_URL="${SERVER%/}/api/enroll"; shift 2 ;;
    --collector) COLLECTOR_URL="$2"; shift 2 ;;
    --enroll-url) ENROLL_URL="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --device-id) DEVICE_ID="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    # 绑定使用人（SSO 工号/姓名）：上报 owner 字段，便于"哪台机器是谁在用"。仅存私有控制台，不入库。
    --owner) OWNER="$2"; shift 2 ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    # pkg/安装器肌肉记忆参数：.run 不需要 -target，忽略并提示（避免"未知参数"困惑）。
    -target|--target) echo "提示: .run 无需 -target（该参数用于 .pkg/installer）；忽略。" >&2; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

# 公共发行包不烘焙真实控制台地址（隐私红线：真实主机只经 env/私有渠道注入）。
# 若仍是占位且未显式指定 → 立即失败并给出明确指引，而不是去连占位域名报 URLError。
if [ "$SERVER_SET" = "0" ] && [ "$SERVER" = "https://aegis.example.com" ]; then
  echo "错误: 本发行包未烘焙控制台地址（公共仓库隐私要求，真实主机不入库）。" >&2
  echo "      请二选一：" >&2
  echo "        1) AEGIS_SERVER_URL=https://<你的控制台> sh aegis-agent-macos-standalone.run" >&2
  echo "        2) 使用私有渠道分发的已烘焙地址安装包（双击 .pkg 或 sh 已烘焙 .run）。" >&2
  exit 2
fi

if [ "$DO_UNINSTALL" = "1" ]; then
  launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
  [ -f "$PLIST" ] && mv -f "$PLIST" "$HOME/.Trash/" 2>/dev/null || true
  echo "已卸载用户级 LaunchAgent；运行时目录保留在 ${INSTALL_DIR}（如需清理请手动移入废纸篓）。"
  exit 0
fi

# 用户级安装已取消（2026-09，用户决策）：系统级（root LaunchDaemon）能力更强——扫全部
# /Users、可用 pf 做连接级封禁、无需逐用户授权；且用户级/系统级并存曾造成双重上报
# （scan_root 在 /Users 与 ~ 之间跳、device_tokens 翻倍，现网实测）。mac 唯一安装形态=.pkg 系统级。
# 本 .run 仅保留 --uninstall 用于清理历史用户级安装；安装一律引导到 .pkg。
echo "错误: 用户级安装已取消。mac 唯一安装形态为系统级 .pkg。" >&2
echo "      请到控制台「分发中心」下载 aegis-agent-macos.pkg 双击安装（root 扫全部 /Users）。" >&2
echo "      如需清理历史用户级安装: sh <本文件> --uninstall" >&2
exit 2

echo "═══ Aegis 终端安装（自包含 / 用户级 / 无需 sudo）═══"
echo "  设备 ID    : $DEVICE_ID"
echo "  安全中心   : $SERVER"
echo "  上报地址   : $COLLECTOR_URL/v1/reports"
echo "  入网地址   : $ENROLL_URL"
echo "  安装目录   : $INSTALL_DIR"
if [ -n "$TOKEN" ]; then echo "  凭据来源   : 手动指定令牌"; else echo "  凭据来源   : 零接触自动入网"; fi

mkdir -p "$INSTALL_DIR" "$(dirname "$PLIST")"
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
# 去-python 化 B：优先用与本架构匹配的冻结原生二进制（无系统 python3 也能跑）；缺则回退 python3+脚本。
ARCH=$(uname -m); AGENT="$INSTALL_DIR/aegis-agent"
case "$ARCH" in
  arm64)  BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-arm64" ;;
  x86_64) BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-x64" ;;
  *)      BIN_SRC="" ;;
esac
if [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then
  cp -f "$BIN_SRC" "$AGENT"
  xattr -d com.apple.quarantine "$AGENT" 2>/dev/null || true
  chmod 755 "$AGENT"; AGENT_MODE="binary"
  echo "  ✓ 原生二进制就位（${ARCH}，无需 python3）"
elif [ -n "$PYTHON_BIN" ]; then
  AGENT_MODE="python"; echo "  ✓ 回退 python3 形态（${PYTHON_BIN}）"
else
  echo "错误: 无本架构(${ARCH})冻结二进制，且无系统 python3，无法安装。" >&2; exit 1
fi
run_agent() { if [ "$AGENT_MODE" = "binary" ]; then "$AGENT" "$@"; else "$PYTHON_BIN" "$INSTALL_DIR/aegis_agent.py" "$@"; fi; }
if [ "$AGENT_MODE" = "binary" ]; then
  PROG_ARGS="        <string>${AGENT}</string>"
else
  PROG_ARGS="        <string>${PYTHON_BIN}</string>
        <string>${INSTALL_DIR}/aegis_agent.py</string>"
fi
AGENT_VER=$(grep -m1 'AGENT_VERSION =' "$INSTALL_DIR/aegis_agent.py" | sed 's/[^"]*"\([^"]*\)".*/\1/')
echo "  ✓ 运行时已就位（agent ${AGENT_VER:-unknown}）"

echo "═══ 2. 获取凭据与策略，写入配置（0600）═══"
# 覆盖安装识别：已存在有效入网凭据且 Collector 地址未变（且未显式传 --token）→ 判定为升级/重装，
# 保留既有身份（reporting.json/config.json/令牌/策略），**不重复零接触入网**：避免对一台已在网的
# 设备无谓轮换令牌、或在控制台瞬断时把"重装"误判成"安装失败"而中止。令牌被吊销由守护 --auto-enroll 自愈。
EXIST_TOKEN=""; EXIST_URL=""
if [ -f "$INSTALL_DIR/reporting.json" ]; then
  EXIST_TOKEN=$(sed -n 's/.*"report_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALL_DIR/reporting.json" | head -1)
  EXIST_URL=$(sed -n 's/.*"report_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALL_DIR/reporting.json" | head -1)
fi
PRESERVE=0
if [ -z "$TOKEN" ] && [ -n "$EXIST_TOKEN" ] && [ "${#EXIST_TOKEN}" -ge 32 ] && [ "${#EXIST_TOKEN}" -le 4096 ]; then
  case "$EXIST_URL" in
    "$COLLECTOR_URL"*) PRESERVE=1 ;;
  esac
fi
# 由 agent 自身（冻结二进制或 python3 脚本）完成入网+写配置——安装器不再内嵌 python heredoc，
# 故无 python3 的 mac 也能装（二进制自带 --install-config 逻辑，与旧 heredoc 等价）。
if [ "$PRESERVE" = 1 ]; then
  echo "  · 覆盖安装：检测到既有有效入网凭据（Collector 地址未变），保留身份，跳过入网"
elif ! run_agent --install-config "$INSTALL_DIR" "$COLLECTOR_URL" "$ENROLL_URL" "$DEVICE_ID" "$INTERVAL" "$TOKEN" "$AGENT_VER"; then
  echo "错误: 凭据/策略获取失败，安装中止（未注册 LaunchAgent）。" >&2; exit 1
fi

echo "═══ 3. 安装用户级 LaunchAgent ═══"
# 令牌/签名密钥都在 reporting.json（0600），Agent 经 --report-config 读取，plist 不再内嵌令牌。
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
${PROG_ARGS}
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
    ${OWNER_ENV_BLOCK}
</dict>
</plist>
PLISTEOF
chmod 600 "$PLIST"
launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
echo "  ✓ LaunchAgent 已加载（开机自启 + 每 ${INTERVAL}s 上报）"

echo "═══ 4. 立即首报并确认连通 ═══"
run_agent "$HOME" \
  --policy "$INSTALL_DIR/aegis-policy.json" \
  --report-config "$INSTALL_DIR/reporting.json" \
  --output "$INSTALL_DIR/last-report.json" --auto-enroll 2>&1 | tail -4 || echo "  （首报返回非零，见 $INSTALL_DIR/agent-error.log）"
echo "═══ 完成。Aegis 安全中心顶栏应很快显示该终端在线。═══"
exit 0
__PAYLOAD__
