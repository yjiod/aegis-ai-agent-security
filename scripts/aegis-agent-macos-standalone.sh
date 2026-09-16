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
  echo "已卸载用户级 LaunchAgent；运行时目录保留在 $INSTALL_DIR（如需清理请手动移入废纸篓）。"
  exit 0
fi

if [ -z "$PYTHON_BIN" ]; then echo "错误: 需要 python3" >&2; exit 1; fi

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
AGENT_VER=$(grep -m1 'AGENT_VERSION =' "$INSTALL_DIR/aegis_agent.py" | sed 's/[^"]*"\([^"]*\)".*/\1/')
echo "  ✓ 运行时已就位（agent ${AGENT_VER:-unknown}）"

echo "═══ 2. 获取凭据与策略，写入配置（0600）═══"
# 手动模式校验令牌；自动模式向 /api/enroll 申请令牌+signing_secret+去签名策略。
# 全部在 python 内完成（写 config.json / reporting.json，必要时用服务端策略覆盖出厂策略）。
if ! "$PYTHON_BIN" - "$INSTALL_DIR" "$COLLECTOR_URL" "$ENROLL_URL" "$DEVICE_ID" "$INTERVAL" "$TOKEN" "$AGENT_VER" <<'PY'
import json,os,sys,socket,secrets,urllib.request,urllib.error
install_dir,collector_url,enroll_url,device_id,interval,token,agent_ver=sys.argv[1:8]
interval=int(interval); manual=bool(token)
report_url=collector_url.rstrip('/')+'/v1/reports'
signing_secret=os.environ.get('AEGIS_REPORT_SIGNING_SECRET','')
policy=None
if manual:
    if '<' in token and '>' in token:
        print("  x 令牌是占位符（如 '<令牌>'）。请填真实令牌，或留空以零接触自动入网。",file=sys.stderr); sys.exit(2)
    if not (32<=len(token)<=4096):
        print("  x 令牌长度 %d 不在 32-4096。请填真实令牌，或留空以自动入网。"%len(token),file=sys.stderr); sys.exit(2)
    if not signing_secret: signing_secret=secrets.token_hex(32)
else:
    req=urllib.request.Request(enroll_url,data=json.dumps({"hostname":socket.gethostname(),"device_id":device_id,"agent_version":agent_ver}).encode(),headers={"Content-Type":"application/json"})
    try:
        d=json.load(urllib.request.urlopen(req,timeout=25))
    except urllib.error.HTTPError as e:
        print("  x 自动入网失败 HTTP %s: %s"%(e.code,e.read().decode()[:200]),file=sys.stderr); sys.exit(3)
    except Exception as e:
        print("  x 自动入网失败 %s（请检查能否访问 %s）"%(type(e).__name__,enroll_url),file=sys.stderr); sys.exit(3)
    token=d.get('report_token') or ''
    signing_secret=d.get('signing_secret') or signing_secret or secrets.token_hex(32)
    report_url=d.get('report_url') or report_url
    pol=d.get('policy')
    if isinstance(pol,dict) and pol.get('schema')=='aegis.policy/v1': policy=pol
    if not (32<=len(token)<=4096):
        print("  x 入网响应缺少有效 report_token（服务端未配置 AEGIS_COLLECTOR_TOKEN？）",file=sys.stderr); sys.exit(4)
# 服务端下发的去签名已发布策略覆盖包内出厂策略（终端从而跑到当前策略而非出厂版）。
if policy is not None:
    p=os.path.join(install_dir,'aegis-policy.json')
    open(p,'w').write(json.dumps(policy,ensure_ascii=False)); os.chmod(p,0o600)
os.makedirs(install_dir,exist_ok=True)
cfg={"collectorURL":collector_url,"reportURL":report_url,"deviceId":device_id,"token":token,"hmacSecret":signing_secret,"scanIntervalSeconds":interval,"scanRoot":None}
open(os.path.join(install_dir,'config.json'),'w').write(json.dumps(cfg,ensure_ascii=False)); os.chmod(os.path.join(install_dir,'config.json'),0o600)
rpt={"schema":"aegis.reporting/v1","report_url":report_url,"report_token":token,"signing_secret":signing_secret}
open(os.path.join(install_dir,'reporting.json'),'w').write(json.dumps(rpt,ensure_ascii=False)); os.chmod(os.path.join(install_dir,'reporting.json'),0o600)
print("  + 凭据来源: %s | 上报: %s | 策略: %s"%('手动令牌' if manual else '自动入网',report_url,(policy or {}).get('version','包内出厂')))
PY
then
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
</dict>
</plist>
PLISTEOF
chmod 600 "$PLIST"
launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
echo "  ✓ LaunchAgent 已加载（开机自启 + 每 ${INTERVAL}s 上报）"

echo "═══ 4. 立即首报并确认连通 ═══"
"$PYTHON_BIN" "$INSTALL_DIR/aegis_agent.py" "$HOME" \
  --policy "$INSTALL_DIR/aegis-policy.json" \
  --report-config "$INSTALL_DIR/reporting.json" \
  --output "$INSTALL_DIR/last-report.json" --auto-enroll 2>&1 | tail -4 || echo "  （首报返回非零，见 $INSTALL_DIR/agent-error.log）"
echo "═══ 完成。Aegis 安全中心顶栏应很快显示该终端在线。═══"
exit 0
__PAYLOAD__
