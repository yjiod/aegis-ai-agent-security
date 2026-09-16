#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-macos-pkg.sh — 构建原生 macOS 安装器 aegis-agent-macos.pkg（双击安装即被纳管）。
#
# 产物是自包含 .pkg：
#   payload  → /Library/Application Support/AegisAgent/{aegis_agent.py,aegis-policy.json,
#              aegis-security-baseline.md} + /Library/LaunchDaemons/com.aegis.agent.plist
#   postinstall（以 root 运行）→ 零接触自动入网：向 ${SERVER}/api/enroll 申请上报令牌+
#              signing_secret+当前已发布策略，写入 reporting.json(0600) 并覆盖出厂策略，
#              随后 bootstrap 系统级 LaunchDaemon（开机自启、周期扫描 /Users 并上报）。
#
# 服务器地址在构建时烘焙进 postinstall：AEGIS_PUBLIC_ORIGIN（默认 RFC 占位
# https://aegis.example.com，绝不入库真实主机）。部署到真实环境时由 deploy 环境变量
# 注入 AEGIS_PUBLIC_ORIGIN=https://你的控制台，生成的 .pkg 即"装完直接连你的安全中心"。
#
# 未做 Developer ID 签名/公证（需 Apple 证书）：首次打开会被 Gatekeeper 拦，右键→打开
# 或在"系统设置→隐私与安全性"放行即可；企业分发应自行 productsign + notarytool。
#
# 产物为构建生成物（.gitignore），随 npm run build 前置重打，始终与当前运行时一致。
# ═══════════════════════════════════════════════════════════════════════
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DL="$ROOT/public/downloads"
OUT="$DL/aegis-agent-macos.pkg"
SERVER="${AEGIS_PUBLIC_ORIGIN:-https://aegis.example.com}"
INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"
IDENT="com.aegis.agent"
RUNTIME="aegis_agent.py aegis-policy.json aegis-security-baseline.md"
# 抑制 macOS 扩展属性产生的 ._ AppleDouble 文件，保持 payload 干净（否则包里混入 ._* 冗余项）。
export COPYFILE_DISABLE=1

command -v pkgbuild >/dev/null 2>&1 || { echo "需要 pkgbuild（macOS 自带）" >&2; exit 1; }
for f in $RUNTIME; do [ -f "$DL/$f" ] || { echo "缺少运行时: $DL/$f" >&2; exit 1; }; done
VERSION=$(grep -m1 'AGENT_VERSION =' "$DL/aegis_agent.py" | sed 's/[^"]*"\([^"]*\)".*/\1/')
[ -n "$VERSION" ] || VERSION="0.0.0"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
ROOTDIR="$WORK/root"; SCRIPTS="$WORK/scripts"
APPDIR="$ROOTDIR/Library/Application Support/AegisAgent"
mkdir -p "$APPDIR" "$ROOTDIR/Library/LaunchDaemons" "$SCRIPTS"

# ── payload：运行时（root:wheel，目录 755 / agent 755 / 配置类 644，reporting 由 postinstall 写 600）
# 用 ditto --noextattr --norsrc 复制，避免把源文件的扩展属性带进 payload（否则 pkgbuild 生成 ._ AppleDouble 冗余项）。
for f in $RUNTIME; do ditto --noextattr --norsrc --noacl "$DL/$f" "$APPDIR/$f"; done
chmod 755 "$APPDIR/aegis_agent.py"; chmod 644 "$APPDIR/aegis-policy.json" "$APPDIR/aegis-security-baseline.md"

# ── 系统级 LaunchDaemon（root，开机自启 + 周期上报；令牌在 reporting.json，由 postinstall 写）
cat > "$ROOTDIR/Library/LaunchDaemons/$IDENT.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$IDENT</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Library/Application Support/AegisAgent/aegis_agent.py</string>
        <string>/Users</string>
        <string>--policy</string><string>/Library/Application Support/AegisAgent/aegis-policy.json</string>
        <string>--report-config</string><string>/Library/Application Support/AegisAgent/reporting.json</string>
        <string>--output</string><string>/Library/Application Support/AegisAgent/last-report.json</string>
        <string>--auto-enroll</string>
        <string>--watch</string><string>--interval</string><string>$INTERVAL</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/Library/Application Support/AegisAgent/agent.log</string>
    <key>StandardErrorPath</key><string>/Library/Application Support/AegisAgent/agent-error.log</string>
</dict>
</plist>
PLIST
chmod 644 "$ROOTDIR/Library/LaunchDaemons/$IDENT.plist"

# ── postinstall：零接触自动入网 + 加载 LaunchDaemon（__SERVER__ 构建时替换）
cat > "$SCRIPTS/postinstall" <<'POST'
#!/bin/sh
SERVER="__SERVER__"
# 预留覆盖文件（用户编辑即全自动切换控制台，无需重装/记参数）：
#   /Library/Preferences/aegis-server.json  内容 {"server_url":"https://<控制台>"}
if [ -f /Library/Preferences/aegis-server.json ]; then
  OV=$(sed -n 's/.*"server_url"[[:space:]]*:[[:space:]]*"\(https://[^"]*\)".*/\1/p' /Library/Preferences/aegis-server.json | head -1 | sed 's#/*$##')
  if [ -n "$OV" ]; then SERVER="$OV"; echo "  · 预留覆盖文件生效：/Library/Preferences/aegis-server.json"; fi
fi
INSTALL_DIR="/Library/Application Support/AegisAgent"
PLIST="/Library/LaunchDaemons/com.aegis.agent.plist"
PYBIN="$(command -v python3 || echo /usr/bin/python3)"
# 设备 ID 优先硬件序列（稳定，不随 hostname/升级变化），与 agent hardware_device_id() 一致。
_hw_serial="$(ioreg -c IOPlatformExpert 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')"
[ -z "$_hw_serial" ] && _hw_serial="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number \(system\)/{gsub(/ /,"",$2); print $2; exit}')"
if [ -n "$_hw_serial" ]; then DEVICE_ID="$(printf 'aegis-hw:%s' "$_hw_serial" | shasum -a 256 | cut -c1-12)"; else DEVICE_ID="$(hostname | tr -d '\n' | shasum -a 256 | cut -c1-12)"; fi
"$PYBIN" - "$SERVER" "$INSTALL_DIR" "$DEVICE_ID" <<'PY'
import json,os,sys,socket,secrets,urllib.request
server,install_dir,device_id=sys.argv[1:4]
base=server.rstrip('/')
os.makedirs(install_dir,exist_ok=True)
enroll_ok=True
try:
    d=json.load(urllib.request.urlopen(urllib.request.Request(base+'/api/enroll',
        data=json.dumps({"hostname":socket.gethostname(),"device_id":device_id,"agent_version":"0.33.1"}).encode(),
        headers={"Content-Type":"application/json"}),timeout=30))
    tok=d.get('report_token') or ''; sec=d.get('signing_secret') or secrets.token_hex(32)
    rurl=d.get('report_url') or (base+'/aegis/v1/reports'); pol=d.get('policy')
except Exception as e:
    enroll_ok=False
    tok=''; sec=secrets.token_hex(32); rurl=base+'/aegis/v1/reports'; pol=None
    sys.stderr.write("auto-enroll deferred (%s); 请确认能访问 %s 后重装或手动入网\n"%(type(e).__name__,base+'/api/enroll'))
    # 写标记供 postinstall 弹 GUI 提示（双击安装看不到 stderr，避免"没反应"）。
    try:
        open(install_dir+'/enroll-pending','w').write("%s %s\n"%(type(e).__name__,base+'/api/enroll'))
        os.chmod(install_dir+'/enroll-pending',0o644)
    except Exception: pass
if enroll_ok:
    try: os.remove(install_dir+'/enroll-pending')
    except Exception: pass
os.makedirs(install_dir,exist_ok=True)
if tok:
    open(install_dir+'/reporting.json','w').write(json.dumps({"schema":"aegis.reporting/v1","report_url":rurl,"report_token":tok,"signing_secret":sec},ensure_ascii=False))
    os.chmod(install_dir+'/reporting.json',0o600)
    open(install_dir+'/config.json','w').write(json.dumps({"collectorURL":base+'/aegis',"reportURL":rurl,"deviceId":device_id,"token":tok,"hmacSecret":sec,"scanIntervalSeconds":3600,"scanRoot":None},ensure_ascii=False))
    os.chmod(install_dir+'/config.json',0o600)
    if isinstance(pol,dict) and pol.get('schema')=='aegis.policy/v1':
        open(install_dir+'/aegis-policy.json','w').write(json.dumps(pol,ensure_ascii=False)); os.chmod(install_dir+'/aegis-policy.json',0o600)
PY
# 入网失败时对双击安装的用户弹 GUI 提示（stderr 不可见，避免"装完没反应"）。
# 守护进程带 --auto-enroll，网络/地址恢复后会自动重试入网。
if [ -f "$INSTALL_DIR/enroll-pending" ]; then
  REASON="$(head -1 "$INSTALL_DIR/enroll-pending" 2>/dev/null || echo unknown)"
  osascript -e "display dialog \"Aegis 已安装，但零接触入网暂失败（$REASON）。守护进程会在能访问控制台后自动重试；如需立即入网请确认网络或使用已烘焙正确地址的安装包。\" with title \"Aegis 安装提示\" buttons {\"知道了\"} default button 1" 2>/dev/null || true
fi
chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
exit 0
POST
# 用 | 作分隔符替换占位（SERVER 含 / 不能用 /）
sed "s|__SERVER__|$SERVER|g" "$SCRIPTS/postinstall" > "$SCRIPTS/postinstall.tmp" && mv -f "$SCRIPTS/postinstall.tmp" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/postinstall"

# ── 打包（未签名；企业分发应再 productsign + 公证）
xattr -cr "$ROOTDIR" 2>/dev/null || true
pkgbuild --root "$ROOTDIR" --scripts "$SCRIPTS" --identifier "$IDENT" --version "$VERSION" --install-location / "$OUT" >/dev/null
echo "✓ 已生成 $OUT (version $VERSION, server $SERVER, $(wc -c < "$OUT" | tr -d ' ') bytes)"
