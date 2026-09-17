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
# 去-python 化 B：CI 冻结的双架构二进制在 downloads/ 就打进 payload；postinstall 按 uname -m 选。
BINS=""; HAS_BINS=0
for b in aegis-agent-darwin-arm64 aegis-agent-darwin-x64; do [ -f "$DL/$b" ] && { BINS="$BINS $b"; HAS_BINS=1; }; done
# 抑制 macOS 扩展属性产生的 ._ AppleDouble 文件，保持 payload 干净（否则包里混入 ._* 冗余项）。
export COPYFILE_DISABLE=1

# 缺 pkgbuild（非 macOS，如 Linux CI）时优雅跳过（exit 0），与 build-windows-msi.sh 缺
# dotnet/wixl 的处理一致——native 安装包由维护者 macOS 机在 deploy 时产出，CI 只校验
# 可移植的 standalone.run + vinext 构建 + release-verify，故 npm run build 需在各平台可跑通。
command -v pkgbuild >/dev/null 2>&1 || { echo "  · 跳过 macOS .pkg（非 macOS 或缺 pkgbuild）"; exit 0; }
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
for f in $RUNTIME $BINS; do ditto --noextattr --norsrc --noacl "$DL/$f" "$APPDIR/$f"; done
chmod 755 "$APPDIR/aegis_agent.py"; chmod 644 "$APPDIR/aegis-policy.json" "$APPDIR/aegis-security-baseline.md"
for b in $BINS; do chmod 755 "$APPDIR/$b"; done

# plist 在构建期烘焙，故 exec 一个**架构无关的 canonical 名** aegis-agent；postinstall 按 uname -m
# 把对应架构二进制装成该名（无二进制则回退 python3+脚本）。
if [ "$HAS_BINS" = 1 ]; then
  PROG_ARGS='        <string>/Library/Application Support/AegisAgent/aegis-agent</string>'
else
  PROG_ARGS='        <string>/usr/bin/python3</string>
        <string>/Library/Application Support/AegisAgent/aegis_agent.py</string>'
fi
# ── 系统级 LaunchDaemon（root，开机自启 + 周期上报；令牌在 reporting.json，由 postinstall 写）
cat > "$ROOTDIR/Library/LaunchDaemons/$IDENT.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$IDENT</string>
    <key>ProgramArguments</key>
    <array>
${PROG_ARGS}
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
# 去-python 化 B：按架构选冻结二进制装为 canonical aegis-agent（plist 即 exec 它）；缺则回退 python3。
ARCH=$(uname -m)
case "$ARCH" in
  arm64)  BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-arm64" ;;
  x86_64) BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-x64" ;;
  *)      BIN_SRC="" ;;
esac
AGENT=""
if [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then
  cp -f "$BIN_SRC" "$INSTALL_DIR/aegis-agent"
  xattr -d com.apple.quarantine "$INSTALL_DIR/aegis-agent" 2>/dev/null || true
  chmod 755 "$INSTALL_DIR/aegis-agent"; AGENT="$INSTALL_DIR/aegis-agent"
fi
# 设备 ID 优先硬件序列（稳定，与 agent hardware_device_id() 同算法同值——install 入网令牌的
# device_id 必须与 runtime 上报的 device_id 一致，否则 401）。
_hw_serial="$(ioreg -c IOPlatformExpert 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')"
[ -z "$_hw_serial" ] && _hw_serial="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number \(system\)/{gsub(/ /,"",$2); print $2; exit}')"
if [ -n "$_hw_serial" ]; then DEVICE_ID="$(printf 'aegis-hw:%s' "$_hw_serial" | shasum -a 256 | cut -c1-12)"; else DEVICE_ID="$(hostname | tr -d '\n' | shasum -a 256 | cut -c1-12)"; fi
# 入网+写配置：二进制(免 python) 优先，否则 python3 脚本；两者统一走 agent 的 --install-config
# （逻辑与原 python heredoc 等价：自动 /api/enroll、写 reporting.json/config.json 0600、服务端策略覆盖出厂）。
INTERVAL="__INTERVAL__"; VERSION="__VERSION__"
CFG_OK=0
if [ -n "$AGENT" ]; then
  "$AGENT" --install-config "$INSTALL_DIR" "$SERVER/aegis" "$SERVER/api/enroll" "$DEVICE_ID" "$INTERVAL" "" "$VERSION" && CFG_OK=1
else
  PYBIN=""
  for cand in /usr/bin/python3 "$(command -v python3 || true)"; do
    if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" -c 'pass' >/dev/null 2>&1; then PYBIN="$cand"; break; fi
  done
  if [ -n "$PYBIN" ]; then "$PYBIN" "$INSTALL_DIR/aegis_agent.py" --install-config "$INSTALL_DIR" "$SERVER/aegis" "$SERVER/api/enroll" "$DEVICE_ID" "$INTERVAL" "" "$VERSION" && CFG_OK=1; fi
fi
if [ "$CFG_OK" != 1 ]; then
  printf '%s %s\n' "enroll-deferred" "$SERVER/api/enroll" > "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
  chmod 644 "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
fi
# 入网失败时对双击安装的用户弹 GUI 提示（stderr 不可见，避免"装完没反应"）。
# 守护进程带 --auto-enroll，网络/地址恢复后会自动重试入网。
if [ -f "$INSTALL_DIR/enroll-pending" ]; then
  REASON="$(head -1 "$INSTALL_DIR/enroll-pending" 2>/dev/null || echo unknown)"
  osascript -e "display dialog \"Aegis 已安装，但零接触入网暂失败（$REASON）。守护进程会在能访问控制台后自动重试；如需立即入网请确认网络或使用已烘焙正确地址的安装包。\" with title \"Aegis 安装提示\" buttons {\"知道了\"} default button 1" 2>/dev/null || true
fi
# 互斥：装了系统级就停用任何用户级 LaunchAgent（同 device_id 会双重上报：scan_root 在 /Users 与 ~
# 之间来回跳、令牌翻倍）。bootout + 改名禁用（不删、可恢复；改名防下次登录又被 launchd 自动加载）。
for _up in /Users/*/Library/LaunchAgents/com.aegis.agent.plist; do
  [ -f "$_up" ] || continue
  _u=$(echo "$_up" | awk -F/ '{print $3}'); _uid=$(id -u "$_u" 2>/dev/null || true)
  if [ -n "$_uid" ]; then launchctl bootout "gui/$_uid/com.aegis.agent" 2>/dev/null || true; fi
  mv -f "$_up" "$_up.disabled-by-system-install" 2>/dev/null || true
done
chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
exit 0
POST
# 用 | 作分隔符替换占位（SERVER 含 / 不能用 /）
sed -e "s|__SERVER__|$SERVER|g" -e "s|__INTERVAL__|$INTERVAL|g" -e "s|__VERSION__|$VERSION|g" "$SCRIPTS/postinstall" > "$SCRIPTS/postinstall.tmp" && mv -f "$SCRIPTS/postinstall.tmp" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/postinstall"

# ── 打包（未签名；企业分发应再 productsign + 公证）
xattr -cr "$ROOTDIR" 2>/dev/null || true
pkgbuild --root "$ROOTDIR" --scripts "$SCRIPTS" --identifier "$IDENT" --version "$VERSION" --install-location / "$OUT" >/dev/null
echo "✓ 已生成 $OUT (version $VERSION, server $SERVER, $(wc -c < "$OUT" | tr -d ' ') bytes)"
