#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-macos-pkg.sh — 构建原生 macOS 安装器 aegis-agent-macos.pkg（双击安装即被纳管）。
#
# 产物是自包含 .pkg：
#   payload  → /Library/Application Support/AegisAgent/{aegis_agent.py,aegis-policy.factory.json,
#              aegis-security-baseline.md} + /Library/LaunchDaemons/com.aegis.agent.plist
#   postinstall（以 root 运行）→ 覆盖安装识别 + 零接触自动入网：
#              · 若已存在有效入网凭据且控制台地址未变（reporting.json 令牌有效、report_url
#                前缀 == 本包烘焙地址），判定为升级/重装：**保留既有身份**（令牌/配置/策略），
#                不重复入网、不弹任何提示——pkg 即"覆盖安装"通道。
#              · 仅当无凭据 / 凭据损坏 / 控制台地址变更（全新安装或换控制台）才向
#                ${SERVER}/api/enroll 申请上报令牌+signing_secret+当前已发布策略，写入
#                reporting.json(0600) 并覆盖出厂策略；此时入网失败才弹"入网暂失败"提示。
#              随后 bootstrap 系统级 LaunchDaemon（开机自启、周期扫描 /Users 并上报）。
#
# 服务器地址在构建时烘焙进 postinstall：AEGIS_PUBLIC_ORIGIN（默认 RFC 占位
# https://aegis.example.com，绝不入库真实主机）。部署到真实环境时由 deploy 环境变量
# 注入 AEGIS_PUBLIC_ORIGIN=https://你的控制台，生成的 .pkg 即"装完直接连你的安全中心"。
#
# 此脚本生成未签名测试包；企业分发仍需 Developer ID 签名、公证和发布验证。
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
RUNTIME="aegis_agent.py aegis_self_update.py aegis_macos_maintenance.py uninstall-aegis-macos.sh MACOS-UNINSTALL.md aegis-policy.json aegis-security-baseline.md"
# 去-python 化 B：CI 冻结的双架构二进制在 downloads/ 就打进 payload；postinstall 按 uname -m 选。
BINS=""; HAS_BINS=0
for b in aegis-agent-darwin-arm64 aegis-agent-darwin-x64; do [ -f "$DL/$b" ] && { BINS="$BINS $b"; HAS_BINS=1; }; done
# ES AUTH_EXEC 执行级封禁守护(可选): 有则打进 payload; 未签名/未授权时守护自退(exit 2),
# 终端回退 chmod exec-deny。entitlement 到位后 launchctl kickstart 即点亮。
GUARDS=""
for g in aegis-exec-guard-darwin-arm64 aegis-exec-guard-darwin-x64; do [ -f "$ROOT/native-dist/$g" ] && GUARDS="$GUARDS $g"; done
# 抑制 macOS 扩展属性产生的 ._ AppleDouble 文件，保持 payload 干净（否则包里混入 ._* 冗余项）。
export COPYFILE_DISABLE=1

# 缺 pkgbuild（非 macOS，如 Linux CI）时优雅跳过（exit 0），与 build-windows-msi.sh 缺
# dotnet/wixl 的处理一致——native 安装包由维护者 macOS 机在 deploy 时产出，CI 只校验
# 可移植的 standalone.run + vinext 构建 + release-verify，故 npm run build 需在各平台可跑通。
command -v pkgbuild >/dev/null 2>&1 || { echo "  · 跳过 macOS .pkg（非 macOS 或缺 pkgbuild）"; exit 0; }
# A universal package must not silently contain only the other CPU's executable.
if [ "$HAS_BINS" = 1 ]; then
  for b in aegis-agent-darwin-arm64 aegis-agent-darwin-x64; do
    [ -f "$DL/$b" ] || { echo "macOS native package requires both ARM64 and x64 runtimes" >&2; exit 1; }
  done
fi
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
for f in $RUNTIME $BINS; do
  destination="$f"
  [ "$f" != aegis-policy.json ] || destination=aegis-policy.factory.json
  ditto --noextattr --norsrc --noacl "$DL/$f" "$APPDIR/$destination"
done
for g in $GUARDS; do ditto --noextattr --norsrc --noacl "$ROOT/native-dist/$g" "$APPDIR/$g"; done
chmod 755 "$APPDIR/aegis_agent.py" "$APPDIR/uninstall-aegis-macos.sh"; chmod 644 "$APPDIR/aegis-policy.factory.json" "$APPDIR/aegis-security-baseline.md" "$APPDIR/aegis_macos_maintenance.py"
for b in $BINS; do chmod 755 "$APPDIR/$b"; done
for g in $GUARDS; do chmod 755 "$APPDIR/$g"; done
if [ -f "$ROOT/client/es-guard/com.aegis.execguard.plist" ]; then
  ditto --noextattr --norsrc --noacl "$ROOT/client/es-guard/com.aegis.execguard.plist" "$ROOTDIR/Library/LaunchDaemons/com.aegis.execguard.plist"
  chmod 644 "$ROOTDIR/Library/LaunchDaemons/com.aegis.execguard.plist"
fi

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
set -eu
SERVER="__SERVER__"
# 预留覆盖文件（用户编辑即全自动切换控制台，无需重装/记参数）：
#   /Library/Preferences/aegis-server.json  内容 {"server_url":"https://<控制台>"}
if [ -f /Library/Preferences/aegis-server.json ]; then
  OV=$(sed -n 's/.*"server_url"[[:space:]]*:[[:space:]]*"\(https://[^"]*\)".*/\1/p' /Library/Preferences/aegis-server.json | head -1 | sed 's#/*$##')
  if [ -n "$OV" ]; then SERVER="$OV"; echo "  · 预留覆盖文件生效：/Library/Preferences/aegis-server.json"; fi
fi
INSTALL_DIR="/Library/Application Support/AegisAgent"
PLIST="/Library/LaunchDaemons/com.aegis.agent.plist"
# The Installer payload must never own the mutable, server-managed policy path.
# Initialize only a fresh installation; retain upgrades byte for byte.
if [ -L "$INSTALL_DIR/aegis-policy.json" ]; then
  echo "Aegis installation refused: active policy must not be a symbolic link" >&2
  exit 1
fi
if [ ! -e "$INSTALL_DIR/aegis-policy.json" ]; then
  cp -p "$INSTALL_DIR/aegis-policy.factory.json" "$INSTALL_DIR/aegis-policy.json"
fi
# 去-python 化 B：按架构选冻结二进制装为 canonical aegis-agent（plist 即 exec 它）；缺则回退 python3。
ARCH=$(uname -m)
case "$ARCH" in
  arm64)  BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-arm64" ;;
  x86_64) BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-x64" ;;
  *)      BIN_SRC="" ;;
esac
AGENT=""
if [ "__NATIVE_PACKAGE__" = 1 ] && [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then
  cp -f "$BIN_SRC" "$INSTALL_DIR/aegis-agent"
  xattr -d com.apple.quarantine "$INSTALL_DIR/aegis-agent" 2>/dev/null || true
  chmod 755 "$INSTALL_DIR/aegis-agent"; AGENT="$INSTALL_DIR/aegis-agent"
fi
if [ "__NATIVE_PACKAGE__" = 1 ] && [ -z "$AGENT" ]; then
  echo "Aegis installation requires a native runtime for this architecture" >&2
  exit 1
fi
# Resolve and test the exact interpreter written into launchd's arguments.
# An existing canonical binary from an older package is not a fallback.
PYBIN=""
if [ -n "$AGENT" ]; then
  "$AGENT" --selftest >/dev/null 2>&1 || { echo "Aegis runtime self-test failed" >&2; exit 1; }
else
  for cand in /usr/bin/python3 "$(command -v python3 || true)"; do
    if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" "$INSTALL_DIR/aegis_agent.py" --selftest >/dev/null 2>&1; then PYBIN="$cand"; break; fi
  done
  [ -n "$PYBIN" ] || { echo "Aegis installation requires a working runtime" >&2; exit 1; }
  /usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 $PYBIN" "$PLIST"
fi
# 设备 ID 优先硬件序列（稳定，与 agent hardware_device_id() 同算法同值——install 入网令牌的
# device_id 必须与 runtime 上报的 device_id 一致，否则 401）。
_hw_serial="$(ioreg -c IOPlatformExpert 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')"
[ -z "$_hw_serial" ] && _hw_serial="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number \(system\)/{gsub(/ /,"",$2); print $2; exit}')"
if [ -n "$_hw_serial" ]; then DEVICE_ID="$(printf 'aegis-hw:%s' "$_hw_serial" | shasum -a 256 | cut -c1-12)"; else DEVICE_ID="$(hostname | tr -d '\n' | shasum -a 256 | cut -c1-12)"; fi
# 覆盖安装识别（pkg = 升级/重装通道）：若已存在有效入网凭据且控制台地址未变，说明本机早已
# 入网——保留既有身份（reporting.json/config.json/令牌/策略），**不重复零接触入网**，也就不会
# 对一台已在网的设备误报"入网失败"。仅当无凭据 / 凭据损坏 / 控制台地址变更时才重新入网。
# （令牌被服务端吊销的情况由守护进程 --auto-enroll 在 401/403 时自动重入网自愈，无需安装期处理。）
EXIST_TOKEN=""; EXIST_URL=""
if [ -f "$INSTALL_DIR/reporting.json" ]; then
  EXIST_TOKEN=$(sed -n 's/.*"report_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALL_DIR/reporting.json" | head -1)
  EXIST_URL=$(sed -n 's/.*"report_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALL_DIR/reporting.json" | head -1)
fi
PRESERVE=0
if [ -n "$EXIST_TOKEN" ] && [ "${#EXIST_TOKEN}" -ge 32 ] && [ "${#EXIST_TOKEN}" -le 4096 ]; then
  case "$EXIST_URL" in
    "$SERVER"*) PRESERVE=1 ;;
  esac
fi
# 入网+写配置：二进制(免 python) 优先，否则 python3 脚本；两者统一走 agent 的 --install-config
# （逻辑与原 python heredoc 等价：自动 /api/enroll、写 reporting.json/config.json 0600、服务端策略覆盖出厂）。
INTERVAL="__INTERVAL__"; VERSION="__VERSION__"
CFG_OK=0
if [ "$PRESERVE" = 1 ]; then
  CFG_OK=1
  echo "  · 覆盖安装：检测到既有有效入网凭据（控制台地址未变），保留身份，跳过零接触入网"
elif [ -n "$AGENT" ]; then
  "$AGENT" --install-config "$INSTALL_DIR" "$SERVER/aegis" "$SERVER/api/enroll" "$DEVICE_ID" "$INTERVAL" "" "$VERSION" && CFG_OK=1
else
  "$PYBIN" "$INSTALL_DIR/aegis_agent.py" --install-config "$INSTALL_DIR" "$SERVER/aegis" "$SERVER/api/enroll" "$DEVICE_ID" "$INTERVAL" "" "$VERSION" && CFG_OK=1
fi
# 入网成功或覆盖保留（设备已在网）→ 清掉历史 enroll-pending，守护无需再重试、也不残留旧标记。
if [ "$CFG_OK" = 1 ]; then
  rm -f "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
fi
if [ "$CFG_OK" != 1 ]; then
  printf '%s %s\n' "enroll-deferred" "$SERVER/api/enroll" > "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
  chmod 644 "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
fi
# 仅"全新安装（无既有身份）且入网失败"才弹 GUI 提示；覆盖安装保留身份时不打扰用户。
# 守护进程带 --auto-enroll，网络/地址恢复后会自动重试入网。
if [ -f "$INSTALL_DIR/enroll-pending" ]; then
  osascript -e 'display dialog "Aegis 入网暂失败。安装程序将尝试注册服务；请检查网络，并在控制台确认终端上报状态。" with title "Aegis 安装提示" buttons {"知道了"} default button 1' 2>/dev/null || true
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
if ! launchctl bootstrap system "$PLIST" 2>/dev/null; then
  echo "Aegis installation incomplete: launchd registration failed" >&2
  exit 1
fi
if ! launchctl print system/com.aegis.agent >/dev/null 2>&1; then
  echo "Aegis installation incomplete: service registration could not be confirmed" >&2
  exit 1
fi
# ES AUTH_EXEC 执行级封禁守护: 按架构装成 canonical 名并 best-effort 加载。
# 未签名/未授权时守护自退(exit 2, KeepAlive=false 不重试), 终端回退 chmod exec-deny; 不阻断安装。
case "$(uname -m)" in
  arm64)  GUARD_SRC="$INSTALL_DIR/aegis-exec-guard-darwin-arm64" ;;
  x86_64) GUARD_SRC="$INSTALL_DIR/aegis-exec-guard-darwin-x64" ;;
  *) GUARD_SRC="" ;;
esac
if [ -n "$GUARD_SRC" ] && [ -f "$GUARD_SRC" ] && [ -f /Library/LaunchDaemons/com.aegis.execguard.plist ]; then
  cp -f "$GUARD_SRC" "$INSTALL_DIR/aegis-exec-guard" 2>/dev/null || true
  chmod 755 "$INSTALL_DIR/aegis-exec-guard" 2>/dev/null || true
  launchctl bootout system /Library/LaunchDaemons/com.aegis.execguard.plist 2>/dev/null || true
  launchctl bootstrap system /Library/LaunchDaemons/com.aegis.execguard.plist 2>/dev/null || true
fi
exit 0
POST
# 用 | 作分隔符替换占位（SERVER 含 / 不能用 /）
sed -e "s|__SERVER__|$SERVER|g" -e "s|__INTERVAL__|$INTERVAL|g" -e "s|__VERSION__|$VERSION|g" -e "s|__NATIVE_PACKAGE__|$HAS_BINS|g" "$SCRIPTS/postinstall" > "$SCRIPTS/postinstall.tmp" && mv -f "$SCRIPTS/postinstall.tmp" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/postinstall"

# ── 打包（未签名；企业分发应再 productsign + 公证）
xattr -cr "$ROOTDIR" 2>/dev/null || true
pkgbuild --root "$ROOTDIR" --scripts "$SCRIPTS" --identifier "$IDENT" --version "$VERSION" --install-location / "$OUT" >/dev/null
echo "✓ 已生成 $OUT (version $VERSION, server $SERVER, $(wc -c < "$OUT" | tr -d ' ') bytes)"
