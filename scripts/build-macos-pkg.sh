#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-macos-pkg.sh — 构建原生 macOS 安装器；安装后仍需验证上报健康。
#
# 产物是自包含 .pkg：
#   payload  → /Library/Application Support/AegisAgent/{aegis-agent-darwin-*,aegis-policy.factory.json,
#              aegis-security-baseline.md} + /Library/LaunchDaemons/com.aegis.agent.plist
#   postinstall（以 root 运行）→ 覆盖安装识别 + 零接触自动入网：
#              · 若已存在格式有效的入网凭据且控制台地址未变（reporting.json 校验通过、report_url
#                完整上报 URL == 本包批准地址），判定为升级/重装：**保留既有身份**（令牌/配置/策略），
#                不重复入网、不弹任何提示——pkg 即"覆盖安装"通道。
#              · 仅当无凭据 / 凭据格式损坏时向 ${SERVER}/api/enroll 申请上报凭据，
#                严格校验后原子写入 reporting.json(0600)。控制台变更需独立迁移。
#                不从入网响应覆盖策略或信任根；失败留下待修复状态。
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
RUNTIME="retire-aegis-user-macos.sh aegis-configure-macos.sh uninstall-aegis-macos.sh mdm-macos-compliance.sh MACOS-UNINSTALL.md aegis-policy.json aegis-security-baseline.md"
# Both self-contained architectures are mandatory. Source scripts are build inputs only.
BINS="aegis-agent-darwin-arm64 aegis-agent-darwin-x64"
# ES AUTH_EXEC 执行级封禁守护(可选): 有则打进 payload; 未签名/未授权时守护自退(exit 2),
# 终端回退 chmod exec-deny。entitlement 到位后 launchctl kickstart 即点亮。
GUARDS=""
for g in aegis-exec-guard-darwin-arm64 aegis-exec-guard-darwin-x64; do [ -f "$ROOT/native-dist/$g" ] && GUARDS="$GUARDS $g"; done
# 抑制 macOS 扩展属性产生的 ._ AppleDouble 文件，保持 payload 干净（否则包里混入 ._* 冗余项）。
export COPYFILE_DISABLE=1

# Frontend builds on other platforms do not produce a Mac package.
command -v pkgbuild >/dev/null 2>&1 || { echo "  · 跳过 macOS .pkg（非 macOS 或缺 pkgbuild）"; exit 0; }
for b in $BINS; do
  [ -f "$DL/$b" ] && [ ! -L "$DL/$b" ] || { echo "macOS native package requires both ARM64 and x64 regular runtimes" >&2; exit 1; }
  case "$b" in
    *-arm64) cpu=arm64 ;;
    *-x64) cpu=x86_64 ;;
  esac
  kind=$(/usr/bin/file -b "$DL/$b")
  case "$kind" in
    "Mach-O 64-bit executable $cpu"|"Mach-O 64-bit executable $cpu "*) ;;
    *) echo "macOS package refuses non-native or mismatched runtime: $b" >&2; exit 1 ;;
  esac
done
for f in $RUNTIME; do [ -f "$DL/$f" ] || { echo "缺少运行时: $DL/$f" >&2; exit 1; }; done
[ -f "$DL/aegis_agent.py" ] && [ ! -L "$DL/aegis_agent.py" ] || { echo "macOS package requires its source version metadata" >&2; exit 1; }
VERSION=$(grep -m1 'AGENT_VERSION =' "$DL/aegis_agent.py" | sed 's/[^"]*"\([^"]*\)".*/\1/')
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' || { echo "macOS package requires a valid source version" >&2; exit 1; }

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
chmod 755 "$APPDIR/uninstall-aegis-macos.sh" "$APPDIR/retire-aegis-user-macos.sh"; chmod 644 "$APPDIR/aegis-policy.factory.json" "$APPDIR/aegis-security-baseline.md"
for b in $BINS; do chmod 755 "$APPDIR/$b"; done
# Public local integrity inventory; authenticity remains a separate signing gate.
ARM_SHA=$(shasum -a 256 "$APPDIR/aegis-agent-darwin-arm64" | awk '{print $1}')
X64_SHA=$(shasum -a 256 "$APPDIR/aegis-agent-darwin-x64" | awk '{print $1}')
BASELINE_SHA=$(shasum -a 256 "$APPDIR/aegis-security-baseline.md" | awk '{print $1}')
printf '{"schema":"aegis.macos-runtime/v1","agent_version":"%s","files":{"aegis-agent-darwin-arm64":"%s","aegis-agent-darwin-x64":"%s","aegis-security-baseline.md":"%s"}}\n' "$VERSION" "$ARM_SHA" "$X64_SHA" "$BASELINE_SHA" > "$APPDIR/aegis-runtime-manifest.json"
chmod 644 "$APPDIR/aegis-runtime-manifest.json" "$APPDIR/mdm-macos-compliance.sh" "$APPDIR/aegis-configure-macos.sh"

for g in $GUARDS; do chmod 755 "$APPDIR/$g"; done
if [ -f "$ROOT/client/es-guard/com.aegis.execguard.plist" ]; then
  ditto --noextattr --norsrc --noacl "$ROOT/client/es-guard/com.aegis.execguard.plist" "$ROOTDIR/Library/LaunchDaemons/com.aegis.execguard.plist"
  chmod 644 "$ROOTDIR/Library/LaunchDaemons/com.aegis.execguard.plist"
fi

# postinstall selects the current architecture into the canonical executable.
PROG_ARGS='        <string>/Library/Application Support/AegisAgent/aegis-agent</string>'
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
# The approved origin is baked into the signed package; legacy override files
# are not interpreted here. Existing cross-server state requires migration.
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
# No external interpreter fallback exists in a system package.
ARCH=$(uname -m)
case "$ARCH" in
  arm64)  BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-arm64" ;;
  x86_64) BIN_SRC="$INSTALL_DIR/aegis-agent-darwin-x64" ;;
  *) echo "Aegis installation requires a supported architecture" >&2; exit 1 ;;
esac
if [ ! -f "$BIN_SRC" ] || [ -L "$BIN_SRC" ]; then
  echo "Aegis installation requires a native runtime for this architecture" >&2
  exit 1
fi
kind=$(/usr/bin/file -b "$BIN_SRC")
case "$kind" in
  "Mach-O 64-bit executable $ARCH"|"Mach-O 64-bit executable $ARCH "*) ;;
  *) echo "Aegis installation refused a non-native or mismatched runtime" >&2; exit 1 ;;
esac
# Validate before overwriting the canonical executable used by the old service.
chmod 755 "$BIN_SRC"
"$BIN_SRC" --selftest >/dev/null 2>&1 || { echo "Aegis runtime self-test failed" >&2; exit 1; }
"$BIN_SRC" --maintenance-selftest >/dev/null 2>&1 || { echo "Aegis embedded maintenance self-test failed" >&2; exit 1; }
"$BIN_SRC" --service-migration-selftest >/dev/null 2>&1 || { echo "Aegis service migration self-test failed" >&2; exit 1; }
# Retire old user launch configurations only after confirmed service removal.
# Use the new candidate before replacing the canonical runtime or enrolling.
LEGACY=0
for legacy in /Users/*/Library/LaunchAgents/com.aegis.agent.plist /Users/*/Library/LaunchAgents/com.company.aegis-agent.plist; do
  if [ -e "$legacy" ] || [ -L "$legacy" ]; then LEGACY=1; fi
done
if [ "$LEGACY" = 1 ] || [ -e "$INSTALL_DIR/legacy-service-migration.json" ] || [ -L "$INSTALL_DIR/legacy-service-migration.json" ]; then
  "$BIN_SRC" --prepare-legacy-services || { echo "Aegis legacy service preparation requires recovery" >&2; exit 1; }
fi
AGENT="$INSTALL_DIR/aegis-agent"
"$BIN_SRC" --stage-native-runtime || { echo "Aegis native runtime staging requires recovery" >&2; exit 1; }
# 设备 ID 优先硬件序列（稳定，与 agent hardware_device_id() 同算法同值——install 入网令牌的
# device_id 必须与 runtime 上报的 device_id 一致，否则 401）。
_hw_serial="$(ioreg -c IOPlatformExpert 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')"
[ -z "$_hw_serial" ] && _hw_serial="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number \(system\)/{gsub(/ /,"",$2); print $2; exit}')"
if [ -n "$_hw_serial" ]; then DEVICE_ID="$(printf 'aegis-hw:%s' "$_hw_serial" | shasum -a 256 | cut -c1-12)"; else DEVICE_ID="$(hostname | tr -d '\n' | shasum -a 256 | cut -c1-12)"; fi
# The embedded runtime validates existing state and any enrollment response.
# No shell parsing of credentials, prefix URL matching or invented signing keys.
INTERVAL="__INTERVAL__"; VERSION="__VERSION__"
CFG_OK=0
"$AGENT" --install-config "$INSTALL_DIR" "$SERVER/aegis" "$SERVER/api/enroll" "$DEVICE_ID" "$INTERVAL" "" "$VERSION" && CFG_OK=1
# 配置写入或格式有效的原配置保留后清除 pending；上报健康须独立确认。
if [ "$CFG_OK" = 1 ]; then
  rm -f "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
fi
if [ "$CFG_OK" != 1 ]; then
  printf '%s %s\n' "enroll-deferred" "$SERVER/api/enroll" > "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
  chmod 644 "$INSTALL_DIR/enroll-pending" 2>/dev/null || true
fi
# 仅"全新安装（无既有身份）且入网失败"才弹 GUI 提示；覆盖安装保留身份时不打扰用户。
# 入网失败保留 pending；需由受管修复重新尝试，不宣称已自动重入网。
if [ -f "$INSTALL_DIR/enroll-pending" ]; then
  osascript -e 'display dialog "Aegis 入网暂失败。安装程序将尝试注册服务；请检查网络，并在控制台确认终端上报状态。" with title "Aegis 安装提示" buttons {"知道了"} default button 1' 2>/dev/null || true
fi
# Prepared user configurations remain available for explicit recovery.
if ! launchctl bootstrap system "$PLIST" 2>/dev/null; then
  echo "Aegis installation incomplete: launchd registration failed" >&2
  exit 1
fi
if ! launchctl print system/com.aegis.agent >/dev/null 2>&1; then
  echo "Aegis installation incomplete: service registration could not be confirmed" >&2
  exit 1
fi
"$BIN_SRC" --confirm-native-runtime || { echo "Aegis native runtime activation requires verification" >&2; exit 1; }
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
sed -e "s|__SERVER__|$SERVER|g" -e "s|__INTERVAL__|$INTERVAL|g" -e "s|__VERSION__|$VERSION|g" "$SCRIPTS/postinstall" > "$SCRIPTS/postinstall.tmp" && mv -f "$SCRIPTS/postinstall.tmp" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/postinstall"
POST_SHA=$(shasum -a 256 "$SCRIPTS/postinstall" | awk '{print $1}')
printf '{"schema":"aegis.macos-package-capabilities/v1","package_identifier":"com.aegis.agent","legacy_user_services":"journaled-prepare-v1","external_python_required":false,"package_recovery":"native-reinstall-v1","runtime_activation":"journaled-replacement-v1","agent_version":"%s","postinstall_sha256":"%s"}\n' "$VERSION" "$POST_SHA" > "$SCRIPTS/aegis-package-capabilities.json"
chmod 644 "$SCRIPTS/aegis-package-capabilities.json"

# ── 打包（未签名；企业分发应再 productsign + 公证）
xattr -cr "$ROOTDIR" 2>/dev/null || true
pkgbuild --root "$ROOTDIR" --scripts "$SCRIPTS" --identifier "$IDENT" --version "$VERSION" --install-location / "$OUT" >/dev/null
echo "✓ 已生成 $OUT (version $VERSION, server $SERVER, $(wc -c < "$OUT" | tr -d ' ') bytes)"
