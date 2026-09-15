#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-windows-msi.sh — 构建 Windows 原生安装器 aegis-agent-windows.msi（可在 macOS/Linux 交叉产出）。
#
# 流程：dotnet 交叉发布 win-x64 自包含单文件 AegisServiceHost.exe → 组装 MSI 源目录
# （host + aegis-windows.ps1 + 策略/基线 + Install-Aegis-Windows.ps1 + 构建时生成的 server.json）
# → wixl 打包 .msi → 解包扫描确保无任何凭据 → 生成 SHA256SUMS。
#
# 缺 dotnet 或 wixl 时优雅跳过（exit 0），故可安全挂在 npm run build 前置链：
#   macOS:  brew install msitools（wixl）；dotnet 10 SDK
# 服务器 origin 经 AEGIS_PUBLIC_ORIGIN 注入并烘焙进 server.json（默认 RFC 占位，真实主机不入库）。
# 产物 .msi 为构建生成物（.gitignore），随 dist 部署。
# ═══════════════════════════════════════════════════════════════════════
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLIENT="$ROOT/client"
DL="$ROOT/public/downloads"
OUT="$DL/aegis-agent-windows.msi"
SERVER="${AEGIS_PUBLIC_ORIGIN:-https://aegis.example.com}"
INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"

if ! command -v dotnet >/dev/null 2>&1; then echo "  · 跳过 Windows .msi（未安装 dotnet SDK）"; exit 0; fi
if ! command -v wixl >/dev/null 2>&1; then echo "  · 跳过 Windows .msi（未安装 wixl/msitools）"; exit 0; fi
for f in aegis-windows.ps1 aegis-policy.json aegis-security-baseline.md; do
  [ -f "$DL/$f" ] || { echo "缺少 $DL/$f" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "  · dotnet 交叉发布 AegisServiceHost (win-x64, self-contained, single-file)…"
dotnet publish "$CLIENT/host/AegisServiceHost.csproj" -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:DebugType=None -p:EnableCompressionInSingleFile=true -o "$WORK/publish" >/dev/null 2>&1
[ -f "$WORK/publish/AegisServiceHost.exe" ] || { echo "dotnet 发布未产出 AegisServiceHost.exe" >&2; exit 1; }

cp "$WORK/publish/AegisServiceHost.exe" "$WORK/"
cp "$DL/aegis-windows.ps1" "$DL/aegis-policy.json" "$DL/aegis-security-baseline.md" "$WORK/"
cp "$CLIENT/Install-Aegis-Windows.ps1" "$WORK/"
cp "$CLIENT/AegisAgent.wxs" "$WORK/"
# server.json 构建时生成（真实 origin 只在部署环境注入，绝不入库）
printf '{"schema":"aegis.server/v1","server_url":"%s","scan_interval_seconds":%s}\n' "$SERVER" "$INTERVAL" > "$WORK/server.json"

echo "  · wixl 打包 .msi…"
( cd "$WORK" && wixl -a x64 -o "$OUT" AegisAgent.wxs )
[ -f "$OUT" ] || { echo "wixl 未产出 $OUT" >&2; exit 1; }

# 解包扫描：安装包内绝不能含任何上报令牌/签名密钥（令牌装机时才经 /api/enroll 获取）。
mkdir -p "$WORK/check"
if command -v msiextract >/dev/null 2>&1; then msiextract -C "$WORK/check" "$OUT" >/dev/null 2>&1 || true; fi
if grep -rInE '"report_token":"[^"]{32,}"|"signing_secret":"[^"]{32,}"|__PILOT_TOKEN__|__PILOT_SECRET__' "$WORK/check" >/dev/null 2>&1; then
  echo "  ✗ 安装包内发现凭据材料，拒绝产出" >&2; rm -f "$OUT"; exit 1
fi

SUM=$(if command -v sha256sum >/dev/null 2>&1; then sha256sum "$OUT" | cut -d' ' -f1; else shasum -a 256 "$OUT" | cut -d' ' -f1; fi)
printf '%s  %s\n' "$SUM" "$(basename "$OUT")" > "$DL/aegis-agent-windows.msi.sha256"
echo "  ✓ 已生成 $OUT (server $SERVER, $(wc -c < "$OUT" | tr -d ' ') bytes, sha256 ${SUM:0:12}…)"
