#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-windows-exe.sh — 用 NSIS 构建 Windows 原生安装器 aegis-agent-windows.exe。
#
# 需要 makensis：
#   macOS:  sudo xcodebuild -license accept && brew install nsis
#   Linux:  apt install nsis     Windows: 官方 NSIS
# 未安装 makensis 时本脚本"优雅跳过"（exit 0 + 提示），因此可安全挂在 npm run build
# 前置链里：有 NSIS 就产出 .exe，没有就只跳过，不阻断 macOS/控制台构建。
#
# 服务器 origin 经 AEGIS_PUBLIC_ORIGIN 注入并烘焙进 .exe（默认 RFC 占位
# https://aegis.example.com，真实主机绝不入库）；产物 .exe 为构建生成物，已 gitignore。
# ═══════════════════════════════════════════════════════════════════════
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DL="$ROOT/public/downloads"
NSI="$ROOT/scripts/aegis-agent-windows.nsi"
SERVER="${AEGIS_PUBLIC_ORIGIN:-https://aegis.example.com}"
OUT="$DL/aegis-agent-windows.exe"

if ! command -v makensis >/dev/null 2>&1; then
  echo "  · 跳过 Windows .exe（未安装 makensis/NSIS；macOS 需先 sudo xcodebuild -license accept && brew install nsis）"
  exit 0
fi
for f in aegis-windows.ps1 aegis-policy.json aegis-security-baseline.md aegis-agent-windows-enroll.ps1; do
  [ -f "$DL/$f" ] || { echo "缺少 $DL/$f" >&2; exit 1; }
done
# makensis 的 File/OutFile 相对当前工作目录：cd 到 downloads 让 File 取到运行时、OutFile 落到 downloads。
( cd "$DL" && makensis -V2 -INPUTCHARSET UTF8 -DSERVER="$SERVER" "$NSI" >/dev/null )
[ -f "$OUT" ] || { echo "构建未产出 $OUT" >&2; exit 1; }
echo "  ✓ 已生成 $OUT (server $SERVER, $(wc -c < "$OUT" | tr -d ' ') bytes)"
