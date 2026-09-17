#!/bin/bash
# build-lite-push.sh — 桌管(MDM)轻量推送包构建器：只推"变化的组件"+apply 脚本+清单，不推完整安装包。
# 用法: sh scripts/build-lite-push.sh [include-host]   # include-host 时 win 包内含单架构 host exe
# 产物: native-dist/push/aegis-push-mac.zip, aegis-push-win-x64.zip, aegis-push-win-arm64.zip
# 每个 zip 内含: 组件文件 + apply-<os>.<sh|ps1> + PUSH-MANIFEST.json(每组件 sha256 + 最低版本 + 应用步骤)
# 体积量级(2026-09-17 实测): mac ≈ 36KB(gz) / win 脚本包 ≈ 24KB(gz) / win 含 host ≈ 5.9MB(gz, 单架构)
#   对比完整安装包: mac .pkg 35KB / win .msi 12.3MB(双架构 cabinet)
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DL="$ROOT/public/downloads"
NATIVE="$ROOT/native-dist"
OUT="$NATIVE/push"
INCLUDE_HOST="${1:-}"
mkdir -p "$OUT"

sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; else sha256sum "$1" | cut -d' ' -f1; fi; }
AGENT_VERSION=$(grep -m1 'AGENT_VERSION = ' "$DL/aegis_agent.py" | sed 's/[^"]*"\([^"]*\)".*/\1/')

# ── mac 轻量包: 仅脚本+基线(无 pkg 包装), apply 直接换文件+重启 launchd ──
W="$OUT/mac"; rm -rf "$W"; mkdir -p "$W"
cp "$DL/aegis_agent.py" "$DL/aegis_self_update.py" "$DL/aegis-security-baseline.md" "$W/"
cp "$ROOT/windows-verify/apply-mac.sh" "$W/apply-mac.sh" 2>/dev/null || cp "$ROOT/scripts/apply-mac-lite.sh" "$W/apply-mac.sh"
chmod +x "$W/apply-mac.sh"
cat > "$W/PUSH-MANIFEST.json" <<EOF
{
  "schema": "aegis.push/v1",
  "platform": "macos",
  "agent_version": "$AGENT_VERSION",
  "kind": "lite",
  "components": {
    "aegis_agent.py": "$(sha "$W/aegis_agent.py")",
    "aegis_self_update.py": "$(sha "$W/aegis_self_update.py")",
    "aegis-security-baseline.md": "$(sha "$W/aegis-security-baseline.md")"
  },
  "apply": "apply-mac.sh",
  "notes": "仅替换脚本+基线并重启 launchd; 不触碰 reporting/policy/入网凭据。host 无独立二进制(mac 为纯 python)。"
}
EOF
( cd "$W" && zip -q -r "$OUT/aegis-push-mac.zip" . )

# ── win 轻量包: 扫描器+安装脚本; include-host 时加单架构 host exe ──
for ARCH in x64 arm64; do
  W="$OUT/win-$ARCH"; rm -rf "$W"; mkdir -p "$W"
  cp "$DL/aegis-windows.ps1" "$W/"
  cp "$ROOT/client/Install-Aegis-Windows.ps1" "$W/"
  cp "$ROOT/windows-verify/apply-win.ps1" "$W/apply-win.ps1" 2>/dev/null || cp "$ROOT/scripts/apply-win-lite.ps1" "$W/apply-win.ps1"
  comps="\"aegis-windows.ps1\": \"$(sha "$W/aegis-windows.ps1")\", \"Install-Aegis-Windows.ps1\": \"$(sha "$W/Install-Aegis-Windows.ps1")\""
  if [ -n "$INCLUDE_HOST" ]; then
    EXE="$NATIVE/host/win-$ARCH/AegisServiceHost.exe"
    [ -f "$EXE" ] || EXE=$(find "$ROOT/client/host" -path "*win-$ARCH*" -name "AegisServiceHost.exe" 2>/dev/null | head -1)
    if [ -n "$EXE" ]; then cp "$EXE" "$W/AegisServiceHost.exe"; comps="$comps, \"AegisServiceHost.exe\": \"$(sha "$W/AegisServiceHost.exe")\""; fi
  fi
  cat > "$W/PUSH-MANIFEST.json" <<EOF
{
  "schema": "aegis.push/v1",
  "platform": "windows-$ARCH",
  "agent_version": "$AGENT_VERSION",
  "kind": "lite",
  "components": { $comps },
  "apply": "apply-win.ps1",
  "notes": "仅替换扫描器/安装脚本(含 host exe 时一并替换)并 Restart-Service; 不触碰 reporting.dpapi/入网。MSI 结构/ACL 变更仍需完整 .msi。"
}
EOF
  ( cd "$W" && zip -q -r "$OUT/aegis-push-win-$ARCH.zip" . )
done

echo "=== lite push packages ==="
ls -l "$OUT"/*.zip | awk '{printf "%s %d B\n",$NF,$5}'
for z in "$OUT"/*.zip; do printf "%s gz=%d B\n" "$(basename "$z")" $(gzip -c "$z" | wc -c | tr -d ' '); done
