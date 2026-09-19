#!/bin/sh
# build-es-guard.sh — 编译 AegisExecGuard(Endpoint Security AUTH_EXEC 执行级封禁守护)。
# 产出 native-dist/aegis-exec-guard-darwin-{arm64,x64}(gitignored, 随 .pkg/部署分发)。
# 无 swiftc 时优雅跳过(exit 0), 不阻断主构建链。
# 注意: 二进制须 Developer ID 签名 + com.apple.developer.endpoint-security.client entitlement
# 才能点亮 ES; 未签名运行时守护自行优雅退出(exit 2), 终端回退 chmod exec-deny。
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="$ROOT/client/es-guard/AegisExecGuard.swift"
OUT="$ROOT/native-dist"
command -v swiftc >/dev/null 2>&1 || { echo "  · 跳过 ES guard(无 swiftc)"; exit 0; }
[ -f "$SRC" ] || { echo "  · 跳过 ES guard(缺源码)"; exit 0; }
mkdir -p "$OUT"
for ARCH in arm64 x86_64; do
  case "$ARCH" in
    arm64)  SUFFIX=arm64; TRIPLE=arm64-apple-macos12 ;;
    x86_64) SUFFIX=x64;   TRIPLE=x86_64-apple-macos12 ;;
  esac
  swiftc -O -target "$TRIPLE" -lEndpointSecurity -o "$OUT/aegis-exec-guard-darwin-$SUFFIX" "$SRC" 2>/dev/null \
    || { echo "  · 跳过 ES guard($ARCH 编译失败, 可能缺 EndpointSecurity SDK)"; continue; }
  xattr -cr "$OUT/aegis-exec-guard-darwin-$SUFFIX" 2>/dev/null || true  # 去 quarantine/provenance, 免 pkg 混入 ._ AppleDouble
  echo "  ✓ aegis-exec-guard-darwin-$SUFFIX ($(wc -c < "$OUT/aegis-exec-guard-darwin-$SUFFIX" | tr -d ' ') B)"
done
exit 0
