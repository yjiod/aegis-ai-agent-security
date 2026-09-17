#!/bin/sh
# ═══════════════════════════════════════════════════════════════════
# fetch-agent-binaries.sh — 从 build-agent-binaries CI 的成功 run 下载双架构冻结二进制到
# public/downloads/（去-python 化 B）。二进制是 CI 产物、gitignored、不入库；发布/部署前拉取，
# 供 build-macos-standalone.sh / build-macos-pkg.sh 嵌入 .run/.pkg，且 aegis_release_build.py
# 会把它们的 sha256 收录进 update-manifest.json（供冻结 agent 后台热更按 os/arch 取用）。
#
# 用法: sh scripts/fetch-agent-binaries.sh [run_id]
#   不带 run_id 时取 build-agent-binaries.yml 最近一次成功 run。需 gh CLI 已认证到本仓。
# 之后正常跑: python3 public/downloads/aegis_release_build.py public/downloads
#            sh scripts/build-macos-standalone.sh && sh scripts/build-macos-pkg.sh
# ═══════════════════════════════════════════════════════════════════
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DL="$ROOT/public/downloads"
REPO="${AEGIS_REPO:-yjiod/aegis-ai-agent-security}"
WORKFLOW="${AEGIS_BIN_WORKFLOW:-build-agent-binaries.yml}"

command -v gh >/dev/null 2>&1 || { echo "需要 gh CLI（并已认证到 $REPO）" >&2; exit 1; }

RID="${1:-}"
if [ -z "$RID" ]; then
  RID=$(gh run list -R "$REPO" --workflow "$WORKFLOW" --status success --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
fi
[ -n "$RID" ] || { echo "未找到成功的 $WORKFLOW run（先触发它或显式传 run_id）" >&2; exit 1; }
echo "从 $WORKFLOW run $RID 下载冻结二进制…"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT INT TERM
gh run download "$RID" -R "$REPO" -D "$TMP"

for arch in arm64 x64; do
  src=$(find "$TMP" -type f -name "aegis-agent-darwin-$arch" | head -1)
  [ -n "$src" ] || { echo "缺产物 aegis-agent-darwin-$arch（run $RID 未产该架构？）" >&2; exit 1; }
  cp -f "$src" "$DL/aegis-agent-darwin-$arch"
  chmod +x "$DL/aegis-agent-darwin-$arch"
  sz=$(wc -c < "$DL/aegis-agent-darwin-$arch" | tr -d ' ')
  fa=$(file -b "$DL/aegis-agent-darwin-$arch" 2>/dev/null | cut -d, -f1-2)
  echo "  ✓ aegis-agent-darwin-$arch  ${sz}B  [$fa]"
done
echo "二进制就位于 public/downloads/（gitignored）。接着："
echo "  python3 public/downloads/aegis_release_build.py public/downloads   # 收录 sha256 进 manifest"
echo "  sh scripts/build-macos-standalone.sh && sh scripts/build-macos-pkg.sh   # 嵌入 .run/.pkg"
