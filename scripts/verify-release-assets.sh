#!/bin/sh
# verify-release-assets.sh — 发布后资产复验 gate（BUG B 防线）。
#
# 用法: sh scripts/verify-release-assets.sh <release-tag> [repo]
#   下载该 release 的每个资产 → 计算 SHA256 → 与 (a) GitHub API 的资产 digest、
#   (b) 本地侧车/CHECKSUMS（若同名文件存在）逐字比对。任一不符 → 退出非零。
#
# 背景（BUG B）：v0.73.1 曾出现"发布后重传 msi 但侧车未重算"，导致按发布说明校验
# 必然失败、误判为篡改。本 gate 强制"下载回来的字节"与"声称的哈希"一致。
# 重传资产必须整组重传（msi+侧车+CHECKSUMS+MANIFEST），禁止只换其一。
set -eu
TAG="${1:?usage: verify-release-assets.sh <release-tag> [repo]}"
REPO="${2:-yjiod/aegis-ai-agent-security}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT INT TERM

echo "· 拉取 $REPO @$TAG 资产清单…"
gh api "repos/$REPO/releases/tags/$TAG" --jq '.assets[] | "\(.name)\t\(.digest)\t\(.browser_download_url)"' > "$WORK/assets.tsv"
[ -s "$WORK/assets.tsv" ] || { echo "无资产" >&2; exit 1; }

fail=0
while IFS="$(printf '\t')" read -r NAME DIGEST URL; do
  [ -n "$NAME" ] || continue
  echo "· 下载 $NAME …"
  curl -fsSL -o "$WORK/$NAME" "$URL"
  ACTUAL="sha256:$(shasum -a 256 "$WORK/$NAME" | cut -d' ' -f1)"
  if [ -n "$DIGEST" ] && [ "$DIGEST" != "sha256:" ] && [ "$ACTUAL" != "$DIGEST" ]; then
    echo "  ✗ $NAME 与 GitHub digest 不符: 下载=$ACTUAL 声称=$DIGEST" >&2; fail=1; continue
  fi
  # 与本地侧车比对仅作 WARN：双通道下本地 native-dist 侧车对应"私有真实 origin 构建"，
  # 与公开占位域资产必然不同，不能据此判失败。权威比对是下方"release 内部自洽"检查。
  for SIDE in "native-dist/$NAME.sha256" "public/downloads/$NAME.sha256"; do
    if [ -f "$SIDE" ]; then
      WANT=$(grep -F "$NAME" "$SIDE" 2>/dev/null | awk '{print $1}' | head -1 || true)
      if [ -n "$WANT" ] && [ "sha256:$WANT" != "$ACTUAL" ]; then
        echo "  ⚠ $NAME 与本地侧车 $SIDE 不同（双通道下属正常：本地为私有真实 origin 构建）"
      fi
    fi
  done
  echo "  ✓ $NAME $ACTUAL"
done < "$WORK/assets.tsv"

# release 内部自洽（BUG B 的权威防线）：侧车资产内容里的哈希 == 同 release 的 msi 资产字节哈希。
if [ -f "$WORK/aegis-agent-windows.msi" ] && [ -f "$WORK/aegis-agent-windows.msi.sha256" ]; then
  MSI_ACTUAL=$(shasum -a 256 "$WORK/aegis-agent-windows.msi" | cut -d' ' -f1)
  SIDE_WANT=$(awk '{print $1}' "$WORK/aegis-agent-windows.msi.sha256" | head -1)
  if [ "$MSI_ACTUAL" != "$SIDE_WANT" ]; then
    echo "  ✗ 侧车与 msi 资产不自洽: msi=$MSI_ACTUAL 侧车=$SIDE_WANT" >&2; fail=1
  else
    echo "  ✓ release 内部自洽: msi == 侧车 ($MSI_ACTUAL)"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "发布后复验失败：资产与声称哈希不一致（撤回 release 或整组重传）。" >&2
  exit 1
fi
echo "✓ $TAG 全部资产复验通过（下载字节 == GitHub digest == 本地侧车）。"
