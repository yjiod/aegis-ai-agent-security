#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-macos-standalone.sh — 把安装器头部 + 内嵌运行时打成单文件 .run。
#
# 产物：public/downloads/aegis-agent-macos-standalone.run
#   = scripts/aegis-agent-macos-standalone.sh（头部，末行 __PAYLOAD__）
#   + tar.gz(aegis_agent.py, aegis-policy.json, aegis-security-baseline.md)
#
# 该 .run 是自包含的"独立的包"：安装时不联网下载运行时，可拷到任意 macOS 机器
# 离线安装，直接对接 Aegis 安全中心（aegis.example.com/aegis），不依赖 MDM/EDR。
# 每次 npm run build 前自动重打（见 package.json 的 build 脚本），保证内嵌运行时
# 与 public/downloads 里的当前版本一致，不会陈旧。产物为构建生成物，已在 .gitignore。
# ═══════════════════════════════════════════════════════════════════════
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HEADER="$ROOT/scripts/aegis-agent-macos-standalone.sh"
DL="$ROOT/public/downloads"
OUT="$DL/aegis-agent-macos-standalone.run"
RUNTIME="aegis_agent.py aegis-policy.json aegis-security-baseline.md"
# 去-python 化 B：CI(build-agent-binaries.yml) 冻结的双架构原生二进制，若已就位于 downloads/ 则一并
# 打进 payload（安装器按 uname -m 选对应架构、exec 二进制，无需系统 python3）；缺则 .run 退回纯 python 形态。
BINS=""
for b in aegis-agent-darwin-arm64 aegis-agent-darwin-x64; do [ -f "$DL/$b" ] && BINS="$BINS $b"; done

[ -f "$HEADER" ] || { echo "缺少安装器头部: $HEADER" >&2; exit 1; }
for f in $RUNTIME; do [ -f "$DL/$f" ] || { echo "缺少运行时文件: $DL/$f" >&2; exit 1; }; done

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT INT TERM
for f in $RUNTIME $BINS; do cp "$DL/$f" "$STAGE/$f"; done
# COPYFILE_DISABLE=1 避免 macOS tar 写入 ._ AppleDouble 资源叉文件，保持包干净。
( cd "$STAGE" && COPYFILE_DISABLE=1 tar czf payload.tar.gz $RUNTIME $BINS )
echo "  嵌入原生二进制:${BINS:- 无（纯 python 形态）}"

# 头部末行必须是 __PAYLOAD__，其后紧跟 tar.gz 字节流（安装器用 tail -n+ 自解压）。
cat "$HEADER" "$STAGE/payload.tar.gz" > "$OUT"
chmod +x "$OUT"

# 自检：标记存在 + 内嵌清单可列出 + 内嵌 agent 与源一致。
# sha256 兼容 macOS(shasum) 与 Linux/sha256sum，从标准输入读取。
sha256_stdin() { if command -v shasum >/dev/null 2>&1; then shasum -a 256; else sha256sum; fi | cut -d' ' -f1; }
# 只用"命中即 exit"的 awk 定位标记——它会停在头部标记行、绝不读取其后的二进制载荷
# （macOS awk 对二进制做 END 全量扫描会触发 multibyte conversion failure）。
PL=$(awk '/^__PAYLOAD__$/{print NR + 1; exit 0;}' "$OUT")
[ -n "$PL" ] || { echo "产物缺少 __PAYLOAD__ 标记" >&2; exit 1; }
LIST=$(tail -n+"$PL" "$OUT" | tar tzf - | sort | tr '\n' ' ')
echo "  payload 内容: $LIST"
EMB=$(tail -n+"$PL" "$OUT" | tar xzf - -O aegis_agent.py | sha256_stdin)
SRC=$(sha256_stdin < "$DL/aegis_agent.py")
[ "$EMB" = "$SRC" ] || { echo "内嵌 agent 与源不一致: $EMB != $SRC" >&2; exit 1; }
echo "  ✓ 内嵌 aegis_agent.py 与源一致 (sha256 $(echo "$SRC" | cut -c1-12)…)"
echo "✓ 已生成 $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
