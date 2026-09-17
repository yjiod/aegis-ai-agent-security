#!/bin/bash
# apply-mac.sh — 应用 mac 轻量推送包（在终端上以 root 运行）：校验 sha256 → 换 agent → kickstart launchd。
# 去-python 化 B：**本脚本自身不依赖 python3**（哈希校验用 shasum + BSD sed 解析 manifest），且自动
# 识别安装形态——二进制形态(存在 INSTALL_DIR/aegis-agent)按 uname -m 换冻结二进制；python 形态(老装机)
# 换 aegis_agent.py。不触碰 reporting.json / aegis-policy.json / 入网凭据。用法: sudo bash apply-mac.sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" = "0" ] || { echo "需 root: sudo bash apply-mac.sh" >&2; exit 2; }
sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; else sha256sum "$1" | cut -d' ' -f1; fi; }
MAN="$HERE/PUSH-MANIFEST.json"
[ -f "$MAN" ] || { echo "缺 PUSH-MANIFEST.json" >&2; exit 3; }

# ── 校验组件哈希（纯 shell，不用 python3——本包正是为无 python 的 mac 准备）──
# grep -oE 抽取每个 "name": "<64hex>" 对（manifest 的 components 可能挤在一行，故用 -o 逐个取，
# 不能用按行贪婪 sed，否则一行只取到最后一个）；BSD grep/sed 均支持，mac 自带。
bad=""
while read -r name want; do
  [ -n "$name" ] || continue
  p="$HERE/$name"
  if [ ! -f "$p" ]; then bad="$bad $name:missing"; continue; fi
  got=$(sha "$p")
  [ "$got" = "$want" ] || bad="$bad $name:sha"
done <<EOF
$(grep -oE '"[^"]+"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' "$MAN" | sed -E 's/"([^"]+)"[[:space:]]*:[[:space:]]*"([0-9a-f]{64})"/\1 \2/')
EOF
[ -z "$bad" ] || { echo "组件校验失败:$bad" >&2; exit 4; }
echo "组件校验通过"

# ── 定位安装目录（系统域优先，回退控制台用户域）──
CU=$(stat -f %Su /dev/console 2>/dev/null || echo "${USER:-}")
INSTALL_DIR=""
for D in "/Library/Application Support/AegisAgent" "/Users/$CU/Library/Application Support/AegisAgent"; do
  if [ -n "$CU" ] && [ -d "$D" ]; then INSTALL_DIR="$D"; break; fi
done
[ -n "$INSTALL_DIR" ] || { echo "未找到安装目录（先用 .run/.pkg 装一次）" >&2; exit 5; }
CUUID=$(id -u "$CU" 2>/dev/null || echo "")

# 基线两形态都用，先更新
if [ -f "$HERE/aegis-security-baseline.md" ]; then cp -f "$HERE/aegis-security-baseline.md" "$INSTALL_DIR/aegis-security-baseline.md"; chmod 600 "$INSTALL_DIR/aegis-security-baseline.md"; fi

kick() { for dom in "system" ${CUUID:+gui/$CUUID}; do launchctl print "$dom/com.aegis.agent" >/dev/null 2>&1 && launchctl kickstart -k "$dom/com.aegis.agent" 2>/dev/null || true; done; }

if [ -f "$INSTALL_DIR/aegis-agent" ]; then
  # ── 二进制形态：按架构换 canonical 二进制（staging+mv 覆盖运行中文件安全：旧进程留旧 inode，kickstart 后用新的）──
  ARCH=$(uname -m)
  case "$ARCH" in
    arm64)  SRC="$HERE/aegis-agent-darwin-arm64" ;;
    x86_64) SRC="$HERE/aegis-agent-darwin-x64" ;;
    *)      SRC="" ;;
  esac
  if [ -z "$SRC" ] || [ ! -f "$SRC" ]; then echo "包内无本架构($ARCH)二进制" >&2; exit 6; fi
  cp -f "$SRC" "$INSTALL_DIR/.aegis-agent.staging"
  mv -f "$INSTALL_DIR/.aegis-agent.staging" "$INSTALL_DIR/aegis-agent"
  xattr -d com.apple.quarantine "$INSTALL_DIR/aegis-agent" 2>/dev/null || true
  chmod 755 "$INSTALL_DIR/aegis-agent"
  kick
  echo "已换二进制($ARCH) → $INSTALL_DIR/aegis-agent 并 kickstart；版本见 PUSH-MANIFEST.json"
else
  # ── python 形态（老装机）：换脚本 ──
  for f in aegis_agent.py aegis_self_update.py; do
    if [ -f "$HERE/$f" ]; then cp -f "$HERE/$f" "$INSTALL_DIR/$f"; chmod 600 "$INSTALL_DIR/$f"; fi
  done
  [ -f "$INSTALL_DIR/aegis_agent.py" ] && chmod 700 "$INSTALL_DIR/aegis_agent.py"
  kick
  echo "已换脚本 → $INSTALL_DIR 并 kickstart；版本见 PUSH-MANIFEST.json"
fi
