#!/bin/bash
# apply-mac-lite.sh — 应用 mac 轻量推送包(在终端上以 root 运行): 校验 sha256 → 换脚本+基线 → 重启 launchd。
# 不触碰 reporting.json / aegis-policy.json / 入网凭据。用法: sudo bash apply-mac.sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" = "0" ] || { echo "需 root: sudo bash apply-mac.sh" >&2; exit 2; }
sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; else sha256sum "$1" | cut -d' ' -f1; fi; }
MAN="$HERE/PUSH-MANIFEST.json"
[ -f "$MAN" ] || { echo "缺 PUSH-MANIFEST.json" >&2; exit 3; }
# 校验组件哈希(防推送链篡改/截断)
python3 - "$MAN" "$HERE" <<'PY'
import json,sys,hashlib,os
man=json.load(open(sys.argv[1])); here=sys.argv[2]
bad=[]
for name,want in man["components"].items():
    p=os.path.join(here,name)
    if not os.path.isfile(p): bad.append(name+":missing"); continue
    got=hashlib.sha256(open(p,'rb').read()).hexdigest()
    if got!=want: bad.append(name+":sha")
if bad:
    print("组件校验失败: "+", ".join(bad)); sys.exit(4)
print("组件校验通过:", ", ".join(man["components"].keys()))
PY
# 定位安装目录(系统域优先, 回退当前控制台用户域)
CU=$(stat -f %Su /dev/console 2>/dev/null || echo "$USER")
for D in "/Library/Application Support/AegisAgent" "/Users/$CU/Library/Application Support/AegisAgent"; do
  if [ -d "$D" ]; then INSTALL_DIR="$D"; break; fi
done
[ -n "${INSTALL_DIR:-}" ] || { echo "未找到安装目录(先装一次完整包)" >&2; exit 5; }
for f in aegis_agent.py aegis_self_update.py aegis-security-baseline.md; do
  [ -f "$HERE/$f" ] && cp -f "$HERE/$f" "$INSTALL_DIR/$f" && chmod 600 "$INSTALL_DIR/$f"
done
chmod 700 "$INSTALL_DIR/aegis_agent.py"
# 重启 launchd(系统域+用户域都试), 让新脚本下个周期生效
for dom in "system" "gui/$(id -u "$CU")"; do
  if launchctl print "$dom/com.aegis.agent" >/dev/null 2>&1; then launchctl kickstart -k "$dom/com.aegis.agent" 2>/dev/null || true; fi
done
echo "已应用轻量包到 $INSTALL_DIR 并 kickstart; 版本见 PUSH-MANIFEST.json"
