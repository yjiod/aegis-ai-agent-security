#!/bin/bash
# aegis-install-macos-oneclick.sh — macOS 一键安装/修复 Aegis Agent
# 用法:  curl -fsSL https://<控制台>/downloads/aegis-install-macos-oneclick.sh | bash
#   或:  bash aegis-install-macos-oneclick.sh [-Server https://<控制台>] [-PkgUrl <url>] [-PkgPath <pkg>]
# 流程: 提权 → 清理旧域(系统域+用户域 LaunchD, 防"双域新旧并存") → 下载 pkg →
#       写 /Library/Preferences/aegis-server.json(占位包也能入网) → installer →
#       kickstart 立即跑一个周期 → 验收(服务状态/upload-status/版本)
set -eu
SERVER="https://aegis.example.com"
PKG_URL=""
PKG_PATH=""
while [ $# -gt 0 ]; do
  case "$1" in
    -Server) SERVER="$2"; shift 2;;
    -PkgUrl) PKG_URL="$2"; shift 2;;
    -PkgPath) PKG_PATH="$2"; shift 2;;
    *) shift;;
  esac
done
SERVER="${SERVER%/}"
# 隐私红线: 仓库/GitHub 副本恒为 RFC2606 占位域且拒绝运行; 真实 origin 由 -Server 传入,
# 或使用你控制台 /downloads/ 下的定制副本(部署时注入真实 origin)。
if [ "$SERVER" = "https://aegis.example.com" ]; then
  echo "[aegis] 请用 -Server https://<你的控制台> 运行; 或直接下载你控制台 /downloads/ 下的定制副本(已注入真实 origin)。" >&2
  exit 2
fi
[ -n "$PKG_URL" ] || PKG_URL="$SERVER/downloads/aegis-agent-macos.pkg"

# 0) 提权(非 root 自动 sudo 重跑)
if [ "$(id -u)" != "0" ]; then
  echo "[aegis] 需要 root, 以 sudo 重跑…"
  exec sudo -E bash "$0" -Server "$SERVER" -PkgUrl "$PKG_URL" -PkgPath "$PKG_PATH"
fi
log(){ echo "[aegis] $*"; }

# 1) 清理旧域: 系统域 + 当前控制台用户域, 防"同 label 双域、新旧并存"(踩过: bootout 错域停掉新版)
CONSOLE_USER="$(stat -f %Su /dev/console 2>/dev/null || echo "$USER")"
CONSOLE_UID="$(id -u "$CONSOLE_USER" 2>/dev/null || echo "")"
for dom in "system" "gui/$CONSOLE_UID"; do
  if launchctl print "$dom/com.aegis.agent" >/dev/null 2>&1; then
    log "bootout 旧任务: $dom/com.aegis.agent"
    launchctl bootout "$dom/com.aegis.agent" 2>/dev/null || true
  fi
done
SYSP="/Library/LaunchDaemons/com.aegis.agent.plist"
if [ -f "$SYSP" ]; then mv -f "$SYSP" "$SYSP.disabled-oneclick" && log "已停用系统域旧 plist"; fi
if [ -n "$CONSOLE_UID" ]; then
  UPL="/Users/$CONSOLE_USER/Library/LaunchAgents/com.aegis.agent.plist"
  if [ -f "$UPL" ]; then mv -f "$UPL" "$UPL.disabled-oneclick" && log "已停用用户域旧 plist"; fi
fi

# 2) 下载 pkg (占位包/真实包皆可; 真实包已烘控制台)
PKG="/tmp/aegis-agent-macos.pkg"
if [ -n "$PKG_PATH" ]; then PKG="$PKG_PATH"; log "使用本地 pkg: $PKG";
else log "下载 $PKG_URL"; curl -fsSL -o "$PKG" "$PKG_URL"; fi

# 3) 写服务器覆盖文件(占位包靠它入网; 真实包也会被读取, 一致即可)
mkdir -p /Library/Preferences
printf '{"schema":"aegis.server/v1","server_url":"%s"}\n' "$SERVER" > /Library/Preferences/aegis-server.json
chmod 644 /Library/Preferences/aegis-server.json
log "已写 /Library/Preferences/aegis-server.json -> $SERVER"

# 4) 安装
log "installer -pkg …"
installer -pkg "$PKG" -target /

# 5) 立即跑一个周期(否则等下一个 interval)
launchctl kickstart -k system/com.aegis.agent 2>/dev/null || log "kickstart 失败(服务可能未加载), 稍等或重启"
log "等待首报(~60s)…"
sleep 60

# 6) 验收
D="/Library/Application Support/AegisAgent"
if launchctl print system/com.aegis.agent >/dev/null 2>&1; then
  log "服务: $(launchctl print system/com.aegis.agent 2>/dev/null | awk '/^\tstate/{print $3}')"
else
  log "系统域服务未加载: 检查 installer 输出或重跑本脚本"
fi
if [ -f "$D/upload-status.json" ]; then log "upload-status: $(cat "$D/upload-status.json")";
else log "upload-status 尚未生成(首报需一个周期, 或配置不可读)"; fi
if [ -f "$D/last-report.json" ]; then
  log "last-report: $(python3 -c "import json;d=json.load(open('$D/last-report.json'));print(d.get('agent_version'), d.get('serial'), d.get('os_user'))" 2>/dev/null || echo '解析失败')"
fi
log "完成。刷新控制台应出现/更新该设备(序列号 + 版本 + 工具列)。"
