#!/bin/sh
# ═══════════════════════════════════════════════════════════
# Aegis Console 部署脚本
#
# 用法: sh scripts/deploy-console.sh [server]
#   server 默认 root@tx.yjiod.com (SSH port 1022, key ~/key)
#
# 凭据来源: 服务器 /etc/aegis/console.env (独立文件, 部署不覆盖)
# 本脚本只上传构建产物, 然后从 console.env 重新注入 wrangler vars。
# ═══════════════════════════════════════════════════════════
set -eu

SERVER="${1:-root@tx.yjiod.com}"
SSH_OPTS="-i ~/key -p 1022"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "═══ 构建控制台 ═══"
cd "$ROOT"
npm run build >/dev/null 2>&1
echo "  ✓ build complete"

echo "═══ 上传 server + client ═══"
ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/console-server /opt/aegis/client"
scp $SSH_OPTS -r dist/server/* "$SERVER:/opt/aegis/console-server/" >/dev/null 2>&1
ssh $SSH_OPTS "$SERVER" "rm -rf /opt/aegis/client && mkdir -p /opt/aegis/client"
scp $SSH_OPTS -r dist/client/* "$SERVER:/opt/aegis/client/" >/dev/null 2>&1
echo "  ✓ uploaded"

echo "═══ 从 /etc/aegis/console.env 注入 vars 并重启 ═══"
ssh $SSH_OPTS "$SERVER" '
set -e
# Read secrets from independent file (never overwritten by scp)
. /etc/aegis/console.env
cd /opt/aegis/console-server
python3 - "$AEGIS_CONSOLE_USER" "$AEGIS_CONSOLE_PASSWORD" "$AEGIS_SESSION_SECRET" "$AEGIS_COLLECTOR_URL" "$AEGIS_COLLECTOR_ALLOWED_HOST" "$AEGIS_COLLECTOR_TOKEN" << PYEOF
import json, sys
user, password, secret, curl, chost, ctoken = sys.argv[1:7]
cfg = json.load(open("wrangler.json"))
cfg["vars"] = {
    "AEGIS_CONSOLE_USER": user,
    "AEGIS_CONSOLE_PASSWORD": password,
    "AEGIS_SESSION_SECRET": secret,
    "AEGIS_COLLECTOR_URL": curl,
    "AEGIS_COLLECTOR_ALLOWED_HOST": chost,
    "AEGIS_COLLECTOR_TOKEN": ctoken,
}
json.dump(cfg, open("wrangler.json", "w"), indent=2)
print("  ✓ vars injected from /etc/aegis/console.env")
PYEOF
systemctl restart aegis-console
sleep 5
systemctl is-active aegis-console
'
echo "═══ 部署完成 ═══"
echo "  控制台: https://tx.yjiod.com"
echo "  凭据文件: /etc/aegis/console.env (独立维护, 部署不覆盖)"
