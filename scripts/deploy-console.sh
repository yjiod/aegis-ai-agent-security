#!/bin/sh
# ═══════════════════════════════════════════════════════════
# Aegis Console 部署脚本
#
# 用法: sh scripts/deploy-console.sh [server]
#   server 默认 root@tx.yjiod.com (SSH port 1022, key ~/key)
#
# 凭据来源: 服务器 /etc/aegis/console.env (独立文件, 部署不覆盖)
#
# 重要: scp dist/server/* 会用构建产物里的空 vars 覆盖 wrangler.json。
# 旧版脚本只回注 6 个 var, 会丢掉 UAC / admin 白名单 / OIDC / AEGIS_PG_URL
# 等其余 var, 导致 SSO 登录、管理员准入、PG 持久化全部失效。
# 本版改为: 上传前备份当前 wrangler.json 的全部 vars, 上传后用
# "备份 vars + console.env 全量覆盖" 合并回注, 永不丢配置。
# ═══════════════════════════════════════════════════════════
set -eu

SERVER="${1:-root@tx.yjiod.com}"
# NOTE: 必须用 $HOME/key(赋值时展开)。写 "~/key" 不会做 tilde 展开,
# ssh/scp 会收到字面 "~/key" 导致认证失败, set -e 下脚本中途 abort。
# 端口旗标两者不同: ssh 用 -p, scp 用 -P(scp 的 -p 是保留时间戳),
# 故分开定义, 否则 scp 会把 "1022" 当成源文件报错。
SSH_OPTS="-i $HOME/key -p 1022"
SCP_OPTS="-i $HOME/key -P 1022"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "═══ 构建控制台 ═══"
cd "$ROOT"
npm run build >/dev/null 2>&1
echo "  ✓ build complete"

echo "═══ 备份当前 wrangler vars (scp 会覆盖 wrangler.json) ═══"
ssh $SSH_OPTS "$SERVER" 'cp -a /opt/aegis/console-server/wrangler.json /tmp/aegis-wrangler-vars.bak 2>/dev/null || printf "{\"vars\":{}}" > /tmp/aegis-wrangler-vars.bak; echo "  ✓ backed up"'

echo "═══ 上传 server + client ═══"
ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/console-server /opt/aegis/client"
scp $SCP_OPTS -r dist/server/* "$SERVER:/opt/aegis/console-server/" >/dev/null
ssh $SSH_OPTS "$SERVER" "rm -rf /opt/aegis/client && mkdir -p /opt/aegis/client"
scp $SCP_OPTS -r dist/client/* "$SERVER:/opt/aegis/client/" >/dev/null
echo "  ✓ uploaded"

echo "═══ 合并 vars (备份 + /etc/aegis/console.env 全量) 并重启 ═══"
ssh $SSH_OPTS "$SERVER" '
set -e
python3 - <<PYEOF
import json
try:
    bak = json.load(open("/tmp/aegis-wrangler-vars.bak"))
except Exception:
    bak = {}
merged = dict(bak.get("vars", {}))
for line in open("/etc/aegis/console.env"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    merged[k.strip()] = v.strip()
cfg = json.load(open("/opt/aegis/console-server/wrangler.json"))
cfg["vars"] = merged
json.dump(cfg, open("/opt/aegis/console-server/wrangler.json", "w"), indent=2)
print("  ✓ vars merged:", len(merged), "keys (backup base + console.env overlay)")
print("  ✓ AEGIS_PG_URL present:", "AEGIS_PG_URL" in merged)
PYEOF
systemctl restart aegis-console
sleep 6
systemctl is-active aegis-console
'
echo "═══ 部署完成 ═══"
echo "  控制台: https://tx.yjiod.com"
echo "  凭据文件: /etc/aegis/console.env (独立维护, 部署不覆盖)"
