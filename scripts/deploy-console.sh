#!/bin/sh
# ═══════════════════════════════════════════════════════════
# Aegis Console 部署脚本
#
# 用法: sh scripts/deploy-console.sh [server]
#   server 默认 root@aegis.example.com（占位主机，请换成你的控制台主机）
#   SSH 端口/密钥用环境变量覆盖：AEGIS_SSH_PORT（默认 22）、AEGIS_SSH_KEY（默认 ~/.ssh/id_ed25519）
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

SERVER="${1:-${AEGIS_DEPLOY_SERVER:-root@aegis.example.com}}"
SSH_PORT="${AEGIS_SSH_PORT:-22}"
SSH_KEY="${AEGIS_SSH_KEY:-$HOME/.ssh/id_ed25519}"
# 端口旗标两者不同: ssh 用 -p, scp 用 -P(scp 的 -p 是保留时间戳), 故分开定义。
SSH_OPTS="-i $SSH_KEY -p $SSH_PORT"
SCP_OPTS="-i $SSH_KEY -P $SSH_PORT"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "═══ 构建控制台 ═══"
cd "$ROOT"
# vinext build 不清理 dist/，反复本地构建会累积陈旧的 hash 命名 chunk（旧页面代码，
# 含已删除的伪造数据/已修复的缺陷），并随 scp 一并上传，仍可按直链 URL 访问。
# dist/ 是 .gitignore 的纯构建产物、下一行即刻重新生成，故构建前先清空以保证部署
# 产物与当前源码一一对应（CI 全新 checkout 无此问题，仅本地重复部署需要）。
rm -rf dist
npm run build >/dev/null 2>&1
echo "  ✓ build complete (clean dist)"

echo "═══ 备份当前 wrangler vars (scp 会覆盖 wrangler.json) ═══"
ssh $SSH_OPTS "$SERVER" 'cp -a /opt/aegis/console-server/wrangler.json /tmp/aegis-wrangler-vars.bak 2>/dev/null || printf "{\"vars\":{}}" > /tmp/aegis-wrangler-vars.bak; echo "  ✓ backed up"'

echo "═══ 上传 server + client ═══"
ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/console-server /opt/aegis/client"
scp $SCP_OPTS -r dist/server/* "$SERVER:/opt/aegis/console-server/" >/dev/null
ssh $SSH_OPTS "$SERVER" "rm -rf /opt/aegis/client && mkdir -p /opt/aegis/client"
scp $SCP_OPTS -r dist/client/* "$SERVER:/opt/aegis/client/" >/dev/null
echo "  ✓ uploaded"

# 大体积原生安装包（Windows .msi ~32MB，自包含 .NET 运行时）超过 Cloudflare Workers
# 单资产 25MiB 上限，不能进 dist/client（否则 wrangler 启动失败、控制台 502）。单独上传到
# /opt/aegis/native-dist/，由 nginx 以精确匹配 location 静态直供（见该目录的 README/部署说明）。
if [ -f native-dist/aegis-agent-windows.msi ]; then
  ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/native-dist"
  scp $SCP_OPTS native-dist/aegis-agent-windows.msi "$SERVER:/opt/aegis/native-dist/" >/dev/null
  [ -f native-dist/aegis-agent-windows.msi.sha256 ] && scp $SCP_OPTS native-dist/aegis-agent-windows.msi.sha256 "$SERVER:/opt/aegis/native-dist/" >/dev/null
  echo "  ✓ native .msi uploaded -> /opt/aegis/native-dist/ (nginx 静态直供)"
fi

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
# wrangler.json 的 vars 内含全部控制台密钥（Collector 令牌/会话密钥/UAC/PG URL）。
# scp 默认 644 会让本机任意用户读到密钥，故每次合并后强制收紧为 600（workerd 以
# root 运行，600 不影响读取）。
chmod 600 /opt/aegis/console-server/wrangler.json
echo "  ✓ wrangler.json 权限收紧为 600"
systemctl restart aegis-console
sleep 6
systemctl is-active aegis-console
'
echo "═══ 部署完成 ═══"
echo "  控制台: https://aegis.example.com"
echo "  凭据文件: /etc/aegis/console.env (独立维护, 部署不覆盖)"
