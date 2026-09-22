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

# 失败前置守卫：缺关键 env 立即退出，绝不进入 build/upload 留下"半部署态"。
# (真事故：AEGIS_PUBLIC_ORIGIN 未设 → set -u 在 client 已原子换、wrangler.json 已被构建产物
#  空 vars 覆盖、但 vars 回注与 restart 尚未执行时才报错 → 控制台载入空配置/卡 activating，
#  需手工从 /tmp/aegis-wrangler-vars.bak 恢复。守卫把这些校验提到任何写操作之前。)
if [ -z "${AEGIS_PUBLIC_ORIGIN:-}" ]; then echo "✗ 缺少 AEGIS_PUBLIC_ORIGIN（oneclick 脚本注入真实 origin 用），拒绝部署" >&2; exit 2; fi
case "$AEGIS_PUBLIC_ORIGIN" in *aegis.example.com*) echo "✗ AEGIS_PUBLIC_ORIGIN 仍为占位域，拒绝部署（应设为真实控制台 origin）" >&2; exit 2;; esac
if [ "$SERVER" = "root@aegis.example.com" ]; then echo "✗ 未指定部署主机（AEGIS_DEPLOY_SERVER 或参数1），拒绝部署" >&2; exit 2; fi
echo "  ✓ 前置守卫通过（origin/host 已设置）"

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
# 双备份: /tmp 供本次合并回注; 带时间戳的持久备份供"上传中断致 wrangler.json 被构建产物
# 覆盖"后恢复(2026-09-18 真事故: scp 中断 → 备份链断裂 → 丢 7 个持久 vars, 靠 09-15 旧备份找回)。
ssh $SSH_OPTS "$SERVER" 'cp -a /opt/aegis/console-server/wrangler.json /tmp/aegis-wrangler-vars.bak 2>/dev/null || printf "{\"vars\":{}}" > /tmp/aegis-wrangler-vars.bak; cp -a /opt/aegis/console-server/wrangler.json /opt/aegis/console-server/wrangler.json.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null; echo "  ✓ backed up (tmp + dated)"'

echo "═══ 上传 server + client ═══"
ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/console-server /opt/aegis/client"
scp $SCP_OPTS -r dist/server/* "$SERVER:/opt/aegis/console-server/" >/dev/null
# client 原子替换: 先传到 .stage 再 mv, 避免 scp 中断留下半残 client 目录把 worker 挂住
# (2026-09-18 真事故: 中断的 rm -rf + scp 使 /opt/aegis/client 半残 → worker 无响应 → 全站 000)。
ssh $SSH_OPTS "$SERVER" "rm -rf /opt/aegis/client.stage" >/dev/null 2>&1
scp $SCP_OPTS -r dist/client "$SERVER:/opt/aegis/client.stage" >/dev/null
ssh $SSH_OPTS "$SERVER" "rm -rf /opt/aegis/client.prev; [ -d /opt/aegis/client ] && mv /opt/aegis/client /opt/aegis/client.prev; mv /opt/aegis/client.stage /opt/aegis/client" >/dev/null
echo "  ✓ uploaded (client atomic swap)"

# 一键脚本隐私双通道: 仓库/GitHub 副本恒为 RFC2606 占位域(且脚本拒绝以占位域运行);
# 服务器 served 副本在此注入真实 origin(私有通道), 用户从自己控制台下载即"一条命令可用",
# 真实域名不入库/不进 GitHub。
for f in aegis-install-windows-oneclick.ps1 aegis-install-macos-oneclick.sh install-aegis-windows.cmd; do
  if [ -f "public/downloads/$f" ]; then
    sed "s|https://aegis.example.com|$AEGIS_PUBLIC_ORIGIN|g" "public/downloads/$f" > "/tmp/$f"
    scp $SCP_OPTS "/tmp/$f" "$SERVER:/opt/aegis/client/downloads/$f" >/dev/null
  fi
done
echo "  ✓ oneclick 脚本服务器副本已注入真实 origin"

# 桌管轻量推送包(native-dist/push/): 上传 + 确保 nginx location 存在(幂等) + reload
if [ -d native-dist/push ]; then
  ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/native-dist/push"
  # 只上传交付物(*.zip + PUSH-INDEX.json); 构建暂存子目录 mac/ win-*/ 不上传(scp 非 -r 会因目录报错中断)
  scp $SCP_OPTS native-dist/push/*.zip native-dist/push/PUSH-INDEX.json "$SERVER:/opt/aegis/native-dist/push/" >/dev/null
  # nginx location 注入是"尽力而为"：探测真实配置文件与锚点，失败只告警不中断部署
  # (set -e 下用 || 兜底，避免锚点措辞与现网不符时整条部署链被拖垮)。
  # 现网约定: 大体积原生文件走 URL 前缀 /downloads/ alias 到磁盘 /opt/aegis/native-dist/,
  # 故推送包 URL = /downloads/push/ (与 .msi/.pkg 同前缀), 磁盘 = /opt/aegis/native-dist/push/。
  ssh $SSH_OPTS "$SERVER" 'python3 - <<PY
import glob
blk = """    location /downloads/push/ {
        alias /opt/aegis/native-dist/push/;
        add_header Cache-Control \"no-store\" always;
    }
"""
cands = glob.glob("/etc/nginx/sites-available/*") + glob.glob("/etc/nginx/conf.d/*") + ["/etc/nginx/nginx.conf"]
path = next((p for p in cands if "native-dist" in open(p, errors="ignore").read()), None)
if not path:
    print("  ! 未找到含 native-dist 的 nginx 配置, 需手工加 /downloads/push/ location"); raise SystemExit(0)
s = open(path).read()
if "/downloads/push/" in s:
    print("  ✓ nginx location /downloads/push/ 已存在 (" + path + ")"); raise SystemExit(0)
lines = s.splitlines(keepends=True)
# 锚点: 任一 /downloads/ 的 location 行(如 location = /downloads/aegis-agent-windows.msi), 插到它前面
idx = next((i for i, l in enumerate(lines) if "location" in l and "/downloads/" in l), None)
if idx is None:
    print("  ! " + path + " 内未找到 /downloads/ location 锚点, 需手工插入 push location"); raise SystemExit(0)
lines.insert(idx, blk)
open(path, "w").write("".join(lines))
print("  ✓ nginx location /downloads/push/ 已插入 " + path)
PY
nginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1 && echo "  ✓ nginx reloaded" || echo "  ! nginx -t/reload 未通过, 已保留配置待人工检查"' || echo "  ! push 包 nginx 配置步骤异常(文件已上传), 需人工确认 location"
  echo "  ✓ lite push packages uploaded -> /opt/aegis/native-dist/push/"
fi


# 大体积原生安装包（Windows .msi ~32MB，自包含 .NET 运行时）超过 Cloudflare Workers
# 单资产 25MiB 上限，不能进 dist/client（否则 wrangler 启动失败、控制台 502）。单独上传到
# /opt/aegis/native-dist/，由 nginx 以精确匹配 location 静态直供（见该目录的 README/部署说明）。
if [ -f native-dist/aegis-agent-windows.msi ]; then
  ssh $SSH_OPTS "$SERVER" "mkdir -p /opt/aegis/native-dist"
  scp $SCP_OPTS native-dist/aegis-agent-windows.msi "$SERVER:/opt/aegis/native-dist/" >/dev/null
  [ -f native-dist/aegis-agent-windows.msi.sha256 ] && scp $SCP_OPTS native-dist/aegis-agent-windows.msi.sha256 "$SERVER:/opt/aegis/native-dist/" >/dev/null
  echo "  ✓ native .msi uploaded -> /opt/aegis/native-dist/ (nginx 静态直供)"
fi

# mac .pkg：worker 已直供 /downloads/aegis-agent-macos.pkg（dist/client 内含当前构建，带二进制）；
# nginx 的 /downloads/aegis-agent-macos-private.pkg（native-dist）同步成同一份当前 pkg，
# 避免 MDM/旧链接走到陈旧的 python-only 副本（去-python 化 B 后两者必须一致）。
ssh $SSH_OPTS "$SERVER" 'mkdir -p /opt/aegis/native-dist; if [ -f /opt/aegis/client/downloads/aegis-agent-macos.pkg ]; then cp -f /opt/aegis/client/downloads/aegis-agent-macos.pkg /opt/aegis/native-dist/aegis-agent-macos-private.pkg && echo "  ✓ private.pkg 同步为当前 .pkg（含冻结二进制）"; fi' || echo "  ! private.pkg 同步跳过"

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
