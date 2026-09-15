#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# rotate-collector-token.sh — 在服务器本地零停机轮转 AEGIS_COLLECTOR_TOKEN。
#
# 全局 Collector 令牌被三处消费：Collector 读取鉴权 authorized()、未配置
# AEGIS_DEVICE_CREDENTIALS_FILE 时终端上报回退到它、控制台读取 Collector。
# 令牌驻留四处，必须一致更新：
#   /etc/aegis/collector.env                 (Collector EnvironmentFile)
#   /etc/aegis/console.env                   (部署时合并进 wrangler vars 的源)
#   /opt/aegis/console-server/wrangler.json  (workerd 运行时真正读取的 vars)
#   /etc/systemd/system/aegis-console.service(硬编码 Environment=，防漂移)
#
# 零停机三段式（每步可回滚，任一时刻控制台都能读到 Collector）：
#   A. Collector 同时接受 [旧,新]（AEGIS_COLLECTOR_TOKENS 是 JSON 数组，设置即覆盖单数）。
#   B. 控制台切到新令牌（console.env + wrangler vars + unit Environment=）。
#   C. Collector 只保留新令牌 → 泄露的旧令牌立即 401 作废。
#
# 断点续跑：若 collector.env 已存在 AEGIS_COLLECTOR_TOKENS（上次 A 段已完成），
#           自动进入 CONTINUE 模式，从中恢复新/旧令牌，跳过 A 段直接做 B、C。
#
# 校验用"已认证"探针：/api/summary 受中间件保护，未登录会 307 到 /login，
#   因此脚本先用 console.env 里的账号密码在服务器本地 POST /api/auth/login 拿会话
#   Cookie，再带 Cookie GET /api/summary 读 connected。凭据与令牌明文全程不打印，
#   仅输出 sha256 指纹前 12 位供人工核对。新令牌存 /etc/aegis/.collector-token-current(600)。
#
# 用法（服务器上以 root 运行）：bash rotate-collector-token.sh
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

COLLECTOR_ENV=/etc/aegis/collector.env
CONSOLE_ENV=/etc/aegis/console.env
WRANGLER=/opt/aegis/console-server/wrangler.json
CONSOLE_UNIT=/etc/systemd/system/aegis-console.service
TOKEN_STASH=/etc/aegis/.collector-token-current
COLLECTOR_URL=http://127.0.0.1:8931
CONSOLE_URL=http://127.0.0.1:8787
TS=$(date +%Y-%m-%d_%H%M%S)

fp(){ printf '%s' "$1" | sha256sum | cut -c1-12; }
get_env(){ grep -E "^$2=" "$1" | head -1 | cut -d= -f2-; }
set_env(){ python3 - "$1" "$2" "$3" <<'PY'
import sys
f,k,v=sys.argv[1],sys.argv[2],sys.argv[3]
lines=open(f).read().splitlines();out=[];done=False
for ln in lines:
    if ln.startswith(k+"="): out.append(k+"="+v);done=True
    else: out.append(ln)
if not done: out.append(k+"="+v)
open(f,"w").write("\n".join(out)+"\n")
PY
}
unset_env(){ python3 - "$1" "$2" <<'PY'
import sys
f,k=sys.argv[1],sys.argv[2]
lines=[ln for ln in open(f).read().splitlines() if not ln.startswith(k+"=")]
open(f,"w").write("\n".join(lines)+"\n")
PY
}
collector_status(){ curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Authorization: Bearer $1" "$COLLECTOR_URL/v1/summary" || echo 000; }
console_ready(){ curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$CONSOLE_URL/api/auth/providers" || echo 000; }
# 已认证读取 /api/summary，只回显 connected（不泄露凭据/令牌）。
console_connected(){ python3 - <<'PY'
import json,urllib.request
env={}
for line in open("/etc/aegis/console.env"):
    line=line.strip()
    if not line or line.startswith("#") or "=" not in line: continue
    k,v=line.split("=",1); env[k.strip()]=v.strip()
u=env.get("AEGIS_CONSOLE_USER","admin"); p=env.get("AEGIS_CONSOLE_PASSWORD","")
base="http://127.0.0.1:8787"
try:
    req=urllib.request.Request(base+"/api/auth/login",data=json.dumps({"username":u,"password":p}).encode(),headers={"Content-Type":"application/json"})
    r=urllib.request.urlopen(req,timeout=15); cookie=r.headers.get("Set-Cookie","").split(";")[0]
except Exception as e:
    print("login_error:"+type(e).__name__); raise SystemExit
if not cookie: print("no_cookie"); raise SystemExit
try:
    r2=urllib.request.urlopen(urllib.request.Request(base+"/api/summary",headers={"Cookie":cookie}),timeout=25)
    b=json.load(r2); print(str(b.get("connected")))
except Exception as e:
    print("summary_error:"+type(e).__name__+":"+str(getattr(e,"code","")))
PY
}

echo "═══ 备份 (后缀 .bak.$TS) ═══"
cp -a "$COLLECTOR_ENV" "$COLLECTOR_ENV.bak.$TS"
cp -a "$CONSOLE_ENV"   "$CONSOLE_ENV.bak.$TS"
cp -a "$WRANGLER"      "$WRANGLER.bak.$TS"
cp -a "$CONSOLE_UNIT"  "$CONSOLE_UNIT.bak.$TS"
echo "  ✓ 4 个文件已备份"

if get_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKENS >/dev/null 2>&1 && [ -n "$(get_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKENS)" ]; then
  MODE=CONTINUE
  NEW=$(get_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKEN)
  OLD=$(python3 - "$COLLECTOR_ENV" "$NEW" <<'PY'
import json,sys
raw=[ln for ln in open(sys.argv[1]) if ln.startswith("AEGIS_COLLECTOR_TOKENS=")]
vals=json.loads(raw[0].split("=",1)[1].strip()) if raw else []
print(next((v for v in vals if v!=sys.argv[2]), ""))
PY
)
  echo "  CONTINUE 模式：检测到过渡态 [旧,新] 已生效，恢复令牌继续 B、C 段"
else
  MODE=FRESH
  OLD=$(get_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKEN)
  NEW=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
fi
[ -n "$OLD" ] && [ -n "$NEW" ] && [ "$OLD" != "$NEW" ] || { echo "FATAL: 无法确定新旧令牌"; exit 1; }
echo "  OLD fp=$(fp "$OLD")   NEW fp=$(fp "$NEW")"

if [ "$MODE" = FRESH ]; then
  echo "═══ STAGE A — Collector 同时接受 [旧,新] ═══"
  PLURAL=$(python3 - "$OLD" "$NEW" <<'PY'
import json,sys;print(json.dumps([sys.argv[1],sys.argv[2]]))
PY
)
  set_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKEN "$NEW"
  set_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKENS "$PLURAL"
  systemctl restart aegis-collector; sleep 3
  s_new=$(collector_status "$NEW"); s_old=$(collector_status "$OLD")
  echo "  collector: NEW->$s_new OLD->$s_old (期望 200/200)"
  if [ "$s_new" != 200 ] || [ "$s_old" != 200 ]; then
    echo "  ✗ 回滚 STAGE A"; cp -a "$COLLECTOR_ENV.bak.$TS" "$COLLECTOR_ENV"; systemctl restart aegis-collector; exit 2
  fi
  echo "  ✓ 双令牌过渡生效，无读取中断"
else
  s_new=$(collector_status "$NEW"); s_old=$(collector_status "$OLD")
  echo "═══ 续跑校验 STAGE A 状态 ═══"
  echo "  collector: NEW->$s_new OLD->$s_old (期望 200/200)"
  [ "$s_new" = 200 ] && [ "$s_old" = 200 ] || { echo "  ✗ 过渡态异常，回滚到备份"; cp -a "$COLLECTOR_ENV.bak.$TS" "$COLLECTOR_ENV"; systemctl restart aegis-collector; exit 2; }
fi

echo "═══ STAGE B — 控制台切到新令牌 ═══"
set_env "$CONSOLE_ENV" AEGIS_COLLECTOR_TOKEN "$NEW"
python3 - <<'PY'
import json
p="/opt/aegis/console-server/wrangler.json"
cfg=json.load(open(p)); merged=dict(cfg.get("vars",{}))
for line in open("/etc/aegis/console.env"):
    line=line.strip()
    if not line or line.startswith("#") or "=" not in line: continue
    k,v=line.split("=",1); merged[k.strip()]=v.strip()
cfg["vars"]=merged; json.dump(cfg,open(p,"w"),indent=2)
print("  ✓ wrangler vars 合并:",len(merged),"keys (含 UAC/PG/admin，未丢配置)")
PY
# wrangler.json vars 内含全部控制台密钥，强制 600（workerd 以 root 运行，不影响读取）。
chmod 600 "$WRANGLER"
# 令牌已由 wrangler.json vars(600) 提供给 workerd；world-readable(644) 的 unit 文件里
# 不再驻留任何密钥——移除冗余的 Environment=AEGIS_COLLECTOR_TOKEN（若存在）。
python3 - <<'PY'
import re
p="/etc/systemd/system/aegis-console.service"
s=open(p).read()
s2=re.sub(r'(?m)^Environment=AEGIS_COLLECTOR_TOKEN=.*\n?','',s)
open(p,"w").write(s2); print("  ✓ unit 内冗余 AEGIS_COLLECTOR_TOKEN 已移除:", s!=s2)
PY
systemctl daemon-reload; systemctl restart aegis-console
echo -n "  等待控制台就绪"; ready=000
for i in $(seq 1 60); do ready=$(console_ready); [ "$ready" = 200 ] && { echo " (第 ${i}s 就绪)"; break; }; echo -n "."; sleep 1; done
cc=$(console_connected)
echo "  console /api/summary(已认证) connected=$cc (期望 True)"
if [ "$cc" != "True" ]; then
  echo "  ✗ 回滚 STAGE B（Collector 仍接受旧+新，控制台回退旧令牌即恢复）"
  cp -a "$CONSOLE_ENV.bak.$TS" "$CONSOLE_ENV"; cp -a "$WRANGLER.bak.$TS" "$WRANGLER"; cp -a "$CONSOLE_UNIT.bak.$TS" "$CONSOLE_UNIT"
  systemctl daemon-reload; systemctl restart aegis-console; exit 3
fi
echo "  ✓ 控制台已用新令牌读取成功"

echo "═══ STAGE C — Collector 只保留新令牌（旧令牌作废） ═══"
unset_env "$COLLECTOR_ENV" AEGIS_COLLECTOR_TOKENS
systemctl restart aegis-collector; sleep 3
s_new=$(collector_status "$NEW"); s_old=$(collector_status "$OLD")
echo "  collector: NEW->$s_new OLD->$s_old (期望 200/401)"
if [ "$s_new" != 200 ]; then echo "  ✗ 回滚 STAGE C"; cp -a "$COLLECTOR_ENV.bak.$TS" "$COLLECTOR_ENV"; systemctl restart aegis-collector; exit 4; fi
if [ "$s_old" = 200 ]; then echo "  ⚠ 警告：旧令牌仍被接受，请人工检查 collector.env"; else echo "  ✓ 泄露的旧令牌已失效 (OLD->$s_old)"; fi

cc=$(console_connected)
echo "═══ 终检 ═══"
echo "  console connected=$cc (期望 True)"
[ "$cc" = True ] || { echo "  ✗ 终检失败，但 Collector 已只用新令牌；请人工核对控制台"; }
umask 077; printf '%s\n' "$NEW" > "$TOKEN_STASH"
echo "  ✓ 新令牌已存 $TOKEN_STASH (mode 600)，供离线终端重新入网取用"
echo "  NEW fp=$(fp "$NEW")  现为唯一有效令牌"
free -m | head -2
echo "═══ 轮转完成 ═══"
