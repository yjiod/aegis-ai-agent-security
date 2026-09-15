#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# run-e2e.sh — 一键拉起控制台 dev server 并跑 Playwright e2e。
#
# 为什么需要它：vite.config.ts 的 devVars 只从 **进程环境** 收集 AEGIS_* 注入 workerd，
# 不读 .env.local；而 e2e 需要一组确定的本地凭据（管理员/审计员/会话密钥/签名密钥环）
# 才能走完登录→发布→读取闭环。本脚本把这些一次性备齐，避免手工 export 漂移。
#
# 两种模式：
#   demo（默认）  不启动 Collector，并临时移开 .env.local 里的 Collector 配置，
#                 确保 /api/summary 走 connected:false 的"演示模式"。console.spec 的
#                 演示态 UI 断言（.demo-notice / 风险事件样例 / 演示模式 toast）据此成立。
#   --live        启动真实 Collector 并播种 demo 终端，导出 Collector 连接环境变量，
#                 用于验证 version-posture 单一可信源的重算分支（连接态）。
#
# 全部凭据仅为本地测试值，非生产、不含任何真实密钥。
#
# 用法：
#   scripts/run-e2e.sh                        # demo 模式，跑全部 e2e
#   scripts/run-e2e.sh --live e2e/policy.spec.ts   # live 模式，只跑指定文件
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

DEV_LOG=/tmp/aegis-e2e-dev.log
COL_LOG=/tmp/aegis-e2e-collector.log
ENV_LOCAL_BAK="$ROOT/.env.local.e2e-bak"

MODE=demo
if [ "${1:-}" = "--live" ]; then MODE=live; shift; fi

# ── 本地测试凭据（可被外部环境覆盖）──────────────────────────────────
export AEGIS_CONSOLE_USER="${E2E_ADMIN_USER:-e2eadmin}"
export AEGIS_CONSOLE_PASSWORD="${E2E_ADMIN_PASSWORD:-E2e-Pass-123}"
export AEGIS_SESSION_SECRET="${AEGIS_SESSION_SECRET:-e2e-secret-0123456789}"
export AEGIS_ADMIN_USERS="${AEGIS_ADMIN_USERS:-e2eadmin}"
export AEGIS_AUDITOR_USERS="${AEGIS_AUDITOR_USERS:-e2eauditor}"
export AEGIS_POLICY_SIGNING_KEYS="${AEGIS_POLICY_SIGNING_KEYS:-{\"k1\":\"e2e-signing-key-1-0123456789abcdef\",\"k2\":\"e2e-signing-key-2-0123456789abcdef\"}}"
export AEGIS_POLICY_ACTIVE_KEY_ID="${AEGIS_POLICY_ACTIVE_KEY_ID:-k1}"
# vinext/Vite 默认把 localhost 解析到 IPv6 ::1，探针走 IPv4 127.0.0.1 会连不上。
export NODE_OPTIONS="--dns-result-order=ipv4first"

cleanup(){
  kill "${DEV_PID:-}" 2>/dev/null || true
  if [ "$MODE" = live ]; then ./scripts/dev-collector.sh --stop >/dev/null 2>&1 || true; fi
  # demo 模式：还原被临时移开的 .env.local
  if [ -f "$ENV_LOCAL_BAK" ]; then mv -f "$ENV_LOCAL_BAK" "$ROOT/.env.local" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [ "$MODE" = live ]; then
  echo "═══ [live] 1. 启动 Collector 并播种 demo 终端 ═══"
  ./scripts/dev-collector.sh >"$COL_LOG" 2>&1
  # dev-collector 把生成的令牌写进 .dev/collector.env；导出到进程环境供 devVars 注入。
  set -a; . ./.dev/collector.env; set +a
  export AEGIS_COLLECTOR_URL="http://127.0.0.1:8931"
  export AEGIS_COLLECTOR_ALLOWED_HOST="127.0.0.1"
  curl -fsS http://127.0.0.1:8931/health >/dev/null && echo "  ✓ collector 健康"
else
  echo "═══ [demo] 1. 确保无 Collector（演示模式）═══"
  ./scripts/dev-collector.sh --stop >/dev/null 2>&1 || true
  # 移开 .env.local 里可能残留的 Collector 配置，避免 dev server 误连。
  if [ -f "$ROOT/.env.local" ]; then mv -f "$ROOT/.env.local" "$ENV_LOCAL_BAK"; echo "  ✓ 已临时移开 .env.local（退出时还原）"; fi
  unset AEGIS_COLLECTOR_URL AEGIS_COLLECTOR_ALLOWED_HOST AEGIS_COLLECTOR_TOKEN || true
fi

echo "═══ 2. 启动控制台 dev server（后台）═══"
nohup npm run dev >"$DEV_LOG" 2>&1 &
DEV_PID=$!

ready=""
for i in $(seq 1 90); do
  if curl -fsS -o /dev/null http://127.0.0.1:3000/ 2>/dev/null; then ready="yes"; echo "  ✓ dev server 就绪（第 $((i*2))s）"; break; fi
  sleep 2
done
[ -n "$ready" ] || { echo "  ✗ dev server 180s 内未就绪，最后 60 行日志："; tail -n 60 "$DEV_LOG"; exit 1; }

echo "═══ 3. 校验已认证 /api/summary 连通态（mode=${MODE}）═══"
python3 - "$MODE" <<'PY'
import json,urllib.request,urllib.error,os,sys
mode=sys.argv[1]; base="http://127.0.0.1:3000"
u=os.environ["AEGIS_CONSOLE_USER"]; p=os.environ["AEGIS_CONSOLE_PASSWORD"]
r=urllib.request.urlopen(urllib.request.Request(base+"/api/auth/login",data=json.dumps({"username":u,"password":p}).encode(),headers={"Content-Type":"application/json"}),timeout=20)
cookie=r.headers.get("Set-Cookie","").split(";")[0]
# demo 模式 /api/summary 返回 503(collector_not_configured)，urlopen 会抛 HTTPError；
# 但响应体仍是 JSON，必须读出来判断 connected，不能让它中断脚本。
req=urllib.request.Request(base+"/api/summary",headers={"Cookie":cookie})
try:
    resp=urllib.request.urlopen(req,timeout=25); body=json.load(resp)
except urllib.error.HTTPError as e:
    body=json.loads(e.read().decode())
print("  connected =",body.get("connected"),"error =",body.get("error"))
if mode=="live":
    assert body.get("connected") is True, "live 模式要求 collector 连通，否则重算分支测不到"
else:
    assert body.get("connected") is not True, "demo 模式不应连通 collector"
PY

echo "═══ 4. 运行 Playwright e2e（mode=${MODE}）═══"
npx playwright test "$@"
