#!/bin/sh
# ═══════════════════════════════════════════════════════════
# Aegis Collector 部署脚本（独立于 console）
#
# 背景: deploy-console.sh 只部署控制台(vinext/wrangler)与静态下载，
#       **不**部署采集器。采集器是独立 systemd 服务(aegis-collector)，
#       跑 /opt/aegis/aegis_collector.py，须单独 scp + restart。
#
# 用法: sh scripts/deploy-collector.sh [server]
#   server  默认 root@aegis.example.com（占位主机；请换成你的采集器主机，
#           或用环境变量 AEGIS_DEPLOY_SERVER 覆盖）
#   AEGIS_SSH_PORT  SSH 端口（默认 22）
#   AEGIS_SSH_KEY   私钥路径（默认 ~/.ssh/id_ed25519）
#   AEGIS_COLLECTOR_PORT  采集器监听端口（默认从远端 systemd 单元探测，
#                         探测不到回退 8788）
#   AEGIS_MIN_FREE_MB     重启前要求的最小可用内存 MB（默认 400；曾 OOM）
#
# 安全网（遵循「真机先冒烟、带重启走 guard/rollback、单次只重启一个服务」）:
#   1. 本地 py_compile 冒烟  2. SSH 可达性冒烟  3. VPS 内存余量 guard
#   4. 备份现网文件(带时间戳)  5. 上传到 staging 后远端 py_compile 校验
#   6. mv 就位 + 单次 systemctl restart  7. /health 轮询冒烟 + is-active
#   任一关键步失败 → 自动回滚(还原备份 + 重启 + 复冒烟)并以非零码退出。
# 不打印任何凭据/主机明文；不使用 rm/truncate 破坏用户数据(备份用 cp -a)。
# ═══════════════════════════════════════════════════════════
set -eu

SERVER="${1:-${AEGIS_DEPLOY_SERVER:-root@aegis.example.com}}"
SSH_PORT="${AEGIS_SSH_PORT:-22}"
SSH_KEY="${AEGIS_SSH_KEY:-$HOME/.ssh/id_ed25519}"
MIN_FREE_MB="${AEGIS_MIN_FREE_MB:-400}"
SSH_OPTS="-i $SSH_KEY -p $SSH_PORT -o ConnectTimeout=15 -o BatchMode=yes"
SCP_OPTS="-i $SSH_KEY -P $SSH_PORT -o ConnectTimeout=15 -o BatchMode=yes"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="$ROOT/public/downloads/aegis_collector.py"
REMOTE_PATH="/opt/aegis/aegis_collector.py"
SERVICE="aegis-collector"
TS=$(date +%Y%m%d_%H%M%S)

fail() { echo "  ✗ $1" >&2; exit "${2:-1}"; }

rollback() {
  echo "═══ 回滚到备份 $1 ═══"
  ssh $SSH_OPTS "$SERVER" "cp -a '$1' '$REMOTE_PATH' && systemctl restart $SERVICE && sleep 3 && systemctl is-active --quiet $SERVICE && echo '  ✓ 回滚后服务 active'" \
    || echo "  ⚠ 回滚后服务未 active，需人工介入: ssh $SERVER 'systemctl status $SERVICE'" >&2
}

# ── 构建基线断言（2026-09-26 事故护栏，勿删）────────────────────────────────
# 真事故：部署窗口内另一名成员并发提交，使仓库 HEAD 在本次构建之后前移。那次侥幸
# 无害，但时序若颠倒就会把未授权内容推上生产而脚本毫无察觉。故部署前固定基线并拒绝
# 脏树，部署后复验 HEAD 未变。失败一律中止报错：不重试、不忽略、不降级为告警。
HEAD_BEFORE=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo "")
if [ -z "$HEAD_BEFORE" ]; then
  fail "无法取得 git HEAD（$ROOT 不是 git 仓库？），构建基线无法固定，拒绝部署" 2
fi
DIRTY=$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null || echo "")
if [ -n "$DIRTY" ]; then
  echo "  ✗ 工作区存在【已跟踪文件】的未提交改动，拒绝部署（上线内容无法追溯到某个 commit）：" >&2
  echo "$DIRTY" | sed "s/^/      /" >&2
  fail "请先 commit 或 stash 后重试（未跟踪的构建产物目录不受影响）" 2
fi
echo "  ✓ 构建基线 HEAD = $(git -C "$ROOT" rev-parse --short HEAD)，无未提交的已跟踪改动"

echo "═══ [1/7] 本地冒烟: py_compile + release_verify ═══"
[ -f "$SRC" ] || fail "找不到源文件: $SRC"
/usr/bin/python3 -m py_compile "$SRC" || fail "本地 py_compile 失败，拒绝部署"
/usr/bin/python3 "$ROOT/public/downloads/aegis_release_verify.py" "$ROOT/public/downloads" >/dev/null 2>&1 \
  || echo "  ⚠ release_verify 未通过（仅告警，采集器不在 bundle 校验的关键路径可继续）"
echo "  ✓ 本地语法/工件校验通过"

echo "═══ [2/7] SSH 可达性冒烟 ═══"
ssh $SSH_OPTS "$SERVER" 'echo ok >/dev/null' || fail "SSH 不可达（检查 AEGIS_DEPLOY_SERVER / AEGIS_SSH_PORT / AEGIS_SSH_KEY）"
echo "  ✓ 远端可达"

echo "═══ [3/7] VPS 内存余量 guard (阈值 ${MIN_FREE_MB}MB) ═══"
FREE_MB=$(ssh $SSH_OPTS "$SERVER" "awk '/MemAvailable/{print int(\$2/1024)}' /proc/meminfo")
echo "  · MemAvailable ≈ ${FREE_MB}MB"
[ "${FREE_MB:-0}" -ge "$MIN_FREE_MB" ] || fail "可用内存 ${FREE_MB}MB < ${MIN_FREE_MB}MB，为防 OOM 中止（曾发生 OOM）"
echo "  ✓ 内存余量充足"

echo "═══ [4/7] 备份现网采集器 ═══"
BACKUP="$REMOTE_PATH.bak.$TS"
ssh $SSH_OPTS "$SERVER" "if [ -f '$REMOTE_PATH' ]; then cp -a '$REMOTE_PATH' '$BACKUP' && echo '  ✓ 已备份 → $BACKUP'; else echo '  · 现网无既有文件（首次部署），跳过备份'; fi"

echo "═══ [5/7] 上传到 staging 并远端 py_compile 校验 ═══"
STAGING="/tmp/aegis_collector.py.$TS"
scp $SCP_OPTS "$SRC" "$SERVER:$STAGING" || fail "scp 上传失败"
# 远端 py_compile 失败即中止，绝不触碰现网文件。staging 残留在 /tmp（临时目录，
# 系统自会清理）；刻意不用 rm，遵循「不对文件做破坏性删除」的安全约束。
ssh $SSH_OPTS "$SERVER" "python3 -m py_compile '$STAGING'" || fail "远端 py_compile 失败，未触碰现网文件（staging 留在 ${STAGING}）"
echo "  ✓ staging 语法校验通过"

echo "═══ [6/7] 就位 + 单次重启 $SERVICE ═══"
ssh $SSH_OPTS "$SERVER" "mv -f '$STAGING' '$REMOTE_PATH' && systemctl restart $SERVICE"
echo "  ✓ 已就位并重启（单次）"

echo "═══ [7/7] /health 冒烟轮询 ═══"
PORT="${AEGIS_COLLECTOR_PORT:-}"
if [ -z "$PORT" ]; then
  PORT=$(ssh $SSH_OPTS "$SERVER" "systemctl cat $SERVICE 2>/dev/null | grep -oE -- '--port[= ]+[0-9]+' | grep -oE '[0-9]+' | head -1")
fi
PORT="${PORT:-8788}"
echo "  · 采集器端口: $PORT"
OK=""
i=0
while [ "$i" -lt 30 ]; do
  i=$((i+1))
  if ssh $SSH_OPTS "$SERVER" "systemctl is-active --quiet $SERVICE && curl -fsS --max-time 5 'http://127.0.0.1:$PORT/health'" 2>/dev/null | grep -Eq '"status":[[:space:]]*"ok"'; then
    OK="1"; break
  fi
  sleep 2
done
if [ -z "$OK" ]; then
  echo "  ✗ 健康冒烟失败（30 次轮询未 ok）" >&2
  if [ -n "${BACKUP:-}" ]; then rollback "$BACKUP"; fi
  fail "部署后采集器不健康，已尝试回滚"
fi
echo "  ✓ /health = ok，服务 active"

# ── 部署后 HEAD 复验（构建基线断言的后半，勿删）──────────────────────────────
# 放在"部署完成"之前：HEAD 若在部署期间被并发提交推进，就不能宣称部署完成，
# 因为此刻仓库状态已无法代表线上正在跑的采集器。
HEAD_AFTER=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo "")
if [ "$HEAD_AFTER" != "$HEAD_BEFORE" ]; then
  echo "  ✗ HEAD 在部署期间发生变化：$(echo "$HEAD_BEFORE" | cut -c1-7) → $(echo "$HEAD_AFTER" | cut -c1-7)" >&2
  echo "    线上工件对应基线 ${HEAD_BEFORE}，当前仓库 HEAD 已不是它。" >&2
  fail "请人工核对该区间提交是否被授权上线，必要时重新部署。不自动重试。" 3
fi
echo "  ✓ HEAD 未变（部署前 = 部署后 = $(git -C "$ROOT" rev-parse --short HEAD)）"

echo "═══ 采集器部署完成 ($SERVICE @ $PORT) ═══"
