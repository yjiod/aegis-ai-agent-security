#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# aegis-pg-restore-drill.sh — PostgreSQL 备份「恢复演练」
#
# 目的: 备份存在 ≠ 备份可恢复。本脚本把最近一次备份还原到一个一次性
#       演练库(scratch db)，逐表校验 schema 与行数，然后丢弃演练库。
#       全程只读生产库(仅用于行数对照)，绝不修改/删除生产数据，也不删除
#       任何文件——只 CREATE/DROP 它自己创建的演练数据库。
#
# 为什么默认用 postgres 超级用户:
#   应用连接角色(aegis)通常没有 CREATEDB 权限，无法建演练库。演练应在 PG
#   宿主机上、以有建库权限的角色运行(与备份 timer 同机同权限模型)。默认
#   `sudo -u postgres psql`(peer 认证，无需密码)。远程/URL 场景可用
#   AEGIS_DRILL_PSQL 覆盖成任意「能连到服务器且可 CREATE DATABASE」的 psql。
#
# 实现要点: SQL 一律经 stdin 喂给 psql(而非 -c 参数)。因为 AEGIS_DRILL_PSQL
#   可能带 `sudo -u postgres` 这类前缀，脚本用 eval 展开前缀；若把多词 SQL 作为
#   -c 参数传入，eval 的词分割会把 "SELECT 1" 拆成 -c SELECT + 位置参数 1(被当成
#   库名)从而连错库。走 stdin 彻底规避该问题。
#
# 依赖: psql(postgresql-client)、gunzip
#
# 用法(PG 宿主机上，root 或有 sudo 的账号):
#   sh scripts/aegis-pg-restore-drill.sh
#
# 可选环境变量:
#   AEGIS_BACKUP_DIR     备份目录           (默认 /var/backups/aegis-pg)
#   AEGIS_BACKUP_GLOB    备份文件通配       (默认 'aegis-*.sql.gz')
#   AEGIS_DRILL_DB       演练库名           (默认 aegis_restore_drill)
#   AEGIS_DRILL_LIVE_DB  生产库名(行数对照) (默认取 AEGIS_PG_URL 的库名，否则 aegis)
#   AEGIS_DRILL_PSQL     建库级 psql 命令    (默认 'sudo -u postgres psql')
#   AEGIS_DRILL_MAINT_DB 维护库名           (默认 postgres)
#   AEGIS_DRILL_KEEP=1   演练后保留演练库(供人工排查)，默认演练后 DROP
#
# 退出码: 0=演练通过  1=校验失败(备份不可用/关键表缺失)  2=前置条件错误
#
# 建议: 由 systemd timer 每周跑一次，或每次备份策略变更后手动跑一次。
#       与 aegis-pg-backup.(sh|service|timer) 配套使用。
# ═══════════════════════════════════════════════════════════════════════
set -eu

BACKUP_DIR="${AEGIS_BACKUP_DIR:-/var/backups/aegis-pg}"
BACKUP_GLOB="${AEGIS_BACKUP_GLOB:-aegis-*.sql.gz}"
DRILL_DB="${AEGIS_DRILL_DB:-aegis_restore_drill}"
MAINT_DB="${AEGIS_DRILL_MAINT_DB:-postgres}"
DRILL_PSQL="${AEGIS_DRILL_PSQL:-sudo -u postgres psql}"
KEEP="${AEGIS_DRILL_KEEP:-0}"

# 生产库名: 优先显式覆盖，其次从 AEGIS_PG_URL 解析，最后回退 aegis。
if [ -n "${AEGIS_DRILL_LIVE_DB:-}" ]; then
  LIVE_DB="$AEGIS_DRILL_LIVE_DB"
elif [ -n "${AEGIS_PG_URL:-}" ]; then
  # postgres://user:pass@host:port/DBNAME?params  ->  DBNAME
  # 纯 POSIX 参数展开(不用 sed)，避免把 user:pass@host 误当成库名而泄漏到日志。
  _u=${AEGIS_PG_URL#*://}   # 去掉 scheme
  _u=${_u%%\?*}             # 去掉 ?params
  LIVE_DB=${_u##*/}         # 取最后一个 / 之后的库名
  [ -n "$LIVE_DB" ] || LIVE_DB="aegis"
else
  LIVE_DB="aegis"
fi

# 关键表: 缺失即判定备份不可用。可选表: 缺失仅告警(可能早于对应迁移)。
REQUIRED_TABLES="devices tickets ticket_history audit_log admins"
OPTIONAL_TABLES="auditors baselines settings asset_labels"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# 经 stdin 把单条 SQL 喂给指定库的 psql(eval 仅展开 DRILL_PSQL 前缀)。
sql() { # $1=dbname $2=sql
  printf '%s\n' "$2" | eval "$DRILL_PSQL" -d "$1" -v ON_ERROR_STOP=1 -At -q
}

# ── 前置检查 ──────────────────────────────────────────────────────────
command -v gunzip >/dev/null 2>&1 || die "未找到 gunzip"
[ -d "$BACKUP_DIR" ] || die "备份目录不存在: $BACKUP_DIR"
sql "$MAINT_DB" "SELECT 1" >/dev/null 2>&1 || die "无法以建库角色连接 PG(检查 AEGIS_DRILL_PSQL / sudo 权限): $DRILL_PSQL"

# 选取最近一次备份(按修改时间倒序)
BACKUP=$(ls -1t "$BACKUP_DIR"/$BACKUP_GLOB 2>/dev/null | head -n1 || true)
[ -n "$BACKUP" ] || die "在 $BACKUP_DIR 未找到匹配 $BACKUP_GLOB 的备份"
log "==> 最近备份: $BACKUP"
log "    大小: $(du -h "$BACKUP" 2>/dev/null | cut -f1)  修改时间: $(date -r "$BACKUP" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo n/a)"
log "    演练库: $DRILL_DB   生产对照库: $LIVE_DB   建库角色命令: $DRILL_PSQL"

# ── 重建演练库 ────────────────────────────────────────────────────────
log "==> (重新)创建演练库 $DRILL_DB"
sql "$MAINT_DB" "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null 2>&1 || true
sql "$MAINT_DB" "CREATE DATABASE $DRILL_DB" >/dev/null 2>&1 || die "创建演练库失败(角色可能无 CREATEDB 权限)"

# 演练库一旦建出，无论后续成功失败都尽量清理(除非 KEEP=1)
cleanup() {
  if [ "$KEEP" != "1" ]; then
    sql "$MAINT_DB" "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null 2>&1 || true
  fi
}

# ── 还原备份到演练库 ──────────────────────────────────────────────────
log "==> 还原备份到 $DRILL_DB (gunzip -c | psql)"
if ! gunzip -c "$BACKUP" | eval "$DRILL_PSQL" -d "$DRILL_DB" -v ON_ERROR_STOP=1 -q >/dev/null 2>&1; then
  cleanup
  die "还原失败：备份不可用(去掉脚本内静默重定向可看 psql 详细报错)"
fi
log "    还原完成"

# ── 逐表校验 ──────────────────────────────────────────────────────────
fail=0
count_in() { # $1=dbname $2=table -> 行数 | absent | err
  exists=$(sql "$1" "SELECT to_regclass('public.$2')" 2>/dev/null || echo "")
  if [ -z "$exists" ]; then echo "absent"; return 0; fi
  sql "$1" "SELECT count(*) FROM $2" 2>/dev/null || echo "err"
}

log "==> 校验关键表(缺失=失败)"
for t in $REQUIRED_TABLES; do
  r=$(count_in "$DRILL_DB" "$t")
  live=$(count_in "$LIVE_DB" "$t")
  if [ "$r" = "absent" ] || [ "$r" = "err" ]; then
    log "    [FAIL] $t 在还原库中缺失/不可查询"
    fail=1
  else
    log "    [OK]   $t 还原=$r 行  (生产对照=$live)"
  fi
done

log "==> 校验可选表(缺失=告警)"
for t in $OPTIONAL_TABLES; do
  r=$(count_in "$DRILL_DB" "$t")
  live=$(count_in "$LIVE_DB" "$t")
  if [ "$r" = "absent" ]; then
    log "    [WARN] $t 不存在(备份可能早于该表对应迁移)"
  elif [ "$r" = "err" ]; then
    log "    [WARN] $t 查询出错"
  else
    log "    [OK]   $t 还原=$r 行  (生产对照=$live)"
  fi
done

# ── 完整性抽查: 审计时间戳可解析、工单主键非空 ─────────────────────────
log "==> 完整性抽查"
bad_ts=$(sql "$DRILL_DB" "SELECT count(*) FROM audit_log WHERE ts IS NOT NULL AND ts <= 0" 2>/dev/null || echo 0)
null_pk=$(sql "$DRILL_DB" "SELECT count(*) FROM tickets WHERE ticket_id IS NULL OR ticket_id = ''" 2>/dev/null || echo 0)
if [ "${bad_ts:-0}" != "0" ]; then log "    [FAIL] audit_log 存在 $bad_ts 条非法时间戳"; fail=1; else log "    [OK]   audit_log 时间戳合法"; fi
if [ "${null_pk:-0}" != "0" ]; then log "    [FAIL] tickets 存在 $null_pk 条空主键"; fail=1; else log "    [OK]   tickets 主键非空"; fi

# ── 清理演练库 ────────────────────────────────────────────────────────
if [ "$KEEP" = "1" ]; then
  log "==> AEGIS_DRILL_KEEP=1，保留演练库 $DRILL_DB 供人工排查(记得稍后手动 DROP DATABASE $DRILL_DB)"
else
  log "==> 丢弃演练库 $DRILL_DB"
  cleanup
fi

if [ "$fail" != "0" ]; then
  log "==> 演练未通过：备份存在校验失败项，请检查上方 [FAIL]"
  exit 1
fi
log "==> 演练通过：最近备份可成功还原且关键表完整 OK"
exit 0
