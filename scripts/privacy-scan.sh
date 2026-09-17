#!/bin/sh
# ═══════════════════════════════════════════════════════════════════
# privacy-scan.sh — 隐私回归门禁（CI + 本地）。只扫 git 跟踪内容。
#
# 三层检测，任一命中即退出非零（CI 失败）。真实敏感字面量永不出现在任何被跟踪文件里：
#
#  层1 通用结构模式（git grep，不含任何具体敏感字面量）：RFC1918 内网 IP、硬编码长密钥/口令、
#      .local mDNS 主机名。这些是「形状」检测，公开无风险。
#  层2 本地 blocklist（gitignored scripts/privacy-blocklist.local，存在才跑）：维护者私存的
#      具体敏感字面量明文 substring 正则——最强，能抓嵌进长词的拉丁字面量。CI 无此文件则跳过
#      （打印提示）。推送前本地必跑本脚本，故字面量在进 CI/上 GitHub 前即被拦下。
#  层3 HMAC 指纹（scripts/privacy_fingerprints.py）：CI 兜底。仓内只提交字面量的 HMAC-SHA256
#      指纹（密钥来自 GH Actions secret / gitignored 本地文件，无密钥不可逆推），按候选 token
#      比对。抓独立 token 形态的泄漏（工号/域名/用户名/序列号/CJK 厂商名等）。
#
# 设计动机：旧版把真实厂商名/工号/用户名/域名当明文正则写死在本脚本里、再 exclude 自身，
# 结果这些字面量随脚本公开到了 GitHub（违反隐私铁律）。现改为「通用形状 + 本地明文 + CI 指纹」，
# 公开仓内不再有任何具体敏感字面量。
# ═══════════════════════════════════════════════════════════════════
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 2

FAIL=0
SELF_EXCLUDE=":(exclude)scripts/privacy-scan.sh :(exclude)scripts/privacy_fingerprints.py :(exclude)scripts/privacy-blocklist.local.example"

# ── 层1：通用结构模式（无具体敏感字面量）──────────────────────────────────────
scan() {
  label="$1"; pattern="$2"; exclude="${3:-}"
  if out=$(git grep -nI -E "$pattern" -- . $SELF_EXCLUDE 2>/dev/null); then
    if [ -n "$exclude" ]; then
      out=$(printf '%s\n' "$out" | grep -vE "$exclude" || true)
    fi
    if [ -n "$out" ]; then
      echo "!! privacy leak [$label]:"
      echo "$out" | head -20
      FAIL=1
    fi
  fi
}

# RFC1918 内网 IP（环回 127.0.0.1 与 RFC5737 文档段 203.0.113/198.51.100/192.0.2 不在此列）
scan private-ip '(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)'
# 硬编码长密钥/令牌（值是全大写环境变量名的常量定义属误报，排除）
scan hardcoded-secret '([A-Z_]*(TOKEN|SECRET|SIGNING_KEY)|password|passwd)[A-Z_]*["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9_\-\.]{16,}["'"'"']' '[:=][[:space:]]*["'"'"'][A-Z0-9_]{16,}["'"'"']'
# .local mDNS 主机名形状（真实机器名常以此结尾）
scan mdns-host '\.local\b'

# ── 层2：本地 blocklist（gitignored，存在才跑；明文 substring，最强）────────────
BL="scripts/privacy-blocklist.local"
if [ -f "$BL" ]; then
  TAB=$(printf '\t')
  while IFS="$TAB" read -r label pattern; do
    [ -n "$label" ] || continue
    case "$label" in '#'*) continue ;; esac
    [ -n "$pattern" ] || continue
    if out=$(git grep -nI -E "$pattern" -- . $SELF_EXCLUDE 2>/dev/null); then
      if [ -n "$out" ]; then
        echo "!! privacy leak [$label] (local blocklist):"
        echo "$out" | head -20
        FAIL=1
      fi
    fi
  done < "$BL"
else
  echo "note: 无 scripts/privacy-blocklist.local（本地明文 substring 层跳过；CI 由 HMAC 指纹层兜底）"
fi

# ── 层3：HMAC 指纹层（CI 兜底，仓内无字面量）──────────────────────────────────
# 选「真能执行」的 python3：PATH 里的 python3 可能是坏架构二进制（如 ARM mac 上的
# Intel /usr/local/bin/python3 → "Bad CPU type"），逐个试跑取第一个可用的，避免指纹层
# 因解释器崩溃而 fail-closed 掩盖真实结果。
pick_python() {
  for c in python3 /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'print(1)' >/dev/null 2>&1; then
      echo "$c"; return 0
    fi
  done
  return 1
}
PY=$(pick_python || true)
if [ -n "$PY" ]; then
  if ! "$PY" scripts/privacy_fingerprints.py; then FAIL=1; fi
else
  echo "note: 无可用 python3，跳过 HMAC 指纹层"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "privacy-scan: FAILED (see above)"
  exit 1
fi
echo "privacy-scan: OK (no personal/infra identifiers in tracked content)"
exit 0
