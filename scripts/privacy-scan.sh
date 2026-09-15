#!/bin/sh
# ═══════════════════════════════════════════════════════════════════
# privacy-scan.sh — 隐私回归门禁（CI + 本地）。
#
# 只扫** git 跟踪内容 **（git grep），防止真实个人/基础设施标识符混入公共仓库：
# 厂商名、真实 IP、真实主机名/.local、真实域名、工号、硬编码长密钥。
# 命中即退出非零（CI 失败）。允许误报豁免通过 ALLOW 行内注释人工维护。
#
# 说明：代码逻辑里合法出现的 "/Users/" 前缀判断、RFC5737 文档段
# (203.0.113.x/198.51.100.x/192.0.2.x)、环回 127.0.0.1、示例占位
# (zhangsan/lisi/张三/李四、demo.eng、alice) 均不在禁止模式内，不会误报。
# ═══════════════════════════════════════════════════════════════════
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 2

FAIL=0

scan() {
  label="$1"; pattern="$2"; exclude="${3:-}"
  if out=$(git grep -nI -E "$pattern" -- . 2>/dev/null); then
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

# 1) 厂商/企业专有命名（红线：不复制厂商命名）
scan vendor '([Tt]ranssion|传音|深信服|[Ss]angfor|edrscenter|edr-scenter|[Ii]ntune)'
# 2) 真实个人/主机标识（用户名/主机名/.local mDNS）
scan personal '(lvshuai|ShineMac|Shine-Mac|[Mm]acbook-Pro|mac-mini|\.local\b)'
# 3) 真实域名（GitHub 组织 yjiod 允许；真实主机域名禁止）
scan domain '(tx\.yjiod|\.yjiod\.com)'
# 4) 真实工号
scan employee '(18620178)'
# 5) 私有/内网 IP（RFC1918）与回环除外的公网 IP 由人工评审；这里挡 RFC1918
scan private-ip '(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)'
# 6) 硬编码长密钥/令牌（示例模板均为空值，不会误报；排除"值是全大写环境变量名"的常量定义）
scan hardcoded-secret '([A-Z_]*(TOKEN|SECRET|SIGNING_KEY)|password|passwd)[A-Z_]*["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9_\-\.]{16,}["'"'"']' '[:=][[:space:]]*["'"'"'][A-Z0-9_]{16,}["'"'"']'

if [ "$FAIL" -ne 0 ]; then
  echo "privacy-scan: FAILED (see above)"
  exit 1
fi
echo "privacy-scan: OK (no personal/infra identifiers in tracked content)"
exit 0
