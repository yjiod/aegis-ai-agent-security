#!/bin/sh
# ═══════════════════════════════════════════════════════════════════
# ps-parse-gate.sh — PowerShell 解析门禁（CI + 本地）。
#
# 所有被 git 跟踪的 .ps1 必须能被 PowerShell 解析器无错解析。CI 原有的 `sh -n` 只覆盖
# *.sh，PowerShell 脚本从来没有任何静态门禁——于是 apply-win.ps1 的引号错位
# ("Name='AegisAgent"' 多了个游离单引号→字符串未终止级联报错)、mdm-*.ps1 的哈希表键
# 引号错位 ('aegis-policy.json='HASH' 把 = 写进了 key 引号内) 长期潜伏，直到在真实
# Windows 上运行才炸。本门禁用 PowerShell 自带的 Language.Parser 做 ParseFile，任何
# 语法错误即退出非零。
#
# 依赖 pwsh（GitHub ubuntu-latest runner 预装；本机 macOS 亦可 brew 装）。无 pwsh 时
# 优雅跳过（exit 0 + 提示），不阻断其它环境。用 PS7 解析器即可捕获这类结构性语法错误
# （与 PS5.1 在这些构造上一致）；PS5.1 专有的 BOM/ANSI 解码问题由 windows-verify 现场
# harness 的 ParseFile 门禁另行覆盖。
# ═══════════════════════════════════════════════════════════════════
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 2

if ! command -v pwsh >/dev/null 2>&1; then
  echo "ps-parse-gate: 无 pwsh，跳过（建议在 CI/本机安装 PowerShell 以启用该门禁）"
  exit 0
fi

fail=0
# git ls-files 逐条解析；路径经环境变量 PS_PARSE_TARGET 传入 pwsh（-Command 的尾随位置参数
# 不会可靠落到 $args，实测为 null），避免插值/引号/空格问题。ParseFile 有任何语法错误即 exit 1。
for f in $(git ls-files '*.ps1'); do
  [ -n "$f" ] || continue
  if ! PS_PARSE_TARGET="$f" pwsh -NoProfile -Command '$p=$env:PS_PARSE_TARGET; if(-not $p){exit 2}; $e=$null; $t=$null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $p).Path,[ref]$t,[ref]$e); if($e){ $e | ForEach-Object { Write-Host ("    L" + $_.Extent.StartLineNumber + ": " + $_.Message) }; exit 1 } else { exit 0 }'; then
    echo "  PARSE FAIL: $f"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "ps-parse-gate: FAILED（上述 .ps1 存在语法错误）"
  exit 1
fi
echo "ps-parse-gate: OK（所有被跟踪 .ps1 解析通过）"
exit 0
