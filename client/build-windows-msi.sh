#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# build-windows-msi.sh — 构建 Windows 原生安装器 aegis-agent-windows.msi（可在 macOS/Linux 交叉产出）。
#
# 流程：dotnet 交叉发布 win-x64 **与** win-arm64 两份自包含单文件 AegisServiceHost
# → 组装 MSI 源目录（两份 host + aegis-windows.ps1 + 策略/基线 + Install-Aegis-Windows.ps1
#   + 构建时生成的 server.json）→ wixl 打包成**单一通用** .msi（装机时按
#   PROCESSOR_ARCHITECTURE 条件只装匹配架构的那份）→ 解包扫描确保无任何凭据 → 生成 SHA256SUMS。
#
# ── 修复记录（AEGIS-WIN-0001 v2，2026-09-16）───────────────────────────────
# 本脚本是 Windows 安装失败的**根因所在**，不是 wxs：
#
#   原实现 SERVER="${AEGIS_PUBLIC_ORIGIN:-https://aegis.example.com}" —— 未设环境变量时
#   静默回落到 RFC2606 占位域，并把它烘进 server.json，然后打印「✓ 已生成」当作成功。
#   package.json 的 build 链（sh client/build-windows-msi.sh）并不注入该变量，
#   于是任何忘记 export AEGIS_PUBLIC_ORIGIN 的构建都会产出一个**必然装不上**的包：
#   占位域不可解析 → Install-Aegis-Windows.ps1 的 Invoke-RestMethod 抛异常 →
#   非零退出 → MSI 自定义动作 Return="check" 判定失败 → 错误 1722 → 回滚 →
#   用户只看到「程序包有问题。作为安装一部分的程序没有按预期完成」。
#
#   F1  （v2）未注入真实 origin 时构建期即失败。
#       （v3 修订）改为**缺省烘占位域**：D9 让装机时可经 MSI 属性 AEGIS_SERVER_URL 注入
#       真实控制台，所以占位域包正是公开发布的正确形态，且真实域名不入库。
#       D1 守卫保证忘了注入时硬失败并打印正确命令，不会静默装出死 agent。
#   F2  打包后解包校验 server.json 与构建意图一致（v3：占位域不再判失败）。
#   F3  裁剪发布：自包含 host 由 ~31MB 降至 ~11MB。
#   F4  打印每个 RID 的 host 与最终 .msi 实际体积，便于持续观测。
#   F5  **BOM 强制**（v3 新增，对应 D0 头号根因）：每次构建都检查并补齐随包 .ps1 的
#       UTF-8 BOM。Windows PowerShell 5.1 对无 BOM 文件按系统 ANSI 代码页解码，
#       cp936 机器上中文字节会吞掉紧随的 ASCII 引号/花括号/换行，脚本在解析期就碎掉，
#       powershell -File 在执行第 1 行之前即以 1 退出 → MSI 1722。
#       en-US（cp1252）机器不受影响，这正是「同一个 MSI 有的机器能装、中文机器装不上」的根因。
#       编辑器与 CI 很容易在某次改动后悄悄丢掉 BOM，故把它固化成流程而非一次性的文件状态。
#
# ⚠ 验证状态（2026-09-16）：本脚本的 **wixl 轨道未在本地执行过**（wixl/msitools 是
#   Linux/macOS 工具，修复环境是 Windows）。同一份 AegisAgent.wxs 已在 **原生 WiX
#   v3.14.1（candle+light）** 轨道上完成构建与真机端到端安装验证（x64 与 ARM64 两条
#   分支均验证通过）。wxs 新增用到的 <Condition>（Component 级）、<RegistrySearch>、
#   Property/@Secure、多个 FileKey 型自定义动作，都是 WiX v3 schema 的合法构造，
#   但 wixl 对它们的支持程度需要在 CI 上确认后再合入。
#
# 缺 dotnet 或 wixl 时优雅跳过（exit 0），故可安全挂在 npm run build 前置链：
#   macOS:  brew install msitools（wixl）；dotnet 10 SDK
# 服务器 origin 经 AEGIS_PUBLIC_ORIGIN 注入并烘焙进 server.json（真实主机不入库）。
# 产物 .msi 为构建生成物（.gitignore），随 dist 部署。
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLIENT="$ROOT/client"
DL="$ROOT/public/downloads"
# .msi 体积与 Cloudflare Workers 单资产 25MiB 上限的关系：
# 裁剪前约 32MB，超限，绝不能放进 public/（会被 vinext 当作 Workers 资产打包，
# 导致 wrangler 启动失败、控制台 502）。裁剪后约 13MB 已低于该上限，但仍保守输出到
# 仓库根的 native-dist/（gitignore），由部署单独 scp 到服务器、nginx 以静态文件直供。
# 若要改走 public/ 分发，请先确认实际产物 < 25MiB 并复核 vinext 资产清单。
NATIVE="$ROOT/native-dist"
OUT="$NATIVE/aegis-agent-windows.msi"
SERVER="${AEGIS_PUBLIC_ORIGIN:-}"
INTERVAL="${AEGIS_SCAN_INTERVAL:-3600}"
ALLOW_PLACEHOLDER="${AEGIS_ALLOW_PLACEHOLDER_ORIGIN:-0}"
PLACEHOLDER="https://aegis.example.com"

# ── F1（v3 修订）占位 origin 不再是构建错误 ─────────────────────────────────
# v2 时这里「未注入 AEGIS_PUBLIC_ORIGIN 就拒绝构建」，理由是占位域不可解析会导致
# 装机 1722。但 v3 给安装脚本加了 D9（装机时经 MSI 公共属性注入 origin）之后，
# **烘占位域的包正是公开发布的正确形态**：
#   · 真实控制台域名不入库（scripts/privacy-scan.sh:38 的门禁要求如此）
#   · 装的人用 AEGIS_SERVER_URL 指向自己的控制台：
#       msiexec /i aegis-agent-windows.msi AEGIS_SERVER_URL=https://<你的控制台>
#   · 忘了注入也不会静默装出死 agent：D1 守卫会硬失败并打印上面这行命令
# 所以现在只在「显式注入了真实 origin」时校验其合法性；缺省走占位域并提示。
if [ -z "$SERVER" ]; then
  SERVER="$PLACEHOLDER"
  echo "  · 未设 AEGIS_PUBLIC_ORIGIN：烘入占位域 ${PLACEHOLDER}（公开发布形态）。" >&2
  echo "    装机时用 AEGIS_SERVER_URL 指向真实控制台，详见 AegisAgent.wxs 头部注释。" >&2
fi
# 归一化：去掉尾部斜杠，拒绝非 https
SERVER=$(printf '%s' "$SERVER" | sed -e 's#/*$##')
case "$SERVER" in
  https://*) : ;;
  *) echo "  ✗ AEGIS_PUBLIC_ORIGIN 必须为 https:// 开头（Agent 强制 https 上报），实际：$SERVER" >&2; exit 1 ;;
esac
case "$SERVER" in
  *example.com|*example.net|*example.org|*invalid|*localhost)
    if [ "$SERVER" != "$PLACEHOLDER" ] && [ "$ALLOW_PLACEHOLDER" != "1" ]; then
      echo "  ✗ AEGIS_PUBLIC_ORIGIN 是保留占位域但又不等于公开发布用的 ${PLACEHOLDER}：${SERVER}" >&2
      echo "    要么留空走公开发布形态，要么给真实 https origin。" >&2
      exit 1
    fi ;;
esac

if ! command -v dotnet >/dev/null 2>&1; then echo "  · 跳过 Windows .msi（未安装 dotnet SDK）"; exit 0; fi
if ! command -v wixl >/dev/null 2>&1; then echo "  · 跳过 Windows .msi（未安装 wixl/msitools）"; exit 0; fi
for f in aegis-windows.ps1 aegis-policy.json aegis-security-baseline.md; do
  [ -f "$DL/$f" ] || { echo "缺少 $DL/$f" >&2; exit 1; }
done
mkdir -p "$NATIVE"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

# ── F3 裁剪发布 ────────────────────────────────────────────────────────────
# 原产物 ~32MB 的构成：自包含 .NET 运行时（~7MB）+ 未启用的桌面栈（host 是控制台 Exe，
# 一行 WPF/WinForms 都不用）+ 全量 satellite 语言资源（host 只有英文串）+ R2R 预编译映像。
# 关闭项：
#   UseWPF/UseWindowsForms=false   去掉 PresentationFramework / WindowsBase 等桌面栈
#   InvariantGlobalization=true     去掉 ICU 数据（csproj 已设，此处兜底）
#   SatelliteResourceLanguages=en   只留英文资源程序集
#   DebugType=None + DebugSymbols=false  不留调试符号
#   PublishTrimmed=true             裁剪未被引用的运行时程序集
#   TrimMode=partial                **保守**裁剪。Program.cs 的 WriteHealth 已改用源生成
#                                   （ServiceHealthJsonContext），full 理论上可用；但对一个
#                                   SYSTEM 权限常驻服务，稳定性优先于再省 1 MB，故保持 partial。
#   EnableCompressionInSingleFile=true  单文件内压缩
#   PublishReadyToRun=false         关闭 R2R（显著放大体积）
#
# 通用包同时携带两份 host（wxs 按 PROCESSOR_ARCHITECTURE 条件只装匹配的那份）。
# BUG A 防线：agent 版本单一真源 = public/downloads/aegis_agent.py 的 AGENT_VERSION
# （可用 AEGIS_AGENT_VERSION 覆盖）。注入 wxs 占位 Version="0.0.0" 与 exe 的 -p:Version，
# 使 MSI ProductVersion / File 版本 / exe FileVersion 三者随 agent 版本递增——
# 否则 MajorUpgrade 匹配不到同版本旧产品 → 升级 2753→1603 回滚（BUG A）。
AGENT_VERSION="${AEGIS_AGENT_VERSION:-$(grep -m1 'AGENT_VERSION =' "$DL/aegis_agent.py" 2>/dev/null | sed 's/[^"]*"\([^"]*\)".*/\1/')}"
[ -n "$AGENT_VERSION" ] || { echo "无法确定 agent 版本（AEGIS_AGENT_VERSION 或 aegis_agent.py）" >&2; exit 1; }
echo "  · agent 版本（单一真源）: $AGENT_VERSION"
for RID in win-x64 win-arm64; do
  echo "  · dotnet 交叉发布 AegisServiceHost ($RID, self-contained, single-file, trimmed)…"
  dotnet publish "$CLIENT/host/AegisServiceHost.csproj" -c Release -r "$RID" --self-contained true \
    -p:Version="$AGENT_VERSION" \
    -p:PublishSingleFile=true \
    -p:DebugType=None -p:DebugSymbols=false \
    -p:EnableCompressionInSingleFile=true \
    -p:UseWPF=false -p:UseWindowsForms=false \
    -p:InvariantGlobalization=true \
    -p:SatelliteResourceLanguages=en \
    -p:PublishTrimmed=true -p:TrimMode=partial \
    -p:PublishReadyToRun=false \
    -o "$WORK/publish-$RID" >/dev/null 2>&1
  [ -f "$WORK/publish-$RID/AegisServiceHost.exe" ] || { echo "dotnet 发布未产出 $RID 的 AegisServiceHost.exe" >&2; exit 1; }
  # F4 体积观测
  HOST_BYTES=$(wc -c < "$WORK/publish-$RID/AegisServiceHost.exe" | tr -d ' ')
  echo "  · AegisServiceHost ($RID) = $((HOST_BYTES / 1024)) KB（裁剪前约 31 MB）"
  case "$RID" in
    win-x64)   cp "$WORK/publish-$RID/AegisServiceHost.exe" "$WORK/AegisServiceHost.x64.exe" ;;
    win-arm64) cp "$WORK/publish-$RID/AegisServiceHost.exe" "$WORK/AegisServiceHost.arm64.exe" ;;
  esac
done

# ── F5 BOM 强制（D0 根因的构建期防线）───────────────────────────────────────
# Windows PowerShell 5.1 对**无 BOM** 的 .ps1 按系统 ANSI 代码页解码。在 cp936（中文）
# 机器上 UTF-8 中文字节会被配成 GBK 双字节并**吞掉紧随其后的 ASCII**（引号/花括号/换行），
# 脚本在语法层面就碎了，powershell -File 在执行第 1 行之前即以 1 退出 → MSI 1722。
# en-US（cp1252 单字节）机器上字节不被吞，同一份文件「碰巧」能跑——
# 这就是「同一个 MSI 有的机器能装、中文机器装不上」的根因。
# 编辑器/CI 很容易在某次改动后悄悄丢掉 BOM，故在此**每次构建都补齐并校验**，
# 把这个修复固化成流程而不是某一次的文件状态。
for PS1 in "$DL/aegis-windows.ps1" "$CLIENT/Install-Aegis-Windows.ps1"; do
  if [ "$(head -c 3 "$PS1" | od -An -tx1 | tr -d ' \n')" != "efbbbf" ]; then
    printf '\xef\xbb\xbf' > "$WORK/bom.tmp"
    cat "$PS1" >> "$WORK/bom.tmp"
    cp "$WORK/bom.tmp" "$PS1"
    echo "  ! 已为 $(basename "$PS1") 补 UTF-8 BOM（原先缺失，中文系统上会解析失败）" >&2
  fi
done

cp "$DL/aegis-windows.ps1" "$DL/aegis-policy.json" "$DL/aegis-security-baseline.md" "$WORK/"
cp "$CLIENT/Install-Aegis-Windows.ps1" "$WORK/"
# BUG A：把单一真源版本注入 wxs 副本的占位 Version="0.0.0"（Product + 两个 File 行）。
# 工具链无关（wixl / 原生 WiX 都吃替换后的字面量）；注入失败立即构建失败，
# 绝不静默发一个版本不变的包（那会让升级 2753 复发）。
sed -e "s/Version=\"0\.0\.0\"/Version=\"$AGENT_VERSION\"/g" "$CLIENT/AegisAgent.wxs" > "$WORK/AegisAgent.wxs"
grep -q "Version=\"$AGENT_VERSION\"" "$WORK/AegisAgent.wxs" || { echo "wxs 版本注入失败" >&2; exit 1; }
[ "$(grep -c 'Version="0.0.0"' "$WORK/AegisAgent.wxs")" -eq 0 ] || { echo "wxs 仍有未注入的版本占位" >&2; exit 1; }
# server.json 构建时生成（真实 origin 只在部署环境注入，绝不入库）
printf '{"schema":"aegis.server/v1","server_url":"%s","scan_interval_seconds":%s}\n' "$SERVER" "$INTERVAL" > "$WORK/server.json"

echo "  · wixl 打包 .msi…"
( cd "$WORK" && wixl -a x64 -o "$OUT" AegisAgent.wxs )
[ -f "$OUT" ] || { echo "wixl 未产出 $OUT" >&2; exit 1; }

# ── 解包校验 ───────────────────────────────────────────────────────────────
mkdir -p "$WORK/check"
if command -v msiextract >/dev/null 2>&1; then msiextract -C "$WORK/check" "$OUT" >/dev/null 2>&1 || true; fi

# 凭据扫描：安装包内绝不能含任何上报令牌/签名密钥（令牌装机时才经 /api/enroll 获取）。
if grep -rInE '"report_token":"[^"]{32,}"|"signing_secret":"[^"]{32,}"|__PILOT_TOKEN__|__PILOT_SECRET__' "$WORK/check" >/dev/null 2>&1; then
  echo "  ✗ 安装包内发现凭据材料，拒绝产出" >&2; rm -f "$OUT"; exit 1
fi

# F2 防回归：确认烘进包里的 server_url 与本次构建意图一致。
# v3 修订：占位域不再判失败——它就是公开发布形态（装机时经 AEGIS_SERVER_URL 注入）。
# 这里只拦「构建注入了真实 origin，包里却不是它」这种真正的回归。
if [ -f "$WORK/check/server.json" ]; then
  BAKED=$(sed -n 's/.*"server_url":"\([^"]*\)".*/\1/p' "$WORK/check/server.json" | head -1)
  if [ "$BAKED" != "$SERVER" ]; then
    echo "  ✗ 包内 server_url ($BAKED) 与构建注入 ($SERVER) 不一致" >&2; rm -f "$OUT"; exit 1
  fi
  case "$BAKED" in
    *example.com|*example.net|*example.org)
      echo "  ✓ 包内 server_url = 占位域（公开发布形态，装机时用 AEGIS_SERVER_URL 注入真实控制台）" ;;
    *)
      echo "  ✓ 包内 server_url 校验通过（已烘焙真实 origin）" ;;
  esac
else
  echo "  · 未能解包校验 server.json（msiextract 不可用），跳过 F2 检查" >&2
fi

SUM=$(if command -v sha256sum >/dev/null 2>&1; then sha256sum "$OUT" | cut -d' ' -f1; else shasum -a 256 "$OUT" | cut -d' ' -f1; fi)
printf '%s  %s\n' "$SUM" "$(basename "$OUT")" > "$NATIVE/aegis-agent-windows.msi.sha256"
MSI_BYTES=$(wc -c < "$OUT" | tr -d ' ')
echo "  ✓ 已生成 $OUT (server $SERVER, $((MSI_BYTES / 1024)) KB, sha256 ${SUM:0:12}…)"
