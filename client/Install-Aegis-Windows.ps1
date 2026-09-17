<#
.SYNOPSIS
  Aegis Windows 原生服务安装/卸载（由 AegisServiceHost.exe --install/--uninstall 委派，MSI 自定义动作触发）。

.DESCRIPTION
  以 SYSTEM/管理员运行时执行：
    1) 把运行时（aegis-windows.ps1 / aegis-policy.json / aegis-security-baseline.md）落到 %ProgramData%\AegisAgent；
    2) 零接触自动入网：读 server.json 的 server_url → POST <server>/api/enroll 取 report_token +
       signing_secret + 当前已发布策略；按 aegis-windows.ps1 的解密契约用 DPAPI(LocalMachine,
       entropy 'AegisAgent.Reporting.v1') 写 reporting.dpapi（4 键 schema/report_url/report_token/signing_secret）；
       用服务端策略覆盖出厂策略；
    3) icacls 收紧 %ProgramData%\AegisAgent；
    4) sc.exe 注册 SCM 服务 AegisAgent（binPath=AegisServiceHost.exe --service, delayed-auto, LocalSystem,
       失败自动重启），并启动。
  -Uninstall：停止并删除服务（保留 ProgramData 供取证；如需清理另行删除）。

  服务器地址来自同目录 server.json（构建时烘焙，公开仓库为占位域）；绝不把令牌写进包/脚本/日志。

.NOTES
  ── 修复记录（AEGIS-WIN-0001 v2，2026-09-16）───────────────────────────────
  本脚本是 Windows 安装失败（MSI 错误 1722 → 回滚 →「程序包有问题。作为安装一部分的
  程序没有按预期完成」）的直接触发点。原实现有三处缺陷：

  D1  无占位域防护。原第 45 行只检查 server.json/server_url 是否**存在**，不检查内容。
      build-windows-msi.sh 在未设 AEGIS_PUBLIC_ORIGIN 时会把 RFC2606 占位域
      https://aegis.example.com 烘进 server.json，而该域**不可解析**。
      于是第 54 行 Invoke-RestMethod 抛异常（$ErrorActionPreference='Stop'）→
      脚本非零退出 → AegisServiceHost --install 非零 → MSI 自定义动作
      Return="check" 判定失败 → 1722 → 回滚。
      对照：同仓 public/downloads/aegis-agent-windows-enroll.ps1 第 48-50 行
      **已有**该防护（`if ($Base -match 'example\.com$' ...)`），本脚本漏了。

  D2  零日志。本脚本作为 MSI deferred 自定义动作以 SYSTEM 运行，Write-Output
      被 Windows Installer 丢弃、无控制台、无 stdout 落盘。任何失败都只剩一句
      通用 1722 对话框，**无法定位**。这是该缺陷能长期潜伏的直接原因。

  D3  全有或全无。入网（网络依赖）与服务启动（时序依赖）都是硬失败前置条件。
      对照 macOS 的 aegis-agent-macos-enroll.sh：launchctl/首报全部 `|| true`
      或 try/catch 容错，安装永远成功。**这就是「mac 能装、Windows 装不上」的根因**。

  D4  （v3 补充，2026-09-16 本机 MSI 端到端实测发现）脚本编码与 $env:ProgramData 兜底：
      · 本文件与 public/downloads/aegis-windows.ps1 均为「UTF-8 无 BOM + 中文」。
        Windows PowerShell 5.1 对无 BOM 脚本按系统 ANSI 代码页解码：在 zh-CN（cp936/GBK）
        机器上，UTF-8 中文字节被两两配对成 GBK 字符时会吞掉其后的 ASCII 引号/大括号/换行，
        实测本文件产生 5 处、aegis-windows.ps1 产生 19 处解析错误——powershell -File
        在**执行第 1 行之前**即告解析失败并以退出码 1 终止（MSI 侧表现为 1722，
        install.log 根本来不及写）。在 en-US（cp1252 单字节）机器上字节不会被吞，
        恰好能跑——这正是「同一 MSI 有的机器能装、中文机器装不上」的编码根因。
        修复：随包分发的 .ps1 一律以 UTF-8 with BOM 保存（PS 5.1/7 均正确识别）。
      · $env:ProgramData 在个别执行上下文（继承自被裁剪环境的 deferred CA、沙箱）下
        可能为 NULL，Join-Path $null 抛 ArgumentNullException 且早于第一条日志。
        修复：与 host 的 DataDir（SpecialFolder.CommonApplicationData）对齐做三级兜底。

  D5  （v3 补充，同批实测发现）Windows PowerShell 5.1 默认**不加载** System.Security.dll，
      [Security.Cryptography.ProtectedData] 类型解析为 NULL；EAP=Stop 下调用其静态方法
      即终止性错误（退出码 1）。实测：入网已成功、服务端策略已写盘，进程死在
      reporting.dpapi 写入之前——每台 PS 5.1 机器必现，与区域/提权无关。
      修复：使用前显式 Add-Type -AssemblyName System.Security（PS 7 无此程序集但
      类型随框架内置，用 -as [type] 探测兼容两者）；并把 DPAPI 写入段收敛为
      SOFT FAIL（写不进 reporting.dpapi 只影响上报，不该回滚整个安装，对齐 D3 哲学）。
      同类缺陷也存在于 public/downloads/aegis-windows.ps1 第 6 行的 Unprotect
      （被 try/catch 吞掉 → PS 5.1 机器上扫描结果**永远无法上报**，静默降级）与
      aegis-agent-windows-enroll.ps1 第 95 行，一并修复。

  修复后的失败策略：
    HARD FAIL（非零退出 → MSI 回滚）——仅限「装了也永远不可能工作」的配置错误：
      · server.json 缺失 / server_url 空 / 仍是 RFC2606 占位域（构建未注入 origin）
      · AegisServiceHost.exe 或运行时脚本缺失（包不完整）
      · sc.exe 服务注册失败
    SOFT FAIL（记录状态、零退出 → 安装成功）——瞬态或外部依赖故障：
      · 控制台不可达 / TLS / 5xx / 限流 / 超时（带退避重试）
      · 服务未在时限内进入 Running（服务已注册，SCM 失败动作会继续重启）
    全部写入 %ProgramData%\AegisAgent\install.log 与 enrollment-status.json，
    使 1722 可诊断、使「已装未入网」可被控制台识别。
#>
[CmdletBinding()]
param(
  [switch]$Uninstall,
  # D9：装机时注入的控制台 origin。由 AegisServiceHost.exe --install AEGIS_SERVER_URL=<origin>
  # 透传，而后者来自 MSI 公共属性（msiexec /i aegis-agent-windows.msi AEGIS_SERVER_URL=...）。
  # 公开仓库的包烘的是 RFC2606 占位域，靠这个参数指向真实控制台，域名不入库。
  [string]$ServerUrl
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'AegisAgent'
$Base = $PSScriptRoot                                   # 安装目录（Program Files\AegisAgent）
# 从别处(如 C:\Windows\Temp)调用时 $PSScriptRoot 没有 exe → 回退到规范安装目录,
# 避免"缺少 AegisServiceHost.exe"误报(2026-09-17 现场实测踩到)。
if (-not (Test-Path (Join-Path $Base 'AegisServiceHost.exe'))) { $Base = Join-Path $env:ProgramFiles 'AegisAgent' }
# D4 修复：$env:ProgramData 可能为 NULL（裁剪环境/沙箱继承），Join-Path $null 会在
# 第一条日志之前抛 ArgumentNullException。三级兜底，与 host 的 DataDir 解析方式对齐。
$ProgramDataRoot = $env:ProgramData
if (-not $ProgramDataRoot) { $ProgramDataRoot = [Environment]::GetFolderPath('CommonApplicationData') }
if (-not $ProgramDataRoot) { $sd = $env:SystemDrive; if (-not $sd) { $sd = 'C:' }; $ProgramDataRoot = Join-Path $sd 'ProgramData' }
$Data = Join-Path $ProgramDataRoot 'AegisAgent'          # 运行数据目录（Agent 从此读取配置）
$HostExe = Join-Path $Base 'AegisServiceHost.exe'
$LogPath = Join-Path $Data 'install.log'
$StatusPath = Join-Path $Data 'enrollment-status.json'

# D2 补充：deferred 自定义动作下未处理的终止性错误默认静默丢弃，只留下 MSI 的
# 「returned actual error code 1」。trap 把异常类型/消息/脚本栈写进 install.log，
# 现场排障不再靠猜（本机实测正是靠它抓到 UnauthorizedAccessException 与 sc 1639）。
trap {
  try {
    Write-Log "UNHANDLED: $($_.Exception.GetType().FullName): $($_.Exception.Message)" 'ERROR'
    Write-Log "STACK: $($_.ScriptStackTrace)" 'ERROR'
  } catch { }
  exit 1
}

# D2 修复：日志落盘。deferred 自定义动作下 Write-Output 会被丢弃，文件是唯一可查依据。
# 安全：只记录布尔/长度/错误文本，**绝不**记录 report_token / signing_secret 明文。
function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
  try {
    if (-not (Test-Path -LiteralPath $Data)) { New-Item -ItemType Directory -Force -Path $Data | Out-Null }
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
  } catch { }
  Write-Output $line
}

# 入网状态机：控制台据此区分「已装已入网 / 已装未入网 / 配置错误」。
function Write-EnrollmentStatus {
  param([string]$State, [string]$Reason = '', [string]$Server = '')
  try {
    if (-not (Test-Path -LiteralPath $Data)) { New-Item -ItemType Directory -Force -Path $Data | Out-Null }
    $obj = [pscustomobject]@{
      schema       = 'aegis.enrollment-status/v1'
      state        = $State          # enrolled | needs_enrollment | config_error
      reason       = $Reason
      server_url   = $Server
      updated_at   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
      contains_secrets = $false
    }
    $tmp = "$StatusPath.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp, ($obj | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $StatusPath -Force
    # BUG D：写-改名成功后清理同前缀的残留 .tmp（此前失败/过期临时文件无限累积）。
    Get-ChildItem -LiteralPath $Data -Filter 'enrollment-status.json.*.tmp' -Force -ErrorAction SilentlyContinue |
      Remove-Item -Force -ErrorAction SilentlyContinue
  } catch { }
}

# 硬失败：写状态 + 日志后以非零退出（MSI 将回滚，这是期望行为——配置错误不该静默装成残废）
function Fail-Hard {
  param([string]$Message, [int]$Code = 78)   # 78 = EX_CONFIG (sysexits.h)
  Write-Log $Message 'ERROR'
  Write-EnrollmentStatus -State 'config_error' -Reason $Message
  exit $Code
}

Write-Log "=== Aegis Windows 安装开始（-Uninstall=$Uninstall）==="
Write-Log "BaseDir=$Base"
Write-Log "DataDir=$Data"
Write-Log "PSVersion=$($PSVersionTable.PSVersion)  OS=$([Environment]::OSVersion.Version)  Arch=$env:PROCESSOR_ARCHITECTURE"

if ($Uninstall) {
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    if ($svc.Status -ne 'Stopped') {
      Write-Log "停止服务 $ServiceName（当前 $($svc.Status)）"
      Stop-Service -Name $ServiceName -Force
      $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
  } else {
    Write-Log "服务 $ServiceName 不存在，跳过停止" 'WARN'
  }
  & sc.exe delete $ServiceName | Out-Null
  Write-Log "sc.exe delete 退出码=$LASTEXITCODE"
  Write-Log "Aegis Windows 服务已停止并删除（$ServiceName）。ProgramData 保留供取证。"
  Write-Output "Aegis Windows 服务已停止并删除（$ServiceName）。"
  exit 0
}

# ── 0) 前置完整性检查（HARD FAIL：包不完整时装了也不可能工作）──────────────
if (-not (Test-Path -LiteralPath $HostExe)) {
  Fail-Hard "缺少 $HostExe（MSI 包不完整或 File 表未落盘）。"
}
foreach ($f in 'aegis-windows.ps1', 'aegis-policy.json', 'aegis-security-baseline.md') {
  if (-not (Test-Path -LiteralPath (Join-Path $Base $f))) {
    # 基线/策略缺失不致命（服务端策略会覆盖），但扫描器脚本缺失致命。
    if ($f -eq 'aegis-windows.ps1') { Fail-Hard "缺少扫描器 $f（MSI 包不完整）。" }
    Write-Log "缺少可选运行时文件 $f，跳过" 'WARN'
  }
}

# ── 1) 运行时落地到 ProgramData（Agent 从 ProgramData 读策略/基线/上报配置）──
New-Item -ItemType Directory -Force -Path $Data, (Join-Path $Data 'reports'), (Join-Path $Data 'spool') | Out-Null
foreach ($f in 'aegis-windows.ps1', 'aegis-policy.json', 'aegis-security-baseline.md') {
  $src = Join-Path $Base $f
  if (Test-Path -LiteralPath $src) {
    try {
      Copy-Item -LiteralPath $src -Destination (Join-Path $Data $f) -Force
    } catch [System.UnauthorizedAccessException] {
      # BUG H/I 自愈: 旧版加固半途而废留下空 DACL(连 SYSTEM 都拒) → takeown+/reset 后重试一次
      Write-Log "落地 $f 被拒(空 DACL?)，takeown+icacls /reset 后重试" 'WARN'
      & takeown.exe /f $Data /r /d Y | Out-Null
      & icacls.exe $Data /reset /t /c | Out-Null
      Copy-Item -LiteralPath $src -Destination (Join-Path $Data $f) -Force
    }
  }
}
Write-Log "运行时已落地到 $Data"

# ── 2) 解析服务器地址 ──────────────────────────────────────────────────────
# D9：占位域判定（RFC2606 保留域永不解析）。必须先解析出 Host 再比对——
# 直接对完整 URL 做正则会被 "https://" 前缀或路径里的 example.com 绕过。
# URL 非法时返回 $false，让它落到下面 D1 的 TryCreate 分支给出可操作的报错。
function Test-PlaceholderOrigin {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Url)
  $u = $null
  if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u)) { return $false }
  return ($u.Host -match '(^|\.)(example\.(com|net|org)|invalid|test|localhost)$')
}

# 解析优先级：公开包烘的是占位域，必须允许装机时注入真实 origin，否则
# 「装得上但永远入不了网」——这正是 D1 想拦住的失败模式，只是拦在了错误的时机。
#   1) -ServerUrl            ← MSI 公共属性 AEGIS_SERVER_URL（类型 18 动作格式化注入）
#   1.5) 预留覆盖文件         ← 用户编辑即全自动，无需记 msiexec 参数：
#        C:\ProgramData\aegis-server.json 或 <安装基目录>\server-override.json
#   2) server.json           ← 构建期烘焙，且烘的不是占位域时才采纳
#   3) $env:AEGIS_SERVER_URL ← 机器级环境变量（deferred 动作以 SYSTEM 运行，读不到用户级）
$serverFile = Join-Path $Base 'server.json'
$baked = $null
if (Test-Path -LiteralPath $serverFile) {
  try {
    $baked = (Get-Content -Encoding UTF8 -LiteralPath $serverFile -Raw | ConvertFrom-Json).server_url
    Write-Log "server.json 解析成功"
  } catch {
    Fail-Hard "server.json 解析失败：$($_.Exception.Message)"
  }
}
# 预留覆盖文件（D4 同款 ProgramData 三级回落）：{"server_url":"https://<控制台>"}
$pdRoot = $env:ProgramData
if (-not $pdRoot) { $pdRoot = [Environment]::GetFolderPath('CommonApplicationData') }
if (-not $pdRoot) { $sd = $env:SystemDrive; if (-not $sd) { $sd = 'C:' }; $pdRoot = Join-Path $sd 'ProgramData' }
$ovServerUrl = $null
foreach ($ovf in @((Join-Path $pdRoot 'aegis-server.json'), (Join-Path $Base 'server-override.json'))) {
  if (Test-Path -LiteralPath $ovf) {
    try {
      $ovu = [string](Get-Content -Encoding UTF8 -LiteralPath $ovf -Raw | ConvertFrom-Json).server_url
      if ($ovu -and $ovu.StartsWith('https://')) { $ovServerUrl = $ovu.TrimEnd('/'); Write-Log "预留覆盖文件生效：$ovf"; break }
    } catch { }
  }
}

$server = $null
$serverSource = $null
if ($ServerUrl) {
  $server = $ServerUrl; $serverSource = 'MSI 属性 AEGIS_SERVER_URL'
} elseif ($ovServerUrl) {
  $server = $ovServerUrl; $serverSource = '预留覆盖文件（aegis-server.json / server-override.json）'
} elseif ($baked -and -not (Test-PlaceholderOrigin ([string]$baked))) {
  $server = $baked; $serverSource = 'server.json（构建期烘焙）'
} elseif ($env:AEGIS_SERVER_URL) {
  $server = $env:AEGIS_SERVER_URL; $serverSource = '机器级环境变量 AEGIS_SERVER_URL'
} else {
  # 只剩占位域或空值：原样交给下面的 D1/D2 守卫，由它们输出可操作的修复指引。
  $server = $baked; $serverSource = 'server.json（仍是占位域）'
}

if (-not $server) {
  Fail-Hard '未获得控制台地址：server.json 缺失或 server_url 为空，且未注入 AEGIS_SERVER_URL。'
}
$server = ([string]$server -replace '/+$', '')

# D1 修复：占位域防护（对齐 public/downloads/aegis-agent-windows-enroll.ps1 的既有检查）。
# RFC2606 保留域永不解析；静默装上一个永久无法入网的 agent 比安装失败更糟，故硬失败。
# 必须解析出 Host 再比对——直接对完整 URL 做正则会被 "https://" 前缀绕过。
$uri = $null
if (-not [Uri]::TryCreate($server, [UriKind]::Absolute, [ref]$uri)) {
  Fail-Hard "server_url 不是合法绝对 URL：'$server'"
}
if ($uri.Scheme -ne 'https') {
  Fail-Hard "server_url 必须为 https（Agent 的 load_reporting_config 强制 https）：'$server'"
}
$isPlaceholder = Test-PlaceholderOrigin $server
if ($isPlaceholder -and ($env:AEGIS_ALLOW_PLACEHOLDER_ORIGIN -ne '1')) {
  Fail-Hard @"
server_url 仍是 RFC2606 保留占位域 '$($uri.Host)'：公开包默认不含真实控制台地址。
修复（任选其一）：
  1) 装机时注入（推荐，公开包即为此设计）：
     msiexec /i aegis-agent-windows.msi AEGIS_SERVER_URL=https://<你的控制台>
  2) 自己构建时烘焙：
     AEGIS_PUBLIC_ORIGIN=https://<你的控制台> sh client/build-windows-msi.sh
  3) 机器级环境变量（deferred 动作以 SYSTEM 运行，用户级变量读不到）：
     setx /M AEGIS_SERVER_URL https://<你的控制台>
（本地功能测试可用 AEGIS_ALLOW_PLACEHOLDER_ORIGIN=1，但该包无法入网。）
"@
}
if ($isPlaceholder) {
  Write-Log "AEGIS_ALLOW_PLACEHOLDER_ORIGIN=1 已放行占位域 '$($uri.Host)'：入网必然失败，状态将记为 needs_enrollment。" 'WARN'
}
Write-Log "入网目标：$server（host=$($uri.Host)，来源=$serverSource）"

# TLS 硬化：Windows PowerShell 5.1 在旧 Win10/.NET<4.7 上默认不含 TLS1.2。
# 用 -bor 追加而非覆盖，避免关掉 SystemDefault 已协商的 TLS1.3。
try {
  [Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  Write-Log "SecurityProtocol=$([Net.ServicePointManager]::SecurityProtocol)"
} catch { Write-Log "设置 TLS1.2 失败（沿用系统默认）：$($_.Exception.Message)" 'WARN' }

# 设备 ID 优先硬件序列号（mac/win 统一；稳定，不随计算机名/升级/语言变化）；无则回落计算机名|域。
$sn = $null
try { $sn = (Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber } catch { $sn = $null }
if (-not $sn) { try { $sn = (Get-CimInstance Win32_BIOS).SerialNumber } catch { $sn = $null } }
$badSn = @('', 'To be filled by O.E.M.', 'None', 'Default string', 'Unknown', 'O.E.M.', 'Not Specified')
if ($sn -and ($badSn -notcontains $sn.Trim())) { $deviceMaterial = "aegis-hw:" + $sn.Trim() } else { $deviceMaterial = "$env:COMPUTERNAME|$env:USERDOMAIN" }
$sha = [Security.Cryptography.SHA256]::Create()
$deviceId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-', '').Substring(0, 12).ToLower()
$sha.Dispose()
Write-Log "device_id=$deviceId（12位小写hex，服务端据此签发 per-device 令牌）"

# ── 3) 零接触入网（D3 修复：瞬态故障 → SOFT FAIL，不回滚安装）──────────────
# D5 修复：PS 5.1 需显式加载 System.Security 才有 ProtectedData；PS 7 类型内置、无此程序集
if (-not ('Security.Cryptography.ProtectedData' -as [type])) {
  try { Add-Type -AssemblyName System.Security } catch { Write-Log "Add-Type System.Security 失败：$($_.Exception.Message)" 'WARN' }
}
$body = @{ hostname = $env:COMPUTERNAME; device_id = $deviceId; agent_version = '0.34.9' } | ConvertTo-Json -Compress
$enroll = $null
$enrollError = $null
for ($attempt = 1; $attempt -le 3; $attempt++) {
  try {
    $enroll = Invoke-RestMethod -Uri "$server/api/enroll" -Method Post `
      -ContentType 'application/json' -Body $body -TimeoutSec 30
    Write-Log "入网成功（第 $attempt 次尝试）"
    break
  } catch {
    $enrollError = $_.Exception.Message
    $httpCode = $null
    if ($_.Exception.Response) { $httpCode = [int]$_.Exception.Response.StatusCode }
    Write-Log "入网第 $attempt/3 次失败（HTTP=$httpCode）：$enrollError" 'WARN'
    if ($attempt -lt 3) { Start-Sleep -Seconds ($attempt * 5) }
  }
}

$enrolled = $false
if ($enroll) {
  # 令牌/密钥契约校验（对齐 aegis-agent-windows-enroll.ps1 第 86-87 行的既有检查）
  $tok = if ($enroll.report_token) { [string]$enroll.report_token } else { '' }
  $sec = if ($enroll.signing_secret) { [string]$enroll.signing_secret } else { '' }
  if ($tok.Length -lt 32 -or $tok.Length -gt 4096) {
    Write-Log "report_token 长度 $($tok.Length) 不在 32-4096（服务端未配置 AEGIS_COLLECTOR_TOKEN？）" 'ERROR'
    $enrollError = 'report_token_invalid'
  } else {
    if (-not $sec) { $sec = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }) }
    if ($sec.Length -lt 32 -or $sec -ceq $tok) {
      $sec = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
      Write-Log 'signing_secret 不满足契约（需32+且不同于令牌），已本地重新生成' 'WARN'
    }
    $reportUrl = if ($enroll.report_url) { [string]$enroll.report_url } else { "$server/aegis/v1/reports" }
    if ($reportUrl -notmatch '^https://') {
      Write-Log "report_url 非 https，拒绝写入：$reportUrl" 'ERROR'
      $enrollError = 'report_url_not_https'
    } else {
      if ($enroll.policy) {
        Set-Content -LiteralPath (Join-Path $Data 'aegis-policy.json') `
          -Value ($enroll.policy | ConvertTo-Json -Depth 24) -Encoding UTF8
        Write-Log "已写入服务端策略 version=$($enroll.policy_version)"
      } else {
        Write-Log '服务端无已发布策略，沿用包内出厂策略' 'WARN'
      }

      $cfg = [pscustomobject]@{
        schema = 'aegis.reporting/v1'; report_url = $reportUrl
        report_token = $tok; signing_secret = $sec
      }
      $json = $cfg | ConvertTo-Json -Compress
      $entropy = [Text.Encoding]::UTF8.GetBytes('AegisAgent.Reporting.v1')
      # D5：ProtectedData 在 PS 5.1 未加载 System.Security 时无法解析类型，EAP=Stop 下会终止进程。
      # 收敛为 SOFT FAIL：DPAPI 写不进只影响上报，不该让整个安装回滚（对齐 D3 哲学）。
      try {
        $enc = [Security.Cryptography.ProtectedData]::Protect(
          [Text.Encoding]::UTF8.GetBytes($json), $entropy,
          [Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes((Join-Path $Data 'reporting.dpapi'), $enc)
        # 清零明文副本（原实现只清 $json，这里连 tok/sec 一并清）
        $json = $null; $tok = $null; $sec = $null; $cfg = $null
        Write-Log "reporting.dpapi 已写入（DPAPI LocalMachine，entropy=AegisAgent.Reporting.v1）"
        Write-Log "report_url=$reportUrl"
        $enrolled = $true
      } catch {
        $json = $null; $tok = $null; $sec = $null; $cfg = $null
        $enrollError = "dpapi_protect_failed: $($_.Exception.Message)"
        Write-Log $enrollError 'ERROR'
        Write-EnrollmentStatus -State 'needs_enrollment' -Reason 'dpapi_protect_failed' -Server $server
      }
    }
  }
}

if (-not $enrolled) {
  # SOFT FAIL：不回滚安装。服务照常注册，控制台可据 enrollment-status.json 识别「已装未入网」。
  Write-Log "入网未完成，安装继续（服务仍会注册，可稍后重跑本脚本 -Uninstall 后重装，或修复网络后重启服务）。原因：$enrollError" 'WARN'
  Write-EnrollmentStatus -State 'needs_enrollment' -Reason ([string]$enrollError) -Server $server
} else {
  Write-EnrollmentStatus -State 'enrolled' -Server $server
}

# ── 4) 收紧 ProgramData\AegisAgent 权限（SYSTEM/管理员完全控制，用户只读执行）──
# D6 修复：ACL 收紧是尽力而为的加固步骤，不该有能力终结整个安装。EAP=Stop 下裸调
# & icacls.exe 一旦无法启动（被安全软件拦截 / 受限环境）就以退出码 1 静默终止，
# MSI 侧只剩无上下文的 1722。失败降级为 WARN，目录保持默认 ACL，安装继续。
try {
  # BUG I 修法: 先 /reset /t 清历史坏 ACL(空 DACL 自愈); 目录级 grant 带 (OI)(CI) 但**不带 /T**
  # (继承只作用于新子对象); 既有子文件单独显式授权(**不带继承标志**, 避免 (OI)(CI) 落在文件上
  # 逐文件失败而继承 ACE 已被剥光 → 空 DACL 锁死配置/上报, 即 BUG I)。
  & icacls.exe $Data /reset /t /c | Out-Null
  & icacls.exe $Data /inheritance:r /C | Out-Null
  & icacls.exe $Data /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /C | Out-Null
  & icacls.exe $Data /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' /T /C | Out-Null
  Write-Log "icacls 收紧退出码=$LASTEXITCODE"
  # 加固后自检: 抽一个子文件, 若 Access 为空视为加固失败 → /reset 回退并记 ERROR,
  # 绝不能让"收紧"产出比默认更糟的状态(空 DACL)。
  $probe = Join-Path $Data 'aegis-policy.json'
  if (Test-Path -LiteralPath $probe) {
    $acl = Get-Acl -LiteralPath $probe -ErrorAction SilentlyContinue
    if ($acl -and @($acl.Access).Count -eq 0) {
      Write-Log "加固自检失败(子文件空 DACL)，回退 /reset" 'ERROR'
      & icacls.exe $Data /reset /t /c | Out-Null
    }
  }
  # BUG D：诊断文件（install.log / enrollment-status.json）显式给 Administrators 只读，
  # 否则提权管理员也读不到、现场排障取不到关键入网日志。SYSTEM 保持完全控制。
  foreach ($diag in @((Join-Path $Data 'install.log'), $StatusPath)) {
    if (Test-Path -LiteralPath $diag) {
      & icacls.exe $diag /grant:r '*S-1-5-32-544:RX' '*S-1-5-18:F' /C | Out-Null
    }
  }
} catch {
  Write-Log "icacls 权限收紧失败（不影响服务注册与运行，目录保持默认 ACL）：$($_.Exception.Message)" 'WARN'
}

# ── 5) 注册并启动 SCM 服务 ─────────────────────────────────────────────────
# D8 修复（本机 MSI 端到端实测抓到的最终硬阻塞）：
# 原实现 & sc.exe create ... "binPath= `"$HostExe`" --service" 在 Windows PowerShell 5.1
# 下传原生命令参数时**不会转义内嵌双引号**（PS 5.1 长期缺陷），带空格路径
# （默认 C:\Program Files\AegisAgent）被 sc.exe 在空格处截断 →
# sc 返回 1639（ERROR_INVALID_PARAMETER）并打印用法 → 服务永远注册不上 →
# Fail-Hard 70 → MSI 1722。实测面包屑：SC exit=1639 + sc 用法帮助全文。
# 修复：改用 New-Service cmdlet —— BinaryPathName 是强类型字符串参数，
# 不经原生命令行重组，带空格路径+参数原样写入 ImagePath；不指定 -Credential
# 即 LocalSystem（与原 obj= 等价）。delayed-auto 与失败恢复动作用 sc.exe
# 仅按服务名补配（无路径引号问题；D7 的启动失败防护仍适用于这些调用）。
$binPath = "`"$HostExe`" --service"
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
try {
  if ($existing) {
    if ($existing.Status -ne 'Stopped') {
      Write-Log "已存在服务（$($existing.Status)），先停止并删除重建"
      Stop-Service -Name $ServiceName -Force
      $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    } else {
      Write-Log '已存在服务（Stopped），删除重建'
    }
    # PS 5.1 的 Set-Service 没有 -BinaryPathName；删除重建以保证 binPath 与当前安装目录一致。
    # sc.exe delete 只带服务名，无引号问题。
    & sc.exe delete $ServiceName | Out-Null
    for ($i = 0; $i -lt 30 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
  }
  New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'Aegis AI Agent Security' `
    -Description 'Aegis 固定功能 AI Agent 安全扫描服务；无任意命令通道。' -StartupType Automatic | Out-Null
  Write-Log "服务已创建（New-Service, binPath=$binPath, LocalSystem）"
} catch {
  # HARD FAIL：服务注册失败意味着 agent 根本不可能运行（D7：启动失败与非零退出同等待遇）。
  Fail-Hard "SCM 服务注册失败: $($_.Exception.Message)" 70
}
# delayed-auto + 失败恢复动作：仅按服务名，无路径引号问题；失败不阻断安装（同 D6 哲学）
try {
  & sc.exe config $ServiceName start= delayed-auto | Out-Null
  & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
  Write-Log '已设置 delayed-auto 与失败恢复动作（restart/60s x3）'
} catch {
  Write-Log "sc.exe config/failure 失败（服务已注册，不影响运行）：$($_.Exception.Message)" 'WARN'
}
Write-Log "服务已注册（delayed-auto, LocalSystem, 失败自动重启）"

# D3 修复：服务启动失败 → SOFT FAIL。
# 时限 30s→60s：单文件自包含 .NET 首次运行需把原生库解压到 %TEMP%\.net\，
# 在 ARM64 的 x64 模拟层下更慢；30s 会在慢机器上误判为失败并回滚整个安装。
$serviceRunning = $false
try {
  Start-Service -Name $ServiceName
  (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
  $serviceRunning = $true
  Write-Log '服务已进入 Running'
} catch {
  Write-Log "服务未在 60s 内进入 Running：$($_.Exception.Message)" 'WARN'
  Write-Log '服务已注册，SCM 失败动作（restart/60s）会继续尝试拉起。' 'WARN'
  Write-Log '排查：sc.exe qc AegisAgent；事件查看器 → 系统 → 来源 Service Control Manager；' 'WARN'
  Write-Log "      以及 $LogPath 与 $(Join-Path $Data 'service-health.json')" 'WARN'
}

# ── 6) 汇总 ────────────────────────────────────────────────────────────────
if ($enrolled -and $serviceRunning) {
  Write-Log '=== 安装完成：已入网 + 服务运行中 ==='
  Write-Output "Aegis Windows SCM 服务已安装并启动；已零接触入网到 $server。"
} elseif ($serviceRunning) {
  Write-Log '=== 安装完成：服务运行中，但尚未入网（见 enrollment-status.json）===' 'WARN'
  Write-Output "Aegis 服务已安装并启动，但入网未完成（$enrollError）。修复网络/控制台后重启服务即可。"
} else {
  Write-Log '=== 安装完成：文件与服务已注册，但服务未运行、入网状态见上 ===' 'WARN'
  Write-Output 'Aegis 已安装，但服务未进入运行状态；详见 install.log。'
}
Write-Log "日志：$LogPath"

# 关键：只要「包完整 + 配置正确 + 服务已注册」就返回 0。
# 网络/时序类故障不再回滚安装——这是与 macOS 入网脚本对齐的容错语义。
exit 0
