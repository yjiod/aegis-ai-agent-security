<#
.SYNOPSIS
  Aegis 终端 Windows 入网安装器（零接触自动纳管）。以管理员身份运行。

.DESCRIPTION
  与 macOS 的 .pkg/.run 等价：装完即被纳管，无需手动下发令牌。步骤：
    1) 从 <Server>/downloads 下载 Agent 运行时（aegis-windows.ps1 / aegis-policy.json /
       aegis-security-baseline.md）到 %ProgramData%\AegisAgent；
    2) 零接触自动入网：POST <Server>/api/enroll 取回 report_token + 每设备 signing_secret
       + 当前已发布策略（去签名，经 TLS 信任落地）；也可用 -Token 手动指定；
    3) 按 aegis-windows.ps1 的契约用 DPAPI(LocalMachine, entropy=AegisAgent.Reporting.v1)
       加密写 reporting.dpapi（{schema,report_url,report_token,signing_secret}）；
    4) 注册 SYSTEM 计划任务 AegisAgent 周期上报；
    5) 立即跑一次首报。

  服务器地址默认 RFC 占位 https://aegis.example.com（公开仓库不含真实主机）；真实环境用
  -Server 或环境变量 AEGIS_SERVER_URL 指定，或由原生 .exe 在构建时烘焙。

.PARAMETER Server
  Aegis 安全中心 origin，如 https://your-console。默认 $env:AEGIS_SERVER_URL 或占位域。

.PARAMETER Token
  可选：手动指定上报令牌。留空则零接触自动入网（推荐）。

.EXAMPLE
  # 以管理员打开 PowerShell：
  Set-ExecutionPolicy -Scope Process Bypass -Force
  iwr https://your-console/downloads/aegis-agent-windows-enroll.ps1 -OutFile enroll.ps1
  .\enroll.ps1 -Server https://your-console
#>
[CmdletBinding()]
param(
  [string]$Server = $(if ($env:AEGIS_SERVER_URL) { $env:AEGIS_SERVER_URL } else { 'https://aegis.example.com' }),
  [string]$Token  = $env:AEGIS_COLLECTOR_TOKEN,
  [int]$IntervalMinutes = 60,
  [switch]$Local   # 由原生 .exe 调用时置位：运行时已内嵌解压到 $Dir，跳过下载
)
$ErrorActionPreference = 'Stop'
$AgentVersion = '0.33.0'
$Dir = Join-Path $env:ProgramData 'AegisAgent'
$Base = ($Server -replace '/+$','')

# 必须以管理员运行：要写 %ProgramData%、注册 SYSTEM 计划任务、用 LocalMachine DPAPI。
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw '请以管理员身份运行（右键 PowerShell → 以管理员身份运行）。'
}
if ($Base -match 'example\.com$' -and -not $Token) {
  throw "Server 仍是占位域 $Base。请用 -Server https://你的控制台 指定真实地址（或设 AEGIS_SERVER_URL）。"
}

Write-Host "=== Aegis Windows 入网（自动纳管）==="
Write-Host "  安全中心 : $Base"
Write-Host "  安装目录 : $Dir"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# 1) 下载运行时（-Local 时运行时已由原生 .exe 内嵌解压到 $Dir，跳过下载）
if (-not $Local) {
  Write-Host "=== 1. 下载 Agent 运行时 ==="
  foreach ($f in 'aegis-windows.ps1','aegis-policy.json','aegis-security-baseline.md') {
    Invoke-WebRequest -Uri "$Base/downloads/$f" -OutFile (Join-Path $Dir $f) -UseBasicParsing
  }
} else {
  Write-Host "=== 1. 使用内嵌运行时（-Local）==="
}

# 2) 凭据与策略：自动入网（默认）或手动令牌
$ReportUrl = "$Base/aegis/v1/reports"
if (-not $Token) {
  Write-Host "=== 2. 零接触自动入网 ($Base/api/enroll) ==="
  $body = @{ hostname = $env:COMPUTERNAME; device_id = "WIN-$($env:COMPUTERNAME)"; agent_version = $AgentVersion } | ConvertTo-Json -Compress
  $enroll = Invoke-RestMethod -Uri "$Base/api/enroll" -Method Post -ContentType 'application/json' -Body $body
  if (-not $enroll.report_token) { throw '入网响应缺少 report_token（服务端未配置上报令牌？）' }
  $Token = [string]$enroll.report_token
  $Secret = [string]$enroll.signing_secret
  if ($enroll.report_url) { $ReportUrl = [string]$enroll.report_url }
  if ($enroll.policy) {
    Set-Content -Path (Join-Path $Dir 'aegis-policy.json') -Value ($enroll.policy | ConvertTo-Json -Depth 24) -Encoding UTF8
    Write-Host "  策略版本 : $($enroll.policy.version)"
  }
} else {
  Write-Host "=== 2. 手动令牌模式 ==="
  # 手动模式仍需一个 32+ 字符、不同于 token 的 signing_secret（Agent 上报契约要求）。
  $Secret = if ($env:AEGIS_REPORT_SIGNING_SECRET) { $env:AEGIS_REPORT_SIGNING_SECRET } else { -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }) }
}
if ($Token.Length -lt 32 -or $Token.Length -gt 4096) { throw "令牌长度 $($Token.Length) 不在 32-4096（很可能把占位符原样传入了）。" }
if ($Secret.Length -lt 32 -or $Secret -ceq $Token) { throw 'signing_secret 无效（需 32+ 且不同于令牌）。' }

# 3) DPAPI(LocalMachine) 加密写 reporting.dpapi —— 必须与 aegis-windows.ps1 的解密契约一致：
#    ProtectedData::Protect(UTF8(json), entropy=UTF8('AegisAgent.Reporting.v1'), LocalMachine)
Write-Host "=== 3. 写 DPAPI 受保护上报配置 ==="
$cfg = [pscustomobject]@{ schema='aegis.reporting/v1'; report_url=$ReportUrl; report_token=$Token; signing_secret=$Secret }
$json = $cfg | ConvertTo-Json -Compress
$entropy = [Text.Encoding]::UTF8.GetBytes('AegisAgent.Reporting.v1')
$enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($json), $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
$rp = Join-Path $Dir 'reporting.dpapi'
[IO.File]::WriteAllBytes($rp, $enc)
# 清零明文内存副本
$json = $null; $Token = $null; $Secret = $null

# 4) 注册 SYSTEM 计划任务（周期上报；开机/登录无关，以 SYSTEM 运行）
Write-Host "=== 4. 注册计划任务 AegisAgent（每 $IntervalMinutes 分钟，SYSTEM）==="
$agent = Join-Path $Dir 'aegis-windows.ps1'
$tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$agent`""
schtasks.exe /Create /TN 'AegisAgent' /TR $tr /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F | Out-Null

# 5) 立即首报
Write-Host "=== 5. 立即首报 ==="
try { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agent } catch { Write-Host "  首报异常：$($_.Exception.Message)" }
Write-Host "=== 完成。Aegis 安全中心应很快显示本机（$env:COMPUTERNAME）在线。==="
