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
#>
[CmdletBinding()]
param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$ServiceName = 'AegisAgent'
$Base = $PSScriptRoot                                   # 安装目录（Program Files\AegisAgent）
$Data = Join-Path $env:ProgramData 'AegisAgent'         # 运行数据目录（Agent 从此读取配置）
$HostExe = Join-Path $Base 'AegisServiceHost.exe'

if ($Uninstall) {
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) { if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } }
  & sc.exe delete $ServiceName | Out-Null
  Write-Output "Aegis Windows 服务已停止并删除（$ServiceName）。"
  return
}

# 1) 运行时落地到 ProgramData（Agent 从 ProgramData 读策略/基线/上报配置）
New-Item -ItemType Directory -Force -Path $Data, (Join-Path $Data 'reports'), (Join-Path $Data 'spool') | Out-Null
foreach ($f in 'aegis-windows.ps1', 'aegis-policy.json', 'aegis-security-baseline.md') {
  $src = Join-Path $Base $f
  if (Test-Path $src) { Copy-Item $src (Join-Path $Data $f) -Force }
}

# 2) 零接触自动入网 + DPAPI 写 reporting.dpapi
$serverFile = Join-Path $Base 'server.json'
$server = if (Test-Path $serverFile) { (Get-Content $serverFile -Raw | ConvertFrom-Json).server_url } else { $env:AEGIS_SERVER_URL }
if (-not $server) { throw "缺少 server.json/server_url（构建未注入服务器地址）。" }
$server = ($server -replace '/+$', '')
$deviceMaterial = "$env:COMPUTERNAME|$env:USERDOMAIN"
$sha = [Security.Cryptography.SHA256]::Create()
$deviceId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-', '').Substring(0, 12).ToLower()
$sha.Dispose()
$body = @{ hostname = $env:COMPUTERNAME; device_id = $deviceId; agent_version = '0.32.0' } | ConvertTo-Json -Compress
$enroll = Invoke-RestMethod -Uri "$server/api/enroll" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 30
if (-not $enroll.report_token) { throw '入网响应缺少 report_token（服务端未配置上报令牌？）。' }
$reportUrl = if ($enroll.report_url) { [string]$enroll.report_url } else { "$server/aegis/v1/reports" }
$secret = if ($enroll.signing_secret) { [string]$enroll.signing_secret } else { -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }) }
if ($enroll.policy) { Set-Content -Path (Join-Path $Data 'aegis-policy.json') -Value ($enroll.policy | ConvertTo-Json -Depth 24) -Encoding UTF8 }

$cfg = [pscustomobject]@{ schema = 'aegis.reporting/v1'; report_url = $reportUrl; report_token = [string]$enroll.report_token; signing_secret = $secret }
$json = $cfg | ConvertTo-Json -Compress
$entropy = [Text.Encoding]::UTF8.GetBytes('AegisAgent.Reporting.v1')
$enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($json), $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
[IO.File]::WriteAllBytes((Join-Path $Data 'reporting.dpapi'), $enc)
$json = $null

# 3) 收紧 ProgramData\AegisAgent 权限（SYSTEM/管理员完全控制，用户只读执行）
& icacls.exe $Data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
& icacls.exe $Data /grant:r '*S-1-5-32-545:RX' /C | Out-Null

# 4) 注册并启动 SCM 服务
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
if ($existing) {
  & sc.exe config $ServiceName "binPath= `"$HostExe`" --service" 'start= delayed-auto' 'obj= LocalSystem' | Out-Null
} else {
  & sc.exe create $ServiceName "binPath= `"$HostExe`" --service" 'start= delayed-auto' 'obj= LocalSystem' "DisplayName= Aegis AI Agent Security" | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "SCM 服务注册失败: $LASTEXITCODE" }
& sc.exe description $ServiceName 'Aegis 固定功能 AI Agent 安全扫描服务；无任意命令通道。' | Out-Null
& sc.exe failure $ServiceName 'reset= 86400' 'actions= restart/60000/restart/60000/restart/60000' | Out-Null
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Output "Aegis Windows SCM 服务已安装并启动；已零接触入网到 $server。"
