# Install-Aegis-Interactive.ps1 — 交互式安装：提示输入控制台地址后自动注入安装。
# 用法（管理员 PowerShell）：右键"以管理员身份运行"，或 powershell -File .\Install-Aegis-Interactive.ps1
# 也可不交互：预先创建 C:\ProgramData\aegis-server.json（{"server_url":"https://<控制台>"}）
# 或直接 msiexec /i aegis-agent-windows.msi AEGIS_SERVER_URL=https://<控制台>
# 安装后仍可随时编辑 %ProgramData%\AegisAgent\server-override.json 切换控制台（全自动）。
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$msi = Join-Path $PSScriptRoot 'aegis-agent-windows.msi'
if (-not (Test-Path -LiteralPath $msi)) { Write-Host "未在同目录找到 aegis-agent-windows.msi" -ForegroundColor Red; exit 1 }
$server = $env:AEGIS_SERVER_URL
if (-not $server) {
  $server = Read-Host "请输入控制台地址（https://<主机>，直接回车取消）"
}
$server = ([string]$server).Trim().TrimEnd('/')
if (-not $server) { Write-Host "已取消。" ; exit 0 }
if (-not $server.StartsWith('https://')) { Write-Host "控制台地址必须是 https:// 开头。" -ForegroundColor Red; exit 1 }
Write-Host "使用控制台: $server 开始安装…"
$proc = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", "AEGIS_SERVER_URL=$server", '/qn', '/l*v', "$env:TEMP\aegis-install.log") -Wait -PassThru
if ($proc.ExitCode -ne 0) {
  Write-Host "安装失败，ExitCode=$($proc.ExitCode)。日志: $env:TEMP\aegis-install.log" -ForegroundColor Red
  exit $proc.ExitCode
}
Write-Host "安装完成。服务 AegisAgent 已注册；如需改控制台，编辑 %ProgramData%\AegisAgent\server-override.json 即可全自动切换。" -ForegroundColor Green
