# Install-Aegis-Windows-OneClick.ps1 — Windows 一键安装/修复 Aegis Agent
# 用法(管理员 PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Aegis-Windows-OneClick.ps1
# 可选参数:
#   -Server  https://<控制台>          默认 https://REDACTED_DOMAIN
#   -MsiUrl  <url>                    覆盖 msi 下载地址
#   -MsiPath <本地msi路径>             跳过下载
#   -WaitSeconds <秒>                 等待 SYSTEM 安装任务的上限, 默认 120
# 流程: 提权自检 → 旧版残留清理(卸载 BUG F 绕过 + 破空 DACL BUG H) → 下载 msi →
#       msiexec /qn 装文件(BUG G: 服务不建) → SYSTEM 补跑安装脚本(建服务+入网+ACL) → 验收
# 注意: 本脚本须以 UTF-8 BOM 保存(PS 5.1 zh-CN 无 BOM 会把中文嚼碎致语法错误, D0)。
param(
  [string]$Server = 'https://aegis.example.com',
  [string]$MsiUrl = '',
  [string]$MsiPath = '',
  [int]$WaitSeconds = 120
)
$ErrorActionPreference = 'Stop'
$Server = $Server.TrimEnd('/')
# 隐私红线: 仓库/GitHub 副本恒为 RFC2606 占位域且拒绝运行; 真实 origin 由
# -Server 传入, 或使用你控制台 /downloads/ 下的定制副本(部署时注入真实 origin)。
if ($Server -eq 'https://aegis.example.com') {
  Write-Host '请用 -Server https://<你的控制台> 运行; 或直接下载你控制台 /downloads/ 下的定制副本(已注入真实 origin)。' -ForegroundColor Red
  exit 2
}
if (-not $MsiUrl) { $MsiUrl = $Server + '/downloads/aegis-agent-windows.msi' }
$work = Join-Path $env:TEMP 'aegis-oneclick'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$log = Join-Path $work 'install.log'
$msi = Join-Path $work 'aegis-agent-windows.msi'
function Log([string]$m) { Write-Host ('[aegis] ' + $m) }

# 0) 提权自检
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($ident)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host '请以管理员身份运行本脚本(右键 PowerShell → 以管理员身份运行)。' -ForegroundColor Red
  exit 2
}

# 1) 旧版残留清理: 卸载(BUG F 绕过: 假 UPGRADINGPRODUCTCODE 跳过 2762 的 deferred CA) + 破空 DACL(BUG H)
$prod = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Aegis*' } | Select-Object -First 1
if ($prod) {
  Log ('发现已安装产品 ' + $prod.DisplayName + ' ' + $prod.DisplayVersion + ', 先卸载(BUG F 绕过)')
  $p = Start-Process msiexec.exe -ArgumentList @('/x', $prod.PSChildName, 'UPGRADINGPRODUCTCODE={11111111-2222-3333-4444-555555555555}', '/qn', '/l*v', (Join-Path $work 'uninstall.log')) -Wait -PassThru
  Log ('卸载退出码 ' + $p.ExitCode)
}
$pd = Join-Path $env:ProgramData 'AegisAgent'
if (Test-Path $pd) {
  Log '清理 ProgramData 空 DACL(BUG H 自愈: takeown + /reset + 删目录)'
  & takeown.exe /f $pd /r /d Y | Out-Null
  & icacls.exe $pd /reset /t /c | Out-Null
  Remove-Item $pd -Recurse -Force -ErrorAction SilentlyContinue
}

# 2) 下载 msi (msiexec 直装 https 会撞 WinHTTP 12150, 故先下载再本地装)
if ($MsiPath) { $msi = $MsiPath; Log ('使用本地 msi: ' + $msi) }
else {
  Log ('下载 ' + $MsiUrl)
  Invoke-WebRequest -Uri $MsiUrl -OutFile $msi -UseBasicParsing
}
if (-not (Test-Path $msi)) { Log ('msi 不存在: ' + $msi); exit 3 }

# 3) 装文件 (BUG G: MSI 不建服务, 第 4 步以 SYSTEM 补)
Log 'msiexec 安装文件(服务稍后由 SYSTEM 补建)'
$p = Start-Process msiexec.exe -ArgumentList @('/i', ('"' + $msi + '"'), ('AEGIS_SERVER_URL=' + $Server), '/qn', '/l*v', $log) -Wait -PassThru
Log ('msiexec 退出码 ' + $p.ExitCode)
if ($p.ExitCode -ne 0) { Log ('安装失败, 日志: ' + $log); exit 4 }

# 4) SYSTEM 补跑安装脚本(建服务 + 零接触入网 + ACL)
$installPs1 = Join-Path $env:ProgramFiles 'AegisAgent\Install-Aegis-Windows.ps1'
if (-not (Test-Path $installPs1)) { Log ('缺少安装脚本: ' + $installPs1); exit 5 }
# 把安装脚本复制到无空格路径, /TR 只需一层外引号(内嵌引号在 PS5.1 调原生 exe 时会被剥掉,
# 路径在 'Program Files' 空格处断开 —— 上一版正是这么坏的)
$tmpPs1 = 'C:\Windows\Temp\AegisOneClickInstall.ps1'
Copy-Item -LiteralPath $installPs1 -Destination $tmpPs1 -Force
$tr = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + $tmpPs1 + ' -ServerUrl ' + $Server
& schtasks.exe /Delete /TN AegisOneClick /F 2>$null | Out-Null
& schtasks.exe /Create /TN AegisOneClick /SC ONCE /ST 00:00 /RU SYSTEM /F /TR $tr 2>$null | Out-Null
& schtasks.exe /Run /TN AegisOneClick 2>$null | Out-Null
Log '已触发 SYSTEM 安装任务, 等待完成...'
$ok = $false
for ($i = 0; $i -lt $WaitSeconds; $i += 5) {
  Start-Sleep -Seconds 5
  $q = (& schtasks.exe /Query /TN AegisOneClick /V /FO LIST 2>$null) -join "`n"
  if ($q -match 'Last Result[^:]*:\s*(\d+)') {
    $code = [int]$Matches[1]
    if ($code -eq 0) { $ok = $true; break }
    if ($code -ne 267011) { Log ('SYSTEM 任务退出码 ' + $code + ' (非0即失败, 267011=仍在运行)'); break }
  }
}
& schtasks.exe /Delete /TN AegisOneClick /F 2>$null | Out-Null
if (-not $ok) { Log 'SYSTEM 安装任务未在时限内成功; 可重跑本脚本或按 Issue#2 恢复手册排查' }

# 5) 验收
Start-Sleep -Seconds 10
$svc = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'" -ErrorAction SilentlyContinue
if ($svc) { Log ('服务: ' + $svc.State + ' / ' + $svc.StartMode + ' / ' + $svc.StartName) }
else { Log '服务未建(BUG G?): 重跑本脚本或手动执行第4步 schtasks 命令' }
$us = Join-Path $env:ProgramData 'AegisAgent\upload-status.json'
if (Test-Path $us) { Log ('upload-status: ' + (Get-Content $us -Raw).Trim()) }
else { Log 'upload-status 尚未生成: 首报需一个扫描周期(默认1小时), 或配置不可读(见 BUG I)' }
Log '完成。刷新控制台应出现新设备(序列号 + 版本 + 工具列)。'
