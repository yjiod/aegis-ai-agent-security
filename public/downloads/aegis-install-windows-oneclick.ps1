# Install-Aegis-Windows-OneClick.ps1 — Windows 一键安装/修复 Aegis Agent
# 用法(管理员 PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Aegis-Windows-OneClick.ps1
# 可选参数:
#   -Server  https://<控制台>          必填(仓库副本为占位域且拒绝运行; 控制台副本已注入真实 origin)
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
# 占位判定用"主机名后缀"而非完整占位 URL 字面量: 部署注入是对全文做
# s|https://aegis.example.com|<真实origin>|g, 守卫里若也写完整占位 URL 会被一并替换成
# 真实 origin → 守卫恒真 → 注入副本反而拒绝运行(真机捕获的自伤 bug)。后缀模式不含该字面量, 注入改不动它。
$_u = $null
$_placeholder = $true
if ([Uri]::TryCreate($Server, [UriKind]::Absolute, [ref]$_u)) {
  $_placeholder = ($_u.Host -match '(^|\.)example\.(com|net|org)$') -or ($_u.Host -in @('invalid', 'localhost', 'test'))
}
if ($_placeholder) {
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
  # 经 cmd /c 做原生重定向: PS5.1 + EAP=Stop 下原生 exe 的 stderr 会变终止性错误
  # (2>$null / 2>&1 都拦不住, 真机两次捕获), 会让脚本中途死掉。cmd 自己吞 stderr 最稳。
  cmd /c "takeown /f `"$pd`" /r /d Y >nul 2>nul"
  cmd /c "icacls `"$pd`" /reset /t /c >nul 2>nul"
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
# 用无空格的 .cmd 包装器调安装脚本: .cmd 里的双引号是字面量(不经过 PS 剥离),
# schtasks /TR 只需一个无空格路径 —— 彻底绕开 PS5.1 调原生 exe 的引号剥离问题
# (内嵌双引号被剥 / -Command & 'path' 被 schtasks 打散, 两种形态都实测失败过)。
$wrap = 'C:\Windows\Temp\AegisOneClickRun.cmd'
Set-Content -LiteralPath $wrap -Value ('@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\AegisAgent\Install-Aegis-Windows.ps1" -ServerUrl ' + $Server) -Encoding ASCII
$tr = $wrap
# schtasks 一律经 cmd /c 并由 cmd 做 >nul 2>nul: PS5.1 + EAP=Stop 下原生 exe 的 stderr
# 是终止性错误(2>$null / 2>&1 均拦不住, 真机捕获两次, 第二次甚至让脚本中途死掉)。
cmd /c "schtasks /Delete /TN AegisOneClick /F >nul 2>nul"
cmd /c "schtasks /Create /TN AegisOneClick /SC ONCE /ST 00:00 /RU SYSTEM /F /TR $tr >nul 2>nul"
cmd /c "schtasks /Run /TN AegisOneClick >nul 2>nul"
Log '已触发 SYSTEM 安装任务, 等待完成...'
$ok = $false
$elapsed = 0
for ($i = 0; $i -lt $WaitSeconds; $i += 5) {
  Start-Sleep -Seconds 5
  $elapsed += 5
  # 每 15s 打一行进度: 此前等待期完全静默, 真机用户误以为脚本卡死(实际 SYSTEM 任务
  # 入网+建服务本身要 1~2 分钟)。有输出才看得出"活着"。
  if ($elapsed % 15 -eq 0) { Log ("等待 SYSTEM 安装任务... {0}s / {1}s" -f $elapsed, $WaitSeconds) }
  $q = (cmd /c "schtasks /Query /TN AegisOneClick /V /FO LIST 2>nul") -join "`n"
  if ($q -match 'Last Result[^:]*:\s*(\d+)') {
    $code = [int]$Matches[1]
    if ($code -eq 0) { $ok = $true; Log ('SYSTEM 安装任务完成(耗时约 {0}s)' -f $elapsed); break }
    if ($code -ne 267011) { Log ('SYSTEM 任务退出码 ' + $code + ' (非0即失败, 267011=仍在运行)'); break }
  }
}
cmd /c "schtasks /Delete /TN AegisOneClick /F >nul 2>nul"
if (-not $ok) { Log 'SYSTEM 安装任务未在时限内成功; 可重跑本脚本或按 Issue#2 恢复手册排查' }

# 5) 验收
Start-Sleep -Seconds 10
$svc = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'" -ErrorAction SilentlyContinue
if ($svc) { Log ('服务: ' + $svc.State + ' / ' + $svc.StartMode + ' / ' + $svc.StartName) }
else { Log '服务未建(BUG G?): 重跑本脚本或手动执行第4步 schtasks 命令' }
$us = Join-Path $env:ProgramData 'AegisAgent\upload-status.json'
if (Test-Path $us) { Log ('upload-status: ' + (Get-Content -Encoding UTF8 $us -Raw).Trim()) }
else { Log 'upload-status 尚未生成: 首报需一个扫描周期(默认1小时), 或配置不可读(见 BUG I)' }
Log '完成。刷新控制台应出现新设备(序列号 + 版本 + 工具列)。'
