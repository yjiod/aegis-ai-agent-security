# apply-win-lite.ps1 — 应用 win 轻量推送包(提权 PowerShell): 校验 sha256 → 换扫描器/安装脚本(含 host exe 时一并) → Restart-Service。
# 不触碰 reporting.dpapi / 入网。用法: powershell -NoProfile -ExecutionPolicy Bypass -File .\apply-win.ps1
$ErrorActionPreference = 'Stop'
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($ident)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host '需管理员' -ForegroundColor Red; exit 2 }
$here = $PSScriptRoot
$man = Join-Path $here 'PUSH-MANIFEST.json'
if (-not (Test-Path $man)) { Write-Host '缺 PUSH-MANIFEST.json' -ForegroundColor Red; exit 3 }
$m = Get-Content -Encoding UTF8 $man -Raw | ConvertFrom-Json
$bad = @()
foreach ($p in $m.components.PSObject.Properties) {
  $f = Join-Path $here $p.Name
  if (-not (Test-Path $f)) { $bad += ($p.Name + ':missing'); continue }
  $got = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $p.Value.ToLower()) { $bad += ($p.Name + ':sha') }
}
if ($bad.Count -gt 0) { Write-Host ('组件校验失败: ' + ($bad -join ', ')) -ForegroundColor Red; exit 4 }
Write-Host ('组件校验通过: ' + (($m.components.PSObject.Properties.Name) -join ', '))
$dst = Join-Path $env:ProgramFiles 'AegisAgent'
if (-not (Test-Path $dst)) { Write-Host '未找到安装目录(先装一次完整 .msi)' -ForegroundColor Red; exit 5 }
# 先停服务再拷：host exe(AegisServiceHost.exe)在服务运行时被锁定，直接 Copy-Item -Force 覆盖会
# 报"文件被占用"并（ErrorActionPreference=Stop）中断。停服务→拷贝→启服务，exe/脚本都能安全替换。
Stop-Service AegisAgent -Force -ErrorAction SilentlyContinue
foreach ($p in $m.components.PSObject.Properties) { Copy-Item -LiteralPath (Join-Path $here $p.Name) -Destination (Join-Path $dst $p.Name) -Force }
$svc = Get-Service AegisAgent -ErrorAction SilentlyContinue
if ($svc) { Start-Service AegisAgent; Write-Host ('服务已启动: ' + (Get-Service AegisAgent).Status) }
else { Write-Host '服务不存在: 用一键脚本/完整 .msi 先注册服务' }
Write-Host '已应用轻量包; 版本见 PUSH-MANIFEST.json'
