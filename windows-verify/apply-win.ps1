# apply-win-lite.ps1 — 应用 win 轻量推送包(提权 PowerShell): 校验 sha256 → 换扫描器/安装脚本(含 host exe 时一并) → Restart-Service。
# 不触碰 reporting.dpapi / 入网。用法: powershell -NoProfile -ExecutionPolicy Bypass -File .\apply-win.ps1
$ErrorActionPreference = 'Stop'
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($ident)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host '需管理员' -ForegroundColor Red; exit 2 }
$here = $PSScriptRoot
$man = Join-Path $here 'PUSH-MANIFEST.json'
if (-not (Test-Path $man)) { Write-Host '缺 PUSH-MANIFEST.json' -ForegroundColor Red; exit 3 }
$m = Get-Content $man -Raw | ConvertFrom-Json
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
foreach ($p in $m.components.PSObject.Properties) { Copy-Item -LiteralPath (Join-Path $here $p.Name) -Destination (Join-Path $dst $p.Name) -Force }
$svc = Get-Service AegisAgent -ErrorAction SilentlyContinue
if ($svc) { Restart-Service AegisAgent -Force; Write-Host ('服务已重启: ' + (Get-Service AegisAgent).Status) }
else { Write-Host '服务不存在: 用一键脚本/完整 .msi 先注册服务' }
Write-Host '已应用轻量包; 版本见 PUSH-MANIFEST.json'
