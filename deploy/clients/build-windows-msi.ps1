# ═══════════════════════════════════════════════════════════
# Aegis Agent for Windows — MSI 构建脚本 (WiX Toolset)
#
# 在 Windows 机器上运行（需安装 WiX Toolset v3/v4）:
#   powershell -ExecutionPolicy Bypass -File build-windows-msi.ps1
#
# 产出: dist/installers/aegis-agent-windows-0.31.0.msi
# ═══════════════════════════════════════════════════════════
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Version = '0.31.0'
$OutDir = Join-Path $Root 'dist\installers'
$SrcDir = Join-Path $OutDir "aegis-agent-windows-$Version"
$Wxs = Join-Path $Root 'deploy\clients\AegisAgent.wxs'

if (-not (Test-Path $SrcDir)) {
    Write-Error "Source bundle not found: $SrcDir (run the assemble step first)"
}

# Locate WiX toolset (candle/light for v3, wax/wix for v4)
$candle = Get-Command candle.exe -ErrorAction SilentlyContinue
$light  = Get-Command light.exe  -ErrorAction SilentlyContinue

if (-not $candle -or -not $light) {
    Write-Host 'WiX v3 (candle/light) not found in PATH.'
    Write-Host 'Install: choco install wixtoolset  OR  download from https://wixtoolset.org'
    Write-Host ''
    Write-Host 'Falling back: the self-contained AegisBootstrap.exe in'
    Write-Host "  $SrcDir"
    Write-Host 'can be distributed directly (runs Install-Aegis.ps1).'
    exit 1
}

$Work = Join-Path $env:TEMP "aegis-msi-$Version"
New-Item -ItemType Directory -Force -Path $Work | Out-Null

# Copy payload next to wxs so relative paths resolve
Copy-Item "$SrcDir\*" $Work -Recurse -Force
Copy-Item $Wxs "$Work\AegisAgent.wxs" -Force

Push-Location $Work
& candle.exe -nologo AegisAgent.wxs -out AegisAgent.wixobj
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Error 'candle failed' }
& light.exe -nologo AegisAgent.wixobj -out "aegis-agent-windows-$Version.msi"
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Error 'light failed' }
Pop-Location

$Msi = Join-Path $Work "aegis-agent-windows-$Version.msi"
Copy-Item $Msi $OutDir -Force
Write-Host "MSI written: $OutDir\aegis-agent-windows-$Version.msi"
