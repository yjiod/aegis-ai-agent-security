$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$policy = Join-Path $installDir 'sentinel-policy.json'
$scanner = Join-Path $installDir 'sentinel-windows.ps1'
if ((Test-Path $policy) -and (Test-Path $scanner)) {
  $version = (Get-Content $policy -Raw | ConvertFrom-Json).version
  Write-Output "SentinelAgent:$version"
  exit 0
}
exit 1
