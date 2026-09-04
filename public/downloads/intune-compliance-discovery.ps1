$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$reportPath = Join-Path $installDir 'reports\latest.json'
$installed = (Test-Path $policyPath) -and (Test-Path (Join-Path $installDir 'sentinel-windows.ps1'))
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$recent = $false; $critical = 0; $high = 0
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  $recent = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$report.scanned_at) -lt 86400
  $critical = [int]$report.summary.critical; $high = [int]$report.summary.high
}
@{ SentinelInstalled=$installed; SentinelPolicyVersion=$policyVersion; SentinelScanRecent=$recent; SentinelCriticalFindings=$critical; SentinelHighFindings=$high } | ConvertTo-Json -Compress
