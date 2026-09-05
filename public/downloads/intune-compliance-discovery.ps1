$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$reportPath = Join-Path $installDir 'reports\latest.json'
$expected = @{ 'sentinel-policy.json'='0f87d2ecdc801505d825c647ef8eced290bc9ba9e0bd17b4abe9b6a7a4d14423'; 'sentinel-windows.ps1'='2c7ce120a97a9df59be65ea4673bb04e38fcd6f6ed251ff274c38d1c83a35282'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$installed=$true;$integrityValid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path)){$installed=$false;$integrityValid=$false}elseif((Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$integrityValid=$false}}
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
$taskHealthy=[bool]($task -and $task.State -ne 'Disabled')
$recent = $false; $critical = 0; $high = 0
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  $age=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$report.scanned_at
  $recent = $report.schema -eq 'sentinel.report/v1' -and $age -ge 0 -and $age -lt 86400
  if($report.schema -eq 'sentinel.report/v1'){$critical = [int]$report.summary.critical; $high = [int]$report.summary.high}
}
@{ SentinelInstalled=$installed; SentinelIntegrityValid=$integrityValid; SentinelScheduledTaskHealthy=$taskHealthy; SentinelPolicyVersion=$policyVersion; SentinelScanRecent=$recent; SentinelCriticalFindings=$critical; SentinelHighFindings=$high } | ConvertTo-Json -Compress
