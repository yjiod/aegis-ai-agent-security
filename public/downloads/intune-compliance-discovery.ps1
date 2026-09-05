$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$reportPath = Join-Path $installDir 'reports\latest.json'
$expected = @{ 'sentinel-policy.json'='679306ad2fbdaf119bfd3cf278b35687c26d9f1c3b7879ec72ba7d1304632769'; 'sentinel-windows.ps1'='013a2e42c824b6e9d46202ac7e4ef23840afa64332757cea33b0a535c5723de7'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
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
