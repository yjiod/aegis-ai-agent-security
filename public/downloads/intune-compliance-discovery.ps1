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
$recent = $false; $reportValid = $false; $critical = 0; $high = 0
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  $age=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$report.scanned_at
  $findings=@($report.findings);$invalidFindings=@($findings|Where-Object{$_ -isnot [PSCustomObject] -or $_.severity -notin @('critical','high','medium','low') -or -not ($_.kind -is [string]) -or -not ($_.path -is [string]) -or -not ($_.message -is [string])});$actualCritical=@($findings|Where-Object severity -eq 'critical').Count;$actualHigh=@($findings|Where-Object severity -eq 'high').Count;$actualMedium=@($findings|Where-Object severity -eq 'medium').Count;$actualLow=@($findings|Where-Object severity -eq 'low').Count
  $reportValid=$report.schema -eq 'sentinel.report/v1' -and $report.agent_version -eq '0.23.0' -and $report.policy_version -eq $policyVersion -and $report.device_id -match '^[a-f0-9]{12}$' -and $report.findings -is [System.Array] -and $findings.Count -le 10000 -and $invalidFindings.Count -eq 0 -and $report.summary -and [int]$report.summary.critical -eq $actualCritical -and [int]$report.summary.high -eq $actualHigh -and [int]$report.summary.medium -eq $actualMedium -and [int]$report.summary.low -eq $actualLow
  if($reportValid){$recent=$age -ge 0 -and $age -lt 86400;$critical=$actualCritical;$high=$actualHigh}
}
@{ SentinelInstalled=$installed; SentinelIntegrityValid=$integrityValid; SentinelScheduledTaskHealthy=$taskHealthy; SentinelPolicyVersion=$policyVersion; SentinelReportValid=$reportValid; SentinelScanRecent=$recent; SentinelCriticalFindings=$critical; SentinelHighFindings=$high } | ConvertTo-Json -Compress
