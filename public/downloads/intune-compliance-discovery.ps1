$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$reportPath = Join-Path $installDir 'reports\latest.json'
$reportDir = Join-Path $installDir 'reports'
$expected = @{ 'sentinel-policy.json'='4ebac2abbe3654d048a8af17cf46df3161de336c00d2f5c4c692d90ffeffb832'; 'sentinel-windows.ps1'='c00dffba7f462ab7e2718971102b914b64d333afa6a377f9f6e5c35f40d7e4e3'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$installed=$true;$integrityValid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path)){$installed=$false;$integrityValid=$false}elseif((Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$integrityValid=$false}}
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
$periodicOk=[bool]($task -and @($task.Triggers|Where-Object{$_.Repetition.Interval -eq 'PT1H'}).Count -eq 1)
$startupOk=[bool]($task -and @($task.Triggers|Where-Object{$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' -and $_.Delay -eq 'PT2M'}).Count -eq 1)
$settingsOk=[bool]($task -and $task.Settings.StartWhenAvailable -and $task.Settings.MultipleInstances -eq 'IgnoreNew' -and $task.Settings.ExecutionTimeLimit -eq 'PT30M' -and $task.Settings.RestartCount -eq 3 -and $task.Settings.RestartInterval -eq 'PT5M')
$taskHealthy=[bool]($task -and $task.State -ne 'Disabled' -and $periodicOk -and $startupOk -and $settingsOk)
$reportingConfigured=$false;$reportingHost='';$reportingPath=Join-Path $installDir 'reporting.dpapi'
if(Test-Path $reportingPath){
  try{
    $encrypted=[IO.File]::ReadAllBytes($reportingPath);$entropy=[Text.Encoding]::UTF8.GetBytes('SentinelAgent.Reporting.v1');$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try{$reporting=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json}finally{[Array]::Clear($plain,0,$plain.Length);[Array]::Clear($encrypted,0,$encrypted.Length)}
    $names=@($reporting.PSObject.Properties.Name|Sort-Object);$uri=$null;$urlValid=[Uri]::TryCreate([string]$reporting.report_url,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -ceq 'https' -and $uri.Host -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment
    $keys=@($reporting.policy_verification_keys|ForEach-Object{[string]$_});$reportingConfigured=($names -join ',') -ceq 'policy_verification_keys,report_token,report_url,schema,signing_secret' -and $reporting.schema -ceq 'sentinel.reporting/v2' -and $urlValid -and ([string]$reporting.report_token).Length -ge 32 -and ([string]$reporting.report_token).Length -le 4096 -and ([string]$reporting.signing_secret).Length -ge 32 -and ([string]$reporting.signing_secret).Length -le 4096 -and $reporting.report_token -cne $reporting.signing_secret -and $keys.Count -ge 1 -and $keys.Count -le 5 -and @($keys|Where-Object{$_.Length -lt 32 -or $_.Length -gt 4096}).Count -eq 0 -and @($keys|Select-Object -Unique).Count -eq $keys.Count -and $reporting.report_token -notin $keys -and $reporting.signing_secret -notin $keys
    if($reportingConfigured){$reportingHost=$uri.DnsSafeHost.ToLower()}
  }catch{$reportingConfigured=$false}
}
$reportingHealthy=$false;$uploadStatusPath=Join-Path $reportDir 'upload-status.json'
if($reportingConfigured -and (Test-Path $uploadStatusPath)){
  try{$uploadStatus=Get-Content $uploadStatusPath -Raw|ConvertFrom-Json;$uploadNames=@($uploadStatus.PSObject.Properties.Name|Sort-Object);$uploadAge=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-[int64]$uploadStatus.last_success;$reportingHealthy=($uploadNames -join ',') -ceq 'collector_host,last_success,schema,status' -and $uploadStatus.schema -ceq 'sentinel.upload-status/v1' -and $uploadStatus.status -ceq 'accepted' -and $uploadStatus.collector_host -ceq $reportingHost -and $uploadAge -ge 0 -and $uploadAge -lt 86400}catch{$reportingHealthy=$false}
}
$recent = $false; $reportValid = $false; $critical = 0; $high = 0
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  $age=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$report.scanned_at
  $findings=@($report.findings);$invalidFindings=@($findings|Where-Object{$_ -isnot [PSCustomObject] -or $_.severity -notin @('critical','high','medium','low') -or -not ($_.kind -is [string]) -or -not ($_.path -is [string]) -or -not ($_.message -is [string])});$actualCritical=@($findings|Where-Object severity -eq 'critical').Count;$actualHigh=@($findings|Where-Object severity -eq 'high').Count;$actualMedium=@($findings|Where-Object severity -eq 'medium').Count;$actualLow=@($findings|Where-Object severity -eq 'low').Count
  $reportValid=$report.schema -eq 'sentinel.report/v1' -and $report.agent_version -eq '0.50.0' -and $report.policy_version -eq $policyVersion -and $report.device_id -match '^[a-f0-9]{12}$' -and $report.findings -is [System.Array] -and $findings.Count -le 10000 -and $invalidFindings.Count -eq 0 -and $report.summary -and [int]$report.summary.critical -eq $actualCritical -and [int]$report.summary.high -eq $actualHigh -and [int]$report.summary.medium -eq $actualMedium -and [int]$report.summary.low -eq $actualLow
  if($reportValid){$recent=$age -ge 0 -and $age -lt 86400;$critical=$actualCritical;$high=$actualHigh}
}
@{ SentinelInstalled=$installed; SentinelIntegrityValid=$integrityValid; SentinelScheduledTaskHealthy=$taskHealthy; SentinelReportingConfigured=$reportingConfigured; SentinelReportingHealthy=$reportingHealthy; SentinelPolicyVersion=$policyVersion; SentinelReportValid=$reportValid; SentinelScanRecent=$recent; SentinelCriticalFindings=$critical; SentinelHighFindings=$high } | ConvertTo-Json -Compress
