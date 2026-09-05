$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$reportPath = Join-Path $installDir 'reports\latest.json'
$expected = @{ 'sentinel-policy.json'='0f87d2ecdc801505d825c647ef8eced290bc9ba9e0bd17b4abe9b6a7a4d14423'; 'sentinel-windows.ps1'='459623f559ca0c8a935b7898a6d1923f8cdd35d09ce3afdfd45e6acebb144270'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$installed=$true;$integrityValid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path)){$installed=$false;$integrityValid=$false}elseif((Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$integrityValid=$false}}
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
$taskHealthy=[bool]($task -and $task.State -ne 'Disabled')
$reportingConfigured=$false;$reportingPath=Join-Path $installDir 'reporting.dpapi'
if(Test-Path $reportingPath){
  try{
    $encrypted=[IO.File]::ReadAllBytes($reportingPath);$entropy=[Text.Encoding]::UTF8.GetBytes('SentinelAgent.Reporting.v1');$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try{$reporting=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json}finally{[Array]::Clear($plain,0,$plain.Length);[Array]::Clear($encrypted,0,$encrypted.Length)}
    $names=@($reporting.PSObject.Properties.Name|Sort-Object);$uri=$null;$urlValid=[Uri]::TryCreate([string]$reporting.report_url,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -ceq 'https' -and $uri.Host -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment
    $reportingConfigured=($names -join ',') -ceq 'report_token,report_url,schema,signing_secret' -and $reporting.schema -ceq 'sentinel.reporting/v1' -and $urlValid -and ([string]$reporting.report_token).Length -ge 32 -and ([string]$reporting.report_token).Length -le 4096 -and ([string]$reporting.signing_secret).Length -ge 32 -and ([string]$reporting.signing_secret).Length -le 4096 -and $reporting.report_token -cne $reporting.signing_secret
  }catch{$reportingConfigured=$false}
}
$recent = $false; $reportValid = $false; $critical = 0; $high = 0
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  $age=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$report.scanned_at
  $findings=@($report.findings);$invalidFindings=@($findings|Where-Object{$_ -isnot [PSCustomObject] -or $_.severity -notin @('critical','high','medium','low') -or -not ($_.kind -is [string]) -or -not ($_.path -is [string]) -or -not ($_.message -is [string])});$actualCritical=@($findings|Where-Object severity -eq 'critical').Count;$actualHigh=@($findings|Where-Object severity -eq 'high').Count;$actualMedium=@($findings|Where-Object severity -eq 'medium').Count;$actualLow=@($findings|Where-Object severity -eq 'low').Count
  $reportValid=$report.schema -eq 'sentinel.report/v1' -and $report.agent_version -eq '0.26.0' -and $report.policy_version -eq $policyVersion -and $report.device_id -match '^[a-f0-9]{12}$' -and $report.findings -is [System.Array] -and $findings.Count -le 10000 -and $invalidFindings.Count -eq 0 -and $report.summary -and [int]$report.summary.critical -eq $actualCritical -and [int]$report.summary.high -eq $actualHigh -and [int]$report.summary.medium -eq $actualMedium -and [int]$report.summary.low -eq $actualLow
  if($reportValid){$recent=$age -ge 0 -and $age -lt 86400;$critical=$actualCritical;$high=$actualHigh}
}
@{ SentinelInstalled=$installed; SentinelIntegrityValid=$integrityValid; SentinelScheduledTaskHealthy=$taskHealthy; SentinelReportingConfigured=$reportingConfigured; SentinelPolicyVersion=$policyVersion; SentinelReportValid=$reportValid; SentinelScanRecent=$recent; SentinelCriticalFindings=$critical; SentinelHighFindings=$high } | ConvertTo-Json -Compress
