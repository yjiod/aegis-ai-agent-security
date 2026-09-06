$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$policyPath = Join-Path $installDir 'aegis-policy.json'
$reportPath = Join-Path $installDir 'reports\latest.json'
$expected = @{ 'aegis-policy.json'='a39a304dcd75e2a1ce43b9c0bf00ece9982b707c1e86652488f4ff9d7e1b0991'; 'aegis-windows.ps1'='f26eca242d89d1774038cf90cf9cbe0fc62f238cba5a8d10f381dd98569b3394'; 'aegis-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$installed=$true;$integrityValid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path)){$installed=$false;$integrityValid=$false}elseif((Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$integrityValid=$false}}
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
$taskHealthy=[bool]($task -and $task.State -ne 'Disabled')
$reportingConfigured=$false;$reportingHost='';$reportingPath=Join-Path $installDir 'reporting.dpapi'
if(Test-Path $reportingPath){
  try{
    $encrypted=[IO.File]::ReadAllBytes($reportingPath);$entropy=[Text.Encoding]::UTF8.GetBytes('AegisAgent.Reporting.v1');$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try{$reporting=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json}finally{[Array]::Clear($plain,0,$plain.Length);[Array]::Clear($encrypted,0,$encrypted.Length)}
    $names=@($reporting.PSObject.Properties.Name|Sort-Object);$uri=$null;$urlValid=[Uri]::TryCreate([string]$reporting.report_url,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -ceq 'https' -and $uri.Host -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment
    $reportingConfigured=($names -join ',') -ceq 'report_token,report_url,schema,signing_secret' -and $reporting.schema -ceq 'aegis.reporting/v1' -and $urlValid -and ([string]$reporting.report_token).Length -ge 32 -and ([string]$reporting.report_token).Length -le 4096 -and ([string]$reporting.signing_secret).Length -ge 32 -and ([string]$reporting.signing_secret).Length -le 4096 -and $reporting.report_token -cne $reporting.signing_secret
    if($reportingConfigured){$reportingHost=$uri.DnsSafeHost.ToLower()}
  }catch{$reportingConfigured=$false}
}
$reportingHealthy=$false;$uploadStatusPath=Join-Path $reportDir 'upload-status.json'
if($reportingConfigured -and (Test-Path $uploadStatusPath)){
  try{$uploadStatus=Get-Content $uploadStatusPath -Raw|ConvertFrom-Json;$uploadNames=@($uploadStatus.PSObject.Properties.Name|Sort-Object);$uploadAge=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-[int64]$uploadStatus.last_success;$reportingHealthy=($uploadNames -join ',') -ceq 'collector_host,last_success,schema,status' -and $uploadStatus.schema -ceq 'aegis.upload-status/v1' -and $uploadStatus.status -ceq 'accepted' -and $uploadStatus.collector_host -ceq $reportingHost -and $uploadAge -ge 0 -and $uploadAge -lt 86400}catch{$reportingHealthy=$false}
}
$recent = $false; $reportValid = $false; $critical = 0; $high = 0
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  $age=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$report.scanned_at
  $findings=@($report.findings);$invalidFindings=@($findings|Where-Object{$_ -isnot [PSCustomObject] -or $_.severity -notin @('critical','high','medium','low') -or -not ($_.kind -is [string]) -or -not ($_.path -is [string]) -or -not ($_.message -is [string])});$actualCritical=@($findings|Where-Object severity -eq 'critical').Count;$actualHigh=@($findings|Where-Object severity -eq 'high').Count;$actualMedium=@($findings|Where-Object severity -eq 'medium').Count;$actualLow=@($findings|Where-Object severity -eq 'low').Count
  $reportValid=$report.schema -eq 'aegis.report/v1' -and $report.agent_version -eq '0.30.0' -and $report.policy_version -eq $policyVersion -and $report.device_id -match '^[a-f0-9]{12}$' -and $report.findings -is [System.Array] -and $findings.Count -le 10000 -and $invalidFindings.Count -eq 0 -and $report.summary -and [int]$report.summary.critical -eq $actualCritical -and [int]$report.summary.high -eq $actualHigh -and [int]$report.summary.medium -eq $actualMedium -and [int]$report.summary.low -eq $actualLow
  if($reportValid){$recent=$age -ge 0 -and $age -lt 86400;$critical=$actualCritical;$high=$actualHigh}
}
@{ AegisInstalled=$installed; AegisIntegrityValid=$integrityValid; AegisScheduledTaskHealthy=$taskHealthy; AegisReportingConfigured=$reportingConfigured; AegisReportingHealthy=$reportingHealthy; AegisPolicyVersion=$policyVersion; AegisReportValid=$reportValid; AegisScanRecent=$recent; AegisCriticalFindings=$critical; AegisHighFindings=$high } | ConvertTo-Json -Compress
