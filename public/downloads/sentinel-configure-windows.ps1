param(
  [string]$ReportUrl = $env:SENTINEL_REPORT_URL,
  [string]$ReportToken = $env:SENTINEL_REPORT_TOKEN,
  [string]$SigningSecret = $env:SENTINEL_REPORT_SIGNING_SECRET,
  [string[]]$PolicyVerificationKeys = @(),
  [string]$DeviceId = '',
  [string]$OutputPath = "$env:ProgramData\SentinelAgent\reporting.dpapi"
)
$ErrorActionPreference='Stop'
if($ReportUrl.Length -gt 2048){throw 'Report URL is too long'}
$uri=$null
if(-not [Uri]::TryCreate($ReportUrl,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'Report URL must be an absolute credential-free HTTPS URL'}
if($ReportToken.Length -lt 32 -or $ReportToken.Length -gt 4096){throw 'Report token must contain 32-4096 characters'}
if($SigningSecret.Length -lt 32 -or $SigningSecret.Length -gt 4096){throw 'Signing secret must contain 32-4096 characters'}
if($ReportToken -ceq $SigningSecret){throw 'Report token and signing secret must be independent'}
if($PolicyVerificationKeys.Count -lt 1 -or $PolicyVerificationKeys.Count -gt 5 -or @($PolicyVerificationKeys|Where-Object{$_.Length -lt 32 -or $_.Length -gt 4096}).Count -or @($PolicyVerificationKeys|Select-Object -Unique).Count -ne $PolicyVerificationKeys.Count -or $ReportToken -in $PolicyVerificationKeys -or $SigningSecret -in $PolicyVerificationKeys){throw 'Policy verification keys must contain 1-5 unique independent values'}
if($DeviceId -and $DeviceId -cnotmatch '^[0-9a-f]{12}$'){throw 'Device ID must be 12 lowercase hexadecimal characters'}
$parent=Split-Path $OutputPath -Parent
New-Item -ItemType Directory -Force -Path $parent|Out-Null
& icacls.exe $parent /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C|Out-Null
$config=if($DeviceId){@{schema='sentinel.reporting/v3';device_id=$DeviceId;report_url=$ReportUrl;report_token=$ReportToken;signing_secret=$SigningSecret;policy_verification_keys=@($PolicyVerificationKeys)}}else{@{schema='sentinel.reporting/v2';report_url=$ReportUrl;report_token=$ReportToken;signing_secret=$SigningSecret;policy_verification_keys=@($PolicyVerificationKeys)}}
$payload=$config|ConvertTo-Json -Compress
$plain=[Text.Encoding]::UTF8.GetBytes($payload);$entropy=[Text.Encoding]::UTF8.GetBytes('SentinelAgent.Reporting.v1')
try{$encrypted=[Security.Cryptography.ProtectedData]::Protect($plain,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)}finally{[Array]::Clear($plain,0,$plain.Length)}
$temp=$OutputPath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
try{
  [IO.File]::WriteAllBytes($temp,$encrypted)
  & icacls.exe $temp /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C|Out-Null
  Move-Item $temp $OutputPath -Force
}finally{Remove-Item $temp -Force -ErrorAction SilentlyContinue;[Array]::Clear($encrypted,0,$encrypted.Length)}
Write-Output 'Sentinel reporting configuration encrypted for this Windows device.'
