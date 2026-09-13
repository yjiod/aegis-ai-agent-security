param(
  [Parameter(Mandatory=$true)][string]$EnrollmentPath,
  [string]$OutputPath = "$env:ProgramData\SentinelAgent\reporting.dpapi"
)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator is required'}
$item=Get-Item -LiteralPath $EnrollmentPath -Force
if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 16384){throw 'Unsafe enrollment file type or size'}
$unsafeSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545')
foreach($rule in (Get-Acl -LiteralPath $EnrollmentPath).Access){
  try{$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}catch{throw 'Enrollment ACL identity cannot be verified'}
  if($rule.AccessControlType -eq 'Allow' -and $sid -in $unsafeSids){throw 'Enrollment file is readable by a broad principal'}
}
$raw=[IO.File]::ReadAllText($item.FullName,[Text.Encoding]::UTF8)
$enrollment=$raw|ConvertFrom-Json
$expected=@('schema','device_id','report_url','report_token','signing_secret','issued_at','expires_at','consume_once')
$names=@($enrollment.PSObject.Properties.Name)
if(@($names|Where-Object{$_ -notin $expected}).Count -or @($expected|Where-Object{$_ -notin $names}).Count -or $enrollment.schema -cne 'sentinel.device-enrollment/v2' -or $enrollment.consume_once -ne $true){throw 'Invalid enrollment contract'}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if([long]$enrollment.issued_at -gt $now+300 -or $now-[long]$enrollment.issued_at -gt 86400 -or [long]$enrollment.expires_at -lt $now -or [long]$enrollment.expires_at-$now -gt 86400){throw 'Expired or future enrollment'}
$material="$env:COMPUTERNAME|$env:USERDOMAIN";$sha=[Security.Cryptography.SHA256]::Create()
$actual=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').Substring(0,12).ToLower()
if([string]$enrollment.device_id -cne $actual){throw 'Enrollment device identity mismatch'}
& "$PSScriptRoot\sentinel-configure-windows.ps1" -ReportUrl ([string]$enrollment.report_url) -ReportToken ([string]$enrollment.report_token) -SigningSecret ([string]$enrollment.signing_secret) -OutputPath $OutputPath
Remove-Item -LiteralPath $item.FullName -Force
Write-Output 'Sentinel enrollment consumed for this Windows device.'
