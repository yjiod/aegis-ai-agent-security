$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$previousDir = Join-Path $installDir 'previous'
$files = @('sentinel-policy.json','sentinel-windows.ps1','sentinel-security-baseline.md')
foreach($name in $files){if(-not (Test-Path (Join-Path $previousDir $name))){throw "Previous version is incomplete: $name"}}
$checksumsPath=Join-Path $previousDir 'checksums.json'
if(-not (Test-Path $checksumsPath)){throw 'Previous version checksum manifest is missing'}
$checksums=Get-Content $checksumsPath -Raw|ConvertFrom-Json
foreach($name in $files){if((Get-FileHash (Join-Path $previousDir $name) -Algorithm SHA256).Hash.ToLower() -ne $checksums.$name){throw "Previous version integrity verification failed: $name"}}
Stop-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
foreach($name in $files){Copy-Item (Join-Path $previousDir $name) (Join-Path $installDir $name) -Force}
Start-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
Write-Output 'Sentinel Agent restored to the previous verified installation.'
