$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$previousDir = Join-Path $installDir 'previous'
$files = @('aegis-policy.json','aegis-windows.ps1','aegis-security-baseline.md')
foreach($name in $files){if(-not (Test-Path (Join-Path $previousDir $name))){throw "Previous version is incomplete: $name"}}
$checksumsPath=Join-Path $previousDir 'checksums.json'
if(-not (Test-Path $checksumsPath)){throw 'Previous version checksum manifest is missing'}
$checksums=Get-Content $checksumsPath -Raw|ConvertFrom-Json
$checksumNames=@($checksums.PSObject.Properties.Name|Sort-Object)
if(($checksumNames -join ',') -ne (($files|Sort-Object) -join ',')){throw 'Previous version checksum manifest has an unexpected file set'}
foreach($name in $files){if((Get-FileHash (Join-Path $previousDir $name) -Algorithm SHA256).Hash.ToLower() -ne $checksums.$name){throw "Previous version integrity verification failed: $name"}}
Stop-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
foreach($name in $files){Copy-Item (Join-Path $previousDir $name) (Join-Path $installDir $name) -Force}
foreach($name in $files){if((Get-FileHash (Join-Path $installDir $name) -Algorithm SHA256).Hash.ToLower() -ne $checksums.$name){throw "Restored version integrity verification failed: $name"}}
Start-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
Write-Output 'Aegis Agent restored to the previous verified installation.'
