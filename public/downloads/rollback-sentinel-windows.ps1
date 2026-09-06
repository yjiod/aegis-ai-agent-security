$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$previousDir = Join-Path $installDir 'previous'
$files = @('sentinel-policy.json','sentinel-windows.ps1','sentinel-security-baseline.md')
foreach($name in $files){if(-not (Test-Path (Join-Path $previousDir $name))){throw "Previous version is incomplete: $name"}}
$taskSnapshot=Join-Path $previousDir 'scheduled-task.xml'
if(-not (Test-Path $taskSnapshot) -or (Get-Item $taskSnapshot).Length -gt 65536){throw 'Previous scheduled task snapshot is missing or oversized'}
$checksumsPath=Join-Path $previousDir 'checksums.json'
if(-not (Test-Path $checksumsPath)){throw 'Previous version checksum manifest is missing'}
$checksums=Get-Content $checksumsPath -Raw|ConvertFrom-Json
$checksumNames=@($checksums.PSObject.Properties.Name|Sort-Object)
if(($checksumNames -join ',') -ne ((@($files)+'scheduled-task.xml'|Sort-Object) -join ',')){throw 'Previous version checksum manifest has an unexpected file set'}
foreach($name in @($files)+'scheduled-task.xml'){if((Get-FileHash (Join-Path $previousDir $name) -Algorithm SHA256).Hash.ToLower() -ne $checksums.$name){throw "Previous version integrity verification failed: $name"}}
$taskXml=Get-Content $taskSnapshot -Raw
[xml]$parsedTask=$taskXml
$namespace=New-Object Xml.XmlNamespaceManager($parsedTask.NameTable);$namespace.AddNamespace('t',$parsedTask.DocumentElement.NamespaceURI)
$command=[string]$parsedTask.SelectSingleNode('//t:Actions/t:Exec/t:Command',$namespace).InnerText
$arguments=[string]$parsedTask.SelectSingleNode('//t:Actions/t:Exec/t:Arguments',$namespace).InnerText
$userId=[string]$parsedTask.SelectSingleNode('//t:Principals/t:Principal/t:UserId',$namespace).InnerText
$expectedArguments="-NoProfile -ExecutionPolicy Bypass -File `"$installDir\sentinel-windows.ps1`" -Output `"$installDir\reports\latest.json`""
if($command -notmatch '(?i)(^|\\)powershell\.exe$' -or $arguments -cne $expectedArguments -or $userId -notin @('SYSTEM','S-1-5-18')){throw 'Previous scheduled task snapshot failed the safety contract'}
Stop-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
foreach($name in $files){Copy-Item (Join-Path $previousDir $name) (Join-Path $installDir $name) -Force}
foreach($name in $files){if((Get-FileHash (Join-Path $installDir $name) -Algorithm SHA256).Hash.ToLower() -ne $checksums.$name){throw "Restored version integrity verification failed: $name"}}
Register-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Xml $taskXml -Force | Out-Null
Start-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
Write-Output 'Sentinel Agent restored to the previous verified installation.'
