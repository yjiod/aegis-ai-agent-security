$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$expected = @{ 'sentinel-policy.json'='8445ffbaf792cd4c92702d4359e1a853b9c35fb80c8862c81a7c46f184469cb1'; 'sentinel-windows.ps1'='06ba277fc6d17df423b6f49135762a2527d1460621633eef47a5d64e23df566a'; 'sentinel-security-baseline.md'='0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content (Join-Path $installDir 'sentinel-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "SentinelAgent:$version:integrity-ok";exit 0}
Write-Output 'SentinelAgent:repair-required'
exit 1
