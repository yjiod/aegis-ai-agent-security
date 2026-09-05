$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$expected = @{ 'sentinel-policy.json'='431a156f48208bcbc2c44dd92f8b2383be6a04df9294631f6386a9a6d48ac64d'; 'sentinel-windows.ps1'='cbd819085ae700d9468fe282bf6a21da67ad7e9d1054b97581026482921efa9d'; 'sentinel-security-baseline.md'='0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content (Join-Path $installDir 'sentinel-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "SentinelAgent:$version:integrity-ok";exit 0}
Write-Output 'SentinelAgent:repair-required'
exit 1
