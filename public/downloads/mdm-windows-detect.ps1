$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$expected = @{ 'aegis-policy.json'='f15d7ebc522c9bcf03554fd698e3f7c8b5e5c604823b6ce802def2b2879c774a'; 'aegis-windows.ps1'='b9a270738731cc0eb7228c5b7569874089b31f0782a679ccf7ae3d51fe8b9702'; 'aegis-security-baseline.md'='5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content -Encoding UTF8 (Join-Path $installDir 'aegis-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "AegisAgent:$version:integrity-ok";exit 0}
Write-Output 'AegisAgent:repair-required'
exit 1
