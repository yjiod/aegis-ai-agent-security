$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$expected = @{ 'aegis-policy.json'='23067c4aada6f6cd1f9d75ac0a74eb54a03a4f58235509b5afd737daf785cd7b'; 'aegis-windows.ps1'='ccba4bbca49d4339c1d891af3dda67dd975ac74a12c21aa20d66e31768e4038e'; 'aegis-security-baseline.md'='5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content -Encoding UTF8 (Join-Path $installDir 'aegis-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "AegisAgent:$version:integrity-ok";exit 0}
Write-Output 'AegisAgent:repair-required'
exit 1
