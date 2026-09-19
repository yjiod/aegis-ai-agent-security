$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$expected = @{ 'aegis-policy.json'='b3daf3ea12b788bd2dcd25f2b17de73e59020283f50443f7b1d0892e4d1ced77'; 'aegis-windows.ps1'='692f707c96cdd3bac4de8d2946946a8442a3bc47c58733923826d927c1239aaf'; 'aegis-security-baseline.md'='5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content -Encoding UTF8 (Join-Path $installDir 'aegis-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "AegisAgent:$version:integrity-ok";exit 0}
Write-Output 'AegisAgent:repair-required'
exit 1
