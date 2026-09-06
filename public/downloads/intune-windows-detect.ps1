$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$expected = @{ 'aegis-policy.json'='a39a304dcd75e2a1ce43b9c0bf00ece9982b707c1e86652488f4ff9d7e1b0991'; 'aegis-windows.ps1'='f26eca242d89d1774038cf90cf9cbe0fc62f238cba5a8d10f381dd98569b3394'; 'aegis-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content (Join-Path $installDir 'aegis-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "AegisAgent:$version:integrity-ok";exit 0}
Write-Output 'AegisAgent:repair-required'
exit 1
