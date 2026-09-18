$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$expected = @{ 'aegis-policy.json'='a8935b03ae59c08002a428d524b46ee69bde6042a5173c510d184f62d6737740'; 'aegis-windows.ps1'='978a9d314b63ce3fdf8c84d4d736af95b793526647122b7ee70e8b80e286de97'; 'aegis-security-baseline.md'='5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content -Encoding UTF8 (Join-Path $installDir 'aegis-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "AegisAgent:$version:integrity-ok";exit 0}
Write-Output 'AegisAgent:repair-required'
exit 1
