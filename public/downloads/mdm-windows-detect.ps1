$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$expected = @{ 'aegis-policy.json'='6d059c7f31b10c8d133184f3673fcba01d25fd409b0310944f7bde0eab30088b'; 'aegis-windows.ps1'='5ccf8a2dca8f36d75a1bd9dd434c67bbf75755d88a6a498678c2998e4fb5d77b'; 'aegis-security-baseline.md'='5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content -Encoding UTF8 (Join-Path $installDir 'aegis-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "AegisAgent:$version:integrity-ok";exit 0}
Write-Output 'AegisAgent:repair-required'
exit 1
