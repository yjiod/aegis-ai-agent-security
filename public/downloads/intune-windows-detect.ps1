$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$expected = @{ 'sentinel-policy.json'='fe6b8160916423c429521c582c94e00e2d3a91feec6644739b1ea4896cb751ca'; 'sentinel-windows.ps1'='afa93412820d3e4b6508d288370deac6b14bb7c3623d75093a868a4d6ba1f447'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
if(-not $task -or $task.State -eq 'Disabled'){$valid=$false}
if($valid){$version=(Get-Content (Join-Path $installDir 'sentinel-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "SentinelAgent:$version:integrity-ok";exit 0}
Write-Output 'SentinelAgent:repair-required'
exit 1
