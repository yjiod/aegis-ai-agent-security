$ErrorActionPreference = 'SilentlyContinue'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$expected = @{ 'sentinel-policy.json'='0f87d2ecdc801505d825c647ef8eced290bc9ba9e0bd17b4abe9b6a7a4d14423'; 'sentinel-windows.ps1'='bd7b0e5f45001892cc2f255092e4182231e924eb11cbbcd13c51f4f7e96661e8'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$valid=$true
foreach($name in $expected.Keys){$path=Join-Path $installDir $name;if(-not(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]){$valid=$false}}
$task=Get-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -ErrorAction SilentlyContinue
$periodicOk=[bool]($task -and @($task.Triggers|Where-Object{$_.Repetition.Interval -eq 'PT1H'}).Count -eq 1)
$startupOk=[bool]($task -and @($task.Triggers|Where-Object{$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' -and $_.Delay -eq 'PT2M'}).Count -eq 1)
$settingsOk=[bool]($task -and $task.Settings.StartWhenAvailable -and $task.Settings.MultipleInstances -eq 'IgnoreNew' -and $task.Settings.ExecutionTimeLimit -eq 'PT30M' -and $task.Settings.RestartCount -eq 3 -and $task.Settings.RestartInterval -eq 'PT5M')
if(-not $task -or $task.State -eq 'Disabled' -or -not $periodicOk -or -not $startupOk -or -not $settingsOk){$valid=$false}
if($valid){$version=(Get-Content (Join-Path $installDir 'sentinel-policy.json') -Raw|ConvertFrom-Json).version;Write-Output "SentinelAgent:$version:integrity-ok";exit 0}
Write-Output 'SentinelAgent:repair-required'
exit 1
