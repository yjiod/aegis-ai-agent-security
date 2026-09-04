$ErrorActionPreference = 'Stop'
Unregister-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Confirm:$false -ErrorAction SilentlyContinue
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
Write-Output 'Sentinel runtime removed. Repository rule files are retained for audit and must be removed through source control.'
