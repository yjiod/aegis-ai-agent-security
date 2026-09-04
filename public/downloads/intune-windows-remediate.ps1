$ErrorActionPreference = 'Stop'
$baseUrl = 'https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$reportDir = Join-Path $installDir 'reports'
New-Item -ItemType Directory -Force -Path $installDir,$reportDir | Out-Null
Invoke-WebRequest "$baseUrl/sentinel-policy.json" -OutFile (Join-Path $installDir 'sentinel-policy.json') -UseBasicParsing
Invoke-WebRequest "$baseUrl/sentinel-windows.ps1" -OutFile (Join-Path $installDir 'sentinel-windows.ps1') -UseBasicParsing
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installDir\sentinel-windows.ps1`" -Output `"$reportDir\latest.json`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Output 'Sentinel Agent installed and scheduled.'
