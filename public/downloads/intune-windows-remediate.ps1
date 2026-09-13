$ErrorActionPreference = 'Stop'
$baseUrl = 'https://sentinel-agent-security.example.com/downloads'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$reportDir = Join-Path $installDir 'reports'
$previousDir = Join-Path $installDir 'previous'
$stageDir = Join-Path $installDir ('.stage-' + [Guid]::NewGuid().ToString('N'))
$expected = @{ 'sentinel-policy.json'='4ebac2abbe3654d048a8af17cf46df3161de336c00d2f5c4c692d90ffeffb832'; 'sentinel-windows.ps1'='0f96da420a9ac739dbef4070ad13020467bfe6018f2e030a9419d3fe0cceec3a'; 'sentinel-security-baseline.md'='e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e' }
$taskName='Sentinel AI Agent Security Scan'
$taskArguments="-NoProfile -ExecutionPolicy Bypass -File `"$installDir\sentinel-windows.ps1`" -Output `"$reportDir\latest.json`""
New-Item -ItemType Directory -Force -Path $installDir,$reportDir,$previousDir,$stageDir | Out-Null
& icacls.exe $installDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
try {
  foreach ($name in $expected.Keys) { Invoke-WebRequest "$baseUrl/$name" -OutFile (Join-Path $stageDir $name) -UseBasicParsing -TimeoutSec 120 }
  foreach ($name in $expected.Keys) { if ((Get-FileHash (Join-Path $stageDir $name) -Algorithm SHA256).Hash.ToLower() -ne $expected[$name]) { throw "Integrity verification failed: $name" } }
  $currentTask=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  $taskSafe=[bool]($currentTask -and @($currentTask.Actions).Count -eq 1 -and $currentTask.Actions[0].Execute -match '(?i)(^|\\)powershell\.exe$' -and $currentTask.Actions[0].Arguments -ceq $taskArguments -and $currentTask.Principal.UserId -in @('SYSTEM','S-1-5-18'))
  $currentComplete=@($expected.Keys|Where-Object {-not (Test-Path (Join-Path $installDir $_))}).Count -eq 0 -and $taskSafe
  if($currentComplete){
    $previousStage=Join-Path $installDir ('.previous-stage-' + [Guid]::NewGuid().ToString('N'));$previousOld=Join-Path $installDir ('.previous-old-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $previousStage|Out-Null;$backupHashes=@{}
    foreach($name in $expected.Keys){$current=Join-Path $installDir $name;Copy-Item $current (Join-Path $previousStage $name);$backupHashes[$name]=(Get-FileHash $current -Algorithm SHA256).Hash.ToLower()}
    Export-ScheduledTask -TaskName $taskName | Set-Content (Join-Path $previousStage 'scheduled-task.xml') -Encoding Unicode
    $backupHashes['scheduled-task.xml']=(Get-FileHash (Join-Path $previousStage 'scheduled-task.xml') -Algorithm SHA256).Hash.ToLower()
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
function Test-SentinelUserTarget([string]$root,[string]$target){
  try{$rootFull=[IO.Path]::GetFullPath($root).TrimEnd('\');$targetFull=[IO.Path]::GetFullPath($target);if(-not $targetFull.StartsWith($rootFull+'\',[StringComparison]::OrdinalIgnoreCase)){return $false};$cursor=Split-Path $targetFull -Parent;while($cursor -and $cursor.Length -ge $rootFull.Length){if(Test-Path $cursor){if((Get-Item $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){return $false}};if($cursor -eq $rootFull){break};$cursor=Split-Path $cursor -Parent};if((Test-Path $targetFull) -and ((Get-Item $targetFull -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){return $false};return $true}catch{return $false}
}
function Set-SentinelUserTextAtomic([string]$root,[string]$target,[string]$content){
  if(-not (Test-SentinelUserTarget $root $target)){return $false};$parent=Split-Path $target -Parent;New-Item -ItemType Directory -Force -Path $parent|Out-Null;if(-not (Test-SentinelUserTarget $root $target)){return $false};if((Test-Path $target) -and -not (Test-Path $target -PathType Leaf)){return $false};$acl=if(Test-Path $target -PathType Leaf){Get-Acl $target}else{$null};$temp=Join-Path $parent ('.'+[IO.Path]::GetFileName($target)+'.'+[Guid]::NewGuid().ToString('N')+'.tmp')
  try{$encoding=[Text.UTF8Encoding]::new($true);$stream=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$preamble=$encoding.GetPreamble();$stream.Write($preamble,0,$preamble.Length);$bytes=$encoding.GetBytes($content);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()};if($acl){Set-Acl -Path $temp -AclObject $acl};if(-not (Test-SentinelUserTarget $root $target)){throw 'managed_target_changed'};Move-Item -LiteralPath $temp -Destination $target -Force;return $true}finally{Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
}
Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object {
  $targets=@()
  $codexDir=Join-Path $_.FullName '.codex';$claudeDir=Join-Path $_.FullName '.claude';$geminiDir=Join-Path $_.FullName '.gemini';$copilotDir=Join-Path $_.FullName '.copilot'
  if((Test-Path $codexDir) -and -not ((Get-Item $codexDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets += Join-Path $_.FullName '.codex\AGENTS.md'}
  if(((Test-Path $claudeDir) -and -not ((Get-Item $claudeDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) -or (Test-Path (Join-Path $_.FullName '.claude.json'))){$targets += Join-Path $_.FullName '.claude\CLAUDE.md'}
  if((Test-Path $geminiDir) -and -not ((Get-Item $geminiDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets += Join-Path $_.FullName '.gemini\GEMINI.md'}
  if((Test-Path $copilotDir) -and -not ((Get-Item $copilotDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets += Join-Path $_.FullName '.copilot\copilot-instructions.md'}
  foreach ($target in $targets) {
    if(-not (Test-SentinelUserTarget $_.FullName $target)){continue}
    $existing=if(Test-Path $target){Get-Content $target -Raw}else{''}
    $pattern=[regex]::Escape($userBaselineStart)+'.*?'+[regex]::Escape($userBaselineEnd)
    if($existing.Contains($userBaselineStart) -xor $existing.Contains($userBaselineEnd)){Write-Output "Sentinel baseline markers malformed; preserving $target";continue}
    if($existing -match [regex]::Escape($userBaselineStart)){$updated=[regex]::Replace($existing,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{param($match)$userBaselineBlock},[System.Text.RegularExpressions.RegexOptions]::Singleline)}
    else{$updated=$existing.TrimEnd()+$(if($existing.Trim()){"`n`n"}else{''})+$userBaselineBlock+"`n"}
    if($updated -ne $existing){$null=Set-SentinelUserTextAtomic $_.FullName $target $updated}
  }
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArguments
$periodicTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1)
$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$startupTrigger.Delay = 'PT2M'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($startupTrigger,$periodicTrigger) -Principal $principal -Settings $settings -Force | Out-Null
Write-Output 'Sentinel Agent installed and scheduled.'
