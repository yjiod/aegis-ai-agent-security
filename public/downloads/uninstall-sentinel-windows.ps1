$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
if (Test-Path $installDir) { if((Get-Item $installDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Sentinel installation directory is a reparse point; refusing recursive removal'} }
Unregister-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Confirm:$false -ErrorAction SilentlyContinue
$start='<!-- sentinel-managed-user-baseline:start -->';$end='<!-- sentinel-managed-user-baseline:end -->';$pattern=[regex]::Escape($start)+'.*?'+[regex]::Escape($end)
Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | ForEach-Object {
  if($_.Attributes -band [IO.FileAttributes]::ReparsePoint){return}
  foreach($relative in @('.codex\AGENTS.md','.claude\CLAUDE.md','.gemini\GEMINI.md','.copilot\copilot-instructions.md')){
    $path=Join-Path $_.FullName $relative
    if(Test-Path $path){$item=Get-Item $path;$parent=Get-Item (Split-Path $path);if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){continue};$current=Get-Content $path -Raw;$starts=[regex]::Matches($current,[regex]::Escape($start));$ends=[regex]::Matches($current,[regex]::Escape($end));if($starts.Count -ne 1 -or $ends.Count -ne 1 -or $starts[0].Index -ge $ends[0].Index){continue};$updated=[regex]::Replace($current,$pattern,'',[System.Text.RegularExpressions.RegexOptions]::Singleline,[TimeSpan]::FromSeconds(1));if($updated -ne $current){Set-Content -Encoding UTF8 -NoNewline $path $updated}}
  }
}
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
Write-Output 'Sentinel runtime and managed user baseline blocks removed. Repository rule files are retained for audit and must be removed through source control.'
