$ErrorActionPreference = 'Stop'
Unregister-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Confirm:$false -ErrorAction SilentlyContinue
$start='<!-- sentinel-managed-user-baseline:start -->';$end='<!-- sentinel-managed-user-baseline:end -->';$pattern=[regex]::Escape($start)+'.*?'+[regex]::Escape($end)
Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | ForEach-Object {
  foreach($relative in @('.codex\AGENTS.md','.claude\CLAUDE.md')){
    $path=Join-Path $_.FullName $relative
    if(Test-Path $path){$item=Get-Item $path;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){continue};$current=Get-Content $path -Raw;$updated=[regex]::Replace($current,$pattern,'',[System.Text.RegularExpressions.RegexOptions]::Singleline);if($updated -ne $current){Set-Content -Encoding UTF8 -NoNewline $path $updated}}
  }
}
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
Write-Output 'Sentinel runtime and managed user baseline blocks removed. Repository rule files are retained for audit and must be removed through source control.'
