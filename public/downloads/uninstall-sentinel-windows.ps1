$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
if (Test-Path $installDir) { if((Get-Item $installDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Sentinel installation directory is a reparse point; refusing recursive removal'} }
Unregister-ScheduledTask -TaskName 'Sentinel AI Agent Security Host' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Sentinel AI Agent Security Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Sentinel AI Agent Security User Bridge' -Confirm:$false -ErrorAction SilentlyContinue
$serviceName='SentinelAIAgentSecurity';$service=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if($service){
  if($service.Status -ne 'Stopped'){Stop-Service -Name $serviceName -Force;$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
  & sc.exe delete $serviceName|Out-Null
  if($LASTEXITCODE -ne 0){throw "SCM service removal failed: $LASTEXITCODE"}
}
$start='<!-- sentinel-managed-user-baseline:start -->';$end='<!-- sentinel-managed-user-baseline:end -->';$pattern=[regex]::Escape($start)+'.*?'+[regex]::Escape($end)
Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | ForEach-Object {
  if($_.Attributes -band [IO.FileAttributes]::ReparsePoint){return}
  foreach($relative in @('.codex\AGENTS.md','.claude\CLAUDE.md','.gemini\GEMINI.md','.copilot\copilot-instructions.md')){
    $path=Join-Path $_.FullName $relative
    if(Test-Path $path){$item=Get-Item $path;$parent=Get-Item (Split-Path $path);if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){continue};$current=Get-Content $path -Raw;$starts=[regex]::Matches($current,[regex]::Escape($start));$ends=[regex]::Matches($current,[regex]::Escape($end));if($starts.Count -ne 1 -or $ends.Count -ne 1 -or $starts[0].Index -ge $ends[0].Index){continue};$updated=[regex]::Replace($current,$pattern,'',[System.Text.RegularExpressions.RegexOptions]::Singleline,[TimeSpan]::FromSeconds(1));if($updated -ne $current){Set-Content -Encoding UTF8 -NoNewline $path $updated}}
  }
  $sessionDir=Join-Path $_.FullName 'AppData\Local\SentinelAgent'
  if(Test-Path -LiteralPath $sessionDir){$sessionItem=Get-Item -LiteralPath $sessionDir -Force;if(-not($sessionItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){$attestation=Join-Path $sessionDir 'session-attestation.json';if((Test-Path -LiteralPath $attestation) -and -not((Get-Item -LiteralPath $attestation -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){Remove-Item -LiteralPath $attestation -Force};Remove-Item -LiteralPath $sessionDir -Force -ErrorAction SilentlyContinue}}
}
$quarantine=Join-Path $installDir 'quarantine'
if(Test-Path -LiteralPath $quarantine){
  $item=Get-Item -LiteralPath $quarantine -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Sentinel quarantine is a reparse point; refusing uninstall'}
  $evidenceRoot=Join-Path $env:ProgramData 'SentinelAgent-Uninstall-Evidence';New-Item -ItemType Directory -Force -Path $evidenceRoot|Out-Null;& icacls.exe $evidenceRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C|Out-Null
  $destination=Join-Path $evidenceRoot ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N'));Move-Item -LiteralPath $quarantine -Destination $destination
}
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
Write-Output 'Sentinel runtime and managed user baseline blocks removed. Quarantine evidence and disabled user objects remain for approved recovery; Repository rule files remain under source control.'
