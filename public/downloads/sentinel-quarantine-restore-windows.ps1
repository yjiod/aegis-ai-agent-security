param(
  [Parameter(Mandatory=$true)][string]$EventPath,
  [Parameter(Mandatory=$true)][string]$ApprovalPath
)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator is required'}
foreach($path in @($EventPath,$ApprovalPath)){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 65536){throw 'Unsafe restore evidence'}}
$expectedAudit=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SentinelAgent\quarantine\audit'));if([IO.Path]::GetFullPath((Split-Path $EventPath -Parent)).TrimEnd('\') -cne $expectedAudit.TrimEnd('\')){throw 'Quarantine event is outside the protected audit directory'}
$unsafeSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545');foreach($path in @($EventPath,$ApprovalPath)){foreach($rule in (Get-Acl -LiteralPath $path).Access){try{$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}catch{throw 'Restore evidence ACL identity cannot be verified'};if($rule.AccessControlType -eq 'Allow' -and $sid -in $unsafeSids){throw 'Restore evidence is readable by a broad principal'}}}
$event=Get-Content -LiteralPath $EventPath -Raw|ConvertFrom-Json;$approval=Get-Content -LiteralPath $ApprovalPath -Raw|ConvertFrom-Json
$eventFields=@($event.PSObject.Properties.Name|Sort-Object);$approvalFields=@($approval.PSObject.Properties.Name|Sort-Object)
if(($eventFields -join ',') -cne 'action,disabled_path,kind,object_ref,occurred_at,original_path,restore_requires_external_approval,schema' -or $event.schema -cne 'sentinel.quarantine-event/v1' -or $event.action -cne 'disable' -or $event.restore_requires_external_approval -ne $true){throw 'Invalid quarantine event'}
if(($approvalFields -join ',') -cne 'approved_by_ref,decision,event_id,expires_at,issued_at,schema' -or $approval.schema -cne 'sentinel.quarantine-approval/v1' -or $approval.decision -cne 'restore' -or ([string]$approval.approved_by_ref) -notmatch '^[0-9a-f]{16,64}$' -or ([string]$approval.event_id) -cne ([IO.Path]::GetFileNameWithoutExtension($EventPath))){throw 'Invalid restore approval'}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();if([long]$approval.issued_at -gt $now+300 -or $now-[long]$approval.issued_at -gt 3600 -or [long]$approval.expires_at -lt $now -or [long]$approval.expires_at-$now -gt 3600){throw 'Stale restore approval'}
$original=[IO.Path]::GetFullPath([string]$event.original_path);$disabled=[IO.Path]::GetFullPath([string]$event.disabled_path)
if($disabled -cne ($original+'.sentinel-disabled') -or (Test-Path -LiteralPath $original) -or -not (Test-Path -LiteralPath $disabled -PathType Leaf) -or ((Get-Item -LiteralPath $disabled -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unsafe restore target'}
Move-Item -LiteralPath $disabled -Destination $original
try{
  $audit=Split-Path $EventPath -Parent;$record=Join-Path $audit (([Guid]::NewGuid().ToString('N'))+'.json');$restore=[ordered]@{schema='sentinel.quarantine-event/v1';action='restore';kind=[string]$event.kind;object_ref=[string]$event.object_ref;original_path=$original;disabled_path=$disabled;occurred_at=$now;approval_event_id=[IO.Path]::GetFileNameWithoutExtension($EventPath);approved_by_ref=[string]$approval.approved_by_ref}|ConvertTo-Json -Compress
  [IO.File]::WriteAllText($record,$restore,[Text.UTF8Encoding]::new($false));& icacls.exe $record /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C|Out-Null
}catch{Move-Item -LiteralPath $original -Destination $disabled -Force;throw}
Remove-Item -LiteralPath $ApprovalPath -Force
Write-Output 'Sentinel quarantine event restored with external approval evidence.'
