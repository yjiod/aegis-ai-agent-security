param([string]$Output = "$env:ProgramData\SentinelAgent\reports\latest.json",[string]$ReportUrl = $env:SENTINEL_REPORT_URL,[string]$ProtectedConfig = "$env:ProgramData\SentinelAgent\reporting.dpapi",[string]$ManagedUsersRoot = 'C:\Users',[switch]$Diagnostics)
$ErrorActionPreference = if($Diagnostics){'Stop'}else{'SilentlyContinue'}
$reportConfigInvalid=$false
if(Test-Path $ProtectedConfig){
  try{
    $encrypted=[IO.File]::ReadAllBytes($ProtectedConfig);$entropy=[Text.Encoding]::UTF8.GetBytes('SentinelAgent.Reporting.v1');$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try{$reportConfig=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json}finally{[Array]::Clear($plain,0,$plain.Length);[Array]::Clear($encrypted,0,$encrypted.Length)}
    $names=@($reportConfig.PSObject.Properties.Name|Sort-Object);$legacy=($names -join ',') -ceq 'report_token,report_url,schema,signing_secret' -and $reportConfig.schema -ceq 'sentinel.reporting/v1';$current=($names -join ',') -ceq 'policy_verification_keys,report_token,report_url,schema,signing_secret' -and $reportConfig.schema -ceq 'sentinel.reporting/v2';$bound=($names -join ',') -ceq 'device_id,policy_verification_keys,report_token,report_url,schema,signing_secret' -and $reportConfig.schema -ceq 'sentinel.reporting/v3';if(-not $legacy -and -not $current -and -not $bound){throw 'invalid reporting config contract'}
    if($bound -and [string]$reportConfig.device_id -cnotmatch '^[0-9a-f]{12}$'){throw 'invalid bound device identity'}
    $uri=$null;if(-not [Uri]::TryCreate([string]$reportConfig.report_url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'invalid reporting URL'}
    if(([string]$reportConfig.report_token).Length -lt 32 -or ([string]$reportConfig.report_token).Length -gt 4096 -or ([string]$reportConfig.signing_secret).Length -lt 32 -or ([string]$reportConfig.signing_secret).Length -gt 4096 -or $reportConfig.report_token -ceq $reportConfig.signing_secret){throw 'invalid reporting secrets'}
    $policyVerificationKeys=if($current){@($reportConfig.policy_verification_keys|ForEach-Object{[string]$_})}else{@()};if($policyVerificationKeys.Count -gt 5 -or @($policyVerificationKeys|Where-Object{$_.Length -lt 32 -or $_.Length -gt 4096}).Count -or @($policyVerificationKeys|Select-Object -Unique).Count -ne $policyVerificationKeys.Count -or $reportConfig.report_token -in $policyVerificationKeys -or $reportConfig.signing_secret -in $policyVerificationKeys){throw 'invalid policy verification keys'}
    $ReportUrl=[string]$reportConfig.report_url;$env:SENTINEL_REPORT_TOKEN=[string]$reportConfig.report_token;$env:SENTINEL_REPORT_SIGNING_SECRET=[string]$reportConfig.signing_secret
  }catch{$reportConfigInvalid=$true;$ReportUrl='';Remove-Item Env:SENTINEL_REPORT_TOKEN -ErrorAction SilentlyContinue;Remove-Item Env:SENTINEL_REPORT_SIGNING_SECRET -ErrorAction SilentlyContinue}
}
$roots = @()
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$baselinePath = Join-Path $installDir 'sentinel-security-baseline.md'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$policySyncFailed=$false
if($reportConfig -and $ReportUrl){
  try{
    $reportUri=[Uri]$ReportUrl;$policyUri=[Uri]::new($reportUri.GetLeftPart([UriPartial]::Authority)+'/v1/policy');$headers=@{Authorization='Bearer '+[string]$reportConfig.report_token;Accept='application/json'}
    $response=Invoke-WebRequest -UseBasicParsing -Uri $policyUri.AbsoluteUri -Method Get -Headers $headers -TimeoutSec 15 -MaximumRedirection 0
    $bytes=[Text.Encoding]::UTF8.GetBytes([string]$response.Content);if($response.StatusCode -ne 200 -or $bytes.Length -gt 2000000){throw 'invalid policy response'}
    $sha256=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-','').ToLower()}finally{$sha256.Dispose()}
    if(([string]$response.Headers['X-Sentinel-Policy-SHA256']) -cne $actual){throw 'policy digest mismatch'}
    if($policyVerificationKeys.Count -lt 1){throw 'policy verification key unavailable'}
    $suppliedSignature=[string]$response.Headers['X-Sentinel-Policy-Signature'];$suppliedKeyId=[string]$response.Headers['X-Sentinel-Policy-Key-ID'];$signatureValid=$false
    foreach($key in $policyVerificationKeys){$sha=[Security.Cryptography.SHA256]::Create();try{$keyId=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)))).Replace('-','').ToLower().Substring(0,16)}finally{$sha.Dispose()};if($keyId -cne $suppliedKeyId){continue};$hmac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($key));try{$expected='sha256='+([BitConverter]::ToString($hmac.ComputeHash($bytes))).Replace('-','').ToLower()}finally{$hmac.Dispose()};$signatureValid=$expected -ceq $suppliedSignature}
    if(-not $signatureValid){throw 'policy signature mismatch'}
    $remote=([string]$response.Content)|ConvertFrom-Json;if($remote.schema -cne 'sentinel.policy/v1' -or -not ([string]$remote.version)){throw 'invalid remote policy'}
    $local=Get-Content $policyPath -Raw|ConvertFrom-Json;if(([version]$remote.version) -lt ([version]$local.version)){throw 'policy downgrade rejected'}
    if(([version]$remote.version) -gt ([version]$local.version)){$temp=$policyPath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp';try{[IO.File]::WriteAllBytes($temp,$bytes);Move-Item -LiteralPath $temp -Destination $policyPath -Force}finally{Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}}
  }catch{$policySyncFailed=$true}
}
$policy=$null;$policyInvalid=$false
try {
  if(-not (Test-Path $policyPath)){throw 'missing policy'}
  $candidate=Get-Content $policyPath -Raw | ConvertFrom-Json
  if($candidate.schema -ne 'sentinel.policy/v1' -or -not ([string]$candidate.version)){throw 'invalid policy contract'}
  if($candidate.limits -isnot [PSCustomObject] -and $candidate.limits -isnot [hashtable]){throw 'invalid policy limits'}
  foreach($key in @('allowed_skills','monitored_skills','blocked_skills','allowed_mcp_transports','allowed_mcp_servers','monitored_mcp_servers','blocked_mcp_servers','blocked_mcp_fingerprints','allowed_mcp_commands','allowed_mcp_command_paths','allowed_mcp_invocations','allowed_mcp_domains','blocked_commands','secret_patterns','skill_rules','mcp_rules','code_rules')){
    if($null -ne $candidate.$key -and $candidate.$key -isnot [System.Array]){throw "invalid policy list: $key"}
    if($key -ne 'allowed_mcp_invocations'){foreach($value in @($candidate.$key)){if($value -isnot [string]){throw "invalid policy list item: $key"}}}
  }
  foreach($invocation in @($candidate.allowed_mcp_invocations)){if($invocation -isnot [System.Array] -or @($invocation).Count -lt 2 -or @($invocation|Where-Object{-not ($_ -is [string]) -or -not $_}).Count){throw 'invalid MCP invocation policy'}}
  foreach($fingerprint in @($candidate.blocked_mcp_fingerprints)){if($fingerprint -notmatch '^sha256:[0-9a-f]{64}$'){throw 'invalid MCP fingerprint policy'}}
  foreach($kind in @('skills','mcp_servers')){$allowed=@($candidate.PSObject.Properties['allowed_'+$kind].Value);$monitored=@($candidate.PSObject.Properties['monitored_'+$kind].Value);$blocked=@($candidate.PSObject.Properties['blocked_'+$kind].Value);if(@($allowed|Where-Object{$_ -in $monitored -or $_ -in $blocked}).Count -or @($monitored|Where-Object{$_ -in $blocked}).Count){throw 'conflicting disposition policy'}}
  foreach($secretPattern in @($candidate.secret_patterns)){$null=[regex]::new([string]$secretPattern,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(250))}
  if($null -ne $candidate.custom_rules -and $candidate.custom_rules -isnot [System.Array]){throw 'invalid custom rules'}
  if(@($candidate.custom_rules).Count -gt 500){throw 'too many custom rules'}
  $customIds=@{}
  foreach($rule in @($candidate.custom_rules)){
    if($rule -isnot [PSCustomObject] -or ([string]$rule.id) -notmatch '^[a-z0-9][a-z0-9_.-]{2,79}$' -or $customIds.ContainsKey([string]$rule.id) -or $rule.scope -notin @('all','code','skill','mcp') -or $rule.severity -notin @('critical','high','medium','low') -or -not ([string]$rule.message) -or ([string]$rule.message).Length -gt 240 -or -not ([string]$rule.pattern) -or ([string]$rule.pattern).Length -gt 1000){throw 'invalid custom rule'}
    $customIds[[string]$rule.id]=$true;$null=[regex]::new([string]$rule.pattern,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(250))
  }
  $policy=$candidate
} catch {$policyInvalid=$true}
$maxFileBytes=1000000
if($policy -and $policy.limits -and $policy.limits.max_file_bytes){$maxFileBytes=[Math]::Min([Math]::Max([int64]$policy.limits.max_file_bytes,65536),10000000)}
$projectFileLimit=10000
if($policy -and $policy.limits -and $policy.limits.project_files){$projectFileLimit=[Math]::Min([Math]::Max([int64]$policy.limits.project_files,100),100000)}
$managedMarker = '<!-- sentinel-managed-baseline -->'
$patterns = @(
  @{ Kind='prompt_override'; Severity='high'; Regex='(?i)ignore (all |any )?(previous|prior) instructions' },
  @{ Kind='credential_access'; Severity='high'; Regex='(?i)(~/|\$HOME/)(\.ssh|\.aws)|security\s+find-(generic|internet)-password' },
  @{ Kind='unbounded_shell'; Severity='high'; Regex='(?i)shell\s*=\s*true|Invoke-Expression|\biex\s' },
  @{ Kind='dynamic_eval'; Severity='medium'; Regex='(?i)\beval\s*\(|\bexec\s*\(' },
  @{ Kind='hidden_instruction'; Severity='high'; Regex='[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]' },
  @{ Kind='weak_random_token'; Severity='high'; Regex='(?is)(token|secret|session|nonce).{0,120}(Math\.random|random\.random)\s*\(|(Math\.random|random\.random)\s*\(.{0,120}(token|secret|session|nonce)' },
  @{ Kind='blocked_command'; Severity='high'; Regex='(?im)^\s*(curl\s+[^\r\n]*\|\s*(sh|bash)|wget\s+[^\r\n]*\|\s*(sh|bash)|chmod\s+777|rm\s+-rf)(\s|$)' },
  @{ Kind='insecure_tls_verification'; Severity='critical'; Regex='(?is)\brequests\.(get|post|put|patch|delete|request)\s*\([^)]{0,500}\bverify\s*=\s*false|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'']?0' },
  @{ Kind='unsafe_deserialization'; Severity='high'; Regex='(?i)\bpickle\.loads?\s*\(|\bBinaryFormatter\s*\(|\bObjectInputStream\s*\(' },
  @{ Kind='debug_mode_enabled'; Severity='medium'; Regex='(?is)\b(app|application)\.run\s*\([^)]{0,300}\bdebug\s*=\s*true' },
  @{ Kind='empty_exception_handler'; Severity='medium'; Regex='(?m)^\s*except(\s+[^:]+)?:\s*(#.*\r?\n\s*)?pass\s*$|\bcatch\s*\{\s*\}' }
)
if($policy){foreach($secretPattern in @($policy.secret_patterns)){$patterns += @{Kind='hardcoded_secret';Severity='critical';Regex=[string]$secretPattern}}}
$compiledPatterns=@();foreach($rule in $patterns){$compiledPatterns += @{Kind=$rule.Kind;Severity=$rule.Severity;Compiled=[regex]::new([string]$rule.Regex,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(250))}}
$findings = @(); $inventory = @()
if($policyInvalid){$findings += @{kind='policy_load_failed';severity='high';path=$policyPath;message='安全策略缺失或契约无效；MCP 策略检查采用失败关闭状态'}}
if($reportConfigInvalid){$findings += @{kind='reporting_config_invalid';severity='high';path='reporting.dpapi';message='受保护上报配置无法解密或契约无效；本轮拒绝上报'}}
if($policySyncFailed){$findings += @{kind='policy_sync_failed';severity='medium';path='sentinel-policy.json';message='动态策略同步失败，继续使用上一份有效策略'}}
function Send-SentinelReport([string]$json,[string]$url) {
  $bytes=[Text.Encoding]::UTF8.GetBytes($json);$headers=@{}
  try{$sentReport=$json|ConvertFrom-Json;$sentDeviceId=[string]$sentReport.device_id}catch{throw 'Report device identity is invalid'}
  if($sentDeviceId -notmatch '^[a-f0-9]{12}$'){throw 'Report device identity is invalid'}
  $headers['X-Sentinel-Device-ID']=$sentDeviceId
  $sha256=[Security.Cryptography.SHA256]::Create();try{$expectedReportId=([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-','').ToLower().Substring(0,20)}finally{$sha256.Dispose()}
  if($env:SENTINEL_REPORT_TOKEN){$headers.Authorization='Bearer '+$env:SENTINEL_REPORT_TOKEN}
  if($env:SENTINEL_REPORT_SIGNING_SECRET){
    $timestamp=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString();$prefix=[Text.Encoding]::UTF8.GetBytes($timestamp+'.'+$sentDeviceId+'.');$signed=New-Object byte[] ($prefix.Length+$bytes.Length);[Array]::Copy($prefix,0,$signed,0,$prefix.Length);[Array]::Copy($bytes,0,$signed,$prefix.Length,$bytes.Length)
    $hmac=[System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($env:SENTINEL_REPORT_SIGNING_SECRET));$signature=([BitConverter]::ToString($hmac.ComputeHash($signed))).Replace('-','').ToLower();$hmac.Dispose()
    $headers['X-Sentinel-Timestamp']=$timestamp;$headers['X-Sentinel-Signature']='sha256='+$signature
  }
  $response=Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 15
  $ackBytes=[Text.Encoding]::UTF8.GetByteCount([string]$response.Content)
  if($response.StatusCode -notin @(200,202) -or $ackBytes -gt 4096){throw 'Collector acknowledgement contract is invalid'}
  try{$ack=([string]$response.Content)|ConvertFrom-Json}catch{throw 'Collector acknowledgement contract is invalid'}
  $names=@($ack.PSObject.Properties.Name|Sort-Object)
  if(($names -join ',') -cne 'accepted,duplicate,report_id,severity' -or $ack.accepted -isnot [bool] -or -not $ack.accepted -or $ack.duplicate -isnot [bool] -or ([string]$ack.report_id) -cne $expectedReportId -or $ack.severity -notin @('critical','high','normal')){throw 'Collector acknowledgement contract is invalid'}
  return $ack
}
function Write-SentinelUploadStatus([string]$url){
  $uri=[Uri]$url;$status=@{schema='sentinel.upload-status/v1';status='accepted';last_success=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();collector_host=$uri.DnsSafeHost.ToLower()}|ConvertTo-Json -Compress
  $path=Join-Path (Split-Path $Output) 'upload-status.json';$temp=$path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
  try{$status|Set-Content -Encoding UTF8 $temp;Move-Item $temp $path -Force}finally{Remove-Item $temp -Force -ErrorAction SilentlyContinue}
}
function Protect-SentinelPath([string]$path) {
  foreach ($userHome in $userHomes) { if ($path.StartsWith($userHome.FullName,[StringComparison]::OrdinalIgnoreCase)) { return '~' + $path.Substring($userHome.FullName.Length) } }
  return $path
}
$script:disabledTargets=@{}
function Disable-SentinelTarget([System.IO.FileInfo]$file,[string]$kind,[string]$objectName) {
  if($script:disabledTargets.ContainsKey($file.FullName)){return $true}
  try{
    if(-not $file.Exists -or $file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'unsafe enforcement target'}
    $disabled=$file.FullName+'.sentinel-disabled';if(Test-Path -LiteralPath $disabled){throw 'quarantine collision'}
    $quarantine=Join-Path $installDir 'quarantine';$audit=Join-Path $quarantine 'audit';New-Item -ItemType Directory -Force -Path $audit|Out-Null
    & icacls.exe $quarantine /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C|Out-Null
    Move-Item -LiteralPath $file.FullName -Destination $disabled
    try{
      $sha=[Security.Cryptography.SHA256]::Create();try{$objectRef=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($objectName)))).Replace('-','').ToLower().Substring(0,16)}finally{$sha.Dispose()}
      $event=[ordered]@{schema='sentinel.quarantine-event/v1';action='disable';kind=$kind;object_ref=$objectRef;original_path=$file.FullName;disabled_path=$disabled;occurred_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();restore_requires_external_approval=$true}|ConvertTo-Json -Compress
      $record=Join-Path $audit (([Guid]::NewGuid().ToString('N'))+'.json');$temp=$record+'.tmp';[IO.File]::WriteAllText($temp,$event,[Text.UTF8Encoding]::new($false));& icacls.exe $temp /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C|Out-Null;Move-Item -LiteralPath $temp -Destination $record
    }catch{Move-Item -LiteralPath $disabled -Destination $file.FullName -Force;throw}
    $script:disabledTargets[$file.FullName]=$true;return $true
  }catch{return $false}
}
function Test-SentinelMcpInvocation([string]$command,[object[]]$args) {
  $actual=@($command)+@($args|ForEach-Object{[string]$_});if($actual.Count -le 1){return $true}
  foreach($candidate in @($policy.allowed_mcp_invocations)){
    $expected=@($candidate|ForEach-Object{[string]$_});if($expected.Count -ne $actual.Count){continue};$same=$true
    for($index=0;$index -lt $actual.Count;$index++){if($actual[$index] -cne $expected[$index]){$same=$false;break}}
    if($same){return $true}
  }
  return $false
}
function Get-SentinelMcpFingerprint([string]$name,[string]$command,[object[]]$args,[string]$url,[string]$transport){
  $canonical=[ordered]@{args=@($args|ForEach-Object{[string]$_});command=$command;name=$name;transport=$transport;url=$url}|ConvertTo-Json -Compress
  $sha=[Security.Cryptography.SHA256]::Create();try{return 'sha256:'+([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-','').ToLower()}finally{$sha.Dispose()}
}
function Test-SentinelSafeTarget([string]$root,[string]$target) {
  try {
    $rootFull=[IO.Path]::GetFullPath($root).TrimEnd('\');$targetFull=[IO.Path]::GetFullPath($target)
    if(-not $targetFull.StartsWith($rootFull+'\',[StringComparison]::OrdinalIgnoreCase)){return $false}
    $cursor=Split-Path $targetFull -Parent
    while($cursor -and $cursor.Length -ge $rootFull.Length){
      if(Test-Path $cursor){$item=Get-Item $cursor -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){return $false}}
      if($cursor -eq $rootFull){break};$next=Split-Path $cursor -Parent;if($next -eq $cursor){break};$cursor=$next
    }
    if(Test-Path $targetFull){$item=Get-Item $targetFull -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){return $false}}
    return $true
  } catch { return $false }
}
function Set-SentinelManagedTextAtomic([string]$root,[string]$target,[string]$content) {
  if(-not (Test-SentinelSafeTarget $root $target)){return $false}
  $parent=Split-Path $target -Parent
  New-Item -ItemType Directory -Force -Path $parent|Out-Null
  if(-not (Test-SentinelSafeTarget $root $target)){return $false}
  if((Test-Path $target) -and -not (Test-Path $target -PathType Leaf)){return $false}
  $existingAcl=if(Test-Path $target -PathType Leaf){Get-Acl $target}else{$null}
  $temp=Join-Path $parent ('.'+[IO.Path]::GetFileName($target)+'.'+[Guid]::NewGuid().ToString('N')+'.tmp')
  try {
    $encoding=[Text.UTF8Encoding]::new($true)
    $stream=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$preamble=$encoding.GetPreamble();$stream.Write($preamble,0,$preamble.Length);$bytes=$encoding.GetBytes($content);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if($existingAcl){Set-Acl -Path $temp -AclObject $existingAcl}
    if(-not (Test-SentinelSafeTarget $root $target)){throw 'managed_target_changed'}
    Move-Item -LiteralPath $temp -Destination $target -Force
    return $true
  } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
}
function Install-SentinelBaseline([string]$repo) {
  if (-not (Test-Path $baselinePath)) { return }
  $baseline = Get-Content $baselinePath -Raw
  $managed = "$managedMarker`n$baseline"
  $ruleTargets = @((Join-Path $repo '.cursor\rules\sentinel-security.mdc'),(Join-Path $repo '.windsurf\rules\sentinel-security.md'))
  foreach ($target in $ruleTargets) {
    if(-not (Test-SentinelSafeTarget $repo $target)){continue}
    $existing=if(Test-Path $target -PathType Leaf){Get-Content $target -Raw}else{''}
    if($existing -cne $managed){$null=Set-SentinelManagedTextAtomic $repo $target $managed}
  }
  foreach ($name in @('AGENTS.md','CLAUDE.md','GEMINI.md')) {
    $target=Join-Path $repo $name;if(-not (Test-SentinelSafeTarget $repo $target)){continue};$existing=if(Test-Path $target){Get-Content $target -Raw}else{''}
    if ($existing -notlike "*$managedMarker*") {$updated=$existing.TrimEnd()+"`n$managedMarker`n## 企业安全基线`n执行任何代码变更前必须遵循 .sentinel/SECURITY_BASELINE.md。`n";$null=Set-SentinelManagedTextAtomic $repo $target $updated}
  }
  $shared=Join-Path $repo '.sentinel\SECURITY_BASELINE.md';if(Test-SentinelSafeTarget $repo $shared){$existing=if(Test-Path $shared -PathType Leaf){Get-Content $shared -Raw}else{''};if($existing -cne $managed){$null=Set-SentinelManagedTextAtomic $repo $shared $managed}}
}
function Sync-SentinelUserBaselines([object[]]$homes) {
  if(-not (Test-Path $baselinePath)){return}
  $content=(Get-Content $baselinePath -Raw).TrimEnd();$start='<!-- sentinel-managed-user-baseline:start -->';$end='<!-- sentinel-managed-user-baseline:end -->';$block=$start+"`n"+$content+"`n"+$end
  foreach($userHome in $homes){
    $targets=@();$codex=Join-Path $userHome.FullName '.codex';$claude=Join-Path $userHome.FullName '.claude';$gemini=Join-Path $userHome.FullName '.gemini';$copilot=Join-Path $userHome.FullName '.copilot'
    if((Test-Path $codex) -and -not ((Get-Item $codex -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets+=Join-Path $codex 'AGENTS.md'}
    if(((Test-Path $claude) -and -not ((Get-Item $claude -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) -or (Test-Path (Join-Path $userHome.FullName '.claude.json'))){$targets+=Join-Path $claude 'CLAUDE.md'}
    if((Test-Path $gemini) -and -not ((Get-Item $gemini -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets+=Join-Path $gemini 'GEMINI.md'}
    if((Test-Path $copilot) -and -not ((Get-Item $copilot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets+=Join-Path $copilot 'copilot-instructions.md'}
    foreach($target in $targets){
      if(-not (Test-SentinelSafeTarget $userHome.FullName $target)){continue};New-Item -ItemType Directory -Force -Path (Split-Path $target)|Out-Null;if(-not (Test-SentinelSafeTarget $userHome.FullName $target)){continue}
      $existing=if(Test-Path $target){Get-Content $target -Raw}else{''};$pattern=[regex]::Escape($start)+'.*?'+[regex]::Escape($end)
      if($existing.Contains($start) -xor $existing.Contains($end)){$script:findings+=@{kind='malformed_user_baseline_block';severity='high';path=(Protect-SentinelPath $target);message='用户级安全基线托管标记不完整，已停止自动修改'};continue}
      if($existing.Contains($start)){$updated=[regex]::Replace($existing,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{param($match)$block},[System.Text.RegularExpressions.RegexOptions]::Singleline)}else{$updated=$existing.TrimEnd()+$(if($existing.Trim()){"`n`n"}else{''})+$block+"`n"}
      if($updated -ne $existing){$null=Set-SentinelManagedTextAtomic $userHome.FullName $target $updated}
    }
  }
}
function Get-SentinelUserBaselineStatus([string]$userHomePath,[string]$agent) {
  $relative=switch($agent){'codex'{'.codex\AGENTS.md'}'claude_code'{'.claude\CLAUDE.md'}'gemini_cli'{'.gemini\GEMINI.md'}'github_copilot_cli'{'.copilot\copilot-instructions.md'}default{return $null}}
  $target=Join-Path $userHomePath $relative
  if(-not (Test-SentinelSafeTarget $userHomePath $target)){return @{path=$target;status='unsafe'}}
  if(-not (Test-Path $target -PathType Leaf)){return @{path=$target;status='missing'}}
  try{
    $text=Get-Content $target -Raw;$start='<!-- sentinel-managed-user-baseline:start -->';$end='<!-- sentinel-managed-user-baseline:end -->';$expected=(Get-Content $baselinePath -Raw).TrimEnd()
    $matches=[regex]::Matches($text,[regex]::Escape($start)+"`n(.*?)`n"+[regex]::Escape($end),[Text.RegularExpressions.RegexOptions]::Singleline)
    if($matches.Count -eq 1 -and $matches[0].Groups[1].Value.TrimEnd() -ceq $expected){return @{path=$target;status='managed'}}
    return @{path=$target;status='malformed'}
  }catch{return @{path=$target;status='unreadable'}}
}
function Inspect-SentinelMcpJson([System.IO.FileInfo]$file,[string]$text) {
  if (-not $policy) { return }
  try { $config=$text | ConvertFrom-Json } catch { $script:findings += @{kind='invalid_mcp_config';severity='medium';path=(Protect-SentinelPath $file.FullName);message='MCP JSON 配置无法解析'}; return }
  $servers=if($config.mcpServers){$config.mcpServers}else{$config.servers}
  if (-not $servers) { return }
  foreach($entry in $servers.PSObject.Properties) {
    $name=$entry.Name; $cfg=$entry.Value; $safePath=Protect-SentinelPath $file.FullName
    if($cfg -isnot [PSCustomObject] -and $cfg -isnot [hashtable]){$script:findings += @{kind='invalid_mcp_server';severity='high';path=$safePath;message="MCP Server $name 配置必须是对象"};continue}
    if($name -in @($policy.blocked_mcp_servers)){$script:findings += @{kind='blocked_mcp';severity='critical';path=$safePath;message="已拉黑的 MCP Server: $name";evidence='[REDACTED]'};if(Disable-SentinelTarget $file 'mcp_config' $name){$script:findings += @{kind='mcp_config_quarantined';severity='critical';path=$safePath;message='包含拒绝 MCP 的配置已整体禁用；恢复需要外部审批';evidence='[REDACTED]'}}else{$script:findings += @{kind='mcp_quarantine_failed';severity='critical';path=$safePath;message='MCP 配置禁用失败；要求终端平台介入'}}}elseif($name -notin @($policy.allowed_mcp_servers) -and $name -notin @($policy.monitored_mcp_servers)){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"};if($policy.enforcement.unknown_mcp -eq 'block'){if(Disable-SentinelTarget $file 'mcp_config' $name){$script:findings += @{kind='mcp_config_quarantined';severity='critical';path=$safePath;message='包含未批准 MCP 的配置已整体禁用；恢复需要外部审批'}}else{$script:findings += @{kind='mcp_quarantine_failed';severity='critical';path=$safePath;message='MCP 配置禁用失败；要求终端平台介入'}}}}
    $rawCommand=[string]$cfg.command;$command=[IO.Path]::GetFileName($rawCommand)
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
    if($rawCommand -match '[\\/]' -and $rawCommand -notin @($policy.allowed_mcp_command_paths)){$script:findings += @{kind='unapproved_mcp_command_path';severity='high';path=$safePath;message="MCP $name 使用未批准的可执行路径"}}
    $invocationArgs=@($cfg.args)
    if($command -and -not (Test-SentinelMcpInvocation $command $invocationArgs)){$script:findings += @{kind='unapproved_mcp_invocation';severity='high';path=$safePath;message="MCP $name 的命令参数组合未获批准"}}
    foreach($arg in @($cfg.args)){if(([string]$arg) -in @('/','C:\','$HOME','~') -or ([string]$arg) -match '^[A-Za-z]:\\Users\\'){$script:findings += @{kind='broad_filesystem_scope';severity='high';path=$safePath;message="MCP $name 请求宽泛文件范围"};break}}
    if($null -ne $cfg.env -and $cfg.env -isnot [PSCustomObject] -and $cfg.env -isnot [hashtable]){$script:findings += @{kind='invalid_mcp_environment';severity='high';path=$safePath;message="MCP $name 的 env 必须是对象"}}
    else{foreach($variable in @($cfg.env.PSObject.Properties)){if($variable.Name -match 'TOKEN|SECRET|PASSWORD|API_KEY' -and ([string]$variable.Value) -notmatch '^\$\{?[A-Z0-9_]+\}?$'){$script:findings += @{kind='literal_mcp_secret';severity='critical';path=$safePath;message="MCP $name 包含明文敏感环境变量: $($variable.Name)";evidence='[REDACTED]'}}}}
    $url=[string]$cfg.url; if(-not $url){$url=[string]$cfg.httpUrl};if(-not $url){$url=[string]$cfg.serverUrl}
    $transport=[string]$cfg.transport;if(-not $transport){$transport=[string]$cfg.type};if($transport -eq 'local'){$transport='stdio'}elseif($transport -eq 'remote'){$transport=if($url.StartsWith('https://')){'https'}else{'http'}};if(-not $transport){if($url.StartsWith('https://')){$transport='https'}elseif($url.StartsWith('http://')){$transport='http'}elseif($command){$transport='stdio'}else{$transport='unknown'}}
    if($command -and $url){$script:findings += @{kind='ambiguous_mcp_transport';severity='high';path=$safePath;message="MCP $name 同时配置本地命令和远程 URL"}}
    if(($policy.PSObject.Properties.Name -contains 'allowed_mcp_transports') -and $transport -notin @($policy.allowed_mcp_transports)){$script:findings += @{kind='unapproved_mcp_transport';severity='high';path=$safePath;message="MCP $name 使用未批准传输: $transport"}}
    $fingerprint=Get-SentinelMcpFingerprint $name $rawCommand $invocationArgs $url $transport;if($fingerprint -in @($policy.blocked_mcp_fingerprints)){$script:findings += @{kind='blocked_mcp_fingerprint';severity='critical';path=$safePath;message="MCP $name 与已拉黑配置指纹一致";evidence=$fingerprint};if(Disable-SentinelTarget $file 'mcp_config' $name){$script:findings += @{kind='mcp_config_quarantined';severity='critical';path=$safePath;message='指纹命中拒绝列表的 MCP 配置已禁用';evidence='[REDACTED]'}}else{$script:findings += @{kind='mcp_quarantine_failed';severity='critical';path=$safePath;message='MCP 配置禁用失败；要求终端平台介入'}}}
    if($url){
      try{$uri=[Uri]$url;$host=$uri.DnsSafeHost.ToLower().TrimEnd('.')}catch{$script:findings += @{kind='invalid_mcp_url';severity='high';path=$safePath;message="MCP $name URL 无法解析"};continue}
      if($uri.Scheme -ne 'https'){$script:findings += @{kind='insecure_mcp_transport';severity='high';path=$safePath;message="MCP $name 未使用 HTTPS"}}
      if(($policy.PSObject.Properties.Name -contains 'allowed_mcp_domains') -and $host -notin @($policy.allowed_mcp_domains)){$script:findings += @{kind='unapproved_mcp_domain';severity='medium';path=$safePath;message="MCP $name 连接未批准域名: $host"}}
      if($uri.UserInfo -or $uri.Query -match '(?i)(token|key|api_key|apikey|secret|password|access_token)='){$script:findings += @{kind='mcp_url_credentials';severity='critical';path=$safePath;message="MCP $name URL 包含凭据或敏感查询参数";evidence='[REDACTED]'}}
    }
    if(-not $command -and -not $url){$script:findings += @{kind='incomplete_mcp_server';severity='medium';path=$safePath;message="MCP $name 未配置命令或 URL"}}
  }
}
function Inspect-SentinelMcpToml([System.IO.FileInfo]$file,[string]$text) {
  if (-not $policy) { return }
  $safePath=Protect-SentinelPath $file.FullName
  $sections=[regex]::Matches($text,'(?ms)^\[mcp_servers\.([A-Za-z0-9_.-]+)\]\s*(.*?)(?=^\[|\z)')
  foreach($section in $sections) {
    $name=$section.Groups[1].Value;if($name.EndsWith('.env')){continue};$body=$section.Groups[2].Value
    $match=[regex]::Match($body,'(?m)^\s*command\s*=\s*"([^"]+)"');$rawCommand=if($match.Success){$match.Groups[1].Value}else{''};$command=if($rawCommand){[IO.Path]::GetFileName($rawCommand)}else{''}
    $match=[regex]::Match($body,'(?m)^\s*url\s*=\s*"([^"]+)"');$url=if($match.Success){$match.Groups[1].Value}else{''}
    $match=[regex]::Match($body,'(?m)^\s*transport\s*=\s*"([^"]+)"');$transport=if($match.Success){$match.Groups[1].Value.ToLower()}else{''}
    $args=@();$match=[regex]::Match($body,'(?ms)^\s*args\s*=\s*\[(.*?)\]');if($match.Success){foreach($arg in [regex]::Matches($match.Groups[1].Value,'"([^"]+)"')){$args += $arg.Groups[1].Value}}
    if($name -in @($policy.blocked_mcp_servers)){$script:findings += @{kind='blocked_mcp';severity='critical';path=$safePath;message="已拉黑的 MCP Server: $name";evidence='[REDACTED]'};if(Disable-SentinelTarget $file 'mcp_config' $name){$script:findings += @{kind='mcp_config_quarantined';severity='critical';path=$safePath;message='包含拒绝 MCP 的 TOML 配置已整体禁用；恢复需要外部审批';evidence='[REDACTED]'}}else{$script:findings += @{kind='mcp_quarantine_failed';severity='critical';path=$safePath;message='MCP TOML 配置禁用失败；要求终端平台介入'}}}elseif($name -notin @($policy.allowed_mcp_servers) -and $name -notin @($policy.monitored_mcp_servers)){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"};if($policy.enforcement.unknown_mcp -eq 'block'){if(Disable-SentinelTarget $file 'mcp_config' $name){$script:findings += @{kind='mcp_config_quarantined';severity='critical';path=$safePath;message='包含未批准 MCP 的 TOML 配置已整体禁用；恢复需要外部审批'}}else{$script:findings += @{kind='mcp_quarantine_failed';severity='critical';path=$safePath;message='MCP TOML 配置禁用失败；要求终端平台介入'}}}}
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
    if($rawCommand -match '[\\/]' -and $rawCommand -notin @($policy.allowed_mcp_command_paths)){$script:findings += @{kind='unapproved_mcp_command_path';severity='high';path=$safePath;message="MCP $name 使用未批准的可执行路径"}}
    if($command -and -not (Test-SentinelMcpInvocation $command $args)){$script:findings += @{kind='unapproved_mcp_invocation';severity='high';path=$safePath;message="MCP $name 的命令参数组合未获批准"}}
    foreach($arg in $args){if($arg -in @('/','C:\','$HOME','~') -or $arg -match '^[A-Za-z]:\\Users\\'){$script:findings += @{kind='broad_filesystem_scope';severity='high';path=$safePath;message="MCP $name 请求宽泛文件范围"};break}}
    if(-not $transport){if($url.StartsWith('https://')){$transport='https'}elseif($url.StartsWith('http://')){$transport='http'}elseif($command){$transport='stdio'}else{$transport='unknown'}}
    if($command -and $url){$script:findings += @{kind='ambiguous_mcp_transport';severity='high';path=$safePath;message="MCP $name 同时配置本地命令和远程 URL"}}
    if(($policy.PSObject.Properties.Name -contains 'allowed_mcp_transports') -and $transport -notin @($policy.allowed_mcp_transports)){$script:findings += @{kind='unapproved_mcp_transport';severity='high';path=$safePath;message="MCP $name 使用未批准传输: $transport"}}
    $fingerprint=Get-SentinelMcpFingerprint $name $rawCommand $args $url $transport;if($fingerprint -in @($policy.blocked_mcp_fingerprints)){$script:findings += @{kind='blocked_mcp_fingerprint';severity='critical';path=$safePath;message="MCP $name 与已拉黑配置指纹一致";evidence=$fingerprint};if(Disable-SentinelTarget $file 'mcp_config' $name){$script:findings += @{kind='mcp_config_quarantined';severity='critical';path=$safePath;message='指纹命中拒绝列表的 MCP TOML 配置已禁用';evidence='[REDACTED]'}}else{$script:findings += @{kind='mcp_quarantine_failed';severity='critical';path=$safePath;message='MCP TOML 配置禁用失败；要求终端平台介入'}}}
    if($url){
      try{$uri=[Uri]$url;$host=$uri.DnsSafeHost.ToLower().TrimEnd('.')}catch{$script:findings += @{kind='invalid_mcp_url';severity='high';path=$safePath;message="MCP $name URL 无法解析"};continue}
      if($uri.Scheme -ne 'https'){$script:findings += @{kind='insecure_mcp_transport';severity='high';path=$safePath;message="MCP $name 未使用 HTTPS"}}
      if(($policy.PSObject.Properties.Name -contains 'allowed_mcp_domains') -and $host -notin @($policy.allowed_mcp_domains)){$script:findings += @{kind='unapproved_mcp_domain';severity='medium';path=$safePath;message="MCP $name 连接未批准域名: $host"}}
      if($uri.UserInfo -or $uri.Query -match '(?i)(token|key|api_key|apikey|secret|password|access_token)='){$script:findings += @{kind='mcp_url_credentials';severity='critical';path=$safePath;message="MCP $name URL 包含凭据或敏感查询参数";evidence='[REDACTED]'}}
    }
    if(-not $command -and -not $url){$script:findings += @{kind='incomplete_mcp_server';severity='medium';path=$safePath;message="MCP $name 未配置命令或 URL"}}
  }
  foreach($secret in [regex]::Matches($text,'(?im)^\s*([A-Z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY)[A-Z0-9_]*)\s*=\s*"([^"]+)"')){
    if($secret.Groups[3].Value -notmatch '^\$\{?[A-Z0-9_]+\}?$'){$script:findings += @{kind='literal_mcp_secret';severity='critical';path=$safePath;message="MCP TOML 包含明文敏感环境变量: $($secret.Groups[1].Value)";evidence='[REDACTED]'}}
  }
}
function Inspect-SentinelDependencies([System.IO.FileInfo]$file,[string]$text) {
  $safePath=Protect-SentinelPath $file.FullName
  if($file.Name -eq 'package.json') {
    try{$manifest=$text|ConvertFrom-Json}catch{$script:findings += @{kind='invalid_dependency_manifest';severity='medium';path=$safePath;message='package.json 无法解析'};return}
    $hasDependencies=$false
    foreach($group in @('dependencies','devDependencies','optionalDependencies','peerDependencies')){
      foreach($entry in @($manifest.$group.PSObject.Properties)){
        $hasDependencies=$true;$version=[string]$entry.Value
        if($version -match '^(?i)(https?://|git(\+|://)|github:)'){$script:findings += @{kind='dependency_untrusted_source';severity='high';path=$safePath;message="依赖 $($entry.Name) 直接使用远程源码"}}
        elseif($version -match '^(\*|latest|next|[~^<>=])'){$script:findings += @{kind='dependency_unpinned';severity='medium';path=$safePath;message="依赖 $($entry.Name) 未固定到精确版本"}}
      }
    }
    $hasLock=$false;foreach($name in @('package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb')){if(Test-Path (Join-Path $file.DirectoryName $name)){$hasLock=$true;break}}
    if($hasDependencies -and -not $hasLock){$script:findings += @{kind='missing_lockfile';severity='medium';path=$safePath;message='JavaScript 依赖缺少受支持的锁文件'}}
  } elseif($file.Name -like 'requirements*.txt') {
    foreach($line in $text -split "`r?`n"){$value=$line.Trim();if(-not $value -or $value.StartsWith('#')){continue};if($value -match '^(?i)(-e\s+)?(https?://|git\+)'){$script:findings += @{kind='dependency_untrusted_source';severity='high';path=$safePath;message='Python 依赖直接使用远程源码'}}elseif($value -notmatch '=='){$script:findings += @{kind='dependency_unpinned';severity='medium';path=$safePath;message='Python 依赖未固定到精确版本'}}}
  }
}
function Get-ManagedRepos {
  $repos=@()
  Get-ChildItem $ManagedUsersRoot -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object {
    foreach($relative in @('source\repos','Documents\GitHub','Projects','Code')) {
      $base=Join-Path $_.FullName $relative
      if((Test-Path $base) -and -not ((Get-Item $base -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        if((Test-Path (Join-Path $base '.git')) -and -not ((Get-Item (Join-Path $base '.git') -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$repos += $base}
        Get-ChildItem $base -Directory -Recurse -Depth 4 | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (Test-Path (Join-Path $_.FullName '.git')) -and -not ((Get-Item (Join-Path $_.FullName '.git') -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object { $repos += $_.FullName }
      }
    }
  }
  return $repos | Select-Object -Unique
}
$userHomes = @(Get-ChildItem $ManagedUsersRoot -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
Sync-SentinelUserBaselines $userHomes
$supportedSessionAgents=@('cursor','claude_code','codex','windsurf','gemini_cli','github_copilot_cli','workbuddy','qwen_enterprise','tongyi_lingma','codebuddy')
foreach($userHome in $userHomes){
  $sessionPath=Join-Path $userHome.FullName 'AppData\Local\SentinelAgent\session-attestation.json'
  if(-not(Test-Path -LiteralPath $sessionPath)){continue}
  try{
    $sessionFile=Get-Item -LiteralPath $sessionPath -Force;if($sessionFile.Attributes -band [IO.FileAttributes]::ReparsePoint -or $sessionFile.Length -gt 4096){throw 'unsafe user session file'}
    $session=Get-Content -LiteralPath $sessionPath -Raw|ConvertFrom-Json;$expectedSessionNames=@('agents','arbitrary_command_enabled','baseline_failures','baseline_targets','baseline_writes','host_version','platform','schema','updated_at')
    $sessionNames=@($session.PSObject.Properties.Name|Sort-Object);$agents=@($session.agents);$uniqueAgents=@($agents|Select-Object -Unique);$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$age=$now-[long]$session.updated_at
    if(($sessionNames -join ',') -cne ($expectedSessionNames -join ',') -or $session.schema -cne 'sentinel.user-session/v1' -or [string]$session.host_version -notmatch '^\d+\.\d+\.\d+$' -or $session.platform -cne 'windows' -or $session.arbitrary_command_enabled -ne $false -or $agents.Count -gt 10 -or $uniqueAgents.Count -ne $agents.Count -or @($agents|Where-Object{$_ -notin $supportedSessionAgents}).Count -or [int]$session.baseline_targets -lt 0 -or [int]$session.baseline_targets -gt 4 -or [int]$session.baseline_writes -lt 0 -or [int]$session.baseline_failures -lt 0 -or [int]$session.baseline_writes+[int]$session.baseline_failures -ne [int]$session.baseline_targets -or $age -lt -300 -or $age -gt 7200){throw 'invalid user session contract'}
    $sessionStatus=if([int]$session.baseline_failures -eq 0){'healthy'}else{'degraded'};$inventory+=@{type='user_session';host_version=[string]$session.host_version;status=$sessionStatus;updated_at=[long]$session.updated_at;agent_count=$agents.Count;baseline_writes=[int]$session.baseline_writes}
    if($sessionStatus -ne 'healthy'){$findings+=@{kind='user_session_degraded';severity='high';path=(Protect-SentinelPath $sessionPath);message='用户会话桥未能更新全部受管基线；系统扫描器将独立复核'}}
  }catch{$inventory+=@{type='user_session';status='invalid'};$findings+=@{kind='user_session_invalid';severity='high';path=(Protect-SentinelPath $sessionPath);message='用户会话桥证明无效或已过期；不得据此放行基线'}}
}
$agentMarkers = @{
  cursor=@('.cursor\mcp.json','AppData\Roaming\Cursor\User\settings.json','AppData\Local\Programs\cursor\Cursor.exe')
  codex=@('.codex\config.toml','AppData\Roaming\npm\codex.cmd')
  claude_code=@('.claude.json','.claude\settings.json','AppData\Roaming\npm\claude.cmd')
  windsurf=@('.codeium\windsurf\mcp_config.json','AppData\Roaming\Windsurf\User\settings.json','AppData\Local\Programs\Windsurf\Windsurf.exe')
  gemini_cli=@('.gemini\settings.json','.gemini\GEMINI.md','AppData\Roaming\npm\gemini.cmd')
  github_copilot_cli=@('.copilot\config.json','.copilot\settings.json','.copilot\mcp-config.json','AppData\Roaming\npm\copilot.cmd')
  workbuddy=@('.workbuddy\mcp.json','workbuddy','AppData\Local\Programs\WorkBuddy\WorkBuddy.exe','AppData\Roaming\CodeBuddyExtension')
  qwen_enterprise=@('.qwenworkcn','AppData\Roaming\QwenWork','AppData\Local\Programs\Qwen\Qwen.exe')
  tongyi_lingma=@('.lingma','.aliyun\lingma','AppData\Roaming\Lingma')
  codebuddy=@('.codebuddy','AppData\Roaming\CodeBuddyExtension','AppData\Local\Programs\CodeBuddy\CodeBuddy.exe')
}
foreach ($userHome in $userHomes) {
  foreach ($relative in @('.cursor','.codex','.claude','.codeium\windsurf','.gemini','.copilot','.workbuddy','.qwenworkcn','.lingma','.codebuddy','workbuddy','AppData\Roaming\CodeBuddyExtension')) { $candidate=Join-Path $userHome.FullName $relative; if(Test-Path $candidate){$roots += $candidate} }
  foreach ($agent in $agentMarkers.Keys) {
    foreach ($relative in $agentMarkers[$agent]) { $marker=Join-Path $userHome.FullName $relative; if(Test-Path $marker){$inventory += @{type='ai_agent';name=$agent;path=(Protect-SentinelPath $marker);scope='user';detected_by='filesystem_marker'};$baseline=Get-SentinelUserBaselineStatus $userHome.FullName $agent;if($baseline){$inventory += @{type='agent_baseline';name=$agent;status=$baseline.status;scope='user'};if($baseline.status -ne 'managed'){$findings += @{kind='agent_baseline_not_loaded';severity='high';path=(Protect-SentinelPath $baseline.path);message="$agent 已发现但企业安全基线未处于受管状态";evidence=$baseline.status}}};break} }
  }
}
$systemMarkers = @{
  cursor=@("$env:LOCALAPPDATA\Programs\cursor\Cursor.exe","$env:ProgramFiles\Cursor\Cursor.exe")
  codex=@("$env:ProgramFiles\nodejs\codex.cmd")
  claude_code=@("$env:ProgramFiles\nodejs\claude.cmd")
  windsurf=@("$env:LOCALAPPDATA\Programs\Windsurf\Windsurf.exe","$env:ProgramFiles\Windsurf\Windsurf.exe")
  gemini_cli=@("$env:APPDATA\npm\gemini.cmd","$env:ProgramFiles\nodejs\gemini.cmd")
  github_copilot_cli=@("$env:APPDATA\npm\copilot.cmd","$env:ProgramFiles\nodejs\copilot.cmd")
  workbuddy=@("$env:LOCALAPPDATA\Programs\WorkBuddy\WorkBuddy.exe","$env:APPDATA\CodeBuddyExtension")
  qwen_enterprise=@("$env:LOCALAPPDATA\Programs\Qwen\Qwen.exe","$env:APPDATA\QwenWork")
  tongyi_lingma=@("$env:APPDATA\Lingma")
  codebuddy=@("$env:LOCALAPPDATA\Programs\CodeBuddy\CodeBuddy.exe","$env:APPDATA\CodeBuddyExtension")
}
foreach($agent in $systemMarkers.Keys){foreach($marker in $systemMarkers[$agent]){if(Test-Path $marker){$inventory += @{type='ai_agent';name=$agent;path=$marker;scope='system';detected_by='filesystem_marker'};break}}}
foreach($repo in Get-ManagedRepos) { Install-SentinelBaseline $repo; $roots += $repo; $inventory += @{type='managed_repository';path=(Protect-SentinelPath $repo)} }
foreach ($root in $roots) {
  if (Test-Path $root) {
    $inventory += @{ type='agent_root'; path=(Protect-SentinelPath $root) }
    $skillManifests=@(Get-ChildItem $root -Filter 'SKILL.md' -File -Recurse -Force|Select-Object -First 501)
    foreach($manifest in @($skillManifests|Select-Object -First 500)){
      $skillName=$manifest.Directory.Name;$approved=$policy -and $skillName -in @($policy.allowed_skills);$monitored=$policy -and $skillName -in @($policy.monitored_skills);$blocked=$policy -and $skillName -in @($policy.blocked_skills);$inventory+=@{type='skill';name=$skillName;path=(Protect-SentinelPath $manifest.FullName);approved=[bool]$approved;disposition=$(if($blocked){'deny'}elseif($approved){'allow'}elseif($monitored){'monitor'}else{'unknown'})}
      if($blocked){$findings+=@{kind='blocked_skill';severity='critical';path=(Protect-SentinelPath $manifest.FullName);message="已拉黑的 Skill: $skillName";evidence='[REDACTED]'};if(Disable-SentinelTarget $manifest 'skill' $skillName){$findings+=@{kind='skill_quarantined';severity='critical';path=(Protect-SentinelPath $manifest.FullName);message='已禁用拒绝 Skill；恢复需要外部审批';evidence='[REDACTED]'}}else{$findings+=@{kind='skill_quarantine_failed';severity='critical';path=(Protect-SentinelPath $manifest.FullName);message='Skill 禁用失败；要求终端平台介入'}}}elseif(-not $approved -and -not $monitored){$findings+=@{kind='unknown_skill';severity='high';path=(Protect-SentinelPath $manifest.FullName);message="未批准的 Skill: $skillName"};if($policy.enforcement.unknown_skill -eq 'block'){if(Disable-SentinelTarget $manifest 'skill' $skillName){$findings+=@{kind='skill_quarantined';severity='critical';path=(Protect-SentinelPath $manifest.FullName);message='已禁用未批准 Skill；恢复需要外部审批'}}else{$findings+=@{kind='skill_quarantine_failed';severity='critical';path=(Protect-SentinelPath $manifest.FullName);message='Skill 禁用失败；要求终端平台介入'}}}}
      $links=@(Get-ChildItem $manifest.Directory.FullName -Recurse -Force -Attributes ReparsePoint|Select-Object -First 101)
      foreach($link in @($links|Select-Object -First 100)){$findings+=@{kind='skill_symlink_escape';severity='high';path=(Protect-SentinelPath $link.FullName);message='Skill 包含重解析点，需人工确认目标边界'}}
      if($links.Count -gt 100){$findings+=@{kind='skill_link_findings_truncated';severity='medium';path=(Protect-SentinelPath $manifest.FullName);message='Skill 重解析点超过 100，仅保留前 100 项'}}
    }
    if($skillManifests.Count -gt 500){$findings+=@{kind='skill_scan_truncated';severity='medium';path=(Protect-SentinelPath $root);message='Skill 数量超过扫描上限 500'}}
    $oversized=@(Get-ChildItem $root -File -Recurse -Force | Where-Object { $_.Length -gt $maxFileBytes -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First 101)
    foreach($file in @($oversized|Select-Object -First 100)){$findings += @{kind='oversized_file_skipped';severity='medium';path=(Protect-SentinelPath $file.FullName);message="文件超过扫描字节上限 $maxFileBytes"}}
    if($oversized.Count -gt 100){$findings += @{kind='oversized_file_findings_truncated';severity='medium';path=(Protect-SentinelPath $root);message='超大文件发现项超过 100，仅保留前 100 项'}}
    $candidates=@(Get-ChildItem $root -File -Recurse -Force | Where-Object { $_.Length -le $maxFileBytes -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First ($projectFileLimit+1))
    if($candidates.Count -gt $projectFileLimit){$findings+=@{kind='project_scan_truncated';severity='medium';path=(Protect-SentinelPath $root);message="项目候选文件超过扫描上限 $projectFileLimit"}}
    $candidates|Select-Object -First $projectFileLimit | ForEach-Object {
      $text = Get-Content $_.FullName -Raw
      foreach ($rule in $compiledPatterns) {
        try{$matched=$rule.Compiled.IsMatch($text)}catch [Text.RegularExpressions.RegexMatchTimeoutException]{$findings += @{kind='scan_rule_timeout';severity='high';path=(Protect-SentinelPath $_.FullName);message='安全扫描规则超过执行时限'};continue}
        if ($matched) { $findings += @{ kind=$rule.Kind; severity=$rule.Severity; path=(Protect-SentinelPath $_.FullName); message='Policy match' } }
      }
      $normalized=$_.FullName.Replace('\','/').ToLower();$scope=if($_.Name -eq 'SKILL.md' -or $normalized.Contains('/skills/')){'skill'}elseif($_.Name -in @('mcp.json','mcp_config.json','mcp-config.json','.mcp.json') -or $normalized.Contains('/mcp')){'mcp'}else{'code'}
      foreach($rule in @($policy.custom_rules)){
        if($rule.scope -notin @('all',$scope)){continue};if(@($rule.extensions).Count -and $_.Extension.ToLower() -notin @($rule.extensions)){continue}
        try{$match=[regex]::Match($text,[string]$rule.pattern,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(250))}catch [Text.RegularExpressions.RegexMatchTimeoutException]{$findings += @{kind='scan_rule_timeout';severity='high';path=(Protect-SentinelPath $_.FullName);message='动态安全扫描规则超过执行时限'};continue}
        if($match.Success){$evidence=if($rule.redact){'[REDACTED]'}else{$match.Value.Substring(0,[Math]::Min(80,$match.Value.Length))};$findings += @{kind=[string]$rule.id;severity=[string]$rule.severity;path=(Protect-SentinelPath $_.FullName);message=[string]$rule.message;evidence=$evidence}}
      }
      if ($_.Name -in @('mcp.json','mcp_config.json','mcp-config.json','.mcp.json') -or ($_.Name -eq 'settings.json' -and $_.Directory.Name -eq '.gemini')) { Inspect-SentinelMcpJson $_ $text }
      if ($_.Name -eq 'config.toml' -and $_.FullName -match '\\\.codex\\') { Inspect-SentinelMcpToml $_ $text }
      if ($_.Name -eq 'package.json' -or $_.Name -like 'requirements*.txt') { $inventory += @{type='dependency_manifest';path=(Protect-SentinelPath $_.FullName)}; Inspect-SentinelDependencies $_ $text }
    }
  }
}
$healthPath=Join-Path $installDir 'service-health.json'
if(Test-Path -LiteralPath $healthPath){
  try{
    $healthFile=Get-Item -LiteralPath $healthPath -Force;if($healthFile.Attributes -band [IO.FileAttributes]::ReparsePoint -or $healthFile.Length -gt 4096){throw 'unsafe health file'}
    $health=Get-Content -LiteralPath $healthPath -Raw|ConvertFrom-Json;$expected=@('schema','host_version','state','service_started_at','updated_at','last_scan_started_at','last_scan_exit_code','scanner','error','arbitrary_command_enabled')
    $names=@($health.PSObject.Properties.Name);if(@($names|Where-Object{$_ -notin $expected}).Count -or @($expected|Where-Object{$_ -notin $names}).Count -or $health.schema -cne 'sentinel.service-health/v1' -or [string]$health.host_version -notmatch '^\d+\.\d+\.\d+$' -or [string]$health.state -notin @('starting','healthy','degraded') -or [string]$health.scanner -cne 'windows-powershell' -or $health.arbitrary_command_enabled -ne $false){throw 'invalid health contract'}
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();if([long]$health.updated_at -gt $now+300 -or $now-[long]$health.updated_at -gt 7200 -or [long]$health.service_started_at -gt [long]$health.updated_at){throw 'stale health'}
    $inventory+=@{type='service_health';host_version=[string]$health.host_version;status=[string]$health.state;updated_at=[long]$health.updated_at;last_scan_exit_code=[int]$health.last_scan_exit_code}
    if($health.state -cne 'healthy'){$findings+=@{kind='service_host_degraded';severity='high';path='managed-service-health';message='Sentinel 服务宿主未处于健康状态'}}
  }catch{$inventory+=@{type='service_health';status='invalid'};$findings+=@{kind='service_health_invalid';severity='high';path='managed-service-health';message='Sentinel 服务宿主健康状态无效或已过期'}}
}
$policyVersion = if ($policy) { [string]$policy.version } else { 'invalid' }
$policyKeyIds=@();foreach($key in @($policyVerificationKeys)){$sha=[Security.Cryptography.SHA256]::Create();try{$policyKeyIds+=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)))).Replace('-','').ToLower().Substring(0,16)}finally{$sha.Dispose()}}
$inventory+=@{type='policy_trust';key_ids=@($policyKeyIds)}
$deviceId=if($bound){[string]$reportConfig.device_id}else{$deviceMaterial="$env:COMPUTERNAME|$env:USERDOMAIN";$sha=[System.Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-','').Substring(0,12).ToLower()}finally{$sha.Dispose()}}
if($bound){$inventory+=@{type='device_identity';source='enrollment';status='bound'}}else{$inventory+=@{type='device_identity';source='legacy_derived';status='migration_required'};$findings+=@{kind='legacy_device_identity';severity='high';path='managed-device-identity';message='设备仍使用主机名派生身份，需重新注册以绑定稳定企业设备身份'}}
$inventoryLimit=5000;$findingLimit=10000
if(@($inventory).Count -gt $inventoryLimit){$omitted=@($inventory).Count-$inventoryLimit+1;$inventory=@($inventory|Select-Object -First ($inventoryLimit-1));$inventory += @{type='inventory_truncated';omitted=$omitted}}
if(@($findings).Count -gt $findingLimit){$omitted=@($findings).Count-$findingLimit+1;$findings=@($findings|Select-Object -First ($findingLimit-1));$findings += @{kind='findings_truncated';severity='medium';path='managed-windows-roots';message="报告发现项超限，省略 $omitted 项"}}
$report = @{ schema='sentinel.report/v1'; agent_version='0.53.0'; policy_version=$policyVersion; device_id=$deviceId; scanned_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); scan_root='managed-windows-roots'; inventory=$inventory; findings=$findings; summary=@{ critical=@($findings|Where-Object severity -eq critical).Count; high=@($findings|Where-Object severity -eq high).Count; medium=@($findings|Where-Object severity -eq medium).Count; low=@($findings|Where-Object severity -eq low).Count } }
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$reportJson=$report|ConvertTo-Json -Depth 8 -Compress
$outputTemp=$Output+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
try{$reportJson|Set-Content -Encoding UTF8 $outputTemp;Move-Item $outputTemp $Output -Force}finally{Remove-Item $outputTemp -Force -ErrorAction SilentlyContinue}
if($ReportUrl){
  $spool=Join-Path $installDir 'spool';New-Item -ItemType Directory -Force -Path $spool|Out-Null
  try{
    foreach($queued in @(Get-ChildItem $spool -Filter '*.json' -File|Sort-Object Name|Select-Object -First 50)){
      try{$queuedJson=Get-Content $queued.FullName -Raw;$null=$queuedJson|ConvertFrom-Json}catch{Move-Item $queued.FullName ($queued.FullName+'.'+[Guid]::NewGuid().ToString('N')+'.invalid') -Force;continue}
      try{$null=Send-SentinelReport $queuedJson $ReportUrl;Remove-Item $queued.FullName -Force}catch{break}
    }
    $null=Send-SentinelReport $reportJson $ReportUrl;Write-SentinelUploadStatus $ReportUrl
  }catch{
    $queue=Join-Path $spool ($report.scanned_at.ToString()+'-'+$report.device_id+'-'+[Guid]::NewGuid().ToString('N')+'.json');$reportJson|Set-Content -Encoding UTF8 $queue
    Get-ChildItem $spool -Filter '*.json' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 500|Remove-Item -Force
    Get-ChildItem $spool -Filter '*.invalid' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 20|Remove-Item -Force
    Write-Warning 'Report upload failed and was queued locally.'
  }
}
if ($report.summary.critical -gt 0 -or $report.summary.high -gt 0) { exit 2 }
exit 0
