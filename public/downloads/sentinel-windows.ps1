param([string]$Output = "$env:ProgramData\SentinelAgent\reports\latest.json",[string]$ReportUrl = $env:SENTINEL_REPORT_URL,[string]$ProtectedConfig = "$env:ProgramData\SentinelAgent\reporting.dpapi")
$ErrorActionPreference = 'SilentlyContinue'
$reportConfigInvalid=$false
if(Test-Path $ProtectedConfig){
  try{
    $encrypted=[IO.File]::ReadAllBytes($ProtectedConfig);$entropy=[Text.Encoding]::UTF8.GetBytes('SentinelAgent.Reporting.v1');$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try{$reportConfig=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json}finally{[Array]::Clear($plain,0,$plain.Length);[Array]::Clear($encrypted,0,$encrypted.Length)}
    $names=@($reportConfig.PSObject.Properties.Name|Sort-Object);if(($names -join ',') -cne 'report_token,report_url,schema,signing_secret' -or $reportConfig.schema -cne 'sentinel.reporting/v1'){throw 'invalid reporting config contract'}
    $uri=$null;if(-not [Uri]::TryCreate([string]$reportConfig.report_url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'invalid reporting URL'}
    if(([string]$reportConfig.report_token).Length -lt 32 -or ([string]$reportConfig.report_token).Length -gt 4096 -or ([string]$reportConfig.signing_secret).Length -lt 32 -or ([string]$reportConfig.signing_secret).Length -gt 4096 -or $reportConfig.report_token -ceq $reportConfig.signing_secret){throw 'invalid reporting secrets'}
    $ReportUrl=[string]$reportConfig.report_url;$env:SENTINEL_REPORT_TOKEN=[string]$reportConfig.report_token;$env:SENTINEL_REPORT_SIGNING_SECRET=[string]$reportConfig.signing_secret
  }catch{$reportConfigInvalid=$true;$ReportUrl='';Remove-Item Env:SENTINEL_REPORT_TOKEN -ErrorAction SilentlyContinue;Remove-Item Env:SENTINEL_REPORT_SIGNING_SECRET -ErrorAction SilentlyContinue}
}
$roots = @()
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$baselinePath = Join-Path $installDir 'sentinel-security-baseline.md'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$policy=$null;$policyInvalid=$false
try {
  if(-not (Test-Path $policyPath)){throw 'missing policy'}
  $candidate=Get-Content $policyPath -Raw | ConvertFrom-Json
  if($candidate.schema -ne 'sentinel.policy/v1' -or -not ([string]$candidate.version)){throw 'invalid policy contract'}
  if($candidate.limits -isnot [PSCustomObject] -and $candidate.limits -isnot [hashtable]){throw 'invalid policy limits'}
  foreach($key in @('allowed_skills','allowed_mcp_transports','allowed_mcp_servers','allowed_mcp_commands','allowed_mcp_command_paths','allowed_mcp_invocations','allowed_mcp_domains','blocked_commands','secret_patterns','skill_rules','mcp_rules','code_rules')){
    if($null -ne $candidate.$key -and $candidate.$key -isnot [System.Array]){throw "invalid policy list: $key"}
  }
  foreach($invocation in @($candidate.allowed_mcp_invocations)){if($invocation -isnot [System.Array] -or @($invocation).Count -lt 2 -or @($invocation|Where-Object{-not ($_ -is [string]) -or -not $_}).Count){throw 'invalid MCP invocation policy'}}
  $policy=$candidate
} catch {$policyInvalid=$true}
$maxFileBytes=1000000
if($policy -and $policy.limits -and $policy.limits.max_file_bytes){$maxFileBytes=[Math]::Min([Math]::Max([int64]$policy.limits.max_file_bytes,65536),10000000)}
$projectFileLimit=10000
if($policy -and $policy.limits -and $policy.limits.project_files){$projectFileLimit=[Math]::Min([Math]::Max([int64]$policy.limits.project_files,100),100000)}
$managedMarker = '<!-- sentinel-managed-baseline -->'
$patterns = @(
  @{ Kind='hardcoded_secret'; Severity='critical'; Regex='AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}' },
  @{ Kind='prompt_override'; Severity='high'; Regex='(?i)ignore (all |any )?(previous|prior) instructions' },
  @{ Kind='unbounded_shell'; Severity='high'; Regex='(?i)shell\s*=\s*true|Invoke-Expression|\biex\s' },
  @{ Kind='hidden_instruction'; Severity='high'; Regex='[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]' },
  @{ Kind='weak_random_token'; Severity='high'; Regex='(?is)(token|secret|session|nonce).{0,120}(Math\.random|random\.random)\s*\(' },
  @{ Kind='blocked_command'; Severity='high'; Regex='(?im)^\s*(curl\s+[^\r\n]*\|\s*(sh|bash)|wget\s+[^\r\n]*\|\s*(sh|bash)|chmod\s+777|rm\s+-rf)(\s|$)' },
  @{ Kind='insecure_tls_verification'; Severity='critical'; Regex='(?is)\brequests\.(get|post|put|patch|delete|request)\s*\([^)]{0,500}\bverify\s*=\s*false|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'']?0' },
  @{ Kind='unsafe_deserialization'; Severity='high'; Regex='(?i)\bpickle\.loads?\s*\(|\bBinaryFormatter\s*\(|\bObjectInputStream\s*\(' },
  @{ Kind='debug_mode_enabled'; Severity='medium'; Regex='(?is)\b(app|application)\.run\s*\([^)]{0,300}\bdebug\s*=\s*true' },
  @{ Kind='empty_exception_handler'; Severity='medium'; Regex='(?m)^\s*except(\s+[^:]+)?:\s*(#.*\r?\n\s*)?pass\s*$|\bcatch\s*\{\s*\}' }
)
$findings = @(); $inventory = @()
if($policyInvalid){$findings += @{kind='policy_load_failed';severity='high';path=$policyPath;message='安全策略缺失或契约无效；MCP 策略检查采用失败关闭状态'}}
if($reportConfigInvalid){$findings += @{kind='reporting_config_invalid';severity='high';path='reporting.dpapi';message='受保护上报配置无法解密或契约无效；本轮拒绝上报'}}
function Send-SentinelReport([string]$json,[string]$url) {
  $bytes=[Text.Encoding]::UTF8.GetBytes($json);$headers=@{}
  if($env:SENTINEL_REPORT_TOKEN){$headers.Authorization='Bearer '+$env:SENTINEL_REPORT_TOKEN}
  if($env:SENTINEL_REPORT_SIGNING_SECRET){
    $timestamp=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString();$prefix=[Text.Encoding]::UTF8.GetBytes($timestamp+'.');$signed=New-Object byte[] ($prefix.Length+$bytes.Length);[Array]::Copy($prefix,0,$signed,0,$prefix.Length);[Array]::Copy($bytes,0,$signed,$prefix.Length,$bytes.Length)
    $hmac=[System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($env:SENTINEL_REPORT_SIGNING_SECRET));$signature=([BitConverter]::ToString($hmac.ComputeHash($signed))).Replace('-','').ToLower();$hmac.Dispose()
    $headers['X-Sentinel-Timestamp']=$timestamp;$headers['X-Sentinel-Signature']='sha256='+$signature
  }
  Invoke-RestMethod -Uri $url -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 15|Out-Null
}
function Write-SentinelUploadStatus([string]$url){
  $uri=[Uri]$url;$status=@{schema='sentinel.upload-status/v1';status='accepted';last_success=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();collector_host=$uri.DnsSafeHost.ToLower()}|ConvertTo-Json -Compress
  $path=Join-Path (Split-Path $Output) 'upload-status.json';$temp=$path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
  try{$status|Set-Content -Encoding UTF8 $temp;Move-Item $temp $path -Force}finally{Remove-Item $temp -Force -ErrorAction SilentlyContinue}
}
function Protect-SentinelPath([string]$path) {
  foreach ($home in $userHomes) { if ($path.StartsWith($home.FullName,[StringComparison]::OrdinalIgnoreCase)) { return '~' + $path.Substring($home.FullName.Length) } }
  return $path
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
function Install-SentinelBaseline([string]$repo) {
  if (-not (Test-Path $baselinePath)) { return }
  $baseline = Get-Content $baselinePath -Raw
  $managed = "$managedMarker`n$baseline"
  $ruleTargets = @((Join-Path $repo '.cursor\rules\sentinel-security.mdc'),(Join-Path $repo '.windsurf\rules\sentinel-security.md'))
  foreach ($target in $ruleTargets) { if(-not (Test-SentinelSafeTarget $repo $target)){continue};New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null;Set-Content -Encoding UTF8 $target $managed }
  foreach ($name in @('AGENTS.md','CLAUDE.md')) {
    $target=Join-Path $repo $name;if(-not (Test-SentinelSafeTarget $repo $target)){continue};$existing=if(Test-Path $target){Get-Content $target -Raw}else{''}
    if ($existing -notlike "*$managedMarker*") { Add-Content -Encoding UTF8 $target "`n$managedMarker`n## 企业安全基线`n执行任何代码变更前必须遵循 .sentinel/SECURITY_BASELINE.md。" }
  }
  $shared=Join-Path $repo '.sentinel\SECURITY_BASELINE.md';if(Test-SentinelSafeTarget $repo $shared){New-Item -ItemType Directory -Force -Path (Split-Path $shared) | Out-Null;Set-Content -Encoding UTF8 $shared $managed}
}
function Sync-SentinelUserBaselines([object[]]$homes) {
  if(-not (Test-Path $baselinePath)){return}
  $content=(Get-Content $baselinePath -Raw).TrimEnd();$start='<!-- sentinel-managed-user-baseline:start -->';$end='<!-- sentinel-managed-user-baseline:end -->';$block=$start+"`n"+$content+"`n"+$end
  foreach($home in $homes){
    $targets=@();$codex=Join-Path $home.FullName '.codex';$claude=Join-Path $home.FullName '.claude'
    if((Test-Path $codex) -and -not ((Get-Item $codex -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets+=Join-Path $codex 'AGENTS.md'}
    if(((Test-Path $claude) -and -not ((Get-Item $claude -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) -or (Test-Path (Join-Path $home.FullName '.claude.json'))){$targets+=Join-Path $claude 'CLAUDE.md'}
    foreach($target in $targets){
      if(-not (Test-SentinelSafeTarget $home.FullName $target)){continue};New-Item -ItemType Directory -Force -Path (Split-Path $target)|Out-Null;if(-not (Test-SentinelSafeTarget $home.FullName $target)){continue}
      $existing=if(Test-Path $target){Get-Content $target -Raw}else{''};$pattern=[regex]::Escape($start)+'.*?'+[regex]::Escape($end)
      if($existing.Contains($start) -xor $existing.Contains($end)){$script:findings+=@{kind='malformed_user_baseline_block';severity='high';path=(Protect-SentinelPath $target);message='用户级安全基线托管标记不完整，已停止自动修改'};continue}
      if($existing.Contains($start)){$updated=[regex]::Replace($existing,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{param($match)$block},[System.Text.RegularExpressions.RegexOptions]::Singleline)}else{$updated=$existing.TrimEnd()+$(if($existing.Trim()){"`n`n"}else{''})+$block+"`n"}
      if($updated -ne $existing){Set-Content -Encoding UTF8 $target $updated}
    }
  }
}
function Inspect-SentinelMcpJson([System.IO.FileInfo]$file,[string]$text) {
  if (-not $policy) { return }
  try { $config=$text | ConvertFrom-Json } catch { $script:findings += @{kind='invalid_mcp_config';severity='medium';path=(Protect-SentinelPath $file.FullName);message='MCP JSON 配置无法解析'}; return }
  $servers=if($config.mcpServers){$config.mcpServers}else{$config.servers}
  if (-not $servers) { return }
  foreach($entry in $servers.PSObject.Properties) {
    $name=$entry.Name; $cfg=$entry.Value; $safePath=Protect-SentinelPath $file.FullName
    if($cfg -isnot [PSCustomObject] -and $cfg -isnot [hashtable]){$script:findings += @{kind='invalid_mcp_server';severity='high';path=$safePath;message="MCP Server $name 配置必须是对象"};continue}
    if($policy.allowed_mcp_servers -and $name -notin $policy.allowed_mcp_servers){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"}}
    $rawCommand=[string]$cfg.command;$command=[IO.Path]::GetFileName($rawCommand)
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
    if($rawCommand -match '[\\/]' -and $rawCommand -notin @($policy.allowed_mcp_command_paths)){$script:findings += @{kind='unapproved_mcp_command_path';severity='high';path=$safePath;message="MCP $name 使用未批准的可执行路径"}}
    $invocationArgs=@($cfg.args)
    if($command -and -not (Test-SentinelMcpInvocation $command $invocationArgs)){$script:findings += @{kind='unapproved_mcp_invocation';severity='high';path=$safePath;message="MCP $name 的命令参数组合未获批准"}}
    foreach($arg in @($cfg.args)){if(([string]$arg) -in @('/','C:\','$HOME','~') -or ([string]$arg) -match '^[A-Za-z]:\\Users\\'){$script:findings += @{kind='broad_filesystem_scope';severity='high';path=$safePath;message="MCP $name 请求宽泛文件范围"};break}}
    if($null -ne $cfg.env -and $cfg.env -isnot [PSCustomObject] -and $cfg.env -isnot [hashtable]){$script:findings += @{kind='invalid_mcp_environment';severity='high';path=$safePath;message="MCP $name 的 env 必须是对象"}}
    else{foreach($variable in @($cfg.env.PSObject.Properties)){if($variable.Name -match 'TOKEN|SECRET|PASSWORD|API_KEY' -and ([string]$variable.Value) -notmatch '^\$\{?[A-Z0-9_]+\}?$'){$script:findings += @{kind='literal_mcp_secret';severity='critical';path=$safePath;message="MCP $name 包含明文敏感环境变量: $($variable.Name)";evidence='[REDACTED]'}}}}
    $url=[string]$cfg.url; if(-not $url){$url=[string]$cfg.serverUrl}
    $transport=[string]$cfg.transport;if(-not $transport){if($url.StartsWith('https://')){$transport='https'}elseif($url.StartsWith('http://')){$transport='http'}elseif($command){$transport='stdio'}else{$transport='unknown'}}
    if($command -and $url){$script:findings += @{kind='ambiguous_mcp_transport';severity='high';path=$safePath;message="MCP $name 同时配置本地命令和远程 URL"}}
    if(($policy.PSObject.Properties.Name -contains 'allowed_mcp_transports') -and $transport -notin @($policy.allowed_mcp_transports)){$script:findings += @{kind='unapproved_mcp_transport';severity='high';path=$safePath;message="MCP $name 使用未批准传输: $transport"}}
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
    if($policy.allowed_mcp_servers -and $name -notin $policy.allowed_mcp_servers){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"}}
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
    if($rawCommand -match '[\\/]' -and $rawCommand -notin @($policy.allowed_mcp_command_paths)){$script:findings += @{kind='unapproved_mcp_command_path';severity='high';path=$safePath;message="MCP $name 使用未批准的可执行路径"}}
    if($command -and -not (Test-SentinelMcpInvocation $command $args)){$script:findings += @{kind='unapproved_mcp_invocation';severity='high';path=$safePath;message="MCP $name 的命令参数组合未获批准"}}
    foreach($arg in $args){if($arg -in @('/','C:\','$HOME','~') -or $arg -match '^[A-Za-z]:\\Users\\'){$script:findings += @{kind='broad_filesystem_scope';severity='high';path=$safePath;message="MCP $name 请求宽泛文件范围"};break}}
    if(-not $transport){if($url.StartsWith('https://')){$transport='https'}elseif($url.StartsWith('http://')){$transport='http'}elseif($command){$transport='stdio'}else{$transport='unknown'}}
    if($command -and $url){$script:findings += @{kind='ambiguous_mcp_transport';severity='high';path=$safePath;message="MCP $name 同时配置本地命令和远程 URL"}}
    if(($policy.PSObject.Properties.Name -contains 'allowed_mcp_transports') -and $transport -notin @($policy.allowed_mcp_transports)){$script:findings += @{kind='unapproved_mcp_transport';severity='high';path=$safePath;message="MCP $name 使用未批准传输: $transport"}}
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
  Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } | ForEach-Object {
    foreach($relative in @('source\repos','Documents\GitHub','Projects','Code')) {
      $base=Join-Path $_.FullName $relative
      if(Test-Path $base) { Get-ChildItem $base -Directory -Recurse -Depth 4 | Where-Object { Test-Path (Join-Path $_.FullName '.git') } | ForEach-Object { $repos += $_.FullName } }
    }
  }
  return $repos | Select-Object -Unique
}
$userHomes = @(Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') })
Sync-SentinelUserBaselines $userHomes
$agentMarkers = @{
  cursor=@('.cursor\mcp.json','AppData\Roaming\Cursor\User\settings.json','AppData\Local\Programs\cursor\Cursor.exe')
  codex=@('.codex\config.toml','AppData\Roaming\npm\codex.cmd')
  claude_code=@('.claude.json','.claude\settings.json','AppData\Roaming\npm\claude.cmd')
  windsurf=@('.codeium\windsurf\mcp_config.json','AppData\Roaming\Windsurf\User\settings.json','AppData\Local\Programs\Windsurf\Windsurf.exe')
}
foreach ($home in $userHomes) {
  foreach ($relative in @('.cursor','.codex','.claude','.codeium\windsurf')) { $candidate=Join-Path $home.FullName $relative; if(Test-Path $candidate){$roots += $candidate} }
  foreach ($agent in $agentMarkers.Keys) {
    foreach ($relative in $agentMarkers[$agent]) { $marker=Join-Path $home.FullName $relative; if(Test-Path $marker){$inventory += @{type='ai_agent';name=$agent;path=(Protect-SentinelPath $marker);scope='user';detected_by='filesystem_marker'};break} }
  }
}
$systemMarkers = @{
  cursor=@("$env:LOCALAPPDATA\Programs\cursor\Cursor.exe","$env:ProgramFiles\Cursor\Cursor.exe")
  codex=@("$env:ProgramFiles\nodejs\codex.cmd")
  claude_code=@("$env:ProgramFiles\nodejs\claude.cmd")
  windsurf=@("$env:LOCALAPPDATA\Programs\Windsurf\Windsurf.exe","$env:ProgramFiles\Windsurf\Windsurf.exe")
}
foreach($agent in $systemMarkers.Keys){foreach($marker in $systemMarkers[$agent]){if(Test-Path $marker){$inventory += @{type='ai_agent';name=$agent;path=$marker;scope='system';detected_by='filesystem_marker'};break}}}
foreach($repo in Get-ManagedRepos) { Install-SentinelBaseline $repo; $roots += $repo; $inventory += @{type='managed_repository';path=(Protect-SentinelPath $repo)} }
foreach ($root in $roots) {
  if (Test-Path $root) {
    $inventory += @{ type='agent_root'; path=(Protect-SentinelPath $root) }
    $skillManifests=@(Get-ChildItem $root -Filter 'SKILL.md' -File -Recurse -Force|Select-Object -First 501)
    foreach($manifest in @($skillManifests|Select-Object -First 500)){
      $skillName=$manifest.Directory.Name;$approved=$policy -and $skillName -in @($policy.allowed_skills);$inventory+=@{type='skill';name=$skillName;path=(Protect-SentinelPath $manifest.FullName);approved=[bool]$approved}
      if(-not $approved){$findings+=@{kind='unknown_skill';severity='high';path=(Protect-SentinelPath $manifest.FullName);message="未批准的 Skill: $skillName"}}
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
      foreach ($rule in $patterns) {
        if ($text -match $rule.Regex) { $findings += @{ kind=$rule.Kind; severity=$rule.Severity; path=(Protect-SentinelPath $_.FullName); message='Policy match' } }
      }
      if ($_.Name -in @('mcp.json','mcp_config.json')) { Inspect-SentinelMcpJson $_ $text }
      if ($_.Name -eq 'config.toml' -and $_.FullName -match '\\\.codex\\') { Inspect-SentinelMcpToml $_ $text }
      if ($_.Name -eq 'package.json' -or $_.Name -like 'requirements*.txt') { $inventory += @{type='dependency_manifest';path=(Protect-SentinelPath $_.FullName)}; Inspect-SentinelDependencies $_ $text }
    }
  }
}
$policyVersion = if ($policy) { [string]$policy.version } else { 'invalid' }
$inventoryLimit=5000;$findingLimit=10000
if(@($inventory).Count -gt $inventoryLimit){$omitted=@($inventory).Count-$inventoryLimit+1;$inventory=@($inventory|Select-Object -First ($inventoryLimit-1));$inventory += @{type='inventory_truncated';omitted=$omitted}}
if(@($findings).Count -gt $findingLimit){$omitted=@($findings).Count-$findingLimit+1;$findings=@($findings|Select-Object -First ($findingLimit-1));$findings += @{kind='findings_truncated';severity='medium';path='managed-windows-roots';message="报告发现项超限，省略 $omitted 项"}}
$deviceMaterial = "$env:COMPUTERNAME|$env:USERDOMAIN"
$sha = [System.Security.Cryptography.SHA256]::Create()
$deviceId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-','').Substring(0,12).ToLower()
$report = @{ schema='sentinel.report/v1'; agent_version='0.27.0'; policy_version=$policyVersion; device_id=$deviceId; scanned_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); scan_root='managed-windows-roots'; inventory=$inventory; findings=$findings; summary=@{ critical=@($findings|Where-Object severity -eq critical).Count; high=@($findings|Where-Object severity -eq high).Count; medium=@($findings|Where-Object severity -eq medium).Count; low=@($findings|Where-Object severity -eq low).Count } }
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$reportJson=$report|ConvertTo-Json -Depth 8 -Compress
$outputTemp=$Output+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
try{$reportJson|Set-Content -Encoding UTF8 $outputTemp;Move-Item $outputTemp $Output -Force}finally{Remove-Item $outputTemp -Force -ErrorAction SilentlyContinue}
if($ReportUrl){
  $spool=Join-Path $installDir 'spool';New-Item -ItemType Directory -Force -Path $spool|Out-Null
  try{
    foreach($queued in @(Get-ChildItem $spool -Filter '*.json' -File|Sort-Object Name|Select-Object -First 50)){
      try{$queuedJson=Get-Content $queued.FullName -Raw;$null=$queuedJson|ConvertFrom-Json}catch{Move-Item $queued.FullName ($queued.FullName+'.'+[Guid]::NewGuid().ToString('N')+'.invalid') -Force;continue}
      try{Send-SentinelReport $queuedJson $ReportUrl;Remove-Item $queued.FullName -Force}catch{break}
    }
    Send-SentinelReport $reportJson $ReportUrl;Write-SentinelUploadStatus $ReportUrl
  }catch{
    $queue=Join-Path $spool ($report.scanned_at.ToString()+'-'+$report.device_id+'-'+[Guid]::NewGuid().ToString('N')+'.json');$reportJson|Set-Content -Encoding UTF8 $queue
    Get-ChildItem $spool -Filter '*.json' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 500|Remove-Item -Force
    Get-ChildItem $spool -Filter '*.invalid' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 20|Remove-Item -Force
    Write-Warning 'Report upload failed and was queued locally.'
  }
}
if ($report.summary.critical -gt 0 -or $report.summary.high -gt 0) { exit 2 }
exit 0
