param([string]$Output = "$env:ProgramData\SentinelAgent\reports\latest.json",[string]$ReportUrl = $env:SENTINEL_REPORT_URL)
$ErrorActionPreference = 'SilentlyContinue'
$roots = @()
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$baselinePath = Join-Path $installDir 'sentinel-security-baseline.md'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$policy = if (Test-Path $policyPath) { Get-Content $policyPath -Raw | ConvertFrom-Json } else { $null }
$maxFileBytes=1000000
if($policy -and $policy.limits -and $policy.limits.max_file_bytes){$maxFileBytes=[Math]::Min([Math]::Max([int64]$policy.limits.max_file_bytes,65536),10000000)}
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
function Protect-SentinelPath([string]$path) {
  foreach ($home in $userHomes) { if ($path.StartsWith($home.FullName,[StringComparison]::OrdinalIgnoreCase)) { return '~' + $path.Substring($home.FullName.Length) } }
  return $path
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
function Inspect-SentinelMcpJson([System.IO.FileInfo]$file,[string]$text) {
  if (-not $policy) { return }
  try { $config=$text | ConvertFrom-Json } catch { $script:findings += @{kind='invalid_mcp_config';severity='medium';path=(Protect-SentinelPath $file.FullName);message='MCP JSON 配置无法解析'}; return }
  $servers=if($config.mcpServers){$config.mcpServers}else{$config.servers}
  if (-not $servers) { return }
  foreach($entry in $servers.PSObject.Properties) {
    $name=$entry.Name; $cfg=$entry.Value; $safePath=Protect-SentinelPath $file.FullName
    if($policy.allowed_mcp_servers -and $name -notin $policy.allowed_mcp_servers){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"}}
    $command=[IO.Path]::GetFileName([string]$cfg.command)
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
    foreach($arg in @($cfg.args)){if(([string]$arg) -in @('/','C:\','$HOME','~') -or ([string]$arg) -match '^[A-Za-z]:\\Users\\'){$script:findings += @{kind='broad_filesystem_scope';severity='high';path=$safePath;message="MCP $name 请求宽泛文件范围"};break}}
    foreach($variable in @($cfg.env.PSObject.Properties)){if($variable.Name -match 'TOKEN|SECRET|PASSWORD|API_KEY' -and ([string]$variable.Value) -notmatch '^\$\{?[A-Z0-9_]+\}?$'){$script:findings += @{kind='literal_mcp_secret';severity='critical';path=$safePath;message="MCP $name 包含明文敏感环境变量: $($variable.Name)";evidence='[REDACTED]'}}}
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
    $match=[regex]::Match($body,'(?m)^\s*command\s*=\s*"([^"]+)"');$command=if($match.Success){[IO.Path]::GetFileName($match.Groups[1].Value)}else{''}
    $match=[regex]::Match($body,'(?m)^\s*url\s*=\s*"([^"]+)"');$url=if($match.Success){$match.Groups[1].Value}else{''}
    $match=[regex]::Match($body,'(?m)^\s*transport\s*=\s*"([^"]+)"');$transport=if($match.Success){$match.Groups[1].Value.ToLower()}else{''}
    $args=@();$match=[regex]::Match($body,'(?ms)^\s*args\s*=\s*\[(.*?)\]');if($match.Success){foreach($arg in [regex]::Matches($match.Groups[1].Value,'"([^"]+)"')){$args += $arg.Groups[1].Value}}
    if($policy.allowed_mcp_servers -and $name -notin $policy.allowed_mcp_servers){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"}}
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
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
    $oversized=@(Get-ChildItem $root -File -Recurse | Where-Object { $_.Length -gt $maxFileBytes -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First 101)
    foreach($file in @($oversized|Select-Object -First 100)){$findings += @{kind='oversized_file_skipped';severity='medium';path=(Protect-SentinelPath $file.FullName);message="文件超过扫描字节上限 $maxFileBytes"}}
    if($oversized.Count -gt 100){$findings += @{kind='oversized_file_findings_truncated';severity='medium';path=(Protect-SentinelPath $root);message='超大文件发现项超过 100，仅保留前 100 项'}}
    Get-ChildItem $root -File -Recurse | Where-Object { $_.Length -le $maxFileBytes -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First 5000 | ForEach-Object {
      $text = Get-Content $_.FullName -Raw
      foreach ($rule in $patterns) {
        if ($text -match $rule.Regex) { $findings += @{ kind=$rule.Kind; severity=$rule.Severity; path=(Protect-SentinelPath $_.FullName); message='Policy match' } }
      }
      if ($_.Name -eq 'SKILL.md') {
        $skillName=$_.Directory.Name
        if($policy -and ($policy.PSObject.Properties.Name -contains 'allowed_skills') -and $skillName -notin @($policy.allowed_skills)){$findings += @{kind='unknown_skill';severity='high';path=(Protect-SentinelPath $_.FullName);message="未批准的 Skill: $skillName"}}
        Get-ChildItem $_.Directory.FullName -Recurse -Attributes ReparsePoint | ForEach-Object {$findings += @{kind='skill_symlink_escape';severity='high';path=(Protect-SentinelPath $_.FullName);message='Skill 包含重解析点，需人工确认目标边界'}}
      }
      if ($_.Name -in @('mcp.json','mcp_config.json')) { Inspect-SentinelMcpJson $_ $text }
      if ($_.Name -eq 'config.toml' -and $_.FullName -match '\\\.codex\\') { Inspect-SentinelMcpToml $_ $text }
      if ($_.Name -eq 'package.json' -or $_.Name -like 'requirements*.txt') { $inventory += @{type='dependency_manifest';path=(Protect-SentinelPath $_.FullName)}; Inspect-SentinelDependencies $_ $text }
    }
  }
}
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$inventoryLimit=5000;$findingLimit=10000
if(@($inventory).Count -gt $inventoryLimit){$omitted=@($inventory).Count-$inventoryLimit+1;$inventory=@($inventory|Select-Object -First ($inventoryLimit-1));$inventory += @{type='inventory_truncated';omitted=$omitted}}
if(@($findings).Count -gt $findingLimit){$omitted=@($findings).Count-$findingLimit+1;$findings=@($findings|Select-Object -First ($findingLimit-1));$findings += @{kind='findings_truncated';severity='medium';path='managed-windows-roots';message="报告发现项超限，省略 $omitted 项"}}
$deviceMaterial = "$env:COMPUTERNAME|$env:USERDOMAIN"
$sha = [System.Security.Cryptography.SHA256]::Create()
$deviceId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-','').Substring(0,12).ToLower()
$report = @{ schema='sentinel.report/v1'; agent_version='0.18.0'; policy_version=$policyVersion; device_id=$deviceId; scanned_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); scan_root='managed-windows-roots'; inventory=$inventory; findings=$findings; summary=@{ critical=@($findings|Where-Object severity -eq critical).Count; high=@($findings|Where-Object severity -eq high).Count; medium=@($findings|Where-Object severity -eq medium).Count; low=@($findings|Where-Object severity -eq low).Count } }
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$reportJson=$report|ConvertTo-Json -Depth 8 -Compress
$reportJson|Set-Content -Encoding UTF8 $Output
if($ReportUrl){
  $spool=Join-Path $installDir 'spool';New-Item -ItemType Directory -Force -Path $spool|Out-Null
  try{
    foreach($queued in @(Get-ChildItem $spool -Filter '*.json' -File|Sort-Object Name|Select-Object -First 50)){
      try{$queuedJson=Get-Content $queued.FullName -Raw;$null=$queuedJson|ConvertFrom-Json}catch{Move-Item $queued.FullName ($queued.FullName+'.'+[Guid]::NewGuid().ToString('N')+'.invalid') -Force;continue}
      try{Send-SentinelReport $queuedJson $ReportUrl;Remove-Item $queued.FullName -Force}catch{break}
    }
    Send-SentinelReport $reportJson $ReportUrl
  }catch{
    $queue=Join-Path $spool ($report.scanned_at.ToString()+'-'+$report.device_id+'-'+[Guid]::NewGuid().ToString('N')+'.json');$reportJson|Set-Content -Encoding UTF8 $queue
    Get-ChildItem $spool -Filter '*.json' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 500|Remove-Item -Force
    Get-ChildItem $spool -Filter '*.invalid' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 20|Remove-Item -Force
    Write-Warning 'Report upload failed and was queued locally.'
  }
}
if ($report.summary.critical -gt 0 -or $report.summary.high -gt 0) { exit 2 }
exit 0
