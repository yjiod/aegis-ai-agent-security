param([string]$Output = "$env:ProgramData\SentinelAgent\reports\latest.json")
$ErrorActionPreference = 'SilentlyContinue'
$roots = @()
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$baselinePath = Join-Path $installDir 'sentinel-security-baseline.md'
$policyPath = Join-Path $installDir 'sentinel-policy.json'
$policy = if (Test-Path $policyPath) { Get-Content $policyPath -Raw | ConvertFrom-Json } else { $null }
$managedMarker = '<!-- sentinel-managed-baseline -->'
$patterns = @(
  @{ Kind='hardcoded_secret'; Severity='critical'; Regex='AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}' },
  @{ Kind='prompt_override'; Severity='high'; Regex='(?i)ignore (all |any )?(previous|prior) instructions' },
  @{ Kind='unbounded_shell'; Severity='high'; Regex='(?i)shell\s*=\s*true|Invoke-Expression|\biex\s' },
  @{ Kind='hidden_instruction'; Severity='high'; Regex='[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]' },
  @{ Kind='weak_random_token'; Severity='high'; Regex='(?is)(token|secret|session|nonce).{0,120}(Math\.random|random\.random)\s*\(' },
  @{ Kind='blocked_command'; Severity='high'; Regex='(?im)^\s*(curl\s+[^\r\n]*\|\s*(sh|bash)|wget\s+[^\r\n]*\|\s*(sh|bash)|chmod\s+777|rm\s+-rf)(\s|$)' }
)
$findings = @(); $inventory = @()
function Protect-SentinelPath([string]$path) {
  foreach ($home in $userHomes) { if ($path.StartsWith($home.FullName,[StringComparison]::OrdinalIgnoreCase)) { return '~' + $path.Substring($home.FullName.Length) } }
  return $path
}
function Install-SentinelBaseline([string]$repo) {
  if (-not (Test-Path $baselinePath)) { return }
  $baseline = Get-Content $baselinePath -Raw
  $managed = "$managedMarker`n$baseline"
  $ruleTargets = @((Join-Path $repo '.cursor\rules\sentinel-security.mdc'),(Join-Path $repo '.windsurf\rules\sentinel-security.md'))
  foreach ($target in $ruleTargets) { New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null; Set-Content -Encoding UTF8 $target $managed }
  foreach ($name in @('AGENTS.md','CLAUDE.md')) {
    $target=Join-Path $repo $name; $existing=if(Test-Path $target){Get-Content $target -Raw}else{''}
    if ($existing -notlike "*$managedMarker*") { Add-Content -Encoding UTF8 $target "`n$managedMarker`n## 企业安全基线`n执行任何代码变更前必须遵循 .sentinel/SECURITY_BASELINE.md。" }
  }
  $shared=Join-Path $repo '.sentinel\SECURITY_BASELINE.md'; New-Item -ItemType Directory -Force -Path (Split-Path $shared) | Out-Null; Set-Content -Encoding UTF8 $shared $managed
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
    if($url.StartsWith('http://')){$script:findings += @{kind='insecure_mcp_transport';severity='high';path=$safePath;message="MCP $name 使用未加密 HTTP"}}
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
    Get-ChildItem $root -File -Recurse | Where-Object { $_.Length -lt 1MB -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First 5000 | ForEach-Object {
      $text = Get-Content $_.FullName -Raw
      foreach ($rule in $patterns) {
        if ($text -match $rule.Regex) { $findings += @{ kind=$rule.Kind; severity=$rule.Severity; path=(Protect-SentinelPath $_.FullName); message='Policy match' } }
      }
      if ($_.Name -in @('mcp.json','mcp_config.json')) { Inspect-SentinelMcpJson $_ $text }
    }
  }
}
$policyVersion = if (Test-Path $policyPath) { (Get-Content $policyPath -Raw | ConvertFrom-Json).version } else { 'missing' }
$deviceMaterial = "$env:COMPUTERNAME|$env:USERDOMAIN"
$sha = [System.Security.Cryptography.SHA256]::Create()
$deviceId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-','').Substring(0,12).ToLower()
$report = @{ schema='sentinel.report/v1'; agent_version='0.7.0'; policy_version=$policyVersion; device_id=$deviceId; scanned_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); scan_root='managed-windows-roots'; inventory=$inventory; findings=$findings; summary=@{ critical=@($findings|Where-Object severity -eq critical).Count; high=@($findings|Where-Object severity -eq high).Count; medium=@($findings|Where-Object severity -eq medium).Count; low=@($findings|Where-Object severity -eq low).Count } }
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $Output
if ($report.summary.critical -gt 0 -or $report.summary.high -gt 0) { exit 2 }
exit 0
