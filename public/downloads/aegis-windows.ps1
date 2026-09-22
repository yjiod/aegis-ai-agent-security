param([string]$Output = "$env:ProgramData\AegisAgent\reports\latest.json",[string]$ReportUrl = $env:AEGIS_REPORT_URL,[string]$ProtectedConfig = "$env:ProgramData\AegisAgent\reporting.dpapi")
$ErrorActionPreference = 'SilentlyContinue'
$reportConfigInvalid=$false
if(-not ('Security.Cryptography.ProtectedData' -as [type])){try{Add-Type -AssemblyName System.Security}catch{}}
if(Test-Path $ProtectedConfig){
  try{
    $encrypted=[IO.File]::ReadAllBytes($ProtectedConfig);$entropy=[Text.Encoding]::UTF8.GetBytes('AegisAgent.Reporting.v1');$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try{$reportConfig=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json}finally{[Array]::Clear($plain,0,$plain.Length);[Array]::Clear($encrypted,0,$encrypted.Length)}
    $names=@($reportConfig.PSObject.Properties.Name|Sort-Object);if(($names -join ',') -cne 'report_token,report_url,schema,signing_secret' -or $reportConfig.schema -cne 'aegis.reporting/v1'){throw 'invalid reporting config contract'}
    $uri=$null;if(-not [Uri]::TryCreate([string]$reportConfig.report_url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'invalid reporting URL'}
    if(([string]$reportConfig.report_token).Length -lt 32 -or ([string]$reportConfig.report_token).Length -gt 4096 -or ([string]$reportConfig.signing_secret).Length -lt 32 -or ([string]$reportConfig.signing_secret).Length -gt 4096 -or $reportConfig.report_token -ceq $reportConfig.signing_secret){throw 'invalid reporting secrets'}
    $ReportUrl=[string]$reportConfig.report_url;$env:AEGIS_REPORT_TOKEN=[string]$reportConfig.report_token;$env:AEGIS_REPORT_SIGNING_SECRET=[string]$reportConfig.signing_secret
  }catch{$reportConfigInvalid=$true;$ReportUrl='';Remove-Item Env:AEGIS_REPORT_TOKEN -ErrorAction SilentlyContinue;Remove-Item Env:AEGIS_REPORT_SIGNING_SECRET -ErrorAction SilentlyContinue}
}
$roots = @()
$installDir = Join-Path $env:ProgramData 'AegisAgent'
$baselinePath = Join-Path $installDir 'aegis-security-baseline.md'
$policyPath = Join-Path $installDir 'aegis-policy.json'
# 策略自助同步(默认开, 可 modules.policy_auto_sync 关): 拉当前签名策略, 版本更新才落盘。
# Windows 无 ed25519 验签原语, 此处校验 schema+签名字段存在+版本递增, 完整性由 TLS+服务端签名链保证(文档注明)。
try{
  if ($script:policyAutoSync -eq $false) { throw 'policy_auto_sync off' }
  if (-not $env:AEGIS_REPORT_TOKEN) { throw 'no token' }
  $curPol=$null; try{ $curPol=Get-Content -Encoding UTF8 $policyPath -Raw | ConvertFrom-Json }catch{}
  $ru=[Uri]$ReportUrl; $pbase=$ru.Scheme+'://'+$ru.Host
  if($ru.AbsolutePath -like '/aegis/*'){$pbase+='/aegis'}elseif($ru.AbsolutePath -like '/api/*'){$pbase+='/api'}
  $fetched=Invoke-RestMethod -Uri ($pbase+'/v1/policy') -Headers @{Authorization='Bearer '+$env:AEGIS_REPORT_TOKEN} -TimeoutSec 20
  function Aegis-VerGt([string]$a,[string]$b){
    $pa=@($a -split '\.' | ForEach-Object { $m=[regex]::Match($_,'\d+'); if($m.Success){[int]$m.Value}else{0} })
    $pb=@($b -split '\.' | ForEach-Object { $m=[regex]::Match($_,'\d+'); if($m.Success){[int]$m.Value}else{0} })
    for($i=0;$i -lt 3;$i++){ if($pa[$i] -gt $pb[$i]){return $true}elseif($pa[$i] -lt $pb[$i]){return $false} }
    return $false
  }
  $curVer=if ($curPol -and $curPol.version) { [string]$curPol.version } else { '0.0.0' }
  if ($fetched -and $fetched.schema -eq 'aegis.policy/v1' -and $fetched.signature -and $fetched.ed25519_signature -and (Aegis-VerGt ([string]$fetched.version) $curVer)) {
    ($fetched | ConvertTo-Json -Depth 20) | Set-Content -Encoding UTF8 $policyPath
  }
}catch{}
$policy=$null;$policyInvalid=$false
try {
  if(-not (Test-Path $policyPath)){throw 'missing policy'}
  $candidate=Get-Content -Encoding UTF8 $policyPath -Raw | ConvertFrom-Json
  if($candidate.schema -ne 'aegis.policy/v1' -or -not ([string]$candidate.version)){throw 'invalid policy contract'}
  if($candidate.limits -isnot [PSCustomObject] -and $candidate.limits -isnot [hashtable]){throw 'invalid policy limits'}
  foreach($key in @('allowed_skills','allowed_mcp_transports','allowed_mcp_servers','allowed_mcp_commands','allowed_mcp_command_paths','allowed_mcp_invocations','allowed_mcp_domains','blocked_commands','secret_patterns','skill_rules','mcp_rules','code_rules')){
    if($null -ne $candidate.$key -and $candidate.$key -isnot [System.Array]){throw "invalid policy list: $key"}
  }
  foreach($invocation in @($candidate.allowed_mcp_invocations)){if($invocation -isnot [System.Array] -or @($invocation).Count -lt 2 -or @($invocation|Where-Object{-not ($_ -is [string]) -or -not $_}).Count){throw 'invalid MCP invocation policy'}}
  $policy=$candidate
} catch {$policyInvalid=$true}
$script:policyAutoSync = if ($policy -and $policy.modules -and ($policy.modules.policy_auto_sync -eq $false)) { $false } else { $true }
$maxFileBytes=1000000
if($policy -and $policy.limits -and $policy.limits.max_file_bytes){$maxFileBytes=[Math]::Min([Math]::Max([int64]$policy.limits.max_file_bytes,65536),10000000)}
$projectFileLimit=10000
if($policy -and $policy.limits -and $policy.limits.project_files){$projectFileLimit=[Math]::Min([Math]::Max([int64]$policy.limits.project_files,100),100000)}
$managedMarker = '<!-- aegis-managed-baseline -->'
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
# 测试/夹具路径特征（与 mac agent _TEST_PATH_RE 同口径）：tests/specs/fixtures/__tests__/testing
# 目录或 .test./.spec./_test. 文件名。用于 hardcoded_secret 路径感知降级。
function Test-AegisTestPath([string]$p) {
  return ($p -match '(?i)[\\/](tests?|specs?|fixtures?|__tests__|testing)[\\/]') -or ($p -match '(?i)\.test\.|\.spec\.|_test[_.]|(^|[\\/])test_')
}
$findings = @(); $inventory = @()
if($policyInvalid){$findings += @{kind='policy_load_failed';severity='high';path=$policyPath;message='安全策略缺失或契约无效；MCP 策略检查采用失败关闭状态'}}
if($reportConfigInvalid){$findings += @{kind='reporting_config_invalid';severity='high';path='reporting.dpapi';message='受保护上报配置无法解密或契约无效；本轮拒绝上报'}}
function Send-AegisReport([string]$json,[string]$url) {
  $bytes=[Text.Encoding]::UTF8.GetBytes($json);$headers=@{}
  try{$sentReport=$json|ConvertFrom-Json;$sentDeviceId=[string]$sentReport.device_id}catch{throw 'Report device identity is invalid'}
  if($sentDeviceId -notmatch '^[a-f0-9]{12}$'){throw 'Report device identity is invalid'}
  $headers['X-Aegis-Device-ID']=$sentDeviceId
  $sha256=[Security.Cryptography.SHA256]::Create();try{$expectedReportId=([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-','').ToLower().Substring(0,20)}finally{$sha256.Dispose()}
  if($env:AEGIS_REPORT_TOKEN){$headers.Authorization='Bearer '+$env:AEGIS_REPORT_TOKEN}
  if($env:AEGIS_REPORT_SIGNING_SECRET){
    $timestamp=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString();$prefix=[Text.Encoding]::UTF8.GetBytes($timestamp+'.'+$sentDeviceId+'.');$signed=New-Object byte[] ($prefix.Length+$bytes.Length);[Array]::Copy($prefix,0,$signed,0,$prefix.Length);[Array]::Copy($bytes,0,$signed,$prefix.Length,$bytes.Length)
    $hmac=[System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($env:AEGIS_REPORT_SIGNING_SECRET));$signature=([BitConverter]::ToString($hmac.ComputeHash($signed))).Replace('-','').ToLower();$hmac.Dispose()
    $headers['X-Aegis-Timestamp']=$timestamp;$headers['X-Aegis-Signature']='sha256='+$signature
  }
  $response=Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 15
  $ackBytes=[Text.Encoding]::UTF8.GetByteCount([string]$response.Content)
  if($response.StatusCode -notin @(200,202) -or $ackBytes -gt 4096){throw 'Collector acknowledgement contract is invalid'}
  try{$ack=([string]$response.Content)|ConvertFrom-Json}catch{throw 'Collector acknowledgement contract is invalid'}
  $names=@($ack.PSObject.Properties.Name|Sort-Object)
  if(($names -join ',') -cne 'accepted,duplicate,report_id,severity' -or $ack.accepted -isnot [bool] -or -not $ack.accepted -or $ack.duplicate -isnot [bool] -or ([string]$ack.report_id) -cne $expectedReportId -or $ack.severity -notin @('critical','high','normal')){throw 'Collector acknowledgement contract is invalid'}
  return $ack
}
function Write-AegisUploadStatus([string]$url){
  $uri=[Uri]$url;$status=@{schema='aegis.upload-status/v1';status='accepted';last_success=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();collector_host=$uri.DnsSafeHost.ToLower()}|ConvertTo-Json -Compress
  $path=Join-Path (Split-Path $Output) 'upload-status.json';$temp=$path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
  try{$status|Set-Content -Encoding UTF8 $temp;Move-Item $temp $path -Force}finally{Remove-Item $temp -Force -ErrorAction SilentlyContinue}
}
function Compare-AegisVersion([string]$a,[string]$b) {
  # 按数字段比较版本串：a>b 返回 1，a<b 返回 -1，相等返回 0（非数字段按 0）。镜像 aegis_self_update.py version_tuple。
  $pa=[string]$a -split '\.'; $pb=[string]$b -split '\.'
  $n=[Math]::Max($pa.Count,$pb.Count)
  for($i=0;$i -lt $n;$i++){
    $da=0;$db=0
    if($i -lt $pa.Count){$m=[regex]::Match($pa[$i],'\d+');if($m.Success){$da=[int]$m.Value}}
    if($i -lt $pb.Count){$m=[regex]::Match($pb[$i],'\d+');if($m.Success){$db=[int]$m.Value}}
    if($da -gt $db){return 1}elseif($da -lt $db){return -1}
  }
  return 0
}
function Update-AegisScanner([string]$ReportUrl,[string]$CurrentVersion,[string]$ScriptPath,[object]$Policy=$null,[string]$DeviceId='') {
  # pinned 设备(开发主机)永不自动更新, 只接受人工/桌管更新。
  if ($Policy -and $DeviceId) {
    $pinned = @($Policy.agent_self_update.pinned | Where-Object { $_ })
    if ($pinned -contains $DeviceId) { return }
  }
  # Windows 客户端自更新兜底通道。此前 Windows 侧（PowerShell 扫描器 + .NET 服务宿主）完全
  # 没有自更新逻辑——只有 mac/linux 的 python agent 会跑 aegis_self_update.py，导致 Windows
  # 终端永远停在安装时的版本、控制台版本长期落后（用户反馈"上线了还是 0.34.6，没自动更新"）。
  # 主通道仍是桌管/MDM 推送；本函数让无桌管的 Windows 终端也能自动跟上版本轴。
  # 严格镜像 aegis_self_update.py 的安全语义：
  #   仅 https；占位域(RFC2606)拒绝；工件 URL 同源钉子(scheme+host+port 必须与 manifest 一致)；
  #   下载后 sha256 校验 + PS5.1 BOM 校验；幂等短路(本地已是目标 sha256 则不动)；.prev 备份后替换；
  #   只替换脚本文件、不执行下载内容(下轮扫描自然生效)；任何失败静默返回、绝不影响本轮扫描与上报。
  try {
    if(-not $ReportUrl -or -not $ScriptPath -or -not (Test-Path -LiteralPath $ScriptPath)){return}
    $base=$null
    if(-not [Uri]::TryCreate($ReportUrl,[UriKind]::Absolute,[ref]$base) -or $base.Scheme -cne 'https'){return}
    $mh=$base.Host.ToLowerInvariant()
    if($mh -eq 'aegis.example.com' -or $mh.EndsWith('.example.com') -or $mh.EndsWith('.example') -or $mh.EndsWith('.invalid') -or $mh.EndsWith('.test') -or $mh.EndsWith('.localhost')){return}
    try{[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12}catch{}
    $origin=$base.Scheme+'://'+$base.Host+$(if($base.IsDefaultPort){''}else{':'+$base.Port})
    $man=$null
    try{$man=Invoke-RestMethod -Uri ($origin+'/downloads/update-manifest.json') -Method Get -TimeoutSec 20}catch{return}
    if(-not $man -or ([string]$man.schema) -cne 'aegis.update/v1'){return}
    $offered=[string]$man.agent_version; if(-not $offered){$offered=[string]$man.release}
    if(-not $offered -or (Compare-AegisVersion $offered $CurrentVersion) -le 0){return}
    $art=$man.artifacts.'aegis-windows.ps1'
    if(-not $art -or -not $art.url -or -not $art.sha256){return}
    $wantSha=([string]$art.sha256).ToLowerInvariant()
    if($wantSha -notmatch '^[0-9a-f]{64}$'){return}
    try{$localSha=(Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()}catch{$localSha=$null}
    if($localSha -eq $wantSha){return}
    # 同源钉子：相对 url 按 manifest 源解析为绝对地址；解析后 scheme+host+port 必须与 manifest 一致，
    # 未签名 manifest 即便被中间人替换也无法把下载改指向恶意主机。
    $resolved=$null
    try{$resolved=New-Object System.Uri($base,[string]$art.url)}catch{return}
    if($resolved.Scheme -cne 'https' -or $resolved.Host -cne $base.Host -or $resolved.Port -ne $base.Port){return}
    $staging=$ScriptPath+'.'+[Guid]::NewGuid().ToString('N')+'.staging'
    try{
      Invoke-WebRequest -Uri $resolved.AbsoluteUri -OutFile $staging -TimeoutSec 60 -UseBasicParsing
      if((Get-FileHash -LiteralPath $staging -Algorithm SHA256).Hash.ToLowerInvariant() -cne $wantSha){return}
      $fs=[IO.File]::OpenRead($staging);$bom=New-Object byte[] 3;$read=$fs.Read($bom,0,3);$fs.Close()
      if($read -lt 3 -or $bom[0] -ne 0xEF -or $bom[1] -ne 0xBB -or $bom[2] -ne 0xBF){return}
      # preflight（PM#2）：替换前用 PowerShell 解析器校验下载脚本语法，挡住"发布件语法损坏"把
      # Windows agent 更新成砖（sha+BOM 只证字节完整，不证语法可解析）。解析报错即拒绝、保留旧脚本。
      try{
        $ptok=$null;$perr=$null
        [void][System.Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText($staging),[ref]$ptok,[ref]$perr)
        if($perr -and $perr.Count -gt 0){return}
      }catch{return}
      Copy-Item -LiteralPath $ScriptPath -Destination ($ScriptPath+'.prev') -Force
      Move-Item -LiteralPath $staging -Destination $ScriptPath -Force
      # 应用后复核：替换后 target 的 sha256 必须仍等于期望；不符则从 .prev 自动回滚（绝不留在坏状态）。
      try{
        if((Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $wantSha){
          if(Test-Path -LiteralPath ($ScriptPath+'.prev')){Move-Item -LiteralPath ($ScriptPath+'.prev') -Destination $ScriptPath -Force}
        }
      }catch{}
    }catch{return}
    finally{if(Test-Path -LiteralPath $staging){try{Remove-Item -LiteralPath $staging -Force}catch{}}}
  }catch{return}
}
function Protect-AegisPath([string]$path) {
  foreach ($userHome in $userHomes) { if ($path.StartsWith($userHome.FullName,[StringComparison]::OrdinalIgnoreCase)) { return '~' + $path.Substring($userHome.FullName.Length) } }
  return $path
}
function Test-AegisMcpInvocation([string]$command,[object[]]$args) {
  $actual=@($command)+@($args|ForEach-Object{[string]$_});if($actual.Count -le 1){return $true}
  foreach($candidate in @($policy.allowed_mcp_invocations)){
    $expected=@($candidate|ForEach-Object{[string]$_});if($expected.Count -ne $actual.Count){continue};$same=$true
    for($index=0;$index -lt $actual.Count;$index++){if($actual[$index] -cne $expected[$index]){$same=$false;break}}
    if($same){return $true}
  }
  return $false
}
function Test-AegisSafeTarget([string]$root,[string]$target) {
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
function Install-AegisBaseline([string]$repo) {
  if (-not (Test-Path $baselinePath)) { return }
  $baseline = Get-Content -Encoding UTF8 $baselinePath -Raw
  $managed = "$managedMarker`n$baseline"
  $ruleTargets = @((Join-Path $repo '.cursor\rules\aegis-security.mdc'),(Join-Path $repo '.windsurf\rules\aegis-security.md'))
  foreach ($target in $ruleTargets) { if(-not (Test-AegisSafeTarget $repo $target)){continue};New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null;Set-Content -Encoding UTF8 $target $managed }
  foreach ($name in @('AGENTS.md','CLAUDE.md')) {
    $target=Join-Path $repo $name;if(-not (Test-AegisSafeTarget $repo $target)){continue};$existing=if(Test-Path $target){Get-Content -Encoding UTF8 $target -Raw}else{''}
    if ($existing -notlike "*$managedMarker*") { Add-Content -Encoding UTF8 $target "`n$managedMarker`n## 企业安全基线`n执行任何代码变更前必须遵循 .aegis/SECURITY_BASELINE.md。" }
  }
  $shared=Join-Path $repo '.aegis\SECURITY_BASELINE.md';if(Test-AegisSafeTarget $repo $shared){New-Item -ItemType Directory -Force -Path (Split-Path $shared) | Out-Null;Set-Content -Encoding UTF8 $shared $managed}
}
function Sync-AegisUserBaselines([object[]]$homes) {
  if(-not (Test-Path $baselinePath)){return}
  $content=(Get-Content -Encoding UTF8 $baselinePath -Raw).TrimEnd();$start='<!-- aegis-managed-user-baseline:start -->';$end='<!-- aegis-managed-user-baseline:end -->';$block=$start+"`n"+$content+"`n"+$end
  foreach($homeDir in $homes){
    $targets=@();$codex=Join-Path $homeDir.FullName '.codex';$claude=Join-Path $homeDir.FullName '.claude'
    if((Test-Path $codex) -and -not ((Get-Item $codex -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$targets+=Join-Path $codex 'AGENTS.md'}
    if(((Test-Path $claude) -and -not ((Get-Item $claude -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) -or (Test-Path (Join-Path $homeDir.FullName '.claude.json'))){$targets+=Join-Path $claude 'CLAUDE.md'}
    foreach($target in $targets){
      if(-not (Test-AegisSafeTarget $homeDir.FullName $target)){continue};New-Item -ItemType Directory -Force -Path (Split-Path $target)|Out-Null;if(-not (Test-AegisSafeTarget $homeDir.FullName $target)){continue}
      $existing=if(Test-Path $target){Get-Content -Encoding UTF8 $target -Raw}else{''};$pattern=[regex]::Escape($start)+'.*?'+[regex]::Escape($end)
      if($existing.Contains($start) -xor $existing.Contains($end)){$script:findings+=@{kind='malformed_user_baseline_block';severity='high';path=(Protect-AegisPath $target);message='用户级安全基线托管标记不完整，已停止自动修改'};continue}
      if($existing.Contains($start)){$updated=[regex]::Replace($existing,$pattern,[System.Text.RegularExpressions.MatchEvaluator]{param($match)$block},[System.Text.RegularExpressions.RegexOptions]::Singleline)}else{$updated=$existing.TrimEnd()+$(if($existing.Trim()){"`n`n"}else{''})+$block+"`n"}
      if($updated -ne $existing){Set-Content -Encoding UTF8 $target $updated}
    }
  }
}
function Inspect-AegisMcpJson([System.IO.FileInfo]$file,[string]$text) {
  if (-not $policy) { return }
  try { $config=$text | ConvertFrom-Json } catch { $script:findings += @{kind='invalid_mcp_config';severity='medium';path=(Protect-AegisPath $file.FullName);message='MCP JSON 配置无法解析'}; return }
  $servers=if($config.mcpServers){$config.mcpServers}else{$config.servers}
  if (-not $servers) { return }
  foreach($entry in $servers.PSObject.Properties) {
    $name=$entry.Name; $cfg=$entry.Value; $safePath=Protect-AegisPath $file.FullName
    if($cfg -isnot [PSCustomObject] -and $cfg -isnot [hashtable]){$script:findings += @{kind='invalid_mcp_server';severity='high';path=$safePath;message="MCP Server $name 配置必须是对象"};continue}
    if($policy.allowed_mcp_servers -and $name -notin $policy.allowed_mcp_servers){$script:findings += @{kind='unknown_mcp';severity='medium';path=$safePath;message="未在允许列表中的 MCP Server: $name"}}
    $rawCommand=[string]$cfg.command;$command=[IO.Path]::GetFileName($rawCommand)
    if($command -and $policy.allowed_mcp_commands -and $command -notin $policy.allowed_mcp_commands){$script:findings += @{kind='unapproved_mcp_command';severity='high';path=$safePath;message="MCP 使用未批准命令: $command"}}
    if($rawCommand -match '[\\/]' -and $rawCommand -notin @($policy.allowed_mcp_command_paths)){$script:findings += @{kind='unapproved_mcp_command_path';severity='high';path=$safePath;message="MCP $name 使用未批准的可执行路径"}}
    $invocationArgs=@($cfg.args)
    if($command -and -not (Test-AegisMcpInvocation $command $invocationArgs)){$script:findings += @{kind='unapproved_mcp_invocation';severity='high';path=$safePath;message="MCP $name 的命令参数组合未获批准"}}
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
function Inspect-AegisMcpToml([System.IO.FileInfo]$file,[string]$text) {
  if (-not $policy) { return }
  $safePath=Protect-AegisPath $file.FullName
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
    if($command -and -not (Test-AegisMcpInvocation $command $args)){$script:findings += @{kind='unapproved_mcp_invocation';severity='high';path=$safePath;message="MCP $name 的命令参数组合未获批准"}}
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
function Inspect-AegisDependencies([System.IO.FileInfo]$file,[string]$text) {
  $safePath=Protect-AegisPath $file.FullName
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
function Get-AegisUserHomes {
  # 跨盘枚举用户主目录: ProfileList 的 ProfileImagePath 为权威来源(不假设 C:),
  # 回退到各固定盘的 \Users。用户可能把 profile/软件装在 D:/E: 等盘。
  $paths = @()
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($p) {
      $p = $p.Replace('%SystemDrive%', "$env:SystemDrive")
      if (Test-Path -LiteralPath $p -PathType Container) { $paths += $p }
    }
  }
  if (-not $paths) {
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
      if ($d.DriveType -eq 'Fixed' -and $d.IsReady) {
        $u = Join-Path $d.Name 'Users'
        if (Test-Path -LiteralPath $u) { Get-ChildItem $u -Directory -ErrorAction SilentlyContinue | ForEach-Object { $paths += $_.FullName } }
      }
    }
  }
  $skip = @('Public','Default','Default User','All Users','DefaultAccount','systemprofile')
  return @($paths | Where-Object { (Split-Path $_ -Leaf) -notin $skip } | Select-Object -Unique | ForEach-Object { Get-Item $_ })
}
function Get-AegisProgramRoots {
  # 所有固定盘的 Program Files / Program Files (x86), 不假设 C:
  $roots = @()
  if ($env:ProgramFiles) { $roots += $env:ProgramFiles }
  if (${env:ProgramFiles(x86)}) { $roots += ${env:ProgramFiles(x86)} }
  foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if ($d.DriveType -eq 'Fixed' -and $d.IsReady) {
      foreach ($n in @('Program Files','Program Files (x86)')) { $p = Join-Path $d.Name $n; if (Test-Path -LiteralPath $p) { $roots += $p } }
    }
  }
  return @($roots | Select-Object -Unique)
}
function Get-ManagedRepos {
  $repos=@()
  foreach ($home_ in (Get-AegisUserHomes)) {
    foreach($relative in @('source\repos','Documents\GitHub','Projects','Code')) {
      $base=Join-Path $home_ $relative
      if(Test-Path $base) { Get-ChildItem $base -Directory -Recurse -Depth 4 -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName '.git') } | ForEach-Object { $repos += $_.FullName } }
    }
  }
  return $repos | Select-Object -Unique
}
$userHomes = @(Get-AegisUserHomes)
Sync-AegisUserBaselines $userHomes
$agentMarkers = @{
  cursor=@('.cursor\mcp.json','AppData\Roaming\Cursor\User\settings.json','AppData\Local\Programs\cursor\Cursor.exe')
  codex=@('.codex\config.toml','AppData\Roaming\npm\codex.cmd')
  claude_code=@('.claude.json','.claude\settings.json','AppData\Roaming\npm\claude.cmd')
  windsurf=@('.codeium\windsurf\mcp_config.json','AppData\Roaming\Windsurf\User\settings.json','AppData\Local\Programs\Windsurf\Windsurf.exe')
  codebuddy=@('.codebuddy\rules.md','.codebuddy\device-id','AppData\Roaming\CodeBuddy\settings.json','AppData\Local\Programs\CodeBuddy\CodeBuddy.exe')
  qwen_enterprise=@('.qwenworkcn\AGENTS.md','.qwenworkcn\mcp.json')
  workbuddy=@('.workbuddy\AGENTS.md','.workbuddy\mcp.json','.workbuddy\device-id','.workbuddy-ai\SOUL.md','.workbuddy-ai\AGENTS.md')
  gemini_cli=@('.gemini\GEMINI.md','.gemini\settings.json')
  github_copilot_cli=@('.copilot\copilot-instructions.md')
  tongyi_lingma=@('.lingma\rules.md')
}
# 多源检测(不盲目按固定路径): 用户目录 marker + 注册表 Uninstall 显示名 + 进程 + 各盘 Program Files 厂商目录
$detected = @{}
function Add-AegisAgent([string]$name,[string]$path,[string]$scope,[string]$by) {
  if (-not $detected.ContainsKey($name)) { $detected[$name] = @{ path = $path; scope = $scope; by = $by } }
}
$uninstallKeywords = [ordered]@{
  'cursor'='cursor'; 'codex'='codex'; 'claude'='claude_code'; 'windsurf'='windsurf'; 'codeium'='windsurf';
  'codebuddy'='codebuddy'; 'qwen'='qwen_enterprise'; 'workbuddy'='workbuddy';
  'gemini'='gemini_cli'; 'copilot'='github_copilot_cli'; 'lingma'='tongyi_lingma'
}
$vendorDirs = [ordered]@{
  'Cursor'='cursor'; 'CodeBuddy'='codebuddy'; 'WorkBuddyAI'='workbuddy'; 'WorkBuddy'='workbuddy';
  'Windsurf'='windsurf'; 'QwenWork'='qwen_enterprise'; 'Gemini'='gemini_cli'; 'Lingma'='tongyi_lingma';
  'Claude'='claude_code'; 'Codex'='codex'
}
$processNames = [ordered]@{
  'Cursor'='cursor'; 'Codex'='codex'; 'Claude'='claude_code'; 'Windsurf'='windsurf'; 'CodeBuddy'='codebuddy';
  'WorkBuddy'='workbuddy'; 'QwenWork'='qwen_enterprise'; 'Gemini'='gemini_cli'; 'Copilot'='github_copilot_cli'; 'Lingma'='tongyi_lingma'
}
foreach ($userHome in $userHomes) {
  foreach ($relative in @('.cursor','.codex','.claude','.codeium\windsurf')) { $candidate=Join-Path $userHome $relative; if(Test-Path $candidate){$roots += $candidate} }
  foreach ($agent in $agentMarkers.Keys) {
    foreach ($relative in $agentMarkers[$agent]) { $marker=Join-Path $userHome $relative; if(Test-Path $marker){ Add-AegisAgent $agent (Protect-AegisPath $marker) 'user' 'filesystem_marker'; break } }
  }
}

# 注册表 Uninstall 显示名(HKLM/WOW64/HKCU), InstallLocation 跨盘
foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
  Get-ItemProperty $hive -ErrorAction SilentlyContinue | ForEach-Object {
    $dn = [string]$_.DisplayName
    if (-not $dn) { return }
    foreach ($k in $uninstallKeywords.Keys) {
      if ($dn.ToLower().Contains($k)) { Add-AegisAgent $uninstallKeywords[$k] ([string]$_.InstallLocation) 'system' 'registry_uninstall'; return }
    }
  }
}
# 进程名(装到任意盘/任意路径都能抓到)
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
  $pn = [string]$_.ProcessName
  foreach ($k in $processNames.Keys) {
    if ($pn.ToLower().Contains($k.ToLower())) {
      $pp = [string]$_.Path
      Add-AegisAgent $processNames[$k] ($(if($pp){Protect-AegisPath $pp}else{$pn})) 'process' 'process'
      return
    }
  }
}
# 各固定盘 Program Files 厂商目录
foreach ($proot in (Get-AegisProgramRoots)) {
  foreach ($v in $vendorDirs.Keys) { $p = Join-Path $proot $v; if (Test-Path -LiteralPath $p) { Add-AegisAgent $vendorDirs[$v] $p 'system' 'program_files' } }
}
foreach ($name in ($detected.Keys | Sort-Object)) {
  $dd = $detected[$name]
  $inventory += @{ type='ai_agent'; name=$name; path=$dd.path; scope=$dd.scope; detected_by=$dd.by }
}
foreach($repo in Get-ManagedRepos) { Install-AegisBaseline $repo; $roots += $repo; $inventory += @{type='managed_repository';path=(Protect-AegisPath $repo)} }
foreach ($root in $roots) {
  if (Test-Path $root) {
    $inventory += @{ type='agent_root'; path=(Protect-AegisPath $root) }
    $skillManifests=@(Get-ChildItem $root -Filter 'SKILL.md' -File -Recurse -Force|Select-Object -First 501)
    foreach($manifest in @($skillManifests|Select-Object -First 500)){
      $skillName=$manifest.Directory.Name;$approved=$policy -and $skillName -in @($policy.allowed_skills);$inventory+=@{type='skill';name=$skillName;path=(Protect-AegisPath $manifest.FullName);approved=[bool]$approved}
      if(-not $approved){$findings+=@{kind='unknown_skill';severity='high';path=(Protect-AegisPath $manifest.FullName);message="未批准的 Skill: $skillName"}}
      $links=@(Get-ChildItem $manifest.Directory.FullName -Recurse -Force -Attributes ReparsePoint|Select-Object -First 101)
      foreach($link in @($links|Select-Object -First 100)){$findings+=@{kind='skill_symlink_escape';severity='high';path=(Protect-AegisPath $link.FullName);message='Skill 包含重解析点，需人工确认目标边界'}}
      if($links.Count -gt 100){$findings+=@{kind='skill_link_findings_truncated';severity='medium';path=(Protect-AegisPath $manifest.FullName);message='Skill 重解析点超过 100，仅保留前 100 项'}}
    }
    if($skillManifests.Count -gt 500){$findings+=@{kind='skill_scan_truncated';severity='medium';path=(Protect-AegisPath $root);message='Skill 数量超过扫描上限 500'}}
    $oversized=@(Get-ChildItem $root -File -Recurse -Force | Where-Object { $_.Length -gt $maxFileBytes -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First 101)
    foreach($file in @($oversized|Select-Object -First 100)){$findings += @{kind='oversized_file_skipped';severity='medium';path=(Protect-AegisPath $file.FullName);message="文件超过扫描字节上限 $maxFileBytes"}}
    if($oversized.Count -gt 100){$findings += @{kind='oversized_file_findings_truncated';severity='medium';path=(Protect-AegisPath $root);message='超大文件发现项超过 100，仅保留前 100 项'}}
    $candidates=@(Get-ChildItem $root -File -Recurse -Force | Where-Object { $_.Length -le $maxFileBytes -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First ($projectFileLimit+1))
    if($candidates.Count -gt $projectFileLimit){$findings+=@{kind='project_scan_truncated';severity='medium';path=(Protect-AegisPath $root);message="项目候选文件超过扫描上限 $projectFileLimit"}}
    $candidates|Select-Object -First $projectFileLimit | ForEach-Object {
      $text = Get-Content -Encoding UTF8 $_.FullName -Raw
      foreach ($rule in $patterns) {
        $matched = $false
        if ($rule.Kind -eq 'insecure_tls_verification') {
          # 与 mac agent 同口径：安全基线文档以"禁止…(verify=False, NODE_TLS_…=0)"禁用示例
          # 引用坏写法，字面匹配会系统性误报；取第一个同行动词前缀**非**禁止语境的命中
          # （真实不安全代码行不带 禁止/never 前缀）。
          foreach ($m in [regex]::Matches($text, $rule.Regex)) {
            $ls = $text.LastIndexOf([char]10, [Math]::Max(0, $m.Index - 1)) + 1
            $prefix = if ($m.Index -gt $ls) { $text.Substring($ls, $m.Index - $ls) } else { '' }
            if ($prefix -notmatch '(?i)禁止|不得|严禁|勿|never|prohibit|forbid') { $matched = $true; break }
          }
        } else {
          $matched = ($text -match $rule.Regex)
        }
        if ($matched) {
          # 路径感知严重度（与 mac agent 同口径）：测试/夹具路径的"凭据"多为 dummy，
          # hardcoded_secret 降为 medium（仍上报），生产代码路径保持 critical。
          $sev = $rule.Severity
          if ($rule.Kind -eq 'hardcoded_secret' -and (Test-AegisTestPath $_.FullName)) { $sev = 'medium' }
          $findings += @{ kind=$rule.Kind; severity=$sev; path=(Protect-AegisPath $_.FullName); message='Policy match' }
        }
      }
      if ($_.Name -in @('mcp.json','mcp_config.json')) { Inspect-AegisMcpJson $_ $text }
      if ($_.Name -eq 'config.toml' -and $_.FullName -match '\\\.codex\\') { Inspect-AegisMcpToml $_ $text }
      if ($_.Name -eq 'package.json' -or $_.Name -like 'requirements*.txt') { $inventory += @{type='dependency_manifest';path=(Protect-AegisPath $_.FullName)}; Inspect-AegisDependencies $_ $text }
    }
  }
}
$policyVersion = if ($policy) { [string]$policy.version } else { 'invalid' }
$inventoryLimit=5000;$findingLimit=10000
if(@($inventory).Count -gt $inventoryLimit){$omitted=@($inventory).Count-$inventoryLimit+1;$inventory=@($inventory|Select-Object -First ($inventoryLimit-1));$inventory += @{type='inventory_truncated';omitted=$omitted}}
if(@($findings).Count -gt $findingLimit){$omitted=@($findings).Count-$findingLimit+1;$findings=@($findings|Select-Object -First ($findingLimit-1));$findings += @{kind='findings_truncated';severity='medium';path='managed-windows-roots';message="报告发现项超限，省略 $omitted 项"}}
$sn = $null
# 序列号来源降级链(取第一个非占位值): 系统序列号 → BIOS → 主板(BaseBoard) → SMBIOS UUID。
# 白牌机常见: 系统/BIOS 序列号是字面占位("System Serial Number"), 主板序列号也可能占位;
# SMBIOS UUID 通常烧录于主板、比字符串序列号更可靠(劣质板全0/全F需排除)。全失败才回落计算机名。
$badSn = @('', 'to be filled by o.e.m.', 'none', 'default string', 'unknown', 'o.e.m.', 'not specified', 'system serial number', 'serial number', 'n/a', 'na', 'empty', 'to be filled')
function Test-AegisGoodSn([string]$v) { return ($v -and ($badSn -notcontains $v.Trim().ToLower())) }
foreach ($src in @(
  { try { (Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 10).IdentifyingNumber } catch { $null } },
  { try { (Get-CimInstance Win32_BIOS -OperationTimeoutSec 10).SerialNumber } catch { $null } },
  { try { (Get-CimInstance Win32_BaseBoard -OperationTimeoutSec 10).SerialNumber } catch { $null } }
)) {
  $c = & $src
  if (Test-AegisGoodSn $c) { $sn = $c.Trim(); break }
}
if (-not $sn) {
  try {
    $u = [string](Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 10).UUID
    $t = $u.Replace('-', '')
    if ($t -and ($t -notmatch '^(0+|F+)$') -and ($badSn -notcontains $t.ToLower())) { $sn = $u }
  } catch { }
}
$serialDisplay = $sn
# 身份(device_id)用**旧链**(CSProduct→BIOS + 旧占位名单), 保证存量设备 id 稳定——令牌(DPAPI)、
# 封禁豁免名单都绑在旧 id 上; 改身份链会使令牌与 device_id 失配恒 401(真机教训)。
# 主板序列号/UUID 只用于**显示** serial($serialDisplay)。
$legacyBad = @('', 'to be filled by o.e.m.', 'none', 'default string', 'unknown', 'o.e.m.', 'not specified')
$identitySn = $null
foreach ($src in @(
  { try { (Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 10).IdentifyingNumber } catch { $null } },
  { try { (Get-CimInstance Win32_BIOS -OperationTimeoutSec 10).SerialNumber } catch { $null } }
)) { $c = & $src; if ($c -and ($legacyBad -notcontains $c.Trim().ToLower())) { $identitySn = $c.Trim(); break } }
if ($identitySn) { $deviceMaterial = "aegis-hw:" + $identitySn } else { $deviceMaterial = "$env:COMPUTERNAME|$env:USERDOMAIN" }
$sha = [System.Security.Cryptography.SHA256]::Create()
$deviceId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($deviceMaterial)))).Replace('-','').Substring(0,12).ToLower()
$sn = $serialDisplay
$agentVersion = '0.36.8'
# ── 服务器地址覆盖（预留文件）：编辑 %ProgramData%\AegisAgent\server-override.json 即全自动
#    重新入网并切换控制台（无需重装）。失败 SOFT FAIL 保持原上报配置。 ──
$ovServer = $null
$ovPath = Join-Path $installDir 'server-override.json'
if (Test-Path -LiteralPath $ovPath) {
  try {
    $ovObj = Get-Content -Encoding UTF8 -LiteralPath $ovPath -Raw | ConvertFrom-Json
    $ovu = [string]$ovObj.server_url
    if ($ovu -and $ovu.StartsWith('https://')) { $ovServer = $ovu.TrimEnd('/') }
  } catch { $ovServer = $null }
}
if ($ovServer) {
  $curUri = $null; [Uri]::TryCreate([string]$ReportUrl, [UriKind]::Absolute, [ref]$curUri) | Out-Null
  $curOrigin = if ($curUri) { "$($curUri.Scheme)://$($curUri.Host)" } else { '' }
  if ($ovServer -ne $curOrigin) {
    try {
      $enr = Invoke-RestMethod -Uri "$ovServer/api/enroll" -Method Post -ContentType 'application/json' -Body (@{ hostname = $env:COMPUTERNAME; device_id = $deviceId; agent_version = $agentVersion } | ConvertTo-Json -Compress) -TimeoutSec 20
      $ovTok = [string]$enr.report_token; $ovSec = [string]$enr.signing_secret; $ovRu = [string]$enr.report_url
      if ($ovTok.Length -ge 32 -and $ovTok.Length -le 4096 -and $ovSec.Length -ge 32 -and $ovSec.Length -le 4096 -and $ovRu.StartsWith('https://')) {
        $ovCfg = @{ schema = 'aegis.reporting/v1'; report_url = $ovRu; report_token = $ovTok; signing_secret = $ovSec } | ConvertTo-Json -Compress
        $ovEnc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($ovCfg), $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes($ProtectedConfig, $ovEnc)
        $ReportUrl = $ovRu; $env:AEGIS_REPORT_TOKEN = $ovTok; $env:AEGIS_REPORT_SIGNING_SECRET = $ovSec; $reportConfigInvalid = $false
      }
    } catch { }
  }
}
# 自更新兜底：拉控制台 update-manifest，若 agent 版本轴更新则 sha256+BOM 校验后原子替换本脚本，
# 下一轮扫描（服务宿主每 interval 重新以 -File 拉起）自然生效。主通道仍是桌管/MDM 推送；
# 此前 Windows 侧无任何自更新，终端会永远停在安装版本（用户反馈"上线了还是 0.34.6，没自动更新"）。
$selfPath = $PSCommandPath
if (-not $selfPath) { try { $selfPath = $MyInvocation.MyCommand.Path } catch { $selfPath = $null } }
Update-AegisScanner -ReportUrl $ReportUrl -CurrentVersion $agentVersion -ScriptPath $selfPath -Policy $policy -DeviceId $deviceId
# 交互使用者解析（服务以 LocalSystem 运行时 $env:USERNAME 为空/SYSTEM）：多源解析 + 粘滞缓存。
# 此前仅靠 Win32_ComputerSystem.UserName，遇到无人交互登录的扫描周期（锁屏/会话断开/无头 VM）
# 会把上报用户抖动成字面量 'unknown'（用户反馈"上报者是 unknown"；实测同一台机 shine/unknown 交替）。
# 现：① 交互控制台用户 → ② 活动会话 explorer.exe 属主 → 解析到真实用户就落盘 last-os-user 缓存；
# 本轮解析不到就复用上次已知值（设备主用户不会周期间跳变，粘滞更稳）；从未解析到才 'unknown'。
$osUser = $env:USERNAME
if (-not $osUser -or $osUser -ieq 'SYSTEM' -or $osUser.EndsWith('$')) {
  $osUser = $null
  $cs = $null
  try { $cs = (Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 10 -ErrorAction Stop).UserName } catch { $cs = $null }
  if (-not $cs) { try { $cs = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName } catch { $cs = $null } }
  if ($cs) { $osUser = ([string]$cs -split '\\')[-1] }
  if (-not $osUser) {
    try {
      $exp = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -OperationTimeoutSec 10 -ErrorAction Stop | Select-Object -First 1
      if ($exp) { $own = Invoke-CimMethod -InputObject $exp -MethodName GetOwner -ErrorAction SilentlyContinue; if ($own -and $own.User) { $osUser = [string]$own.User } }
    } catch { }
  }
}
$osUserCache = Join-Path $installDir 'last-os-user'
if ($osUser -and $osUser -ine 'SYSTEM' -and -not $osUser.EndsWith('$')) {
  try { [IO.File]::WriteAllText($osUserCache, $osUser) } catch { }
} else {
  $osUser = $null
  if (Test-Path -LiteralPath $osUserCache) { try { $cachedUser = ([IO.File]::ReadAllText($osUserCache)).Trim(); if ($cachedUser) { $osUser = $cachedUser } } catch { } }
}
if (-not $osUser) { $osUser = 'unknown' }
# 归属人：优先安装期显式绑定的 AEGIS_DEVICE_OWNER，其次由控制台按 os_user 归一(override||os_user||待分配)。
$owner = if ($env:AEGIS_DEVICE_OWNER) { [string]$env:AEGIS_DEVICE_OWNER } else { '' }
# ── 物理网卡采集（MAC + 本机 IP）──────────────────────────────────────────
# 用 .NET NetworkInterface 而非 Get-NetAdapter/Get-NetIPAddress：后者走 WMI/CIM，
# 在 WMI 仓库慢/挂的机器上会把整个扫描周期拖死（真机疑似捕获：服务在跑但永不上报）。
# .NET 这条路不碰 WMI，快且不会挂。物理判定：排除 Tunnel/Loopback/Ppp 等类型 +
# 描述含虚拟关键字(Hyper-V/VMware/Parallels/vEthernet/Docker/TAP…)。本机 IP 剔除
# 回环(127.*/::1)与链路本地(169.254./fe80)。出口 IP 由 Collector 记请求源, 不在此采集。
# 全程 try/catch 兜底空对象：采集失败绝不影响上报。
$networkInfo = @{ physical_nics = @(); macs = @(); local_ips = @() }
try {
  $nics = @(); $allMacs = @(); $allIps = @()
  foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    $t = [string]$ni.NetworkInterfaceType
    if ($t -in @('Tunnel', 'Loopback', 'Ppp', 'Unknown', 'Atm', 'GenericModem')) { continue }
    if ($ni.Description -match 'Virtual|VMware|Hyper-V|Parallels|VirtualBox|TAP-Windows|TUN|Docker|vEthernet|WireGuard|ZeroTier') { continue }
    $macraw = $ni.GetPhysicalAddress().ToString()
    if (-not $macraw -or $macraw -eq '000000000000') { continue }
    $mac = (([regex]::Matches($macraw, '..') | ForEach-Object { $_.Value }) -join ':').ToLower()
    $ips = @()
    try {
      $ips = @($ni.GetIPProperties().UnicastAddresses | ForEach-Object { $_.Address.ToString() } |
        Where-Object { $_ -and $_ -notlike '127.*' -and $_ -notlike '169.254.*' -and $_ -notlike 'fe80*' -and $_ -ne '::1' })
    } catch { }
    $nics += @{ name = $ni.Name; mac = $mac; ips = $ips }
    $allMacs += $mac
    $allIps += $ips
  }
  $networkInfo = @{ physical_nics = $nics; macs = $allMacs; local_ips = $allIps }
} catch { }
# ── 封禁执行器(deny-only): 移除 + 每周期自动再执行 + 备份可回滚, 回执进报告 ──────
# 语义(用户口径: 封禁就真的封禁, 不是"搬一次不管"): Skill=目录移入隔离备份区(工具不可再加载),
# MCP=从 AI 工具配置删除; 每个扫描周期自动对账, 复发即再封, 无需人工反复操作;
# 备份/隔离区仅供管理员回滚(名单解除后自动原样恢复)。只封签名策略 deny.* 名单
# (发布=人工审批), 且受 modules.skill_enforce/mcp_enforce 门控(缺省关=只报不封)。
# ── 执行级封禁(真封禁): 终止在跑进程 + icacls exec-deny + 防火墙出站 block ──────
# 弥补"移除配置"管不住已运行/已连接实例。只针对 deny 名单; 进程匹配用精确可执行路径
# (Get-Process.Path 全等), 绝不模糊匹配。防火墙规则命名 aegis-deny-<name> 便于解封移除。
function Get-AegisMcpSpec {
  param($BakPath, $Name)
  $bak = $null
  try { $bak = Get-Content -LiteralPath $BakPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
  if (-not $bak) { return $null }
  foreach ($k in @('mcpServers', 'servers', 'mcp_servers')) {
    $v = $bak.$k
    if ($v -and $v.PSObject.Properties[$Name]) {
      $cfg = $v.$Name
      return @{ command = [string]$cfg.command; url = [string]$cfg.url }
    }
  }
  return $null
}
function Invoke-AegisHardBlock {
  param($Name, $Spec)
  $out = @()
  if (-not $Spec) { return $out }
  $cmd = [string]$Spec.command
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $bin = $null
  if ($cmd) {
    if (Test-Path -LiteralPath $cmd) { $bin = (Resolve-Path -LiteralPath $cmd).Path }
    else { $w = Get-Command $cmd -ErrorAction SilentlyContinue; if ($w) { $bin = $w.Source } }
  }
  if ($bin) {
    Get-Process | Where-Object { $_.Path -eq $bin } | ForEach-Object {
      try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; $out += @{ asset_type = 'mcp'; asset_key = $Name; action = 'process_killed'; target = $bin; reason = 'policy_deny'; ok = $true; at = $ts; pid = $_.Id } } catch { }
    }
    try {
      & icacls $bin /deny "*S-1-1-0:(RX)" 2>&1 | Out-Null
      $out += @{ asset_type = 'mcp'; asset_key = $Name; action = 'exec_denied'; target = $bin; reason = 'policy_deny'; ok = $true; at = $ts }
    } catch { }
  }
  $url = [string]$Spec.url
  if ($url) {
    try {
      $u = [Uri]$url; $h = $u.Host
      $rule = "aegis-deny-$Name"
      Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -RemoteAddress $h -ErrorAction Stop | Out-Null
      $out += @{ asset_type = 'mcp'; asset_key = $Name; action = 'net_blocked'; target = $h; reason = 'policy_deny'; ok = $true; at = $ts }
    } catch { }
  }
  return $out
}
function Invoke-AegisHardUnblock {
  param($Name, $Spec)
  $out = @()
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $cmd = if ($Spec) { [string]$Spec.command } else { '' }
  $bin = $null
  if ($cmd) {
    if (Test-Path -LiteralPath $cmd) { $bin = (Resolve-Path -LiteralPath $cmd).Path }
    else { $w = Get-Command $cmd -ErrorAction SilentlyContinue; if ($w) { $bin = $w.Source } }
  }
  if ($bin) {
    try { & icacls $bin /remove:d "*S-1-1-0" 2>&1 | Out-Null; $out += @{ asset_type = 'mcp'; asset_key = $Name; action = 'exec_restored'; target = $bin; reason = 'policy_no_longer_denies'; ok = $true; at = $ts } } catch { }
  }
  try {
    $r = Remove-NetFirewallRule -DisplayName "aegis-deny-$Name" -ErrorAction SilentlyContinue
    if ($r) { $out += @{ asset_type = 'mcp'; asset_key = $Name; action = 'net_unblocked'; target = "aegis-deny-$Name"; reason = 'policy_no_longer_denies'; ok = $true; at = $ts } }
  } catch { }
  return $out
}
function Invoke-AegisEnforce {
  param($Policy)
  $actions = @()
  # 封禁豁免(签名策略一等字段): 开发主机等豁免设备不执行任何封禁, 只报不封。
  $exempt = @($Policy.enforce_exempt | Where-Object { $_ })
  if ($exempt -contains $deviceId) { return $actions }
  $mods = if ($Policy -and $Policy.modules) { $Policy.modules } else { $null }
  $deny = if ($Policy -and $Policy.deny) { $Policy.deny } else { $null }
  $denySkills = @(); $denyMcp = @()
  if ($deny) { $denySkills = @($deny.skills | Where-Object { $_ }); $denyMcp = @($deny.mcp | Where-Object { $_ }) }
  $enSkill = [bool]($mods.skill_enforce); $enMcp = [bool]($mods.mcp_enforce)
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $skillRoots = @('.codex\skills', '.claude\skills', '.cursor\skills', '.gemini\skills', '.copilot\skills', '.workbuddy\skills', '.qwenworkcn\skills', '.lingma\skills', '.codebuddy\skills')
  # 封禁/恢复必须覆盖**所有受管用户主目录**(与发现侧 managed homes 一致)。此前只看 $env:USERPROFILE
  # (=服务账户 systemprofile), 真实用户 home 里的 skill 永远封不到 → Windows deny 实际空转(真机演练发现)。
  foreach ($homeDir in @($userHomes)) {
    $qroot = Join-Path $homeDir.FullName '.aegis-quarantine'
    if ($enSkill -and $denySkills.Count) {
      foreach ($rel in $skillRoots) {
        $d = Join-Path $homeDir.FullName $rel
        if (-not (Test-Path -LiteralPath $d)) { continue }
        Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue | Where-Object { $denySkills -contains $_.Name } | ForEach-Object {
          $src = $_.FullName
          # dest 带源路径哈希后缀: 多 home 同名 skill 否则 dest 碰撞, 第二个静默跳过=封禁不完整。
          $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($src))
          $tag = ((($h | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 8))
          $dest = Join-Path $qroot ("{0}-{1}-{2}" -f $ts, $_.Name, $tag)
          if (Test-Path -LiteralPath $dest) { return }
          try {
            New-Item -ItemType Directory -Force -Path $qroot | Out-Null
            Move-Item -LiteralPath $src -Destination $dest -Force
            $mf = $dest + '.aegis-quarantine.json'
            (@{ schema = 'aegis.quarantine/v1'; asset_type = 'skill'; asset_key = $_.Name; source = $src; dest = $dest; reason = 'policy_deny'; at = $ts; agent_version = $agentVersion } | ConvertTo-Json -Compress) | Set-Content -LiteralPath $mf -Encoding UTF8
            $actions += @{ asset_type = 'skill'; asset_key = $_.Name; action = 'quarantined'; target = $src; backup = $dest; reason = 'policy_deny'; ok = $true; at = $ts }
          } catch { }
        }
      }
    }
    if (Test-Path -LiteralPath $qroot) {
      Get-ChildItem -LiteralPath $qroot -File -Filter '*.aegis-quarantine.json' -ErrorAction SilentlyContinue | ForEach-Object {
        $m = $null
        try { $m = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
        if (-not $m -or $m.schema -ne 'aegis.quarantine/v1' -or $m.asset_type -ne 'skill') { return }
        $key = [string]$m.asset_key
        $still = $enSkill -and ($denySkills -contains $key)
        if (-not $still) {
          $dest = [string]$m.dest; $src = [string]$m.source
          if ((Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath $src)) {
            try {
              New-Item -ItemType Directory -Force -Path (Split-Path -Parent $src) | Out-Null
              Move-Item -LiteralPath $dest -Destination $src -Force
              Remove-Item -LiteralPath $_.FullName -Force
              $actions += @{ asset_type = 'skill'; asset_key = $key; action = 'restored'; target = $src; backup = $dest; reason = 'policy_no_longer_denies'; ok = $true; at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
            } catch { }
          }
        }
      }
    }
  }
  $cfgRels = @('.cursor\mcp.json', '.claude.json', '.gemini\settings.json', '.copilot\mcp-config.json', '.workbuddy\mcp.json', '.qwenworkcn\mcp.json', '.lingma\mcp.json', '.codebuddy\mcp.json')
  # MCP 封禁/恢复同样必须覆盖所有受管用户主目录(与发现侧一致)。此前只看 $env:USERPROFILE
  # (=服务账户 systemprofile), 真实用户 home 的 MCP 配置永远封不到 → Windows MCP deny 空转(与 skill 同源 bug)。
  foreach ($homeDir in @($userHomes)) {
  foreach ($rel in $cfgRels) {
    $p = Join-Path $homeDir.FullName $rel
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $data = $null
    try { $data = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
    if (-not $data) { continue }
    $holder = $null
    foreach ($k in @('mcpServers', 'servers', 'mcp_servers')) {
      $v = $data.$k
      if ($v) { foreach ($nm in $denyMcp) { if ($v.PSObject.Properties[$nm]) { $holder = $k; break } } }
      if ($holder) { break }
    }
    $bak = $p + '.aegis-bak'
    if ($enMcp -and $holder -and $denyMcp.Count) {
      if (-not (Test-Path -LiteralPath $bak)) { try { Copy-Item -LiteralPath $p -Destination $bak -Force } catch { continue } }
      foreach ($nm in $denyMcp) {
        if ($data.$holder.PSObject.Properties[$nm]) {
          $data.$holder.PSObject.Properties.Remove($nm)
          $actions += @{ asset_type = 'mcp'; asset_key = $nm; action = 'config_removed'; target = $p; backup = $bak; reason = 'policy_deny'; ok = $true; at = $ts }
          $actions += @(Invoke-AegisHardBlock -Name $nm -Spec (Get-AegisMcpSpec -BakPath $bak -Name $nm))
        }
      }
      try { ($data | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $p -Encoding UTF8 } catch { }
    }
    if (Test-Path -LiteralPath $bak) {
      $bakdata = $null
      try { $bakdata = Get-Content -LiteralPath $bak -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
      if ($bakdata) {
        $changed = $false
        foreach ($k in @('mcpServers', 'servers', 'mcp_servers')) {
          $bv = $bakdata.$k
          if (-not $bv) { continue }
          foreach ($prop in @($bv.PSObject.Properties)) {
            $nm = $prop.Name
            if ($enMcp -and ($denyMcp -contains $nm)) { continue }
            $curHas = $false
            foreach ($ck in @('mcpServers', 'servers', 'mcp_servers')) { if ($data.$ck -and $data.$ck.PSObject.Properties[$nm]) { $curHas = $true; break } }
            if (-not $curHas) {
              if (-not $data.$k) { $data | Add-Member -NotePropertyName $k -NotePropertyValue ([pscustomobject]@{}) -Force }
              $data.$k | Add-Member -NotePropertyName $nm -NotePropertyValue $prop.Value -Force
              $changed = $true
              $actions += @{ asset_type = 'mcp'; asset_key = $nm; action = 'config_restored'; target = $p; backup = $bak; reason = 'policy_no_longer_denies'; ok = $true; at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
              $actions += @(Invoke-AegisHardUnblock -Name $nm -Spec (Get-AegisMcpSpec -BakPath $bak -Name $nm))
            }
          }
        }
        if ($changed) { try { ($data | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $p -Encoding UTF8 } catch { } }
      }
    }
  }
  }
  return $actions
}
$enforceActions = @(Invoke-AegisEnforce -Policy $policy)
$report = @{ schema='aegis.report/v1'; agent_version=$agentVersion; policy_version=$policyVersion; device_id=$deviceId; hostname=$env:COMPUTERNAME; os='windows'; os_user=$osUser; owner=$owner; serial=([string]$sn); network=$networkInfo; enforcement=$enforceActions; run_mode='system'; capabilities=@{ pf=$true; es=$false }; scanned_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); scan_root='managed-windows-roots'; inventory=$inventory; findings=$findings; summary=@{ critical=@($findings|Where-Object severity -eq critical).Count; high=@($findings|Where-Object severity -eq high).Count; medium=@($findings|Where-Object severity -eq medium).Count; low=@($findings|Where-Object severity -eq low).Count } }
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$reportJson=$report|ConvertTo-Json -Depth 8 -Compress
$outputTemp=$Output+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
try{$reportJson|Set-Content -Encoding UTF8 $outputTemp;Move-Item $outputTemp $Output -Force}finally{Remove-Item $outputTemp -Force -ErrorAction SilentlyContinue}
if($ReportUrl){
  $spool=Join-Path $installDir 'spool';New-Item -ItemType Directory -Force -Path $spool|Out-Null
  try{
    foreach($queued in @(Get-ChildItem $spool -Filter '*.json' -File|Sort-Object Name|Select-Object -First 5)){
      try{$queuedJson=Get-Content -Encoding UTF8 $queued.FullName -Raw;$null=$queuedJson|ConvertFrom-Json}catch{Move-Item $queued.FullName ($queued.FullName+'.'+[Guid]::NewGuid().ToString('N')+'.invalid') -Force;continue}
      try{$null=Send-AegisReport $queuedJson $ReportUrl;Remove-Item $queued.FullName -Force}catch{break}
    }
    $null=Send-AegisReport $reportJson $ReportUrl;Write-AegisUploadStatus $ReportUrl
  }catch{
    $queue=Join-Path $spool ($report.scanned_at.ToString()+'-'+$report.device_id+'-'+[Guid]::NewGuid().ToString('N')+'.json');$reportJson|Set-Content -Encoding UTF8 $queue
    Get-ChildItem $spool -Filter '*.json' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 500|Remove-Item -Force
    Get-ChildItem $spool -Filter '*.invalid' -File|Sort-Object LastWriteTimeUtc -Descending|Select-Object -Skip 20|Remove-Item -Force
    Write-Warning ('Report upload failed and was queued locally. reason: ' + $_.Exception.Message)
  }
}
if ($report.summary.critical -gt 0 -or $report.summary.high -gt 0) { exit 2 }
exit 0
