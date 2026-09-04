param([string]$Output = "$env:ProgramData\SentinelAgent\reports\latest.json")
$ErrorActionPreference = 'SilentlyContinue'
$roots = @("$env:USERPROFILE\.cursor", "$env:USERPROFILE\.codex", "$env:USERPROFILE\.claude")
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$baselinePath = Join-Path $installDir 'sentinel-security-baseline.md'
$managedMarker = '<!-- sentinel-managed-baseline -->'
$patterns = @(
  @{ Kind='hardcoded_secret'; Severity='critical'; Regex='AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}' },
  @{ Kind='prompt_override'; Severity='high'; Regex='(?i)ignore (all |any )?(previous|prior) instructions' },
  @{ Kind='unbounded_shell'; Severity='high'; Regex='(?i)shell\s*=\s*true|Invoke-Expression|\biex\s' }
)
$findings = @(); $inventory = @()
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
foreach($repo in Get-ManagedRepos) { Install-SentinelBaseline $repo; $roots += $repo; $inventory += @{type='managed_repository';path=$repo} }
foreach ($root in $roots) {
  if (Test-Path $root) {
    $inventory += @{ type='agent_root'; path=$root }
    Get-ChildItem $root -File -Recurse | Where-Object { $_.Length -lt 1MB -and $_.FullName -notmatch '\\.git\\|\\node_modules\\|\\dist\\|\\build\\' } | Select-Object -First 5000 | ForEach-Object {
      $text = Get-Content $_.FullName -Raw
      foreach ($rule in $patterns) {
        if ($text -match $rule.Regex) { $findings += @{ kind=$rule.Kind; severity=$rule.Severity; path=$_.FullName; message='Policy match' } }
      }
    }
  }
}
$report = @{ schema='sentinel.report/v1'; agent_version='0.2.0'; device_id=$env:COMPUTERNAME; scanned_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); inventory=$inventory; findings=$findings; summary=@{ critical=@($findings|Where-Object severity -eq critical).Count; high=@($findings|Where-Object severity -eq high).Count } }
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $Output
if ($report.summary.critical -gt 0 -or $report.summary.high -gt 0) { exit 2 }
exit 0
