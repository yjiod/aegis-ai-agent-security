param([string]$Output = "$env:ProgramData\SentinelAgent\reports\latest.json")
$ErrorActionPreference = 'SilentlyContinue'
$roots = @("$env:USERPROFILE\.cursor", "$env:USERPROFILE\.codex", "$env:USERPROFILE\.claude")
$patterns = @(
  @{ Kind='hardcoded_secret'; Severity='critical'; Regex='AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}' },
  @{ Kind='prompt_override'; Severity='high'; Regex='(?i)ignore (all |any )?(previous|prior) instructions' },
  @{ Kind='unbounded_shell'; Severity='high'; Regex='(?i)shell\s*=\s*true|Invoke-Expression|\biex\s' }
)
$findings = @(); $inventory = @()
foreach ($root in $roots) {
  if (Test-Path $root) {
    $inventory += @{ type='agent_root'; path=$root }
    Get-ChildItem $root -File -Recurse | Where-Object { $_.Length -lt 1MB } | ForEach-Object {
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
