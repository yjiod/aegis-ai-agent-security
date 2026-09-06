$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'public\downloads'
$sandbox = Join-Path $env:RUNNER_TEMP ('sentinel-windows-smoke-' + [Guid]::NewGuid().ToString('N'))
$programData = Join-Path $sandbox 'ProgramData'
$install = Join-Path $programData 'SentinelAgent'
$users = Join-Path $sandbox 'Users'
$output = Join-Path $sandbox 'reports\latest.json'
New-Item -ItemType Directory -Force -Path $install,$users | Out-Null
Copy-Item (Join-Path $source 'sentinel-windows.ps1') $install
Copy-Item (Join-Path $source 'sentinel-policy.json') $install
Copy-Item (Join-Path $source 'sentinel-security-baseline.md') $install
$agent = Join-Path $install 'sentinel-windows.ps1'
$previousProgramData = $env:ProgramData
try {
  $env:ProgramData = $programData
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agent -Output $output -ManagedUsersRoot $users
  if ($LASTEXITCODE -ne 0) { throw "clean agent run failed with exit code $LASTEXITCODE" }
  $report = Get-Content $output -Raw | ConvertFrom-Json
  if ($report.schema -cne 'sentinel.report/v1' -or $report.agent_version -cne '0.34.0' -or $report.policy_version -cne '4.9.0') { throw 'clean report contract mismatch' }
  if ($report.summary.critical -ne 0 -or $report.summary.high -ne 0) { throw 'clean report unexpectedly contains blocking findings' }

  $policyPath = Join-Path $install 'sentinel-policy.json'
  $policy = Get-Content $policyPath -Raw | ConvertFrom-Json
  $policy.secret_patterns = @('[invalid')
  $policy | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 $policyPath
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agent -Output $output -ManagedUsersRoot $users
  if ($LASTEXITCODE -ne 2) { throw "invalid policy did not fail closed; exit code $LASTEXITCODE" }
  $report = Get-Content $output -Raw | ConvertFrom-Json
  if ($report.policy_version -cne 'invalid' -or @($report.findings | Where-Object kind -eq 'policy_load_failed').Count -ne 1) { throw 'invalid policy finding contract mismatch' }
} finally {
  $env:ProgramData = $previousProgramData
  Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}
