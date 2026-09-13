$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'public\downloads'
$sandbox = Join-Path $env:RUNNER_TEMP ('sentinel-windows-smoke-' + [Guid]::NewGuid().ToString('N'))
$programData = Join-Path $sandbox 'ProgramData'
$install = Join-Path $programData 'SentinelAgent'
$users = 'C:\Users'
$output = Join-Path $sandbox 'reports\latest.json'
New-Item -ItemType Directory -Force -Path $install | Out-Null
Copy-Item (Join-Path $source 'sentinel-windows.ps1') $install
Copy-Item (Join-Path $source 'sentinel-policy.json') $install
Copy-Item (Join-Path $source 'sentinel-security-baseline.md') $install
$agent = Join-Path $install 'sentinel-windows.ps1'
$previousProgramData = $env:ProgramData
function Invoke-SentinelAgent([switch]$Diagnostics) {
  $stdout = Join-Path $sandbox 'agent.stdout.log'
  $stderr = Join-Path $sandbox 'agent.stderr.log'
  $command = "& '$($agent.Replace("'","''"))' -Output '$($output.Replace("'","''"))' -ManagedUsersRoot '$($users.Replace("'","''"))'"
  if ($Diagnostics) { $command += ' -Diagnostics' }
  $command += '; exit $LASTEXITCODE'
  $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encodedCommand)
  $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $messages = @()
  if (Test-Path $stdout) { $messages += Get-Content $stdout -Raw }
  if (Test-Path $stderr) { $messages += Get-Content $stderr -Raw }
  return @{ ExitCode=$process.ExitCode; Output=($messages -join "`n") }
}
try {
  $env:ProgramData = $programData
  $result = Invoke-SentinelAgent -Diagnostics
  if ($result.ExitCode -ne 0) { Write-Error "clean agent run failed with exit code $($result.ExitCode): $($result.Output)" }
  $report = Get-Content $output -Raw | ConvertFrom-Json
  if ($report.schema -cne 'sentinel.report/v1' -or $report.agent_version -cne '0.46.0' -or $report.policy_version -cne '5.1.0') { throw 'clean report contract mismatch' }
  if ($report.summary.critical -ne 0 -or $report.summary.high -ne 0) { throw 'clean report unexpectedly contains blocking findings' }

  $testHome = Join-Path $users ('sentinel-ci-' + [Guid]::NewGuid().ToString('N'))
  $codex = Join-Path $testHome '.codex'
  New-Item -ItemType Directory -Force -Path $codex | Out-Null
  $instruction = Join-Path $codex 'AGENTS.md'
  Set-Content -Encoding UTF8 $instruction '# Personal rules'
  $instructionAcl = (Get-Acl $instruction).Sddl
  $repo = Join-Path $testHome 'Projects'
  New-Item -ItemType Directory -Force -Path (Join-Path $repo '.git') | Out-Null
  $repoInstruction = Join-Path $repo 'AGENTS.md'
  Set-Content -Encoding UTF8 $repoInstruction '# Repository rules'
  $repoInstructionAcl = (Get-Acl $repoInstruction).Sddl
  Set-Content -Encoding UTF8 (Join-Path $codex 'config.toml') '# Sentinel native discovery marker'
  $secret = 'sk-abcdefghijklmnopqrstuvwxyz123456'
  Set-Content -Encoding UTF8 (Join-Path $codex 'source.py') ('token="' + $secret + '"')
  $result = Invoke-SentinelAgent
  $reportText = if(Test-Path $output){Get-Content $output -Raw}else{'[report missing]'}
  if ($result.ExitCode -ne 2) { Write-Error "secret scan did not block; exit code $($result.ExitCode): $($result.Output); report=$reportText" }
  $report = $reportText | ConvertFrom-Json
  if (@($report.inventory | Where-Object { $_.type -eq 'ai_agent' -and $_.name -eq 'codex' }).Count -ne 1) { throw 'Codex discovery evidence is missing' }
  if (-not (Test-Path (Join-Path $codex 'AGENTS.md')) -or (Get-Content (Join-Path $codex 'AGENTS.md') -Raw) -notmatch 'sentinel-managed-user-baseline:start') { throw "Codex managed baseline was not installed; agent=$($result.Output); inventory=$($report.inventory|ConvertTo-Json -Compress -Depth 5)" }
  if (@($report.inventory | Where-Object { $_.type -eq 'agent_baseline' -and $_.name -eq 'codex' -and $_.status -eq 'managed' }).Count -ne 1) { throw "Codex managed baseline evidence is missing; baseline=$($report.inventory|Where-Object type -eq 'agent_baseline'|ConvertTo-Json -Compress -Depth 5); bytes=$([Convert]::ToBase64String([IO.File]::ReadAllBytes($instruction)))" }
  if ((Get-Acl $instruction).Sddl -cne $instructionAcl) { throw 'Codex instruction ACL changed during managed update' }
  if (@(Get-ChildItem $codex -Force -Filter '.AGENTS.md.*.tmp').Count -ne 0) { throw 'Codex atomic update left a temporary file' }
  if ((Get-Content $repoInstruction -Raw) -notmatch 'sentinel-managed-baseline') { throw 'repository managed baseline was not installed' }
  if ((Get-Acl $repoInstruction).Sddl -cne $repoInstructionAcl) { throw 'repository instruction ACL changed during managed update' }
  if (@(Get-ChildItem $repo -Recurse -Force -Filter '*.tmp').Count -ne 0) { throw 'repository atomic update left a temporary file' }
  if (@($report.findings | Where-Object kind -eq 'hardcoded_secret').Count -ne 1 -or $reportText.Contains($secret)) { throw 'secret finding is missing or not redacted' }

  $policyPath = Join-Path $install 'sentinel-policy.json'
  $policy = Get-Content $policyPath -Raw | ConvertFrom-Json
  $policy.secret_patterns = @('[invalid')
  $policy | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 $policyPath
  $result = Invoke-SentinelAgent
  if ($result.ExitCode -ne 2) { Write-Error "invalid policy did not fail closed; exit code $($result.ExitCode): $($result.Output)" }
  $report = Get-Content $output -Raw | ConvertFrom-Json
  if ($report.policy_version -cne 'invalid' -or @($report.findings | Where-Object kind -eq 'policy_load_failed').Count -ne 1) { throw 'invalid policy finding contract mismatch' }
} finally {
  $env:ProgramData = $previousProgramData
  if ($testHome -and $testHome.StartsWith('C:\Users\sentinel-ci-', [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $testHome -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}
