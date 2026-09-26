param(
  [Parameter(Mandatory=$true)][string]$BinaryPath,
  [Parameter(Mandatory=$true)][ValidateSet('Arm64','X64')][string]$ExpectedArchitecture,
  [switch]$AllowEmulation,
  [string]$EvidencePath
)
$ErrorActionPreference = 'Stop'
$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$raw = & $binary --selftest
if ($LASTEXITCODE -ne 0) { throw 'client_selftest_exit_failed' }
$result = ($raw -join "`n") | ConvertFrom-Json
if ($result.schema -cne 'aegis.client-selftest/v1' -or $result.ok -ne $true -or $result.health_serialization -ne $true) {
  throw 'client_selftest_contract_failed'
}
if ($result.process_architecture -cne $ExpectedArchitecture) { throw 'client_process_architecture_mismatch' }
$native = $result.os_architecture -ceq $ExpectedArchitecture
if (-not $native -and -not $AllowEmulation) { throw 'native_architecture_required' }
if (-not $result.host_version) { throw 'client_version_missing' }

# Invalid arguments must fail before any installation or scanning can occur.
$process = Start-Process -FilePath $binary -ArgumentList '--selftest','unexpected' -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 64) { throw 'unexpected_argument_not_rejected' }
$process = Start-Process -FilePath $binary -ArgumentList '--not-a-valid-command' -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 64) { throw 'unknown_command_not_rejected' }

$evidence = [ordered]@{
  schema = 'aegis.windows-client-test/v1'
  passed = $true
  os_architecture = $result.os_architecture
  process_architecture = $result.process_architecture
  native_execution = $native
  host_version = $result.host_version
  sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
  health_serialization = $result.health_serialization
  invalid_arguments_rejected = $true
  scope = 'runtime_and_serialization_only'
}
$json = $evidence | ConvertTo-Json -Compress
if ($EvidencePath) { [IO.File]::WriteAllText($EvidencePath, $json, [Text.UTF8Encoding]::new($false)) }
Write-Output $json
