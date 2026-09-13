$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelAIAgentSecurity'
$installDir = Join-Path $env:ProgramData 'SentinelAgent'
$publishDir = Join-Path $env:RUNNER_TEMP 'sentinel-service-host'
$executable = Join-Path $installDir 'SentinelServiceHost.exe'

dotnet publish deploy/clients/host/SentinelServiceHost.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=None -o $publishDir
if ($LASTEXITCODE -ne 0) { throw 'Windows service host publish failed' }

try {
  New-Item -ItemType Directory -Force -Path $installDir,(Join-Path $installDir 'reports'),(Join-Path $installDir 'spool') | Out-Null
  Copy-Item (Join-Path $publishDir 'SentinelServiceHost.exe') $executable -Force
  foreach ($name in @('sentinel-windows.ps1','sentinel-policy.json','sentinel-security-baseline.md')) {
    Copy-Item (Join-Path 'public/downloads' $name) (Join-Path $installDir $name) -Force
  }
  & sc.exe create $serviceName "binPath= `"$executable`" --service" 'start= delayed-auto' 'obj= LocalSystem' 'DisplayName= Sentinel AI Agent Security CI' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "SCM create failed: $LASTEXITCODE" }
  & sc.exe failure $serviceName 'reset= 86400' 'actions= restart/60000/restart/60000/restart/60000' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "SCM recovery configuration failed: $LASTEXITCODE" }

  Start-Service -Name $serviceName
  (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
  $definition = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
  if (-not $definition -or $definition.State -ne 'Running' -or $definition.StartMode -ne 'Auto' -or $definition.StartName -ne 'LocalSystem') { throw 'SCM service definition mismatch' }
  if ($definition.PathName -ne "`"$executable`" --service") { throw 'SCM service path permits an unexpected command' }

  $healthPath = Join-Path $installDir 'service-health.json'
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  while (-not (Test-Path $healthPath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
  if (-not (Test-Path $healthPath)) { throw 'SCM service did not publish health evidence' }
  $health = Get-Content $healthPath -Raw | ConvertFrom-Json
  $healthNames = @($health.PSObject.Properties.Name | Sort-Object)
  $expectedNames = @('arbitrary_command_enabled','error','host_version','last_scan_exit_code','last_scan_started_at','scanner','schema','service_started_at','state','updated_at')
  if (($healthNames -join ',') -cne ($expectedNames -join ',')) { throw 'Service health field set mismatch' }
  if ($health.schema -cne 'sentinel.service-health/v1' -or $health.host_version -cne '0.3.0' -or $health.scanner -cne 'windows-powershell' -or $health.arbitrary_command_enabled -ne $false) { throw 'Service health contract mismatch' }

  Stop-Service -Name $serviceName -Force
  (Get-Service -Name $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
} finally {
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($service -and $service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
  if ($service) { & sc.exe delete $serviceName | Out-Null }
  if (Test-Path $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }
}
