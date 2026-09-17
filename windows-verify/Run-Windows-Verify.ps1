# Run-Windows-Verify.ps1 — Aegis Windows 出货/安装验证 harness（在 Windows 验证机上跑）
# 用法(提权 PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-Windows-Verify.ps1 `
#       -MsiNew <新msi> -MsiOld <旧一代msi> -Server https://<控制台> [-RepoPs1Dir <含ps1的目录>]
# 输出: 每项 PASS/FAIL + 汇总; 任一阻断项 FAIL 退出码非 0。
# 覆盖: BOM 门禁 / PS5.1 ParseFile 门禁 / MSI 魔数 / 全新安装 / 升级 N-1→N(BUG E 探测) /
#       同版本重装(2753 探测) / 卸载(BUG F 探测) / SYSTEM 补跑 / 服务 / 入网 / upload-status /
#       health state(BUG I 掩盖面: 配置不可读时应 degraded 非 healthy)。
param(
  [string]$MsiNew = '',
  [string]$MsiOld = '',
  [string]$Server = 'https://aegis.example.com',
  [string]$RepoPs1Dir = ''
)
$ErrorActionPreference = 'Continue'
$Server = $Server.TrimEnd('/')
if ($Server -eq 'https://aegis.example.com') { Write-Host '请用 -Server https://<控制台> 运行(隐私: 包内恒占位域)。' -ForegroundColor Red; exit 2 }
$results = @()
function Note([string]$name, [bool]$ok, [string]$detail) {
  $script:results += [pscustomobject]@{ Item = $name; Result = ($(if ($ok) { 'PASS' } else { 'FAIL' })); Detail = $detail }
  Write-Host ("[{0}] {1}  {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail)
}
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($ident)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host '需管理员' -ForegroundColor Red; exit 2 }

# ── Gate 1: BOM(PS5.1 zh-CN 无 BOM 会语法碎, D0) ──
if ($RepoPs1Dir) {
  foreach ($f in (Get-ChildItem $RepoPs1Dir -Filter *.ps1)) {
    $b = [IO.File]::ReadAllBytes($f.FullName)[0..2]
    Note ("BOM " + $f.Name) (($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)) ''
  }
}
# ── Gate 2: PS5.1 ParseFile 解析 0 错误 ──
if ($RepoPs1Dir) {
  foreach ($f in (Get-ChildItem $RepoPs1Dir -Filter *.ps1)) {
    $toks = $null; $errs = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$toks, [ref]$errs) | Out-Null
    Note ("ParseFile " + $f.Name) (@($errs).Count -eq 0) ("errors=" + @($errs).Count)
  }
}
# ── Gate 3: MSI 魔数 + 体积观测 ──
if ($MsiNew) {
  $mb = [IO.File]::ReadAllBytes($MsiNew)[0..7]
  $magic = ($mb -join ',') -eq '208,207,17,224,161,177,26,225'
  Note 'MSI magic' $magic ('size=' + (Get-Item $MsiNew).Length)
}
function Uninstall-Any {
  $prod = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Aegis*' } | Select-Object -First 1
  if (-not $prod) { return 0 }
  $p = Start-Process msiexec.exe -ArgumentList @('/x', $prod.PSChildName, 'UPGRADINGPRODUCTCODE={11111111-2222-3333-4444-555555555555}', '/qn', '/l*v', "$env:TEMP\aegis-un.log") -Wait -PassThru
  return $p.ExitCode
}
function Clean-ProgramData {
  $pd = Join-Path $env:ProgramData 'AegisAgent'
  if (Test-Path $pd) { & takeown.exe /f $pd /r /d Y | Out-Null; & icacls.exe $pd /reset /t /c | Out-Null; Remove-Item $pd -Recurse -Force -ErrorAction SilentlyContinue }
}
function Install-Msi([string]$msi) {
  $p = Start-Process msiexec.exe -ArgumentList @('/i', $msi, ('AEGIS_SERVER_URL=' + $Server), '/qn', '/l*v', "$env:TEMP\aegis-in.log") -Wait -PassThru
  return $p.ExitCode
}
function System-RunInstall {
  $wrap = 'C:\Windows\Temp\AegisVerifyRun.cmd'
  Set-Content -LiteralPath $wrap -Value ('@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\AegisAgent\Install-Aegis-Windows.ps1" -ServerUrl ' + $Server) -Encoding ASCII
  & schtasks.exe /Delete /TN AegisVerify /F 2>$null | Out-Null
  & schtasks.exe /Create /TN AegisVerify /SC ONCE /ST 00:00 /RU SYSTEM /F /TR $wrap 2>$null | Out-Null
  & schtasks.exe /Run /TN AegisVerify 2>$null | Out-Null
  Start-Sleep -Seconds 45
  $q = (& schtasks.exe /Query /TN AegisVerify /V /FO LIST 2>$null) -join "`n"
  $code = -1
  if ($q -match '(?:Last Result|上次结果)[^:]*:\s*(\d+)') { $code = [int]$Matches[1] }
  & schtasks.exe /Delete /TN AegisVerify /F 2>$null | Out-Null
  return $code
}
function Service-State { $s = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'" -ErrorAction SilentlyContinue; if ($s) { return $s.State } else { return 'Absent' } }

# ── 矩阵 1: 全新安装 ──
if ($MsiNew) {
  Uninstall-Any | Out-Null; Clean-ProgramData
  $rc = Install-Msi $MsiNew
  Note '全新安装 msiexec=0' ($rc -eq 0) ("rc=" + $rc)
  $exe = 'C:\Program Files\AegisAgent\AegisServiceHost.exe'
  Note 'host exe 落盘(BUG E 探测)' (Test-Path $exe) ''
  if (Test-Path $exe) { Note 'exe FileVersion 非空' ([bool](Get-Item $exe).VersionInfo.FileVersion) ((Get-Item $exe).VersionInfo.FileVersion) }
  $tc = System-RunInstall
  Note 'SYSTEM 补跑 LastResult=0' ($tc -eq 0) ("code=" + $tc)
  Note '服务 Running' ((Service-State) -eq 'Running') (Service-State)
  Start-Sleep -Seconds 30
  $us = Join-Path $env:ProgramData 'AegisAgent\upload-status.json'
  Note 'upload-status accepted' ((Test-Path $us) -and ((Get-Content -Encoding UTF8 $us -Raw) -match '"accepted"')) ''
  $hp = Join-Path $env:ProgramData 'AegisAgent\service-health.json'
  if (Test-Path $hp) {
    $h = Get-Content -Encoding UTF8 $hp -Raw | ConvertFrom-Json
    $cfgbad = ((Get-Content -Encoding UTF8 (Join-Path $env:ProgramData 'AegisAgent\reports\latest.json') -Raw -ErrorAction SilentlyContinue) -match 'reporting_config_invalid|policy_load_failed')
    Note 'health 状态合理(配置坏时非 healthy)' (-not ($cfgbad -and $h.state -eq 'healthy')) ('state=' + $h.state)
  }
  # ── 矩阵 3: 同版本重装(2753 探测) ──
  $rc2 = Install-Msi $MsiNew
  Note '同版本重装 msiexec=0(无2753)' ($rc2 -eq 0) ("rc=" + $rc2)
  # ── 矩阵 2: 升级 N-1→N(BUG E 探测) ──
  if ($MsiOld) {
    Uninstall-Any | Out-Null; Clean-ProgramData
    Install-Msi $MsiOld | Out-Null
    System-RunInstall | Out-Null
    $rc3 = Install-Msi $MsiNew
    $exeOk = (Test-Path $exe) -and ((Get-Item $exe).Length -gt 1MB)
    Note '升级 N-1→N 后 exe 仍在且>1MB(BUG E)' ($rc3 -eq 0 -and $exeOk) ("rc=" + $rc3)
    System-RunInstall | Out-Null
    Note '升级后服务 Running' ((Service-State) -eq 'Running') (Service-State)
  }
  # ── 矩阵 4: 卸载(BUG F 探测) ──
  $rc4 = Uninstall-Any
  Note '卸载 msiexec=0(无2762)' ($rc4 -eq 0) ("rc=" + $rc4)
}
Write-Host '==== 汇总 ===='
$results | Format-Table -AutoSize
$fail = @($results | Where-Object { $_.Result -eq 'FAIL' })
if ($fail.Count -gt 0) { exit 1 }
exit 0
