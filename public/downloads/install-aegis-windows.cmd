@echo off
setlocal EnableExtensions
REM ================================================================
REM  Aegis Agent - Windows first-time installer (double-click)
REM
REM  What it does: auto-requests Administrator, downloads the proven
REM  one-click installer from your console, and runs it. The one-click
REM  lays down files (msiexec /qn), registers + starts the AegisAgent
REM  service as SYSTEM, and performs zero-touch enrollment. Works on
REM  both x64 and ARM64 (the MSI carries both hosts and picks by CPU).
REM
REM  Privacy: the repo copy bakes the RFC2606 placeholder origin and
REM  REFUSES to run. The copy served from your console /push page has
REM  the real origin injected at deploy time (never committed to git).
REM  The guard below uses a substring test (example.com) that the
REM  deploy-time origin injection does NOT rewrite, so it stays correct.
REM
REM  ASCII-only on purpose: cmd.exe on zh-CN (cp936) garbles UTF-8 text.
REM ================================================================

set "SERVER=https://aegis.example.com"

REM --- placeholder guard: refuse the public repo template (no real origin) ---
echo %SERVER%| findstr /I /C:"example.com" /C:".invalid" /C:"localhost" >nul 2>&1
if not errorlevel 1 (
  echo.
  echo ERROR: this copy has no console origin baked in ^(it is the public repo template^).
  echo Download the installer from your console /push page instead, then double-click it.
  echo.
  pause
  exit /b 1
)

REM --- self-elevate to Administrator (relaunch this same .cmd elevated) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "ONECLICK=%TEMP%\aegis-oneclick.ps1"

echo ================================================================
echo   Aegis Agent - first-time install
echo   Console: %SERVER%
echo ================================================================
echo.

echo [1/2] Downloading one-click installer...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri '%SERVER%/downloads/aegis-install-windows-oneclick.ps1' -OutFile '%ONECLICK%' -UseBasicParsing; exit 0 } catch { Write-Host ('DOWNLOAD FAILED: ' + $_.Exception.Message); exit 1 }"
if not exist "%ONECLICK%" (
  echo.
  echo ERROR: could not download the installer. Check the network, then double-click again.
  echo.
  pause
  exit /b 1
)

echo [2/2] Running installer ^(this can take about a minute^)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%ONECLICK%" -Server %SERVER%

echo.
echo ================================================================
echo   Done. Refresh the console - the new device should appear
echo   (serial number + agent version + discovered AI tools).
echo   If a step failed, the messages above say which one and why.
echo ================================================================
echo.
pause
endlocal
