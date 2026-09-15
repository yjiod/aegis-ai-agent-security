; ═══════════════════════════════════════════════════════════════════════
; aegis-agent-windows.nsi — Aegis Windows 原生安装器（NSIS → 单文件 .exe）。
; 由 scripts/build-windows-exe.sh 用 makensis 构建；服务器 origin 经 -DSERVER 注入
; （默认 RFC 占位 https://aegis.example.com，真实主机绝不入库）。
;
; 装完即被纳管：内嵌运行时解压到 %ProgramData%\AegisAgent，再以 -Local 调用
; aegis-agent-windows-enroll.ps1 —— 零接触向 <SERVER>/api/enroll 申请令牌+策略，
; DPAPI(LocalMachine) 写 reporting.dpapi，注册 SYSTEM 计划任务，立即首报。
; 需要管理员权限（RequestExecutionLevel admin → UAC 提权）。
;
; 未做代码签名：首次运行会有 SmartScreen 提示（"更多信息 → 仍要运行"）；
; 企业分发应自行 signtool 签名。
; ═══════════════════════════════════════════════════════════════════════
!include "MUI2.nsh"

!ifndef SERVER
  !define SERVER "https://aegis.example.com"
!endif

Name "Aegis Agent"
OutFile "aegis-agent-windows.exe"
RequestExecutionLevel admin
InstallDir "$PROGRAMDATA64\AegisAgent"
SetCompressor /SOLID lzma
ShowInstDetails show

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Section "Aegis Agent (required)"
  SectionIn RO
  SetOutPath "$INSTDIR"
  ; 运行时与入网脚本由 build-windows-exe.sh 保证与本脚本同目录（public/downloads）。
  File "aegis-windows.ps1"
  File "aegis-policy.json"
  File "aegis-security-baseline.md"
  File "aegis-agent-windows-enroll.ps1"

  ; 零接触自动入网（内嵌运行时 → -Local）：申请令牌+策略、DPAPI 写配置、注册计划任务、首报。
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\aegis-agent-windows-enroll.ps1" -Server "${SERVER}" -Local'

  WriteUninstaller "$INSTDIR\uninstall-aegis.exe"
SectionEnd

Section "Uninstall"
  ; 停止并删除计划任务，移除运行时目录（reporting.dpapi 含 DPAPI 密文，一并删除）。
  nsExec::ExecToLog 'schtasks.exe /Delete /TN AegisAgent /F'
  RMDir /r "$INSTDIR"
SectionEnd
