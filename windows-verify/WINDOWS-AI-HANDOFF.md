# WINDOWS-AI-HANDOFF — 给 Windows 侧 AI 的即插即用交接包

> 读这一个文件即可开工。目标：在 Windows 验证机上**验证并修复** Aegis Windows 客户端的
> wixl 轨道缺陷（BUG E/F/G）、跑通 PS5.1 门禁，并把结果回报。所有背景在本包内自包含。

## 0. 你是谁 / 要做什么
- 你是接手 `yjiod/aegis-ai-agent-security`（GitHub fork；**不要碰上游** `yjiod/sentinel-ai-agent-security`）Windows 客户端的 AI。
- 任务优先级：① 跑 `Run-Windows-Verify.ps1` 全矩阵，记录每项 PASS/FAIL；② 按 `AEGIS-WIN-0002-WIX-FIX.md` 修法 A（原生 WiX）或 B（SetProperty）修 `client/AegisAgent.wxs`，**修完必须重跑全矩阵全 PASS 才允许出 release**；③ 把 PS5.1 ParseFile 门禁跑进流程（harness 已含）；④ 结果写进本包 `RESULT.md` 并评论到 GitHub Issue #2。

## 1. 仓库 / 版本 / 环境现状（2026-09-17）
- 仓库：https://github.com/yjiod/aegis-ai-agent-security （main）。最新 release v0.73.9 / Endpoint Agent 0.34.6。
- 控制台（真实 origin，仅私有通道可见）：由维护者持有；公开仓/ GitHub 资产恒为 RFC2606 占位域 `https://aegis.example.com`。验证时用 `-Server https://<维护者给你的控制台>`。
- fleet 现状（3 台全 0.34.6 在线）：Macbook SERIAL-REDACTED-A(MESH-REDACTED)、Mac mini SERIAL-REDACTED-B(USER-REDACTED)、Windows WIN-DEV-REDACTED(Parallels ARM64, MESH-REDACTED, tools=[workbuddy])。
- 验证机画像（此前那台）：Win11 23H2 ARM64、PS 5.1.22621.6133、zh-CN/cp936。**`$env:PROCESSOR_ARCHITECTURE` 报 AMD64 是失真读数**，判架构读 PE 头/WMI（Win32_Processor.Architecture=12）。

## 2. 架构速览
- 终端 = `AegisServiceHost.exe`（.NET, SCM 服务, 每 interval 拉起扫描器）+ `aegis-windows.ps1`（扫描器, PS5.1）+ `Install-Aegis-Windows.ps1`（安装/入网/ACL, 需 SYSTEM）。
- 入网：POST `<console>/api/enroll` → report_token/signing_secret → DPAPI(LocalMachine, entropy=AegisAgent.Reporting.v1) 写 `C:\ProgramData\AegisAgent\reporting.dpapi`。
- 上报：POST `<console>/aegis/v1/reports`（Bearer token + X-Aegis-Device-ID）；**入网≠上清单**，清单靠扫描报告驱动，验收必看 `upload-status.json`。
- 设备身份 = 硬件序列号 sha256 前 12 位（Win32_ComputerSystemProduct.IdentifyingNumber → BIOS SerialNumber 回落）。
- MSI = wixl(msitools) 出货（双架构单包, AEGIS_PROCARCH 条件二选一）；**wixl 有三个阻断缺陷 E/F/G，见下**。

## 3. 缺陷状态表（详情见 GITHUB-ISSUE-2.md / HANDOFF-WINDOWS-MSI.md）
| ID | 症状 | 状态 |
|---|---|---|
| A | 同版本覆盖升级 2753→1603（Version 写死） | 已修（版本注入+AllowSameVersionUpgrades），但衍生 E/F/G |
| B | v0.73.1 侧车与 msi 哈希不符 | 已修（发布后三方复验 gate） |
| C | host_version 硬编码 0.1.0 | 已修（读 InformationalVersion） |
| D | ProgramData tmp 泄漏/诊断不可读 | 部分修（全新装 0 残留；长期待观察） |
| E | 覆盖升级静默删 host exe 且 exit 0 | **待修**（wixl File 表 Version 丢失） |
| F | 卸载必 2762→1603 | **待修**（卸载 CA 落窗问题）；绕过：`msiexec /x {码} UPGRADINGPRODUCTCODE={11111111-2222-3333-4444-555555555555} /qn` |
| G | `$Component=3` 守卫在 wixl 恒假→全新装不建服务 | **待修**；一键脚本用 SYSTEM 补跑绕过 |
| H | 旧版空 DACL 锁配置（连 SYSTEM 拒） | 已修（Install 自愈 takeown+/reset+自检） |
| I | ACL /T 加固锁配置→报告不到→不上清单；exit=2 被映射 healthy 掩盖 | 已修（ACL 修法 + host 健康映射 degraded，v0.73.10 待 Windows 重启服务验证） |
| J | Agent 检测只认固定 C: 路径 | 已修（跨盘多源：ProfileList/各盘 ProgramFiles/注册表 Uninstall/进程名） |

## 4. 验证 harness 用法（提权 PowerShell）
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-Windows-Verify.ps1 `
  -MsiNew <待验证msi> -MsiOld <上一代msi> -Server https://<控制台> -RepoPs1Dir <仓库 public/downloads 目录>
```
覆盖：BOM 门禁、PS5.1 ParseFile 0 错误、MSI 魔数、全新安装、host exe 落盘+FileVersion、SYSTEM 补跑、服务 Running、upload-status accepted、health 状态合理（配置坏时不得 healthy）、同版本重装无 2753、升级 N-1→N 后 exe 仍在（BUG E 探测）、卸载无 2762（BUG F 探测）。任一 FAIL 退出码 1。

## 5. 一键脚本 / 安装包双通道（别破坏）
- 公开仓/ GitHub 副本：占位域 + **以占位域运行直接 exit 2**；服务器 served 副本由部署期注入真实 origin。
- schtasks /TR 只能用**无空格 .cmd 包装器**（PS5.1 会剥内嵌引号；`-Command & 'path'` 也会被打散——两种都实测失败过）。
- Install 脚本必须从其真实目录运行（`$PSScriptRoot` 需含 exe；脚本内有回退但别依赖）。
- 选 python3 要逐个试跑（ARM 机 `command -v python3` 可能返回 bad-CPU 二进制）。
- 中文系统 schtasks /V 字段名是"上次结果"不是 "Last Result"。

## 6. 工作约定（硬）
- 门禁：tsc / oxlint / python unittest(94) / privacy-scan / release-verify 全绿才提交；改 public/downloads 后必须重跑 `python3 public/downloads/aegis_release_build.py`。
- 隐私铁律：仓库/GitHub/issue 附件/日志**不得出现真实控制台域名**（用 `https://<CONSOLE_ORIGIN>`）、机器名、SID、device_id、DPAPI 密文；privacy-scan 会拦注释里的真实域名。
- 只推 fork；不 force-push；发布后跑 `scripts/verify-release-assets.sh <tag>` 三方复验。
- MSI 换 exe 后服务不热加载：需 `Restart-Service AegisAgent`（或重启）。

## 7. 回报格式（写进 RESULT.md 并评论 Issue #2）
```
验证机: <OS/架构/PS版本/locale>
harness 汇总: 逐项 PASS/FAIL 表
修复: <wxs 改动摘要 / 修法A或B>
复跑: 全矩阵 PASS 截图或文本
隐私自检: 附件已脱敏确认
```

## 8. 包内文件
- `Run-Windows-Verify.ps1`（UTF-8 BOM）验证 harness
- `AEGIS-WIN-0002-WIX-FIX.md` E/F/G 修法 A/B + 合并门禁
- `GITHUB-ISSUE-2.md` Issue #2 全文（E/F/G/H/I/J 取证）
- `HANDOFF-WINDOWS-MSI.md` 完整交接（含现场恢复手册 §5.6、发布规程 §5）
- `repo-snapshot/` 关键文件快照（aegis-windows.ps1 / Install ps1 / oneclick×2 / AegisAgent.wxs / build-windows-msi.sh / Program.cs）——开工前先 `git clone` fork 以拿全量
