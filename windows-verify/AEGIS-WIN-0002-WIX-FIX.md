# AEGIS-WIN-0002 — wixl 轨道 E/F/G 修复方案（待 Windows 验证机验证后合并）

> 状态：**已设计、未合并**。wixl(msitools) 产物有三个阻断级缺陷（见 GitHub Issue #2）：
> E 覆盖升级静默删 host exe 且 exit 0；F 卸载必 2762→1603；G `$Component=3` 守卫恒假→全新安装不建服务。
> 本文件给出两套修法（优先 A），以及**必须在 Windows 验证机上跑 `Run-Windows-Verify.ps1` 全矩阵通过后才能合并/出货**。

## 修法 A（优先）：换原生 WiX v3.14 出货
- CI/验证机装 WiX 3.14.1（candle+light）。同一份 `client/AegisAgent.wxs` 已在该轨道端到端验证过（x64+ARM64）。
- 注意 `Codepage="936"` 必须与 `Language="2052"` 配套（否则 light 报 LGHT0311）；wixl 不校验该项，故该缺陷只在原生轨道暴露。
- 出货后跑 `Run-Windows-Verify.ps1 -MsiNew <原生WiX包> -MsiOld <上一代>` 全矩阵。

## 修法 B（留在 wixl）：SetProperty 替代 `$Component` 守卫 + 卸载 CA 落窗
1. **G 修复**：在立即序列加两个 SetProperty，把组件选择结果写进自定义属性，CA 条件改判属性：
   ```xml
   <Property Id="AEGIS_INSTALL_ARM64" Value="0" />
   <Property Id="AEGIS_INSTALL_X64"   Value="0" />
   <SetProperty Id="AEGIS_INSTALL_ARM64" Value="1" After="CostFinalize" Sequence="execute">AEGIS_PROCARCH="ARM64" AND $HostArm64=3</SetProperty>
   <SetProperty Id="AEGIS_INSTALL_X64"   Value="1" After="CostFinalize" Sequence="execute">AEGIS_PROCARCH&lt;&gt;"ARM64" AND $HostX64=3</SetProperty>
   <Custom Action="InstallAegisArm64" After="InstallFiles">NOT Installed AND AEGIS_INSTALL_ARM64="1"</Custom>
   <Custom Action="InstallAegisX64"   After="InstallFiles">NOT Installed AND AEGIS_INSTALL_X64="1"</Custom>
   ```
   ⚠ 若 wixl 对 `SetProperty` 的 `Sequence="execute"` 支持仍异常，退路：CA 条件退回 v0.73.2 形态（只判架构）+ 依赖 `AllowSameVersionUpgrades="yes"` 保证 RemoveExistingProducts 真卸旧（消掉 keyfile 冲突面），并接受升级场景复测。
2. **F 修复**：卸载 CA 改双锚点落进 InstallInitialize..InstallFinalize 窗口：
   ```xml
   <Custom Action="UninstallAegisArm64" After="InstallInitialize" Before="RemoveFiles">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE AND AEGIS_PROCARCH="ARM64"</Custom>
   <Custom Action="UninstallAegisX64"   After="InstallInitialize" Before="RemoveFiles">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE AND AEGIS_PROCARCH&lt;&gt;"ARM64"</Custom>
   ```
   验证：`msiexec /x {码}` 直接退出 0（不再需要假 UPGRADINGPRODUCTCODE 绕过）。
3. **E 防线**：构建后解包读 MSI 数据库 File 表 Version 列确认写入；升级场景装完校验 exe 存在且 FileVersion==期望（harness 已含该探测）。

## 验证门禁（合并/出货前必跑，Windows 验证机）
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-Windows-Verify.ps1 -MsiNew <待出货msi> -MsiOld <上一代msi> -Server https://<控制台> -RepoPs1Dir <仓库 public/downloads>
```
全 PASS 才允许：合并 wxs 改动 → 出 release → 更新一键脚本指向。任一 FAIL：回退 wxs 改动，记录到 Issue #2。

## 隐私红线（Windows 验证机同样适用）
- 验证产物/日志/issue 附件先脱敏真实控制台域名（替换 `https://<CONSOLE_ORIGIN>`）；不带机器名/SID/device_id/DPAPI 密文。
- 公开仓/ GitHub 资产恒为占位域；真实 origin 只在你自己控制台的 served 副本里。
