# Sentinel 企业终端操作手册

适用版本：产品 5.13.0、Endpoint Agent 0.51.0。当前 MSI/PKG 是未完成企业代码签名与 Apple 公证的试点验证包，不得直接晋级生产。

## 1. 责任边界

- MDM、桌管、软件分发或受控人工流程负责 MSI/PKG 的安装、升级、卸载和紧急停用。
- Sentinel 只更新自身策略、基线、规则和 Skill/MCP 情报，不推送或控制其他厂商客户端。
- 统一身份/4A 负责人员身份、审批和审计；终端只消费与设备及动作精确绑定的短时证据。
- 基础安装包不含 Collector Token、HMAC 密钥、人员口令或生产地址凭据。

## 2. 安装与首次注册

Windows 管理员安装：

```text
msiexec /i Sentinel-Agent-Windows-x64-5.13.0.msi /qn /l*v %ProgramData%\SentinelAgent-install.log
```

macOS root 安装：

```text
installer -pkg Sentinel-Agent-macOS-5.13.0.pkg -target /
```

安装后通过受保护企业通道投递目标设备专属的 `sentinel.device-enrollment/v3` JSON。Windows 以管理员调用安装目录中的 `sentinel-enroll-windows.ps1 -EnrollmentPath <文件>`；macOS 调用 `/Library/Application Support/SentinelAgent/sentinel-enroll-macos.sh <文件>`。注册文件必须为短时、单次消费且不得进入 Git、聊天、工单、日志或通用脚本包。成功后文件自动删除；失败时保持原文件，先隔离终端并检查设备 ID、期限、权限和 Collector HTTPS 地址。注册成功会把分配的 `device_id` 写入 DPAPI/root-only `sentinel.reporting/v3`；该不透明身份绑定报告、HMAC 和离线队列，后续主机重命名不得改变它。旧 v1/v2 配置仅作迁移兼容，会触发高风险迁移项，应重新注册。v3 同时下发独立的策略验证密钥环；不得与设备上报 Token 或报告签名密钥复用。

## 3. 健康与验收

- Windows 检查 SCM 服务 `SentinelAIAgentSecurity`、`%ProgramData%\SentinelAgent\service-health.json` 和最新报告；服务应为“正在运行/延迟自动启动”，失败恢复不得配置任意脚本或外部命令。
- macOS 检查 `system/com.yjiod.sentinel-agent`、`/Library/Application Support/SentinelAgent/service-health.json` 和最新报告。
- Windows 的 `Sentinel AI Agent Security User Bridge` 由 Users 组登录触发，macOS 的 `com.yjiod.sentinel-user-session` 在登录及每小时触发。桥接器只接受固定 `--user-session` 模式，以登录用户权限写入自己的基线受管块和私有 `session-attestation.json`；首次安装后已登录用户需重新登录或由终端平台触发一次固定任务。
- 会话证明只包含平台、宿主版本、受支持 Agent 名称和基线计数，不包含用户名、主目录、完整路径、Prompt 或凭据。它仅用于发现/健康提示，系统扫描器必须独立复核受管块，`invalid/degraded` 均不得放行。
- Collector `/health` 必须返回数据库健康；控制台版本、Agent 版本、策略版本和报告凭据代次不得漂移。
- 生产晋级前必须完成 Authenticode、Developer ID/notarization、安装/升级/回滚/卸载真机验证和发行摘要核对。

## 4. Skill/MCP 阻断和恢复

被拒绝 Skill 的入口文件改名为 `SKILL.md.sentinel-disabled`；包含拒绝 MCP 的配置改名为 `.sentinel-disabled`。用户内容不会删除。Windows 审计位于 `%ProgramData%\SentinelAgent\quarantine\audit`，macOS 审计位于安装目录 `quarantine/audit.json`；这些路径只允许 SYSTEM/root 和管理员访问，禁止上传完整路径或内容。

恢复必须由 4A/统一审批流程生成 `sentinel.quarantine-approval/v1` 短时证据，精确绑定隔离事件。Windows 使用 `sentinel-quarantine-restore-windows.ps1`；macOS 使用 `sentinel_quarantine_restore.py`。恢复工具拒绝过期、宽权限、链接、目标冲突或事件不匹配，并在成功后销毁审批文件、追加恢复审计。不要手工改名绕过审计。

## 5. 升级与回滚

- 按 lab → pilot → broad → production 灰度推进，并满足 24/48/72/168 小时观察窗口。
- 二进制仍由外部平台推送；策略和情报更新先经过摘要、签名、Schema、回归及 LKG 门禁。
- 策略密钥轮换遵循“终端先信任新旧密钥 → Collector 切换首密钥 → 覆盖率验收 → 移除旧密钥”；任一步失败都保留旧密钥和 LKG。
- 覆盖率验收以 Collector 的 `policy_trust_posture` 为准：全部活跃设备必须计入 `current`，`legacy` 与 `unrecognized` 必须为 0；`overlap` 表示仍同时信任新旧密钥，不能单独作为移除旧密钥的充分证据。
- 使用 `sentinel_policy_keyring.py --keyring <密钥环> --add` 生成并把新密钥置于首位；工具回执只返回 Key ID。移除旧密钥前，将受保护的最新 `/v1/summary` 保存为 0600 证据，并由统一身份/4A 审批系统生成 `sentinel.policy-key-retirement-approval/v1` 短时审批文件，精确绑定新旧 Key ID，再调用 `--remove-key-id <旧Key ID> --evidence <证据> --approval <审批>`。工具要求证据不超过 15 分钟、全部登记设备在线且信任当前密钥，并拒绝删除当前密钥或最后一个密钥；成功后审批文件自动销毁以防重放。操作后重启 Collector 并再次验证策略签名。
- 升级失败使用随包 `rollback-sentinel-windows.ps1` 或 `rollback-sentinel-macos.sh`，完成健康验证后再扩大范围。
- 不允许跳过签名、关闭 TLS 校验、修改安全策略降级或用全局共享终端凭据替代设备凭据。

## 6. 卸载

Windows：通过“应用和功能”、MDM 卸载分配，或管理员运行：

```text
msiexec /x Sentinel-Agent-Windows-x64-5.13.0.msi /qn /l*v %ProgramData%\SentinelAgent-uninstall.log
```

MSI 会调用受保护清理程序，停止并删除 `SentinelAIAgentSecurity` SCM 服务、删除用户会话桥及旧版计划任务、移除 Sentinel 管理的用户基线块和运行目录。macOS 使用：

```text
sudo '/Library/Application Support/SentinelAgent/uninstall-sentinel-macos.sh'
```

卸载不会删除仓库内安全文件，也不会自动恢复已禁用的 Skill/MCP。隔离审计会迁移到 `SentinelAgent-Uninstall-Evidence`，禁用对象保持原位，待外部审批后恢复。完成后在 Collector 标记设备退役并按企业留存策略处理历史审计；不要复用该设备凭据。

macOS 同时删除全局用户 LaunchAgent 和每用户最小会话证明；Windows 同时注销登录触发任务。卸载不会删除其他应用数据或非 Sentinel 管理的指令内容。

## 7. 故障处置

- Agent 无报告：检查服务宿主、注册配置权限、设备时间、HTTPS、Collector 确认回执和本地 spool。
- 策略更新失败：继续使用 LKG；核对版本单调性、摘要、签名和 Schema，禁止覆盖 LKG。
- 隔离失败：保持 critical 告警，通过终端平台阻断对应 AI Agent，再检查重解析点、ACL、文件占用和同名 `.sentinel-disabled` 冲突。
- Collector/4A 不可用：终端继续执行 LKG，报告和厂商事件进入有界私有队列；恢复后幂等补发。

所有生产变更都应保留变更单、审批关联号、操作者身份摘要、发行摘要、观察窗口证据和回滚结果。
