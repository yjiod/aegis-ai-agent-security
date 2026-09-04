# Sentinel 企业部署指南

## 推荐职责

- Microsoft Intune：Windows/macOS 安装、周期检测、修复与合规状态。
- 深信服 EDR：接收高危事件后执行主机隔离、查杀和取证；接口以客户实际版本的 OpenAPI 为准。
- 联软 UniAccess/LeagView：资产映射、软件统一分发，以及未安装 Sentinel 终端的准入限制。

## Intune Windows

在“设备 > 脚本和修正”创建包，检测脚本使用 `intune-windows-detect.ps1`，修复脚本使用 `intune-windows-remediate.ps1`，使用 64 位 PowerShell 并以 SYSTEM 运行。先分配试点设备组，再逐步扩大范围。

如需把扫描结果纳入设备合规和条件访问，上传 `intune-compliance-discovery.ps1` 与 `intune-compliance-policy.json`，评估 `SentinelInstalled`、`SentinelScanRecent`、`SentinelCriticalFindings` 和 `SentinelHighFindings`。高危项包括被阻断的未知 Skill；先在试点组完善 `allowed_skills` 并确认误报，再绑定条件访问。

## Intune macOS

将 `intune-macos-install.sh` 作为 macOS Shell Script 下发，以 root 运行。脚本需要终端已有 Python 3。正式部署前应将脚本、策略和扫描器放入企业可信软件源并进行代码签名。

## 深信服 EDR

Sentinel 报告使用 `sentinel.report/v1`。由中转服务将 critical/high finding 转换为当前 EDR 版本支持的告警或联动请求。隔离、查杀等动作必须经 EDR 控制台策略授权。不要把管理口令写入终端脚本。

`sentinel_collector.py` 是最小参考接收器，支持令牌认证、报告大小限制、SQLite 留存和设备列表。生产环境应部署在企业反向代理之后，配置 TLS、密钥轮换、审计、限流和备份；终端不得直接访问 EDR 管理面。

使用 `sentinel-adapters.example.json` 创建不含凭据的配置副本，并用 `sentinel_adapter.py <报告> --config <配置> --dry-run` 检查事件映射。适配器默认关闭；深信服隔离动作只生成 `isolate_pending_approval` 建议，不会直接调用隔离。确认现网 API 后再设置 URL、环境变量令牌并去掉 `--dry-run`。

## 联软桌管

将 Windows 脚本或后续签名 MSI 作为软件分发包。使用软件资产规则检查 `%ProgramData%\SentinelAgent\sentinel-policy.json`，未安装或策略过期的设备进入修复组；若启用准入隔离，先以观察模式验证误报率。

## 上线门槛

1. 脚本签名与哈希固定（安装器已校验核心文件 SHA-256）；2. 100 台以内试点；3. 误报复核；4. 回滚与卸载包；5. EDR 动作双人审批；6. 数据保留和脱敏评审。

## 项目级基线加载

对受管代码仓库执行 `sentinel_agent.py <项目目录> --install-baseline`。该命令为 Cursor 创建 Always Project Rule，为 Windsurf 创建项目规则，并以带标记的增量内容接入 `AGENTS.md` 和 `CLAUDE.md`；不会覆盖仓库已有规范。随后使用 `--watch --interval 300` 持续发现新增 Agent 配置、Skill、MCP 和代码风险。

0.6.0 起，扫描器通过只读文件标记识别 Cursor、Codex、Claude Code 与 Windsurf，不启动或执行被发现的 Agent。以管理员或 SYSTEM/root 身份运行时会覆盖受管用户目录；仅存在 Sentinel 写入的项目规则目录不会被误判为已安装 Agent。Windows 报告中的用户目录会替换为 `~`，控制台可根据 `inventory` 中的 `ai_agent` 项统计覆盖率。

0.7.0 起，MCP 最小权限检查同时覆盖 Cursor/Claude/Windsurf 的 JSON 配置和 Codex 的 `config.toml`，并执行策略中已声明的隐藏 Unicode、弱随机令牌与阻断命令规则。敏感环境变量只上报变量名和 `[REDACTED]`，不上传原值。

0.8.0 起，Skill 扫描覆盖 `SKILL.md` 及包内脚本、配置和说明文件，并检查越界符号链接。策略 `allowed_skills` 是企业允许名单；默认空名单配合 `unknown_skill: block`，表示未经审批的第三方 Skill 一律产生高危项。试点前应填入已完成安全评审的 Skill 目录名。

配置 `SENTINEL_REPORT_URL` 和 `SENTINEL_REPORT_TOKEN` 后启用上报。网络中断时报告会进入本地 spool，后续成功连接时按时间顺序补传；上报路径会把用户主目录替换为 `~`，明文密钥证据仅保留脱敏标记。
