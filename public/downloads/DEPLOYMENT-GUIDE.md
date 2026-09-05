# Sentinel 企业部署指南

## 推荐职责

- Microsoft Intune：Windows/macOS 安装、周期检测、修复与合规状态。
- 深信服 EDR：接收高危事件后执行主机隔离、查杀和取证；接口以客户实际版本的 OpenAPI 为准。
- 联软 UniAccess/LeagView：资产映射、软件统一分发，以及未安装 Sentinel 终端的准入限制。

## Intune Windows

在“设备 > 脚本和修正”创建包，检测脚本使用 `intune-windows-detect.ps1`，修复脚本使用 `intune-windows-remediate.ps1`，使用 64 位 PowerShell 并以 SYSTEM 运行。先分配试点设备组，再逐步扩大范围。

如需把扫描结果纳入设备合规和条件访问，上传 `intune-compliance-discovery.ps1` 与 `intune-compliance-policy.json`。策略同时验证安装状态、三个运行文件的固定哈希、计划任务状态、策略版本、报告时效及 critical/high 风险数；未来时间戳不会被当作新鲜报告。高危项包括被阻断的未知 Skill；先在试点组完善 `allowed_skills` 并确认误报，再绑定条件访问。

## Intune macOS

将 `intune-macos-install.sh` 作为 macOS Shell Script 下发，以 root 运行。脚本需要终端已有 Python 3，并会把实际解析到的 Python 路径写入 LaunchDaemon。正式部署前应将脚本、策略和扫描器放入企业可信软件源并进行代码签名。

macOS 自定义合规上传 `intune-macos-compliance.sh` 与 `intune-macos-compliance-policy.json`，发现脚本使用 Bash、UTF-8 无 BOM，并设置为不使用已登录用户凭据运行，以便读取受 root 保护的运行文件和报告；启用签名检查及隐藏通知。规则验证安装、三项固定哈希、LaunchDaemon、策略版本、24 小时内扫描和 critical/high 数量，并同时包含 Intune 要求的 `en_US` 与中文修复文案。按微软限制，脚本与输出均须小于 1 MB、运行不超过 10 分钟。

## 深信服 EDR

Sentinel 报告使用 `sentinel.report/v1`。由中转服务将 critical/high finding 转换为当前 EDR 版本支持的告警或联动请求。隔离、查杀等动作必须经 EDR 控制台策略授权。不要把管理口令写入终端脚本。

`sentinel_collector.py` 是最小参考接收器，支持令牌认证、可选 HMAC 请求签名、报告大小限制、SQLite 留存和设备列表。生产环境应部署在企业反向代理之后，配置 TLS、密钥轮换、审计、限流和备份；终端不得直接访问 EDR 管理面。

接收器默认保留 30 天报告，可通过 `SENTINEL_RETENTION_DAYS` 设置 1–3650 天。SQLite 启用 WAL 和五秒忙等待；写入时清理过期数据。同一报告按规范化 JSON 内容去重，不会因空格或字段顺序不同而重复计数。服务端与公开 Schema 同时限制 2 MB 请求、5000 个资产项、10000 个发现项及各字符串字段长度。`/health` 会实际检查数据库，数据库不可用或繁忙超时返回 503，而格式错误仍返回明确的 400，便于监控区分客户端与服务端故障。

接收器 0.5 增加线程安全的每来源滑动窗口限流，默认每分钟 120 次，可通过 `SENTINEL_REQUESTS_PER_MINUTE` 设置 1–10000；超限返回 429 和 `Retry-After`，健康检查不计入额度。内存中的来源表最多保留 10000 项，防止来源标识耗尽内存。该机制只使用直接连接地址，不信任可伪造的转发头；生产反向代理仍应执行公网限流，并按代理后的汇聚连接数调整应用层额度。

接收器 0.6 提供受 Bearer 认证和应用层限流保护的 `GET /v1/summary`，按每台设备最新一份已接受报告聚合设备总数、24 小时活跃/过期数量及 critical/high/normal 最新态。接口不返回报告正文或终端路径，可供内部监控采集；时间窗口固定有界，避免历史报告重复放大风险计数。

使用 `python3 sentinel_collector_backup.py --db /var/lib/sentinel/sentinel.db --output /受保护备份目录 --keep 14` 执行 SQLite 在线一致性备份。工具通过 SQLite Backup API 读取运行中的 WAL 数据库，在同一目标目录原子落盘，执行 `PRAGMA quick_check` 后才发布文件，并将权限收敛为 0600；只轮换自身命名的备份，保留数量限制为 1–365。应由企业备份平台加密、异地复制并定期演练恢复，且备份目录不得由 Web 服务公开。

使用 `sentinel-adapters.example.json` 创建不含凭据的配置副本，并用 `sentinel_adapter.py <报告> --config <配置> --dry-run` 检查事件映射。适配器默认关闭；只允许 HTTPS 且目标主机名必须精确列入顶层 `allowed_hosts`，URL 中不得携带凭据。深信服动作仅允许 `observe`、`alert`、`isolate_pending_approval` 和 `block_pending_approval`；直接隔离、查杀或封禁会被拒绝，必须由现有审批与响应平台执行。确认现网 API 字段后再设置 URL、环境变量令牌并去掉 `--dry-run`。

三个输出通道彼此隔离：某个厂商接口不可用时，其事件以 0600 权限写入 `SENTINEL_ADAPTER_SPOOL`，不阻塞其他通道；网络恢复后运行 `sentinel_adapter.py --config <配置> --spool-dir <目录> --flush-only` 重放。队列默认最多保留 500 个事件，可用 `SENTINEL_ADAPTER_SPOOL_MAX_EVENTS` 设置 10–10000；同秒事件不会覆盖，损坏记录会隔离并最多保留 20 份，不阻塞有效事件。队列不保存令牌，凭据只从环境变量读取。当前包定义的是安全边界与通用 Webhook 契约，深信服和联软的最终路径、鉴权头与字段映射仍需按客户现网产品版本的正式 API 文档完成验收。

## 联软桌管

将 Windows 脚本或后续签名 MSI 作为软件分发包。使用软件资产规则检查 `%ProgramData%\SentinelAgent\sentinel-policy.json`，未安装或策略过期的设备进入修复组；若启用准入隔离，先以观察模式验证误报率。

## 上线门槛

1. 脚本签名与哈希固定（安装器已校验核心文件 SHA-256）；2. 100 台以内试点；3. 误报复核；4. 回滚与卸载包；5. EDR 动作双人审批；6. 数据保留和脱敏评审。

每次导入 Intune 或桌管前，在解压目录运行 `python3 sentinel_release_verify.py .`。验收器离线检查核心文件 SHA-256、所有安装/检测脚本内嵌哈希、策略版本、Intune `en_US` 修复文案，以及企业 ZIP 中每个文件与发布目录逐字节一致；必须返回 `{"ok":true,"errors":[]}` 才能进入试点。

## 升级、回滚与卸载

Intune 修复脚本先把新版本下载到受限暂存目录，校验扫描器、策略和基线三项 SHA-256 后才替换运行文件；已有完整版本会备份到 `previous`。需要回退时，通过 Intune 以 SYSTEM/root 下发 `rollback-sentinel-windows.ps1` 或 `rollback-sentinel-macos.sh`，脚本会先验证备份清单，再恢复并重启周期任务。回滚只保留最近一个完整版本。

卸载使用 `uninstall-sentinel-windows.ps1` 或 `uninstall-sentinel-macos.sh`。卸载会移除运行时、周期任务以及 Codex/Claude 用户指令文件中带 Sentinel 起止标记的受管区块，保留用户自定义内容；符号链接或重解析点不会被修改。已进入源码管理的仓库基线文件仍会保留，必须通过正常代码评审移除，避免绕过审计。

## 项目级基线加载

对受管代码仓库执行 `sentinel_agent.py <项目目录> --install-baseline`。该命令为 Cursor 创建 Always Project Rule，为 Windsurf 创建项目规则，并以带标记的增量内容接入 `AGENTS.md` 和 `CLAUDE.md`；不会覆盖仓库已有规范。`--auto-enroll` 还会仅针对已存在 `.codex` 或 `.claude` 安装标记的用户，将受管区块增量写入用户级 `AGENTS.md`/`CLAUDE.md`；区块可随基线升级原位更新，不会为未安装工具创建目录。所有写入在执行前都会解析父目录真实路径，并拒绝越出仓库/用户根目录的符号链接或 Windows 重解析点。随后使用 `--watch --interval 300` 持续发现新增 Agent 配置、Skill、MCP 和代码风险。

0.6.0 起，扫描器通过只读文件标记识别 Cursor、Codex、Claude Code 与 Windsurf，不启动或执行被发现的 Agent。以管理员或 SYSTEM/root 身份运行时会覆盖受管用户目录；仅存在 Sentinel 写入的项目规则目录不会被误判为已安装 Agent。Windows 报告中的用户目录会替换为 `~`，控制台可根据 `inventory` 中的 `ai_agent` 项统计覆盖率。

0.7.0 起，MCP 最小权限检查同时覆盖 Cursor/Claude/Windsurf 的 JSON 配置和 Codex 的 `config.toml`，并执行策略中已声明的隐藏 Unicode、弱随机令牌与阻断命令规则。敏感环境变量只上报变量名和 `[REDACTED]`，不上传原值。

0.8.0 起，Skill 扫描覆盖 `SKILL.md` 及包内脚本、配置和说明文件，并检查越界符号链接。策略 `allowed_skills` 是企业允许名单；默认空名单配合 `unknown_skill: block`，表示未经审批的第三方 Skill 一律产生高危项。试点前应填入已完成安全评审的 Skill 目录名。

0.9.0 起，代码质量扫描会解析 npm `package.json` 与 Python `requirements*.txt`，识别浮动版本、直接远程源码和缺失锁文件；依赖清单也会作为资产写入报告。该检查用于供应链基线，不替代企业 SCA/CVE 数据源。

0.10.0 起，MCP 远程连接采用默认拒绝：`allowed_mcp_domains` 为空时不允许任何远程域名。域名按解析后的完整主机名精确匹配，并检查未批准传输、命令与 URL 混用、URL 用户信息及敏感查询参数。远程 MCP 上线前必须显式填写受信域名。

0.12.0 起，Windows 原生扫描器也解析 Codex `.codex/config.toml` 中的 `[mcp_servers.*]` 配置，执行与 JSON MCP 相同的 Server、命令、传输、远程域名、宽泛文件范围和凭据检查；扫描仅读取配置，不启动 MCP Server。

0.15.0 起，Python 端单次项目扫描默认最多检查 10000 个候选文件，并跳过符号链接目录；可通过策略 `limits.project_files` 设置 100–100000。跨平台报告统一限制为最多 5000 个 inventory 和 10000 个 findings，超限时保留明确的 `inventory_truncated` / `findings_truncated` 标记，确保报告仍符合接收契约而不是反复补传失败。

0.16.0 起，跨平台代码质量扫描新增关闭 TLS 证书校验、不安全反序列化、生产调试模式和空异常处理检测；规则由策略 4.4.0 的 `code_rules` 统一发布。

配置 `SENTINEL_REPORT_URL` 和 `SENTINEL_REPORT_TOKEN` 后启用上报。生产环境同时在终端和接收器配置相同的 `SENTINEL_REPORT_SIGNING_SECRET`；每次请求使用当前时间戳和原始请求体计算 HMAC-SHA256，接收器只接受五分钟窗口内的有效签名。网络中断时报告会进入权限受限的本地 spool，补传时使用新的请求时间重新签名；同秒报告使用唯一文件名，损坏文件会被隔离，不再阻塞后续补传。Python 端默认最多保留 500 份待传报告（可用 `SENTINEL_SPOOL_MAX_REPORTS` 设置 10–10000），Windows 端固定保留最近 500 份及 20 份损坏样本，超限时优先淘汰最旧文件。上报路径会把用户主目录替换为 `~`，明文密钥证据仅保留脱敏标记。密钥应由 Intune 的受保护配置流程注入，不要写入脚本或仓库。
