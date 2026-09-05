# Sentinel 企业部署指南

私有站点当前提供经验证的发行物下载、架构说明和治理界面样例，但尚未连接客户报告接收器或 Intune/EDR/联软任务 API。页面以“演示模式”明确标识所有样例指标，任何按钮都不会声称已执行外部变更。只有完成企业私有 API、身份认证、授权与审计接入后，才能将其作为实时运营控制台启用。

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

接收器 0.10 在不阻断滚动升级报告上传的前提下，将每台设备最新报告按版本态分类为 `current`、`agent_mismatch`、`policy_mismatch`、`both_mismatch` 或 `unknown`。`GET /v1/summary` 同时返回要求的 Agent/策略版本和 `version_posture`；默认要求 Agent 0.25.0、策略 4.8.0，可通过 `SENTINEL_REQUIRED_AGENT_VERSION` 与 `SENTINEL_REQUIRED_POLICY_VERSION` 调整。数据库升级会原位增加版本列，不删除历史报告。

使用 `python3 sentinel_collector_backup.py --db /var/lib/sentinel/sentinel.db --output /受保护备份目录 --keep 14` 执行 SQLite 在线一致性备份。工具通过 SQLite Backup API 读取运行中的 WAL 数据库，在同一目标目录原子落盘，执行 `PRAGMA quick_check` 后才发布文件，并将权限收敛为 0600；只轮换自身命名的备份，保留数量限制为 1–365。应由企业备份平台加密、异地复制并定期演练恢复，且备份目录不得由 Web 服务公开。

恢复演练使用 `python3 sentinel_collector_restore.py --backup <备份.sqlite> --output <全新候选数据库>`。工具先检查备份，再通过 SQLite Backup API 原子生成 0600 权限的候选库并复检；若目标已存在会直接拒绝，永不覆盖运行库。验证 `/health`、设备数量和最新风险摘要后，应停止接收器并通过变更审批手工切换 `--db` 路径，保留原库以便反向回退。

接收器 0.7 将报告接受/重复提交及已认证的设备、摘要、审计读取写入结构化 `audit_events`，`GET /v1/audit` 返回最近最多 200 条且同样受 Bearer 认证与限流保护。审计只保存事件名、时间、设备标识、报告短哈希和风险级别，不保存令牌、签名、报告正文或终端路径。默认保留 90 天和最多 100000 条，可通过 `SENTINEL_AUDIT_RETENTION_DAYS`（1–3650）及 `SENTINEL_AUDIT_MAX_EVENTS`（1000–1000000）调整；备份与恢复工具会连同审计表保持一致。

接收器支持无中断凭据轮换：`SENTINEL_COLLECTOR_TOKENS='["新 Token","旧 Token"]'` 与 `SENTINEL_REPORT_SIGNING_SECRETS='["新 HMAC 密钥","旧 HMAC 密钥"]'` 各最多接受 5 个非空值，并兼容原有单值变量。先在服务端加入新旧值，再分批更新 Intune 受保护配置，确认旧版本不再活跃后移除旧值；数组 JSON 无效、为空、超过上限或含非字符串时会安全拒绝，而不会退回旧单值。密钥不得写入脚本、策略、日志、审计表或发布包。

接收器 0.8 默认要求配置单值或轮换数组形式的 HMAC 报告签名密钥；没有有效密钥时服务拒绝启动，运行期未签名或签名无效的报告返回 401。仅隔离试点可显式设置 `SENTINEL_ALLOW_UNSIGNED_REPORTS=true`，该开关不得用于生产，也不会绕过 Bearer 认证、大小限制或 Schema 校验。上线检查应确认兼容开关为空，并用错误签名探针验证 401。

接收器 0.9 在监听端口前校验运行密钥：每个 Bearer Token 和 HMAC 密钥至少 32 个字符，同一用途内不得重复，认证 Token 与签名密钥不得复用。任一条件不满足时进程以明确的非敏感错误类别退出，不在错误信息中打印秘密。建议由企业密码系统生成至少 32 字节随机值，并通过服务环境或密钥管理器注入。

使用 `sentinel-adapters.example.json` 创建不含凭据的配置副本，并用 `sentinel_adapter.py <报告> --config <配置> --dry-run` 检查事件映射。适配器默认关闭；只允许 HTTPS 且目标主机名必须精确列入顶层 `allowed_hosts`，URL 中不得携带凭据。深信服动作仅允许 `observe`、`alert`、`isolate_pending_approval` 和 `block_pending_approval`；直接隔离、查杀或封禁会被拒绝，必须由现有审批与响应平台执行。确认现网 API 字段后再设置 URL、环境变量令牌并去掉 `--dry-run`。

三个输出通道彼此隔离：某个厂商接口不可用时，其事件以 0600 权限写入 `SENTINEL_ADAPTER_SPOOL`，不阻塞其他通道；网络恢复后运行 `sentinel_adapter.py --config <配置> --spool-dir <目录> --flush-only` 重放。队列默认最多保留 500 个事件，可用 `SENTINEL_ADAPTER_SPOOL_MAX_EVENTS` 设置 10–10000；同秒事件不会覆盖，损坏记录会隔离并最多保留 20 份，不阻塞有效事件。队列不保存令牌，凭据只从环境变量读取。当前包定义的是安全边界与通用 Webhook 契约，深信服和联软的最终路径、鉴权头与字段映射仍需按客户现网产品版本的正式 API 文档完成验收。

适配器 0.6 对顶层配置、目标对象、字段集合、启用标志和动作表执行严格校验。深信服、联软和安全 Webhook 的凭据变量必须分别使用 `SANGFOR_`、`LEAGSOFT_`、`SENTINEL_` 前缀，避免错误配置把 `PATH` 等无关环境变量作为令牌外发。只有整数 2xx 响应会确认投递并删除队列事件；其他返回值与网络错误均保留事件等待重放。

适配器 0.5 在任何通道处理前执行完整 `sentinel.report/v1` 白名单、类型、长度、数量和摘要一致性校验；额外字段不会透传到安全 Webhook。深信服与联软投影也使用精确字段集合验证，离线队列重放前再次验证；被篡改、`null` 或结构异常的载荷进入隔离区而不发网，报告或事件构建失败也不会排队空载荷。

## 联软桌管

将 Windows 脚本或后续签名 MSI 作为软件分发包。使用软件资产规则检查 `%ProgramData%\SentinelAgent\sentinel-policy.json`，未安装或策略过期的设备进入修复组；若启用准入隔离，先以观察模式验证误报率。

## 上线门槛

1. 脚本签名与哈希固定（安装器已校验核心文件 SHA-256）；2. 100 台以内试点；3. 误报复核；4. 回滚与卸载包；5. EDR 动作双人审批；6. 数据保留和脱敏评审。

每次导入 Intune 或桌管前，在解压目录运行 `python3 sentinel_release_verify.py .`。验收器离线检查核心文件 SHA-256、所有安装/检测脚本内嵌哈希、策略版本、Intune `en_US` 修复文案，以及企业 ZIP 中每个文件与发布目录逐字节一致；必须返回 `{"ok":true,"errors":[]}` 才能进入试点。

## 升级、回滚与卸载

Intune 修复脚本先把新版本下载到受限暂存目录，校验扫描器、策略和基线三项 SHA-256 后才替换运行文件；已有完整版本会备份到 `previous`。需要回退时，通过 Intune 以 SYSTEM/root 下发 `rollback-sentinel-windows.ps1` 或 `rollback-sentinel-macos.sh`，脚本会先验证备份清单，再恢复并重启周期任务。回滚只保留最近一个完整版本。

升级脚本只在当前扫描器、策略和基线三件套全部存在时创建回滚点；先在独立的受限目录复制三件套并生成校验清单，再原子切换 `previous`。当前安装残缺时会保留已有完整回滚点，不生成混合版本快照。若回滚点目录切换失败，升级在替换运行文件前终止并恢复旧目录。

所有安装与修复下载均设置 15 秒连接超时和每文件 120 秒总时限；Windows 使用对应的 120 秒请求超时。三个文件最坏网络等待受控在 Intune 脚本执行窗口内，失败后保留当前运行版本并由下一次 MDM 修复周期重试。超时设置不替代 SHA-256 固定：只有三项下载全部完成且哈希匹配才会备份与替换。

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

0.17.0 起，策略 4.5.0 通过 `limits.max_file_bytes` 统一控制 64 KiB–10 MB 的单文件扫描上限，默认 1 MB。代码、Agent 配置或 Skill 文件超过阈值时不再静默跳过，而产生 `oversized_file_skipped` 中危项；Skill 的超大文件仍计入包文件数上限。Windows 端单根目录最多保留 100 条超大文件明细并额外标记截断，防止填充文件放大报告。

0.18.0 起，深度异常或结构损坏的 MCP、依赖 JSON 会转化为 `invalid_mcp_config` / `invalid_dependency_manifest`，不会终止整次扫描。策略中的敏感信息正则若无效，运行时仅上报正则摘要而不回显内容；离线发布验收会直接返回 `invalid_secret_pattern_regex`，阻止错误策略进入试点。

0.19.0 起，Python 与 Windows 扫描器均在报告同目录写入唯一临时文件，完成写入后再原子替换 `latest.json`；Python 端在替换前执行 flush、fsync 并设置 0600，离线 spool 也复用相同写入路径。写入或替换失败会清理临时文件并保留上一份完整报告，避免 Intune 合规读取半份 JSON。

0.20.0 起，Python `--watch` 模式每轮重新读取并验证 `sentinel.policy/v1` 策略，使 MDM 更新无需重启长驻进程即可生效。若新文件缺失、损坏、编码异常或契约错误，本轮继续使用内存中的上一份有效策略并增加 `policy_reload_failed` 高危项；首次启动没有有效策略时直接拒绝运行，避免空策略降级。

0.21.0 起，MCP 命令同时校验 basename 与可执行路径。`node`、`npx` 等裸命令仍按 `allowed_mcp_commands` 审批；任何包含 `/` 或 `\` 的绝对/相对路径默认产生 `unapproved_mcp_command_path` 高危项，只有与策略 4.6.0 `allowed_mcp_command_paths` 精确匹配才放行，防止 `/tmp/node` 等同名伪造二进制绕过。

0.22.0 起，带参数的 MCP 本地命令必须与策略 4.7.0 `allowed_mcp_invocations` 中的完整 argv 精确匹配。允许 `npx`、`uvx`、`docker`、`node` 或 `python3` 的 basename 不再隐含允许任意包、镜像或脚本；参数顺序或任一值变化都会产生 `unapproved_mcp_invocation` 高危项。

0.23.0 起，策略热加载会完整校验对象、列表、正则和 MCP 调用结构；无效更新保持上一份有效策略并报告 `policy_reload_failed`。畸形 MCP Server、`args` 或 `env` 不再被静默忽略或中断扫描，而是产生明确高危发现项。

0.42.0 起，Intune 自定义合规增加 `SentinelReportValid`。发现项严重度会在终端重新计数，且报告必须同时匹配已批准的 Agent 0.23.0、当前策略版本、设备标识格式和报告契约；旧版本或汇总不一致的报告无法再用于证明设备合规。

0.43.0 / Agent 0.24.0 起，Windows 周期任务每次扫描都会重新发现用户后来安装的 Codex 与 Claude Code，并以幂等方式创建或更新用户级安全编码基线。路径或托管标记异常时停止写入并产生高危发现，避免覆盖个人规则或经重解析点写出用户目录。

0.44.0 / Agent 0.25.0 起，Windows 在读取内容前独立发现 `SKILL.md`，因此超大清单不能绕过 `unknown_skill`。每个扫描根最多发现 500 个 Skill、每个 Skill 最多报告 100 个重解析点，项目候选文件遵循策略 `project_files`；任何截断都会生成可见发现项。

配置 `SENTINEL_REPORT_URL` 和 `SENTINEL_REPORT_TOKEN` 后启用上报。生产环境同时在终端和接收器配置相同的 `SENTINEL_REPORT_SIGNING_SECRET`；每次请求使用当前时间戳和原始请求体计算 HMAC-SHA256，接收器只接受五分钟窗口内的有效签名。网络中断时报告会进入权限受限的本地 spool，补传时使用新的请求时间重新签名；同秒报告使用唯一文件名，损坏文件会被隔离，不再阻塞后续补传。Python 端默认最多保留 500 份待传报告（可用 `SENTINEL_SPOOL_MAX_REPORTS` 设置 10–10000），Windows 端固定保留最近 500 份及 20 份损坏样本，超限时优先淘汰最旧文件。上报路径会把用户主目录替换为 `~`，明文密钥证据仅保留脱敏标记。密钥应由 Intune 的受保护配置流程注入，不要写入脚本或仓库。
