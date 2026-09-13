# Sentinel 企业部署指南

私有站点提供经验证的发行物下载、架构说明和治理界面。配置 Collector 后，顶部摘要和最多 200 台匿名终端姿态可切换为真实只读数据；覆盖分布、风险事件以及外部平台任务仍明确标识为样例或未接入，任何按钮都不会声称已执行外部变更。完成对应企业 API、身份认证、授权与审计接入前，不得把样例面板用于运营判断。

0.48.0 起，站点提供只读同源 `/api/summary` 代理。服务端配置 `SENTINEL_COLLECTOR_URL`、精确主机名 `SENTINEL_COLLECTOR_ALLOWED_HOST` 和至少 32 字符的 `SENTINEL_COLLECTOR_TOKEN` 后，顶部四项指标读取接收器摘要；令牌不会进入浏览器。代理只允许 HTTPS、拒绝 URL 凭据/查询参数、五秒超时、禁用缓存并严格复核汇总计数。未配置、上游异常或契约不符时自动回到明确标识的演示模式。

0.49.0 起，摘要代理以流式读取执行 64 KiB 硬上限，包括没有 `Content-Length` 的分块响应；超过限制会立即取消上游读取。响应必须是严格 UTF-8，只有控制台需要的计数和版本字段会被重新构造并返回，获准主机附加的未知字段不会透传。所有成功及错误响应均设置 `Cache-Control: no-store`。

## 推荐职责

- 任意企业终端管理平台：Windows/macOS 安装、周期检测、修复与合规状态；Intune 制品作为可选参考实现保留。
- 企业 4A：标准化设备主体、安全认证、待审批授权建议和审计关联，是默认外部集成边界。
- 可选兼容适配器：深信服 EDR、联软 UniAccess/LeagView 与安全 Webhook，全部默认关闭。

## 企业 4A（默认标准接口）

使用 `sentinel-enterprise-4a.openapi.json` 和 `ENTERPRISE-4A-INTEGRATION.md` 与企业 IAM/4A 团队对接。配置只需精确 HTTPS 主机、租户标识和以 `SENTINEL_4A_` 开头的令牌环境变量。事件不含用户名、代码正文或路径，影响访问的建议始终要求外部审批。Intune、深信服和联软均不是核心运行前置条件。

## Intune Windows

在“设备 > 脚本和修正”创建包，检测脚本使用 `intune-windows-detect.ps1`，修复脚本使用 `intune-windows-remediate.ps1`，使用 64 位 PowerShell 并以 SYSTEM 运行。先分配试点设备组，再逐步扩大范围。

如需把扫描结果纳入设备合规和条件访问，上传 `intune-compliance-discovery.ps1` 与 `intune-compliance-policy.json`。策略同时验证安装状态、三个运行文件的固定哈希、计划任务状态、策略版本、报告时效及 critical/high 风险数；未来时间戳不会被当作新鲜报告。高危项包括被阻断的未知 Skill；先在试点组完善 `allowed_skills` 并确认误报，再绑定条件访问。

## Intune macOS

将 `intune-macos-install.sh` 作为 macOS Shell Script 下发，以 root 运行。脚本需要终端已有 Python 3，并会把实际解析到的 Python 路径写入 LaunchDaemon。正式部署前应将脚本、策略和扫描器放入企业可信软件源并进行代码签名。

macOS 自定义合规上传 `intune-macos-compliance.sh` 与 `intune-macos-compliance-policy.json`，发现脚本使用 Bash、UTF-8 无 BOM，并设置为不使用已登录用户凭据运行，以便读取受 root 保护的运行文件和报告；启用签名检查及隐藏通知。规则验证安装、三项固定哈希、LaunchDaemon、策略版本、24 小时内扫描和 critical/high 数量，并同时包含 Intune 要求的 `en_US` 与中文修复文案。按微软限制，脚本与输出均须小于 1 MB、运行不超过 10 分钟。

## 深信服 EDR

Sentinel 报告使用 `sentinel.report/v1`。由中转服务将 critical/high finding 转换为当前 EDR 版本支持的告警或联动请求。隔离、查杀等动作必须经 EDR 控制台策略授权。不要把管理口令写入终端脚本。

`sentinel_collector.py` 是最小参考接收器，支持令牌认证、可选 HMAC 请求签名、报告大小限制、SQLite 留存和设备列表。生产环境应部署在企业反向代理之后，配置 TLS、密钥轮换、审计、限流和备份；终端不得直接访问 EDR 管理面。

0.51.0 提供可审计的 Linux 生产部署基线：将 `sentinel_collector.py` 放入 `/opt/sentinel/`，创建无登录权限的 `sentinel` 系统用户，把 `sentinel-collector.service` 安装到 `/etc/systemd/system/`；从 `sentinel-collector.env.example` 创建 `/etc/sentinel/collector.env`，分别生成至少 32 字符的认证令牌和 HMAC 密钥，设置 `root:sentinel`、0640 后再启动服务。空密钥会使服务拒绝启动。接收器只监听 `127.0.0.1:8788`，由 `sentinel-collector.nginx.conf` 提供 TLS 1.2/1.3、2 MB 请求上限和外层限流。替换示例域名及证书路径后先执行 `nginx -t` 和 `systemd-analyze security sentinel-collector.service`，再进入试点流量。

生产验收至少包含：`/health` 返回数据库可用；无 Bearer、错误 HMAC、过期时间戳分别返回 401；首份有效报告返回 202、同内容重放返回 200 且标记重复；`/v1/summary` 仅在认证后可读；超过代理或应用限额分别返回 413/429；重启服务后 SQLite 数据仍存在。认证令牌与签名密钥必须独立轮换，不得放入 Intune 脚本文本、Nginx 配置或 Git。

接收器默认保留 30 天报告，可通过 `SENTINEL_RETENTION_DAYS` 设置 1–3650 天。SQLite 启用 WAL 和五秒忙等待；写入时清理过期数据。同一报告按规范化 JSON 内容去重，不会因空格或字段顺序不同而重复计数。服务端与公开 Schema 同时限制 2 MB 请求、5000 个资产项、10000 个发现项及各字符串字段长度。`/health` 会实际检查数据库，数据库不可用或繁忙超时返回 503，而格式错误仍返回明确的 400，便于监控区分客户端与服务端故障。

接收器 0.5 增加线程安全的每来源滑动窗口限流，默认每分钟 120 次，可通过 `SENTINEL_REQUESTS_PER_MINUTE` 设置 1–10000；超限返回 429 和 `Retry-After`，健康检查不计入额度。内存中的来源表最多保留 10000 项，防止来源标识耗尽内存。该机制只使用直接连接地址，不信任可伪造的转发头；生产反向代理仍应执行公网限流，并按代理后的汇聚连接数调整应用层额度。

接收器 0.6 提供受 Bearer 认证和应用层限流保护的 `GET /v1/summary`，按每台设备最新一份已接受报告聚合设备总数、24 小时活跃/过期数量及 critical/high/normal 最新态。接口不返回报告正文或终端路径，可供内部监控采集；时间窗口固定有界，避免历史报告重复放大风险计数。

接收器 0.10 在不阻断滚动升级报告上传的前提下，将每台设备最新报告按版本态分类为 `current`、`agent_mismatch`、`policy_mismatch`、`both_mismatch` 或 `unknown`。`GET /v1/summary` 同时返回要求的 Agent/策略版本和 `version_posture`；接收器 0.19 默认要求 Agent 0.44.0、策略 5.1.0，可通过 `SENTINEL_REQUIRED_AGENT_VERSION` 与 `SENTINEL_REQUIRED_POLICY_VERSION` 调整。数据库升级会原位增加版本列，不删除历史报告。

使用 `python3 sentinel_collector_backup.py --db /var/lib/sentinel/sentinel.db --output /受保护备份目录 --keep 14` 执行 SQLite 在线一致性备份。工具通过 SQLite Backup API 读取运行中的 WAL 数据库，在同一目标目录原子落盘，执行 `PRAGMA quick_check` 后才发布文件，并将权限收敛为 0600；只轮换自身命名的备份，保留数量限制为 1–365。应由企业备份平台加密、异地复制并定期演练恢复，且备份目录不得由 Web 服务公开。

恢复演练使用 `python3 sentinel_collector_restore.py --backup <备份.sqlite> --output <全新候选数据库>`。工具先检查备份，再通过 SQLite Backup API 原子生成 0600 权限的候选库并复检；若目标已存在会直接拒绝，永不覆盖运行库。验证 `/health`、设备数量和最新风险摘要后，应停止接收器并通过变更审批手工切换 `--db` 路径，保留原库以便反向回退。

接收器 0.7 将报告接受/重复提交及已认证的设备、摘要、审计读取写入结构化 `audit_events`，`GET /v1/audit` 返回最近最多 200 条且同样受 Bearer 认证与限流保护。审计只保存事件名、时间、设备标识、报告短哈希和风险级别，不保存令牌、签名、报告正文或终端路径。默认保留 90 天和最多 100000 条，可通过 `SENTINEL_AUDIT_RETENTION_DAYS`（1–3650）及 `SENTINEL_AUDIT_MAX_EVENTS`（1000–1000000）调整；备份与恢复工具会连同审计表保持一致。

接收器支持无中断凭据轮换：`SENTINEL_COLLECTOR_TOKENS='["新 Token","旧 Token"]'` 与 `SENTINEL_REPORT_SIGNING_SECRETS='["新 HMAC 密钥","旧 HMAC 密钥"]'` 各最多接受 5 个非空值，并兼容原有单值变量。先在服务端加入新旧值，再分批更新 Intune 受保护配置，确认旧版本不再活跃后移除旧值；数组 JSON 无效、为空、超过上限或含非字符串时会安全拒绝，而不会退回旧单值。密钥不得写入脚本、策略、日志、审计表或发布包。

接收器 0.8 默认要求配置单值或轮换数组形式的 HMAC 报告签名密钥；没有有效密钥时服务拒绝启动，运行期未签名或签名无效的报告返回 401。仅隔离试点可显式设置 `SENTINEL_ALLOW_UNSIGNED_REPORTS=true`，该开关不得用于生产，也不会绕过 Bearer 认证、大小限制或 Schema 校验。上线检查应确认兼容开关为空，并用错误签名探针验证 401。

接收器 0.9 在监听端口前校验运行密钥：每个 Bearer Token 和 HMAC 密钥至少 32 个字符，同一用途内不得重复，认证 Token 与签名密钥不得复用。任一条件不满足时进程以明确的非敏感错误类别退出，不在错误信息中打印秘密。建议由企业密码系统生成至少 32 字节随机值，并通过服务环境或密钥管理器注入。

使用 `sentinel-adapters.example.json` 创建不含凭据的配置副本，并用 `sentinel_adapter.py <报告> --config <配置> --dry-run` 检查事件映射。适配器默认关闭；只允许 HTTPS 且目标主机名必须精确列入顶层 `allowed_hosts`，URL 中不得携带凭据。深信服动作仅允许 `observe`、`alert`、`isolate_pending_approval` 和 `block_pending_approval`；直接隔离、查杀或封禁会被拒绝，必须由现有审批与响应平台执行。确认现网 API 字段后再设置 URL、环境变量令牌并去掉 `--dry-run`。

三个输出通道彼此隔离：某个厂商接口不可用时，其事件以 0600 权限写入 `SENTINEL_ADAPTER_SPOOL`，不阻塞其他通道；网络恢复后运行 `sentinel_adapter.py --config <配置> --spool-dir <目录> --flush-only` 重放。队列默认最多保留 500 个事件，可用 `SENTINEL_ADAPTER_SPOOL_MAX_EVENTS` 设置 10–10000；同秒事件不会覆盖，损坏记录会隔离并最多保留 20 份，不阻塞有效事件。队列不保存令牌，凭据只从环境变量读取。当前包定义的是安全边界与通用 Webhook 契约，深信服和联软的最终路径、鉴权头与字段映射仍需按客户现网产品版本的正式 API 文档完成验收。

适配器 0.6 对顶层配置、目标对象、字段集合、启用标志和动作表执行严格校验。深信服、联软和安全 Webhook 的凭据变量必须分别使用 `SANGFOR_`、`LEAGSOFT_`、`SENTINEL_` 前缀，避免错误配置把 `PATH` 等无关环境变量作为令牌外发。只有整数 2xx 响应会确认投递并删除队列事件；其他返回值与网络错误均保留事件等待重放。

适配器 0.7 新增自动派发 Worker。将 `sentinel_adapter_worker.py` 与 `sentinel_adapter.py` 放入 `/opt/sentinel/`，从示例生成 `/etc/sentinel/adapters.json` 和 `/etc/sentinel/adapter.env`，仅启用已完成厂商验收的目标，再安装 `sentinel-adapter-worker.service`。Worker 启动时会验证精确 HTTPS 主机、凭据变量和安全动作；配置无启用目标或缺少凭据时拒绝启动。它从 Collector 数据库读取尚未派发的已验证报告，失败投递进入有界 spool，成功接受后写入不含 payload 或设备标识的最小派发账本。每个 HTTP 请求携带基于规范化请求体 SHA-256 的稳定 `Idempotency-Key`；深信服和联软接收端应按该键去重，以覆盖“远端已接收、Worker 在写账本前重启”的边界。

厂商联调顺序为：先使用 `sentinel_adapter.py --dry-run` 让双方确认字段和动作只表示“待审批”，再在隔离测试地址启用 Worker；验证同一报告不会被账本重复发送、网络失败会排队且恢复后补发、非 2xx 不会确认、错误主机和明文 HTTP 会被拒绝。未经厂商确认不得把 `isolate_pending_approval` 映射为自动隔离指令。

适配器 0.5 在任何通道处理前执行完整 `sentinel.report/v1` 白名单、类型、长度、数量和摘要一致性校验；额外字段不会透传到安全 Webhook。深信服与联软投影也使用精确字段集合验证，离线队列重放前再次验证；被篡改、`null` 或结构异常的载荷进入隔离区而不发网，报告或事件构建失败也不会排队空载荷。

## 联软桌管

将 Windows 脚本或后续签名 MSI 作为软件分发包。使用软件资产规则检查 `%ProgramData%\SentinelAgent\sentinel-policy.json`，未安装或策略过期的设备进入修复组；若启用准入隔离，先以观察模式验证误报率。

## 上线门槛

1. 脚本签名与哈希固定（安装器已校验核心文件 SHA-256）；2. 100 台以内试点；3. 误报复核；4. 回滚与卸载包；5. EDR 动作双人审批；6. 数据保留和脱敏评审。

每次导入 Intune 或桌管前，在解压目录运行 `python3 sentinel_release_verify.py .`。验收器离线检查核心文件 SHA-256、所有安装/检测脚本内嵌哈希、策略版本、Intune `en_US` 修复文案，以及企业 ZIP 中每个文件与发布目录逐字节一致；必须返回 `{"ok":true,"errors":[]}` 才能进入试点。

## 升级、回滚与卸载

Intune 修复脚本先把新版本下载到受限暂存目录，校验扫描器、策略和基线三项 SHA-256 后才替换运行文件；已有完整版本会备份到 `previous`。需要回退时，通过 Intune 以 SYSTEM/root 下发 `rollback-sentinel-windows.ps1` 或 `rollback-sentinel-macos.sh`，脚本会先验证备份清单，再恢复并重启周期任务。回滚只保留最近一个完整版本。

升级脚本只在当前扫描器、策略和基线三件套全部存在时创建回滚点；先在独立的受限目录复制三件套并生成校验清单，再原子切换 `previous`。当前安装残缺时会保留已有完整回滚点，不生成混合版本快照。若回滚点目录切换失败，升级在替换运行文件前终止并恢复旧目录。

0.50.0 起，回滚只接受恰好包含扫描器、策略和基线三项的校验清单；漏项或附加路径均拒绝。回滚先停止周期任务，验证快照，恢复后再次验证运行目录，只有二次哈希全部一致才重启任务；复制或落地校验失败时任务保持停止，由 Intune 检测进入修复流程，避免混合版本继续运行。

所有安装与修复下载均设置 15 秒连接超时和每文件 120 秒总时限；Windows 使用对应的 120 秒请求超时。三个文件最坏网络等待受控在 Intune 脚本执行窗口内，失败后保留当前运行版本并由下一次 MDM 修复周期重试。超时设置不替代 SHA-256 固定：只有三项下载全部完成且哈希匹配才会备份与替换。

卸载使用 `uninstall-sentinel-windows.ps1` 或 `uninstall-sentinel-macos.sh`。卸载会移除运行时、周期任务以及 Codex、Claude、Gemini 与 Copilot 用户指令文件中带 Sentinel 起止标记的受管区块，保留用户自定义内容；符号链接或重解析点不会被修改。已进入源码管理的仓库基线文件仍会保留，必须通过正常代码评审移除，避免绕过审计。

## 项目级基线加载

对受管代码仓库执行 `sentinel_agent.py <项目目录> --install-baseline`。该命令为 Cursor 创建 Always Project Rule，为 Windsurf 创建项目规则，并以带标记的增量内容接入 `AGENTS.md`、`CLAUDE.md` 和 `GEMINI.md`；不会覆盖仓库已有规范。`--auto-enroll` 还会仅针对已存在 `.codex`、`.claude`、`.gemini` 或 `.copilot` 安装标记的用户，将受管区块增量写入对应用户级指令文件；区块可随基线升级原位更新，不会为未安装工具创建目录。所有写入在执行前都会解析父目录真实路径，并拒绝越出仓库/用户根目录的符号链接或 Windows 重解析点。随后使用 `--watch --interval 300` 持续发现新增 Agent 配置、Skill、MCP 和代码风险。

扫描器通过只读文件标记识别 Cursor、Codex、Claude Code、Windsurf、Gemini CLI 与 GitHub Copilot CLI，不启动或执行被发现的 Agent。以管理员或 SYSTEM/root 身份运行时会覆盖受管用户目录；仅存在 Sentinel 写入的项目规则目录不会被误判为已安装 Agent。Windows 报告中的用户目录会替换为 `~`，控制台可根据 `inventory` 中的 `ai_agent` 项统计覆盖率。

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

0.44.0 / Agent 0.24.0 起，Windows 周期任务每次扫描都会重新发现用户后来安装的 Codex 与 Claude Code，并以幂等方式创建或更新用户级安全编码基线。路径或托管标记异常时停止写入并产生高危发现，避免覆盖个人规则或经重解析点写出用户目录。

0.44.0 / Agent 0.25.0 起，Windows 在读取内容前独立发现 `SKILL.md`，因此超大清单不能绕过 `unknown_skill`。每个扫描根最多发现 500 个 Skill、每个 Skill 最多报告 100 个重解析点，项目候选文件遵循策略 `project_files`；任何截断都会生成可见发现项。

配置 `SENTINEL_REPORT_URL` 和 `SENTINEL_REPORT_TOKEN` 后启用上报。生产环境同时在终端和接收器配置相同的 `SENTINEL_REPORT_SIGNING_SECRET`；每次请求使用当前时间戳和原始请求体计算 HMAC-SHA256，接收器只接受五分钟窗口内的有效签名。网络中断时报告会进入权限受限的本地 spool，补传时使用新的请求时间重新签名；同秒报告使用唯一文件名，损坏文件会被隔离，不再阻塞后续补传。Python 端默认最多保留 500 份待传报告（可用 `SENTINEL_SPOOL_MAX_REPORTS` 设置 10–10000），Windows 端固定保留最近 500 份及 20 份损坏样本，超限时优先淘汰最旧文件。上报路径会把用户主目录替换为 `~`，明文密钥证据仅保留脱敏标记。密钥应由 Intune 的受保护配置流程注入，不要写入脚本或仓库。

0.53.0 / Agent 0.26.0 修复 Intune 周期任务无法继承安装进程环境变量的问题。Windows 使用 `sentinel-configure-windows.ps1` 将 URL、Bearer 和 HMAC 密钥通过 DPAPI LocalMachine 加密到 `%ProgramData%\SentinelAgent\reporting.dpapi`；任务以 SYSTEM 运行时自动解密，密钥不进入任务参数。macOS 使用 `sentinel-configure-macos.sh` 原子写入 root-only 0600 的 `reporting.json`，Agent 每次启动自动发现。两种配置均要求无凭据、无查询参数的 HTTPS URL、两项独立且至少 32 字符的密钥；权限、所有者、契约或解密异常会产生 `reporting_config_invalid` 高危项并拒绝上报。配置脚本应通过 Intune 的受保护变量或企业密钥代理获取临时输入，切勿把真实值写入 Intune 脚本文本。

0.54.0 将 `SentinelReportingConfigured` 纳入 Windows 与 macOS 的 Intune 自定义合规。Windows 发现脚本以 SYSTEM 实际执行 DPAPI 解密并重新验证 URL、字段集合和密钥边界；macOS 发现脚本验证 root 所有权、普通文件、0600 权限及相同契约。仅存在文件不能证明合规，复制其他设备的 DPAPI 文件、宽权限文件、损坏 JSON 或不安全 URL 均返回 false。生产分配顺序应先下发受保护上报配置，再启用这条合规规则，避免部署竞态造成短暂误报。

0.55.0 / Agent 0.27.0 在 Collector 返回成功后原子写入无密钥的 `sentinel.upload-status/v1` 回执，仅包含成功时间和 Collector 主机。网络失败或本地排队不会刷新回执。`SentinelReportingHealthy` 要求回执不超过 24 小时，且主机必须与当前受保护配置一致；旧 Collector 的成功记录不能掩盖配置切换后的故障。回执只证明最近一次 HTTP 接受，Collector 仍以签名验证、报告契约和服务端设备摘要作为最终事实源。

0.56.0 / Agent 0.28.0 要求 Collector 的 200/202 响应同时满足严格确认契约：字段必须恰好为 `accepted`、`duplicate`、20 位十六进制 `report_id` 和受限 `severity`，响应体不得超过 4 KiB。空 200、HTML 登录页、反向代理占位响应、附加字段或伪造报告 ID 都按上传失败处理，不刷新健康回执，并进入原有离线队列。该约束要求中间代理原样转发 Collector JSON，不得用统一成功页替换响应。

0.57.0 / Agent 0.29.0 / Collector 0.11 将 `report_id` 定义为本次 HTTP 原始请求体 SHA-256 的前 20 位。Agent 在发送前独立计算期望值，并以常量精确比较确认值；格式正确但不对应本次请求体的伪造回执同样失败。Collector 仍以规范化 JSON 摘要执行语义去重，因此相同报告采用不同空白格式重传时仍标记重复，但每次回执都绑定实际收到的字节。升级时必须先部署 Collector 0.11，再分批提升 Agent 0.29.0。

0.58.0 / Agent 0.30.0 / Collector 0.12 增加逐设备身份边界。Agent 发送 `X-Sentinel-Device-ID`，并把该 ID 纳入 HMAC 输入；Collector 可通过 `SENTINEL_DEVICE_CREDENTIALS_FILE` 加载最多 10000 台设备的独立 Token/HMAC 轮换集合，先按头部选择凭据，再要求已验证报告中的 `device_id` 完全一致。凭据文件拒绝符号链接、组写/其他用户权限、额外字段、重复密钥、Token/HMAC 复用和无效设备 ID。分三阶段启用：先部署 Collector 0.12 且保持该变量为空，再滚动升级全部 Agent 0.30，最后为每台设备生成独立凭据、以 `root:sentinel` 0640 安装清单并设置变量。启用清单后，旧 Agent、未知设备、跨设备凭据及身份错配均返回 401；管理查询仍使用独立的全局 Collector Token。

0.59.0 提供离线 `sentinel_device_credentials.py`。以受管终端的 12 位 `device_id` 列表运行，并同时指定服务端清单和独立 enrollment 目录；工具使用系统 CSPRNG 生成每台设备互不复用的 Token/HMAC，原子写入 0600 文件，标准输出只含设备 ID 与计数，不含密钥。`--rotate` 生成新凭据并只保留上一代作为重叠窗口，先准备 endpoint enrollment 文件、最后切换服务端清单；完成 Intune 受保护变量分发并确认新凭据活跃后，使用 `--prune-old` 删除旧代。部署服务端清单时再设置 `root:sentinel` 0640；enrollment 目录属于敏感暂存物，导入 Intune 后应按企业密钥介质流程销毁，不得提交 Git、工单或聊天。

0.60.0 修复在线轮换的文件元数据边界。新清单仍以 0600 创建；如果目标清单已存在且是合规的 0600 或 `root:sentinel` 0640 普通文件，原子替换会保留其 owner、group 和 mode。替换前无法保留任一元数据时操作失败且旧清单不变，避免轮换后 Collector 因属组或读取位丢失而停服。Collector 与生成器均只接受精确 0600/0640，不再接受其他“看似私有”但不符合部署契约的模式。

0.61.0 / Collector 0.13 强制 Token 与 HMAC 必须来自同一凭据代次；“新 Token + 旧 HMAC”等交叉组合返回 401。每次成功接收（包括语义重复报告）都会更新设备认证代次，`/v1/summary` 返回 `credential_posture.current/previous/legacy`，`/v1/devices` 返回每台设备的 `credential_generation`，均不暴露凭据。裁剪旧代前，将认证后的 `/v1/devices` 响应保存为本地 JSON，并以 `--activation-evidence` 传给 `sentinel_device_credentials.py --prune-old`；只有本次目标设备全部明确为 `current` 时才允许裁剪，缺失、重复、过大、结构异常或仍使用 previous/legacy 的证据均失败关闭。私有控制台的只读摘要代理会验证并展示该代次姿态。

0.62.0 / Collector 0.14 为 `/v1/devices` 增加 `generated_at`，逐设备 `last_seen` 在启用身份绑定后使用最近一次成功认证时间，因此相同报告重放也可证明新凭据已生效。裁剪工具只接受生成时间不超过 15 分钟、未来偏差不超过 60 秒的证据，并要求每台目标设备在证据生成前 24 小时内以 current 凭据成功认证。过期导出、长期离线终端或时间不一致均不能作为删除旧代的依据。

0.63.0 / Collector 0.15 为 `/v1/devices` 增加 `limit` 查询参数（1–10000，默认 500）及 `complete` 标志，并用单次聚合查询替代逐设备计数。全 fleet 裁剪前应请求 `/v1/devices?limit=10000`；只有结果未被截断时 `complete` 才为 true。凭据工具要求证据包含精确的 `complete:true`，因此默认 500 条导出、超出 10000 台的 fleet 或任何截断结果都不能被误当成全量激活证明。

0.64.0 提供 `sentinel_collector_probe.py` 将生产验收转为机器可执行检查。默认只读模式验证健康状态、未认证访问被拒绝、摘要及最多 10000 台设备的管理契约；令牌仅从指定环境变量读取且不会输出。维护窗口可增加 `--write-test --device-id <已配置的探针设备>`，并通过 `SENTINEL_PROBE_SIGNING_SECRET` 验证 HMAC 上传、响应与原始请求体绑定以及相同报告重放去重。启用每设备凭据时，Token/HMAC 必须属于该探针设备；写模式会留下可识别的正常测试报告，不应对未获授权的生产环境运行。

0.65.0 / Agent 0.31.0 将自动治理范围扩展到 Gemini CLI 与 GitHub Copilot CLI。终端仅通过配置、指令文件或可执行文件的文件系统标记发现工具，不启动第三方 Agent；发现后分别把带托管边界的用户基线同步到 `~/.gemini/GEMINI.md` 与 `~/.copilot/copilot-instructions.md`，并扫描 Gemini `settings.json`、Copilot `mcp-config.json`、仓库 `.mcp.json` / `.github/mcp.json` 及两者 Skill 目录。仓库继续使用 `AGENTS.md` 作为 Copilot 的跨工具入口，并新增 `GEMINI.md`。路径依据 [Gemini CLI context](https://google-gemini.github.io/gemini-cli/docs/cli/gemini-md.html)、[Gemini MCP](https://google-gemini.github.io/gemini-cli/docs/tools/mcp-server.html) 与 [GitHub Copilot CLI instructions](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions) 官方规范；卸载只删除 Sentinel 托管块，保留用户原有内容。

0.66.0 将运营界面和当前部署说明与六类 Agent 的实际终端能力对齐，并把 Collector 验收探针加入控制台下载入口。控制台覆盖数字仍明确标记为演示样例；连接企业 Collector 后应只使用经过服务端白名单清洗的实时摘要，不得把样例数据解释为真实部署状态。

0.67.0 / Collector 0.16 在认证摘要中增加 `agent_coverage`：仅从每台设备最新的已接受报告中按六个固定 Agent 名称去重计数，并分别返回总设备数与 24 小时活跃设备数。未知名称、路径、用户名和原始 inventory 均不会进入摘要，旧报告也不会重复放大覆盖率。控制台摘要代理要求固定键集合、非负安全整数、`active <= total <= total_devices`，清洗后才交给页面；未连接时仍使用明确标识的演示数据。

0.68.0 提供 `intune-deployment-manifest.json`，固定 Intune 上传文件的 SHA-256、SYSTEM/root 执行上下文、64 位 Windows 模式、隐藏 macOS 通知、部署依赖顺序和四级扩圈观察窗口。每次上传前先运行离线发行验证器，任何脚本字节变化都会使清单校验失败。当前仓库发行物明确标记为试点未签名；进入生产环前必须使用企业代码签名证书签署 PowerShell 脚本、重新生成摘要和清单并通过验证，不得把“MDM 已认证上传”替代脚本签名。凭据仍必须通过 Intune 受保护变量或企业密钥代理在清单之外传递。

0.69.0 提供不含凭据的 Intune 晋级证据模板与 `sentinel_intune_preflight.py`。将模板复制到受控工作目录，填写当前时间、当前环及入环时间、只读 Collector 探针、发行验证、凭据带外投递、回滚演练、critical 数量、上报健康起始时间和企业签名核验结果，再运行 `python3 sentinel_intune_preflight.py --evidence <文件> --target-ring <pilot|broad|production>`。证据超过 24 小时、未满足当前环最短观察时间、跳环、脚本哈希漂移、critical 非零、宽范围前未完成回滚或 24 小时健康观察都会返回非零；当前试点未签名发行物无论证据如何均不能通过 production 预检。模板本身所有门禁默认为 false，不能被误作通过凭证。

0.70.0 提供 OpenAPI 3.1 格式的 `sentinel-collector.openapi.json`，覆盖健康检查、报告提交、fleet 摘要、设备证据和最小审计五个实际端点，以及 Bearer、三项签名头、2 MB 请求上限、五分钟时间窗、原始请求体 HMAC 输入、接收/去重回执和错误响应。该文件可交给企业 API 网关和后端联调团队作为导入基线；示例服务器地址必须替换为企业内网域名。发行验证器会同时固定端点/方法集合、Collector 版本、认证方式、报告 Schema 引用、签名输入与报告响应码，防止实现与接口文档静默漂移。

0.71.0 / Adapter 0.8 提供 `sentinel-vendor-contracts.json`，以机器可读方式固定深信服事件、联软合规姿态和安全 Webhook 的字段、HTTPS、15 秒超时、Bearer/HMAC 凭据边界及请求体 SHA-256 幂等键。深信服只允许观察、告警和待审批隔离/封禁，不允许适配器直接执行破坏性动作；非法动作现在在配置加载阶段即拒绝。联软配置必须明确提供 1–168 小时的策略有效期且 `critical_allowed` 必须为 0，缺字段、布尔值冒充整数或放宽 critical 门禁都会拒绝启动。该契约是与现网厂商 API 团队做字段映射和验收的安全上限，不能替代对应产品版本的正式接口文档。

0.72.0 将 Windows 回滚与卸载脚本纳入 Intune 清单摘要，并提供 `sentinel-sign-intune.ps1`。在隔离的 Windows 签名工作站上，以未修改的企业 ZIP、全新输出目录、40 位证书指纹和 HTTPS 时间戳服务运行该工具；它只接受当前有效、含私钥及 Code Signing EKU 的唯一证书，对检测、修复、合规、上报配置、回滚和卸载六个 PowerShell 文件执行 SHA-256 Authenticode 签名并逐一复核签名状态与证书指纹。成功后更新十一项 Intune 文件摘要、标记 `production_signed`、记录不含秘密的签名元数据并重建独立 ZIP；任何错误都会删除不完整输出。随后在同一 Windows 工作站再次执行 `Get-AuthenticodeSignature`，并运行发行验证器及 Intune 晋级预检。原始试点 ZIP 保持不变，证书私钥和 PIN 不得进入命令参数、输出目录、Git 或 Intune 脚本文本。

0.73.0 / Agent 0.32.0 / Collector 0.17 将“自动加载基线”变成可验证结果。每次周期扫描会先重新发现 Codex、Claude Code、Gemini CLI 与 GitHub Copilot CLI 并增量同步用户级托管块，随后逐项验证目标没有越界/重解析、托管标记唯一完整且内容与当前基线一致；失败产生 `agent_baseline_not_loaded` 高危项，报告 inventory 仅记录 Agent 名、`managed|missing|malformed|unsafe|unreadable` 状态和用户级范围，不包含用户名或指令正文。Collector 只从每台设备最新报告聚合四类 `baseline_coverage.total/managed`，忽略未知名称和路径；私有控制台代理再次执行固定键、非负整数及 `managed <= total <= total_devices` 校验后才显示实时受管数量。Cursor 与 Windsurf 继续通过受管代码仓库规则加载基线，不伪装成用户级全局指令能力。

0.74.0 / Adapter 0.9 为深信服 EDR 与联软增加生产启用门禁。先从 `vendor-acceptance-evidence.example.json` 生成 `/etc/sentinel/vendor-acceptance.json`，填写双方确认的产品版本、正式 API 文档标识、与配置完全一致的 HTTPS 地址及审批人；只有字段映射、幂等、非 2xx 重试、安全动作语义和 dry-run payload 五项均验收为真，且证据不超过七天、未包含秘密时，`sentinel_vendor_preflight.py` 才通过。Adapter Worker 启动和每批派发都会执行同一门禁；缺少证据、证据过期、Adapter 版本变化或 URL 漂移都会拒绝派发。证据文件只能记录引用与结论，令牌仍只放在权限受限的环境文件中。

0.75.0 将新安装 AI Agent 的自动发现窗口从四小时缩短到一小时。Windows 同时注册延迟两分钟的开机触发和一小时周期触发，启用错过计划补跑、三次失败重试、30 分钟执行上限及忽略并发实例；Intune 检测与自定义合规会逐项验证这些配置，任务仅仅存在不再视为健康。macOS LaunchDaemon 使用一小时 `StartInterval`、`RunAtLoad` 和后台进程类型，合规脚本同时读取 plist 配置与 launchd 运行态。由此新安装的受支持 Agent 在设备在线时最迟一小时进入基线同步与扫描，重启或休眠错过计划后会补跑。

0.76.0 将运行调度定义纳入完整回滚点。Windows 升级仅在当前任务以 SYSTEM 身份、唯一 PowerShell 动作和精确 Sentinel 参数运行时导出 `scheduled-task.xml`，并与 Agent、策略、基线一起写入哈希清单；回滚在注册 XML 前再次验证大小、哈希、命令、参数和身份。macOS 升级仅快照 root 所有、非符号链接且 Label/Agent 路径正确的 plist，回滚同样在恢复前验证清单、大小与安全字段。缺少调度快照或出现字段漂移时回滚失败关闭，不再产生“文件版本已回退但调度仍是新版”的混合状态。旧格式回滚点必须先由 0.76.0 的一次成功升级刷新后才能使用。

0.77.0 收紧卸载边界。Windows 与 macOS 仅在每个用户指令文件恰好存在一组、顺序正确的 Sentinel 起止标记时删除受管块；标记缺失、重复或倒置时完整保留文件供人工审计。用户主目录、工具配置父目录、文件本身或 Sentinel 运行目录出现符号链接/重解析点时拒绝越界访问；macOS 运行目录还必须由 root 所有。macOS 卸载脚本现已加入 Intune 部署清单并固定 SHA-256，Windows 卸载仍纳入 Authenticode 生产签名流程。

0.78.0 将跨平台语法验证提升为 GitHub 必过门禁：原有 Ubuntu 作业继续执行完整行为测试、依赖审计、构建、Shell 语法和离线发行验证；新增 Windows runner 使用 Windows PowerShell 5.1 AST 解析全部 PowerShell 脚本，新增 macOS runner 同时用系统 Bash 与 POSIX sh 解析全部终端 Shell 脚本。首次原生门禁发现 Windows PowerShell 5.1 会按旧代码页误读含中文的 UTF-8 无 BOM Agent，现已将该脚本改为 UTF-8 BOM 并同步全部哈希消费者。三个作业都使用固定提交哈希的 checkout action、只读仓库权限和明确超时。真实 Intune 试点机仍需完成安装、升级、回滚和卸载演练，CI 不会冒充现网验收。

0.79.0 / Agent 0.33.0 / Policy 5.0.0 消除 Windows 与 Python 的密钥扫描漂移。Windows 不再维护独立硬编码列表，而是在策略通过契约及正则预检后逐条加载 `secret_patterns`；策略新增 Google API Key、Slack、GitLab、npm Token 与私钥头检测，命中只生成通用发现项而不回传密钥正文。Windows 同时补齐凭据目录/系统钥匙串访问、动态 eval/exec 以及弱随机数出现在敏感变量前后的对等检测。Collector 默认版本姿态、探针、Intune 合规和控制台版本提示同步升级。

0.80.0 / Agent 0.34.0 / Policy 5.0.0 加固 Windows 动态策略执行。所有策略列表元素必须是字符串，密钥正则在策略启用前使用 250ms 超时完成编译预检；扫描阶段复用有超时的已编译规则。恶意或退化输入导致规则超时时生成高危 `scan_rule_timeout` 发现项，而不会终止整次终端扫描。Intune 合规、Collector 版本姿态、探针和控制台版本提示同步升级。

0.81.0 / Agent 0.34.0 / Policy 5.0.0 将 Windows 发布门禁从语法检查扩展到真实运行。GitHub Windows runner 在隔离的 ProgramData 和用户目录中使用 Windows PowerShell 5.1 执行 Agent，验证干净策略报告契约，并注入损坏正则确认 Agent 返回阻断状态、策略版本标记为 `invalid` 且仅生成预期失败关闭发现项。`ManagedUsersRoot` 仅作为可选隔离参数，生产默认仍为 `C:\Users`；`Diagnostics` 仅供隔离验收时显式启用，以便暴露原生运行错误，生产计划任务不启用。

0.82.0 / Agent 0.34.0 / Policy 5.0.0 将 macOS 发布门禁从 Shell 语法检查扩展到真实安装和扫描。GitHub macOS runner 使用隔离的 HOME、安装目录和项目目录，从本地发行源执行哈希固定安装，随后验证干净报告契约与 0600 权限；再注入测试密钥，确认 Agent 返回阻断状态且报告只保留脱敏证据。测试不会读取或修改 runner 的真实用户 Agent 配置。

0.83.0 / Agent 0.35.0 / Policy 5.0.0 在 Windows PowerShell 5.1 原生门禁中加入完整终端链路。门禁发现并修复了 PowerShell 大小写不敏感导致循环变量 `$home` 与只读系统变量 `$HOME` 冲突的问题；该缺陷会在存在真实用户时跳过发现、用户基线同步和路径脱敏。修复后使用 `$userHome`/`$userHomePath`，离线验证器禁止回归。一次性合成 Windows 用户目录内放置 Codex 标记和测试密钥，必须得到发现、`managed` 基线、阻断发现及无密钥原文报告证据；测试结束仅删除带随机 `sentinel-ci-` 前缀的精确目录。

0.84.0 / Agent 0.35.0 / Policy 5.0.0 将 macOS 原生门禁扩展为完整终端链路。隔离 HOME 中模拟已安装 Codex 和个人指令，周期扫描必须自动发现 Codex、保留个人内容并以单一受管块加载用户基线，同时为模拟 Git 仓库加载共享安全基线。第二轮在隔离 HOME 和项目内分别注入未批准 Skill、提示覆盖指令、非 HTTPS MCP、硬编码测试密钥及不安全 TLS 代码，必须同时产生 Skill、MCP、密钥和代码质量发现，保留 `managed` 基线证明，并确保报告不包含测试密钥原文。该测试不读取或修改 runner 的真实用户配置。

0.85.0 / Adapter 0.10 修复联软合规姿态未执行 `max_policy_age_hours` 的生产缺口。联软输出现在同时检查 critical/high 风险、最近扫描时间和五分钟设备时钟容差；正常但过期或超前超过容差的报告会失败关闭为 `compliant=false`、`reason=stale_policy`，不能继续证明终端合规。Adapter Worker 将本轮派发时间显式传给姿态构建器，确保批次内结果确定且可复验；契约、验收证据版本和离线发行验证同步升级。现网仍须由联软团队确认字段与枚举映射后才能启用。

0.86.0 / Adapter 0.11 消除厂商离线队列满载时的静默数据丢失。队列达到配置上限后不再淘汰最旧事件，而是返回 `adapter_spool_full`；Worker 不写入完成账本，Collector 中的源报告保持待派发，待网络恢复并清空队列后自动重试。单个厂商队列满不会阻止同轮其他厂商通道处理；重复投递仍由规范化请求体的稳定幂等键保护。队列契约明确禁止静默淘汰及存储凭据，离线验证器固定该行为。

0.87.0 / Adapter 0.12 加固厂商队列的崩溃一致性。事件先写入同目录 0600 临时文件，完成 flush 与文件 `fsync` 后原子替换目标，再对队列目录执行 `fsync`；任何写入或切换错误都会清理临时文件并让 Collector 源报告保持待派发。显式或竞态检测到的符号链接队列目录会以 `adapter_spool_unsafe` 失败关闭，避免将报告写到受管目录之外。离线测试覆盖原子切换失败不遗留半文件、符号链接拒绝及原有队列恢复流程。

0.88.0 / Adapter 0.13 将 Collector 与厂商边界的单请求上限统一为 2 MB。Adapter 在报告契约验证及 HTTP 发送前都检查规范化 UTF-8 载荷大小，超限请求不会发送；离线队列文件在读取 JSON 前执行 2.1 MB 硬上限，异常大文件直接隔离，避免以解析器内存消耗进行拒绝服务。机器可读厂商契约和离线发行验证器固定两项上限，测试覆盖直接发送、独立 Adapter 报告和被篡改队列三条入口。

0.89.0 / Adapter 0.14 为所有本地厂商输入增加解析前门禁。独立 Adapter、自动 Worker 和厂商预检只接受非符号链接普通文件及严格 UTF-8：配置最大 64 KiB，验收证据最大 256 KiB，报告最大 2 MB，并在读取后再次核对长度以缩小检查与使用之间的竞态窗口。超限、链接、非法编码或无效 JSON 均在启用网络派发前失败关闭；机器可读契约、离线验证器和测试同步固定这些限制。

0.90.0 / Adapter 0.15 将 Collector 数据库读取改为小型元数据批次和逐份正文读取，避免最大批次把单份上限放大为高内存占用。Worker 在 JSON 解析和厂商派发前以 BLOB 字节长度执行 2 MB 门禁，并重新计算规范正文 SHA-256 与 Collector 保存的 `report_hash` 做常量时间比较；超大、摘要缺失或被本地篡改的正文会写入不含设备信息和载荷的拒绝账本，绝不会进入深信服、联软或安全 Webhook。

0.91.0 / Adapter 0.16 加固厂商离线队列读取。重放不再通过路径直接读取，而是先 `lstat`，再以 `O_NOFOLLOW` 打开文件描述符，并核对普通文件类型、inode、设备号及 2.1 MB 上限；读取本身最多取上限加一字节。符号链接、目录、设备文件和检查后被替换的队列项均不会解析或外发，隔离流程也不会对链接目标执行 chmod，而是安全移除非普通队列入口。

0.92.0 / Adapter 0.17 将队列目录门禁统一应用到写入、Worker 自动重放和 `--flush-only`。目录必须是真实目录、由当前服务用户所有，且不授予任何 group/world 权限；缺失目录只允许写入入口以 0700 创建，纯重放不会意外创建。符号链接目录、错误所有者或宽权限目录会在枚举任何事件前以 `adapter_spool_unsafe` 失败关闭，避免从受管路径之外读取或删除队列内容。

0.93.0 / Adapter 0.18 将独立报告、Adapter 配置和厂商验收证据的本地读取升级为文件描述符绑定。读取前后必须保持同一普通文件 inode 与设备号，以 `O_NOFOLLOW` 打开，并最多读取各自上限加一字节；在路径检查后换入新文件、符号链接或超大内容会在 JSON 解析和任何网络动作前失败关闭。Adapter 与独立厂商预检使用同一安全语义，Worker 因此同时覆盖启动配置和周期验收门禁。

0.94.0 加固 Intune 晋级预检的本地信任边界。证据最大 64 KiB、部署清单最大 256 KiB、每项待核验脚本或策略最大 2 MB；三类文件均以 `O_NOFOLLOW`、普通文件类型、inode/设备号绑定和上限加一字节读取。清单中的制品名必须是 128 字符内的单层文件名，拒绝绝对路径、`..`、额外字段和符号链接；因此被替换的证据、越界摘要目标或异常大签名脚本不能用于推动 Intune 扩圈。

0.95.0 将 Intune 部署清单从“摘要来源”提升为不可放宽的完整治理契约。预检固定 1%/5%/25%/100% 四级范围、24/48/72/168 小时观察窗口、六步部署顺序、六项晋级门禁、SYSTEM/root 执行上下文及十三个制品角色；试点清单不得携带签名元数据，生产清单必须含唯一的六文件签名集合、40 位证书指纹、HTTPS 时间戳服务和整型签名时间。篡改观察期、扩圈比例、门禁、角色或附加字段均在读取任何证据结论前直接阻断。

0.96.0 将 Intune 晋级证据升级为 `sentinel.intune-evidence/v2`。每份证据必须记录当前 `release.json` 的产品版本及当前部署清单完整 SHA-256；预检从同一次有界读取计算清单摘要并以常量时间比较，版本或摘要任一不一致都会拒绝扩圈。签名工作站产生生产清单后必须重新生成证据中的摘要，因此上一发行、未签名试点包或签名前清单的通过结论不能复用于新版本。

0.97.0 将 Intune 晋级证据升级为 `sentinel.intune-evidence/v3`，增加全量受管终端、当前环分配、成功上报、合规及安装失败五项实测数量。预检要求当前环分配不超过清单固定比例（小规模环境至少允许一台），上报与合规覆盖率均不低于 95%，安装失败率不高于 2%，并校验各数量之间的子集关系。由此不能再用单台成功样本、超范围分配或不完整遥测推动 broad/production 扩圈。

0.98.0 提供 `sentinel_intune_evidence.py`，从十五分钟内的 Intune 设备导出和 Collector 完整 `/v1/devices?limit=10000` 导出计算 v3 数量。工具验证设备 ID 唯一性、分配/合规/失败集合关系、Collector 完整标记及 24 小时活跃上报，只输出聚合数量并自动绑定当前发行版本与清单摘要，不把设备 ID 带入晋级证据。操作者仍需在基础证据中填写入环时间、只读探针、回滚和签名结论，然后用生成结果运行晋级预检。

0.99.0 提供 `sentinel_intune_graph_normalize.py`，将 Microsoft Graph 的受管设备 `id`/`complianceState`、环分配 ID、应用 `deviceId`/`installState` 和已分配终端的 Sentinel ID 绑定表归一化为 `sentinel.intune-export/v2`。归一化器严格限制字段、枚举、数量与一对一绑定，要求每台已分配设备都有安装状态和唯一绑定；输出删除 Graph 设备 ID，并以全量设备计数替代不必要的全量标识列表。随后把输出交给 `sentinel_intune_evidence.py` 与 Collector 设备导出联接。Graph 数据获取应使用只读 `DeviceManagementManagedDevices.Read.All` 和 `DeviceManagementApps.Read.All` 权限，在受控工作目录离线处理；不得导出设备名、UPN、邮件、序列号或硬件标识。

1.0.0 提供 `sentinel_vendor_probe.py`，用于深信服 EDR 或联软预生产接收端的非破坏性协议验收。默认只生成不发网的合成正常态载荷摘要；显式加入 `--live` 后才向配置中的精确 HTTPS 端点连续发送两份字节完全一致的载荷，并验证两个 2xx 响应。深信服探针强制把动作覆盖为 `observe`，联软只发送正常合规姿态，不能触发隔离、查杀、封禁或准入阻断。输出仅含端点、载荷摘要、幂等键、状态码和结果，不含令牌、原始载荷或终端身份。该探针证明传输和重复请求接受能力，但不能替代厂商对字段映射、失败重试及安全动作语义的人工验收；完成探针后仍需填写并通过 `sentinel_vendor_preflight.py`。

1.1.0 将厂商验收证据升级为 `sentinel.vendor-acceptance/v2`，每个启用的深信服或联软目标必须嵌入最近 24 小时的真实 `--live` 探针回执。预检把回执与当前 Adapter 版本、厂商名和精确端点绑定，要求两个响应均为整数 2xx、载荷 SHA-256 与幂等键常量时间一致、动作保持 `observe` 或仅合规姿态，且不得含秘密。其他端点、旧版本、离线 dry-run、过期回执或单次成功在结构上均不能通过生产 Worker 启动门禁；回执文件仍属于受控验收记录而不是防篡改证明，必须保存在审计系统中，并由厂商与安全负责人签署字段及动作审批。

1.2.0 将生产验收升级为 `sentinel.vendor-acceptance/v3`，对完整的 v2 审批记录执行 HMAC-SHA256。审批工作站通过 `SENTINEL_VENDOR_ACCEPTANCE_SIGNING_SECRET` 注入至少 32 字符的独立密钥，运行 `sentinel_vendor_evidence_sign.py --evidence <v2.json> --key-id <轮换标识>` 生成带签名的 v3 文件。Adapter Worker 使用同名受保护环境变量逐批验签；缺少密钥、签名字段异常或审批内容被修改都会失败关闭。该密钥不得与厂商令牌、Webhook HMAC 或 Collector 报告密钥复用，也不得写入证据、Git、命令参数或日志。

1.3.0 为厂商验收签名增加零停机密钥轮换。Worker 优先从 `SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS` 读取由 `key_id` 到密钥的 JSON 对象，严格接受 1–5 个唯一、至少 32 字符的值，并按证据中的 `key_id` 精确选键；无效 JSON、重复密钥、未知 key_id 或超限密钥环都会失败关闭。轮换时先加入新旧两把密钥，再用新 key_id 重签当前证据，确认 Worker 已加载并成功派发后删除旧键。旧的单值变量仅用于迁移兼容，稳定生产配置应使用密钥环。

1.4.0 让 Adapter Worker 在每个派发批次重新读取配置和厂商验收证据，而不是仅在进程启动时缓存。读取继续使用大小上限、`O_NOFOLLOW`、普通文件和 inode/设备号绑定；新 key_id 的已签证据原子替换落盘后可在下一批次生效，无需重启 Worker。端点、动作、证据或签名出现漂移时，当前批次在读取 Collector 报告和发网前失败关闭，并由 systemd 的失败重启策略持续重试安全状态。

1.5.0 增加 `SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS_FILE`。Worker 每批次从最多 64 KiB 的 JSON 密钥环重新加载 1–5 把唯一密钥，拒绝符号链接、非普通文件、其他用户权限、组写/执行、错误所有者及非服务组读取。推荐以 `root:sentinel 0640` 原子安装 `/etc/sentinel/vendor-acceptance-keys.json`；先部署新旧双键、再切换签名证据、确认后移除旧键即可真正无重启轮换。环境变量密钥环仅作兼容，变更仍需重启。

1.6.0 让离线审批签名工具也支持 `--keyring <文件>`，并按 `--key-id` 精确选择密钥。密钥环沿用 1.5 的 64 KiB、普通文件、防符号链接、所有者及权限约束，未知 key id 安全拒绝。审批密钥因此不必进入环境变量或命令行；签名输出仍只包含 HMAC 和 key id，不包含密钥。

1.7.0 为离线审批签名增加 `--output <v3.json>`。工具在所有者受控且不可组写/其他用户写入的真实目录中创建 0600 临时文件，完成内容 `fsync`、原子替换和目录 `fsync`；拒绝符号链接输出、非普通既有目标及含符号链接的父路径。使用该参数时标准输出仅返回 key id、输出路径和 `secrets_embedded:false`，避免 shell 重定向造成权限过宽或半写证据。旧的证据标准输出保留为兼容模式。

1.8.0 修复在线更新现有验收文件的服务可读性边界。`--output` 在覆盖前要求目标为当前用户或 root 所有、权限精确为 0600/0640 的普通文件；原子临时文件继承既有安全 mode、uid 与 gid 后再替换。因此 `root:sentinel 0640` 不会退化为 `root:root 0600`，Worker 下一批次仍可加载；宽松权限、错误所有者或非普通目标安全拒绝。首次创建仍使用 0600，需由部署流程显式设置预期服务组。

1.9.0 提供 `sentinel_vendor_keyring.py` 管理验收密钥环。使用 `--keyring <文件> --add-key-id <id>` 由系统 CSPRNG 创建至少 384 位随机密钥，安全原子写入且从不输出密钥；首次创建后按部署边界设置 `root:sentinel 0640`。退役使用 `--remove-key-id <旧 id> --acceptance <当前 v3.json>`，工具要求证据不超过七天、HMAC 有效且由将被保留的另一把密钥签署；正在使用的键、最后一把键、过期或伪造证据均不能推动删除。

2.0.0 扩展私有控制台只读面。新增同源 `/api/devices`，服务端以现有 Collector 管理令牌请求 `/v1/devices?limit=200`；浏览器只收到设备哈希 ID、最近上报时间、报告数量和 current/previous/legacy 凭据代次。代理限制 256 KiB、5 秒超时和 15 分钟生成时效，拒绝额外字段、重复/非法设备 ID、错误枚举、未来时间及超量结果；响应与错误均 `no-store`。设备列表连接失败时独立回退为明确标识的样例，不影响已验证摘要。

2.1.0 将控制台版本展示绑定到 `release.json.component_versions`。浏览器仅接受严格的产品 semver 以及 Endpoint Agent、策略、Collector、Adapter 四个版本字段，缺失、额外字段或非法格式不会进入界面状态；发行验证器同时固定这组版本与实际制品。由此基线页面不再保留手工维护的 v4.8 标签，当前展示与策略 5.0.0 一致。

2.2.0 / Collector 0.18 为 `/v1/devices` 增加 `view=console`。该视图在原匿名设备 ID、最近上报、报告数量和凭据代次上补充最新严重度、Agent 版本和策略版本；默认 `view=activation` 仍精确返回原四字段，既有 Intune 证据生成及凭据裁剪工具无需变更。控制台只读代理改为请求 console 视图，并严格要求七字段、三种严重度和受限版本字符串，使设备页面可直接识别风险与版本漂移。

2.3.0 增加确定性企业发行构建器 `sentinel_release_build.py`。开发者通过 `npm run release:build` 一次性同步四项运行文件摘要、所有安装/检测/合规脚本内嵌摘要、十三项 Intune 制品摘要、与当前清单绑定的晋级证据模板，以及按发行时间和稳定文件顺序生成的 ZIP。`npm run release:check` 在临时隔离副本中重建并逐字节比较派生文件，CI 因而会拒绝遗漏同步或非确定性打包。构建器只处理 `pilot_unsigned` 清单；生产 Authenticode 包仍必须由隔离 Windows 签名工作站生成，避免自动重建破坏签名。

2.4.0 将完整 `RELEASE-MANIFEST.sha256` 纳入离线包。该清单覆盖自身之外的每一个预期文件，包括 Collector、Adapter、Intune、回滚、卸载、验收工具、契约和文档；验证器要求文件集合完全相等、每行使用规范的小写 SHA-256 与单层文件名、文件名唯一，并逐项比较实际字节。它用于发现传输损坏和发行漂移，不替代受信下载通道、代码签名或企业制品库的签名证明。

2.5.0 / Collector 0.19 增加独立的 `sentinel_collector_maintenance.py` 及 systemd service/timer。部署脚本与 Collector 后启用 `sentinel-collector-maintenance.timer`；它每天在最多一小时随机延迟内执行，错过开机时间会由 `Persistent=true` 补跑。维护任务以 Collector 服务用户运行，要求数据库目录不可为符号链接、仅由 root/服务用户拥有且不可组写或公开写入，数据库必须是 0600/0640 的普通文件。任务在短暂 `BEGIN IMMEDIATE` 事务中强制执行报告与审计保留策略，再做 `quick_check`、被动 WAL checkpoint 和 optimize；输出只有删除/保留计数与 WAL busy 状态，不含设备身份、报告正文或秘密。由此在无新报告期间也能持续满足数据最小化要求。

2.6.0 / Agent 0.36 收紧持续自动发现的文件系统边界。macOS/Linux root 扫描只接受 `/Users` 或 `/home` 的真实直接子目录，拒绝符号链接用户目录；Git 仓库发现拒绝符号链接扫描根和符号链接 `.git` 标记。Windows 在用户基线同步、Agent 发现和仓库发现前排除用户目录、候选仓库根及 `.git` 的重解析点，并补充对 `Projects`、`Code` 等搜索根自身就是仓库的识别。由此每小时任务仍可加载后来安装的 AI Agent 与后来创建的真实仓库，但不会沿链接把企业基线写到受管边界之外。

2.7.0 / Agent 0.37 修复 root 周期任务创建仓库基线时的所有权与半写风险。macOS/Linux 的仓库文件现在通过同目录临时文件写入，保留既有文件 mode/uid/gid；新文件及由 Sentinel 新建的父目录使用仓库根所有者，完成文件 `fsync`、第二次目标边界检查、原子替换和目录 `fsync`。替换失败保留原文件并清除临时项，因此自动加载不会把开发者仓库变成 root-only，也不会留下截断指令。

2.8.0 / Agent 0.38 将 2.7 的安全写入语义扩展到用户级 Agent 指令。Codex `AGENTS.md`、Claude `CLAUDE.md`、Gemini `GEMINI.md` 与 Copilot `copilot-instructions.md` 均通过同目录临时文件、`fsync` 和原子替换更新；既有 mode/uid/gid 保持不变，新建 `.claude` 等目录与文件归属用户主目录所有者。显式传入的符号链接主目录也被拒绝，替换失败不会破坏用户原有指令。

2.9.0 / Agent 0.39 将用户级安全写入补齐到 Windows。Agent 与 Intune 修复脚本都先在目标目录创建唯一临时文件，以 UTF-8 BOM 写入并强制刷新到磁盘；既有指令文件的 ACL 在替换前复制，目标主目录边界与所有父路径重解析点在创建目录后再次验证。替换失败会清除临时项并保留原文件，Windows 原生 CI 同时验证受管更新后的 ACL 与临时文件残留。

3.0.0 / Agent 0.40 将 Windows 的原子安全写入覆盖到自动发现仓库。`AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、Cursor/Windsurf 规则和 `.sentinel/SECURITY_BASELINE.md` 不再直接 `Set-Content` 或 `Add-Content`；所有目标复用同目录临时写、UTF-8 BOM、强制落盘、ACL 复制、二次重解析点校验和原子替换。Windows 原生 CI 创建真实仓库并验证已有 `AGENTS.md` 的 ACL 不变且无临时文件残留。

3.1.0 将 `PRODUCTION-READINESS.md` 纳入离线包和完整 SHA-256 清单。它按责任人、输入、操作、通过证据与失败回退组织 Collector、Intune、深信服、联软及控制台联合验收，并显式列出只能由客户环境证明的六项生产签署记录；本地测试、CI 或演示控制台不能把这些项目自动标记完成。

3.2.0 新增 `sentinel.production-acceptance/v1` 与 `sentinel_production_preflight.py`。最终证据必须在 24 小时内生成，绑定当前产品版本、完整发行清单 SHA-256、40 位 Git 提交和正整数 Sites 版本；Collector 探针/恢复、Intune production 预检、双平台升级回滚、深信服与联软 v3 验收及真实只读控制台十项检查必须全部为 true，并提供安全、终端、平台与业务四方标识。读取使用 64 KiB、`O_NOFOLLOW` 和 inode 绑定，额外字段、缺签、秘密或设备标识声明、旧证据均失败关闭。

3.3.0 收紧最终生产证据的来源绑定。预检命令现在必须提供 `--expected-git-commit` 与 `--expected-site-version`；两者应分别来自 GitHub 主分支/成功 CI 和 Sites 已成功部署版本的独立只读查询。证据中的 SHA 与站点版本必须精确相等，格式正确但伪造或过期的其他值会以 `git_commit_mismatch` 或 `site_version_mismatch` 拒绝。

## 3.4.0 生产验收证据签名

最终生产验收使用 `sentinel.production-acceptance/v2`。十项检查必须分别填写外部验收记录 SHA-256，安全、终端、平台和业务四方审批必须分别绑定审批记录 SHA-256。审查完成后，在受保护工作站通过 `SENTINEL_PRODUCTION_ACCEPTANCE_SIGNING_KEYS` 注入独立密钥环，并用 `sentinel_production_evidence_sign.py` 生成私有原子输出；不得把密钥写入模板、脚本参数或日志。`sentinel_production_preflight.py` 同时验证签名、密钥 ID、记录摘要、当前发行清单，以及从 GitHub 和私有 Sites 独立查询的权威提交与版本。任何篡改、缺项、未知密钥或模板占位值均失败关闭。

## 3.5.0 生产验收密钥生命周期

`sentinel_production_keyring.py` 通过系统 CSPRNG 创建长期验收密钥，并以私有原子文件保存；签名和最终预检均优先使用 `--keyring`，避免密钥进入进程环境。密钥环限 64 KiB、1–5 个唯一密钥，要求普通文件、防符号链接、root/当前用户所有，权限仅允许 `0600` 或受控组 `0640`。轮换顺序为增加新键、用新键签署新鲜 v2 验收记录、验证通过、再凭该记录退役旧键；旧键不能用自身授权删除，最后一把键不可删除。

## 3.6.0 原始验收记录链

最终证据升级为 `sentinel.production-acceptance/v3`。`evidence_files` 为十项检查分别指定证据目录内的单层文件名，四方审批也分别指定独立记录；对应 SHA-256 纳入 HMAC 签名。最终预检必须传入 `--evidence-root <证据目录>`，逐文件从受约束描述符读取最多 2 MiB 并核对摘要。证据根目录不得为符号链接或路径别名，十四份记录不得复用文件；缺失、摘要漂移、超限或目录逃逸均阻断放行。

## 3.7.0 验收证据准备器

复制 v3 模板并填写十四个证据文件名、真实检查结果和审批人后，运行 `python3 sentinel_production_evidence_prepare.py --evidence <工作副本.json> --evidence-root <证据目录> --output <待签名.json>`。工具沿用最终预检的固定目录描述符、有界读取和防符号链接规则，自动计算全部 SHA-256，并以 `0600` 私有原子文件输出。它拒绝已签名输入和重复记录，不改变检查布尔值、审批身份、版本绑定或时间戳；输出仍须人工复核后再签名。

## 3.8.0 签名前强制门禁

`sentinel_production_evidence_sign.py` 要求 `--evidence-root`，在访问签名密钥并写出结果前重新执行证据级验证：发行/提交/Sites 绑定格式完整，时间戳在 24 小时内，十项检查均为 true，四方审批身份完整，隐私声明为 false，十四份原始记录可安全读取且摘要吻合。任何失败只返回最小错误，不产生签名文件。

## 3.9.0 签名绑定权威发布

签名命令新增必需的 `--expected-git-commit` 和 `--expected-site-version`，两者必须来自 GitHub 与 Sites 的独立只读查询。工具还从 `--downloads`（默认脚本目录）读取当前 `release.json` 和 `RELEASE-MANIFEST.sha256`。证据的产品版本、清单摘要、完整提交和站点版本必须分别精确匹配，才能进入密钥选择与签名输出；这防止为旧发行、其他提交或尚未发布的站点版本签发生产批准。
## 4.0.0 厂商无关与企业 4A

核心部署不再以 Intune、深信服或联软为前置条件。Adapter 0.19 新增 `enterprise_4a` 通道，按 `sentinel.enterprise-4a.event/v1` 输出最小设备安全姿态，通过精确 HTTPS 主机、`SENTINEL_4A_` 凭据命名空间、Bearer 服务身份和稳定幂等键对接企业 4A。授权输出只包含观察、告警、访问复核待处理和隔离待审批，不允许 Adapter 直接改变访问权限。

生产验收的十项门禁保持数量和签名结构不变，但平台相关项目迁移为 `deployment_platform_preflight_passed`、`enterprise_4a_interface_accepted` 和 `optional_adapters_disabled_or_accepted`。未采用 Intune 时提供所选部署平台的等价实测记录；未采用深信服或联软时提供目标关闭且无凭据引用的审计记录即可。

## 4.1.0 企业 4A 安全验收探针

`sentinel_4a_probe.py` 默认只生成脱敏 dry-run 回执；只有显式指定 `--live` 才访问配置中的精确 HTTPS 端点。探针忽略生产动作映射并强制使用 `observe`，连续发送两份相同事件，两个响应均为 2xx 时才确认幂等重放能力。输出仅包含端点、租户、载荷摘要、幂等键、状态码与布尔结论，不包含访问令牌、设备 ID 或事件正文，可作为 4A 接口生产门禁的原始验收记录。

## 4.2.0 通用部署平台生产门禁

复制 `deployment-platform-evidence.example.json`，从所选终端管理平台写入 lab、pilot、broad、production 四环聚合结果，并运行 `python3 sentinel_deployment_preflight.py <证据文件>`。门禁支持 `mdm`、`desktop_management`、`software_distribution` 和 `manual_controlled`，固定要求 24/48/72/168 小时观察期、每环回滚与审批、至少 95% 安装/上报/合规率以及不高于 2% 的失败率。证据绑定当前发行及完整清单摘要，24 小时后失效，禁止嵌入秘密或设备标识。Intune 专用工具继续保留，但不再是非 Intune 环境的前置条件。
## 4.3.0 真实 Collector 与参考 4A 服务

本版本提供 `sentinel_4a_receiver.py` 与加固的 systemd 单元，作为企业 4A 标准安全事件接口的轻量参考实现。接收器只接受最小化姿态事件、强制 Bearer 认证、校验请求体绑定的幂等键，并把影响访问的动作保留为外部审批状态。生产控制台不再回退到样例数据：Collector 或明细接口不可用时显示空状态。参考身份层可采用 Authelia 与 Nginx AuthRequest，覆盖账号、认证、路径授权和访问审计；Intune、深信服与联软仍作为默认关闭的可插拔兼容适配器。
