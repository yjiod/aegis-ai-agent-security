# Aegis 企业部署指南

私有站点当前提供经验证的发行物下载、架构说明和治理界面样例，但尚未连接客户报告接收器或 MDM/EDR/厂商桌管任务 API。页面以“演示模式”明确标识所有样例指标，任何按钮都不会声称已执行外部变更。只有完成企业私有 API、身份认证、授权与审计接入后，才能将其作为实时运营控制台启用。

0.48.0 起，站点提供只读同源 `/api/summary` 代理。服务端配置 `AEGIS_COLLECTOR_URL`、精确主机名 `AEGIS_COLLECTOR_ALLOWED_HOST` 和至少 32 字符的 `AEGIS_COLLECTOR_TOKEN` 后，顶部四项指标读取接收器摘要；令牌不会进入浏览器。代理只允许 HTTPS、拒绝 URL 凭据/查询参数、五秒超时、禁用缓存并严格复核汇总计数。未配置、上游异常或契约不符时自动回到明确标识的演示模式。

0.49.0 起，摘要代理以流式读取执行 64 KiB 硬上限，包括没有 `Content-Length` 的分块响应；超过限制会立即取消上游读取。响应必须是严格 UTF-8，只有控制台需要的计数和版本字段会被重新构造并返回，获准主机附加的未知字段不会透传。所有成功及错误响应均设置 `Cache-Control: no-store`。

## 推荐职责

- Microsoft MDM：Windows/macOS 安装、周期检测、修复与合规状态。
- 厂商 EDR：接收高危事件后执行主机隔离、查杀和取证；接口以客户实际版本的 OpenAPI 为准。
- 厂商桌管控制台：资产映射、软件统一分发，以及未安装 Aegis 终端的准入限制。

## MDM Windows

在“设备 > 脚本和修正”创建包，检测脚本使用 `mdm-windows-detect.ps1`，修复脚本使用 `mdm-windows-remediate.ps1`，使用 64 位 PowerShell 并以 SYSTEM 运行。先分配试点设备组，再逐步扩大范围。

如需把扫描结果纳入设备合规和条件访问，上传 `mdm-compliance-discovery.ps1` 与 `mdm-compliance-policy.json`。策略同时验证安装状态、三个运行文件的固定哈希、计划任务状态、策略版本、报告时效及 critical/high 风险数；未来时间戳不会被当作新鲜报告。高危项包括被阻断的未知 Skill；先在试点组完善 `allowed_skills` 并确认误报，再绑定条件访问。

## MDM macOS

将 `mdm-macos-install.sh` 作为 macOS Shell Script 下发，以 root 运行。脚本需要终端已有 Python 3，并会把实际解析到的 Python 路径写入 LaunchDaemon。正式部署前应将脚本、策略和扫描器放入企业可信软件源并进行代码签名。

macOS 自定义合规上传 `mdm-macos-compliance.sh` 与 `mdm-macos-compliance-policy.json`，发现脚本使用 Bash、UTF-8 无 BOM，并设置为不使用已登录用户凭据运行，以便读取受 root 保护的运行文件和报告；启用签名检查及隐藏通知。规则验证安装、三项固定哈希、LaunchDaemon、策略版本、24 小时内扫描和 critical/high 数量，并同时包含 MDM 要求的 `en_US` 与中文修复文案。按微软限制，脚本与输出均须小于 1 MB、运行不超过 10 分钟。

## 厂商 EDR

Aegis 报告使用 `aegis.report/v1`。由中转服务将 critical/high finding 转换为当前 EDR 版本支持的告警或联动请求。隔离、查杀等动作必须经 EDR 控制台策略授权。不要把管理口令写入终端脚本。

`aegis_collector.py` 是最小参考接收器，支持令牌认证、可选 HMAC 请求签名、报告大小限制、SQLite 留存和设备列表。生产环境应部署在企业反向代理之后，配置 TLS、密钥轮换、审计、限流和备份；终端不得直接访问 EDR 管理面。

0.51.0 提供可审计的 Linux 生产部署基线：将 `aegis_collector.py` 放入 `/opt/aegis/`，创建无登录权限的 `aegis` 系统用户，把 `aegis-collector.service` 安装到 `/etc/systemd/system/`；从 `aegis-collector.env.example` 创建 `/etc/aegis/collector.env`，分别生成至少 32 字符的认证令牌和 HMAC 密钥，设置 `root:aegis`、0640 后再启动服务。空密钥会使服务拒绝启动。接收器只监听 `127.0.0.1:8788`，由 `aegis-collector.nginx.conf` 提供 TLS 1.2/1.3、2 MB 请求上限和外层限流。替换示例域名及证书路径后先执行 `nginx -t` 和 `systemd-analyze security aegis-collector.service`，再进入试点流量。

生产验收至少包含：`/health` 返回数据库可用；无 Bearer、错误 HMAC、过期时间戳分别返回 401；首份有效报告返回 202、同内容重放返回 200 且标记重复；`/v1/summary` 仅在认证后可读；超过代理或应用限额分别返回 413/429；重启服务后 SQLite 数据仍存在。认证令牌与签名密钥必须独立轮换，不得放入 MDM 脚本文本、Nginx 配置或 Git。

接收器默认保留 30 天报告，可通过 `AEGIS_RETENTION_DAYS` 设置 1–3650 天。SQLite 启用 WAL 和五秒忙等待；写入时清理过期数据。同一报告按规范化 JSON 内容去重，不会因空格或字段顺序不同而重复计数。服务端与公开 Schema 同时限制 2 MB 请求、5000 个资产项、10000 个发现项及各字符串字段长度。`/health` 会实际检查数据库，数据库不可用或繁忙超时返回 503，而格式错误仍返回明确的 400，便于监控区分客户端与服务端故障。

接收器 0.5 增加线程安全的每来源滑动窗口限流，默认每分钟 120 次，可通过 `AEGIS_REQUESTS_PER_MINUTE` 设置 1–10000；超限返回 429 和 `Retry-After`，健康检查不计入额度。内存中的来源表最多保留 10000 项，防止来源标识耗尽内存。该机制只使用直接连接地址，不信任可伪造的转发头；生产反向代理仍应执行公网限流，并按代理后的汇聚连接数调整应用层额度。

接收器 0.6 提供受 Bearer 认证和应用层限流保护的 `GET /v1/summary`，按每台设备最新一份已接受报告聚合设备总数、24 小时活跃/过期数量及 critical/high/normal 最新态。接口不返回报告正文或终端路径，可供内部监控采集；时间窗口固定有界，避免历史报告重复放大风险计数。

接收器 0.10 在不阻断滚动升级报告上传的前提下，将每台设备最新报告按版本态分类为 `current`、`agent_mismatch`、`policy_mismatch`、`both_mismatch` 或 `unknown`。`GET /v1/summary` 同时返回要求的 Agent/策略版本和 `version_posture`；接收器 0.15 默认要求 Agent 0.30.0、策略 4.8.0，可通过 `AEGIS_REQUIRED_AGENT_VERSION` 与 `AEGIS_REQUIRED_POLICY_VERSION` 调整。数据库升级会原位增加版本列，不删除历史报告。

使用 `python3 aegis_collector_backup.py --db /var/lib/aegis/aegis.db --output /受保护备份目录 --keep 14` 执行 SQLite 在线一致性备份。工具通过 SQLite Backup API 读取运行中的 WAL 数据库，在同一目标目录原子落盘，执行 `PRAGMA quick_check` 后才发布文件，并将权限收敛为 0600；只轮换自身命名的备份，保留数量限制为 1–365。应由企业备份平台加密、异地复制并定期演练恢复，且备份目录不得由 Web 服务公开。

恢复演练使用 `python3 aegis_collector_restore.py --backup <备份.sqlite> --output <全新候选数据库>`。工具先检查备份，再通过 SQLite Backup API 原子生成 0600 权限的候选库并复检；若目标已存在会直接拒绝，永不覆盖运行库。验证 `/health`、设备数量和最新风险摘要后，应停止接收器并通过变更审批手工切换 `--db` 路径，保留原库以便反向回退。

接收器 0.7 将报告接受/重复提交及已认证的设备、摘要、审计读取写入结构化 `audit_events`，`GET /v1/audit` 返回最近最多 200 条且同样受 Bearer 认证与限流保护。审计只保存事件名、时间、设备标识、报告短哈希和风险级别，不保存令牌、签名、报告正文或终端路径。默认保留 90 天和最多 100000 条，可通过 `AEGIS_AUDIT_RETENTION_DAYS`（1–3650）及 `AEGIS_AUDIT_MAX_EVENTS`（1000–1000000）调整；备份与恢复工具会连同审计表保持一致。

接收器支持无中断凭据轮换：`AEGIS_COLLECTOR_TOKENS='["新 Token","旧 Token"]'` 与 `AEGIS_REPORT_SIGNING_SECRETS='["新 HMAC 密钥","旧 HMAC 密钥"]'` 各最多接受 5 个非空值，并兼容原有单值变量。先在服务端加入新旧值，再分批更新 MDM 受保护配置，确认旧版本不再活跃后移除旧值；数组 JSON 无效、为空、超过上限或含非字符串时会安全拒绝，而不会退回旧单值。密钥不得写入脚本、策略、日志、审计表或发布包。

接收器 0.8 默认要求配置单值或轮换数组形式的 HMAC 报告签名密钥；没有有效密钥时服务拒绝启动，运行期未签名或签名无效的报告返回 401。仅隔离试点可显式设置 `AEGIS_ALLOW_UNSIGNED_REPORTS=true`，该开关不得用于生产，也不会绕过 Bearer 认证、大小限制或 Schema 校验。上线检查应确认兼容开关为空，并用错误签名探针验证 401。

接收器 0.9 在监听端口前校验运行密钥：每个 Bearer Token 和 HMAC 密钥至少 32 个字符，同一用途内不得重复，认证 Token 与签名密钥不得复用。任一条件不满足时进程以明确的非敏感错误类别退出，不在错误信息中打印秘密。建议由企业密码系统生成至少 32 字节随机值，并通过服务环境或密钥管理器注入。

使用 `aegis-adapters.example.json` 创建不含凭据的配置副本，并用 `aegis_adapter.py <报告> --config <配置> --dry-run` 检查事件映射。适配器默认关闭；只允许 HTTPS 且目标主机名必须精确列入顶层 `allowed_hosts`，URL 中不得携带凭据。厂商 EDR动作仅允许 `observe`、`alert`、`isolate_pending_approval` 和 `block_pending_approval`；直接隔离、查杀或封禁会被拒绝，必须由现有审批与响应平台执行。确认现网 API 字段后再设置 URL、环境变量令牌并去掉 `--dry-run`。

三个输出通道彼此隔离：某个厂商接口不可用时，其事件以 0600 权限写入 `AEGIS_ADAPTER_SPOOL`，不阻塞其他通道；网络恢复后运行 `aegis_adapter.py --config <配置> --spool-dir <目录> --flush-only` 重放。队列默认最多保留 500 个事件，可用 `AEGIS_ADAPTER_SPOOL_MAX_EVENTS` 设置 10–10000；同秒事件不会覆盖，损坏记录会隔离并最多保留 20 份，不阻塞有效事件。队列不保存令牌，凭据只从环境变量读取。当前包定义的是安全边界与通用 Webhook 契约，厂商 EDR和厂商桌管的最终路径、鉴权头与字段映射仍需按客户现网产品版本的正式 API 文档完成验收。

适配器 0.6 对顶层配置、目标对象、字段集合、启用标志和动作表执行严格校验。厂商 EDR、厂商桌管和安全 Webhook 的凭据变量必须分别使用 `VENDOR_EDR_`、`VENDOR_MDM_`、`AEGIS_` 前缀，避免错误配置把 `PATH` 等无关环境变量作为令牌外发。只有整数 2xx 响应会确认投递并删除队列事件；其他返回值与网络错误均保留事件等待重放。

适配器 0.7 新增自动派发 Worker。将 `aegis_adapter_worker.py` 与 `aegis_adapter.py` 放入 `/opt/aegis/`，从示例生成 `/etc/aegis/adapters.json` 和 `/etc/aegis/adapter.env`，仅启用已完成厂商验收的目标，再安装 `aegis-adapter-worker.service`。Worker 启动时会验证精确 HTTPS 主机、凭据变量和安全动作；配置无启用目标或缺少凭据时拒绝启动。它从 Collector 数据库读取尚未派发的已验证报告，失败投递进入有界 spool，成功接受后写入不含 payload 或设备标识的最小派发账本。每个 HTTP 请求携带基于规范化请求体 SHA-256 的稳定 `Idempotency-Key`；厂商 EDR和厂商桌管接收端应按该键去重，以覆盖“远端已接收、Worker 在写账本前重启”的边界。

厂商联调顺序为：先使用 `aegis_adapter.py --dry-run` 让双方确认字段和动作只表示“待审批”，再在隔离测试地址启用 Worker；验证同一报告不会被账本重复发送、网络失败会排队且恢复后补发、非 2xx 不会确认、错误主机和明文 HTTP 会被拒绝。未经厂商确认不得把 `isolate_pending_approval` 映射为自动隔离指令。

适配器 0.5 在任何通道处理前执行完整 `aegis.report/v1` 白名单、类型、长度、数量和摘要一致性校验；额外字段不会透传到安全 Webhook。厂商 EDR与厂商桌管投影也使用精确字段集合验证，离线队列重放前再次验证；被篡改、`null` 或结构异常的载荷进入隔离区而不发网，报告或事件构建失败也不会排队空载荷。

## 厂商桌管

将 Windows 脚本或后续签名 MSI 作为软件分发包。使用软件资产规则检查 `%ProgramData%\AegisAgent\aegis-policy.json`，未安装或策略过期的设备进入修复组；若启用准入隔离，先以观察模式验证误报率。

## 上线门槛

1. 脚本签名与哈希固定（安装器已校验核心文件 SHA-256）；2. 100 台以内试点；3. 误报复核；4. 回滚与卸载包；5. EDR 动作双人审批；6. 数据保留和脱敏评审。

每次导入 MDM 或桌管前，在解压目录运行 `python3 aegis_release_verify.py .`。验收器离线检查核心文件 SHA-256、所有安装/检测脚本内嵌哈希、策略版本、MDM `en_US` 修复文案，以及企业 ZIP 中每个文件与发布目录逐字节一致；必须返回 `{"ok":true,"errors":[]}` 才能进入试点。

## 升级、回滚与卸载

MDM 修复脚本先把新版本下载到受限暂存目录，校验扫描器、策略和基线三项 SHA-256 后才替换运行文件；已有完整版本会备份到 `previous`。需要回退时，通过 MDM 以 SYSTEM/root 下发 `rollback-aegis-windows.ps1` 或 `rollback-aegis-macos.sh`，脚本会先验证备份清单，再恢复并重启周期任务。回滚只保留最近一个完整版本。

升级脚本只在当前扫描器、策略和基线三件套全部存在时创建回滚点；先在独立的受限目录复制三件套并生成校验清单，再原子切换 `previous`。当前安装残缺时会保留已有完整回滚点，不生成混合版本快照。若回滚点目录切换失败，升级在替换运行文件前终止并恢复旧目录。

0.50.0 起，回滚只接受恰好包含扫描器、策略和基线三项的校验清单；漏项或附加路径均拒绝。回滚先停止周期任务，验证快照，恢复后再次验证运行目录，只有二次哈希全部一致才重启任务；复制或落地校验失败时任务保持停止，由 MDM 检测进入修复流程，避免混合版本继续运行。

所有安装与修复下载均设置 15 秒连接超时和每文件 120 秒总时限；Windows 使用对应的 120 秒请求超时。三个文件最坏网络等待受控在 MDM 脚本执行窗口内，失败后保留当前运行版本并由下一次 MDM 修复周期重试。超时设置不替代 SHA-256 固定：只有三项下载全部完成且哈希匹配才会备份与替换。

卸载使用 `uninstall-aegis-windows.ps1` 或 `uninstall-aegis-macos.sh`。卸载会移除运行时、周期任务以及 Codex/Claude 用户指令文件中带 Aegis 起止标记的受管区块，保留用户自定义内容；符号链接或重解析点不会被修改。已进入源码管理的仓库基线文件仍会保留，必须通过正常代码评审移除，避免绕过审计。

## Collector 令牌轮转（运维手册）

全局 Collector 令牌（`AEGIS_COLLECTOR_TOKEN`）同时用于控制台读取，以及（未启用每设备凭据 `AEGIS_DEVICE_CREDENTIALS_FILE` 时的）终端上报；一旦泄露必须轮转。`scripts/rotate-collector-token.sh` 在服务器本地执行零停机三段式轮转，自动一致更新四处驻留（`/etc/aegis/collector.env`、`/etc/aegis/console.env`、`wrangler.json` 的 vars、systemd unit），每步带"已认证连通"校验与失败自动回滚，全程不打印明文（仅输出 sha256 指纹供核对）：

1. **A 双令牌过渡**：Collector 经 `AEGIS_COLLECTOR_TOKENS='["旧","新"]'`（JSON 数组，最多 5 个）同时接受新旧令牌，读取与上报都不中断。
2. **B 控制台切换**：把新令牌写入 `console.env` 并合并进 `wrangler.json` 的 vars，重启后控制台改用新令牌读取。
3. **C 旧令牌作废**：移除过渡数组，Collector 只保留新令牌，泄露的旧令牌立即返回 401。

轮转后新令牌存于服务器 `/etc/aegis/.collector-token-current`（0600），供终端重新入网取用；切勿写入仓库、工单、日志或聊天。脚本可断点续跑：若上次已完成 A 步（`collector.env` 存在 `AEGIS_COLLECTOR_TOKENS`），再次运行会自动恢复新/旧令牌并继续 B、C。

**终端重新入网**：已部署 Agent 的令牌驻留于 `/Library/Application Support/AegisAgent/` 下的 `config.json`、`reporting.json` 与 LaunchDaemon plist（均 0600/root）。用新令牌重跑安装器即可原子重写三处并重载周期任务：

```bash
sudo AEGIS_COLLECTOR_TOKEN='<新令牌>' sh aegis-agent-macos.run
# 或等价地： sudo sh aegis-agent-macos.run --token '<新令牌>'
```

在执行 C 步作废旧令牌之前，存量终端仍可用旧令牌上报（A 步过渡窗口），因此可先在过渡态下批量迁移：按 MDM 受保护配置分批下发新令牌、确认全部终端活跃后，再执行 C 步收口。Windows 终端同理——经 MDM 更新受保护的 `AEGIS_REPORT_TOKEN` 并重载计划任务。密钥永不进入脚本、策略、发布包或源码管理。

## 项目级基线加载

对受管代码仓库执行 `aegis_agent.py <项目目录> --install-baseline`。该命令为 Cursor 创建 Always Project Rule，为 Windsurf 创建项目规则，并以带标记的增量内容接入 `AGENTS.md` 和 `CLAUDE.md`；不会覆盖仓库已有规范。`--auto-enroll` 还会仅针对已存在 `.codex` 或 `.claude` 安装标记的用户，将受管区块增量写入用户级 `AGENTS.md`/`CLAUDE.md`；区块可随基线升级原位更新，不会为未安装工具创建目录。所有写入在执行前都会解析父目录真实路径，并拒绝越出仓库/用户根目录的符号链接或 Windows 重解析点。随后使用 `--watch --interval 300` 持续发现新增 Agent 配置、Skill、MCP 和代码风险。

0.6.0 起，扫描器通过只读文件标记识别 Cursor、Codex、Claude Code 与 Windsurf，不启动或执行被发现的 Agent。以管理员或 SYSTEM/root 身份运行时会覆盖受管用户目录；仅存在 Aegis 写入的项目规则目录不会被误判为已安装 Agent。Windows 报告中的用户目录会替换为 `~`，控制台可根据 `inventory` 中的 `ai_agent` 项统计覆盖率。

0.7.0 起，MCP 最小权限检查同时覆盖 Cursor/Claude/Windsurf 的 JSON 配置和 Codex 的 `config.toml`，并执行策略中已声明的隐藏 Unicode、弱随机令牌与阻断命令规则。敏感环境变量只上报变量名和 `[REDACTED]`，不上传原值。

0.8.0 起，Skill 扫描覆盖 `SKILL.md` 及包内脚本、配置和说明文件，并检查越界符号链接。策略 `allowed_skills` 是企业允许名单；默认空名单配合 `unknown_skill: block`，表示未经审批的第三方 Skill 一律产生高危项。试点前应填入已完成安全评审的 Skill 目录名。

0.9.0 起，代码质量扫描会解析 npm `package.json` 与 Python `requirements*.txt`，识别浮动版本、直接远程源码和缺失锁文件；依赖清单也会作为资产写入报告。该检查用于供应链基线，不替代企业 SCA/CVE 数据源。

0.10.0 起，MCP 远程连接采用默认拒绝：`allowed_mcp_domains` 为空时不允许任何远程域名。域名按解析后的完整主机名精确匹配，并检查未批准传输、命令与 URL 混用、URL 用户信息及敏感查询参数。远程 MCP 上线前必须显式填写受信域名。

0.12.0 起，Windows 原生扫描器也解析 Codex `.codex/config.toml` 中的 `[mcp_servers.*]` 配置，执行与 JSON MCP 相同的 Server、命令、传输、远程域名、宽泛文件范围和凭据检查；扫描仅读取配置，不启动 MCP Server。

0.15.0 起，Python 端单次项目扫描默认最多检查 10000 个候选文件，并跳过符号链接目录；可通过策略 `limits.project_files` 设置 100–100000。跨平台报告统一限制为最多 5000 个 inventory 和 10000 个 findings，超限时保留明确的 `inventory_truncated` / `findings_truncated` 标记，确保报告仍符合接收契约而不是反复补传失败。

0.16.0 起，跨平台代码质量扫描新增关闭 TLS 证书校验、不安全反序列化、生产调试模式和空异常处理检测；规则由策略 4.4.0 的 `code_rules` 统一发布。

0.17.0 起，策略 4.5.0 通过 `limits.max_file_bytes` 统一控制 64 KiB–10 MB 的单文件扫描上限，默认 1 MB。代码、Agent 配置或 Skill 文件超过阈值时不再静默跳过，而产生 `oversized_file_skipped` 中危项；Skill 的超大文件仍计入包文件数上限。Windows 端单根目录最多保留 100 条超大文件明细并额外标记截断，防止填充文件放大报告。

0.18.0 起，深度异常或结构损坏的 MCP、依赖 JSON 会转化为 `invalid_mcp_config` / `invalid_dependency_manifest`，不会终止整次扫描。策略中的敏感信息正则若无效，运行时仅上报正则摘要而不回显内容；离线发布验收会直接返回 `invalid_secret_pattern_regex`，阻止错误策略进入试点。

0.19.0 起，Python 与 Windows 扫描器均在报告同目录写入唯一临时文件，完成写入后再原子替换 `latest.json`；Python 端在替换前执行 flush、fsync 并设置 0600，离线 spool 也复用相同写入路径。写入或替换失败会清理临时文件并保留上一份完整报告，避免 MDM 合规读取半份 JSON。

0.20.0 起，Python `--watch` 模式每轮重新读取并验证 `aegis.policy/v1` 策略，使 MDM 更新无需重启长驻进程即可生效。若新文件缺失、损坏、编码异常或契约错误，本轮继续使用内存中的上一份有效策略并增加 `policy_reload_failed` 高危项；首次启动没有有效策略时直接拒绝运行，避免空策略降级。

0.21.0 起，MCP 命令同时校验 basename 与可执行路径。`node`、`npx` 等裸命令仍按 `allowed_mcp_commands` 审批；任何包含 `/` 或 `\` 的绝对/相对路径默认产生 `unapproved_mcp_command_path` 高危项，只有与策略 4.6.0 `allowed_mcp_command_paths` 精确匹配才放行，防止 `/tmp/node` 等同名伪造二进制绕过。

0.22.0 起，带参数的 MCP 本地命令必须与策略 4.7.0 `allowed_mcp_invocations` 中的完整 argv 精确匹配。允许 `npx`、`uvx`、`docker`、`node` 或 `python3` 的 basename 不再隐含允许任意包、镜像或脚本；参数顺序或任一值变化都会产生 `unapproved_mcp_invocation` 高危项。

0.23.0 起，策略热加载会完整校验对象、列表、正则和 MCP 调用结构；无效更新保持上一份有效策略并报告 `policy_reload_failed`。畸形 MCP Server、`args` 或 `env` 不再被静默忽略或中断扫描，而是产生明确高危发现项。

0.42.0 起，MDM 自定义合规增加 `AegisReportValid`。发现项严重度会在终端重新计数，且报告必须同时匹配已批准的 Agent 0.23.0、当前策略版本、设备标识格式和报告契约；旧版本或汇总不一致的报告无法再用于证明设备合规。

0.43.0 / Agent 0.24.0 起，Windows 周期任务每次扫描都会重新发现用户后来安装的 Codex 与 Claude Code，并以幂等方式创建或更新用户级安全编码基线。路径或托管标记异常时停止写入并产生高危发现，避免覆盖个人规则或经重解析点写出用户目录。

0.44.0 / Agent 0.25.0 起，Windows 在读取内容前独立发现 `SKILL.md`，因此超大清单不能绕过 `unknown_skill`。每个扫描根最多发现 500 个 Skill、每个 Skill 最多报告 100 个重解析点，项目候选文件遵循策略 `project_files`；任何截断都会生成可见发现项。

配置 `AEGIS_REPORT_URL` 和 `AEGIS_REPORT_TOKEN` 后启用上报。生产环境同时在终端和接收器配置相同的 `AEGIS_REPORT_SIGNING_SECRET`；每次请求使用当前时间戳和原始请求体计算 HMAC-SHA256，接收器只接受五分钟窗口内的有效签名。网络中断时报告会进入权限受限的本地 spool，补传时使用新的请求时间重新签名；同秒报告使用唯一文件名，损坏文件会被隔离，不再阻塞后续补传。Python 端默认最多保留 500 份待传报告（可用 `AEGIS_SPOOL_MAX_REPORTS` 设置 10–10000），Windows 端固定保留最近 500 份及 20 份损坏样本，超限时优先淘汰最旧文件。上报路径会把用户主目录替换为 `~`，明文密钥证据仅保留脱敏标记。密钥应由 MDM 的受保护配置流程注入，不要写入脚本或仓库。

0.53.0 / Agent 0.26.0 修复 MDM 周期任务无法继承安装进程环境变量的问题。Windows 使用 `aegis-configure-windows.ps1` 将 URL、Bearer 和 HMAC 密钥通过 DPAPI LocalMachine 加密到 `%ProgramData%\AegisAgent\reporting.dpapi`；任务以 SYSTEM 运行时自动解密，密钥不进入任务参数。macOS 的 `aegis-configure-macos.sh` 调用已安装自包含客户端的 `--configure-reporting`，无需外部 Python，原子写入固定目录的私有 0600 `reporting.json`，Agent 每次启动自动发现。需 root、受保护变量、独立密钥和无扩展 ACL 的受保护安装目录；拒绝自定义输出路径。轮换凭据或更换 URL 后，必须产生匹配新配置指纹的成功上报，健康诊断才认可；旧回执不再作为新配置的成功证据。配置命令只写配置，不自动入网、停服或改策略；详见仓库 `docs/MACOS-CONFIGURATION.md`。两种配置均要求无凭据、无查询参数的 HTTPS URL、两项独立且至少 32 字符的密钥；权限、所有者、契约或解密异常会产生 `reporting_config_invalid` 高危项并拒绝上报。配置脚本应通过 MDM 的受保护变量或企业密钥代理获取临时输入，切勿把真实值写入 MDM 脚本文本。

0.54.0 将 `AegisReportingConfigured` 纳入 Windows 与 macOS 的 MDM 自定义合规。Windows 发现脚本以 SYSTEM 实际执行 DPAPI 解密并重新验证 URL、字段集合和密钥边界；macOS 发现脚本验证 root 所有权、普通文件、0600 权限及相同契约。仅存在文件不能证明合规，复制其他设备的 DPAPI 文件、宽权限文件、损坏 JSON 或不安全 URL 均返回 false。生产分配顺序应先下发受保护上报配置，再启用这条合规规则，避免部署竞态造成短暂误报。

0.55.0 / Agent 0.27.0 在 Collector 返回成功后原子写入无密钥的 `aegis.upload-status/v1` 回执，仅包含成功时间和 Collector 主机。网络失败或本地排队不会刷新回执。`AegisReportingHealthy` 要求回执不超过 24 小时，且主机必须与当前受保护配置一致；旧 Collector 的成功记录不能掩盖配置切换后的故障。回执只证明最近一次 HTTP 接受，Collector 仍以签名验证、报告契约和服务端设备摘要作为最终事实源。

0.56.0 / Agent 0.28.0 要求 Collector 的 200/202 响应同时满足严格确认契约：字段必须恰好为 `accepted`、`duplicate`、20 位十六进制 `report_id` 和受限 `severity`，响应体不得超过 4 KiB。空 200、HTML 登录页、反向代理占位响应、附加字段或伪造报告 ID 都按上传失败处理，不刷新健康回执，并进入原有离线队列。该约束要求中间代理原样转发 Collector JSON，不得用统一成功页替换响应。

0.57.0 / Agent 0.29.0 / Collector 0.11 将 `report_id` 定义为本次 HTTP 原始请求体 SHA-256 的前 20 位。Agent 在发送前独立计算期望值，并以常量精确比较确认值；格式正确但不对应本次请求体的伪造回执同样失败。Collector 仍以规范化 JSON 摘要执行语义去重，因此相同报告采用不同空白格式重传时仍标记重复，但每次回执都绑定实际收到的字节。升级时必须先部署 Collector 0.11，再分批提升 Agent 0.29.0。

0.58.0 / Agent 0.30.0 / Collector 0.12 增加逐设备身份边界。Agent 发送 `X-Aegis-Device-ID`，并把该 ID 纳入 HMAC 输入；Collector 可通过 `AEGIS_DEVICE_CREDENTIALS_FILE` 加载最多 10000 台设备的独立 Token/HMAC 轮换集合，先按头部选择凭据，再要求已验证报告中的 `device_id` 完全一致。凭据文件拒绝符号链接、组写/其他用户权限、额外字段、重复密钥、Token/HMAC 复用和无效设备 ID。分三阶段启用：先部署 Collector 0.12 且保持该变量为空，再滚动升级全部 Agent 0.30，最后为每台设备生成独立凭据、以 `root:aegis` 0640 安装清单并设置变量。启用清单后，旧 Agent、未知设备、跨设备凭据及身份错配均返回 401；管理查询仍使用独立的全局 Collector Token。

Agent 0.31.0 收口逐设备入网的终端侧：Agent 现在按优先级解析上报凭据——`--enrollment-config`（或 `AEGIS_ENROLLMENT_CONFIG`）指定的每设备文件 > `--enrollment-dir`（或 `AEGIS_ENROLLMENT_DIR`）下与本机 `device_id` 同名的 `<device_id>.json` > 全网 `reporting.json`（向后兼容）。每设备入网文件为 `aegis.device-enrollment/v1`，与全网配置同等加固：拒绝符号链接、要求 0600 普通文件、属主为 root 或当前 euid、`device_id` 必须匹配 `[0-9a-f]{12}`、Token/HMAC 为互不相等的 32–4096 字符串。若入网文件的 `device_id` 与本机派生 ID 不符，Agent 产生 `enrollment_device_mismatch` 高危项并拒绝本轮上报；入网文件权限/属主/契约无效则产生 `enrollment_config_invalid`——两种情况都**绝不静默回退到全网共享密钥**。至此第三阶段可真正执行：用 `aegis_device_credentials.py` 为每台设备生成 enrollment 文件，经 MDM 分发到终端，并让 Agent 以 `--enrollment-dir` 指向该目录即可启用每设备独立凭据。

强制已签名策略（fail-closed，默认关闭）：默认情况下 Agent 仍接受未签名策略以兼容存量机群；当某机群已完成签名密钥分发后，可强制"只接受已签名策略"。该开关**只来自带外可信源、绝不读取（可能未签名的）策略体本身**，否则攻击者可自行降级——来源二选一：每设备入网文件的可选布尔字段 `require_signed_policy`，或环境变量 `AEGIS_REQUIRE_SIGNED_POLICY=1`（入网配置优先于 env）。开启后，未签名策略会被拒绝：冷启动时 Agent 直接退出（`valid Aegis policy is required`）；热加载时 fail-safe 回退上一份有效签名策略，并产出 `policy_reload_failed` 高危项（注明已启用强制验签）。这堵住了"能写本地策略文件者丢弃签名、放宽 `blocked_commands`/`allowed_*` 来静默降级强制力"的攻击。建议先用 `/api/policy/posture` 确认全部终端已在签名发布版本上，再经 MDM 灰度开启。

0.59.0 提供离线 `aegis_device_credentials.py`。以受管终端的 12 位 `device_id` 列表运行，并同时指定服务端清单和独立 enrollment 目录；工具使用系统 CSPRNG 生成每台设备互不复用的 Token/HMAC，原子写入 0600 文件，标准输出只含设备 ID 与计数，不含密钥。`--rotate` 生成新凭据并只保留上一代作为重叠窗口，先准备 endpoint enrollment 文件、最后切换服务端清单；完成 MDM 受保护变量分发并确认新凭据活跃后，使用 `--prune-old` 删除旧代。部署服务端清单时再设置 `root:aegis` 0640；enrollment 目录属于敏感暂存物，导入 MDM 后应按企业密钥介质流程销毁，不得提交 Git、工单或聊天。

0.60.0 修复在线轮换的文件元数据边界。新清单仍以 0600 创建；如果目标清单已存在且是合规的 0600 或 `root:aegis` 0640 普通文件，原子替换会保留其 owner、group 和 mode。替换前无法保留任一元数据时操作失败且旧清单不变，避免轮换后 Collector 因属组或读取位丢失而停服。Collector 与生成器均只接受精确 0600/0640，不再接受其他“看似私有”但不符合部署契约的模式。

0.61.0 / Collector 0.13 强制 Token 与 HMAC 必须来自同一凭据代次；“新 Token + 旧 HMAC”等交叉组合返回 401。每次成功接收（包括语义重复报告）都会更新设备认证代次，`/v1/summary` 返回 `credential_posture.current/previous/legacy`，`/v1/devices` 返回每台设备的 `credential_generation`，均不暴露凭据。裁剪旧代前，将认证后的 `/v1/devices` 响应保存为本地 JSON，并以 `--activation-evidence` 传给 `aegis_device_credentials.py --prune-old`；只有本次目标设备全部明确为 `current` 时才允许裁剪，缺失、重复、过大、结构异常或仍使用 previous/legacy 的证据均失败关闭。私有控制台的接收器代理会验证并展示该代次姿态。

0.62.0 / Collector 0.14 为 `/v1/devices` 增加 `generated_at`，逐设备 `last_seen` 在启用身份绑定后使用最近一次成功认证时间，因此相同报告重放也可证明新凭据已生效。裁剪工具只接受生成时间不超过 15 分钟、未来偏差不超过 60 秒的证据，并要求每台目标设备在证据生成前 24 小时内以 current 凭据成功认证。过期导出、长期离线终端或时间不一致均不能作为删除旧代的依据。

0.63.0 / Collector 0.15 为 `/v1/devices` 增加 `limit` 查询参数（1–10000，默认 500）及 `complete` 标志，并用单次聚合查询替代逐设备计数。全 fleet 裁剪前应请求 `/v1/devices?limit=10000`；只有结果未被截断时 `complete` 才为 true。凭据工具要求证据包含精确的 `complete:true`，因此默认 500 条导出、超出 10000 台的 fleet 或任何截断结果都不能被误当成全量激活证明。

## 4A 身份与会话运营手册（0.72.x）

控制台侧身份/会话/审计能力（服务端强制；UI 在「团队与权限」「审计日志」）：

- **角色（capability RBAC）**：服务端按 subject 推导，序 admin > operator > auditor > viewer，不信任 cookie。admin 全权（`AEGIS_ADMIN_USERS`+持久化）；operator（运维）仅 device:write+非审计只读（`AEGIS_OPERATOR_USERS` ∪ 持久化，团队页可加/移除，存 PG `settings.allowlist:operators`，未配置即无该档 fail-closed）；auditor 只读+审计查阅/导出；viewer 其余只读。
- **MFA(TOTP)**：团队页「我的两步验证」自助启用（enroll→展示 base32+otpauth URI→输码确认→启用）；启用后该账号登录为密码+6 位码两步，默认关闭不影响存量账号；密钥存 PG `mfa:<subject>`。无人值守/脚本场景勿对生产运维账号启用，避免锁死。
- **会话吊销**：团队页每行「吊销会话」或 `POST /api/auth/revoke {subject}`（仅 admin）；改密、移除白名单亦自动吊销该 subject 既有会话；经 `session_invalid_before:<subject>` 生效（≤30s 缓存窗口）。
- **审计导出**：审计日志页「导出 CSV / 导出 JSON」=`GET /api/audit?format=csv|json`（全量、合并 Collector+控制台两源、附件下载）；导出自身留审计 `audit:export`；仅 admin/auditor。
- **隐私门禁**：CI 跑 `scripts/privacy-scan.sh`，跟踪内容命中厂商名/真实主机/真实域名/工号/RFC1918/硬编码长密钥即失败；真实值一律经环境变量注入，仓库只留占位。

## 生产 serving 与可靠性手册（0.73.x）

控制台以 `wrangler dev --config /opt/aegis/console-server/wrangler.json` 常驻（self-hosted 无 Cloudflare 远端，workerd 本地运行时）。小内存盒上的运维要点：

- **NODE_ENV=production**：systemd unit 必须设 `Environment=NODE_ENV=production`，让 vinext 以生产 bundle 服务（关闭 dev 重编译/热更开销）。误设 development 会显著加重冷启与内存。
- **内存 sizing**：drop-in `limits.conf` 设 `MemoryHigh=1600M / MemoryMax=2400M`。冷启期 wrangler 需打包全部路由，峰值 ~1.3–1.5G；上限过低（如 1.5G）会在冷启时内存抖动→worker 长时间不 bind→公网 502/000（真实事故）。3.7G 盒上 2.4G 上限给冷启留足余量且仍受 cgroup 约束。
- **冷启预期**：首次 bind 可能需 1–4 分钟（小盒打包慢）。部署/重启后**不要**只看 `systemctl is-active`（进程在≠worker 在），要轮询 `curl 127.0.0.1:8787/login` 直到 200/307 才算就绪。
- **自愈看门狗**：`aegis-console-healthcheck.timer` 每 60s 探活 `127.0.0.1:8787/login`；**仅当** worker 不可用且服务已启动超过 240s（boot grace，避免把正常冷启误杀成重启循环）才 `systemctl restart aegis-console`。真实挂死自愈窗口 ≤ 探活间隔+grace 判定。改探活间隔/grace 时务必保持 grace > 最长冷启时间。
- **重启循环防护**：unit 已 `Restart=always / RestartSec=5`；看门狗 grace 是防"冷启被探活误杀→反复重启"的关键，勿删。
- **就绪预热（ExecStartPost）**：unit 加 `ExecStartPost=/bin/sh -c 'for i in $(seq 1 60); do code=$(curl -s -o /dev/null -w %{http_code} -m 5 http://127.0.0.1:8787/login); if [ "$code" = 200 ] || [ "$code" = 307 ]; then exit 0; fi; sleep 5; done; exit 0'`，使 `systemctl restart` 阻塞到 worker 真正可服务（超时仍 exit 0 不把服务判失败，真挂死交给看门狗）。**必须同时设 `TimeoutStartSec=360`**（默认 90s 小于 ExecStartPost 最长 300s 轮询，否则 restart 被 systemd 判 timeout 失败——真实踩过）。部署脚本/人工重启后无需再手动轮询就绪。
- **演练**：enforce 封禁/恢复演练用 `scripts/run_enforce_drill.py`（见下），在隔离的非豁免测试端点上验证 deny→quarantine→回执 与 un-deny→auto-restore→回执，绝不触碰豁免的开发主机。
