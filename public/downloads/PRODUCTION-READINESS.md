# Sentinel 生产就绪与联合验收清单

本清单把代码门禁与必须在客户环境完成的操作分开。所有命令在解压后的发行目录执行；不得把真实令牌、主机名、设备 ID、报告正文或签名私钥提交到 Git。每项证据应进入企业审计系统，并记录发行版本、Git 提交、执行时间、操作者和审批人。

## 1. 发行物接收

责任人：安全工程、制品管理员。

1. 从私有控制台下载 `sentinel-enterprise-bundle.zip`，在隔离目录解压。
2. 运行 `python3 sentinel_release_verify.py .`，结果必须为 `{"ok":true,"errors":[]}`。
3. 记录 `release.json`、`RELEASE-MANIFEST.sha256` 和 ZIP 自身 SHA-256。
4. Windows 生产环必须在隔离签名工作站运行 `sentinel-sign-intune.ps1`，并重新执行发行验证；试点未签名包不得晋级生产。

失败回退：停止导入，不修改 Intune、EDR、联软或 Collector；重新获取与 Git 提交绑定的完整包。

## 2. Collector 上线

责任人：平台运维、安全运营。

1. 依据 `DEPLOYMENT-GUIDE.md` 创建专用无登录服务账号、受限配置目录、systemd 服务和反向代理。
2. 分别生成 Bearer、报告 HMAC 和逐设备凭据；三类密钥必须独立，长度至少 32 字符，并通过受保护渠道注入。
3. 执行 `sentinel_collector_probe.py`，验证健康检查、认证、签名、重复上报、摘要、大小限制和限流。
4. 验证备份、恢复候选库、每日维护 timer、保留期和数据库 `quick_check`。
5. 控制台仅配置 Collector 精确 HTTPS URL、精确允许主机和服务端令牌；浏览器不得收到令牌。

通过证据：探针回执、反向代理配置审查、systemd 加固输出、备份恢复演练、控制台只读摘要。失败回退：撤销代理路由并停止服务，保留数据库和审计记录，不删除失败现场。

## 3. Intune 分阶段部署

责任人：终端管理、安全工程、业务代表。

1. 按 `intune-deployment-manifest.json` 固定的顺序导入安装、检测、修复、合规与回滚制品；Windows 以 SYSTEM、macOS 以 root 运行。
2. 通过受保护配置下发 Collector URL 和逐设备凭据，禁止把秘密写入脚本、策略或命令行。
3. 依次使用 lab 1%、pilot 5%、broad 25%、production 100% 环；不得跳环或缩短观察期。
4. 从 Microsoft Graph 导出原始状态后运行 `sentinel_intune_graph_normalize.py`，再运行 `sentinel_intune_evidence.py` 生成最小聚合证据。
5. 对下一环运行 `sentinel_intune_preflight.py`。只有全部门禁通过，且生产签名、上报覆盖、合规覆盖、失败率、回滚演练和高危风险均满足清单要求时才能晋级。

每个环必须抽样验证：新增 AI Agent 自动发现、用户和仓库基线加载、Skill/MCP/代码扫描、24 小时内上报、离线重试、升级、回滚和卸载。失败回退：停止扩圈，下发对应平台回滚；若恢复校验失败，保持周期任务停止并进入人工修复组。

## 4. 深信服 EDR 验收边界

责任人：EDR 管理员、安全运营、厂商技术负责人。

1. 厂商确认现网产品版本、正式 OpenAPI 路径、鉴权头、字段长度、枚举、幂等行为、限流和超时。
2. 在禁用目标配置下运行 Adapter dry-run，审查最小事件投影；终端不得直连 EDR 管理面。
3. 预生产仅用 `sentinel_vendor_probe.py --live` 的强制 `observe` 动作发送两份相同载荷，禁止隔离、查杀或封禁。
4. 将探针回执写入 v2 验收证据，由安全与厂商审批后，使用独立密钥生成 v3 签名证据。
5. 用 `sentinel_vendor_preflight.py` 验证端点、Adapter 版本、24 小时时效、幂等回执、动作和签名，再允许 Worker 启动。

生产安全动作只能保持 `*_pending_approval`，由既有响应平台审批执行。失败回退：禁用该目标；其 spool 与派发账本保留，其他通道继续运行。

## 5. 联软桌管验收边界

责任人：桌管管理员、安全运营、厂商技术负责人。

1. 厂商确认 UniAccess/LeagView 现网版本、资产映射键、软件分发状态、合规枚举、准入策略和正式 API。
2. 先以软件资产/观察模式验证 Sentinel 安装和策略版本，不启用准入阻断。
3. 用 `sentinel_vendor_probe.py --live` 只发送正常合规姿态并验证重复请求接受能力。
4. 完成 v2 审批、v3 签名和 `sentinel_vendor_preflight.py` 后才启用 Worker 目标。
5. 准入限制必须在误报率、离线设备、例外组和紧急解除流程经过业务审批后单独启用。

失败回退：关闭联软目标或观察规则，不删除 spool；通过 Intune/联软分发原回滚包，不直接改写终端运行文件。

## 6. 日常运营与变更

责任人：安全运营、平台运维、开发维护者。

- 每日：检查 Collector 健康、版本姿态、上报覆盖、关键/高危发现、spool 满载和厂商派发失败。
- 每周：抽查匿名设备姿态、备份可恢复性、凭据代次和审计保留；禁止在控制台伪造终端写操作。
- 每次发行：从短生命周期分支更新代码、测试、文档和 `release.json`，运行 `npm run release:build`，通过三平台 CI 后推送同一提交到私有 Sites。
- 密钥轮换：先并存新旧值，分批更新终端或 Worker，确认旧代次不再活跃后删除旧值；不得复用不同信任边界的密钥。
- 安全事件：保全报告摘要、审计记录、幂等键、派发状态和版本信息；任何日志与工单不得包含令牌或完整敏感代码。

## 7. 生产签署记录

以下项目没有客户环境证据时必须标记为“未完成”，不得用本地测试或 CI 替代：

| 项目 | 必需证据 | 责任人 | 结果 |
|---|---|---|---|
| Collector 生产 TLS 与密钥注入 | 探针、配置审查、轮换演练 |  | 未完成 |
| Intune lab/pilot/broad/production | v3 晋级证据与预检输出 |  | 未完成 |
| Windows/macOS 真实终端升级回滚 | MDM 执行记录与合规结果 |  | 未完成 |
| 深信服现网 API | 24 小时内 v3 厂商验收证据 |  | 未完成 |
| 联软现网 API 与观察规则 | 24 小时内 v3 厂商验收证据 |  | 未完成 |
| 生产控制台 Collector 连通 | 只读摘要与无秘密浏览器检查 |  | 未完成 |

最终批准：安全负责人、终端管理负责人、平台运维负责人和业务代表均签署后，才能把发行标记为生产可用。

将上述实测结果填写到 `production-acceptance-evidence.example.json` 的副本。每个 `checks` 项必须绑定对应外部验收记录的 SHA-256；每个审批项必须填写审批人身份，并绑定审批记录 SHA-256。替换发行清单 SHA-256、Git 提交、Sites 版本和时间戳后，在受保护的签名工作站从密钥系统注入 `SENTINEL_PRODUCTION_ACCEPTANCE_SIGNING_KEYS`，运行 `python3 sentinel_production_evidence_sign.py --evidence <已审查未签名证据.json> --key-id <当前密钥ID> --output <已签名证据.json>`。密钥不得写入文件、命令参数、日志或工单。

随后运行 `python3 sentinel_production_preflight.py <已签名证据.json> --expected-git-commit <从 GitHub 核验的完整 SHA> --expected-site-version <从 Sites 核验的版本号>`。预期值必须来自两个系统的独立只读查询而不是证据文件本身；只有输出 `{"ok":true,"errors":[]}` 才构成最终机器门禁。模板默认全部为 false、摘要为空且没有有效签名，不能直接通过。密钥轮换时可短期并存最多五个 key ID；确认所有有效证据已迁移后才退役旧密钥。
