# Sentinel 动态规则更新指南

## 目标

Sentinel 5.0 策略把规则更新拆成两个边界：第三方上游仅提供候选情报或独立扫描引擎；企业审核通过的 `sentinel-policy.json` 才是终端可执行策略。终端不得直接从 GitHub、PyPI、npm 或任意 MCP Server 拉取并执行规则。

## 已接入的长期规则源

| 上游 | 用途 | 接入方式 | 自动发布 |
|---|---|---|---|
| Cisco AI Defense Skill Scanner | Skill 静态、YARA-X、AST、数据流检测 | 固定发行版，可选本地引擎 | 否 |
| Cisco AI Defense MCP Scanner | MCP 工具投毒、能力与连接风险 | 固定发行版，仅沙箱验证 | 否 |
| Semgrep Community Rules | 多语言 SAST | 保留 Semgrep 原生 YAML 语义 | 否 |
| Gitleaks Core | 密钥与令牌检测 | 固定发行版；不使用商业许可 Action | 否 |
| Snyk Agent Scan | Skill/MCP 风险补充 | 需安全、法务及 API 用量审批 | 否 |
| OWASP Agentic Applications 2026 | 治理映射 | 标准条目映射，不执行 | 否 |

许可证和服务条款可能变化。每次引擎晋级都必须重新记录上游版本、许可证摘要、制品 SHA-256、SBOM/签名状态和审批人。

## 更新管道

1. `sentinel_rule_updater.py` 每日读取固定的 `sentinel-rule-sources.json`，仅访问允许的 HTTPS API 主机。
2. 上游元数据写入 `/var/lib/sentinel/rule-source-status.json`，状态固定为 `quarantined`；该步骤不下载可执行文件、不启动 MCP Server、不修改生产策略。
3. 安全工程在隔离 CI/虚拟机中固定版本和摘要，执行许可证、恶意样本、误报、性能、SARIF/JSON 契约及离线行为测试。
4. 通过评审的检测逻辑转换为 Sentinel `custom_rules`，或作为保持原生语义的可选引擎发布。不同规则语言不得自动降级为通用正则。
5. 发行构建重新生成完整 SHA-256 清单并完成跨平台测试后，将新策略原子部署到 Collector 的 `SENTINEL_POLICY_FILE`。
6. macOS/Linux 与 Windows 客户端通过同一受认证 Collector 的 `GET /v1/policy` 拉取策略，同时验证 HTTPS、SHA-256、独立策略 HMAC、Schema 和版本单调性后原子替换。失败、缺少签名或降级时继续使用 last-known-good。

## 策略签名与轮换

Collector 从 root 所有、0600/0640 的 `/etc/sentinel/policy-signing-keys.json` 读取 `sentinel.policy-signing-keys/v1` 密钥环，首个密钥用于签发，最多五个密钥用于平滑轮换。设备注册 v3 将同一轮换窗口的验证密钥写入受保护的 `sentinel.reporting/v2`；这些密钥必须与上报 Token、报告签名密钥和审批回调密钥相互独立。轮换顺序是先让终端同时信任新旧密钥，再切换 Collector 首密钥，确认全量活跃设备完成注册更新后移除旧密钥。

本阶段使用独立 HMAC 信任域，解决摘要可被同源攻击者一并替换的问题，但共享验证密钥不等同于公钥代码签名或硬件密钥保护。生产演进应将签发端迁移到离线/受管 KMS 的非对称签名，终端只持有公钥；当前包不得宣称具备该能力。

## 安全边界

- MCP 扫描默认只解析配置。需要连接或启动 stdio Server 的第三方扫描必须放在一次性沙箱内，并逐项审批命令、参数、环境和文件范围。
- Snyk Agent Scan 的云分析需要令牌并受使用条款和规模限制；未完成审批时只跟踪版本，不上传 Skill 或 MCP 内容。
- Semgrep Community Rules 使用独立 Semgrep Rules License；企业法务批准前不得把其规则复制进自有许可包。
- Gitleaks 核心扫描器与 Gitleaks GitHub Action 许可证不同；本方案只跟踪核心项目。
- 客户端仅信任配置的 Collector，不接受任意策略 URL、跳转、版本降级、缺失摘要或缺失/无效 HMAC 的响应。旧版 reporting v1 终端可继续上报，但在重新注册前不接收远程策略更新。

## systemd

将同步器、源目录、service 和 timer 放入清单声明路径后启用 `sentinel-rule-update.timer`。同步器服务使用非特权 `sentinel` 用户、只读系统和唯一可写状态目录。它只生成候选状态；策略发布仍需发行门禁。
