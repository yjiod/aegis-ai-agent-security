# 扫描模式与工具清单（阶段 E）

> 扫描模式由用户选择，存全局设置（`settings.scan_mode`）并写入策略 `scan_mode`；Agent 按模式门控扫描范围。
> 自定义基线（`baselines` source=custom）与上游基线（source=upstream）合并生效，同 id 自定义优先。

## 一、扫描模式定义

| 模式 | 范围 | 典型耗时 | 适用 |
|---|---|---|---|
| **quick** | 密钥(Gitleaks 类规则) + 依赖(Trivy 类: 漏洞/未固定/远程源) | 秒级 | CI 每次提交、PR 门禁 |
| **standard** | quick + 核心 SAST(Semgrep 规则集: 注入/反序列化/弱加密/调试模式/空异常) | 分钟级 | 日常开发扫描（默认） |
| **deep** | standard + 污点/数据流(CodeQL) + AI 审查(LLM 误报分诊 + AI PR 安全审查) | 较慢 | 发版前 / 安全专项 |
| **custom** | 仅启用 `custom_baseline_rules` 指定的规则 id | 视规则 | 企业自定义基线强制项 |

Agent 门控（`aegis_agent.py`）：quick→跳过代码质量规则；custom→仅 custom_baseline_rules；standard/deep→code_rules。

## 二、工具清单（Fortify 之外，按模式映射）

### 开源 SAST / 依赖 / 密钥
| 工具 | 语言/对象 | 映射模式 | 说明 |
|---|---|---|---|
| **Semgrep** | 多语言规则即代码 | standard/deep | 规则集可导入为自定义基线；CI 友好 |
| **CodeQL** | 多语言污点/数据流 | deep | 深度分析；需 build db |
| **Gitleaks** | 密钥/令牌 | quick+ | git 历史+工作区密钥 |
| **Trivy** | 依赖/镜像/IaC/密钥 | quick+ | 漏洞+未固定+远程源 |
| **Bandit** | Python | standard | Python 专项 |
| **gosec** | Go | standard | Go 专项 |
| **SpotBugs+FindSecBugs** | Java/JVM | standard | JVM 专项 |
| **ESLint-plugin-security** | JS/TS | standard | 前端/Node 专项 |
| **Brakeman** | Ruby | standard | Rails 专项 |
| **ShellCheck** | Shell | standard | 脚本专项 |

### AI 增强（deep 模式）
| 能力 | 实现 | 说明 |
|---|---|---|
| **LLM 误报分诊** | Semgrep/CodeQL 结果 → LLM 判定真/误报 | 降低告警疲劳 |
| **AI PR 安全审查** | Codex/Gemini/Claude 对 diff 做安全审查 | 发版前人工+AI 双审 |
| **自定义基线生成** | LLM 从企业规范文档抽取规则 id/标题/严重度 | 导入为 custom 基线 |

## 三、自定义基线 + 上游同步
- 导入：`POST /api/baselines {name, rules:[{id,title,severity,mode}], scan_modes?}`（admin）。
- 上游同步：`POST /api/baselines/sync {url}` 拉上游基线全文存为 source=upstream；定时任务可周期调用。
- 生效：`effectiveRules()` = upstream + custom 合并（同 id custom 覆盖）；推送给客户端经策略/发行通道（`scan_mode` + `custom_baseline_rules` 已在策略中）。
- 模式切换：`PUT /api/settings/scan-mode {mode}`（admin），`GET` 查询；可选值 quick/standard/deep/custom。
