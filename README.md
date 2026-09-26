# Aegis AI Agent Security

Aegis 是面向企业终端的 **AI Coding 安全治理**工具。它在员工电脑上随 AI 编码工具运行一个轻量 Agent，**只读**发现本机受管的 AI Agent / Skill / MCP，加载企业安全编码基线，扫描 Skill、MCP、依赖与密钥风险（代码质量域出厂默认停用，详见[扫描范围](#扫描范围)），并上报到受认证的接收器（Collector）；私有控制台用于研判、处置、**签名策略下发**、版本态势与审计。

遵循**单端原则**：员工终端只安装 Aegis 一个 agent，其余平台（EDR / 桌管 / 开源安全栈）通过适配边界协同，不重复装探针。

**当前发行**：产品 `0.73.3`（channel `pilot`）· Endpoint Agent `0.37.3` · 策略出厂 `4.8.0`（控制台发布件按 `4.<8+n>.0` 递增，**具体已发布版本以控制台「策略配置」页显示为准**，属运行态不写死于文档）· Collector `0.15` · Adapter `0.7`。

> 版本号单一真源：Agent 见 `public/downloads/aegis_agent.py` 的 `AGENT_VERSION`，产品/发行见 `public/downloads/release.json`，策略出厂见 `public/downloads/aegis-policy.json`，Collector 见 `public/downloads/aegis_collector.py` 的 `server_version`，Adapter 见 `public/downloads/aegis_adapter.py` 的 `User-Agent`。改动上述任一文件时须同步本行。

---

## 支持的 AI Coding 工具

Agent 通过**只读文件标记**识别下列工具（不启动、不执行被发现的 Agent），发现其 Skill / MCP / 配置并纳入治理：

| 工具 | 标识 | 工具 | 标识 |
| --- | --- | --- | --- |
| Cursor | `cursor` | GitHub Copilot CLI | `github_copilot_cli` |
| Claude Code | `claude_code` | QwenWork / 通义千问 | `qwen_enterprise` |
| Codex CLI | `codex_cli` | 通义灵码 | `tongyi_lingma` |
| Windsurf | `windsurf` | CodeBuddy | `codebuddy` |
| Gemini CLI | `gemini_cli` | **WorkBuddy** | `workbuddy` |

> 另支持登记为「其他工具」。表中「标识」是**控制台侧**的规范枚举值（`lib/store.ts` 的 `AGENT_TYPES`）。

**工具清单当前有五处定义，且尚未完全同步（已知缺陷，修复中）**：

| # | 位置 | 作用 |
| --- | --- | --- |
| 1 | `public/downloads/aegis_agent.py` 的 `AGENT_HOME_MARKERS` / `AGENT_SYSTEM_MARKERS` | macOS / Linux 只读发现标记 |
| 2 | `public/downloads/aegis-windows.ps1` 的 `$agentMarkers`（及注册表/进程/厂商目录映射） | Windows 发现标记 |
| 3 | `lib/store.ts` 的 `AGENT_TYPES` | 控制台规范枚举 |
| 4 | `components/device-form.tsx` 的 `AGENT_TYPE_OPTIONS` | 设备表单选项与归一化 |
| 5 | `app/page.tsx` 的 `AGENT_LABEL` | 总览覆盖面板显示名 |

已知不一致（会在 UI 上可见）：

- **macOS / Linux 侧不发现 WorkBuddy**：上表 1 的两个标记字典各 9 个键，均无 `workbuddy`；Windows 侧（上表 2）有。macOS 上仍会扫描 `.workbuddy/` 下的 MCP 配置与 Skill（它们在 `AGENT_CONFIGS` / `SKILL_ROOTS` 中），但**不会**把 WorkBuddy 作为一项「已安装 AI 工具」上报，因此设备页与覆盖面板在 macOS 舰队上少计该工具。
- **Codex 标识两端不同**：终端上报的名字是 `codex`（上表 1 的字典键），控制台枚举与显示名用 `codex_cli`，且 `tools` 芯片按原始名直出，故总览「终端覆盖」可能显示原始标识 `codex` 而非「Codex CLI」。

**平台**：macOS 提供自包含原生 `.pkg`，Windows 提供原生 `.msi` 与免安装器入网脚本。两端扫描器是**各自独立的实现**——macOS 从 `aegis_agent.py` 冻结为自包含原生客户端，Linux 可运行 Python 源码，Windows 是 PowerShell 脚本（`aegis-windows.ps1`），同一功能两边各写一份，改动必须逐项 diff（历史上曾因 Windows 漏了扩展名白名单而产生 964 条文档误报）。Python Agent 亦可在 Linux 运行。

---

## 控制台能力

| 页面 | 作用 |
| --- | --- |
| 总览 / 快速开始 | 实时安全态势、版本姿态、技战法覆盖与活跃、处置效能指标；五步接入引导（连接接收器 → 部署 Agent → 研判 → 处置 → 基线下发） |
| 设备与 Agent | 终端清单、在线/覆盖、**版本姿态**（Agent/策略漂移与分维修复动作）、AI 工具覆盖矩阵、封禁回执、豁免与自更保护名单 |
| 风险中心 | 工单队列与状态机（待处理→认领→调查→解决/驳回）、统一筛选（等级/来源/终端/时间窗/超 SLA）、关联发现与命中证据、响应闭环与 Playbook |
| 处置中心 | 对 Skill / MCP / 代码路径 / 目录前缀打标：加白 / 观察 / 拉黑，编译进签名策略；发布前爆炸半径预览 |
| Skill / MCP / 代码质量扫描器 | 分域查看**真实扫描发现**（严重度分布 + 命中溯源明细 + 链到处置）。注意：**代码质量域默认无数据**——`modules.code_scan` 出厂为 `false`（代码扫描交由专业扫描器负责，终端不扫也不上报代码类发现），需在「策略配置 → 模块开关」显式打开才恢复 |
| 扫描引擎 | 引擎框架已实现的适配器：内置 `aegis-regex`、Semgrep、Gitleaks、Cisco skill-scanner、OSV.dev SCA、pip-audit（各引擎保持原生规则语法，不互转；上游均免 API Token）。**这些是框架侧适配器，终端 Agent 当前不调用它们**——终端扫描由 `aegis_agent.py` / `aegis-windows.ps1` 内置规则执行。页面另含规则更新管道遥测与 OWASP 技战法覆盖矩阵 |
| 策略配置 | 9 个模块开关 + **签名策略发布**（`aegis.policy/v1`，HMAC + Ed25519 双签、密钥环轮换、一键回滚）+ 灰度设置。终端拉取验签后加载；**拉黑（deny）是否在终端真正隔离/拒连由 `modules.skill_enforce` / `mcp_enforce` 决定，二者出厂为 `false`（只报告不拦截）** |
| 基线管理 | 企业自定义编码基线导入 + 上游基线同步 + **扫描模式切换**（`quick` / `standard` / `custom`）+ 企业级 MD 灰度推送 |
| 审计日志 | 双源合并留痕：Collector 终端/设备侧事件 + 控制台控制面与认证事件（策略发布、模块变更、令牌轮换、登录/改密/吊销等），字段经归一化后统一时间线排序 + **合规导出 CSV/JSON** + Ed25519 签名证据包（可独立验签）。因缺动作名或缺可信时间戳而被剔除的记录计入 `audit_incomplete_dropped` 并在包内披露，**不把过滤后的残缺审计包装成完整审计**。两条已知边界：① 审计**非完整历史**（Collector 单次读取有上限且无游标、控制台内存保留有上限），完整历史导出属待办；② `/api/audit` 已返回 `connected` 标识审计源是否可达，但**审计页尚未渲染该状态**，故源不可达时界面无提示（属已知缺口，待补） |
| 团队与权限 | **五档 RBAC**：管理员 / 运维工程师（终端管理）/ 审计员（只读 + 审计查阅）/ 开发者（仅本人设备）/ 只读访客；按账号可选 **MFA(TOTP) 两步验证**（绑定二维码）；会话可吊销 |
| 系统设置 | 全局配置（数据保留期 / 审计保留 / 审计封顶，实时读写 Collector 运行时配置）+ 告警推送（webhook / 邮件收件人、离线阈值、去重节流、投递可靠性）+ **自动纠偏**三开关（总开关 / 自动封禁 / 推送通知）。**扫描模式不在本页**，在「基线管理」 |
| 分发中心 | 首次安装（macOS `.pkg` / Windows `.msi` / 一键脚本，已烘焙服务器地址）+ 桌管热更推送包（SHA-256 校验）+ 自更新灰度（canary）面板 |
| 接入中心 | Collector 连接状态与厂商适配（Fleet / Wazuh / PacketFence 及商用 EDR / 桌管）健康探测、凭据配置与告警汇聚建单。另有 5 个对外集成预留端点（`/api/integrations/{health,events,inventory,subscribe,remediate}`）当前恒返回 501，供外部系统按 OpenAPI 契约先行开发 |

控制台基于 vinext（Next.js on Cloudflare Workers）+ PostgreSQL 持久化；未连接接收器时**诚实显示空态/演示模式，绝不伪造数据**。

---

## 终端零接触入网（装完即被纳管）

拿到客户端、连到正确的服务器地址，即**自动获得上报令牌与当前策略**，无需管理员手动逐台下发：客户端调用 `POST /api/enroll`（会话豁免、限流、审计、可选入网密钥门），取回上报令牌、每设备独立签名密钥与**去签名的已发布策略**（经 TLS 信任加载，不暴露签名/验签密钥）。

> 路线：签名策略强制 + 非对称验签密钥分发（Ed25519 公钥内嵌/公开端点分发、enroll 下发签名策略、每设备可吊销令牌）见设计稿 [`docs/4A-POLICY-INTEGRITY-DESIGN.md`](docs/4A-POLICY-INTEGRITY-DESIGN.md)，按 dual-sign → 强制两阶段灰度推进。

```bash
# macOS —— 原生 .pkg（双击安装；postinstall 自动入网 + 系统 LaunchDaemon，开机自启）
sudo installer -pkg aegis-agent-macos.pkg -target /

# Windows —— 原生 .msi（双击或 msiexec 安装 → 注册 SCM 服务 AegisAgent，安装时零接触入网）
#   从控制台 /downloads/aegis-agent-windows.msi 获取（已烘焙你的服务器地址；wixl 交叉构建、自包含 .NET 服务壳）
msiexec /i aegis-agent-windows.msi

# Windows —— 或免安装器的入网脚本（管理员 PowerShell；DPAPI 受保护配置 + SYSTEM 计划任务）
.\aegis-agent-windows-enroll.ps1 -Server https://你的控制台
```

Mac 新安装统一使用系统 `.pkg`；用户级 `.run` 已拒绝新安装，主构建停止生成。系统包要求 ARM64/x64 原生载荷，安装、启动和入网不再回退外部 Python。CI 保留的包目前为合成服务器地址的未签名候选，尚未完成生产发布及完整干净终端验收，详见 [Mac 验证边界](docs/MACOS-PACKAGE-VALIDATION.md)。

企业规模化下发的 MDM / EDR（`mdm-*` 脚本）及离线企业包见[企业部署指南](public/downloads/DEPLOYMENT-GUIDE.md)。Mac 合规检查和独立上报配置已迁入客户端自带的[健康诊断](docs/MACOS-DIAGNOSTICS.md)与[配置能力](docs/MACOS-CONFIGURATION.md)。[Mac MDM 安装入口](docs/MACOS-MDM-INSTALL.md)已改为系统工具验证整包摘要、批准发布者及公证结果后安装原生 pkg；签名公证正向实机验收仍待完成。旧用户级自动入网、回滚等入口仍需迁移，完成前不满足 [R7 交付要求](docs/MACOS-RUNTIME-CONTRACT.md)，不能用作免 Python 客户端的替代路径。

---

## 扫描范围

各域由策略 `modules` 独立门控。**出厂默认：`skill_scan` / `mcp_scan` / `deps_scan` 开，`code_scan` 关**（代码扫描交由专业扫描器负责，终端不扫也不上报代码类发现）。因此下表「默认」列标明生产开箱状态。

| 域 | 检出内容 | 门控开关 | 默认 |
| --- | --- | --- | --- |
| **Skill** | 未批准 Skill（按名字白名单判定）、Skill 符号链接越界、包超大/超文件数截断；未批准 Skill 另附能力风险信号（`exec` / `cred` / `network` / `filewrite` + 综合分 0–6，≥4 高危）与**逐处命中证据**（文件:行:片段）供研判、避免误伤 | `skill_scan` | 开 |
| **MCP** | 传输协议、域名、命令与命令路径、精确调用白名单（完整 argv）、URL 内嵌凭据、明文敏感环境变量、文件系统范围、残缺/非法服务定义 | `mcp_scan` | 开 |
| **依赖** | 清单清点、不可信/远程源、引用外部清单、清单无法安全解析 | `deps_scan` | 开 |
| **代码质量** | `shell=True`、动态执行（`eval`/`exec`）、不安全 TLS 校验、不安全反序列化、调试模式、空异常处理、弱随机令牌、被阻断命令、超大文件跳过 | `code_scan` | **关** |
| **代码内密钥** | `AKIA…`、`sk-…`、`ghp_…` 等策略 `secret_patterns` 模式（测试/夹具路径降级为中危） | `code_scan` | **关** |

已知口径细节（避免误读上表）：

- **「未批准」是按名字白名单判定，不是签名校验**：终端只比对 Skill 目录名是否在策略 `allowed_skills` 中，**当前没有 Skill 签名/摘要校验**。命中白名单名字的 Skill 会跳过 `unknown_skill` 判定与风险信号打分（即预置加白名单内的 Skill 不产出发现）。签名/来源绑定属规划中能力。
- **`deps_scan` 开但两个依赖类发现默认不上报**：`dependency_unpinned` 与 `missing_lockfile` 同时被列在终端的 `CODE_QUALITY_KINDS` 兜底过滤名单里，`code_scan` 关闭时会在上报前被剔除。因此默认状态下依赖域实际只有「不可信/远程源、引用外部清单、清单解析失败」三类可见。这是两个开关的交叉副作用，已记录待修。
- **`code_scan` 关闭同时关掉了 Skill/Agent 治理类信号**：`prompt_override`、`credential_access`、`hidden_instruction`、`context_poisoning`、`unbounded_shell`、`unvalidated_llm_execution` 与代码质量规则同产于终端的 `scan_text`，且该函数整体受 `code_scan` 门控，故默认状态下这些信号也不产出。拆分「治理组恒开 / 代码质量组受门控」已在演进计划中。

扫描模式 `quick` / `standard` / `custom` 进一步门控代码质量规则集（详见[扫描模式与工具清单](docs/SCAN-MODES-AND-TOOLS.md)）；策略另含 `limits`（项目文件数 / 单文件字节 / 清单条目 / 发现数上限）。

> 策略体中还有 `enforcement`（`unknown_skill` / `unknown_mcp` / `critical_finding`）字段，**当前终端不消费它**：Agent 读出 `unknown_skill` 的取值后未据此采取任何动作，`critical_finding` 在终端代码中无任何引用。真实的终端强制路径是 `deny.skills` / `deny.mcp` 名单配合 `modules.skill_enforce` / `mcp_enforce`（隔离 Skill、移除 MCP 配置、终止进程、拒绝执行、macOS 出站封禁），且这两个开关出厂为 `false`。

---

## 架构与信任边界

```
员工终端 Agent（只读发现 + 扫描 + 上报）
        │  HMAC 签名报告 / 每设备或全局令牌
        ▼
Collector（受认证报告汇聚，/v1/*，SQLite，速率限制 + 审计）
        │  接收器 / 设备 / 发现
        ▼
控制台（vinext + PostgreSQL；摘要代理、签名策略发布、工单/处置、RBAC、审计）
        │  单向适配边界（凭据隔离）
        ▼
厂商 EDR / 桌管 / 开源安全栈
```

详见[架构与信任边界](docs/ARCHITECTURE.md)及[产品硬约束与验收契约](docs/PRODUCT-REQUIREMENTS.md)。后者包含长期高可用与容量、完整 API、全自动纠偏、封禁优先级和问题去重要求。当前开源版保留 4A 接口，不强制接入、不继续扩展；未来企业版仍需完成 4A 对接。这些要求不代表能力已全部验收。

---

## 目录

- `public/downloads/`：终端 Agent、策略与基线、安装器（macOS 系统 `.pkg`、Windows `.ps1`；Windows `.msi` 因体积经 nginx 静态直供）、MDM 脚本、配置/回滚/卸载、报告 Schema、Collector、厂商适配器、离线企业包。
- `app/`：私有治理控制台、只读 Collector 摘要代理、零接触入网端点（`/api/enroll`）、签名策略工件（`/api/policy/artifact`）。
- `lib/`：策略编译与签名、存储与持久化、鉴权与 RBAC。
- `components/`：控制台 UI 组件。
- `client/`：原生安装器构建——.NET 服务壳 `host/`（Windows SCM）、`AegisAgent.wxs`（wixl MSI）、`Install-Aegis-Windows.ps1`、`build-windows-msi.sh`。
- `scripts/`：部署、令牌轮转、macOS 系统包构建（`.pkg`；旧 `.run` 构建器待移除）、e2e 运行器。
- `migrations/`：PostgreSQL 迁移。
- `tests/`：Python 标准库测试；`e2e/`：Playwright 端到端。
- `docs/`：架构、开发、发布、术语与专项分析文档。

---

## 快速验证

```bash
npm ci
python3 -m unittest discover -s tests          # 扫描/报告/认证/合规/备份/发行完整性
for f in public/downloads/*.sh scripts/*.sh; do sh -n "$f"; done
npm run build                                   # Mac 主机构建 .pkg 需已准备双架构原生客户端；不再构建旧 .run
python3 public/downloads/aegis_release_verify.py public/downloads   # 离线发行完整性
npx tsc --noEmit && npm run lint
scripts/run-e2e.sh                              # Playwright（demo 模式全量）
scripts/run-e2e.sh --live e2e/policy.spec.ts    # live 模式（真实 Collector，验证版本姿态/入网）
```

本地启动控制台：`npm run dev`。未配置服务端 Collector 环境变量时，控制台如实显示「接收器未连接」与各页空态，**不注入任何演示数据**（仓库内虽保留历史 seed 定义，但已无调用方，不会渲染）；配置后顶部摘要与全部列表切换为真实只读数据。

---

## 文档

**入门与流程**

- [架构与信任边界](docs/ARCHITECTURE.md)
- [联合开发指南](CONTRIBUTING.md)
- [开发与测试流程](docs/DEVELOPMENT.md)
- [发行与部署流程](docs/RELEASE.md)
- [企业部署指南](public/downloads/DEPLOYMENT-GUIDE.md)
- [安全响应说明](SECURITY.md)

**产品口径**

- [扫描模式与工具清单](docs/SCAN-MODES-AND-TOOLS.md)
- [风险信号术语（人话版）](docs/RISK-SIGNAL-GLOSSARY.md)
- [Skill / MCP 研判分析](docs/SKILL-MCP-DETAIL-ANALYSIS.md)
- [Skill 策略分析](docs/SKILL-POLICY-ANALYSIS.md)
- [单端推送原则](docs/SINGLE-ENDPOINT.md)
- [演进路线](docs/EVOLUTION-ROADMAP.md)

**架构设计与规模化**

- [高可用与 30k 规模化架构](docs/HA-ARCHITECTURE.md)
- [发现聚合端点扩展（P1-1）](docs/SCALE-P1-1-FINDINGS-AGGREGATE.md)
- [4A 与策略完整性设计](docs/4A-POLICY-INTEGRITY-DESIGN.md)
- [UAC / SSO 集成](docs/UAC-INTEGRATION.md)
- [厂商集成（EDR / 桌管 / NAC）](docs/VENDOR-INTEGRATION.md)
- [开源选型验证报告](docs/OPEN-SOURCE-VALIDATION-REPORT.md)

**运维**

- [控制台服务化部署与 504 分诊](docs/CONSOLE-SERVING.md)
- [舰队告警体系](docs/FLEET-ALERTING.md)
- [Canary 灰度发布 + Enforce 演练 Runbook](docs/CANARY-DRILL-RUNBOOK.md)
- [服务端运维单元说明](ops/README.md)

---

## 安全与隐私

- 真实 MDM / EDR / 桌管 / Collector 凭据，以及真实主机名、域名、IP **绝不入库**：公开仓库一律使用 RFC 保留占位（`aegis.example.com`、`203.0.113.7`、`192.0.2.x` 等），真实值仅存在于运行命令与服务端环境变量，安装/部署时注入。
- 密钥不写入脚本、策略、日志、审计表或发布包。
- 演示模式绝不展示虚构数字；无数据时如实显示空态。
