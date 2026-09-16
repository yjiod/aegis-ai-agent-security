# Aegis AI Agent Security

Aegis 是面向企业终端的 **AI Coding 安全治理**工具。它在员工电脑上随 AI 编码工具运行一个轻量 Agent，**只读**发现本机受管的 AI Agent / Skill / MCP，加载企业安全编码基线，扫描 Skill、MCP、代码质量、依赖与密钥风险，并上报到受认证的接收器（Collector）；私有控制台用于研判、处置、**签名策略下发**、版本态势与审计。

遵循**单端原则**：员工终端只安装 Aegis 一个 agent，其余平台（EDR / 桌管 / 开源安全栈）通过适配边界协同，不重复装探针。

**当前发行**：产品 `0.72.0` · Endpoint Agent `0.33.0` · 策略出厂 `4.8.0`（控制台发布件递增 `4.9.0+`）· Collector `0.15` · Adapter `0.7`。

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

> 另支持登记为「其他工具」。工具清单在三处保持同步：`aegis_agent.py` 的发现标记、`lib/store.ts` 的类型、控制台设备表单选项。

**平台**：macOS 与 Windows 提供原生安装器；Python Agent 亦可运行于 Linux。

---

## 控制台能力

| 页面 | 作用 |
| --- | --- |
| 总览 / 快速开始 | 实时安全态势；五步接入引导（连接接收器 → 部署 Agent → 研判 → 处置 → 基线下发） |
| 设备与 Agent | 终端清单、在线/覆盖、**版本姿态**（Agent/策略是否漂移） |
| 风险中心 | 工单队列与状态机（待处理→认领→调查→解决/驳回）、关联发现、**命中证据「详细信息」** |
| 处置中心 | 对 Skill / MCP 打标：加白 / 观察 / 拉黑，编译进下发策略 |
| Skill / MCP / 代码质量扫描器 | 分域查看**真实扫描发现**（严重度分布 + 命中溯源明细 + 链到处置） |
| 扫描引擎 | 内置引擎 + Semgrep / Gitleaks / Cisco skill-scanner / Snyk（引擎独立，不互转规则语法） |
| 策略配置 | **签名策略发布**（`aegis.policy/v1`，HMAC 签名 + 密钥环轮换），终端可拉取强制执行 |
| 基线管理 | 企业自定义编码基线导入 + 上游基线同步 |
| 审计日志 | 全操作留痕（含自动入网、策略发布、令牌轮换、认证/改密/吊销等）+ **合规导出 CSV/JSON** |
| 团队与权限 | 三级 RBAC：**管理员 / 审计员 / 只读**；按账号可选 **MFA(TOTP) 两步验证**；会话可吊销 |
| 系统设置 | 扫描模式（`quick` / `standard` / `custom`）等全局配置 |
| 接入中心 | Collector 连接与厂商适配（EDR / 桌管）集成 |

控制台基于 vinext（Next.js on Cloudflare Workers）+ PostgreSQL 持久化；未连接接收器时**诚实显示空态/演示模式，绝不伪造数据**。

---

## 终端零接触入网（装完即被纳管）

拿到客户端、连到正确的服务器地址，即**自动获得上报令牌与当前策略**，无需管理员手动逐台下发：客户端调用 `POST /api/enroll`（会话豁免、限流、审计、可选入网密钥门），取回上报令牌、每设备独立签名密钥与**去签名的已发布策略**（经 TLS 信任加载，不暴露签名/验签密钥）。

> 路线：签名策略强制 + 非对称验签密钥分发（Ed25519 公钥内嵌/公开端点分发、enroll 下发签名策略、每设备可吊销令牌）见设计稿 [`docs/4A-POLICY-INTEGRITY-DESIGN.md`](docs/4A-POLICY-INTEGRITY-DESIGN.md)，按 dual-sign → 强制两阶段灰度推进。

```bash
# macOS —— 原生 .pkg（双击安装；postinstall 自动入网 + 系统 LaunchDaemon，开机自启）
sudo installer -pkg aegis-agent-macos.pkg -target /

# macOS —— 自包含 .run（用户级，无需 sudo；内嵌运行时，离线可装）
AEGIS_SERVER_URL=https://你的控制台 sh aegis-agent-macos-standalone.run

# Windows —— 原生 .msi（双击或 msiexec 安装 → 注册 SCM 服务 AegisAgent，安装时零接触入网）
#   从控制台 /downloads/aegis-agent-windows.msi 获取（已烘焙你的服务器地址；wixl 交叉构建、自包含 .NET 服务壳）
msiexec /i aegis-agent-windows.msi

# Windows —— 或免安装器的入网脚本（管理员 PowerShell；DPAPI 受保护配置 + SYSTEM 计划任务）
.\aegis-agent-windows-enroll.ps1 -Server https://你的控制台
```

企业规模化下发亦可走 MDM / EDR（`mdm-*` 脚本）或离线企业包 `aegis-enterprise-bundle.zip`。详见[企业部署指南](public/downloads/DEPLOYMENT-GUIDE.md)。

---

## 扫描范围

- **Skill**：未批准 / 未签名 Skill；能力风险信号（`exec` / `cred` / `network` / `filewrite` + 综合分 0–6，≥4 高危），并回收**逐处命中证据**（文件:行:片段）供研判、避免误伤。
- **MCP**：传输协议、域名、命令与命令路径、精确调用白名单、URL 凭据、文件系统范围。
- **代码质量**：硬编码密钥、`shell=True`、动态执行（`eval`/`exec`）、弱随机令牌、被阻断命令、不安全 TLS 校验、不安全反序列化、调试模式、空异常处理、超大文件跳过等。
- **依赖**：清单清点 + 未固定版本、不可信/远程源、缺失锁文件。
- **密钥**：`AKIA…`、`sk-…`、`ghp_…` 等模式。

扫描模式 `quick` / `standard` / `custom` 门控范围；策略含 `limits`（文件数/大小/清单/发现上限）与 `enforcement`（unknown_skill / unknown_mcp / critical_finding）。

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

详见[架构与信任边界](docs/ARCHITECTURE.md)。

---

## 目录

- `public/downloads/`：终端 Agent、策略与基线、安装器（macOS `.pkg`/`.run`、Windows `.ps1`；Windows `.msi` 因体积经 nginx 静态直供）、MDM 脚本、配置/回滚/卸载、报告 Schema、Collector、厂商适配器、离线企业包。
- `app/`：私有治理控制台、只读 Collector 摘要代理、零接触入网端点（`/api/enroll`）、签名策略工件（`/api/policy/artifact`）。
- `lib/`：策略编译与签名、存储与持久化、鉴权与 RBAC。
- `components/`：控制台 UI 组件。
- `client/`：原生安装器构建——.NET 服务壳 `host/`（Windows SCM）、`AegisAgent.wxs`（wixl MSI）、`Install-Aegis-Windows.ps1`、`build-windows-msi.sh`。
- `scripts/`：部署、令牌轮转、macOS 原生包构建（`.run`/`.pkg`）、e2e 运行器。
- `migrations/`：PostgreSQL 迁移。
- `tests/`：Python 标准库测试；`e2e/`：Playwright 端到端。
- `docs/`：架构、开发、发布、术语与专项分析文档。

---

## 快速验证

```bash
npm ci
python3 -m unittest discover -s tests          # 扫描/报告/认证/合规/备份/发行完整性
for f in public/downloads/*.sh scripts/*.sh; do sh -n "$f"; done
npm run build                                   # 同时重打 macOS .run/.pkg（及 Windows .exe，若装了 NSIS）
python3 public/downloads/aegis_release_verify.py public/downloads   # 离线发行完整性
npx tsc --noEmit && npm run lint
scripts/run-e2e.sh                              # Playwright（demo 模式全量）
scripts/run-e2e.sh --live e2e/policy.spec.ts    # live 模式（真实 Collector，验证版本姿态/入网）
```

本地启动控制台：`npm run dev`。默认演示模式明确标识、不下发终端任务、不伪造数据；配置服务端 Collector 环境变量后，顶部摘要切换为真实只读数据。

---

## 文档

- [架构与信任边界](docs/ARCHITECTURE.md)
- [联合开发指南](CONTRIBUTING.md)
- [开发与测试流程](docs/DEVELOPMENT.md)
- [发行与部署流程](docs/RELEASE.md)
- [企业部署指南](public/downloads/DEPLOYMENT-GUIDE.md)
- [扫描模式与工具清单](docs/SCAN-MODES-AND-TOOLS.md)
- [风险信号术语](docs/RISK-SIGNAL-GLOSSARY.md)
- [单端推送原则](docs/SINGLE-ENDPOINT.md)
- [演进路线](docs/EVOLUTION-ROADMAP.md)
- [安全响应说明](SECURITY.md)

---

## 安全与隐私

- 真实 MDM / EDR / 桌管 / Collector 凭据，以及真实主机名、域名、IP **绝不入库**：公开仓库一律使用 RFC 保留占位（`aegis.example.com`、`203.0.113.7`、`192.0.2.x` 等），真实值仅存在于运行命令与服务端环境变量，安装/部署时注入。
- 密钥不写入脚本、策略、日志、审计表或发布包。
- 演示模式绝不展示虚构数字；无数据时如实显示空态。
