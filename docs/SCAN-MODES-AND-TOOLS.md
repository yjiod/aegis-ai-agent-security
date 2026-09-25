# 扫描模式与工具清单

> 扫描模式由管理员在控制台**「基线管理」页**选择（不在「系统设置」页），存全局设置 `settings.scan_mode` 并写入策略 `scan_mode`；终端 Agent 按模式门控**代码质量规则集**。
> 自定义基线（`baselines` source=custom）与上游基线（source=upstream）合并生效，同 id 自定义优先。
>
> **本文档描述的是已发布的实际行为。** 历史上此页曾记录 `deep` 模式与一批尚未接入的第三方工具，已按磁盘事实更正；规划中的能力见 [演进路线](EVOLUTION-ROADMAP.md)。

---

## 一、前置：`modules.code_scan` 决定代码质量域是否运行

扫描模式只在**代码质量域内部**起作用，而该域整体受策略开关 `modules.code_scan` 门控：

| `modules.code_scan` | 行为 |
|---|---|
| `false`（**出厂默认**） | 终端不执行代码文本扫描，且上报前剔除全部代码质量类 kind（`CODE_QUALITY_KINDS`，兜底防旧策略/篡改）。此时**下述任何扫描模式都不产出代码质量发现** |
| `true` | 按 `scan_mode` 门控规则集，产出代码质量发现 |

出厂默认关闭是产品决策：代码扫描交由专业扫描器负责，终端专注 Skill / MCP / 依赖治理。开关位于控制台「策略配置 → 模块开关」，改动需重新发布签名策略才下发终端。

Skill 身份与 MCP 域不受 `code_scan` 影响，分别由 `modules.skill_scan` / `modules.mcp_scan` 门控（出厂均为 `true`）。

> 已知交叉副作用（待修）：`dependency_unpinned` 与 `missing_lockfile` 虽属依赖域（`modules.deps_scan`，出厂 `true`），但也被列入 `CODE_QUALITY_KINDS`，因此 `code_scan=false` 时会在上报前被一并剔除。

---

## 二、扫描模式定义

可选值共 **3 档**（`lib/baselines.ts` 的 `SCAN_MODES`），默认 `standard`：

| 模式 | 代码质量规则集 | 典型耗时 | 适用 |
|---|---|---|---|
| **quick** | 空集（`enabled = set()`）——跳过全部 `quality_checks` | 秒级 | 只要 Skill/MCP/依赖清点，不要代码质量噪声 |
| **standard**（默认） | 策略 `code_rules` 全集 | 分钟级 | 日常扫描 |
| **custom** | 仅 `custom_baseline_rules` 中**且属于 `code_rules`** 的规则 id | 视规则 | 企业自定义基线强制项 |

终端门控实现见 `public/downloads/aegis_agent.py` 的 `scan_text()`：读取 `policy.scan_mode`，`quick` → 空集；`custom` → `custom_baseline_rules`；其余 → `code_rules`。

**两条 fail-safe（避免"静默关闭扫描"）**：

1. 终端侧：`custom` 模式下若 `custom_baseline_rules` 为空，回落为 `code_rules`，而不是扫零条规则。
2. 控制台侧：`POST /api/policy/publish` 在 `scan_mode=custom` 且无可执行规则时返回 **409 `custom_mode_has_no_enforceable_rules`**，拒绝签发一份等于"关闭扫描"的策略。

> `deep` 模式（污点/数据流 + AI 审查）**已从产品移除**（见 `public/downloads/release.json` 的 `scan_mode_deep_removed`），`lib/baselines.ts` 的 `SCAN_MODES` 不含该值，终端也无对应分支。请勿再按四档模式设计集成。

---

## 三、引擎与工具的真实状态

### 3.1 引擎框架已实现的适配器

`public/downloads/aegis_engine_framework.py` 提供统一的 `ScanEngine` 协议与下列适配器，控制台「扫描引擎」页展示的就是这份注册表：

| 引擎 | 版本来源 | 范围 | 模式 | 上游规则源 | 是否需 Token |
|---|---|---|---|---|---|
| `aegis-regex` | 硬编码 `1.0.0` | skill / mcp / code / secrets | local | 内置 | 否 |
| `semgrep` | 运行时 `check_version()` 探测 | code / secrets | local | `semgrep.dev/c/p/default` | 否 |
| `gitleaks` | 运行时探测 | secrets | local | `github.com/gitleaks/gitleaks` | 否 |
| `cisco-skill-scanner` | 运行时探测 | skill / mcp | local | `github.com/cisco-ai-security/skill-scanner` | 否 |
| `osv-sca` | 硬编码 `1.0` | deps | cloud | `osv.dev` | 否 |
| `pip-audit` | 运行时探测 | deps | local | `pypi.org/project/pip-audit` | 否 |

> Snyk 适配器**已移除**（需 API Token），由免 Token 的 `osv-sca` + `pip-audit` 替代。

### 3.2 重要边界：框架适配器当前不被终端调用

上述适配器是**引擎框架侧**的实现，供框架/测试与未来集成使用。终端 Agent（`aegis_agent.py` / `aegis-windows.ps1`）**不调用其中任何一个**——终端扫描由内置规则（正则 + 结构化解析）执行；在这两个终端文件中检索 `semgrep` / `gitleaks` / `pip-audit` / `osv` 均无命中。框架文件本身在仓库内的引用方只有测试与发行完整性校验（`tests/test_aegis.py`、`public/downloads/aegis_release_verify.py`）。控制台侧仅「扫描引擎」页以静态注册表形式列出这些名称用于展示，不构成调用。

因此：

- 「扫描引擎」页的 `builtin: true` 含义是**框架已实现该适配器**，不是"已在本机安装并可用"；版本标为「运行时探测」的项，控制台没有探测 API，故不写死版本号（历史上曾写死 `1.89.0` / `8.21.2` 属虚构，已移除）。
- 该页的「同步规则库」「全量扫描」按钮为禁用态并附原因说明，不是可执行能力。

### 3.3 曾评估但未实现的工具

以下工具出现在早期选型评估中（见 [开源选型验证报告](OPEN-SOURCE-VALIDATION-REPORT.md)），**当前代码库无任何实现或调用**，不应被理解为产品能力：

CodeQL（污点/数据流）、Trivy（依赖/镜像/IaC）、Bandit（Python）、gosec（Go）、SpotBugs + FindSecBugs（Java）、ESLint-plugin-security（JS/TS）、Brakeman（Ruby）、ShellCheck（Shell）。

同样未实现的 AI 增强能力：LLM 误报分诊、AI PR 安全审查、从企业规范文档自动抽取基线规则。

---

## 四、自定义基线 + 上游同步

- **导入**：`POST /api/baselines {name, rules:[{id,title,severity,mode}], scan_modes?, version?}`（admin）。
- **上游同步**：`POST /api/baselines/sync {url}` 拉取上游基线全文并存为 `source=upstream`；后台循环可周期调用。
- **删除**：`DELETE /api/baselines?name=X`（admin，经统一确认弹窗）。
- **生效**：`effectiveRules()` = upstream + custom 合并（同 id custom 覆盖）；经 `enforceableRuleIds()` 与策略 `code_rules` 取交集后写入 `custom_baseline_rules`，随签名策略下发。**只有终端可执行的规则 id 才会进入策略**，导入终端不认识的规则不会生效（也不会报错）。
- **模式切换**：`PUT /api/settings/scan-mode {mode}`（admin），`GET` 查询当前值与可选值；可选值 `quick` / `standard` / `custom`。改动写入设置后，**需重新发布签名策略**才下发终端。

---

## 五、企业级 MD（用户基线注入）

`modules.baseline_install`（出厂 `true`）控制终端是否安装/同步安全基线文件：

- 仓库级：向受管仓库注入带托管标记的基线文件（`install_baseline`）。
- 用户级：按 AI 工具类型同步到对应约定文件（如 `AGENTS.md` / `CLAUDE.md` / `rules.md`），以托管标记区块包裹，不覆盖用户自有内容。
- 企业级 MD：控制台「基线管理」页可编辑并**按灰度（全量 / 百分比 / 部门）**推送到 Collector，终端按设备令牌拉取；投递失败会在终端产出可观测发现。
