# Skill / MCP 逐项细节说明（告警研判手册）

> 针对终端 61de615d9f53（ShineMac-mini.local）的 23 个 high + 64 个 medium 发现，
> 逐项说明「它是什么 / 为什么告警 / 风险多大 / 建议处置」。供安全运营研判，非代码清单。

---

## 一、MCP 发现（5 类，均 high）

### 1. `cua_repl` — Codex Computer-Use REPL
- **是什么**：Codex 桌面端自带的 computer-use REPL MCP Server。配置里 `command` 指向
  `/Applications/Codex.app/Contents/MacOS/ChatGPT`（ChatGPT 桌面主程序二进制）。
- **为什么告警**：① 命令 `ChatGPT` 不在 `allowed_mcp_commands` 白名单；② 可执行路径
  `/Applications/Codex.app/...` 不在 `allowed_mcp_command_paths`。
- **风险**：该 MCP 一旦启用，Agent 可通过 REPL 驱动 ChatGPT 桌面程序做 computer-use
  （屏幕/键鼠控制），属最高权限类。当前 `enabled = false`（未启用），但**声明仍在配置里**，
  扫描器对"声明了未批准的高权限 MCP"仍告警（防止被悄悄启用）。
- **建议**：保持 disabled。若业务确需 computer-use，走审批把该路径加入
  `allowed_mcp_command_paths` 并开启监控；否则从配置移除该声明。

### 2. `node_repl` — Node.js REPL（computer-use 配套）
- **是什么**：Codex computer-use 配套的 Node.js REPL MCP Server，
  `command = /Applications/Codex.app/Contents/Resources/cua_node/bin/node_repl`，**已启用**。
  环境变量里用 `NODE_REPL_TRUSTED_CODE_PATHS` 限定了可信代码目录。
- **为什么告警**：命令 `node_repl` 与可执行路径均未在白名单。
- **风险**：**REPL = 任意代码执行**。Agent 可通过它在受信目录外尝试执行 Node 代码。
  虽有 TRUSTED_CODE_PATHS 约束，但 REPL 本质是代码执行通道，属 high。
- **建议**：high 保留告警。若 computer-use 是必需能力，审批加白并严格限定
  TRUSTED_CODE_PATHS；否则 disable 该 MCP。

### 3. `computer-use` — SkyComputerUseClient（屏幕控制）
- **是什么**：`./Codex Computer Use.app/.../SkyComputerUseClient`，`args=["mcp"]`，
  即 Codex 的屏幕/键鼠控制 MCP。当前 `enabled = false`。
- **为什么告警**：① 可执行路径未批准；② 「命令+参数组合」（SkyComputerUseClient + mcp）
  不在 `allowed_mcp_invocations`。
- **风险**：屏幕/键鼠控制 = 最高权限（可操作任意 UI、读取屏幕内容）。disabled 但声明在。
- **建议**：默认 deny。确需启用必须审批 + 全程监控 + 限定使用场景。

### 4. `ChatGPT`（作为 cua_repl 的 command）
- **是什么**：ChatGPT 桌面主程序被当作 MCP 命令调用。
- **为什么告警**：`ChatGPT` 不在允许命令列表。
- **风险**：同 cua_repl（驱动桌面主程序）。
- **建议**：同 cua_repl，保持 disabled 或审批。

### 5. 小结
5 个 MCP 发现全部围绕 **Codex computer-use 家族**（cua_repl / node_repl / computer-use /
ChatGPT）。它们都是"高权限控制类"MCP。当前多数 disabled，告警意义在于**防止被静默启用**。
处置优先级：node_repl（已启用，最急）> computer-use / cua_repl / ChatGPT（disabled，审批或移除）。

---

## 二、Skill 发现（deny 10 个，high）

### 文档处理四件套：pdf / pptx / xlsx / docx
- **是什么**：QwenWork 官方文档处理技能。pdf=PDF 读写/填表/合并/OCR；pptx=PPT 创建/编辑/
  合并；xlsx=电子表格读写/公式/图表；docx=Word 创建/编辑/模板/修订。
- **为什么告警**：未加入 `allowed_skills`；风险信号高（pdf cred=122/filewrite=60，
  pptx network=79/filewrite=44，xlsx network=36，docx network=46/cred=7）。
  信号高是因为技能内含大量脚本（调用外部工具、读写文件、下载字体/依赖）。
- **风险**：中-高。功能本身合法且常用，但脚本具备文件读写+网络+子进程能力，
  若被篡改或供应链投毒危害大。
- **建议**：业务必需 → 加入 `allowed_skills` 加白 + 锁定版本 + 监控；非必需 → 禁用。
  不建议长期保持 high 告警（会淹没真实告警）。

### 钉钉类：dingtalk-misc / dingtalk-aitable / dingtalk-minutes / dingtalk-calendar
- **是什么**：钉钉（DWS）集成技能。misc=OA审批/考勤/直播/DING/日志等长尾产品；
  aitable=AI 多维表增删改查；minutes=AI 听记查询/修改；calendar=日历/会议室。
- **为什么告警**：未加白；信号高（misc cred=92/exec=50/network=51；aitable network=47/exec=15；
  minutes exec=8/cred=7；calendar exec=9）。信号高因技能通过 `dws` CLI 调用钉钉 OpenAPI
  （exec+network+credential 属正常 CLI 调用模式）。
- **风险**：中。CLI 调用钉钉 API 是设计行为，cred 信号多为 token 传参说明（非硬编码密钥）。
  但具备"代用户操作钉钉"能力（审批/写表/改日程），属敏感操作类。
- **建议**：monitor。逐个研判：只读类（minutes 查询、calendar 查日程）可加白；
  写操作类（aitable 写、misc 审批处理）保持告警或加白+审计。

### aiskillstore-working-with-documents
- **是什么**：Office 文档处理技能（Word/PDF/PPT 创建编辑、格式转换）。
- **为什么告警**：未加白；filewrite=4/network=1（文档生成需写文件+拉依赖）。
- **风险**：中。同文档四件套。
- **建议**：与 pdf/pptx/xlsx/docx 统一策略（加白+锁版本 或 禁用）。

### diegosouzapw-python-testing-andyhsutw
- **是什么**：Python 测试策略技能（pytest/TDD/fixtures/覆盖率）。
- **为什么告警**：未加白；network=8/cred=6/filewrite=5（测试示例含网络 mock、token 示例、写测试文件）。
- **风险**：低-中。纯方法论+示例代码，cred 信号多为示例占位。
- **建议**：可加白（monitor→allow），或保持 monitor。

---

## 三、Skill 发现（monitor 26 个，medium）摘要

多为钉钉子技能（chat/contact/doc/drive/event/mail/shared/todo/wiki）与开发辅助技能
（ai-dev-tools、create-skill、plugin-creator、qw-pages、media-generation 等）。
信号以 exec（CLI 调用）+ cred（token 传参说明）+ network（API 调用）为主，属设计行为。
**建议**：批量研判后把只读/低危类加入 `allowed_skills`；写操作/外联类保持 monitor。

## 四、Skill 发现（allow 12 个，已加白）

claude-dev-suite-java-quality、dingtalk-aisearch、fwrite0920-project-bootstrapping、
l-mb-py-modernize、majesticlabs-dev-python-debugger、majiayu000-deeplearningcoder、
majiayu000-fix-markdown-lint、majiayu000-frontend-code-quality、
michaelboeding-feature-council、mini-program-dev、godot-headless-game-pipeline、
handwritten-form-to-excel。
**已加入 allowed_skills，不再产生 unknown_skill 告警。**

---

## 五、研判优先级（建议工单顺序）
1. **node_repl**（已启用的代码执行 REPL）— 最急，审批或 disable
2. **computer-use / cua_repl / ChatGPT**（disabled 屏幕控制）— 审批或移除声明
3. **文档四件套 + working-with-documents** — 加白+锁版本 或 禁用（消 high 噪声）
4. **钉钉写操作类**（aitable 写 / misc 审批）— 加白+审计 或 保持告警
5. **钉钉只读类 + 开发辅助** — 批量加白（消 medium 噪声）
