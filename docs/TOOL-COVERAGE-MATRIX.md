# AI 工具覆盖：候选目录与登记模板

**候选目录不等于当前支持清单。** 本文使用官方公开入口帮助建立版本化验收矩阵，不提供市场份额排名，也不声称穷尽市场。是否通过以[试点验收证据](PILOT-ACCEPTANCE.md)为准；不能从官方支持某系统推导 Aegis 已适配。

## 登记规则

按产品形态、地区版、工具版本、操作系统/架构、原生或 WSL 环境、安装与配置作用域分别登记。本期治理对象是本地 IDE、CLI 和桌面 Agent；网页、云执行和自建 SDK 服务不由本地工具名称自动纳入。

同一品牌的 CLI、IDE 扩展和桌面应用可以共享部分配置，但必须分别证明实际有效来源。用户、项目、插件、企业设置、显式路径和动态注册均需按工具能力记录；未能读取的来源显示未知，不靠遍历全部用户目录扩大权限。

| 产品/形态/地区 | 工具版本 | OS/架构/环境 | 配置作用域 | 工具识别 | 资产发现 | 检测 | 处置 | 恢复/告知/证明 | 环境类别与证据 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 待登记 | 待冻结 | 待冻结 | 待确认 | 未核验 | 未核验 | 未核验 | 未核验 | 未核验 | 不得预填通过 |

未实现与不适用不是同一状态；不适用需要官方依据。发现新工具或工具版本改变配置/执行语义时，新增或重新验证对应行。存量版本与停止维护的工具应保留识别、迁移及处置边界，不为了凑覆盖而推荐部署。

## 中国厂商及地区版候选

以下条目需结合项目实际工具汇总补充；平台和配置细节以锁定版本的官方说明及实机证据为准。

| 产品族/条目 | 必须区分的形态 | 官方入口与验收关注点 |
| --- | --- | --- |
| 通义灵码 / Qoder CN | IDE、VS Code、JetBrains；新旧名称 | [产品入口](https://help.aliyun.com/zh/lingma/)、[安装](https://docs.qoder.cn/user-guide/installation-guide)、[MCP](https://help.aliyun.com/zh/lingma/guide-for-using-mcp)；CN 与国际版分别验收 |
| Qwen Code | CLI、桌面、IDE 扩展 | [官方仓库](https://github.com/QwenLM/qwen-code)、[配置](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/)；不能按 QwenWork 归类 |
| Qoder 国际版 | IDE、CLI | [IDE](https://docs.qoder.com/quick-start)、[CLI](https://docs.qoder.com/cli/installation)、[扩展](https://docs.qoder.com/qoder/extension-publishing)；自定义目录和地区差异 |
| CodeBuddy IDE / 插件 | IDE、VS Code、JetBrains | [下载](https://www.codebuddy.cn/ide/)、[Skills](https://www.codebuddy.ai/docs/ide/Features/Skills)、[MCP](https://www.codebuddy.ai/docs/ide/User-guide/MCP)；用户与项目配置 |
| CodeBuddy Code CLI | CLI | [开始](https://www.codebuddy.ai/docs/cli/quickstart)、[参数](https://www.codebuddy.ai/docs/cli/cli-reference)、[插件](https://www.codebuddy.ai/docs/cli/plugins-reference)；显式 MCP 配置及插件来源 |
| WorkBuddy | 桌面 Agent | [Mac](https://www.codebuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Installation-Mac-Guide)、[Windows](https://www.codebuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Installation-Win-Guide)、[连接器](https://open.workbuddy.cn/docs/connector)；连接器与技能范围 |
| TRAE 中国版 | TraeCode、TraeWork、CLI；旧版本分别登记 | [下载](https://www.trae.cn/download)、[CLI](https://docs.trae.cn/cli_get-started-with-trae-code-cli-2)、[Skills](https://docs.trae.cn/ide_skills)；地区目录和原生/WSL |
| TRAE 国际版 | 本地 IDE、桌面形态 | [下载](https://www.trae.ai/download)、[文档](https://docs.trae.ai/)；不能直接套用 CN 配置 |
| QwenWork / 千问办公 | 国内、国际桌面版 | [国内](https://qwenwork.cn/)、[国际](https://qwenwork.ai/)、[Skills](https://docs.qwenwork.ai/desktop/skills)、[连接器](https://docs.qwenwork.ai/desktop/connectors)；旧国内目录不证明国际版覆盖 |
| Kimi | Code CLI、Code Desktop、Kimi Work | [CLI](https://moonshotai.github.io/kimi-code/en/)、[Work](https://www.kimi.com/en/help/kimi-work/overview)、[Code Desktop](https://www.kimi.com/code/docs/en/kimi-code-desktop/settings-and-extensions.html)；目录迁移与已有会话 |
| 百度 Comate / 文心快码 | IDE、VS Code、JetBrains | [产品与系统](https://comate.baidu.com/docs/vscode.html)、[MCP](https://comate.baidu.com/docs/IDE%E5%8A%9F%E8%83%BD/MCP/)；宿主版本及项目配置 |
| 华为 CodeArts Agent / 码道 | IDE、CLI | [IDE](https://support.huaweicloud.com/bestpractice-codeartsagent/codeartsagent_bp_0013.html)、[CLI](https://support.huaweicloud.com/usermanual-cli/codeartsagent_cli_0001.html)、[MCP](https://support.huaweicloud.com/usermanual-cli/codeartsagent_cli_0035.html)；配置格式及作用域 |

## 国际及开源候选

| 产品族/条目 | 必须区分的形态 | 官方入口与验收关注点 |
| --- | --- | --- |
| Codex | CLI、IDE 扩展、桌面；远程执行单列边界 | [桌面](https://learn.chatgpt.com/docs/app)、[Windows](https://learn.chatgpt.com/docs/windows/windows-sandbox)、[Skills](https://learn.chatgpt.com/docs/build-skills)、[MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)；项目/用户/插件来源 |
| Claude | Code CLI、IDE 集成、Desktop Code | [安装](https://code.claude.com/docs/en/setup)、[配置](https://code.claude.com/docs/en/settings)、[桌面差异](https://code.claude.com/docs/en/desktop)；各形态有效配置独立核验 |
| Cursor | IDE、CLI | [下载](https://cursor.com/download)、[CLI](https://cursor.com/docs/cli/installation)、[MCP](https://prod.cursor.com/help/customization/mcp)；动态注册与文件配置分别记录 |
| GitHub Copilot | VS Code、JetBrains、CLI | [CLI](https://docs.github.com/en/copilot/get-started/cli-quickstart)、[IDE MCP](https://code.visualstudio.com/docs/agent-customization/mcp-servers)、[CLI MCP](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers)；配置格式与宿主区别 |
| Windsurf / Devin Desktop | 按实际安装名称和版本登记 | [当前下载](https://devin.ai/download)、[当前 MCP](https://docs.devin.ai/desktop/cascade/mcp)；保留旧安装和配置迁移证据 |
| Gemini CLI | CLI | [安装](https://geminicli.com/docs/get-started/installation/)、[配置](https://geminicli.com/docs/reference/configuration/)；全局、项目、系统及扩展配置 |
| Kiro | IDE、CLI | [CLI](https://kiro.dev/cli/)、[MCP](https://kiro.dev/docs/mcp/configuration/)、[配置](https://kiro.dev/docs/cli/reference/settings/)；同源产品不自动共享验收结果 |
| OpenCode | CLI/TUI、IDE 等本地形态 | [产品](https://opencode.ai/docs/)、[配置](https://opencode.ai/docs/config/)、[Skills](https://opencode.ai/docs/skills/)；自定义、内联与组织配置 |
| Cline | IDE 扩展、CLI、桌面形态 | [安装](https://docs.cline.bot/getting-started/installing-cline)、[产品](https://docs.cline.bot/cline-overview)、[配置](https://docs.cline.bot/getting-started/config)；旧扩展存储与共享目录 |
| JetBrains Junie | IDE 插件、CLI | [IDE](https://junie.jetbrains.com/docs/junie-ide-plugin.html)、[CLI](https://junie.jetbrains.com/docs/junie-cli.html)、[MCP](https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html)、[Skills](https://junie.jetbrains.com/docs/agent-skills.html)；宿主版本与新旧入口 |
| Continue | VS Code、JetBrains、CLI | [IDE](https://docs.continue.dev/ide-extensions/install)、[CLI](https://docs.continue.dev/cli/quickstart)、[配置](https://docs.continue.dev/cli/configuration)；当前 YAML 与旧 JSON 配置 |
| Aider | CLI、IDE 工作流 | [安装](https://aider.chat/docs/install.html)、[配置](https://aider.chat/docs/config/aider_conf.html)；未证实的 MCP/Skills 不预填支持 |
| Google Antigravity | IDE、桌面 Agent、CLI | [上手](https://www.antigravity.google/docs/getting-started/)、[MCP](https://antigravity.google/docs/ide-mcp)、[CLI](https://antigravity.google/docs/cli/features/)、[权限](https://www.antigravity.google/docs/agent-settings)；双端权限体系分别验收 |
| Roo Code（存量） | 已有扩展及配置 | [官方状态](https://roocodeinc.github.io/Roo-Code/)、[存量 Skills](https://roocodeinc.github.io/Roo-Code/advanced-usage/available-tools/skill/)；保留识别/迁移边界，不作为新增部署推荐 |

Gemini Code Assist、Amazon Q Developer 或其他实际出现的产品应独立补录，不由 Gemini CLI、Kiro 或泛称“其他工具”替代。上述候选目录的更新只改变待评估范围，不能自动扩大已经发布的支持声明。

## 更新与留痕

矩阵变更应随 PR 记录新增/变更的工具形态、官方来源、适用版本和待验证能力。状态提升必须引用同一被测构建的证据；跨操作系统、版本或运行环境不能复制通过结果。

公共仓保存模板及脱敏结果引用。原始配置、用户路径、设备和人员明细、认证信息及现场安排放在受控记录中；不要将这些数据复制进 PR、Issue 或提交信息。
