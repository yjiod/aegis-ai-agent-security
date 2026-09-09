# Sentinel AI Agent Security

Sentinel 是面向企业终端的 AI Coding 安全治理工具。它通过 Microsoft Intune 部署，在 Windows、macOS/Linux 上自动发现 Cursor、Claude Code、Codex、Windsurf、Gemini CLI 和 GitHub Copilot CLI，加载企业安全编码基线，并扫描 Skill、MCP、代码质量与依赖风险。报告可进入受认证的接收器，并通过安全适配边界与深信服 EDR、联软桌管协同。

当前发行：产品 `3.6.0`，Endpoint Agent `0.40.0`，策略 `4.9.0`，Collector `0.19`，Adapter `0.18`。

## 目录

- `public/downloads/`：终端 Agent、策略、Intune 脚本、回滚、报告 Schema、Collector、厂商适配器及离线发行包。
- `public/downloads/PRODUCTION-READINESS.md`：按责任人、输入、通过证据与失败回退组织的生产联合验收清单。
- `app/`：私有治理控制台与安全的只读 Collector 摘要代理。
- `tests/`：标准库测试，覆盖扫描、报告、认证、队列、合规、备份恢复与发行完整性。
- `docs/`：架构、开发和发布过程文档。

## 快速验证

```bash
npm ci
python3 -m unittest discover -s tests
for file in public/downloads/*.sh; do sh -n "$file"; done
npm run build
python3 public/downloads/sentinel_release_verify.py public/downloads
npm run release:check
```

本地启动控制台：`npm run dev`。默认控制台明确显示演示模式，不会下发终端任务。配置服务端 Collector 环境变量后，仅顶部摘要切换为真实只读数据。

## 文档

- [架构与信任边界](docs/ARCHITECTURE.md)
- [联合开发指南](CONTRIBUTING.md)
- [开发与测试流程](docs/DEVELOPMENT.md)
- [发行与部署流程](docs/RELEASE.md)
- [企业部署指南](public/downloads/DEPLOYMENT-GUIDE.md)
- [安全响应说明](SECURITY.md)

真实 Intune、深信服 EDR、联软及 Collector 凭据不得提交到 Git。

## 1.5 在线验签密钥轮换

Adapter Worker 每批次重新读取 `SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS_FILE`，因此可通过原子替换 `/etc/sentinel/vendor-acceptance-keys.json` 在线增加或移除验签密钥，无需重启进程。文件必须是普通文件、不得是符号链接，最大 64 KiB，所有者必须为 root 或服务用户；禁止其他用户访问，组仅可读且必须属于服务用户。推荐 `root:sentinel 0640`，内容是包含 1–5 个不同密钥的 JSON 对象。

安全轮换顺序：先把新旧密钥同时写入临时文件并原子替换；用新 `key_id` 签署并原子替换验收证据；确认下一批次通过后再从密钥环移除旧密钥。环境变量密钥环只保留兼容用途，其内容变更仍需重启服务。

1.6 起，审批工作站可运行 `sentinel_vendor_evidence_sign.py --evidence <v2.json> --key-id <id> --keyring <受保护密钥环>`，从同样经过权限、所有者、大小和防符号链接校验的文件精确选键。这样签名密钥无需进入进程环境、命令参数、证据或标准输出；环境变量单密钥方式仅保留兼容用途。

1.7 起，增加 `--output <v3.json>` 直接生成 0600 的验收证据。工具拒绝符号链接输出、不安全或经符号链接解析的父目录，并执行文件与目录 `fsync` 后原子替换；标准输出仅返回不含密钥的完成回执。省略 `--output` 的原有标准输出方式仅用于兼容。

1.8 起，替换既有验收证据时会在确认其为安全的 0600/0640 普通文件后保留所有者、组和权限，避免把 `root:sentinel 0640` 意外替换成 Worker 无法读取的 `root:root 0600`。既有文件权限过宽、所有者异常或非普通文件时拒绝写入。

1.9 起，`sentinel_vendor_keyring.py` 使用系统 CSPRNG 创建和增加密钥，标准输出只返回 key id、数量与动作。删除旧键必须提供七天内、且由另一把保留密钥有效签署的当前验收证据；不能删除证据正在使用的键，也不能删除最后一把键。

2.0 起，私有控制台新增 `/api/devices` 只读代理，最多展示 200 台终端的匿名设备 ID、最近上报、报告数量与凭据代次。代理复用 Collector 精确 HTTPS 主机和服务端令牌边界，并增加响应大小、时效、字段、枚举、重复 ID 和数量校验；不向浏览器暴露 Collector 凭据，也不提供终端写操作。

2.1 起，控制台从同一受验证发行包的 `release.json` 读取产品及组件版本，严格验证字段和版本格式后显示；元数据不可用时使用当前安全默认值。发行验证器固定 Endpoint Agent、策略、Collector 与 Adapter 的版本组合，消除界面静态版本与实际制品漂移。

2.2 起，Collector 0.18 为 `/v1/devices` 增加显式 `view=console` 只读视图，返回每台设备最新风险等级及 Agent/策略版本；默认 activation 视图保持原四字段契约，Intune 晋级和凭据裁剪证据不受影响。控制台代理只接受七字段 console 契约。

2.3 起，`npm run release:build` 统一生成运行文件摘要、脚本内嵌摘要、Intune 制品清单、晋级证据模板和确定性 ZIP。CI 会在隔离副本中重建并逐字节比较所有派生制品，防止联合开发过程中提交旧哈希或旧发行包；已签名生产清单不会被自动改写。

2.4 起，离线包提供 `RELEASE-MANIFEST.sha256`，覆盖包内除清单自身外的全部制品。发行验证器严格校验唯一文件集合、摘要行格式及每个文件的 SHA-256，可发现 Collector、Adapter、Intune、回滚、验收工具或文档的缺失、增加与字节漂移。

2.5 起，Collector 0.19 提供每日 systemd 维护任务。即使终端没有新报告，也会执行报告和审计保留期、数量上限、数据库 `quick_check`、被动 WAL checkpoint 和 SQLite optimize；任务只输出聚合数量且不读取或打印凭据、设备 ID 与报告正文。

2.6 起，Endpoint Agent 0.36 在多用户自动发现时拒绝符号链接用户目录、Windows 重解析点用户目录以及符号链接/reparse Git 标记，并能识别本身就是 Git 仓库的标准 Windows 项目根目录。周期任务仍会为之后安装的 Agent 和之后创建的真实仓库加载基线，但不会沿伪造目录越过受管边界。

2.7 起，Endpoint Agent 0.37 在 macOS/Linux 以原子替换写入仓库基线，写入前后重复校验目标边界并同步文件与目录。既有文件保留权限和所有者；root 周期任务创建的新文件及目录继承仓库所有者，避免企业基线使开发者仓库变成 root-only。写入失败时保留原文件并清理临时文件。

2.8 起，Endpoint Agent 0.38 将相同的原子写入、所有权和权限保留机制扩展到 Codex、Claude Code、Gemini CLI 与 GitHub Copilot CLI 的用户级指令文件，并拒绝显式传入的符号链接用户主目录。root 周期同步不会留下截断文件或短暂的 root-only 指令文件。

2.9 起，Endpoint Agent 0.39 在 Windows 上使用同目录临时文件、落盘刷新和原子替换更新用户级 Agent 指令；既有文件 ACL 在替换前复制到临时文件，写入前后重复检查主目录边界与重解析点，失败时清除临时项并保留原文件。Intune 修复脚本复用同一安全语义。

3.0 起，Endpoint Agent 0.40 将 Windows 原子写入覆盖到自动发现仓库中的 `AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、Cursor/Windsurf 规则和共享安全基线。既有仓库指令 ACL 保持不变，所有目标在替换前再次验证仓库边界和重解析点，失败不会留下临时文件或截断仓库规范。

3.1 起，离线包新增生产就绪与联合验收清单，明确 Collector、Intune、深信服 EDR、联软桌管和控制台的责任人、输入、执行顺序、通过证据及失败回退。必须依赖客户凭据或真实终端的事项保持显式“未完成”，避免用本地测试或 CI 冒充生产验收。

3.2 起，`sentinel_production_preflight.py` 对最终生产验收证据执行失败关闭校验。证据必须绑定当前发行与完整清单 SHA-256、40 位 Git 提交、私有站点版本、十项客户环境实测结论和安全/终端/平台/业务四方签署，并明确不含秘密和设备标识；任何假值、缺签、过期或字段漂移都会拒绝放行。

3.3 起，最终生产预检要求操作者分别传入从 GitHub 和 Sites 权威查询获得的预期完整提交与站点版本，并与证据做精确匹配。证据文件内任意格式正确但不一致的 SHA 或版本不再能够通过放行门禁。

3.4 起，最终生产验收升级为 v2：十项门禁分别绑定外部验收记录 SHA-256，四方审批分别绑定审批记录摘要，完整证据再由独立生产密钥环执行 HMAC-SHA256 签名。签名工具只写入受保护的原子输出，预检拒绝篡改、未知/退役密钥、缺失记录摘要和未签名模板。

3.5 起，生产验收签名与预检均支持 `--keyring <受保护文件>`，长期密钥无需进入进程环境。`sentinel_production_keyring.py` 使用系统 CSPRNG 创建密钥，并支持最多五把密钥重叠轮换；删除旧键必须提供 24 小时内、由另一把保留密钥有效签署的生产验收记录，且不能删除最后一把键。环境变量仅保留兼容用途。

3.6 起，生产验收升级为 v3，签名结论不再只携带人工填写的摘要。预检通过 `--evidence-root` 对十项检查记录和四方审批记录逐文件执行有界、防符号链接 SHA-256 核验；文件名限单层安全名称且十四份记录不得复用同一文件。缺失、替换、越界、重复或摘要不匹配均失败关闭。
