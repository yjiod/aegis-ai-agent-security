# Sentinel AI Agent Security

Sentinel 是面向企业终端的 AI Coding 安全治理工具。它通过 Microsoft Intune 部署，在 Windows、macOS/Linux 上自动发现 Cursor、Claude Code、Codex、Windsurf、Gemini CLI 和 GitHub Copilot CLI，加载企业安全编码基线，并扫描 Skill、MCP、代码质量与依赖风险。报告可进入受认证的接收器，并通过安全适配边界与深信服 EDR、联软桌管协同。

当前发行：产品 `1.9.0`，Endpoint Agent `0.35.0`，策略 `4.9.0`，Collector `0.17`，Adapter `0.18`。

## 目录

- `public/downloads/`：终端 Agent、策略、Intune 脚本、回滚、报告 Schema、Collector、厂商适配器及离线发行包。
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
