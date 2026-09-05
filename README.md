# Sentinel AI Agent Security

Sentinel 是面向企业终端的 AI Coding 安全治理工具。它通过 Microsoft Intune 部署，在 Windows、macOS/Linux 上自动发现 Cursor、Claude Code、Codex 和 Windsurf，加载企业安全编码基线，并扫描 Skill、MCP、代码质量与依赖风险。报告可进入受认证的接收器，并通过安全适配边界与深信服 EDR、联软桌管协同。

当前发行：产品 `0.53.0`，Endpoint Agent `0.26.0`，策略 `4.8.0`，Collector `0.10`，Adapter `0.7`。

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
