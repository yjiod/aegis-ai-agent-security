# 开发与测试流程

## 环境

- Node.js `>=22.13.0`
- Python 3（运行时代码仅用标准库）
- macOS/Linux Shell；PowerShell 5.1+

从 `main` 创建短生命周期分支。一个提交聚焦一个安全不变量，同时更新测试、部署文档和 `release.json`。不得提交 `.env`、令牌、客户主机名、设备清单或真实报告。

## 本地门禁

```bash
npm ci
python3 -m unittest discover -s tests -v
for file in public/downloads/*.sh; do sh -n "$file"; done
npm run build
npm run release:build
python3 public/downloads/sentinel_release_verify.py public/downloads
npm run release:check
git diff --check
```

GitHub 发布门禁还会在独立的 `windows-latest` runner 上使用 Windows PowerShell 5.1 AST 解析全部 `.ps1`，并在 `macos-latest` runner 上分别用系统 Bash 与 POSIX sh 解析全部 `.sh`。这些原生平台检查不能代替 Intune 试点机的真实安装、升级、回滚和卸载演练。

`package.json` 暂时将间接依赖 `sharp` 固定到 0.35.4，以覆盖 Miniflare 仍声明的 0.35.2 并修复 libheif 高危公告。升级 Cloudflare 工具链时必须重新运行 `npm ls sharp`、完整构建和 `npm audit --audit-level=low`；上游依赖修复后可在单独评审中移除 override。

修改发行文件后运行 `npm run release:build`。确定性构建器会同步运行文件摘要、安装/检测/合规脚本内嵌摘要、Intune 制品清单、晋级证据模板以及 ZIP，并在完成前执行离线验证。CI 的 `release:check` 会在隔离副本中重建并逐字节比较派生制品，拒绝手工遗漏和非确定性归档。生产签名包必须继续由隔离的 Windows 签名工作站生成；构建器会拒绝改写已签名清单。

评审必须检查：不可信输入边界、代码执行可能性、链接越界、失败关闭、可恢复性、敏感数据暴露、虚假成功状态和跨平台行为对等。
