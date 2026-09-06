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
python3 public/downloads/sentinel_release_verify.py public/downloads
git diff --check
```

GitHub 发布门禁还会在独立的 `windows-latest` runner 上使用 Windows PowerShell 5.1 AST 解析全部 `.ps1`，并在 `macos-latest` runner 上分别用系统 Bash 与 POSIX sh 解析全部 `.sh`。这些原生平台检查不能代替 Intune 试点机的真实安装、升级、回滚和卸载演练。

修改 `sentinel_agent.py`、`sentinel-windows.ps1`、`sentinel-policy.json` 或 `sentinel-security-baseline.md` 后，必须重算 `CHECKSUMS.sha256`，同步安装/检测/合规脚本内嵌哈希，并重建 ZIP。

评审必须检查：不可信输入边界、代码执行可能性、链接越界、失败关闭、可恢复性、敏感数据暴露、虚假成功状态和跨平台行为对等。
