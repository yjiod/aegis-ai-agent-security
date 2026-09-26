# Mac 原生客户端安装

适用 Apple Silicon ARM64 与 Intel x64。客户端自带所需运行时，用户不需要安装 Python、Homebrew 或开发工具。

当前仓库仍为待验收候选，未签名的 CI 包不能通过正式安装验证。生产分发还需完成签名公证、完整安装恢复及干净终端验收。

## 管理员安装

从企业受信任发布渠道取得经过审核的本地安装脚本、已批准安装包的完整 SHA-256 和发布者 Team ID。保护脚本及配置，不能从同一待验证下载地址临时获取信任摘要。包应为本企业正确服务端地址构建。

`aegis-install-macos-oneclick.sh` 和 `mdm-macos-install.sh` 内容完全一致，使用相同的安装验证和失败处理。以前直接下载并执行脚本的管道命令已不再作为控制台推荐流程；脚本不会自行重新下载提权副本或提前停止现有服务。

以管理员身份运行本地经过审核的脚本。以下变量只代表公开工件身份，不是上报凭据，应先由管理员填入已批准的真实值：

```sh
sudo /bin/sh ./aegis-install-macos-oneclick.sh \
  -PkgUrl "$APPROVED_PACKAGE_URL" \
  -PkgSha256 "$APPROVED_PACKAGE_SHA256" \
  -TeamId "$APPROVED_PUBLISHER_TEAM_ID"
```

本地包使用 `-PkgPath` 替代 `-PkgUrl`；需要绝对路径、root 所有、不可由普通用户写入的常规文件。两种来源不能同时指定。参数缺值、重复或未知均拒绝；命令行值覆盖对应环境变量，但不会自动清除另一种包来源以掩盖冲突。

MDM 无需命令行参数，通过受保护的 `AEGIS_MACOS_PKG_SHA256`、`AEGIS_MACOS_TEAM_ID`、`AEGIS_MACOS_PKG_URL` 或 `AEGIS_MACOS_PKG_PATH` 配置同一流程。不得把 Token/HMAC、登录凭据放入命令行、脚本或包。

旧 `-Server` 参数已移除，不再写入服务器覆盖配置。使用为正确服务端构建的包；存量服务器覆盖文件的检查与清理仍属于待完成的迁移工作，不能假定重装会自动修正其内容。

## 安装结果

入口必须确认完整摘要、批准的 Developer ID Installer 发布者、已启用且无覆盖放行的公证评估；安装前再次复核摘要。任一步失败均不调用 Installer，不回退 Python 或关闭系统验证。

- `installed_health_pending`：Installer 成功，仍需验证服务、入网和当前配置的成功上报。
- `legacy_service_migration_required`：旧服务需先迁移，本次未开始安装。
- `prior_cleanup_requires_verification`：核实之前的扫描进程清理结果后再安装。
- `installer_failed_state_requires_verification`：Installer 已运行，可能部分修改系统；需核实恢复，不代表自动回滚。

下载限制为 15 秒连接超时、120 秒总时限及 128 MiB。系统公证评估和 Installer 不受该网络时限覆盖；任务中断或超时后应核实状态。历史 Python 三文件回滚脚本不适用于原生包。

上报配置由已安装客户端的 `aegis-configure-macos.sh` 写入；健康检查使用 `mdm-macos-compliance.sh`。这些能力均使用客户端自带运行时。旧用户级入网、完整原生包回滚和实际签名发布验收仍在推进，不能将本入口测试通过当作全生命周期验收完成。
