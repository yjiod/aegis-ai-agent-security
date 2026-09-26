# Mac 原生客户端安装

系统 pkg 入网由内嵌客户端校验服务端响应并原子写入私有上报配置，无需外部 Python。
重装仅保留格式有效且完整上报 URL 相同的配置；更换控制台需独立迁移。入网失败保留
待修复状态，不承诺自动重新入网。入网响应不会覆盖策略或信任根，也不配置旧 Swift
界面。配置成功仍需确认控制台接受上报；详见仓库 `docs/MACOS-ENROLLMENT.md`。

适用 Apple Silicon ARM64 与 Intel x64。客户端自带所需运行时，用户不需要安装 Python、Homebrew 或开发工具。

当前仓库仍为待验收候选，未签名的 CI 包不能通过正式安装验证。生产分发还需完成签名公证、完整安装恢复及干净终端验收。

## 管理员安装

从企业受信任发布渠道取得经过审核的本地安装脚本、已批准安装包的完整 SHA-256 和发布者 Team ID。保护脚本及配置，不能从同一待验证下载地址临时获取信任摘要。包应为本企业正确服务端地址构建。

`aegis-install-macos-oneclick.sh`、`mdm-macos-install.sh` 和保留的历史文件名 `aegis-agent-macos-enroll.sh` 内容完全一致，使用相同的原生系统包安装验证和失败处理。历史文件名现在要求管理员身份和批准包配置，不再安装用户级 Python 运行时。以前直接下载并执行脚本的管道命令已不再作为控制台推荐流程；脚本不会自行重新下载提权副本或提前停止现有服务。

以管理员身份运行本地经过审核的脚本。以下变量只代表公开工件身份，不是上报凭据，应先由管理员填入已批准的真实值：

```sh
sudo /bin/sh ./aegis-install-macos-oneclick.sh \
  -PkgUrl "$APPROVED_PACKAGE_URL" \
  -PkgSha256 "$APPROVED_PACKAGE_SHA256" \
  -TeamId "$APPROVED_PUBLISHER_TEAM_ID"
```

本地包使用 `-PkgPath` 替代 `-PkgUrl`；需要绝对路径、root 所有、不可由普通用户写入的常规文件。两种来源不能同时指定。参数缺值、重复或未知均拒绝；命令行值覆盖对应环境变量，但不会自动清除另一种包来源以掩盖冲突。

MDM 无需命令行参数，通过受保护的 `AEGIS_MACOS_PKG_SHA256`、`AEGIS_MACOS_TEAM_ID`、`AEGIS_MACOS_PKG_URL` 或 `AEGIS_MACOS_PKG_PATH` 配置同一流程。不得把 Token/HMAC、登录凭据放入命令行、脚本或包。

迁移已有用户级服务时，可在受保护 MDM 配置中设置 `AEGIS_MACOS_MIGRATE_USER_SERVICES=1`，或为已审核的本地入口增加 `-MigrateUserServices 1`（默认 0）。只有通过摘要、签名、公证和包内迁移能力声明/脚本摘要检查后才调用 Installer，由包内原生客户端准备旧启动配置；不会提前停服。旧包缺少迁移协议时拒绝。旧系统服务仍须独立迁移，不能用此开关放行。

旧 `-Server` 参数已移除，不再写入服务器覆盖配置。使用为正确服务端构建的包；存量服务器覆盖文件的检查与清理仍属于待完成的迁移工作，不能假定重装会自动修正其内容。

## 历史入网命令迁移

旧 `AEGIS_COLLECTOR_URL`、`AEGIS_COLLECTOR_TOKEN`、`AEGIS_REPORT_SIGNING_SECRET`、`AEGIS_SCAN_INTERVAL`、`AEGIS_DEVICE_ID`、`AEGIS_INSTALL_DIR` 任一变量仍存在时，三个安装入口都会在外部命令及任何安装动作之前返回 `legacy_enrollment_settings_not_supported`（退出 2）。空值也算存在；不会回显值、生成替代签名密钥、覆盖用户配置或默默忽略设置。管理员应重新配置部署任务，明确选择以下操作：

- 新安装或迁移：移除旧入网变量，按上方批准包流程安装。迁移旧用户服务须显式增加 `-MigrateUserServices 1`；包内原生入网写入系统配置。下载根变量 `AEGIS_BASE_URL` 仍只表示包下载根地址，不会改变 Collector。
- 系统客户端凭据轮转：使用已安装的 `aegis-configure-macos.sh` 和受保护的原生配置变量；不要运行安装入口轮转凭据。随后核对新配置对应的成功上报。
- 更换 Collector：使用受保护的管理员迁移流程，不能靠旧环境变量改变服务器。迁移不会自动迁移离线队列或吊销原服务器注册。
- 卸载：使用 [原生卸载说明](MACOS-UNINSTALL.md)。只要 `AEGIS_ENROLL_UNINSTALL` 存在（包括 0 或空值），安装入口返回 `legacy_uninstall_setting_requires_maintenance`，不调用 Installer、不停服；不要直接清除变量并重跑同一命令。当前用户旧服务退役可使用经过审核的新 `.run --uninstall` 维护入口，由可信已安装原生客户端执行，保留运行数据和基线。它不等于完整单用户卸载；系统卸载会处理多用户，不能冒充单用户卸载。

## 安装结果

入口必须确认完整摘要、批准的 Developer ID Installer 发布者、已启用且无覆盖放行的公证评估；安装前再次复核摘要。任一步失败均不调用 Installer，不回退 Python 或关闭系统验证。

- `installed_health_pending`：Installer 成功，仍需验证服务、入网和当前配置的成功上报。
- `legacy_service_migration_required`：旧系统服务需独立迁移；旧用户服务尚未启用迁移模式时，本次未开始安装。
- `migration_capability_unavailable` / `migration_script_digest_mismatch`：批准包缺少迁移协议或脚本摘要不符，本次未开始安装。
- `prior_cleanup_requires_verification`：核实之前的扫描进程清理结果后再安装。
- `installer_failed_state_requires_verification`：Installer 已运行，可能部分修改系统；需核实恢复，不代表自动回滚。

下载限制为 15 秒连接超时、120 秒总时限及 128 MiB。系统公证评估和 Installer 不受该网络时限覆盖；任务中断或超时后应核实状态。历史 Python 三文件回滚脚本不适用于原生包。

上报配置由已安装客户端的 `aegis-configure-macos.sh` 写入；健康检查使用 `mdm-macos-compliance.sh`。这些能力均使用客户端自带运行时。旧用户服务真实切换/激活、单用户退役、完整原生包回滚和实际签名发布验收仍在推进，不能将本入口测试通过当作全生命周期验收完成。
