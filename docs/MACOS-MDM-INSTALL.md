# macOS MDM 原生安装入口

`public/downloads/mdm-macos-install.sh` 使用 macOS 系统工具验证并安装自包含 `.pkg`。客户端和此入口均不要求用户安装 Python；不下载解释器，不调用源码扫描器。开发测试使用 Python 不属于终端运行依赖。

本入口仍是候选实现。正向签名、公证、Installer 调用顺序使用隔离夹具验证；系统 `pkgutil` 对真实未签名包的拒绝另有测试。尚未完成真实签名公证包的正向安装、完整升级恢复和干净终端验收，不能将候选 CI 包用于生产。

## 受信任输入

以 root 运行。MDM 通常不传命令行参数，由受保护的部署配置提供以下环境变量；这些变量不是终端上报凭据。

| 变量 | 要求 |
| --- | --- |
| `AEGIS_MACOS_PKG_SHA256` | 必填，已批准安装包的完整 SHA-256，64 位十六进制 |
| `AEGIS_MACOS_TEAM_ID` | 必填，已批准发布者的 10 位大写字母/数字 Team ID |
| `AEGIS_MACOS_PKG_URL` | HTTPS 安装包地址；拒绝用户信息、查询参数、片段、空白及重定向 |
| `AEGIS_MACOS_PKG_PATH` | 与 URL 二选一；绝对路径、本地 root 所有的普通 `.pkg`，无符号链接、额外硬链接、组/其他用户写权限 |
| `AEGIS_MACOS_MIGRATE_USER_SERVICES` | 默认 `0`；设为 `1` 允许经过包能力校验后由 Installer 内的原生流程准备旧用户服务；其他值拒绝 |
| `AEGIS_BASE_URL` | 未指定包路径或 URL 时，用此下载根地址拼接 `/aegis-agent-macos.pkg`；默认域名仅为占位符 |

哈希和 Team ID 应由经过评审的发布记录导入 MDM 控制面，不能从同一个待验证下载地址临时取得。MDM 必须保护引导脚本本身及其配置。现有企业发布清单固定引导脚本摘要；它没有自动提供可信的原生包摘要或发布者身份。包必须为本企业正确的服务端地址构建，禁止将上报 Token/HMAC 写入脚本文本、命令行、URL 或安装包。

管理员交互入口 `aegis-install-macos-oneclick.sh` 和历史文件名 `aegis-agent-macos-enroll.sh` 由发布构建从本脚本生成，逐字节一致，并纳入企业包及摘要清单。三个入口均支持公开工件参数 `-PkgSha256`、`-TeamId`、`-PkgUrl` 或 `-PkgPath`，以及 `-MigrateUserServices 0/1`；参数覆盖对应环境变量，重复、缺值、未知参数和来源冲突拒绝。交互入口不再自行提权、提前停旧服务、下载未验证包或写服务器覆盖文件；旧 `-Server` 参数拒绝。控制台部署不得再注入改写 Mac 脚本内容。见 [管理员安装说明](../public/downloads/MACOS-INSTALL.md)。

历史入网的 Collector/令牌/签名密钥、间隔、设备 ID、安装目录环境变量，以及 `AEGIS_ENROLL_UNINSTALL`，存在即在任何外部命令前拒绝（包括空值）。不输出值、不重解释为新安装或凭据轮转。`AEGIS_BASE_URL` 保持下载根地址含义。详细迁移表见管理员安装说明；旧单用户卸载不能自动扩展为系统多用户卸载。

## 安装顺序与拒绝条件

1. 检查管理员身份、macOS、输入及旧版服务状态。发现旧系统服务或待核实的清理标记时，返回迁移/核实状态。常见用户 LaunchAgent 默认拒绝；显式启用用户迁移时只记录发现状态，继续工件信任验证，此时不停止旧服务。当前不承诺覆盖所有自定义历史服务位置。
2. 在系统临时目录建立私有暂存目录，复制本地包或下载 HTTPS 包。连接超时 15 秒、下载总时限 120 秒，包上限 128 MiB；文件写入资源限额和落盘大小复核共同约束超大输入。
3. 验证整包 SHA-256，再要求系统 `pkgutil --check-signature` 成功，且签名链的首个证书为匹配固定 Team ID 的 Developer ID Installer。
4. 要求系统安全评估已启用；使用 `spctl --assess --type install --raw --ignore-cache --no-cache` 获取结构化结果。只接受布尔允许、`Notarized Developer ID` 来源、无覆盖放行字段；存在下层判定时也必须为布尔允许。退出码为零或顶层允许均不足以单独证明可信。
5. 再次校验整包摘要。显式启用用户迁移时，才用系统 `pkgutil --expand` 展开已批准包的元数据与脚本（不展开 Payload、不执行脚本），验证 `Scripts/aegis-package-capabilities.json`：固定 schema、包标识、`journaled-prepare-v1` 协议、布尔外部 Python 依赖为 false，并校验声明绑定的 postinstall SHA-256。能力文件和脚本必须为无链接/额外硬链接的常规文件，大小分别不超过 4 KiB/256 KiB；路径组件不能为符号链接。旧包缺失能力声明、声明错误或脚本摘要不符时，拒绝调用 Installer。
6. 能力检查后重新检查旧服务、启动文件和待清理状态，再次验证完整包摘要，然后调用系统 Installer。下载/评估期间出现的新文件不能绕过迁移开关；这是时点复核，包内准备流程仍负责重新校验与确认停服。已批准包的 postinstall 使用原生候选执行旧用户服务准备；准备失败中止安装。Installer 成功仍需客户端诊断、入网及 Collector 接收证据。

能力声明属于批准发布者的包内契约，整包签名和固定摘要保护其来源；它不是独立的运行证明。postinstall 仍需客户端能力自检，双架构 CI 验证实际冻结程序与包。迁移只准备固定用户服务标签，不扩大到旧系统 daemon。详见 [准备与恢复契约](MACOS-LEGACY-SERVICES.md)。

不会修改系统安全评估设置、删除隔离属性或使用允许不受信任包的参数。签名与公证由 Apple 工具判断，入口额外限制批准发布者和批准工件；有关两类签名与安装包评估，见 [Apple 公证说明](https://developer.apple.com/videos/play/wwdc2019/703/)。

网络步骤有内部时限；平台验签/公证评估及 Installer 没有由本脚本强制终止的时限。MDM 应设置任务监控；外部超时、断电或强制终止后的安装状态必须重新核实，不得据此自动宣称回滚。暂存记录仅限 root 访问，正常退出/可捕获信号会清理；强制终止可能留下私有暂存目录。

## 结果与后续处理

标准输出为 `aegis.mdm-install-result/v1`，只包含固定状态、是否尝试安装、Installer 是否成功、健康是否验证及合法格式的工件摘要，另含 `legacy_user_migration_requested` 与 `legacy_user_launch_files_detected`。后者仅表示发现已识别的启动文件，不证明服务正在运行或迁移完成。原始下载、签名、公证和安装器输出不上传为 MDM 结果。

| 状态 | 处理 |
| --- | --- |
| `installed_health_pending`（退出 0） | 安装器成功；`health_verified` 仍为 false，执行内嵌诊断及上报验收 |
| `trusted_digest_required` / `publisher_required`（退出 2） | 补齐经过批准的 MDM 发布配置，不降低验证要求 |
| `legacy_enrollment_settings_not_supported`（退出 2） | 按实际意图改用批准包安装、原生配置或服务器迁移流程；不静默忽略旧设置 |
| `legacy_uninstall_setting_requires_maintenance`（退出 2） | 没有安装或停服；按实际退役范围使用维护流程，不能去掉变量后直接重跑安装 |
| `legacy_service_migration_required` | 旧系统服务需单独迁移；旧用户服务可通过受保护部署设置启用本入口的迁移流程 |
| `migration_capability_unavailable` / `migration_script_digest_mismatch` / `migration_package_expansion_failed` | 不调用 Installer；使用有经过验证的迁移能力的批准包，不直接绕过门禁 |
| `prior_cleanup_requires_verification` / `legacy_service_state_unavailable` | 核实旧进程/服务状态后再安装 |
| 摘要、签名、公证、覆盖放行或包变化拒绝 | 不调用 Installer，保留已安装客户端状态，检查发布供应链与部署配置 |
| `installer_failed_state_requires_verification` | Installer 已运行，可能部分更改系统；核实状态，不能承诺旧版完整或自动回滚 |

健康检查使用 `mdm-macos-compliance.sh` 调用客户端内嵌诊断；受保护上报配置使用 [原生配置入口](MACOS-CONFIGURATION.md)。历史 `rollback-aegis-macos.sh` 管理的是 Python 三文件安装布局，不能用于本原生包。原生安装回滚、真实旧用户服务切换/激活恢复、真实签名公证及完整生命周期验收仍为发布前待办，见 [R7 契约](MACOS-RUNTIME-CONTRACT.md)。
