# Aegis macOS 状态界面

Swift 菜单栏界面只读取受管系统服务的公开状态快照。扫描、治理、策略验证和上报由统一后台引擎执行。界面不会生成设备身份、存储凭据、读取原始报告或独立联网。

终端最低 macOS 14；无需 Python、Swift、Homebrew 或开发工具。构建机使用 Swift 5.9+ 和 macOS SDK。客户端遵守 [R7 零外部 Python 契约](../../docs/MACOS-RUNTIME-CONTRACT.md)。

## 开发构建

在仓库根目录执行：

```sh
swift test --package-path clients/macos
sh clients/macos/build-app.sh /absolute/path/to/new-output-directory
```

输出原生 `Aegis.app` 和 `Aegis.app.zip`，目录必须尚不存在。构建过程不安装依赖、不关闭 SwiftPM 沙箱。ARM64 与 Intel x64 分别由原生 CI runner 构建和测试；产物尚未完成正式签名公证。

## 界面行为

- 菜单显示最近检查状态，支持刷新和查看七项服务检查。
- 服务每 60 秒发布快照，界面每 30 秒刷新。超过 150 秒或明显来自未来的快照显示过期；缺失、不可信或格式错误的文件不显示正常。
- 退出界面不会停止系统服务。界面不要求管理员权限。
- 暂不提供手动扫描、配置编辑、自动启动和告警通知；这些能力需要受保护服务接口，不能另起一套扫描和凭据管理流程。

开发候选界面目前独立产出，尚未并入系统安装包及更新事务。完整客户端交付仍需完成该集成、签名公证和无外部 Python 环境下的生命周期验收，不能将独立 app 构建成功视为完成。

状态文件、安全边界及验证范围见 [桌面状态契约](../../docs/MACOS-DESKTOP-STATUS.md)。
