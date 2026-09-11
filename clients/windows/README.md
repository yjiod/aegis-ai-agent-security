# Aegis Agent for Windows

企业 AI Coding 安全治理终端客户端 — Windows 系统托盘应用。

## 要求

- Windows 10 1809+ 或 Windows 11
- .NET 8 SDK (构建时)
- .NET 8 Desktop Runtime (运行时，或使用 self-contained 发布)

## 构建

```powershell
dotnet build -c Release
```

## 发布 (self-contained，无需目标机装 .NET)

```powershell
dotnet publish -c Release -r win-x64 --self-contained -o publish\
```

## 运行

双击 `AegisAgent.exe`，应用启动后无主窗口，仅在系统通知区域显示盾牌图标。

右键菜单：
- 状态: 就绪/扫描中/已上报
- 立即扫描 (Ctrl+S)
- 查看最近报告
- 设置...
- 关于 Aegis Agent
- 退出

## 配置文件

`%PROGRAMDATA%\AegisAgent\config.json`

```json
{
  "collector_url": "http://127.0.0.1:8931",
  "device_id": "WIN-YOUR-MACHINE-NAME",
  "token": "<collector-bearer-token>",
  "hmac_secret": "<hmac-signing-secret>",
  "scan_interval_seconds": 3600,
  "scan_root": "C:\\Users\\you\\projects"
}
```

## 策略文件

`%PROGRAMDATA%\AegisAgent\policy.json`

由 Intune 部署。FileSystemWatcher 热重载，解析失败保留 last-known-good。

## 部署 (Intune)

使用 `public/downloads/intune-windows-remediate.ps1` 脚本：
1. 将 publish 目录复制到 `%PROGRAMFILES%\AegisAgent\`
2. 创建计划任务 (SYSTEM 账户，每小时触发)
3. 注册检测脚本 (`intune-windows-detect.ps1`) 用于合规检查

## 项目结构

```
├── AegisAgent.csproj       # .NET 8 WPF 项目
├── App.xaml / App.xaml.cs  # 应用入口，无主窗口
├── Views/
│   └── TrayIcon.xaml/.cs   # 系统托盘图标 + 右键菜单
├── Services/
│   ├── ScannerService.cs   # 发现 + Skill/MCP/代码扫描
│   ├── ReporterService.cs  # HTTPS 上报 + HMAC 签名 + 离线队列
│   └── PolicyService.cs    # 策略热重载 + last-known-good
└── Models/
    └── Report.cs           # aegis.report/v1 数据模型 + 配置
```
