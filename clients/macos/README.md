# Aegis Agent for macOS

企业 AI Coding 安全治理终端客户端 — macOS 菜单栏应用。

## 要求

- macOS 14 (Sonoma) 或更高
- Swift 5.9+
- 注意：本机 SwiftPM 沙箱被系统禁用，构建必须加 `--disable-sandbox`

## 构建与运行

```bash
swift build --disable-sandbox
swift run --disable-sandbox
```

运行后在菜单栏出现盾牌图标，右键菜单：
- 状态：显示当前连接状态和最近扫描结果
- 立即扫描：手动触发一次完整扫描
- 查看最近报告：显示上次扫描的 JSON 报告摘要
- 偏好设置：显示配置文件路径和当前参数
- 退出

## 配置文件

`~/Library/Application Support/AegisAgent/config.json`

```json
{
  "collectorURL": "http://127.0.0.1:8931",
  "deviceId": "MAC-YOUR-HOSTNAME",
  "token": "<collector-bearer-token>",
  "hmacSecret": "<hmac-signing-secret>",
  "scanIntervalSeconds": 3600,
  "scanRoot": "/path/to/projects"
}
```

## 策略文件

`~/Library/Application Support/AegisAgent/policy.json`

由 Intune 或手动部署。支持热重载（修改后自动生效），解析失败时保留 last-known-good。

## 部署 (Intune)

使用 `public/downloads/intune-macos-install.sh` 脚本，将编译产物放到：
`/Library/Application Support/AegisAgent/AegisAgent`

LaunchDaemon plist 负责开机自启和周期保活。

## 项目结构

```
Sources/
├── main.swift              # 入口：NSApplication + accessory 模式
├── AppDelegate.swift       # 菜单栏 UI + 周期扫描调度
└── Agent/
    ├── Scanner.swift       # 发现 + Skill/MCP/代码扫描
    ├── Reporter.swift      # HTTPS 上报 + HMAC 签名 + 离线队列
    ├── PolicyLoader.swift  # 策略热重载 + last-known-good
    └── Config.swift        # 配置加载与默认值
```
