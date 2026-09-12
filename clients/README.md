# Aegis 原生终端客户端

企业 AI Coding 安全治理终端 Agent 的原生实现，替代 Python 脚本用于生产部署。

## 架构

```
┌─────────────────────────────────────────────────────┐
│  原生客户端 (Swift / C#)                             │
│  ├─ Scanner: 发现 AI Agent + 扫描 Skill/MCP/代码     │
│  ├─ Reporter: HTTPS + HMAC-SHA256 上报 + 离线队列    │
│  ├─ PolicyLoader: 热重载 + last-known-good 回退      │
│  └─ Tray/MenuBar UI: 状态展示 + 手动触发             │
└──────────────────────┬──────────────────────────────┘
                       │ aegis.report/v1 (JSON)
                       ▼
              ┌─────────────────┐
              │   Collector     │  (Python, 端口 8931)
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │  Adapter Worker │ → 厂商 EDR / 厂商桌管
              └─────────────────┘
```

## 平台

| 平台 | 目录 | 语言 | UI 形态 | 部署方式 |
|------|------|------|---------|----------|
| macOS 14+ | `clients/macos/` | Swift 5.9 | 菜单栏 (NSStatusItem) | MDM Shell Script |
| Windows 10+ | `clients/windows/` | C# / .NET 8 | 系统托盘 (WPF NotifyIcon) | MDM Remediations |

## 功能对等矩阵

| 能力 | Python Agent | macOS Swift | Windows C# |
|------|:---:|:---:|:---:|
| AI Agent 发现 | ✓ | ✓ | ✓ |
| Skill 扫描 | ✓ | ✓ | ✓ |
| MCP 扫描 | ✓ | ✓ | ✓ |
| 代码质量扫描 | ✓ | ✓ | ✓ |
| HMAC 签名上报 | ✓ | ✓ | ✓ |
| 离线队列 (有界) | ✓ | ✓ | ✓ |
| 策略热重载 | ✓ | ✓ | ✓ |
| last-known-good 回退 | ✓ | ✓ | ✓ |
| 原生 UI (托盘/菜单栏) | ✗ | ✓ | ✓ |
| 周期自动扫描 | ✓ (cron) | ✓ (Timer) | ✓ (DispatcherTimer) |

## 共享契约

- **报告格式**: `aegis.report/v1` (JSON Schema 见 `public/downloads/aegis-report.schema.json`)
- **认证**: Bearer token + HMAC-SHA256 签名 (`X-Report-Signature` header)
- **策略格式**: 同 `public/downloads/aegis-policy.json`
- **配置路径**:
  - macOS: `~/Library/Application Support/AegisAgent/config.json`
  - Windows: `%PROGRAMDATA%\AegisAgent\config.json`

## 构建

### macOS
```bash
cd clients/macos
swift build --disable-sandbox   # 本机 SwiftPM 沙箱被禁，必须加此标志
swift run --disable-sandbox
```

### Windows
```powershell
cd clients\windows
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained
```

## 当前状态

**骨架阶段** — 核心架构和接口已定义，扫描逻辑已移植关键路径，
复杂规则（完整 SAST、依赖 CVE 比对、Skill 签名验证）标记为 TODO 待后续迭代。

## 下一步

- [ ] 补全 Skill 签名验证逻辑
- [ ] 补全依赖 CVE 数据库比对
- [ ] macOS: 打包为 .pkg + 代码签名 + 公证
- [ ] Windows: 打包为 .msi + Authenticode 签名
- [ ] MDM 部署脚本适配原生客户端
- [ ] 自动更新通道 (灰度 → 全量)
