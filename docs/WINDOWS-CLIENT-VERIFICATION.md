# Windows 客户端架构与验证

支持目标为 Windows ARM64 与 Intel/AMD x64。统一的客户端命令和报告契约由两个原生运行时构建实现；ARM64 上运行 x64 模拟进程必须明确标注模拟执行。

## 无副作用运行时自检

```powershell
.\AegisServiceHost.exe --selftest
```

成功退出码为 0，输出 `aegis.client-selftest/v1` JSON，包含主机版本、操作系统架构、进程架构及健康报告序列化结果。自检不读取配置、凭据或用户文件，不执行扫描、服务安装、卸载或网络请求。额外参数和未知命令以退出码 64 拒绝。

测试必须运行经过裁剪、自包含发布的二进制，而不只是检查 C# 编译。这样可以覆盖源生成 JSON 序列化及运行时架构问题。

```powershell
.\scripts\test-windows-client.ps1 -BinaryPath .\artifacts\client\AegisServiceHost.exe -ExpectedArchitecture Arm64 -EvidencePath .\artifacts\client\evidence.json
```

将 `ExpectedArchitecture` 改为 `X64` 可验证 x64。仅验证模拟运行时才指定 `-AllowEmulation`，证据中的 `native_execution` 会保持 false。

## CI 与证据范围

`windows-client-runtime` 工作流分别使用 `windows-2025`（x64）与 `windows-11-arm`（ARM64）原生构建并运行自检、参数拒绝测试。使用项目已有 .NET 10 SDK 目标，不引入新的 NuGet 包或 GitHub Action。运行器采用 GitHub 提供的预装 SDK；它的具体版本会随运行器镜像变化，这不是可复现签名发行构建。

这些标签与架构见 [GitHub 官方运行器说明](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。每次测试输出二进制 SHA-256、实际运行架构及验证范围，写入工作流摘要；摘要不包含真实设备或用户信息。

此自检不证明 MSI 安装、SCM 服务启动、真实扫描、基线注入、Skill/MCP 阻断、更新回滚或卸载已通过。以上项目需要隔离终端另行验收。生产签名、发布和部署继续走人工审批与原有门禁。

## 部署与回滚

新增命令与现有命令兼容。只有重新构建的客户端包含 `--selftest`，旧包会按未知命令返回 64。它可纳入发行候选包验证，但本变更不会自动发布安装包。回滚客户端会移除此命令，既有安装和扫描命令保持原契约。
