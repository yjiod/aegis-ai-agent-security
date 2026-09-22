// AegisServiceHost —— 最小化 Windows 服务壳（SCM）。
//
// 设计取舍（对照 sentinel 原生 host 的"最小移植"）：
//   只保留 Windows 服务真正需要的部分——SCM 生命周期 + 周期调用扫描器 + 安装/卸载委派；
//   刻意丢弃 sentinel 的 --status 版本耦合报告校验、--user-session 用户会话桥（Aegis 的
//   PowerShell/Python Agent 自身已做基线注入）、以及 sentinel.* 私有 schema。
//   入网（/api/enroll + DPAPI 写 reporting.dpapi）与 SCM 服务注册放在随包的
//   Install-Aegis-Windows.ps1 里（复用已验证的 PowerShell 逻辑），host 只负责 shell-out，
//   因此本二进制无需 HttpClient / ProtectedData 依赖，保持精简。
//
// 动词：
//   --service    作为 Windows 服务运行（SCM 调度；周期执行 aegis-windows.ps1）
//   --install [AEGIS_SERVER_URL=<https origin>]
//              委派 Install-Aegis-Windows.ps1：零接触入网 + DPAPI 配置 + 注册服务并启动。
//              可选第二个参数由 MSI 类型 18 自定义动作格式化注入（见 AegisAgent.wxs），
//              使公开包能在装机时指向真实控制台而不把域名烘进包里。
//   --uninstall  委派 Install-Aegis-Windows.ps1 -Uninstall：停止并删除服务
//   --once       前台跑一次扫描（排障用）
//
// macOS 不使用本壳：macOS 由 .pkg + LaunchDaemon 直接驱动 Python Agent（已是服务级）。
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

internal static class Program
{
    private const string ServiceName = "AegisAgent";
    // BUG C：host_version 不再硬编码。读程序集版本（-p:Version 注入的单一真源）：
    // 优先 InformationalVersion（含 commit sha），回落 AssemblyVersion（裁剪安全）。
    // 用实例方法 GetCustomAttributes（非扩展方法），避免额外 using 与裁剪影响。
    private static readonly string HostVersion = ResolveHostVersion();
    private static string ResolveHostVersion()
    {
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        foreach (var attr in asm.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false))
        {
            if (attr is System.Reflection.AssemblyInformationalVersionAttribute iv
                && !string.IsNullOrEmpty(iv.InformationalVersion))
                return iv.InformationalVersion;
        }
        return asm.GetName().Version?.ToString() ?? "0.0.0";
    }
    private const string HealthSchema = "aegis.service-health/v1";
    private const int DefaultIntervalSeconds = 3600;

    private static readonly Native.ServiceMainCallback ServiceMainDelegate = ServiceMain;
    private static readonly Native.ServiceControlHandler ServiceControlDelegate = ServiceControl;
    private static CancellationTokenSource? serviceStop;
    private static IntPtr serviceStatusHandle;
    private static Native.ServiceStatus serviceStatus;

    private static string BaseDir => AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    private static string DataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisAgent");

    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("AegisServiceHost 仅用于 Windows 服务；macOS 请用 .pkg（LaunchDaemon 驱动 Python Agent）。");
            return 64;
        }
        // --install 额外接受一个 AEGIS_SERVER_URL=<origin> 参数：MSI 类型 18 自定义动作把
        // 安装期公共属性格式化进 ExeCommand（见 AegisAgent.wxs），用于公开包在装机时
        // 指向真实控制台——真实主机域名不入库，包里烘的是 RFC2606 占位域。
        if (args.Length >= 1 && args[0] == "--install")
        {
            if (args.Length > 2) return BadUsage();
            var forwarded = ParseInstallArgs(args);
            if (forwarded is null) return BadUsage();
            return await DelegateAsync("Install-Aegis-Windows.ps1", forwarded);
        }
        if (args.Length != 1) return BadUsage();
        return args[0] switch
        {
            "--service" => RunWindowsService(),
            "--uninstall" => await DelegateAsync("Install-Aegis-Windows.ps1", new[] { "-Uninstall" }),
            "--once" => await RunAsync(once: true, CancellationToken.None),
            _ => BadUsage(),
        };
    }

    private static int BadUsage() { Console.Error.WriteLine("usage: AegisServiceHost --service|--install [AEGIS_SERVER_URL=<https origin>]|--uninstall|--once"); return 64; }

    /// <summary>
    /// 把 <c>--install AEGIS_SERVER_URL=&lt;origin&gt;</c> 翻译成脚本的 <c>-ServerUrl</c>。
    /// 属性未注入时 MSI 格式化成空值（<c>AEGIS_SERVER_URL=</c>），此时不传 -ServerUrl，
    /// 由脚本按「server.json 非占位域 → 机器级环境变量」的顺序自行解析。
    /// 返回 null 表示第二个参数无法识别——按用法错误退出，避免把 URL 静默丢掉后
    /// 装出一个永远无法入网的 agent。
    /// </summary>
    private static string[]? ParseInstallArgs(string[] args)
    {
        if (args.Length != 2) return Array.Empty<string>();
        const string prefix = "AEGIS_SERVER_URL=";
        if (!args[1].StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        var url = args[1].Substring(prefix.Length).Trim();
        return url.Length == 0 ? Array.Empty<string>() : new[] { "-ServerUrl", url };
    }

    // ── 委派 PowerShell（安装/卸载逻辑随包，避免在 C# 里重复 DPAPI/入网）────────────
    private static async Task<int> DelegateAsync(string script, string[] extraArgs)
    {
        var path = Path.Combine(BaseDir, script);
        if (!File.Exists(path)) { Console.Error.WriteLine($"missing {script}"); return 78; }
        var psi = new ProcessStartInfo(PowerShell()) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path }) psi.ArgumentList.Add(a);
        foreach (var a in extraArgs) psi.ArgumentList.Add(a);
        try
        {
            using var p = new Process { StartInfo = psi };
            if (!p.Start()) return 70;
            await p.WaitForExitAsync();
            return p.ExitCode;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception) { return 70; }
    }

    private static string PowerShell() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

    // ── Windows 服务（SCM）──────────────────────────────────────────────
    private static int RunWindowsService()
    {
        var entries = new[]
        {
            new Native.ServiceTableEntry { ServiceName = ServiceName, ServiceMain = ServiceMainDelegate },
            new Native.ServiceTableEntry()
        };
        if (!Native.StartServiceCtrlDispatcher(entries)) return Marshal.GetLastWin32Error();
        return 0;
    }

    private static void ServiceMain(int argumentCount, IntPtr arguments)
    {
        serviceStatusHandle = Native.RegisterServiceCtrlHandlerEx(ServiceName, ServiceControlDelegate, IntPtr.Zero);
        if (serviceStatusHandle == IntPtr.Zero) return;
        serviceStatus = new Native.ServiceStatus { ServiceType = Native.ServiceWin32OwnProcess, CurrentState = Native.ServiceStartPending, WaitHint = 30_000 };
        PublishServiceStatus();
        serviceStop = new CancellationTokenSource();
        serviceStatus.CurrentState = Native.ServiceRunning;
        serviceStatus.ControlsAccepted = Native.ServiceAcceptStop | Native.ServiceAcceptShutdown;
        serviceStatus.WaitHint = 0;
        PublishServiceStatus();
        var exitCode = 0;
        try { exitCode = RunAsync(once: false, serviceStop.Token).GetAwaiter().GetResult(); }
        catch { exitCode = 1; }
        serviceStatus.CurrentState = Native.ServiceStopped;
        serviceStatus.ControlsAccepted = 0;
        serviceStatus.Win32ExitCode = exitCode == 0 ? 0u : 1066u;
        serviceStatus.ServiceSpecificExitCode = (uint)Math.Max(exitCode, 0);
        PublishServiceStatus();
        serviceStop.Dispose();
        serviceStop = null;
    }

    private static uint ServiceControl(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is Native.ServiceControlStop or Native.ServiceControlShutdown)
        {
            serviceStatus.CurrentState = Native.ServiceStopPending;
            serviceStatus.ControlsAccepted = 0;
            serviceStatus.WaitHint = 30_000;
            PublishServiceStatus();
            serviceStop?.Cancel();
        }
        return 0;
    }

    private static void PublishServiceStatus()
    {
        if (serviceStatusHandle != IntPtr.Zero) Native.SetServiceStatus(serviceStatusHandle, ref serviceStatus);
    }

    // ── 扫描循环：周期调用 aegis-windows.ps1（它从 %ProgramData%\AegisAgent 读取配置）──
    private static async Task<int> RunAsync(bool once, CancellationToken stop)
    {
        var scanner = Path.Combine(BaseDir, "aegis-windows.ps1");
        var healthPath = Path.Combine(DataDir, "service-health.json");
        Directory.CreateDirectory(DataDir);
        var startedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var interval = ReadIntervalSeconds();
        await WriteHealth(healthPath, "starting", null, 0, startedAt, null);
        do
        {
            var scanStarted = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exitCode = 127;
            string? error = null;
            try
            {
                var psi = new ProcessStartInfo(PowerShell()) { UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scanner }) psi.ArgumentList.Add(a);
                using var p = new Process { StartInfo = psi };
                if (!File.Exists(scanner)) throw new InvalidOperationException("scanner_missing");
                if (!p.Start()) throw new InvalidOperationException("scanner_start_failed");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
                timeout.CancelAfter(TimeSpan.FromMinutes(30));
                try { await p.WaitForExitAsync(timeout.Token); exitCode = p.ExitCode; }
                catch (OperationCanceledException) { if (!p.HasExited) p.Kill(entireProcessTree: true); throw; }
            }
            catch (OperationCanceledException) { error = stop.IsCancellationRequested ? "scanner_shutdown" : "scanner_timeout"; }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception) { error = ex.GetType().Name; }
            // PowerShell 扫描器：0=无高危，2=有 critical/high（均属正常完成），其余为异常。
            // BUG I 掩盖面修复：exit=2 但若发现项含"配置不可读/策略加载失败"类（空 DACL 等导致
            // 扫描器拒报），健康状态记 degraded 而非 healthy，避免健康度把故障掩盖。
            var state = exitCode is 0 or 2 ? "healthy" : "degraded";
            if (exitCode == 2 && HasConfigFailureFinding(healthPath)) { state = "degraded"; error = (error ?? "") + "+config_unreadable"; }
            await WriteHealth(healthPath, state, scanStarted, exitCode, startedAt, error);
            if (once || stop.IsCancellationRequested) break;
            // P1-3(30k 防惊群): 每周期加 ±10% 抖动，避免批量装机终端长期对齐到同一分钟齐发上报
            // (无抖动时 30k 台窄窗口齐发 → 瞬时数百写/秒压垮单写采集器)。仅影响计时。
            var jitteredSeconds = interval * (0.9 + Random.Shared.NextDouble() * 0.2);
            try { await Task.Delay(TimeSpan.FromSeconds(jitteredSeconds), stop); } catch (OperationCanceledException) { break; }
        } while (!stop.IsCancellationRequested);
        return 0;
    }

    private static int ReadIntervalSeconds()
    {
        try
        {
            var path = Path.Combine(BaseDir, "server.json");
            if (!File.Exists(path)) return DefaultIntervalSeconds;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("scan_interval_seconds", out var v) && v.TryGetInt32(out var s) && s >= 60 && s <= 86400) return s;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { }
        return DefaultIntervalSeconds;
    }

    /// <summary>读最近一次扫描报告，判断是否含"配置不可读/策略加载失败"类发现（空 DACL 等）。
    /// 读不到报告/解析失败一律返回 false（不据此降级，避免误报）。</summary>
    private static bool HasConfigFailureFinding(string healthPath)
    {
        try
        {
            var dir = Path.GetDirectoryName(healthPath);
            if (string.IsNullOrEmpty(dir)) return false;
            var latest = Path.Combine(dir, "reports", "latest.json");
            if (!File.Exists(latest)) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(latest));
            if (!doc.RootElement.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array) return false;
            foreach (var f in findings.EnumerateArray())
            {
                if (f.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String)
                {
                    var s = k.GetString();
                    if (s is "reporting_config_invalid" or "policy_load_failed" or "reporting_config_unreadable") return true;
                }
            }
            return false;
        }
        catch { return false; }
    }

    private static async Task WriteHealth(string path, string state, long? lastScanStartedAt, int exitCode, long serviceStartedAt, string? error)
    {
        var value = new ServiceHealth
        {
            Schema = HealthSchema,
            HostVersion = HostVersion,
            State = state,
            ServiceStartedAt = serviceStartedAt,
            UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            LastScanStartedAt = lastScanStartedAt,
            LastScanExitCode = exitCode,
            Scanner = "windows-powershell",
            Error = error,
            ContainsSecrets = false,
            ArbitraryCommandEnabled = false,
        };
        try
        {
            // 必须传源生成的 JsonTypeInfo：发布启用 PublishTrimmed 后 SDK 会关闭反射式序列化
            // （JsonSerializerIsReflectionEnabledByDefault=false），无上下文的 SerializeToUtf8Bytes<T>
            // 会抛 InvalidOperationException；而 WriteHealth 在扫描循环之前就被调用，
            // 该异常会直接终结进程 —— 装成服务即表现为 SCM 1053 + 恢复策略下的无限重启。
            var bytes = JsonSerializer.SerializeToUtf8Bytes(value, ServiceHealthJsonContext.Default.ServiceHealth);
            var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await File.WriteAllBytesAsync(temp, bytes);
            File.Move(temp, path, true);
        }
        // 健康文件是尽力而为：任何失败（序列化 / 权限 / IO）都不得让服务进程退出。
        // 原先的 catch 过滤器只覆盖 IOException / UnauthorizedAccessException，
        // 漏掉序列化类异常正是崩溃逃逸的原因，故此处收敛为全量兜底。
        catch (Exception) { }
    }

    // ── Win32 SCM P/Invoke（通用骨架，移植自成熟实现，无产品耦合）──────────────
    private static class Native
    {
        internal const uint ServiceWin32OwnProcess = 0x10;
        internal const uint ServiceStopped = 0x01;
        internal const uint ServiceStartPending = 0x02;
        internal const uint ServiceStopPending = 0x03;
        internal const uint ServiceRunning = 0x04;
        internal const uint ServiceAcceptStop = 0x01;
        internal const uint ServiceAcceptShutdown = 0x04;
        internal const uint ServiceControlStop = 0x01;
        internal const uint ServiceControlShutdown = 0x05;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void ServiceMainCallback(int argumentCount, IntPtr arguments);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate uint ServiceControlHandler(uint control, uint eventType, IntPtr eventData, IntPtr context);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct ServiceTableEntry
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string? ServiceName;
            internal ServiceMainCallback? ServiceMain;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatus
        {
            internal uint ServiceType;
            internal uint CurrentState;
            internal uint ControlsAccepted;
            internal uint Win32ExitCode;
            internal uint ServiceSpecificExitCode;
            internal uint CheckPoint;
            internal uint WaitHint;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, ServiceControlHandler callback, IntPtr context);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus serviceStatus);
    }
}

// ── service-health.json 载荷（源生成序列化，trim / NativeAOT 安全）─────────────
// 字段名经 JsonPropertyName 钉死为既有 snake_case，保证改用源生成后
// %ProgramData%\AegisAgent\service-health.json 的对外 schema 与之前逐字节一致
// （含 error / last_scan_started_at 为 null 时仍显式输出 null）。
internal sealed class ServiceHealth
{
    [JsonPropertyName("schema")] public string Schema { get; set; } = string.Empty;
    [JsonPropertyName("host_version")] public string HostVersion { get; set; } = string.Empty;
    [JsonPropertyName("state")] public string State { get; set; } = string.Empty;
    [JsonPropertyName("service_started_at")] public long ServiceStartedAt { get; set; }
    [JsonPropertyName("updated_at")] public long UpdatedAt { get; set; }
    [JsonPropertyName("last_scan_started_at")] public long? LastScanStartedAt { get; set; }
    [JsonPropertyName("last_scan_exit_code")] public int LastScanExitCode { get; set; }
    [JsonPropertyName("scanner")] public string Scanner { get; set; } = string.Empty;
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("contains_secrets")] public bool ContainsSecrets { get; set; }
    [JsonPropertyName("arbitrary_command_enabled")] public bool ArbitraryCommandEnabled { get; set; }
}

[JsonSerializable(typeof(ServiceHealth))]
internal sealed partial class ServiceHealthJsonContext : JsonSerializerContext
{
}
