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
//   --install    委派 Install-Aegis-Windows.ps1：零接触入网 + DPAPI 配置 + sc.exe 注册服务并启动
//   --uninstall  委派 Install-Aegis-Windows.ps1 -Uninstall：停止并删除服务
//   --once       前台跑一次扫描（排障用）
//
// macOS 不使用本壳：macOS 由 .pkg + LaunchDaemon 直接驱动 Python Agent（已是服务级）。
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

internal static class Program
{
    private const string ServiceName = "AegisAgent";
    private const string HostVersion = "0.1.0";
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
        if (args.Length != 1) { Console.Error.WriteLine("usage: AegisServiceHost --service|--install|--uninstall|--once"); return 64; }
        return args[0] switch
        {
            "--service" => RunWindowsService(),
            "--install" => await DelegateAsync("Install-Aegis-Windows.ps1", Array.Empty<string>()),
            "--uninstall" => await DelegateAsync("Install-Aegis-Windows.ps1", new[] { "-Uninstall" }),
            "--once" => await RunAsync(once: true, CancellationToken.None),
            _ => BadUsage(),
        };
    }

    private static int BadUsage() { Console.Error.WriteLine("usage: AegisServiceHost --service|--install|--uninstall|--once"); return 64; }

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
            await WriteHealth(healthPath, exitCode is 0 or 2 ? "healthy" : "degraded", scanStarted, exitCode, startedAt, error);
            if (once || stop.IsCancellationRequested) break;
            try { await Task.Delay(TimeSpan.FromSeconds(interval), stop); } catch (OperationCanceledException) { break; }
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

    private static async Task WriteHealth(string path, string state, long? lastScanStartedAt, int exitCode, long serviceStartedAt, string? error)
    {
        var value = new
        {
            schema = HealthSchema,
            host_version = HostVersion,
            state,
            service_started_at = serviceStartedAt,
            updated_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            last_scan_started_at = lastScanStartedAt,
            last_scan_exit_code = exitCode,
            scanner = "windows-powershell",
            error,
            contains_secrets = false,
            arbitrary_command_enabled = false,
        };
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await File.WriteAllBytesAsync(temp, bytes);
            File.Move(temp, path, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* 健康文件尽力而为，不影响服务 */ }
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
