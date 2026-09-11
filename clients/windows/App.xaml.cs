using System.Windows;
using AegisAgent.Services;
using AegisAgent.Models;

namespace AegisAgent;

/// <summary>
/// Aegis Agent — Windows 系统托盘安全客户端
/// 无主窗口，仅在通知区域运行。
/// </summary>
public partial class App : Application
{
    private readonly ScannerService _scanner = new();
    private readonly ReporterService _reporter = new();
    private readonly PolicyService _policy = new();
    private AgentConfig _config = AgentConfig.Load();
    private System.Windows.Threading.DispatcherTimer? _scanTimer;
    private Report? _lastReport;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 初始化托盘图标（通过 Views/TrayIcon.xaml）
        var tray = new Views.TrayIcon();
        tray.ScanNow += async (_, _) => await RunScanAsync();
        tray.ShowReport += (_, _) => ShowLastReport();
        tray.Exit += (_, _) => Shutdown();
        tray.Show();

        // 策略热重载
        _policy.StartWatching();
        _policy.PolicyChanged += (_, p) => _config.ScanIntervalSeconds = p?.ScanIntervalSeconds ?? _config.ScanIntervalSeconds;

        // 周期扫描
        StartPeriodicScan();

        // 首次扫描
        _ = RunScanAsync();
    }

    private void StartPeriodicScan()
    {
        _scanTimer?.Stop();
        _scanTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(_config.ScanIntervalSeconds)
        };
        _scanTimer.Tick += async (_, _) => await RunScanAsync();
        _scanTimer.Start();
    }

    private async Task RunScanAsync()
    {
        var report = _scanner.BuildReport(_config, _policy.Current);
        _lastReport = report;
        await _reporter.SubmitAsync(report, _config);
    }

    private void ShowLastReport()
    {
        if (_lastReport is null)
        {
            MessageBox.Show("暂无报告，请先执行一次扫描。", "Aegis Agent", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var summary = $"设备: {_lastReport.DeviceId}\n" +
                      $"严重: {_lastReport.Summary.Critical} | 高危: {_lastReport.Summary.High} | " +
                      $"中危: {_lastReport.Summary.Medium} | 低危: {_lastReport.Summary.Low}\n" +
                      $"发现总数: {_lastReport.Findings.Count}\n" +
                      $"扫描时间: {DateTimeOffset.FromUnixTimeSeconds(_lastReport.ScannedAt).LocalDateTime:yyyy-MM-dd HH:mm:ss}";
        MessageBox.Show(summary, "最近扫描报告", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
