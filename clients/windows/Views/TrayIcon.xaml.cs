using System.Windows;
using System.Windows.Controls;
using Hardcodet.Wpf.TaskbarNotification;

namespace AegisAgent.Views;

/// <summary>
/// 系统托盘图标 + 右键菜单。
/// 使用 Hardcodet.NotifyIcon.Wpf 实现通知区域图标。
/// </summary>
public partial class TrayIcon : Window
{
    private TaskbarIcon? _icon;

    public event EventHandler? ScanNow;
    public event EventHandler? ShowReport;
    public event EventHandler? Exit;

    public TrayIcon()
    {
        InitializeComponent();
        InitTrayIcon();
    }

    private void InitTrayIcon()
    {
        _icon = new TaskbarIcon
        {
            IconSource = new System.Drawing.Icon(System.Drawing.SystemIcons.Shield, 16, 16),
            ToolTipText = $"Aegis Agent v{Models.AgentConfig.Version} — 企业 AI Coding 安全治理",
            ContextMenu = BuildMenu(),
            Visibility = Visibility.Visible,
        };
    }

    private ContextMenu BuildMenu()
    {
        var menu = new ContextMenu();

        var header = new MenuItem { Header = $"Aegis Agent v{Models.AgentConfig.Version}", IsEnabled = false };
        menu.Items.Add(header);
        menu.Items.Add(new Separator());

        var status = new MenuItem { Header = "状态: 就绪", IsEnabled = false, Tag = "status" };
        menu.Items.Add(status);

        var scan = new MenuItem { Header = "立即扫描 (_S)", InputGestureText = "Ctrl+S" };
        scan.Click += (_, _) => ScanNow?.Invoke(this, EventArgs.Empty);
        menu.Items.Add(scan);

        var report = new MenuItem { Header = "查看最近报告 (_R)" };
        report.Click += (_, _) => ShowReport?.Invoke(this, EventArgs.Empty);
        menu.Items.Add(report);

        menu.Items.Add(new Separator());

        var settings = new MenuItem { Header = "设置..." };
        settings.Click += (_, _) => MessageBox.Show(
            $"配置文件: {System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisAgent", "config.json")}",
            "Aegis Agent 设置", MessageBoxButton.OK, MessageBoxImage.Information);
        menu.Items.Add(settings);

        var about = new MenuItem { Header = "关于 Aegis Agent" };
        about.Click += (_, _) => MessageBox.Show(
            "Aegis Agent for Windows\n版本 0.30.0\n\n企业 AI Coding 安全治理终端客户端\n发现 Cursor / Claude Code / Codex / Windsurf\n加载安全基线 · 扫描 Skill / MCP / 代码\n上报至 Collector · 联动深信服 EDR",
            "关于", MessageBoxButton.OK, MessageBoxImage.Information);
        menu.Items.Add(about);

        menu.Items.Add(new Separator());

        var exit = new MenuItem { Header = "退出 (_X)" };
        exit.Click += (_, _) => Exit?.Invoke(this, EventArgs.Empty);
        menu.Items.Add(exit);

        return menu;
    }

    public void UpdateStatus(string text)
    {
        if (_icon?.ContextMenu?.Items.OfType<MenuItem>().FirstOrDefault(m => m.Tag as string == "status") is { } item)
            item.Header = $"状态: {text}";
    }

    public new void Show()
    {
        // 不显示窗口本体，仅初始化托盘
        WindowState = WindowState.Minimized;
        ShowInTaskbar = false;
        Visibility = Visibility.Hidden;
    }

    protected override void OnClosed(EventArgs e)
    {
        _icon?.Dispose();
        base.OnClosed(e);
    }
}
