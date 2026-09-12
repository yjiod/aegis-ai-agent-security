import AppKit
import Foundation

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private let scanner = Scanner()
    private let reporter = Reporter()
    private let policy = PolicyLoader()
    private var config = AgentConfig.load()
    private var scanTimer: Timer?
    private var lastReport: Report?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "Aegis Agent")
        }
        buildMenu()
        policy.startWatching()
        startPeriodicScan()
        Task { await runScan() }
    }

    private func buildMenu() {
        let menu = NSMenu()
        menu.addItem(withTitle: "Aegis Agent v\(AgentConfig.version)", action: nil, keyEquivalent: "")
        menu.addItem(.separator())

        let statusItem = NSMenuItem(title: "状态: 检查中...", action: nil, keyEquivalent: "")
        statusItem.tag = 100
        menu.addItem(statusItem)

        menu.addItem(NSMenuItem(title: "立即扫描", action: #selector(scanNow), keyEquivalent: "s"))
        menu.addItem(NSMenuItem(title: "查看最近报告", action: #selector(showReport), keyEquivalent: "r"))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "偏好设置...", action: #selector(openSettings), keyEquivalent: ","))
        menu.addItem(NSMenuItem(title: "关于 Aegis Agent", action: #selector(showAbout), keyEquivalent: ""))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "退出", action: #selector(quit), keyEquivalent: "q"))

        for item in menu.items where item.action != nil {
            item.target = self
        }
        self.statusItem.menu = menu
    }

    private func updateStatus(_ text: String) {
        if let item = statusItem.menu?.item(withTag: 100) {
            item.title = "状态: \(text)"
        }
    }

    private func startPeriodicScan() {
        scanTimer?.invalidate()
        scanTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(config.scanIntervalSeconds), repeats: true) { [weak self] _ in
            Task { await self?.runScan() }
        }
    }

    @objc private func scanNow() { Task { await runScan() } }

    private func runScan() async {
        updateStatus("扫描中...")
        let report = scanner.buildReport(config: config, policy: policy.current)
        lastReport = report
        updateStatus("上报中...")
        let result = await reporter.submit(report, config: config)
        switch result {
        case .success: updateStatus("✓ 已上报 (\(report.findings.count) 个发现)")
        case .failure(let err): updateStatus("✗ 上报失败: \(err.localizedDescription)")
        }
    }

    @objc private func showReport() {
        guard let report = lastReport else {
            NSAlert.run(message: "暂无报告", info: "请先执行一次扫描。")
            return
        }
        let json = report.prettyJSON
        NSAlert.run(message: "最近扫描报告", info: json.prefix(2000).description)
    }

    @objc private func openSettings() {
        NSAlert.run(message: "偏好设置", info: "配置文件: ~/Library/Application Support/AegisAgent/config.json\n\n扫描间隔: \(config.scanIntervalSeconds)s\nCollector: \(config.collectorURL)")
    }

    @objc private func showAbout() {
        NSAlert.run(message: "Aegis Agent for macOS", info: "版本 \(AgentConfig.version)\n企业 AI Coding 安全治理终端客户端\n\n发现 Cursor / Claude Code / Codex / Windsurf\n加载安全基线 · 扫描 Skill / MCP / 代码\n上报至 Collector · 联动厂商 EDR")
    }

    @objc private func quit() { NSApp.terminate(nil) }
}

extension NSAlert {
    static func run(message: String, info: String) {
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = info
        alert.alertStyle = .informational
        alert.runModal()
    }
}
