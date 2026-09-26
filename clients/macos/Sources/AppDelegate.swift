import AppKit
import Foundation
import AegisStatus

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let reader = StatusReader()
    private var timer: Timer?
    private var loading = false
    private var latest: Result<DesktopStatus, StatusReadError> = .failure(.missing)
    private let labels = [("installed", "客户端安装"), ("integrity", "程序与基线完整性"), ("service", "后台服务"),
                          ("configured", "上报配置"), ("reporting", "最近上报"), ("report_valid", "扫描报告"), ("scan_recent", "最近扫描")]

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        let menu = NSMenu()
        menu.delegate = self
        menu.addItem(withTitle: "Aegis · 系统保护状态", action: nil, keyEquivalent: "")
        menu.addItem(.separator())
        let status = NSMenuItem(title: "正在读取服务状态…", action: nil, keyEquivalent: "")
        status.tag = 100
        menu.addItem(status)
        menu.addItem(withTitle: "刷新状态", action: #selector(refreshStatus), keyEquivalent: "r")
        menu.addItem(withTitle: "查看服务状态", action: #selector(showStatus), keyEquivalent: "s")
        menu.addItem(.separator())
        menu.addItem(withTitle: "关于 Aegis", action: #selector(showAbout), keyEquivalent: "")
        menu.addItem(withTitle: "退出状态界面", action: #selector(quit), keyEquivalent: "q")
        for item in menu.items where item.action != nil { item.target = self }
        statusItem.menu = menu
        timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
        if let timer { RunLoop.main.add(timer, forMode: .common) }
        refreshStatus()
    }
    func applicationWillTerminate(_ notification: Notification) { timer?.invalidate() }
    func menuWillOpen(_ menu: NSMenu) { refreshStatus() }

    @objc private func refreshStatus() {
        render() // Expire cached green state even if the next filesystem read stalls.
        guard !loading else { return }
        loading = true
        let source = reader
        Task { [weak self] in
            let value = await Task.detached { source.load() }.value
            guard let self else { return }
            self.latest = value
            self.loading = false
            self.render()
        }
    }
    private var headline: String {
        switch latest {
        case .failure(.missing): return "尚未获取系统服务状态"
        case .failure: return "无法验证系统服务状态"
        case .success(let status):
            switch status.assessment() {
            case .healthy: return "最近检查正常"
            case .attention: return "需要管理员检查"
            case .stale: return "服务状态已过期"
            }
        }
    }
    private func render() {
        statusItem.menu?.item(withTag: 100)?.title = headline
        let healthy: Bool
        if case .success(let status) = latest, case .healthy = status.assessment() { healthy = true } else { healthy = false }
        statusItem.button?.image = NSImage(systemSymbolName: healthy ? "checkmark.shield" : "exclamationmark.shield", accessibilityDescription: headline)
        statusItem.button?.image?.isTemplate = true
        statusItem.button?.toolTip = "Aegis · " + headline
    }
    @objc private func showStatus() {
        refreshStatus()
        var lines = [headline]
        if case .success(let status) = latest {
            let formatter = DateFormatter()
            formatter.dateStyle = .short
            formatter.timeStyle = .medium
            lines += ["客户端版本：\(status.agentVersion)", "策略版本：\(status.policyVersion == "unknown" ? "待核验" : status.policyVersion)",
                      "最近检查：\(formatter.string(from: Date(timeIntervalSince1970: Double(status.observedAt))))", ""]
            let stale: Bool
            if case .stale = status.assessment() { stale = true } else { stale = false }
            lines += labels.map { key, label in "\(label)：\(stale ? "待核验" : (status.checks[key] == true ? "通过" : "待检查"))" }
        } else {
            lines += ["请联系安全管理员确认系统服务已部署并正在运行。"]
        }
        lines += ["", "界面展示后台服务最近的检查结果。退出界面不会停止后台保护。"]
        showAlert("Aegis 系统服务状态", lines.joined(separator: "\n"))
    }
    @objc private func showAbout() {
        showAlert("Aegis", "企业 AI Agent 安全系统\n\n治理和上报由受管系统服务执行。此界面仅展示状态，不保存凭据，也不执行另一套扫描。")
    }
    private func showAlert(_ title: String, _ text: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.addButton(withTitle: "知道了")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
    @objc private func quit() { NSApp.terminate(nil) }
}
