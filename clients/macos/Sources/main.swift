import AppKit

// Aegis Agent — macOS 菜单栏安全客户端
// 构建: swift build --disable-sandbox && swift run --disable-sandbox

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory) // 无 Dock 图标，仅菜单栏
app.run()
