import Foundation

/// 策略加载器 — 热重载 + last-known-good 回退
final class PolicyLoader: @unchecked Sendable {
    private(set) var current: Policy?
    private var source: DispatchSourceFileSystemObject?
    private var fd: CInt = -1

    private var policyPath: String {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AegisAgent").path
        return "\(dir)/policy.json"
    }

    func load() {
        guard let data = FileManager.default.contents(atPath: policyPath),
              let policy = try? JSONDecoder().decode(Policy.self, from: data) else { return }
        current = policy // 仅在解析成功时更新（last-known-good）
    }

    func startWatching() {
        load()
        fd = open(policyPath, O_EVTONLY)
        guard fd >= 0 else { return }
        source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .delete], queue: .global())
        source?.setEventHandler { [weak self] in self?.load() }
        source?.setCancelHandler { [weak self] in if let fd = self?.fd, fd >= 0 { close(fd) } }
        source?.resume()
    }

    deinit { source?.cancel() }
}

struct Policy: Codable {
    let version: String
    var rules: [PolicyRule]?
    var scan_interval_seconds: Int?
    var exclusions: [String]?
}

struct PolicyRule: Codable {
    let id: String
    let description: String?
    let severity: String?
    let action: String? // "block" | "alert" | "observe"
}
