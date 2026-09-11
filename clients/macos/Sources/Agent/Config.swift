import Foundation

/// Agent 配置 — 从 ~/Library/Application Support/AegisAgent/config.json 加载
struct AgentConfig: Codable {
    static let version = "0.30.0"

    var collectorURL: String
    var deviceId: String
    var token: String
    var hmacSecret: String?
    var scanIntervalSeconds: Int
    var scanRoot: String?

    static var defaultConfigDir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AegisAgent", isDirectory: true)
    }

    static func load() -> AgentConfig {
        let path = defaultConfigDir.appendingPathComponent("config.json")
        if let data = try? Data(contentsOf: path),
           let config = try? JSONDecoder().decode(AgentConfig.self, from: data) {
            return config
        }
        // 首次运行：生成默认配置
        let hostname = Host.current().localizedName ?? "unknown-mac"
        let defaultConfig = AgentConfig(
            collectorURL: "http://127.0.0.1:8931",
            deviceId: "MAC-\(hostname.prefix(12).uppercased().replacingOccurrences(of: " ", with: "-"))",
            token: "",
            hmacSecret: nil,
            scanIntervalSeconds: 3600,
            scanRoot: nil
        )
        try? FileManager.default.createDirectory(at: defaultConfigDir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(defaultConfig) {
            try? data.write(to: path, options: .atomic)
        }
        return defaultConfig
    }
}
