import Foundation

/// 终端扫描器 — 发现 AI Coding 工具并执行安全扫描
/// 移植自 public/downloads/aegis_agent.py 的核心逻辑
struct Scanner {

    /// 发现已安装的 AI Coding Agent
    func discoverAgents() -> [DiscoveredAgent] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var found: [DiscoveredAgent] = []

        let targets: [(name: String, paths: [String])] = [
            ("cursor", ["\(home)/Library/Application Support/Cursor", "\(home)/.cursor"]),
            ("claude_code", ["\(home)/.claude", "\(home)/Library/Application Support/Claude"]),
            ("codex_cli", ["\(home)/.codex", "\(home)/Library/Application Support/codex"]),
            ("windsurf", ["\(home)/Library/Application Support/Windsurf", "\(home)/.windsurf"]),
        ]

        for target in targets {
            for path in target.paths {
                if FileManager.default.fileExists(atPath: path) {
                    found.append(DiscoveredAgent(name: target.name, configPath: path))
                    break
                }
            }
        }
        return found
    }

    /// 扫描 Skill 文件：检查权限声明、隐藏指令、可疑依赖
    func scanSkills(at path: String) -> [Finding] {
        // TODO: 遍历 .skill / .md 文件，检查:
        // - 隐藏指令覆盖 (base64 编码的 system prompt)
        // - 未声明的文件系统/网络权限
        // - 可疑的外部依赖引用
        var findings: [Finding] = []
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: path) else { return findings }
        var count = 0
        while let file = enumerator.nextObject() as? String, count < 500 {
            count += 1
            guard file.hasSuffix(".skill") || file.hasSuffix(".md") else { continue }
            let fullPath = (path as NSString).appendingPathComponent(file)
            guard let content = try? String(contentsOfFile: fullPath, encoding: .utf8),
                  content.count <= 1_000_000 else { continue }
            // 检查隐藏指令模式
            if content.contains("ignore previous instructions") || content.contains("system prompt override") {
                findings.append(Finding(kind: "skill_hidden_instruction", severity: "high", path: file, message: "Skill 包含可疑的隐藏指令覆盖"))
            }
            // 检查 base64 编码块
            if content.range(of: "[A-Za-z0-9+/]{100,}={0,2}", options: .regularExpression) != nil {
                findings.append(Finding(kind: "skill_encoded_payload", severity: "medium", path: file, message: "Skill 包含大段 base64 编码内容"))
            }
        }
        return findings
    }

    /// 扫描 MCP 配置：检查越权目录访问、未声明外联、密钥暴露
    func scanMCP(at path: String) -> [Finding] {
        // TODO: 解析 mcp.json / mcp_servers.json，检查:
        // - allowed_directories 是否超出 workspace
        // - 未声明的外部 URL 连接
        // - 硬编码的 API key / token
        var findings: [Finding] = []
        let mcpFiles = ["mcp.json", "mcp_servers.json", ".mcp/config.json"]
        for name in mcpFiles {
            let fullPath = (path as NSString).appendingPathComponent(name)
            guard let data = FileManager.default.contents(atPath: fullPath),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            if let servers = json["mcpServers"] as? [String: Any] {
                for (serverName, serverConfig) in servers {
                    guard let cfg = serverConfig as? [String: Any] else { continue }
                    if let args = cfg["args"] as? [String] {
                        for arg in args where arg.hasPrefix("/") && !arg.hasPrefix("/tmp") {
                            if arg.contains("/etc") || arg.contains(".ssh") || arg.contains(".env") {
                                findings.append(Finding(kind: "mcp_unauthorized_path", severity: "critical", path: "\(name)/\(serverName)", message: "MCP Server 请求了未授权文件目录: \(arg)"))
                            }
                        }
                    }
                }
            }
        }
        return findings
    }

    /// 扫描代码质量：硬编码密钥、弱加密、SQL 注入模式
    func scanCodeQuality(at path: String) -> [Finding] {
        // TODO: 遍历源代码文件，检查:
        // - 硬编码 API key / password / token
        // - Math.random() 用于安全场景
        // - 字符串拼接 SQL
        var findings: [Finding] = []
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: path) else { return findings }
        let sourceExts: Set<String> = ["swift", "py", "js", "ts", "tsx", "java", "go", "rs"]
        var count = 0
        while let file = enumerator.nextObject() as? String, count < 2000 {
            let ext = (file as NSString).pathExtension.lowercased()
            guard sourceExts.contains(ext) else { continue }
            count += 1
            let fullPath = (path as NSString).appendingPathComponent(file)
            guard let content = try? String(contentsOfFile: fullPath, encoding: .utf8),
                  content.count <= 500_000 else { continue }
            // 硬编码密钥检测
            let secretPatterns = ["api_key\\s*=\\s*[\"'][^\"']{8,}", "password\\s*=\\s*[\"'][^\"']{4,}", "secret\\s*=\\s*[\"'][^\"']{8,}", "AKIA[0-9A-Z]{16}"]
            for pattern in secretPatterns {
                if content.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil {
                    findings.append(Finding(kind: "code_hardcoded_secret", severity: "critical", path: file, message: "检测到硬编码密钥或凭据"))
                    break
                }
            }
            // 弱随机数检测
            if content.contains("Math.random()") && (content.contains("token") || content.contains("session")) {
                findings.append(Finding(kind: "code_weak_random", severity: "high", path: file, message: "使用弱随机数生成安全令牌"))
            }
        }
        return findings
    }

    /// 组装完整报告 (aegis.report/v1)
    func buildReport(config: AgentConfig, policy: Policy?) -> Report {
        let agents = discoverAgents()
        var allFindings: [Finding] = []

        for agent in agents {
            allFindings.append(contentsOf: scanSkills(at: agent.configPath))
            allFindings.append(contentsOf: scanMCP(at: agent.configPath))
        }

        // 扫描用户项目目录（如果配置了）
        if let projectRoot = config.scanRoot {
            allFindings.append(contentsOf: scanCodeQuality(at: projectRoot))
        }

        let summary = Summary(
            critical: allFindings.filter { $0.severity == "critical" }.count,
            high: allFindings.filter { $0.severity == "high" }.count,
            medium: allFindings.filter { $0.severity == "medium" }.count,
            low: allFindings.filter { $0.severity == "low" }.count
        )

        return Report(
            schema: "aegis.report/v1",
            agent_version: AgentConfig.version,
            policy_version: policy?.version ?? "0.0.0",
            device_id: config.deviceId,
            scanned_at: Int(Date().timeIntervalSince1970),
            summary: summary,
            findings: allFindings,
            inventory: agents.map { ["tool": $0.name, "path": $0.configPath] }
        )
    }
}

/* ─── Models ────────────────────────────────────────────── */

struct DiscoveredAgent { let name: String; let configPath: String }

struct Finding: Codable {
    let kind: String; let severity: String; let path: String; let message: String
    var evidence: String?
}

struct Summary: Codable { let critical: Int; let high: Int; let medium: Int; let low: Int }

struct Report: Codable {
    let schema: String; let agent_version: String; let policy_version: String
    let device_id: String; let scanned_at: Int
    let summary: Summary; let findings: [Finding]
    var inventory: [[String: String]]?
    var prettyJSON: String {
        guard let data = try? JSONEncoder().encode(self),
              let str = String(data: data, encoding: .utf8) else { return "{}" }
        return str
    }
}
