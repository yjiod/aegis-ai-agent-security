import Foundation
import CryptoKit

/// 报告上报器 — HTTPS + HMAC-SHA256 签名 + 离线队列
/// 移植自 public/downloads/aegis_agent.py 的上报逻辑
actor Reporter {
    enum SubmitResult { case success; case failure(Error) }

    private let session = URLSession(configuration: .ephemeral)
    private var queueDir: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AegisAgent/queue", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    private let maxQueueSize = 200

    /// 提交报告到 Collector
    func submit(_ report: Report, config: AgentConfig) async -> SubmitResult {
        guard let url = URL(string: "\(config.collectorURL)/v1/report") else {
            return .failure(ReportError.invalidURL)
        }
        do {
            let body = try JSONEncoder().encode(report)
            var request = URLRequest(url: url, timeoutInterval: 15)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue(report.device_id, forHTTPHeaderField: "X-Device-ID")
            request.setValue(report.agent_version, forHTTPHeaderField: "X-Agent-Version")

            // HMAC-SHA256 签名
            if let secret = config.hmacSecret, !secret.isEmpty {
                let key = SymmetricKey(data: Data(secret.utf8))
                let signature = HMAC<SHA256>.authenticationCode(for: body, using: key)
                request.setValue(Data(signature).map { String(format: "%02x", $0) }.joined(),
                                 forHTTPHeaderField: "X-Report-Signature")
            }
            request.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization")
            request.httpBody = body

            let (_, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw ReportError.invalidResponse }
            if (200...299).contains(http.statusCode) {
                drainQueue(config: config) // 成功后尝试排空离线队列
                return .success
            }
            if http.statusCode >= 500 { enqueue(body) } // 服务端错误→入队
            return .failure(ReportError.httpStatus(http.statusCode))
        } catch {
            if let body = try? JSONEncoder().encode(report) { enqueue(body) }
            return .failure(error)
        }
    }

    /// 离线队列：有界、原子写入
    private func enqueue(_ data: Data) {
        let fm = FileManager.default
        let existing = (try? fm.contentsOfDirectory(at: queueDir, includingPropertiesForKeys: nil)) ?? []
        if existing.count >= maxQueueSize {
            // 丢弃最旧的
            let sorted = existing.sorted { ($0.lastPathComponent) < ($1.lastPathComponent) }
            try? fm.removeItem(at: sorted[0])
        }
        let name = "\(Int(Date().timeIntervalSince1970 * 1000))-\(UUID().uuidString.prefix(8)).json"
        let tmp = queueDir.appendingPathComponent(name + ".tmp")
        let dest = queueDir.appendingPathComponent(name)
        try? data.write(to: tmp, options: .atomic)
        try? fm.moveItem(at: tmp, to: dest)
    }

    /// 排空离线队列
    private func drainQueue(config: AgentConfig) {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: queueDir, includingPropertiesForKeys: nil) else { return }
        for file in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }).prefix(10) {
            guard let data = try? Data(contentsOf: file),
                  let report = try? JSONDecoder().decode(Report.self, from: data) else {
                try? fm.removeItem(at: file); continue
            }
            Task {
                let result = await submit(report, config: config)
                if case .success = result { try? fm.removeItem(at: file) }
            }
        }
    }
}

enum ReportError: LocalizedError {
    case invalidURL, invalidResponse, httpStatus(Int)
    var errorDescription: String? {
        switch self {
        case .invalidURL: return "Collector URL 无效"
        case .invalidResponse: return "响应格式异常"
        case .httpStatus(let code): return "HTTP \(code)"
        }
    }
}
