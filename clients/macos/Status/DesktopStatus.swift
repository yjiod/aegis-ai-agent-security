import Foundation
import Darwin

public enum StatusReadError: Error, Sendable { case missing, untrusted, invalid, unavailable }
public enum StatusAssessment: Sendable { case healthy, attention, stale }

public struct DesktopStatus: Decodable, Sendable {
    public static let schemaName = "aegis.desktop-status/v1"
    public static let maximumAge: TimeInterval = 150
    public static let checkNames: Set<String> = ["installed", "integrity", "service", "configured", "reporting", "report_valid", "scan_recent"]
    public let schema: String
    public let agentVersion: String
    public let policyVersion: String
    public let observedAt: Int64
    public let checks: [String: Bool]

    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    private enum CodingKeys: String, CodingKey {
        case schema, checks
        case agentVersion = "agent_version", policyVersion = "policy_version", observedAt = "observed_at"
    }
    public init(from decoder: Decoder) throws {
        let all = try decoder.container(keyedBy: Key.self)
        guard Set(all.allKeys.map(\.stringValue)) == Set(["schema", "agent_version", "policy_version", "observed_at", "checks"]) else { throw StatusReadError.invalid }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        agentVersion = try values.decode(String.self, forKey: .agentVersion)
        policyVersion = try values.decode(String.self, forKey: .policyVersion)
        observedAt = try values.decode(Int64.self, forKey: .observedAt)
        checks = try values.decode([String: Bool].self, forKey: .checks)
        guard schema == Self.schemaName, Self.versionValid(agentVersion),
              policyVersion == "unknown" || Self.versionValid(policyVersion),
              observedAt >= 0, observedAt <= 253402300799, Set(checks.keys) == Self.checkNames else { throw StatusReadError.invalid }
    }
    private static func versionValid(_ value: String) -> Bool {
        value.utf8.count <= 64 && value.range(of: #"\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,32})?\z"#, options: .regularExpression) != nil
    }
    public func assessment(now: TimeInterval = Date().timeIntervalSince1970) -> StatusAssessment {
        let age = now - Double(observedAt)
        guard now.isFinite, age >= -30, age <= Self.maximumAge else { return .stale }
        return checks.values.allSatisfy { $0 } ? .healthy : .attention
    }
}

public struct StatusReader: Sendable {
    public static let systemPath = "/Library/Application Support/AegisAgent/desktop-status.json"
    let path: String
    let owner: uid_t
    // The shipped UI always uses defaults. Parameters exist for isolated tests;
    // there is no CLI/environment/config override for the production reader.
    public init(path: String = Self.systemPath, owner: uid_t = 0) { self.path = path; self.owner = owner }

    public func load() -> Result<DesktopStatus, StatusReadError> {
        do { return .success(try read()) }
        catch let error as StatusReadError { return .failure(error) }
        catch { return .failure(.invalid) }
    }

    private func noACL(_ fd: Int32) throws {
        errno = 0
        if let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) {
            acl_free(UnsafeMutableRawPointer(acl))
            throw StatusReadError.untrusted
        }
        guard errno == ENOENT else { throw StatusReadError.untrusted }
    }
    private func metadata(_ fd: Int32, directory: Bool = false) throws -> stat {
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw StatusReadError.unavailable }
        guard value.st_uid == owner, value.st_mode & 0o022 == 0,
              value.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              directory || (value.st_nlink == 1 && value.st_size > 0 && value.st_size <= 4096) else { throw StatusReadError.untrusted }
        try noACL(fd)
        return value
    }
    private func same(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev && first.st_ino == second.st_ino && first.st_size == second.st_size &&
        first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec &&
        first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec && first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec
    }
    private func read() throws -> DesktopStatus {
        let parts = (path as NSString).pathComponents
        guard parts.first == "/", parts.count > 2, !parts.contains(".."), !parts.contains(".") else { throw StatusReadError.untrusted }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw StatusReadError.unavailable }
        defer { close(parent) }
        for part in parts.dropFirst().dropLast() {
            let next = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw errno == ENOENT ? StatusReadError.missing : StatusReadError.untrusted }
            close(parent)
            parent = next
        }
        _ = try metadata(parent, directory: true)
        guard let name = parts.last else { throw StatusReadError.invalid }
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw errno == ENOENT ? StatusReadError.missing : StatusReadError.untrusted }
        defer { close(fd) }
        let before = try metadata(fd)
        var bytes = [UInt8](repeating: 0, count: 4097)
        var count = 0
        while count < bytes.count {
            let received = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(fd, buffer.baseAddress!.advanced(by: count), buffer.count - count)
            }
            if received == 0 { break }
            if received < 0 {
                if errno == EINTR { continue }
                throw StatusReadError.unavailable
            }
            count += received
        }
        let after = try metadata(fd)
        var current = stat()
        guard count == before.st_size, count <= 4096, same(before, after),
              fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0, same(before, current) else { throw StatusReadError.untrusted }
        return try JSONDecoder().decode(DesktopStatus.self, from: Data(bytes.prefix(count)))
    }
}
