import XCTest
import Foundation
import Darwin
@testable import AegisStatus

final class DesktopStatusTests: XCTestCase {
    private var directory: URL!
    private var file: URL { directory.appendingPathComponent("desktop-status.json") }
    private var value: [String: Any] {
        ["schema": DesktopStatus.schemaName, "agent_version": "0.37.3", "policy_version": "1.2.3",
         "observed_at": 1800000000, "checks": Dictionary(uniqueKeysWithValues: DesktopStatus.checkNames.map { ($0, true) })]
    }
    override func setUpWithError() throws {
        let canonical = try XCTUnwrap(realpath(FileManager.default.temporaryDirectory.path, nil))
        defer { free(canonical) }
        directory = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    private func write(_ object: [String: Any]? = nil) throws {
        try JSONSerialization.data(withJSONObject: object ?? value).write(to: file)
        XCTAssertEqual(chmod(file.path, 0o644), 0)
    }
    private func load() -> Result<DesktopStatus, StatusReadError> { StatusReader(path: file.path, owner: getuid()).load() }
    private func assertRejected(_ result: Result<DesktopStatus, StatusReadError>, _ reason: StatusReadError? = nil, line: UInt = #line) {
        switch result {
        case .success: XCTFail("Untrusted state accepted", line: line)
        case .failure(let error): if let reason { XCTAssertEqual(error, reason, line: line) }
        }
    }
    func testHealthyAttentionAndStaleBoundaries() throws {
        try write()
        var state = try load().get()
        XCTAssertEqual(state.assessment(now: 1800000150), .healthy)
        XCTAssertEqual(state.assessment(now: 1800000151), .stale)
        XCTAssertEqual(state.assessment(now: 1799999969), .stale)
        XCTAssertEqual(state.assessment(now: .nan), .stale)
        var changed = value
        var checks = changed["checks"] as! [String: Bool]
        checks["reporting"] = false
        changed["checks"] = checks
        try write(changed)
        state = try load().get()
        XCTAssertEqual(state.assessment(now: 1800000001), .attention)
    }
    func testMalformedAndAdditionalFieldsNeverDisplayHealthy() throws {
        for delta: [String: Any] in [["schema": "unknown"], ["agent_version": "1.2.3\n"], ["observed_at": true],
                                    ["observed_at": -1], ["observed_at": 253402300800], ["checks": ["service": true]],
                                    ["private_report": "synthetic"], ["policy_version": "<script>"]] {
            try write(value.merging(delta) { _, new in new })
            assertRejected(load(), .invalid)
        }
        try Data("{invalid".utf8).write(to: file)
        assertRejected(load(), .invalid)
    }
    func testMissingAndUnsafePermissionsOrOwner() throws {
        assertRejected(load(), .missing)
        try write()
        assertRejected(StatusReader(path: file.path, owner: getuid()+1).load(), .untrusted)
        XCTAssertEqual(chmod(file.path, 0o666), 0)
        assertRejected(load(), .untrusted)
        XCTAssertEqual(chmod(file.path, 0o644), 0)
        XCTAssertEqual(chmod(directory.path, 0o777), 0)
        assertRejected(load(), .untrusted)
    }
    func testRejectsSymlinkHardlinkAndFifoWithoutBlocking() throws {
        let other = directory.appendingPathComponent("other")
        try JSONSerialization.data(withJSONObject: value).write(to: other)
        XCTAssertEqual(symlink(other.path, file.path), 0)
        assertRejected(load(), .untrusted)
        XCTAssertEqual(unlink(file.path), 0)
        XCTAssertEqual(link(other.path, file.path), 0)
        assertRejected(load(), .untrusted)
        XCTAssertEqual(unlink(file.path), 0)
        XCTAssertEqual(mkfifo(file.path, 0o600), 0)
        assertRejected(load(), .untrusted)
    }
    func testRejectsSymlinkAncestorAndOversize() throws {
        let alias = directory.appendingPathComponent("alias")
        XCTAssertEqual(symlink(directory.path, alias.path), 0)
        try write()
        assertRejected(StatusReader(path: alias.appendingPathComponent(file.lastPathComponent).path, owner: getuid()).load(), .untrusted)
        try Data(repeating: 32, count: 4097).write(to: file)
        assertRejected(load(), .untrusted)
    }
    func testExtendedACLIsRejected() throws {
        try write()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone allow read", file.path]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        assertRejected(load(), .untrusted)
    }
    func testProducerInteroperability() throws {
        guard let path = ProcessInfo.processInfo.environment["AEGIS_TEST_DESKTOP_SNAPSHOT"] else {
            throw XCTSkip("CI passes a snapshot produced by the Python publisher in an isolated fixture")
        }
        let status = try StatusReader(path: path, owner: getuid()).load().get()
        XCTAssertEqual(status.agentVersion, "0.37.3")
        XCTAssertEqual(status.policyVersion, "1.2.3")
        XCTAssertEqual(status.assessment(now: 1800000001), .healthy)
    }
}
