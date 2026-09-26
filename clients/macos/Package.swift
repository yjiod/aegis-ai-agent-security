// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisAgent",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "AegisStatus", path: "Status"),
        .executableTarget(name: "AegisAgent", dependencies: ["AegisStatus"], path: "Sources",
                          swiftSettings: [.enableExperimentalFeature("StrictConcurrency")]),
        .testTarget(name: "AegisStatusTests", dependencies: ["AegisStatus"], path: "Tests"),
    ]
)
