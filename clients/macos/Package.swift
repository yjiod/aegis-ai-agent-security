// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisAgent",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "AegisAgent",
            path: "Sources",
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")]
        ),
    ]
)
