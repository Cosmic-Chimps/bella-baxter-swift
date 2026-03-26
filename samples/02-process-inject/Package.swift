// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "02-process-inject",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "ProcessInjectSample",
            path: "Sources/ProcessInjectSample"
        ),
    ]
)
