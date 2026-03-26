// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "01-dotenv-file",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "DotenvFileSample",
            path: "Sources/DotenvFileSample"
        ),
    ]
)
