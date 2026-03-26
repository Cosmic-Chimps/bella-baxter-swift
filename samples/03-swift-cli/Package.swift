// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "03-swift-cli",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "PullSecretsSample",
            dependencies: [
                .product(name: "BellaBaxterSwift", package: "swift"),
            ],
            path: "Sources/PullSecretsSample"
        ),
    ]
)
