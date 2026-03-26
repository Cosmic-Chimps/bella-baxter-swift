// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "03-ios-app",
    platforms: [.macOS(.v14), .iOS(.v17)],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "iOSAppSample",
            dependencies: [
                .product(name: "BellaBaxterSwift", package: "swift"),
            ],
            path: "Sources/iOSAppSample"
        ),
    ]
)
