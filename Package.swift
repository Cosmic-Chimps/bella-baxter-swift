// swift-tools-version: 6.2
//
// Swift 6.2 (Xcode 26+) is the real floor, and this line states it (#993). A library's
// Package.resolved is never used by its consumers, so a consumer resolves the dependency graph
// fresh — and that pulls swift-collections 1.7.x (via swift-openapi-generator AND
// swift-openapi-urlsession, neither of which caps it), whose only manifest is tools 6.2. The old
// `5.10` here promised a floor the graph could not meet: on Swift 6.1 resolution failed inside
// swift-collections before any SDK code compiled. Declaring 6.2 turns that into SwiftPM's own
// clear "requires a minimum Swift tools version of 6.2" message.
//
// Capping swift-collections below 1.7 (so 6.0/6.1 could build) was rejected: no direct
// dependency's requirement can be edited, so it would need an otherwise unused direct dependency
// whose ceiling every consumer inherits and conflicts with, and it could not be proven here.
import PackageDescription

let package = Package(
    name: "bella-baxter-swift",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .watchOS(.v10),
        .tvOS(.v17),
    ],
    products: [
        .library(
            name: "BellaBaxterSwift",
            targets: ["BellaBaxterSwift"]
        ),
    ],
    dependencies: [
        // Apple's official OpenAPI Generator Swift plugin — generates Client at build time
        .package(
            url: "https://github.com/apple/swift-openapi-generator",
            from: "1.4.0"
        ),
        // OpenAPI runtime types (HTTPRequest, HTTPResponse, HTTPBody, ClientMiddleware, ...)
        .package(
            url: "https://github.com/apple/swift-openapi-runtime",
            from: "1.7.0"
        ),
        // URLSession transport — zero extra dependencies on Apple platforms
        .package(
            url: "https://github.com/apple/swift-openapi-urlsession",
            from: "1.0.0"
        ),
    ],
    targets: [
        .target(
            name: "BellaBaxterSwift",
            dependencies: [
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime"),
                .product(name: "OpenAPIURLSession", package: "swift-openapi-urlsession"),
            ],
            // The plugin reads openapi.json + openapi-generator-config.yaml from
            // Sources/BellaBaxterSwift/ at build time and generates a Swift Client.
            // Run `generate.sh` to keep openapi.json up to date.
            plugins: [
                .plugin(name: "OpenAPIGenerator", package: "swift-openapi-generator"),
            ]
        ),
        .testTarget(
            name: "BellaBaxterSwiftTests",
            dependencies: ["BellaBaxterSwift"]
        ),
    ],
    // Tools 6.x defaults to the Swift 6 language mode. Raising the tools version (above) is a
    // statement about the toolchain, not a request to change how this module compiles, so the
    // language mode stays what `5.10` gave it.
    swiftLanguageModes: [.v5]
)
