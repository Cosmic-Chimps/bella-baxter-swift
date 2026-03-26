// swift-tools-version: 5.10
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
    ]
)
