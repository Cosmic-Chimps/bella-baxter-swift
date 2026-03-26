import Foundation

/// Sample 02: Swift app — reads secrets injected into the environment by bella run.
///
/// Bella runs your app as a subprocess and injects secrets as env vars.
/// Your code reads them via ProcessInfo — no SDK, no file, no network calls.
///
/// Workflow:
///   bella run -- swift run
@main
struct ProcessInjectSample {
    static func main() {
        let env = ProcessInfo.processInfo.environment

        let port       = env["PORT"] ?? "(not set)"
        let dbUrl      = env["DATABASE_URL"] ?? "(not set)"
        let apiKey     = env["EXTERNAL_API_KEY"] ?? "(not set)"
        let gleapKey   = env["GLEAP_API_KEY"] ?? "(not set)"
        let features   = env["ENABLE_FEATURES"] ?? "(not set)"
        let appId      = env["APP_ID"] ?? "(not set)"
        let connStr    = env["ConnectionStrings__Postgres"] ?? "(not set)"
        let appConfig  = env["APP_CONFIG"] ?? "(not set)"

        print("=== Bella Baxter: process-inject sample (Swift) ===")
        print("")
        print("PORT                      : \(port)")
        print("DATABASE_URL              : \(mask(dbUrl))")
        print("EXTERNAL_API_KEY          : \(maskKey(apiKey))")
        print("GLEAP_API_KEY             : \(maskKey(gleapKey))")
        print("ENABLE_FEATURES           : \(features)")
        print("APP_ID                    : \(appId)")
        print("ConnectionStrings__Postgres: \(mask(connStr))")
        print("APP_CONFIG                : \(appConfig)")
        print("")
        print("Secrets were injected by:")
        print("  bella run -- swift run")
    }

    static func mask(_ value: String) -> String {
        guard value.count > 8, value != "(not set)" else { return value }
        return String(value.prefix(8)) + "***"
    }

    static func maskKey(_ value: String) -> String {
        guard value.count > 4, value != "(not set)" else { return value }
        return String(value.prefix(4)) + "***"
    }
}
