import Foundation

/// Sample 01: Swift app — reads secrets from a .env file written by bella.
///
/// Pattern: bella writes the .env file once; your app loads it on startup.
/// No network calls at runtime — the secrets are already on disk.
///
/// Workflow:
///   bella secrets get -o .env
///   swift run
@main
struct DotenvFileSample {
    static func main() throws {
        let env = try loadDotenv()

        let port       = env["PORT"] ?? "(not set)"
        let dbUrl      = env["DATABASE_URL"] ?? "(not set)"
        let apiKey     = env["EXTERNAL_API_KEY"] ?? "(not set)"
        let gleapKey   = env["GLEAP_API_KEY"] ?? "(not set)"
        let features   = env["ENABLE_FEATURES"] ?? "(not set)"
        let appId      = env["APP_ID"] ?? "(not set)"
        let connStr    = env["ConnectionStrings__Postgres"] ?? "(not set)"
        let appConfig  = env["APP_CONFIG"] ?? "(not set)"

        print("=== Bella Baxter: .env file sample (Swift) ===")
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
        print("All env vars loaded from .env file written by:")
        print("  bella secrets get -o .env")
    }

    /// Minimal .env parser — handles KEY=VALUE lines, ignores comments and blanks.
    static func loadDotenv(path: String = ".env") throws -> [String: String] {
        let url = URL(fileURLWithPath: path)
        guard let content = try? String(contentsOf: url, encoding: .utf8) else {
            fputs("Warning: .env file not found at \(path)\n", stderr)
            return [:]
        }
        var result: [String: String] = [:]
        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#"),
                  let eq = trimmed.firstIndex(of: "=") else { continue }
            let key   = String(trimmed[..<eq])
            var value = String(trimmed[trimmed.index(after: eq)...])
            // Strip optional surrounding quotes
            if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
               (value.hasPrefix("'")  && value.hasSuffix("'")) {
                value = String(value.dropFirst().dropLast())
            }
            result[key] = value
        }
        return result
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
