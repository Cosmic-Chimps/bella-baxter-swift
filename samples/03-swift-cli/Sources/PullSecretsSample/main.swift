import Foundation
import BellaBaxterSwift

let apiURL   = ProcessInfo.processInfo.environment["BELLA_BAXTER_URL"] ?? "http://localhost:5522"
let apiKey   = ProcessInfo.processInfo.environment["BELLA_API_KEY"] ?? ""
let outputPath = ProcessInfo.processInfo.environment["DOTENV_OUTPUT"]

guard !apiKey.isEmpty, let url = URL(string: apiURL) else {
    fputs("""
    Usage:
      BELLA_URL=https://api.example.com \\
      BELLA_API_KEY=bax-... \\
      [DOTENV_OUTPUT=.env] \\
      swift run
    """, stderr)
    exit(1)
}

let client = try BellaClient(
    BellaClientOptions(baseURL: url, apiKey: apiKey)
)

// Discover project + environment from the API key
let ctx = try await client.getKeyContext()
print("Pulling secrets: \(ctx.projectSlug) / \(ctx.environmentSlug) ...")

let secrets = try await client.pullSecrets()

if secrets.isEmpty {
    print("No secrets found.")
    exit(0)
}

let envLines = secrets.sorted(by: { $0.key < $1.key }).map { "\($0.key)=\($0.value)" }
let envContent = envLines.joined(separator: "\n") + "\n"

if let outputPath {
    try envContent.write(toFile: outputPath, atomically: true, encoding: .utf8)
    print("✓ Written \(secrets.count) secrets to \(outputPath)")
} else {
    print(envContent, terminator: "")
}
