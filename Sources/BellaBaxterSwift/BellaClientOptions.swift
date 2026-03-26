import Foundation

/// Configuration for ``BellaClient``.
public struct BellaClientOptions: Sendable {
    /// Default base URL for the hosted Bella Baxter service.
    public static let defaultBaseURL = URL(string: "https://api.bella-baxter.io")!

    /// The base URL of the Bella Baxter API.
    /// Example: `URL(string: "https://api.bella-baxter.io")!`
    public let baseURL: URL

    /// Bearer API key (starts with `bax-...`).
    public let apiKey: String

    /// Request timeout in seconds (default: 30).
    public let timeoutSeconds: TimeInterval

    public init(
        baseURL: URL = BellaClientOptions.defaultBaseURL,
        apiKey: String,
        timeoutSeconds: TimeInterval = 30
    ) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.timeoutSeconds = timeoutSeconds
    }
}
