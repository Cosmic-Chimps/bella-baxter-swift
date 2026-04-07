import CryptoKit
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

    /// Optional cache for persisting fetched secrets across app launches.
    ///
    /// On Apple platforms use ``KeychainSecretCache`` for encrypted,
    /// OS-managed storage:
    /// ```swift
    /// BellaClientOptions(apiKey: "bax-...", cache: KeychainSecretCache())
    /// ```
    public let cache: (any SecretCache)?

    // MARK: ZKE options

    /// Optional persistent P-256 private key for Zero-Knowledge Encryption.
    ///
    /// When set, the client sends the corresponding **SPKI DER** public key with every
    /// secrets request so the server can wrap the Data-Encryption Key (DEK) for it and
    /// return it in the `X-Bella-Wrapped-Dek` response header.
    ///
    /// Load with ``BellaClient/loadPrivateKey(pkcs8Der:)`` or
    /// ``BellaClient/loadPrivateKey(pkcs8Pem:)``.
    ///
    /// Defaults to `nil` (ephemeral key per request — existing behaviour).
    public let privateKey: P256.KeyAgreement.PrivateKey?

    /// Called whenever the server returns a `X-Bella-Wrapped-Dek` header on a secrets
    /// response (ZKE mode only).
    ///
    /// Arguments: `projectSlug`, `environmentSlug`, `wrappedDek` (base64), `leaseExpires`.
    ///
    /// Use this to persist the wrapped DEK for offline / cold-start secret retrieval.
    public let onWrappedDekReceived: (@Sendable (String, String, String, Date?) -> Void)?

    public init(
        baseURL: URL = BellaClientOptions.defaultBaseURL,
        apiKey: String,
        timeoutSeconds: TimeInterval = 30,
        cache: (any SecretCache)? = nil,
        privateKey: P256.KeyAgreement.PrivateKey? = nil,
        onWrappedDekReceived: (@Sendable (String, String, String, Date?) -> Void)? = nil
    ) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.timeoutSeconds = timeoutSeconds
        self.cache = cache
        // Auto-read BELLA_BAXTER_PRIVATE_KEY env var if no key was passed explicitly.
        // On macOS / Linux CLI tools this var is injected by `bella sdk run`.
        // On iOS / tvOS ProcessInfo.processInfo.environment is always empty — safe to check.
        if let key = privateKey {
            self.privateKey = key
        } else if let b64 = ProcessInfo.processInfo.environment["BELLA_BAXTER_PRIVATE_KEY"],
                  let der = Data(base64Encoded: b64),
                  let loaded = try? P256.KeyAgreement.PrivateKey(derRepresentation: der) {
            self.privateKey = loaded
        } else {
            self.privateKey = nil
        }
        self.onWrappedDekReceived = onWrappedDekReceived
    }
}
