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

    /// Set when `BELLA_BAXTER_PRIVATE_KEY` is present but unreadable. ``BellaClient/init(_:)``
    /// throws it: the options initializer cannot throw without breaking every caller, and
    /// continuing with an ephemeral key is exactly the silent failure #989 removed.
    let privateKeyError: BellaError?

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
        // On macOS / Linux CLI tools this var is injected by `bella sdk run`, as PKCS#8 PEM.
        // On iOS / tvOS ProcessInfo.processInfo.environment is always empty — safe to check.
        //
        // #989 — this used to accept ONLY bare base64 DER and `try?` everything else away, so the
        // PEM `bella sdk run` injects was silently dropped and the client presented an ephemeral key
        // nobody had registered. Now PEM and base64 both load (one parser:
        // `BellaClient.loadPrivateKey(pkcs8Pem:)`), and a key that is present but unreadable is
        // recorded and thrown by `BellaClient.init` — never replaced by an ephemeral key.
        if let key = privateKey {
            self.privateKey = key
            self.privateKeyError = nil
        } else {
            let resolved = Self.privateKeyFromEnvironment(
                ProcessInfo.processInfo.environment["BELLA_BAXTER_PRIVATE_KEY"]
            )
            self.privateKey = resolved.key
            self.privateKeyError = resolved.error
        }
        self.onWrappedDekReceived = onWrappedDekReceived
    }

    /// Resolves the value of `BELLA_BAXTER_PRIVATE_KEY`: absent or blank means no device key
    /// (ephemeral, as before); anything else must load, or it is an error naming the variable.
    static func privateKeyFromEnvironment(
        _ value: String?
    ) -> (key: P256.KeyAgreement.PrivateKey?, error: BellaError?) {
        guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return (nil, nil)
        }
        do {
            return (try BellaClient.loadPrivateKey(pkcs8Pem: value), nil)
        } catch {
            return (nil, .invalidKey(
                "BELLA_BAXTER_PRIVATE_KEY is set but is not a readable PKCS#8 P-256 private key "
                    + "(PEM or base64 DER expected). Refusing to continue with a throwaway key instead "
                    + "of your device key. Unset it, or re-run: bella auth setup"
            ))
        }
    }
}
