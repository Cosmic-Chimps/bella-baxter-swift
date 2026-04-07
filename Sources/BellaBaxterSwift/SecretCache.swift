/// A type that can cache secrets fetched from Bella Baxter.
///
/// Implement this protocol to persist secrets across app launches.
/// The built-in ``KeychainSecretCache`` stores secrets in the Apple Keychain
/// and is available on iOS, macOS, watchOS, and tvOS.
///
/// Example — using the Keychain cache:
/// ```swift
/// let client = BellaClient(
///     options: BellaClientOptions(
///         apiKey: "bax-...",
///         cache: KeychainSecretCache()
///     )
/// )
/// ```
public protocol SecretCache: Sendable {
    /// Read cached secrets. Returns `nil` if no cache entry exists.
    func read() async throws -> [String: String]?

    /// Persist a complete set of secrets.
    func write(_ secrets: [String: String]) async throws

    /// Remove all cached secrets.
    func clear() async throws
}
