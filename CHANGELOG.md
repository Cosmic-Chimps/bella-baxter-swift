# Changelog

All notable changes to the Bella Baxter Swift SDK are documented here.

## 0.1.0

- Initial release: `BellaClient` with HMAC-SHA256 authentication
- `pullSecrets()`, `exportSecretsAsEnv()`, `injectIntoEnvironment()`
- `E2EEncryptionMiddleware` for end-to-end encrypted secrets
- `WebhookSignatureVerifier` for verifying webhook payloads
- `SecretCache` protocol for pluggable secret caching
- `KeychainSecretCache` — Apple Keychain backed cache (iOS, macOS, watchOS, tvOS)
- Swift Package Manager support (iOS 17+, macOS 14+, watchOS 10+, tvOS 17+)
