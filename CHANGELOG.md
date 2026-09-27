# Changelog

All notable changes to the Bella Baxter Swift SDK are documented here.

## Unreleased

- **Fixed:** responses carrying dates with fractional seconds — which the API always sends, e.g.
  `lastModified` on `pullSecrets()` — failed to decode (`Expected date string to be
  ISO8601-formatted`). Dates now decode with and without fractional seconds (#993).
- **Fixed:** the `onWrappedDekReceived` callback always received a `nil` lease expiry, because
  `X-Bella-Lease-Expires` carries seven fractional digits (#993).
- **Changed:** the minimum toolchain is now Swift 6.2 (Xcode 26). It already was in practice: a
  fresh resolve pulls `swift-collections` 1.7.x, which requires tools 6.2 (#993).

## 0.1.0

- Initial release: `BellaClient` with HMAC-SHA256 authentication
- `pullSecrets()`, `exportSecretsAsEnv()`, `injectIntoEnvironment()`
- `E2EEncryptionMiddleware` for end-to-end encrypted secrets
- `WebhookSignatureVerifier` for verifying webhook payloads
- `SecretCache` protocol for pluggable secret caching
- `KeychainSecretCache` — Apple Keychain backed cache (iOS, macOS, watchOS, tvOS)
- Swift Package Manager support (iOS 17+, macOS 14+, watchOS 10+, tvOS 17+)
