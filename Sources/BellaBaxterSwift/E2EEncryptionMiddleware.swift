import CryptoKit
import Foundation
import HTTPTypes
import OpenAPIRuntime

/// `ClientMiddleware` that transparently adds end-to-end encryption to secrets requests.
///
/// **On outbound:** adds `X-E2E-Public-Key` to `getAllEnvironmentSecrets` requests so the server
/// encrypts the response payload.
///
/// **On inbound:** decrypts the `E2EEncryptedPayload` and passes the full plaintext JSON through
/// so the generated Swift client can deserialize it normally (preserving `version`,
/// `environmentSlug`, `lastModified`, etc.).
///
/// **Fail closed (#1050):** once the key is presented, a `2xx` answer to a value-carrying read
/// (``requiresEnvelope(method:path:)``) that is not an envelope throws ``E2EEResponseError`` with
/// `e2ee-plaintext-response`, and an envelope that does not decrypt — malformed, tampered, or
/// encrypted to another key — throws it with `e2ee-decryption-failed`. Neither is ever passed on.
///
/// **ZKE mode:** when initialised with a persistent `P256.KeyAgreement.PrivateKey`, the server
/// can return a `X-Bella-Wrapped-Dek` header containing a Data-Encryption Key that has been
/// wrapped with the persistent public key. The `onWrappedDekReceived` callback fires whenever
/// that header is present so callers can cache the DEK for offline use.
///
/// Algorithm: ECDH-P256 → HKDF-SHA256 → AES-256-GCM (matches all other Bella Baxter SDKs).
struct E2EEncryptionMiddleware: ClientMiddleware {

    private let privateKey: P256.KeyAgreement.PrivateKey

    /// Base64-encoded SPKI DER public key — sent as the `X-E2E-Public-Key` request header.
    let publicKeyBase64: String

    /// ZKE: called when the server returns `X-Bella-Wrapped-Dek` on a secrets response.
    ///
    /// Arguments: `projectSlug`, `environmentSlug`, `wrappedDek` (base64), `leaseExpires`.
    let onWrappedDekReceived: (@Sendable (String, String, String, Date?) -> Void)?

    /// Default: generates an ephemeral P-256 key (existing behaviour — no ZKE).
    init() {
        let key = P256.KeyAgreement.PrivateKey()
        self.privateKey = key
        self.publicKeyBase64 = key.publicKey.derRepresentation.base64EncodedString()
        self.onWrappedDekReceived = nil
    }

    /// ZKE: use a persistent P-256 private key so the server can wrap the DEK for it.
    ///
    /// - Parameters:
    ///   - privateKey: Persistent P-256 key (e.g. loaded from Keychain after `bella auth setup`).
    ///   - onWrappedDekReceived: Called whenever `X-Bella-Wrapped-Dek` is present in a secrets
    ///     response. Arguments: `projectSlug`, `environmentSlug`, `wrappedDek` (base64),
    ///     `leaseExpires`.
    init(
        privateKey: P256.KeyAgreement.PrivateKey,
        onWrappedDekReceived: (@Sendable (String, String, String, Date?) -> Void)? = nil
    ) {
        self.privateKey = privateKey
        // Export as SPKI DER — the format the server expects for key wrapping.
        self.publicKeyBase64 = privateKey.publicKey.derRepresentation.base64EncodedString()
        self.onWrappedDekReceived = onWrappedDekReceived
    }

    func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: @Sendable (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        // Only intercept getAllEnvironmentSecrets (GET .../secrets)
        let isSecretsGet = operationID == "getAllEnvironmentSecrets"

        var modifiedRequest = request
        if isSecretsGet {
            modifiedRequest.headerFields[HTTPField.Name("X-E2E-Public-Key")!] = publicKeyBase64
        }

        let (response, responseBody) = try await next(modifiedRequest, body, baseURL)

        guard isSecretsGet,
              response.status.code >= 200, response.status.code < 300
        else {
            return (response, responseBody)
        }

        // #1050 (b) — the key was presented. On an envelope-required read the answer MUST be an envelope
        // that decrypts to this key; anything else is refused, never handed to the decoder as secrets.
        let path = Self.pathOnly(request.path)
        let envelopeRequired = Self.requiresEnvelope(method: request.method, path: path)

        // Collect body bytes
        var data = Data()
        if let responseBody {
            for try await chunk in responseBody {
                data.append(contentsOf: chunk)
            }
        }

        let finalData: Data
        if let envelope = Self.envelope(in: data) {
            do {
                finalData = try decrypt(envelope)
            } catch {
                // #1050 — never the original bytes in place of a failed decryption.
                throw E2EEResponseError(code: .decryptionFailed, path: path, underlying: error)
            }
        } else if envelopeRequired {
            throw E2EEResponseError(code: .plaintextResponse, path: path, underlying: nil)
        } else {
            guard responseBody != nil else { return (response, nil) }
            finalData = data // not a value-carrying read: plain JSON is the server's real answer
        }

        // ZKE: capture wrapped DEK header when a persistent key + callback are configured.
        if let onWrappedDek = onWrappedDekReceived,
           let wrappedDek = response.headerFields[HTTPField.Name("X-Bella-Wrapped-Dek")!] {
            let leaseExpiresStr = response.headerFields[HTTPField.Name("X-Bella-Lease-Expires")!]
            // The API writes this with DateTimeOffset.ToString("O") — seven fractional digits —
            // which a default ISO8601DateFormatter rejects, so the lease always arrived as nil (#993).
            let leaseExpires: Date? = leaseExpiresStr.flatMap {
                try? BellaDateTranscoder().decode($0)
            }
            let pathComponents = request.path?.split(separator: "/").map(String.init) ?? []
            let projectSlug = extractSlug(from: pathComponents, after: "projects")
            let envSlug     = extractSlug(from: pathComponents, after: "environments")
            onWrappedDek(projectSlug, envSlug, wrappedDek, leaseExpires)
        }

        return (response, HTTPBody(finalData))
    }

    // MARK: - Envelope-required reads (apps/sdk/SDK_CONTRACT.md)

    /// Whether a `2xx` answer to this request, once the key was presented, MUST be an E2EE envelope:
    /// the `GET`s that carry secret values (SDK_CONTRACT.md, "Which Endpoints Support E2EE"). Every other
    /// call under `/secrets` is answered in plain JSON even when the key is presented.
    ///
    /// `path` may be absolute or relative to the server URL; it is located by `/api/v1/projects/`.
    static func requiresEnvelope(method: HTTPRequest.Method, path: String) -> Bool {
        guard method == .get else { return false }
        let normalized = path.hasPrefix("/") ? path : "/" + path
        guard let range = normalized.range(of: "/api/v1/projects/") else { return false }
        let segments = normalized[range.upperBound...].split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
        guard segments.count >= 2, !segments[0].isEmpty else { return false }
        let rest = Array(segments.dropFirst())
        switch rest.count {
        case 1:
            return rest[0] == "secrets"                                          // listGlobalSecrets
        case 3:
            return rest[0] == "environments" && rest[2] == "secrets"             // getAllEnvironmentSecrets
        case 4:
            return rest[0] == "environments" && rest[2] == "secrets" && rest[3] == "export"
        case 5:
            return rest[0] == "environments" && rest[2] == "providers" && rest[4] == "secrets"
        case 6:
            // exportSecrets, or getSecret for any key but the `hash` route
            return rest[0] == "environments" && rest[2] == "providers" && rest[4] == "secrets"
                && !rest[5].isEmpty && rest[5] != "hash"
        case 8:
            return rest[0] == "environments" && rest[2] == "providers" && rest[4] == "secrets"
                && !rest[5].isEmpty && rest[6] == "versions"
                && !rest[7].isEmpty && rest[7].allSatisfy { $0.isASCII && $0.isNumber }
        default:
            return false
        }
    }

    /// The request path without its query string.
    static func pathOnly(_ path: String?) -> String {
        guard let path else { return "" }
        if let q = path.firstIndex(of: "?") { return String(path[..<q]) }
        return path
    }

    // MARK: - Helpers

    /// Returns the path component that immediately follows `keyword`, or `""` if not found.
    private func extractSlug(from components: [String], after keyword: String) -> String {
        guard let idx = components.firstIndex(of: keyword), idx + 1 < components.count else {
            return ""
        }
        return components[idx + 1]
    }

    // MARK: - Decryption

    /// The body as an envelope (`{"encrypted": true, …}`), or nil when it is not one.
    private static func envelope(in data: Data) -> [String: Any]? {
        guard
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            json["encrypted"] as? Bool == true
        else { return nil }
        return json
    }

    private func decrypt(_ json: [String: Any]) throws -> Data {
        guard
            let serverPubB64 = json["serverPublicKey"] as? String,
            let nonceB64     = json["nonce"]            as? String,
            let tagB64       = json["tag"]              as? String,
            let cipherB64    = json["ciphertext"]       as? String,
            let serverPubDer = Data(base64Encoded: serverPubB64),
            let nonceData    = Data(base64Encoded: nonceB64),
            let tagData      = Data(base64Encoded: tagB64),
            let cipherData   = Data(base64Encoded: cipherB64)
        else {
            throw E2EDecryptionError.malformedPayload
        }

        // 1. Import server ephemeral public key (SPKI DER)
        let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPubDer)

        // 2. ECDH → shared secret
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)

        // 3. HKDF-SHA256 → 32-byte AES key
        //    salt = 32 zero bytes (matches server / RFC 5869 default for SHA-256 HashLen)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0, count: 32),
            sharedInfo: Data("bella-e2ee-v1".utf8),
            outputByteCount: 32
        )

        // 4. AES-256-GCM decrypt
        let gcmNonce  = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: cipherData, tag: tagData)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

        // Plaintext is the full AllEnvironmentSecretsResponse JSON — return as-is
        // so the generated client can deserialize it directly.
        return plaintext
    }
}

// MARK: - Errors

/// The cause behind ``E2EEResponseError/underlying`` when an envelope lacks a field.
enum E2EDecryptionError: Error, LocalizedError {
    case malformedPayload

    var errorDescription: String? {
        switch self {
        case .malformedPayload: "E2EE payload is missing required fields"
        }
    }
}

/// A secrets response that was refused because this client presented its E2EE key and the answer was
/// not an envelope it could decrypt (#1050; apps/sdk/SDK_CONTRACT.md, "a presented key requires an
/// envelope"). There is no plaintext fallback: an answer that should have been encrypted to this client
/// and was not — or was encrypted to someone else, or was tampered with — is never returned as secrets.
///
/// ``code`` is the cross-SDK contract (the same strings in all nine SDKs). The message names the request
/// path and the code, never the body, ciphertext or key material.
public struct E2EEResponseError: Error, LocalizedError, CustomStringConvertible, Sendable {
    /// The stable, cross-SDK reason for the refusal.
    public enum Code: String, Sendable {
        /// The key was presented, and a value-carrying read came back without an envelope.
        case plaintextResponse = "e2ee-plaintext-response"
        /// An envelope came back but did not decrypt: malformed, tampered, or encrypted to another key.
        case decryptionFailed = "e2ee-decryption-failed"
    }

    /// Why the response was refused.
    public let code: Code
    /// The request path whose response was refused (no query string).
    public let path: String
    /// The decryption failure behind ``Code/decryptionFailed``; nil for ``Code/plaintextResponse``.
    public let underlying: (any Error)?

    public init(code: Code, path: String, underlying: (any Error)? = nil) {
        self.code = code
        self.path = path
        self.underlying = underlying
    }

    public var description: String {
        switch code {
        case .plaintextResponse:
            "E2EE response expected but plaintext received for \(path); refusing it (\(code.rawValue))"
        case .decryptionFailed:
            "E2EE response could not be decrypted for \(path); refusing it (\(code.rawValue))"
        }
    }

    public var errorDescription: String? { description }
}
