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
              response.status.code >= 200, response.status.code < 300,
              let responseBody
        else {
            return (response, responseBody)
        }

        // Collect body bytes
        var data = Data()
        for try await chunk in responseBody {
            data.append(contentsOf: chunk)
        }

        let finalData: Data
        do {
            finalData = try decryptIfNeeded(data)
        } catch {
            await Console.error("[BellaClient] E2EE decryption failed: \(error)")
            finalData = data
        }

        // ZKE: capture wrapped DEK header when a persistent key + callback are configured.
        if let onWrappedDek = onWrappedDekReceived,
           let wrappedDek = response.headerFields[HTTPField.Name("X-Bella-Wrapped-Dek")!] {
            let leaseExpiresStr = response.headerFields[HTTPField.Name("X-Bella-Lease-Expires")!]
            let leaseExpires: Date? = leaseExpiresStr.flatMap {
                ISO8601DateFormatter().date(from: $0)
            }
            let pathComponents = request.path?.split(separator: "/").map(String.init) ?? []
            let projectSlug = extractSlug(from: pathComponents, after: "projects")
            let envSlug     = extractSlug(from: pathComponents, after: "environments")
            onWrappedDek(projectSlug, envSlug, wrappedDek, leaseExpires)
        }

        return (response, HTTPBody(finalData))
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

    private func decryptIfNeeded(_ data: Data) throws -> Data {
        guard
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            json["encrypted"] as? Bool == true
        else {
            return data // plain response — pass through as-is
        }

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

enum E2EDecryptionError: Error, LocalizedError {
    case malformedPayload

    var errorDescription: String? {
        switch self {
        case .malformedPayload: "E2EE payload is missing required fields"
        }
    }
}

// MARK: - Console helper (stderr)

private enum Console {
    static func error(_ message: String) async {
        var stderr = FileHandle.standardError
        if let data = (message + "\n").data(using: .utf8) {
            stderr.write(data)
        }
    }
}
