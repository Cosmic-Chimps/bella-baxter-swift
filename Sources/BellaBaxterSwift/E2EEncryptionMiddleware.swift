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
/// Algorithm: ECDH-P256 → HKDF-SHA256 → AES-256-GCM (matches all other Bella Baxter SDKs).
struct E2EEncryptionMiddleware: ClientMiddleware {

    private let privateKey: P256.KeyAgreement.PrivateKey

    /// Base64-encoded SPKI DER public key — sent as the `X-E2E-Public-Key` request header.
    let publicKeyBase64: String

    init() {
        let key = P256.KeyAgreement.PrivateKey()
        self.privateKey = key
        self.publicKeyBase64 = key.publicKey.derRepresentation.base64EncodedString()
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

        return (response, HTTPBody(finalData))
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
