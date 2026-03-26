import CryptoKit
import Foundation

/// Verifies the `X-Bella-Signature` header on incoming Bella Baxter webhook requests.
///
/// Header format: `t={unix_epoch_seconds},v1={hmac_sha256_hex}`
/// Signing input:  `{t}.{rawBodyJson}` (UTF-8)
/// HMAC key:       the raw `whsec-xxx` signing secret (UTF-8 encoded)
public struct WebhookSignatureVerifier {

    public static let defaultToleranceSeconds: Double = 300

    /// Verifies the webhook signature.
    ///
    /// - Parameters:
    ///   - secret: The `whsec-xxx` signing secret string.
    ///   - signatureHeader: Value of the `X-Bella-Signature` header.
    ///   - rawBody: The raw request body as a UTF-8 string.
    ///   - toleranceSeconds: Max timestamp age in seconds (default 300).
    /// - Returns: `true` if the signature is valid and within the timestamp tolerance.
    public static func verify(
        secret: String,
        signatureHeader: String,
        rawBody: String,
        toleranceSeconds: Double = defaultToleranceSeconds
    ) -> Bool {
        var t: String?
        var v1: String?

        for part in signatureHeader.split(separator: ",") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("t=") {
                t = String(trimmed.dropFirst(2))
            } else if trimmed.hasPrefix("v1=") {
                v1 = String(trimmed.dropFirst(3))
            }
        }

        guard let timestampStr = t, !timestampStr.isEmpty,
              let signature = v1, !signature.isEmpty,
              let timestampSeconds = Double(timestampStr)
        else {
            return false
        }

        let now = Date().timeIntervalSince1970
        guard abs(now - timestampSeconds) <= toleranceSeconds else {
            return false
        }

        guard let keyData = secret.data(using: .utf8),
              let signingData = "\(timestampStr).\(rawBody)".data(using: .utf8)
        else {
            return false
        }

        let key = SymmetricKey(data: keyData)

        // Constant-time comparison via CryptoKit's built-in isValidAuthenticationCode,
        // reconstructing the MAC from the hex-decoded candidate to stay timing-safe.
        guard let candidateBytes = hexDecode(signature),
              candidateBytes.count == SHA256.byteCount
        else {
            return false
        }

        return HMAC<SHA256>.isValidAuthenticationCode(
            candidateBytes,
            authenticating: signingData,
            using: key
        )
    }

    // MARK: - Private helpers

    private static func hexDecode(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        return data
    }
}
