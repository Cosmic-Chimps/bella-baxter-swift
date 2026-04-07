#if canImport(Security)
import Foundation
import Security

/// A ``SecretCache`` implementation backed by the Apple Keychain.
///
/// Secrets are stored as a single JSON-encoded entry under
/// `kSecClassGenericPassword` with:
/// - `kSecAttrService` = `"io.bella-baxter.secrets"`
/// - `kSecAttrAccount` = the `account` you provide (defaults to `"default"`)
///
/// This makes it easy to store secrets for multiple environments
/// by using the environment ID as the `account`:
/// ```swift
/// let cache = KeychainSecretCache(account: environmentId)
/// ```
///
/// All operations are thread-safe — the Security framework serialises
/// Keychain access internally.
public struct KeychainSecretCache: SecretCache {
    private let service: String
    private let account: String

    /// Creates a Keychain cache entry.
    /// - Parameters:
    ///   - service: Keychain service name. Default: `"io.bella-baxter.secrets"`.
    ///   - account: Keychain account (use environment ID to namespace per environment).
    ///              Default: `"default"`.
    public init(
        service: String = "io.bella-baxter.secrets",
        account: String = "default"
    ) {
        self.service = service
        self.account = account
    }

    // MARK: - SecretCache

    public func read() async throws -> [String: String]? {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      service,
            kSecAttrAccount:      account,
            kSecReturnData:       true,
            kSecMatchLimit:       kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return nil }
            let decoded = try JSONDecoder().decode([String: String].self, from: data)
            return decoded
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.readFailed(status)
        }
    }

    public func write(_ secrets: [String: String]) async throws {
        let data = try JSONEncoder().encode(secrets)

        // Try updating an existing entry first.
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let attributes: [CFString: Any] = [kSecValueData: data]

        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)

        if status == errSecItemNotFound {
            // No existing entry — add a new one.
            var addQuery = query
            addQuery[kSecValueData] = data
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }

        guard status == errSecSuccess else {
            throw KeychainError.writeFailed(status)
        }
    }

    public func clear() async throws {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}

// MARK: - Errors

/// Errors thrown by ``KeychainSecretCache``.
public enum KeychainError: Error, Sendable {
    case readFailed(OSStatus)
    case writeFailed(OSStatus)
    case deleteFailed(OSStatus)
}

#endif // canImport(Security)
