import CryptoKit
import Foundation
import XCTest
@testable import BellaBaxterSwift

/// #993 — the API sends `DateTimeOffset` values WITH fractional seconds, and the SDK must decode
/// them. The shapes below are what the API actually emits, produced by serializing
/// `AllEnvironmentSecretsResponse` with the API's own options (not guessed):
///
/// - E2EE path — what this SDK always receives, because it always sends `X-E2E-Public-Key`:
///   `GetAllEnvironmentSecrets.TryEncrypt` serializes with `JsonSerializerOptions.Web`, whose
///   DateTimeOffset format is round-trip ISO 8601 with 0–7 fractional digits and a `+00:00`
///   offset — `"2026-09-27T07:35:49.634244+00:00"`, `"…30.1234568+00:00"`, `"…30+00:00"`.
/// - Plain path — `DateTimeOffsetJsonConverter`, always exactly three digits and `Z`:
///   `"2026-09-27T07:35:49.634Z"`, even `"…30.000Z"` on a whole second.
/// - `X-Bella-Lease-Expires` is `DateTimeOffset.ToString("O")`: `"…49.7033890+00:00"`.
///
/// The swift-openapi-runtime default transcoder (`.iso8601`) accepts none of the fractional forms,
/// so before the fix every `pullSecrets()` against the real API failed to decode.
///
/// The test drives the real client: `BellaClient` → HMAC + E2EE middleware → `URLSessionTransport`
/// → a `URLProtocol` stub that encrypts the body to the client's presented key exactly as the API
/// does → the generated decoder.
final class DateDecodingTests: XCTestCase {

    // A throwaway key-pair format that passes `HmacAuthMiddleware` — it protects nothing.
    private static let apiKey = "bax-0123456789abcdef0123456789abcdef-" + String(repeating: "ab", count: 32)
    private static let baseURL = URL(string: "https://bella.test")!

    override func tearDown() {
        StubBellaAPI.reset()
        super.tearDown()
    }

    private func pull(lastModified: String) async throws -> [String: String] {
        StubBellaAPI.lastModified = lastModified
        let client = try BellaClient(
            BellaClientOptions(
                baseURL: Self.baseURL,
                apiKey: Self.apiKey,
                privateKey: P256.KeyAgreement.PrivateKey()
            ),
            sessionConfiguration: StubBellaAPI.sessionConfiguration()
        )
        return try await client.pullSecrets()
    }

    // MARK: - lastModified, as the E2EE path serializes it

    func test_pullSecrets_decodes_lastModified_with_microseconds_and_offset() async throws {
        let secrets = try await pull(lastModified: "2026-09-27T07:35:49.634244+00:00")
        XCTAssertEqual(secrets, ["DATABASE_URL": "postgres://db"])
    }

    func test_pullSecrets_decodes_lastModified_with_seven_fractional_digits() async throws {
        let secrets = try await pull(lastModified: "2026-09-27T10:15:30.1234568+00:00")
        XCTAssertEqual(secrets, ["DATABASE_URL": "postgres://db"])
    }

    func test_pullSecrets_decodes_lastModified_on_a_whole_second() async throws {
        let secrets = try await pull(lastModified: "2026-09-27T10:15:30+00:00")
        XCTAssertEqual(secrets, ["DATABASE_URL": "postgres://db"])
    }

    // MARK: - lastModified, as the plain path serializes it

    func test_pullSecrets_decodes_lastModified_with_milliseconds_and_Z() async throws {
        let secrets = try await pull(lastModified: "2026-09-27T07:35:49.634Z")
        XCTAssertEqual(secrets, ["DATABASE_URL": "postgres://db"])
    }

    func test_pullSecrets_decodes_lastModified_without_fraction_and_Z() async throws {
        let secrets = try await pull(lastModified: "2026-09-27T10:15:30Z")
        XCTAssertEqual(secrets, ["DATABASE_URL": "postgres://db"])
    }

    // MARK: - X-Bella-Lease-Expires (ZKE callback)

    func test_wrapped_dek_callback_receives_the_lease_expiry() async throws {
        StubBellaAPI.lastModified = "2026-09-27T07:35:49.634244+00:00"
        StubBellaAPI.extraSecretsHeaders = [
            "X-Bella-Wrapped-Dek": "d3JhcHBlZA==",
            "X-Bella-Lease-Expires": "2026-09-27T07:50:49.7033890+00:00",
        ]
        let received = LeaseBox()
        let client = try BellaClient(
            BellaClientOptions(
                baseURL: Self.baseURL,
                apiKey: Self.apiKey,
                privateKey: P256.KeyAgreement.PrivateKey(),
                onWrappedDekReceived: { project, env, dek, lease in
                    received.set(project: project, env: env, dek: dek, lease: lease)
                }
            ),
            sessionConfiguration: StubBellaAPI.sessionConfiguration()
        )

        _ = try await client.pullSecrets()

        XCTAssertEqual(received.project, "my-app")
        XCTAssertEqual(received.env, "production")
        XCTAssertEqual(received.dek, "d3JhcHBlZA==")
        let lease = try XCTUnwrap(received.lease, "X-Bella-Lease-Expires was not parsed")
        XCTAssertEqual(lease.timeIntervalSince1970, 1_790_495_449.703, accuracy: 0.001)
    }
}

// MARK: - Stub API

/// Answers the two calls `pullSecrets()` makes, the way the real API does.
final class StubBellaAPI: URLProtocol {
    nonisolated(unsafe) static var lastModified = ""
    nonisolated(unsafe) static var extraSecretsHeaders: [String: String] = [:]

    static func reset() {
        lastModified = ""
        extraSecretsHeaders = [:]
    }

    static func sessionConfiguration() -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubBellaAPI.self]
        return cfg
    }

    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "bella.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        do {
            let (status, headers, body) = try respond(to: request)
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    private func respond(to request: URLRequest) throws -> (Int, [String: String], Data) {
        let json = ["Content-Type": "application/json"]
        let path = request.url?.path ?? ""
        if path.hasSuffix("/api/v1/keys/me") {
            let body = #"{"keyId":"0123456789abcdef0123456789abcdef","role":"READER","projectSlug":"my-app","environmentSlug":"production","projectName":"My App","environmentName":"Production"}"#
            return (200, json, Data(body.utf8))
        }
        if path.hasSuffix("/api/v1/projects/my-app/environments/production/secrets") {
            // Byte-for-byte the shape JsonSerializerOptions.Web gives AllEnvironmentSecretsResponse.
            let plaintext = #"{"environmentSlug":"production","environmentName":"Production","secrets":{"DATABASE_URL":"postgres://db"},"version":1790494549,"lastModified":"\#(Self.lastModified)"}"#
            guard let presented = request.value(forHTTPHeaderField: "X-E2E-Public-Key") else {
                return (200, json, Data(plaintext.utf8))
            }
            let payload = try Self.encrypt(Data(plaintext.utf8), toSpkiBase64: presented)
            return (200, json.merging(Self.extraSecretsHeaders) { a, _ in a }, payload)
        }
        return (404, json, Data("{}".utf8))
    }

    /// The API's E2EE envelope: ECDH-P256 → HKDF-SHA256 (32 zero-byte salt, "bella-e2ee-v1") →
    /// AES-256-GCM, fields base64.
    private static func encrypt(_ plaintext: Data, toSpkiBase64 spki: String) throws -> Data {
        let clientKey = try P256.KeyAgreement.PublicKey(derRepresentation: Data(base64Encoded: spki)!)
        let serverKey = P256.KeyAgreement.PrivateKey()
        let shared = try serverKey.sharedSecretFromKeyAgreement(with: clientKey)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0, count: 32),
            sharedInfo: Data("bella-e2ee-v1".utf8),
            outputByteCount: 32
        )
        let sealed = try AES.GCM.seal(plaintext, using: key)
        let envelope: [String: Any] = [
            "encrypted": true,
            "algorithm": "ECDH-P256-HKDF-SHA256-AES256GCM",
            "serverPublicKey": serverKey.publicKey.derRepresentation.base64EncodedString(),
            "nonce": Data(sealed.nonce).base64EncodedString(),
            "tag": sealed.tag.base64EncodedString(),
            "ciphertext": sealed.ciphertext.base64EncodedString(),
        ]
        return try JSONSerialization.data(withJSONObject: envelope)
    }
}

private final class LeaseBox: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var project: String?
    private(set) var env: String?
    private(set) var dek: String?
    private(set) var lease: Date?

    func set(project: String, env: String, dek: String, lease: Date?) {
        lock.lock(); defer { lock.unlock() }
        self.project = project
        self.env = env
        self.dek = dek
        self.lease = lease
    }
}
