import CryptoKit
import Foundation
import HTTPTypes
import OpenAPIRuntime
import XCTest
@testable import BellaBaxterSwift

/// #1050 (b) — once this SDK has presented its E2EE key, an answer to a value-carrying read that is not
/// an envelope it can decrypt is REFUSED (apps/sdk/SDK_CONTRACT.md, "a presented key requires an envelope").
///
/// The misbehaving server is the `next` closure handed to the middleware (and, end to end, a `URLProtocol`
/// behind the real `BellaClient`): it answers the presented key with a genuine envelope, with plaintext,
/// with a tampered envelope, or with an envelope encrypted to a different key.
final class E2EEResponseRefusalTests: XCTestCase {

    private static let secretsPath = "/api/v1/projects/my-app/environments/production/secrets"
    private static let sentinel = "the-sentinel-must-never-reach-the-caller"
    private static let plaintext = Data(
        #"{"environmentSlug":"production","environmentName":"Production","secrets":{"SENTINEL":"\#(sentinel)"},"version":1,"lastModified":"2026-10-04T10:00:00Z"}"#.utf8)

    enum Server: Sendable {
        case envelope, plaintext, tampered, wrongKey, malformed
        case status(Int, Data)
    }

    // MARK: - Middleware, driven directly

    private func intercept(
        _ server: Server,
        operationID: String = "getAllEnvironmentSecrets",
        method: HTTPRequest.Method = .get,
        path: String = secretsPath
    ) async throws -> (presented: String?, status: Int, body: Data?) {
        let middleware = E2EEncryptionMiddleware(privateKey: P256.KeyAgreement.PrivateKey())
        let presented = PresentedBox()
        let request = HTTPRequest(method: method, scheme: nil, authority: nil, path: path)
        let (response, body) = try await middleware.intercept(
            request, body: nil, baseURL: URL(string: "https://bella.test")!, operationID: operationID
        ) { request, _, _ in
            let key = request.headerFields[HTTPField.Name("X-E2E-Public-Key")!]
            presented.set(key)
            let (status, data) = try Self.answer(server, presentedKey: key)
            return (HTTPResponse(status: .init(code: status)), HTTPBody(data))
        }
        let data: Data? = if let body { try await Data(collecting: body, upTo: .max) } else { nil }
        return (presented.value, response.status.code, data)
    }

    private func assertRefused(
        _ server: Server, _ code: E2EEResponseError.Code, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            let result = try await intercept(server)
            XCTFail("accepted the answer: \(String(decoding: result.body ?? Data(), as: UTF8.self))", file: file, line: line)
        } catch let error as E2EEResponseError {
            XCTAssertEqual(error.code, code, file: file, line: line)
            XCTAssertEqual(error.path, Self.secretsPath, file: file, line: line)
            XCTAssertTrue("\(error)".contains(code.rawValue), "\(error)", file: file, line: line)
            XCTAssertFalse("\(error)".contains(Self.sentinel), file: file, line: line)
        } catch {
            XCTFail("expected E2EEResponseError, got \(error)", file: file, line: line)
        }
    }

    func test_valid_envelope_to_the_presented_key_is_decrypted() async throws {
        let result = try await intercept(.envelope)
        XCTAssertNotNil(result.presented)
        XCTAssertEqual(result.status, 200)
        XCTAssertEqual(result.body, Self.plaintext)
    }

    func test_plaintext_after_presenting_the_key_is_refused() async {
        await assertRefused(.plaintext, .plaintextResponse)
    }

    func test_tampered_envelope_is_refused() async {
        await assertRefused(.tampered, .decryptionFailed)
    }

    func test_envelope_to_another_key_is_refused() async {
        await assertRefused(.wrongKey, .decryptionFailed)
    }

    func test_envelope_missing_a_field_is_refused() async {
        await assertRefused(.malformed, .decryptionFailed)
    }

    func test_empty_2xx_body_after_presenting_the_key_is_refused() async {
        await assertRefused(.status(200, Data()), .plaintextResponse)
    }

    func test_non_2xx_answer_is_not_turned_into_a_refusal() async throws {
        let problem = Data(#"{"type":"zke-device-not-registered","status":403}"#.utf8)
        let result = try await intercept(.status(403, problem))
        XCTAssertEqual(result.status, 403)
        XCTAssertEqual(result.body, problem)
    }

    func test_other_operations_present_no_key_and_pass_plaintext_through() async throws {
        let plain = Data(#"{"version":7}"#.utf8)
        let result = try await intercept(
            .status(200, plain), operationID: "getEnvironmentSecretsVersion", path: Self.secretsPath + "/version")
        XCTAssertNil(result.presented)
        XCTAssertEqual(result.body, plain)
    }

    // MARK: - The envelope-required reads (SDK_CONTRACT.md)

    func test_requiresEnvelope_matches_exactly_the_value_carrying_reads() {
        let base = "/api/v1/projects/p/environments/e"
        let required = [
            "/api/v1/projects/p/secrets",
            "\(base)/secrets",
            "\(base)/secrets/export",
            "\(base)/providers/v/secrets",
            "\(base)/providers/v/secrets/export",
            "\(base)/providers/v/secrets/DB_URL",
            "\(base)/providers/v/secrets/DB_URL/versions/3",
            "api/v1/projects/p/environments/e/secrets",          // relative to the server URL
            "/bella/api/v1/projects/p/environments/e/secrets",    // behind a path prefix
        ]
        for path in required {
            XCTAssertTrue(E2EEncryptionMiddleware.requiresEnvelope(method: .get, path: path), path)
        }
        let notRequired = [
            "\(base)/secrets/version",
            "\(base)/secrets/manifest",
            "\(base)/secrets/certificates",
            "\(base)/providers/v/secrets/hash",
            "\(base)/providers/v/secrets/DB_URL/metadata",
            "\(base)/providers/v/secrets/DB_URL/versions",
            "\(base)/providers/v/secrets/DB_URL/versions/latest",
            "\(base)/providers/v/secrets/DB_URL/rotation-policy",
            "\(base)/providers/v/secrets/import/preview",
            "/api/v1/projects/p/environments",
            "/api/v1/tenants/me/zke",
        ]
        for path in notRequired {
            XCTAssertFalse(E2EEncryptionMiddleware.requiresEnvelope(method: .get, path: path), path)
        }
        for method in [HTTPRequest.Method.post, .put, .patch, .delete] {
            XCTAssertFalse(E2EEncryptionMiddleware.requiresEnvelope(method: method, path: "\(base)/secrets"))
        }
    }

    // MARK: - End to end: what a caller of pullSecrets() sees

    private func pull(_ server: Server) async throws -> [String: String] {
        RefusalStubAPI.server = server
        defer { RefusalStubAPI.server = .envelope }
        let client = try BellaClient(
            BellaClientOptions(
                baseURL: URL(string: "https://bella-refusal.test")!,
                apiKey: "bax-0123456789abcdef0123456789abcdef-" + String(repeating: "ab", count: 32),
                privateKey: P256.KeyAgreement.PrivateKey()
            ),
            sessionConfiguration: RefusalStubAPI.sessionConfiguration()
        )
        return try await client.pullSecrets()
    }

    func test_pullSecrets_returns_the_values_of_a_valid_envelope() async throws {
        let secrets = try await pull(.envelope)
        XCTAssertEqual(secrets, ["SENTINEL": Self.sentinel])
    }

    func test_pullSecrets_throws_the_refusal_itself_with_its_code() async {
        let cases: [(Server, E2EEResponseError.Code)] = [
            (.plaintext, .plaintextResponse), (.tampered, .decryptionFailed), (.wrongKey, .decryptionFailed),
        ]
        for (server, code) in cases {
            do {
                let secrets = try await pull(server)
                XCTFail("\(server): accepted \(secrets)")
            } catch let error as E2EEResponseError {
                // Unwrapped from the runtime's ClientError, so `"\(error)"` — what the contract program
                // prints — is the contract message and carries the code.
                XCTAssertEqual(error.code, code, "\(server)")
                XCTAssertTrue("\(error)".contains(code.rawValue), "\(error)")
                XCTAssertFalse("\(error)".contains(Self.sentinel))
            } catch {
                XCTFail("\(server): expected E2EEResponseError, got \(error)")
            }
        }
    }

    // MARK: - The misbehaving server

    static func answer(_ server: Server, presentedKey: String?) throws -> (Int, Data) {
        switch server {
        case .status(let code, let data):
            return (code, data)
        case .plaintext:
            return (200, plaintext)
        case .envelope, .tampered, .wrongKey, .malformed:
            guard let presentedKey else { return (403, Data(#"{"error":"no key presented"}"#.utf8)) }
            let recipient = server == .wrongKey
                ? P256.KeyAgreement.PrivateKey().publicKey.derRepresentation.base64EncodedString()
                : presentedKey
            var envelope = try encrypt(plaintext, toSpkiBase64: recipient)
            if server == .tampered {
                var bytes = Data(base64Encoded: envelope["ciphertext"] as! String)!
                bytes[bytes.startIndex] ^= 0x01
                envelope["ciphertext"] = bytes.base64EncodedString()
            }
            if server == .malformed { envelope.removeValue(forKey: "tag") }
            return (200, try JSONSerialization.data(withJSONObject: envelope))
        }
    }

    /// The API's envelope: ECDH-P256 → HKDF-SHA256 (32 zero-byte salt, "bella-e2ee-v1") → AES-256-GCM.
    static func encrypt(_ plaintext: Data, toSpkiBase64 spki: String) throws -> [String: Any] {
        let clientKey = try P256.KeyAgreement.PublicKey(derRepresentation: Data(base64Encoded: spki)!)
        let serverKey = P256.KeyAgreement.PrivateKey()
        let key = try serverKey.sharedSecretFromKeyAgreement(with: clientKey).hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0, count: 32),
            sharedInfo: Data("bella-e2ee-v1".utf8),
            outputByteCount: 32
        )
        let sealed = try AES.GCM.seal(plaintext, using: key)
        return [
            "encrypted": true,
            "algorithm": "ECDH-P256-HKDF-SHA256-AES256GCM",
            "serverPublicKey": serverKey.publicKey.derRepresentation.base64EncodedString(),
            "nonce": Data(sealed.nonce).base64EncodedString(),
            "tag": sealed.tag.base64EncodedString(),
            "ciphertext": sealed.ciphertext.base64EncodedString(),
        ]
    }
}

extension E2EEResponseRefusalTests.Server: Equatable {}

private final class PresentedBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: String?
    var value: String? { lock.lock(); defer { lock.unlock() }; return _value }
    func set(_ value: String?) { lock.lock(); defer { lock.unlock() }; _value = value }
}

/// The two calls `pullSecrets()` makes, answered by a server that misbehaves on the secrets read.
final class RefusalStubAPI: URLProtocol {
    nonisolated(unsafe) static var server: E2EEResponseRefusalTests.Server = .envelope

    static func sessionConfiguration() -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [RefusalStubAPI.self]
        return cfg
    }

    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "bella-refusal.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        do {
            let path = request.url?.path ?? ""
            let (status, body): (Int, Data)
            if path.hasSuffix("/api/v1/keys/me") {
                (status, body) = (200, Data(#"{"keyId":"k","role":"READER","projectSlug":"my-app","environmentSlug":"production","projectName":"My App","environmentName":"Production"}"#.utf8))
            } else if path.hasSuffix("/api/v1/projects/my-app/environments/production/secrets") {
                (status, body) = try E2EEResponseRefusalTests.answer(
                    Self.server, presentedKey: request.value(forHTTPHeaderField: "X-E2E-Public-Key"))
            } else {
                (status, body) = (404, Data("{}".utf8))
            }
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }
}
