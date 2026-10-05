import CryptoKit
import Foundation
import HTTPTypes
import OpenAPIRuntime
import XCTest
@testable import BellaBaxterSwift

/// #1162 — the key is presented on EVERY envelope-required read (apps/sdk/SDK_CONTRACT.md, "Rule: the key
/// is presented on every envelope-required read"), decided by path in one place, and the decrypted body is
/// handed on unchanged. Before the fix the middleware presented only on `getAllEnvironmentSecrets` (matched
/// by operationId), and `exportSecretsAsEnv` sent its value read raw, with no key at all.
final class E2EEPresentationTests: XCTestCase {

    private static let base = "/api/v1/projects/my-app/environments/production"
    private static let item = #"{"key":"DB_URL","value":"postgres://sentinel","description":null,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z","type":null}"#

    /// The seven envelope-required reads, each with the plaintext the API encrypts for it.
    static let reads: [(operation: String, path: String, plaintext: String)] = [
        ("getAllEnvironmentSecrets", "\(base)/secrets",
         #"{"environmentSlug":"production","environmentName":"Production","secrets":{"DB_URL":"postgres://sentinel"},"version":1,"lastModified":"2026-10-04T10:00:00Z"}"#),
        ("exportEnvironmentSecrets", "\(base)/secrets/export?format=json", #"{"DB_URL":"postgres://sentinel"}"#),
        ("listSecrets", "\(base)/providers/vault/secrets", "[\(item)]"),
        ("exportSecrets", "\(base)/providers/vault/secrets/export", #"{"DB_URL":"postgres://sentinel"}"#),
        ("getSecret", "\(base)/providers/vault/secrets/DB_URL", item),
        ("getSecretVersion", "\(base)/providers/vault/secrets/DB_URL/versions/3", item),
        ("listGlobalSecrets", "/api/v1/projects/my-app/secrets",
         #"{"projectRef":"my-app","projectSlug":"my-app","globalSecretProviderId":null,"secrets":[\#(item)]}"#),
    ]

    // MARK: - The middleware, driven directly

    private func intercept(path: String, operationID: String, answer: Data? = nil) async throws
        -> (presented: String?, body: Data?)
    {
        let middleware = E2EEncryptionMiddleware(privateKey: P256.KeyAgreement.PrivateKey())
        let presented = Box()
        let request = HTTPRequest(method: .get, scheme: nil, authority: nil, path: path)
        let (_, body) = try await middleware.intercept(
            request, body: nil, baseURL: URL(string: "https://bella.test")!, operationID: operationID
        ) { request, _, _ in
            let key = request.headerFields[HTTPField.Name("X-E2E-Public-Key")!]
            presented.set(key)
            let read = Self.reads.first { $0.path == path }
            let data: Data
            if let answer {
                data = answer
            } else if let read, let key {
                data = try JSONSerialization.data(withJSONObject:
                    E2EEResponseRefusalTests.encrypt(Data(read.plaintext.utf8), toSpkiBase64: key))
            } else {
                data = Data(#"{"version":7}"#.utf8)
            }
            return (HTTPResponse(status: .ok), HTTPBody(data))
        }
        let data: Data? = if let body { try await Data(collecting: body, upTo: .max) } else { nil }
        return (presented.value, data)
    }

    func test_the_key_is_presented_on_every_envelope_required_read_whatever_the_operation() async throws {
        for read in Self.reads {
            // An operationId that names none of them: the path decides, not the operation.
            let result = try await intercept(path: read.path, operationID: "someOtherOperation")
            XCTAssertNotNil(result.presented, read.operation)
            XCTAssertEqual(result.body, Data(read.plaintext.utf8), "\(read.operation): body must pass on unchanged")
        }
    }

    func test_a_read_that_carries_no_value_is_not_sent_the_key_even_under_the_bulk_operationId() async throws {
        let plain = Data(#"{"version":7}"#.utf8)
        let result = try await intercept(
            path: "\(Self.base)/secrets/version", operationID: "getAllEnvironmentSecrets", answer: plain)
        XCTAssertNil(result.presented)
        XCTAssertEqual(result.body, plain)
    }

    func test_plaintext_on_any_of_the_seven_is_refused() async {
        for read in Self.reads {
            do {
                _ = try await intercept(path: read.path, operationID: "x", answer: Data(read.plaintext.utf8))
                XCTFail("\(read.operation): accepted plaintext after presenting the key")
            } catch let error as E2EEResponseError {
                XCTAssertEqual(error.code, .plaintextResponse, read.operation)
            } catch {
                XCTFail("\(read.operation): expected E2EEResponseError, got \(error)")
            }
        }
    }

    // MARK: - End to end: BellaClient.rawGet and exportSecretsAsEnv

    private func client() throws -> BellaClient {
        try BellaClient(
            BellaClientOptions(
                baseURL: URL(string: "https://bella-presentation.test")!,
                apiKey: "bax-0123456789abcdef0123456789abcdef-" + String(repeating: "ab", count: 32),
                privateKey: P256.KeyAgreement.PrivateKey()
            ),
            sessionConfiguration: PresentationStubAPI.sessionConfiguration()
        )
    }

    override func setUp() {
        PresentationStubAPI.reset()
    }

    func test_rawGet_presents_the_key_on_each_read_and_returns_the_decrypted_body_unchanged() async throws {
        let client = try client()
        for read in Self.reads {
            let body = try await client.rawGet(path: read.path)
            XCTAssertEqual(body, Data(read.plaintext.utf8), read.operation)
        }
        XCTAssertEqual(PresentationStubAPI.presentedPaths, Self.reads.map { E2EEncryptionMiddleware.pathOnly($0.path) })
        XCTAssertTrue(PresentationStubAPI.unsigned.isEmpty, "unsigned requests: \(PresentationStubAPI.unsigned)")
    }

    func test_rawGet_on_a_read_without_values_sends_no_key_and_returns_the_plain_answer() async throws {
        let body = try await client().rawGet(path: "api/v1/projects/my-app/environments/production/secrets/version")
        XCTAssertEqual(body, Data(#"{"version":7}"#.utf8))
        XCTAssertTrue(PresentationStubAPI.presentedPaths.isEmpty)
    }

    func test_rawGet_surfaces_a_refusal_as_itself() async throws {
        PresentationStubAPI.plaintext = true
        do {
            _ = try await client().rawGet(path: "\(Self.base)/providers/vault/secrets/DB_URL")
            XCTFail("accepted plaintext")
        } catch let error as E2EEResponseError {
            XCTAssertEqual(error.code, .plaintextResponse)
            XCTAssertFalse("\(error)".contains("sentinel"))
        }
    }

    func test_rawGet_maps_a_404() async throws {
        do {
            _ = try await client().rawGet(path: "/api/v1/projects/nope/environments/x/secrets")
            XCTFail("no error")
        } catch BellaError.notFound {
        }
    }

    func test_exportSecretsAsEnv_presents_the_key_and_renders_the_decrypted_dict_as_dotenv() async throws {
        PresentationStubAPI.exportDict = ["B_KEY": "plain", "A_KEY": "has space", "C_KEY": #"q"uote\back"#]
        let text = try await client().exportSecretsAsEnv(
            projectRef: "my-app", environmentSlug: "production", providerSlug: "vault")
        XCTAssertEqual(text, "A_KEY=\"has space\"\nB_KEY=plain\nC_KEY=\"q\\\"uote\\\\back\"\n")
        XCTAssertEqual(PresentationStubAPI.presentedPaths, ["\(Self.base)/providers/vault/secrets/export"])
    }

    func test_exportSecretsAsEnv_refuses_a_plaintext_export() async throws {
        PresentationStubAPI.plaintext = true
        do {
            let text = try await client().exportSecretsAsEnv(
                projectRef: "my-app", environmentSlug: "production", providerSlug: "vault")
            XCTFail("accepted \(text)")
        } catch let error as E2EEResponseError {
            XCTAssertEqual(error.code, .plaintextResponse)
        }
    }

    func test_formatDotenv_matches_the_servers_env_rules() {
        XCTAssertEqual(
            BellaClient.formatDotenv(["Z": "a#b", "M": "line1\nline2", "A": "x=y", "E": ""]),
            "A=x=y\nE=\nM=\"line1\nline2\"\nZ=\"a#b\"\n"
        )
    }
}

private final class Box: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: String?
    var value: String? { lock.lock(); defer { lock.unlock() }; return _value }
    func set(_ value: String?) { lock.lock(); defer { lock.unlock() }; _value = value }
}

/// A Bella that answers the seven reads only to a presented key, encrypted to it.
final class PresentationStubAPI: URLProtocol {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var _presented: [String] = []
    nonisolated(unsafe) private static var _unsigned: [String] = []
    nonisolated(unsafe) static var plaintext = false
    nonisolated(unsafe) static var exportDict: [String: String]? = nil

    static var presentedPaths: [String] { lock.lock(); defer { lock.unlock() }; return _presented }
    static var unsigned: [String] { lock.lock(); defer { lock.unlock() }; return _unsigned }

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        _presented = []; _unsigned = []; plaintext = false; exportDict = nil
    }

    static func sessionConfiguration() -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [PresentationStubAPI.self]
        return cfg
    }

    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "bella-presentation.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        do {
            let path = request.url?.path ?? ""
            let key = request.value(forHTTPHeaderField: "X-E2E-Public-Key")
            Self.lock.lock()
            if key != nil { Self._presented.append(path) }
            if request.value(forHTTPHeaderField: "X-Bella-Signature") == nil { Self._unsigned.append(path) }
            Self.lock.unlock()

            var plaintext = E2EEPresentationTests.reads.first { E2EEncryptionMiddleware.pathOnly($0.path) == path }?
                .plaintext
            if path.hasSuffix("/providers/vault/secrets/export"), let dict = Self.exportDict {
                plaintext = String(decoding: try JSONSerialization.data(withJSONObject: dict), as: UTF8.self)
            }
            let (status, body): (Int, Data)
            if path.hasSuffix("/secrets/version") {
                (status, body) = (200, Data(#"{"version":7}"#.utf8))
            } else if let plaintext {
                if let key {
                    (status, body) = Self.plaintext
                        ? (200, Data(plaintext.utf8))
                        : (200, try JSONSerialization.data(withJSONObject:
                            E2EEResponseRefusalTests.encrypt(Data(plaintext.utf8), toSpkiBase64: key)))
                } else {
                    (status, body) = (403, Data(#"{"error":"no key presented"}"#.utf8))
                }
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
