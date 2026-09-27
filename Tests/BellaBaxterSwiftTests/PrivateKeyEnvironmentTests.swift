import CryptoKit
import Foundation
import XCTest
@testable import BellaBaxterSwift

/// #989 — `BELLA_BAXTER_PRIVATE_KEY` must load as PEM (what `bella sdk run` injects) AND as base64
/// PKCS#8 DER, and a key that is present but unreadable must fail loudly instead of silently
/// becoming an ephemeral key. Before the fix the options initializer did
/// `Data(base64Encoded:)` + `try?`, so the injected PEM became `nil` without a word.
final class PrivateKeyEnvironmentTests: XCTestCase {
    private static let variable = "BELLA_BAXTER_PRIVATE_KEY"

    // A throwaway P-256 key generated for this test only — it protects nothing.
    private static let pem = """
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsRj1N+yeYs4m7pH3
        We/3RD2dPnY3qn/GMnO95RIadNmhRANCAARsr5nCopK1zDCQeeJIOTdI1+lvXOI2
        6MCCkfapMFpxN9JN+8XObkqRgSSSNzBzxxUHq0I6NoXfePrhscq3iPqu
        -----END PRIVATE KEY-----
        """

    // The same key as bare base64 PKCS#8 DER (the pre-#755 injection format).
    private static let base64Der =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsRj1N+yeYs4m7pH3"
        + "We/3RD2dPnY3qn/GMnO95RIadNmhRANCAARsr5nCopK1zDCQeeJIOTdI1+lvXOI2"
        + "6MCCkfapMFpxN9JN+8XObkqRgSSSNzBzxxUHq0I6NoXfePrhscq3iPqu"

    // Its SPKI public key — what the client must present as X-E2E-Public-Key.
    private static let expectedSpki =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbK+ZwqKStcwwkHniSDk3SNfpb1ziNujAgpH2qTBacTfSTfvFzm5KkYEkkjcwc8cVB6tCOjaF33j64bHKt4j6rg=="

    // Construction only; no request is made.
    private static let apiKey = "bax-00000000000000000000000000000000-00"

    override func tearDown() {
        unsetenv(Self.variable)
        super.tearDown()
    }

    private func options(withEnvironmentValue value: String?) -> BellaClientOptions {
        if let value { setenv(Self.variable, value, 1) } else { unsetenv(Self.variable) }
        return BellaClientOptions(apiKey: Self.apiKey)
    }

    private func assertLoadsTheDeviceKey(_ value: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let opts = options(withEnvironmentValue: value)
        XCTAssertNil(opts.privateKeyError, file: file, line: line)
        XCTAssertEqual(
            opts.privateKey?.publicKey.derRepresentation.base64EncodedString(), Self.expectedSpki,
            file: file, line: line)
        XCTAssertNoThrow(try BellaClient(opts), file: file, line: line)
    }

    func testLoadsThePemBellaSdkRunInjects() throws {
        try assertLoadsTheDeviceKey(Self.pem)
    }

    func testLoadsAPemWithCrlfLineEndings() throws {
        try assertLoadsTheDeviceKey(Self.pem.replacingOccurrences(of: "\n", with: "\r\n"))
    }

    func testLoadsBareBase64Der() throws {
        try assertLoadsTheDeviceKey(Self.base64Der)
    }

    func testAPresentButUnreadableKeyFailsLoudly() {
        for garbage in [
            "not a key",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            "aGVsbG8gd29ybGQ=",  // valid base64, not a key
        ] {
            let opts = options(withEnvironmentValue: garbage)
            XCTAssertNil(opts.privateKey, garbage)
            XCTAssertThrowsError(try BellaClient(opts), garbage) { error in
                guard case BellaError.invalidKey(let detail) = error else {
                    return XCTFail("expected BellaError.invalidKey, got \(error)")
                }
                XCTAssertTrue(detail.contains(Self.variable), detail)
            }
        }
    }

    func testAbsentOrBlankMeansEphemeral() {
        for absent in [nil, "", "  \n"] as [String?] {
            let opts = options(withEnvironmentValue: absent)
            XCTAssertNil(opts.privateKey)
            XCTAssertNil(opts.privateKeyError)
            XCTAssertNoThrow(try BellaClient(opts))
        }
    }

    func testAnExplicitKeyWinsOverTheEnvironment() throws {
        setenv(Self.variable, "not a key", 1)
        let key = try BellaClient.loadPrivateKey(pkcs8Pem: Self.pem)
        let opts = BellaClientOptions(apiKey: Self.apiKey, privateKey: key)
        XCTAssertNil(opts.privateKeyError)
        XCTAssertNoThrow(try BellaClient(opts))
    }
}
