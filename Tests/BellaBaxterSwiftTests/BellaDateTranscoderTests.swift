import Foundation
import OpenAPIRuntime
import XCTest
@testable import BellaBaxterSwift

/// #993 — the transcoder the generated client is configured with. The end-to-end proof is
/// `DateDecodingTests`; these pin the parsing rule and the unchanged encoding.
final class BellaDateTranscoderTests: XCTestCase {

    func test_decodes_every_form_the_api_emits_to_the_same_instant() throws {
        let transcoder = BellaDateTranscoder()
        let whole: TimeInterval = 1_790_504_130 // 2026-09-27T10:15:30Z
        let cases: [(String, TimeInterval)] = [
            ("2026-09-27T10:15:30+00:00", whole),              // E2EE path, whole second
            ("2026-09-27T10:15:30Z", whole),
            ("2026-09-27T10:15:30.000Z", whole),               // plain path, whole second
            ("2026-09-27T10:15:30.123Z", whole + 0.123),       // plain path
            ("2026-09-27T10:15:30.1234568+00:00", whole + 0.123), // E2EE path / "O" format
            ("2026-09-27T12:15:30.5+02:00", whole + 0.5),      // non-UTC offset
        ]
        for (string, expected) in cases {
            XCTAssertEqual(try transcoder.decode(string).timeIntervalSince1970, expected, accuracy: 0.001, string)
        }
    }

    func test_still_rejects_what_is_not_iso8601() {
        XCTAssertThrowsError(try BellaDateTranscoder().decode("27/09/2026 10:15"))
        XCTAssertThrowsError(try BellaDateTranscoder().decode(""))
    }

    func test_encoding_is_unchanged_whole_second_iso8601() throws {
        let date = Date(timeIntervalSince1970: 1_790_504_130.75)
        XCTAssertEqual(try BellaDateTranscoder().encode(date), "2026-09-27T10:15:30Z")
        XCTAssertEqual(try BellaDateTranscoder().encode(date), try ISO8601DateTranscoder.iso8601.encode(date))
    }

    func test_the_sdk_configuration_uses_it() throws {
        XCTAssertTrue(Configuration.bella.dateTranscoder is BellaDateTranscoder)
    }
}
