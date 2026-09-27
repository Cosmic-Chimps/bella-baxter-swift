import Foundation
import OpenAPIRuntime

/// Decodes every ISO 8601 date-time the Bella API sends, with or without fractional seconds (#993).
///
/// The API serializes `DateTimeOffset` two ways, and both carry fractions:
/// - encrypted (E2EE) responses — which this SDK always receives — use `JsonSerializerOptions.Web`:
///   `2026-09-27T07:35:49.634244+00:00`, 0–7 fractional digits, dropped on a whole second;
/// - plain responses use the API's `DateTimeOffsetJsonConverter`: `2026-09-27T07:35:49.634Z`, always
///   three digits.
///
/// swift-openapi-runtime's default `.iso8601` transcoder rejects any fraction and
/// `.iso8601WithFractionalSeconds` rejects its absence, so neither alone can read this API. This
/// tries the fractional form first and falls back to the whole-second form. Sub-millisecond digits
/// are truncated (Foundation's `ISO8601DateFormatter` resolution).
///
/// Encoding is unchanged from the runtime default (whole-second `…Z`), so requests are byte-for-byte
/// what they were; the API parses either form.
///
/// Built on the runtime's own lock-protected `ISO8601DateTranscoder` rather than
/// `Date.ISO8601FormatStyle`, whose parsing leniency differs across the OS versions this package
/// supports (macOS 14 / iOS 17 and later).
struct BellaDateTranscoder: DateTranscoder {
    private let fractional = ISO8601DateTranscoder(options: [.withInternetDateTime, .withFractionalSeconds])
    private let wholeSeconds = ISO8601DateTranscoder()

    func encode(_ date: Date) throws -> String {
        try wholeSeconds.encode(date)
    }

    func decode(_ dateString: String) throws -> Date {
        if let date = try? fractional.decode(dateString) { return date }
        return try wholeSeconds.decode(dateString)
    }
}

extension Configuration {
    /// The configuration every generated `Client` in this SDK is built with. One place, so a second
    /// construction site cannot silently fall back to the runtime's fraction-rejecting default.
    static let bella = Configuration(dateTranscoder: BellaDateTranscoder())
}
