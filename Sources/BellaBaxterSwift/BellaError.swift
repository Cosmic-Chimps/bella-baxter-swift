import Foundation

/// Errors thrown by ``BellaClient``.
public enum BellaError: Error, LocalizedError, Sendable {
    case unauthorized
    case notFound(String)
    case serverError(Int, String)
    case unexpectedResponse(String)

    public var errorDescription: String? {
        switch self {
        case .unauthorized:
            return "Unauthorized: check your API key."
        case .notFound(let resource):
            return "Not found: \(resource)"
        case .serverError(let code, let message):
            return "Server error \(code): \(message)"
        case .unexpectedResponse(let detail):
            return "Unexpected response: \(detail)"
        }
    }
}
