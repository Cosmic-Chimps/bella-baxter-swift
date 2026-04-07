import CryptoKit
import Foundation
import HTTPTypes
import OpenAPIRuntime
import OpenAPIURLSession

// MARK: - HMAC Auth Middleware

/// Signs every outgoing request with HMAC-SHA256 using the Bella API key.
///
/// Adds three signing headers per request:
///   - `X-Bella-Key-Id`:    the 32-hex key identifier (middle segment of the bax-... token)
///   - `X-Bella-Timestamp`: ISO-8601 UTC timestamp (replay window: ±5 minutes)
///   - `X-Bella-Signature`: HEX(HMAC-SHA256(signingSecret, StringToSign))
///
/// StringToSign = "METHOD\n/path\nsorted_query\ntimestamp\nhex(sha256(body))"
struct HmacAuthMiddleware: ClientMiddleware {
    let keyId: String
    let signingKey: SymmetricKey

    init(apiKey: String) throws {
        let parts = apiKey.split(separator: "-", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[0] == "bax",
              let secretData = Data(hexString: parts[2]) else {
            throw BellaError.unexpectedResponse("Expected API key format: bax-{keyId}-{signingSecret}")
        }
        self.keyId = parts[1]
        self.signingKey = SymmetricKey(data: secretData)
    }

    func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: @Sendable (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        var modified = request

        // Buffer body so we can both hash it and pass it on
        var bodyData = Data()
        var passthroughBody: HTTPBody?
        if let body {
            var bytes = [UInt8]()
            for try await chunk in body { bytes.append(contentsOf: chunk) }
            bodyData = Data(bytes)
            passthroughBody = bodyData.isEmpty ? nil : HTTPBody(bodyData)
        }

        let timestamp = bellaTimestamp()
        let (pathOnly, queryString) = splitPath(modified.path ?? "/")
        let method = modified.method.rawValue.uppercased()
        let bodyHash = SHA256.hash(data: bodyData).hexEncodedString()
        let stringToSign = "\(method)\n\(pathOnly)\n\(queryString)\n\(timestamp)\n\(bodyHash)"
        let sig = HMAC<SHA256>.authenticationCode(for: Data(stringToSign.utf8), using: signingKey)
            .hexEncodedString()

        modified.headerFields[.init("X-Bella-Key-Id")!]    = keyId
        modified.headerFields[.init("X-Bella-Timestamp")!] = timestamp
        modified.headerFields[.init("X-Bella-Signature")!] = sig
        modified.headerFields[.init("X-Bella-Client")!]    = "bella-swift-sdk"
        modified.headerFields[.init("User-Agent")!]        = "bella-swift-sdk/1.0"
        return try await next(modified, passthroughBody, baseURL)
    }
}

// MARK: - URLRequest HMAC helper

extension URLRequest {
    /// Adds HMAC-SHA256 signing headers to a plain URLRequest.
    mutating func addBellaHmacHeaders(keyId: String, signingKey: SymmetricKey, body: Data = Data()) {
        let timestamp = bellaTimestamp()
        let url = self.url!
        let pathOnly = url.path
        let rawQuery = url.query ?? ""
        let queryString = sortedQueryString(rawQuery)
        let method = (self.httpMethod ?? "GET").uppercased()
        let bodyHash = SHA256.hash(data: body).hexEncodedString()
        let stringToSign = "\(method)\n\(pathOnly)\n\(queryString)\n\(timestamp)\n\(bodyHash)"
        let sig = HMAC<SHA256>.authenticationCode(for: Data(stringToSign.utf8), using: signingKey)
            .hexEncodedString()

        setValue(keyId,    forHTTPHeaderField: "X-Bella-Key-Id")
        setValue(timestamp, forHTTPHeaderField: "X-Bella-Timestamp")
        setValue(sig,       forHTTPHeaderField: "X-Bella-Signature")
        setValue("bella-swift-sdk", forHTTPHeaderField: "X-Bella-Client")
        setValue("bella-swift-sdk/1.0", forHTTPHeaderField: "User-Agent")
    }
}

// MARK: - Shared helpers

private func bellaTimestamp() -> String {
    let fmt = ISO8601DateFormatter()
    fmt.formatOptions = [.withInternetDateTime]
    return fmt.string(from: Date())
}

private func splitPath(_ pathWithQuery: String) -> (path: String, query: String) {
    guard let qIdx = pathWithQuery.firstIndex(of: "?") else {
        return (pathWithQuery, "")
    }
    let path  = String(pathWithQuery[..<qIdx])
    let query = sortedQueryString(String(pathWithQuery[pathWithQuery.index(after: qIdx)...]))
    return (path, query)
}

private func sortedQueryString(_ raw: String) -> String {
    guard !raw.isEmpty else { return "" }
    return raw.split(separator: "&").map(String.init).sorted().joined(separator: "&")
}

extension Sequence where Element == UInt8 {
    func hexEncodedString() -> String { map { String(format: "%02x", $0) }.joined() }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var idx = hexString.startIndex
        while idx < hexString.endIndex {
            let end = hexString.index(idx, offsetBy: 2)
            guard let byte = UInt8(hexString[idx..<end], radix: 16) else { return nil }
            data.append(byte)
            idx = end
        }
        self = data
    }
}

// MARK: - KeyContext

public struct KeyContext: Sendable {
    public let keyId: String
    public let role: String
    public let projectSlug: String
    public let environmentSlug: String
    public let projectName: String
    public let environmentName: String
}

// MARK: - BellaClient

/// High-level Bella Baxter client built on top of the generated ``Client``.
///
/// ```swift
/// let bella = try BellaClient(
///     BellaClientOptions(
///         baseURL: URL(string: "https://api.example.com")!,
///         apiKey: "bax-..."
///     )
/// )
///
/// // Project + environment are auto-discovered from the API key:
/// let secrets = try await bella.pullSecrets()
/// print(secrets["DATABASE_URL"] ?? "")
/// ```
public final class BellaClient: @unchecked Sendable {

    private let generated: Client
    private let options: BellaClientOptions
    private let urlSession: URLSession
    private let hmacMiddleware: HmacAuthMiddleware
    private var _keyContext: KeyContext?

    // MARK: Init

    public init(_ options: BellaClientOptions) throws {
        self.options = options
        let session = URLSession(configuration: {
            let cfg = URLSessionConfiguration.default
            cfg.timeoutIntervalForRequest = options.timeoutSeconds
            cfg.timeoutIntervalForResource = options.timeoutSeconds * 3
            return cfg
        }())
        self.urlSession = session
        let transport = URLSessionTransport(configuration: .init(session: session))
        let auth  = try HmacAuthMiddleware(apiKey: options.apiKey)
        let e2ee: E2EEncryptionMiddleware
        if let key = options.privateKey {
            e2ee = E2EEncryptionMiddleware(
                privateKey: key,
                onWrappedDekReceived: options.onWrappedDekReceived
            )
        } else {
            e2ee = E2EEncryptionMiddleware()
        }
        self.hmacMiddleware = auth
        self.generated = Client(
            serverURL: options.baseURL,
            transport: transport,
            middlewares: [auth, e2ee]
        )
    }

    // MARK: - Key Context

    /// Calls GET /api/v1/keys/me to discover which project + environment this
    /// API key is scoped to. Result is cached for the lifetime of this client.
    public func getKeyContext() async throws -> KeyContext {
        if let ctx = _keyContext { return ctx }

        var req = URLRequest(url: options.baseURL.appendingPathComponent("api/v1/keys/me"))
        req.addBellaHmacHeaders(keyId: hmacMiddleware.keyId, signingKey: hmacMiddleware.signingKey)
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await urlSession.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw BellaError.serverError(
                (response as? HTTPURLResponse)?.statusCode ?? 0,
                "getKeyContext failed"
            )
        }

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        let ctx = KeyContext(
            keyId: json["keyId"] as? String ?? "",
            role: json["role"] as? String ?? "",
            projectSlug: json["projectSlug"] as? String ?? "",
            environmentSlug: json["environmentSlug"] as? String ?? "",
            projectName: json["projectName"] as? String ?? "",
            environmentName: json["environmentName"] as? String ?? ""
        )
        _keyContext = ctx
        return ctx
    }

    // MARK: - Projects

    public func listProjects(
        page: Int = 0,
        size: Int = 50
    ) async throws -> [Components.Schemas.ProjectResponse] {
        let response = try await generated.getAllProjects(.init(query: .init(page: Int32(page), size: Int32(size))))
        switch response {
        case .ok(let ok):
            switch ok.body {
            case .json(let body):
                return body.content ?? []
            }
        case .notFound:
            return []
        case .undocumented(let statusCode, _):
            throw BellaError.serverError(statusCode, "getAllProjects failed")
        }
    }

    public func getProject(ref: String) async throws -> Components.Schemas.GetProjectResponse {
        let response = try await generated.getProjectById(.init(path: .init(projectRef: ref)))
        switch response {
        case .ok(let ok):
            switch ok.body {
            case .json(let body):
                return body
            }
        case .notFound:
            throw BellaError.notFound("project '\(ref)'")
        case .undocumented(let statusCode, _):
            throw BellaError.serverError(statusCode, "getProjectById failed")
        }
    }

    // MARK: - Environments

    public func listEnvironments(projectRef: String) async throws -> [Components.Schemas.EnvironmentResponse] {
        let response = try await generated.getEnvironmentsByProject(
            .init(path: .init(projectRef: projectRef))
        )
        switch response {
        case .ok(let ok):
            switch ok.body {
            case .json(let body):
                return body
            }
        case .notFound:
            throw BellaError.notFound("project '\(projectRef)'")
        case .undocumented(let statusCode, _):
            throw BellaError.serverError(statusCode, "getEnvironmentsByProject failed")
        }
    }

    // MARK: - Secrets

    /// Returns all secrets for an environment across all assigned providers.
    ///
    /// Project and environment are auto-discovered from the API key if not provided.
    /// The response is transparently E2EE-decrypted by `E2EEncryptionMiddleware`.
    public func pullSecrets(
        projectRef: String? = nil,
        environmentSlug: String? = nil
    ) async throws -> [String: String] {
        // Return from cache if available.
        if let cached = try await options.cache?.read() {
            return cached
        }

        let ctx = try await getKeyContext()
        let resolvedProject = projectRef ?? ctx.projectSlug
        let resolvedEnv = environmentSlug ?? ctx.environmentSlug

        let response = try await generated.getAllEnvironmentSecrets(
            .init(path: .init(projectRef: resolvedProject, envSlug: resolvedEnv))
        )
        switch response {
        case .ok(let ok):
            switch ok.body {
            case .json(let body):
                let secrets = body.secrets.additionalProperties
                try await options.cache?.write(secrets)
                return secrets
            }
        case .notFound:
            throw BellaError.notFound("environment '\(resolvedProject)/\(resolvedEnv)'")
        case .undocumented(let statusCode, _):
            throw BellaError.serverError(statusCode, "getAllEnvironmentSecrets failed")
        }
    }

    /// Downloads the `.env`-formatted secrets for a specific provider.
    ///
    /// Uses a raw URLSession request because the generated export endpoint returns a
    /// plain-text body that the OpenAPI client cannot easily deserialize.
    public func exportSecretsAsEnv(
        projectRef: String,
        environmentSlug: String,
        providerSlug: String
    ) async throws -> String {
        let path = "api/v1/projects/\(projectRef)/environments/\(environmentSlug)/providers/\(providerSlug)/secrets/export"
        var req = URLRequest(url: options.baseURL.appendingPathComponent(path))
        req.addBellaHmacHeaders(keyId: hmacMiddleware.keyId, signingKey: hmacMiddleware.signingKey)
        req.setValue("text/plain, application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await urlSession.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            if code == 404 {
                throw BellaError.notFound("provider '\(providerSlug)' in '\(projectRef)/\(environmentSlug)'")
            }
            throw BellaError.serverError(code, "exportSecrets failed")
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Pulls secrets and injects them into the current process environment.
    @MainActor
    public func injectIntoEnvironment(
        projectRef: String? = nil,
        environmentSlug: String? = nil
    ) async throws {
        let secrets = try await pullSecrets(projectRef: projectRef, environmentSlug: environmentSlug)
        for (key, value) in secrets {
            if ProcessInfo.processInfo.environment[key] == nil {
                setenv(key, value, 0)
            }
        }
    }

    // MARK: - ZKE Key Loading

    /// Loads a P-256 private key from PKCS#8 DER bytes.
    ///
    /// Use this to create the `privateKey` option for ZKE mode, e.g. when reading from the
    /// iOS Keychain or from a DER file produced by `openssl genpkey`.
    ///
    /// ```swift
    /// let key = try BellaClient.loadPrivateKey(pkcs8Der: derData)
    /// let options = BellaClientOptions(apiKey: "bax-...", privateKey: key)
    /// ```
    public static func loadPrivateKey(pkcs8Der: Data) throws -> P256.KeyAgreement.PrivateKey {
        return try P256.KeyAgreement.PrivateKey(derRepresentation: pkcs8Der)
    }

    /// Loads a P-256 private key from a PKCS#8 PEM string.
    ///
    /// ```swift
    /// let pem = """
    /// -----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
    /// -----END PRIVATE KEY-----
    /// """
    /// let key = try BellaClient.loadPrivateKey(pkcs8Pem: pem)
    /// ```
    public static func loadPrivateKey(pkcs8Pem: String) throws -> P256.KeyAgreement.PrivateKey {
        let b64 = pkcs8Pem
            .components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
            .joined()
        guard let der = Data(base64Encoded: b64) else {
            throw BellaError.invalidKey("Could not decode PEM base64")
        }
        return try P256.KeyAgreement.PrivateKey(derRepresentation: der)
    }
}
