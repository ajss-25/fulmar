import Foundation

enum OllamaRuntimeAvailability: String, Codable, Sendable {
    case notInstalled
    case untrusted
    case installedOffline
    case online

    var displayName: String {
        switch self {
        case .notInstalled: return "Not installed"
        case .untrusted: return "Installed · not trusted"
        case .installedOffline: return "Installed · not running"
        case .online: return "Online"
        }
    }
}

enum OllamaProbeIssue: String, Codable, Sendable {
    case untrustedInstallation
    case endpointUnreachable
    case invalidHTTPResponse
    case malformedPayload

    var displayMessage: String {
        switch self {
        case .untrustedInstallation: return "The installed Ollama signature, owner, path, or file identity is not trusted."
        case .endpointUnreachable: return "The local Ollama service did not answer."
        case .invalidHTTPResponse: return "Ollama returned an unexpected local response."
        case .malformedPayload: return "Ollama returned data this app could not read."
        }
    }
}

struct OllamaInstalledModelSnapshot: Codable, Equatable, Sendable {
    let name: String
    let sizeBytes: Int64
}

struct OllamaRunningModelSnapshot: Codable, Equatable, Sendable {
    let name: String
    let sizeBytes: Int64
    let sizeVRAMBytes: Int64
    let contextLength: Int
}

struct OllamaRuntimeSnapshot: Codable, Equatable, Sendable {
    let capturedAt: Date
    let availability: OllamaRuntimeAvailability
    let executablePath: String?
    let installedModels: [OllamaInstalledModelSnapshot]
    let runningModels: [OllamaRunningModelSnapshot]
    let issue: OllamaProbeIssue?

    static func unavailable(at date: Date = Date()) -> OllamaRuntimeSnapshot {
        OllamaRuntimeSnapshot(
            capturedAt: date,
            availability: .notInstalled,
            executablePath: nil,
            installedModels: [],
            runningModels: [],
            issue: nil
        )
    }
}

protocol OllamaRuntimeSnapshotProviding {
    func capture(at date: Date) async -> OllamaRuntimeSnapshot
}

struct OllamaInstallationSnapshot: Equatable, Sendable {
    let executableURL: URL?
    let issue: OllamaProbeIssue?
}

protocol OllamaInstallationLocating {
    func locateInstallation() -> OllamaInstallationSnapshot
}

struct SystemOllamaInstallationLocator: OllamaInstallationLocating {
    func locateInstallation() -> OllamaInstallationSnapshot {
        do {
            return OllamaInstallationSnapshot(
                executableURL: try OllamaExecutableTrust.resolve().executableURL,
                issue: nil
            )
        } catch OllamaRuntimeSecurityError.executableNotFound {
            return OllamaInstallationSnapshot(executableURL: nil, issue: nil)
        } catch {
            return OllamaInstallationSnapshot(executableURL: nil, issue: .untrustedInstallation)
        }
    }
}

/// Performance diagnostics for an app-owned runtime reuse the exact identity
/// that was attested at launch. They never resolve a second executable merely
/// because another installation path appeared later.
struct AppOwnedOllamaInstallationLocator: OllamaInstallationLocating {
    let identity: OllamaExecutableIdentity

    func locateInstallation() -> OllamaInstallationSnapshot {
        do {
            try OllamaExecutableTrust.revalidate(identity)
            return OllamaInstallationSnapshot(executableURL: identity.executableURL, issue: nil)
        } catch {
            return OllamaInstallationSnapshot(executableURL: nil, issue: .untrustedInstallation)
        }
    }
}

protocol LoopbackHTTPTransport {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

final class URLSessionLoopbackTransport: LoopbackHTTPTransport {
    private let timeout: TimeInterval
    private let maximumBytes: Int

    init(timeout: TimeInterval = 2, maximumBytes: Int = 5 * 1_024 * 1_024) {
        self.timeout = max(0.25, min(timeout, 10))
        self.maximumBytes = max(1, min(maximumBytes, 5 * 1_024 * 1_024))
    }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            BoundedOllamaHTTPTask(
                request: request,
                maximumBytes: maximumBytes,
                timeout: timeout
            ) { result in
                continuation.resume(with: result.map { ($0.data, $0.response) })
            }.start()
        }
    }
}

enum OllamaRuntimeInspectorError: Error, Equatable, LocalizedError {
    case endpointMustBeLoopbackHTTP

    var errorDescription: String? {
        switch self {
        case .endpointMustBeLoopbackHTTP:
            return "The Ollama inspector only accepts an HTTP endpoint on this Mac."
        }
    }
}

/// Explicit, read-only Ollama probe. Constructing the inspector performs no I/O;
/// callers decide when capture() may issue the two loopback GET requests.
final class OllamaRuntimeInspector: OllamaRuntimeSnapshotProviding {
    private let endpoint: URL
    private let transport: any LoopbackHTTPTransport
    private let locator: any OllamaInstallationLocating
    private let decoder = JSONDecoder()

    init(
        endpoint: URL,
        transport: any LoopbackHTTPTransport = URLSessionLoopbackTransport(),
        locator: any OllamaInstallationLocating = SystemOllamaInstallationLocator()
    ) throws {
        guard Self.isAllowedBaseEndpoint(endpoint) else {
            throw OllamaRuntimeInspectorError.endpointMustBeLoopbackHTTP
        }
        self.endpoint = endpoint
        self.transport = transport
        self.locator = locator
    }

    func capture(at date: Date = Date()) async -> OllamaRuntimeSnapshot {
        let installation = locator.locateInstallation()
        let executable = installation.executableURL
        let tags = await fetch(path: "api/tags", as: TagsResponse.self)
        let running = await fetch(path: "api/ps", as: RunningResponse.self)

        let installedModels: [OllamaInstalledModelSnapshot]
        let runningModels: [OllamaRunningModelSnapshot]
        var issues: [OllamaProbeIssue] = []

        switch tags {
        case .success(let response):
            installedModels = Self.normalizedInstalled(response.models)
        case .failure(let issue):
            installedModels = []
            issues.append(issue)
        }
        switch running {
        case .success(let response):
            runningModels = Self.normalizedRunning(response.models)
        case .failure(let issue):
            runningModels = []
            issues.append(issue)
        }

        let responded = tags.isSuccess || running.isSuccess
        let availability: OllamaRuntimeAvailability
        if responded {
            availability = .online
        } else if installation.issue == .untrustedInstallation {
            availability = .untrusted
        } else if executable != nil {
            availability = .installedOffline
        } else {
            availability = .notInstalled
        }

        return OllamaRuntimeSnapshot(
            capturedAt: date,
            availability: availability,
            executablePath: executable?.path,
            installedModels: installedModels,
            runningModels: runningModels,
            issue: installation.issue ?? issues.first
        )
    }

    private func fetch<Value: Decodable>(path: String, as type: Value.Type) async -> ProbeResult<Value> {
        guard let url = URL(string: path, relativeTo: endpoint)?.absoluteURL,
              Self.isAllowed(endpoint: url) else {
            return .failure(.endpointUnreachable)
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await transport.data(for: request)
            guard response.statusCode == 200, data.count <= 5 * 1_024 * 1_024 else {
                return .failure(.invalidHTTPResponse)
            }
            do {
                return .success(try decoder.decode(type, from: data))
            } catch {
                return .failure(.malformedPayload)
            }
        } catch {
            return .failure(.endpointUnreachable)
        }
    }

    private static func isAllowed(endpoint: URL) -> Bool {
        OllamaLoopbackEndpointPolicy.isAllowed(endpoint)
    }

    private static func isAllowedBaseEndpoint(_ endpoint: URL) -> Bool {
        OllamaLoopbackEndpointPolicy.isAllowedBase(endpoint)
    }

    private static func normalizedInstalled(_ models: [TagsResponse.Model]) -> [OllamaInstalledModelSnapshot] {
        var byName: [String: OllamaInstalledModelSnapshot] = [:]
        for model in models.prefix(1_000) {
            let name = model.name
            guard OllamaModelNamePolicy.isSafe(name) else { continue }
            byName[name] = OllamaInstalledModelSnapshot(name: name, sizeBytes: max(0, model.size))
        }
        return byName.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private static func normalizedRunning(_ models: [RunningResponse.Model]) -> [OllamaRunningModelSnapshot] {
        var byName: [String: OllamaRunningModelSnapshot] = [:]
        for model in models.prefix(1_000) {
            let name = model.name
            guard OllamaModelNamePolicy.isSafe(name) else { continue }
            byName[name] = OllamaRunningModelSnapshot(
                name: name,
                sizeBytes: max(0, model.size),
                sizeVRAMBytes: max(0, model.sizeVRAM),
                contextLength: max(0, model.contextLength)
            )
        }
        return byName.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private enum ProbeResult<Value> {
        case success(Value)
        case failure(OllamaProbeIssue)

        var isSuccess: Bool {
            if case .success = self { return true }
            return false
        }
    }

    private struct TagsResponse: Decodable {
        struct Model: Decodable {
            let name: String
            let size: Int64
        }
        let models: [Model]
    }

    private struct RunningResponse: Decodable {
        struct Model: Decodable {
            let name: String
            let size: Int64
            let sizeVRAM: Int64
            let contextLength: Int

            enum CodingKeys: String, CodingKey {
                case name
                case size
                case sizeVRAM = "size_vram"
                case contextLength = "context_length"
            }
        }
        let models: [Model]
    }
}
