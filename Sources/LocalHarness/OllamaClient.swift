import Foundation

struct OllamaModel: Codable, Equatable, Identifiable, Sendable {
    struct Details: Codable, Equatable, Sendable {
        let parameterSize: String?
        let quantizationLevel: String?

        enum CodingKeys: String, CodingKey {
            case parameterSize = "parameter_size"
            case quantizationLevel = "quantization_level"
        }
    }

    let name: String
    let digest: String?
    let size: Int64
    let modifiedAt: String?
    let details: Details?
    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, digest, size, details
        case modifiedAt = "modified_at"
    }
}

struct OllamaRunningModel: Codable, Equatable, Identifiable, Sendable {
    let name: String
    let size: Int64
    let sizeVRAM: Int64
    let expiresAt: String?
    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, size
        case sizeVRAM = "size_vram"
        case expiresAt = "expires_at"
    }
}

struct LocalChatMessage: Codable, Equatable {
    let role: String
    let content: String
}

enum OllamaModelCompatibility: Equatable, Sendable {
    case compatible(contextLength: Int, supportsThinking: Bool)
    case incompatible(OllamaModelCompatibilityIssue)
}

enum OllamaModelCompatibilityIssue: Equatable, Sendable {
    case toolsUnavailable
    case thinkingRequiresExplicitSupport(contextLength: Int)
    case contextTooSmall(actual: Int, minimum: Int)
    case contextTooLarge(actual: Int, maximum: Int)
}

enum OllamaModelInspectionError: Error, Equatable, LocalizedError {
    case invalidModelName
    case malformedResponse
    case invalidCapabilities
    case missingArchitecture
    case invalidArchitecture
    case missingContextLength

    var errorDescription: String? {
        switch self {
        case .invalidModelName: return "The requested Ollama model name is unsafe."
        case .malformedResponse: return "Ollama returned malformed model metadata."
        case .invalidCapabilities: return "Ollama returned missing, duplicate, or unsupported capability metadata."
        case .missingArchitecture: return "Ollama did not report one model architecture."
        case .invalidArchitecture: return "Ollama reported an unsafe model architecture identifier."
        case .missingContextLength: return "Ollama did not report one valid architecture context length."
        }
    }
}

final class OllamaClient {
    private struct ModelList: Decodable { let models: [OllamaModel] }
    private struct RunningList: Decodable { let models: [OllamaRunningModel] }

    private let baseURLProvider: () -> URL?
    private let lock = NSLock()
    private var streams: [UUID: OllamaChatStream] = [:]

    init(baseURLProvider: @escaping () -> URL?) {
        self.baseURLProvider = baseURLProvider
    }

    func fetchCompatibleVersion(
        completion: @escaping (Result<OllamaStableVersion, Error>) -> Void
    ) {
        get(path: "api/version", maximumBytes: OllamaVersionCompatibilityPolicy.maximumResponseBytes) {
            result in
            switch result {
            case .success(let data):
                completion(Result { try OllamaVersionCompatibilityPolicy.parseResponse(data) })
            case .failure:
                // The listener/PID boundary is proved by the owner. Do not
                // expose transport internals; turn a missing, redirected,
                // oversized, or non-successful official endpoint into one
                // actionable runtime-upgrade/reinstall result.
                completion(.failure(OllamaVersionCompatibilityError.unavailable))
            }
        }
    }

    func fetchCompatibleVersion() async throws -> OllamaStableVersion {
        try await withCheckedThrowingContinuation { continuation in
            fetchCompatibleVersion { continuation.resume(with: $0) }
        }
    }

    func fetchModels(completion: @escaping (Result<[OllamaModel], Error>) -> Void) {
        decode(path: "api/tags", as: ModelList.self) { result in
            completion(result.map { Self.normalizedModels($0.models) })
        }
    }

    func fetchModels() async throws -> [OllamaModel] {
        try await withCheckedThrowingContinuation { continuation in
            fetchModels { continuation.resume(with: $0) }
        }
    }

    func fetchRunningModels(completion: @escaping (Result<[OllamaRunningModel], Error>) -> Void) {
        decode(path: "api/ps", as: RunningList.self) { result in
            completion(result.map { Self.normalizedRunningModels($0.models) })
        }
    }

    /// Reads bounded metadata only from the already-verified app-owned Ollama
    /// listener. This assessment is advisory: callers must still preserve the
    /// existing fail-closed selection and topology transaction.
    func inspectModelCompatibility(model: String) async throws -> OllamaModelCompatibility {
        guard OllamaModelNamePolicy.isSafe(model) else {
            throw OllamaModelInspectionError.invalidModelName
        }
        let data = try await withCheckedThrowingContinuation { continuation in
            post(path: "api/show", json: ["model": model, "verbose": false]) {
                continuation.resume(with: $0)
            }
        }
        return try Self.assessModelShowResponse(data, requestedModel: model)
    }

    static func assessModelShowResponse(
        _ data: Data,
        requestedModel: String
    ) throws -> OllamaModelCompatibility {
        guard OllamaModelNamePolicy.isSafe(requestedModel) else {
            throw OllamaModelInspectionError.invalidModelName
        }
        guard data.count <= 1 * 1_024 * 1_024,
              let value = try? JSONSerialization.jsonObject(with: data, options: []),
              let root = value as? [String: Any],
              let rawCapabilities = root["capabilities"] as? [Any],
              !rawCapabilities.isEmpty,
              rawCapabilities.count <= 16,
              let modelInfo = root["model_info"] as? [String: Any] else {
            throw OllamaModelInspectionError.malformedResponse
        }

        let allowedCapabilities: Set<String> = [
            "completion", "tools", "thinking", "vision", "embedding", "insert"
        ]
        var capabilities = Set<String>()
        for raw in rawCapabilities {
            guard let capability = raw as? String,
                  capability.range(of: #"^[a-z][a-z0-9_-]{0,63}$"#, options: .regularExpression) != nil,
                  allowedCapabilities.contains(capability),
                  capabilities.insert(capability).inserted else {
                throw OllamaModelInspectionError.invalidCapabilities
            }
        }
        guard capabilities.contains("completion") else {
            throw OllamaModelInspectionError.invalidCapabilities
        }

        guard let architecture = modelInfo["general.architecture"] as? String else {
            throw OllamaModelInspectionError.missingArchitecture
        }
        guard architecture.range(
            of: #"^[a-z0-9][a-z0-9_-]{0,63}$"#,
            options: .regularExpression
        ) != nil else {
            throw OllamaModelInspectionError.invalidArchitecture
        }
        let contextKey = "\(architecture).context_length"
        guard let rawContext = modelInfo[contextKey] as? NSNumber,
              CFGetTypeID(rawContext) != CFBooleanGetTypeID(),
              rawContext.doubleValue.isFinite,
              rawContext.doubleValue.rounded(.towardZero) == rawContext.doubleValue,
              rawContext.int64Value > 0,
              rawContext.int64Value <= Int64(Int.max) else {
            throw OllamaModelInspectionError.missingContextLength
        }
        let contextLength = Int(rawContext.int64Value)
        let minimumContext = 8_192
        // High-context models are safe here because Fulmar still applies its
        // smaller selected cap. Reject only implausible metadata which could
        // otherwise overflow or mask a malformed response.
        let maximumContext = 1_048_576
        if contextLength < minimumContext {
            return .incompatible(.contextTooSmall(actual: contextLength, minimum: minimumContext))
        }
        if contextLength > maximumContext {
            return .incompatible(.contextTooLarge(actual: contextLength, maximum: maximumContext))
        }
        guard capabilities.contains("tools") else {
            return .incompatible(.toolsUnavailable)
        }
        if capabilities.contains("thinking") {
            return .incompatible(.thinkingRequiresExplicitSupport(contextLength: contextLength))
        }
        return .compatible(contextLength: contextLength, supportsThinking: false)
    }

    @discardableResult
    func chat(
        model: String,
        messages: [LocalChatMessage],
        think: Bool = false,
        performance: ModelPerformanceSettings = .balanced48GBAppleSilicon,
        onToken: @escaping (String) -> Void,
        completion: @escaping (Result<Void, Error>) -> Void
    ) -> UUID {
        let identifier = UUID()
        guard OllamaModelNamePolicy.isSafe(model) else {
            DispatchQueue.main.async { completion(.failure(OllamaError.invalidRequest)) }
            return identifier
        }
        guard let baseURL = resolvedBaseURL() else {
            DispatchQueue.main.async { completion(.failure(OllamaError.ownedEndpointUnavailable)) }
            return identifier
        }
        var request = URLRequest(url: baseURL.appendingPathComponent("api/chat"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let payload: [String: Any] = [
            "model": model,
            "messages": messages.map { ["role": $0.role, "content": $0.content] },
            "stream": true,
            "think": think,
            "keep_alive": performance.keepAliveSeconds,
            "options": [
                "num_ctx": performance.contextWindowTokens,
                "num_predict": performance.maxOutputTokens
            ]
        ]
        guard let body = try? JSONSerialization.data(withJSONObject: payload),
              body.count <= 16 * 1_024 * 1_024 else {
            DispatchQueue.main.async { completion(.failure(OllamaError.invalidRequest)) }
            return identifier
        }
        request.httpBody = body

        let stream = OllamaChatStream(request: request, onToken: onToken) { [weak self] result in
            self?.lock.lock()
            self?.streams.removeValue(forKey: identifier)
            self?.lock.unlock()
            DispatchQueue.main.async { completion(result) }
        }
        lock.lock()
        streams[identifier] = stream
        lock.unlock()
        stream.start()
        return identifier
    }

    func cancelChat(_ identifier: UUID) {
        lock.lock()
        let stream = streams.removeValue(forKey: identifier)
        lock.unlock()
        stream?.cancel()
    }

    func unload(model: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard OllamaModelNamePolicy.isSafe(model) else {
            DispatchQueue.main.async { completion(.failure(OllamaError.invalidRequest)) }
            return
        }
        post(path: "api/generate", json: ["model": model, "keep_alive": 0, "prompt": ""]) { result in
            completion(result.map { _ in () })
        }
    }

    func warm(
        model: String,
        performance: ModelPerformanceSettings = .balanced48GBAppleSilicon,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard OllamaModelNamePolicy.isSafe(model) else {
            DispatchQueue.main.async { completion(.failure(OllamaError.invalidRequest)) }
            return
        }
        post(path: "api/generate", json: [
            "model": model,
            "keep_alive": performance.keepAliveSeconds,
            "prompt": "",
            "stream": false,
            "options": ["num_ctx": performance.contextWindowTokens]
        ]) { result in
            completion(result.map { _ in () })
        }
    }

    func unloadAllRunning(completion: @escaping () -> Void) {
        fetchRunningModels { [weak self] result in
            guard let self, case .success(let models) = result, !models.isEmpty else { completion(); return }
            let group = DispatchGroup()
            for model in models {
                group.enter()
                self.unload(model: model.name) { _ in group.leave() }
            }
            group.notify(queue: .main, execute: completion)
        }
    }

    private func decode<T: Decodable>(path: String, as type: T.Type, completion: @escaping (Result<T, Error>) -> Void) {
        guard let baseURL = resolvedBaseURL() else {
            DispatchQueue.main.async { completion(.failure(OllamaError.ownedEndpointUnavailable)) }
            return
        }
        let request = URLRequest(url: baseURL.appendingPathComponent(path))
        BoundedOllamaHTTPTask(request: request, maximumBytes: 5 * 1_024 * 1_024) { result in
            let bounded = result.flatMap(Self.requireSuccess)
            let decoded = bounded.flatMap { data -> Result<T, Error> in
                do { return .success(try JSONDecoder().decode(T.self, from: data)) }
                catch { return .failure(error) }
            }
            DispatchQueue.main.async { completion(decoded) }
        }.start()
    }

    private func get(
        path: String,
        maximumBytes: Int,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        guard let baseURL = resolvedBaseURL() else {
            DispatchQueue.main.async { completion(.failure(OllamaError.ownedEndpointUnavailable)) }
            return
        }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        BoundedOllamaHTTPTask(request: request, maximumBytes: maximumBytes) { result in
            DispatchQueue.main.async { completion(result.flatMap(Self.requireSuccess)) }
        }.start()
    }

    private func post(path: String, json: [String: Any], completion: @escaping (Result<Data, Error>) -> Void) {
        guard let baseURL = resolvedBaseURL() else {
            DispatchQueue.main.async { completion(.failure(OllamaError.ownedEndpointUnavailable)) }
            return
        }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        guard let body = try? JSONSerialization.data(withJSONObject: json),
              body.count <= 16 * 1_024 * 1_024 else {
            DispatchQueue.main.async { completion(.failure(OllamaError.invalidRequest)) }
            return
        }
        request.httpBody = body
        BoundedOllamaHTTPTask(request: request, maximumBytes: 1 * 1_024 * 1_024) { result in
            DispatchQueue.main.async { completion(result.flatMap(Self.requireSuccess)) }
        }.start()
    }

    private static func requireSuccess(_ bounded: BoundedOllamaHTTPResponse) -> Result<Data, Error> {
        guard (200...299).contains(bounded.response.statusCode) else {
            return .failure(OllamaError.http(bounded.response.statusCode))
        }
        return .success(bounded.data)
    }

    private func resolvedBaseURL() -> URL? {
        guard let url = baseURLProvider(),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "http",
              components.host?.lowercased() == AppOwnedOllamaEndpoint.host,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/",
              let port = components.port,
              AppOwnedOllamaEndpoint(port: port) != nil else { return nil }
        return url
    }

    static func normalizedModels(_ models: [OllamaModel]) -> [OllamaModel] {
        // Preserve duplicate names. The qualified-model admission policy must be
        // able to distinguish one exact installed manifest from an ambiguous
        // or malformed catalogue; collapsing by name here would make that
        // fail-closed check unreachable on the real HTTP path.
        models.prefix(1_000)
            .filter { OllamaModelNamePolicy.isSafe($0.name) }
            .sorted {
                let nameOrder = $0.name.localizedStandardCompare($1.name)
                if nameOrder != .orderedSame { return nameOrder == .orderedAscending }
                if $0.digest != $1.digest { return ($0.digest ?? "") < ($1.digest ?? "") }
                return $0.size < $1.size
            }
    }

    private static func normalizedRunningModels(_ models: [OllamaRunningModel]) -> [OllamaRunningModel] {
        var values: [String: OllamaRunningModel] = [:]
        for model in models.prefix(1_000) where OllamaModelNamePolicy.isSafe(model.name) {
            values[model.name] = model
        }
        return values.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}

private final class OllamaChatStream: NSObject, URLSessionDataDelegate {
    private struct Chunk: Decodable {
        struct Message: Decodable { let content: String }
        let message: Message?
        let done: Bool?
        let error: String?
    }

    private let request: URLRequest
    private let onToken: (String) -> Void
    private let completion: (Result<Void, Error>) -> Void
    private var session: URLSession?
    private var buffer = Data()
    private var responseBudget = OllamaResponseBudget(maximumBytes: 4_194_304)
    private var completed = false

    init(request: URLRequest, onToken: @escaping (String) -> Void, completion: @escaping (Result<Void, Error>) -> Void) {
        self.request = request
        self.onToken = onToken
        self.completion = completion
    }

    func start() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 60 * 60
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        self.session = session
        session.dataTask(with: request).resume()
    }

    func cancel() {
        session?.invalidateAndCancel()
        finish(.failure(CancellationError()))
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse,
              response.url == request.url,
              request.url.map(OllamaLoopbackEndpointPolicy.isAllowed) == true else {
            finish(.failure(OllamaError.invalidResponse))
            completionHandler(.cancel)
            return
        }
        if !(200...299).contains(response.statusCode) {
            finish(.failure(OllamaError.http(response.statusCode)))
            completionHandler(.cancel)
        } else {
            do {
                responseBudget = try OllamaResponseBudget(
                    maximumBytes: 4_194_304,
                    expectedContentLength: response.expectedContentLength
                )
                completionHandler(.allow)
            } catch {
                finish(.failure(error))
                completionHandler(.cancel)
            }
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        finish(.failure(OllamaError.redirectDenied))
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard !completed else { return }
        do { try responseBudget.admit(data) }
        catch { finish(.failure(error)); return }
        buffer.append(data)
        guard buffer.count <= 4_194_304 else { finish(.failure(OllamaError.responseTooLarge)); return }
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer.prefix(upTo: newline)
            buffer.removeSubrange(...newline)
            guard !line.isEmpty else { continue }
            consume(line)
            if completed { return }
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error, (error as NSError).code != NSURLErrorCancelled { finish(.failure(error)) }
        else if !completed {
            if !buffer.isEmpty { consume(buffer[...]) }
            if !completed { finish(.failure(OllamaError.invalidResponse)) }
        }
    }

    private func consume(_ line: Data.SubSequence) {
        guard !completed, !line.isEmpty else { return }
        do {
            let chunk = try JSONDecoder().decode(Chunk.self, from: line)
            if let error = chunk.error {
                finish(.failure(OllamaError.server(error)))
                return
            }
            if let token = chunk.message?.content, !token.isEmpty {
                DispatchQueue.main.async { [onToken] in onToken(token) }
            }
            if chunk.done == true { finish(.success(())) }
        } catch {
            finish(.failure(error))
        }
    }

    private func finish(_ result: Result<Void, Error>) {
        guard !completed else { return }
        completed = true
        session?.finishTasksAndInvalidate()
        completion(result)
    }
}

enum OllamaError: LocalizedError, Equatable {
    case http(Int)
    case server(String)
    case responseTooLarge
    case ownedEndpointUnavailable
    case redirectDenied
    case invalidResponse
    case invalidRequest

    var errorDescription: String? {
        switch self {
        case .http(let status): return "The local model service returned HTTP \(status)."
        case .server(let message): return message
        case .responseTooLarge: return "The local model response exceeded the safety limit."
        case .ownedEndpointUnavailable: return "The app-owned local model service is not ready. Start the local runtime and try again."
        case .redirectDenied: return "The local model service attempted an unexpected redirect."
        case .invalidResponse: return "The local model service returned an invalid response."
        case .invalidRequest: return "The local model request is invalid or exceeds the safety limit."
        }
    }
}
