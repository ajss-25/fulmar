import CryptoKit
import Darwin
import Foundation
import Testing
@testable import LocalHarness

private final class HarnessMockURLProtocol: URLProtocol, @unchecked Sendable {
    struct Reply {
        let response: HTTPURLResponse
        let data: Data
        let delay: TimeInterval

        init(response: HTTPURLResponse, data: Data, delay: TimeInterval = 0) {
            self.response = response
            self.data = data
            self.delay = delay
        }
    }

    final class Store: @unchecked Sendable {
        typealias Handler = @Sendable (URLRequest) throws -> Reply
        private let lock = NSLock()
        private var handler: Handler?

        func set(_ handler: @escaping Handler) {
            lock.lock()
            self.handler = handler
            lock.unlock()
        }

        func response(for request: URLRequest) throws -> Reply {
            lock.lock()
            let current = handler
            lock.unlock()
            guard let current else { throw URLError(.resourceUnavailable) }
            return try current(request)
        }
    }

    static let store = Store()
    private let stateLock = NSLock()
    private var stopped = false

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            let reply = try Self.store.response(for: request)
            let deliver = { [weak self] in
                guard let self else { return }
                self.stateLock.lock()
                let shouldDeliver = !self.stopped
                self.stateLock.unlock()
                guard shouldDeliver else { return }
                self.client?.urlProtocol(self, didReceive: reply.response, cacheStoragePolicy: .notAllowed)
                self.client?.urlProtocol(self, didLoad: reply.data)
                self.client?.urlProtocolDidFinishLoading(self)
            }
            if reply.delay > 0 {
                DispatchQueue.global().asyncAfter(deadline: .now() + reply.delay, execute: deliver)
            } else {
                deliver()
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {
        stateLock.lock()
        stopped = true
        stateLock.unlock()
    }
}

private final class LockedRequests: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [[String: Any]] = []

    func append(_ value: [String: Any]) {
        lock.lock()
        storage.append(value)
        lock.unlock()
    }

    var values: [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private final class AsyncTestSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var signaled = false
    private var continuation: CheckedContinuation<Void, Never>?

    func signal() {
        lock.lock()
        signaled = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume()
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if signaled {
                lock.unlock()
                continuation.resume()
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }
}

private enum OneShotWebSocketFixtureError: Error {
    case socket(Int32)
    case malformedHandshake
}

/// A one-connection RFC 6455 fixture that exercises Foundation's real native
/// WebSocket upgrade path. Unlike the injected transport fixtures below, this
/// fails if production accidentally regresses to HTTP/SSE again.
private final class OneShotWebSocketFixture: @unchecked Sendable {
    let port: Int
    private let descriptor: Int32
    private let lock = NSLock()
    private var requestText = ""

    init(textFrame: String) throws {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw OneShotWebSocketFixtureError.socket(errno) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, Darwin.listen(descriptor, 1) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw OneShotWebSocketFixtureError.socket(code)
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }
        guard named == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw OneShotWebSocketFixtureError.socket(code)
        }
        self.port = Int(UInt16(bigEndian: address.sin_port))
        self.descriptor = descriptor

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.serve(textFrame: textFrame)
        }
    }

    deinit { Darwin.close(descriptor) }

    func capturedRequest() -> String {
        lock.lock()
        defer { lock.unlock() }
        return requestText
    }

    private func serve(textFrame: String) {
        var peer = sockaddr()
        var peerLength = socklen_t(MemoryLayout<sockaddr>.size)
        let client = Darwin.accept(descriptor, &peer, &peerLength)
        guard client >= 0 else { return }
        defer {
            _ = Darwin.shutdown(client, SHUT_RDWR)
            Darwin.close(client)
        }
        var noSignal: Int32 = 1
        _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var received = Data()
        var buffer = [UInt8](repeating: 0, count: 2_048)
        while received.count <= 32 * 1_024,
              !received.contains(Data("\r\n\r\n".utf8)) {
            let count = Darwin.read(client, &buffer, buffer.count)
            guard count > 0 else { return }
            received.append(contentsOf: buffer.prefix(count))
        }
        guard let request = String(data: received, encoding: .utf8),
              let keyLine = request.components(separatedBy: "\r\n").first(where: {
                  $0.lowercased().hasPrefix("sec-websocket-key:")
              }) else { return }
        lock.lock()
        requestText = request
        lock.unlock()

        let key = keyLine.split(separator: ":", maxSplits: 1)[1]
            .trimmingCharacters(in: .whitespaces)
        let magic = Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)
        let accept = Data(Insecure.SHA1.hash(data: magic)).base64EncodedString()
        let response = Data((
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: \(accept)\r\n\r\n"
        ).utf8)
        guard Self.write(response, to: client) else { return }
        _ = Self.write(Self.serverTextFrame(Data(textFrame.utf8)), to: client)
        Thread.sleep(forTimeInterval: 0.5)
    }

    private static func serverTextFrame(_ payload: Data) -> Data {
        precondition(payload.count <= Int(UInt16.max))
        var frame = Data([0x81])
        if payload.count <= 125 {
            frame.append(UInt8(payload.count))
        } else {
            frame.append(126)
            frame.append(UInt8((payload.count >> 8) & 0xff))
            frame.append(UInt8(payload.count & 0xff))
        }
        frame.append(payload)
        return frame
    }

    private static func write(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return false }
            var offset = 0
            while offset < rawBuffer.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
    }
}

private func mockSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [HarnessMockURLProtocol.self]
    configuration.httpCookieStorage = nil
    configuration.urlCache = nil
    return URLSession(configuration: configuration)
}

private let fixedRPCUUID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!

private let mockMuxTransport: HarnessRPCClient.MuxTransport = {
    request, limits, continuation, onOpen, validateEndpoint in
    let reply = try HarnessMockURLProtocol.store.response(for: request)
    if reply.delay > 0 {
        try await Task.sleep(for: .seconds(reply.delay))
    }
    try validateEndpoint()
    guard (200..<300).contains(reply.response.statusCode) else {
        throw HarnessRPCClientError.httpStatus(reply.response.statusCode)
    }
    onOpen()
    for frame in reply.data.split(separator: 0x0A, omittingEmptySubsequences: true) {
        try Task.checkCancellation()
        if let event = try HarnessMuxFrameDecoder.decodeMuxFrame(
            Data(frame),
            maximumBytes: limits.muxFrameBytes
        ) {
            switch continuation.yield(event) {
            case .enqueued: break
            case .dropped: throw HarnessRPCClientError.responseTooLarge(limit: limits.muxBufferedEvents)
            case .terminated: throw HarnessRPCClientError.cancelled
            @unknown default: throw HarnessMuxFrameError.invalidEnvelope
            }
        }
    }
}

private func endpoint(token: String = "private-token", port: Int = 39001) -> HarnessEndpoint {
    HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:\(port)/")!,
        token: token,
        nonce: "runtime-nonce",
        processIdentifier: 42
    )
}

private func requestObject(_ request: URLRequest) throws -> [String: Any] {
    let body: Data
    if let direct = request.httpBody {
        body = direct
    } else if let stream = request.httpBodyStream {
        stream.open()
        defer { stream.close() }
        var collected = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count == 0 { break }
            guard count > 0 else { throw stream.streamError ?? URLError(.cannotDecodeContentData) }
            collected.append(contentsOf: buffer.prefix(count))
        }
        body = collected
    } else {
        throw URLError(.cannotDecodeContentData)
    }
    return try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
}

private func jsonReply(
    request: URLRequest,
    object: Any,
    status: Int = 200,
    contentType: String = "application/json",
    delay: TimeInterval = 0
) throws -> HarnessMockURLProtocol.Reply {
    let data = try JSONSerialization.data(withJSONObject: object)
    guard let url = request.url,
          let response = HTTPURLResponse(
        url: url,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Type": contentType, "Content-Length": "\(data.count)"]
    ) else { throw URLError(.badServerResponse) }
    return HarnessMockURLProtocol.Reply(response: response, data: data, delay: delay)
}

private func successReply(
    request: URLRequest,
    value: Any,
    rpcID: String? = nil,
    type: String = "server-response",
    delay: TimeInterval = 0
) throws -> HarnessMockURLProtocol.Reply {
    let body = try requestObject(request)
    return try jsonReply(
        request: request,
        object: [
            "type": type,
            "rpcId": rpcID ?? (body["rpcId"] as? String ?? "missing"),
            "result": ["ok": true, "value": value]
        ],
        delay: delay
    )
}

private func client(
    endpoint initialEndpoint: HarnessEndpoint? = endpoint(),
    limits: HarnessRPCClientLimits = .init()
) -> HarnessRPCClient {
    HarnessRPCClient(
        endpoint: initialEndpoint,
        session: mockSession(),
        limits: limits,
        uuid: { fixedRPCUUID },
        muxTransport: mockMuxTransport
    )
}

@Suite(.serialized)
struct HarnessRPCClientTests {
    @Test func productionTransportIsEphemeralCredentialFreeCachelessAndProxyIndependent() {
        let configuration = HarnessRPCClient.makePrivateLoopbackSession().configuration
        #expect(configuration.identifier == nil)
        #expect(configuration.requestCachePolicy == .reloadIgnoringLocalCacheData)
        #expect(configuration.urlCache == nil)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.httpShouldSetCookies == false)
        #expect(configuration.urlCredentialStorage == nil)
        #expect(configuration.connectionProxyDictionary?.isEmpty == true)
        #expect(configuration.waitsForConnectivity == false)
    }

    @Test @MainActor
    func ollamaPrerequisiteRecoveryAllowsOnlyProviderAdministrationAndRequiresExactIdentityPromotion() async throws {
        for issue in [
            OllamaPrerequisiteRecoveryIssue.insufficientPhysicalMemory(
                requiredBytes: QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes,
                availableBytes: 8 * 1_073_741_824
            ),
            OllamaPrerequisiteRecoveryIssue.notInstalled,
            .untrustedInstallation,
            .readinessTimedOut
        ] {
            var observedIssue: OllamaPrerequisiteRecoveryIssue?
            let controller = HarnessController(lifecycleTestConfiguration: .init(
                harnessProcess: nil,
                ollamaProcess: nil,
                initialState: .startingOllama,
                stopProcess: { _, _ in Issue.record("No child exists to stop in this fixture") },
                startReplacement: { Issue.record("Ollama recovery must not request an inference replacement") },
                startOllamaPrerequisiteRecovery: { observedIssue = $0 }
            ))
            controller.transitionToProviderRecovery(after: issue)
            #expect(observedIssue == issue)
            #expect(controller.ollamaPrerequisiteRecoveryIssue == issue)
            #expect(controller.currentState == .providerRecovery)
            #expect(controller.endpoint == nil)
            #expect(!controller.ownsHarness)
            #expect(!controller.ownsOllama)
        }

        let requests = LockedRequests()
        HarnessMockURLProtocol.store.set { request in
            let body = try requestObject(request)
            requests.append(body)
            let method = try #require(body["method"] as? String)
            let value: Any
            switch method {
            case "llm.providers": value = ["providers": []]
            case "llm.models": value = ["groups": [], "failures": []]
            case "settings.describe": value = ["writable": true, "hasDocument": true, "namespaces": []]
            case "settings.mutate": value = [
                "ns": "agent-default-model", "schema": ["type": "object"], "value": [:],
                "applies": "live", "secrets": [], "revision": 1
            ]
            case "credentials.describe": value = ["credentials": [:]]
            case "credentials.set", "credentials.unset": value = [:]
            default:
                Issue.record("Recovery sent a non-control-plane method: \(method)")
                throw URLError(.dataNotAllowed)
            }
            return try successReply(request: request, value: value)
        }

        let first = endpoint(port: 39011)
        let replacement = endpoint(token: "replacement-token", port: 39012)
        let rpc = HarnessRPCClient(
            endpoint: first,
            accessMode: .controlPlaneOnly,
            session: mockSession(),
            uuid: { fixedRPCUUID }
        )

        _ = try await rpc.llmProviders()
        _ = try await rpc.llmModels()
        _ = try await rpc.describeSettings()
        _ = try await rpc.mutateSettings(
            namespace: "agent-default-model",
            operations: [.set(path: ["provider"], value: .string("openai"))],
            expectedRevision: 0
        )
        _ = try await rpc.describeCredentials([CredentialReference("OPENAI_API_KEY")])
        try await rpc.setCredential(CredentialReference("OPENAI_API_KEY"), value: "write-only")
        try await rpc.unsetCredential(CredentialReference("OPENAI_API_KEY"))
        #expect(Set(requests.values.compactMap { $0["method"] as? String }) == Set([
            "llm.providers", "llm.models", "settings.describe", "settings.mutate",
            "credentials.describe", "credentials.set", "credentials.unset"
        ]))

        let countBeforeRejectedCalls = requests.values.count
        do { _ = try await rpc.listSessions(); Issue.record("session.list escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.searchSessions(query: "private"); Issue.record("session.search escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.createSession(); Issue.record("session.create escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.sessionHistory(HarnessSessionID("recovery")); Issue.record("session.history escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.sessionModels(HarnessSessionID("recovery")); Issue.record("session.models escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do {
            _ = try await rpc.selectModel(
                sessionID: HarnessSessionID("recovery"),
                selection: .init(provider: ProviderID("openai"), model: ModelID("model"))
            )
            Issue.record("session.selectModel escaped recovery")
        } catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.renameSession(HarnessSessionID("recovery"), title: "title"); Issue.record("session.rename escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.forkSession(HarnessSessionID("recovery")); Issue.record("session.fork escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.archiveSession(HarnessSessionID("recovery")); Issue.record("archive escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.prompt(sessionID: HarnessSessionID("recovery"), content: [.text("private")]); Issue.record("prompt escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try await rpc.cancel(sessionID: HarnessSessionID("recovery")); Issue.record("cancel escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do { _ = try rpc.muxEvents(); Issue.record("event stream escaped recovery") }
        catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do {
            _ = try await rpc.respondToApproval(
                rpcID: "rpc", sessionID: HarnessSessionID("recovery"),
                approvalID: "approval", decision: .rejected
            )
            Issue.record("approval response escaped recovery")
        } catch let error as HarnessRPCClientError { #expect(error == .controlPlaneOnly) }
        do {
            _ = try await rpc.mutateSettings(namespace: "unreviewed", operations: [], expectedRevision: nil)
            Issue.record("unreviewed settings namespace escaped recovery")
        } catch let error as HarnessRPCClientError { #expect(error == .invalidArgument) }
        #expect(requests.values.count == countBeforeRejectedCalls)

        rpc.setControlPlaneEndpoint(replacement)
        #expect(!rpc.promoteToFullInference(expected: first))
        #expect(rpc.currentAccessMode() == .controlPlaneOnly)
        #expect(rpc.promoteToFullInference(expected: replacement))
        #expect(rpc.currentAccessMode() == .fullInference)
        #expect(!rpc.promoteToFullInference(expected: replacement))
    }

    @Test func defaultPromptLimitMatchesDSHImageCarrierWhileOtherRPCsStayTight() {
        let limits = HarnessRPCClientLimits()
        #expect(limits.requestBytes == 2 * 1_024 * 1_024)
        #expect(limits.promptRequestBytes == 160 * 1_024 * 1_024)
        #expect(limits.unaryResponseBytes == 4 * 1_024 * 1_024)
    }

    @Test func providerCatalogNormalizesHostileDisplayTextAtTheWireBoundary() throws {
        let longName = String(repeating: "N", count: HarnessCatalogWirePolicy.maximumNameScalars + 40)
        let directoryData = try JSONSerialization.data(withJSONObject: [
            "providers": [[
                "provider": "provider/fallback",
                "displayName": " \u{202E}\n\t",
                "settingsNs": "llm-pi-ai",
                "settingsPath": ["providers", "provider/fallback"],
                "active": true,
                "declared": true
            ], [
                "provider": "long-name",
                "displayName": longName,
                "settingsNs": "llm-pi-ai",
                "settingsPath": ["providers", "long-name"],
                "active": false
            ], [
                "provider": "missing-name",
                "settingsNs": "llm-pi-ai",
                "settingsPath": ["providers", "missing-name"],
                "active": false
            ]]
        ])
        let directory = try JSONDecoder().decode(HarnessProviderDirectory.self, from: directoryData)
        #expect(directory.providers[0].displayName == "provider/fallback")
        #expect(directory.providers[1].displayName.unicodeScalars.count == HarnessCatalogWirePolicy.maximumNameScalars)
        #expect(directory.providers[2].displayName == "missing-name")
        #expect(directory.providers[0].settingsNs == "llm-pi-ai")
        #expect(directory.providers[0].settingsPath == ["providers", "provider/fallback"])

        let failureSecret = ["sk", "catalog", String(repeating: "c", count: 48)].joined(separator: "-")
        let hostileFailureMessage = "\u{001B}[2J\u{202E}\(failureSecret)"
            + String(repeating: "F", count: 32 * 1_024)
        let catalogData = try JSONSerialization.data(withJSONObject: [
            "groups": [[
                "id": "provider/fallback",
                "name": " \u{202E}\n",
                "models": [[
                    "id": "model/fallback",
                    "name": "Model\u{200B}\u{202E}\nTitle",
                    "description": " First\n\tline \u{202E} second ",
                    "reasoning": [
                        "efforts": [[
                            "id": "deep/max",
                            "name": "\u{202E}\n",
                            "description": String(repeating: "D", count: HarnessCatalogWirePolicy.maximumDetailScalars + 80)
                        ]],
                        "defaultEffort": "deep/max"
                    ]
                ]]
            ]],
            "failures": [[
                "id": "broken/provider",
                "name": "\u{202E}\n",
                "message": hostileFailureMessage
            ]]
        ])
        let catalog = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalogData)
        let group = try #require(catalog.groups.first)
        let model = try #require(group.models.first)
        let effort = try #require(model.reasoning?.efforts.first)
        let failure = try #require(catalog.failures.first)
        #expect(group.name == "provider/fallback")
        #expect(model.name == "Model Title")
        #expect(model.description == "First line second")
        #expect(effort.name == "deep/max")
        #expect(effort.description?.unicodeScalars.count == HarnessCatalogWirePolicy.maximumDetailScalars)
        #expect(failure.name == "broken/provider")
        #expect(failure.message == "Provider unavailable")
        #expect(!failure.message.contains(failureSecret))
        #expect(!failure.message.contains("\u{001B}"))
    }

    @Test func providerCatalogRejectsUnsafeOrUnboundedOpaqueWireMetadataWithoutRewritingPunctuation() throws {
        func directory(
            provider: String = "route/acme:west@v1+prod?x=1",
            settingsNs: String = "llm-pi-ai/v2:prod",
            settingsPath: [String] = ["providers", "route/acme:west@v1+prod?x=1"]
        ) throws -> Data {
            try JSONSerialization.data(withJSONObject: ["providers": [[
                "provider": provider,
                "displayName": "Acme",
                "settingsNs": settingsNs,
                "settingsPath": settingsPath,
                "active": true
            ]]])
        }
        func catalog(
            groupID: String = "route/acme:west@v1+prod?x=1",
            modelID: String = "model/family:27b@Q4_K_M+tools",
            effortID: String = "reason/deep:max+tools",
            defaultEffort: String = "reason/deep:max+tools",
            failureID: String = "failure/route:west"
        ) throws -> Data {
            try JSONSerialization.data(withJSONObject: [
                "groups": [[
                    "id": groupID,
                    "name": "Acme",
                    "models": [[
                        "id": modelID,
                        "name": "Model",
                        "reasoning": [
                            "efforts": [["id": effortID, "name": "Deep"]],
                            "defaultEffort": defaultEffort
                        ]
                    ]]
                ]],
                "failures": [["id": failureID, "name": "Failure", "message": "Unavailable"]]
            ])
        }

        let punctuationDirectory = try JSONDecoder().decode(
            HarnessProviderDirectory.self,
            from: directory()
        )
        #expect(punctuationDirectory.providers[0].provider.rawValue == "route/acme:west@v1+prod?x=1")
        #expect(punctuationDirectory.providers[0].settingsNs == "llm-pi-ai/v2:prod")
        #expect(punctuationDirectory.providers[0].settingsPath[1] == "route/acme:west@v1+prod?x=1")
        let punctuationCatalog = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalog())
        #expect(punctuationCatalog.groups[0].id.rawValue == "route/acme:west@v1+prod?x=1")
        #expect(punctuationCatalog.groups[0].models[0].id.rawValue == "model/family:27b@Q4_K_M+tools")
        #expect(punctuationCatalog.groups[0].models[0].reasoning?.efforts[0].id == "reason/deep:max+tools")

        let oversizedID = String(repeating: "x", count: HarnessCatalogWirePolicy.maximumIdentifierScalars + 1)
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessProviderDirectory.self, from: directory(provider: "bad\nprovider"))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessProviderDirectory.self, from: directory(settingsNs: oversizedID))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessProviderDirectory.self, from: directory(settingsPath: ["providers", "bad\u{202E}path"]))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(
                HarnessProviderDirectory.self,
                from: directory(settingsPath: Array(repeating: "path", count: HarnessCatalogWirePolicy.maximumSettingsPathComponents + 1))
            )
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalog(groupID: "bad\u{200B}group"))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalog(modelID: oversizedID))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalog(effortID: "bad\tvalue"))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalog(defaultEffort: oversizedID))
        }
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: catalog(failureID: "bad\u{2066}failure"))
        }
        let unsafeSelection = try JSONSerialization.data(withJSONObject: [
            "provider": "provider",
            "model": "model",
            "reasoningEffort": "bad\nreasoning"
        ])
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessWireModelSelection.self, from: unsafeSelection)
        }
    }

    @Test func providerCatalogRejectsEveryOversizedCollectionBeforeUIProjection() throws {
        func provider(_ index: Int) -> [String: Any] {
            [
                "provider": "provider-\(index)",
                "displayName": "Provider \(index)",
                "settingsNs": "llm-pi-ai",
                "settingsPath": ["providers", "provider-\(index)"],
                "active": true
            ]
        }
        func model(_ index: Int, efforts: [[String: Any]] = []) -> [String: Any] {
            var value: [String: Any] = [
                "id": "model-\(index)",
                "name": "Model \(index)"
            ]
            if !efforts.isEmpty {
                value["reasoning"] = ["efforts": efforts]
            }
            return value
        }
        func catalog(groups: [[String: Any]], failures: [[String: Any]] = []) throws -> Data {
            try JSONSerialization.data(withJSONObject: ["groups": groups, "failures": failures])
        }

        let tooManyProviders = try JSONSerialization.data(withJSONObject: [
            "providers": (0...HarnessCatalogWirePolicy.maximumProviders).map(provider)
        ])
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessProviderDirectory.self, from: tooManyProviders)
        }

        let tooManyGroups = try catalog(groups: (0...HarnessCatalogWirePolicy.maximumProviderGroups).map {
            ["id": "provider-\($0)", "name": "Provider \($0)", "models": []]
        })
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: tooManyGroups)
        }
        let oversizedSessionCatalog = try JSONSerialization.data(withJSONObject: [
            "current": ["provider": "provider-0", "model": "model-0"],
            "routable": true,
            "groups": (0...HarnessCatalogWirePolicy.maximumProviderGroups).map {
                ["id": "provider-\($0)", "name": "Provider \($0)", "models": []]
            },
            "failures": []
        ])
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessSessionModels.self, from: oversizedSessionCatalog)
        }

        let tooManyModels = try catalog(groups: [[
            "id": "provider",
            "name": "Provider",
            "models": (0...HarnessCatalogWirePolicy.maximumModelsPerGroup).map { model($0) }
        ]])
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: tooManyModels)
        }

        let efforts = (0...HarnessCatalogWirePolicy.maximumReasoningEfforts).map {
            ["id": "effort-\($0)", "name": "Effort \($0)"]
        }
        let tooManyEfforts = try catalog(groups: [[
            "id": "provider",
            "name": "Provider",
            "models": [model(0, efforts: efforts)]
        ]])
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: tooManyEfforts)
        }

        let maximumGroup = (0..<HarnessCatalogWirePolicy.maximumModelsPerGroup).map { model($0) }
        let groupsNeeded = HarnessCatalogWirePolicy.maximumModelsTotal
            / HarnessCatalogWirePolicy.maximumModelsPerGroup + 1
        let tooManyTotal = try catalog(groups: (0..<groupsNeeded).map {
            ["id": "provider-\($0)", "name": "Provider \($0)", "models": maximumGroup]
        })
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: tooManyTotal)
        }

        let tooManyFailures = try catalog(
            groups: [],
            failures: (0...HarnessCatalogWirePolicy.maximumFailures).map {
                ["id": "provider-\($0)", "name": "Provider \($0)", "message": "Unavailable"]
            }
        )
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HarnessModelCatalog.self, from: tooManyFailures)
        }
    }

    @Test func unaryRequestIsAuthenticatedAndStrictlyEnveloped() async throws {
        let requests = LockedRequests()
        HarnessMockURLProtocol.store.set { request in
            #expect(request.httpMethod == "POST")
            #expect(request.url?.path == "/api/llm.providers")
            #expect(request.value(forHTTPHeaderField: "X-Local-Harness-Token") == "private-token")
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
            #expect(request.timeoutInterval == 30)
            let object = try requestObject(request)
            requests.append(object)
            return try successReply(request: request, value: ["providers": [[
                "provider": "route/acme:west",
                "displayName": "Acme",
                "settingsNs": "llm-pi-ai",
                "settingsPath": ["providers", "route/acme:west"],
                "active": true,
                "declared": true
            ]]])
        }

        let result = try await client().llmProviders()
        #expect(result.providers.first?.provider == ProviderID("route/acme:west"))
        let body = try #require(requests.values.first)
        #expect(body["type"] as? String == "client-request")
        #expect(body["rpcId"] as? String == fixedRPCUUID.uuidString.lowercased())
        #expect(body["method"] as? String == "llm.providers")
        #expect((body["payload"] as? [String: Any])?.isEmpty == true)
    }

    @Test func everySupportedUnaryRouteUsesTypedPayloadsAndResponses() async throws {
        let requests = LockedRequests()
        HarnessMockURLProtocol.store.set { request in
            let body = try requestObject(request)
            requests.append(body)
            let method = try #require(body["method"] as? String)
            let value: Any
            switch method {
            case "llm.providers": value = ["providers": []]
            case "llm.models": value = [
                "groups": [[
                    "id": "vendor/route:v2", "name": "Vendor", "models": [[
                        "id": "org/model:27b/q5", "name": "Model", "description": "Detailed",
                        "reasoning": ["efforts": [["id": "deep/max", "name": "Deep"]], "defaultEffort": "deep/max"]
                    ]]
                ]],
                "failures": []
            ]
            case "session.list": value = ["items": [[
                "sessionId": "session/list:1", "updatedAt": 42.5, "running": false, "blank": true,
                "cwd": "/private/project", "projections": ["asOfSeq": -1, "values": [:]]
            ]]]
            case "session.search": value = ["items": [["sessionId": "session/list:1", "snippet": "matching text"]], "hasMore": false]
            case "session.create": value = ["sessionId": "session/new:1", "agentPreset": "default"]
            case "session.history": value = [
                "events": [["event": [
                    "type": "assistant/message", "seq": 7, "time": 12.25,
                    "data": ["turn": 1], "sourceEventSeqs": [5, 6], "ignorable": true
                ], "view": ["for": "result", "view": ["card": "text"]]]],
                "hasMore": true,
                "projections": ["asOfSeq": 7, "values": ["title": "Example"]]
            ]
            case "session.models": value = [
                "current": ["provider": "vendor/route:v2", "model": "org/model:27b/q5", "reasoningEffort": "deep/max"],
                "routable": true, "groups": [], "failures": []
            ]
            case "session.selectModel": value = ["selected": [
                "provider": "vendor/route:v2", "model": "org/model:27b/q5", "reasoningEffort": "deep/max"
            ]]
            case "session.rename": value = ["title": "Renamed task", "seq": 9]
            case "session.fork": value = ["sessionId": "session/fork:2"]
            case "session.prompt": value = ["accepted": true, "command": ["kind": "success", "text": "done"]]
            case "session.cancel": value = ["accepted": true]
            case "workspace.archiveSession": value = ["archivedSessionIds": ["session/list:1"]]
            case "settings.describe": value = [
                "writable": true, "hasDocument": true,
                "namespaces": [[
                    "ns": "llm-pi-ai", "schema": ["type": "object"], "value": ["providers": [:]],
                    "applies": "live", "secrets": [["path": ["apiKey"], "set": false]], "revision": 3
                ]]
            ]
            case "settings.mutate": value = [
                "ns": "llm-pi-ai", "schema": ["type": "object"], "value": ["enabled": true],
                "applies": "live", "secrets": [], "revision": 4
            ]
            case "credentials.describe": value = ["credentials": [
                "CUSTOM_API_KEY": ["configured": true, "source": "file", "writable": true]
            ]]
            case "credentials.set", "credentials.unset": value = [:]
            default: throw URLError(.badServerResponse)
            }
            return try successReply(request: request, value: value)
        }

        let rpc = client()
        _ = try await rpc.llmProviders()
        let catalog = try await rpc.llmModels()
        #expect(catalog.groups[0].id == ProviderID("vendor/route:v2"))
        #expect(catalog.groups[0].models[0].id == ModelID("org/model:27b/q5"))
        let sessions = try await rpc.listSessions(cursor: "future:cursor")
        #expect(sessions.items[0].sessionId == HarnessSessionID("session/list:1"))
        #expect(sessions.items[0].projections?.asOfSeq == -1)
        let search = try await rpc.searchSessions(query: "  matching text  ")
        #expect(search.items[0].snippet == "matching text")
        let created = try await rpc.createSession(.init(cwd: "/project"))
        #expect(created.sessionId == HarnessSessionID("session/new:1"))
        let history = try await rpc.sessionHistory(HarnessSessionID("session/list:1"), beforeSequence: 8, maximumMessages: 20)
        #expect(history.events[0].event.sourceEventSeqs == [5, 6])
        #expect(history.projections?.values["title"] == .string("Example"))
        let models = try await rpc.sessionModels(HarnessSessionID("session/list:1"))
        #expect(models.current.route == ModelRoute(provider: ProviderID("vendor/route:v2"), model: ModelID("org/model:27b/q5")))
        let selected = try await rpc.selectModel(
            sessionID: HarnessSessionID("session/list:1"),
            selection: .init(provider: ProviderID("vendor/route:v2"), model: ModelID("org/model:27b/q5"), reasoningEffort: "deep/max")
        )
        #expect(selected.reasoningEffort == "deep/max")
        #expect(try await rpc.renameSession(HarnessSessionID("session/list:1"), title: "  Renamed task  ").title == "Renamed task")
        #expect(try await rpc.forkSession(HarnessSessionID("session/list:1"), atSequence: 9).sessionId == HarnessSessionID("session/fork:2"))
        #expect(try await rpc.archiveSession(HarnessSessionID("session/list:1")).archivedSessionIds == [HarnessSessionID("session/list:1")])
        let prompt = try await rpc.prompt(
            sessionID: HarnessSessionID("session/list:1"),
            mode: .steer,
            content: [.text("private prompt"), .image(mediaType: .png, data: "aGVsbG8=", name: "test.png")],
            clientTimeZone: "Europe/London"
        )
        #expect(prompt.command?.text == "done")
        #expect(try await rpc.cancel(sessionID: HarnessSessionID("session/list:1")).accepted)
        #expect(try await rpc.describeSettings().namespaces[0].revision == 3)
        let mutated = try await rpc.mutateSettings(
            namespace: "llm-pi-ai",
            operations: [.set(path: ["providers", "custom", "enabled"], value: .bool(true)), .unset(path: ["legacy"])],
            expectedRevision: 3
        )
        #expect(mutated.revision == 4)
        #expect(try await rpc.describeCredentials([CredentialReference("CUSTOM_API_KEY")]).credentials["CUSTOM_API_KEY"]?.configured == true)
        try await rpc.setCredential(CredentialReference("CUSTOM_API_KEY"), value: "one-way-secret")
        try await rpc.unsetCredential(CredentialReference("CUSTOM_API_KEY"))

        let methods = requests.values.compactMap { $0["method"] as? String }
        #expect(Set(methods) == Set([
            "llm.providers", "llm.models", "session.list", "session.search", "session.create", "session.history",
            "session.models", "session.selectModel", "session.rename", "session.fork", "session.prompt", "session.cancel",
            "workspace.archiveSession", "settings.describe",
            "settings.mutate", "credentials.describe", "credentials.set", "credentials.unset"
        ]))
        let searchBody = try #require(requests.values.first { $0["method"] as? String == "session.search" })
        #expect((searchBody["payload"] as? [String: Any])?["query"] as? String == "matching text")
        let selectionBody = try #require(requests.values.first { $0["method"] as? String == "session.selectModel" })
        let selectionPayload = try #require(selectionBody["payload"] as? [String: Any])
        #expect(selectionPayload["provider"] as? String == "vendor/route:v2")
        #expect(selectionPayload["model"] as? String == "org/model:27b/q5")
        let renameBody = try #require(requests.values.first { $0["method"] as? String == "session.rename" })
        #expect((renameBody["payload"] as? [String: Any])?["title"] as? String == "Renamed task")
        let forkBody = try #require(requests.values.first { $0["method"] as? String == "session.fork" })
        #expect((forkBody["payload"] as? [String: Any])?["atSeq"] as? Int == 9)
    }

    @Test func approvalAndQuestionResponsesEchoServerRPCIDOnRespondCarrier() async throws {
        let requests = LockedRequests()
        HarnessMockURLProtocol.store.set { request in
            #expect(request.url?.path == "/api/respond")
            let object = try requestObject(request)
            requests.append(object)
            return try jsonReply(request: request, object: ["accepted": true])
        }
        let rpc = client()
        #expect(try await rpc.respondToApproval(
            rpcID: "approval/rpc:1",
            sessionID: HarnessSessionID("session/1"),
            approvalID: "approval:1",
            decision: .allowedOnce
        ).accepted)
        #expect(try await rpc.respondToQuestion(
            rpcID: "question/rpc:1",
            sessionID: HarnessSessionID("session/1"),
            answer: .init(answers: [.init(id: "framework", selected: ["SwiftUI"], custom: nil)])
        ).accepted)
        #expect(try await rpc.cancelQuestion(rpcID: "question/rpc:2").accepted)

        #expect(requests.values.map { $0["type"] as? String } == ["client-response", "client-response", "client-response"])
        #expect(requests.values.map { $0["rpcId"] as? String } == ["approval/rpc:1", "question/rpc:1", "question/rpc:2"])
        let approvalResult = try #require(requests.values[0]["result"] as? [String: Any])
        let approvalValue = try #require(approvalResult["value"] as? [String: Any])
        #expect(approvalValue["outcome"] as? String == "allowed-once")
        let cancelledResult = try #require(requests.values[2]["result"] as? [String: Any])
        #expect(cancelledResult["ok"] as? Bool == false)
        #expect(((cancelledResult["error"] as? [String: Any])?["code"] as? String) == "cancelled")
    }

    @Test func receiptRejectsContradictoryShapes() async throws {
        HarnessMockURLProtocol.store.set { request in
            try jsonReply(request: request, object: ["accepted": true, "reason": "not-pending"])
        }
        do {
            _ = try await client().cancelQuestion(rpcID: "question/rpc")
            Issue.record("Expected invalid receipt")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseViolation(.invalidEnvelope))
        }
    }

    @Test func responseEnvelopeAndRPCIDEchoAreValidated() async throws {
        HarnessMockURLProtocol.store.set { request in
            try successReply(request: request, value: ["providers": []], rpcID: "wrong-id")
        }
        do {
            _ = try await client().llmProviders()
            Issue.record("Expected rpc id mismatch")
        } catch let error as HarnessRPCClientError {
            #expect(error == .rpcIDMismatch)
        }

        HarnessMockURLProtocol.store.set { request in
            try successReply(request: request, value: ["providers": []], type: "client-response")
        }
        do {
            _ = try await client().llmProviders()
            Issue.record("Expected invalid envelope")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseViolation(.invalidEnvelope))
        }
    }

    @Test func remoteErrorsMapToTypedCodesWithoutEchoingCredentialBodies() async throws {
        HarnessMockURLProtocol.store.set { request in
            let body = try requestObject(request)
            return try jsonReply(request: request, object: [
                "type": "server-response",
                "rpcId": body["rpcId"] as? String ?? "",
                "result": [
                    "ok": false,
                    "error": [
                        "code": "credential-rejected",
                        "message": "Credential storage is shadowed.",
                        "details": ["ref": "CUSTOM_API_KEY"]
                    ]
                ]
            ])
        }
        let secret = "never-print-this-secret"
        do {
            try await client().setCredential(CredentialReference("CUSTOM_API_KEY"), value: secret)
            Issue.record("Expected remote error")
        } catch let error as HarnessRPCClientError {
            guard case .remote(let remote) = error else { Issue.record("Wrong error"); return }
            #expect(remote.code == .credentialRejected)
            #expect(remote.details["ref"] == .string("CUSTOM_API_KEY"))
            #expect(!String(describing: error).contains(secret))
            #expect(!error.localizedDescription.contains(secret))
        }

        let hostileSecret = ["sk", "remote", String(repeating: "q", count: 48)].joined(separator: "-")
        let hostile = "\u{001B}[2J\u{202E}\(hostileSecret)"
            + String(repeating: "M", count: 2 * 1_024 * 1_024)
        let unknown: HarnessRPCClientError = .remote(.init(
            code: .other(hostile),
            message: hostile,
            details: ["provider": .string(hostile)]
        ))
        #expect(unknown.localizedDescription == "Harness could not complete the request.")
        #expect(!unknown.localizedDescription.contains(hostileSecret))
        #expect(!unknown.localizedDescription.contains("\u{001B}"))
        #expect(unknown.localizedDescription.utf8.count < 128)

        let rejected: HarnessRPCClientError = .remote(.init(
            code: .credentialRejected,
            message: hostile,
            details: [:]
        ))
        #expect(rejected.localizedDescription
            == "The provider credential was rejected. Check or replace it in Models & Providers.")
        #expect(!rejected.localizedDescription.contains(hostileSecret))
    }

    @Test func contentTypeStatusAndSizeLimitsFailClosed() async throws {
        HarnessMockURLProtocol.store.set { request in
            try jsonReply(request: request, object: ["not": "json carrier"], contentType: "text/plain")
        }
        do {
            _ = try await client().llmProviders()
            Issue.record("Expected content type failure")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseViolation(.invalidContentType))
        }

        HarnessMockURLProtocol.store.set { request in
            try jsonReply(request: request, object: ["error": true], status: 503)
        }
        do {
            _ = try await client().llmProviders()
            Issue.record("Expected HTTP failure")
        } catch let error as HarnessRPCClientError {
            #expect(error == .httpStatus(503))
        }

        let tight = HarnessRPCClientLimits(requestBytes: 128, unaryResponseBytes: 64)
        do {
            try await client(limits: tight).setCredential(
                CredentialReference("CUSTOM_API_KEY"),
                value: String(repeating: "s", count: 500)
            )
            Issue.record("Expected request limit")
        } catch let error as HarnessRPCClientError {
            #expect(error == .requestTooLarge(limit: 128))
        }

        HarnessMockURLProtocol.store.set { request in
            try successReply(request: request, value: ["providers": [["padding": String(repeating: "x", count: 500)] ]])
        }
        do {
            _ = try await client(limits: tight).llmProviders()
            Issue.record("Expected response limit")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseTooLarge(limit: 64))
        }
    }

    @Test func invalidSearchAndHistoryBoundsNeverReachTransport() async throws {
        let calls = LockedRequests()
        HarnessMockURLProtocol.store.set { request in
            calls.append(try requestObject(request))
            return try successReply(request: request, value: [:])
        }
        let rpc = client()
        for query in [
            "   ",
            "bad\0query",
            String(repeating: "q", count: 501),
            // 251 graphemes but 502 JavaScript UTF-16 code units.
            String(repeating: "😀", count: 251)
        ] {
            do {
                _ = try await rpc.searchSessions(query: query)
                Issue.record("Expected invalid query")
            } catch let error as HarnessRPCClientError {
                #expect(error == .invalidArgument)
            }
        }
        do {
            _ = try await rpc.sessionHistory(HarnessSessionID("s"), beforeSequence: -1, maximumMessages: 0)
            Issue.record("Expected invalid page")
        } catch let error as HarnessRPCClientError {
            #expect(error == .invalidArgument)
        }
        do {
            _ = try await rpc.createSession(.init(workspaceId: "workspace", cwd: "/also-a-cwd"))
            Issue.record("Expected mutually exclusive project fields")
        } catch let error as HarnessRPCClientError {
            #expect(error == .invalidArgument)
        }
        #expect(throws: HarnessRPCClientError.invalidArgument) {
            _ = try rpc.muxEvents(since: [HarnessSessionID("s"): -2])
        }
        #expect(calls.values.isEmpty)
    }

    @Test func authenticatedRuntimeTokenCanOnlyBeSentToLoopbackOrigins() async throws {
        let external = HarnessEndpoint(
            baseURL: URL(string: "https://example.com/")!,
            token: "must-not-leak",
            nonce: "nonce",
            processIdentifier: 1
        )
        do {
            _ = try await client(endpoint: external).llmProviders()
            Issue.record("Expected invalid external endpoint")
        } catch let error as HarnessRPCClientError {
            #expect(error == .invalidEndpoint)
        }
    }

    @Test func clearingEndpointInvalidatesAndCancelsInFlightWork() async throws {
        let started = AsyncTestSignal()
        HarnessMockURLProtocol.store.set { request in
            started.signal()
            return try successReply(request: request, value: ["providers": []], delay: 5)
        }
        let rpc = client()
        let operation = Task { try await rpc.llmProviders() }
        await started.wait()
        rpc.clearEndpoint()
        do {
            _ = try await operation.value
            Issue.record("Expected endpoint invalidation")
        } catch let error as HarnessRPCClientError {
            #expect(error == .endpointChanged)
        }
        do {
            _ = try await rpc.llmProviders()
            Issue.record("Expected unavailable endpoint")
        } catch let error as HarnessRPCClientError {
            #expect(error == .endpointUnavailable)
        }
    }

    @Test func muxStreamAuthenticatesCarriesCursorAndEmitsTypedEvents() async throws {
        let frame = try muxEnvelope(method: "session/event", payload: [
            "type": "session/event", "sessionId": "session/opaque:1",
            "event": [
                "type": "assistant/chunk", "seq": 9, "time": 100.5,
                "data": ["turn": 2, "step": 1, "chunk": ["type": "text-delta", "index": 0, "text": "Hello"]]
            ]
        ])
        HarnessMockURLProtocol.store.set { request in
            #expect(request.httpMethod == "GET")
            #expect(request.url?.path == "/api/events.mux")
            #expect(request.url?.scheme == "ws")
            #expect(request.value(forHTTPHeaderField: "X-Local-Harness-Token") == "private-token")
            #expect(request.value(forHTTPHeaderField: "Origin") == "http://127.0.0.1:39001")
            #expect(request.value(forHTTPHeaderField: "Accept") == nil)
            let cursor = URLComponents(url: try #require(request.url), resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "since" })?.value
            let cursorData = try #require(cursor?.data(using: .utf8))
            let decoded = try JSONDecoder().decode([String: Int].self, from: cursorData)
            #expect(decoded == ["session/opaque:1": 8])
            let data = Data(frame.utf8)
            guard let url = request.url,
                  let response = HTTPURLResponse(
                url: url, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            ) else { throw URLError(.badServerResponse) }
            return .init(response: response, data: data)
        }

        let rpc = client()
        let subscription = try rpc.muxEvents(since: [HarnessSessionID("session/opaque:1"): 8])
        var received: [HarnessMuxEvent] = []
        for try await event in subscription.events { received.append(event) }
        let event = try #require(received.first)
        guard case .assistantTextDelta(let delta) = event else { Issue.record("Wrong event"); return }
        #expect(delta.sessionID == HarnessSessionID("session/opaque:1"))
        #expect(delta.text == "Hello")
        #expect(delta.sequence == 9)
    }

    @Test func productionMuxUsesARealAuthenticatedWebSocketUpgrade() async throws {
        let frame = try muxEnvelope(method: "session/subscribed", payload: [
            "type": "session/subscribed", "sessionId": "session/native-ws", "lastSeq": 4
        ])
        let fixture = try OneShotWebSocketFixture(textFrame: frame)
        let endpoint = HarnessEndpoint(
            baseURL: URL(string: "http://127.0.0.1:\(fixture.port)/")!,
            token: "native-private-token",
            nonce: "native-runtime",
            processIdentifier: getpid()
        )
        let rpc = HarnessRPCClient(
            endpoint: endpoint,
            limits: HarnessRPCClientLimits(streamConnectTimeout: 3),
            uuid: { fixedRPCUUID }
        )
        let subscription = try rpc.muxEvents(since: [HarnessSessionID("session/native-ws"): 3])
        try await subscription.waitUntilOpen()
        var iterator = subscription.events.makeAsyncIterator()
        let event = try #require(try await iterator.next())
        guard case .subscribed(let value) = event else {
            Issue.record("The native WebSocket emitted the wrong typed event")
            return
        }
        #expect(value.sessionID == HarnessSessionID("session/native-ws"))
        #expect(value.lastSequence == 4)
        let request = fixture.capturedRequest()
        #expect(request.hasPrefix("GET /api/events.mux?"))
        #expect(request.localizedCaseInsensitiveContains("Upgrade: websocket"))
        #expect(request.localizedCaseInsensitiveContains("Origin: http://127.0.0.1:\(fixture.port)"))
        #expect(request.localizedCaseInsensitiveContains("X-Local-Harness-Token: native-private-token"))
        subscription.cancel()
    }

    @Test func muxStreamFailsClosedWhenTheConsumerBufferSaturates() async throws {
        let payload = String(repeating: "x", count: 128 * 1_024)
        let frames = try (1...8).map { sequence in
            try muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/buffer",
                "event": [
                    "type": "assistant/chunk", "seq": sequence, "time": Double(sequence),
                    "data": [
                        "turn": 1, "step": 1,
                        "chunk": ["type": "text-delta", "index": 0, "text": payload]
                    ]
                ]
            ])
        }
        HarnessMockURLProtocol.store.set { request in
            guard let url = request.url,
                  let response = HTTPURLResponse(
                    url: url, statusCode: 200, httpVersion: nil,
                    headerFields: ["Content-Type": "text/event-stream"]
                  ) else { throw URLError(.badServerResponse) }
            let wire = frames.joined(separator: "\n")
            return .init(response: response, data: Data(wire.utf8))
        }

        let rpc = client(limits: HarnessRPCClientLimits(
            muxFrameBytes: 256 * 1_024,
            muxBufferedEvents: 2
        ))
        let subscription = try rpc.muxEvents()
        try await subscription.waitUntilOpen()
        try await Task.sleep(for: .milliseconds(80))
        var received = 0
        var receivedBytes = 0
        do {
            for try await event in subscription.events {
                received += 1
                if case .assistantTextDelta(let value) = event {
                    receivedBytes += value.text.utf8.count
                }
            }
            Issue.record("Expected the bounded stream to fail")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseTooLarge(limit: 2))
        } catch {
            Issue.record("Unexpected stream error: \(error)")
        }
        #expect(received <= 2)
        #expect(receivedBytes <= 256 * 1_024)
    }

    @Test func muxSubscriptionCancellationStopsTheUnderlyingRequest() async throws {
        let started = AsyncTestSignal()
        HarnessMockURLProtocol.store.set { request in
            started.signal()
            guard let url = request.url,
                  let response = HTTPURLResponse(
                    url: url, statusCode: 200, httpVersion: nil,
                    headerFields: ["Content-Type": "text/event-stream"]
                  ) else { throw URLError(.badServerResponse) }
            return .init(response: response, data: Data(), delay: 5)
        }
        let rpc = client()
        let subscription = try rpc.muxEvents()
        await started.wait()
        subscription.cancel()
        do {
            for try await _ in subscription.events {}
            Issue.record("Expected cancellation")
        } catch let error as HarnessRPCClientError {
            #expect(error == .cancelled)
        }
    }
}

private func muxEnvelope(rpcID: String = "mux/rpc:1", method: String, payload: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: [
        "type": "server-request", "rpcId": rpcID, "method": method, "payload": payload
    ], options: [.sortedKeys])
    return try #require(String(data: data, encoding: .utf8))
}

@Suite(.serialized)
struct HarnessMuxFrameDecoderTests {
    @Test func decoderAuthenticatesBoundedAutomaticContinuationSources() throws {
        func frame(source: [String: Any], sequence: Int = 1) throws -> Data {
            Data(try muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "user/message", "seq": sequence, "time": sequence,
                    "data": [
                        "id": "message/\(sequence)", "role": "user",
                        "content": [["type": "text", "text": "private continuation instructions"]],
                        "source": source
                    ]
                ]
            ]).utf8)
        }

        let progress = try #require(try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: [
            "kind": "plugin",
            "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
            "form": "notice",
            "summary": "Fulmar continued automatically · 1/12"
        ])))
        guard case .userMessage(let progressMessage) = progress else {
            Issue.record("Expected a typed continuation message")
            return
        }
        #expect(progressMessage.automaticContinuation == .init(
            round: 1,
            maximum: 12,
            isTerminalBudgetNotice: false
        ))
        #expect(progressMessage.sourceRPCID == nil)
        #expect(!progressMessage.isDirectUserMessage)

        let terminal = try #require(try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: [
            "kind": "plugin",
            "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
            "form": "notice",
            "summary": "Fulmar reached its automatic-continuation safety limit"
        ], sequence: 2)))
        guard case .userMessage(let terminalMessage) = terminal else {
            Issue.record("Expected a typed terminal continuation message")
            return
        }
        #expect(terminalMessage.automaticContinuation?.isTerminalBudgetNotice == true)

        for hostileSource: [String: Any] in [
            ["kind": "user", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 1/12"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "instructions", "summary": "Fulmar continued automatically · 1/12"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 0/12"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 01/12"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 1/33"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 1/11"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 1/32"],
            ["kind": "plugin", "plugin": HarnessAutomaticContinuationNotice.pluginIdentifier,
             "form": "notice", "summary": "Fulmar continued automatically · 1/12", "rpcId": "spoof"]
        ] {
            #expect(throws: HarnessMuxFrameError.invalidPayload) {
                _ = try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: hostileSource))
            }
        }

        let ordinary = try #require(try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: [
            "kind": "user", "rpcId": "prompt-rpc"
        ], sequence: 3)))
        guard case .userMessage(let ordinaryMessage) = ordinary else {
            Issue.record("Expected an ordinary user message")
            return
        }
        #expect(ordinaryMessage.sourceRPCID == "prompt-rpc")
        #expect(ordinaryMessage.isDirectUserMessage)
        #expect(ordinaryMessage.automaticContinuation == nil)

        for spoofedHumanSource: [String: Any] in [
            ["kind": "user"],
            ["kind": "user", "rpcId": "prompt-rpc", "plugin": "another-plugin"],
            ["kind": "user", "rpcId": "prompt-rpc", "form": "notice"],
            ["kind": "user", "rpcId": "prompt-rpc", "summary": "not human provenance"]
        ] {
            #expect(throws: HarnessMuxFrameError.invalidPayload) {
                _ = try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: spoofedHumanSource))
            }
        }
    }

    @Test func decoderHandlesAllRequiredEventKinds() throws {
        let frames: [String] = try [
            muxEnvelope(method: "session/subscribed", payload: [
                "type": "session/subscribed", "sessionId": "session/1", "lastSeq": 4
            ]),
            muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "assistant/chunk", "seq": 5, "time": 10,
                    "data": ["turn": 1, "step": 0, "chunk": ["type": "text-delta", "index": 2, "text": "Hi"]]
                ]
            ]),
            muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "assistant/message", "seq": 6, "time": 11,
                    "data": [
                        "turn": 1, "step": 0, "interrupted": true,
                        "message": [
                            "id": "message/1", "role": "assistant",
                            "content": [["type": "text", "text": "Hello"], ["type": "reasoning", "text": "hidden"]],
                            "source": ["kind": "model", "provider": "ollama", "model": "qwen/model:27b"]
                        ]
                    ]
                ]
            ]),
            muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "tool/call", "seq": 7, "time": 11.5,
                    "data": [
                        "turn": 1, "step": 0, "callId": "call/1", "name": "Bash",
                        "arguments": #"{"cmd":"swift test"}"#
                    ]
                ]
            ]),
            muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "turn/end", "seq": 7, "time": 12,
                    "data": ["turn": 1, "reason": ["kind": "completed"]]
                ]
            ]),
            muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "turn/end", "seq": 8, "time": 13,
                    "data": ["turn": 2, "reason": [
                        "kind": "error", "error": ["message": "provider failed", "code": "UPSTREAM", "status": 429]
                    ]]
                ]
            ]),
            muxEnvelope(rpcID: "approval/rpc", method: "approval/requested", payload: [
                "type": "approval/requested", "sessionId": "session/1", "approvalId": "approval/1",
                "toolName": "Bash", "callId": "call/1", "reason": "Needs workspace access"
            ]),
            muxEnvelope(method: "approval/resolved", payload: [
                "type": "approval/resolved", "sessionId": "session/1", "approvalId": "approval/1", "outcome": "allowed-once"
            ]),
            muxEnvelope(rpcID: "question/rpc", method: "question/requested", payload: [
                "type": "question/requested", "sessionId": "session/1", "questions": [[
                    "id": "q1", "question": "Choose", "header": "Stack", "detail": "One option",
                    "options": [["label": "SwiftUI", "description": "Native"]], "multiSelect": false,
                    "intent": ["kind": "plan-review", "approve": "SwiftUI"]
                ]]
            ]),
            muxEnvelope(method: "question/resolved", payload: [
                "type": "question/resolved", "sessionId": "session/1", "questionRpcId": "question/rpc", "outcome": "answered"
            ]),
            muxEnvelope(method: "stream/error", payload: [
                "type": "stream/error", "error": ["code": "internal", "message": "stream failed", "details": [:]]
            ])
        ]
        let events = try frames.compactMap {
            try HarnessMuxFrameDecoder.decodeMuxFrame(Data($0.utf8), maximumBytes: 65_536)
        }

        #expect(events.count == 11)
        guard case .subscribed(let subscribed) = events[0] else { Issue.record("Missing subscribed"); return }
        #expect(subscribed.lastSequence == 4)
        guard case .assistantTextDelta(let delta) = events[1] else { Issue.record("Missing delta"); return }
        #expect(delta.blockIndex == 2 && delta.text == "Hi")
        guard case .assistantFinalMessage(let final) = events[2] else { Issue.record("Missing final"); return }
        #expect(final.text == "Hello")
        #expect(final.model == ModelID("qwen/model:27b"))
        #expect(final.interrupted)
        guard case .toolCall(let toolCall) = events[3] else { Issue.record("Missing tool call"); return }
        #expect(toolCall.callID == "call/1")
        #expect(toolCall.argumentsJSON.contains("swift test"))
        guard case .turnCompleted(let completed) = events[4] else { Issue.record("Missing completion"); return }
        #expect(completed.reason == .completed)
        guard case .turnFailed(let failed) = events[5] else { Issue.record("Missing turn failure"); return }
        #expect(failed.failure.status == 429)
        guard case .approvalRequested(let approval) = events[6] else { Issue.record("Missing approval"); return }
        #expect(approval.rpcID == "approval/rpc")
        guard case .questionRequested(let question) = events[8] else { Issue.record("Missing question"); return }
        #expect(question.questions[0].options?[0].label == "SwiftUI")
        guard case .questionResolved(let resolution) = events[9] else { Issue.record("Missing resolution"); return }
        #expect(resolution.questionRPCID == "question/rpc")
        guard case .streamError(let streamError) = events[10] else { Issue.record("Missing stream error"); return }
        #expect(streamError.code == .internalError)
    }

    @Test func assistantSourceIdentifiersAreExactBoundedAndAllOrNothing() throws {
        func frame(source: [String: Any]) throws -> Data {
            Data(try muxEnvelope(method: "session/event", payload: [
                "type": "session/event", "sessionId": "session/1",
                "event": [
                    "type": "assistant/message", "seq": 1, "time": 1,
                    "data": [
                        "turn": 1, "step": 0,
                        "message": [
                            "id": "message/1", "role": "assistant",
                            "content": [["type": "text", "text": "ok"]],
                            "source": source
                        ]
                    ]
                ]
            ]).utf8)
        }

        let provider = "route/acme:west@v1+prod?x=1"
        let model = "model/family:27b@Q4_K_M+tools"
        let valid = try #require(try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: [
            "provider": provider, "model": model
        ])))
        guard case .assistantFinalMessage(let message) = valid else {
            Issue.record("Expected assistant message")
            return
        }
        #expect(message.provider == ProviderID(provider))
        #expect(message.model == ModelID(model))

        for invalidSource: [String: Any] in [
            ["provider": "provider\nforged", "model": model],
            ["provider": "provider\u{202E}forged", "model": model],
            ["provider": String(repeating: "p", count: HarnessCatalogWirePolicy.maximumIdentifierScalars + 1), "model": model],
            ["provider": provider],
            ["model": model]
        ] {
            #expect(throws: HarnessMuxFrameError.invalidPayload) {
                _ = try HarnessMuxFrameDecoder.decodeMuxFrame(try frame(source: invalidSource))
            }
        }
    }

    @Test func unknownCompletionReasonCollapsesWithoutRetainingProviderText() throws {
        let secret = ["sk", "reason", String(repeating: "r", count: 48)].joined(separator: "-")
        let frame = try muxEnvelope(method: "session/event", payload: [
            "type": "session/event", "sessionId": "session/1",
            "event": [
                "type": "turn/end", "seq": 2, "time": 2,
                "data": [
                    "turn": 1,
                    "reason": ["kind": "future-\(secret)", "reason": ["private": secret]]
                ]
            ]
        ])
        let decoded = try #require(try HarnessMuxFrameDecoder.decodeMuxFrame(Data(frame.utf8)))
        guard case .turnCompleted(let completion) = decoded else {
            Issue.record("Expected completion")
            return
        }
        #expect(completion.reason == .other)
        #expect(!String(describing: completion.reason).contains(secret))
    }

    @Test func decoderEnforcesFrameLimitAndRejectsMalformedOrMismatchedFrames() throws {
        #expect(throws: HarnessMuxFrameError.frameLimitExceeded(limit: 4)) {
            _ = try HarnessMuxFrameDecoder.decodeMuxFrame(Data("12345".utf8), maximumBytes: 4)
        }
        let mismatched = try muxEnvelope(method: "approval/requested", payload: [
            "type": "question/requested", "sessionId": "s", "questions": []
        ])
        #expect(throws: HarnessMuxFrameError.invalidEnvelope) {
            _ = try HarnessMuxFrameDecoder.decodeMuxFrame(Data(mismatched.utf8))
        }
        #expect(throws: HarnessMuxFrameError.invalidEnvelope) {
            _ = try HarnessMuxFrameDecoder.decodeMuxFrame(Data([0xff]))
        }
    }

    @Test func decoderIgnoresAnUnknownButInternallyConsistentFutureFrame() throws {
        let future = try muxEnvelope(method: "future/event", payload: [
            "type": "future/event", "schemaVersion": 2
        ])
        #expect(try HarnessMuxFrameDecoder.decodeMuxFrame(Data(future.utf8)) == nil)
    }
}
