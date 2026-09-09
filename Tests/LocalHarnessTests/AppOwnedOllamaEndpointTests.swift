import Darwin
import Foundation
import Testing
@testable import LocalHarness

private enum OneShotHTTPFixtureError: Error {
    case socket(Int32)
}

/// A deliberately tiny raw HTTP fixture used to prove URLSession's real
/// delegate path, including transfer-decoded chunked responses. It listens only
/// on literal IPv4 loopback and serves exactly one request.
private final class OneShotHTTPFixture: @unchecked Sendable {
    let endpoint: AppOwnedOllamaEndpoint
    private let descriptor: Int32

    init(response: Data, holdOpen: TimeInterval = 0) throws {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw OneShotHTTPFixtureError.socket(errno) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr(AppOwnedOllamaEndpoint.host))
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, Darwin.listen(descriptor, 1) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw OneShotHTTPFixtureError.socket(code)
        }

        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }
        let port = Int(UInt16(bigEndian: address.sin_port))
        guard named == 0, let endpoint = AppOwnedOllamaEndpoint(port: port) else {
            let code = errno == 0 ? EINVAL : errno
            Darwin.close(descriptor)
            throw OneShotHTTPFixtureError.socket(code)
        }
        self.descriptor = descriptor
        self.endpoint = endpoint

        DispatchQueue.global(qos: .userInitiated).async {
            var peer = sockaddr()
            var peerLength = socklen_t(MemoryLayout<sockaddr>.size)
            let client = Darwin.accept(descriptor, &peer, &peerLength)
            guard client >= 0 else {
                Darwin.close(descriptor)
                return
            }
            var noSignal: Int32 = 1
            _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            var requestBuffer = [UInt8](repeating: 0, count: 4_096)
            _ = Darwin.read(client, &requestBuffer, requestBuffer.count)
            response.withUnsafeBytes { rawBuffer in
                guard let base = rawBuffer.baseAddress else { return }
                var sent = 0
                while sent < rawBuffer.count {
                    let count = Darwin.write(client, base.advanced(by: sent), rawBuffer.count - sent)
                    guard count > 0 else { break }
                    sent += count
                }
            }
            if holdOpen > 0 { Thread.sleep(forTimeInterval: min(holdOpen, 3)) }
            _ = Darwin.shutdown(client, SHUT_RDWR)
            Darwin.close(client)
            Darwin.close(descriptor)
        }
    }
}

private func boundedFixtureRequest(
    _ endpoint: AppOwnedOllamaEndpoint,
    maximumBytes: Int,
    timeout: TimeInterval = 2
) async throws -> BoundedOllamaHTTPResponse {
    var request = URLRequest(url: endpoint.tagsURL)
    request.httpMethod = "GET"
    return try await withCheckedThrowingContinuation { continuation in
        BoundedOllamaHTTPTask(request: request, maximumBytes: maximumBytes, timeout: timeout) {
            continuation.resume(with: $0)
        }.start()
    }
}

@Test func descriptorBufferPlanningRejectsEveryUnsafeNarrowing() throws {
    let stride = MemoryLayout<proc_fdinfo>.stride
    let requiredBytes = try #require(Int32(exactly: stride * 3))
    let regular = try #require(OwnedLoopbackListenerVerifier.descriptorBufferPlan(
        requiredBytes: requiredBytes,
        stride: stride
    ))
    let expectedByteCount = try #require(Int32(exactly: regular.capacity * stride))
    #expect(regular.capacity == 11)
    #expect(regular.byteCount == expectedByteCount)

    #expect(OwnedLoopbackListenerVerifier.descriptorBufferPlan(
        requiredBytes: 0,
        stride: stride
    )?.capacity == nil)
    #expect(OwnedLoopbackListenerVerifier.descriptorBufferPlan(
        requiredBytes: -1,
        stride: stride
    )?.capacity == nil)
    #expect(OwnedLoopbackListenerVerifier.descriptorBufferPlan(
        requiredBytes: Int32.max,
        stride: 1
    )?.capacity == nil)
    #expect(OwnedLoopbackListenerVerifier.descriptorBufferPlan(
        requiredBytes: 1,
        stride: Int.max
    )?.capacity == nil)
}

@Test func ollamaClientAcceptsOnlyABoundedCompatibleOfficialVersionResponse() async throws {
    let body = "{\"version\":\"0.33.2\"}\n"
    let accepted = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)".utf8
    ))
    let client = OllamaClient { accepted.endpoint.baseURL }
    #expect(try await client.fetchCompatibleVersion() == OllamaVersionCompatibilityPolicy.tested)

    let oversized = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 200 OK\r\nContent-Length: \(OllamaVersionCompatibilityPolicy.maximumResponseBytes + 1)\r\nConnection: close\r\n\r\n".utf8
    ))
    let oversizedClient = OllamaClient { oversized.endpoint.baseURL }
    do {
        _ = try await oversizedClient.fetchCompatibleVersion()
        Issue.record("An oversized Ollama version response was admitted")
    } catch {
        #expect(error as? OllamaVersionCompatibilityError == .unavailable)
    }

    let missing = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8
    ))
    let missingClient = OllamaClient { missing.endpoint.baseURL }
    do {
        _ = try await missingClient.fetchCompatibleVersion()
        Issue.record("A missing official Ollama version endpoint was admitted")
    } catch {
        #expect(error as? OllamaVersionCompatibilityError == .unavailable)
    }
}

@Test func appOwnedOllamaEndpointAcceptsOnlyExactLiteralLoopbackProviderURLs() {
    let endpoint = AppOwnedOllamaEndpoint(port: 49_152)
    #expect(endpoint?.baseURL.absoluteString == "http://127.0.0.1:49152/")
    #expect(endpoint?.versionURL.absoluteString == "http://127.0.0.1:49152/api/version")
    #expect(endpoint?.tagsURL.absoluteString == "http://127.0.0.1:49152/api/tags")
    #expect(endpoint?.providerBaseURL.absoluteString == "http://127.0.0.1:49152/v1")
    #expect(AppOwnedOllamaEndpoint.validatingProviderBaseURL(
        URL(string: "http://127.0.0.1:49152/v1")!
    ) == endpoint)

    for invalid in [
        "http://localhost:49152/v1",
        "http://[::1]:49152/v1",
        "https://127.0.0.1:49152/v1",
        "http://127.0.0.1/v1",
        "http://127.0.0.1:49152/other",
        "http://127.0.0.1:49152/v1?redirect=1",
        "http://user:secret@127.0.0.1:49152/v1"
    ] {
        #expect(AppOwnedOllamaEndpoint.validatingProviderBaseURL(URL(string: invalid)!) == nil)
    }
}

@Test func loopbackReservationsAreEphemeralExclusiveAndPIDVerifiable() throws {
    let first = try LoopbackPortReservation.reserve()
    let second = try LoopbackPortReservation.reserve()

    #expect(first.endpoint.port != second.endpoint.port)
    #expect(OwnedLoopbackListenerVerifier.process(getpid(), owns: first.endpoint))
    #expect(OwnedLoopbackListenerVerifier.process(getpid(), owns: second.endpoint))

    let wrongPort = try #require((49_152...65_535).first {
        $0 != first.endpoint.port && $0 != second.endpoint.port
    })
    let wrong = try #require(AppOwnedOllamaEndpoint(port: wrongPort))
    #expect(!OwnedLoopbackListenerVerifier.process(getpid(), owns: wrong))

    first.releaseForLaunch()
    #expect(!OwnedLoopbackListenerVerifier.process(getpid(), owns: first.endpoint))
    #expect(OwnedLoopbackListenerVerifier.process(getpid(), owns: second.endpoint))
}

@Test func childEnvironmentNeverInventsAConventionalOllamaEndpoint() {
    let environment = ChildProcessEnvironment.make(nodeBin: nil)
    #expect(environment["OLLAMA_HOST"] == nil)
    #expect(environment["OLLAMA_API_KEY"] == nil)
}

@Test func arbitraryOriginSerializationCanCarryOnlyTheExactOwnedListener() throws {
    let endpoint = try #require(AppOwnedOllamaEndpoint(port: 49_152))
    let encoded = ProviderEgressPolicy.serializedAllowlist(
        origins: [endpoint.networkOrigin],
        boundary: .onDevice
    )
    let decoded = try JSONDecoder().decode([ProviderRuntimeNetworkOrigin].self, from: Data(encoded.utf8))
    #expect(decoded == [ProviderRuntimeNetworkOrigin(origin: endpoint.networkOrigin, boundary: .onDevice)])
    #expect(!encoded.contains("/v1"))
    #expect(!encoded.contains("11434"))
}

@Test func ollamaResponseBudgetRejectsDeclaredAndCumulativeChunkedOversize() throws {
    #expect(throws: OllamaError.responseTooLarge) {
        _ = try OllamaResponseBudget(maximumBytes: 10, expectedContentLength: 11)
    }

    var chunked = OllamaResponseBudget(maximumBytes: 10)
    try chunked.admit(Data(repeating: 0x61, count: 4))
    try chunked.admit(Data(repeating: 0x0A, count: 3))
    try chunked.admit(Data(repeating: 0x62, count: 3))
    #expect(chunked.receivedBytes == 10)
    #expect(throws: OllamaError.responseTooLarge) {
        try chunked.admit(Data([0x63]))
    }
    #expect(chunked.receivedBytes == 10)
}

@Test func realLoopbackTransportRejectsDeclaredAndChunkedOversizeBeforeSuccess() async throws {
    let declared = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world".utf8
    ))
    do {
        _ = try await boundedFixtureRequest(declared.endpoint, maximumBytes: 10)
        Issue.record("A declared oversized response was accepted")
    } catch {
        #expect(error as? OllamaError == .responseTooLarge)
    }

    let chunked = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\naaaa\r\n3\r\nbbb\r\n4\r\ncccc\r\n0\r\n\r\n".utf8
    ))
    do {
        _ = try await boundedFixtureRequest(chunked.endpoint, maximumBytes: 10)
        Issue.record("A cumulatively oversized chunked response was accepted")
    } catch {
        #expect(error as? OllamaError == .responseTooLarge)
    }
}

@Test func realLoopbackTransportHandlesUnframedBodiesRedirectsAndTimeoutExactlyOnce() async throws {
    let unframed = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello".utf8
    ))
    let accepted = try await boundedFixtureRequest(unframed.endpoint, maximumBytes: 5)
    #expect(accepted.response.statusCode == 200)
    #expect(accepted.data == Data("hello".utf8))

    let redirect = try OneShotHTTPFixture(response: Data(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/escape\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8
    ))
    do {
        _ = try await boundedFixtureRequest(redirect.endpoint, maximumBytes: 64)
        Issue.record("A loopback redirect was accepted")
    } catch {
        #expect(error as? OllamaError == .redirectDenied)
    }

    let stalled = try OneShotHTTPFixture(
        response: Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n".utf8),
        holdOpen: 1
    )
    do {
        _ = try await boundedFixtureRequest(stalled.endpoint, maximumBytes: 64, timeout: 0.25)
        Issue.record("A response that never finished bypassed the hard timeout")
    } catch {
        #expect((error as? URLError)?.code == .timedOut)
    }
}

@Test func ollamaModelNamesRejectInvisibleAndRouteAmbiguousValues() {
    for valid in [
        "qwen3.8:27b-mlx",
        "team/coder:Q6_K",
        "registry.example:5000/library/model:latest"
    ] {
        #expect(OllamaModelNamePolicy.isSafe(valid))
    }
    for invalid in [
        "", " leading", "trailing ", "two words", "../escape", "team//model",
        "model\nnext", "model\u{202E}hidden", String(repeating: "a", count: 513)
    ] {
        #expect(!OllamaModelNamePolicy.isSafe(invalid))
    }
}
