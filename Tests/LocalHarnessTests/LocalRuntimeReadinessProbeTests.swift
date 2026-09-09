import Darwin
import Foundation
import Testing
@testable import LocalHarness

private enum ReadinessFixtureError: Error {
    case socket(Int32)
}

private struct ScriptedHTTPResponse: Sendable {
    let data: Data
    let holdOpen: TimeInterval

    init(_ text: String, holdOpen: TimeInterval = 0) {
        data = Data(text.utf8)
        self.holdOpen = holdOpen
    }
}

/// A literal-IPv4 loopback server that serves a fixed sequence of replies.
/// It intentionally does not implement HTTP semantics beyond what URLSession
/// needs, making malformed framing, redirects, and stalls fully controllable.
private final class ScriptedHTTPFixture: @unchecked Sendable {
    let endpoint: AppOwnedOllamaEndpoint
    private let descriptor: Int32

    init(responses: [ScriptedHTTPResponse]) throws {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ReadinessFixtureError.socket(errno) }

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
        guard bound == 0, Darwin.listen(descriptor, Int32(max(1, responses.count))) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw ReadinessFixtureError.socket(code)
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
            throw ReadinessFixtureError.socket(code)
        }
        self.descriptor = descriptor
        self.endpoint = endpoint

        DispatchQueue.global(qos: .userInitiated).async {
            for response in responses {
                var peer = sockaddr()
                var peerLength = socklen_t(MemoryLayout<sockaddr>.size)
                let client = Darwin.accept(descriptor, &peer, &peerLength)
                guard client >= 0 else { break }
                var noSignal: Int32 = 1
                _ = setsockopt(
                    client,
                    SOL_SOCKET,
                    SO_NOSIGPIPE,
                    &noSignal,
                    socklen_t(MemoryLayout<Int32>.size)
                )
                var request = [UInt8](repeating: 0, count: 8_192)
                _ = Darwin.read(client, &request, request.count)
                response.data.withUnsafeBytes { bytes in
                    guard let base = bytes.baseAddress else { return }
                    var sent = 0
                    while sent < bytes.count {
                        let count = Darwin.write(client, base.advanced(by: sent), bytes.count - sent)
                        guard count > 0 else { break }
                        sent += count
                    }
                }
                if response.holdOpen > 0 {
                    Thread.sleep(forTimeInterval: min(response.holdOpen, 3))
                }
                _ = Darwin.shutdown(client, SHUT_RDWR)
                Darwin.close(client)
            }
            Darwin.close(descriptor)
        }
    }
}

private func harnessProbe(
    endpoint: HarnessEndpoint,
    timeout: TimeInterval = 2
) async -> Bool {
    await withCheckedContinuation { continuation in
        LocalRuntimeReadinessProbe.harnessIdentity(endpoint: endpoint, timeout: timeout) {
            continuation.resume(returning: $0)
        }
    }
}

private func ollamaProbe(
    endpoint: AppOwnedOllamaEndpoint,
    timeout: TimeInterval = 2
) async -> Bool {
    await withCheckedContinuation { continuation in
        LocalRuntimeReadinessProbe.ollamaCatalog(endpoint: endpoint, timeout: timeout) {
            continuation.resume(returning: $0)
        }
    }
}

private func ollamaEventuallyReady(
    endpoint: AppOwnedOllamaEndpoint,
    totalTimeout: TimeInterval = 2,
    attemptTimeout: TimeInterval = 0.25,
    retryDelay: TimeInterval = 0.02,
    boundaryStatus: @escaping () -> OllamaCatalogBoundaryStatus = { .valid }
) async -> OllamaCatalogReadinessOutcome {
    await withCheckedContinuation { continuation in
        LocalRuntimeReadinessProbe.ollamaCatalogUntilReady(
            endpoint: endpoint,
            totalTimeout: totalTimeout,
            attemptTimeout: attemptTimeout,
            retryDelay: retryDelay,
            boundaryStatus: boundaryStatus
        ) { continuation.resume(returning: $0) }
    }
}

private func framed(_ status: String = "200 OK", body: String) -> String {
    "HTTP/1.1 \(status)\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
}

@Test func harnessReadinessRequiresExactHealthThenBoundedRoot() async throws {
    let nonce = "instance-nonce"
    let pid: Int32 = 4_242
    let health = """
    {"service":"\(HarnessEndpoint.serviceIdentifier)","protocolVersion":\(HarnessEndpoint.protocolVersion),"nonce":"\(nonce)","pid":\(pid)}
    """
    let fixture = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(framed(body: health)),
        ScriptedHTTPResponse(framed(body: "ready"))
    ])
    let endpoint = HarnessEndpoint(
        baseURL: fixture.endpoint.baseURL,
        token: "secret-token",
        nonce: nonce,
        processIdentifier: pid
    )
    #expect(await harnessProbe(endpoint: endpoint))
}

@Test func harnessReadinessRejectsIdentityDriftOversizeRedirectAndStall() async throws {
    let wrongHealth = framed(body: """
    {"service":"\(HarnessEndpoint.serviceIdentifier)","protocolVersion":\(HarnessEndpoint.protocolVersion),"nonce":"wrong","pid":42}
    """)
    let wrongFixture = try ScriptedHTTPFixture(responses: [ScriptedHTTPResponse(wrongHealth)])
    let wrongEndpoint = HarnessEndpoint(
        baseURL: wrongFixture.endpoint.baseURL,
        token: "token",
        nonce: "right",
        processIdentifier: 42
    )
    #expect(!(await harnessProbe(endpoint: wrongEndpoint)))

    let oversizeFixture = try ScriptedHTTPFixture(responses: [ScriptedHTTPResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: \(LocalRuntimeReadinessProbe.harnessHealthMaximumBytes + 1)\r\nConnection: close\r\n\r\n"
    )])
    let oversizeEndpoint = HarnessEndpoint(
        baseURL: oversizeFixture.endpoint.baseURL,
        token: "token",
        nonce: "nonce",
        processIdentifier: 1
    )
    #expect(!(await harnessProbe(endpoint: oversizeEndpoint)))

    let validHealth = framed(body: """
    {"service":"\(HarnessEndpoint.serviceIdentifier)","protocolVersion":\(HarnessEndpoint.protocolVersion),"nonce":"nonce","pid":7}
    """)
    let redirectFixture = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(validHealth),
        ScriptedHTTPResponse(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/escape\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    ])
    let redirectEndpoint = HarnessEndpoint(
        baseURL: redirectFixture.endpoint.baseURL,
        token: "token",
        nonce: "nonce",
        processIdentifier: 7
    )
    #expect(!(await harnessProbe(endpoint: redirectEndpoint)))

    let stalledFixture = try ScriptedHTTPFixture(responses: [ScriptedHTTPResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\n",
        holdOpen: 1
    )])
    let stalledEndpoint = HarnessEndpoint(
        baseURL: stalledFixture.endpoint.baseURL,
        token: "token",
        nonce: "nonce",
        processIdentifier: 7
    )
    #expect(!(await harnessProbe(endpoint: stalledEndpoint, timeout: 0.25)))
}

@Test func ollamaReadinessRequiresBoundedNonredirectedModelCatalog() async throws {
    let valid = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(framed(body: "{\"models\":[]}"))
    ])
    #expect(await ollamaProbe(endpoint: valid.endpoint))

    let malformed = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(framed(body: "{\"models\":{}}"))
    ])
    #expect(!(await ollamaProbe(endpoint: malformed.endpoint)))

    let oversized = try ScriptedHTTPFixture(responses: [ScriptedHTTPResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: \(LocalRuntimeReadinessProbe.ollamaCatalogMaximumBytes + 1)\r\nConnection: close\r\n\r\n"
    )])
    #expect(!(await ollamaProbe(endpoint: oversized.endpoint)))

    let redirect = try ScriptedHTTPFixture(responses: [ScriptedHTTPResponse(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/api/tags\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )])
    #expect(!(await ollamaProbe(endpoint: redirect.endpoint)))
}

@Test func ollamaReadinessPollsBoundedlyUntilDelayedCatalogAndRechecksBoundary() async throws {
    let delayed = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(framed("503 Service Unavailable", body: "{}")),
        ScriptedHTTPResponse(framed(body: "{\"models\":{}}")),
        ScriptedHTTPResponse(framed(body: "{\"models\":[]}"))
    ])
    #expect(await ollamaEventuallyReady(endpoint: delayed.endpoint) == .ready)

    let drift = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(framed("503 Service Unavailable", body: "{}"))
    ])
    let lock = NSLock()
    var checks = 0
    let outcome = await ollamaEventuallyReady(endpoint: drift.endpoint) {
        lock.withLock {
            checks += 1
            return checks < 3 ? .valid : .invalid
        }
    }
    #expect(outcome == .boundaryInvalid)
    #expect(lock.withLock { checks } == 3)

    let initiallyPending = try ScriptedHTTPFixture(responses: [
        ScriptedHTTPResponse(framed(body: "{\"models\":[]}"))
    ])
    var pendingChecks = 0
    let pendingOutcome = await ollamaEventuallyReady(endpoint: initiallyPending.endpoint) {
        lock.withLock {
            pendingChecks += 1
            return pendingChecks < 3 ? .pending : .valid
        }
    }
    #expect(pendingOutcome == .ready)
    #expect(lock.withLock { pendingChecks } >= 4)
}
