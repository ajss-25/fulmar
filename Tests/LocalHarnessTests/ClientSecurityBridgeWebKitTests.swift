import AppKit
import Darwin
import Foundation
import Testing
import WebKit
@testable import LocalHarness

private enum ClientBridgeLoopbackFixtureError: Error {
    case socket(Int32)
}

/// Serves the exact reviewed browser bundle over an ephemeral IPv4 loopback
/// origin. Web Crypto's `randomUUID` is secure-context-only, so a real HTTP
/// navigation is materially different from loading a string into a Node VM.
private final class ClientBridgeLoopbackFixture: @unchecked Sendable {
    let port: Int

    private let descriptor: Int32
    private let html: Data
    private let clientScript: Data
    private let lock = NSLock()
    private var paths: [String] = []

    init(clientScript: Data) throws {
        self.clientScript = clientScript
        html = Data(Self.page.utf8)

        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ClientBridgeLoopbackFixtureError.socket(errno) }
        var noSignal: Int32 = 1
        _ = setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSignal,
            socklen_t(MemoryLayout<Int32>.size)
        )

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
        guard bound == 0, Darwin.listen(descriptor, 2) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw ClientBridgeLoopbackFixtureError.socket(code)
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
            throw ClientBridgeLoopbackFixtureError.socket(code)
        }
        self.port = Int(UInt16(bigEndian: address.sin_port))
        self.descriptor = descriptor

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.serveTwoRequests()
        }
    }

    deinit {
        _ = Darwin.shutdown(descriptor, SHUT_RDWR)
        Darwin.close(descriptor)
    }

    func requestedPaths() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return paths
    }

    private func serveTwoRequests() {
        for _ in 0..<2 {
            var peer = sockaddr()
            var peerLength = socklen_t(MemoryLayout<sockaddr>.size)
            let client = Darwin.accept(descriptor, &peer, &peerLength)
            guard client >= 0 else { return }
            serve(client)
        }
    }

    private func serve(_ client: Int32) {
        defer {
            _ = Darwin.shutdown(client, SHUT_RDWR)
            Darwin.close(client)
        }
        var noSignal: Int32 = 1
        _ = setsockopt(
            client,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSignal,
            socklen_t(MemoryLayout<Int32>.size)
        )
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = setsockopt(
            client,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        _ = setsockopt(
            client,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )

        var request = Data()
        var buffer = [UInt8](repeating: 0, count: 2_048)
        while request.count <= 32 * 1_024,
              !request.contains(Data("\r\n\r\n".utf8)) {
            let count = Darwin.read(client, &buffer, buffer.count)
            guard count > 0 else { return }
            request.append(contentsOf: buffer.prefix(count))
        }
        guard let text = String(data: request, encoding: .utf8),
              let requestLine = text.components(separatedBy: "\r\n").first else { return }
        let fields = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count == 3, fields[0] == "GET" else { return }
        let path = String(fields[1])
        lock.lock()
        paths.append(path)
        lock.unlock()

        let body: Data
        let contentType: String
        let status: String
        switch path {
        case "/":
            body = html
            contentType = "text/html; charset=utf-8"
            status = "200 OK"
        case "/client.js":
            body = clientScript
            contentType = "text/javascript; charset=utf-8"
            status = "200 OK"
        default:
            body = Data()
            contentType = "text/plain; charset=utf-8"
            status = "404 Not Found"
        }
        let headers = Data((
            "HTTP/1.1 \(status)\r\n" +
            "Content-Type: \(contentType)\r\n" +
            "Content-Length: \(body.count)\r\n" +
            "Cache-Control: no-store\r\n" +
            "X-Content-Type-Options: nosniff\r\n" +
            "Connection: close\r\n\r\n"
        ).utf8)
        guard Self.write(headers, to: client) else { return }
        _ = Self.write(body, to: client)
    }

    private static func write(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return true }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
    }

    private static let page = #"""
    <!doctype html>
    <meta charset="utf-8">
    <script>
    window.__ModuleLoader__ = {
      load(value) { window.__clientSecurityRegistration = value; }
    };
    </script>
    <script src="/client.js"></script>
    <script>
    (() => {
      const events = [];
      const sessionID = "webkit-client-security-session";
      const snapshot = {
        current: sessionID,
        ids: [sessionID],
        byId: { [sessionID]: { id: sessionID, blank: false } }
      };
      const sessions = {
        list: { getSnapshot: () => snapshot, subscribe: () => () => {} },
        async create() { throw new Error("unexpected session creation"); },
        open() { throw new Error("unexpected session selection"); }
      };
      const workspaces = {
        list: {
          getSnapshot: () => ({
            baselinesReady: true,
            recentWorkspaceId: "workspace",
            items: [{ workspaceId: "workspace", path: "/webkit-workspace", sessionIds: [sessionID] }]
          }),
          subscribe: () => () => {}
        },
        async create() { throw new Error("unexpected workspace creation"); }
      };
      const conversation = {
        scopedSession: () => ({ sessionId: sessionID }),
        async send(text) { events.push(["send", text]); return "sent"; },
        async sendSession(session, text, imageIds, mode) {
          events.push(["sendSession", session.sessionId, text, imageIds, mode]);
          return { kind: "success" };
        }
      };
      let dispose;
      const plugin = window.__clientSecurityRegistration.factory();
      plugin.apply({
        sessions,
        workspaces,
        conversation,
        effect(factory) { dispose = factory(); }
      });
      window.__runFulmarClientBridgeProbe = async () => {
        const independentUUID = crypto.randomUUID();
        const result = await conversation.sendSession(
          { sessionId: sessionID },
          "webkit bridge proof",
          [],
          "queue"
        );
        return JSON.stringify({
          isSecureContext,
          globalMatchesWindow: globalThis === window,
          independentUUID,
          result,
          events
        });
      };
      window.__disposeFulmarClientBridgeProbe = () => dispose?.();
    })();
    </script>
    """#
}

private final class ClientBridgeNavigationWaiter: NSObject, WKNavigationDelegate {
    private enum WaitError: Error { case timedOut }

    private var result: Result<Void, Error>?
    private var continuation: CheckedContinuation<Void, Error>?
    private var timeoutTask: Task<Void, Never>?

    func wait() async throws {
        if let result {
            try result.get()
            return
        }
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            timeoutTask = Task { @MainActor [weak self] in
                do { try await Task.sleep(for: .seconds(10)) } catch { return }
                self?.resolve(.failure(WaitError.timedOut))
            }
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        resolve(.success(()))
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation!,
        withError error: Error
    ) {
        resolve(.failure(error))
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        resolve(.failure(error))
    }

    private func resolve(_ result: Result<Void, Error>) {
        guard self.result == nil else { return }
        self.result = result
        timeoutTask?.cancel()
        timeoutTask = nil
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(with: result)
    }
}

private final class ClientBridgeRecoveryReplyHandler: NSObject, WKScriptMessageHandlerWithReply {
    private(set) var messages: [[String: Any]] = []

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping (Any?, String?) -> Void
    ) {
        guard message.frameInfo.isMainFrame,
              let body = message.body as? [String: Any] else {
            replyHandler(nil, "invalid test recovery request")
            return
        }
        messages.append(body)
        replyHandler(["ok": true, "mode": "protected"], nil)
    }
}

private func isExactUUIDv4(_ value: String) -> Bool {
    value.range(
        of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
        options: [.regularExpression, .caseInsensitive]
    ) != nil
}

@Test @MainActor
func exactServedClientBridgeUsesWebCryptoInARealLoopbackWKWebView() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let project = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let reviewedClient = project
        .appendingPathComponent("Resources/DSHPlugins/client-security-bridge/client.js")
    let exactBytes = try Data(contentsOf: reviewedClient, options: [.mappedIfSafe])
    let fixture = try ClientBridgeLoopbackFixture(clientScript: exactBytes)
    let handler = ClientBridgeRecoveryReplyHandler()
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    configuration.userContentController.addScriptMessageHandler(
        handler,
        contentWorld: .page,
        name: "localHarnessRecovery"
    )
    let webView = WKWebView(frame: .zero, configuration: configuration)
    let waiter = ClientBridgeNavigationWaiter()
    webView.navigationDelegate = waiter
    let url = try #require(URL(string: "http://127.0.0.1:\(fixture.port)/"))
    webView.load(URLRequest(url: url))
    try await waiter.wait()

    let value: Any? = try await withCheckedThrowingContinuation { continuation in
        webView.callAsyncJavaScript(
            "return await window.__runFulmarClientBridgeProbe();",
            arguments: [:],
            in: nil,
            in: .page
        ) { result in
            continuation.resume(with: result)
        }
    }
    let text = try #require(value as? String)
    let object = try #require(
        JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
    )
    let independentUUID = try #require(object["independentUUID"] as? String)
    let result = try #require(object["result"] as? [String: Any])
    let events = try #require(object["events"] as? [[Any]])
    #expect(object["isSecureContext"] as? Bool == true)
    #expect(object["globalMatchesWindow"] as? Bool == true)
    #expect(isExactUUIDv4(independentUUID))
    #expect(result["kind"] as? String == "success")
    #expect(events.count == 1)
    #expect(events[0][0] as? String == "sendSession")
    #expect(events[0][1] as? String == "webkit-client-security-session")

    let message = try #require(handler.messages.first)
    let operationID = try #require(message["operationID"] as? String)
    let operationUUID = try #require(UUID(uuidString: operationID))
    #expect(handler.messages.count == 1)
    #expect((message["version"] as? NSNumber)?.intValue == 2)
    #expect(message["action"] as? String == "prepare")
    #expect(message["sessionID"] as? String == "webkit-client-security-session")
    #expect(isExactUUIDv4(operationID))
    #expect(operationID != independentUUID)
    #expect(RecoveryBridgeRequest.decode(message) == .prepare(
        operationID: operationUUID,
        sessionID: HarnessSessionID("webkit-client-security-session")
    ))
    #expect(fixture.requestedPaths() == ["/", "/client.js"])

    let _: Any? = try? await withCheckedThrowingContinuation { continuation in
        webView.callAsyncJavaScript(
            "window.__disposeFulmarClientBridgeProbe();",
            arguments: [:],
            in: nil,
            in: .page
        ) { result in
            continuation.resume(with: result)
        }
    }
    configuration.userContentController.removeScriptMessageHandler(
        forName: "localHarnessRecovery",
        contentWorld: .page
    )
}
