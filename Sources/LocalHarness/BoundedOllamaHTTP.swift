import Foundation

/// The single network policy used by every native request to the app-owned
/// Ollama process. Hostname aliases are deliberately excluded so DNS can never
/// participate in this trust boundary.
enum OllamaLoopbackEndpointPolicy {
    static func isAllowed(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "http",
              components.host?.lowercased() == AppOwnedOllamaEndpoint.host,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              let port = components.port,
              (1...65_535).contains(port) else {
            return false
        }
        // URLComponents represents a valid origin-only URL with an empty
        // path. Requests may also carry an absolute path, but never a relative
        // one. The base policy below deliberately admits both origin spellings.
        return components.path.isEmpty || components.path.hasPrefix("/")
    }

    static func isAllowedBase(_ url: URL) -> Bool {
        guard isAllowed(url), let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        return components.path.isEmpty || components.path == "/"
    }
}

struct OllamaResponseBudget {
    let maximumBytes: Int
    private(set) var receivedBytes = 0

    init(maximumBytes: Int) {
        precondition(maximumBytes > 0)
        self.maximumBytes = maximumBytes
    }

    init(maximumBytes: Int, expectedContentLength: Int64) throws {
        self.init(maximumBytes: maximumBytes)
        if expectedContentLength != NSURLSessionTransferSizeUnknown,
           (expectedContentLength < 0 || expectedContentLength > Int64(maximumBytes)) {
            throw OllamaError.responseTooLarge
        }
    }

    mutating func admit(_ data: Data) throws {
        guard data.count <= maximumBytes - receivedBytes else {
            throw OllamaError.responseTooLarge
        }
        receivedBytes += data.count
    }
}

struct BoundedOllamaHTTPResponse {
    let data: Data
    let response: HTTPURLResponse
}

/// A redirect-denying, cumulatively bounded URLSession data task. It checks the
/// declared body length before accepting bytes and checks every delivered chunk
/// before appending it, so neither fixed-length nor chunked responses can make
/// the process buffer past `maximumBytes`.
final class BoundedOllamaHTTPTask: NSObject, URLSessionDataDelegate {
    private let request: URLRequest
    private let maximumBytes: Int
    private let timeout: TimeInterval
    private let completion: (Result<BoundedOllamaHTTPResponse, Error>) -> Void
    private var session: URLSession?
    private var budget: OllamaResponseBudget?
    private var body = Data()
    private var receivedResponse: HTTPURLResponse?
    private var completed = false

    init(
        request: URLRequest,
        maximumBytes: Int,
        timeout: TimeInterval = 15,
        completion: @escaping (Result<BoundedOllamaHTTPResponse, Error>) -> Void
    ) {
        precondition(maximumBytes > 0)
        self.request = request
        self.maximumBytes = maximumBytes
        self.timeout = max(0.25, min(timeout, 60))
        self.completion = completion
    }

    func start() {
        guard let url = request.url, OllamaLoopbackEndpointPolicy.isAllowed(url) else {
            finish(.failure(OllamaError.ownedEndpointUnavailable))
            return
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        self.session = session
        session.dataTask(with: request).resume()
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

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        guard let response = response as? HTTPURLResponse,
              let requestedURL = request.url,
              response.url == requestedURL,
              OllamaLoopbackEndpointPolicy.isAllowed(requestedURL) else {
            finish(.failure(OllamaError.invalidResponse))
            completionHandler(.cancel)
            return
        }
        do {
            budget = try OllamaResponseBudget(
                maximumBytes: maximumBytes,
                expectedContentLength: response.expectedContentLength
            )
            receivedResponse = response
            if response.expectedContentLength > 0 {
                body.reserveCapacity(min(maximumBytes, Int(response.expectedContentLength)))
            }
            completionHandler(.allow)
        } catch {
            finish(.failure(error))
            completionHandler(.cancel)
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard var budget else {
            finish(.failure(OllamaError.invalidResponse))
            return
        }
        do {
            try budget.admit(data)
            self.budget = budget
            body.append(data)
        } catch {
            finish(.failure(error))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard !completed else { return }
        if let error {
            finish(.failure(error))
        } else if let receivedResponse {
            finish(.success(BoundedOllamaHTTPResponse(data: body, response: receivedResponse)))
        } else {
            finish(.failure(OllamaError.invalidResponse))
        }
    }

    private func finish(_ result: Result<BoundedOllamaHTTPResponse, Error>) {
        guard !completed else { return }
        completed = true
        switch result {
        case .success:
            session?.finishTasksAndInvalidate()
        case .failure:
            session?.invalidateAndCancel()
        }
        completion(result)
    }
}
