import Foundation

enum OllamaCatalogReadinessOutcome: Equatable, Sendable {
    case ready
    case timedOut
    case boundaryInvalid
}

enum OllamaCatalogBoundaryStatus: Equatable, Sendable {
    /// The exact child is still starting, but it has not yet proved both its
    /// signed running identity and ownership of the reserved listener. No HTTP
    /// request may be sent in this state.
    case pending
    case valid
    case invalid
}

/// Repeats the bounded one-shot catalog request for a bounded monotonic window.
/// Ollama can bind its listener before `/api/tags` is ready, so socket presence
/// alone is not readiness. The caller-supplied boundary check runs before and
/// after every request, preserving exact PID/listener/signature ownership
/// throughout the startup window.
private final class OllamaCatalogReadinessPoller {
    private let endpoint: AppOwnedOllamaEndpoint
    private let totalTimeout: TimeInterval
    private let attemptTimeout: TimeInterval
    private let retryDelay: TimeInterval
    private let boundaryStatus: () -> OllamaCatalogBoundaryStatus
    private let completion: (OllamaCatalogReadinessOutcome) -> Void
    private let startedAt = DispatchTime.now().uptimeNanoseconds
    private var completed = false

    init(
        endpoint: AppOwnedOllamaEndpoint,
        totalTimeout: TimeInterval,
        attemptTimeout: TimeInterval,
        retryDelay: TimeInterval,
        boundaryStatus: @escaping () -> OllamaCatalogBoundaryStatus,
        completion: @escaping (OllamaCatalogReadinessOutcome) -> Void
    ) {
        self.endpoint = endpoint
        self.totalTimeout = max(0.25, min(totalTimeout, 120))
        self.attemptTimeout = max(0.25, min(attemptTimeout, 10))
        self.retryDelay = max(0.01, min(retryDelay, 2))
        self.boundaryStatus = boundaryStatus
        self.completion = completion
    }

    func start() {
        if Thread.isMainThread { attempt() }
        else { DispatchQueue.main.async { self.attempt() } }
    }

    private func attempt() {
        guard !completed else { return }
        switch boundaryStatus() {
        case .invalid:
            finish(.boundaryInvalid)
            return
        case .pending:
            scheduleRetryOrTimeout()
            return
        case .valid:
            break
        }
        let remaining = remainingSeconds()
        guard remaining >= 0.25 else {
            finish(.timedOut)
            return
        }
        LocalRuntimeReadinessProbe.ollamaCatalog(
            endpoint: endpoint,
            timeout: min(attemptTimeout, remaining)
        ) { [self] ready in
            guard !completed else { return }
            guard boundaryStatus() == .valid else {
                finish(.boundaryInvalid)
                return
            }
            if ready {
                finish(.ready)
                return
            }
            scheduleRetryOrTimeout()
        }
    }

    private func scheduleRetryOrTimeout() {
        let remaining = remainingSeconds()
        guard remaining > retryDelay else {
            finish(.timedOut)
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + retryDelay) { [self] in
            attempt()
        }
    }

    private func remainingSeconds() -> TimeInterval {
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = Double(now - startedAt) / 1_000_000_000
        return max(0, totalTimeout - elapsed)
    }

    private func finish(_ outcome: OllamaCatalogReadinessOutcome) {
        guard !completed else { return }
        completed = true
        completion(outcome)
    }
}

/// Performs the two native control-plane readiness checks without allowing a
/// loopback service to redirect, proxy, stall indefinitely, or make the app
/// buffer an unbounded body. The caller remains responsible for proving that
/// the exact child PID owns the listener before and after these HTTP checks.
enum LocalRuntimeReadinessProbe {
    static let harnessHealthMaximumBytes = 16 * 1_024
    static let harnessRootMaximumBytes = 1 * 1_024 * 1_024
    static let ollamaCatalogMaximumBytes = 5 * 1_024 * 1_024

    static func harnessIdentity(
        endpoint: HarnessEndpoint,
        timeout: TimeInterval = 2,
        completion: @escaping (Bool) -> Void
    ) {
        let healthRequest = endpoint.authenticatedRequest(to: endpoint.healthURL)
        BoundedOllamaHTTPTask(
            request: healthRequest,
            maximumBytes: harnessHealthMaximumBytes,
            timeout: timeout
        ) { healthResult in
            guard case .success(let healthResponse) = healthResult,
                  healthResponse.response.statusCode == 200,
                  let health = try? JSONDecoder().decode(RuntimeHealth.self, from: healthResponse.data),
                  health == RuntimeHealth(
                    service: HarnessEndpoint.serviceIdentifier,
                    protocolVersion: HarnessEndpoint.protocolVersion,
                    nonce: endpoint.nonce,
                    pid: endpoint.processIdentifier
                  ) else {
                completeOnMain(false, completion: completion)
                return
            }

            var rootRequest = endpoint.authenticatedRequest()
            rootRequest.httpMethod = "GET"
            BoundedOllamaHTTPTask(
                request: rootRequest,
                maximumBytes: harnessRootMaximumBytes,
                timeout: timeout
            ) { rootResult in
                guard case .success(let rootResponse) = rootResult else {
                    completeOnMain(false, completion: completion)
                    return
                }
                completeOnMain(
                    (200...299).contains(rootResponse.response.statusCode),
                    completion: completion
                )
            }.start()
        }.start()
    }

    static func ollamaCatalog(
        endpoint: AppOwnedOllamaEndpoint,
        timeout: TimeInterval = 2,
        completion: @escaping (Bool) -> Void
    ) {
        var request = URLRequest(url: endpoint.tagsURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        BoundedOllamaHTTPTask(
            request: request,
            maximumBytes: ollamaCatalogMaximumBytes,
            timeout: timeout
        ) { result in
            guard case .success(let response) = result,
                  response.response.statusCode == 200,
                  let object = try? JSONSerialization.jsonObject(with: response.data) as? [String: Any],
                  object["models"] is [Any] else {
                completeOnMain(false, completion: completion)
                return
            }
            completeOnMain(true, completion: completion)
        }.start()
    }

    static func ollamaCatalogUntilReady(
        endpoint: AppOwnedOllamaEndpoint,
        totalTimeout: TimeInterval = 30,
        attemptTimeout: TimeInterval = 2,
        retryDelay: TimeInterval = 0.5,
        boundaryStatus: @escaping () -> OllamaCatalogBoundaryStatus,
        completion: @escaping (OllamaCatalogReadinessOutcome) -> Void
    ) {
        OllamaCatalogReadinessPoller(
            endpoint: endpoint,
            totalTimeout: totalTimeout,
            attemptTimeout: attemptTimeout,
            retryDelay: retryDelay,
            boundaryStatus: boundaryStatus,
            completion: completion
        ).start()
    }

    private static func completeOnMain(_ value: Bool, completion: @escaping (Bool) -> Void) {
        if Thread.isMainThread {
            completion(value)
        } else {
            DispatchQueue.main.async { completion(value) }
        }
    }
}
