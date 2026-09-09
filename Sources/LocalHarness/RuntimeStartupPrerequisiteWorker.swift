import Foundation

enum RuntimeStartupPrerequisitePhase: String, Equatable, Sendable {
    case bundleIntegrity
    case harnessHomePreflight
    case ollamaLaunchPlan
    case harnessLaunchPlan
    case skillActivation
    case mcpActivation
    case sandboxBoundary
}

enum RuntimeStartupPrerequisiteError: Error, Equatable, LocalizedError {
    case cancelled
    case timedOut

    var errorDescription: String? {
        switch self {
        case .cancelled:
            return "Secure runtime preparation was cancelled before launch."
        case .timedOut:
            return "Secure runtime preparation exceeded its bounded startup deadline."
        }
    }
}

final class RuntimeStartupPrerequisiteCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var settled = false
    private var settlementObservers: [() -> Void] = []

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    var isSettled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return settled
    }

    /// Registers an exact-operation settlement barrier. Observers always run
    /// on the main queue, including observers registered after settlement, so
    /// lifecycle state remains single-threaded. Cancellation alone is not
    /// settlement: the worker may still be unwinding a filesystem operation.
    func notifyWhenSettled(_ observer: @escaping () -> Void) {
        lock.lock()
        if settled {
            lock.unlock()
            DispatchQueue.main.async(execute: observer)
            return
        }
        settlementObservers.append(observer)
        lock.unlock()
    }

    func checkCancellation() throws {
        if isCancelled { throw RuntimeStartupPrerequisiteError.cancelled }
    }

    fileprivate func markSettled() {
        lock.lock()
        guard !settled else {
            lock.unlock()
            return
        }
        settled = true
        let observers = settlementObservers
        settlementObservers.removeAll(keepingCapacity: false)
        lock.unlock()
        for observer in observers {
            DispatchQueue.main.async(execute: observer)
        }
    }
}

/// One monotonic deadline shared by every filesystem, fingerprint, and probe
/// phase in a launch-preparation pass. Individual operations may impose a
/// tighter cap, but none may reset or extend this total budget.
final class RuntimeStartupPrerequisiteBudget: @unchecked Sendable {
    private let cancellation: RuntimeStartupPrerequisiteCancellation
    private let deadline: UInt64
    private let now: () -> UInt64

    init(
        cancellation: RuntimeStartupPrerequisiteCancellation,
        duration: TimeInterval,
        now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) {
        self.cancellation = cancellation
        self.now = now
        let start = now()
        let boundedDuration = duration.isFinite ? max(0, min(duration, 300)) : 0
        let delta = UInt64(boundedDuration * 1_000_000_000)
        let addition = start.addingReportingOverflow(delta)
        deadline = addition.overflow ? UInt64.max : addition.partialValue
    }

    func checkpoint() throws {
        try cancellation.checkCancellation()
        guard now() <= deadline else { throw RuntimeStartupPrerequisiteError.timedOut }
    }

    func remainingTimeInterval(maximum: TimeInterval) throws -> TimeInterval {
        try checkpoint()
        let current = now()
        guard current <= deadline else { throw RuntimeStartupPrerequisiteError.timedOut }
        return min(max(0, maximum), Double(deadline - current) / 1_000_000_000)
    }
}

/// Serializes the bounded disk-heavy launch prerequisites away from AppKit's
/// main thread. The main-queue commit predicate is the final generation gate:
/// an old or explicitly cancelled pass can never authorize process launch.
final class RuntimeStartupPrerequisiteWorker: @unchecked Sendable {
    private let queue: DispatchQueue

    init(
        queue: DispatchQueue = DispatchQueue(
            label: "app.localharness.runtime-startup-prerequisites",
            qos: .utility
        )
    ) {
        self.queue = queue
    }

    @discardableResult
    func submit(
        operation: @escaping (RuntimeStartupPrerequisiteCancellation) throws -> Void,
        isGenerationCurrent: @escaping () -> Bool,
        completion: @escaping (Result<Void, Error>) -> Void
    ) -> RuntimeStartupPrerequisiteCancellation {
        submitValue(
            operation: { cancellation in
                try operation(cancellation)
                return ()
            },
            isGenerationCurrent: isGenerationCurrent,
            completion: completion
        )
    }

    @discardableResult
    func submitValue<Value: Sendable>(
        operation: @escaping (RuntimeStartupPrerequisiteCancellation) throws -> Value,
        isGenerationCurrent: @escaping () -> Bool,
        completion: @escaping (Result<Value, Error>) -> Void
    ) -> RuntimeStartupPrerequisiteCancellation {
        let cancellation = RuntimeStartupPrerequisiteCancellation()
        queue.async {
            let workerResult: Result<Value, Error>
            if cancellation.isCancelled {
                workerResult = .failure(RuntimeStartupPrerequisiteError.cancelled)
            } else {
                do {
                    let value = try operation(cancellation)
                    workerResult = cancellation.isCancelled
                        ? .failure(RuntimeStartupPrerequisiteError.cancelled)
                        : .success(value)
                } catch {
                    workerResult = .failure(error)
                }
            }

            // Settlement means the exact submitted closure has returned and
            // can no longer mutate HarnessHome. Stop/restore barriers wait for
            // this event rather than treating cooperative cancellation as an
            // immediate filesystem-quiescence guarantee.
            cancellation.markSettled()

            DispatchQueue.main.async {
                guard !cancellation.isCancelled, isGenerationCurrent() else {
                    completion(.failure(RuntimeStartupPrerequisiteError.cancelled))
                    return
                }
                completion(workerResult)
            }
        }
        return cancellation
    }
}
