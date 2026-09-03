import Foundation

enum ApplicationTerminationBarrierError: Error, Equatable, LocalizedError {
    case timedOut

    var errorDescription: String? {
        switch self {
        case .timedOut:
            return "Local services did not confirm shutdown before the safe quit deadline."
        }
    }
}

/// A one-shot, bounded quit barrier. Model unload gets a short grace period,
/// but can never prevent the authoritative owned-process shutdown from
/// starting. A quiescence failure or deadline skips unload and forces the exact
/// owned-process stop; once terminal shutdown begins, successful stop always
/// completes Quit rather than trying to reopen a partially stopped runtime.
final class ApplicationTerminationBarrier {
    typealias Cancellation = () -> Void
    typealias Scheduler = (_ delay: TimeInterval, _ action: @escaping () -> Void) -> Cancellation

    private let unloadGrace: TimeInterval
    private let totalTimeout: TimeInterval
    private let forcedStopTimeout: TimeInterval
    private let scheduler: Scheduler
    private var cancelUnloadGrace: Cancellation?
    private var cancelTimeout: Cancellation?
    private var quiesceFinished = false
    private var stopStarted = false
    private var finished = false
    private var stop: ((@escaping (Result<Void, Error>) -> Void) -> Void)?
    private var completion: ((Result<Void, Error>) -> Void)?

    init(
        unloadGrace: TimeInterval = 3,
        totalTimeout: TimeInterval = 40,
        forcedStopTimeout: TimeInterval = 12,
        scheduler: @escaping Scheduler = ApplicationTerminationBarrier.dispatchScheduler
    ) {
        precondition(unloadGrace >= 0 && totalTimeout > unloadGrace && forcedStopTimeout > 0)
        self.unloadGrace = unloadGrace
        self.totalTimeout = totalTimeout
        self.forcedStopTimeout = forcedStopTimeout
        self.scheduler = scheduler
    }

    func begin(
        quiesce: ((@escaping (Result<Void, Error>) -> Void) -> Void)? = nil,
        unloadRequested: Bool,
        unload: @escaping (@escaping () -> Void) -> Void,
        stop: @escaping (@escaping (Result<Void, Error>) -> Void) -> Void,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        precondition(self.completion == nil, "ApplicationTerminationBarrier is one-shot")
        self.stop = stop
        self.completion = completion
        cancelTimeout = scheduler(totalTimeout) { [weak self] in self?.handleTimeout() }
        let quiesceCompletion: (Result<Void, Error>) -> Void = { [weak self] result in
            self?.completeQuiesce(result, unloadRequested: unloadRequested, unload: unload)
        }
        if let quiesce { quiesce(quiesceCompletion) }
        else { quiesceCompletion(.success(())) }
    }

    private func completeQuiesce(
        _ result: Result<Void, Error>,
        unloadRequested: Bool,
        unload: (@escaping () -> Void) -> Void
    ) {
        guard !finished, !quiesceFinished else { return }
        quiesceFinished = true
        guard case .success = result else {
            beginForcedStop()
            return
        }
        guard unloadRequested else {
            beginStop()
            return
        }
        cancelUnloadGrace = scheduler(unloadGrace) { [weak self] in self?.beginStop() }
        unload { [weak self] in self?.beginStop() }
    }

    private func beginStop() {
        guard !finished, !stopStarted, let stop else { return }
        stopStarted = true
        cancelUnloadGrace?()
        cancelUnloadGrace = nil
        stop { [weak self] result in self?.finish(result) }
    }

    private func beginForcedStop() {
        guard !finished else { return }
        cancelUnloadGrace?()
        cancelUnloadGrace = nil
        cancelTimeout?()
        cancelTimeout = scheduler(forcedStopTimeout) { [weak self] in
            self?.finish(.failure(ApplicationTerminationBarrierError.timedOut))
        }
        beginStop()
    }

    private func handleTimeout() {
        guard !finished else { return }
        if stopStarted {
            finish(.failure(ApplicationTerminationBarrierError.timedOut))
        } else {
            beginForcedStop()
        }
    }

    private func finish(_ result: Result<Void, Error>) {
        guard !finished else { return }
        finished = true
        cancelUnloadGrace?()
        cancelTimeout?()
        cancelUnloadGrace = nil
        cancelTimeout = nil
        stop = nil
        let callback = completion
        completion = nil
        callback?(result)
    }

    private static func dispatchScheduler(
        delay: TimeInterval,
        action: @escaping () -> Void
    ) -> Cancellation {
        let work = DispatchWorkItem(block: action)
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
        return { work.cancel() }
    }
}
