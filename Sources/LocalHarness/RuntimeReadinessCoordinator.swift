import Foundation

/// The noninteractive migration decision made before a background scheduler
/// wake may launch either DSH or Ollama.
enum BackgroundRuntimeMigrationPreparation: Equatable {
    case current(version: String)
    case backupCreated(version: String)
    case recoveryNeeded(version: String, backupID: UUID)
}

enum BackgroundScheduleLifecycleError: LocalizedError {
    case runtimeUnavailable
    case quiescenceUnavailable

    var errorDescription: String? {
        switch self {
        case .runtimeUnavailable:
            return "The reviewed Harness runtime version could not be resolved, so background schedules remained stopped."
        case .quiescenceUnavailable:
            return "Background agent cancellation could not be verified, so \(ProductBrand.displayName) stopped the runtime but remained open and failed closed."
        }
    }
}

/// Owns the complete one-shot `--background-schedule` lifecycle.
///
/// Every asynchronous edge is bound to the exact runtime generation and
/// phase that created it. A successful wake is strictly ordered as:
/// credential-free home preflight -> migration backup gate -> bounded identity probe -> migration commit ->
/// provider topology verification -> full-inference promotion -> due work -> idle -> exact
/// owned-process stop -> application exit. Any launch/readiness/topology
/// failure enters the same terminal stop barrier, and exit is unreachable if
/// the exact children could not be confirmed reaped.
final class BackgroundScheduleLifecycleCoordinator {
    typealias HarnessHomePreflight = (@escaping (Result<Void, Error>) -> Void) -> Void
    typealias MigrationPreparation = (@escaping (Result<BackgroundRuntimeMigrationPreparation, Error>) -> Void) -> Void
    typealias Probe = (@escaping (Bool) -> Void) -> Void
    typealias Scheduler = (TimeInterval, @escaping () -> Void) -> Void
    typealias TopologyVerification = (UUID, @escaping (Result<Void, Error>) -> Void) -> Void
    typealias QuiesceSchedules = (@escaping (Result<Void, Error>) -> Void) -> Void
    typealias StopRuntime = (@escaping (Result<Void, Error>) -> Void) -> Void

    enum Phase: Equatable {
        case idle
        case preflightingHarnessHome
        case preparingMigration
        case waitingForRuntimeStart
        case probing(generation: UUID, attempt: Int)
        case waitingForProbeRetry(generation: UUID, completedAttempts: Int)
        case waitingForReadyPublication(generation: UUID)
        case verifyingTopology(generation: UUID)
        case runningSchedules(generation: UUID)
        case quiescingSchedules(generation: UUID)
        case stopping(generation: UUID)
        case cleanupFailed(generation: UUID)
        case finished
    }

    private let maximumAttempts: Int
    private let delay: TimeInterval
    private let preflightHarnessHome: HarnessHomePreflight
    private let prepareMigration: MigrationPreparation
    private let launchRuntime: () -> Void
    private let recordRecoveryNeeded: (_ version: String, _ backupID: UUID) -> Void
    private let probe: Probe
    private let schedule: Scheduler
    private let reportIdentityReady: () -> Void
    private let verifyTopology: TopologyVerification
    private let markMigrationReady: (_ version: String) -> Result<Void, Error>
    private let promoteToFullInference: () -> Bool
    private let runDueSchedules: () -> Void
    private let quiesceSchedules: QuiesceSchedules
    private let stopRuntime: StopRuntime
    private let exitApplication: () -> Void

    private var pendingMigrationVersion: String?
    private var activeProbe = UUID()
    private(set) var phase: Phase = .idle

    init(
        maximumAttempts: Int = 100,
        delay: TimeInterval = 0.6,
        preflightHarnessHome: @escaping HarnessHomePreflight = { $0(.success(())) },
        prepareMigration: @escaping MigrationPreparation,
        launchRuntime: @escaping () -> Void,
        recordRecoveryNeeded: @escaping (_ version: String, _ backupID: UUID) -> Void,
        probe: @escaping Probe,
        schedule: @escaping Scheduler = { delay, action in
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: action)
        },
        reportIdentityReady: @escaping () -> Void,
        verifyTopology: @escaping TopologyVerification,
        markMigrationReady: @escaping (_ version: String) -> Result<Void, Error>,
        promoteToFullInference: @escaping () -> Bool,
        runDueSchedules: @escaping () -> Void,
        quiesceSchedules: @escaping QuiesceSchedules = { completion in completion(.success(())) },
        stopRuntime: @escaping StopRuntime,
        exitApplication: @escaping () -> Void
    ) {
        precondition(maximumAttempts > 0)
        precondition(delay >= 0)
        self.maximumAttempts = maximumAttempts
        self.delay = delay
        self.preflightHarnessHome = preflightHarnessHome
        self.prepareMigration = prepareMigration
        self.launchRuntime = launchRuntime
        self.recordRecoveryNeeded = recordRecoveryNeeded
        self.probe = probe
        self.schedule = schedule
        self.reportIdentityReady = reportIdentityReady
        self.verifyTopology = verifyTopology
        self.markMigrationReady = markMigrationReady
        self.promoteToFullInference = promoteToFullInference
        self.runDueSchedules = runDueSchedules
        self.quiesceSchedules = quiesceSchedules
        self.stopRuntime = stopRuntime
        self.exitApplication = exitApplication
    }

    /// Runs before the controller is allowed to start a service. This method
    /// is one-shot for a single background app process.
    func prepareAndLaunch() {
        guard phase == .idle else { return }
        phase = .preflightingHarnessHome
        preflightHarnessHome { [weak self] result in
            guard let self, self.phase == .preflightingHarnessHome else { return }
            guard case .success = result else {
                // The preflight owner publishes any typed foreground recovery
                // signal before completing. Only then may this process exit.
                self.phase = .finished
                self.exitApplication()
                return
            }
            self.prepareMigrationAndLaunch()
        }
    }

    private func prepareMigrationAndLaunch() {
        phase = .preparingMigration
        prepareMigration { [weak self] result in
            guard let self, self.phase == .preparingMigration else { return }
            switch result {
            case .success(.current):
                self.pendingMigrationVersion = nil
                self.phase = .waitingForRuntimeStart
                self.launchRuntime()
            case .success(.backupCreated(let version)):
                self.pendingMigrationVersion = version
                self.phase = .waitingForRuntimeStart
                self.launchRuntime()
            case .success(.recoveryNeeded(let version, let backupID)):
                // RuntimeMigrationCoordinator has already durably persisted
                // the pending version/backup tuple. Add the user-facing result
                // before this headless wake exits and start no service.
                self.recordRecoveryNeeded(version, backupID)
                self.phase = .finished
                self.exitApplication()
            case .failure:
                // Failure to prove/create the safety backup is fail-closed.
                // No service exists, so normal AppKit termination can run its
                // empty exact-process barrier.
                self.phase = .finished
                self.exitApplication()
            }
        }
    }

    /// Resumes the exact launch closure after admission was deferred between
    /// migration preparation and child creation. Calling prepareAndLaunch at
    /// this point would be inert because the one-shot lifecycle already owns
    /// `.waitingForRuntimeStart`.
    @discardableResult
    func resumeDeferredRuntimeLaunch() -> Bool {
        guard phase == .waitingForRuntimeStart else { return false }
        launchRuntime()
        return true
    }

    /// Starts bounded polling for the exact controller generation that
    /// published `.startingHarness`.
    func runtimeStarted(generation: UUID) {
        guard phase == .waitingForRuntimeStart else { return }
        activeProbe = UUID()
        poll(generation: generation, attempt: 1)
    }

    /// Called only for the controller's `.ready` publication. A probe result
    /// by itself never authorizes provider/model use.
    func runtimePublishedReady(generation: UUID) {
        guard phase == .waitingForReadyPublication(generation: generation) else { return }
        phase = .verifyingTopology(generation: generation)
        verifyTopology(generation) { [weak self] result in
            guard let self, self.phase == .verifyingTopology(generation: generation) else { return }
            guard case .success = result else {
                self.stopAndExit(generation: generation)
                return
            }

            guard self.promoteToFullInference() else {
                self.stopAndExit(generation: generation)
                return
            }
            self.phase = .runningSchedules(generation: generation)
            self.runDueSchedules()
        }
    }

    /// A controller failure/recovery state is terminal for a noninteractive
    /// scheduler wake. Provider repair is intentionally a foreground action.
    func runtimeFailed(generation: UUID) {
        switch phase {
        case .waitingForRuntimeStart:
            stopAndExit(generation: generation)
        case .probing(let active, _) where active == generation:
            stopAndExit(generation: generation)
        case .waitingForProbeRetry(let active, _) where active == generation:
            stopAndExit(generation: generation)
        case .waitingForReadyPublication(let active) where active == generation:
            stopAndExit(generation: generation)
        case .verifyingTopology(let active) where active == generation:
            stopAndExit(generation: generation)
        case .runningSchedules(let active) where active == generation:
            stopAndExit(generation: generation)
        default:
            break
        }
    }

    /// Handles an unexpected controller stop before due work completed. A
    /// second exact stop is harmless and closes the controller launch latch.
    func runtimeStopped(generation: UUID) {
        runtimeFailed(generation: generation)
    }

    /// ScheduleManager emits this once only after there is no active run,
    /// manual queue entry, or currently due schedule.
    func scheduledWorkBecameIdle() {
        guard case .runningSchedules(let generation) = phase else { return }
        stopAndExit(generation: generation)
    }

    private func poll(generation: UUID, attempt: Int) {
        let probeID = UUID()
        activeProbe = probeID
        phase = .probing(generation: generation, attempt: attempt)
        probe { [weak self] ready in
            guard let self,
                  self.activeProbe == probeID,
                  self.phase == .probing(generation: generation, attempt: attempt) else { return }
            self.activeProbe = UUID()
            if ready {
                // A successful probe authenticates the exact DSH control-plane
                // identity and proves its private home/schema can be opened.
                // Provider/model readiness is a separate, repairable concern;
                // it must not make a completed Harness migration look crashed
                // on the next launch.
                if let version = self.pendingMigrationVersion {
                    guard case .success = self.markMigrationReady(version) else {
                        self.stopAndExit(generation: generation)
                        return
                    }
                    self.pendingMigrationVersion = nil
                }
                self.phase = .waitingForReadyPublication(generation: generation)
                self.reportIdentityReady()
            } else if attempt >= self.maximumAttempts {
                self.stopAndExit(generation: generation)
            } else {
                self.phase = .waitingForProbeRetry(generation: generation, completedAttempts: attempt)
                self.schedule(self.delay) { [weak self] in
                    guard let self,
                          self.phase == .waitingForProbeRetry(
                            generation: generation,
                            completedAttempts: attempt
                          ) else { return }
                    self.poll(generation: generation, attempt: attempt + 1)
                }
            }
        }
    }

    private func stopAndExit(generation: UUID) {
        switch phase {
        case .quiescingSchedules, .stopping, .cleanupFailed, .finished:
            return
        default:
            break
        }
        activeProbe = UUID()
        phase = .quiescingSchedules(generation: generation)
        quiesceSchedules { [weak self] result in
            guard let self,
                  self.phase == .quiescingSchedules(generation: generation) else { return }
            self.beginRuntimeStop(
                generation: generation,
                quiescenceVerified: result.isSuccess
            )
        }
    }

    private func beginRuntimeStop(generation: UUID, quiescenceVerified: Bool) {
        phase = .stopping(generation: generation)
        stopRuntime { [weak self] result in
            guard let self, self.phase == .stopping(generation: generation) else { return }
            switch result {
            case .success:
                if quiescenceVerified {
                    self.phase = .finished
                    self.exitApplication()
                } else {
                    // Exact local children are stopped, but a cloud/provider
                    // cancellation was not acknowledged. Do not falsely claim
                    // a clean one-shot exit or allow another background wake.
                    self.phase = .cleanupFailed(generation: generation)
                }
            case .failure:
                // Exiting here could orphan the exact DSH/Ollama children the
                // stop barrier failed to reap. Remain alive and failed closed.
                self.phase = .cleanupFailed(generation: generation)
            }
        }
    }
}

private extension Result where Success == Void, Failure == Error {
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}
