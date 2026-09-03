import Foundation

/// One-shot bridge from controller state callbacks into structured lifecycle
/// operations. The monotonic deadline prevents a missing callback or silent
/// start refusal from holding the global mutation gate forever.
@MainActor
final class ProtectedRuntimeReadinessWaiter {
    private var continuation: CheckedContinuation<Void, Error>?
    private var timeoutTask: Task<Void, Never>?
    private var token: UUID?

    var isWaiting: Bool { continuation != nil }

    func wait(
        label: String,
        timeout: Duration = .seconds(180),
        start: @MainActor () -> Void
    ) async throws {
        guard continuation == nil else {
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.readinessWaiterBusy)
        }
        let operationToken = UUID()
        token = operationToken
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            timeoutTask = Task { @MainActor [weak self] in
                do { try await Task.sleep(for: timeout) }
                catch { return }
                self?.settle(
                    token: operationToken,
                    result: .failure(ProtectedRuntimeMutationCoordinatorError.transitionFailed(.readinessTimedOut))
                )
            }
            start()
        }
    }

    /// Returns true only when this call owned and settled a live waiter.
    @discardableResult
    func resume(with result: Result<Void, Error>) -> Bool {
        guard let token else { return false }
        return settle(token: token, result: result)
    }

    @discardableResult
    private func settle(token expectedToken: UUID, result: Result<Void, Error>) -> Bool {
        guard token == expectedToken, let continuation else { return false }
        self.continuation = nil
        token = nil
        timeoutTask?.cancel()
        timeoutTask = nil
        continuation.resume(with: result)
        return true
    }
}

enum ProtectedRuntimeMutationKind: String, Equatable, Sendable {
    case providerSelection
    case providerProfile
    case providerActivation
    case providerCredential
    case nativeProviderStateReset
    case performanceProfile
    case sshAgentAccess
    case skillActivation
    case mcpActivation
    case credentialMigration
    case stateBackup
    case stateRestore
    case workspaceRestore
    case updateInstall
    case manualRestart
    case modelMemory
    case websiteData
}

enum ProtectedRuntimeMutationRequirement: Equatable, Sendable {
    /// The mutation touches only app-owned state and must run after every exact
    /// inference child has exited.
    case stoppedRuntime
    /// The mutation requires DSH's authenticated settings/credential RPCs. It
    /// runs in the no-provider-egress, no-skill, no-MCP recovery control plane.
    case providerControlPlane
}

enum ProtectedRuntimeMutationDisposition: Equatable, Sendable {
    /// Start, topology-check, and expose one fresh inference runtime.
    case restartInference
    /// Replace the mutation control plane with a fresh zero-egress control
    /// plane and keep all work admissions closed. Provider setup can then
    /// continue to an explicit model/boundary commit without trying to restart
    /// an old unavailable default route in between those two user decisions.
    case restartProviderControlPlane
    /// Release the operation permit but keep admissions and auxiliary starts
    /// closed. A later explicit repair may reacquire from this fail-closed
    /// state; ordinary work cannot resume against invalid persisted state.
    case remainStopped
    /// Keep the runtime stopped because a verified update helper will replace
    /// the app and terminate this process.
    case terminateForUpdate
}

enum ProtectedRuntimeTransitionFailure: Equatable, Sendable {
    case applicationLifecycleEnded
    case readinessWaiterBusy
    case readinessTimedOut
    case providerRecoveryPending
    case failedClosed
    case runtimeStopFailed
    case providerControlPlaneStartFailed
    case inferenceStartFailed
    case runtimeFailed
    case coordinationUnavailable
    case compensationIncomplete

    var userMessage: String {
        switch self {
        case .applicationLifecycleEnded:
            return "The application lifecycle ended before the protected change completed."
        case .readinessWaiterBusy:
            return "Another lifecycle readiness check is already active."
        case .readinessTimedOut:
            return "The fresh runtime did not become ready within its bounded deadline."
        case .providerRecoveryPending:
            return "Provider setup is still in its zero-egress recovery control plane."
        case .failedClosed:
            return "A failed protected change still owns the runtime boundary."
        case .runtimeStopFailed:
            return "The previous runtime could not be confirmed stopped."
        case .providerControlPlaneStartFailed:
            return "The isolated provider recovery control plane could not be verified."
        case .inferenceStartFailed:
            return "A fresh inference runtime could not be verified."
        case .runtimeFailed:
            return "The private runtime entered a failed state."
        case .coordinationUnavailable:
            return "Protected runtime coordination is unavailable."
        case .compensationIncomplete:
            return "The previous provider state could not be restored completely."
        }
    }
}

enum ProtectedRuntimeMutationCoordinatorError: LocalizedError, Equatable {
    case busy(ProtectedRuntimeMutationKind)
    case terminating
    case invalidPermit
    case mutationFailed(ProtectedRuntimeMutationKind)
    case transitionFailed(ProtectedRuntimeTransitionFailure)
    case previousVerifiedStateRestored
    case mutationCommittedButRecoveryFailed(kind: ProtectedRuntimeMutationKind)
    case mutationOutcomeUncertainAndRecoveryFailed(kind: ProtectedRuntimeMutationKind)
    case mutationAndRecoveryFailed(kind: ProtectedRuntimeMutationKind)

    var errorDescription: String? {
        switch self {
        case .busy(let kind):
            return "Another protected runtime change is still finishing (\(kind.rawValue)). Try again when \(ProductBrand.displayName) is ready."
        case .terminating:
            return "\(ProductBrand.displayName) is shutting down. The requested change was not started."
        case .invalidPermit:
            return "The protected runtime change lost its exact lifecycle permit. No state was changed."
        case .mutationFailed(let kind):
            return "The \(kind.rawValue) change did not complete. The previous verified runtime was restored."
        case .transitionFailed(let reason):
            return "\(ProductBrand.displayName) kept agent work blocked because the protected runtime transition did not finish safely. \(reason.userMessage)"
        case .previousVerifiedStateRestored:
            return "The fresh runtime rejected the requested change, so the previous verified state was restored."
        case .mutationCommittedButRecoveryFailed(let kind):
            return "The \(kind.rawValue) change was committed, but a fresh verified runtime could not start. Agent work remains blocked; the saved state will be rechecked during recovery."
        case .mutationOutcomeUncertainAndRecoveryFailed(let kind):
            return "The outcome of the \(kind.rawValue) change is uncertain, and a fresh verified runtime could not determine the saved state. Agent work remains blocked; review this provider before using it."
        case .mutationAndRecoveryFailed(let kind):
            return "The \(kind.rawValue) change failed, and the fresh runtime could not be restored. Agent work remains blocked."
        }
    }
}

/// Thread-safe authority behind a transition permit. Durable/off-main workers
/// can validate the exact generation immediately before every namespace
/// commit without calling back synchronously onto the main actor.
private final class ProtectedRuntimeMutationPermitAuthority: @unchecked Sendable {
    private let lock = NSLock()
    private var activeToken: UUID?

    func activate(_ token: UUID) {
        lock.lock()
        precondition(activeToken == nil)
        activeToken = token
        lock.unlock()
    }

    func invalidate(_ token: UUID) {
        lock.lock()
        if activeToken == token { activeToken = nil }
        lock.unlock()
    }

    func validate(_ token: UUID) throws {
        lock.lock()
        let valid = activeToken == token
        lock.unlock()
        guard valid else { throw ProtectedRuntimeMutationCoordinatorError.invalidPermit }
    }
}

struct ProtectedRuntimeMutationPermit: @unchecked Sendable, Equatable {
    let id: UUID
    let kind: ProtectedRuntimeMutationKind
    let requirement: ProtectedRuntimeMutationRequirement
    private let validateClosure: @Sendable () throws -> Void

    fileprivate init(
        id: UUID,
        kind: ProtectedRuntimeMutationKind,
        requirement: ProtectedRuntimeMutationRequirement,
        validate: @escaping @Sendable () throws -> Void
    ) {
        self.id = id
        self.kind = kind
        self.requirement = requirement
        validateClosure = validate
    }

    func validate() throws { try validateClosure() }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id && lhs.kind == rhs.kind && lhs.requirement == rhs.requirement
    }
}

@MainActor
struct ProtectedRuntimeMutationDriver {
    /// Must close Web/native/schedule admissions synchronously before acquire
    /// reaches its first suspension point.
    let closeAdmissions: @MainActor () -> Void
    /// Drains native turns and schedule execution. Exact process stop remains
    /// the authoritative boundary if an RPC acknowledgement is unavailable.
    let quiesceAdmissions: @MainActor () async throws -> Void
    /// Settles only after every exact app-owned inference/control-plane child
    /// captured by the stop generation has exited.
    let stopRuntime: @MainActor () async throws -> Void
    /// Settles only after the authenticated, zero-egress provider control plane
    /// is reachable through the native allowlisted RPC client.
    let startProviderControlPlane: @MainActor () async throws -> Void
    /// Settles only after topology verification has promoted a fresh runtime.
    let startVerifiedInference: @MainActor () async throws -> Void
    let remainStoppedForUpdate: @MainActor () -> Void
    let failClosed: @MainActor (_ error: Error) -> Void
}

/// The single lifecycle gate shared by every window that can change runtime,
/// provider, trust, credential, backup, or update state. It deliberately
/// rejects concurrent requests instead of queuing stale UI intent.
@MainActor
final class ProtectedRuntimeMutationCoordinator {
    private enum Phase: Equatable {
        case idle
        case closing(ProtectedRuntimeMutationKind, UUID)
        case controlPlane(ProtectedRuntimeMutationKind, UUID)
        case stopped(ProtectedRuntimeMutationKind, UUID)
        case finishing(ProtectedRuntimeMutationKind, UUID)
        /// No mutation permit is live, but a fresh authenticated zero-egress
        /// provider control plane remains available for the next explicit
        /// repair or selection transaction.
        case providerRecoveryReady
        /// The verified installer helper is running and waiting for this exact
        /// process to exit. Admissions and every restart path stay closed.
        case terminalUpdate
        case failedClosed
    }

    private let driver: ProtectedRuntimeMutationDriver
    private let authority = ProtectedRuntimeMutationPermitAuthority()
    private var phase: Phase = .idle
    private var currentPermit: ProtectedRuntimeMutationPermit?
    private var terminationBegun = false
    private var updateTerminationClaimed = false

    init(driver: ProtectedRuntimeMutationDriver) {
        self.driver = driver
    }

    var isTransitionInFlight: Bool { phase != .idle }
    var hasActiveMutation: Bool {
        switch phase {
        case .idle, .providerRecoveryReady, .terminalUpdate, .failedClosed: return false
        default: return true
        }
    }

    /// Local-model inspection may start an auxiliary Ollama child while an
    /// ordinary, stable runtime is active. It must not do so after shutdown is
    /// latched or while a protected transition owns the exact child set.
    func validateAuxiliaryServiceStart() throws {
        guard !terminationBegun else {
            throw ProtectedRuntimeMutationCoordinatorError.terminating
        }
        switch phase {
        case .idle:
            return
        case .closing(let kind, _), .controlPlane(let kind, _),
             .stopped(let kind, _), .finishing(let kind, _):
            throw ProtectedRuntimeMutationCoordinatorError.busy(kind)
        case .terminalUpdate:
            throw ProtectedRuntimeMutationCoordinatorError.terminating
        case .providerRecoveryReady:
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.providerRecoveryPending)
        case .failedClosed:
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.failedClosed)
        }
    }

    /// Permanently latches mutation admission closed before Quit reaches its
    /// first asynchronous barrier. A UI task queued before this call cannot
    /// acquire later and restart inference underneath application shutdown.
    func beginTermination() -> Bool {
        guard !hasActiveMutation else { return false }
        terminationBegun = true
        return true
    }

    /// Consumes the single update-specific handoff after the coordinator has
    /// entered its irreversible terminal phase. Ordinary Quit cannot create
    /// this authority and stale helper completions cannot consume it twice.
    func claimAuthorizedUpdateTermination() -> Bool {
        guard terminationBegun, phase == .terminalUpdate, !updateTerminationClaimed else {
            return false
        }
        updateTerminationClaimed = true
        return true
    }

    func validateClaimedUpdateTermination() -> Bool {
        terminationBegun && phase == .terminalUpdate && updateTerminationClaimed
    }

    /// Closes every admission path before the first await, then reaches either
    /// an exact stopped runtime or the isolated provider control plane.
    func acquire(
        kind: ProtectedRuntimeMutationKind,
        requirement: ProtectedRuntimeMutationRequirement
    ) async throws -> ProtectedRuntimeMutationPermit {
        guard !terminationBegun else {
            throw ProtectedRuntimeMutationCoordinatorError.terminating
        }
        if phase == .failedClosed || phase == .providerRecoveryReady {
            // A failed transition deliberately leaves admissions closed. A
            // later user-authorized repair reuses that hold, exact-stops any
            // partial child again, and may recover without relaunching the app.
            phase = .idle
        }
        guard phase == .idle else {
            let activeKind: ProtectedRuntimeMutationKind
            switch phase {
            case .closing(let kind, _), .controlPlane(let kind, _),
                 .stopped(let kind, _), .finishing(let kind, _):
                activeKind = kind
            case .idle, .providerRecoveryReady, .terminalUpdate, .failedClosed:
                activeKind = kind
            }
            throw ProtectedRuntimeMutationCoordinatorError.busy(activeKind)
        }

        let token = UUID()
        phase = .closing(kind, token)
        driver.closeAdmissions()

        // A missing cancellation acknowledgement does not permit mutation on
        // a live process, but it also cannot deadlock recovery forever. Exact
        // process exit below is the final security boundary.
        var quiescenceError: Error?
        do { try await driver.quiesceAdmissions() }
        catch { quiescenceError = error }

        do {
            try await driver.stopRuntime()
        } catch {
            phase = .failedClosed
            driver.failClosed(error)
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.runtimeStopFailed)
        }

        do {
            if requirement == .providerControlPlane {
                try await driver.startProviderControlPlane()
                phase = .controlPlane(kind, token)
            } else {
                phase = .stopped(kind, token)
            }
            let permit = ProtectedRuntimeMutationPermit(
                id: token,
                kind: kind,
                requirement: requirement,
                validate: { [authority] in try authority.validate(token) }
            )
            authority.activate(token)
            currentPermit = permit
            _ = quiescenceError // Exact process exit supersedes RPC ambiguity.
            return permit
        } catch {
            // A partially-started repair process is captured and stopped before
            // restoring inference. If restoration fails, admissions stay shut.
            _ = try? await driver.stopRuntime()
            do {
                try await driver.startVerifiedInference()
                phase = .idle
            } catch let recoveryError {
                _ = try? await driver.stopRuntime()
                phase = .failedClosed
                driver.failClosed(recoveryError)
            }
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.providerControlPlaneStartFailed)
        }
    }

    func finish(
        _ permit: ProtectedRuntimeMutationPermit,
        disposition: ProtectedRuntimeMutationDisposition = .restartInference,
        mutationCommitted: Bool = false
    ) async throws {
        try validateOwnedPermit(permit)
        phase = .finishing(permit.kind, permit.id)
        authority.invalidate(permit.id)
        currentPermit = nil

        if permit.requirement == .providerControlPlane {
            do { try await driver.stopRuntime() }
            catch {
                phase = .failedClosed
                driver.failClosed(error)
                if mutationCommitted {
                    throw ProtectedRuntimeMutationCoordinatorError.mutationCommittedButRecoveryFailed(
                        kind: permit.kind
                    )
                }
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.runtimeStopFailed)
            }
        }

        switch disposition {
        case .restartInference:
            do {
                try await driver.startVerifiedInference()
                phase = .idle
            } catch {
                // Readiness can fail after a child reached its listening state
                // (for example, exact-origin topology rejection). Capture and
                // stop that partial child before reporting the closed state.
                _ = try? await driver.stopRuntime()
                phase = .failedClosed
                driver.failClosed(error)
                if mutationCommitted {
                    throw ProtectedRuntimeMutationCoordinatorError.mutationCommittedButRecoveryFailed(
                        kind: permit.kind
                    )
                }
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.inferenceStartFailed)
            }
        case .restartProviderControlPlane:
            do {
                try await driver.startProviderControlPlane()
                phase = .providerRecoveryReady
            } catch {
                _ = try? await driver.stopRuntime()
                phase = .failedClosed
                driver.failClosed(error)
                if mutationCommitted {
                    throw ProtectedRuntimeMutationCoordinatorError.mutationCommittedButRecoveryFailed(
                        kind: permit.kind
                    )
                }
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.providerControlPlaneStartFailed)
            }
        case .remainStopped:
            phase = .failedClosed
        case .terminateForUpdate:
            driver.remainStoppedForUpdate()
            // This is intentionally irreversible. The update helper is now
            // waiting for this process to exit; reopening inference or
            // accepting another mutation could race replacement of the app.
            terminationBegun = true
            updateTerminationClaimed = false
            phase = .terminalUpdate
        }
    }

    func perform<Value>(
        kind: ProtectedRuntimeMutationKind,
        requirement: ProtectedRuntimeMutationRequirement,
        disposition: ProtectedRuntimeMutationDisposition = .restartInference,
        compensateAfterRecoveryFailure: (@MainActor (_ committedValue: Value, _ permit: ProtectedRuntimeMutationPermit) async throws -> Void)? = nil,
        mutation: @MainActor (ProtectedRuntimeMutationPermit) async throws -> Value
    ) async throws -> Value {
        let permit = try await acquire(kind: kind, requirement: requirement)
        let mutationResult: Result<Value, Error>
        do { mutationResult = .success(try await mutation(permit)) }
        catch { mutationResult = .failure(error) }

        do {
            try await finish(permit, disposition: disposition, mutationCommitted: false)
        } catch {
            switch mutationResult {
            case .success(let value):
                if let compensateAfterRecoveryFailure {
                    do {
                        try await compensateAndRestorePreviousRuntime(
                            kind: kind,
                            committedValue: value,
                            compensation: compensateAfterRecoveryFailure
                        )
                        throw ProtectedRuntimeMutationCoordinatorError.previousVerifiedStateRestored
                    } catch let compensationError as ProtectedRuntimeMutationCoordinatorError {
                        if case .previousVerifiedStateRestored = compensationError {
                            throw compensationError
                        }
                        throw ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(
                            kind: kind
                        )
                    } catch {
                        throw ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(
                            kind: kind
                        )
                    }
                }
                throw ProtectedRuntimeMutationCoordinatorError.mutationCommittedButRecoveryFailed(
                    kind: kind
                )
            case .failure:
                throw ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(
                    kind: kind
                )
            }
        }

        switch mutationResult {
        case .success(let value):
            return value
        case .failure:
            // The mutation closure is an extensibility boundary. Its Error may
            // contain provider responses, credentials, private paths, or
            // attacker-sized diagnostic text. Keep the original Error only in
            // this stack frame and return a closed, typed presentation result.
            throw ProtectedRuntimeMutationCoordinatorError.mutationFailed(kind)
        }
    }

    /// A provider selection promises previous-route rollback. If the newly
    /// committed route cannot reach verified Ready, this internal recovery
    /// pass cleans any partial inference child, launches a fresh zero-egress
    /// control plane, restores the captured state, and verifies the old route
    /// before releasing admissions.
    private func compensateAndRestorePreviousRuntime<Value>(
        kind: ProtectedRuntimeMutationKind,
        committedValue: Value,
        compensation: @MainActor (_ committedValue: Value, _ permit: ProtectedRuntimeMutationPermit) async throws -> Void
    ) async throws {
        do {
            try await driver.stopRuntime()
            try await driver.startProviderControlPlane()
            let token = UUID()
            phase = .controlPlane(kind, token)
            let permit = ProtectedRuntimeMutationPermit(
                id: token,
                kind: kind,
                requirement: .providerControlPlane,
                validate: { [authority] in try authority.validate(token) }
            )
            authority.activate(token)
            currentPermit = permit
            try await compensation(committedValue, permit)
            try validateOwnedPermit(permit)
            authority.invalidate(token)
            currentPermit = nil
            phase = .finishing(kind, token)
            try await driver.stopRuntime()
            try await driver.startVerifiedInference()
            phase = .idle
        } catch {
            _ = try? await driver.stopRuntime()
            if let permit = currentPermit {
                authority.invalidate(permit.id)
                currentPermit = nil
            }
            phase = .failedClosed
            driver.failClosed(error)
            throw error
        }
    }

    private func validateOwnedPermit(_ permit: ProtectedRuntimeMutationPermit) throws {
        try permit.validate()
        guard currentPermit == permit else {
            throw ProtectedRuntimeMutationCoordinatorError.invalidPermit
        }
        switch phase {
        case .controlPlane(let kind, let token), .stopped(let kind, let token):
            guard kind == permit.kind, token == permit.id else {
                throw ProtectedRuntimeMutationCoordinatorError.invalidPermit
            }
        default:
            throw ProtectedRuntimeMutationCoordinatorError.invalidPermit
        }
    }
}
