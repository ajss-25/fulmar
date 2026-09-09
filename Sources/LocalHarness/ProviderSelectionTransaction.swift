import Foundation

protocol ModelDefaultSynchronizing: Sendable {
    func synchronizeDefault(_ selection: ModelSelection) async throws -> HarnessSettingsNamespace
}

extension ModelSelectionCoordinator: ModelDefaultSynchronizing {}

@MainActor
protocol ModelProviderSettingsStoring: AnyObject {
    func loadOrMigrate() throws -> ModelProviderSettingsLoadResult
    func save(_ settings: ModelProviderSettings) throws
}

extension ModelProviderSettingsStore: ModelProviderSettingsStoring {}

@MainActor
protocol ProviderConsentStoring: AnyObject {
    func load() throws -> ProviderConsentState
    func activate(_ descriptor: ProviderDescriptor) throws -> ProviderConsentState
    func restore(_ state: ProviderConsentState) throws
}

extension ProviderConsentStore: ProviderConsentStoring {}

@MainActor
protocol StrictLocalModeStoring: AnyObject {
    var strictLocalMode: Bool { get set }
}

extension PreferencesStore: StrictLocalModeStoring {}

/// `@MainActor` methods are reentrant at every `await`. This explicit FIFO gate
/// therefore protects the complete multi-store commit, including both of its
/// Harness RPCs during rollback. It is process-wide so an independently-created
/// native window cannot accidentally race the transaction shared by the app.
@MainActor
private enum ProviderSelectionCommitGate {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Bool, Never>
    }

    private static var occupied = false
    private static var waiters: [Waiter] = []

    static var isOccupied: Bool { occupied }

    static func acquire(rejectIfOccupied: Bool = false) async throws {
        try Task.checkCancellation()
        guard occupied else {
            occupied = true
            return
        }
        if rejectIfOccupied {
            throw ProtectedRuntimeMutationCoordinatorError.busy(.providerSelection)
        }

        let id = UUID()
        let acquired = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(returning: false)
                } else {
                    waiters.append(Waiter(id: id, continuation: continuation))
                }
            }
        } onCancel: {
            Task { @MainActor in cancel(id: id) }
        }
        guard acquired else { throw CancellationError() }
        if Task.isCancelled {
            // Ownership may have transferred just before cancellation reached
            // the main actor. Pass it on rather than running a stale UI choice.
            release()
            throw CancellationError()
        }
    }

    static func release() {
        if waiters.isEmpty {
            occupied = false
            return
        }
        let waiter = waiters.removeFirst()
        // Ownership transfers directly to the next waiter, so there is no gap
        // in which a later caller can overtake it.
        waiter.continuation.resume(returning: true)
    }

    private static func cancel(id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = waiters.remove(at: index)
        waiter.continuation.resume(returning: false)
    }
}

struct ProviderSelectionCommitResult: Equatable, Sendable {
    let selection: ModelSelection
    let boundary: DataBoundary
    let origin: ProviderEndpointOrigin?
}

/// A successful multi-store commit creates a mandatory lifecycle handoff. Task
/// cancellation may prevent a queued commit from starting, but once `commit`
/// returns there is deliberately no suspension or cancellation check before
/// the caller clears old session state and restarts the exact-origin runtime.
@MainActor
enum ProviderSelectionHandoff {
    @discardableResult
    static func commit(
        selection: ModelSelection,
        descriptor: ProviderDescriptor,
        using transaction: ProviderSelectionTransaction,
        onCommitted: (ProviderSelectionCommitResult) -> Void
    ) async throws -> ProviderSelectionCommitResult {
        let result = try await transaction.commit(selection: selection, descriptor: descriptor)
        onCommitted(result)
        return result
    }
}

enum ProviderSelectionFailurePresentation {
    static func message(for error: Error) -> String {
        let safeLocalReason: String? = switch error {
        case let value as LocalModelAdmissionError: value.localizedDescription
        case let value as QualifiedLocalModelHostAdmissionError: value.localizedDescription
        case let value as LocalModelSelectionPreflightError: value.localizedDescription
        case let value as OllamaVersionCompatibilityError: value.localizedDescription
        case let value as OllamaModelInspectionError: value.localizedDescription
        default: nil
        }
        if let safeLocalReason {
            return "The model switch was not completed. The previous route remains active. \(safeLocalReason)"
        }
        guard let transaction = error as? ProviderSelectionTransactionError else {
            return "The model switch was not completed. The previous route remains active. Review Models & Providers and try again."
        }
        guard transaction.rollbackComplete else {
            return "The model switch failed and rollback was incomplete. Network access remains blocked; restart \(ProductBrand.displayName) before trying again."
        }

        let reason: String
        switch transaction.cause {
        case is CancellationError:
            reason = "The model switch was cancelled before it completed."
        case let selection as ModelSelectionCoordinatorError:
            reason = selection.localizedDescription
        case let consent as ProviderConsentStoreError:
            reason = consent.localizedDescription
        case let activation as ProviderActivationTransactionError:
            switch activation.cause {
            case .credentialRequired, .credentialManagedElsewhere, .credentialStateUnavailable,
                 .credentialWriteNotVerified, .credentialReplacementRequiresSeparateAction:
                reason = "The selected provider credential is not ready. Open Models & Providers to check or replace its API key."
            default:
                reason = "The selected provider could not be prepared safely. Review Models & Providers and try again."
            }
        case let rpc as HarnessRPCClientError:
            switch rpc {
            case .timedOut:
                reason = "Harness timed out while verifying the selected provider and model."
            case .remote(let remote) where remote.code == .credentialRejected:
                reason = "The selected provider credential was rejected. Check or replace its API key in Models & Providers."
            case .remote(let remote) where remote.code == .settingsConflict:
                reason = "Provider settings changed during verification. Refresh Models & Providers and try again."
            case .controlPlaneOnly:
                reason = "Provider recovery is still active. Finish recovery before selecting a model."
            default:
                reason = "Harness could not verify the selected provider and model. Review Models & Providers and try again."
            }
        default:
            // Never surface arbitrary Error.localizedDescription here. The
            // underlying error can originate in a provider or runtime plugin.
            reason = "Harness could not safely verify the selected provider and model."
        }
        return "The model switch was not completed. The previous route remains active. \(reason)"
    }
}

struct ProviderSelectionTransactionError: LocalizedError {
    let cause: Error
    let rollbackComplete: Bool

    var errorDescription: String? {
        ProviderSelectionFailurePresentation.message(for: self)
    }
}

/// One commit path shared by every native model switcher. It keeps the app's
/// typed preference, DSH's authoritative `agent-default-model`, and the exact
/// endpoint consent in lockstep.
final class ProviderSelectionTransaction {
    typealias LocalModelPreflight = @MainActor (
        _ selection: ModelSelection,
        _ descriptor: ProviderDescriptor
    ) async throws -> Void

    private struct Snapshot {
        let settings: ModelProviderSettings
        let consent: ProviderConsentState
        let strictLocalMode: Bool
    }

    private struct CommittedSelection {
        let result: ProviderSelectionCommitResult
        let previous: Snapshot
    }

    private let coordinator: any ModelDefaultSynchronizing
    private let settingsStore: any ModelProviderSettingsStoring
    private let consentStore: any ProviderConsentStoring
    private let preferences: any StrictLocalModeStoring
    private let runtimeMutations: ProtectedRuntimeMutationCoordinator?
    private let localModelPreflight: LocalModelPreflight?
    private let beforeFreshRuntime: (@MainActor (ProviderSelectionCommitResult) throws -> Void)?

    init(
        coordinator: any ModelDefaultSynchronizing,
        settingsStore: any ModelProviderSettingsStoring,
        consentStore: any ProviderConsentStoring,
        preferences: any StrictLocalModeStoring,
        runtimeMutations: ProtectedRuntimeMutationCoordinator? = nil,
        localModelPreflight: LocalModelPreflight? = nil,
        beforeFreshRuntime: (@MainActor (ProviderSelectionCommitResult) throws -> Void)? = nil
    ) {
        self.coordinator = coordinator
        self.settingsStore = settingsStore
        self.consentStore = consentStore
        self.preferences = preferences
        self.runtimeMutations = runtimeMutations
        self.localModelPreflight = localModelPreflight
        self.beforeFreshRuntime = beforeFreshRuntime
    }

    @MainActor
    func isPrepared(selection: ModelSelection, descriptor: ProviderDescriptor) -> Bool {
        guard !ProviderSelectionCommitGate.isOccupied,
              selection.route.provider == descriptor.id,
              let stored = try? settingsStore.loadOrMigrate().settings.defaultSelection,
              stored.route.provider == selection.route.provider else { return false }
        // The local performance contract is synchronized for one exact model
        // route. A saved task for another model under the same Ollama provider
        // must first use the full stop/commit/restart transaction; otherwise it
        // could load an unsized model and bypass the 48 GB context boundary.
        if descriptor.boundary == .onDevice,
           stored.route != selection.route {
            return false
        }
        if descriptor.boundary == .onDevice,
           descriptor.id == BuiltInProviderDescriptors.ollama.id {
            return true
        }
        guard let consent = try? consentStore.load(),
              consent.activeProvider == descriptor.id,
              let grant = consent.activeGrant(for: descriptor.id),
              grant.permits(descriptor) else { return false }
        if descriptor.boundary == .onDevice { return true }
        return ProviderEgressPolicy.allowedOrigins(selection: selection, consent: consent).count == 1
    }

    @MainActor
    func commit(
        selection: ModelSelection,
        descriptor: ProviderDescriptor
    ) async throws -> ProviderSelectionCommitResult {
        guard selection.route.provider == descriptor.id else {
            throw ModelSelectionCoordinatorError.invalidSelection
        }
        // Production selections own the global lifecycle boundary and reject
        // a second stale UI choice. The FIFO form remains only for isolated
        // legacy transactions that have no runtime lifecycle driver.
        try await ProviderSelectionCommitGate.acquire(rejectIfOccupied: runtimeMutations != nil)
        defer { ProviderSelectionCommitGate.release() }
        let previous = try Snapshot(
            settings: settingsStore.loadOrMigrate().settings,
            consent: consentStore.load(),
            strictLocalMode: preferences.strictLocalMode
        )
        if selection.route.provider == BuiltInProviderDescriptors.ollama.id {
            // A transaction with a lifecycle driver can stop both DSH and the
            // owned Ollama generation. It must never cross that disruptive
            // boundary without the shared read-only model admission first.
            guard let localModelPreflight else {
                if runtimeMutations != nil {
                    throw LocalModelSelectionPreflightError.unavailable
                }
                // Isolated controller/unit-test transactions have no runtime
                // mutation boundary. Production injects the preflight below.
                return try await commitExclusively(
                    selection: selection,
                    descriptor: descriptor,
                    previous: previous
                )
            }
            try await localModelPreflight(selection, descriptor)
            try Task.checkCancellation()
        }
        guard let runtimeMutations else {
            return try await commitExclusively(
                selection: selection,
                descriptor: descriptor,
                previous: previous
            )
        }
        do {
            let committed: CommittedSelection = try await runtimeMutations.perform(
                kind: .providerSelection,
                requirement: .providerControlPlane,
                compensateAfterRecoveryFailure: { committed, permit in
                    try permit.validate()
                    guard await self.restore(
                        committed.previous,
                        synchronizeHarness: true
                    ) else {
                        throw ProviderSelectionTransactionError(
                            cause: ProtectedRuntimeMutationCoordinatorError.transitionFailed(.compensationIncomplete),
                            rollbackComplete: false
                        )
                    }
                    try self.beforeFreshRuntime?(self.handoffResult(for: committed.previous))
                }
            ) { _ in
                let result = try await self.commitExclusively(
                    selection: selection,
                    descriptor: descriptor,
                    previous: previous
                )
                try self.beforeFreshRuntime?(result)
                return CommittedSelection(result: result, previous: previous)
            }
            return committed.result
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            let rollbackComplete: Bool
            rollbackComplete = error == .previousVerifiedStateRestored
            throw ProviderSelectionTransactionError(cause: error, rollbackComplete: rollbackComplete)
        }
    }

    /// Caller must own `ProviderSelectionCommitGate`. Keeping the snapshot and
    /// rollback inside this non-reentrant critical section ensures that a later
    /// caller can never mistake an in-flight state for its own previous state.
    @MainActor
    private func commitExclusively(
        selection: ModelSelection,
        descriptor: ProviderDescriptor,
        previous: Snapshot
    ) async throws -> ProviderSelectionCommitResult {
        var attemptedHarnessSynchronization = false

        do {
            let newConsent = try consentStore.activate(descriptor)
            guard newConsent.activeProvider == descriptor.id,
                  let activeGrant = newConsent.activeGrant(for: descriptor.id),
                  activeGrant.permits(descriptor) else {
                throw ProviderConsentStoreError.unresolvedExternalEndpoint
            }
            if descriptor.requiresExplicitConsent,
               ProviderEgressPolicy.allowedOrigins(selection: selection, consent: newConsent).count != 1 {
                throw ProviderConsentStoreError.unresolvedExternalEndpoint
            }
            // A transport error can arrive after the remote mutation was
            // accepted. Treat every attempted RPC as potentially applied and
            // always restore the prior Harness route on failure.
            attemptedHarnessSynchronization = true
            _ = try await coordinator.synchronizeDefault(selection)
            var nextSettings = previous.settings
            nextSettings.defaultSelection = selection
            try settingsStore.save(nextSettings)
            preferences.strictLocalMode = descriptor.boundary == .onDevice
            return ProviderSelectionCommitResult(
                selection: selection,
                boundary: descriptor.boundary,
                origin: activeGrant.origin
            )
        } catch {
            let rollbackComplete = await restore(
                previous,
                synchronizeHarness: attemptedHarnessSynchronization
            )
            throw ProviderSelectionTransactionError(cause: error, rollbackComplete: rollbackComplete)
        }
    }

    @MainActor
    private func restore(_ snapshot: Snapshot, synchronizeHarness: Bool) async -> Bool {
        var complete = true
        do { try consentStore.restore(snapshot.consent) } catch { complete = false }
        if synchronizeHarness {
            // Compensation must survive cancellation of the UI task that began
            // the switch and settle before the global lifecycle gate can move.
            let coordinator = self.coordinator
            let previousSelection = snapshot.settings.defaultSelection
            let rollback = Task { try await coordinator.synchronizeDefault(previousSelection) }
            do { _ = try await rollback.value } catch { complete = false }
        }
        do { try settingsStore.save(snapshot.settings) } catch { complete = false }
        preferences.strictLocalMode = snapshot.strictLocalMode
        return complete
    }

    @MainActor
    private func handoffResult(for snapshot: Snapshot) -> ProviderSelectionCommitResult {
        let selection = snapshot.settings.defaultSelection
        let grant = snapshot.consent.activeGrant(for: selection.route.provider)
        let boundary = grant?.boundary
            ?? (selection.route.provider == BuiltInProviderDescriptors.ollama.id ? .onDevice : .cloud)
        return ProviderSelectionCommitResult(
            selection: selection,
            boundary: boundary,
            origin: grant?.origin
        )
    }
}
