import Foundation
import Testing
@testable import LocalHarness

@MainActor
private final class RuntimeMutationDriverFixture {
    var events: [String] = []
    var quiescenceContinuation: CheckedContinuation<Void, Error>?
    var stopContinuation: CheckedContinuation<Void, Error>?
    var inferenceContinuation: CheckedContinuation<Void, Error>?
    var controlPlaneContinuation: CheckedContinuation<Void, Error>?
    var pauseNextQuiescence = false
    var pauseNextStop = false
    var pauseNextInference = false
    var pauseNextControlPlane = false
    var quiescenceError: Error?
    var stopError: Error?
    var stopFailuresRemaining = 0
    var inferenceFailuresRemaining = 0
    var controlPlaneFailuresRemaining = 0
    var admissionsClosed = false
    var closeCount = 0
    var inferenceOpenCount = 0
    var failClosedCount = 0

    func driver() -> ProtectedRuntimeMutationDriver {
        ProtectedRuntimeMutationDriver(
            closeAdmissions: {
                self.events.append("close")
                self.closeCount += 1
                self.admissionsClosed = true
            },
            quiesceAdmissions: {
                self.events.append("quiesce")
                if self.pauseNextQuiescence {
                    self.pauseNextQuiescence = false
                    try await withCheckedThrowingContinuation { continuation in
                        self.quiescenceContinuation = continuation
                    }
                    self.quiescenceContinuation = nil
                }
                if let quiescenceError = self.quiescenceError { throw quiescenceError }
            },
            stopRuntime: {
                self.events.append("stop-begin")
                if let stopError = self.stopError { throw stopError }
                if self.stopFailuresRemaining > 0 {
                    self.stopFailuresRemaining -= 1
                    throw RuntimeMutationTestError.stop
                }
                if self.pauseNextStop {
                    self.pauseNextStop = false
                    try await withCheckedThrowingContinuation { continuation in
                        self.stopContinuation = continuation
                    }
                    self.stopContinuation = nil
                }
                self.events.append("stop-end")
            },
            startProviderControlPlane: {
                self.events.append("control-begin")
                if self.controlPlaneFailuresRemaining > 0 {
                    self.controlPlaneFailuresRemaining -= 1
                    throw RuntimeMutationTestError.controlPlane
                }
                if self.pauseNextControlPlane {
                    self.pauseNextControlPlane = false
                    try await withCheckedThrowingContinuation { continuation in
                        self.controlPlaneContinuation = continuation
                    }
                    self.controlPlaneContinuation = nil
                }
                self.events.append("control-end")
            },
            startVerifiedInference: {
                self.events.append("inference-begin")
                if self.inferenceFailuresRemaining > 0 {
                    self.inferenceFailuresRemaining -= 1
                    throw RuntimeMutationTestError.inference
                }
                if self.pauseNextInference {
                    self.pauseNextInference = false
                    try await withCheckedThrowingContinuation { continuation in
                        self.inferenceContinuation = continuation
                    }
                    self.inferenceContinuation = nil
                }
                self.events.append("inference-end")
                self.inferenceOpenCount += 1
                self.admissionsClosed = false
            },
            remainStoppedForUpdate: { self.events.append("update-stopped") },
            failClosed: {
                self.events.append("failed:\($0.localizedDescription)")
                self.failClosedCount += 1
                self.admissionsClosed = true
            }
        )
    }
}

private enum RuntimeMutationTestError: Error, Equatable, LocalizedError {
    case quiescence
    case stop
    case controlPlane
    case inference
    case mutation
    case compensation

    var errorDescription: String? {
        switch self {
        case .quiescence: return "quiescence acknowledgement was ambiguous"
        case .stop: return "exact runtime stop failed"
        case .controlPlane: return "control-plane startup failed"
        case .inference: return "verified inference startup failed"
        case .mutation: return "protected mutation failed"
        case .compensation: return "provider compensation failed"
        }
    }
}

@MainActor
private func waitForMutationFixture(_ condition: @MainActor () -> Bool) async -> Bool {
    for _ in 0..<1_000 {
        if condition() { return true }
        await Task.yield()
    }
    return condition()
}

@Suite("Protected runtime mutation lifecycle")
@MainActor
struct ProtectedRuntimeMutationCoordinatorTests {
    @Test
    func synchronousClosurePrecedesPausedCheckpointSendAndExactStopPrecedesControlPlaneMutation() async throws {
        let fixture = RuntimeMutationDriverFixture()
        fixture.pauseNextQuiescence = true
        fixture.pauseNextStop = true
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())

        var mutationRan = false
        let task = Task { @MainActor in
            try await coordinator.perform(
                kind: .providerSelection,
                requirement: .providerControlPlane
            ) { _ in
                fixture.events.append("mutation")
                mutationRan = true
            }
        }

        #expect(await waitForMutationFixture { fixture.quiescenceContinuation != nil })
        #expect(fixture.events == ["close", "quiesce"])
        #expect(fixture.admissionsClosed)
        #expect(!mutationRan)

        // The browser checkpoint reply may already be acknowledged while its
        // JavaScript continuation is paused before the captured priorSend.
        // Admission closure is synchronous, but mutation still waits for exact
        // process exit even if that old continuation subsequently runs.
        fixture.events.append("checkpoint-acknowledged-send-paused")
        fixture.quiescenceContinuation?.resume()
        #expect(await waitForMutationFixture { fixture.stopContinuation != nil })
        #expect(fixture.stopContinuation != nil)
        #expect(fixture.events == [
            "close", "quiesce", "checkpoint-acknowledged-send-paused", "stop-begin"
        ])
        #expect(!mutationRan)
        fixture.events.append("old-prior-send-ran")
        await Task.yield()
        #expect(!mutationRan)
        #expect(!fixture.events.contains("control-begin"))
        fixture.stopContinuation?.resume()
        try await task.value
        #expect(mutationRan)
        #expect(fixture.events == [
            "close", "quiesce", "checkpoint-acknowledged-send-paused", "stop-begin",
            "old-prior-send-ran", "stop-end", "control-begin", "control-end",
            "mutation", "stop-begin", "stop-end",
            "inference-begin", "inference-end"
        ])
        #expect(!fixture.admissionsClosed)
    }

    @Test
    func quiescenceAmbiguityIsSupersededOnlyAfterExactStopSettles() async throws {
        let fixture = RuntimeMutationDriverFixture()
        fixture.quiescenceError = RuntimeMutationTestError.quiescence
        fixture.pauseNextStop = true
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        var mutationRan = false
        let task = Task { @MainActor in
            try await coordinator.perform(kind: .skillActivation, requirement: .stoppedRuntime) { permit in
                try permit.validate()
                fixture.events.append("mutation")
                mutationRan = true
            }
        }

        #expect(await waitForMutationFixture { fixture.stopContinuation != nil })
        #expect(fixture.events == ["close", "quiesce", "stop-begin"])
        #expect(!mutationRan)
        #expect(fixture.admissionsClosed)
        fixture.stopContinuation?.resume()
        try await task.value
        #expect(fixture.events == [
            "close", "quiesce", "stop-begin", "stop-end", "mutation",
            "inference-begin", "inference-end"
        ])
        #expect(mutationRan)
    }

    @Test
    func rejectsConcurrentIntentDuringClosingWithoutTakingASecondAdmissionHold() async throws {
        let fixture = RuntimeMutationDriverFixture()
        fixture.pauseNextStop = true
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let first = Task { @MainActor in
            try await coordinator.acquire(kind: .providerSelection, requirement: .providerControlPlane)
        }
        #expect(await waitForMutationFixture { fixture.stopContinuation != nil })
        do {
            _ = try await coordinator.acquire(kind: .manualRestart, requirement: .stoppedRuntime)
            Issue.record("Expected the concurrent protected mutation to be rejected")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .busy(.providerSelection))
        }
        #expect(fixture.closeCount == 1)
        fixture.stopContinuation?.resume()
        let permit = try await first.value
        try await coordinator.finish(permit)
        #expect(fixture.closeCount == 1)
    }

    @Test
    func rejectsStaleSecondProviderSelectionInsteadOfQueuingItForLater() async throws {
        let fixture = RuntimeMutationDriverFixture()
        fixture.pauseNextStop = true
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let firstSelection = Task { @MainActor in
            try await coordinator.perform(
                kind: .providerSelection,
                requirement: .providerControlPlane
            ) { permit in
                try permit.validate()
                fixture.events.append("first-provider-selection")
            }
        }
        #expect(await waitForMutationFixture { fixture.stopContinuation != nil })

        var staleSelectionRan = false
        do {
            try await coordinator.perform(
                kind: .providerSelection,
                requirement: .providerControlPlane
            ) { _ in
                staleSelectionRan = true
                fixture.events.append("stale-provider-selection")
            }
            Issue.record("Expected stale provider selection to be rejected")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .busy(.providerSelection))
        } catch {
            Issue.record("Unexpected stale provider-selection error: \(error)")
        }
        #expect(!staleSelectionRan)
        #expect(fixture.closeCount == 1)

        fixture.stopContinuation?.resume()
        try await firstSelection.value
        await Task.yield()
        #expect(fixture.events.filter { $0 == "first-provider-selection" }.count == 1)
        #expect(!fixture.events.contains("stale-provider-selection"))
        #expect(fixture.closeCount == 1)
        #expect(!coordinator.isTransitionInFlight)
    }

    @Test
    func invalidatesPermitBeforePausedFreshInferenceAndRejectsFinishingIntent() async throws {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let permit = try await coordinator.acquire(kind: .stateBackup, requirement: .stoppedRuntime)
        try permit.validate()
        fixture.pauseNextInference = true
        let finish = Task { @MainActor in try await coordinator.finish(permit) }
        #expect(await waitForMutationFixture { fixture.inferenceContinuation != nil })
        #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
            try permit.validate()
        }
        do {
            _ = try await coordinator.acquire(kind: .websiteData, requirement: .stoppedRuntime)
            Issue.record("Expected finishing transition to reject concurrent intent")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .busy(.stateBackup))
        }
        fixture.inferenceContinuation?.resume()
        try await finish.value
        #expect(!coordinator.isTransitionInFlight)
    }

    @Test
    func queuedAcquireCannotOutrunSynchronousTerminationLatch() async {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let queuedAcquire = Task { @MainActor in
            try await coordinator.acquire(kind: .providerSelection, requirement: .providerControlPlane)
        }

        #expect(coordinator.beginTermination())
        #expect(!coordinator.claimAuthorizedUpdateTermination())
        #expect(!coordinator.validateClaimedUpdateTermination())
        do {
            _ = try await queuedAcquire.value
            Issue.record("Expected the pre-queued acquire to observe termination")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .terminating)
        } catch {
            Issue.record("Unexpected queued-acquire error: \(error)")
        }
        #expect(fixture.events.isEmpty)
        #expect(fixture.closeCount == 0)
        #expect(!coordinator.isTransitionInFlight)
    }

    @Test
    func auxiliaryServiceStartsOnlyWhileIdleAndBeforeTermination() async throws {
        let activeFixture = RuntimeMutationDriverFixture()
        activeFixture.pauseNextStop = true
        let activeCoordinator = ProtectedRuntimeMutationCoordinator(driver: activeFixture.driver())
        try activeCoordinator.validateAuxiliaryServiceStart()
        let acquire = Task { @MainActor in
            try await activeCoordinator.acquire(kind: .modelMemory, requirement: .stoppedRuntime)
        }
        #expect(await waitForMutationFixture { activeFixture.stopContinuation != nil })
        do {
            try activeCoordinator.validateAuxiliaryServiceStart()
            Issue.record("Expected auxiliary start rejection during an active mutation")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .busy(.modelMemory))
        }
        activeFixture.stopContinuation?.resume()
        let permit = try await acquire.value
        try await activeCoordinator.finish(permit)
        try activeCoordinator.validateAuxiliaryServiceStart()

        let failedFixture = RuntimeMutationDriverFixture()
        failedFixture.stopFailuresRemaining = 1
        let failedCoordinator = ProtectedRuntimeMutationCoordinator(driver: failedFixture.driver())
        do {
            _ = try await failedCoordinator.acquire(kind: .manualRestart, requirement: .stoppedRuntime)
            Issue.record("Expected exact-stop failure")
        } catch {
            #expect(failedCoordinator.isTransitionInFlight)
        }
        do {
            try failedCoordinator.validateAuxiliaryServiceStart()
            Issue.record("Expected auxiliary start rejection while failed closed")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .transitionFailed(let reason) = error else {
                Issue.record("Expected typed failed-closed rejection")
                return
            }
            #expect(reason == .failedClosed)
        }

        let terminatingFixture = RuntimeMutationDriverFixture()
        let terminatingCoordinator = ProtectedRuntimeMutationCoordinator(driver: terminatingFixture.driver())
        #expect(terminatingCoordinator.beginTermination())
        #expect(throws: ProtectedRuntimeMutationCoordinatorError.terminating) {
            try terminatingCoordinator.validateAuxiliaryServiceStart()
        }
    }

    @Test
    func readinessWaiterTimesOutWithItsLabelAndIgnoresLateOrDuplicateCallbacks() async throws {
        let waiter = ProtectedRuntimeReadinessWaiter()
        var startCount = 0
        do {
            try await waiter.wait(label: "provider topology", timeout: .milliseconds(1)) {
                startCount += 1
            }
            Issue.record("Expected readiness timeout")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .transitionFailed(let reason) = error else {
                Issue.record("Expected typed readiness timeout")
                return
            }
            #expect(reason == .readinessTimedOut)
        }
        #expect(startCount == 1)
        #expect(!waiter.isWaiting)
        #expect(!waiter.resume(with: .success(())))

        let resumed = Task { @MainActor in
            try await waiter.wait(label: "manual callback", timeout: .seconds(10)) {
                startCount += 1
            }
        }
        #expect(await waitForMutationFixture { waiter.isWaiting })
        do {
            try await waiter.wait(label: "overlapping callback", timeout: .seconds(10)) {}
            Issue.record("Expected overlapping waiter rejection")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .transitionFailed(let reason) = error else {
                Issue.record("Expected typed overlapping-waiter rejection")
                return
            }
            #expect(reason == .readinessWaiterBusy)
        }
        #expect(waiter.resume(with: .success(())))
        try await resumed.value
        #expect(!waiter.resume(with: .success(())))
        #expect(startCount == 2)
    }

    @Test
    func updateTerminateDispositionIsIrreversibleAndClaimsAuthorityExactlyOnce() async throws {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        var updatePermit: ProtectedRuntimeMutationPermit?
        try await coordinator.perform(
            kind: .updateInstall,
            requirement: .stoppedRuntime,
            disposition: .terminateForUpdate
        ) { permit in
            try permit.validate()
            updatePermit = permit
            fixture.events.append("install")
        }
        #expect(fixture.events == [
            "close", "quiesce", "stop-begin", "stop-end", "install", "update-stopped"
        ])
        if let updatePermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try updatePermit.validate()
            }
        }
        #expect(fixture.admissionsClosed)
        #expect(fixture.inferenceOpenCount == 0)
        #expect(coordinator.isTransitionInFlight)
        #expect(!coordinator.hasActiveMutation)

        do {
            _ = try await coordinator.acquire(kind: .manualRestart, requirement: .stoppedRuntime)
            Issue.record("Expected terminal update to reject every later restart")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .terminating)
        }
        #expect(throws: ProtectedRuntimeMutationCoordinatorError.terminating) {
            try coordinator.validateAuxiliaryServiceStart()
        }
        #expect(fixture.closeCount == 1)
        #expect(fixture.inferenceOpenCount == 0)

        #expect(!coordinator.validateClaimedUpdateTermination())
        #expect(coordinator.claimAuthorizedUpdateTermination())
        #expect(coordinator.validateClaimedUpdateTermination())
        #expect(!coordinator.claimAuthorizedUpdateTermination())
        #expect(coordinator.validateClaimedUpdateTermination())
        #expect(coordinator.isTransitionInFlight)
    }

    @Test
    func remainStoppedDispositionInvalidatesPermitAndRequiresAnExplicitRepair() async throws {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        var firstPermit: ProtectedRuntimeMutationPermit?
        _ = try await coordinator.perform(
            kind: .nativeProviderStateReset,
            requirement: .stoppedRuntime,
            disposition: .remainStopped
        ) { permit in
            try permit.validate()
            firstPermit = permit
            fixture.events.append("reset")
            return "reset-complete"
        }
        if let firstPermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try firstPermit.validate()
            }
        }
        #expect(fixture.events == [
            "close", "quiesce", "stop-begin", "stop-end", "reset"
        ])
        #expect(fixture.admissionsClosed)
        #expect(coordinator.isTransitionInFlight)
        #expect(!coordinator.hasActiveMutation)
        #expect(throws: ProtectedRuntimeMutationCoordinatorError.self) {
            try coordinator.validateAuxiliaryServiceStart()
        }

        try await coordinator.perform(kind: .manualRestart, requirement: .stoppedRuntime) { permit in
            try permit.validate()
            fixture.events.append("repair")
        }
        #expect(fixture.closeCount == 2)
        #expect(fixture.inferenceOpenCount == 1)
        #expect(!fixture.admissionsClosed)
        #expect(!coordinator.isTransitionInFlight)
    }

    @Test
    func committedSecondaryProviderActivationReturnsToFreshControlPlaneWithoutInference() async throws {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let permit = try await coordinator.acquire(
            kind: .providerActivation,
            requirement: .providerControlPlane
        )
        try permit.validate()
        fixture.events.append("credential-and-profile-committed")
        try await coordinator.finish(
            permit,
            disposition: .restartProviderControlPlane,
            mutationCommitted: true
        )

        #expect(fixture.events == [
            "close", "quiesce", "stop-begin", "stop-end", "control-begin", "control-end",
            "credential-and-profile-committed", "stop-begin", "stop-end", "control-begin", "control-end"
        ])
        #expect(fixture.inferenceOpenCount == 0)
        #expect(fixture.admissionsClosed)
        #expect(coordinator.isTransitionInFlight)
        #expect(!coordinator.hasActiveMutation)
        #expect(throws: ProtectedRuntimeMutationCoordinatorError.self) {
            try coordinator.validateAuxiliaryServiceStart()
        }

        // The next explicit provider choice can acquire from this stable
        // control-plane state and is the only operation that reopens inference.
        try await coordinator.perform(
            kind: .providerSelection,
            requirement: .providerControlPlane
        ) { nextPermit in
            try nextPermit.validate()
            fixture.events.append("explicit-model-selection")
        }
        #expect(fixture.inferenceOpenCount == 1)
        #expect(!fixture.admissionsClosed)
        #expect(!coordinator.isTransitionInFlight)
    }

    @Test
    func committedActiveCustomProfileEditRequiresExplicitReselectionBeforeInference() async throws {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let mutation = ProviderProtectedMutation(
            providerID: ProviderID("private-gateway"),
            kind: .profile
        )
        let permit = try await coordinator.acquire(
            kind: .providerProfile,
            requirement: .providerControlPlane
        )
        try permit.validate()
        fixture.events.append("profile-committed-consent-revoked")
        let disposition = ProviderMutationCompletionPolicy.disposition(
            for: mutation,
            effect: .committed,
            defaultProvider: mutation.providerID
        )
        #expect(disposition == .restartProviderControlPlane)
        try await coordinator.finish(
            permit,
            disposition: disposition,
            mutationCommitted: true
        )

        #expect(fixture.events == [
            "close", "quiesce", "stop-begin", "stop-end", "control-begin", "control-end",
            "profile-committed-consent-revoked", "stop-begin", "stop-end", "control-begin", "control-end"
        ])
        #expect(fixture.inferenceOpenCount == 0)
        #expect(fixture.admissionsClosed)
        #expect(coordinator.isTransitionInFlight)

        try await coordinator.perform(
            kind: .providerSelection,
            requirement: .providerControlPlane
        ) { selectionPermit in
            try selectionPermit.validate()
            fixture.events.append("exact-origin-reconsented")
        }
        #expect(fixture.inferenceOpenCount == 1)
        #expect(!fixture.admissionsClosed)
        #expect(!coordinator.isTransitionInFlight)
    }

    @Test
    func providerActivationCompletionPolicyRequiresExplicitSecondarySelection() {
        let deepSeek = ProviderProtectedMutation(
            providerID: ProviderID("deepseek"),
            kind: .activation
        )
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: deepSeek,
            effect: .committed,
            defaultProvider: ProviderID("ollama")
        ) == .restartProviderControlPlane)
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: deepSeek,
            effect: .notCommitted,
            defaultProvider: ProviderID("ollama")
        ) == .restartInference)
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: deepSeek,
            effect: .committed,
            defaultProvider: ProviderID("deepseek")
        ) == .restartInference)

        let activeProfile = ProviderProtectedMutation(
            providerID: ProviderID("private-gateway"),
            kind: .profile
        )
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: activeProfile,
            effect: .committed,
            defaultProvider: activeProfile.providerID
        ) == .restartProviderControlPlane)
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: activeProfile,
            effect: .committed,
            defaultProvider: ProviderID("ollama")
        ) == .restartInference)
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: activeProfile,
            effect: .notCommitted,
            defaultProvider: activeProfile.providerID
        ) == .restartInference)
        #expect(ProviderMutationCompletionPolicy.disposition(
            for: activeProfile,
            effect: .uncertain,
            defaultProvider: activeProfile.providerID
        ) == .restartProviderControlPlane)
    }

    @Test
    func providerActivationConfirmationNamesTheVerifiedProvider() {
        let message = ProviderActivationPresentation.verifiedCredentialMessage(
            providerDisplayName: "DeepSeek"
        )
        #expect(message == "Credential saved to Keychain. DeepSeek has not been contacted yet. Choose a model, review its data boundary, select Use for New Tasks, then run a test task to validate authentication and quota.")
        #expect(!message.contains("(result.provider.displayName)"))
    }

    @Test
    func exactStopFailureFailsClosedWithoutMutationControlPlaneOrReplacement() async {
        let fixture = RuntimeMutationDriverFixture()
        fixture.stopError = RuntimeMutationTestError.stop
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        var mutationRan = false
        do {
            try await coordinator.perform(kind: .mcpActivation, requirement: .stoppedRuntime) { _ in
                mutationRan = true
            }
            Issue.record("Expected exact stop failure")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .transitionFailed(let reason) = error else {
                Issue.record("Expected typed transition failure")
                return
            }
            #expect(reason == .runtimeStopFailed)
        } catch {
            Issue.record("Unexpected exact-stop error: \(error)")
        }
        #expect(!mutationRan)
        #expect(fixture.failClosedCount == 1)
        #expect(fixture.admissionsClosed)
        #expect(coordinator.isTransitionInFlight)
        #expect(!coordinator.hasActiveMutation)
        #expect(!fixture.events.contains("control-begin"))
        #expect(!fixture.events.contains("inference-begin"))
    }

    @Test
    func mutationFailureStillRestoresFreshVerifiedInferenceAndReleasesHold() async {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        do {
            try await coordinator.perform(kind: .sshAgentAccess, requirement: .stoppedRuntime) { _ in
                fixture.events.append("mutation-failed")
                throw RuntimeMutationTestError.mutation
            }
            Issue.record("Expected mutation failure")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .mutationFailed(.sshAgentAccess))
        } catch {
            Issue.record("Unexpected mutation error: \(error)")
        }
        #expect(fixture.events.suffix(2) == ["inference-begin", "inference-end"])
        #expect(!coordinator.isTransitionInFlight)
        #expect(!fixture.admissionsClosed)
        #expect(fixture.failClosedCount == 0)
    }

    @Test
    func hostileDriverMutationAndRecoveryErrorsNeverEnterPublicDescriptions() async {
        struct HostileError: LocalizedError {
            var errorDescription: String? {
                "api_key=sk-hostile-secret-123456789 /Users/private/project \u{202E}\u{0007}" +
                    String(repeating: "ATTACKER-DIAGNOSTIC", count: 4_000)
            }
        }

        let stopFixture = RuntimeMutationDriverFixture()
        stopFixture.stopError = HostileError()
        let stopCoordinator = ProtectedRuntimeMutationCoordinator(driver: stopFixture.driver())
        do {
            _ = try await stopCoordinator.acquire(kind: .manualRestart, requirement: .stoppedRuntime)
            Issue.record("Expected hostile stop failure")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            let message = error.localizedDescription
            #expect(!message.contains("sk-hostile"))
            #expect(!message.contains("/Users/private"))
            #expect(!message.contains("ATTACKER-DIAGNOSTIC"))
            #expect(!message.contains("\u{202E}"))
            #expect(message.count < 400)
        } catch {
            Issue.record("Expected typed protected-runtime error")
        }

        let mutationFixture = RuntimeMutationDriverFixture()
        let mutationCoordinator = ProtectedRuntimeMutationCoordinator(driver: mutationFixture.driver())
        do {
            try await mutationCoordinator.perform(kind: .websiteData, requirement: .stoppedRuntime) { _ in
                throw HostileError()
            }
            Issue.record("Expected hostile mutation failure")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .mutationFailed(.websiteData))
            let message = error.localizedDescription
            #expect(!message.contains("sk-hostile"))
            #expect(!message.contains("/Users/private"))
            #expect(!message.contains("ATTACKER-DIAGNOSTIC"))
            #expect(message.count < 400)
        } catch {
            Issue.record("Expected typed protected-runtime error")
        }

        let direct = ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(
            kind: .websiteData
        ).localizedDescription
        #expect(!direct.contains("sk-hostile"))
        #expect(!direct.contains("/Users/private"))
        #expect(!direct.contains("ATTACKER-DIAGNOSTIC"))
        #expect(direct.count < 400)
    }

    @Test
    func mutationAndRecoveryFailureIsTypedAndRemainsFailClosed() async {
        let fixture = RuntimeMutationDriverFixture()
        fixture.inferenceFailuresRemaining = 1
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        do {
            try await coordinator.perform(kind: .websiteData, requirement: .stoppedRuntime) { _ in
                throw RuntimeMutationTestError.mutation
            }
            Issue.record("Expected mutation and recovery failure")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .mutationAndRecoveryFailed(let kind) = error else {
                Issue.record("Expected typed mutation-and-recovery failure")
                return
            }
            #expect(kind == .websiteData)
        } catch {
            Issue.record("Unexpected mutation/recovery error: \(error)")
        }
        #expect(fixture.admissionsClosed)
        #expect(fixture.failClosedCount == 1)
        #expect(coordinator.isTransitionInFlight)
    }

    @Test
    func committedMutationWithFailedRecoveryReturnsDedicatedTypedOutcome() async {
        let fixture = RuntimeMutationDriverFixture()
        fixture.inferenceFailuresRemaining = 1
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        do {
            _ = try await coordinator.perform(
                kind: .performanceProfile,
                requirement: .stoppedRuntime
            ) { _ in
                fixture.events.append("committed")
                return "saved-profile"
            }
            Issue.record("Expected committed-but-recovery-failed outcome")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .mutationCommittedButRecoveryFailed(let kind) = error else {
                Issue.record("Expected dedicated committed outcome")
                return
            }
            #expect(kind == .performanceProfile)
        } catch {
            Issue.record("Unexpected committed/recovery error: \(error)")
        }
        #expect(fixture.events.contains("committed"))
        #expect(fixture.admissionsClosed)
        #expect(fixture.failClosedCount == 1)
        #expect(!coordinator.hasActiveMutation)
    }

    @Test
    func providerCompensationRestoresPreviousRouteAndInvalidatesBothPermits() async {
        let fixture = RuntimeMutationDriverFixture()
        fixture.inferenceFailuresRemaining = 1
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        var mutationPermit: ProtectedRuntimeMutationPermit?
        var compensationPermit: ProtectedRuntimeMutationPermit?
        do {
            _ = try await coordinator.perform(
                kind: .providerSelection,
                requirement: .providerControlPlane,
                compensateAfterRecoveryFailure: { value, permit in
                    #expect(value == "new-route")
                    try permit.validate()
                    compensationPermit = permit
                    fixture.events.append("compensate")
                },
                mutation: { permit in
                    try permit.validate()
                    mutationPermit = permit
                    fixture.events.append("commit-new-route")
                    return "new-route"
                }
            )
            Issue.record("Expected restored-previous-route transition result")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .previousVerifiedStateRestored = error else {
                Issue.record("Expected previous-route-restored transition result")
                return
            }
        } catch {
            Issue.record("Unexpected provider compensation result: \(error)")
        }
        #expect(fixture.events == [
            "close", "quiesce", "stop-begin", "stop-end", "control-begin", "control-end",
            "commit-new-route", "stop-begin", "stop-end", "inference-begin",
            "stop-begin", "stop-end",
            "failed:verified inference startup failed",
            "stop-begin", "stop-end", "control-begin", "control-end", "compensate",
            "stop-begin", "stop-end", "inference-begin", "inference-end"
        ])
        #expect(!coordinator.isTransitionInFlight)
        #expect(!fixture.admissionsClosed)
        #expect(fixture.failClosedCount == 1) // Initial new-route recovery failed closed before compensation.
        if let mutationPermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try mutationPermit.validate()
            }
        }
        if let compensationPermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try compensationPermit.validate()
            }
        }
    }

    @Test
    func providerCompensationFailureIsTypedAndKeepsEveryPermitInvalid() async {
        let fixture = RuntimeMutationDriverFixture()
        fixture.inferenceFailuresRemaining = 1
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        var mutationPermit: ProtectedRuntimeMutationPermit?
        var compensationPermit: ProtectedRuntimeMutationPermit?
        do {
            _ = try await coordinator.perform(
                kind: .providerSelection,
                requirement: .providerControlPlane,
                compensateAfterRecoveryFailure: { _, permit in
                    compensationPermit = permit
                    try permit.validate()
                    throw RuntimeMutationTestError.compensation
                },
                mutation: { permit in
                    mutationPermit = permit
                    return "committed-route"
                }
            )
            Issue.record("Expected failed compensation outcome")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .mutationAndRecoveryFailed(let kind) = error else {
                Issue.record("Expected typed compensation failure")
                return
            }
            #expect(kind == .providerSelection)
        } catch {
            Issue.record("Unexpected provider compensation error: \(error)")
        }
        #expect(coordinator.isTransitionInFlight)
        #expect(!coordinator.hasActiveMutation)
        #expect(fixture.admissionsClosed)
        #expect(fixture.failClosedCount == 2)
        if let mutationPermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try mutationPermit.validate()
            }
        }
        if let compensationPermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try compensationPermit.validate()
            }
        }
    }

    @Test
    func providerControlPlaneFinishStopFailureFailsClosedBeforeInference() async throws {
        let fixture = RuntimeMutationDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let permit = try await coordinator.acquire(
            kind: .providerCredential,
            requirement: .providerControlPlane
        )
        fixture.stopFailuresRemaining = 1
        do {
            try await coordinator.finish(permit)
            Issue.record("Expected control-plane stop failure")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            guard case .transitionFailed(let reason) = error else {
                Issue.record("Expected typed transition failure")
                return
            }
            #expect(reason == .runtimeStopFailed)
        }
        #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
            try permit.validate()
        }
        #expect(!fixture.events.contains("inference-begin"))
        #expect(fixture.admissionsClosed)
        #expect(fixture.failClosedCount == 1)
    }

    @Test
    func failedClosedRetryExactStopsAgainAndReleasesOnlyTheNewHold() async throws {
        let fixture = RuntimeMutationDriverFixture()
        fixture.stopFailuresRemaining = 1
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        do {
            _ = try await coordinator.perform(kind: .manualRestart, requirement: .stoppedRuntime) { _ in
                Issue.record("First failed-stop mutation must not run")
            }
            Issue.record("Expected first stop failure")
        } catch {
            #expect(coordinator.isTransitionInFlight)
        }
        #expect(fixture.admissionsClosed)
        #expect(fixture.closeCount == 1)

        var retryPermit: ProtectedRuntimeMutationPermit?
        try await coordinator.perform(kind: .manualRestart, requirement: .stoppedRuntime) { permit in
            try permit.validate()
            retryPermit = permit
            fixture.events.append("retry-mutation")
        }
        #expect(fixture.closeCount == 2)
        #expect(fixture.inferenceOpenCount == 1)
        #expect(!fixture.admissionsClosed)
        #expect(!coordinator.isTransitionInFlight)
        #expect(!coordinator.hasActiveMutation)
        if let retryPermit {
            #expect(throws: ProtectedRuntimeMutationCoordinatorError.invalidPermit) {
                try retryPermit.validate()
            }
        }
        #expect(fixture.events.suffix(3) == [
            "retry-mutation", "inference-begin", "inference-end"
        ])
    }
}
