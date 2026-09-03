import Foundation
import Testing
@testable import LocalHarness

private enum SelectionTransactionTestError: Error, Equatable {
    case settingsLoad
    case settingsSave
    case consentLoad
    case consentActivate
    case consentRestore
    case harnessMutation
    case localPreflight
}

private actor SelectionTransactionBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func enterAndWait() async {
        entered = true
        let observers = entryWaiters
        entryWaiters.removeAll()
        observers.forEach { $0.resume() }
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        released = true
        let blocked = releaseWaiters
        releaseWaiters.removeAll()
        blocked.forEach { $0.resume() }
    }
}

private actor SelectionTransactionSynchronizer: ModelDefaultSynchronizing {
    private var currentSelection: ModelSelection
    private var history: [ModelSelection] = []
    private var failingCalls: Set<Int>
    private var applyBeforeFailureCalls: Set<Int>
    private var cancellationSensitiveCalls: Set<Int>
    private var barriers: [Int: SelectionTransactionBarrier]

    init(
        currentSelection: ModelSelection,
        failingCalls: Set<Int> = [],
        applyBeforeFailureCalls: Set<Int> = [],
        cancellationSensitiveCalls: Set<Int> = [],
        barriers: [Int: SelectionTransactionBarrier] = [:]
    ) {
        self.currentSelection = currentSelection
        self.failingCalls = failingCalls
        self.applyBeforeFailureCalls = applyBeforeFailureCalls
        self.cancellationSensitiveCalls = cancellationSensitiveCalls
        self.barriers = barriers
    }

    func synchronizeDefault(_ selection: ModelSelection) async throws -> HarnessSettingsNamespace {
        history.append(selection)
        let call = history.count
        if let barrier = barriers[call] { await barrier.enterAndWait() }
        if applyBeforeFailureCalls.contains(call) { currentSelection = selection }
        if cancellationSensitiveCalls.contains(call), Task.isCancelled { throw CancellationError() }
        if failingCalls.contains(call) { throw SelectionTransactionTestError.harnessMutation }
        currentSelection = selection
        return HarnessSettingsNamespace(
            ns: "agent-default-model",
            schema: .object([:]),
            value: .object([
                "provider": .string(selection.route.provider.rawValue),
                "model": .string(selection.route.model.rawValue)
            ]),
            base: nil,
            user: nil,
            applies: .live,
            secrets: [],
            revision: call
        )
    }

    func snapshot() -> (current: ModelSelection, history: [ModelSelection]) {
        (currentSelection, history)
    }
}

@MainActor
private final class SelectionTransactionSettingsStore: ModelProviderSettingsStoring {
    struct SaveBehavior {
        let fails: Bool
        let appliesBeforeFailure: Bool

        static let succeed = SaveBehavior(fails: false, appliesBeforeFailure: false)
        static let fail = SaveBehavior(fails: true, appliesBeforeFailure: false)
        static let applyThenFail = SaveBehavior(fails: true, appliesBeforeFailure: true)
    }

    var settings: ModelProviderSettings
    var loadError: SelectionTransactionTestError?
    var saveBehaviors: [SaveBehavior] = []
    private(set) var saveAttempts: [ModelProviderSettings] = []

    init(selection: ModelSelection) {
        settings = ModelProviderSettings(defaultSelection: selection)
    }

    func loadOrMigrate() throws -> ModelProviderSettingsLoadResult {
        if let loadError { throw loadError }
        return ModelProviderSettingsLoadResult(settings: settings, source: .stored)
    }

    func save(_ settings: ModelProviderSettings) throws {
        saveAttempts.append(settings)
        let behavior = saveBehaviors.isEmpty ? .succeed : saveBehaviors.removeFirst()
        if !behavior.fails || behavior.appliesBeforeFailure { self.settings = settings }
        if behavior.fails { throw SelectionTransactionTestError.settingsSave }
    }
}

@MainActor
private final class SelectionTransactionConsentStore: ProviderConsentStoring {
    var state: ProviderConsentState
    var loadError: SelectionTransactionTestError?
    var activateError: SelectionTransactionTestError?
    var activateAppliesBeforeFailure = false
    var activatedStateOverride: ProviderConsentState?
    var restoreError: SelectionTransactionTestError?
    private(set) var activations: [ProviderDescriptor] = []
    private(set) var restorations: [ProviderConsentState] = []

    init(state: ProviderConsentState) {
        self.state = state
    }

    func load() throws -> ProviderConsentState {
        if let loadError { throw loadError }
        return state
    }

    func activate(_ descriptor: ProviderDescriptor) throws -> ProviderConsentState {
        activations.append(descriptor)
        if let activatedStateOverride {
            state = activatedStateOverride
            return activatedStateOverride
        }
        var next = state
        next.activeProvider = descriptor.id
        next.grants = next.grants.filter { $0.provider != descriptor.id }
        next.grants.insert(ProviderConsentGrant(for: descriptor))
        if activateAppliesBeforeFailure { state = next }
        if let activateError { throw activateError }
        state = next
        return next
    }

    func restore(_ state: ProviderConsentState) throws {
        restorations.append(state)
        if let restoreError { throw restoreError }
        self.state = state
    }
}

@MainActor
private final class SelectionTransactionPreferences: StrictLocalModeStoring {
    var strictLocalMode: Bool

    init(strictLocalMode: Bool) {
        self.strictLocalMode = strictLocalMode
    }
}

@MainActor
private struct SelectionTransactionFixture {
    let transaction: ProviderSelectionTransaction
    let settings: SelectionTransactionSettingsStore
    let consent: SelectionTransactionConsentStore
    let preferences: SelectionTransactionPreferences
    let synchronizer: SelectionTransactionSynchronizer
    let initialSelection: ModelSelection
    let initialConsent: ProviderConsentState

    init(
        initialSelection: ModelSelection = .defaultLocal,
        initialDescriptor: ProviderDescriptor = BuiltInProviderDescriptors.ollama,
        strictLocal: Bool = true,
        failingHarnessCalls: Set<Int> = [],
        applyBeforeHarnessFailureCalls: Set<Int> = [],
        cancellationSensitiveHarnessCalls: Set<Int> = [],
        barriers: [Int: SelectionTransactionBarrier] = [:],
        localModelPreflight: ProviderSelectionTransaction.LocalModelPreflight? = nil
    ) {
        self.initialSelection = initialSelection
        initialConsent = ProviderConsentState(
            activeProvider: initialDescriptor.id,
            grants: [ProviderConsentGrant(for: initialDescriptor)]
        )
        settings = SelectionTransactionSettingsStore(selection: initialSelection)
        consent = SelectionTransactionConsentStore(state: initialConsent)
        preferences = SelectionTransactionPreferences(strictLocalMode: strictLocal)
        synchronizer = SelectionTransactionSynchronizer(
            currentSelection: initialSelection,
            failingCalls: failingHarnessCalls,
            applyBeforeFailureCalls: applyBeforeHarnessFailureCalls,
            cancellationSensitiveCalls: cancellationSensitiveHarnessCalls,
            barriers: barriers
        )
        transaction = ProviderSelectionTransaction(
            coordinator: synchronizer,
            settingsStore: settings,
            consentStore: consent,
            preferences: preferences,
            localModelPreflight: localModelPreflight
        )
    }
}

private func testDescriptor(
    id: String,
    endpoint: String,
    boundary: DataBoundary
) -> ProviderDescriptor {
    BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID(id),
        displayName: id,
        baseURL: URL(string: endpoint)!,
        boundary: boundary
    )
}

private func testSelection(_ provider: String, _ model: String) -> ModelSelection {
    ModelSelection(
        route: ModelRoute(provider: ProviderID(provider), model: ModelID(model)),
        reasoningEffort: "high",
        performanceProfile: .deep
    )
}

@MainActor
private func requireTransactionFailure(
    _ operation: () async throws -> Void,
    rollbackComplete: Bool,
    cause: SelectionTransactionTestError
) async {
    do {
        try await operation()
        Issue.record("Expected the provider selection transaction to fail")
    } catch let error as ProviderSelectionTransactionError {
        #expect(error.rollbackComplete == rollbackComplete)
        #expect(error.cause as? SelectionTransactionTestError == cause)
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }
}

@Suite(.serialized)
struct ProviderSelectionTransactionTests {
    @Test @MainActor
    func alternateOllamaPreflightFailureCannotMutateAnySelectionStoreOrHarnessRoute() async throws {
        var preflightCalls: [ModelSelection] = []
        let fixture = SelectionTransactionFixture(
            localModelPreflight: { selection, descriptor in
                #expect(descriptor == BuiltInProviderDescriptors.ollama)
                preflightCalls.append(selection)
                throw SelectionTransactionTestError.localPreflight
            }
        )
        let requested = ModelSelection(
            route: ModelRoute(
                provider: BuiltInProviderDescriptors.ollama.id,
                model: ModelID("alternate-tools:latest")
            ),
            performanceProfile: .compatibility
        )

        await #expect(throws: SelectionTransactionTestError.localPreflight) {
            _ = try await fixture.transaction.commit(
                selection: requested,
                descriptor: BuiltInProviderDescriptors.ollama
            )
        }

        #expect(preflightCalls == [requested])
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.settings.saveAttempts.isEmpty)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.consent.activations.isEmpty)
        #expect(fixture.preferences.strictLocalMode)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func committedSwitchHandoffSurvivesCancellationBeforeANextSwitchFails() async throws {
        let firstBarrier = SelectionTransactionBarrier()
        let fixture = SelectionTransactionFixture(
            failingHarnessCalls: [2],
            barriers: [1: firstBarrier]
        )
        let firstDescriptor = testDescriptor(
            id: "route-a", endpoint: "https://a.example/v1", boundary: .cloud
        )
        let firstSelection = testSelection("route-a", "model-a")
        let secondDescriptor = testDescriptor(
            id: "route-b", endpoint: "https://b.example/v1", boundary: .cloud
        )
        let secondSelection = testSelection("route-b", "model-b")
        var handoffs: [ProviderSelectionCommitResult] = []

        let first = Task { @MainActor in
            try await ProviderSelectionHandoff.commit(
                selection: firstSelection,
                descriptor: firstDescriptor,
                using: fixture.transaction
            ) { handoffs.append($0) }
        }
        await firstBarrier.waitUntilEntered()
        first.cancel()
        await firstBarrier.release()
        _ = try await first.value

        do {
            try await ProviderSelectionHandoff.commit(
                selection: secondSelection,
                descriptor: secondDescriptor,
                using: fixture.transaction
            ) { handoffs.append($0) }
            Issue.record("Expected the second route to fail and roll back")
        } catch let error as ProviderSelectionTransactionError {
            #expect(error.rollbackComplete)
            #expect(error.cause as? SelectionTransactionTestError == .harnessMutation)
        }

        #expect(handoffs.map(\.selection) == [firstSelection])
        #expect(fixture.settings.settings.defaultSelection == firstSelection)
        #expect(fixture.consent.state.activeProvider == firstDescriptor.id)
        #expect(fixture.preferences.strictLocalMode == false)
        let runtime = await fixture.synchronizer.snapshot()
        #expect(runtime.current == firstSelection)
        #expect(runtime.history == [firstSelection, secondSelection, firstSelection])
    }

    @Test @MainActor
    func successfulCommitPersistsOneExactRouteBoundaryAndOrigin() async throws {
        let fixture = SelectionTransactionFixture()
        let descriptor = testDescriptor(
            id: "remote-a",
            endpoint: "https://models.example.test:8443/v1",
            boundary: .cloud
        )
        let selection = testSelection("remote-a", "reasoner/v2")

        let result = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)

        #expect(result.selection == selection)
        #expect(result.boundary == .cloud)
        #expect(result.origin == ProviderEndpointOrigin(url: descriptor.defaultBaseURL!))
        #expect(fixture.settings.settings.defaultSelection == selection)
        #expect(fixture.consent.state.activeProvider == descriptor.id)
        let grant = try #require(fixture.consent.state.activeGrant(for: descriptor.id))
        #expect(grant.provider == descriptor.id)
        #expect(grant.boundary == .cloud)
        #expect(grant.origin == ProviderEndpointOrigin(url: descriptor.defaultBaseURL!))
        #expect(!fixture.preferences.strictLocalMode)
        #expect(await fixture.synchronizer.snapshot().current == selection)
        #expect(fixture.transaction.isPrepared(selection: selection, descriptor: descriptor))

        // A repaired cloud route is still not inference-ready on the old
        // recovery identity. Only the exact freshly restarted endpoint can be
        // promoted after the transaction/topology checks above succeed.
        let recoveryEndpoint = HarnessEndpoint(
            baseURL: URL(string: "http://127.0.0.1:41001")!,
            token: "recovery-token",
            nonce: "recovery-nonce",
            processIdentifier: 41_001
        )
        let restartedEndpoint = HarnessEndpoint(
            baseURL: URL(string: "http://127.0.0.1:41002")!,
            token: "inference-token",
            nonce: "inference-nonce",
            processIdentifier: 41_002
        )
        let rpc = HarnessRPCClient(endpoint: recoveryEndpoint, accessMode: .controlPlaneOnly)
        rpc.setControlPlaneEndpoint(restartedEndpoint)
        #expect(!rpc.promoteToFullInference(expected: recoveryEndpoint))
        #expect(rpc.currentAccessMode() == .controlPlaneOnly)
        #expect(rpc.promoteToFullInference(expected: restartedEndpoint))
        #expect(rpc.currentAccessMode() == .fullInference)
    }

    @Test @MainActor
    func preparedLocalRouteRequiresExactModelWhileConsentedCloudMayUseAnotherModel() throws {
        let localFixture = SelectionTransactionFixture()
        let anotherLocalModel = ModelSelection(
            route: ModelRoute(
                provider: BuiltInProviderDescriptors.ollama.id,
                model: ModelID("another-local-model")
            ),
            reasoningEffort: "high",
            performanceProfile: .balanced
        )
        #expect(!localFixture.transaction.isPrepared(
            selection: anotherLocalModel,
            descriptor: BuiltInProviderDescriptors.ollama
        ))

        let cloudDescriptor = testDescriptor(
            id: "cloud-provider",
            endpoint: "https://cloud.example.test/v1",
            boundary: .cloud
        )
        let cloudDefault = testSelection("cloud-provider", "model-a")
        let cloudFixture = SelectionTransactionFixture(
            initialSelection: cloudDefault,
            initialDescriptor: cloudDescriptor,
            strictLocal: false
        )
        #expect(cloudFixture.transaction.isPrepared(
            selection: testSelection("cloud-provider", "model-b"),
            descriptor: cloudDescriptor
        ))
    }

    @Test @MainActor
    func mismatchedDescriptorIsRejectedBeforeAnyStateChanges() async {
        let fixture = SelectionTransactionFixture()
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-b", "model")

        await #expect(throws: ModelSelectionCoordinatorError.invalidSelection) {
            _ = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.preferences.strictLocalMode)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func settingsSnapshotFailureMakesNoChanges() async {
        let fixture = SelectionTransactionFixture()
        fixture.settings.loadError = .settingsLoad
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)

        await #expect(throws: SelectionTransactionTestError.settingsLoad) {
            _ = try await fixture.transaction.commit(
                selection: testSelection("remote-a", "model"), descriptor: descriptor
            )
        }
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.settings.saveAttempts.isEmpty)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func consentSnapshotFailureMakesNoChanges() async {
        let fixture = SelectionTransactionFixture()
        fixture.consent.loadError = .consentLoad
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)

        await #expect(throws: SelectionTransactionTestError.consentLoad) {
            _ = try await fixture.transaction.commit(
                selection: testSelection("remote-a", "model"), descriptor: descriptor
            )
        }
        #expect(fixture.consent.activations.isEmpty)
        #expect(fixture.settings.saveAttempts.isEmpty)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func consentActivationFailureRollsBackEveryLocalState() async {
        let fixture = SelectionTransactionFixture()
        fixture.consent.activateError = .consentActivate
        fixture.consent.activateAppliesBeforeFailure = true
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(
                selection: testSelection("remote-a", "model"), descriptor: descriptor
            )
        }, rollbackComplete: true, cause: .consentActivate)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.preferences.strictLocalMode)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func unsafeExternalOriginFailsBeforeHarnessMutationAndRollsBackConsent() async {
        let fixture = SelectionTransactionFixture()
        let descriptor = testDescriptor(id: "remote-http", endpoint: "http://public.example.test/v1", boundary: .cloud)

        do {
            _ = try await fixture.transaction.commit(
                selection: testSelection("remote-http", "model"), descriptor: descriptor
            )
            Issue.record("Expected the unsafe external endpoint to fail")
        } catch let error as ProviderSelectionTransactionError {
            #expect(error.rollbackComplete)
            #expect(error.cause as? ProviderConsentStoreError == .unresolvedExternalEndpoint)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func nonExactConsentResultFailsClosedBeforeHarnessMutation() async {
        let fixture = SelectionTransactionFixture()
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let wrongDescriptor = testDescriptor(
            id: "remote-a", endpoint: "http://192.168.20.4:8080/v1", boundary: .localNetwork
        )
        fixture.consent.activatedStateOverride = ProviderConsentState(
            activeProvider: descriptor.id,
            grants: [ProviderConsentGrant(for: wrongDescriptor)]
        )

        do {
            _ = try await fixture.transaction.commit(
                selection: testSelection("remote-a", "model"), descriptor: descriptor
            )
            Issue.record("Expected mismatched endpoint/boundary consent to fail")
        } catch let error as ProviderSelectionTransactionError {
            #expect(error.rollbackComplete)
            #expect(error.cause as? ProviderConsentStoreError == .unresolvedExternalEndpoint)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(await fixture.synchronizer.snapshot().history.isEmpty)
    }

    @Test @MainActor
    func ambiguousHarnessFailureAlwaysAttemptsAuthoritativeRollback() async {
        let fixture = SelectionTransactionFixture(
            failingHarnessCalls: [1],
            applyBeforeHarnessFailureCalls: [1]
        )
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-a", "model")

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }, rollbackComplete: true, cause: .harnessMutation)
        let harness = await fixture.synchronizer.snapshot()
        #expect(harness.history == [selection, fixture.initialSelection])
        #expect(harness.current == fixture.initialSelection)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.preferences.strictLocalMode)
    }

    @Test @MainActor
    func settingsCommitFailureRestoresHarnessConsentSettingsAndPreference() async {
        let fixture = SelectionTransactionFixture()
        fixture.settings.saveBehaviors = [.fail, .succeed]
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-a", "model")

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }, rollbackComplete: true, cause: .settingsSave)
        let harness = await fixture.synchronizer.snapshot()
        #expect(harness.history == [selection, fixture.initialSelection])
        #expect(harness.current == fixture.initialSelection)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.preferences.strictLocalMode)
    }

    @Test @MainActor
    func rollbackRestoresPriorOriginWhenTheProviderIDIsUnchanged() async {
        let oldDescriptor = testDescriptor(
            id: "private-gateway", endpoint: "https://old.example.test:9443/v1", boundary: .cloud
        )
        let oldSelection = testSelection("private-gateway", "old-model")
        let fixture = SelectionTransactionFixture(
            initialSelection: oldSelection,
            initialDescriptor: oldDescriptor,
            strictLocal: false
        )
        fixture.settings.saveBehaviors = [.fail, .succeed]
        let newDescriptor = testDescriptor(
            id: "private-gateway", endpoint: "https://new.example.test:10443/v1", boundary: .cloud
        )
        let newSelection = testSelection("private-gateway", "new-model")

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(selection: newSelection, descriptor: newDescriptor)
        }, rollbackComplete: true, cause: .settingsSave)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.consent.state.activeGrant(for: oldDescriptor.id)?.origin == ProviderEndpointOrigin(url: oldDescriptor.defaultBaseURL!))
        #expect(await fixture.synchronizer.snapshot().current == oldSelection)
        #expect(!fixture.preferences.strictLocalMode)
    }

    @Test @MainActor
    func consentRollbackFailureIsReportedAndLeavesExternalEgressFailClosed() async {
        let fixture = SelectionTransactionFixture(failingHarnessCalls: [1])
        fixture.consent.restoreError = .consentRestore
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-a", "model")

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }, rollbackComplete: false, cause: .harnessMutation)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.preferences.strictLocalMode)
        #expect(ProviderEgressPolicy.allowedOrigins(
            selection: fixture.initialSelection,
            consent: fixture.consent.state
        ).isEmpty)
    }

    @Test @MainActor
    func harnessRollbackFailureIsReportedAndLocalPolicyRemainsFailClosed() async {
        let fixture = SelectionTransactionFixture(failingHarnessCalls: [2])
        fixture.settings.saveBehaviors = [.fail, .succeed]
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-a", "model")

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }, rollbackComplete: false, cause: .settingsSave)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.preferences.strictLocalMode)
        #expect(ProviderEgressPolicy.allowedOrigins(
            selection: selection,
            consent: fixture.consent.state
        ).isEmpty)
    }

    @Test @MainActor
    func settingsRollbackFailureIsReportedAndMismatchedConsentFailsClosed() async {
        let fixture = SelectionTransactionFixture()
        fixture.settings.saveBehaviors = [.applyThenFail, .fail]
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-a", "model")

        await requireTransactionFailure({
            _ = try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }, rollbackComplete: false, cause: .settingsSave)
        #expect(fixture.settings.settings.defaultSelection == selection)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.preferences.strictLocalMode)
        #expect(ProviderEgressPolicy.allowedOrigins(
            selection: selection,
            consent: fixture.consent.state
        ).isEmpty)
    }

    @Test @MainActor
    func overlappingCommitsFromSeparateCallersAreFIFOAndNeverInterleave() async throws {
        let barrier = SelectionTransactionBarrier()
        let fixture = SelectionTransactionFixture(barriers: [1: barrier])
        let secondTransaction = ProviderSelectionTransaction(
            coordinator: fixture.synchronizer,
            settingsStore: fixture.settings,
            consentStore: fixture.consent,
            preferences: fixture.preferences
        )
        let firstDescriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let firstSelection = testSelection("remote-a", "first")
        let secondDescriptor = testDescriptor(id: "lan-b", endpoint: "http://192.168.8.40:8080/v1", boundary: .localNetwork)
        let secondSelection = testSelection("lan-b", "second")

        let first = Task { try await fixture.transaction.commit(selection: firstSelection, descriptor: firstDescriptor) }
        await barrier.waitUntilEntered()
        let secondStarted = SelectionTransactionBarrier()
        let second = Task {
            await secondStarted.release()
            return try await secondTransaction.commit(selection: secondSelection, descriptor: secondDescriptor)
        }
        await secondStarted.enterAndWait()
        for _ in 0..<20 { await Task.yield() }

        #expect(await fixture.synchronizer.snapshot().history == [firstSelection])
        #expect(fixture.consent.state.activeProvider == firstDescriptor.id)
        #expect(!fixture.transaction.isPrepared(selection: firstSelection, descriptor: firstDescriptor))

        await barrier.release()
        _ = try await first.value
        _ = try await second.value

        let harness = await fixture.synchronizer.snapshot()
        #expect(harness.history == [firstSelection, secondSelection])
        #expect(harness.current == secondSelection)
        #expect(fixture.settings.settings.defaultSelection == secondSelection)
        #expect(fixture.consent.state.activeProvider == secondDescriptor.id)
        let grant = try #require(fixture.consent.state.activeGrant(for: secondDescriptor.id))
        #expect(grant.boundary == .localNetwork)
        #expect(grant.origin == ProviderEndpointOrigin(url: secondDescriptor.defaultBaseURL!))
        #expect(!fixture.preferences.strictLocalMode)
    }

    @Test @MainActor
    func queuedCommitStartsOnlyAfterFailedCommitFinishesItsRollback() async throws {
        let barrier = SelectionTransactionBarrier()
        let fixture = SelectionTransactionFixture(
            failingHarnessCalls: [1],
            applyBeforeHarnessFailureCalls: [1],
            barriers: [1: barrier]
        )
        let firstDescriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let firstSelection = testSelection("remote-a", "first")
        let secondDescriptor = testDescriptor(id: "remote-b", endpoint: "https://b.example.test/v1", boundary: .cloud)
        let secondSelection = testSelection("remote-b", "second")

        let first = Task { try await fixture.transaction.commit(selection: firstSelection, descriptor: firstDescriptor) }
        await barrier.waitUntilEntered()
        let second = Task { try await fixture.transaction.commit(selection: secondSelection, descriptor: secondDescriptor) }
        for _ in 0..<20 { await Task.yield() }
        #expect(await fixture.synchronizer.snapshot().history == [firstSelection])

        await barrier.release()
        do {
            _ = try await first.value
            Issue.record("Expected the first commit to fail")
        } catch let error as ProviderSelectionTransactionError {
            #expect(error.rollbackComplete)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
        _ = try await second.value

        let harness = await fixture.synchronizer.snapshot()
        #expect(harness.history == [firstSelection, fixture.initialSelection, secondSelection])
        #expect(harness.current == secondSelection)
        #expect(fixture.settings.settings.defaultSelection == secondSelection)
        #expect(fixture.consent.state.activeProvider == secondDescriptor.id)
        #expect(fixture.consent.state.activeGrant(for: secondDescriptor.id)?.origin == ProviderEndpointOrigin(url: secondDescriptor.defaultBaseURL!))
    }

    @Test @MainActor
    func cancellingAQueuedCallerRemovesItWithoutBreakingTheGate() async throws {
        let barrier = SelectionTransactionBarrier()
        let fixture = SelectionTransactionFixture(barriers: [1: barrier])
        let firstDescriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let firstSelection = testSelection("remote-a", "first")
        let cancelledDescriptor = testDescriptor(id: "remote-b", endpoint: "https://b.example.test/v1", boundary: .cloud)
        let cancelledSelection = testSelection("remote-b", "cancelled")
        let finalDescriptor = testDescriptor(id: "remote-c", endpoint: "https://c.example.test/v1", boundary: .cloud)
        let finalSelection = testSelection("remote-c", "final")

        let first = Task { try await fixture.transaction.commit(selection: firstSelection, descriptor: firstDescriptor) }
        await barrier.waitUntilEntered()
        let cancelled = Task {
            try await fixture.transaction.commit(selection: cancelledSelection, descriptor: cancelledDescriptor)
        }
        for _ in 0..<20 { await Task.yield() }
        cancelled.cancel()
        do {
            _ = try await cancelled.value
            Issue.record("Expected the queued commit to honor cancellation")
        } catch is CancellationError {
            // Expected: it never owned the transaction gate.
        } catch {
            Issue.record("Unexpected cancellation error: \(error)")
        }

        await barrier.release()
        _ = try await first.value
        _ = try await fixture.transaction.commit(selection: finalSelection, descriptor: finalDescriptor)

        let harness = await fixture.synchronizer.snapshot()
        #expect(harness.history == [firstSelection, finalSelection])
        #expect(harness.current == finalSelection)
        #expect(fixture.settings.settings.defaultSelection == finalSelection)
        #expect(fixture.consent.state.activeProvider == finalDescriptor.id)
    }

    @Test @MainActor
    func cancellationDuringHarnessMutationStillCompletesRollbackBeforeUnlocking() async {
        let barrier = SelectionTransactionBarrier()
        let fixture = SelectionTransactionFixture(
            applyBeforeHarnessFailureCalls: [1],
            cancellationSensitiveHarnessCalls: [1, 2],
            barriers: [1: barrier]
        )
        let descriptor = testDescriptor(id: "remote-a", endpoint: "https://a.example.test/v1", boundary: .cloud)
        let selection = testSelection("remote-a", "cancelled-active")

        let task = Task {
            try await fixture.transaction.commit(selection: selection, descriptor: descriptor)
        }
        await barrier.waitUntilEntered()
        task.cancel()
        await barrier.release()

        do {
            _ = try await task.value
            Issue.record("Expected the cancelled Harness mutation to roll back")
        } catch let error as ProviderSelectionTransactionError {
            #expect(error.rollbackComplete)
            #expect(error.cause is CancellationError)
        } catch {
            Issue.record("Unexpected cancellation error: \(error)")
        }
        let harness = await fixture.synchronizer.snapshot()
        #expect(harness.history == [selection, fixture.initialSelection])
        #expect(harness.current == fixture.initialSelection)
        #expect(fixture.settings.settings.defaultSelection == fixture.initialSelection)
        #expect(fixture.consent.state == fixture.initialConsent)
        #expect(fixture.preferences.strictLocalMode)
    }
}
