import AppKit
import Foundation
import Testing
@testable import LocalHarness

private enum ProviderCredentialRecordsProbeError: LocalizedError {
    case unused
    case hostile

    var errorDescription: String? {
        switch self {
        case .unused: "Unused test dependency"
        case .hostile: "REMOTE_SECRET_CANARY_\(String(repeating: "X", count: 32_000))\u{001B}[31m"
        }
    }
}

private actor ProviderCredentialRecordsRecoveryProbe: ProviderCredentialRecoveryServicing {
    enum Action: Equatable, Sendable { case authorize, adopt, remove }

    private struct PendingAction {
        let action: Action
        let key: String
        let continuation: CheckedContinuation<Void, Error>
    }

    private var listContinuations: [CheckedContinuation<[ProviderRecordCredentialAttention], Error>] = []
    private var actionContinuations: [PendingAction] = []
    private var recordedActions: [(Action, String)] = []

    func authorizeExisting(_ reference: CredentialReference) async throws { throw ProviderCredentialRecordsProbeError.unused }
    func adoptCurrent(_ reference: CredentialReference) async throws { throw ProviderCredentialRecordsProbeError.unused }
    func replaceCurrent(_ reference: CredentialReference, value: String) async throws { throw ProviderCredentialRecordsProbeError.unused }
    func removeCurrent(_ reference: CredentialReference) async throws { throw ProviderCredentialRecordsProbeError.unused }

    func listRecordAttention() async throws -> [ProviderRecordCredentialAttention] {
        try await withCheckedThrowingContinuation { listContinuations.append($0) }
    }

    func authorizeRecord(_ key: String) async throws { try await perform(.authorize, key: key) }
    func adoptCurrentRecord(_ key: String) async throws { try await perform(.adopt, key: key) }
    func removeCurrentRecord(_ key: String) async throws { try await perform(.remove, key: key) }

    private func perform(_ action: Action, key: String) async throws {
        recordedActions.append((action, key))
        try await withCheckedThrowingContinuation {
            actionContinuations.append(PendingAction(action: action, key: key, continuation: $0))
        }
    }

    func pendingListCount() -> Int { listContinuations.count }
    func pendingActionCount() -> Int { actionContinuations.count }
    func actions() -> [(Action, String)] { recordedActions }

    @discardableResult
    func resolveList(
        at index: Int = 0,
        with result: Result<[ProviderRecordCredentialAttention], Error>
    ) -> Bool {
        guard listContinuations.indices.contains(index) else { return false }
        listContinuations.remove(at: index).resume(with: result)
        return true
    }

    @discardableResult
    func resolveAction(at index: Int = 0, with result: Result<Void, Error>) -> Bool {
        guard actionContinuations.indices.contains(index) else { return false }
        actionContinuations.remove(at: index).continuation.resume(with: result)
        return true
    }
}

private actor ProviderCredentialRecordsModelProbe: HarnessModelRPCServicing {
    private var catalogLoads = 0

    func llmProviders() async throws -> HarnessProviderDirectory {
        catalogLoads += 1
        return HarnessProviderDirectory(providers: [])
    }
    func llmModels() async throws -> HarnessModelCatalog {
        HarnessModelCatalog(groups: [], failures: [])
    }
    func describeSettings() async throws -> HarnessSettingsDescription {
        HarnessSettingsDescription(writable: true, hasDocument: false, namespaces: [])
    }
    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace { throw ProviderCredentialRecordsProbeError.unused }
    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels {
        throw ProviderCredentialRecordsProbeError.unused
    }
    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection { throw ProviderCredentialRecordsProbeError.unused }
    func loadCount() -> Int { catalogLoads }
}

private struct ProviderCredentialRecordsCredentialStub: HarnessProviderCredentialServicing {
    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        HarnessCredentialDescription(credentials: [:])
    }
    func setCredential(_ reference: CredentialReference, value: String) async throws {}
    func unsetCredential(_ reference: CredentialReference) async throws {}
}

private struct ProviderCredentialRecordsActivatorStub: ProviderActivating {
    func activate(descriptor: ProviderDescriptor, credentialValue: String?) async throws -> ProviderActivationResult {
        throw ProviderCredentialRecordsProbeError.unused
    }
}

private struct ProviderCredentialRecordsProfileStub: CustomProviderProfileEditing {
    func save(_ draft: CustomProviderProfileDraft) async throws -> CustomProviderProfileResult {
        throw ProviderCredentialRecordsProbeError.unused
    }
}

@MainActor
private final class ProviderCredentialRecordsInteractionProbe {
    var recordSelection: Int? = 0
    var actionSelection: Int?
    var removalConfirmed = true
    var healthyPresentations = 0
    var recordMenus: [[ProviderCredentialRecordDisplay]] = []
    var actionMenus: [(ProviderCredentialRecordDisplay, [ProviderRecordRecoveryAction])] = []
    var removalConfirmations: [ProviderCredentialRecordDisplay] = []

    var interactions: ProviderCredentialRecordsInteractions {
        ProviderCredentialRecordsInteractions(
            presentHealthy: { [unowned self] in healthyPresentations += 1 },
            chooseRecord: { [unowned self] records in
                recordMenus.append(records)
                return recordSelection
            },
            chooseAction: { [unowned self] record, actions in
                actionMenus.append((record, actions))
                return actionSelection
            },
            confirmRemoval: { [unowned self] record in
                removalConfirmations.append(record)
                return removalConfirmed
            }
        )
    }
}

@MainActor
private struct ProviderCredentialRecordsFixture {
    let suite: String
    let controller: ProviderCenterWindowController
    let model: ProviderCredentialRecordsModelProbe

    init(
        recovery: ProviderCredentialRecordsRecoveryProbe,
        interactions: ProviderCredentialRecordsInteractions,
        label: String
    ) throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        suite = "Fulmar.ProviderCredentialRecordsUI.\(label).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        model = ProviderCredentialRecordsModelProbe()
        controller = ProviderCenterWindowController(
            coordinator: ModelSelectionCoordinator(service: model),
            credentials: ProviderCredentialRecordsCredentialStub(),
            credentialRecovery: recovery,
            settingsStore: ModelProviderSettingsStore(defaults: defaults),
            consentStore: ProviderConsentStore(defaults: defaults),
            providerActivation: ProviderCredentialRecordsActivatorStub(),
            customProfileEditor: ProviderCredentialRecordsProfileStub(),
            preferences: PreferencesStore(defaults: defaults),
            credentialRecordsInteractions: interactions
        )
    }

    func remove() { UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite) }
}

private struct ProviderCredentialRecordsControls {
    let review: NSButton
    let addCustom: NSButton
    let status: NSTextField
    let allViews: [NSView]
}

@MainActor
private func providerCredentialRecordsControls(
    _ controller: ProviderCenterWindowController
) throws -> ProviderCredentialRecordsControls {
    let root = try #require(controller.window?.contentViewController?.view)
    let views = providerCredentialRecordsDescendants(root)
    let buttons = views.compactMap { $0 as? NSButton }
    return ProviderCredentialRecordsControls(
        review: try #require(buttons.first { $0.title == "Credential Records…" }),
        addCustom: try #require(buttons.first { $0.title == "Add Custom…" }),
        status: try #require(views.compactMap { $0 as? NSTextField }.first {
            $0.stringValue == "Loading providers…"
        }),
        allViews: views
    )
}

private func providerCredentialRecordsDescendants(_ root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(providerCredentialRecordsDescendants)
}

private func providerCredentialRecord(
    key: String,
    kind: String,
    reason: ProviderRecordCredentialAttentionReason,
    token: Character = "a"
) -> ProviderRecordCredentialAttention {
    ProviderRecordCredentialAttention(
        key: key,
        kind: kind,
        reason: reason,
        token: String(repeating: String(token), count: 64)
    )
}

@MainActor
private func providerCredentialRecordsWait(
    _ description: String,
    until condition: @escaping @MainActor () async -> Bool
) async {
    for _ in 0..<2_000 {
        if await condition() { return }
        await Task.yield()
    }
    Issue.record("Timed out waiting for \(description)")
}

@MainActor
private func providerCredentialRecordsForceSelector(_ button: NSButton) throws {
    let action = try #require(button.action)
    #expect(NSApp.sendAction(action, to: button.target, from: button))
}

@MainActor
@Test func credentialRecordsEmptyAndHostileListFailureRestoreControlsWithoutLeakingText() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recovery = ProviderCredentialRecordsRecoveryProbe()
    let interactions = ProviderCredentialRecordsInteractionProbe()
    let fixture = try ProviderCredentialRecordsFixture(
        recovery: recovery, interactions: interactions.interactions, label: "List"
    )
    defer { fixture.remove() }
    let controls = try providerCredentialRecordsControls(fixture.controller)

    controls.review.performClick(nil)
    #expect(!controls.review.isEnabled)
    #expect(!controls.addCustom.isEnabled)
    await providerCredentialRecordsWait("empty list request") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([])))
    await providerCredentialRecordsWait("empty list presentation") {
        controls.status.stringValue == "No credential records need attention."
    }
    #expect(interactions.healthyPresentations == 1)
    #expect(controls.review.isEnabled)
    #expect(controls.addCustom.isEnabled)

    controls.review.performClick(nil)
    await providerCredentialRecordsWait("failed list request") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .failure(ProviderCredentialRecordsProbeError.hostile)))
    await providerCredentialRecordsWait("safe failed list status") {
        controls.status.stringValue.contains("could not be checked")
    }
    #expect(controls.review.isEnabled)
    #expect(controls.addCustom.isEnabled)
    #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
    #expect(controls.status.stringValue.count < 200)
}

@MainActor
@Test func credentialRecordReasonMenusExposeOnlyAuthorizedActionsAndNeverRecoveryTokens() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recovery = ProviderCredentialRecordsRecoveryProbe()
    let interactions = ProviderCredentialRecordsInteractionProbe()
    interactions.recordSelection = 0
    interactions.actionSelection = nil
    let fixture = try ProviderCredentialRecordsFixture(
        recovery: recovery, interactions: interactions.interactions, label: "Actions"
    )
    defer { fixture.remove() }
    let controls = try providerCredentialRecordsControls(fixture.controller)
    let cases: [(ProviderRecordCredentialAttentionReason, String, [ProviderRecordRecoveryAction])] = [
        (.authorization, "api-key", [.authorizeExisting]),
        (.ambiguous, "grant", [.adoptCurrent, .remove]),
        (.invalid, "unknown", [.remove])
    ]

    for (offset, value) in cases.enumerated() {
        let token = Character(String(offset + 1))
        controls.review.performClick(nil)
        await providerCredentialRecordsWait("reason list request") { await recovery.pendingListCount() == 1 }
        #expect(await recovery.resolveList(with: .success([
            providerCredentialRecord(key: "record/\(offset)", kind: value.1, reason: value.0, token: token)
        ])))
        await providerCredentialRecordsWait("reason action menu") {
            interactions.actionMenus.count == offset + 1
        }
        #expect(interactions.actionMenus[offset].1 == value.2)
        #expect(interactions.recordMenus[offset].count == 1)
        #expect(controls.review.isEnabled)
        let tokenText = String(repeating: String(token), count: 64)
        let visibleText = controls.allViews.compactMap { ($0 as? NSTextField)?.stringValue }.joined(separator: " ")
        #expect(!visibleText.contains(tokenText))
    }
    #expect(await recovery.actions().isEmpty)
}

@MainActor
@Test func credentialRecordCancelInvalidAndRemovalConfirmationPathsFailClosed() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recovery = ProviderCredentialRecordsRecoveryProbe()
    let interactions = ProviderCredentialRecordsInteractionProbe()
    let fixture = try ProviderCredentialRecordsFixture(
        recovery: recovery, interactions: interactions.interactions, label: "Cancel"
    )
    defer { fixture.remove() }
    let controls = try providerCredentialRecordsControls(fixture.controller)
    let ambiguous = providerCredentialRecord(key: "grant/current", kind: "grant", reason: .ambiguous)

    interactions.recordSelection = nil
    controls.review.performClick(nil)
    await providerCredentialRecordsWait("cancelled record list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([ambiguous])))
    await providerCredentialRecordsWait("first cancellation") {
        controls.status.stringValue.contains("cancelled")
    }
    #expect(interactions.actionMenus.isEmpty)

    interactions.recordSelection = 99
    controls.review.performClick(nil)
    await providerCredentialRecordsWait("invalid record list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([ambiguous])))
    await providerCredentialRecordsWait("invalid record selection") {
        controls.status.stringValue.contains("selection was invalid")
    }
    #expect(interactions.actionMenus.isEmpty)

    interactions.recordSelection = 0
    interactions.actionSelection = nil
    controls.review.performClick(nil)
    await providerCredentialRecordsWait("cancelled action list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([ambiguous])))
    await providerCredentialRecordsWait("second cancellation") {
        controls.status.stringValue.contains("cancelled") && interactions.actionMenus.count == 1
    }

    interactions.actionSelection = 99
    controls.review.performClick(nil)
    await providerCredentialRecordsWait("invalid action list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([ambiguous])))
    await providerCredentialRecordsWait("invalid action selection") {
        controls.status.stringValue.contains("selection was invalid")
    }

    interactions.actionSelection = 0
    interactions.removalConfirmed = false
    let invalid = providerCredentialRecord(key: "broken/item", kind: "unknown", reason: .invalid)
    controls.review.performClick(nil)
    await providerCredentialRecordsWait("remove confirmation list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([invalid])))
    await providerCredentialRecordsWait("remove confirmation cancellation") {
        controls.status.stringValue.contains("cancelled") && interactions.removalConfirmations.count == 1
    }
    #expect(await recovery.actions().isEmpty)
    #expect(controls.review.isEnabled)
    #expect(controls.addCustom.isEnabled)
}

@MainActor
@Test func credentialRecordRepairIsBlockedWithoutProtectedRuntimeQuiescence() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recovery = ProviderCredentialRecordsRecoveryProbe()
    let interactions = ProviderCredentialRecordsInteractionProbe()
    interactions.recordSelection = 0
    interactions.actionSelection = 0
    let fixture = try ProviderCredentialRecordsFixture(
        recovery: recovery, interactions: interactions.interactions, label: "Quiescence"
    )
    defer { fixture.remove() }
    let controls = try providerCredentialRecordsControls(fixture.controller)

    controls.review.performClick(nil)
    await providerCredentialRecordsWait("quiescence list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([
        providerCredentialRecord(key: "provider/account", kind: "api-key", reason: .authorization)
    ])))
    await providerCredentialRecordsWait("quiescence status") {
        controls.status.stringValue.contains("quiescence is unavailable")
    }
    #expect(await recovery.actions().isEmpty)
    #expect(controls.review.isEnabled)
    #expect(controls.addCustom.isEnabled)
}

@MainActor
@Test func credentialRecordSuccessAndHostileFailureBothRefreshAndRestoreControls() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for succeeds in [true, false] {
        let recovery = ProviderCredentialRecordsRecoveryProbe()
        let interactions = ProviderCredentialRecordsInteractionProbe()
        interactions.recordSelection = 0
        interactions.actionSelection = 0
        let fixture = try ProviderCredentialRecordsFixture(
            recovery: recovery,
            interactions: interactions.interactions,
            label: succeeds ? "Success" : "Failure"
        )
        defer { fixture.remove() }
        let controls = try providerCredentialRecordsControls(fixture.controller)
        var prepared = 0
        var finished = 0
        fixture.controller.onPrepareProtectedMutation = { _ in prepared += 1 }
        fixture.controller.onProtectedMutationFinished = { _, _ in finished += 1 }

        controls.review.performClick(nil)
        await providerCredentialRecordsWait("repair list") { await recovery.pendingListCount() == 1 }
        #expect(await recovery.resolveList(with: .success([
            providerCredentialRecord(key: "provider/account", kind: "api-key", reason: .authorization)
        ])))
        await providerCredentialRecordsWait("repair action") { await recovery.pendingActionCount() == 1 }
        #expect(!controls.review.isEnabled)
        #expect(!controls.addCustom.isEnabled)
        #expect(await recovery.actions().map(\.0) == [.authorize])
        let outcome: Result<Void, Error> = succeeds
            ? .success(())
            : .failure(ProviderCredentialRecordsProbeError.hostile)
        #expect(await recovery.resolveAction(with: outcome))
        await providerCredentialRecordsWait("post-repair catalog refresh") { await fixture.model.loadCount() == 1 }
        await providerCredentialRecordsWait("post-repair control restoration") { controls.review.isEnabled }
        #expect(prepared == 1)
        #expect(finished == 1)
        #expect(controls.addCustom.isEnabled)
        #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
        #expect(controls.status.stringValue.count < 200)
        if succeeds {
            #expect(controls.status.stringValue.contains("completed and was freshly verified"))
        } else {
            #expect(controls.status.stringValue.contains("could not be verified"))
        }
    }
}

@MainActor
@Test func credentialRecordStaleListResultCannotPresentOrOverwriteNewerReview() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recovery = ProviderCredentialRecordsRecoveryProbe()
    let interactions = ProviderCredentialRecordsInteractionProbe()
    let fixture = try ProviderCredentialRecordsFixture(
        recovery: recovery, interactions: interactions.interactions, label: "StaleList"
    )
    defer { fixture.remove() }
    let controls = try providerCredentialRecordsControls(fixture.controller)

    controls.review.performClick(nil)
    await providerCredentialRecordsWait("first list") { await recovery.pendingListCount() == 1 }
    try providerCredentialRecordsForceSelector(controls.review)
    await providerCredentialRecordsWait("second list") { await recovery.pendingListCount() == 2 }
    #expect(await recovery.resolveList(at: 1, with: .success([])))
    await providerCredentialRecordsWait("newer empty list") {
        controls.status.stringValue == "No credential records need attention."
    }
    #expect(await recovery.resolveList(with: .success([
        providerCredentialRecord(key: "stale/record", kind: "api-key", reason: .authorization)
    ])))
    for _ in 0..<20 { await Task.yield() }
    #expect(interactions.healthyPresentations == 1)
    #expect(interactions.recordMenus.isEmpty)
    #expect(controls.status.stringValue == "No credential records need attention.")
    #expect(controls.review.isEnabled)
}

@MainActor
@Test func credentialRecordStaleActionResultCannotRefreshOrOverwriteNewerReview() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recovery = ProviderCredentialRecordsRecoveryProbe()
    let interactions = ProviderCredentialRecordsInteractionProbe()
    interactions.recordSelection = 0
    interactions.actionSelection = 0
    let fixture = try ProviderCredentialRecordsFixture(
        recovery: recovery, interactions: interactions.interactions, label: "StaleAction"
    )
    defer { fixture.remove() }
    let controls = try providerCredentialRecordsControls(fixture.controller)
    fixture.controller.onPrepareProtectedMutation = { _ in }
    fixture.controller.onProtectedMutationFinished = { _, _ in }

    controls.review.performClick(nil)
    await providerCredentialRecordsWait("action source list") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([
        providerCredentialRecord(key: "provider/account", kind: "api-key", reason: .authorization)
    ])))
    await providerCredentialRecordsWait("pending stale action") { await recovery.pendingActionCount() == 1 }
    try providerCredentialRecordsForceSelector(controls.review)
    await providerCredentialRecordsWait("newer list after action") { await recovery.pendingListCount() == 1 }
    #expect(await recovery.resolveList(with: .success([])))
    await providerCredentialRecordsWait("newer review presentation") {
        controls.status.stringValue == "No credential records need attention."
    }
    #expect(await recovery.resolveAction(with: .success(())))
    for _ in 0..<50 { await Task.yield() }
    #expect(await fixture.model.loadCount() == 0)
    #expect(controls.status.stringValue == "No credential records need attention.")
    #expect(controls.review.isEnabled)
    #expect(controls.addCustom.isEnabled)
}
