import AppKit
import Foundation
import Testing
@testable import LocalHarness

private final class ScheduleWindowBehaviorExecutor: ScheduleConversationExecuting, @unchecked Sendable {
    @discardableResult
    func execute(
        _ request: ScheduleConversationRequest,
        completion: @escaping ScheduleConversationExecuting.Completion
    ) -> UUID {
        UUID()
    }

    func cancel(_ identifier: UUID) {}
    func cancelAll() {}
}

private struct HostileScheduleWindowError: LocalizedError {
    var errorDescription: String? { "HOSTILE_PROVIDER_CREDENTIAL_CANARY /Users/private/ledger" }
}

@MainActor
private final class ScheduleWindowOperationProbe {
    var schedules: [LocalSchedule]
    var running: Set<UUID> = []
    var backgroundEnabled = false
    var storageIssue = false
    var inboxCount = 0
    var defaultSelection = ModelSelection.defaultLocal
    var effectiveBoundary: DataBoundary = .onDevice
    var effectiveOrigin: ProviderEndpointOrigin?
    var authorization: ScheduleAuthorizationStatus = .authorized
    var throwingActions: Set<String> = []
    var calls: [String: Int] = [:]
    var added: [(NewScheduleSubmission, ModelSelection, Bool)] = []
    var onAction: ((String) -> Void)?

    init(schedules: [LocalSchedule]) {
        self.schedules = schedules
    }

    func count(_ action: String) -> Int { calls[action, default: 0] }

    func operations(basedOn manager: ScheduleManager) -> ScheduleWindowOperations {
        var value = ScheduleWindowOperations(manager: manager)
        value.snapshot = { [self] in schedules }
        value.runningScheduleIDs = { [self] in running }
        value.backgroundServiceEnabled = { [self] in backgroundEnabled }
        value.inboxCount = { [self] in inboxCount }
        value.hasStorageIssue = { [self] in storageIssue }
        value.defaultModelSelection = { [self] in defaultSelection }
        value.boundary = { [self] _ in effectiveBoundary }
        value.origin = { [self] _ in effectiveOrigin }
        value.authorizationStatus = { [self] _ in authorization }
        value.setBackgroundService = { [self] enabled in
            try record("service")
            backgroundEnabled = enabled
        }
        value.add = { [self] submission, selection, allowed in
            try record("add")
            added.append((submission, selection, allowed))
        }
        value.runNow = { [self] id in
            recordWithoutThrowing("run")
            running.insert(id)
        }
        value.cancelRun = { [self] id in
            recordWithoutThrowing("cancel")
            running.remove(id)
        }
        value.toggle = { [self] id in
            try record("toggle")
            if let index = schedules.firstIndex(where: { $0.id == id }) {
                schedules[index].enabled.toggle()
            }
        }
        value.authorizeAndEnable = { [self] id in
            try record("authorize")
            authorization = .authorized
            if let index = schedules.firstIndex(where: { $0.id == id }) {
                schedules[index].enabled = true
            }
        }
        value.revokeUnattendedConsent = { [self] id in
            try record("revoke")
            if let index = schedules.firstIndex(where: { $0.id == id }) {
                schedules[index].enabled = false
                schedules[index].unattendedConsent = nil
            }
        }
        value.remove = { [self] id in
            try record("remove")
            schedules.removeAll { $0.id == id }
            running.remove(id)
        }
        return value
    }

    private func record(_ action: String) throws {
        calls[action, default: 0] += 1
        onAction?(action)
        if throwingActions.contains(action) { throw HostileScheduleWindowError() }
    }

    private func recordWithoutThrowing(_ action: String) {
        calls[action, default: 0] += 1
        onAction?(action)
    }
}

@MainActor
private final class ScheduleWindowInteractionProbe {
    var submissions: [NewScheduleSubmission?] = []
    var externalConfirmations: [Bool] = []
    var revokeConfirmations: [Bool] = []
    var deleteConfirmations: [Bool] = []
    private(set) var externalRequests: [(ModelSelection, DataBoundary, Int, ProviderEndpointOrigin)] = []
    private(set) var providerInactiveNotices: [(LocalSchedule, ProviderID?)] = []
    private(set) var routeInactiveNotices: [(LocalSchedule, ModelRoute?)] = []
    private(set) var endpointUnavailableNoticeCount = 0
    private(set) var failures: [ScheduleWindowFailure] = []

    var interactions: ScheduleWindowInteractions {
        ScheduleWindowInteractions(
            presentNewSchedule: { [self] _ in
                submissions.isEmpty ? nil : submissions.removeFirst()
            },
            confirmExternalAccess: { [self] selection, boundary, bytes, origin in
                externalRequests.append((selection, boundary, bytes, origin))
                return externalConfirmations.isEmpty ? false : externalConfirmations.removeFirst()
            },
            confirmRevokeAccess: { [self] _ in
                revokeConfirmations.isEmpty ? false : revokeConfirmations.removeFirst()
            },
            confirmDeleteSchedule: { [self] _ in
                deleteConfirmations.isEmpty ? false : deleteConfirmations.removeFirst()
            },
            showProviderInactive: { [self] schedule, active in
                providerInactiveNotices.append((schedule, active))
            },
            showRouteInactive: { [self] schedule, active in
                routeInactiveNotices.append((schedule, active))
            },
            showEndpointUnavailable: { [self] in endpointUnavailableNoticeCount += 1 },
            showFailure: { [self] in failures.append($0) }
        )
    }
}

@MainActor
private final class TaskInboxInteractionProbe {
    var deleteConfirmations: [Bool] = []
    var clearConfirmations: [Bool] = []
    private(set) var deletePrompts: [UUID] = []
    private(set) var clearPromptCounts: [Int] = []
    private(set) var failures: [ScheduleWindowFailure] = []

    var interactions: TaskInboxInteractions {
        TaskInboxInteractions(
            confirmDelete: { [self] result in
                deletePrompts.append(result.id)
                return deleteConfirmations.isEmpty ? false : deleteConfirmations.removeFirst()
            },
            confirmClear: { [self] count in
                clearPromptCounts.append(count)
                return clearConfirmations.isEmpty ? false : clearConfirmations.removeFirst()
            },
            showFailure: { [self] in failures.append($0) }
        )
    }
}

private actor TaskInboxLoadScript {
    private var continuations: [CheckedContinuation<ScheduleInboxLoadOutcome, Never>?] = []

    func load() async -> ScheduleInboxLoadOutcome {
        await withCheckedContinuation { continuation in
            continuations.append(continuation)
        }
    }

    func requestCount() -> Int { continuations.count }

    func resume(_ index: Int, with outcome: ScheduleInboxLoadOutcome) {
        guard continuations.indices.contains(index), let continuation = continuations[index] else { return }
        continuations[index] = nil
        continuation.resume(returning: outcome)
    }
}

private enum ScheduleWindowBehaviorTimeout: Error { case timedOut }

@MainActor
private func scheduleWindowEventually(
    attempts: Int = 300,
    _ condition: @escaping @MainActor () async -> Bool
) async throws {
    for _ in 0..<attempts {
        if await condition() { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    throw ScheduleWindowBehaviorTimeout.timedOut
}

@MainActor
private func scheduleWindowDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(scheduleWindowDescendants(of:))
}

@MainActor
private func scheduleWindowButton(_ title: String, in root: NSView) throws -> NSButton {
    try #require(scheduleWindowDescendants(of: root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func scheduleWindowTable(in root: NSView) throws -> NSTableView {
    try #require(scheduleWindowDescendants(of: root).compactMap { $0 as? NSTableView }.first)
}

@MainActor
private func scheduleStatus(in root: NSView) throws -> NSTextField {
    try #require(scheduleWindowDescendants(of: root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == "Schedule status"
    })
}

@MainActor
private func taskInboxDetail(in root: NSView) throws -> NSTextView {
    try #require(scheduleWindowDescendants(of: root).compactMap { $0 as? NSTextView }.first {
        $0.accessibilityLabel() == "Selected scheduled task result"
    })
}

@MainActor
private func invokeIgnoringEnabled(_ button: NSButton) throws {
    let action = try #require(button.action)
    #expect(NSApplication.shared.sendAction(action, to: button.target, from: button))
}

private func localSchedule(
    id: UUID = UUID(),
    title: String = "Local scheduled task",
    enabled: Bool = true
) throws -> LocalSchedule {
    try LocalSchedule(
        id: id,
        title: title,
        prompt: "Create a bounded private summary.",
        selection: .defaultLocal,
        boundary: .onDevice,
        intervalSeconds: 3_600,
        nextRun: Date(timeIntervalSince1970: 1_900_000_000),
        enabled: enabled
    )
}

private func externalSchedule(
    id: UUID = UUID(),
    enabled: Bool = true,
    includeConsent: Bool = true
) throws -> (LocalSchedule, ProviderEndpointOrigin) {
    let selection = ModelSelection(
        route: ModelRoute(provider: ProviderID("deepseek"), model: ModelID("deepseek-chat")),
        performanceProfile: .balanced
    )
    let origin = try #require(ProviderEndpointOrigin(url: URL(string: "https://api.deepseek.com/v1")!))
    let consent = includeConsent
        ? try ScheduleUnattendedConsent(selection: selection, boundary: .cloud, origin: origin)
        : nil
    return (
        try LocalSchedule(
            id: id,
            title: "Connected scheduled task",
            prompt: "Prepare an external summary.",
            selection: selection,
            boundary: .cloud,
            unattendedConsent: consent,
            intervalSeconds: 3_600,
            nextRun: Date(timeIntervalSince1970: 1_900_000_000),
            enabled: enabled
        ),
        origin
    )
}

private func scheduledResult(
    id: UUID = UUID(),
    title: String,
    response: String = "Saved result"
) -> ScheduledResult {
    ScheduledResult(
        id: id,
        scheduleID: UUID(),
        title: title,
        completedAt: Date(timeIntervalSince1970: 1_900_000_000),
        selection: .defaultLocal,
        boundary: .onDevice,
        sessionID: HarnessSessionID("scheduled-result-session"),
        response: response,
        failure: nil,
        truncated: false
    )
}

@MainActor
private func scheduleManagerFixture() throws -> (ScheduleManager, PreferencesStore, () -> Void) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarScheduleWindowBehavior-\(UUID().uuidString)", isDirectory: true)
    let suite = "FulmarScheduleWindowBehavior.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: ScheduleWindowBehaviorExecutor(),
        activities: ActivityStore(applicationSupport: root)
    )
    return (
        manager,
        PreferencesStore(defaults: defaults),
        {
            try? FileManager.default.removeItem(at: root)
            defaults.removePersistentDomain(forName: suite)
        }
    )
}

@MainActor
private func makeScheduleController(
    probe: ScheduleWindowOperationProbe,
    interactions: ScheduleWindowInteractionProbe
) throws -> (ScheduleWindowController, () -> Void) {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let (manager, preferences, cleanup) = try scheduleManagerFixture()
    let controller = ScheduleWindowController(
        manager: manager,
        preferences: preferences,
        operations: probe.operations(basedOn: manager),
        interactions: interactions.interactions
    )
    controller.refresh()
    return (controller, cleanup)
}

@Suite(.serialized)
struct ScheduleWindowBehaviorTests {
    @Test @MainActor func newScheduleCancelAndValidationNeverReachStorage() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = ScheduleWindowOperationProbe(schedules: [])
        let interactions = ScheduleWindowInteractionProbe()
        interactions.submissions = [nil, NewScheduleSubmission(
            title: "\n",
            prompt: "prompt",
            providerID: "ollama",
            modelID: "qwen",
            performanceProfile: .balanced,
            timeoutSeconds: 600,
            firstRun: Date(),
            intervalSeconds: 3_600
        )]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let add = try scheduleWindowButton("New Schedule…", in: root)

        add.performClick(nil)
        add.performClick(nil)

        #expect(probe.count("add") == 0)
        #expect(interactions.failures == [.invalidNewSchedule])
        #expect(!ScheduleWindowFailure.invalidNewSchedule.message.contains("SECRET"))
    }

    @Test @MainActor func newLocalSchedulePreservesRouteSemanticsAndRestoresAfterStoreFailure() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = ScheduleWindowOperationProbe(schedules: [])
        let interactions = ScheduleWindowInteractionProbe()
        let firstRun = Date(timeIntervalSince1970: 1_900_000_100)
        let submission = NewScheduleSubmission(
            title: "Private summary",
            prompt: "Summarize this workspace.",
            providerID: ModelSelection.defaultLocal.route.provider.rawValue,
            modelID: ModelSelection.defaultLocal.route.model.rawValue,
            performanceProfile: .deep,
            timeoutSeconds: 1_200,
            firstRun: firstRun,
            intervalSeconds: 86_400
        )
        interactions.submissions = [submission, submission]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let add = try scheduleWindowButton("New Schedule…", in: root)

        add.performClick(nil)
        #expect(probe.count("add") == 1)
        #expect(probe.added.first?.0 == submission)
        #expect(probe.added.first?.1.route == ModelSelection.defaultLocal.route)
        #expect(probe.added.first?.1.performanceProfile == .deep)
        #expect(probe.added.first?.2 == false)

        probe.throwingActions.insert("add")
        add.performClick(nil)
        #expect(probe.count("add") == 2)
        #expect(interactions.failures == [.addSchedule])
        #expect(add.isEnabled)
        #expect(!ScheduleWindowFailure.addSchedule.message.contains("HOSTILE_PROVIDER_CREDENTIAL_CANARY"))
    }

    @Test @MainActor func connectedNewScheduleRequiresExactOriginConsent() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = ScheduleWindowOperationProbe(schedules: [])
        probe.effectiveBoundary = .cloud
        let origin = try #require(ProviderEndpointOrigin(url: URL(string: "https://api.deepseek.com")!))
        probe.effectiveOrigin = origin
        let interactions = ScheduleWindowInteractionProbe()
        let submission = NewScheduleSubmission(
            title: "Connected summary",
            prompt: "Send this only after consent.",
            providerID: "deepseek",
            modelID: "deepseek-chat",
            performanceProfile: .balanced,
            timeoutSeconds: 600,
            firstRun: Date(),
            intervalSeconds: 3_600
        )
        interactions.submissions = [submission, submission]
        interactions.externalConfirmations = [false, true]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let add = try scheduleWindowButton("New Schedule…", in: root)

        add.performClick(nil)
        #expect(probe.count("add") == 0)
        add.performClick(nil)
        #expect(probe.count("add") == 1)
        #expect(probe.added.first?.2 == true)
        #expect(interactions.externalRequests.count == 2)
        #expect(interactions.externalRequests.last?.3 == origin)
        #expect(interactions.externalRequests.last?.2 == submission.prompt.utf8.count)
    }

    @Test @MainActor func connectedScheduleWithoutVerifiedOriginFailsClosed() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = ScheduleWindowOperationProbe(schedules: [])
        probe.effectiveBoundary = .cloud
        probe.effectiveOrigin = nil
        let interactions = ScheduleWindowInteractionProbe()
        interactions.submissions = [NewScheduleSubmission(
            title: "Connected summary",
            prompt: "Prompt",
            providerID: "deepseek",
            modelID: "deepseek-chat",
            performanceProfile: .balanced,
            timeoutSeconds: 600,
            firstRun: Date(),
            intervalSeconds: 3_600
        )]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)

        try scheduleWindowButton("New Schedule…", in: root).performClick(nil)

        #expect(probe.count("add") == 0)
        #expect(interactions.endpointUnavailableNoticeCount == 1)
        #expect(interactions.externalRequests.isEmpty)
    }

    @Test @MainActor func runNowHonorsAuthorizationAndAllRouteBlockers() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let schedule = try localSchedule(enabled: true)
        let probe = ScheduleWindowOperationProbe(schedules: [schedule])
        let interactions = ScheduleWindowInteractionProbe()
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let run = try scheduleWindowButton("Run Now", in: root)
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)

        probe.authorization = .providerInactive(active: ProviderID("other"))
        run.performClick(nil)
        probe.authorization = .routeInactive(active: ModelSelection.defaultLocal.route)
        run.performClick(nil)
        probe.authorization = .endpointUnavailable
        run.performClick(nil)
        #expect(probe.count("run") == 0)
        #expect(interactions.providerInactiveNotices.count == 1)
        #expect(interactions.routeInactiveNotices.count == 1)
        #expect(interactions.endpointUnavailableNoticeCount == 1)

        probe.authorization = .authorized
        run.performClick(nil)
        #expect(probe.count("run") == 1)
        #expect(try scheduleWindowButton("Cancel Run", in: root).isEnabled)
        try invokeIgnoringEnabled(run)
        #expect(probe.count("run") == 1)
    }

    @Test @MainActor func runNowConsentCancellationAuthorizationFailureAndSuccessAreAtomic() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let (schedule, origin) = try externalSchedule(enabled: false, includeConsent: false)
        let probe = ScheduleWindowOperationProbe(schedules: [schedule])
        probe.authorization = .consentRequired(.cloud)
        probe.effectiveOrigin = origin
        let interactions = ScheduleWindowInteractionProbe()
        interactions.externalConfirmations = [false, true, true]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let run = try scheduleWindowButton("Run Now", in: root)
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)

        run.performClick(nil)
        #expect(probe.count("authorize") == 0)
        #expect(probe.count("run") == 0)

        probe.throwingActions.insert("authorize")
        run.performClick(nil)
        #expect(probe.count("authorize") == 1)
        #expect(probe.count("run") == 0)
        #expect(interactions.failures == [.authorizeSchedule])
        #expect(run.isEnabled)

        probe.throwingActions.remove("authorize")
        run.performClick(nil)
        #expect(probe.count("authorize") == 2)
        #expect(probe.count("run") == 1)
    }

    @Test @MainActor func changedBoundaryRequiresFreshExactConsentBeforeRun() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let (schedule, origin) = try externalSchedule(enabled: false, includeConsent: false)
        let probe = ScheduleWindowOperationProbe(schedules: [schedule])
        probe.authorization = .boundaryChanged(stored: .localNetwork, effective: .cloud)
        probe.effectiveOrigin = origin
        let interactions = ScheduleWindowInteractionProbe()
        interactions.externalConfirmations = [false, true]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let run = try scheduleWindowButton("Run Now", in: root)
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)

        run.performClick(nil)
        #expect(probe.count("authorize") == 0)
        #expect(probe.count("run") == 0)
        run.performClick(nil)
        #expect(probe.count("authorize") == 1)
        #expect(probe.count("run") == 1)
        #expect(interactions.externalRequests.map(\.1) == [.cloud, .cloud])
        #expect(interactions.externalRequests.allSatisfy { $0.3 == origin })
    }

    @Test @MainActor func cancelToggleAndServiceActionsRestoreControlsAndRejectReentry() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let schedule = try localSchedule(enabled: true)
        let probe = ScheduleWindowOperationProbe(schedules: [schedule])
        let interactions = ScheduleWindowInteractionProbe()
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        let toggle = try scheduleWindowButton("Enable / Disable", in: root)
        let cancel = try scheduleWindowButton("Cancel Run", in: root)
        let service = try scheduleWindowButton("Run due tasks even when the main window is closed", in: root)

        probe.throwingActions.insert("toggle")
        probe.onAction = { action in
            if action == "toggle" { try? invokeIgnoringEnabled(toggle) }
        }
        toggle.performClick(nil)
        #expect(probe.count("toggle") == 1)
        #expect(interactions.failures == [.toggleSchedule])
        #expect(toggle.isEnabled)
        probe.throwingActions.remove("toggle")
        probe.onAction = nil
        toggle.performClick(nil)
        #expect(probe.count("toggle") == 2)
        #expect(probe.schedules.first?.enabled == false)
        #expect(toggle.isEnabled)

        try invokeIgnoringEnabled(cancel)
        #expect(probe.count("cancel") == 0)
        probe.running.insert(schedule.id)
        controller.refresh()
        cancel.performClick(nil)
        #expect(probe.count("cancel") == 1)
        #expect(try scheduleWindowButton("Run Now", in: root).isEnabled)

        probe.throwingActions.insert("service")
        service.state = .on
        service.performClick(nil)
        #expect(probe.count("service") == 1)
        #expect(interactions.failures == [.toggleSchedule, .backgroundService])
        #expect(service.state == .off)
        #expect(service.isEnabled)
        probe.throwingActions.remove("service")
        service.state = .on
        try invokeIgnoringEnabled(service)
        #expect(probe.count("service") == 2)
        #expect(probe.backgroundEnabled)
        #expect(service.state == .on)
    }

    @Test @MainActor func revokeAndDeleteHonorConfirmationAndPreserveStateOnFailure() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let (schedule, _) = try externalSchedule()
        let probe = ScheduleWindowOperationProbe(schedules: [schedule])
        let interactions = ScheduleWindowInteractionProbe()
        interactions.revokeConfirmations = [false, true, true]
        interactions.deleteConfirmations = [false, true, true]
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        let revoke = try scheduleWindowButton("Revoke External Access", in: root)
        let remove = try scheduleWindowButton("Delete", in: root)

        revoke.performClick(nil)
        #expect(probe.count("revoke") == 0)
        probe.throwingActions.insert("revoke")
        revoke.performClick(nil)
        #expect(probe.count("revoke") == 1)
        #expect(interactions.failures == [.revokeAccess])
        #expect(revoke.isEnabled)
        probe.throwingActions.remove("revoke")
        revoke.performClick(nil)
        #expect(probe.count("revoke") == 2)
        #expect(probe.schedules.first?.unattendedConsent == nil)
        #expect(!revoke.isEnabled)

        remove.performClick(nil)
        #expect(probe.count("remove") == 0)
        probe.throwingActions.insert("remove")
        remove.performClick(nil)
        #expect(probe.count("remove") == 1)
        #expect(interactions.failures == [.revokeAccess, .deleteSchedule])
        #expect(remove.isEnabled)
        probe.throwingActions.remove("remove")
        remove.performClick(nil)
        #expect(probe.count("remove") == 2)
        #expect(table.numberOfRows == 0)
    }

    @Test @MainActor func scheduleListFailureUsesFixedAppOwnedStatusAndSafeControls() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = ScheduleWindowOperationProbe(schedules: [])
        probe.storageIssue = true
        probe.inboxCount = 7
        let interactions = ScheduleWindowInteractionProbe()
        let (controller, cleanup) = try makeScheduleController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let status = try scheduleStatus(in: root)

        #expect(status.stringValue == "Private schedule storage needs attention. Existing data was preserved.")
        #expect(!status.stringValue.contains("SECRET"))
        for title in ["Run Now", "Cancel Run", "Enable / Disable", "Revoke External Access", "Delete"] {
            #expect(try !scheduleWindowButton(title, in: root).isEnabled)
        }
    }

    @Test @MainActor func taskInboxLoadSelectionAndRefreshDriveRealControls() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let first = scheduledResult(title: "First result", response: "First body")
        let second = scheduledResult(title: "Second result", response: "Second body")
        let (manager, _, cleanup) = try scheduleManagerFixture()
        var loadCount = 0
        var operations = TaskInboxOperations(manager: manager)
        operations.load = {
            loadCount += 1
            return .loaded(loadCount == 1 ? [first, second] : [second, first])
        }
        let interactions = TaskInboxInteractionProbe()
        let controller = TaskInboxWindowController(operations: operations, interactions: interactions.interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let detail = try taskInboxDetail(in: root)
        let refresh = try scheduleWindowButton("Refresh", in: root)

        try await scheduleWindowEventually { table.numberOfRows == 2 && detail.string.contains("First body") }
        #expect(try scheduleWindowButton("Delete Result", in: root).isEnabled)
        #expect(try scheduleWindowButton("Clear Inbox…", in: root).isEnabled)
        table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
        #expect(detail.string.contains("Second body"))
        refresh.performClick(nil)
        try await scheduleWindowEventually { loadCount == 2 && detail.string.contains("Second body") }
        #expect(!detail.string.contains("First body"))
        #expect(table.selectedRow == 0)
    }

    @Test @MainActor func taskInboxLoadFailureDiscardsHostileProviderText() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let (manager, _, cleanup) = try scheduleManagerFixture()
        var operations = TaskInboxOperations(manager: manager)
        operations.load = { .unavailable("HOSTILE_INBOX_FAILURE_CANARY /Users/private") }
        let controller = TaskInboxWindowController(
            operations: operations,
            interactions: TaskInboxInteractionProbe().interactions
        )
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let detail = try taskInboxDetail(in: root)

        try await scheduleWindowEventually { detail.string.contains("Task Inbox is unavailable") }
        #expect(!detail.string.contains("HOSTILE_INBOX_FAILURE_CANARY"))
        #expect(try !scheduleWindowButton("Delete Result", in: root).isEnabled)
        #expect(try !scheduleWindowButton("Clear Inbox…", in: root).isEnabled)
        #expect(try scheduleWindowButton("Refresh", in: root).isEnabled)
    }

    @Test @MainActor func taskInboxDeleteCancelFailureAndSuccessPreserveCorrectResult() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let first = scheduledResult(title: "First")
        let second = scheduledResult(title: "Second")
        let (manager, _, cleanup) = try scheduleManagerFixture()
        var deleted: [UUID] = []
        var shouldThrow = true
        var reenterDelete: (() -> Void)?
        var operations = TaskInboxOperations(manager: manager)
        operations.load = { .loaded([first, second]) }
        operations.delete = { id in
            deleted.append(id)
            reenterDelete?()
            if shouldThrow { throw HostileScheduleWindowError() }
        }
        let interactions = TaskInboxInteractionProbe()
        interactions.deleteConfirmations = [false, true, true]
        let controller = TaskInboxWindowController(operations: operations, interactions: interactions.interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let delete = try scheduleWindowButton("Delete Result", in: root)
        reenterDelete = { try? invokeIgnoringEnabled(delete) }
        try await scheduleWindowEventually { table.numberOfRows == 2 && delete.isEnabled }

        delete.performClick(nil)
        #expect(deleted.isEmpty)
        delete.performClick(nil)
        #expect(deleted == [first.id])
        #expect(interactions.failures == [.deleteInboxResult])
        #expect(table.numberOfRows == 2)
        #expect(delete.isEnabled)

        shouldThrow = false
        delete.performClick(nil)
        #expect(deleted == [first.id, first.id])
        #expect(table.numberOfRows == 1)
        #expect(try taskInboxDetail(in: root).string.contains("Second"))
        #expect(!ScheduleWindowFailure.deleteInboxResult.message.contains("SECRET"))
    }

    @Test @MainActor func taskInboxClearCancelFailureAndSuccessRestoreControls() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let result = scheduledResult(title: "Only result")
        let (manager, _, cleanup) = try scheduleManagerFixture()
        var clearCount = 0
        var shouldThrow = true
        var operations = TaskInboxOperations(manager: manager)
        operations.load = { .loaded([result]) }
        operations.clear = {
            clearCount += 1
            if shouldThrow { throw HostileScheduleWindowError() }
        }
        let interactions = TaskInboxInteractionProbe()
        interactions.clearConfirmations = [false, true, true]
        let controller = TaskInboxWindowController(operations: operations, interactions: interactions.interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let clear = try scheduleWindowButton("Clear Inbox…", in: root)
        try await scheduleWindowEventually { table.numberOfRows == 1 && clear.isEnabled }

        clear.performClick(nil)
        #expect(clearCount == 0)
        clear.performClick(nil)
        #expect(clearCount == 1)
        #expect(interactions.failures == [.clearInbox])
        #expect(table.numberOfRows == 1)
        #expect(clear.isEnabled)

        shouldThrow = false
        clear.performClick(nil)
        #expect(clearCount == 2)
        #expect(table.numberOfRows == 0)
        #expect(!clear.isEnabled)
        #expect(try taskInboxDetail(in: root).string == "No scheduled results.")
    }

    @Test @MainActor func taskInboxRejectsLateResultFromCancelledReload() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let stale = scheduledResult(title: "Stale result", response: "STALE BODY")
        let current = scheduledResult(title: "Current result", response: "CURRENT BODY")
        let script = TaskInboxLoadScript()
        let (manager, _, cleanup) = try scheduleManagerFixture()
        var operations = TaskInboxOperations(manager: manager)
        operations.load = { await script.load() }
        let controller = TaskInboxWindowController(
            operations: operations,
            interactions: TaskInboxInteractionProbe().interactions
        )
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try scheduleWindowTable(in: root)
        let detail = try taskInboxDetail(in: root)
        let refresh = try scheduleWindowButton("Refresh", in: root)
        try await scheduleWindowEventually { await script.requestCount() == 1 }

        refresh.performClick(nil)
        try await scheduleWindowEventually { await script.requestCount() == 2 }
        await script.resume(1, with: .loaded([current]))
        try await scheduleWindowEventually { table.numberOfRows == 1 && detail.string.contains("CURRENT BODY") }
        await script.resume(0, with: .loaded([stale]))
        try await Task.sleep(nanoseconds: 30_000_000)

        #expect(detail.string.contains("CURRENT BODY"))
        #expect(!detail.string.contains("STALE BODY"))
        #expect(table.numberOfRows == 1)
    }

    @Test @MainActor func scheduleWindowControlsFitItsDeclaredMinimumAndRemainInteractiveAcrossAppearances() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let (schedule, _) = try externalSchedule()
        let probe = ScheduleWindowOperationProbe(schedules: [schedule])
        let interactions = ScheduleWindowInteractionProbe()
        let (controller, cleanup) = try makeScheduleController(
            probe: probe,
            interactions: interactions
        )
        defer { controller.close(); cleanup() }
        let window = try #require(controller.window)
        let content = try #require(window.contentViewController?.view)
        let table = try scheduleWindowTable(in: content)
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        controller.tableViewSelectionDidChange(
            Notification(name: NSTableView.selectionDidChangeNotification)
        )
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)

        let actionTitles = [
            "Run due tasks even when the main window is closed",
            "New Schedule…",
            "Open Task Inbox",
            "Run Now",
            "Cancel Run",
            "Enable / Disable",
            "Revoke External Access",
            "Delete"
        ]
        let tableScroll = try #require(
            scheduleWindowDescendants(of: content)
                .compactMap { $0 as? NSScrollView }
                .first { $0.documentView === table }
        )
        #expect(tableScroll.hasHorizontalScroller)
        #expect(table.tableColumns.map(\.title) == [
            "State", "Schedule", "Next Run", "Provider / Model", "Data Boundary"
        ])
        func isScrollableTableContent(_ view: NSView) -> Bool {
            var ancestor = view.superview
            while let current = ancestor {
                if current === table { return true }
                ancestor = current.superview
            }
            return false
        }

        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearance)
            window.layoutIfNeeded()
            content.layoutSubtreeIfNeeded()
            #expect(!content.hasAmbiguousLayout)

            for view in scheduleWindowDescendants(of: content)
                where view is NSButton || view is NSTextField || view is NSStackView {
                #expect(!view.hasAmbiguousLayout)
                guard !view.isHidden, !isScrollableTableContent(view) else { continue }
                let rect = view.convert(view.bounds, to: content)
                #expect(content.bounds.insetBy(dx: -0.5, dy: -0.5).contains(rect))
            }

            for title in actionTitles {
                let button = try scheduleWindowButton(title, in: content)
                #expect(button.target != nil)
                #expect(button.action != nil)
                let rect = button.convert(button.bounds, to: content)
                #expect(content.bounds.insetBy(dx: -0.5, dy: -0.5).contains(rect))
            }

            let status = try scheduleStatus(in: content)
            #expect(status.accessibilityLabel() == "Schedule status")
            #expect(table.accessibilityLabel() == "Scheduled tasks and provider boundaries")
        }
    }

    @Test @MainActor func taskInboxActionsFitItsMinimumWindowInLightAndDarkAppearances() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let result = scheduledResult(title: "Layout result")
        let (manager, _, cleanup) = try scheduleManagerFixture()
        var operations = TaskInboxOperations(manager: manager)
        operations.load = { .loaded([result]) }
        let controller = TaskInboxWindowController(
            operations: operations,
            interactions: TaskInboxInteractionProbe().interactions
        )
        defer { controller.close(); cleanup() }
        let window = try #require(controller.window)
        let content = try #require(window.contentView)
        let table = try scheduleWindowTable(in: content)
        try await scheduleWindowEventually { table.numberOfRows == 1 }
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)

        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearance)
            window.layoutIfNeeded()
            content.layoutSubtreeIfNeeded()
            for title in ["Refresh", "Delete Result", "Clear Inbox…"] {
                let button = try scheduleWindowButton(title, in: content)
                let rect = button.convert(button.bounds, to: content)
                #expect(content.bounds.insetBy(dx: -0.5, dy: -0.5).contains(rect))
                #expect(button.target != nil)
                #expect(button.action != nil)
            }
        }
    }
}
