import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct AuxiliaryHostileError: LocalizedError, Sendable {
    var errorDescription: String? {
        let credential = ["s", "k-private-diagnostics-secret"].joined()
        return "AUXILIARY_PRIVATE_CANARY \(credential) /Users/private/Fulmar/state.json\n\u{001B}[31m"
    }
}

private final class AuxiliaryPreparationProbe: @unchecked Sendable {
    enum Result {
        case success
        case failure
    }

    private let lock = NSLock()
    private let releaseGate = DispatchSemaphore(value: 0)
    private let finishGate = DispatchSemaphore(value: 0)
    private let result: Result
    private var callCountStorage = 0
    private var startedStorage = false
    private var ranOnMainStorage = false
    private var finishedStorage = false

    init(result: Result) { self.result = result }

    var callCount: Int { locked { callCountStorage } }
    var started: Bool { locked { startedStorage } }
    var ranOnMain: Bool { locked { ranOnMainStorage } }
    var finished: Bool { locked { finishedStorage } }

    func prepare(_ directory: URL) throws -> URL {
        defer {
            locked { finishedStorage = true }
            finishGate.signal()
        }
        locked {
            callCountStorage += 1
            startedStorage = true
            ranOnMainStorage = Thread.isMainThread
        }
        releaseGate.wait()
        switch result {
        case .success:
            return directory
        case .failure:
            throw AuxiliaryHostileError()
        }
    }

    func release() { releaseGate.signal() }

    func waitUntilFinished(timeout: DispatchTime = .now() + 1) -> Bool {
        finishGate.wait(timeout: timeout) == .success
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

@MainActor
private final class AuxiliaryDiagnosticsInteractionProbe {
    var copied: [String] = []
    var opened: [URL] = []
    var notices: [(title: String, message: String)] = []
    var acceptsCopy = true
    var acceptsOpen = true
    var onCopy: (() -> Void)?

    var interactions: DiagnosticsInteractions {
        DiagnosticsInteractions(
            copyText: { [unowned self] value in
                copied.append(value)
                onCopy?()
                return acceptsCopy
            },
            openDirectory: { [unowned self] directory in
                opened.append(directory)
                return acceptsOpen
            },
            presentNotice: { [unowned self] title, message in
                notices.append((title, message))
            }
        )
    }
}

@MainActor
private final class AuxiliaryCommandTarget: NSObject {
    private(set) var calls = 0

    @objc func openFeature(_ sender: Any?) { calls += 1 }
}

private final class AuxiliaryClearProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var callCountStorage = 0
    private var ranOnMainStorage = false

    var callCount: Int { locked { callCountStorage } }
    var ranOnMain: Bool { locked { ranOnMainStorage } }

    func clear(_ directory: URL) {
        locked {
            callCountStorage += 1
            ranOnMainStorage = Thread.isMainThread
        }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

@MainActor
private func auxiliaryDescendants(_ root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(auxiliaryDescendants)
}

@MainActor
private func auxiliaryRoot(_ controller: NSWindowController) throws -> NSView {
    return try #require(controller.window?.contentViewController?.view ?? controller.window?.contentView)
}

@MainActor
private func auxiliaryButton(_ title: String, in root: NSView) throws -> NSButton {
    try #require(auxiliaryDescendants(root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func auxiliaryButton(label: String, in root: NSView) throws -> NSButton {
    try #require(auxiliaryDescendants(root).compactMap { $0 as? NSButton }.first {
        $0.accessibilityLabel() == label
    })
}

@MainActor
private func auxiliaryWait(
    _ description: String,
    attempts: Int = 240,
    condition: @escaping @MainActor () -> Bool
) async throws {
    for _ in 0..<attempts {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(5))
    }
    Issue.record("Timed out waiting for \(description)")
}

private func auxiliaryPrivateDirectory(_ label: String) throws -> URL {
    try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarAuxiliary-\(label)")
}

private func auxiliarySnapshot(
    reason: String = "Enough headroom for a balanced local task.",
    model: String = "qwen3.8:27b-hermes"
) -> PerformanceCenterSnapshot {
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let host = HostPerformanceSnapshot(
        capturedAt: now,
        physicalMemoryBytes: 48 * 1_073_741_824,
        thermalCondition: .nominal,
        lowPowerModeEnabled: false,
        processorArchitecture: .appleSilicon,
        logicalProcessorCount: 14,
        activeProcessorCount: 14
    )
    let ollama = OllamaRuntimeSnapshot(
        capturedAt: now,
        availability: .online,
        executablePath: nil,
        installedModels: [OllamaInstalledModelSnapshot(name: model, sizeBytes: 18_000_000_000)],
        runningModels: [OllamaRunningModelSnapshot(
            name: model,
            sizeBytes: 18_000_000_000,
            sizeVRAMBytes: 17_000_000_000,
            contextLength: 49_152
        )],
        issue: nil
    )
    let recommendation = AdaptivePerformanceRecommendation(
        recommendedProfile: .balanced,
        reasons: [reason],
        assessments: [PerformanceProfileAssessment(
            profile: .balanced,
            settings: PerformanceProfile.balanced.settingsFor48GBAppleSilicon,
            summary: reason,
            isRecommended: true
        )]
    )
    let telemetry = [GenerationTelemetryRecord(
        id: UUID(),
        route: ModelRoute(provider: ProviderID("ollama"), model: ModelID(model)),
        startedAt: now.addingTimeInterval(-3),
        completedAt: now,
        timeToFirstTokenSeconds: 1,
        elapsedSeconds: 3,
        outputTokens: 30,
        outputTokenCountSource: .providerReported,
        outputTokensPerSecond: 10,
        outcome: .completed,
        failureCategory: nil
    )]
    return PerformanceCenterSnapshot(
        capturedAt: now,
        host: host,
        ollama: ollama,
        recommendation: recommendation,
        telemetry: telemetry
    )
}

@Test func auxiliaryDisplayPolicyRedactsSecretsPathsControlsAndBidiWithinHardBounds() {
    let credential = ["s", "k-", String(repeating: "a", count: 36)].joined()
    let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
    let hostile = "\u{202E}\(home)/private.json\u{001B}[31m \(credential)\nsecond\tline "
        + String(repeating: "Z", count: 80_000)

    let single = AuxiliaryDisplayPolicy.singleLine(
        hostile,
        maximumCharacters: 96,
        fallback: "fallback"
    )
    let multiline = AuxiliaryDisplayPolicy.multiline(hostile, maximumCharacters: 220)

    for rendered in [single, multiline] {
        #expect(!rendered.contains(credential))
        #expect(!rendered.contains(home))
        #expect(!rendered.unicodeScalars.contains { $0.properties.generalCategory == .format })
        #expect(!rendered.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) && $0 != "\n" })
    }
    #expect(single.unicodeScalars.count <= 96)
    #expect(multiline.unicodeScalars.count <= 220)
    #expect(single.contains("<private home>"))
}

@Test func activityStorageFailurePresentationIsTypedGenericAndFailClosed() {
    let failures: [ActivityStoreFailure] = [
        .unsafeStorage, .oversizedDocument, .malformedDocument, .invalidRecord, .persistenceFailed
    ]
    for failure in failures {
        let presentation = ActivityCenterStoragePresentation.make(status: .unavailable(failure))
        #expect(presentation.isFailure)
        #expect(!presentation.allowsClearing)
        #expect(presentation.message.hasPrefix("Activity history is unavailable"))
        #expect(presentation.message.unicodeScalars.count < 300)
        #expect(!presentation.message.contains("/Users/"))
    }
}

@MainActor
@Test func activitySelectionSurvivesReloadAndClearIsSingleFlight() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try auxiliaryPrivateDirectory("Activity")
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ActivityStore(applicationSupport: root)
    _ = try store.addWaitingSynchronously(.runtime, title: "Keep selected")
    _ = try store.addWaitingSynchronously(.runtime, title: "Second")
    store.addCompleted(.chat, title: "Finished")
    try await auxiliaryWait("initial activity persistence") { store.snapshot().count == 3 }

    let controller = ActivityCenterWindowController(store: store)
    defer { controller.close() }
    let content = try auxiliaryRoot(controller)
    let table = try #require(auxiliaryDescendants(content).compactMap { $0 as? NSTableView }.first)
    let clear = try auxiliaryButton("Clear Finished", in: content)
    table.selectRowIndexes(IndexSet(integer: 2), byExtendingSelection: false)
    #expect(table.selectedRow == 2)

    _ = try store.addWaitingSynchronously(.model, title: "Newest")
    try await auxiliaryWait("activity reload with preserved selection") {
        table.numberOfRows == 4 && table.selectedRow == 3
    }
    let selectedTitle = try #require(table.view(atColumn: 1, row: 3, makeIfNecessary: true) as? NSTextField)
    #expect(selectedTitle.stringValue == "Keep selected")

    clear.performClick(nil)
    #expect(!clear.isEnabled)
    clear.performClick(nil)
    try await auxiliaryWait("finished activity clear and table reload") {
        store.snapshot().count == 3
            && table.numberOfRows == 3
            && table.selectedRow == 2
    }
    #expect(store.snapshot().allSatisfy { $0.state != .completed })
    #expect(table.selectedRow == 2)
}

@MainActor
@Test func commandCenterBoundsHostileCopyFiltersAndBlocksSynchronousReentry() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let credential = ["s", "k-", String(repeating: "b", count: 36)].joined()
    let hostile = "\u{202E}\(FileManager.default.homeDirectoryForCurrentUser.path)/x \(credential) "
        + String(repeating: "A", count: 2_000)
    let target = AuxiliaryCommandTarget()
    var sendCalls = 0
    var reenter: (() -> Void)?
    let controller = CommandCenterWindowController(
        commands: [CommandCenterCommand(
            title: hostile,
            detail: "Private detail \(hostile)",
            symbolName: "not.a.real.symbol",
            keywords: ["private", hostile],
            action: #selector(AuxiliaryCommandTarget.openFeature(_:))
        )],
        actionTarget: target,
        interactions: CommandCenterInteractions(sendAction: { _, _, _ in
            sendCalls += 1
            reenter?()
            return false
        })
    )
    defer { controller.close() }
    controller.showWindow(nil)
    let root = try auxiliaryRoot(controller)
    let table = try #require(auxiliaryDescendants(root).compactMap { $0 as? NSTableView }.first)
    let row = try #require(table.view(atColumn: 0, row: 0, makeIfNecessary: true))
    let rendered = auxiliaryDescendants(row).compactMap { ($0 as? NSTextField)?.stringValue }.joined(separator: " ")
    #expect(!rendered.contains(credential))
    #expect(!rendered.contains(FileManager.default.homeDirectoryForCurrentUser.path))
    #expect(!rendered.unicodeScalars.contains { $0.properties.generalCategory == .format })

    let search = try #require(auxiliaryDescendants(root).compactMap { $0 as? NSSearchField }.first)
    search.stringValue = "private"
    controller.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: search))
    #expect(table.numberOfRows == 1)
    let open = try auxiliaryButton("Open", in: root)
    reenter = { open.performClick(nil) }
    open.performClick(nil)
    #expect(sendCalls == 1)
    #expect(open.title == "Open")
    #expect(open.isEnabled)
}

@MainActor
@Test func commandCenterFailsClosedForWeakOrInvalidTargets() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    var target: AuxiliaryCommandTarget? = AuxiliaryCommandTarget()
    var deliveries = 0
    let command = CommandCenterCommand(
        title: "Open feature",
        detail: "A bounded command",
        symbolName: "gearshape",
        keywords: [],
        action: #selector(AuxiliaryCommandTarget.openFeature(_:))
    )
    let weakController = CommandCenterWindowController(
        commands: [command],
        actionTarget: try #require(target),
        interactions: CommandCenterInteractions(sendAction: { _, _, _ in
            deliveries += 1
            return true
        })
    )
    defer { weakController.close() }
    target = nil
    weakController.showWindow(nil)
    let weakRoot = try auxiliaryRoot(weakController)
    let weakOpen = try auxiliaryButton("Open", in: weakRoot)
    #expect(!weakOpen.isEnabled)
    _ = weakController.perform(NSSelectorFromString("openSelected:"), with: nil)
    #expect(deliveries == 0)

    let invalidTarget = NSObject()
    let invalidController = CommandCenterWindowController(
        commands: [command],
        actionTarget: invalidTarget,
        interactions: CommandCenterInteractions(sendAction: { _, _, _ in
            deliveries += 1
            return true
        })
    )
    defer { invalidController.close() }
    invalidController.showWindow(nil)
    let invalidOpen = try auxiliaryButton("Open", in: auxiliaryRoot(invalidController))
    #expect(!invalidOpen.isEnabled)
    _ = invalidController.perform(NSSelectorFromString("openSelected:"), with: nil)
    #expect(deliveries == 0)
}

@MainActor
@Test func diagnosticsCopyAndRestartSynchronousCallbacksCannotReenter() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try auxiliaryPrivateDirectory("DiagnosticsCopy")
    defer { try? FileManager.default.removeItem(at: root) }
    let harness = HarnessController(
        applicationSupportDirectory: root,
        modelStoreDirectory: root.appendingPathComponent("Models"),
        forbidCredentialHelper: true
    )
    let probe = AuxiliaryDiagnosticsInteractionProbe()
    let controller = DiagnosticsWindowController(controller: harness, interactions: probe.interactions)
    defer { controller.close() }
    let content = try auxiliaryRoot(controller)
    let copy = try auxiliaryButton("Copy Support Report", in: content)
    let restart = try auxiliaryButton("Restart Services", in: content)
    let text = try #require(auxiliaryDescendants(content).compactMap { $0 as? NSTextView }.first)
    let credential = ["s", "k-", String(repeating: "c", count: 36)].joined()
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    text.string = "\u{202E}\(home)/secret.txt \(credential)\u{001B}[31m"

    probe.onCopy = { copy.performClick(nil) }
    copy.performClick(nil)
    #expect(probe.copied.count == 1)
    let copied = try #require(probe.copied.first)
    #expect(!copied.contains(credential))
    #expect(!copied.contains(home))
    #expect(copied.unicodeScalars.count <= DiagnosticsWindowController.maximumReportCharacters)
    #expect(copy.isEnabled)

    var restarts = 0
    controller.onRestart = {
        restarts += 1
        restart.performClick(nil)
    }
    restart.performClick(nil)
    #expect(restarts == 1)
    #expect(restart.isEnabled)
}

@MainActor
@Test func diagnosticsPreparationRunsOffMainIsSingleFlightAndShowsOnlyGenericFailure() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try auxiliaryPrivateDirectory("DiagnosticsFailure")
    defer { try? FileManager.default.removeItem(at: root) }
    let harness = HarnessController(
        applicationSupportDirectory: root,
        modelStoreDirectory: root.appendingPathComponent("Models"),
        forbidCredentialHelper: true
    )
    let preparation = AuxiliaryPreparationProbe(result: .failure)
    let interaction = AuxiliaryDiagnosticsInteractionProbe()
    let controller = DiagnosticsWindowController(
        controller: harness,
        operations: DiagnosticsOperations(prepareDirectory: { @Sendable directory in
            try preparation.prepare(directory)
        }),
        interactions: interaction.interactions
    )
    defer { controller.close() }
    let content = try auxiliaryRoot(controller)
    let open = try auxiliaryButton("Open Diagnostics Folder", in: content)
    open.performClick(nil)
    try await auxiliaryWait("diagnostics preparation start") { preparation.started }
    #expect(!preparation.ranOnMain)
    #expect(!open.isEnabled)
    _ = controller.perform(NSSelectorFromString("openFolder:"), with: nil)
    #expect(preparation.callCount == 1)

    preparation.release()
    try await auxiliaryWait("generic diagnostics failure") { interaction.notices.count == 1 }
    #expect(interaction.opened.isEmpty)
    let notice = interaction.notices.map { "\($0.title) \($0.message)" }.joined()
    #expect(!notice.contains("AUXILIARY_PRIVATE_CANARY"))
    #expect(!notice.contains("/Users/private"))
    #expect(!notice.contains("secret"))
    #expect(open.isEnabled)
}

@MainActor
@Test func diagnosticsCloseInvalidatesLatePreparationAndReopenRecovers() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try auxiliaryPrivateDirectory("DiagnosticsClose")
    defer { try? FileManager.default.removeItem(at: root) }
    let harness = HarnessController(
        applicationSupportDirectory: root,
        modelStoreDirectory: root.appendingPathComponent("Models"),
        forbidCredentialHelper: true
    )
    let preparation = AuxiliaryPreparationProbe(result: .success)
    let interaction = AuxiliaryDiagnosticsInteractionProbe()
    let controller = DiagnosticsWindowController(
        controller: harness,
        operations: DiagnosticsOperations(prepareDirectory: { @Sendable directory in
            try preparation.prepare(directory)
        }),
        interactions: interaction.interactions
    )
    // Ordering a fixture out before delivering its close lifecycle can make the
    // AppKit test host exit before Swift Testing records later filtered tests.
    // Exercise the delegate transition first, exactly as a real close does, and
    // hide the reopened fixture only during final cleanup.
    defer {
        controller.windowWillClose(
            Notification(name: NSWindow.willCloseNotification, object: controller.window)
        )
        controller.window?.orderOut(nil)
    }
    let open = try auxiliaryButton("Open Diagnostics Folder", in: auxiliaryRoot(controller))
    open.performClick(nil)
    try await auxiliaryWait("stale diagnostics preparation start") { preparation.started }
    controller.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: controller.window))
    preparation.release()
    let preparationSettled = await Task.detached {
        preparation.waitUntilFinished()
    }.value
    #expect(preparationSettled)
    #expect(preparation.finished)
    // The close path intentionally cancels the UI task. Yield through one
    // explicit main-queue continuation without throwing CancellationError so
    // its late result can reach the generation guard and prove that no stale
    // callback is rendered.
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        DispatchQueue.main.async { continuation.resume() }
    }
    #expect(interaction.opened.isEmpty)
    #expect(interaction.notices.isEmpty)

    controller.showWindow(nil)
    let reopened = try auxiliaryButton("Open Diagnostics Folder", in: auxiliaryRoot(controller))
    #expect(reopened.isEnabled)
    #expect(reopened.title == "Open Diagnostics Folder")
}

@MainActor
@Test func performanceCenterBoundsEveryHostileProviderLabelBeforeRendering() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let credential = ["s", "k-", String(repeating: "d", count: 36)].joined()
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let hostile = "\u{202E}\(home)/model \(credential)\u{001B}[31m " + String(repeating: "Q", count: 8_000)
    let controller = PerformanceCenterWindowController(snapshot: auxiliarySnapshot(reason: hostile, model: hostile))
    defer { controller.close() }
    let fields = auxiliaryDescendants(try auxiliaryRoot(controller)).compactMap { $0 as? NSTextField }
    let rendered = fields.map(\.stringValue).joined(separator: "\n")
    #expect(!rendered.contains(credential))
    #expect(!rendered.contains(home))
    #expect(!rendered.unicodeScalars.contains { $0.properties.generalCategory == .format })
    #expect(fields.allSatisfy { $0.stringValue.unicodeScalars.count <= 1_200 })
    #expect(rendered.contains("<private home>"))
}

@MainActor
@Test func performanceClearSynchronousCallbackCannotReenterOrLosePendingState() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let controller = PerformanceCenterWindowController(snapshot: auxiliarySnapshot())
    defer { controller.close() }
    let root = try auxiliaryRoot(controller)
    let clear = try auxiliaryButton(label: "Clear private performance history", in: root)
    var calls = 0
    controller.onClearHistory = {
        calls += 1
        clear.performClick(nil)
        controller.setHistoryClearPending(true)
    }

    clear.performClick(nil)
    #expect(calls == 1)
    #expect(controller.historyClearPending)
    let replacement = try auxiliaryButton(
        label: "Clear private performance history",
        in: auxiliaryRoot(controller)
    )
    #expect(replacement.title == "Clearing…")
    #expect(!replacement.isEnabled)
}

@MainActor
@Test func performanceClearCoordinatorHandlesImmediateWorkerCompletionOffMainAndDuplicateSafe() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try auxiliaryPrivateDirectory("PerformanceClear")
    defer { try? FileManager.default.removeItem(at: root) }
    let probe = AuxiliaryClearProbe()
    let coordinator = PerformanceHistoryClearCoordinator(
        applicationSupport: root,
        storageClear: { @Sendable directory in
            probe.clear(directory)
        }
    )
    var outcomes: [PerformanceHistoryClearOutcome] = []
    #expect(coordinator.clear { outcomes.append($0) })
    #expect(coordinator.state == .clearing)
    #expect(!coordinator.clear { _ in Issue.record("duplicate clear completed") })
    try await auxiliaryWait("immediate clear completion") { outcomes == [.success] }
    #expect(probe.callCount == 1)
    #expect(!probe.ranOnMain)
    #expect(coordinator.state == .idle)
}

@MainActor
@Test func auxiliaryWindowsRemainAccessibleAtCompactSizeInLightAndDarkAppearances() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try auxiliaryPrivateDirectory("CompactLayout")
    defer { try? FileManager.default.removeItem(at: root) }
    let activity = ActivityCenterWindowController(
        store: ActivityStore(applicationSupport: root.appendingPathComponent("Activity"))
    )
    let target = AuxiliaryCommandTarget()
    let command = CommandCenterWindowController(
        commands: [CommandCenterCommand(
            title: "Settings",
            detail: "Open application settings",
            symbolName: "gearshape",
            keywords: [],
            action: #selector(AuxiliaryCommandTarget.openFeature(_:))
        )],
        actionTarget: target
    )
    let harness = HarnessController(
        applicationSupportDirectory: root.appendingPathComponent("Support"),
        modelStoreDirectory: root.appendingPathComponent("Models"),
        forbidCredentialHelper: true
    )
    let diagnostics = DiagnosticsWindowController(controller: harness)
    let performance = PerformanceCenterWindowController(snapshot: auxiliarySnapshot())
    let controllers: [(String, NSWindowController, NSSize)] = [
        ("Activity", activity, NSSize(width: 640, height: 420)),
        ("Command", command, NSSize(width: 640, height: 420)),
        ("Diagnostics", diagnostics, NSSize(width: 640, height: 420)),
        ("Performance", performance, NSSize(width: 760, height: 560))
    ]
    defer { controllers.forEach { $0.1.close() } }

    for (name, controller, contentSize) in controllers {
        let window = try #require(controller.window, Comment(rawValue: name))
        window.setContentSize(contentSize)
        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearance)
            window.layoutIfNeeded()
            let content = try auxiliaryRoot(controller)
            content.layoutSubtreeIfNeeded()
            #expect(!content.hasAmbiguousLayout, Comment(rawValue: "\(name) \(appearance.rawValue) root"))
            let bitmap = try #require(
                content.bitmapImageRepForCachingDisplay(in: content.bounds),
                Comment(rawValue: "\(name) \(appearance.rawValue) bitmap")
            )
            content.cacheDisplay(in: content.bounds, to: bitmap)
            #expect(bitmap.pixelsWide > 0 && bitmap.pixelsHigh > 0)
        }
    }

    let activityRoot = try auxiliaryRoot(activity)
    #expect(auxiliaryDescendants(activityRoot).contains {
        ($0 as? NSTableView)?.accessibilityLabel() == "Recent agent and service activity"
    })
    #expect(try auxiliaryButton(label: "Clear finished activity history", in: activityRoot).action != nil)

    let commandRoot = try auxiliaryRoot(command)
    #expect(auxiliaryDescendants(commandRoot).contains {
        ($0 as? NSSearchField)?.accessibilityLabel() == "Search Fulmar features"
    })
    #expect(auxiliaryDescendants(commandRoot).contains {
        ($0 as? NSTableView)?.accessibilityLabel() == "Fulmar features"
    })

    let diagnosticsRoot = try auxiliaryRoot(diagnostics)
    #expect(auxiliaryDescendants(diagnosticsRoot).contains {
        ($0 as? NSTextView)?.accessibilityLabel() == "Fulmar support report"
    })
    for label in [
        "Copy sanitized support report",
        "Open private diagnostics folder",
        "Restart local services"
    ] {
        #expect(try auxiliaryButton(label: label, in: diagnosticsRoot).action != nil)
    }

    let performanceRoot = try auxiliaryRoot(performance)
    #expect(auxiliaryDescendants(performanceRoot).contains {
        ($0 as? NSScrollView)?.accessibilityLabel() == "Performance details"
    })
    #expect(try auxiliaryButton(label: "Clear private performance history", in: performanceRoot).action != nil)
}
