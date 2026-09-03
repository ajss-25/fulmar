import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct HostileWorkspaceRecoveryError: LocalizedError {
    var errorDescription: String? {
        "WORKSPACE_SECRET_CANARY sk-private \(String(repeating: "X", count: 32_000))\u{001B}[31m"
    }
}

private final class WorkspaceRecoveryOperationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var listResults: [Result<[WorkspaceCheckpointSummary], Error>] = []
    private(set) var captureResults: [Result<WorkspaceCheckpoint, Error>] = []
    private(set) var deleteResults: [Result<Void, Error>] = []
    private(set) var previewResults: [Result<WorkspaceRestorePreview, Error>] = []
    private(set) var restoreResults: [Result<WorkspaceRestoreReport, Error>] = []
    private var listCallsValue = 0
    private var captureLabelsValue: [String] = []
    private var deletedIDsValue: [UUID] = []
    private var previewIDsValue: [UUID] = []
    private var restoreRequestsValue: [(UUID, WorkspaceRestorePreview, WorkspaceRestoreOptions)] = []
    var listGate: DispatchSemaphore?

    func enqueueLists(_ values: [Result<[WorkspaceCheckpointSummary], Error>]) {
        lock.withLock { listResults.append(contentsOf: values) }
    }

    func enqueueCaptures(_ values: [Result<WorkspaceCheckpoint, Error>]) {
        lock.withLock { captureResults.append(contentsOf: values) }
    }

    func enqueueDeletes(_ values: [Result<Void, Error>]) {
        lock.withLock { deleteResults.append(contentsOf: values) }
    }

    func enqueuePreviews(_ values: [Result<WorkspaceRestorePreview, Error>]) {
        lock.withLock { previewResults.append(contentsOf: values) }
    }

    func enqueueRestores(_ values: [Result<WorkspaceRestoreReport, Error>]) {
        lock.withLock { restoreResults.append(contentsOf: values) }
    }

    func operations(workspace: URL) -> WorkspaceRecoveryOperations {
        WorkspaceRecoveryOperations(
            approvedWorkspaceURL: workspace,
            listCheckpoints: { [self] in try list() },
            captureCheckpoint: { [self] in try capture($0) },
            deleteCheckpoint: { [self] in try delete($0) },
            previewRestore: { [self] in try preview($0) },
            restore: { [self] in try restore($0, $1, $2) }
        )
    }

    func counts() -> (list: Int, capture: Int, delete: Int, preview: Int, restore: Int) {
        lock.withLock {
            (listCallsValue, captureLabelsValue.count, deletedIDsValue.count, previewIDsValue.count, restoreRequestsValue.count)
        }
    }

    func captureLabels() -> [String] { lock.withLock { captureLabelsValue } }
    func deletedIDs() -> [UUID] { lock.withLock { deletedIDsValue } }
    func restoreRequests() -> [(UUID, WorkspaceRestorePreview, WorkspaceRestoreOptions)] {
        lock.withLock { restoreRequestsValue }
    }

    private func list() throws -> [WorkspaceCheckpointSummary] {
        let gate: DispatchSemaphore? = lock.withLock {
            listCallsValue += 1
            return listGate
        }
        gate?.wait()
        return try lock.withLock {
            guard !listResults.isEmpty else { throw HostileWorkspaceRecoveryError() }
            return try listResults.removeFirst().get()
        }
    }

    private func capture(_ label: String) throws -> WorkspaceCheckpoint {
        try lock.withLock {
            captureLabelsValue.append(label)
            guard !captureResults.isEmpty else { throw HostileWorkspaceRecoveryError() }
            return try captureResults.removeFirst().get()
        }
    }

    private func delete(_ id: UUID) throws {
        try lock.withLock {
            deletedIDsValue.append(id)
            guard !deleteResults.isEmpty else { throw HostileWorkspaceRecoveryError() }
            try deleteResults.removeFirst().get()
        }
    }

    private func preview(_ id: UUID) throws -> WorkspaceRestorePreview {
        try lock.withLock {
            previewIDsValue.append(id)
            guard !previewResults.isEmpty else { throw HostileWorkspaceRecoveryError() }
            return try previewResults.removeFirst().get()
        }
    }

    private func restore(
        _ id: UUID,
        _ preview: WorkspaceRestorePreview,
        _ options: WorkspaceRestoreOptions
    ) throws -> WorkspaceRestoreReport {
        try lock.withLock {
            restoreRequestsValue.append((id, preview, options))
            guard !restoreResults.isEmpty else { throw HostileWorkspaceRecoveryError() }
            return try restoreResults.removeFirst().get()
        }
    }
}

@MainActor
private final class WorkspaceRecoveryAlertProbe {
    var decisions: [Bool] = []
    var checkpointLabels: [String] = []
    private(set) var titles: [String] = []
    private(set) var messages: [String] = []

    var presenter: WorkspaceRecoveryAlertPresenter {
        WorkspaceRecoveryAlertPresenter(present: { [unowned self] alert, _, completion in
            titles.append(alert.messageText)
            messages.append(alert.informativeText)
            if let field = alert.accessoryView as? NSTextField, !checkpointLabels.isEmpty {
                field.stringValue = checkpointLabels.removeFirst()
            }
            completion(decisions.isEmpty ? false : decisions.removeFirst())
        })
    }
}

@MainActor
private func workspaceRecoveryDescendants(_ root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(workspaceRecoveryDescendants)
}

@MainActor
private func workspaceRecoveryButton(_ title: String, root: NSView) throws -> NSButton {
    try #require(workspaceRecoveryDescendants(root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func workspaceRecoveryStatus(_ root: NSView) throws -> NSTextField {
    try #require(workspaceRecoveryDescendants(root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == "Workspace recovery status"
    })
}

@MainActor
private func workspaceRecoveryTable(_ label: String, root: NSView) throws -> NSTableView {
    try #require(workspaceRecoveryDescendants(root).compactMap { $0 as? NSTableView }.first {
        $0.accessibilityLabel() == label
    })
}

@MainActor
private func workspaceRecoveryForceSelector(_ button: NSButton) throws {
    let action = try #require(button.action)
    #expect(NSApp.sendAction(action, to: button.target, from: button))
}

private enum WorkspaceRecoveryBehaviorTimeout: Error { case timedOut }

@MainActor
private func workspaceRecoveryEventually(
    attempts: Int = 500,
    _ condition: @escaping @MainActor () -> Bool
) async throws {
    for _ in 0..<attempts {
        if condition() { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    throw WorkspaceRecoveryBehaviorTimeout.timedOut
}

private struct WorkspaceRecoveryBehaviorFixtures {
    let id = UUID()
    let summary: WorkspaceCheckpointSummary
    let checkpoint: WorkspaceCheckpoint
    let emptyPreview: WorkspaceRestorePreview
    let changedPreview: WorkspaceRestorePreview

    init() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        summary = WorkspaceCheckpointSummary(
            id: id,
            createdAt: now,
            label: "Before changes",
            fileCount: 2,
            totalBytes: 12,
            metadataFingerprint: "metadata"
        )
        checkpoint = WorkspaceCheckpoint(
            formatVersion: WorkspaceCheckpoint.currentFormatVersion,
            id: id,
            createdAt: now,
            label: "Before changes",
            origin: .manual,
            workspaceCanonicalPath: "/tmp/workspace",
            workspaceIdentifier: "workspace-id",
            files: [],
            totalBytes: 0,
            metadataFingerprint: "metadata"
        )
        emptyPreview = WorkspaceRestorePreview(
            checkpointID: id,
            workspaceIdentifier: "workspace-id",
            changes: [],
            conflicts: [],
            stateFingerprint: "clean"
        )
        changedPreview = WorkspaceRestorePreview(
            checkpointID: id,
            workspaceIdentifier: "workspace-id",
            changes: [
                WorkspaceChange(kind: .modified, relativePath: "modified.txt", checkpoint: nil, current: nil),
                WorkspaceChange(kind: .deleted, relativePath: "missing.txt", checkpoint: nil, current: nil),
                WorkspaceChange(kind: .added, relativePath: "added.txt", checkpoint: nil, current: nil)
            ],
            conflicts: [
                WorkspaceRestoreConflict(kind: .wouldOverwriteModifiedFile, relativePath: "modified.txt")
            ],
            stateFingerprint: "changed"
        )
    }
}

@MainActor
@Test func workspaceRecoveryCaptureDeleteCancelSuccessAndSelectionLifecycle() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = WorkspaceRecoveryBehaviorFixtures()
    let operations = WorkspaceRecoveryOperationProbe()
    operations.enqueueLists([.success([]), .success([fixture.summary]), .success([])])
    operations.enqueueCaptures([.success(fixture.checkpoint)])
    operations.enqueueDeletes([.success(())])
    operations.enqueuePreviews([.success(fixture.emptyPreview)])
    let alerts = WorkspaceRecoveryAlertProbe()
    let controller = WorkspaceRecoveryWindowController(
        operations: operations.operations(workspace: URL(fileURLWithPath: "/tmp/workspace")),
        alertPresenter: alerts.presenter
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let refresh = try workspaceRecoveryButton("Refresh", root: root)
    let capture = try workspaceRecoveryButton("Create Checkpoint…", root: root)
    let delete = try workspaceRecoveryButton("Delete…", root: root)
    let status = try workspaceRecoveryStatus(root)
    let checkpoints = try workspaceRecoveryTable("Workspace recovery checkpoints", root: root)

    refresh.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 1 && refresh.isEnabled }
    #expect(status.stringValue == "No local recovery checkpoints.")

    alerts.decisions = [false]
    capture.performClick(nil)
    #expect(operations.counts().capture == 0)
    alerts.decisions = [true]
    alerts.checkpointLabels = ["  reviewed baseline  "]
    capture.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 2 && checkpoints.numberOfRows == 1 }
    #expect(operations.captureLabels() == ["  reviewed baseline  "])
    #expect(checkpoints.selectedRow == 0)

    alerts.decisions = [false]
    delete.performClick(nil)
    #expect(operations.counts().delete == 0)
    alerts.decisions = [true]
    delete.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 3 && checkpoints.numberOfRows == 0 }
    #expect(operations.deletedIDs() == [fixture.id])
    #expect(status.stringValue == "No local recovery checkpoints.")
}

@MainActor
@Test func workspaceRecoveryRestoreRequiresEveryConsentAndExactQuiescenceOnce() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = WorkspaceRecoveryBehaviorFixtures()
    let operations = WorkspaceRecoveryOperationProbe()
    operations.enqueueLists([.success([fixture.summary])])
    operations.enqueuePreviews([.success(fixture.changedPreview), .success(fixture.emptyPreview)])
    operations.enqueueRestores([
        .failure(HostileWorkspaceRecoveryError()),
        .success(WorkspaceRestoreReport(
            restoredDeletedFiles: 1,
            overwrittenModifiedFiles: 1,
            removedAddedFiles: 1,
            unchangedFiles: 0
        ))
    ])
    let alerts = WorkspaceRecoveryAlertProbe()
    let controller = WorkspaceRecoveryWindowController(
        operations: operations.operations(workspace: URL(fileURLWithPath: "/tmp/workspace")),
        alertPresenter: alerts.presenter
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let refresh = try workspaceRecoveryButton("Refresh", root: root)
    let restore = try workspaceRecoveryButton("Restore…", root: root)
    let removeAdded = try workspaceRecoveryButton("Also remove files created after this checkpoint", root: root)
    let status = try workspaceRecoveryStatus(root)

    refresh.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().preview == 1 && restore.isEnabled }
    removeAdded.state = .on
    try workspaceRecoveryForceSelector(removeAdded)

    alerts.decisions = [false]
    restore.performClick(nil)
    #expect(operations.counts().restore == 0)
    alerts.decisions = [true, false]
    restore.performClick(nil)
    #expect(operations.counts().restore == 0)

    var finished: [Bool] = []
    controller.onRestoreAttemptFinished = { finished.append($0) }
    alerts.decisions = [true, true]
    restore.performClick(nil)
    #expect(finished == [false])
    #expect(operations.counts().restore == 0)
    #expect(status.stringValue.contains("protected runtime coordinator is not connected"))

    var preparations: [(Result<Void, Error>) -> Void] = []
    controller.onPrepareRestore = { preparations.append($0) }
    alerts.decisions = [true, true]
    restore.performClick(nil)
    #expect(preparations.count == 1)
    preparations[0](.failure(HostileWorkspaceRecoveryError()))
    try await workspaceRecoveryEventually { restore.isEnabled }
    #expect(finished == [false, false])
    #expect(!status.stringValue.contains("WORKSPACE_SECRET_CANARY"))
    #expect(operations.counts().restore == 0)

    alerts.decisions = [true, true]
    restore.performClick(nil)
    #expect(preparations.count == 2)
    preparations[1](.success(()))
    preparations[1](.failure(HostileWorkspaceRecoveryError()))
    try await workspaceRecoveryEventually { operations.counts().restore == 1 && restore.isEnabled }
    #expect(finished == [false, false, false])
    #expect(!status.stringValue.contains("WORKSPACE_SECRET_CANARY"))

    alerts.decisions = [true, true]
    restore.performClick(nil)
    #expect(preparations.count == 3)
    preparations[2](.success(()))
    preparations[2](.success(()))
    try await workspaceRecoveryEventually { operations.counts().restore == 2 && status.stringValue.contains("Restore completed") }
    #expect(finished == [false, false, false, true])
    let requests = operations.restoreRequests()
    #expect(requests.count == 2)
    #expect(requests.allSatisfy { $0.2 == WorkspaceRestoreOptions(overwriteModifiedFiles: true, removeAddedFiles: true) })
}

@MainActor
@Test func workspaceRecoveryAllOperationFailuresAreBoundedAndAppOwned() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = WorkspaceRecoveryBehaviorFixtures()
    let hostile: Result<[WorkspaceCheckpointSummary], Error> = .failure(HostileWorkspaceRecoveryError())
    let operations = WorkspaceRecoveryOperationProbe()
    operations.enqueueLists([hostile, .success([fixture.summary])])
    operations.enqueueCaptures([.failure(HostileWorkspaceRecoveryError())])
    operations.enqueuePreviews([.failure(HostileWorkspaceRecoveryError())])
    operations.enqueueDeletes([.failure(HostileWorkspaceRecoveryError())])
    let alerts = WorkspaceRecoveryAlertProbe()
    let controller = WorkspaceRecoveryWindowController(
        operations: operations.operations(workspace: URL(fileURLWithPath: "/tmp/workspace")),
        alertPresenter: alerts.presenter
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let refresh = try workspaceRecoveryButton("Refresh", root: root)
    let capture = try workspaceRecoveryButton("Create Checkpoint…", root: root)
    let status = try workspaceRecoveryStatus(root)

    refresh.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 1 && refresh.isEnabled }
    #expect(!status.stringValue.contains("WORKSPACE_SECRET_CANARY"))
    #expect(status.stringValue.count < 240)

    alerts.decisions = [true]
    alerts.checkpointLabels = ["failure"]
    capture.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().capture == 1 && capture.isEnabled }
    #expect(!status.stringValue.contains("WORKSPACE_SECRET_CANARY"))
    #expect(status.stringValue.count < 240)

    refresh.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 2 && operations.counts().preview == 1 }
    #expect(!status.stringValue.contains("WORKSPACE_SECRET_CANARY"))
    #expect(status.stringValue.count < 240)

    // The failed preview leaves restore disabled, while deletion remains an
    // independently confirmed metadata operation.
    let delete = try workspaceRecoveryButton("Delete…", root: root)
    alerts.decisions = [true]
    delete.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().delete == 1 && delete.isEnabled }
    #expect(!status.stringValue.contains("WORKSPACE_SECRET_CANARY"))
    #expect(status.stringValue.count < 240)
    #expect(alerts.messages.allSatisfy { !$0.contains("WORKSPACE_SECRET_CANARY") && $0.count < 600 })
}

@MainActor
@Test func workspaceRecoveryBusyAndCloseReopenCannotReenterBlockedOperations() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let operations = WorkspaceRecoveryOperationProbe()
    operations.enqueueLists([.success([]), .success([])])
    let gate = DispatchSemaphore(value: 0)
    operations.listGate = gate
    let alerts = WorkspaceRecoveryAlertProbe()
    let controller = WorkspaceRecoveryWindowController(
        operations: operations.operations(workspace: URL(fileURLWithPath: "/tmp/workspace")),
        alertPresenter: alerts.presenter
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let refresh = try workspaceRecoveryButton("Refresh", root: root)
    let capture = try workspaceRecoveryButton("Create Checkpoint…", root: root)
    let delete = try workspaceRecoveryButton("Delete…", root: root)
    let restore = try workspaceRecoveryButton("Restore…", root: root)

    refresh.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 1 }
    for button in [refresh, capture, delete, restore] { try workspaceRecoveryForceSelector(button) }
    let blockedCounts = operations.counts()
    #expect(blockedCounts.list == 1)
    #expect(blockedCounts.capture == 0)
    #expect(blockedCounts.delete == 0)
    #expect(blockedCounts.preview == 0)
    #expect(blockedCounts.restore == 0)
    controller.close()
    controller.showWindow(nil)
    #expect(operations.counts().list == 1)
    gate.signal()
    try await workspaceRecoveryEventually { refresh.isEnabled }

    refresh.performClick(nil)
    try await workspaceRecoveryEventually { operations.counts().list == 2 }
    gate.signal()
    try await workspaceRecoveryEventually { refresh.isEnabled }
    #expect(operations.counts().list == 2)
}
