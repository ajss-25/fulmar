import AppKit
import Foundation
import Testing
@testable import LocalHarness

private enum SecurityWindowProbeError: LocalizedError {
    case hostile

    var errorDescription: String? {
        "REMOTE_SECRET_CANARY_\(String(repeating: "X", count: 32_000))"
    }
}

@MainActor
private final class PrivacyInteractionProbe {
    var shouldConfirmClear = false
    var destination: URL?
    var requestedExports: [(PrivacyLedgerExportFormat, String)] = []
    var notices: [PrivacyDashboardNotice] = []
    var pendingMaintenanceWork: (() -> Void)?
    var pendingMaintenanceCompletion: (() -> Void)?

    var interactions: PrivacyDashboardInteractions {
        PrivacyDashboardInteractions(
            confirmClear: { [unowned self] in shouldConfirmClear },
            chooseExportDestination: { [unowned self] format, name in
                requestedExports.append((format, name))
                return destination
            },
            presentNotice: { [unowned self] notice in notices.append(notice) },
            runMaintenance: { [unowned self] work, completion in
                pendingMaintenanceWork = work
                pendingMaintenanceCompletion = completion
            }
        )
    }
}

private struct PrivacyWindowFixture {
    let root: URL
    let defaultsSuite: String
    let preferences: PreferencesStore
    let ledger: PrivacyLedger
    let maintenance: PrivacyMaintenanceCoordinator

    init(label: String = "Privacy") throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FulmarSecurityWindow-\(label)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defaultsSuite = "FulmarSecurityWindow.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: defaultsSuite))
        defaults.removePersistentDomain(forName: defaultsSuite)
        preferences = PreferencesStore(defaults: defaults)
        ledger = PrivacyLedger(applicationSupport: root)
        maintenance = PrivacyMaintenanceCoordinator(
            appshots: AppshotController(
                preferences: preferences,
                directory: root.appendingPathComponent("Appshots", isDirectory: true)
            ),
            ledger: ledger,
            attachments: AttachmentRetentionManager(harnessHome: root.appendingPathComponent("Harness", isDirectory: true)),
            preferences: preferences,
            canPurgeAttachments: { false }
        )
    }

    func remove() {
        UserDefaults(suiteName: defaultsSuite)?.removePersistentDomain(forName: defaultsSuite)
        try? FileManager.default.removeItem(at: root)
    }
}

@MainActor
@Test func privacyDashboardExportsBothFormatsAndTreatsSaveCancellationAsNoOp() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try PrivacyWindowFixture(label: "Export")
    defer { fixture.remove() }
    try fixture.ledger.recordSynchronously(.runtimeStarted, summary: "local", localOnly: true)
    let probe = PrivacyInteractionProbe()
    let controller = PrivacyDashboardWindowController(
        ledger: fixture.ledger,
        preferences: fixture.preferences,
        maintenance: fixture.maintenance,
        interactions: probe.interactions
    )
    let views = try securityWindowViews(controller)
    let export = try securityWindowButton("Export…", in: views)
    let format = try #require(views.compactMap { $0 as? NSPopUpButton }.first)

    let json = fixture.root.appendingPathComponent("Export/ledger.json")
    probe.destination = json
    format.selectItem(at: 0)
    export.performClick(nil)
    #expect(probe.requestedExports.last?.0 == .json)
    #expect(probe.requestedExports.last?.1 == "\(ProductBrand.displayName) Privacy Ledger.json")
    #expect(try JSONDecoder().decode([PrivacyEvent].self, from: Data(contentsOf: json)).count == 1)
    #expect(probe.notices.last == .exportSucceeded(PrivacyLedgerExportResult(
        exported: 1,
        invalidSkipped: 0,
        destination: json
    )))

    let jsonl = fixture.root.appendingPathComponent("Export/ledger.jsonl")
    probe.destination = jsonl
    format.selectItem(at: 1)
    export.performClick(nil)
    #expect(probe.requestedExports.last?.0 == .jsonl)
    #expect(probe.requestedExports.last?.1 == "\(ProductBrand.displayName) Privacy Ledger.jsonl")
    #expect(String(decoding: try Data(contentsOf: jsonl), as: UTF8.self).split(separator: "\n").count == 1)

    let noticesBeforeCancel = probe.notices
    probe.destination = nil
    export.performClick(nil)
    #expect(probe.notices == noticesBeforeCancel)
}

@MainActor
@Test func privacyDashboardExportAndClearFailuresUseBoundedAppOwnedNotices() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try PrivacyWindowFixture(label: "Failure")
    defer { fixture.remove() }
    try fixture.ledger.recordSynchronously(.runtimeStarted, summary: "retain", localOnly: true)
    let probe = PrivacyInteractionProbe()
    let controller = PrivacyDashboardWindowController(
        ledger: fixture.ledger,
        preferences: fixture.preferences,
        maintenance: fixture.maintenance,
        interactions: probe.interactions
    )
    let views = try securityWindowViews(controller)
    let export = try securityWindowButton("Export…", in: views)
    probe.destination = fixture.root // A directory cannot become the export file.
    export.performClick(nil)
    #expect(probe.notices == [.exportFailed])
    #expect(fixture.ledger.counts().valid == 1)

    let clear = try securityWindowButton("Clear Ledger…", in: views)
    probe.shouldConfirmClear = false
    clear.performClick(nil)
    #expect(fixture.ledger.counts().valid == 1)

    probe.shouldConfirmClear = true
    clear.performClick(nil)
    #expect(fixture.ledger.counts().valid == 0)

    let unsafeRoot = fixture.root.appendingPathComponent("Unsafe", isDirectory: true)
    let outside = fixture.root.appendingPathComponent("outside.jsonl")
    try FileManager.default.createDirectory(
        at: unsafeRoot.appendingPathComponent("Privacy", isDirectory: true),
        withIntermediateDirectories: true
    )
    try Data("must remain".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(
        at: unsafeRoot.appendingPathComponent("Privacy/events.jsonl"),
        withDestinationURL: outside
    )
    let unsafeLedger = PrivacyLedger(applicationSupport: unsafeRoot)
    let unsafeMaintenance = PrivacyMaintenanceCoordinator(
        appshots: AppshotController(
            preferences: fixture.preferences,
            directory: unsafeRoot.appendingPathComponent("Appshots", isDirectory: true)
        ),
        ledger: unsafeLedger,
        attachments: AttachmentRetentionManager(harnessHome: unsafeRoot),
        preferences: fixture.preferences,
        canPurgeAttachments: { false }
    )
    let unsafeProbe = PrivacyInteractionProbe()
    unsafeProbe.shouldConfirmClear = true
    let unsafeController = PrivacyDashboardWindowController(
        ledger: unsafeLedger,
        preferences: fixture.preferences,
        maintenance: unsafeMaintenance,
        interactions: unsafeProbe.interactions
    )
    let unsafeViews = try securityWindowViews(unsafeController)
    try securityWindowButton("Clear Ledger…", in: unsafeViews).performClick(nil)
    #expect(unsafeProbe.notices == [.clearFailed])
    #expect(try String(contentsOf: outside, encoding: .utf8) == "must remain")
}

@MainActor
@Test func privacyDashboardPurgeDisablesEveryMutationUntilCompletionAndRefreshes() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try PrivacyWindowFixture(label: "Purge")
    defer { fixture.remove() }
    let probe = PrivacyInteractionProbe()
    let controller = PrivacyDashboardWindowController(
        ledger: fixture.ledger,
        preferences: fixture.preferences,
        maintenance: fixture.maintenance,
        interactions: probe.interactions
    )
    let views = try securityWindowViews(controller)
    let purge = try securityWindowButton("Purge Expired Data", in: views)
    let clear = try securityWindowButton("Clear Ledger…", in: views)
    let export = try securityWindowButton("Export…", in: views)
    purge.performClick(nil)
    #expect(!purge.isEnabled)
    #expect(!clear.isEnabled)
    #expect(!export.isEnabled)
    #expect(probe.pendingMaintenanceWork != nil)
    #expect(probe.pendingMaintenanceCompletion != nil)

    probe.pendingMaintenanceWork?()
    probe.pendingMaintenanceCompletion?()
    #expect(purge.isEnabled)
    #expect(clear.isEnabled)
    #expect(export.isEnabled)
    let labels = views.compactMap { $0 as? NSTextField }.map(\.stringValue)
    #expect(labels.contains { $0.contains("Appshots:") && $0.contains("Ledger:") })
}

@MainActor
private final class BackupOperationProbe {
    struct CreateCall {
        let label: String
        let sourceVersion: String
        let permit: StateBackupQuiescencePermit
        let completion: @MainActor (Result<StateBackup, Error>) -> Void
    }

    struct RestoreCall {
        let backup: StateBackup
        let permit: StateBackupQuiescencePermit
        let completion: @MainActor (Result<StateBackupRestoreReport, Error>) -> Void
    }

    struct DeleteCall {
        let backup: StateBackup
        let completion: @MainActor (Result<Void, Error>) -> Void
    }

    var canAuthorize = true
    var listCompletions: [@MainActor (Result<[StateBackup], Error>) -> Void] = []
    var authorizationCompletions: [@MainActor (Result<Void, Error>) -> Void] = []
    var creates: [CreateCall] = []
    var restores: [RestoreCall] = []
    var deletes: [DeleteCall] = []

    var operations: BackupWindowOperations {
        BackupWindowOperations(
            validatedListAsync: { [unowned self] completion in
                listCompletions.append(completion)
                return StateBackupOperationCancellation()
            },
            canAuthorizeAuthenticationKeyForForeground: { [unowned self] in canAuthorize },
            authorizeAuthenticationKeyForForegroundAsync: { [unowned self] completion in
                authorizationCompletions.append(completion)
                return StateBackupOperationCancellation()
            },
            createAsync: { [unowned self] label, version, permit, completion in
                creates.append(CreateCall(
                    label: label,
                    sourceVersion: version,
                    permit: permit,
                    completion: completion
                ))
                return StateBackupOperationCancellation()
            },
            restoreAsync: { [unowned self] backup, permit, completion in
                restores.append(RestoreCall(backup: backup, permit: permit, completion: completion))
                return StateBackupOperationCancellation()
            },
            deleteAsync: { [unowned self] backup, completion in
                deletes.append(DeleteCall(backup: backup, completion: completion))
                return StateBackupOperationCancellation()
            }
        )
    }

    func completeList(_ result: Result<[StateBackup], Error>) {
        listCompletions.removeFirst()(result)
    }
}

@MainActor
private final class BackupInteractionProbe {
    var confirmations: [BackupWindowConfirmation] = []
    var notices: [BackupWindowNotice] = []
    var shouldConfirm = true

    var interactions: BackupWindowInteractions {
        BackupWindowInteractions(
            confirm: { [unowned self] confirmation in
                confirmations.append(confirmation)
                return shouldConfirm
            },
            presentNotice: { [unowned self] notice in notices.append(notice) }
        )
    }
}

private struct BackupWindowControls {
    let reload: NSButton
    let create: NSButton
    let authorize: NSButton
    let delete: NSButton
    let restore: NSButton
    let table: NSTableView
    let status: NSTextField
    let privacyDisclosure: NSTextField
}

@MainActor
@Test func backupWindowReloadSelectionAndFailureAreFailClosedAndBounded() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let operations = BackupOperationProbe()
    let interactions = BackupInteractionProbe()
    let controller = BackupWindowController(
        operations: operations.operations,
        runtimeVersion: { "test" },
        interactions: interactions.interactions
    )
    let controls = try backupWindowControls(controller)
    #expect(controls.privacyDisclosure.stringValue == BackupWindowController.privacyDisclosure)
    #expect(controls.privacyDisclosure.accessibilityLabel() == "Backup privacy and protection")
    #expect(controls.privacyDisclosure.accessibilityHelp() == BackupWindowController.privacyDisclosure)
    #expect(controls.privacyDisclosure.stringValue.contains("not encrypted"))
    #expect(controls.privacyDisclosure.stringValue.contains("durable tool-output spills"))
    #expect(controls.privacyDisclosure.stringValue.contains("Keychain values"))
    #expect(controls.privacyDisclosure.stringValue.contains("Keep backup files private"))
    #expect(!controls.restore.isEnabled)
    #expect(!controls.delete.isEnabled)

    controls.reload.performClick(nil)
    #expect(!controls.reload.isEnabled)
    #expect(!controls.create.isEnabled)
    #expect(!controls.table.isEnabled)
    let backups = [securityWindowBackup(1), securityWindowBackup(2)]
    operations.completeList(.success(backups))
    #expect(controls.table.numberOfRows == 2)
    #expect(controls.reload.isEnabled)
    #expect(controls.create.isEnabled)
    #expect(!controls.restore.isEnabled)
    controls.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
    controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification))
    #expect(controls.restore.isEnabled)
    #expect(controls.delete.isEnabled)

    controls.reload.performClick(nil)
    operations.completeList(.failure(SecurityWindowProbeError.hostile))
    #expect(controls.table.numberOfRows == 0)
    #expect(controls.reload.isEnabled)
    #expect(!controls.create.isEnabled)
    #expect(!controls.restore.isEnabled)
    #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
    #expect(controls.status.stringValue == "Backups are unavailable because the authenticated catalog could not be verified.")
}

@MainActor
@Test func backupCreateFailsClosedWithoutCoordinatorAndRestoresControlsAfterAcquireFailure() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let operations = BackupOperationProbe()
    let interactions = BackupInteractionProbe()
    let controller = BackupWindowController(
        operations: operations.operations,
        runtimeVersion: { "1.2.35" },
        interactions: interactions.interactions
    )
    let controls = try backupWindowControls(controller)
    controls.create.performClick(nil)
    #expect(interactions.notices == [.protectedTransitionUnavailable])
    #expect(!controls.create.isEnabled)
    #expect(operations.creates.isEmpty)

    let secondOperations = BackupOperationProbe()
    let secondInteractions = BackupInteractionProbe()
    let second = BackupWindowController(
        operations: secondOperations.operations,
        runtimeVersion: { "1.2.35" },
        interactions: secondInteractions.interactions
    )
    let secondControls = try backupWindowControls(second)
    second.onAcquireProtectedTransition = { operation, completion in
        #expect(operation == .manualCreate)
        completion(.failure(SecurityWindowProbeError.hostile))
    }
    second.onFinishProtectedTransition = { _, _, _, completion in completion() }
    secondControls.create.performClick(nil)
    #expect(secondInteractions.notices == [.acquireFailed(.manualCreate)])
    #expect(secondControls.create.isEnabled)
    #expect(secondControls.reload.isEnabled)
    #expect(secondOperations.creates.isEmpty)
    #expect(!secondControls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
}

@MainActor
@Test func backupCreateKeepsControlsLockedThroughWorkerAndFinishForSuccessAndFailure() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for succeeds in [true, false] {
        let operations = BackupOperationProbe()
        let interactions = BackupInteractionProbe()
        let controller = BackupWindowController(
            operations: operations.operations,
            runtimeVersion: { "runtime-version" },
            interactions: interactions.interactions
        )
        let controls = try backupWindowControls(controller)
        var finishCompletion: (@MainActor () -> Void)?
        var finishResult: Result<Void, Error>?
        controller.onAcquireProtectedTransition = { _, completion in
            completion(.success(StateBackupQuiescencePermit(validation: {})))
        }
        controller.onFinishProtectedTransition = { _, disposition, result, completion in
            #expect(disposition == .restartAndReopen)
            finishResult = result
            finishCompletion = completion
        }
        controls.create.performClick(nil)
        #expect(operations.creates.count == 1)
        #expect(operations.creates[0].label == "Manual backup")
        #expect(operations.creates[0].sourceVersion == "runtime-version")
        #expect(!controls.create.isEnabled)
        #expect(!controls.reload.isEnabled)
        if succeeds {
            operations.creates[0].completion(.success(securityWindowBackup(10)))
        } else {
            operations.creates[0].completion(.failure(SecurityWindowProbeError.hostile))
        }
        #expect(finishCompletion != nil)
        #expect(!controls.create.isEnabled)
        #expect(finishResult?.isSuccess == succeeds)
        finishCompletion?()
        if succeeds {
            #expect(operations.listCompletions.count == 1)
            #expect(!controls.create.isEnabled)
            operations.completeList(.success([securityWindowBackup(10)]))
            #expect(controls.create.isEnabled)
            #expect(interactions.notices.isEmpty)
        } else {
            #expect(operations.listCompletions.isEmpty)
            #expect(controls.create.isEnabled)
            #expect(interactions.notices == [.createFailed])
            #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
        }
    }
}

@MainActor
@Test func backupRestoreCancelAcquireFailureSuccessAndWorkerFailureAreQualified() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scenario in ["cancel", "acquire", "success", "worker"] {
        let operations = BackupOperationProbe()
        let interactions = BackupInteractionProbe()
        interactions.shouldConfirm = scenario != "cancel"
        let controller = BackupWindowController(
            operations: operations.operations,
            runtimeVersion: { "test" },
            interactions: interactions.interactions
        )
        let controls = try backupWindowControls(controller)
        let backup = securityWindowBackup(20)
        controls.reload.performClick(nil)
        operations.completeList(.success([backup]))
        controls.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification))

        var acquireCount = 0
        var finishCompletion: (@MainActor () -> Void)?
        var restoreCallback: StateBackupRestoreReport?
        controller.onAcquireProtectedTransition = { operation, completion in
            acquireCount += 1
            #expect(operation == .restore(backup.id))
            if scenario == "acquire" {
                completion(.failure(SecurityWindowProbeError.hostile))
            } else {
                completion(.success(StateBackupQuiescencePermit(validation: {})))
            }
        }
        controller.onFinishProtectedTransition = { _, disposition, _, completion in
            #expect(disposition == .restartAndReopen)
            finishCompletion = completion
        }
        controller.onRestoreCompleted = { restoreCallback = $0 }
        controls.restore.performClick(nil)
        #expect(interactions.confirmations == [.restore(backup.id)])

        switch scenario {
        case "cancel":
            #expect(acquireCount == 0)
            #expect(operations.restores.isEmpty)
            #expect(controls.restore.isEnabled)
        case "acquire":
            #expect(acquireCount == 1)
            #expect(operations.restores.isEmpty)
            #expect(interactions.notices == [.acquireFailed(.restore(backup.id))])
            #expect(controls.restore.isEnabled)
            #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
        case "success":
            #expect(operations.restores.count == 1)
            #expect(!controls.restore.isEnabled)
            let report = StateBackupRestoreReport(backupID: backup.id, quarantineURL: nil)
            operations.restores[0].completion(.success(report))
            #expect(finishCompletion != nil)
            #expect(restoreCallback == nil)
            #expect(!controls.restore.isEnabled)
            finishCompletion?()
            #expect(restoreCallback == report)
            #expect(operations.listCompletions.count == 1)
            operations.completeList(.success([backup]))
            #expect(!controls.restore.isEnabled) // Refresh intentionally clears the stale selection.
            #expect(interactions.notices.isEmpty)
        default:
            #expect(operations.restores.count == 1)
            operations.restores[0].completion(.failure(SecurityWindowProbeError.hostile))
            #expect(finishCompletion != nil)
            finishCompletion?()
            #expect(restoreCallback == nil)
            #expect(interactions.notices == [.restoreFailed])
            #expect(controls.restore.isEnabled)
            #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
        }
    }
}

@MainActor
@Test func backupDeleteCancelSuccessAndFailureRestoreSafeControlState() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scenario in ["cancel", "success", "failure"] {
        let operations = BackupOperationProbe()
        let interactions = BackupInteractionProbe()
        interactions.shouldConfirm = scenario != "cancel"
        let controller = BackupWindowController(
            operations: operations.operations,
            runtimeVersion: { "test" },
            interactions: interactions.interactions
        )
        let controls = try backupWindowControls(controller)
        let backup = securityWindowBackup(30)
        controls.reload.performClick(nil)
        operations.completeList(.success([backup]))
        controls.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification))
        controls.delete.performClick(nil)
        #expect(interactions.confirmations == [.delete(backup.id)])

        if scenario == "cancel" {
            #expect(operations.deletes.isEmpty)
            #expect(controls.delete.isEnabled)
        } else {
            #expect(operations.deletes.count == 1)
            #expect(!controls.delete.isEnabled)
            if scenario == "success" {
                operations.deletes[0].completion(.success(()))
                #expect(operations.listCompletions.count == 1)
                #expect(!controls.delete.isEnabled)
                operations.completeList(.success([]))
                #expect(controls.create.isEnabled)
                #expect(interactions.notices.isEmpty)
            } else {
                operations.deletes[0].completion(.failure(SecurityWindowProbeError.hostile))
                #expect(operations.listCompletions.isEmpty)
                #expect(controls.delete.isEnabled)
                #expect(interactions.notices == [.deleteFailed])
                #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
            }
        }
    }
}

@MainActor
@Test func backupKeyAuthorizationCancelSuccessFailureAndUnavailableCapabilityAreQualified() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scenario in ["cancel", "success", "failure", "unsupported"] {
        let operations = BackupOperationProbe()
        operations.canAuthorize = scenario != "unsupported"
        let interactions = BackupInteractionProbe()
        interactions.shouldConfirm = scenario != "cancel"
        let controller = BackupWindowController(
            operations: operations.operations,
            runtimeVersion: { "test" },
            interactions: interactions.interactions
        )
        let controls = try backupWindowControls(controller)
        controls.reload.performClick(nil)
        operations.completeList(.failure(BackupError.authenticationAuthorizationRequired))
        #expect(!controls.authorize.isHidden)
        #expect(controls.authorize.isEnabled == (scenario != "unsupported"))
        #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))

        controls.authorize.performClick(nil)
        if scenario == "unsupported" {
            #expect(interactions.confirmations.isEmpty)
            #expect(operations.authorizationCompletions.isEmpty)
        } else {
            #expect(interactions.confirmations == [.authorizeExistingKey])
            if scenario == "cancel" {
                #expect(operations.authorizationCompletions.isEmpty)
                #expect(controls.authorize.isEnabled)
            } else {
                #expect(operations.authorizationCompletions.count == 1)
                #expect(!controls.authorize.isEnabled)
                if scenario == "success" {
                    operations.authorizationCompletions[0](.success(()))
                    #expect(operations.listCompletions.count == 1)
                    #expect(controls.authorize.isHidden)
                    operations.completeList(.success([]))
                    #expect(controls.create.isEnabled)
                    #expect(interactions.notices.isEmpty)
                } else {
                    operations.authorizationCompletions[0](.failure(SecurityWindowProbeError.hostile))
                    #expect(interactions.notices == [.authorizationFailed])
                    #expect(controls.authorize.isHidden)
                    #expect(controls.reload.isEnabled)
                    #expect(!controls.status.stringValue.contains("REMOTE_SECRET_CANARY"))
                }
            }
        }
    }
}

@MainActor
private func backupWindowControls(_ controller: BackupWindowController) throws -> BackupWindowControls {
    let views = try securityWindowViews(controller)
    return BackupWindowControls(
        reload: try securityWindowButton("Reload", in: views),
        create: try securityWindowButton("Create Backup", in: views),
        authorize: try securityWindowButton("Authorize Backup Key…", in: views),
        delete: try securityWindowButton("Delete Selected…", in: views),
        restore: try securityWindowButton("Restore Selected…", in: views),
        table: try #require(views.compactMap { $0 as? NSTableView }.first),
        status: try #require(views.compactMap { $0 as? NSTextField }.first),
        privacyDisclosure: try #require(
            views.compactMap { $0 as? NSTextField }
                .first { $0.accessibilityLabel() == "Backup privacy and protection" }
        )
    )
}

@MainActor
private func securityWindowViews(_ controller: NSWindowController) throws -> [NSView] {
    let root = try #require(controller.window?.contentViewController?.view)
    return [root] + securityWindowDescendants(of: root)
}

@MainActor
private func securityWindowDescendants(of view: NSView) -> [NSView] {
    view.subviews.flatMap { [$0] + securityWindowDescendants(of: $0) }
}

@MainActor
private func securityWindowButton(_ title: String, in views: [NSView]) throws -> NSButton {
    try #require(views.compactMap { $0 as? NSButton }.first { $0.title == title })
}

private func securityWindowBackup(_ suffix: UInt8) -> StateBackup {
    let bytes: uuid_t = (
        0, 0, 0, 0,
        0, 0,
        0, 0,
        0, 0, 0, 0, 0, 0, 0, suffix
    )
    let id = UUID(uuid: bytes)
    return StateBackup(
        id: id,
        createdAt: Date(timeIntervalSince1970: TimeInterval(suffix)),
        label: "Backup \(suffix)",
        sourceVersion: "test",
        path: "/private/tmp/fulmar-test-\(id.uuidString)"
    )
}

private extension Result where Success == Void {
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}
