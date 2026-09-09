import AppKit
import Testing
@testable import LocalHarness

private struct KnowledgeWindowHostileError: LocalizedError {
    let errorDescription: String? = "secret-token=/Users/alice/private/knowledge.txt"
}

@MainActor
private final class KnowledgeOperationsProbe {
    typealias QueryCompletion = @MainActor (Result<KnowledgeCenterQueryPayload, Error>) -> Void
    typealias DetailCompletion = @MainActor (Result<String, Error>) -> Void
    typealias NoteCompletion = @MainActor (Result<KnowledgeMemoryNote, Error>) -> Void
    typealias SaveCompletion = @MainActor (Result<KnowledgeDocumentDescriptor, Error>) -> Void
    typealias ImportCompletion = @MainActor (Result<KnowledgeCenterImportOutcome, Error>) -> Void
    typealias RemoveCompletion = @MainActor (Result<KnowledgeDocumentDescriptor, Error>) -> Void
    typealias ClearCompletion = @MainActor (Result<Int, Error>) -> Void
    typealias ExportCompletion = @MainActor (Result<Void, Error>) -> Void

    struct QueryCall {
        let text: String
        let filter: KnowledgeScopeFilter
        let completion: QueryCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct DetailCall {
        let descriptor: KnowledgeDocumentDescriptor
        let chunk: Int
        let completion: DetailCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct NoteCall {
        let id: UUID
        let completion: NoteCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct SaveCall {
        let existing: KnowledgeMemoryNote?
        let draft: KnowledgeMemoryDraft
        let completion: SaveCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct ImportCall {
        let urls: [URL]
        let scope: KnowledgeScope
        let completion: ImportCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct RemoveCall {
        let id: UUID
        let completion: RemoveCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct ClearCall {
        let scope: KnowledgeScope
        let completion: ClearCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }
    struct ExportCall {
        let destination: URL
        let completion: ExportCompletion
        let cancellation: KnowledgeCenterOperationCancellation
    }

    var availability: LocalKnowledgeStoreAvailability = .ready
    var recovery = KnowledgeRecoveryReport()
    var storage = URL(fileURLWithPath: "/private/var/folders/fulmar-knowledge")
    var statusHandler: (@Sendable (LocalKnowledgeStoreStatus) -> Void)?
    var loads: [Bool] = []
    var maintenanceRetries = 0
    var queries: [QueryCall] = []
    var details: [DetailCall] = []
    var notes: [NoteCall] = []
    var saves: [SaveCall] = []
    var imports: [ImportCall] = []
    var removals: [RemoveCall] = []
    var clears: [ClearCall] = []
    var exports: [ExportCall] = []

    func makeOperations() -> KnowledgeCenterOperations {
        KnowledgeCenterOperations(
            availability: { self.availability },
            recoveryReport: { self.recovery },
            storageDirectory: { self.storage },
            setStatusHandler: { self.statusHandler = $0 },
            load: { self.loads.append($0) },
            retryDeferredMaintenance: { self.maintenanceRetries += 1 },
            query: { text, filter, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.queries.append(.init(text: text, filter: filter, completion: completion, cancellation: cancellation))
                return cancellation
            },
            detail: { descriptor, chunk, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.details.append(.init(descriptor: descriptor, chunk: chunk, completion: completion, cancellation: cancellation))
                return cancellation
            },
            memoryNote: { id, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.notes.append(.init(id: id, completion: completion, cancellation: cancellation))
                return cancellation
            },
            save: { existing, draft, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.saves.append(.init(existing: existing, draft: draft, completion: completion, cancellation: cancellation))
                return cancellation
            },
            importFiles: { urls, scope, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.imports.append(.init(urls: urls, scope: scope, completion: completion, cancellation: cancellation))
                return cancellation
            },
            remove: { id, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.removals.append(.init(id: id, completion: completion, cancellation: cancellation))
                return cancellation
            },
            clear: { scope, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.clears.append(.init(scope: scope, completion: completion, cancellation: cancellation))
                return cancellation
            },
            export: { destination, completion in
                let cancellation = KnowledgeCenterOperationCancellation()
                self.exports.append(.init(destination: destination, completion: completion, cancellation: cancellation))
                return cancellation
            }
        )
    }

    func publishStatus() {
        statusHandler?(LocalKnowledgeStoreStatus(availability: availability, recoveryReport: recovery))
    }
}

@MainActor
private final class KnowledgeInteractionsProbe {
    var importChoices: [@MainActor ([URL]?) -> Void] = []
    var exportChoices: [@MainActor (URL?) -> Void] = []
    var confirmations: [(KnowledgeCenterConfirmation, @MainActor (Bool) -> Void)] = []
    var notices: [KnowledgeCenterNotice] = []

    func makeInteractions() -> KnowledgeCenterInteractions {
        KnowledgeCenterInteractions(
            beginNoteEditor: { _, _ in },
            endNoteEditor: { _, _ in },
            chooseImportFiles: { _, completion in self.importChoices.append(completion) },
            chooseExportDestination: { _, completion in self.exportChoices.append(completion) },
            confirm: { confirmation, _, completion in self.confirmations.append((confirmation, completion)) },
            presentNotice: { notice, _ in self.notices.append(notice) }
        )
    }
}

@MainActor
private struct KnowledgeWindowFixture {
    let operations = KnowledgeOperationsProbe()
    let interactions = KnowledgeInteractionsProbe()
    let controller: KnowledgeCenterWindowController

    init(
        projects: [KnowledgeProjectOption] = [KnowledgeProjectOption(id: "project-1", displayName: "Project One")],
        displayPolicy: NativeAccessibilityDisplayPolicy = .fixed()
    ) {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        controller = KnowledgeCenterWindowController(
            operations: operations.makeOperations(),
            projects: projects,
            interactions: interactions.makeInteractions(),
            displayPolicy: displayPolicy
        )
    }

    var root: NSView { controller.window!.contentViewController!.view }
    var views: [NSView] { knowledgeDescendants(of: root) }
    var table: NSTableView { views.compactMap { $0 as? NSTableView }.first! }
    var detail: NSTextView { textView(label: "Selected knowledge context") }

    func button(_ title: String) -> NSButton {
        views.compactMap { $0 as? NSButton }.first { $0.title == title }!
    }

    func popup(_ label: String) -> NSPopUpButton {
        views.compactMap { $0 as? NSPopUpButton }.first { $0.accessibilityLabel() == label }!
    }

    func textField(label: String) -> NSTextField {
        views.compactMap { $0 as? NSTextField }.first { $0.accessibilityLabel() == label }!
    }

    func textView(label: String) -> NSTextView {
        views.compactMap { $0 as? NSTextView }.first { $0.accessibilityLabel() == label }!
    }

    func completeQuery(_ descriptors: [KnowledgeDocumentDescriptor], at index: Int? = nil) {
        let call = operations.queries[index ?? operations.queries.count - 1]
        call.completion(.success(.init(all: descriptors, documents: descriptors, results: [])))
    }
}

@MainActor
@Test func knowledgeLoadingIndicatorHonorsInjectedMotionPolicy() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for reducesMotion in [false, true] {
        let fixture = KnowledgeWindowFixture(
            displayPolicy: .fixed(reduceMotion: reducesMotion)
        )
        let spinner = try #require(
            fixture.views.compactMap { $0 as? NSProgressIndicator }.first
        )

        fixture.controller.refresh()
        #expect(spinner.isHidden == reducesMotion)

        fixture.completeQuery([])
        #expect(spinner.isHidden)
    }
}

@MainActor
@Test func knowledgeLoadingIndicatorRespondsToLiveAccessibilityNotification() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    final class PreferenceState { var reducesMotion = false }
    let state = PreferenceState()
    let fixture = KnowledgeWindowFixture(displayPolicy: NativeAccessibilityDisplayPolicy(
        reduceMotion: { state.reducesMotion },
        reduceTransparency: { false }
    ))
    let spinner = try #require(
        fixture.views.compactMap { $0 as? NSProgressIndicator }.first
    )

    fixture.controller.refresh()
    #expect(!spinner.isHidden)

    state.reducesMotion = true
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(spinner.isHidden)

    state.reducesMotion = false
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(!spinner.isHidden)

    fixture.completeQuery([])
    state.reducesMotion = true
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(spinner.isHidden)
}

@MainActor
@Test func knowledgeReloadPreservesSelectionAndRejectsStaleQueryAndDetailResults() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let first = knowledgeDescriptor(title: "First")
    let second = knowledgeDescriptor(title: "Second")

    fixture.controller.refresh()
    fixture.controller.refresh()
    #expect(fixture.operations.queries.count == 2)
    #expect(fixture.operations.queries[0].cancellation.isCancelled)
    fixture.completeQuery([first, second])
    #expect(fixture.table.numberOfRows == 2)

    fixture.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    let secondDetail = fixture.operations.details.last!
    fixture.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    let firstDetail = fixture.operations.details.last!
    #expect(secondDetail.cancellation.isCancelled)
    firstDetail.completion(.success("latest visible detail"))
    secondDetail.completion(.success("stale secret-token detail"))
    #expect(fixture.detail.string == "latest visible detail")

    fixture.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    fixture.operations.details.last?.completion(.failure(KnowledgeWindowHostileError()))
    #expect(fixture.detail.string == KnowledgeCenterFailure.detail.message)
    #expect(!fixture.detail.string.contains("secret-token"))

    fixture.controller.refresh()
    fixture.completeQuery([second, first])
    #expect(fixture.table.selectedRow == 0)
    #expect(fixture.operations.details.last?.descriptor.id == second.id)

    fixture.operations.queries[0].completion(.failure(KnowledgeWindowHostileError()))
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))

    fixture.controller.refresh()
    fixture.operations.queries.last?.completion(.failure(KnowledgeWindowHostileError()))
    #expect(knowledgeVisibleText(fixture.root).contains(KnowledgeCenterFailure.query.message))
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))
}

@MainActor
@Test func knowledgeScopeSearchUnavailableRetryMaintenanceAndStorageControlsAreRealAndBounded() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let popup = fixture.popup("Knowledge scope")
    let projectItem = try #require(popup.itemArray.first { ($0.representedObject as? String) == "project-1" })
    popup.select(projectItem)
    _ = NSApp.sendAction(try #require(popup.action), to: popup.target, from: popup)
    #expect(fixture.operations.queries.last?.filter == .project("project-1", includeGlobal: true))

    let includeGlobal = fixture.button("Include global memory")
    includeGlobal.state = .off
    _ = NSApp.sendAction(try #require(includeGlobal.action), to: includeGlobal.target, from: includeGlobal)
    #expect(fixture.operations.queries.last?.filter == .project("project-1", includeGlobal: false))

    let search = fixture.views.compactMap { $0 as? NSSearchField }.first!
    search.stringValue = "private phrase"
    fixture.controller.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: search))
    try await Task.sleep(for: .milliseconds(250))
    #expect(fixture.operations.queries.last?.text == "private phrase")

    fixture.operations.availability = .unavailable("secret-token=/private/path")
    fixture.operations.publishStatus()
    await Task.yield()
    for title in ["New Memory", "Import Files…", "Export Metadata…", "Clear Project One…", "Edit Memory", "Remove…"] {
        #expect(!fixture.button(title).isEnabled, Comment(rawValue: title))
    }
    #expect(fixture.button("Show Storage").isEnabled)
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))
    fixture.button("Try Again").performClick(nil)
    #expect(fixture.operations.loads == [true])

    var opened: [URL] = []
    fixture.controller.onOpenStorage = { opened.append($0) }
    fixture.button("Show Storage").performClick(nil)
    #expect(opened == [fixture.operations.storage])

    fixture.operations.availability = .ready
    fixture.operations.recovery.trashCleanupIssue = "secret-token=/private/trash"
    fixture.controller.refresh()
    fixture.completeQuery([])
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))
    fixture.button("Retry Cleanup").performClick(nil)
    #expect(fixture.operations.maintenanceRetries == 1)
}

@MainActor
@Test func knowledgeImportCancelSuccessFailureBusyAndDuplicateCallbacksAreSafe() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    fixture.controller.refresh()
    fixture.completeQuery([])
    let importButton = fixture.button("Import Files…")

    importButton.performClick(nil)
    #expect(fixture.interactions.importChoices.count == 1)
    assertKnowledgeMutationControls(fixture, enabled: false)
    fixture.interactions.importChoices[0](nil)
    fixture.interactions.importChoices[0]([URL(fileURLWithPath: "/ignored")])
    #expect(fixture.operations.imports.isEmpty)
    assertKnowledgeMutationControls(fixture, enabled: true)

    importButton.performClick(nil)
    let source = URL(fileURLWithPath: "/tmp/fixture.md")
    fixture.interactions.importChoices[1]([source])
    importButton.performClick(nil)
    #expect(fixture.interactions.importChoices.count == 2)
    #expect(fixture.operations.imports.count == 1)
    #expect(fixture.operations.imports[0].urls == [source])
    assertKnowledgeMutationControls(fixture, enabled: false)

    let imported = knowledgeDescriptor(title: "Imported", kind: .markdown)
    var changes = 0
    fixture.controller.onKnowledgeChanged = { _ in changes += 1 }
    fixture.operations.imports[0].completion(.success(.init(imported: [imported], failedCount: 1)))
    fixture.operations.imports[0].completion(.success(.init(imported: [imported], failedCount: 0)))
    #expect(changes == 1)
    #expect(fixture.interactions.notices == [.importCompleted(imported: 1, failed: 1)])

    fixture.completeQuery([imported])
    importButton.performClick(nil)
    fixture.interactions.importChoices[2]([source])
    fixture.operations.imports[1].completion(.failure(KnowledgeWindowHostileError()))
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))
    #expect(knowledgeVisibleText(fixture.root).contains(KnowledgeCenterFailure.importing.message))
    assertKnowledgeMutationControls(fixture, enabled: true)
}

@MainActor
@Test func knowledgeExportCancelSuccessFailureAndNoticesAreDeterministic() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let descriptor = knowledgeDescriptor(title: "Memory")
    fixture.controller.refresh()
    fixture.completeQuery([descriptor])
    let button = fixture.button("Export Metadata…")

    button.performClick(nil)
    fixture.interactions.exportChoices[0](nil)
    fixture.interactions.exportChoices[0](URL(fileURLWithPath: "/tmp/ignored.json"))
    #expect(fixture.operations.exports.isEmpty)

    let destination = URL(fileURLWithPath: "/tmp/knowledge.json")
    button.performClick(nil)
    fixture.interactions.exportChoices[1](destination)
    button.performClick(nil)
    #expect(fixture.interactions.exportChoices.count == 2)
    #expect(fixture.operations.exports[0].destination == destination)
    fixture.operations.exports[0].completion(.success(()))
    fixture.operations.exports[0].completion(.failure(KnowledgeWindowHostileError()))
    #expect(fixture.interactions.notices == [.exportSucceeded])

    button.performClick(nil)
    fixture.interactions.exportChoices[2](destination)
    fixture.operations.exports[1].completion(.failure(KnowledgeWindowHostileError()))
    #expect(knowledgeVisibleText(fixture.root).contains(KnowledgeCenterFailure.export.message))
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))
}

@MainActor
@Test func knowledgeRemoveAndClearConfirmCancelSuccessFailureAndDuplicateResponsesAreSafe() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let descriptor = knowledgeDescriptor(title: "Memory")
    fixture.controller.refresh()
    fixture.completeQuery([descriptor])
    let remove = fixture.button("Remove…")

    remove.performClick(nil)
    #expect(fixture.interactions.confirmations.first?.0 == .remove(id: descriptor.id, title: descriptor.title))
    fixture.interactions.confirmations[0].1(false)
    fixture.interactions.confirmations[0].1(true)
    #expect(fixture.operations.removals.isEmpty)

    remove.performClick(nil)
    fixture.interactions.confirmations[1].1(true)
    remove.performClick(nil)
    #expect(fixture.interactions.confirmations.count == 2)
    fixture.operations.removals[0].completion(.failure(KnowledgeWindowHostileError()))
    #expect(knowledgeVisibleText(fixture.root).contains(KnowledgeCenterFailure.removal.message))
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))

    remove.performClick(nil)
    fixture.interactions.confirmations[2].1(true)
    var changes = 0
    fixture.controller.onKnowledgeChanged = { _ in changes += 1 }
    fixture.operations.removals[1].completion(.success(descriptor))
    fixture.operations.removals[1].completion(.success(descriptor))
    #expect(changes == 1)
    fixture.completeQuery([descriptor])

    let clear = fixture.button("Clear Global Memory…")
    clear.performClick(nil)
    fixture.interactions.confirmations[3].1(false)
    #expect(fixture.operations.clears.isEmpty)
    clear.performClick(nil)
    fixture.interactions.confirmations[4].1(true)
    fixture.operations.clears[0].completion(.failure(KnowledgeWindowHostileError()))
    #expect(knowledgeVisibleText(fixture.root).contains(KnowledgeCenterFailure.clearing.message))
    clear.performClick(nil)
    fixture.interactions.confirmations[5].1(true)
    fixture.operations.clears[1].completion(.success(1))
    fixture.operations.clears[1].completion(.success(1))
    #expect(changes == 2)
}

@MainActor
@Test func knowledgeNewMemoryValidatesFailsClosedRetriesAndIgnoresDuplicateSave() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    fixture.controller.refresh()
    fixture.completeQuery([])
    fixture.button("New Memory").performClick(nil)
    let editor = try #require(fixture.controller.noteEditor)
    let editorRoot = try #require(editor.window?.contentViewController?.view)
    let editorViews = knowledgeDescendants(of: editorRoot)
    let title = try #require(editorViews.compactMap { $0 as? NSTextField }.first { $0.accessibilityLabel() == "Memory title" })
    let body = try #require(editorViews.compactMap { $0 as? NSTextView }.first { $0.accessibilityLabel() == "Memory text" })
    let save = knowledgeButton("Save Memory", in: editorViews)
    let cancel = knowledgeButton("Cancel", in: editorViews)
    assertKnowledgeMutationControls(fixture, enabled: false)

    save.performClick(nil)
    #expect(fixture.operations.saves.isEmpty)
    #expect(knowledgeVisibleText(editorRoot).contains("Enter a title"))
    title.stringValue = "  Private plan  "
    save.performClick(nil)
    #expect(fixture.operations.saves.isEmpty)
    #expect(knowledgeVisibleText(editorRoot).contains("Enter some text"))
    body.string = "  Durable text  "
    save.performClick(nil)
    save.performClick(nil)
    #expect(fixture.operations.saves.count == 1)
    #expect(fixture.operations.saves[0].draft.title == "Private plan")
    #expect(fixture.operations.saves[0].draft.text == "Durable text")
    #expect(!cancel.isEnabled)

    fixture.operations.saves[0].completion(.failure(KnowledgeWindowHostileError()))
    fixture.operations.saves[0].completion(.success(knowledgeDescriptor(title: "Ignored")))
    #expect(fixture.controller.noteEditor === editor)
    #expect(knowledgeVisibleText(editorRoot).contains(KnowledgeCenterFailure.save.message))
    #expect(!knowledgeVisibleText(editorRoot).contains("secret-token"))
    #expect(save.isEnabled && cancel.isEnabled)

    save.performClick(nil)
    let saved = knowledgeDescriptor(title: "Private plan")
    var changes = 0
    fixture.controller.onKnowledgeChanged = { _ in changes += 1 }
    fixture.operations.saves[1].completion(.success(saved))
    fixture.operations.saves[1].completion(.success(saved))
    #expect(fixture.controller.noteEditor == nil)
    #expect(changes == 1)
}

@MainActor
@Test func knowledgeMemoryEditorCancelCloseAndEditFailureSuccessRestoreState() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let descriptor = knowledgeDescriptor(title: "Editable")
    fixture.controller.refresh()
    fixture.completeQuery([descriptor])

    fixture.button("New Memory").performClick(nil)
    let newEditor = try #require(fixture.controller.noteEditor)
    let newViews = knowledgeDescendants(of: try #require(newEditor.window?.contentViewController?.view))
    knowledgeButton("Cancel", in: newViews).performClick(nil)
    #expect(fixture.controller.noteEditor == nil)
    assertKnowledgeMutationControls(fixture, enabled: true)

    fixture.button("Edit Memory").performClick(nil)
    fixture.button("Edit Memory").performClick(nil)
    #expect(fixture.operations.notes.count == 1)
    fixture.operations.notes[0].completion(.failure(KnowledgeWindowHostileError()))
    #expect(knowledgeVisibleText(fixture.root).contains(KnowledgeCenterFailure.edit.message))
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))
    assertKnowledgeMutationControls(fixture, enabled: true)

    fixture.button("Edit Memory").performClick(nil)
    fixture.operations.notes[1].completion(.success(.init(descriptor: descriptor, text: "Existing body")))
    let editor = try #require(fixture.controller.noteEditor)
    let editorRoot = try #require(editor.window?.contentViewController?.view)
    #expect(knowledgeVisibleText(editorRoot).contains("Editable"))
    #expect(knowledgeVisibleText(editorRoot).contains("Existing body"))
    knowledgeButton("Cancel", in: knowledgeDescendants(of: editorRoot)).performClick(nil)
    #expect(fixture.controller.noteEditor == nil)
    assertKnowledgeMutationControls(fixture, enabled: true)
}

@MainActor
@Test func knowledgeImportedItemsCannotInvokeEditByButtonOrDoubleClick() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let imported = knowledgeDescriptor(title: "Imported", kind: .markdown)
    fixture.controller.refresh()
    fixture.completeQuery([imported])
    #expect(!fixture.button("Edit Memory").isEnabled)
    fixture.button("Edit Memory").performClick(nil)
    _ = NSApp.sendAction(try #require(fixture.table.doubleAction), to: fixture.table.target, from: fixture.table)
    #expect(fixture.operations.notes.isEmpty)
}

@MainActor
@Test func knowledgeUnavailableTransitionCancelsChooserAndSaveWhilePreservingDraft() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    fixture.controller.showWindow(nil)
    defer {
        fixture.controller.windowWillClose(
            Notification(name: NSWindow.willCloseNotification, object: fixture.controller.window)
        )
        fixture.controller.window?.orderOut(nil)
    }
    fixture.completeQuery([])

    fixture.button("Import Files…").performClick(nil)
    let chooser = fixture.interactions.importChoices[0]
    fixture.operations.availability = .unavailable("secret-token=/private/store")
    fixture.operations.publishStatus()
    await Task.yield()
    chooser([URL(fileURLWithPath: "/tmp/stale.md")])
    #expect(fixture.operations.imports.isEmpty)
    #expect(fixture.button("Show Storage").isEnabled)
    #expect(!knowledgeVisibleText(fixture.root).contains("secret-token"))

    fixture.operations.availability = .ready
    fixture.operations.publishStatus()
    await Task.yield()
    fixture.completeQuery([])
    fixture.button("New Memory").performClick(nil)
    let editor = try #require(fixture.controller.noteEditor)
    let editorRoot = try #require(editor.window?.contentViewController?.view)
    let editorViews = knowledgeDescendants(of: editorRoot)
    let title = try #require(editorViews.compactMap { $0 as? NSTextField }.first { $0.accessibilityLabel() == "Memory title" })
    let body = try #require(editorViews.compactMap { $0 as? NSTextView }.first { $0.accessibilityLabel() == "Memory text" })
    let save = knowledgeButton("Save Memory", in: editorViews)
    title.stringValue = "Preserved draft"
    body.string = "This text must remain visible."
    save.performClick(nil)
    let staleSave = fixture.operations.saves[0]
    #expect(!save.isEnabled)

    fixture.operations.availability = .unavailable("secret-token=/private/store")
    fixture.operations.publishStatus()
    await Task.yield()
    #expect(staleSave.cancellation.isCancelled)
    #expect(save.isEnabled)
    #expect(body.string == "This text must remain visible.")
    #expect(knowledgeVisibleText(editorRoot).contains("draft remains open"))
    staleSave.completion(.success(knowledgeDescriptor(title: "Stale")))
    #expect(fixture.controller.noteEditor === editor)

    fixture.operations.availability = .ready
    fixture.operations.publishStatus()
    await Task.yield()
    save.performClick(nil)
    #expect(fixture.operations.saves.count == 2)
    fixture.operations.saves[1].completion(.success(knowledgeDescriptor(title: "Preserved draft")))
    #expect(fixture.controller.noteEditor == nil)
}

@MainActor
@Test func knowledgeCloseCancelsPendingWorkIgnoresLateResultsAndReopenRefreshes() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    fixture.controller.showWindow(nil)
    let firstQuery = fixture.operations.queries[0]
    fixture.button("Import Files…").performClick(nil)
    let chooser = fixture.interactions.importChoices[0]
    fixture.controller.window?.performClose(nil)
    #expect(firstQuery.cancellation.isCancelled)
    chooser([URL(fileURLWithPath: "/tmp/stale.md")])
    #expect(fixture.operations.imports.isEmpty)
    fixture.controller.showWindow(nil)
    #expect(fixture.operations.queries.count == 2)
    fixture.operations.queries[0].completion(.success(.init(all: [knowledgeDescriptor(title: "Stale")], documents: [], results: [])))
    #expect(fixture.table.numberOfRows == 0)
}

@MainActor
@Test func knowledgeControlsAreAccessibleWiredAndFitDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = KnowledgeWindowFixture()
    let window = try #require(fixture.controller.window)
    window.setContentSize(NSSize(width: window.minSize.width, height: window.minSize.height))
    window.layoutIfNeeded()
    #expect(fixture.table.accessibilityLabel() == "Knowledge library and ranked search results")
    #expect(fixture.table.target === fixture.controller)
    #expect(fixture.table.doubleAction != nil)
    #expect(fixture.popup("Knowledge scope").action != nil)
    for title in ["New Memory", "Import Files…", "Export Metadata…", "Clear Global Memory…", "Show Storage", "Edit Memory", "Remove…", "Try Again", "Retry Cleanup"] {
        let button = fixture.button(title)
        #expect(button.target != nil, Comment(rawValue: title))
        #expect(button.action != nil, Comment(rawValue: title))
    }
    let root = fixture.root
    #expect(root.fittingSize.width <= window.contentLayoutRect.width + 1)
    #expect(root.fittingSize.height <= window.contentLayoutRect.height + 1)
}

private func knowledgeDescriptor(
    id: UUID = UUID(),
    title: String,
    kind: KnowledgeSourceKind = .memoryNote,
    scope: KnowledgeScope = .global
) -> KnowledgeDocumentDescriptor {
    KnowledgeDocumentDescriptor(
        id: id,
        scope: scope,
        sourceKind: kind,
        title: title,
        sourceName: kind == .memoryNote ? nil : "fixture.md",
        sourceSHA256: String(repeating: "a", count: 64),
        contentSHA256: String(repeating: "b", count: 64),
        createdAt: Date(timeIntervalSince1970: 1_700_000_000),
        updatedAt: Date(timeIntervalSince1970: 1_700_000_100),
        characterCount: 12,
        utf8ByteCount: 12,
        chunkCount: 1
    )
}

@MainActor
private func assertKnowledgeMutationControls(_ fixture: KnowledgeWindowFixture, enabled: Bool) {
    for title in ["New Memory", "Import Files…", "Show Storage"] {
        #expect(fixture.button(title).isEnabled == enabled, Comment(rawValue: title))
    }
    #expect(fixture.popup("Knowledge scope").isEnabled == enabled)
    #expect(fixture.views.compactMap { $0 as? NSSearchField }.first?.isEnabled == enabled)
    #expect(fixture.table.isEnabled == enabled)
    if !enabled {
        for title in ["Edit Memory", "Remove…", "Export Metadata…", "Clear Global Memory…", "Clear Project One…"] {
            if let button = fixture.views.compactMap({ $0 as? NSButton }).first(where: { $0.title == title }) {
                #expect(!button.isEnabled, Comment(rawValue: title))
            }
        }
        if let includeGlobal = fixture.views.compactMap({ $0 as? NSButton }).first(where: { $0.title == "Include global memory" }) {
            #expect(!includeGlobal.isEnabled)
        }
    }
}

private func knowledgeButton(_ title: String, in views: [NSView]) -> NSButton {
    views.compactMap { $0 as? NSButton }.first { $0.title == title }!
}

private func knowledgeVisibleText(_ root: NSView) -> String {
    knowledgeDescendants(of: root).compactMap { view -> String? in
        guard !view.isHidden else { return nil }
        if let field = view as? NSTextField { return field.stringValue }
        if let text = view as? NSTextView { return text.string }
        return nil
    }.joined(separator: "\n")
}

private func knowledgeDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(knowledgeDescendants(of:))
}
