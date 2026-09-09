import AppKit
import Testing
@testable import LocalHarness

private struct ArtifactPluginHostileError: LocalizedError {
    let errorDescription: String? = "secret-token=/Users/alice/private/plugin.json"
}

@MainActor
private final class ArtifactOperationsProbe {
    typealias ReadCompletion = @MainActor (Result<String, Error>) -> Void
    typealias WriteCompletion = @MainActor (Result<Void, Error>) -> Void

    struct ReadCall {
        let artifact: URL
        let completion: ReadCompletion
        let cancellation: ArtifactPreviewOperationCancellation
    }
    struct WriteCall {
        let note: String
        let artifact: URL
        let completion: WriteCompletion
        let cancellation: ArtifactPreviewOperationCancellation
    }

    var reads: [ReadCall] = []
    var writes: [WriteCall] = []

    func operations() -> ArtifactPreviewOperations {
        ArtifactPreviewOperations(
            read: { artifact, completion in
                let cancellation = ArtifactPreviewOperationCancellation()
                self.reads.append(.init(artifact: artifact, completion: completion, cancellation: cancellation))
                return cancellation
            },
            write: { note, artifact, completion in
                let cancellation = ArtifactPreviewOperationCancellation()
                self.writes.append(.init(note: note, artifact: artifact, completion: completion, cancellation: cancellation))
                return cancellation
            }
        )
    }
}

@MainActor
private final class ArtifactInteractionsProbe {
    var reveals: [(URL, @MainActor (Result<Void, Error>) -> Void)] = []
    var comparisonChoices: [(String, @MainActor (Result<URL?, Error>) -> Void)] = []
    var comparisons: [(URL, URL)] = []
    var failures: [ArtifactPreviewFailure] = []
    var verifiedCloseRequests = 0

    func interactions() -> ArtifactPreviewInteractions {
        ArtifactPreviewInteractions(
            reveal: { artifact, completion in self.reveals.append((artifact, completion)) },
            chooseComparison: { _, safeName, completion in self.comparisonChoices.append((safeName, completion)) },
            presentComparison: { left, right, _ in
                self.comparisons.append((left, right))
                return NSWindowController(window: NSWindow())
            },
            presentFailure: { failure, _ in self.failures.append(failure) },
            requestVerifiedClose: { _ in self.verifiedCloseRequests += 1 }
        )
    }
}

@MainActor
private struct ArtifactWindowFixture {
    let artifact: URL
    let operations = ArtifactOperationsProbe()
    let interactions = ArtifactInteractionsProbe()
    let controller: ArtifactPreviewWindowController

    init(name: String = "artifact.pdf") {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        artifact = URL(fileURLWithPath: "/tmp/\(name)")
        controller = ArtifactPreviewWindowController(
            artifact: artifact,
            operations: operations.operations(),
            interactions: interactions.interactions(),
            previewFactory: makeArtifactPreviewTestView
        )
    }

    var root: NSView { controller.window!.contentViewController!.view }
    var views: [NSView] { artifactPluginDescendants(root) }
    var notes: NSTextView {
        views.compactMap { $0 as? NSTextView }.first { $0.accessibilityLabel() == "Artifact notes" }!
    }
    var status: NSTextField {
        views.compactMap { $0 as? NSTextField }.first { $0.accessibilityLabel() == "Artifact note status" }!
    }
    func button(_ title: String) -> NSButton {
        views.compactMap { $0 as? NSButton }.first { $0.title == title }!
    }
}

@MainActor
@Test func artifactLoadRetryFailureStaleDuplicateCloseAndReopenAreSafe() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = ArtifactWindowFixture()
    fixture.controller.prepareNoteForPresentation()
    #expect(fixture.operations.reads.count == 1)
    #expect(!fixture.notes.isEditable)

    fixture.controller.prepareNoteForPresentation()
    #expect(fixture.operations.reads.count == 2)
    #expect(fixture.operations.reads[0].cancellation.isCancelled)
    fixture.operations.reads[1].completion(.failure(ArtifactPluginHostileError()))
    fixture.operations.reads[1].completion(.success("stale duplicate"))
    #expect(fixture.interactions.failures == [.loadNote])
    #expect(fixture.status.stringValue == ArtifactPreviewFailure.loadNote.message)
    #expect(!artifactPluginVisibleText(fixture.root).contains("secret-token"))
    #expect(!fixture.notes.isEditable)

    fixture.button("Retry Note Load").performClick(nil)
    #expect(fixture.operations.reads.count == 3)
    fixture.operations.reads[2].completion(.success(String(repeating: "x", count: ArtifactAnnotationStore.maximumNoteBytes + 1)))
    #expect(fixture.interactions.failures == [.loadNote, .loadNote])
    fixture.button("Retry Note Load").performClick(nil)
    fixture.operations.reads[3].completion(.success("latest private note"))
    fixture.operations.reads[0].completion(.success("stale old note"))
    #expect(fixture.notes.string == "latest private note")
    #expect(fixture.notes.isEditable)

    fixture.controller.prepareNoteForPresentation()
    let closingRead = fixture.operations.reads.last!
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: fixture.controller.window))
    #expect(closingRead.cancellation.isCancelled)
    closingRead.completion(.success("resurrected after close"))
    #expect(fixture.notes.string != "resurrected after close")
    fixture.controller.prepareNoteForPresentation()
    #expect(fixture.operations.reads.count == 6)
    fixture.operations.reads.last?.completion(.success("reopened note"))
    #expect(fixture.notes.string == "reopened note")
}

@MainActor
@Test func artifactDirtyCloseSavesAsynchronouslyFailsClosedCancelsAndClosesOnlyAfterSuccess() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = ArtifactWindowFixture()
    fixture.controller.prepareNoteForPresentation()
    fixture.operations.reads[0].completion(.success("original"))
    fixture.notes.string = "edited private note"
    fixture.controller.textDidChange(Notification(name: NSText.didChangeNotification, object: fixture.notes))
    let window = try #require(fixture.controller.window)

    #expect(!fixture.controller.windowShouldClose(window))
    #expect(fixture.operations.writes.count == 1)
    #expect(fixture.operations.writes[0].note == "edited private note")
    #expect(!fixture.notes.isEditable)
    #expect(!fixture.button("Cancel Save").isHidden)
    #expect(!fixture.controller.windowShouldClose(window))
    #expect(fixture.operations.writes.count == 1)

    fixture.operations.writes[0].completion(.failure(ArtifactPluginHostileError()))
    fixture.operations.writes[0].completion(.success(()))
    #expect(fixture.interactions.failures == [.saveNote])
    #expect(fixture.interactions.verifiedCloseRequests == 0)
    #expect(fixture.notes.isEditable)
    #expect(fixture.notes.string == "edited private note")
    #expect(!artifactPluginVisibleText(fixture.root).contains("secret-token"))

    #expect(!fixture.controller.windowShouldClose(window))
    let cancelled = fixture.operations.writes[1]
    fixture.button("Cancel Save").performClick(nil)
    #expect(cancelled.cancellation.isCancelled)
    cancelled.completion(.success(()))
    #expect(fixture.interactions.verifiedCloseRequests == 0)
    #expect(fixture.notes.isEditable)

    #expect(!fixture.controller.windowShouldClose(window))
    fixture.operations.writes[2].completion(.success(()))
    fixture.operations.writes[2].completion(.success(()))
    #expect(fixture.interactions.verifiedCloseRequests == 1)
    #expect(fixture.controller.windowShouldClose(window))
}

@MainActor
@Test func artifactNoteByteBoundRejectsOversizeWithoutStartingSave() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = ArtifactWindowFixture()
    fixture.controller.prepareNoteForPresentation()
    fixture.operations.reads[0].completion(.success(""))
    let oversized = String(repeating: "a", count: ArtifactAnnotationStore.maximumNoteBytes + 1)
    let allowed = fixture.controller.textView(
        fixture.notes,
        shouldChangeTextIn: NSRange(location: 0, length: 0),
        replacementString: oversized
    )
    #expect(!allowed)
    #expect(fixture.status.stringValue.contains("256 KB"))
    #expect(fixture.operations.writes.isEmpty)
}

@MainActor
@Test func artifactRevealAndComparisonControlsHandleCancelFailureSuccessDuplicateAndInvalidSelection() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = ArtifactWindowFixture(name: "unsafe\nname.pdf")
    fixture.controller.prepareNoteForPresentation()
    fixture.operations.reads[0].completion(.success(""))
    #expect(fixture.controller.window?.title == "unsafe name.pdf")

    let reveal = fixture.button("Show in Finder")
    reveal.performClick(nil)
    reveal.performClick(nil)
    #expect(fixture.interactions.reveals.count == 1)
    fixture.interactions.reveals[0].1(.failure(ArtifactPluginHostileError()))
    fixture.interactions.reveals[0].1(.success(()))
    #expect(fixture.interactions.failures == [.reveal])
    #expect(reveal.isEnabled)
    reveal.performClick(nil)
    fixture.interactions.reveals[1].1(.success(()))

    let compare = fixture.button("Compare Version…")
    compare.performClick(nil)
    compare.performClick(nil)
    #expect(fixture.interactions.comparisonChoices.count == 1)
    #expect(fixture.interactions.comparisonChoices[0].0 == "unsafe name.pdf")
    fixture.interactions.comparisonChoices[0].1(.success(nil))
    fixture.interactions.comparisonChoices[0].1(.success(URL(fileURLWithPath: "/tmp/stale.pdf")))
    #expect(fixture.interactions.comparisons.isEmpty)

    compare.performClick(nil)
    fixture.interactions.comparisonChoices[1].1(.failure(ArtifactPluginHostileError()))
    #expect(fixture.interactions.failures.last == .comparison)
    #expect(!artifactPluginVisibleText(fixture.root).contains("secret-token"))

    compare.performClick(nil)
    fixture.interactions.comparisonChoices[2].1(.success(fixture.artifact))
    #expect(fixture.interactions.failures.last == .comparison)
    #expect(fixture.interactions.comparisons.isEmpty)

    let other = URL(fileURLWithPath: "/tmp/other.pdf")
    compare.performClick(nil)
    fixture.interactions.comparisonChoices[3].1(.success(other))
    fixture.interactions.comparisonChoices[3].1(.success(URL(fileURLWithPath: "/tmp/duplicate.pdf")))
    #expect(fixture.interactions.comparisons.count == 1)
    #expect(fixture.interactions.comparisons[0].0 == fixture.artifact)
    #expect(fixture.interactions.comparisons[0].1 == other)
    #expect(fixture.controller.comparisonWindow != nil)
}

@MainActor
@Test func artifactControlsAreWiredAccessibleAndFitMinimumInLightAndDark() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = ArtifactWindowFixture(name: "artifact\rprivate.pdf")
    let window = try #require(fixture.controller.window)
    #expect(!window.isVisible)
    let retry = fixture.button("Retry Note Load")
    let cancel = fixture.button("Cancel Save")
    retry.isHidden = false
    cancel.isHidden = false
    window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
    let preview = try #require(
        fixture.views.first { ($0.accessibilityLabel() ?? "").hasPrefix("Artifact preview:") }
    )
    let runtimeStates: [(message: String, retryVisible: Bool, cancelVisible: Bool)] = [
        (ArtifactPreviewFailure.loadNote.message, true, false),
        (ArtifactPreviewFailure.saveNote.message, false, false),
        ("Saving the private note before closing…", false, true),
    ]
    for appearance in [NSAppearance.Name.aqua, .darkAqua] {
        window.appearance = NSAppearance(named: appearance)
        window.layoutIfNeeded()
        #expect(fixture.root.fittingSize.width <= window.contentLayoutRect.width + 1)
        #expect(fixture.root.fittingSize.height <= window.contentLayoutRect.height + 1)

        for state in runtimeStates {
            fixture.status.stringValue = state.message
            retry.isHidden = !state.retryVisible
            cancel.isHidden = !state.cancelVisible
            window.layoutIfNeeded()
            #expect(fixture.root.fittingSize.width <= window.contentLayoutRect.width + 1)
            #expect(fixture.root.fittingSize.height <= window.contentLayoutRect.height + 1)
            let statusFrame = fixture.status.convert(fixture.status.bounds, to: fixture.root)
            #expect(fixture.root.bounds.insetBy(dx: -1, dy: -1).contains(statusFrame))
            #expect(preview.bounds.width >= 400)
            #expect((fixture.notes.enclosingScrollView?.bounds.width ?? 0) >= 260)
            let visibleControls = [
                retry,
                cancel,
                fixture.button("Compare Version…"),
                fixture.button("Show in Finder"),
            ].filter { !$0.isHidden }
            for button in visibleControls {
                let buttonFrame = button.convert(button.bounds, to: fixture.root)
                #expect(fixture.root.bounds.insetBy(dx: -1, dy: -1).contains(buttonFrame))
                #expect(button.bounds.width + 1 >= button.fittingSize.width)
            }
        }
    }
    for title in ["Retry Note Load", "Cancel Save", "Compare Version…", "Show in Finder"] {
        let button = fixture.button(title)
        #expect(button.target != nil, Comment(rawValue: title))
        #expect(button.action != nil, Comment(rawValue: title))
    }
    #expect(fixture.notes.accessibilityLabel() == "Artifact notes")
    #expect(fixture.status.accessibilityLabel() == "Artifact note status")
    #expect(!(preview.accessibilityLabel() ?? "").contains("\r"))
}

@MainActor
@Test func artifactComparisonPreviewsAreSanitizedAccessibleAndFitMinimumInLightAndDark() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let controller = ArtifactComparisonWindowController(
        left: URL(fileURLWithPath: "/tmp/before\nprivate.pdf"),
        right: URL(fileURLWithPath: "/tmp/after\rprivate.pdf"),
        previewFactory: makeArtifactPreviewTestView
    )
    let window = try #require(controller.window)
    let root = try #require(window.contentViewController?.view)
    // This is a deterministic geometry/accessibility test. The test injects
    // inert preview views and keeps the window off-screen; live QuickLook and
    // visible-window behavior belong to physical app qualification.
    #expect(!window.isVisible)
    window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
    for appearance in [NSAppearance.Name.aqua, .darkAqua] {
        window.appearance = NSAppearance(named: appearance)
        window.layoutIfNeeded()
        #expect(root.fittingSize.width <= window.contentLayoutRect.width + 1)
        #expect(root.fittingSize.height <= window.contentLayoutRect.height + 1)
    }
    let labels = artifactPluginDescendants(root).compactMap { $0.accessibilityLabel() }
    #expect(labels.contains("Left artifact preview: before private.pdf"))
    #expect(labels.contains("Right artifact preview: after private.pdf"))
    #expect(!window.subtitle.contains("\n"))
    #expect(!window.subtitle.contains("\r"))
}

@MainActor
private final class PluginOperationsProbe {
    typealias AuditCompletion = @MainActor (Result<[PluginTrustFinding], Error>) -> Void
    typealias RevokeCompletion = @MainActor (Result<Void, Error>) -> Void
    struct AuditCall {
        let completion: AuditCompletion
        let cancellation: PluginTrustWindowController.OperationCancellation
    }
    struct RevokeCall {
        let name: String
        let completion: RevokeCompletion
        let cancellation: PluginTrustWindowController.OperationCancellation
    }
    var audits: [AuditCall] = []
    var revokes: [RevokeCall] = []

    func operations() -> PluginTrustWindowController.Operations {
        .init(
            findings: { completion in
                let cancellation = PluginTrustWindowController.OperationCancellation()
                self.audits.append(.init(completion: completion, cancellation: cancellation))
                return cancellation
            },
            revoke: { name, completion in
                let cancellation = PluginTrustWindowController.OperationCancellation()
                self.revokes.append(.init(name: name, completion: completion, cancellation: cancellation))
                return cancellation
            }
        )
    }
}

@MainActor
private final class PluginInteractionsProbe {
    var confirmations: [(String, @MainActor (Bool) -> Void)] = []
    var notices: [PluginTrustWindowController.Notice] = []

    func interactions() -> PluginTrustWindowController.Interactions {
        .init(
            confirmRevoke: { name, _, completion in self.confirmations.append((name, completion)) },
            presentNotice: { notice, _ in self.notices.append(notice) }
        )
    }
}

@MainActor
private struct PluginWindowFixture {
    let operations = PluginOperationsProbe()
    let interactions = PluginInteractionsProbe()
    let controller: PluginTrustWindowController

    init() {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        controller = PluginTrustWindowController(
            operations: operations.operations(),
            interactions: interactions.interactions()
        )
        controller.window?.animationBehavior = .none
    }

    var root: NSView { controller.window!.contentViewController!.view }
    var views: [NSView] { artifactPluginDescendants(root) }
    var table: NSTableView { views.compactMap { $0 as? NSTableView }.first! }
    var summary: NSTextField {
        views.compactMap { $0 as? NSTextField }.first { $0 !== table.headerView }!
    }
    func button(_ title: String) -> NSButton {
        views.compactMap { $0 as? NSButton }.first { $0.title == title }!
    }
}

@MainActor
@Test func pluginAuditPreservesSelectionRejectsStaleDuplicateFailureAndReopensCleanly() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = PluginWindowFixture()
    let approved = pluginFinding(id: "approved", name: "approved-plugin", status: .approved)
    let blocked = pluginFinding(id: "blocked", name: "blocked-plugin", status: .blocked)
    fixture.controller.prepareAuditForPresentation()
    fixture.controller.prepareAuditForPresentation()
    #expect(fixture.operations.audits.count == 2)
    #expect(fixture.operations.audits[0].cancellation.isCancelled)
    fixture.operations.audits[1].completion(.success([approved, blocked]))
    fixture.operations.audits[1].completion(.success([]))
    #expect(fixture.table.numberOfRows == 2)
    fixture.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))

    fixture.button("Refresh").performClick(nil)
    fixture.operations.audits[2].completion(.success([blocked, approved]))
    #expect(fixture.table.selectedRow == 0)
    fixture.operations.audits[0].completion(.failure(ArtifactPluginHostileError()))
    #expect(fixture.table.numberOfRows == 2)

    fixture.button("Refresh").performClick(nil)
    fixture.operations.audits[3].completion(.failure(ArtifactPluginHostileError()))
    #expect(fixture.table.numberOfRows == 0)
    #expect(fixture.interactions.notices.last == .failure)
    #expect(!artifactPluginVisibleText(fixture.root).contains("secret-token"))

    fixture.controller.prepareAuditForPresentation()
    let closingAudit = fixture.operations.audits[4]
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: fixture.controller.window))
    #expect(closingAudit.cancellation.isCancelled)
    closingAudit.completion(.success([approved]))
    #expect(fixture.table.numberOfRows == 0)
    fixture.controller.prepareAuditForPresentation()
    #expect(fixture.operations.audits.count == 6)
    let oversized = (0...512).map {
        pluginFinding(id: "plugin-\($0)", name: "plugin-\($0)", status: .blocked)
    }
    fixture.operations.audits[5].completion(.success(oversized))
    #expect(fixture.table.numberOfRows == 0)
    #expect(fixture.interactions.notices.last == .failure)
}

@MainActor
@Test func pluginRevokeMissingSelectionCancelFailureSuccessDuplicateAndBusyAreSafe() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = PluginWindowFixture()
    let approved = pluginFinding(id: "approved", name: "legacy-plugin", status: .approved)
    fixture.controller.prepareAuditForPresentation()
    let revoke = fixture.button("Remove Legacy Approval")
    revoke.isEnabled = true
    revoke.performClick(nil)
    #expect(fixture.interactions.confirmations.isEmpty)

    fixture.operations.audits[0].completion(.success([approved]))
    fixture.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    #expect(revoke.isEnabled)
    revoke.performClick(nil)
    revoke.performClick(nil)
    #expect(fixture.interactions.confirmations.count == 1)
    #expect(fixture.interactions.confirmations[0].0 == "legacy-plugin")
    #expect(!fixture.table.isEnabled)
    #expect(!fixture.button("Refresh").isEnabled)
    fixture.interactions.confirmations[0].1(false)
    fixture.interactions.confirmations[0].1(true)
    #expect(fixture.operations.revokes.isEmpty)
    #expect(revoke.isEnabled)

    revoke.performClick(nil)
    fixture.interactions.confirmations[1].1(true)
    fixture.interactions.confirmations[1].1(true)
    #expect(fixture.operations.revokes.count == 1)
    #expect(fixture.operations.revokes[0].name == approved.name)
    #expect(!fixture.table.isEnabled)
    fixture.operations.revokes[0].completion(.failure(ArtifactPluginHostileError()))
    fixture.operations.revokes[0].completion(.success(()))
    #expect(fixture.interactions.notices.last == .failure)
    #expect(!artifactPluginVisibleText(fixture.root).contains("secret-token"))
    #expect(revoke.isEnabled)

    revoke.performClick(nil)
    fixture.interactions.confirmations[2].1(true)
    fixture.operations.revokes[1].completion(.success(()))
    fixture.operations.revokes[1].completion(.success(()))
    #expect(fixture.interactions.notices.contains(.revoked("legacy-plugin")))
    #expect(fixture.operations.audits.count == 2)
    fixture.operations.audits[1].completion(.success([pluginFinding(id: "approved", name: approved.name, status: .blocked)]))
    #expect(!revoke.isEnabled)
}

@MainActor
@Test func pluginApprovalNoticeAndCloseInvalidatePendingConfirmationAndRevoke() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = PluginWindowFixture()
    let approved = pluginFinding(id: "approved", name: "approved", status: .approved)
    fixture.controller.prepareAuditForPresentation()
    fixture.operations.audits[0].completion(.success([approved]))

    let approve = fixture.button("Community Plugins Disabled")
    approve.isEnabled = true
    approve.performClick(nil)
    #expect(fixture.interactions.notices == [.communityDisabled])
    approve.isEnabled = false

    fixture.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    fixture.button("Remove Legacy Approval").performClick(nil)
    let staleConfirmation = fixture.interactions.confirmations[0].1
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: fixture.controller.window))
    staleConfirmation(true)
    #expect(fixture.operations.revokes.isEmpty)

    fixture.controller.prepareAuditForPresentation()
    fixture.operations.audits[1].completion(.success([approved]))
    fixture.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    fixture.button("Remove Legacy Approval").performClick(nil)
    fixture.interactions.confirmations[1].1(true)
    let revoke = fixture.operations.revokes[0]
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: fixture.controller.window))
    #expect(revoke.cancellation.isCancelled)
    revoke.completion(.success(()))
    #expect(!fixture.interactions.notices.contains(.revoked("approved")))
}

@MainActor
@Test func pluginStringsAreSanitizedAndControlsFitMinimumInLightAndDark() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = PluginWindowFixture()
    let hostile = pluginFinding(
        id: "hostile",
        name: String(repeating: "n", count: 200) + "\nsecret",
        version: "1.0\rsecret",
        status: .approved
    )
    fixture.controller.prepareAuditForPresentation()
    #expect(fixture.controller.window?.isVisible == false)
    fixture.operations.audits[0].completion(.success([hostile]))
    let nameColumn = try #require(fixture.table.tableColumn(withIdentifier: .init("plugin")))
    let versionColumn = try #require(fixture.table.tableColumn(withIdentifier: .init("version")))
    let trustColumn = try #require(fixture.table.tableColumn(withIdentifier: .init("trust")))
    let name = try #require(fixture.controller.tableView(fixture.table, viewFor: nameColumn, row: 0) as? NSTextField)
    let version = try #require(fixture.controller.tableView(fixture.table, viewFor: versionColumn, row: 0) as? NSTextField)
    let trust = try #require(fixture.controller.tableView(fixture.table, viewFor: trustColumn, row: 0) as? NSTextField)
    #expect(name.stringValue.count == 160)
    #expect(!name.stringValue.contains("\n"))
    #expect(!version.stringValue.contains("\r"))
    #expect(trust.stringValue == "Approved")
    fixture.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: fixture.table))
    #expect(!fixture.button("Remove Legacy Approval").isEnabled)

    let window = try #require(fixture.controller.window)
    window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
    for appearance in [NSAppearance.Name.aqua, .darkAqua] {
        window.appearance = NSAppearance(named: appearance)
        window.layoutIfNeeded()
        #expect(fixture.root.fittingSize.width <= window.contentLayoutRect.width + 1)
        #expect(fixture.root.fittingSize.height <= window.contentLayoutRect.height + 1)
    }
    #expect(fixture.table.accessibilityLabel() == "Plugin trust decisions")
    for title in ["Refresh", "Community Plugins Disabled", "Remove Legacy Approval"] {
        let button = fixture.button(title)
        #expect(button.target != nil, Comment(rawValue: title))
        #expect(button.action != nil, Comment(rawValue: title))
    }
}

private func pluginFinding(
    id: String,
    name: String,
    version: String = "1.0.0",
    status: PluginTrustFinding.Status
) -> PluginTrustFinding {
    PluginTrustFinding(
        id: id,
        name: name,
        declaredVersion: version,
        fingerprint: "fingerprint",
        source: "fixture",
        status: status
    )
}

private func artifactPluginVisibleText(_ root: NSView) -> String {
    artifactPluginDescendants(root).compactMap { view -> String? in
        guard !view.isHidden else { return nil }
        if let field = view as? NSTextField { return field.stringValue }
        if let text = view as? NSTextView { return text.string }
        return nil
    }.joined(separator: "\n")
}

private func artifactPluginDescendants(_ root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(artifactPluginDescendants)
}
