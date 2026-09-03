import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct MCPCenterHostileError: LocalizedError {
    var errorDescription: String? {
        "MCP_REMOTE_SECRET_CANARY_sk-private_\(String(repeating: "X", count: 32_000))\u{001B}[31m"
    }
}

@MainActor
private final class MCPCenterOperationProbe {
    struct InspectCall {
        let draft: MCPServerDraft
        let completion: MCPCenterResultHandler<MCPDraftInspection>
    }
    struct PersistCall {
        let draft: MCPServerDraft
        let approve: Bool
        let completion: MCPCenterResultHandler<MCPServerTrustRecord>
    }
    struct VerifyCall {
        let ids: [String]
        let completion: MCPCenterResultHandler<MCPStatusBatch>
    }
    struct MutationCall {
        let id: String
        let completion: MCPCenterResultHandler<Void>
    }

    var records: [MCPServerTrustRecord]
    var recordsError: (any Error)?
    var inspectCalls: [InspectCall] = []
    var persistCalls: [PersistCall] = []
    var verifyCalls: [VerifyCall] = []
    var revokeCalls: [MutationCall] = []
    var removeCalls: [MutationCall] = []

    init(records: [MCPServerTrustRecord]) { self.records = records }

    var operations: MCPCenterOperations {
        MCPCenterOperations(
            records: { [unowned self] in
                if let recordsError { throw recordsError }
                return records
            },
            inspect: { [unowned self] draft, completion in
                inspectCalls.append(.init(draft: draft, completion: completion))
            },
            persist: { [unowned self] draft, approve, completion in
                persistCalls.append(.init(draft: draft, approve: approve, completion: completion))
            },
            verify: { [unowned self] ids, completion in
                verifyCalls.append(.init(ids: ids, completion: completion))
            },
            revoke: { [unowned self] id, completion in
                revokeCalls.append(.init(id: id, completion: completion))
            },
            remove: { [unowned self] id, completion in
                removeCalls.append(.init(id: id, completion: completion))
            }
        )
    }
}

@MainActor
private final class MCPCenterInteractionProbe {
    struct ConfirmationCall {
        let value: MCPCenterConfirmation
        let completion: MCPCenterConfirmationHandler
    }

    var begunSheets: [NSWindow] = []
    var endedSheets: [NSWindow] = []
    var confirmations: [ConfirmationCall] = []
    var notices: [MCPCenterNotice] = []

    var interactions: MCPCenterInteractions {
        MCPCenterInteractions(
            beginSheet: { [unowned self] _, sheet in begunSheets.append(sheet) },
            endSheet: { [unowned self] _, sheet in endedSheets.append(sheet) },
            confirm: { [unowned self] value, _, completion in
                confirmations.append(.init(value: value, completion: completion))
            },
            presentNotice: { [unowned self] notice, _ in notices.append(notice) }
        )
    }
}

@MainActor
private final class MCPCenterApplyProbe {
    private(set) var calls = 0
    private var continuations: [CheckedContinuation<Void, any Error>] = []

    func run() async throws {
        calls += 1
        try await withCheckedThrowingContinuation { continuations.append($0) }
    }

    func resolve(_ result: Result<Void, any Error>, at index: Int = 0) throws {
        let continuation = try #require(
            continuations.indices.contains(index) ? continuations.remove(at: index) : nil
        )
        continuation.resume(with: result)
    }
}

@MainActor
private struct MCPCenterFixture {
    let root: URL
    let operationProbe: MCPCenterOperationProbe
    let interactionProbe: MCPCenterInteractionProbe
    let controller: MCPCenterWindowController

    init(records: [MCPServerTrustRecord] = [], apply: (@MainActor () async throws -> Void)? = nil) throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("Fulmar-MCPCenter-\(UUID().uuidString)", isDirectory: true)
        let support = root.appendingPathComponent("Support", isDirectory: true)
        let project = root.appendingPathComponent("Project", isDirectory: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        operationProbe = MCPCenterOperationProbe(records: records)
        interactionProbe = MCPCenterInteractionProbe()
        controller = MCPCenterWindowController(
            store: try MCPTrustStore(applicationSupport: support),
            projectRoot: project,
            providerChoices: [MCPProviderChoice(
                provider: ProviderID("ollama"),
                displayName: "Ollama Local",
                boundary: .onDevice
            )],
            onApplyAndRestart: apply,
            operations: operationProbe.operations,
            interactions: interactionProbe.interactions
        )
    }

    func cleanup() {
        controller.close()
        try? FileManager.default.removeItem(at: root)
    }
}

private func mcpCenterDraft(
    id: String = "safe-local",
    displayName: String = "Safe Local Server"
) -> MCPServerDraft {
    MCPServerDraft(
        id: id,
        displayName: displayName,
        serverName: id.replacingOccurrences(of: "-", with: "_"),
        executablePath: "/usr/bin/true",
        arguments: ["--stdio"],
        allowedProviders: [MCPProviderEnablement(
            provider: ProviderID("ollama"),
            boundary: .onDevice
        )],
        disclosure: MCPDisclosureProfile(
            boundary: .onDevice,
            dataKinds: [.toolArguments, .toolResults]
        )
    )
}

private func mcpCenterRecord(
    id: String = "safe-local",
    displayName: String = "Safe Local Server",
    approved: Bool = true
) -> MCPServerTrustRecord {
    MCPServerTrustRecord(
        id: id,
        draft: mcpCenterDraft(id: id, displayName: displayName),
        project: MCPProjectIdentity(
            canonicalPath: "/private/tmp/FulmarProject",
            ownerUID: 501,
            deviceID: 1,
            inode: 2,
            fingerprint: "project-fingerprint"
        ),
        approval: approved ? MCPTrustApproval(
            reviewFingerprint: "review-fingerprint",
            executableFingerprint: MCPExecutableFingerprint("executable-fingerprint"),
            approvedAt: Date(timeIntervalSince1970: 1_700_000_000)
        ) : nil,
        updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
    )
}

private func mcpCenterInspection(
    hostilePath: String? = nil
) -> MCPDraftInspection {
    let path = hostilePath ?? "/usr/bin/true"
    return MCPDraftInspection(
        executable: MCPExecutableAudit(
            declaredPath: path,
            canonicalPath: path,
            contentSHA256: String(repeating: "a", count: 64),
            byteCount: 1_024,
            ownerUID: 0,
            permissions: 0o755,
            interpreterCanonicalPath: nil,
            interpreterContentSHA256: nil,
            fingerprint: MCPExecutableFingerprint("executable-fingerprint")
        ),
        project: MCPProjectIdentity(
            canonicalPath: "/private/tmp/FulmarProject",
            ownerUID: 501,
            deviceID: 1,
            inode: 2,
            fingerprint: "project-fingerprint"
        ),
        reviewedFiles: []
    )
}

@MainActor
private func mcpCenterDescendants(_ root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(mcpCenterDescendants)
}

@MainActor
private func mcpCenterRoot(_ controller: MCPCenterWindowController) throws -> NSView {
    try #require(controller.window?.contentViewController?.view)
}

@MainActor
private func mcpCenterButton(_ title: String, in root: NSView) throws -> NSButton {
    try #require(mcpCenterDescendants(root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func mcpCenterField(_ label: String, in root: NSView) throws -> NSTextField {
    try #require(mcpCenterDescendants(root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == label
    })
}

@MainActor
private func mcpCenterTable(in root: NSView) throws -> NSTableView {
    try #require(mcpCenterDescendants(root).compactMap { $0 as? NSTableView }.first {
        $0.accessibilityLabel() == "Configured MCP servers"
    })
}

@MainActor
private func mcpCenterDisplayedText(_ roots: [NSView]) -> String {
    roots.flatMap(mcpCenterDescendants).map { view -> String in
        if let field = view as? NSTextField { return field.stringValue }
        if let text = view as? NSTextView { return text.string }
        if let button = view as? NSButton { return button.title }
        return view.toolTip ?? ""
    }.joined(separator: "\n")
}

@MainActor
private func mcpCenterForceSelector(_ button: NSButton) throws {
    let action = try #require(button.action)
    #expect(NSApp.sendAction(action, to: button.target, from: button))
}

@MainActor
private func mcpCenterWait(
    _ description: String,
    until condition: @escaping @MainActor () -> Bool
) async {
    for _ in 0..<2_000 {
        if condition() { return }
        await Task.yield()
    }
    Issue.record("Timed out waiting for \(description)")
}

@MainActor
private func mcpCenterShowAndVerify(
    _ fixture: MCPCenterFixture,
    statuses: [String: MCPTrustStatus]? = nil
) throws {
    fixture.controller.showWindow(nil)
    let call = try #require(fixture.operationProbe.verifyCalls.last)
    call.completion(.success(MCPStatusBatch(
        statuses: statuses ?? Dictionary(uniqueKeysWithValues: call.ids.map { ($0, .trusted) }),
        failedIDs: []
    )))
}

@MainActor
private func mcpCenterFillValidEditor(_ root: NSView) throws {
    try mcpCenterField("MCP definition ID", in: root).stringValue = "new-server"
    try mcpCenterField("MCP display name", in: root).stringValue = "New Server"
    try mcpCenterField("MCP tool namespace", in: root).stringValue = "new_server"
    try mcpCenterField("MCP executable path", in: root).stringValue = "/usr/bin/true"
}

@MainActor
@Test func mcpCenterEmptyLoadFailureAndRecoveryAreBoundedAndFailClosed() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try MCPCenterFixture()
    defer { fixture.cleanup() }
    let root = try mcpCenterRoot(fixture.controller)
    let add = try mcpCenterButton("Add Server…", in: root)
    let status = try mcpCenterField("MCP server status", in: root)
    let empty = try mcpCenterField("MCP server empty state", in: root)

    fixture.controller.showWindow(nil)
    #expect(add.isEnabled)
    #expect(!empty.isHidden)
    #expect(fixture.operationProbe.verifyCalls.isEmpty)

    fixture.operationProbe.recordsError = MCPCenterHostileError()
    fixture.controller.showWindow(nil)
    #expect(fixture.interactionProbe.notices.last == .recordsUnavailable)
    #expect(status.stringValue == MCPCenterNotice.recordsUnavailable.message)
    #expect(!status.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    #expect(status.stringValue.count < 500)
    #expect(!add.isEnabled)

    fixture.operationProbe.recordsError = nil
    fixture.controller.showWindow(nil)
    #expect(add.isEnabled)
    #expect(empty.stringValue == "No MCP servers are configured for this project.")
}

@MainActor
@Test func mcpCenterAddCancelInvalidInspectFailureAndDuplicateCompletionUseRealSelectors() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try MCPCenterFixture()
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    let root = try mcpCenterRoot(fixture.controller)
    let add = try mcpCenterButton("Add Server…", in: root)

    add.performClick(nil)
    let firstEditor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    #expect(try mcpCenterButton("Choose…", in: firstEditor).accessibilityLabel() == "Choose MCP server executable")
    try mcpCenterButton("Cancel", in: firstEditor).performClick(nil)
    #expect(fixture.interactionProbe.endedSheets.count == 1)

    add.performClick(nil)
    let editor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let review = try mcpCenterButton("Review Definition…", in: editor)
    review.performClick(nil)
    let editorStatus = try mcpCenterField("MCP editor status", in: editor)
    #expect(editorStatus.stringValue.contains("Definition ID"))
    #expect(fixture.operationProbe.inspectCalls.isEmpty)

    try mcpCenterFillValidEditor(editor)
    review.performClick(nil)
    #expect(fixture.operationProbe.inspectCalls.count == 1)
    #expect(!review.isEnabled)
    try mcpCenterForceSelector(review)
    #expect(fixture.operationProbe.inspectCalls.count == 1)
    fixture.operationProbe.inspectCalls[0].completion(.failure(MCPCenterHostileError()))
    #expect(review.isEnabled)
    #expect(editorStatus.stringValue.contains("could not verify"))
    #expect(!editorStatus.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    #expect(editorStatus.stringValue.count < 300)
    fixture.operationProbe.inspectCalls[0].completion(.success(mcpCenterInspection()))
    #expect(fixture.interactionProbe.begunSheets.count == 2)
}

@MainActor
@Test func mcpCenterExactReviewConsentBackAndHostileInspectionFailClosed() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try MCPCenterFixture()
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    let main = try mcpCenterRoot(fixture.controller)
    try mcpCenterButton("Add Server…", in: main).performClick(nil)
    let editor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    try mcpCenterFillValidEditor(editor)
    try mcpCenterButton("Review Definition…", in: editor).performClick(nil)
    fixture.operationProbe.inspectCalls[0].completion(.success(mcpCenterInspection()))

    let review = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let approve = try mcpCenterButton("Approve Server", in: review)
    let confirmation = try #require(mcpCenterDescendants(review).compactMap { $0 as? NSButton }.first {
        $0.accessibilityLabel() == "Confirm exact MCP server review"
    })
    let text = mcpCenterDisplayedText([review])
    #expect(text.contains("EXACT EXECUTABLE"))
    #expect(text.contains("LITERAL ARGUMENTS"))
    #expect(text.contains("ALLOWED MODEL ROUTES"))
    #expect(text.contains("Ollama Local [ollama] — On this Mac"))
    #expect(text.contains("MCP PROCESS DISCLOSURE"))
    #expect(text.contains("ENFORCED LIMITS"))
    #expect(!approve.isEnabled)
    confirmation.performClick(nil)
    #expect(approve.isEnabled)
    try mcpCenterButton("Back", in: review).performClick(nil)
    #expect(fixture.interactionProbe.endedSheets.last === fixture.interactionProbe.begunSheets[1])
    #expect(fixture.interactionProbe.begunSheets.last === fixture.interactionProbe.begunSheets[0])

    try mcpCenterButton("Review Definition…", in: editor).performClick(nil)
    fixture.operationProbe.inspectCalls[1].completion(.success(mcpCenterInspection(
        hostilePath: "MCP_REVIEW_CANARY\u{202E}" + String(repeating: "Z", count: 8_000)
    )))
    let blockedReview = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let blockedText = mcpCenterDisplayedText([blockedReview])
    let blockedApprove = try mcpCenterButton("Approve Server", in: blockedReview)
    #expect(!blockedApprove.isEnabled)
    #expect(!blockedText.contains("MCP_REVIEW_CANARY"))
    #expect(blockedText.contains("cannot be reviewed safely"))
}

@MainActor
@Test func mcpCenterPersistFailureDisabledSaveApprovalSuccessAndEditAreRecoverable() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try MCPCenterFixture()
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    let main = try mcpCenterRoot(fixture.controller)
    try mcpCenterButton("Add Server…", in: main).performClick(nil)
    let editor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    try mcpCenterFillValidEditor(editor)
    try mcpCenterButton("Review Definition…", in: editor).performClick(nil)
    fixture.operationProbe.inspectCalls[0].completion(.success(mcpCenterInspection()))
    let review = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let save = try mcpCenterButton("Save Disabled", in: review)
    save.performClick(nil)
    #expect(fixture.operationProbe.persistCalls.count == 1)
    #expect(!fixture.operationProbe.persistCalls[0].approve)
    try mcpCenterForceSelector(save)
    #expect(fixture.operationProbe.persistCalls.count == 1)
    fixture.operationProbe.persistCalls[0].completion(.failure(MCPCenterHostileError()))
    let reviewStatus = try mcpCenterField("MCP review status", in: review)
    #expect(!reviewStatus.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    #expect(save.isEnabled)
    fixture.operationProbe.persistCalls[0].completion(.success(mcpCenterRecord(
        id: "new-server",
        displayName: "Late Result"
    )))
    #expect(fixture.interactionProbe.endedSheets.count == 1)

    save.performClick(nil)
    let disabled = mcpCenterRecord(id: "new-server", displayName: "New Server", approved: false)
    fixture.operationProbe.records = [disabled]
    fixture.operationProbe.persistCalls[1].completion(.success(disabled))
    #expect(fixture.interactionProbe.endedSheets.last === fixture.interactionProbe.begunSheets.last)
    let table = try mcpCenterTable(in: main)
    #expect(table.selectedRow == 0)
    #expect(try mcpCenterButton("Edit…", in: main).isEnabled)

    try mcpCenterButton("Edit…", in: main).performClick(nil)
    let edit = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let id = try mcpCenterField("MCP definition ID", in: edit)
    #expect(id.stringValue == "new-server")
    #expect(!id.isEditable)
    #expect(try mcpCenterField("MCP display name", in: edit).stringValue == "New Server")
    try mcpCenterButton("Cancel", in: edit).performClick(nil)
}

@MainActor
@Test func mcpCenterVerificationMissingFailureDuplicateAndSelectionAreFailClosed() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let first = mcpCenterRecord(id: "first", displayName: "First")
    let second = mcpCenterRecord(id: "second", displayName: "Second")
    let fixture = try MCPCenterFixture(records: [first, second])
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    let root = try mcpCenterRoot(fixture.controller)
    let table = try mcpCenterTable(in: root)
    table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
    fixture.controller.tableViewSelectionDidChange(Notification(
        name: NSTableView.selectionDidChangeNotification,
        object: table
    ))
    let verify = try #require(fixture.operationProbe.verifyCalls.first)
    verify.completion(.success(MCPStatusBatch(statuses: ["first": .trusted], failedIDs: [])))
    let status = try mcpCenterField("MCP server status", in: root)
    #expect(status.stringValue == MCPCenterNotice.verificationFailed(count: 1).message)
    #expect(fixture.interactionProbe.notices.last == .verificationFailed(count: 1))
    #expect(table.selectedRow == 1)
    let stateColumn = try #require(table.tableColumns.first { $0.identifier.rawValue == "state" })
    let secondState = try #require(fixture.controller.tableView(table, viewFor: stateColumn, row: 1) as? NSTextField)
    #expect(secondState.stringValue == "Changed")

    verify.completion(.success(MCPStatusBatch(
        statuses: ["first": .trusted, "second": .trusted],
        failedIDs: []
    )))
    #expect(status.stringValue == MCPCenterNotice.verificationFailed(count: 1).message)
    #expect(secondState.stringValue == "Changed")

    try mcpCenterButton("Verify Files", in: root).performClick(nil)
    let failure = try #require(fixture.operationProbe.verifyCalls.last)
    failure.completion(.failure(MCPCenterHostileError()))
    #expect(status.stringValue == MCPCenterNotice.verificationFailed(count: 2).message)
    #expect(!status.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    #expect(status.stringValue.count < 500)
}

@MainActor
@Test func mcpCenterRevokeAndRemoveConfirmationsAreSingleFlightAndSafe() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let trusted = mcpCenterRecord()
    let fixture = try MCPCenterFixture(records: [trusted])
    defer { fixture.cleanup() }
    try mcpCenterShowAndVerify(fixture)
    let root = try mcpCenterRoot(fixture.controller)
    let revoke = try mcpCenterButton("Revoke", in: root)

    revoke.performClick(nil)
    #expect(fixture.interactionProbe.confirmations.count == 1)
    #expect(!revoke.isEnabled)
    try mcpCenterForceSelector(revoke)
    #expect(fixture.interactionProbe.confirmations.count == 1)
    fixture.interactionProbe.confirmations[0].completion(false)
    fixture.interactionProbe.confirmations[0].completion(true)
    #expect(fixture.operationProbe.revokeCalls.isEmpty)
    #expect(revoke.isEnabled)

    revoke.performClick(nil)
    fixture.interactionProbe.confirmations[1].completion(true)
    fixture.interactionProbe.confirmations[1].completion(true)
    #expect(fixture.operationProbe.revokeCalls.count == 1)
    fixture.operationProbe.revokeCalls[0].completion(.failure(MCPCenterHostileError()))
    #expect(fixture.interactionProbe.notices.last == .revokeFailed)
    let status = try mcpCenterField("MCP server status", in: root)
    #expect(!status.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    fixture.operationProbe.revokeCalls[0].completion(.success(()))
    #expect(fixture.interactionProbe.notices.last == .revokeFailed)

    revoke.performClick(nil)
    fixture.interactionProbe.confirmations[2].completion(true)
    let disabled = mcpCenterRecord(approved: false)
    fixture.operationProbe.records = [disabled]
    fixture.operationProbe.revokeCalls[1].completion(.success(()))
    #expect(!revoke.isEnabled)
    let remove = try mcpCenterButton("Remove…", in: root)

    remove.performClick(nil)
    fixture.interactionProbe.confirmations[3].completion(false)
    #expect(fixture.operationProbe.removeCalls.isEmpty)
    remove.performClick(nil)
    fixture.interactionProbe.confirmations[4].completion(true)
    #expect(fixture.operationProbe.removeCalls.count == 1)
    fixture.operationProbe.removeCalls[0].completion(.failure(MCPCenterHostileError()))
    #expect(fixture.interactionProbe.notices.last == .removeFailed)
    remove.performClick(nil)
    fixture.interactionProbe.confirmations[5].completion(true)
    fixture.operationProbe.records = []
    fixture.operationProbe.removeCalls[1].completion(.success(()))
    #expect(try mcpCenterTable(in: root).numberOfRows == 0)
}

@MainActor
@Test func mcpCenterCloseInvalidatesPendingEditorAndMutationCompletions() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try MCPCenterFixture()
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    let root = try mcpCenterRoot(fixture.controller)
    try mcpCenterButton("Add Server…", in: root).performClick(nil)
    let editor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    try mcpCenterFillValidEditor(editor)
    try mcpCenterButton("Review Definition…", in: editor).performClick(nil)
    #expect(fixture.operationProbe.inspectCalls.count == 1)
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification))
    fixture.operationProbe.inspectCalls[0].completion(.success(mcpCenterInspection()))
    #expect(fixture.interactionProbe.begunSheets.count == 1)

    fixture.controller.showWindow(nil)
    try mcpCenterButton("Add Server…", in: root).performClick(nil)
    let reopenedEditor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    try mcpCenterFillValidEditor(reopenedEditor)
    try mcpCenterButton("Review Definition…", in: reopenedEditor).performClick(nil)
    fixture.operationProbe.inspectCalls[1].completion(.success(mcpCenterInspection()))
    let review = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    try mcpCenterButton("Save Disabled", in: review).performClick(nil)
    #expect(fixture.operationProbe.persistCalls.count == 1)
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification))
    let late = mcpCenterRecord(id: "new-server", displayName: "Late Result", approved: false)
    fixture.operationProbe.records = [late]
    fixture.operationProbe.persistCalls[0].completion(.success(late))
    #expect(try mcpCenterTable(in: root).numberOfRows == 0)
}

@MainActor
@Test func mcpCenterUntrustedRecordLabelsAndConfirmationsAreBoundedNativeText() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let hostileName = "Untrusted label\u{202E}\u{001B}[31m" + String(repeating: "Z", count: 8_000)
    let record = mcpCenterRecord(displayName: hostileName)
    let fixture = try MCPCenterFixture(records: [record])
    defer { fixture.cleanup() }
    try mcpCenterShowAndVerify(fixture)
    let root = try mcpCenterRoot(fixture.controller)
    let table = try mcpCenterTable(in: root)
    let nameColumn = try #require(table.tableColumns.first { $0.identifier.rawValue == "name" })
    let name = try #require(fixture.controller.tableView(table, viewFor: nameColumn, row: 0) as? NSTextField)
    #expect(name.stringValue.count <= 160)
    #expect(!name.stringValue.contains("\u{202E}"))
    #expect(!name.stringValue.contains("\u{001B}"))
    try mcpCenterButton("Revoke", in: root).performClick(nil)
    let confirmation = try #require(fixture.interactionProbe.confirmations.last?.value)
    guard case let .revoke(id, displayName) = confirmation else {
        Issue.record("Expected revoke confirmation")
        return
    }
    #expect(id == record.id)
    #expect(displayName.count <= 160)
    #expect(!displayName.contains("\u{202E}"))
    #expect(!displayName.contains("\u{001B}"))
}

@MainActor
@Test func mcpCenterApplyRequiresCoordinatorAndIgnoresBusyReentry() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let disabled = mcpCenterRecord(approved: false)
    let fixture = try MCPCenterFixture(records: [disabled])
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    let initialVerification = try #require(fixture.operationProbe.verifyCalls.first)
    initialVerification.completion(.success(MCPStatusBatch(
        statuses: [disabled.id: .unreviewed],
        failedIDs: []
    )))
    let root = try mcpCenterRoot(fixture.controller)

    let edit = try mcpCenterButton("Edit…", in: root)
    edit.performClick(nil)
    let editor = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let maximumResult = try mcpCenterField("MCP maximum result in KiB", in: editor)
    #expect(maximumResult.stringValue == "1024")
    try mcpCenterButton("Review Definition…", in: editor).performClick(nil)
    let editorStatus = try mcpCenterField("MCP editor status", in: editor)
    #expect(editorStatus.stringValue.contains("Fingerprinting"))
    let inspection = try #require(fixture.operationProbe.inspectCalls.first)
    inspection.completion(.success(mcpCenterInspection()))
    let review = try #require(fixture.interactionProbe.begunSheets.last?.contentViewController?.view)
    let consent = try #require(mcpCenterDescendants(review).compactMap { $0 as? NSButton }.first {
        $0.accessibilityLabel() == "Confirm exact MCP server review"
    })
    consent.performClick(nil)
    try mcpCenterButton("Approve Server", in: review).performClick(nil)
    let approved = mcpCenterRecord()
    fixture.operationProbe.records = [approved]
    let persistence = try #require(fixture.operationProbe.persistCalls.first)
    persistence.completion(.success(approved))

    let apply = try mcpCenterButton("Apply & Restart Agent Service", in: root)
    #expect(apply.isEnabled)
    apply.performClick(nil)
    let unavailableCoordinatorVerification = try #require(
        fixture.operationProbe.verifyCalls.count == 2
            ? fixture.operationProbe.verifyCalls.last
            : nil
    )
    unavailableCoordinatorVerification.completion(.success(MCPStatusBatch(
        statuses: [approved.id: .trusted], failedIDs: []
    )))
    let status = try mcpCenterField("MCP server status", in: root)
    #expect(status.stringValue.contains("protected runtime coordination is unavailable"))
    #expect(apply.isEnabled)

    let applyProbe = MCPCenterApplyProbe()
    fixture.controller.onApplyAndRestart = { try await applyProbe.run() }
    apply.performClick(nil)
    let firstApplyVerification = try #require(
        fixture.operationProbe.verifyCalls.count == 3
            ? fixture.operationProbe.verifyCalls.last
            : nil
    )
    firstApplyVerification.completion(.success(MCPStatusBatch(
        statuses: [approved.id: .trusted], failedIDs: []
    )))
    await mcpCenterWait("apply callback") { applyProbe.calls == 1 }
    try mcpCenterForceSelector(apply)
    #expect(applyProbe.calls == 1)
    try applyProbe.resolve(.failure(MCPCenterHostileError()))
    await mcpCenterWait("apply failure") { !status.stringValue.contains("Stopping") }
    #expect(status.stringValue == MCPCenterNotice.applyFailed.message)
    #expect(!status.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    #expect(fixture.interactionProbe.notices.last == .applyFailed)

    apply.performClick(nil)
    let secondApplyVerification = try #require(
        fixture.operationProbe.verifyCalls.count == 4
            ? fixture.operationProbe.verifyCalls.last
            : nil
    )
    secondApplyVerification.completion(.success(MCPStatusBatch(
        statuses: [approved.id: .trusted], failedIDs: []
    )))
    await mcpCenterWait("second apply callback") { applyProbe.calls == 2 }
    try applyProbe.resolve(.success(()))
    await mcpCenterWait("apply success") { status.stringValue.contains("active") }
    #expect(!apply.isEnabled)
}

@MainActor
@Test func mcpCenterCloseReopenInvalidatesStaleVerificationAndLayoutIsAccessible() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let record = mcpCenterRecord()
    let fixture = try MCPCenterFixture(records: [record])
    defer { fixture.cleanup() }
    fixture.controller.showWindow(nil)
    #expect(fixture.operationProbe.verifyCalls.count == 1)
    fixture.controller.windowWillClose(Notification(name: NSWindow.willCloseNotification))
    fixture.controller.showWindow(nil)
    #expect(fixture.operationProbe.verifyCalls.count == 2)
    let root = try mcpCenterRoot(fixture.controller)
    let status = try mcpCenterField("MCP server status", in: root)
    fixture.operationProbe.verifyCalls[0].completion(.failure(MCPCenterHostileError()))
    #expect(!status.stringValue.contains("MCP_REMOTE_SECRET_CANARY"))
    fixture.operationProbe.verifyCalls[1].completion(.success(MCPStatusBatch(
        statuses: [record.id: .trusted], failedIDs: []
    )))
    #expect(status.stringValue.contains("Verification complete"))

    let window = try #require(fixture.controller.window)
    #expect(window.minSize.width == 860)
    #expect(window.minSize.height == 560)
    #expect(window.contentLayoutRect.width >= 0)
    let table = try mcpCenterTable(in: root)
    #expect(table.accessibilityLabel() == "Configured MCP servers")
    #expect(try mcpCenterField("MCP server status", in: root).accessibilityLabel() == "MCP server status")
    for title in ["Add Server…", "Edit…", "Verify Files", "Revoke", "Remove…", "Apply & Restart Agent Service"] {
        let button = try mcpCenterButton(title, in: root)
        #expect(button.action != nil)
        #expect(button.target === fixture.controller)
    }
}
