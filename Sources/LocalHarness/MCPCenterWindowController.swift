import AppKit
import Foundation

/// One exact provider boundary offered by the native MCP editor. Callers build
/// this catalog from the live Harness provider catalog; the editor never
/// guesses whether an opaque provider identifier is local or remote.
struct MCPProviderChoice: Hashable, Sendable {
    let provider: ProviderID
    let displayName: String
    let boundary: DataBoundary

    init(provider: ProviderID, displayName: String, boundary: DataBoundary) {
        self.provider = provider
        self.displayName = displayName
        self.boundary = boundary
    }
}

private final class MCPTrustStoreSendableBox: @unchecked Sendable {
    let store: MCPTrustStore

    init(_ store: MCPTrustStore) { self.store = store }
}

struct MCPStatusBatch: Sendable {
    let statuses: [String: MCPTrustStatus]
    let failedIDs: Set<String>
}

struct MCPDraftInspection: Sendable {
    let executable: MCPExecutableAudit
    let project: MCPProjectIdentity
    let reviewedFiles: [MCPReviewedArgumentFileAudit]
}

private enum MCPDraftInspectionWorker {
    static func inspect(draft: MCPServerDraft, projectRoot: URL) async throws -> MCPDraftInspection {
        try await Task.detached(priority: .userInitiated) {
            let project = try MCPProjectInspector.inspect(projectRoot)
            let executable = try MCPExecutableInspector.inspect(URL(fileURLWithPath: draft.executablePath))
            let reviewedFiles = try draft.reviewedFileArgumentIndexes.sorted().map { index in
                try MCPExecutableInspector.inspectReviewedArgumentFile(
                    path: draft.arguments[index],
                    index: index
                )
            }
            return MCPDraftInspection(
                executable: executable,
                project: project,
                reviewedFiles: reviewedFiles
            )
        }.value
    }
}

enum MCPCenterConfirmation: Equatable, Sendable {
    case revoke(id: String, displayName: String)
    case remove(id: String, displayName: String)
}

enum MCPCenterNotice: Equatable, Sendable {
    case recordsUnavailable
    case verificationFailed(count: Int)
    case revokeFailed
    case removeFailed
    case applyFailed

    var title: String {
        switch self {
        case .recordsUnavailable: "MCP servers are unavailable"
        case .verificationFailed: "MCP verification did not finish"
        case .revokeFailed: "Approval was not revoked"
        case .removeFailed: "Server was not removed"
        case .applyFailed: "MCP servers were not applied"
        }
    }

    var message: String {
        switch self {
        case .recordsUnavailable:
            "Fulmar could not read the reviewed MCP definitions. No server will be made available until the records can be read safely."
        case let .verificationFailed(count):
            "Fulmar could not verify \(count) server\(count == 1 ? "" : "s"). They remain unavailable until verification succeeds."
        case .revokeFailed:
            "Fulmar could not revoke this approval. Its current state was not changed."
        case .removeFailed:
            "Fulmar could not remove this definition. Its current state was not changed."
        case .applyFailed:
            "Fulmar could not restart the protected runtime. The new MCP configuration was not applied."
        }
    }
}

private enum MCPCenterPresentationFailure: Error {
    case invalidRecords
}

typealias MCPCenterResultHandler<Value> = @MainActor (Result<Value, any Error>) -> Void
typealias MCPCenterConfirmationHandler = @MainActor (Bool) -> Void

struct MCPCenterOperations {
    let records: @MainActor () throws -> [MCPServerTrustRecord]
    let inspect: @MainActor (
        MCPServerDraft,
        @escaping MCPCenterResultHandler<MCPDraftInspection>
    ) -> Void
    let persist: @MainActor (
        MCPServerDraft,
        Bool,
        @escaping MCPCenterResultHandler<MCPServerTrustRecord>
    ) -> Void
    let verify: @MainActor (
        [String],
        @escaping MCPCenterResultHandler<MCPStatusBatch>
    ) -> Void
    let revoke: @MainActor (String, @escaping MCPCenterResultHandler<Void>) -> Void
    let remove: @MainActor (String, @escaping MCPCenterResultHandler<Void>) -> Void

    @MainActor
    static func production(store: MCPTrustStore, projectRoot: URL) -> Self {
        let storeBox = MCPTrustStoreSendableBox(store)
        let standardizedProjectRoot = projectRoot.standardizedFileURL
        return Self(
            records: { storeBox.store.records() },
            inspect: { draft, completion in
                Task { @MainActor in
                    do {
                        completion(.success(try await MCPDraftInspectionWorker.inspect(
                            draft: draft,
                            projectRoot: standardizedProjectRoot
                        )))
                    } catch {
                        completion(.failure(error))
                    }
                }
            },
            persist: { draft, approve, completion in
                Task { @MainActor in
                    do {
                        let saved = try await Task.detached(priority: .userInitiated) {
                            let record = try storeBox.store.saveDraft(
                                draft,
                                projectRoot: standardizedProjectRoot
                            )
                            if approve { return try storeBox.store.approve(id: record.id) }
                            try storeBox.store.revoke(id: record.id)
                            guard let disabled = storeBox.store.record(id: record.id) else {
                                throw MCPTrustStoreError.recordNotFound
                            }
                            return disabled
                        }.value
                        completion(.success(saved))
                    } catch {
                        completion(.failure(error))
                    }
                }
            },
            verify: { ids, completion in
                Task { @MainActor in
                    let batch = await Task.detached(priority: .userInitiated) {
                        var statuses: [String: MCPTrustStatus] = [:]
                        var failedIDs = Set<String>()
                        for id in ids {
                            do { statuses[id] = try storeBox.store.status(id: id) }
                            catch { failedIDs.insert(id) }
                        }
                        return MCPStatusBatch(statuses: statuses, failedIDs: failedIDs)
                    }.value
                    completion(.success(batch))
                }
            },
            revoke: { id, completion in
                Task { @MainActor in
                    do {
                        try await Task.detached(priority: .userInitiated) {
                            try storeBox.store.revoke(id: id)
                        }.value
                        completion(.success(()))
                    } catch {
                        completion(.failure(error))
                    }
                }
            },
            remove: { id, completion in
                Task { @MainActor in
                    do {
                        try await Task.detached(priority: .userInitiated) {
                            try storeBox.store.remove(id: id)
                        }.value
                        completion(.success(()))
                    } catch {
                        completion(.failure(error))
                    }
                }
            }
        )
    }
}

struct MCPCenterInteractions {
    let beginSheet: @MainActor (NSWindow, NSWindow) -> Void
    let endSheet: @MainActor (NSWindow, NSWindow) -> Void
    let confirm: @MainActor (
        MCPCenterConfirmation,
        NSWindow,
        @escaping MCPCenterConfirmationHandler
    ) -> Void
    let presentNotice: @MainActor (MCPCenterNotice, NSWindow?) -> Void

    static let production = Self(
        beginSheet: { host, sheet in host.beginSheet(sheet) },
        endSheet: { host, sheet in host.endSheet(sheet) },
        confirm: { confirmation, host, completion in
            let alert = NSAlert()
            alert.alertStyle = .warning
            switch confirmation {
            case let .revoke(_, displayName):
                alert.messageText = "Revoke \(displayName)?"
                alert.informativeText = "Its tools will stop being available after Apply & Restart. The reviewed definition stays in the list and can be approved again later."
                alert.addButton(withTitle: "Revoke Approval")
            case let .remove(_, displayName):
                alert.messageText = "Remove \(displayName)?"
                alert.informativeText = "This removes the saved MCP definition and approval. It does not delete the server executable, project files, or credentials."
                alert.addButton(withTitle: "Remove Definition")
                alert.buttons.first?.hasDestructiveAction = true
            }
            alert.addButton(withTitle: "Cancel")
            alert.beginSheetModal(for: host) { response in
                completion(response == .alertFirstButtonReturn)
            }
        },
        presentNotice: { notice, host in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = notice.title
            alert.informativeText = notice.message
            alert.addButton(withTitle: "OK")
            if let host { alert.beginSheetModal(for: host) }
            else { alert.runModal() }
        }
    )
}

/// Native control plane for project-bound local stdio MCP servers. This window
/// stores definitions and trust decisions only; activation remains the
/// HarnessController's responsibility after the explicit Apply & Restart step.
@MainActor
final class MCPCenterWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate {
    var onApplyAndRestart: (@MainActor () async throws -> Void)?

    private let projectRoot: URL
    private let providerChoices: [MCPProviderChoice]
    private let operations: MCPCenterOperations
    private let interactions: MCPCenterInteractions

    private let tableView = NSTableView()
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let emptyLabel = NSTextField(wrappingLabelWithString: "No MCP servers are configured for this project.")
    private let selectionTitle = NSTextField(labelWithString: "No server selected")
    private let selectionStatus = NSTextField(labelWithString: "")
    private let selectionSummary = NSTextField(wrappingLabelWithString: "Add a local stdio server to expose its tools through DeepSeek Harness.")
    private let selectionFingerprint = NSTextField(wrappingLabelWithString: "")
    private let addButton = NSButton(title: "Add Server…", target: nil, action: nil)
    private let editButton = NSButton(title: "Edit…", target: nil, action: nil)
    private let verifyButton = NSButton(title: "Verify Files", target: nil, action: nil)
    private let revokeButton = NSButton(title: "Revoke", target: nil, action: nil)
    private let removeButton = NSButton(title: "Remove…", target: nil, action: nil)
    private let applyButton = NSButton(title: "Apply & Restart Agent Service", target: nil, action: nil)

    private var records: [MCPServerTrustRecord] = []
    private var displayedStatuses: [String: MCPTrustStatus] = [:]
    private var operationInProgress = false
    private var recordsAvailable = true
    private var mainOperationToken: UUID?
    private var editorOperationToken: UUID?
    private var reviewOperationToken: UUID?
    private var restartNeeded = false
    private var editorController: MCPServerEditorSheetController?
    private var reviewController: MCPServerReviewSheetController?

    init(
        store: MCPTrustStore,
        projectRoot: URL,
        providerChoices: [MCPProviderChoice],
        onApplyAndRestart: (@MainActor () async throws -> Void)? = nil,
        operations: MCPCenterOperations? = nil,
        interactions: MCPCenterInteractions = .production
    ) {
        self.projectRoot = projectRoot.standardizedFileURL
        let uniqueChoices = Self.uniqueProviderChoices(providerChoices)
        self.providerChoices = uniqueChoices.count <= 64 ? uniqueChoices : []
        self.onApplyAndRestart = onApplyAndRestart
        self.operations = operations ?? .production(store: store, projectRoot: projectRoot)
        self.interactions = interactions

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_040, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "MCP Servers"
        window.subtitle = "Reviewed local tools for this project"
        window.minSize = NSSize(width: 860, height: 560)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.MCPCenter")
        super.init(window: window)
        window.delegate = self
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.MCPCenter") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    static func safeProjectName(_ url: URL) -> String {
        AuxiliaryDisplayPolicy.singleLine(
            url.lastPathComponent,
            maximumCharacters: 180,
            fallback: "approved project"
        )
    }

    override func showWindow(_ sender: Any?) {
        let loaded = !operationInProgress && reloadRecords()
        super.showWindow(sender)
        if loaded, !operationInProgress { verifyAllRecords() }
    }

    func windowWillClose(_ notification: Notification) {
        mainOperationToken = nil
        editorOperationToken = nil
        reviewOperationToken = nil
        operationInProgress = false
        editorController = nil
        reviewController = nil
        updateControls()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { records.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard records.indices.contains(row), let tableColumn else { return nil }
        let record = records[row]
        let field = NSTextField(labelWithString: "")
        field.lineBreakMode = .byTruncatingMiddle
        switch tableColumn.identifier.rawValue {
        case "state":
            let presentation = statusPresentation(displayedStatuses[record.id])
            field.stringValue = presentation.text
            field.textColor = presentation.color
            field.font = .systemFont(ofSize: 11.5, weight: .semibold)
        case "provider":
            field.stringValue = safeInline(providerSummary(record.draft.allowedProviders), limit: 120)
            field.textColor = .secondaryLabelColor
            field.toolTip = safeInline(providerLongSummary(record.draft.allowedProviders), limit: 500)
        default:
            field.stringValue = safeInline(record.draft.displayName, limit: 160)
            field.font = .systemFont(ofSize: 13, weight: .medium)
            field.toolTip = safeInline(record.draft.serverName, limit: 160)
        }
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        presentSelection()
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = AppearanceAwareLayerView()
        root.semanticBackgroundColor = .windowBackgroundColor

        let title = NSTextField(labelWithString: "MCP Servers")
        title.font = .systemFont(ofSize: 25, weight: .bold)
        let subtitle = NSTextField(wrappingLabelWithString:
            "Connect reviewed local stdio tool servers to DeepSeek Harness. Trust is bound to this exact project, executable, configuration, and model-provider boundary."
        )
        subtitle.textColor = .secondaryLabelColor
        subtitle.font = .systemFont(ofSize: 12.5)
        let heading = NSStackView(views: [title, subtitle])
        heading.orientation = .vertical
        heading.alignment = .leading
        heading.spacing = 4

        let nameColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("name"))
        nameColumn.title = "Server"
        nameColumn.width = 170
        let stateColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("state"))
        stateColumn.title = "Trust"
        stateColumn.width = 82
        let providerColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("provider"))
        providerColumn.title = "Allowed with"
        providerColumn.width = 130
        [nameColumn, stateColumn, providerColumn].forEach(tableView.addTableColumn)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 32
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.allowsEmptySelection = true
        tableView.setAccessibilityLabel("Configured MCP servers")

        let tableScroll = NSScrollView()
        tableScroll.documentView = tableView
        tableScroll.hasVerticalScroller = true
        tableScroll.hasHorizontalScroller = true
        tableScroll.autohidesScrollers = true
        tableScroll.translatesAutoresizingMaskIntoConstraints = false

        emptyLabel.alignment = .center
        emptyLabel.textColor = .tertiaryLabelColor
        emptyLabel.font = .systemFont(ofSize: 12)
        emptyLabel.setAccessibilityLabel("MCP server empty state")

        configureButton(addButton, action: #selector(addServer(_:)))
        let leftActions = NSStackView(views: [addButton, NSView()])
        leftActions.orientation = .horizontal
        leftActions.spacing = 8

        let left = NSView()
        tableScroll.translatesAutoresizingMaskIntoConstraints = false
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        leftActions.translatesAutoresizingMaskIntoConstraints = false
        left.addSubview(tableScroll)
        left.addSubview(emptyLabel)
        left.addSubview(leftActions)
        NSLayoutConstraint.activate([
            tableScroll.topAnchor.constraint(equalTo: left.topAnchor),
            tableScroll.leadingAnchor.constraint(equalTo: left.leadingAnchor),
            tableScroll.trailingAnchor.constraint(equalTo: left.trailingAnchor),
            leftActions.topAnchor.constraint(equalTo: tableScroll.bottomAnchor, constant: 10),
            leftActions.leadingAnchor.constraint(equalTo: left.leadingAnchor),
            leftActions.trailingAnchor.constraint(equalTo: left.trailingAnchor),
            leftActions.bottomAnchor.constraint(equalTo: left.bottomAnchor),
            emptyLabel.centerXAnchor.constraint(equalTo: tableScroll.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: tableScroll.centerYAnchor),
            emptyLabel.widthAnchor.constraint(lessThanOrEqualTo: tableScroll.widthAnchor, constant: -50)
        ])

        selectionTitle.font = .systemFont(ofSize: 20, weight: .semibold)
        selectionStatus.font = .systemFont(ofSize: 12, weight: .semibold)
        selectionSummary.font = .systemFont(ofSize: 12.5)
        selectionSummary.textColor = .secondaryLabelColor
        selectionSummary.maximumNumberOfLines = 0
        selectionFingerprint.font = .monospacedSystemFont(ofSize: 10.5, weight: .regular)
        selectionFingerprint.textColor = .tertiaryLabelColor
        selectionFingerprint.maximumNumberOfLines = 0

        configureButton(editButton, action: #selector(editServer(_:)))
        configureButton(verifyButton, action: #selector(verifyAction(_:)))
        configureButton(revokeButton, action: #selector(revokeServer(_:)))
        configureButton(removeButton, action: #selector(removeServer(_:)))
        removeButton.hasDestructiveAction = true
        let detailActions = NSStackView(views: [editButton, verifyButton, revokeButton, NSView(), removeButton])
        detailActions.orientation = .horizontal
        detailActions.spacing = 8

        let securityNote = NSTextField(wrappingLabelWithString:
            "Every server starts with a minimal environment and project-confined filesystem access. Credential values stay in the credential service; only reference names are saved here. MCP tool calls remain subject to native approval."
        )
        securityNote.font = .systemFont(ofSize: 10.5)
        securityNote.textColor = .secondaryLabelColor

        let detailStack = NSStackView(views: [
            selectionTitle, selectionStatus, Self.divider(), selectionSummary,
            selectionFingerprint, NSView(), securityNote, detailActions
        ])
        detailStack.orientation = .vertical
        detailStack.alignment = .leading
        detailStack.spacing = 12
        detailStack.translatesAutoresizingMaskIntoConstraints = false
        for arranged in [selectionSummary, selectionFingerprint, securityNote, detailActions] {
            arranged.translatesAutoresizingMaskIntoConstraints = false
            arranged.widthAnchor.constraint(equalTo: detailStack.widthAnchor).isActive = true
        }

        let detail = AppearanceAwareLayerView()
        detail.semanticBackgroundColor = .controlBackgroundColor
        detail.layer?.cornerRadius = 12
        detail.addSubview(detailStack)
        NSLayoutConstraint.activate([
            detailStack.topAnchor.constraint(equalTo: detail.topAnchor, constant: 20),
            detailStack.leadingAnchor.constraint(equalTo: detail.leadingAnchor, constant: 20),
            detailStack.trailingAnchor.constraint(equalTo: detail.trailingAnchor, constant: -20),
            detailStack.bottomAnchor.constraint(equalTo: detail.bottomAnchor, constant: -18)
        ])

        let panes = NSStackView(views: [left, detail])
        panes.orientation = .horizontal
        panes.alignment = .top
        panes.spacing = 16
        panes.distribution = .fill
        left.widthAnchor.constraint(equalToConstant: 410).isActive = true
        left.heightAnchor.constraint(equalTo: panes.heightAnchor).isActive = true
        detail.heightAnchor.constraint(equalTo: panes.heightAnchor).isActive = true

        statusLabel.font = .systemFont(ofSize: 11.5)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setAccessibilityLabel("MCP server status")
        configureButton(applyButton, action: #selector(applyAndRestart(_:)))
        applyButton.keyEquivalent = "\r"
        let footer = NSStackView(views: [statusLabel, NSView(), applyButton])
        footer.orientation = .horizontal
        footer.alignment = .centerY
        footer.spacing = 12

        let content = NSStackView(views: [heading, panes, footer])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 16
        content.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(content)
        panes.translatesAutoresizingMaskIntoConstraints = false
        footer.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: root.topAnchor, constant: 24),
            content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            content.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -20),
            heading.widthAnchor.constraint(equalTo: content.widthAnchor),
            panes.widthAnchor.constraint(equalTo: content.widthAnchor),
            panes.heightAnchor.constraint(greaterThanOrEqualToConstant: 390),
            footer.widthAnchor.constraint(equalTo: content.widthAnchor)
        ])
        controller.view = root
        updateControls()
        return controller
    }

    private var selectedRecord: MCPServerTrustRecord? {
        records.indices.contains(tableView.selectedRow) ? records[tableView.selectedRow] : nil
    }

    @discardableResult
    private func reloadRecords(retaining recordID: String? = nil) -> Bool {
        do {
            let loaded = try operations.records()
            guard loaded.count <= 256,
                  Set(loaded.map(\.id)).count == loaded.count,
                  loaded.allSatisfy({ record in
                      record.id.utf8.count <= 256
                          && SessionHistorySafeText.inline(record.id, limit: 256) == record.id
                  }) else {
                throw MCPCenterPresentationFailure.invalidRecords
            }
            records = loaded
            recordsAvailable = true
            emptyLabel.stringValue = "No MCP servers are configured for this project."
        } catch {
            recordsAvailable = false
            records = []
            displayedStatuses = [:]
            tableView.reloadData()
            tableView.isHidden = true
            emptyLabel.isHidden = false
            emptyLabel.stringValue = "MCP definitions could not be read safely."
            presentSelection()
            statusLabel.stringValue = MCPCenterNotice.recordsUnavailable.message
            statusLabel.textColor = .systemRed
            interactions.presentNotice(.recordsUnavailable, window)
            return false
        }
        for record in records where displayedStatuses[record.id] == nil {
            displayedStatuses[record.id] = record.approval == nil ? .unreviewed : .trusted
        }
        let validIDs = Set(records.map(\.id))
        displayedStatuses = displayedStatuses.filter { validIDs.contains($0.key) }
        tableView.reloadData()
        emptyLabel.isHidden = !records.isEmpty
        tableView.isHidden = records.isEmpty
        if let recordID, let row = records.firstIndex(where: { $0.id == recordID }) {
            tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        } else if !records.isEmpty, !records.indices.contains(tableView.selectedRow) {
            tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        } else {
            presentSelection()
        }
        updateCatalogStatus()
        return true
    }

    private func presentSelection() {
        guard let record = selectedRecord else {
            selectionTitle.stringValue = "No server selected"
            selectionStatus.stringValue = ""
            selectionSummary.stringValue = records.isEmpty
                ? "Add a reviewed local stdio server to make its tools available in Harness."
                : "Select a server to inspect its permissions and trust state."
            selectionFingerprint.stringValue = ""
            updateControls()
            return
        }
        let presentation = statusPresentation(displayedStatuses[record.id])
        selectionTitle.stringValue = safeInline(record.draft.displayName, limit: 160)
        selectionStatus.stringValue = presentation.detail
        selectionStatus.textColor = presentation.color

        let workingDirectory = safeInline(
            record.draft.projectRelativeWorkingDirectory ?? "Project root",
            limit: 500
        )
        let disclosure = safeInline(disclosureSummary(record.draft.disclosure), limit: 500)
        let credentials = record.draft.environment.isEmpty
            ? "None"
            : record.draft.environment
                .sorted { $0.variableName < $1.variableName }
                .prefix(64)
                .map {
                    "\(safeInline($0.variableName, limit: 128)) ← \(safeInline($0.credential.rawValue, limit: 256))"
                }
                .joined(separator: ", ")
        selectionSummary.stringValue = """
        Tool namespace: \(safeInline(record.draft.serverName, limit: 160))
        Transport: Local stdio · no shell
        Executable: \(safeInline(record.draft.executablePath, limit: 1_024))
        Working folder: \(workingDirectory)
        Allowed providers: \(safeInline(providerLongSummary(record.draft.allowedProviders), limit: 1_000))
        MCP disclosure: \(disclosure)
        Credential references: \(credentials)
        Limits: \(record.draft.limits.maximumDiscoveredTools) tools · \(Self.formatBytes(record.draft.limits.maximumOutputBytes)) output · \(record.draft.limits.toolCallTimeoutMilliseconds / 1_000)s per call
        """
        if let approval = record.approval {
            selectionFingerprint.stringValue = "Review fingerprint  \(safeInline(approval.reviewFingerprint, limit: 256))\nApproved  \(Self.dateFormatter.string(from: approval.approvedAt))\nProject  \(safeInline(record.project.canonicalPath, limit: 1_024))"
        } else {
            selectionFingerprint.stringValue = "Not active. Review and approve this exact definition before applying it.\nProject  \(safeInline(record.project.canonicalPath, limit: 1_024))"
        }
        updateControls()
    }

    private func updateCatalogStatus() {
        guard !operationInProgress else { return }
        let trusted = displayedStatuses.values.filter { $0 == .trusted }.count
        let attention = displayedStatuses.values.filter { $0 != .trusted }.count
        if providerChoices.isEmpty {
            statusLabel.stringValue = "No provider catalog is available. Refresh Models & Providers before adding a server."
            statusLabel.textColor = .systemOrange
        } else if records.isEmpty {
            statusLabel.stringValue = "Nothing starts until a definition is reviewed, approved, and applied."
            statusLabel.textColor = .secondaryLabelColor
        } else {
            statusLabel.stringValue = "\(trusted) approved · \(attention) disabled or needing review"
            statusLabel.textColor = attention == 0 ? .secondaryLabelColor : .systemOrange
        }
    }

    private func updateControls() {
        let hasSelection = selectedRecord != nil
        let selectedStatus = selectedRecord.flatMap { displayedStatuses[$0.id] }
        tableView.isEnabled = !operationInProgress && recordsAvailable
        addButton.isEnabled = !operationInProgress && recordsAvailable && !providerChoices.isEmpty
        editButton.isEnabled = !operationInProgress && hasSelection
        verifyButton.isEnabled = !operationInProgress && !records.isEmpty
        revokeButton.isEnabled = !operationInProgress && selectedStatus == .trusted
        removeButton.isEnabled = !operationInProgress && hasSelection
        applyButton.isEnabled = !operationInProgress && restartNeeded
    }

    private func setBusy(_ busy: Bool, message: String) {
        operationInProgress = busy
        statusLabel.stringValue = message
        statusLabel.textColor = .secondaryLabelColor
        updateControls()
    }

    @objc private func addServer(_ sender: Any?) {
        guard !operationInProgress, editorController == nil, reviewController == nil else { return }
        presentEditor(record: nil)
    }

    @objc private func editServer(_ sender: Any?) {
        guard !operationInProgress, editorController == nil, reviewController == nil,
              let selectedRecord else { return }
        presentEditor(record: selectedRecord)
    }

    private func presentEditor(record: MCPServerTrustRecord?) {
        guard let window, editorController == nil, reviewController == nil else { return }
        let choices = mergedProviderChoices(for: record)
        let editor = MCPServerEditorSheetController(
            projectRoot: projectRoot,
            providerChoices: choices,
            existing: record?.draft
        )
        editor.onCancel = { [weak self, weak editor] in
            guard let self, let editor, self.editorController === editor,
                  self.editorOperationToken == nil, let sheet = editor.window,
                  let host = self.window else { return }
            self.interactions.endSheet(host, sheet)
            self.editorController = nil
        }
        editor.onReview = { [weak self, weak editor] draft in
            guard let self, let editor else { return }
            self.inspectForReview(draft: draft, editor: editor)
        }
        editorController = editor
        if let sheet = editor.window { interactions.beginSheet(window, sheet) }
    }

    private func inspectForReview(draft: MCPServerDraft, editor: MCPServerEditorSheetController) {
        guard editorController === editor, editorOperationToken == nil else { return }
        let token = UUID()
        editorOperationToken = token
        editor.setBusy(true, message: "Fingerprinting the exact executable and reviewed entry files…")
        operations.inspect(draft) { [weak self, weak editor] result in
            guard let self, let editor, self.editorController === editor,
                  self.editorOperationToken == token else { return }
            self.editorOperationToken = nil
            switch result {
            case let .success(inspection):
                editor.setBusy(false, message: "")
                self.presentReview(draft: draft, inspection: inspection, editor: editor)
            case .failure:
                editor.setBusy(
                    false,
                    message: "Fulmar could not verify the executable and reviewed entry files. Check the selected paths and try again.",
                    isError: true
                )
            }
        }
    }

    private func presentReview(
        draft: MCPServerDraft,
        inspection: MCPDraftInspection,
        editor: MCPServerEditorSheetController
    ) {
        guard editorController === editor, let hostWindow = window,
              let editorWindow = editor.window else { return }
        interactions.endSheet(hostWindow, editorWindow)
        let review = MCPServerReviewSheetController(
            draft: draft,
            inspection: inspection,
            projectRoot: projectRoot,
            providerNames: Dictionary(uniqueKeysWithValues: providerChoices.map {
                (Self.providerKey($0.provider, $0.boundary), safeInline($0.displayName, limit: 256))
            })
        )
        review.onBack = { [weak self, weak review, weak editor] in
            guard let self, let review, let editor, self.reviewController === review,
                  self.reviewOperationToken == nil, let host = self.window,
                  let reviewWindow = review.window, let editorWindow = editor.window else { return }
            self.interactions.endSheet(host, reviewWindow)
            self.reviewController = nil
            self.interactions.beginSheet(host, editorWindow)
        }
        review.onSaveDisabled = { [weak self, weak review] in
            guard let self, let review else { return }
            self.persistReviewedDraft(draft, approve: false, review: review)
        }
        review.onApprove = { [weak self, weak review] in
            guard let self, let review else { return }
            self.persistReviewedDraft(draft, approve: true, review: review)
        }
        reviewController = review
        if let sheet = review.window { interactions.beginSheet(hostWindow, sheet) }
    }

    private func persistReviewedDraft(
        _ draft: MCPServerDraft,
        approve: Bool,
        review: MCPServerReviewSheetController
    ) {
        guard reviewController === review, reviewOperationToken == nil else { return }
        let token = UUID()
        reviewOperationToken = token
        review.setBusy(true, message: approve ? "Rechecking files and recording approval…" : "Saving the server disabled…")
        operations.persist(draft, approve) { [weak self, weak review] result in
            guard let self, let review, self.reviewController === review,
                  self.reviewOperationToken == token else { return }
            self.reviewOperationToken = nil
            switch result {
            case let .success(saved):
                if let sheet = review.window, let host = self.window {
                    self.interactions.endSheet(host, sheet)
                }
                self.editorController = nil
                self.reviewController = nil
                self.displayedStatuses[saved.id] = approve ? .trusted : .unreviewed
                self.restartNeeded = true
                guard self.reloadRecords(retaining: saved.id) else { return }
                let displayName = self.safeInline(saved.draft.displayName, limit: 160)
                self.statusLabel.stringValue = approve
                    ? "\(displayName) is approved. Apply & Restart to expose its tools."
                    : "\(displayName) was saved disabled."
                self.statusLabel.textColor = approve ? .systemGreen : .secondaryLabelColor
            case .failure:
                review.setBusy(
                    false,
                    message: "Fulmar could not save and verify this MCP definition. No new approval was recorded.",
                    isError: true
                )
            }
        }
    }

    @objc private func verifyAction(_ sender: Any?) {
        verifyAllRecords()
    }

    private func verifyAllRecords(completion: ((Bool) -> Void)? = nil) {
        guard !operationInProgress else {
            completion?(false)
            return
        }
        guard !records.isEmpty else {
            completion?(true)
            return
        }
        let ids = records.map(\.id)
        let requestedIDs = Set(ids)
        let token = UUID()
        mainOperationToken = token
        setBusy(true, message: "Verifying approved executable and entry-file fingerprints…")
        operations.verify(ids) { [weak self] result in
            guard let self, self.mainOperationToken == token else { return }
            self.mainOperationToken = nil
            self.operationInProgress = false
            let previouslyTrusted = Set(self.displayedStatuses.filter { $0.value == .trusted }.map(\.key))
            let failedIDs: Set<String>
            switch result {
            case let .success(batch):
                let returnedIDs = Set(batch.statuses.keys).intersection(requestedIDs)
                failedIDs = requestedIDs
                    .subtracting(returnedIDs)
                    .union(batch.failedIDs.intersection(requestedIDs))
                for id in requestedIDs {
                    self.displayedStatuses[id] = failedIDs.contains(id)
                        ? .changed
                        : batch.statuses[id] ?? .changed
                }
            case .failure:
                failedIDs = requestedIDs
                for id in requestedIDs { self.displayedStatuses[id] = .changed }
            }
            let revoked = previouslyTrusted.filter { self.displayedStatuses[$0] != .trusted }
            if !revoked.isEmpty { self.restartNeeded = true }
            let selectedID = self.selectedRecord?.id
            guard self.reloadRecords(retaining: selectedID) else {
                completion?(false)
                return
            }
            if failedIDs.isEmpty {
                self.statusLabel.stringValue = revoked.isEmpty
                    ? "Verification complete. Approved server files are unchanged."
                    : "\(revoked.count) approval\(revoked.count == 1 ? " was" : "s were") revoked because reviewed files changed."
                self.statusLabel.textColor = revoked.isEmpty ? .systemGreen : .systemRed
            } else {
                let notice = MCPCenterNotice.verificationFailed(count: failedIDs.count)
                self.statusLabel.stringValue = notice.message
                self.statusLabel.textColor = .systemRed
                self.interactions.presentNotice(notice, self.window)
            }
            self.updateControls()
            completion?(failedIDs.isEmpty)
        }
    }

    @objc private func revokeServer(_ sender: Any?) {
        guard !operationInProgress, let record = selectedRecord, let window else { return }
        let confirmationToken = UUID()
        mainOperationToken = confirmationToken
        setBusy(true, message: "Waiting for confirmation…")
        interactions.confirm(
            .revoke(id: record.id, displayName: safeInline(record.draft.displayName, limit: 160)),
            window
        ) { [weak self] confirmed in
            guard let self, self.mainOperationToken == confirmationToken else { return }
            guard confirmed else {
                self.mainOperationToken = nil
                self.operationInProgress = false
                self.updateCatalogStatus()
                self.updateControls()
                return
            }
            let mutationToken = UUID()
            self.mainOperationToken = mutationToken
            self.setBusy(true, message: "Revoking the reviewed approval…")
            self.operations.revoke(record.id) { [weak self] result in
                guard let self, self.mainOperationToken == mutationToken else { return }
                self.mainOperationToken = nil
                self.operationInProgress = false
                switch result {
                case .success:
                    self.displayedStatuses[record.id] = .unreviewed
                    self.restartNeeded = true
                    guard self.reloadRecords(retaining: record.id) else { return }
                    self.statusLabel.stringValue = "Approval revoked. Apply & Restart to remove its tools from the agent runtime."
                    self.statusLabel.textColor = .systemOrange
                case .failure:
                    let notice = MCPCenterNotice.revokeFailed
                    self.statusLabel.stringValue = notice.message
                    self.statusLabel.textColor = .systemRed
                    self.interactions.presentNotice(notice, self.window)
                    self.updateControls()
                }
            }
        }
    }

    @objc private func removeServer(_ sender: Any?) {
        guard !operationInProgress, let record = selectedRecord, let window else { return }
        let confirmationToken = UUID()
        mainOperationToken = confirmationToken
        setBusy(true, message: "Waiting for confirmation…")
        interactions.confirm(
            .remove(id: record.id, displayName: safeInline(record.draft.displayName, limit: 160)),
            window
        ) { [weak self] confirmed in
            guard let self, self.mainOperationToken == confirmationToken else { return }
            guard confirmed else {
                self.mainOperationToken = nil
                self.operationInProgress = false
                self.updateCatalogStatus()
                self.updateControls()
                return
            }
            let mutationToken = UUID()
            self.mainOperationToken = mutationToken
            self.setBusy(true, message: "Removing the reviewed definition…")
            self.operations.remove(record.id) { [weak self] result in
                guard let self, self.mainOperationToken == mutationToken else { return }
                self.mainOperationToken = nil
                self.operationInProgress = false
                switch result {
                case .success:
                    self.displayedStatuses.removeValue(forKey: record.id)
                    self.restartNeeded = true
                    guard self.reloadRecords() else { return }
                    self.statusLabel.stringValue = "Definition removed. The executable and credentials were not changed."
                    self.statusLabel.textColor = .secondaryLabelColor
                case .failure:
                    let notice = MCPCenterNotice.removeFailed
                    self.statusLabel.stringValue = notice.message
                    self.statusLabel.textColor = .systemRed
                    self.interactions.presentNotice(notice, self.window)
                    self.updateControls()
                }
            }
        }
    }

    @objc private func applyAndRestart(_ sender: Any?) {
        verifyAllRecords { [weak self] verificationSucceeded in
            guard let self, verificationSucceeded else { return }
            let trustedCount = displayedStatuses.values.filter { $0 == .trusted }.count
            guard let apply = onApplyAndRestart else {
                statusLabel.stringValue = "MCP servers were not applied because protected runtime coordination is unavailable."
                statusLabel.textColor = .systemRed
                updateControls()
                return
            }
            let token = UUID()
            mainOperationToken = token
            setBusy(true, message: "Stopping the exact old runtime before applying \(trustedCount) approved server\(trustedCount == 1 ? "" : "s")…")
            statusLabel.textColor = .secondaryLabelColor
            Task { @MainActor [weak self] in
                guard let self else { return }
                do {
                    try await apply()
                    guard self.mainOperationToken == token else { return }
                    self.mainOperationToken = nil
                    self.restartNeeded = false
                    self.operationInProgress = false
                    self.updateControls()
                    self.statusLabel.stringValue = "Approved MCP servers are active in a fresh verified runtime."
                    self.statusLabel.textColor = .systemGreen
                } catch {
                    guard self.mainOperationToken == token else { return }
                    self.mainOperationToken = nil
                    self.operationInProgress = false
                    self.updateControls()
                    let notice = MCPCenterNotice.applyFailed
                    self.statusLabel.stringValue = notice.message
                    self.statusLabel.textColor = .systemRed
                    self.interactions.presentNotice(notice, self.window)
                }
            }
        }
    }

    private func providerSummary(_ providers: [MCPProviderEnablement]) -> String {
        guard providers.count == 1, let provider = providers.first else {
            return "\(providers.count) routes"
        }
        return displayName(for: provider.provider, boundary: provider.boundary)
    }

    private func providerLongSummary(_ providers: [MCPProviderEnablement]) -> String {
        providers.map { provider in
            "\(displayName(for: provider.provider, boundary: provider.boundary)) — \(provider.boundary.displayName)"
        }.joined(separator: ", ")
    }

    private func displayName(for provider: ProviderID, boundary: DataBoundary) -> String {
        providerChoices.first {
            $0.provider == provider && $0.boundary == boundary
        }?.displayName ?? provider.rawValue
    }

    private func disclosureSummary(_ disclosure: MCPDisclosureProfile) -> String {
        let kinds = disclosure.dataKinds.map(Self.dataKindTitle).joined(separator: ", ")
        if let destination = disclosure.destinationName {
            return "\(disclosure.boundary.displayName) to \(destination) · \(kinds)"
        }
        return "\(disclosure.boundary.displayName) · \(kinds)"
    }

    private func mergedProviderChoices(for record: MCPServerTrustRecord?) -> [MCPProviderChoice] {
        var result = providerChoices
        for allowed in record?.draft.allowedProviders ?? [] where !result.contains(where: {
            $0.provider == allowed.provider && $0.boundary == allowed.boundary
        }) {
            result.append(MCPProviderChoice(
                provider: allowed.provider,
                displayName: "Unlisted provider · \(allowed.provider.rawValue)",
                boundary: allowed.boundary
            ))
        }
        return Self.uniqueProviderChoices(result)
    }

    private func statusPresentation(_ status: MCPTrustStatus?) -> (text: String, detail: String, color: NSColor) {
        switch status {
        case .trusted:
            return ("Approved", "Approved · reviewed files match", .systemGreen)
        case .changed:
            return ("Changed", "Disabled · a reviewed file or project identity changed", .systemRed)
        case .unreviewed:
            return ("Disabled", "Disabled · approval required", .systemOrange)
        case nil:
            return ("Checking", "Checking reviewed files…", .secondaryLabelColor)
        }
    }

    private func configureButton(_ button: NSButton, action: Selector) {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
    }

    private func safeInline(_ value: String, limit: Int) -> String {
        let safe = SessionHistorySafeText.inline(value, limit: limit)
        return safe.isEmpty ? "Unavailable" : safe
    }

    private static func uniqueProviderChoices(_ values: [MCPProviderChoice]) -> [MCPProviderChoice] {
        var seen = Set<String>()
        return values.filter { seen.insert(providerKey($0.provider, $0.boundary)).inserted }
            .sorted {
                if $0.boundary != $1.boundary {
                    return boundaryOrder($0.boundary) < boundaryOrder($1.boundary)
                }
                return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
            }
    }

    private static func providerKey(_ provider: ProviderID, _ boundary: DataBoundary) -> String {
        "\(boundary.rawValue)\u{1F}\(provider.rawValue)"
    }

    private static func boundaryOrder(_ boundary: DataBoundary) -> Int {
        switch boundary {
        case .onDevice: return 0
        case .localNetwork: return 1
        case .cloud: return 2
        }
    }

    fileprivate static func dataKindTitle(_ kind: MCPDisclosureDataKind) -> String {
        switch kind {
        case .accountData: return "Account data"
        case .authenticationMetadata: return "Authentication metadata"
        case .fileContents: return "File contents"
        case .fileNames: return "File names"
        case .projectMetadata: return "Project metadata"
        case .toolArguments: return "Tool arguments"
        case .toolResults: return "Tool results"
        }
    }

    private static func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private static func divider() -> NSView {
        let view = NSBox()
        view.boxType = .separator
        return view
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

private enum MCPServerEditorError: LocalizedError {
    case invalidField(String)

    var errorDescription: String? {
        switch self {
        case .invalidField(let description): return description
        }
    }
}

@MainActor
final class MCPServerEditorSheetController: NSWindowController, NSTextFieldDelegate {
    var onCancel: (() -> Void)?
    var onReview: ((MCPServerDraft) -> Void)?

    private let projectRoot: URL
    private let providerChoices: [MCPProviderChoice]
    private let existing: MCPServerDraft?

    private let identifierField = NSTextField()
    private let displayNameField = NSTextField()
    private let serverNameField = NSTextField()
    private let executableField = NSTextField()
    private let argumentsView = NSTextView()
    private let reviewedIndexesField = NSTextField()
    private let workingDirectoryField = NSTextField()
    private let credentialBindingsView = NSTextView()
    private var providerButtons: [NSButton] = []
    private let disclosureBoundaryPicker = NSPopUpButton()
    private let destinationField = NSTextField()
    private var dataKindButtons: [MCPDisclosureDataKind: NSButton] = [:]
    private let startupSecondsField = NSTextField()
    private let toolSecondsField = NSTextField()
    private let maximumToolsField = NSTextField()
    private let maximumOutputKiBField = NSTextField()
    private let reconnectButton = NSButton(checkboxWithTitle: "Reconnect after an unexpected exit", target: nil, action: nil)
    private let reconnectAttemptsField = NSTextField()
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let reviewButton = NSButton(title: "Review Definition…", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)
    private var lastGeneratedIdentifier = ""
    private var lastGeneratedNamespace = ""

    init(projectRoot: URL, providerChoices: [MCPProviderChoice], existing: MCPServerDraft?) {
        self.projectRoot = projectRoot
        self.providerChoices = providerChoices
        self.existing = existing
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 780, height: 760),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        panel.title = existing == nil ? "Add MCP Server" : "Edit MCP Server"
        panel.minSize = NSSize(width: 780, height: 760)
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        panel.contentViewController = buildContent()
        populate()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func setBusy(_ busy: Bool, message: String, isError: Bool = false) {
        reviewButton.isEnabled = !busy
        cancelButton.isEnabled = !busy
        errorLabel.stringValue = message
        errorLabel.textColor = isError ? .systemRed : .secondaryLabelColor
    }

    func controlTextDidChange(_ obj: Notification) {
        if obj.object as? NSTextField === displayNameField, existing == nil {
            let slug = Self.slug(displayNameField.stringValue)
            if identifierField.stringValue.isEmpty || identifierField.stringValue == lastGeneratedIdentifier {
                identifierField.stringValue = slug
                lastGeneratedIdentifier = slug
            }
            let namespace = Self.namespaceSlug(displayNameField.stringValue)
            if serverNameField.stringValue.isEmpty || serverNameField.stringValue == lastGeneratedNamespace {
                serverNameField.stringValue = namespace
                lastGeneratedNamespace = namespace
            }
        }
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let title = NSTextField(labelWithString: existing == nil ? "Add a local MCP server" : "Edit local MCP server")
        title.font = .systemFont(ofSize: 22, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString:
            "\(ProductBrand.displayName) launches one exact executable directly—never through a shell. All paths and permissions are inspected before you can approve it."
        )
        subtitle.font = .systemFont(ofSize: 12)
        subtitle.textColor = .secondaryLabelColor

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false

        let document = NSView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document

        let form = NSStackView()
        form.orientation = .vertical
        form.alignment = .leading
        form.spacing = 16
        form.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(form)

        displayNameField.delegate = self
        identifierField.placeholderString = "stable-definition-id"
        displayNameField.placeholderString = "GitHub project tools"
        serverNameField.placeholderString = "github_tools"
        executableField.placeholderString = "/absolute/path/to/server"
        workingDirectoryField.placeholderString = "Blank = project root; for example tools/mcp"
        reviewedIndexesField.placeholderString = "For example: 1, 3"
        identifierField.setAccessibilityLabel("MCP definition ID")
        displayNameField.setAccessibilityLabel("MCP display name")
        serverNameField.setAccessibilityLabel("MCP tool namespace")
        executableField.setAccessibilityLabel("MCP executable path")
        reviewedIndexesField.setAccessibilityLabel("MCP code-file argument indexes")
        workingDirectoryField.setAccessibilityLabel("MCP working folder")

        let executableChoose = NSButton(title: "Choose…", target: self, action: #selector(chooseExecutable(_:)))
        executableChoose.setAccessibilityLabel("Choose MCP server executable")
        let executableRow = NSStackView(views: [executableField, executableChoose])
        executableRow.orientation = .horizontal
        executableRow.spacing = 8
        executableField.setContentHuggingPriority(.defaultLow, for: .horizontal)

        argumentsView.isRichText = false
        argumentsView.isAutomaticQuoteSubstitutionEnabled = false
        argumentsView.isAutomaticDashSubstitutionEnabled = false
        argumentsView.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        argumentsView.string = ""
        argumentsView.setAccessibilityLabel("MCP literal arguments")
        let argumentsScroll = Self.textScroll(argumentsView, height: 104)

        credentialBindingsView.isRichText = false
        credentialBindingsView.isAutomaticQuoteSubstitutionEnabled = false
        credentialBindingsView.isAutomaticDashSubstitutionEnabled = false
        credentialBindingsView.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        credentialBindingsView.setAccessibilityLabel("MCP credential reference bindings")
        let credentialsScroll = Self.textScroll(credentialBindingsView, height: 78)

        form.addArrangedSubview(Self.sectionTitle("Identity & command"))
        form.addArrangedSubview(Self.formRow(
            title: "Definition ID",
            control: identifierField,
            help: "A stable identifier. It cannot be changed after this definition is created."
        ))
        form.addArrangedSubview(Self.formRow(title: "Display name", control: displayNameField))
        form.addArrangedSubview(Self.formRow(
            title: "Tool namespace",
            control: serverNameField,
            help: "1–32 letters, numbers, underscores, or hyphens. Tool names are grouped under this namespace."
        ))
        form.addArrangedSubview(Self.formRow(
            title: "Executable",
            control: executableRow,
            help: "Choose the executable itself, such as node or python—not a shell command."
        ))
        form.addArrangedSubview(Self.formRow(
            title: "Literal arguments",
            control: argumentsScroll,
            help: "One argument per line. Quotes, spaces, pipes, and semicolons are passed literally; they are never interpreted by a shell."
        ))
        form.addArrangedSubview(Self.formRow(
            title: "Code-file arguments",
            control: reviewedIndexesField,
            help: "1-based line numbers above that contain scripts/packages to fingerprint, such as a .mjs or .py entry point."
        ))
        form.addArrangedSubview(Self.formRow(
            title: "Working folder",
            control: workingDirectoryField,
            help: "Relative to approved project \(MCPCenterWindowController.safeProjectName(projectRoot)). Absolute paths and parent traversal are refused."
        ))

        form.addArrangedSubview(Self.sectionTitle("Allowed model routes"))
        let providerStack = NSStackView()
        providerStack.orientation = .vertical
        providerStack.alignment = .leading
        providerStack.spacing = 6
        for (index, choice) in providerChoices.enumerated() {
            let button = NSButton(
                checkboxWithTitle: SessionHistorySafeText.inline(
                    "\(choice.displayName) — \(choice.boundary.displayName)",
                    limit: 320
                ),
                target: nil,
                action: nil
            )
            button.tag = index
            button.toolTip = choice.provider.rawValue
            providerButtons.append(button)
            providerStack.addArrangedSubview(button)
        }
        form.addArrangedSubview(Self.insetBox(
            content: providerStack,
            note: "The server is available only when a task uses one of these exact provider boundaries."
        ))

        form.addArrangedSubview(Self.sectionTitle("MCP process boundary (enforced)"))
        disclosureBoundaryPicker.addItems(withTitles: [DataBoundary.onDevice.displayName])
        disclosureBoundaryPicker.isEnabled = false
        destinationField.placeholderString = "External MCP destinations are not enabled"
        disclosureBoundaryPicker.setAccessibilityLabel("MCP server destination boundary")
        destinationField.setAccessibilityLabel("MCP destination name")
        form.addArrangedSubview(Self.formRow(
            title: "Server destination",
            control: disclosureBoundaryPicker,
            help: "The MCP subprocess always stays on this Mac with no network and read-only project access. Cloud or local-network model choices above remain available under their separate consent boundary."
        ))
        form.addArrangedSubview(Self.formRow(title: "Destination name", control: destinationField))

        let kinds = NSStackView()
        kinds.orientation = .vertical
        kinds.alignment = .leading
        kinds.spacing = 5
        for kind in MCPDisclosureDataKind.allCases {
            let button = NSButton(
                checkboxWithTitle: MCPCenterWindowController.dataKindTitle(kind),
                target: nil,
                action: nil
            )
            dataKindButtons[kind] = button
            kinds.addArrangedSubview(button)
        }
        form.addArrangedSubview(Self.insetBox(
            content: kinds,
            note: "Select every category the server can receive or return. Authentication metadata is required when credential references are used."
        ))

        form.addArrangedSubview(Self.sectionTitle("Credential references"))
        form.addArrangedSubview(Self.formRow(
            title: "Bindings",
            control: credentialsScroll,
            help: "Optional. One NAME=CREDENTIAL_REFERENCE per line. Both sides are names only (for example GITHUB_TOKEN=GITHUB_TOKEN); never paste a secret value."
        ))

        startupSecondsField.stringValue = "30"
        toolSecondsField.stringValue = "30"
        maximumToolsField.stringValue = "32"
        maximumOutputKiBField.stringValue = "1024"
        reconnectAttemptsField.stringValue = "5"
        reconnectButton.state = .on
        let startupLabel = AccessibleFormSupport.makeLabel(
            "Startup timeout", for: startupSecondsField, font: .systemFont(ofSize: 11.5)
        )
        let toolLabel = AccessibleFormSupport.makeLabel(
            "Tool-call timeout", for: toolSecondsField, font: .systemFont(ofSize: 11.5)
        )
        let maximumToolsLabel = AccessibleFormSupport.makeLabel(
            "Maximum tools", for: maximumToolsField, font: .systemFont(ofSize: 11.5)
        )
        let maximumResultLabel = AccessibleFormSupport.makeLabel(
            "Maximum result", for: maximumOutputKiBField, font: .systemFont(ofSize: 11.5)
        )
        let reconnectAttemptsLabel = AccessibleFormSupport.makeLabel(
            "Reconnect attempts", for: reconnectAttemptsField, font: .systemFont(ofSize: 11.5)
        )
        startupSecondsField.setAccessibilityLabel("MCP startup timeout in seconds")
        toolSecondsField.setAccessibilityLabel("MCP tool-call timeout in seconds")
        maximumToolsField.setAccessibilityLabel("MCP maximum discovered tools")
        maximumOutputKiBField.setAccessibilityLabel("MCP maximum result in KiB")
        reconnectAttemptsField.setAccessibilityLabel("MCP reconnect attempts")
        startupSecondsField.setAccessibilityHelp("Enter 1 to 60 seconds.")
        toolSecondsField.setAccessibilityHelp("Enter 1 to 120 seconds.")
        maximumToolsField.setAccessibilityHelp("Enter 1 to 128 discovered tools.")
        maximumOutputKiBField.setAccessibilityHelp("Enter 1 to 4096 KiB.")
        reconnectAttemptsField.setAccessibilityHelp("Enter 1 to 20 attempts.")
        let limitsGrid = NSGridView(views: [
            [startupLabel, startupSecondsField, Self.smallLabel("seconds")],
            [toolLabel, toolSecondsField, Self.smallLabel("seconds")],
            [maximumToolsLabel, maximumToolsField, Self.smallLabel("1–128")],
            [maximumResultLabel, maximumOutputKiBField, Self.smallLabel("KiB")],
            [reconnectAttemptsLabel, reconnectAttemptsField, Self.smallLabel("1–20")]
        ])
        limitsGrid.rowSpacing = 7
        limitsGrid.columnSpacing = 8
        limitsGrid.column(at: 0).xPlacement = .trailing
        limitsGrid.column(at: 1).width = 90
        let limitStack = NSStackView(views: [limitsGrid, reconnectButton])
        limitStack.orientation = .vertical
        limitStack.alignment = .leading
        limitStack.spacing = 10
        form.addArrangedSubview(Self.sectionTitle("Safety limits"))
        form.addArrangedSubview(Self.insetBox(
            content: limitStack,
            note: "Defaults cap startup time, each call, discovered tools, and returned data. The wrapper enforces these independently of the MCP package."
        ))

        for arranged in form.arrangedSubviews {
            arranged.translatesAutoresizingMaskIntoConstraints = false
            arranged.widthAnchor.constraint(equalTo: form.widthAnchor).isActive = true
        }
        NSLayoutConstraint.activate([
            document.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            document.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            document.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            form.topAnchor.constraint(equalTo: document.topAnchor, constant: 4),
            form.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 4),
            form.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -12),
            form.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -8)
        ])

        errorLabel.font = .systemFont(ofSize: 11.5)
        errorLabel.textColor = .systemRed
        errorLabel.setAccessibilityLabel("MCP editor status")
        configureButton(cancelButton, action: #selector(cancel(_:)))
        configureButton(reviewButton, action: #selector(review(_:)))
        reviewButton.keyEquivalent = "\r"
        cancelButton.keyEquivalent = "\u{1b}"
        let footer = NSStackView(views: [errorLabel, NSView(), cancelButton, reviewButton])
        footer.orientation = .horizontal
        footer.alignment = .centerY
        footer.spacing = 8

        let content = NSStackView(views: [title, subtitle, scroll, footer])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 10
        content.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(content)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        footer.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: root.topAnchor, constant: 20),
            content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            content.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16),
            subtitle.widthAnchor.constraint(equalTo: content.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: content.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 560),
            footer.widthAnchor.constraint(equalTo: content.widthAnchor)
        ])
        controller.view = root
        return controller
    }

    private func populate() {
        guard let existing else {
            dataKindButtons[.toolArguments]?.state = .on
            dataKindButtons[.toolResults]?.state = .on
            if providerButtons.count == 1 { providerButtons[0].state = .on }
            disclosureBoundaryPicker.selectItem(at: 0)
            updateDisclosureFields()
            return
        }
        identifierField.stringValue = SessionHistorySafeText.inline(existing.id, limit: 64)
        identifierField.isEditable = false
        identifierField.textColor = .secondaryLabelColor
        displayNameField.stringValue = SessionHistorySafeText.inline(existing.displayName, limit: 100)
        serverNameField.stringValue = SessionHistorySafeText.inline(existing.serverName, limit: 32)
        executableField.stringValue = SessionHistorySafeText.inline(existing.executablePath, limit: 4_096)
        argumentsView.string = existing.arguments.prefix(64).map {
            SessionHistorySafeText.inline($0, limit: 4_096)
        }.joined(separator: "\n")
        reviewedIndexesField.stringValue = existing.reviewedFileArgumentIndexes
            .sorted().map { String($0 + 1) }.joined(separator: ", ")
        workingDirectoryField.stringValue = SessionHistorySafeText.inline(
            existing.projectRelativeWorkingDirectory ?? "",
            limit: 1_024
        )
        for (index, choice) in providerChoices.enumerated() where existing.allowedProviders.contains(where: {
            $0.provider == choice.provider && $0.boundary == choice.boundary
        }) {
            providerButtons[index].state = .on
        }
        disclosureBoundaryPicker.selectItem(at: 0)
        destinationField.stringValue = ""
        for kind in existing.disclosure.dataKinds { dataKindButtons[kind]?.state = .on }
        credentialBindingsView.string = existing.environment.prefix(12)
            .sorted { $0.variableName < $1.variableName }
            .map {
                "\(SessionHistorySafeText.inline($0.variableName, limit: 64))=\(SessionHistorySafeText.inline($0.credential.rawValue, limit: 96))"
            }
            .joined(separator: "\n")
        // These fields are parsed as bounded ASCII integers. `integerValue`
        // asks AppKit to apply the current locale and can render 1024 as
        // "1,024", which the strict parser then rejects when an existing MCP
        // definition is reviewed. Preserve a canonical editable representation.
        startupSecondsField.stringValue = String(existing.limits.startupTimeoutMilliseconds / 1_000)
        toolSecondsField.stringValue = String(existing.limits.toolCallTimeoutMilliseconds / 1_000)
        maximumToolsField.stringValue = String(existing.limits.maximumDiscoveredTools)
        maximumOutputKiBField.stringValue = String(existing.limits.maximumOutputBytes / 1_024)
        reconnectButton.state = existing.reconnect.enabled ? .on : .off
        reconnectAttemptsField.stringValue = String(existing.reconnect.maximumAttempts)
        updateDisclosureFields()
    }

    @objc private func chooseExecutable(_ sender: Any?) {
        let panel = NSOpenPanel()
        panel.title = "Choose the MCP server executable"
        panel.message = "Choose one executable file. Scripts with an absolute, reviewed shebang are supported; shell executables are refused."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        executableField.stringValue = url.path
    }

    @objc private func disclosureBoundaryChanged(_ sender: Any?) {
        updateDisclosureFields()
    }

    private func updateDisclosureFields() {
        destinationField.isEnabled = false
        destinationField.stringValue = ""
    }

    @objc private func review(_ sender: Any?) {
        do {
            errorLabel.stringValue = ""
            onReview?(try makeDraft())
        } catch let error as MCPServerEditorError {
            errorLabel.stringValue = error.localizedDescription
            errorLabel.textColor = .systemRed
        } catch {
            errorLabel.stringValue = "This MCP definition could not be validated safely. Review its fields and try again."
            errorLabel.textColor = .systemRed
        }
    }

    @objc private func cancel(_ sender: Any?) { onCancel?() }

    private func makeDraft() throws -> MCPServerDraft {
        let identifier = clean(identifierField.stringValue)
        let displayName = clean(displayNameField.stringValue)
        let serverName = clean(serverNameField.stringValue)
        let executable = clean(executableField.stringValue)
        guard identifier.range(
            of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#,
            options: .regularExpression
        ) != nil else {
            throw MCPServerEditorError.invalidField(
                "Definition ID must be 1–64 letters, numbers, dots, underscores, or hyphens."
            )
        }
        guard !displayName.isEmpty, displayName.utf8.count <= 100,
              displayName.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw MCPServerEditorError.invalidField("Display name must be 1–100 ordinary characters.")
        }
        guard serverName.range(
            of: #"^[A-Za-z0-9_-]{1,32}$"#,
            options: .regularExpression
        ) != nil else {
            throw MCPServerEditorError.invalidField(
                "Tool namespace must be 1–32 letters, numbers, underscores, or hyphens."
            )
        }
        guard executable.hasPrefix("/") else { throw MCPServerEditorError.invalidField("Choose an absolute executable path.") }

        let arguments = nonemptyLines(argumentsView.string)
        guard arguments.count <= 64,
              arguments.reduce(0, { $0 + $1.utf8.count }) <= 16_384,
              arguments.allSatisfy({ $0.utf8.count <= 4_096 && !$0.contains("\0") && !$0.contains("\r") }) else {
            throw MCPServerEditorError.invalidField("Use at most 64 literal arguments totaling no more than 16 KiB.")
        }
        if arguments.contains(where: Self.looksLikeSecret) {
            throw MCPServerEditorError.invalidField(
                "An argument looks like a secret. Store it in Credentials and add only a NAME=CREDENTIAL_REFERENCE binding."
            )
        }
        let reviewedIndexes = try parseReviewedIndexes(reviewedIndexesField.stringValue, argumentCount: arguments.count)
        let codeExtensions: Set<String> = ["js", "mjs", "cjs", "ts", "py", "rb", "pl", "jar"]
        for (index, argument) in arguments.enumerated()
            where argument.hasPrefix("/")
                && codeExtensions.contains(URL(fileURLWithPath: argument).pathExtension.lowercased())
                && !reviewedIndexes.contains(index) {
            throw MCPServerEditorError.invalidField(
                "Literal argument line \(index + 1) is a code entry file. Add \(index + 1) to Code-file arguments so its bytes are fingerprinted."
            )
        }
        let working = clean(workingDirectoryField.stringValue)
        if !working.isEmpty {
            let components = NSString(string: working).pathComponents
            guard !working.hasPrefix("/"), !working.contains("\0"),
                  components.allSatisfy({ $0 != "." && $0 != ".." && $0 != "/" }) else {
                throw MCPServerEditorError.invalidField(
                    "Working folder must be a project-relative directory without . or .. components."
                )
            }
        }
        let providers = providerButtons.compactMap { button -> MCPProviderEnablement? in
            guard button.state == .on, providerChoices.indices.contains(button.tag) else { return nil }
            let choice = providerChoices[button.tag]
            return MCPProviderEnablement(provider: choice.provider, boundary: choice.boundary)
        }
        guard !providers.isEmpty else {
            throw MCPServerEditorError.invalidField("Select at least one exact model-provider boundary.")
        }
        guard Set(providers.map(\.provider)).count == providers.count else {
            throw MCPServerEditorError.invalidField(
                "Select only one data boundary for each exact provider identifier."
            )
        }

        let environment = try parseCredentialBindings(credentialBindingsView.string)
        let kinds = MCPDisclosureDataKind.allCases.filter { dataKindButtons[$0]?.state == .on }
        guard !kinds.isEmpty else {
            throw MCPServerEditorError.invalidField("Select at least one MCP disclosure data category.")
        }
        if !environment.isEmpty && !kinds.contains(.authenticationMetadata) {
            throw MCPServerEditorError.invalidField(
                "Select Authentication metadata because this server uses credential references."
            )
        }
        let disclosureBoundary = selectedDisclosureBoundary
        let destination = clean(destinationField.stringValue)
        if disclosureBoundary.requiresExplicitConsent {
            guard !destination.isEmpty, destination.utf8.count <= 120,
                  destination.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw MCPServerEditorError.invalidField(
                    "Name the local-network or cloud destination in 120 ordinary characters or fewer."
                )
            }
        }

        let startupSeconds = try boundedInteger(startupSecondsField, name: "Startup timeout", range: 1...60)
        let callSeconds = try boundedInteger(toolSecondsField, name: "Tool-call timeout", range: 1...120)
        let tools = try boundedInteger(maximumToolsField, name: "Maximum tools", range: 1...128)
        let outputKiB = try boundedInteger(maximumOutputKiBField, name: "Maximum result", range: 1...4_096)
        let attempts = try boundedInteger(reconnectAttemptsField, name: "Reconnect attempts", range: 1...20)

        return MCPServerDraft(
            id: identifier,
            displayName: displayName,
            serverName: serverName,
            executablePath: executable,
            arguments: arguments,
            reviewedFileArgumentIndexes: reviewedIndexes,
            projectRelativeWorkingDirectory: working.isEmpty ? nil : working,
            environment: environment,
            allowedProviders: providers,
            disclosure: MCPDisclosureProfile(
                boundary: disclosureBoundary,
                destinationName: disclosureBoundary.requiresExplicitConsent ? destination : nil,
                dataKinds: kinds
            ),
            limits: MCPExecutionLimits(
                startupTimeoutMilliseconds: startupSeconds * 1_000,
                toolCallTimeoutMilliseconds: callSeconds * 1_000,
                maximumDiscoveredTools: tools,
                maximumOutputBytes: outputKiB * 1_024
            ),
            reconnect: MCPReconnectConfiguration(
                enabled: reconnectButton.state == .on,
                initialDelayMilliseconds: 500,
                maximumDelayMilliseconds: 15_000,
                maximumAttempts: attempts
            )
        )
    }

    private var selectedDisclosureBoundary: DataBoundary {
        .onDevice
    }

    private func parseReviewedIndexes(_ value: String, argumentCount: Int) throws -> [Int] {
        let tokens = value.split { $0 == "," || $0 == " " || $0 == "\t" || $0 == "\n" }
        var indexes: [Int] = []
        for token in tokens {
            guard let oneBased = Int(token), oneBased >= 1, oneBased <= argumentCount else {
                throw MCPServerEditorError.invalidField(
                    "Code-file argument indexes must match 1-based lines in Literal arguments."
                )
            }
            indexes.append(oneBased - 1)
        }
        guard Set(indexes).count == indexes.count else {
            throw MCPServerEditorError.invalidField("Each code-file argument index can appear only once.")
        }
        return indexes.sorted()
    }

    private func parseCredentialBindings(_ value: String) throws -> [MCPEnvironmentBinding] {
        let bindings = try nonemptyLines(value).map { line in
            let pieces = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pieces.count == 2 else {
                throw MCPServerEditorError.invalidField("Credential bindings must use NAME=CREDENTIAL_REFERENCE, one per line.")
            }
            let variable = clean(String(pieces[0]))
            let reference = clean(String(pieces[1]))
            guard Self.matchesName(variable, maximum: 64), Self.matchesName(reference, maximum: 96) else {
                throw MCPServerEditorError.invalidField(
                    "Credential bindings accept uppercase reference names only; secret values are never accepted."
                )
            }
            return MCPEnvironmentBinding(
                variableName: variable,
                credential: CredentialReference(reference)
            )
        }
        guard Set(bindings.map(\.variableName)).count == bindings.count else {
            throw MCPServerEditorError.invalidField("Each environment variable can be bound only once.")
        }
        guard bindings.count <= 12 else {
            throw MCPServerEditorError.invalidField("Use no more than 12 credential bindings for one server.")
        }
        let forbiddenNames: Set<String> = [
            "BASH_ENV", "ENV", "HOME", "IFS", "NODE_OPTIONS", "PATH", "PERL5OPT",
            "PYTHONHOME", "PYTHONPATH", "RUBYOPT", "SHELL", "TMPDIR", "ZDOTDIR"
        ]
        guard bindings.allSatisfy({ binding in
            !forbiddenNames.contains(binding.variableName)
                && !binding.variableName.hasPrefix("DSH_")
                && !binding.variableName.hasPrefix("DYLD_")
                && !binding.variableName.hasPrefix("LD_")
        }) else {
            throw MCPServerEditorError.invalidField(
                "A binding tries to replace a protected runtime or loader environment variable."
            )
        }
        return bindings
    }

    private func boundedInteger(_ field: NSTextField, name: String, range: ClosedRange<Int>) throws -> Int {
        guard let value = Int(clean(field.stringValue)), range.contains(value) else {
            throw MCPServerEditorError.invalidField("\(name) must be between \(range.lowerBound) and \(range.upperBound).")
        }
        return value
    }

    private func nonemptyLines(_ value: String) -> [String] {
        value.components(separatedBy: .newlines).filter { !$0.isEmpty }
    }

    private func clean(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func configureButton(_ button: NSButton, action: Selector) {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
    }

    private static func looksLikeSecret(_ value: String) -> Bool {
        let lowered = value.lowercased()
        if lowered.hasPrefix("sk-") || lowered.hasPrefix("ghp_")
            || lowered.hasPrefix("github_pat_") || lowered.hasPrefix("xoxb-")
            || lowered.hasPrefix("xoxp-") || lowered.hasPrefix("bearer ") {
            return true
        }
        if lowered.range(of: #"(?i)(?:api[-_]?key|password|secret|access[-_]?token|auth[-_]?token)(?:=|$)"#,
                         options: .regularExpression) != nil {
            return true
        }
        if value.range(of: #"^AKIA[0-9A-Z]{16}$"#, options: .regularExpression) != nil
            || value.range(of: #"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"#,
                           options: .regularExpression) != nil {
            return true
        }
        if let components = URLComponents(string: value), components.password != nil { return true }
        return false
    }

    private static func matchesName(_ value: String, maximum: Int) -> Bool {
        guard !value.isEmpty, value.count <= maximum else { return false }
        return value.range(of: #"^[A-Z][A-Z0-9_]*$"#, options: .regularExpression) != nil
    }

    private static func slug(_ value: String) -> String {
        let lowered = value.lowercased()
        let mapped = lowered.map { character -> Character in
            character.isLetter || character.isNumber || character == "." || character == "_" ? character : "-"
        }
        let normalized = String(mapped)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
            .replacingOccurrences(of: #"-+"#, with: "-", options: .regularExpression)
        return String(normalized.prefix(64))
    }

    private static func namespaceSlug(_ value: String) -> String {
        String(slug(value).replacingOccurrences(of: "-", with: "_").prefix(32))
    }

    private static func sectionTitle(_ value: String) -> NSTextField {
        let field = NSTextField(labelWithString: value)
        field.font = .systemFont(ofSize: 14, weight: .semibold)
        return field
    }

    private static func smallLabel(_ value: String) -> NSTextField {
        let field = NSTextField(labelWithString: value)
        field.font = .systemFont(ofSize: 11.5)
        field.textColor = .secondaryLabelColor
        return field
    }

    private static func formRow(title: String, control: NSView, help: String? = nil) -> NSView {
        let label = AccessibleFormSupport.makeLabel(
            title,
            for: control,
            font: .systemFont(ofSize: 11.5, weight: .medium),
            alignment: .right
        )
        label.widthAnchor.constraint(equalToConstant: 142).isActive = true
        control.translatesAutoresizingMaskIntoConstraints = false
        let controlStack: NSStackView
        if let help {
            let helpLabel = NSTextField(wrappingLabelWithString: help)
            helpLabel.font = .systemFont(ofSize: 10.5)
            helpLabel.textColor = .tertiaryLabelColor
            controlStack = NSStackView(views: [control, helpLabel])
            controlStack.orientation = .vertical
            controlStack.alignment = .leading
            controlStack.spacing = 4
            helpLabel.widthAnchor.constraint(equalTo: controlStack.widthAnchor).isActive = true
        } else {
            controlStack = NSStackView(views: [control])
            controlStack.orientation = .vertical
            controlStack.alignment = .leading
        }
        control.widthAnchor.constraint(equalTo: controlStack.widthAnchor).isActive = true
        let row = NSStackView(views: [label, controlStack])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 12
        return row
    }

    private static func textScroll(_ textView: NSTextView, height: CGFloat) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
        return scroll
    }

    private static func insetBox(content: NSView, note: String) -> NSView {
        let box = NSBox()
        box.boxType = .custom
        box.cornerRadius = 8
        box.fillColor = NSColor.controlBackgroundColor
        box.borderColor = NSColor.separatorColor
        box.borderWidth = 1
        let noteLabel = NSTextField(wrappingLabelWithString: note)
        noteLabel.font = .systemFont(ofSize: 10.5)
        noteLabel.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [content, noteLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 9
        stack.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: box.topAnchor, constant: 12),
            stack.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -12),
            stack.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -12),
            noteLabel.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        return box
    }
}

@MainActor
final class MCPServerReviewSheetController: NSWindowController {
    var onBack: (() -> Void)?
    var onSaveDisabled: (() -> Void)?
    var onApprove: (() -> Void)?

    private let confirmation = NSButton(
        checkboxWithTitle: "I reviewed this exact command, project, provider access, disclosures, and limits.",
        target: nil,
        action: nil
    )
    private let approveButton = NSButton(title: "Approve Server", target: nil, action: nil)
    private let saveButton = NSButton(title: "Save Disabled", target: nil, action: nil)
    private let backButton = NSButton(title: "Back", target: nil, action: nil)
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private var reviewAvailable = true

    init(
        draft: MCPServerDraft,
        inspection: MCPDraftInspection,
        projectRoot: URL,
        providerNames: [String: String]
    ) {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 740, height: 650),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        panel.title = "Review MCP Server"
        panel.minSize = NSSize(width: 740, height: 650)
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        panel.contentViewController = buildContent(
            draft: draft,
            inspection: inspection,
            projectRoot: projectRoot,
            providerNames: providerNames
        )
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func setBusy(_ busy: Bool, message: String, isError: Bool = false) {
        confirmation.isEnabled = !busy && reviewAvailable
        backButton.isEnabled = !busy
        saveButton.isEnabled = !busy
        approveButton.isEnabled = !busy && reviewAvailable && confirmation.state == .on
        statusLabel.stringValue = message
        statusLabel.textColor = isError ? .systemRed : .secondaryLabelColor
    }

    private func buildContent(
        draft: MCPServerDraft,
        inspection: MCPDraftInspection,
        projectRoot: URL,
        providerNames: [String: String]
    ) -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let title = NSTextField(labelWithString: "Review before approving")
        title.font = .systemFont(ofSize: 22, weight: .semibold)
        let boundaryIsExternal = draft.allowedProviders.contains { $0.boundary.isExternalToThisMac }
            || draft.disclosure.boundary.isExternalToThisMac
        let warning = NSTextField(wrappingLabelWithString: boundaryIsExternal
            ? "This definition can be used across an off-device boundary. Review exactly what may leave this Mac."
            : "The server stays on this Mac, but it can act on project data through the tools it exposes."
        )
        warning.font = .systemFont(ofSize: 12, weight: .medium)
        warning.textColor = boundaryIsExternal ? .systemOrange : .secondaryLabelColor

        let textView = NSTextView()
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.drawsBackground = false
        textView.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        let reviewText = Self.reviewText(
            draft: draft,
            inspection: inspection,
            projectRoot: projectRoot,
            providerNames: providerNames
        )
        reviewAvailable = reviewText != nil
        textView.string = reviewText
            ?? "This definition cannot be reviewed safely because one or more displayed fields are invalid or too large. Return to the editor and choose bounded ordinary values."
        MCPReviewAccessibility.configure(review: textView, title: title)
        let scroll = NSScrollView()
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        confirmation.target = self
        confirmation.action = #selector(confirmationChanged(_:))
        confirmation.setAccessibilityLabel("Confirm exact MCP server review")
        confirmation.isEnabled = reviewAvailable
        statusLabel.font = .systemFont(ofSize: 11.5)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setAccessibilityLabel("MCP review status")
        if !reviewAvailable {
            statusLabel.stringValue = "Approval is unavailable until every exact capability can be displayed safely."
            statusLabel.textColor = .systemRed
        }

        configureButton(backButton, action: #selector(back(_:)))
        configureButton(saveButton, action: #selector(saveDisabled(_:)))
        configureButton(approveButton, action: #selector(approve(_:)))
        approveButton.keyEquivalent = "\r"
        approveButton.isEnabled = false
        backButton.keyEquivalent = "\u{1b}"
        let actions = NSStackView(views: [statusLabel, NSView(), backButton, saveButton, approveButton])
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 8

        let content = NSStackView(views: [title, warning, scroll, confirmation, actions])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 12
        content.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(content)
        actions.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
            content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            content.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
            warning.widthAnchor.constraint(equalTo: content.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: content.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 440),
            confirmation.widthAnchor.constraint(equalTo: content.widthAnchor),
            actions.widthAnchor.constraint(equalTo: content.widthAnchor)
        ])
        controller.view = root
        return controller
    }

    @objc private func confirmationChanged(_ sender: NSButton) {
        approveButton.isEnabled = reviewAvailable && sender.state == .on
    }

    @objc private func back(_ sender: Any?) { onBack?() }
    @objc private func saveDisabled(_ sender: Any?) { onSaveDisabled?() }
    @objc private func approve(_ sender: Any?) {
        guard confirmation.state == .on else { return }
        onApprove?()
    }

    private func configureButton(_ button: NSButton, action: Selector) {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
    }

    private static func reviewText(
        draft: MCPServerDraft,
        inspection: MCPDraftInspection,
        projectRoot: URL,
        providerNames: [String: String]
    ) -> String? {
        guard draft.arguments.count <= 64,
              draft.arguments.reduce(0, { $0 + $1.utf8.count }) <= 16_384,
              draft.environment.count <= 12,
              draft.allowedProviders.count <= 64,
              inspection.reviewedFiles.count <= 64 else { return nil }
        var exactValues = [
            draft.displayName, draft.id, draft.serverName, draft.executablePath,
            inspection.project.canonicalPath, inspection.project.fingerprint,
            inspection.executable.declaredPath, inspection.executable.canonicalPath,
            inspection.executable.contentSHA256
        ]
        exactValues.append(contentsOf: draft.arguments)
        exactValues.append(contentsOf: draft.environment.flatMap {
            [$0.variableName, $0.credential.rawValue]
        })
        exactValues.append(contentsOf: draft.allowedProviders.flatMap {
            let key = "\($0.boundary.rawValue)\u{1F}\($0.provider.rawValue)"
            return [$0.provider.rawValue, providerNames[key] ?? $0.provider.rawValue]
        })
        exactValues.append(contentsOf: inspection.reviewedFiles.flatMap {
            [$0.canonicalPath, $0.contentSHA256]
        })
        if let value = draft.projectRelativeWorkingDirectory { exactValues.append(value) }
        if let value = draft.disclosure.destinationName { exactValues.append(value) }
        if let value = inspection.executable.interpreterCanonicalPath { exactValues.append(value) }
        if let value = inspection.executable.interpreterContentSHA256 { exactValues.append(value) }
        guard exactValues.allSatisfy({ safeExactReviewValue($0, limit: 4_096) }) else {
            return nil
        }
        let arguments = draft.arguments.isEmpty
            ? "  (none)"
            : draft.arguments.enumerated().map { index, value in
                let marker = draft.reviewedFileArgumentIndexes.contains(index) ? "  [fingerprinted code file]" : ""
                return "  \(index + 1). \(value)\(marker)"
            }.joined(separator: "\n")
        let reviewedFiles = inspection.reviewedFiles.isEmpty
            ? "  (none)"
            : inspection.reviewedFiles.map {
                "  line \($0.argumentIndex + 1): \($0.canonicalPath)\n    SHA-256 \($0.contentSHA256)"
            }.joined(separator: "\n")
        let providers = draft.allowedProviders.map { allowed -> String in
            let key = "\(allowed.boundary.rawValue)\u{1F}\(allowed.provider.rawValue)"
            let name = providerNames[key] ?? allowed.provider.rawValue
            return "  \(name) [\(allowed.provider.rawValue)] — \(allowed.boundary.displayName)"
        }.joined(separator: "\n")
        let credentials = draft.environment.isEmpty
            ? "  (none)"
            : draft.environment.map {
                "  \($0.variableName) ← credential reference \($0.credential.rawValue)"
            }.joined(separator: "\n")
        let disclosureKinds = draft.disclosure.dataKinds
            .map(MCPCenterWindowController.dataKindTitle).joined(separator: ", ")
        let disclosureDestination = draft.disclosure.destinationName.map { " to \($0)" } ?? ""
        let working = draft.projectRelativeWorkingDirectory.map {
            projectRoot.appendingPathComponent($0, isDirectory: true).standardizedFileURL.path
        } ?? inspection.project.canonicalPath

        let result = """
        IDENTITY
          Display name: \(draft.displayName)
          Definition ID: \(draft.id)
          Tool namespace: \(draft.serverName)
          Transport: local stdio (direct launch; no shell)

        PROJECT
          Approved root: \(inspection.project.canonicalPath)
          Project identity: \(inspection.project.fingerprint)
          Working folder: \(working)

        EXACT EXECUTABLE
          Declared: \(inspection.executable.declaredPath)
          Resolved: \(inspection.executable.canonicalPath)
          SHA-256: \(inspection.executable.contentSHA256)
          Size: \(ByteCountFormatter.string(fromByteCount: Int64(inspection.executable.byteCount), countStyle: .file))
          Interpreter: \(inspection.executable.interpreterCanonicalPath ?? "native executable")

        LITERAL ARGUMENTS (never interpreted by a shell)
        \(arguments)

        REVIEWED ENTRY FILES
        \(reviewedFiles)

        ALLOWED MODEL ROUTES
        \(providers)

        MCP PROCESS DISCLOSURE
          Boundary: \(draft.disclosure.boundary.displayName)\(disclosureDestination)
          Data categories: \(disclosureKinds)

        CREDENTIAL REFERENCES (names only; no values stored)
        \(credentials)

        ENFORCED LIMITS
          Startup: \(draft.limits.startupTimeoutMilliseconds / 1_000) seconds
          Each tool call: \(draft.limits.toolCallTimeoutMilliseconds / 1_000) seconds
          Discovered tools: \(draft.limits.maximumDiscoveredTools)
          Tool result: \(ByteCountFormatter.string(fromByteCount: Int64(draft.limits.maximumOutputBytes), countStyle: .file))
          Reconnect: \(draft.reconnect.enabled ? "up to \(draft.reconnect.maximumAttempts) attempts" : "off")

        Approval is revoked automatically if the executable, reviewed entry files,
        project identity, command, route policy, disclosure, credentials, or limits change.
        """
        guard result.unicodeScalars.count <= 40_000 else { return nil }
        return result
    }

    private static func safeExactReviewValue(_ value: String, limit: Int) -> Bool {
        guard value.unicodeScalars.count <= limit,
              value.utf8.count <= limit * 4,
              !value.contains("\n"), !value.contains("\r"), !value.contains("\t") else {
            return false
        }
        return SessionHistorySafeText.multiline(value, limit: limit) == value
    }
}
