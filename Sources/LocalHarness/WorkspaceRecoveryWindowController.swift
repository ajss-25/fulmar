import AppKit

private enum WorkspaceRecoveryControllerError: LocalizedError {
    case restorePreparationUnavailable
    case restorePreparationFailed

    var errorDescription: String? {
        switch self {
        case .restorePreparationUnavailable:
            "Workspace restore is unavailable because the protected runtime coordinator is not connected. No workspace file was changed."
        case .restorePreparationFailed:
            "Workspace restore stayed paused because agent work could not be stopped and verified safely. No workspace file was changed."
        }
    }
}

struct WorkspaceRecoveryOperations: @unchecked Sendable {
    let approvedWorkspaceURL: URL
    let listCheckpoints: @Sendable () throws -> [WorkspaceCheckpointSummary]
    let captureCheckpoint: @Sendable (String) throws -> WorkspaceCheckpoint
    let deleteCheckpoint: @Sendable (UUID) throws -> Void
    let previewRestore: @Sendable (UUID) throws -> WorkspaceRestorePreview
    let restore: @Sendable (
        UUID,
        WorkspaceRestorePreview,
        WorkspaceRestoreOptions
    ) throws -> WorkspaceRestoreReport

    static func production(journal: WorkspaceChangeJournal) -> Self {
        Self(
            approvedWorkspaceURL: journal.approvedWorkspaceURL,
            listCheckpoints: { try journal.listCheckpoints() },
            captureCheckpoint: { try journal.captureCheckpoint(label: $0) },
            deleteCheckpoint: { try journal.deleteCheckpoint(checkpointID: $0) },
            previewRestore: { try journal.previewRestore(checkpointID: $0) },
            restore: { try journal.restore(checkpointID: $0, preview: $1, options: $2) }
        )
    }
}

typealias WorkspaceRecoveryAlertCompletion = @MainActor (Bool) -> Void

struct WorkspaceRecoveryAlertPresenter {
    let present: @MainActor (
        NSAlert,
        NSWindow?,
        @escaping WorkspaceRecoveryAlertCompletion
    ) -> Void

    static let production = Self(present: { alert, window, completion in
        guard let window else {
            completion(false)
            return
        }
        alert.beginSheetModal(for: window) { response in
            completion(response == .alertFirstButtonReturn)
        }
    })
}

/// A native, local-only recovery surface for one explicitly approved workspace.
///
/// The journal owns all filesystem validation and transactional restore logic.
/// This controller keeps every scan and mutation off the main thread, binds a
/// restore to the exact preview the user saw, and obtains separate approval for
/// overwriting modified files and removing files added after a checkpoint.
final class WorkspaceRecoveryWindowController: NSWindowController,
    NSTableViewDataSource,
    NSTableViewDelegate {

    var onCheckpointCaptured: ((WorkspaceCheckpoint) -> Void)?
    /// The host asynchronously quiesces schedules and waits for its exact
    /// agent process to exit. Restore cannot begin until this barrier succeeds.
    var onPrepareRestore: ((@escaping (Result<Void, Error>) -> Void) -> Void)?
    var onRestoreCompleted: ((WorkspaceRestoreReport) -> Void)?
    /// Invoked for every started restore attempt, including failure, so the
    /// host can safely bring a previously stopped runtime back online.
    var onRestoreAttemptFinished: ((Bool) -> Void)?

    private struct PreviewRow {
        let change: WorkspaceChange
        let conflicts: [WorkspaceRestoreConflict]
    }

    private let operations: WorkspaceRecoveryOperations
    private let alertPresenter: WorkspaceRecoveryAlertPresenter
    private let displayPolicy: NativeAccessibilityDisplayPolicy
    private var accessibilityDisplayObserver: NativeAccessibilityDisplayObserver?
    private var sidebarContainer: NativeAccessibilitySidebarView?
    private let operationQueue = DispatchQueue(
        label: "com.localharness.workspace-recovery",
        qos: .userInitiated
    )

    private let checkpointTable = NSTableView()
    private let previewTable = NSTableView()
    private let emptyCheckpointLabel = NSTextField(wrappingLabelWithString: "No recovery checkpoints yet. Create one before asking an agent to make broad changes.")
    private let emptyPreviewLabel = NSTextField(wrappingLabelWithString: "Select a checkpoint to compare it with the current workspace.")
    private let detailTitleLabel = NSTextField(wrappingLabelWithString: "Select a checkpoint")
    private let detailMetadataLabel = NSTextField(wrappingLabelWithString: "")
    private let summaryLabel = NSTextField(wrappingLabelWithString: "")
    private let safetyLabel = NSTextField(wrappingLabelWithString: "Recovery previews are bound to the exact current workspace state.")
    private let statusLabel = NSTextField(wrappingLabelWithString: "Loading local recovery checkpoints…")
    private let progressIndicator = NSProgressIndicator()
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let captureButton = NSButton(title: "Create Checkpoint…", target: nil, action: nil)
    private let deleteButton = NSButton(title: "Delete…", target: nil, action: nil)
    private let restoreButton = NSButton(title: "Restore…", target: nil, action: nil)
    private let removeAddedFilesButton = NSButton(
        checkboxWithTitle: "Also remove files created after this checkpoint",
        target: nil,
        action: nil
    )

    private var checkpoints: [WorkspaceCheckpointSummary] = []
    private var previewRows: [PreviewRow] = []
    private var currentPreview: WorkspaceRestorePreview?
    private var isBusy = false
    private var operationGeneration = 0
    private var pendingRestorePreparationGeneration: Int?

    convenience init(
        journal: WorkspaceChangeJournal,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live
    ) {
        self.init(
            operations: .production(journal: journal),
            displayPolicy: displayPolicy
        )
    }

    init(
        operations: WorkspaceRecoveryOperations,
        alertPresenter: WorkspaceRecoveryAlertPresenter? = nil,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live
    ) {
        self.operations = operations
        self.alertPresenter = alertPresenter ?? .production
        self.displayPolicy = displayPolicy
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_040, height: 700),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Workspace Recovery"
        window.subtitle = "Local, bounded checkpoints"
        window.minSize = NSSize(width: 820, height: 560)
        window.isReleasedWhenClosed = false
        window.toolbarStyle = .unified
        window.setFrameAutosaveName("LocalHarness.WorkspaceRecovery")
        super.init(window: window)
        window.contentViewController = buildContent()
        accessibilityDisplayObserver = NativeAccessibilityDisplayObserver { [weak self] in
            self?.refreshAccessibilityDisplayOptions()
        }
        updateControlState()
        if !window.setFrameUsingName("LocalHarness.WorkspaceRecovery") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        refresh()
    }

    /// Refreshes checkpoint metadata without scanning workspace contents. A
    /// selected checkpoint is then previewed, which performs a bounded scan.
    func refresh() {
        guard !isBusy else { return }
        reloadCheckpoints(selecting: selectedCheckpoint?.id)
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        tableView === checkpointTable ? checkpoints.count : previewRows.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        if tableView === checkpointTable {
            guard checkpoints.indices.contains(row) else { return nil }
            let identifier = NSUserInterfaceItemIdentifier("WorkspaceCheckpointRow")
            let cell = tableView.makeView(withIdentifier: identifier, owner: self) as? WorkspaceCheckpointCellView
                ?? WorkspaceCheckpointCellView(identifier: identifier)
            cell.configure(summary: checkpoints[row])
            return cell
        }

        guard previewRows.indices.contains(row), let tableColumn else { return nil }
        let previewRow = previewRows[row]
        let identifier = NSUserInterfaceItemIdentifier("RecoveryPreview.\(tableColumn.identifier.rawValue)")
        let field = tableView.makeView(withIdentifier: identifier, owner: self) as? NSTextField
            ?? NSTextField(labelWithString: "")
        field.identifier = identifier
        field.font = tableColumn.identifier.rawValue == "path"
            ? .monospacedSystemFont(ofSize: 11, weight: .regular)
            : .systemFont(ofSize: 11)
        field.lineBreakMode = .byTruncatingMiddle
        field.toolTip = previewRow.change.relativePath

        switch tableColumn.identifier.rawValue {
        case "change":
            field.stringValue = Self.changeDescription(previewRow.change.kind)
            field.textColor = Self.changeColor(previewRow.change.kind)
        case "safety":
            field.stringValue = Self.safetyDescription(for: previewRow)
            field.textColor = previewRow.conflicts.contains(where: { $0.kind != .wouldOverwriteModifiedFile })
                ? .systemRed
                : (previewRow.conflicts.isEmpty ? .secondaryLabelColor : .systemOrange)
        default:
            field.stringValue = previewRow.change.relativePath
            field.textColor = .labelColor
        }
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard notification.object as? NSTableView === checkpointTable, !isBusy else { return }
        guard let checkpoint = selectedCheckpoint else {
            clearPreview(message: "Select a checkpoint to compare it with the current workspace.")
            return
        }
        preview(checkpoint)
    }

    private var selectedCheckpoint: WorkspaceCheckpointSummary? {
        let row = checkpointTable.selectedRow
        return checkpoints.indices.contains(row) ? checkpoints[row] : nil
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let heading = NSTextField(labelWithString: "Workspace Recovery")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        let workspaceName = Self.safeWorkspaceName(operations.approvedWorkspaceURL)
        let subtitle = NSTextField(wrappingLabelWithString: "Create local checkpoints for \(workspaceName). Generated folders and likely credential files are deliberately excluded.")
        subtitle.textColor = .secondaryLabelColor
        subtitle.maximumNumberOfLines = 2
        subtitle.toolTip = "Approved workspace: \(workspaceName)"
        let titles = NSStackView(views: [heading, subtitle])
        titles.orientation = .vertical
        titles.alignment = .leading
        titles.spacing = 3

        configureButton(refreshButton, action: #selector(refreshAction(_:)), symbol: "arrow.clockwise")
        configureButton(captureButton, action: #selector(captureCheckpoint(_:)), symbol: "plus.circle")
        captureButton.keyEquivalent = "n"
        captureButton.keyEquivalentModifierMask = [.command, .shift]
        let header = NSStackView(views: [titles, NSView(), refreshButton, captureButton])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 8

        let sidebar = buildCheckpointSidebar()
        let detail = buildPreviewDetail()
        let splitView = NSSplitView()
        splitView.isVertical = true
        splitView.dividerStyle = .thin
        splitView.addArrangedSubview(sidebar)
        splitView.addArrangedSubview(detail)
        sidebar.widthAnchor.constraint(greaterThanOrEqualToConstant: 250).isActive = true
        sidebar.widthAnchor.constraint(lessThanOrEqualToConstant: 340).isActive = true

        progressIndicator.style = .spinning
        progressIndicator.controlSize = .small
        progressIndicator.isDisplayedWhenStopped = false
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.setAccessibilityLabel("Workspace recovery status")
        statusLabel.maximumNumberOfLines = 2
        statusLabel.lineBreakMode = .byTruncatingTail
        let footer = NSStackView(views: [progressIndicator, statusLabel])
        footer.orientation = .horizontal
        footer.alignment = .centerY
        footer.spacing = 7

        let layout = NSStackView(views: [header, splitView, footer])
        layout.orientation = .vertical
        layout.alignment = .leading
        layout.spacing = 12
        layout.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(layout)
        NSLayoutConstraint.activate([
            layout.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            layout.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 18),
            layout.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18),
            layout.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -14),
            header.widthAnchor.constraint(equalTo: layout.widthAnchor),
            splitView.widthAnchor.constraint(equalTo: layout.widthAnchor),
            footer.widthAnchor.constraint(equalTo: layout.widthAnchor),
            splitView.heightAnchor.constraint(greaterThanOrEqualToConstant: 430)
        ])
        controller.view = root
        return controller
    }

    private func buildCheckpointSidebar() -> NSView {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("checkpoint"))
        column.title = "Checkpoint"
        column.resizingMask = .autoresizingMask
        checkpointTable.addTableColumn(column)
        checkpointTable.headerView = nil
        checkpointTable.delegate = self
        checkpointTable.dataSource = self
        checkpointTable.rowHeight = 56
        checkpointTable.backgroundColor = .clear
        checkpointTable.selectionHighlightStyle = .regular
        checkpointTable.setAccessibilityLabel("Workspace recovery checkpoints")

        let scrollView = NSScrollView()
        scrollView.documentView = checkpointTable
        scrollView.hasVerticalScroller = true
        scrollView.drawsBackground = false
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        emptyCheckpointLabel.textColor = .secondaryLabelColor
        emptyCheckpointLabel.alignment = .center
        emptyCheckpointLabel.maximumNumberOfLines = 5
        emptyCheckpointLabel.translatesAutoresizingMaskIntoConstraints = false

        let sidebar = displayPolicy.makeSidebarContainer()
        sidebarContainer = sidebar
        sidebar.addSubview(scrollView)
        sidebar.addSubview(emptyCheckpointLabel)
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: sidebar.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor),
            emptyCheckpointLabel.centerYAnchor.constraint(equalTo: sidebar.centerYAnchor),
            emptyCheckpointLabel.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 24),
            emptyCheckpointLabel.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -24)
        ])
        return sidebar
    }

    private func buildPreviewDetail() -> NSView {
        detailTitleLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        detailTitleLabel.maximumNumberOfLines = 2
        detailMetadataLabel.textColor = .secondaryLabelColor
        detailMetadataLabel.maximumNumberOfLines = 2
        summaryLabel.font = .systemFont(ofSize: 13, weight: .medium)
        summaryLabel.maximumNumberOfLines = 3
        safetyLabel.textColor = .secondaryLabelColor
        safetyLabel.maximumNumberOfLines = 4

        configurePreviewTable()
        let tableScroll = NSScrollView()
        tableScroll.documentView = previewTable
        tableScroll.hasVerticalScroller = true
        tableScroll.hasHorizontalScroller = true
        tableScroll.drawsBackground = false
        tableScroll.translatesAutoresizingMaskIntoConstraints = false

        emptyPreviewLabel.textColor = .secondaryLabelColor
        emptyPreviewLabel.alignment = .center
        emptyPreviewLabel.maximumNumberOfLines = 4
        emptyPreviewLabel.translatesAutoresizingMaskIntoConstraints = false
        let previewContainer = NSView()
        previewContainer.addSubview(tableScroll)
        previewContainer.addSubview(emptyPreviewLabel)
        NSLayoutConstraint.activate([
            tableScroll.topAnchor.constraint(equalTo: previewContainer.topAnchor),
            tableScroll.leadingAnchor.constraint(equalTo: previewContainer.leadingAnchor),
            tableScroll.trailingAnchor.constraint(equalTo: previewContainer.trailingAnchor),
            tableScroll.bottomAnchor.constraint(equalTo: previewContainer.bottomAnchor),
            emptyPreviewLabel.centerYAnchor.constraint(equalTo: previewContainer.centerYAnchor),
            emptyPreviewLabel.leadingAnchor.constraint(equalTo: previewContainer.leadingAnchor, constant: 30),
            emptyPreviewLabel.trailingAnchor.constraint(equalTo: previewContainer.trailingAnchor, constant: -30)
        ])

        removeAddedFilesButton.target = self
        removeAddedFilesButton.action = #selector(restoreScopeChanged(_:))
        removeAddedFilesButton.setAccessibilityLabel("Remove files added after checkpoint during restore")
        let scopeExplanation = NSTextField(wrappingLabelWithString: "By default, files created after the checkpoint are preserved. Restoring modified files always requires a separate confirmation.")
        scopeExplanation.font = .systemFont(ofSize: 11)
        scopeExplanation.textColor = .secondaryLabelColor
        scopeExplanation.maximumNumberOfLines = 3
        let scope = NSStackView(views: [removeAddedFilesButton, scopeExplanation])
        scope.orientation = .vertical
        scope.alignment = .leading
        scope.spacing = 3

        configureButton(deleteButton, action: #selector(deleteCheckpoint(_:)), symbol: "trash")
        deleteButton.contentTintColor = .systemRed
        configureButton(restoreButton, action: #selector(restoreCheckpoint(_:)), symbol: "arrow.uturn.backward.circle")
        restoreButton.keyEquivalent = "\r"
        let actions = NSStackView(views: [deleteButton, NSView(), restoreButton])
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 8

        let separator = NSBox()
        separator.boxType = .separator
        let detail = NSStackView(views: [
            detailTitleLabel,
            detailMetadataLabel,
            summaryLabel,
            safetyLabel,
            separator,
            previewContainer,
            scope,
            actions
        ])
        detail.orientation = .vertical
        detail.alignment = .leading
        detail.spacing = 9
        detail.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        for view in [detailTitleLabel, detailMetadataLabel, summaryLabel, safetyLabel, separator, previewContainer, scope, actions] {
            view.widthAnchor.constraint(equalTo: detail.widthAnchor, constant: -40).isActive = true
        }
        previewContainer.heightAnchor.constraint(greaterThanOrEqualToConstant: 210).isActive = true
        return detail
    }

    private func configurePreviewTable() {
        let change = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("change"))
        change.title = "Change"
        change.width = 92
        change.minWidth = 82
        change.maxWidth = 120
        let path = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("path"))
        path.title = "File"
        path.minWidth = 180
        path.resizingMask = .autoresizingMask
        let safety = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("safety"))
        safety.title = "Restore behavior"
        safety.width = 210
        safety.minWidth = 155
        previewTable.addTableColumn(change)
        previewTable.addTableColumn(path)
        previewTable.addTableColumn(safety)
        previewTable.delegate = self
        previewTable.dataSource = self
        previewTable.rowHeight = 27
        previewTable.selectionHighlightStyle = .none
        previewTable.usesAlternatingRowBackgroundColors = true
        previewTable.setAccessibilityLabel("Workspace changes in selected checkpoint preview")
    }

    private func configureButton(_ button: NSButton, action: Selector, symbol: String) {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
        if let image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) {
            button.image = image
            button.imagePosition = .imageLeading
        }
    }

    @objc private func refreshAction(_ sender: Any?) { refresh() }

    @objc private func captureCheckpoint(_ sender: Any?) {
        guard !isBusy else { return }
        let labelField = NSTextField(string: "Before agent changes — \(Self.labelDateFormatter.string(from: Date()))")
        labelField.placeholderString = "Checkpoint label"
        labelField.maximumNumberOfLines = 1
        labelField.frame = NSRect(x: 0, y: 0, width: 380, height: 24)
        labelField.setAccessibilityLabel("Checkpoint label")

        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "Create a workspace checkpoint?"
        alert.informativeText = "Recoverable regular files will be copied into private app storage. Generated folders, links, oversized content, and likely credential files are excluded or rejected by policy."
        alert.accessoryView = labelField
        alert.addButton(withTitle: "Create Checkpoint")
        alert.addButton(withTitle: "Cancel")
        present(alert) { [weak self, weak labelField] approved in
            guard approved, let self, let labelField else { return }
            self.beginCheckpointCapture(label: labelField.stringValue)
        }
    }

    private func beginCheckpointCapture(label: String) {
        operationGeneration += 1
        let generation = operationGeneration
        setBusy(true, message: "Scanning the approved workspace and creating a private checkpoint…")
        operationQueue.async { [operations] in
            let result = Result { try operations.captureCheckpoint(label) }
            DispatchQueue.main.async { [weak self] in
                guard let self, generation == self.operationGeneration else { return }
                switch result {
                case .success(let checkpoint):
                    self.onCheckpointCaptured?(checkpoint)
                    self.setBusy(false, message: "Checkpoint “\(checkpoint.label)” was created with \(checkpoint.files.count) recoverable files.")
                    self.reloadCheckpoints(selecting: checkpoint.id)
                case .failure(let error):
                    self.setBusy(false, message: "Checkpoint was not created: \(Self.errorDescription(error))")
                    self.showError(title: "Checkpoint was not created", error: error)
                }
            }
        }
    }

    @objc private func deleteCheckpoint(_ sender: Any?) {
        guard !isBusy, let checkpoint = selectedCheckpoint else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Delete “\(checkpoint.label)”?"
        alert.informativeText = "This permanently removes the local recovery copy. It does not change any file in the workspace."
        alert.addButton(withTitle: "Delete Checkpoint")
        alert.addButton(withTitle: "Cancel")
        present(alert) { [weak self] approved in
            guard approved, let self else { return }
            self.beginCheckpointDeletion(checkpoint)
        }
    }

    private func beginCheckpointDeletion(_ checkpoint: WorkspaceCheckpointSummary) {
        operationGeneration += 1
        let generation = operationGeneration
        setBusy(true, message: "Deleting the selected local checkpoint…")
        operationQueue.async { [operations] in
            let result = Result { try operations.deleteCheckpoint(checkpoint.id) }
            DispatchQueue.main.async { [weak self] in
                guard let self, generation == self.operationGeneration else { return }
                switch result {
                case .success:
                    self.setBusy(false, message: "Checkpoint “\(checkpoint.label)” was deleted. The workspace was not changed.")
                    self.reloadCheckpoints(selecting: nil)
                case .failure(let error):
                    self.setBusy(false, message: "Checkpoint was not deleted: \(Self.errorDescription(error))")
                    self.showError(title: "Checkpoint was not deleted", error: error)
                }
            }
        }
    }

    @objc private func restoreScopeChanged(_ sender: Any?) { updateControlState() }

    @objc private func restoreCheckpoint(_ sender: Any?) {
        guard !isBusy,
              let checkpoint = selectedCheckpoint,
              let preview = currentPreview,
              preview.checkpointID == checkpoint.id else { return }

        let hardConflicts = preview.conflicts.filter { $0.kind != .wouldOverwriteModifiedFile }
        guard hardConflicts.isEmpty else {
            showConflictAlert(hardConflicts)
            return
        }

        let modifiedCount = preview.changes.filter { $0.kind == .modified }.count
        let deletedCount = preview.changes.filter { $0.kind == .deleted }.count
        let addedCount = preview.changes.filter { $0.kind == .added }.count
        let removeAddedFiles = removeAddedFilesButton.state == .on && addedCount > 0

        let options = WorkspaceRestoreOptions(
            overwriteModifiedFiles: modifiedCount > 0,
            removeAddedFiles: removeAddedFiles
        )
        let continueAfterModifiedApproval = { [weak self] in
            guard let self else { return }
            if removeAddedFiles {
                let alert = NSAlert()
                alert.alertStyle = .critical
                alert.messageText = "Remove \(Self.fileCount(addedCount)) added after the checkpoint?"
                alert.informativeText = "This is a separate destructive choice. These files do not exist in the checkpoint and will be removed from the workspace during the restore."
                alert.addButton(withTitle: "Remove Added Files")
                alert.addButton(withTitle: "Keep Added Files")
                self.present(alert) { [weak self] approved in
                    guard approved, let self else { return }
                    self.beginRestoreOperation(checkpoint: checkpoint, preview: preview, options: options)
                }
            } else if modifiedCount == 0 {
                guard deletedCount > 0 else { return }
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "Restore \(Self.fileCount(deletedCount))?"
                alert.informativeText = "Missing files will be recreated from the selected checkpoint. Files added since the checkpoint will be kept."
                alert.addButton(withTitle: "Restore Missing Files")
                alert.addButton(withTitle: "Cancel")
                self.present(alert) { [weak self] approved in
                    guard approved, let self else { return }
                    self.beginRestoreOperation(checkpoint: checkpoint, preview: preview, options: options)
                }
            } else {
                self.beginRestoreOperation(checkpoint: checkpoint, preview: preview, options: options)
            }
        }

        if modifiedCount > 0 {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Overwrite \(Self.fileCount(modifiedCount))?"
            alert.informativeText = "These files were modified after the checkpoint. Their current contents will be replaced by the checkpoint versions. The restore is transactional, but you should keep independent source-control or backups for important work."
            alert.addButton(withTitle: "Overwrite Modified Files")
            alert.addButton(withTitle: "Cancel Restore")
            present(alert) { approved in
                guard approved else { return }
                continueAfterModifiedApproval()
            }
        } else {
            continueAfterModifiedApproval()
        }
    }

    private func beginRestoreOperation(
        checkpoint: WorkspaceCheckpointSummary,
        preview: WorkspaceRestorePreview,
        options: WorkspaceRestoreOptions
    ) {
        operationGeneration += 1
        let generation = operationGeneration
        pendingRestorePreparationGeneration = generation
        setBusy(true, message: "Stopping agent work before restoring the workspace…")
        let beginRestore = { [weak self] (preparation: Result<Void, Error>) in
            DispatchQueue.main.async { [weak self] in
                guard let self,
                      generation == self.operationGeneration,
                      self.pendingRestorePreparationGeneration == generation else { return }
                // A host boundary is callback-based and may be buggy. Only its
                // first answer can consume this restore generation.
                self.pendingRestorePreparationGeneration = nil
                switch preparation {
                case .success:
                    self.performRestore(
                        checkpoint: checkpoint,
                        preview: preview,
                        options: options,
                        generation: generation
                    )
                case .failure:
                    self.onRestoreAttemptFinished?(false)
                    let safeError = WorkspaceRecoveryControllerError.restorePreparationFailed
                    self.setBusy(false, message: safeError.localizedDescription)
                    self.showError(title: "Restore kept safely paused", error: safeError)
                }
            }
        }
        guard let onPrepareRestore else {
            pendingRestorePreparationGeneration = nil
            onRestoreAttemptFinished?(false)
            let error = WorkspaceRecoveryControllerError.restorePreparationUnavailable
            setBusy(false, message: Self.errorDescription(error))
            showError(title: "Restore kept safely paused", error: error)
            return
        }
        onPrepareRestore(beginRestore)
    }

    private func performRestore(
        checkpoint: WorkspaceCheckpointSummary,
        preview: WorkspaceRestorePreview,
        options: WorkspaceRestoreOptions,
        generation: Int
    ) {
        setBusy(true, message: "Authenticating checkpoint contents and restoring the workspace transactionally…")
        operationQueue.async { [operations] in
            do {
                let report = try operations.restore(checkpoint.id, preview, options)
                let refreshedPreview = Result { try operations.previewRestore(checkpoint.id) }
                DispatchQueue.main.async { [weak self] in
                    guard let self, generation == self.operationGeneration else { return }
                    self.onRestoreCompleted?(report)
                    self.onRestoreAttemptFinished?(true)
                    switch refreshedPreview {
                    case .success(let freshPreview):
                        self.currentPreview = freshPreview
                        self.render(preview: freshPreview, checkpoint: checkpoint)
                        self.setBusy(false, message: Self.reportDescription(report))
                    case .failure:
                        self.clearPreview(message: "Restore completed, but the updated workspace preview could not be verified.")
                        self.setBusy(false, message: "\(Self.reportDescription(report)) The updated preview could not be verified; refresh before another restore.")
                    }
                }
            } catch {
                DispatchQueue.main.async { [weak self] in
                    guard let self, generation == self.operationGeneration else { return }
                    self.onRestoreAttemptFinished?(false)
                    self.setBusy(false, message: "Restore did not complete: \(Self.errorDescription(error))")
                    if let journalError = error as? WorkspaceJournalError,
                       case .stalePreview = journalError {
                        self.currentPreview = nil
                        self.previewRows = []
                        self.previewTable.reloadData()
                        self.emptyPreviewLabel.isHidden = false
                    }
                    self.showError(title: Self.restoreErrorTitle(error), error: error)
                    if let journalError = error as? WorkspaceJournalError,
                       case .stalePreview = journalError {
                        self.preview(checkpoint)
                    }
                }
            }
        }
    }

    private func reloadCheckpoints(selecting checkpointID: UUID?) {
        guard !isBusy else { return }
        let retainedID = checkpointID ?? selectedCheckpoint?.id
        operationGeneration += 1
        let generation = operationGeneration
        setBusy(true, message: "Loading local recovery checkpoints…")
        operationQueue.async { [operations] in
            let result = Result { try operations.listCheckpoints() }
            DispatchQueue.main.async { [weak self] in
                guard let self, generation == self.operationGeneration else { return }
                switch result {
                case .success(let checkpoints):
                    self.checkpoints = checkpoints
                    self.checkpointTable.reloadData()
                    self.emptyCheckpointLabel.isHidden = !checkpoints.isEmpty
                    self.checkpointTable.isHidden = checkpoints.isEmpty
                    self.clearPreview(message: checkpoints.isEmpty
                        ? "Create a checkpoint to establish a recoverable baseline."
                        : "Select a checkpoint to compare it with the current workspace.")
                    self.setBusy(false, message: checkpoints.isEmpty
                        ? "No local recovery checkpoints."
                        : "\(checkpoints.count) local recovery checkpoint\(checkpoints.count == 1 ? "" : "s"). Select one to scan for changes.")
                    let selectedRow: Int?
                    if let retainedID,
                       let retainedRow = checkpoints.firstIndex(where: { $0.id == retainedID }) {
                        selectedRow = retainedRow
                    } else {
                        selectedRow = checkpoints.isEmpty ? nil : 0
                    }
                    if let selectedRow {
                        self.checkpointTable.selectRowIndexes(IndexSet(integer: selectedRow), byExtendingSelection: false)
                    }
                case .failure(let error):
                    self.checkpoints = []
                    self.checkpointTable.reloadData()
                    self.emptyCheckpointLabel.isHidden = false
                    self.checkpointTable.isHidden = true
                    self.clearPreview(message: "Recovery storage could not be read safely.")
                    self.setBusy(false, message: "Recovery checkpoints are unavailable: \(Self.errorDescription(error))")
                    self.showError(title: "Recovery checkpoints are unavailable", error: error)
                }
            }
        }
    }

    private func preview(_ checkpoint: WorkspaceCheckpointSummary) {
        guard !isBusy else { return }
        currentPreview = nil
        previewRows = []
        previewTable.reloadData()
        emptyPreviewLabel.stringValue = "Scanning the current workspace against “\(checkpoint.label)”…"
        emptyPreviewLabel.isHidden = false
        detailTitleLabel.stringValue = checkpoint.label
        detailMetadataLabel.stringValue = Self.checkpointMetadata(checkpoint)
        summaryLabel.stringValue = "Scanning for added, modified, and missing files…"
        safetyLabel.stringValue = "Nothing is changed while a preview is created."
        removeAddedFilesButton.state = .off

        operationGeneration += 1
        let generation = operationGeneration
        setBusy(true, message: "Scanning the approved workspace. No files are being changed…")
        operationQueue.async { [operations] in
            let result = Result { try operations.previewRestore(checkpoint.id) }
            DispatchQueue.main.async { [weak self] in
                guard let self, generation == self.operationGeneration else { return }
                switch result {
                case .success(let preview):
                    guard self.selectedCheckpoint?.id == checkpoint.id else {
                        self.setBusy(false, message: "Preview finished for a checkpoint that is no longer selected.")
                        return
                    }
                    self.currentPreview = preview
                    self.render(preview: preview, checkpoint: checkpoint)
                    let hardCount = preview.conflicts.filter { $0.kind != .wouldOverwriteModifiedFile }.count
                    self.setBusy(false, message: hardCount == 0
                        ? "Preview is current and bound to this exact workspace state."
                        : "Preview found \(hardCount) unsafe path conflict\(hardCount == 1 ? "" : "s"); restore is blocked until the workspace is corrected and rescanned.")
                case .failure(let error):
                    self.clearPreview(message: "The workspace could not be compared safely.")
                    self.detailTitleLabel.stringValue = checkpoint.label
                    self.detailMetadataLabel.stringValue = Self.checkpointMetadata(checkpoint)
                    self.setBusy(false, message: "Workspace preview failed: \(Self.errorDescription(error))")
                    self.showError(title: "Workspace preview failed", error: error)
                }
            }
        }
    }

    private func render(preview: WorkspaceRestorePreview, checkpoint: WorkspaceCheckpointSummary) {
        let conflictsByPath = Dictionary(grouping: preview.conflicts, by: \WorkspaceRestoreConflict.relativePath)
        previewRows = preview.changes.map {
            PreviewRow(change: $0, conflicts: conflictsByPath[$0.relativePath] ?? [])
        }
        previewTable.reloadData()
        emptyPreviewLabel.isHidden = !previewRows.isEmpty
        emptyPreviewLabel.stringValue = "The workspace currently matches this checkpoint."
        detailTitleLabel.stringValue = checkpoint.label
        detailMetadataLabel.stringValue = Self.checkpointMetadata(checkpoint)

        let added = preview.changes.filter { $0.kind == .added }.count
        let modified = preview.changes.filter { $0.kind == .modified }.count
        let deleted = preview.changes.filter { $0.kind == .deleted }.count
        summaryLabel.stringValue = "\(added) added · \(modified) modified · \(deleted) missing"
        let hardConflicts = preview.conflicts.filter { $0.kind != .wouldOverwriteModifiedFile }
        if hardConflicts.isEmpty {
            safetyLabel.stringValue = modified > 0
                ? "Modified files can be restored only after explicit overwrite approval. Added files are kept unless you separately choose and confirm their removal."
                : "No unsafe path conflicts were found. Added files are kept unless you separately choose and confirm their removal."
            safetyLabel.textColor = .secondaryLabelColor
        } else {
            safetyLabel.stringValue = "Restore is blocked by \(hardConflicts.count) unsafe destination conflict\(hardConflicts.count == 1 ? "" : "s"). Symbolic links, non-regular files, directories at file destinations, and obstructed parents are never replaced."
            safetyLabel.textColor = .systemRed
        }
        removeAddedFilesButton.state = .off
        updateControlState()
    }

    private func clearPreview(message: String) {
        currentPreview = nil
        previewRows = []
        previewTable.reloadData()
        emptyPreviewLabel.stringValue = message
        emptyPreviewLabel.isHidden = false
        detailTitleLabel.stringValue = selectedCheckpoint?.label ?? "Select a checkpoint"
        detailMetadataLabel.stringValue = selectedCheckpoint.map(Self.checkpointMetadata) ?? ""
        summaryLabel.stringValue = ""
        safetyLabel.stringValue = selectedCheckpoint == nil
            ? "Recovery previews are bound to the exact current workspace state."
            : "Nothing will be changed until a verified preview is available."
        safetyLabel.textColor = .secondaryLabelColor
        removeAddedFilesButton.state = .off
        updateControlState()
    }

    /// Internal so deterministic accessibility tests can verify the exact
    /// native control state without waiting on an operation-queue race.
    func setBusy(_ busy: Bool, message: String) {
        isBusy = busy
        statusLabel.stringValue = message
        displayPolicy.progressIndicatorPresentation(isBusy: busy).apply(to: progressIndicator)
        updateControlState()
    }

    private func refreshAccessibilityDisplayOptions() {
        sidebarContainer?.refreshAccessibilityAppearance()
        displayPolicy.progressIndicatorPresentation(isBusy: isBusy).apply(to: progressIndicator)
    }

    private func updateControlState() {
        refreshButton.isEnabled = !isBusy
        captureButton.isEnabled = !isBusy
        checkpointTable.isEnabled = !isBusy && !checkpoints.isEmpty
        deleteButton.isEnabled = !isBusy && selectedCheckpoint != nil

        let addedCount = currentPreview?.changes.filter { $0.kind == .added }.count ?? 0
        removeAddedFilesButton.isEnabled = !isBusy && addedCount > 0
        guard !isBusy, let preview = currentPreview else {
            restoreButton.isEnabled = false
            return
        }
        let hasHardConflicts = preview.conflicts.contains { $0.kind != .wouldOverwriteModifiedFile }
        let hasBaseRestore = preview.changes.contains { $0.kind == .modified || $0.kind == .deleted }
        let removesAdditions = removeAddedFilesButton.state == .on && addedCount > 0
        restoreButton.isEnabled = !hasHardConflicts && (hasBaseRestore || removesAdditions)
    }

    private func showConflictAlert(_ conflicts: [WorkspaceRestoreConflict]) {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Restore is blocked by unsafe workspace paths"
        let details = conflicts.prefix(12).map { "• \($0.relativePath) — \(Self.conflictDescription($0.kind))" }
        let remaining = max(0, conflicts.count - details.count)
        alert.informativeText = details.joined(separator: "\n") + (remaining > 0 ? "\n…and \(remaining) more." : "") + "\n\nCorrect these paths, then refresh the preview. \(ProductBrand.displayName) will not replace links or non-regular filesystem objects."
        alert.addButton(withTitle: "OK")
        present(alert) { _ in }
    }

    private func showError(title: String, error: Error) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = Self.errorDescription(error)
        alert.addButton(withTitle: "OK")
        present(alert) { _ in }
    }

    private func present(_ alert: NSAlert, completion: @escaping WorkspaceRecoveryAlertCompletion) {
        alertPresenter.present(alert, window, completion)
    }

    private static func checkpointMetadata(_ checkpoint: WorkspaceCheckpointSummary) -> String {
        "\(dateFormatter.string(from: checkpoint.createdAt)) · \(checkpoint.fileCount) files · \(ByteCountFormatter.string(fromByteCount: checkpoint.totalBytes, countStyle: .file))"
    }

    private static func changeDescription(_ kind: WorkspaceChangeKind) -> String {
        switch kind {
        case .added: return "Added since"
        case .modified: return "Modified"
        case .deleted: return "Missing"
        }
    }

    private static func changeColor(_ kind: WorkspaceChangeKind) -> NSColor {
        switch kind {
        case .added: return .systemBlue
        case .modified: return .systemOrange
        case .deleted: return .systemPurple
        }
    }

    private static func safetyDescription(for row: PreviewRow) -> String {
        if let conflict = row.conflicts.first(where: { $0.kind != .wouldOverwriteModifiedFile }) {
            return "Blocked: \(conflictDescription(conflict.kind))"
        }
        if row.conflicts.contains(where: { $0.kind == .wouldOverwriteModifiedFile }) {
            return "Separate overwrite approval required"
        }
        switch row.change.kind {
        case .added: return "Kept unless separately removed"
        case .modified: return "Separate overwrite approval required"
        case .deleted: return "Recreated from checkpoint"
        }
    }

    private static func conflictDescription(_ kind: WorkspaceRestoreConflictKind) -> String {
        switch kind {
        case .wouldOverwriteModifiedFile: return "would overwrite a modified file"
        case .symbolicLinkAtDestination: return "symbolic link at destination"
        case .directoryAtFileDestination: return "directory at file destination"
        case .nonRegularDestination: return "non-regular file at destination"
        case .obstructedParent: return "parent path is linked or obstructed"
        }
    }

    private static func fileCount(_ count: Int) -> String {
        "\(count) file\(count == 1 ? "" : "s")"
    }

    private static func reportDescription(_ report: WorkspaceRestoreReport) -> String {
        "Restore completed: \(report.restoredDeletedFiles) recreated, \(report.overwrittenModifiedFiles) overwritten, \(report.removedAddedFiles) added files removed, \(report.unchangedFiles) unchanged."
    }

    static func safeWorkspaceName(_ url: URL) -> String {
        AuxiliaryDisplayPolicy.singleLine(
            url.lastPathComponent,
            maximumCharacters: 180,
            fallback: "the approved workspace"
        )
    }

    private static func restoreErrorTitle(_ error: Error) -> String {
        guard let journalError = error as? WorkspaceJournalError else {
            return "Workspace was not restored"
        }
        if case .rollbackFailed = journalError {
            return "Restore rollback needs immediate attention"
        }
        if case .stalePreview = journalError {
            return "Workspace changed after the preview"
        }
        return "Workspace was not restored"
    }

    private static func errorDescription(_ error: Error) -> String {
        if let controllerError = error as? WorkspaceRecoveryControllerError {
            return controllerError.localizedDescription
        }
        guard let journalError = error as? WorkspaceJournalError else {
            return "The workspace recovery operation failed safely. No unverified error detail was displayed."
        }
        switch journalError {
        case .restoreConflicts(let conflicts):
            let details = conflicts.prefix(10).map { "• \($0.relativePath) — \(conflictDescription($0.kind))" }
            return (journalError.errorDescription ?? "Restore conflicts were found.") + "\n\n" + details.joined(separator: "\n")
        case .rollbackFailed(let recoveryDirectory):
            return "The restore failed and the automatic rollback could not be completed. Agent work remains stopped. Authenticated recovery material was preserved at:\n\n\(recoveryDirectory)\n\nCopy that private folder before making further changes."
        case .fileTooLarge(_, let maximum):
            return "A workspace file exceeds the per-file recovery limit of \(maximum) bytes."
        case .depthLimitExceeded(_, let maximum):
            return "A workspace path exceeds the recovery depth limit of \(maximum)."
        case .workspaceChangedDuringScan:
            return "A workspace path changed or could not be displayed safely while it was being scanned. Try again."
        case .checkpointContentCorrupt:
            return "Stored recovery content failed its integrity check."
        default:
            return journalError.errorDescription ?? "The workspace recovery operation failed safely."
        }
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private static let labelDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

private final class WorkspaceCheckpointCellView: NSTableCellView {
    private let titleLabel = NSTextField(labelWithString: "")
    private let metadataLabel = NSTextField(labelWithString: "")

    init(identifier: NSUserInterfaceItemIdentifier) {
        super.init(frame: .zero)
        self.identifier = identifier
        titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        titleLabel.lineBreakMode = .byTruncatingTail
        metadataLabel.font = .systemFont(ofSize: 10)
        metadataLabel.textColor = .secondaryLabelColor
        metadataLabel.lineBreakMode = .byTruncatingTail
        let stack = NSStackView(views: [titleLabel, metadataLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            titleLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            metadataLabel.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(summary: WorkspaceCheckpointSummary) {
        titleLabel.stringValue = summary.label
        metadataLabel.stringValue = "\(Self.dateFormatter.string(from: summary.createdAt)) · \(summary.fileCount) files · \(ByteCountFormatter.string(fromByteCount: summary.totalBytes, countStyle: .file))"
        toolTip = "\(summary.label)\n\(metadataLabel.stringValue)"
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}
