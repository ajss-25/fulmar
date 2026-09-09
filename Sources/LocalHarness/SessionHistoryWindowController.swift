import AppKit
import UniformTypeIdentifiers

struct SessionHistoryExportSelection: Equatable {
    let format: ConversationExportFormat
    let redaction: ConversationExportRedactionOptions
}

/// All blocking AppKit interactions owned by Task History live behind this
/// main-actor seam. Production keeps the native sheets/panels below; tests can
/// drive the real controller actions without opening process-global modals.
@MainActor
struct SessionHistoryWindowInteractions {
    let requestRename: (_ currentTitle: String) -> String?
    let confirmArchive: () -> Bool
    let requestExport: () -> SessionHistoryExportSelection?
    let chooseExportDestination: (_ artifact: ConversationExportArtifact) -> URL?
    let revealExport: (_ url: URL) -> Void

    static let live = SessionHistoryWindowInteractions(
        requestRename: { currentTitle in
            let alert = NSAlert()
            alert.messageText = "Rename task"
            alert.informativeText = "Choose a private title for this Harness task."
            alert.addButton(withTitle: "Rename")
            alert.addButton(withTitle: "Cancel")
            let field = NSTextField(string: currentTitle)
            field.frame = NSRect(x: 0, y: 0, width: 420, height: 26)
            field.setAccessibilityLabel("Task title")
            alert.accessoryView = field
            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            return field.stringValue
        },
        confirmArchive: {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Archive this task?"
            alert.informativeText = "The task is hidden from active history but remains in the Harness archive. Its files are not deleted."
            alert.addButton(withTitle: "Archive Task")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        requestExport: {
            let choices = NSAlert()
            choices.messageText = "Export this conversation"
            choices.informativeText = "Exports never include attachment files. The recommended privacy option removes detected credentials, attachment names, and the private task identifier."
            choices.addButton(withTitle: "Continue")
            choices.addButton(withTitle: "Cancel")
            let accessory = ConversationExportChoiceAccessory()
            choices.accessoryView = accessory.view
            guard choices.runModal() == .alertFirstButtonReturn else { return nil }

            let format: ConversationExportFormat = accessory.formatPicker.indexOfSelectedItem == 1
                ? .json
                : .markdown
            let redaction: ConversationExportRedactionOptions
            switch accessory.privacyPicker.indexOfSelectedItem {
            case 1:
                redaction = .structureOnly
            case 2:
                let warning = NSAlert()
                warning.alertStyle = .warning
                warning.messageText = "Export the full private transcript?"
                warning.informativeText = "Message text, provider details, task identifiers, and any secrets written in the chat may be included. Save it only somewhere you trust."
                warning.addButton(withTitle: "Export Full Transcript")
                warning.addButton(withTitle: "Cancel")
                guard warning.runModal() == .alertFirstButtonReturn else { return nil }
                redaction = .none
            default:
                redaction = .recommended
            }
            return SessionHistoryExportSelection(format: format, redaction: redaction)
        },
        chooseExportDestination: { artifact in
            let panel = NSSavePanel()
            panel.title = "Export Conversation"
            panel.prompt = "Export"
            panel.nameFieldStringValue = artifact.suggestedFilename
            panel.canCreateDirectories = true
            panel.isExtensionHidden = false
            panel.allowedContentTypes = artifact.format == .markdown
                ? [UTType(filenameExtension: "md") ?? .plainText]
                : [.json]
            guard panel.runModal() == .OK else { return nil }
            return panel.url
        },
        revealExport: { url in
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    )
}

/// Native, provider-neutral history browser. Opening a task is intentionally a
/// callback: DSH has list/search/history/create RPCs, but no mutable "select"
/// RPC. The host application owns navigation to the selected surface.
final class SessionHistoryWindowController: NSWindowController,
    NSTableViewDataSource,
    NSTableViewDelegate,
    NSSearchFieldDelegate,
    NSWindowDelegate {

    var onSessionSelected: ((HarnessSessionID) -> Void)?

    private let dataSource: any SessionHistoryDataProviding
    private let lifecycle: SessionHistoryLifecycleGate
    private let newSessionRequest: () -> HarnessSessionCreateRequest?
    private let newSessionSelection: () -> ModelSelection?
    private let interactions: SessionHistoryWindowInteractions
    private let displayPolicy: NativeAccessibilityDisplayPolicy
    private var accessibilityDisplayObserver: NativeAccessibilityDisplayObserver?
    private var sidebarContainer: NativeAccessibilitySidebarView?

    private let searchField = NSSearchField()
    private let tableView = NSTableView()
    private let listStatusLabel = NSTextField(labelWithString: "Loading task history…")
    private let detailTitleLabel = NSTextField(wrappingLabelWithString: "Select a task")
    private let projectLabel = NSTextField(labelWithString: "")
    private let routeLabel = NSTextField(wrappingLabelWithString: "")
    private let routeIDsLabel = NSTextField(wrappingLabelWithString: "")
    private let boundaryLabel = NSTextField(labelWithString: "")
    private let transcriptTextView = NSTextView()
    private let openButton = NSButton(title: "Open Task", target: nil, action: nil)
    private let renameButton = NSButton(title: "Rename", target: nil, action: nil)
    private let branchButton = NSButton(title: "Branch", target: nil, action: nil)
    private let archiveButton = NSButton(title: "Archive", target: nil, action: nil)
    private let exportButton = NSButton(title: "Export…", target: nil, action: nil)
    private let olderButton = NSButton(title: "Load Earlier Messages", target: nil, action: nil)
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let newButton = NSButton(title: "New Task", target: nil, action: nil)

    private var rows: [SessionHistoryRow] = []
    private var messages: [SessionTranscriptMessage] = []
    private var selectedSessionID: HarnessSessionID?
    private var selectedRoute: SessionRouteMetadataState = .unavailable
    private var olderBeforeSequence: Int?
    private var browseGeneration = 0
    private var detailGeneration = 0
    private var isProgrammaticSelection = false
    private var searchWorkItem: DispatchWorkItem?
    private var browseTask: Task<Void, Never>?
    private var detailTask: Task<Void, Never>?
    private var olderTask: Task<Void, Never>?
    private var createTask: Task<Void, Never>?
    private var actionTask: Task<Void, Never>?
    private var exportTask: Task<Void, Never>?
    private var createGeneration = 0
    private var actionGeneration = 0
    private var exportGeneration = 0

    init(
        dataSource: any SessionHistoryDataProviding,
        newSessionRequest: @escaping () -> HarnessSessionCreateRequest? = { .init() },
        newSessionSelection: @escaping () -> ModelSelection? = { .defaultLocal },
        interactions: SessionHistoryWindowInteractions? = nil,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live,
        lifecycle: SessionHistoryLifecycleGate = .init()
    ) {
        self.dataSource = dataSource
        self.lifecycle = lifecycle
        self.newSessionRequest = newSessionRequest
        self.newSessionSelection = newSessionSelection
        self.interactions = interactions ?? .live
        self.displayPolicy = displayPolicy
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_080, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Task History"
        window.subtitle = "Private Harness conversations"
        window.minSize = NSSize(width: 820, height: 540)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.SessionHistory")
        super.init(window: window)
        window.delegate = self
        window.contentViewController = buildContent()
        accessibilityDisplayObserver = NativeAccessibilityDisplayObserver { [weak self] in
            self?.sidebarContainer?.refreshAccessibilityAppearance()
        }
        if !window.setFrameUsingName("LocalHarness.SessionHistory") { window.center() }
    }

    convenience init(
        rpcClient: HarnessRPCClient,
        descriptors: [ProviderDescriptor] = BuiltInProviderDescriptors.all,
        newSessionRequest: @escaping () -> HarnessSessionCreateRequest? = { .init() },
        newSessionSelection: @escaping () -> ModelSelection? = { .defaultLocal },
        interactions: SessionHistoryWindowInteractions? = nil,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live,
        lifecycle: SessionHistoryLifecycleGate = .init()
    ) {
        self.init(
            dataSource: SessionHistoryRepository(
                service: rpcClient,
                descriptors: descriptors,
                lifecycle: lifecycle
            ),
            newSessionRequest: newSessionRequest,
            newSessionSelection: newSessionSelection,
            interactions: interactions,
            displayPolicy: displayPolicy,
            lifecycle: lifecycle
        )
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit { cancelWork() }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        refresh()
    }

    func refresh() {
        browseGeneration += 1
        let generation = browseGeneration
        let query = searchField.stringValue
        let retainedSelection = selectedSessionID
        let source = dataSource
        browseTask?.cancel()
        listStatusLabel.stringValue = query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "Loading task history…"
            : "Searching task history…"
        refreshButton.isEnabled = false

        browseTask = Task { [weak self] in
            do {
                let snapshot = try await source.browse(query: query)
                guard !Task.isCancelled else { return }
                await MainActor.run { [weak self] in
                    guard let self, generation == self.browseGeneration else { return }
                    self.rows = snapshot.rows
                    self.tableView.reloadData()
                    self.refreshButton.isEnabled = true
                    self.updateListStatus(snapshot)
                    if let retainedSelection,
                       let row = self.rows.firstIndex(where: { $0.id == retainedSelection }) {
                        self.selectAndLoadRow(at: row)
                    } else if !self.rows.isEmpty {
                        self.selectAndLoadRow(at: 0)
                    } else {
                        self.clearDetail(message: snapshot.query == nil
                            ? "No conversations yet. Create a new task to get started."
                            : "No conversations matched your search.")
                    }
                }
            } catch is CancellationError {
                return
            } catch {
                await MainActor.run { [weak self] in
                    guard let self, generation == self.browseGeneration else { return }
                    self.rows = []
                    self.tableView.reloadData()
                    self.refreshButton.isEnabled = true
                    self.listStatusLabel.stringValue = SessionHistoryErrorMessage.message(for: error)
                    self.clearDetail(message: "Task history is unavailable.")
                }
            }
        }
    }

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard rows.indices.contains(row) else { return nil }
        let identifier = NSUserInterfaceItemIdentifier("SessionHistoryRow")
        let cell = tableView.makeView(withIdentifier: identifier, owner: self) as? SessionHistoryRowCellView
            ?? SessionHistoryRowCellView(identifier: identifier)
        cell.configure(row: rows[row], dateText: Self.rowDateFormatter.string(from: rows[row].updatedAt))
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard !isProgrammaticSelection else { return }
        let index = tableView.selectedRow
        guard rows.indices.contains(index) else {
            selectedSessionID = nil
            clearDetail(message: "Select a task to see its conversation.")
            return
        }
        loadDetail(for: rows[index])
    }

    private func selectAndLoadRow(at index: Int) {
        guard rows.indices.contains(index) else { return }
        isProgrammaticSelection = true
        tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        isProgrammaticSelection = false
        loadDetail(for: rows[index])
    }

    func controlTextDidChange(_ obj: Notification) {
        guard obj.object as? NSSearchField === searchField else { return }
        searchWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.refresh() }
        searchWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: work)
    }

    func windowWillClose(_ notification: Notification) { cancelWork() }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let heading = NSTextField(labelWithString: "Task History")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        let subtitle = NSTextField(labelWithString: "Search conversations stored by your private agent runtime.")
        subtitle.textColor = .secondaryLabelColor

        searchField.placeholderString = "Search conversation content"
        searchField.delegate = self
        searchField.sendsSearchStringImmediately = false
        searchField.setAccessibilityLabel("Search task history")
        searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 280).isActive = true

        refreshButton.target = self
        refreshButton.action = #selector(refreshAction(_:))
        refreshButton.bezelStyle = .rounded
        refreshButton.setAccessibilityLabel("Refresh task history")

        newButton.target = self
        newButton.action = #selector(createNewSession(_:))
        newButton.bezelStyle = .rounded
        newButton.keyEquivalent = "n"
        newButton.keyEquivalentModifierMask = [.command]
        newButton.setAccessibilityLabel("Create new task")

        let titleStack = NSStackView(views: [heading, subtitle])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 2
        let header = NSStackView(views: [titleStack, NSView(), searchField, refreshButton, newButton])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 8

        configureSessionTable()
        let tableScroll = NSScrollView()
        tableScroll.documentView = tableView
        tableScroll.hasVerticalScroller = true
        tableScroll.drawsBackground = false

        listStatusLabel.textColor = .secondaryLabelColor
        listStatusLabel.font = .systemFont(ofSize: 11)
        listStatusLabel.lineBreakMode = .byTruncatingTail
        listStatusLabel.setAccessibilityLabel("Task history status")
        let sidebarStack = NSStackView(views: [tableScroll, listStatusLabel])
        sidebarStack.orientation = .vertical
        sidebarStack.alignment = .leading
        sidebarStack.spacing = 8
        sidebarStack.translatesAutoresizingMaskIntoConstraints = false

        let sidebar = displayPolicy.makeSidebarContainer()
        sidebarContainer = sidebar
        sidebar.addSubview(sidebarStack)
        NSLayoutConstraint.activate([
            sidebarStack.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 10),
            sidebarStack.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 10),
            sidebarStack.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -10),
            sidebarStack.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -10),
            tableScroll.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor),
            listStatusLabel.widthAnchor.constraint(equalTo: sidebarStack.widthAnchor)
        ])

        let detail = buildDetail()
        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.addArrangedSubview(sidebar)
        split.addArrangedSubview(detail)
        sidebar.widthAnchor.constraint(greaterThanOrEqualToConstant: 285).isActive = true
        sidebar.widthAnchor.constraint(lessThanOrEqualToConstant: 410).isActive = true
        sidebar.setContentHuggingPriority(.defaultHigh, for: .horizontal)

        let layout = NSStackView(views: [header, split])
        layout.orientation = .vertical
        layout.alignment = .leading
        layout.spacing = 14
        layout.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(layout)
        NSLayoutConstraint.activate([
            layout.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            layout.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 18),
            layout.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18),
            layout.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
            header.widthAnchor.constraint(equalTo: layout.widthAnchor),
            split.widthAnchor.constraint(equalTo: layout.widthAnchor)
        ])
        controller.view = root
        return controller
    }

    private func configureSessionTable() {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("session"))
        column.title = "Task"
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 72
        tableView.intercellSpacing = NSSize(width: 0, height: 1)
        tableView.selectionHighlightStyle = .regular
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tableView.target = self
        tableView.doubleAction = #selector(openSelectedSession(_:))
        tableView.setAccessibilityLabel("Harness tasks")
    }

    private func buildDetail() -> NSView {
        detailTitleLabel.font = .systemFont(ofSize: 21, weight: .semibold)
        detailTitleLabel.maximumNumberOfLines = 2
        detailTitleLabel.lineBreakMode = .byTruncatingTail
        projectLabel.textColor = .secondaryLabelColor
        projectLabel.font = .systemFont(ofSize: 12)
        routeLabel.font = .systemFont(ofSize: 13, weight: .medium)
        routeIDsLabel.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        routeIDsLabel.textColor = .tertiaryLabelColor
        routeIDsLabel.maximumNumberOfLines = 2
        boundaryLabel.font = .systemFont(ofSize: 12, weight: .semibold)

        openButton.target = self
        openButton.action = #selector(openSelectedSession(_:))
        openButton.bezelStyle = .rounded
        openButton.keyEquivalent = "\r"
        openButton.isEnabled = false

        for button in [renameButton, branchButton, archiveButton, exportButton] {
            button.target = self
            button.bezelStyle = .rounded
            button.isEnabled = false
        }
        renameButton.action = #selector(renameSelectedSession(_:))
        branchButton.action = #selector(branchSelectedSession(_:))
        archiveButton.action = #selector(archiveSelectedSession(_:))
        archiveButton.contentTintColor = .systemRed
        exportButton.action = #selector(exportSelectedSession(_:))

        let detailHeading = NSStackView(views: [detailTitleLabel, NSView(), openButton])
        detailHeading.orientation = .horizontal
        detailHeading.alignment = .top
        detailHeading.spacing = 8
        let metadata = NSStackView(views: [projectLabel, routeLabel, routeIDsLabel, boundaryLabel])
        metadata.orientation = .vertical
        metadata.alignment = .leading
        metadata.spacing = 3
        let taskActions = NSStackView(views: [renameButton, branchButton, exportButton, archiveButton, NSView()])
        taskActions.orientation = .horizontal
        taskActions.alignment = .centerY
        taskActions.spacing = 8

        olderButton.target = self
        olderButton.action = #selector(loadOlder(_:))
        olderButton.bezelStyle = .inline
        olderButton.isEnabled = false
        olderButton.isHidden = true
        olderButton.setAccessibilityLabel("Load earlier task messages")

        transcriptTextView.isEditable = false
        transcriptTextView.isSelectable = true
        transcriptTextView.isRichText = false
        transcriptTextView.importsGraphics = false
        transcriptTextView.isAutomaticLinkDetectionEnabled = false
        transcriptTextView.drawsBackground = false
        transcriptTextView.textContainerInset = NSSize(width: 18, height: 16)
        transcriptTextView.isHorizontallyResizable = false
        transcriptTextView.isVerticallyResizable = true
        transcriptTextView.autoresizingMask = [.width]
        transcriptTextView.textContainer?.widthTracksTextView = true
        transcriptTextView.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)
        transcriptTextView.setAccessibilityLabel("Task conversation")
        let transcriptScroll = NSScrollView()
        transcriptScroll.documentView = transcriptTextView
        transcriptScroll.hasVerticalScroller = true
        transcriptScroll.borderType = .noBorder
        transcriptScroll.drawsBackground = true
        transcriptScroll.backgroundColor = .textBackgroundColor

        let panel = NSView()
        let stack = NSStackView(views: [detailHeading, metadata, taskActions, olderButton, transcriptScroll])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: panel.topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 18),
            stack.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -12),
            stack.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -12),
            detailHeading.widthAnchor.constraint(equalTo: stack.widthAnchor),
            metadata.widthAnchor.constraint(equalTo: stack.widthAnchor),
            taskActions.widthAnchor.constraint(equalTo: stack.widthAnchor),
            transcriptScroll.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        return panel
    }

    private func loadDetail(for row: SessionHistoryRow) {
        invalidateExportForSelectionChange()
        detailGeneration += 1
        let generation = detailGeneration
        selectedSessionID = row.id
        selectedRoute = .unavailable
        messages = []
        olderBeforeSequence = nil
        detailTask?.cancel()
        olderTask?.cancel()
        detailTitleLabel.stringValue = row.title
        projectLabel.stringValue = row.projectLabel.map { "Project · \($0)" } ?? "No project folder"
        routeLabel.stringValue = "Loading provider and model…"
        routeIDsLabel.stringValue = ""
        boundaryLabel.stringValue = "Data boundary · Checking…"
        boundaryLabel.textColor = .secondaryLabelColor
        openButton.isEnabled = true
        renameButton.isEnabled = true
        branchButton.isEnabled = !row.running
        archiveButton.isEnabled = !row.running
        exportButton.isEnabled = false
        olderButton.isHidden = true
        renderPlaceholder("Loading conversation…")

        let source = dataSource
        let sessionID = row.id
        detailTask = Task { [weak self] in
            do {
                let detail = try await source.detail(for: sessionID)
                guard !Task.isCancelled else { return }
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.detailGeneration,
                          self.selectedSessionID == sessionID else { return }
                    self.messages = detail.transcript.messages
                    self.olderBeforeSequence = detail.transcript.olderBeforeSequence
                    self.selectedRoute = detail.route
                    self.present(route: detail.route)
                    self.exportButton.isEnabled = !detail.transcript.messages.isEmpty
                    self.updateOlderButton()
                    self.renderTranscript(scrollToBottom: true)
                }
            } catch is CancellationError {
                return
            } catch {
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.detailGeneration,
                          self.selectedSessionID == sessionID else { return }
                    self.routeLabel.stringValue = "Provider and model unavailable"
                    self.routeIDsLabel.stringValue = ""
                    self.boundaryLabel.stringValue = "Data boundary · Unknown"
                    self.boundaryLabel.textColor = .systemOrange
                    self.renderPlaceholder(SessionHistoryErrorMessage.message(for: error))
                }
            }
        }
    }

    private func present(route state: SessionRouteMetadataState) {
        switch state {
        case .available(let metadata):
            var routeText = "Provider · \(metadata.providerName)    Model · \(metadata.modelName)"
            if let effort = metadata.reasoningEffort, !effort.isEmpty { routeText += "    Effort · \(effort)" }
            if !metadata.routable { routeText += "    Currently unavailable" }
            routeLabel.stringValue = routeText
            let providerID = SessionHistorySafeText.inline(metadata.route.provider.rawValue, limit: 240)
            let modelID = SessionHistorySafeText.inline(metadata.route.model.rawValue, limit: 240)
            routeIDsLabel.stringValue = "Provider ID: \(providerID)    Model ID: \(modelID)"
            boundaryLabel.stringValue = "\(Self.boundaryGlyph(metadata.boundary)) Data boundary · \(metadata.boundary.displayName)"
            boundaryLabel.textColor = Self.boundaryColor(metadata.boundary)
        case .unavailable:
            routeLabel.stringValue = "Provider and model details are temporarily unavailable"
            routeIDsLabel.stringValue = ""
            boundaryLabel.stringValue = "Data boundary · Unknown"
            boundaryLabel.textColor = .systemOrange
        }
    }

    private func renderTranscript(scrollToBottom: Bool) {
        guard !messages.isEmpty else {
            renderPlaceholder("This task has no visible human or assistant messages yet.")
            return
        }
        let output = NSMutableAttributedString()
        let bodyParagraph = NSMutableParagraphStyle()
        bodyParagraph.lineSpacing = 3
        bodyParagraph.paragraphSpacing = 5
        for message in messages {
            var header = "\(message.role.displayName) · \(Self.messageDateFormatter.string(from: message.date))"
            if message.interrupted { header += " · Stopped" }
            if let source = message.source {
                let provider = SessionHistorySafeText.inline(source.route.provider.rawValue, limit: 100)
                let model = SessionHistorySafeText.inline(source.route.model.rawValue, limit: 140)
                header += " · \(provider) · \(model) · \(source.boundary.displayName)"
            }
            output.append(NSAttributedString(
                string: header + "\n",
                attributes: [
                    .font: NSFont.systemFont(ofSize: 11, weight: .semibold),
                    .foregroundColor: message.role == .user ? NSColor.systemBlue : NSColor.secondaryLabelColor
                ]
            ))
            output.append(NSAttributedString(
                string: message.text + "\n\n",
                attributes: [
                    .font: NSFont.systemFont(ofSize: 14),
                    .foregroundColor: NSColor.labelColor,
                    .paragraphStyle: bodyParagraph
                ]
            ))
        }
        transcriptTextView.textStorage?.setAttributedString(output)
        if scrollToBottom { transcriptTextView.scrollToEndOfDocument(nil) }
    }

    private func renderPlaceholder(_ message: String) {
        transcriptTextView.string = "\n\n\(message)"
        transcriptTextView.font = .systemFont(ofSize: 14)
        transcriptTextView.textColor = .secondaryLabelColor
    }

    private func clearDetail(message: String) {
        invalidateExportForSelectionChange()
        detailGeneration += 1
        detailTask?.cancel()
        olderTask?.cancel()
        selectedSessionID = nil
        selectedRoute = .unavailable
        messages = []
        olderBeforeSequence = nil
        detailTitleLabel.stringValue = "Task History"
        projectLabel.stringValue = ""
        routeLabel.stringValue = ""
        routeIDsLabel.stringValue = ""
        boundaryLabel.stringValue = ""
        openButton.isEnabled = false
        renameButton.isEnabled = false
        branchButton.isEnabled = false
        archiveButton.isEnabled = false
        exportButton.isEnabled = false
        olderButton.isEnabled = false
        olderButton.isHidden = true
        renderPlaceholder(message)
    }

    private func updateListStatus(_ snapshot: SessionHistoryBrowseSnapshot) {
        if snapshot.rows.isEmpty {
            listStatusLabel.stringValue = snapshot.query == nil ? "No saved conversations" : "No matches"
        } else if snapshot.hasMoreSearchResults {
            listStatusLabel.stringValue = "Showing the top \(snapshot.rows.count) matches"
        } else {
            listStatusLabel.stringValue = snapshot.query == nil
                ? "\(snapshot.rows.count) saved conversation\(snapshot.rows.count == 1 ? "" : "s")"
                : "\(snapshot.rows.count) match\(snapshot.rows.count == 1 ? "" : "es")"
        }
    }

    private func updateOlderButton() {
        olderButton.isHidden = olderBeforeSequence == nil
        olderButton.isEnabled = olderBeforeSequence != nil
        olderButton.title = "Load Earlier Messages"
    }

    private func restoreSelectedActionControls() {
        guard let selectedSessionID,
              let row = rows.first(where: { $0.id == selectedSessionID }) else {
            renameButton.isEnabled = false
            branchButton.isEnabled = false
            archiveButton.isEnabled = false
            return
        }
        renameButton.isEnabled = true
        branchButton.isEnabled = !row.running
        archiveButton.isEnabled = !row.running
    }

    private func restoreExportButton() {
        exportButton.isEnabled = selectedSessionID != nil && !messages.isEmpty
    }

    private func invalidateExportForSelectionChange() {
        let wasExporting = exportTask != nil
        exportGeneration += 1
        exportTask?.cancel()
        exportTask = nil
        if wasExporting {
            listStatusLabel.stringValue = "Export cancelled after switching tasks"
        }
    }

    private func cancelWork() {
        createGeneration += 1
        actionGeneration += 1
        exportGeneration += 1
        searchWorkItem?.cancel()
        browseTask?.cancel()
        detailTask?.cancel()
        olderTask?.cancel()
        createTask?.cancel()
        actionTask?.cancel()
        exportTask?.cancel()
        newButton.isEnabled = true
        restoreSelectedActionControls()
        restoreExportButton()
    }

    @objc private func refreshAction(_ sender: Any?) { refresh() }

    @objc private func openSelectedSession(_ sender: Any?) {
        let index = tableView.selectedRow
        guard rows.indices.contains(index) else { return }
        onSessionSelected?(rows[index].id)
    }

    @objc private func createNewSession(_ sender: Any?) {
        guard let request = newSessionRequest(), let selection = newSessionSelection() else { return }
        createGeneration += 1
        let generation = createGeneration
        newButton.isEnabled = false
        listStatusLabel.stringValue = "Creating a new task…"
        let source = dataSource
        let lifecycle = lifecycle
        createTask?.cancel()
        createTask = Task { [weak self] in
            do {
                try lifecycle.beginOperation()
                defer { lifecycle.endOperation() }
                try await SessionHistoryLifecycleContext.$ownsOuterAdmission.withValue(true) {
                    let sessionID = try await source.createSession(request, selection: selection)
                    let delivered = await MainActor.run { [weak self] in
                        guard !Task.isCancelled,
                              let self,
                              generation == self.createGeneration,
                              let onSessionSelected = self.onSessionSelected else { return false }
                        self.createTask = nil
                        self.newButton.isEnabled = true
                        onSessionSelected(sessionID)
                        self.refresh()
                        return true
                    }
                    guard !delivered else { return }
                    // The outer admission remains active until exact-session
                    // cleanup settles, so runtime quiescence cannot cross the
                    // create -> stale-owner compensation gap.
                    do {
                        try await source.discardUnownedSession(sessionID)
                    } catch {
                        lifecycle.recordCleanupFailure()
                        throw HarnessConversationError.sessionCleanupUnverified
                    }
                }
            } catch is CancellationError {
                await MainActor.run { [weak self] in
                    guard let self, generation == self.createGeneration else { return }
                    self.createTask = nil
                    self.newButton.isEnabled = true
                }
                return
            } catch {
                await MainActor.run { [weak self] in
                    guard let self, generation == self.createGeneration else { return }
                    self.createTask = nil
                    self.newButton.isEnabled = true
                    self.listStatusLabel.stringValue = SessionHistoryErrorMessage.message(for: error)
                }
            }
        }
    }

    @objc private func renameSelectedSession(_ sender: Any?) {
        guard let sessionID = selectedSessionID,
              let row = rows.first(where: { $0.id == sessionID }) else { return }
        guard let requestedTitle = interactions.requestRename(row.title) else { return }
        let title = SessionHistorySafeText.inline(requestedTitle, limit: 160)
        guard !title.isEmpty else { return }
        runAction(status: "Renaming task…") { source in
            try await source.renameSession(sessionID, title: title)
            return nil
        }
    }

    @objc private func branchSelectedSession(_ sender: Any?) {
        guard let sessionID = selectedSessionID,
              let row = rows.first(where: { $0.id == sessionID }),
              !row.running else { return }
        runAction(status: "Creating a private branch…") { source in
            try await source.forkSession(sessionID, atSequence: nil)
        }
    }

    @objc private func archiveSelectedSession(_ sender: Any?) {
        guard let sessionID = selectedSessionID,
              let row = rows.first(where: { $0.id == sessionID }),
              !row.running else { return }
        guard interactions.confirmArchive() else { return }
        runAction(status: "Archiving task…") { source in
            try await source.archiveSession(sessionID)
            return nil
        }
    }

    @objc private func exportSelectedSession(_ sender: Any?) {
        guard let sessionID = selectedSessionID,
              let row = rows.first(where: { $0.id == sessionID }),
              !messages.isEmpty else { return }
        guard let selection = interactions.requestExport() else { return }

        exportGeneration += 1
        let generation = exportGeneration
        exportButton.isEnabled = false
        listStatusLabel.stringValue = olderBeforeSequence == nil
            ? "Preparing private export…"
            : "Loading the full conversation for export…"
        let source = dataSource
        let initialMessages = messages
        let initialCursor = olderBeforeSequence
        let route = selectedRoute
        exportTask?.cancel()
        exportTask = Task { [weak self] in
            do {
                var allMessages = initialMessages
                var cursor = initialCursor
                var pageCount = 0
                var partial = false
                while let before = cursor {
                    try Task.checkCancellation()
                    guard pageCount < 100 else { partial = true; break }
                    let page = try await source.olderPage(for: sessionID, beforeSequence: before)
                    let merged = SessionTranscriptAccumulator.merge(
                        older: page.messages,
                        newer: allMessages,
                        maximumMessages: 5_000,
                        maximumCharacters: 12_000_000
                    )
                    allMessages = merged.messages
                    if merged.truncated { partial = true; break }
                    cursor = page.olderBeforeSequence
                    pageCount += 1
                }
                let detail = SessionHistoryDetailSnapshot(
                    sessionID: sessionID,
                    transcript: SessionTranscriptPage(
                        messages: allMessages,
                        olderBeforeSequence: partial ? cursor : nil
                    ),
                    route: route
                )
                let artifact = try ConversationExporter.prepare(
                    from: detail,
                    title: row.title,
                    format: selection.format,
                    redaction: selection.redaction
                )
                try Task.checkCancellation()
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.exportGeneration,
                          self.selectedSessionID == sessionID else { return }
                    self.presentSavePanel(
                        for: artifact,
                        generation: generation,
                        sessionID: sessionID
                    )
                }
            } catch is CancellationError {
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.exportGeneration,
                          self.selectedSessionID == sessionID else { return }
                    self.exportTask = nil
                    self.restoreExportButton()
                }
                return
            } catch {
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.exportGeneration,
                          self.selectedSessionID == sessionID else { return }
                    self.exportTask = nil
                    self.restoreExportButton()
                    self.listStatusLabel.stringValue = "The conversation could not be prepared for export."
                }
            }
        }
    }

    private func presentSavePanel(
        for artifact: ConversationExportArtifact,
        generation: Int,
        sessionID: HarnessSessionID
    ) {
        defer {
            if generation == exportGeneration, selectedSessionID == sessionID {
                restoreExportButton()
                exportTask = nil
            }
        }
        guard generation == exportGeneration, selectedSessionID == sessionID else { return }
        guard let destination = interactions.chooseExportDestination(artifact) else {
            listStatusLabel.stringValue = "Export cancelled"
            return
        }
        guard generation == exportGeneration, selectedSessionID == sessionID else { return }
        do {
            let written = try ConversationExporter.write(artifact, to: destination)
            listStatusLabel.stringValue = "Exported \(artifact.messageCount) messages"
            interactions.revealExport(written)
        } catch {
            listStatusLabel.stringValue = Self.exportWriteErrorMessage(for: error)
        }
    }

    private static func exportWriteErrorMessage(for error: Error) -> String {
        guard let exportError = error as? ConversationExportError else {
            return "The conversation export could not be saved safely."
        }
        switch exportError {
        case .invalidDestination:
            return "Choose a safe local file destination with the correct extension."
        case .destinationAlreadyExists:
            return "That export already exists. Choose a different filename."
        case .filesystemFailure:
            return "The conversation export could not be written safely."
        case .invalidMessage, .duplicateSequence, .messageLimitExceeded, .messageTooLarge,
             .totalTextLimitExceeded, .attachmentLimitExceeded, .invalidAttachmentMetadata,
             .outputLimitExceeded:
            return "The conversation could not be prepared within the app’s export safety limits."
        }
    }

    private func runAction(
        status: String,
        operation: @escaping @Sendable (any SessionHistoryDataProviding) async throws -> HarnessSessionID?
    ) {
        actionGeneration += 1
        let generation = actionGeneration
        actionTask?.cancel()
        listStatusLabel.stringValue = status
        renameButton.isEnabled = false
        branchButton.isEnabled = false
        archiveButton.isEnabled = false
        let source = dataSource
        actionTask = Task { [weak self] in
            do {
                let opened = try await operation(source)
                guard !Task.isCancelled else { return }
                await MainActor.run { [weak self] in
                    guard let self, generation == self.actionGeneration else { return }
                    self.actionTask = nil
                    if let opened { self.onSessionSelected?(opened) }
                    self.refresh()
                }
            } catch is CancellationError {
                await MainActor.run { [weak self] in
                    guard let self, generation == self.actionGeneration else { return }
                    self.actionTask = nil
                    self.restoreSelectedActionControls()
                }
                return
            } catch {
                await MainActor.run { [weak self] in
                    guard let self, generation == self.actionGeneration else { return }
                    self.actionTask = nil
                    self.listStatusLabel.stringValue = SessionHistoryErrorMessage.message(for: error)
                    self.restoreSelectedActionControls()
                }
            }
        }
    }

    @objc private func loadOlder(_ sender: Any?) {
        guard let sessionID = selectedSessionID,
              let beforeSequence = olderBeforeSequence else { return }
        olderButton.isEnabled = false
        olderButton.title = "Loading…"
        let source = dataSource
        let generation = detailGeneration
        olderTask?.cancel()
        olderTask = Task { [weak self] in
            do {
                let page = try await source.olderPage(for: sessionID, beforeSequence: beforeSequence)
                guard !Task.isCancelled else { return }
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.detailGeneration,
                          self.selectedSessionID == sessionID else { return }
                    let merged = SessionTranscriptAccumulator.merge(older: page.messages, newer: self.messages)
                    self.messages = merged.messages
                    self.olderBeforeSequence = merged.truncated ? nil : page.olderBeforeSequence
                    self.updateOlderButton()
                    if merged.truncated {
                        self.listStatusLabel.stringValue = "Conversation display capped at the newest 2 million characters"
                    }
                    self.renderTranscript(scrollToBottom: false)
                }
            } catch is CancellationError {
                return
            } catch {
                await MainActor.run { [weak self] in
                    guard let self,
                          generation == self.detailGeneration,
                          self.selectedSessionID == sessionID else { return }
                    self.olderButton.isEnabled = true
                    self.olderButton.title = "Try Loading Earlier Messages Again"
                    self.listStatusLabel.stringValue = SessionHistoryErrorMessage.message(for: error)
                }
            }
        }
    }

    private static func boundaryGlyph(_ boundary: DataBoundary) -> String {
        switch boundary {
        case .onDevice: return "●"
        case .localNetwork: return "◐"
        case .cloud: return "☁"
        }
    }

    private static func boundaryColor(_ boundary: DataBoundary) -> NSColor {
        switch boundary {
        case .onDevice: return .systemGreen
        case .localNetwork: return .systemOrange
        case .cloud: return .systemBlue
        }
    }

    private static let rowDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        formatter.doesRelativeDateFormatting = true
        return formatter
    }()

    private static let messageDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

private final class SessionHistoryRowCellView: NSTableCellView {
    private let titleLabel = NSTextField(labelWithString: "")
    private let metadataLabel = NSTextField(labelWithString: "")
    private let snippetLabel = NSTextField(labelWithString: "")

    init(identifier: NSUserInterfaceItemIdentifier) {
        super.init(frame: .zero)
        self.identifier = identifier
        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        titleLabel.lineBreakMode = .byTruncatingTail
        metadataLabel.font = .systemFont(ofSize: 10)
        metadataLabel.textColor = .secondaryLabelColor
        metadataLabel.lineBreakMode = .byTruncatingTail
        snippetLabel.font = .systemFont(ofSize: 11)
        snippetLabel.textColor = .secondaryLabelColor
        snippetLabel.lineBreakMode = .byTruncatingTail

        let stack = NSStackView(views: [titleLabel, metadataLabel, snippetLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 7),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -6),
            titleLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            metadataLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            snippetLabel.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(row: SessionHistoryRow, dateText: String) {
        titleLabel.stringValue = row.title
        var metadata: [String] = []
        if row.running { metadata.append("Running") }
        if let project = row.projectLabel { metadata.append(project) }
        metadata.append(dateText)
        metadataLabel.stringValue = metadata.joined(separator: " · ")
        snippetLabel.stringValue = row.searchSnippet ?? ""
        snippetLabel.isHidden = row.searchSnippet == nil
        toolTip = row.searchSnippet ?? row.title
        setAccessibilityLabel(([row.title] + metadata + [row.searchSnippet].compactMap { $0 }).joined(separator: ", "))
    }
}
