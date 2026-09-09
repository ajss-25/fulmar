import AppKit
import UniformTypeIdentifiers

/// A project that can own private local knowledge. The identifier is persisted
/// by `LocalKnowledgeStore`; the display name is presentation-only.
struct KnowledgeProjectOption: Equatable, Identifiable, Sendable {
    let id: String
    let displayName: String

    init(id: String, displayName: String) {
        self.id = id
        self.displayName = displayName
    }
}

/// Emitted after a durable store mutation so the app delegate can refresh any
/// other knowledge-aware surfaces without observing note bodies.
enum KnowledgeCenterChange: Sendable {
    case created(KnowledgeDocumentDescriptor)
    case updated(KnowledgeDocumentDescriptor)
    case imported([KnowledgeDocumentDescriptor])
    case removed(KnowledgeDocumentDescriptor)
    case cleared(scope: KnowledgeScope, count: Int)
}

struct KnowledgeMemoryDraft {
    let title: String
    let text: String
    let scope: KnowledgeScope
}

final class KnowledgeCenterOperationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

struct KnowledgeCenterQueryPayload: Sendable {
    let all: [KnowledgeDocumentDescriptor]
    let documents: [KnowledgeDocumentDescriptor]
    let results: [KnowledgeSearchResult]
}

struct KnowledgeCenterImportOutcome: Sendable {
    let imported: [KnowledgeDocumentDescriptor]
    let failedCount: Int
}

enum KnowledgeCenterFailure: Error, Equatable, LocalizedError {
    case query
    case detail
    case edit
    case save
    case importing
    case removal
    case clearing
    case export

    var message: String {
        switch self {
        case .query:
            "The private knowledge library could not be read. No partial results are shown."
        case .detail:
            "This local context could not be loaded. Select the item again or reload the library."
        case .edit:
            "The selected memory could not be opened for editing. Reload the library and try again."
        case .save:
            "The memory could not be saved. Your draft remains open so you can try again."
        case .importing:
            "The selected files could not be imported safely. No incomplete item was admitted."
        case .removal:
            "The selected knowledge item was not removed. Reload the library and try again."
        case .clearing:
            "The selected knowledge scope was not cleared. Existing items remain available."
        case .export:
            "Knowledge metadata could not be exported to that destination. Choose a new location and try again."
        }
    }

    var errorDescription: String? { message }
}

enum KnowledgeCenterConfirmation: Equatable {
    case remove(id: UUID, title: String)
    case clear(scope: KnowledgeScope, displayName: String, count: Int)
}

enum KnowledgeCenterNotice: Equatable {
    case importCompleted(imported: Int, failed: Int)
    case exportSucceeded
}

struct KnowledgeCenterInteractions {
    let beginNoteEditor: @MainActor (_ parent: NSWindow, _ editor: NSWindow) -> Void
    let endNoteEditor: @MainActor (_ parent: NSWindow, _ editor: NSWindow) -> Void
    let chooseImportFiles: @MainActor (
        _ parent: NSWindow,
        _ completion: @escaping @MainActor ([URL]?) -> Void
    ) -> Void
    let chooseExportDestination: @MainActor (
        _ parent: NSWindow,
        _ completion: @escaping @MainActor (URL?) -> Void
    ) -> Void
    let confirm: @MainActor (
        _ confirmation: KnowledgeCenterConfirmation,
        _ parent: NSWindow,
        _ completion: @escaping @MainActor (Bool) -> Void
    ) -> Void
    let presentNotice: @MainActor (_ notice: KnowledgeCenterNotice, _ parent: NSWindow?) -> Void

    static let live = KnowledgeCenterInteractions(
        beginNoteEditor: { parent, editor in parent.beginSheet(editor) },
        endNoteEditor: { parent, editor in
            if parent.attachedSheet === editor { parent.endSheet(editor) }
            editor.orderOut(nil)
        },
        chooseImportFiles: { parent, completion in
            let panel = NSOpenPanel()
            panel.title = "Import Private Knowledge"
            panel.message = "Files are copied into the local knowledge index. Original paths are not retained."
            panel.prompt = "Import Locally"
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            panel.allowsMultipleSelection = true
            panel.resolvesAliases = false
            panel.allowedContentTypes = KnowledgeCenterWindowController.supportedImportContentTypes
            panel.beginSheetModal(for: parent) { response in
                completion(response == .OK && !panel.urls.isEmpty ? panel.urls : nil)
            }
        },
        chooseExportDestination: { parent, completion in
            let panel = NSSavePanel()
            panel.title = "Export Knowledge Metadata"
            panel.message = "Exports titles, scopes, file names, dates, sizes, and hashes for all knowledge. Note and file contents are excluded."
            panel.nameFieldStringValue = "\(ProductBrand.displayName) Knowledge Metadata.json"
            panel.allowedContentTypes = [.json]
            panel.canCreateDirectories = true
            panel.beginSheetModal(for: parent) { response in
                completion(response == .OK ? panel.url : nil)
            }
        },
        confirm: { confirmation, parent, completion in
            let alert = NSAlert()
            alert.alertStyle = .warning
            switch confirmation {
            case .remove(_, let title):
                alert.messageText = "Remove “\(title)” ?"
                alert.informativeText = "This permanently removes the local index and stored text for this item. The original imported file, if any, is not changed."
                alert.addButton(withTitle: "Remove")
            case .clear(_, let displayName, let count):
                alert.alertStyle = .critical
                alert.messageText = "Clear \(displayName)?"
                alert.informativeText = "This permanently removes \(count.formatted()) item\(count == 1 ? "" : "s") and its locally stored text. Other scopes and original imported files are not changed."
                alert.addButton(withTitle: "Clear \(displayName)")
            }
            alert.addButton(withTitle: "Cancel")
            alert.beginSheetModal(for: parent) { response in
                completion(response == .alertFirstButtonReturn)
            }
        },
        presentNotice: { notice, parent in
            let alert = NSAlert()
            switch notice {
            case .importCompleted(let imported, let failed):
                alert.messageText = failed == 0
                    ? "Knowledge imported"
                    : (imported == 0 ? "Files could not be imported" : "Import completed with some issues")
                alert.informativeText = failed == 0
                    ? "\(imported.formatted()) file\(imported == 1 ? " was" : "s were") copied, indexed, and stored locally. Original paths were not retained."
                    : "Imported \(imported) of \(imported + failed) selected files. Files that failed validation were not admitted to the private library."
                alert.alertStyle = failed == 0 ? .informational : .warning
            case .exportSucceeded:
                alert.messageText = "Knowledge metadata exported"
                alert.informativeText = "The JSON manifest contains metadata only. Memory notes and imported file contents were excluded."
                alert.alertStyle = .informational
            }
            if let parent { alert.beginSheetModal(for: parent) }
        }
    )
}

struct KnowledgeCenterOperations {
    let availability: @MainActor () -> LocalKnowledgeStoreAvailability
    let recoveryReport: @MainActor () -> KnowledgeRecoveryReport
    let storageDirectory: @MainActor () -> URL
    let setStatusHandler: @MainActor ((@Sendable (LocalKnowledgeStoreStatus) -> Void)?) -> Void
    let load: @MainActor (_ retry: Bool) -> Void
    let retryDeferredMaintenance: @MainActor () -> Void
    let query: @MainActor (
        _ query: String,
        _ filter: KnowledgeScopeFilter,
        _ completion: @escaping @MainActor (Result<KnowledgeCenterQueryPayload, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let detail: @MainActor (
        _ descriptor: KnowledgeDocumentDescriptor,
        _ chunkIndex: Int,
        _ completion: @escaping @MainActor (Result<String, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let memoryNote: @MainActor (
        _ id: UUID,
        _ completion: @escaping @MainActor (Result<KnowledgeMemoryNote, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let save: @MainActor (
        _ existing: KnowledgeMemoryNote?,
        _ draft: KnowledgeMemoryDraft,
        _ completion: @escaping @MainActor (Result<KnowledgeDocumentDescriptor, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let importFiles: @MainActor (
        _ urls: [URL],
        _ scope: KnowledgeScope,
        _ completion: @escaping @MainActor (Result<KnowledgeCenterImportOutcome, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let remove: @MainActor (
        _ id: UUID,
        _ completion: @escaping @MainActor (Result<KnowledgeDocumentDescriptor, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let clear: @MainActor (
        _ scope: KnowledgeScope,
        _ completion: @escaping @MainActor (Result<Int, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation
    let export: @MainActor (
        _ destination: URL,
        _ completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation

    init(
        availability: @escaping @MainActor () -> LocalKnowledgeStoreAvailability,
        recoveryReport: @escaping @MainActor () -> KnowledgeRecoveryReport,
        storageDirectory: @escaping @MainActor () -> URL,
        setStatusHandler: @escaping @MainActor ((@Sendable (LocalKnowledgeStoreStatus) -> Void)?) -> Void,
        load: @escaping @MainActor (Bool) -> Void,
        retryDeferredMaintenance: @escaping @MainActor () -> Void,
        query: @escaping @MainActor (String, KnowledgeScopeFilter, @escaping @MainActor (Result<KnowledgeCenterQueryPayload, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        detail: @escaping @MainActor (KnowledgeDocumentDescriptor, Int, @escaping @MainActor (Result<String, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        memoryNote: @escaping @MainActor (UUID, @escaping @MainActor (Result<KnowledgeMemoryNote, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        save: @escaping @MainActor (KnowledgeMemoryNote?, KnowledgeMemoryDraft, @escaping @MainActor (Result<KnowledgeDocumentDescriptor, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        importFiles: @escaping @MainActor ([URL], KnowledgeScope, @escaping @MainActor (Result<KnowledgeCenterImportOutcome, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        remove: @escaping @MainActor (UUID, @escaping @MainActor (Result<KnowledgeDocumentDescriptor, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        clear: @escaping @MainActor (KnowledgeScope, @escaping @MainActor (Result<Int, Error>) -> Void) -> KnowledgeCenterOperationCancellation,
        export: @escaping @MainActor (URL, @escaping @MainActor (Result<Void, Error>) -> Void) -> KnowledgeCenterOperationCancellation
    ) {
        self.availability = availability
        self.recoveryReport = recoveryReport
        self.storageDirectory = storageDirectory
        self.setStatusHandler = setStatusHandler
        self.load = load
        self.retryDeferredMaintenance = retryDeferredMaintenance
        self.query = query
        self.detail = detail
        self.memoryNote = memoryNote
        self.save = save
        self.importFiles = importFiles
        self.remove = remove
        self.clear = clear
        self.export = export
    }

    init(store: LocalKnowledgeStore) {
        availability = { store.availability }
        recoveryReport = { store.recoveryReport }
        storageDirectory = { store.storageDirectory }
        setStatusHandler = { store.setStatusHandler($0) }
        load = { retry in store.load(retry: retry) { _ in } }
        retryDeferredMaintenance = { store.retryDeferredMaintenance() }
        query = { query, filter, completion in
            Self.run({
                let all = try store.listDocuments(scope: .all)
                if query.isEmpty {
                    return KnowledgeCenterQueryPayload(
                        all: all,
                        documents: try store.listDocuments(scope: filter),
                        results: []
                    )
                }
                return KnowledgeCenterQueryPayload(
                    all: all,
                    documents: [],
                    results: try store.search(query, scope: filter, limit: 100)
                )
            }, completion: completion)
        }
        detail = { descriptor, chunkIndex, completion in
            Self.run({
                if descriptor.sourceKind == .memoryNote {
                    return try store.memoryNote(id: descriptor.id).text
                }
                return try store.context(documentID: descriptor.id, chunkIndex: chunkIndex).text
            }, completion: completion)
        }
        memoryNote = { id, completion in
            Self.run({ try store.memoryNote(id: id) }, completion: completion)
        }
        save = { existing, draft, completion in
            Self.run({
                if let existing {
                    return try store.updateMemoryNote(
                        id: existing.descriptor.id,
                        title: draft.title,
                        text: draft.text
                    )
                }
                return try store.createMemoryNote(
                    title: draft.title,
                    text: draft.text,
                    scope: draft.scope
                )
            }, completion: completion)
        }
        importFiles = { urls, scope, completion in
            Self.run({
                var imported: [KnowledgeDocumentDescriptor] = []
                var failedCount = 0
                for url in urls {
                    let granted = url.startAccessingSecurityScopedResource()
                    defer { if granted { url.stopAccessingSecurityScopedResource() } }
                    do {
                        imported.append(try store.importFile(at: url, scope: scope))
                    } catch {
                        failedCount += 1
                    }
                }
                return KnowledgeCenterImportOutcome(imported: imported, failedCount: failedCount)
            }, completion: completion)
        }
        remove = { id, completion in
            Self.run({ try store.delete(id: id) }, completion: completion)
        }
        clear = { scope, completion in
            Self.run({ try store.clear(scope: scope) }, completion: completion)
        }
        export = { destination, completion in
            Self.run({
                let granted = destination.startAccessingSecurityScopedResource()
                defer { if granted { destination.stopAccessingSecurityScopedResource() } }
                try store.exportManifest(to: destination)
            }, completion: completion)
        }
    }

    private static func run<Value>(
        _ work: @escaping () throws -> Value,
        completion: @escaping @MainActor (Result<Value, Error>) -> Void
    ) -> KnowledgeCenterOperationCancellation {
        let cancellation = KnowledgeCenterOperationCancellation()
        DispatchQueue.global(qos: .userInitiated).async {
            guard !cancellation.isCancelled else { return }
            let result = Result { try work() }
            guard !cancellation.isCancelled else { return }
            DispatchQueue.main.async {
                guard !cancellation.isCancelled else { return }
                completion(result)
            }
        }
        return cancellation
    }
}

/// A native, offline control surface for `LocalKnowledgeStore`.
///
/// The controller performs no networking and does not log search queries or
/// memory bodies. Slow file extraction and index queries run away from the UI
/// thread; all AppKit state changes are marshalled back to the main queue.
final class KnowledgeCenterWindowController: NSWindowController,
    NSTableViewDataSource,
    NSTableViewDelegate,
    NSSearchFieldDelegate,
    NSWindowDelegate
{
    var onKnowledgeChanged: ((KnowledgeCenterChange) -> Void)?
    var onOpenStorage: ((URL) -> Void)?

    private enum DisplayItem {
        case document(KnowledgeDocumentDescriptor)
        case result(KnowledgeSearchResult)

        var documentID: UUID {
            switch self {
            case .document(let descriptor): descriptor.id
            case .result(let result): result.documentID
            }
        }

        var title: String {
            switch self {
            case .document(let descriptor): descriptor.title
            case .result(let result): result.title
            }
        }

        var scope: KnowledgeScope {
            switch self {
            case .document(let descriptor): descriptor.scope
            case .result(let result): result.scope
            }
        }
    }

    private enum StatePresentation {
        case loading(String)
        case empty(title: String, detail: String, symbol: String)
        case error(title: String, detail: String)
        case content
    }

    private static let supportedExtensions = [
        "txt", "text", "log", "md", "markdown", "mdown", "pdf", "json", "jsonl", "csv", "tsv",
        "swift", "m", "mm", "h", "hpp", "c", "cc", "cpp", "cs", "go", "rs", "py", "js", "jsx",
        "ts", "tsx", "java", "kt", "kts", "rb", "php", "sh", "bash", "zsh", "fish", "sql", "html",
        "htm", "css", "scss", "xml", "yaml", "yml", "toml", "ini"
    ]

    static var supportedImportContentTypes: [UTType] {
        supportedExtensions.compactMap { UTType(filenameExtension: $0) }
    }

    private let operations: KnowledgeCenterOperations
    private let interactions: KnowledgeCenterInteractions
    private let displayPolicy: NativeAccessibilityDisplayPolicy
    private var accessibilityDisplayObserver: NativeAccessibilityDisplayObserver?
    private var projects: [KnowledgeProjectOption]
    private var selectedScope: KnowledgeScope
    private var items: [DisplayItem] = []
    private var allDescriptors: [UUID: KnowledgeDocumentDescriptor] = [:]
    private var queryGeneration = 0
    private var detailGeneration = 0
    private var pendingSearch: DispatchWorkItem?
    private var mutationInProgress = false
    private var mutationGeneration = 0
    private var activeQuery: KnowledgeCenterOperationCancellation?
    private var activeDetail: KnowledgeCenterOperationCancellation?
    private var activeMutation: KnowledgeCenterOperationCancellation?
    private var tableStateIsBusy = false
    private(set) var noteEditor: KnowledgeNoteEditorWindowController?

    private let scopePicker = NSPopUpButton()
    private let includeGlobalButton = NSButton(checkboxWithTitle: "Include global memory", target: nil, action: nil)
    private let searchField = NSSearchField()
    private let tableView = NSTableView()
    private let tableScroll = NSScrollView()
    private let tableStateContainer = NSView()
    private let tableStateIcon = NSImageView()
    private let tableStateTitle = NSTextField(labelWithString: "")
    private let tableStateDetail = NSTextField(wrappingLabelWithString: "")
    private let tableStateSpinner = NSProgressIndicator()
    private let retryButton = NSButton(title: "Try Again", target: nil, action: nil)
    private let resultCountLabel = NSTextField(labelWithString: "")
    private let errorBanner = NSTextField(wrappingLabelWithString: "")
    private let maintenanceRetryButton = NSButton(title: "Retry Cleanup", target: nil, action: nil)

    private let privacyCard = KnowledgeStatusCardView(
        symbolName: "lock.shield.fill",
        title: "Privacy",
        value: "Local-only storage & search",
        accent: .systemGreen
    )
    private let retentionCard = KnowledgeStatusCardView(
        symbolName: "clock.arrow.circlepath",
        title: "Retention",
        value: "Kept until you remove it",
        accent: .systemBlue
    )
    private let storageCard = KnowledgeStatusCardView(
        symbolName: "internaldrive.fill",
        title: "Storage",
        value: "Calculating…",
        accent: .systemPurple
    )

    private let detailTitle = NSTextField(wrappingLabelWithString: "Select an item")
    private let detailBadges = NSTextField(labelWithString: "")
    private let detailMetadata = NSTextField(wrappingLabelWithString: "")
    private let detailText = NSTextView()
    private let detailScroll = NSScrollView()
    private let editButton = NSButton(title: "Edit Memory", target: nil, action: nil)
    private let removeButton = NSButton(title: "Remove…", target: nil, action: nil)
    private let addButton = NSButton(title: "New Memory", target: nil, action: nil)
    private let importButton = NSButton(title: "Import Files…", target: nil, action: nil)
    private let exportButton = NSButton(title: "Export Metadata…", target: nil, action: nil)
    private let clearButton = NSButton(title: "Clear Scope…", target: nil, action: nil)
    private let revealButton = NSButton(title: "Show Storage", target: nil, action: nil)

    convenience init(
        store: LocalKnowledgeStore,
        projects: [KnowledgeProjectOption] = [],
        selectedScope: KnowledgeScope = .global,
        interactions: KnowledgeCenterInteractions = .live,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live
    ) {
        self.init(
            operations: KnowledgeCenterOperations(store: store),
            projects: projects,
            selectedScope: selectedScope,
            interactions: interactions,
            displayPolicy: displayPolicy
        )
    }

    init(
        operations: KnowledgeCenterOperations,
        projects: [KnowledgeProjectOption] = [],
        selectedScope: KnowledgeScope = .global,
        interactions: KnowledgeCenterInteractions = .live,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live
    ) {
        self.operations = operations
        self.interactions = interactions
        self.displayPolicy = displayPolicy
        self.projects = Self.normalizedProjects(projects)
        self.selectedScope = selectedScope
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_120, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Knowledge & Memory"
        window.subtitle = "Private context stored and searched on this Mac"
        window.minSize = NSSize(width: 860, height: 620)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.KnowledgeCenter")
        super.init(window: window)
        window.delegate = self
        window.contentViewController = buildContent()
        accessibilityDisplayObserver = NativeAccessibilityDisplayObserver { [weak self] in
            self?.refreshAccessibilityDisplayOptions()
        }
        rebuildScopePicker()
        updateMutationControls()
        if !window.setFrameUsingName("LocalHarness.KnowledgeCenter") { window.center() }
        operations.setStatusHandler { [weak self] status in
            Task { @MainActor [weak self] in
                self?.storeStatusChanged(status)
            }
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        refresh()
    }

    func windowWillClose(_ notification: Notification) {
        invalidateOutstandingWork()
        if let editorWindow = noteEditor?.window, let parentWindow = window {
            interactions.endNoteEditor(parentWindow, editorWindow)
        }
        noteEditor = nil
        setMutationInProgress(false)
    }

    /// Replaces the project choices without exposing the store or note bodies to
    /// the caller. If the active project disappeared, the window safely returns
    /// to global memory.
    func updateProjects(_ projects: [KnowledgeProjectOption]) {
        guard !mutationInProgress else { return }
        self.projects = Self.normalizedProjects(projects)
        if case .project(let projectID) = selectedScope,
           !self.projects.contains(where: { $0.id == projectID }) {
            selectedScope = .global
        }
        rebuildScopePicker()
        refresh()
    }

    /// Selects an exact storage scope. Unknown projects are ignored rather than
    /// creating an accidental orphan scope from UI state.
    func selectScope(_ scope: KnowledgeScope) {
        guard !mutationInProgress else { return }
        if case .project(let projectID) = scope,
           !projects.contains(where: { $0.id == projectID }) {
            return
        }
        selectedScope = scope
        rebuildScopePicker()
        refresh()
    }

    func refresh() {
        pendingSearch?.cancel()
        activeQuery?.cancel()
        activeQuery = nil
        queryGeneration += 1
        switch operations.availability() {
        case .idle:
            beginStoreLoad(retry: false)
            return
        case .loading:
            presentTableState(.loading("Loading private knowledge…"))
            updateMutationControls()
            return
        case .unavailable:
            items = []
            allDescriptors = [:]
            tableView.reloadData()
            clearDetail()
            presentTableState(.error(
                title: "Knowledge unavailable",
                detail: "The private library could not be verified. No partial index is in use."
            ))
            updateStorageStatus()
            updateMutationControls()
            return
        case .ready:
            break
        }
        let generation = queryGeneration
        let query = searchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let filter = currentFilter
        let selectedID = selectedDisplayItem?.documentID
        presentTableState(.loading(query.isEmpty ? "Loading private knowledge…" : "Searching on this Mac…"))
        errorBanner.isHidden = true

        activeQuery = operations.query(query, filter) { [weak self] result in
            guard let self, generation == self.queryGeneration else { return }
            self.activeQuery = nil
            switch result {
            case .success(let payload):
                self.allDescriptors = Dictionary(uniqueKeysWithValues: payload.all.map { ($0.id, $0) })
                self.items = query.isEmpty
                    ? payload.documents.map(DisplayItem.document)
                    : payload.results.map(DisplayItem.result)
                self.reloadTable(query: query, preserving: selectedID)
            case .failure:
                self.items = []
                self.allDescriptors = [:]
                self.tableView.reloadData()
                self.clearDetail()
                self.presentFailure(
                    .query,
                    tableTitle: query.isEmpty ? "Knowledge unavailable" : "Search unavailable"
                )
            }
        }
    }

    private func beginStoreLoad(retry: Bool) {
        presentTableState(.loading(retry ? "Retrying private knowledge…" : "Loading private knowledge…"))
        errorBanner.isHidden = true
        updateStorageStatus()
        updateMutationControls()
        operations.load(retry)
    }

    private func storeStatusChanged(_ status: LocalKnowledgeStoreStatus) {
        updateStorageStatus()
        switch status.availability {
        case .idle:
            if window?.isVisible == true { beginStoreLoad(retry: false) }
        case .loading:
            presentTableState(.loading("Loading private knowledge…"))
            updateMutationControls()
        case .ready:
            if window?.isVisible == true { refresh() }
        case .unavailable:
            activeQuery?.cancel()
            activeQuery = nil
            activeMutation?.cancel()
            activeMutation = nil
            queryGeneration += 1
            mutationGeneration += 1
            if let noteEditor {
                noteEditor.operationBecameUnavailable()
                mutationInProgress = true
            } else {
                mutationInProgress = false
            }
            items = []
            allDescriptors = [:]
            tableView.reloadData()
            clearDetail()
            presentTableState(.error(
                title: "Knowledge unavailable",
                detail: "The private library could not be verified. No partial index is in use."
            ))
            updateMutationControls()
        }
    }

    func numberOfRows(in tableView: NSTableView) -> Int { items.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard items.indices.contains(row), let tableColumn else { return nil }
        let item = items[row]
        switch tableColumn.identifier.rawValue {
        case "scope":
            let identifier = NSUserInterfaceItemIdentifier("KnowledgeScopeCell")
            let field = (tableView.makeView(withIdentifier: identifier, owner: self) as? NSTextField)
                ?? NSTextField(labelWithString: "")
            field.identifier = identifier
            field.stringValue = scopeDisplayName(item.scope)
            field.textColor = item.scope == .global ? .systemBlue : .systemPurple
            field.font = .systemFont(ofSize: 11, weight: .medium)
            field.lineBreakMode = .byTruncatingTail
            field.toolTip = field.stringValue
            return field
        case "rank":
            let identifier = NSUserInterfaceItemIdentifier("KnowledgeRankCell")
            let field = (tableView.makeView(withIdentifier: identifier, owner: self) as? NSTextField)
                ?? NSTextField(labelWithString: "")
            field.identifier = identifier
            if case .result(let result) = item {
                field.stringValue = "#\(row + 1)"
                field.toolTip = "Local relevance score \(String(format: "%.3f", result.score))"
            } else {
                field.stringValue = ""
                field.toolTip = nil
            }
            field.alignment = .center
            field.font = .monospacedDigitSystemFont(ofSize: 11, weight: .semibold)
            field.textColor = .secondaryLabelColor
            return field
        default:
            let identifier = NSUserInterfaceItemIdentifier("KnowledgeItemCell")
            let cell = (tableView.makeView(withIdentifier: identifier, owner: self) as? KnowledgeItemCellView)
                ?? KnowledgeItemCellView()
            cell.identifier = identifier
            switch item {
            case .document(let descriptor):
                cell.configure(
                    title: descriptor.title,
                    detail: "\(sourceKindDisplayName(descriptor.sourceKind)) · Updated \(Self.relativeDate.string(for: descriptor.updatedAt) ?? "recently") · \(Self.byteCount.string(fromByteCount: Int64(descriptor.utf8ByteCount)))",
                    symbolName: symbolName(for: descriptor.sourceKind),
                    accent: descriptor.sourceKind == .memoryNote ? .systemBlue : .secondaryLabelColor
                )
            case .result(let result):
                cell.configure(
                    title: result.title,
                    detail: result.snippet.replacingOccurrences(of: "\n", with: " "),
                    symbolName: "text.magnifyingglass",
                    accent: .systemOrange
                )
            }
            cell.setAccessibilityLabel(accessibilityDescription(for: item, rank: row + 1))
            return cell
        }
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updateSelection()
    }

    func controlTextDidChange(_ notification: Notification) {
        guard notification.object as? NSSearchField === searchField else { return }
        pendingSearch?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.refresh() }
        pendingSearch = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.18, execute: work)
    }

    // MARK: - View construction

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let title = NSTextField(labelWithString: "Knowledge & Memory")
        title.font = .systemFont(ofSize: 24, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: "Give Harness durable context without sending your library anywhere. Search and indexing stay on-device; task-time context still follows the model boundary you choose.")
        subtitle.textColor = .secondaryLabelColor
        subtitle.maximumNumberOfLines = 2

        let localBadge = NSTextField(labelWithString: "  LOCAL-ONLY LIBRARY  ")
        localBadge.font = .systemFont(ofSize: 10, weight: .bold)
        localBadge.textColor = .systemGreen
        localBadge.drawsBackground = true
        localBadge.backgroundColor = NSColor.systemGreen.withAlphaComponent(0.10)
        localBadge.wantsLayer = true
        localBadge.layer?.cornerRadius = 8
        localBadge.setAccessibilityLabel("Local-only knowledge library")

        let headingRow = NSStackView(views: [title, NSView(), localBadge])
        headingRow.orientation = .horizontal
        headingRow.alignment = .centerY
        headingRow.spacing = 10

        let cards = NSStackView(views: [privacyCard, retentionCard, storageCard])
        cards.orientation = .horizontal
        cards.distribution = .fillEqually
        cards.spacing = 10
        cards.setAccessibilityLabel("Knowledge privacy, retention, and storage status")

        scopePicker.target = self
        scopePicker.action = #selector(scopeChanged(_:))
        scopePicker.setAccessibilityLabel("Knowledge scope")
        includeGlobalButton.target = self
        includeGlobalButton.action = #selector(includeGlobalChanged(_:))
        includeGlobalButton.state = .on
        includeGlobalButton.setAccessibilityHelp("When a project is selected, include global memory in browsing and search results.")

        searchField.placeholderString = "Search titles and contents"
        searchField.sendsSearchStringImmediately = true
        searchField.sendsWholeSearchString = false
        searchField.delegate = self
        searchField.setAccessibilityLabel("Search private knowledge")
        searchField.setAccessibilityHelp("Search is ranked locally and no query leaves this Mac.")

        configureButton(addButton, symbol: "plus", action: #selector(addMemory(_:)), prominent: true)
        configureButton(importButton, symbol: "square.and.arrow.down", action: #selector(importFiles(_:)))

        let controls = NSStackView(views: [scopePicker, includeGlobalButton, searchField, addButton, importButton])
        controls.orientation = .horizontal
        controls.alignment = .centerY
        controls.spacing = 8
        searchField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        searchField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        scopePicker.widthAnchor.constraint(greaterThanOrEqualToConstant: 170).isActive = true
        searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true

        errorBanner.font = .systemFont(ofSize: 12, weight: .medium)
        errorBanner.textColor = .systemRed
        errorBanner.maximumNumberOfLines = 2
        errorBanner.isHidden = true
        errorBanner.setAccessibilityLabel("Knowledge error")
        maintenanceRetryButton.target = self
        maintenanceRetryButton.action = #selector(retryMaintenance(_:))
        maintenanceRetryButton.setAccessibilityLabel("Retry private knowledge cleanup")
        maintenanceRetryButton.isHidden = true
        let bannerRow = NSStackView(views: [errorBanner, maintenanceRetryButton])
        bannerRow.orientation = .horizontal
        bannerRow.alignment = .centerY
        bannerRow.spacing = 10

        configureTable()
        configureTableState()
        let listContainer = NSView()
        tableScroll.translatesAutoresizingMaskIntoConstraints = false
        tableStateContainer.translatesAutoresizingMaskIntoConstraints = false
        listContainer.addSubview(tableScroll)
        listContainer.addSubview(tableStateContainer)
        NSLayoutConstraint.activate([
            tableScroll.topAnchor.constraint(equalTo: listContainer.topAnchor),
            tableScroll.leadingAnchor.constraint(equalTo: listContainer.leadingAnchor),
            tableScroll.trailingAnchor.constraint(equalTo: listContainer.trailingAnchor),
            tableScroll.bottomAnchor.constraint(equalTo: listContainer.bottomAnchor),
            tableStateContainer.topAnchor.constraint(equalTo: listContainer.topAnchor),
            tableStateContainer.leadingAnchor.constraint(equalTo: listContainer.leadingAnchor),
            tableStateContainer.trailingAnchor.constraint(equalTo: listContainer.trailingAnchor),
            tableStateContainer.bottomAnchor.constraint(equalTo: listContainer.bottomAnchor)
        ])

        let listHeading = NSTextField(labelWithString: "Library")
        listHeading.font = .systemFont(ofSize: 13, weight: .semibold)
        resultCountLabel.textColor = .secondaryLabelColor
        resultCountLabel.font = .systemFont(ofSize: 11)
        let listHeader = NSStackView(views: [listHeading, NSView(), resultCountLabel])
        listHeader.orientation = .horizontal
        listHeader.alignment = .centerY

        let listPane = NSStackView(views: [listHeader, listContainer])
        listPane.orientation = .vertical
        listPane.alignment = .leading
        listPane.spacing = 8
        listContainer.widthAnchor.constraint(equalTo: listPane.widthAnchor).isActive = true

        let detailPane = buildDetailPane()
        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.addArrangedSubview(listPane)
        split.addArrangedSubview(detailPane)
        split.setHoldingPriority(.defaultLow, forSubviewAt: 0)
        detailPane.widthAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true
        detailPane.widthAnchor.constraint(lessThanOrEqualToConstant: 430).isActive = true

        let support = NSTextField(wrappingLabelWithString: "Supported: text, Markdown, PDFs with extractable text, JSON/JSONL, CSV/TSV, source code and common config files. Up to \(Self.byteCount.string(fromByteCount: Int64(LocalKnowledgeLimits.maximumImportBytes))) per file, \(LocalKnowledgeLimits.maximumPDFPages.formatted()) PDF pages, and \(Self.byteCount.string(fromByteCount: Int64(LocalKnowledgeLimits.maximumStoredUTF8Bytes))) of indexed text. Encrypted or image-only PDFs are not imported.")
        support.textColor = .secondaryLabelColor
        support.font = .systemFont(ofSize: 11)
        support.maximumNumberOfLines = 2
        support.setAccessibilityLabel("Supported knowledge file formats and limits")

        configureButton(revealButton, symbol: "folder", action: #selector(revealStorage(_:)))
        configureButton(exportButton, symbol: "square.and.arrow.up", action: #selector(exportMetadata(_:)))
        configureButton(clearButton, symbol: "trash", action: #selector(clearScope(_:)))
        clearButton.contentTintColor = .systemRed
        let footerActions = NSStackView(views: [revealButton, NSView(), exportButton, clearButton])
        footerActions.orientation = .horizontal
        footerActions.spacing = 8

        let stack = NSStackView(views: [headingRow, subtitle, cards, controls, bannerRow, split, support, footerActions])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)

        for view in [headingRow, subtitle, cards, controls, bannerRow, split, support, footerActions] {
            view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        cards.heightAnchor.constraint(equalToConstant: 68).isActive = true
        split.heightAnchor.constraint(greaterThanOrEqualToConstant: 350).isActive = true
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18)
        ])

        controller.view = root
        updateSelection()
        return controller
    }

    private func configureTable() {
        let itemColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("item"))
        itemColumn.title = "Knowledge"
        itemColumn.minWidth = 330
        itemColumn.width = 470
        let scopeColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("scope"))
        scopeColumn.title = "Scope"
        scopeColumn.minWidth = 90
        scopeColumn.width = 120
        let rankColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("rank"))
        rankColumn.title = "Rank"
        rankColumn.width = 54
        rankColumn.minWidth = 48
        rankColumn.maxWidth = 64
        [itemColumn, scopeColumn, rankColumn].forEach(tableView.addTableColumn)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.target = self
        tableView.rowHeight = 52
        tableView.intercellSpacing = NSSize(width: 8, height: 4)
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.allowsMultipleSelection = false
        tableView.selectionHighlightStyle = .regular
        tableView.setAccessibilityLabel("Knowledge library and ranked search results")
        tableView.doubleAction = #selector(editSelectedFromDoubleClick(_:))

        tableScroll.documentView = tableView
        tableScroll.hasVerticalScroller = true
        tableScroll.hasHorizontalScroller = true
        tableScroll.autohidesScrollers = true
        tableScroll.borderType = .bezelBorder
    }

    private func configureTableState() {
        tableStateIcon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 30, weight: .regular)
        tableStateIcon.contentTintColor = .tertiaryLabelColor
        tableStateIcon.imageScaling = .scaleProportionallyDown
        tableStateTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        tableStateTitle.alignment = .center
        tableStateDetail.textColor = .secondaryLabelColor
        tableStateDetail.alignment = .center
        tableStateDetail.maximumNumberOfLines = 3
        tableStateDetail.preferredMaxLayoutWidth = 360
        tableStateSpinner.style = .spinning
        tableStateSpinner.controlSize = .small
        retryButton.target = self
        retryButton.action = #selector(retry(_:))

        let stateStack = NSStackView(views: [tableStateSpinner, tableStateIcon, tableStateTitle, tableStateDetail, retryButton])
        stateStack.orientation = .vertical
        stateStack.alignment = .centerX
        stateStack.spacing = 8
        stateStack.translatesAutoresizingMaskIntoConstraints = false
        tableStateContainer.addSubview(stateStack)
        tableStateContainer.setAccessibilityElement(true)
        tableStateContainer.setAccessibilityRole(.group)
        tableStateContainer.setAccessibilityLabel("Knowledge library status")
        NSLayoutConstraint.activate([
            stateStack.centerXAnchor.constraint(equalTo: tableStateContainer.centerXAnchor),
            stateStack.centerYAnchor.constraint(equalTo: tableStateContainer.centerYAnchor),
            stateStack.leadingAnchor.constraint(greaterThanOrEqualTo: tableStateContainer.leadingAnchor, constant: 24),
            stateStack.trailingAnchor.constraint(lessThanOrEqualTo: tableStateContainer.trailingAnchor, constant: -24)
        ])
    }

    private func buildDetailPane() -> NSView {
        let pane = NSView()
        detailTitle.font = .systemFont(ofSize: 18, weight: .semibold)
        detailTitle.maximumNumberOfLines = 2
        detailBadges.font = .systemFont(ofSize: 11, weight: .semibold)
        detailBadges.textColor = .systemBlue
        detailMetadata.font = .systemFont(ofSize: 11)
        detailMetadata.textColor = .secondaryLabelColor
        detailMetadata.maximumNumberOfLines = 4

        detailText.isEditable = false
        detailText.isSelectable = true
        detailText.drawsBackground = false
        detailText.font = .systemFont(ofSize: 13)
        detailText.textContainerInset = NSSize(width: 10, height: 10)
        detailText.string = "Select a memory or imported file to inspect its locally stored context."
        detailText.setAccessibilityLabel("Selected knowledge context")
        detailScroll.documentView = detailText
        detailScroll.hasVerticalScroller = true
        detailScroll.autohidesScrollers = true
        detailScroll.borderType = .bezelBorder

        configureButton(editButton, symbol: "pencil", action: #selector(editMemory(_:)))
        configureButton(removeButton, symbol: "trash", action: #selector(removeSelected(_:)))
        removeButton.contentTintColor = .systemRed
        let actions = NSStackView(views: [editButton, NSView(), removeButton])
        actions.orientation = .horizontal
        actions.spacing = 8

        let stack = NSStackView(views: [detailTitle, detailBadges, detailMetadata, detailScroll, actions])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        pane.addSubview(stack)
        for view in [detailTitle, detailBadges, detailMetadata, detailScroll, actions] {
            view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: pane.topAnchor, constant: 4),
            stack.leadingAnchor.constraint(equalTo: pane.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: pane.trailingAnchor),
            stack.bottomAnchor.constraint(equalTo: pane.bottomAnchor, constant: -2),
            detailScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 220)
        ])
        return pane
    }

    // MARK: - Presentation

    private var currentFilter: KnowledgeScopeFilter {
        switch selectedScope {
        case .global:
            return .globalOnly
        case .project(let projectID):
            return .project(projectID, includeGlobal: includeGlobalButton.state == .on)
        }
    }

    private func rebuildScopePicker() {
        scopePicker.menu?.removeAllItems()
        let global = NSMenuItem(title: "Global Memory", action: nil, keyEquivalent: "")
        global.representedObject = ""
        global.image = NSImage(systemSymbolName: "globe", accessibilityDescription: nil)
        scopePicker.menu?.addItem(global)
        if !projects.isEmpty {
            scopePicker.menu?.addItem(.separator())
            for project in projects {
                let item = NSMenuItem(title: project.displayName, action: nil, keyEquivalent: "")
                item.representedObject = project.id
                item.image = NSImage(systemSymbolName: "folder", accessibilityDescription: nil)
                scopePicker.menu?.addItem(item)
            }
        }
        let targetID = selectedScope.projectID ?? ""
        if let target = scopePicker.itemArray.first(where: { ($0.representedObject as? String) == targetID }) {
            scopePicker.select(target)
        } else {
            selectedScope = .global
            scopePicker.select(global)
        }
        includeGlobalButton.isHidden = selectedScope == .global
        includeGlobalButton.isEnabled = selectedScope != .global && !mutationInProgress
        updateActionTitles()
    }

    private func reloadTable(query: String, preserving selectedID: UUID?) {
        tableView.rowHeight = query.isEmpty ? 48 : 64
        tableView.reloadData()
        updateStorageStatus()
        updateActionTitles()
        resultCountLabel.stringValue = query.isEmpty
            ? "\(items.count.formatted()) item\(items.count == 1 ? "" : "s")"
            : "\(items.count.formatted()) ranked result\(items.count == 1 ? "" : "s")"

        if items.isEmpty {
            if query.isEmpty {
                presentTableState(.empty(
                    title: selectedScope == .global ? "No global memory yet" : "No knowledge in this project",
                    detail: "Create a memory note or import a supported file. Everything is indexed locally.",
                    symbol: "books.vertical"
                ))
            } else {
                presentTableState(.empty(
                    title: "No local matches",
                    detail: "Try different words or change the knowledge scope.",
                    symbol: "magnifyingglass"
                ))
            }
            clearDetail()
        } else {
            presentTableState(.content)
            if let selectedID, let index = items.firstIndex(where: { $0.documentID == selectedID }) {
                tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            } else {
                tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
            }
            updateSelection()
        }
        updateMutationControls()
    }

    private func presentTableState(_ state: StatePresentation) {
        switch state {
        case .loading:
            tableStateIsBusy = true
        case .content, .empty, .error:
            tableStateIsBusy = false
        }
        switch state {
        case .content:
            tableScroll.isHidden = false
            tableStateContainer.isHidden = true
            displayPolicy.progressIndicatorPresentation(isBusy: false).apply(to: tableStateSpinner)
        case .loading(let message):
            tableScroll.isHidden = true
            tableStateContainer.isHidden = false
            displayPolicy.progressIndicatorPresentation(isBusy: true).apply(to: tableStateSpinner)
            tableStateIcon.isHidden = true
            tableStateTitle.stringValue = message
            tableStateDetail.stringValue = ""
            retryButton.isHidden = true
            tableStateContainer.setAccessibilityValue(message)
        case .empty(let title, let detail, let symbol):
            tableScroll.isHidden = true
            tableStateContainer.isHidden = false
            displayPolicy.progressIndicatorPresentation(isBusy: false).apply(to: tableStateSpinner)
            tableStateIcon.isHidden = false
            tableStateIcon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            tableStateTitle.stringValue = title
            tableStateDetail.stringValue = detail
            retryButton.isHidden = true
            tableStateContainer.setAccessibilityValue("\(title). \(detail)")
        case .error(let title, let detail):
            tableScroll.isHidden = true
            tableStateContainer.isHidden = false
            displayPolicy.progressIndicatorPresentation(isBusy: false).apply(to: tableStateSpinner)
            tableStateIcon.isHidden = false
            tableStateIcon.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: nil)
            tableStateTitle.stringValue = title
            tableStateDetail.stringValue = detail
            retryButton.isHidden = false
            tableStateContainer.setAccessibilityValue("\(title). \(detail)")
        }
    }

    private func refreshAccessibilityDisplayOptions() {
        displayPolicy.progressIndicatorPresentation(isBusy: tableStateIsBusy).apply(to: tableStateSpinner)
    }

    private func presentFailure(_ failure: KnowledgeCenterFailure, tableTitle: String? = nil) {
        let detail = failure.message
        errorBanner.stringValue = detail
        errorBanner.textColor = .systemRed
        errorBanner.isHidden = false
        if let tableTitle { presentTableState(.error(title: tableTitle, detail: detail)) }
        updateMutationControls()
    }

    private func updateStorageStatus() {
        switch operations.availability() {
        case .idle:
            maintenanceRetryButton.isHidden = true
            storageCard.value = "Loads only when opened"
            storageCard.setAccessibilityValue("Private knowledge has not been loaded")
            return
        case .loading:
            maintenanceRetryButton.isHidden = true
            storageCard.value = "Loading privately…"
            storageCard.setAccessibilityValue("Private knowledge is loading")
            return
        case .unavailable:
            maintenanceRetryButton.isHidden = true
            storageCard.value = "Unavailable · no partial index"
            storageCard.setAccessibilityValue("Private knowledge is unavailable and no partial index is in use")
            return
        case .ready:
            break
        }
        let descriptors = Array(allDescriptors.values)
        let used = descriptors.reduce(Int64(0)) { $0 + Int64($1.utf8ByteCount) }
        storageCard.value = "\(Self.byteCount.string(fromByteCount: used)) of \(Self.byteCount.string(fromByteCount: Int64(LocalKnowledgeLimits.maximumStoredUTF8Bytes))) · \(descriptors.count.formatted()) items"
        storageCard.setAccessibilityValue("\(descriptors.count) items using \(Self.byteCount.string(fromByteCount: used)) of \(Self.byteCount.string(fromByteCount: Int64(LocalKnowledgeLimits.maximumStoredUTF8Bytes)))")

        let report = operations.recoveryReport()
        let recovered = (report.recoveredCatalog ? 1 : 0) + report.recoveredOrphanDocuments + report.quarantinedDocuments
        if report.trashCleanupIssue != nil {
            errorBanner.stringValue = "Knowledge is ready, but old deleted-item cleanup could not finish. Retry cleanup when convenient."
            errorBanner.textColor = .systemOrange
            errorBanner.isHidden = false
            maintenanceRetryButton.isHidden = false
        } else if report.trashCleanupPending {
            errorBanner.stringValue = "Knowledge is ready. Old deleted items are being cleaned up privately in the background."
            errorBanner.textColor = .secondaryLabelColor
            errorBanner.isHidden = false
            maintenanceRetryButton.isHidden = true
        } else if recovered > 0 {
            errorBanner.stringValue = "Local storage recovery preserved usable knowledge. \(report.quarantinedDocuments) damaged item\(report.quarantinedDocuments == 1 ? " was" : "s were") quarantined."
            errorBanner.textColor = .systemOrange
            errorBanner.isHidden = false
            maintenanceRetryButton.isHidden = true
        } else {
            errorBanner.textColor = .systemRed
            maintenanceRetryButton.isHidden = true
        }
    }

    private func updateSelection() {
        activeDetail?.cancel()
        activeDetail = nil
        detailGeneration += 1
        let generation = detailGeneration
        guard let item = selectedDisplayItem,
              let descriptor = allDescriptors[item.documentID] else {
            clearDetail()
            return
        }

        detailTitle.stringValue = descriptor.title
        detailBadges.stringValue = "\(scopeDisplayName(descriptor.scope).uppercased())   ·   \(sourceKindDisplayName(descriptor.sourceKind).uppercased())"
        var metadata = "Updated \(Self.longDate.string(from: descriptor.updatedAt)) · \(descriptor.characterCount.formatted()) characters · \(descriptor.chunkCount.formatted()) chunk\(descriptor.chunkCount == 1 ? "" : "s")"
        if let sourceName = descriptor.sourceName { metadata += "\nImported from \(sourceName) — the original path was not retained" }
        detailMetadata.stringValue = metadata
        detailText.string = "Loading local context…"
        editButton.isEnabled = descriptor.sourceKind == .memoryNote && !mutationInProgress
        removeButton.isEnabled = !mutationInProgress

        let chunkIndex: Int
        if case .result(let result) = item { chunkIndex = result.chunkIndex } else { chunkIndex = 0 }
        activeDetail = operations.detail(descriptor, chunkIndex) { [weak self] result in
            guard let self, generation == self.detailGeneration,
                  self.selectedDisplayItem?.documentID == descriptor.id else { return }
            self.activeDetail = nil
            switch result {
            case .success(let text):
                self.detailText.string = text
                self.detailText.scrollToBeginningOfDocument(nil)
            case .failure:
                self.detailText.string = KnowledgeCenterFailure.detail.message
            }
        }
    }

    private func clearDetail() {
        activeDetail?.cancel()
        activeDetail = nil
        detailGeneration += 1
        detailTitle.stringValue = "Select an item"
        detailBadges.stringValue = ""
        detailMetadata.stringValue = ""
        detailText.string = "Select a memory or imported file to inspect its locally stored context."
        editButton.isEnabled = false
        removeButton.isEnabled = false
    }

    private var selectedDisplayItem: DisplayItem? {
        items.indices.contains(tableView.selectedRow) ? items[tableView.selectedRow] : nil
    }

    private var selectedDescriptor: KnowledgeDocumentDescriptor? {
        guard let id = selectedDisplayItem?.documentID else { return nil }
        return allDescriptors[id]
    }

    private func updateMutationControls() {
        let ready = operations.availability() == .ready
        tableView.isEnabled = ready && !mutationInProgress
        scopePicker.isEnabled = ready && !mutationInProgress
        includeGlobalButton.isEnabled = ready && selectedScope != .global && !mutationInProgress
        searchField.isEnabled = ready && !mutationInProgress
        addButton.isEnabled = ready && !mutationInProgress
        importButton.isEnabled = ready && !mutationInProgress
        exportButton.isEnabled = ready && !mutationInProgress && !allDescriptors.isEmpty
        revealButton.isEnabled = !mutationInProgress
        clearButton.isEnabled = ready && !mutationInProgress && exactScopeDocumentCount > 0
        editButton.isEnabled = ready && !mutationInProgress && selectedDescriptor?.sourceKind == .memoryNote
        removeButton.isEnabled = ready && !mutationInProgress && selectedDescriptor != nil
    }

    private func setMutationInProgress(_ busy: Bool, message: String? = nil) {
        mutationInProgress = busy
        updateMutationControls()
        if let message {
            errorBanner.textColor = .secondaryLabelColor
            errorBanner.stringValue = message
            errorBanner.isHidden = false
        } else if operations.recoveryReport().quarantinedDocuments == 0 {
            errorBanner.isHidden = true
        }
    }

    private var exactScopeDocumentCount: Int {
        allDescriptors.values.filter { $0.scope == selectedScope }.count
    }

    private func updateActionTitles() {
        let label = scopeDisplayName(selectedScope)
        clearButton.title = "Clear \(label)…"
        clearButton.setAccessibilityLabel("Clear \(label)")
    }

    @discardableResult
    private func beginMutation(message: String) -> Int {
        mutationGeneration += 1
        activeMutation?.cancel()
        activeMutation = nil
        setMutationInProgress(true, message: message)
        return mutationGeneration
    }

    private func finishMutation(_ generation: Int) -> Bool {
        guard generation == mutationGeneration, mutationInProgress else { return false }
        activeMutation = nil
        setMutationInProgress(false)
        return true
    }

    private func acceptMutationCompletion(_ generation: Int) -> Bool {
        guard generation == mutationGeneration,
              mutationInProgress,
              activeMutation != nil else { return false }
        activeMutation = nil
        return true
    }

    private func invalidateOutstandingWork() {
        pendingSearch?.cancel()
        pendingSearch = nil
        activeQuery?.cancel()
        activeQuery = nil
        activeDetail?.cancel()
        activeDetail = nil
        activeMutation?.cancel()
        activeMutation = nil
        queryGeneration += 1
        detailGeneration += 1
        mutationGeneration += 1
    }

    // MARK: - Actions

    @objc private func scopeChanged(_ sender: NSPopUpButton) {
        guard !mutationInProgress else { return }
        let projectID = sender.selectedItem?.representedObject as? String ?? ""
        selectedScope = projectID.isEmpty ? .global : .project(projectID)
        includeGlobalButton.isHidden = selectedScope == .global
        updateActionTitles()
        refresh()
    }

    @objc private func includeGlobalChanged(_ sender: NSButton) { guard !mutationInProgress else { return }; refresh() }
    @objc private func retry(_ sender: Any?) { guard !mutationInProgress else { return }; beginStoreLoad(retry: true) }
    @objc private func retryMaintenance(_ sender: Any?) { guard !mutationInProgress else { return }; operations.retryDeferredMaintenance() }

    @objc private func addMemory(_ sender: Any?) {
        guard !mutationInProgress, window != nil else { return }
        _ = beginMutation(message: "Editing a private memory note…")
        presentNoteEditor(note: nil)
    }

    @objc private func editMemory(_ sender: Any?) {
        guard !mutationInProgress,
              let descriptor = selectedDescriptor,
              descriptor.sourceKind == .memoryNote else { return }
        let generation = beginMutation(message: "Loading the private memory note…")
        activeMutation = operations.memoryNote(descriptor.id) { [weak self] result in
            guard let self, self.acceptMutationCompletion(generation) else { return }
            guard self.selectedDescriptor?.id == descriptor.id else {
                self.setMutationInProgress(false)
                return
            }
            switch result {
            case .success(let note):
                self.presentNoteEditor(note: note)
            case .failure:
                self.setMutationInProgress(false)
                self.presentFailure(.edit)
            }
        }
    }

    @objc private func editSelectedFromDoubleClick(_ sender: Any?) {
        guard !mutationInProgress, selectedDescriptor?.sourceKind == .memoryNote else { return }
        editMemory(sender)
    }

    private func presentNoteEditor(note: KnowledgeMemoryNote?) {
        guard let parentWindow = window else {
            activeMutation?.cancel()
            activeMutation = nil
            mutationGeneration += 1
            setMutationInProgress(false)
            return
        }
        let editor = KnowledgeNoteEditorWindowController(
            note: note,
            projects: projects,
            initialScope: note?.descriptor.scope ?? selectedScope
        )
        editor.onCancel = { [weak self, weak editor] in
            guard let self, let editor, self.noteEditor === editor else { return }
            self.activeMutation?.cancel()
            self.activeMutation = nil
            self.mutationGeneration += 1
            if let editorWindow = editor.window, let parentWindow = self.window {
                self.interactions.endNoteEditor(parentWindow, editorWindow)
            }
            self.noteEditor = nil
            self.setMutationInProgress(false)
        }
        editor.onSave = { [weak self, weak editor] draft, completion in
            guard let self, let editor, self.noteEditor === editor, self.mutationInProgress else { return }
            guard self.operations.availability() == .ready else {
                completion(.failure(KnowledgeCenterFailure.save))
                return
            }
            self.mutationGeneration += 1
            let generation = self.mutationGeneration
            self.activeMutation?.cancel()
            self.activeMutation = self.operations.save(note, draft) { [weak self, weak editor] result in
                guard let self, let editor,
                      self.noteEditor === editor,
                      self.acceptMutationCompletion(generation) else { return }
                switch result {
                case .success(let descriptor):
                    self.setMutationInProgress(false)
                    if let editorWindow = editor.window, let parentWindow = self.window {
                        self.interactions.endNoteEditor(parentWindow, editorWindow)
                    }
                    self.noteEditor = nil
                    self.onKnowledgeChanged?(note == nil ? .created(descriptor) : .updated(descriptor))
                    self.refresh()
                    completion(.success(()))
                case .failure:
                    self.presentFailure(.save)
                    completion(.failure(KnowledgeCenterFailure.save))
                }
            }
        }
        guard let editorWindow = editor.window else {
            activeMutation?.cancel()
            activeMutation = nil
            mutationGeneration += 1
            setMutationInProgress(false)
            presentFailure(.edit)
            return
        }
        noteEditor = editor
        interactions.beginNoteEditor(parentWindow, editorWindow)
    }

    @objc private func importFiles(_ sender: Any?) {
        guard !mutationInProgress, let parentWindow = window else { return }
        let scope = selectedScope
        let generation = beginMutation(message: "Choose files to import into \(scopeDisplayName(scope))…")
        var responded = false
        interactions.chooseImportFiles(parentWindow) { [weak self] urls in
            guard let self, !responded else { return }
            responded = true
            guard generation == self.mutationGeneration, self.mutationInProgress else { return }
            guard let urls, !urls.isEmpty else {
                _ = self.finishMutation(generation)
                return
            }
            self.performImports(urls, scope: scope, generation: generation)
        }
    }

    private func performImports(_ urls: [URL], scope: KnowledgeScope, generation: Int) {
        setMutationInProgress(true, message: "Importing \(urls.count.formatted()) file\(urls.count == 1 ? "" : "s") into \(scopeDisplayName(scope))…")
        activeMutation = operations.importFiles(urls, scope) { [weak self] result in
            guard let self, self.acceptMutationCompletion(generation) else { return }
            self.setMutationInProgress(false)
            switch result {
            case .success(let outcome):
                if !outcome.imported.isEmpty { self.onKnowledgeChanged?(.imported(outcome.imported)) }
                self.refresh()
                self.interactions.presentNotice(
                    .importCompleted(imported: outcome.imported.count, failed: outcome.failedCount),
                    self.window
                )
            case .failure:
                self.presentFailure(.importing)
            }
        }
    }

    @objc private func removeSelected(_ sender: Any?) {
        guard !mutationInProgress, let descriptor = selectedDescriptor, let parentWindow = window else { return }
        let generation = beginMutation(message: "Confirm removal of the selected knowledge item…")
        var responded = false
        interactions.confirm(.remove(id: descriptor.id, title: descriptor.title), parentWindow) { [weak self] confirmed in
            guard let self, !responded else { return }
            responded = true
            guard generation == self.mutationGeneration, self.mutationInProgress else { return }
            guard confirmed else {
                _ = self.finishMutation(generation)
                return
            }
            self.performRemoval(id: descriptor.id, generation: generation)
        }
    }

    private func performRemoval(id: UUID, generation: Int) {
        setMutationInProgress(true, message: "Removing the selected local knowledge item…")
        activeMutation = operations.remove(id) { [weak self] result in
            guard let self, self.acceptMutationCompletion(generation) else { return }
            self.setMutationInProgress(false)
            switch result {
            case .success(let descriptor):
                self.onKnowledgeChanged?(.removed(descriptor))
                self.refresh()
            case .failure:
                self.presentFailure(.removal)
            }
        }
    }

    @objc private func clearScope(_ sender: Any?) {
        let count = exactScopeDocumentCount
        guard !mutationInProgress, count > 0, let parentWindow = window else { return }
        let scope = selectedScope
        let displayName = scopeDisplayName(scope)
        let generation = beginMutation(message: "Confirm clearing \(displayName)…")
        var responded = false
        interactions.confirm(.clear(scope: scope, displayName: displayName, count: count), parentWindow) { [weak self] confirmed in
            guard let self, !responded else { return }
            responded = true
            guard generation == self.mutationGeneration, self.mutationInProgress else { return }
            guard confirmed else {
                _ = self.finishMutation(generation)
                return
            }
            self.performClear(scope: scope, generation: generation)
        }
    }

    private func performClear(scope: KnowledgeScope, generation: Int) {
        setMutationInProgress(true, message: "Clearing \(scopeDisplayName(scope))…")
        activeMutation = operations.clear(scope) { [weak self] result in
            guard let self, self.acceptMutationCompletion(generation) else { return }
            self.setMutationInProgress(false)
            switch result {
            case .success(let count):
                self.onKnowledgeChanged?(.cleared(scope: scope, count: count))
                self.refresh()
            case .failure:
                self.presentFailure(.clearing)
            }
        }
    }

    @objc private func exportMetadata(_ sender: Any?) {
        guard !mutationInProgress, let parentWindow = window else { return }
        let generation = beginMutation(message: "Choose where to export metadata…")
        var responded = false
        interactions.chooseExportDestination(parentWindow) { [weak self] destination in
            guard let self, !responded else { return }
            responded = true
            guard generation == self.mutationGeneration, self.mutationInProgress else { return }
            guard let destination else {
                _ = self.finishMutation(generation)
                return
            }
            self.performMetadataExport(to: destination, generation: generation)
        }
    }

    private func performMetadataExport(to destination: URL, generation: Int) {
        setMutationInProgress(true, message: "Exporting metadata only — no note or file contents…")
        activeMutation = operations.export(destination) { [weak self] result in
            guard let self, self.acceptMutationCompletion(generation) else { return }
            self.setMutationInProgress(false)
            switch result {
            case .success:
                self.interactions.presentNotice(.exportSucceeded, self.window)
            case .failure:
                self.presentFailure(.export)
            }
        }
    }

    @objc private func revealStorage(_ sender: Any?) {
        guard !mutationInProgress else { return }
        let storageDirectory = operations.storageDirectory()
        if let onOpenStorage {
            onOpenStorage(storageDirectory)
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([storageDirectory])
        }
    }

    // MARK: - Formatting

    private func scopeDisplayName(_ scope: KnowledgeScope) -> String {
        switch scope {
        case .global:
            return "Global Memory"
        case .project(let projectID):
            return projects.first(where: { $0.id == projectID })?.displayName ?? "Project"
        }
    }

    private func sourceKindDisplayName(_ kind: KnowledgeSourceKind) -> String {
        switch kind {
        case .memoryNote: "Memory note"
        case .plainText: "Text"
        case .markdown: "Markdown"
        case .sourceCode: "Source code"
        case .json: "JSON"
        case .csv: "Table"
        case .pdf: "PDF"
        }
    }

    private func symbolName(for kind: KnowledgeSourceKind) -> String {
        switch kind {
        case .memoryNote: "brain.head.profile"
        case .plainText: "doc.text"
        case .markdown: "text.document"
        case .sourceCode: "chevron.left.forwardslash.chevron.right"
        case .json: "curlybraces"
        case .csv: "tablecells"
        case .pdf: "doc.richtext"
        }
    }

    private func accessibilityDescription(for item: DisplayItem, rank: Int) -> String {
        switch item {
        case .document(let descriptor):
            return "\(descriptor.title), \(sourceKindDisplayName(descriptor.sourceKind)), \(scopeDisplayName(descriptor.scope))"
        case .result(let result):
            return "Rank \(rank), \(result.title), \(scopeDisplayName(result.scope)), \(result.snippet)"
        }
    }

    private func configureButton(_ button: NSButton, symbol: String, action: Selector, prominent: Bool = false) {
        button.target = self
        button.action = action
        button.bezelStyle = prominent ? .rounded : .rounded
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        button.imagePosition = .imageLeading
        if prominent { button.contentTintColor = .controlAccentColor }
    }

    private static func normalizedProjects(_ projects: [KnowledgeProjectOption]) -> [KnowledgeProjectOption] {
        var seen = Set<String>()
        return projects.compactMap { project in
            let id = project.id.trimmingCharacters(in: .whitespacesAndNewlines)
            let name = project.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard id == project.id,
                  !id.isEmpty,
                  id.utf8.count <= 256,
                  id.count <= 128,
                  !id.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  !name.isEmpty,
                  name.count <= 200,
                  name.utf8.count <= 800,
                  !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  !seen.contains(id) else { return nil }
            seen.insert(id)
            return KnowledgeProjectOption(id: id, displayName: name)
        }.sorted {
            $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
        }
    }

    private static let byteCount: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        formatter.countStyle = .file
        formatter.includesUnit = true
        formatter.isAdaptive = true
        return formatter
    }()

    private static let relativeDate: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter
    }()

    private static let longDate: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

final class KnowledgeNoteEditorWindowController: NSWindowController, NSTextViewDelegate, NSWindowDelegate {
    var onSave: ((KnowledgeMemoryDraft, @escaping (Result<Void, Error>) -> Void) -> Void)?
    var onCancel: (() -> Void)?

    private let existingNote: KnowledgeMemoryNote?
    private let projects: [KnowledgeProjectOption]
    private let initialScope: KnowledgeScope
    private let titleField = NSTextField()
    private let bodyView = NSTextView()
    private let scopePicker = NSPopUpButton()
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let countLabel = NSTextField(labelWithString: "")
    private let saveButton = NSButton(title: "Save Memory", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)
    private var isSaving = false
    private var saveGeneration = 0

    init(note: KnowledgeMemoryNote?, projects: [KnowledgeProjectOption], initialScope: KnowledgeScope) {
        existingNote = note
        self.projects = projects
        self.initialScope = initialScope
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 520),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        panel.title = note == nil ? "New Memory" : "Edit Memory"
        panel.minSize = NSSize(width: 520, height: 420)
        super.init(window: panel)
        panel.delegate = self
        panel.contentViewController = buildContent()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func cancelOperation(_ sender: Any?) { cancel(sender) }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard !isSaving else { return false }
        onCancel?()
        return false
    }

    func operationBecameUnavailable() {
        guard isSaving else { return }
        saveGeneration += 1
        setSaving(false)
        showValidation("Private knowledge became unavailable. Your draft remains open; retry after the library is ready.", focus: bodyView)
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()
        let heading = NSTextField(labelWithString: existingNote == nil ? "Add durable private context" : "Edit private memory")
        heading.font = .systemFont(ofSize: 20, weight: .semibold)
        let explanation = NSTextField(wrappingLabelWithString: "This note is stored and searched locally. It is never included in a task unless the knowledge workflow selects it as relevant context.")
        explanation.textColor = .secondaryLabelColor
        explanation.maximumNumberOfLines = 2

        let titleLabel = NSTextField(labelWithString: "Title")
        titleLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        titleField.placeholderString = "What should Harness remember?"
        titleField.stringValue = existingNote?.descriptor.title ?? ""
        titleField.setAccessibilityLabel("Memory title")

        let scopeLabel = NSTextField(labelWithString: "Scope")
        scopeLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        populateScopePicker()
        scopePicker.isEnabled = existingNote == nil
        scopePicker.setAccessibilityLabel("Memory scope")
        scopePicker.setAccessibilityHelp(existingNote == nil
            ? "Choose whether this memory applies globally or to one project."
            : "A memory's scope cannot be changed while editing.")

        let bodyLabel = NSTextField(labelWithString: "Memory")
        bodyLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        bodyView.string = existingNote?.text ?? ""
        bodyView.font = .systemFont(ofSize: 13)
        bodyView.textContainerInset = NSSize(width: 10, height: 10)
        bodyView.isRichText = false
        bodyView.allowsUndo = true
        bodyView.delegate = self
        bodyView.setAccessibilityLabel("Memory text")
        let bodyScroll = NSScrollView()
        bodyScroll.documentView = bodyView
        bodyScroll.hasVerticalScroller = true
        bodyScroll.autohidesScrollers = true
        bodyScroll.borderType = .bezelBorder

        statusLabel.textColor = .systemRed
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.maximumNumberOfLines = 2
        statusLabel.isHidden = true
        statusLabel.setAccessibilityLabel("Memory validation status")
        countLabel.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        countLabel.textColor = .secondaryLabelColor
        countLabel.alignment = .right

        saveButton.target = self
        saveButton.action = #selector(save(_:))
        saveButton.keyEquivalent = "\r"
        saveButton.image = NSImage(systemSymbolName: "checkmark", accessibilityDescription: nil)
        saveButton.imagePosition = .imageLeading
        cancelButton.target = self
        cancelButton.action = #selector(cancel(_:))

        let formHeader = NSStackView(views: [scopeLabel, scopePicker])
        formHeader.orientation = .horizontal
        formHeader.alignment = .centerY
        formHeader.spacing = 8
        let statusRow = NSStackView(views: [statusLabel, NSView(), countLabel])
        statusRow.orientation = .horizontal
        statusRow.alignment = .centerY
        let actions = NSStackView(views: [NSView(), cancelButton, saveButton])
        actions.orientation = .horizontal
        actions.spacing = 8

        let stack = NSStackView(views: [heading, explanation, titleLabel, titleField, formHeader, bodyLabel, bodyScroll, statusRow, actions])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 9
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        for view in [heading, explanation, titleField, formHeader, bodyScroll, statusRow, actions] {
            view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
            bodyScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 210)
        ])
        controller.view = root
        updateCount()
        return controller
    }

    private func populateScopePicker() {
        scopePicker.removeAllItems()
        scopePicker.addItem(withTitle: "Global Memory")
        scopePicker.lastItem?.representedObject = ""
        for project in projects {
            scopePicker.addItem(withTitle: project.displayName)
            scopePicker.lastItem?.representedObject = project.id
        }
        let targetID = existingNote?.descriptor.scope.projectID ?? initialScope.projectID ?? ""
        if let item = scopePicker.itemArray.first(where: { ($0.representedObject as? String) == targetID }) {
            scopePicker.select(item)
        }
    }

    func textDidChange(_ notification: Notification) { updateCount() }

    private func updateCount() {
        let bytes = bodyView.string.utf8.count
        countLabel.stringValue = "\(bytes.formatted()) / \(LocalKnowledgeLimits.maximumExtractedUTF8Bytes.formatted()) bytes"
        countLabel.textColor = bytes > LocalKnowledgeLimits.maximumExtractedUTF8Bytes ? .systemRed : .secondaryLabelColor
        saveButton.isEnabled = bytes <= LocalKnowledgeLimits.maximumExtractedUTF8Bytes
    }

    @objc private func save(_ sender: Any?) {
        guard !isSaving else { return }
        let normalizedTitle = titleField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedTitle.isEmpty,
              normalizedTitle.count <= 200,
              normalizedTitle.utf8.count <= 800,
              !normalizedTitle.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            showValidation("Enter a title between 1 and 200 characters without control characters.", focus: titleField)
            return
        }
        var normalizedText = bodyView.string
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if normalizedText.first == "\u{FEFF}" { normalizedText.removeFirst() }
        guard !normalizedText.isEmpty else {
            showValidation("Enter some text for this private memory.", focus: bodyView)
            return
        }
        guard !normalizedText.unicodeScalars.contains(where: {
            CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\t"
        }) else {
            showValidation("The memory contains unsupported control characters.", focus: bodyView)
            return
        }
        guard normalizedText.utf8.count <= LocalKnowledgeLimits.maximumExtractedUTF8Bytes else {
            showValidation("The memory is too large to store locally. Shorten it and try again.", focus: bodyView)
            return
        }
        let projectID = scopePicker.selectedItem?.representedObject as? String ?? ""
        let scope: KnowledgeScope = projectID.isEmpty ? .global : .project(projectID)
        let draft = KnowledgeMemoryDraft(title: normalizedTitle, text: normalizedText, scope: scope)
        saveGeneration += 1
        let generation = saveGeneration
        setSaving(true)
        guard let onSave else {
            setSaving(false)
            showValidation(KnowledgeCenterFailure.save.message, focus: titleField)
            return
        }
        var responded = false
        onSave(draft) { [weak self] result in
            guard let self,
                  !responded,
                  self.isSaving,
                  generation == self.saveGeneration else { return }
            responded = true
            switch result {
            case .success:
                break
            case .failure:
                self.setSaving(false)
                self.showValidation(KnowledgeCenterFailure.save.message, focus: self.bodyView)
            }
        }
    }

    @objc private func cancel(_ sender: Any?) {
        guard !isSaving else { return }
        saveGeneration += 1
        onCancel?()
    }

    private func showValidation(_ message: String, focus: NSResponder) {
        statusLabel.stringValue = message
        statusLabel.textColor = .systemRed
        statusLabel.isHidden = false
        window?.makeFirstResponder(focus)
    }

    private func setSaving(_ saving: Bool) {
        isSaving = saving
        titleField.isEnabled = !saving
        bodyView.isEditable = !saving
        scopePicker.isEnabled = !saving && existingNote == nil
        saveButton.isEnabled = !saving
        cancelButton.isEnabled = !saving
        statusLabel.stringValue = saving ? "Saving privately on this Mac…" : ""
        statusLabel.textColor = saving ? .secondaryLabelColor : .systemRed
        statusLabel.isHidden = false
    }
}

private final class KnowledgeItemCellView: NSTableCellView {
    private let icon = NSImageView()
    private let primary = NSTextField(labelWithString: "")
    private let secondary = NSTextField(labelWithString: "")

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        icon.imageScaling = .scaleProportionallyDown
        primary.font = .systemFont(ofSize: 13, weight: .medium)
        primary.lineBreakMode = .byTruncatingTail
        secondary.font = .systemFont(ofSize: 11)
        secondary.textColor = .secondaryLabelColor
        secondary.lineBreakMode = .byTruncatingTail
        secondary.maximumNumberOfLines = 2

        let labels = NSStackView(views: [primary, secondary])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 2
        labels.translatesAutoresizingMaskIntoConstraints = false
        icon.translatesAutoresizingMaskIntoConstraints = false
        addSubview(icon)
        addSubview(labels)
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 6),
            icon.centerYAnchor.constraint(equalTo: centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 20),
            icon.heightAnchor.constraint(equalToConstant: 20),
            labels.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 8),
            labels.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            labels.centerYAnchor.constraint(equalTo: centerYAnchor),
            primary.widthAnchor.constraint(equalTo: labels.widthAnchor),
            secondary.widthAnchor.constraint(equalTo: labels.widthAnchor)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(title: String, detail: String, symbolName: String, accent: NSColor) {
        primary.stringValue = title
        secondary.stringValue = detail
        primary.toolTip = title
        secondary.toolTip = detail
        icon.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)
        icon.contentTintColor = accent
    }
}

private final class KnowledgeStatusCardView: NSView {
    private let icon = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let valueLabel = NSTextField(labelWithString: "")

    var value: String {
        get { valueLabel.stringValue }
        set { valueLabel.stringValue = newValue }
    }

    init(symbolName: String, title: String, value: String, accent: NSColor) {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.cornerRadius = 10
        layer?.borderWidth = 1
        icon.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)
        icon.contentTintColor = accent
        icon.imageScaling = .scaleProportionallyDown
        titleLabel.stringValue = title.uppercased()
        titleLabel.font = .systemFont(ofSize: 9, weight: .bold)
        titleLabel.textColor = .secondaryLabelColor
        valueLabel.stringValue = value
        valueLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        valueLabel.lineBreakMode = .byTruncatingTail

        let labels = NSStackView(views: [titleLabel, valueLabel])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 3
        icon.translatesAutoresizingMaskIntoConstraints = false
        labels.translatesAutoresizingMaskIntoConstraints = false
        addSubview(icon)
        addSubview(labels)
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 14),
            icon.centerYAnchor.constraint(equalTo: centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 22),
            icon.heightAnchor.constraint(equalToConstant: 22),
            labels.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 10),
            labels.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            labels.centerYAnchor.constraint(equalTo: centerYAnchor),
            valueLabel.widthAnchor.constraint(equalTo: labels.widthAnchor)
        ])
        setAccessibilityElement(true)
        setAccessibilityRole(.group)
        setAccessibilityLabel(title)
        setAccessibilityValue(value)
        updateColors()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateColors()
    }

    private func updateColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.55).cgColor
            layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.65).cgColor
        }
    }
}
