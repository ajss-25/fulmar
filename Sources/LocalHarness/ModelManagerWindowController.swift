import AppKit

@MainActor
struct ModelManagerInteractions {
    var confirmCompatibilitySelection: (String) -> Bool

    static let live = ModelManagerInteractions { model in
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Use an unqualified local model?"
        alert.informativeText = "Fulmar will first verify that \(model) advertises completion, tool use, at least an 8K context, and no model-specific thinking mode. If it passes, every task uses fixed 8K context and 2K output limits. This model has not passed Fulmar's release qualification and some DeepSeek Harness agents may still behave differently."
        alert.addButton(withTitle: "Use Compatibility Mode")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

final class ModelManagerWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    enum SupportStatus: Equatable {
        case releaseQualified
        case compatibility
        case officialTagIdentityMismatch
        case duplicateCompatibilityTag

        var label: String {
            switch self {
            case .releaseQualified: return "Release-qualified"
            case .compatibility: return "Compatibility candidate"
            case .officialTagIdentityMismatch: return "Identity mismatch"
            case .duplicateCompatibilityTag: return "Duplicate tag"
            }
        }

        var help: String {
            switch self {
            case .releaseQualified:
                return "This is the exact immutable Qwen manifest qualified for Fulmar's performance profiles (identity \(BuiltInProviderDescriptors.qwenLocalModelManifestDigest.prefix(19))…)."
            case .compatibility:
                return "This is not release-qualified. Fulmar will verify its tool and context metadata before selection and again at startup, then use the fixed 8K context and 2K output compatibility profile."
            case .officialTagIdentityMismatch:
                return "This official Qwen tag is missing, duplicated, or does not match Fulmar's release-qualified immutable manifest. It cannot unlock the qualified profile."
            case .duplicateCompatibilityTag:
                return "Ollama returned more than one installed manifest for this tag. Fulmar cannot select it unambiguously. Remove the duplicate before using it for new tasks."
            }
        }
    }

    struct Row {
        let model: OllamaModel
        let running: OllamaRunningModel?
        let installedVariantCount: Int
        let supportStatus: SupportStatus

        var canSelectForNewTasks: Bool {
            installedVariantCount == 1
                && supportStatus != .officialTagIdentityMismatch
                && supportStatus != .duplicateCompatibilityTag
        }
    }

    private let client: OllamaClient
    private let activities: ActivityStore
    private let fetchModels: (@escaping (Result<[OllamaModel], Error>) -> Void) -> Void
    private let fetchRunningModels: (@escaping (Result<[OllamaRunningModel], Error>) -> Void) -> Void
    private let ensureLocalService: (@escaping (Result<Void, Error>) -> Void) -> Void
    private let currentSelection: () -> ModelSelection?
    private let useModelForNewTasks: (String, @escaping (Result<ModelSelection, Error>) -> Void) -> Void
    private let releaseModelMemory: (String, @escaping (Result<Void, Error>) -> Void) -> Void
    private let interactions: ModelManagerInteractions
    private let tableView = NSTableView()
    private let summary = NSTextField(labelWithString: "Checking Ollama…")
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let warmButton = NSButton(title: "Load", target: nil, action: nil)
    private let unloadButton = NSButton(title: "Unload", target: nil, action: nil)
    private let defaultButton = NSButton(title: "Use for New Tasks", target: nil, action: nil)
    private var rows: [Row] = []
    private enum ActiveOperation: Equatable {
        case preparing
        case refreshingModels
        case refreshingRunning
        case confirmingCompatibility(String)
        case selecting(String)
        case unloading(String)
    }
    private var activeOperation: ActiveOperation?
    private var operationGeneration: UInt64 = 0

    init(
        client: OllamaClient,
        activities: ActivityStore,
        ensureLocalService: @escaping (@escaping (Result<Void, Error>) -> Void) -> Void,
        currentSelection: @escaping () -> ModelSelection?,
        useModelForNewTasks: @escaping (String, @escaping (Result<ModelSelection, Error>) -> Void) -> Void,
        releaseModelMemory: @escaping (String, @escaping (Result<Void, Error>) -> Void) -> Void,
        fetchModels: ((@escaping (Result<[OllamaModel], Error>) -> Void) -> Void)? = nil,
        fetchRunningModels: ((@escaping (Result<[OllamaRunningModel], Error>) -> Void) -> Void)? = nil,
        interactions: ModelManagerInteractions? = nil
    ) {
        self.client = client
        self.activities = activities
        self.fetchModels = fetchModels ?? { completion in client.fetchModels(completion: completion) }
        self.fetchRunningModels = fetchRunningModels ?? { completion in client.fetchRunningModels(completion: completion) }
        self.ensureLocalService = ensureLocalService
        self.currentSelection = currentSelection
        self.useModelForNewTasks = useModelForNewTasks
        self.releaseModelMemory = releaseModelMemory
        self.interactions = interactions ?? .live
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 820, height: 500),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Local Models"
        window.subtitle = "Installed models and memory usage"
        window.minSize = NSSize(width: 680, height: 400)
        window.setFrameAutosaveName("LocalHarness.ModelManager")
        super.init(window: window)
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.ModelManager") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        prepareAndRefresh()
    }

    private func showPreparingLocalService() {
        rows = []
        tableView.reloadData()
        summary.stringValue = "Starting an isolated local-model service…"
        updateButtons()
    }

    private func showLocalServiceFailure() {
        rows = []
        tableView.reloadData()
        summary.stringValue = "Local models are unavailable. Confirm that the supported Ollama app is installed and can start, then choose Refresh."
        updateButtons()
    }

    private func prepareAndRefresh() {
        guard activeOperation == nil else { return }
        let generation = beginOperation(.preparing)
        showPreparingLocalService()
        ensureLocalService { [weak self] result in
            guard let self else { return }
            self.performOnMain {
                guard self.isCurrentOperation(.preparing, generation: generation) else { return }
                switch result {
                case .success:
                    self.activeOperation = .refreshingModels
                    self.showRefreshingCatalogue()
                    self.fetchCatalogue(generation: generation)
                case .failure:
                    self.finishOperation(.preparing, generation: generation)
                    self.showLocalServiceFailure()
                }
            }
        }
    }

    @discardableResult
    private func beginOperation(_ operation: ActiveOperation) -> UInt64 {
        operationGeneration &+= 1
        activeOperation = operation
        updateButtons()
        return operationGeneration
    }

    private func isCurrentOperation(_ operation: ActiveOperation, generation: UInt64) -> Bool {
        operationGeneration == generation && activeOperation == operation
    }

    private func finishOperation(_ operation: ActiveOperation, generation: UInt64) {
        guard isCurrentOperation(operation, generation: generation) else { return }
        activeOperation = nil
        updateButtons()
    }

    private func performOnMain(_ action: @escaping () -> Void) {
        if Thread.isMainThread {
            action()
        } else {
            DispatchQueue.main.async(execute: action)
        }
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()
        summary.font = .systemFont(ofSize: 13)
        summary.textColor = .secondaryLabelColor
        summary.setAccessibilityLabel("Local model status")
        summary.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(summary)

        for (identifier, title, width) in [("model", "Model", 245.0), ("profile", "Fulmar Support", 155.0), ("disk", "On Disk", 95.0), ("state", "State", 90.0), ("memory", "Memory", 105.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            tableView.addTableColumn(column)
        }
        tableView.delegate = self
        tableView.dataSource = self
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 30
        tableView.setAccessibilityLabel("Installed local models and memory state")
        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(scroll)

        for button in [refreshButton, warmButton, unloadButton, defaultButton] { button.bezelStyle = .rounded }
        refreshButton.target = self; refreshButton.action = #selector(refreshAction(_:))
        warmButton.title = "Loads automatically"
        warmButton.toolTip = "\(ProductBrand.displayName) loads the selected model on its first verified task. Manual preloading is disabled so it cannot evict a model during another task."
        unloadButton.target = self; unloadButton.action = #selector(unload(_:))
        defaultButton.target = self; defaultButton.action = #selector(makeDefault(_:))
        let actions = NSStackView(views: [refreshButton, NSView(), defaultButton, warmButton, unloadButton])
        actions.orientation = .horizontal
        actions.spacing = 8
        actions.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(actions)

        NSLayoutConstraint.activate([
            summary.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            summary.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            summary.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            scroll.topAnchor.constraint(equalTo: summary.bottomAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            actions.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            actions.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            actions.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            actions.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18)
        ])
        controller.view = root
        updateButtons()
        return controller
    }

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard rows.indices.contains(row), let tableColumn else { return nil }
        let item = rows[row]
        let field = NSTextField(labelWithString: "")
        switch tableColumn.identifier.rawValue {
        case "model":
            let isDefault = item.model.name == authoritativeLocalDefaultModel
            let suffix = isDefault ? "  · New tasks" : ""
            field.stringValue = item.model.name + suffix
            field.font = .systemFont(ofSize: 13, weight: isDefault ? .semibold : .regular)
            field.toolTip = item.installedVariantCount == 1
                ? item.model.name
                : "\(item.model.name) · \(item.installedVariantCount) installed manifests share this tag"
        case "profile":
            field.stringValue = item.supportStatus.label
            field.font = .systemFont(ofSize: 12.5, weight: .semibold)
            switch item.supportStatus {
            case .releaseQualified: field.textColor = .systemGreen
            case .compatibility: field.textColor = .secondaryLabelColor
            case .officialTagIdentityMismatch: field.textColor = .systemRed
            case .duplicateCompatibilityTag: field.textColor = .systemOrange
            }
            field.toolTip = item.supportStatus.help
            field.setAccessibilityHelp(item.supportStatus.help)
        case "disk":
            field.stringValue = item.installedVariantCount == 1
                ? ByteCountFormatter.string(fromByteCount: item.model.size, countStyle: .file)
                : "\(item.installedVariantCount) variants"
        case "state":
            field.stringValue = item.running == nil ? "Unloaded" : "Loaded"
            field.textColor = item.running == nil ? .secondaryLabelColor : .systemGreen
        case "memory":
            field.stringValue = item.running.map { ByteCountFormatter.string(fromByteCount: $0.sizeVRAM, countStyle: .memory) } ?? "—"
        default: break
        }
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateButtons() }

    private func showRefreshingCatalogue() {
        summary.stringValue = "Checking installed local models and memory use…"
        updateButtons()
    }

    private func fetchCatalogue(generation: UInt64) {
        fetchModels { [weak self] modelsResult in
            guard let self else { return }
            self.performOnMain {
                guard self.isCurrentOperation(.refreshingModels, generation: generation) else { return }
                switch modelsResult {
                case .failure:
                    self.finishCatalogueFailure(operation: .refreshingModels, generation: generation)
                case .success(let models):
                    self.activeOperation = .refreshingRunning
                    self.fetchRunningModels { [weak self] runningResult in
                        guard let self else { return }
                        self.performOnMain {
                            guard self.isCurrentOperation(.refreshingRunning, generation: generation) else { return }
                            switch runningResult {
                            case .success(let running):
                                self.activeOperation = nil
                                self.applyCatalogue(models: models, running: running)
                            case .failure:
                                self.finishCatalogueFailure(operation: .refreshingRunning, generation: generation)
                            }
                        }
                    }
                }
            }
        }
    }

    private func beginCatalogueRefresh() {
        guard activeOperation == nil else { return }
        let generation = beginOperation(.refreshingModels)
        showRefreshingCatalogue()
        fetchCatalogue(generation: generation)
    }

    private func finishCatalogueFailure(operation: ActiveOperation, generation: UInt64) {
        finishOperation(operation, generation: generation)
        rows = []
        tableView.reloadData()
        summary.stringValue = "Installed local models could not be refreshed. Confirm that Ollama is running, then try again."
        updateButtons()
    }

    private var selected: Row? {
        let index = tableView.selectedRow
        return rows.indices.contains(index) ? rows[index] : nil
    }

    private var authoritativeLocalDefaultModel: String? {
        guard let selection = currentSelection(),
              selection.route.provider == BuiltInProviderDescriptors.ollama.id else { return nil }
        return selection.route.model.rawValue
    }

    static func catalogueRows(
        models: [OllamaModel],
        running: [OllamaRunningModel]
    ) -> [Row] {
        var runningByName: [String: OllamaRunningModel] = [:]
        for candidate in running where OllamaModelNamePolicy.isSafe(candidate.name) {
            // A malformed duplicate `/api/ps` row must never trap through
            // Dictionary(uniqueKeysWithValues:). The largest reported memory
            // residency is the conservative single-tag presentation.
            if let current = runningByName[candidate.name], current.sizeVRAM >= candidate.sizeVRAM {
                continue
            }
            runningByName[candidate.name] = candidate
        }

        var modelsByName: [String: [OllamaModel]] = [:]
        for model in models where OllamaModelNamePolicy.isSafe(model.name) {
            modelsByName[model.name, default: []].append(model)
        }

        return modelsByName.keys.sorted {
            $0.localizedStandardCompare($1) == .orderedAscending
        }.compactMap { name in
            guard let variants = modelsByName[name], let representative = variants.first else { return nil }
            let status: SupportStatus
            if name == BuiltInProviderDescriptors.qwenLocalModel.id.rawValue {
                status = variants.count == 1
                    && representative.digest == BuiltInProviderDescriptors.qwenLocalModelManifestDigest
                    ? .releaseQualified
                    : .officialTagIdentityMismatch
            } else {
                status = variants.count == 1 ? .compatibility : .duplicateCompatibilityTag
            }
            return Row(
                model: representative,
                running: runningByName[name],
                installedVariantCount: variants.count,
                supportStatus: status
            )
        }
    }

    func applyCatalogue(models: [OllamaModel], running: [OllamaRunningModel]) {
        let selectedModelName = selected?.model.name
        rows = Self.catalogueRows(models: models, running: running)
        reloadTable(preservingModelName: selectedModelName)
        let loaded = rows.compactMap(\.running)
        let used = loaded.reduce(Int64(0)) { partial, item in
            let (value, overflow) = partial.addingReportingOverflow(item.sizeVRAM)
            return overflow ? Int64.max : value
        }
        if models.isEmpty {
            summary.stringValue = "No local models are installed. Install or pull a tool-capable model in the official Ollama app, then choose Refresh."
        } else if rows.count == models.count {
            summary.stringValue = "\(models.count) installed · \(loaded.count) loaded · \(ByteCountFormatter.string(fromByteCount: used, countStyle: .memory)) in model memory"
        } else {
            summary.stringValue = "\(rows.count) installed tags · \(models.count) manifests · resolve duplicate tags before selection"
        }
        updateButtons()
    }

    private func reloadTable(preservingModelName modelName: String?) {
        tableView.reloadData()
        guard let modelName,
              let row = rows.firstIndex(where: { $0.model.name == modelName }) else { return }
        tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
    }

    private func updateButtons() {
        let isIdle = activeOperation == nil
        refreshButton.isEnabled = isIdle
        tableView.isEnabled = isIdle
        warmButton.isEnabled = false
        unloadButton.isEnabled = isIdle && selected?.running != nil
        guard isIdle else {
            defaultButton.isEnabled = false
            return
        }
        guard let selected else {
            defaultButton.isEnabled = false
            defaultButton.title = "Use for New Tasks"
            defaultButton.toolTip = "Select one unambiguous installed model."
            return
        }
        defaultButton.isEnabled = selected.canSelectForNewTasks
            && selected.model.name != authoritativeLocalDefaultModel
        switch selected.supportStatus {
        case .compatibility:
            defaultButton.title = "Use Compatibility Mode"
            defaultButton.toolTip = "Verify text, tools and context metadata, then use fixed 8K/2K limits."
        case .releaseQualified:
            defaultButton.title = "Use for New Tasks"
            defaultButton.toolTip = "Use the release-qualified Qwen performance profile for new tasks."
        case .officialTagIdentityMismatch:
            defaultButton.title = "Identity Mismatch"
            defaultButton.toolTip = selected.supportStatus.help
        case .duplicateCompatibilityTag:
            defaultButton.title = "Resolve Duplicate Tag"
            defaultButton.toolTip = selected.supportStatus.help
        }
    }

    @objc private func refreshAction(_ sender: Any?) { prepareAndRefresh() }

    @objc private func warm(_ sender: Any?) {
        NSSound.beep()
    }

    @objc private func unload(_ sender: Any?) {
        guard activeOperation == nil, let model = selected?.model.name else { return }
        let generation = beginOperation(.unloading(model))
        summary.stringValue = "Releasing \(model) from local-model memory…"
        let activity = activities.begin(.model, title: "Unload \(model)", detail: "Releasing model memory.")
        releaseModelMemory(model) { [weak self] result in
            guard let self else { return }
            self.performOnMain {
                guard self.isCurrentOperation(.unloading(model), generation: generation) else { return }
                switch result {
                case .success:
                    self.activities.update(activity, state: .completed, detail: "Model memory released.", progress: 1)
                    self.activeOperation = nil
                    self.beginCatalogueRefresh()
                case .failure:
                    self.activities.update(activity, state: .failed, detail: "Model memory could not be released safely.")
                    self.finishOperation(.unloading(model), generation: generation)
                    self.summary.stringValue = "Model memory could not be released. The model remains available; try again after active local tasks finish."
                    self.updateButtons()
                }
            }
        }
    }

    @objc private func makeDefault(_ sender: Any?) {
        guard activeOperation == nil, let selected, selected.canSelectForNewTasks else {
            NSSound.beep()
            return
        }
        let model = selected.model.name
        if selected.supportStatus == .compatibility {
            let confirmationGeneration = beginOperation(.confirmingCompatibility(model))
            let confirmed = interactions.confirmCompatibilitySelection(model)
            guard isCurrentOperation(
                .confirmingCompatibility(model),
                generation: confirmationGeneration
            ) else { return }
            finishOperation(.confirmingCompatibility(model), generation: confirmationGeneration)
            guard confirmed else { return }
        }
        let generation = beginOperation(.selecting(model))
        summary.stringValue = "Verifying and switching new tasks to \(model)…"
        useModelForNewTasks(model) { [weak self] result in
            guard let self else { return }
            self.performOnMain {
                guard self.isCurrentOperation(.selecting(model), generation: generation) else { return }
                self.finishOperation(.selecting(model), generation: generation)
                switch result {
                case .success:
                    self.summary.stringValue = "\(model) is now the verified default for new agent, chat, and scheduled tasks."
                case .failure(let error):
                    self.summary.stringValue = ProviderSelectionFailurePresentation.message(for: error)
                }
                self.reloadTable(preservingModelName: model)
                self.updateButtons()
            }
        }
    }
}
