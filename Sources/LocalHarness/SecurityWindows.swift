import AppKit
import UniformTypeIdentifiers

enum PrivacyDashboardNotice: Equatable {
    case exportSucceeded(PrivacyLedgerExportResult)
    case exportFailed
    case clearFailed
}

struct PrivacyDashboardInteractions {
    let confirmClear: () -> Bool
    let chooseExportDestination: (_ format: PrivacyLedgerExportFormat, _ suggestedName: String) -> URL?
    let presentNotice: (PrivacyDashboardNotice) -> Void
    let runMaintenance: (_ work: @escaping () -> Void, _ completion: @escaping () -> Void) -> Void

    static let live = PrivacyDashboardInteractions(
        confirmClear: {
            let alert = NSAlert()
            alert.messageText = "Clear the Privacy Ledger?"
            alert.informativeText = "This permanently removes the event metadata shown here. It does not delete chats, prompts, attachments or Appshots."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Clear Ledger")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        chooseExportDestination: { format, suggestedName in
            let panel = NSSavePanel()
            panel.title = "Export Privacy Ledger"
            panel.nameFieldStringValue = suggestedName
            panel.allowedContentTypes = format == .json ? [.json] : [UTType(filenameExtension: "jsonl") ?? .plainText]
            guard panel.runModal() == .OK else { return nil }
            return panel.url
        },
        presentNotice: { notice in
            let alert = NSAlert()
            switch notice {
            case .exportSucceeded(let result):
                alert.messageText = "Privacy Ledger exported"
                alert.informativeText = "\(result.exported) valid events were exported with owner-only file permissions." +
                    (result.invalidSkipped == 0 ? "" : " \(result.invalidSkipped) unreadable rows were skipped and remain in the local ledger.")
            case .exportFailed:
                alert.messageText = "Privacy Ledger export failed"
                alert.informativeText = "No export was completed. The local Privacy Ledger was not changed."
                alert.alertStyle = .critical
            case .clearFailed:
                alert.messageText = "Privacy Ledger could not be cleared"
                alert.informativeText = "The ledger remains in place. Chats, prompts, attachments and Appshots were not changed."
                alert.alertStyle = .critical
            }
            alert.runModal()
        },
        runMaintenance: { work, completion in
            DispatchQueue.global(qos: .utility).async {
                work()
                DispatchQueue.main.async(execute: completion)
            }
        }
    )
}

final class PrivacyDashboardWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let ledger: PrivacyLedger
    private let preferences: PreferencesStore
    private let maintenance: PrivacyMaintenanceCoordinator
    private let interactions: PrivacyDashboardInteractions
    private let table = NSTableView()
    private let status = NSTextField(wrappingLabelWithString: "")
    private let countsLabel = NSTextField(wrappingLabelWithString: "")
    private let retentionLabel = NSTextField(wrappingLabelWithString: "")
    private let maintenanceLabel = NSTextField(wrappingLabelWithString: "")
    private let exportFormat = NSPopUpButton()
    private let exportButton = NSButton(title: "Export…", target: nil, action: nil)
    private let clearButton = NSButton(title: "Clear Ledger…", target: nil, action: nil)
    private let purgeButton = NSButton(title: "Purge Expired Data", target: nil, action: nil)
    private var events: [PrivacyEvent] = []

    init(
        ledger: PrivacyLedger,
        preferences: PreferencesStore,
        maintenance: PrivacyMaintenanceCoordinator,
        interactions: PrivacyDashboardInteractions = .live
    ) {
        self.ledger = ledger
        self.preferences = preferences
        self.maintenance = maintenance
        self.interactions = interactions
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 620), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Privacy Dashboard"
        window.subtitle = "What stayed local and what left the app"
        window.minSize = NSSize(width: 680, height: 520)
        window.setFrameAutosaveName("LocalHarness.PrivacyDashboard")
        super.init(window: window)
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.PrivacyDashboard") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) { refresh(); super.showWindow(sender) }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()
        status.font = .systemFont(ofSize: 15, weight: .semibold)
        status.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(status)
        countsLabel.textColor = .secondaryLabelColor
        countsLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(countsLabel)
        retentionLabel.textColor = .secondaryLabelColor
        retentionLabel.font = .systemFont(ofSize: 11)
        retentionLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(retentionLabel)
        maintenanceLabel.textColor = .secondaryLabelColor
        maintenanceLabel.font = .systemFont(ofSize: 11)
        maintenanceLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(maintenanceLabel)
        exportFormat.addItems(withTitles: ["JSON", "JSON Lines"])
        exportFormat.setAccessibilityLabel("Privacy Ledger export format")
        exportButton.target = self; exportButton.action = #selector(exportLedger(_:))
        clearButton.target = self; clearButton.action = #selector(clearLedger(_:))
        purgeButton.target = self; purgeButton.action = #selector(purgeExpiredData(_:))
        let actions = NSStackView(views: [exportFormat, exportButton, clearButton, NSView(), purgeButton])
        actions.orientation = .horizontal
        actions.spacing = 8
        actions.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(actions)
        for (id, title, width) in [("time", "Time", 130.0), ("event", "Event", 370.0), ("boundary", "Boundary", 110.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = title; column.width = width; table.addTableColumn(column)
        }
        table.delegate = self; table.dataSource = self; table.usesAlternatingRowBackgroundColors = true; table.rowHeight = 28
        table.setAccessibilityLabel("Privacy boundary events")
        let scroll = NSScrollView(); scroll.documentView = table; scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(scroll)
        let note = NSTextField(wrappingLabelWithString: "The ledger records categories and destinations, never prompt text, model output, secrets, or captured image content.")
        note.textColor = .secondaryLabelColor; note.font = .systemFont(ofSize: 11); note.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(note)
        NSLayoutConstraint.activate([
            status.topAnchor.constraint(equalTo: root.topAnchor, constant: 20), status.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20), status.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            countsLabel.topAnchor.constraint(equalTo: status.bottomAnchor, constant: 8), countsLabel.leadingAnchor.constraint(equalTo: status.leadingAnchor), countsLabel.trailingAnchor.constraint(equalTo: status.trailingAnchor),
            retentionLabel.topAnchor.constraint(equalTo: countsLabel.bottomAnchor, constant: 4), retentionLabel.leadingAnchor.constraint(equalTo: status.leadingAnchor), retentionLabel.trailingAnchor.constraint(equalTo: status.trailingAnchor),
            actions.topAnchor.constraint(equalTo: retentionLabel.bottomAnchor, constant: 12), actions.leadingAnchor.constraint(equalTo: status.leadingAnchor), actions.trailingAnchor.constraint(equalTo: status.trailingAnchor),
            maintenanceLabel.topAnchor.constraint(equalTo: actions.bottomAnchor, constant: 10), maintenanceLabel.leadingAnchor.constraint(equalTo: status.leadingAnchor), maintenanceLabel.trailingAnchor.constraint(equalTo: status.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: maintenanceLabel.bottomAnchor, constant: 12), scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20), scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            note.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 10), note.leadingAnchor.constraint(equalTo: scroll.leadingAnchor), note.trailingAnchor.constraint(equalTo: scroll.trailingAnchor), note.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])
        controller.view = root
        return controller
    }

    private func refresh() {
        events = ledger.recent()
        let counts = ledger.counts()
        status.stringValue = preferences.strictLocalMode ? "● Strict Local is active — Harness egress is blocked" : "● Network access is enabled — review non-local events below"
        status.textColor = preferences.strictLocalMode ? .systemGreen : .systemOrange
        if counts.storageIssue {
            countsLabel.stringValue = "The Privacy Ledger store could not be verified. No ledger data was read or purged."
            countsLabel.textColor = .systemRed
        } else {
            countsLabel.stringValue = "\(counts.valid) valid events · \(counts.local) stayed local · \(counts.external) left the app · \(counts.invalid) unreadable row\(counts.invalid == 1 ? "" : "s") retained"
            countsLabel.textColor = .secondaryLabelColor
        }
        retentionLabel.stringValue = "Automatic retention: Privacy Ledger \(PrivacyLedger.defaultRetentionDays) days · Appshots \(preferences.appshotRetentionDays) days · unreferenced attachments \(preferences.attachmentRetentionDays) days. Referenced or unverified attachments are never removed."
        maintenanceLabel.stringValue = maintenance.lastReport().map(Self.describe) ?? "No retention maintenance result is available yet."
        table.reloadData()
    }

    @objc private func clearLedger(_ sender: Any?) {
        guard interactions.confirmClear() else { return }
        do {
            try ledger.clear()
            refresh()
        } catch {
            interactions.presentNotice(.clearFailed)
        }
    }

    @objc private func exportLedger(_ sender: Any?) {
        let format: PrivacyLedgerExportFormat = exportFormat.indexOfSelectedItem == 1 ? .jsonl : .json
        let suggestedName = format == .json ? "\(ProductBrand.displayName) Privacy Ledger.json" : "\(ProductBrand.displayName) Privacy Ledger.jsonl"
        guard let destination = interactions.chooseExportDestination(format, suggestedName) else { return }
        do {
            let result = try ledger.export(to: destination, format: format)
            interactions.presentNotice(.exportSucceeded(result))
        } catch {
            interactions.presentNotice(.exportFailed)
        }
    }

    @objc private func purgeExpiredData(_ sender: Any?) {
        purgeButton.isEnabled = false
        clearButton.isEnabled = false
        exportButton.isEnabled = false
        maintenanceLabel.stringValue = "Inspecting retention stores…"
        interactions.runMaintenance({ [maintenance] in
            _ = maintenance.run(includeAttachments: true)
        }, { [weak self] in
            guard let self else { return }
            self.purgeButton.isEnabled = true
            self.clearButton.isEnabled = true
            self.exportButton.isEnabled = true
            self.refresh()
        })
    }

    func numberOfRows(in tableView: NSTableView) -> Int { events.count }
    func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
        guard events.indices.contains(row), let column else { return nil }
        let event = events[row]
        let field = NSTextField(labelWithString: "")
        switch column.identifier.rawValue {
        case "time": field.stringValue = Self.formatter.string(from: event.occurredAt); field.textColor = .secondaryLabelColor
        case "boundary": field.stringValue = event.localOnly ? "Stayed local" : "Left app"; field.textColor = event.localOnly ? .systemGreen : .systemOrange
        default:
            field.stringValue = PrivacyLedger.safeSummaryForDisplay(event.summary)
            field.toolTip = field.stringValue
        }
        return field
    }

    private static let formatter: DateFormatter = { let value = DateFormatter(); value.dateStyle = .short; value.timeStyle = .short; return value }()

    private static func describe(_ report: PrivacyMaintenanceReport) -> String {
        let appshots = "Appshots: \(report.appshots.removed) removed, \(report.appshots.retained) retained" +
            (report.appshots.failures == 0 ? "" : ", \(report.appshots.failures) failed")
        let ledger = report.ledger.failure ??
            "Ledger: \(report.ledger.removed) expired removed, \(report.ledger.retained) retained" +
            (report.ledger.invalidRetained == 0 ? "" : " (including \(report.ledger.invalidRetained) unreadable)")
        let attachments: String
        switch report.attachments.status {
        case .completed:
            attachments = "Attachments: \(report.attachments.deleted) unreferenced expired removed, \(report.attachments.referenced) referenced and \(report.attachments.retained - report.attachments.referenced) other retained"
        case .noStore:
            attachments = "Attachments: no app-owned attachment store exists yet"
        case .deferred(let reason), .unsupported(let reason), .failed(let reason):
            attachments = "Attachments: \(reason)"
        }
        return "\(appshots) · \(ledger) · \(attachments)"
    }
}

final class PluginTrustWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate {
    final class OperationCancellation: @unchecked Sendable {
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

    struct Operations {
        let findings: @MainActor (
            _ completion: @escaping @MainActor (Result<[PluginTrustFinding], Error>) -> Void
        ) -> OperationCancellation
        let revoke: @MainActor (
            _ name: String,
            _ completion: @escaping @MainActor (Result<Void, Error>) -> Void
        ) -> OperationCancellation

        init(
            findings: @escaping @MainActor (@escaping @MainActor (Result<[PluginTrustFinding], Error>) -> Void) -> OperationCancellation,
            revoke: @escaping @MainActor (String, @escaping @MainActor (Result<Void, Error>) -> Void) -> OperationCancellation
        ) {
            self.findings = findings
            self.revoke = revoke
        }

        init(controller: HarnessController) {
            let queue = DispatchQueue(label: "app.fulmar.plugin-trust", qos: .userInitiated)
            findings = { completion in
                Self.run(on: queue, work: { controller.pluginFindings() }, completion: completion)
            }
            revoke = { name, completion in
                Self.run(on: queue, work: { try controller.revokePlugin(name: name) }, completion: completion)
            }
        }

        private static func run<Value>(
            on queue: DispatchQueue,
            work: @escaping () throws -> Value,
            completion: @escaping @MainActor (Result<Value, Error>) -> Void
        ) -> OperationCancellation {
            let cancellation = OperationCancellation()
            queue.async {
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

    enum Notice: Equatable {
        case communityDisabled
        case revoked(String)
        case failure
    }

    struct Interactions {
        let confirmRevoke: @MainActor (
            _ safePluginName: String,
            _ parent: NSWindow,
            _ completion: @escaping @MainActor (Bool) -> Void
        ) -> Void
        let presentNotice: @MainActor (_ notice: Notice, _ parent: NSWindow?) -> Void

        static let live = Interactions(
            confirmRevoke: { safeName, parent, completion in
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "Remove legacy approval for “\(safeName)”?"
                alert.informativeText = "The plugin will be blocked by the production policy. Its files are not deleted."
                alert.addButton(withTitle: "Remove Approval")
                alert.addButton(withTitle: "Cancel")
                alert.beginSheetModal(for: parent) { response in
                    completion(response == .alertFirstButtonReturn)
                }
            },
            presentNotice: { notice, parent in
                let alert = NSAlert()
                switch notice {
                case .communityDisabled:
                    alert.messageText = "Community plugins are disabled"
                    alert.informativeText = "This production profile accepts only plugins bundled and signed with \(ProductBrand.displayName). External plugin approval is intentionally unavailable."
                    alert.alertStyle = .informational
                case .revoked(let safeName):
                    alert.messageText = "Legacy approval removed"
                    alert.informativeText = "“\(safeName)” is now blocked by the production policy. Restart the agent service before relying on the new decision."
                    alert.alertStyle = .informational
                case .failure:
                    alert.messageText = "Plugin trust needs attention"
                    alert.informativeText = "The plugin trust decision could not be verified or changed safely. No partial result was applied."
                    alert.alertStyle = .warning
                }
                if let parent { alert.beginSheetModal(for: parent) }
            }
        )
    }

    private let operations: Operations
    private let interactions: Interactions
    private let table = NSTableView()
    private let summary = NSTextField(wrappingLabelWithString: "")
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let approve = NSButton(title: "Community Plugins Disabled", target: nil, action: nil)
    private let revoke = NSButton(title: "Remove Legacy Approval", target: nil, action: nil)
    private var findings: [PluginTrustFinding] = []
    private var generation = 0
    private var activeOperation: OperationCancellation?
    private var busy = false
    private static let maximumDisplayedFindings = 512

    convenience init(controller: HarnessController) {
        self.init(operations: Operations(controller: controller))
    }

    init(operations: Operations, interactions: Interactions = .live) {
        self.operations = operations
        self.interactions = interactions
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 780, height: 500), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Plugin Trust"
        window.subtitle = "Production policy allows bundled plugins only"
        window.minSize = NSSize(width: 650, height: 400)
        window.setFrameAutosaveName("LocalHarness.PluginTrust")
        super.init(window: window)
        window.delegate = self
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.PluginTrust") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func showWindow(_ sender: Any?) { super.showWindow(sender); prepareAuditForPresentation() }

    func windowWillClose(_ notification: Notification) {
        activeOperation?.cancel()
        activeOperation = nil
        generation += 1
        busy = false
        findings = []
        table.reloadData()
        summary.stringValue = "Plugin trust review closed."
        updateButtons()
    }

    private func buildContent() -> NSViewController {
        let vc = NSViewController(); let root = NSView()
        summary.translatesAutoresizingMaskIntoConstraints = false
        summary.maximumNumberOfLines = 3
        summary.preferredMaxLayoutWidth = 610
        summary.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        summary.setAccessibilityLabel("Plugin trust status")
        root.addSubview(summary)
        for (id, title, width) in [("plugin", "Plugin", 330.0), ("version", "Version", 130.0), ("trust", "Trust", 130.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = title; column.width = width; table.addTableColumn(column)
        }
        table.delegate = self; table.dataSource = self; table.rowHeight = 28; table.usesAlternatingRowBackgroundColors = true; table.allowsMultipleSelection = false
        table.setAccessibilityLabel("Plugin trust decisions")
        let scroll = NSScrollView(); scroll.documentView = table; scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(scroll)
        refreshButton.target = self; refreshButton.action = #selector(refreshSelected(_:)); approve.target = self; approve.action = #selector(approveSelected(_:)); revoke.target = self; revoke.action = #selector(revokeSelected(_:))
        let actions = NSStackView(views: [refreshButton, NSView(), revoke, approve]); actions.orientation = .horizontal; actions.spacing = 8; actions.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(actions)
        NSLayoutConstraint.activate([
            summary.topAnchor.constraint(equalTo: root.topAnchor, constant: 18), summary.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20), summary.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            scroll.topAnchor.constraint(equalTo: summary.bottomAnchor, constant: 12), scroll.leadingAnchor.constraint(equalTo: summary.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: summary.trailingAnchor),
            actions.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12), actions.leadingAnchor.constraint(equalTo: scroll.leadingAnchor), actions.trailingAnchor.constraint(equalTo: scroll.trailingAnchor), actions.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])
        vc.view = root; updateButtons(); return vc
    }

    func prepareAuditForPresentation() {
        activeOperation?.cancel()
        generation += 1
        let currentGeneration = generation
        let selectedID = selected?.id
        busy = true
        table.isEnabled = false
        findings = []
        table.reloadData()
        summary.stringValue = "Auditing the isolated plugin profile…"
        summary.textColor = .secondaryLabelColor
        updateButtons()
        activeOperation = operations.findings { [weak self] result in
            guard let self,
                  currentGeneration == self.generation,
                  self.activeOperation != nil else { return }
            self.activeOperation = nil
            self.busy = false
            switch result {
            case .success(let findings):
                guard findings.count <= Self.maximumDisplayedFindings,
                      findings.allSatisfy({ !$0.id.isEmpty && $0.id.utf8.count <= 512 }),
                      Set(findings.map(\.id)).count == findings.count else {
                    self.presentAuditFailure()
                    return
                }
                self.findings = findings
                self.table.reloadData()
                if let selectedID, let row = findings.firstIndex(where: { $0.id == selectedID }) {
                    self.table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
                }
                self.presentSummary()
            case .failure:
                self.presentAuditFailure()
                return
            }
            self.table.isEnabled = true
            self.updateButtons()
        }
    }

    private func presentSummary() {
        let blocked = findings.filter { $0.status == .blocked }.count
        summary.stringValue = blocked == 0
            ? "Only plugins bundled and signed with \(ProductBrand.displayName) may run. Community plugin installation and approval are disabled in this build."
            : "\(blocked) external plugin\(blocked == 1 ? " is" : "s are") blocked. Remove \(blocked == 1 ? "it" : "them") from the isolated Harness profile before restarting."
        summary.textColor = blocked == 0 ? .systemGreen : .systemOrange
    }

    private func presentAuditFailure() {
        findings = []
        table.reloadData()
        summary.stringValue = "Plugin trust could not be audited safely. No partial decisions are shown."
        summary.textColor = .systemRed
        table.isEnabled = true
        updateButtons()
        interactions.presentNotice(.failure, window)
    }
    func numberOfRows(in tableView: NSTableView) -> Int { findings.count }
    func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
        guard findings.indices.contains(row), let column else { return nil }; let item = findings[row]; let field = NSTextField(labelWithString: "")
        switch column.identifier.rawValue {
        case "version": field.stringValue = Self.safeText(item.declaredVersion, fallback: "Unknown", limit: 80); field.textColor = .secondaryLabelColor
        case "trust": field.stringValue = item.status == .builtIn ? "Built in" : item.status.rawValue.capitalized; field.textColor = item.status == .blocked ? .systemOrange : .systemGreen
        default: field.stringValue = Self.safeText(item.name, fallback: "Unnamed plugin", limit: 160)
        }
        field.lineBreakMode = .byTruncatingTail
        field.toolTip = field.stringValue
        return field
    }
    func tableViewSelectionDidChange(_ notification: Notification) { updateButtons() }
    private var selected: PluginTrustFinding? { findings.indices.contains(table.selectedRow) ? findings[table.selectedRow] : nil }
    private func updateButtons() {
        approve.isEnabled = false
        refreshButton.isEnabled = !busy
        revoke.isEnabled = !busy
            && selected?.status == .approved
            && selected.map { Self.isValidOperationName($0.name) } == true
        table.isEnabled = !busy
    }
    @objc private func approveSelected(_ sender: Any?) {
        guard !busy else { return }
        interactions.presentNotice(.communityDisabled, window)
    }
    @objc private func refreshSelected(_ sender: Any?) {
        guard !busy else { return }
        prepareAuditForPresentation()
    }
    @objc private func revokeSelected(_ sender: Any?) {
        guard !busy,
              let selected,
              selected.status == .approved,
              Self.isValidOperationName(selected.name),
              let parent = window else { return }
        generation += 1
        let currentGeneration = generation
        busy = true
        updateButtons()
        var responded = false
        interactions.confirmRevoke(Self.safeText(selected.name, fallback: "Unnamed plugin", limit: 160), parent) { [weak self] confirmed in
            guard let self,
                  !responded,
                  currentGeneration == self.generation,
                  self.busy else { return }
            responded = true
            guard confirmed else {
                self.busy = false
                self.updateButtons()
                return
            }
            self.summary.stringValue = "Removing the legacy approval…"
            self.summary.textColor = .secondaryLabelColor
            self.activeOperation = self.operations.revoke(selected.name) { [weak self] result in
                guard let self,
                      currentGeneration == self.generation,
                      self.busy,
                      self.activeOperation != nil else { return }
                self.activeOperation = nil
                self.busy = false
                switch result {
                case .success:
                    self.interactions.presentNotice(
                        .revoked(Self.safeText(selected.name, fallback: "Unnamed plugin", limit: 160)),
                        self.window
                    )
                    self.prepareAuditForPresentation()
                case .failure:
                    self.summary.stringValue = "The legacy approval was not removed. The existing trust decision remains unchanged."
                    self.summary.textColor = .systemRed
                    self.interactions.presentNotice(.failure, self.window)
                    self.updateButtons()
                }
            }
        }
    }

    private static func safeText(_ value: String, fallback: String, limit: Int) -> String {
        let flattened = String(value.unicodeScalars.map { scalar in
            CharacterSet.controlCharacters.contains(scalar) ? " " : Character(scalar)
        })
        let collapsed = flattened.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
        return collapsed.isEmpty ? fallback : String(collapsed.prefix(limit))
    }

    private static func isValidOperationName(_ value: String) -> Bool {
        guard !value.isEmpty,
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              value.utf8.count <= 512,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            return false
        }
        return true
    }
}

final class StateBackupWindowOperationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var activeOperation: UUID?

    func begin(_ operationID: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard activeOperation == nil else { return false }
        activeOperation = operationID
        return true
    }

    func owns(_ operationID: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return activeOperation == operationID
    }

    @discardableResult
    func finish(_ operationID: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard activeOperation == operationID else { return false }
        activeOperation = nil
        return true
    }

    var isIdle: Bool {
        lock.lock()
        defer { lock.unlock() }
        return activeOperation == nil
    }
}

enum BackupWindowConfirmation: Equatable {
    case authorizeExistingKey
    case restore(UUID)
    case delete(UUID)
}

enum BackupWindowNotice: Equatable {
    case protectedTransitionUnavailable
    case authorizationFailed
    case acquireFailed(StateBackupProtectedOperation)
    case createFailed
    case restoreFailed
    case deleteFailed
}

struct BackupWindowInteractions {
    let confirm: (BackupWindowConfirmation) -> Bool
    let presentNotice: (BackupWindowNotice) -> Void

    static let live = BackupWindowInteractions(
        confirm: { confirmation in
            let alert = NSAlert()
            alert.alertStyle = .warning
            switch confirmation {
            case .authorizeExistingKey:
                alert.messageText = "Authorize the existing backup key?"
                alert.informativeText = "macOS may ask for your approval. Fulmar will read only the exact existing backup-authentication key, verify it against your authenticated backup catalog, and keep it in memory for this app session. It will not replace or delete any Keychain item."
                alert.addButton(withTitle: "Authorize Existing Key")
            case .restore:
                alert.messageText = "Restore this authenticated Harness backup?"
                alert.informativeText = "Local services must stop completely before state changes. The current state is retained in a private recovery quarantine until you confirm the restored runtime is healthy."
                alert.addButton(withTitle: "Stop, Restore and Restart")
            case .delete:
                alert.messageText = "Permanently delete this authenticated backup?"
                alert.informativeText = "The backup will be removed with a crash-safe authenticated catalog transaction. This cannot be undone."
                alert.addButton(withTitle: "Delete Backup")
            }
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        presentNotice: { notice in
            let alert = NSAlert()
            alert.alertStyle = .critical
            switch notice {
            case .protectedTransitionUnavailable:
                alert.messageText = "Protected backup transition unavailable"
                alert.informativeText = "\(ProductBrand.displayName) refused to read or replace live Harness state because it could not first close agent admissions and stop every exact owned service."
            case .authorizationFailed:
                alert.messageText = "Backup-key authorization did not complete"
                alert.informativeText = "The existing backup key was not admitted. No Keychain item was replaced or deleted."
            case .acquireFailed:
                alert.messageText = "Protected backup transition did not start"
                alert.informativeText = "Agent admissions and local-service state could not be verified, so no backup state was read or changed."
            case .createFailed:
                alert.messageText = "Backup did not complete"
                alert.informativeText = "No incomplete snapshot was admitted to the authenticated backup catalog."
            case .restoreFailed:
                alert.messageText = "Restore did not complete"
                alert.informativeText = "The protected restore did not complete. Fulmar did not report the replacement state as healthy."
            case .deleteFailed:
                alert.messageText = "Backup was not deleted"
                alert.informativeText = "The selected authenticated backup remains in the catalog."
            }
            alert.runModal()
        }
    )
}

struct BackupWindowOperations {
    let validatedListAsync: @MainActor (@escaping @MainActor (Result<[StateBackup], Error>) -> Void) -> StateBackupOperationCancellation
    let canAuthorizeAuthenticationKeyForForeground: @MainActor () -> Bool
    let authorizeAuthenticationKeyForForegroundAsync: @MainActor (@escaping @MainActor (Result<Void, Error>) -> Void) -> StateBackupOperationCancellation
    let createAsync: @MainActor (
        _ label: String,
        _ sourceVersion: String,
        _ permit: StateBackupQuiescencePermit,
        _ completion: @escaping @MainActor (Result<StateBackup, Error>) -> Void
    ) -> StateBackupOperationCancellation
    let restoreAsync: @MainActor (
        _ backup: StateBackup,
        _ permit: StateBackupQuiescencePermit,
        _ completion: @escaping @MainActor (Result<StateBackupRestoreReport, Error>) -> Void
    ) -> StateBackupOperationCancellation
    let deleteAsync: @MainActor (
        _ backup: StateBackup,
        _ completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> StateBackupOperationCancellation

    init(manager: StateBackupManager) {
        validatedListAsync = { manager.validatedListAsync(completion: $0) }
        canAuthorizeAuthenticationKeyForForeground = { manager.canAuthorizeAuthenticationKeyForForeground }
        authorizeAuthenticationKeyForForegroundAsync = {
            manager.authorizeAuthenticationKeyForForegroundAsync(completion: $0)
        }
        createAsync = { label, sourceVersion, permit, completion in
            manager.createAsync(
                label: label,
                sourceVersion: sourceVersion,
                permit: permit,
                completion: completion
            )
        }
        restoreAsync = { backup, permit, completion in
            manager.restoreAsync(backup, permit: permit, completion: completion)
        }
        deleteAsync = { backup, completion in
            manager.deleteAsync(backup, completion: completion)
        }
    }

    init(
        validatedListAsync: @escaping @MainActor (@escaping @MainActor (Result<[StateBackup], Error>) -> Void) -> StateBackupOperationCancellation,
        canAuthorizeAuthenticationKeyForForeground: @escaping @MainActor () -> Bool,
        authorizeAuthenticationKeyForForegroundAsync: @escaping @MainActor (@escaping @MainActor (Result<Void, Error>) -> Void) -> StateBackupOperationCancellation,
        createAsync: @escaping @MainActor (
            String,
            String,
            StateBackupQuiescencePermit,
            @escaping @MainActor (Result<StateBackup, Error>) -> Void
        ) -> StateBackupOperationCancellation,
        restoreAsync: @escaping @MainActor (
            StateBackup,
            StateBackupQuiescencePermit,
            @escaping @MainActor (Result<StateBackupRestoreReport, Error>) -> Void
        ) -> StateBackupOperationCancellation,
        deleteAsync: @escaping @MainActor (
            StateBackup,
            @escaping @MainActor (Result<Void, Error>) -> Void
        ) -> StateBackupOperationCancellation
    ) {
        self.validatedListAsync = validatedListAsync
        self.canAuthorizeAuthenticationKeyForForeground = canAuthorizeAuthenticationKeyForForeground
        self.authorizeAuthenticationKeyForForegroundAsync = authorizeAuthenticationKeyForForegroundAsync
        self.createAsync = createAsync
        self.restoreAsync = restoreAsync
        self.deleteAsync = deleteAsync
    }
}

final class BackupWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    static let privacyDisclosure = "Backups are integrity-authenticated, not encrypted. They may contain chats, attachments, and durable tool-output spills. Keychain values and known secret paths are excluded. Keep backup files private."

    /// Both callbacks are mandatory for every source-state mutation. There is
    /// intentionally no production fallback: a snapshot or restore without an
    /// application-wide quiescence permit would be cross-file incoherent.
    var onAcquireProtectedTransition: AcquireStateBackupTransition?
    var onFinishProtectedTransition: FinishStateBackupTransition?
    var onRestoreCompleted: ((StateBackupRestoreReport) -> Void)?
    private let operations: BackupWindowOperations
    private let runtimeVersion: () -> String
    private let interactions: BackupWindowInteractions
    private let table = NSTableView()
    private let status = NSTextField(labelWithString: "")
    private let privacyDisclosureLabel = NSTextField(
        wrappingLabelWithString: BackupWindowController.privacyDisclosure
    )
    private let refreshButton = NSButton(title: "Reload", target: nil, action: nil)
    private let createButton = NSButton(title: "Create Backup", target: nil, action: nil)
    private let restoreButton = NSButton(title: "Restore Selected…", target: nil, action: nil)
    private let deleteButton = NSButton(title: "Delete Selected…", target: nil, action: nil)
    private let authorizeButton = NSButton(title: "Authorize Backup Key…", target: nil, action: nil)
    private var backups: [StateBackup] = []
    private var backupKeyAuthorizationRequired = false
    private var activeCancellation: StateBackupOperationCancellation?
    private let operationGate = StateBackupWindowOperationGate()
    private enum OperationState: Equatable {
        case idle
        case loading(UUID)
        case authorizing(UUID)
        case acquiring(UUID)
        case creating(UUID)
        case restoring(UUID)
        case deleting(UUID)
        case finishing(UUID)
        case unavailable
    }
    private var operationState: OperationState = .idle

    convenience init(
        manager: StateBackupManager,
        runtimeVersion: @escaping () -> String,
        interactions: BackupWindowInteractions = .live
    ) {
        self.init(
            operations: BackupWindowOperations(manager: manager),
            runtimeVersion: runtimeVersion,
            interactions: interactions
        )
    }

    init(
        operations: BackupWindowOperations,
        runtimeVersion: @escaping () -> String,
        interactions: BackupWindowInteractions = .live
    ) {
        self.operations = operations
        self.runtimeVersion = runtimeVersion
        self.interactions = interactions
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 460), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Backups & Restore"; window.subtitle = "Recover Harness sessions, settings and attachments"; window.minSize = NSSize(width: 600, height: 360); window.setFrameAutosaveName("LocalHarness.Backups")
        super.init(window: window); window.contentViewController = buildContent(); if !window.setFrameUsingName("LocalHarness.Backups") { window.center() }
    }
    @available(*, unavailable) required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func showWindow(_ sender: Any?) { refresh(); super.showWindow(sender) }
    private func buildContent() -> NSViewController {
        let vc = NSViewController(); let root = NSView(); status.textColor = .secondaryLabelColor; status.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(status)
        privacyDisclosureLabel.font = .systemFont(ofSize: 11)
        privacyDisclosureLabel.textColor = .secondaryLabelColor
        privacyDisclosureLabel.maximumNumberOfLines = 3
        privacyDisclosureLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        privacyDisclosureLabel.setAccessibilityLabel("Backup privacy and protection")
        privacyDisclosureLabel.setAccessibilityHelp(Self.privacyDisclosure)
        privacyDisclosureLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(privacyDisclosureLabel)
        for (id, title, width) in [("date", "Created", 170.0), ("label", "Backup", 300.0), ("version", "Harness", 120.0)] { let c = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); c.title = title; c.width = width; table.addTableColumn(c) }
        table.delegate = self; table.dataSource = self; table.rowHeight = 28; table.usesAlternatingRowBackgroundColors = true
        table.setAccessibilityLabel("Fulmar state backups")
        let scroll = NSScrollView(); scroll.documentView = table; scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(scroll)
        createButton.target = self; createButton.action = #selector(createBackup(_:)); refreshButton.target = self; refreshButton.action = #selector(refreshBackups(_:)); restoreButton.target = self; restoreButton.action = #selector(restore(_:)); deleteButton.target = self; deleteButton.action = #selector(deleteSelected(_:)); authorizeButton.target = self; authorizeButton.action = #selector(authorizeBackupKey(_:)); authorizeButton.setAccessibilityLabel("Authorize the existing backup key in macOS Keychain"); let actions = NSStackView(views: [createButton, refreshButton, authorizeButton, NSView(), deleteButton, restoreButton]); actions.orientation = .horizontal; actions.spacing = 10; actions.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(actions)
        NSLayoutConstraint.activate([
            status.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            status.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            status.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            privacyDisclosureLabel.topAnchor.constraint(equalTo: status.bottomAnchor, constant: 8),
            privacyDisclosureLabel.leadingAnchor.constraint(equalTo: status.leadingAnchor),
            privacyDisclosureLabel.trailingAnchor.constraint(equalTo: status.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: privacyDisclosureLabel.bottomAnchor, constant: 10),
            scroll.leadingAnchor.constraint(equalTo: status.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: status.trailingAnchor),
            actions.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            actions.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            actions.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            actions.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])
        vc.view = root
        updateButtons()
        return vc
    }
    private func refresh() {
        switch operationState {
        case .idle, .unavailable: break
        case .loading(let previous):
            activeCancellation?.cancel()
            _ = operationGate.finish(previous)
        case .authorizing, .acquiring, .creating, .restoring, .deleting, .finishing: return
        }
        let operationID = UUID()
        guard operationGate.begin(operationID) else { return }
        operationState = .loading(operationID)
        status.textColor = .secondaryLabelColor
        status.stringValue = "Loading and authenticating local backups…"
        backupKeyAuthorizationRequired = false
        updateButtons()
        activeCancellation = operations.validatedListAsync { [weak self] result in
            guard let self, self.operationState == .loading(operationID) else { return }
            guard self.operationGate.finish(operationID) else { return }
            self.activeCancellation = nil
            switch result {
            case .success(let backups):
                self.operationState = .idle
                self.backups = backups
                self.status.textColor = .secondaryLabelColor
                self.status.stringValue = backups.isEmpty
                    ? "No authenticated backups yet."
                    : "\(backups.count) authenticated local backup\(backups.count == 1 ? "" : "s")"
            case .failure(let error):
                self.operationState = .unavailable
                self.backups = []
                if case .authenticationAuthorizationRequired = error as? BackupError {
                    self.backupKeyAuthorizationRequired = true
                }
                self.status.textColor = .systemRed
                self.status.stringValue = self.backupKeyAuthorizationRequired
                    ? "Backups are unavailable until macOS authorizes the existing backup key."
                    : "Backups are unavailable because the authenticated catalog could not be verified."
            }
            self.table.reloadData()
            self.updateButtons()
        }
    }
    private var isIdle: Bool {
        operationState == .idle && operationGate.isIdle
    }
    private var selectedBackup: StateBackup? {
        backups.indices.contains(table.selectedRow) ? backups[table.selectedRow] : nil
    }
    private func failClosedForMissingCoordinator() {
        operationState = .unavailable
        status.textColor = .systemRed
        status.stringValue = "Backups are unavailable because the protected runtime transition coordinator is not connected."
        table.reloadData()
        updateButtons()
        interactions.presentNotice(.protectedTransitionUnavailable)
    }
    private func updateButtons() {
        createButton.isEnabled = isIdle
        table.isEnabled = isIdle
        restoreButton.isEnabled = isIdle && selectedBackup != nil
        deleteButton.isEnabled = isIdle && selectedBackup != nil
        refreshButton.isEnabled = isIdle || operationState == .unavailable
        authorizeButton.isHidden = !backupKeyAuthorizationRequired
        authorizeButton.isEnabled = operationState == .unavailable
            && operationGate.isIdle
            && backupKeyAuthorizationRequired
            && operations.canAuthorizeAuthenticationKeyForForeground()
    }
    func numberOfRows(in tableView: NSTableView) -> Int { backups.count }
    func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? { guard backups.indices.contains(row), let column else { return nil }; let item = backups[row]; let field = NSTextField(labelWithString: ""); switch column.identifier.rawValue { case "date": field.stringValue = Self.formatter.string(from: item.createdAt); case "version": field.stringValue = item.sourceVersion; default: field.stringValue = item.label }; return field }
    func tableViewSelectionDidChange(_ notification: Notification) { updateButtons() }
    @objc private func refreshBackups(_ sender: Any?) { refresh() }
    @objc private func authorizeBackupKey(_ sender: Any?) {
        guard operationState == .unavailable,
              operationGate.isIdle,
              backupKeyAuthorizationRequired,
              operations.canAuthorizeAuthenticationKeyForForeground() else { return }
        guard interactions.confirm(.authorizeExistingKey) else { return }

        let operationID = UUID()
        guard operationGate.begin(operationID) else { return }
        operationState = .authorizing(operationID)
        status.textColor = .secondaryLabelColor
        status.stringValue = "Waiting for macOS to authorize the existing backup key…"
        updateButtons()
        activeCancellation = operations.authorizeAuthenticationKeyForForegroundAsync { [weak self] result in
            guard let self, self.operationState == .authorizing(operationID) else { return }
            guard self.operationGate.finish(operationID) else { return }
            self.activeCancellation = nil
            switch result {
            case .success:
                self.operationState = .idle
                self.backupKeyAuthorizationRequired = false
                self.refresh()
            case .failure(let error):
                self.operationState = .unavailable
                self.backupKeyAuthorizationRequired = false
                if case .authenticationAuthorizationRequired = error as? BackupError {
                    self.backupKeyAuthorizationRequired = true
                }
                self.status.textColor = .systemRed
                self.status.stringValue = "Backup-key authorization did not complete. No Keychain item was changed."
                self.updateButtons()
                self.interactions.presentNotice(.authorizationFailed)
            }
        }
    }
    @objc private func createBackup(_ sender: Any?) {
        guard isIdle else { return }
        guard let acquire = onAcquireProtectedTransition,
              let finish = onFinishProtectedTransition else {
            failClosedForMissingCoordinator()
            return
        }
        let operationID = UUID()
        guard operationGate.begin(operationID) else { return }
        let version = runtimeVersion()
        operationState = .acquiring(operationID)
        status.textColor = .secondaryLabelColor
        status.stringValue = "Closing agent admissions and stopping local services…"
        updateButtons()
        acquire(.manualCreate) { [weak self] result in
            guard let self, self.operationState == .acquiring(operationID) else { return }
            switch result {
            case .failure:
                _ = self.operationGate.finish(operationID)
                self.operationState = .idle
                self.status.stringValue = "Backup was not started."
                self.updateButtons()
                self.interactions.presentNotice(.acquireFailed(.manualCreate))
            case .success(let permit):
                self.operationState = .creating(operationID)
                self.status.stringValue = "Creating a coherent authenticated snapshot off the main thread…"
                self.activeCancellation = self.operations.createAsync(
                    "Manual backup",
                    version,
                    permit
                ) { [weak self] result in
                    self?.finishProtected(
                        operationID: operationID,
                        permit: permit,
                        result: result,
                        finish: finish
                    ) { [weak self] settled in
                        guard let self else { return }
                        switch settled {
                        case .success:
                            self.refresh()
                        case .failure:
                            self.status.stringValue = "Backup did not complete."
                            self.updateButtons()
                            self.interactions.presentNotice(.createFailed)
                        }
                    }
                }
            }
        }
    }
    @objc private func restore(_ sender: Any?) {
        guard isIdle, let backup = selectedBackup else { return }
        guard let acquire = onAcquireProtectedTransition,
              let finish = onFinishProtectedTransition else {
            failClosedForMissingCoordinator()
            return
        }
        guard interactions.confirm(.restore(backup.id)) else { return }

        let operationID = UUID()
        guard operationGate.begin(operationID) else { return }
        operationState = .acquiring(operationID)
        status.stringValue = "Closing agent admissions and stopping every exact local service…"
        updateButtons()
        acquire(.restore(backup.id)) { [weak self] result in
            guard let self, self.operationState == .acquiring(operationID) else { return }
            switch result {
            case .failure:
                _ = self.operationGate.finish(operationID)
                self.operationState = .idle
                self.status.stringValue = "Restore was not started."
                self.updateButtons()
                self.interactions.presentNotice(.acquireFailed(.restore(backup.id)))
            case .success(let permit):
                self.operationState = .restoring(operationID)
                self.status.stringValue = "Verifying and restoring the authenticated backup off the main thread…"
                self.activeCancellation = self.operations.restoreAsync(backup, permit) { [weak self] result in
                    self?.finishProtected(
                        operationID: operationID,
                        permit: permit,
                        result: result,
                        finish: finish
                    ) { [weak self] settled in
                        guard let self else { return }
                        switch settled {
                        case .success(let report):
                            self.onRestoreCompleted?(report)
                            self.status.stringValue = "Backup restored and verified. Revalidating the fresh runtime…"
                            self.refresh()
                        case .failure:
                            self.status.stringValue = "Restore did not complete."
                            self.updateButtons()
                            self.interactions.presentNotice(.restoreFailed)
                        }
                    }
                }
            }
        }
    }

    @objc private func deleteSelected(_ sender: Any?) {
        guard isIdle, let backup = selectedBackup else { return }
        guard interactions.confirm(.delete(backup.id)) else { return }
        let operationID = UUID()
        guard operationGate.begin(operationID) else { return }
        operationState = .deleting(operationID)
        status.stringValue = "Deleting the authenticated backup with crash-safe cleanup…"
        updateButtons()
        activeCancellation = operations.deleteAsync(backup) { [weak self] result in
            guard let self, self.operationState == .deleting(operationID) else { return }
            guard self.operationGate.finish(operationID) else { return }
            self.activeCancellation = nil
            self.operationState = .idle
            switch result {
            case .success:
                self.refresh()
            case .failure:
                self.status.stringValue = "Backup was not deleted."
                self.updateButtons()
                self.interactions.presentNotice(.deleteFailed)
            }
        }
    }

    private func finishProtected<Value>(
        operationID: UUID,
        permit: StateBackupQuiescencePermit,
        result: Result<Value, Error>,
        finish: FinishStateBackupTransition,
        onSettled: @escaping (Result<Value, Error>) -> Void
    ) {
        guard operationState == .creating(operationID) || operationState == .restoring(operationID) else {
            return
        }
        activeCancellation = nil
        operationState = .finishing(operationID)
        status.stringValue = "Finalizing the protected transition and revalidating the runtime…"
        updateButtons()
        finish(permit, .restartAndReopen, result.map { _ in () }) { [weak self] in
            guard let self, self.operationState == .finishing(operationID) else { return }
            guard self.operationGate.finish(operationID) else { return }
            self.operationState = .idle
            onSettled(result)
        }
    }
    private static let formatter: DateFormatter = { let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .short; return f }()
}
