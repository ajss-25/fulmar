import AppKit

/// The auxiliary windows render a mixture of persisted labels, provider model
/// names, and process diagnostics.  Treat every such value as display-only,
/// hostile input: remove invisible direction/format controls, collapse layout
/// whitespace, redact known credential shapes and the current user's home
/// path, and bound the result before handing it to AppKit.
enum AuxiliaryDisplayPolicy {
    static func singleLine(
        _ value: String,
        maximumCharacters: Int,
        fallback: String
    ) -> String {
        let cleaned = cleaned(value, maximumCharacters: maximumCharacters, preservesNewlines: false)
        return cleaned.isEmpty ? fallback : cleaned
    }

    static func multiline(
        _ value: String,
        maximumCharacters: Int,
        fallback: String = ""
    ) -> String {
        let cleaned = cleaned(value, maximumCharacters: maximumCharacters, preservesNewlines: true)
        return cleaned.isEmpty ? fallback : cleaned
    }

    private static func cleaned(
        _ value: String,
        maximumCharacters: Int,
        preservesNewlines: Bool
    ) -> String {
        let outputLimit = min(max(1, maximumCharacters), 16_000)
        // Bound work before applying regular-expression redaction. The extra
        // headroom permits whitespace/control removal without ever processing
        // an attacker-sized NSString.
        let inputLimit = min(max(outputLimit * 8, 4_096), 64_000)
        var normalized = String.UnicodeScalarView()
        normalized.reserveCapacity(inputLimit)
        var previousWasSpace = false
        var previousWasNewline = false

        for scalar in value.unicodeScalars.prefix(inputLimit) {
            if scalar.properties.generalCategory == .format || CharacterSet.controlCharacters.contains(scalar) {
                if preservesNewlines, scalar == "\n" || scalar == "\r" {
                    if !previousWasNewline { normalized.append("\n") }
                    previousWasNewline = true
                    previousWasSpace = false
                } else if !previousWasSpace, !previousWasNewline {
                    normalized.append(" ")
                    previousWasSpace = true
                }
                continue
            }
            if CharacterSet.whitespacesAndNewlines.contains(scalar) {
                if preservesNewlines, scalar == "\n" || scalar == "\r" {
                    if !previousWasNewline { normalized.append("\n") }
                    previousWasNewline = true
                    previousWasSpace = false
                } else if !previousWasSpace, !previousWasNewline {
                    normalized.append(" ")
                    previousWasSpace = true
                }
                continue
            }
            normalized.append(scalar)
            previousWasSpace = false
            previousWasNewline = false
        }

        var redacted = ServiceLogStore.redactedDiagnosticText(String(normalized))
        let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
        if home.hasPrefix("/"), home.utf8.count <= 16_384 {
            redacted = redacted.replacingOccurrences(of: home, with: "<private home>")
        }
        redacted = redacted.trimmingCharacters(in: .whitespacesAndNewlines)

        let scalars = redacted.unicodeScalars
        guard scalars.count > outputLimit else { return redacted }
        let prefixCount = max(0, outputLimit - 1)
        return String(String.UnicodeScalarView(scalars.prefix(prefixCount))) + "…"
    }
}

struct ActivityCenterStoragePresentation: Equatable {
    let message: String
    let isFailure: Bool
    let allowsClearing: Bool

    static func make(status: ActivityStoreStatus) -> Self {
        switch status {
        case .available:
            return Self(
                message: "Activity history is stored privately on this Mac.",
                isFailure: false,
                allowsClearing: true
            )
        case .unavailable(let failure):
            return Self(
                message: "Activity history is unavailable and new activity is not being saved. \(failure.localizedDescription)",
                isFailure: true,
                allowsClearing: false
            )
        }
    }
}

final class ActivityCenterWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let store: ActivityStore
    private let tableView = NSTableView()
    private let detailLabel = NSTextField(wrappingLabelWithString: "Select an activity to see details.")
    private let storageLabel = NSTextField(wrappingLabelWithString: "")
    private let clearButton = NSButton(title: "Clear Finished", target: nil, action: nil)
    private var activities: [LocalActivity] = []
    private var clearPending = false

    init(store: ActivityStore) {
        self.store = store
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Activity Center"
        window.subtitle = "Local work, model jobs, schedules and transfers"
        window.minSize = NSSize(width: 620, height: 400)
        window.setFrameAutosaveName("LocalHarness.ActivityCenter")
        super.init(window: window)
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.ActivityCenter") { window.center() }
        store.onChange = { [weak self] activities in self?.reload(activities) }
        store.onStatusChange = { [weak self] status in self?.reloadStorageStatus(status) }
        reload(store.snapshot())
        reloadStorageStatus(store.status())
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()
        let header = NSTextField(labelWithString: "Everything \(ProductBrand.displayName) is doing, in one place")
        header.font = .systemFont(ofSize: 18, weight: .semibold)
        header.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(header)

        clearButton.target = self
        clearButton.action = #selector(clearFinished(_:))
        clearButton.bezelStyle = .rounded
        clearButton.translatesAutoresizingMaskIntoConstraints = false
        clearButton.setAccessibilityLabel("Clear finished activity history")
        root.addSubview(clearButton)

        storageLabel.font = .systemFont(ofSize: 12)
        storageLabel.maximumNumberOfLines = 2
        storageLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(storageLabel)

        for (identifier, title, width) in [("state", "State", 100.0), ("title", "Activity", 280.0), ("updated", "Updated", 130.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            tableView.addTableColumn(column)
        }
        tableView.delegate = self
        tableView.dataSource = self
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 30
        tableView.target = self
        tableView.doubleAction = #selector(showSelectedDetail(_:))
        tableView.setAccessibilityLabel("Recent agent and service activity")
        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(scroll)

        detailLabel.textColor = .secondaryLabelColor
        detailLabel.maximumNumberOfLines = 3
        detailLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(detailLabel)

        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: root.topAnchor, constant: 20),
            header.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            clearButton.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            clearButton.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            storageLabel.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 6),
            storageLabel.leadingAnchor.constraint(equalTo: header.leadingAnchor),
            storageLabel.trailingAnchor.constraint(equalTo: clearButton.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: storageLabel.bottomAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            detailLabel.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            detailLabel.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            detailLabel.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            detailLabel.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18)
        ])
        controller.view = root
        return controller
    }

    private func reload(_ activities: [LocalActivity]) {
        let selectedID = self.activities.indices.contains(tableView.selectedRow)
            ? self.activities[tableView.selectedRow].id
            : nil
        self.activities = activities
        tableView.reloadData()
        if let selectedID, let row = activities.firstIndex(where: { $0.id == selectedID }) {
            tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        } else if selectedID != nil {
            tableView.deselectAll(nil)
        }
        setClearPending(false)
        updateDetail()
    }

    private func reloadStorageStatus(_ status: ActivityStoreStatus) {
        let presentation = ActivityCenterStoragePresentation.make(status: status)
        storageLabel.stringValue = presentation.message
        storageLabel.textColor = presentation.isFailure ? .systemRed : .secondaryLabelColor
        storageLabel.setAccessibilityLabel(presentation.message)
        if presentation.isFailure { setClearPending(false) }
        clearButton.isEnabled = presentation.allowsClearing && !clearPending
    }

    func numberOfRows(in tableView: NSTableView) -> Int { activities.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard activities.indices.contains(row), let tableColumn else { return nil }
        let activity = activities[row]
        let field = NSTextField(labelWithString: "")
        field.lineBreakMode = .byTruncatingTail
        switch tableColumn.identifier.rawValue {
        case "state":
            field.stringValue = activity.state.rawValue.capitalized
            field.textColor = color(for: activity.state)
            field.font = .systemFont(ofSize: 12, weight: .semibold)
        case "updated":
            field.stringValue = Self.dateFormatter.string(from: activity.updatedAt)
            field.textColor = .secondaryLabelColor
        default:
            field.stringValue = Self.safeTitle(activity.title)
            let detail = Self.safeDetail(activity.detail)
            field.toolTip = detail.isEmpty ? nil : detail
        }
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateDetail() }

    private func updateDetail() {
        let row = tableView.selectedRow
        guard activities.indices.contains(row) else {
            detailLabel.stringValue = activities.isEmpty ? "No activity yet." : "Select an activity to see details."
            return
        }
        let activity = activities[row]
        let detail = Self.safeDetail(activity.detail)
        detailLabel.stringValue = detail.isEmpty
            ? "\(activity.kind.rawValue.capitalized) · \(activity.state.rawValue)"
            : detail
    }

    private func color(for state: LocalActivity.State) -> NSColor {
        switch state {
        case .completed: return .systemGreen
        case .failed: return .systemRed
        case .waiting: return .systemOrange
        case .cancelled: return .secondaryLabelColor
        case .queued, .running: return .systemBlue
        }
    }

    @objc private func clearFinished(_ sender: Any?) {
        guard !clearPending, store.status().isAvailable else { return }
        setClearPending(true)
        store.clearFinished()
    }
    @objc private func showSelectedDetail(_ sender: Any?) { updateDetail() }

    private func setClearPending(_ pending: Bool) {
        clearPending = pending
        clearButton.title = pending ? "Clearing…" : "Clear Finished"
        clearButton.isEnabled = !pending && store.status().isAvailable
        clearButton.setAccessibilityValue(pending ? "Clearing" : "Ready")
    }

    static func safeTitle(_ value: String) -> String {
        AuxiliaryDisplayPolicy.singleLine(value, maximumCharacters: 160, fallback: "Untitled activity")
    }

    static func safeDetail(_ value: String) -> String {
        AuxiliaryDisplayPolicy.multiline(value, maximumCharacters: 1_200)
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter
    }()
}
