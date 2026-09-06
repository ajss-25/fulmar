import AppKit

struct CommandCenterCommand {
    let title: String
    let detail: String
    let symbolName: String
    let keywords: [String]
    let action: Selector

    init(
        title: String,
        detail: String,
        symbolName: String,
        keywords: [String],
        action: Selector
    ) {
        self.title = AuxiliaryDisplayPolicy.singleLine(
            title,
            maximumCharacters: 100,
            fallback: "Unnamed feature"
        )
        self.detail = AuxiliaryDisplayPolicy.singleLine(
            detail,
            maximumCharacters: 180,
            fallback: "Open this feature"
        )
        self.symbolName = AuxiliaryDisplayPolicy.singleLine(
            symbolName,
            maximumCharacters: 64,
            fallback: "square.grid.2x2"
        )
        self.keywords = Array(keywords.prefix(32)).map {
            AuxiliaryDisplayPolicy.singleLine($0, maximumCharacters: 80, fallback: "")
        }.filter { !$0.isEmpty }
        self.action = action
    }

    func matches(_ query: String) -> Bool {
        let terms = AuxiliaryDisplayPolicy.singleLine(
            query,
            maximumCharacters: 256,
            fallback: ""
        )
            .lowercased()
            .split(whereSeparator: { $0.isWhitespace })
            .prefix(16)
            .map(String.init)
        guard !terms.isEmpty else { return true }
        let haystack = ([title, detail] + keywords).joined(separator: " ").lowercased()
        return terms.allSatisfy(haystack.contains)
    }
}

@MainActor
struct CommandCenterInteractions {
    var sendAction: (_ action: Selector, _ target: AnyObject, _ sender: Any?) -> Bool

    static var live: Self {
        Self(sendAction: { action, target, sender in
            NSApp.sendAction(action, to: target, from: sender)
        })
    }
}

final class CommandCenterWindowController: NSWindowController,
    NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    private weak var actionTarget: AnyObject?
    private let allCommands: [CommandCenterCommand]
    private var visibleCommands: [CommandCenterCommand]
    private let searchField = NSSearchField()
    private let tableView = NSTableView()
    private let openButton = NSButton(title: "Open", target: nil, action: nil)
    private let emptyLabel = NSTextField(labelWithString: "No matching feature")
    private let interactions: CommandCenterInteractions
    private var isDispatching = false

    init(
        commands: [CommandCenterCommand],
        actionTarget: AnyObject,
        interactions: CommandCenterInteractions? = nil
    ) {
        let boundedCommands = Array(commands.prefix(100))
        allCommands = boundedCommands
        visibleCommands = boundedCommands
        self.actionTarget = actionTarget
        self.interactions = interactions ?? .live
        let window = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 560),
            styleMask: [.titled, .closable, .resizable, .utilityWindow],
            backing: .buffered,
            defer: false
        )
        window.title = "Command Center"
        window.subtitle = "Everything in \(ProductBrand.displayName)"
        window.minSize = NSSize(width: 540, height: 400)
        window.isFloatingPanel = false
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.CommandCenter")
        super.init(window: window)
        window.contentViewController = buildContent()
        window.initialFirstResponder = searchField
        if !window.setFrameUsingName("LocalHarness.CommandCenter") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        setDispatching(false)
        searchField.stringValue = ""
        visibleCommands = allCommands
        tableView.reloadData()
        emptyLabel.stringValue = visibleCommands.isEmpty ? "No features are available" : "No matching feature"
        emptyLabel.isHidden = !visibleCommands.isEmpty
        selectFirstResult()
        super.showWindow(sender)
        window?.makeFirstResponder(searchField)
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let heading = NSTextField(labelWithString: "What would you like to do?")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        heading.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(heading)

        let subtitle = NSTextField(labelWithString: "Search Chat, agent tools, models, privacy, recovery and settings.")
        subtitle.textColor = .secondaryLabelColor
        subtitle.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(subtitle)

        searchField.placeholderString = "Search features"
        searchField.delegate = self
        searchField.sendsSearchStringImmediately = true
        searchField.setAccessibilityLabel("Search Fulmar features")
        searchField.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(searchField)

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("command"))
        column.title = "Feature"
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.rowHeight = 58
        tableView.intercellSpacing = NSSize(width: 0, height: 2)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.target = self
        tableView.doubleAction = #selector(openSelected(_:))
        tableView.setAccessibilityLabel("Fulmar features")

        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(scroll)

        emptyLabel.textColor = .secondaryLabelColor
        emptyLabel.alignment = .center
        emptyLabel.isHidden = true
        emptyLabel.setAccessibilityLabel("Command Center search result status")
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(emptyLabel)

        openButton.target = self
        openButton.action = #selector(openSelected(_:))
        openButton.keyEquivalent = "\r"
        openButton.bezelStyle = .rounded
        openButton.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(openButton)

        let hint = NSTextField(labelWithString: "↩ Open   ·   ⌘K Show Command Center")
        hint.font = .systemFont(ofSize: 11)
        hint.textColor = .tertiaryLabelColor
        hint.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(hint)

        NSLayoutConstraint.activate([
            heading.topAnchor.constraint(equalTo: root.topAnchor, constant: 24),
            heading.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            subtitle.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 4),
            subtitle.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            subtitle.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            searchField.topAnchor.constraint(equalTo: subtitle.bottomAnchor, constant: 16),
            searchField.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            searchField.trailingAnchor.constraint(equalTo: subtitle.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: searchField.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: searchField.trailingAnchor),
            emptyLabel.centerXAnchor.constraint(equalTo: scroll.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: scroll.centerYAnchor),
            hint.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            hint.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            hint.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
            openButton.centerYAnchor.constraint(equalTo: hint.centerYAnchor),
            openButton.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            openButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 84)
        ])
        controller.view = root
        return controller
    }

    func numberOfRows(in tableView: NSTableView) -> Int { visibleCommands.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard visibleCommands.indices.contains(row) else { return nil }
        let command = visibleCommands[row]
        let icon = NSImage(
            systemSymbolName: command.symbolName,
            accessibilityDescription: command.title
        ) ?? NSImage(
            systemSymbolName: "square.grid.2x2",
            accessibilityDescription: "Feature"
        ) ?? NSApp.applicationIconImage ?? NSImage(size: NSSize(width: 24, height: 24))
        let image = NSImageView(image: icon)
        image.contentTintColor = .secondaryLabelColor
        image.translatesAutoresizingMaskIntoConstraints = false
        image.widthAnchor.constraint(equalToConstant: 24).isActive = true
        image.heightAnchor.constraint(equalToConstant: 24).isActive = true

        let title = NSTextField(labelWithString: command.title)
        title.font = .systemFont(ofSize: 14, weight: .semibold)
        title.lineBreakMode = .byTruncatingTail
        let detail = NSTextField(labelWithString: command.detail)
        detail.font = .systemFont(ofSize: 11.5)
        detail.textColor = .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingTail
        let labels = NSStackView(views: [title, detail])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 2

        let rowView = NSTableCellView()
        let stack = NSStackView(views: [image, labels])
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        rowView.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: rowView.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: rowView.trailingAnchor, constant: -12),
            stack.centerYAnchor.constraint(equalTo: rowView.centerYAnchor)
        ])
        rowView.setAccessibilityLabel("\(command.title). \(command.detail)")
        return rowView
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updateOpenAvailability()
    }

    func controlTextDidChange(_ obj: Notification) {
        visibleCommands = allCommands.filter { $0.matches(searchField.stringValue) }
        tableView.reloadData()
        emptyLabel.isHidden = !visibleCommands.isEmpty
        selectFirstResult()
    }

    private func selectFirstResult() {
        guard !visibleCommands.isEmpty else {
            tableView.deselectAll(nil)
            updateOpenAvailability()
            return
        }
        tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        updateOpenAvailability()
    }

    @objc private func openSelected(_ sender: Any?) {
        let row = tableView.selectedRow
        guard !isDispatching,
              visibleCommands.indices.contains(row),
              let target = actionTarget else {
            updateOpenAvailability()
            return
        }
        let command = visibleCommands[row]
        guard (target as? NSObject)?.responds(to: command.action) == true else {
            updateOpenAvailability()
            return
        }
        setDispatching(true)
        let delivered = interactions.sendAction(command.action, target, self)
        if delivered { window?.orderOut(sender) }
        setDispatching(false)
    }

    private func updateOpenAvailability() {
        guard !isDispatching,
              visibleCommands.indices.contains(tableView.selectedRow),
              let target = actionTarget else {
            openButton.isEnabled = false
            return
        }
        openButton.isEnabled = (target as? NSObject)?.responds(
            to: visibleCommands[tableView.selectedRow].action
        ) == true
    }

    private func setDispatching(_ dispatching: Bool) {
        isDispatching = dispatching
        searchField.isEnabled = !dispatching
        tableView.isEnabled = !dispatching
        openButton.title = dispatching ? "Opening…" : "Open"
        openButton.setAccessibilityValue(dispatching ? "Opening" : "Ready")
        updateOpenAvailability()
    }
}
