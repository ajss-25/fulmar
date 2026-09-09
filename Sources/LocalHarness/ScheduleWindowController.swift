import AppKit

@MainActor
enum NewScheduleFormAccessibility {
    static func labels(
        title: NSTextField,
        promptScroll: NSScrollView,
        provider: NSTextField,
        model: NSTextField,
        profile: NSPopUpButton,
        timeout: NSPopUpButton,
        firstRun: NSDatePicker,
        interval: NSPopUpButton
    ) -> [NSTextField] {
        title.setAccessibilityLabel("Schedule name")
        (promptScroll.documentView as? NSTextView)?.setAccessibilityLabel("Scheduled task prompt")
        provider.setAccessibilityLabel("Scheduled task provider ID")
        model.setAccessibilityLabel("Scheduled task model ID")
        profile.setAccessibilityLabel("Scheduled task output profile")
        timeout.setAccessibilityLabel("Scheduled task time limit")
        firstRun.setAccessibilityLabel("Scheduled task first run date and time")
        interval.setAccessibilityLabel("Scheduled task repeat interval")
        return [
            AccessibleFormSupport.makeLabel("Name", for: title),
            AccessibleFormSupport.makeLabel("Prompt", for: promptScroll),
            AccessibleFormSupport.makeLabel("Provider ID", for: provider),
            AccessibleFormSupport.makeLabel("Model ID", for: model),
            AccessibleFormSupport.makeLabel("Output profile", for: profile),
            AccessibleFormSupport.makeLabel("Task time limit", for: timeout),
            AccessibleFormSupport.makeLabel("First run", for: firstRun),
            AccessibleFormSupport.makeLabel("Repeat", for: interval)
        ]
    }
}

struct NewScheduleSubmission: Equatable {
    let title: String
    let prompt: String
    let providerID: String
    let modelID: String
    let performanceProfile: PerformanceProfile
    let timeoutSeconds: TimeInterval
    let firstRun: Date
    let intervalSeconds: TimeInterval
}

enum ScheduleWindowFailure: Equatable {
    case invalidNewSchedule
    case backgroundService
    case addSchedule
    case authorizeSchedule
    case toggleSchedule
    case revokeAccess
    case deleteSchedule
    case deleteInboxResult
    case clearInbox

    var title: String {
        switch self {
        case .invalidNewSchedule: "Check the schedule details"
        case .backgroundService: "Background scheduling was not changed"
        case .addSchedule: "The schedule was not saved"
        case .authorizeSchedule: "Unattended access was not enabled"
        case .toggleSchedule: "The schedule was not changed"
        case .revokeAccess: "Unattended access was not revoked"
        case .deleteSchedule: "The schedule was not deleted"
        case .deleteInboxResult: "The result was not deleted"
        case .clearInbox: "The Task Inbox was not cleared"
        }
    }

    var message: String {
        switch self {
        case .invalidNewSchedule:
            "Enter a name, prompt, provider ID, and model ID that fit the documented limits."
        case .backgroundService:
            "Your previous background-service setting was restored. You can try again from Schedules."
        case .addSchedule:
            "Existing schedules were preserved. Review the details and try again."
        case .authorizeSchedule:
            "The schedule remains blocked. Review its provider and endpoint before trying again."
        case .toggleSchedule:
            "The previous schedule state was preserved. Try again after storage is available."
        case .revokeAccess:
            "The existing consent state was preserved. Try again after storage is available."
        case .deleteSchedule:
            "The schedule and any current run were preserved. Try again after storage is available."
        case .deleteInboxResult:
            "The existing Task Inbox result was preserved. Try again after storage is available."
        case .clearInbox:
            "Existing Task Inbox results were preserved. Try again after storage is available."
        }
    }
}

@MainActor
struct ScheduleWindowInteractions {
    var presentNewSchedule: (ModelSelection) -> NewScheduleSubmission?
    var confirmExternalAccess: (ModelSelection, DataBoundary, Int, ProviderEndpointOrigin) -> Bool
    var confirmRevokeAccess: (LocalSchedule) -> Bool
    var confirmDeleteSchedule: (LocalSchedule) -> Bool
    var showProviderInactive: (LocalSchedule, ProviderID?) -> Void
    var showRouteInactive: (LocalSchedule, ModelRoute?) -> Void
    var showEndpointUnavailable: () -> Void
    var showFailure: (ScheduleWindowFailure) -> Void

    static let live = ScheduleWindowInteractions(
        presentNewSchedule: { ScheduleAppKitPresentation.presentNewSchedule(current: $0) },
        confirmExternalAccess: { selection, boundary, promptBytes, origin in
            ScheduleAppKitPresentation.confirmExternalAccess(
                selection: selection,
                boundary: boundary,
                promptBytes: promptBytes,
                origin: origin
            )
        },
        confirmRevokeAccess: { schedule in
            let alert = NSAlert()
            alert.messageText = "Revoke unattended access?"
            alert.informativeText = "The schedule will be disabled and cannot contact \(schedule.provider) again until you review and approve it."
            alert.addButton(withTitle: "Revoke and Disable")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        confirmDeleteSchedule: { schedule in
            let alert = NSAlert()
            alert.messageText = "Delete \(schedule.title)?"
            alert.informativeText = "Any running task will be cancelled. Existing Task Inbox results are retained."
            alert.addButton(withTitle: "Delete")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        showProviderInactive: { schedule, active in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Select this schedule's provider first"
            alert.informativeText = active.map {
                "The secure runtime currently permits only \($0.rawValue). Switch the app's model provider to \(schedule.provider), wait for Harness to restart, then run this schedule."
            } ?? "Wait for the live provider catalog to load, then select \(schedule.provider) before running this schedule."
            alert.addButton(withTitle: "OK")
            alert.runModal()
        },
        showRouteInactive: { schedule, active in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Select this schedule's exact local model first"
            alert.informativeText = active.map {
                "The secure runtime currently permits only \($0.provider.rawValue) / \($0.model.rawValue). Switch to \(schedule.provider) / \(schedule.model), wait for Harness to restart, then run this schedule."
            } ?? "Wait for the live model catalog to load, then select \(schedule.provider) / \(schedule.model) before running this schedule."
            alert.addButton(withTitle: "OK")
            alert.runModal()
        },
        showEndpointUnavailable: {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "The provider endpoint cannot be verified"
            alert.informativeText = "Unattended access remained blocked. Open Models & Providers, verify the exact HTTP(S) endpoint, then review this schedule again."
            alert.addButton(withTitle: "OK")
            alert.runModal()
        },
        showFailure: { failure in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = failure.title
            alert.informativeText = failure.message
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    )
}

@MainActor
struct ScheduleWindowOperations {
    var snapshot: () -> [LocalSchedule]
    var runningScheduleIDs: () -> Set<UUID>
    var backgroundServiceEnabled: () -> Bool
    var inboxCount: () -> Int
    var hasStorageIssue: () -> Bool
    var defaultModelSelection: () -> ModelSelection
    var boundary: (ModelSelection) -> DataBoundary
    var origin: (ModelSelection) -> ProviderEndpointOrigin?
    var authorizationStatus: (LocalSchedule) -> ScheduleAuthorizationStatus
    var setBackgroundService: (Bool) throws -> Void
    var add: (NewScheduleSubmission, ModelSelection, Bool) throws -> Void
    var runNow: (UUID) -> Void
    var cancelRun: (UUID) -> Void
    var toggle: (UUID) throws -> Void
    var authorizeAndEnable: (UUID) throws -> Void
    var revokeUnattendedConsent: (UUID) throws -> Void
    var remove: (UUID) throws -> Void

    init(manager: ScheduleManager) {
        snapshot = { manager.snapshot() }
        runningScheduleIDs = { manager.runningScheduleIDs() }
        backgroundServiceEnabled = { manager.backgroundServiceEnabled }
        inboxCount = { manager.inboxCount() }
        hasStorageIssue = { manager.storageIssue() != nil }
        defaultModelSelection = { manager.defaultModelSelection() }
        boundary = { manager.boundary(for: $0) }
        origin = { manager.origin(for: $0) }
        authorizationStatus = { manager.authorizationStatus(for: $0) }
        setBackgroundService = { try manager.setBackgroundService(enabled: $0) }
        add = { submission, selection, allowExternal in
            _ = try manager.add(
                title: submission.title,
                prompt: submission.prompt,
                selection: selection,
                intervalSeconds: submission.intervalSeconds,
                timeoutSeconds: submission.timeoutSeconds,
                firstRun: submission.firstRun,
                allowUnattendedExternal: allowExternal
            )
        }
        runNow = { manager.runNow(id: $0) }
        cancelRun = { manager.cancelRun(id: $0) }
        toggle = { try manager.toggle(id: $0) }
        authorizeAndEnable = { try manager.authorizeAndEnable(id: $0) }
        revokeUnattendedConsent = { try manager.revokeUnattendedConsent(id: $0) }
        remove = { try manager.remove(id: $0) }
    }
}

@MainActor
private enum ScheduleAppKitPresentation {
    static func presentNewSchedule(current: ModelSelection) -> NewScheduleSubmission? {
        let title = NSTextField(string: "Daily summary")
        let prompt = NSTextView(frame: NSRect(x: 0, y: 0, width: 480, height: 88))
        prompt.string = "Summarize what I should focus on today."
        prompt.font = .systemFont(ofSize: 13)
        prompt.textContainerInset = NSSize(width: 6, height: 6)
        let promptScroll = NSScrollView()
        promptScroll.documentView = prompt
        promptScroll.hasVerticalScroller = true
        promptScroll.borderType = .bezelBorder
        promptScroll.heightAnchor.constraint(equalToConstant: 92).isActive = true

        let provider = NSTextField(string: current.route.provider.rawValue)
        let model = NSTextField(string: current.route.model.rawValue)
        let interval = NSPopUpButton()
        interval.addItems(withTitles: ["Once", "Every hour", "Every 6 hours", "Daily", "Weekly"])
        interval.selectItem(at: 3)
        let firstRun = NSDatePicker()
        firstRun.datePickerElements = [.yearMonthDay, .hourMinute]
        firstRun.dateValue = Date().addingTimeInterval(300)
        firstRun.minDate = Date()
        let profile = NSPopUpButton()
        profile.addItems(withTitles: PerformanceProfile.allCases.map(\.displayName))
        profile.selectItem(at: PerformanceProfile.allCases.firstIndex(of: current.performanceProfile) ?? 1)
        let timeout = NSPopUpButton()
        timeout.addItems(withTitles: ["2 minutes", "10 minutes", "20 minutes", "1 hour"])
        let defaultTimeoutIndex = (current.performanceProfile == .fast || current.performanceProfile == .compatibility)
            ? 0 : (current.performanceProfile == .deep ? 2 : 1)
        timeout.selectItem(at: defaultTimeoutIndex)

        let labels = NewScheduleFormAccessibility.labels(
            title: title,
            promptScroll: promptScroll,
            provider: provider,
            model: model,
            profile: profile,
            timeout: timeout,
            firstRun: firstRun,
            interval: interval
        )
        let stack = NSStackView(views: [
            labels[0], title, labels[1], promptScroll, labels[2], provider, labels[3], model,
            labels[4], profile, labels[5], timeout, labels[6], firstRun, labels[7], interval
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 5
        stack.setFrameSize(NSSize(width: 480, height: 440))
        [title, provider, model].forEach { $0.widthAnchor.constraint(equalToConstant: 480).isActive = true }
        promptScroll.widthAnchor.constraint(equalToConstant: 480).isActive = true

        let alert = NSAlert()
        alert.messageText = "New Schedule"
        alert.informativeText = "The task runs through DeepSeek Harness using this exact provider and model route. For local routes, context capacity is app-wide; this task profile selects its output cap."
        alert.accessoryView = stack
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }

        let intervals: [TimeInterval] = [0, 3_600, 21_600, 86_400, 604_800]
        let timeoutValues: [TimeInterval] = [120, 600, 1_200, 3_600]
        return NewScheduleSubmission(
            title: title.stringValue,
            prompt: prompt.string,
            providerID: provider.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            modelID: model.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            performanceProfile: PerformanceProfile.allCases[
                min(max(0, profile.indexOfSelectedItem), PerformanceProfile.allCases.count - 1)
            ],
            timeoutSeconds: timeoutValues[min(timeoutValues.count - 1, max(0, timeout.indexOfSelectedItem))],
            firstRun: firstRun.dateValue,
            intervalSeconds: intervals[min(intervals.count - 1, max(0, interval.indexOfSelectedItem))]
        )
    }

    static func confirmExternalAccess(
        selection: ModelSelection,
        boundary: DataBoundary,
        promptBytes: Int,
        origin: ProviderEndpointOrigin
    ) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Allow unattended \(boundary.displayName.lowercased()) requests?"
        alert.informativeText = "When this schedule is due, \(ProductBrand.displayName) will send its saved prompt (currently \(ByteCountFormatter.string(fromByteCount: Int64(promptBytes), countStyle: .file))) to \(selection.route.provider.rawValue) / \(selection.route.model.rawValue) at exactly \(origin.displayName), even when you are not present. Tool approvals and questions are always rejected. Changing the route, boundary, or endpoint invalidates this consent."
        alert.addButton(withTitle: "Allow This Schedule")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

@MainActor
struct TaskInboxInteractions {
    var confirmDelete: (ScheduledResult) -> Bool
    var confirmClear: (Int) -> Bool
    var showFailure: (ScheduleWindowFailure) -> Void

    static let live = TaskInboxInteractions(
        confirmDelete: { result in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Delete this scheduled result?"
            alert.informativeText = "\(result.title) will be removed from the private Task Inbox. This cannot be undone."
            alert.addButton(withTitle: "Delete Result")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        confirmClear: { count in
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Clear the Task Inbox?"
            alert.informativeText = "All \(count) retained scheduled results will be permanently removed. Schedules themselves are not changed."
            alert.addButton(withTitle: "Clear Inbox")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        showFailure: ScheduleWindowInteractions.live.showFailure
    )
}

@MainActor
struct TaskInboxOperations {
    var load: () async -> ScheduleInboxLoadOutcome
    var delete: (UUID) throws -> Void
    var clear: () throws -> Void

    init(manager: ScheduleManager) {
        load = { await manager.inboxAsync() }
        delete = { try manager.deleteInboxResult(id: $0) }
        clear = { try manager.clearInbox() }
    }
}

final class ScheduleWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let manager: ScheduleManager
    private let operations: ScheduleWindowOperations
    private let interactions: ScheduleWindowInteractions
    private let table = NSTableView()
    private let serviceToggle = NSButton(
        checkboxWithTitle: "Run due tasks even when the main window is closed",
        target: nil,
        action: nil
    )
    private let status = NSTextField(labelWithString: "")
    private let runButton = NSButton(title: "Run Now", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel Run", target: nil, action: nil)
    private let toggleButton = NSButton(title: "Enable / Disable", target: nil, action: nil)
    private let revokeButton = NSButton(title: "Revoke External Access", target: nil, action: nil)
    private let removeButton = NSButton(title: "Delete", target: nil, action: nil)
    private let addButton = NSButton(title: "New Schedule…", target: nil, action: nil)
    private let inboxButton = NSButton(title: "Open Task Inbox", target: nil, action: nil)
    private var schedules: [LocalSchedule] = []
    private var running: Set<UUID> = []
    private var pendingRunIDs: Set<UUID> = []
    private var isMutating = false
    private var inboxWindow: NSWindowController?

    convenience init(manager: ScheduleManager, preferences: PreferencesStore) {
        self.init(
            manager: manager,
            preferences: preferences,
            operations: ScheduleWindowOperations(manager: manager),
            interactions: .live
        )
    }

    init(
        manager: ScheduleManager,
        preferences: PreferencesStore,
        operations: ScheduleWindowOperations,
        interactions: ScheduleWindowInteractions
    ) {
        self.manager = manager
        self.operations = operations
        self.interactions = interactions
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 560),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Schedules & Task Inbox"
        window.subtitle = "Local or connected model tasks with explicit data boundaries"
        window.minSize = NSSize(width: 780, height: 440)
        window.setFrameAutosaveName("LocalHarness.Schedules")
        super.init(window: window)
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.Schedules") { window.center() }
        manager.onChange = { [weak self] in self?.refresh() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        refresh()
        super.showWindow(sender)
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        serviceToggle.target = self
        serviceToggle.action = #selector(toggleService(_:))
        serviceToggle.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(serviceToggle)

        status.textColor = .secondaryLabelColor
        status.lineBreakMode = .byTruncatingMiddle
        status.setAccessibilityLabel("Schedule status")
        status.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(status)

        for (identifier, title, width) in [
            ("state", "State", 80.0),
            ("title", "Schedule", 220.0),
            ("next", "Next Run", 145.0),
            ("route", "Provider / Model", 290.0),
            ("boundary", "Data Boundary", 120.0)
        ] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            table.addTableColumn(column)
        }
        table.delegate = self
        table.dataSource = self
        table.rowHeight = 32
        table.usesAlternatingRowBackgroundColors = true
        table.allowsEmptySelection = true
        table.setAccessibilityLabel("Scheduled tasks and provider boundaries")
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        // The explicit columns intentionally preserve enough width for model
        // and data-boundary disclosure. At the supported minimum window size
        // they exceed the viewport, so horizontal access must remain available
        // instead of silently clipping the security-relevant right columns.
        scroll.hasHorizontalScroller = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(scroll)

        addButton.target = self; addButton.action = #selector(addSchedule(_:))
        inboxButton.target = self; inboxButton.action = #selector(openInbox(_:))
        runButton.target = self; runButton.action = #selector(runNow(_:))
        cancelButton.target = self; cancelButton.action = #selector(cancelRun(_:))
        toggleButton.target = self; toggleButton.action = #selector(toggleSchedule(_:))
        revokeButton.target = self; revokeButton.action = #selector(revokeAccess(_:))
        removeButton.target = self; removeButton.action = #selector(remove(_:))
        let primaryActions = NSStackView(views: [addButton, inboxButton, NSView()])
        primaryActions.orientation = .horizontal
        primaryActions.spacing = 8
        let selectedScheduleActions = NSStackView(views: [
            runButton, cancelButton, toggleButton, revokeButton, NSView(), removeButton
        ])
        selectedScheduleActions.orientation = .horizontal
        selectedScheduleActions.spacing = 8
        let actions = NSStackView(views: [primaryActions, selectedScheduleActions])
        actions.orientation = .vertical
        actions.alignment = .width
        actions.spacing = 8
        actions.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(actions)

        let privacy = NSTextField(wrappingLabelWithString:
            "Connected schedules can send their saved prompt without you present. \(ProductBrand.displayName) records the exact provider and refuses tool approvals or questions during unattended runs."
        )
        privacy.font = .systemFont(ofSize: 10.5)
        privacy.textColor = .secondaryLabelColor
        privacy.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(privacy)

        NSLayoutConstraint.activate([
            serviceToggle.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            serviceToggle.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            status.centerYAnchor.constraint(equalTo: serviceToggle.centerYAnchor),
            status.leadingAnchor.constraint(greaterThanOrEqualTo: serviceToggle.trailingAnchor, constant: 16),
            status.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            scroll.topAnchor.constraint(equalTo: serviceToggle.bottomAnchor, constant: 14),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            actions.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            actions.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            actions.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            privacy.topAnchor.constraint(equalTo: actions.bottomAnchor, constant: 10),
            privacy.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            privacy.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            privacy.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -14)
        ])
        controller.view = root
        updateButtons()
        return controller
    }

    func refresh() {
        let previouslySelectedID = selected?.id
        schedules = operations.snapshot()
        running = operations.runningScheduleIDs()
        let visibleIDs = Set(schedules.map(\.id))
        pendingRunIDs.formIntersection(visibleIDs)
        pendingRunIDs.subtract(running)
        table.reloadData()
        if let previouslySelectedID,
           let row = schedules.firstIndex(where: { $0.id == previouslySelectedID }) {
            table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        }
        serviceToggle.state = operations.backgroundServiceEnabled() ? .on : .off
        let resultCount = operations.inboxCount()
        if operations.hasStorageIssue() {
            status.stringValue = "Private schedule storage needs attention. Existing data was preserved."
            status.textColor = .systemRed
        } else {
            status.stringValue = "\(schedules.count) schedule\(schedules.count == 1 ? "" : "s") · \(resultCount) inbox result\(resultCount == 1 ? "" : "s")"
            status.textColor = .secondaryLabelColor
        }
        updateButtons()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { schedules.count }

    func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
        guard schedules.indices.contains(row), let column else { return nil }
        let item = schedules[row]
        let field = NSTextField(labelWithString: "")
        field.lineBreakMode = .byTruncatingMiddle
        switch column.identifier.rawValue {
        case "state":
            if running.contains(item.id) {
                field.stringValue = "Running"
                field.textColor = .systemBlue
            } else if pendingRunIDs.contains(item.id) {
                field.stringValue = "Starting"
                field.textColor = .systemBlue
            } else if operations.authorizationStatus(item) != .authorized {
                field.stringValue = "Review"
                field.textColor = .systemOrange
            } else {
                field.stringValue = item.enabled ? "On" : "Off"
                field.textColor = item.enabled ? .systemGreen : .secondaryLabelColor
            }
            field.font = .systemFont(ofSize: 12, weight: .semibold)
        case "next":
            field.stringValue = item.enabled ? Self.formatter.string(from: item.nextRun) : "Disabled"
            field.textColor = .secondaryLabelColor
        case "route":
            field.stringValue = "\(item.provider) / \(item.model)"
            field.toolTip = field.stringValue
        case "boundary":
            field.stringValue = item.boundary.displayName
            field.textColor = item.boundary == .onDevice ? .systemGreen : .systemOrange
        default:
            field.stringValue = item.title
        }
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateButtons() }

    private var selected: LocalSchedule? {
        schedules.indices.contains(table.selectedRow) ? schedules[table.selectedRow] : nil
    }

    private func updateButtons() {
        serviceToggle.isEnabled = !isMutating
        addButton.isEnabled = !isMutating
        inboxButton.isEnabled = !isMutating
        guard let selected else {
            [runButton, cancelButton, toggleButton, revokeButton, removeButton].forEach { $0.isEnabled = false }
            return
        }
        runButton.isEnabled = !isMutating
            && !running.contains(selected.id)
            && !pendingRunIDs.contains(selected.id)
        cancelButton.isEnabled = !isMutating && running.contains(selected.id)
        toggleButton.isEnabled = !isMutating && !running.contains(selected.id)
        revokeButton.isEnabled = !isMutating
            && !running.contains(selected.id)
            && selected.boundary.requiresExplicitConsent
            && selected.unattendedConsent != nil
        removeButton.isEnabled = !isMutating
    }

    @objc private func toggleService(_ sender: NSButton) {
        guard !isMutating else {
            sender.state = operations.backgroundServiceEnabled() ? .on : .off
            return
        }
        let requested = sender.state == .on
        performMutation(failure: .backgroundService) {
            try operations.setBackgroundService(requested)
        }
    }

    @objc private func runNow(_ sender: Any?) {
        guard !isMutating,
              let selected,
              !running.contains(selected.id),
              !pendingRunIDs.contains(selected.id) else { return }
        guard ensureAuthorization(for: selected) else { return }
        pendingRunIDs.insert(selected.id)
        performAction { operations.runNow(selected.id) }
        let scheduleID = selected.id
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            guard let self,
                  pendingRunIDs.contains(scheduleID),
                  !running.contains(scheduleID) else { return }
            pendingRunIDs.remove(scheduleID)
            refresh()
        }
    }

    @objc private func cancelRun(_ sender: Any?) {
        guard !isMutating, let selected, running.contains(selected.id) else { return }
        performAction { operations.cancelRun(selected.id) }
    }

    @objc private func toggleSchedule(_ sender: Any?) {
        guard !isMutating, let selected, !running.contains(selected.id) else { return }
        if selected.enabled || operations.authorizationStatus(selected) == .authorized {
            performMutation(failure: .toggleSchedule) {
                try operations.toggle(selected.id)
            }
        } else {
            _ = ensureAuthorization(for: selected) // Consent path enables atomically.
        }
    }

    @objc private func revokeAccess(_ sender: Any?) {
        guard !isMutating,
              let selected,
              !running.contains(selected.id),
              selected.boundary.requiresExplicitConsent,
              selected.unattendedConsent != nil else { return }
        guard interactions.confirmRevokeAccess(selected) else { return }
        performMutation(failure: .revokeAccess) {
            try operations.revokeUnattendedConsent(selected.id)
        }
    }

    @objc private func remove(_ sender: Any?) {
        guard !isMutating, let selected else { return }
        guard interactions.confirmDeleteSchedule(selected) else { return }
        performMutation(failure: .deleteSchedule) {
            try operations.remove(selected.id)
        }
    }

    @objc private func addSchedule(_ sender: Any?) {
        guard !isMutating else { return }
        let current = operations.defaultModelSelection()
        guard let submission = interactions.presentNewSchedule(current) else { return }
        let providerID = submission.providerID.trimmingCharacters(in: .whitespacesAndNewlines)
        let modelID = submission.modelID.trimmingCharacters(in: .whitespacesAndNewlines)
        let selection = ModelSelection(
            route: ModelRoute(provider: ProviderID(providerID), model: ModelID(modelID)),
            reasoningEffort: providerID == current.route.provider.rawValue && modelID == current.route.model.rawValue
                ? current.reasoningEffort
                : nil,
            performanceProfile: submission.performanceProfile
        )
        guard ScheduleFieldValidation.isSafeTitle(submission.title),
              ScheduleFieldValidation.isSafePrompt(submission.prompt),
              ScheduleFieldValidation.isSafe(selection: selection),
              ScheduleFieldValidation.isValidInterval(submission.intervalSeconds),
              ScheduleFieldValidation.isValidTimeout(submission.timeoutSeconds),
              submission.firstRun.timeIntervalSinceReferenceDate.isFinite else {
            interactions.showFailure(.invalidNewSchedule)
            return
        }
        let boundary = operations.boundary(selection)

        var allowExternal = false
        if boundary.requiresExplicitConsent {
            guard confirmUnattendedExternal(
                selection: selection,
                boundary: boundary,
                promptBytes: submission.prompt.utf8.count
            ) else { return }
            allowExternal = true
        }
        performMutation(failure: .addSchedule) {
            try operations.add(submission, selection, allowExternal)
        }
    }

    private func ensureAuthorization(for schedule: LocalSchedule) -> Bool {
        switch operations.authorizationStatus(schedule) {
        case .authorized:
            return true
        case .consentRequired(let boundary), .boundaryChanged(_, let boundary):
            guard confirmUnattendedExternal(
                selection: schedule.selection,
                boundary: boundary,
                promptBytes: schedule.prompt.utf8.count
            ) else { return false }
            return performMutation(failure: .authorizeSchedule) {
                try operations.authorizeAndEnable(schedule.id)
            }
        case .providerInactive(let active):
            interactions.showProviderInactive(schedule, active)
            return false
        case .routeInactive(let active):
            interactions.showRouteInactive(schedule, active)
            return false
        case .endpointUnavailable:
            interactions.showEndpointUnavailable()
            return false
        }
    }

    private func confirmUnattendedExternal(
        selection: ModelSelection,
        boundary: DataBoundary,
        promptBytes: Int
    ) -> Bool {
        guard boundary.requiresExplicitConsent else { return true }
        guard let origin = operations.origin(selection) else {
            interactions.showEndpointUnavailable()
            return false
        }
        return interactions.confirmExternalAccess(selection, boundary, promptBytes, origin)
    }

    private func performAction(_ action: () -> Void) {
        guard !isMutating else { return }
        isMutating = true
        updateButtons()
        action()
        isMutating = false
        refresh()
    }

    @discardableResult
    private func performMutation(
        failure: ScheduleWindowFailure,
        _ mutation: () throws -> Void
    ) -> Bool {
        guard !isMutating else { return false }
        isMutating = true
        updateButtons()
        defer {
            isMutating = false
            refresh()
        }
        do {
            try mutation()
            return true
        } catch {
            interactions.showFailure(failure)
            return false
        }
    }

    @objc private func openInbox(_ sender: Any?) {
        let controller = TaskInboxWindowController(manager: manager)
        inboxWindow = controller
        controller.showWindow(sender)
        controller.window?.makeKeyAndOrderFront(sender)
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter
    }()
}

final class TaskInboxWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let operations: TaskInboxOperations
    private let interactions: TaskInboxInteractions
    private var results: [ScheduledResult] = []
    private var loadTask: Task<Void, Never>?
    private var loadError: String?
    private var loadGeneration: UInt64 = 0
    private var isLoading = false
    private var isMutating = false
    private let table = NSTableView()
    private let detail = NSTextView()
    private let deleteButton = NSButton(title: "Delete Result", target: nil, action: nil)
    private let clearButton = NSButton(title: "Clear Inbox…", target: nil, action: nil)
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)

    convenience init(manager: ScheduleManager) {
        self.init(
            operations: TaskInboxOperations(manager: manager),
            interactions: .live
        )
    }

    init(operations: TaskInboxOperations, interactions: TaskInboxInteractions) {
        self.operations = operations
        self.interactions = interactions
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 620),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Task Inbox"
        window.subtitle = "Scheduled results and their exact model route"
        window.minSize = NSSize(width: 700, height: 480)
        window.setFrameAutosaveName("LocalHarness.TaskInbox")
        super.init(window: window)

        let root = NSView()
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("result"))
        column.title = "Results"
        column.width = 280
        table.addTableColumn(column)
        table.delegate = self
        table.dataSource = self
        table.rowHeight = 48
        table.setAccessibilityLabel("Scheduled task results")
        let list = NSScrollView()
        list.documentView = table
        list.hasVerticalScroller = true
        list.hasHorizontalScroller = true
        list.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(list)

        detail.isEditable = false
        detail.isSelectable = true
        detail.font = .systemFont(ofSize: 13)
        detail.textContainerInset = NSSize(width: 16, height: 16)
        detail.setAccessibilityLabel("Selected scheduled task result")
        let body = NSScrollView()
        body.documentView = detail
        body.hasVerticalScroller = true
        body.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(body)

        deleteButton.target = self
        deleteButton.action = #selector(deleteSelectedResult(_:))
        deleteButton.setAccessibilityLabel("Delete selected scheduled result")
        clearButton.target = self
        clearButton.action = #selector(clearInbox(_:))
        clearButton.setAccessibilityLabel("Clear Task Inbox")
        refreshButton.target = self
        refreshButton.action = #selector(refreshInbox(_:))
        refreshButton.setAccessibilityLabel("Refresh Task Inbox")
        let retention = NSTextField(labelWithString: "Automatically keeps up to 2,000 results, 256 MB, and 30 days.")
        retention.textColor = .secondaryLabelColor
        retention.font = .systemFont(ofSize: 11)
        let actions = NSStackView(views: [retention, NSView(), refreshButton, deleteButton, clearButton])
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 8
        actions.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(actions)

        NSLayoutConstraint.activate([
            list.topAnchor.constraint(equalTo: root.topAnchor),
            list.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            list.bottomAnchor.constraint(equalTo: actions.topAnchor, constant: -10),
            list.widthAnchor.constraint(equalToConstant: 300),
            body.topAnchor.constraint(equalTo: root.topAnchor),
            body.leadingAnchor.constraint(equalTo: list.trailingAnchor),
            body.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            body.bottomAnchor.constraint(equalTo: actions.topAnchor, constant: -10),
            actions.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12),
            actions.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -12),
            actions.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -10)
        ])
        let controller = NSViewController()
        controller.view = root
        window.contentViewController = controller
        if !window.setFrameUsingName("LocalHarness.TaskInbox") { window.center() }
        detail.string = "Loading the private Task Inbox…"
        updateButtons()
        loadResults()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit { loadTask?.cancel() }

    func numberOfRows(in tableView: NSTableView) -> Int { results.count }

    func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
        guard results.indices.contains(row) else { return nil }
        let result = results[row]
        let state = result.failure == nil ? (result.truncated ? "Partial" : "Completed") : "Failed"
        let field = NSTextField(wrappingLabelWithString:
            "\(result.title)\n\(state) · \(Self.formatter.string(from: result.completedAt))"
        )
        field.toolTip = "\(result.provider) / \(result.model)"
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updateDetail()
        updateButtons()
    }

    private func updateDetail() {
        guard results.indices.contains(table.selectedRow) else {
            detail.string = loadError
                ?? (results.isEmpty ? "No scheduled results." : "Select a result to read it.")
            return
        }
        let result = results[table.selectedRow]
        let session = result.sessionID?.rawValue ?? "Not created"
        let status = result.failure?.displayMessage ?? (result.truncated ? "Completed with truncated output" : "Completed")
        let body = result.failure == nil ? result.response : (result.response.isEmpty ? "No response was saved." : result.response)
        detail.string = """
        \(result.title)

        Status: \(status)
        Provider: \(result.provider)
        Model: \(result.model)
        Data boundary: \(result.boundary.displayName)
        Harness session: \(session)
        Completed: \(result.completedAt.formatted())

        \(body)
        """
    }

    private func updateButtons() {
        refreshButton.isEnabled = !isMutating
        deleteButton.isEnabled = !isLoading && !isMutating && results.indices.contains(table.selectedRow)
        clearButton.isEnabled = !isLoading && !isMutating && !results.isEmpty
    }

    private func loadResults() {
        loadTask?.cancel()
        loadGeneration &+= 1
        let generation = loadGeneration
        isLoading = true
        loadError = nil
        detail.string = "Loading the private Task Inbox…"
        updateButtons()
        loadTask = Task { [weak self, operations] in
            let outcome = await operations.load()
            guard !Task.isCancelled,
                  let self,
                  self.loadGeneration == generation else { return }
            isLoading = false
            let previouslySelectedID = results.indices.contains(table.selectedRow)
                ? results[table.selectedRow].id
                : nil
            switch outcome {
            case .loaded(let loaded):
                loadError = nil
                results = loaded
            case .unavailable:
                loadError = "The private Task Inbox is unavailable. Existing results were preserved."
                results = []
            }
            table.reloadData()
            if !results.isEmpty {
                let row = previouslySelectedID.flatMap { selectedID in
                    self.results.firstIndex(where: { $0.id == selectedID })
                } ?? 0
                table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            }
            updateDetail()
            updateButtons()
        }
    }

    @objc private func deleteSelectedResult(_ sender: Any?) {
        guard !isLoading, !isMutating, results.indices.contains(table.selectedRow) else { return }
        let result = results[table.selectedRow]
        guard interactions.confirmDelete(result) else { return }
        isMutating = true
        updateButtons()
        defer {
            isMutating = false
            updateButtons()
        }
        do {
            try operations.delete(result.id)
            guard let index = results.firstIndex(where: { $0.id == result.id }) else {
                updateDetail()
                return
            }
            results.remove(at: index)
            table.reloadData()
            if !results.isEmpty {
                table.selectRowIndexes(IndexSet(integer: min(index, results.count - 1)), byExtendingSelection: false)
            }
            updateDetail()
            updateButtons()
        } catch {
            interactions.showFailure(.deleteInboxResult)
        }
    }

    @objc private func clearInbox(_ sender: Any?) {
        guard !isLoading, !isMutating, !results.isEmpty else { return }
        guard interactions.confirmClear(results.count) else { return }
        isMutating = true
        updateButtons()
        defer {
            isMutating = false
            updateButtons()
        }
        do {
            try operations.clear()
            results.removeAll()
            table.reloadData()
            detail.string = "No scheduled results."
            updateButtons()
        } catch {
            interactions.showFailure(.clearInbox)
        }
    }

    @objc private func refreshInbox(_ sender: Any?) {
        guard !isMutating else { return }
        loadResults()
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter
    }()
}
