import AppKit
import ServiceManagement

enum SettingsWindowFailure: Equatable {
    case launchAtLogin
    case launchAtLoginApprovalRequired
    case sshAgentNotChanged
    case sshAgentSavedRuntimeBlocked
    case sshAgentVerification
    case performanceNotChanged
    case performanceSavedRuntimeBlocked
    case performanceVerification
    case restartServices
    case websiteDataNotCleared
    case websiteDataUnavailable

    var title: String {
        switch self {
        case .launchAtLogin:
            "Launch at login could not be changed"
        case .launchAtLoginApprovalRequired:
            "Approve launch at login in System Settings"
        case .sshAgentNotChanged, .sshAgentVerification:
            "SSH agent setting was not changed"
        case .sshAgentSavedRuntimeBlocked:
            "SSH agent setting saved; runtime blocked"
        case .performanceNotChanged, .performanceVerification:
            "Performance setting was not saved"
        case .performanceSavedRuntimeBlocked:
            "Performance setting saved; runtime blocked"
        case .restartServices:
            "Local services did not restart"
        case .websiteDataNotCleared, .websiteDataUnavailable:
            "Embedded website data was not cleared"
        }
    }

    var message: String {
        switch self {
        case .launchAtLogin:
            "macOS kept the previous launch-at-login setting. Review Fulmar in System Settings, then try again."
        case .launchAtLoginApprovalRequired:
            "macOS recorded the request but requires your approval under System Settings → General → Login Items."
        case .sshAgentNotChanged:
            "The previous SSH-agent permission remains in effect. Protected runtime coordination did not complete safely."
        case .sshAgentSavedRuntimeBlocked:
            "The permission was saved, but a fresh verified runtime could not start. Agent work remains blocked until recovery succeeds."
        case .sshAgentVerification:
            "Fulmar could not verify the saved SSH-agent permission, so the previous visible state has been restored."
        case .performanceNotChanged:
            "The previous local performance profile remains in effect. Protected runtime coordination did not complete safely."
        case .performanceSavedRuntimeBlocked:
            "The profile was saved, but a fresh verified runtime could not start. Agent work remains blocked until recovery succeeds."
        case .performanceVerification:
            "Fulmar could not verify the saved performance profile, so it will not present the requested profile as active."
        case .restartServices:
            "The existing runtime was not presented as ready because a fresh verified service did not start safely."
        case .websiteDataNotCleared:
            "Private browser storage was left unchanged because the protected clear operation did not finish safely."
        case .websiteDataUnavailable:
            "Protected website-data coordination is unavailable. No browser storage was changed."
        }
    }
}

enum SettingsLaunchAtLoginStatus: Equatable {
    case disabled
    case enabled
    case requiresApproval
}

@MainActor
struct SettingsWindowInteractions {
    var confirmSSHAgentAccess: () -> Bool
    var confirmWebsiteDataClear: () -> Bool
    var showFailure: (SettingsWindowFailure) -> Void

    static let live = SettingsWindowInteractions(
        confirmSSHAgentAccess: {
            let alert = NSAlert()
            alert.messageText = "Allow SSH agent access?"
            alert.informativeText = "Coding tools will be able to request signatures from your logged-in SSH identities. Enable this only when a local task needs private Git access."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Allow SSH Agent")
            alert.addButton(withTitle: "Keep Blocked")
            return alert.runModal() == .alertFirstButtonReturn
        },
        confirmWebsiteDataClear: {
            let alert = NSAlert()
            alert.messageText = "Clear embedded website data?"
            alert.informativeText = "This clears private browser cookies, caches, and local web storage. Your \(ProductBrand.displayName) projects and tasks are not deleted."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Clear Data")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
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
struct SettingsWindowOperations {
    var launchAtLoginStatus: () throws -> SettingsLaunchAtLoginStatus
    var setLaunchAtLogin: (Bool) throws -> Void
    var defaultModelSelection: () throws -> ModelSelection
    var physicalMemoryBytes: () -> UInt64

    static func live(modelSettingsStore: ModelProviderSettingsStore) -> SettingsWindowOperations {
        SettingsWindowOperations(
            launchAtLoginStatus: {
                switch SMAppService.mainApp.status {
                case .enabled: .enabled
                case .requiresApproval: .requiresApproval
                case .notRegistered, .notFound: .disabled
                @unknown default: .disabled
                }
            },
            setLaunchAtLogin: { enabled in
                if enabled { try SMAppService.mainApp.register() }
                else { try SMAppService.mainApp.unregister() }
            },
            defaultModelSelection: {
                try modelSettingsStore.loadOrMigrate().settings.defaultSelection
            },
            physicalMemoryBytes: { ProcessInfo.processInfo.physicalMemory }
        )
    }
}

/// Native settings are grouped by user intent so security, performance, and
/// recovery controls do not compete in one long engineering-oriented page.
/// The underlying preference keys and protected mutation callbacks stay stable
/// so upgrades preserve existing Local Harness/Fulmar state.
private final class SettingsDocumentView: NSView {
    override var isFlipped: Bool { true }
}

final class SettingsWindowController: NSWindowController {
    static let tabStyle: NSTabViewController.TabStyle = .segmentedControlOnTop
    static let contentTopInset: CGFloat = 18

    var onRestartServices: (() -> Void)?
    /// Completion-bearing replacement for the legacy restart callback. New
    /// integrations use it to keep Settings single-flight until the protected
    /// runtime transition has a verified outcome.
    var onRestartServicesRequested: (@MainActor () async throws -> Void)?
    var onOpenDiagnostics: (() -> Void)?
    var onClearWebData: (() -> Void)?
    /// Completion-bearing replacement for the legacy fire-and-forget callback.
    /// New integrations must use this seam so the Settings UI can report the
    /// protected clear operation's verified success or bounded failure.
    var onClearWebDataRequested: (@MainActor () async throws -> Void)?
    var onOpenPrivacy: (() -> Void)?
    var onOpenPluginTrust: (() -> Void)?
    var onOpenBackups: (() -> Void)?
    var onOpenMenuBarSettings: (() -> Void)?
    var onMigrateCredentials: (() -> Void)?
    var onNotificationsEnabled: (() -> Void)?
    var onPerformanceProfileRequested: (@MainActor (PerformanceProfile) async throws -> Void)?
    var onSSHAgentAccessRequested: (@MainActor (Bool) async throws -> Void)?

    private let preferences: PreferencesStore
    private let operations: SettingsWindowOperations
    private let interactions: SettingsWindowInteractions
    private let typography: NativeTypographyPolicy
    private lazy var launchAtLogin = NSButton(
        checkboxWithTitle: "Launch \(ProductBrand.displayName) when I log in",
        target: nil,
        action: nil
    )
    private let confirmLinks = NSButton(
        checkboxWithTitle: "Confirm before opening links outside the app",
        target: nil,
        action: nil
    )
    private let notifications = NSButton(
        checkboxWithTitle: "Show service and task notifications",
        target: nil,
        action: nil
    )
    private let autoRestart = NSButton(
        checkboxWithTitle: "Automatically recover the agent service after a crash",
        target: nil,
        action: nil
    )
    private let strictLocal = NSButton(
        checkboxWithTitle: "Current route is confined to this Mac",
        target: nil,
        action: nil
    )
    private lazy var unloadIdle = NSButton(
        checkboxWithTitle: "Release local-model memory when \(ProductBrand.displayName) quits",
        target: nil,
        action: nil
    )
    private let allowSSHAgent = NSButton(
        checkboxWithTitle: "Allow coding tools to use my SSH agent",
        target: nil,
        action: nil
    )
    private let appshotRetention = NSPopUpButton()
    private let performanceProfile = NSPopUpButton()
    private lazy var performanceRow = labelledRow("Performance", control: performanceProfile)
    private lazy var localPerformanceSection = section(
        "Local model performance",
        detail: "Balanced is the everyday default for the release-qualified 27B Qwen route. Fulmar adapts its recommendation to this Mac's memory, processor, temperature, and recent local performance. A profile change restarts the verified local runtime."
    )
    private lazy var localPerformanceNote = note(
        "Thermal protection remains authoritative in every profile. Fast reduces heat and latency; Deep increases sustained memory and compute load."
    )
    private lazy var localModelStoreLimitation = note(
        OllamaModelStoreConfigurationError.userSelectionUnavailable.localizedDescription
    )
    private lazy var cloudPerformanceNote = note(
        "The selected cloud or network provider keeps its own model limits. Fulmar does not apply local Fast, Balanced, Deep, Compatibility, memory, or thermal settings to that route."
    )
    private var operationControls: [NSControl] = []
    private var activeOperation: Operation?
    private var operationGeneration: UInt64 = 0
    private var launchAtLoginStatusIsAvailable = true
    private var performanceSelectionIsAvailable = true
    private var selectedModelUsesCompatibilityProfile = false
    private var selectedModelSupportsVariablePerformanceProfiles = true

    private enum Operation: Equatable {
        case preference
        case navigation
        case launchAtLogin
        case sshAgent
        case performance
        case restartServices
        case websiteData

        var subtitle: String {
            switch self {
            case .preference: "Saving setting…"
            case .navigation: "Opening…"
            case .launchAtLogin: "Updating launch at login…"
            case .sshAgent: "Applying SSH-agent permission safely…"
            case .performance: "Applying local performance profile safely…"
            case .restartServices: "Restarting local services safely…"
            case .websiteData: "Clearing embedded website data safely…"
            }
        }
    }

    convenience init(
        preferences: PreferencesStore,
        typography: NativeTypographyPolicy = .standard
    ) {
        let modelSettingsStore = ModelProviderSettingsStore()
        self.init(
            preferences: preferences,
            operations: .live(modelSettingsStore: modelSettingsStore),
            interactions: .live,
            typography: typography
        )
    }

    init(
        preferences: PreferencesStore,
        operations: SettingsWindowOperations,
        interactions: SettingsWindowInteractions,
        typography: NativeTypographyPolicy = .standard
    ) {
        self.preferences = preferences
        self.operations = operations
        self.interactions = interactions
        self.typography = typography
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 560),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "\(ProductBrand.displayName) Settings"
        window.minSize = NSSize(width: 620, height: 500)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.Settings")
        super.init(window: window)
        configureControls()
        window.contentViewController = buildTabs()
        if !window.setFrameUsingName("LocalHarness.Settings") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        refresh()
        super.showWindow(sender)
    }

    private func configureControls() {
        for button in [launchAtLogin, confirmLinks, notifications, autoRestart, unloadIdle, allowSSHAgent] {
            button.target = self
            button.action = #selector(preferenceChanged(_:))
            button.setAccessibilityLabel(button.title)
        }
        strictLocal.isEnabled = false
        strictLocal.toolTip = "The selected provider determines this boundary. External routes require exact-endpoint consent."
        strictLocal.setAccessibilityLabel("Current provider privacy boundary")

        appshotRetention.addItems(withTitles: ["1 day", "7 days", "30 days", "90 days"])
        appshotRetention.target = self
        appshotRetention.action = #selector(retentionChanged(_:))
        appshotRetention.setAccessibilityLabel("Appshot retention")

        performanceProfile.addItems(withTitles: [
            "Fast · 32K context / 4K output",
            "Balanced · 48K context / 8K output",
            "Deep · 64K context / 16K output",
            "Compatibility · 8K context / 2K output"
        ])
        performanceProfile.target = self
        performanceProfile.action = #selector(performanceChanged(_:))
        performanceProfile.setAccessibilityLabel("Local inference performance profile")
        operationControls.append(contentsOf: [
            launchAtLogin, confirmLinks, notifications, autoRestart, unloadIdle,
            allowSSHAgent, appshotRetention, performanceProfile
        ])
    }

    private func buildTabs() -> NSTabViewController {
        let tabs = NSTabViewController()
        // `.toolbar` reserves a large icon-and-title band above the content.
        // These settings are a compact set of peer pages, so the native
        // segmented selector is both clearer and substantially less wasteful.
        tabs.tabStyle = Self.tabStyle
        addTab(to: tabs, controller: tab(
            title: "General",
            views: [
                section(
                    "Everyday use",
                    detail: "Choose how Fulmar starts and communicates without changing where model requests are processed."
                ),
                launchAtLogin,
                notifications,
                confirmLinks,
                actionButton("Open Menu Bar Settings…", action: #selector(openMenuBarSettings(_:))),
                note("On macOS 26, choose Fulmar under System Settings → Menu Bar → Allow in the Menu Bar. macOS—not Fulmar—has final control over whether third-party menu-bar items are displayed.")
            ]
        ))
        addTab(to: tabs, controller: tab(
            title: "Models",
            views: [
                localPerformanceSection,
                cloudPerformanceNote,
                performanceRow,
                strictLocal,
                unloadIdle,
                localPerformanceNote,
                localModelStoreLimitation
            ]
        ))
        addTab(to: tabs, controller: tab(
            title: "Privacy",
            views: [
                section(
                    "Privacy and access",
                    detail: "Review retained data and permissions. Provider credentials remain in macOS Keychain and are never shown here."
                ),
                allowSSHAgent,
                labelledRow("Keep appshots for", control: appshotRetention),
                buttonRow([
                    actionButton("Privacy Dashboard…", action: #selector(openPrivacy(_:))),
                    actionButton("Plugin Security…", action: #selector(openPluginTrust(_:))),
                    actionButton("Backups & Restore…", action: #selector(openBackups(_:)))
                ]),
                actionButton("Move Existing Secrets to Keychain…", action: #selector(migrateCredentials(_:))),
                actionButton("Clear Embedded Website Data…", action: #selector(clearWebsiteData(_:))),
                note("Clearing embedded website data removes only the private WebView cache and storage. Projects, conversations, Workspace files, and Keychain credentials are not deleted.")
            ]
        ))
        addTab(to: tabs, controller: tab(
            title: "Advanced",
            views: [
                section(
                    "Reliability and support",
                    detail: "Recovery actions are safe to use when the app reports a service problem. They do not bypass provider or workspace checks."
                ),
                autoRestart,
                buttonRow([
                    actionButton("Restart Local Services", action: #selector(restartServices(_:))),
                    actionButton("Open Diagnostics", action: #selector(openDiagnostics(_:)))
                ]),
                note("Fulmar keeps the DeepSeek Harness runtime pinned. Runtime upgrades are staged, tested against a copied state, and must preserve a rollback build before installation.")
            ]
        ))
        return tabs
    }

    private func addTab(to tabs: NSTabViewController, controller: NSViewController) {
        let item = NSTabViewItem(viewController: controller)
        item.label = controller.title ?? "Settings"
        tabs.addTabViewItem(item)
    }

    private func tab(title: String, views: [NSView]) -> NSViewController {
        let controller = NSViewController()
        controller.title = title

        let root = NSView()
        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(scroll)
        // A standard AppKit document view is bottom-origin. When a settings page
        // is shorter than its clip view, that leaves a page-dependent empty band
        // above the first heading. A flipped document starts every page at the
        // visible top while preserving native scrolling for longer content.
        let document = SettingsDocumentView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(stack)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: root.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            document.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            document.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            document.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            stack.topAnchor.constraint(equalTo: document.topAnchor, constant: Self.contentTopInset),
            stack.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 34),
            stack.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -34),
            stack.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -24)
        ])
        for view in views where view is NSTextField || view is NSStackView {
            view.widthAnchor.constraint(lessThanOrEqualTo: stack.widthAnchor).isActive = true
        }
        controller.view = root
        return controller
    }

    private func section(_ title: String, detail: String) -> NSView {
        let heading = NSTextField(labelWithString: title)
        heading.font = typography.font(for: .settingsHeading)
        let subtitle = NSTextField(wrappingLabelWithString: detail)
        subtitle.font = typography.font(for: .settingsSubtitle)
        subtitle.textColor = .secondaryLabelColor
        subtitle.maximumNumberOfLines = 5
        let stack = NSStackView(views: [heading, subtitle])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 5
        return stack
    }

    private func note(_ text: String) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = typography.font(for: .settingsNote)
        field.textColor = .tertiaryLabelColor
        field.maximumNumberOfLines = 6
        return field
    }

    private func labelledRow(_ title: String, control: NSView) -> NSStackView {
        let label = NSTextField(labelWithString: title)
        label.setContentHuggingPriority(.required, for: .horizontal)
        let row = NSStackView(views: [label, NSView(), control])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12
        return row
    }

    private func buttonRow(_ buttons: [NSButton]) -> NSStackView {
        // The page stack gives each row the available width. An explicit
        // flexible tail owns that surplus space so Auto Layout never has to
        // choose an arbitrary button to stretch (or report an ambiguous row).
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: buttons + [spacer])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10
        return row
    }

    private func actionButton(_ title: String, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        button.setAccessibilityLabel(title.replacingOccurrences(of: "…", with: ""))
        operationControls.append(button)
        return button
    }

    private func refresh() {
        do {
            let status = try operations.launchAtLoginStatus()
            launchAtLogin.state = status == .enabled ? .on : .off
            launchAtLoginStatusIsAvailable = true
            launchAtLogin.toolTip = status == .requiresApproval
                ? "Approval is waiting in System Settings → General → Login Items."
                : "Start Fulmar automatically after you log in."
        } catch {
            launchAtLogin.state = .off
            launchAtLoginStatusIsAvailable = false
            launchAtLogin.toolTip = "macOS launch-at-login status is temporarily unavailable."
        }
        confirmLinks.state = preferences.confirmExternalLinks ? .on : .off
        notifications.state = preferences.notificationsEnabled ? .on : .off
        autoRestart.state = preferences.autoRestartHarness ? .on : .off
        strictLocal.state = preferences.strictLocalMode ? .on : .off
        strictLocal.title = preferences.strictLocalMode
            ? "Current route is confined to this Mac"
            : "Current route has one approved provider endpoint"
        unloadIdle.state = preferences.unloadModelWhenIdle ? .on : .off
        allowSSHAgent.state = preferences.allowSSHAgent ? .on : .off
        let retention = preferences.appshotRetentionDays
        appshotRetention.selectItem(withTitle: "\(retention) day\(retention == 1 ? "" : "s")")
        do {
            let selection = try operations.defaultModelSelection()
            performanceProfile.selectItem(at: PerformanceProfile.allCases.firstIndex(of: selection.performanceProfile) ?? 1)
            performanceSelectionIsAvailable = true
            selectedModelUsesCompatibilityProfile = selection.isLocalCompatibilityRoute
            selectedModelSupportsVariablePerformanceProfiles = supportsVariablePerformanceProfiles(selection)
            let isLocalRoute = selection.route.provider == BuiltInProviderDescriptors.ollama.id
            performanceRow.isHidden = !isLocalRoute
            localPerformanceSection.isHidden = !isLocalRoute
            localPerformanceNote.isHidden = !isLocalRoute
            localModelStoreLimitation.isHidden = !isLocalRoute
            cloudPerformanceNote.isHidden = isLocalRoute
            if selection.isLocalCompatibilityRoute {
                performanceProfile.toolTip = "This installed model uses Fulmar's fixed 8K/2K compatibility limits."
            } else if selection.isReleaseQualifiedLocalQwen,
                      !selectedModelSupportsVariablePerformanceProfiles {
                performanceProfile.toolTip = "Fast, Balanced, and Deep require at least 48 GB of physical memory for Fulmar's release-qualified Qwen model."
            } else if selection.isReleaseQualifiedLocalQwen {
                performanceProfile.toolTip = "Choose the limits for the release-qualified local Qwen model."
            } else {
                performanceProfile.toolTip = "Local performance profiles do not change cloud or network-provider requests."
            }
        } catch {
            performanceProfile.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .balanced) ?? 1)
            performanceSelectionIsAvailable = false
            selectedModelUsesCompatibilityProfile = false
            selectedModelSupportsVariablePerformanceProfiles = false
            performanceRow.isHidden = false
            localPerformanceSection.isHidden = false
            localPerformanceNote.isHidden = false
            localModelStoreLimitation.isHidden = false
            cloudPerformanceNote.isHidden = true
            performanceProfile.toolTip = "The saved model selection could not be verified."
        }
        updateOperationControls()
    }

    @objc private func preferenceChanged(_ sender: NSButton) {
        guard activeOperation == nil else { refresh(); return }
        if sender === allowSSHAgent {
            let requested = sender.state == .on
            guard let apply = onSSHAgentAccessRequested else {
                refresh()
                interactions.showFailure(.sshAgentNotChanged)
                return
            }
            guard let generation = beginOperation(.sshAgent) else { refresh(); return }
            if requested, !interactions.confirmSSHAgentAccess() {
                _ = finishOperation(.sshAgent, generation: generation)
                return
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                let failure: SettingsWindowFailure?
                do {
                    try await apply(requested)
                    failure = self.preferences.allowSSHAgent == requested ? nil : .sshAgentVerification
                }
                catch {
                    failure = Self.mutationWasCommitted(error)
                        ? .sshAgentSavedRuntimeBlocked
                        : .sshAgentNotChanged
                }
                guard self.finishOperation(.sshAgent, generation: generation) else { return }
                if let failure { self.interactions.showFailure(failure) }
            }
            return
        }
        if sender === launchAtLogin {
            guard launchAtLoginStatusIsAvailable else {
                refresh()
                interactions.showFailure(.launchAtLogin)
                return
            }
            let requested = sender.state == .on
            guard let generation = beginOperation(.launchAtLogin) else { refresh(); return }
            var failed = false
            var approvalRequired = false
            do {
                try operations.setLaunchAtLogin(requested)
                let status = try operations.launchAtLoginStatus()
                approvalRequired = requested && status == .requiresApproval
                failed = requested ? status != .enabled : status != .disabled
            } catch { failed = true }
            guard finishOperation(.launchAtLogin, generation: generation) else { return }
            if approvalRequired { interactions.showFailure(.launchAtLoginApprovalRequired) }
            else if failed { interactions.showFailure(.launchAtLogin) }
            return
        }

        guard let generation = beginOperation(.preference) else { refresh(); return }
        if sender === confirmLinks { preferences.confirmExternalLinks = sender.state == .on }
        if sender === notifications {
            let enabled = sender.state == .on
            preferences.notificationsEnabled = enabled
            if enabled { onNotificationsEnabled?() }
        }
        if sender === autoRestart { preferences.autoRestartHarness = sender.state == .on }
        if sender === unloadIdle { preferences.unloadModelWhenIdle = sender.state == .on }
        _ = finishOperation(.preference, generation: generation)
    }

    @objc private func restartServices(_ sender: Any?) {
        guard activeOperation == nil else { return }
        guard let restart = onRestartServicesRequested else {
            performNavigation(onRestartServices)
            return
        }
        guard let generation = beginOperation(.restartServices) else { return }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let failed: Bool
            do { try await restart(); failed = false }
            catch { failed = true }
            guard self.finishOperation(.restartServices, generation: generation) else { return }
            if failed { self.interactions.showFailure(.restartServices) }
        }
    }
    @objc private func openDiagnostics(_ sender: Any?) { performNavigation(onOpenDiagnostics) }
    @objc private func openPrivacy(_ sender: Any?) { performNavigation(onOpenPrivacy) }
    @objc private func openPluginTrust(_ sender: Any?) { performNavigation(onOpenPluginTrust) }
    @objc private func openBackups(_ sender: Any?) { performNavigation(onOpenBackups) }
    @objc private func openMenuBarSettings(_ sender: Any?) { performNavigation(onOpenMenuBarSettings) }
    @objc private func migrateCredentials(_ sender: Any?) { performNavigation(onMigrateCredentials) }

    @objc private func retentionChanged(_ sender: Any?) {
        guard activeOperation == nil else { refresh(); return }
        let values = [1, 7, 30, 90]
        let index = appshotRetention.indexOfSelectedItem
        guard values.indices.contains(index), let generation = beginOperation(.preference) else {
            refresh()
            return
        }
        preferences.appshotRetentionDays = values[index]
        _ = finishOperation(.preference, generation: generation)
    }

    @objc private func performanceChanged(_ sender: Any?) {
        guard activeOperation == nil else { refresh(); return }
        let profiles = PerformanceProfile.allCases
        let index = performanceProfile.indexOfSelectedItem
        guard profiles.indices.contains(index) else { refresh(); return }
        let stored: ModelSelection
        do { stored = try operations.defaultModelSelection() }
        catch {
            refresh()
            interactions.showFailure(.performanceVerification)
            return
        }
        guard supportsVariablePerformanceProfiles(stored) else { refresh(); return }
        guard stored.performanceProfile != profiles[index] else { refresh(); return }
        guard let apply = onPerformanceProfileRequested else {
            refresh()
            interactions.showFailure(.performanceNotChanged)
            return
        }
        let requested = profiles[index]
        guard let generation = beginOperation(.performance) else { refresh(); return }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let failure: SettingsWindowFailure?
            do {
                try await apply(requested)
                let verified = try? self.operations.defaultModelSelection()
                failure = verified?.performanceProfile == requested
                    && verified.map(self.supportsVariablePerformanceProfiles) == true
                    ? nil
                    : .performanceVerification
            }
            catch {
                failure = Self.mutationWasCommitted(error)
                    ? .performanceSavedRuntimeBlocked
                    : .performanceNotChanged
            }
            guard self.finishOperation(.performance, generation: generation) else { return }
            if let failure { self.interactions.showFailure(failure) }
        }
    }

    @objc private func clearWebsiteData(_ sender: Any?) {
        guard activeOperation == nil else { return }
        let clear: @MainActor () async throws -> Void
        if let requested = onClearWebDataRequested {
            clear = requested
        } else if let legacy = onClearWebData {
            clear = { legacy() }
        } else {
            interactions.showFailure(.websiteDataUnavailable)
            return
        }
        guard let generation = beginOperation(.websiteData) else { return }
        guard interactions.confirmWebsiteDataClear() else {
            _ = finishOperation(.websiteData, generation: generation)
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let failed: Bool
            do { try await clear(); failed = false }
            catch { failed = true }
            guard self.finishOperation(.websiteData, generation: generation) else { return }
            if failed { self.interactions.showFailure(.websiteDataNotCleared) }
        }
    }

    private func performNavigation(_ action: (() -> Void)?) {
        guard let action, let generation = beginOperation(.navigation) else { return }
        action()
        _ = finishOperation(.navigation, generation: generation)
    }

    private func beginOperation(_ operation: Operation) -> UInt64? {
        guard activeOperation == nil else { return nil }
        operationGeneration &+= 1
        activeOperation = operation
        window?.subtitle = operation.subtitle
        updateOperationControls()
        return operationGeneration
    }

    @discardableResult
    private func finishOperation(_ operation: Operation, generation: UInt64) -> Bool {
        guard activeOperation == operation, operationGeneration == generation else { return false }
        activeOperation = nil
        window?.subtitle = ""
        refresh()
        return true
    }

    private func updateOperationControls() {
        let idle = activeOperation == nil
        for control in operationControls { control.isEnabled = idle }
        strictLocal.isEnabled = false
        launchAtLogin.isEnabled = idle && launchAtLoginStatusIsAvailable
        performanceProfile.isEnabled = idle
            && performanceSelectionIsAvailable
            && !selectedModelUsesCompatibilityProfile
            && selectedModelSupportsVariablePerformanceProfiles
    }

    private func supportsVariablePerformanceProfiles(_ selection: ModelSelection) -> Bool {
        selection.isReleaseQualifiedLocalQwen
            && operations.physicalMemoryBytes() >= QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes
    }

    private static func mutationWasCommitted(_ error: Error) -> Bool {
        guard let protected = error as? ProtectedRuntimeMutationCoordinatorError else { return false }
        if case .mutationCommittedButRecoveryFailed = protected { return true }
        return false
    }
}
