import AppKit

enum ProviderProtectedMutationKind: Equatable, Sendable {
    case profile
    case credential
    case activation
}

struct ProviderProtectedMutation: Equatable, Sendable {
    let providerID: ProviderID
    let kind: ProviderProtectedMutationKind
}

enum ProviderProtectedMutationEffect: Equatable, Sendable {
    case notCommitted
    case committed
    case uncertain
}

enum ProviderCenterFailureContext: CaseIterable, Equatable, Sendable {
    case catalogRefresh
    case credentialRecovery
    case customProfileSave
    case customProfileValidation
    case providerActivation
    case credentialMutation
    case performanceProfile
    case modelSelection
}

/// Provider and plugin failures cross an authenticated process boundary, but
/// they still remain hostile display input. Keep every Provider Center catch
/// on one bounded presentation path: known app-owned error types may contribute
/// their fixed message, while an arbitrary `LocalizedError` is reduced to the
/// operation-specific fallback and can never project provider text, paths, or
/// credentials into AppKit or accessibility surfaces.
enum ProviderCenterFailurePresentation {
    static let maximumMessageCharacters = 900

    static func message(for error: Error, context: ProviderCenterFailureContext) -> String {
        if context == .modelSelection {
            return bounded(ProviderSelectionFailurePresentation.message(for: error))
        }

        let fallback: String = switch context {
        case .catalogRefresh:
            "Provider catalog unavailable. Verify that the private Harness runtime is ready, then try again."
        case .credentialRecovery:
            "Credential recovery did not complete. No credential value is shown; review Credential Records before using this provider."
        case .customProfileSave:
            "The custom provider profile was not saved. The previous verified provider state remains in effect or agent work remains blocked."
        case .customProfileValidation:
            "The custom profile is not valid. Review the provider, endpoint, model, and credential-reference fields."
        case .providerActivation:
            "Provider activation did not complete. The previous verified provider state remains in effect or agent work remains blocked."
        case .credentialMutation:
            "The credential change did not complete or could not be verified. Review Credential Records before using this provider."
        case .performanceProfile:
            "The performance profile was not changed. The previous verified local-runtime settings remain active."
        case .modelSelection:
            // Keep the switch total even if this function is refactored and
            // the fast path above is accidentally bypassed. A presentation
            // boundary must never turn an ordinary provider failure into a
            // process trap.
            ProviderSelectionFailurePresentation.message(for: error)
        }

        guard let reason = safeKnownReason(for: error), !reason.isEmpty else {
            return bounded(fallback)
        }
        return bounded("\(fallback) \(reason)")
    }

    private static func safeKnownReason(for error: Error) -> String? {
        switch error {
        case let value as HarnessRPCClientError: value.localizedDescription
        case let value as ModelSelectionCoordinatorError: value.localizedDescription
        case let value as ProviderCredentialRecoveryFailure: value.localizedDescription
        case let value as CustomProviderProfileFailure: value.localizedDescription
        case let value as CustomProviderProfileTransactionError: value.localizedDescription
        case let value as ProviderActivationTransactionError: value.localizedDescription
        case let value as ProtectedRuntimeMutationCoordinatorError: value.localizedDescription
        case let value as ModelProviderSettingsStoreError: value.localizedDescription
        case let value as LocalModelAdmissionError: value.localizedDescription
        case let value as QualifiedLocalModelHostAdmissionError: value.localizedDescription
        case let value as LocalModelSelectionPreflightError: value.localizedDescription
        case let value as OllamaVersionCompatibilityError: value.localizedDescription
        case let value as OllamaModelInspectionError: value.localizedDescription
        case let value as ProviderConsentStoreError: value.localizedDescription
        case is CancellationError: "The operation was cancelled before it completed."
        default: nil
        }
    }

    private static func bounded(_ value: String) -> String {
        let scalars = value.unicodeScalars
        guard scalars.count > maximumMessageCharacters else { return value }
        return String(String.UnicodeScalarView(scalars.prefix(maximumMessageCharacters - 1))) + "…"
    }
}

enum ProviderMutationCompletionPolicy {
    static func disposition(
        for mutation: ProviderProtectedMutation,
        effect: ProviderProtectedMutationEffect,
        defaultProvider: ProviderID
    ) -> ProtectedRuntimeMutationDisposition {
        // Every custom-profile edit revokes that provider's exact-origin grant
        // before changing DSH settings. A committed or uncertain outcome cannot
        // prove that grant was restored, so an active/default route must remain
        // isolated until the user reviews and explicitly re-consents.
        if mutation.kind == .profile,
           effect != .notCommitted,
           mutation.providerID == defaultProvider {
            return .restartProviderControlPlane
        }
        if effect == .committed {
            // Saving a credential for an inactive provider must likewise stay
            // in the isolated control plane until a separate model choice.
            if mutation.kind == .activation,
               mutation.providerID != defaultProvider {
                return .restartProviderControlPlane
            }
        }
        return .restartInference
    }
}

enum ProviderActivationPresentation {
    static func verifiedCredentialMessage(providerDisplayName: String) -> String {
        "Credential saved to Keychain. \(providerDisplayName) has not been contacted yet. Choose a model, review its data boundary, select Use for New Tasks, then run a test task to validate authentication and quota."
    }
}

enum CustomProviderEditorPresentation {
    static func endpointPlaceholder(for wireProtocol: ProviderWireProtocol) -> String {
        wireProtocol == .anthropicMessages
            ? "https://api.anthropic.com"
            : "https://gateway.example/v1"
    }

    static func endpointGuidance(for wireProtocol: ProviderWireProtocol) -> String {
        if wireProtocol == .anthropicMessages {
            return "Anthropic Messages: enter the service origin or deployment prefix without a final /v1. The SDK appends /v1/messages."
        }
        return "OpenAI-compatible: enter the API prefix expected before /chat/completions or /responses; most endpoints end in /v1."
    }

    static let configurationVerifiedMessage = "Profile configuration saved and round-trip verified by Harness. The endpoint has not been contacted. Run a test task to verify authentication, protocol behavior, streaming, tools, and limits."
}

@MainActor
private final class CustomProviderEditorInteraction: NSObject {
    private let protocols: [ProviderWireProtocol]
    private let protocolPicker: NSPopUpButton
    private let endpoint: NSTextField
    private let endpointGuidance: NSTextField
    private let unauthenticated: NSButton
    private let credentialReference: NSTextField
    private let credentialValue: NSSecureTextField

    init(
        protocols: [ProviderWireProtocol],
        protocolPicker: NSPopUpButton,
        endpoint: NSTextField,
        endpointGuidance: NSTextField,
        unauthenticated: NSButton,
        credentialReference: NSTextField,
        credentialValue: NSSecureTextField
    ) {
        self.protocols = protocols
        self.protocolPicker = protocolPicker
        self.endpoint = endpoint
        self.endpointGuidance = endpointGuidance
        self.unauthenticated = unauthenticated
        self.credentialReference = credentialReference
        self.credentialValue = credentialValue
        super.init()
    }

    @objc func refreshProtocolGuidance(_ sender: Any?) {
        let index = min(max(protocolPicker.indexOfSelectedItem, 0), protocols.count - 1)
        let wireProtocol = protocols[index]
        endpoint.placeholderString = CustomProviderEditorPresentation.endpointPlaceholder(for: wireProtocol)
        endpointGuidance.stringValue = CustomProviderEditorPresentation.endpointGuidance(for: wireProtocol)
    }

    @objc func refreshAuthentication(_ sender: Any?) {
        let usesCredential = unauthenticated.state != .on
        credentialReference.isEnabled = usesCredential
        credentialValue.isEnabled = usesCredential
        if !usesCredential {
            // The no-auth action is explicit. Do not retain a hidden credential
            // reference or secret behind disabled controls.
            credentialReference.stringValue = ""
            credentialValue.stringValue = ""
        }
    }
}

enum ProviderCredentialRecoveryPresentation {
    static let foregroundRecoverySource = "Fulmar credential recovery required"

    static func requiresForegroundRepair(_ state: HarnessCredentialView?) -> Bool {
        state?.configured == false
            && state?.writable == false
            && state?.source == foregroundRecoverySource
    }
}

enum ProviderRecordRecoveryAction: Equatable, Sendable {
    case authorizeExisting
    case adoptCurrent
    case remove
}

enum ProviderRecordRecoveryPresentation {
    static func actions(for reason: ProviderRecordCredentialAttentionReason) -> [ProviderRecordRecoveryAction] {
        switch reason {
        case .authorization: [.authorizeExisting]
        case .ambiguous: [.adoptCurrent, .remove]
        case .invalid: [.remove]
        }
    }

    static func reasonLabel(_ reason: ProviderRecordCredentialAttentionReason) -> String {
        switch reason {
        case .authorization: "Needs Keychain authorization"
        case .ambiguous: "Interrupted change needs a decision"
        case .invalid: "Stored record is invalid"
        }
    }
}

struct ProviderCredentialRecordDisplay: Equatable, Sendable {
    let key: String
    let kind: String
    let reason: ProviderRecordCredentialAttentionReason
}

struct ProviderCredentialRecordsInteractions {
    let presentHealthy: @MainActor () -> Void
    let chooseRecord: @MainActor ([ProviderCredentialRecordDisplay]) -> Int?
    let chooseAction: @MainActor (ProviderCredentialRecordDisplay, [ProviderRecordRecoveryAction]) -> Int?
    let confirmRemoval: @MainActor (ProviderCredentialRecordDisplay) -> Bool

    static let production = Self(
            presentHealthy: {
                let alert = NSAlert()
                alert.messageText = "Credential records are healthy"
                alert.informativeText = "No authorization, interrupted-change, or invalid-record condition needs foreground attention. No secret values were read into this window."
                alert.addButton(withTitle: "OK")
                alert.runModal()
            },
            chooseRecord: { records in
                let picker = NSPopUpButton()
                picker.addItems(withTitles: records.map {
                    "\($0.key) · \(ProviderRecordRecoveryPresentation.reasonLabel($0.reason))"
                })
                picker.setAccessibilityLabel("Credential record needing attention")
                picker.widthAnchor.constraint(equalToConstant: 520).isActive = true
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "Review credential record"
                alert.informativeText = "Choose one value-free record identifier. Fulmar will show only actions safe for its current condition."
                alert.accessoryView = picker
                alert.addButton(withTitle: "Review…")
                alert.addButton(withTitle: "Cancel")
                guard alert.runModal() == .alertFirstButtonReturn else { return nil }
                return picker.indexOfSelectedItem
            },
            chooseAction: { record, actions in
                let alert = NSAlert()
                alert.alertStyle = record.reason == .invalid ? .critical : .warning
                alert.messageText = "Repair \(record.key)?"
                let description = record.kind == "unknown" ? "malformed stored" : record.kind
                alert.informativeText = "The credential value remains hidden. The helper will freshly lock and verify this exact \(description) record before and after the chosen action."
                for action in actions {
                    switch action {
                    case .authorizeExisting: alert.addButton(withTitle: "Authorize Existing…")
                    case .adoptCurrent: alert.addButton(withTitle: "Adopt Current Record")
                    case .remove: alert.addButton(withTitle: record.reason == .invalid ? "Remove Invalid Record…" : "Remove Record…")
                    }
                }
                alert.addButton(withTitle: "Cancel")
                let index = alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
                return index >= 0 ? index : nil
            },
            confirmRemoval: { record in
                let alert = NSAlert()
                alert.alertStyle = .critical
                alert.messageText = "Permanently remove \(record.key)?"
                alert.informativeText = "This removes only the exact freshly locked Keychain record. The secret is never displayed. This cannot be undone."
                alert.addButton(withTitle: "Remove Record")
                alert.addButton(withTitle: "Cancel")
                return alert.runModal() == .alertFirstButtonReturn
            }
        )
}

@MainActor
protocol ProviderSelectionCommitting: AnyObject {
    func commit(
        selection: ModelSelection,
        descriptor: ProviderDescriptor
    ) async throws -> ProviderSelectionCommitResult
}

extension ProviderSelectionTransaction: ProviderSelectionCommitting {}

/// Native, provider-neutral control plane for the default route used by new
/// Quick Chats and scheduled tasks. DSH remains authoritative for the model
/// catalog and for the current route of an already-open Harness session.
final class ProviderCenterWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    var onSelectionCommitted: ((ModelSelection, DataBoundary) -> Void)?
    var onOpenHarnessProviderSettings: (() -> Void)?
    var onPrepareProtectedMutation: (@MainActor (ProviderProtectedMutation) async throws -> Void)?
    var onProtectedMutationFinished: (@MainActor (ProviderProtectedMutation, ProviderProtectedMutationEffect) async throws -> Void)?
    var onPerformanceProfileRequested: (@MainActor (PerformanceProfile) async throws -> Void)?

    private let coordinator: ModelSelectionCoordinator
    private let credentials: any HarnessProviderCredentialServicing
    private let credentialRecovery: any ProviderCredentialRecoveryServicing
    private let credentialRecordsInteractions: ProviderCredentialRecordsInteractions
    private let credentialMutation: ProviderCredentialMutationVerifier
    private let settingsStore: ModelProviderSettingsStore
    private let preferences: PreferencesStore
    private let selectionTransaction: any ProviderSelectionCommitting
    private let providerActivation: any ProviderActivating
    private let customProfileEditor: any CustomProviderProfileEditing
    private let providerRecoveryCatalogAllowed: @MainActor () -> Bool

    private let providerTable = NSTableView()
    private let modelTable = NSTableView()
    private let searchField = NSSearchField()
    private let statusLabel = NSTextField(wrappingLabelWithString: "Loading providers…")
    private let boundaryLabel = NSTextField(labelWithString: "")
    private let profilePicker = NSPopUpButton()
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let configureButton = NSButton(title: "Provider Settings…", target: nil, action: nil)
    private let addCustomButton = NSButton(title: "Add Custom…", target: nil, action: nil)
    private let credentialRecordsButton = NSButton(title: "Credential Records…", target: nil, action: nil)
    private let commitButton = NSButton(title: "Use for New Tasks", target: nil, action: nil)

    private var providers: [ProviderView] = []
    private var visibleModels: [ModelView] = []
    private var defaultSelection: ModelSelection = .defaultLocal
    private var preferredRoute: ModelRoute?
    private var refreshGeneration = 0
    private var catalogLoading = false
    private var commitInProgress = false
    private var credentialOperationInProgress = false
    private var credentialRecordsGeneration = 0
    /// Lifecycle-driven catalog refreshes can overlap the completion of a
    /// protected provider mutation. Preserve that mutation's actionable result
    /// until the user explicitly refreshes or begins another operation.
    private var operationOutcomeMessage: String?

    init(
        coordinator: ModelSelectionCoordinator,
        credentials: any HarnessProviderCredentialServicing,
        credentialRecovery: any ProviderCredentialRecoveryServicing = ProviderCredentialRecoveryClient(),
        settingsStore: ModelProviderSettingsStore = ModelProviderSettingsStore(),
        consentStore: ProviderConsentStore = ProviderConsentStore(),
        selectionTransaction: (any ProviderSelectionCommitting)? = nil,
        providerActivation: any ProviderActivating,
        customProfileEditor: any CustomProviderProfileEditing,
        preferences: PreferencesStore,
        providerRecoveryCatalogAllowed: @escaping @MainActor () -> Bool = { false },
        credentialRecordsInteractions: ProviderCredentialRecordsInteractions = .production
    ) {
        self.coordinator = coordinator
        self.credentials = credentials
        self.credentialRecovery = credentialRecovery
        self.credentialRecordsInteractions = credentialRecordsInteractions
        credentialMutation = ProviderCredentialMutationVerifier(service: credentials)
        self.settingsStore = settingsStore
        self.preferences = preferences
        self.selectionTransaction = selectionTransaction ?? ProviderSelectionTransaction(
            coordinator: coordinator,
            settingsStore: settingsStore,
            consentStore: consentStore,
            preferences: preferences
        )
        self.providerActivation = providerActivation
        self.customProfileEditor = customProfileEditor
        self.providerRecoveryCatalogAllowed = providerRecoveryCatalogAllowed
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Models & Providers"
        window.subtitle = "Choose where new work runs"
        window.minSize = NSSize(width: 760, height: 500)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.ProviderCenter")
        super.init(window: window)
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.ProviderCenter") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        loadStoredSelection()
        super.showWindow(sender)
        refresh()
    }

    func refresh() {
        let routeToRestore = selectedRoute ?? preferredRoute ?? defaultSelection.route
        preferredRoute = routeToRestore
        refreshGeneration += 1
        let generation = refreshGeneration
        setLoading(true, message: "Checking the live model catalog…")
        Task { [weak self] in
            guard let self else { return }
            do {
                let catalog = try await coordinator.loadCatalog()
                await MainActor.run {
                    guard generation == self.refreshGeneration else { return }
                    self.providers = catalog.providers
                    self.providerTable.reloadData()
                    self.restoreProviderSelection(preferredRoute: routeToRestore)
                    self.setLoading(false, message: self.operationOutcomeMessage ?? self.catalogSummary)
                }
            } catch {
                let recoveryCatalog = self.providerRecoveryCatalogAllowed()
                    ? await self.coordinator.providerRecoverySetupCatalog()
                    : nil
                await MainActor.run {
                    guard generation == self.refreshGeneration else { return }
                    // The actor hop above is intentionally rechecked at the
                    // presentation boundary. A runtime that left recovery in
                    // the meantime must not retain recovery-only affordances.
                    let currentRecoveryCatalog = self.providerRecoveryCatalogAllowed()
                        ? recoveryCatalog : nil
                    self.providers = currentRecoveryCatalog?.providers ?? []
                    self.visibleModels = []
                    self.providerTable.reloadData()
                    self.modelTable.reloadData()
                    // A setup catalog is an affordance, not a routing
                    // authority. Do not carry a stale/default row selection
                    // into it; the user must explicitly choose a provider,
                    // and no model exists until DSH verifies the live catalog.
                    self.providerTable.deselectAll(nil)
                    self.modelTable.deselectAll(nil)
                    self.updateControls()
                    self.setLoading(
                        false,
                        message: currentRecoveryCatalog == nil
                            ? ProviderCenterFailurePresentation.message(
                                for: error,
                                context: .catalogRefresh
                            )
                            : "The live catalog is temporarily unavailable. Reviewed built-in provider setup remains available; no model or network route will be selected until Harness verifies it."
                    )
                }
            }
        }
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        tableView === providerTable ? providers.count : visibleModels.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let tableColumn else { return nil }
        let field = NSTextField(labelWithString: "")
        field.lineBreakMode = .byTruncatingTail
        if tableView === providerTable {
            guard providers.indices.contains(row) else { return nil }
            let provider = providers[row]
            switch tableColumn.identifier.rawValue {
            case "boundary":
                field.stringValue = boundaryGlyph(provider.boundary)
                field.textColor = boundaryColor(provider.boundary)
                field.alignment = .center
                field.toolTip = provider.boundary.displayName
            case "state":
                field.stringValue = stateText(provider)
                field.textColor = stateColor(provider)
            default:
                field.stringValue = provider.displayName
                field.font = .systemFont(ofSize: 13, weight: provider.id == defaultSelection.route.provider ? .semibold : .regular)
                if provider.id == defaultSelection.route.provider { field.stringValue += "  · Default" }
            }
        } else {
            guard visibleModels.indices.contains(row) else { return nil }
            let model = visibleModels[row]
            switch tableColumn.identifier.rawValue {
            case "capabilities":
                var values: [String] = []
                if model.capabilities.reasoning == .supported { values.append("Reasoning") }
                if model.capabilities.inputModalities.contains(.image) { values.append("Vision") }
                if model.capabilities.toolUse == .supported { values.append("Tools") }
                field.stringValue = values.isEmpty ? "—" : values.joined(separator: " · ")
                field.textColor = .secondaryLabelColor
            default:
                field.stringValue = model.displayName
                if model.id == defaultSelection.route.model,
                   selectedProvider?.id == defaultSelection.route.provider {
                    field.stringValue += "  · Default"
                    field.font = .systemFont(ofSize: 13, weight: .semibold)
                }
                field.toolTip = model.detail ?? model.id.rawValue
            }
        }
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard let table = notification.object as? NSTableView else { return }
        if table === providerTable {
            if let provider = selectedProvider, preferredRoute?.provider != provider.id {
                preferredRoute = defaultSelection.route.provider == provider.id ? defaultSelection.route : nil
            }
            updateVisibleModels(selectDefault: true)
        } else if let route = selectedRoute {
            preferredRoute = route
        }
        updateControls()
    }

    func controlTextDidChange(_ obj: Notification) {
        guard obj.object as? NSSearchField === searchField else { return }
        updateVisibleModels(selectDefault: false)
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let title = NSTextField(labelWithString: "Models & Providers")
        title.font = .systemFont(ofSize: 22, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: "Local models keep prompts on this Mac. Cloud and network providers are used only after an explicit boundary confirmation.")
        subtitle.textColor = .secondaryLabelColor

        statusLabel.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 12)
        boundaryLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        boundaryLabel.alignment = .right

        searchField.placeholderString = "Search models"
        searchField.delegate = self
        searchField.setAccessibilityLabel("Search provider models")

        let providerName = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("provider"))
        providerName.title = "Provider"; providerName.width = 155
        let providerState = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("state"))
        providerState.title = "Status"; providerState.width = 90
        let providerBoundary = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("boundary"))
        providerBoundary.title = ""; providerBoundary.width = 28
        [providerName, providerState, providerBoundary].forEach(providerTable.addTableColumn)
        providerTable.delegate = self; providerTable.dataSource = self
        providerTable.rowHeight = 30; providerTable.usesAlternatingRowBackgroundColors = true
        providerTable.setAccessibilityLabel("Providers")

        let modelName = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("model"))
        modelName.title = "Model"; modelName.width = 330
        let capabilities = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("capabilities"))
        capabilities.title = "Capabilities"; capabilities.width = 190
        [modelName, capabilities].forEach(modelTable.addTableColumn)
        modelTable.delegate = self; modelTable.dataSource = self
        modelTable.rowHeight = 30; modelTable.usesAlternatingRowBackgroundColors = true
        modelTable.setAccessibilityLabel("Models")

        let providersScroll = NSScrollView()
        providersScroll.documentView = providerTable
        providersScroll.hasVerticalScroller = true
        providersScroll.hasHorizontalScroller = true
        let modelsScroll = NSScrollView()
        modelsScroll.documentView = modelTable
        modelsScroll.hasVerticalScroller = true
        modelsScroll.hasHorizontalScroller = true
        providersScroll.translatesAutoresizingMaskIntoConstraints = false
        modelsScroll.translatesAutoresizingMaskIntoConstraints = false

        let lists = NSStackView(views: [providersScroll, modelsScroll])
        lists.orientation = .horizontal; lists.spacing = 12; lists.distribution = .fill
        providersScroll.widthAnchor.constraint(equalToConstant: 300).isActive = true

        profilePicker.addItems(withTitles: [
            "Fast · 32K context / 4K output",
            "Balanced · 48K context / 8K output",
            "Deep · 64K context / 16K output",
            "Compatibility · 8K context / 2K output"
        ])
        profilePicker.target = self; profilePicker.action = #selector(profileChanged(_:))
        profilePicker.setAccessibilityLabel("Local model performance")
        refreshButton.target = self; refreshButton.action = #selector(refreshAction(_:))
        configureButton.target = self; configureButton.action = #selector(configure(_:))
        addCustomButton.target = self; addCustomButton.action = #selector(addCustomProvider(_:))
        addCustomButton.setAccessibilityLabel("Add custom provider profile")
        credentialRecordsButton.target = self
        credentialRecordsButton.action = #selector(reviewCredentialRecords(_:))
        credentialRecordsButton.setAccessibilityLabel("Review credential records needing attention")
        commitButton.target = self; commitButton.action = #selector(commit(_:)); commitButton.keyEquivalent = "\r"

        let providerActions = NSStackView(views: [
            profilePicker, refreshButton, addCustomButton, configureButton, credentialRecordsButton, NSView()
        ])
        providerActions.orientation = .horizontal
        providerActions.spacing = 8
        let commitActions = NSStackView(views: [NSView(), commitButton])
        commitActions.orientation = .horizontal
        commitActions.spacing = 8
        let footer = NSStackView(views: [providerActions, commitActions])
        footer.orientation = .vertical
        footer.alignment = .width
        footer.spacing = 8
        let statusRow = NSStackView(views: [statusLabel, NSView(), boundaryLabel])
        statusRow.orientation = .horizontal; statusRow.spacing = 8

        let stack = NSStackView(views: [title, subtitle, searchField, statusRow, lists, footer])
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        lists.translatesAutoresizingMaskIntoConstraints = false
        footer.translatesAutoresizingMaskIntoConstraints = false
        statusRow.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 24),
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -20),
            subtitle.widthAnchor.constraint(equalTo: stack.widthAnchor),
            searchField.widthAnchor.constraint(equalTo: stack.widthAnchor),
            statusRow.widthAnchor.constraint(equalTo: stack.widthAnchor),
            lists.widthAnchor.constraint(equalTo: stack.widthAnchor),
            lists.heightAnchor.constraint(greaterThanOrEqualToConstant: 320),
            footer.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        controller.view = root
        updateControls()
        return controller
    }

    private var selectedProvider: ProviderView? {
        providers.indices.contains(providerTable.selectedRow) ? providers[providerTable.selectedRow] : nil
    }

    private var selectedModel: ModelView? {
        visibleModels.indices.contains(modelTable.selectedRow) ? visibleModels[modelTable.selectedRow] : nil
    }

    private var selectedRoute: ModelRoute? {
        guard let provider = selectedProvider, let model = selectedModel else { return nil }
        return ModelRoute(provider: provider.id, model: model.id)
    }

    private var catalogSummary: String {
        let modelCount = providers.reduce(0) { $0 + $1.models.count }
        return "\(providers.count) provider\(providers.count == 1 ? "" : "s") · \(modelCount) model\(modelCount == 1 ? "" : "s") reported by Harness"
    }

    private func loadStoredSelection() {
        defaultSelection = (try? settingsStore.loadOrMigrate().settings.defaultSelection) ?? .defaultLocal
        preferredRoute = defaultSelection.route
        profilePicker.selectItem(at: PerformanceProfile.allCases.firstIndex(of: defaultSelection.performanceProfile) ?? 1)
    }

    private func restoreProviderSelection(preferredRoute route: ModelRoute? = nil) {
        let providerID = route?.provider ?? defaultSelection.route.provider
        let index = providers.firstIndex { $0.id == providerID }
            ?? providers.firstIndex { $0.id == defaultSelection.route.provider }
            ?? (providers.isEmpty ? nil : 0)
        if let index { providerTable.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false) }
        updateVisibleModels(selectDefault: true)
    }

    private func updateVisibleModels(selectDefault: Bool) {
        let provider = selectedProvider
        let query = searchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        visibleModels = (provider?.models ?? []).filter { model in
            query.isEmpty || model.displayName.lowercased().contains(query)
                || model.id.rawValue.lowercased().contains(query)
                || (model.detail?.lowercased().contains(query) ?? false)
        }
        modelTable.reloadData()

        let retainedModel: ModelID? = {
            guard let provider else { return nil }
            if preferredRoute?.provider == provider.id { return preferredRoute?.model }
            if selectDefault, defaultSelection.route.provider == provider.id { return defaultSelection.route.model }
            return nil
        }()
        var target = retainedModel.flatMap { modelID in
            visibleModels.firstIndex { $0.id == modelID }
        }
        if target == nil, selectDefault, query.isEmpty, !visibleModels.isEmpty {
            target = 0
        }
        if let target {
            modelTable.selectRowIndexes(IndexSet(integer: target), byExtendingSelection: false)
            if let provider, visibleModels.indices.contains(target) {
                preferredRoute = ModelRoute(provider: provider.id, model: visibleModels[target].id)
            }
        } else {
            modelTable.deselectAll(nil)
        }
        updateControls()
    }

    private func updateControls() {
        let provider = selectedProvider
        let model = selectedModel
        commitButton.isEnabled = !catalogLoading && !commitInProgress && !credentialOperationInProgress
            && provider?.configurationState == .ready && model != nil
        configureButton.isEnabled = !catalogLoading && !commitInProgress && !credentialOperationInProgress && provider != nil
        addCustomButton.isEnabled = !catalogLoading && !commitInProgress && !credentialOperationInProgress
        credentialRecordsButton.isEnabled = !catalogLoading && !commitInProgress && !credentialOperationInProgress
        searchField.isEnabled = !catalogLoading && !commitInProgress
        let selectedLocalCompatibility = provider?.id == BuiltInProviderDescriptors.ollama.id
            && model.map { $0.id != BuiltInProviderDescriptors.qwenLocalModel.id } == true
        profilePicker.isEnabled = !catalogLoading && !commitInProgress
            && provider?.id == BuiltInProviderDescriptors.ollama.id
            && !selectedLocalCompatibility
        if selectedLocalCompatibility {
            profilePicker.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .compatibility) ?? 3)
            profilePicker.toolTip = "Compatibility models use a fixed 8K context and 2K output cap."
        } else if provider?.id == BuiltInProviderDescriptors.ollama.id {
            profilePicker.toolTip = "Performance limits for the release-qualified local Qwen route."
        } else {
            profilePicker.toolTip = "Local performance profiles do not change cloud or network providers."
        }
        configureButton.title = provider.map { selected in
            if isNativeCustomProvider(selected.descriptor) { return "Edit Profile…" }
            return ProviderActivationTransaction.supportsNativeActivation(selected.descriptor)
                && selected.configurationState != .unavailable ? "API Key…" : "Provider Settings…"
        } ?? "Provider Settings…"
        if let provider {
            boundaryLabel.stringValue = "\(boundaryGlyph(provider.boundary))  \(provider.boundary.displayName)"
            boundaryLabel.textColor = boundaryColor(provider.boundary)
            if let failure = provider.failureMessage, !failure.isEmpty { statusLabel.stringValue = failure }
        } else {
            boundaryLabel.stringValue = ""
        }
    }

    private func setLoading(_ loading: Bool, message: String) {
        catalogLoading = loading
        statusLabel.stringValue = message
        refreshButton.isEnabled = !loading && !commitInProgress
        providerTable.isEnabled = !loading && !commitInProgress
        modelTable.isEnabled = !loading && !commitInProgress
        updateControls()
    }

    private func setCredentialOperationInProgress(_ inProgress: Bool) {
        credentialOperationInProgress = inProgress
        updateControls()
    }

    private func setCommitting(_ committing: Bool, message: String) {
        commitInProgress = committing
        statusLabel.stringValue = message
        refreshButton.isEnabled = !committing && !catalogLoading
        providerTable.isEnabled = !committing && !catalogLoading
        modelTable.isEnabled = !committing && !catalogLoading
        updateControls()
    }

    private func stateText(_ provider: ProviderView) -> String {
        if provider.failureMessage != nil { return "Unavailable" }
        switch provider.configurationState {
        case .ready: return isNativeCustomProvider(provider.descriptor) ? "Configured" : "Ready"
        case .needsCredential: return "Needs key"
        case .dormant: return "Not set up"
        case .unavailable: return "Unavailable"
        }
    }

    private func stateColor(_ provider: ProviderView) -> NSColor {
        guard provider.configurationState == .ready, provider.failureMessage == nil else {
            return .secondaryLabelColor
        }
        return isNativeCustomProvider(provider.descriptor) ? .systemBlue : .systemGreen
    }

    private func boundaryGlyph(_ boundary: DataBoundary) -> String {
        switch boundary { case .onDevice: return "●"; case .localNetwork: return "◆"; case .cloud: return "☁" }
    }

    private func boundaryColor(_ boundary: DataBoundary) -> NSColor {
        switch boundary { case .onDevice: return .systemGreen; case .localNetwork: return .systemOrange; case .cloud: return .systemBlue }
    }

    private func resolvedExternalOrigin(for provider: ProviderView) -> ProviderEndpointOrigin? {
        guard provider.boundary.requiresExplicitConsent,
              let endpoint = provider.descriptor.defaultBaseURL,
              ProviderNetworkOrigin(url: endpoint) != nil
        else { return nil }
        return ProviderEndpointOrigin(url: endpoint)
    }

    private func confirmExternalBoundary(_ provider: ProviderView, origin: ProviderEndpointOrigin) -> Bool {
        guard provider.boundary.requiresExplicitConsent else { return true }
        let host = origin.host.contains(":") ? "[\(origin.host)]" : origin.host
        let destination = "\(origin.scheme)://\(host):\(origin.port)"
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = provider.boundary == .cloud ? "Use \(provider.displayName) in the cloud?" : "Use \(provider.displayName) on your network?"
        alert.informativeText = Self.externalBoundaryDisclosure(
            provider: provider,
            destination: destination
        )
        alert.addButton(withTitle: provider.boundary == .cloud ? "Use Cloud Provider" : "Use Network Provider")
        alert.addButton(withTitle: "Keep Work on This Mac")
        return alert.runModal() == .alertFirstButtonReturn
    }

    static func externalBoundaryDisclosure(provider: ProviderView, destination: String) -> String {
        var disclosure = "Prompts, attached content, tool results, and conversation context for tasks using this provider may leave this Mac and be sent to exactly \(destination). \(ProductBrand.displayName) will allow only this scheme, host, and port."
        if let reference = provider.descriptor.credentialReference {
            disclosure += " To authenticate, the secret stored in macOS Keychain under credential reference \(reference.rawValue) may be sent only to this exact destination. The credential value is never shown in this window or stored in the consent record."
        }
        return disclosure
    }

    @objc private func refreshAction(_ sender: Any?) {
        operationOutcomeMessage = nil
        refresh()
    }
    @objc private func addCustomProvider(_ sender: Any?) { presentCustomProfileEditor(provider: nil) }
    @objc private func reviewCredentialRecords(_ sender: Any?) {
        credentialRecordsGeneration += 1
        let generation = credentialRecordsGeneration
        setCredentialOperationInProgress(true)
        statusLabel.stringValue = "Checking private credential records without reading their values into the app…"
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let attention = try await credentialRecovery.listRecordAttention()
                guard generation == credentialRecordsGeneration else { return }
                setCredentialOperationInProgress(false)
                presentRecordAttention(attention, generation: generation)
            } catch {
                guard generation == credentialRecordsGeneration else { return }
                setCredentialOperationInProgress(false)
                statusLabel.stringValue = "Credential records could not be checked. Verify that the private Harness runtime is ready, then try again."
            }
        }
    }

    private func presentRecordAttention(_ attention: [ProviderRecordCredentialAttention], generation: Int) {
        guard generation == credentialRecordsGeneration else { return }
        guard !attention.isEmpty else {
            credentialRecordsInteractions.presentHealthy()
            guard generation == credentialRecordsGeneration else { return }
            statusLabel.stringValue = "No credential records need attention."
            return
        }
        let displays = attention.map {
            ProviderCredentialRecordDisplay(key: $0.key, kind: $0.kind, reason: $0.reason)
        }
        guard let index = credentialRecordsInteractions.chooseRecord(displays) else {
            statusLabel.stringValue = "Credential record review was cancelled. Nothing was changed."
            return
        }
        guard generation == credentialRecordsGeneration else { return }
        guard attention.indices.contains(index) else {
            statusLabel.stringValue = "Credential record recovery was not started because the selection was invalid."
            return
        }
        presentRecordRecovery(attention[index], generation: generation)
    }

    private func presentRecordRecovery(_ item: ProviderRecordCredentialAttention, generation: Int) {
        guard generation == credentialRecordsGeneration else { return }
        let actions = ProviderRecordRecoveryPresentation.actions(for: item.reason)
        let display = ProviderCredentialRecordDisplay(key: item.key, kind: item.kind, reason: item.reason)
        guard let index = credentialRecordsInteractions.chooseAction(display, actions) else {
            statusLabel.stringValue = "Credential record review was cancelled. Nothing was changed."
            return
        }
        guard generation == credentialRecordsGeneration else { return }
        guard actions.indices.contains(index) else {
            statusLabel.stringValue = "Credential record recovery was not started because the selection was invalid."
            return
        }
        let action = actions[index]
        if action == .remove {
            guard credentialRecordsInteractions.confirmRemoval(display) else {
                statusLabel.stringValue = "Credential record review was cancelled. Nothing was changed."
                return
            }
            guard generation == credentialRecordsGeneration else { return }
        }
        performRecordRecovery(item: item, action: action, generation: generation)
    }

    private func performRecordRecovery(
        item: ProviderRecordCredentialAttention,
        action: ProviderRecordRecoveryAction,
        generation: Int
    ) {
        guard generation == credentialRecordsGeneration else { return }
        guard onPrepareProtectedMutation != nil, onProtectedMutationFinished != nil else {
            statusLabel.stringValue = "Credential record repair is blocked because protected runtime quiescence is unavailable."
            return
        }
        setCredentialOperationInProgress(true)
        statusLabel.stringValue = "Repairing and freshly verifying \(item.key)…"
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                _ = try await performProtectedMutation(
                    ProviderProtectedMutation(providerID: defaultSelection.route.provider, kind: .credential)
                ) {
                    switch action {
                    case .authorizeExisting: try await self.credentialRecovery.authorizeRecord(item.key)
                    case .adoptCurrent: try await self.credentialRecovery.adoptCurrentRecord(item.key)
                    case .remove: try await self.credentialRecovery.removeCurrentRecord(item.key)
                    }
                }
                guard generation == credentialRecordsGeneration else { return }
                setCredentialOperationInProgress(false)
                operationOutcomeMessage = "Credential record recovery completed and was freshly verified."
                statusLabel.stringValue = operationOutcomeMessage ?? "Credential record recovery completed."
                refresh()
            } catch {
                guard generation == credentialRecordsGeneration else { return }
                setCredentialOperationInProgress(false)
                operationOutcomeMessage = "Credential record recovery could not be verified. Review Credential Records before using the affected provider."
                statusLabel.stringValue = operationOutcomeMessage ?? "Credential record recovery could not be verified."
                refresh()
            }
        }
    }
    @objc private func configure(_ sender: Any?) {
        guard let provider = selectedProvider else { return }
        if isNativeCustomProvider(provider.descriptor) {
            presentCustomProfileEditor(provider: provider)
            return
        }
        if provider.configurationState == .unavailable {
            onOpenHarnessProviderSettings?()
            return
        }
        guard ProviderActivationTransaction.supportsNativeActivation(provider.descriptor),
              let reference = provider.descriptor.credentialReference else {
            onOpenHarnessProviderSettings?()
            return
        }
        setCredentialOperationInProgress(true)
        statusLabel.stringValue = "Checking the Keychain-backed credential state…"
        Task { [weak self] in
            guard let self else { return }
            do {
                let description = try await credentials.describeCredentials([reference])
                let state = description.credentials[reference.rawValue]
                await MainActor.run {
                    self.setCredentialOperationInProgress(false)
                    if ProviderCredentialRecoveryPresentation.requiresForegroundRepair(state) {
                        self.presentCredentialRecovery(provider: provider, reference: reference)
                    } else {
                        self.presentCredentialEditor(provider: provider, reference: reference, state: state)
                    }
                }
            } catch {
                await MainActor.run {
                    self.setCredentialOperationInProgress(false)
                    self.statusLabel.stringValue = "Fulmar could not check the private credential service. Verify that the Harness runtime is ready, then try again. No Keychain value was changed."
                }
            }
        }
    }

    private func presentCredentialRecovery(provider: ProviderView, reference: CredentialReference) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Repair \(provider.displayName) credential access?"
        alert.informativeText = "Fulmar could not verify this exact Keychain reference. You can authorize the existing item, or explicitly resolve an interrupted change. No secret is shown to this window."
        alert.addButton(withTitle: "Authorize Existing…")
        alert.addButton(withTitle: "Recovery Options…")
        alert.addButton(withTitle: "Cancel")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            performForegroundCredentialRecovery(
                provider: provider,
                message: "Waiting for macOS to authorize the exact existing credential…"
            ) {
                try await self.credentialRecovery.authorizeExisting(reference)
            }
        case .alertSecondButtonReturn:
            presentInterruptedCredentialRecovery(provider: provider, reference: reference)
        default:
            statusLabel.stringValue = "Credential repair was cancelled. The Keychain item was not changed."
        }
    }

    private func presentInterruptedCredentialRecovery(
        provider: ProviderView,
        reference: CredentialReference
    ) {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Resolve interrupted credential state"
        alert.informativeText = "Choose what Fulmar should do with the exact current Keychain value. Every choice re-reads and verifies it under the credential transaction lock."
        alert.addButton(withTitle: "Adopt Current Key")
        alert.addButton(withTitle: "Replace Key…")
        alert.addButton(withTitle: "Remove Key…")
        alert.addButton(withTitle: "Cancel")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            let confirm = NSAlert()
            confirm.alertStyle = .warning
            confirm.messageText = "Trust the current Keychain value?"
            confirm.informativeText = "Fulmar will mark the exact freshly re-read value as the credential for \(provider.displayName). The value will remain hidden."
            confirm.addButton(withTitle: "Adopt Current Key")
            confirm.addButton(withTitle: "Cancel")
            guard confirm.runModal() == .alertFirstButtonReturn else { return }
            performForegroundCredentialRecovery(
                provider: provider,
                message: "Adopting and verifying the exact current Keychain value…"
            ) { try await self.credentialRecovery.adoptCurrent(reference) }
        case .alertSecondButtonReturn:
            presentReplacementForInterruptedCredential(provider: provider, reference: reference)
        case .alertThirdButtonReturn:
            let confirm = NSAlert()
            confirm.alertStyle = .critical
            confirm.messageText = "Remove this Keychain credential?"
            confirm.informativeText = "This permanently removes the exact current credential for \(provider.displayName). Provider access will stop until a new key is saved."
            confirm.addButton(withTitle: "Remove Key")
            confirm.addButton(withTitle: "Cancel")
            guard confirm.runModal() == .alertFirstButtonReturn else { return }
            performForegroundCredentialRecovery(
                provider: provider,
                message: "Removing and verifying the exact current Keychain value…"
            ) { try await self.credentialRecovery.removeCurrent(reference) }
        default:
            statusLabel.stringValue = "Credential recovery was cancelled. The Keychain item was not changed."
        }
    }

    private func presentReplacementForInterruptedCredential(
        provider: ProviderView,
        reference: CredentialReference
    ) {
        let field = NSSecureTextField(string: "")
        field.placeholderString = "Enter replacement API key"
        field.widthAnchor.constraint(equalToConstant: 430).isActive = true
        field.setAccessibilityLabel("Replacement \(provider.displayName) API key")
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Replace the current Keychain credential?"
        alert.informativeText = "Fulmar will freshly re-read the current value, replace it with this key, and verify the final value before retiring recovery state."
        alert.accessoryView = field
        alert.addButton(withTitle: "Replace Key")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        field.stringValue = ""
        guard !value.isEmpty, value.utf8.count <= 32 * 1_024,
              !value.unicodeScalars.contains(where: CharacterSet.newlines.contains) else {
            statusLabel.stringValue = "The credential was not changed. Enter a non-empty key without line breaks."
            return
        }
        performForegroundCredentialRecovery(
            provider: provider,
            message: "Replacing and verifying the exact Keychain credential…"
        ) { try await self.credentialRecovery.replaceCurrent(reference, value: value) }
    }

    private func performForegroundCredentialRecovery(
        provider: ProviderView,
        message: String,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        guard onPrepareProtectedMutation != nil, onProtectedMutationFinished != nil else {
            statusLabel.stringValue = "Credential repair is blocked because protected runtime quiescence is unavailable."
            return
        }
        setCredentialOperationInProgress(true)
        statusLabel.stringValue = message
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                _ = try await self.performProtectedMutation(
                    ProviderProtectedMutation(providerID: provider.id, kind: .credential),
                    mutation: operation
                )
                self.setCredentialOperationInProgress(false)
                self.operationOutcomeMessage = "Credential recovery completed and was verified. Refreshing the provider in a fresh runtime…"
                self.statusLabel.stringValue = self.operationOutcomeMessage ?? "Credential recovery completed."
                self.refresh()
            } catch {
                self.setCredentialOperationInProgress(false)
                let message = ProviderCenterFailurePresentation.message(
                    for: error,
                    context: .credentialRecovery
                )
                self.operationOutcomeMessage = message
                self.statusLabel.stringValue = message
                self.refresh()
            }
        }
    }

    private func isNativeCustomProvider(_ descriptor: ProviderDescriptor) -> Bool {
        descriptor.adapterKind == .piAI
            && descriptor.settingsNamespace == "llm-pi-ai"
            && descriptor.settingsPath == ["providers", descriptor.id.rawValue]
            && !BuiltInProviderDescriptors.all.contains(where: { $0.id == descriptor.id })
            && descriptor.supportsNativeProfileEditing
    }

    private func performProtectedMutation<Result>(
        _ request: ProviderProtectedMutation,
        effect: @MainActor (Result) -> ProviderProtectedMutationEffect = { _ in .committed },
        mutation: @MainActor () async throws -> Result
    ) async throws -> Result {
        guard let prepare = onPrepareProtectedMutation,
              let finished = onProtectedMutationFinished else {
            throw CustomProviderProfileFailure.mutationNotVerified
        }
        var prepared = false
        let outcome: Swift.Result<Result, Error>
        do {
            outcome = .success(try await ProviderStateMutationSafetyPolicy.performMutation(
                targetProvider: request.providerID,
                prepare: { _ in
                    try await prepare(request)
                    prepared = true
                },
                mutation: mutation
            ))
        } catch {
            outcome = .failure(error)
        }
        if prepared {
            let mutationEffect: ProviderProtectedMutationEffect
            switch outcome {
            case .success(let value): mutationEffect = effect(value)
            case .failure: mutationEffect = .notCommitted
            }
            do { try await finished(request, mutationEffect) }
            catch let recoveryError {
                if case .failure = outcome {
                    let kind: ProtectedRuntimeMutationKind = switch request.kind {
                    case .profile: .providerProfile
                    case .credential: .providerCredential
                    case .activation: .providerActivation
                    }
                    throw ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(
                        kind: kind
                    )
                }
                throw recoveryError
            }
        }
        return try outcome.get()
    }

    private func presentCustomProfileEditor(provider: ProviderView?) {
        let providerID = NSTextField(string: provider?.id.rawValue ?? "")
        providerID.placeholderString = "private-gateway"
        providerID.isEnabled = provider == nil
        let displayName = NSTextField(string: provider?.displayName ?? "")
        displayName.placeholderString = "Private Gateway"
        let protocolPicker = NSPopUpButton()
        let protocols: [ProviderWireProtocol] = [.openAICompletions, .openAIResponses, .anthropicMessages]
        protocolPicker.addItems(withTitles: ["OpenAI Chat Completions", "OpenAI Responses", "Anthropic Messages"])
        if let wireProtocol = provider?.descriptor.wireProtocol,
           let index = protocols.firstIndex(of: wireProtocol) { protocolPicker.selectItem(at: index) }
        let endpoint = NSTextField(string: provider?.descriptor.defaultBaseURL?.absoluteString ?? "")
        let credentialReference = NSTextField(string: provider?.descriptor.credentialReference?.rawValue ?? "")
        credentialReference.placeholderString = "PRIVATE_GATEWAY_API_KEY"
        let credentialValue = NSSecureTextField(string: "")
        credentialValue.placeholderString = "API key only when the reference is new"
        let unauthenticated = NSButton(
            checkboxWithTitle: "No authentication (literal private IP only)",
            target: nil,
            action: nil
        )
        // A nil reference may mean provider-native credential discovery. Only
        // the explicit DSH no-auth bit is allowed to select this destructive
        // authentication-mode choice in the editor.
        unauthenticated.state = provider?.descriptor.explicitlyUnauthenticated == true ? .on : .off
        unauthenticated.setAccessibilityLabel("Use this custom provider without authentication")

        let endpointGuidance = NSTextField(wrappingLabelWithString: "")
        endpointGuidance.textColor = .secondaryLabelColor
        endpointGuidance.font = .systemFont(ofSize: 11)
        endpointGuidance.maximumNumberOfLines = 3
        endpointGuidance.widthAnchor.constraint(equalToConstant: 520).isActive = true
        let editorInteraction = CustomProviderEditorInteraction(
            protocols: protocols,
            protocolPicker: protocolPicker,
            endpoint: endpoint,
            endpointGuidance: endpointGuidance,
            unauthenticated: unauthenticated,
            credentialReference: credentialReference,
            credentialValue: credentialValue
        )
        protocolPicker.target = editorInteraction
        protocolPicker.action = #selector(CustomProviderEditorInteraction.refreshProtocolGuidance(_:))
        unauthenticated.target = editorInteraction
        unauthenticated.action = #selector(CustomProviderEditorInteraction.refreshAuthentication(_:))
        editorInteraction.refreshProtocolGuidance(nil)
        editorInteraction.refreshAuthentication(nil)

        let modelText = NSTextView()
        modelText.isRichText = false
        modelText.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        modelText.string = (provider?.models ?? []).map { model in
            let input = model.capabilities.inputModalities.map(\.rawValue).joined(separator: ",")
            let context = model.capabilities.contextWindowTokens ?? 32_768
            let output = model.capabilities.maxOutputTokens ?? min(4_096, context)
            return "\(model.id.rawValue) | \(model.displayName) | \(input) | \(context) | \(output)"
        }.joined(separator: "\n")
        if modelText.string.isEmpty {
            modelText.string = "model-id | Model Name | text | 32768 | 4096"
        }
        let modelsScroll = NSScrollView()
        modelsScroll.documentView = modelText
        modelsScroll.hasVerticalScroller = true
        modelsScroll.borderType = .bezelBorder
        modelsScroll.widthAnchor.constraint(equalToConstant: 520).isActive = true
        modelsScroll.heightAnchor.constraint(equalToConstant: 110).isActive = true

        for field in [providerID, displayName, endpoint, credentialReference, credentialValue] {
            field.widthAnchor.constraint(equalToConstant: 360).isActive = true
        }
        providerID.setAccessibilityLabel("Custom provider ID")
        displayName.setAccessibilityLabel("Custom provider display name")
        protocolPicker.setAccessibilityLabel("Custom provider protocol")
        endpoint.setAccessibilityLabel("Custom provider base URL")
        credentialReference.setAccessibilityLabel("Custom provider credential reference")
        credentialValue.setAccessibilityLabel("New custom provider API key")
        modelText.setAccessibilityLabel("Custom provider models and input modalities")

        let grid = NSGridView(views: [
            [NSTextField(labelWithString: "Provider ID"), providerID],
            [NSTextField(labelWithString: "Name"), displayName],
            [NSTextField(labelWithString: "Protocol"), protocolPicker],
            [NSTextField(labelWithString: "Base URL"), endpoint],
            [NSTextField(labelWithString: "Authentication"), unauthenticated],
            [NSTextField(labelWithString: "Credential ref"), credentialReference],
            [NSTextField(labelWithString: "New API key"), credentialValue]
        ])
        grid.rowSpacing = 7
        grid.columnSpacing = 10
        let syntax = NSTextField(wrappingLabelWithString: "Models — one per line: model ID | display name | text,image | context tokens | max output tokens. Text is required; declare the endpoint's real positive limits.")
        syntax.textColor = .secondaryLabelColor
        syntax.font = .systemFont(ofSize: 11)
        syntax.maximumNumberOfLines = 3
        syntax.widthAnchor.constraint(equalToConstant: 520).isActive = true
        let authenticationHelp = NSTextField(wrappingLabelWithString: "Credential mode stores a bearer-style API key in Keychain. No authentication sends no Authorization or API-key header and is accepted only for a literal loopback, RFC 1918, or IPv6 ULA address.")
        authenticationHelp.textColor = .secondaryLabelColor
        authenticationHelp.font = .systemFont(ofSize: 11)
        authenticationHelp.maximumNumberOfLines = 3
        authenticationHelp.widthAnchor.constraint(equalToConstant: 520).isActive = true
        let stack = NSStackView(views: [grid, endpointGuidance, authenticationHelp, syntax, modelsScroll])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.setFrameSize(stack.fittingSize)

        let alert = NSAlert()
        alert.messageText = provider == nil ? "Add a custom provider" : "Edit \(provider?.displayName ?? "custom provider")"
        alert.informativeText = "The profile is written only through the authenticated Harness settings service. Cloud and network access still requires a separate exact-origin confirmation before agent work can resume."
        alert.accessoryView = stack
        alert.addButton(withTitle: "Save Profile")
        alert.addButton(withTitle: "Cancel")

        while alert.runModal() == .alertFirstButtonReturn {
            do {
                let draft = try customDraft(
                    providerID: providerID.stringValue,
                    displayName: displayName.stringValue,
                    wireProtocol: protocols[protocolPicker.indexOfSelectedItem],
                    endpoint: endpoint.stringValue,
                    models: modelText.string,
                    credentialReference: credentialReference.stringValue,
                    credentialValue: credentialValue.stringValue,
                    unauthenticated: unauthenticated.state == .on
                )
                if onPrepareProtectedMutation == nil || onProtectedMutationFinished == nil {
                    throw CustomProviderProfileFailure.mutationNotVerified
                }
                setCredentialOperationInProgress(true)
                statusLabel.stringValue = "Pausing agent work before changing the provider profile…"
                let protectedMutation = ProviderProtectedMutation(
                    providerID: provider?.id ?? ProviderID(draft.providerID),
                    kind: .profile
                )
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    do {
                        let result = try await self.performProtectedMutation(
                            protectedMutation,
                            mutation: {
                                self.statusLabel.stringValue = "Saving and verifying the custom provider profile…"
                                return try await self.customProfileEditor.save(draft)
                            }
                        )
                        self.setCredentialOperationInProgress(false)
                        self.preferredRoute = result.provider.models.first.map {
                            ModelRoute(provider: result.provider.id, model: $0.id)
                        }
                        self.operationOutcomeMessage = CustomProviderEditorPresentation.configurationVerifiedMessage
                        self.refresh()
                    } catch {
                        self.setCredentialOperationInProgress(false)
                        self.statusLabel.stringValue = ProviderCenterFailurePresentation.message(
                            for: error,
                            context: .customProfileSave
                        )
                    }
                }
                return
            } catch {
                let invalid = NSAlert()
                invalid.alertStyle = .warning
                invalid.messageText = "Custom profile is not valid"
                invalid.informativeText = ProviderCenterFailurePresentation.message(
                    for: error,
                    context: .customProfileValidation
                )
                invalid.runModal()
            }
        }
    }

    private func customDraft(
        providerID: String,
        displayName: String,
        wireProtocol: ProviderWireProtocol,
        endpoint: String,
        models rawModels: String,
        credentialReference: String,
        credentialValue: String,
        unauthenticated: Bool
    ) throws -> CustomProviderProfileDraft {
        let lines = rawModels.split(whereSeparator: \.isNewline)
        let models: [CustomProviderModelDraft] = try lines.map { line in
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            guard parts.count == 5,
                  let contextWindowTokens = Int(parts[3]),
                  let maxOutputTokens = Int(parts[4]) else {
                throw CustomProviderProfileFailure.invalidModels
            }
            let modalities = parts[2].split(separator: ",", omittingEmptySubsequences: false).map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            guard let parsed = try? modalities.map({ raw -> ModelInputModality in
                guard let modality = ModelInputModality(rawValue: raw) else {
                    throw CustomProviderProfileFailure.invalidModels
                }
                return modality
            }) else { throw CustomProviderProfileFailure.invalidModels }
            return CustomProviderModelDraft(
                id: parts[0],
                displayName: parts[1],
                inputModalities: parsed,
                contextWindowTokens: contextWindowTokens,
                maxOutputTokens: maxOutputTokens
            )
        }
        return CustomProviderProfileDraft(
            providerID: providerID,
            displayName: displayName,
            wireProtocol: wireProtocol,
            baseURL: endpoint,
            models: models,
            credentialReference: credentialReference,
            credentialValue: credentialValue,
            unauthenticated: unauthenticated
        )
    }

    private func presentCredentialEditor(
        provider: ProviderView,
        reference: CredentialReference,
        state: HarnessCredentialView?
    ) {
        guard state?.writable != false else {
            let alert = NSAlert()
            alert.messageText = "This credential is managed elsewhere"
            alert.informativeText = "Harness reports that the \(provider.displayName) credential cannot be changed from this app."
            alert.runModal()
            return
        }
        if state?.configured == true, provider.configurationState != .ready {
            let alert = NSAlert()
            alert.messageText = "Enable \(provider.displayName)?"
            alert.informativeText = "A Keychain credential is already configured. \(ProductBrand.displayName) will keep that key unchanged and create only the reviewed provider profile."
            alert.addButton(withTitle: "Enable with Existing Key")
            alert.addButton(withTitle: "Authorize Existing…")
            alert.addButton(withTitle: "Remove Key")
            alert.addButton(withTitle: "Cancel")
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                activateProvider(provider: provider, credentialValue: nil)
            case .alertSecondButtonReturn:
                performForegroundCredentialRecovery(
                    provider: provider,
                    message: "Waiting for macOS to authorize the exact existing credential…"
                ) { try await self.credentialRecovery.authorizeExisting(reference) }
            case .alertThirdButtonReturn:
                mutateCredential(provider: provider, reference: reference, value: nil)
            default:
                statusLabel.stringValue = catalogSummary
            }
            return
        }
        let field = NSSecureTextField(string: "")
        field.placeholderString = state?.configured == true ? "Enter a replacement API key" : "Enter API key"
        field.widthAnchor.constraint(equalToConstant: 430).isActive = true
        field.setAccessibilityLabel("\(provider.displayName) API key")
        let detail = NSTextField(wrappingLabelWithString: "The key is sent only to the authenticated local Harness credential service and stored in macOS Keychain. It cannot be read back by this window.")
        detail.textColor = .secondaryLabelColor
        detail.font = .systemFont(ofSize: 11)
        detail.maximumNumberOfLines = 4
        detail.widthAnchor.constraint(equalToConstant: 430).isActive = true
        let stack = NSStackView(views: [field, detail])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.setFrameSize(stack.fittingSize)

        let alert = NSAlert()
        alert.messageText = state?.configured == true ? "Replace \(provider.displayName) API key" : "Set up \(provider.displayName)"
        alert.informativeText = state?.configured == true
            ? "A credential is already configured\(state?.source.map { " via \($0)" } ?? ""). Leave the field empty unless you intend to replace it."
            : "Enter the API key issued by \(provider.displayName)."
        alert.accessoryView = stack
        alert.addButton(withTitle: state?.configured == true ? "Replace Key" : "Save to Keychain")
        if state?.configured == true {
            alert.addButton(withTitle: "Authorize Existing…")
            alert.addButton(withTitle: "Remove Key")
        }
        alert.addButton(withTitle: "Cancel")
        let response = alert.runModal()
        let cancelResponse = state?.configured == true
            ? NSApplication.ModalResponse(rawValue: NSApplication.ModalResponse.alertThirdButtonReturn.rawValue + 1)
            : .alertSecondButtonReturn
        guard response != cancelResponse else { statusLabel.stringValue = catalogSummary; return }

        if state?.configured == true, response == .alertSecondButtonReturn {
            field.stringValue = ""
            performForegroundCredentialRecovery(
                provider: provider,
                message: "Waiting for macOS to authorize the exact existing credential…"
            ) { try await self.credentialRecovery.authorizeExisting(reference) }
            return
        }

        let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        field.stringValue = ""
        if response == .alertThirdButtonReturn, state?.configured == true {
            mutateCredential(provider: provider, reference: reference, value: nil)
            return
        }
        guard !value.isEmpty, value.utf8.count <= 32 * 1_024,
              !value.unicodeScalars.contains(where: CharacterSet.newlines.contains) else {
            statusLabel.stringValue = "The API key was not changed. Enter a non-empty key without line breaks."
            return
        }
        if state?.configured == true {
            // Credential values are intentionally write-only, so replacement is
            // an explicit key-only commit rather than part of provider activation.
            mutateCredential(provider: provider, reference: reference, value: value)
        } else {
            activateProvider(provider: provider, credentialValue: value)
        }
    }

    private func activateProvider(provider: ProviderView, credentialValue: String?) {
        operationOutcomeMessage = nil
        setCredentialOperationInProgress(true)
        statusLabel.stringValue = credentialValue == nil
            ? "Enabling \(provider.displayName) with the existing Keychain credential…"
            : "Saving the credential and enabling \(provider.displayName)…"
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let result = try await self.performProtectedMutation(
                    ProviderProtectedMutation(providerID: provider.id, kind: .activation),
                    mutation: {
                        try await self.providerActivation.activate(
                            descriptor: provider.descriptor,
                            credentialValue: credentialValue
                        )
                    }
                )
                let message = ProviderActivationPresentation.verifiedCredentialMessage(
                    providerDisplayName: result.provider.displayName
                )
                operationOutcomeMessage = message
                statusLabel.stringValue = message
                setCredentialOperationInProgress(false)
                preferredRoute = ModelRoute(
                    provider: result.provider.id,
                    model: result.provider.models[0].id
                )
                refresh()
            } catch {
                setCredentialOperationInProgress(false)
                if case .mutationCommittedButRecoveryFailed = error as? ProtectedRuntimeMutationCoordinatorError {
                    let message = ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .providerActivation
                    )
                    operationOutcomeMessage = message
                    statusLabel.stringValue = message
                    refresh()
                    return
                }
                if case .mutationAndRecoveryFailed = error as? ProtectedRuntimeMutationCoordinatorError {
                    let message = ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .providerActivation
                    )
                    operationOutcomeMessage = message
                    statusLabel.stringValue = message
                    refresh()
                    return
                }
                if let transaction = error as? ProviderActivationTransactionError {
                    // Preserve the typed failure reason. A generic rollback
                    // message left users unable to distinguish a Keychain
                    // problem, a read-only Harness profile, or a provider that
                    // never became ready.
                    let message = ProviderCenterFailurePresentation.message(
                        for: transaction,
                        context: .providerActivation
                    )
                    operationOutcomeMessage = message
                    statusLabel.stringValue = message
                } else {
                    let message = ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .providerActivation
                    )
                    operationOutcomeMessage = message
                    statusLabel.stringValue = message
                }
            }
        }
    }

    private func mutateCredential(provider: ProviderView, reference: CredentialReference, value: String?) {
        guard onPrepareProtectedMutation != nil, onProtectedMutationFinished != nil else {
            statusLabel.stringValue = "Credential changes are blocked because protected runtime quiescence is unavailable."
            return
        }
        operationOutcomeMessage = nil
        setCredentialOperationInProgress(true)
        statusLabel.stringValue = value == nil ? "Removing \(provider.displayName) credential…" : "Saving \(provider.displayName) credential to Keychain…"
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let assessment = try await self.performProtectedMutation(
                    ProviderProtectedMutation(providerID: provider.id, kind: .credential),
                    effect: { assessment in
                        switch assessment.disposition {
                        case .verifiedApplied, .appliedAfterAmbiguousResponse: return .committed
                        case .confirmedNotApplied: return .notCommitted
                        case .uncertain: return .uncertain
                        }
                    },
                    mutation: { await self.credentialMutation.mutate(reference: reference, value: value) }
                )
                let active = self.defaultSelection.route.provider == provider.id
                self.setCredentialOperationInProgress(false)
                switch assessment.disposition {
                case .verifiedApplied:
                    self.statusLabel.stringValue = value == nil
                        ? "Credential removed from Keychain; configuration state refreshed."
                        : "Credential saved to Keychain; configuration ready. The provider has not been contacted."
                case .appliedAfterAmbiguousResponse:
                    self.statusLabel.stringValue = value == nil
                        ? "Credential removal completed, although its first acknowledgement was lost."
                        : "Credential save completed, although its first acknowledgement was lost. The provider has not been contacted."
                case .confirmedNotApplied:
                    self.statusLabel.stringValue = value == nil
                        ? "Credential was not removed; the agent service still reports the existing key as configured."
                        : "Credential was not saved; the agent service did not retain the new Keychain reference."
                case .uncertain:
                    self.statusLabel.stringValue = active
                        ? "Credential outcome is uncertain; restarting into a fail-closed readiness check…"
                        : "Credential outcome is uncertain. Refresh and verify this provider before using it."
                }
                self.operationOutcomeMessage = self.statusLabel.stringValue

                // Protected mutation completion always launches one fresh,
                // fail-closed runtime so Keychain and provider readiness are
                // re-read before any new task is admitted.
                self.refresh()
            } catch {
                self.setCredentialOperationInProgress(false)
                if case .mutationCommittedButRecoveryFailed = error as? ProtectedRuntimeMutationCoordinatorError {
                    self.statusLabel.stringValue = ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .credentialMutation
                    )
                } else if case .mutationOutcomeUncertainAndRecoveryFailed = error as? ProtectedRuntimeMutationCoordinatorError {
                    self.statusLabel.stringValue = ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .credentialMutation
                    )
                } else {
                    self.statusLabel.stringValue = ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .credentialMutation
                    )
                }
                self.operationOutcomeMessage = self.statusLabel.stringValue
                self.refresh()
            }
        }
    }

    @objc private func profileChanged(_ sender: Any?) {
        let index = profilePicker.indexOfSelectedItem
        guard PerformanceProfile.allCases.indices.contains(index) else { return }
        let requested = PerformanceProfile.allCases[index]
        guard requested != defaultSelection.performanceProfile else { return }
        guard let apply = onPerformanceProfileRequested else {
            loadStoredSelection()
            presentError(ProtectedRuntimeMutationCoordinatorError.transitionFailed(.coordinationUnavailable))
            return
        }
        setCommitting(true, message: "Stopping the exact old runtime before applying local performance settings…")
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await apply(requested)
                self.loadStoredSelection()
                self.setCommitting(false, message: "Performance profile applied to a fresh verified runtime.")
            } catch {
                self.loadStoredSelection()
                self.setCommitting(
                    false,
                    message: ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .performanceProfile
                    )
                )
            }
        }
    }

    @objc private func commit(_ sender: Any?) {
        guard let provider = selectedProvider, let model = selectedModel else { return }
        let route = ModelRoute(provider: provider.id, model: model.id)
        let requestedProfile = PerformanceProfile.allCases.indices.contains(profilePicker.indexOfSelectedItem)
            ? PerformanceProfile.allCases[profilePicker.indexOfSelectedItem] : .balanced
        let profile: PerformanceProfile = route.provider == BuiltInProviderDescriptors.ollama.id
            && route.model != BuiltInProviderDescriptors.qwenLocalModel.id
            ? .compatibility
            : requestedProfile
        setCommitting(true, message: "Rechecking the configured route and model catalog…")
        Task { @MainActor [weak self] in
            guard let self else { return }
            let verifiedProvider: ProviderView
            let verifiedModel: ModelView
            do {
                let catalog = try await coordinator.loadCatalog()
                guard let currentProvider = catalog.provider(route.provider),
                      currentProvider.configurationState == .ready,
                      let currentModel = currentProvider.models.first(where: { $0.id == route.model })
                else {
                    setCommitting(
                        false,
                        message: "The selected route changed in the agent service. Nothing was saved; refresh Models & Providers and choose again."
                    )
                    return
                }
                verifiedProvider = currentProvider
                verifiedModel = currentModel
            } catch {
                setCommitting(
                    false,
                    message: "The configured route and model catalog could not be confirmed. Nothing was saved and external access remains blocked."
                )
                return
            }

            if verifiedProvider.boundary.requiresExplicitConsent {
                guard let origin = resolvedExternalOrigin(for: verifiedProvider) else {
                    setCommitting(
                        false,
                        message: "External access remains blocked because the agent service did not resolve a safe, exact provider endpoint. Refresh or review Provider Settings."
                    )
                    return
                }
                guard confirmExternalBoundary(verifiedProvider, origin: origin) else {
                    setCommitting(false, message: "Model switch cancelled. The previous route remains active.")
                    return
                }
            }

            let selection = ModelSelection(
                route: route,
                reasoningEffort: verifiedModel.capabilities.defaultReasoningEffort,
                performanceProfile: profile
            )
            statusLabel.stringValue = route.provider == BuiltInProviderDescriptors.ollama.id
                ? "Checking local model size, identity, tools, and context before switching…"
                : "Synchronizing the default model route…"
            do {
                let result = try await selectionTransaction.commit(
                    selection: selection,
                    descriptor: verifiedProvider.descriptor
                )
                defaultSelection = result.selection
                preferredRoute = result.selection.route
                profilePicker.selectItem(
                    at: PerformanceProfile.allCases.firstIndex(of: result.selection.performanceProfile) ?? 1
                )
                providerTable.reloadData()
                modelTable.reloadData()
                setCommitting(false, message: "Default saved for new tasks · \(result.boundary.displayName)")
                onSelectionCommitted?(result.selection, result.boundary)
            } catch {
                setCommitting(
                    false,
                    message: ProviderCenterFailurePresentation.message(
                        for: error,
                        context: .modelSelection
                    )
                )
            }
        }
    }
}
