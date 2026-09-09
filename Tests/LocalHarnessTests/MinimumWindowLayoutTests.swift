import AppKit
import Testing
@testable import LocalHarness

private enum MinimumLayoutStubError: Error { case unavailable }

private struct MinimumLayoutProviderActivator: ProviderActivating {
    func activate(
        descriptor: ProviderDescriptor,
        credentialValue: String?
    ) async throws -> ProviderActivationResult {
        throw MinimumLayoutStubError.unavailable
    }
}

private struct MinimumLayoutProfileEditor: CustomProviderProfileEditing {
    func save(_ draft: CustomProviderProfileDraft) async throws -> CustomProviderProfileResult {
        throw MinimumLayoutStubError.unavailable
    }
}

@MainActor
@Test func appshotReviewControlsFitAtDeclaredMinimumWithOCRVisible() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let controller = AppshotReviewWindowController(
        image: NSImage(size: NSSize(width: 1_200, height: 800))
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    for button in minimumLayoutDescendants(of: root).compactMap({ $0 as? NSButton })
        where button.title == "Include recognized text for accessibility" {
        button.isHidden = false
    }
    window.layoutIfNeeded()
    assertMinimumWindowLayout(root)
    let cancel = try #require(
        minimumLayoutDescendants(of: root).compactMap { $0 as? NSButton }
            .first { $0.title == "Cancel" }
    )
    #expect(cancel.keyEquivalent == "\u{1b}")
}

@MainActor
@Test func appshotCanvasHasKeyboardAndAccessibilitySelection() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let canvas = AppshotCanvasView(image: NSImage(size: NSSize(width: 1_200, height: 800)))
    canvas.frame = NSRect(x: 0, y: 0, width: 800, height: 600)
    #expect(canvas.acceptsFirstResponder)
    #expect(canvas.accessibilityRole() == .image)
    #expect(canvas.selection.isEmpty)

    canvas.setDefaultKeyboardSelection()
    let initial = canvas.selection
    #expect(!initial.isEmpty)
    #expect(canvas.bounds.contains(initial))
    #expect((canvas.accessibilityValue() as? String)?.contains("Selected area") == true)

    canvas.adjustKeyboardSelection(dx: 6, dy: -6, resizing: false)
    #expect(canvas.selection.origin != initial.origin)
    let moved = canvas.selection
    canvas.adjustKeyboardSelection(dx: 6, dy: 6, resizing: true)
    #expect(canvas.selection.width >= moved.width)
    #expect(canvas.selection.height >= moved.height)
    #expect(canvas.bounds.contains(canvas.selection))

    canvas.reset()
    #expect(canvas.selection.isEmpty)
}

@MainActor
@Test func providerCenterTablesAndActionsRemainAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarProviderMinimumLayout.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let rpc = HarnessRPCClient()
    let controller = ProviderCenterWindowController(
        coordinator: ModelSelectionCoordinator(service: rpc),
        credentials: rpc,
        settingsStore: ModelProviderSettingsStore(defaults: defaults),
        consentStore: ProviderConsentStore(defaults: defaults),
        providerActivation: MinimumLayoutProviderActivator(),
        customProfileEditor: MinimumLayoutProfileEditor(),
        preferences: PreferencesStore(defaults: defaults)
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)

    try assertTablesRemainAccessible(root, expectedCount: 2)
}

@MainActor
@Test func quickChatWorstCaseControlsFitAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarQuickChatMinimumLayout.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let rpc = HarnessRPCClient()
    let coordinator = ModelSelectionCoordinator(service: rpc)
    let settings = ModelProviderSettingsStore(defaults: defaults)
    let preferences = PreferencesStore(defaults: defaults)
    let transaction = ProviderSelectionTransaction(
        coordinator: coordinator,
        settingsStore: settings,
        consentStore: ProviderConsentStore(defaults: defaults),
        preferences: preferences
    )
    let controller = CompanionWindowController(
        conversationService: HarnessConversationService(rpc: rpc),
        modelCoordinator: coordinator,
        settingsStore: settings,
        selectionTransaction: transaction,
        preferences: preferences,
        telemetry: GenerationTelemetryAccumulator(),
        knowledgeStore: nil,
        workspace: FileManager.default.temporaryDirectory,
        actionTarget: NSObject()
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    for button in minimumLayoutDescendants(of: root).compactMap({ $0 as? NSButton })
        where ["Remove attachments", "Stop response"].contains(button.accessibilityLabel()) {
        button.isHidden = false
    }
    window.layoutIfNeeded()
    assertMinimumWindowLayout(root)

    let modelPicker = try #require(
        minimumLayoutDescendants(of: root).compactMap { $0 as? NSPopUpButton }
            .first { $0.accessibilityLabel() == "Provider and model" }
    )
    #expect(modelPicker.cell?.lineBreakMode == .byTruncatingTail)
    #expect(modelPicker.accessibilityHelp()?.contains("full route") == true)
    #expect(modelPicker.bounds.width >= 260)
    #expect(modelPicker.bounds.width <= 360)
    #expect(modelPicker.toolTip?.isEmpty == false)
    let boundary = try #require(
        minimumLayoutDescendants(of: root).compactMap { $0 as? NSTextField }
            .first { $0.accessibilityLabel() == "Chat data boundary" }
    )
    #expect(boundary.lineBreakMode == .byTruncatingTail)
    #expect(boundary.maximumNumberOfLines == 1)
    #expect(boundary.toolTip == boundary.stringValue)

    let inputScroll = try #require(
        minimumLayoutDescendants(of: root).compactMap { $0 as? AppearanceAwareSeparatorScrollView }.first
    )
    for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
        let appearance = try #require(NSAppearance(named: appearanceName))
        window.appearance = appearance
        window.layoutIfNeeded()
        inputScroll.layoutSubtreeIfNeeded()
        inputScroll.displayIfNeeded()
        let backing = try #require(inputScroll.layer)
        #expect(backing.cornerRadius == 10)
        let border = inputScroll.separatorBorderLayer
        #expect(border.superlayer === backing)
        #expect(border.frame == inputScroll.bounds)
        #expect(border.path != nil)
        #expect(border.lineWidth == 1)
        #expect(border.isHidden == false)
        #expect(border.opacity == 1)
        let actual = try #require(border.strokeColor).rgbaComponents
        var expectedColor: CGColor?
        appearance.performAsCurrentDrawingAppearance {
            expectedColor = NSColor.separatorColor.cgColor
        }
        let expected = try #require(expectedColor).rgbaComponents
        for index in 0..<4 {
            #expect(abs(actual[index] - expected[index]) < 0.01)
        }
    }
}

@MainActor
@Test func backupTableRemainsAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarBackupMinimumLayout-\(UUID().uuidString)", isDirectory: true)
    let source = directory.appendingPathComponent("source", isDirectory: true)
    let backups = directory.appendingPathComponent("backups", isDirectory: true)
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try writeCurrentProviderHistoryPrivacyReceipt(at: source)
    defer { try? FileManager.default.removeItem(at: directory) }
    let manager = StateBackupManager(
        applicationSupport: directory,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 7, count: 32)
    )
    let controller = BackupWindowController(manager: manager, runtimeVersion: { "layout-test" })
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)
    try assertTablesRemainAccessible(root, expectedCount: 1)
    let disclosure = try #require(
        minimumLayoutDescendants(of: root).compactMap { $0 as? NSTextField }
            .first { $0.accessibilityLabel() == "Backup privacy and protection" }
    )
    #expect(disclosure.stringValue == BackupWindowController.privacyDisclosure)
    #expect(disclosure.accessibilityHelp() == BackupWindowController.privacyDisclosure)
    let disclosureFrame = disclosure.convert(disclosure.bounds, to: root)
    #expect(root.bounds.insetBy(dx: -0.5, dy: -0.5).contains(disclosureFrame))
}

@MainActor
@Test func localModelsTableRemainsAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarModelsMinimumLayout-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { completion in completion(.failure(MinimumLayoutStubError.unavailable)) },
        currentSelection: { nil },
        useModelForNewTasks: { _, completion in completion(.failure(MinimumLayoutStubError.unavailable)) },
        releaseModelMemory: { _, completion in completion(.failure(MinimumLayoutStubError.unavailable)) }
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)
    try assertTablesRemainAccessible(root, expectedCount: 1)
}

@MainActor
@Test func localModelsTableExposesReleaseIdentityAsVisibleAccessibleUI() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarModelsIdentityUI-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { completion in completion(.failure(MinimumLayoutStubError.unavailable)) },
        currentSelection: { nil },
        useModelForNewTasks: { _, completion in completion(.failure(MinimumLayoutStubError.unavailable)) },
        releaseModelMemory: { _, completion in completion(.failure(MinimumLayoutStubError.unavailable)) }
    )
    controller.applyCatalogue(models: [OllamaModel(
        name: BuiltInProviderDescriptors.qwenLocalModel.id.rawValue,
        digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest,
        size: 18_000_000_000,
        modifiedAt: nil,
        details: nil
    )], running: [])
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    let modelTables = minimumLayoutDescendants(of: root)
        .compactMap { ($0 as? NSScrollView)?.documentView as? NSTableView }
    let table = try #require(modelTables.first)
    let profileIndex = table.column(withIdentifier: NSUserInterfaceItemIdentifier("profile"))
    #expect(profileIndex >= 0)
    let field = try #require(controller.tableView(
        table,
        viewFor: table.tableColumns[profileIndex],
        row: 0
    ) as? NSTextField)

    #expect(field.stringValue == "Release-qualified")
    #expect(field.toolTip?.contains("exact immutable Qwen manifest") == true)
    #expect(field.accessibilityHelp()?.contains("exact immutable Qwen manifest") == true)
}

@MainActor
@Test func privacyDashboardTableRemainsAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarPrivacyMinimumLayout-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let suite = "FulmarPrivacyMinimumLayout.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let preferences = PreferencesStore(defaults: defaults)
    let ledger = PrivacyLedger(applicationSupport: directory)
    let maintenance = PrivacyMaintenanceCoordinator(
        appshots: AppshotController(
            preferences: preferences,
            directory: directory.appendingPathComponent("Appshots")
        ),
        ledger: ledger,
        attachments: AttachmentRetentionManager(harnessHome: directory),
        preferences: preferences,
        canPurgeAttachments: { false }
    )
    let controller = PrivacyDashboardWindowController(
        ledger: ledger,
        preferences: preferences,
        maintenance: maintenance
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)
    try assertTablesRemainAccessible(root, expectedCount: 1)
}

@MainActor
@Test func knowledgeTableRemainsAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarKnowledgeMinimumLayout-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let controller = KnowledgeCenterWindowController(
        store: try LocalKnowledgeStore(applicationSupportDirectory: directory)
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)
    try assertTablesRemainAccessible(root, expectedCount: 1)
}

@MainActor
@Test func workspaceRecoveryTablesRemainAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let rootDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarRecoveryMinimumLayout-\(UUID().uuidString)", isDirectory: true)
    let workspace = rootDirectory.appendingPathComponent("Workspace", isDirectory: true)
    let support = rootDirectory.appendingPathComponent("Support", isDirectory: true)
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: rootDirectory) }
    let controller = WorkspaceRecoveryWindowController(
        journal: try WorkspaceChangeJournal(
            approvedWorkspace: workspace,
            applicationSupport: support
        )
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)
    try assertTablesRemainAccessible(root, expectedCount: 2)
}

@MainActor
@Test func mcpTableRemainsAccessibleAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let rootDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarMCPMinimumLayout-\(UUID().uuidString)", isDirectory: true)
    let project = rootDirectory.appendingPathComponent("Project", isDirectory: true)
    let support = rootDirectory.appendingPathComponent("Support", isDirectory: true)
    try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: rootDirectory) }
    let controller = MCPCenterWindowController(
        store: try MCPTrustStore(applicationSupport: support),
        projectRoot: project,
        providerChoices: []
    )
    let (window, root) = try prepareAtDeclaredMinimum(controller)
    defer { window.orderOut(nil) }
    assertMinimumWindowLayout(root)
    try assertTablesRemainAccessible(root, expectedCount: 1)
}

@MainActor
private func prepareAtDeclaredMinimum(
    _ controller: NSWindowController
) throws -> (NSWindow, NSView) {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let window = try #require(controller.window)
    window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
    #expect(!window.isVisible)
    window.layoutIfNeeded()
    window.contentView?.layoutSubtreeIfNeeded()
    window.contentView?.displayIfNeeded()
    window.layoutIfNeeded()
    return (window, try #require(window.contentViewController?.view))
}

@MainActor
private func assertMinimumWindowLayout(_ root: NSView) {
    for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
        root.window?.appearance = NSAppearance(named: appearanceName)
        root.window?.layoutIfNeeded()
        root.layoutSubtreeIfNeeded()
        root.displayIfNeeded()
        root.window?.layoutIfNeeded()
        for view in minimumLayoutDescendants(of: root)
            where view is NSButton || view is NSTextField || view is NSStackView {
            #expect(!view.hasAmbiguousLayout)
            guard !view.isHidden else { continue }
            let frame = view.convert(view.bounds, to: root)
            #expect(frame.minX >= root.bounds.minX - 0.5)
            #expect(frame.maxX <= root.bounds.maxX + 0.5)
            #expect(frame.minY >= root.bounds.minY - 0.5)
            #expect(frame.maxY <= root.bounds.maxY + 0.5)
        }
    }
}

@MainActor
private func assertTablesRemainAccessible(_ root: NSView, expectedCount: Int) throws {
    let tableScrolls = minimumLayoutDescendants(of: root).compactMap { $0 as? NSScrollView }
        .filter { $0.documentView is NSTableView }
    #expect(tableScrolls.count == expectedCount)
    for scroll in tableScrolls {
        let table = try #require(scroll.documentView as? NSTableView)
        #expect(table.frame.width <= scroll.documentVisibleRect.width + 0.5 || scroll.hasHorizontalScroller)
    }
}

private func minimumLayoutDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(minimumLayoutDescendants)
}

private extension CGColor {
    var rgbaComponents: [CGFloat] {
        let color = NSColor(cgColor: self)?.usingColorSpace(.deviceRGB) ?? .clear
        return [color.redComponent, color.greenComponent, color.blueComponent, color.alphaComponent]
    }
}
