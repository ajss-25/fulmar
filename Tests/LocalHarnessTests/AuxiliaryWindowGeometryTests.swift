import AppKit
import Testing
@testable import LocalHarness

private actor EmptySessionHistorySource: SessionHistoryDataProviding {
    func browse(query: String?) async throws -> SessionHistoryBrowseSnapshot {
        SessionHistoryBrowseSnapshot(rows: [], query: query, hasMoreSearchResults: false)
    }

    func detail(for sessionID: HarnessSessionID) async throws -> SessionHistoryDetailSnapshot {
        SessionHistoryDetailSnapshot(
            sessionID: sessionID,
            transcript: SessionTranscriptPage(messages: [], olderBeforeSequence: nil),
            route: .unavailable
        )
    }

    func olderPage(for sessionID: HarnessSessionID, beforeSequence: Int) async throws -> SessionTranscriptPage {
        SessionTranscriptPage(messages: [], olderBeforeSequence: nil)
    }

    func createSession(
        _ request: HarnessSessionCreateRequest,
        selection: ModelSelection
    ) async throws -> HarnessSessionID {
        HarnessSessionID(rawValue: "layout-test")
    }

    func renameSession(_ sessionID: HarnessSessionID, title: String) async throws {}
    func forkSession(_ sessionID: HarnessSessionID, atSequence: Int?) async throws -> HarnessSessionID {
        HarnessSessionID(rawValue: "layout-test-fork")
    }
    func archiveSession(_ sessionID: HarnessSessionID) async throws {}
}

@MainActor
@Test func remainingConstructibleAuxiliaryWindowsFitAtMinimumInBothAppearances() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let fixture = try AuxiliaryWindowFixture()
    defer { fixture.remove() }

    let now = Date(timeIntervalSince1970: 2_000_000_000)
    let host = HostPerformanceSnapshot(
        capturedAt: now,
        physicalMemoryBytes: 48 * 1_073_741_824,
        thermalCondition: .nominal,
        lowPowerModeEnabled: false,
        processorArchitecture: .appleSilicon,
        logicalProcessorCount: 14,
        activeProcessorCount: 14
    )
    let ollama = OllamaRuntimeSnapshot.unavailable(at: now)
    let recommendation = AdaptivePerformanceRecommender.recommend(
        host: host,
        ollama: ollama,
        recentTelemetry: []
    )
    let scheduleManager = ScheduleManager(
        applicationSupport: fixture.directory.appendingPathComponent("ScheduleSupport", isDirectory: true),
        executor: UnconfiguredScheduleConversationExecutor(),
        activities: ActivityStore(
            applicationSupport: fixture.directory.appendingPathComponent("ScheduleActivity", isDirectory: true)
        )
    )
    let harnessController = HarnessController(
        applicationSupportDirectory: fixture.directory.appendingPathComponent("HarnessSupport", isDirectory: true),
        modelStoreDirectory: fixture.directory.appendingPathComponent("ModelStore", isDirectory: true),
        forbidCredentialHelper: true
    )
    let mcpDraft = MCPServerDraft(
        id: "geometry-local",
        displayName: "Geometry Local Server",
        serverName: "geometry_local",
        executablePath: fixture.executable.path,
        allowedProviders: [MCPProviderEnablement(provider: ProviderID("ollama"), boundary: .onDevice)],
        disclosure: MCPDisclosureProfile(boundary: .onDevice, dataKinds: [.toolArguments, .toolResults])
    )
    let mcpInspection = MCPDraftInspection(
        executable: try MCPExecutableInspector.inspect(fixture.executable),
        project: try MCPProjectInspector.inspect(fixture.project),
        reviewedFiles: []
    )
    let controllers: [(String, NSWindowController, Int, NSSize?)] = [
        ("Performance Center", PerformanceCenterWindowController(snapshot: PerformanceCenterSnapshot(
            capturedAt: now,
            host: host,
            ollama: ollama,
            recommendation: recommendation,
            telemetry: []
        )), 0, nil),
        ("Task History", SessionHistoryWindowController(dataSource: EmptySessionHistorySource()), 1, nil),
        ("Activity Center", ActivityCenterWindowController(store: ActivityStore(
            applicationSupport: fixture.directory.appendingPathComponent("ActivitySupport", isDirectory: true)
        )), 1, nil),
        ("Skills", SkillsCenterWindowController(
            store: try SkillsTrustStore(
                applicationSupport: fixture.directory.appendingPathComponent("SkillsSupport", isDirectory: true),
                harnessHome: fixture.directory.appendingPathComponent("HarnessHome", isDirectory: true)
            ),
            projectURL: fixture.project,
            currentBoundary: { .local }
        ), 1, nil),
        ("Command Center", CommandCenterWindowController(
            commands: [CommandCenterCommand(
                title: "Settings",
                detail: "Open all application settings",
                symbolName: "gearshape",
                keywords: ["preferences"],
                action: #selector(NSApplication.orderFrontStandardAboutPanel(_:))
            )],
            actionTarget: NSApplication.shared
        ), 1, nil),
        ("Artifact Preview", ArtifactPreviewWindowController(
            artifact: fixture.artifact,
            annotations: ArtifactAnnotationStore(
                applicationSupport: fixture.directory.appendingPathComponent("ArtifactSupport", isDirectory: true)
            ),
            previewFactory: makeArtifactPreviewTestView
        ), 0, nil),
        ("Artifact Comparison", ArtifactComparisonWindowController(
            left: fixture.artifact,
            right: fixture.comparisonArtifact,
            previewFactory: makeArtifactPreviewTestView
        ), 0, nil),
        ("Knowledge Note Editor", KnowledgeNoteEditorWindowController(
            note: nil,
            projects: [KnowledgeProjectOption(id: "geometry", displayName: "Geometry Project")],
            initialScope: .global
        ), 0, nil),
        ("Task Inbox", TaskInboxWindowController(manager: scheduleManager), 1, nil),
        ("Add MCP Server", MCPServerEditorSheetController(
            projectRoot: fixture.project,
            providerChoices: [],
            existing: nil
        ), 0, nil),
        ("Review MCP Server", MCPServerReviewSheetController(
            draft: mcpDraft,
            inspection: mcpInspection,
            projectRoot: fixture.project,
            providerNames: ["ollama": "Ollama"]
        ), 0, nil),
        ("Diagnostics", DiagnosticsWindowController(controller: harnessController), 0, nil),
        ("Plugin Trust", PluginTrustWindowController(controller: harnessController), 1, nil)
    ]
    for (name, controller, expectedTableCount, fallbackMinimum) in controllers {
        try assertAuxiliaryGeometry(
            controller,
            name: name,
            expectedTableCount: expectedTableCount,
            fallbackMinimum: fallbackMinimum
        )
    }
    try assertEnabledControlActions(in: controllers)

    try assertButtonPolicy(in: controllers, named: "Knowledge Note Editor", titles: ["Save Memory", "Cancel"])
    try assertDisabledButtons(in: controllers, named: "Task Inbox", titles: ["Delete Result", "Clear Inbox…"])
    try assertButtonPolicy(in: controllers, named: "Review MCP Server", titles: ["Back", "Save Disabled", "Approve Server"])
    try assertDisabledButtons(in: controllers, named: "Review MCP Server", titles: ["Approve Server"])
    try assertWindowDeclaresResizingFloor(in: controllers, named: "Review MCP Server")
    try assertButtonPolicy(
        in: controllers,
        named: "Diagnostics",
        titles: ["Refresh", "Copy Support Report", "Open Diagnostics Folder", "Restart Services"]
    )
    try assertButtonPolicy(
        in: controllers,
        named: "Plugin Trust",
        titles: ["Community Plugins Disabled", "Remove Legacy Approval"]
    )
    try assertDisabledButtons(
        in: controllers,
        named: "Plugin Trust",
        titles: ["Community Plugins Disabled", "Remove Legacy Approval"]
    )
}

@MainActor
private func assertEnabledControlActions(
    in controllers: [(String, NSWindowController, Int, NSSize?)]
) throws {
    // Empty-title AppKit/Quick Look chrome is framework-owned. Every visible,
    // enabled, titled app button or popup in these native surfaces must have
    // an explicit target and action; disabled controls are checked separately.
    let passiveMCPFormValues: Set<String> = [
        "Reconnect after an unexpected exit", "Account data", "Authentication metadata",
        "File contents", "File names", "Project metadata", "Tool arguments", "Tool results"
    ]
    for (name, controller, _, _) in controllers {
        let root = try #require(controller.window?.contentViewController?.view ?? controller.window?.contentView)
        let controls = auxiliaryDescendants(of: root).compactMap { $0 as? NSControl }
        for control in controls where !control.isHidden && control.isEnabled {
            if let button = control as? NSButton {
                if button.title.isEmpty { continue }
                // Form checkboxes/radios are passive values intentionally read
                // by Save/Approve; they do not promise an immediate action.
                if name == "Add MCP Server", passiveMCPFormValues.contains(button.title) { continue }
            }
            // The memory scope is another submit-time form value.
            if let popup = control as? NSPopUpButton,
               popup.accessibilityLabel() == "Memory scope" { continue }
            guard control is NSButton || control is NSPopUpButton else { continue }
            #expect(control.target != nil, Comment(rawValue: "\(name): \(type(of: control)) target"))
            #expect(control.action != nil, Comment(rawValue: "\(name): \(type(of: control)) action"))
        }
    }
}

@MainActor
private func assertWindowDeclaresResizingFloor(
    in controllers: [(String, NSWindowController, Int, NSSize?)],
    named name: String
) throws {
    let window = try #require(controllers.first(where: { $0.0 == name })?.1.window)
    let minimum = window.minSize
    #expect(minimum == NSSize(width: 740, height: 650), Comment(rawValue: "\(name) declared minimum"))
    #expect(window.styleMask.contains(.resizable) == false, Comment(rawValue: "\(name) cannot be dragged below minimum"))
}

@MainActor
private func assertAuxiliaryGeometry(
    _ controller: NSWindowController,
    name: String,
    expectedTableCount: Int,
    fallbackMinimum: NSSize?
) throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let window = try #require(controller.window, Comment(rawValue: name))
    let minimum = fallbackMinimum ?? window.minSize
    #expect(minimum.width > 0 && minimum.height > 0, Comment(rawValue: name))
    window.setFrame(NSRect(origin: .zero, size: minimum), display: false)
    #expect(!window.isVisible, Comment(rawValue: "\(name) remains off-screen"))

    for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
        window.appearance = NSAppearance(named: appearanceName)
        window.layoutIfNeeded()
        window.contentView?.layoutSubtreeIfNeeded()
        window.layoutIfNeeded()

        let root = try #require(
            window.contentViewController?.view ?? window.contentView,
            Comment(rawValue: name)
        )
        #expect(!root.hasAmbiguousLayout, Comment(rawValue: "\(name) root"))
        let descendants = auxiliaryDescendants(of: root)
        let tables = descendants.compactMap { $0 as? NSTableView }
        #expect(tables.count == expectedTableCount, Comment(rawValue: "\(name) table inventory"))

        for scroll in descendants.compactMap({ $0 as? NSScrollView }) {
            #expect(!scroll.hasAmbiguousLayout, Comment(rawValue: "\(name) scroll view"))
            guard let document = scroll.documentView else { continue }
            #expect(!document.hasAmbiguousLayout, Comment(rawValue: "\(name) scroll document"))
            if document is NSTableView {
                #expect(
                    document.frame.width <= scroll.documentVisibleRect.width + 0.5 || scroll.hasHorizontalScroller,
                    Comment(rawValue: "\(name) table scroll width")
                )
            }
            #expect(
                document.frame.height <= scroll.documentVisibleRect.height + 0.5 || scroll.hasVerticalScroller,
                Comment(rawValue: "\(name) scroll height")
            )
        }

        for table in tables {
            #expect(!table.hasAmbiguousLayout, Comment(rawValue: "\(name) table"))
            #expect(table.accessibilityRole() == .table, Comment(rawValue: "\(name) table accessibility"))
        }

        for view in descendants where isGeometryRelevant(view) {
            guard !view.isHidden, view.window === window else { continue }
            let boundary = auxiliaryLayoutBoundary(for: view, root: root)
            guard view !== boundary else { continue }
            let frame = view.convert(view.bounds, to: boundary)
            #expect(frame.minX >= boundary.bounds.minX - 0.5, Comment(rawValue: "\(name) minimum X"))
            #expect(frame.maxX <= boundary.bounds.maxX + 0.5, Comment(rawValue: "\(name) maximum X"))
            #expect(frame.minY >= boundary.bounds.minY - 0.5, Comment(rawValue: "\(name) minimum Y"))
            #expect(frame.maxY <= boundary.bounds.maxY + 0.5, Comment(rawValue: "\(name) maximum Y"))
        }

    }
}

@MainActor
private func assertButtonPolicy(
    in controllers: [(String, NSWindowController, Int, NSSize?)],
    named name: String,
    titles: [String]
) throws {
    let controller = try #require(controllers.first(where: { $0.0 == name })?.1)
    let root = try #require(controller.window?.contentViewController?.view ?? controller.window?.contentView)
    let buttons = auxiliaryDescendants(of: root).compactMap { $0 as? NSButton }
    for title in titles {
        let button = try #require(buttons.first(where: { $0.title == title }), Comment(rawValue: "\(name): \(title)"))
        #expect(button.target != nil, Comment(rawValue: "\(name): \(title) target"))
        #expect(button.action != nil, Comment(rawValue: "\(name): \(title) action"))
    }
}

@MainActor
private func assertDisabledButtons(
    in controllers: [(String, NSWindowController, Int, NSSize?)],
    named name: String,
    titles: [String]
) throws {
    let controller = try #require(controllers.first(where: { $0.0 == name })?.1)
    let root = try #require(controller.window?.contentViewController?.view ?? controller.window?.contentView)
    let buttons = auxiliaryDescendants(of: root).compactMap { $0 as? NSButton }
    for title in titles {
        let button = try #require(buttons.first(where: { $0.title == title }), Comment(rawValue: "\(name): \(title)"))
        #expect(!button.isEnabled, Comment(rawValue: "\(name): \(title) starts disabled"))
    }
}

private func isGeometryRelevant(_ view: NSView) -> Bool {
    view is NSButton || view is NSTextField || view is NSTextView || view is NSPopUpButton
        || view is NSSearchField || view is NSTableView || view is NSScrollView || view is NSStackView
}

private func auxiliaryLayoutBoundary(for view: NSView, root: NSView) -> NSView {
    var candidate: NSView? = view
    while let current = candidate, current !== root {
        if let scroll = current.enclosingScrollView, scroll.documentView === current {
            return current
        }
        candidate = current.superview
    }
    return root
}

private func auxiliaryDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(auxiliaryDescendants)
}

private final class AuxiliaryWindowFixture {
    let directory: URL
    let project: URL
    let artifact: URL
    let comparisonArtifact: URL
    let executable: URL

    init() throws {
        let candidate = try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarAuxiliaryGeometry")
        var initialized = false
        defer {
            if !initialized { try? FileManager.default.removeItem(at: candidate) }
        }
        directory = candidate
        project = directory.appendingPathComponent("Project", isDirectory: true)
        artifact = directory.appendingPathComponent("preview.txt", isDirectory: false)
        comparisonArtifact = directory.appendingPathComponent("comparison.txt", isDirectory: false)
        executable = directory.appendingPathComponent("mcp-server", isDirectory: false)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: project.path)
        try Data("Preview geometry fixture".utf8).write(to: artifact, options: .atomic)
        try Data("Comparison geometry fixture".utf8).write(to: comparisonArtifact, options: .atomic)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
        initialized = true
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}
