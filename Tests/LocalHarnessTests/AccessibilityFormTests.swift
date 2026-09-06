import AppKit
import Foundation
import Testing
@testable import LocalHarness

@MainActor
@Suite("Native accessibility forms")
struct AccessibilityFormTests {
    @Test func conversationExportPickersHaveNamesHelpAndVisibleTitleRelationships() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let accessory = ConversationExportChoiceAccessory()

        #expect(accessory.formatPicker.accessibilityLabel() == "Export format")
        #expect(accessory.privacyPicker.accessibilityLabel() == "Export privacy")
        #expect(accessory.formatPicker.accessibilityHelp()?.isEmpty == false)
        #expect(accessory.privacyPicker.accessibilityHelp()?.isEmpty == false)
        try expectTitleRelationship(accessory.formatPicker, title: accessory.formatLabel)
        try expectTitleRelationship(accessory.privacyPicker, title: accessory.privacyLabel)
    }

    @Test func agentQuestionChoiceAndCustomAnswerRetainQuestionContext() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let title = NSTextField(wrappingLabelWithString: "Which deployment target should I use?")
        let picker = NSPopUpButton()
        picker.addItems(withTitles: ["Staging", "Production"])
        let custom = NSTextField()

        AgentQuestionAccessibility.configure(
            question: title.stringValue,
            title: title,
            optionButtons: [],
            optionPicker: picker,
            customField: custom
        )

        #expect(picker.accessibilityLabel() == "Answer choice for: Which deployment target should I use?")
        #expect(custom.accessibilityLabel() == "Custom answer to: Which deployment target should I use?")
        try expectTitleRelationship(picker, title: title)
        try expectTitleRelationship(custom, title: title)

        let first = NSButton(checkboxWithTitle: "Unit tests", target: nil, action: nil)
        let second = NSButton(checkboxWithTitle: "UI tests", target: nil, action: nil)
        let multiTitle = NSTextField(wrappingLabelWithString: "Which test suites should run?")
        let multiCustom = NSTextField()
        AgentQuestionAccessibility.configure(
            question: multiTitle.stringValue,
            title: multiTitle,
            optionButtons: [first, second],
            optionPicker: nil,
            customField: multiCustom
        )
        #expect(first.accessibilityLabel() == "Unit tests, answer to: Which test suites should run?")
        #expect(second.accessibilityLabel() == "UI tests, answer to: Which test suites should run?")
        #expect(multiCustom.accessibilityLabel() == "Custom answer to: Which test suites should run?")
        try expectTitleRelationship(first, title: multiTitle)
        try expectTitleRelationship(second, title: multiTitle)
        try expectTitleRelationship(multiCustom, title: multiTitle)
    }

    @Test func newScheduleFieldsAndPickersHaveSpecificNamesAndTitleRelationships() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let title = NSTextField()
        let prompt = NSTextView()
        let promptScroll = NSScrollView()
        promptScroll.documentView = prompt
        let provider = NSTextField()
        let model = NSTextField()
        let profile = NSPopUpButton()
        let timeout = NSPopUpButton()
        let firstRun = NSDatePicker()
        let interval = NSPopUpButton()
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

        let controls: [(NSView, String)] = [
            (title, "Schedule name"),
            (prompt, "Scheduled task prompt"),
            (provider, "Scheduled task provider ID"),
            (model, "Scheduled task model ID"),
            (profile, "Scheduled task output profile"),
            (timeout, "Scheduled task time limit"),
            (firstRun, "Scheduled task first run date and time"),
            (interval, "Scheduled task repeat interval")
        ]
        #expect(labels.map(\.stringValue) == [
            "Name", "Prompt", "Provider ID", "Model ID", "Output profile",
            "Task time limit", "First run", "Repeat"
        ])
        for (index, entry) in controls.enumerated() {
            #expect(entry.0.accessibilityLabel() == entry.1)
            try expectTitleRelationship(entry.0, title: labels[index])
        }
    }

    @Test func mcpAddAndEditWindowsExposeEveryFieldAndSafetyLimit() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let project = FileManager.default.temporaryDirectory
            .appendingPathComponent("FulmarMCPAccessibility-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: project) }
        let choice = MCPProviderChoice(
            provider: ProviderID("ollama"),
            displayName: "Qwen local",
            boundary: .onDevice
        )
        let add = MCPServerEditorSheetController(
            projectRoot: project,
            providerChoices: [choice],
            existing: nil
        )
        try verifyMCPWindow(add, expectedTitle: "Add MCP Server")

        let existing = MCPServerDraft(
            id: "safe-local",
            displayName: "Safe Local Server",
            serverName: "safe_local",
            executablePath: "/usr/bin/true",
            allowedProviders: [MCPProviderEnablement(provider: choice.provider, boundary: choice.boundary)],
            disclosure: MCPDisclosureProfile(
                boundary: .onDevice,
                dataKinds: [.toolArguments, .toolResults]
            )
        )
        let edit = MCPServerEditorSheetController(
            projectRoot: project,
            providerChoices: [choice],
            existing: existing
        )
        try verifyMCPWindow(edit, expectedTitle: "Edit MCP Server")
    }

    @Test func historyWindowConstructsAtItsMinimumSize() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let history = SessionHistoryWindowController(rpcClient: HarnessRPCClient())
        _ = try verifyMinimumWindow(history)
    }

    @Test func artifactAndComparisonPreviewsReceiveDistinctAccessibleNames() {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let primary = NSView()
        let left = NSView()
        let right = NSView()
        ArtifactPreviewAccessibility.configure(primary, position: .primary, fileName: "artifact.pdf")
        ArtifactPreviewAccessibility.configure(left, position: .left, fileName: "before.pdf")
        ArtifactPreviewAccessibility.configure(right, position: .right, fileName: "after.pdf")

        #expect(primary.accessibilityLabel() == "Artifact preview: artifact.pdf")
        #expect(left.accessibilityLabel() == "Left artifact preview: before.pdf")
        #expect(right.accessibilityLabel() == "Right artifact preview: after.pdf")
        #expect(primary.accessibilityHelp()?.isEmpty == false)
        #expect(left.accessibilityHelp()?.contains("left side") == true)
        #expect(right.accessibilityHelp()?.contains("right side") == true)
    }

    @Test func exactMCPApprovalReviewHasASecuritySpecificNameAndVisibleTitle() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let title = NSTextField(labelWithString: "Review before approving")
        let review = NSTextView()
        MCPReviewAccessibility.configure(review: review, title: title)

        #expect(review.accessibilityLabel() == "Exact MCP server configuration review")
        #expect(review.accessibilityHelp()?.contains("provider boundaries") == true)
        try expectTitleRelationship(review, title: title)
    }

    private func verifyMCPWindow(
        _ controller: MCPServerEditorSheetController,
        expectedTitle: String
    ) throws {
        // The editor intentionally keeps a form taller than its viewport in a
        // scroll view. Validate the fixed shell at minimum size, then inspect
        // the scrolled controls independently below.
        let root = try verifyMinimumWindow(controller, skipsScrolledContent: true)
        #expect(controller.window?.title == expectedTitle)
        let expected = Set([
            "MCP definition ID",
            "MCP display name",
            "MCP tool namespace",
            "MCP executable path",
            "MCP literal arguments",
            "MCP code-file argument indexes",
            "MCP working folder",
            "MCP server destination boundary",
            "MCP destination name",
            "MCP credential reference bindings",
            "MCP startup timeout in seconds",
            "MCP tool-call timeout in seconds",
            "MCP maximum discovered tools",
            "MCP maximum result in KiB",
            "MCP reconnect attempts"
        ])
        let views = descendants(of: root)
        let labeled = Dictionary(grouping: views.compactMap { view -> (String, NSView)? in
            guard let label = view.accessibilityLabel(), !label.isEmpty else { return nil }
            return (label, view)
        }, by: \.0)
        for name in expected {
            let control = try #require(labeled[name]?.first?.1)
            #expect(control.accessibilityTitleUIElement() != nil)
        }
    }

    private func verifyMinimumWindow(
        _ controller: NSWindowController,
        skipsScrolledContent: Bool = false
    ) throws -> NSView {
        let window = try #require(controller.window)
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
        window.contentView?.layoutSubtreeIfNeeded()
        let root = try #require(window.contentViewController?.view)
        let layoutViews = skipsScrolledContent
            ? descendantsOutsideScrollDocuments(of: root)
            : descendants(of: root)
        for view in layoutViews
            where view is NSButton || view is NSTextField || view is NSStackView {
            #expect(!view.hasAmbiguousLayout)
            guard !view.isHidden else { continue }
            let frame = view.convert(view.bounds, to: root)
            #expect(frame.minX >= root.bounds.minX - 0.5)
            #expect(frame.maxX <= root.bounds.maxX + 0.5)
            #expect(frame.minY >= root.bounds.minY - 0.5)
            #expect(frame.maxY <= root.bounds.maxY + 0.5)
        }
        return root
    }

    private func expectTitleRelationship(_ control: NSView, title: NSTextField) throws {
        let titleElement = try #require(control.accessibilityTitleUIElement() as? NSTextField)
        #expect(titleElement === title)
        let titled = title.accessibilityServesAsTitleForUIElements() ?? []
        #expect(titled.contains { ($0 as? NSView) === control })
    }

    private func descendants(of root: NSView) -> [NSView] {
        return [root] + root.subviews.flatMap(descendants(of:))
    }

    private func descendantsOutsideScrollDocuments(of root: NSView) -> [NSView] {
        guard !(root is NSScrollView) else { return [root] }
        return [root] + root.subviews.flatMap(descendantsOutsideScrollDocuments(of:))
    }
}
