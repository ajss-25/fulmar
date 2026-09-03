import AppKit
import Foundation
import Testing
@testable import LocalHarness

private final class LayoutScheduleExecutor: ScheduleConversationExecuting, @unchecked Sendable {
    @discardableResult
    func execute(
        _ request: ScheduleConversationRequest,
        completion: @escaping ScheduleConversationExecuting.Completion
    ) -> UUID {
        UUID()
    }

    func cancel(_ identifier: UUID) {}

    func cancelAll() {}
}

@MainActor
@Test func scheduleTableAndActionsRemainAccessibleAtMinimumWindowSize() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarScheduleLayout-\(UUID().uuidString)", isDirectory: true)
    let suite = "FulmarScheduleLayout.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer {
        try? FileManager.default.removeItem(at: root)
        defaults.removePersistentDomain(forName: suite)
    }

    let activities = ActivityStore(applicationSupport: root)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: LayoutScheduleExecutor(),
        activities: activities
    )
    let controller = ScheduleWindowController(
        manager: manager,
        preferences: PreferencesStore(defaults: defaults)
    )
    let window = try #require(controller.window)
    window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
    window.contentView?.layoutSubtreeIfNeeded()
    let content = try #require(window.contentView)

    for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
        window.appearance = NSAppearance(named: appearanceName)
        window.layoutIfNeeded()
        window.contentView?.layoutSubtreeIfNeeded()
        window.contentView?.displayIfNeeded()
        window.layoutIfNeeded()
        let scheduleScroll = try #require(
            descendants(of: content).compactMap { $0 as? NSScrollView }
                .first { $0.documentView is NSTableView }
        )
        let table = try #require(scheduleScroll.documentView as? NSTableView)
        #expect(table.tableColumns.map(\.identifier.rawValue).contains("boundary"))
        #expect(
            table.frame.width <= scheduleScroll.documentVisibleRect.width
                || scheduleScroll.hasHorizontalScroller
        )

        let buttonTitles = Set([
            "New Schedule…", "Open Task Inbox", "Run Now", "Cancel Run",
            "Enable / Disable", "Revoke External Access", "Delete"
        ])
        let buttons = descendants(of: content).compactMap { $0 as? NSButton }
            .filter { buttonTitles.contains($0.title) }
        #expect(buttons.count == buttonTitles.count)
        for button in buttons {
            let rect = button.convert(button.bounds, to: content)
            #expect(content.bounds.insetBy(dx: -0.5, dy: -0.5).contains(rect))
        }
    }
}

@MainActor
private func descendants(of root: NSView) -> [NSView] {
    root.subviews.flatMap { [$0] + descendants(of: $0) }
}
