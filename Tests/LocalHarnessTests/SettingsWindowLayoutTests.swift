import AppKit
import Testing
@testable import LocalHarness

@MainActor
@Test func settingsUseCompactTabsWithoutAnEmptyToolbarBand() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarSettingsWindowLayoutTests.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }

    let controller = SettingsWindowController(preferences: PreferencesStore(defaults: defaults))
    let tabs = try #require(controller.window?.contentViewController as? NSTabViewController)

    #expect(tabs.tabStyle == .segmentedControlOnTop)
    #expect(tabs.tabViewItems.map(\.label) == ["General", "Models", "Privacy", "Advanced"])
    #expect(SettingsWindowController.contentTopInset == 18)
    for item in tabs.tabViewItems {
        let root = try #require(item.viewController?.view)
        let scroll = try #require(root.subviews.compactMap { $0 as? NSScrollView }.first)
        #expect(scroll.hasVerticalScroller)
        #expect(scroll.documentView != nil)
    }
}

@MainActor
@Test func everySettingsPageRemainsReachableAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarSettingsMinimumLayoutTests.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }

    let controller = SettingsWindowController(preferences: PreferencesStore(defaults: defaults))
    let window = try #require(controller.window)
    let tabs = try #require(window.contentViewController as? NSTabViewController)
    window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
    let expectedHeadings = [
        "Everyday use",
        "Local model performance",
        "Privacy and access",
        "Reliability and support"
    ]

    for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
        window.appearance = NSAppearance(named: appearanceName)
        for index in tabs.tabViewItems.indices {
            tabs.selectedTabViewItemIndex = index
            window.layoutIfNeeded()
            tabs.view.layoutSubtreeIfNeeded()
            tabs.view.displayIfNeeded()
            window.layoutIfNeeded()

            let root = try #require(tabs.tabViewItems[index].viewController?.view)
            let scroll = try #require(settingsDescendants(of: root).compactMap { $0 as? NSScrollView }.first)
            let document = try #require(scroll.documentView)
            let segmentedControl = try #require(
                settingsDescendants(of: tabs.view).compactMap { $0 as? NSSegmentedControl }.first
            )
            let heading = try #require(
                settingsDescendants(of: document).compactMap { $0 as? NSTextField }
                    .first { $0.stringValue == expectedHeadings[index] }
            )
            // Window-base coordinates are always non-flipped, so this proves
            // the content begins below—not overlapping or above—the tabs.
            let segmentedFrame = segmentedControl.convert(segmentedControl.bounds, to: nil)
            let headingFrame = heading.convert(heading.bounds, to: nil)
            #expect(segmentedFrame.minY >= headingFrame.maxY)
            let verticalGap = segmentedFrame.minY - headingFrame.maxY
            #expect(!scroll.hasHorizontalScroller)
            #expect(document.frame.width <= scroll.documentVisibleRect.width + 0.5)
            #expect(!document.hasAmbiguousLayout)
            #expect(verticalGap >= SettingsWindowController.contentTopInset - 1)
            #expect(
                verticalGap <= 48,
                Comment(rawValue: "\(tabs.tabViewItems[index].label) content begins \(verticalGap) points from the segmented tabs")
            )

            for view in settingsDescendants(of: document)
                where view is NSButton || view is NSTextField || view is NSPopUpButton || view is NSStackView {
                #expect(!view.hasAmbiguousLayout)
                guard !view.isHidden else { continue }
                let frame = view.convert(view.bounds, to: document)
                #expect(frame.minX >= document.bounds.minX - 0.5)
                #expect(frame.maxX <= document.bounds.maxX + 0.5)
                #expect(frame.minY >= document.bounds.minY - 0.5)
                #expect(frame.maxY <= document.bounds.maxY + 0.5)
            }
        }
    }
}

@MainActor
@Test func settingsSemanticTypeScalesFitEveryPageAtDeclaredMinimum() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scale in [CGFloat(1), 1.25, 1.5] {
        let suite = "FulmarSettingsTypeScale.\(scale).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        let typography = NativeTypographyPolicy(scale: scale)
        let controller = SettingsWindowController(
            preferences: PreferencesStore(defaults: defaults),
            typography: typography
        )
        let window = try #require(controller.window)
        let tabs = try #require(window.contentViewController as? NSTabViewController)
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)

        for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearanceName)
            for index in tabs.tabViewItems.indices {
                tabs.selectedTabViewItemIndex = index
                window.layoutIfNeeded()
                let root = try #require(tabs.tabViewItems[index].viewController?.view)
                let descendants = settingsDescendants(of: root)
                let scroll = try #require(descendants.compactMap { $0 as? NSScrollView }.first)
                let document = try #require(scroll.documentView)
                #expect(!scroll.hasHorizontalScroller)
                #expect(document.frame.width <= scroll.documentVisibleRect.width + 0.5)
                #expect(!document.hasAmbiguousLayout)
                for view in settingsDescendants(of: document) where !view.isHidden {
                    #expect(!view.hasAmbiguousLayout)
                    let frame = view.convert(view.bounds, to: document)
                    #expect(frame.minX >= document.bounds.minX - 0.5)
                    #expect(frame.maxX <= document.bounds.maxX + 0.5)
                }

                let fields = descendants.compactMap { $0 as? NSTextField }
                #expect(fields.contains {
                    abs(($0.font?.pointSize ?? 0) - typography.font(for: .settingsHeading).pointSize) < 0.01
                })
                #expect(fields.contains {
                    abs(($0.font?.pointSize ?? 0) - typography.font(for: .settingsSubtitle).pointSize) < 0.01
                })
                #expect(fields.contains {
                    abs(($0.font?.pointSize ?? 0) - typography.font(for: .settingsNote).pointSize) < 0.01
                })
            }
        }

        defaults.removePersistentDomain(forName: suite)
    }
}

private func settingsDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(settingsDescendants)
}
