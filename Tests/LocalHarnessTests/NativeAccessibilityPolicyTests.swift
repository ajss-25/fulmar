import AppKit
import Testing
@testable import LocalHarness

private enum AccessibilityPolicyFixtureError: Error {
    case unavailable
}

private func accessibilityDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(accessibilityDescendants)
}

private func accessibilityRecoveryOperations() -> WorkspaceRecoveryOperations {
    WorkspaceRecoveryOperations(
        approvedWorkspaceURL: URL(fileURLWithPath: "/tmp/fulmar-accessibility-policy", isDirectory: true),
        listCheckpoints: { [] },
        captureCheckpoint: { _ in throw AccessibilityPolicyFixtureError.unavailable },
        deleteCheckpoint: { _ in },
        previewRestore: { _ in throw AccessibilityPolicyFixtureError.unavailable },
        restore: { _, _, _ in throw AccessibilityPolicyFixtureError.unavailable }
    )
}

private func accessibilityProgressIndicator(in root: NSView) throws -> NSProgressIndicator {
    try #require(
        accessibilityDescendants(of: root).compactMap { $0 as? NSProgressIndicator }.first
    )
}

@Test func semanticTypographyScaleIsBoundedAndPreservesRoleHierarchy() {
    #expect(NativeTypographyPolicy(scale: 0.5).scale == 1)
    #expect(NativeTypographyPolicy(scale: 2).scale == 1.5)

    for scale in [CGFloat(1), 1.25, 1.5] {
        let policy = NativeTypographyPolicy(scale: scale)
        #expect(abs(policy.font(for: .toolbarStatus).pointSize - 11 * scale) < 0.01)
        #expect(abs(policy.font(for: .settingsHeading).pointSize - 22 * scale) < 0.01)
        #expect(abs(policy.font(for: .settingsSubtitle).pointSize - 13 * scale) < 0.01)
        #expect(abs(policy.font(for: .settingsNote).pointSize - 11.5 * scale) < 0.01)
        #expect(abs(policy.font(for: .workspaceStatus).pointSize - 15 * scale) < 0.01)
        #expect(abs(policy.font(for: .workspaceDetail).pointSize - 13 * scale) < 0.01)
        #expect(policy.toolbarControlHeight >= 26)
    }
    #expect(NativeTypographyPolicy(scale: 1).toolbarControlHeight == 26)
}

@MainActor
@Test func reduceTransparencySelectsOpaqueSidebarContainers() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let vibrant = NativeAccessibilityDisplayPolicy.fixed().makeSidebarContainer()
    #expect(!vibrant.isUsingOpaqueBackground)
    let vibrantViews = accessibilityDescendants(of: vibrant)
    #expect(vibrantViews.compactMap { $0 as? NSVisualEffectView }.first?.isHidden == false)
    #expect(vibrantViews.compactMap { $0 as? AppearanceAwareLayerView }.first?.isHidden == true)

    let opaque = NativeAccessibilityDisplayPolicy.fixed(
        reduceTransparency: true
    ).makeSidebarContainer()
    #expect(opaque.isUsingOpaqueBackground)
    let opaqueViews = accessibilityDescendants(of: opaque)
    #expect(opaqueViews.compactMap { $0 as? NSVisualEffectView }.first?.isHidden == true)
    let opaqueLayer = try #require(opaqueViews.compactMap { $0 as? AppearanceAwareLayerView }.first)
    #expect(!opaqueLayer.isHidden)
    #expect(opaqueLayer.semanticBackgroundColor == .windowBackgroundColor)
    #expect(opaqueLayer.backgroundAlpha == 1)
}

@MainActor
@Test func recoveryAndHistoryControllersHonorOpaqueSidebarInjection() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let opaquePolicy = NativeAccessibilityDisplayPolicy.fixed(reduceTransparency: true)
    let recovery = WorkspaceRecoveryWindowController(
        operations: accessibilityRecoveryOperations(),
        displayPolicy: opaquePolicy
    )
    let recoveryRoot = try #require(recovery.window?.contentViewController?.view)
    let recoveryViews = accessibilityDescendants(of: recoveryRoot)
    let recoverySidebar = try #require(
        recoveryViews.compactMap { $0 as? NativeAccessibilitySidebarView }.first
    )
    #expect(recoverySidebar.isUsingOpaqueBackground)

    let history = SessionHistoryWindowController(
        rpcClient: HarnessRPCClient(),
        displayPolicy: opaquePolicy
    )
    let historyRoot = try #require(history.window?.contentViewController?.view)
    let historyViews = accessibilityDescendants(of: historyRoot)
    let historySidebar = try #require(
        historyViews.compactMap { $0 as? NativeAccessibilitySidebarView }.first
    )
    #expect(historySidebar.isUsingOpaqueBackground)
}

@MainActor
@Test func liveAccessibilityNotificationRefreshesExistingBusyIndicatorAndSidebars() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    final class PreferenceState {
        var reducesMotion = false
        var reducesTransparency = false
    }
    let state = PreferenceState()
    let policy = NativeAccessibilityDisplayPolicy(
        reduceMotion: { state.reducesMotion },
        reduceTransparency: { state.reducesTransparency }
    )
    let recovery = WorkspaceRecoveryWindowController(
        operations: accessibilityRecoveryOperations(),
        displayPolicy: policy
    )
    let recoveryRoot = try #require(recovery.window?.contentViewController?.view)
    let recoveryViews = accessibilityDescendants(of: recoveryRoot)
    let indicator = try accessibilityProgressIndicator(in: recoveryRoot)
    let recoverySidebar = try #require(
        recoveryViews.compactMap { $0 as? NativeAccessibilitySidebarView }.first
    )
    let history = SessionHistoryWindowController(
        rpcClient: HarnessRPCClient(),
        displayPolicy: policy
    )
    let historyRoot = try #require(history.window?.contentViewController?.view)
    let historySidebar = try #require(
        accessibilityDescendants(of: historyRoot)
            .compactMap { $0 as? NativeAccessibilitySidebarView }.first
    )

    recovery.setBusy(true, message: "Working safely…")
    #expect(!indicator.isHidden)
    #expect(!recoverySidebar.isUsingOpaqueBackground)
    #expect(!historySidebar.isUsingOpaqueBackground)

    state.reducesMotion = true
    state.reducesTransparency = true
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(indicator.isHidden)
    #expect(recoverySidebar.isUsingOpaqueBackground)
    #expect(historySidebar.isUsingOpaqueBackground)

    state.reducesMotion = false
    state.reducesTransparency = false
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(!indicator.isHidden)
    #expect(!recoverySidebar.isUsingOpaqueBackground)
    #expect(!historySidebar.isUsingOpaqueBackground)
}

@Test func progressIndicatorPresentationCoversBusyAndReduceMotionMatrix() {
    let expected: [(reducesMotion: Bool, busy: Bool, presentation: NativeProgressIndicatorPresentation)] = [
        (false, false, NativeProgressIndicatorPresentation(isHidden: true, shouldAnimate: false)),
        (false, true, NativeProgressIndicatorPresentation(isHidden: false, shouldAnimate: true)),
        (true, false, NativeProgressIndicatorPresentation(isHidden: true, shouldAnimate: false)),
        (true, true, NativeProgressIndicatorPresentation(isHidden: true, shouldAnimate: false))
    ]

    for entry in expected {
        let policy = NativeAccessibilityDisplayPolicy.fixed(reduceMotion: entry.reducesMotion)
        #expect(policy.progressIndicatorPresentation(isBusy: entry.busy) == entry.presentation)
    }
}

@MainActor
@Test func workspaceRecoveryBusyIndicatorHonorsInjectedMotionPolicy() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for reducesMotion in [false, true] {
        let controller = WorkspaceRecoveryWindowController(
            operations: accessibilityRecoveryOperations(),
            displayPolicy: .fixed(reduceMotion: reducesMotion)
        )
        let root = try #require(controller.window?.contentViewController?.view)
        let indicator = try accessibilityProgressIndicator(in: root)

        controller.setBusy(true, message: "Working safely…")
        #expect(indicator.isHidden == reducesMotion)

        controller.setBusy(false, message: "Ready")
        #expect(indicator.isHidden)
    }
}
