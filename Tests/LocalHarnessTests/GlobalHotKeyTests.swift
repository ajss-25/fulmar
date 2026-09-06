import AppKit
import Testing
@testable import LocalHarness

private final class GlobalHotKeyTestToken: GlobalHotKeyRegistrationToken {
    private let onInvalidate: () -> Void
    private var invalidated = false

    init(onInvalidate: @escaping () -> Void) {
        self.onInvalidate = onInvalidate
    }

    func invalidate() {
        guard !invalidated else { return }
        invalidated = true
        onInvalidate()
    }
}

private final class GlobalHotKeyTestRegistrar: GlobalHotKeyRegistering {
    var result: Result<GlobalHotKeyRegistrationToken, GlobalHotKeyRegistrationFailure>
    private(set) var registeredKeyCode: UInt32?
    private(set) var registeredModifiers: UInt32?
    private(set) var action: (() -> Void)?

    init(result: Result<GlobalHotKeyRegistrationToken, GlobalHotKeyRegistrationFailure>) {
        self.result = result
    }

    func register(
        keyCode: UInt32,
        modifiers: UInt32,
        action: @escaping () -> Void
    ) -> Result<GlobalHotKeyRegistrationToken, GlobalHotKeyRegistrationFailure> {
        registeredKeyCode = keyCode
        registeredModifiers = modifiers
        self.action = action
        return result
    }
}

private final class GlobalHotKeyTestProbe {
    var invalidations = 0
    var actions = 0
}

private func successfullyRegisteredGlobalHotKey(
    registrar: GlobalHotKeyRegistering,
    action: @escaping () -> Void
) -> GlobalHotKey? {
    guard case .success(let registration) = GlobalHotKey.register(
        keyCode: 49,
        modifiers: 2_048,
        registrar: registrar,
        action: action
    ) else { return nil }
    return registration
}

@Test func globalHotKeyReportsHandlerAndShortcutRegistrationFailures() {
    for failure in [
        GlobalHotKeyRegistrationFailure.eventHandlerRegistrationFailed(-987),
        .shortcutRegistrationFailed(-986)
    ] {
        let registrar = GlobalHotKeyTestRegistrar(result: .failure(failure))
        let result = GlobalHotKey.register(
            keyCode: 49,
            modifiers: 2_048,
            registrar: registrar,
            action: {}
        )
        guard case .failure(let actual) = result else {
            Issue.record("A failed registrar must not produce an active shortcut")
            continue
        }
        #expect(actual == failure)
        #expect(registrar.registeredKeyCode == 49)
        #expect(registrar.registeredModifiers == 2_048)

        let availability = GlobalHotKeyAvailability.unavailable(actual)
        #expect(availability.statusMenuDetail == "Option-Space unavailable — use Chat or ⌘⌥Space")
        #expect(availability.diagnosticSummary.contains("status"))
    }
}

@Test func globalHotKeySuccessDispatchesAndUnregistersExactlyOnce() {
    let probe = GlobalHotKeyTestProbe()
    let token = GlobalHotKeyTestToken { probe.invalidations += 1 }
    let registrar = GlobalHotKeyTestRegistrar(result: .success(token))
    var hotKey: GlobalHotKey?

    hotKey = successfullyRegisteredGlobalHotKey(
        registrar: registrar,
        action: { probe.actions += 1 }
    )
    guard hotKey != nil else {
        Issue.record("A successful registrar must produce an active shortcut")
        return
    }
    #expect(hotKey != nil)
    registrar.action?()
    #expect(probe.actions == 1)
    #expect(GlobalHotKeyAvailability.available.statusMenuDetail == nil)
    #expect(GlobalHotKeyAvailability.available.diagnosticSummary == "Option-Space registered")
    #expect(
        GlobalHotKeyAvailability.disabledForShutdown.statusMenuDetail
            == "Option-Space disabled while shutdown is pending"
    )
    #expect(
        GlobalHotKeyAvailability.disabledForShutdown.diagnosticSummary
            == "Disabled while shutdown is pending"
    )

    hotKey = nil
    #expect(probe.invalidations == 1)
    token.invalidate()
    #expect(probe.invalidations == 1)
}

@Test func globalHotKeyCapturedCallbackIsSuppressedAfterDeallocation() throws {
    let probe = GlobalHotKeyTestProbe()
    let token = GlobalHotKeyTestToken { probe.invalidations += 1 }
    let registrar = GlobalHotKeyTestRegistrar(result: .success(token))
    var hotKey: GlobalHotKey?

    hotKey = successfullyRegisteredGlobalHotKey(
        registrar: registrar,
        action: { probe.actions += 1 }
    )
    guard hotKey != nil else {
        Issue.record("A successful registrar must produce an active shortcut")
        return
    }
    let capturedCallback = try #require(registrar.action)

    hotKey = nil
    #expect(probe.invalidations == 1)
    capturedCallback()
    #expect(probe.actions == 0)

    token.invalidate()
    #expect(probe.invalidations == 1)
}

@MainActor
@Test func diagnosticsIncludesTheNonSecretGlobalShortcutStatus() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let root = try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarHotKeyDiagnostics")
    defer { try? FileManager.default.removeItem(at: root) }
    let harness = HarnessController(
        applicationSupportDirectory: root,
        modelStoreDirectory: root.appendingPathComponent("Models"),
        forbidCredentialHelper: true
    )
    let controller = DiagnosticsWindowController(
        controller: harness,
        globalHotKeyStatus: { "Option-Space conflict; menu fallback available" }
    )
    defer { controller.close() }
    controller.refresh()
    let rootView = try #require(controller.window?.contentView)
    let report = try #require(globalHotKeyDescendants(of: rootView).compactMap { $0 as? NSTextView }.first)
    #expect(report.string.contains("Global Chat shortcut: Option-Space conflict; menu fallback available"))
    #expect(report.string.contains("Menu-bar API: "))
    #expect(report.string.contains("Menu-bar placement: "))
}

@MainActor
private func globalHotKeyDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(globalHotKeyDescendants)
}
