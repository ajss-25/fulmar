import AppKit
import Testing
import WebKit
@testable import LocalHarness

private func allDescendants(of view: NSView) -> [NSView] {
    view.subviews.flatMap { [$0] + allDescendants(of: $0) }
}

@MainActor
private final class ExternalLinkDelegateProbe: HarnessWebViewControllerDelegate {
    var opened: [URL] = []
    func webSurface(_ surface: HarnessWebViewController, didOpenExternalURL url: URL) {
        opened.append(url)
    }
    func webSurface(_ surface: HarnessWebViewController, didCompleteDownload artifact: StagedDownloadArtifact, action: StagedDownloadUserAction) {}
    func webSurface(_ surface: HarnessWebViewController, didFailWith message: String) {}
    func webSurface(
        _ surface: HarnessWebViewController,
        validateFreshSession sessionID: HarnessSessionID,
        completion: @escaping (Result<Void, Error>) -> Void
    ) { completion(.success(())) }
    func webSurface(
        _ surface: HarnessWebViewController,
        prepareTurnIn sessionID: HarnessSessionID,
        operationID: UUID,
        completion: @escaping (Result<TurnPreparationBridgeResult, Error>) -> Void
    ) { completion(.failure(CancellationError())) }
    func webSurface(_ surface: HarnessWebViewController, cancelTurnPreparation operationID: UUID) {}
    func performanceSessionID(for surface: HarnessWebViewController) -> HarnessSessionID? { nil }
    func approvedWorkspacePath(for surface: HarnessWebViewController) -> String? { nil }
}

@Test @MainActor
func externalBrowserHandoffConfirmsExactNormalizedHTTPSAndCancelDoesNothing() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarExternalLinkHandoff.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let preferences = PreferencesStore(defaults: defaults)
    preferences.confirmExternalLinks = true
    let surface = HarnessWebViewController(dataStore: .nonPersistent(), preferences: preferences)
    surface.configure(endpoint: HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:3080/")!,
        token: "test-token",
        nonce: "test-nonce",
        processIdentifier: 123
    ))
    let delegate = ExternalLinkDelegateProbe()
    surface.delegate = delegate
    var confirmations: [URL] = []
    surface.externalLinkConfirmationHandler = { url in
        confirmations.append(url)
        return false
    }

    surface.requestExternalBrowserHandoff(
        URL(string: "HTTPS://Example.COM:443/a/../report?q=one#result")!
    )
    #expect(confirmations.map(\.absoluteString) == ["https://example.com/report?q=one#result"])
    #expect(delegate.opened.isEmpty)

    surface.externalLinkConfirmationHandler = { url in
        confirmations.append(url)
        return true
    }
    surface.requestExternalBrowserHandoff(URL(string: "https://EXAMPLE.com:8443/approved")!)
    #expect(delegate.opened.map(\.absoluteString) == ["https://example.com:8443/approved"])

    surface.requestExternalBrowserHandoff(URL(string: "http://example.com/plaintext")!)
    surface.requestExternalBrowserHandoff(URL(string: "https://user:secret@example.com/private")!)
    #expect(confirmations.count == 2)
    #expect(delegate.opened.count == 1)

    preferences.confirmExternalLinks = false
    surface.externalLinkConfirmationHandler = { _ in
        Issue.record("confirmation must not run when the user disabled it")
        return false
    }
    surface.requestExternalBrowserHandoff(URL(string: "https://example.com/direct")!)
    #expect(delegate.opened.map(\.absoluteString) == [
        "https://example.com:8443/approved",
        "https://example.com/direct"
    ])
}

@Test func recoveryBridgeV2RequiresExactOperationBoundSchemas() throws {
    let operation = try #require(UUID(uuidString: "12345678-1234-4123-8123-1234567890AB"))
    #expect(RecoveryBridgeRequest.decode([
        "version": 2,
        "action": "prepare",
        "operationID": operation.uuidString,
        "sessionID": "session/one"
    ]) == .prepare(operationID: operation, sessionID: HarnessSessionID("session/one")))
    #expect(RecoveryBridgeRequest.decode([
        "version": 2,
        "action": "cancel",
        "operationID": operation.uuidString
    ]) == .cancel(operationID: operation))

    for hostile in [
        ["version": 1, "action": "prepare", "operationID": operation.uuidString, "sessionID": "s"],
        ["version": 2, "action": "cancel", "operationID": operation.uuidString, "sessionID": "smuggled"],
        ["version": 2, "action": "prepare", "operationID": operation.uuidString],
        ["version": 2, "action": "prepare", "operationID": "not-a-uuid", "sessionID": "s"],
        ["version": 2, "action": "prepare", "operationID": operation.uuidString, "sessionID": "bad\nvalue"],
        ["version": 2, "action": "unknown", "operationID": operation.uuidString]
    ] as [[String: Any]] {
        #expect(RecoveryBridgeRequest.decode(hostile) == nil)
    }
}

@Test func recoveryBridgeRequiresAnExactIntegerProtocolVersion() throws {
    let operation = try #require(UUID(uuidString: "12345678-1234-4123-8123-1234567890AB"))
    let base: [String: Any] = [
        "action": "prepare",
        "operationID": operation.uuidString,
        "sessionID": "session/one"
    ]

    // A JavaScript Number may arrive as a floating NSNumber even when its
    // value is an integer. Its semantics remain exact and must be accepted.
    var bridgedJavaScriptInteger = base
    bridgedJavaScriptInteger["version"] = NSNumber(value: 2.0)
    #expect(RecoveryBridgeRequest.decode(bridgedJavaScriptInteger) != nil)

    let hostileVersions: [Any] = [
        NSNumber(value: 2.9),
        NSNumber(value: 2.000_001),
        NSNumber(value: Double.nan),
        NSNumber(value: Double.infinity),
        NSNumber(value: true),
        "2",
        "2.0",
        NSNull()
    ]
    for hostileVersion in hostileVersions {
        var body = base
        body["version"] = hostileVersion
        #expect(RecoveryBridgeRequest.decode(body) == nil)
    }
}

@Test func recoveryBridgeRequiresRFC4122Version4OperationIdentities() throws {
    let accepted = try #require(UUID(uuidString: "12345678-1234-4123-8123-1234567890AB"))
    #expect(RecoveryBridgeRequest.decode([
        "version": 2,
        "action": "cancel",
        "operationID": accepted.uuidString
    ]) == .cancel(operationID: accepted))

    let disallowedIdentities = [
        // Correct RFC 4122 variant, but UUID versions 1, 3 and 5.
        "12345678-1234-1123-8123-1234567890AB",
        "12345678-1234-3123-8123-1234567890AB",
        "12345678-1234-5123-8123-1234567890AB",
        // Version 4 with NCS, Microsoft and reserved variant bits.
        "12345678-1234-4123-0123-1234567890AB",
        "12345678-1234-4123-C123-1234567890AB",
        "12345678-1234-4123-E123-1234567890AB"
    ]
    for identity in disallowedIdentities {
        #expect(RecoveryBridgeRequest.decode([
            "version": 2,
            "action": "cancel",
            "operationID": identity
        ]) == nil)
    }
}

@Test @MainActor
func browserTurnPreparationAdmissionIsBoundedAndDuplicateSafe() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let gate = BrowserTurnPreparationAdmissionGate(maximumConcurrent: 3)
    let first = UUID()
    let second = UUID()
    let third = UUID()
    let overflow = UUID()

    #expect(gate.admit(first) == .accepted)
    #expect(gate.admit(second) == .accepted)
    #expect(gate.admit(third) == .accepted)
    #expect(gate.count == 3)
    #expect(gate.admit(first) == .duplicateOperation)
    #expect(gate.admit(overflow) == .atCapacity)
    #expect(gate.count == 3)
    #expect(!gate.release(overflow))
    #expect(gate.release(second))
    #expect(gate.admit(second) == .duplicateOperation)
    #expect(gate.admit(overflow) == .accepted)
    #expect(gate.count == 3)
}

@Test @MainActor
func completedBrowserTurnOperationIdentitiesHaveABoundedReplayWindow() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let gate = BrowserTurnPreparationAdmissionGate(
        maximumConcurrent: 1,
        completedReplayCapacity: 2
    )
    let first = UUID()
    let second = UUID()
    let third = UUID()

    #expect(gate.admit(first) == .accepted)
    #expect(gate.release(first))
    #expect(gate.admit(first) == .duplicateOperation)
    #expect(gate.admit(second) == .accepted)
    #expect(gate.release(second))
    #expect(gate.admit(third) == .accepted)
    #expect(gate.release(third))
    #expect(gate.completedReplayCount == 2)

    // The oldest identity is evicted only when the fixed-size replay window
    // advances; both newer completed identities remain blocked.
    #expect(gate.admit(first) == .accepted)
    #expect(gate.admit(second) == .duplicateOperation)
    #expect(gate.admit(third) == .duplicateOperation)
}

@Test func concurrentBrowserTurnPreparationFloodNeverExceedsTheAdmissionCap() async {
    let maximumConcurrent = 8
    let gate = await BrowserTurnPreparationAdmissionGate(
        maximumConcurrent: maximumConcurrent
    )

    // Repeated waves exercise the same main-actor serialization used by the
    // real WKWebView delegate while callers race from independent tasks.
    for _ in 0..<16 {
        let operationIDs = (0..<128).map { _ in UUID() }
        var acceptedOperationIDs: [UUID] = []
        await withTaskGroup(of: (UUID, BrowserTurnPreparationAdmission).self) { group in
            for operationID in operationIDs {
                group.addTask {
                    (operationID, await gate.admit(operationID))
                }
            }
            for await (operationID, admission) in group {
                if admission == .accepted {
                    acceptedOperationIDs.append(operationID)
                }
            }
        }

        #expect(acceptedOperationIDs.count == maximumConcurrent)
        #expect(await gate.count == maximumConcurrent)
        await withTaskGroup(of: Bool.self) { group in
            for operationID in acceptedOperationIDs {
                group.addTask {
                    await gate.release(operationID)
                }
            }
            var releases = 0
            for await released in group where released {
                releases += 1
            }
            #expect(releases == maximumConcurrent)
        }
        #expect(await gate.count == 0)
        #expect(await gate.completedReplayCount <= BrowserTurnPreparationAdmissionGate.productionCompletedReplayCapacity)
    }
}

@MainActor
private final class TestNavigationWaiter: NSObject, WKNavigationDelegate {
    private enum WaitError: Error {
        case timedOut
    }

    private var result: Result<Void, Error>?
    private var continuation: CheckedContinuation<Void, Error>?
    private var timeoutTask: Task<Void, Never>?

    func wait() async throws {
        if let result {
            try result.get()
            return
        }
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            timeoutTask = Task { @MainActor [weak self] in
                do {
                    try await Task.sleep(for: .seconds(5))
                } catch {
                    return
                }
                self?.resolve(.failure(WaitError.timedOut))
            }
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        resolve(.success(()))
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation!,
        withError error: Error
    ) {
        resolve(.failure(error))
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        resolve(.failure(error))
    }

    private func resolve(_ result: Result<Void, Error>) {
        guard self.result == nil else { return }
        self.result = result
        timeoutTask?.cancel()
        timeoutTask = nil
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(with: result)
    }
}

@Test @MainActor
func providerRecoveryActionsExistOnlyForTypedRecoveryAndAreKeyboardAccessible() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        displayPolicy: .fixed()
    )
    surface.loadViewIfNeeded()
    let buttons = allDescendants(of: surface.view).compactMap { $0 as? NSButton }
    let retry = try #require(buttons.first { $0.title == "Retry Verification" })
    let localModels = try #require(buttons.first { $0.title == "Choose Installed Local Model" })
    let providers = try #require(buttons.first { $0.title == "Models & Providers" })
    let reset = try #require(buttons.first { $0.title == "Reset Damaged State…" })
    #expect(retry.keyEquivalent == "\r")
    #expect(providers.keyEquivalent == ",")
    #expect(providers.keyEquivalentModifierMask == [.command])
    #expect(providers.accessibilityHelp()?.contains("selected local model") == true)
    #expect(providers.accessibilityHelp()?.localizedCaseInsensitiveContains("qwen") == false)

    var actions: [String] = []
    surface.showProviderRecovery(
        "Repair required",
        allowsNativeStateReset: true,
        retry: { actions.append("retry") },
        chooseLocalModel: { actions.append("local-models") },
        openProviders: { actions.append("providers") },
        resetNativeState: { actions.append("reset") }
    )
    #expect(surface.isProviderRecoveryVisible)
    #expect(retry.isEnabled && !retry.isHidden)
    #expect(localModels.isEnabled && !localModels.isHidden)
    #expect(localModels.accessibilityLabel() == "Choose an installed local model")
    #expect(localModels.accessibilityHelp()?.contains("Local Models") == true)
    #expect(providers.isEnabled && !providers.isHidden)
    #expect(reset.isEnabled && !reset.isHidden)
    retry.performClick(nil)
    localModels.performClick(nil)
    providers.performClick(nil)
    reset.performClick(nil)
    #expect(actions == ["retry", "local-models", "providers", "reset"])

    surface.showProviderRecovery(
        "Non-local repair required",
        allowsNativeStateReset: false,
        retry: {},
        chooseLocalModel: nil,
        openProviders: {},
        resetNativeState: nil
    )
    localModels.performClick(nil)
    #expect(localModels.isHidden && !localModels.isEnabled)
    #expect(actions == ["retry", "local-models", "providers", "reset"])

    surface.showFailure("Integrity failure")
    #expect(!surface.isProviderRecoveryVisible)
    #expect(!retry.isEnabled)
    #expect(localModels.isHidden && !localModels.isEnabled)
    #expect(!providers.isEnabled)
    #expect(!reset.isEnabled)
}

@Test @MainActor
func thermalCooldownKeepsExplicitProviderAndPerformanceActionsAvailable() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        displayPolicy: .fixed()
    )
    surface.loadViewIfNeeded()
    let buttons = allDescendants(of: surface.view).compactMap { $0 as? NSButton }
    let providers = try #require(buttons.first { $0.title == "Switch Model or Provider" })
    let performance = try #require(buttons.first { $0.title == "Performance Details" })
    #expect(providers.keyEquivalent == ",")
    #expect(providers.keyEquivalentModifierMask == [.command])
    #expect(performance.keyEquivalent == "p")
    #expect(performance.keyEquivalentModifierMask == [.command, .option])

    var actions: [String] = []
    surface.showThermalCooldown(
        headline: "Local AI paused safely",
        detail: "The task remains visible and saved.",
        openProviders: { actions.append("providers") },
        openPerformance: { actions.append("performance") }
    )
    #expect(surface.isThermalCooldownVisible)
    #expect(providers.isEnabled && !providers.isHidden)
    #expect(performance.isEnabled && !performance.isHidden)
    let overlay = try #require(
        allDescendants(of: surface.view).compactMap { $0 as? AppearanceAwareLayerView }
            .first { abs($0.backgroundAlpha - 0.90) < 0.001 }
    )
    providers.performClick(nil)
    performance.performClick(nil)
    #expect(actions == ["providers", "performance"])

    surface.showProviderRecovery(
        "Provider repair required",
        allowsNativeStateReset: false,
        retry: {},
        chooseLocalModel: nil,
        openProviders: {},
        resetNativeState: nil
    )
    #expect(!surface.isThermalCooldownVisible)
    #expect(surface.isProviderRecoveryVisible)
    #expect(overlay.semanticBackgroundColor == .windowBackgroundColor)
    #expect(overlay.backgroundAlpha == 1)

    surface.showLoading("Restarting local services…")
    #expect(!surface.isThermalCooldownVisible)
    #expect(!providers.isEnabled)
    #expect(!performance.isEnabled)
}

@Test @MainActor
func freshSessionFailureIsReadableHidesSpinnerAndOffersDeterministicRecovery() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        displayPolicy: .fixed()
    )
    surface.loadViewIfNeeded()
    surface.view.frame = NSRect(x: 0, y: 0, width: 900, height: 600)
    surface.view.layoutSubtreeIfNeeded()

    let descendants = allDescendants(of: surface.view)
    let spinner = try #require(descendants.compactMap { $0 as? NSProgressIndicator }.first)
    let labels = descendants.compactMap { $0 as? NSTextField }
    let buttons = descendants.compactMap { $0 as? NSButton }
    let retry = try #require(buttons.first { $0.title == "Try New Task Again" })
    let reload = try #require(buttons.first { $0.title == "Reload Agent Workspace" })

    surface.showFreshSessionFailure()
    surface.view.layoutSubtreeIfNeeded()
    let message = try #require(labels.first {
        $0.stringValue.contains("No prompt was sent")
    })
    #expect(surface.isFreshSessionFailureVisible)
    #expect(spinner.isHidden)
    #expect(message.maximumNumberOfLines >= 6)
    #expect(message.lineBreakMode == .byWordWrapping)
    #expect(message.cell?.truncatesLastVisibleLine == false)
    let requiredMessageSize = try #require(message.cell?.cellSize(forBounds: message.bounds))
    #expect(requiredMessageSize.height <= message.bounds.height + 1)
    #expect(!message.stringValue.contains("JavaScript"))
    #expect(!message.stringValue.contains("localizedDescription"))
    #expect(retry.isEnabled && !retry.isHidden)
    #expect(reload.isEnabled && !reload.isHidden)
    #expect(retry.keyEquivalent == "\r")
    #expect(reload.keyEquivalent == "r")
    #expect(reload.keyEquivalentModifierMask == [.command])
    #expect(retry.accessibilityLabel() == "Try creating a new task again")
    #expect(reload.accessibilityLabel() == "Reload Agent Workspace")
    #expect(surface.view.bounds.contains(retry.convert(retry.bounds, to: surface.view)))
    #expect(surface.view.bounds.contains(reload.convert(reload.bounds, to: surface.view)))

    retry.performClick(nil)
    #expect(!surface.isFreshSessionFailureVisible)
    #expect(!spinner.isHidden)
    #expect(message.stringValue == "Waiting for the private runtime…")

    surface.showFreshSessionFailure()
    reload.performClick(nil)
    #expect(!surface.isFreshSessionFailureVisible)
    #expect(!spinner.isHidden)
    #expect(message.stringValue == "Waiting for the private runtime…")
}

@Test @MainActor
func genericFailureNeverLeavesAStoppedSpinnerOnScreen() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        displayPolicy: .fixed()
    )
    surface.loadViewIfNeeded()
    let spinner = try #require(
        allDescendants(of: surface.view).compactMap { $0 as? NSProgressIndicator }.first
    )

    surface.showLoading("Opening DeepSeek Harness…")
    #expect(!spinner.isHidden)

    surface.showFailure("Harness could not be displayed safely.")
    #expect(spinner.isHidden)
    #expect(!surface.isFreshSessionFailureVisible)
}

@Test @MainActor
func reducedMotionAndTransparencyKeepWorkspaceRecoveryStaticAndOpaque() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        displayPolicy: .fixed(reduceMotion: true, reduceTransparency: true)
    )
    surface.loadViewIfNeeded()
    let descendants = allDescendants(of: surface.view)
    let spinner = try #require(descendants.compactMap { $0 as? NSProgressIndicator }.first)
    let overlay = try #require(descendants.compactMap { $0 as? AppearanceAwareLayerView }.first)

    surface.showLoading("Preparing the private workspace…")
    #expect(spinner.isHidden)
    #expect(overlay.backgroundAlpha == 1)

    surface.showThermalCooldown(
        headline: "Local AI paused safely",
        detail: "Work remains saved while this Mac cools.",
        openProviders: {},
        openPerformance: {}
    )
    #expect(spinner.isHidden)
    #expect(overlay.backgroundAlpha == 1)

    surface.showProviderRecovery(
        "The selected provider route needs verification.",
        allowsNativeStateReset: false,
        retry: {},
        chooseLocalModel: nil,
        openProviders: {},
        resetNativeState: nil
    )
    #expect(spinner.isHidden)
    #expect(overlay.backgroundAlpha == 1)
}

@Test @MainActor
func liveAccessibilityNotificationRefreshesVisibleWorkspaceOverlay() throws {
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
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        displayPolicy: policy
    )
    surface.loadViewIfNeeded()
    let descendants = allDescendants(of: surface.view)
    let spinner = try #require(descendants.compactMap { $0 as? NSProgressIndicator }.first)
    let overlay = try #require(descendants.compactMap { $0 as? AppearanceAwareLayerView }.first)

    surface.showThermalCooldown(
        headline: "Local AI paused safely",
        detail: "Work remains saved while this Mac cools.",
        openProviders: {},
        openPerformance: {}
    )
    #expect(!spinner.isHidden)
    #expect(overlay.backgroundAlpha == 0.90)

    state.reducesMotion = true
    state.reducesTransparency = true
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(spinner.isHidden)
    #expect(overlay.backgroundAlpha == 1)

    state.reducesMotion = false
    state.reducesTransparency = false
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(!spinner.isHidden)
    #expect(overlay.backgroundAlpha == 0.90)

    surface.showFailure("Harness could not be displayed safely.")
    state.reducesMotion = true
    NSWorkspace.shared.notificationCenter.post(
        name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
        object: nil
    )
    #expect(spinner.isHidden)
}

@Test @MainActor
func workspaceStateOverlaysFitMinimumInBothAppearancesAndRemainAccessible() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(dataStore: .nonPersistent(), preferences: .shared)
    surface.loadViewIfNeeded()
    surface.view.frame = NSRect(x: 0, y: 0, width: 900, height: 600)
    let longestFailure = "Fulmar could not verify that DeepSeek Harness opened a different empty task. No prompt was sent, and the composer remains locked. Try again or reload the Agent Workspace."
    let presentations: [(String, () -> Void)] = [
        ("loading", { surface.showLoading("Creating a recoverable pre-upgrade snapshot and verifying the private runtime boundary…") }),
        ("failure", { surface.showFailure(longestFailure) }),
        ("provider recovery", {
            surface.showProviderRecovery(
                "The selected provider, endpoint consent, and model could not be verified against the live Harness catalogue. Agent work remains blocked until the exact route is repaired.",
                allowsNativeStateReset: true,
                retry: {},
                chooseLocalModel: {},
                openProviders: {},
                resetNativeState: {}
            )
        }),
        ("thermal cooldown", {
            surface.showThermalCooldown(
                headline: "Local AI paused safely",
                detail: "Critical thermal pressure paused the selected local model. Your task and completed work remain saved; the interrupted model step may need to resume. The minimum pause has finished, and Fulmar is waiting for macOS to report a stable normal thermal state.",
                openProviders: {},
                openPerformance: {}
            )
        })
    ]

    for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
        surface.view.appearance = NSAppearance(named: appearanceName)
        for (state, present) in presentations {
            present()
            surface.view.layoutSubtreeIfNeeded()
            surface.view.displayIfNeeded()
            surface.view.layoutSubtreeIfNeeded()
            #expect(!surface.view.hasAmbiguousLayout, Comment(rawValue: state))
            let visible = allDescendants(of: surface.view).filter {
                !$0.isHidden && ($0 is NSButton || $0 is NSTextField || $0 is NSProgressIndicator)
            }
            for view in visible {
                let frame = view.convert(view.bounds, to: surface.view)
                #expect(surface.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(frame), Comment(rawValue: state))
            }
            for button in visible.compactMap({ $0 as? NSButton }) where button.isEnabled {
                #expect(button.target != nil, Comment(rawValue: "\(state) button target"))
                #expect(button.action != nil, Comment(rawValue: "\(state) button action"))
                #expect(button.accessibilityLabel()?.isEmpty == false, Comment(rawValue: "\(state) button label"))
            }
            let message = try #require(visible.compactMap { $0 as? NSTextField }.first { !$0.stringValue.isEmpty })
            #expect(message.accessibilityRole() == .staticText, Comment(rawValue: "\(state) message role"))
            #expect(message.stringValue.utf8.count > 0, Comment(rawValue: "\(state) message value"))
        }
    }
}

@Test @MainActor
func workspaceStateSemanticTypeScalesFitMinimumInBothAppearances() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scale in [CGFloat(1), 1.25, 1.5] {
        let typography = NativeTypographyPolicy(scale: scale)
        let surface = HarnessWebViewController(
            dataStore: .nonPersistent(),
            preferences: .shared,
            displayPolicy: .fixed(),
            typography: typography
        )
        surface.loadViewIfNeeded()
        surface.view.frame = NSRect(x: 0, y: 0, width: 900, height: 600)
        let presentations: [() -> Void] = [
            { surface.showLoading("Creating a recoverable snapshot and verifying the private runtime boundary…") },
            { surface.showFreshSessionFailure() },
            {
                surface.showProviderRecovery(
                    "The selected provider, endpoint consent, and model could not be verified against the live Harness catalogue.",
                    allowsNativeStateReset: true,
                    retry: {},
                    chooseLocalModel: {},
                    openProviders: {},
                    resetNativeState: {}
                )
            },
            {
                surface.showThermalCooldown(
                    headline: "Local AI paused safely",
                    detail: "Critical thermal pressure paused local work. The task remains saved while Fulmar waits for a stable normal thermal state.",
                    openProviders: {},
                    openPerformance: {}
                )
            }
        ]

        for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
            surface.view.appearance = NSAppearance(named: appearanceName)
            for present in presentations {
                present()
                surface.view.layoutSubtreeIfNeeded()
                let visible = allDescendants(of: surface.view).filter {
                    !$0.isHidden && ($0 is NSButton || $0 is NSTextField || $0 is NSProgressIndicator)
                }
                for view in visible {
                    let frame = view.convert(view.bounds, to: surface.view)
                    #expect(surface.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(frame))
                    #expect(!view.hasAmbiguousLayout)
                }
                let labels = visible.compactMap { $0 as? NSTextField }
                let status = try #require(labels.first { $0.accessibilityLabel() == "Workspace status" })
                #expect(abs((status.font?.pointSize ?? 0) - typography.font(for: .workspaceStatus).pointSize) < 0.01)
                if surface.isThermalCooldownVisible {
                    let detail = try #require(labels.first {
                        $0.accessibilityLabel() == "Local AI protection details"
                    })
                    #expect(abs((detail.font?.pointSize ?? 0) - typography.font(for: .workspaceDetail).pointSize) < 0.01)
                }
            }
        }
    }
}

@Test @MainActor
func freshSessionHandshakeWaitsForDelayedWebKitBridgeRegistration() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
    let navigationWaiter = TestNavigationWaiter()
    webView.navigationDelegate = navigationWaiter
    guard webView.loadHTMLString(
        """
        <!doctype html><meta charset="utf-8"><script>
        setTimeout(() => {
          Object.defineProperty(window, "__localHarnessSecurityBridge", {
            configurable: true,
            value: {
              startFreshSession: async () => ({ before: "old", created: "fresh", current: "fresh" })
            }
          });
        }, 400);
        </script>
        """,
        baseURL: nil
    ) != nil else {
        Issue.record("WebKit refused to create the test navigation")
        return
    }
    try await navigationWaiter.wait()
    let started = ContinuousClock.now
    let value: Any? = try await withCheckedThrowingContinuation { continuation in
        webView.callAsyncJavaScript(
            FreshSessionBrowserHandshake.javaScript,
            arguments: [:],
            in: nil,
            in: .page
        ) { result in
            continuation.resume(with: result)
        }
    }
    let text = try #require(value as? String)
    let object = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    let proof = try #require(object["proof"] as? [String: Any])
    #expect(object["ok"] as? Bool == true)
    #expect(proof["created"] as? String == "fresh")
    #expect(ContinuousClock.now - started >= .milliseconds(150))
}
