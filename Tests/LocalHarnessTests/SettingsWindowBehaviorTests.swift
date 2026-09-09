import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct HostileSettingsWindowError: LocalizedError {
    var errorDescription: String? {
        "SETTINGS_SECRET_CANARY sk-private /Users/private/settings-ledger"
    }
}

@MainActor
private final class SettingsWindowOperationProbe {
    var launchStatus: SettingsLaunchAtLoginStatus = .disabled
    var launchReadFails = false
    var launchWriteFails = false
    var ignoreLaunchWrites = false
    var launchWrites: [Bool] = []
    var onLaunchWrite: (() -> Void)?
    var selection = ModelSelection.defaultLocal
    var selectionReadFails = false
    var physicalMemoryBytes = UInt64(48) * 1_073_741_824

    var operations: SettingsWindowOperations {
        SettingsWindowOperations(
            launchAtLoginStatus: { [self] in
                if launchReadFails { throw HostileSettingsWindowError() }
                return launchStatus
            },
            setLaunchAtLogin: { [self] enabled in
                launchWrites.append(enabled)
                onLaunchWrite?()
                if launchWriteFails { throw HostileSettingsWindowError() }
                if !ignoreLaunchWrites { launchStatus = enabled ? .enabled : .disabled }
            },
            defaultModelSelection: { [self] in
                if selectionReadFails { throw HostileSettingsWindowError() }
                return selection
            },
            physicalMemoryBytes: { [self] in physicalMemoryBytes }
        )
    }
}

@MainActor
private final class SettingsWindowInteractionProbe {
    var sshConfirmations: [Bool] = []
    var websiteConfirmations: [Bool] = []
    var onSSHConfirmation: (() -> Void)?
    var onWebsiteConfirmation: (() -> Void)?
    private(set) var sshConfirmationCount = 0
    private(set) var websiteConfirmationCount = 0
    private(set) var failures: [SettingsWindowFailure] = []

    var interactions: SettingsWindowInteractions {
        SettingsWindowInteractions(
            confirmSSHAgentAccess: { [self] in
                sshConfirmationCount += 1
                onSSHConfirmation?()
                return sshConfirmations.isEmpty ? false : sshConfirmations.removeFirst()
            },
            confirmWebsiteDataClear: { [self] in
                websiteConfirmationCount += 1
                onWebsiteConfirmation?()
                return websiteConfirmations.isEmpty ? false : websiteConfirmations.removeFirst()
            },
            showFailure: { [self] in failures.append($0) }
        )
    }
}

@MainActor
private final class SettingsWindowAsyncGate {
    private(set) var requests: [String] = []
    private var continuations: [CheckedContinuation<Void, Error>?] = []

    func run(_ request: String) async throws {
        requests.append(request)
        try await withCheckedThrowingContinuation { continuation in
            continuations.append(continuation)
        }
    }

    func succeed(_ index: Int) {
        guard continuations.indices.contains(index), let continuation = continuations[index] else { return }
        continuations[index] = nil
        continuation.resume()
    }

    func fail(_ index: Int, with error: Error = HostileSettingsWindowError()) {
        guard continuations.indices.contains(index), let continuation = continuations[index] else { return }
        continuations[index] = nil
        continuation.resume(throwing: error)
    }
}

private enum SettingsWindowBehaviorTimeout: Error { case timedOut }

@MainActor
private func settingsWindowEventually(
    attempts: Int = 300,
    _ condition: @escaping @MainActor () -> Bool
) async throws {
    for _ in 0..<attempts {
        if condition() { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    throw SettingsWindowBehaviorTimeout.timedOut
}

@MainActor
private func settingsWindowDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(settingsWindowDescendants(of:))
}

@MainActor
private func settingsWindowRoots(_ controller: SettingsWindowController) throws -> [NSView] {
    let tabs = try #require(controller.window?.contentViewController as? NSTabViewController)
    return try tabs.tabViewItems.map { try #require($0.viewController?.view) }
}

@MainActor
private func settingsWindowViews(_ controller: SettingsWindowController) throws -> [NSView] {
    try settingsWindowRoots(controller).flatMap(settingsWindowDescendants(of:))
}

@MainActor
private func settingsWindowButton(
    _ title: String,
    controller: SettingsWindowController
) throws -> NSButton {
    try #require(try settingsWindowViews(controller).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func settingsWindowPopUp(
    _ accessibilityLabel: String,
    controller: SettingsWindowController
) throws -> NSPopUpButton {
    try #require(try settingsWindowViews(controller).compactMap { $0 as? NSPopUpButton }.first {
        $0.accessibilityLabel() == accessibilityLabel
    })
}

@MainActor
private func invokeSettingsControlIgnoringEnabled(_ control: NSControl) throws {
    let action = try #require(control.action)
    #expect(NSApplication.shared.sendAction(action, to: control.target, from: control))
}

@MainActor
private func makeSettingsWindowController(
    operationProbe: SettingsWindowOperationProbe,
    interactionProbe: SettingsWindowInteractionProbe
) throws -> (SettingsWindowController, PreferencesStore, () -> Void) {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarSettingsWindowBehavior.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    let preferences = PreferencesStore(defaults: defaults)
    let controller = SettingsWindowController(
        preferences: preferences,
        operations: operationProbe.operations,
        interactions: interactionProbe.interactions
    )
    return (controller, preferences, {
        controller.close()
        defaults.removePersistentDomain(forName: suite)
    })
}

@MainActor
private func showSettingsWindow(_ controller: SettingsWindowController) {
    controller.showWindow(nil)
    controller.window?.orderOut(nil)
}

@Suite(.serialized)
struct SettingsWindowBehaviorTests {
    @Test @MainActor func immediatePreferencesRetentionAndEveryNavigationActionUseRealControls() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        operations.launchStatus = .enabled
        operations.selection = ModelSelection(
            route: ModelSelection.defaultLocal.route,
            performanceProfile: .deep
        )
        let interactions = SettingsWindowInteractionProbe()
        let (controller, preferences, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)

        let launch = try settingsWindowButton("Launch \(ProductBrand.displayName) when I log in", controller: controller)
        let confirm = try settingsWindowButton("Confirm before opening links outside the app", controller: controller)
        let notifications = try settingsWindowButton("Show service and task notifications", controller: controller)
        let recovery = try settingsWindowButton("Automatically recover the agent service after a crash", controller: controller)
        let unload = try settingsWindowButton("Release local-model memory when \(ProductBrand.displayName) quits", controller: controller)
        let retention = try settingsWindowPopUp("Appshot retention", controller: controller)
        let performance = try settingsWindowPopUp("Local inference performance profile", controller: controller)
        let strictLocal = try settingsWindowButton("Current route is confined to this Mac", controller: controller)

        #expect(launch.state == .on)
        #expect(confirm.state == .on)
        #expect(notifications.state == .off)
        #expect(recovery.state == .on)
        #expect(unload.state == .on)
        #expect(retention.titleOfSelectedItem == "7 days")
        #expect(performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .deep))
        #expect(!strictLocal.isEnabled)
        #expect(strictLocal.accessibilityLabel() == "Current provider privacy boundary")

        confirm.performClick(nil)
        #expect(!preferences.confirmExternalLinks)

        var notificationCallbacks = 0
        controller.onNotificationsEnabled = {
            notificationCallbacks += 1
            try? invokeSettingsControlIgnoringEnabled(notifications)
        }
        notifications.performClick(nil)
        #expect(preferences.notificationsEnabled)
        #expect(notificationCallbacks == 1)
        notifications.performClick(nil)
        #expect(!preferences.notificationsEnabled)
        #expect(notificationCallbacks == 1)

        recovery.performClick(nil)
        unload.performClick(nil)
        #expect(!preferences.autoRestartHarness)
        #expect(!preferences.unloadModelWhenIdle)

        retention.selectItem(at: 0)
        try invokeSettingsControlIgnoringEnabled(retention)
        #expect(preferences.appshotRetentionDays == 1)
        retention.selectItem(at: 3)
        try invokeSettingsControlIgnoringEnabled(retention)
        #expect(preferences.appshotRetentionDays == 90)

        var actions: [String] = []
        controller.onOpenMenuBarSettings = { actions.append("menu") }
        controller.onOpenPrivacy = { actions.append("privacy") }
        controller.onOpenPluginTrust = { actions.append("plugins") }
        controller.onOpenBackups = { actions.append("backups") }
        controller.onMigrateCredentials = { actions.append("migrate") }
        controller.onRestartServices = { actions.append("restart") }
        controller.onOpenDiagnostics = { actions.append("diagnostics") }
        for (title, expected) in [
            ("Open Menu Bar Settings…", "menu"),
            ("Privacy Dashboard…", "privacy"),
            ("Plugin Security…", "plugins"),
            ("Backups & Restore…", "backups"),
            ("Move Existing Secrets to Keychain…", "migrate"),
            ("Restart Local Services", "restart"),
            ("Open Diagnostics", "diagnostics")
        ] {
            try settingsWindowButton(title, controller: controller).performClick(nil)
            #expect(actions.last == expected)
        }

        let menu = try settingsWindowButton("Open Menu Bar Settings…", controller: controller)
        controller.onOpenMenuBarSettings = {
            actions.append("menu-reentry")
            try? invokeSettingsControlIgnoringEnabled(menu)
        }
        menu.performClick(nil)
        #expect(actions.filter { $0 == "menu-reentry" }.count == 1)
    }

    @Test @MainActor func launchAtLoginIsVerifiedSingleFlightAndNeverLeaksNativeErrors() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        let (controller, _, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)
        let launch = try settingsWindowButton("Launch \(ProductBrand.displayName) when I log in", controller: controller)

        operations.onLaunchWrite = { try? invokeSettingsControlIgnoringEnabled(launch) }
        launch.performClick(nil)
        #expect(operations.launchWrites == [true])
        #expect(operations.launchStatus == .enabled)
        #expect(launch.state == .on)
        #expect(interactions.failures.isEmpty)

        operations.onLaunchWrite = nil
        operations.launchWriteFails = true
        launch.performClick(nil)
        #expect(operations.launchWrites == [true, false])
        #expect(launch.state == .on)
        #expect(interactions.failures == [.launchAtLogin])

        operations.launchWriteFails = false
        operations.ignoreLaunchWrites = true
        launch.performClick(nil)
        #expect(operations.launchWrites == [true, false, false])
        #expect(launch.state == .on)
        #expect(interactions.failures == [.launchAtLogin, .launchAtLogin])

        operations.launchStatus = .disabled
        operations.onLaunchWrite = { operations.launchStatus = .requiresApproval }
        showSettingsWindow(controller)
        launch.performClick(nil)
        #expect(operations.launchWrites == [true, false, false, true])
        #expect(launch.state == .off)
        #expect(launch.toolTip?.contains("Approval is waiting") == true)
        #expect(interactions.failures.last == .launchAtLoginApprovalRequired)
        #expect(SettingsWindowFailure.launchAtLogin.message.contains("macOS kept the previous"))
        #expect(!SettingsWindowFailure.launchAtLogin.message.contains("SETTINGS_SECRET_CANARY"))
    }

    @Test @MainActor func unavailableNativeAndModelStateDisablesUnsafeControlsAndRestoresRoutePresentation() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        operations.launchReadFails = true
        operations.selectionReadFails = true
        let interactions = SettingsWindowInteractionProbe()
        let (controller, preferences, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        preferences.strictLocalMode = false
        showSettingsWindow(controller)

        let launch = try settingsWindowButton("Launch \(ProductBrand.displayName) when I log in", controller: controller)
        let performance = try settingsWindowPopUp("Local inference performance profile", controller: controller)
        let external = try settingsWindowButton("Current route has one approved provider endpoint", controller: controller)
        #expect(!launch.isEnabled)
        #expect(launch.toolTip?.contains("temporarily unavailable") == true)
        #expect(!performance.isEnabled)
        #expect(performance.toolTip?.contains("could not be verified") == true)
        #expect(!external.isEnabled)

        try invokeSettingsControlIgnoringEnabled(launch)
        #expect(operations.launchWrites.isEmpty)
        #expect(interactions.failures == [.launchAtLogin])

        operations.launchReadFails = false
        operations.selectionReadFails = false
        operations.selection = ModelSelection(
            route: ModelRoute(
                provider: BuiltInProviderDescriptors.ollama.id,
                model: ModelID("reviewed-compatible-model")
            )
        )
        showSettingsWindow(controller)
        #expect(launch.isEnabled)
        #expect(!performance.isEnabled)
        #expect(performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .compatibility))
        #expect(performance.toolTip?.contains("fixed 8K/2K") == true)
        try invokeSettingsControlIgnoringEnabled(performance)
        #expect(interactions.failures == [.launchAtLogin])
    }

    @Test @MainActor func performanceProfilesAreHiddenForCloudAndBlockedBelowQualifiedQwenMemoryFloor() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        let (controller, _, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        let performance = try settingsWindowPopUp("Local inference performance profile", controller: controller)

        operations.selection = ModelSelection(
            route: ModelRoute(
                provider: BuiltInProviderDescriptors.deepSeekOfficial.id,
                model: ModelID("deepseek-chat")
            ),
            performanceProfile: .deep
        )
        showSettingsWindow(controller)
        #expect(!performance.isEnabled)
        #expect(performance.superview?.isHidden == true)
        #expect(performance.toolTip?.contains("do not change cloud") == true)
        let fields = try settingsWindowViews(controller).compactMap { $0 as? NSTextField }
        let cloudGuidance = try #require(fields.first { $0.stringValue.contains("keeps its own model limits") })
        let localRecommendation = try #require(fields.first { $0.stringValue.contains("Balanced is the everyday default") })
        let modelStoreLimitation = try #require(fields.first {
            $0.stringValue.contains("Choosing a different model-store folder is not yet supported")
        })
        #expect(!cloudGuidance.isHiddenOrHasHiddenAncestor)
        #expect(localRecommendation.isHiddenOrHasHiddenAncestor)
        #expect(modelStoreLimitation.isHiddenOrHasHiddenAncestor)
        try invokeSettingsControlIgnoringEnabled(performance)
        #expect(interactions.failures.isEmpty)

        operations.selection = ModelSelection(
            route: ModelSelection.defaultLocal.route,
            performanceProfile: .balanced
        )
        operations.physicalMemoryBytes = 32 * 1_073_741_824
        showSettingsWindow(controller)
        #expect(performance.superview?.isHidden == false)
        #expect(!modelStoreLimitation.isHiddenOrHasHiddenAncestor)
        #expect(!performance.isEnabled)
        #expect(performance.toolTip?.contains("at least 48 GB") == true)
        try invokeSettingsControlIgnoringEnabled(performance)
        #expect(interactions.failures.isEmpty)

        operations.physicalMemoryBytes = 48 * 1_073_741_824
        showSettingsWindow(controller)
        #expect(performance.isEnabled)
        #expect(performance.toolTip?.contains("release-qualified local Qwen") == true)
    }

    @Test @MainActor func sshConsentProtectedMutationFailuresVerificationAndReopenAreExact() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        interactions.sshConfirmations = [false, true, true]
        let gate = SettingsWindowAsyncGate()
        let (controller, preferences, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)
        let ssh = try settingsWindowButton("Allow coding tools to use my SSH agent", controller: controller)
        let performance = try settingsWindowPopUp("Local inference performance profile", controller: controller)

        ssh.performClick(nil)
        #expect(interactions.failures == [.sshAgentNotChanged])
        #expect(ssh.state == .off)
        #expect(interactions.sshConfirmationCount == 0)

        controller.onSSHAgentAccessRequested = { allowed in
            try await gate.run("ssh:\(allowed)")
        }
        ssh.performClick(nil)
        #expect(interactions.sshConfirmationCount == 1)
        #expect(gate.requests.isEmpty)
        #expect(ssh.state == .off)

        ssh.performClick(nil)
        try await settingsWindowEventually { gate.requests == ["ssh:true"] }
        #expect(!ssh.isEnabled)
        #expect(!performance.isEnabled)
        #expect(controller.window?.subtitle.contains("SSH-agent") == true)
        try invokeSettingsControlIgnoringEnabled(ssh)
        #expect(gate.requests == ["ssh:true"])
        controller.close()
        showSettingsWindow(controller)
        #expect(!ssh.isEnabled)
        preferences.allowSSHAgent = true
        gate.succeed(0)
        try await settingsWindowEventually { ssh.isEnabled && ssh.state == .on }
        #expect(interactions.failures == [.sshAgentNotChanged])

        ssh.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 2 }
        gate.fail(1)
        try await settingsWindowEventually { ssh.isEnabled && interactions.failures.count == 2 }
        #expect(ssh.state == .on)
        #expect(interactions.failures.last == .sshAgentNotChanged)

        ssh.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 3 }
        preferences.allowSSHAgent = false
        gate.fail(2, with: ProtectedRuntimeMutationCoordinatorError.mutationCommittedButRecoveryFailed(
            kind: .sshAgentAccess
        ))
        try await settingsWindowEventually { ssh.isEnabled && interactions.failures.count == 3 }
        #expect(ssh.state == .off)
        #expect(interactions.failures.last == .sshAgentSavedRuntimeBlocked)

        ssh.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 4 }
        gate.succeed(3)
        try await settingsWindowEventually { ssh.isEnabled && interactions.failures.count == 4 }
        #expect(ssh.state == .off)
        #expect(interactions.failures.last == .sshAgentVerification)
        #expect(interactions.failures.allSatisfy { !$0.message.contains("SETTINGS_SECRET_CANARY") })
    }

    @Test @MainActor func performanceChangesAreVerifiedSingleFlightBoundedAndRecoverable() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        let gate = SettingsWindowAsyncGate()
        let (controller, _, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)
        let performance = try settingsWindowPopUp("Local inference performance profile", controller: controller)
        let ssh = try settingsWindowButton("Allow coding tools to use my SSH agent", controller: controller)

        performance.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .fast)!)
        try invokeSettingsControlIgnoringEnabled(performance)
        #expect(interactions.failures == [.performanceNotChanged])
        #expect(performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .balanced))

        controller.onPerformanceProfileRequested = { profile in
            try await gate.run("performance:\(profile.rawValue)")
        }
        performance.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .deep)!)
        try invokeSettingsControlIgnoringEnabled(performance)
        try await settingsWindowEventually { gate.requests == ["performance:deep"] }
        #expect(!performance.isEnabled)
        #expect(!ssh.isEnabled)
        try invokeSettingsControlIgnoringEnabled(performance)
        #expect(gate.requests.count == 1)
        controller.close()
        showSettingsWindow(controller)
        #expect(!performance.isEnabled)
        operations.selection = ModelSelection(
            route: ModelSelection.defaultLocal.route,
            performanceProfile: .deep
        )
        gate.succeed(0)
        try await settingsWindowEventually {
            performance.isEnabled
                && performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .deep)
        }

        performance.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .fast)!)
        try invokeSettingsControlIgnoringEnabled(performance)
        try await settingsWindowEventually { gate.requests.count == 2 }
        gate.fail(1)
        try await settingsWindowEventually { performance.isEnabled && interactions.failures.count == 2 }
        #expect(interactions.failures.last == .performanceNotChanged)
        #expect(performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .deep))

        performance.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .fast)!)
        try invokeSettingsControlIgnoringEnabled(performance)
        try await settingsWindowEventually { gate.requests.count == 3 }
        operations.selection = ModelSelection(
            route: ModelSelection.defaultLocal.route,
            performanceProfile: .fast
        )
        gate.fail(2, with: ProtectedRuntimeMutationCoordinatorError.mutationCommittedButRecoveryFailed(
            kind: .performanceProfile
        ))
        try await settingsWindowEventually { performance.isEnabled && interactions.failures.count == 3 }
        #expect(interactions.failures.last == .performanceSavedRuntimeBlocked)
        #expect(performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .fast))

        performance.selectItem(at: PerformanceProfile.allCases.firstIndex(of: .balanced)!)
        try invokeSettingsControlIgnoringEnabled(performance)
        try await settingsWindowEventually { gate.requests.count == 4 }
        gate.succeed(3)
        try await settingsWindowEventually { performance.isEnabled && interactions.failures.count == 4 }
        #expect(interactions.failures.last == .performanceVerification)
        #expect(performance.indexOfSelectedItem == PerformanceProfile.allCases.firstIndex(of: .fast))
        #expect(interactions.failures.allSatisfy { !$0.message.contains("SETTINGS_SECRET_CANARY") })
    }

    @Test @MainActor func websiteDataCancelLegacySuccessAsyncFailureAndAsyncSuccessAreDeterministic() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        interactions.websiteConfirmations = [false, true, true, true]
        let gate = SettingsWindowAsyncGate()
        let (controller, _, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)
        let clear = try settingsWindowButton("Clear Embedded Website Data…", controller: controller)
        let launch = try settingsWindowButton("Launch \(ProductBrand.displayName) when I log in", controller: controller)

        clear.performClick(nil)
        #expect(interactions.failures == [.websiteDataUnavailable])
        #expect(interactions.websiteConfirmationCount == 0)

        var legacyCalls = 0
        controller.onClearWebData = { legacyCalls += 1 }
        clear.performClick(nil)
        #expect(legacyCalls == 0)
        #expect(interactions.websiteConfirmationCount == 1)
        #expect(clear.isEnabled)
        clear.performClick(nil)
        try await settingsWindowEventually { legacyCalls == 1 && clear.isEnabled }
        #expect(interactions.websiteConfirmationCount == 2)

        controller.onClearWebData = nil
        controller.onClearWebDataRequested = { try await gate.run("clear") }
        interactions.onWebsiteConfirmation = { try? invokeSettingsControlIgnoringEnabled(clear) }
        clear.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 1 }
        #expect(interactions.websiteConfirmationCount == 3)
        #expect(!clear.isEnabled)
        #expect(!launch.isEnabled)
        #expect(controller.window?.subtitle.contains("website data") == true)
        try invokeSettingsControlIgnoringEnabled(clear)
        #expect(gate.requests.count == 1)
        gate.fail(0)
        try await settingsWindowEventually { clear.isEnabled && interactions.failures.count == 2 }
        #expect(interactions.failures.last == .websiteDataNotCleared)

        interactions.onWebsiteConfirmation = nil
        clear.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 2 }
        gate.succeed(1)
        try await settingsWindowEventually { clear.isEnabled }
        #expect(interactions.failures == [.websiteDataUnavailable, .websiteDataNotCleared])
        #expect(!SettingsWindowFailure.websiteDataNotCleared.message.contains("SETTINGS_SECRET_CANARY"))
    }

    @Test @MainActor func protectedServiceRestartPrefersCompletionSeamAndIsSingleFlightAcrossReopen() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        let gate = SettingsWindowAsyncGate()
        let (controller, _, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)
        let restart = try settingsWindowButton("Restart Local Services", controller: controller)
        let clear = try settingsWindowButton("Clear Embedded Website Data…", controller: controller)

        var legacyCalls = 0
        controller.onRestartServices = { legacyCalls += 1 }
        controller.onRestartServicesRequested = { try await gate.run("restart") }
        restart.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 1 }
        #expect(legacyCalls == 0)
        #expect(!restart.isEnabled)
        #expect(!clear.isEnabled)
        #expect(controller.window?.subtitle.contains("Restarting local services") == true)
        try invokeSettingsControlIgnoringEnabled(restart)
        #expect(gate.requests.count == 1)
        controller.close()
        showSettingsWindow(controller)
        #expect(!restart.isEnabled)
        gate.fail(0)
        try await settingsWindowEventually { restart.isEnabled && interactions.failures == [.restartServices] }
        #expect(!SettingsWindowFailure.restartServices.message.contains("SETTINGS_SECRET_CANARY"))

        restart.performClick(nil)
        try await settingsWindowEventually { gate.requests.count == 2 }
        gate.succeed(1)
        try await settingsWindowEventually { restart.isEnabled }
        #expect(interactions.failures == [.restartServices])
        #expect(legacyCalls == 0)

        controller.onRestartServicesRequested = nil
        restart.performClick(nil)
        #expect(legacyCalls == 1)
    }

    @Test @MainActor func allInteractiveControlsRemainWiredAccessibleAndReachableAcrossAppearances() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let operations = SettingsWindowOperationProbe()
        let interactions = SettingsWindowInteractionProbe()
        let (controller, _, cleanup) = try makeSettingsWindowController(
            operationProbe: operations,
            interactionProbe: interactions
        )
        defer { cleanup() }
        showSettingsWindow(controller)
        let window = try #require(controller.window)
        let tabs = try #require(window.contentViewController as? NSTabViewController)
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)

        for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearanceName)
            for index in tabs.tabViewItems.indices {
                tabs.selectedTabViewItemIndex = index
                window.layoutIfNeeded()
                let root = try #require(tabs.tabViewItems[index].viewController?.view)
                let descendants = settingsWindowDescendants(of: root)
                for control in descendants.compactMap({ $0 as? NSControl }) where control !== root {
                    if control is NSButton || control is NSPopUpButton {
                        if control.action != nil {
                            #expect(control.target != nil)
                            #expect(!(control.accessibilityLabel() ?? "").isEmpty)
                        }
                    }
                    guard !control.isHidden else { continue }
                    let frame = control.convert(control.bounds, to: root)
                    #expect(frame.minX >= root.bounds.minX - 0.5)
                    #expect(frame.maxX <= root.bounds.maxX + 0.5)
                    #expect(frame.minY >= root.bounds.minY - 0.5)
                    #expect(frame.maxY <= root.bounds.maxY + 0.5)
                    #expect(!control.hasAmbiguousLayout)
                }
            }
        }
    }
}
