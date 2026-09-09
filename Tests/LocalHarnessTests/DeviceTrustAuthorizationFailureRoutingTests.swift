import Foundation
import LocalHarnessDeviceAttestation
import Testing
@testable import LocalHarness

/// Records every recovery dialog AppDelegate actually reaches for, through the
/// same `HarnessHomeRecoveryInteractions` seam production uses. Each scripted
/// answer latches the presentation gate exactly as Quit does, so the routing is
/// observed without driving the sequence into the window surface a test process
/// has never created.
@MainActor
private final class RecoveryDialogProbe {
    enum Dialog: Equatable {
        case blockedRemedy(HarnessHomeRecoveryBlockedRemedy)
        case incompleteAuthorization
        case failureMessage
        case reveal
    }

    var dialogs: [Dialog] = []
    var messages: [String] = []
    var blockedChoice: HarnessHomeRecoveryBlockedChoice = .keepStopped
    var onDialog: (() -> Void)?

    var interactions: HarnessHomeRecoveryInteractions {
        HarnessHomeRecoveryInteractions(
            chooseInitial: { _, _ in
                Issue.record("An authorization failure must not reopen the initial recovery choice")
                return .keepStopped
            },
            chooseInterrupted: { _ in
                Issue.record("An authorization failure must not reopen the interrupted recovery choice")
                return .keepStopped
            },
            chooseAuthorization: { _ in
                Issue.record("An authorization failure must not reopen the authorization choice")
                return .keepStopped
            },
            showSuccess: { _ in
                Issue.record("An authorization failure must not present a success receipt")
                return false
            },
            showFailure: { [unowned self] message, _ in
                dialogs.append(.failureMessage)
                messages.append(message)
                onDialog?()
                return false
            },
            reveal: { [unowned self] _ in dialogs.append(.reveal) },
            chooseBlockedRemedy: { [unowned self] message, remedy, _ in
                dialogs.append(.blockedRemedy(remedy))
                messages.append(message)
                onDialog?()
                return blockedChoice
            },
            chooseAfterIncompleteAuthorization: { [unowned self] message in
                dialogs.append(.incompleteAuthorization)
                messages.append(message)
                onDialog?()
                return false
            }
        )
    }
}

@MainActor
private final class InertRoutingMemoryPressureObserver: MemoryPressureObserving {
    var onConditionChange: ((HostMemoryPressureCondition) -> Void)?

    func start() {}
    func stop() {}
}

@MainActor
private func routingDelegate(_ probe: RecoveryDialogProbe) -> AppDelegate {
    AppDelegate(
        memoryPressureObserver: InertRoutingMemoryPressureObserver(),
        harnessHomeRecoveryInteractions: probe.interactions
    )
}

private func blockedPending(_ remedy: HarnessHomeRecoveryBlockedRemedy) -> HarnessHomeRecoveryPendingState {
    .blocked(
        root: URL(fileURLWithPath: "/nonexistent/fulmar-routing-home", isDirectory: true),
        message: "Device-trust verification is blocked.",
        remedy: remedy
    )
}

@Test @MainActor
func retryableDeviceTrustAuthorizationFailuresReachTheRetryDialogNotTheRecoveryFolderDialog() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recoveryFolder = URL(fileURLWithPath: "/nonexistent/fulmar-routing-recovery", isDirectory: true)
    // Every retryable typed cause an explicit authorization can end in. Before
    // this routing existed each of these fell through to the generic
    // recovery-folder dialog, which offers no way to try the check again.
    let retryable: [any Error] = [
        DeviceAttestationError.keychainInteractionUnavailable(.contended),
        DeviceAttestationError.keychainInteractionUnavailable(.unavailable),
        DeviceAttestationError.deadlineExceeded,
        DeviceAttestationError.foregroundRequired
    ]
    for error in retryable {
        let probe = RecoveryDialogProbe()
        let delegate = routingDelegate(probe)
        let token = try #require(delegate.beginHarnessHomeRecoveryPresentationForTesting())
        let pending = blockedPending(.retry)
        // Answering the dialog is where the user's decision lands. Latching the
        // gate there models Quit arriving while it is open: the completion that
        // follows must resume nothing.
        probe.blockedChoice = .retry
        probe.onDialog = { [weak delegate] in delegate?.latchHarnessHomeRecoveryPresentationForTesting() }

        delegate.presentDeviceTrustAuthorizationFailure(
            error,
            pending: pending,
            recoveryFolder: recoveryFolder,
            token: token
        )

        #expect(probe.dialogs == [.blockedRemedy(.retry)])
        #expect(!probe.dialogs.contains(.failureMessage))
        #expect(!probe.dialogs.contains(.incompleteAuthorization))
        // Exactly one dialog per failure: nothing retries or re-prompts by itself.
        #expect(probe.messages.count == 1)
        let message = try #require(probe.messages.first)
        #expect(!message.isEmpty)
        #expect(!message.contains("/nonexistent/"))
        // The wording may not claim an absence of side effects the code cannot
        // prove; it may only promise what Fulmar never does.
        #expect(!message.contains("Nothing was read"))
        #expect(!message.contains("made no Keychain call at all"))
        // A completion whose gate was latched while the dialog was open runs no
        // further step: no reveal, no second dialog, and no resumption — the
        // latched gate refuses every later token, including a fresh one.
        #expect(delegate.beginHarnessHomeRecoveryPresentationForTesting() == nil)
    }
}

@Test @MainActor
func nonRetryableDeviceTrustAuthorizationFailuresKeepTheRecoveryFolderDialog() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let recoveryFolder = URL(fileURLWithPath: "/nonexistent/fulmar-routing-recovery", isDirectory: true)
    let probe = RecoveryDialogProbe()
    let delegate = routingDelegate(probe)
    let token = try #require(delegate.beginHarnessHomeRecoveryPresentationForTesting())
    probe.onDialog = { [weak delegate] in delegate?.latchHarnessHomeRecoveryPresentationForTesting() }

    delegate.presentDeviceTrustAuthorizationFailure(
        HarnessHomeError.receiptlessRecoveryStateChanged,
        pending: blockedPending(.inspectRecoveryFolder),
        recoveryFolder: recoveryFolder,
        token: token
    )

    #expect(probe.dialogs == [.failureMessage])
    #expect(!probe.dialogs.contains(.blockedRemedy(.retry)))
    #expect(!probe.dialogs.contains(.reveal))
}

@Test @MainActor
func aDeviceTrustAuthorizationFailureArrivingAfterShutdownPresentsNoDialogAtAll() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let probe = RecoveryDialogProbe()
    let delegate = routingDelegate(probe)
    let token = try #require(delegate.beginHarnessHomeRecoveryPresentationForTesting())
    // Quit latched the gate before the authorization completion arrived.
    delegate.latchHarnessHomeRecoveryPresentationForTesting()

    for error in [
        DeviceAttestationError.keychainInteractionUnavailable(.contended),
        DeviceAttestationError.deadlineExceeded
    ] as [any Error] {
        delegate.presentDeviceTrustAuthorizationFailure(
            error,
            pending: blockedPending(.retry),
            recoveryFolder: URL(fileURLWithPath: "/nonexistent/fulmar-routing-recovery", isDirectory: true),
            token: token
        )
    }

    #expect(probe.dialogs.isEmpty)
    #expect(delegate.beginHarnessHomeRecoveryPresentationForTesting() == nil)
}
