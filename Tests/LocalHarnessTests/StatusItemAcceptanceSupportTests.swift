import Dispatch
import Foundation
import Testing
@testable import LocalHarness

@Test func statusItemPIDEnumerationTreatsProcResultAsCountNotBytes() {
    #expect(StatusItemAcceptanceSupport.boundedPIDCount(reportedCount: 745, capacity: 828) == 745)
    #expect(StatusItemAcceptanceSupport.boundedPIDCount(reportedCount: 900, capacity: 828) == 828)
    #expect(StatusItemAcceptanceSupport.boundedPIDCount(reportedCount: 0, capacity: 828) == 0)
    #expect(StatusItemAcceptanceSupport.boundedPIDCount(reportedCount: -1, capacity: 828) == 0)
    #expect(StatusItemAcceptanceSupport.boundedPIDCount(reportedCount: 10, capacity: 0) == 0)
}

@Test func statusItemPIDEnumerationFailsClosedWhenInventoryCannotComplete() {
    #expect(StatusItemAcceptanceSupport.pidBufferDisposition(
        reportedCount: 745,
        capacity: 828,
        canRetry: true
    ) == .complete(count: 745))
    #expect(StatusItemAcceptanceSupport.pidBufferDisposition(
        reportedCount: 828,
        capacity: 828,
        canRetry: true
    ) == .grow(nextCapacity: 1_656))
    #expect(StatusItemAcceptanceSupport.pidBufferDisposition(
        reportedCount: 828,
        capacity: 828,
        canRetry: false
    ) == .invalid)
    #expect(StatusItemAcceptanceSupport.pidBufferDisposition(
        reportedCount: 0,
        capacity: 828,
        canRetry: true
    ) == .invalid)
    #expect(StatusItemAcceptanceSupport.pidBufferDisposition(
        reportedCount: -1,
        capacity: 828,
        canRetry: true
    ) == .invalid)
}

@Test func statusItemProcessPathDecodeIsStrictlyBoundedAndNullTerminated() {
    var valid = [CChar](repeating: 0, count: 32)
    let path = Array("/Applications/Fulmar.app".utf8)
    for (index, byte) in path.enumerated() {
        valid[index] = CChar(bitPattern: byte)
    }
    #expect(StatusItemAcceptanceSupport.decodeProcessPath(
        buffer: valid,
        reportedLength: Int32(path.count)
    ) == "/Applications/Fulmar.app")

    var unterminated = valid
    unterminated[path.count] = 65
    #expect(StatusItemAcceptanceSupport.decodeProcessPath(
        buffer: unterminated,
        reportedLength: Int32(path.count)
    ) == nil)
    #expect(StatusItemAcceptanceSupport.decodeProcessPath(
        buffer: valid,
        reportedLength: Int32(valid.count)
    ) == nil)
    #expect(StatusItemAcceptanceSupport.decodeProcessPath(buffer: valid, reportedLength: 0) == nil)
}

@Test func statusItemPeerClassificationAcceptsOnlyTheDeclaredBundleMainExecutable() {
    let bundle = "/Applications/Fulmar.app"
    #expect(StatusItemAcceptanceSupport.isBundleMainExecutable(
        executablePath: "/Applications/Fulmar.app/Contents/MacOS/LocalHarness",
        bundlePath: bundle,
        executableName: "LocalHarness"
    ))
    #expect(!StatusItemAcceptanceSupport.isBundleMainExecutable(
        executablePath: "/Applications/Fulmar.app/Contents/MacOS/LocalHarnessRuntimeLease",
        bundlePath: bundle,
        executableName: "LocalHarness"
    ))
    #expect(!StatusItemAcceptanceSupport.isBundleMainExecutable(
        executablePath: "/private/tmp/LocalHarnessBuild/Fulmar.app/Contents/MacOS/LocalHarness",
        bundlePath: bundle,
        executableName: "LocalHarness"
    ))
    #expect(!StatusItemAcceptanceSupport.isBundleMainExecutable(
        executablePath: "/Applications/Fulmar.app/Contents/MacOS/LocalHarness",
        bundlePath: bundle,
        executableName: "../LocalHarness"
    ))
}

@Test func statusItemWindowVisibilityRequiresPositiveIntersectionWithARealDisplay() {
    let displays = [
        CGRect(x: 0, y: 0, width: 1_512, height: 982),
        CGRect(x: 1_512, y: 0, width: 1_920, height: 1_080)
    ]
    #expect(StatusItemAcceptanceSupport.frameIntersectsVisibleDisplay(
        CGRect(x: 100, y: 100, width: 800, height: 600),
        displays: displays
    ))
    #expect(StatusItemAcceptanceSupport.frameIntersectsVisibleDisplay(
        CGRect(x: 1_500, y: 100, width: 40, height: 40),
        displays: displays
    ))
    #expect(!StatusItemAcceptanceSupport.frameIntersectsVisibleDisplay(
        CGRect(x: -2_000, y: -2_000, width: 800, height: 600),
        displays: displays
    ))
    #expect(!StatusItemAcceptanceSupport.frameIntersectsVisibleDisplay(
        CGRect(x: 100, y: 100, width: 0, height: 600),
        displays: displays
    ))
}

@Test func statusItemWindowTitleMatchingAllowsOnlyTheDynamicAgentWorkspaceSubtitle() {
    #expect(StatusItemAcceptanceSupport.windowNames(
        ["Fulmar"],
        matchExpectedTitle: "Fulmar",
        productName: "Fulmar"
    ))
    #expect(StatusItemAcceptanceSupport.windowNames(
        ["Fulmar – qwen3.8:27b-mlx · On this Mac"],
        matchExpectedTitle: "Fulmar",
        productName: "Fulmar"
    ))
    #expect(StatusItemAcceptanceSupport.windowNames(
        ["Chat"],
        matchExpectedTitle: "Chat",
        productName: "Fulmar"
    ))
    #expect(StatusItemAcceptanceSupport.windowNames(
        ["Fulmar Settings"],
        matchExpectedTitle: "Fulmar Settings",
        productName: "Fulmar"
    ))

    #expect(!StatusItemAcceptanceSupport.windowNames(
        ["Fulmar –   "],
        matchExpectedTitle: "Fulmar",
        productName: "Fulmar"
    ))
    #expect(!StatusItemAcceptanceSupport.windowNames(
        ["Fulmar Settings"],
        matchExpectedTitle: "Fulmar",
        productName: "Fulmar"
    ))
    #expect(!StatusItemAcceptanceSupport.windowNames(
        ["Fulmar – qwen3.8:27b-mlx · On this Mac"],
        matchExpectedTitle: "Chat",
        productName: "Fulmar"
    ))
    #expect(!StatusItemAcceptanceSupport.windowNames(
        ["Fulmar — qwen3.8:27b-mlx · On this Mac"],
        matchExpectedTitle: "Fulmar",
        productName: "Fulmar"
    ))
    #expect(!StatusItemAcceptanceSupport.windowNames(
        [""],
        matchExpectedTitle: "Fulmar",
        productName: "Fulmar"
    ))
}

@Test func statusItemLiveUIGatesRequireTheExactUnlockedConsoleSession() {
    let ready = { (
        onConsole: Bool?, loginDone: Bool?, sessionUserID: UInt32?,
        frontmost: String?, menuBarOwner: String?
    ) in
        StatusItemAcceptanceSupport.interactiveSessionIsReady(
            onConsole: onConsole,
            loginDone: loginDone,
            sessionUserID: sessionUserID,
            effectiveUserID: 501,
            frontmostBundleIdentifier: frontmost,
            menuBarOwnerBundleIdentifier: menuBarOwner
        )
    }

    #expect(ready(true, true, 501, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(nil, true, 501, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(false, true, 501, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(true, nil, 501, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(true, false, 501, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(true, true, nil, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(true, true, 502, "com.openai.codex", "com.openai.codex"))
    #expect(!ready(true, true, 501, nil, "com.openai.codex"))
    #expect(!ready(true, true, 501, "", "com.openai.codex"))
    #expect(!ready(true, true, 501, "com.apple.loginwindow", "com.openai.codex"))
    #expect(!ready(true, true, 501, "com.apple.ScreenSaver.Engine", "com.openai.codex"))
    #expect(!ready(true, true, 501, "com.openai.codex", nil))
    #expect(!ready(true, true, 501, "com.openai.codex", ""))
    #expect(!ready(true, true, 501, "com.openai.codex", "com.apple.loginwindow"))
    #expect(!ready(true, true, 501, "com.openai.codex", "com.apple.ScreenSaver.Engine.legacy"))
}

@Test func statusItemLiveUIGatesDistinguishSecureAndTransientSessionState() {
    let state = { (
        onConsole: Bool?, loginDone: Bool?, sessionUserID: UInt32?,
        frontmost: String?, menuBarOwner: String?
    ) in
        StatusItemAcceptanceSupport.interactiveSessionState(
            onConsole: onConsole,
            loginDone: loginDone,
            sessionUserID: sessionUserID,
            effectiveUserID: 501,
            frontmostBundleIdentifier: frontmost,
            menuBarOwnerBundleIdentifier: menuBarOwner
        )
    }

    #expect(state(true, true, 501, "com.openai.codex", "com.openai.codex") == .ready)
    #expect(state(nil, true, 501, "com.openai.codex", "com.openai.codex") == .indeterminate)
    #expect(state(true, nil, 501, "com.openai.codex", "com.openai.codex") == .indeterminate)
    #expect(state(true, true, nil, "com.openai.codex", "com.openai.codex") == .indeterminate)
    #expect(state(true, true, 501, nil, "com.openai.codex") == .indeterminate)
    #expect(state(true, true, 501, "", "com.openai.codex") == .indeterminate)
    #expect(state(true, true, 501, "com.openai.codex", nil) == .indeterminate)
    #expect(state(true, true, 501, "com.openai.codex", "") == .indeterminate)
    #expect(state(false, true, 501, "com.openai.codex", "com.openai.codex") == .secureOrWrongUser)
    #expect(state(true, false, 501, "com.openai.codex", "com.openai.codex") == .secureOrWrongUser)
    #expect(state(true, true, 502, "com.openai.codex", "com.openai.codex") == .secureOrWrongUser)
    #expect(state(true, true, 501, "com.apple.loginwindow", "com.openai.codex") == .secureOrWrongUser)
    #expect(state(true, true, 501, "com.openai.codex", "com.apple.ScreenSaver.Engine") == .secureOrWrongUser)
}

@Test func statusItemOpenRequestBarrierSettlesOnlyTheDelayedMatchingGeneration() {
    let barrier = StatusItemAcceptanceSupport.OpenRequestBarrier<Int>()
    let staleGeneration = UUID()
    #expect(!barrier.resolve(
        generation: staleGeneration,
        payload: 7,
        errorDescription: "stale callback"
    ))

    let completion = DispatchSemaphore(value: 0)
    let generation = barrier.generation
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.02) {
        _ = barrier.resolve(
            generation: generation,
            payload: 42,
            errorDescription: nil
        )
        completion.signal()
    }
    #expect(completion.wait(timeout: .now() + 1) == .success)

    var payload: Int?
    var errorDescription: String?
    switch barrier.snapshot() {
    case .pending:
        Issue.record("The delayed matching callback did not settle its request.")
    case let .completed(value, error):
        payload = value
        errorDescription = error
    }
    #expect(payload == 42)
    #expect(errorDescription == nil)
    #expect(!barrier.resolve(
        generation: generation,
        payload: 99,
        errorDescription: "duplicate callback"
    ))
}

@Test func statusItemInteractiveTransportReclassifiesAMidActionLock() {
    #expect(StatusItemAcceptanceSupport.interactiveTransportDisposition(
        transportAccepted: true,
        postActionSessionState: .ready
    ) == .accepted)
    #expect(StatusItemAcceptanceSupport.interactiveTransportDisposition(
        transportAccepted: false,
        postActionSessionState: .ready
    ) == .candidateFailure)
    #expect(StatusItemAcceptanceSupport.interactiveTransportDisposition(
        transportAccepted: true,
        postActionSessionState: .secureOrWrongUser
    ) == .environmentallyDeferred)
    #expect(StatusItemAcceptanceSupport.interactiveTransportDisposition(
        transportAccepted: false,
        postActionSessionState: .indeterminate
    ) == .environmentallyDeferred)
}

@Test func statusItemTimeoutBoundaryUsesThePostSleepSessionObservation() {
    #expect(StatusItemAcceptanceSupport.interactiveTimeoutDisposition(
        postSleepSessionState: .ready
    ) == .candidateFailure)
    #expect(StatusItemAcceptanceSupport.interactiveTimeoutDisposition(
        postSleepSessionState: .secureOrWrongUser
    ) == .environmentallyDeferred)
    #expect(StatusItemAcceptanceSupport.interactiveTimeoutDisposition(
        postSleepSessionState: .indeterminate
    ) == .environmentallyDeferred)

    // Model the exact race: the body observed ready, its final sleep crossed a
    // lock transition, and terminal classification consumes the new state.
    let injectedSessionObservations: [StatusItemAcceptanceSupport.InteractiveSessionState] = [
        .ready,
        .ready,
        .secureOrWrongUser
    ]
    #expect(StatusItemAcceptanceSupport.interactiveTimeoutDisposition(
        postSleepSessionState: injectedSessionObservations.last!
    ) == .environmentallyDeferred)
}

@Test func statusItemCleanupRequiresCompleteAndQuiescentProcessInventories() {
    let quiescent = StatusItemAcceptanceSupport.ProcessInventoryObservation(
        launchedIdentityRunning: false,
        capturedChildRunning: false,
        targetInventoryComplete: true,
        targetOwnedProcessCount: 0,
        runtimeInventoryComplete: true,
        candidateRuntimeProcessCount: 0
    )
    #expect(StatusItemAcceptanceSupport.processInventoryIsQuiescent(quiescent))

    let observations = [
        StatusItemAcceptanceSupport.ProcessInventoryObservation(
            launchedIdentityRunning: true,
            capturedChildRunning: false,
            targetInventoryComplete: true,
            targetOwnedProcessCount: 0,
            runtimeInventoryComplete: true,
            candidateRuntimeProcessCount: 0
        ),
        StatusItemAcceptanceSupport.ProcessInventoryObservation(
            launchedIdentityRunning: false,
            capturedChildRunning: true,
            targetInventoryComplete: true,
            targetOwnedProcessCount: 0,
            runtimeInventoryComplete: true,
            candidateRuntimeProcessCount: 0
        ),
        StatusItemAcceptanceSupport.ProcessInventoryObservation(
            launchedIdentityRunning: false,
            capturedChildRunning: false,
            targetInventoryComplete: false,
            targetOwnedProcessCount: -1,
            runtimeInventoryComplete: true,
            candidateRuntimeProcessCount: 0
        ),
        StatusItemAcceptanceSupport.ProcessInventoryObservation(
            launchedIdentityRunning: false,
            capturedChildRunning: false,
            targetInventoryComplete: true,
            targetOwnedProcessCount: 1,
            runtimeInventoryComplete: true,
            candidateRuntimeProcessCount: 0
        ),
        StatusItemAcceptanceSupport.ProcessInventoryObservation(
            launchedIdentityRunning: false,
            capturedChildRunning: false,
            targetInventoryComplete: true,
            targetOwnedProcessCount: 0,
            runtimeInventoryComplete: false,
            candidateRuntimeProcessCount: -1
        ),
        StatusItemAcceptanceSupport.ProcessInventoryObservation(
            launchedIdentityRunning: false,
            capturedChildRunning: false,
            targetInventoryComplete: true,
            targetOwnedProcessCount: 0,
            runtimeInventoryComplete: true,
            candidateRuntimeProcessCount: 1
        )
    ]
    for observation in observations {
        #expect(!StatusItemAcceptanceSupport.processInventoryIsQuiescent(observation))
    }
}

@Test func statusItemSafetyDeferralRequiresSettlementCleanupAndStateDeletion() {
    #expect(StatusItemAcceptanceSupport.safetyExitDisposition(
        openRequestSettled: true,
        cleanupComplete: true,
        disposableStateRemoved: true
    ) == .deferred)
    #expect(StatusItemAcceptanceSupport.safetyExitDisposition(
        openRequestSettled: false,
        cleanupComplete: true,
        disposableStateRemoved: true
    ) == .hardFailure)
    #expect(StatusItemAcceptanceSupport.safetyExitDisposition(
        openRequestSettled: true,
        cleanupComplete: false,
        disposableStateRemoved: true
    ) == .hardFailure)
    #expect(StatusItemAcceptanceSupport.safetyExitDisposition(
        openRequestSettled: true,
        cleanupComplete: true,
        disposableStateRemoved: false
    ) == .hardFailure)
}
