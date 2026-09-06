import AppKit
import Foundation
import Testing
@testable import LocalHarness

@Test func harnessHomeRecoveryPromptResponsesAreDeterministicAndCancelSafe() {
    #expect(HarnessHomeRecoveryPresentation.initialChoice(
        for: .alertFirstButtonReturn
    ) == .preserveSettingsAndRepair)
    #expect(HarnessHomeRecoveryPresentation.initialChoice(
        for: .alertSecondButtonReturn
    ) == .preserveAndStartClean)
    #expect(HarnessHomeRecoveryPresentation.initialChoice(
        for: .alertThirdButtonReturn
    ) == .keepStopped)
    #expect(HarnessHomeRecoveryPresentation.initialChoice(
        for: NSApplication.ModalResponse(rawValue: -999)
    ) == .keepStopped)

    #expect(HarnessHomeRecoveryPresentation.authorizationChoice(
        for: .alertFirstButtonReturn
    ) == .authorizeAndRetry)
    #expect(HarnessHomeRecoveryPresentation.authorizationChoice(
        for: .alertSecondButtonReturn
    ) == .openRecoveryFolder)
    #expect(HarnessHomeRecoveryPresentation.authorizationChoice(
        for: .alertThirdButtonReturn
    ) == .keepStopped)
    #expect(HarnessHomeRecoveryPresentation.authorizationChoice(
        for: NSApplication.ModalResponse(rawValue: -999)
    ) == .keepStopped)
}

@Test func successfulHarnessHomeRecoveryRevealsOptionallyAndRestartsExactlyOnce() {
    let quarantine = URL(fileURLWithPath: "/private/tmp/receiptless-test", isDirectory: true)
    let receipt = HarnessHomeReceiptlessRecoveryReceipt(
        quarantine: quarantine,
        copiedEntries: ["settings.yaml"]
    )
    var revealed: [URL] = []
    var restartCount = 0
    var gate = HarnessHomeRecoveryCompletionGate()

    let firstFinished = gate.finish(
        receipt: receipt,
        openPreservedCopy: true,
        reveal: { revealed.append($0) },
        restart: { restartCount += 1 }
    )
    #expect(firstFinished)
    let duplicateFinished = gate.finish(
        receipt: receipt,
        openPreservedCopy: true,
        reveal: { revealed.append($0) },
        restart: { restartCount += 1 }
    )
    #expect(!duplicateFinished)
    #expect(revealed == [quarantine])
    #expect(restartCount == 1)

    gate.reset()
    let resetFinished = gate.finish(
        receipt: receipt,
        openPreservedCopy: false,
        reveal: { revealed.append($0) },
        restart: { restartCount += 1 }
    )
    #expect(resetFinished)
    #expect(revealed == [quarantine])
    #expect(restartCount == 2)
}

@Test @MainActor
func quitInvalidatesNestedRecoveryPresentationAndLateCompletions() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    var presentation = HarnessHomeRecoveryPresentationGate()
    let pendingToken = presentation.begin()
    let token = try #require(pendingToken)
    #expect(presentation.admits(token))

    // Models Quit arriving through AppKit's nested modal event loop while the
    // success receipt or authorization prompt is still visible.
    presentation.latchTermination()
    #expect(!presentation.admits(token))
    let lateFinishWasAccepted = presentation.finish(token)
    #expect(!lateFinishWasAccepted)

    var acknowledgementCount = 0
    var restartCount = 0
    if presentation.admits(token) {
        acknowledgementCount += 1
        restartCount += 1
    }
    #expect(acknowledgementCount == 0)
    #expect(restartCount == 0)
    let postTerminationToken = presentation.begin()
    #expect(postTerminationToken == nil)
}

@Test @MainActor
func recoveryPresentationTokenRejectsDuplicateAndStaleSequences() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    var presentation = HarnessHomeRecoveryPresentationGate()
    let pendingFirst = presentation.begin()
    let first = try #require(pendingFirst)
    let overlapping = presentation.begin()
    #expect(overlapping == nil)
    let firstFinishWasAccepted = presentation.finish(first)
    #expect(firstFinishWasAccepted)
    let duplicateFinishWasAccepted = presentation.finish(first)
    #expect(!duplicateFinishWasAccepted)

    let pendingReplacement = presentation.begin()
    let replacement = try #require(pendingReplacement)
    #expect(replacement != first)
    #expect(!presentation.admits(first))
    #expect(presentation.admits(replacement))
}

@Test @MainActor
func startCleanChoiceRemainsBoundAcrossForegroundAuthorizationRetry() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    var presentation = HarnessHomeRecoveryPresentationGate()
    let pendingToken = presentation.begin()
    let token = try #require(pendingToken)
    let startCleanWasBound = presentation.bindInitialChoice(.startClean, to: token)
    #expect(startCleanWasBound)

    // Models the first recovery attempt returning Keychain authorization
    // required and the later authorization completion retrying under the same
    // foreground token. The privacy decision cannot default to settings-only.
    #expect(presentation.initialChoice(for: token) == .startClean)
    let settingsOnlyWasBound = presentation.bindInitialChoice(.settingsOnly, to: token)
    #expect(!settingsOnlyWasBound)
    #expect(presentation.initialChoice(for: token) == .startClean)

    let finishWasAccepted = presentation.finish(token)
    #expect(finishWasAccepted)
    #expect(presentation.initialChoice(for: token) == nil)
}
