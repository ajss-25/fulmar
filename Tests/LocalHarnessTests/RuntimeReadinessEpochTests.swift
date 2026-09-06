import Foundation
import Testing
@testable import LocalHarness

@Suite("Runtime readiness admission epoch")
@MainActor
struct RuntimeReadinessEpochTests {
    @Test("A protected transition rejects an old ready publication and only a fresh runtime can reopen admissions")
    func staleReadyCompletionCannotReopenAdmissions() {
        let oldGeneration = UUID()
        let epoch = RuntimeReadinessEpoch(current: oldGeneration)
        var rpcPromotions = 0
        var webResumes = 0
        var scheduleStarts = 0

        // This is the synchronous close at the protected-mutation boundary.
        epoch.rotate()

        let staleAccepted = epoch.performIfCurrent(oldGeneration) {
            rpcPromotions += 1
            webResumes += 1
            scheduleStarts += 1
        }

        #expect(!staleAccepted)
        #expect(rpcPromotions == 0)
        #expect(webResumes == 0)
        #expect(scheduleStarts == 0)

        let freshGeneration = epoch.rotate()
        let freshAccepted = epoch.performIfCurrent(freshGeneration) {
            rpcPromotions += 1
            webResumes += 1
            scheduleStarts += 1
        }

        #expect(freshAccepted)
        #expect(rpcPromotions == 1)
        #expect(webResumes == 1)
        #expect(scheduleStarts == 1)
    }

    @Test("Quit closes queued controller-ready and in-flight topology paths before its first await")
    func quitSynchronouslyInvalidatesEveryReadinessPath() throws {
        let controllerGate = HarnessController.StatePublicationGate()
        let appEpoch = RuntimeReadinessEpoch()
        let capturedAppGeneration = appEpoch.current
        let current: HarnessController.State? = .ready(managedByApp: true)
        var queued: [() -> Void] = []
        var controllerPromotions = 0
        var topologyPromotions = 0

        controllerGate.beginGeneration()
        controllerGate.enqueue(
            state: .ready(managedByApp: true),
            currentState: { current },
            dispatcher: { queued.append($0) },
            delivery: { _ in
                _ = appEpoch.performIfCurrent(capturedAppGeneration) {
                    controllerPromotions += 1
                }
            }
        )
        let inFlightTopologyCompletion = {
            _ = appEpoch.performIfCurrent(capturedAppGeneration) {
                topologyPromotions += 1
            }
        }

        // This is the synchronous prefix of prepareForTermination().
        controllerGate.suspend()
        appEpoch.rotate()

        try #require(queued.count == 1)
        queued[0]()
        inFlightTopologyCompletion()

        #expect(controllerPromotions == 0)
        #expect(topologyPromotions == 0)
    }
}
