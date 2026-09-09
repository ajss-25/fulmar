import Testing
@testable import LocalHarness

@Suite("Harness controller state publication")
struct HarnessControllerStatePublicationTests {
    @Test("A queued old ready state remains inert after synchronous suspension")
    func queuedReadyCannotCrossProtectedTransition() throws {
        let gate = HarnessController.StatePublicationGate()
        var current: HarnessController.State? = .ready(managedByApp: true)
        var queued: [() -> Void] = []
        var rpcPromotions = 0
        var webResumes = 0
        var scheduleStarts = 0

        gate.beginGeneration()
        gate.enqueue(
            state: .ready(managedByApp: true),
            currentState: { current },
            dispatcher: { queued.append($0) },
            delivery: { _ in
                rpcPromotions += 1
                webResumes += 1
                scheduleStarts += 1
            }
        )

        // This exactly models closeAllRuntimeAdmissionsSynchronously running
        // before the main queue gets to deliver the controller's old event.
        gate.suspend()
        let staleDelivery = try #require(queued.first)
        staleDelivery()

        #expect(rpcPromotions == 0)
        #expect(webResumes == 0)
        #expect(scheduleStarts == 0)

        queued.removeAll()
        gate.beginGeneration()
        current = .ready(managedByApp: true)
        gate.enqueue(
            state: .ready(managedByApp: true),
            currentState: { current },
            dispatcher: { queued.append($0) },
            delivery: { _ in
                rpcPromotions += 1
                webResumes += 1
                scheduleStarts += 1
            }
        )
        let freshDelivery = try #require(queued.first)
        freshDelivery()

        #expect(rpcPromotions == 1)
        #expect(webResumes == 1)
        #expect(scheduleStarts == 1)
    }

    @Test("Only the latest state in one live generation can be delivered")
    func supersededStateCannotArriveAfterNewerState() throws {
        let gate = HarnessController.StatePublicationGate()
        var current: HarnessController.State? = .checking
        var queued: [() -> Void] = []
        var delivered: [HarnessController.State] = []

        gate.beginGeneration()
        gate.enqueue(
            state: .checking,
            currentState: { current },
            dispatcher: { queued.append($0) },
            delivery: { delivered.append($0) }
        )
        current = .startingHarness
        gate.enqueue(
            state: .startingHarness,
            currentState: { current },
            dispatcher: { queued.append($0) },
            delivery: { delivered.append($0) }
        )

        #expect(queued.count == 2)
        try #require(queued.count == 2)
        queued[0]()
        queued[1]()
        #expect(delivered == [.startingHarness])
    }
}
