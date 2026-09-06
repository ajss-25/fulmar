import Dispatch
import Testing
@testable import LocalHarness

@MainActor
private final class FakeMemoryPressureEventSource: MemoryPressureEventSource {
    private(set) var activated = false
    private(set) var cancellationCount = 0
    private var handler: (@Sendable () -> Void)?
    var data: DispatchSource.MemoryPressureEvent = .normal

    func setEventHandler(_ handler: @escaping @Sendable () -> Void) {
        self.handler = handler
    }

    func activate() { activated = true }

    func cancel() { cancellationCount += 1 }

    func send(_ event: DispatchSource.MemoryPressureEvent) {
        data = event
        handler?()
    }
}

@Suite("Memory pressure observer boundary")
struct MemoryPressureSafetyTests {
    @Test @MainActor
    func dispatchEventMappingIsDeterministicAndCriticalWins() {
        #expect(DispatchMemoryPressureObserver.condition(for: .normal) == .normal)
        #expect(DispatchMemoryPressureObserver.condition(for: .warning) == .warning)
        #expect(DispatchMemoryPressureObserver.condition(for: .critical) == .critical)
        #expect(DispatchMemoryPressureObserver.condition(
            for: [.normal, .warning, .critical]
        ) == .critical)
    }

    @Test @MainActor
    func injectedSourceDrivesLiveTransitionsAndStopsExactlyOnce() {
        let source = FakeMemoryPressureEventSource()
        let observer = DispatchMemoryPressureObserver(sourceFactory: { source })
        var observed: [HostMemoryPressureCondition] = []
        observer.onConditionChange = { observed.append($0) }

        observer.start()
        observer.start()
        #expect(source.activated)
        source.send(.warning)
        source.send(.critical)
        source.send(.normal)
        #expect(observed == [.warning, .critical, .normal])

        observer.stop()
        observer.stop()
        #expect(source.cancellationCount == 1)
        source.send(.warning)
        #expect(observed == [.warning, .critical, .normal])
    }

    @Test
    func rawPressureGateClosesLocalRouteTransitionButNeverCloud() {
        var gate = MemoryPressureRouteGate(recoverySeconds: 3)
        #expect(!gate.blocksNewLocalGeneration(localRuntimeRelevant: true, uptime: 0))

        gate.observe(.warning, uptime: 1)
        #expect(gate.blocksNewLocalGeneration(localRuntimeRelevant: true, uptime: 1))
        #expect(!gate.requiresImmediateLocalShutdown(localRuntimeRelevant: true))

        gate.observe(.critical, uptime: 2)
        #expect(gate.blocksNewLocalGeneration(localRuntimeRelevant: true, uptime: 2))
        #expect(gate.requiresImmediateLocalShutdown(localRuntimeRelevant: true))
        #expect(!gate.blocksNewLocalGeneration(localRuntimeRelevant: false, uptime: 2))
        #expect(!gate.requiresImmediateLocalShutdown(localRuntimeRelevant: false))

        gate.observe(.normal, uptime: 3)
        #expect(gate.blocksNewLocalGeneration(localRuntimeRelevant: true, uptime: 5.9))
        #expect(!gate.blocksNewLocalGeneration(localRuntimeRelevant: false, uptime: 5.9))
        #expect(!gate.blocksNewLocalGeneration(localRuntimeRelevant: true, uptime: 6))
    }
}
