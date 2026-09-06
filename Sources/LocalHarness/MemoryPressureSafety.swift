import Dispatch
import Foundation

enum HostMemoryPressureCondition: String, Codable, Equatable, Sendable {
    case normal
    case warning
    case critical
}

/// The raw Dispatch condition is also consulted at every route boundary. This
/// closes the small interval where pressure was first observed while a cloud
/// provider was selected and the user switches to a local route before the
/// periodic safety sample has advanced the shared thermal state machine.
struct MemoryPressureRouteGate: Equatable, Sendable {
    private let recoverySeconds: TimeInterval
    private(set) var condition: HostMemoryPressureCondition = .normal
    private var recoveryUntilUptime: TimeInterval?

    init(recoverySeconds: TimeInterval) {
        precondition(recoverySeconds > 0)
        self.recoverySeconds = recoverySeconds
    }

    mutating func observe(
        _ condition: HostMemoryPressureCondition,
        uptime: TimeInterval
    ) {
        precondition(uptime >= 0)
        let previous = self.condition
        self.condition = condition
        switch condition {
        case .warning, .critical:
            recoveryUntilUptime = nil
        case .normal:
            if previous != .normal {
                recoveryUntilUptime = uptime + recoverySeconds
            }
        }
    }

    func blocksNewLocalGeneration(
        localRuntimeRelevant: Bool,
        uptime: TimeInterval
    ) -> Bool {
        guard localRuntimeRelevant else { return false }
        if condition != .normal { return true }
        return recoveryUntilUptime.map { uptime < $0 } ?? false
    }

    func requiresImmediateLocalShutdown(localRuntimeRelevant: Bool) -> Bool {
        localRuntimeRelevant && condition == .critical
    }
}

@MainActor
protocol MemoryPressureEventSource: AnyObject {
    var data: DispatchSource.MemoryPressureEvent { get }
    func setEventHandler(_ handler: @escaping @Sendable () -> Void)
    func activate()
    func cancel()
}

@MainActor
private final class SystemMemoryPressureEventSource: MemoryPressureEventSource {
    private let source: any DispatchSourceMemoryPressure

    init() {
        source = DispatchSource.makeMemoryPressureSource(
            eventMask: [.normal, .warning, .critical],
            queue: .main
        )
    }

    var data: DispatchSource.MemoryPressureEvent { source.data }

    func setEventHandler(_ handler: @escaping @Sendable () -> Void) {
        source.setEventHandler(handler: handler)
    }

    func activate() { source.activate() }
    func cancel() { source.cancel() }
}

/// Small injectable boundary around Dispatch memory-pressure notifications.
/// Tests can deliver exact transitions without allocating gigabytes or relying
/// on the host's current load; production retains one system source for the
/// application lifetime.
@MainActor
protocol MemoryPressureObserving: AnyObject {
    var onConditionChange: ((HostMemoryPressureCondition) -> Void)? { get set }
    func start()
    func stop()
}

@MainActor
final class DispatchMemoryPressureObserver: MemoryPressureObserving {
    var onConditionChange: ((HostMemoryPressureCondition) -> Void)?

    private let sourceFactory: @MainActor () -> any MemoryPressureEventSource
    private var source: (any MemoryPressureEventSource)?
    private var started = false
    private var stopped = false

    init(
        sourceFactory: @escaping @MainActor () -> any MemoryPressureEventSource = {
            SystemMemoryPressureEventSource()
        }
    ) {
        self.sourceFactory = sourceFactory
    }

    static func condition(
        for event: DispatchSource.MemoryPressureEvent
    ) -> HostMemoryPressureCondition {
        if event.contains(.critical) { return .critical }
        if event.contains(.warning) { return .warning }
        return .normal
    }

    func start() {
        guard !started, !stopped else { return }
        started = true
        let source = sourceFactory()
        self.source = source
        source.setEventHandler { [weak self, weak source] in
            MainActor.assumeIsolated {
                guard let self, let source, self.source === source else { return }
                self.onConditionChange?(Self.condition(for: source.data))
            }
        }
        source.activate()
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        onConditionChange = nil
        source?.setEventHandler {}
        source?.cancel()
        source = nil
    }
}
