import Foundation
import Testing
@testable import LocalHarness

@MainActor
private final class InertThermalRecoveryMemoryPressureObserver: MemoryPressureObserving {
    var onConditionChange: ((HostMemoryPressureCondition) -> Void)?

    func start() {}
    func stop() {}
}

private enum InjectedThermalNormalModeWriteError: Error, LocalizedError {
    case unavailable

    var errorDescription: String? {
        "Injected Normal workload policy write failure."
    }
}

private let admittedReadyEffectOrder = [
    "promote-inference",
    "release-holds",
    "resume-surface",
    "start-schedules",
    "publish-handoff",
    "acknowledge-health",
    "resume-inference-waiter"
]

private func traceReadyAdmission(
    blocked: Bool,
    blockedError: any Error,
    receivedBlockedError: inout (any Error)?
) -> (admitted: Bool, trace: [String]) {
    var trace: [String] = []
    let admitted = ThermalReadyStateAdmissionGate.perform(
        selectedLocalRuntimeBlocked: blocked,
        onBlocked: {
            receivedBlockedError = blockedError
            trace.append("blocked")
        },
        onAdmitted: {
            trace.append(contentsOf: admittedReadyEffectOrder)
        }
    )
    return (admitted, trace)
}

@MainActor
private func waitUntilReadyWaiterIsInstalled(
    _ waiter: ProtectedRuntimeReadinessWaiter,
    maximumYields: Int = 1_000
) async -> Bool {
    for _ in 0..<maximumYields {
        if waiter.isWaiting { return true }
        await Task.yield()
    }
    return waiter.isWaiting
}

private func deferredReadyEndpoint(
    port: Int,
    token: String = "synthetic-token",
    processIdentifier: Int32 = 42
) -> HarnessEndpoint {
    HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:\(port)/")!,
        token: token,
        nonce: "synthetic-nonce-\(port)",
        processIdentifier: processIdentifier
    )
}

@Suite("AppDelegate thermal Normal-mode recovery boundary")
struct AppDelegateThermalNormalModeRecoveryTests {
    @Test("Startup cannot publish green Ready when Normal policy persistence fails")
    @MainActor
    func startupFailureRetainsDegradedState() {
        var writes: [ThermalWorkloadMode] = []
        let delegate = AppDelegate(
            memoryPressureObserver: InertThermalRecoveryMemoryPressureObserver(),
            thermalWorkloadModeWriter: ThermalWorkloadModeWriter { mode, _ in
                writes.append(mode)
                throw InjectedThermalNormalModeWriteError.unavailable
            }
        )
        var publishedGreenReady = false

        let result = delegate.applyNormalThermalWorkloadMode(at: .startup) {
            publishedGreenReady = true
        }

        #expect(writes == [.normal])
        #expect(!publishedGreenReady)
        #expect(delegate.pendingThermalNormalModeRecovery?.boundary == .startup)
        #expect(!delegate.mayPublishReadyStatusForThermalPolicy(localRuntimeSelected: true))
        #expect(delegate.mayPublishReadyStatusForThermalPolicy(localRuntimeSelected: false))
        #expect(!delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: true))
        #expect(delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: false))
        let blocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: true,
            normalModeRecoveryPending: true,
            phase: .ready,
            memoryPressureBlocksNewLocalGeneration: false
        )
        var blockedError: (any Error)?
        let readyAdmission = traceReadyAdmission(
            blocked: blocked,
            blockedError: delegate.currentLocalRuntimeAdmissionError,
            receivedBlockedError: &blockedError
        )
        #expect(!readyAdmission.admitted)
        #expect(readyAdmission.trace == ["blocked"])
        #expect((blockedError as? ThermalNormalModeRecoveryFailure)?.boundary == .startup)
        if case .success = result {
            Issue.record("The injected startup policy failure was reported as success.")
        }
    }

    @Test("Eco recovery without a memory hold still blocks local admission when Normal persistence fails")
    @MainActor
    func ecoClearedFailureRetainsSuccessEffects() {
        let delegate = AppDelegate(
            memoryPressureObserver: InertThermalRecoveryMemoryPressureObserver(),
            thermalWorkloadModeWriter: ThermalWorkloadModeWriter { _, _ in
                throw InjectedThermalNormalModeWriteError.unavailable
            }
        )
        var releasedAdmissionHold = false

        let result = delegate.applyNormalThermalWorkloadMode(at: .ecoCleared) {
            releasedAdmissionHold = true
        }

        #expect(!releasedAdmissionHold)
        #expect(delegate.pendingThermalNormalModeRecovery?.boundary == .ecoCleared)
        #expect(!delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: true))
        #expect(delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: false))
        let admissionError = delegate.currentLocalRuntimeAdmissionError
        #expect((admissionError as? ThermalNormalModeRecoveryFailure)?.boundary == .ecoCleared)
        #expect(admissionError.localizedDescription.contains("New local work"))
        #expect(!admissionError.localizedDescription.localizedCaseInsensitiveContains("cooling down"))
        let blocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: true,
            normalModeRecoveryPending: true,
            phase: .eco(reason: .thermalPressure),
            memoryPressureBlocksNewLocalGeneration: false
        )
        var blockedError: (any Error)?
        let readyAdmission = traceReadyAdmission(
            blocked: blocked,
            blockedError: admissionError,
            receivedBlockedError: &blockedError
        )
        #expect(!readyAdmission.admitted)
        #expect(readyAdmission.trace == ["blocked"])
        #expect((blockedError as? ThermalNormalModeRecoveryFailure)?.boundary == .ecoCleared)
        if case .success = result {
            Issue.record("The injected Eco-clear policy failure released its success effects.")
        }
    }

    @Test("Cooldown recovery cannot restart local AI when Normal persistence fails")
    @MainActor
    func cooldownFailureRetainsRestartHold() {
        let delegate = AppDelegate(
            memoryPressureObserver: InertThermalRecoveryMemoryPressureObserver(),
            thermalWorkloadModeWriter: ThermalWorkloadModeWriter { _, _ in
                throw InjectedThermalNormalModeWriteError.unavailable
            }
        )
        var restartedRuntime = false

        let result = delegate.applyNormalThermalWorkloadMode(at: .cooldownRecovered) {
            restartedRuntime = true
        }

        #expect(!restartedRuntime)
        #expect(delegate.pendingThermalNormalModeRecovery?.boundary == .cooldownRecovered)
        #expect(!delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: true))
        #expect(delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: false))
        if case .success = result {
            Issue.record("The injected cooldown policy failure restarted the runtime.")
        }
    }

    @Test("A later verified Normal write clears degradation and runs success exactly once")
    @MainActor
    func verifiedRetryRunsDeferredSuccess() {
        var shouldFail = true
        var writes: [ThermalWorkloadMode] = []
        let delegate = AppDelegate(
            memoryPressureObserver: InertThermalRecoveryMemoryPressureObserver(),
            thermalWorkloadModeWriter: ThermalWorkloadModeWriter { mode, _ in
                writes.append(mode)
                if shouldFail {
                    throw InjectedThermalNormalModeWriteError.unavailable
                }
            }
        )
        var successCount = 0

        _ = delegate.applyNormalThermalWorkloadMode(at: .ecoCleared) {
            successCount += 1
        }
        shouldFail = false
        let result = delegate.applyNormalThermalWorkloadMode(at: .ecoCleared) {
            successCount += 1
        }

        #expect(writes == [.normal, .normal])
        #expect(successCount == 1)
        #expect(delegate.pendingThermalNormalModeRecovery == nil)
        #expect(delegate.mayPublishReadyStatusForThermalPolicy(localRuntimeSelected: true))
        #expect(delegate.mayAdmitWorkForThermalPolicy(localRuntimeSelected: true))
        let blocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: true,
            normalModeRecoveryPending: false,
            phase: .ready,
            memoryPressureBlocksNewLocalGeneration: false
        )
        var blockedError: (any Error)?
        let readyAdmission = traceReadyAdmission(
            blocked: blocked,
            blockedError: ThermalSafetyError.coolingDown,
            receivedBlockedError: &blockedError
        )
        #expect(readyAdmission.admitted)
        #expect(readyAdmission.trace == admittedReadyEffectOrder)
        #expect(blockedError == nil)
        if case .failure(let failure) = result {
            Issue.record("The verified retry remained degraded: \(failure.localizedDescription)")
        }
    }

    @Test("Cloud routes remain admitted throughout retained local cooling and lock state")
    func cloudRoutesEscapeRetainedLocalProtection() {
        let phases: [ThermalSafetyPhase] = [
            .cooling(
                trigger: .seriousThermalState,
                cooldownUntil: Date(timeIntervalSince1970: 2_000)
            ),
            .locked(trigger: .criticalThermalState)
        ]

        for phase in phases {
            let blocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
                localRuntimeSelected: false,
                normalModeRecoveryPending: true,
                phase: phase,
                memoryPressureBlocksNewLocalGeneration: true
            )
            var blockedError: (any Error)?
            let readyAdmission = traceReadyAdmission(
                blocked: blocked,
                blockedError: ThermalSafetyError.runtimeLocked,
                receivedBlockedError: &blockedError
            )
            #expect(!blocked)
            #expect(readyAdmission.admitted)
            #expect(readyAdmission.trace == admittedReadyEffectOrder)
            #expect(blockedError == nil)
        }
    }

    @Test("Local memory Eco blocks startup and inference promotion without running Ready effects")
    func localMemoryEcoBlocksFreshRuntimeEffects() {
        let blocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: true,
            normalModeRecoveryPending: false,
            phase: .eco(reason: .memoryPressure),
            memoryPressureBlocksNewLocalGeneration: false
        )
        var promoted = 0
        let promotionSucceeded = ThermalRuntimeAdmissionPolicy.promoteIfAdmitted(
            selectedLocalRuntimeBlocked: blocked
        ) {
            promoted += 1
            return true
        }
        var blockedError: (any Error)?
        let readyAdmission = traceReadyAdmission(
            blocked: blocked,
            blockedError: ThermalSafetyError.memoryPressure,
            receivedBlockedError: &blockedError
        )

        #expect(blocked)
        #expect(!promotionSucceeded)
        #expect(promoted == 0)
        #expect(!readyAdmission.admitted)
        #expect(readyAdmission.trace == ["blocked"])
        #expect((blockedError as? ThermalSafetyError) == .memoryPressure)
    }

    @Test("Pending local Normal recovery cannot promote background inference, while cloud can")
    func backgroundPromotionUsesTheSameRouteAwareGate() {
        let localBlocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: true,
            normalModeRecoveryPending: true,
            phase: .ready,
            memoryPressureBlocksNewLocalGeneration: false
        )
        var promotionTrace: [String] = []
        #expect(!ThermalRuntimeAdmissionPolicy.promoteIfAdmitted(
            selectedLocalRuntimeBlocked: localBlocked
        ) {
            promotionTrace.append("local-promotion")
            return true
        })

        let cloudBlocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: false,
            normalModeRecoveryPending: true,
            phase: .locked(trigger: .criticalThermalState),
            memoryPressureBlocksNewLocalGeneration: true
        )
        #expect(ThermalRuntimeAdmissionPolicy.promoteIfAdmitted(
            selectedLocalRuntimeBlocked: cloudBlocked
        ) {
            promotionTrace.append("cloud-promotion")
            return true
        })
        #expect(promotionTrace == ["cloud-promotion"])
    }

    @Test("Provider control-plane repair remains startable while local inference is blocked")
    func providerControlPlaneBypassesOnlyTheInferenceAdmissionHold() {
        #expect(ThermalRuntimeAdmissionPolicy.permitsRuntimeStart(
            selectedLocalRuntimeBlocked: true,
            providerControlPlaneOnly: true
        ))
        #expect(!ThermalRuntimeAdmissionPolicy.permitsRuntimeStart(
            selectedLocalRuntimeBlocked: true,
            providerControlPlaneOnly: false
        ))
        #expect(ThermalRuntimeAdmissionPolicy.permitsRuntimeStart(
            selectedLocalRuntimeBlocked: false,
            providerControlPlaneOnly: false
        ))
    }

    @Test("A blocked Ready settles its inference waiter with the exact policy failure")
    @MainActor
    func blockedReadySettlesExactAdmissionFailure() async {
        let delegate = AppDelegate(
            memoryPressureObserver: InertThermalRecoveryMemoryPressureObserver(),
            thermalWorkloadModeWriter: ThermalWorkloadModeWriter { _, _ in
                throw InjectedThermalNormalModeWriteError.unavailable
            }
        )
        _ = delegate.applyNormalThermalWorkloadMode(at: .ecoCleared) {}
        let waiter = ProtectedRuntimeReadinessWaiter()
        let waitTask = Task { @MainActor in
            do {
                try await waiter.wait(
                    label: "an injected Ready publication",
                    timeout: .seconds(2)
                ) {}
                return nil as ThermalNormalModeRecoveryBoundary?
            } catch {
                return (error as? ThermalNormalModeRecoveryFailure)?.boundary
            }
        }
        let waiterInstalled = await waitUntilReadyWaiterIsInstalled(waiter)
        #expect(waiterInstalled)
        guard waiterInstalled else {
            waitTask.cancel()
            return
        }

        let blocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: true,
            normalModeRecoveryPending: true,
            phase: .ready,
            memoryPressureBlocksNewLocalGeneration: false
        )
        _ = ThermalReadyStateAdmissionGate.perform(
            selectedLocalRuntimeBlocked: blocked,
            onBlocked: {
                _ = waiter.resume(with: .failure(delegate.currentLocalRuntimeAdmissionError))
            },
            onAdmitted: {
                Issue.record("The blocked Ready publication ran its admitted effects.")
            }
        )

        #expect(await waitTask.value == .ecoCleared)
        #expect(!waiter.isWaiting)
    }

    @Test("Exact deferred Ready waits for topology, finalizes once, and cannot double-publish")
    func exactDeferredReadyFinalizesOnce() {
        let generation = UUID()
        let endpoint = deferredReadyEndpoint(port: 41_001)
        var gate = ThermalReadyFinalizationGate()

        gate.deferAwaitingTopology(generation: generation, endpoint: endpoint)
        #expect(gate.isPending)
        #expect(gate.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: endpoint,
            runtimeIsReady: true
        ) == .awaitTopology)

        gate.deferVerifiedTopology(generation: generation, endpoint: endpoint)
        #expect(gate.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: endpoint,
            runtimeIsReady: true
        ) == .finalizeVerifiedRuntime)
        #expect(!gate.isPending)
        #expect(gate.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: endpoint,
            runtimeIsReady: true
        ) == .none)
    }

    @Test("Stale generation or endpoint can only request an exact restart")
    func staleDeferredReadyNeverFinalizes() {
        let generation = UUID()
        let endpoint = deferredReadyEndpoint(port: 41_002)

        var staleGeneration = ThermalReadyFinalizationGate()
        staleGeneration.deferVerifiedTopology(generation: generation, endpoint: endpoint)
        #expect(staleGeneration.recoveryDecision(
            currentGeneration: UUID(),
            currentEndpoint: endpoint,
            runtimeIsReady: true
        ) == .restartAfterIdentityChange)
        #expect(!staleGeneration.isPending)

        var staleEndpoint = ThermalReadyFinalizationGate()
        staleEndpoint.deferVerifiedTopology(generation: generation, endpoint: endpoint)
        #expect(staleEndpoint.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: deferredReadyEndpoint(port: 41_003),
            runtimeIsReady: true
        ) == .restartAfterIdentityChange)
        #expect(!staleEndpoint.isPending)
    }

    @Test("A transient endpoint replacement stays stale even if the old endpoint returns")
    func transientDeferredEndpointChangeIsSticky() {
        let generation = UUID()
        let endpoint = deferredReadyEndpoint(port: 41_004)
        var gate = ThermalReadyFinalizationGate()

        gate.deferAwaitingTopology(generation: generation, endpoint: endpoint)
        gate.endpointDidChange(to: deferredReadyEndpoint(port: 41_005))
        gate.endpointDidChange(to: endpoint)
        gate.deferVerifiedTopology(generation: generation, endpoint: endpoint)

        #expect(gate.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: endpoint,
            runtimeIsReady: true
        ) == .restartAfterIdentityChange)
        #expect(!gate.isPending)
    }

    @Test("Blocked pre-launch startup has no Ready token, while stop and lock clear one")
    func preLaunchAndStopBoundariesRemainDistinct() {
        let generation = UUID()
        let endpoint = deferredReadyEndpoint(port: 41_006)
        var gate = ThermalReadyFinalizationGate()

        #expect(gate.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: nil,
            runtimeIsReady: false
        ) == .none)

        gate.deferVerifiedTopology(generation: generation, endpoint: endpoint)
        #expect(gate.isPending)
        gate.clear()
        #expect(gate.recoveryDecision(
            currentGeneration: generation,
            currentEndpoint: endpoint,
            runtimeIsReady: true
        ) == .none)
    }
}
