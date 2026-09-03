import Foundation
import Testing
@testable import LocalHarness

@Suite("Thermal safety circuit breaker")
struct ThermalSafetyTests {
    private let policy = ThermalSafetyPolicy(
        proactiveEcoActiveSeconds: 4,
        maximumConstrainedActiveSeconds: 8,
        inactiveResetSeconds: 3,
        maximumSampleGapSeconds: 1,
        seriousCooldownSeconds: 5,
        criticalCooldownSeconds: 10,
        sustainedLoadCooldownSeconds: 5,
        nominalRecoverySeconds: 2,
        ecoNominalRecoverySeconds: 2,
        memoryPressureCooldownSeconds: 4,
        memoryPressureRecoverySeconds: 2
    )

    private func sample(
        _ seconds: TimeInterval,
        condition: HostThermalCondition = .nominal,
        relevant: Bool = true,
        active: Bool = true,
        memory: HostMemoryPressureCondition = .normal
    ) -> ThermalSafetySample {
        ThermalSafetySample(
            wallTime: Date(timeIntervalSinceReferenceDate: 1_000 + seconds),
            uptime: 10_000 + seconds,
            condition: condition,
            localRuntimeRelevant: relevant,
            localGenerationActive: active,
            memoryPressure: memory
        )
    }

    @Test("Production limits use adaptive Eco mode before bounded emergency stops")
    func productionLimitsAreExplicit() {
        #expect(ThermalSafetyPolicy.production.proactiveEcoActiveSeconds == 240)
        #expect(ThermalSafetyPolicy.production.maximumConstrainedActiveSeconds == 900)
        #expect(ThermalSafetyPolicy.production.seriousCooldownSeconds == 90)
        #expect(ThermalSafetyPolicy.production.criticalCooldownSeconds == 600)
        #expect(ThermalSafetyPolicy.production.sustainedLoadCooldownSeconds == 120)
        #expect(ThermalSafetyPolicy.production.nominalRecoverySeconds == 60)
        #expect(ThermalSafetyPolicy.production.ecoNominalRecoverySeconds == 60)
        #expect(ThermalSafetyPolicy.production.memoryPressureCooldownSeconds == 30)
        #expect(ThermalSafetyPolicy.production.memoryPressureRecoverySeconds == 30)

        let restart = ThermalSafetyPresentation.restartNotificationBody(
            trigger: .seriousThermalState,
            recoveryCondition: "a stable nominal temperature"
        )
        let cooldown = ThermalSafetyPresentation.cooldownDetail(
            trigger: .criticalMemoryPressure,
            estimate: "About one minute remains."
        )
        let persistence = ThermalSafetyPresentation.normalModeRecoveryDetail(
            reason: "The policy file was unavailable."
        )
        for userFacingText in [
            restart,
            cooldown,
            persistence,
            ThermalSafetyPresentation.normalModeRecoveryNotification
        ] {
            #expect(userFacingText.localizedCaseInsensitiveContains("selected local model"))
            #expect(!userFacingText.localizedCaseInsensitiveContains("qwen"))
        }
    }

    @Test("Memory warning enters Eco, lets current work settle, and blocks new local admissions")
    func memoryWarningPausesOnlyNewLocalWork() {
        var machine = ThermalSafetyStateMachine(policy: policy)

        #expect(machine.evaluate(sample(0, memory: .warning)) == [
            .ecoStarted(reason: .memoryPressure)
        ])
        #expect(machine.phase == .eco(reason: .memoryPressure))
        #expect(machine.usesEcoWorkload)
        #expect(!machine.blocksLocalGeneration)
        #expect(machine.blocksNewLocalGeneration)
        #expect(machine.evaluate(sample(1, memory: .warning)).isEmpty)
    }

    @Test("Critical memory pressure immediately enters the exact-stop cooldown")
    func criticalMemoryPressureTripsImmediately() {
        var machine = ThermalSafetyStateMachine(policy: policy)

        #expect(machine.evaluate(sample(0, active: false, memory: .critical)) == [
            .trip(
                trigger: .criticalMemoryPressure,
                cooldownUntil: sample(0).wallTime.addingTimeInterval(4)
            )
        ])
        #expect(machine.blocksLocalGeneration)
        #expect(machine.blocksNewLocalGeneration)
    }

    @Test("Memory recovery requires a continuous normal hysteresis window")
    func memoryPressureRecoveryIsHysteretic() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, active: false, memory: .warning))

        #expect(machine.evaluate(sample(1, active: false, memory: .normal)).isEmpty)
        #expect(machine.evaluate(sample(2, active: false, memory: .warning)).isEmpty)
        #expect(machine.evaluate(sample(3, active: false, memory: .normal)).isEmpty)
        #expect(machine.evaluate(sample(4, active: false, memory: .normal)).isEmpty)
        #expect(machine.evaluate(sample(5, active: false, memory: .normal)) == [.ecoCleared])
        #expect(machine.phase == .ready)
        #expect(!machine.blocksNewLocalGeneration)
    }

    @Test("Critical memory recovery requires both cooldown and stable normal pressure")
    func criticalMemoryRecoveryWaitsForCooldownAndHysteresis() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, active: false, memory: .critical))

        #expect(machine.evaluate(sample(1, active: false, memory: .normal)) == [
            .cooling(trigger: .criticalMemoryPressure, secondsRemaining: 3)
        ])
        #expect(machine.evaluate(sample(2, active: false, memory: .warning)) == [
            .cooling(trigger: .criticalMemoryPressure, secondsRemaining: 2)
        ])
        #expect(machine.evaluate(sample(4, active: false, memory: .normal)) == [
            .cooling(trigger: .criticalMemoryPressure, secondsRemaining: 0)
        ])
        #expect(machine.evaluate(sample(5, active: false, memory: .normal)) == [
            .cooling(trigger: .criticalMemoryPressure, secondsRemaining: 0)
        ])
        #expect(machine.evaluate(sample(6, active: false, memory: .normal)) == [.recovered])
        #expect(machine.phase == .ready)
    }

    @Test("Memory pressure never blocks an unrelated cloud route")
    func memoryPressureBypassesCloudRoutes() {
        var warning = ThermalSafetyStateMachine(policy: policy)
        var critical = ThermalSafetyStateMachine(policy: policy)

        #expect(warning.evaluate(sample(
            0, relevant: false, active: true, memory: .warning
        )).isEmpty)
        #expect(critical.evaluate(sample(
            0, relevant: false, active: true, memory: .critical
        )).isEmpty)
        #expect(warning.phase == .ready)
        #expect(critical.phase == .ready)
        #expect(!warning.blocksNewLocalGeneration)
        #expect(!critical.blocksNewLocalGeneration)
    }

    @Test("Concurrent serious heat remains the stronger recovery gate after a memory trip")
    func combinedHeatAndMemoryRetainsThermalRecoveryWindow() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, active: false, memory: .critical))

        #expect(machine.evaluate(sample(
            1, condition: .serious, active: false, memory: .critical
        )) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 5)
        ])
        #expect(machine.evaluate(sample(
            6, condition: .nominal, active: false, memory: .normal
        )) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 0)
        ])
        #expect(machine.evaluate(sample(
            7, condition: .nominal, active: false, memory: .normal
        )) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 0)
        ])
        #expect(machine.evaluate(sample(
            8, condition: .nominal, active: false, memory: .normal
        )) == [.recovered])
    }

    @Test("Fair pressure enters Eco mode without blocking local work")
    func fairPressureEntersEcoMode() {
        var machine = ThermalSafetyStateMachine(policy: policy)

        #expect(machine.evaluate(sample(0, condition: .fair)) == [
            .ecoStarted(reason: .thermalPressure)
        ])
        #expect(machine.phase == .eco(reason: .thermalPressure))
        #expect(machine.usesEcoWorkload)
        #expect(!machine.blocksLocalGeneration)
        #expect(machine.evaluate(sample(1, condition: .fair)).isEmpty)
    }

    @Test("Constrained Eco mode retains a bounded emergency fail-safe")
    func constrainedEcoTripsOnlyAtFailSafeLimit() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, condition: .fair))
        for second in 1..<8 {
            #expect(machine.evaluate(sample(TimeInterval(second), condition: .fair)).isEmpty)
        }
        let actions = machine.evaluate(sample(8, condition: .fair))

        #expect(actions == [
            .trip(
                trigger: .sustainedLocalGeneration,
                cooldownUntil: sample(8).wallTime.addingTimeInterval(5)
            )
        ])
        #expect(machine.blocksLocalGeneration)
    }

    @Test("Nominal work cannot pre-consume the constrained emergency timer")
    func constrainedFailSafeCountsOnlyContinuousPressure() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        for second in 0...20 {
            _ = machine.evaluate(sample(TimeInterval(second)))
        }
        #expect(machine.phase == .eco(reason: .sustainedLocalGeneration))

        #expect(machine.evaluate(sample(21, condition: .fair)).isEmpty)
        #expect(machine.constrainedActiveSeconds == 0)
        for second in 22..<29 {
            #expect(machine.evaluate(sample(TimeInterval(second), condition: .fair)).isEmpty)
        }
        #expect(machine.constrainedActiveSeconds == 7)
        #expect(machine.evaluate(sample(29, condition: .fair)) == [
            .trip(
                trigger: .sustainedLocalGeneration,
                cooldownUntil: sample(29).wallTime.addingTimeInterval(5)
            )
        ])
    }

    @Test("Sustained nominal work enters Eco mode and never trips a wall-clock cutoff")
    func nominalGenerationUsesEcoWithoutArbitraryShutdown() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        for second in 0..<4 {
            #expect(machine.evaluate(sample(TimeInterval(second))).isEmpty)
        }
        #expect(machine.evaluate(sample(4)) == [
            .ecoStarted(reason: .sustainedLocalGeneration)
        ])
        for second in 5...30 {
            #expect(machine.evaluate(sample(TimeInterval(second))).isEmpty)
        }
        #expect(machine.phase == .eco(reason: .sustainedLocalGeneration))
        #expect(!machine.blocksLocalGeneration)
    }

    @Test("Thermal Eco mode clears only after a stable nominal window")
    func thermalEcoRequiresStableNominalRecovery() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, condition: .fair, active: false))
        #expect(machine.evaluate(sample(1, condition: .nominal, active: false)).isEmpty)
        #expect(machine.evaluate(sample(2, condition: .fair, active: false)).isEmpty)
        #expect(machine.evaluate(sample(3, condition: .nominal, active: false)).isEmpty)
        #expect(machine.evaluate(sample(4, condition: .nominal, active: false)).isEmpty)
        #expect(machine.evaluate(sample(5, condition: .nominal, active: false)) == [.ecoCleared])
        #expect(machine.phase == .ready)
    }

    @Test("Serious and critical pressure stop immediately with different cooldowns")
    func severeConditionsTripImmediately() {
        var serious = ThermalSafetyStateMachine(policy: policy)
        var critical = ThermalSafetyStateMachine(policy: policy)

        #expect(serious.evaluate(sample(0, condition: .serious, active: false)) == [
            .trip(
                trigger: .seriousThermalState,
                cooldownUntil: sample(0).wallTime.addingTimeInterval(5)
            )
        ])
        #expect(critical.evaluate(sample(0, condition: .critical, active: false)) == [
            .trip(
                trigger: .criticalThermalState,
                cooldownUntil: sample(0).wallTime.addingTimeInterval(10)
            )
        ])
    }

    @Test("Critical pressure during cooldown upgrades and extends the hold")
    func criticalPressureExtendsCooldown() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, condition: .serious))

        #expect(machine.evaluate(sample(1, condition: .critical)) == [
            .cooling(trigger: .criticalThermalState, secondsRemaining: 10)
        ])
        #expect(machine.phase == .cooling(
            trigger: .criticalThermalState,
            cooldownUntil: sample(1).wallTime.addingTimeInterval(10)
        ))
    }

    @Test("Serious pressure upgrades a sustained-load cooldown")
    func seriousPressureUpgradesSustainedCooldown() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, condition: .fair))
        for second in 1...8 { _ = machine.evaluate(sample(TimeInterval(second), condition: .fair)) }

        #expect(machine.evaluate(sample(9, condition: .serious)) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 5)
        ])
        #expect(machine.phase == .cooling(
            trigger: .seriousThermalState,
            cooldownUntil: sample(9).wallTime.addingTimeInterval(5)
        ))
    }

    @Test("Cooldown requires its deadline and a continuous nominal recovery window")
    func recoveryRequiresStableNominalTemperature() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0, condition: .serious))

        #expect(machine.evaluate(sample(1, condition: .nominal)) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 4)
        ])
        #expect(machine.evaluate(sample(2, condition: .fair)) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 3)
        ])
        #expect(machine.evaluate(sample(5, condition: .nominal)) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 0)
        ])
        #expect(machine.evaluate(sample(6, condition: .nominal)) == [
            .cooling(trigger: .seriousThermalState, secondsRemaining: 0)
        ])
        #expect(machine.evaluate(sample(7, condition: .nominal)) == [.recovered])
        #expect(machine.phase == .ready)
        #expect(!machine.blocksLocalGeneration)
    }

    @Test("A future persisted cooldown restores while an expired one does not")
    func persistedCooldownRestorationIsBoundedByTime() {
        let now = sample(0).wallTime
        var active = ThermalSafetyStateMachine(policy: policy)
        active.restoreCooling(
            trigger: .seriousThermalState,
            cooldownUntil: now.addingTimeInterval(5),
            now: now
        )
        #expect(active.blocksLocalGeneration)

        var expired = ThermalSafetyStateMachine(policy: policy)
        expired.restoreCooling(
            trigger: .seriousThermalState,
            cooldownUntil: now,
            now: now
        )
        #expect(expired.phase == .ready)
    }

    @Test("Thermal pressure never blocks an unrelated cloud route")
    func irrelevantLocalRuntimeDoesNotTrip() {
        var machine = ThermalSafetyStateMachine(policy: policy)

        #expect(machine.evaluate(sample(
            0,
            condition: .critical,
            relevant: false,
            active: true
        )).isEmpty)
        #expect(machine.phase == .ready)
    }

    @Test("Short tool pauses retain the load budget while a real idle period resets it")
    func idleResetDistinguishesToolGapsFromCompletedWork() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0))
        _ = machine.evaluate(sample(1))
        _ = machine.evaluate(sample(2, active: false))
        _ = machine.evaluate(sample(3))
        #expect(machine.accumulatedActiveSeconds == 2)

        _ = machine.evaluate(sample(4, active: false))
        _ = machine.evaluate(sample(5, active: false))
        _ = machine.evaluate(sample(6, active: false))
        #expect(machine.accumulatedActiveSeconds == 0)

        _ = machine.evaluate(sample(7))
        #expect(machine.accumulatedActiveSeconds == 0)
    }

    @Test("A real idle period clears sustained-work Eco mode")
    func idleClearsSustainedEcoMode() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        for second in 0...4 { _ = machine.evaluate(sample(TimeInterval(second))) }
        #expect(machine.phase == .eco(reason: .sustainedLocalGeneration))
        _ = machine.evaluate(sample(5, active: false))
        _ = machine.evaluate(sample(6, active: false))
        #expect(machine.evaluate(sample(7, active: false)) == [.ecoCleared])
        #expect(machine.phase == .ready)
    }

    @Test("A long sample gap or system sleep cannot consume an unbounded load budget")
    func sampleGapIsBounded() {
        var machine = ThermalSafetyStateMachine(policy: policy)
        _ = machine.evaluate(sample(0))

        #expect(machine.evaluate(sample(100)).isEmpty)
        #expect(machine.accumulatedActiveSeconds == 1)
    }

    @Test("An unverifiable shutdown locks the circuit breaker until restart")
    func shutdownFailureLocksPermanently() {
        var machine = ThermalSafetyStateMachine(policy: policy)

        #expect(machine.lock(trigger: .criticalThermalState) == [
            .locked(trigger: .criticalThermalState)
        ])
        #expect(machine.evaluate(sample(100, condition: .nominal, active: false)) == [
            .locked(trigger: .criticalThermalState)
        ])
        #expect(machine.blocksLocalGeneration)
    }

    @Test("Cooldown persistence survives relaunch but rejects stale or excessive holds")
    func cooldownPersistenceIsFailSafeAndBounded() throws {
        let suite = "FulmarThermalSafetyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = PreferencesStore(defaults: defaults)
        let now = Date(timeIntervalSinceReferenceDate: 2_000)
        let until = now.addingTimeInterval(300)

        store.recordThermalSafetyCooldown(trigger: .seriousThermalState, until: until)
        let restored = try #require(store.thermalSafetyCooldown(now: now))
        #expect(restored.trigger == .seriousThermalState)
        #expect(restored.until == until)

        store.recordThermalSafetyCooldown(
            trigger: .criticalThermalState,
            until: now.addingTimeInterval(3_601)
        )
        #expect(store.thermalSafetyCooldown(now: now) == nil)

        store.recordThermalSafetyCooldown(trigger: .seriousThermalState, until: now)
        #expect(store.thermalSafetyCooldown(now: now) == nil)
    }

    @Test("Persistent deadline extensions are batched and escalation is immediate")
    func cooldownPersistenceGateAvoidsSampleRateWrites() {
        let start = Date(timeIntervalSinceReferenceDate: 3_000)
        var gate = ThermalCooldownPersistenceGate()
        gate.markPersisted(
            trigger: .seriousThermalState,
            cooldownUntil: start.addingTimeInterval(300)
        )

        let twoSecondExtension = gate.shouldPersist(
            trigger: .seriousThermalState,
            cooldownUntil: start.addingTimeInterval(302)
        )
        let thirtySecondExtension = gate.shouldPersist(
            trigger: .seriousThermalState,
            cooldownUntil: start.addingTimeInterval(330)
        )
        let criticalEscalation = gate.shouldPersist(
            trigger: .criticalThermalState,
            cooldownUntil: start.addingTimeInterval(331)
        )
        #expect(!twoSecondExtension)
        #expect(thirtySecondExtension)
        #expect(criticalEscalation)

        gate.clear()
        #expect(gate.trigger == nil)
        #expect(gate.cooldownUntil == nil)
    }

    @Test("Cooldown cannot restart or publish underneath a protected mutation permit")
    func protectedMutationOwnsThermalRecoveryUntilItsInferenceWaiterStarts() {
        #expect(ProtectedThermalRecoveryPolicy.recoveryDecision(
            protectedTransitionInFlight: true
        ) == .deferToProtectedTransition)
        #expect(!ProtectedThermalRecoveryPolicy.mayPublishReady(
            protectedTransitionInFlight: true,
            protectedInferenceStartIsWaiting: false
        ))

        // Once the same protected transition explicitly begins its verified
        // inference start, Ready is its acknowledgement rather than an
        // independent thermal restart and may complete the normal handoff.
        #expect(ProtectedThermalRecoveryPolicy.mayPublishReady(
            protectedTransitionInFlight: true,
            protectedInferenceStartIsWaiting: true
        ))
        #expect(ProtectedThermalRecoveryPolicy.recoveryDecision(
            protectedTransitionInFlight: false
        ) == .restartRuntime)
        #expect(ProtectedThermalRecoveryPolicy.mayPublishReady(
            protectedTransitionInFlight: false,
            protectedInferenceStartIsWaiting: false
        ))
    }
}
