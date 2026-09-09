import Foundation

enum ThermalSafetyTrigger: String, Codable, Equatable, Sendable {
    case seriousThermalState
    case criticalThermalState
    case criticalMemoryPressure
    case sustainedLocalGeneration

    var displayName: String {
        switch self {
        case .seriousThermalState: return "High temperature"
        case .criticalThermalState: return "Critical temperature"
        case .criticalMemoryPressure: return "Critical memory pressure"
        case .sustainedLocalGeneration: return "Sustained local generation"
        }
    }
}

enum ThermalEcoReason: String, Codable, Equatable, Sendable {
    case thermalPressure
    case memoryPressure
    case sustainedLocalGeneration

    var displayName: String {
        switch self {
        case .thermalPressure: return "Reduced thermal headroom"
        case .memoryPressure: return "Reduced memory headroom"
        case .sustainedLocalGeneration: return "Sustained local AI work"
        }
    }
}

/// Model-neutral copy for the app-owned local-runtime safety path. Thermal
/// protection applies to every admitted Ollama model, so user-facing recovery
/// text must not imply that the selected route is always the qualified Qwen
/// manifest.
enum ThermalSafetyPresentation {
    static func restartNotificationBody(
        trigger: ThermalSafetyTrigger,
        recoveryCondition: String
    ) -> String {
        "\(trigger.displayName) triggered cooldown. Fulmar will verify \(recoveryCondition) before restarting the selected local model."
    }

    static func cooldownDetail(
        trigger: ThermalSafetyTrigger,
        estimate: String
    ) -> String {
        "\(trigger.displayName) paused the selected local model. Your task and completed work remain saved; the interrupted model step may need to resume. \(estimate)"
    }

    static func normalModeRecoveryDetail(reason: String) -> String {
        "Fulmar could not save and verify its Normal workload policy, so the selected local model was not restarted. Fulmar will retry automatically. Open Performance Center for the current safety state, or repair Fulmar’s app-data permissions and choose Restart Local Services to retry now. \(reason)"
    }

    static let normalModeRecoveryNotification =
        "The selected local model remains paused. Fulmar will retry automatically; open Performance Center or use Restart Local Services after repairing app-data permissions."
}

struct ThermalSafetyPolicy: Equatable, Sendable {
    let proactiveEcoActiveSeconds: TimeInterval
    let maximumConstrainedActiveSeconds: TimeInterval
    let inactiveResetSeconds: TimeInterval
    let maximumSampleGapSeconds: TimeInterval
    let seriousCooldownSeconds: TimeInterval
    let criticalCooldownSeconds: TimeInterval
    let sustainedLoadCooldownSeconds: TimeInterval
    let nominalRecoverySeconds: TimeInterval
    let ecoNominalRecoverySeconds: TimeInterval
    let memoryPressureCooldownSeconds: TimeInterval
    let memoryPressureRecoverySeconds: TimeInterval

    static let production = ThermalSafetyPolicy(
        proactiveEcoActiveSeconds: 240,
        maximumConstrainedActiveSeconds: 900,
        inactiveResetSeconds: 90,
        maximumSampleGapSeconds: 10,
        seriousCooldownSeconds: 90,
        criticalCooldownSeconds: 600,
        sustainedLoadCooldownSeconds: 120,
        nominalRecoverySeconds: 60,
        ecoNominalRecoverySeconds: 60,
        memoryPressureCooldownSeconds: 30,
        memoryPressureRecoverySeconds: 30
    )

    init(
        proactiveEcoActiveSeconds: TimeInterval,
        maximumConstrainedActiveSeconds: TimeInterval,
        inactiveResetSeconds: TimeInterval,
        maximumSampleGapSeconds: TimeInterval,
        seriousCooldownSeconds: TimeInterval,
        criticalCooldownSeconds: TimeInterval,
        sustainedLoadCooldownSeconds: TimeInterval,
        nominalRecoverySeconds: TimeInterval,
        ecoNominalRecoverySeconds: TimeInterval,
        memoryPressureCooldownSeconds: TimeInterval = 30,
        memoryPressureRecoverySeconds: TimeInterval = 30
    ) {
        precondition(proactiveEcoActiveSeconds > 0)
        precondition(maximumConstrainedActiveSeconds >= proactiveEcoActiveSeconds)
        precondition(inactiveResetSeconds > 0)
        precondition(maximumSampleGapSeconds > 0)
        precondition(seriousCooldownSeconds > 0)
        precondition(criticalCooldownSeconds >= seriousCooldownSeconds)
        precondition(sustainedLoadCooldownSeconds > 0)
        precondition(nominalRecoverySeconds > 0)
        precondition(ecoNominalRecoverySeconds > 0)
        precondition(memoryPressureCooldownSeconds > 0)
        precondition(memoryPressureRecoverySeconds > 0)
        self.proactiveEcoActiveSeconds = proactiveEcoActiveSeconds
        self.maximumConstrainedActiveSeconds = maximumConstrainedActiveSeconds
        self.inactiveResetSeconds = inactiveResetSeconds
        self.maximumSampleGapSeconds = maximumSampleGapSeconds
        self.seriousCooldownSeconds = seriousCooldownSeconds
        self.criticalCooldownSeconds = criticalCooldownSeconds
        self.sustainedLoadCooldownSeconds = sustainedLoadCooldownSeconds
        self.nominalRecoverySeconds = nominalRecoverySeconds
        self.ecoNominalRecoverySeconds = ecoNominalRecoverySeconds
        self.memoryPressureCooldownSeconds = memoryPressureCooldownSeconds
        self.memoryPressureRecoverySeconds = memoryPressureRecoverySeconds
    }
}

struct ThermalSafetySample: Equatable, Sendable {
    let wallTime: Date
    let uptime: TimeInterval
    let condition: HostThermalCondition
    let localRuntimeRelevant: Bool
    let localGenerationActive: Bool
    let memoryPressure: HostMemoryPressureCondition

    init(
        wallTime: Date,
        uptime: TimeInterval,
        condition: HostThermalCondition,
        localRuntimeRelevant: Bool,
        localGenerationActive: Bool,
        memoryPressure: HostMemoryPressureCondition = .normal
    ) {
        self.wallTime = wallTime
        self.uptime = uptime
        self.condition = condition
        self.localRuntimeRelevant = localRuntimeRelevant
        self.localGenerationActive = localGenerationActive
        self.memoryPressure = memoryPressure
    }
}

enum ThermalSafetyPhase: Equatable, Sendable {
    case ready
    case eco(reason: ThermalEcoReason)
    case cooling(trigger: ThermalSafetyTrigger, cooldownUntil: Date)
    case locked(trigger: ThermalSafetyTrigger)

    var blocksNewLocalGeneration: Bool {
        switch self {
        case .ready:
            return false
        case .eco(reason: .memoryPressure), .cooling, .locked:
            return true
        case .eco(reason: .thermalPressure), .eco(reason: .sustainedLocalGeneration):
            return false
        }
    }
}

enum ThermalSafetyAction: Equatable, Sendable {
    case ecoStarted(reason: ThermalEcoReason)
    case ecoCleared
    case trip(trigger: ThermalSafetyTrigger, cooldownUntil: Date)
    case cooling(trigger: ThermalSafetyTrigger, secondsRemaining: Int)
    case recovered
    case locked(trigger: ThermalSafetyTrigger)
}

/// A deterministic, content-free thermal circuit breaker. The app samples
/// DSH's running-session bit and macOS thermal pressure, while this state
/// machine owns only bounded timings and transitions. It never receives a
/// prompt, model response, tool argument, path, or credential.
struct ThermalSafetyStateMachine: Equatable, Sendable {
    private(set) var phase: ThermalSafetyPhase = .ready
    private(set) var accumulatedActiveSeconds: TimeInterval = 0
    private(set) var constrainedActiveSeconds: TimeInterval = 0

    private let policy: ThermalSafetyPolicy
    private var lastSampleUptime: TimeInterval?
    private var lastActiveUptime: TimeInterval?
    private var lastConstrainedActiveUptime: TimeInterval?
    private var nominalSinceUptime: TimeInterval?

    init(policy: ThermalSafetyPolicy = .production) {
        self.policy = policy
    }

    var blocksLocalGeneration: Bool {
        switch phase {
        case .ready, .eco: return false
        case .cooling, .locked: return true
        }
    }

    /// Warning pressure lets an already-running local turn settle at the Eco
    /// workload, but refuses every new local turn until memory has remained
    /// normal for the recovery window. Critical pressure uses the stronger
    /// shutdown path represented by `blocksLocalGeneration` as well.
    var blocksNewLocalGeneration: Bool {
        phase.blocksNewLocalGeneration
    }

    var usesEcoWorkload: Bool {
        if case .eco = phase { return true }
        return false
    }

    mutating func restoreCooling(
        trigger: ThermalSafetyTrigger,
        cooldownUntil: Date,
        now: Date
    ) {
        guard cooldownUntil > now else { return }
        phase = .cooling(trigger: trigger, cooldownUntil: cooldownUntil)
        accumulatedActiveSeconds = 0
        constrainedActiveSeconds = 0
        lastConstrainedActiveUptime = nil
        nominalSinceUptime = nil
    }

    mutating func lock(trigger: ThermalSafetyTrigger) -> [ThermalSafetyAction] {
        phase = .locked(trigger: trigger)
        accumulatedActiveSeconds = 0
        constrainedActiveSeconds = 0
        lastConstrainedActiveUptime = nil
        nominalSinceUptime = nil
        return [.locked(trigger: trigger)]
    }

    mutating func evaluate(_ sample: ThermalSafetySample) -> [ThermalSafetyAction] {
        let delta: TimeInterval
        if let lastSampleUptime, sample.uptime >= lastSampleUptime {
            delta = min(policy.maximumSampleGapSeconds, sample.uptime - lastSampleUptime)
        } else {
            delta = 0
        }
        lastSampleUptime = sample.uptime

        switch phase {
        case .locked(let trigger):
            return [.locked(trigger: trigger)]
        case .cooling(let trigger, let cooldownUntil):
            return evaluateCooling(
                sample,
                trigger: trigger,
                cooldownUntil: cooldownUntil
            )
        case .ready, .eco:
            break
        }

        guard sample.localRuntimeRelevant else {
            resetLoadTracking()
            guard case .eco = phase else { return [] }
            phase = .ready
            nominalSinceUptime = nil
            return [.ecoCleared]
        }


        switch sample.memoryPressure {
        case .critical:
            return trip(.criticalMemoryPressure, at: sample.wallTime)
        case .warning:
            nominalSinceUptime = nil
            guard phase != .eco(reason: .memoryPressure) else { return [] }
            phase = .eco(reason: .memoryPressure)
            return [.ecoStarted(reason: .memoryPressure)]
        case .normal:
            break
        }

        switch sample.condition {
        case .critical:
            return trip(.criticalThermalState, at: sample.wallTime)
        case .serious:
            return trip(.seriousThermalState, at: sample.wallTime)
        case .nominal, .fair, .unknown:
            break
        }

        let constrained = sample.condition == .fair || sample.condition == .unknown
        if sample.localGenerationActive {
            if lastActiveUptime != nil { accumulatedActiveSeconds += delta }
            lastActiveUptime = sample.uptime
            if constrained {
                if lastConstrainedActiveUptime != nil { constrainedActiveSeconds += delta }
                lastConstrainedActiveUptime = sample.uptime
            } else {
                constrainedActiveSeconds = 0
                lastConstrainedActiveUptime = nil
            }
        } else if let lastActiveUptime,
                  sample.uptime - lastActiveUptime >= policy.inactiveResetSeconds {
            resetLoadTracking()
            if case .eco(reason: .sustainedLocalGeneration) = phase,
               sample.condition == .nominal {
                phase = .ready
                nominalSinceUptime = nil
                return [.ecoCleared]
            }
        }

        if case .eco(let reason) = phase {
            if constrained {
                nominalSinceUptime = nil
                if sample.localGenerationActive,
                   constrainedActiveSeconds >= policy.maximumConstrainedActiveSeconds {
                    return trip(.sustainedLocalGeneration, at: sample.wallTime)
                }
                return []
            }

            switch reason {
            case .memoryPressure:
                guard sample.condition == .nominal else {
                    nominalSinceUptime = nil
                    return []
                }
                if nominalSinceUptime == nil { nominalSinceUptime = sample.uptime }
                let stableNominal = max(0, sample.uptime - (nominalSinceUptime ?? sample.uptime))
                guard stableNominal >= policy.memoryPressureRecoverySeconds else { return [] }
                if sample.localGenerationActive,
                   accumulatedActiveSeconds >= policy.proactiveEcoActiveSeconds {
                    phase = .eco(reason: .sustainedLocalGeneration)
                    nominalSinceUptime = nil
                    return []
                }
                phase = .ready
                nominalSinceUptime = nil
                return [.ecoCleared]
            case .thermalPressure:
                if nominalSinceUptime == nil { nominalSinceUptime = sample.uptime }
                let stableNominal = max(0, sample.uptime - (nominalSinceUptime ?? sample.uptime))
                guard stableNominal >= policy.ecoNominalRecoverySeconds else { return [] }
                if sample.localGenerationActive,
                   accumulatedActiveSeconds >= policy.proactiveEcoActiveSeconds {
                    phase = .eco(reason: .sustainedLocalGeneration)
                    nominalSinceUptime = nil
                    return []
                }
                phase = .ready
                nominalSinceUptime = nil
                return [.ecoCleared]
            case .sustainedLocalGeneration:
                return []
            }
        }

        if constrained {
            phase = .eco(reason: .thermalPressure)
            nominalSinceUptime = nil
            return [.ecoStarted(reason: .thermalPressure)]
        }
        if sample.localGenerationActive,
           accumulatedActiveSeconds >= policy.proactiveEcoActiveSeconds {
            phase = .eco(reason: .sustainedLocalGeneration)
            nominalSinceUptime = nil
            return [.ecoStarted(reason: .sustainedLocalGeneration)]
        }
        return []
    }

    private mutating func evaluateCooling(
        _ sample: ThermalSafetySample,
        trigger: ThermalSafetyTrigger,
        cooldownUntil: Date
    ) -> [ThermalSafetyAction] {
        var effectiveTrigger = trigger
        var effectiveUntil = cooldownUntil
        switch sample.memoryPressure {
        case .critical:
            if effectiveTrigger != .seriousThermalState,
               effectiveTrigger != .criticalThermalState {
                effectiveTrigger = .criticalMemoryPressure
            }
            effectiveUntil = max(
                effectiveUntil,
                sample.wallTime.addingTimeInterval(policy.memoryPressureCooldownSeconds)
            )
            nominalSinceUptime = nil
        case .warning:
            nominalSinceUptime = nil
        case .normal:
            break
        }
        switch sample.condition {
        case .critical:
            effectiveTrigger = .criticalThermalState
            effectiveUntil = max(effectiveUntil, sample.wallTime.addingTimeInterval(policy.criticalCooldownSeconds))
            nominalSinceUptime = nil
        case .serious:
            if effectiveTrigger != .criticalThermalState {
                effectiveTrigger = .seriousThermalState
            }
            effectiveUntil = max(effectiveUntil, sample.wallTime.addingTimeInterval(policy.seriousCooldownSeconds))
            nominalSinceUptime = nil
        case .nominal:
            if sample.memoryPressure == .normal, nominalSinceUptime == nil {
                nominalSinceUptime = sample.uptime
            }
        case .fair, .unknown:
            nominalSinceUptime = nil
        }

        phase = .cooling(trigger: effectiveTrigger, cooldownUntil: effectiveUntil)
        if sample.memoryPressure != .normal { nominalSinceUptime = nil }
        let nominalDuration = nominalSinceUptime.map { max(0, sample.uptime - $0) } ?? 0
        let requiredRecoverySeconds = effectiveTrigger == .criticalMemoryPressure
            ? policy.memoryPressureRecoverySeconds
            : policy.nominalRecoverySeconds
        if sample.wallTime >= effectiveUntil,
           nominalDuration >= requiredRecoverySeconds {
            phase = .ready
            accumulatedActiveSeconds = 0
            lastActiveUptime = nil
            nominalSinceUptime = nil
            return [.recovered]
        }
        let remaining = max(0, Int(ceil(effectiveUntil.timeIntervalSince(sample.wallTime))))
        return [.cooling(trigger: effectiveTrigger, secondsRemaining: remaining)]
    }

    private mutating func trip(
        _ trigger: ThermalSafetyTrigger,
        at date: Date
    ) -> [ThermalSafetyAction] {
        let duration: TimeInterval
        switch trigger {
        case .seriousThermalState: duration = policy.seriousCooldownSeconds
        case .criticalThermalState: duration = policy.criticalCooldownSeconds
        case .criticalMemoryPressure: duration = policy.memoryPressureCooldownSeconds
        case .sustainedLocalGeneration: duration = policy.sustainedLoadCooldownSeconds
        }
        let until = date.addingTimeInterval(duration)
        phase = .cooling(trigger: trigger, cooldownUntil: until)
        accumulatedActiveSeconds = 0
        constrainedActiveSeconds = 0
        lastActiveUptime = nil
        lastConstrainedActiveUptime = nil
        nominalSinceUptime = nil
        return [.trip(trigger: trigger, cooldownUntil: until)]
    }

    private mutating func resetLoadTracking() {
        accumulatedActiveSeconds = 0
        constrainedActiveSeconds = 0
        lastActiveUptime = nil
        lastConstrainedActiveUptime = nil
    }
}

enum ThermalSafetyError: LocalizedError, Equatable {
    case coolingDown
    case memoryPressure
    case runtimeLocked

    var errorDescription: String? {
        switch self {
        case .coolingDown:
            return "Thermal protection is cooling this Mac. Local model tasks remain paused until a stable nominal temperature is verified."
        case .memoryPressure:
            return "Memory protection has paused local model tasks. At warning pressure, work already running may finish in Eco mode; critical pressure cancels local generation and stops the app-owned runtime. New local work resumes only after memory pressure stays normal. Cloud routes remain available."
        case .runtimeLocked:
            return "Thermal protection could not verify that the local runtime stopped. Local model tasks remain locked until Fulmar is restarted and the runtime is verified."
        }
    }
}

/// Batches persisted cooldown extensions while retaining immediate durability
/// for the first trip and any escalation. This keeps a continuously serious
/// thermal reading from writing UserDefaults on every monitor sample.
struct ThermalCooldownPersistenceGate: Equatable, Sendable {
    private(set) var trigger: ThermalSafetyTrigger?
    private(set) var cooldownUntil: Date?

    mutating func markPersisted(trigger: ThermalSafetyTrigger, cooldownUntil: Date) {
        self.trigger = trigger
        self.cooldownUntil = cooldownUntil
    }

    mutating func shouldPersist(
        trigger: ThermalSafetyTrigger,
        cooldownUntil: Date,
        minimumExtension: TimeInterval = 30
    ) -> Bool {
        precondition(minimumExtension >= 0)
        let triggerEscalated = self.trigger != trigger
        let deadlineExtension = cooldownUntil.timeIntervalSince(self.cooldownUntil ?? .distantPast)
        guard triggerEscalated || deadlineExtension >= minimumExtension else { return false }
        markPersisted(trigger: trigger, cooldownUntil: cooldownUntil)
        return true
    }

    mutating func clear() {
        trigger = nil
        cooldownUntil = nil
    }
}
