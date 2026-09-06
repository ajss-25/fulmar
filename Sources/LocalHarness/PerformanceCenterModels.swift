import Foundation

enum HostThermalCondition: String, Codable, CaseIterable, Sendable {
    case nominal
    case fair
    case serious
    case critical
    case unknown

    var displayName: String {
        switch self {
        case .nominal: return "Nominal"
        case .fair: return "Warm"
        case .serious: return "Hot"
        case .critical: return "Critical"
        case .unknown: return "Unknown"
        }
    }
}

enum HostProcessorArchitecture: String, Codable, Sendable {
    case appleSilicon
    case intel
    case unknown

    var displayName: String {
        switch self {
        case .appleSilicon: return "Apple silicon"
        case .intel: return "Intel"
        case .unknown: return "Unknown"
        }
    }
}

struct HostPerformanceSnapshot: Codable, Equatable, Sendable {
    let capturedAt: Date
    let physicalMemoryBytes: UInt64
    let thermalCondition: HostThermalCondition
    let lowPowerModeEnabled: Bool
    let processorArchitecture: HostProcessorArchitecture
    let logicalProcessorCount: Int
    let activeProcessorCount: Int

    var physicalMemoryGiB: Double {
        Double(physicalMemoryBytes) / 1_073_741_824
    }
}

protocol HostEnvironmentReading {
    var physicalMemory: UInt64 { get }
    var thermalCondition: HostThermalCondition { get }
    var lowPowerModeEnabled: Bool { get }
    var processorArchitecture: HostProcessorArchitecture { get }
    var logicalProcessorCount: Int { get }
    var activeProcessorCount: Int { get }
}

struct SystemHostEnvironmentReader: HostEnvironmentReading {
    private let processInfo = ProcessInfo.processInfo

    var physicalMemory: UInt64 { processInfo.physicalMemory }

    var thermalCondition: HostThermalCondition {
        switch processInfo.thermalState {
        case .nominal: return .nominal
        case .fair: return .fair
        case .serious: return .serious
        case .critical: return .critical
        @unknown default: return .unknown
        }
    }

    var lowPowerModeEnabled: Bool { processInfo.isLowPowerModeEnabled }

    var processorArchitecture: HostProcessorArchitecture {
        #if arch(arm64)
        return .appleSilicon
        #elseif arch(x86_64)
        return .intel
        #else
        return .unknown
        #endif
    }

    var logicalProcessorCount: Int { processInfo.processorCount }
    var activeProcessorCount: Int { processInfo.activeProcessorCount }
}

struct HostPerformanceSnapshotCollector {
    private let environment: any HostEnvironmentReading

    init(environment: any HostEnvironmentReading = SystemHostEnvironmentReader()) {
        self.environment = environment
    }

    func capture(at date: Date = Date()) -> HostPerformanceSnapshot {
        HostPerformanceSnapshot(
            capturedAt: date,
            physicalMemoryBytes: environment.physicalMemory,
            thermalCondition: environment.thermalCondition,
            lowPowerModeEnabled: environment.lowPowerModeEnabled,
            processorArchitecture: environment.processorArchitecture,
            logicalProcessorCount: max(1, environment.logicalProcessorCount),
            activeProcessorCount: max(1, environment.activeProcessorCount)
        )
    }
}

enum GenerationOutcome: String, Codable, Sendable {
    case completed
    case cancelled
    case failed
}

/// Deliberately coarse. Raw errors may contain request URLs, response bodies, or
/// user content, so telemetry never retains an Error or localized description.
enum GenerationFailureCategory: String, Codable, Sendable {
    case providerUnavailable
    case timedOut
    case invalidResponse
    case toolFailure
    case resourcePressure
    case unknown
}

enum OutputTokenCountSource: String, Codable, Sendable {
    case providerReported
    case estimated
}

struct GenerationTelemetryRecord: Codable, Equatable, Identifiable, Sendable {
    let id: UUID
    let route: ModelRoute?
    let startedAt: Date
    let completedAt: Date
    let timeToFirstTokenSeconds: TimeInterval?
    let elapsedSeconds: TimeInterval
    let outputTokens: Int
    let outputTokenCountSource: OutputTokenCountSource
    let outputTokensPerSecond: Double?
    let outcome: GenerationOutcome
    let failureCategory: GenerationFailureCategory?
}

struct GenerationTelemetryRetentionPolicy: Equatable, Sendable {
    enum ValidationError: Error, Equatable, LocalizedError {
        case invalidRecordCount
        case invalidMaximumAge

        var errorDescription: String? {
            switch self {
            case .invalidRecordCount:
                return "Telemetry retention must keep between 1 and 500 records."
            case .invalidMaximumAge:
                return "Telemetry retention must be between 1 hour and 7 days."
            }
        }
    }

    static let absoluteMaximumRecords = 500
    static let absoluteMaximumAge: TimeInterval = 7 * 86_400
    static let `default` = try! GenerationTelemetryRetentionPolicy(
        maximumRecords: 100,
        maximumAge: 24 * 60 * 60
    )

    let maximumRecords: Int
    let maximumAge: TimeInterval

    init(maximumRecords: Int, maximumAge: TimeInterval) throws {
        guard (1...Self.absoluteMaximumRecords).contains(maximumRecords) else {
            throw ValidationError.invalidRecordCount
        }
        guard maximumAge >= 3_600, maximumAge <= Self.absoluteMaximumAge else {
            throw ValidationError.invalidMaximumAge
        }
        self.maximumRecords = maximumRecords
        self.maximumAge = maximumAge
    }
}

/// Thread-safe, memory-only performance telemetry. It has no API that accepts a
/// prompt or stores generated text. Text deltas are reduced immediately to a
/// UTF-8 byte count for a clearly labelled token estimate.
final class GenerationTelemetryAccumulator: @unchecked Sendable {
    static let absoluteMaximumActiveGenerations = 64

    private struct ActiveGeneration {
        let id: UUID
        let route: ModelRoute?
        let startedAt: Date
        var firstTokenAt: Date?
        var outputUTF8Bytes: Int
    }

    private let lock = NSLock()
    private let retention: GenerationTelemetryRetentionPolicy
    private var active: [UUID: ActiveGeneration] = [:]
    private var records: [GenerationTelemetryRecord] = []

    init(retention: GenerationTelemetryRetentionPolicy = .default) {
        self.retention = retention
    }

    @discardableResult
    func begin(route: ModelRoute? = nil, at date: Date = Date()) -> UUID {
        let id = UUID()
        lock.withLock {
            prune(referenceDate: date)
            if active.count >= Self.absoluteMaximumActiveGenerations,
               let oldest = active.values.min(by: {
                   if $0.startedAt == $1.startedAt { return $0.id.uuidString < $1.id.uuidString }
                   return $0.startedAt < $1.startedAt
               }) {
                active.removeValue(forKey: oldest.id)
            }
            active[id] = ActiveGeneration(
                id: id,
                route: sanitized(route: route),
                startedAt: date,
                firstTokenAt: nil,
                outputUTF8Bytes: 0
            )
        }
        return id
    }

    /// Records a response delta without retaining its contents.
    @discardableResult
    func recordOutput(_ text: String, for id: UUID, at date: Date = Date()) -> Bool {
        guard !text.isEmpty else { return false }
        return lock.withLock {
            prune(referenceDate: date)
            guard var generation = active[id] else { return false }
            if generation.firstTokenAt == nil { generation.firstTokenAt = date }
            let (newCount, overflow) = generation.outputUTF8Bytes.addingReportingOverflow(text.utf8.count)
            generation.outputUTF8Bytes = overflow ? Int.max : newCount
            active[id] = generation
            return true
        }
    }

    @discardableResult
    func finish(
        _ id: UUID,
        reportedOutputTokens: Int? = nil,
        at date: Date = Date()
    ) -> GenerationTelemetryRecord? {
        complete(id, outcome: .completed, failureCategory: nil, reportedOutputTokens: reportedOutputTokens, at: date)
    }

    @discardableResult
    func cancel(_ id: UUID, at date: Date = Date()) -> GenerationTelemetryRecord? {
        complete(id, outcome: .cancelled, failureCategory: nil, reportedOutputTokens: nil, at: date)
    }

    @discardableResult
    func fail(
        _ id: UUID,
        category: GenerationFailureCategory = .unknown,
        at date: Date = Date()
    ) -> GenerationTelemetryRecord? {
        complete(id, outcome: .failed, failureCategory: category, reportedOutputTokens: nil, at: date)
    }

    func history(at date: Date = Date()) -> [GenerationTelemetryRecord] {
        lock.withLock {
            prune(referenceDate: date)
            return records
        }
    }

    var activeGenerationCount: Int {
        lock.withLock { active.count }
    }

    /// Privacy action: discards completed telemetry and any in-flight counters.
    func clear() {
        lock.withLock {
            active.removeAll(keepingCapacity: false)
            records.removeAll(keepingCapacity: false)
        }
    }

    private func complete(
        _ id: UUID,
        outcome: GenerationOutcome,
        failureCategory: GenerationFailureCategory?,
        reportedOutputTokens: Int?,
        at date: Date
    ) -> GenerationTelemetryRecord? {
        lock.withLock {
            prune(referenceDate: date)
            guard let generation = active.removeValue(forKey: id) else { return nil }
            let elapsed = max(0, date.timeIntervalSince(generation.startedAt))
            let ttft = generation.firstTokenAt.map { max(0, $0.timeIntervalSince(generation.startedAt)) }
            let estimatedTokens = estimatedTokenCount(forUTF8Bytes: generation.outputUTF8Bytes)
            let hasReportedCount = reportedOutputTokens.map { $0 >= 0 } ?? false
            let tokenCount = hasReportedCount ? reportedOutputTokens! : estimatedTokens
            let tokenSource: OutputTokenCountSource = hasReportedCount ? .providerReported : .estimated
            let generationDuration = generation.firstTokenAt.map { max(0, date.timeIntervalSince($0)) }
            let rate = generationDuration.flatMap { duration in
                duration > 0 && tokenCount > 0 ? Double(tokenCount) / duration : nil
            }
            let record = GenerationTelemetryRecord(
                id: generation.id,
                route: generation.route,
                startedAt: generation.startedAt,
                completedAt: date,
                timeToFirstTokenSeconds: ttft,
                elapsedSeconds: elapsed,
                outputTokens: tokenCount,
                outputTokenCountSource: tokenSource,
                outputTokensPerSecond: rate,
                outcome: outcome,
                failureCategory: outcome == .failed ? (failureCategory ?? .unknown) : nil
            )
            records.append(record)
            prune(referenceDate: date)
            return record
        }
    }

    private func estimatedTokenCount(forUTF8Bytes byteCount: Int) -> Int {
        guard byteCount > 0 else { return 0 }
        let quotient = byteCount / 4
        return quotient + (byteCount.isMultiple(of: 4) ? 0 : 1)
    }

    private func prune(referenceDate: Date) {
        let oldestAllowed = referenceDate.addingTimeInterval(-retention.maximumAge)
        active = active.filter { $0.value.startedAt >= oldestAllowed }
        records.removeAll { $0.completedAt < oldestAllowed }
        records.sort {
            if $0.completedAt == $1.completedAt { return $0.id.uuidString < $1.id.uuidString }
            return $0.completedAt > $1.completedAt
        }
        if records.count > retention.maximumRecords {
            records.removeLast(records.count - retention.maximumRecords)
        }
    }

    private func sanitized(route: ModelRoute?) -> ModelRoute? {
        guard let route,
              isSafeIdentifier(route.provider.rawValue),
              isSafeIdentifier(route.model.rawValue) else { return nil }
        return route
    }

    private func isSafeIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 512 &&
            !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}

enum PerformanceWorkload: String, Codable, CaseIterable, Sendable {
    case interactive
    case general
    case longContext

    var displayName: String {
        switch self {
        case .interactive: return "Interactive"
        case .general: return "Everyday"
        case .longContext: return "Long context"
        }
    }
}

struct PerformanceProfileAssessment: Equatable, Sendable {
    let profile: PerformanceProfile
    let settings: ModelPerformanceSettings
    let summary: String
    let isRecommended: Bool
}

struct AdaptivePerformanceRecommendation: Equatable, Sendable {
    let recommendedProfile: PerformanceProfile?
    let reasons: [String]
    let assessments: [PerformanceProfileAssessment]
}

enum AdaptivePerformanceRecommender {
    private static let gibibyte: UInt64 = 1_073_741_824

    static func recommend(
        host: HostPerformanceSnapshot,
        ollama: OllamaRuntimeSnapshot,
        recentTelemetry: [GenerationTelemetryRecord],
        workload: PerformanceWorkload = .general,
        selection: ModelSelection? = .defaultLocal
    ) -> AdaptivePerformanceRecommendation {
        guard let selection else {
            return unavailable("The current provider and model route could not be verified, so Fulmar will not guess at local performance settings.")
        }
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else {
            return unavailable("Cloud and network-provider requests keep their provider-defined limits and are not changed by this Mac's memory, power, or thermal state.")
        }
        if selection.isLocalCompatibilityRoute {
            return AdaptivePerformanceRecommendation(
                recommendedProfile: .compatibility,
                reasons: ["This alternate Ollama model uses Fulmar's fixed Compatibility limits; Fast, Balanced, and Deep are reserved for the release-qualified Qwen route."],
                assessments: [PerformanceProfileAssessment(
                    profile: .compatibility,
                    settings: .compatibilityLocalModel,
                    summary: assessmentSummary(for: .compatibility),
                    isRecommended: true
                )]
            )
        }
        guard host.physicalMemoryBytes >= QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes else {
            return unavailable("Fulmar's release-qualified Qwen profiles require at least 48 GB of physical memory. Choose a smaller admitted Compatibility model or an API provider on this Mac.")
        }

        var profile = baselineProfile(for: host, workload: workload)
        var reasons = baselineReasons(for: host, workload: workload, profile: profile)

        if host.lowPowerModeEnabled {
            profile = .fast
            reasons.insert("Low Power Mode is on, so Fast avoids sustained model load.", at: 0)
        }

        switch host.thermalCondition {
        case .serious, .critical:
            profile = .fast
            reasons.insert("The Mac is thermally constrained; Fast reduces heat and latency spikes.", at: 0)
        case .fair, .unknown:
            profile = .fast
            reasons.insert("The Mac is warm or its thermal reading is unavailable, so Fast preserves headroom.", at: 0)
        default:
            break
        }

        let loadedBytes = ollama.runningModels.reduce(UInt64(0)) { partial, model in
            let value = model.sizeVRAMBytes > 0 ? UInt64(model.sizeVRAMBytes) : 0
            let (sum, overflow) = partial.addingReportingOverflow(value)
            return overflow ? UInt64.max : sum
        }
        let memoryPressureThreshold = host.physicalMemoryBytes / 3 * 2
        if ollama.runningModels.count > 1 || loadedBytes > memoryPressureThreshold {
            profile = lower(profile)
            reasons.insert("Loaded local models are using substantial unified memory, so the recommendation leaves extra headroom.", at: 0)
        }

        let completed = Array(recentTelemetry
            .filter { $0.route == nil || $0.route?.provider == BuiltInProviderDescriptors.ollama.id }
            .sorted { $0.completedAt > $1.completedAt }
            .prefix(20))
        if completed.count >= 3 {
            let failures = completed.filter { $0.outcome == .failed }.count
            let failureRate = Double(failures) / Double(completed.count)
            if failureRate >= 0.25 {
                profile = .fast
                reasons.insert("At least one in four recent generations failed; Fast is the safest recovery profile.", at: 0)
            } else {
                let ttfts = completed.compactMap(\.timeToFirstTokenSeconds).filter { $0.isFinite && $0 >= 0 }
                let averageTTFT = ttfts.isEmpty ? nil : ttfts.reduce(0, +) / Double(ttfts.count)
                let rates = completed.compactMap(\.outputTokensPerSecond).filter { $0.isFinite && $0 >= 0 }
                let averageRate = rates.isEmpty ? nil : rates.reduce(0, +) / Double(rates.count)
                if (averageTTFT ?? 0) > 20 || (averageRate.map { $0 < 6 } ?? false) {
                    profile = lower(profile)
                    reasons.insert("Recent local generations are slow, so the recommendation steps down one profile.", at: 0)
                } else if profile == .deep, completed.count >= 5 {
                    reasons.insert("Recent generation latency is stable enough for the larger Deep context.", at: 0)
                }
            }
        } else {
            reasons.append("More local runs will make this recommendation adapt to measured latency and throughput.")
        }

        // Compatibility is a route-enforced safety cap for an unqualified
        // installed model, not a performance choice for the qualified Qwen
        // route. Showing it as a fourth recommendation card lets users apply
        // the wrong semantic profile from the Performance Center.
        let recommendableProfiles: [PerformanceProfile] = [.fast, .balanced, .deep]
        let assessments = recommendableProfiles.map { candidate in
            PerformanceProfileAssessment(
                profile: candidate,
                settings: candidate.settingsFor48GBAppleSilicon,
                summary: assessmentSummary(for: candidate),
                isRecommended: candidate == profile
            )
        }
        return AdaptivePerformanceRecommendation(
            recommendedProfile: profile,
            reasons: deduplicated(reasons),
            assessments: assessments
        )
    }

    private static func baselineProfile(
        for host: HostPerformanceSnapshot,
        workload: PerformanceWorkload
    ) -> PerformanceProfile {
        if host.physicalMemoryBytes < 32 * gibibyte { return .fast }
        switch workload {
        case .interactive:
            return .fast
        case .general:
            return .balanced
        case .longContext:
            return host.processorArchitecture == .appleSilicon && host.physicalMemoryBytes >= 48 * gibibyte
                ? .deep
                : .balanced
        }
    }

    private static func baselineReasons(
        for host: HostPerformanceSnapshot,
        workload: PerformanceWorkload,
        profile: PerformanceProfile
    ) -> [String] {
        var reasons: [String] = []
        if host.processorArchitecture == .appleSilicon && host.physicalMemoryBytes >= 48 * gibibyte {
            reasons.append("48 GB of Apple-silicon unified memory can run a quantized 27B model with useful context headroom.")
        } else if host.physicalMemoryBytes < 32 * gibibyte {
            reasons.append("Less than 32 GB of physical memory makes Fast the conservative local-model profile.")
        } else {
            reasons.append("Available memory supports the \(profile.displayName) profile for this workload.")
        }
        switch workload {
        case .interactive:
            reasons.append("Interactive work prioritizes first-token latency and responsiveness.")
        case .general:
            reasons.append("Everyday agent work benefits from Balanced's 48K configured model context and an 8K output budget.")
        case .longContext:
            reasons.append("Demanding builds can use Deep's 64K context and 16K output budget; adaptive Eco mode reduces sustained heat when needed.")
        }
        return reasons
    }

    private static func lower(_ profile: PerformanceProfile) -> PerformanceProfile {
        switch profile {
        case .deep: return .balanced
        case .balanced, .fast: return .fast
        case .compatibility: return .compatibility
        }
    }

    private static func assessmentSummary(for profile: PerformanceProfile) -> String {
        switch profile {
        case .fast:
            return "32K context · 4K output · shortest warm residency"
        case .balanced:
            return "48K context · 8K output · safest everyday default"
        case .deep:
            return "64K context · 16K output · bounded demanding builds"
        case .compatibility:
            return "8K context · 2K output · unqualified tool-model safety cap"
        }
    }

    private static func unavailable(_ reason: String) -> AdaptivePerformanceRecommendation {
        AdaptivePerformanceRecommendation(
            recommendedProfile: nil,
            reasons: [reason],
            assessments: []
        )
    }

    private static func deduplicated(_ strings: [String]) -> [String] {
        var seen: Set<String> = []
        return strings.filter { seen.insert($0).inserted }
    }
}

struct PerformanceCenterSnapshot: Equatable, Sendable {
    let capturedAt: Date
    let host: HostPerformanceSnapshot
    let ollama: OllamaRuntimeSnapshot
    let recommendation: AdaptivePerformanceRecommendation
    let telemetry: [GenerationTelemetryRecord]
    let selection: ModelSelection?

    init(
        capturedAt: Date,
        host: HostPerformanceSnapshot,
        ollama: OllamaRuntimeSnapshot,
        recommendation: AdaptivePerformanceRecommendation,
        telemetry: [GenerationTelemetryRecord],
        selection: ModelSelection? = .defaultLocal
    ) {
        self.capturedAt = capturedAt
        self.host = host
        self.ollama = ollama
        self.recommendation = recommendation
        self.telemetry = Array(telemetry.prefix(GenerationTelemetryRetentionPolicy.absoluteMaximumRecords))
        self.selection = selection
    }
}
