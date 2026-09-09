import Foundation

enum PerformanceProfile: String, Codable, CaseIterable, Hashable, Sendable {
    case fast
    case balanced
    case deep
    /// Fixed, deliberately small limits for an installed Ollama model which
    /// has passed Fulmar's text/tool/context checks but is not the release-
    /// qualified Qwen route. It is a real runtime contract rather than a UI
    /// label: session IDs, DSH output caps, Ollama launch limits and adapter
    /// metadata all resolve this same value.
    case compatibility

    var displayName: String {
        switch self {
        case .fast: return "Fast"
        case .balanced: return "Balanced"
        case .deep: return "Deep"
        case .compatibility: return "Compatibility"
        }
    }

    /// Conservative presets for a 27B quantized local model on a 48 GB Apple
    /// Silicon Mac. Provider adapters may cap these values further when a model
    /// advertises smaller limits.
    var settingsFor48GBAppleSilicon: ModelPerformanceSettings {
        switch self {
        case .fast: return .fast48GBAppleSilicon
        case .balanced: return .balanced48GBAppleSilicon
        case .deep: return .deep48GBAppleSilicon
        case .compatibility: return .compatibilityLocalModel
        }
    }

    /// Stable, non-secret per-session output catalog shared with the reviewed
    /// DSH performance plugin. Context capacity is deliberately not carried in
    /// this catalog: DSH owns it as exact adapter/model metadata, so it cannot
    /// safely vary between concurrent sessions that use the same route.
    static var runtimeCatalogJSON: String {
        struct Entry: Encodable {
            let maxOutputTokens: Int
        }

        let catalog = Dictionary(uniqueKeysWithValues: allCases.map { profile in
            let settings = profile.settingsFor48GBAppleSilicon
            return (
                profile.rawValue,
                Entry(
                    maxOutputTokens: settings.maxOutputTokens
                )
            )
        })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try! encoder.encode(catalog)
        return String(decoding: data, as: UTF8.self)
    }
}

enum ReasoningPreference: String, Codable, Hashable, Sendable {
    case disabled
    case automatic
    case high
}

/// Typed request and local-runtime hints associated with a performance profile.
/// These values are limits, not claims about a model's underlying capability.
struct ModelPerformanceSettings: Codable, Hashable, Sendable {
    enum ValidationError: Error, Equatable, LocalizedError {
        case contextWindowTooSmall
        case outputLimitTooSmall
        case outputExceedsContext
        case invalidKeepAlive
        case invalidConcurrency

        var errorDescription: String? {
            switch self {
            case .contextWindowTooSmall: return "Context window must be at least 1,024 tokens."
            case .outputLimitTooSmall: return "Output limit must be at least 256 tokens."
            case .outputExceedsContext: return "Output limit cannot exceed the context window."
            case .invalidKeepAlive: return "Keep-alive must be between zero and 86,400 seconds."
            case .invalidConcurrency: return "Concurrent generations must be between one and eight."
            }
        }
    }

    let contextWindowTokens: Int
    let maxOutputTokens: Int
    let keepAliveSeconds: Int
    let maxConcurrentGenerations: Int
    let reasoningPreference: ReasoningPreference

    init(
        contextWindowTokens: Int,
        maxOutputTokens: Int,
        keepAliveSeconds: Int,
        maxConcurrentGenerations: Int,
        reasoningPreference: ReasoningPreference
    ) throws {
        guard contextWindowTokens >= 1_024 else { throw ValidationError.contextWindowTooSmall }
        guard maxOutputTokens >= 256 else { throw ValidationError.outputLimitTooSmall }
        guard maxOutputTokens <= contextWindowTokens else { throw ValidationError.outputExceedsContext }
        guard (0...86_400).contains(keepAliveSeconds) else { throw ValidationError.invalidKeepAlive }
        guard (1...8).contains(maxConcurrentGenerations) else { throw ValidationError.invalidConcurrency }
        self.contextWindowTokens = contextWindowTokens
        self.maxOutputTokens = maxOutputTokens
        self.keepAliveSeconds = keepAliveSeconds
        self.maxConcurrentGenerations = maxConcurrentGenerations
        self.reasoningPreference = reasoningPreference
    }

    private enum CodingKeys: String, CodingKey {
        case contextWindowTokens
        case maxOutputTokens
        case keepAliveSeconds
        case maxConcurrentGenerations
        case reasoningPreference
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            contextWindowTokens: container.decode(Int.self, forKey: .contextWindowTokens),
            maxOutputTokens: container.decode(Int.self, forKey: .maxOutputTokens),
            keepAliveSeconds: container.decode(Int.self, forKey: .keepAliveSeconds),
            maxConcurrentGenerations: container.decode(Int.self, forKey: .maxConcurrentGenerations),
            reasoningPreference: container.decode(ReasoningPreference.self, forKey: .reasoningPreference)
        )
    }

    static let fast48GBAppleSilicon = try! ModelPerformanceSettings(
        contextWindowTokens: 32_768,
        maxOutputTokens: 4_096,
        keepAliveSeconds: 120,
        maxConcurrentGenerations: 1,
        reasoningPreference: .disabled
    )

    static let balanced48GBAppleSilicon = try! ModelPerformanceSettings(
        contextWindowTokens: 49_152,
        maxOutputTokens: 8_192,
        keepAliveSeconds: 600,
        maxConcurrentGenerations: 1,
        reasoningPreference: .automatic
    )

    static let deep48GBAppleSilicon = try! ModelPerformanceSettings(
        contextWindowTokens: 65_536,
        maxOutputTokens: 16_384,
        keepAliveSeconds: 1_200,
        maxConcurrentGenerations: 1,
        reasoningPreference: .high
    )

    /// Conservative fixed limits for an otherwise compatible local model.
    /// Unknown models never inherit the 27B Qwen presets simply because they
    /// happen to be selected through the same Ollama provider.
    static let compatibilityLocalModel = try! ModelPerformanceSettings(
        contextWindowTokens: 8_192,
        maxOutputTokens: 2_048,
        keepAliveSeconds: 120,
        maxConcurrentGenerations: 1,
        reasoningPreference: .disabled
    )
}

enum QualifiedLocalModelHostAdmissionError: Error, Equatable, LocalizedError {
    case insufficientPhysicalMemory(requiredBytes: UInt64, availableBytes: UInt64)

    var errorDescription: String? {
        switch self {
        case .insufficientPhysicalMemory(let requiredBytes, let availableBytes):
            let gibibyte = UInt64(1_073_741_824)
            let required = requiredBytes / gibibyte
            let available = availableBytes / gibibyte
            return "Fulmar's qualified Qwen 27B profiles require at least \(required) GB of physical memory. This Mac reports \(available) GB. Choose a smaller admitted local model in Compatibility mode or use a cloud provider."
        }
    }
}

/// Release qualification is a claim about one exact model and host class, not
/// a suggestion that a thermal trip will eventually make an undersized Mac
/// safe. This admission check runs before Fulmar starts its owned inference
/// service. Other installed local models remain subject to their separate,
/// conservative Compatibility admission policy.
enum QualifiedLocalModelHostAdmissionPolicy {
    static let minimumPhysicalMemoryBytes = UInt64(48) * 1_073_741_824

    static func validate(
        selection: ModelSelection,
        physicalMemoryBytes: UInt64
    ) throws {
        guard selection.isReleaseQualifiedLocalQwen else { return }
        guard physicalMemoryBytes >= minimumPhysicalMemoryBytes else {
            throw QualifiedLocalModelHostAdmissionError.insufficientPhysicalMemory(
                requiredBytes: minimumPhysicalMemoryBytes,
                availableBytes: physicalMemoryBytes
            )
        }
    }
}

/// Caller-owned DSH session identities carry only the selected performance
/// profile name and random session entropy. They contain no prompt, model,
/// provider, filesystem, or credential data. The reviewed host plugin resolves
/// the profile through `PerformanceProfile.runtimeCatalogJSON` and applies its
/// max-output cap at every agent request boundary.
enum PerformanceSessionIdentity {
    private static let prefix = "local-harness-performance-v1"

    static func make(
        profile: PerformanceProfile,
        uuid: UUID = UUID()
    ) -> HarnessSessionID {
        HarnessSessionID("\(prefix)-\(profile.rawValue)-\(uuid.uuidString.lowercased())")
    }

    static func profile(from sessionID: HarnessSessionID) -> PerformanceProfile? {
        let parts = sessionID.rawValue.split(separator: "-", omittingEmptySubsequences: false)
        // local-harness-performance-v1-<profile>-<canonical UUID: five parts>
        guard parts.count == 10,
              parts[0] == "local",
              parts[1] == "harness",
              parts[2] == "performance",
              parts[3] == "v1",
              let profile = PerformanceProfile(rawValue: String(parts[4])),
              UUID(uuidString: parts[5...].joined(separator: "-")) != nil else {
            return nil
        }
        return profile
    }
}

/// Versioned selection persisted as the default for newly created tasks.
struct ModelSelection: Codable, Hashable, Sendable {
    static let currentSchemaVersion = 1
    /// The model tag shipped by older private Fulmar builds. It remains a
    /// valid, explicit Compatibility-model selection; upgrades must never
    /// reinterpret it as a request for different model weights.
    static let legacyHermesModel = ModelID("qwen3.8:27b-hermes")

    let schemaVersion: Int
    var route: ModelRoute
    var reasoningEffort: String?
    var performanceProfile: PerformanceProfile

    init(
        route: ModelRoute,
        reasoningEffort: String? = nil,
        performanceProfile: PerformanceProfile = .balanced
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.route = route
        if Self.requiresCompatibilityProfile(route) {
            self.reasoningEffort = nil
            self.performanceProfile = .compatibility
        } else {
            self.reasoningEffort = reasoningEffort
            self.performanceProfile = performanceProfile
        }
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case route
        case reasoningEffort
        case performanceProfile
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == Self.currentSchemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported model selection schema version \(version)."
            )
        }
        schemaVersion = version
        route = try container.decode(ModelRoute.self, forKey: .route)
        let decodedEffort = try container.decodeIfPresent(String.self, forKey: .reasoningEffort)
        let decodedProfile = try container.decode(PerformanceProfile.self, forKey: .performanceProfile)
        if Self.requiresCompatibilityProfile(route) {
            reasoningEffort = nil
            performanceProfile = .compatibility
        } else {
            reasoningEffort = decodedEffort
            performanceProfile = decodedProfile
        }
    }

    var isReleaseQualifiedLocalQwen: Bool {
        route.provider == BuiltInProviderDescriptors.ollama.id
            && route.model == BuiltInProviderDescriptors.qwenLocalModel.id
    }

    var isLocalCompatibilityRoute: Bool { Self.requiresCompatibilityProfile(route) }

    var effectivePerformanceSettings: ModelPerformanceSettings {
        isLocalCompatibilityRoute
            ? .compatibilityLocalModel
            : performanceProfile.settingsFor48GBAppleSilicon
    }

    private static func requiresCompatibilityProfile(_ route: ModelRoute) -> Bool {
        route.provider == BuiltInProviderDescriptors.ollama.id
            && route.model != BuiltInProviderDescriptors.qwenLocalModel.id
    }

    static let defaultLocal = ModelSelection(
        route: ModelRoute(provider: BuiltInProviderDescriptors.ollama.id, model: BuiltInProviderDescriptors.qwenLocalModel.id),
        performanceProfile: .balanced
    )
}

/// Root of the typed model preferences document. It remains separate from general
/// UI preferences so provider selection can later move to DSH without another
/// legacy string migration.
struct ModelProviderSettings: Codable, Hashable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    var defaultSelection: ModelSelection

    init(defaultSelection: ModelSelection = .defaultLocal) {
        schemaVersion = Self.currentSchemaVersion
        self.defaultSelection = defaultSelection
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case defaultSelection
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == Self.currentSchemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported model provider settings schema version \(version)."
            )
        }
        schemaVersion = version
        defaultSelection = try container.decode(ModelSelection.self, forKey: .defaultSelection)
    }
}

enum ModelProviderSettingsSource: Equatable, Sendable {
    case stored
    case migratedLegacy(model: ModelID)
    case initializedDefaults
}

struct ModelProviderSettingsLoadResult: Equatable, Sendable {
    let settings: ModelProviderSettings
    let source: ModelProviderSettingsSource
}

enum ModelProviderSettingsStoreError: Error, Equatable, LocalizedError {
    case invalidStoredType

    var errorDescription: String? {
        switch self {
        case .invalidStoredType: return "Stored model provider settings are not a valid data document."
        }
    }
}

/// Small persistence seam with an injectable UserDefaults instance for deterministic
/// migration and testing. Corrupt or future-version data throws and is never silently
/// overwritten.
final class ModelProviderSettingsStore {
    static let settingsKey = "modelProviderSettings"
    static let legacySelectedLocalModelKey = "selectedLocalModel"

    private let defaults: UserDefaults
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        decoder = JSONDecoder()
    }

    func load() throws -> ModelProviderSettings? {
        guard let stored = defaults.object(forKey: Self.settingsKey) else { return nil }
        guard let data = stored as? Data else { throw ModelProviderSettingsStoreError.invalidStoredType }
        return try decoder.decode(ModelProviderSettings.self, from: data)
    }

    func save(_ settings: ModelProviderSettings) throws {
        defaults.set(try encoder.encode(settings), forKey: Self.settingsKey)
    }

    /// Loads current settings or performs the one-way, non-destructive migration
    /// from PreferencesStore's legacy local-model string. The old key is retained
    /// for downgrade compatibility until the UI cutover is complete.
    @discardableResult
    func loadOrMigrate() throws -> ModelProviderSettingsLoadResult {
        if let stored = try load() {
            // `ModelSelection` decoding already normalizes every non-qualified
            // Ollama route to the conservative Compatibility profile with no
            // reasoning field. Keep the exact stored route and bytes: changing
            // an explicit Hermes selection to the qualified default would ask
            // Ollama for different weights without the user's consent.
            return ModelProviderSettingsLoadResult(settings: stored, source: .stored)
        }

        let legacy = defaults.string(forKey: Self.legacySelectedLocalModelKey)
        let meaningfulLegacy = legacy.flatMap { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            // PreferencesStore registers this shipped value process-wide. A
            // suite-specific UserDefaults can therefore see it even when no
            // user-authored legacy value exists; treating that exact value as
            // the new typed default is lossless and keeps migration deterministic.
            guard trimmed != ModelSelection.defaultLocal.route.model.rawValue else { return nil }
            return value
        }

        let result: ModelProviderSettingsLoadResult
        if let meaningfulLegacy {
            let legacyModel = ModelID(meaningfulLegacy)
            let selection = ModelSelection(
                route: ModelRoute(provider: BuiltInProviderDescriptors.ollama.id, model: legacyModel),
                performanceProfile: .balanced
            )
            let settings = ModelProviderSettings(defaultSelection: selection)
            result = ModelProviderSettingsLoadResult(settings: settings, source: .migratedLegacy(model: legacyModel))
        } else {
            result = ModelProviderSettingsLoadResult(settings: ModelProviderSettings(), source: .initializedDefaults)
        }
        try save(result.settings)
        return result
    }
}
