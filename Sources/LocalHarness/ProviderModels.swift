import Foundation

/// Opaque identifier for a Harness provider route.
///
/// Route identifiers are deliberately not parsed. DSH and compatible providers may
/// legitimately use punctuation such as `/` and `:`, and the provider and model
/// components must remain separate throughout the app.
struct ProviderID: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        rawValue = try HarnessCatalogWirePolicy.opaqueIdentifier(
            container.decode(String.self),
            codingPath: decoder.codingPath,
            label: "provider identifier"
        )
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    var description: String { rawValue }
}

/// Opaque identifier owned by a provider route.
struct ModelID: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        rawValue = try HarnessCatalogWirePolicy.opaqueIdentifier(
            container.decode(String.self),
            codingPath: decoder.codingPath,
            label: "model identifier"
        )
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    var description: String { rawValue }
}

/// Exact provider/model route used for a request.
struct ModelRoute: Codable, Hashable, Sendable {
    var provider: ProviderID
    var model: ModelID
}

/// Where user content leaves the app when a provider is selected.
enum DataBoundary: String, Codable, CaseIterable, Hashable, Sendable {
    /// Inference is performed on this Mac through loopback-only services.
    case onDevice
    /// Inference is performed by a service elsewhere on the user's private network.
    case localNetwork
    /// Inference is performed by a remote internet service.
    case cloud

    var requiresExplicitConsent: Bool { self != .onDevice }
    var isExternalToThisMac: Bool { self != .onDevice }

    var displayName: String {
        switch self {
        case .onDevice: return "On this Mac"
        case .localNetwork: return "Local network"
        case .cloud: return "Cloud"
        }
    }
}

/// Stable credential-store reference. This type can name a secret but can never
/// contain its value, keeping provider configuration safe to serialize and log.
struct CredentialReference: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    var description: String { rawValue }
}

/// Wire protocol understood by the bundled generic DSH adapter. Kept opaque so a
/// future adapter protocol can be represented without an app update.
struct ProviderWireProtocol: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    var description: String { rawValue }

    static let openAICompletions = ProviderWireProtocol("openai-completions")
    static let openAIResponses = ProviderWireProtocol("openai-responses")
    static let anthropicMessages = ProviderWireProtocol("anthropic-messages")
}

enum ProviderAdapterKind: String, Codable, Hashable, Sendable {
    case deepSeekOfficial
    case piAI
}

enum ModelInputModality: String, Codable, CaseIterable, Hashable, Sendable {
    case text
    case image
    case audio
    case video
}

/// Three-state support avoids claiming a capability that a provider did not report.
enum CapabilitySupport: String, Codable, Hashable, Sendable {
    case unknown
    case unsupported
    case supported
}

struct ReasoningEffortView: Codable, Hashable, Sendable, Identifiable {
    let id: String
    let displayName: String
    let detail: String?

    init(id: String, displayName: String, detail: String? = nil) {
        self.id = id
        self.displayName = displayName
        self.detail = detail
    }
}

/// Provider-reported model capabilities. Optional capacities mean unknown rather
/// than unlimited; callers must not infer support from a missing value.
struct ModelCapabilities: Codable, Hashable, Sendable {
    var inputModalities: [ModelInputModality]
    var toolUse: CapabilitySupport
    var reasoning: CapabilitySupport
    var contextWindowTokens: Int?
    var maxOutputTokens: Int?
    var reasoningEfforts: [ReasoningEffortView]
    var defaultReasoningEffort: String?

    init(
        inputModalities: [ModelInputModality] = [.text],
        toolUse: CapabilitySupport = .unknown,
        reasoning: CapabilitySupport = .unknown,
        contextWindowTokens: Int? = nil,
        maxOutputTokens: Int? = nil,
        reasoningEfforts: [ReasoningEffortView] = [],
        defaultReasoningEffort: String? = nil
    ) {
        self.inputModalities = Self.uniqued(inputModalities)
        self.toolUse = toolUse
        self.reasoning = reasoning
        self.contextWindowTokens = contextWindowTokens
        self.maxOutputTokens = maxOutputTokens
        self.reasoningEfforts = reasoningEfforts
        self.defaultReasoningEffort = defaultReasoningEffort.flatMap { candidate in
            reasoningEfforts.filter { $0.id == candidate }.count == 1 ? candidate : nil
        }
    }

    private static func uniqued(_ modalities: [ModelInputModality]) -> [ModelInputModality] {
        var seen = Set<ModelInputModality>()
        return modalities.filter { seen.insert($0).inserted }
    }
}

struct ModelView: Codable, Hashable, Sendable, Identifiable {
    let id: ModelID
    let displayName: String
    let detail: String?
    let capabilities: ModelCapabilities

    init(id: ModelID, displayName: String, detail: String? = nil, capabilities: ModelCapabilities = .init()) {
        self.id = id
        self.displayName = displayName
        self.detail = detail
        self.capabilities = capabilities
    }
}

enum ProviderConfigurationState: String, Codable, Hashable, Sendable {
    case dormant
    case needsCredential
    case ready
    case unavailable
}

enum ProviderAuthenticationMode: String, Codable, Hashable, Sendable {
    case referencedCredential
    case providerNative
    case explicitlyUnauthenticated
}

/// Non-secret, serializable facts required to present and configure a provider.
struct ProviderDescriptor: Codable, Hashable, Sendable, Identifiable {
    let id: ProviderID
    let displayName: String
    let settingsNamespace: String
    let settingsPath: [String]
    let adapterKind: ProviderAdapterKind
    let wireProtocol: ProviderWireProtocol?
    let defaultBaseURL: URL?
    let boundary: DataBoundary
    let credentialReference: CredentialReference?
    /// Exact non-secret authentication semantics projected from DSH settings.
    /// A nil credential reference alone is not enough: it may mean either
    /// provider-native discovery or an explicit private-endpoint no-auth route.
    let explicitlyUnauthenticated: Bool
    /// True only when the raw DSH profile is within the exact lossless subset
    /// Fulmar's native editor can round-trip. Advanced or externally-authored
    /// profiles remain usable, but are edited in Harness settings so Fulmar
    /// cannot silently discard fields it does not expose.
    let supportsNativeProfileEditing: Bool

    init(
        id: ProviderID,
        displayName: String,
        settingsNamespace: String,
        settingsPath: [String],
        adapterKind: ProviderAdapterKind,
        wireProtocol: ProviderWireProtocol?,
        defaultBaseURL: URL?,
        boundary: DataBoundary,
        credentialReference: CredentialReference?,
        explicitlyUnauthenticated: Bool = false,
        supportsNativeProfileEditing: Bool = false
    ) {
        self.id = id
        self.displayName = displayName
        self.settingsNamespace = settingsNamespace
        self.settingsPath = settingsPath
        self.adapterKind = adapterKind
        self.wireProtocol = wireProtocol
        self.defaultBaseURL = defaultBaseURL
        self.boundary = boundary
        self.credentialReference = credentialReference
        self.explicitlyUnauthenticated = explicitlyUnauthenticated
        self.supportsNativeProfileEditing = supportsNativeProfileEditing
    }

    var authenticationMode: ProviderAuthenticationMode {
        if explicitlyUnauthenticated { return .explicitlyUnauthenticated }
        return credentialReference == nil ? .providerNative : .referencedCredential
    }

    private enum CodingKeys: String, CodingKey {
        case id, displayName, settingsNamespace, settingsPath, adapterKind
        case wireProtocol, defaultBaseURL, boundary, credentialReference
        case explicitlyUnauthenticated, supportsNativeProfileEditing
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(ProviderID.self, forKey: .id)
        displayName = try container.decode(String.self, forKey: .displayName)
        settingsNamespace = try container.decode(String.self, forKey: .settingsNamespace)
        settingsPath = try container.decode([String].self, forKey: .settingsPath)
        adapterKind = try container.decode(ProviderAdapterKind.self, forKey: .adapterKind)
        wireProtocol = try container.decodeIfPresent(ProviderWireProtocol.self, forKey: .wireProtocol)
        defaultBaseURL = try container.decodeIfPresent(URL.self, forKey: .defaultBaseURL)
        boundary = try container.decode(DataBoundary.self, forKey: .boundary)
        credentialReference = try container.decodeIfPresent(CredentialReference.self, forKey: .credentialReference)
        explicitlyUnauthenticated = try container.decodeIfPresent(
            Bool.self,
            forKey: .explicitlyUnauthenticated
        ) ?? false
        supportsNativeProfileEditing = try container.decodeIfPresent(
            Bool.self,
            forKey: .supportsNativeProfileEditing
        ) ?? false
    }

    var requiresExplicitConsent: Bool { boundary.requiresExplicitConsent }
}

/// Current provider-directory view consumed by selectors and diagnostics.
struct ProviderView: Codable, Hashable, Sendable, Identifiable {
    let descriptor: ProviderDescriptor
    var configurationState: ProviderConfigurationState
    var models: [ModelView]
    var failureMessage: String?

    var id: ProviderID { descriptor.id }
    var displayName: String { descriptor.displayName }
    var boundary: DataBoundary { descriptor.boundary }
}

/// Normalized network origin attached to an explicit consent grant.
struct ProviderEndpointOrigin: Codable, Hashable, Sendable {
    let scheme: String
    let host: String
    let port: Int

    init?(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil,
              components.password == nil,
              let rawScheme = components.scheme,
              let rawHost = components.host,
              !rawHost.isEmpty,
              components.fragment == nil else { return nil }
        let scheme = rawScheme.lowercased()
        guard scheme == "http" || scheme == "https" else { return nil }
        self.scheme = scheme
        host = rawHost.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let candidatePort = components.port ?? (scheme == "https" ? 443 : 80)
        guard !host.isEmpty, (1...65_535).contains(candidatePort) else { return nil }
        port = candidatePort
    }

    var displayName: String {
        let defaultPort = scheme == "https" ? 443 : 80
        return port == defaultPort ? "\(scheme)://\(host)" : "\(scheme)://\(host):\(port)"
    }
}

struct ProviderConsentGrant: Codable, Hashable, Sendable {
    let provider: ProviderID
    let boundary: DataBoundary
    let origin: ProviderEndpointOrigin?
    /// Stable Keychain reference authorized for this exact endpoint. This is a
    /// name only; the credential value is never serialized into consent state.
    let credentialReference: CredentialReference?
    /// Prevents an old consent from silently changing between provider-native
    /// credential discovery and explicit no-auth at the same network origin.
    let explicitlyUnauthenticated: Bool

    init(
        provider: ProviderID,
        boundary: DataBoundary,
        baseURL: URL?,
        credentialReference: CredentialReference? = nil,
        explicitlyUnauthenticated: Bool = false
    ) {
        self.provider = provider
        self.boundary = boundary
        origin = baseURL.flatMap(ProviderEndpointOrigin.init(url:))
        self.credentialReference = credentialReference
        self.explicitlyUnauthenticated = explicitlyUnauthenticated
    }

    init(for descriptor: ProviderDescriptor) {
        self.init(
            provider: descriptor.id,
            boundary: descriptor.boundary,
            baseURL: descriptor.defaultBaseURL,
            credentialReference: descriptor.credentialReference,
            explicitlyUnauthenticated: descriptor.explicitlyUnauthenticated
        )
    }

    func permits(_ descriptor: ProviderDescriptor) -> Bool {
        guard provider == descriptor.id,
              boundary == descriptor.boundary,
              credentialReference == descriptor.credentialReference,
              explicitlyUnauthenticated == descriptor.explicitlyUnauthenticated else { return false }
        if descriptor.boundary == .onDevice { return true }
        guard let expectedOrigin = descriptor.defaultBaseURL.flatMap(ProviderEndpointOrigin.init(url:)) else {
            // External consent must bind to a known HTTP(S) origin. A provider whose
            // endpoint is unresolved cannot be approved accidentally with a nil origin.
            return false
        }
        return origin == expectedOrigin
    }
}

enum ProviderConsentPolicy {
    static func canSendData(to descriptor: ProviderDescriptor, grants: Set<ProviderConsentGrant>) -> Bool {
        guard descriptor.requiresExplicitConsent else { return true }
        return grants.contains { $0.permits(descriptor) }
    }
}

enum BuiltInProviderDescriptors {
    static let ollama = ProviderDescriptor(
        id: ProviderID("ollama"),
        displayName: "Ollama (Local)",
        settingsNamespace: "llm-pi-ai",
        settingsPath: ["providers", "ollama"],
        adapterKind: .piAI,
        wireProtocol: .openAICompletions,
        // Assigned only after HarnessController starts and verifies an exact
        // app-owned Ollama listener for this launch.
        defaultBaseURL: nil,
        boundary: .onDevice,
        credentialReference: CredentialReference("OLLAMA_API_KEY")
    )

    static let deepSeekOfficial = ProviderDescriptor(
        id: ProviderID("deepseek-official"),
        displayName: "DeepSeek",
        settingsNamespace: "llm-deepseek",
        settingsPath: [],
        adapterKind: .deepSeekOfficial,
        wireProtocol: nil,
        defaultBaseURL: URL(string: "https://api.deepseek.com")!,
        boundary: .cloud,
        credentialReference: CredentialReference("DEEPSEEK_API_KEY")
    )

    static let openAI = ProviderDescriptor(
        id: ProviderID("openai"),
        displayName: "OpenAI",
        settingsNamespace: "llm-pi-ai",
        settingsPath: ["providers", "openai"],
        adapterKind: .piAI,
        wireProtocol: nil,
        defaultBaseURL: URL(string: "https://api.openai.com/v1")!,
        boundary: .cloud,
        credentialReference: CredentialReference("OPENAI_API_KEY")
    )

    static let anthropic = ProviderDescriptor(
        id: ProviderID("anthropic"),
        displayName: "Anthropic",
        settingsNamespace: "llm-pi-ai",
        settingsPath: ["providers", "anthropic"],
        adapterKind: .piAI,
        wireProtocol: nil,
        defaultBaseURL: URL(string: "https://api.anthropic.com")!,
        boundary: .cloud,
        credentialReference: CredentialReference("ANTHROPIC_API_KEY")
    )

    /// Built-in routes in stable presentation order. Provider model catalogs remain
    /// owned by DSH and are intentionally not frozen into the app.
    static let all: [ProviderDescriptor] = [ollama, deepSeekOfficial, openAI, anthropic]

    static let qwenLocalModel = ModelView(
        id: ModelID("qwen3.8:27b-mlx"),
        displayName: "Qwen 3.8 27B MLX (Local)",
        capabilities: ModelCapabilities(
            inputModalities: [.text],
            toolUse: .supported,
            reasoning: .supported,
            contextWindowTokens: 65_536,
            maxOutputTokens: 16_384,
            reasoningEfforts: [
                ReasoningEffortView(id: "off", displayName: "Off"),
                ReasoningEffortView(id: "high", displayName: "High")
            ]
        )
    )

    /// Immutable manifest identity returned by Ollama's `/api/tags` endpoint
    /// for the release-qualified official model. Ollama's wire value is the
    /// raw 64-character lowercase SHA-256 hex digest; it does not include an
    /// algorithm prefix. A mutable tag or compatible capability report alone
    /// must never unlock the 48 GB Qwen presets.
    static let qwenLocalModelManifestDigest = "5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e"

    /// Declares an OpenAI-compatible endpoint without ever accepting a credential
    /// value. The caller must classify its boundary explicitly.
    static func openAICompatible(
        id: ProviderID,
        displayName: String,
        baseURL: URL,
        boundary: DataBoundary,
        credentialReference: CredentialReference? = nil,
        wireProtocol: ProviderWireProtocol = .openAICompletions,
        explicitlyUnauthenticated: Bool = false,
        supportsNativeProfileEditing: Bool = false
    ) -> ProviderDescriptor {
        ProviderDescriptor(
            id: id,
            displayName: displayName,
            settingsNamespace: "llm-pi-ai",
            settingsPath: ["providers", id.rawValue],
            adapterKind: .piAI,
            wireProtocol: wireProtocol,
            defaultBaseURL: baseURL,
            boundary: boundary,
            credentialReference: credentialReference,
            explicitlyUnauthenticated: explicitlyUnauthenticated,
            supportsNativeProfileEditing: supportsNativeProfileEditing
        )
    }
}
