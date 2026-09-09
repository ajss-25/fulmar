import Foundation

// MARK: - JSON and wire-domain values

/// A lossless-enough, Sendable JSON value used where DSH deliberately exposes
/// adapter-owned schemas, settings, and error details. Credential values are
/// never returned by DSH and this type is intentionally not printable.
enum HarnessJSONValue: Codable, Equatable, Hashable, Sendable {
    case null
    case bool(Bool)
    case integer(Int64)
    case number(Double)
    case string(String)
    case array([HarnessJSONValue])
    case object([String: HarnessJSONValue])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([HarnessJSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: HarnessJSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value.")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    var objectValue: [String: HarnessJSONValue]? {
        guard case .object(let value) = self else { return nil }
        return value
    }

    var stringValue: String? {
        guard case .string(let value) = self else { return nil }
        return value
    }
}

struct HarnessSessionID: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    let rawValue: String

    init(rawValue: String) { self.rawValue = rawValue }
    init(_ rawValue: String) { self.rawValue = rawValue }

    init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    var description: String { rawValue }
}

struct HarnessProviderDirectory: Codable, Equatable, Sendable {
    let providers: [HarnessProviderDirectoryEntry]

    init(providers: [HarnessProviderDirectoryEntry]) {
        self.providers = providers
    }

    private enum CodingKeys: String, CodingKey { case providers }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var providers = try container.nestedUnkeyedContainer(forKey: .providers)
        self.providers = try HarnessCatalogWirePolicy.decodeBoundedArray(
            HarnessProviderDirectoryEntry.self,
            from: &providers,
            maximumCount: HarnessCatalogWirePolicy.maximumProviders,
            label: "provider directory"
        )
    }
}

struct HarnessProviderDirectoryEntry: Codable, Equatable, Sendable {
    let provider: ProviderID
    let displayName: String
    let settingsNs: String
    let settingsPath: [String]
    let active: Bool
    let declared: Bool?

    init(
        provider: ProviderID,
        displayName: String,
        settingsNs: String,
        settingsPath: [String],
        active: Bool,
        declared: Bool?
    ) {
        self.provider = provider
        self.displayName = displayName
        self.settingsNs = settingsNs
        self.settingsPath = settingsPath
        self.active = active
        self.declared = declared
    }

    private enum CodingKeys: String, CodingKey {
        case provider, displayName, settingsNs, settingsPath, active, declared
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let providerValue = try container.decode(String.self, forKey: .provider)
        provider = ProviderID(try HarnessCatalogWirePolicy.opaqueIdentifier(
            providerValue,
            codingPath: container.codingPath + [CodingKeys.provider],
            label: "provider identifier"
        ))
        displayName = HarnessCatalogWirePolicy.displayName(
            try container.decodeIfPresent(String.self, forKey: .displayName) ?? "",
            fallback: provider.rawValue,
            genericFallback: "Unnamed provider"
        )
        settingsNs = try HarnessCatalogWirePolicy.settingsNamespace(
            container.decode(String.self, forKey: .settingsNs),
            codingPath: container.codingPath + [CodingKeys.settingsNs]
        )
        var pathValues = try container.nestedUnkeyedContainer(forKey: .settingsPath)
        settingsPath = try HarnessCatalogWirePolicy.decodeSettingsPath(from: &pathValues)
        active = try container.decode(Bool.self, forKey: .active)
        declared = try container.decodeIfPresent(Bool.self, forKey: .declared)
    }
}

struct HarnessModelCatalog: Codable, Equatable, Sendable {
    let groups: [HarnessModelProviderGroup]
    let failures: [HarnessModelCatalogFailure]

    init(groups: [HarnessModelProviderGroup], failures: [HarnessModelCatalogFailure]) {
        self.groups = groups
        self.failures = failures
    }

    private enum CodingKeys: String, CodingKey { case groups, failures }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var groupValues = try container.nestedUnkeyedContainer(forKey: .groups)
        groups = try HarnessCatalogWirePolicy.decodeProviderGroups(from: &groupValues)
        var failureValues = try container.nestedUnkeyedContainer(forKey: .failures)
        failures = try HarnessCatalogWirePolicy.decodeBoundedArray(
            HarnessModelCatalogFailure.self,
            from: &failureValues,
            maximumCount: HarnessCatalogWirePolicy.maximumFailures,
            label: "provider failures"
        )
    }
}

struct HarnessModelProviderGroup: Codable, Equatable, Sendable {
    let id: ProviderID
    let name: String
    let models: [HarnessModelCatalogEntry]

    init(id: ProviderID, name: String, models: [HarnessModelCatalogEntry]) {
        self.id = id
        self.name = name
        self.models = models
    }

    private enum CodingKeys: String, CodingKey { case id, name, models }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let idValue = try container.decode(String.self, forKey: .id)
        id = ProviderID(try HarnessCatalogWirePolicy.opaqueIdentifier(
            idValue,
            codingPath: container.codingPath + [CodingKeys.id],
            label: "provider identifier"
        ))
        name = HarnessCatalogWirePolicy.displayName(
            try container.decodeIfPresent(String.self, forKey: .name) ?? "",
            fallback: id.rawValue,
            genericFallback: "Unnamed provider"
        )
        var modelValues = try container.nestedUnkeyedContainer(forKey: .models)
        models = try HarnessCatalogWirePolicy.decodeBoundedArray(
            HarnessModelCatalogEntry.self,
            from: &modelValues,
            maximumCount: HarnessCatalogWirePolicy.maximumModelsPerGroup,
            label: "models in one provider group"
        )
    }
}

struct HarnessModelCatalogEntry: Codable, Equatable, Sendable {
    let id: ModelID
    let name: String
    let description: String?
    let reasoning: HarnessModelReasoning?

    init(id: ModelID, name: String, description: String?, reasoning: HarnessModelReasoning?) {
        self.id = id
        self.name = name
        self.description = description
        self.reasoning = reasoning
    }

    private enum CodingKeys: String, CodingKey { case id, name, description, reasoning }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let idValue = try container.decode(String.self, forKey: .id)
        id = ModelID(try HarnessCatalogWirePolicy.opaqueIdentifier(
            idValue,
            codingPath: container.codingPath + [CodingKeys.id],
            label: "model identifier"
        ))
        name = HarnessCatalogWirePolicy.displayName(
            try container.decodeIfPresent(String.self, forKey: .name) ?? "",
            fallback: id.rawValue,
            genericFallback: "Unnamed model"
        )
        description = HarnessCatalogWirePolicy.detail(
            try container.decodeIfPresent(String.self, forKey: .description)
        )
        reasoning = try container.decodeIfPresent(HarnessModelReasoning.self, forKey: .reasoning)
    }
}

struct HarnessModelReasoning: Codable, Equatable, Sendable {
    let efforts: [HarnessReasoningEffort]
    let defaultEffort: String?

    init(efforts: [HarnessReasoningEffort], defaultEffort: String?) {
        self.efforts = efforts
        self.defaultEffort = defaultEffort
    }

    private enum CodingKeys: String, CodingKey { case efforts, defaultEffort }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var effortValues = try container.nestedUnkeyedContainer(forKey: .efforts)
        efforts = try HarnessCatalogWirePolicy.decodeBoundedArray(
            HarnessReasoningEffort.self,
            from: &effortValues,
            maximumCount: HarnessCatalogWirePolicy.maximumReasoningEfforts,
            label: "reasoning efforts"
        )
        defaultEffort = try HarnessCatalogWirePolicy.optionalOpaqueIdentifier(
            container.decodeIfPresent(String.self, forKey: .defaultEffort),
            codingPath: container.codingPath + [CodingKeys.defaultEffort],
            label: "default reasoning-effort identifier"
        )
    }
}

struct HarnessReasoningEffort: Codable, Equatable, Sendable {
    let id: String
    let name: String
    let description: String?

    init(id: String, name: String, description: String? = nil) {
        self.id = id
        self.name = name
        self.description = description
    }

    private enum CodingKeys: String, CodingKey { case id, name, description }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try HarnessCatalogWirePolicy.opaqueIdentifier(
            container.decode(String.self, forKey: .id),
            codingPath: container.codingPath + [CodingKeys.id],
            label: "reasoning-effort identifier"
        )
        name = HarnessCatalogWirePolicy.displayName(
            try container.decodeIfPresent(String.self, forKey: .name) ?? "",
            fallback: id,
            genericFallback: "Reasoning option"
        )
        description = HarnessCatalogWirePolicy.detail(
            try container.decodeIfPresent(String.self, forKey: .description)
        )
    }
}

struct HarnessModelCatalogFailure: Codable, Equatable, Sendable {
    let id: ProviderID
    let name: String
    let message: String

    init(id: ProviderID, name: String, message: String) {
        self.id = id
        self.name = name
        self.message = message
    }

    private enum CodingKeys: String, CodingKey { case id, name, message }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let idValue = try container.decode(String.self, forKey: .id)
        id = ProviderID(try HarnessCatalogWirePolicy.opaqueIdentifier(
            idValue,
            codingPath: container.codingPath + [CodingKeys.id],
            label: "provider identifier"
        ))
        name = HarnessCatalogWirePolicy.displayName(
            try container.decodeIfPresent(String.self, forKey: .name) ?? "",
            fallback: id.rawValue,
            genericFallback: "Unnamed provider"
        )
        message = HarnessCatalogWirePolicy.failureMessage(
            try container.decodeIfPresent(String.self, forKey: .message) ?? ""
        )
    }
}

struct HarnessWireModelSelection: Codable, Equatable, Sendable {
    let provider: ProviderID
    let model: ModelID
    let reasoningEffort: String?

    init(route: ModelRoute, reasoningEffort: String? = nil) {
        provider = route.provider
        model = route.model
        self.reasoningEffort = reasoningEffort
    }

    init(provider: ProviderID, model: ModelID, reasoningEffort: String? = nil) {
        self.provider = provider
        self.model = model
        self.reasoningEffort = reasoningEffort
    }

    private enum CodingKeys: String, CodingKey { case provider, model, reasoningEffort }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        provider = ProviderID(try HarnessCatalogWirePolicy.opaqueIdentifier(
            container.decode(String.self, forKey: .provider),
            codingPath: container.codingPath + [CodingKeys.provider],
            label: "selected provider identifier"
        ))
        model = ModelID(try HarnessCatalogWirePolicy.opaqueIdentifier(
            container.decode(String.self, forKey: .model),
            codingPath: container.codingPath + [CodingKeys.model],
            label: "selected model identifier"
        ))
        reasoningEffort = try HarnessCatalogWirePolicy.optionalOpaqueIdentifier(
            container.decodeIfPresent(String.self, forKey: .reasoningEffort),
            codingPath: container.codingPath + [CodingKeys.reasoningEffort],
            label: "selected reasoning-effort identifier"
        )
    }

    var route: ModelRoute { ModelRoute(provider: provider, model: model) }
}

struct HarnessSessionModels: Codable, Equatable, Sendable {
    let current: HarnessWireModelSelection
    let routable: Bool
    let groups: [HarnessModelProviderGroup]
    let failures: [HarnessModelCatalogFailure]

    init(
        current: HarnessWireModelSelection,
        routable: Bool,
        groups: [HarnessModelProviderGroup],
        failures: [HarnessModelCatalogFailure]
    ) {
        self.current = current
        self.routable = routable
        self.groups = groups
        self.failures = failures
    }

    private enum CodingKeys: String, CodingKey { case current, routable, groups, failures }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        current = try container.decode(HarnessWireModelSelection.self, forKey: .current)
        routable = try container.decode(Bool.self, forKey: .routable)
        var groupValues = try container.nestedUnkeyedContainer(forKey: .groups)
        groups = try HarnessCatalogWirePolicy.decodeProviderGroups(from: &groupValues)
        var failureValues = try container.nestedUnkeyedContainer(forKey: .failures)
        failures = try HarnessCatalogWirePolicy.decodeBoundedArray(
            HarnessModelCatalogFailure.self,
            from: &failureValues,
            maximumCount: HarnessCatalogWirePolicy.maximumFailures,
            label: "provider failures"
        )
    }
}

struct HarnessSessionCreateRequest: Codable, Equatable, Sendable {
    let workspaceId: String?
    let cwd: String?
    let sessionId: HarnessSessionID?
    let agentPreset: String?
    let reuseWorkspaceBlank: Bool?

    init(
        workspaceId: String? = nil,
        cwd: String? = nil,
        sessionId: HarnessSessionID? = nil,
        agentPreset: String? = nil,
        reuseWorkspaceBlank: Bool? = nil
    ) {
        self.workspaceId = workspaceId
        self.cwd = cwd
        self.sessionId = sessionId
        self.agentPreset = agentPreset
        self.reuseWorkspaceBlank = reuseWorkspaceBlank == true ? true : nil
    }
}

struct HarnessSessionCreateResult: Codable, Equatable, Sendable {
    let sessionId: HarnessSessionID
    let agentPreset: String?
}

struct HarnessSessionRenameResult: Codable, Equatable, Sendable {
    let title: String
    let seq: Int
}

struct HarnessSessionForkResult: Codable, Equatable, Sendable {
    let sessionId: HarnessSessionID
}

struct HarnessArchivedSessionsResult: Codable, Equatable, Sendable {
    let archivedSessionIds: [HarnessSessionID]
}

struct HarnessSessionProjectionBlock: Codable, Equatable, Sendable {
    let asOfSeq: Int
    let values: [String: HarnessJSONValue]
}

struct HarnessSessionSummary: Codable, Equatable, Sendable {
    let sessionId: HarnessSessionID
    let updatedAt: Double
    let running: Bool
    let blank: Bool
    let parentSessionId: HarnessSessionID?
    let origin: String?
    let cwd: String?
    let agentPreset: String?
    let projections: HarnessSessionProjectionBlock?
}

struct HarnessSessionList: Codable, Equatable, Sendable {
    let items: [HarnessSessionSummary]
}

struct HarnessSessionSearchItem: Codable, Equatable, Sendable {
    let sessionId: HarnessSessionID
    let snippet: String
}

struct HarnessSessionSearchResult: Codable, Equatable, Sendable {
    let items: [HarnessSessionSearchItem]
    let hasMore: Bool
}

struct HarnessSessionEventRecord: Codable, Equatable, Sendable {
    let type: String
    let seq: Int
    let time: Double
    let data: HarnessJSONValue
    let sourceEventSeqs: [Int]?
    let surfaceOp: HarnessJSONValue?
    let ignorable: Bool?
}

struct HarnessSessionHistoryEntry: Codable, Equatable, Sendable {
    let event: HarnessSessionEventRecord
    let view: HarnessJSONValue?
}

struct HarnessSessionHistoryPage: Codable, Equatable, Sendable {
    let events: [HarnessSessionHistoryEntry]
    let hasMore: Bool
    let projections: HarnessSessionProjectionBlock?
}

enum HarnessPromptMode: String, Codable, Equatable, Sendable {
    case queue
    case steer
}

enum HarnessImageMediaType: String, Codable, Equatable, Sendable {
    case png = "image/png"
    case jpeg = "image/jpeg"
    case webp = "image/webp"
    case gif = "image/gif"
}

enum HarnessPromptContentPart: Codable, Equatable, Sendable {
    case text(String)
    case image(mediaType: HarnessImageMediaType, data: String, name: String?)

    private enum CodingKeys: String, CodingKey { case type, text, mediaType, data, name }
    private enum Kind: String, Codable { case text, image }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .type) {
        case .text:
            self = .text(try container.decode(String.self, forKey: .text))
        case .image:
            self = .image(
                mediaType: try container.decode(HarnessImageMediaType.self, forKey: .mediaType),
                data: try container.decode(String.self, forKey: .data),
                name: try container.decodeIfPresent(String.self, forKey: .name)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .text(let text):
            try container.encode(Kind.text, forKey: .type)
            try container.encode(text, forKey: .text)
        case .image(let mediaType, let data, let name):
            try container.encode(Kind.image, forKey: .type)
            try container.encode(mediaType, forKey: .mediaType)
            try container.encode(data, forKey: .data)
            try container.encodeIfPresent(name, forKey: .name)
        }
    }
}

struct HarnessPromptResult: Codable, Equatable, Sendable {
    struct Command: Codable, Equatable, Sendable {
        let kind: String
        let text: String?
    }

    let accepted: Bool
    let command: Command?
}

/// The prompt result paired with the exact client RPC identifier that DSH
/// persists on the resulting direct `user/message`. The WebSocket mux uses
/// unrelated server-request identifiers, so callers must correlate turns with
/// this value rather than with the mux envelope.
struct HarnessPromptSubmission: Equatable, Sendable {
    let rpcID: String
    let result: HarnessPromptResult

    var accepted: Bool { result.accepted }
    var command: HarnessPromptResult.Command? { result.command }
}

struct HarnessCancelResult: Codable, Equatable, Sendable {
    let accepted: Bool
}

struct HarnessSettingsDescription: Codable, Equatable, Sendable {
    let writable: Bool
    let hasDocument: Bool
    let namespaces: [HarnessSettingsNamespace]
}

struct HarnessSettingsNamespace: Codable, Equatable, Sendable {
    let ns: String
    let schema: HarnessJSONValue
    let value: HarnessJSONValue
    let base: HarnessJSONValue?
    let user: HarnessJSONValue?
    let applies: HarnessSettingsApplyMode
    let secrets: [HarnessSettingsSecret]
    let revision: Int
}

enum HarnessSettingsApplyMode: String, Codable, Equatable, Sendable {
    case live
    case restart
}

struct HarnessSettingsSecret: Codable, Equatable, Sendable {
    let path: [String]
    let set: Bool
}

enum HarnessSettingsPathOperation: Codable, Equatable, Sendable {
    case set(path: [String], value: HarnessJSONValue)
    case unset(path: [String])

    private enum CodingKeys: String, CodingKey { case op, path, value }
    private enum Operation: String, Codable { case set, unset }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Operation.self, forKey: .op) {
        case .set:
            self = .set(
                path: try container.decode([String].self, forKey: .path),
                value: try container.decode(HarnessJSONValue.self, forKey: .value)
            )
        case .unset:
            self = .unset(path: try container.decode([String].self, forKey: .path))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .set(let path, let value):
            try container.encode(Operation.set, forKey: .op)
            try container.encode(path, forKey: .path)
            try container.encode(value, forKey: .value)
        case .unset(let path):
            try container.encode(Operation.unset, forKey: .op)
            try container.encode(path, forKey: .path)
        }
    }
}

struct HarnessCredentialDescription: Codable, Equatable, Sendable {
    let credentials: [String: HarnessCredentialView]
}

struct HarnessCredentialView: Codable, Equatable, Sendable {
    let configured: Bool
    let source: String?
    let writable: Bool
}

// MARK: - Typed failures

enum HarnessRemoteErrorCode: Equatable, Hashable, Sendable, Codable {
    case badRequest
    case cancelled
    case sessionNotFound
    case modelUnavailable
    case sessionConflict
    case agentBusy
    case attachmentError
    case commandError
    case unknownCommand
    case settingsRejected
    case settingsConflict
    case credentialRejected
    case modelDiscoveryFailed
    case internalError
    case other(String)

    var rawValue: String {
        switch self {
        case .badRequest: return "bad-request"
        case .cancelled: return "cancelled"
        case .sessionNotFound: return "session-not-found"
        case .modelUnavailable: return "model-unavailable"
        case .sessionConflict: return "session-conflict"
        case .agentBusy: return "agent-busy"
        case .attachmentError: return "attachment-error"
        case .commandError: return "command-error"
        case .unknownCommand: return "unknown-command"
        case .settingsRejected: return "settings-rejected"
        case .settingsConflict: return "settings-conflict"
        case .credentialRejected: return "credential-rejected"
        case .modelDiscoveryFailed: return "model-discovery-failed"
        case .internalError: return "internal"
        case .other(let value): return value
        }
    }

    init(rawValue: String) {
        switch rawValue {
        case "bad-request": self = .badRequest
        case "cancelled": self = .cancelled
        case "session-not-found": self = .sessionNotFound
        case "model-unavailable": self = .modelUnavailable
        case "session-conflict": self = .sessionConflict
        case "agent-busy": self = .agentBusy
        case "attachment-error": self = .attachmentError
        case "command-error": self = .commandError
        case "unknown-command": self = .unknownCommand
        case "settings-rejected": self = .settingsRejected
        case "settings-conflict": self = .settingsConflict
        case "credential-rejected": self = .credentialRejected
        case "model-discovery-failed": self = .modelDiscoveryFailed
        case "internal": self = .internalError
        default: self = .other(rawValue)
        }
    }

    init(from decoder: Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

struct HarnessRPCRemoteError: Error, Codable, Equatable, Sendable {
    let code: HarnessRemoteErrorCode
    let message: String
    let details: [String: HarnessJSONValue]
}

enum HarnessResponseViolation: Equatable, Sendable {
    case nonHTTPResponse
    case invalidContentType
    case invalidEnvelope
    case invalidResult
    case invalidPayload
}

enum HarnessRPCClientError: Error, Equatable, Sendable {
    case endpointUnavailable
    case endpointChanged
    case controlPlaneOnly
    case invalidEndpoint
    case invalidArgument
    case requestTooLarge(limit: Int)
    case responseTooLarge(limit: Int)
    case httpStatus(Int)
    case responseViolation(HarnessResponseViolation)
    case rpcIDMismatch
    case remote(HarnessRPCRemoteError)
    case timedOut
    case cancelled
    case transport(URLError.Code)
}

extension HarnessRPCClientError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .endpointUnavailable: return "The private Harness runtime is not connected."
        case .endpointChanged: return "The private Harness runtime changed while the request was in flight."
        case .controlPlaneOnly: return "Provider recovery is active. Agent sessions remain blocked until the selected route is verified."
        case .invalidEndpoint: return "The private Harness runtime endpoint is invalid."
        case .invalidArgument: return "The Harness request contains an invalid argument."
        case .requestTooLarge: return "The Harness request exceeds the configured safety limit."
        case .responseTooLarge: return "The Harness response exceeds the configured safety limit."
        case .httpStatus(let status): return "The Harness transport returned HTTP status \(status)."
        case .responseViolation: return "The Harness returned an invalid protocol response."
        case .rpcIDMismatch: return "The Harness response did not match the request."
        case .remote(let error):
            switch error.code {
            case .badRequest: return "Harness rejected the request."
            case .cancelled: return "Harness cancelled the request."
            case .sessionNotFound: return "The requested Harness task is no longer available."
            case .modelUnavailable: return "The selected provider or model is unavailable."
            case .sessionConflict: return "The Harness task changed while the request was in flight."
            case .agentBusy: return "The Harness agent is busy. Try again shortly."
            case .attachmentError: return "Harness rejected one or more attachments."
            case .commandError, .unknownCommand: return "Harness could not complete the requested command."
            case .settingsRejected: return "Harness rejected the provider settings change."
            case .settingsConflict: return "Provider settings changed concurrently. Refresh and try again."
            case .credentialRejected: return "The provider credential was rejected. Check or replace it in Models & Providers."
            case .modelDiscoveryFailed: return "Harness could not load the provider model catalog."
            case .internalError, .other: return "Harness could not complete the request."
            }
        case .timedOut: return "The Harness request timed out."
        case .cancelled: return "The Harness request was cancelled."
        case .transport(let code): return "The Harness transport failed (\(code.rawValue))."
        }
    }
}

// MARK: - Typed mux events

struct HarnessSessionSubscription: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let lastSequence: Int
}

struct HarnessTurnStart: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let turn: Int
}

struct HarnessUserMessage: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let messageID: String
    /// The client request identifier recorded in MessageSource by
    /// `session.prompt`; nil for injected/plugin/user messages without one.
    let sourceRPCID: String?

    /// A narrowly typed, source-authenticated Fulmar continuation notice. Raw
    /// plugin source strings are not retained in the native client: only the
    /// exact packaged plugin identity and one of its bounded summaries can
    /// cross this boundary.
    let automaticContinuation: HarnessAutomaticContinuationNotice?

    /// True only for DSH's canonical human-message source. This lets a native
    /// stream yield cleanly when newer queued user work wins over a staged
    /// automatic continuation without adopting that unrelated turn.
    let isDirectUserMessage: Bool

    init(
        rpcID: String,
        sessionID: HarnessSessionID,
        sequence: Int,
        time: Double,
        messageID: String,
        sourceRPCID: String?,
        automaticContinuation: HarnessAutomaticContinuationNotice? = nil,
        isDirectUserMessage: Bool = false
    ) {
        self.rpcID = rpcID
        self.sessionID = sessionID
        self.sequence = sequence
        self.time = time
        self.messageID = messageID
        self.sourceRPCID = sourceRPCID
        self.automaticContinuation = automaticContinuation
        self.isDirectUserMessage = isDirectUserMessage
    }
}

struct HarnessAutomaticContinuationNotice: Equatable, Sendable {
    static let pluginIdentifier = "fulmar-automatic-continuation"
    /// Must remain byte-for-byte aligned with the packaged production plugin.
    /// Accepting a caller-selected larger budget would turn source labelling
    /// into an unbounded-work primitive.
    static let packagedMaximumRounds = 12

    let round: Int?
    let maximum: Int?
    let isTerminalBudgetNotice: Bool

    private static let progressPrefix = "Fulmar continued automatically · "
    private static let terminalSummary = "Fulmar reached its automatic-continuation safety limit"

    static func decode(
        kind: String,
        plugin: String?,
        form: String?,
        summary: String?,
        rpcID: String?
    ) -> HarnessAutomaticContinuationNotice? {
        guard kind == "plugin",
              plugin == pluginIdentifier,
              form == "notice",
              rpcID == nil,
              let summary else { return nil }
        if summary == terminalSummary {
            return HarnessAutomaticContinuationNotice(
                round: nil,
                maximum: nil,
                isTerminalBudgetNotice: true
            )
        }
        guard summary.hasPrefix(progressPrefix) else { return nil }
        let suffix = summary.dropFirst(progressPrefix.count)
        let components = suffix.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count == 2,
              components.allSatisfy({ component in
                  !component.isEmpty && component.utf8.allSatisfy { (48...57).contains($0) }
              }),
              let round = Int(components[0]),
              let maximum = Int(components[1]),
              String(round) == String(components[0]),
              String(maximum) == String(components[1]),
              (1...packagedMaximumRounds).contains(round),
              maximum == packagedMaximumRounds,
              round <= maximum else { return nil }
        return HarnessAutomaticContinuationNotice(
            round: round,
            maximum: maximum,
            isTerminalBudgetNotice: false
        )
    }
}

struct HarnessCommandResponse: Equatable, Sendable {
    let sessionID: HarnessSessionID
    let kind: String
    let text: String?
}

struct HarnessAssistantTextDelta: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let turn: Int
    let step: Int
    let blockIndex: Int
    let text: String
}

struct HarnessAssistantFinalMessage: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let turn: Int
    let step: Int
    let messageID: String
    let textBlocks: [String]
    let provider: ProviderID?
    let model: ModelID?
    let interrupted: Bool

    var text: String { textBlocks.joined() }
}

enum HarnessTurnCompletionReason: Equatable, Sendable {
    case completed
    case aborted(HarnessJSONValue?)
    case blocked
    case maxTokens
    case interrupted
    case other
}

struct HarnessTurnCompletion: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let turn: Int
    let reason: HarnessTurnCompletionReason
}

struct HarnessLLMFailure: Codable, Equatable, Sendable {
    let message: String
    let code: String
    let status: Int?
    let providerRetryAfterMs: Int?
    let requestId: String?
}

struct HarnessTurnFailure: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let turn: Int
    let failure: HarnessLLMFailure
}

enum HarnessApprovalOutcome: String, Codable, Equatable, Sendable {
    case allowedOnce = "allowed-once"
    case rejected
    case cancelled
    case unavailable
}

struct HarnessApprovalRequest: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let approvalID: String
    let toolName: String
    let callID: String?
    let reason: String?
}

struct HarnessToolCall: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let sequence: Int
    let time: Double
    let turn: Int
    let step: Int
    let callID: String
    let toolName: String
    let argumentsJSON: String
}

struct HarnessApprovalResolution: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let approvalID: String
    let outcome: HarnessApprovalOutcome
}

struct HarnessQuestionOption: Codable, Equatable, Sendable {
    let label: String
    let description: String?
}

struct HarnessQuestionIntent: Codable, Equatable, Sendable {
    let kind: String
    let approve: String?
}

struct HarnessQuestion: Codable, Equatable, Sendable {
    let id: String
    let question: String
    let detail: String?
    let header: String?
    let options: [HarnessQuestionOption]?
    let multiSelect: Bool?
    let intent: HarnessQuestionIntent?
}

struct HarnessQuestionRequest: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let questions: [HarnessQuestion]
}

enum HarnessQuestionOutcome: String, Codable, Equatable, Sendable {
    case answered
    case cancelled
}

enum HarnessApprovalDecision: String, Codable, Equatable, Sendable {
    case allowedOnce = "allowed-once"
    case rejected
}

struct HarnessQuestionAnswerItem: Codable, Equatable, Sendable {
    let id: String
    let selected: [String]
    let custom: String?

    init(id: String, selected: [String], custom: String? = nil) {
        self.id = id
        self.selected = selected
        self.custom = custom
    }
}

struct HarnessQuestionAnswer: Codable, Equatable, Sendable {
    let answers: [HarnessQuestionAnswerItem]
}

enum HarnessRPCReceiptReason: String, Codable, Equatable, Sendable {
    case notPending = "not-pending"
    case badResponse = "bad-response"
}

struct HarnessRPCReceipt: Codable, Equatable, Sendable {
    let accepted: Bool
    let reason: HarnessRPCReceiptReason?

    private enum CodingKeys: String, CodingKey { case accepted, reason }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accepted = try container.decode(Bool.self, forKey: .accepted)
        reason = try container.decodeIfPresent(HarnessRPCReceiptReason.self, forKey: .reason)
        guard accepted ? reason == nil : reason != nil else {
            throw DecodingError.dataCorruptedError(
                forKey: .accepted,
                in: container,
                debugDescription: "Invalid RPC receipt."
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(accepted, forKey: .accepted)
        try container.encodeIfPresent(reason, forKey: .reason)
    }
}

struct HarnessQuestionResolution: Equatable, Sendable {
    let rpcID: String
    let sessionID: HarnessSessionID
    let questionRPCID: String
    let outcome: HarnessQuestionOutcome
}

enum HarnessMuxEvent: Equatable, Sendable {
    case subscribed(HarnessSessionSubscription)
    case turnStarted(HarnessTurnStart)
    case userMessage(HarnessUserMessage)
    case commandResponse(HarnessCommandResponse)
    case toolCall(HarnessToolCall)
    case assistantTextDelta(HarnessAssistantTextDelta)
    case assistantFinalMessage(HarnessAssistantFinalMessage)
    case turnCompleted(HarnessTurnCompletion)
    case turnFailed(HarnessTurnFailure)
    case approvalRequested(HarnessApprovalRequest)
    case approvalResolved(HarnessApprovalResolution)
    case questionRequested(HarnessQuestionRequest)
    case questionResolved(HarnessQuestionResolution)
    case streamError(HarnessRPCRemoteError)
}

enum HarnessMuxFrameError: Error, Equatable, Sendable {
    case frameLimitExceeded(limit: Int)
    case invalidEnvelope
    case invalidPayload
}

/// Strict decoder for one bounded DSH WebSocket mux message. WebSocket framing
/// preserves message boundaries, so there is no line-oriented compatibility
/// path that can accidentally mask a server transport change.
struct HarnessMuxFrameDecoder: Sendable {
    static func decodeMuxFrame(
        _ data: Data,
        maximumBytes: Int = 1 * 1_024 * 1_024
    ) throws -> HarnessMuxEvent? {
        precondition(maximumBytes > 0)
        guard data.count <= maximumBytes else {
            throw HarnessMuxFrameError.frameLimitExceeded(limit: maximumBytes)
        }
        let envelope: MuxServerRequest
        do {
            envelope = try JSONDecoder().decode(MuxServerRequest.self, from: data)
        } catch {
            throw HarnessMuxFrameError.invalidEnvelope
        }
        guard envelope.type == "server-request",
              let object = envelope.payload.objectValue,
              let payloadType = object["type"]?.stringValue,
              payloadType == envelope.method else {
            throw HarnessMuxFrameError.invalidEnvelope
        }

        func decode<Value: Decodable>(_ type: Value.Type) throws -> Value {
            do {
                let encoded = try JSONEncoder().encode(envelope.payload)
                return try JSONDecoder().decode(type, from: encoded)
            } catch {
                throw HarnessMuxFrameError.invalidPayload
            }
        }

        switch payloadType {
        case "session/subscribed":
            let payload = try decode(SubscribedPayload.self)
            return .subscribed(.init(
                rpcID: envelope.rpcId,
                sessionID: payload.sessionId,
                lastSequence: payload.lastSeq
            ))

        case "session/event":
            let payload = try decode(SessionEventPayload.self)
            switch payload.event.type {
            case "turn/start":
                let body = try decodeJSONValue(TurnStartData.self, payload.event.data)
                return .turnStarted(.init(
                    rpcID: envelope.rpcId,
                    sessionID: payload.sessionId,
                    sequence: payload.event.seq,
                    time: payload.event.time,
                    turn: body.turn
                ))

            case "user/message":
                let body = try decodeJSONValue(UserMessageData.self, payload.event.data)
                guard body.role == "user" else { throw HarnessMuxFrameError.invalidPayload }
                let automaticContinuation = HarnessAutomaticContinuationNotice.decode(
                    kind: body.source.kind,
                    plugin: body.source.plugin,
                    form: body.source.form,
                    summary: body.source.summary,
                    rpcID: body.source.rpcId
                )
                // A source claiming Fulmar's packaged continuation identity is
                // security-sensitive. Reject a malformed/spoofed variant instead
                // of degrading it into an unrelated opaque plugin message.
                if body.source.plugin == HarnessAutomaticContinuationNotice.pluginIdentifier,
                   automaticContinuation == nil {
                    throw HarnessMuxFrameError.invalidPayload
                }
                let isDirectUserMessage = body.source.kind == "user"
                    && body.source.rpcId != nil
                    && body.source.plugin == nil
                    && body.source.form == nil
                    && body.source.summary == nil
                // A source cannot gain human-queue priority merely by spelling
                // kind=user while carrying plugin provenance or omitting the
                // request receipt that binds a real session.prompt.
                if body.source.kind == "user", !isDirectUserMessage {
                    throw HarnessMuxFrameError.invalidPayload
                }
                return .userMessage(.init(
                    rpcID: envelope.rpcId,
                    sessionID: payload.sessionId,
                    sequence: payload.event.seq,
                    time: payload.event.time,
                    messageID: body.id,
                    sourceRPCID: isDirectUserMessage ? body.source.rpcId : nil,
                    automaticContinuation: automaticContinuation,
                    isDirectUserMessage: isDirectUserMessage
                ))

            case "assistant/chunk":
                let body = try decodeJSONValue(AssistantChunkData.self, payload.event.data)
                guard body.chunk.type == "text-delta" else { return nil }
                guard let index = body.chunk.index, let text = body.chunk.text else {
                    throw HarnessMuxFrameError.invalidPayload
                }
                return .assistantTextDelta(.init(
                    rpcID: envelope.rpcId,
                    sessionID: payload.sessionId,
                    sequence: payload.event.seq,
                    time: payload.event.time,
                    turn: body.turn,
                    step: body.step,
                    blockIndex: index,
                    text: text
                ))

            case "assistant/message":
                let body = try decodeJSONValue(AssistantMessageData.self, payload.event.data)
                guard body.message.role == "assistant" else { throw HarnessMuxFrameError.invalidPayload }
                return .assistantFinalMessage(.init(
                    rpcID: envelope.rpcId,
                    sessionID: payload.sessionId,
                    sequence: payload.event.seq,
                    time: payload.event.time,
                    turn: body.turn,
                    step: body.step,
                    messageID: body.message.id,
                    textBlocks: body.message.content.compactMap { $0.type == "text" ? $0.text : nil },
                    provider: body.message.source.provider,
                    model: body.message.source.model,
                    interrupted: body.interrupted == true
                ))

            case "tool/call":
                let body = try decodeJSONValue(ToolCallData.self, payload.event.data)
                let arguments = body.arguments.utf8.count <= 64 * 1_024
                    ? body.arguments
                    : String(body.arguments.prefix(32_000)) + "\n… [arguments truncated for display]"
                return .toolCall(.init(
                    rpcID: envelope.rpcId,
                    sessionID: payload.sessionId,
                    sequence: payload.event.seq,
                    time: payload.event.time,
                    turn: body.turn,
                    step: body.step,
                    callID: body.callId,
                    toolName: body.name,
                    argumentsJSON: arguments
                ))

            case "turn/end":
                let body = try decodeJSONValue(TurnEndData.self, payload.event.data)
                if body.reason.kind == "error" {
                    guard let failure = body.reason.error else { throw HarnessMuxFrameError.invalidPayload }
                    return .turnFailed(.init(
                        rpcID: envelope.rpcId,
                        sessionID: payload.sessionId,
                        sequence: payload.event.seq,
                        time: payload.event.time,
                        turn: body.turn,
                        failure: failure
                    ))
                }
                let reason: HarnessTurnCompletionReason
                switch body.reason.kind {
                case "completed": reason = .completed
                case "aborted": reason = .aborted(body.reason.reason)
                case "blocked": reason = .blocked
                case "max-tokens": reason = .maxTokens
                case "interrupted": reason = .interrupted
                default: reason = .other
                }
                return .turnCompleted(.init(
                    rpcID: envelope.rpcId,
                    sessionID: payload.sessionId,
                    sequence: payload.event.seq,
                    time: payload.event.time,
                    turn: body.turn,
                    reason: reason
                ))
            default:
                // Other session events (tool calls, queue state, projections, etc.)
                // are valid but outside this focused conversation stream.
                return nil
            }

        case "approval/requested":
            let payload = try decode(ApprovalRequestedPayload.self)
            return .approvalRequested(.init(
                rpcID: envelope.rpcId,
                sessionID: payload.sessionId,
                approvalID: payload.approvalId,
                toolName: payload.toolName,
                callID: payload.callId,
                reason: payload.reason
            ))

        case "approval/resolved":
            let payload = try decode(ApprovalResolvedPayload.self)
            return .approvalResolved(.init(
                rpcID: envelope.rpcId,
                sessionID: payload.sessionId,
                approvalID: payload.approvalId,
                outcome: payload.outcome
            ))

        case "question/requested":
            let payload = try decode(QuestionRequestedPayload.self)
            return .questionRequested(.init(
                rpcID: envelope.rpcId,
                sessionID: payload.sessionId,
                questions: payload.questions
            ))

        case "question/resolved":
            let payload = try decode(QuestionResolvedPayload.self)
            return .questionResolved(.init(
                rpcID: envelope.rpcId,
                sessionID: payload.sessionId,
                questionRPCID: payload.questionRpcId,
                outcome: payload.outcome
            ))

        case "stream/error":
            let payload = try decode(StreamErrorPayload.self)
            return .streamError(payload.error)

        default:
            // Mux is merge-extensible. Method/type agreement is still enforced,
            // while unknown future frame kinds remain forward compatible.
            return nil
        }
    }

    private static func decodeJSONValue<Value: Decodable>(_ type: Value.Type, _ value: HarnessJSONValue) throws -> Value {
        do {
            return try JSONDecoder().decode(type, from: JSONEncoder().encode(value))
        } catch {
            throw HarnessMuxFrameError.invalidPayload
        }
    }
}

private struct MuxServerRequest: Decodable {
    let type: String
    let rpcId: String
    let method: String
    let payload: HarnessJSONValue
}

private struct SubscribedPayload: Decodable {
    let sessionId: HarnessSessionID
    let lastSeq: Int
}

private struct SessionEventPayload: Decodable {
    struct Event: Decodable {
        let type: String
        let seq: Int
        let time: Double
        let data: HarnessJSONValue
    }
    let sessionId: HarnessSessionID
    let event: Event
}

private struct AssistantChunkData: Decodable {
    struct Chunk: Decodable {
        let type: String
        let index: Int?
        let text: String?
    }
    let turn: Int
    let step: Int
    let chunk: Chunk
}

private struct TurnStartData: Decodable {
    let turn: Int
}

private struct UserMessageData: Decodable {
    struct Source: Decodable {
        let kind: String
        let rpcId: String?
        let plugin: String?
        let form: String?
        let summary: String?
    }
    let id: String
    let role: String
    let source: Source
}

private struct AssistantMessageData: Decodable {
    struct Message: Decodable {
        struct Content: Decodable {
            let type: String
            let text: String?
        }
        struct Source: Decodable {
            let provider: ProviderID?
            let model: ModelID?

            private enum CodingKeys: String, CodingKey { case provider, model }

            init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                provider = try container.decodeIfPresent(ProviderID.self, forKey: .provider)
                model = try container.decodeIfPresent(ModelID.self, forKey: .model)
                guard (provider == nil) == (model == nil) else {
                    throw DecodingError.dataCorrupted(.init(
                        codingPath: container.codingPath,
                        debugDescription: "Assistant source must contain both provider and model identifiers."
                    ))
                }
            }
        }
        let id: String
        let role: String
        let content: [Content]
        let source: Source
    }
    let turn: Int
    let step: Int
    let message: Message
    let interrupted: Bool?
}

private struct TurnEndData: Decodable {
    struct Reason: Decodable {
        let kind: String
        let reason: HarnessJSONValue?
        let error: HarnessLLMFailure?
    }
    let turn: Int
    let reason: Reason
}

private struct ToolCallData: Decodable {
    let turn: Int
    let step: Int
    let callId: String
    let name: String
    let arguments: String
}

private struct ApprovalRequestedPayload: Decodable {
    let sessionId: HarnessSessionID
    let approvalId: String
    let toolName: String
    let callId: String?
    let reason: String?
}

private struct ApprovalResolvedPayload: Decodable {
    let sessionId: HarnessSessionID
    let approvalId: String
    let outcome: HarnessApprovalOutcome
}

private struct QuestionRequestedPayload: Decodable {
    let sessionId: HarnessSessionID
    let questions: [HarnessQuestion]
}

private struct QuestionResolvedPayload: Decodable {
    let sessionId: HarnessSessionID
    let questionRpcId: String
    let outcome: HarnessQuestionOutcome
}

private struct StreamErrorPayload: Decodable {
    let error: HarnessRPCRemoteError
}

// MARK: - RPC transport

struct HarnessRPCClientLimits: Equatable, Sendable {
    var requestBytes: Int
    /// Matches DSH's bounded HTTP bridge so its documented 100 MiB aggregate
    /// image intake remains usable after base64 expansion and envelope overhead.
    var promptRequestBytes: Int
    var unaryResponseBytes: Int
    var muxFrameBytes: Int
    var muxBufferedEvents: Int
    var unaryTimeout: TimeInterval
    var streamConnectTimeout: TimeInterval

    init(
        requestBytes: Int = 2 * 1_024 * 1_024,
        promptRequestBytes: Int = 160 * 1_024 * 1_024,
        unaryResponseBytes: Int = 4 * 1_024 * 1_024,
        muxFrameBytes: Int = 1 * 1_024 * 1_024,
        muxBufferedEvents: Int = 8,
        unaryTimeout: TimeInterval = 30,
        streamConnectTimeout: TimeInterval = 86_400
    ) {
        precondition(requestBytes > 0 && promptRequestBytes > 0 && unaryResponseBytes > 0)
        precondition(
            muxFrameBytes > 0 && muxFrameBytes <= 8 * 1_024 * 1_024
                && muxBufferedEvents > 0
        )
        // AsyncThrowingStream is count-bounded, so tie that count to the
        // already-enforced decoded frame ceiling. The transport can retain at
        // most 8 MiB of wire payload before it fails instead of dropping order.
        precondition(muxBufferedEvents <= max(1, (8 * 1_024 * 1_024) / muxFrameBytes))
        precondition(unaryTimeout > 0 && streamConnectTimeout > 0)
        self.requestBytes = requestBytes
        self.promptRequestBytes = promptRequestBytes
        self.unaryResponseBytes = unaryResponseBytes
        self.muxFrameBytes = muxFrameBytes
        self.muxBufferedEvents = muxBufferedEvents
        self.unaryTimeout = unaryTimeout
        self.streamConnectTimeout = streamConnectTimeout
    }
}

struct HarnessMuxSubscription: Sendable {
    let events: AsyncThrowingStream<HarnessMuxEvent, Error>
    private let opening: @Sendable () async throws -> Void
    private let cancellation: @Sendable () -> Void

    init(
        events: AsyncThrowingStream<HarnessMuxEvent, Error>,
        waitUntilOpen: @escaping @Sendable () async throws -> Void = {},
        cancellation: @escaping @Sendable () -> Void
    ) {
        self.events = events
        opening = waitUntilOpen
        self.cancellation = cancellation
    }

    /// Completes only after the authenticated WebSocket upgrade has been accepted.
    /// Callers must await this before submitting work: DSH
    /// v1 does not replay ordinary turn events, so merely creating the stream task
    /// is not a sufficient subscription barrier.
    func waitUntilOpen() async throws { try await opening() }

    func cancel() { cancellation() }
}

/// One-shot async gate used to publish the exact point at which URLSession has
/// accepted a WebSocket upgrade. It is lock-backed because URLSession completion,
/// cancellation, and consumers may arrive on unrelated executors.
private final class HarnessStreamOpenGate: @unchecked Sendable {
    private enum State {
        case pending([CheckedContinuation<Void, Error>])
        case opened
        case failed(Error)
    }

    private let lock = NSLock()
    private var state: State = .pending([])

    func wait() async throws {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            switch state {
            case .pending(var waiters):
                waiters.append(continuation)
                state = .pending(waiters)
                lock.unlock()
            case .opened:
                lock.unlock()
                continuation.resume()
            case .failed(let error):
                lock.unlock()
                continuation.resume(throwing: error)
            }
        }
    }

    func open() {
        resolve(.success(()))
    }

    func fail(_ error: Error) {
        resolve(.failure(error))
    }

    private func resolve(_ result: Result<Void, Error>) {
        lock.lock()
        guard case .pending(let waiters) = state else {
            lock.unlock()
            return
        }
        switch result {
        case .success: state = .opened
        case .failure(let error): state = .failed(error)
        }
        lock.unlock()
        for waiter in waiters {
            switch result {
            case .success: waiter.resume()
            case .failure(let error): waiter.resume(throwing: error)
            }
        }
    }
}

private enum HarnessRPCMethod: String {
    case llmProviders = "llm.providers"
    case llmModels = "llm.models"
    case sessionList = "session.list"
    case sessionSearch = "session.search"
    case sessionCreate = "session.create"
    case sessionHistory = "session.history"
    case sessionModels = "session.models"
    case sessionSelectModel = "session.selectModel"
    case sessionRename = "session.rename"
    case sessionFork = "session.fork"
    case sessionPrompt = "session.prompt"
    case sessionCancel = "session.cancel"
    case workspaceArchiveSession = "workspace.archiveSession"
    case settingsDescribe = "settings.describe"
    case settingsMutate = "settings.mutate"
    case credentialsDescribe = "credentials.describe"
    case credentialsSet = "credentials.set"
    case credentialsUnset = "credentials.unset"

    var isProviderControlPlaneMethod: Bool {
        switch self {
        case .llmProviders, .llmModels, .settingsDescribe,
             .settingsMutate, .credentialsDescribe, .credentialsSet, .credentialsUnset:
            return true
        case .sessionList, .sessionSearch, .sessionCreate, .sessionHistory,
             .sessionModels, .sessionSelectModel, .sessionRename, .sessionFork,
             .sessionPrompt, .sessionCancel, .workspaceArchiveSession:
            return false
        }
    }
}

enum HarnessRPCAccessMode: Equatable, Sendable {
    case controlPlaneOnly
    case fullInference
}

private struct EmptyPayload: Codable, Sendable {}
private struct EmptyValue: Codable, Sendable {}

private struct SessionListPayload: Codable, Sendable {
    let cursor: String?
}

private struct SessionSearchPayload: Codable, Sendable {
    let query: String
}

private struct SessionIDPayload: Codable, Sendable {
    let sessionId: HarnessSessionID
}

private struct SessionHistoryPayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let beforeSeq: Int?
    let maxMessages: Int?
}

private struct SessionRenamePayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let title: String
}

private struct SessionForkPayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let atSeq: Int?
}

private struct SelectModelPayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let provider: ProviderID
    let model: ModelID
    let reasoningEffort: String?
}

private struct SelectModelValue: Codable, Sendable {
    let selected: HarnessWireModelSelection
}

private struct PromptPayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let mode: HarnessPromptMode
    let content: [HarnessPromptContentPart]
    let clientTimeZone: String?
}

private struct SettingsMutatePayload: Codable, Sendable {
    let ns: String
    let ops: [HarnessSettingsPathOperation]
    let expectedRevision: Int?
}

private struct CredentialRefsPayload: Codable, Sendable {
    let refs: [String]
}

private struct CredentialSetPayload: Codable, Sendable {
    let ref: String
    let value: String
}

private struct CredentialUnsetPayload: Codable, Sendable {
    let ref: String
}

private struct ApprovalResponsePayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let approvalId: String
    let outcome: HarnessApprovalDecision
}

private struct QuestionResponsePayload: Codable, Sendable {
    let sessionId: HarnessSessionID
    let answer: HarnessQuestionAnswer
}

private struct RPCClientResponse<Value: Encodable>: Encodable {
    let type = "client-response"
    let rpcId: String
    let result: RPCOutboundResult<Value>
}

private enum RPCOutboundResult<Value: Encodable>: Encodable {
    case success(Value)
    case failure(HarnessRPCRemoteError)

    private enum CodingKeys: String, CodingKey { case ok, value, error }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .success(let value):
            try container.encode(true, forKey: .ok)
            try container.encode(value, forKey: .value)
        case .failure(let error):
            try container.encode(false, forKey: .ok)
            try container.encode(error, forKey: .error)
        }
    }
}

private struct RPCClientRequest<Payload: Encodable>: Encodable {
    let type = "client-request"
    let rpcId: String
    let method: String
    let payload: Payload
}

private enum RPCResult<Value: Decodable>: Decodable {
    case success(Value)
    case failure(HarnessRPCRemoteError)

    private enum CodingKeys: String, CodingKey { case ok, value, error }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let ok = try container.decode(Bool.self, forKey: .ok)
        if ok {
            guard container.contains(.value), !container.contains(.error) else {
                throw DecodingError.dataCorruptedError(forKey: .ok, in: container, debugDescription: "Invalid success result.")
            }
            self = .success(try container.decode(Value.self, forKey: .value))
        } else {
            guard container.contains(.error), !container.contains(.value) else {
                throw DecodingError.dataCorruptedError(forKey: .ok, in: container, debugDescription: "Invalid failure result.")
            }
            self = .failure(try container.decode(HarnessRPCRemoteError.self, forKey: .error))
        }
    }
}

private struct RPCServerResponse<Value: Decodable>: Decodable {
    let type: String
    let rpcId: String
    let result: RPCResult<Value>
}

private final class HarnessNoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

private final class HarnessWebSocketDelegate: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    private let didOpen: @Sendable () -> Void

    init(didOpen: @escaping @Sendable () -> Void) {
        self.didOpen = didOpen
    }

    func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didOpenWithProtocol protocol: String?
    ) {
        didOpen()
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

private final class HarnessCancellationHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var cancellation: (@Sendable () -> Void)?

    init(_ cancellation: @escaping @Sendable () -> Void) {
        self.cancellation = cancellation
    }

    func cancel() {
        lock.lock()
        let action = cancellation
        cancellation = nil
        lock.unlock()
        action?()
    }
}

/// Authenticated client for the loopback DSH fetch carrier. It never logs or
/// embeds request/response bodies in errors, because settings mutations and the
/// one-way credential setter may contain secrets.
final class HarnessRPCClient: @unchecked Sendable {
    typealias UUIDGenerator = @Sendable () -> UUID
    typealias MuxTransport = @Sendable (
        URLRequest,
        HarnessRPCClientLimits,
        AsyncThrowingStream<HarnessMuxEvent, Error>.Continuation,
        @escaping @Sendable () -> Void,
        @escaping @Sendable () throws -> Void
    ) async throws -> Void

    private struct Snapshot {
        let endpoint: HarnessEndpoint
        let generation: UInt64
        let accessMode: HarnessRPCAccessMode
    }

    private let session: URLSession
    private let uuid: UUIDGenerator
    private let limits: HarnessRPCClientLimits
    private let muxTransport: MuxTransport
    private let lock = NSLock()
    private var endpoint: HarnessEndpoint?
    private var accessMode: HarnessRPCAccessMode
    private var generation: UInt64 = 0
    private var nextOperationID: UInt64 = 0
    private var operations: [UInt64: HarnessCancellationHandle] = [:]

    init(
        endpoint: HarnessEndpoint? = nil,
        accessMode: HarnessRPCAccessMode = .fullInference,
        session: URLSession? = nil,
        limits: HarnessRPCClientLimits = .init(),
        uuid: @escaping UUIDGenerator = { UUID() },
        muxTransport: MuxTransport? = nil
    ) {
        self.endpoint = endpoint
        self.accessMode = accessMode
        self.session = session ?? Self.makePrivateLoopbackSession()
        self.limits = limits
        self.uuid = uuid
        self.muxTransport = muxTransport ?? { request, limits, continuation, onOpen, validateEndpoint in
            try await Self.consumeMuxWebSocket(
                request: request,
                limits: limits,
                continuation: continuation,
                onOpen: onOpen,
                validateEndpoint: validateEndpoint
            )
        }
    }

    /// Control-plane requests can carry write-only credential material. The
    /// production transport is therefore isolated from browser state, shared
    /// caches, credential stores, and system proxy discovery. Tests may still
    /// inject a protocol-backed URLSession through the initializer.
    static func privateLoopbackSessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.connectionProxyDictionary = [:]
        configuration.waitsForConnectivity = false
        return configuration
    }

    static func makePrivateLoopbackSession() -> URLSession {
        URLSession(configuration: privateLoopbackSessionConfiguration())
    }

    deinit {
        lock.lock()
        let active = Array(operations.values)
        operations.removeAll()
        lock.unlock()
        active.forEach { $0.cancel() }
    }

    /// Swapping or clearing the runtime invalidates every in-flight operation;
    /// stale responses can never be accepted under a new runtime identity.
    func setEndpoint(_ endpoint: HarnessEndpoint?) {
        replaceEndpoint(endpoint, accessMode: .fullInference)
    }

    /// Provider recovery receives the same authenticated, runtime-identity-
    /// bound endpoint as the full client, but only the exact provider/settings/
    /// credential control plane is admitted until verification succeeds.
    func setControlPlaneEndpoint(_ endpoint: HarnessEndpoint?) {
        replaceEndpoint(endpoint, accessMode: .controlPlaneOnly)
    }

    private func replaceEndpoint(_ endpoint: HarnessEndpoint?, accessMode: HarnessRPCAccessMode) {
        lock.lock()
        self.endpoint = endpoint
        self.accessMode = accessMode
        generation &+= 1
        let active = Array(operations.values)
        operations.removeAll()
        lock.unlock()
        active.forEach { $0.cancel() }
    }

    /// Promotion is a one-way transition for one exact live runtime identity.
    /// Replacing or clearing the endpoint changes its generation and identity,
    /// so a stale verification result can never promote a successor process.
    @discardableResult
    func promoteToFullInference(expected endpoint: HarnessEndpoint) -> Bool {
        lock.lock()
        guard self.endpoint == endpoint, accessMode == .controlPlaneOnly else {
            lock.unlock()
            return false
        }
        accessMode = .fullInference
        generation &+= 1
        let active = Array(operations.values)
        operations.removeAll()
        lock.unlock()
        active.forEach { $0.cancel() }
        return true
    }

    func currentAccessMode() -> HarnessRPCAccessMode? {
        lock.lock()
        defer { lock.unlock() }
        return endpoint == nil ? nil : accessMode
    }

    func clearEndpoint() { setEndpoint(nil) }

    func llmProviders() async throws -> HarnessProviderDirectory {
        try await call(.llmProviders, payload: EmptyPayload())
    }

    func llmModels() async throws -> HarnessModelCatalog {
        try await call(.llmModels, payload: EmptyPayload())
    }

    func listSessions(cursor: String? = nil) async throws -> HarnessSessionList {
        try await call(.sessionList, payload: SessionListPayload(cursor: cursor))
    }

    func searchSessions(query: String) async throws -> HarnessSessionSearchResult {
        let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines)
        // DSH's z.string() wire bound is measured in JavaScript UTF-16 code
        // units, not Swift grapheme clusters.
        guard !normalized.isEmpty, normalized.utf16.count <= 500, !normalized.contains("\0") else {
            throw HarnessRPCClientError.invalidArgument
        }
        return try await call(.sessionSearch, payload: SessionSearchPayload(query: normalized))
    }

    func createSession(_ request: HarnessSessionCreateRequest = .init()) async throws -> HarnessSessionCreateResult {
        guard request.workspaceId == nil || request.cwd == nil,
              request.reuseWorkspaceBlank != true || (request.workspaceId != nil && request.sessionId != nil) else {
            throw HarnessRPCClientError.invalidArgument
        }
        return try await call(.sessionCreate, payload: request)
    }

    func sessionHistory(
        _ sessionID: HarnessSessionID,
        beforeSequence: Int? = nil,
        maximumMessages: Int? = nil
    ) async throws -> HarnessSessionHistoryPage {
        guard beforeSequence.map({ $0 >= 0 }) ?? true,
              maximumMessages.map({ $0 > 0 }) ?? true else {
            throw HarnessRPCClientError.invalidArgument
        }
        return try await call(
            .sessionHistory,
            payload: SessionHistoryPayload(
                sessionId: sessionID,
                beforeSeq: beforeSequence,
                maxMessages: maximumMessages
            )
        )
    }

    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels {
        try await call(.sessionModels, payload: SessionIDPayload(sessionId: sessionID))
    }

    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection {
        let value: SelectModelValue = try await call(
            .sessionSelectModel,
            payload: SelectModelPayload(
                sessionId: sessionID,
                provider: selection.provider,
                model: selection.model,
                reasoningEffort: selection.reasoningEffort
            )
        )
        return value.selected
    }

    func renameSession(
        _ sessionID: HarnessSessionID,
        title: String
    ) async throws -> HarnessSessionRenameResult {
        let normalized = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty,
              normalized.utf16.count <= 500,
              !normalized.contains("\0") else { throw HarnessRPCClientError.invalidArgument }
        return try await call(
            .sessionRename,
            payload: SessionRenamePayload(sessionId: sessionID, title: normalized)
        )
    }

    func forkSession(
        _ sessionID: HarnessSessionID,
        atSequence: Int? = nil
    ) async throws -> HarnessSessionForkResult {
        guard atSequence.map({ $0 >= 0 }) ?? true else { throw HarnessRPCClientError.invalidArgument }
        return try await call(
            .sessionFork,
            payload: SessionForkPayload(sessionId: sessionID, atSeq: atSequence)
        )
    }

    func archiveSession(_ sessionID: HarnessSessionID) async throws -> HarnessArchivedSessionsResult {
        try await call(
            .workspaceArchiveSession,
            payload: SessionIDPayload(sessionId: sessionID)
        )
    }

    func prompt(
        sessionID: HarnessSessionID,
        mode: HarnessPromptMode = .queue,
        content: [HarnessPromptContentPart],
        clientTimeZone: String? = nil
    ) async throws -> HarnessPromptSubmission {
        let correlated: (value: HarnessPromptResult, rpcID: String) = try await callWithRPCID(
            .sessionPrompt,
            payload: PromptPayload(
                sessionId: sessionID,
                mode: mode,
                content: content,
                clientTimeZone: clientTimeZone
            ),
            maximumRequestBytes: limits.promptRequestBytes
        )
        return HarnessPromptSubmission(rpcID: correlated.rpcID, result: correlated.value)
    }

    func cancel(sessionID: HarnessSessionID) async throws -> HarnessCancelResult {
        try await call(.sessionCancel, payload: SessionIDPayload(sessionId: sessionID))
    }

    func describeSettings() async throws -> HarnessSettingsDescription {
        try await call(.settingsDescribe, payload: EmptyPayload())
    }

    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int? = nil
    ) async throws -> HarnessSettingsNamespace {
        guard Self.recoveryMutableSettingsNamespaces.contains(namespace) else {
            throw HarnessRPCClientError.invalidArgument
        }
        return try await call(
            .settingsMutate,
            payload: SettingsMutatePayload(ns: namespace, ops: operations, expectedRevision: expectedRevision)
        )
    }

    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        try await call(
            .credentialsDescribe,
            payload: CredentialRefsPayload(refs: references.map(\.rawValue))
        )
    }

    func setCredential(_ reference: CredentialReference, value: String) async throws {
        let _: EmptyValue = try await call(
            .credentialsSet,
            payload: CredentialSetPayload(ref: reference.rawValue, value: value)
        )
    }

    func unsetCredential(_ reference: CredentialReference) async throws {
        let _: EmptyValue = try await call(
            .credentialsUnset,
            payload: CredentialUnsetPayload(ref: reference.rawValue)
        )
    }

    func respondToApproval(
        rpcID: String,
        sessionID: HarnessSessionID,
        approvalID: String,
        decision: HarnessApprovalDecision
    ) async throws -> HarnessRPCReceipt {
        guard !rpcID.isEmpty, !approvalID.isEmpty else { throw HarnessRPCClientError.invalidArgument }
        return try await respond(
            rpcID: rpcID,
            result: .success(ApprovalResponsePayload(
                sessionId: sessionID,
                approvalId: approvalID,
                outcome: decision
            ))
        )
    }

    func respondToQuestion(
        rpcID: String,
        sessionID: HarnessSessionID,
        answer: HarnessQuestionAnswer
    ) async throws -> HarnessRPCReceipt {
        guard !rpcID.isEmpty else { throw HarnessRPCClientError.invalidArgument }
        return try await respond(
            rpcID: rpcID,
            result: .success(QuestionResponsePayload(sessionId: sessionID, answer: answer))
        )
    }

    func cancelQuestion(rpcID: String) async throws -> HarnessRPCReceipt {
        guard !rpcID.isEmpty else { throw HarnessRPCClientError.invalidArgument }
        let error = HarnessRPCRemoteError(code: .cancelled, message: "The user cancelled the question.", details: [:])
        return try await respond(rpcID: rpcID, result: RPCOutboundResult<EmptyValue>.failure(error))
    }

    /// Opens the all-session event stream. DSH v1 currently ignores `since`,
    /// but the cursor is carried for reconnect-safe clients and future runtimes.
    func muxEvents(since: [HarnessSessionID: Int] = [:]) throws -> HarnessMuxSubscription {
        guard since.values.allSatisfy({ $0 >= -1 }) else { throw HarnessRPCClientError.invalidArgument }
        let snapshot = try endpointSnapshot(requireFullInference: true)
        let request = try muxRequest(snapshot: snapshot, since: since)

        let streamLimits = limits
        var continuation: AsyncThrowingStream<HarnessMuxEvent, Error>.Continuation!
        let stream = AsyncThrowingStream<HarnessMuxEvent, Error>(
            bufferingPolicy: .bufferingOldest(streamLimits.muxBufferedEvents)
        ) { continuation = $0 }
        let muxTransport = muxTransport
        let openGate = HarnessStreamOpenGate()
        let task = Task { [weak self] in
            do {
                try await muxTransport(
                    request,
                    streamLimits,
                    continuation,
                    { openGate.open() },
                    { [weak self] in
                        guard let self else { throw HarnessRPCClientError.cancelled }
                        try self.validateGeneration(snapshot.generation)
                    }
                )
                continuation.finish()
            } catch {
                let mapped = self?.mapTransportError(error, generation: snapshot.generation)
                    ?? HarnessRPCClientError.cancelled
                openGate.fail(mapped)
                continuation.finish(throwing: mapped)
            }
        }
        let handle = HarnessCancellationHandle { task.cancel() }
        guard let operationID = register(handle, generation: snapshot.generation) else {
            handle.cancel()
            throw HarnessRPCClientError.endpointChanged
        }
        continuation.onTermination = { [weak self] _ in
            handle.cancel()
            self?.unregister(operationID)
        }
        Task { [weak self] in
            _ = await task.result
            self?.unregister(operationID)
        }
        return HarnessMuxSubscription(
            events: stream,
            waitUntilOpen: { try await openGate.wait() },
            cancellation: {
                openGate.fail(HarnessRPCClientError.cancelled)
                handle.cancel()
            }
        )
    }

    private func respond<Value: Encodable & Sendable>(
        rpcID: String,
        result: RPCOutboundResult<Value>
    ) async throws -> HarnessRPCReceipt {
        let snapshot = try endpointSnapshot(requireFullInference: true)
        let envelope = RPCClientResponse(rpcId: rpcID, result: result)
        let body: Data
        do {
            body = try JSONEncoder().encode(envelope)
        } catch {
            throw HarnessRPCClientError.responseViolation(.invalidPayload)
        }
        guard body.count <= limits.requestBytes else {
            throw HarnessRPCClientError.requestTooLarge(limit: limits.requestBytes)
        }
        let request = try jsonPostRequest(snapshot: snapshot, path: "respond", body: body)
        let task = Task<HarnessRPCReceipt, Error> { [session, limits] in
            let (data, response) = try await Self.boundedData(
                for: request,
                session: session,
                maximumBytes: limits.unaryResponseBytes
            )
            try self.validateGeneration(snapshot.generation)
            try Self.validateHTTP(response, contentType: "application/json")
            do {
                return try JSONDecoder().decode(HarnessRPCReceipt.self, from: data)
            } catch {
                throw HarnessRPCClientError.responseViolation(.invalidEnvelope)
            }
        }
        let handle = HarnessCancellationHandle { task.cancel() }
        guard let operationID = register(handle, generation: snapshot.generation) else {
            handle.cancel()
            throw HarnessRPCClientError.endpointChanged
        }
        defer { unregister(operationID) }
        return try await withTaskCancellationHandler {
            do {
                return try await task.value
            } catch {
                throw mapTransportError(error, generation: snapshot.generation)
            }
        } onCancel: {
            handle.cancel()
        }
    }

    private func call<Payload: Encodable & Sendable, Value: Decodable & Sendable>(
        _ method: HarnessRPCMethod,
        payload: Payload,
        maximumRequestBytes: Int? = nil
    ) async throws -> Value {
        let correlated: (value: Value, rpcID: String) = try await callWithRPCID(
            method,
            payload: payload,
            maximumRequestBytes: maximumRequestBytes
        )
        return correlated.value
    }

    private func callWithRPCID<Payload: Encodable & Sendable, Value: Decodable & Sendable>(
        _ method: HarnessRPCMethod,
        payload: Payload,
        maximumRequestBytes: Int? = nil
    ) async throws -> (value: Value, rpcID: String) {
        let snapshot = try endpointSnapshot(method: method)
        let rpcID = uuid().uuidString.lowercased()
        let envelope = RPCClientRequest(rpcId: rpcID, method: method.rawValue, payload: payload)
        let body: Data
        do {
            body = try JSONEncoder().encode(envelope)
        } catch {
            throw HarnessRPCClientError.responseViolation(.invalidPayload)
        }
        let requestLimit = maximumRequestBytes ?? limits.requestBytes
        guard body.count <= requestLimit else {
            throw HarnessRPCClientError.requestTooLarge(limit: requestLimit)
        }
        let request = try unaryRequest(snapshot: snapshot, method: method, body: body)

        let task = Task<Value, Error> { [session, limits] in
            let (data, response) = try await Self.boundedData(
                for: request,
                session: session,
                maximumBytes: limits.unaryResponseBytes
            )
            try self.validateGeneration(snapshot.generation)
            try Self.validateHTTP(response, contentType: "application/json")

            let decoded: RPCServerResponse<Value>
            do {
                decoded = try JSONDecoder().decode(RPCServerResponse<Value>.self, from: data)
            } catch {
                throw HarnessRPCClientError.responseViolation(.invalidEnvelope)
            }
            guard decoded.type == "server-response" else {
                throw HarnessRPCClientError.responseViolation(.invalidEnvelope)
            }
            guard decoded.rpcId == rpcID else { throw HarnessRPCClientError.rpcIDMismatch }
            switch decoded.result {
            case .success(let value): return value
            case .failure(let error): throw HarnessRPCClientError.remote(error)
            }
        }
        let handle = HarnessCancellationHandle { task.cancel() }
        guard let operationID = register(handle, generation: snapshot.generation) else {
            handle.cancel()
            throw HarnessRPCClientError.endpointChanged
        }
        defer { unregister(operationID) }

        let value = try await withTaskCancellationHandler {
            do {
                return try await task.value
            } catch {
                throw mapTransportError(error, generation: snapshot.generation)
            }
        } onCancel: {
            handle.cancel()
        }
        return (value, rpcID)
    }

    private static let recoveryMutableSettingsNamespaces: Set<String> = [
        "agent-default-model", "llm-pi-ai", "llm-deepseek"
    ]

    private func endpointSnapshot(
        method: HarnessRPCMethod? = nil,
        requireFullInference: Bool = false
    ) throws -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        guard let endpoint else { throw HarnessRPCClientError.endpointUnavailable }
        if accessMode == .controlPlaneOnly,
           requireFullInference || method?.isProviderControlPlaneMethod != true {
            throw HarnessRPCClientError.controlPlaneOnly
        }
        return Snapshot(endpoint: endpoint, generation: generation, accessMode: accessMode)
    }

    private func register(_ handle: HarnessCancellationHandle, generation expected: UInt64) -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expected, endpoint != nil else { return nil }
        nextOperationID &+= 1
        operations[nextOperationID] = handle
        return nextOperationID
    }

    private func unregister(_ operationID: UInt64) {
        lock.lock()
        operations.removeValue(forKey: operationID)
        lock.unlock()
    }

    private func validateGeneration(_ expected: UInt64) throws {
        lock.lock()
        let valid = generation == expected && endpoint != nil
        lock.unlock()
        guard valid else { throw HarnessRPCClientError.endpointChanged }
    }

    private func unaryRequest(snapshot: Snapshot, method: HarnessRPCMethod, body: Data) throws -> URLRequest {
        try jsonPostRequest(snapshot: snapshot, path: method.rawValue, body: body)
    }

    private func jsonPostRequest(snapshot: Snapshot, path: String, body: Data) throws -> URLRequest {
        guard var url = apiURL(endpoint: snapshot.endpoint, path: path) else {
            throw HarnessRPCClientError.invalidEndpoint
        }
        // Discard any endpoint fragment; it is never part of an HTTP request.
        if var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            components.fragment = nil
            if let normalized = components.url { url = normalized }
        }
        var request = snapshot.endpoint.authenticatedRequest(to: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.timeoutInterval = limits.unaryTimeout
        request.httpShouldHandleCookies = false
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    private func muxRequest(snapshot: Snapshot, since: [HarnessSessionID: Int]) throws -> URLRequest {
        guard let base = apiURL(endpoint: snapshot.endpoint, path: "events.mux"),
              var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw HarnessRPCClientError.invalidEndpoint
        }
        switch components.scheme?.lowercased() {
        case "http": components.scheme = "ws"
        case "https": components.scheme = "wss"
        default: throw HarnessRPCClientError.invalidEndpoint
        }
        if !since.isEmpty {
            let rawCursor = Dictionary(uniqueKeysWithValues: since.map { ($0.key.rawValue, $0.value) })
            let encoded = try JSONEncoder().encode(rawCursor)
            guard encoded.count <= limits.requestBytes, let cursor = String(data: encoded, encoding: .utf8) else {
                throw HarnessRPCClientError.requestTooLarge(limit: limits.requestBytes)
            }
            components.queryItems = [URLQueryItem(name: "since", value: cursor)]
        }
        components.fragment = nil
        guard let url = components.url else { throw HarnessRPCClientError.invalidEndpoint }
        var request = snapshot.endpoint.authenticatedRequest(to: url)
        request.httpMethod = "GET"
        request.timeoutInterval = limits.streamConnectTimeout
        request.httpShouldHandleCookies = false
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        request.setValue(Self.originHeader(for: snapshot.endpoint), forHTTPHeaderField: "Origin")
        return request
    }

    private static func originHeader(for endpoint: HarnessEndpoint) -> String {
        var components = URLComponents(url: endpoint.baseURL, resolvingAgainstBaseURL: false)!
        components.path = ""
        components.query = nil
        components.fragment = nil
        return components.string!
    }

    private func apiURL(endpoint: HarnessEndpoint, path: String) -> URL? {
        guard let components = URLComponents(url: endpoint.baseURL, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              let host = components.host?.lowercased(),
              ["127.0.0.1", "localhost", "::1"].contains(host),
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil else { return nil }
        return endpoint.baseURL
            .appendingPathComponent("api", isDirectory: true)
            .appendingPathComponent(path, isDirectory: false)
    }

    private static func consumeMuxWebSocket(
        request: URLRequest,
        limits: HarnessRPCClientLimits,
        continuation: AsyncThrowingStream<HarnessMuxEvent, Error>.Continuation,
        onOpen: @escaping @Sendable () -> Void,
        validateEndpoint: @escaping @Sendable () throws -> Void
    ) async throws {
        let delegate = HarnessWebSocketDelegate {
            do {
                try validateEndpoint()
                onOpen()
            } catch {
                // Endpoint replacement cancels the registered operation. The
                // receiving task maps that cancellation to endpointChanged.
            }
        }
        let session = URLSession(
            configuration: privateLoopbackSessionConfiguration(),
            delegate: delegate,
            delegateQueue: nil
        )
        let socket = session.webSocketTask(with: request)
        socket.maximumMessageSize = limits.muxFrameBytes
        socket.resume()
        defer {
            socket.cancel(with: .goingAway, reason: nil)
            session.finishTasksAndInvalidate()
        }

        try await withTaskCancellationHandler {
            while true {
                try Task.checkCancellation()
                let message = try await socket.receive()
                try validateEndpoint()
                let data: Data
                switch message {
                case .string(let text):
                    data = Data(text.utf8)
                case .data(let bytes):
                    data = bytes
                @unknown default:
                    throw HarnessMuxFrameError.invalidEnvelope
                }
                if let event = try HarnessMuxFrameDecoder.decodeMuxFrame(
                    data,
                    maximumBytes: limits.muxFrameBytes
                ) {
                    try yieldMux(event, continuation: continuation, limit: limits.muxBufferedEvents)
                }
            }
        } onCancel: {
            socket.cancel(with: .goingAway, reason: nil)
        }
    }

    private static func yieldMux(
        _ event: HarnessMuxEvent,
        continuation: AsyncThrowingStream<HarnessMuxEvent, Error>.Continuation,
        limit: Int
    ) throws {
        switch continuation.yield(event) {
        case .enqueued:
            return
        case .dropped:
            throw HarnessRPCClientError.responseTooLarge(limit: limit)
        case .terminated:
            throw HarnessRPCClientError.cancelled
        @unknown default:
            throw HarnessRPCClientError.responseViolation(.invalidEnvelope)
        }
    }

    private static func boundedData(
        for request: URLRequest,
        session: URLSession,
        maximumBytes: Int
    ) async throws -> (Data, URLResponse) {
        let delegate = HarnessNoRedirectDelegate()
        let (bytes, response) = try await session.bytes(for: request, delegate: delegate)
        if let expected = response.expectedContentLength as Int64?, expected > Int64(maximumBytes) {
            throw HarnessRPCClientError.responseTooLarge(limit: maximumBytes)
        }
        var data = Data()
        data.reserveCapacity(min(max(Int(response.expectedContentLength), 0), maximumBytes))
        for try await byte in bytes {
            guard data.count < maximumBytes else {
                throw HarnessRPCClientError.responseTooLarge(limit: maximumBytes)
            }
            data.append(byte)
        }
        return (data, response)
    }

    private static func validateHTTP(_ response: URLResponse, contentType: String) throws {
        guard let http = response as? HTTPURLResponse else {
            throw HarnessRPCClientError.responseViolation(.nonHTTPResponse)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw HarnessRPCClientError.httpStatus(http.statusCode)
        }
        guard http.mimeType?.lowercased() == contentType else {
            throw HarnessRPCClientError.responseViolation(.invalidContentType)
        }
    }

    private func mapTransportError(_ error: Error, generation expected: UInt64) -> Error {
        lock.lock()
        let changed = generation != expected || endpoint == nil
        lock.unlock()
        if changed { return HarnessRPCClientError.endpointChanged }
        if let error = error as? HarnessRPCClientError { return error }
        if let error = error as? HarnessMuxFrameError { return error }
        if error is CancellationError { return HarnessRPCClientError.cancelled }
        if let urlError = error as? URLError {
            switch urlError.code {
            case .timedOut: return HarnessRPCClientError.timedOut
            case .cancelled: return HarnessRPCClientError.cancelled
            default: return HarnessRPCClientError.transport(urlError.code)
            }
        }
        return HarnessRPCClientError.transport(.unknown)
    }
}
