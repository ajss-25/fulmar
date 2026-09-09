import Darwin
import Foundation

enum ScheduleValidationError: Error, Equatable, LocalizedError {
    case invalidTitle
    case invalidPrompt
    case invalidRoute
    case invalidInterval
    case invalidTimeout
    case invalidSchemaVersion
    case invalidConsent

    var errorDescription: String? {
        switch self {
        case .invalidTitle: return "Schedule names must contain between 1 and 200 characters."
        case .invalidPrompt: return "Schedule prompts must contain between 1 byte and 200 KB."
        case .invalidRoute: return "The scheduled provider and model identifiers are invalid."
        case .invalidInterval: return "Repeating schedules must run between once a minute and once every ten years."
        case .invalidTimeout: return "Scheduled task timeout must be between 30 seconds and 2 hours."
        case .invalidSchemaVersion: return "This schedule was created by an unsupported app version."
        case .invalidConsent: return "The unattended provider consent is invalid."
        }
    }
}

struct ScheduleUnattendedConsent: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 2

    let schemaVersion: Int
    let provider: ProviderID
    let model: ModelID
    let boundary: DataBoundary
    /// Exact HTTP(S) origin reviewed for this unattended route. Legacy v1
    /// consent decodes with nil and is deliberately never considered valid.
    let origin: ProviderEndpointOrigin?
    let grantedAt: Date

    init(
        selection: ModelSelection,
        boundary: DataBoundary,
        origin: ProviderEndpointOrigin,
        grantedAt: Date = Date()
    ) throws {
        guard boundary.requiresExplicitConsent,
              ScheduleFieldValidation.isSafeIdentifier(selection.route.provider.rawValue),
              ScheduleFieldValidation.isSafeIdentifier(selection.route.model.rawValue) else {
            throw ScheduleValidationError.invalidConsent
        }
        schemaVersion = Self.currentSchemaVersion
        provider = selection.route.provider
        model = selection.route.model
        self.boundary = boundary
        self.origin = origin
        self.grantedAt = grantedAt
    }

    func permits(
        selection: ModelSelection,
        effectiveBoundary: DataBoundary,
        effectiveOrigin: ProviderEndpointOrigin?
    ) -> Bool {
        schemaVersion == Self.currentSchemaVersion &&
            effectiveBoundary.requiresExplicitConsent &&
            provider == selection.route.provider &&
            model == selection.route.model &&
            boundary == effectiveBoundary &&
            origin != nil && origin == effectiveOrigin
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case provider
        case model
        case boundary
        case origin
        case grantedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == 1 || version == Self.currentSchemaVersion else {
            throw ScheduleValidationError.invalidSchemaVersion
        }
        let provider = try container.decode(ProviderID.self, forKey: .provider)
        let model = try container.decode(ModelID.self, forKey: .model)
        let boundary = try container.decode(DataBoundary.self, forKey: .boundary)
        guard boundary.requiresExplicitConsent,
              ScheduleFieldValidation.isSafeIdentifier(provider.rawValue),
              ScheduleFieldValidation.isSafeIdentifier(model.rawValue) else {
            throw ScheduleValidationError.invalidConsent
        }
        schemaVersion = version
        self.provider = provider
        self.model = model
        self.boundary = boundary
        origin = try container.decodeIfPresent(ProviderEndpointOrigin.self, forKey: .origin)
        if version == Self.currentSchemaVersion, origin == nil {
            throw ScheduleValidationError.invalidConsent
        }
        grantedAt = try container.decode(Date.self, forKey: .grantedAt)
    }
}

struct LocalSchedule: Codable, Equatable, Identifiable, Sendable {
    static let currentSchemaVersion = 2
    static let defaultTimeoutSeconds: TimeInterval = 10 * 60

    let schemaVersion: Int
    let id: UUID
    var title: String
    var prompt: String
    var selection: ModelSelection
    var boundary: DataBoundary
    var unattendedConsent: ScheduleUnattendedConsent?
    var intervalSeconds: TimeInterval
    var timeoutSeconds: TimeInterval
    var nextRun: Date
    var enabled: Bool
    var lastRun: Date?

    var model: String { selection.route.model.rawValue }
    var provider: String { selection.route.provider.rawValue }

    init(
        id: UUID = UUID(),
        title: String,
        prompt: String,
        selection: ModelSelection,
        boundary: DataBoundary,
        unattendedConsent: ScheduleUnattendedConsent? = nil,
        intervalSeconds: TimeInterval,
        timeoutSeconds: TimeInterval = Self.defaultTimeoutSeconds,
        nextRun: Date,
        enabled: Bool = true,
        lastRun: Date? = nil
    ) throws {
        guard ScheduleFieldValidation.isSafeTitle(title) else { throw ScheduleValidationError.invalidTitle }
        guard ScheduleFieldValidation.isSafePrompt(prompt) else { throw ScheduleValidationError.invalidPrompt }
        guard ScheduleFieldValidation.isSafe(selection: selection) else { throw ScheduleValidationError.invalidRoute }
        guard ScheduleFieldValidation.isValidInterval(intervalSeconds) else { throw ScheduleValidationError.invalidInterval }
        guard ScheduleFieldValidation.isValidTimeout(timeoutSeconds) else { throw ScheduleValidationError.invalidTimeout }
        schemaVersion = Self.currentSchemaVersion
        self.id = id
        self.title = title.trimmingCharacters(in: .whitespacesAndNewlines)
        self.prompt = prompt
        self.selection = selection
        self.boundary = boundary
        self.unattendedConsent = unattendedConsent
        self.intervalSeconds = intervalSeconds
        self.timeoutSeconds = timeoutSeconds
        self.nextRun = nextRun
        self.enabled = enabled
        self.lastRun = lastRun
    }

    func isAuthorized(
        for effectiveBoundary: DataBoundary,
        origin effectiveOrigin: ProviderEndpointOrigin?
    ) -> Bool {
        guard boundary == effectiveBoundary else { return false }
        if !effectiveBoundary.requiresExplicitConsent { return true }
        return unattendedConsent?.permits(
            selection: selection,
            effectiveBoundary: effectiveBoundary,
            effectiveOrigin: effectiveOrigin
        ) == true
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case id
        case title
        case prompt
        case model
        case selection
        case boundary
        case unattendedConsent
        case intervalSeconds
        case timeoutSeconds
        case nextRun
        case enabled
        case lastRun
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion)
        if decodedVersion == nil {
            let legacyModel = try container.decode(String.self, forKey: .model)
            let interval = try container.decode(TimeInterval.self, forKey: .intervalSeconds)
            try self.init(
                id: container.decode(UUID.self, forKey: .id),
                title: container.decode(String.self, forKey: .title),
                prompt: container.decode(String.self, forKey: .prompt),
                selection: ModelSelection(
                    route: ModelRoute(
                        provider: BuiltInProviderDescriptors.ollama.id,
                        model: ModelID(legacyModel)
                    ),
                    performanceProfile: .balanced
                ),
                boundary: .onDevice,
                intervalSeconds: interval > 0 ? max(60, interval) : 0,
                timeoutSeconds: Self.defaultTimeoutSeconds,
                nextRun: container.decode(Date.self, forKey: .nextRun),
                enabled: container.decode(Bool.self, forKey: .enabled),
                lastRun: container.decodeIfPresent(Date.self, forKey: .lastRun)
            )
            return
        }

        guard decodedVersion == Self.currentSchemaVersion else {
            throw ScheduleValidationError.invalidSchemaVersion
        }
        try self.init(
            id: container.decode(UUID.self, forKey: .id),
            title: container.decode(String.self, forKey: .title),
            prompt: container.decode(String.self, forKey: .prompt),
            selection: container.decode(ModelSelection.self, forKey: .selection),
            boundary: container.decode(DataBoundary.self, forKey: .boundary),
            unattendedConsent: container.decodeIfPresent(ScheduleUnattendedConsent.self, forKey: .unattendedConsent),
            intervalSeconds: container.decode(TimeInterval.self, forKey: .intervalSeconds),
            timeoutSeconds: container.decode(TimeInterval.self, forKey: .timeoutSeconds),
            nextRun: container.decode(Date.self, forKey: .nextRun),
            enabled: container.decode(Bool.self, forKey: .enabled),
            lastRun: container.decodeIfPresent(Date.self, forKey: .lastRun)
        )
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encode(prompt, forKey: .prompt)
        try container.encode(model, forKey: .model) // Read compatibility with the pre-v2 app.
        try container.encode(selection, forKey: .selection)
        try container.encode(boundary, forKey: .boundary)
        try container.encodeIfPresent(unattendedConsent, forKey: .unattendedConsent)
        try container.encode(intervalSeconds, forKey: .intervalSeconds)
        try container.encode(timeoutSeconds, forKey: .timeoutSeconds)
        try container.encode(nextRun, forKey: .nextRun)
        try container.encode(enabled, forKey: .enabled)
        try container.encodeIfPresent(lastRun, forKey: .lastRun)
    }
}

struct ScheduleResultFailure: Codable, Equatable, Sendable {
    enum Code: String, Codable, Sendable {
        case runtimeUnavailable
        case consentRequired
        case providerFailed
        case timedOut
        case cancelled
        case interactionRequired
        case responseTooLarge
        case filesystem
        case checkpointFailed
        case interrupted
        case unknown
        case legacy
    }

    let code: Code
    let detail: String?

    init(code: Code, detail: String? = nil) {
        self.code = code
        if code == .providerFailed {
            self.detail = detail.flatMap(ScheduleProviderFailureCategory.init(rawValue:))?.rawValue
        } else if code == .legacy || code == .checkpointFailed {
            // Legacy and checkpoint result files may contain arbitrary
            // underlying error text. It can include provider bodies,
            // credentials, or local paths, so retain only the failure class.
            self.detail = nil
        } else {
            self.detail = detail.flatMap(ScheduleFieldValidation.sanitizedDetail)
        }
    }

    private enum CodingKeys: String, CodingKey { case code, detail }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        code = try container.decode(Code.self, forKey: .code)
        let decodedDetail = try container.decodeIfPresent(String.self, forKey: .detail)
        if code == .providerFailed {
            detail = decodedDetail.flatMap(ScheduleProviderFailureCategory.init(rawValue:))?.rawValue
        } else if code == .legacy || code == .checkpointFailed {
            detail = nil
        } else {
            detail = decodedDetail.flatMap(ScheduleFieldValidation.sanitizedDetail)
        }
    }

    var displayMessage: String {
        switch code {
        case .runtimeUnavailable: return "The private Harness runtime was unavailable."
        case .consentRequired: return "This provider or data boundary needs renewed unattended-use consent."
        case .providerFailed:
            return detail.flatMap(ScheduleProviderFailureCategory.init(rawValue:))?.displayMessage
                ?? ScheduleProviderFailureCategory.generic.displayMessage
        case .timedOut: return "The scheduled task exceeded its time limit."
        case .cancelled: return "The scheduled task was cancelled."
        case .interactionRequired: return "The task requested an approval or answer that cannot be granted unattended."
        case .responseTooLarge: return "The scheduled response exceeded the 2 MB safety limit."
        case .filesystem: return "The private schedule workspace or inbox was unavailable."
        case .checkpointFailed: return "A recovery point could not be created, so the task did not run."
        case .interrupted: return "The previous app process ended after dispatching this scheduled task; the occurrence was not repeated."
        case .legacy: return "The legacy scheduled task failed."
        case .unknown: return "The scheduled task failed."
        }
    }
}

struct ScheduledResult: Codable, Equatable, Identifiable, Sendable {
    static let currentSchemaVersion = 2

    let schemaVersion: Int
    let id: UUID
    let scheduleID: UUID
    let title: String
    let completedAt: Date
    let selection: ModelSelection
    let boundary: DataBoundary
    let sessionID: HarnessSessionID?
    let response: String
    let failure: ScheduleResultFailure?
    let truncated: Bool

    var model: String { selection.route.model.rawValue }
    var provider: String { selection.route.provider.rawValue }
    var error: String? { failure?.displayMessage }

    init(
        id: UUID = UUID(),
        scheduleID: UUID,
        title: String,
        completedAt: Date,
        selection: ModelSelection,
        boundary: DataBoundary,
        sessionID: HarnessSessionID?,
        response: String,
        failure: ScheduleResultFailure?,
        truncated: Bool
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.id = id
        self.scheduleID = scheduleID
        self.title = title
        self.completedAt = completedAt
        self.selection = selection
        self.boundary = boundary
        self.sessionID = sessionID
        self.response = response
        self.failure = failure
        self.truncated = truncated
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case id
        case scheduleID
        case title
        case completedAt
        case model
        case selection
        case boundary
        case sessionID
        case response
        case error
        case failure
        case truncated
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion)
        id = try container.decode(UUID.self, forKey: .id)
        scheduleID = try container.decode(UUID.self, forKey: .scheduleID)
        title = try container.decode(String.self, forKey: .title)
        completedAt = try container.decode(Date.self, forKey: .completedAt)
        response = try container.decode(String.self, forKey: .response)
        if version == nil {
            let legacyModel = try container.decode(String.self, forKey: .model)
            selection = ModelSelection(
                route: ModelRoute(provider: BuiltInProviderDescriptors.ollama.id, model: ModelID(legacyModel)),
                performanceProfile: .balanced
            )
            boundary = .onDevice
            sessionID = nil
            failure = try container.decodeIfPresent(String.self, forKey: .error).map {
                ScheduleResultFailure(code: .legacy, detail: $0)
            }
            truncated = false
            schemaVersion = Self.currentSchemaVersion
            return
        }
        guard version == Self.currentSchemaVersion else { throw ScheduleValidationError.invalidSchemaVersion }
        schemaVersion = version!
        selection = try container.decode(ModelSelection.self, forKey: .selection)
        boundary = try container.decode(DataBoundary.self, forKey: .boundary)
        sessionID = try container.decodeIfPresent(HarnessSessionID.self, forKey: .sessionID)
        failure = try container.decodeIfPresent(ScheduleResultFailure.self, forKey: .failure)
        truncated = try container.decode(Bool.self, forKey: .truncated)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(id, forKey: .id)
        try container.encode(scheduleID, forKey: .scheduleID)
        try container.encode(title, forKey: .title)
        try container.encode(completedAt, forKey: .completedAt)
        try container.encode(model, forKey: .model)
        try container.encode(selection, forKey: .selection)
        try container.encode(boundary, forKey: .boundary)
        try container.encodeIfPresent(sessionID, forKey: .sessionID)
        try container.encode(response, forKey: .response)
        try container.encodeIfPresent(error, forKey: .error)
        try container.encodeIfPresent(failure, forKey: .failure)
        try container.encode(truncated, forKey: .truncated)
    }
}

/// Durable at-most-once journal for one provider-backed schedule occurrence.
/// A `started` record is fsynced before the prompt reaches Harness. A
/// `completed` record embeds the exact deterministic Inbox result and schedule
/// transition, allowing startup to replay either side of a crash without
/// issuing the prompt again.
struct ScheduleOccurrenceReceipt: Codable, Equatable, Identifiable, Sendable {
    static let currentSchemaVersion = 1

    enum State: String, Codable, Sendable {
        case started
        case completed
    }

    let schemaVersion: Int
    let id: UUID
    let scheduleID: UUID
    let startedAt: Date
    let state: State
    let result: ScheduledResult?
    let disable: Bool?
    let retrySoon: Bool?

    init(id: UUID, scheduleID: UUID, startedAt: Date) throws {
        guard startedAt.timeIntervalSinceReferenceDate.isFinite else {
            throw ScheduleDocumentStoreError.invalidDocument
        }
        schemaVersion = Self.currentSchemaVersion
        self.id = id
        self.scheduleID = scheduleID
        self.startedAt = startedAt
        state = .started
        result = nil
        disable = nil
        retrySoon = nil
    }

    func completing(with result: ScheduledResult, disable: Bool, retrySoon: Bool) throws -> Self {
        guard state == .started,
              result.id == id,
              result.scheduleID == scheduleID,
              result.completedAt.timeIntervalSinceReferenceDate.isFinite else {
            throw ScheduleDocumentStoreError.invalidDocument
        }
        return Self(
            schemaVersion: Self.currentSchemaVersion,
            id: id,
            scheduleID: scheduleID,
            startedAt: startedAt,
            state: .completed,
            result: result,
            disable: disable,
            retrySoon: retrySoon
        )
    }

    private init(
        schemaVersion: Int,
        id: UUID,
        scheduleID: UUID,
        startedAt: Date,
        state: State,
        result: ScheduledResult?,
        disable: Bool?,
        retrySoon: Bool?
    ) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.scheduleID = scheduleID
        self.startedAt = startedAt
        self.state = state
        self.result = result
        self.disable = disable
        self.retrySoon = retrySoon
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, id, scheduleID, startedAt, state, result, disable, retrySoon
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        let id = try container.decode(UUID.self, forKey: .id)
        let scheduleID = try container.decode(UUID.self, forKey: .scheduleID)
        let startedAt = try container.decode(Date.self, forKey: .startedAt)
        let state = try container.decode(State.self, forKey: .state)
        let result = try container.decodeIfPresent(ScheduledResult.self, forKey: .result)
        let disable = try container.decodeIfPresent(Bool.self, forKey: .disable)
        let retrySoon = try container.decodeIfPresent(Bool.self, forKey: .retrySoon)
        guard schemaVersion == Self.currentSchemaVersion,
              startedAt.timeIntervalSinceReferenceDate.isFinite else {
            throw ScheduleDocumentStoreError.invalidDocument
        }
        switch state {
        case .started:
            guard result == nil, disable == nil, retrySoon == nil else {
                throw ScheduleDocumentStoreError.invalidDocument
            }
        case .completed:
            guard let result,
                  result.id == id,
                  result.scheduleID == scheduleID,
                  result.completedAt.timeIntervalSinceReferenceDate.isFinite,
                  disable != nil,
                  retrySoon != nil else {
                throw ScheduleDocumentStoreError.invalidDocument
            }
        }
        self.init(
            schemaVersion: schemaVersion,
            id: id,
            scheduleID: scheduleID,
            startedAt: startedAt,
            state: state,
            result: result,
            disable: disable,
            retrySoon: retrySoon
        )
    }
}

/// Idempotently applies the transition encoded by one occurrence. Replaying
/// the same receipt after a crash never advances a recurring schedule twice.
@discardableResult
func applyScheduleOccurrenceTransition(
    schedules: inout [LocalSchedule],
    scheduleID: UUID,
    completedAt: Date,
    disable: Bool,
    retrySoon: Bool
) -> Bool {
    guard completedAt.timeIntervalSinceReferenceDate.isFinite,
          let index = schedules.firstIndex(where: { $0.id == scheduleID }) else { return false }
    if let lastRun = schedules[index].lastRun, lastRun > completedAt { return false }

    let previous = schedules[index]
    schedules[index].lastRun = completedAt
    if disable {
        schedules[index].enabled = false
    } else if retrySoon {
        schedules[index].nextRun = completedAt.addingTimeInterval(60)
    } else if schedules[index].intervalSeconds <= 0 {
        schedules[index].enabled = false
    } else {
        schedules[index].nextRun = completedAt.addingTimeInterval(schedules[index].intervalSeconds)
    }
    return schedules[index] != previous
}

struct ScheduleBoundaryPolicy: Sendable {
    private let boundaries: [ProviderID: DataBoundary]
    private let origins: [ProviderID: ProviderEndpointOrigin]

    init(
        descriptors: [ProviderDescriptor] = BuiltInProviderDescriptors.all,
        includeBuiltInDefaults: Bool = true
    ) {
        var values = (includeBuiltInDefaults ? BuiltInProviderDescriptors.all : []).reduce(into: [ProviderID: DataBoundary]()) { result, descriptor in
            result[descriptor.id] = descriptor.boundary
        }
        var originValues = (includeBuiltInDefaults ? BuiltInProviderDescriptors.all : []).reduce(into: [ProviderID: ProviderEndpointOrigin]()) { result, descriptor in
            if let origin = descriptor.defaultBaseURL.flatMap(ProviderEndpointOrigin.init(url:)) {
                result[descriptor.id] = origin
            }
        }
        // A verified live descriptor must override the static built-in default:
        // for example, an "ollama" provider configured to a LAN endpoint is no
        // longer an on-device boundary merely because its opaque ID is ollama.
        for descriptor in descriptors {
            values[descriptor.id] = descriptor.boundary
            if let origin = descriptor.defaultBaseURL.flatMap(ProviderEndpointOrigin.init(url:)) {
                originValues[descriptor.id] = origin
            } else {
                originValues.removeValue(forKey: descriptor.id)
            }
        }
        boundaries = values
        origins = originValues
    }

    /// Unknown providers are conservatively treated as cloud providers.
    func boundary(for provider: ProviderID) -> DataBoundary {
        boundaries[provider] ?? .cloud
    }

    func origin(for provider: ProviderID) -> ProviderEndpointOrigin? {
        origins[provider]
    }
}

enum ScheduleFieldValidation {
    static let maximumPromptBytes = 200_000
    static let maximumInterval: TimeInterval = 10 * 365 * 86_400

    static func isSafeTitle(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed.count <= 200 && !containsControls(trimmed)
    }

    static func isSafePrompt(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumPromptBytes
    }

    static func isSafe(selection: ModelSelection) -> Bool {
        isSafeIdentifier(selection.route.provider.rawValue) && isSafeIdentifier(selection.route.model.rawValue)
    }

    static func isSafeIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 512 && !containsControls(value)
    }

    static func isValidInterval(_ value: TimeInterval) -> Bool {
        value.isFinite && (value == 0 || (value >= 60 && value <= maximumInterval))
    }

    static func isValidTimeout(_ value: TimeInterval) -> Bool {
        value.isFinite && (30...7_200).contains(value)
    }

    static func sanitizedDetail(_ value: String) -> String? {
        let scalars = value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        let cleaned = String(String.UnicodeScalarView(scalars)).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return nil }
        return cleaned.count > 80 ? String(cleaned.prefix(80)) : cleaned
    }

    private static func containsControls(_ value: String) -> Bool {
        value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

enum ScheduleAuthorizationStatus: Equatable, Sendable {
    case authorized
    case consentRequired(DataBoundary)
    case boundaryChanged(stored: DataBoundary, effective: DataBoundary)
    case providerInactive(active: ProviderID?)
    /// On-device providers may expose several models behind one loopback
    /// origin. Only the exact route promoted by the native runtime is allowed.
    case routeInactive(active: ModelRoute?)
    case endpointUnavailable
}

struct ScheduleDocumentLoadResult: Equatable {
    let schedules: [LocalSchedule]
    let migratedLegacySchema: Bool
}

struct ScheduleInboxRetentionPolicy: Equatable, Sendable {
    let maximumRecords: Int
    let maximumBytes: Int
    let maximumAge: TimeInterval

    static let production = ScheduleInboxRetentionPolicy(
        maximumRecords: 2_000,
        maximumBytes: 256 * 1_024 * 1_024,
        maximumAge: 30 * 86_400
    )

    init(maximumRecords: Int, maximumBytes: Int, maximumAge: TimeInterval) {
        precondition(maximumRecords > 0)
        precondition(maximumBytes >= ScheduleDocumentStore.maximumDocumentBytes)
        precondition(maximumAge > 0 && maximumAge.isFinite)
        self.maximumRecords = maximumRecords
        self.maximumBytes = maximumBytes
        self.maximumAge = maximumAge
    }
}

struct ScheduleDirectoryScanLimits: Equatable, Sendable {
    let maximumInboxEntries: Int
    let maximumOccurrenceEntries: Int
    let deadlineSeconds: TimeInterval

    init(
        maximumInboxEntries: Int,
        maximumOccurrenceEntries: Int,
        deadlineSeconds: TimeInterval
    ) {
        precondition(maximumInboxEntries > 0)
        precondition(maximumOccurrenceEntries > 0)
        precondition(deadlineSeconds > 0 && deadlineSeconds.isFinite)
        self.maximumInboxEntries = maximumInboxEntries
        self.maximumOccurrenceEntries = maximumOccurrenceEntries
        self.deadlineSeconds = deadlineSeconds
    }

    static func production(for retention: ScheduleInboxRetentionPolicy) -> Self {
        let fivefold = retention.maximumRecords.multipliedReportingOverflow(by: 5)
        let repairRecords = max(
            retention.maximumRecords,
            fivefold.overflow ? Int.max : fivefold.partialValue
        )
        let doubled = repairRecords.multipliedReportingOverflow(by: 2)
        return Self(
            maximumInboxEntries: doubled.overflow ? Int.max : doubled.partialValue,
            maximumOccurrenceEntries: 2_048,
            deadlineSeconds: 2
        )
    }
}

enum ScheduleDocumentStoreError: Error, Equatable, LocalizedError {
    case unsafeStorage
    case documentTooLarge
    case tooManySchedules
    case invalidDocument
    case directoryEntryLimitExceeded(Int)
    case directoryScanTimedOut

    var errorDescription: String? {
        switch self {
        case .unsafeStorage: return "Schedule storage is not a private regular file."
        case .documentTooLarge: return "The schedule document exceeds its 5 MB safety limit."
        case .tooManySchedules: return "No more than 1,000 schedules can be stored."
        case .invalidDocument: return "The schedule document is invalid or from an unsupported app version."
        case .directoryEntryLimitExceeded(let maximum):
            return "Schedule storage contains more than the allowed \(maximum) directory entries."
        case .directoryScanTimedOut:
            return "Schedule storage could not be inspected within its bounded deadline."
        }
    }
}

final class ScheduleDocumentStore: @unchecked Sendable {
    static let maximumDocumentBytes = 5 * 1_024 * 1_024
    static let maximumScheduleCount = 1_000
    static let maximumInboxResultCount = ScheduleInboxRetentionPolicy.production.maximumRecords
    static let maximumInboxBytes = ScheduleInboxRetentionPolicy.production.maximumBytes
    static let maximumInboxAge = ScheduleInboxRetentionPolicy.production.maximumAge

    let directory: URL
    let schedulesURL: URL
    let inboxDirectory: URL
    let workspaceDirectory: URL
    let occurrenceDirectory: URL
    private let fileManager: FileManager
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let inboxRetentionPolicy: ScheduleInboxRetentionPolicy
    private let directoryScanLimits: ScheduleDirectoryScanLimits
    private let directoryScanNow: @Sendable () -> UInt64
    private let now: @Sendable () -> Date
    private let inboxLock = NSLock()
    private let occurrenceLock = NSLock()
    private var cachedInboxCount = 0

    init(
        applicationSupport: URL,
        fileManager: FileManager = .default,
        inboxRetentionPolicy: ScheduleInboxRetentionPolicy = .production,
        now: @escaping @Sendable () -> Date = { Date() },
        directoryScanLimits: ScheduleDirectoryScanLimits? = nil,
        directoryScanNow: @escaping @Sendable () -> UInt64 = {
            DispatchTime.now().uptimeNanoseconds
        }
    ) throws {
        self.fileManager = fileManager
        self.inboxRetentionPolicy = inboxRetentionPolicy
        self.directoryScanLimits = directoryScanLimits ?? .production(for: inboxRetentionPolicy)
        self.directoryScanNow = directoryScanNow
        self.now = now
        directory = applicationSupport.appendingPathComponent("Schedules", isDirectory: true)
        schedulesURL = directory.appendingPathComponent("schedules.json")
        inboxDirectory = directory.appendingPathComponent("Inbox", isDirectory: true)
        workspaceDirectory = directory.appendingPathComponent("Workspaces", isDirectory: true)
        occurrenceDirectory = directory.appendingPathComponent("Occurrences", isDirectory: true)
        try prepareDirectory(applicationSupport)
        try prepareDirectory(directory)
        try prepareDirectory(inboxDirectory)
        try prepareDirectory(workspaceDirectory)
        try prepareDirectory(occurrenceDirectory)
        encoder.outputFormatting = [.sortedKeys]
        cachedInboxCount = try fastInboxFilenameCount()
    }

    func load() throws -> ScheduleDocumentLoadResult {
        guard fileManager.fileExists(atPath: schedulesURL.path) else {
            return ScheduleDocumentLoadResult(schedules: [], migratedLegacySchema: false)
        }
        try requireRegularFile(schedulesURL)
        let data = try readPrivateRegularFile(schedulesURL)
        let schedules: [LocalSchedule]
        do {
            schedules = try decoder.decode([LocalSchedule].self, from: data)
        } catch let error as ScheduleValidationError {
            throw error
        } catch {
            throw ScheduleDocumentStoreError.invalidDocument
        }
        guard schedules.count <= Self.maximumScheduleCount else {
            throw ScheduleDocumentStoreError.tooManySchedules
        }
        guard let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw ScheduleDocumentStoreError.invalidDocument
        }
        return ScheduleDocumentLoadResult(
            schedules: schedules,
            migratedLegacySchema: raw.contains { $0["schemaVersion"] == nil }
        )
    }

    func save(_ schedules: [LocalSchedule]) throws {
        try prepareDirectory(directory)
        if fileManager.fileExists(atPath: schedulesURL.path) { try requireRegularFile(schedulesURL) }
        guard schedules.count <= Self.maximumScheduleCount else {
            throw ScheduleDocumentStoreError.tooManySchedules
        }
        let data = try encoder.encode(schedules)
        guard data.count <= Self.maximumDocumentBytes else { throw ScheduleDocumentStoreError.documentTooLarge }
        try writePrivateAtomically(data, to: schedulesURL)
    }

    func workspace(for scheduleID: UUID) throws -> URL {
        try prepareDirectory(workspaceDirectory)
        let workspace = workspaceDirectory.appendingPathComponent(scheduleID.uuidString, isDirectory: true)
        try prepareDirectory(workspace)
        return workspace
    }

    func write(result: ScheduledResult) throws {
        try withInboxLock {
            try prepareDirectory(inboxDirectory)
            _ = try maintainInbox(now: now())
            let url = inboxDirectory.appendingPathComponent("\(result.id.uuidString).json")
            guard !pathExistsNoFollow(url) else { throw ScheduleDocumentStoreError.unsafeStorage }
            let data = try encoder.encode(result)
            guard data.count <= Self.maximumDocumentBytes else { throw ScheduleDocumentStoreError.documentTooLarge }
            try writePrivateAtomically(data, to: url)
            do {
                _ = try maintainInbox(now: now())
            } catch {
                // Do not report a successful append if the bounded retention
                // invariant could not be restored. The exact new file is the
                // only byte this operation owns and is safe to roll back.
                try? removePrivateRegularFiles([url])
                throw error
            }
        }
    }

    /// Writes the same deterministic occurrence result at most once. This is
    /// used by journal replay after a crash between Inbox and schedule commits.
    func ensure(result: ScheduledResult) throws {
        try withInboxLock {
            try prepareDirectory(inboxDirectory)
            _ = try maintainInbox(now: now())
            let url = inboxDirectory.appendingPathComponent("\(result.id.uuidString).json")
            let data = try encoder.encode(result)
            guard data.count <= Self.maximumDocumentBytes else {
                throw ScheduleDocumentStoreError.documentTooLarge
            }
            if pathExistsNoFollow(url) {
                try requireRegularFile(url)
                let existing = try decoder.decode(ScheduledResult.self, from: readPrivateRegularFile(url))
                guard existing == result else { throw ScheduleDocumentStoreError.unsafeStorage }
            } else {
                try writePrivateAtomically(data, to: url)
            }
            _ = try maintainInbox(now: now())
        }
    }

    /// Fsyncs an at-most-once lease before a provider-backed prompt is sent.
    func beginOccurrence(id: UUID, scheduleID: UUID, startedAt: Date) throws {
        try withOccurrenceLock {
            try prepareDirectory(occurrenceDirectory)
            let pending = try enumerateOccurrenceReceipts(cleanTemporaryFiles: true)
            guard !pending.contains(where: { $0.scheduleID == scheduleID }) else {
                throw ScheduleDocumentStoreError.invalidDocument
            }
            let url = occurrenceURL(id: id)
            guard !pathExistsNoFollow(url) else { throw ScheduleDocumentStoreError.unsafeStorage }
            let receipt = try ScheduleOccurrenceReceipt(id: id, scheduleID: scheduleID, startedAt: startedAt)
            let data = try encoder.encode(receipt)
            guard data.count <= Self.maximumDocumentBytes else {
                throw ScheduleDocumentStoreError.documentTooLarge
            }
            try writePrivateAtomically(data, to: url)
        }
    }

    /// Atomically upgrades the dispatch lease to the exact completed result
    /// before the Inbox or schedules document is mutated.
    func completeOccurrence(
        id: UUID,
        result: ScheduledResult,
        disable: Bool,
        retrySoon: Bool
    ) throws {
        try withOccurrenceLock {
            let url = occurrenceURL(id: id)
            try requireRegularFile(url)
            let started = try decoder.decode(
                ScheduleOccurrenceReceipt.self,
                from: readPrivateRegularFile(url)
            )
            guard started.id == id, started.state == .started else {
                throw ScheduleDocumentStoreError.invalidDocument
            }
            let completed = try started.completing(
                with: result,
                disable: disable,
                retrySoon: retrySoon
            )
            let data = try encoder.encode(completed)
            guard data.count <= Self.maximumDocumentBytes else {
                throw ScheduleDocumentStoreError.documentTooLarge
            }
            try writePrivateAtomically(data, to: url)
        }
    }

    /// Removes a finalized journal record only after both the deterministic
    /// Inbox result and the schedules document have been fsynced.
    func finishOccurrence(id: UUID) throws {
        try withOccurrenceLock {
            let url = occurrenceURL(id: id)
            guard pathExistsNoFollow(url) else { return }
            try removeOccurrenceFiles([url])
        }
    }

    /// Startup recovery is deliberately at-most-once. A mere `started` lease
    /// means the prompt may already have reached an external provider, so it
    /// receives a deterministic interrupted result and advances without ever
    /// dispatching that occurrence again. A completed record replays its exact
    /// result. Schedule advancement is derived from the receipt timestamp, not
    /// current state, and is therefore idempotent.
    func reconcilePendingOccurrences(in schedules: [LocalSchedule]) throws -> [LocalSchedule] {
        try withOccurrenceLock {
            let receipts = try enumerateOccurrenceReceipts(cleanTemporaryFiles: true)
            guard !receipts.isEmpty else { return schedules }
            guard Set(receipts.map(\.scheduleID)).count == receipts.count else {
                throw ScheduleDocumentStoreError.invalidDocument
            }

            var updated = schedules
            for receipt in receipts {
                guard let schedule = updated.first(where: { $0.id == receipt.scheduleID }) else {
                    continue
                }
                let result: ScheduledResult
                let disable: Bool
                let retrySoon: Bool
                switch receipt.state {
                case .started:
                    result = ScheduledResult(
                        id: receipt.id,
                        scheduleID: schedule.id,
                        title: schedule.title,
                        completedAt: receipt.startedAt,
                        selection: schedule.selection,
                        boundary: schedule.boundary,
                        sessionID: nil,
                        response: "",
                        failure: ScheduleResultFailure(code: .interrupted),
                        truncated: false
                    )
                    disable = false
                    retrySoon = false
                case .completed:
                    guard let committed = receipt.result,
                          let committedDisable = receipt.disable,
                          let committedRetry = receipt.retrySoon else {
                        throw ScheduleDocumentStoreError.invalidDocument
                    }
                    result = committed
                    disable = committedDisable
                    retrySoon = committedRetry
                }
                try ensure(result: result)
                _ = applyScheduleOccurrenceTransition(
                    schedules: &updated,
                    scheduleID: receipt.scheduleID,
                    completedAt: result.completedAt,
                    disable: disable,
                    retrySoon: retrySoon
                )
            }
            if updated != schedules { try save(updated) }
            try removeOccurrenceFiles(receipts.map { occurrenceURL(id: $0.id) })
            return updated
        }
    }

    func pendingOccurrenceCount() throws -> Int {
        try withOccurrenceLock {
            try enumerateOccurrenceReceipts(cleanTemporaryFiles: true).count
        }
    }

    func inbox() -> [ScheduledResult] {
        (try? inboxChecked()) ?? []
    }

    func inboxChecked() throws -> [ScheduledResult] {
        try withInboxLock {
            try maintainInbox(now: now())
        }
    }

    /// Metadata-only count for status UI. Result bodies are deliberately not
    /// opened or decoded on the main thread.
    func inboxCount() -> Int {
        withInboxLock { cachedInboxCount }
    }

    func deleteInboxResult(id: UUID) throws {
        try withInboxLock {
            try prepareDirectory(inboxDirectory)
            let entries = try enumerateInboxFiles(cleanTemporaryFiles: true)
            guard let entry = entries.first(where: { $0.id == id }) else { return }
            try removePrivateRegularFiles([entry.url])
            cachedInboxCount = try fastInboxFilenameCount()
        }
    }

    func clearInbox() throws {
        try withInboxLock {
            try prepareDirectory(inboxDirectory)
            let entries = try enumerateInboxFiles(cleanTemporaryFiles: true)
            try removePrivateRegularFiles(entries.map(\.url))
            cachedInboxCount = 0
        }
    }

    private struct InboxFile {
        let url: URL
        let id: UUID
        let bytes: Int
        let modifiedAt: Date
    }

    private struct InboxRecord {
        let file: InboxFile
        let result: ScheduledResult
    }

    private func maintainInbox(now: Date) throws -> [ScheduledResult] {
        guard now.timeIntervalSinceReferenceDate.isFinite else {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        var files = try enumerateInboxFiles(cleanTemporaryFiles: true)

        // Bound migration work for an Inbox created by an older unbounded
        // build before decoding content. App-created mtimes track append order,
        // and the newest new write is therefore retained during this repair.
        let multipliedRecords = inboxRetentionPolicy.maximumRecords.multipliedReportingOverflow(by: 5)
        let scanRecordLimit = max(
            inboxRetentionPolicy.maximumRecords,
            multipliedRecords.overflow ? Int.max : multipliedRecords.partialValue
        )
        let multipliedBytes = inboxRetentionPolicy.maximumBytes.multipliedReportingOverflow(by: 4)
        let scanByteLimit = max(
            inboxRetentionPolicy.maximumBytes,
            multipliedBytes.overflow ? Int.max : multipliedBytes.partialValue
        )
        var aggregateBytes = 0
        var exceedsByteLimit = false
        for file in files {
            guard file.bytes <= scanByteLimit,
                  aggregateBytes <= scanByteLimit - file.bytes else {
                exceedsByteLimit = true
                break
            }
            aggregateBytes += file.bytes
        }
        if files.count > scanRecordLimit || exceedsByteLimit {
            files.sort {
                if $0.modifiedAt != $1.modifiedAt { return $0.modifiedAt > $1.modifiedAt }
                return $0.url.lastPathComponent < $1.url.lastPathComponent
            }
            var kept: [InboxFile] = []
            var removed: [URL] = []
            var bytes = 0
            for file in files {
                if kept.count < scanRecordLimit, bytes <= scanByteLimit - file.bytes {
                    kept.append(file)
                    bytes += file.bytes
                } else {
                    removed.append(file.url)
                }
            }
            try removePrivateRegularFiles(removed)
            files = kept
        }

        let oldestAllowed = now.addingTimeInterval(-inboxRetentionPolicy.maximumAge)
        let newestAllowed = now.addingTimeInterval(86_400)
        var records: [InboxRecord] = []
        var invalidOrExpired: [URL] = []
        for file in files {
            do {
                let result = try decoder.decode(ScheduledResult.self, from: readPrivateRegularFile(file.url))
                guard result.id == file.id,
                      result.completedAt.timeIntervalSinceReferenceDate.isFinite,
                      result.completedAt >= oldestAllowed,
                      result.completedAt <= newestAllowed else {
                    invalidOrExpired.append(file.url)
                    continue
                }
                records.append(InboxRecord(file: file, result: result))
            } catch {
                invalidOrExpired.append(file.url)
            }
        }
        try removePrivateRegularFiles(invalidOrExpired)

        records.sort {
            if $0.result.completedAt != $1.result.completedAt {
                return $0.result.completedAt > $1.result.completedAt
            }
            return $0.result.id.uuidString < $1.result.id.uuidString
        }
        var retained: [ScheduledResult] = []
        var removedForLimits: [URL] = []
        var retainedBytes = 0
        for record in records {
            if retained.count < inboxRetentionPolicy.maximumRecords,
               retainedBytes <= inboxRetentionPolicy.maximumBytes - record.file.bytes {
                retained.append(record.result)
                retainedBytes += record.file.bytes
            } else {
                removedForLimits.append(record.file.url)
            }
        }
        try removePrivateRegularFiles(removedForLimits)
        cachedInboxCount = retained.count
        return retained
    }

    private func enumerateInboxFiles(cleanTemporaryFiles: Bool) throws -> [InboxFile] {
        var files: [InboxFile] = []
        var temporaryFiles: [URL] = []
        try scanDirectory(
            at: inboxDirectory,
            maximumEntries: directoryScanLimits.maximumInboxEntries
        ) { url in
            let name = url.lastPathComponent
            if name.hasPrefix(".writing-"),
               canonicalUUID(String(name.dropFirst(".writing-".count))) != nil {
                try requireRegularFile(url)
                temporaryFiles.append(url)
                return
            }
            guard url.pathExtension == "json",
                  let id = canonicalUUID(url.deletingPathExtension().lastPathComponent) else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            var value = stat()
            guard lstat(url.path, &value) == 0,
                  (value.st_mode & S_IFMT) == S_IFREG,
                  value.st_uid == geteuid(),
                  value.st_nlink == 1,
                  (value.st_mode & 0o077) == 0,
                  value.st_size >= 0,
                  value.st_size <= off_t(Self.maximumDocumentBytes) else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            files.append(InboxFile(
                url: url,
                id: id,
                bytes: Int(value.st_size),
                modifiedAt: Date(timeIntervalSince1970: TimeInterval(value.st_mtimespec.tv_sec))
            ))
        }
        if cleanTemporaryFiles {
            try removePrivateRegularFiles(temporaryFiles)
        } else if !temporaryFiles.isEmpty {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        return files
    }

    private func canonicalUUID(_ value: String) -> UUID? {
        guard let id = UUID(uuidString: value),
              id.uuidString.caseInsensitiveCompare(value) == .orderedSame else { return nil }
        return id
    }

    private func fastInboxFilenameCount() throws -> Int {
        min(
            try enumerateInboxFiles(cleanTemporaryFiles: true).count,
            inboxRetentionPolicy.maximumRecords
        )
    }

    private func removePrivateRegularFiles(_ urls: [URL]) throws {
        guard !urls.isEmpty else { return }
        for url in urls {
            try requireRegularFile(url)
        }
        for url in urls {
            guard unlink(url.path) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        }
        let descriptor = open(inboxDirectory.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
    }

    private func withInboxLock<T>(_ operation: () throws -> T) rethrows -> T {
        inboxLock.lock()
        defer { inboxLock.unlock() }
        return try operation()
    }

    private func occurrenceURL(id: UUID) -> URL {
        occurrenceDirectory.appendingPathComponent("\(id.uuidString).json", isDirectory: false)
    }

    private func enumerateOccurrenceReceipts(
        cleanTemporaryFiles: Bool
    ) throws -> [ScheduleOccurrenceReceipt] {
        try prepareDirectory(occurrenceDirectory)
        var receipts: [ScheduleOccurrenceReceipt] = []
        var temporaryFiles: [URL] = []
        var aggregateBytes = 0
        try scanDirectory(
            at: occurrenceDirectory,
            maximumEntries: directoryScanLimits.maximumOccurrenceEntries
        ) { url in
            let name = url.lastPathComponent
            if name.hasPrefix(".writing-"),
               canonicalUUID(String(name.dropFirst(".writing-".count))) != nil {
                try requireRegularFile(url)
                temporaryFiles.append(url)
                return
            }
            guard url.pathExtension == "json",
                  let id = canonicalUUID(url.deletingPathExtension().lastPathComponent) else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            var value = stat()
            guard lstat(url.path, &value) == 0,
                  (value.st_mode & S_IFMT) == S_IFREG,
                  value.st_uid == geteuid(),
                  value.st_nlink == 1,
                  (value.st_mode & 0o077) == 0,
                  value.st_size >= 0,
                  value.st_size <= off_t(Self.maximumDocumentBytes) else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            let fileBytes = Int(value.st_size)
            guard receipts.count < Self.maximumScheduleCount,
                  fileBytes <= Self.maximumInboxBytes,
                  aggregateBytes <= Self.maximumInboxBytes - fileBytes else {
                throw ScheduleDocumentStoreError.documentTooLarge
            }
            aggregateBytes += fileBytes
            let receipt: ScheduleOccurrenceReceipt
            do {
                receipt = try decoder.decode(
                    ScheduleOccurrenceReceipt.self,
                    from: readPrivateRegularFile(url)
                )
            } catch let error as ScheduleDocumentStoreError {
                throw error
            } catch {
                throw ScheduleDocumentStoreError.invalidDocument
            }
            guard receipt.id == id else { throw ScheduleDocumentStoreError.invalidDocument }
            receipts.append(receipt)
        }
        if cleanTemporaryFiles {
            try removeOccurrenceFiles(temporaryFiles)
        } else if !temporaryFiles.isEmpty {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        return receipts.sorted { $0.id.uuidString < $1.id.uuidString }
    }

    /// Streams a single private directory without first materializing all of
    /// its names. Both budgets include unknown and temporary entries so an
    /// attacker cannot hide work outside the records eventually decoded.
    private func scanDirectory(
        at directory: URL,
        maximumEntries: Int,
        visit: (URL) throws -> Void
    ) throws {
        let startedAt = directoryScanNow()
        let requestedNanoseconds = directoryScanLimits.deadlineSeconds * 1_000_000_000
        guard requestedNanoseconds.isFinite, requestedNanoseconds > 0 else {
            throw ScheduleDocumentStoreError.directoryScanTimedOut
        }
        let durationNanoseconds = requestedNanoseconds >= Double(UInt64.max)
            ? UInt64.max
            : UInt64(requestedNanoseconds.rounded(.up))
        let deadlineResult = startedAt.addingReportingOverflow(durationNanoseconds)
        let deadline = deadlineResult.overflow ? UInt64.max : deadlineResult.partialValue

        let descriptor = open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else { throw ScheduleDocumentStoreError.unsafeStorage }

        var initial = stat()
        guard fstat(descriptor, &initial) == 0,
              isPrivateOwnedDirectory(initial) else {
            close(descriptor)
            throw ScheduleDocumentStoreError.unsafeStorage
        }

        guard let stream = fdopendir(descriptor) else {
            close(descriptor)
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        var streamOpen = true
        defer {
            if streamOpen { closedir(stream) }
        }

        var observedEntries = 0
        while true {
            guard directoryScanNow() <= deadline else {
                throw ScheduleDocumentStoreError.directoryScanTimedOut
            }
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
                break
            }
            guard directoryScanNow() <= deadline else {
                throw ScheduleDocumentStoreError.directoryScanTimedOut
            }
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            if name == "." || name == ".." { continue }
            guard observedEntries < maximumEntries else {
                throw ScheduleDocumentStoreError.directoryEntryLimitExceeded(maximumEntries)
            }
            observedEntries += 1
            try visit(directory.appendingPathComponent(name, isDirectory: false))
        }

        var final = stat()
        var current = stat()
        guard fstat(descriptor, &final) == 0,
              isPrivateOwnedDirectory(final),
              final.st_dev == initial.st_dev,
              final.st_ino == initial.st_ino,
              lstat(directory.path, &current) == 0,
              isPrivateOwnedDirectory(current),
              current.st_dev == initial.st_dev,
              current.st_ino == initial.st_ino else {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        guard closedir(stream) == 0 else {
            streamOpen = false
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        streamOpen = false
    }

    private func isPrivateOwnedDirectory(_ value: stat) -> Bool {
        (value.st_mode & S_IFMT) == S_IFDIR &&
            value.st_uid == geteuid() &&
            value.st_nlink >= 1 &&
            (value.st_mode & 0o077) == 0
    }

    private func removeOccurrenceFiles(_ urls: [URL]) throws {
        guard !urls.isEmpty else { return }
        for url in urls { try requireRegularFile(url) }
        for url in urls {
            guard unlink(url.path) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        }
        let descriptor = open(occurrenceDirectory.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
    }

    private func withOccurrenceLock<T>(_ operation: () throws -> T) rethrows -> T {
        occurrenceLock.lock()
        defer { occurrenceLock.unlock() }
        return try operation()
    }

    private func prepareDirectory(_ url: URL) throws {
        if fileManager.fileExists(atPath: url.path) {
            var value = stat()
            guard lstat(url.path, &value) == 0,
                  (value.st_mode & S_IFMT) == S_IFDIR,
                  value.st_uid == geteuid() else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
        } else {
            try fileManager.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        guard chmod(url.path, 0o700) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        var secured = stat()
        guard lstat(url.path, &secured) == 0,
              (secured.st_mode & S_IFMT) == S_IFDIR,
              secured.st_uid == geteuid(),
              (secured.st_mode & 0o077) == 0 else {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
    }

    private func requireRegularFile(_ url: URL) throws {
        var value = stat()
        guard lstat(url.path, &value) == 0,
              (value.st_mode & S_IFMT) == S_IFREG,
              value.st_uid == geteuid(),
              value.st_nlink == 1,
              (value.st_mode & 0o077) == 0 else {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
    }

    private func readPrivateRegularFile(_ url: URL) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        defer { close(descriptor) }

        var value = stat()
        guard fstat(descriptor, &value) == 0,
              (value.st_mode & S_IFMT) == S_IFREG,
              value.st_uid == geteuid(),
              value.st_nlink == 1,
              (value.st_mode & 0o077) == 0 else {
            throw ScheduleDocumentStoreError.unsafeStorage
        }
        guard value.st_size >= 0, value.st_size <= off_t(Self.maximumDocumentBytes) else {
            throw ScheduleDocumentStoreError.documentTooLarge
        }

        let expected = Int(value.st_size)
        var bytes = [UInt8](repeating: 0, count: expected)
        var offset = 0
        while offset < expected {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress!.advanced(by: offset), expected - offset)
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            guard count > 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
            offset += count
        }
        var trailing: UInt8 = 0
        while true {
            let count = Darwin.read(descriptor, &trailing, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 0 else { throw ScheduleDocumentStoreError.documentTooLarge }
            break
        }
        return Data(bytes)
    }

    private func writePrivateAtomically(_ data: Data, to destination: URL) throws {
        let temporary = destination.deletingLastPathComponent().appendingPathComponent(
            ".writing-\(UUID().uuidString)",
            isDirectory: false
        )
        let descriptor = open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600
        )
        guard descriptor >= 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        var descriptorOpen = true
        defer {
            if descriptorOpen { close(descriptor) }
            unlink(temporary.path)
        }

        do {
            try data.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(
                        descriptor,
                        buffer.baseAddress!.advanced(by: offset),
                        buffer.count - offset
                    )
                    if count < 0 {
                        if errno == EINTR { continue }
                        throw ScheduleDocumentStoreError.unsafeStorage
                    }
                    guard count > 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
                    offset += count
                }
            }
            guard fsync(descriptor) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
            let closeResult = close(descriptor)
            descriptorOpen = false
            guard closeResult == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
            if pathExistsNoFollow(destination) { try requireRegularFile(destination) }
            guard rename(temporary.path, destination.path) == 0 else {
                throw ScheduleDocumentStoreError.unsafeStorage
            }
            let directoryDescriptor = open(
                destination.deletingLastPathComponent().path,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
            guard directoryDescriptor >= 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
            defer { close(directoryDescriptor) }
            guard fsync(directoryDescriptor) == 0 else { throw ScheduleDocumentStoreError.unsafeStorage }
        } catch {
            throw error
        }
    }

    private func pathExistsNoFollow(_ url: URL) -> Bool {
        var value = stat()
        return lstat(url.path, &value) == 0
    }
}
