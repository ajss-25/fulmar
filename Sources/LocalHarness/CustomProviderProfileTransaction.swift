import Foundation

struct CustomProviderModelDraft: Equatable, Sendable {
    let id: String
    let displayName: String
    let inputModalities: [ModelInputModality]
    let contextWindowTokens: Int
    let maxOutputTokens: Int

    init(
        id: String,
        displayName: String,
        inputModalities: [ModelInputModality],
        contextWindowTokens: Int = 32_768,
        maxOutputTokens: Int = 4_096
    ) {
        self.id = id
        self.displayName = displayName
        self.inputModalities = inputModalities
        self.contextWindowTokens = contextWindowTokens
        self.maxOutputTokens = maxOutputTokens
    }
}

struct CustomProviderProfileDraft: Equatable, Sendable {
    let providerID: String
    let displayName: String
    let wireProtocol: ProviderWireProtocol
    let baseURL: String
    let models: [CustomProviderModelDraft]
    let credentialReference: String?
    /// Write-only and never included in the settings profile or an error.
    let credentialValue: String?
    /// Explicit opt-in for a credential-free server. This mode is accepted
    /// only for a literal loopback or RFC1918/ULA address and is serialized so
    /// the reviewed runtime can suppress every API-key header deliberately.
    let unauthenticated: Bool

    init(
        providerID: String,
        displayName: String,
        wireProtocol: ProviderWireProtocol,
        baseURL: String,
        models: [CustomProviderModelDraft],
        credentialReference: String?,
        credentialValue: String?,
        unauthenticated: Bool = false
    ) {
        self.providerID = providerID
        self.displayName = displayName
        self.wireProtocol = wireProtocol
        self.baseURL = baseURL
        self.models = models
        self.credentialReference = credentialReference
        self.credentialValue = credentialValue
        self.unauthenticated = unauthenticated
    }
}

struct CustomProviderProfileResult: Equatable, Sendable {
    let provider: ProviderView
    let createdCredential: Bool
    let createdProfile: Bool
}

/// Exact raw-profile shape the native editor can replace without losing DSH
/// configuration it does not render. Anything outside this subset remains
/// usable and is deliberately routed to Harness settings for editing.
enum CustomProviderNativeEditingPolicy {
    private static let commonProfileKeys: Set<String> = [
        "displayName", "api", "baseURL", "models"
    ]
    private static let modelKeys: Set<String> = [
        "id", "name", "input", "contextWindow", "maxTokens"
    ]
    private static let supportedProtocols: Set<String> = [
        ProviderWireProtocol.openAICompletions.rawValue,
        ProviderWireProtocol.openAIResponses.rawValue,
        ProviderWireProtocol.anthropicMessages.rawValue
    ]

    static func isSafelyEditableProfile(_ value: HarnessJSONValue?) -> Bool {
        guard let object = value?.objectValue else { return false }
        let hasCredential = object["apiKeyEnv"]?.stringValue?.isEmpty == false
        let explicitlyUnauthenticated = object["unauthenticated"] == .bool(true)
        guard hasCredential != explicitlyUnauthenticated else { return false }

        var expectedKeys = commonProfileKeys
        expectedKeys.insert(hasCredential ? "apiKeyEnv" : "unauthenticated")
        guard Set(object.keys) == expectedKeys,
              object["displayName"]?.stringValue?.isEmpty == false,
              let protocolID = object["api"]?.stringValue,
              supportedProtocols.contains(protocolID),
              object["baseURL"]?.stringValue?.isEmpty == false,
              case .array(let models)? = object["models"],
              (1...128).contains(models.count) else { return false }

        return models.allSatisfy { value in
            guard let model = value.objectValue,
                  Set(model.keys) == modelKeys,
                  model["id"]?.stringValue?.isEmpty == false,
                  model["name"]?.stringValue?.isEmpty == false,
                  case .array(let inputs)? = model["input"],
                  !inputs.isEmpty,
                  inputs.allSatisfy({ $0.stringValue != nil }),
                  case .integer(let context)? = model["contextWindow"],
                  case .integer(let output)? = model["maxTokens"] else { return false }
            return context >= 1_024 && output >= 256 && output <= context
        }
    }
}

enum CustomProviderProfileFailure: Error, Equatable, LocalizedError, Sendable {
    case invalidProviderID
    case builtInProviderReserved
    case invalidDisplayName
    case invalidProtocol
    case invalidEndpoint
    case anthropicVersionPathNotAllowed
    case unauthenticatedEndpointNotAllowed
    case invalidModels
    case invalidCredentialReference
    case credentialRequired
    case credentialStateUnavailable
    case credentialWriteNotVerified
    case credentialManagedElsewhere
    case credentialReplacementRequiresSeparateAction
    case settingsUnavailable
    case settingsReadOnly
    case settingsRestartRequired
    case settingsConflict
    case profileManagedExternally
    case mutationNotVerified
    case providerNotReady
    case runtimeFailure
    case cancelled

    var errorDescription: String? {
        switch self {
        case .invalidProviderID: return "Enter a provider ID between 1 and 256 bytes without control characters."
        case .builtInProviderReserved: return "Built-in provider IDs cannot be replaced by a custom profile."
        case .invalidDisplayName: return "Enter a provider name between 1 and 256 bytes."
        case .invalidProtocol: return "Choose one of the three reviewed provider protocols."
        case .invalidEndpoint: return "Enter an HTTPS base URL, or HTTP only for a literal loopback or private-network address. User info, query parameters, and fragments are not allowed."
        case .anthropicVersionPathNotAllowed: return "Anthropic Messages base URLs must stop before /v1 because the SDK appends /v1/messages. For the official service, use https://api.anthropic.com."
        case .unauthenticatedEndpointNotAllowed: return "No authentication is allowed only for a literal loopback, RFC 1918, or IPv6 ULA address. Cloud hosts and localhost names require a credential."
        case .invalidModels: return "Declare 1–128 unique models with bounded IDs, names, and text or text,image input only. Audio and video are not supported by this custom-provider path."
        case .invalidCredentialReference: return "Credential references must be 1–256 characters using A–Z, 0–9, and underscore."
        case .credentialRequired: return "Enter a credential reference and its API key, or explicitly choose no authentication for an eligible literal private address."
        case .credentialStateUnavailable: return "Harness did not expose the declared credential state."
        case .credentialWriteNotVerified: return "The newly created credential could not be verified."
        case .credentialManagedElsewhere: return "Harness reports that this credential cannot be changed from the app."
        case .credentialReplacementRequiresSeparateAction: return "Replace an existing API key as a separate explicit key-only action."
        case .settingsUnavailable: return "Harness did not expose the writable llm-pi-ai provider namespace."
        case .settingsReadOnly: return "Harness reports that provider settings are read-only."
        case .settingsRestartRequired: return "Harness cannot apply this provider profile live."
        case .settingsConflict: return "Provider settings changed concurrently. Review the latest profile and try again."
        case .profileManagedExternally: return "This provider profile contains advanced or externally managed settings that Fulmar cannot edit losslessly. Open Harness Provider Settings to change it."
        case .mutationNotVerified: return "Harness did not retain the exact custom provider profile."
        case .providerNotReady: return "Harness did not round-trip the exact configured provider endpoint, protocol, and model catalog after the change. The endpoint was not contacted."
        case .runtimeFailure: return "The authenticated Harness control plane could not complete the provider change."
        case .cancelled: return "The custom provider change was cancelled."
        }
    }
}

struct CustomProviderProfileTransactionError: Error, Equatable, LocalizedError, Sendable {
    let cause: CustomProviderProfileFailure
    let rollbackComplete: Bool

    var errorDescription: String? {
        let rollback = rollbackComplete
            ? "The previous provider profile and credential state were retained."
            : "Rollback could not be fully verified; network access remains blocked."
        return "\(cause.localizedDescription) \(rollback)"
    }
}

protocol CustomProviderProfileEditing: Sendable {
    func save(_ draft: CustomProviderProfileDraft) async throws -> CustomProviderProfileResult
}

enum ProviderStateMutationSafetyPolicy {
    /// Serializes every provider-profile, activation, and credential mutation
    /// behind the host's real quiescence barrier. New and inactive providers
    /// are included because another UI or a persisted schedule can select them
    /// while an authenticated settings transaction is suspended.
    @MainActor
    static func performMutation<Result>(
        targetProvider: ProviderID,
        prepare: @MainActor (ProviderID) async throws -> Void,
        mutation: @MainActor () async throws -> Result
    ) async throws -> Result {
        try await prepare(targetProvider)
        return try await mutation()
    }
}

/// Transactional native editor for one bounded pi-ai custom profile. It may
/// create a missing Keychain credential but never reads or replaces an existing
/// value. Profile mutation and any newly-created key are rolled back together
/// unless the live catalog round-trips the exact configured
/// protocol/origin/models. This is configuration verification, not an endpoint
/// request; authentication, protocol behavior, and quota remain unverified
/// until the user runs a test task.
actor CustomProviderProfileTransaction: CustomProviderProfileEditing {
    private struct Validated: Sendable {
        let providerID: ProviderID
        let displayName: String
        let wireProtocol: ProviderWireProtocol
        let baseURL: URL
        let models: [CustomProviderModelDraft]
        let credentialReference: CredentialReference?
        let credentialValue: String?
        let explicitlyUnauthenticated: Bool
        let profile: HarnessJSONValue
    }

    private let service: any HarnessProviderActivationServicing
    private let catalog: any ProviderCatalogLoading
    private let catalogAttempts: Int
    private let catalogRetryNanoseconds: UInt64

    init(
        service: any HarnessProviderActivationServicing,
        catalog: any ProviderCatalogLoading,
        catalogAttempts: Int = 12,
        catalogRetryNanoseconds: UInt64 = 50_000_000
    ) {
        self.service = service
        self.catalog = catalog
        self.catalogAttempts = max(1, catalogAttempts)
        self.catalogRetryNanoseconds = catalogRetryNanoseconds
    }

    func save(_ draft: CustomProviderProfileDraft) async throws -> CustomProviderProfileResult {
        let validated: Validated
        do { validated = try Self.validate(draft) }
        catch let failure as CustomProviderProfileFailure {
            throw CustomProviderProfileTransactionError(cause: failure, rollbackComplete: true)
        }

        var createdCredential: CredentialReference?
        // Installed before the one-way setter is called: its response can be
        // lost after the Keychain write has already committed.
        var credentialMutationToRollback: CredentialReference?
        var previousProfile: HarnessJSONValue?
        var appliedRevision: Int?
        var mutationAttempted = false
        var createdProfile = false
        var currentFailure = CustomProviderProfileFailure.runtimeFailure
        do {
            // Refuse a lossy edit before any Keychain operation and retain
            // this exact profile plus revision through the mutation. Adopting
            // a later revision after credential preparation would mask a
            // concurrent settings edit and overwrite another writer.
            currentFailure = .settingsUnavailable
            let preflight = try await service.describeSettings()
            guard preflight.hasDocument else { throw CustomProviderProfileFailure.settingsUnavailable }
            guard preflight.writable else { throw CustomProviderProfileFailure.settingsReadOnly }
            guard let preflightNamespace = preflight.namespaces.first(where: { $0.ns == "llm-pi-ai" }) else {
                throw CustomProviderProfileFailure.settingsUnavailable
            }
            guard preflightNamespace.applies == .live else {
                throw CustomProviderProfileFailure.settingsRestartRequired
            }
            let path = ["providers", validated.providerID.rawValue]
            previousProfile = Self.persistedValue(at: path, in: preflightNamespace)
            createdProfile = previousProfile == nil
            if let existing = previousProfile,
               !CustomProviderNativeEditingPolicy.isSafelyEditableProfile(existing) {
                throw CustomProviderProfileFailure.profileManagedExternally
            }

            if let reference = validated.credentialReference {
                currentFailure = .credentialStateUnavailable
                let description = try await service.describeCredentials([reference])
                guard let state = description.credentials[reference.rawValue] else {
                    throw CustomProviderProfileFailure.credentialStateUnavailable
                }
                let supplied = validated.credentialValue?.trimmingCharacters(in: .whitespacesAndNewlines)
                if state.configured, supplied?.isEmpty == false {
                    throw CustomProviderProfileFailure.credentialReplacementRequiresSeparateAction
                }
                if !state.configured {
                    guard state.writable else { throw CustomProviderProfileFailure.credentialManagedElsewhere }
                    guard let supplied, !supplied.isEmpty,
                          supplied.utf8.count <= 32 * 1_024,
                          !supplied.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                        throw CustomProviderProfileFailure.credentialRequired
                    }
                    credentialMutationToRollback = reference
                    currentFailure = .credentialWriteNotVerified
                    try await service.setCredential(reference, value: supplied)
                    let verified = try await service.describeCredentials([reference])
                    guard verified.credentials[reference.rawValue]?.configured == true else {
                        throw CustomProviderProfileFailure.credentialWriteNotVerified
                    }
                    createdCredential = reference
                }
            }

            mutationAttempted = true
            currentFailure = .mutationNotVerified
            let updated = try await service.mutateSettings(
                namespace: preflightNamespace.ns,
                operations: [.set(path: path, value: validated.profile)],
                expectedRevision: preflightNamespace.revision
            )
            guard updated.ns == preflightNamespace.ns,
                  updated.applies == .live,
                  Self.persistedValue(at: path, in: updated) == validated.profile else {
                throw CustomProviderProfileFailure.mutationNotVerified
            }

            // A mutation response is not durable proof. Re-read the settings
            // document through the authenticated control plane and bind any
            // later rollback to that exact observed revision before allowing
            // the provider to become selectable.
            let roundTrip = try await service.describeSettings()
            guard roundTrip.hasDocument,
                  roundTrip.writable,
                  let roundTripNamespace = roundTrip.namespaces.first(where: { $0.ns == preflightNamespace.ns }),
                  roundTripNamespace.applies == .live,
                  Self.persistedValue(at: path, in: roundTripNamespace) == validated.profile else {
                throw CustomProviderProfileFailure.mutationNotVerified
            }
            appliedRevision = roundTripNamespace.revision

            currentFailure = .providerNotReady
            let provider = try await waitForExactProviderConfiguration(validated)
            return .init(
                provider: provider,
                createdCredential: createdCredential != nil,
                createdProfile: createdProfile
            )
        } catch {
            let settingsMutationWasRejected: Bool
            let failure: CustomProviderProfileFailure
            if error is CancellationError || Task.isCancelled {
                settingsMutationWasRejected = false
                failure = .cancelled
            } else if let rpcError = error as? HarnessRPCClientError,
                      case .remote(let remote) = rpcError,
                      remote.code == .settingsConflict {
                settingsMutationWasRejected = true
                failure = .settingsConflict
            } else {
                settingsMutationWasRejected = false
                failure = (error as? CustomProviderProfileFailure) ?? currentFailure
            }
            // Rollback must not inherit cancellation from the editor task;
            // URLSession otherwise aborts the very calls needed to restore the
            // previous settings and remove a newly-created credential.
            let rollbackPreviousProfile = previousProfile
            let rollbackAppliedRevision = appliedRevision
            // A typed settings conflict proves DSH rejected the write before
            // applying it. Preserve the legitimate concurrent profile while
            // still rolling back any credential this transaction created.
            let rollbackMutationAttempted = mutationAttempted && !settingsMutationWasRejected
            let rollbackCredential = credentialMutationToRollback
            let rollbackComplete = await Task.detached { [self] in
                await rollback(
                    validated: validated,
                    previousProfile: rollbackPreviousProfile,
                    appliedRevision: rollbackAppliedRevision,
                    mutationAttempted: rollbackMutationAttempted,
                    createdCredential: rollbackCredential
                )
            }.value
            throw CustomProviderProfileTransactionError(cause: failure, rollbackComplete: rollbackComplete)
        }
    }

    private func waitForExactProviderConfiguration(_ validated: Validated) async throws -> ProviderView {
        let expectedModels = Dictionary(uniqueKeysWithValues: validated.models.map {
            (ModelID($0.id), (
                $0.displayName,
                $0.inputModalities,
                $0.contextWindowTokens,
                $0.maxOutputTokens
            ))
        })
        for attempt in 0..<catalogAttempts {
            try Task.checkCancellation()
            if let snapshot = try? await catalog.loadCatalog(),
               let provider = snapshot.provider(validated.providerID),
               provider.configurationState == .ready,
               provider.descriptor.defaultBaseURL == validated.baseURL,
               provider.descriptor.wireProtocol == validated.wireProtocol,
               provider.descriptor.credentialReference == validated.credentialReference,
               provider.descriptor.explicitlyUnauthenticated == validated.explicitlyUnauthenticated,
               provider.descriptor.supportsNativeProfileEditing,
               provider.models.count == expectedModels.count,
               provider.models.allSatisfy({ model in
                   guard let expected = expectedModels[model.id] else { return false }
                   return model.displayName == expected.0
                       && model.capabilities.inputModalities == expected.1
                       && model.capabilities.contextWindowTokens == expected.2
                       && model.capabilities.maxOutputTokens == expected.3
               }) {
                return provider
            }
            if attempt + 1 < catalogAttempts, catalogRetryNanoseconds > 0 {
                try await Task.sleep(nanoseconds: catalogRetryNanoseconds)
            }
        }
        throw CustomProviderProfileFailure.providerNotReady
    }

    private func rollback(
        validated: Validated,
        previousProfile: HarnessJSONValue?,
        appliedRevision: Int?,
        mutationAttempted: Bool,
        createdCredential: CredentialReference?
    ) async -> Bool {
        var complete = true
        if mutationAttempted {
            do {
                let path = ["providers", validated.providerID.rawValue]
                var revision = appliedRevision
                if revision == nil {
                    let settings = try await service.describeSettings()
                    guard let namespace = settings.namespaces.first(where: { $0.ns == "llm-pi-ai" }) else {
                        throw CustomProviderProfileFailure.settingsUnavailable
                    }
                    let current = Self.persistedValue(at: path, in: namespace)
                    if current == previousProfile {
                        revision = nil
                    } else {
                        guard current == validated.profile else { throw CustomProviderProfileFailure.mutationNotVerified }
                        revision = namespace.revision
                    }
                }
                if let revision {
                    let operation: HarnessSettingsPathOperation = previousProfile.map {
                        .set(path: path, value: $0)
                    } ?? .unset(path: path)
                    let restored = try await service.mutateSettings(
                        namespace: "llm-pi-ai",
                        operations: [operation],
                        expectedRevision: revision
                    )
                    guard restored.ns == "llm-pi-ai",
                          Self.persistedValue(at: path, in: restored) == previousProfile else {
                        throw CustomProviderProfileFailure.mutationNotVerified
                    }
                }
            } catch { complete = false }
        }
        if let createdCredential {
            do {
                try await service.unsetCredential(createdCredential)
                let state = try await service.describeCredentials([createdCredential])
                guard state.credentials[createdCredential.rawValue]?.configured == false else { throw CustomProviderProfileFailure.credentialRequired }
            } catch { complete = false }
        }
        return complete
    }

    private static func validate(_ draft: CustomProviderProfileDraft) throws -> Validated {
        func safe(_ raw: String, maximumBytes: Int) -> String? {
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, value.utf8.count <= maximumBytes,
                  !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { return nil }
            return value
        }
        guard let providerRaw = safe(draft.providerID, maximumBytes: 256) else { throw CustomProviderProfileFailure.invalidProviderID }
        let providerID = ProviderID(providerRaw)
        guard !BuiltInProviderDescriptors.all.contains(where: { $0.id == providerID }) else {
            throw CustomProviderProfileFailure.builtInProviderReserved
        }
        guard let displayName = safe(draft.displayName, maximumBytes: 256) else { throw CustomProviderProfileFailure.invalidDisplayName }
        let supportedProtocols: Set<ProviderWireProtocol> = [.openAICompletions, .openAIResponses, .anthropicMessages]
        guard supportedProtocols.contains(draft.wireProtocol) else { throw CustomProviderProfileFailure.invalidProtocol }
        guard draft.baseURL.utf8.count <= 2_048,
              let components = URLComponents(string: draft.baseURL.trimmingCharacters(in: .whitespacesAndNewlines)),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let baseURL = components.url,
              ProviderNetworkOrigin(url: baseURL) != nil else {
            throw CustomProviderProfileFailure.invalidEndpoint
        }
        if draft.wireProtocol == .anthropicMessages,
           baseURL.pathComponents.last?.lowercased() == "v1" {
            throw CustomProviderProfileFailure.anthropicVersionPathNotAllowed
        }
        guard (1...128).contains(draft.models.count) else { throw CustomProviderProfileFailure.invalidModels }
        var modelIDs = Set<String>()
        var models: [CustomProviderModelDraft] = []
        for model in draft.models {
            guard let id = safe(model.id, maximumBytes: 512),
                  let name = safe(model.displayName, maximumBytes: 256),
                  modelIDs.insert(id).inserted,
                  !model.inputModalities.isEmpty,
                  model.inputModalities.count <= ModelInputModality.allCases.count,
                  Set(model.inputModalities).count == model.inputModalities.count,
                  model.inputModalities.contains(.text),
                  model.inputModalities.allSatisfy({ $0 == .text || $0 == .image }),
                  (1_024...16_777_216).contains(model.contextWindowTokens),
                  (256...model.contextWindowTokens).contains(model.maxOutputTokens) else {
                throw CustomProviderProfileFailure.invalidModels
            }
            models.append(.init(
                id: id,
                displayName: name,
                inputModalities: model.inputModalities,
                contextWindowTokens: model.contextWindowTokens,
                maxOutputTokens: model.maxOutputTokens
            ))
        }
        let credentialReference: CredentialReference?
        if draft.unauthenticated {
            guard ProviderNetworkOrigin.isLiteralPrivateOrLoopback(baseURL),
                  draft.credentialReference?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false,
                  draft.credentialValue?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false else {
                throw CustomProviderProfileFailure.unauthenticatedEndpointNotAllowed
            }
            credentialReference = nil
        } else if let raw = draft.credentialReference?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            guard raw.utf8.count <= 256,
                  raw.first?.isLetter == true,
                  raw.unicodeScalars.allSatisfy({ scalar in
                      scalar.isASCII && ((65...90).contains(scalar.value) || (48...57).contains(scalar.value) || scalar.value == 95)
                  }) else { throw CustomProviderProfileFailure.invalidCredentialReference }
            credentialReference = CredentialReference(raw)
        } else {
            throw CustomProviderProfileFailure.credentialRequired
        }

        var profile: [String: HarnessJSONValue] = [
            "displayName": .string(displayName),
            "api": .string(draft.wireProtocol.rawValue),
            "baseURL": .string(baseURL.absoluteString),
            "models": .array(models.map { model in
                .object([
                    "id": .string(model.id),
                    "name": .string(model.displayName),
                    "input": .array(model.inputModalities.map { .string($0.rawValue) }),
                    "contextWindow": .integer(Int64(model.contextWindowTokens)),
                    "maxTokens": .integer(Int64(model.maxOutputTokens))
                ])
            })
        ]
        if let credentialReference { profile["apiKeyEnv"] = .string(credentialReference.rawValue) }
        if draft.unauthenticated { profile["unauthenticated"] = .bool(true) }
        let profileValue = HarnessJSONValue.object(profile)
        guard let encoded = try? JSONEncoder().encode(profileValue), encoded.count <= 1_048_576 else {
            throw CustomProviderProfileFailure.invalidModels
        }
        return Validated(
            providerID: providerID,
            displayName: displayName,
            wireProtocol: draft.wireProtocol,
            baseURL: baseURL,
            models: models,
            credentialReference: credentialReference,
            credentialValue: draft.credentialValue,
            explicitlyUnauthenticated: draft.unauthenticated,
            profile: profileValue
        )
    }

    private static func persistedValue(
        at path: [String],
        in namespace: HarnessSettingsNamespace
    ) -> HarnessJSONValue? {
        if let user = namespace.user { return value(at: path, in: user) }
        return value(at: path, in: namespace.value)
    }

    private static func value(at path: [String], in root: HarnessJSONValue) -> HarnessJSONValue? {
        var current = root
        for component in path {
            guard case .object(let object) = current, let next = object[component] else { return nil }
            current = next
        }
        return current
    }
}
