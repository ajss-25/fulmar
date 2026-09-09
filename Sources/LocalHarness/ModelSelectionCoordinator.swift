import Foundation

/// Narrow seam used by model selection. Keeping this protocol below the UI
/// makes the coordinator deterministic in tests and leaves DSH as the only
/// authority that can list or change an actual route.
protocol HarnessModelRPCServicing: Sendable {
    func llmProviders() async throws -> HarnessProviderDirectory
    func llmModels() async throws -> HarnessModelCatalog
    func describeSettings() async throws -> HarnessSettingsDescription
    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace
    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels
    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection
}

extension HarnessRPCClient: HarnessModelRPCServicing {}

struct HarnessModelCatalogSnapshot: Equatable, Sendable {
    let providers: [ProviderView]

    func provider(_ id: ProviderID) -> ProviderView? {
        providers.first { $0.id == id }
    }
}

struct HarnessSessionSelectionState: Equatable, Sendable {
    let selection: HarnessWireModelSelection
    let routable: Bool
    let boundary: DataBoundary
    let groups: [HarnessModelProviderGroup]
    let failures: [HarnessModelCatalogFailure]
}

struct HarnessModelSelectionOutcome: Equatable, Sendable {
    let selection: HarnessWireModelSelection
    let boundary: DataBoundary
}

/// Exact adapter-owned limits which DSH has accepted for one local route.
/// Context is route-global in DSH; per-session performance identities only
/// select an output cap because concurrent sessions cannot safely rewrite one
/// shared adapter model to different capacities.
struct HarnessLocalPerformanceCapability: Equatable, Sendable {
    let route: ModelRoute
    let contextWindowTokens: Int
    let maxOutputTokens: Int
}

enum ModelSelectionCoordinatorError: Error, Equatable, LocalizedError {
    case settingsUnavailable
    case settingsReadOnly
    case invalidSelection
    case defaultVerificationFailed
    case localProviderBootstrapUnavailable
    case localProviderBootstrapNotLive
    case localProviderEndpointInvalid
    case localProviderBootstrapVerificationFailed
    case localPerformanceProviderUnavailable
    case localPerformanceSettingsNotLive
    case localPerformanceModelUnavailable
    case localPerformanceVerificationFailed

    var errorDescription: String? {
        switch self {
        case .settingsUnavailable:
            return "DeepSeek Harness did not expose its default-model settings."
        case .settingsReadOnly:
            return "DeepSeek Harness reports that its default-model settings are read-only."
        case .invalidSelection:
            return "The provider or model identifier is empty."
        case .defaultVerificationFailed:
            return "DeepSeek Harness did not retain the selected default provider, model, and reasoning mode."
        case .localProviderBootstrapUnavailable:
            return "DeepSeek Harness did not expose writable provider settings for the default local model."
        case .localProviderBootstrapNotLive:
            return "DeepSeek Harness cannot activate the default local provider without a restart."
        case .localProviderEndpointInvalid:
            return "The local provider endpoint is not the private loopback endpoint owned by this app."
        case .localProviderBootstrapVerificationFailed:
            return "DeepSeek Harness did not retain the reviewed loopback Ollama provider profile."
        case .localPerformanceProviderUnavailable:
            return "DeepSeek Harness did not expose one active llm-pi-ai settings route for the selected local provider."
        case .localPerformanceSettingsNotLive:
            return "DeepSeek Harness cannot apply the selected local context capacity without a restart."
        case .localPerformanceModelUnavailable:
            return "The selected local model is missing or ambiguous in DeepSeek Harness provider settings."
        case .localPerformanceVerificationFailed:
            return "DeepSeek Harness did not retain the selected local model context and output limits."
        }
    }
}

/// Maps DSH's separate provider/model identifiers into presentation types while
/// preserving the exact opaque values submitted back to DSH. Catalogs are
/// advisory; session state and mutations are always read from the runtime.
actor ModelSelectionCoordinator {
    private let service: any HarnessModelRPCServicing
    private let credentialService: (any HarnessProviderCredentialServicing)?
    private let policyDescriptors: [ProviderID: ProviderDescriptor]
    private let capabilityCatalog: any ModelCapabilityCatalogProviding
    private var latestCatalog: HarnessModelCatalogSnapshot?

    init(
        service: any HarnessModelRPCServicing,
        descriptors: [ProviderDescriptor] = BuiltInProviderDescriptors.all,
        credentialService: (any HarnessProviderCredentialServicing)? = nil,
        capabilityCatalog: any ModelCapabilityCatalogProviding = BundledModelCapabilityCatalog()
    ) {
        self.service = service
        self.credentialService = credentialService
        self.capabilityCatalog = capabilityCatalog
        policyDescriptors = descriptors.reduce(into: [:]) { result, descriptor in
            result[descriptor.id] = descriptor
        }
    }

    /// Loads provider topology and model catalogs from one logical refresh.
    /// Neither list is persisted as a routing decision.
    func loadCatalog() async throws -> HarnessModelCatalogSnapshot {
        async let providerDirectory = service.llmProviders()
        async let modelCatalog = service.llmModels()
        async let settings = service.describeSettings()
        var snapshot = Self.mapCatalog(
            directory: try await providerDirectory,
            catalog: try await modelCatalog,
            settings: try await settings,
            policyDescriptors: policyDescriptors,
            capabilityCatalog: capabilityCatalog
        )
        if let credentialService {
            let references = ProviderCredentialReadiness.requiredReferences(in: snapshot)
            if !references.isEmpty {
                // Credential inspection must fail closed for external routes,
                // but a Keychain/helper outage must never make an otherwise
                // healthy local Ollama catalog unavailable.
                let credentials = (try? await credentialService.describeCredentials(references))
                    ?? HarnessCredentialDescription(credentials: [:])
                snapshot = ProviderCredentialReadiness.applying(credentials, to: snapshot)
            }
        }
        latestCatalog = snapshot
        return snapshot
    }

    func cachedCatalog() -> HarnessModelCatalogSnapshot? { latestCatalog }

    /// Value-free setup affordances used only while the authenticated runtime
    /// is already in provider-recovery mode and its live catalog RPC failed.
    /// These descriptors are not a model catalog or routing authority: every
    /// provider is fail-closed, no model is exposed, and activation/selection
    /// must still be freshly verified against DSH before anything is saved.
    func providerRecoverySetupCatalog() -> HarnessModelCatalogSnapshot {
        HarnessModelCatalogSnapshot(
            providers: BuiltInProviderDescriptors.all.map { descriptor in
                ProviderView(
                    descriptor: descriptor,
                    configurationState: descriptor.boundary.isExternalToThisMac
                        ? .needsCredential : .dormant,
                    models: [],
                    failureMessage: nil
                )
            }
        )
    }

    /// Reconciles the reviewed Ollama route to this launch's PID-owned endpoint
    /// through DSH's authenticated, revision-checked settings service. A stale
    /// profile is intentionally replaced on every port change; no conventional
    /// system-wide Ollama endpoint is ever inherited or adopted.
    @discardableResult
    func synchronizeAppOwnedLocalProvider(
        _ selection: ModelSelection,
        providerBaseURL: URL
    ) async throws -> Bool {
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else { return false }
        guard OllamaModelNamePolicy.isSafe(selection.route.model.rawValue) else {
            throw ModelSelectionCoordinatorError.invalidSelection
        }
        guard AppOwnedOllamaEndpoint.validatingProviderBaseURL(providerBaseURL) != nil else {
            throw ModelSelectionCoordinatorError.localProviderEndpointInvalid
        }

        for attempt in 0..<2 {
            let description = try await service.describeSettings()
            guard description.writable else { throw ModelSelectionCoordinatorError.settingsReadOnly }
            guard let namespace = description.namespaces.first(where: { $0.ns == "llm-pi-ai" }) else {
                throw ModelSelectionCoordinatorError.localProviderBootstrapUnavailable
            }
            guard namespace.applies == .live else {
                throw ModelSelectionCoordinatorError.localProviderBootstrapNotLive
            }
            let profile = Self.reviewedLocalBootstrapProfile(
                selection: selection,
                providerBaseURL: providerBaseURL
            )
            // `value` is the schema-resolved layer and therefore contains
            // adapter defaults which were never persisted by this app. Trust
            // and compare only DSH's redacted raw `user` layer when deciding
            // whether our exact reviewed profile is already durable.
            if let user = namespace.user,
               let existing = Self.jsonValue(at: ["providers", "ollama"], in: user),
               Self.isReviewedLocalBootstrapProfile(
                   existing,
                   selection: selection,
                   providerBaseURL: providerBaseURL
               ) {
                return false
            }
            do {
                _ = try await service.mutateSettings(
                    namespace: namespace.ns,
                    operations: [.set(path: ["providers", "ollama"], value: profile)],
                    expectedRevision: namespace.revision
                )
            } catch let HarnessRPCClientError.remote(error)
                where error.code == .settingsConflict && attempt == 0 {
                continue
            }

            let verified = try await service.describeSettings()
            guard let verifiedNamespace = verified.namespaces.first(where: { $0.ns == namespace.ns }),
                  let verifiedUser = verifiedNamespace.user,
                  let stored = Self.jsonValue(at: ["providers", "ollama"], in: verifiedUser),
                  Self.isReviewedLocalBootstrapProfile(
                      stored,
                      selection: selection,
                      providerBaseURL: providerBaseURL
                  ) else {
                throw ModelSelectionCoordinatorError.localProviderBootstrapVerificationFailed
            }
            return true
        }
        throw ModelSelectionCoordinatorError.localProviderBootstrapUnavailable
    }

    /// Reads the session's current target from DSH every time. A model missing
    /// from the advisory groups may still be routable, so callers must honor the
    /// explicit `routable` value rather than infer it from catalog membership.
    func currentSelection(for sessionID: HarnessSessionID) async throws -> HarnessSessionSelectionState {
        let state = try await service.sessionModels(sessionID)
        return HarnessSessionSelectionState(
            selection: state.current,
            routable: state.routable,
            boundary: boundary(for: state.current.provider),
            groups: state.groups,
            failures: state.failures
        )
    }

    /// Selects one exact route for one exact session. The returned selection is
    /// the runtime-normalized response; no app default or cached session value is
    /// written here.
    func select(
        sessionID: HarnessSessionID,
        route: ModelRoute,
        reasoningEffort: String? = nil
    ) async throws -> HarnessModelSelectionOutcome {
        let selected = try await service.selectModel(
            sessionID: sessionID,
            selection: HarnessWireModelSelection(route: route, reasoningEffort: reasoningEffort)
        )
        return HarnessModelSelectionOutcome(
            selection: selected,
            boundary: boundary(for: selected.provider)
        )
    }

    /// Commits the same default that the DSH web app and headless/scheduled
    /// agents read. A single revision-conflict retry prevents a stale native
    /// catalog refresh from overwriting a newer settings edit.
    @discardableResult
    func synchronizeDefault(_ selection: ModelSelection) async throws -> HarnessSettingsNamespace {
        guard !selection.route.provider.rawValue.isEmpty,
              !selection.route.model.rawValue.isEmpty else {
            throw ModelSelectionCoordinatorError.invalidSelection
        }
        let operations: [HarnessSettingsPathOperation] = [
            .set(path: ["provider"], value: .string(selection.route.provider.rawValue)),
            .set(path: ["model"], value: .string(selection.route.model.rawValue)),
            selection.reasoningEffort.map {
                .set(path: ["reasoningEffort"], value: .string($0))
            } ?? .unset(path: ["reasoningEffort"])
        ]

        for attempt in 0..<2 {
            let description = try await service.describeSettings()
            guard description.writable else { throw ModelSelectionCoordinatorError.settingsReadOnly }
            guard let namespace = description.namespaces.first(where: { $0.ns == "agent-default-model" }) else {
                throw ModelSelectionCoordinatorError.settingsUnavailable
            }
            do {
                let updated = try await service.mutateSettings(
                    namespace: namespace.ns,
                    operations: operations,
                    expectedRevision: namespace.revision
                )
                guard updated.ns == namespace.ns,
                      Self.jsonValue(at: ["provider"], in: updated.value)?.stringValue == selection.route.provider.rawValue,
                      Self.jsonValue(at: ["model"], in: updated.value)?.stringValue == selection.route.model.rawValue else {
                    throw ModelSelectionCoordinatorError.defaultVerificationFailed
                }
                let returnedEffort = Self.jsonValue(at: ["reasoningEffort"], in: updated.value)
                if let requestedEffort = selection.reasoningEffort {
                    guard returnedEffort?.stringValue == requestedEffort else {
                        throw ModelSelectionCoordinatorError.defaultVerificationFailed
                    }
                } else if returnedEffort != nil, returnedEffort != .null {
                    throw ModelSelectionCoordinatorError.defaultVerificationFailed
                }
                return updated
            } catch let HarnessRPCClientError.remote(error)
                where error.code == .settingsConflict && attempt == 0 {
                continue
            }
        }
        throw ModelSelectionCoordinatorError.settingsUnavailable
    }

    /// Commits the selected app-wide local capacity into the exact llm-pi-ai
    /// model profile before any session is exposed. The mutation preserves the
    /// provider profile and every sibling model. For catalog-backed routes with
    /// no explicit model list, `modelOverrides` changes only the selected model
    /// without narrowing the catalog.
    ///
    /// The performance DSH plugin independently calls `resolveModelInfo` at
    /// every matching agent request, so a later settings drift fails before
    /// provider I/O rather than silently reverting compaction to a larger
    /// context window.
    @discardableResult
    func synchronizeLocalPerformanceCapability(
        _ selection: ModelSelection
    ) async throws -> HarnessLocalPerformanceCapability {
        guard !selection.route.provider.rawValue.isEmpty,
              !selection.route.model.rawValue.isEmpty else {
            throw ModelSelectionCoordinatorError.invalidSelection
        }
        let directory = try await service.llmProviders()
        let matches = directory.providers.filter {
            $0.provider == selection.route.provider && $0.active
        }
        guard matches.count == 1,
              let provider = matches.first,
              provider.settingsNs == "llm-pi-ai",
              !provider.settingsPath.isEmpty,
              !provider.settingsPath.contains(where: \.isEmpty) else {
            throw ModelSelectionCoordinatorError.localPerformanceProviderUnavailable
        }

        let expected = selection.effectivePerformanceSettings
        let result = HarnessLocalPerformanceCapability(
            route: selection.route,
            contextWindowTokens: expected.contextWindowTokens,
            maxOutputTokens: expected.maxOutputTokens
        )

        for attempt in 0..<2 {
            let description = try await service.describeSettings()
            guard description.writable else { throw ModelSelectionCoordinatorError.settingsReadOnly }
            guard let namespace = description.namespaces.first(where: { $0.ns == provider.settingsNs }) else {
                throw ModelSelectionCoordinatorError.settingsUnavailable
            }
            guard namespace.applies == .live else {
                throw ModelSelectionCoordinatorError.localPerformanceSettingsNotLive
            }
            let operation = try Self.localPerformanceMutation(
                namespace: namespace,
                providerPath: provider.settingsPath,
                model: selection.route.model,
                settings: expected
            )

            guard let operation else { return result }
            do {
                _ = try await service.mutateSettings(
                    namespace: namespace.ns,
                    operations: [operation],
                    expectedRevision: namespace.revision
                )
            } catch let HarnessRPCClientError.remote(error)
                where error.code == .settingsConflict && attempt == 0 {
                continue
            }

            let verified = try await service.describeSettings()
            guard let verifiedNamespace = verified.namespaces.first(where: { $0.ns == provider.settingsNs }),
                  let values = Self.localPerformanceValues(
                    namespace: verifiedNamespace,
                    providerPath: provider.settingsPath,
                    model: selection.route.model
                  ),
                  values.0 == expected.contextWindowTokens,
                  values.1 == expected.maxOutputTokens else {
                throw ModelSelectionCoordinatorError.localPerformanceVerificationFailed
            }
            return result
        }
        throw ModelSelectionCoordinatorError.settingsUnavailable
    }

    /// Unknown routes fail closed as cloud routes until the app is given an
    /// explicit descriptor (for example, a user-declared LAN endpoint).
    func dataBoundary(for provider: ProviderID) -> DataBoundary {
        boundary(for: provider)
    }

    private func boundary(for provider: ProviderID) -> DataBoundary {
        latestCatalog?.provider(provider)?.boundary ?? policyDescriptors[provider]?.boundary ?? .cloud
    }

    private static func mapCatalog(
        directory: HarnessProviderDirectory,
        catalog: HarnessModelCatalog,
        settings: HarnessSettingsDescription,
        policyDescriptors: [ProviderID: ProviderDescriptor],
        capabilityCatalog: any ModelCapabilityCatalogProviding
    ) -> HarnessModelCatalogSnapshot {
        var groups: [ProviderID: HarnessModelProviderGroup] = [:]
        for group in catalog.groups where groups[group.id] == nil { groups[group.id] = group }

        var failures: [ProviderID: HarnessModelCatalogFailure] = [:]
        for failure in catalog.failures where failures[failure.id] == nil { failures[failure.id] = failure }

        var orderedIDs: [ProviderID] = []
        var seen = Set<ProviderID>()
        for entry in directory.providers where seen.insert(entry.provider).inserted { orderedIDs.append(entry.provider) }
        for group in catalog.groups where seen.insert(group.id).inserted { orderedIDs.append(group.id) }
        for failure in catalog.failures where seen.insert(failure.id).inserted { orderedIDs.append(failure.id) }

        let directoryByID = directory.providers.reduce(into: [ProviderID: HarnessProviderDirectoryEntry]()) {
            if $0[$1.provider] == nil { $0[$1.provider] = $1 }
        }

        let views = orderedIDs.map { providerID -> ProviderView in
            let directoryEntry = directoryByID[providerID]
            let group = groups[providerID]
            let failure = failures[providerID]
            let descriptor = descriptor(
                providerID: providerID,
                directory: directoryEntry,
                group: group,
                settings: settings,
                policyDescriptor: policyDescriptors[providerID]
            )
            let models: [ModelView] = group?.models.map { model in
                let configuredLimits = configuredModelLimits(
                    directory: directoryEntry,
                    model: model.id,
                    settings: settings
                )
                let modalities = configuredInputModalities(
                    directory: directoryEntry,
                    adapterKind: descriptor.adapterKind,
                    model: model.id,
                    settings: settings
                ) ?? capabilityCatalog.inputModalities(provider: providerID, model: model.id)
                    ?? configuredDefaultInputModalities(
                        directory: directoryEntry,
                        adapterKind: descriptor.adapterKind,
                        settings: settings
                    )
                    ?? [ModelInputModality.text]
                return modelView(
                    model,
                    inputModalities: modalities,
                    contextWindowTokens: configuredLimits?.0,
                    maxOutputTokens: configuredLimits?.1
                )
            } ?? []
            let active = directoryEntry?.active ?? (group != nil)
            let rawProfile = directoryEntry.flatMap {
                configuredRawProfile(directory: $0, settings: settings)
            }
            let endpointInvalid = directoryEntry.map {
                configuredEndpointScalar(directory: $0, settings: settings) != nil && descriptor.defaultBaseURL == nil
            } ?? false
            let protocolInvalid = directoryEntry.map {
                configuredWireProtocolScalar(directory: $0, settings: settings) != nil
                    && wireProtocol(directory: $0, settings: settings) == nil
            } ?? false
            let authenticationInvalid = authenticationConfigurationIsInvalid(
                rawProfile: rawProfile,
                declared: directoryEntry?.declared == true,
                descriptor: descriptor
            )
            let unresolvedExternalEndpoint = descriptor.boundary.requiresExplicitConsent
                && descriptor.defaultBaseURL == nil
            let unavailable = endpointInvalid || protocolInvalid || authenticationInvalid
                || unresolvedExternalEndpoint
            let declaredCustomProviderNeedsCredential = policyDescriptors[providerID] == nil
                && directoryEntry?.declared == true
                && descriptor.authenticationMode == .providerNative
            let unavailableMessage: String?
            if endpointInvalid {
                unavailableMessage = "Configured endpoint is invalid or unsafe"
            } else if protocolInvalid {
                unavailableMessage = "Configured provider protocol has not been reviewed"
            } else if authenticationInvalid {
                unavailableMessage = "Configured provider authentication is invalid or unsafe"
            } else if unresolvedExternalEndpoint {
                unavailableMessage = "Provider endpoint is not exposed, so exact-origin consent cannot be verified"
            } else {
                unavailableMessage = failure?.message
            }
            return ProviderView(
                descriptor: descriptor,
                configurationState: unavailable ? .unavailable
                    : (declaredCustomProviderNeedsCredential ? .needsCredential
                        : (active ? .ready : .dormant)),
                models: models,
                failureMessage: unavailableMessage
            )
        }
        return HarnessModelCatalogSnapshot(providers: views)
    }

    private static func descriptor(
        providerID: ProviderID,
        directory: HarnessProviderDirectoryEntry?,
        group: HarnessModelProviderGroup?,
        settings: HarnessSettingsDescription,
        policyDescriptor: ProviderDescriptor?
    ) -> ProviderDescriptor {
        let displayName = directory?.displayName ?? group?.name ?? policyDescriptor?.displayName ?? providerID.rawValue
        let configuredScalar = directory.flatMap { configuredEndpointScalar(directory: $0, settings: settings) }
        let configuredEndpoint = configuredScalar.flatMap(validatedEndpoint)
        let defaultEndpoint = policyDescriptor?.defaultBaseURL.flatMap(validatedEndpoint)
        let effectiveEndpoint = configuredScalar == nil ? defaultEndpoint : configuredEndpoint
        let configuredCredentialReference = directory.flatMap {
            credentialReference(directory: $0, settings: settings)
        }
        let configuredWireProtocol = directory.flatMap {
            wireProtocol(directory: $0, settings: settings)
        }
        let rawProfile = directory.flatMap {
            configuredRawProfile(directory: $0, settings: settings)
        }
        let hasConfiguredProfile = rawProfile != nil
        let explicitlyUnauthenticated = rawProfile?.objectValue?["unauthenticated"] == .bool(true)
        let fallbackBoundary = policyDescriptor?.boundary ?? .cloud
        let boundary: DataBoundary
        if providerID == BuiltInProviderDescriptors.ollama.id,
           fallbackBoundary == .onDevice,
           let effectiveEndpoint,
           AppOwnedOllamaEndpoint.validatingProviderBaseURL(effectiveEndpoint) != nil {
            // The native host separately verifies that this exact listener is
            // owned by its Ollama PID before exposing the catalog.
            boundary = .onDevice
        } else {
            boundary = effectiveEndpoint.map { inferredBoundary(for: $0) } ?? fallbackBoundary
        }
        if let policyDescriptor {
            let projectsConfiguredPiAIAuthentication = policyDescriptor.adapterKind == .piAI
                && providerID != BuiltInProviderDescriptors.ollama.id
                && hasConfiguredProfile
            return ProviderDescriptor(
                id: providerID,
                displayName: displayName,
                settingsNamespace: directory?.settingsNs ?? policyDescriptor.settingsNamespace,
                settingsPath: directory?.settingsPath ?? policyDescriptor.settingsPath,
                adapterKind: policyDescriptor.adapterKind,
                wireProtocol: projectsConfiguredPiAIAuthentication
                    ? configuredWireProtocol : policyDescriptor.wireProtocol,
                defaultBaseURL: effectiveEndpoint,
                boundary: boundary,
                credentialReference: projectsConfiguredPiAIAuthentication
                    ? (explicitlyUnauthenticated ? nil : configuredCredentialReference)
                    : policyDescriptor.credentialReference,
                explicitlyUnauthenticated: projectsConfiguredPiAIAuthentication
                    && explicitlyUnauthenticated
            )
        }

        return ProviderDescriptor(
            id: providerID,
            displayName: displayName,
            settingsNamespace: directory?.settingsNs ?? "",
            settingsPath: directory?.settingsPath ?? [],
            adapterKind: .piAI,
            wireProtocol: configuredWireProtocol,
            defaultBaseURL: effectiveEndpoint,
            boundary: boundary,
            credentialReference: explicitlyUnauthenticated ? nil : configuredCredentialReference,
            explicitlyUnauthenticated: explicitlyUnauthenticated,
            supportsNativeProfileEditing: CustomProviderNativeEditingPolicy
                .isSafelyEditableProfile(rawProfile)
        )
    }

    /// Mirrors DSH's settings-models surface: a custom pi-ai profile declares a
    /// credential only through its resolved `apiKeyEnv`. Reference-free custom
    /// profiles deliberately remain eligible for provider-native authentication.
    private static func credentialReference(
        directory: HarnessProviderDirectoryEntry,
        settings: HarnessSettingsDescription
    ) -> CredentialReference? {
        guard !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }) else {
            return nil
        }
        // A declared profile must project authentication from its raw user
        // bytes. The resolved layer may merge a catalog route's default
        // credential and would turn an explicit no-auth collision back into a
        // credential-bound native descriptor.
        let source: HarnessJSONValue
        if let user = namespace.user,
           jsonValue(at: directory.settingsPath, in: user) != nil {
            source = user
        } else if directory.declared == true {
            return nil
        } else {
            source = namespace.value
        }
        guard
              let raw = jsonValue(
                at: directory.settingsPath + ["apiKeyEnv"],
                in: source
              )?.stringValue,
              !raw.isEmpty,
              raw.utf8.count <= 256,
              raw.first?.isLetter == true,
              raw.unicodeScalars.allSatisfy({ scalar in
                  scalar.isASCII && ((65...90).contains(scalar.value) || (48...57).contains(scalar.value) || scalar.value == 95)
              }) else { return nil }
        return CredentialReference(raw)
    }

    private static func configuredRawProfile(
        directory: HarnessProviderDirectoryEntry,
        settings: HarnessSettingsDescription
    ) -> HarnessJSONValue? {
        guard !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }),
              let user = namespace.user else { return nil }
        return jsonValue(at: directory.settingsPath, in: user)
    }

    private static func authenticationConfigurationIsInvalid(
        rawProfile: HarnessJSONValue?,
        declared: Bool,
        descriptor: ProviderDescriptor
    ) -> Bool {
        guard descriptor.adapterKind == .piAI else { return false }
        guard let profile = rawProfile?.objectValue else { return declared }
        if descriptor.id == BuiltInProviderDescriptors.ollama.id {
            return profile["apiKeyEnv"] != .string("OLLAMA_API_KEY")
                || profile["unauthenticated"] == .bool(true)
        }
        let namesCredential = profile["apiKeyEnv"] != nil
        if namesCredential, descriptor.credentialReference == nil { return true }

        guard profile["unauthenticated"] == .bool(true) else { return false }
        if namesCredential { return true }
        if let headers = profile["headers"] {
            guard let object = headers.objectValue, object.isEmpty else { return true }
        }
        guard let endpoint = descriptor.defaultBaseURL else { return true }
        return !ProviderNetworkOrigin.isLiteralPrivateOrLoopback(endpoint)
    }

    private static func wireProtocol(
        directory: HarnessProviderDirectoryEntry,
        settings: HarnessSettingsDescription
    ) -> ProviderWireProtocol? {
        guard let raw = configuredWireProtocolScalar(directory: directory, settings: settings) else { return nil }
        let protocolID = ProviderWireProtocol(raw)
        return [ProviderWireProtocol.openAICompletions, .openAIResponses, .anthropicMessages]
            .contains(protocolID) ? protocolID : nil
    }

    private static func configuredWireProtocolScalar(
        directory: HarnessProviderDirectoryEntry,
        settings: HarnessSettingsDescription
    ) -> String? {
        guard !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }) else {
            return nil
        }
        return jsonValue(at: directory.settingsPath + ["api"], in: namespace.value)?.stringValue
    }

    private static func configuredEndpointScalar(
        directory: HarnessProviderDirectoryEntry,
        settings: HarnessSettingsDescription
    ) -> String? {
        guard !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }) else {
            return nil
        }
        return jsonValue(at: directory.settingsPath + ["baseURL"], in: namespace.value)?.stringValue
    }

    /// Explicit per-model settings take precedence over the bundled registry.
    /// A malformed explicit declaration resolves to text-only rather than
    /// falling through to a potentially more permissive catalog record.
    private static func configuredInputModalities(
        directory: HarnessProviderDirectoryEntry?,
        adapterKind: ProviderAdapterKind,
        model: ModelID,
        settings: HarnessSettingsDescription
    ) -> [ModelInputModality]? {
        guard let directory,
              !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }),
              let provider = jsonValue(at: directory.settingsPath, in: namespace.value)?.objectValue else {
            return nil
        }

        if adapterKind == .piAI, let rawOverrides = provider["modelOverrides"] {
            guard let overrides = rawOverrides.objectValue else { return [.text] }
            if let rawOverride = overrides[model.rawValue] {
                guard let override = rawOverride.objectValue else { return [.text] }
                if let input = override["input"] {
                    if !emptyModalityDeclaration(input) {
                        return parsedModalities(input) ?? [.text]
                    }
                }
            }
        }

        guard let rawModels = provider["models"] else { return nil }
        guard case .array(let models) = rawModels else { return [.text] }
        var matches: [[String: HarnessJSONValue]] = []
        for value in models {
            guard let object = value.objectValue,
                  let identifier = object["id"]?.stringValue,
                  !identifier.isEmpty else {
                return [.text]
            }
            if identifier == model.rawValue { matches.append(object) }
        }
        guard matches.count <= 1 else { return [.text] }
        guard let selected = matches.first else { return nil }
        let inputField = adapterKind == .deepSeekOfficial ? "inputModalities" : "input"
        guard let input = selected[inputField] else {
            // pi-ai lets a catalog model inherit its installed registry entry.
            // DeepSeek's explicit model list instead defaults an omitted field
            // to text and replaces its built-in list.
            return adapterKind == .deepSeekOfficial ? [.text] : nil
        }
        if adapterKind == .piAI, emptyModalityDeclaration(input) { return nil }
        return parsedModalities(input) ?? [.text]
    }

    private static func configuredDefaultInputModalities(
        directory: HarnessProviderDirectoryEntry?,
        adapterKind: ProviderAdapterKind,
        settings: HarnessSettingsDescription
    ) -> [ModelInputModality]? {
        guard adapterKind == .piAI,
              let directory,
              !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }),
              let provider = jsonValue(at: directory.settingsPath, in: namespace.value)?.objectValue,
              let value = provider["defaultInput"] else {
            return nil
        }
        return parsedModalities(value) ?? [.text]
    }

    private static func parsedModalities(_ value: HarnessJSONValue) -> [ModelInputModality]? {
        guard case .array(let values) = value,
              !values.isEmpty,
              values.count <= ModelInputModality.allCases.count else {
            return nil
        }
        var seen = Set<ModelInputModality>()
        var result: [ModelInputModality] = []
        for value in values {
            guard let raw = value.stringValue,
                  let modality = ModelInputModality(rawValue: raw),
                  seen.insert(modality).inserted else {
                return nil
            }
            result.append(modality)
        }
        return seen.contains(.text) ? result : nil
    }

    private static func emptyModalityDeclaration(_ value: HarnessJSONValue) -> Bool {
        if case .array(let values) = value { return values.isEmpty }
        return false
    }

    private static func configuredModelLimits(
        directory: HarnessProviderDirectoryEntry?,
        model: ModelID,
        settings: HarnessSettingsDescription
    ) -> (Int, Int)? {
        guard let directory,
              !directory.settingsNs.isEmpty,
              let namespace = settings.namespaces.first(where: { $0.ns == directory.settingsNs }),
              let values = localPerformanceValues(
                namespace: namespace,
                providerPath: directory.settingsPath,
                model: model
              ),
              (1_024...16_777_216).contains(values.0),
              (256...values.0).contains(values.1) else {
            return nil
        }
        return values
    }

    private static func jsonValue(at path: [String], in root: HarnessJSONValue) -> HarnessJSONValue? {
        var current = root
        for component in path {
            guard case .object(let object) = current, let next = object[component] else { return nil }
            current = next
        }
        return current
    }

    private static func localPerformanceMutation(
        namespace: HarnessSettingsNamespace,
        providerPath: [String],
        model: ModelID,
        settings: ModelPerformanceSettings
    ) throws -> HarnessSettingsPathOperation? {
        guard let provider = jsonValue(at: providerPath, in: namespace.value)?.objectValue else {
            throw ModelSelectionCoordinatorError.localPerformanceProviderUnavailable
        }
        let context = HarnessJSONValue.integer(Int64(settings.contextWindowTokens))
        let output = HarnessJSONValue.integer(Int64(settings.maxOutputTokens))

        if let rawModels = provider["models"] {
            guard case .array(let models) = rawModels else {
                throw ModelSelectionCoordinatorError.localPerformanceModelUnavailable
            }
            if !models.isEmpty {
                var exactIndices: [Int] = []
                for (index, value) in models.enumerated() {
                    guard let object = value.objectValue,
                          let id = object["id"]?.stringValue,
                          !id.isEmpty else {
                        throw ModelSelectionCoordinatorError.localPerformanceModelUnavailable
                    }
                    if id == model.rawValue { exactIndices.append(index) }
                }
                guard exactIndices.count == 1, let index = exactIndices.first,
                      var selected = models[index].objectValue else {
                    throw ModelSelectionCoordinatorError.localPerformanceModelUnavailable
                }
                if selected["contextWindow"] == context, selected["maxTokens"] == output { return nil }
                selected["contextWindow"] = context
                selected["maxTokens"] = output
                var updated = models
                updated[index] = .object(selected)
                return .set(path: providerPath + ["models"], value: .array(updated))
            }
        }

        var overrides: [String: HarnessJSONValue]
        if let rawOverrides = provider["modelOverrides"] {
            guard let value = rawOverrides.objectValue else {
                throw ModelSelectionCoordinatorError.localPerformanceModelUnavailable
            }
            overrides = value
        } else {
            overrides = [:]
        }
        var selected: [String: HarnessJSONValue]
        if let rawSelected = overrides[model.rawValue] {
            guard let value = rawSelected.objectValue else {
                throw ModelSelectionCoordinatorError.localPerformanceModelUnavailable
            }
            selected = value
        } else {
            selected = [:]
        }
        if selected["contextWindow"] == context, selected["maxTokens"] == output { return nil }
        selected["contextWindow"] = context
        selected["maxTokens"] = output
        overrides[model.rawValue] = .object(selected)
        return .set(path: providerPath + ["modelOverrides"], value: .object(overrides))
    }

    private static func reviewedLocalBootstrapProfile(
        selection: ModelSelection,
        providerBaseURL: URL
    ) -> HarnessJSONValue {
        let performance = selection.effectivePerformanceSettings
        let displayName = selection.route.model == BuiltInProviderDescriptors.qwenLocalModel.id
            ? BuiltInProviderDescriptors.qwenLocalModel.displayName
            : selection.route.model.rawValue
        var localModel: [String: HarnessJSONValue] = [
            "id": .string(selection.route.model.rawValue),
            "name": .string(displayName),
            "contextWindow": .integer(Int64(performance.contextWindowTokens)),
            "maxTokens": .integer(Int64(performance.maxOutputTokens)),
            "input": .array([.string("text")])
        ]
        var profile: [String: HarnessJSONValue] = [
            "apiKeyEnv": .string("OLLAMA_API_KEY"),
            "displayName": .string("Ollama (Local)"),
            "api": .string("openai-completions"),
            "baseURL": .string(providerBaseURL.absoluteString),
            "models": .array([.object(localModel)])
        ]
        if selection.isReleaseQualifiedLocalQwen {
            // The exact Qwen route is the only local route whose reasoning
            // controls have been release-qualified. Compatibility models are
            // accepted only when Ollama reports no thinking capability and
            // therefore must not inherit these Qwen-specific declarations.
            profile["reasoning"] = .string("off")
            profile["compat"] = .object([
                "maxTokensField": .string("max_tokens"),
                "supportsReasoningEffort": .bool(true)
            ])
            localModel["reasoningEfforts"] = .object([
                "off": .string("none"),
                "high": .string("high")
            ])
            profile["models"] = .array([.object(localModel)])
        } else {
            profile["compat"] = .object([
                "maxTokensField": .string("max_tokens")
            ])
        }
        return .object(profile)
    }

    private static func isReviewedLocalBootstrapProfile(
        _ value: HarnessJSONValue,
        selection: ModelSelection,
        providerBaseURL: URL
    ) -> Bool {
        guard let profile = value.objectValue,
              profile["apiKeyEnv"] == .string("OLLAMA_API_KEY"),
              profile["api"] == .string("openai-completions"),
              profile["baseURL"] == .string(providerBaseURL.absoluteString),
              case .array(let models)? = profile["models"],
              models.count == 1,
              let model = models[0].objectValue else { return false }
        let performance = selection.effectivePerformanceSettings
        let common = model["id"] == .string(selection.route.model.rawValue)
            && model["contextWindow"] == .integer(Int64(performance.contextWindowTokens))
            && model["maxTokens"] == .integer(Int64(performance.maxOutputTokens))
            && model["input"] == .array([.string("text")])
        guard common else { return false }
        if selection.isReleaseQualifiedLocalQwen {
            return profile["reasoning"] == .string("off")
                && profile["compat"] == .object([
                    "maxTokensField": .string("max_tokens"),
                    "supportsReasoningEffort": .bool(true)
                ])
                && model["reasoningEfforts"] == .object([
                "off": .string("none"),
                "high": .string("high")
            ])
        }
        return profile["reasoning"] == nil
            && profile["compat"] == .object([
                "maxTokensField": .string("max_tokens")
            ])
            && model["reasoningEfforts"] == nil
    }

    private static func localPerformanceValues(
        namespace: HarnessSettingsNamespace,
        providerPath: [String],
        model: ModelID
    ) -> (Int, Int)? {
        guard let provider = jsonValue(at: providerPath, in: namespace.value)?.objectValue else { return nil }
        let selected: [String: HarnessJSONValue]?
        if case .array(let models)? = provider["models"], !models.isEmpty {
            let matches = models.compactMap(\.objectValue).filter { $0["id"]?.stringValue == model.rawValue }
            guard matches.count == 1 else { return nil }
            selected = matches[0]
        } else {
            selected = provider["modelOverrides"]?.objectValue?[model.rawValue]?.objectValue
        }
        guard let selected,
              case .integer(let context)? = selected["contextWindow"],
              case .integer(let output)? = selected["maxTokens"],
              let contextValue = Int(exactly: context),
              let outputValue = Int(exactly: output) else { return nil }
        return (contextValue, outputValue)
    }

    private static func validatedEndpoint(_ scalar: String) -> URL? {
        guard let url = URL(string: scalar), ProviderNetworkOrigin(url: url) != nil else { return nil }
        return url
    }

    private static func validatedEndpoint(_ url: URL) -> URL? {
        ProviderNetworkOrigin(url: url) == nil ? nil : url
    }

    private static func inferredBoundary(for url: URL) -> DataBoundary {
        guard let origin = ProviderNetworkOrigin(url: url) else { return .cloud }
        let host = origin.host.lowercased()
        // An arbitrary loopback server is still outside this app's process
        // trust boundary. It requires the same explicit, origin-bound consent
        // as another private-network service. Only the exact app-owned Ollama
        // route is promoted to `.onDevice` in `descriptor` above.
        if host == "localhost" || host == "::1" || host.hasPrefix("127.") { return .localNetwork }
        return ProviderNetworkOrigin.isLocalAddress(host) ? .localNetwork : .cloud
    }

    private static func modelView(
        _ model: HarnessModelCatalogEntry,
        inputModalities: [ModelInputModality],
        contextWindowTokens: Int?,
        maxOutputTokens: Int?
    ) -> ModelView {
        let efforts = model.reasoning?.efforts.map {
            ReasoningEffortView(id: $0.id, displayName: $0.name, detail: $0.description)
        } ?? []
        let defaultEffort = model.reasoning?.defaultEffort.flatMap { candidate in
            efforts.filter { $0.id == candidate }.count == 1 ? candidate : nil
        }
        return ModelView(
            id: model.id,
            displayName: model.name,
            detail: model.description,
            capabilities: ModelCapabilities(
                inputModalities: inputModalities,
                toolUse: .unknown,
                reasoning: model.reasoning == nil ? .unknown : .supported,
                contextWindowTokens: contextWindowTokens,
                maxOutputTokens: maxOutputTokens,
                reasoningEfforts: efforts,
                defaultReasoningEffort: defaultEffort
            )
        )
    }
}
