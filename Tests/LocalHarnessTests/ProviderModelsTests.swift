import Foundation
import Testing
@testable import LocalHarness

private func codableRoundTrip<Value: Codable>(_ value: Value, as type: Value.Type = Value.self) throws -> Value {
    try JSONDecoder().decode(type, from: JSONEncoder().encode(value))
}

private func isolatedDefaults() throws -> (UserDefaults, String) {
    let name = "LocalHarnessTests.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: name))
    defaults.removePersistentDomain(forName: name)
    return (defaults, name)
}

@Test func opaqueProviderAndModelIDsRoundTripAsSingleJSONValues() throws {
    let provider = ProviderID("tenant/acme:west/v2")
    let model = ModelID("org/model:27b/q4_K_M")

    #expect(try codableRoundTrip(provider) == provider)
    #expect(try codableRoundTrip(model) == model)
    #expect(try JSONSerialization.jsonObject(with: JSONEncoder().encode(provider), options: .fragmentsAllowed) as? String == provider.rawValue)
    #expect(try JSONSerialization.jsonObject(with: JSONEncoder().encode(model), options: .fragmentsAllowed) as? String == model.rawValue)
}

@Test func modelRouteNeverConflatesProviderAndModelComponents() throws {
    let route = ModelRoute(
        provider: ProviderID("gateway/acme:prod"),
        model: ModelID("team/model:v3/quant:q5")
    )
    let decoded = try codableRoundTrip(route)

    #expect(decoded == route)
    #expect(decoded.provider.rawValue == "gateway/acme:prod")
    #expect(decoded.model.rawValue == "team/model:v3/quant:q5")
}

@Test func providerAndModelViewsRoundTripWithoutLosingCapabilities() throws {
    let capabilities = ModelCapabilities(
        inputModalities: [.image, .text, .image],
        toolUse: .supported,
        reasoning: .supported,
        contextWindowTokens: 131_072,
        maxOutputTokens: 16_384,
        reasoningEfforts: [ReasoningEffortView(id: "ultra:max", displayName: "Ultra")]
    )
    let descriptor = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("corp/gateway:v2"),
        displayName: "Corp Gateway",
        baseURL: URL(string: "https://models.example.test/v1")!,
        boundary: .cloud,
        credentialReference: CredentialReference("CORP_GATEWAY_API_KEY"),
        wireProtocol: .openAIResponses
    )
    let view = ProviderView(
        descriptor: descriptor,
        configurationState: .ready,
        models: [ModelView(id: ModelID("research/model:large"), displayName: "Research Large", capabilities: capabilities)],
        failureMessage: nil
    )
    let decoded = try codableRoundTrip(view)

    #expect(decoded == view)
    #expect(decoded.models[0].capabilities.inputModalities == [.image, .text])
    #expect(decoded.models[0].capabilities.reasoningEfforts[0].id == "ultra:max")
}

@Test func legacyProviderDescriptorDefaultsNewAuthenticationAndEditingFactsClosed() throws {
    let descriptor = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("legacy-gateway"),
        displayName: "Legacy Gateway",
        baseURL: URL(string: "https://legacy.example.test/v1")!,
        boundary: .cloud,
        credentialReference: nil
    )
    var object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(descriptor)) as? [String: Any]
    )
    object.removeValue(forKey: "explicitlyUnauthenticated")
    object.removeValue(forKey: "supportsNativeProfileEditing")
    let legacy = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])

    let decoded = try JSONDecoder().decode(ProviderDescriptor.self, from: legacy)
    #expect(decoded.authenticationMode == .providerNative)
    #expect(!decoded.explicitlyUnauthenticated)
    #expect(!decoded.supportsNativeProfileEditing)
}

@Test func builtInProviderDescriptorsHaveExpectedRoutesBoundariesAndCredentialReferences() {
    #expect(BuiltInProviderDescriptors.all.map(\.id) == [
        ProviderID("ollama"), ProviderID("deepseek-official"), ProviderID("openai"), ProviderID("anthropic")
    ])
    #expect(BuiltInProviderDescriptors.ollama.boundary == .onDevice)
    #expect(BuiltInProviderDescriptors.ollama.wireProtocol == .openAICompletions)
    #expect(BuiltInProviderDescriptors.ollama.credentialReference == CredentialReference("OLLAMA_API_KEY"))
    #expect(BuiltInProviderDescriptors.deepSeekOfficial.adapterKind == .deepSeekOfficial)
    #expect(BuiltInProviderDescriptors.deepSeekOfficial.credentialReference == CredentialReference("DEEPSEEK_API_KEY"))
    #expect(BuiltInProviderDescriptors.openAI.credentialReference == CredentialReference("OPENAI_API_KEY"))
    #expect(BuiltInProviderDescriptors.anthropic.credentialReference == CredentialReference("ANTHROPIC_API_KEY"))
    #expect(BuiltInProviderDescriptors.deepSeekOfficial.boundary == .cloud)
    #expect(BuiltInProviderDescriptors.openAI.boundary == .cloud)
    #expect(BuiltInProviderDescriptors.anthropic.boundary == .cloud)
}

@Test func serializedProviderDescriptorsContainReferencesButNoCredentialValues() throws {
    let data = try JSONEncoder().encode(BuiltInProviderDescriptors.all)
    let json = try #require(String(data: data, encoding: .utf8))

    #expect(json.contains("OPENAI_API_KEY"))
    #expect(json.contains("ANTHROPIC_API_KEY"))
    #expect(json.contains("DEEPSEEK_API_KEY"))
    #expect(!json.contains("apiKeyValue"))
    #expect(!json.contains("secretValue"))
}

@Test func genericOpenAICompatibleDescriptorRequiresExplicitBoundaryClassification() {
    let descriptor = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("lab/llama:server"),
        displayName: "Lab Llama Server",
        baseURL: URL(string: "http://192.168.20.8:8080/v1")!,
        boundary: .localNetwork,
        wireProtocol: .openAICompletions
    )

    #expect(descriptor.id == ProviderID("lab/llama:server"))
    #expect(descriptor.settingsPath == ["providers", "lab/llama:server"])
    #expect(descriptor.boundary == .localNetwork)
    #expect(descriptor.credentialReference == nil)
    #expect(descriptor.requiresExplicitConsent)
}

@Test func onDeviceProvidersNeedNoConsentButExternalBoundariesDo() {
    #expect(!DataBoundary.onDevice.requiresExplicitConsent)
    #expect(DataBoundary.localNetwork.requiresExplicitConsent)
    #expect(DataBoundary.cloud.requiresExplicitConsent)
    #expect(ProviderConsentPolicy.canSendData(to: BuiltInProviderDescriptors.ollama, grants: []))
    #expect(!ProviderConsentPolicy.canSendData(to: BuiltInProviderDescriptors.openAI, grants: []))
}

@Test func consentIsScopedToExactProviderBoundaryAndOrigin() {
    let openAI = BuiltInProviderDescriptors.openAI
    let exact = ProviderConsentGrant(for: openAI)
    let wrongProvider = ProviderConsentGrant(
        provider: ProviderID("anthropic"),
        boundary: .cloud,
        baseURL: openAI.defaultBaseURL,
        credentialReference: openAI.credentialReference
    )
    let wrongOrigin = ProviderConsentGrant(
        provider: openAI.id,
        boundary: .cloud,
        baseURL: URL(string: "https://gateway.example.test/v1"),
        credentialReference: openAI.credentialReference
    )
    let wrongBoundary = ProviderConsentGrant(
        provider: openAI.id,
        boundary: .localNetwork,
        baseURL: openAI.defaultBaseURL,
        credentialReference: openAI.credentialReference
    )

    #expect(ProviderConsentPolicy.canSendData(to: openAI, grants: [exact]))
    #expect(!ProviderConsentPolicy.canSendData(to: openAI, grants: [wrongProvider]))
    #expect(!ProviderConsentPolicy.canSendData(to: openAI, grants: [wrongOrigin]))
    #expect(!ProviderConsentPolicy.canSendData(to: openAI, grants: [wrongBoundary]))
}

@Test func consentIsScopedToTheExactCredentialReferenceWithoutSerializingASecret() throws {
    let descriptor = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("credential-bound"),
        displayName: "Credential Bound",
        baseURL: URL(string: "https://models.example.test/v1")!,
        boundary: .cloud,
        credentialReference: CredentialReference("FIRST_API_KEY")
    )
    let exact = ProviderConsentGrant(for: descriptor)
    let changedReference = BuiltInProviderDescriptors.openAICompatible(
        id: descriptor.id,
        displayName: descriptor.displayName,
        baseURL: descriptor.defaultBaseURL!,
        boundary: descriptor.boundary,
        credentialReference: CredentialReference("SECOND_API_KEY")
    )
    let removedReference = BuiltInProviderDescriptors.openAICompatible(
        id: descriptor.id,
        displayName: descriptor.displayName,
        baseURL: descriptor.defaultBaseURL!,
        boundary: descriptor.boundary,
        credentialReference: nil
    )

    #expect(exact.permits(descriptor))
    #expect(!exact.permits(changedReference))
    #expect(!exact.permits(removedReference))

    let encoded = String(decoding: try JSONEncoder().encode(exact), as: UTF8.self)
    #expect(encoded.contains("FIRST_API_KEY"))
    #expect(!encoded.contains("SECOND_API_KEY"))
    #expect(!encoded.contains("secretValue"))
    #expect(!encoded.contains("apiKeyValue"))
}

@Test func consentIsInvalidatedWhenTheAuthenticationModeChangesAtTheSameOrigin() {
    let endpoint = URL(string: "http://127.0.0.1:49174/v1")!
    let providerNative = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("mode-bound"),
        displayName: "Mode Bound",
        baseURL: endpoint,
        boundary: .localNetwork
    )
    let explicitNoAuth = BuiltInProviderDescriptors.openAICompatible(
        id: providerNative.id,
        displayName: providerNative.displayName,
        baseURL: endpoint,
        boundary: .localNetwork,
        explicitlyUnauthenticated: true
    )
    let nativeGrant = ProviderConsentGrant(for: providerNative)
    let noAuthGrant = ProviderConsentGrant(for: explicitNoAuth)

    #expect(nativeGrant.permits(providerNative))
    #expect(!nativeGrant.permits(explicitNoAuth))
    #expect(noAuthGrant.permits(explicitNoAuth))
    #expect(!noAuthGrant.permits(providerNative))
}

@Test @MainActor func externalProviderDisclosureNamesTheCredentialReferenceButNeverItsValue() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let descriptor = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("disclosure"),
        displayName: "Disclosure",
        baseURL: URL(string: "https://models.example.test/v1")!,
        boundary: .cloud,
        credentialReference: CredentialReference("DISCLOSURE_API_KEY")
    )
    let provider = ProviderView(
        descriptor: descriptor,
        configurationState: .ready,
        models: [],
        failureMessage: nil
    )

    let disclosure = ProviderCenterWindowController.externalBoundaryDisclosure(
        provider: provider,
        destination: "https://models.example.test:443"
    )
    #expect(disclosure.contains("DISCLOSURE_API_KEY"))
    #expect(disclosure.contains("secret stored in macOS Keychain"))
    #expect(disclosure.contains("sent only to this exact destination"))
    #expect(!disclosure.contains("credential-value-canary"))
}

@Test func consentOriginNormalizesCaseAndDefaultPorts() {
    let implicit = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("case-test"),
        displayName: "Case Test",
        baseURL: URL(string: "https://MODELS.example.test/v1")!,
        boundary: .cloud
    )
    let explicit = BuiltInProviderDescriptors.openAICompatible(
        id: implicit.id,
        displayName: implicit.displayName,
        baseURL: URL(string: "https://models.example.test:443/another/path")!,
        boundary: .cloud
    )
    let grant = ProviderConsentGrant(for: implicit)

    #expect(grant.permits(explicit))
}

@Test func externalConsentFailsClosedUntilAnHTTPOriginIsKnown() {
    let unresolved = ProviderDescriptor(
        id: ProviderID("future-provider"),
        displayName: "Future Provider",
        settingsNamespace: "llm-pi-ai",
        settingsPath: ["providers", "future-provider"],
        adapterKind: .piAI,
        wireProtocol: nil,
        defaultBaseURL: nil,
        boundary: .cloud,
        credentialReference: CredentialReference("FUTURE_PROVIDER_API_KEY")
    )
    let originlessGrant = ProviderConsentGrant(for: unresolved)

    #expect(!originlessGrant.permits(unresolved))
    #expect(!ProviderConsentPolicy.canSendData(to: unresolved, grants: [originlessGrant]))
}

@Test func performanceProfilesAreConservativeAndMonotonicFor48GBAppleSilicon() {
    let fast = PerformanceProfile.fast.settingsFor48GBAppleSilicon
    let balanced = PerformanceProfile.balanced.settingsFor48GBAppleSilicon
    let deep = PerformanceProfile.deep.settingsFor48GBAppleSilicon

    #expect(fast.contextWindowTokens < balanced.contextWindowTokens)
    #expect(balanced.contextWindowTokens < deep.contextWindowTokens)
    #expect(fast.maxOutputTokens < balanced.maxOutputTokens)
    #expect(balanced.maxOutputTokens < deep.maxOutputTokens)
    #expect(fast.keepAliveSeconds < balanced.keepAliveSeconds)
    #expect(balanced.keepAliveSeconds < deep.keepAliveSeconds)
    #expect(fast.reasoningPreference == .disabled)
    #expect(balanced.reasoningPreference == .automatic)
    #expect(deep.reasoningPreference == .high)
    #expect(fast.contextWindowTokens == 32_768)
    #expect(fast.maxOutputTokens == 4_096)
    #expect(balanced.contextWindowTokens == 49_152)
    #expect(balanced.maxOutputTokens == 8_192)
    #expect(deep.contextWindowTokens == 65_536)
    #expect(deep.maxOutputTokens == 16_384)
    let compatibility = PerformanceProfile.compatibility.settingsFor48GBAppleSilicon
    #expect(compatibility.contextWindowTokens == 8_192)
    #expect(compatibility.maxOutputTokens == 2_048)
    #expect(compatibility.keepAliveSeconds == 120)
    #expect(compatibility.reasoningPreference == .disabled)
    #expect(PerformanceProfile.allCases.allSatisfy { $0.settingsFor48GBAppleSilicon.maxConcurrentGenerations == 1 })
}

@Test func performanceSettingsValidateConstructionAndDecoding() throws {
    #expect(throws: ModelPerformanceSettings.ValidationError.outputExceedsContext) {
        try ModelPerformanceSettings(
            contextWindowTokens: 2_048,
            maxOutputTokens: 4_096,
            keepAliveSeconds: 60,
            maxConcurrentGenerations: 1,
            reasoningPreference: .automatic
        )
    }

    let invalidJSON = Data(#"{"contextWindowTokens":32768,"maxOutputTokens":4096,"keepAliveSeconds":600,"maxConcurrentGenerations":0,"reasoningPreference":"automatic"}"#.utf8)
    #expect(throws: ModelPerformanceSettings.ValidationError.invalidConcurrency) {
        try JSONDecoder().decode(ModelPerformanceSettings.self, from: invalidJSON)
    }
}

@Test func versionedSelectionRoundTripsOpaqueRouteReasoningAndProfile() throws {
    let selection = ModelSelection(
        route: ModelRoute(provider: ProviderID("vendor/route:v2"), model: ModelID("org/model:large/v3")),
        reasoningEffort: "reasoning/ultra:max",
        performanceProfile: .deep
    )
    let decoded = try codableRoundTrip(selection)

    #expect(decoded == selection)
    #expect(decoded.schemaVersion == ModelSelection.currentSchemaVersion)
    #expect(decoded.reasoningEffort == "reasoning/ultra:max")
}

@Test func unsupportedSelectionAndSettingsVersionsFailClosed() throws {
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()

    var selectionObject = try #require(JSONSerialization.jsonObject(with: encoder.encode(ModelSelection.defaultLocal)) as? [String: Any])
    selectionObject["schemaVersion"] = 99
    let futureSelection = try JSONSerialization.data(withJSONObject: selectionObject)
    #expect(throws: DecodingError.self) {
        try decoder.decode(ModelSelection.self, from: futureSelection)
    }

    var settingsObject = try #require(JSONSerialization.jsonObject(with: encoder.encode(ModelProviderSettings())) as? [String: Any])
    settingsObject["schemaVersion"] = 99
    let futureSettings = try JSONSerialization.data(withJSONObject: settingsObject)
    #expect(throws: DecodingError.self) {
        try decoder.decode(ModelProviderSettings.self, from: futureSettings)
    }
}

@Test func modelProviderSettingsRoundTripWithVersionedSelection() throws {
    let settings = ModelProviderSettings(defaultSelection: ModelSelection(
        route: ModelRoute(provider: ProviderID("openai"), model: ModelID("gpt/custom:v1")),
        reasoningEffort: "high",
        performanceProfile: .fast
    ))

    #expect(try codableRoundTrip(settings) == settings)
    #expect(settings.schemaVersion == ModelProviderSettings.currentSchemaVersion)
}

@Test func legacySelectedLocalModelMigratesExactlyOnceAndPreservesOpaqueID() throws {
    let (defaults, suite) = try isolatedDefaults()
    defer { defaults.removePersistentDomain(forName: suite) }
    let legacyID = "team/qwen:27b/hermes:q4_K_M"
    defaults.set(legacyID, forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey)
    let store = ModelProviderSettingsStore(defaults: defaults)

    let first = try store.loadOrMigrate()
    #expect(first.source == .migratedLegacy(model: ModelID(legacyID)))
    #expect(first.settings.defaultSelection.route == ModelRoute(provider: ProviderID("ollama"), model: ModelID(legacyID)))
    #expect(first.settings.defaultSelection.performanceProfile == .compatibility)
    #expect(first.settings.defaultSelection.reasoningEffort == nil)
    #expect(defaults.string(forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey) == legacyID)

    let second = try store.loadOrMigrate()
    #expect(second.source == .stored)
    #expect(second.settings == first.settings)
}

@Test func missingOrWhitespaceLegacyPreferenceInitializesSafeLocalDefaults() throws {
    for legacy in [nil, "   \n", ModelSelection.defaultLocal.route.model.rawValue] as [String?] {
        let (defaults, suite) = try isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: suite) }
        if let legacy { defaults.set(legacy, forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey) }

        let result = try ModelProviderSettingsStore(defaults: defaults).loadOrMigrate()
        #expect(result.source == .initializedDefaults)
        #expect(result.settings.defaultSelection == .defaultLocal)
        #expect(result.settings.defaultSelection.performanceProfile == .balanced)
    }
}

@Test func storedHermesUpgradePreservesTheExactRouteAndStoredBytes() throws {
    let (defaults, suite) = try isolatedDefaults()
    defer { defaults.removePersistentDomain(forName: suite) }
    let store = ModelProviderSettingsStore(defaults: defaults)
    // Encode a real older document rather than constructing ModelSelection,
    // whose current initializer already applies Compatibility normalization.
    let stored = try #require(#"{"defaultSelection":{"performanceProfile":"deep","reasoningEffort":"high","route":{"model":"qwen3.8:27b-hermes","provider":"ollama"},"schemaVersion":1},"schemaVersion":1}"#.data(using: .utf8))
    defaults.set(stored, forKey: ModelProviderSettingsStore.settingsKey)

    let first = try store.loadOrMigrate()
    #expect(first.source == .stored)
    #expect(first.settings.defaultSelection.route == ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: ModelSelection.legacyHermesModel
    ))
    #expect(first.settings.defaultSelection.performanceProfile == .compatibility)
    #expect(first.settings.defaultSelection.reasoningEffort == nil)
    #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == stored)

    let second = try store.loadOrMigrate()
    #expect(second.source == .stored)
    #expect(second.settings == first.settings)
    #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == stored)
}

@Test func freshLegacyHermesPreferencePreservesHermesInCompatibilityMode() throws {
    let (defaults, suite) = try isolatedDefaults()
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set(
        ModelSelection.legacyHermesModel.rawValue,
        forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey
    )

    let store = ModelProviderSettingsStore(defaults: defaults)
    let migrated = try store.loadOrMigrate()
    #expect(migrated.source == .migratedLegacy(model: ModelSelection.legacyHermesModel))
    #expect(migrated.settings.defaultSelection.route == ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: ModelSelection.legacyHermesModel
    ))
    #expect(migrated.settings.defaultSelection.performanceProfile == .compatibility)
    #expect(migrated.settings.defaultSelection.reasoningEffort == nil)

    let persisted = try #require(defaults.data(forKey: ModelProviderSettingsStore.settingsKey))
    let repeated = try store.loadOrMigrate()
    #expect(repeated.source == .stored)
    #expect(repeated.settings == migrated.settings)
    #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == persisted)
}

@Test func storedTypedSettingsTakePrecedenceOverLegacyPreference() throws {
    let (defaults, suite) = try isolatedDefaults()
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set("old:qwen", forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey)
    let store = ModelProviderSettingsStore(defaults: defaults)
    let intended = ModelProviderSettings(defaultSelection: ModelSelection(
        route: ModelRoute(provider: ProviderID("anthropic"), model: ModelID("claude/custom")),
        performanceProfile: .deep
    ))
    try store.save(intended)

    let loaded = try store.loadOrMigrate()
    #expect(loaded.source == .stored)
    #expect(loaded.settings == intended)
}

@Test func corruptTypedSettingsAreNotOverwrittenByMigration() throws {
    let (defaults, suite) = try isolatedDefaults()
    defer { defaults.removePersistentDomain(forName: suite) }
    let corrupt = Data("not-json".utf8)
    defaults.set(corrupt, forKey: ModelProviderSettingsStore.settingsKey)
    defaults.set("qwen:legacy", forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey)
    let store = ModelProviderSettingsStore(defaults: defaults)

    #expect(throws: DecodingError.self) {
        try store.loadOrMigrate()
    }
    #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == corrupt)
}

@Test func wrongTypeTypedSettingsAreNotOverwrittenByMigration() throws {
    let (defaults, suite) = try isolatedDefaults()
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set("unexpected-string", forKey: ModelProviderSettingsStore.settingsKey)
    defaults.set("qwen:legacy", forKey: ModelProviderSettingsStore.legacySelectedLocalModelKey)
    let store = ModelProviderSettingsStore(defaults: defaults)

    #expect(throws: ModelProviderSettingsStoreError.invalidStoredType) {
        try store.loadOrMigrate()
    }
    #expect(defaults.string(forKey: ModelProviderSettingsStore.settingsKey) == "unexpected-string")
}
