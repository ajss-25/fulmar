import CryptoKit
import Foundation
import Testing
@testable import LocalHarness

private enum FakeSettingsMutationError: Error { case invalidPath }

private struct FakeCatalogCredentialService: HarnessProviderCredentialServicing {
    let configured: Bool

    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        HarnessCredentialDescription(credentials: Dictionary(uniqueKeysWithValues: references.map {
            ($0.rawValue, HarnessCredentialView(configured: configured, source: nil, writable: true))
        }))
    }

    func setCredential(_ reference: CredentialReference, value: String) async throws {}
    func unsetCredential(_ reference: CredentialReference) async throws {}
}

private struct StaticModelCapabilityCatalog: ModelCapabilityCatalogProviding {
    let values: [ModelRoute: [ModelInputModality]]

    init(_ values: [ModelRoute: [ModelInputModality]] = [:]) {
        self.values = values
    }

    func inputModalities(provider: ProviderID, model: ModelID) -> [ModelInputModality]? {
        values[ModelRoute(provider: provider, model: model)]
    }
}

private func applying(
    _ operation: HarnessSettingsPathOperation,
    to root: HarnessJSONValue
) throws -> HarnessJSONValue {
    func update(
        _ value: HarnessJSONValue,
        path: ArraySlice<String>,
        replacement: HarnessJSONValue?
    ) throws -> HarnessJSONValue {
        guard let component = path.first, !component.isEmpty,
              case .object(var object) = value else {
            throw FakeSettingsMutationError.invalidPath
        }
        if path.count == 1 {
            object[component] = replacement
            return .object(object)
        }
        let child = object[component] ?? .object([:])
        object[component] = try update(child, path: path.dropFirst(), replacement: replacement)
        return .object(object)
    }

    switch operation {
    case .set(let path, let value):
        guard !path.isEmpty else { throw FakeSettingsMutationError.invalidPath }
        return try update(root, path: path[...], replacement: value)
    case .unset(let path):
        guard !path.isEmpty else { throw FakeSettingsMutationError.invalidPath }
        return try update(root, path: path[...], replacement: nil)
    }
}

private actor FakeModelRPCService: HarnessModelRPCServicing {
    var directory: HarnessProviderDirectory
    var catalog: HarnessModelCatalog
    var sessionState: HarnessSessionModels
    var normalizedSelection: HarnessWireModelSelection?
    var settings: HarnessSettingsDescription
    var mutationFailures: [HarnessRPCClientError] = []
    var mutationReplyOverride: HarnessSettingsNamespace?
    var persistMutations = true
    private(set) var providerCalls = 0
    private(set) var catalogCalls = 0
    private(set) var sessionModelCalls: [HarnessSessionID] = []
    private(set) var selections: [(HarnessSessionID, HarnessWireModelSelection)] = []
    private(set) var settingsMutations: [(String, [HarnessSettingsPathOperation], Int?)] = []

    init(
        directory: HarnessProviderDirectory,
        catalog: HarnessModelCatalog,
        sessionState: HarnessSessionModels,
        settings: HarnessSettingsDescription = defaultHarnessSettings()
    ) {
        self.directory = directory
        self.catalog = catalog
        self.sessionState = sessionState
        self.settings = settings
    }

    func llmProviders() async throws -> HarnessProviderDirectory {
        providerCalls += 1
        return directory
    }

    func llmModels() async throws -> HarnessModelCatalog {
        catalogCalls += 1
        return catalog
    }

    func describeSettings() async throws -> HarnessSettingsDescription { settings }

    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace {
        settingsMutations.append((namespace, operations, expectedRevision))
        if !mutationFailures.isEmpty { throw mutationFailures.removeFirst() }
        guard let index = settings.namespaces.firstIndex(where: { $0.ns == namespace }) else {
            throw FakeSettingsMutationError.invalidPath
        }
        let current = settings.namespaces[index]
        if let expectedRevision, expectedRevision != current.revision {
            throw HarnessRPCClientError.remote(.init(code: .settingsConflict, message: "stale", details: [:]))
        }
        var value = current.value
        var user = current.user ?? .object([:])
        for operation in operations {
            value = try applying(operation, to: value)
            user = try applying(operation, to: user)
        }
        let updated = HarnessSettingsNamespace(
            ns: current.ns,
            schema: current.schema,
            value: value,
            base: current.base,
            user: user,
            applies: current.applies,
            secrets: current.secrets,
            revision: current.revision + 1
        )
        if persistMutations {
            var namespaces = settings.namespaces
            namespaces[index] = updated
            settings = HarnessSettingsDescription(
                writable: settings.writable,
                hasDocument: settings.hasDocument,
                namespaces: namespaces
            )
        }
        return mutationReplyOverride ?? updated
    }

    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels {
        sessionModelCalls.append(sessionID)
        return sessionState
    }

    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection {
        selections.append((sessionID, selection))
        return normalizedSelection ?? selection
    }

    func setSessionState(_ state: HarnessSessionModels) { sessionState = state }
    func setNormalizedSelection(_ selection: HarnessWireModelSelection?) { normalizedSelection = selection }
    func setMutationFailures(_ failures: [HarnessRPCClientError]) { mutationFailures = failures }
    func setMutationReplyOverride(_ value: HarnessSettingsNamespace?) { mutationReplyOverride = value }
    func setPersistMutations(_ value: Bool) { persistMutations = value }

    func callCounts() -> (providers: Int, catalog: Int, sessionModels: Int, selections: Int) {
        (providerCalls, catalogCalls, sessionModelCalls.count, selections.count)
    }

    func lastSelection() -> (HarnessSessionID, HarnessWireModelSelection)? { selections.last }
    func recordedMutations() -> [(String, [HarnessSettingsPathOperation], Int?)] { settingsMutations }
}

private func defaultHarnessSettings(
    piAI: HarnessJSONValue = .object([:]),
    piAIUser: HarnessJSONValue? = nil,
    writable: Bool = true,
    defaultRevision: Int = 7
) -> HarnessSettingsDescription {
    HarnessSettingsDescription(
        writable: writable,
        hasDocument: true,
        namespaces: [
            .init(
                ns: "llm-pi-ai", schema: .object([:]), value: piAI,
                base: nil, user: piAIUser ?? piAI, applies: .live, secrets: [], revision: 3
            ),
            .init(
                ns: "agent-default-model", schema: .object([:]),
                value: .object(["provider": .string("ollama"), "model": .string("qwen:27b")]),
                base: nil, user: nil, applies: .live, secrets: [], revision: defaultRevision
            )
        ]
    )
}

private func emptySessionState(
    provider: ProviderID = ProviderID("ollama"),
    model: ModelID = ModelID("qwen:27b"),
    routable: Bool = true
) -> HarnessSessionModels {
    HarnessSessionModels(
        current: HarnessWireModelSelection(provider: provider, model: model),
        routable: routable,
        groups: [],
        failures: []
    )
}

@Suite(.serialized)
struct ModelSelectionCoordinatorTests {
    @Test func providerRecoverySetupCatalogExposesOnlyFailClosedBuiltInSetup() async {
        let coordinator = ModelSelectionCoordinator(
            service: FakeModelRPCService(
                directory: .init(providers: []),
                catalog: .init(groups: [], failures: []),
                sessionState: emptySessionState(
                    provider: BuiltInProviderDescriptors.ollama.id,
                    model: BuiltInProviderDescriptors.qwenLocalModel.id
                )
            )
        )

        let snapshot = await coordinator.providerRecoverySetupCatalog()

        #expect(snapshot.providers.map(\.id) == BuiltInProviderDescriptors.all.map(\.id))
        #expect(snapshot.providers.allSatisfy { $0.models.isEmpty })
        #expect(snapshot.provider(BuiltInProviderDescriptors.ollama.id)?.configurationState == .dormant)
        #expect(snapshot.provider(BuiltInProviderDescriptors.deepSeekOfficial.id)?.configurationState == .needsCredential)
        #expect(snapshot.provider(BuiltInProviderDescriptors.deepSeekOfficial.id)?.descriptor
            == BuiltInProviderDescriptors.deepSeekOfficial)
        #expect(snapshot.providers.allSatisfy { $0.configurationState != .ready })
    }

    @Test func catalogCombinesDSHTopologyWithExplicitLocalBoundaryPolicy() async throws {
        let directory = HarnessProviderDirectory(providers: [
            .init(
                provider: ProviderID("ollama"), displayName: "Ollama Runtime", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "ollama"], active: true, declared: false
            ),
            .init(
                provider: ProviderID("future/remote:route"), displayName: "Future Route", settingsNs: "llm-future",
                settingsPath: ["routes", "future/remote:route"], active: false, declared: true
            )
        ])
        let catalog = HarnessModelCatalog(
            groups: [
                .init(id: ProviderID("ollama"), name: "Ollama", models: [
                    .init(
                        id: ModelID("org/qwen:27b/q5"), name: "Qwen 27B", description: "Local coder",
                        reasoning: .init(
                            efforts: [
                                .init(id: "reason/quick", name: "Quick", description: "Lower cost"),
                                .init(id: "reason/deep:max", name: "Deep", description: "More thought")
                            ],
                            defaultEffort: "reason/deep:max"
                        )
                    )
                ]),
                .init(id: ProviderID("catalog-only:route"), name: "Catalog Only", models: [
                    .init(id: ModelID("model/one:v1"), name: "One", description: nil, reasoning: nil)
                ])
            ],
            failures: [
                .init(id: ProviderID("future/remote:route"), name: "Future Route", message: "Credential missing")
            ]
        )
        let service = FakeModelRPCService(directory: directory, catalog: catalog, sessionState: emptySessionState())
        let coordinator = ModelSelectionCoordinator(service: service)

        let snapshot = try await coordinator.loadCatalog()
        #expect(snapshot.providers.map(\.id) == [ProviderID("ollama"), ProviderID("future/remote:route"), ProviderID("catalog-only:route")])
        let ollama = try #require(snapshot.provider(ProviderID("ollama")))
        #expect(ollama.displayName == "Ollama Runtime")
        #expect(ollama.boundary == .onDevice)
        #expect(ollama.models[0].id == ModelID("org/qwen:27b/q5"))
        #expect(ollama.models[0].capabilities.reasoning == .supported)
        #expect(ollama.models[0].capabilities.reasoningEfforts[0].id == "reason/quick")
        #expect(ollama.models[0].capabilities.defaultReasoningEffort == "reason/deep:max")
        let future = try #require(snapshot.provider(ProviderID("future/remote:route")))
        #expect(future.configurationState == .unavailable)
        #expect(future.failureMessage == "Configured provider authentication is invalid or unsafe")
        #expect(future.boundary == .cloud)
        let catalogOnly = try #require(snapshot.provider(ProviderID("catalog-only:route")))
        #expect(catalogOnly.configurationState == .unavailable)
        #expect(catalogOnly.failureMessage == "Provider endpoint is not exposed, so exact-origin consent cannot be verified")
        #expect(catalogOnly.boundary == .cloud)
        let counts = await service.callCounts()
        #expect(counts.providers == 1 && counts.catalog == 1)
        #expect(await coordinator.cachedCatalog() == snapshot)
    }

    @Test func checkedInCapabilitySourcesEnableOnlyExactReviewedVisionModels() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let dataDirectory = projectRoot.appendingPathComponent(
            "VendorRuntime/node_modules/@earendil-works/pi-ai/dist/providers/data",
            isDirectory: true
        )
        let capabilities = BundledModelCapabilityCatalog(providerDataDirectory: dataDirectory)

        #expect(capabilities.inputModalities(
            provider: ProviderID("openai"), model: ModelID("gpt-4o")
        ) == [.text, .image])
        #expect(capabilities.inputModalities(
            provider: ProviderID("openai"), model: ModelID("gpt-4")
        ) == [.text])
        #expect(capabilities.inputModalities(
            provider: ProviderID("anthropic"), model: ModelID("claude-haiku-4-5")
        ) == [.text, .image])
        #expect(capabilities.inputModalities(
            provider: ProviderID("google"), model: ModelID("deep-research-max-preview-04-2026")
        ) == [.text, .image])
        #expect(capabilities.inputModalities(
            provider: ProviderID("openrouter"), model: ModelID("amazon/nova-2-lite-v1")
        ) == [.text, .image])
        #expect(capabilities.inputModalities(
            provider: ProviderID("openrouter"), model: ModelID("ai21/jamba-large-1.7")
        ) == [.text])
        #expect(capabilities.inputModalities(
            provider: ProviderID("openai"), model: ModelID("unknown-model")
        ) == nil)
        #expect(capabilities.inputModalities(
            provider: ProviderID("deepseek-official"), model: ModelID("deepseek-v4-flash-vision-exp")
        ) == [.text, .image])
        #expect(capabilities.inputModalities(
            provider: ProviderID("deepseek-official"), model: ModelID("deepseek-v4-pro")
        ) == [.text])
        let adapter = try String(contentsOf: projectRoot.appendingPathComponent(
            "VendorRuntime/node_modules/@deepseek-ai/dsh-llm-deepseek/lib/index.js"
        ), encoding: .utf8)
        #expect(adapter.contains(#"id: "deepseek-v4-flash-vision-exp""#))
        #expect(adapter.contains(#"inputModalities: ["text", "image"]"#))
    }

    @Test func manifestedCapabilityCatalogRejectsAnyHashDriftOrUnexpectedRegistry() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("LocalHarnessCapabilityCatalog-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let registry = try JSONSerialization.data(withJSONObject: [
            "openai-completions": [
                "vision-model": [
                    "id": "vision-model",
                    "provider": "fixture-provider",
                    "api": "openai-completions",
                    "input": ["text", "image"]
                ]
            ]
        ], options: [.sortedKeys])
        let digest = SHA256.hash(data: registry).map { String(format: "%02x", $0) }.joined()
        let registryURL = root.appendingPathComponent("fixture-provider.json")
        try registry.write(to: registryURL)
        let manifest = try JSONSerialization.data(withJSONObject: [
            "schemaVersion": 3,
            "generatedAt": "2026-08-22T00:00:00Z",
            "structureHash": String(repeating: "0", count: 64),
            "files": ["fixture-provider.json": digest]
        ], options: [.sortedKeys])
        try manifest.write(to: root.appendingPathComponent(".manifest.json"))

        let valid = BundledModelCapabilityCatalog(providerDataDirectory: root)
        #expect(valid.inputModalities(
            provider: ProviderID("fixture-provider"), model: ModelID("vision-model")
        ) == [.text, .image])

        try Data("{}".utf8).write(to: registryURL)
        let drifted = BundledModelCapabilityCatalog(providerDataDirectory: root)
        #expect(drifted.inputModalities(
            provider: ProviderID("fixture-provider"), model: ModelID("vision-model")
        ) == nil)

        try registry.write(to: registryURL)
        try Data("{}".utf8).write(to: root.appendingPathComponent("unexpected.json"))
        let unexpected = BundledModelCapabilityCatalog(providerDataDirectory: root)
        #expect(unexpected.inputModalities(
            provider: ProviderID("fixture-provider"), model: ModelID("vision-model")
        ) == nil)

        try FileManager.default.removeItem(at: root.appendingPathComponent("unexpected.json"))
        for index in 0..<256 {
            try Data().write(to: root.appendingPathComponent("unexpected-\(index).json"))
        }
        let wide = BundledModelCapabilityCatalog(providerDataDirectory: root)
        #expect(wide.inputModalities(
            provider: ProviderID("fixture-provider"), model: ModelID("vision-model")
        ) == nil)
    }

    @Test func catalogMapsBundledAndExplicitImageCapabilitiesAndFailsClosedOnMalformedSettings() async throws {
        let openAI = ProviderID("openai")
        let custom = ProviderID("private-vision")
        let directory = HarnessProviderDirectory(providers: [
            .init(
                provider: openAI, displayName: "OpenAI", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "openai"], active: true, declared: false
            ),
            .init(
                provider: custom, displayName: "Private Vision", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", custom.rawValue], active: true, declared: true
            )
        ])
        let catalog = HarnessModelCatalog(groups: [
            .init(id: openAI, name: "OpenAI", models: [
                .init(id: ModelID("gpt-4o"), name: "GPT-4o", description: nil, reasoning: nil)
            ]),
            .init(id: custom, name: "Private Vision", models: [
                .init(id: ModelID("vision-good"), name: "Vision", description: nil, reasoning: nil),
                .init(id: ModelID("vision-malformed"), name: "Malformed", description: nil, reasoning: nil),
                .init(id: ModelID("unreported"), name: "Unreported", description: nil, reasoning: nil)
            ])
        ], failures: [])
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                custom.rawValue: .object([
                    "models": .array([
                        .object(["id": .string("vision-good"), "input": .array([.string("text"), .string("image")])]),
                        .object(["id": .string("vision-malformed"), "input": .array([.string("text"), .string("future-modality")])]),
                        .object(["id": .string("unreported")])
                    ])
                ])
            ])
        ]))
        let fallback = StaticModelCapabilityCatalog([
            ModelRoute(provider: openAI, model: ModelID("gpt-4o")): [.text, .image],
            ModelRoute(provider: custom, model: ModelID("vision-malformed")): [.text, .image]
        ])
        let coordinator = ModelSelectionCoordinator(
            service: FakeModelRPCService(
                directory: directory,
                catalog: catalog,
                sessionState: emptySessionState(),
                settings: settings
            ),
            capabilityCatalog: fallback
        )

        let snapshot = try await coordinator.loadCatalog()
        let openAIModels = try #require(snapshot.provider(openAI)).models
        let customModels = try #require(snapshot.provider(custom)).models
        #expect(openAIModels.first?.capabilities.inputModalities == [.text, .image])
        #expect(customModels.first(where: { $0.id == ModelID("vision-good") })?.capabilities.inputModalities == [.text, .image])
        #expect(customModels.first(where: { $0.id == ModelID("vision-malformed") })?.capabilities.inputModalities == [.text])
        #expect(customModels.first(where: { $0.id == ModelID("unreported") })?.capabilities.inputModalities == [.text])
    }

    @Test func customRouteDefaultInputEnablesUndescribedVisionModelsAfterCatalogFallback() async throws {
        let provider = ProviderID("private-vision-default")
        let model = ModelID("gateway-vision")
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "Private Vision", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", provider.rawValue], active: true, declared: true
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "Private Vision",
                models: [.init(id: model, name: "Gateway Vision", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: model),
            settings: defaultHarnessSettings(piAI: .object([
                "providers": .object([
                    provider.rawValue: .object([
                        "models": .array([.object([
                            "id": .string(model.rawValue),
                            "input": .array([]),
                            "contextWindow": .integer(16_384),
                            "maxTokens": .integer(2_048)
                        ])]),
                        "defaultInput": .array([.string("text"), .string("image")])
                    ])
                ])
            ]))
        )

        let snapshot = try await ModelSelectionCoordinator(
            service: service,
            capabilityCatalog: StaticModelCapabilityCatalog()
        ).loadCatalog()
        let capabilities = try #require(snapshot.provider(provider)?.models.first?.capabilities)
        #expect(capabilities.inputModalities == [.text, .image])
        #expect(capabilities.contextWindowTokens == 16_384)
        #expect(capabilities.maxOutputTokens == 2_048)
    }

    @Test func pinnedDeepSeekVisionCapabilityYieldsToAnExplicitTextOnlyReplacement() async throws {
        let provider = ProviderID("deepseek-official")
        let model = ModelID("deepseek-v4-flash-vision-exp")
        let settings = HarnessSettingsDescription(
            writable: true,
            hasDocument: true,
            namespaces: [
                .init(
                    ns: "llm-deepseek", schema: .object([:]),
                    value: .object([
                        "models": .array([.object(["id": .string(model.rawValue)])])
                    ]),
                    base: nil, user: nil, applies: .live, secrets: [], revision: 1
                )
            ]
        )
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "DeepSeek", settingsNs: "llm-deepseek",
                settingsPath: [], active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "DeepSeek",
                models: [.init(id: model, name: "Vision", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: model),
            settings: settings
        )
        let capabilities = StaticModelCapabilityCatalog([
            ModelRoute(provider: provider, model: model): [.text, .image]
        ])

        let snapshot = try await ModelSelectionCoordinator(
            service: service,
            capabilityCatalog: capabilities
        ).loadCatalog()
        #expect(snapshot.provider(provider)?.models.first?.capabilities.inputModalities == [.text])
    }

    @Test func explicitModelOverrideCanConservativelyRemoveBundledVisionCapability() async throws {
        let provider = ProviderID("openai")
        let model = ModelID("gpt-4o")
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "OpenAI", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "openai"], active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider,
                name: "OpenAI",
                models: [.init(id: model, name: "GPT-4o", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: model),
            settings: defaultHarnessSettings(piAI: .object([
                "providers": .object([
                    "openai": .object([
                        "modelOverrides": .object([
                            model.rawValue: .object(["input": .array([.string("text")])])
                        ])
                    ])
                ])
            ]))
        )
        let capabilities = StaticModelCapabilityCatalog([
            ModelRoute(provider: provider, model: model): [.text, .image]
        ])

        let snapshot = try await ModelSelectionCoordinator(
            service: service,
            capabilityCatalog: capabilities
        ).loadCatalog()
        #expect(snapshot.provider(provider)?.models.first?.capabilities.inputModalities == [.text])
    }

    @Test func emptyPiAIModelInputContinuesToTheReviewedRegistryCapability() async throws {
        let provider = ProviderID("openai")
        let model = ModelID("gpt-4o")
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "OpenAI", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "openai"], active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "OpenAI",
                models: [.init(id: model, name: "GPT-4o", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: model),
            settings: defaultHarnessSettings(piAI: .object([
                "providers": .object([
                    "openai": .object([
                        "models": .array([.object([
                            "id": .string(model.rawValue),
                            "input": .array([])
                        ])])
                    ])
                ])
            ]))
        )
        let capabilities = StaticModelCapabilityCatalog([
            ModelRoute(provider: provider, model: model): [.text, .image]
        ])

        let snapshot = try await ModelSelectionCoordinator(
            service: service,
            capabilityCatalog: capabilities
        ).loadCatalog()
        #expect(snapshot.provider(provider)?.models.first?.capabilities.inputModalities == [.text, .image])
    }

    @Test func customProfilesPreserveExactAuthenticationModes() async throws {
        let keyed = ProviderID("private-gateway")
        let declaredKeyless = ProviderID("declared-keyless")
        let privateNoAuth = ProviderID("private-no-auth")
        let catalogNative = ProviderID("groq")
        let directory = HarnessProviderDirectory(providers: [
            .init(
                provider: keyed, displayName: "Private Gateway", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", keyed.rawValue], active: true, declared: true
            ),
            .init(
                provider: declaredKeyless, displayName: "Declared Keyless", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", declaredKeyless.rawValue], active: true, declared: true
            ),
            .init(
                provider: privateNoAuth, displayName: "Private No Auth", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", privateNoAuth.rawValue], active: true, declared: true
            ),
            .init(
                provider: catalogNative, displayName: "Catalog Native", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", catalogNative.rawValue], active: true, declared: false
            )
        ])
        let catalog = HarnessModelCatalog(groups: [
            .init(id: keyed, name: "Private Gateway", models: [
                .init(id: ModelID("gateway-model"), name: "Gateway Model", description: nil, reasoning: nil)
            ]),
            .init(id: declaredKeyless, name: "Declared Keyless", models: [
                .init(id: ModelID("native-model"), name: "Native Model", description: nil, reasoning: nil)
            ]),
            .init(id: privateNoAuth, name: "Private No Auth", models: [
                .init(id: ModelID("private-model"), name: "Private Model", description: nil, reasoning: nil)
            ]),
            .init(id: catalogNative, name: "Catalog Native", models: [
                .init(id: ModelID("catalog-model"), name: "Catalog Model", description: nil, reasoning: nil)
            ])
        ], failures: [])
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                keyed.rawValue: .object([
                    "baseURL": .string("https://gateway.example/v1"),
                    "apiKeyEnv": .string("PRIVATE_GATEWAY_KEY")
                ]),
                declaredKeyless.rawValue: .object([
                    "baseURL": .string("http://192.168.1.20:8080/v1")
                ]),
                privateNoAuth.rawValue: .object([
                    "baseURL": .string("http://192.168.1.21:8080/v1"),
                    "api": .string("openai-completions"),
                    "unauthenticated": .bool(true)
                ]),
                catalogNative.rawValue: .object([
                    "baseURL": .string("https://api.groq.com/openai/v1"),
                    "api": .string("openai-completions")
                ])
            ])
        ]))
        let coordinator = ModelSelectionCoordinator(
            service: FakeModelRPCService(
                directory: directory,
                catalog: catalog,
                sessionState: emptySessionState(),
                settings: settings
            ),
            credentialService: FakeCatalogCredentialService(configured: false)
        )

        let snapshot = try await coordinator.loadCatalog()
        let keyedProvider = try #require(snapshot.provider(keyed))
        let keylessProvider = try #require(snapshot.provider(declaredKeyless))
        let noAuthProvider = try #require(snapshot.provider(privateNoAuth))
        let catalogProvider = try #require(snapshot.provider(catalogNative))

        #expect(keyedProvider.descriptor.credentialReference == CredentialReference("PRIVATE_GATEWAY_KEY"))
        #expect(keyedProvider.configurationState == .needsCredential)
        #expect(keylessProvider.descriptor.credentialReference == nil)
        #expect(keylessProvider.configurationState == .needsCredential)
        #expect(keylessProvider.descriptor.authenticationMode == .providerNative)
        #expect(noAuthProvider.configurationState == .ready)
        #expect(noAuthProvider.descriptor.authenticationMode == .explicitlyUnauthenticated)
        #expect(catalogProvider.configurationState == .ready)
        #expect(catalogProvider.descriptor.authenticationMode == .providerNative)
    }

    @Test func explicitNoAuthCatalogCollisionNeverInheritsTheCatalogCredential() async throws {
        let provider = ProviderID("groq")
        let endpoint = "http://127.0.0.1:49172/v1"
        let rawProfile: HarnessJSONValue = .object([
            "providers": .object([
                provider.rawValue: .object([
                    "displayName": .string("Private Groq-compatible Gateway"),
                    "api": .string("openai-completions"),
                    "baseURL": .string(endpoint),
                    "unauthenticated": .bool(true),
                    "models": .array([.object([
                        "id": .string("local-model"),
                        "name": .string("Local Model"),
                        "input": .array([.string("text")]),
                        "contextWindow": .integer(8_192),
                        "maxTokens": .integer(2_048)
                    ])])
                ])
            ])
        ])
        var resolvedProvider = try #require(
            rawProfile.objectValue?["providers"]?.objectValue?[provider.rawValue]?.objectValue
        )
        // Simulate DSH's resolved catalog layer supplying an installed-route
        // credential default. Native projection must still trust raw user auth.
        resolvedProvider["apiKeyEnv"] = .string("GROQ_API_KEY")
        let resolved: HarnessJSONValue = .object([
            "providers": .object([provider.rawValue: .object(resolvedProvider)])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "Private Groq-compatible Gateway",
                settingsNs: "llm-pi-ai", settingsPath: ["providers", provider.rawValue],
                active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "Private Groq-compatible Gateway",
                models: [.init(id: ModelID("local-model"), name: "Local Model", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: ModelID("local-model")),
            settings: defaultHarnessSettings(piAI: resolved, piAIUser: rawProfile)
        )

        let projected = try #require(
            try await ModelSelectionCoordinator(service: service).loadCatalog().provider(provider)
        )
        #expect(projected.descriptor.credentialReference == nil)
        #expect(projected.descriptor.explicitlyUnauthenticated)
        #expect(projected.descriptor.supportsNativeProfileEditing)
        #expect(projected.configurationState == .ready)
    }

    @Test func builtInPiAIProfilesProjectConfiguredAuthenticationAndProtocolExactly() async throws {
        let provider = BuiltInProviderDescriptors.openAI.id
        let endpoint = "http://127.0.0.1:49173/v1"
        let profile: HarnessJSONValue = .object([
            "providers": .object([
                provider.rawValue: .object([
                    "baseURL": .string(endpoint),
                    "api": .string("openai-completions"),
                    "unauthenticated": .bool(true)
                ])
            ])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "Private OpenAI-compatible Gateway",
                settingsNs: "llm-pi-ai", settingsPath: ["providers", provider.rawValue],
                active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "Private OpenAI-compatible Gateway",
                models: [.init(id: ModelID("private-model"), name: "Private Model", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: ModelID("private-model")),
            settings: defaultHarnessSettings(piAI: profile)
        )

        let projected = try #require(
            try await ModelSelectionCoordinator(service: service).loadCatalog().provider(provider)
        )
        #expect(projected.descriptor.defaultBaseURL == URL(string: endpoint))
        #expect(projected.descriptor.wireProtocol == .openAICompletions)
        #expect(projected.descriptor.credentialReference == nil)
        #expect(projected.descriptor.explicitlyUnauthenticated)
        #expect(projected.boundary == .localNetwork)
        #expect(projected.configurationState == .ready)
    }

    @Test func builtInPiAICredentialOverrideNeverFallsBackToThePolicyKey() async throws {
        let provider = BuiltInProviderDescriptors.openAI.id
        let profile: HarnessJSONValue = .object([
            "providers": .object([
                provider.rawValue: .object([
                    "baseURL": .string("https://gateway.example.test/v1"),
                    "api": .string("openai-responses"),
                    "apiKeyEnv": .string("PRIVATE_GATEWAY_KEY")
                ])
            ])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "Private Gateway",
                settingsNs: "llm-pi-ai", settingsPath: ["providers", provider.rawValue],
                active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "Private Gateway",
                models: [.init(id: ModelID("gateway-model"), name: "Gateway Model", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: ModelID("gateway-model")),
            settings: defaultHarnessSettings(piAI: profile)
        )

        let projected = try #require(
            try await ModelSelectionCoordinator(service: service).loadCatalog().provider(provider)
        )
        #expect(projected.descriptor.credentialReference == CredentialReference("PRIVATE_GATEWAY_KEY"))
        #expect(projected.descriptor.wireProtocol == .openAIResponses)
        #expect(!projected.descriptor.explicitlyUnauthenticated)
    }

    @Test func declaredCustomRouteWithoutRawAuthenticationStateFailsClosed() async throws {
        let provider = ProviderID("raw-state-unavailable")
        let piAI: HarnessJSONValue = .object([
            "providers": .object([
                provider.rawValue: .object([
                    "baseURL": .string("https://gateway.example.test/v1"),
                    "api": .string("openai-completions")
                ])
            ])
        ])
        let settings = HarnessSettingsDescription(
            writable: true,
            hasDocument: true,
            namespaces: [.init(
                ns: "llm-pi-ai", schema: .object([:]), value: piAI,
                base: nil, user: nil, applies: .live, secrets: [], revision: 1
            )]
        )
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "Raw State Unavailable",
                settingsNs: "llm-pi-ai", settingsPath: ["providers", provider.rawValue],
                active: true, declared: true
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "Raw State Unavailable",
                models: [.init(id: ModelID("model"), name: "Model", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: ModelID("model")),
            settings: settings
        )

        let projected = try #require(
            try await ModelSelectionCoordinator(service: service).loadCatalog().provider(provider)
        )
        #expect(projected.configurationState == .unavailable)
        #expect(projected.failureMessage == "Configured provider authentication is invalid or unsafe")
        #expect(projected.descriptor.authenticationMode == .providerNative)
    }

    @Test func tamperedOllamaNoAuthProfileNeverProjectsAsReady() async throws {
        let provider = BuiltInProviderDescriptors.ollama.id
        let profile: HarnessJSONValue = .object([
            "providers": .object([
                provider.rawValue: .object([
                    "baseURL": .string("http://127.0.0.1:49175/v1"),
                    "api": .string("openai-completions"),
                    "unauthenticated": .bool(true)
                ])
            ])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "Ollama (Local)",
                settingsNs: "llm-pi-ai", settingsPath: ["providers", provider.rawValue],
                active: true, declared: false
            )]),
            catalog: .init(groups: [.init(
                id: provider, name: "Ollama (Local)",
                models: [.init(id: ModelID("model"), name: "Model", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: provider, model: ModelID("model")),
            settings: defaultHarnessSettings(piAI: profile)
        )

        let projected = try #require(
            try await ModelSelectionCoordinator(service: service).loadCatalog().provider(provider)
        )
        #expect(projected.configurationState == .unavailable)
        #expect(projected.failureMessage == "Configured provider authentication is invalid or unsafe")
        #expect(projected.descriptor.credentialReference == CredentialReference("OLLAMA_API_KEY"))
        #expect(!projected.descriptor.explicitlyUnauthenticated)
    }

    @Test func explicitGenericDescriptorCanClassifyUnknownRouteAsLocalNetwork() async throws {
        let provider = ProviderID("lab/gateway:8080")
        let descriptor = BuiltInProviderDescriptors.openAICompatible(
            id: provider,
            displayName: "Lab Gateway",
            baseURL: URL(string: "http://192.168.1.20:8080/v1")!,
            boundary: .localNetwork
        )
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: provider, displayName: "DSH Lab", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", provider.rawValue], active: true, declared: true
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(provider: provider)
        )
        let coordinator = ModelSelectionCoordinator(service: service, descriptors: [descriptor])
        let snapshot = try await coordinator.loadCatalog()

        #expect(snapshot.provider(provider)?.boundary == .localNetwork)
        #expect(snapshot.provider(provider)?.displayName == "DSH Lab")
        #expect(await coordinator.dataBoundary(for: provider) == .localNetwork)
    }

    @Test func catalogUsesResolvedConfiguredEndpointAndReclassifiesBoundary() async throws {
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                "openai": .object(["baseURL": .string("http://192.168.1.20:8080/v1")])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("openai"), displayName: "Office Gateway", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "openai"], active: true, declared: true
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: settings
        )
        let snapshot = try await ModelSelectionCoordinator(service: service).loadCatalog()
        let provider = try #require(snapshot.provider(ProviderID("openai")))
        #expect(provider.descriptor.defaultBaseURL == URL(string: "http://192.168.1.20:8080/v1"))
        #expect(provider.boundary == .localNetwork)
    }

    @Test func customLoopbackProviderRequiresOriginBoundLocalNetworkConsent() async throws {
        let providerID = ProviderID("private-loopback-gateway")
        let endpoint = URL(string: "http://127.0.0.1:49200/v1")!
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                providerID.rawValue: .object([
                    "baseURL": .string(endpoint.absoluteString),
                    "api": .string("openai-completions"),
                    "unauthenticated": .bool(true)
                ])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: providerID,
                displayName: "Private Loopback Gateway",
                settingsNs: "llm-pi-ai",
                settingsPath: ["providers", providerID.rawValue],
                active: true,
                declared: true
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(provider: providerID),
            settings: settings
        )

        let snapshot = try await ModelSelectionCoordinator(service: service).loadCatalog()
        let provider = try #require(snapshot.provider(providerID))
        #expect(provider.boundary == .localNetwork)
        #expect(provider.descriptor.defaultBaseURL == endpoint)
        #expect(provider.descriptor.explicitlyUnauthenticated)
        #expect(provider.configurationState == .ready)

        let selection = ModelSelection(route: .init(provider: providerID, model: ModelID("test")))
        #expect(ProviderEgressPolicy.allowedOrigins(selection: selection, consent: .init()).isEmpty)
        let consent = ProviderConsentState(
            activeProvider: providerID,
            grants: [ProviderConsentGrant(for: provider.descriptor)]
        )
        #expect(ProviderEgressPolicy.allowedOrigins(selection: selection, consent: consent) == [
            ProviderNetworkOrigin(url: endpoint)!
        ])
    }

    @Test func unsafeConfiguredEndpointFailsClosedInsteadOfFallingBackToOfficialOrigin() async throws {
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                "openai": .object(["baseURL": .string("http://public.example.test/v1")])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("openai"), displayName: "OpenAI", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "openai"], active: true, declared: true
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: settings
        )
        let provider = try #require(try await ModelSelectionCoordinator(service: service).loadCatalog().provider(ProviderID("openai")))
        #expect(provider.descriptor.defaultBaseURL == nil)
        #expect(provider.configurationState == .unavailable)
    }

    @Test func explicitlyConfiguredUnreviewedWireProtocolFailsClosed() async throws {
        let providerID = ProviderID("future-websocket-provider")
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                providerID.rawValue: .object([
                    "baseURL": .string("https://provider.example.test/v1"),
                    "api": .string("openai-codex-responses")
                ])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: providerID,
                displayName: "Future WebSocket Provider",
                settingsNs: "llm-pi-ai",
                settingsPath: ["providers", providerID.rawValue],
                active: true,
                declared: true
            )]),
            catalog: .init(groups: [.init(
                id: providerID,
                name: "Future WebSocket Provider",
                models: [.init(id: ModelID("future-model"), name: "Future", description: nil, reasoning: nil)]
            )], failures: []),
            sessionState: emptySessionState(provider: providerID, model: ModelID("future-model")),
            settings: settings
        )

        let provider = try #require(
            try await ModelSelectionCoordinator(service: service).loadCatalog().provider(providerID)
        )
        #expect(provider.descriptor.wireProtocol == nil)
        #expect(provider.configurationState == .unavailable)
        #expect(provider.failureMessage == "Configured provider protocol has not been reviewed")
    }

    @Test func currentSelectionAlwaysRereadsDSHAndHonorsRoutableFlag() async throws {
        let service = FakeModelRPCService(
            directory: .init(providers: []),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(provider: ProviderID("ollama"), model: ModelID("first/model"), routable: true)
        )
        let coordinator = ModelSelectionCoordinator(service: service)
        let sessionID = HarnessSessionID("session/canonical:1")

        let first = try await coordinator.currentSelection(for: sessionID)
        #expect(first.selection.model == ModelID("first/model"))
        #expect(first.routable)
        await service.setSessionState(emptySessionState(
            provider: ProviderID("provider/removed"), model: ModelID("still-selected:model"), routable: false
        ))
        let second = try await coordinator.currentSelection(for: sessionID)
        #expect(second.selection.provider == ProviderID("provider/removed"))
        #expect(second.selection.model == ModelID("still-selected:model"))
        #expect(!second.routable)
        #expect(second.boundary == .cloud)
        let counts = await service.callCounts()
        #expect(counts.sessionModels == 2)
    }

    @Test func sessionSelectionKeepsOpaqueProviderAndModelSeparateAndTrustsNormalizedReply() async throws {
        let service = FakeModelRPCService(
            directory: .init(providers: []),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState()
        )
        await service.setNormalizedSelection(.init(
            provider: ProviderID("openai"), model: ModelID("normalized/model:v2"), reasoningEffort: "provider/default"
        ))
        let coordinator = ModelSelectionCoordinator(service: service)
        let sessionID = HarnessSessionID("session/one:1")
        let requestedRoute = ModelRoute(
            provider: ProviderID("gateway/acme:west"),
            model: ModelID("team/model:27b/q5")
        )

        let result = try await coordinator.select(
            sessionID: sessionID,
            route: requestedRoute,
            reasoningEffort: "reasoning/ultra:max"
        )
        let submitted = try #require(await service.lastSelection())
        #expect(submitted.0 == sessionID)
        #expect(submitted.1.provider == requestedRoute.provider)
        #expect(submitted.1.model == requestedRoute.model)
        #expect(submitted.1.reasoningEffort == "reasoning/ultra:max")
        #expect(result.selection.provider == ProviderID("openai"))
        #expect(result.selection.model == ModelID("normalized/model:v2"))
        #expect(result.boundary == .cloud)
        let counts = await service.callCounts()
        #expect(counts.selections == 1)
        #expect(counts.sessionModels == 0)
    }

    @Test func defaultSelectionMutatesHarnessAuthorityAndClearsStaleReasoning() async throws {
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState()
        )
        let selection = ModelSelection(route: .init(
            provider: ProviderID("deepseek-official"), model: ModelID("deepseek-reasoner")
        ))
        _ = try await ModelSelectionCoordinator(service: service).synchronizeDefault(selection)
        let mutation = try #require(await service.recordedMutations().last)
        #expect(mutation.0 == "agent-default-model")
        #expect(mutation.2 == 7)
        #expect(mutation.1 == [
            .set(path: ["provider"], value: .string("deepseek-official")),
            .set(path: ["model"], value: .string("deepseek-reasoner")),
            .unset(path: ["reasoningEffort"])
        ])
    }

    @Test func cleanHarnessHomeBootstrapsExactReviewedOllamaQwenProfileBeforeCatalogLoad() async throws {
        let ownedProviderURL = URL(string: "http://127.0.0.1:49152/v1")!
        let service = FakeModelRPCService(
            directory: .init(providers: []),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: .object([:]))
        )
        let coordinator = ModelSelectionCoordinator(service: service)

        #expect(try await coordinator.synchronizeAppOwnedLocalProvider(
            .defaultLocal,
            providerBaseURL: ownedProviderURL
        ))
        let mutation = try #require(await service.recordedMutations().last)
        #expect(mutation.0 == "llm-pi-ai")
        #expect(mutation.2 == 3)
        #expect(mutation.1.count == 1)
        guard case .set(let path, let rawProfile) = try #require(mutation.1.first),
              let profile = rawProfile.objectValue,
              case .array(let models)? = profile["models"],
              models.count == 1,
              let model = models[0].objectValue else {
            Issue.record("Expected one exact reviewed local profile")
            return
        }
        #expect(path == ["providers", "ollama"])
        #expect(profile["apiKeyEnv"] == .string("OLLAMA_API_KEY"))
        #expect(profile["api"] == .string("openai-completions"))
        #expect(profile["baseURL"] == .string(ownedProviderURL.absoluteString))
        #expect(profile["reasoning"] == .string("off"))
        #expect(profile["compat"] == .object([
            "maxTokensField": .string("max_tokens"),
            "supportsReasoningEffort": .bool(true)
        ]))
        #expect(model["id"] == .string("qwen3.8:27b-mlx"))
        #expect(model["contextWindow"] == .integer(49_152))
        #expect(model["maxTokens"] == .integer(8_192))
        #expect(model["input"] == .array([.string("text")]))
        #expect(model["reasoningEfforts"] == .object([
            "off": .string("none"),
            "high": .string("high")
        ]))
    }

    @Test func alternateOllamaModelGetsOnlyFixedTextToolCompatibilityMetadata() async throws {
        let ownedProviderURL = URL(string: "http://127.0.0.1:49153/v1")!
        let service = FakeModelRPCService(
            directory: .init(providers: []),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: .object([:]))
        )
        let selection = ModelSelection(
            route: .init(provider: ProviderID("ollama"), model: ModelID("llama-tools:latest")),
            reasoningEffort: "high",
            performanceProfile: .deep
        )
        #expect(selection.performanceProfile == .compatibility)
        #expect(selection.reasoningEffort == nil)

        _ = try await ModelSelectionCoordinator(service: service).synchronizeAppOwnedLocalProvider(
            selection,
            providerBaseURL: ownedProviderURL
        )
        let mutation = try #require(await service.recordedMutations().last)
        guard case .set(_, let rawProfile) = try #require(mutation.1.first),
              let profile = rawProfile.objectValue,
              case .array(let models)? = profile["models"],
              let model = models.first?.objectValue else {
            Issue.record("Expected one compatibility profile")
            return
        }
        #expect(profile["reasoning"] == nil)
        #expect(profile["compat"] == .object(["maxTokensField": .string("max_tokens")]))
        #expect(model["id"] == .string("llama-tools:latest"))
        #expect(model["contextWindow"] == .integer(8_192))
        #expect(model["maxTokens"] == .integer(2_048))
        #expect(model["input"] == .array([.string("text")]))
        #expect(model["reasoningEfforts"] == nil)
    }

    @Test func localBootstrapIsIdempotentOnlyForTheExactOwnedProfile() async throws {
        let ownedProviderURL = URL(string: "http://127.0.0.1:49152/v1")!
        let existing: HarnessJSONValue = .object([
            "apiKeyEnv": .string("OLLAMA_API_KEY"),
            "displayName": .string("Ollama (Local)"),
            "api": .string("openai-completions"),
            "baseURL": .string(ownedProviderURL.absoluteString),
            "reasoning": .string("off"),
            "compat": .object([
                "maxTokensField": .string("max_tokens"),
                "supportsReasoningEffort": .bool(true)
            ]),
            "models": .array([.object([
                "id": .string("qwen3.8:27b-mlx"),
                "name": .string("Qwen 3.8 27B MLX (Local)"),
                "contextWindow": .integer(49_152),
                "maxTokens": .integer(8_192),
                "input": .array([.string("text")]),
                "reasoningEfforts": .object([
                    "off": .string("none"),
                    "high": .string("high")
                ])
            ])])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: .object([
                "providers": .object(["ollama": existing])
            ]))
        )

        #expect(try await !ModelSelectionCoordinator(service: service)
            .synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: ownedProviderURL))
        #expect(await service.recordedMutations().isEmpty)
    }

    @Test func localBootstrapVerifiesThePersistedUserLayerInsteadOfSchemaResolvedDefaults() async throws {
        let ownedProviderURL = URL(string: "http://127.0.0.1:49152/v1")!
        let rawProfile: HarnessJSONValue = .object([
            "apiKeyEnv": .string("OLLAMA_API_KEY"),
            "displayName": .string("Ollama (Local)"),
            "api": .string("openai-completions"),
            "baseURL": .string(ownedProviderURL.absoluteString),
            "reasoning": .string("off"),
            "compat": .object([
                "maxTokensField": .string("max_tokens"),
                "supportsReasoningEffort": .bool(true)
            ]),
            "models": .array([.object([
                "id": .string("qwen3.8:27b-mlx"),
                "name": .string("Qwen 3.8 27B MLX (Local)"),
                "contextWindow": .integer(49_152),
                "maxTokens": .integer(8_192),
                "input": .array([.string("text")]),
                "reasoningEfforts": .object([
                    "off": .string("none"),
                    "high": .string("high")
                ])
            ])])
        ])
        guard var resolvedProfile = rawProfile.objectValue else {
            Issue.record("Expected an object profile")
            return
        }
        // DSH's schema-resolved `value` contains defaults that do not exist in
        // settings.yaml. The redacted `user` layer is the durable write proof.
        resolvedProfile["defaultContextWindow"] = .integer(200_000)
        resolvedProfile["defaultInput"] = .array([.string("text")])
        let rawNamespace = HarnessJSONValue.object(["providers": .object(["ollama": rawProfile])])
        let resolvedNamespace = HarnessJSONValue.object([
            "providers": .object(["ollama": .object(resolvedProfile)])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: resolvedNamespace, piAIUser: rawNamespace)
        )

        #expect(try await !ModelSelectionCoordinator(service: service)
            .synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: ownedProviderURL))
        #expect(await service.recordedMutations().isEmpty)
    }

    @Test func localBootstrapReplacesPersistedConventionalPortAndUnreviewedFields() async throws {
        let stale: HarnessJSONValue = .object([
            "baseURL": .string("http://127.0.0.1:11434/v1"),
            "headers": .object(["X-Unreviewed": .string("must-not-survive")]),
            "models": .array([.object(["id": .string("qwen3.8:27b-mlx")])])
        ])
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: .object([
                "providers": .object(["ollama": stale])
            ]))
        )
        let ownedProviderURL = URL(string: "http://127.0.0.1:49153/v1")!

        #expect(try await ModelSelectionCoordinator(service: service)
            .synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: ownedProviderURL))
        let mutation = try #require(await service.recordedMutations().last)
        guard case .set(_, let replacement) = try #require(mutation.1.first),
              let profile = replacement.objectValue else {
            Issue.record("Expected a complete replacement profile")
            return
        }
        #expect(profile["baseURL"] == .string(ownedProviderURL.absoluteString))
        #expect(profile["headers"] == nil)
    }

    @Test func anySafeInstalledModelIdentityCanBeSelectedRestartedAndReverted() async throws {
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: .object([:]))
        )
        let endpoint = URL(string: "http://127.0.0.1:49154/v1")!
        let alternate = ModelSelection(
            route: .init(provider: ProviderID("ollama"), model: ModelID("registry.example:5000/team/coder:Q6_K")),
            performanceProfile: .deep
        )

        let first = ModelSelectionCoordinator(service: service)
        #expect(try await first.synchronizeAppOwnedLocalProvider(alternate, providerBaseURL: endpoint))

        // A fresh coordinator represents a native app restart against the
        // persisted private DSH home. The exact route is already durable.
        let restarted = ModelSelectionCoordinator(service: service)
        #expect(try await !restarted.synchronizeAppOwnedLocalProvider(alternate, providerBaseURL: endpoint))

        #expect(try await restarted.synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: endpoint))
        let mutation = try #require(await service.recordedMutations().last)
        guard case .set(_, let replacement) = try #require(mutation.1.first),
              case .array(let models)? = replacement.objectValue?["models"],
              let model = models.first?.objectValue else {
            Issue.record("Expected the reverted local model profile")
            return
        }
        #expect(model["id"] == .string(BuiltInProviderDescriptors.qwenLocalModel.id.rawValue))
    }

    @Test func localBootstrapRetriesOneConflictAndVerifiesDurableSettings() async throws {
        let ownedProviderURL = URL(string: "http://127.0.0.1:49152/v1")!
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(), settings: defaultHarnessSettings(piAI: .object([:]))
        )
        await service.setMutationFailures([
            .remote(.init(code: .settingsConflict, message: "stale", details: [:]))
        ])
        #expect(try await ModelSelectionCoordinator(service: service)
            .synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: ownedProviderURL))
        #expect(await service.recordedMutations().count == 2)

        let nonPersisting = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(), settings: defaultHarnessSettings(piAI: .object([:]))
        )
        await nonPersisting.setPersistMutations(false)
        await #expect(throws: ModelSelectionCoordinatorError.localProviderBootstrapVerificationFailed) {
            _ = try await ModelSelectionCoordinator(service: nonPersisting)
                .synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: ownedProviderURL)
        }
    }

    @Test func localBootstrapIgnoresRemoteDefaultsRepairsMalformedAndRejectsUnownedEndpoints() async throws {
        let ownedProviderURL = URL(string: "http://127.0.0.1:49152/v1")!
        let remote = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(), settings: defaultHarnessSettings(piAI: .object([:]))
        )
        let remoteSelection = ModelSelection(route: .init(
            provider: ProviderID("deepseek-official"), model: ModelID("deepseek-chat")
        ))
        #expect(try await !ModelSelectionCoordinator(service: remote)
            .synchronizeAppOwnedLocalProvider(remoteSelection, providerBaseURL: ownedProviderURL))
        #expect(await remote.recordedMutations().isEmpty)

        let malformed = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: defaultHarnessSettings(piAI: .object([
                "providers": .object(["ollama": .string("unsafe")])
            ]))
        )
        #expect(try await ModelSelectionCoordinator(service: malformed)
            .synchronizeAppOwnedLocalProvider(.defaultLocal, providerBaseURL: ownedProviderURL))
        #expect(await malformed.recordedMutations().count == 1)

        for invalid in [
            "http://127.0.0.1:49152/other",
            "http://localhost:49152/v1",
            "https://127.0.0.1:49152/v1",
            "http://127.0.0.1:49152/v1?target=elsewhere",
            "http://user:secret@127.0.0.1:49152/v1"
        ] {
            await #expect(throws: ModelSelectionCoordinatorError.localProviderEndpointInvalid) {
                _ = try await ModelSelectionCoordinator(service: malformed)
                    .synchronizeAppOwnedLocalProvider(
                        .defaultLocal,
                        providerBaseURL: URL(string: invalid)!
                    )
            }
        }
    }

    @Test func cleanHarnessCloudDefaultIsReplacedByVerifiedNativeLocalDefault() async throws {
        let cloudDefault = HarnessSettingsDescription(
            writable: true,
            hasDocument: true,
            namespaces: [
                .init(
                    ns: "agent-default-model",
                    schema: .object([:]),
                    value: .object([
                        "provider": .string("deepseek-official"),
                        "model": .string("deepseek-v4-flash"),
                        "reasoningEffort": .string("high")
                    ]),
                    base: nil,
                    user: nil,
                    applies: .live,
                    secrets: [],
                    revision: 1
                )
            ]
        )
        let service = FakeModelRPCService(
            directory: .init(providers: []),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(),
            settings: cloudDefault
        )

        let result = try await ModelSelectionCoordinator(service: service).synchronizeDefault(.defaultLocal)
        #expect(result.value.objectValue?["provider"] == .string("ollama"))
        #expect(result.value.objectValue?["model"] == .string("qwen3.8:27b-mlx"))
        #expect(result.value.objectValue?["reasoningEffort"] == nil)
    }

    @Test func defaultSynchronizationFailsClosedWhenHarnessReturnsDifferentRoute() async throws {
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState()
        )
        let stale = HarnessSettingsNamespace(
            ns: "agent-default-model",
            schema: .object([:]),
            value: .object([
                "provider": .string("deepseek-official"),
                "model": .string("deepseek-v4-flash")
            ]),
            base: nil,
            user: nil,
            applies: .live,
            secrets: [],
            revision: 8
        )
        await service.setMutationReplyOverride(stale)

        await #expect(throws: ModelSelectionCoordinatorError.defaultVerificationFailed) {
            _ = try await ModelSelectionCoordinator(service: service).synchronizeDefault(.defaultLocal)
        }
    }

    @Test func defaultSelectionRetriesOneRevisionConflict() async throws {
        let service = FakeModelRPCService(
            directory: .init(providers: []), catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState()
        )
        await service.setMutationFailures([.remote(.init(code: .settingsConflict, message: "stale", details: [:]))])
        _ = try await ModelSelectionCoordinator(service: service).synchronizeDefault(.defaultLocal)
        #expect(await service.recordedMutations().count == 2)
    }

    @Test func localPerformanceSynchronizesOnlyTheExactConfiguredModelAndVerifiesTheWrite() async throws {
        let selectedModel = ModelID("qwen3.8:27b-mlx")
        let sibling: HarnessJSONValue = .object([
            "id": .string("qwen3:8b"),
            "name": .string("Small sibling"),
            "contextWindow": .integer(8_192),
            "maxTokens": .integer(1_024)
        ])
        let selected: HarnessJSONValue = .object([
            "id": .string(selectedModel.rawValue),
            "name": .string("Hermes Qwen"),
            "contextWindow": .integer(65_536),
            "maxTokens": .integer(8_192),
            "input": .array([.string("text")])
        ])
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                "ollama": .object([
                    "baseURL": .string("http://127.0.0.1:11434/v1"),
                    "models": .array([sibling, selected]),
                    "streamIdleTimeoutMs": .integer(300_000)
                ])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("ollama"), displayName: "Ollama", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "ollama"], active: true, declared: false
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(model: selectedModel),
            settings: settings
        )
        let selection = ModelSelection(
            route: .init(provider: ProviderID("ollama"), model: selectedModel),
            performanceProfile: .balanced
        )

        let capability = try await ModelSelectionCoordinator(service: service)
            .synchronizeLocalPerformanceCapability(selection)

        #expect(capability == HarnessLocalPerformanceCapability(
            route: selection.route,
            contextWindowTokens: 49_152,
            maxOutputTokens: 8_192
        ))
        let mutation = try #require(await service.recordedMutations().last)
        #expect(mutation.0 == "llm-pi-ai")
        #expect(mutation.2 == 3)
        #expect(mutation.1.count == 1)
        guard case .set(let path, let value) = try #require(mutation.1.first) else {
            Issue.record("Expected one settings set operation")
            return
        }
        #expect(path == ["providers", "ollama", "models"])
        guard case .array(let models) = value else {
            Issue.record("Expected the complete preserved model array")
            return
        }
        #expect(models.count == 2)
        #expect(models[0] == sibling)
        let updated = try #require(models[1].objectValue)
        #expect(updated["name"] == .string("Hermes Qwen"))
        #expect(updated["input"] == .array([.string("text")]))
        #expect(updated["contextWindow"] == .integer(49_152))
        #expect(updated["maxTokens"] == .integer(8_192))
    }

    @Test func localPerformanceUsesOneModelOverrideWithoutNarrowingCatalogRoute() async throws {
        let model = ModelID("qwen3.8:27b-mlx")
        let existingOverride: HarnessJSONValue = .object([
            "name": .string("Preserved name"),
            "compat": .object(["supportsStore": .bool(false)])
        ])
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                "ollama": .object([
                    "models": .array([]),
                    "modelOverrides": .object([model.rawValue: existingOverride]),
                    "headers": .object(["X-Preserved": .string("yes")])
                ])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("ollama"), displayName: "Ollama", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "ollama"], active: true, declared: false
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(model: model),
            settings: settings
        )
        let selection = ModelSelection(
            route: .init(provider: ProviderID("ollama"), model: model),
            performanceProfile: .fast
        )

        _ = try await ModelSelectionCoordinator(service: service)
            .synchronizeLocalPerformanceCapability(selection)
        let mutation = try #require(await service.recordedMutations().last)
        #expect(mutation.1.count == 1)
        guard case .set(let path, let value) = try #require(mutation.1.first),
              case .object(let overrides) = value,
              let updated = overrides[model.rawValue]?.objectValue else {
            Issue.record("Expected one exact modelOverrides mutation")
            return
        }
        #expect(path == ["providers", "ollama", "modelOverrides"])
        #expect(updated["name"] == .string("Preserved name"))
        #expect(updated["compat"] == .object(["supportsStore": .bool(false)]))
        #expect(updated["contextWindow"] == .integer(32_768))
        #expect(updated["maxTokens"] == .integer(4_096))
    }

    @Test func alternateOllamaPerformanceNeverInheritsQwenCapacity() async throws {
        let model = ModelID("llama-tools:latest")
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                "ollama": .object([
                    "models": .array([.object([
                        "id": .string(model.rawValue),
                        "contextWindow": .integer(65_536),
                        "maxTokens": .integer(16_384)
                    ])])
                ])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("ollama"), displayName: "Ollama", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "ollama"], active: true, declared: false
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(model: model),
            settings: settings
        )
        let selection = ModelSelection(
            route: .init(provider: ProviderID("ollama"), model: model),
            performanceProfile: .deep
        )
        let capability = try await ModelSelectionCoordinator(service: service)
            .synchronizeLocalPerformanceCapability(selection)
        #expect(capability.contextWindowTokens == 8_192)
        #expect(capability.maxOutputTokens == 2_048)
        let mutation = try #require(await service.recordedMutations().last)
        guard case .set(_, .array(let models)) = try #require(mutation.1.first),
              let updated = models.first?.objectValue else {
            Issue.record("Expected compatibility model mutation")
            return
        }
        #expect(updated["contextWindow"] == .integer(8_192))
        #expect(updated["maxTokens"] == .integer(2_048))
    }

    @Test func localPerformanceRetriesOneConflictAndSkipsAnAlreadyExactWrite() async throws {
        let model = ModelID("qwen3.8:27b-mlx")
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object([
                "ollama": .object(["models": .array([.object([
                    "id": .string(model.rawValue),
                    "contextWindow": .integer(49_152),
                    "maxTokens": .integer(8_192)
                ])])])
            ])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("ollama"), displayName: "Ollama", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "ollama"], active: true, declared: false
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(model: model),
            settings: settings
        )

        _ = try await ModelSelectionCoordinator(service: service).synchronizeLocalPerformanceCapability(
            ModelSelection(
                route: .init(provider: ProviderID("ollama"), model: model),
                performanceProfile: .balanced
            )
        )
        #expect(await service.recordedMutations().isEmpty)

        await service.setMutationFailures([.remote(.init(code: .settingsConflict, message: "stale", details: [:]))])
        _ = try await ModelSelectionCoordinator(service: service).synchronizeLocalPerformanceCapability(
            ModelSelection(
                route: .init(provider: ProviderID("ollama"), model: model),
                performanceProfile: .deep
            )
        )
        #expect(await service.recordedMutations().count == 2)
    }

    @Test func localPerformanceFailsClosedForDuplicateExactModels() async throws {
        let model = ModelID("qwen3.8:27b-mlx")
        let duplicate: HarnessJSONValue = .object(["id": .string(model.rawValue)])
        let settings = defaultHarnessSettings(piAI: .object([
            "providers": .object(["ollama": .object(["models": .array([duplicate, duplicate])])])
        ]))
        let service = FakeModelRPCService(
            directory: .init(providers: [.init(
                provider: ProviderID("ollama"), displayName: "Ollama", settingsNs: "llm-pi-ai",
                settingsPath: ["providers", "ollama"], active: true, declared: false
            )]),
            catalog: .init(groups: [], failures: []),
            sessionState: emptySessionState(model: model),
            settings: settings
        )

        await #expect(throws: ModelSelectionCoordinatorError.localPerformanceModelUnavailable) {
            _ = try await ModelSelectionCoordinator(service: service).synchronizeLocalPerformanceCapability(
                ModelSelection(route: .init(provider: ProviderID("ollama"), model: model))
            )
        }
        #expect(await service.recordedMutations().isEmpty)
    }
}
