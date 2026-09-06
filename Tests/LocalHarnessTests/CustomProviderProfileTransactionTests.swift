import Foundation
import Testing
@testable import LocalHarness

private enum CustomProfileFixtureError: Error { case mutation }

private actor CustomProfileService: HarnessProviderActivationServicing {
    private var providerProfiles: [String: HarnessJSONValue]
    private var revision = 3
    private var credentials: [String: HarnessCredentialView]
    private let failAfterApplying: Bool
    private let writable: Bool
    private let hasDocument: Bool
    private let includeNamespace: Bool
    private let applies: HarnessSettingsApplyMode
    private let failMutationCalls: Set<Int>
    private let conflictMutationCalls: Set<Int>
    private let failCredentialSet: Bool
    private let failCredentialSetAfterApplying: Bool
    private let failCredentialUnset: Bool
    private let concurrentProfileAfterCredentialSet: HarnessJSONValue?
    private(set) var mutationCount = 0

    init(
        providerProfiles: [String: HarnessJSONValue] = [:],
        credentials: [String: HarnessCredentialView],
        failAfterApplying: Bool = false,
        writable: Bool = true,
        hasDocument: Bool = true,
        includeNamespace: Bool = true,
        applies: HarnessSettingsApplyMode = .live,
        failMutationCalls: Set<Int> = [],
        conflictMutationCalls: Set<Int> = [],
        failCredentialSet: Bool = false,
        failCredentialSetAfterApplying: Bool = false,
        failCredentialUnset: Bool = false,
        concurrentProfileAfterCredentialSet: HarnessJSONValue? = nil
    ) {
        self.providerProfiles = providerProfiles
        self.credentials = credentials
        self.failAfterApplying = failAfterApplying
        self.writable = writable
        self.hasDocument = hasDocument
        self.includeNamespace = includeNamespace
        self.applies = applies
        self.failMutationCalls = failMutationCalls
        self.conflictMutationCalls = conflictMutationCalls
        self.failCredentialSet = failCredentialSet
        self.failCredentialSetAfterApplying = failCredentialSetAfterApplying
        self.failCredentialUnset = failCredentialUnset
        self.concurrentProfileAfterCredentialSet = concurrentProfileAfterCredentialSet
    }

    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        .init(credentials: Dictionary(uniqueKeysWithValues: references.compactMap { reference in
            credentials[reference.rawValue].map { (reference.rawValue, $0) }
        }))
    }

    func setCredential(_ reference: CredentialReference, value: String) async throws {
        if failCredentialSet { throw CustomProfileFixtureError.mutation }
        credentials[reference.rawValue] = .init(configured: true, source: "fixture", writable: true)
        if let concurrentProfileAfterCredentialSet {
            providerProfiles["private-gateway"] = concurrentProfileAfterCredentialSet
            revision += 1
        }
        if failCredentialSetAfterApplying { throw CustomProfileFixtureError.mutation }
    }

    func unsetCredential(_ reference: CredentialReference) async throws {
        if failCredentialUnset { throw CustomProfileFixtureError.mutation }
        credentials[reference.rawValue] = .init(configured: false, source: nil, writable: true)
    }

    func describeSettings() async throws -> HarnessSettingsDescription {
        .init(writable: writable, hasDocument: hasDocument, namespaces: includeNamespace ? [namespace] : [])
    }

    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace {
        guard namespace == "llm-pi-ai" else {
            throw CustomProfileFixtureError.mutation
        }
        guard expectedRevision == revision else {
            throw HarnessRPCClientError.remote(.init(
                code: .settingsConflict,
                message: "fixture revision conflict",
                details: [:]
            ))
        }
        mutationCount += 1
        if failMutationCalls.contains(mutationCount) { throw CustomProfileFixtureError.mutation }
        if conflictMutationCalls.contains(mutationCount) {
            throw HarnessRPCClientError.remote(.init(
                code: .settingsConflict,
                message: "fixture conflict",
                details: [:]
            ))
        }
        for operation in operations {
            switch operation {
            case .set(let path, let value):
                guard path.count == 2, path[0] == "providers" else { throw CustomProfileFixtureError.mutation }
                providerProfiles[path[1]] = value
            case .unset(let path):
                guard path.count == 2, path[0] == "providers" else { throw CustomProfileFixtureError.mutation }
                providerProfiles[path[1]] = nil
            }
        }
        revision += 1
        if failAfterApplying, mutationCount == 1 { throw CustomProfileFixtureError.mutation }
        return namespaceView
    }

    func snapshot(reference: String, provider: String) -> (HarnessJSONValue?, Bool, Int) {
        (providerProfiles[provider], credentials[reference]?.configured == true, mutationCount)
    }

    private var namespace: HarnessSettingsNamespace { namespaceView }
    private var namespaceView: HarnessSettingsNamespace {
        .init(
            ns: "llm-pi-ai",
            schema: .object([:]),
            value: .object(["providers": .object(providerProfiles)]),
            base: nil,
            user: nil,
            applies: applies,
            secrets: [],
            revision: revision
        )
    }
}

private actor CustomProfileCatalog: ProviderCatalogLoading {
    let snapshot: HarnessModelCatalogSnapshot
    init(_ snapshot: HarnessModelCatalogSnapshot) { self.snapshot = snapshot }
    func loadCatalog() async throws -> HarnessModelCatalogSnapshot { snapshot }
}

private actor CustomProfileDefaultSynchronizer: ModelDefaultSynchronizing {
    func synchronizeDefault(_ selection: ModelSelection) async throws -> HarnessSettingsNamespace {
        .init(
            ns: "agent-default-model",
            schema: .object([:]),
            value: .object([
                "provider": .string(selection.route.provider.rawValue),
                "model": .string(selection.route.model.rawValue)
            ]),
            base: nil,
            user: nil,
            applies: .live,
            secrets: [],
            revision: 1
        )
    }
}

@MainActor
private final class CustomProfilePreferences: StrictLocalModeStoring {
    var strictLocalMode = true
}

private func customDraft(
    providerID: String = "private-gateway",
    displayName: String = "Private Gateway",
    wireProtocol: ProviderWireProtocol = .openAIResponses,
    endpoint: String = "https://gateway.example.test/v1",
    models: [CustomProviderModelDraft] = [.init(
        id: "gateway-model", displayName: "Gateway Model", inputModalities: [.text, .image]
    )],
    credentialReference: String? = "PRIVATE_GATEWAY_KEY",
    credentialValue: String? = "fixture-secret",
    unauthenticated: Bool = false
) -> CustomProviderProfileDraft {
    .init(
        providerID: providerID,
        displayName: displayName,
        wireProtocol: wireProtocol,
        baseURL: endpoint,
        models: models,
        credentialReference: credentialReference,
        credentialValue: credentialValue,
        unauthenticated: unauthenticated
    )
}

private func safelyEditableStoredProfile(
    endpoint: String = "https://old.example.test/v1"
) -> HarnessJSONValue {
    .object([
        "displayName": .string("Private Gateway"),
        "api": .string("openai-responses"),
        "baseURL": .string(endpoint),
        "apiKeyEnv": .string("PRIVATE_GATEWAY_KEY"),
        "models": .array([.object([
            "id": .string("gateway-model"),
            "name": .string("Gateway Model"),
            "input": .array([.string("text"), .string("image")]),
            "contextWindow": .integer(32_768),
            "maxTokens": .integer(4_096)
        ])])
    ])
}

private func readyCustomProvider(
    endpoint: URL = URL(string: "https://gateway.example.test/v1")!,
    wireProtocol: ProviderWireProtocol = .openAIResponses,
    credentialReference: CredentialReference? = CredentialReference("PRIVATE_GATEWAY_KEY"),
    modelName: String = "Gateway Model",
    modalities: [ModelInputModality] = [.text, .image],
    contextWindowTokens: Int = 32_768,
    maxOutputTokens: Int = 4_096
) -> ProviderView {
    let descriptor = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("private-gateway"),
        displayName: "Private Gateway",
        baseURL: endpoint,
        boundary: .cloud,
        credentialReference: credentialReference,
        wireProtocol: wireProtocol,
        explicitlyUnauthenticated: credentialReference == nil,
        supportsNativeProfileEditing: true
    )
    return .init(
        descriptor: descriptor,
        configurationState: .ready,
        models: [.init(
            id: ModelID("gateway-model"),
            displayName: modelName,
            detail: nil,
            capabilities: .init(
                inputModalities: modalities,
                contextWindowTokens: contextWindowTokens,
                maxOutputTokens: maxOutputTokens
            )
        )],
        failureMessage: nil
    )
}

@Test @MainActor
func badSelectedCustomProfileCanBeEditedVerifiedConsentedAndExactlyPromoted() async throws {
    let oldProfile = safelyEditableStoredProfile(endpoint: "https://wrong.example.test/v1")
    let service = CustomProfileService(
        providerProfiles: ["private-gateway": oldProfile],
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)]
    )
    let provider = readyCustomProvider()
    let editor = CustomProviderProfileTransaction(
        service: service,
        catalog: CustomProfileCatalog(.init(providers: [provider])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    let result = try await editor.save(customDraft())
    #expect(result.provider == provider)
    #expect(result.createdCredential)
    #expect(!result.createdProfile)
    let stored = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(stored.1)
    #expect(stored.2 == 1)
    #expect(stored.0?.objectValue?["api"] == .string("openai-responses"))
    #expect(stored.0?.objectValue?["baseURL"] == .string("https://gateway.example.test/v1"))
    let storedModels = try #require(stored.0?.objectValue?["models"])
    guard case .array(let modelValues) = storedModels else {
        Issue.record("The verified custom profile did not retain its model array")
        return
    }
    let storedModel = try #require(modelValues.first?.objectValue)
    #expect(storedModel["contextWindow"] == .integer(32_768))
    #expect(storedModel["maxTokens"] == .integer(4_096))

    let suite = "CustomProviderRecovery-\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let selected = ModelSelection(
        route: ModelRoute(provider: provider.id, model: provider.models[0].id)
    )
    try ModelProviderSettingsStore(defaults: defaults).save(.init(defaultSelection: selected))
    let support = FileManager.default.temporaryDirectory.appendingPathComponent("custom-provider-recovery-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
    defer { try? FileManager.default.removeItem(at: support) }
    let recovery = NativeProviderStateRecovery(defaults: defaults, applicationSupport: support)
    #expect(recovery.inspect().routeIssue == .consentUnavailable)

    let transaction = ProviderSelectionTransaction(
        coordinator: CustomProfileDefaultSynchronizer(),
        settingsStore: ModelProviderSettingsStore(defaults: defaults),
        consentStore: ProviderConsentStore(defaults: defaults),
        preferences: CustomProfilePreferences()
    )
    _ = try await transaction.commit(selection: selected, descriptor: provider.descriptor)
    #expect(!recovery.inspect().requiresRecovery)
    let consent = try ProviderConsentStore(defaults: defaults).load()
    #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: consent)
        == [ProviderNetworkOrigin(url: URL(string: "https://gateway.example.test/v1")!)!])

    let endpoint = HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:49152")!, token: "token", nonce: "nonce", processIdentifier: 42
    )
    let rpc = HarnessRPCClient(endpoint: endpoint, accessMode: .controlPlaneOnly)
    #expect(rpc.currentAccessMode() == .controlPlaneOnly)
    let replacement = HarnessEndpoint(
        baseURL: endpoint.baseURL, token: "other", nonce: endpoint.nonce, processIdentifier: 43
    )
    #expect(!rpc.promoteToFullInference(expected: replacement))
    #expect(rpc.promoteToFullInference(expected: endpoint))
    #expect(rpc.currentAccessMode() == .fullInference)
}

@Test
func malformedCustomProfileNeverTouchesCredentialOrSettings() async throws {
    let service = CustomProfileService(
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)]
    )
    let editor = CustomProviderProfileTransaction(
        service: service,
        catalog: CustomProfileCatalog(.init(providers: [])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    do {
        _ = try await editor.save(customDraft(endpoint: "http://public.example.test/v1"))
        Issue.record("Malformed public HTTP endpoint was accepted")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .invalidEndpoint)
        #expect(error.rollbackComplete)
    }
    let stored = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(stored.0 == nil)
    #expect(!stored.1)
    #expect(stored.2 == 0)
}

@Test
func advancedExternalProfileIsNeverReplacedByTheLossyNativeEditor() async throws {
    var advanced = try #require(safelyEditableStoredProfile().objectValue)
    advanced["retryPolicy"] = .object([
        "mode": .string("none"),
        "maxRetries": .integer(0)
    ])
    let original = HarnessJSONValue.object(advanced)
    let service = CustomProfileService(
        providerProfiles: ["private-gateway": original],
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: true, source: "fixture", writable: true)]
    )
    let editor = CustomProviderProfileTransaction(
        service: service,
        catalog: CustomProfileCatalog(.init(providers: [readyCustomProvider()])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )

    do {
        _ = try await editor.save(customDraft(credentialValue: nil))
        Issue.record("An advanced externally managed profile was replaced")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .profileManagedExternally)
        #expect(error.rollbackComplete)
    }

    let stored = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(stored.0 == original)
    #expect(stored.1)
    #expect(stored.2 == 0)
    #expect(!CustomProviderNativeEditingPolicy.isSafelyEditableProfile(original))
}

@Test
func customProfileMutationFailureRollsBackPriorProfileAndNewCredential() async throws {
    let oldProfile = safelyEditableStoredProfile()
    let service = CustomProfileService(
        providerProfiles: ["private-gateway": oldProfile],
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
        failAfterApplying: true
    )
    let editor = CustomProviderProfileTransaction(
        service: service,
        catalog: CustomProfileCatalog(.init(providers: [])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    do {
        _ = try await editor.save(customDraft())
        Issue.record("Fixture mutation failure unexpectedly succeeded")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .mutationNotVerified)
        #expect(error.rollbackComplete)
    }
    let stored = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(stored.0 == oldProfile)
    #expect(!stored.1)
    #expect(stored.2 == 2)
}

@Test
func explicitPrivateNoAuthAndExistingKeyProfilesPreserveTheirCredentialSemantics() async throws {
    let privateEndpoint = URL(string: "http://127.0.0.1:49161/v1")!
    let keylessProvider = readyCustomProvider(endpoint: privateEndpoint, credentialReference: nil)
    let keylessService = CustomProfileService(credentials: [:])
    let keyless = CustomProviderProfileTransaction(
        service: keylessService,
        catalog: CustomProfileCatalog(.init(providers: [keylessProvider])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    let keylessResult = try await keyless.save(customDraft(
        endpoint: privateEndpoint.absoluteString,
        credentialReference: nil,
        credentialValue: nil,
        unauthenticated: true
    ))
    #expect(!keylessResult.createdCredential)
    #expect(keylessResult.createdProfile)
    let keylessState = await keylessService.snapshot(reference: "", provider: "private-gateway")
    #expect(keylessState.0?.objectValue?["unauthenticated"] == .bool(true))
    #expect(keylessState.0?.objectValue?["apiKeyEnv"] == nil)

    let priorProfile = safelyEditableStoredProfile()
    let existingService = CustomProfileService(
        providerProfiles: ["private-gateway": priorProfile],
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: true, source: "fixture", writable: true)]
    )
    let existing = CustomProviderProfileTransaction(
        service: existingService,
        catalog: CustomProfileCatalog(.init(providers: [readyCustomProvider()])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    let existingResult = try await existing.save(customDraft(credentialValue: nil))
    #expect(!existingResult.createdCredential)
    #expect(!existingResult.createdProfile)
    let state = await existingService.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(state.1)

    do {
        _ = try await existing.save(customDraft(credentialValue: "replacement-must-not-be-written"))
        Issue.record("Existing credential was replaced inside the profile transaction")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .credentialReplacementRequiresSeparateAction)
        #expect(error.rollbackComplete)
    }
    let afterReplacementAttempt = await existingService.snapshot(
        reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway"
    )
    #expect(afterReplacementAttempt.1)
    #expect(afterReplacementAttempt.2 == 1)
}

@Test
func everyMalformedCustomProfileClassFailsBeforeAnyRPCMutation() async throws {
    let duplicateModels = [
        CustomProviderModelDraft(id: "same", displayName: "One", inputModalities: [.text]),
        CustomProviderModelDraft(id: "same", displayName: "Two", inputModalities: [.text])
    ]
    let invalidContext = CustomProviderModelDraft(
        id: "model", displayName: "Model", inputModalities: [.text],
        contextWindowTokens: 1_023, maxOutputTokens: 256
    )
    let outputBeyondContext = CustomProviderModelDraft(
        id: "model", displayName: "Model", inputModalities: [.text],
        contextWindowTokens: 4_096, maxOutputTokens: 4_097
    )
    let invalid: [(CustomProviderProfileDraft, CustomProviderProfileFailure)] = [
        (customDraft(providerID: "openai"), .builtInProviderReserved),
        (customDraft(providerID: String(repeating: "p", count: 257)), .invalidProviderID),
        (customDraft(displayName: "\n"), .invalidDisplayName),
        (customDraft(wireProtocol: ProviderWireProtocol("unreviewed-protocol")), .invalidProtocol),
        (customDraft(wireProtocol: .anthropicMessages, endpoint: "https://api.anthropic.com/v1"), .anthropicVersionPathNotAllowed),
        (customDraft(wireProtocol: .anthropicMessages, endpoint: "https://gateway.example.test/prefix/V1/"), .anthropicVersionPathNotAllowed),
        (customDraft(endpoint: "https://user:password@example.test/v1"), .invalidEndpoint),
        (customDraft(endpoint: "https://100.64.0.1/v1"), .invalidEndpoint),
        (customDraft(endpoint: "https://192.0.2.1/v1"), .invalidEndpoint),
        (customDraft(endpoint: "https://[2001:db8::1]/v1"), .invalidEndpoint),
        (customDraft(models: []), .invalidModels),
        (customDraft(models: duplicateModels), .invalidModels),
        (customDraft(models: [.init(id: "m", displayName: "M", inputModalities: [.image])]), .invalidModels),
        (customDraft(models: [.init(id: "m", displayName: "M", inputModalities: [.text, .audio])]), .invalidModels),
        (customDraft(models: [.init(id: "m", displayName: "M", inputModalities: [.text, .video])]), .invalidModels),
        (customDraft(models: [invalidContext]), .invalidModels),
        (customDraft(models: [outputBeyondContext]), .invalidModels),
        (customDraft(credentialReference: "lowercase-key"), .invalidCredentialReference),
        (customDraft(credentialReference: nil, credentialValue: nil), .credentialRequired),
        (customDraft(
            endpoint: "https://gateway.example.test/v1",
            credentialReference: nil,
            credentialValue: nil,
            unauthenticated: true
        ), .unauthenticatedEndpointNotAllowed),
        (customDraft(
            endpoint: "http://localhost:49161/v1",
            credentialReference: nil,
            credentialValue: nil,
            unauthenticated: true
        ), .unauthenticatedEndpointNotAllowed)
    ]
    for (draft, expected) in invalid {
        let service = CustomProfileService(
            credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)]
        )
        let editor = CustomProviderProfileTransaction(
            service: service,
            catalog: CustomProfileCatalog(.init(providers: [])),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        do {
            _ = try await editor.save(draft)
            Issue.record("Invalid profile unexpectedly succeeded")
        } catch let error as CustomProviderProfileTransactionError {
            #expect(error.cause == expected)
            #expect(error.rollbackComplete)
        }
        let state = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
        #expect(state.2 == 0)
    }
}

@Test
func readOnlyAndRestartSettingsRollBackANewCredentialWithoutProfileMutation() async throws {
    let cases: [(Bool, HarnessSettingsApplyMode, CustomProviderProfileFailure)] = [
        (false, .live, .settingsReadOnly),
        (true, .restart, .settingsRestartRequired)
    ]
    for (writable, applies, expected) in cases {
        let service = CustomProfileService(
            credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
            writable: writable,
            applies: applies
        )
        let editor = CustomProviderProfileTransaction(
            service: service,
            catalog: CustomProfileCatalog(.init(providers: [])),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        do {
            _ = try await editor.save(customDraft())
            Issue.record("Unsafe settings mode unexpectedly succeeded")
        } catch let error as CustomProviderProfileTransactionError {
            #expect(error.cause == expected)
            #expect(error.rollbackComplete)
        }
        let state = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
        #expect(!state.1)
        #expect(state.2 == 0)
    }
}

@Test
func unavailableSettingsAndRevisionConflictRollBackTheNewCredential() async throws {
    let unavailableCases = [
        CustomProfileService(
            credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
            hasDocument: false
        ),
        CustomProfileService(
            credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
            includeNamespace: false
        )
    ]
    for service in unavailableCases {
        let editor = CustomProviderProfileTransaction(
            service: service,
            catalog: CustomProfileCatalog(.init(providers: [])),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        do {
            _ = try await editor.save(customDraft())
            Issue.record("Unavailable settings unexpectedly accepted a profile")
        } catch let error as CustomProviderProfileTransactionError {
            #expect(error.cause == .settingsUnavailable)
            #expect(error.rollbackComplete)
        }
        let state = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
        #expect(state.0 == nil)
        #expect(!state.1)
        #expect(state.2 == 0)
    }

    let conflictService = CustomProfileService(
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
        conflictMutationCalls: [1]
    )
    let conflictEditor = CustomProviderProfileTransaction(
        service: conflictService,
        catalog: CustomProfileCatalog(.init(providers: [])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    do {
        _ = try await conflictEditor.save(customDraft())
        Issue.record("Conflicting revision unexpectedly accepted a profile")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .settingsConflict)
        #expect(error.rollbackComplete)
    }
    let conflictState = await conflictService.snapshot(
        reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway"
    )
    #expect(conflictState.0 == nil)
    #expect(!conflictState.1)
    #expect(conflictState.2 == 1)
}

@Test
func concurrentProfileCreatedDuringCredentialWriteIsPreservedAndCredentialRollsBack() async throws {
    let concurrent = safelyEditableStoredProfile(endpoint: "https://concurrent.example.test/v1")
    let service = CustomProfileService(
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
        concurrentProfileAfterCredentialSet: concurrent
    )
    let editor = CustomProviderProfileTransaction(
        service: service,
        catalog: CustomProfileCatalog(.init(providers: [])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )

    do {
        _ = try await editor.save(customDraft())
        Issue.record("Concurrent profile creation unexpectedly got overwritten")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .settingsConflict)
        #expect(error.rollbackComplete)
    }

    let state = await service.snapshot(
        reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway"
    )
    #expect(state.0 == concurrent)
    #expect(!state.1)
    #expect(state.2 == 0)
}

@Test
func credentialApplyThenLostResponseIsCompensatedAndRollbackFailureIsReported() async throws {
    for failRollback in [false, true] {
        let service = CustomProfileService(
            credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
            failCredentialSetAfterApplying: true,
            failCredentialUnset: failRollback
        )
        let editor = CustomProviderProfileTransaction(
            service: service,
            catalog: CustomProfileCatalog(.init(providers: [])),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        do {
            _ = try await editor.save(customDraft())
            Issue.record("Lost credential response unexpectedly completed the transaction")
        } catch let error as CustomProviderProfileTransactionError {
            #expect(error.cause == .credentialWriteNotVerified)
            #expect(error.rollbackComplete == !failRollback)
        }
        let state = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
        #expect(state.0 == nil)
        #expect(state.1 == failRollback)
        #expect(state.2 == 0)
    }
}

@Test
func catalogMustMatchExactEndpointProtocolCredentialModelNameAndModalities() async throws {
    let mismatches = [
        readyCustomProvider(endpoint: URL(string: "https://other.example.test/v1")!),
        readyCustomProvider(wireProtocol: .anthropicMessages),
        readyCustomProvider(credentialReference: CredentialReference("OTHER_KEY")),
        readyCustomProvider(modelName: "Different Name"),
        readyCustomProvider(modalities: [.text])
    ]
    for mismatch in mismatches {
        let old = safelyEditableStoredProfile()
        let service = CustomProfileService(
            providerProfiles: ["private-gateway": old],
            credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)]
        )
        let editor = CustomProviderProfileTransaction(
            service: service,
            catalog: CustomProfileCatalog(.init(providers: [mismatch])),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        do {
            _ = try await editor.save(customDraft())
            Issue.record("Mismatched live catalog unexpectedly verified")
        } catch let error as CustomProviderProfileTransactionError {
            #expect(error.cause == .providerNotReady)
            #expect(error.rollbackComplete)
        }
        let state = await service.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
        #expect(state.0 == old)
        #expect(!state.1)
    }
}

@Test
func cancellationAfterMutationRollsBackAndRollbackConflictIsReportedIncomplete() async throws {
    let old = safelyEditableStoredProfile()
    let cancellationService = CustomProfileService(
        providerProfiles: ["private-gateway": old],
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)]
    )
    let cancellingEditor = CustomProviderProfileTransaction(
        service: cancellationService,
        catalog: CustomProfileCatalog(.init(providers: [])),
        catalogAttempts: 2,
        catalogRetryNanoseconds: 10_000_000_000
    )
    let task = Task { try await cancellingEditor.save(customDraft()) }
    while await cancellationService.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway").2 == 0 {
        await Task.yield()
    }
    task.cancel()
    do {
        _ = try await task.value
        Issue.record("Cancelled edit unexpectedly succeeded")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(error.cause == .cancelled)
        #expect(error.rollbackComplete)
    }
    let cancelled = await cancellationService.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(cancelled.0 == old)
    #expect(!cancelled.1)

    let conflictService = CustomProfileService(
        providerProfiles: ["private-gateway": old],
        credentials: ["PRIVATE_GATEWAY_KEY": .init(configured: false, source: nil, writable: true)],
        failMutationCalls: [2]
    )
    let conflictEditor = CustomProviderProfileTransaction(
        service: conflictService,
        catalog: CustomProfileCatalog(.init(providers: [])),
        catalogAttempts: 1,
        catalogRetryNanoseconds: 0
    )
    do {
        _ = try await conflictEditor.save(customDraft())
        Issue.record("Catalog failure unexpectedly succeeded")
    } catch let error as CustomProviderProfileTransactionError {
        #expect(!error.rollbackComplete)
    }
    let conflicted = await conflictService.snapshot(reference: "PRIVATE_GATEWAY_KEY", provider: "private-gateway")
    #expect(conflicted.0 != old)
    #expect(!conflicted.1)
}
