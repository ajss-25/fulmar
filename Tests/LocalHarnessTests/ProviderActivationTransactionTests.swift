import Foundation
import Testing
@testable import LocalHarness

private enum ActivationFixtureError: Error {
    case settingsMutation
    case credentialSet
    case credentialUnset
    case invalidPath
}

private func applyingActivationOperation(
    _ operation: HarnessSettingsPathOperation,
    to root: HarnessJSONValue
) throws -> HarnessJSONValue {
    func update(
        _ value: HarnessJSONValue,
        path: ArraySlice<String>,
        replacement: HarnessJSONValue?
    ) throws -> HarnessJSONValue {
        guard let component = path.first, !component.isEmpty,
              case .object(var object) = value else { throw ActivationFixtureError.invalidPath }
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
        guard !path.isEmpty else { throw ActivationFixtureError.invalidPath }
        return try update(root, path: path[...], replacement: value)
    case .unset(let path):
        guard !path.isEmpty else { throw ActivationFixtureError.invalidPath }
        return try update(root, path: path[...], replacement: nil)
    }
}

private func activationValue(at path: [String], in root: HarnessJSONValue) -> HarnessJSONValue? {
    var current = root
    for component in path {
        guard case .object(let object) = current, let next = object[component] else { return nil }
        current = next
    }
    return current
}

private actor ActivationService: HarnessProviderActivationServicing {
    private var credentials: [String: HarnessCredentialView]
    private var settings: HarnessSettingsDescription
    private var mutationCalls = 0
    private var failMutationCalls: Set<Int>
    private var failAfterApplyingMutationCalls: Set<Int>
    private var failCredentialSet: Bool
    private var failAfterApplyingCredentialSet: Bool
    private var failCredentialUnset: Bool
    private(set) var setReferences: [CredentialReference] = []
    private(set) var unsetReferences: [CredentialReference] = []
    private(set) var mutations: [(String, [HarnessSettingsPathOperation], Int?)] = []

    init(
        credentials: [String: HarnessCredentialView],
        piAI: HarnessJSONValue = .object([:]),
        writable: Bool = true,
        applies: HarnessSettingsApplyMode = .live,
        failMutationCalls: Set<Int> = [],
        failAfterApplyingMutationCalls: Set<Int> = [],
        failCredentialSet: Bool = false,
        failAfterApplyingCredentialSet: Bool = false,
        failCredentialUnset: Bool = false
    ) {
        self.credentials = credentials
        settings = HarnessSettingsDescription(
            writable: writable,
            hasDocument: true,
            namespaces: [
                HarnessSettingsNamespace(
                    ns: "llm-pi-ai",
                    schema: .object([:]),
                    value: piAI,
                    base: nil,
                    user: nil,
                    applies: applies,
                    secrets: [],
                    revision: 9
                )
            ]
        )
        self.failMutationCalls = failMutationCalls
        self.failAfterApplyingMutationCalls = failAfterApplyingMutationCalls
        self.failCredentialSet = failCredentialSet
        self.failAfterApplyingCredentialSet = failAfterApplyingCredentialSet
        self.failCredentialUnset = failCredentialUnset
    }

    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        HarnessCredentialDescription(credentials: Dictionary(uniqueKeysWithValues: references.compactMap { reference in
            credentials[reference.rawValue].map { (reference.rawValue, $0) }
        }))
    }

    func setCredential(_ reference: CredentialReference, value: String) async throws {
        setReferences.append(reference)
        if failCredentialSet { throw ActivationFixtureError.credentialSet }
        credentials[reference.rawValue] = HarnessCredentialView(
            configured: true,
            source: "macOS Keychain",
            writable: true
        )
        if failAfterApplyingCredentialSet { throw ActivationFixtureError.credentialSet }
    }

    func unsetCredential(_ reference: CredentialReference) async throws {
        unsetReferences.append(reference)
        if failCredentialUnset { throw ActivationFixtureError.credentialUnset }
        credentials[reference.rawValue] = HarnessCredentialView(
            configured: false,
            source: nil,
            writable: true
        )
    }

    func describeSettings() async throws -> HarnessSettingsDescription { settings }

    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace {
        mutationCalls += 1
        mutations.append((namespace, operations, expectedRevision))
        if failMutationCalls.contains(mutationCalls) { throw ActivationFixtureError.settingsMutation }
        guard let index = settings.namespaces.firstIndex(where: { $0.ns == namespace }) else {
            throw ActivationFixtureError.invalidPath
        }
        let current = settings.namespaces[index]
        guard expectedRevision == nil || expectedRevision == current.revision else {
            throw HarnessRPCClientError.remote(.init(code: .settingsConflict, message: "stale", details: [:]))
        }
        var value = current.value
        for operation in operations { value = try applyingActivationOperation(operation, to: value) }
        let updated = HarnessSettingsNamespace(
            ns: current.ns,
            schema: current.schema,
            value: value,
            base: current.base,
            user: current.user,
            applies: current.applies,
            secrets: current.secrets,
            revision: current.revision + 1
        )
        var namespaces = settings.namespaces
        namespaces[index] = updated
        settings = HarnessSettingsDescription(
            writable: settings.writable,
            hasDocument: settings.hasDocument,
            namespaces: namespaces
        )
        if failAfterApplyingMutationCalls.contains(mutationCalls) {
            throw ActivationFixtureError.settingsMutation
        }
        return updated
    }

    func credential(_ reference: CredentialReference) -> HarnessCredentialView? {
        credentials[reference.rawValue]
    }

    func piAIValue() -> HarnessJSONValue { settings.namespaces[0].value }

    func recordedCalls() -> (sets: [CredentialReference], unsets: [CredentialReference], mutations: Int) {
        (setReferences, unsetReferences, mutations.count)
    }
}

private actor ActivationCatalog: ProviderCatalogLoading {
    private var snapshots: [HarnessModelCatalogSnapshot]
    private(set) var calls = 0

    init(_ snapshots: [HarnessModelCatalogSnapshot]) { self.snapshots = snapshots }

    func loadCatalog() async throws -> HarnessModelCatalogSnapshot {
        calls += 1
        guard !snapshots.isEmpty else { return HarnessModelCatalogSnapshot(providers: []) }
        if snapshots.count == 1 { return snapshots[0] }
        return snapshots.removeFirst()
    }
}

private struct CredentialReadinessModelRPC: HarnessModelRPCServicing {
    let descriptor: ProviderDescriptor

    func llmProviders() async throws -> HarnessProviderDirectory {
        HarnessProviderDirectory(providers: [
            HarnessProviderDirectoryEntry(
                provider: descriptor.id,
                displayName: descriptor.displayName,
                settingsNs: descriptor.settingsNamespace,
                settingsPath: descriptor.settingsPath,
                active: true,
                declared: false
            )
        ])
    }

    func llmModels() async throws -> HarnessModelCatalog {
        HarnessModelCatalog(groups: [
            HarnessModelProviderGroup(
                id: descriptor.id,
                name: descriptor.displayName,
                models: [HarnessModelCatalogEntry(
                    id: ModelID("fixture-model"),
                    name: "Fixture Model",
                    description: nil,
                    reasoning: nil
                )]
            )
        ], failures: [])
    }

    func describeSettings() async throws -> HarnessSettingsDescription {
        HarnessSettingsDescription(
            writable: true,
            hasDocument: true,
            namespaces: [
                HarnessSettingsNamespace(
                    ns: descriptor.settingsNamespace,
                    schema: .object([:]),
                    value: .object([:]),
                    base: nil,
                    user: nil,
                    applies: .live,
                    secrets: [],
                    revision: 1
                )
            ]
        )
    }

    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace {
        throw ActivationFixtureError.settingsMutation
    }

    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels {
        throw ActivationFixtureError.invalidPath
    }

    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection { selection }
}

private struct FailingCredentialReadinessService: HarnessProviderCredentialServicing {
    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        throw ActivationFixtureError.credentialSet
    }

    func setCredential(_ reference: CredentialReference, value: String) async throws {
        throw ActivationFixtureError.credentialSet
    }

    func unsetCredential(_ reference: CredentialReference) async throws {
        throw ActivationFixtureError.credentialUnset
    }
}

private func activationProvider(
    _ descriptor: ProviderDescriptor,
    state: ProviderConfigurationState = .ready
) -> ProviderView {
    ProviderView(
        descriptor: descriptor,
        configurationState: state,
        models: state == .ready ? [
            ModelView(id: ModelID("fixture-model"), displayName: "Fixture Model")
        ] : [],
        failureMessage: nil
    )
}

private func unconfiguredCredential() -> HarnessCredentialView {
    HarnessCredentialView(configured: false, source: nil, writable: true)
}

private func configuredCredential() -> HarnessCredentialView {
    HarnessCredentialView(configured: true, source: "macOS Keychain", writable: true)
}

@Suite(.serialized)
struct ProviderActivationTransactionTests {
    @Test func credentialRemovalChangesExternalBuiltInFromReadyToNeedsCredential() async throws {
        let descriptor = BuiltInProviderDescriptors.deepSeekOfficial
        let reference = try #require(descriptor.credentialReference)
        let raw = HarnessModelCatalogSnapshot(providers: [activationProvider(descriptor)])
        let configured = HarnessCredentialDescription(credentials: [
            reference.rawValue: configuredCredential()
        ])
        let removed = HarnessCredentialDescription(credentials: [
            reference.rawValue: unconfiguredCredential()
        ])

        #expect(ProviderCredentialReadiness.applying(configured, to: raw).providers[0].configurationState == .ready)
        #expect(ProviderCredentialReadiness.applying(removed, to: raw).providers[0].configurationState == .needsCredential)
    }

    @Test func coordinatorFailsExternalRouteReadinessClosedBeforeSelectionOrPrompt() async throws {
        let descriptor = BuiltInProviderDescriptors.deepSeekOfficial
        let reference = try #require(descriptor.credentialReference)
        let credentialService = ActivationService(credentials: [
            reference.rawValue: unconfiguredCredential()
        ])
        let coordinator = ModelSelectionCoordinator(
            service: CredentialReadinessModelRPC(descriptor: descriptor),
            credentialService: credentialService
        )

        let catalog = try await coordinator.loadCatalog()

        #expect(catalog.provider(descriptor.id)?.configurationState == .needsCredential)
        #expect(catalog.provider(descriptor.id)?.models.map(\.id) == [ModelID("fixture-model")])
    }

    @Test func credentialGateDoesNotInventRequirementsForOllamaOrKeylessCustomRoutes() throws {
        let custom = BuiltInProviderDescriptors.openAICompatible(
            id: ProviderID("keyless-private"),
            displayName: "Keyless Private",
            baseURL: URL(string: "http://192.168.1.20:8080/v1")!,
            boundary: .localNetwork,
            credentialReference: nil
        )
        let snapshot = HarnessModelCatalogSnapshot(providers: [
            activationProvider(BuiltInProviderDescriptors.ollama),
            activationProvider(custom)
        ])

        #expect(ProviderCredentialReadiness.requiredReferences(in: snapshot).isEmpty)
        #expect(ProviderCredentialReadiness.applying(.init(credentials: [:]), to: snapshot) == snapshot)
    }

    @Test func credentialInspectionFailureKeepsLocalReadyAndExternalFailClosed() async throws {
        let externalCoordinator = ModelSelectionCoordinator(
            service: CredentialReadinessModelRPC(descriptor: BuiltInProviderDescriptors.deepSeekOfficial),
            credentialService: FailingCredentialReadinessService()
        )
        let localCoordinator = ModelSelectionCoordinator(
            service: CredentialReadinessModelRPC(descriptor: BuiltInProviderDescriptors.ollama),
            credentialService: FailingCredentialReadinessService()
        )

        let external = try await externalCoordinator.loadCatalog()
        let local = try await localCoordinator.loadCatalog()

        #expect(external.providers[0].configurationState == .needsCredential)
        #expect(local.providers[0].configurationState == .ready)
    }

    @Test func newOpenAICredentialAndProfileActivateWithoutChangingSiblingSettings() async throws {
        let reference = try #require(BuiltInProviderDescriptors.openAI.credentialReference)
        let sibling: HarnessJSONValue = .object([
            "apiKeyEnv": .string("ANTHROPIC_API_KEY"),
            "retryPolicy": .object(["maxRetries": .integer(2)])
        ])
        let service = ActivationService(
            credentials: [reference.rawValue: unconfiguredCredential()],
            piAI: .object(["providers": .object(["anthropic": sibling]), "keep": .string("exact")])
        )
        let catalog = ActivationCatalog([
            HarnessModelCatalogSnapshot(providers: [activationProvider(BuiltInProviderDescriptors.openAI)])
        ])
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: catalog,
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )

        let result = try await transaction.activate(
            descriptor: BuiltInProviderDescriptors.openAI,
            credentialValue: "  test-openai-key  "
        )

        #expect(result.provider.id == BuiltInProviderDescriptors.openAI.id)
        #expect(result.createdCredential)
        #expect(result.createdProviderProfile)
        #expect(await service.credential(reference)?.configured == true)
        let value = await service.piAIValue()
        #expect(activationValue(at: ["providers", "openai", "apiKeyEnv"], in: value) == .string(reference.rawValue))
        #expect(activationValue(at: ["providers", "anthropic"], in: value) == sibling)
        #expect(activationValue(at: ["keep"], in: value) == .string("exact"))
        let calls = await service.recordedCalls()
        #expect(calls.sets == [reference])
        #expect(calls.unsets.isEmpty)
        #expect(calls.mutations == 1)
    }

    @Test func existingCredentialActivatesDormantCatalogRouteWithoutReplacement() async throws {
        let reference = try #require(BuiltInProviderDescriptors.anthropic.credentialReference)
        let service = ActivationService(credentials: [reference.rawValue: configuredCredential()])
        let catalog = ActivationCatalog([
            HarnessModelCatalogSnapshot(providers: [activationProvider(BuiltInProviderDescriptors.anthropic)])
        ])
        let transaction = ProviderActivationTransaction(service: service, catalog: catalog, catalogAttempts: 1, catalogRetryNanoseconds: 0)

        let result = try await transaction.activate(
            descriptor: BuiltInProviderDescriptors.anthropic,
            credentialValue: nil
        )

        #expect(!result.createdCredential)
        #expect(result.createdProviderProfile)
        let calls = await service.recordedCalls()
        #expect(calls.sets.isEmpty)
        #expect(calls.unsets.isEmpty)
        #expect(calls.mutations == 1)
    }

    @Test func activationNeverReplacesAnExistingWriteOnlyCredential() async throws {
        let reference = try #require(BuiltInProviderDescriptors.openAI.credentialReference)
        let service = ActivationService(credentials: [reference.rawValue: configuredCredential()])
        let catalog = ActivationCatalog([])
        let transaction = ProviderActivationTransaction(service: service, catalog: catalog, catalogAttempts: 1, catalogRetryNanoseconds: 0)

        do {
            _ = try await transaction.activate(
                descriptor: BuiltInProviderDescriptors.openAI,
                credentialValue: "replacement"
            )
            Issue.record("Expected activation to reject credential replacement")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(
                cause: .credentialReplacementRequiresSeparateAction,
                rollbackComplete: true
            ))
        }
        let calls = await service.recordedCalls()
        #expect(calls.sets.isEmpty)
        #expect(calls.unsets.isEmpty)
        #expect(calls.mutations == 0)
    }

    @Test func credentialApplyThenLostResponseIsCompensatedAndFailureIsHonest() async throws {
        let descriptor = BuiltInProviderDescriptors.deepSeekOfficial
        let reference = try #require(descriptor.credentialReference)
        for failRollback in [false, true] {
            let service = ActivationService(
                credentials: [reference.rawValue: unconfiguredCredential()],
                failAfterApplyingCredentialSet: true,
                failCredentialUnset: failRollback
            )
            let transaction = ProviderActivationTransaction(
                service: service,
                catalog: ActivationCatalog([]),
                catalogAttempts: 1,
                catalogRetryNanoseconds: 0
            )

            do {
                _ = try await transaction.activate(descriptor: descriptor, credentialValue: "new-key")
                Issue.record("Lost credential response unexpectedly completed activation")
            } catch let error as ProviderActivationTransactionError {
                #expect(error == ProviderActivationTransactionError(
                    cause: .credentialWriteNotVerified,
                    rollbackComplete: !failRollback
                ))
            }
            #expect(await service.credential(reference)?.configured == failRollback)
            let calls = await service.recordedCalls()
            #expect(calls.sets == [reference])
            #expect(calls.unsets == [reference])
            #expect(calls.mutations == 0)
        }
    }

    @Test func failedProfileEditNeverRemovesOrReplacesAPriorCredential() async throws {
        let descriptor = BuiltInProviderDescriptors.openAI
        let reference = try #require(descriptor.credentialReference)
        let previous: HarnessJSONValue = .object([
            "displayName": .string("Existing Gateway"),
            "retryPolicy": .object(["maxRetries": .integer(1)])
        ])
        let service = ActivationService(
            credentials: [reference.rawValue: configuredCredential()],
            piAI: .object(["providers": .object(["openai": previous])])
        )
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: ActivationCatalog([.init(providers: [activationProvider(descriptor, state: .dormant)])]),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )

        do {
            _ = try await transaction.activate(descriptor: descriptor, credentialValue: nil)
            Issue.record("Dormant edited provider unexpectedly verified")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(cause: .providerNotReady, rollbackComplete: true))
        }
        #expect(await service.credential(reference)?.configured == true)
        #expect(activationValue(at: ["providers", "openai"], in: await service.piAIValue()) == previous)
        let calls = await service.recordedCalls()
        #expect(calls.sets.isEmpty)
        #expect(calls.unsets.isEmpty)
        #expect(calls.mutations == 2)
    }

    @Test func cancellationAfterCredentialCreationRunsRollbackOutsideTheCancelledTask() async throws {
        let descriptor = BuiltInProviderDescriptors.deepSeekOfficial
        let reference = try #require(descriptor.credentialReference)
        let service = ActivationService(credentials: [reference.rawValue: unconfiguredCredential()])
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: ActivationCatalog([]),
            catalogAttempts: 2,
            catalogRetryNanoseconds: 10_000_000_000
        )
        let task = Task {
            try await transaction.activate(descriptor: descriptor, credentialValue: "new-key")
        }
        while await service.recordedCalls().sets.isEmpty { await Task.yield() }
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Cancelled activation unexpectedly succeeded")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(cause: .cancelled, rollbackComplete: true))
        }
        #expect(await service.credential(reference)?.configured == false)
        let calls = await service.recordedCalls()
        #expect(calls.sets == [reference])
        #expect(calls.unsets == [reference])
        #expect(calls.mutations == 0)
    }

    @Test func catalogFailureRestoresExactPreviousProfileAndRemovesOnlyNewCredential() async throws {
        let reference = try #require(BuiltInProviderDescriptors.openAI.credentialReference)
        let previous: HarnessJSONValue = .object([
            "displayName": .string("Office Gateway"),
            "retryPolicy": .object(["maxRetries": .integer(0)])
        ])
        let service = ActivationService(
            credentials: [reference.rawValue: unconfiguredCredential()],
            piAI: .object(["providers": .object(["openai": previous])])
        )
        let catalog = ActivationCatalog([
            HarnessModelCatalogSnapshot(providers: [activationProvider(BuiltInProviderDescriptors.openAI, state: .dormant)])
        ])
        let transaction = ProviderActivationTransaction(service: service, catalog: catalog, catalogAttempts: 1, catalogRetryNanoseconds: 0)

        do {
            _ = try await transaction.activate(
                descriptor: BuiltInProviderDescriptors.openAI,
                credentialValue: "new-key"
            )
            Issue.record("Expected catalog verification to fail")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(cause: .providerNotReady, rollbackComplete: true))
        }

        #expect(await service.credential(reference)?.configured == false)
        let value = await service.piAIValue()
        #expect(activationValue(at: ["providers", "openai"], in: value) == previous)
        let calls = await service.recordedCalls()
        #expect(calls.sets == [reference])
        #expect(calls.unsets == [reference])
        #expect(calls.mutations == 2)
    }

    @Test func incompleteSettingsRollbackIsReportedAndCredentialRemovalStillRuns() async throws {
        let reference = try #require(BuiltInProviderDescriptors.anthropic.credentialReference)
        let service = ActivationService(
            credentials: [reference.rawValue: unconfiguredCredential()],
            failMutationCalls: [2]
        )
        let catalog = ActivationCatalog([
            HarnessModelCatalogSnapshot(providers: [activationProvider(BuiltInProviderDescriptors.anthropic, state: .dormant)])
        ])
        let transaction = ProviderActivationTransaction(service: service, catalog: catalog, catalogAttempts: 1, catalogRetryNanoseconds: 0)

        do {
            _ = try await transaction.activate(
                descriptor: BuiltInProviderDescriptors.anthropic,
                credentialValue: "new-key"
            )
            Issue.record("Expected catalog verification to fail")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(cause: .providerNotReady, rollbackComplete: false))
        }
        let calls = await service.recordedCalls()
        #expect(calls.unsets == [reference])
        #expect(await service.credential(reference)?.configured == false)
    }

    @Test func ambiguousTransportFailureAfterAppliedProfileStillRollsBackExactly() async throws {
        let reference = try #require(BuiltInProviderDescriptors.openAI.credentialReference)
        let sibling: HarnessJSONValue = .object(["keep": .string("untouched")])
        let service = ActivationService(
            credentials: [reference.rawValue: unconfiguredCredential()],
            piAI: .object(["providers": .object(["anthropic": sibling])]),
            failAfterApplyingMutationCalls: [1]
        )
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: ActivationCatalog([]),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )

        do {
            _ = try await transaction.activate(
                descriptor: BuiltInProviderDescriptors.openAI,
                credentialValue: "new-key"
            )
            Issue.record("Expected the simulated lost reply to fail activation")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(
                cause: .settingsMutationNotVerified,
                rollbackComplete: true
            ))
        }

        let value = await service.piAIValue()
        #expect(activationValue(at: ["providers", "openai"], in: value) == nil)
        #expect(activationValue(at: ["providers", "anthropic"], in: value) == sibling)
        #expect(await service.credential(reference)?.configured == false)
        let calls = await service.recordedCalls()
        #expect(calls.mutations == 2)
        #expect(calls.unsets == [reference])
    }

    @Test func readOnlySettingsRollBackNewCredential() async throws {
        let reference = try #require(BuiltInProviderDescriptors.openAI.credentialReference)
        let service = ActivationService(
            credentials: [reference.rawValue: unconfiguredCredential()],
            writable: false
        )
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: ActivationCatalog([]),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )

        do {
            _ = try await transaction.activate(
                descriptor: BuiltInProviderDescriptors.openAI,
                credentialValue: "new-key"
            )
            Issue.record("Expected read-only settings to fail")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(cause: .settingsReadOnly, rollbackComplete: true))
        }
        let calls = await service.recordedCalls()
        #expect(calls.sets == [reference])
        #expect(calls.unsets == [reference])
        #expect(calls.mutations == 0)
    }

    @Test func deepSeekCredentialActivationDoesNotMutatePiAISettings() async throws {
        let reference = try #require(BuiltInProviderDescriptors.deepSeekOfficial.credentialReference)
        let service = ActivationService(credentials: [reference.rawValue: unconfiguredCredential()])
        let catalog = ActivationCatalog([
            HarnessModelCatalogSnapshot(providers: [activationProvider(BuiltInProviderDescriptors.deepSeekOfficial)])
        ])
        let transaction = ProviderActivationTransaction(service: service, catalog: catalog, catalogAttempts: 1, catalogRetryNanoseconds: 0)

        let result = try await transaction.activate(
            descriptor: BuiltInProviderDescriptors.deepSeekOfficial,
            credentialValue: "deepseek-key"
        )

        #expect(result.createdCredential)
        #expect(!result.createdProviderProfile)
        let calls = await service.recordedCalls()
        #expect(calls.sets == [reference])
        #expect(calls.mutations == 0)
    }

    @Test func newCustomAndOllamaProfilesStayInTheirDedicatedSetupPaths() async throws {
        let service = ActivationService(credentials: [:])
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: ActivationCatalog([]),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        let custom = BuiltInProviderDescriptors.openAICompatible(
            id: ProviderID("private-gateway"),
            displayName: "Private Gateway",
            baseURL: URL(string: "https://gateway.example/v1")!,
            boundary: .cloud,
            credentialReference: CredentialReference("PRIVATE_GATEWAY_KEY")
        )

        for descriptor in [custom, BuiltInProviderDescriptors.ollama] {
            #expect(!ProviderActivationTransaction.supportsNativeActivation(descriptor))
            do {
                _ = try await transaction.activate(descriptor: descriptor, credentialValue: "key")
                Issue.record("Expected unsupported native activation")
            } catch let error as ProviderActivationTransactionError {
                #expect(error == ProviderActivationTransactionError(cause: .unsupportedProvider, rollbackComplete: true))
            }
        }
        #expect(ProviderActivationTransaction.supportsNativeActivation(BuiltInProviderDescriptors.deepSeekOfficial))
        #expect(ProviderActivationTransaction.supportsNativeActivation(BuiltInProviderDescriptors.openAI))
        #expect(ProviderActivationTransaction.supportsNativeActivation(BuiltInProviderDescriptors.anthropic))
        let calls = await service.recordedCalls()
        #expect(calls.sets.isEmpty)
        #expect(calls.mutations == 0)
    }

    @Test func nativeActivationRequiresTheCompleteReviewedBuiltInDescriptor() async throws {
        let expected = BuiltInProviderDescriptors.openAI
        let mutations: [ProviderDescriptor] = [
            ProviderDescriptor(
                id: expected.id, displayName: "Spoofed OpenAI",
                settingsNamespace: expected.settingsNamespace, settingsPath: expected.settingsPath,
                adapterKind: expected.adapterKind, wireProtocol: expected.wireProtocol,
                defaultBaseURL: expected.defaultBaseURL, boundary: expected.boundary,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: "llm-deepseek", settingsPath: expected.settingsPath,
                adapterKind: expected.adapterKind, wireProtocol: expected.wireProtocol,
                defaultBaseURL: expected.defaultBaseURL, boundary: expected.boundary,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: expected.settingsNamespace, settingsPath: ["providers", "anthropic"],
                adapterKind: expected.adapterKind, wireProtocol: expected.wireProtocol,
                defaultBaseURL: expected.defaultBaseURL, boundary: expected.boundary,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: expected.settingsNamespace, settingsPath: expected.settingsPath,
                adapterKind: .deepSeekOfficial, wireProtocol: expected.wireProtocol,
                defaultBaseURL: expected.defaultBaseURL, boundary: expected.boundary,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: expected.settingsNamespace, settingsPath: expected.settingsPath,
                adapterKind: expected.adapterKind, wireProtocol: .anthropicMessages,
                defaultBaseURL: expected.defaultBaseURL, boundary: expected.boundary,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: expected.settingsNamespace, settingsPath: expected.settingsPath,
                adapterKind: expected.adapterKind, wireProtocol: expected.wireProtocol,
                defaultBaseURL: URL(string: "https://attacker.example/v1")!, boundary: expected.boundary,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: expected.settingsNamespace, settingsPath: expected.settingsPath,
                adapterKind: expected.adapterKind, wireProtocol: expected.wireProtocol,
                defaultBaseURL: expected.defaultBaseURL, boundary: .localNetwork,
                credentialReference: expected.credentialReference
            ),
            ProviderDescriptor(
                id: expected.id, displayName: expected.displayName,
                settingsNamespace: expected.settingsNamespace, settingsPath: expected.settingsPath,
                adapterKind: expected.adapterKind, wireProtocol: expected.wireProtocol,
                defaultBaseURL: expected.defaultBaseURL, boundary: expected.boundary,
                credentialReference: CredentialReference("ANTHROPIC_API_KEY")
            )
        ]
        for descriptor in mutations {
            #expect(!ProviderActivationTransaction.supportsNativeActivation(descriptor))
        }
    }

    @Test func readyCatalogMustReturnTheSameCompleteDescriptorNotOnlyTheSameID() async throws {
        let expected = BuiltInProviderDescriptors.openAI
        let reference = try #require(expected.credentialReference)
        let drifted = ProviderDescriptor(
            id: expected.id,
            displayName: expected.displayName,
            settingsNamespace: expected.settingsNamespace,
            settingsPath: expected.settingsPath,
            adapterKind: expected.adapterKind,
            wireProtocol: expected.wireProtocol,
            defaultBaseURL: URL(string: "https://attacker.example/v1")!,
            boundary: expected.boundary,
            credentialReference: expected.credentialReference
        )
        let service = ActivationService(
            credentials: [reference.rawValue: configuredCredential()],
            piAI: .object([
                "providers": .object([
                    "openai": .object(["apiKeyEnv": .string(reference.rawValue)])
                ])
            ])
        )
        let transaction = ProviderActivationTransaction(
            service: service,
            catalog: ActivationCatalog([
                HarnessModelCatalogSnapshot(providers: [activationProvider(drifted)])
            ]),
            catalogAttempts: 1,
            catalogRetryNanoseconds: 0
        )
        do {
            _ = try await transaction.activate(descriptor: expected, credentialValue: nil)
            Issue.record("Expected descriptor-bound readiness failure")
        } catch let error as ProviderActivationTransactionError {
            #expect(error == ProviderActivationTransactionError(cause: .providerNotReady, rollbackComplete: true))
        }
        let calls = await service.recordedCalls()
        #expect(calls.sets.isEmpty)
        #expect(calls.mutations == 0)
    }
}
