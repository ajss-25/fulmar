import Foundation
import Testing
@testable import LocalHarness

private enum LocalPreflightFixtureError: Error {
    case transport
}

@MainActor
private final class LocalPreflightService: LocalModelSelectionPreflightServing {
    var catalogs: [[OllamaModel]]
    var assessment: OllamaModelCompatibility
    var versionError: Error?
    private(set) var events: [String] = []

    init(
        catalogs: [[OllamaModel]],
        assessment: OllamaModelCompatibility = .compatible(
            contextLength: 32_768,
            supportsThinking: false
        ),
        versionError: Error? = nil
    ) {
        self.catalogs = catalogs
        self.assessment = assessment
        self.versionError = versionError
    }

    func fetchCompatibleVersion() async throws -> OllamaStableVersion {
        events.append("version")
        if let versionError { throw versionError }
        return OllamaVersionCompatibilityPolicy.tested
    }

    func fetchModels() async throws -> [OllamaModel] {
        events.append("tags")
        guard !catalogs.isEmpty else { throw LocalPreflightFixtureError.transport }
        return catalogs.removeFirst()
    }

    func inspectModelCompatibility(model: String) async throws -> OllamaModelCompatibility {
        events.append("show:\(model)")
        return assessment
    }
}

private let preflightGiB = UInt64(1_073_741_824)

private func preflightModel(
    name: String,
    size: Int64,
    digest: String? = nil,
    modifiedAt: String = "2026-09-01T00:00:00Z"
) -> OllamaModel {
    OllamaModel(
        name: name,
        digest: digest,
        size: size,
        modifiedAt: modifiedAt,
        details: nil
    )
}

private func compatibilitySelection(_ model: String = "alternate-tools:latest") -> ModelSelection {
    ModelSelection(
        route: ModelRoute(
            provider: BuiltInProviderDescriptors.ollama.id,
            model: ModelID(model)
        ),
        reasoningEffort: "high",
        performanceProfile: .deep
    )
}

private func preflightOllamaDescriptor(
    id: ProviderID = BuiltInProviderDescriptors.ollama.id,
    displayName: String = BuiltInProviderDescriptors.ollama.displayName,
    settingsNamespace: String = BuiltInProviderDescriptors.ollama.settingsNamespace,
    settingsPath: [String] = BuiltInProviderDescriptors.ollama.settingsPath,
    adapterKind: ProviderAdapterKind = BuiltInProviderDescriptors.ollama.adapterKind,
    wireProtocol: ProviderWireProtocol? = BuiltInProviderDescriptors.ollama.wireProtocol,
    defaultBaseURL: URL?,
    boundary: DataBoundary = BuiltInProviderDescriptors.ollama.boundary,
    credentialReference: CredentialReference? = BuiltInProviderDescriptors.ollama.credentialReference,
    explicitlyUnauthenticated: Bool = BuiltInProviderDescriptors.ollama.explicitlyUnauthenticated,
    supportsNativeProfileEditing: Bool = BuiltInProviderDescriptors.ollama.supportsNativeProfileEditing
) -> ProviderDescriptor {
    ProviderDescriptor(
        id: id,
        displayName: displayName,
        settingsNamespace: settingsNamespace,
        settingsPath: settingsPath,
        adapterKind: adapterKind,
        wireProtocol: wireProtocol,
        defaultBaseURL: defaultBaseURL,
        boundary: boundary,
        credentialReference: credentialReference,
        explicitlyUnauthenticated: explicitlyUnauthenticated,
        supportsNativeProfileEditing: supportsNativeProfileEditing
    )
}

@Suite(.serialized)
struct LocalModelSelectionPreflightTests {
    @Test @MainActor
    func compatibilityPreflightCoversEveryDocumentedHardwareTierBeforeSelection() async throws {
        for hostGiB in [8, 16, 24, 32, 48, 64, 96] {
            let hostBytes = UInt64(hostGiB) * preflightGiB
            let modelBytes = Int64((hostBytes - 4 * preflightGiB) / 2)
            let selection = compatibilitySelection()
            let model = preflightModel(
                name: selection.route.model.rawValue,
                size: modelBytes
            )
            let service = LocalPreflightService(catalogs: [[model], [model]])
            let preflight = LocalModelSelectionPreflight(
                service: service,
                physicalMemoryBytes: { hostBytes }
            )

            try await preflight.validate(
                selection: selection,
                descriptor: BuiltInProviderDescriptors.ollama
            )

            #expect(selection.performanceProfile == .compatibility)
            #expect(selection.reasoningEffort == nil)
            #expect(service.events == [
                "version", "tags", "show:\(selection.route.model.rawValue)", "tags"
            ])
        }
    }

    @Test @MainActor
    func qualifiedQwenPreflightKeepsTheExactFortyEightGiBAndDigestBoundary() async throws {
        let selection = ModelSelection.defaultLocal
        let model = preflightModel(
            name: selection.route.model.rawValue,
            size: 18_174_721_847,
            digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
        )

        for hostGiB in [8, 16, 24, 32] {
            let hostBytes = UInt64(hostGiB) * preflightGiB
            let service = LocalPreflightService(
                catalogs: [[model]],
                assessment: .incompatible(.thinkingRequiresExplicitSupport(contextLength: 262_144))
            )
            let preflight = LocalModelSelectionPreflight(
                service: service,
                physicalMemoryBytes: { hostBytes }
            )
            await #expect(throws: QualifiedLocalModelHostAdmissionError.insufficientPhysicalMemory(
                requiredBytes: 48 * preflightGiB,
                availableBytes: hostBytes
            )) {
                try await preflight.validate(
                    selection: selection,
                    descriptor: BuiltInProviderDescriptors.ollama
                )
            }
            #expect(service.events == ["version", "tags"])
        }

        for hostGiB in [48, 64, 96] {
            let service = LocalPreflightService(
                catalogs: [[model], [model]],
                assessment: .incompatible(.thinkingRequiresExplicitSupport(contextLength: 262_144))
            )
            let preflight = LocalModelSelectionPreflight(
                service: service,
                physicalMemoryBytes: { UInt64(hostGiB) * preflightGiB }
            )
            try await preflight.validate(
                selection: selection,
                descriptor: BuiltInProviderDescriptors.ollama
            )
            #expect(service.events == [
                "version", "tags", "show:\(selection.route.model.rawValue)", "tags"
            ])
        }
    }

    @Test @MainActor
    func cloudRoutesNeverTouchOllamaOrInheritLocalHardwareAdmission() async throws {
        let selection = ModelSelection(
            route: ModelRoute(
                provider: BuiltInProviderDescriptors.deepSeekOfficial.id,
                model: ModelID("deepseek-chat")
            )
        )
        for hostGiB in [8, 16, 24, 32, 48, 64, 96] {
            let service = LocalPreflightService(catalogs: [])
            let preflight = LocalModelSelectionPreflight(
                service: service,
                physicalMemoryBytes: { UInt64(hostGiB) * preflightGiB }
            )
            try await preflight.validate(
                selection: selection,
                descriptor: BuiltInProviderDescriptors.deepSeekOfficial
            )
            #expect(service.events.isEmpty)
        }
    }

    @Test @MainActor
    func missingToolsFailsBeforeTheSecondCatalogReadOrAnyMutation() async {
        let selection = compatibilitySelection()
        let model = preflightModel(
            name: selection.route.model.rawValue,
            size: Int64(4 * preflightGiB)
        )
        let service = LocalPreflightService(
            catalogs: [[model]],
            assessment: .incompatible(.toolsUnavailable)
        )
        let preflight = LocalModelSelectionPreflight(
            service: service,
            physicalMemoryBytes: { 16 * preflightGiB }
        )

        await #expect(throws: LocalModelAdmissionError.toolsUnavailable) {
            try await preflight.validate(
                selection: selection,
                descriptor: BuiltInProviderDescriptors.ollama
            )
        }
        #expect(service.events == [
            "version", "tags", "show:\(selection.route.model.rawValue)"
        ])
    }

    @Test @MainActor
    func retagOrReplacementRaceFailsClosedBeforeSelectionCommit() async {
        let selection = compatibilitySelection()
        let first = preflightModel(
            name: selection.route.model.rawValue,
            size: Int64(4 * preflightGiB),
            digest: String(repeating: "1", count: 64)
        )
        let replacement = preflightModel(
            name: selection.route.model.rawValue,
            size: Int64(4 * preflightGiB),
            digest: String(repeating: "2", count: 64),
            modifiedAt: "2026-09-01T00:00:01Z"
        )
        let service = LocalPreflightService(catalogs: [[first], [replacement]])
        let preflight = LocalModelSelectionPreflight(
            service: service,
            physicalMemoryBytes: { 16 * preflightGiB }
        )

        await #expect(throws: LocalModelSelectionPreflightError.modelChangedDuringInspection) {
            try await preflight.validate(
                selection: selection,
                descriptor: BuiltInProviderDescriptors.ollama
            )
        }
        #expect(service.events == [
            "version", "tags", "show:\(selection.route.model.rawValue)", "tags"
        ])
    }

    @Test @MainActor
    func untrustedTransportFailureCollapsesToAnAppOwnedMessage() async {
        let service = LocalPreflightService(
            catalogs: [],
            versionError: LocalPreflightFixtureError.transport
        )
        let preflight = LocalModelSelectionPreflight(
            service: service,
            physicalMemoryBytes: { 48 * preflightGiB }
        )

        await #expect(throws: LocalModelSelectionPreflightError.unavailable) {
            try await preflight.validate(
                selection: .defaultLocal,
                descriptor: BuiltInProviderDescriptors.ollama
            )
        }
        #expect(!LocalModelSelectionPreflightError.unavailable.localizedDescription.contains("transport"))
    }

    @Test @MainActor
    func forgedOllamaDescriptorFailsBeforeAnyServiceCall() async throws {
        let selection = compatibilitySelection()
        let model = preflightModel(
            name: selection.route.model.rawValue,
            size: Int64(4 * preflightGiB)
        )
        let liveEndpoint = URL(string: "http://127.0.0.1:49152/v1")!
        let liveService = LocalPreflightService(catalogs: [[model], [model]])
        let livePreflight = LocalModelSelectionPreflight(
            service: liveService,
            physicalMemoryBytes: { 16 * preflightGiB }
        )

        try await livePreflight.validate(
            selection: selection,
            descriptor: preflightOllamaDescriptor(defaultBaseURL: liveEndpoint)
        )
        #expect(liveService.events == [
            "version", "tags", "show:\(selection.route.model.rawValue)", "tags"
        ])

        let endpointForgeries = [
            "https://127.0.0.1:49152/v1",
            "http://localhost:49152/v1",
            "http://127.0.0.1:49152/api",
            "http://127.0.0.1:49152/v1?route=forged",
            "http://attacker.example:49152/v1"
        ].map { preflightOllamaDescriptor(defaultBaseURL: URL(string: $0)!) }
        let identityForgeries = [
            preflightOllamaDescriptor(
                id: ProviderID("forged-ollama"),
                defaultBaseURL: liveEndpoint
            ),
            preflightOllamaDescriptor(
                displayName: "Forged Ollama",
                defaultBaseURL: liveEndpoint
            ),
            preflightOllamaDescriptor(
                settingsNamespace: "forged",
                defaultBaseURL: liveEndpoint
            ),
            preflightOllamaDescriptor(
                settingsPath: ["providers", "forged"],
                defaultBaseURL: liveEndpoint
            ),
            preflightOllamaDescriptor(
                adapterKind: .deepSeekOfficial,
                defaultBaseURL: liveEndpoint
            ),
            preflightOllamaDescriptor(
                wireProtocol: .anthropicMessages,
                defaultBaseURL: liveEndpoint
            ),
            preflightOllamaDescriptor(
                defaultBaseURL: liveEndpoint,
                boundary: .localNetwork
            ),
            preflightOllamaDescriptor(
                defaultBaseURL: liveEndpoint,
                credentialReference: CredentialReference("FORGED_API_KEY")
            ),
            preflightOllamaDescriptor(
                defaultBaseURL: liveEndpoint,
                explicitlyUnauthenticated: true
            ),
            preflightOllamaDescriptor(
                defaultBaseURL: liveEndpoint,
                supportsNativeProfileEditing: true
            )
        ]

        for forged in endpointForgeries + identityForgeries {
            let service = LocalPreflightService(catalogs: [])
            let preflight = LocalModelSelectionPreflight(service: service)
            await #expect(throws: LocalModelSelectionPreflightError.invalidProviderDescriptor) {
                try await preflight.validate(selection: selection, descriptor: forged)
            }
            #expect(service.events.isEmpty)
        }
    }
}
