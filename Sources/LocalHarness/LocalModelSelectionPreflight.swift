import Foundation

@MainActor
protocol LocalModelSelectionPreflightServing: AnyObject {
    func fetchCompatibleVersion() async throws -> OllamaStableVersion
    func fetchModels() async throws -> [OllamaModel]
    func inspectModelCompatibility(model: String) async throws -> OllamaModelCompatibility
}

extension OllamaClient: LocalModelSelectionPreflightServing {}

enum LocalModelSelectionPreflightError: Error, Equatable, LocalizedError {
    case unavailable
    case invalidProviderDescriptor
    case modelUnavailable
    case modelChangedDuringInspection

    var errorDescription: String? {
        switch self {
        case .unavailable:
            return "Fulmar could not complete the local-model safety check. The previous model remains active; verify Ollama is ready and try again."
        case .invalidProviderDescriptor:
            return "The local-model route no longer matches Fulmar's reviewed Ollama provider. Refresh Models & Providers before trying again."
        case .modelUnavailable:
            return "Ollama did not report exactly one installed manifest for this model. Refresh Local Models, resolve any duplicate tag, and try again."
        case .modelChangedDuringInspection:
            return "The installed model changed while Fulmar was checking it. Nothing was switched; wait for the Ollama pull or removal to finish, then try again."
        }
    }
}

/// Read-only admission shared by every native Ollama model picker. It runs
/// before a protected provider-selection mutation is allowed to stop the old
/// runtime, so a model which is too large, lacks tools, has unsafe metadata,
/// or changes during inspection cannot cause a disruptive restart.
@MainActor
final class LocalModelSelectionPreflight {
    private let service: any LocalModelSelectionPreflightServing
    private let physicalMemoryBytes: () -> UInt64

    init(
        service: any LocalModelSelectionPreflightServing,
        physicalMemoryBytes: @escaping () -> UInt64 = { ProcessInfo.processInfo.physicalMemory }
    ) {
        self.service = service
        self.physicalMemoryBytes = physicalMemoryBytes
    }

    func validate(selection: ModelSelection, descriptor: ProviderDescriptor) async throws {
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else { return }
        guard Self.isReviewedOllamaDescriptor(descriptor) else {
            throw LocalModelSelectionPreflightError.invalidProviderDescriptor
        }
        guard OllamaModelNamePolicy.isSafe(selection.route.model.rawValue) else {
            throw ModelSelectionCoordinatorError.invalidSelection
        }

        do {
            try Task.checkCancellation()
            _ = try await service.fetchCompatibleVersion()
            try Task.checkCancellation()

            let firstCatalog = try await service.fetchModels()
            let admittedManifest = try Self.admittedManifest(
                selection: selection,
                installedModels: firstCatalog,
                physicalMemoryBytes: physicalMemoryBytes()
            )
            try Task.checkCancellation()

            let assessment = try await service.inspectModelCompatibility(
                model: selection.route.model.rawValue
            )
            _ = try LocalModelCompatibilityPolicy.validate(
                selection: selection,
                assessment: assessment
            )
            try Task.checkCancellation()

            // `/api/show` and `/api/tags` are separate Ollama reads. Re-read
            // the exact manifest after capability inspection so an overlapping
            // pull, retag, replacement, or deletion fails before lifecycle
            // mutation rather than applying the assessment to another model.
            let secondCatalog = try await service.fetchModels()
            let confirmedManifest = try Self.admittedManifest(
                selection: selection,
                installedModels: secondCatalog,
                physicalMemoryBytes: physicalMemoryBytes()
            )
            guard confirmedManifest == admittedManifest else {
                throw LocalModelSelectionPreflightError.modelChangedDuringInspection
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as LocalModelSelectionPreflightError {
            throw error
        } catch let error as LocalModelAdmissionError {
            throw error
        } catch let error as QualifiedLocalModelHostAdmissionError {
            throw error
        } catch let error as OllamaVersionCompatibilityError {
            throw error
        } catch let error as OllamaModelInspectionError {
            throw error
        } catch let error as ModelSelectionCoordinatorError {
            throw error
        } catch {
            // Transport/provider errors are untrusted display input. Collapse
            // them to one app-owned message at this UI-facing boundary.
            throw LocalModelSelectionPreflightError.unavailable
        }
    }

    /// The reviewed Ollama identity is static, but its app-owned listener gets
    /// a fresh reserved port on every launch. Comparing the complete descriptor
    /// therefore rejects the legitimate live catalog entry. Keep every stable
    /// identity and security field pinned while admitting only the exact
    /// loopback `/v1` URL shape used by an `AppOwnedOllamaEndpoint`.
    private static func isReviewedOllamaDescriptor(_ descriptor: ProviderDescriptor) -> Bool {
        let reviewed = BuiltInProviderDescriptors.ollama
        guard descriptor.id == reviewed.id,
              descriptor.displayName == reviewed.displayName,
              descriptor.settingsNamespace == reviewed.settingsNamespace,
              descriptor.settingsPath == reviewed.settingsPath,
              descriptor.adapterKind == reviewed.adapterKind,
              descriptor.wireProtocol == reviewed.wireProtocol,
              descriptor.boundary == reviewed.boundary,
              descriptor.credentialReference == reviewed.credentialReference,
              descriptor.explicitlyUnauthenticated == reviewed.explicitlyUnauthenticated,
              descriptor.supportsNativeProfileEditing == reviewed.supportsNativeProfileEditing else {
            return false
        }

        // The nil endpoint belongs to the immutable recovery descriptor. A
        // live catalog may replace only that field, and only with the strict
        // HTTP/127.0.0.1/explicit-port/v1 form validated by the owned-runtime
        // endpoint type. Listener ownership is independently verified before
        // the catalog is exposed.
        guard let baseURL = descriptor.defaultBaseURL else { return true }
        return AppOwnedOllamaEndpoint.validatingProviderBaseURL(baseURL) != nil
    }

    private static func admittedManifest(
        selection: ModelSelection,
        installedModels: [OllamaModel],
        physicalMemoryBytes: UInt64
    ) throws -> OllamaModel {
        try LocalModelCompatibilityPolicy.validateInstalledIdentity(
            selection: selection,
            installedModels: installedModels
        )
        let matches = installedModels.filter { $0.name == selection.route.model.rawValue }
        guard matches.count == 1 else {
            throw LocalModelSelectionPreflightError.modelUnavailable
        }
        try LocalModelCompatibilityPolicy.validateHostMemory(
            selection: selection,
            installedModels: installedModels,
            physicalMemoryBytes: physicalMemoryBytes
        )
        return matches[0]
    }
}
