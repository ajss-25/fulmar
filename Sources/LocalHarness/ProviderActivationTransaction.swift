import Foundation

protocol HarnessProviderCredentialServicing: Sendable {
    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription
    func setCredential(_ reference: CredentialReference, value: String) async throws
    func unsetCredential(_ reference: CredentialReference) async throws
}

protocol HarnessProviderActivationServicing: HarnessProviderCredentialServicing {
    func describeSettings() async throws -> HarnessSettingsDescription
    func mutateSettings(
        namespace: String,
        operations: [HarnessSettingsPathOperation],
        expectedRevision: Int?
    ) async throws -> HarnessSettingsNamespace
}

extension HarnessRPCClient: HarnessProviderCredentialServicing, HarnessProviderActivationServicing {}

protocol ProviderCatalogLoading: Sendable {
    func loadCatalog() async throws -> HarnessModelCatalogSnapshot
}

extension ModelSelectionCoordinator: ProviderCatalogLoading {}

protocol ProviderActivating: Sendable {
    func activate(
        descriptor: ProviderDescriptor,
        credentialValue: String?
    ) async throws -> ProviderActivationResult
}

struct ProviderActivationResult: Equatable, Sendable {
    let provider: ProviderView
    let createdCredential: Bool
    let createdProviderProfile: Bool
}

/// Applies credential readiness to DSH's provider/model topology without ever
/// reading a secret. Only external routes that declare an exact credential
/// reference are gated; Ollama's fixed internal marker and intentionally keyless
/// custom/local profiles keep their adapter-reported state.
enum ProviderCredentialReadiness {
    static func requiredReferences(in snapshot: HarnessModelCatalogSnapshot) -> [CredentialReference] {
        var seen = Set<CredentialReference>()
        return snapshot.providers.compactMap { provider in
            guard provider.boundary.isExternalToThisMac,
                  let reference = provider.descriptor.credentialReference,
                  seen.insert(reference).inserted else { return nil }
            return reference
        }
    }

    static func applying(
        _ credentials: HarnessCredentialDescription,
        to snapshot: HarnessModelCatalogSnapshot
    ) -> HarnessModelCatalogSnapshot {
        HarnessModelCatalogSnapshot(providers: snapshot.providers.map { provider in
            guard provider.configurationState != .unavailable,
                  provider.boundary.isExternalToThisMac,
                  let reference = provider.descriptor.credentialReference,
                  credentials.credentials[reference.rawValue]?.configured != true else {
                return provider
            }
            var updated = provider
            updated.configurationState = .needsCredential
            return updated
        })
    }
}

enum ProviderActivationFailure: String, Error, Equatable, Sendable {
    case unsupportedProvider
    case credentialStateUnavailable
    case credentialRequired
    case credentialManagedElsewhere
    case credentialReplacementRequiresSeparateAction
    case credentialWriteNotVerified
    case settingsUnavailable
    case settingsReadOnly
    case settingsRestartRequired
    case settingsConflict
    case settingsMutationNotVerified
    case providerNotReady
    case runtimeFailure
    case cancelled
}

struct ProviderActivationTransactionError: LocalizedError, Equatable, Sendable {
    let cause: ProviderActivationFailure
    let rollbackComplete: Bool

    var errorDescription: String? {
        let detail: String
        switch cause {
        case .unsupportedProvider:
            detail = "Configure this provider in DeepSeek Harness Provider Settings. Its existing profile will remain available in \(ProductBrand.displayName)."
        case .credentialStateUnavailable:
            detail = "The Keychain-backed credential state could not be verified."
        case .credentialRequired:
            detail = "Enter an API key before enabling this provider."
        case .credentialManagedElsewhere:
            detail = "This provider credential is managed elsewhere and cannot be created here."
        case .credentialReplacementRequiresSeparateAction:
            detail = "The existing API key was not replaced during provider activation. Enable the provider first, then replace its key as a separate action."
        case .credentialWriteNotVerified:
            detail = "The new Keychain credential could not be verified."
        case .settingsUnavailable:
            detail = "DeepSeek Harness did not expose the provider settings namespace."
        case .settingsReadOnly:
            detail = "DeepSeek Harness reports that provider settings are read-only."
        case .settingsRestartRequired:
            detail = "This provider cannot be enabled safely without restarting DeepSeek Harness."
        case .settingsConflict:
            detail = "Provider settings changed concurrently. Review the latest state and try again."
        case .settingsMutationNotVerified:
            detail = "DeepSeek Harness did not retain the exact provider profile."
        case .providerNotReady:
            detail = "DeepSeek Harness did not expose the enabled provider and its models."
        case .runtimeFailure:
            detail = "The authenticated local Harness service could not complete provider activation."
        case .cancelled:
            detail = "Provider activation was cancelled."
        }
        if rollbackComplete { return "Provider activation was not completed. \(detail) No new credential or provider profile was retained." }
        return "Provider activation failed and rollback was incomplete. \(detail) Restart \(ProductBrand.displayName) and review Provider Settings before continuing."
    }
}

/// Enables only the reviewed built-in cloud routes. Existing custom profiles are
/// selected through the live catalog; creating or changing a custom profile stays
/// in DSH Provider Settings, where its protocol, endpoint, and model schema can be
/// validated together.
///
/// Credential values are write-only. Consequently this transaction may create a
/// missing credential, but it never replaces an existing one: a replacement is a
/// separate explicit key-only operation which cannot honestly promise rollback.
actor ProviderActivationTransaction: ProviderActivating {
    private struct SettingsRollback: Sendable {
        let namespace: String
        let path: [String]
        let previousValue: HarnessJSONValue?
        let appliedValue: HarnessJSONValue
        let expectedRevision: Int?
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

    /// Only these exact, reviewed descriptors can be safely completed by the
    /// native credential flow. Custom providers need DSH's own settings UI so
    /// protocol, endpoint, model discovery, and credential schema stay coupled.
    nonisolated static func supportsNativeActivation(_ descriptor: ProviderDescriptor) -> Bool {
        (try? routeKind(for: descriptor)) != nil
    }

    func activate(
        descriptor: ProviderDescriptor,
        credentialValue: String?
    ) async throws -> ProviderActivationResult {
        let routeKind = try Self.routeKind(for: descriptor)
        guard let reference = descriptor.credentialReference else {
            throw ProviderActivationTransactionError(cause: .credentialStateUnavailable, rollbackComplete: true)
        }

        let credentialState: HarnessCredentialView
        do {
            let description = try await service.describeCredentials([reference])
            guard let state = description.credentials[reference.rawValue] else {
                throw ProviderActivationFailure.credentialStateUnavailable
            }
            credentialState = state
        } catch let failure as ProviderActivationFailure {
            throw ProviderActivationTransactionError(cause: failure, rollbackComplete: true)
        } catch {
            throw ProviderActivationTransactionError(cause: .credentialStateUnavailable, rollbackComplete: true)
        }

        let normalizedCredential = credentialValue?.trimmingCharacters(in: .whitespacesAndNewlines)
        if credentialState.configured, normalizedCredential?.isEmpty == false {
            throw ProviderActivationTransactionError(
                cause: .credentialReplacementRequiresSeparateAction,
                rollbackComplete: true
            )
        }
        if !credentialState.configured {
            guard credentialState.writable else {
                throw ProviderActivationTransactionError(cause: .credentialManagedElsewhere, rollbackComplete: true)
            }
            guard let normalizedCredential,
                  !normalizedCredential.isEmpty,
                  normalizedCredential.utf8.count <= 32 * 1_024,
                  !normalizedCredential.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                throw ProviderActivationTransactionError(cause: .credentialRequired, rollbackComplete: true)
            }
        }

        var createdCredential = false
        var credentialMutationToRollback: CredentialReference?
        var settingsRollback: SettingsRollback?
        var createdProviderProfile = false
        var currentFailure = ProviderActivationFailure.runtimeFailure

        do {
            if !credentialState.configured, let normalizedCredential {
                currentFailure = .credentialWriteNotVerified
                // The Keychain write may commit even when its transport reply
                // is lost. Install compensating intent before calling the
                // one-way setter, not after it returns.
                credentialMutationToRollback = reference
                try await service.setCredential(reference, value: normalizedCredential)
                let verified = try await service.describeCredentials([reference])
                guard verified.credentials[reference.rawValue]?.configured == true else {
                    throw ProviderActivationFailure.credentialWriteNotVerified
                }
                createdCredential = true
            }

            if case .piAICatalog = routeKind {
                currentFailure = .settingsUnavailable
                let description = try await service.describeSettings()
                guard description.hasDocument else { throw ProviderActivationFailure.settingsUnavailable }
                guard description.writable else { throw ProviderActivationFailure.settingsReadOnly }
                guard let namespace = description.namespaces.first(where: { $0.ns == descriptor.settingsNamespace }) else {
                    throw ProviderActivationFailure.settingsUnavailable
                }
                guard namespace.applies == .live else { throw ProviderActivationFailure.settingsRestartRequired }

                let previousProvider = Self.value(at: descriptor.settingsPath, in: namespace.value)
                let credentialPath = descriptor.settingsPath + ["apiKeyEnv"]
                if Self.value(at: credentialPath, in: namespace.value) != .string(reference.rawValue) {
                    var appliedProvider: [String: HarnessJSONValue]
                    if let previousProvider {
                        guard let object = previousProvider.objectValue else {
                            throw ProviderActivationFailure.settingsMutationNotVerified
                        }
                        appliedProvider = object
                    } else {
                        appliedProvider = [:]
                    }
                    appliedProvider["apiKeyEnv"] = .string(reference.rawValue)
                    let rollback = SettingsRollback(
                        namespace: namespace.ns,
                        path: descriptor.settingsPath,
                        previousValue: previousProvider,
                        appliedValue: .object(appliedProvider),
                        expectedRevision: nil
                    )
                    // Install rollback intent before transport. A response may
                    // be lost after DSH has already accepted the mutation.
                    settingsRollback = rollback
                    currentFailure = .settingsMutationNotVerified
                    let updated = try await service.mutateSettings(
                        namespace: namespace.ns,
                        operations: [.set(path: credentialPath, value: .string(reference.rawValue))],
                        expectedRevision: namespace.revision
                    )
                    settingsRollback = SettingsRollback(
                        namespace: rollback.namespace,
                        path: rollback.path,
                        previousValue: rollback.previousValue,
                        appliedValue: rollback.appliedValue,
                        expectedRevision: updated.revision
                    )
                    guard updated.ns == namespace.ns,
                          updated.applies == .live,
                          Self.value(at: credentialPath, in: updated.value) == .string(reference.rawValue) else {
                        throw ProviderActivationFailure.settingsMutationNotVerified
                    }
                    createdProviderProfile = previousProvider == nil
                }
            }

            currentFailure = .providerNotReady
            let provider = try await waitForReadyProvider(descriptor)
            return ProviderActivationResult(
                provider: provider,
                createdCredential: createdCredential,
                createdProviderProfile: createdProviderProfile
            )
        } catch {
            let failure: ProviderActivationFailure
            if error is CancellationError || Task.isCancelled {
                failure = .cancelled
            } else if let rpcError = error as? HarnessRPCClientError,
                      case .remote(let remote) = rpcError,
                      remote.code == .settingsConflict {
                failure = .settingsConflict
            } else {
                failure = (error as? ProviderActivationFailure) ?? currentFailure
            }
            let service = self.service
            let rollbackSettings = settingsRollback
            let rollbackCredential = credentialMutationToRollback
            let rollback = Task.detached {
                await Self.rollback(
                    service: service,
                    settings: rollbackSettings,
                    createdCredential: rollbackCredential
                )
            }
            let rollbackComplete = await rollback.value
            throw ProviderActivationTransactionError(cause: failure, rollbackComplete: rollbackComplete)
        }
    }

    private enum RouteKind {
        case deepSeekOfficial
        case piAICatalog
    }

    private static func routeKind(for descriptor: ProviderDescriptor) throws -> RouteKind {
        if descriptor == BuiltInProviderDescriptors.deepSeekOfficial {
            return .deepSeekOfficial
        }
        if descriptor == BuiltInProviderDescriptors.openAI
            || descriptor == BuiltInProviderDescriptors.anthropic {
            return .piAICatalog
        }
        throw ProviderActivationTransactionError(cause: .unsupportedProvider, rollbackComplete: true)
    }

    private func waitForReadyProvider(_ expectedDescriptor: ProviderDescriptor) async throws -> ProviderView {
        for attempt in 0..<catalogAttempts {
            try Task.checkCancellation()
            if let snapshot = try? await catalog.loadCatalog(),
               let provider = snapshot.provider(expectedDescriptor.id),
               provider.descriptor == expectedDescriptor,
               provider.configurationState == .ready,
               !provider.models.isEmpty {
                return provider
            }
            if attempt + 1 < catalogAttempts, catalogRetryNanoseconds > 0 {
                try await Task.sleep(nanoseconds: catalogRetryNanoseconds)
            }
        }
        throw ProviderActivationFailure.providerNotReady
    }

    private static func rollback(
        service: any HarnessProviderActivationServicing,
        settings: SettingsRollback?,
        createdCredential: CredentialReference?
    ) async -> Bool {
        var complete = true
        if let settings {
            do {
                var revision = settings.expectedRevision
                if revision == nil {
                    let description = try await service.describeSettings()
                    guard let namespace = description.namespaces.first(where: { $0.ns == settings.namespace }) else {
                        throw ProviderActivationFailure.settingsUnavailable
                    }
                    let current = value(at: settings.path, in: namespace.value)
                    if current == settings.previousValue {
                        revision = nil
                    } else {
                        guard current == settings.appliedValue else {
                            throw ProviderActivationFailure.settingsMutationNotVerified
                        }
                        revision = namespace.revision
                    }
                }
                if let revision {
                    let operation: HarnessSettingsPathOperation = settings.previousValue.map {
                        .set(path: settings.path, value: $0)
                    } ?? .unset(path: settings.path)
                    let restored = try await service.mutateSettings(
                        namespace: settings.namespace,
                        operations: [operation],
                        expectedRevision: revision
                    )
                    guard restored.ns == settings.namespace,
                          value(at: settings.path, in: restored.value) == settings.previousValue else {
                        throw ProviderActivationFailure.settingsMutationNotVerified
                    }
                }
            } catch {
                complete = false
            }
        }
        if let createdCredential {
            do {
                try await service.unsetCredential(createdCredential)
                let verified = try await service.describeCredentials([createdCredential])
                if verified.credentials[createdCredential.rawValue]?.configured != false { complete = false }
            } catch {
                complete = false
            }
        }
        return complete
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
