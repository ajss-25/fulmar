import Foundation

enum ProviderCredentialMutationAction: Equatable, Sendable {
    case replace
    case remove
}

enum ProviderCredentialMutationDisposition: Equatable, Sendable {
    /// The mutation RPC returned and the subsequent write-only readiness view
    /// matched the requested configured/unconfigured state.
    case verifiedApplied
    /// The mutation response was lost, but an unconfigured state proves that a
    /// removal took effect. Replacement values remain intentionally unreadable
    /// and therefore can never use this disposition.
    case appliedAfterAmbiguousResponse
    /// A failed removal was followed by the still-configured state, proving the
    /// one-way mutation did not remove the credential.
    case confirmedNotApplied
    /// Readiness could not establish a safe conclusion. For replacement this
    /// includes a configured result after a lost acknowledgement because the
    /// old and new secret are intentionally indistinguishable.
    case uncertain
}

struct ProviderCredentialMutationAssessment: Equatable, Sendable {
    let action: ProviderCredentialMutationAction
    let disposition: ProviderCredentialMutationDisposition
    let configured: Bool?

    var requiresRuntimeRestartWhenActive: Bool {
        disposition != .confirmedNotApplied
    }
}

/// Performs the one-way Keychain mutation and then re-describes only readiness.
/// It never reads or attempts to roll back a credential value. A transport loss
/// after `set` cannot distinguish old from new secret material, so replacement
/// deliberately reports uncertainty even when the reference remains configured.
actor ProviderCredentialMutationVerifier {
    private let service: any HarnessProviderCredentialServicing

    init(service: any HarnessProviderCredentialServicing) {
        self.service = service
    }

    func mutate(
        reference: CredentialReference,
        value: String?
    ) async -> ProviderCredentialMutationAssessment {
        let action: ProviderCredentialMutationAction = value == nil ? .remove : .replace
        var acknowledged = false
        do {
            if let value { try await service.setCredential(reference, value: value) }
            else { try await service.unsetCredential(reference) }
            acknowledged = true
        } catch {
            // The response is not authoritative: DSH may have committed the
            // Keychain operation before the authenticated transport failed.
        }

        let configured: Bool?
        do {
            configured = try await service.describeCredentials([reference])
                .credentials[reference.rawValue]?.configured
        } catch {
            configured = nil
        }

        let disposition: ProviderCredentialMutationDisposition
        switch (action, acknowledged, configured) {
        case (.remove, true, false), (.replace, true, true):
            disposition = .verifiedApplied
        case (.remove, false, false):
            disposition = .appliedAfterAmbiguousResponse
        case (.remove, false, true):
            disposition = .confirmedNotApplied
        default:
            disposition = .uncertain
        }
        return ProviderCredentialMutationAssessment(
            action: action,
            disposition: disposition,
            configured: configured
        )
    }
}
