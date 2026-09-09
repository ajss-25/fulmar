import Foundation

/// Versioned, non-secret record of the one provider route whose endpoint the
/// contained Harness runtime may currently contact. Consent is bound to the
/// normalized origin, so editing a provider's base URL invalidates it.
struct ProviderConsentState: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 3

    let schemaVersion: Int
    var activeProvider: ProviderID?
    var grants: Set<ProviderConsentGrant>

    init(activeProvider: ProviderID? = nil, grants: Set<ProviderConsentGrant> = []) {
        schemaVersion = Self.currentSchemaVersion
        self.activeProvider = activeProvider
        self.grants = grants
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, activeProvider, grants
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        if version == 1 || version == 2 {
            // Version 1 did not bind the Keychain reference; version 2 still
            // did not distinguish provider-native discovery from explicit
            // no-auth. Decode the complete relevant legacy shape so malformed
            // state is not silently accepted, then revoke it all and require
            // one fresh authentication-mode-aware activation. No secret is read.
            _ = try container.decodeIfPresent(ProviderID.self, forKey: .activeProvider)
            if version == 1 {
                _ = try container.decode(Set<LegacyV1Grant>.self, forKey: .grants)
            } else {
                _ = try container.decode(Set<LegacyV2Grant>.self, forKey: .grants)
            }
            schemaVersion = Self.currentSchemaVersion
            activeProvider = nil
            grants = []
            return
        }
        guard version == Self.currentSchemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported provider-consent schema version \(version)."
            )
        }
        schemaVersion = version
        activeProvider = try container.decodeIfPresent(ProviderID.self, forKey: .activeProvider)
        grants = try container.decode(Set<ProviderConsentGrant>.self, forKey: .grants)
    }

    private struct LegacyV1Grant: Codable, Hashable {
        let provider: ProviderID
        let boundary: DataBoundary
        let origin: ProviderEndpointOrigin?
    }

    private struct LegacyV2Grant: Codable, Hashable {
        let provider: ProviderID
        let boundary: DataBoundary
        let origin: ProviderEndpointOrigin?
        let credentialReference: CredentialReference?
    }

    func activeGrant(for provider: ProviderID) -> ProviderConsentGrant? {
        guard activeProvider == provider else { return nil }
        let matches = grants.filter { $0.provider == provider }
        // A Set de-duplicates exact grants, not conflicting grants for the same
        // provider. Never let arbitrary Set iteration choose an egress origin.
        guard matches.count == 1 else { return nil }
        return matches.first
    }
}

enum ProviderConsentStoreError: Error, Equatable, LocalizedError {
    case invalidStoredType
    case unresolvedExternalEndpoint

    var errorDescription: String? {
        switch self {
        case .invalidStoredType:
            return "Stored provider consent is not a valid data document."
        case .unresolvedExternalEndpoint:
            return "The provider endpoint could not be normalized, so external access remains blocked."
        }
    }
}

final class ProviderConsentStore {
    static let stateKey = "providerConsentState"

    private let defaults: UserDefaults
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        decoder = JSONDecoder()
    }

    func load() throws -> ProviderConsentState {
        guard let stored = defaults.object(forKey: Self.stateKey) else { return ProviderConsentState() }
        guard let data = stored as? Data else { throw ProviderConsentStoreError.invalidStoredType }
        let state = try decoder.decode(ProviderConsentState.self, from: data)
        // Persist fail-closed legacy migrations immediately so an old external
        // grant cannot reappear after a later partial rollback.
        if let stored = Self.storedSchemaVersion(in: data), stored < ProviderConsentState.currentSchemaVersion {
            defaults.set(try encoder.encode(state), forKey: Self.stateKey)
        }
        return state
    }

    func save(_ state: ProviderConsentState) throws {
        defaults.set(try encoder.encode(state), forKey: Self.stateKey)
    }

    @discardableResult
    func activate(_ descriptor: ProviderDescriptor) throws -> ProviderConsentState {
        var state = try load()
        state.activeProvider = descriptor.id
        state.grants = state.grants.filter { $0.provider != descriptor.id }
        let grant = ProviderConsentGrant(for: descriptor)
        if descriptor.requiresExplicitConsent, grant.origin == nil {
            throw ProviderConsentStoreError.unresolvedExternalEndpoint
        }
        state.grants.insert(grant)
        try save(state)
        return state
    }

    func restore(_ state: ProviderConsentState) throws {
        try save(state)
    }

    /// Revokes every grant for an edited provider before its live settings are
    /// changed. Re-consent must flow through the normal exact-descriptor commit.
    func deactivate(_ provider: ProviderID) throws {
        var state = try load()
        state.grants = state.grants.filter { $0.provider != provider }
        if state.activeProvider == provider { state.activeProvider = nil }
        try save(state)
    }

    private static func storedSchemaVersion(in data: Data) -> Int? {
        (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["schemaVersion"] as? Int
    }
}
