import Foundation

/// Network-capable features that are not the selected conversation model.
/// They deliberately have their own route and consent vocabulary so a local
/// conversation can never inherit cloud access from provider-selection state.
enum AuxiliaryCapability: String, Codable, CaseIterable, Hashable, Sendable {
    case webSearch
    case imageGeneration
    case transcription
    case speech
    case connector
}

/// Non-secret route declaration for one auxiliary capability. `origin` is
/// normalized at configuration time; an API-key value can never be stored here.
struct AuxiliaryCapabilityRoute: Codable, Hashable, Sendable, Identifiable {
    let id: String
    let capability: AuxiliaryCapability
    let provider: ProviderID
    let boundary: DataBoundary
    let origin: ProviderEndpointOrigin?
    let credentialReference: CredentialReference?

    init(
        id: String,
        capability: AuxiliaryCapability,
        provider: ProviderID,
        boundary: DataBoundary,
        endpoint: URL?,
        credentialReference: CredentialReference?
    ) {
        self.id = id
        self.capability = capability
        self.provider = provider
        self.boundary = boundary
        origin = endpoint.flatMap(ProviderEndpointOrigin.init(url:))
        self.credentialReference = credentialReference
    }
}

/// Consent is bound to every disclosure-relevant route field, not merely the
/// provider name. Editing capability, boundary, or endpoint invalidates it.
struct AuxiliaryCapabilityConsentGrant: Codable, Hashable, Sendable {
    let routeID: String
    let capability: AuxiliaryCapability
    let provider: ProviderID
    let boundary: DataBoundary
    let origin: ProviderEndpointOrigin?

    init(route: AuxiliaryCapabilityRoute) {
        routeID = route.id
        capability = route.capability
        provider = route.provider
        boundary = route.boundary
        origin = route.origin
    }

    func permits(_ route: AuxiliaryCapabilityRoute) -> Bool {
        routeID == route.id
            && capability == route.capability
            && provider == route.provider
            && boundary == route.boundary
            && origin == route.origin
    }
}

enum AuxiliaryCapabilityEgressDenial: String, Equatable, Sendable {
    case invalidRoute
    case missingConsent
    case conflictingConsent
    case invalidBoundary
}

enum AuxiliaryCapabilityEgressDecision: Equatable, Sendable {
    case onDevice
    case allow(ProviderNetworkOrigin)
    case deny(AuxiliaryCapabilityEgressDenial)
}

enum AuxiliaryCapabilityEgressPolicy {
    private static let maximumIdentifierBytes = 256

    /// Evaluates only capability-specific grants. Conversation-provider consent
    /// is intentionally absent from this API and therefore cannot be reused by
    /// an auxiliary transport accidentally.
    static func evaluate(
        route: AuxiliaryCapabilityRoute,
        grants: Set<AuxiliaryCapabilityConsentGrant>
    ) -> AuxiliaryCapabilityEgressDecision {
        guard validIdentifier(route.id), validIdentifier(route.provider.rawValue) else {
            return .deny(.invalidRoute)
        }

        switch route.boundary {
        case .onDevice:
            guard route.origin == nil, route.credentialReference == nil else {
                return .deny(.invalidBoundary)
            }
            return .onDevice
        case .localNetwork, .cloud:
            guard let endpoint = route.origin,
                  let origin = networkOrigin(endpoint) else {
                return .deny(.invalidRoute)
            }
            if route.boundary == .localNetwork {
                guard ProviderNetworkOrigin.isLocalAddress(origin.host) else {
                    return .deny(.invalidBoundary)
                }
            } else {
                guard origin.scheme == "https", !ProviderNetworkOrigin.isLocalAddress(origin.host) else {
                    return .deny(.invalidBoundary)
                }
            }
            let matches = grants.filter { $0.routeID == route.id }
            guard matches.count <= 1 else { return .deny(.conflictingConsent) }
            guard matches.first?.permits(route) == true else { return .deny(.missingConsent) }
            return .allow(origin)
        }
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= maximumIdentifierBytes
            && value.unicodeScalars.allSatisfy { scalar in
                scalar.isASCII && !CharacterSet.controlCharacters.contains(scalar)
            }
    }

    private static func networkOrigin(_ endpoint: ProviderEndpointOrigin) -> ProviderNetworkOrigin? {
        var components = URLComponents()
        components.scheme = endpoint.scheme
        components.host = endpoint.host
        components.port = endpoint.port
        return components.url.flatMap(ProviderNetworkOrigin.init(url:))
    }
}
