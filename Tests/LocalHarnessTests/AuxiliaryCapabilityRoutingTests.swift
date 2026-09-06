import Foundation
import Testing
@testable import LocalHarness

private func capabilityRoute(
    id: String = "search.deepseek.primary",
    capability: AuxiliaryCapability = .webSearch,
    provider: ProviderID = ProviderID("deepseek-search"),
    boundary: DataBoundary = .cloud,
    endpoint: URL? = URL(string: "https://api.deepseek.com/anthropic/v1"),
    credential: CredentialReference? = CredentialReference("DEEPSEEK_API_KEY")
) -> AuxiliaryCapabilityRoute {
    AuxiliaryCapabilityRoute(
        id: id,
        capability: capability,
        provider: provider,
        boundary: boundary,
        endpoint: endpoint,
        credentialReference: credential
    )
}

@Test func auxiliaryCloudCapabilityRequiresItsOwnExactConsent() {
    let route = capabilityRoute()
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: route, grants: []) == .deny(.missingConsent))

    let grant = AuxiliaryCapabilityConsentGrant(route: route)
    let expected = ProviderNetworkOrigin(url: URL(string: "https://api.deepseek.com")!)!
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: route, grants: [grant]) == .allow(expected))
}

@Test func conversationConsentCannotAuthorizeAnAuxiliaryCapability() {
    let route = capabilityRoute()
    let conversationConsent = ProviderConsentState(
        activeProvider: BuiltInProviderDescriptors.deepSeekOfficial.id,
        grants: [ProviderConsentGrant(for: BuiltInProviderDescriptors.deepSeekOfficial)]
    )
    #expect(ProviderEgressPolicy.allowedOrigins(
        selection: ModelSelection(route: ModelRoute(
            provider: BuiltInProviderDescriptors.deepSeekOfficial.id,
            model: ModelID("deepseek-v4-flash")
        )),
        consent: conversationConsent
    ).count == 1)
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: route, grants: []) == .deny(.missingConsent))
}

@Test func changedCapabilityEndpointOrBoundaryInvalidatesConsent() {
    let original = capabilityRoute()
    let grant = AuxiliaryCapabilityConsentGrant(route: original)

    let changedCapability = capabilityRoute(capability: .imageGeneration)
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: changedCapability, grants: [grant]) == .deny(.missingConsent))

    let changedEndpoint = capabilityRoute(endpoint: URL(string: "https://search.example.test/v1"))
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: changedEndpoint, grants: [grant]) == .deny(.missingConsent))

    let changedBoundary = capabilityRoute(
        boundary: .localNetwork,
        endpoint: URL(string: "http://192.168.1.50:8080"),
        credential: CredentialReference("LAN_SEARCH_KEY")
    )
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: changedBoundary, grants: [grant]) == .deny(.missingConsent))
}

@Test func onDeviceCapabilityCannotSmuggleAnEndpointOrCredential() {
    let valid = capabilityRoute(
        id: "speech.on-device",
        capability: .speech,
        provider: ProviderID("macos-speech"),
        boundary: .onDevice,
        endpoint: nil,
        credential: nil
    )
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: valid, grants: []) == .onDevice)

    let endpoint = capabilityRoute(
        id: "speech.on-device",
        capability: .speech,
        provider: ProviderID("macos-speech"),
        boundary: .onDevice,
        endpoint: URL(string: "https://speech.example.test"),
        credential: nil
    )
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: endpoint, grants: []) == .deny(.invalidBoundary))

    let credential = capabilityRoute(
        id: "speech.on-device",
        capability: .speech,
        provider: ProviderID("macos-speech"),
        boundary: .onDevice,
        endpoint: nil,
        credential: CredentialReference("CLOUD_SPEECH_KEY")
    )
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(route: credential, grants: []) == .deny(.invalidBoundary))
}

@Test func auxiliaryCapabilityRejectsConflictingGrantsAndWrongNetworkClass() {
    let route = capabilityRoute()
    let exact = AuxiliaryCapabilityConsentGrant(route: route)
    let conflictingRoute = capabilityRoute(endpoint: URL(string: "https://other.example.test/v1"))
    let conflicting = AuxiliaryCapabilityConsentGrant(route: conflictingRoute)
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(
        route: route,
        grants: [exact, conflicting]
    ) == .deny(.conflictingConsent))

    let publicLAN = capabilityRoute(
        id: "search.lan",
        boundary: .localNetwork,
        endpoint: URL(string: "https://example.com"),
        credential: CredentialReference("LAN_KEY")
    )
    #expect(AuxiliaryCapabilityEgressPolicy.evaluate(
        route: publicLAN,
        grants: [AuxiliaryCapabilityConsentGrant(route: publicLAN)]
    ) == .deny(.invalidBoundary))
}

@Test func auxiliaryRouteSerializationNeverContainsCredentialValues() throws {
    let data = try JSONEncoder().encode(capabilityRoute())
    let text = String(decoding: data, as: UTF8.self)
    #expect(text.contains("DEEPSEEK_API_KEY"))
    #expect(!text.contains("sk-"))
    #expect(!text.contains("secret"))
}
