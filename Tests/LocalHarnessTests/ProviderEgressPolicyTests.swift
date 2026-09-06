import Foundation
import Testing
@testable import LocalHarness

private func selection(provider: ProviderID) -> ModelSelection {
    ModelSelection(route: ModelRoute(provider: provider, model: ModelID("test-model")))
}

@MainActor
private final class CustomProviderMutationBarrierProbe {
    var preparationEntered = false
    var mutationStarted = false
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func prepare(_ provider: ProviderID) async {
        _ = provider
        preparationEntered = true
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

@Test func localSelectionPublishesNoProviderOrigins() {
    let selected = selection(provider: BuiltInProviderDescriptors.ollama.id)
    let consent = ProviderConsentState(activeProvider: selected.route.provider)
    #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: consent).isEmpty)
    #expect(ProviderEgressPolicy.serializedAllowlist(selection: selected, consent: consent) == "[]")
}

@Test func officialCloudProviderStillRequiresExactActiveConsent() {
    let provider = BuiltInProviderDescriptors.deepSeekOfficial
    let selected = selection(provider: provider.id)
    #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: .init()).isEmpty)

    let inactive = ProviderConsentState(
        activeProvider: BuiltInProviderDescriptors.openAI.id,
        grants: [ProviderConsentGrant(for: provider)]
    )
    #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: inactive).isEmpty)

    let active = ProviderConsentState(
        activeProvider: provider.id,
        grants: [ProviderConsentGrant(for: provider)]
    )
    let origins = ProviderEgressPolicy.allowedOrigins(selection: selected, consent: active)
    #expect(origins == [ProviderNetworkOrigin(url: URL(string: "https://api.deepseek.com/v1")!)!])
}

@Test func consentCannotBeReusedAcrossProviders() {
    let first = BuiltInProviderDescriptors.openAICompatible(
        id: ProviderID("private-gateway"),
        displayName: "Private Gateway",
        baseURL: URL(string: "https://one.example.test/v1")!,
        boundary: .cloud
    )
    let consent = ProviderConsentState(
        activeProvider: first.id,
        grants: [ProviderConsentGrant(for: first)]
    )
    let selected = selection(provider: first.id)
    #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: consent).count == 1)
    #expect(ProviderEgressPolicy.allowedOrigins(
        selection: selection(provider: ProviderID("different-provider")),
        consent: consent
    ).isEmpty)
}

@Test func boundaryRulesRejectPublicHTTPAndMismatchedLocalEndpoints() {
    let provider = ProviderID("gateway")
    let selected = selection(provider: provider)
    let publicHTTP = ProviderConsentGrant(
        provider: provider,
        boundary: .cloud,
        baseURL: URL(string: "http://example.com/v1")
    )
    #expect(ProviderEgressPolicy.allowedOrigins(
        selection: selected,
        consent: .init(activeProvider: provider, grants: [publicHTTP])
    ).isEmpty)

    let publicMarkedLAN = ProviderConsentGrant(
        provider: provider,
        boundary: .localNetwork,
        baseURL: URL(string: "https://example.com/v1")
    )
    #expect(ProviderEgressPolicy.allowedOrigins(
        selection: selected,
        consent: .init(activeProvider: provider, grants: [publicMarkedLAN])
    ).isEmpty)

    let lan = ProviderConsentGrant(
        provider: provider,
        boundary: .localNetwork,
        baseURL: URL(string: "http://192.168.1.20:8080/v1")
    )
    #expect(ProviderEgressPolicy.allowedOrigins(
        selection: selected,
        consent: .init(activeProvider: provider, grants: [lan])
    ).count == 1)
}

@Test func providerOriginsRejectCredentialsInsecurePublicHTTPAndMetadataTargets() {
    #expect(ProviderNetworkOrigin(url: URL(string: "https://user:secret@example.com/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://example.com/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://169.254.169.254/latest/meta-data")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "https://metadata.google.internal/")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "file:///etc/passwd")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://127.0.0.1:11434/v1")!) != nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://192.168.evil.example/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://fdexample.com/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://fc-not-an-ip.example/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://10.evil.example/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://[fd00::1]:8080/v1")!) != nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "http://[fe80::1]:8080/v1")!) == nil)
    for reservedIPv4 in [
        "0.0.0.0", "100.64.0.1", "169.254.169.254", "192.0.2.1",
        "192.88.99.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1"
    ] {
        #expect(ProviderNetworkOrigin(url: URL(string: "https://\(reservedIPv4)/v1")!) == nil)
    }
    for reservedIPv6 in [
        "::", "fe80::1", "ff02::1", "2001:db8::1", "2001:2::1",
        "2001:10::1", "2001:20::1", "2002:0a00:0001::1", "3ffe::1", "3fff::1"
    ] {
        #expect(ProviderNetworkOrigin(url: URL(string: "https://[\(reservedIPv6)]/v1")!) == nil)
    }
    #expect(ProviderNetworkOrigin(url: URL(string: "https://93.184.216.34/v1")!) != nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "https://[2606:2800:220:1:248:1893:25c8:1946]/v1")!) != nil)
    for malformed in [
        "*.example.com", "example..com", "-bad.example", "bad-.example",
        "exa_mple.com", ".example.com", "..example.com..", "example.com...",
        "127.1", "0177.0.0.1", "2130706433", "0x7f000001"
    ] {
        #expect(ProviderNetworkOrigin(url: URL(string: "https://\(malformed)/v1")!) == nil)
    }
    // Foundation may Unicode-decode IDNA hostnames. This boundary deliberately
    // rejects them instead of mixing display and wire identities.
    #expect(ProviderNetworkOrigin(url: URL(string: "https://xn--bcher-kva.example/v1")!) == nil)
    #expect(ProviderNetworkOrigin(url: URL(string: "https://api.deepseek.com./v1")!)?.host == "api.deepseek.com")
}

@Test func providerAllowlistSerializationContainsOnlyNormalizedOrigin() throws {
    let provider = BuiltInProviderDescriptors.openAI
    let selected = selection(provider: provider.id)
    let consent = ProviderConsentState(
        activeProvider: provider.id,
        grants: [ProviderConsentGrant(for: provider)]
    )
    let encoded = ProviderEgressPolicy.serializedAllowlist(selection: selected, consent: consent)
    let decoded = try JSONDecoder().decode([ProviderRuntimeNetworkOrigin].self, from: Data(encoded.utf8))
    #expect(decoded.count == 1)
    #expect(decoded.first?.boundary == .cloud)
    #expect(decoded.first?.host == "api.openai.com")
    #expect(!encoded.contains("/v1"))
    #expect(!encoded.contains("API_KEY"))
    #expect(!encoded.contains("secret"))
}

@Test func runtimeSerializationNeverOmitsOrInfersTheReviewedBoundary() throws {
    let cloud = try #require(ProviderNetworkOrigin(url: URL(string: "https://api.example.test/v1")!))
    let local = try #require(ProviderNetworkOrigin(url: URL(string: "http://192.168.1.20:8080/v1")!))

    let cloudData = ProviderEgressPolicy.serializedAllowlist(origins: [cloud], boundary: .cloud)
    let localData = ProviderEgressPolicy.serializedAllowlist(origins: [local], boundary: .localNetwork)
    let cloudValues = try JSONDecoder().decode([ProviderRuntimeNetworkOrigin].self, from: Data(cloudData.utf8))
    let localValues = try JSONDecoder().decode([ProviderRuntimeNetworkOrigin].self, from: Data(localData.utf8))

    #expect(cloudValues == [ProviderRuntimeNetworkOrigin(origin: cloud, boundary: .cloud)])
    #expect(localValues == [ProviderRuntimeNetworkOrigin(origin: local, boundary: .localNetwork)])
    #expect(cloudData.contains(#""boundary":"cloud""#))
    #expect(localData.contains(#""boundary":"localNetwork""#))
}

@Test func conflictingDuplicateProviderGrantsNeverDependOnSetOrWireOrder() throws {
    let first = #"{"schemaVersion":3,"activeProvider":"gateway","grants":[{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"one.example.test","port":443},"credentialReference":"ONE_API_KEY","explicitlyUnauthenticated":false},{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"two.example.test","port":443},"credentialReference":"ONE_API_KEY","explicitlyUnauthenticated":false}]}"#
    let second = #"{"schemaVersion":3,"activeProvider":"gateway","grants":[{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"two.example.test","port":443},"credentialReference":"ONE_API_KEY","explicitlyUnauthenticated":false},{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"one.example.test","port":443},"credentialReference":"ONE_API_KEY","explicitlyUnauthenticated":false}]}"#
    let selected = selection(provider: ProviderID("gateway"))

    for encoded in [first, second] {
        let state = try JSONDecoder().decode(ProviderConsentState.self, from: Data(encoded.utf8))
        #expect(state.activeGrant(for: selected.route.provider) == nil)
        #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: state).isEmpty)
    }
}

@Suite(.serialized)
struct ProviderConsentStoreTests {
    @Test func legacyConsentIsMigratedByRevokingEveryUnboundGrant() throws {
        let name = "ProviderConsentStoreTests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let legacy = Data(#"{"schemaVersion":1,"activeProvider":"openai","grants":[{"provider":"openai","boundary":"cloud","origin":{"scheme":"https","host":"api.openai.com","port":443}}]}"#.utf8)
        defaults.set(legacy, forKey: ProviderConsentStore.stateKey)

        let migrated = try ProviderConsentStore(defaults: defaults).load()
        #expect(migrated.schemaVersion == ProviderConsentState.currentSchemaVersion)
        #expect(migrated.activeProvider == nil)
        #expect(migrated.grants.isEmpty)
        let persisted = try #require(defaults.data(forKey: ProviderConsentStore.stateKey))
        #expect(!persisted.elementsEqual(legacy))
        #expect(try JSONDecoder().decode(ProviderConsentState.self, from: persisted) == migrated)
    }

    @Test func schemaTwoConsentIsMigratedByRevokingAuthenticationAmbiguousGrants() throws {
        let name = "ProviderConsentStoreTests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let legacy = Data(#"{"schemaVersion":2,"activeProvider":"gateway","grants":[{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"gateway.example.test","port":443},"credentialReference":"GATEWAY_API_KEY"}]}"#.utf8)
        defaults.set(legacy, forKey: ProviderConsentStore.stateKey)

        let migrated = try ProviderConsentStore(defaults: defaults).load()
        #expect(migrated.schemaVersion == ProviderConsentState.currentSchemaVersion)
        #expect(migrated.activeProvider == nil)
        #expect(migrated.grants.isEmpty)
        let persisted = try #require(defaults.data(forKey: ProviderConsentStore.stateKey))
        #expect(!persisted.elementsEqual(legacy))
        #expect(try JSONDecoder().decode(ProviderConsentState.self, from: persisted) == migrated)
    }

    @Test func persistsOneActiveRouteAndRetainsEndpointBoundGrant() throws {
        let name = "ProviderConsentStoreTests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let store = ProviderConsentStore(defaults: defaults)
        let openAI = BuiltInProviderDescriptors.openAI

        let state = try store.activate(openAI)
        #expect(state.activeProvider == openAI.id)
        #expect(state.activeGrant(for: openAI.id)?.origin?.host == "api.openai.com")
        #expect(try store.load() == state)

        let local = try store.activate(BuiltInProviderDescriptors.ollama)
        #expect(local.activeProvider == BuiltInProviderDescriptors.ollama.id)
        #expect(local.activeGrant(for: BuiltInProviderDescriptors.ollama.id)?.boundary == .onDevice)
    }

    @Test func everyExistingProfileEditQuiescesBeforeAnInactiveProfileCanBecomeActive() throws {
        let name = "ProviderConsentStoreTests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let store = ProviderConsentStore(defaults: defaults)
        let active = BuiltInProviderDescriptors.openAICompatible(
            id: ProviderID("active-custom"), displayName: "Active",
            baseURL: URL(string: "https://active.example.test/v1")!, boundary: .cloud
        )
        _ = try store.activate(active)
        let selected = ModelSelection(route: ModelRoute(provider: active.id, model: ModelID("model")))

        try store.deactivate(active.id)
        let revoked = try store.load()
        #expect(revoked.activeProvider == nil)
        #expect(revoked.grants.isEmpty)
        #expect(ProviderEgressPolicy.allowedOrigins(selection: selected, consent: revoked).isEmpty)
    }

    @Test @MainActor
    func existingProfileMutationCannotStartBeforeTheAsyncQuiescenceBarrier() async throws {
        let probe = CustomProviderMutationBarrierProbe()
        let task = Task { @MainActor in
            try await ProviderStateMutationSafetyPolicy.performMutation(
                targetProvider: ProviderID("inactive-custom"),
                prepare: { await probe.prepare($0) },
                mutation: {
                    probe.mutationStarted = true
                    return 7
                }
            )
        }
        for _ in 0..<100 where !probe.preparationEntered { await Task.yield() }
        #expect(probe.preparationEntered)
        #expect(!probe.mutationStarted)
        probe.release()
        #expect(try await task.value == 7)
        #expect(probe.mutationStarted)
    }

    @Test func corruptOrFutureConsentFailsClosed() throws {
        let name = "ProviderConsentStoreTests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let store = ProviderConsentStore(defaults: defaults)
        defaults.set("not-data", forKey: ProviderConsentStore.stateKey)
        #expect(throws: ProviderConsentStoreError.invalidStoredType) { try store.load() }

        defaults.set(Data(#"{"schemaVersion":99,"activeProvider":null,"grants":[]}"#.utf8), forKey: ProviderConsentStore.stateKey)
        #expect(throws: DecodingError.self) { try store.load() }
    }
}
