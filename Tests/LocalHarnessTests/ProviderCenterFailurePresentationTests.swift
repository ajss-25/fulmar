import Foundation
import Testing
@testable import LocalHarness

private struct HostileProviderCenterPresentationError: LocalizedError {
    var errorDescription: String? {
        let credential = ["sk", "provider-center", String(repeating: "Z", count: 48)].joined(separator: "-")
        return "PROVIDER_CENTER_PRIVATE_CANARY \(credential) /Users/private/Fulmar/state.json\n\u{001B}[31m"
            + String(repeating: "X", count: 32_000)
    }
}

@Test(arguments: ProviderCenterFailureContext.allCases)
func providerCenterEveryCatchFamilyRejectsArbitraryLocalizedProviderText(
    context: ProviderCenterFailureContext
) {
    let message = ProviderCenterFailurePresentation.message(
        for: HostileProviderCenterPresentationError(),
        context: context
    )

    #expect(!message.contains("PROVIDER_CENTER_PRIVATE_CANARY"))
    #expect(!message.contains("sk-provider-center"))
    #expect(!message.contains("/Users/private"))
    #expect(!message.contains("\u{001B}"))
    #expect(message.unicodeScalars.count <= ProviderCenterFailurePresentation.maximumMessageCharacters)
    #expect(!message.isEmpty)
}

@Test func providerCenterKnownAppOwnedFailuresRetainActionableBoundedReasons() {
    let recovery = ProviderCenterFailurePresentation.message(
        for: ProviderCredentialRecoveryFailure.authorizationRequired,
        context: .credentialRecovery
    )
    #expect(recovery.contains("macOS did not authorize"))
    #expect(recovery.contains("Credential Records"))

    let activation = ProviderCenterFailurePresentation.message(
        for: ProviderActivationTransactionError(
            cause: .credentialRequired,
            rollbackComplete: true
        ),
        context: .providerActivation
    )
    #expect(activation.contains("Enter an API key"))
    #expect(activation.contains("previous verified provider state"))

    let profile = ProviderCenterFailurePresentation.message(
        for: CustomProviderProfileFailure.invalidEndpoint,
        context: .customProfileValidation
    )
    #expect(profile.contains("Enter an HTTPS base URL"))
    #expect(profile.contains("literal loopback or private-network address"))
    #expect(profile.contains("User info, query parameters, and fragments are not allowed"))

    let performance = ProviderCenterFailurePresentation.message(
        for: ProtectedRuntimeMutationCoordinatorError.transitionFailed(.coordinationUnavailable),
        context: .performanceProfile
    )
    #expect(performance.contains("Protected runtime coordination is unavailable"))

    for message in [recovery, activation, profile, performance] {
        #expect(message.unicodeScalars.count <= ProviderCenterFailurePresentation.maximumMessageCharacters)
    }
}
