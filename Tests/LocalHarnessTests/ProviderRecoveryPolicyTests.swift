import Testing
@testable import LocalHarness

@Test
func installedLocalModelRecoveryIsAvailableOnlyForTypedLocalFailures() {
    let local = ProviderRecoveryContext.localModelSelectionRequired("Configured model is missing")
    #expect(local.allowsInstalledLocalModelChoice)
    #expect(local.userMessage.contains("Choose an installed tool-capable local model"))

    let generic = ProviderRecoveryContext.routeVerification("Cloud consent is missing")
    #expect(!generic.allowsInstalledLocalModelChoice)
}

@Test
func undersizedHostRecoveryExplainsExplicitProviderChoiceWithoutClaimingOllamaRepair() {
    let context = ProviderRecoveryContext.ollamaPrerequisite(
        .insufficientPhysicalMemory(
            requiredBytes: QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes,
            availableBytes: 8 * 1_073_741_824
        )
    )

    #expect(context.allowsInstalledLocalModelChoice)
    #expect(context.userMessage.contains("not supported on this Mac"))
    #expect(context.userMessage.contains("explicitly configure and consent"))
    #expect(context.userMessage.contains("Models & Providers"))
    #expect(!context.userMessage.contains("repair Ollama"))
}

@Test
func topologyStagesDoNotOfferLocalRepairAcrossTrustBoundaries() {
    let repairable: [ProviderTopologyVerificationStage] = [
        .resolveOwnedOllamaEndpoint,
        .inspectInstalledLocalModels,
        .synchronizeLocalProvider,
        .validateSelectedRoute,
        .synchronizeLocalPerformance,
        .reloadLocalProviderCatalog,
    ]
    let notRepairable: [ProviderTopologyVerificationStage] = [
        .loadSelection,
        .validateLocalRuntimeVersion,
        .loadProviderCatalog,
        .validateOnDeviceBoundary,
        .recordEndpointConsent,
        .validateExternalConsent,
        .synchronizeDefaultRoute,
    ]

    #expect(repairable.allSatisfy { $0.allowsInstalledLocalModelChoice })
    #expect(notRepairable.allSatisfy { !$0.allowsInstalledLocalModelChoice })
}

@Test
func topologyFailureCarriesThePrecomputedRecoveryCapability() {
    let failure = ProviderTopologyVerificationFailure(
        stage: .inspectInstalledLocalModels,
        reason: "Configured model is absent",
        allowsInstalledLocalModelChoice: true
    )
    #expect(failure.allowsInstalledLocalModelChoice)
    #expect(failure.localizedDescription.contains("Checking installed Ollama models failed"))
}

@Test
func onlyTheExactValueFreeCredentialAttentionMarkerOffersForegroundRepair() {
    let marker = HarnessCredentialView(
        configured: false,
        source: ProviderCredentialRecoveryPresentation.foregroundRecoverySource,
        writable: false
    )
    #expect(ProviderCredentialRecoveryPresentation.requiresForegroundRepair(marker))

    for state in [
        HarnessCredentialView(configured: true, source: marker.source, writable: false),
        HarnessCredentialView(configured: false, source: marker.source, writable: true),
        HarnessCredentialView(configured: false, source: "macOS Keychain", writable: false),
        nil,
    ] {
        #expect(!ProviderCredentialRecoveryPresentation.requiresForegroundRepair(state))
    }
}

@Test func recordRecoveryOffersOnlySafeActionsForEachValueFreeReason() {
    #expect(ProviderRecordRecoveryPresentation.actions(for: .authorization) == [.authorizeExisting])
    #expect(ProviderRecordRecoveryPresentation.actions(for: .ambiguous) == [.adoptCurrent, .remove])
    #expect(ProviderRecordRecoveryPresentation.actions(for: .invalid) == [.remove])
    #expect(ProviderRecordRecoveryPresentation.reasonLabel(.authorization).contains("authorization"))
    #expect(ProviderRecordRecoveryPresentation.reasonLabel(.ambiguous).contains("Interrupted"))
    #expect(ProviderRecordRecoveryPresentation.reasonLabel(.invalid).contains("invalid"))
}
