import Foundation
import Testing
@testable import LocalHarness

private enum CredentialMutationFixtureError: Error {
    case responseLost
    case unavailable
}

private actor CredentialMutationFixture: HarnessProviderCredentialServicing {
    enum MutationBehavior {
        case succeed
        case applyThenThrow
        case throwWithoutApplying
    }

    var configured: Bool
    var behavior: MutationBehavior
    var describeFails = false

    init(configured: Bool, behavior: MutationBehavior) {
        self.configured = configured
        self.behavior = behavior
    }

    func describeCredentials(_ references: [CredentialReference]) async throws -> HarnessCredentialDescription {
        if describeFails { throw CredentialMutationFixtureError.unavailable }
        return HarnessCredentialDescription(credentials: Dictionary(uniqueKeysWithValues: references.map {
            ($0.rawValue, HarnessCredentialView(configured: configured, source: "fixture", writable: true))
        }))
    }

    func setCredential(_ reference: CredentialReference, value: String) async throws {
        switch behavior {
        case .succeed: configured = true
        case .applyThenThrow:
            configured = true
            throw CredentialMutationFixtureError.responseLost
        case .throwWithoutApplying:
            throw CredentialMutationFixtureError.responseLost
        }
    }

    func unsetCredential(_ reference: CredentialReference) async throws {
        switch behavior {
        case .succeed: configured = false
        case .applyThenThrow:
            configured = false
            throw CredentialMutationFixtureError.responseLost
        case .throwWithoutApplying:
            throw CredentialMutationFixtureError.responseLost
        }
    }

    func failDescribe() { describeFails = true }
}

@Test
func credentialReplacementNeverClaimsWhichWriteOnlyValueWonAfterResponseLoss() async {
    let fixture = CredentialMutationFixture(configured: true, behavior: .applyThenThrow)
    let verifier = ProviderCredentialMutationVerifier(service: fixture)
    let assessment = await verifier.mutate(
        reference: CredentialReference("DEEPSEEK_API_KEY"),
        value: "replacement"
    )
    #expect(assessment == .init(action: .replace, disposition: .uncertain, configured: true))
    #expect(assessment.requiresRuntimeRestartWhenActive)
}

@Test
func acknowledgedCredentialReplacementStillRequiresAnActiveRuntimeRestart() async {
    let fixture = CredentialMutationFixture(configured: true, behavior: .succeed)
    let assessment = await ProviderCredentialMutationVerifier(service: fixture).mutate(
        reference: CredentialReference("DEEPSEEK_API_KEY"),
        value: "replacement"
    )
    #expect(assessment == .init(action: .replace, disposition: .verifiedApplied, configured: true))
    #expect(assessment.requiresRuntimeRestartWhenActive)
}

@Test
func credentialRemovalReconcilesApplyThenThrowAndNotAppliedOutcomes() async {
    let appliedFixture = CredentialMutationFixture(configured: true, behavior: .applyThenThrow)
    let applied = await ProviderCredentialMutationVerifier(service: appliedFixture).mutate(
        reference: CredentialReference("OPENAI_API_KEY"), value: nil
    )
    #expect(applied == .init(action: .remove, disposition: .appliedAfterAmbiguousResponse, configured: false))
    #expect(applied.requiresRuntimeRestartWhenActive)

    let retainedFixture = CredentialMutationFixture(configured: true, behavior: .throwWithoutApplying)
    let retained = await ProviderCredentialMutationVerifier(service: retainedFixture).mutate(
        reference: CredentialReference("OPENAI_API_KEY"), value: nil
    )
    #expect(retained == .init(action: .remove, disposition: .confirmedNotApplied, configured: true))
    #expect(!retained.requiresRuntimeRestartWhenActive)
}

@Test
func credentialMutationFailsClosedWhenReadinessCannotBeRedescribed() async {
    let fixture = CredentialMutationFixture(configured: true, behavior: .succeed)
    await fixture.failDescribe()
    let assessment = await ProviderCredentialMutationVerifier(service: fixture).mutate(
        reference: CredentialReference("ANTHROPIC_API_KEY"), value: nil
    )
    #expect(assessment == .init(action: .remove, disposition: .uncertain, configured: nil))
    #expect(assessment.requiresRuntimeRestartWhenActive)
}
