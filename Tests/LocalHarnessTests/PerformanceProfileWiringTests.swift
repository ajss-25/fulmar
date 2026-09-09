import Foundation
import Testing
@testable import LocalHarness

@Suite("Performance profile wiring")
struct PerformanceProfileWiringTests {
    @Test("Performance session identities round-trip exact profiles")
    func sessionIdentityRoundTrip() {
        let uuid = UUID(uuidString: "12345678-1234-4abc-8def-1234567890ab")!
        for profile in PerformanceProfile.allCases {
            let identity = PerformanceSessionIdentity.make(profile: profile, uuid: uuid)
            #expect(identity.rawValue == "local-harness-performance-v1-\(profile.rawValue)-12345678-1234-4abc-8def-1234567890ab")
            #expect(PerformanceSessionIdentity.profile(from: identity) == profile)
        }
        #expect(PerformanceSessionIdentity.profile(from: HarnessSessionID("ordinary-session")) == nil)
        #expect(PerformanceSessionIdentity.profile(from: HarnessSessionID(
            "local-harness-performance-v1-unknown-12345678-1234-4abc-8def-1234567890ab"
        )) == nil)
        #expect(PerformanceSessionIdentity.profile(from: HarnessSessionID(
            "local-harness-performance-v1-fast-not-a-uuid"
        )) == nil)
    }

    @Test("Runtime catalog is generated from every typed preset")
    func runtimeCatalogMatchesPresets() throws {
        struct Entry: Decodable, Equatable {
            let maxOutputTokens: Int
        }
        let catalog = try JSONDecoder().decode(
            [String: Entry].self,
            from: Data(PerformanceProfile.runtimeCatalogJSON.utf8)
        )
        #expect(Set(catalog.keys) == Set(PerformanceProfile.allCases.map(\.rawValue)))
        for profile in PerformanceProfile.allCases {
            let settings = profile.settingsFor48GBAppleSilicon
            #expect(catalog[profile.rawValue] == Entry(
                maxOutputTokens: settings.maxOutputTokens
            ))
        }
    }

    @Test("Fresh-session gate stays latched across failure and stale callbacks")
    func freshSessionGateIsFailClosed() {
        let first = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
        let second = UUID(uuidString: "00000000-0000-4000-8000-000000000002")!
        var state = FreshSessionRequirementState()
        #expect(state.permitsTurnPreparation)

        state.require()
        #expect(!state.permitsTurnPreparation)
        #expect(state.begin(attempt: first) == first)
        #expect(state.begin(attempt: second) == nil)
        let firstFailed = state.fail(first)
        #expect(firstFailed)
        #expect(state.isRequired)
        #expect(state.activeAttempt == nil)
        #expect(!state.permitsTurnPreparation)

        #expect(state.begin(attempt: second) == second)
        let staleSucceeded = state.succeed(first)
        #expect(!staleSucceeded)
        #expect(state.isRequired)
        #expect(state.activeAttempt == second)
        let secondSucceeded = state.succeed(second)
        #expect(secondSucceeded)
        #expect(!state.isRequired)
        #expect(state.activeAttempt == nil)
        #expect(state.permitsTurnPreparation)
    }

    @Test("Endpoint replacement invalidates only the attempt, never the requirement")
    func freshSessionGateInvalidation() {
        let attempt = UUID(uuidString: "00000000-0000-4000-8000-000000000003")!
        var state = FreshSessionRequirementState()
        state.require()
        #expect(!state.permitsTurnPreparation)
        #expect(state.begin(attempt: attempt) == attempt)
        state.invalidateAttempt()
        #expect(state.isRequired)
        #expect(state.activeAttempt == nil)
        #expect(!state.permitsTurnPreparation)
        let staleSucceeded = state.succeed(attempt)
        #expect(!staleSucceeded)
    }
}
