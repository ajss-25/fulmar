import Foundation
import Testing
@testable import LocalHarness

private struct HostileProviderSelectionError: LocalizedError {
    let errorDescription: String?
}

@Suite("Provider selection failure presentation")
struct ProviderSelectionFailurePresentationTests {
    private func presented(_ cause: Error, rollbackComplete: Bool = true) -> String {
        ProviderSelectionFailurePresentation.message(for: ProviderSelectionTransactionError(
            cause: cause,
            rollbackComplete: rollbackComplete
        ))
    }

    @Test("Rollback-complete failures preserve safe actionable typed reasons")
    func actionableTypedReasons() {
        let readOnly = presented(ModelSelectionCoordinatorError.settingsReadOnly)
        #expect(readOnly.contains("previous route remains active"))
        #expect(readOnly.contains("default-model settings are read-only"))

        let origin = presented(ProviderConsentStoreError.unresolvedExternalEndpoint)
        #expect(origin.contains("previous route remains active"))
        #expect(origin.contains("endpoint could not be normalized"))

        let timeout = presented(HarnessRPCClientError.timedOut)
        #expect(timeout.contains("previous route remains active"))
        #expect(timeout.contains("timed out while verifying"))

        let cancelled = presented(CancellationError())
        #expect(cancelled.contains("previous route remains active"))
        #expect(cancelled.contains("cancelled before it completed"))

        let credential = presented(ProviderActivationTransactionError(
            cause: .credentialRequired,
            rollbackComplete: true
        ))
        #expect(credential.contains("previous route remains active"))
        #expect(credential.contains("credential is not ready"))

        let rejected = presented(HarnessRPCClientError.remote(.init(
            code: .credentialRejected,
            message: "untrusted provider detail",
            details: [:]
        )))
        #expect(rejected.contains("previous route remains active"))
        #expect(rejected.contains("credential was rejected"))
        #expect(!rejected.contains("untrusted provider detail"))
    }

    @Test("Hostile arbitrary errors and incomplete rollback never expose raw text")
    func hostileErrorsAreClosed() {
        let credential = ["sk", "hostile", String(repeating: "z", count: 32)].joined(separator: "-")
        let raw = "\u{001B}[2Jpassword=\(credential)\u{0000}" + String(repeating: "X", count: 2 * 1_024 * 1_024)
        let safe = presented(HostileProviderSelectionError(errorDescription: raw))
        #expect(safe.contains("previous route remains active"))
        #expect(safe.contains("could not safely verify"))
        #expect(!safe.contains(credential))
        #expect(!safe.contains("\u{001B}"))
        #expect(safe.utf8.count < 256)

        let transactionDescription = ProviderSelectionTransactionError(
            cause: HostileProviderSelectionError(errorDescription: raw),
            rollbackComplete: true
        ).localizedDescription
        #expect(transactionDescription == safe)
        #expect(!transactionDescription.contains(credential))
        #expect(!transactionDescription.contains("\u{001B}"))
        #expect(transactionDescription.utf8.count < 256)

        let incomplete = presented(HostileProviderSelectionError(errorDescription: raw), rollbackComplete: false)
        #expect(incomplete.contains("rollback was incomplete"))
        #expect(incomplete.contains("Network access remains blocked"))
        #expect(!incomplete.contains(credential))
    }
}
