import Foundation

enum StartupCredentialMigrationCoordinatorError: Error, Equatable, LocalizedError {
    case contentionTimedOut

    var errorDescription: String? {
        switch self {
        case .contentionTimedOut:
            return "Another verified Fulmar process is still protecting the credential migration. The runtime remained stopped; retry after that process finishes."
        }
    }
}

/// Keeps a second startup process behind the same fail-closed credential
/// boundary while the process which owns the persistent migration lease
/// finishes. A lease loser must never treat `migrationInProgress` as an
/// ordinary migration failure and continue into DSH with the plaintext source
/// still present.
@MainActor
enum StartupCredentialMigrationCoordinator {
    static let defaultMaximumContentionRetries = 240
    static let defaultRetryDelayNanoseconds: UInt64 = 250_000_000

    typealias MigrationAttempt = @MainActor @Sendable () async throws
        -> CredentialMigrationResult
    typealias Sleeper = @MainActor @Sendable (UInt64) async throws -> Void

    static func migrateAfterVerifiedLeaseSettlement(
        maximumContentionRetries: Int = 240,
        retryDelayNanoseconds: UInt64 = 250_000_000,
        sleep: @escaping Sleeper = { delay in
            try await Task.sleep(nanoseconds: delay)
        },
        attempt: @escaping MigrationAttempt
    ) async throws -> CredentialMigrationResult {
        precondition(maximumContentionRetries >= 0)
        precondition(retryDelayNanoseconds > 0)

        var contentionRetries = 0
        while true {
            do {
                return try await attempt()
            } catch CredentialMigrationError.migrationInProgress {
                guard contentionRetries < maximumContentionRetries else {
                    throw StartupCredentialMigrationCoordinatorError.contentionTimedOut
                }
                contentionRetries += 1
                try await sleep(retryDelayNanoseconds)
            } catch {
                throw error
            }
        }
    }
}
