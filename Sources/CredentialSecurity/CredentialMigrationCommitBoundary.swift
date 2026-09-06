import Foundation

public enum CredentialMigrationCommitCheckpoint: String, CaseIterable, Sendable {
    case preparedReceiptDurable
    case sourceTruncated
    case sourceSynchronized
    case scrubbedReceiptDurable
}

public enum CredentialMigrationCommitOutcome: Equatable, Sendable {
    case success
    case recoveryRequired
}

/// Encodes the one-way plaintext scrub boundary. Everything through the
/// truncate closure is reversible by the caller's Keychain batch and may
/// throw. Once truncate returns successfully, no error is allowed to unwind
/// into that rollback: a durable prepared receipt plus the zero tombstone is
/// instead recovered and reverified on the next launch.
public enum CredentialMigrationCommitBoundary {
    public typealias Checkpoint = (CredentialMigrationCommitCheckpoint) throws -> Void

    public static func commit(
        receiptStore: CredentialMigrationReceiptStore,
        preparedReceipt: CredentialMigrationReceipt,
        validateBeforeScrub: () throws -> Void,
        truncate: () throws -> Void,
        synchronizeAndValidateScrubbedSource: () throws -> Void,
        checkpoint: Checkpoint = { _ in }
    ) throws -> CredentialMigrationCommitOutcome {
        guard preparedReceipt.phase == .prepared else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        try validateBeforeScrub()
        try receiptStore.write(preparedReceipt)
        try checkpoint(.preparedReceiptDurable)
        try validateBeforeScrub()
        try truncate()

        do {
            try checkpoint(.sourceTruncated)
            try synchronizeAndValidateScrubbedSource()
            try checkpoint(.sourceSynchronized)
            try receiptStore.write(preparedReceipt.replacingPhase(.scrubbed))
            try checkpoint(.scrubbedReceiptDurable)
            return .success
        } catch {
            return .recoveryRequired
        }
    }

    /// Completes the prepared-receipt crash window only after the caller has
    /// independently rebound the zero source and reverified every current
    /// Keychain value digest. This function itself never reads credential data.
    public static func finalizePreparedReceipt(
        _ receipt: CredentialMigrationReceipt,
        receiptStore: CredentialMigrationReceiptStore,
        synchronizeAndValidateScrubbedSource: () throws -> Void
    ) throws -> CredentialMigrationReceipt {
        guard receipt.phase == .prepared else { return receipt }
        try synchronizeAndValidateScrubbedSource()
        let scrubbed = receipt.replacingPhase(.scrubbed)
        try receiptStore.write(scrubbed)
        return scrubbed
    }
}
