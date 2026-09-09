import Foundation

enum WorkspaceReadOnlyReason: String, Codable, Equatable, Sendable {
    case recoverabilityLimit
    case recoveryDeadline

    var userMessage: String {
        switch self {
        case .recoverabilityLimit:
            return "This workspace is larger than Fulmar's bounded recovery journal. Chat and read/search tools remain available; every workspace-changing tool and subagent is blocked for this turn."
        case .recoveryDeadline:
            return "The recovery scan could not finish within its safety deadline. Chat and read/search tools remain available; every workspace-changing tool and subagent is blocked for this turn."
        }
    }
}

enum WorkspaceTurnProtection: Equatable, Sendable {
    case checkpoint(WorkspaceCheckpointSummary, reused: Bool)
    case readOnly(WorkspaceReadOnlyReason)

    var checkpoint: WorkspaceCheckpointSummary? {
        if case .checkpoint(let checkpoint, _) = self { return checkpoint }
        return nil
    }

    var isReadOnly: Bool {
        if case .readOnly = self { return true }
        return false
    }

    var userMessage: String? {
        if case .readOnly(let reason) = self { return reason.userMessage }
        return nil
    }
}

/// Serialises automatic recovery points around agent turns while leaving
/// manually named checkpoints under the user's control. Automatic entries are
/// rotated first and are never allowed to evict a manual checkpoint.
actor WorkspaceRecoveryCoordinator {
    private let journal: WorkspaceChangeJournal
    private let policy: WorkspaceMutationPolicyStore
    private let maximumAutomaticCheckpoints: Int
    private let maximumTotalCheckpoints: Int

    init(
        journal: WorkspaceChangeJournal,
        policy: WorkspaceMutationPolicyStore,
        maximumAutomaticCheckpoints: Int = 12,
        maximumTotalCheckpoints: Int = 24
    ) {
        precondition(maximumAutomaticCheckpoints > 0)
        precondition(maximumTotalCheckpoints >= maximumAutomaticCheckpoints)
        self.journal = journal
        self.policy = policy
        self.maximumAutomaticCheckpoints = maximumAutomaticCheckpoints
        self.maximumTotalCheckpoints = maximumTotalCheckpoints
    }

    /// Returns read-only protection only for a typed bounded-recoverability
    /// condition. Corrupt storage, an unstable workspace and authentication
    /// failures still block the prompt. The policy is closed before scanning,
    /// so neither cancellation nor an error can inherit an earlier write grant.
    func captureBeforeTurn(
        reason: String,
        cancellation: WorkspaceJournalOperationCancellation = WorkspaceJournalOperationCancellation()
    ) throws -> WorkspaceTurnProtection {
        try policy.requireCheckpoint()
        do {
            try cancellation.check()
            let fingerprint = try journal.currentMetadataFingerprint(cancellation: cancellation)
            let checkpoints = try journal.listCheckpoints(cancellation: cancellation)
            let automatic = checkpoints
                .filter { $0.origin == .automatic }
                .sorted { $0.createdAt < $1.createdAt }

            if let reusable = automatic.last,
               reusable.metadataFingerprint == fingerprint {
                try cancellation.check()
                try policy.allowProtectedMutation()
                return .checkpoint(reusable, reused: true)
            }

            let mustRotate = automatic.count >= maximumAutomaticCheckpoints ||
                checkpoints.count >= maximumTotalCheckpoints
            if mustRotate, automatic.isEmpty {
                throw WorkspaceJournalError.checkpointLimitExceeded(maximum: maximumTotalCheckpoints)
            }

            let label = Self.automaticPrefix + Self.safeLabel(reason)
            let checkpoint: WorkspaceCheckpoint
            do {
                checkpoint = try journal.captureCheckpoint(
                    label: label,
                    origin: .automatic,
                    replacing: mustRotate ? automatic.first?.id : nil,
                    expectedMetadataFingerprint: fingerprint,
                    cancellation: cancellation
                )
            } catch let journalError as WorkspaceJournalError {
                switch journalError {
                case .storedByteLimitExceeded, .checkpointLimitExceeded:
                    let latestOldest = try journal.listCheckpoints(cancellation: cancellation)
                        .filter { $0.origin == .automatic }
                        .min { $0.createdAt < $1.createdAt }
                    guard let latestOldest else { throw journalError }
                    checkpoint = try journal.captureCheckpoint(
                        label: label,
                        origin: .automatic,
                        replacing: latestOldest.id,
                        expectedMetadataFingerprint: fingerprint,
                        cancellation: cancellation
                    )
                default:
                    throw journalError
                }
            }
            try cancellation.check()
            let summary = WorkspaceCheckpointSummary(
                id: checkpoint.id,
                createdAt: checkpoint.createdAt,
                label: checkpoint.label,
                origin: .automatic,
                fileCount: checkpoint.files.count,
                totalBytes: checkpoint.totalBytes,
                metadataFingerprint: checkpoint.metadataFingerprint
            )
            try policy.allowProtectedMutation()
            return .checkpoint(summary, reused: false)
        } catch let error as WorkspaceJournalError {
            guard let reason = Self.readOnlyReason(for: error) else { throw error }
            try cancellation.check()
            switch reason {
            case .recoverabilityLimit:
                try policy.requireReadOnly(reason: .recoverabilityLimit)
            case .recoveryDeadline:
                try policy.requireReadOnly(reason: .recoveryDeadline)
            }
            return .readOnly(reason)
        }
    }

    private static func readOnlyReason(for error: WorkspaceJournalError) -> WorkspaceReadOnlyReason? {
        switch error {
        case .scanDeadlineExceeded:
            return .recoveryDeadline
        case .checkpointLimitExceeded,
             .storedByteLimitExceeded,
             .fileCountLimitExceeded,
             .entryCountLimitExceeded,
             .totalByteLimitExceeded,
             .fileTooLarge,
             .depthLimitExceeded,
             .relativePathByteLimitExceeded:
            return .recoverabilityLimit
        case .invalidLimits, .invalidWorkspace, .workspaceRootChanged,
             .unsafeStorage, .unsafeCheckpoint, .checkpointNotFound,
             .cancelled, .workspaceChangedDuringScan, .stalePreview,
             .restoreConflicts, .checkpointContentCorrupt, .restoreFailed,
             .rollbackFailed:
            return nil
        }
    }

    private static let automaticPrefix = "Automatic · "

    private static func safeLabel(_ value: String) -> String {
        let scalars = value.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0) && $0.value != 0x7F
        }
        let trimmed = String(String.UnicodeScalarView(scalars))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Before agent turn" : String(trimmed.prefix(120))
    }
}
