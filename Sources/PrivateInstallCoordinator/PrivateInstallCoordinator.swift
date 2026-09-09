import AppKit
import CryptoKit
import Darwin
import Foundation
import LocalHarnessAtomicInstallSwap

public struct PrivateInstallBundleProof: Codable, Equatable, Sendable {
    public let identity: AtomicInstallIdentity
    public let treeSHA256Hex: String
    public let attestation: PrivateStableApplicationAttestation

    public init(
        identity: AtomicInstallIdentity,
        treeSHA256Hex: String,
        attestation: PrivateStableApplicationAttestation
    ) {
        self.identity = identity
        self.treeSHA256Hex = treeSHA256Hex
        self.attestation = attestation
    }
}

public struct PrivateInstallCoordinatorReceipt: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schemaVersion: Int
    public let nonce: String
    public let committedAtUnixSeconds: UInt64
    public let installed: PrivateInstallBundleProof
    public let retainedRollback: PrivateInstallBundleProof

    public init(
        nonce: String,
        committedAtUnixSeconds: UInt64,
        installed: PrivateInstallBundleProof,
        retainedRollback: PrivateInstallBundleProof
    ) {
        schemaVersion = Self.schemaVersion
        self.nonce = nonce
        self.committedAtUnixSeconds = committedAtUnixSeconds
        self.installed = installed
        self.retainedRollback = retainedRollback
    }
}

public enum PrivateInstallJournalPhase: String, Codable, Equatable, Sendable {
    /// The candidate has been copied and fully proven, but the APFS exchange
    /// has not yet been requested. The journal is immutable after this point;
    /// recovery derives the current phase from the bound inode/tree/signature
    /// proofs instead of trusting a mutable flag after a process interruption.
    case preparedForAtomicSwap
}

public struct PrivateInstallRecoveryJournal: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schemaVersion: Int
    public let phase: PrivateInstallJournalPhase
    public let nonce: String
    public let preparedAtUnixSeconds: UInt64
    public let originalInstalled: PrivateInstallBundleProof
    public let frozenCandidate: PrivateInstallBundleProof
    public let stagedCandidate: PrivateInstallBundleProof

    public init(
        nonce: String,
        preparedAtUnixSeconds: UInt64,
        originalInstalled: PrivateInstallBundleProof,
        frozenCandidate: PrivateInstallBundleProof,
        stagedCandidate: PrivateInstallBundleProof
    ) {
        schemaVersion = Self.schemaVersion
        phase = .preparedForAtomicSwap
        self.nonce = nonce
        self.preparedAtUnixSeconds = preparedAtUnixSeconds
        self.originalInstalled = originalInstalled
        self.frozenCandidate = frozenCandidate
        self.stagedCandidate = stagedCandidate
    }
}

public enum PrivateInstallPreparationPhase: String, Codable, Equatable, Sendable {
    case preparedForStaging
}

/// Immutable intent committed before the first stage-path mutation. It binds
/// the only stage leaf this transaction may create and the complete source
/// proofs from which a missing final pre-swap journal can be reconstructed.
public struct PrivateInstallPreparationJournal: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schemaVersion: Int
    public let phase: PrivateInstallPreparationPhase
    public let nonce: String
    public let stageLeaf: String
    public let preparedAtUnixSeconds: UInt64
    public let originalInstalled: PrivateInstallBundleProof
    public let frozenCandidate: PrivateInstallBundleProof

    public init(
        nonce: String,
        stageLeaf: String,
        preparedAtUnixSeconds: UInt64,
        originalInstalled: PrivateInstallBundleProof,
        frozenCandidate: PrivateInstallBundleProof
    ) {
        schemaVersion = Self.schemaVersion
        phase = .preparedForStaging
        self.nonce = nonce
        self.stageLeaf = stageLeaf
        self.preparedAtUnixSeconds = preparedAtUnixSeconds
        self.originalInstalled = originalInstalled
        self.frozenCandidate = frozenCandidate
    }
}

public struct PrivateInstallOpaqueStageIdentity: Codable, Equatable, Sendable {
    public let identity: AtomicInstallIdentity
    public let mode: UInt32
    public let group: UInt32
    public let linkCount: UInt64

    public init(identity: AtomicInstallIdentity, mode: UInt32, group: UInt32, linkCount: UInt64) {
        self.identity = identity
        self.mode = mode
        self.group = group
        self.linkCount = linkCount
    }
}

public struct PrivateInstallAbandonmentJournal: Codable, Equatable, Sendable {
    public static let schemaVersion = 1
    public let schemaVersion: Int
    public let nonce: String
    public let preparedAtUnixSeconds: UInt64
    public let preparation: PrivateInstallPreparationJournal
    public let activeInstalled: PrivateInstallBundleProof
    public let opaqueStage: PrivateInstallOpaqueStageIdentity?

    public init(
        nonce: String,
        preparedAtUnixSeconds: UInt64,
        preparation: PrivateInstallPreparationJournal,
        activeInstalled: PrivateInstallBundleProof,
        opaqueStage: PrivateInstallOpaqueStageIdentity?
    ) {
        schemaVersion = Self.schemaVersion
        self.nonce = nonce
        self.preparedAtUnixSeconds = preparedAtUnixSeconds
        self.preparation = preparation
        self.activeInstalled = activeInstalled
        self.opaqueStage = opaqueStage
    }
}

public enum PrivateInstallLifecycleOperation: String, Codable, Equatable, Sendable {
    case cancelOriginalActive
    case retireCommitted
}

/// Immutable intent written before a retained stage or its records are moved.
/// The marker binds both bundles and every transaction record, so a later
/// process can replay either rename without trusting path names or mutable
/// phase flags.
public struct PrivateInstallLifecycleJournal: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schemaVersion: Int
    public let operation: PrivateInstallLifecycleOperation
    public let nonce: String
    public let preparedAtUnixSeconds: UInt64
    public let activeInstalled: PrivateInstallBundleProof
    public let retainedStage: PrivateInstallBundleProof
    public let recoveryJournal: PrivateInstallRecoveryJournal?
    public let receipt: PrivateInstallCoordinatorReceipt?

    public init(
        operation: PrivateInstallLifecycleOperation,
        nonce: String,
        preparedAtUnixSeconds: UInt64,
        activeInstalled: PrivateInstallBundleProof,
        retainedStage: PrivateInstallBundleProof,
        recoveryJournal: PrivateInstallRecoveryJournal?,
        receipt: PrivateInstallCoordinatorReceipt?
    ) {
        schemaVersion = Self.schemaVersion
        self.operation = operation
        self.nonce = nonce
        self.preparedAtUnixSeconds = preparedAtUnixSeconds
        self.activeInstalled = activeInstalled
        self.retainedStage = retainedStage
        self.recoveryJournal = recoveryJournal
        self.receipt = receipt
    }
}

public enum PrivateInstallRecoveryState: String, Codable, Equatable, Sendable {
    case none
    case stagingPrepared
    case stagedAwaitingJournal
    case stagingInterrupted
    case abandonmentPrepared
    case abandonmentArchived
    case committed
    case originalActive
    case swappedAwaitingCommit
    case cancellationPrepared
    case cancellationArchived
    case retirementPrepared
    case retirementArchived
}

@_spi(PrivateInstallCrashProbe)
public enum PrivateInstallRecordPersistenceBoundary: String, Sendable {
    case afterTemporaryCreate
    case afterPartialFileSync
    case afterCompleteFileSync
    case beforeExclusiveRename
    case afterRenameBeforeDirectorySync
}

public struct PrivateInstallRecoveryInspection: Equatable, Sendable {
    public let preparationJournal: PrivateInstallPreparationJournal?
    public let state: PrivateInstallRecoveryState
    public let journal: PrivateInstallRecoveryJournal?
    public let receipt: PrivateInstallCoordinatorReceipt?
    public let lifecycleJournal: PrivateInstallLifecycleJournal?
    public let stagePath: String?
    public let archivePath: String?
    public let candidateState: PrivateRollbackCandidateState?

    public init(
        state: PrivateInstallRecoveryState,
        preparationJournal: PrivateInstallPreparationJournal? = nil,
        journal: PrivateInstallRecoveryJournal?,
        receipt: PrivateInstallCoordinatorReceipt?,
        lifecycleJournal: PrivateInstallLifecycleJournal? = nil,
        stagePath: String?,
        archivePath: String? = nil,
        candidateState: PrivateRollbackCandidateState?
    ) {
        self.state = state
        self.preparationJournal = preparationJournal
        self.journal = journal
        self.receipt = receipt
        self.lifecycleJournal = lifecycleJournal
        self.stagePath = stagePath
        self.archivePath = archivePath
        self.candidateState = candidateState
    }
}

public enum PrivateRollbackCandidateState: String, Codable, Equatable, Sendable {
    case absent
    case exact
}

public struct PrivateRollbackInspection: Codable, Equatable, Sendable {
    public let receipt: PrivateInstallCoordinatorReceipt
    public let stagePath: String
    public let candidateState: PrivateRollbackCandidateState

    public init(
        receipt: PrivateInstallCoordinatorReceipt,
        stagePath: String,
        candidateState: PrivateRollbackCandidateState
    ) {
        self.receipt = receipt
        self.stagePath = stagePath
        self.candidateState = candidateState
    }
}

public enum PrivateInstallCoordinatorError: Error, Equatable, LocalizedError {
    case invalidInvocation
    case unsafeCandidate
    case unsafeInstalledApplication
    case applicationRunning
    case signerMismatch
    case candidateChanged
    case stageAlreadyExists
    case stagingFailed
    case stageProofFailed
    case helperUnavailable
    case helperFailed
    case postInstallProofFailed
    case journalFailed
    case receiptFailed
    case rollbackFailed
    case rollbackInspectionFailed
    case interruptedInstallNotSwapped
    case interruptedRecordWrite
    case lifecycleFailed
    case lifecycleOperationMismatch

    public var errorDescription: String? {
        switch self {
        case .invalidInvocation:
            return "The private installer invocation is invalid."
        case .unsafeCandidate:
            return "The frozen private candidate failed its safety checks."
        case .unsafeInstalledApplication:
            return "The installed Fulmar bundle failed its safety checks."
        case .applicationRunning:
            return "Fulmar or one of its bundled runtime processes is still running."
        case .signerMismatch:
            return "The private candidate does not match the installed private signer."
        case .candidateChanged:
            return "The frozen private candidate changed while it was being staged."
        case .stageAlreadyExists:
            return "The exact private installation stage already exists."
        case .stagingFailed:
            return "The private candidate could not be staged safely."
        case .stageProofFailed:
            return "The staged bundle does not exactly match the frozen candidate."
        case .helperUnavailable:
            return "The atomic installation helper failed its safety checks."
        case .helperFailed:
            return "The atomic installation helper did not commit the installation."
        case .postInstallProofFailed:
            return "The installed bundle failed its post-install proof; rollback was attempted."
        case .journalFailed:
            return "The private installation recovery journal could not be committed before the atomic swap. No swap was requested."
        case .receiptFailed:
            return "The private installation receipt could not be proven durable. The recovery journal and exact app pair were preserved; inspect recovery before any further install."
        case .rollbackFailed:
            return "The previous Fulmar bundle could not be proven restored. Manual recovery is required."
        case .rollbackInspectionFailed:
            return "The retained private rollback could not be proven. No application data was changed."
        case .interruptedInstallNotSwapped:
            return "The interrupted private install has the original app active; there is no committed swap to finalize. Preserve the journal and staged candidate for reviewed cancellation or retry."
        case .interruptedRecordWrite:
            return "A private-install record write was interrupted. Read-only inspection changed nothing; run the explicit record-reconciliation operation to archive the exact temporary evidence and reconstruct only a fully proven record."
        case .lifecycleFailed:
            return "The private-install lifecycle transition could not be proven durable. No active app was removed; inspect the retained transaction and retry the same explicit operation."
        case .lifecycleOperationMismatch:
            return "The retained transaction is already bound to a different explicit lifecycle operation. No data was changed."
        }
    }
}

@_spi(PrivateInstallCrashProbe)
public struct PrivateInstallCoordinatorHooks {
    public var proveApplicationsStopped: () throws -> Void
    public var inspectInstalled: () throws -> PrivateInstallBundleProof
    public var inspectCandidate: () throws -> PrivateInstallBundleProof
    public var stageCandidate: () throws -> Void
    public var inspectStage: () throws -> PrivateInstallBundleProof
    public var invokeAtomicSwap: (
        _ expectedCurrent: AtomicInstallIdentity,
        _ expectedStage: AtomicInstallIdentity,
        _ expectedCandidate: PrivateStableApplicationAttestation
    ) throws -> Void
    public var postInstallBoundary: () throws -> Void
    public var persistJournal: (PrivateInstallRecoveryJournal) throws -> Void
    public var persistPreparation: (PrivateInstallPreparationJournal) throws -> Void
    public var persistReceipt: (PrivateInstallCoordinatorReceipt) throws -> Void
    public var nowUnixSeconds: () -> UInt64

    public init(
        proveApplicationsStopped: @escaping () throws -> Void,
        inspectInstalled: @escaping () throws -> PrivateInstallBundleProof,
        inspectCandidate: @escaping () throws -> PrivateInstallBundleProof,
        stageCandidate: @escaping () throws -> Void,
        inspectStage: @escaping () throws -> PrivateInstallBundleProof,
        invokeAtomicSwap: @escaping (
            AtomicInstallIdentity,
            AtomicInstallIdentity,
            PrivateStableApplicationAttestation
        ) throws -> Void,
        postInstallBoundary: @escaping () throws -> Void = {},
        persistPreparation: @escaping (PrivateInstallPreparationJournal) throws -> Void = { _ in },
        persistJournal: @escaping (PrivateInstallRecoveryJournal) throws -> Void,
        persistReceipt: @escaping (PrivateInstallCoordinatorReceipt) throws -> Void,
        nowUnixSeconds: @escaping () -> UInt64 = {
            UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
        }
    ) {
        self.proveApplicationsStopped = proveApplicationsStopped
        self.inspectInstalled = inspectInstalled
        self.inspectCandidate = inspectCandidate
        self.stageCandidate = stageCandidate
        self.inspectStage = inspectStage
        self.invokeAtomicSwap = invokeAtomicSwap
        self.postInstallBoundary = postInstallBoundary
        self.persistPreparation = persistPreparation
        self.persistJournal = persistJournal
        self.persistReceipt = persistReceipt
        self.nowUnixSeconds = nowUnixSeconds
    }
}

@_spi(PrivateInstallCrashProbe)
public struct PrivateInstallRecoveryHooks {
    public var loadPreparation: () throws -> PrivateInstallPreparationJournal?
    public var loadJournal: () throws -> PrivateInstallRecoveryJournal?
    public var loadReceipt: () throws -> PrivateInstallCoordinatorReceipt?
    public var loadLifecycleJournal: () throws -> PrivateInstallLifecycleJournal?
    public var stageLeaves: () throws -> [String]
    public var archiveLeaves: () throws -> [String]
    public var inspectInstalled: () throws -> PrivateInstallBundleProof
    public var inspectStage: (_ stageLeaf: String) throws -> PrivateInstallBundleProof
    public var inspectArchive: (_ archiveLeaf: String) throws -> PrivateInstallBundleProof
    public var inspectCandidateIfPresent: () throws -> PrivateInstallBundleProof?
    public var proveApplicationsStopped: () throws -> Void
    public var invokeAtomicSwap: (
        _ expectedCurrent: AtomicInstallIdentity,
        _ expectedStage: AtomicInstallIdentity,
        _ expectedCandidate: PrivateStableApplicationAttestation
    ) throws -> Void
    public var persistReceipt: (PrivateInstallCoordinatorReceipt) throws -> Void
    public var persistLifecycleJournal: (PrivateInstallLifecycleJournal) throws -> Void
    public var archiveStage: (
        _ stageLeaf: String,
        _ archiveLeaf: String,
        _ expected: PrivateInstallBundleProof
    ) throws -> Void
    public var proveArchiveDurable: (
        _ archiveLeaf: String,
        _ expected: PrivateInstallBundleProof
    ) throws -> Void
    public var archiveRecordDirectory: (PrivateInstallLifecycleJournal) throws -> Void
    public var nowUnixSeconds: () -> UInt64
    public var persistJournal: (PrivateInstallRecoveryJournal) throws -> Void
    public var stageCandidate: () throws -> Void
    public var inspectOpaqueStage: (String) throws -> PrivateInstallOpaqueStageIdentity?

    public init(
        loadJournal: @escaping () throws -> PrivateInstallRecoveryJournal?,
        loadReceipt: @escaping () throws -> PrivateInstallCoordinatorReceipt?,
        loadLifecycleJournal: @escaping () throws -> PrivateInstallLifecycleJournal?,
        stageLeaves: @escaping () throws -> [String],
        archiveLeaves: @escaping () throws -> [String],
        inspectInstalled: @escaping () throws -> PrivateInstallBundleProof,
        inspectStage: @escaping (String) throws -> PrivateInstallBundleProof,
        inspectArchive: @escaping (String) throws -> PrivateInstallBundleProof,
        inspectCandidateIfPresent: @escaping () throws -> PrivateInstallBundleProof?,
        proveApplicationsStopped: @escaping () throws -> Void,
        invokeAtomicSwap: @escaping (
            AtomicInstallIdentity,
            AtomicInstallIdentity,
            PrivateStableApplicationAttestation
        ) throws -> Void,
        persistReceipt: @escaping (PrivateInstallCoordinatorReceipt) throws -> Void,
        persistLifecycleJournal: @escaping (PrivateInstallLifecycleJournal) throws -> Void,
        archiveStage: @escaping (
            String,
            String,
            PrivateInstallBundleProof
        ) throws -> Void,
        proveArchiveDurable: @escaping (
            String,
            PrivateInstallBundleProof
        ) throws -> Void,
        archiveRecordDirectory: @escaping (PrivateInstallLifecycleJournal) throws -> Void,
        loadPreparation: @escaping () throws -> PrivateInstallPreparationJournal? = { nil },
        persistJournal: @escaping (PrivateInstallRecoveryJournal) throws -> Void = { _ in
            throw PrivateInstallCoordinatorError.journalFailed
        },
        stageCandidate: @escaping () throws -> Void = {
            throw PrivateInstallCoordinatorError.stagingFailed
        },
        inspectOpaqueStage: @escaping (String) throws -> PrivateInstallOpaqueStageIdentity? = { _ in nil },
        nowUnixSeconds: @escaping () -> UInt64 = {
            UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
        }
    ) {
        self.loadJournal = loadJournal
        self.loadReceipt = loadReceipt
        self.loadLifecycleJournal = loadLifecycleJournal
        self.stageLeaves = stageLeaves
        self.archiveLeaves = archiveLeaves
        self.inspectInstalled = inspectInstalled
        self.inspectStage = inspectStage
        self.inspectArchive = inspectArchive
        self.inspectCandidateIfPresent = inspectCandidateIfPresent
        self.proveApplicationsStopped = proveApplicationsStopped
        self.invokeAtomicSwap = invokeAtomicSwap
        self.persistReceipt = persistReceipt
        self.persistLifecycleJournal = persistLifecycleJournal
        self.archiveStage = archiveStage
        self.proveArchiveDurable = proveArchiveDurable
        self.archiveRecordDirectory = archiveRecordDirectory
        self.loadPreparation = loadPreparation
        self.persistJournal = persistJournal
        self.stageCandidate = stageCandidate
        self.inspectOpaqueStage = inspectOpaqueStage
        self.nowUnixSeconds = nowUnixSeconds
    }
}

struct PrivateRollbackInspectionHooks {
    var loadReceipt: () throws -> PrivateInstallCoordinatorReceipt?
    var stageLeaves: () throws -> [String]
    var inspectInstalled: () throws -> PrivateInstallBundleProof
    var inspectStage: (_ stageLeaf: String) throws -> PrivateInstallBundleProof
    var inspectCandidateIfPresent: () throws -> PrivateInstallBundleProof?
}

private enum InterruptedPrivateInstallRecordKind: String, CaseIterable {
    case abandonment
    case preparation
    case journal
    case receipt
    case lifecycle

    var temporaryPrefix: String {
        switch self {
        case .abandonment: return ".pending-private-abandonment."
        case .preparation: return ".pending-private-install-preparation."
        case .journal: return ".pending-private-install."
        case .receipt: return ".latest-private-install."
        case .lifecycle: return ".pending-lifecycle."
        }
    }

    var canonicalLeaf: String {
        switch self {
        case .abandonment: return "pending-private-abandonment.json"
        case .preparation: return "pending-private-install-preparation.json"
        case .journal: return "pending-private-install.json"
        case .receipt: return "latest-private-install.json"
        case .lifecycle: return "pending-lifecycle.json"
        }
    }

    var maximumBytes: Int {
        switch self {
        case .abandonment: return 98_304
        case .preparation: return 49_152
        case .journal: return 49_152
        case .receipt: return 24_576
        case .lifecycle: return 98_304
        }
    }
}

private struct InterruptedPrivateInstallRecordArtifact: Equatable {
    let kind: InterruptedPrivateInstallRecordKind
    let nonce: String
    let leaf: String
    let archived: Bool
}

public enum PrivateInstallCoordinator {
    public static let frozenCandidatePath = "/private/tmp/LocalHarnessBuild/Fulmar.app"
    public static let installedApplicationPath = "/Applications/Fulmar.app"
    public static let receiptRelativePath =
        "Library/Application Support/.Fulmar Private Install Receipts/latest-private-install.json"
    public static let journalRelativePath =
        "Library/Application Support/.Fulmar Private Install Receipts/pending-private-install.json"
    public static let preparationJournalRelativePath =
        "Library/Application Support/.Fulmar Private Install Receipts/pending-private-install-preparation.json"
    public static let lifecycleJournalRelativePath =
        "Library/Application Support/.Fulmar Private Install Receipts/pending-lifecycle.json"

    private static let expectedBundleIdentifier = "com.angadjairath.localharness"
    private static let maximumReceiptBytes = 24_576
    private static let maximumJournalBytes = 49_152
    private static let maximumPreparationJournalBytes = 49_152
    private static let maximumAbandonmentJournalBytes = 98_304
    private static let maximumLifecycleJournalBytes = 98_304
    private static let helperLeaf = "LocalHarnessAtomicInstallSwapHelper"
    private static let receiptLeaf = "latest-private-install.json"
    private static let journalLeaf = "pending-private-install.json"
    private static let preparationJournalLeaf = "pending-private-install-preparation.json"
    private static let abandonmentJournalLeaf = "pending-private-abandonment.json"
    private static let lifecycleJournalLeaf = "pending-lifecycle.json"
    private static let recordDirectoryLeaf = ".Fulmar Private Install Receipts"
    private static let interruptedRecordArchivePrefix =
        ".Fulmar.private-install-interrupted-record."

    public static func performProduction(nonce: String) throws -> PrivateInstallCoordinatorReceipt {
        guard try inspectProductionRecovery().state == .none else {
            throw PrivateInstallCoordinatorError.stageAlreadyExists
        }
        let stageLeaf = try mappedStageLeaf(nonce: nonce)
        let stageURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
            .appendingPathComponent(stageLeaf, isDirectory: true)
        let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
        let candidateURL = URL(fileURLWithPath: frozenCandidatePath, isDirectory: true)
        let helperURL = try productionHelperURL()

        let hooks = PrivateInstallCoordinatorHooks(
            proveApplicationsStopped: {
                guard productionApplicationsAreStopped(
                    additionalBundleURLs: [stageURL]
                ) else {
                    throw PrivateInstallCoordinatorError.applicationRunning
                }
            },
            inspectInstalled: {
                try inspectBundle(
                    at: installedURL,
                    failure: .unsafeInstalledApplication
                )
            },
            inspectCandidate: {
                try inspectBundle(at: candidateURL, failure: .unsafeCandidate)
            },
            stageCandidate: {
                try stageProductionCandidate(from: candidateURL, to: stageURL)
            },
            inspectStage: {
                try inspectBundle(at: stageURL, failure: .stageProofFailed)
            },
            invokeAtomicSwap: { expectedCurrent, expectedStage, expectedCandidate in
                try invokeProductionHelper(
                    helperURL: helperURL,
                    nonce: nonce,
                    expectedCurrent: expectedCurrent,
                    expectedStage: expectedStage,
                    expectedCandidate: expectedCandidate
                )
            },
            persistPreparation: { preparation in
                try persistProductionPreparation(preparation)
            },
            persistJournal: { journal in
                try persistProductionJournal(journal)
            },
            persistReceipt: { receipt in
                try persistProductionReceipt(receipt)
            }
        )
        return try perform(nonce: nonce, hooks: hooks)
    }

    public static func inspectProductionRecovery() throws -> PrivateInstallRecoveryInspection {
        do {
            let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
            let candidateURL = URL(fileURLWithPath: frozenCandidatePath, isDirectory: true)
            let receiptDirectory = try productionReceiptDirectory(requireExisting: false)
            if let receiptDirectory {
                let temporaryRecords = try interruptedRecordArtifacts(
                    in: receiptDirectory
                )
                let hasTemporaryRecord = !temporaryRecords.isEmpty
                let hasUnreconciledArchive = try hasUnreconciledInterruptedRecordArchive(
                    in: receiptDirectory
                )
                if hasTemporaryRecord || hasUnreconciledArchive {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
                if let abandonment = try readAbandonment(directory: receiptDirectory) {
                    return try inspectProductionAbandonment(abandonment)
                }
            } else if let abandonment = try pendingProductionAbandonmentArchive() {
                return try inspectProductionAbandonment(abandonment.journal)
            }
            let hooks = productionRecoveryHooks(
                installedURL: installedURL,
                candidateURL: candidateURL,
                receiptDirectory: receiptDirectory
            )
            return try inspectRecovery(hooks: hooks)
        } catch let error as PrivateInstallCoordinatorError {
            if error == .rollbackInspectionFailed || error == .interruptedRecordWrite {
                throw error
            }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        } catch {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    /// Explicitly reconciles one interrupted owner-private record write. The
    /// temporary inode is archived outside the active record directory through
    /// an exclusive descriptor-relative rename and is never deleted. Only the
    /// record implied by repeated app/stage/signer proofs is reconstructed.
    public static func reconcileProductionInterruptedRecordWrite()
        throws -> PrivateInstallRecoveryInspection {
        guard let receiptDirectory = try productionReceiptDirectory(requireExisting: true) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let hooks = productionRecoveryHooks(
            installedURL: URL(
                fileURLWithPath: installedApplicationPath,
                isDirectory: true
            ),
            candidateURL: URL(
                fileURLWithPath: frozenCandidatePath,
                isDirectory: true
            ),
            receiptDirectory: receiptDirectory
        )
        try reconcileInterruptedRecordWrite(in: receiptDirectory, hooks: hooks)
        return try inspectProductionRecovery()
    }

    /// Completes only the missing durable receipt for an already-committed
    /// APFS exchange. This never swaps, removes, or rewrites either app bundle.
    /// The caller must opt in explicitly and should hold the installer lock.
    public static func commitProductionInterruptedInstall()
        throws -> PrivateInstallCoordinatorReceipt {
        let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
        let candidateURL = URL(fileURLWithPath: frozenCandidatePath, isDirectory: true)
        guard let receiptDirectory = try productionReceiptDirectory(requireExisting: true) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let hooks = productionRecoveryHooks(
            installedURL: installedURL,
            candidateURL: candidateURL,
            receiptDirectory: receiptDirectory
        )
        return try commitInterruptedInstall(hooks: hooks)
    }

    /// Explicitly resumes a journaled transaction whose original app is still
    /// active. All proofs and stopped-process checks are repeated before the
    /// same atomic helper is invoked; no staged data is silently discarded.
    public static func resumeProductionInterruptedInstall()
        throws -> PrivateInstallCoordinatorReceipt {
        let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
        let candidateURL = URL(fileURLWithPath: frozenCandidatePath, isDirectory: true)
        let helperURL = try productionHelperURL()
        guard let receiptDirectory = try productionReceiptDirectory(requireExisting: true) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let hooks = productionRecoveryHooks(
            installedURL: installedURL,
            candidateURL: candidateURL,
            receiptDirectory: receiptDirectory,
            helperURL: helperURL
        )
        return try resumeInterruptedInstall(hooks: hooks)
    }

    /// Explicitly abandons a journaled transaction before its swap. The exact
    /// staged candidate and its records are archived, never deleted. A nil
    /// result means there is no active private-install transaction.
    public static func cancelProductionInterruptedInstall()
        throws -> PrivateInstallLifecycleJournal? {
        try performProductionLifecycle(operation: .cancelOriginalActive)
    }

    /// Explicitly retires a proven committed rollback after the caller has
    /// accepted the installed candidate. The rollback and records are archived,
    /// never deleted, so the next qualified private update can start cleanly.
    public static func retireProductionCommittedInstall()
        throws -> PrivateInstallLifecycleJournal? {
        try performProductionLifecycle(operation: .retireCommitted)
    }

    private static func performProductionLifecycle(
        operation: PrivateInstallLifecycleOperation
    ) throws -> PrivateInstallLifecycleJournal? {
        let initial = try inspectProductionRecovery()
        if initial.state == .none { return nil }
        if operation == .cancelOriginalActive,
           [.stagingPrepared, .stagedAwaitingJournal, .stagingInterrupted,
            .abandonmentPrepared, .abandonmentArchived].contains(initial.state) {
            try abandonProductionInterruptedStaging()
            return nil
        }
        let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
        let candidateURL = URL(fileURLWithPath: frozenCandidatePath, isDirectory: true)
        guard let receiptDirectory = try productionReceiptDirectory(requireExisting: true) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let hooks = productionRecoveryHooks(
            installedURL: installedURL,
            candidateURL: candidateURL,
            receiptDirectory: receiptDirectory
        )
        return try performLifecycle(operation: operation, hooks: hooks)
    }

    private static func abandonProductionInterruptedStaging() throws {
        let activeDirectory = try productionReceiptDirectory(requireExisting: false)
        if activeDirectory == nil, let pending = try pendingProductionAbandonmentArchive() {
            let abandonedStage = URL(fileURLWithPath: "/Applications", isDirectory: true)
                .appendingPathComponent(
                    try opaqueAbandonmentLeaf(nonce: pending.journal.nonce),
                    isDirectory: true
                )
            guard productionApplicationsAreStopped(additionalBundleURLs: [abandonedStage]) else {
                throw PrivateInstallCoordinatorError.applicationRunning
            }
            try archiveAbandonmentRecordDirectory(
                pending.directory,
                abandonment: pending.journal,
                sourceAlreadyArchived: true
            )
            guard productionApplicationsAreStopped(additionalBundleURLs: [abandonedStage]) else {
                throw PrivateInstallCoordinatorError.applicationRunning
            }
            return
        }
        guard let directory = activeDirectory,
              let preparation = try readPreparation(directory: directory) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
        let stageURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
            .appendingPathComponent(preparation.stageLeaf, isDirectory: true)
        var abandonment = try readAbandonment(directory: directory)
        if abandonment == nil {
            let active = try inspectBundle(at: installedURL, failure: .rollbackInspectionFailed)
            guard active == preparation.originalInstalled else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            abandonment = PrivateInstallAbandonmentJournal(
                nonce: preparation.nonce,
                preparedAtUnixSeconds: UInt64(
                    max(0, Date().timeIntervalSince1970.rounded(.down))
                ),
                preparation: preparation,
                activeInstalled: active,
                opaqueStage: try inspectOptionalOpaqueStage(at: stageURL)
            )
            try persistAbandonment(abandonment!, directory: directory)
        }
        guard let abandonment else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        try validateAbandonmentShape(abandonment)
        let hooks = productionRecoveryHooks(
            installedURL: installedURL,
            candidateURL: URL(fileURLWithPath: frozenCandidatePath, isDirectory: true),
            receiptDirectory: directory
        )
        try hooks.proveApplicationsStopped()
        guard try readPreparation(directory: directory) == preparation,
              try readAbandonment(directory: directory) == abandonment,
              try inspectBundle(at: installedURL, failure: .rollbackInspectionFailed)
                == abandonment.activeInstalled else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try archiveOpaqueStage(abandonment, stageURL: stageURL)
        try hooks.proveApplicationsStopped()
        try archiveAbandonmentRecordDirectory(directory, abandonment: abandonment)
    }

    public static func inspectProductionRollback() throws -> PrivateRollbackInspection? {
        do {
            let installedURL = URL(fileURLWithPath: installedApplicationPath, isDirectory: true)
            let candidateURL = URL(fileURLWithPath: frozenCandidatePath, isDirectory: true)
            let receiptDirectory = try productionReceiptDirectory(requireExisting: false)
            let hooks = PrivateRollbackInspectionHooks(
                loadReceipt: {
                    guard let receiptDirectory else { return nil }
                    return try readReceipt(directory: receiptDirectory)
                },
                stageLeaves: {
                    try productionStageLeaves()
                },
                inspectInstalled: {
                    try inspectBundle(at: installedURL, failure: .rollbackInspectionFailed)
                },
                inspectStage: { stageLeaf in
                    let stageURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
                        .appendingPathComponent(stageLeaf, isDirectory: true)
                    return try inspectBundle(at: stageURL, failure: .rollbackInspectionFailed)
                },
                inspectCandidateIfPresent: {
                    try inspectOptionalBundle(
                        at: candidateURL,
                        failure: .rollbackInspectionFailed
                    )
                }
            )
            return try inspectRollback(hooks: hooks)
        } catch let error as PrivateInstallCoordinatorError {
            if error == .rollbackInspectionFailed { throw error }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        } catch {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    static func inspectRollback(
        hooks: PrivateRollbackInspectionHooks
    ) throws -> PrivateRollbackInspection? {
        do {
            let receiptBefore = try hooks.loadReceipt()
            let leavesBefore = try hooks.stageLeaves()
            guard let receipt = receiptBefore else {
                guard leavesBefore.isEmpty,
                      try hooks.loadReceipt() == nil,
                      try hooks.stageLeaves().isEmpty else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                return nil
            }
            try validateReceiptShape(receipt)
            let expectedStageLeaf = try mappedStageLeaf(nonce: receipt.nonce)
            guard leavesBefore == [expectedStageLeaf] else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }

            let installed = try hooks.inspectInstalled()
            let rollback = try hooks.inspectStage(expectedStageLeaf)
            let candidate = try hooks.inspectCandidateIfPresent()
            try validateProofShape(installed, failure: .rollbackInspectionFailed)
            try validateProofShape(rollback, failure: .rollbackInspectionFailed)
            if let candidate {
                try validateProofShape(candidate, failure: .rollbackInspectionFailed)
            }
            guard installed == receipt.installed,
                  rollback == receipt.retainedRollback,
                  installed.identity != rollback.identity,
                  samePrivateSigner(installed.attestation, rollback.attestation),
                  candidate.map({ sameBundleContent($0, installed) }) ?? true else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }

            // Repeat every mutable proof after the complete bounded tree and
            // signature inspections. This makes replacement, receipt rewrite,
            // or stage-name changes during a read fail closed.
            guard try hooks.loadReceipt() == receipt,
                  try hooks.stageLeaves() == [expectedStageLeaf],
                  try hooks.inspectInstalled() == installed,
                  try hooks.inspectStage(expectedStageLeaf) == rollback,
                  try hooks.inspectCandidateIfPresent() == candidate else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            return PrivateRollbackInspection(
                receipt: receipt,
                stagePath: "/Applications/\(expectedStageLeaf)",
                candidateState: candidate == nil ? .absent : .exact
            )
        } catch let error as PrivateInstallCoordinatorError {
            if error == .rollbackInspectionFailed { throw error }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        } catch {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    @_spi(PrivateInstallCrashProbe)
    public static func inspectRecovery(
        hooks: PrivateInstallRecoveryHooks
    ) throws -> PrivateInstallRecoveryInspection {
        do {
            let preparation = try hooks.loadPreparation()
            let journal = try hooks.loadJournal()
            let receipt = try hooks.loadReceipt()
            let lifecycleJournal = try hooks.loadLifecycleJournal()
            let leaves = try hooks.stageLeaves()

            if let lifecycleJournal {
                return try inspectLifecycleRecovery(
                    lifecycleJournal: lifecycleJournal,
                    preparation: preparation,
                    journal: journal,
                    receipt: receipt,
                    stageLeaves: leaves,
                    hooks: hooks
                )
            }

            if let preparation, journal == nil, receipt == nil, lifecycleJournal == nil {
                try validatePreparationShape(preparation)
                let installed = try hooks.inspectInstalled()
                let candidate = try hooks.inspectCandidateIfPresent()
                try validateOptionalCandidate(candidate, expected: preparation.frozenCandidate)
                guard installed == preparation.originalInstalled else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                var state: PrivateInstallRecoveryState
                var exactStage: PrivateInstallBundleProof?
                if leaves.isEmpty {
                    state = .stagingPrepared
                } else if leaves == [preparation.stageLeaf] {
                    do {
                        let staged = try hooks.inspectStage(preparation.stageLeaf)
                        try validateProofShape(staged, failure: .rollbackInspectionFailed)
                        guard sameBundleContent(staged, preparation.frozenCandidate),
                              staged.identity != preparation.originalInstalled.identity,
                              staged.identity != preparation.frozenCandidate.identity,
                              staged.identity.device == preparation.originalInstalled.identity.device
                        else {
                            state = .stagingInterrupted
                            exactStage = nil
                            guard try hooks.loadPreparation() == preparation,
                                  try hooks.stageLeaves() == leaves else {
                                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                            }
                            return PrivateInstallRecoveryInspection(
                                state: state,
                                preparationJournal: preparation,
                                journal: nil,
                                receipt: nil,
                                stagePath: "/Applications/\(preparation.stageLeaf)",
                                candidateState: candidate == nil ? .absent : .exact
                            )
                        }
                        exactStage = staged
                        state = .stagedAwaitingJournal
                    } catch {
                        state = .stagingInterrupted
                    }
                } else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                guard try hooks.loadPreparation() == preparation,
                      try hooks.loadJournal() == nil,
                      try hooks.loadReceipt() == nil,
                      try hooks.loadLifecycleJournal() == nil,
                      try hooks.stageLeaves() == leaves,
                      try hooks.inspectInstalled() == installed,
                      try hooks.inspectCandidateIfPresent() == candidate else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                if let exactStage {
                    guard try hooks.inspectStage(preparation.stageLeaf) == exactStage else {
                        throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                    }
                }
                return PrivateInstallRecoveryInspection(
                    state: state,
                    preparationJournal: preparation,
                    journal: nil,
                    receipt: nil,
                    stagePath: leaves.isEmpty ? nil : "/Applications/\(preparation.stageLeaf)",
                    candidateState: candidate == nil ? .absent : .exact
                )
            }

            if journal == nil, receipt == nil {
                guard leaves.isEmpty,
                      preparation == nil,
                      try hooks.loadPreparation() == nil,
                      try hooks.loadJournal() == nil,
                      try hooks.loadReceipt() == nil,
                      try hooks.loadLifecycleJournal() == nil,
                      try hooks.stageLeaves().isEmpty else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                return PrivateInstallRecoveryInspection(
                    state: .none,
                    journal: nil,
                    receipt: nil,
                    stagePath: nil,
                    candidateState: nil
                )
            }

            if journal == nil, let receipt {
                try validateReceiptShape(receipt)
                let stageLeaf = try mappedStageLeaf(nonce: receipt.nonce)
                guard leaves == [stageLeaf] else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                let installed = try hooks.inspectInstalled()
                let stage = try hooks.inspectStage(stageLeaf)
                let candidate = try hooks.inspectCandidateIfPresent()
                try validateOptionalCandidate(candidate, expected: receipt.installed)
                guard installed == receipt.installed,
                      stage == receipt.retainedRollback,
                      try hooks.loadJournal() == nil,
                      try hooks.loadReceipt() == receipt,
                      try hooks.loadLifecycleJournal() == nil,
                      try hooks.stageLeaves() == [stageLeaf],
                      try hooks.inspectInstalled() == installed,
                      try hooks.inspectStage(stageLeaf) == stage,
                      try hooks.inspectCandidateIfPresent() == candidate else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                return PrivateInstallRecoveryInspection(
                    state: .committed,
                    journal: nil,
                    receipt: receipt,
                    stagePath: "/Applications/\(stageLeaf)",
                    candidateState: candidate == nil ? .absent : .exact
                )
            }

            guard let journal else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            try validateJournalShape(journal)
            if let preparation {
                try validatePreparationShape(preparation)
                guard preparation.nonce == journal.nonce,
                      preparation.stageLeaf == (try mappedStageLeaf(nonce: journal.nonce)),
                      preparation.originalInstalled == journal.originalInstalled,
                      preparation.frozenCandidate == journal.frozenCandidate else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
            }
            let stageLeaf = try mappedStageLeaf(nonce: journal.nonce)
            guard leaves == [stageLeaf] else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            let installed = try hooks.inspectInstalled()
            let stage = try hooks.inspectStage(stageLeaf)
            let candidate = try hooks.inspectCandidateIfPresent()
            try validateProofShape(installed, failure: .rollbackInspectionFailed)
            try validateProofShape(stage, failure: .rollbackInspectionFailed)
            try validateOptionalCandidate(candidate, expected: journal.frozenCandidate)

            let state: PrivateInstallRecoveryState
            if installed == journal.originalInstalled,
               stage == journal.stagedCandidate {
                guard receipt == nil else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                state = .originalActive
            } else if installed == journal.stagedCandidate,
                      stage == journal.originalInstalled {
                if let receipt {
                    try validateReceiptShape(receipt)
                    guard receipt.nonce == journal.nonce,
                          receipt.installed == journal.stagedCandidate,
                          receipt.retainedRollback == journal.originalInstalled else {
                        throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                    }
                    state = .committed
                } else {
                    state = .swappedAwaitingCommit
                }
            } else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }

            guard try hooks.loadJournal() == journal,
                  try hooks.loadPreparation() == preparation,
                  try hooks.loadReceipt() == receipt,
                  try hooks.loadLifecycleJournal() == nil,
                  try hooks.stageLeaves() == [stageLeaf],
                  try hooks.inspectInstalled() == installed,
                  try hooks.inspectStage(stageLeaf) == stage,
                  try hooks.inspectCandidateIfPresent() == candidate else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            return PrivateInstallRecoveryInspection(
                state: state,
                preparationJournal: preparation,
                journal: journal,
                receipt: receipt,
                stagePath: "/Applications/\(stageLeaf)",
                candidateState: candidate == nil ? .absent : .exact
            )
        } catch let error as PrivateInstallCoordinatorError {
            if error == .rollbackInspectionFailed { throw error }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        } catch {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    private static func inspectLifecycleRecovery(
        lifecycleJournal: PrivateInstallLifecycleJournal,
        preparation: PrivateInstallPreparationJournal?,
        journal: PrivateInstallRecoveryJournal?,
        receipt: PrivateInstallCoordinatorReceipt?,
        stageLeaves: [String],
        hooks: PrivateInstallRecoveryHooks
    ) throws -> PrivateInstallRecoveryInspection {
        try validateLifecycleJournalShape(lifecycleJournal)
        guard journal == lifecycleJournal.recoveryJournal,
              receipt == lifecycleJournal.receipt else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        if let preparation {
            try validatePreparationShape(preparation)
            let expectedOriginal = journal?.originalInstalled ?? receipt?.retainedRollback
            let expectedCandidate = journal?.frozenCandidate ?? receipt?.installed
            guard preparation.nonce == lifecycleJournal.nonce,
                  preparation.originalInstalled == expectedOriginal,
                  preparation.frozenCandidate == expectedCandidate else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
        }
        let stageLeaf = try mappedStageLeaf(nonce: lifecycleJournal.nonce)
        let archiveLeaf = try mappedArchiveLeaf(
            nonce: lifecycleJournal.nonce,
            operation: lifecycleJournal.operation
        )
        let archiveLeaves = try hooks.archiveLeaves()
        let installed = try hooks.inspectInstalled()
        let candidate = try hooks.inspectCandidateIfPresent()
        try validateProofShape(installed, failure: .rollbackInspectionFailed)
        guard installed == lifecycleJournal.activeInstalled else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let expectedCandidate: PrivateInstallBundleProof
        switch lifecycleJournal.operation {
        case .cancelOriginalActive:
            guard let journal else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            expectedCandidate = journal.frozenCandidate
        case .retireCommitted:
            guard let receipt else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            expectedCandidate = receipt.installed
        }
        try validateOptionalCandidate(candidate, expected: expectedCandidate)

        let retained: PrivateInstallBundleProof
        let state: PrivateInstallRecoveryState
        let archivePath: String?
        if stageLeaves == [stageLeaf], !archiveLeaves.contains(archiveLeaf) {
            retained = try hooks.inspectStage(stageLeaf)
            state = lifecycleJournal.operation == .cancelOriginalActive
                ? .cancellationPrepared
                : .retirementPrepared
            archivePath = nil
        } else if stageLeaves.isEmpty, archiveLeaves.contains(archiveLeaf) {
            retained = try hooks.inspectArchive(archiveLeaf)
            state = lifecycleJournal.operation == .cancelOriginalActive
                ? .cancellationArchived
                : .retirementArchived
            archivePath = "/Applications/\(archiveLeaf)"
        } else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        guard retained == lifecycleJournal.retainedStage,
              try hooks.loadJournal() == journal,
              try hooks.loadReceipt() == receipt,
              try hooks.loadLifecycleJournal() == lifecycleJournal,
              try hooks.loadPreparation() == preparation,
              try hooks.stageLeaves() == stageLeaves,
              try hooks.archiveLeaves() == archiveLeaves,
              try hooks.inspectInstalled() == installed,
              try hooks.inspectCandidateIfPresent() == candidate else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        if archivePath == nil {
            guard try hooks.inspectStage(stageLeaf) == retained else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
        } else {
            guard try hooks.inspectArchive(archiveLeaf) == retained else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
        }
        return PrivateInstallRecoveryInspection(
            state: state,
            preparationJournal: preparation,
            journal: journal,
            receipt: receipt,
            lifecycleJournal: lifecycleJournal,
            stagePath: archivePath == nil ? "/Applications/\(stageLeaf)" : nil,
            archivePath: archivePath,
            candidateState: candidate == nil ? .absent : .exact
        )
    }

    static func commitInterruptedInstall(
        hooks: PrivateInstallRecoveryHooks
    ) throws -> PrivateInstallCoordinatorReceipt {
        try hooks.proveApplicationsStopped()
        let inspection = try inspectRecovery(hooks: hooks)
        if inspection.state == .committed, let receipt = inspection.receipt {
            return receipt
        }
        guard inspection.state == .swappedAwaitingCommit,
              let journal = inspection.journal,
              inspection.receipt == nil else {
            if inspection.state == .originalActive {
                throw PrivateInstallCoordinatorError.interruptedInstallNotSwapped
            }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try hooks.proveApplicationsStopped()
        let receipt = PrivateInstallCoordinatorReceipt(
            nonce: journal.nonce,
            committedAtUnixSeconds: hooks.nowUnixSeconds(),
            installed: journal.stagedCandidate,
            retainedRollback: journal.originalInstalled
        )
        do {
            try hooks.persistReceipt(receipt)
        } catch {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        let committed = try inspectRecovery(hooks: hooks)
        guard committed.state == .committed,
              committed.receipt == receipt,
              committed.journal == journal else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return receipt
    }

    static func resumeInterruptedInstall(
        hooks: PrivateInstallRecoveryHooks
    ) throws -> PrivateInstallCoordinatorReceipt {
        try hooks.proveApplicationsStopped()
        let initial = try inspectRecovery(hooks: hooks)
        if initial.state == .committed, let receipt = initial.receipt {
            return receipt
        }
        if initial.state == .swappedAwaitingCommit {
            return try commitInterruptedInstall(hooks: hooks)
        }
        if initial.state == .stagingPrepared {
            guard let preparation = initial.preparationJournal,
                  initial.journal == nil,
                  initial.receipt == nil else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            try hooks.proveApplicationsStopped()
            let candidate = try hooks.inspectCandidateIfPresent()
            guard candidate == preparation.frozenCandidate,
                  try hooks.inspectInstalled() == preparation.originalInstalled,
                  try hooks.stageLeaves().isEmpty,
                  try hooks.loadPreparation() == preparation else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            try hooks.stageCandidate()
            return try resumeInterruptedInstall(hooks: hooks)
        }
        if initial.state == .stagedAwaitingJournal {
            guard let preparation = initial.preparationJournal,
                  initial.journal == nil,
                  initial.receipt == nil else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            try hooks.proveApplicationsStopped()
            let staged = try hooks.inspectStage(preparation.stageLeaf)
            guard try hooks.loadPreparation() == preparation,
                  try hooks.inspectInstalled() == preparation.originalInstalled,
                  try hooks.inspectCandidateIfPresent() == preparation.frozenCandidate,
                  try hooks.stageLeaves() == [preparation.stageLeaf],
                  sameBundleContent(staged, preparation.frozenCandidate),
                  staged.identity != preparation.originalInstalled.identity,
                  staged.identity != preparation.frozenCandidate.identity else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            let journal = PrivateInstallRecoveryJournal(
                nonce: preparation.nonce,
                preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                originalInstalled: preparation.originalInstalled,
                frozenCandidate: preparation.frozenCandidate,
                stagedCandidate: staged
            )
            do {
                try hooks.persistJournal(journal)
            } catch {
                throw PrivateInstallCoordinatorError.journalFailed
            }
            return try resumeInterruptedInstall(hooks: hooks)
        }
        if initial.state == .stagingInterrupted {
            throw PrivateInstallCoordinatorError.lifecycleOperationMismatch
        }
        guard initial.state == .originalActive,
              let journal = initial.journal,
              initial.receipt == nil else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }

        try hooks.proveApplicationsStopped()
        let immediatelyBeforeSwap = try inspectRecovery(hooks: hooks)
        guard immediatelyBeforeSwap.state == .originalActive,
              immediatelyBeforeSwap.journal == journal,
              immediatelyBeforeSwap.receipt == nil else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        do {
            try hooks.invokeAtomicSwap(
                journal.originalInstalled.identity,
                journal.stagedCandidate.identity,
                journal.frozenCandidate.attestation
            )
        } catch {
            let afterFailure = try inspectRecovery(hooks: hooks)
            if afterFailure.state == .originalActive {
                throw PrivateInstallCoordinatorError.helperFailed
            }
            guard afterFailure.state == .swappedAwaitingCommit else {
                throw PrivateInstallCoordinatorError.rollbackFailed
            }
        }
        let swapped = try inspectRecovery(hooks: hooks)
        guard swapped.state == .swappedAwaitingCommit,
              swapped.journal == journal,
              swapped.receipt == nil else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try commitInterruptedInstall(hooks: hooks)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func performLifecycle(
        operation: PrivateInstallLifecycleOperation,
        hooks: PrivateInstallRecoveryHooks
    ) throws -> PrivateInstallLifecycleJournal? {
        try hooks.proveApplicationsStopped()
        var inspection = try inspectRecovery(hooks: hooks)
        if inspection.state == .none { return nil }

        let lifecycleJournal: PrivateInstallLifecycleJournal
        if let existing = inspection.lifecycleJournal {
            guard existing.operation == operation else {
                throw PrivateInstallCoordinatorError.lifecycleOperationMismatch
            }
            lifecycleJournal = existing
        } else {
            switch operation {
            case .cancelOriginalActive:
                guard inspection.state == .originalActive,
                      let journal = inspection.journal,
                      inspection.receipt == nil else {
                    throw PrivateInstallCoordinatorError.lifecycleOperationMismatch
                }
                lifecycleJournal = PrivateInstallLifecycleJournal(
                    operation: operation,
                    nonce: journal.nonce,
                    preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                    activeInstalled: journal.originalInstalled,
                    retainedStage: journal.stagedCandidate,
                    recoveryJournal: journal,
                    receipt: nil
                )
            case .retireCommitted:
                guard inspection.state == .committed,
                      let receipt = inspection.receipt else {
                    throw PrivateInstallCoordinatorError.lifecycleOperationMismatch
                }
                lifecycleJournal = PrivateInstallLifecycleJournal(
                    operation: operation,
                    nonce: receipt.nonce,
                    preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                    activeInstalled: receipt.installed,
                    retainedStage: receipt.retainedRollback,
                    recoveryJournal: inspection.journal,
                    receipt: receipt
                )
            }
            do {
                try hooks.persistLifecycleJournal(lifecycleJournal)
            } catch {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            inspection = try inspectRecovery(hooks: hooks)
        }

        let preparedState: PrivateInstallRecoveryState = operation == .cancelOriginalActive
            ? .cancellationPrepared
            : .retirementPrepared
        let archivedState: PrivateInstallRecoveryState = operation == .cancelOriginalActive
            ? .cancellationArchived
            : .retirementArchived
        guard inspection.lifecycleJournal == lifecycleJournal,
              inspection.state == preparedState || inspection.state == archivedState else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }

        let stageLeaf = try mappedStageLeaf(nonce: lifecycleJournal.nonce)
        let archiveLeaf = try mappedArchiveLeaf(
            nonce: lifecycleJournal.nonce,
            operation: operation
        )
        if inspection.state == preparedState {
            try hooks.proveApplicationsStopped()
            let immediatelyBeforeArchive = try inspectRecovery(hooks: hooks)
            guard immediatelyBeforeArchive.state == preparedState,
                  immediatelyBeforeArchive.lifecycleJournal == lifecycleJournal else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            do {
                try hooks.archiveStage(
                    stageLeaf,
                    archiveLeaf,
                    lifecycleJournal.retainedStage
                )
            } catch {
                let afterFailure = try inspectRecovery(hooks: hooks)
                guard afterFailure.state == archivedState,
                      afterFailure.lifecycleJournal == lifecycleJournal else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
            }
        }

        try hooks.proveApplicationsStopped()
        inspection = try inspectRecovery(hooks: hooks)
        guard inspection.state == archivedState,
              inspection.lifecycleJournal == lifecycleJournal else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        do {
            try hooks.proveArchiveDurable(archiveLeaf, lifecycleJournal.retainedStage)
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        try hooks.proveApplicationsStopped()
        let immediatelyBeforeRecordArchive = try inspectRecovery(hooks: hooks)
        guard immediatelyBeforeRecordArchive.state == archivedState,
              immediatelyBeforeRecordArchive.lifecycleJournal == lifecycleJournal else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        do {
            try hooks.archiveRecordDirectory(lifecycleJournal)
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        return lifecycleJournal
    }

    @_spi(PrivateInstallCrashProbe)
    public static func perform(
        nonce: String,
        hooks: PrivateInstallCoordinatorHooks
    ) throws -> PrivateInstallCoordinatorReceipt {
        _ = try mappedStageLeaf(nonce: nonce)
        try hooks.proveApplicationsStopped()

        let original = try hooks.inspectInstalled()
        let candidate = try hooks.inspectCandidate()
        try validateProofShape(original, failure: .unsafeInstalledApplication)
        try validateProofShape(candidate, failure: .unsafeCandidate)
        guard samePrivateSigner(original.attestation, candidate.attestation) else {
            throw PrivateInstallCoordinatorError.signerMismatch
        }
        guard original.identity != candidate.identity else {
            throw PrivateInstallCoordinatorError.unsafeCandidate
        }

        let preparation = PrivateInstallPreparationJournal(
            nonce: nonce,
            stageLeaf: try mappedStageLeaf(nonce: nonce),
            preparedAtUnixSeconds: hooks.nowUnixSeconds(),
            originalInstalled: original,
            frozenCandidate: candidate
        )
        do {
            try hooks.persistPreparation(preparation)
        } catch {
            throw PrivateInstallCoordinatorError.journalFailed
        }

        // No staging mutation is permitted until the immutable preparation
        // record is durable. Repeat the mutable source proofs at this boundary.
        try hooks.proveApplicationsStopped()
        guard try hooks.inspectInstalled() == original,
              try hooks.inspectCandidate() == candidate else {
            throw PrivateInstallCoordinatorError.candidateChanged
        }

        try hooks.stageCandidate()
        let candidateAfterCopy = try hooks.inspectCandidate()
        guard candidateAfterCopy == candidate else {
            throw PrivateInstallCoordinatorError.candidateChanged
        }
        let staged = try hooks.inspectStage()
        try validateProofShape(staged, failure: .stageProofFailed)
        guard staged.treeSHA256Hex == candidate.treeSHA256Hex,
              staged.attestation == candidate.attestation,
              staged.identity != candidate.identity,
              staged.identity != original.identity,
              staged.identity.device == original.identity.device else {
            throw PrivateInstallCoordinatorError.stageProofFailed
        }

        let journal = PrivateInstallRecoveryJournal(
            nonce: nonce,
            preparedAtUnixSeconds: hooks.nowUnixSeconds(),
            originalInstalled: original,
            frozenCandidate: candidate,
            stagedCandidate: staged
        )
        guard journal.nonce == preparation.nonce,
              preparation.stageLeaf == (try mappedStageLeaf(nonce: journal.nonce)),
              journal.originalInstalled == preparation.originalInstalled,
              journal.frozenCandidate == preparation.frozenCandidate else {
            throw PrivateInstallCoordinatorError.journalFailed
        }
        do {
            try hooks.persistJournal(journal)
        } catch {
            throw PrivateInstallCoordinatorError.journalFailed
        }

        // The journal is the last durable boundary before the helper. Repeat
        // every mutable proof after it is fsynced so the recorded transaction
        // and the identities handed to the atomic helper describe one state.
        try hooks.proveApplicationsStopped()
        guard try hooks.inspectInstalled() == original,
              try hooks.inspectCandidate() == candidate,
              try hooks.inspectStage() == staged else {
            throw PrivateInstallCoordinatorError.candidateChanged
        }
        do {
            try hooks.invokeAtomicSwap(
                original.identity,
                staged.identity,
                candidate.attestation
            )
        } catch {
            try resolveFailedHelperInvocation(
                original: original,
                candidate: candidate,
                staged: staged,
                hooks: hooks
            )
            throw PrivateInstallCoordinatorError.helperFailed
        }

        do {
            try hooks.proveApplicationsStopped()
            let installed = try hooks.inspectInstalled()
            let rollback = try hooks.inspectStage()
            guard installed == proof(candidate, withIdentity: staged.identity),
                  rollback == original else {
                throw PrivateInstallCoordinatorError.postInstallProofFailed
            }
            try hooks.postInstallBoundary()
            let receipt = PrivateInstallCoordinatorReceipt(
                nonce: nonce,
                committedAtUnixSeconds: hooks.nowUnixSeconds(),
                installed: installed,
                retainedRollback: rollback
            )
            do {
                try hooks.persistReceipt(receipt)
            } catch {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
            return receipt
        } catch {
            let failure = (error as? PrivateInstallCoordinatorError)
                ?? PrivateInstallCoordinatorError.postInstallProofFailed
            // After receipt persistence begins, its durability may be
            // indeterminate (for example, the rename completed but the parent
            // fsync reported failure). Swapping back could then leave a
            // durable committed receipt describing the opposite app pair.
            // Preserve the journal and exact post-swap pair for deterministic,
            // explicit recovery instead.
            if failure == .receiptFailed {
                throw failure
            }
            do {
                try recoverOriginal(
                    original: original,
                    candidate: candidate,
                    staged: staged,
                    hooks: hooks
                )
            } catch {
                throw PrivateInstallCoordinatorError.rollbackFailed
            }
            throw failure
        }
    }

    @_spi(PrivateInstallCrashProbe)
    public static func treeSHA256ForTesting(at root: URL) throws -> String {
        try treeSHA256(at: root, failure: .unsafeCandidate)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func identityForTesting(at root: URL) throws -> AtomicInstallIdentity {
        try safeDirectoryIdentity(at: root, failure: .unsafeCandidate)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func productionApplicationSupportDirectoryForTesting(
        homeDirectory: URL
    ) throws -> URL {
        try productionApplicationSupportDirectory(homeDirectory: homeDirectory)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func opaqueStageIdentityForTesting(
        at stage: URL
    ) throws -> PrivateInstallOpaqueStageIdentity? {
        guard stage.path.hasPrefix("/private/tmp/FulmarPrivateInstall") else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try inspectOptionalOpaqueStage(at: stage)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func persistReceiptForTesting(
        _ receipt: PrivateInstallCoordinatorReceipt,
        in directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        try persistReceipt(receipt, directory: directory, boundaryHook: boundaryHook)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func readReceiptForTesting(
        in directory: URL
    ) throws -> PrivateInstallCoordinatorReceipt? {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try readReceipt(directory: directory)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func persistJournalForTesting(
        _ journal: PrivateInstallRecoveryJournal,
        in directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.journalFailed
        }
        try persistJournal(journal, directory: directory, boundaryHook: boundaryHook)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func readJournalForTesting(
        in directory: URL
    ) throws -> PrivateInstallRecoveryJournal? {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try readJournal(directory: directory)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func persistPreparationForTesting(
        _ preparation: PrivateInstallPreparationJournal,
        in directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.journalFailed
        }
        try persistPreparation(
            preparation,
            directory: directory,
            boundaryHook: boundaryHook
        )
    }

    @_spi(PrivateInstallCrashProbe)
    public static func readPreparationForTesting(
        in directory: URL
    ) throws -> PrivateInstallPreparationJournal? {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try readPreparation(directory: directory)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func persistAbandonmentForTesting(
        _ abandonment: PrivateInstallAbandonmentJournal,
        in directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        try persistAbandonment(
            abandonment,
            directory: directory,
            boundaryHook: boundaryHook
        )
    }

    @_spi(PrivateInstallCrashProbe)
    public static func readAbandonmentForTesting(
        in directory: URL
    ) throws -> PrivateInstallAbandonmentJournal? {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try readAbandonment(directory: directory)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func persistLifecycleJournalForTesting(
        _ lifecycle: PrivateInstallLifecycleJournal,
        in directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        try persistLifecycleJournal(
            lifecycle,
            directory: directory,
            boundaryHook: boundaryHook
        )
    }

    @_spi(PrivateInstallCrashProbe)
    public static func readLifecycleJournalForTesting(
        in directory: URL
    ) throws -> PrivateInstallLifecycleJournal? {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return try readLifecycleJournal(directory: directory)
    }

    @_spi(PrivateInstallCrashProbe)
    public static func archiveInterruptedRecordWriteForTesting(
        in directory: URL
    ) throws -> String? {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        let artifacts = try interruptedRecordArtifacts(in: directory)
        guard artifacts.count <= 1 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        guard let artifact = artifacts.first else { return nil }
        try archiveInterruptedRecordArtifact(artifact, from: directory)
        return "\(artifact.kind.rawValue):\(artifact.nonce)"
    }

    @_spi(PrivateInstallCrashProbe)
    public static func hasInterruptedRecordWriteForTesting(
        in directory: URL
    ) throws -> Bool {
        guard testingRecordDirectoryIsAllowed(directory) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        return try !interruptedRecordArtifacts(in: directory).isEmpty
    }

    @_spi(PrivateInstallCrashProbe)
    public static func interruptedRecordMetadataIsSafeForTesting(
        mode: mode_t,
        owner: uid_t,
        expectedOwner: uid_t,
        linkCount: nlink_t,
        size: off_t,
        maximumBytes: Int
    ) -> Bool {
        interruptedRecordMetadataIsSafe(
            mode: mode,
            owner: owner,
            expectedOwner: expectedOwner,
            linkCount: linkCount,
            size: size,
            maximumBytes: maximumBytes
        )
    }

    private static func testingRecordDirectoryIsAllowed(_ directory: URL) -> Bool {
        if directory.path.hasPrefix("/private/tmp/FulmarPrivateInstallCoordinatorTests."),
           directory.deletingLastPathComponent().path == "/private/tmp" {
            return true
        }
        let parent = directory.deletingLastPathComponent()
        let prefix = "/private/tmp/FulmarPrivateInstallCrashProbe."
        let suffix = String(parent.path.dropFirst(prefix.count))
        let recordLeaf = directory.lastPathComponent
        let validRecordLeaf: Bool
        if recordLeaf == "records" {
            validRecordLeaf = true
        } else {
            let prefixes = ["records.cancelled.", "records.retired."]
            if let recordPrefix = prefixes.first(where: { recordLeaf.hasPrefix($0) }) {
                let recordNonce = String(recordLeaf.dropFirst(recordPrefix.count))
                validRecordLeaf = recordNonce.utf8.count == 64 && isLowerHex(recordNonce)
            } else {
                validRecordLeaf = false
            }
        }
        return validRecordLeaf
            && parent.path.hasPrefix(prefix)
            && parent.deletingLastPathComponent().path == "/private/tmp"
            && suffix.utf8.count == 64
            && suffix.utf8.allSatisfy { byte in
                (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                    || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
            }
    }

    private static func resolveFailedHelperInvocation(
        original: PrivateInstallBundleProof,
        candidate: PrivateInstallBundleProof,
        staged: PrivateInstallBundleProof,
        hooks: PrivateInstallCoordinatorHooks
    ) throws {
        let currentProof = try hooks.inspectInstalled()
        let stageProof = try hooks.inspectStage()
        if currentProof == original,
           stageProof == proof(candidate, withIdentity: staged.identity) {
            return
        }
        guard currentProof == proof(candidate, withIdentity: staged.identity),
              stageProof == original else {
            throw PrivateInstallCoordinatorError.rollbackFailed
        }
        try recoverOriginal(
            original: original,
            candidate: candidate,
            staged: staged,
            hooks: hooks
        )
    }

    private static func recoverOriginal(
        original: PrivateInstallBundleProof,
        candidate: PrivateInstallBundleProof,
        staged: PrivateInstallBundleProof,
        hooks: PrivateInstallCoordinatorHooks
    ) throws {
        try hooks.proveApplicationsStopped()
        let currentBefore = try hooks.inspectInstalled()
        let stageBefore = try hooks.inspectStage()
        if currentBefore == proof(candidate, withIdentity: staged.identity),
           stageBefore == original {
            try hooks.invokeAtomicSwap(
                staged.identity,
                original.identity,
                original.attestation
            )
        } else if currentBefore != original
                    || stageBefore != proof(candidate, withIdentity: staged.identity) {
            throw PrivateInstallCoordinatorError.rollbackFailed
        }

        try hooks.proveApplicationsStopped()
        guard try hooks.inspectInstalled() == original,
              try hooks.inspectStage() == proof(candidate, withIdentity: staged.identity) else {
            throw PrivateInstallCoordinatorError.rollbackFailed
        }
    }

    private static func proof(
        _ proof: PrivateInstallBundleProof,
        withIdentity identity: AtomicInstallIdentity
    ) -> PrivateInstallBundleProof {
        PrivateInstallBundleProof(
            identity: identity,
            treeSHA256Hex: proof.treeSHA256Hex,
            attestation: proof.attestation
        )
    }

    private static func sameBundleContent(
        _ first: PrivateInstallBundleProof,
        _ second: PrivateInstallBundleProof
    ) -> Bool {
        first.treeSHA256Hex == second.treeSHA256Hex
            && first.attestation == second.attestation
    }

    private static func validateReceiptShape(
        _ receipt: PrivateInstallCoordinatorReceipt
    ) throws {
        guard receipt.schemaVersion == PrivateInstallCoordinatorReceipt.schemaVersion,
              receipt.committedAtUnixSeconds > 0,
              (try? mappedStageLeaf(nonce: receipt.nonce)) != nil else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try validateProofShape(receipt.installed, failure: .rollbackInspectionFailed)
        try validateProofShape(receipt.retainedRollback, failure: .rollbackInspectionFailed)
        guard receipt.installed.identity != receipt.retainedRollback.identity,
              samePrivateSigner(
                receipt.installed.attestation,
                receipt.retainedRollback.attestation
              ) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    private static func validateJournalShape(
        _ journal: PrivateInstallRecoveryJournal
    ) throws {
        guard journal.schemaVersion == PrivateInstallRecoveryJournal.schemaVersion,
              journal.phase == .preparedForAtomicSwap,
              journal.preparedAtUnixSeconds > 0,
              (try? mappedStageLeaf(nonce: journal.nonce)) != nil else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try validateProofShape(
            journal.originalInstalled,
            failure: .rollbackInspectionFailed
        )
        try validateProofShape(
            journal.frozenCandidate,
            failure: .rollbackInspectionFailed
        )
        try validateProofShape(
            journal.stagedCandidate,
            failure: .rollbackInspectionFailed
        )
        guard samePrivateSigner(
                journal.originalInstalled.attestation,
                journal.frozenCandidate.attestation
              ),
              sameBundleContent(journal.frozenCandidate, journal.stagedCandidate),
              journal.originalInstalled.identity != journal.frozenCandidate.identity,
              journal.originalInstalled.identity != journal.stagedCandidate.identity,
              journal.frozenCandidate.identity != journal.stagedCandidate.identity,
              journal.originalInstalled.identity.device == journal.stagedCandidate.identity.device
        else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    private static func validatePreparationShape(
        _ preparation: PrivateInstallPreparationJournal
    ) throws {
        guard preparation.schemaVersion == PrivateInstallPreparationJournal.schemaVersion,
              preparation.phase == .preparedForStaging,
              preparation.preparedAtUnixSeconds > 0,
              preparation.stageLeaf == (try? mappedStageLeaf(nonce: preparation.nonce)) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try validateProofShape(
            preparation.originalInstalled,
            failure: .rollbackInspectionFailed
        )
        try validateProofShape(
            preparation.frozenCandidate,
            failure: .rollbackInspectionFailed
        )
        guard preparation.originalInstalled.identity != preparation.frozenCandidate.identity,
              samePrivateSigner(
                  preparation.originalInstalled.attestation,
                  preparation.frozenCandidate.attestation
              ) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    private static func validateAbandonmentShape(
        _ abandonment: PrivateInstallAbandonmentJournal
    ) throws {
        guard abandonment.schemaVersion == PrivateInstallAbandonmentJournal.schemaVersion,
              abandonment.preparedAtUnixSeconds > 0,
              abandonment.nonce == abandonment.preparation.nonce,
              abandonment.activeInstalled == abandonment.preparation.originalInstalled else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try validatePreparationShape(abandonment.preparation)
        if let opaque = abandonment.opaqueStage {
            guard opaque.identity.device != 0,
                  opaque.identity.inode != 0,
                  opaque.identity.owner == UInt32(geteuid()),
                  opaque.mode & UInt32(mode_t(S_IFMT)) == UInt32(mode_t(S_IFDIR)),
                  opaque.mode & 0o022 == 0,
                  opaque.linkCount >= 1 else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
        }
    }

    private static func validateLifecycleJournalShape(
        _ lifecycle: PrivateInstallLifecycleJournal
    ) throws {
        guard lifecycle.schemaVersion == PrivateInstallLifecycleJournal.schemaVersion,
              lifecycle.preparedAtUnixSeconds > 0,
              (try? mappedStageLeaf(nonce: lifecycle.nonce)) != nil,
              (try? mappedArchiveLeaf(
                  nonce: lifecycle.nonce,
                  operation: lifecycle.operation
              )) != nil else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        try validateProofShape(
            lifecycle.activeInstalled,
            failure: .rollbackInspectionFailed
        )
        try validateProofShape(
            lifecycle.retainedStage,
            failure: .rollbackInspectionFailed
        )
        guard lifecycle.activeInstalled.identity != lifecycle.retainedStage.identity,
              samePrivateSigner(
                  lifecycle.activeInstalled.attestation,
                  lifecycle.retainedStage.attestation
              ) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        switch lifecycle.operation {
        case .cancelOriginalActive:
            guard let journal = lifecycle.recoveryJournal,
                  lifecycle.receipt == nil,
                  journal.nonce == lifecycle.nonce,
                  lifecycle.activeInstalled == journal.originalInstalled,
                  lifecycle.retainedStage == journal.stagedCandidate else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            try validateJournalShape(journal)
        case .retireCommitted:
            guard let receipt = lifecycle.receipt,
                  receipt.nonce == lifecycle.nonce,
                  lifecycle.activeInstalled == receipt.installed,
                  lifecycle.retainedStage == receipt.retainedRollback else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            try validateReceiptShape(receipt)
            if let journal = lifecycle.recoveryJournal {
                try validateJournalShape(journal)
                guard journal.nonce == receipt.nonce,
                      journal.stagedCandidate == receipt.installed,
                      journal.originalInstalled == receipt.retainedRollback else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
            }
        }
    }

    private static func validateOptionalCandidate(
        _ candidate: PrivateInstallBundleProof?,
        expected: PrivateInstallBundleProof
    ) throws {
        guard let candidate else { return }
        try validateProofShape(candidate, failure: .rollbackInspectionFailed)
        guard sameBundleContent(candidate, expected) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    private static func validateProofShape(
        _ proof: PrivateInstallBundleProof,
        failure: PrivateInstallCoordinatorError
    ) throws {
        do {
            try proof.attestation.validateShape()
        } catch {
            throw failure
        }
        guard proof.identity.device != 0,
              proof.identity.inode != 0,
              proof.identity.owner == UInt32(geteuid()),
              proof.treeSHA256Hex.utf8.count == 64,
              isLowerHex(proof.treeSHA256Hex),
              proof.attestation.identifier == expectedBundleIdentifier else {
            throw failure
        }
    }

    private static func samePrivateSigner(
        _ installed: PrivateStableApplicationAttestation,
        _ candidate: PrivateStableApplicationAttestation
    ) -> Bool {
        installed.identifier == candidate.identifier
            && installed.leafCertificateSHA256Hex == candidate.leafCertificateSHA256Hex
            && installed.designatedRequirement == candidate.designatedRequirement
    }

    private static func mappedStageLeaf(nonce: String) throws -> String {
        do {
            return try AtomicInstallSwap.stageLeaf(nonce: nonce)
        } catch {
            throw PrivateInstallCoordinatorError.invalidInvocation
        }
    }

    private static func mappedArchiveLeaf(
        nonce: String,
        operation: PrivateInstallLifecycleOperation
    ) throws -> String {
        _ = try mappedStageLeaf(nonce: nonce)
        switch operation {
        case .cancelOriginalActive:
            return ".Fulmar.private-cancelled.\(nonce).app"
        case .retireCommitted:
            return ".Fulmar.private-retired.\(nonce).app"
        }
    }

    private static func mappedRecordArchiveLeaf(
        nonce: String,
        operation: PrivateInstallLifecycleOperation
    ) throws -> String {
        _ = try mappedStageLeaf(nonce: nonce)
        switch operation {
        case .cancelOriginalActive:
            return "\(recordDirectoryLeaf).cancelled.\(nonce)"
        case .retireCommitted:
            return "\(recordDirectoryLeaf).retired.\(nonce)"
        }
    }

    private static func inspectBundle(
        at application: URL,
        failure: PrivateInstallCoordinatorError
    ) throws -> PrivateInstallBundleProof {
        do {
            let before = try safeDirectoryIdentity(at: application, failure: failure)
            let digest = try treeSHA256(at: application, failure: failure)
            let attestation = try AtomicInstallSwap.privateStableAttestation(at: application)
            let after = try safeDirectoryIdentity(at: application, failure: failure)
            guard before == after else { throw failure }
            return PrivateInstallBundleProof(
                identity: before,
                treeSHA256Hex: digest,
                attestation: attestation
            )
        } catch let error as PrivateInstallCoordinatorError {
            throw error
        } catch {
            throw failure
        }
    }

    private static func inspectOptionalBundle(
        at application: URL,
        failure: PrivateInstallCoordinatorError
    ) throws -> PrivateInstallBundleProof? {
        var metadata = stat()
        errno = 0
        if lstat(application.path, &metadata) != 0 {
            guard errno == ENOENT else { throw failure }
            return nil
        }
        return try inspectBundle(at: application, failure: failure)
    }

    private static func safeDirectoryIdentity(
        at url: URL,
        failure: PrivateInstallCoordinatorError
    ) throws -> AtomicInstallIdentity {
        guard url.path.hasPrefix("/"),
              url.path.utf8.count <= 4_096,
              !url.path.contains("\0"),
              url.path.split(separator: "/", omittingEmptySubsequences: false)
                .dropFirst()
                .allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw failure
        }
        guard let canonical = realpath(url.path, nil) else { throw failure }
        defer { free(canonical) }
        guard String(cString: canonical) == url.path else { throw failure }
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0 else { throw failure }
        guard metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else { throw failure }
        guard metadata.st_uid == geteuid() else { throw failure }
        guard metadata.st_mode & 0o022 == 0 else { throw failure }
        guard metadata.st_ino != 0 else { throw failure }
        return AtomicInstallIdentity(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(metadata.st_ino),
            owner: UInt32(metadata.st_uid)
        )
    }

    private static func stageProductionCandidate(from source: URL, to destination: URL) throws {
        let applications = destination.deletingLastPathComponent()
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: applications.path)
        } catch {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        guard !names.contains(where: { $0.hasPrefix(".Fulmar.install-stage.") }) else {
            // A successful install deliberately retains exactly one hidden stage
            // as rollback. It must be explicitly reviewed and removed before a
            // later private install; the coordinator never accumulates or
            // guesses which rollback bundle is disposable.
            throw PrivateInstallCoordinatorError.stageAlreadyExists
        }
        var destinationMetadata = stat()
        errno = 0
        guard lstat(destination.path, &destinationMetadata) != 0, errno == ENOENT else {
            throw PrivateInstallCoordinatorError.stageAlreadyExists
        }
        let flags = copyfile_flags_t(
            COPYFILE_ALL
                | COPYFILE_RECURSIVE
                | COPYFILE_CLONE
                | COPYFILE_NOFOLLOW_SRC
                | COPYFILE_NOFOLLOW_DST
        )
        guard copyfile(source.path, destination.path, nil, flags) == 0 else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        do {
            var sync = DurableBundleSyncState(root: destination)
            try sync.commit()
        } catch {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
    }

    private static func opaqueAbandonmentLeaf(nonce: String) throws -> String {
        _ = try mappedStageLeaf(nonce: nonce)
        return ".Fulmar.private-abandoned.\(nonce).app"
    }

    private static func inspectOptionalOpaqueStage(
        at url: URL
    ) throws -> PrivateInstallOpaqueStageIdentity? {
        var before = stat()
        errno = 0
        guard lstat(url.path, &before) == 0 else {
            if errno == ENOENT { return nil }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        var after = stat()
        guard before.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              before.st_uid == geteuid(),
              before.st_mode & 0o022 == 0,
              before.st_ino != 0,
              lstat(url.path, &after) == 0,
              stableNode(before, after) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return PrivateInstallOpaqueStageIdentity(
            identity: AtomicInstallIdentity(
                device: UInt64(truncatingIfNeeded: before.st_dev),
                inode: UInt64(before.st_ino),
                owner: UInt32(before.st_uid)
            ),
            mode: UInt32(before.st_mode),
            group: UInt32(before.st_gid),
            linkCount: UInt64(before.st_nlink)
        )
    }

    private static func inspectProductionAbandonment(
        _ abandonment: PrivateInstallAbandonmentJournal
    ) throws -> PrivateInstallRecoveryInspection {
        try validateAbandonmentShape(abandonment)
        let applications = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let stage = applications.appendingPathComponent(
            abandonment.preparation.stageLeaf,
            isDirectory: true
        )
        let archiveLeaf = try opaqueAbandonmentLeaf(nonce: abandonment.nonce)
        let archive = applications.appendingPathComponent(archiveLeaf, isDirectory: true)
        let stageIdentity = try inspectOptionalOpaqueStage(at: stage)
        let archiveIdentity = try inspectOptionalOpaqueStage(at: archive)
        let state: PrivateInstallRecoveryState
        if stageIdentity == abandonment.opaqueStage, archiveIdentity == nil {
            state = .abandonmentPrepared
        } else if stageIdentity == nil, archiveIdentity == abandonment.opaqueStage,
                  abandonment.opaqueStage != nil {
            state = .abandonmentArchived
        } else if abandonment.opaqueStage == nil,
                  stageIdentity == nil,
                  archiveIdentity == nil {
            state = .abandonmentArchived
        } else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let installed = try inspectBundle(
            at: URL(fileURLWithPath: installedApplicationPath, isDirectory: true),
            failure: .rollbackInspectionFailed
        )
        guard installed == abandonment.activeInstalled else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return PrivateInstallRecoveryInspection(
            state: state,
            preparationJournal: abandonment.preparation,
            journal: nil,
            receipt: nil,
            stagePath: state == .abandonmentPrepared && abandonment.opaqueStage != nil
                ? stage.path : nil,
            archivePath: state == .abandonmentArchived && abandonment.opaqueStage != nil
                ? archive.path : nil,
            candidateState: nil
        )
    }

    private static func archiveOpaqueStage(
        _ abandonment: PrivateInstallAbandonmentJournal,
        stageURL: URL
    ) throws {
        guard let expected = abandonment.opaqueStage else {
            guard try inspectOptionalOpaqueStage(at: stageURL) == nil else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            return
        }
        let parent = stageURL.deletingLastPathComponent()
        let archiveLeaf = try opaqueAbandonmentLeaf(nonce: abandonment.nonce)
        let archiveURL = parent.appendingPathComponent(archiveLeaf, isDirectory: true)
        if try inspectOptionalOpaqueStage(at: stageURL) == nil {
            guard try inspectOptionalOpaqueStage(at: archiveURL) == expected else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            return
        }
        guard try inspectOptionalOpaqueStage(at: stageURL) == expected,
              try inspectOptionalOpaqueStage(at: archiveURL) == nil else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        let descriptor = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw PrivateInstallCoordinatorError.lifecycleFailed }
        defer { _ = Darwin.close(descriptor) }
        guard stageURL.lastPathComponent.withCString({ source in
            archiveLeaf.withCString { destination in
                renameatx_np(descriptor, source, descriptor, destination, UInt32(RENAME_EXCL))
            }
        }) == 0,
        Darwin.fsync(descriptor) == 0,
        try inspectOptionalOpaqueStage(at: stageURL) == nil,
        try inspectOptionalOpaqueStage(at: archiveURL) == expected else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func productionHelperURL() throws -> URL {
        guard let executable = realpath(CommandLine.arguments[0], nil) else {
            throw PrivateInstallCoordinatorError.helperUnavailable
        }
        defer { free(executable) }
        let coordinator = URL(fileURLWithPath: String(cString: executable), isDirectory: false)
        let helper = coordinator.deletingLastPathComponent()
            .appendingPathComponent(helperLeaf, isDirectory: false)
        _ = try safeHelperIdentity(at: helper)
        return helper
    }

    private static func safeHelperIdentity(at helper: URL) throws -> AtomicInstallIdentity {
        var metadata = stat()
        guard lstat(helper.path, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o022 == 0,
              metadata.st_mode & 0o111 != 0,
              metadata.st_nlink == 1,
              metadata.st_ino != 0 else {
            throw PrivateInstallCoordinatorError.helperUnavailable
        }
        return AtomicInstallIdentity(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(metadata.st_ino),
            owner: UInt32(metadata.st_uid)
        )
    }

    private static func invokeProductionHelper(
        helperURL: URL,
        nonce: String,
        expectedCurrent: AtomicInstallIdentity,
        expectedStage: AtomicInstallIdentity,
        expectedCandidate: PrivateStableApplicationAttestation
    ) throws {
        let helperBefore = try safeHelperIdentity(at: helperURL)
        let process = Process()
        process.executableURL = helperURL
        process.arguments = [
            "--nonce", nonce,
            "--current-device", String(expectedCurrent.device),
            "--current-inode", String(expectedCurrent.inode),
            "--stage-device", String(expectedStage.device),
            "--stage-inode", String(expectedStage.inode),
            "--candidate-attestation", try expectedCandidate.encodedArgument()
        ]
        process.environment = ["PATH": "/usr/bin:/bin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            throw PrivateInstallCoordinatorError.helperFailed
        }

        let deadline = Date().addingTimeInterval(30)
        while process.isRunning, Date() < deadline {
            usleep(10_000)
        }
        if process.isRunning {
            process.terminate()
            let terminationDeadline = Date().addingTimeInterval(2)
            while process.isRunning, Date() < terminationDeadline {
                usleep(10_000)
            }
            if process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
                let reapDeadline = DispatchTime.now().uptimeNanoseconds &+ 2_000_000_000
                var status: Int32 = 0
                while DispatchTime.now().uptimeNanoseconds < reapDeadline {
                    let waited = Darwin.waitpid(process.processIdentifier, &status, WNOHANG)
                    if waited == process.processIdentifier
                        || (waited < 0 && errno == ECHILD) {
                        break
                    }
                    if waited < 0, errno != EINTR { break }
                    Darwin.usleep(10_000)
                }
            }
            throw PrivateInstallCoordinatorError.helperFailed
        }
        guard process.terminationReason == .exit,
              process.terminationStatus == 0,
              try safeHelperIdentity(at: helperURL) == helperBefore else {
            throw PrivateInstallCoordinatorError.helperFailed
        }
    }

    private static func productionApplicationsAreStopped(
        additionalBundleURLs: [URL]
    ) -> Bool {
        if NSRunningApplication.runningApplications(
            withBundleIdentifier: expectedBundleIdentifier
        ).contains(where: { !$0.isTerminated }) {
            return false
        }
        let protectedPrefixes = [
            "\(installedApplicationPath)/",
            "\(frozenCandidatePath)/"
        ] + additionalBundleURLs.map { "\($0.path)/" }
        var processIdentifiers = [pid_t](repeating: 0, count: 65_536)
        let count = proc_listallpids(
            &processIdentifiers,
            Int32(processIdentifiers.count * MemoryLayout<pid_t>.size)
        )
        guard count >= 0, count <= processIdentifiers.count else { return false }
        var pathBytes = [CChar](repeating: 0, count: 4_096)
        for processIdentifier in processIdentifiers.prefix(Int(count)) where processIdentifier > 1 {
            pathBytes.withUnsafeMutableBufferPointer { buffer in
                buffer.initialize(repeating: 0)
            }
            let length = proc_pidpath(
                processIdentifier,
                &pathBytes,
                UInt32(pathBytes.count)
            )
            guard length > 0 else { continue }
            let executable = String(cString: pathBytes)
            if protectedPrefixes.contains(where: { executable.hasPrefix($0) }) {
                return false
            }
        }
        return true
    }

    private static func persistProductionReceipt(
        _ receipt: PrivateInstallCoordinatorReceipt
    ) throws {
        let applicationSupport = try productionApplicationSupportDirectory()
        let receipts = applicationSupport.appendingPathComponent(
            ".Fulmar Private Install Receipts",
            isDirectory: true
        )
        try createOwnerPrivateDirectoryIfNeeded(receipts)
        try persistReceipt(receipt, directory: receipts)
    }

    private static func persistProductionJournal(
        _ journal: PrivateInstallRecoveryJournal
    ) throws {
        let applicationSupport = try productionApplicationSupportDirectory()
        let receipts = applicationSupport.appendingPathComponent(
            ".Fulmar Private Install Receipts",
            isDirectory: true
        )
        try createOwnerPrivateDirectoryIfNeeded(receipts)
        try persistJournal(journal, directory: receipts)
    }

    private static func persistProductionPreparation(
        _ preparation: PrivateInstallPreparationJournal
    ) throws {
        let applicationSupport = try productionApplicationSupportDirectory()
        let receipts = applicationSupport.appendingPathComponent(
            ".Fulmar Private Install Receipts",
            isDirectory: true
        )
        try createOwnerPrivateDirectoryIfNeeded(receipts)
        try persistPreparation(preparation, directory: receipts)
    }

    private static func productionRecoveryHooks(
        installedURL: URL,
        candidateURL: URL,
        receiptDirectory: URL?,
        helperURL: URL? = nil
    ) -> PrivateInstallRecoveryHooks {
        PrivateInstallRecoveryHooks(
            loadJournal: {
                guard let receiptDirectory else { return nil }
                return try readJournal(directory: receiptDirectory)
            },
            loadReceipt: {
                guard let receiptDirectory else { return nil }
                return try readReceipt(directory: receiptDirectory)
            },
            loadLifecycleJournal: {
                guard let receiptDirectory else { return nil }
                return try readLifecycleJournal(directory: receiptDirectory)
            },
            stageLeaves: {
                try productionStageLeaves()
            },
            archiveLeaves: {
                try productionArchiveLeaves()
            },
            inspectInstalled: {
                try inspectBundle(at: installedURL, failure: .rollbackInspectionFailed)
            },
            inspectStage: { stageLeaf in
                try inspectBundle(
                    at: URL(fileURLWithPath: "/Applications", isDirectory: true)
                        .appendingPathComponent(stageLeaf, isDirectory: true),
                    failure: .rollbackInspectionFailed
                )
            },
            inspectArchive: { archiveLeaf in
                try inspectBundle(
                    at: URL(fileURLWithPath: "/Applications", isDirectory: true)
                        .appendingPathComponent(archiveLeaf, isDirectory: true),
                    failure: .rollbackInspectionFailed
                )
            },
            inspectCandidateIfPresent: {
                try inspectOptionalBundle(at: candidateURL, failure: .rollbackInspectionFailed)
            },
            proveApplicationsStopped: {
                guard let receiptDirectory else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                let journal = try readJournal(directory: receiptDirectory)
                let preparation = try readPreparation(directory: receiptDirectory)
                let receipt = try readReceipt(directory: receiptDirectory)
                let lifecycle = try readLifecycleJournal(directory: receiptDirectory)
                guard let nonce = lifecycle?.nonce
                    ?? journal?.nonce
                    ?? receipt?.nonce
                    ?? preparation?.nonce else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                let stageURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
                    .appendingPathComponent(
                        try mappedStageLeaf(nonce: nonce),
                        isDirectory: true
                    )
                var additional = [stageURL]
                if let lifecycle {
                    additional.append(
                        URL(fileURLWithPath: "/Applications", isDirectory: true)
                            .appendingPathComponent(
                                try mappedArchiveLeaf(
                                    nonce: lifecycle.nonce,
                                    operation: lifecycle.operation
                                ),
                                isDirectory: true
                            )
                    )
                }
                guard productionApplicationsAreStopped(
                    additionalBundleURLs: additional
                ) else {
                    throw PrivateInstallCoordinatorError.applicationRunning
                }
            },
            invokeAtomicSwap: { expectedCurrent, expectedStage, expectedCandidate in
                guard let helperURL,
                      let receiptDirectory,
                      let journal = try readJournal(directory: receiptDirectory) else {
                    throw PrivateInstallCoordinatorError.helperUnavailable
                }
                try invokeProductionHelper(
                    helperURL: helperURL,
                    nonce: journal.nonce,
                    expectedCurrent: expectedCurrent,
                    expectedStage: expectedStage,
                    expectedCandidate: expectedCandidate
                )
            },
            persistReceipt: { receipt in
                guard let receiptDirectory else {
                    throw PrivateInstallCoordinatorError.receiptFailed
                }
                try persistReceipt(receipt, directory: receiptDirectory)
            },
            persistLifecycleJournal: { lifecycle in
                guard let receiptDirectory else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                try persistLifecycleJournal(lifecycle, directory: receiptDirectory)
            },
            archiveStage: { stageLeaf, archiveLeaf, expected in
                try archiveProductionStage(
                    stageLeaf: stageLeaf,
                    archiveLeaf: archiveLeaf,
                    expected: expected
                )
            },
            proveArchiveDurable: { archiveLeaf, expected in
                try proveProductionArchiveDurable(
                    archiveLeaf: archiveLeaf,
                    expected: expected
                )
            },
            archiveRecordDirectory: { lifecycle in
                guard let receiptDirectory else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                try archiveProductionRecordDirectory(
                    receiptDirectory,
                    lifecycle: lifecycle
                )
            },
            loadPreparation: {
                guard let receiptDirectory else { return nil }
                return try readPreparation(directory: receiptDirectory)
            },
            persistJournal: { journal in
                guard let receiptDirectory else {
                    throw PrivateInstallCoordinatorError.journalFailed
                }
                try persistJournal(journal, directory: receiptDirectory)
            },
            stageCandidate: {
                guard let receiptDirectory,
                      let preparation = try readPreparation(directory: receiptDirectory) else {
                    throw PrivateInstallCoordinatorError.stagingFailed
                }
                let stageURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
                    .appendingPathComponent(preparation.stageLeaf, isDirectory: true)
                try stageProductionCandidate(from: candidateURL, to: stageURL)
            },
            inspectOpaqueStage: { stageLeaf in
                try inspectOptionalOpaqueStage(
                    at: URL(fileURLWithPath: "/Applications", isDirectory: true)
                        .appendingPathComponent(stageLeaf, isDirectory: true)
                )
            }
        )
    }

    private static func productionApplicationSupportDirectory() throws -> URL {
        try productionApplicationSupportDirectory(
            homeDirectory: URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
        )
    }

    /// Accepts a macOS login home at any canonical absolute location while
    /// retaining the private installer's path-replacement boundary. Every
    /// ancestor must be a real directory owned by root or the current account
    /// and must not be group/world writable; a nonstandard ancestry must also
    /// be free of extended ACLs. The home, Library, and Application Support
    /// directories must additionally be owned by the current account. This can
    /// admit a structurally safe mobile/external home without treating an
    /// attacker-controlled mount, ACL, writable ancestor, or symlink alias as
    /// a receipt authority.
    private static func productionApplicationSupportDirectory(
        homeDirectory suppliedHome: URL
    ) throws -> URL {
        let home = suppliedHome
        let path = home.path
        let components = path.components(separatedBy: "/")
        guard home.isFileURL,
              path.hasPrefix("/"), path != "/", !path.hasSuffix("/"),
              path.utf8.count <= 4_096,
              components.first == "",
              components.dropFirst().allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".."
              }),
              let canonicalHome = realpath(path, nil) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        defer { free(canonicalHome) }
        guard String(cString: canonicalHome) == path else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        let requiresACLFreeAncestry = !isConventionalUsersHome(path)
        try validateProductionHomeAncestry(
            home,
            requiresNoExtendedACL: requiresACLFreeAncestry
        )
        try validateOwnerPrivateDirectory(
            home,
            exactMode: nil,
            requiresNoExtendedACL: requiresACLFreeAncestry
        )
        let library = home.appendingPathComponent("Library", isDirectory: true)
        let applicationSupport = library.appendingPathComponent(
            "Application Support",
            isDirectory: true
        )
        try validateOwnerPrivateDirectory(
            library,
            exactMode: nil,
            requiresNoExtendedACL: requiresACLFreeAncestry
        )
        try validateOwnerPrivateDirectory(
            applicationSupport,
            exactMode: nil,
            requiresNoExtendedACL: requiresACLFreeAncestry
        )
        return applicationSupport
    }

    private static func isConventionalUsersHome(_ path: String) -> Bool {
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        return components.count == 2 && components.first == "Users"
    }

    private static func validateProductionHomeAncestry(
        _ home: URL,
        requiresNoExtendedACL: Bool
    ) throws {
        var cursor = ""
        for component in home.path.split(separator: "/", omittingEmptySubsequences: true) {
            cursor += "/" + component
            var metadata = stat()
            guard lstat(cursor, &metadata) == 0,
                  metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
                  metadata.st_uid == 0 || metadata.st_uid == geteuid(),
                  metadata.st_mode & 0o022 == 0,
                  !requiresNoExtendedACL
                    || directoryHasNoExtendedACL(at: cursor, matching: metadata) else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
        }
    }

    private static func directoryHasNoExtendedACL(
        at path: String,
        matching metadata: stat
    ) -> Bool {
        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else { return false }
        defer { _ = Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == metadata.st_dev,
              opened.st_ino == metadata.st_ino,
              (try? descriptorHasNoExtendedACL(descriptor)) == true else {
            return false
        }
        return true
    }

    private static func productionReceiptDirectory(
        requireExisting: Bool
    ) throws -> URL? {
        let directory = try productionApplicationSupportDirectory().appendingPathComponent(
            ".Fulmar Private Install Receipts",
            isDirectory: true
        )
        var metadata = stat()
        errno = 0
        if lstat(directory.path, &metadata) != 0 {
            guard errno == ENOENT, !requireExisting else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            return nil
        }
        do {
            try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
        } catch {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return directory
    }

    static func reconcileInterruptedRecordWrite(
        in directory: URL,
        hooks: PrivateInstallRecoveryHooks
    ) throws {
        do {
            try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
            let temporary = try interruptedRecordArtifacts(in: directory)
            guard temporary.count <= 1 else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }

            let preparation = try hooks.loadPreparation()
            let abandonment = try readAbandonment(directory: directory)
            let journal = try hooks.loadJournal()
            let receipt = try hooks.loadReceipt()
            let lifecycle = try hooks.loadLifecycleJournal()
            let stageLeaves = try hooks.stageLeaves()
            let allArchived = try interruptedRecordArchives(
                in: directory.deletingLastPathComponent()
            )
            let recordNonces = Set(
                [preparation?.nonce, abandonment?.nonce, journal?.nonce, receipt?.nonce, lifecycle?.nonce]
                    .compactMap { $0 }
                    + temporary.map(\.nonce)
            )
            guard recordNonces.count <= 1 else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            let stageNonce: String?
            if stageLeaves.isEmpty {
                stageNonce = nil
            } else if stageLeaves.count == 1 {
                stageNonce = try nonceFromStageLeaf(stageLeaves[0])
            } else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            // A previous recovery process may already have moved the sole
            // O_EXCL temporary artifact into the durable parent archive and
            // then died before reconstructing its canonical record. In that
            // state the archive itself is the only nonce-bearing evidence.
            // Accept it only when it is unique; multiple archive nonces are
            // deliberately ambiguous and remain untouched.
            let archivedNonces = Set(allArchived.map(\.nonce))
            let knownNonce = recordNonces.first ?? stageNonce
            let nonce: String
            if let knownNonce {
                nonce = knownNonce
            } else {
                guard archivedNonces.count <= 1 else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
                guard let archivedNonce = archivedNonces.first else { return }
                nonce = archivedNonce
            }
            guard stageNonce == nil || stageNonce == nonce else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }

            let archived = allArchived.filter { $0.nonce == nonce }
            let matchingTemporary = temporary.filter { $0.nonce == nonce }
            guard matchingTemporary.count == temporary.count,
                  archived.count <= 1,
                  !(matchingTemporary.count == 1 && archived.count == 1),
                  let artifact = matchingTemporary.first ?? archived.first else {
                if temporary.isEmpty, archived.isEmpty { return }
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }

            let stageLeaf = try mappedStageLeaf(nonce: nonce)
            guard stageLeaves.isEmpty || stageLeaves == [stageLeaf] else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            try hooks.proveApplicationsStopped()

            enum Reconstruction {
                case none
                case preparation(PrivateInstallPreparationJournal)
                case abandonment(PrivateInstallAbandonmentJournal)
                case journal(PrivateInstallRecoveryJournal)
                case receipt(PrivateInstallCoordinatorReceipt)
                case lifecycle(PrivateInstallLifecycleJournal)
            }
            let reconstruction: Reconstruction
            switch artifact.kind {
            case .abandonment:
                if let abandonment {
                    guard abandonment.nonce == nonce else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .none
                } else {
                    guard let preparation,
                          journal == nil, receipt == nil, lifecycle == nil else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    let active = try hooks.inspectInstalled()
                    guard active == preparation.originalInstalled else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .abandonment(
                        PrivateInstallAbandonmentJournal(
                            nonce: nonce,
                            preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                            preparation: preparation,
                            activeInstalled: active,
                            opaqueStage: try hooks.inspectOpaqueStage(stageLeaf)
                        )
                    )
                }
            case .preparation:
                if let preparation {
                    guard preparation.nonce == nonce else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .none
                } else {
                    guard journal == nil, receipt == nil, lifecycle == nil,
                          let candidate = try hooks.inspectCandidateIfPresent() else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    let original = try hooks.inspectInstalled()
                    try validateProofShape(original, failure: .interruptedRecordWrite)
                    try validateProofShape(candidate, failure: .interruptedRecordWrite)
                    guard samePrivateSigner(original.attestation, candidate.attestation),
                          original.identity != candidate.identity else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .preparation(
                        PrivateInstallPreparationJournal(
                            nonce: nonce,
                            stageLeaf: stageLeaf,
                            preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                            originalInstalled: original,
                            frozenCandidate: candidate
                        )
                    )
                }
            case .journal:
                if let journal {
                    guard journal.nonce == nonce else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .none
                } else {
                    guard receipt == nil, lifecycle == nil,
                          let preparation,
                          let candidate = try hooks.inspectCandidateIfPresent() else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    let original = try hooks.inspectInstalled()
                    let staged = try hooks.inspectStage(stageLeaf)
                    try validateProofShape(original, failure: .interruptedRecordWrite)
                    try validateProofShape(candidate, failure: .interruptedRecordWrite)
                    try validateProofShape(staged, failure: .interruptedRecordWrite)
                    guard preparation.nonce == nonce,
                          preparation.stageLeaf == stageLeaf,
                          preparation.originalInstalled == original,
                          preparation.frozenCandidate == candidate,
                          samePrivateSigner(original.attestation, candidate.attestation),
                          sameBundleContent(candidate, staged),
                          original.identity != candidate.identity,
                          original.identity != staged.identity,
                          candidate.identity != staged.identity,
                          original.identity.device == staged.identity.device else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .journal(
                        PrivateInstallRecoveryJournal(
                            nonce: nonce,
                            preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                            originalInstalled: original,
                            frozenCandidate: candidate,
                            stagedCandidate: staged
                        )
                    )
                }
            case .receipt:
                if let receipt {
                    guard receipt.nonce == nonce else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .none
                } else {
                    guard let journal, lifecycle == nil else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    let installed = try hooks.inspectInstalled()
                    let retained = try hooks.inspectStage(stageLeaf)
                    try validateOptionalCandidate(
                        try hooks.inspectCandidateIfPresent(),
                        expected: journal.frozenCandidate
                    )
                    guard installed == journal.stagedCandidate,
                          retained == journal.originalInstalled else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .receipt(
                        PrivateInstallCoordinatorReceipt(
                            nonce: nonce,
                            committedAtUnixSeconds: hooks.nowUnixSeconds(),
                            installed: installed,
                            retainedRollback: retained
                        )
                    )
                }
            case .lifecycle:
                if let lifecycle {
                    guard lifecycle.nonce == nonce else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                    reconstruction = .none
                } else {
                    let installed = try hooks.inspectInstalled()
                    let retained = try hooks.inspectStage(stageLeaf)
                    if let receipt {
                        guard installed == receipt.installed,
                              retained == receipt.retainedRollback else {
                            throw PrivateInstallCoordinatorError.interruptedRecordWrite
                        }
                        reconstruction = .lifecycle(
                            PrivateInstallLifecycleJournal(
                                operation: .retireCommitted,
                                nonce: nonce,
                                preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                                activeInstalled: installed,
                                retainedStage: retained,
                                recoveryJournal: journal,
                                receipt: receipt
                            )
                        )
                    } else if let journal {
                        guard installed == journal.originalInstalled,
                              retained == journal.stagedCandidate else {
                            throw PrivateInstallCoordinatorError.interruptedRecordWrite
                        }
                        reconstruction = .lifecycle(
                            PrivateInstallLifecycleJournal(
                                operation: .cancelOriginalActive,
                                nonce: nonce,
                                preparedAtUnixSeconds: hooks.nowUnixSeconds(),
                                activeInstalled: installed,
                                retainedStage: retained,
                                recoveryJournal: journal,
                                receipt: nil
                            )
                        )
                    } else {
                        throw PrivateInstallCoordinatorError.interruptedRecordWrite
                    }
                }
            }

            // When the canonical record already exists, prove the complete
            // read-only transaction state before moving stale temporary
            // evidence. Use the bounded artifact-specific proof here; the
            // repeated record, stage, process and bundle checks below bind the
            // post-rename state without weakening the proof.
            if case .none = reconstruction {
                try validateCanonicalRecordStateForReconciliation(
                    kind: artifact.kind,
                    preparation: preparation,
                    abandonment: abandonment,
                    journal: journal,
                    receipt: receipt,
                    lifecycle: lifecycle,
                    stageLeaf: stageLeaf,
                    hooks: hooks
                )
            }

            if !artifact.archived {
                try archiveInterruptedRecordArtifact(artifact, from: directory)
            }
            let archivedArtifact = InterruptedPrivateInstallRecordArtifact(
                kind: artifact.kind,
                nonce: artifact.nonce,
                leaf: "\(interruptedRecordArchivePrefix)\(artifact.kind.rawValue).\(artifact.nonce)",
                archived: true
            )
            try proveInterruptedRecordArchiveDurable(
                archivedArtifact,
                in: directory.deletingLastPathComponent()
            )
            try hooks.proveApplicationsStopped()
            guard try hooks.loadPreparation() == preparation,
                  try readAbandonment(directory: directory) == abandonment,
                  try hooks.loadJournal() == journal,
                  try hooks.loadReceipt() == receipt,
                  try hooks.loadLifecycleJournal() == lifecycle,
                  try hooks.stageLeaves() == stageLeaves else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            switch reconstruction {
            case .none:
                break
            case let .preparation(value):
                guard preparation == nil, journal == nil, receipt == nil, lifecycle == nil,
                      try hooks.inspectInstalled() == value.originalInstalled,
                      try hooks.inspectCandidateIfPresent() == value.frozenCandidate,
                      try hooks.stageLeaves() == stageLeaves else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
            case let .abandonment(value):
                guard abandonment == nil,
                      preparation == value.preparation,
                      journal == nil, receipt == nil, lifecycle == nil,
                      try hooks.inspectInstalled() == value.activeInstalled,
                      try hooks.inspectOpaqueStage(stageLeaf) == value.opaqueStage else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
            case let .journal(value):
                guard journal == nil, receipt == nil, lifecycle == nil,
                      try hooks.inspectInstalled() == value.originalInstalled,
                      try hooks.inspectCandidateIfPresent() == value.frozenCandidate,
                      try hooks.inspectStage(stageLeaf) == value.stagedCandidate else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
            case let .receipt(value):
                guard let journal,
                      receipt == nil,
                      lifecycle == nil,
                      try hooks.inspectInstalled() == value.installed,
                      try hooks.inspectStage(stageLeaf) == value.retainedRollback else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
                try validateOptionalCandidate(
                    try hooks.inspectCandidateIfPresent(),
                    expected: journal.frozenCandidate
                )
            case let .lifecycle(value):
                guard lifecycle == nil,
                      try hooks.inspectInstalled() == value.activeInstalled,
                      try hooks.inspectStage(stageLeaf) == value.retainedStage else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
                let expectedCandidate = receipt?.installed ?? journal?.frozenCandidate
                guard let expectedCandidate else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
                try validateOptionalCandidate(
                    try hooks.inspectCandidateIfPresent(),
                    expected: expectedCandidate
                )
            }
            switch reconstruction {
            case .none:
                break
            case let .preparation(value):
                try persistPreparation(value, directory: directory)
            case let .abandonment(value):
                try persistAbandonment(value, directory: directory)
            case let .journal(value):
                try persistJournal(value, directory: directory)
            case let .receipt(value):
                try persistReceipt(value, directory: directory)
            case let .lifecycle(value):
                try persistLifecycleJournal(value, directory: directory)
            }
        } catch let error as PrivateInstallCoordinatorError {
            if error == .interruptedRecordWrite { throw error }
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        } catch {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
    }

    private static func hasUnreconciledInterruptedRecordArchive(
        in directory: URL
    ) throws -> Bool {
        let stages = try productionStageLeaves()
        guard stages.count <= 1 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        if stages.isEmpty {
            let archives = try interruptedRecordArchives(
                in: directory.deletingLastPathComponent()
            )
            let unresolvedPreparations = try archives.filter { archive in
                switch archive.kind {
                case .preparation:
                    return try readPreparation(directory: directory)?.nonce != archive.nonce
                case .abandonment:
                    return try readAbandonment(directory: directory)?.nonce != archive.nonce
                case .journal, .receipt, .lifecycle:
                    return false
                }
            }
            guard unresolvedPreparations.count <= 1 else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            return !unresolvedPreparations.isEmpty
        }
        let stage = stages[0]
        let nonce = try nonceFromStageLeaf(stage)
        let archives = try interruptedRecordArchives(
            in: directory.deletingLastPathComponent()
        ).filter { $0.nonce == nonce }
        guard archives.count <= 1 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        guard let archive = archives.first else { return false }
        switch archive.kind {
        case .abandonment:
            return try readAbandonment(directory: directory) == nil
        case .preparation:
            return try readPreparation(directory: directory) == nil
        case .journal:
            return try readJournal(directory: directory) == nil
        case .receipt:
            return try readReceipt(directory: directory) == nil
        case .lifecycle:
            return try readLifecycleJournal(directory: directory) == nil
        }
    }

    private static func validateCanonicalRecordStateForReconciliation(
        kind: InterruptedPrivateInstallRecordKind,
        preparation: PrivateInstallPreparationJournal?,
        abandonment: PrivateInstallAbandonmentJournal?,
        journal: PrivateInstallRecoveryJournal?,
        receipt: PrivateInstallCoordinatorReceipt?,
        lifecycle: PrivateInstallLifecycleJournal?,
        stageLeaf: String,
        hooks: PrivateInstallRecoveryHooks
    ) throws {
        let installed = try hooks.inspectInstalled()
        let candidate = try hooks.inspectCandidateIfPresent()
        switch kind {
        case .preparation:
            guard let preparation,
                  installed == preparation.originalInstalled else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            try validateOptionalCandidate(candidate, expected: preparation.frozenCandidate)
        case .abandonment:
            guard let abandonment,
                  installed == abandonment.activeInstalled,
                  try hooks.inspectOpaqueStage(stageLeaf) == abandonment.opaqueStage else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
        case .journal:
            guard let journal else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            let stage = try hooks.inspectStage(stageLeaf)
            let originalPair = installed == journal.originalInstalled
                && stage == journal.stagedCandidate && receipt == nil
            let swappedPair = installed == journal.stagedCandidate
                && stage == journal.originalInstalled
                && (receipt == nil || (receipt?.installed == installed
                    && receipt?.retainedRollback == stage))
            guard originalPair || swappedPair else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            try validateOptionalCandidate(candidate, expected: journal.frozenCandidate)
        case .receipt:
            guard let receipt,
                  installed == receipt.installed,
                  try hooks.inspectStage(stageLeaf) == receipt.retainedRollback else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
        case .lifecycle:
            guard let lifecycle, installed == lifecycle.activeInstalled else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            let leaves = try hooks.stageLeaves()
            let archives = try hooks.archiveLeaves()
            let archiveLeaf = try mappedArchiveLeaf(
                nonce: lifecycle.nonce,
                operation: lifecycle.operation
            )
            if leaves == [stageLeaf] {
                guard try hooks.inspectStage(stageLeaf) == lifecycle.retainedStage else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
            } else if leaves.isEmpty, archives.contains(archiveLeaf) {
                guard try hooks.inspectArchive(archiveLeaf) == lifecycle.retainedStage else {
                    throw PrivateInstallCoordinatorError.interruptedRecordWrite
                }
            } else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
        }
    }

    private static func interruptedRecordArtifacts(
        in directory: URL
    ) throws -> [InterruptedPrivateInstallRecordArtifact] {
        try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        defer { _ = Darwin.close(descriptor) }
        let names = try descriptorDirectoryNames(descriptor, maximumCount: 8)
        let artifacts = try names.compactMap { name in
            try interruptedRecordArtifact(fromTemporaryLeaf: name)
        }
        let allowed = Set([
            abandonmentJournalLeaf,
            preparationJournalLeaf,
            receiptLeaf,
            journalLeaf,
            lifecycleJournalLeaf
        ])
            .union(artifacts.map(\.leaf))
        guard artifacts.count <= 1,
              Set(names).isSubset(of: allowed) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        for artifact in artifacts {
            _ = try validateInterruptedRecordFile(
                descriptor: descriptor,
                leaf: artifact.leaf,
                maximumBytes: artifact.kind.maximumBytes
            )
        }
        return artifacts
    }

    private static func interruptedRecordArchives(
        in parent: URL
    ) throws -> [InterruptedPrivateInstallRecordArtifact] {
        let descriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        defer { _ = Darwin.close(descriptor) }
        let names = try descriptorDirectoryNames(descriptor, maximumCount: 100_000)
        let matching = names.filter { $0.hasPrefix(interruptedRecordArchivePrefix) }
        guard matching.count <= 1_024 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        return try matching.map { name in
            guard let artifact = interruptedRecordArtifact(fromArchiveLeaf: name) else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            _ = try validateInterruptedRecordFile(
                descriptor: descriptor,
                leaf: name,
                maximumBytes: artifact.kind.maximumBytes
            )
            return artifact
        }
    }

    private static func interruptedRecordArtifact(
        fromTemporaryLeaf leaf: String
    ) throws -> InterruptedPrivateInstallRecordArtifact? {
        for kind in InterruptedPrivateInstallRecordKind.allCases
        where leaf.hasPrefix(kind.temporaryPrefix) && leaf.hasSuffix(".tmp") {
            let nonce = String(leaf.dropFirst(kind.temporaryPrefix.count).dropLast(4))
            guard nonce.utf8.count == 64, isLowerHex(nonce) else {
                throw PrivateInstallCoordinatorError.interruptedRecordWrite
            }
            return InterruptedPrivateInstallRecordArtifact(
                kind: kind,
                nonce: nonce,
                leaf: leaf,
                archived: false
            )
        }
        return nil
    }

    private static func interruptedRecordArtifact(
        fromArchiveLeaf leaf: String
    ) -> InterruptedPrivateInstallRecordArtifact? {
        for kind in InterruptedPrivateInstallRecordKind.allCases {
            let prefix = "\(interruptedRecordArchivePrefix)\(kind.rawValue)."
            guard leaf.hasPrefix(prefix) else { continue }
            let nonce = String(leaf.dropFirst(prefix.count))
            guard nonce.utf8.count == 64, isLowerHex(nonce) else { return nil }
            return InterruptedPrivateInstallRecordArtifact(
                kind: kind,
                nonce: nonce,
                leaf: leaf,
                archived: true
            )
        }
        return nil
    }

    private static func validateInterruptedRecordFile(
        descriptor: Int32,
        leaf: String,
        maximumBytes: Int
    ) throws -> stat {
        let file = leaf.withCString {
            openat(descriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard file >= 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        defer { _ = Darwin.close(file) }
        var before = stat()
        var after = stat()
        guard fstat(file, &before) == 0,
              interruptedRecordMetadataIsSafe(
                  mode: before.st_mode,
                  owner: before.st_uid,
                  expectedOwner: geteuid(),
                  linkCount: before.st_nlink,
                  size: before.st_size,
                  maximumBytes: maximumBytes
              ),
              try descriptorHasNoExtendedACL(file),
              fstat(file, &after) == 0,
              stableNode(before, after) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        return after
    }

    private static func interruptedRecordMetadataIsSafe(
        mode: mode_t,
        owner: uid_t,
        expectedOwner: uid_t,
        linkCount: nlink_t,
        size: off_t,
        maximumBytes: Int
    ) -> Bool {
        mode & mode_t(S_IFMT) == mode_t(S_IFREG)
            && owner == expectedOwner
            && mode & 0o7777 == 0o600
            && linkCount == 1
            && size >= 0
            && size <= maximumBytes
    }

    private static func archiveInterruptedRecordArtifact(
        _ artifact: InterruptedPrivateInstallRecordArtifact,
        from directory: URL
    ) throws {
        guard !artifact.archived else { return }
        let parent = directory.deletingLastPathComponent()
        let archiveLeaf = "\(interruptedRecordArchivePrefix)\(artifact.kind.rawValue).\(artifact.nonce)"
        let sourceDescriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        let parentDescriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard sourceDescriptor >= 0, parentDescriptor >= 0 else {
            if sourceDescriptor >= 0 { _ = Darwin.close(sourceDescriptor) }
            if parentDescriptor >= 0 { _ = Darwin.close(parentDescriptor) }
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        defer {
            _ = Darwin.close(sourceDescriptor)
            _ = Darwin.close(parentDescriptor)
        }
        var sourceDirectoryBefore = stat()
        var parentBefore = stat()
        guard fstat(sourceDescriptor, &sourceDirectoryBefore) == 0,
              fstat(parentDescriptor, &parentBefore) == 0,
              sourceDirectoryBefore.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              parentBefore.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              sourceDirectoryBefore.st_uid == geteuid(),
              parentBefore.st_uid == geteuid(),
              sourceDirectoryBefore.st_mode & 0o022 == 0,
              parentBefore.st_mode & 0o022 == 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        let validatedSource = try validateInterruptedRecordFile(
            descriptor: sourceDescriptor,
            leaf: artifact.leaf,
            maximumBytes: artifact.kind.maximumBytes
        )
        var source = stat()
        var destination = stat()
        errno = 0
        let destinationStatus = archiveLeaf.withCString {
            fstatat(parentDescriptor, $0, &destination, AT_SYMLINK_NOFOLLOW)
        }
        let destinationErrno = errno
        guard artifact.leaf.withCString({
                  fstatat(sourceDescriptor, $0, &source, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              stableNode(validatedSource, source),
              destinationStatus != 0,
              destinationErrno == ENOENT,
              artifact.leaf.withCString({ sourcePointer in
                  archiveLeaf.withCString { destinationPointer in
                      renameatx_np(
                          sourceDescriptor,
                          sourcePointer,
                          parentDescriptor,
                          destinationPointer,
                          UInt32(RENAME_EXCL)
                      )
                  }
              }) == 0,
              Darwin.fsync(sourceDescriptor) == 0,
              Darwin.fsync(parentDescriptor) == 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        var archived = stat()
        var staleSource = stat()
        var sourceDirectoryAfter = stat()
        var parentAfter = stat()
        errno = 0
        let staleStatus = artifact.leaf.withCString {
            fstatat(sourceDescriptor, $0, &staleSource, AT_SYMLINK_NOFOLLOW)
        }
        let staleErrno = errno
        guard staleStatus != 0,
              staleErrno == ENOENT,
              fstat(sourceDescriptor, &sourceDirectoryAfter) == 0,
              fstat(parentDescriptor, &parentAfter) == 0,
              stableDirectoryHandleAfterEntryMutation(
                  sourceDirectoryBefore,
                  sourceDirectoryAfter
              ),
              stableDirectoryHandleAfterEntryMutation(parentBefore, parentAfter),
              archiveLeaf.withCString({
                  fstatat(parentDescriptor, $0, &archived, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              stableRenamedRecord(source, archived) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
    }

    private static func proveInterruptedRecordArchiveDurable(
        _ artifact: InterruptedPrivateInstallRecordArtifact,
        in parent: URL
    ) throws {
        guard artifact.archived,
              interruptedRecordArtifact(fromArchiveLeaf: artifact.leaf) == artifact else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        let descriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        defer { _ = Darwin.close(descriptor) }
        var directoryBefore = stat()
        guard fstat(descriptor, &directoryBefore) == 0,
              directoryBefore.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              directoryBefore.st_uid == geteuid(),
              directoryBefore.st_mode & 0o022 == 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        let fileBefore = try validateInterruptedRecordFile(
            descriptor: descriptor,
            leaf: artifact.leaf,
            maximumBytes: artifact.kind.maximumBytes
        )
        guard Darwin.fsync(descriptor) == 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        let fileAfter = try validateInterruptedRecordFile(
            descriptor: descriptor,
            leaf: artifact.leaf,
            maximumBytes: artifact.kind.maximumBytes
        )
        var directoryAfter = stat()
        guard stableNode(fileBefore, fileAfter),
              fstat(descriptor, &directoryAfter) == 0,
              stableNode(directoryBefore, directoryAfter) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
    }

    private static func archiveProductionRecordDirectory(
        _ directory: URL,
        lifecycle: PrivateInstallLifecycleJournal
    ) throws {
        do {
            try validateLifecycleJournalShape(lifecycle)
            try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
            let preparation = try readPreparation(directory: directory)
            guard try readLifecycleJournal(directory: directory) == lifecycle,
                  try readJournal(directory: directory) == lifecycle.recoveryJournal,
                  try readReceipt(directory: directory) == lifecycle.receipt else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let expectedLeaves = Set(
                [lifecycleJournalLeaf]
                    + (preparation == nil
                        ? [] : [preparationJournalLeaf])
                    + (lifecycle.recoveryJournal == nil ? [] : [journalLeaf])
                    + (lifecycle.receipt == nil ? [] : [receiptLeaf])
            )
            let sourceDescriptor = Darwin.open(
                directory.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard sourceDescriptor >= 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            defer { _ = Darwin.close(sourceDescriptor) }
            var sourceBefore = stat()
            guard fstat(sourceDescriptor, &sourceBefore) == 0,
                  Set(try descriptorDirectoryNames(
                      sourceDescriptor,
                      maximumCount: 5
                  )) == expectedLeaves else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }

            let parent = directory.deletingLastPathComponent()
            let destinationLeaf = try mappedRecordArchiveLeaf(
                nonce: lifecycle.nonce,
                operation: lifecycle.operation
            )
            guard directory.lastPathComponent == recordDirectoryLeaf,
                  !(try productionRecordArchiveLeaves(in: parent)).contains(destinationLeaf) else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let parentDescriptor = Darwin.open(
                parent.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard parentDescriptor >= 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            defer { _ = Darwin.close(parentDescriptor) }
            var parentBefore = stat()
            var sourceAtParent = stat()
            guard fstat(parentDescriptor, &parentBefore) == 0,
                  recordDirectoryLeaf.withCString({
                      fstatat(
                          parentDescriptor,
                          $0,
                          &sourceAtParent,
                          AT_SYMLINK_NOFOLLOW
                      )
                  }) == 0,
                  stableDirectoryIdentity(sourceBefore, sourceAtParent) else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            var destinationAtParent = stat()
            errno = 0
            let destinationStatus = destinationLeaf.withCString {
                fstatat(
                    parentDescriptor,
                    $0,
                    &destinationAtParent,
                    AT_SYMLINK_NOFOLLOW
                )
            }
            let destinationErrno = errno
            guard destinationStatus != 0, destinationErrno == ENOENT else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            guard recordDirectoryLeaf.withCString({ sourcePointer in
                destinationLeaf.withCString { destinationPointer in
                    renameatx_np(
                        parentDescriptor,
                        sourcePointer,
                        parentDescriptor,
                        destinationPointer,
                        UInt32(RENAME_EXCL)
                    )
                }
            }) == 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            guard Darwin.fsync(parentDescriptor) == 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            var parentAfter = stat()
            var staleSource = stat()
            errno = 0
            let staleSourceStatus = recordDirectoryLeaf.withCString {
                fstatat(parentDescriptor, $0, &staleSource, AT_SYMLINK_NOFOLLOW)
            }
            let staleSourceErrno = errno
            var destinationAfter = stat()
            let destinationAfterStatus = destinationLeaf.withCString {
                fstatat(
                    parentDescriptor,
                    $0,
                    &destinationAfter,
                    AT_SYMLINK_NOFOLLOW
                )
            }
            guard fstat(parentDescriptor, &parentAfter) == 0,
                  stableDirectoryIdentity(parentBefore, parentAfter),
                  staleSourceStatus != 0,
                  staleSourceErrno == ENOENT,
                  destinationAfterStatus == 0,
                  stableDirectoryIdentity(sourceBefore, destinationAfter) else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let destination = parent.appendingPathComponent(
                destinationLeaf,
                isDirectory: true
            )
            try validateOwnerPrivateDirectory(destination, exactMode: 0o700)
            guard try readLifecycleJournal(directory: destination) == lifecycle,
                  try readPreparation(directory: destination) == preparation,
                  try readJournal(directory: destination) == lifecycle.recoveryJournal,
                  try readReceipt(directory: destination) == lifecycle.receipt else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        } catch let error as PrivateInstallCoordinatorError {
            if error == .lifecycleFailed { throw error }
            throw PrivateInstallCoordinatorError.lifecycleFailed
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func archiveAbandonmentRecordDirectory(
        _ directory: URL,
        abandonment: PrivateInstallAbandonmentJournal,
        sourceAlreadyArchived: Bool = false
    ) throws {
        try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
        guard try readPreparation(directory: directory) == abandonment.preparation,
              try readAbandonment(directory: directory) == abandonment else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        let sourceDescriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard sourceDescriptor >= 0 else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        defer { _ = Darwin.close(sourceDescriptor) }
        guard Set(try descriptorDirectoryNames(sourceDescriptor, maximumCount: 3))
            == Set([preparationJournalLeaf, abandonmentJournalLeaf]) else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        let parent = directory.deletingLastPathComponent()
        let destinationLeaf = "\(recordDirectoryLeaf).abandoned.\(abandonment.nonce)"
        let descriptor = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw PrivateInstallCoordinatorError.lifecycleFailed }
        defer { _ = Darwin.close(descriptor) }
        let markerLeaf = ".pending-private-abandonment-records.\(abandonment.nonce)"
        if !sourceAlreadyArchived {
            let marker = markerLeaf.withCString {
                openat(descriptor, $0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
            }
            if marker >= 0 {
                guard Darwin.fsync(marker) == 0 else {
                    _ = Darwin.close(marker)
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                _ = Darwin.close(marker)
                guard Darwin.fsync(descriptor) == 0 else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
            } else {
                guard errno == EEXIST else { throw PrivateInstallCoordinatorError.lifecycleFailed }
                var existing = stat()
                guard markerLeaf.withCString({
                    fstatat(descriptor, $0, &existing, AT_SYMLINK_NOFOLLOW)
                }) == 0,
                existing.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                existing.st_mode & 0o7777 == 0o600,
                existing.st_uid == geteuid(), existing.st_nlink == 1,
                existing.st_size == 0 else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
            }
        }
        var destination = stat()
        errno = 0
        let destinationStatus = destinationLeaf.withCString {
            fstatat(descriptor, $0, &destination, AT_SYMLINK_NOFOLLOW)
        }
        let destinationErrno = errno
        if !sourceAlreadyArchived {
            guard destinationStatus != 0,
                  destinationErrno == ENOENT,
                  recordDirectoryLeaf.withCString({ source in
                      destinationLeaf.withCString { target in
                          renameatx_np(descriptor, source, descriptor, target, UInt32(RENAME_EXCL))
                      }
                  }) == 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        } else {
            guard directory.lastPathComponent == destinationLeaf,
                  destinationStatus == 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        let archived = parent.appendingPathComponent(destinationLeaf, isDirectory: true)
        try validateOwnerPrivateDirectory(archived, exactMode: 0o700)
        guard try readPreparation(directory: archived) == abandonment.preparation,
              try readAbandonment(directory: archived) == abandonment else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        guard markerLeaf.withCString({ unlinkat(descriptor, $0, 0) }) == 0,
              Darwin.fsync(descriptor) == 0 else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func pendingProductionAbandonmentArchive()
        throws -> (directory: URL, journal: PrivateInstallAbandonmentJournal)? {
        let parent = try productionApplicationSupportDirectory()
        try validateOwnerPrivateDirectory(parent, exactMode: nil)
        let descriptor = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw PrivateInstallCoordinatorError.rollbackInspectionFailed }
        defer { _ = Darwin.close(descriptor) }
        let prefix = ".pending-private-abandonment-records."
        let markers = try descriptorDirectoryNames(descriptor, maximumCount: 100_000)
            .filter { $0.hasPrefix(prefix) }
        guard markers.count <= 1 else { throw PrivateInstallCoordinatorError.interruptedRecordWrite }
        guard let marker = markers.first else { return nil }
        let nonce = String(marker.dropFirst(prefix.count))
        _ = try mappedStageLeaf(nonce: nonce)
        var metadata = stat()
        guard marker.withCString({ fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW) }) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_mode & 0o7777 == 0o600,
              metadata.st_uid == geteuid(), metadata.st_nlink == 1, metadata.st_size == 0 else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        let leaf = "\(recordDirectoryLeaf).abandoned.\(nonce)"
        let directory = parent.appendingPathComponent(leaf, isDirectory: true)
        try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
        guard let journal = try readAbandonment(directory: directory), journal.nonce == nonce,
              try readPreparation(directory: directory) == journal.preparation else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        var repeated = stat()
        guard marker.withCString({
            fstatat(descriptor, $0, &repeated, AT_SYMLINK_NOFOLLOW)
        }) == 0, stableNode(metadata, repeated) else {
            throw PrivateInstallCoordinatorError.interruptedRecordWrite
        }
        return (directory, journal)
    }

    private static func productionRecordArchiveLeaves(in parent: URL) throws -> [String] {
        let descriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        defer { _ = Darwin.close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0 else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        let prefixes = [
            "\(recordDirectoryLeaf).cancelled.",
            "\(recordDirectoryLeaf).retired."
        ]
        let names = try descriptorDirectoryNames(descriptor, maximumCount: 100_000)
        let archives = names.filter { name in
            prefixes.contains { name.hasPrefix($0) }
        }.sorted()
        guard archives.count <= 1_024,
              archives.allSatisfy(validProductionRecordArchiveLeaf) else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              stableNode(before, after) else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        return archives
    }

    private static func validProductionRecordArchiveLeaf(_ leaf: String) -> Bool {
        let prefixes = [
            "\(recordDirectoryLeaf).cancelled.",
            "\(recordDirectoryLeaf).retired."
        ]
        guard let prefix = prefixes.first(where: { leaf.hasPrefix($0) }) else { return false }
        let nonce = String(leaf.dropFirst(prefix.count))
        return nonce.utf8.count == 64 && isLowerHex(nonce)
    }

    private static func createOwnerPrivateDirectoryIfNeeded(_ directory: URL) throws {
        var metadata = stat()
        if lstat(directory.path, &metadata) != 0 {
            guard errno == ENOENT else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
            let parent = directory.deletingLastPathComponent()
            try validateOwnerPrivateDirectory(parent, exactMode: nil)
            let parentDescriptor = Darwin.open(
                parent.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard parentDescriptor >= 0 else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
            defer { _ = Darwin.close(parentDescriptor) }
            var parentBefore = stat()
            guard fstat(parentDescriptor, &parentBefore) == 0,
                  directory.lastPathComponent.withCString({
                      mkdirat(parentDescriptor, $0, 0o700)
                  }) == 0,
                  Darwin.fsync(parentDescriptor) == 0 else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
            var parentAfter = stat()
            guard fstat(parentDescriptor, &parentAfter) == 0,
                  parentBefore.st_dev == parentAfter.st_dev,
                  parentBefore.st_ino == parentAfter.st_ino,
                  parentBefore.st_mode == parentAfter.st_mode,
                  parentBefore.st_uid == parentAfter.st_uid,
                  parentBefore.st_gid == parentAfter.st_gid else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
        }
        try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
    }

    private static func validateOwnerPrivateDirectory(
        _ directory: URL,
        exactMode: mode_t?,
        requiresNoExtendedACL: Bool = false
    ) throws {
        var metadata = stat()
        guard lstat(directory.path, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o022 == 0,
              exactMode == nil || metadata.st_mode & 0o7777 == exactMode,
              let canonical = realpath(directory.path, nil) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        defer { free(canonical) }
        guard String(cString: canonical) == directory.path else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        if exactMode != nil || requiresNoExtendedACL {
            let descriptor = Darwin.open(
                directory.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard descriptor >= 0 else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
            defer { _ = Darwin.close(descriptor) }
            var opened = stat()
            guard fstat(descriptor, &opened) == 0,
                  opened.st_dev == metadata.st_dev,
                  opened.st_ino == metadata.st_ino,
                  try descriptorHasNoExtendedACL(descriptor) else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
        }
    }

    private static func persistReceipt(
        _ receipt: PrivateInstallCoordinatorReceipt,
        directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        do {
            try validateReceiptShape(receipt)
            try persistExclusiveRecord(
                receipt,
                leaf: receiptLeaf,
                temporaryLeaf: ".latest-private-install.\(receipt.nonce).tmp",
                maximumBytes: maximumReceiptBytes,
                allowedExistingLeaves: [preparationJournalLeaf, journalLeaf],
                directory: directory,
                boundaryHook: boundaryHook
            )
            guard try readReceipt(directory: directory) == receipt else {
                throw PrivateInstallCoordinatorError.receiptFailed
            }
        } catch {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
    }

    private static func persistJournal(
        _ journal: PrivateInstallRecoveryJournal,
        directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        do {
            try validateJournalShape(journal)
            try persistExclusiveRecord(
                journal,
                leaf: journalLeaf,
                temporaryLeaf: ".pending-private-install.\(journal.nonce).tmp",
                maximumBytes: maximumJournalBytes,
                allowedExistingLeaves: [preparationJournalLeaf],
                directory: directory,
                boundaryHook: boundaryHook
            )
            guard try readJournal(directory: directory) == journal else {
                throw PrivateInstallCoordinatorError.journalFailed
            }
        } catch {
            throw PrivateInstallCoordinatorError.journalFailed
        }
    }

    private static func persistPreparation(
        _ preparation: PrivateInstallPreparationJournal,
        directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        do {
            try validatePreparationShape(preparation)
            try persistExclusiveRecord(
                preparation,
                leaf: preparationJournalLeaf,
                temporaryLeaf: ".pending-private-install-preparation.\(preparation.nonce).tmp",
                maximumBytes: maximumPreparationJournalBytes,
                allowedExistingLeaves: [],
                directory: directory,
                boundaryHook: boundaryHook
            )
            guard try readPreparation(directory: directory) == preparation else {
                throw PrivateInstallCoordinatorError.journalFailed
            }
        } catch {
            throw PrivateInstallCoordinatorError.journalFailed
        }
    }

    private static func persistAbandonment(
        _ abandonment: PrivateInstallAbandonmentJournal,
        directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        do {
            try validateAbandonmentShape(abandonment)
            try persistExclusiveRecord(
                abandonment,
                leaf: abandonmentJournalLeaf,
                temporaryLeaf: ".pending-private-abandonment.\(abandonment.nonce).tmp",
                maximumBytes: maximumAbandonmentJournalBytes,
                allowedExistingLeaves: [preparationJournalLeaf],
                directory: directory,
                boundaryHook: boundaryHook
            )
            guard try readAbandonment(directory: directory) == abandonment else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func persistLifecycleJournal(
        _ lifecycle: PrivateInstallLifecycleJournal,
        directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void = { _ in }
    ) throws {
        do {
            try validateLifecycleJournalShape(lifecycle)
            var allowed = Set([preparationJournalLeaf, journalLeaf])
            if lifecycle.receipt != nil { allowed.insert(receiptLeaf) }
            try persistExclusiveRecord(
                lifecycle,
                leaf: lifecycleJournalLeaf,
                temporaryLeaf: ".pending-lifecycle.\(lifecycle.nonce).tmp",
                maximumBytes: maximumLifecycleJournalBytes,
                allowedExistingLeaves: allowed,
                directory: directory,
                boundaryHook: boundaryHook
            )
            guard try readLifecycleJournal(directory: directory) == lifecycle else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func persistExclusiveRecord<Record: Encodable>(
        _ record: Record,
        leaf: String,
        temporaryLeaf: String,
        maximumBytes: Int,
        allowedExistingLeaves: Set<String>,
        directory: URL,
        boundaryHook: (PrivateInstallRecordPersistenceBoundary) throws -> Void
    ) throws {
        try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(record)
        guard !bytes.isEmpty, bytes.count <= maximumBytes else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        let directoryDescriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard directoryDescriptor >= 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        defer { _ = Darwin.close(directoryDescriptor) }
        var directoryBefore = stat()
        let existingLeaves = Set(
            try descriptorDirectoryNames(directoryDescriptor, maximumCount: 4)
        )
        guard fstat(directoryDescriptor, &directoryBefore) == 0,
              existingLeaves.isSubset(of: allowedExistingLeaves),
              !existingLeaves.contains(leaf) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }

        let descriptor = temporaryLeaf.withCString {
            openat(
                directoryDescriptor,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0o600
            )
        }
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        defer {
            _ = Darwin.close(descriptor)
        }
        var temporaryBefore = stat()
        guard fstat(descriptor, &temporaryBefore) == 0,
              temporaryBefore.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              temporaryBefore.st_uid == geteuid(),
              temporaryBefore.st_mode & 0o7777 == 0o600,
              temporaryBefore.st_nlink == 1,
              try descriptorHasNoExtendedACL(descriptor) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        // Make the empty temporary name itself durable before any content
        // boundary. A power loss can then resolve to either this proven temp or
        // the later canonical rename, never to an unjournaled missing file.
        guard Darwin.fsync(descriptor) == 0,
              Darwin.fsync(directoryDescriptor) == 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        try boundaryHook(.afterTemporaryCreate)
        let partialCount = max(1, bytes.count / 2)
        try writeAll(bytes.prefix(partialCount), descriptor: descriptor)
        guard Darwin.fsync(descriptor) == 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        try boundaryHook(.afterPartialFileSync)
        if partialCount < bytes.count {
            try writeAll(bytes.suffix(from: partialCount), descriptor: descriptor)
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        try boundaryHook(.afterCompleteFileSync)
        var temporaryAfter = stat()
        guard fstat(descriptor, &temporaryAfter) == 0,
              temporaryAfter.st_dev == temporaryBefore.st_dev,
              temporaryAfter.st_ino == temporaryBefore.st_ino,
              temporaryAfter.st_mode == temporaryBefore.st_mode,
              temporaryAfter.st_uid == temporaryBefore.st_uid,
              temporaryAfter.st_gid == temporaryBefore.st_gid,
              temporaryAfter.st_nlink == temporaryBefore.st_nlink,
              temporaryAfter.st_size == off_t(bytes.count) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        try boundaryHook(.beforeExclusiveRename)
        guard temporaryLeaf.withCString({ temporaryPointer in
            leaf.withCString { leafPointer in
                renameatx_np(
                    directoryDescriptor,
                    temporaryPointer,
                    directoryDescriptor,
                    leafPointer,
                    UInt32(RENAME_EXCL)
                )
            }
        }) == 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        try boundaryHook(.afterRenameBeforeDirectorySync)
        guard Darwin.fsync(directoryDescriptor) == 0 else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        var directoryAfter = stat()
        guard fstat(directoryDescriptor, &directoryAfter) == 0,
              directoryAfter.st_dev == directoryBefore.st_dev,
              directoryAfter.st_ino == directoryBefore.st_ino,
              directoryAfter.st_mode == directoryBefore.st_mode,
              directoryAfter.st_uid == directoryBefore.st_uid,
              directoryAfter.st_gid == directoryBefore.st_gid,
              Set(try descriptorDirectoryNames(directoryDescriptor, maximumCount: 4))
                == existingLeaves.union([leaf]) else {
            throw PrivateInstallCoordinatorError.receiptFailed
        }
    }

    private static func readReceipt(
        directory: URL
    ) throws -> PrivateInstallCoordinatorReceipt? {
        try readCanonicalRecord(
            PrivateInstallCoordinatorReceipt.self,
            leaf: receiptLeaf,
            maximumBytes: maximumReceiptBytes,
            directory: directory,
            validate: validateReceiptShape
        )
    }

    private static func readJournal(
        directory: URL
    ) throws -> PrivateInstallRecoveryJournal? {
        try readCanonicalRecord(
            PrivateInstallRecoveryJournal.self,
            leaf: journalLeaf,
            maximumBytes: maximumJournalBytes,
            directory: directory,
            validate: validateJournalShape
        )
    }

    private static func readPreparation(
        directory: URL
    ) throws -> PrivateInstallPreparationJournal? {
        try readCanonicalRecord(
            PrivateInstallPreparationJournal.self,
            leaf: preparationJournalLeaf,
            maximumBytes: maximumPreparationJournalBytes,
            directory: directory,
            validate: validatePreparationShape
        )
    }

    private static func readAbandonment(
        directory: URL
    ) throws -> PrivateInstallAbandonmentJournal? {
        try readCanonicalRecord(
            PrivateInstallAbandonmentJournal.self,
            leaf: abandonmentJournalLeaf,
            maximumBytes: maximumAbandonmentJournalBytes,
            directory: directory,
            validate: validateAbandonmentShape
        )
    }

    private static func readLifecycleJournal(
        directory: URL
    ) throws -> PrivateInstallLifecycleJournal? {
        try readCanonicalRecord(
            PrivateInstallLifecycleJournal.self,
            leaf: lifecycleJournalLeaf,
            maximumBytes: maximumLifecycleJournalBytes,
            directory: directory,
            validate: validateLifecycleJournalShape
        )
    }

    private static func readCanonicalRecord<Record: Codable>(
        _ type: Record.Type,
        leaf: String,
        maximumBytes: Int,
        directory: URL,
        validate: (Record) throws -> Void
    ) throws -> Record? {
        do {
            try validateOwnerPrivateDirectory(directory, exactMode: 0o700)
            let directoryDescriptor = Darwin.open(
                directory.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard directoryDescriptor >= 0 else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            defer { _ = Darwin.close(directoryDescriptor) }
            var directoryBefore = stat()
            guard fstat(directoryDescriptor, &directoryBefore) == 0 else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            let names = try descriptorDirectoryNames(directoryDescriptor, maximumCount: 8)
            let temporaryArtifacts = try names.compactMap {
                try interruptedRecordArtifact(fromTemporaryLeaf: $0)
            }
            let temporaryLeaves = Set(temporaryArtifacts.map(\.leaf))
            let canonicalLeaves = Set([
                abandonmentJournalLeaf,
                preparationJournalLeaf,
                receiptLeaf,
                journalLeaf,
                lifecycleJournalLeaf
            ])
            guard temporaryArtifacts.count <= 1,
                  Set(names).isSubset(of: canonicalLeaves.union(temporaryLeaves)),
                  names.count <= 6 else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            for artifact in temporaryArtifacts {
                _ = try validateInterruptedRecordFile(
                    descriptor: directoryDescriptor,
                    leaf: artifact.leaf,
                    maximumBytes: artifact.kind.maximumBytes
                )
            }
            guard names.contains(leaf) else {
                var directoryAfter = stat()
                guard fstat(directoryDescriptor, &directoryAfter) == 0,
                      stableNode(directoryBefore, directoryAfter) else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                return nil
            }
            let descriptor = leaf.withCString {
                openat(directoryDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            }
            guard descriptor >= 0 else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            defer { _ = Darwin.close(descriptor) }
            var before = stat()
            guard fstat(descriptor, &before) == 0,
                  before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                  before.st_uid == geteuid(),
                  before.st_mode & 0o7777 == 0o600,
                  before.st_nlink == 1,
                  before.st_size > 0,
                  before.st_size <= maximumBytes,
                  (try? descriptorHasNoExtendedACL(descriptor)) == true else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            var bytes = [UInt8](repeating: 0, count: Int(before.st_size))
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeMutableBytes { buffer in
                    Darwin.read(
                        descriptor,
                        buffer.baseAddress?.advanced(by: offset),
                        buffer.count - offset
                    )
                }
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
            }
            var trailingByte: UInt8 = 0
            guard Darwin.read(descriptor, &trailingByte, 1) == 0 else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            var after = stat()
            var directoryAfter = stat()
            guard fstat(descriptor, &after) == 0,
                  fstat(directoryDescriptor, &directoryAfter) == 0,
                  stableNode(before, after),
                  stableNode(directoryBefore, directoryAfter) else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            let data = Data(bytes)
            let record = try JSONDecoder().decode(type, from: data)
            try validate(record)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            guard try encoder.encode(record) == data else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            return record
        } catch let error as PrivateInstallCoordinatorError {
            if error == .rollbackInspectionFailed { throw error }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        } catch {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
    }

    private static func productionStageLeaves() throws -> [String] {
        let applications = "/Applications"
        guard let canonical = realpath(applications, nil) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        defer { free(canonical) }
        guard String(cString: canonical) == applications else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let descriptor = Darwin.open(
            applications,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        defer { _ = Darwin.close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              productionApplicationsMetadataIsSafe(before),
              (try? descriptorHasNoExtendedACL(descriptor)) == true else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let names = try descriptorDirectoryNames(descriptor, maximumCount: 100_000)
        let stages = names.filter { $0.hasPrefix(".Fulmar.install-stage.") }.sorted()
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              stableNode(before, after) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return stages
    }

    private static func productionArchiveLeaves() throws -> [String] {
        let applications = "/Applications"
        guard let canonical = realpath(applications, nil) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        defer { free(canonical) }
        guard String(cString: canonical) == applications else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let descriptor = Darwin.open(
            applications,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        defer { _ = Darwin.close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              productionApplicationsMetadataIsSafe(before),
              (try? descriptorHasNoExtendedACL(descriptor)) == true else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        let names = try descriptorDirectoryNames(descriptor, maximumCount: 100_000)
        let archivePrefixes = [
            ".Fulmar.private-cancelled.",
            ".Fulmar.private-retired."
        ]
        let archives = names.filter { name in
            archivePrefixes.contains(where: name.hasPrefix)
        }.sorted()
        guard archives.count <= 1_024,
              archives.allSatisfy(validProductionArchiveLeaf) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              stableNode(before, after) else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return archives
    }

    private static func validProductionArchiveLeaf(_ leaf: String) -> Bool {
        let prefixes = [
            ".Fulmar.private-cancelled.",
            ".Fulmar.private-retired."
        ]
        guard let prefix = prefixes.first(where: { leaf.hasPrefix($0) }),
              leaf.hasSuffix(".app") else {
            return false
        }
        let nonce = String(leaf.dropFirst(prefix.count).dropLast(4))
        return nonce.utf8.count == 64 && isLowerHex(nonce)
    }

    private static func archiveProductionStage(
        stageLeaf: String,
        archiveLeaf: String,
        expected: PrivateInstallBundleProof
    ) throws {
        do {
            let nonce = try nonceFromStageLeaf(stageLeaf)
            let allowedArchiveLeaves = Set([
                try mappedArchiveLeaf(
                    nonce: nonce,
                    operation: .cancelOriginalActive
                ),
                try mappedArchiveLeaf(
                    nonce: nonce,
                    operation: .retireCommitted
                )
            ])
            guard allowedArchiveLeaves.contains(archiveLeaf),
                  validProductionArchiveLeaf(archiveLeaf),
                  try productionStageLeaves() == [stageLeaf],
                  !(try productionArchiveLeaves()).contains(archiveLeaf) else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let applicationsURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
            let stageURL = applicationsURL.appendingPathComponent(stageLeaf, isDirectory: true)
            let archiveURL = applicationsURL.appendingPathComponent(archiveLeaf, isDirectory: true)
            guard try inspectBundle(
                at: stageURL,
                failure: .lifecycleFailed
            ) == expected else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let descriptor = Darwin.open(
                applicationsURL.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard descriptor >= 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            defer { _ = Darwin.close(descriptor) }
            var directoryBefore = stat()
            var source = stat()
            var destination = stat()
            errno = 0
            let destinationStatus = archiveLeaf.withCString {
                fstatat(descriptor, $0, &destination, AT_SYMLINK_NOFOLLOW)
            }
            let destinationErrno = errno
            guard fstat(descriptor, &directoryBefore) == 0,
                  productionApplicationsMetadataIsSafe(directoryBefore),
                  stageLeaf.withCString({
                      fstatat(descriptor, $0, &source, AT_SYMLINK_NOFOLLOW)
                  }) == 0,
                  source.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
                  UInt64(truncatingIfNeeded: source.st_dev) == expected.identity.device,
                  UInt64(source.st_ino) == expected.identity.inode,
                  UInt32(source.st_uid) == expected.identity.owner,
                  destinationStatus != 0,
                  destinationErrno == ENOENT,
                  stageLeaf.withCString({ sourcePointer in
                      archiveLeaf.withCString { destinationPointer in
                          renameatx_np(
                              descriptor,
                              sourcePointer,
                              descriptor,
                              destinationPointer,
                              UInt32(RENAME_EXCL)
                          )
                      }
                  }) == 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            guard Darwin.fsync(descriptor) == 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            var directoryAfter = stat()
            var staleSource = stat()
            errno = 0
            let staleSourceStatus = stageLeaf.withCString {
                fstatat(descriptor, $0, &staleSource, AT_SYMLINK_NOFOLLOW)
            }
            let staleSourceErrno = errno
            guard fstat(descriptor, &directoryAfter) == 0,
                  stableDirectoryIdentity(directoryBefore, directoryAfter),
                  staleSourceStatus != 0,
                  staleSourceErrno == ENOENT,
                  try inspectBundle(
                      at: archiveURL,
                      failure: .lifecycleFailed
                  ) == expected else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        } catch let error as PrivateInstallCoordinatorError {
            if error == .lifecycleFailed { throw error }
            throw PrivateInstallCoordinatorError.lifecycleFailed
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func proveProductionArchiveDurable(
        archiveLeaf: String,
        expected: PrivateInstallBundleProof
    ) throws {
        do {
            guard validProductionArchiveLeaf(archiveLeaf),
                  try productionArchiveLeaves().contains(archiveLeaf) else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let archiveURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
                .appendingPathComponent(archiveLeaf, isDirectory: true)
            guard try inspectBundle(
                at: archiveURL,
                failure: .lifecycleFailed
            ) == expected else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            let descriptor = Darwin.open(
                "/Applications",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard descriptor >= 0 else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
            defer { _ = Darwin.close(descriptor) }
            guard Darwin.fsync(descriptor) == 0,
                  try inspectBundle(
                      at: archiveURL,
                      failure: .lifecycleFailed
                  ) == expected else {
                throw PrivateInstallCoordinatorError.lifecycleFailed
            }
        } catch let error as PrivateInstallCoordinatorError {
            if error == .lifecycleFailed { throw error }
            throw PrivateInstallCoordinatorError.lifecycleFailed
        } catch {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
    }

    private static func nonceFromStageLeaf(_ leaf: String) throws -> String {
        let prefix = ".Fulmar.install-stage."
        guard leaf.hasPrefix(prefix), leaf.hasSuffix(".app") else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        let nonce = String(leaf.dropFirst(prefix.count).dropLast(4))
        guard (try? mappedStageLeaf(nonce: nonce)) == leaf else {
            throw PrivateInstallCoordinatorError.lifecycleFailed
        }
        return nonce
    }

    private static func productionApplicationsMetadataIsSafe(_ metadata: stat) -> Bool {
        guard metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              metadata.st_uid == 0,
              let admin = getgrnam("admin"),
              let wheel = getgrnam("wheel") else {
            return false
        }
        let permissions = metadata.st_mode & 0o7777
        if permissions == 0o775 {
            return metadata.st_gid == admin.pointee.gr_gid
        }
        return permissions == 0o755
            && (metadata.st_gid == admin.pointee.gr_gid
                || metadata.st_gid == wheel.pointee.gr_gid)
    }

    /// Decodes a Darwin `dirent` without materializing the imported
    /// 1,024-byte `d_name` tuple. `readdir` may return a variable-length
    /// record near the end of its internal buffer, so every read here is
    /// bounded by the entry's own record and name lengths.
    private static let direntNameOffset = MemoryLayout<dirent>.offset(of: \dirent.d_name)

    private static func boundedDirectoryEntryName(
        _ entry: UnsafeMutablePointer<dirent>
    ) -> String? {
        let byteCount = Int(entry.pointee.d_namlen)
        let recordByteCount = Int(entry.pointee.d_reclen)
        guard let nameOffset = direntNameOffset,
              byteCount > 0,
              byteCount <= Int(MAXNAMLEN),
              recordByteCount <= MemoryLayout<dirent>.size,
              nameOffset <= recordByteCount,
              byteCount < recordByteCount - nameOffset else {
            return nil
        }
        let bytes = UnsafeRawBufferPointer(
            start: UnsafeRawPointer(entry).advanced(by: nameOffset),
            count: byteCount + 1
        )
        let nameBytes = bytes.prefix(byteCount)
        guard bytes[byteCount] == 0,
              !nameBytes.contains(0),
              !nameBytes.contains(47) else {
            return nil
        }
        return String(bytes: nameBytes, encoding: .utf8)
    }

    private static func descriptorDirectoryNames(
        _ descriptor: Int32,
        maximumCount: Int
    ) throws -> [String] {
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        guard lseek(duplicate, 0, SEEK_SET) >= 0,
              let stream = fdopendir(duplicate) else {
            if duplicate >= 0 { _ = Darwin.close(duplicate) }
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        defer { _ = closedir(stream) }
        var names: [String] = []
        errno = 0
        while let entry = readdir(stream) {
            guard let name = Self.boundedDirectoryEntryName(entry) else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            if name == "." || name == ".." { continue }
            guard !name.isEmpty,
                  name.utf8.count <= Int(MAXNAMLEN),
                  !name.contains("/"),
                  !name.contains("\0"),
                  names.count < maximumCount else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            names.append(name)
        }
        guard errno == 0 else {
            throw PrivateInstallCoordinatorError.rollbackInspectionFailed
        }
        return names.sorted()
    }

    private static func stableNode(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_gid == second.st_gid
            && first.st_nlink == second.st_nlink
            && first.st_size == second.st_size
            && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
            && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
            && first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec
            && first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec
    }

    private static func stableDirectoryIdentity(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_gid == second.st_gid
            && first.st_nlink == second.st_nlink
    }

    /// A cross-directory rename changes each directory's entry count. APFS
    /// exposes that change through `st_nlink`, so requiring an unchanged link
    /// count would reject the exact mutation we just made. The already-open
    /// directory handle must still name the same directory, with the same type,
    /// ownership, and permissions.
    private static func stableDirectoryHandleAfterEntryMutation(
        _ first: stat,
        _ second: stat
    ) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_gid == second.st_gid
    }

    private static func stableRenamedRecord(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_gid == second.st_gid
            && first.st_nlink == second.st_nlink
            && first.st_size == second.st_size
            && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
            && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
    }

    private static func writeAll(_ bytes: Data, descriptor: Int32) throws {
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(
                    descriptor,
                    buffer.baseAddress?.advanced(by: offset),
                    buffer.count - offset
                )
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    throw PrivateInstallCoordinatorError.receiptFailed
                }
            }
        }
    }

    private static func descriptorHasNoExtendedACL(_ descriptor: Int32) throws -> Bool {
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return true }
            throw PrivateInstallCoordinatorError.receiptFailed
        }
        _ = acl_free(UnsafeMutableRawPointer(accessControlList))
        return false
    }

    private static func treeSHA256(
        at root: URL,
        failure: PrivateInstallCoordinatorError
    ) throws -> String {
        let initialIdentity = try safeDirectoryIdentity(at: root, failure: failure)
        var state = TreeDigestState(root: root, failure: failure)
        try state.appendDirectory(relativeComponents: [], depth: 0)
        guard try safeDirectoryIdentity(at: root, failure: failure) == initialIdentity else {
            throw failure
        }
        return state.finalize()
    }

    private static func isLowerHex(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
        }
    }
}

private struct TreeDigestState {
    private static let maximumDepth = 64
    private static let maximumEntries = 100_000
    private static let maximumFileBytes: UInt64 = 8 * 1_024 * 1_024 * 1_024
    private static let maximumTotalPathBytes = 32 * 1_024 * 1_024

    let root: URL
    let failure: PrivateInstallCoordinatorError
    private var hasher = SHA256()
    private var entryCount = 0
    private var totalFileBytes: UInt64 = 0
    private var totalPathBytes = 0

    init(root: URL, failure: PrivateInstallCoordinatorError) {
        self.root = root
        self.failure = failure
        append(Data("FULMAR-PRIVATE-TREE-V1\0".utf8))
    }

    mutating func appendDirectory(relativeComponents: [String], depth: Int) throws {
        guard depth <= Self.maximumDepth else { throw failure }
        let directory = relativeComponents.reduce(root) {
            $0.appendingPathComponent($1, isDirectory: true)
        }
        let before = try metadata(at: directory)
        guard before.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              before.st_uid == geteuid(),
              before.st_mode & 0o022 == 0 else {
            throw failure
        }
        if !relativeComponents.isEmpty {
            try appendEntryHeader(
                kind: UInt8(ascii: "d"),
                relativeComponents: relativeComponents,
                metadata: before
            )
        }
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        } catch {
            throw failure
        }
        for name in names {
            guard validComponent(name) else { throw failure }
            let components = relativeComponents + [name]
            let url = directory.appendingPathComponent(name, isDirectory: false)
            let item = try metadata(at: url)
            switch item.st_mode & mode_t(S_IFMT) {
            case mode_t(S_IFDIR):
                try appendDirectory(relativeComponents: components, depth: depth + 1)
            case mode_t(S_IFREG):
                try appendRegularFile(at: url, relativeComponents: components, before: item)
            case mode_t(S_IFLNK):
                try appendSymbolicLink(at: url, relativeComponents: components, before: item)
            default:
                throw failure
            }
        }
        let after = try metadata(at: directory)
        guard stable(before, after),
              after.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
            throw failure
        }
    }

    mutating func finalize() -> String {
        hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private mutating func appendRegularFile(
        at url: URL,
        relativeComponents: [String],
        before: stat
    ) throws {
        guard before.st_uid == geteuid(),
              before.st_mode & 0o022 == 0,
              before.st_size >= 0,
              UInt64(before.st_size) <= Self.maximumFileBytes - totalFileBytes else {
            throw failure
        }
        let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw failure }
        defer { _ = Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              stable(before, opened),
              opened.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
            throw failure
        }
        try appendEntryHeader(
            kind: UInt8(ascii: "f"),
            relativeComponents: relativeComponents,
            metadata: opened
        )
        appendInteger(UInt64(opened.st_size))
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        var totalRead: UInt64 = 0
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count > 0 {
                totalRead += UInt64(count)
                guard totalRead <= UInt64(opened.st_size) else { throw failure }
                append(Data(buffer.prefix(count)))
            } else if count == 0 {
                break
            } else if errno == EINTR {
                continue
            } else {
                throw failure
            }
        }
        var after = stat()
        guard totalRead == UInt64(opened.st_size),
              fstat(descriptor, &after) == 0,
              stable(opened, after) else {
            throw failure
        }
        totalFileBytes += totalRead
    }

    private mutating func appendSymbolicLink(
        at url: URL,
        relativeComponents: [String],
        before: stat
    ) throws {
        guard before.st_uid == geteuid(),
              before.st_size >= 0,
              before.st_size <= 4_096 else {
            throw failure
        }
        var bytes = [UInt8](repeating: 0, count: Int(before.st_size) + 1)
        let count = bytes.withUnsafeMutableBytes {
            readlink(url.path, $0.baseAddress, max(0, $0.count - 1))
        }
        guard count == before.st_size, count > 0 else { throw failure }
        let targetBytes = Array(bytes.prefix(count))
        guard !targetBytes.contains(0),
              let target = String(bytes: targetBytes, encoding: .utf8),
              safeRelativeLink(target, from: relativeComponents.dropLast()) else {
            throw failure
        }
        try appendEntryHeader(
            kind: UInt8(ascii: "l"),
            relativeComponents: relativeComponents,
            metadata: before
        )
        appendInteger(UInt64(targetBytes.count))
        append(Data(targetBytes))
        let after = try metadata(at: url)
        guard stable(before, after),
              after.st_mode & mode_t(S_IFMT) == mode_t(S_IFLNK) else {
            throw failure
        }
    }

    private mutating func appendEntryHeader(
        kind: UInt8,
        relativeComponents: [String],
        metadata: stat
    ) throws {
        entryCount += 1
        guard entryCount <= Self.maximumEntries else { throw failure }
        let relativePath = relativeComponents.joined(separator: "/")
        let pathBytes = Data(relativePath.utf8)
        totalPathBytes += pathBytes.count
        guard !pathBytes.isEmpty,
              pathBytes.count <= 4_096,
              totalPathBytes <= Self.maximumTotalPathBytes else {
            throw failure
        }
        append(Data([kind]))
        appendInteger(UInt64(pathBytes.count))
        append(pathBytes)
        appendInteger(UInt64(metadata.st_mode & 0o7777))
    }

    private func metadata(at url: URL) throws -> stat {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { throw failure }
        return value
    }

    private func stable(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_uid == second.st_uid
            && first.st_mode == second.st_mode
            && first.st_size == second.st_size
            && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
            && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
            && first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec
            && first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec
    }

    private func validComponent(_ component: String) -> Bool {
        let bytes = Array(component.utf8)
        return !bytes.isEmpty
            && bytes.count <= 255
            && component == component.precomposedStringWithCanonicalMapping
            && component != "."
            && component != ".."
            && !bytes.contains(UInt8(ascii: "/"))
            && !bytes.contains(0)
    }

    private func safeRelativeLink<S: Collection>(
        _ target: String,
        from parent: S
    ) -> Bool where S.Element == String {
        guard !target.hasPrefix("/"),
              !target.isEmpty,
              target.utf8.count <= 4_096,
              !target.contains("\0") else {
            return false
        }
        var depth = parent.count
        for component in target.split(separator: "/", omittingEmptySubsequences: false) {
            if component.isEmpty || component == "." {
                continue
            }
            if component == ".." {
                guard depth > 0 else { return false }
                depth -= 1
            } else {
                depth += 1
            }
        }
        return true
    }

    private mutating func append(_ data: Data) {
        hasher.update(data: data)
    }

    private mutating func appendInteger(_ value: UInt64) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { append(Data($0)) }
    }
}

private struct DurableBundleSyncState {
    private static let maximumDepth = 64
    private static let maximumEntries = 100_000

    let root: URL
    private var entries = 0

    init(root: URL) {
        self.root = root
    }

    mutating func commit() throws {
        let rootBefore = try metadata(root)
        try syncNode(root, depth: 0)
        let parent = root.deletingLastPathComponent()
        let parentDescriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard parentDescriptor >= 0 else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        defer { _ = Darwin.close(parentDescriptor) }
        guard Darwin.fsync(parentDescriptor) == 0,
              stable(rootBefore, try metadata(root)) else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
    }

    private mutating func syncNode(_ url: URL, depth: Int) throws {
        guard depth <= Self.maximumDepth, entries < Self.maximumEntries else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        entries += 1
        let before = try metadata(url)
        guard before.st_uid == geteuid() else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        switch before.st_mode & mode_t(S_IFMT) {
        case mode_t(S_IFDIR):
            guard before.st_mode & 0o022 == 0 else {
                throw PrivateInstallCoordinatorError.stagingFailed
            }
            let names = try FileManager.default.contentsOfDirectory(atPath: url.path)
                .sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
            for name in names {
                guard !name.isEmpty,
                      name != ".",
                      name != "..",
                      !name.contains("/"),
                      !name.contains("\0") else {
                    throw PrivateInstallCoordinatorError.stagingFailed
                }
                try syncNode(
                    url.appendingPathComponent(name, isDirectory: false),
                    depth: depth + 1
                )
            }
            try syncDescriptor(url, flags: O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW, before: before)
        case mode_t(S_IFREG):
            guard before.st_mode & 0o022 == 0 else {
                throw PrivateInstallCoordinatorError.stagingFailed
            }
            try syncDescriptor(url, flags: O_RDONLY | O_CLOEXEC | O_NOFOLLOW, before: before)
        case mode_t(S_IFLNK):
            // Symlinks have no independently fsyncable data on macOS. Their
            // directory entry is committed by the containing directory fsync,
            // and the subsequent bounded tree proof validates the exact target.
            guard stable(before, try metadata(url)) else {
                throw PrivateInstallCoordinatorError.stagingFailed
            }
        default:
            throw PrivateInstallCoordinatorError.stagingFailed
        }
    }

    private func syncDescriptor(_ url: URL, flags: Int32, before: stat) throws {
        let descriptor = Darwin.open(url.path, flags)
        guard descriptor >= 0 else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        defer { _ = Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              stable(before, opened),
              Darwin.fsync(descriptor) == 0 else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              stable(opened, after),
              stable(after, try metadata(url)) else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
    }

    private func metadata(_ url: URL) throws -> stat {
        var value = stat()
        guard lstat(url.path, &value) == 0 else {
            throw PrivateInstallCoordinatorError.stagingFailed
        }
        return value
    }

    private func stable(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_gid == second.st_gid
            && first.st_nlink == second.st_nlink
            && first.st_size == second.st_size
            && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
            && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
            && first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec
            && first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec
    }
}
