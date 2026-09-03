import Darwin
import CryptoKit
import Foundation
import LocalHarnessDeviceAttestation

struct HarnessHomeReceiptlessRecoveryRequest: Equatable, Sendable {
    let root: URL
    fileprivate let sourceIdentity: HarnessHomeRecoveryIdentity
}

extension ProviderHistoryRecoveryChoice {
    var attestationChoice: HarnessHomeAttestationRecoveryChoice {
        switch self {
        case .settingsOnly: return .settingsOnly
        case .startClean: return .startClean
        }
    }
}

enum HarnessHomeRecoveryPreflightStatus: Equatable, Sendable {
    case absent
    case foregroundAttestationRequired
    case current
}

/// Detection-only identity for an interrupted authenticated recovery. Unlike
/// the transaction identity stored inside the journal, this binds the exact
/// unopened prompt to all metadata which can change while foreground consent
/// or Keychain authorization is pending.
fileprivate struct HarnessHomeRecoveryPromptIdentity: Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
    let owner: UInt32
    let permissions: UInt16
    let kind: UInt16
    let linkCount: UInt64
    let byteCount: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
    let changeSeconds: Int64
    let changeNanoseconds: Int64

    init(_ value: stat) {
        device = UInt64(truncatingIfNeeded: value.st_dev)
        inode = UInt64(truncatingIfNeeded: value.st_ino)
        owner = value.st_uid
        permissions = UInt16(value.st_mode & 0o7777)
        kind = UInt16(truncatingIfNeeded: value.st_mode & S_IFMT)
        linkCount = UInt64(truncatingIfNeeded: value.st_nlink)
        byteCount = Int64(value.st_size)
        modificationSeconds = Int64(value.st_mtimespec.tv_sec)
        modificationNanoseconds = Int64(value.st_mtimespec.tv_nsec)
        changeSeconds = Int64(value.st_ctimespec.tv_sec)
        changeNanoseconds = Int64(value.st_ctimespec.tv_nsec)
    }
}

struct HarnessHomeInterruptedRecoveryRequest: Equatable, Sendable {
    let root: URL
    fileprivate let parentIdentity: HarnessHomeRecoveryPromptIdentity
    fileprivate let recoveryDirectoryIdentity: HarnessHomeRecoveryPromptIdentity
    fileprivate let journalIdentity: HarnessHomeRecoveryPromptIdentity
}

/// Foreground authorization result for one exact interrupted transaction.
/// The operation identifier and recovery choice are read from the authenticated
/// journal only after the existing device key has verified it. Callers must
/// return this intent unchanged when asking the manager to resume; a peer
/// transaction cannot inherit an earlier user acknowledgement.
struct HarnessHomeInterruptedRecoveryIntent: Equatable, Sendable {
    let operationID: UUID
    let choice: ProviderHistoryRecoveryChoice
    fileprivate let request: HarnessHomeInterruptedRecoveryRequest
}

enum HarnessHomeRecoveryPendingState: Equatable, Sendable {
    case initial(HarnessHomeReceiptlessRecoveryRequest)
    case interrupted(HarnessHomeInterruptedRecoveryRequest)
    case published(HarnessHomeReceiptlessRecoveryReceipt)
    case blocked(root: URL, message: String)

    var root: URL {
        switch self {
        case .initial(let request): return request.root
        case .interrupted(let request): return request.root
        case .published(let receipt): return receipt.recoveryRoot
            ?? receipt.quarantine.deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("HarnessHome", isDirectory: true)
        case .blocked(let root, _): return root
        }
    }

    var recoveryFolder: URL {
        root.deletingLastPathComponent()
            .appendingPathComponent(HarnessHomeManager.receiptlessRecoveryDirectoryName, isDirectory: true)
    }
}

struct HarnessHomeReceiptlessRecoveryReceipt: Equatable, Sendable {
    let quarantine: URL
    let copiedEntries: [String]
    fileprivate let recoveryRoot: URL?
    fileprivate let completion: HarnessHomeRecoveryCompletionIdentity?

    var operationID: UUID? { completion?.operationID }

    init(quarantine: URL, copiedEntries: [String]) {
        self.quarantine = quarantine
        self.copiedEntries = copiedEntries
        recoveryRoot = nil
        completion = nil
    }

    fileprivate init(
        root: URL,
        quarantine: URL,
        copiedEntries: [String],
        completion: HarnessHomeRecoveryCompletionIdentity
    ) {
        self.quarantine = quarantine
        self.copiedEntries = copiedEntries
        recoveryRoot = root
        self.completion = completion
    }
}

fileprivate struct HarnessHomeRecoveryCompletionIdentity: Equatable, Sendable {
    let operationID: UUID
    let parentIdentity: HarnessHomeRecoveryIdentity
    let recoveryDirectoryIdentity: HarnessHomeRecoveryIdentity
    let journalIdentity: HarnessHomeRecoveryPromptIdentity
}

fileprivate struct HarnessHomeRecoveryIdentity: Codable, Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
    let owner: UInt32
    let permissions: UInt16
    let kind: UInt16

    init(_ value: stat) {
        device = UInt64(truncatingIfNeeded: value.st_dev)
        inode = UInt64(truncatingIfNeeded: value.st_ino)
        owner = value.st_uid
        permissions = UInt16(value.st_mode & 0o7777)
        kind = UInt16(truncatingIfNeeded: value.st_mode & S_IFMT)
    }
}

enum HarnessHomeError: LocalizedError, Equatable {
    case unsafeHomePatch(String)
    case unsafeProfile(String)
    case unsafeMigrationEntry(String)
    case migrationTooLarge
    case profileInputTooLarge(String)
    case preparationLimitExceeded(String)
    case receiptlessRecoveryRequired(HarnessHomeReceiptlessRecoveryRequest)
    case receiptlessRecoveryInterrupted(HarnessHomeInterruptedRecoveryRequest)
    case receiptlessRecoveryStateChanged
    case receiptlessRecoveryInProgress
    case receiptlessRecoveryAuthenticationRequired
    case receiptlessRecoveryAuthenticationUnavailable
    case receiptlessRecoveryJournalInvalid

    var errorDescription: String? {
        switch self {
        case .unsafeHomePatch(let path):
            return "An unreviewed Harness-wide patch was blocked at \(path). Remove it or review it before launching."
        case .unsafeProfile(let detail):
            return "The app-owned Harness profile failed its integrity check: \(detail)."
        case .unsafeMigrationEntry(let path):
            return "A private Harness-home recovery entry is unsafe or unrecognized and was preserved: \(path)."
        case .migrationTooLarge:
            return "Legacy Harness data is too large to migrate safely in one operation."
        case .profileInputTooLarge(let name):
            return "The app-owned Harness profile input \(name) exceeds its safe startup byte limit."
        case .preparationLimitExceeded(let detail):
            return "Harness home preparation exceeded its safe startup limit: \(detail)."
        case .receiptlessRecoveryRequired:
            return "Historical private provider state must be preserved before Fulmar can create a privacy-epoch-current Harness home. Nothing was changed or enumerated."
        case .receiptlessRecoveryInterrupted:
            return "An authenticated Harness-home recovery was interrupted and needs an explicit foreground resume. Nothing was changed during detection."
        case .receiptlessRecoveryStateChanged:
            return "The historical Harness home changed while recovery was being prepared. Nothing was replaced. Review the preserved data and try again."
        case .receiptlessRecoveryInProgress:
            return "Another Fulmar process is already completing the exact Harness-home recovery transaction."
        case .receiptlessRecoveryAuthenticationRequired:
            return "macOS must authorize the existing device-only recovery key before Fulmar can continue this recovery."
        case .receiptlessRecoveryAuthenticationUnavailable:
            return "The device-only key needed to authenticate Harness-home recovery could not be accessed. The preserved data was not changed."
        case .receiptlessRecoveryJournalInvalid:
            return "The private Harness-home recovery journal is missing, changed, or unauthenticated. The preserved data was not removed."
        }
    }
}

enum HarnessHomeMigrationPhase: Sendable, Equatable {
    case stagingCreated
    case contentDurable
    case receiptDurable
    case installed
}

enum HarnessHomeMigrationTestInterruption: Error, Equatable {
    case simulatedCrash(HarnessHomeMigrationPhase)
}

enum HarnessHomeReceiptlessRecoveryPhase: String, Codable, CaseIterable, Sendable {
    case initialStagingDurable
    case journalPrepared
    case sourceQuarantined
    case sourceQuarantineRecorded
    case reviewedContentDurable
    case contentRecorded
    case receiptDurable
    case receiptRecorded
    case published
    case publicationRecorded
    case journalCleared
}

enum HarnessHomeReceiptlessRecoveryTestInterruption: Error, Equatable {
    case simulatedCrash(HarnessHomeReceiptlessRecoveryPhase)
}

enum HarnessHomeReceiptlessRecoveryDescriptorPoint: Equatable, Sendable {
    case receiptProbe
    case receiptInstall
    case receiptRevalidation
}

/// Owns the private DSH home used by the embedded runtime. Keeping it separate
/// from ~/.dsh prevents a machine-wide Cordis patch or profile override from
/// silently changing the reviewed app composition.
final class HarnessHomeManager {
    private enum RecoveryPermissionPolicy {
        case privateStaging
        case formerReceiptlessHome
    }

    struct Limits: Sendable {
        var maximumProfileFileBytes: Int64
        var maximumProfileAggregateBytes: Int64
        var maximumMigrationNodes: Int
        var maximumMigrationDepth: Int
        var maximumRelativePathBytes: Int
        var maximumMigrationFileBytes: Int64
        var maximumMigrationBytes: Int64
        var maximumRuntimeTemporaryEntries: Int
        var preparationDuration: TimeInterval

        init(
            maximumProfileFileBytes: Int64 = 1 * 1_024 * 1_024,
            maximumProfileAggregateBytes: Int64 = 2 * 1_024 * 1_024,
            maximumMigrationNodes: Int = 100_000,
            maximumMigrationDepth: Int = 64,
            maximumRelativePathBytes: Int = 4_096,
            maximumMigrationFileBytes: Int64 = 4 * 1_024 * 1_024 * 1_024,
            maximumMigrationBytes: Int64 = 20 * 1_024 * 1_024 * 1_024,
            maximumRuntimeTemporaryEntries: Int = 10_000,
            preparationDuration: TimeInterval = 120
        ) {
            self.maximumProfileFileBytes = maximumProfileFileBytes
            self.maximumProfileAggregateBytes = maximumProfileAggregateBytes
            self.maximumMigrationNodes = maximumMigrationNodes
            self.maximumMigrationDepth = maximumMigrationDepth
            self.maximumRelativePathBytes = maximumRelativePathBytes
            self.maximumMigrationFileBytes = maximumMigrationFileBytes
            self.maximumMigrationBytes = maximumMigrationBytes
            self.maximumRuntimeTemporaryEntries = maximumRuntimeTemporaryEntries
            self.preparationDuration = preparationDuration
        }

        fileprivate var isValid: Bool {
            maximumProfileFileBytes > 0
                && maximumProfileFileBytes <= 64 * 1_024 * 1_024
                && maximumProfileAggregateBytes >= maximumProfileFileBytes
                && maximumProfileAggregateBytes <= 128 * 1_024 * 1_024
                && maximumMigrationNodes > 0
                && maximumMigrationNodes <= 1_000_000
                && maximumMigrationDepth >= 0
                && maximumMigrationDepth <= 256
                && maximumRelativePathBytes > 0
                && maximumRelativePathBytes <= 64 * 1_024
                && maximumMigrationFileBytes >= 0
                && maximumMigrationBytes >= maximumMigrationFileBytes
                && maximumRuntimeTemporaryEntries > 0
                && maximumRuntimeTemporaryEntries <= 100_000
                && preparationDuration.isFinite
                && preparationDuration >= 0
                && preparationDuration <= 300
        }
    }

    private struct MigrationReceipt: Codable {
        let version: Int
        let migratedAt: Date
        let source: String?
        let copiedEntries: [String]
        let sourceKind: MigrationSourceKind?
        let providerHistoryPrivacyEpoch: Int?
    }

    private enum MigrationSourceKind: String, Codable {
        case receiptlessRecovery
        case historicalProviderState
    }

    private enum ReceiptlessTransactionPhase: Int, Codable, Comparable {
        case prepared = 0
        case sourceQuarantined = 1
        case contentDurable = 2
        case receiptDurable = 3
        case published = 4

        static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    private struct ReceiptlessRecoveryJournal: Codable, Equatable {
        let formatVersion: Int
        let operationID: UUID
        var phase: ReceiptlessTransactionPhase
        let rootName: String
        let stagingName: String
        let quarantineName: String
        let parentIdentity: HarnessHomeRecoveryIdentity
        let recoveryDirectoryIdentity: HarnessHomeRecoveryIdentity
        let sourceIdentity: HarnessHomeRecoveryIdentity
        var stagingIdentity: HarnessHomeRecoveryIdentity
        var copiedEntries: [String]
        let providerHistoryRecoveryChoice: ProviderHistoryRecoveryChoice
    }

    private struct ReceiptlessRecoveryEnvelope: Codable {
        let payload: ReceiptlessRecoveryJournal
        let authenticationTag: String
    }

    /// Exact schema emitted before the provider-history privacy epoch. It is
    /// intentionally separate from the current journal: missing consent must
    /// never decode as an optional/defaulted current choice.
    private struct LegacyReceiptlessRecoveryJournalV1: Codable, Equatable {
        let formatVersion: Int
        let operationID: UUID
        var phase: ReceiptlessTransactionPhase
        let rootName: String
        let stagingName: String
        let quarantineName: String
        let parentIdentity: HarnessHomeRecoveryIdentity
        let recoveryDirectoryIdentity: HarnessHomeRecoveryIdentity
        let sourceIdentity: HarnessHomeRecoveryIdentity
        var stagingIdentity: HarnessHomeRecoveryIdentity
        var copiedEntries: [String]
    }

    private struct LegacyReceiptlessRecoveryEnvelopeV1: Codable {
        let payload: LegacyReceiptlessRecoveryJournalV1
        let authenticationTag: String
    }

    private enum AuthenticatedReceiptlessRecoveryJournal {
        case current(ReceiptlessRecoveryJournal)
        case legacyV1(LegacyReceiptlessRecoveryJournalV1)
    }

    private struct PreparationDeadline {
        let uptimeNanoseconds: UInt64
        let cancellationCheck: (() throws -> Void)?

        init(duration: TimeInterval, cancellationCheck: (() throws -> Void)? = nil) {
            let started = DispatchTime.now().uptimeNanoseconds
            let nanoseconds = UInt64(max(0, min(duration, 300)) * 1_000_000_000)
            let (candidate, overflow) = started.addingReportingOverflow(nanoseconds)
            uptimeNanoseconds = overflow ? UInt64.max : candidate
            self.cancellationCheck = cancellationCheck
        }

        func check() throws {
            try cancellationCheck?()
            guard DispatchTime.now().uptimeNanoseconds < uptimeNanoseconds else {
                throw HarnessHomeError.preparationLimitExceeded("monotonic deadline")
            }
        }
    }

    private final class ReceiptlessRecoveryLease {
        let descriptor: Int32
        let createdLock: Bool

        init(descriptor: Int32, createdLock: Bool) {
            self.descriptor = descriptor
            self.createdLock = createdLock
        }

        deinit {
            _ = flock(descriptor, LOCK_UN)
            Darwin.close(descriptor)
        }
    }

    private struct MigrationState {
        var nodes = 0
        var aggregateBytes: Int64 = 0
    }

    private let fileManager: FileManager
    let root: URL
    let legacyRoot: URL
    private let limits: Limits
    private let migrationCrashHook: (@Sendable (HarnessHomeMigrationPhase) -> Bool)?
    private let receiptlessRecoveryCrashHook: (@Sendable (HarnessHomeReceiptlessRecoveryPhase) -> Bool)?
    private let receiptlessRecoveryDescriptorTestHook: (@Sendable (
        HarnessHomeReceiptlessRecoveryDescriptorPoint,
        Int32
    ) throws -> Void)?
    private let makeUUID: @Sendable () -> UUID
    private let recoveryAuthenticationKeyClient: StateBackupAuthenticationKeyClient?
    private let recoveryAuthenticationKeyProvider: @Sendable () throws -> Data
    private let recoveryAuthenticationKeyCacheLock = NSLock()
    private var admittedRecoveryAuthenticationKey: Data?
    private let interruptedRequestAliasLock = NSLock()
    private var interruptedRequestAlias: (
        original: HarnessHomeInterruptedRecoveryRequest,
        refreshed: HarnessHomeInterruptedRecoveryRequest
    )?

    private static let historicalReceiptEntries: Set<String> = [
        "settings.yaml", "settings.json", "sessions", "storages", "attachments"
    ]
    private static let formerEmptySkillsScaffoldName = "skills"
    private static let formerEmptySkillsScaffoldChildren: Set<String> = ["Active", "Packages"]
    private static let maximumFallbackPackages = 2_048
    private static let migrationReceiptName = ".local-harness-home.json"
    private static let migrationStagingName = ".local-harness-home-migration-v1"
    private static let maximumMigrationReceiptBytes = 64 * 1_024
    private static let maximumHistoricalSettingsFileBytes: Int64 = 8 * 1_024 * 1_024
    private static let maximumHistoricalSettingsAggregateBytes: Int64 = 16 * 1_024 * 1_024
    static let receiptlessRecoveryDirectoryName = "HarnessHomeRecovery"
    static let receiptlessRecoveryJournalName = ".receiptless-recovery-transaction.json"
    static let receiptlessRecoveryLockName = ".receiptless-recovery.lock"
    private static let receiptlessRecoveryStagingPrefix = ".repairing-"
    private static let receiptlessRecoveryQuarantinePrefix = "receiptless-"
    private static let legacyRecoveryOutputPrefix = ".historical-output-"
    private static let maximumReceiptlessRecoveryJournalBytes = 128 * 1_024
    private static let maximumReceiptlessRecoveryNamespaceEntries = 4_096
    private static let maximumReceiptlessRecoveryClockSkew: TimeInterval = 1
    private static let receiptlessRecoveryFormatVersion = 2
    private static let runtimeTemporaryDirectoryName = "Temp"
    private static let disposableRuntimeTemporaryPrefixes = ["dsh-spill-", "dsh-subprocess-"]

    init(
        root: URL,
        legacyRoot: URL? = nil,
        fileManager: FileManager = .default,
        limits: Limits = Limits(),
        migrationCrashHook: (@Sendable (HarnessHomeMigrationPhase) -> Bool)? = nil,
        recoveryAuthenticationKey: Data? = nil,
        recoveryAuthenticationKeyProvider: (@Sendable () throws -> Data)? = nil,
        makeUUID: @escaping @Sendable () -> UUID = { UUID() },
        receiptlessRecoveryCrashHook: (@Sendable (HarnessHomeReceiptlessRecoveryPhase) -> Bool)? = nil,
        receiptlessRecoveryDescriptorTestHook: (@Sendable (
            HarnessHomeReceiptlessRecoveryDescriptorPoint,
            Int32
        ) throws -> Void)? = nil
    ) {
        self.root = root
        self.fileManager = fileManager
        self.legacyRoot = legacyRoot ?? fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".dsh", isDirectory: true)
        self.limits = limits
        self.migrationCrashHook = migrationCrashHook
        self.makeUUID = makeUUID
        self.receiptlessRecoveryCrashHook = receiptlessRecoveryCrashHook
        self.receiptlessRecoveryDescriptorTestHook = receiptlessRecoveryDescriptorTestHook
        if let recoveryAuthenticationKeyProvider {
            recoveryAuthenticationKeyClient = nil
            self.recoveryAuthenticationKeyProvider = recoveryAuthenticationKeyProvider
        } else if let recoveryAuthenticationKey {
            recoveryAuthenticationKeyClient = nil
            self.recoveryAuthenticationKeyProvider = { recoveryAuthenticationKey }
        } else {
            let client = StateBackupAuthenticationKeyClient()
            recoveryAuthenticationKeyClient = client
            self.recoveryAuthenticationKeyProvider = { try client.loadOrCreate() }
        }
    }

    func prepare(cancellationCheck: (() throws -> Void)? = nil) throws {
        guard limits.isValid else {
            throw HarnessHomeError.preparationLimitExceeded("invalid configured bounds")
        }
        let deadline = PreparationDeadline(
            duration: limits.preparationDuration,
            cancellationCheck: cancellationCheck
        )
        try deadline.check()
        let parent = root.deletingLastPathComponent().standardizedFileURL
        if !nodeExists(parent) {
            try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: parent.path)
        }
        let parentDescriptor = try openHarnessHomeParentDirectory()
        defer { Darwin.close(parentDescriptor) }
        let rootName = root.lastPathComponent
        guard Self.validPathComponent(rootName) else {
            throw HarnessHomeError.unsafeProfile("Harness home has an invalid leaf name")
        }
        if let interrupted = try detectInterruptedReceiptlessRecovery(
            parentDescriptor: parentDescriptor,
            rootName: rootName,
            deadline: deadline
        ) {
            throw HarnessHomeError.receiptlessRecoveryInterrupted(interrupted)
        }
        try recoverOrInstallHarnessHome(
            parentDescriptor: parentDescriptor,
            rootName: rootName,
            deadline: deadline
        )
        try requireSecureNode(root, directory: true, label: "Harness home")
        let rootDescriptor = try openSecureDirectory(root, label: "Harness home")
        defer { Darwin.close(rootDescriptor) }
        let receipt = try readAndValidateMigrationReceipt(
            beneath: rootDescriptor,
            deadline: deadline
        )
        try requireCurrentProviderHistoryPrivacyEpoch(receipt)
        try removeEmptyRuntimeTemporaryArtifacts(
            beneath: rootDescriptor,
            deadline: deadline
        )
        try verifyCompositionInputs(deadline: deadline)
    }

    /// Credential-free, mutation-free admission used before a background
    /// pre-upgrade backup. It creates no parent/home/recovery node, performs no
    /// cleanup or migration, and never asks for an authentication key. Its only
    /// purpose is to surface an already-pending receiptless or interrupted
    /// recovery before backup/catalog/runtime work can begin.
    func preflightHarnessHomeRecovery(
        cancellationCheck: (() throws -> Void)? = nil
    ) throws -> HarnessHomeRecoveryPreflightStatus {
        guard limits.isValid else {
            throw HarnessHomeError.preparationLimitExceeded("invalid configured bounds")
        }
        let deadline = PreparationDeadline(
            duration: limits.preparationDuration,
            cancellationCheck: cancellationCheck
        )
        try deadline.check()
        let parent = root.deletingLastPathComponent().standardizedFileURL
        guard nodeExists(parent) else { return .absent }
        let parentDescriptor = try openHarnessHomeParentDirectory()
        defer { Darwin.close(parentDescriptor) }
        let rootName = root.lastPathComponent
        guard Self.validPathComponent(rootName) else {
            throw HarnessHomeError.unsafeProfile("Harness home has an invalid leaf name")
        }
        if let interrupted = try detectInterruptedReceiptlessRecovery(
            parentDescriptor: parentDescriptor,
            rootName: rootName,
            deadline: deadline
        ) {
            throw HarnessHomeError.receiptlessRecoveryInterrupted(interrupted)
        }
        guard let rootMetadata = try metadata(named: rootName, beneath: parentDescriptor) else {
            try requireHarnessHomeParentDirectoryBinding(parentDescriptor)
            return .absent
        }
        guard secureDirectory(rootMetadata) else {
            throw HarnessHomeError.unsafeProfile("Harness home is linked or unsafe")
        }
        let sourceIdentity = HarnessHomeRecoveryIdentity(rootMetadata)
        let rootDescriptor = try openReceiptlessSource(
            parentDescriptor: parentDescriptor,
            rootName: rootName,
            expected: sourceIdentity
        )
        defer { Darwin.close(rootDescriptor) }
        if try metadata(named: Self.migrationReceiptName, beneath: rootDescriptor) != nil {
            let receipt = try readAndValidateMigrationReceipt(
                beneath: rootDescriptor,
                deadline: deadline
            )
            if ProviderHistoryPrivacyEpoch.isCurrent(
                receiptVersion: receipt.version,
                epoch: receipt.providerHistoryPrivacyEpoch
            ) {
                try requireDescriptorIdentity(rootDescriptor, expected: sourceIdentity)
                try requireHarnessHomeParentDirectoryBinding(parentDescriptor)
                return .current
            }
        }
        try validateOpaqueHistoricalRootCapability(
            descriptor: rootDescriptor,
            deadline: deadline
        )
        try requireDescriptorIdentity(rootDescriptor, expected: sourceIdentity)
        try requireHarnessHomeParentDirectoryBinding(parentDescriptor)
        throw HarnessHomeError.receiptlessRecoveryRequired(
            HarnessHomeReceiptlessRecoveryRequest(root: root, sourceIdentity: sourceIdentity)
        )
    }

    /// The caller must invoke this only after the user explicitly chooses to
    /// preserve the older home and start a repaired copy. Detection and Cancel
    /// never reach this method and therefore perform neither filesystem writes
    /// nor Keychain access.
    func recoverReceiptlessHomeAfterExplicitConfirmation(
        _ request: HarnessHomeReceiptlessRecoveryRequest,
        choice: ProviderHistoryRecoveryChoice,
        attestationRotation: HarnessHomeAttestationStore.RotationSession? = nil,
        cancellationCheck: (() throws -> Void)? = nil
    ) throws -> HarnessHomeReceiptlessRecoveryReceipt {
        guard limits.isValid, request.root.standardizedFileURL == root.standardizedFileURL else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let deadline = PreparationDeadline(
            duration: limits.preparationDuration,
            cancellationCheck: cancellationCheck
        )
        let parentDescriptor = try openHarnessHomeParentDirectory()
        defer { Darwin.close(parentDescriptor) }
        let rootName = root.lastPathComponent
        guard Self.validPathComponent(rootName) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }

        var recoveryDescriptor: Int32
        if let existingRecovery = try openReceiptlessRecoveryDirectoryIfPresent(
            parentDescriptor: parentDescriptor
        ) {
            recoveryDescriptor = existingRecovery
            if try metadata(
                named: Self.receiptlessRecoveryJournalName,
                beneath: recoveryDescriptor
            ) != nil {
                Darwin.close(recoveryDescriptor)
                guard let interrupted = try detectInterruptedReceiptlessRecovery(
                    parentDescriptor: parentDescriptor,
                    rootName: rootName,
                    deadline: deadline
                ) else {
                    throw HarnessHomeError.receiptlessRecoveryStateChanged
                }
                throw HarnessHomeError.receiptlessRecoveryInterrupted(interrupted)
            }
        } else {
            recoveryDescriptor = try openOrCreateReceiptlessRecoveryDirectory(
                parentDescriptor: parentDescriptor,
                deadline: deadline
            )
        }
        defer { Darwin.close(recoveryDescriptor) }

        let transactionLease = try acquireReceiptlessRecoveryLease(
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        defer { withExtendedLifetime(transactionLease) {} }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )

        // A peer may have published a journal between the initial prompt and
        // lease acquisition. Treat that as a newly interrupted transaction;
        // this path must not load or create a replacement authentication key.
        if try metadata(
            named: Self.receiptlessRecoveryJournalName,
            beneath: recoveryDescriptor
        ) != nil {
            guard let interrupted = try detectInterruptedReceiptlessRecovery(
                parentDescriptor: parentDescriptor,
                rootName: rootName,
                deadline: deadline
            ) else {
                throw HarnessHomeError.receiptlessRecoveryStateChanged
            }
            throw HarnessHomeError.receiptlessRecoveryInterrupted(interrupted)
        }

        try removeOrphanedEmptyReceiptlessRecoveryStaging(
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )

        let sourceDescriptor = try openReceiptlessSource(
            parentDescriptor: parentDescriptor,
            rootName: rootName,
            expected: request.sourceIdentity
        )
        defer { Darwin.close(sourceDescriptor) }
        try validateOpaqueHistoricalRootCapability(
            descriptor: sourceDescriptor,
            deadline: deadline
        )
        try requireDescriptorIdentity(sourceDescriptor, expected: request.sourceIdentity)
        var reboundSource = stat()
        guard fstatat(parentDescriptor, rootName, &reboundSource, AT_SYMLINK_NOFOLLOW) == 0,
              HarnessHomeRecoveryIdentity(reboundSource) == request.sourceIdentity else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }

        // Load-or-create is permitted only for a genuinely new transaction and
        // only after the source and empty journal namespace are pinned under the
        // interprocess lease.
        let key = try receiptlessRecoveryAuthenticationKey()
        let parentIdentity = try directoryIdentity(parentDescriptor, exactPrivate: false)
        let recoveryIdentity = try directoryIdentity(recoveryDescriptor, exactPrivate: true)
        guard try metadata(named: Self.receiptlessRecoveryJournalName, beneath: recoveryDescriptor) == nil else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }

        let operationID = makeUUID()
        // `makeUUID` is injectable in adversarial tests and represents arbitrary
        // work between lease acquisition and namespace mutation. Rebind both the
        // configured parent and recovery leaf after it returns, before creating
        // staging or moving the source.
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        let operation = operationID.uuidString.lowercased()
        let stagingName = Self.receiptlessRecoveryStagingPrefix + operation
        let quarantineName = Self.receiptlessRecoveryQuarantinePrefix + operation
        guard Self.validPathComponent(stagingName), Self.validPathComponent(quarantineName),
              try metadata(named: stagingName, beneath: recoveryDescriptor) == nil,
              try metadata(named: quarantineName, beneath: recoveryDescriptor) == nil,
              mkdirat(recoveryDescriptor, stagingName, mode_t(0o700)) == 0,
              Darwin.fsync(recoveryDescriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let stagingDescriptor = try openMigrationDirectory(
            named: stagingName,
            beneath: recoveryDescriptor,
            label: "receiptless recovery staging directory"
        )
        Darwin.close(stagingDescriptor)
        try interruptReceiptlessRecoveryIfRequested(.initialStagingDurable)
        var journal = ReceiptlessRecoveryJournal(
            formatVersion: Self.receiptlessRecoveryFormatVersion,
            operationID: operationID,
            phase: .prepared,
            rootName: rootName,
            stagingName: stagingName,
            quarantineName: quarantineName,
            parentIdentity: parentIdentity,
            recoveryDirectoryIdentity: recoveryIdentity,
            sourceIdentity: request.sourceIdentity,
            stagingIdentity: try identity(
                named: stagingName,
                beneath: recoveryDescriptor,
                exactPrivateDirectory: true
            ),
            copiedEntries: [],
            providerHistoryRecoveryChoice: choice
        )
        do {
            try writeReceiptlessRecoveryJournal(
                journal,
                key: key,
                recoveryDescriptor: recoveryDescriptor,
                expectedPrevious: nil,
                deadline: deadline
            )
        } catch {
            // Once a journal entry may have been published, retain its exact
            // staging directory so a later authenticated reconciliation can
            // finish safely. Cleanup is allowed only when no journal exists.
            let originalError = error
            let journalMetadata: stat?
            do {
                journalMetadata = try metadata(
                    named: Self.receiptlessRecoveryJournalName,
                    beneath: recoveryDescriptor
                )
            } catch {
                throw originalError
            }
            if case nil = journalMetadata,
               let current = try? metadata(named: stagingName, beneath: recoveryDescriptor),
               HarnessHomeRecoveryIdentity(current) == journal.stagingIdentity {
                try? removeBoundedTree(
                    named: stagingName,
                    beneath: recoveryDescriptor,
                    deadline: deadline
                )
            }
            throw originalError
        }
        if let attestationRotation {
            try attestationRotation.begin(
                operationID: journal.operationID,
                choice: journal.providerHistoryRecoveryChoice.attestationChoice,
                stagedRootURL: recoveryStagingURL(journal)
            )
        }
        try interruptReceiptlessRecoveryIfRequested(.journalPrepared)

        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        try durableExclusiveRename(
            sourceName: rootName,
            sourceParent: parentDescriptor,
            destinationName: quarantineName,
            destinationParent: recoveryDescriptor,
            expectedIdentity: journal.sourceIdentity,
            deadline: deadline
        )
        try interruptReceiptlessRecoveryIfRequested(.sourceQuarantined)
        let previousPhase = journal.phase
        journal.phase = .sourceQuarantined
        try writeReceiptlessRecoveryJournal(
            journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            expectedPrevious: previousPhase,
            deadline: deadline
        )
        try interruptReceiptlessRecoveryIfRequested(.sourceQuarantineRecorded)

        journal = try populateReceiptlessRecoveryStaging(
            journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )

        journal = try installReceiptlessRecoveryReceipt(
            journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )

        return try publishReceiptlessRecovery(
            journal,
            key: key,
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor,
            attestationRotation: attestationRotation,
            deadline: deadline
        )
    }

    /// Continues only the exact journal which was detected without credentials
    /// during startup. Production requires a foreground-authorized existing key;
    /// an interrupted transaction must never create a replacement key.
    func resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
        _ request: HarnessHomeInterruptedRecoveryRequest,
        intent: HarnessHomeInterruptedRecoveryIntent,
        attestationRotation: HarnessHomeAttestationStore.RotationSession? = nil,
        cancellationCheck: (() throws -> Void)? = nil
    ) throws -> HarnessHomeReceiptlessRecoveryReceipt {
        guard limits.isValid,
              request.root.standardizedFileURL == root.standardizedFileURL,
              intent.request == request else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let deadline = PreparationDeadline(
            duration: limits.preparationDuration,
            cancellationCheck: cancellationCheck
        )
        let parentDescriptor = try openHarnessHomeParentDirectory()
        defer { Darwin.close(parentDescriptor) }
        guard let recoveryDescriptor = try openReceiptlessRecoveryDirectoryIfPresent(
            parentDescriptor: parentDescriptor
        ) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        defer { Darwin.close(recoveryDescriptor) }
        try validateInterruptedRecoveryRequest(
            request,
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        let lease = try acquireReceiptlessRecoveryLease(
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline,
            createIfMissing: true
        )
        defer { withExtendedLifetime(lease) {} }
        if lease.createdLock {
            try recordLegacyLockTransition(
                from: request,
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline
            )
        }
        try validateInterruptedRecoveryRequest(
            request,
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        let key = try receiptlessRecoveryExistingAuthenticationKey()
        let authenticated = try readAuthenticatedReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        guard authenticatedOperationAndChoice(authenticated).operationID == intent.operationID,
              authenticatedOperationAndChoice(authenticated).choice == intent.choice else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        return try reconcileReceiptlessRecovery(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor,
            rootName: root.lastPathComponent,
            key: key,
            attestationRotation: attestationRotation,
            deadline: deadline
        )
    }

    /// Removes the durable published marker only after foreground presentation
    /// has completed. Until this succeeds, every relaunch re-presents the same
    /// authenticated receipt and background launches remain stopped.
    func acknowledgePublishedReceiptlessRecovery(
        _ receipt: HarnessHomeReceiptlessRecoveryReceipt,
        cancellationCheck: (() throws -> Void)? = nil
    ) throws {
        guard limits.isValid, let completion = receipt.completion else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let deadline = PreparationDeadline(
            duration: limits.preparationDuration,
            cancellationCheck: cancellationCheck
        )
        let parentDescriptor = try openHarnessHomeParentDirectory()
        defer { Darwin.close(parentDescriptor) }
        guard try directoryIdentity(parentDescriptor, exactPrivate: false) == completion.parentIdentity,
              let recoveryDescriptor = try openReceiptlessRecoveryDirectoryIfPresent(
                  parentDescriptor: parentDescriptor
              ) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        defer { Darwin.close(recoveryDescriptor) }
        let lease = try acquireReceiptlessRecoveryLease(
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline,
            createIfMissing: false
        )
        defer { withExtendedLifetime(lease) {} }
        guard try directoryIdentity(recoveryDescriptor, exactPrivate: true)
                == completion.recoveryDirectoryIdentity,
              try currentPromptIdentity(
                  named: Self.receiptlessRecoveryJournalName,
                  beneath: recoveryDescriptor
              ) == completion.journalIdentity else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let key = try receiptlessRecoveryExistingAuthenticationKey()
        let journal = try readReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        guard journal.operationID == completion.operationID,
              journal.phase == .published,
              recoveryQuarantineURL(journal) == receipt.quarantine,
              journal.copiedEntries == receipt.copiedEntries else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        try clearReceiptlessRecoveryJournal(
            expected: journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        try interruptReceiptlessRecoveryIfRequested(.journalCleared)
    }

    /// Runs only after a foreground user action. If an interrupted authenticated
    /// journal exists, the candidate key must authenticate that exact journal
    /// before it is admitted to this manager's process cache.
    func authorizeReceiptlessRecoveryKeyForForeground(
        interruptedRequest: HarnessHomeInterruptedRecoveryRequest? = nil
    ) throws -> HarnessHomeInterruptedRecoveryIntent? {
        let deadline = PreparationDeadline(duration: limits.preparationDuration)
        var parentDescriptor: Int32 = -1
        var recoveryDescriptor: Int32 = -1
        var lease: ReceiptlessRecoveryLease?
        // Install ownership before the first throwing child lookup. In
        // particular, an unsafe/ACL-bearing recovery directory can make
        // `openReceiptlessRecoveryDirectoryIfPresent` throw after the parent was
        // opened; every such path must still close the exact parent descriptor.
        defer {
            withExtendedLifetime(lease) {}
            if recoveryDescriptor >= 0 { Darwin.close(recoveryDescriptor) }
            if parentDescriptor >= 0 { Darwin.close(parentDescriptor) }
        }
        var authenticatedIntent: HarnessHomeInterruptedRecoveryIntent?
        if let interruptedRequest {
            parentDescriptor = try openHarnessHomeParentDirectory()
            guard let openedRecovery = try openReceiptlessRecoveryDirectoryIfPresent(
                parentDescriptor: parentDescriptor
            ) else {
                throw HarnessHomeError.receiptlessRecoveryStateChanged
            }
            recoveryDescriptor = openedRecovery
            try validateInterruptedRecoveryRequest(
                interruptedRequest,
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor
            )
            lease = try acquireReceiptlessRecoveryLease(
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline,
                createIfMissing: true
            )
            if lease?.createdLock == true {
                try recordLegacyLockTransition(
                    from: interruptedRequest,
                    parentDescriptor: parentDescriptor,
                    recoveryDescriptor: recoveryDescriptor,
                    deadline: deadline
                )
            }
            try validateInterruptedRecoveryRequest(
                interruptedRequest,
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor
            )
        }
        let candidate: Data
        if let recoveryAuthenticationKeyClient {
            do { candidate = try recoveryAuthenticationKeyClient.authorizeExistingForForeground() }
            catch let error as BackupError {
                switch error {
                case .authenticationAuthorizationRequired:
                    throw HarnessHomeError.receiptlessRecoveryAuthenticationRequired
                default:
                    throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
                }
            }
            catch { throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable }
        } else {
            do { candidate = try recoveryAuthenticationKeyProvider() }
            catch { throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable }
        }
        guard candidate.count == 32 else {
            throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
        }
        if let interruptedRequest {
            try validateInterruptedRecoveryRequest(
                interruptedRequest,
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor
            )
            let authenticated = try readAuthenticatedReceiptlessRecoveryJournal(
                key: SymmetricKey(data: candidate),
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline
            )
            let bound = authenticatedOperationAndChoice(authenticated)
            authenticatedIntent = HarnessHomeInterruptedRecoveryIntent(
                operationID: bound.operationID,
                choice: bound.choice,
                request: interruptedRequest
            )
        }
        admitRecoveryAuthenticationKey(candidate)
        recoveryAuthenticationKeyClient?.admitValidatedKey(candidate)
        return authenticatedIntent
    }

    private func authenticatedOperationAndChoice(
        _ journal: AuthenticatedReceiptlessRecoveryJournal
    ) -> (operationID: UUID, choice: ProviderHistoryRecoveryChoice) {
        switch journal {
        case .current(let current):
            return (current.operationID, current.providerHistoryRecoveryChoice)
        case .legacyV1(let legacy):
            // Format 1 has no import choice. Its authenticated format version
            // binds the only privacy-safe upgrade policy: preserve all old
            // output opaquely and start the replacement home clean.
            return (legacy.operationID, .startClean)
        }
    }

    /// DSH creates one private scratch directory for each managed subprocess,
    /// even when it never spills output. A clean shutdown does not currently
    /// remove those empty roots. Reclaim only exact, empty, owner-controlled
    /// directories while the embedded runtime is stopped. Unknown, linked,
    /// nonempty, or wrong-type entries are retained without being traversed.
    private func removeEmptyRuntimeTemporaryArtifacts(
        beneath rootDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        guard let temporaryDescriptor = try openOptionalDirectory(
            named: Self.runtimeTemporaryDirectoryName,
            beneath: rootDescriptor,
            label: "runtime temporary directory"
        ) else { return }
        defer { Darwin.close(temporaryDescriptor) }

        var inspected = 0
        var candidates: [String] = []
        try forEachDirectoryEntry(descriptor: temporaryDescriptor, deadline: deadline) { name in
            inspected += 1
            guard inspected <= limits.maximumRuntimeTemporaryEntries else {
                throw HarnessHomeError.preparationLimitExceeded("runtime temporary entry count")
            }
            guard Self.disposableRuntimeTemporaryPrefixes.contains(where: name.hasPrefix),
                  Self.validPathComponent(name) else { return }
            candidates.append(name)
        }

        var removedAny = false
        for name in candidates {
            try deadline.check()
            guard let pathMetadata = try metadata(named: name, beneath: temporaryDescriptor),
                  secureDirectory(pathMetadata) else { continue }
            let descriptor = openat(
                temporaryDescriptor,
                name,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard descriptor >= 0 else { continue }

            var opened = stat()
            var after = stat()
            let isEmptyAndStable: Bool
            do {
                var stable = Darwin.fstat(descriptor, &opened) == 0
                    && Self.sameIdentity(pathMetadata, opened)
                    && secureDirectory(opened)
                if stable {
                    stable = try firstDirectoryEntry(
                        descriptor: descriptor,
                        deadline: deadline
                    ) == nil
                }
                if stable {
                    stable = Darwin.fstat(descriptor, &after) == 0
                        && Self.sameIdentity(opened, after)
                }
                isEmptyAndStable = stable
                Darwin.close(descriptor)
            } catch {
                Darwin.close(descriptor)
                throw error
            }
            guard isEmptyAndStable else { continue }

            var finalPathMetadata = stat()
            guard fstatat(
                temporaryDescriptor,
                name,
                &finalPathMetadata,
                AT_SYMLINK_NOFOLLOW
            ) == 0,
                  Self.sameIdentity(opened, finalPathMetadata) else { continue }
            if unlinkat(temporaryDescriptor, name, AT_REMOVEDIR) == 0 {
                removedAny = true
            } else if errno != ENOENT && errno != ENOTEMPTY {
                throw HarnessHomeError.unsafeProfile("runtime temporary artifact could not be removed safely")
            }
        }
        if removedAny, Darwin.fsync(temporaryDescriptor) != 0 {
            throw HarnessHomeError.unsafeProfile("runtime temporary cleanup could not be made durable")
        }
    }

    func verifyCompositionInputs() throws {
        guard limits.isValid else {
            throw HarnessHomeError.preparationLimitExceeded("invalid configured bounds")
        }
        try verifyCompositionInputs(
            deadline: PreparationDeadline(duration: limits.preparationDuration)
        )
    }

    private func verifyCompositionInputs(deadline: PreparationDeadline) throws {
        try deadline.check()
        let rootDescriptor = try openSecureDirectory(root, label: "Harness home")
        defer { Darwin.close(rootDescriptor) }

        if try metadata(named: "cordis.patch.yml", beneath: rootDescriptor) != nil {
            throw HarnessHomeError.unsafeHomePatch(root.appendingPathComponent("cordis.patch.yml").path)
        }
        for name in ["settings.yaml", "settings.json"] {
            if let value = try metadata(named: name, beneath: rootDescriptor) {
                guard secureRegular(value) else {
                    throw HarnessHomeError.unsafeProfile(
                        "\(name) is linked, has the wrong type, ownership, link count, or unsafe write permissions"
                    )
                }
            }
        }

        guard let profilesDescriptor = try openOptionalDirectory(
            named: "profiles",
            beneath: rootDescriptor,
            label: "profiles"
        ) else { return }
        defer { Darwin.close(profilesDescriptor) }

        var profileBytes: Int64 = 0
        if let profileDescriptor = try openOptionalDirectory(
            named: "web",
            beneath: profilesDescriptor,
            label: "web profile"
        ) {
            defer { Darwin.close(profileDescriptor) }
            if let modulesDescriptor = try openOptionalDirectory(
                named: "node_modules",
                beneath: profileDescriptor,
                label: "web profile modules"
            ) {
                defer { Darwin.close(modulesDescriptor) }
                if try firstDirectoryEntry(descriptor: modulesDescriptor, deadline: deadline) != nil {
                    throw HarnessHomeError.unsafeProfile("profile-local module overrides are disabled")
                }
            }

            if try metadata(named: "cordis.patch.yml", beneath: profileDescriptor) != nil {
                let data = try readBoundedProfileFile(
                    named: "cordis.patch.yml",
                    beneath: profileDescriptor,
                    aggregateBytes: &profileBytes,
                    deadline: deadline
                )
                guard let text = String(data: data, encoding: .utf8) else {
                    throw HarnessHomeError.unsafeProfile("web/cordis.patch.yml is not UTF-8")
                }
                let normalized = text
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                    .joined(separator: "\n")
                try deadline.check()
                guard normalized == "[]" else {
                    throw HarnessHomeError.unsafeProfile("web/cordis.patch.yml is not the reviewed empty layer")
                }
            }

            if try metadata(named: "package.json", beneath: profileDescriptor) != nil {
                let data = try readBoundedProfileFile(
                    named: "package.json",
                    beneath: profileDescriptor,
                    aggregateBytes: &profileBytes,
                    deadline: deadline
                )
                guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let dependencies = object["dependencies"] as? [String: Any], dependencies.isEmpty,
                      let dsh = object["dsh"] as? [String: Any],
                      let profileObject = dsh["profile"] as? [String: Any],
                      let bundles = profileObject["bundles"] as? [String],
                      bundles == ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"] else {
                    throw HarnessHomeError.unsafeProfile(
                        "web/package.json contains an unreviewed bundle or dependency"
                    )
                }
                try deadline.check()
            }
        }
        try verifyInstallationFallback(
            profilesDescriptor: profilesDescriptor,
            deadline: deadline
        )
    }

    private func readBoundedProfileFile(
        named name: String,
        beneath directoryDescriptor: Int32,
        aggregateBytes: inout Int64,
        deadline: PreparationDeadline
    ) throws -> Data {
        try deadline.check()
        guard let pathMetadata = try metadata(named: name, beneath: directoryDescriptor),
              secureRegular(pathMetadata),
              pathMetadata.st_size >= 0 else {
            throw HarnessHomeError.unsafeProfile("web/\(name) is not a private regular file")
        }
        let size = Int64(pathMetadata.st_size)
        guard size <= limits.maximumProfileFileBytes,
              size <= limits.maximumProfileAggregateBytes - aggregateBytes else {
            throw HarnessHomeError.profileInputTooLarge("web/\(name)")
        }
        let descriptor = openat(
            directoryDescriptor,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeProfile("web/\(name) could not be opened safely")
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              secureRegular(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.unsafeProfile("web/\(name) changed while opening")
        }

        var result = Data()
        result.reserveCapacity(Int(size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            try deadline.check()
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw HarnessHomeError.unsafeProfile("web/\(name) could not be read safely")
            }
            guard Int64(result.count + count) <= limits.maximumProfileFileBytes,
                  Int64(result.count + count) <= limits.maximumProfileAggregateBytes - aggregateBytes else {
                throw HarnessHomeError.profileInputTooLarge("web/\(name)")
            }
            result.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Self.sameIdentity(opened, after),
              result.count == Int(size) else {
            throw HarnessHomeError.unsafeProfile("web/\(name) changed while reading")
        }
        aggregateBytes += Int64(result.count)
        return result
    }

    private func nodeExists(_ url: URL) -> Bool {
        var value = stat()
        return Darwin.lstat(url.path, &value) == 0
    }

    private func requireSecureNode(_ url: URL, directory: Bool, label: String) throws {
        var value = stat()
        guard Darwin.lstat(url.path, &value) == 0,
              value.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              value.st_uid == geteuid(),
              value.st_mode & (S_IWGRP | S_IWOTH) == 0,
              directory || value.st_nlink == 1 else {
            throw HarnessHomeError.unsafeProfile(
                "\(label) is linked, has the wrong type, ownership, link count, or unsafe write permissions"
            )
        }
    }

    private func openSecureDirectory(_ url: URL, label: String) throws -> Int32 {
        var pathMetadata = stat()
        guard Darwin.lstat(url.path, &pathMetadata) == 0,
              secureDirectory(pathMetadata) else {
            throw HarnessHomeError.unsafeProfile("\(label) is linked or unsafe")
        }
        let descriptor = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeProfile("\(label) could not be opened safely")
        }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              secureDirectory(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            throw HarnessHomeError.unsafeProfile("\(label) changed while opening")
        }
        return descriptor
    }

    /// Opens the configured Harness-home parent through its exact grandparent
    /// descriptor. Holding a parent descriptor alone is insufficient: the parent
    /// path can be renamed and replaced while descriptor-relative recovery keeps
    /// operating inside the displaced inode. Every recovery mutation reuses the
    /// companion validator below to prove that the descriptor is still the leaf
    /// currently named by the configured absolute path.
    private func openHarnessHomeParentDirectory() throws -> Int32 {
        let parent = root.deletingLastPathComponent().standardizedFileURL
        let grandparent = parent.deletingLastPathComponent().standardizedFileURL
        let parentName = parent.lastPathComponent
        guard parent.isFileURL,
              parent.path.hasPrefix("/"),
              parent != grandparent,
              Self.validPathComponent(parentName) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let grandparentDescriptor = try openHarnessHomeParentAncestor(grandparent)
        defer { Darwin.close(grandparentDescriptor) }

        var declared = stat()
        guard fstatat(grandparentDescriptor, parentName, &declared, AT_SYMLINK_NOFOLLOW) == 0,
              secureDirectory(declared) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let descriptor = openat(
            grandparentDescriptor,
            parentName,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        do {
            try requireHarnessHomeParentDirectoryBinding(
                descriptor,
                grandparentDescriptor: grandparentDescriptor,
                grandparent: grandparent,
                parentName: parentName,
                declaredParent: declared
            )
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func requireHarnessHomeParentDirectoryBinding(
        _ parentDescriptor: Int32
    ) throws {
        let parent = root.deletingLastPathComponent().standardizedFileURL
        let grandparent = parent.deletingLastPathComponent().standardizedFileURL
        let parentName = parent.lastPathComponent
        guard parent.isFileURL,
              parent.path.hasPrefix("/"),
              parent != grandparent,
              Self.validPathComponent(parentName) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let grandparentDescriptor = try openHarnessHomeParentAncestor(grandparent)
        defer { Darwin.close(grandparentDescriptor) }
        var declared = stat()
        guard fstatat(grandparentDescriptor, parentName, &declared, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        try requireHarnessHomeParentDirectoryBinding(
            parentDescriptor,
            grandparentDescriptor: grandparentDescriptor,
            grandparent: grandparent,
            parentName: parentName,
            declaredParent: declared
        )
    }

    private func requireHarnessHomeParentDirectoryBinding(
        _ parentDescriptor: Int32,
        grandparentDescriptor: Int32,
        grandparent: URL,
        parentName: String,
        declaredParent: stat
    ) throws {
        var openedGrandparent = stat()
        var reboundGrandparent = stat()
        var openedParent = stat()
        var reboundParent = stat()
        guard Darwin.fstat(grandparentDescriptor, &openedGrandparent) == 0,
              Darwin.lstat(grandparent.path, &reboundGrandparent) == 0,
              Self.sameDirectoryBindingIdentity(openedGrandparent, reboundGrandparent),
              secureHarnessHomeParentAncestor(openedGrandparent),
              try Self.descriptorHasNoExtendedACL(grandparentDescriptor),
              Darwin.fstat(parentDescriptor, &openedParent) == 0,
              Self.sameDirectoryBindingIdentity(declaredParent, openedParent),
              secureDirectory(openedParent),
              try Self.descriptorHasNoExtendedACL(parentDescriptor),
              fstatat(
                  grandparentDescriptor,
                  parentName,
                  &reboundParent,
                  AT_SYMLINK_NOFOLLOW
              ) == 0,
              Self.sameDirectoryBindingIdentity(openedParent, reboundParent) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
    }

    private func openHarnessHomeParentAncestor(_ url: URL) throws -> Int32 {
        var declared = stat()
        guard Darwin.lstat(url.path, &declared) == 0,
              secureHarnessHomeParentAncestor(declared) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameDirectoryBindingIdentity(declared, opened),
              secureHarnessHomeParentAncestor(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        return descriptor
    }

    private func secureHarnessHomeParentAncestor(_ value: stat) -> Bool {
        guard value.st_mode & S_IFMT == S_IFDIR else { return false }
        let unsafeWrites = value.st_mode & (S_IWGRP | S_IWOTH) != 0
        if !unsafeWrites {
            return value.st_uid == geteuid() || value.st_uid == 0
        }
        // Private test/application roots may sit directly beneath the
        // root-owned sticky temporary directory. Sticky ownership prevents a
        // different user from renaming this process's secure parent leaf.
        return value.st_uid == 0 && value.st_mode & S_ISVTX != 0
    }

    private func openOptionalDirectory(
        named name: String,
        beneath parentDescriptor: Int32,
        label: String
    ) throws -> Int32? {
        guard let pathMetadata = try metadata(named: name, beneath: parentDescriptor) else { return nil }
        guard secureDirectory(pathMetadata) else {
            throw HarnessHomeError.unsafeProfile("\(label) is linked or unsafe")
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeProfile("\(label) could not be opened safely")
        }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              secureDirectory(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            throw HarnessHomeError.unsafeProfile("\(label) changed while opening")
        }
        return descriptor
    }

    private func metadata(named name: String, beneath descriptor: Int32) throws -> stat? {
        var value = stat()
        if fstatat(descriptor, name, &value, AT_SYMLINK_NOFOLLOW) == 0 { return value }
        if errno == ENOENT { return nil }
        throw HarnessHomeError.unsafeProfile("could not inspect \(name) safely")
    }

    private func firstDirectoryEntry(
        descriptor: Int32,
        deadline: PreparationDeadline
    ) throws -> String? {
        let iterationDescriptor = Darwin.dup(descriptor)
        guard iterationDescriptor >= 0 else {
            throw HarnessHomeError.unsafeProfile("could not inspect directory safely")
        }
        guard let stream = fdopendir(iterationDescriptor) else {
            Darwin.close(iterationDescriptor)
            throw HarnessHomeError.unsafeProfile("could not inspect directory safely")
        }
        defer { closedir(stream) }
        // Each bounded-removal iteration deletes the entry it just returned.
        // Restart from the beginning so filesystem directory cookies cannot
        // skip a sibling after that mutation.
        rewinddir(stream)
        while true {
            try deadline.check()
            errno = 0
            guard let entry = readdir(stream) else {
                if errno != 0 { throw HarnessHomeError.unsafeProfile("could not inspect directory safely") }
                return nil
            }
            let name = try Self.directoryEntryName(entry)
            if name != "." && name != ".." { return name }
        }
    }

    private func verifyInstallationFallback(
        profilesDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        guard let fallbackDescriptor = try openOptionalDirectory(
            named: "node_modules",
            beneath: profilesDescriptor,
            label: "installation module fallback"
        ) else { return }
        var fallbackMetadata = stat()
        guard Darwin.fstat(fallbackDescriptor, &fallbackMetadata) == 0 else {
            Darwin.close(fallbackDescriptor)
            throw HarnessHomeError.unsafeProfile("installation module fallback could not be inspected")
        }
        var inspected = 0
        do {
            try forEachDirectoryEntry(descriptor: fallbackDescriptor, deadline: deadline) { entry in
                inspected += 1
                guard inspected <= Self.maximumFallbackPackages,
                      entry.utf8.count <= limits.maximumRelativePathBytes else {
                    throw HarnessHomeError.preparationLimitExceeded("installation fallback entries")
                }
                guard let value = try metadata(named: entry, beneath: fallbackDescriptor) else {
                    throw HarnessHomeError.unsafeProfile("installation fallback entry disappeared")
                }
                if entry.hasPrefix("@") {
                    guard secureDirectory(value),
                          let scope = try openOptionalDirectory(
                              named: entry,
                              beneath: fallbackDescriptor,
                              label: "installation fallback scope"
                          ) else {
                        throw HarnessHomeError.unsafeProfile("installation fallback scope is unsafe")
                    }
                    defer { Darwin.close(scope) }
                    try forEachDirectoryEntry(descriptor: scope, deadline: deadline) { package in
                        inspected += 1
                        guard inspected <= Self.maximumFallbackPackages,
                              "\(entry)/\(package)".utf8.count <= limits.maximumRelativePathBytes else {
                            throw HarnessHomeError.preparationLimitExceeded("installation fallback entries")
                        }
                        guard let packageMetadata = try metadata(named: package, beneath: scope),
                              packageMetadata.st_mode & S_IFMT == S_IFLNK else {
                            throw HarnessHomeError.unsafeProfile(
                                "installation fallback contains a non-link package: \(entry)/\(package)"
                            )
                        }
                    }
                } else {
                    guard value.st_mode & S_IFMT == S_IFLNK else {
                        throw HarnessHomeError.unsafeProfile(
                            "installation fallback contains a non-link package: \(entry)"
                        )
                    }
                }
            }
            try deadline.check()
            var after = stat()
            guard Darwin.fstat(fallbackDescriptor, &after) == 0,
                  Self.sameIdentity(fallbackMetadata, after) else {
                throw HarnessHomeError.unsafeProfile("installation module fallback changed during inspection")
            }
            Darwin.close(fallbackDescriptor)
        } catch {
            Darwin.close(fallbackDescriptor)
            throw error
        }

        let fallback = root.appendingPathComponent("profiles/node_modules", isDirectory: true)
        var pathMetadata = stat()
        guard Darwin.lstat(fallback.path, &pathMetadata) == 0,
              Self.sameIdentity(fallbackMetadata, pathMetadata) else {
            throw HarnessHomeError.unsafeProfile("installation module fallback changed before removal")
        }
        try fileManager.removeItem(at: fallback)
        try deadline.check()
    }

    private func receiptlessRecoveryAuthenticationKey() throws -> SymmetricKey {
        do {
            let bytes = try recoveryAuthenticationKeyProvider()
            guard bytes.count == 32 else {
                throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
            }
            admitRecoveryAuthenticationKey(bytes)
            return SymmetricKey(data: bytes)
        } catch let error as HarnessHomeError {
            throw error
        } catch let error as BackupError {
            switch error {
            case .authenticationAuthorizationRequired:
                throw HarnessHomeError.receiptlessRecoveryAuthenticationRequired
            default:
                throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
            }
        } catch {
            throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
        }
    }

    private func receiptlessRecoveryExistingAuthenticationKey() throws -> SymmetricKey {
        if let bytes = admittedRecoveryAuthenticationKeyBytes(), bytes.count == 32 {
            return SymmetricKey(data: bytes)
        }
        if recoveryAuthenticationKeyClient != nil {
            guard admittedRecoveryAuthenticationKeyBytes() != nil else {
                throw HarnessHomeError.receiptlessRecoveryAuthenticationRequired
            }
            throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
        }
        // Deterministic injected providers are used only by tests. Production's
        // client branch above can return only an already-admitted existing key.
        return try receiptlessRecoveryAuthenticationKey()
    }

    private func admitRecoveryAuthenticationKey(_ bytes: Data) {
        guard bytes.count == 32 else { return }
        recoveryAuthenticationKeyCacheLock.lock()
        admittedRecoveryAuthenticationKey = bytes
        recoveryAuthenticationKeyCacheLock.unlock()
    }

    private func admittedRecoveryAuthenticationKeyBytes() -> Data? {
        recoveryAuthenticationKeyCacheLock.lock()
        defer { recoveryAuthenticationKeyCacheLock.unlock() }
        return admittedRecoveryAuthenticationKey
    }

    private func interruptReceiptlessRecoveryIfRequested(
        _ phase: HarnessHomeReceiptlessRecoveryPhase
    ) throws {
        if receiptlessRecoveryCrashHook?(phase) == true {
            throw HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(phase)
        }
    }

    private func directoryIdentity(
        _ descriptor: Int32,
        exactPrivate: Bool
    ) throws -> HarnessHomeRecoveryIdentity {
        var value = stat()
        guard Darwin.fstat(descriptor, &value) == 0,
              (exactPrivate ? Self.secureStagedDirectory(value) : secureDirectory(value)),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        return HarnessHomeRecoveryIdentity(value)
    }

    private func identity(
        named name: String,
        beneath parentDescriptor: Int32,
        exactPrivateDirectory: Bool
    ) throws -> HarnessHomeRecoveryIdentity {
        guard let value = try metadata(named: name, beneath: parentDescriptor),
              (exactPrivateDirectory ? Self.secureStagedDirectory(value) : secureDirectory(value)) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        return HarnessHomeRecoveryIdentity(value)
    }

    private func requireDescriptorIdentity(
        _ descriptor: Int32,
        expected: HarnessHomeRecoveryIdentity,
        exactPrivate: Bool = false
    ) throws {
        var value = stat()
        guard Darwin.fstat(descriptor, &value) == 0,
              HarnessHomeRecoveryIdentity(value) == expected,
              (exactPrivate ? Self.secureStagedDirectory(value) : secureDirectory(value)),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
    }

    private func openReceiptlessSource(
        parentDescriptor: Int32,
        rootName: String,
        expected: HarnessHomeRecoveryIdentity
    ) throws -> Int32 {
        guard let pathMetadata = try metadata(named: rootName, beneath: parentDescriptor),
              HarnessHomeRecoveryIdentity(pathMetadata) == expected,
              secureDirectory(pathMetadata) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let descriptor = openat(
            parentDescriptor,
            rootName,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw HarnessHomeError.receiptlessRecoveryStateChanged }
        do {
            try requireDescriptorIdentity(descriptor, expected: expected)
            var rebound = stat()
            guard fstatat(parentDescriptor, rootName, &rebound, AT_SYMLINK_NOFOLLOW) == 0,
                  HarnessHomeRecoveryIdentity(rebound) == expected else {
                throw HarnessHomeError.receiptlessRecoveryStateChanged
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func validateOpaqueHistoricalRootCapability(
        descriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        // Provider-history state is an opaque preservation unit. Do not list or
        // parse its child namespace: doing so would rediscover sessions,
        // attachments, Skills, provider caches, or future unknown state before
        // the user's explicit privacy decision. The already-open directory and
        // its ACL/ownership boundary are the complete admission proof.
        try deadline.check()
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              secureDirectory(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
    }

    private func openReceiptlessRecoveryDirectoryIfPresent(
        parentDescriptor: Int32
    ) throws -> Int32? {
        guard try metadata(
            named: Self.receiptlessRecoveryDirectoryName,
            beneath: parentDescriptor
        ) != nil else { return nil }
        return try openMigrationDirectory(
            named: Self.receiptlessRecoveryDirectoryName,
            beneath: parentDescriptor,
            label: "receiptless recovery directory"
        )
    }

    private func openOrCreateReceiptlessRecoveryDirectory(
        parentDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws -> Int32 {
        try deadline.check()
        try requireHarnessHomeParentDirectoryBinding(parentDescriptor)
        if let existing = try openReceiptlessRecoveryDirectoryIfPresent(
            parentDescriptor: parentDescriptor
        ) {
            do {
                try requireRecoveryDirectoryBinding(
                    parentDescriptor: parentDescriptor,
                    recoveryDescriptor: existing
                )
                return existing
            } catch {
                Darwin.close(existing)
                throw error
            }
        }
        guard mkdirat(
            parentDescriptor,
            Self.receiptlessRecoveryDirectoryName,
            mode_t(0o700)
        ) == 0,
              Darwin.fsync(parentDescriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let descriptor = try openMigrationDirectory(
            named: Self.receiptlessRecoveryDirectoryName,
            beneath: parentDescriptor,
            label: "receiptless recovery directory"
        )
        do {
            try requireRecoveryDirectoryBinding(
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: descriptor
            )
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    /// A process can die after fsyncing its empty `.repairing-UUID` directory but
    /// before exclusively publishing the first journal. With no authenticated
    /// journal, only that exact empty/private/name-bound shape is safe to reclaim.
    /// The fixed lease excludes a live peer, while enumeration, time, type,
    /// identity, ACL, and emptiness checks keep cleanup bounded and fail closed.
    private func removeOrphanedEmptyReceiptlessRecoveryStaging(
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        let scanTime = Date().timeIntervalSince1970
        var inspected = 0
        var candidates: [(name: String, metadata: stat)] = []
        try forEachDirectoryEntry(descriptor: recoveryDescriptor, deadline: deadline) { name in
            inspected += 1
            guard inspected <= Self.maximumReceiptlessRecoveryNamespaceEntries else {
                throw HarnessHomeError.preparationLimitExceeded(
                    "receiptless recovery namespace entry count"
                )
            }
            guard name.hasPrefix(Self.receiptlessRecoveryStagingPrefix) else { return }
            let identifier = String(name.dropFirst(Self.receiptlessRecoveryStagingPrefix.count))
            guard let uuid = UUID(uuidString: identifier),
                  identifier == uuid.uuidString.lowercased(),
                  let value = try metadata(named: name, beneath: recoveryDescriptor),
                  Self.secureStagedDirectory(value) else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            let modification = Double(value.st_mtimespec.tv_sec)
                + Double(value.st_mtimespec.tv_nsec) / 1_000_000_000
            let change = Double(value.st_ctimespec.tv_sec)
                + Double(value.st_ctimespec.tv_nsec) / 1_000_000_000
            guard modification.isFinite,
                  change.isFinite,
                  modification <= scanTime + Self.maximumReceiptlessRecoveryClockSkew,
                  change <= scanTime + Self.maximumReceiptlessRecoveryClockSkew else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            candidates.append((name, value))
        }

        for candidate in candidates {
            try deadline.check()
            try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
            try withRecoveryDirectory(
                named: candidate.name,
                beneath: recoveryDescriptor,
                expected: HarnessHomeRecoveryIdentity(candidate.metadata),
                exactPrivate: true
            ) { descriptor in
                var opened = stat()
                var rebound = stat()
                guard Darwin.fstat(descriptor, &opened) == 0,
                      Self.sameIdentity(candidate.metadata, opened),
                      try firstDirectoryEntry(
                          descriptor: descriptor,
                          deadline: deadline
                      ) == nil,
                      fstatat(
                          recoveryDescriptor,
                          candidate.name,
                          &rebound,
                          AT_SYMLINK_NOFOLLOW
                      ) == 0,
                      Self.sameIdentity(opened, rebound) else {
                    throw HarnessHomeError.receiptlessRecoveryJournalInvalid
                }
                try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
                guard unlinkat(recoveryDescriptor, candidate.name, AT_REMOVEDIR) == 0,
                      Darwin.fsync(recoveryDescriptor) == 0 else {
                    throw HarnessHomeError.receiptlessRecoveryJournalInvalid
                }
            }
            try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        }
    }

    private func acquireReceiptlessRecoveryLease(
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline,
        createIfMissing: Bool = true
    ) throws -> ReceiptlessRecoveryLease {
        try deadline.check()
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        var created = false
        var descriptor = openat(
            recoveryDescriptor,
            Self.receiptlessRecoveryLockName,
            O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0, errno == ENOENT, createIfMissing {
            descriptor = openat(
                recoveryDescriptor,
                Self.receiptlessRecoveryLockName,
                O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
            if descriptor >= 0 {
                created = true
            } else if errno == EEXIST {
                descriptor = openat(
                    recoveryDescriptor,
                    Self.receiptlessRecoveryLockName,
                    O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                )
            }
        }
        guard descriptor >= 0 else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        var locked = false
        do {
            if created {
                guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
                      Darwin.fsync(descriptor) == 0,
                      Darwin.fsync(recoveryDescriptor) == 0 else {
                    throw HarnessHomeError.receiptlessRecoveryJournalInvalid
                }
            }
            var opened = stat()
            var rebound = stat()
            guard Darwin.fstat(descriptor, &opened) == 0,
                  Self.secureStagedRegular(opened),
                  opened.st_size == 0,
                  try Self.descriptorHasNoExtendedACL(descriptor) else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            while true {
                try deadline.check()
                if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                    locked = true
                    break
                }
                if errno == EINTR { continue }
                if errno == EWOULDBLOCK || errno == EAGAIN {
                    throw HarnessHomeError.receiptlessRecoveryInProgress
                }
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            guard fstatat(
                recoveryDescriptor,
                Self.receiptlessRecoveryLockName,
                &rebound,
                AT_SYMLINK_NOFOLLOW
            ) == 0,
                  Self.sameIdentity(opened, rebound),
                  try Self.descriptorHasNoExtendedACL(descriptor) else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
            return ReceiptlessRecoveryLease(descriptor: descriptor, createdLock: created)
        } catch {
            if locked { _ = flock(descriptor, LOCK_UN) }
            Darwin.close(descriptor)
            if created {
                _ = unlinkat(recoveryDescriptor, Self.receiptlessRecoveryLockName, 0)
                _ = Darwin.fsync(recoveryDescriptor)
            }
            throw error
        }
    }

    private func currentPromptIdentity(
        named name: String,
        beneath parentDescriptor: Int32
    ) throws -> HarnessHomeRecoveryPromptIdentity {
        guard Self.validPathComponent(name),
              let pathMetadata = try metadata(named: name, beneath: parentDescriptor),
              Self.secureStagedRegular(pathMetadata),
              pathMetadata.st_size > 0,
              pathMetadata.st_size <= off_t(Self.maximumReceiptlessRecoveryJournalBytes) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        var rebound = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              Self.secureStagedRegular(opened),
              try Self.descriptorHasNoExtendedACL(descriptor),
              fstatat(parentDescriptor, name, &rebound, AT_SYMLINK_NOFOLLOW) == 0,
              Self.sameIdentity(opened, rebound) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        return HarnessHomeRecoveryPromptIdentity(opened)
    }

    private func validateInterruptedRecoveryRequest(
        _ request: HarnessHomeInterruptedRecoveryRequest,
        parentDescriptor: Int32,
        recoveryDescriptor: Int32
    ) throws {
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        let expected = resolvedInterruptedRecoveryRequest(request)
        guard expected.root.standardizedFileURL == root.standardizedFileURL else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        var parentMetadata = stat()
        var recoveryMetadata = stat()
        var reboundRecovery = stat()
        guard Darwin.fstat(parentDescriptor, &parentMetadata) == 0,
              Darwin.fstat(recoveryDescriptor, &recoveryMetadata) == 0,
              fstatat(
                  parentDescriptor,
                  Self.receiptlessRecoveryDirectoryName,
                  &reboundRecovery,
                  AT_SYMLINK_NOFOLLOW
              ) == 0,
              Self.sameIdentity(recoveryMetadata, reboundRecovery),
              HarnessHomeRecoveryPromptIdentity(parentMetadata) == expected.parentIdentity,
              HarnessHomeRecoveryPromptIdentity(recoveryMetadata)
                == expected.recoveryDirectoryIdentity,
              try Self.descriptorHasNoExtendedACL(parentDescriptor),
              try Self.descriptorHasNoExtendedACL(recoveryDescriptor),
              try currentPromptIdentity(
                  named: Self.receiptlessRecoveryJournalName,
                  beneath: recoveryDescriptor
              ) == expected.journalIdentity else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
    }

    /// A journal written by a release predating the fixed transaction lock has
    /// no lock entry. The explicit foreground Resume/Authorize action may add
    /// exactly that private file. Bind the original prompt to a refreshed exact
    /// identity only when the parent and journal are byte-for-byte the same and
    /// the recovery directory itself is still the same protected inode.
    private func recordLegacyLockTransition(
        from original: HarnessHomeInterruptedRecoveryRequest,
        parentDescriptor: Int32,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        let refreshed = try captureInterruptedReceiptlessRecoveryRequest(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        guard refreshed.parentIdentity == original.parentIdentity,
              refreshed.journalIdentity == original.journalIdentity,
              Self.sameProtectedDirectory(
                  refreshed.recoveryDirectoryIdentity,
                  original.recoveryDirectoryIdentity
              ) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        interruptedRequestAliasLock.lock()
        interruptedRequestAlias = (original, refreshed)
        interruptedRequestAliasLock.unlock()
    }

    private func resolvedInterruptedRecoveryRequest(
        _ request: HarnessHomeInterruptedRecoveryRequest
    ) -> HarnessHomeInterruptedRecoveryRequest {
        interruptedRequestAliasLock.lock()
        defer { interruptedRequestAliasLock.unlock() }
        guard let alias = interruptedRequestAlias,
              alias.original == request else { return request }
        return alias.refreshed
    }

    private func captureInterruptedReceiptlessRecoveryRequest(
        parentDescriptor: Int32,
        recoveryDescriptor: Int32
    ) throws -> HarnessHomeInterruptedRecoveryRequest {
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        var parentMetadata = stat()
        var recoveryMetadata = stat()
        var reboundRecovery = stat()
        guard Darwin.fstat(parentDescriptor, &parentMetadata) == 0,
              Darwin.fstat(recoveryDescriptor, &recoveryMetadata) == 0,
              fstatat(
                  parentDescriptor,
                  Self.receiptlessRecoveryDirectoryName,
                  &reboundRecovery,
                  AT_SYMLINK_NOFOLLOW
              ) == 0,
              Self.sameIdentity(recoveryMetadata, reboundRecovery),
              try Self.descriptorHasNoExtendedACL(parentDescriptor),
              try Self.descriptorHasNoExtendedACL(recoveryDescriptor) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        return HarnessHomeInterruptedRecoveryRequest(
            root: root,
            parentIdentity: HarnessHomeRecoveryPromptIdentity(parentMetadata),
            recoveryDirectoryIdentity: HarnessHomeRecoveryPromptIdentity(recoveryMetadata),
            journalIdentity: try currentPromptIdentity(
                named: Self.receiptlessRecoveryJournalName,
                beneath: recoveryDescriptor
            )
        )
    }

    private func requireRecoveryDirectoryBinding(
        parentDescriptor: Int32,
        recoveryDescriptor: Int32
    ) throws {
        try requireHarnessHomeParentDirectoryBinding(parentDescriptor)
        var opened = stat()
        var rebound = stat()
        guard Darwin.fstat(recoveryDescriptor, &opened) == 0,
              Self.secureStagedDirectory(opened),
              try Self.descriptorHasNoExtendedACL(recoveryDescriptor),
              fstatat(
                  parentDescriptor,
                  Self.receiptlessRecoveryDirectoryName,
                  &rebound,
                  AT_SYMLINK_NOFOLLOW
              ) == 0,
              Self.sameIdentity(opened, rebound) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
    }

    private func requireConfiguredRecoveryDirectoryBinding(
        _ recoveryDescriptor: Int32
    ) throws {
        let parentDescriptor = try openHarnessHomeParentDirectory()
        defer { Darwin.close(parentDescriptor) }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
    }

    private static func sameProtectedDirectory(
        _ lhs: HarnessHomeRecoveryPromptIdentity,
        _ rhs: HarnessHomeRecoveryPromptIdentity
    ) -> Bool {
        // A legacy journal has no fixed lease file. Creating that one exact
        // regular file is the only namespace transition admitted here. APFS
        // changes a directory's link count as children are added, so link count,
        // size, and timestamps cannot be part of the stable inode binding.
        // The caller separately requires the parent and journal prompt
        // identities to remain byte-for-byte unchanged.
        lhs.device == rhs.device
            && lhs.inode == rhs.inode
            && lhs.owner == rhs.owner
            && lhs.permissions == rhs.permissions
            && lhs.kind == rhs.kind
    }

    private func detectInterruptedReceiptlessRecovery(
        parentDescriptor: Int32,
        rootName: String,
        deadline: PreparationDeadline
    ) throws -> HarnessHomeInterruptedRecoveryRequest? {
        try deadline.check()
        guard Self.validPathComponent(rootName) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        guard let recoveryDescriptor = try openReceiptlessRecoveryDirectoryIfPresent(
            parentDescriptor: parentDescriptor
        ) else { return nil }
        defer { Darwin.close(recoveryDescriptor) }
        guard let pathMetadata = try metadata(
            named: Self.receiptlessRecoveryJournalName,
            beneath: recoveryDescriptor
        ) else { return nil }
        guard Self.secureStagedRegular(pathMetadata),
              pathMetadata.st_size > 0,
              pathMetadata.st_size <= off_t(Self.maximumReceiptlessRecoveryJournalBytes) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let journalDescriptor = openat(
            recoveryDescriptor,
            Self.receiptlessRecoveryJournalName,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard journalDescriptor >= 0 else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        defer { Darwin.close(journalDescriptor) }
        var journalMetadata = stat()
        var reboundJournal = stat()
        guard Darwin.fstat(journalDescriptor, &journalMetadata) == 0,
              Self.sameIdentity(pathMetadata, journalMetadata),
              Self.secureStagedRegular(journalMetadata),
              try Self.descriptorHasNoExtendedACL(journalDescriptor),
              fstatat(
                  recoveryDescriptor,
                  Self.receiptlessRecoveryJournalName,
                  &reboundJournal,
                  AT_SYMLINK_NOFOLLOW
              ) == 0,
              Self.sameIdentity(journalMetadata, reboundJournal) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let captured = try captureInterruptedReceiptlessRecoveryRequest(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        guard captured.journalIdentity == HarnessHomeRecoveryPromptIdentity(journalMetadata) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        return captured
    }

    private func recoveryAuthenticationTag<T: Encodable>(
        for payload: T,
        key: SymmetricKey
    ) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(payload)
        return Data(HMAC<SHA256>.authenticationCode(for: bytes, using: key)).base64EncodedString()
    }

    private func verifyRecoveryAuthenticationTag<T: Encodable>(
        for payload: T,
        supplied: String,
        key: SymmetricKey
    ) throws -> Bool {
        guard let suppliedBytes = Data(base64Encoded: supplied),
              suppliedBytes.count == SHA256.byteCount else { return false }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: try encoder.encode(payload),
            using: key
        ))
        guard suppliedBytes.count == expected.count else { return false }
        var difference: UInt8 = 0
        for index in suppliedBytes.indices { difference |= suppliedBytes[index] ^ expected[index] }
        return difference == 0
    }

    private func validateReceiptlessRecoveryJournal(
        _ journal: ReceiptlessRecoveryJournal
    ) throws {
        let operation = journal.operationID.uuidString.lowercased()
        let expectedStaging = Self.receiptlessRecoveryStagingPrefix + operation
        let expectedQuarantine = Self.receiptlessRecoveryQuarantinePrefix + operation
        let directoryKind = UInt16(truncatingIfNeeded: S_IFDIR)
        guard journal.formatVersion == Self.receiptlessRecoveryFormatVersion,
              journal.rootName == root.lastPathComponent,
              journal.stagingName == expectedStaging,
              journal.quarantineName == expectedQuarantine,
              Self.validPathComponent(journal.rootName),
              Self.validPathComponent(journal.stagingName),
              Self.validPathComponent(journal.quarantineName),
              journal.parentIdentity.kind == directoryKind,
              journal.parentIdentity.owner == geteuid(),
              journal.parentIdentity.permissions & 0o022 == 0,
              journal.recoveryDirectoryIdentity.kind == directoryKind,
              journal.recoveryDirectoryIdentity.owner == geteuid(),
              journal.recoveryDirectoryIdentity.permissions & 0o777 == 0o700,
              journal.sourceIdentity.kind == directoryKind,
              journal.sourceIdentity.owner == geteuid(),
              journal.sourceIdentity.permissions & 0o022 == 0,
              journal.stagingIdentity.kind == directoryKind,
              journal.stagingIdentity.owner == geteuid(),
              journal.stagingIdentity.permissions & 0o777 == 0o700,
              journal.copiedEntries == journal.copiedEntries.sorted(),
              Set(journal.copiedEntries).count == journal.copiedEntries.count,
              journal.copiedEntries.count <= ProviderHistoryPrivacyEpoch.settingsFileNames.count,
              journal.copiedEntries.allSatisfy(
                  ProviderHistoryPrivacyEpoch.settingsFileNames.contains
              ),
              (journal.providerHistoryRecoveryChoice == .settingsOnly
                || journal.copiedEntries.isEmpty),
              (journal.phase >= .contentDurable || journal.copiedEntries.isEmpty) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
    }

    private func validateLegacyReceiptlessRecoveryJournalV1(
        _ journal: LegacyReceiptlessRecoveryJournalV1
    ) throws {
        let operation = journal.operationID.uuidString.lowercased()
        let directoryKind = UInt16(truncatingIfNeeded: S_IFDIR)
        guard journal.formatVersion == 1,
              journal.rootName == root.lastPathComponent,
              journal.stagingName == Self.receiptlessRecoveryStagingPrefix + operation,
              journal.quarantineName == Self.receiptlessRecoveryQuarantinePrefix + operation,
              Self.validPathComponent(journal.rootName),
              Self.validPathComponent(journal.stagingName),
              Self.validPathComponent(journal.quarantineName),
              journal.parentIdentity.kind == directoryKind,
              journal.parentIdentity.owner == geteuid(),
              journal.parentIdentity.permissions & 0o022 == 0,
              journal.recoveryDirectoryIdentity.kind == directoryKind,
              journal.recoveryDirectoryIdentity.owner == geteuid(),
              journal.recoveryDirectoryIdentity.permissions & 0o777 == 0o700,
              journal.sourceIdentity.kind == directoryKind,
              journal.sourceIdentity.owner == geteuid(),
              journal.sourceIdentity.permissions & 0o022 == 0,
              journal.stagingIdentity.kind == directoryKind,
              journal.stagingIdentity.owner == geteuid(),
              journal.stagingIdentity.permissions & 0o777 == 0o700,
              journal.copiedEntries == journal.copiedEntries.sorted(),
              Set(journal.copiedEntries).count == journal.copiedEntries.count,
              journal.copiedEntries.count <= Self.historicalReceiptEntries.count,
              journal.copiedEntries.allSatisfy(Self.historicalReceiptEntries.contains),
              (journal.phase >= .contentDurable || journal.copiedEntries.isEmpty) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
    }

    private func readReceiptlessRecoveryJournal(
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws -> ReceiptlessRecoveryJournal {
        guard case .current(let journal) = try readAuthenticatedReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        ) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        return journal
    }

    private func readAuthenticatedReceiptlessRecoveryJournal(
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws -> AuthenticatedReceiptlessRecoveryJournal {
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        let data = try readBoundedPrivateRecoveryFile(
            named: Self.receiptlessRecoveryJournalName,
            beneath: recoveryDescriptor,
            maximumBytes: Self.maximumReceiptlessRecoveryJournalBytes,
            deadline: deadline
        )
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["payload", "authenticationTag"]),
              let payloadObject = object["payload"] as? [String: Any],
              let formatVersion = payloadObject["formatVersion"] as? Int else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        switch formatVersion {
        case Self.receiptlessRecoveryFormatVersion:
            guard Self.exactReceiptlessRecoveryJournalSchema(payloadObject),
                  let envelope = try? JSONDecoder().decode(
                    ReceiptlessRecoveryEnvelope.self,
                    from: data
                  ),
                  try verifyRecoveryAuthenticationTag(
                    for: envelope.payload,
                    supplied: envelope.authenticationTag,
                    key: key
                  ) else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try validateReceiptlessRecoveryJournal(envelope.payload)
            return .current(envelope.payload)
        case 1:
            guard Self.exactLegacyReceiptlessRecoveryJournalV1Schema(payloadObject),
                  let envelope = try? JSONDecoder().decode(
                    LegacyReceiptlessRecoveryEnvelopeV1.self,
                    from: data
                  ),
                  try verifyRecoveryAuthenticationTag(
                    for: envelope.payload,
                    supplied: envelope.authenticationTag,
                    key: key
                  ) else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try validateLegacyReceiptlessRecoveryJournalV1(envelope.payload)
            return .legacyV1(envelope.payload)
        default:
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
    }

    private static func exactReceiptlessRecoveryJournalSchema(
        _ object: [String: Any]
    ) -> Bool {
        let identityKeys: Set<String> = ["device", "inode", "owner", "permissions", "kind"]
        let identityNames = [
            "parentIdentity", "recoveryDirectoryIdentity", "sourceIdentity", "stagingIdentity"
        ]
        let payloadKeys: Set<String> = [
            "formatVersion", "operationID", "phase", "rootName", "stagingName",
            "quarantineName", "parentIdentity", "recoveryDirectoryIdentity",
            "sourceIdentity", "stagingIdentity", "copiedEntries",
            "providerHistoryRecoveryChoice"
        ]
        guard Set(object.keys) == payloadKeys else { return false }
        return identityNames.allSatisfy { name in
            guard let identity = object[name] as? [String: Any] else { return false }
            return Set(identity.keys) == identityKeys
        }
    }

    private static func exactLegacyReceiptlessRecoveryJournalV1Schema(
        _ object: [String: Any]
    ) -> Bool {
        let identityKeys: Set<String> = ["device", "inode", "owner", "permissions", "kind"]
        let identityNames = [
            "parentIdentity", "recoveryDirectoryIdentity", "sourceIdentity", "stagingIdentity"
        ]
        let payloadKeys: Set<String> = [
            "formatVersion", "operationID", "phase", "rootName", "stagingName",
            "quarantineName", "parentIdentity", "recoveryDirectoryIdentity",
            "sourceIdentity", "stagingIdentity", "copiedEntries"
        ]
        guard Set(object.keys) == payloadKeys else { return false }
        return identityNames.allSatisfy { name in
            guard let identity = object[name] as? [String: Any] else { return false }
            return Set(identity.keys) == identityKeys
        }
    }

    private func writeReceiptlessRecoveryJournal(
        _ journal: ReceiptlessRecoveryJournal,
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        expectedPrevious: ReceiptlessTransactionPhase?,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        try validateReceiptlessRecoveryJournal(journal)
        if let expectedPrevious {
            let current = try readReceiptlessRecoveryJournal(
                key: key,
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline
            )
            guard current.operationID == journal.operationID,
                  current.phase == expectedPrevious,
                  journal.phase.rawValue == current.phase.rawValue + 1,
                  current.rootName == journal.rootName,
                  current.stagingName == journal.stagingName,
                  current.quarantineName == journal.quarantineName,
                  current.parentIdentity == journal.parentIdentity,
                  current.recoveryDirectoryIdentity == journal.recoveryDirectoryIdentity,
                  current.sourceIdentity == journal.sourceIdentity,
                  current.stagingIdentity == journal.stagingIdentity,
                  current.providerHistoryRecoveryChoice == journal.providerHistoryRecoveryChoice,
                  (journal.phase == .contentDurable
                    || current.copiedEntries == journal.copiedEntries) else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
        } else if try metadata(
            named: Self.receiptlessRecoveryJournalName,
            beneath: recoveryDescriptor
        ) != nil {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }

        let envelope = ReceiptlessRecoveryEnvelope(
            payload: journal,
            authenticationTag: try recoveryAuthenticationTag(for: journal, key: key)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(envelope)
        guard !data.isEmpty, data.count <= Self.maximumReceiptlessRecoveryJournalBytes else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let temporaryName = ".receiptless-journal-\(journal.operationID.uuidString.lowercased())-\(journal.phase.rawValue)-\(makeUUID().uuidString.lowercased())"
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        guard Self.validPathComponent(temporaryName) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let descriptor = openat(
            recoveryDescriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw HarnessHomeError.receiptlessRecoveryJournalInvalid }
        var temporaryExists = true
        defer {
            Darwin.close(descriptor)
            if temporaryExists { _ = unlinkat(recoveryDescriptor, temporaryName, 0) }
        }
        try Self.writeAll(
            Array(data),
            count: data.count,
            descriptor: descriptor,
            deadline: deadline
        )
        var written = stat()
        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
              Darwin.fsync(descriptor) == 0,
              Darwin.fstat(descriptor, &written) == 0,
              Self.secureStagedRegular(written),
              written.st_size == off_t(data.count),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        let renameStatus: Int32
        if expectedPrevious == nil {
            renameStatus = renameatx_np(
                recoveryDescriptor,
                temporaryName,
                recoveryDescriptor,
                Self.receiptlessRecoveryJournalName,
                UInt32(RENAME_EXCL)
            )
        } else {
            renameStatus = renameat(
                recoveryDescriptor,
                temporaryName,
                recoveryDescriptor,
                Self.receiptlessRecoveryJournalName
            )
        }
        guard renameStatus == 0, Darwin.fsync(recoveryDescriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        temporaryExists = false
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        let installed = try readReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        guard installed == journal else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
    }

    private func replaceAuthenticatedLegacyRecoveryJournal(
        _ legacy: LegacyReceiptlessRecoveryJournalV1,
        with journal: ReceiptlessRecoveryJournal,
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        try validateLegacyReceiptlessRecoveryJournalV1(legacy)
        try validateReceiptlessRecoveryJournal(journal)
        guard case .legacyV1(let installedLegacy) = try readAuthenticatedReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        ), installedLegacy == legacy else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }

        let envelope = ReceiptlessRecoveryEnvelope(
            payload: journal,
            authenticationTag: try recoveryAuthenticationTag(for: journal, key: key)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(envelope)
        guard !data.isEmpty, data.count <= Self.maximumReceiptlessRecoveryJournalBytes else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let temporaryName = ".receiptless-journal-upgrade-\(journal.operationID.uuidString.lowercased())-\(makeUUID().uuidString.lowercased())"
        guard Self.validPathComponent(temporaryName) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let descriptor = openat(
            recoveryDescriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw HarnessHomeError.receiptlessRecoveryJournalInvalid }
        var temporaryExists = true
        defer {
            Darwin.close(descriptor)
            if temporaryExists { _ = unlinkat(recoveryDescriptor, temporaryName, 0) }
        }
        try Self.writeAll(
            Array(data),
            count: data.count,
            descriptor: descriptor,
            deadline: deadline
        )
        var written = stat()
        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
              Darwin.fsync(descriptor) == 0,
              Darwin.fstat(descriptor, &written) == 0,
              Self.secureStagedRegular(written),
              written.st_size == off_t(data.count),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        guard case .legacyV1(let reboundLegacy) = try readAuthenticatedReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        ), reboundLegacy == legacy,
              renameat(
                recoveryDescriptor,
                temporaryName,
                recoveryDescriptor,
                Self.receiptlessRecoveryJournalName
              ) == 0,
              Darwin.fsync(recoveryDescriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        temporaryExists = false
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        guard try readReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        ) == journal else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
    }

    private func readBoundedPrivateRecoveryFile(
        named name: String,
        beneath parentDescriptor: Int32,
        maximumBytes: Int,
        deadline: PreparationDeadline
    ) throws -> Data {
        try deadline.check()
        guard let pathMetadata = try metadata(named: name, beneath: parentDescriptor),
              Self.secureStagedRegular(pathMetadata),
              pathMetadata.st_size > 0,
              pathMetadata.st_size <= off_t(maximumBytes) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw HarnessHomeError.receiptlessRecoveryJournalInvalid }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              Self.secureStagedRegular(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        var result = Data()
        result.reserveCapacity(Int(opened.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
        while true {
            try deadline.check()
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            guard count <= maximumBytes - result.count else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            result.append(contentsOf: buffer.prefix(count))
        }
        var afterDescriptor = stat()
        var afterPath = stat()
        guard result.count == Int(opened.st_size),
              Darwin.fstat(descriptor, &afterDescriptor) == 0,
              fstatat(parentDescriptor, name, &afterPath, AT_SYMLINK_NOFOLLOW) == 0,
              Self.sameIdentity(opened, afterDescriptor),
              Self.sameIdentity(opened, afterPath) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        return result
    }

    private func clearReceiptlessRecoveryJournal(
        expected: ReceiptlessRecoveryJournal,
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        let current = try readReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        guard current == expected, current.phase == .published,
              let pathMetadata = try metadata(
                named: Self.receiptlessRecoveryJournalName,
                beneath: recoveryDescriptor
              ), Self.secureStagedRegular(pathMetadata) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        var rebound = stat()
        guard fstatat(
            recoveryDescriptor,
            Self.receiptlessRecoveryJournalName,
            &rebound,
            AT_SYMLINK_NOFOLLOW
        ) == 0,
              Self.sameIdentity(pathMetadata, rebound),
              unlinkat(recoveryDescriptor, Self.receiptlessRecoveryJournalName, 0) == 0,
              Darwin.fsync(recoveryDescriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
    }

    private func durableExclusiveRename(
        sourceName: String,
        sourceParent: Int32,
        destinationName: String,
        destinationParent: Int32,
        expectedIdentity: HarnessHomeRecoveryIdentity,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        guard Self.validPathComponent(sourceName), Self.validPathComponent(destinationName),
              let sourceMetadata = try metadata(named: sourceName, beneath: sourceParent),
              HarnessHomeRecoveryIdentity(sourceMetadata) == expectedIdentity,
              try metadata(named: destinationName, beneath: destinationParent) == nil,
              renameatx_np(
                sourceParent,
                sourceName,
                destinationParent,
                destinationName,
                UInt32(RENAME_EXCL)
              ) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        guard let rebound = try metadata(named: destinationName, beneath: destinationParent),
              HarnessHomeRecoveryIdentity(rebound) == expectedIdentity,
              Darwin.fsync(destinationParent) == 0,
              (sourceParent == destinationParent || Darwin.fsync(sourceParent) == 0) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
    }

    private func openRecoveryDirectory(
        named name: String,
        beneath parentDescriptor: Int32,
        expected: HarnessHomeRecoveryIdentity,
        exactPrivate: Bool
    ) throws -> Int32 {
        guard let pathMetadata = try metadata(named: name, beneath: parentDescriptor),
              HarnessHomeRecoveryIdentity(pathMetadata) == expected,
              (exactPrivate ? Self.secureStagedDirectory(pathMetadata) : secureDirectory(pathMetadata)) else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw HarnessHomeError.receiptlessRecoveryStateChanged }
        do {
            try requireDescriptorIdentity(descriptor, expected: expected, exactPrivate: exactPrivate)
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func clearRecoveryStagingContents(
        descriptor: Int32,
        expected: HarnessHomeRecoveryIdentity,
        deadline: PreparationDeadline
    ) throws {
        try requireDescriptorIdentity(descriptor, expected: expected, exactPrivate: true)
        var state = MigrationState()
        while let child = try firstDirectoryEntry(descriptor: descriptor, deadline: deadline) {
            try recordMigrationNode(relative: child, depth: 0, state: &state)
            try removeBoundedEntry(
                named: child,
                relative: child,
                depth: 0,
                parentDescriptor: descriptor,
                state: &state,
                permissionPolicy: .privateStaging,
                deadline: deadline
            )
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        try requireDescriptorIdentity(descriptor, expected: expected, exactPrivate: true)
    }

    private func copyReviewedReceiptlessEntries(
        sourceDescriptor: Int32,
        stagingDescriptor: Int32,
        choice: ProviderHistoryRecoveryChoice,
        deadline: PreparationDeadline
    ) throws -> [String] {
        guard choice == .settingsOnly else {
            guard Darwin.fsync(stagingDescriptor) == 0 else {
                throw HarnessHomeError.receiptlessRecoveryStateChanged
            }
            return []
        }
        var copied: [String] = []
        var state = MigrationState()
        // Two exact descriptor-relative probes are intentional. Never enumerate
        // the preserved home, and never recurse into a settings leaf: only a
        // bounded, owner-controlled, O_NOFOLLOW regular file may cross epochs.
        for name in ProviderHistoryPrivacyEpoch.settingsFileNames.sorted() {
            try deadline.check()
            guard let sourceMetadata = try legacyMetadata(
                named: name,
                beneath: sourceDescriptor
            ) else { continue }
            guard sourceMetadata.st_size >= 0,
                  Int64(sourceMetadata.st_size) <= Self.maximumHistoricalSettingsFileBytes,
                  Int64(sourceMetadata.st_size)
                    <= Self.maximumHistoricalSettingsAggregateBytes - state.aggregateBytes else {
                throw HarnessHomeError.migrationTooLarge
            }
            guard try metadata(named: name, beneath: stagingDescriptor) == nil else {
                throw HarnessHomeError.receiptlessRecoveryStateChanged
            }
            try recordMigrationNode(relative: name, depth: 0, state: &state)
            try copyRegularFile(
                named: name,
                relative: name,
                sourceMetadata: sourceMetadata,
                sourceParent: sourceDescriptor,
                destinationParent: stagingDescriptor,
                state: &state,
                deadline: deadline
            )
            copied.append(name)
        }
        guard Darwin.fsync(stagingDescriptor) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        return copied
    }

    private func rebuildReceiptlessRecoveryContent(
        _ journal: ReceiptlessRecoveryJournal,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws -> [String] {
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        let source = try openRecoveryDirectory(
            named: journal.quarantineName,
            beneath: recoveryDescriptor,
            expected: journal.sourceIdentity,
            exactPrivate: false
        )
        defer { Darwin.close(source) }
        try validateOpaqueHistoricalRootCapability(descriptor: source, deadline: deadline)
        try requireDescriptorIdentity(source, expected: journal.sourceIdentity)
        let staging = try openRecoveryDirectory(
            named: journal.stagingName,
            beneath: recoveryDescriptor,
            expected: journal.stagingIdentity,
            exactPrivate: true
        )
        defer { Darwin.close(staging) }
        try clearRecoveryStagingContents(
            descriptor: staging,
            expected: journal.stagingIdentity,
            deadline: deadline
        )
        let copied = try copyReviewedReceiptlessEntries(
            sourceDescriptor: source,
            stagingDescriptor: staging,
            choice: journal.providerHistoryRecoveryChoice,
            deadline: deadline
        )
        try requireDescriptorIdentity(source, expected: journal.sourceIdentity)
        try requireDescriptorIdentity(staging, expected: journal.stagingIdentity, exactPrivate: true)
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        return copied
    }

    private func populateReceiptlessRecoveryStaging(
        _ original: ReceiptlessRecoveryJournal,
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline,
        invokeCrashHooks: Bool = true
    ) throws -> ReceiptlessRecoveryJournal {
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        guard original.phase == .sourceQuarantined else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        var journal = original
        journal.copiedEntries = try rebuildReceiptlessRecoveryContent(
            journal,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        if invokeCrashHooks { try interruptReceiptlessRecoveryIfRequested(.reviewedContentDurable) }
        let previous = journal.phase
        journal.phase = .contentDurable
        try writeReceiptlessRecoveryJournal(
            journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            expectedPrevious: previous,
            deadline: deadline
        )
        if invokeCrashHooks { try interruptReceiptlessRecoveryIfRequested(.contentRecorded) }
        return journal
    }

    private func recoveryQuarantineURL(_ journal: ReceiptlessRecoveryJournal) -> URL {
        root.deletingLastPathComponent()
            .appendingPathComponent(Self.receiptlessRecoveryDirectoryName, isDirectory: true)
            .appendingPathComponent(journal.quarantineName, isDirectory: true)
    }

    private func recoveryStagingURL(_ journal: ReceiptlessRecoveryJournal) -> URL {
        root.deletingLastPathComponent()
            .appendingPathComponent(Self.receiptlessRecoveryDirectoryName, isDirectory: true)
            .appendingPathComponent(journal.stagingName, isDirectory: true)
    }

    private func publishedReceipt(
        _ journal: ReceiptlessRecoveryJournal,
        parentDescriptor: Int32,
        recoveryDescriptor: Int32
    ) throws -> HarnessHomeReceiptlessRecoveryReceipt {
        guard journal.phase == .published else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        return HarnessHomeReceiptlessRecoveryReceipt(
            root: root,
            quarantine: recoveryQuarantineURL(journal),
            copiedEntries: journal.copiedEntries,
            completion: HarnessHomeRecoveryCompletionIdentity(
                operationID: journal.operationID,
                parentIdentity: journal.parentIdentity,
                recoveryDirectoryIdentity: journal.recoveryDirectoryIdentity,
                journalIdentity: try currentPromptIdentity(
                    named: Self.receiptlessRecoveryJournalName,
                    beneath: recoveryDescriptor
                )
            )
        )
    }

    private func installReceiptlessRecoveryReceipt(
        _ original: ReceiptlessRecoveryJournal,
        key: SymmetricKey,
        recoveryDescriptor: Int32,
        deadline: PreparationDeadline,
        invokeCrashHooks: Bool = true
    ) throws -> ReceiptlessRecoveryJournal {
        try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
        guard original.phase == .contentDurable else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        var journal = original
        let receiptIsValid = try withRecoveryDirectory(
            named: journal.stagingName,
            beneath: recoveryDescriptor,
            expected: journal.stagingIdentity,
            exactPrivate: true
        ) { staging in
            try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
            try receiptlessRecoveryDescriptorTestHook?(.receiptProbe, staging)
            guard try metadata(named: Self.migrationReceiptName, beneath: staging) != nil else {
                return false
            }
            return (try? validateReceiptlessMigrationReceipt(
                beneath: staging,
                journal: journal,
                deadline: deadline
            )) != nil
        }
        if !receiptIsValid {
            journal.copiedEntries = try rebuildReceiptlessRecoveryContent(
                journal,
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline
            )
            try withRecoveryDirectory(
                named: journal.stagingName,
                beneath: recoveryDescriptor,
                expected: journal.stagingIdentity,
                exactPrivate: true
            ) { staging in
                try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
                try receiptlessRecoveryDescriptorTestHook?(.receiptInstall, staging)
                let receipt = MigrationReceipt(
                    version: ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
                    migratedAt: Date(),
                    source: recoveryQuarantineURL(journal).path,
                    copiedEntries: journal.copiedEntries,
                    sourceKind: .historicalProviderState,
                    providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current
                )
                try writeMigrationReceipt(receipt, beneath: staging, deadline: deadline)
                guard Darwin.fsync(staging) == 0 else {
                    throw HarnessHomeError.receiptlessRecoveryStateChanged
                }
                try validateReceiptlessMigrationReceipt(
                    beneath: staging,
                    journal: journal,
                    deadline: deadline
                )
            }
        } else {
            try withRecoveryDirectory(
                named: journal.stagingName,
                beneath: recoveryDescriptor,
                expected: journal.stagingIdentity,
                exactPrivate: true
            ) { staging in
                try requireConfiguredRecoveryDirectoryBinding(recoveryDescriptor)
                try receiptlessRecoveryDescriptorTestHook?(.receiptRevalidation, staging)
                try validateReceiptlessMigrationReceipt(
                    beneath: staging,
                    journal: journal,
                    deadline: deadline
                )
            }
        }
        if invokeCrashHooks { try interruptReceiptlessRecoveryIfRequested(.receiptDurable) }
        let previous = journal.phase
        journal.phase = .receiptDurable
        try writeReceiptlessRecoveryJournal(
            journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            expectedPrevious: previous,
            deadline: deadline
        )
        if invokeCrashHooks { try interruptReceiptlessRecoveryIfRequested(.receiptRecorded) }
        return journal
    }

    private func withRecoveryDirectory<T>(
        named name: String,
        beneath parentDescriptor: Int32,
        expected: HarnessHomeRecoveryIdentity,
        exactPrivate: Bool,
        operation: (Int32) throws -> T
    ) throws -> T {
        let descriptor = try openRecoveryDirectory(
            named: name,
            beneath: parentDescriptor,
            expected: expected,
            exactPrivate: exactPrivate
        )
        defer { Darwin.close(descriptor) }
        return try operation(descriptor)
    }

    private func validateReceiptlessMigrationReceipt(
        beneath descriptor: Int32,
        journal: ReceiptlessRecoveryJournal,
        deadline: PreparationDeadline
    ) throws {
        let receipt = try readAndValidateMigrationReceipt(beneath: descriptor, deadline: deadline)
        guard ProviderHistoryPrivacyEpoch.isCurrent(
                  receiptVersion: receipt.version,
                  epoch: receipt.providerHistoryPrivacyEpoch
              ),
              receipt.sourceKind == .historicalProviderState,
              receipt.source == recoveryQuarantineURL(journal).path,
              receipt.copiedEntries == journal.copiedEntries else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try validateMigrationContentTree(
            descriptor: descriptor,
            expectedTopLevel: Set(journal.copiedEntries),
            deadline: deadline
        )
    }

    private func publishReceiptlessRecovery(
        _ original: ReceiptlessRecoveryJournal,
        key: SymmetricKey,
        parentDescriptor: Int32,
        recoveryDescriptor: Int32,
        attestationRotation: HarnessHomeAttestationStore.RotationSession?,
        deadline: PreparationDeadline,
        invokeCrashHooks: Bool = true
    ) throws -> HarnessHomeReceiptlessRecoveryReceipt {
        guard original.phase == .receiptDurable else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        var journal = original
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        if let attestationRotation {
            try attestationRotation.prepare(
                operationID: journal.operationID,
                choice: journal.providerHistoryRecoveryChoice.attestationChoice,
                stagedRootURL: recoveryStagingURL(journal)
            )
        }
        try durableExclusiveRename(
            sourceName: journal.stagingName,
            sourceParent: recoveryDescriptor,
            destinationName: journal.rootName,
            destinationParent: parentDescriptor,
            expectedIdentity: journal.stagingIdentity,
            deadline: deadline
        )
        if invokeCrashHooks { try interruptReceiptlessRecoveryIfRequested(.published) }
        if let attestationRotation {
            _ = try attestationRotation.finalize(
                operationID: journal.operationID,
                choice: journal.providerHistoryRecoveryChoice.attestationChoice
            )
        }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        let previous = journal.phase
        journal.phase = .published
        try writeReceiptlessRecoveryJournal(
            journal,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            expectedPrevious: previous,
            deadline: deadline
        )
        if invokeCrashHooks { try interruptReceiptlessRecoveryIfRequested(.publicationRecorded) }
        try withRecoveryDirectory(
            named: journal.rootName,
            beneath: parentDescriptor,
            expected: journal.stagingIdentity,
            exactPrivate: true
        ) { installed in
            try validateReceiptlessMigrationReceipt(
                beneath: installed,
                journal: journal,
                deadline: deadline
            )
        }
        return try publishedReceipt(
            journal,
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
    }

    private func readOrUpgradeReceiptlessRecoveryJournal(
        parentDescriptor: Int32,
        recoveryDescriptor: Int32,
        rootName: String,
        key: SymmetricKey,
        deadline: PreparationDeadline
    ) throws -> ReceiptlessRecoveryJournal {
        switch try readAuthenticatedReceiptlessRecoveryJournal(
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        ) {
        case .current(let journal):
            return journal
        case .legacyV1(let legacy):
            return try upgradeAuthenticatedLegacyRecoveryJournal(
                legacy,
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor,
                rootName: rootName,
                key: key,
                deadline: deadline
            )
        }
    }

    /// Authenticated format-1 journals predate an explicit provider-history
    /// import choice. Their only privacy-safe deterministic upgrade is
    /// `startClean`. Both the original source and the old staged/published output
    /// move only as whole directory capabilities; no child is listed, parsed,
    /// copied, or removed. A fresh empty staging inode then receives format 2.
    private func upgradeAuthenticatedLegacyRecoveryJournal(
        _ legacy: LegacyReceiptlessRecoveryJournalV1,
        parentDescriptor: Int32,
        recoveryDescriptor: Int32,
        rootName: String,
        key: SymmetricKey,
        deadline: PreparationDeadline
    ) throws -> ReceiptlessRecoveryJournal {
        try validateLegacyReceiptlessRecoveryJournalV1(legacy)
        guard legacy.rootName == rootName,
              try directoryIdentity(parentDescriptor, exactPrivate: false) == legacy.parentIdentity,
              try directoryIdentity(recoveryDescriptor, exactPrivate: true)
                == legacy.recoveryDirectoryIdentity else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )

        // First guarantee that the former whole home is in its original opaque
        // quarantine. A prepared journal may have crashed immediately before or
        // after that rename without recording the phase.
        if let quarantine = try metadata(
            named: legacy.quarantineName,
            beneath: recoveryDescriptor
        ) {
            guard HarnessHomeRecoveryIdentity(quarantine) == legacy.sourceIdentity else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try withRecoveryDirectory(
                named: legacy.quarantineName,
                beneath: recoveryDescriptor,
                expected: legacy.sourceIdentity,
                exactPrivate: false
            ) { descriptor in
                try validateOpaqueHistoricalRootCapability(
                    descriptor: descriptor,
                    deadline: deadline
                )
                try requireDescriptorIdentity(descriptor, expected: legacy.sourceIdentity)
            }
        } else {
            guard legacy.phase == .prepared,
                  let source = try metadata(named: rootName, beneath: parentDescriptor),
                  HarnessHomeRecoveryIdentity(source) == legacy.sourceIdentity else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            let sourceDescriptor = try openReceiptlessSource(
                parentDescriptor: parentDescriptor,
                rootName: rootName,
                expected: legacy.sourceIdentity
            )
            defer { Darwin.close(sourceDescriptor) }
            try validateOpaqueHistoricalRootCapability(
                descriptor: sourceDescriptor,
                deadline: deadline
            )
            try durableExclusiveRename(
                sourceName: rootName,
                sourceParent: parentDescriptor,
                destinationName: legacy.quarantineName,
                destinationParent: recoveryDescriptor,
                expectedIdentity: legacy.sourceIdentity,
                deadline: deadline
            )
        }

        let operation = legacy.operationID.uuidString.lowercased()
        let historicalOutputName = Self.legacyRecoveryOutputPrefix + operation
        guard Self.validPathComponent(historicalOutputName) else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }

        // Preserve the old copied output too. Before publication it is the old
        // staging directory; after publication (including the receiptDurable →
        // published crash gap) it is the configured root. A previous upgrade
        // attempt may already have completed this exact rename.
        if let preservedOutput = try metadata(
            named: historicalOutputName,
            beneath: recoveryDescriptor
        ) {
            guard HarnessHomeRecoveryIdentity(preservedOutput) == legacy.stagingIdentity else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try withRecoveryDirectory(
                named: historicalOutputName,
                beneath: recoveryDescriptor,
                expected: legacy.stagingIdentity,
                exactPrivate: true
            ) { descriptor in
                try requireDescriptorIdentity(
                    descriptor,
                    expected: legacy.stagingIdentity,
                    exactPrivate: true
                )
            }
        } else if let published = try metadata(named: rootName, beneath: parentDescriptor),
                  HarnessHomeRecoveryIdentity(published) == legacy.stagingIdentity {
            guard legacy.phase >= .receiptDurable,
                  try metadata(named: legacy.stagingName, beneath: recoveryDescriptor) == nil else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try withRecoveryDirectory(
                named: rootName,
                beneath: parentDescriptor,
                expected: legacy.stagingIdentity,
                exactPrivate: true
            ) { descriptor in
                try requireDescriptorIdentity(
                    descriptor,
                    expected: legacy.stagingIdentity,
                    exactPrivate: true
                )
            }
            try durableExclusiveRename(
                sourceName: rootName,
                sourceParent: parentDescriptor,
                destinationName: historicalOutputName,
                destinationParent: recoveryDescriptor,
                expectedIdentity: legacy.stagingIdentity,
                deadline: deadline
            )
        } else if let staged = try metadata(
            named: legacy.stagingName,
            beneath: recoveryDescriptor
        ), HarnessHomeRecoveryIdentity(staged) == legacy.stagingIdentity {
            guard legacy.phase < .published,
                  try metadata(named: rootName, beneath: parentDescriptor) == nil else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try withRecoveryDirectory(
                named: legacy.stagingName,
                beneath: recoveryDescriptor,
                expected: legacy.stagingIdentity,
                exactPrivate: true
            ) { descriptor in
                try requireDescriptorIdentity(
                    descriptor,
                    expected: legacy.stagingIdentity,
                    exactPrivate: true
                )
            }
            try durableExclusiveRename(
                sourceName: legacy.stagingName,
                sourceParent: recoveryDescriptor,
                destinationName: historicalOutputName,
                destinationParent: recoveryDescriptor,
                expectedIdentity: legacy.stagingIdentity,
                deadline: deadline
            )
        } else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }

        guard try metadata(named: rootName, beneath: parentDescriptor) == nil,
              let reboundSource = try metadata(
                named: legacy.quarantineName,
                beneath: recoveryDescriptor
              ), HarnessHomeRecoveryIdentity(reboundSource) == legacy.sourceIdentity,
              let reboundOutput = try metadata(
                named: historicalOutputName,
                beneath: recoveryDescriptor
              ), HarnessHomeRecoveryIdentity(reboundOutput) == legacy.stagingIdentity else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }

        let freshStagingIdentity: HarnessHomeRecoveryIdentity
        if let freshCandidate = try metadata(
            named: legacy.stagingName,
            beneath: recoveryDescriptor
        ) {
            let candidateIdentity = HarnessHomeRecoveryIdentity(freshCandidate)
            guard candidateIdentity != legacy.stagingIdentity else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            freshStagingIdentity = try withRecoveryDirectory(
                named: legacy.stagingName,
                beneath: recoveryDescriptor,
                expected: candidateIdentity,
                exactPrivate: true
            ) { descriptor in
                // This path exists only after our upgrade created it under the
                // fixed lease and crashed before journal replacement. It must
                // still be exactly empty; no historical directory is inspected.
                guard try firstDirectoryEntry(
                    descriptor: descriptor,
                    deadline: deadline
                ) == nil else {
                    throw HarnessHomeError.receiptlessRecoveryJournalInvalid
                }
                return try directoryIdentity(descriptor, exactPrivate: true)
            }
        } else {
            guard mkdirat(recoveryDescriptor, legacy.stagingName, mode_t(0o700)) == 0,
                  Darwin.fsync(recoveryDescriptor) == 0 else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            freshStagingIdentity = try identity(
                named: legacy.stagingName,
                beneath: recoveryDescriptor,
                exactPrivateDirectory: true
            )
        }

        let upgraded = ReceiptlessRecoveryJournal(
            formatVersion: Self.receiptlessRecoveryFormatVersion,
            operationID: legacy.operationID,
            phase: .sourceQuarantined,
            rootName: legacy.rootName,
            stagingName: legacy.stagingName,
            quarantineName: legacy.quarantineName,
            parentIdentity: legacy.parentIdentity,
            recoveryDirectoryIdentity: legacy.recoveryDirectoryIdentity,
            sourceIdentity: legacy.sourceIdentity,
            stagingIdentity: freshStagingIdentity,
            copiedEntries: [],
            providerHistoryRecoveryChoice: .startClean
        )
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )
        guard let reboundStaging = try metadata(
            named: legacy.stagingName,
            beneath: recoveryDescriptor
        ), HarnessHomeRecoveryIdentity(reboundStaging) == freshStagingIdentity else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try replaceAuthenticatedLegacyRecoveryJournal(
            legacy,
            with: upgraded,
            key: key,
            recoveryDescriptor: recoveryDescriptor,
            deadline: deadline
        )
        return upgraded
    }

    private func reconcileReceiptlessRecovery(
        parentDescriptor: Int32,
        recoveryDescriptor: Int32,
        rootName: String,
        key: SymmetricKey,
        attestationRotation: HarnessHomeAttestationStore.RotationSession?,
        deadline: PreparationDeadline
    ) throws -> HarnessHomeReceiptlessRecoveryReceipt {
        var journal = try readOrUpgradeReceiptlessRecoveryJournal(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor,
            rootName: rootName,
            key: key,
            deadline: deadline
        )
        guard journal.rootName == rootName,
              try directoryIdentity(parentDescriptor, exactPrivate: false) == journal.parentIdentity,
              try directoryIdentity(recoveryDescriptor, exactPrivate: true)
                == journal.recoveryDirectoryIdentity else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        try requireRecoveryDirectoryBinding(
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor
        )

        let rootMetadata = try metadata(named: rootName, beneath: parentDescriptor)
        let quarantineMetadata = try metadata(
            named: journal.quarantineName,
            beneath: recoveryDescriptor
        )
        if let attestationRotation,
           try metadata(named: journal.stagingName, beneath: recoveryDescriptor) != nil {
            try attestationRotation.begin(
                operationID: journal.operationID,
                choice: journal.providerHistoryRecoveryChoice.attestationChoice,
                stagedRootURL: recoveryStagingURL(journal)
            )
        }
        if let rootMetadata,
           HarnessHomeRecoveryIdentity(rootMetadata) == journal.stagingIdentity {
            guard journal.phase >= .receiptDurable,
                  quarantineMetadata.map({ HarnessHomeRecoveryIdentity($0) }) == journal.sourceIdentity,
                  try metadata(named: journal.stagingName, beneath: recoveryDescriptor) == nil else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try withRecoveryDirectory(
                named: rootName,
                beneath: parentDescriptor,
                expected: journal.stagingIdentity,
                exactPrivate: true
            ) { installed in
                try validateReceiptlessMigrationReceipt(
                    beneath: installed,
                    journal: journal,
                    deadline: deadline
                )
            }
            if let attestationRotation {
                _ = try attestationRotation.finalize(
                    operationID: journal.operationID,
                    choice: journal.providerHistoryRecoveryChoice.attestationChoice
                )
            }
            if journal.phase != .published {
                let previous = journal.phase
                journal.phase = .published
                try writeReceiptlessRecoveryJournal(
                    journal,
                    key: key,
                    recoveryDescriptor: recoveryDescriptor,
                    expectedPrevious: previous,
                    deadline: deadline
                )
            }
            return try publishedReceipt(
                journal,
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor
            )
        }

        if quarantineMetadata == nil {
            guard let rootMetadata,
                  HarnessHomeRecoveryIdentity(rootMetadata) == journal.sourceIdentity,
                  journal.phase == .prepared else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
            try requireRecoveryDirectoryBinding(
                parentDescriptor: parentDescriptor,
                recoveryDescriptor: recoveryDescriptor
            )
            try durableExclusiveRename(
                sourceName: rootName,
                sourceParent: parentDescriptor,
                destinationName: journal.quarantineName,
                destinationParent: recoveryDescriptor,
                expectedIdentity: journal.sourceIdentity,
                deadline: deadline
            )
        } else {
            guard rootMetadata == nil,
                  quarantineMetadata.map({ HarnessHomeRecoveryIdentity($0) }) == journal.sourceIdentity else {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
        }
        if journal.phase == .prepared {
            let previous = journal.phase
            journal.phase = .sourceQuarantined
            try writeReceiptlessRecoveryJournal(
                journal,
                key: key,
                recoveryDescriptor: recoveryDescriptor,
                expectedPrevious: previous,
                deadline: deadline
            )
        }

        guard let stagingMetadata = try metadata(
            named: journal.stagingName,
            beneath: recoveryDescriptor
        ), HarnessHomeRecoveryIdentity(stagingMetadata) == journal.stagingIdentity else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        if journal.phase == .sourceQuarantined {
            journal = try populateReceiptlessRecoveryStaging(
                journal,
                key: key,
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline,
                invokeCrashHooks: false
            )
        } else {
            do {
                try withRecoveryDirectory(
                    named: journal.stagingName,
                    beneath: recoveryDescriptor,
                    expected: journal.stagingIdentity,
                    exactPrivate: true
                ) { staging in
                    try validateMigrationContentTree(
                        descriptor: staging,
                        expectedTopLevel: Set(journal.copiedEntries),
                        deadline: deadline
                    )
                }
            } catch {
                throw HarnessHomeError.receiptlessRecoveryJournalInvalid
            }
        }
        if journal.phase == .contentDurable {
            journal = try installReceiptlessRecoveryReceipt(
                journal,
                key: key,
                recoveryDescriptor: recoveryDescriptor,
                deadline: deadline,
                invokeCrashHooks: false
            )
        } else if journal.phase >= .receiptDurable {
            try withRecoveryDirectory(
                named: journal.stagingName,
                beneath: recoveryDescriptor,
                expected: journal.stagingIdentity,
                exactPrivate: true
            ) { staging in
                try validateReceiptlessMigrationReceipt(
                    beneath: staging,
                    journal: journal,
                    deadline: deadline
                )
            }
        }
        guard journal.phase == .receiptDurable else {
            throw HarnessHomeError.receiptlessRecoveryJournalInvalid
        }
        return try publishReceiptlessRecovery(
            journal,
            key: key,
            parentDescriptor: parentDescriptor,
            recoveryDescriptor: recoveryDescriptor,
            attestationRotation: attestationRotation,
            deadline: deadline,
            invokeCrashHooks: false
        )
    }

    private func recoverOrInstallHarnessHome(
        parentDescriptor: Int32,
        rootName: String,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        if let rootMetadata = try metadata(named: rootName, beneath: parentDescriptor) {
            guard secureDirectory(rootMetadata) else {
                throw HarnessHomeError.unsafeProfile("Harness home is linked or unsafe")
            }
            let rootDescriptor = openat(
                parentDescriptor,
                rootName,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard rootDescriptor >= 0 else {
                throw HarnessHomeError.unsafeProfile("Harness home could not be opened safely")
            }
            var opened = stat()
            guard Darwin.fstat(rootDescriptor, &opened) == 0,
                  Self.sameIdentity(rootMetadata, opened),
                  secureDirectory(opened),
                  try Self.descriptorHasNoExtendedACL(rootDescriptor) else {
                Darwin.close(rootDescriptor)
                throw HarnessHomeError.unsafeProfile("Harness home changed while opening")
            }
            if try metadata(named: Self.migrationReceiptName, beneath: rootDescriptor) != nil {
                do {
                    let receipt = try readAndValidateMigrationReceipt(
                        beneath: rootDescriptor,
                        deadline: deadline
                    )
                    guard ProviderHistoryPrivacyEpoch.isCurrent(
                        receiptVersion: receipt.version,
                        epoch: receipt.providerHistoryPrivacyEpoch
                    ) else {
                        let request = HarnessHomeReceiptlessRecoveryRequest(
                            root: root,
                            sourceIdentity: HarnessHomeRecoveryIdentity(opened)
                        )
                        throw HarnessHomeError.receiptlessRecoveryRequired(request)
                    }
                } catch {
                    Darwin.close(rootDescriptor)
                    throw error
                }
                Darwin.close(rootDescriptor)
                try discardVerifiedCurrentCleanInstallStagingIfPresent(
                    parentDescriptor: parentDescriptor,
                    deadline: deadline
                )
                return
            }

            // A receipt-less home can contain user-created sessions, Skills,
            // profiles, or unknown data from an older Fulmar build. Never
            // delete or rewrite it during ordinary startup. Bind the recovery
            // prompt to the exact open directory and require an explicit user
            // decision before even accessing the journal-authentication key.
            let request = HarnessHomeReceiptlessRecoveryRequest(
                root: root,
                sourceIdentity: HarnessHomeRecoveryIdentity(opened)
            )
            Darwin.close(rootDescriptor)
            throw HarnessHomeError.receiptlessRecoveryRequired(request)
        }

        try deadline.check()
        if try metadata(named: Self.migrationStagingName, beneath: parentDescriptor) != nil {
            let stagingDescriptor = try openMigrationDirectory(
                named: Self.migrationStagingName,
                beneath: parentDescriptor,
                label: "migration staging directory"
            )
            defer { Darwin.close(stagingDescriptor) }
            let receipt: MigrationReceipt
            do {
                receipt = try readAndValidateMigrationReceipt(
                    beneath: stagingDescriptor,
                    deadline: deadline
                )
            } catch let error as HarnessHomeError {
                if case .preparationLimitExceeded = error { throw error }
                // A receipt-less, malformed, or future-schema staging directory
                // is not provably ours. Leave the entire directory at its fixed
                // private path without listing or removing any child.
                throw HarnessHomeError.unsafeMigrationEntry(
                    "unrecognized migration staging (preserved without inspection)"
                )
            } catch {
                throw error
            }

            if exactCurrentCleanInstallReceipt(receipt) {
                try validateMigrationContentTree(
                    descriptor: stagingDescriptor,
                    expectedTopLevel: Set(receipt.copiedEntries),
                    deadline: deadline
                )
                guard renameat(
                    parentDescriptor,
                    Self.migrationStagingName,
                    parentDescriptor,
                    rootName
                ) == 0,
                      Darwin.fsync(parentDescriptor) == 0 else {
                    throw HarnessHomeError.unsafeMigrationEntry("atomic migration install")
                }
                return
            }

            guard !ProviderHistoryPrivacyEpoch.isCurrent(
                receiptVersion: receipt.version,
                epoch: receipt.providerHistoryPrivacyEpoch
            ) else {
                // v3 receipts with a recovery source are valid only in the
                // receiptless-recovery namespace, never at this clean-install
                // staging leaf. Preserve and fail closed.
                throw HarnessHomeError.unsafeMigrationEntry(
                    "unexpected current migration staging (preserved without inspection)"
                )
            }

            // A predecessor may have crashed with a valid v1/v2 staged home.
            // Move that exact directory into the configured home slot so the
            // normal opaque, user-confirmed preservation transaction can handle
            // it. Never enumerate or install its child state.
            guard renameat(
                parentDescriptor,
                Self.migrationStagingName,
                parentDescriptor,
                rootName
            ) == 0,
                  Darwin.fsync(parentDescriptor) == 0,
                  let rebound = try metadata(named: rootName, beneath: parentDescriptor),
                  secureDirectory(rebound) else {
                throw HarnessHomeError.unsafeMigrationEntry("historical migration staging preservation")
            }
            throw HarnessHomeError.receiptlessRecoveryRequired(
                HarnessHomeReceiptlessRecoveryRequest(
                    root: root,
                    sourceIdentity: HarnessHomeRecoveryIdentity(rebound)
                )
            )
        }

        try installEmptyCurrentHarnessHome(
            parentDescriptor: parentDescriptor,
            rootName: rootName,
            deadline: deadline
        )
    }

    private func installEmptyCurrentHarnessHome(
        parentDescriptor: Int32,
        rootName: String,
        deadline: PreparationDeadline
    ) throws {
        guard try metadata(named: rootName, beneath: parentDescriptor) == nil,
              try metadata(named: Self.migrationStagingName, beneath: parentDescriptor) == nil,
              mkdirat(parentDescriptor, Self.migrationStagingName, mode_t(0o700)) == 0 else {
            throw HarnessHomeError.unsafeMigrationEntry("migration staging directory")
        }
        let stagingDescriptor = try openMigrationDirectory(
            named: Self.migrationStagingName,
            beneath: parentDescriptor,
            label: "migration staging directory"
        )
        defer { Darwin.close(stagingDescriptor) }
        let stagingIdentity = try directoryIdentity(stagingDescriptor, exactPrivate: true)

        do {
            // A genuinely absent app-owned home is a clean install. Do not
            // probe ~/.dsh, enumerate provider state, or access Keychain.
            let receipt = MigrationReceipt(
                version: ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
                migratedAt: Date(),
                source: nil,
                copiedEntries: [],
                sourceKind: nil,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current
            )
            try writeMigrationReceipt(
                receipt,
                beneath: stagingDescriptor,
                deadline: deadline
            )
            guard Darwin.fsync(stagingDescriptor) == 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("migration receipt durability")
            }
            // Every injected crash boundary now follows the exact v3/epoch-1
            // clean-install marker. A real crash before that marker leaves an
            // unclassified directory which the next launch preserves and stops
            // on rather than guessing that it is disposable.
            try interruptMigrationIfRequested(.stagingCreated)
            try interruptMigrationIfRequested(.contentDurable)
            try interruptMigrationIfRequested(.receiptDurable)

            guard renameat(
                parentDescriptor,
                Self.migrationStagingName,
                parentDescriptor,
                rootName
            ) == 0,
                  Darwin.fsync(parentDescriptor) == 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("atomic migration install")
            }
            try interruptMigrationIfRequested(.installed)
        } catch {
            if error is HarnessHomeMigrationTestInterruption { throw error }
            if try metadata(named: Self.migrationStagingName, beneath: parentDescriptor) != nil {
                try? removeBoundedTree(
                    named: Self.migrationStagingName,
                    beneath: parentDescriptor,
                    expectedIdentity: stagingIdentity,
                    deadline: deadline
                )
            }
            throw error
        }
    }

    private func interruptMigrationIfRequested(_ phase: HarnessHomeMigrationPhase) throws {
        if migrationCrashHook?(phase) == true {
            throw HarnessHomeMigrationTestInterruption.simulatedCrash(phase)
        }
    }

    private func openMigrationDirectory(
        named name: String,
        beneath parentDescriptor: Int32,
        label: String
    ) throws -> Int32 {
        guard let pathMetadata = try metadata(named: name, beneath: parentDescriptor),
              Self.secureStagedDirectory(pathMetadata) else {
            throw HarnessHomeError.unsafeMigrationEntry(label)
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw HarnessHomeError.unsafeMigrationEntry(label) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              Self.secureStagedDirectory(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            throw HarnessHomeError.unsafeMigrationEntry(label)
        }
        return descriptor
    }

    private func writeMigrationReceipt(
        _ receipt: MigrationReceipt,
        beneath destinationDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(receipt)
        guard !data.isEmpty, data.count <= Self.maximumMigrationReceiptBytes,
              try metadata(named: Self.migrationReceiptName, beneath: destinationDescriptor) == nil else {
            throw HarnessHomeError.unsafeMigrationEntry("migration receipt")
        }
        let descriptor = openat(
            destinationDescriptor,
            Self.migrationReceiptName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeMigrationEntry("migration receipt")
        }
        defer { Darwin.close(descriptor) }
        try data.withUnsafeBytes { rawBuffer in
            var offset = 0
            while offset < rawBuffer.count {
                try deadline.check()
                let written = Darwin.write(
                    descriptor,
                    rawBuffer.baseAddress?.advanced(by: offset),
                    rawBuffer.count - offset
                )
                if written > 0 {
                    offset += written
                } else if written < 0, errno == EINTR {
                    continue
                } else {
                    throw HarnessHomeError.unsafeMigrationEntry("migration receipt write")
                }
            }
        }
        var metadata = stat()
        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
              Darwin.fsync(descriptor) == 0,
              Darwin.fstat(descriptor, &metadata) == 0,
              Self.secureStagedRegular(metadata),
              Int(metadata.st_size) == data.count,
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.unsafeMigrationEntry("migration receipt durability")
        }
    }

    private func readAndValidateMigrationReceipt(
        beneath parentDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws -> MigrationReceipt {
        try deadline.check()
        guard let pathMetadata = try metadata(
            named: Self.migrationReceiptName,
            beneath: parentDescriptor
        ), Self.secureStagedRegular(pathMetadata), pathMetadata.st_size > 0,
           pathMetadata.st_size <= off_t(Self.maximumMigrationReceiptBytes) else {
            throw HarnessHomeError.unsafeProfile("migration receipt is missing, linked, public, or oversized")
        }
        let descriptor = openat(
            parentDescriptor,
            Self.migrationReceiptName,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeProfile("migration receipt could not be opened safely")
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              Self.secureStagedRegular(opened),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.unsafeProfile("migration receipt changed while opening")
        }

        var data = Data()
        data.reserveCapacity(Int(opened.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
        while true {
            try deadline.check()
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw HarnessHomeError.unsafeProfile("migration receipt could not be read safely")
            }
            guard count <= Self.maximumMigrationReceiptBytes - data.count else {
                throw HarnessHomeError.unsafeProfile("migration receipt is oversized")
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        var afterDescriptor = stat()
        var afterPath = stat()
        guard data.count == Int(opened.st_size),
              Darwin.fstat(descriptor, &afterDescriptor) == 0,
              fstatat(
                parentDescriptor,
                Self.migrationReceiptName,
                &afterPath,
                AT_SYMLINK_NOFOLLOW
              ) == 0,
              Self.sameIdentity(opened, afterDescriptor),
              Self.sameIdentity(opened, afterPath),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let receipt = try? JSONDecoder().decode(MigrationReceipt.self, from: data) else {
            throw HarnessHomeError.unsafeProfile("migration receipt is malformed or changed")
        }

        let requiredKeys: Set<String> = ["version", "migratedAt", "copiedEntries"]
        let copied = receipt.copiedEntries
        guard receipt.migratedAt.timeIntervalSinceReferenceDate.isFinite,
              copied == copied.sorted(),
              Set(copied).count == copied.count else {
            throw HarnessHomeError.unsafeProfile("migration receipt has an invalid schema or source")
        }
        switch receipt.version {
        case 1:
            let exactKeys = receipt.source == nil
                ? requiredKeys
                : requiredKeys.union(["source"])
            guard Set(object.keys) == exactKeys,
                  receipt.sourceKind == nil,
                  receipt.providerHistoryPrivacyEpoch == nil,
                  copied.count <= Self.historicalReceiptEntries.count,
                  copied.allSatisfy(Self.historicalReceiptEntries.contains),
                  (copied.isEmpty
                    ? receipt.source == nil
                    : receipt.source == legacyRoot.path) else {
                throw HarnessHomeError.unsafeProfile("migration receipt has an invalid schema or source")
            }
        case 2:
            guard Set(object.keys) == requiredKeys.union(["source", "sourceKind"]),
                  receipt.sourceKind == .receiptlessRecovery,
                  receipt.providerHistoryPrivacyEpoch == nil,
                  copied.count <= Self.historicalReceiptEntries.count,
                  copied.allSatisfy(Self.historicalReceiptEntries.contains),
                  validReceiptlessRecoverySource(receipt.source) else {
                throw HarnessHomeError.unsafeProfile("migration receipt has an invalid schema or source")
            }
        case ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion:
            guard receipt.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
                  copied.count <= ProviderHistoryPrivacyEpoch.settingsFileNames.count,
                  copied.allSatisfy(ProviderHistoryPrivacyEpoch.settingsFileNames.contains) else {
                throw HarnessHomeError.unsafeProfile("migration receipt has an invalid privacy epoch")
            }
            if receipt.source == nil {
                guard Set(object.keys) == requiredKeys.union(["providerHistoryPrivacyEpoch"]),
                      receipt.sourceKind == nil,
                      copied.isEmpty else {
                    throw HarnessHomeError.unsafeProfile("migration receipt has an invalid schema or source")
                }
            } else {
                guard Set(object.keys) == requiredKeys.union([
                    "source", "sourceKind", "providerHistoryPrivacyEpoch"
                ]),
                      receipt.sourceKind == .historicalProviderState,
                      validReceiptlessRecoverySource(receipt.source) else {
                    throw HarnessHomeError.unsafeProfile("migration receipt has an invalid schema or source")
                }
            }
        default:
            throw HarnessHomeError.unsafeProfile("migration receipt has an invalid schema or source")
        }
        return receipt
    }

    private func requireCurrentProviderHistoryPrivacyEpoch(
        _ receipt: MigrationReceipt
    ) throws {
        guard ProviderHistoryPrivacyEpoch.isCurrent(
            receiptVersion: receipt.version,
            epoch: receipt.providerHistoryPrivacyEpoch
        ) else {
            throw HarnessHomeError.unsafeProfile(
                "historical provider state requires foreground preservation"
            )
        }
    }

    private func exactCurrentCleanInstallReceipt(_ receipt: MigrationReceipt) -> Bool {
        ProviderHistoryPrivacyEpoch.isCurrent(
            receiptVersion: receipt.version,
            epoch: receipt.providerHistoryPrivacyEpoch
        )
            && receipt.source == nil
            && receipt.sourceKind == nil
            && receipt.copiedEntries.isEmpty
    }

    private func validReceiptlessRecoverySource(_ source: String?) -> Bool {
        guard let source, !source.isEmpty else { return false }
        let sourceURL = URL(fileURLWithPath: source).standardizedFileURL
        let recoveryDirectory = root.deletingLastPathComponent()
            .appendingPathComponent(Self.receiptlessRecoveryDirectoryName, isDirectory: true)
            .standardizedFileURL
        let name = sourceURL.lastPathComponent
        guard sourceURL.path == source,
              sourceURL.deletingLastPathComponent() == recoveryDirectory,
              name.hasPrefix(Self.receiptlessRecoveryQuarantinePrefix) else { return false }
        let identifier = String(name.dropFirst(Self.receiptlessRecoveryQuarantinePrefix.count))
        guard let uuid = UUID(uuidString: identifier) else { return false }
        return identifier == uuid.uuidString.lowercased()
    }

    /// Validates either a complete staged transaction (`expectedTopLevel`) or
    /// the receipt-less exact topology produced by the former direct copier.
    private func validateMigrationContentTree(
        descriptor: Int32,
        expectedTopLevel: Set<String>?,
        permissionPolicy: RecoveryPermissionPolicy = .privateStaging,
        deadline: PreparationDeadline
    ) throws {
        var state = MigrationState()
        var topLevel = Set<String>()
        try forEachDirectoryEntry(descriptor: descriptor, deadline: deadline) { name in
            if name == Self.migrationReceiptName {
                guard expectedTopLevel != nil else {
                    throw HarnessHomeError.unsafeMigrationEntry(name)
                }
                return
            }
            guard topLevel.insert(name).inserted else {
                throw HarnessHomeError.unsafeMigrationEntry(name)
            }
            try recordMigrationNode(relative: name, depth: 0, state: &state)
            if Self.historicalReceiptEntries.contains(name) {
                try validateMigrationTreeEntry(
                    named: name,
                    relative: name,
                    depth: 0,
                    parentDescriptor: descriptor,
                    state: &state,
                    permissionPolicy: permissionPolicy,
                    deadline: deadline
                )
            } else if expectedTopLevel == nil,
                      case .formerReceiptlessHome = permissionPolicy,
                      name == Self.formerEmptySkillsScaffoldName {
                try validateFormerEmptySkillsScaffold(
                    named: name,
                    parentDescriptor: descriptor,
                    state: &state,
                    deadline: deadline
                )
            } else {
                throw HarnessHomeError.unsafeMigrationEntry(name)
            }
        }
        if let expectedTopLevel, topLevel != expectedTopLevel {
            throw HarnessHomeError.unsafeMigrationEntry("migration receipt/content mismatch")
        }
        try deadline.check()
    }

    /// Early 1.1.0 UI construction could create this exact empty scaffold
    /// before the atomic Harness-home migration ran. It contains no user data
    /// and may be discarded only when every node is an empty, owner-controlled
    /// directory. A package, file, link, special object, or unknown child keeps
    /// the former home untouched and fails closed.
    private func validateFormerEmptySkillsScaffold(
        named name: String,
        parentDescriptor: Int32,
        state: inout MigrationState,
        deadline: PreparationDeadline
    ) throws {
        guard let metadata = try self.metadata(named: name, beneath: parentDescriptor),
              recoveryDirectoryIsAllowed(metadata, policy: .formerReceiptlessHome) else {
            throw HarnessHomeError.unsafeMigrationEntry("\(name) scaffold root")
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeMigrationEntry("\(name) scaffold open")
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(metadata, opened),
              recoveryDirectoryIsAllowed(opened, policy: .formerReceiptlessHome),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessHomeError.unsafeMigrationEntry("\(name) scaffold identity")
        }
        var seen = Set<String>()
        try forEachDirectoryEntry(descriptor: descriptor, deadline: deadline) { child in
            let relative = "\(name)/\(child)"
            try recordMigrationNode(relative: relative, depth: 1, state: &state)
            guard Self.formerEmptySkillsScaffoldChildren.contains(child),
                  seen.insert(child).inserted,
                  let childMetadata = try self.metadata(named: child, beneath: descriptor),
                  recoveryDirectoryIsAllowed(childMetadata, policy: .formerReceiptlessHome) else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
            let childDescriptor = openat(
                descriptor,
                child,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard childDescriptor >= 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) open")
            }
            var openedChild = stat()
            do {
                guard Darwin.fstat(childDescriptor, &openedChild) == 0,
                      Self.sameIdentity(childMetadata, openedChild),
                      recoveryDirectoryIsAllowed(openedChild, policy: .formerReceiptlessHome),
                      try Self.descriptorHasNoExtendedACL(childDescriptor),
                      try firstDirectoryEntry(descriptor: childDescriptor, deadline: deadline) == nil else {
                    throw HarnessHomeError.unsafeMigrationEntry(relative)
                }
                Darwin.close(childDescriptor)
            } catch {
                Darwin.close(childDescriptor)
                throw error
            }
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Self.sameIdentity(opened, after) else {
            throw HarnessHomeError.unsafeMigrationEntry("\(name) scaffold final identity")
        }
    }

    private func validateMigrationTreeEntry(
        named name: String,
        relative: String,
        depth: Int,
        parentDescriptor: Int32,
        state: inout MigrationState,
        permissionPolicy: RecoveryPermissionPolicy,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        guard let pathMetadata = try metadata(named: name, beneath: parentDescriptor) else {
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
        switch pathMetadata.st_mode & S_IFMT {
        case S_IFDIR:
            guard recoveryDirectoryIsAllowed(pathMetadata, policy: permissionPolicy) else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
            let descriptor = openat(
                parentDescriptor,
                name,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard descriptor >= 0 else { throw HarnessHomeError.unsafeMigrationEntry(relative) }
            defer { Darwin.close(descriptor) }
            var opened = stat()
            guard Darwin.fstat(descriptor, &opened) == 0,
                  Self.sameIdentity(pathMetadata, opened),
                  recoveryDirectoryIsAllowed(opened, policy: permissionPolicy),
                  try Self.descriptorHasNoExtendedACL(descriptor) else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
            try forEachDirectoryEntry(descriptor: descriptor, deadline: deadline) { child in
                let childRelative = "\(relative)/\(child)"
                try recordMigrationNode(
                    relative: childRelative,
                    depth: depth + 1,
                    state: &state
                )
                try validateMigrationTreeEntry(
                    named: child,
                    relative: childRelative,
                    depth: depth + 1,
                    parentDescriptor: descriptor,
                    state: &state,
                    permissionPolicy: permissionPolicy,
                    deadline: deadline
                )
            }
            var afterDescriptor = stat()
            var afterPath = stat()
            guard Darwin.fstat(descriptor, &afterDescriptor) == 0,
                  fstatat(parentDescriptor, name, &afterPath, AT_SYMLINK_NOFOLLOW) == 0,
                  Self.sameIdentity(opened, afterDescriptor),
                  Self.sameIdentity(opened, afterPath) else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
        case S_IFREG:
            guard recoveryRegularIsAllowed(pathMetadata, policy: permissionPolicy),
                  pathMetadata.st_size >= 0 else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
            let size = Int64(pathMetadata.st_size)
            guard size <= limits.maximumMigrationFileBytes,
                  size <= limits.maximumMigrationBytes - state.aggregateBytes else {
                throw HarnessHomeError.migrationTooLarge
            }
            let descriptor = openat(
                parentDescriptor,
                name,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard descriptor >= 0 else { throw HarnessHomeError.unsafeMigrationEntry(relative) }
            defer { Darwin.close(descriptor) }
            var opened = stat()
            var afterPath = stat()
            guard Darwin.fstat(descriptor, &opened) == 0,
                  Self.sameIdentity(pathMetadata, opened),
                  recoveryRegularIsAllowed(opened, policy: permissionPolicy),
                  try Self.descriptorHasNoExtendedACL(descriptor),
                  fstatat(parentDescriptor, name, &afterPath, AT_SYMLINK_NOFOLLOW) == 0,
                  Self.sameIdentity(opened, afterPath) else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
            state.aggregateBytes += size
        default:
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
    }

    private func discardVerifiedCurrentCleanInstallStagingIfPresent(
        parentDescriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        guard try metadata(named: Self.migrationStagingName, beneath: parentDescriptor) != nil else {
            return
        }
        let descriptor = try openMigrationDirectory(
            named: Self.migrationStagingName,
            beneath: parentDescriptor,
            label: "migration staging directory"
        )
        defer { Darwin.close(descriptor) }
        let identity = try directoryIdentity(descriptor, exactPrivate: true)
        let receipt: MigrationReceipt
        do {
            receipt = try readAndValidateMigrationReceipt(
                beneath: descriptor,
                deadline: deadline
            )
        } catch let error as HarnessHomeError {
            if case .preparationLimitExceeded = error { throw error }
            throw HarnessHomeError.unsafeMigrationEntry(
                "unrecognized migration staging beside current home (preserved without inspection)"
            )
        } catch {
            throw error
        }
        guard exactCurrentCleanInstallReceipt(receipt) else {
            throw HarnessHomeError.unsafeMigrationEntry(
                "historical or unexpected migration staging beside current home (preserved without inspection)"
            )
        }
        try validateMigrationContentTree(
            descriptor: descriptor,
            expectedTopLevel: [],
            deadline: deadline
        )
        try requireDescriptorIdentity(descriptor, expected: identity, exactPrivate: true)
        try removeBoundedTree(
            named: Self.migrationStagingName,
            beneath: parentDescriptor,
            expectedIdentity: identity,
            deadline: deadline
        )
    }

    private func removeBoundedTree(
        named name: String,
        beneath parentDescriptor: Int32,
        permissionPolicy: RecoveryPermissionPolicy = .privateStaging,
        expectedIdentity: HarnessHomeRecoveryIdentity? = nil,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        guard let metadata = try self.metadata(named: name, beneath: parentDescriptor),
              recoveryDirectoryIsAllowed(metadata, policy: permissionPolicy),
              expectedIdentity.map({ HarnessHomeRecoveryIdentity(metadata) == $0 }) ?? true else {
            throw HarnessHomeError.unsafeMigrationEntry("unsafe recovery tree")
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw HarnessHomeError.unsafeMigrationEntry("recovery tree")
        }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(metadata, opened),
              expectedIdentity.map({ HarnessHomeRecoveryIdentity(opened) == $0 }) ?? true,
              recoveryDirectoryIsAllowed(opened, policy: permissionPolicy),
              try Self.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            throw HarnessHomeError.unsafeMigrationEntry("recovery tree")
        }
        var state = MigrationState()
        do {
            while let child = try firstDirectoryEntry(descriptor: descriptor, deadline: deadline) {
                try recordMigrationNode(relative: child, depth: 0, state: &state)
                try removeBoundedEntry(
                    named: child,
                    relative: child,
                    depth: 0,
                    parentDescriptor: descriptor,
                    state: &state,
                    permissionPolicy: permissionPolicy,
                    deadline: deadline
                )
            }
            guard Darwin.fsync(descriptor) == 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("recovery tree durability")
            }
            Darwin.close(descriptor)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
        guard unlinkat(parentDescriptor, name, AT_REMOVEDIR) == 0,
              Darwin.fsync(parentDescriptor) == 0 else {
            throw HarnessHomeError.unsafeMigrationEntry("recovery tree removal")
        }
    }

    private func removeBoundedEntry(
        named name: String,
        relative: String,
        depth: Int,
        parentDescriptor: Int32,
        state: inout MigrationState,
        permissionPolicy: RecoveryPermissionPolicy,
        deadline: PreparationDeadline
    ) throws {
        try deadline.check()
        guard let metadata = try self.metadata(named: name, beneath: parentDescriptor) else {
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
        if metadata.st_mode & S_IFMT == S_IFDIR {
            guard recoveryDirectoryIsAllowed(metadata, policy: permissionPolicy) else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery permissions")
            }
            let descriptor = openat(
                parentDescriptor,
                name,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard descriptor >= 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery open")
            }
            var opened = stat()
            guard Darwin.fstat(descriptor, &opened) == 0,
                  Self.sameIdentity(metadata, opened),
                  recoveryDirectoryIsAllowed(opened, policy: permissionPolicy),
                  try Self.descriptorHasNoExtendedACL(descriptor) else {
                Darwin.close(descriptor)
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery identity")
            }
            do {
                while let child = try firstDirectoryEntry(descriptor: descriptor, deadline: deadline) {
                    let childRelative = "\(relative)/\(child)"
                    try recordMigrationNode(
                        relative: childRelative,
                        depth: depth + 1,
                        state: &state
                    )
                    try removeBoundedEntry(
                        named: child,
                        relative: childRelative,
                        depth: depth + 1,
                        parentDescriptor: descriptor,
                        state: &state,
                        permissionPolicy: permissionPolicy,
                        deadline: deadline
                    )
                }
                guard Darwin.fsync(descriptor) == 0 else {
                    throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery durability")
                }
                Darwin.close(descriptor)
            } catch {
                Darwin.close(descriptor)
                throw error
            }
            guard unlinkat(parentDescriptor, name, AT_REMOVEDIR) == 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery removal")
            }
        } else if metadata.st_mode & S_IFMT == S_IFREG,
                  recoveryRegularIsAllowed(metadata, policy: permissionPolicy) {
            let descriptor = openat(
                parentDescriptor,
                name,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard descriptor >= 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery open")
            }
            var opened = stat()
            var rebound = stat()
            let descriptorHasNoExtendedACL: Bool
            do {
                descriptorHasNoExtendedACL = try Self.descriptorHasNoExtendedACL(descriptor)
            } catch {
                Darwin.close(descriptor)
                throw error
            }
            let safe = Darwin.fstat(descriptor, &opened) == 0
                && Self.sameIdentity(metadata, opened)
                && recoveryRegularIsAllowed(opened, policy: permissionPolicy)
                && descriptorHasNoExtendedACL
                && fstatat(parentDescriptor, name, &rebound, AT_SYMLINK_NOFOLLOW) == 0
                && Self.sameIdentity(opened, rebound)
            Darwin.close(descriptor)
            guard safe else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery identity")
            }
            guard unlinkat(parentDescriptor, name, 0) == 0 else {
                throw HarnessHomeError.unsafeMigrationEntry("\(relative) recovery removal")
            }
        } else {
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
    }

    private func recoveryDirectoryIsAllowed(
        _ value: stat,
        policy: RecoveryPermissionPolicy
    ) -> Bool {
        switch policy {
        case .privateStaging:
            return Self.secureStagedDirectory(value)
        case .formerReceiptlessHome:
            return secureMigrationDirectory(value)
        }
    }

    private func recoveryRegularIsAllowed(
        _ value: stat,
        policy: RecoveryPermissionPolicy
    ) -> Bool {
        switch policy {
        case .privateStaging:
            return Self.secureStagedRegular(value)
        case .formerReceiptlessHome:
            return secureMigrationRegular(value)
        }
    }

    private static func validPathComponent(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." &&
            !value.contains("/") && !value.contains("\0") &&
            value.utf8.count <= Int(MAXNAMLEN)
    }

    private static func secureStagedDirectory(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFDIR &&
            value.st_uid == geteuid() &&
            (Int(value.st_mode) & 0o777) == 0o700
    }

    private static func secureStagedRegular(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFREG &&
            value.st_uid == geteuid() &&
            value.st_nlink == 1 &&
            (Int(value.st_mode) & 0o777) == 0o600
    }

    private static func descriptorHasNoExtendedACL(_ descriptor: Int32) throws -> Bool {
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // ENOENT means no extended ACL. Any other inspection failure is a
            // fail-closed `false`, allowing the caller's already-open descriptor
            // cleanup path to run rather than throwing out of a guard expression.
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(accessControlList))
        return false
    }

    private func copyRegularFile(
        named name: String,
        relative: String,
        sourceMetadata: stat,
        sourceParent: Int32,
        destinationParent: Int32,
        state: inout MigrationState,
        deadline: PreparationDeadline
    ) throws {
        guard secureMigrationRegular(sourceMetadata), sourceMetadata.st_size >= 0 else {
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
        let size = Int64(sourceMetadata.st_size)
        guard size <= limits.maximumMigrationFileBytes,
              size <= limits.maximumMigrationBytes - state.aggregateBytes else {
            throw HarnessHomeError.migrationTooLarge
        }
        state.aggregateBytes += size
        let source = openat(
            sourceParent,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard source >= 0 else { throw HarnessHomeError.unsafeMigrationEntry(relative) }
        var openedSource = stat()
        guard Darwin.fstat(source, &openedSource) == 0,
              Self.sameIdentity(sourceMetadata, openedSource),
              secureMigrationRegular(openedSource),
              try Self.descriptorHasNoExtendedACL(source) else {
            Darwin.close(source)
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
        let destination = openat(
            destinationParent,
            name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard destination >= 0 else {
            Darwin.close(source)
            throw HarnessHomeError.unsafeMigrationEntry(relative)
        }
        var copied: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        do {
            while true {
                try deadline.check()
                let count = buffer.withUnsafeMutableBytes {
                    Darwin.read(source, $0.baseAddress, $0.count)
                }
                if count == 0 { break }
                if count < 0 {
                    if errno == EINTR { continue }
                    throw HarnessHomeError.unsafeMigrationEntry(relative)
                }
                copied += Int64(count)
                guard copied <= size else { throw HarnessHomeError.unsafeMigrationEntry(relative) }
                try Self.writeAll(buffer, count: count, descriptor: destination, deadline: deadline)
            }
            var afterSource = stat()
            var destinationMetadata = stat()
            guard Darwin.fstat(source, &afterSource) == 0,
                  Self.sameIdentity(openedSource, afterSource),
                  copied == size,
                  Darwin.fchmod(destination, 0o600) == 0,
                  Darwin.fsync(destination) == 0,
                  Darwin.fstat(destination, &destinationMetadata) == 0,
                  destinationMetadata.st_mode & S_IFMT == S_IFREG,
                  destinationMetadata.st_uid == geteuid(),
                  destinationMetadata.st_nlink == 1,
                  destinationMetadata.st_size == copied,
                  try Self.descriptorHasNoExtendedACL(destination) else {
                throw HarnessHomeError.unsafeMigrationEntry(relative)
            }
            Darwin.close(destination)
            Darwin.close(source)
        } catch {
            Darwin.close(destination)
            Darwin.close(source)
            _ = unlinkat(destinationParent, name, 0)
            throw error
        }
    }

    private func recordMigrationNode(
        relative: String,
        depth: Int,
        state: inout MigrationState
    ) throws {
        state.nodes += 1
        guard state.nodes <= limits.maximumMigrationNodes else {
            throw HarnessHomeError.preparationLimitExceeded("legacy node count")
        }
        guard depth <= limits.maximumMigrationDepth else {
            throw HarnessHomeError.preparationLimitExceeded("legacy directory depth")
        }
        guard relative.utf8.count <= limits.maximumRelativePathBytes else {
            throw HarnessHomeError.preparationLimitExceeded("legacy relative path bytes")
        }
    }

    private func legacyMetadata(named name: String, beneath descriptor: Int32) throws -> stat? {
        var value = stat()
        if fstatat(descriptor, name, &value, AT_SYMLINK_NOFOLLOW) == 0 { return value }
        if errno == ENOENT { return nil }
        throw HarnessHomeError.unsafeMigrationEntry(name)
    }

    private func forEachDirectoryEntry(
        descriptor: Int32,
        deadline: PreparationDeadline,
        body: (String) throws -> Void
    ) throws {
        let iterationDescriptor = Darwin.dup(descriptor)
        guard iterationDescriptor >= 0 else {
            throw HarnessHomeError.unsafeMigrationEntry("directory descriptor")
        }
        guard let stream = fdopendir(iterationDescriptor) else {
            Darwin.close(iterationDescriptor)
            throw HarnessHomeError.unsafeMigrationEntry("directory stream")
        }
        defer { closedir(stream) }
        while true {
            try deadline.check()
            errno = 0
            guard let entry = readdir(stream) else {
                if errno != 0 { throw HarnessHomeError.unsafeMigrationEntry("directory stream") }
                return
            }
            let name = try Self.directoryEntryName(entry)
            if name == "." || name == ".." { continue }
            try body(name)
        }
    }

    private static func directoryEntryName(_ entry: UnsafeMutablePointer<dirent>) throws -> String {
        guard let name = DarwinDirectoryEntry.name(entry) else {
            throw HarnessHomeError.unsafeMigrationEntry("invalid directory entry")
        }
        return name
    }

    private static func writeAll(
        _ bytes: [UInt8],
        count: Int,
        descriptor: Int32,
        deadline: PreparationDeadline
    ) throws {
        var offset = 0
        while offset < count {
            try deadline.check()
            let written = bytes.withUnsafeBytes { raw in
                Darwin.write(descriptor, raw.baseAddress?.advanced(by: offset), count - offset)
            }
            if written > 0 {
                offset += written
            } else if written < 0, errno == EINTR {
                continue
            } else {
                throw HarnessHomeError.unsafeMigrationEntry("destination write")
            }
        }
    }

    private func secureDirectory(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFDIR
            && value.st_uid == geteuid()
            && value.st_mode & (S_IWGRP | S_IWOTH) == 0
    }

    private func secureRegular(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFREG
            && value.st_uid == geteuid()
            && value.st_nlink == 1
            && value.st_mode & (S_IWGRP | S_IWOTH) == 0
    }

    private func secureMigrationDirectory(_ value: stat) -> Bool {
        secureDirectory(value)
    }

    private func secureMigrationRegular(_ value: stat) -> Bool {
        secureRegular(value)
    }

    private static func sameIdentity(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_nlink == second.st_nlink
            && first.st_size == second.st_size
            && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
            && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
            && first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec
            && first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec
    }

    /// Proves that two directory observations name the same protected inode.
    /// Directory size, link count, and timestamps are namespace state, not
    /// binding identity: creating or deleting an unrelated child changes those
    /// fields (including on a shared temporary/Application Support ancestor).
    /// Callers separately validate ownership, permissions, type, and ACLs.
    static func sameDirectoryBindingIdentity(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_uid == second.st_uid
            && first.st_gid == second.st_gid
    }
}
