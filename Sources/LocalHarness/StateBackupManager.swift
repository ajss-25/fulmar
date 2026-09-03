import CryptoKit
import CoreFoundation
import Darwin
import Foundation
import LocalHarnessDeviceAttestation
import Security

struct StateBackup: Codable, Equatable, Identifiable {
    let id: UUID
    let createdAt: Date
    let label: String
    let sourceVersion: String
    let path: String
}

struct StateBackupRestoreReport: Equatable {
    let backupID: UUID
    /// This is intentionally not catalogued as a trusted backup: it is the
    /// unauthenticated state that existed immediately before restoration.
    let quarantineURL: URL?
}

/// Detection-only classification for startup ordering. It never requests the
/// backup authentication key or reconciles a namespace transaction.
enum StateBackupPrivacyEpochPreflight: Equatable, Sendable {
    case absent
    case current
    case historical
}

enum StateBackupProtectedOperation: Equatable, Sendable {
    case manualCreate
    case restore(UUID)
    case updateInstall
}

enum StateBackupTransitionDisposition: Equatable, Sendable {
    case restartAndReopen
    /// The coordinator must enter its irreversible termination latch before
    /// acknowledging this disposition. Only that acknowledgement authorizes
    /// the app delegate to perform the one update-specific quit.
    case terminateForUpdate
}

/// The application-wide transition coordinator owns this permit. Backup and
/// restore workers revalidate it before source capture and every namespace
/// commit, so a stale or superseded quiescence decision cannot mutate state.
struct StateBackupQuiescencePermit: @unchecked Sendable {
    let id: UUID
    private let validation: @Sendable () throws -> Void

    init(
        id: UUID = UUID(),
        validation: @escaping @Sendable () throws -> Void
    ) {
        self.id = id
        self.validation = validation
    }

    func validate() throws { try validation() }

    /// Startup migration runs before either service is admitted. This retains
    /// the existing noninteractive migration API until the app-wide transition
    /// coordinator owns that route as well.
    static let protectedStartup = StateBackupQuiescencePermit(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        validation: {}
    )
}

typealias AcquireStateBackupTransition = (
    _ operation: StateBackupProtectedOperation,
    _ completion: @escaping @MainActor (Result<StateBackupQuiescencePermit, Error>) -> Void
) -> Void

typealias FinishStateBackupTransition = (
    _ permit: StateBackupQuiescencePermit,
    _ disposition: StateBackupTransitionDisposition,
    _ result: Result<Void, Error>,
    _ completion: @escaping @MainActor () -> Void
) -> Void

final class StateBackupOperationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func check() throws {
        lock.lock()
        let value = cancelled
        lock.unlock()
        if value { throw BackupError.cancelled }
    }
}

/// Migration rollback points are not ordinary user-managed snapshots. This
/// registry is owned by the backup manager so deletion and retention enforce
/// the protection at the mutation boundary, not just in the UI.
private final class StateBackupProtectionRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var identifiers = Set<UUID>()

    func protect(_ id: UUID) {
        lock.lock()
        identifiers.insert(id)
        lock.unlock()
    }

    func release(_ id: UUID) {
        lock.lock()
        identifiers.remove(id)
        lock.unlock()
    }

    func contains(_ id: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return identifiers.contains(id)
    }
}

struct StateBackupLimits: Equatable, Sendable {
    var maximumManifestBytes = 32 * 1_024 * 1_024
    var maximumEntryCount = 100_000
    var maximumOperationEntries = 400_000
    var maximumDirectoryDepth = 64
    var maximumRelativePathBytes = 4_096
    var maximumFileBytes: Int64 = 16 * 1_024 * 1_024 * 1_024
    var maximumBackupBytes: Int64 = 64 * 1_024 * 1_024 * 1_024
    var maximumOperationBytes: Int64 = 256 * 1_024 * 1_024 * 1_024
    var maximumBackupCount = 32
    var maximumCatalogEntries = 256
    var maximumAggregateStoredBytes: Int64 = 128 * 1_024 * 1_024 * 1_024
    var operationDuration: TimeInterval = 120

    static let production = StateBackupLimits()
}

/// Test-only interruption marker: unlike an ordinary injected error, this
/// deliberately leaves the durable transaction exactly as a killed process
/// would, allowing a new manager instance to prove relaunch reconciliation.
enum StateBackupSimulatedProcessLoss: Error {
    case terminate
}

enum StateBackupFailurePoint: Hashable {
    case afterSourceDirectoryOpened(String)
    case afterSourceFileOpened(String)
    case afterDestinationDirectoryOpened(String)
    case afterDestinationFileOpened(String)
    case afterStagedBackupCopy
    case afterBackupJournalDurable
    case beforeBackupPublication
    case afterBackupPublished
    case afterBackupCatalogCommitted
    case afterRetentionApplied
    case afterDeleteJournalDurable
    case afterDeleteQuarantined
    case afterDeleteCatalogCommitted
    case afterDeleteFinalizationDurable
    case afterRestoreStaging
    case afterRestoreJournalDurable
    case afterSourceQuarantined
    case afterReplacementActivated
    case beforeRestoreFinalization
    case afterRestoreFinalizationDurable
    case beforeRollback
}

/// Authenticated, all-or-nothing snapshots of Harness state.
///
/// Every catalog and manifest is authenticated with a device-only Keychain
/// key, and every regular file is independently SHA-256 hashed. Backup and
/// restore payloads are assembled in private staging directories and verified
/// before a same-volume rename makes them visible. Links and special files are
/// rejected rather than followed.
final class StateBackupManager: @unchecked Sendable {
    private enum NodeKind: String, Codable {
        case directory
        case regular
    }

    private struct ManifestEntry: Codable, Equatable {
        let relativePath: String
        let kind: NodeKind
        let byteCount: Int64
        let posixPermissions: Int
        let contentSHA256: String?
    }

    private struct ManifestPayload: Codable, Equatable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        let id: UUID
        let createdAt: Date
        let label: String
        let sourceVersion: String
        let sourceCanonicalPath: String
        let entries: [ManifestEntry]
        let totalBytes: Int64
    }

    private struct ManifestEnvelope: Codable {
        let payload: ManifestPayload
        let authenticationTag: String
    }

    private struct CatalogPayload: Codable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        let backups: [StateBackup]
    }

    private struct CatalogEnvelope: Codable {
        let payload: CatalogPayload
        let authenticationTag: String
    }

    private struct FileIdentity: Codable, Equatable, Sendable {
        let device: UInt64
        let inode: UInt64
        let owner: UInt32
        let byteCount: Int64
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let linkCount: UInt64
        let mode: mode_t
    }

    private struct BackupReceiptPayload: Codable, Equatable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        let operationID: UUID
        let backup: StateBackup
        let manifestSHA256: String
    }

    private struct BackupReceiptEnvelope: Codable {
        let payload: BackupReceiptPayload
        let authenticationTag: String
    }

    private enum BackupTransactionKind: String, Codable {
        case create
        case delete
    }

    private enum BackupTransactionPhase: String, Codable {
        case prepared
        case namespaceMoved
        case catalogCommitted
        case retentionApplied
    }

    private struct BackupTransactionPayload: Codable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        let operationID: UUID
        let kind: BackupTransactionKind
        var phase: BackupTransactionPhase
        let backup: StateBackup
        let stagingName: String
        let publishedName: String
        let namespaceIdentity: FileIdentity
        let targetCatalog: [StateBackup]
        let evictedBackupIDs: [UUID]
        let evictedNamespaceIdentities: [String: FileIdentity]
    }

    private struct BackupTransactionEnvelope: Codable {
        let payload: BackupTransactionPayload
        let authenticationTag: String
    }

    private enum RestoreTransactionPhase: String, Codable {
        case prepared
        case sourceQuarantined
        case replacementActivated
        case finalized
    }

    private struct RestoreTransactionPayload: Codable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        let operationID: UUID
        let backupID: UUID
        var phase: RestoreTransactionPhase
        let stagedName: String
        let quarantineName: String
        let sourceName: String
        let stagedIdentity: FileIdentity
        let sourceIdentity: FileIdentity?
    }

    private struct RestoreTransactionEnvelope: Codable {
        let payload: RestoreTransactionPayload
        let authenticationTag: String
    }

    private final class OperationBudget {
        let limits: StateBackupLimits
        let deadline: UInt64
        let monotonicNow: @Sendable () -> UInt64
        let cancellation: StateBackupOperationCancellation
        var visitedEntries = 0
        var catalogEntries = 0
        var processedBytes: Int64 = 0

        init(
            limits: StateBackupLimits,
            deadline: UInt64,
            monotonicNow: @escaping @Sendable () -> UInt64,
            cancellation: StateBackupOperationCancellation
        ) {
            self.limits = limits
            self.deadline = deadline
            self.monotonicNow = monotonicNow
            self.cancellation = cancellation
        }

        func checkpoint() throws {
            try cancellation.check()
            guard monotonicNow() <= deadline else { throw BackupError.deadlineExceeded }
        }

        func consumeEntry(relativePath: String, depth: Int) throws {
            try checkpoint()
            visitedEntries += 1
            guard visitedEntries <= limits.maximumOperationEntries,
                  depth <= limits.maximumDirectoryDepth,
                  relativePath.utf8.count <= limits.maximumRelativePathBytes else {
                throw BackupError.backupLimitExceeded
            }
        }

        func consumeCatalogEntry(name: String) throws {
            try checkpoint()
            catalogEntries += 1
            guard catalogEntries <= limits.maximumCatalogEntries,
                  Self.validComponent(name) else {
                throw BackupError.backupLimitExceeded
            }
        }

        func consumeBytes(_ byteCount: Int64) throws {
            try checkpoint()
            guard byteCount >= 0 else { throw BackupError.backupLimitExceeded }
            let (next, overflow) = processedBytes.addingReportingOverflow(byteCount)
            guard !overflow, next <= limits.maximumOperationBytes else {
                throw BackupError.backupLimitExceeded
            }
            processedBytes = next
        }

        private static func validComponent(_ value: String) -> Bool {
            !value.isEmpty && value != "." && value != ".." &&
                !value.contains("/") && !value.contains("\0") &&
                !value.unicodeScalars.contains {
                    CharacterSet.controlCharacters.contains($0) || $0.properties.generalCategory == .format
                } &&
                value.utf8.count <= Int(MAXNAMLEN)
        }
    }

    private enum FilesystemKind: Equatable {
        case missing
        case regular
        case directory
        case symbolicLink
        case other
    }

    private struct RegularSnapshot {
        let byteCount: Int64
        let posixPermissions: Int
        let contentSHA256: String
    }

    /// An operation-scoped capability for a directory entry.  Both the parent
    /// and the exact child remain open so every mutation can be expressed with
    /// *at(2), and an attacker cannot redirect private bytes by replacing a
    /// pathname after verification.
    private final class DirectoryCapability {
        var url: URL
        var parentURL: URL
        var leafName: String
        let parentDescriptor: Int32
        let descriptor: Int32
        let parentIdentity: FileIdentity
        let identity: FileIdentity
        let marker: ProviderHistoryNamespaceMarker?

        init(
            url: URL,
            parentDescriptor: Int32,
            descriptor: Int32,
            parentIdentity: FileIdentity,
            identity: FileIdentity,
            marker: ProviderHistoryNamespaceMarker?
        ) {
            self.url = url.standardizedFileURL
            parentURL = url.deletingLastPathComponent().standardizedFileURL
            leafName = url.lastPathComponent
            self.parentDescriptor = parentDescriptor
            self.descriptor = descriptor
            self.parentIdentity = parentIdentity
            self.identity = identity
            self.marker = marker
        }

        deinit {
            _ = Darwin.close(descriptor)
            _ = Darwin.close(parentDescriptor)
        }
    }

    /// The Harness-home capability additionally retains the exact receipt
    /// descriptor and raw bytes which the signed attestation authenticated.
    private final class HarnessHomeOperationCapability {
        let url: URL
        let parentURL: URL
        let leafName: String
        let parentDescriptor: Int32
        let descriptor: Int32
        let parentIdentity: FileIdentity
        let identity: FileIdentity
        let receiptDescriptor: Int32
        let receiptIdentity: FileIdentity
        let receiptBytes: Data
        let attestationRecord: HarnessHomeAttestationRecord?
        let ownsHomeDescriptor: Bool
        var installedAtOriginalLeaf = true

        init(
            url: URL,
            parentDescriptor: Int32,
            descriptor: Int32,
            parentIdentity: FileIdentity,
            identity: FileIdentity,
            receiptDescriptor: Int32,
            receiptIdentity: FileIdentity,
            receiptBytes: Data,
            attestationRecord: HarnessHomeAttestationRecord?,
            ownsHomeDescriptor: Bool
        ) {
            self.url = url.standardizedFileURL
            parentURL = url.deletingLastPathComponent().standardizedFileURL
            leafName = url.lastPathComponent
            self.parentDescriptor = parentDescriptor
            self.descriptor = descriptor
            self.parentIdentity = parentIdentity
            self.identity = identity
            self.receiptDescriptor = receiptDescriptor
            self.receiptIdentity = receiptIdentity
            self.receiptBytes = receiptBytes
            self.attestationRecord = attestationRecord
            self.ownsHomeDescriptor = ownsHomeDescriptor
        }

        deinit {
            _ = Darwin.close(receiptDescriptor)
            if ownsHomeDescriptor { _ = Darwin.close(descriptor) }
            _ = Darwin.close(parentDescriptor)
        }
    }

    private static let manifestName = "manifest.json"
    private static let receiptName = "receipt.json"
    private static let payloadName = "payload"
    private static let backupJournalName = ".backup-transaction.json"
    private static let restoreJournalName = ".restore-transaction.json"
    /// Format 4 is the first backup schema bound to provider-history privacy
    /// epoch 1. Older authenticated snapshots are preserved in place but are
    /// never discovered, catalogued, restored, or used as migration rollback
    /// points by this build.
    private static let formatVersion = 4
    private static let transactionFormatVersion = 4
    private static let harnessHomeReceiptName = ProviderHistoryPrivacyEpoch.ownershipReceiptName
    private static let maximumHarnessHomeReceiptBytes = 64 * 1_024
    // These fixed names are deliberately isolated here until the shared
    // namespace specification exports its pre-publication leaf names.
    private static let backupPublicationStagingName = ".fulmar-backups-installing"
    private static let recoveryPublicationStagingName = ".fulmar-state-recovery-installing"

    private let applicationSupport: URL
    private let root: URL
    private let catalogURL: URL
    private let sourceState: URL
    private let keyProvider: @Sendable () throws -> Data
    private let authenticationKeyClient: StateBackupAuthenticationKeyClient?
    private let protectionRegistry = StateBackupProtectionRegistry()
    private let failureInjector: @Sendable (StateBackupFailurePoint) throws -> Void
    private let now: @Sendable () -> Date
    private let makeUUID: @Sendable () -> UUID
    private let monotonicNow: @Sendable () -> UInt64
    private let limits: StateBackupLimits
    private let harnessHomeCapabilityProvider: @Sendable () -> HarnessHomeAttestationCapability?
    private let allowUnattestedHarnessHomeForTesting: Bool
    private let managesAttestedNamespaces: Bool
    private let attestationKeyStore: any DeviceAttestationKeyStore
    private let worker = DispatchQueue(
        label: "app.localharness.state-backup-manager",
        qos: .utility
    )
    private let lock = NSLock()
    private var rootIdentity: FileIdentity?
    private var initializationError: Error?
    // Accessed only while `lock` is held.  They never escape one synchronous
    // operation and are cleared before the borrowed home descriptor is
    // returned to its owner.
    private var activeHome: HarnessHomeOperationCapability?
    private var activeBackupRoot: DirectoryCapability?
    private var activeRecoveryRoot: DirectoryCapability?
    private var activeReplacementHome: DirectoryCapability?
    private var activeSourceParent: DirectoryCapability?
    private var activeEphemeralDirectories: [DirectoryCapability] = []

    init(
        applicationSupport: URL,
        sourceState: URL? = nil,
        backupRoot: URL? = nil,
        authenticationKey: Data? = nil,
        fileManager: FileManager = .default,
        now: @escaping @Sendable () -> Date = { Date() },
        makeUUID: @escaping @Sendable () -> UUID = { UUID() },
        monotonicNow: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        limits: StateBackupLimits = .production,
        failureInjector: @escaping @Sendable (StateBackupFailurePoint) throws -> Void = { _ in },
        harnessHomeCapabilityProvider: @escaping @Sendable () -> HarnessHomeAttestationCapability? = { nil },
        allowUnattestedHarnessHomeForTesting: Bool = false,
        attestationKeyStore: (any DeviceAttestationKeyStore)? = nil
    ) {
        self.applicationSupport = applicationSupport.standardizedFileURL
        root = (backupRoot ?? applicationSupport.appendingPathComponent(
            ProviderHistoryDeviceAttestation.backups.leafName,
            isDirectory: true
        )).standardizedFileURL
        catalogURL = root.appendingPathComponent("catalog.json", isDirectory: false)
        self.sourceState = (sourceState ?? fileManager.homeDirectoryForCurrentUser.appendingPathComponent(".dsh", isDirectory: true)).standardizedFileURL
        if let authenticationKey {
            authenticationKeyClient = nil
            keyProvider = { authenticationKey }
        } else {
            let client = StateBackupAuthenticationKeyClient()
            authenticationKeyClient = client
            keyProvider = { try client.loadOrCreate() }
        }
        self.failureInjector = failureInjector
        self.now = now
        self.makeUUID = makeUUID
        self.monotonicNow = monotonicNow
        self.limits = limits
        self.harnessHomeCapabilityProvider = harnessHomeCapabilityProvider
        self.allowUnattestedHarnessHomeForTesting = allowUnattestedHarnessHomeForTesting
        managesAttestedNamespaces = backupRoot == nil
        self.attestationKeyStore = attestationKeyStore
            ?? ProviderHistoryDeviceAttestation.productionKeyStore()

        do {
            guard Self.valid(limits: limits) else { throw BackupError.invalidLimits }
            // Initialization is inspection-only. In particular, constructing a
            // manager while an old Harness home is awaiting a foreground
            // privacy decision must not create backup storage or touch
            // Keychain. The first permitted create lazily publishes this root
            // after validating the source's current privacy receipt.
            switch Self.kind(root) {
            case .missing:
                rootIdentity = nil
            case .directory:
                guard let identity = Self.identity(root),
                      Self.securePrivateDirectory(identity) else {
                    throw BackupError.unsafeStorage
                }
                rootIdentity = identity
            case .regular, .symbolicLink, .other:
                throw BackupError.unsafeStorage
            }
        } catch {
            initializationError = error
        }
    }

    /// Returns only records whose authenticated catalog and manifest agree.
    /// Authentication, privacy-epoch, and corruption failures are never
    /// collapsed into an apparently empty catalog.
    func list() throws -> [StateBackup] {
        try validatedList()
    }

    func privacyEpochPreflight(
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws -> StateBackupPrivacyEpochPreflight {
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            do {
                guard try validateStorageIfPresent() else {
                    try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
                    return .absent
                }
                try validateBackupPrivacyEpochStorage(budget: budget)
                return .current
            } catch let error as BackupError {
                if case .providerHistoryPrivacyMigrationRequired = error {
                    return .historical
                }
                throw error
            }
        }
    }

    /// Use this in security-sensitive UI so corruption is distinguishable from
    /// an ordinary empty catalog.
    func validatedList(
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws -> [StateBackup] {
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try budget.checkpoint()
            guard try validateStorageIfPresent() else {
                try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
                return []
            }
            try validateBackupPrivacyEpochStorage(budget: budget)
            let key = try authenticationKey()
            try reconcileTransactions(key: key, budget: budget)
            return try loadBackups(key: key, budget: budget)
        }
    }

    /// Completes any authenticated transaction left by process loss. Restore
    /// reconciliation is deliberately permit-gated because it may replace the
    /// live Harness home and therefore requires the same stopped-service
    /// boundary as an interactive restore.
    func reconcilePendingTransactions(
        permit: StateBackupQuiescencePermit,
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws {
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try permit.validate()
            guard try validateStorageIfPresent() else {
                try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
                return
            }
            try validateBackupPrivacyEpochStorage(budget: budget)
            try reconcileTransactions(
                key: authenticationKey(),
                budget: budget,
                permit: permit
            )
        }
    }

    @discardableResult
    func reconcilePendingTransactionsAsync(
        permit: StateBackupQuiescencePermit,
        completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> StateBackupOperationCancellation {
        let cancellation = StateBackupOperationCancellation()
        worker.async { [weak self] in
            let result = Result {
                guard let self else { throw BackupError.cancelled }
                try self.reconcilePendingTransactions(
                    permit: permit,
                    cancellation: cancellation
                )
            }
            DispatchQueue.main.async { completion(result) }
        }
        return cancellation
    }

    @discardableResult
    func validatedListAsync(
        completion: @escaping @MainActor (Result<[StateBackup], Error>) -> Void
    ) -> StateBackupOperationCancellation {
        let cancellation = StateBackupOperationCancellation()
        worker.async { [weak self] in
            let result = Result { try self?.validatedList(cancellation: cancellation) ?? [] }
            DispatchQueue.main.async { completion(result) }
        }
        return cancellation
    }

    var canAuthorizeAuthenticationKeyForForeground: Bool {
        authenticationKeyClient != nil
    }

    /// Runs only after an explicit foreground user action. The helper may ask
    /// macOS to authorize a read of the existing item, but it cannot create,
    /// replace, or delete it. Returned bytes are admitted to the process cache
    /// only after they authenticate the existing catalog and every listed
    /// manifest, preserving the exact key/data relationship.
    func authorizeAuthenticationKeyForForeground(
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws {
        guard let authenticationKeyClient else {
            throw BackupError.authenticationUnavailable
        }
        let hasStorage = try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try budget.checkpoint()
            guard try validateStorageIfPresent() else {
                try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
                return false
            }
            try validateBackupPrivacyEpochStorage(budget: budget)
            return true
        }
        guard hasStorage else { return }
        let candidate = try authenticationKeyClient.authorizeExistingForForeground()
        guard candidate.count == 32 else { throw BackupError.authenticationUnavailable }
        let key = SymmetricKey(data: candidate)
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try budget.checkpoint()
            guard try validateStorageIfPresent() else {
                try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
                return
            }
            try validateBackupPrivacyEpochStorage(budget: budget)
            try reconcileTransactions(key: key, budget: budget)
            _ = try loadBackups(key: key, budget: budget)
        }
        authenticationKeyClient.admitValidatedKey(candidate)
    }

    @discardableResult
    func authorizeAuthenticationKeyForForegroundAsync(
        completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> StateBackupOperationCancellation {
        let cancellation = StateBackupOperationCancellation()
        worker.async { [weak self] in
            let result = Result {
                guard let self else { throw BackupError.cancelled }
                try self.authorizeAuthenticationKeyForForeground(cancellation: cancellation)
            }
            DispatchQueue.main.async { completion(result) }
        }
        return cancellation
    }

    /// Pre-service startup migration remains an explicitly protected boundary.
    /// Interactive and update callers must use the permit-taking overload.
    func create(label: String, sourceVersion: String) throws -> StateBackup {
        try create(
            label: label,
            sourceVersion: sourceVersion,
            permit: .protectedStartup
        )
    }

    func create(
        label: String,
        sourceVersion: String,
        permit: StateBackupQuiescencePermit,
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws -> StateBackup {
        return try createBoundToHarnessHome(
            label: label,
            sourceVersion: sourceVersion,
            permit: permit,
            cancellation: cancellation
        )
    }

    private func createBoundToHarnessHome(
        label: String,
        sourceVersion: String,
        permit: StateBackupQuiescencePermit,
        cancellation: StateBackupOperationCancellation
    ) throws -> StateBackup {
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try permit.validate()
            try budget.checkpoint()
            // This receipt gate is deliberately before backup-root creation,
            // transaction reconciliation, or a Keychain read.
            try validateCurrentProviderHistorySource(
                requireExisting: true
            )
            try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
            try ensureStorageForCreate()
            try validateStorage()
            try validateBackupPrivacyEpochStorage(budget: budget)
            let key = try authenticationKey()
            try reconcileTransactions(key: key, budget: budget, permit: permit)
            let catalog = try loadBackups(key: key, budget: budget)
            let identifier = makeUUID()
            let operationID = makeUUID()
            let createdAt = Date(
                timeIntervalSince1970: floor(now().timeIntervalSince1970 * 1_000) / 1_000
            )
            let stagingName = ".creating-\(operationID.uuidString)-\(identifier.uuidString)"
            let staging = root.appendingPathComponent(stagingName, isDirectory: true)
            let publishedName = identifier.uuidString
            let published = root.appendingPathComponent(publishedName, isDirectory: true)
            let payloadURL = staging.appendingPathComponent(Self.payloadName, isDirectory: true)
            var transactionDurable = false

            guard boundKind(staging) == .missing,
                  boundKind(published) == .missing,
                  boundKind(root.appendingPathComponent(Self.backupJournalName)) == .missing else {
                throw BackupError.invalidBackup
            }
            try ensurePrivateDirectoryBound(staging)
            defer {
                if !transactionDurable,
                   let expected = activeEphemeralDirectories.first(where: {
                    $0.url == staging.standardizedFileURL
                   })?.identity {
                    releaseEphemeralDirectory(at: staging)
                    try? removeTree(staging, expectedIdentity: expected, budget: cleanupBudget())
                }
            }

            try ensurePrivateDirectoryBound(payloadURL)
            var entries: [ManifestEntry] = []
            var totalBytes: Int64 = 0
            if activeHome != nil {
                try permit.validate()
                try validateSourceRoot(descriptor: activeHome?.descriptor)
                try copyState(
                    fromDescriptor: activeHome?.descriptor,
                    fallbackSource: sourceState,
                    to: payloadURL,
                    relativePath: "",
                    depth: 0,
                    entries: &entries,
                    totalBytes: &totalBytes,
                    excludesSecrets: true,
                    budget: budget
                )
            }
            entries.sort { $0.relativePath < $1.relativePath }
            let payload = ManifestPayload(
                formatVersion: Self.formatVersion,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
                id: identifier,
                createdAt: createdAt,
                label: Self.normalizedLabel(label),
                sourceVersion: Self.normalizedVersion(sourceVersion),
                sourceCanonicalPath: canonicalSourcePath(),
                entries: entries,
                totalBytes: totalBytes
            )
            try validateManifest(payload, containerID: identifier.uuidString)
            let envelope = try authenticate(payload, key: key)
            let manifestData = try Self.encode(envelope)
            try durableAtomicWrite(
                manifestData,
                to: staging.appendingPathComponent(Self.manifestName),
                permissions: 0o600,
                expectedParent: staging,
                budget: budget
            )
            let backup = StateBackup(
                id: identifier,
                createdAt: createdAt,
                label: payload.label,
                sourceVersion: payload.sourceVersion,
                path: published.appendingPathComponent(Self.payloadName, isDirectory: true).path
            )
            let receiptPayload = BackupReceiptPayload(
                formatVersion: Self.transactionFormatVersion,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
                operationID: operationID,
                backup: backup,
                manifestSHA256: Self.sha256(manifestData)
            )
            let receipt = BackupReceiptEnvelope(
                payload: receiptPayload,
                authenticationTag: try authenticationTag(for: receiptPayload, key: key)
            )
            try durableAtomicWrite(
                try Self.encode(receipt),
                to: staging.appendingPathComponent(Self.receiptName),
                permissions: 0o600,
                expectedParent: staging,
                budget: budget
            )
            try syncDirectory(staging, budget: budget)
            try verifyPayload(payload, at: payloadURL, budget: budget)
            try validateReceipt(
                at: staging,
                expectedBackup: backup,
                expectedManifestData: manifestData,
                expectedOperationID: operationID,
                key: key,
                budget: budget
            )
            try failureInjector(.afterStagedBackupCopy)
            try permit.validate()
            try validateCurrentProviderHistorySource(
                requireExisting: true
            )
            try validateStorage()
            guard let stagingIdentity = boundIdentity(staging),
                  Self.securePrivateDirectory(stagingIdentity) else {
                throw BackupError.unsafeStorage
            }
            let retention = try retentionPlan(
                existing: catalog,
                adding: backup,
                newBackupBytes: totalBytes,
                key: key,
                budget: budget
            )
            var evictedIdentities: [String: FileIdentity] = [:]
            for id in retention.evicted {
                let url = Self.containerURL(for: id, root: root)
                guard let identity = boundIdentity(url), Self.securePrivateDirectory(identity) else {
                    throw BackupError.integrityCheckFailed
                }
                evictedIdentities[id.uuidString] = identity
            }
            var journal = BackupTransactionPayload(
                formatVersion: Self.transactionFormatVersion,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
                operationID: operationID,
                kind: .create,
                phase: .prepared,
                backup: backup,
                stagingName: stagingName,
                publishedName: publishedName,
                namespaceIdentity: stagingIdentity,
                targetCatalog: retention.catalog,
                evictedBackupIDs: retention.evicted,
                evictedNamespaceIdentities: evictedIdentities
            )
            // This legacy seam denotes the last abortable point. Once the
            // authenticated journal is durable, relaunch reconciliation owns
            // an intentional roll-forward transaction.
            try failureInjector(.beforeBackupPublication)
            try writeBackupJournal(journal, key: key, budget: budget)
            transactionDurable = true
            try failureInjector(.afterBackupJournalDurable)
            try permit.validate()
            try validateCurrentProviderHistorySource(
                requireExisting: true
            )
            try durableRename(
                from: staging,
                to: published,
                expectedIdentity: stagingIdentity,
                sourceParent: root,
                destinationParent: root,
                budget: budget
            )
            remapEphemeralDirectories(from: staging, to: published)
            journal.phase = .namespaceMoved
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterBackupPublished)
            try permit.validate()
            try persist(journal.targetCatalog, key: key, budget: budget)
            journal.phase = .catalogCommitted
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterBackupCatalogCommitted)
            try applyRetention(journal, budget: budget)
            journal.phase = .retentionApplied
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterRetentionApplied)
            try permit.validate()
            try validateCurrentProviderHistorySource(
                requireExisting: true
            )
            try clearBackupJournal(budget: budget)
            transactionDurable = false
            return backup
        }
    }

    @discardableResult
    func createAsync(
        label: String,
        sourceVersion: String,
        permit: StateBackupQuiescencePermit,
        completion: @escaping @MainActor (Result<StateBackup, Error>) -> Void
    ) -> StateBackupOperationCancellation {
        let cancellation = StateBackupOperationCancellation()
        worker.async { [weak self] in
            let result = Result {
                guard let self else { throw BackupError.cancelled }
                return try self.create(
                    label: label,
                    sourceVersion: sourceVersion,
                    permit: permit,
                    cancellation: cancellation
                )
            }
            DispatchQueue.main.async { completion(result) }
        }
        return cancellation
    }

    func backup(id: UUID) -> StateBackup? {
        (try? withLock {
            let budget = try makeBudget(cancellation: StateBackupOperationCancellation())
            try validateStorage()
            try validateBackupPrivacyEpochStorage(budget: budget)
            let key = try authenticationKey()
            try reconcileTransactions(key: key, budget: budget)
            return try loadBackups(key: key, budget: budget).first { $0.id == id }
        }) ?? nil
    }

    /// Security-sensitive callers must not collapse authentication, catalog,
    /// integrity, or missing-record failures into the same optional result.
    func requiredBackup(id: UUID) throws -> StateBackup {
        try withLock {
            let budget = try makeBudget(cancellation: StateBackupOperationCancellation())
            try validateStorage()
            try validateBackupPrivacyEpochStorage(budget: budget)
            let key = try authenticationKey()
            try reconcileTransactions(key: key, budget: budget)
            guard let backup = try loadBackups(key: key, budget: budget).first(where: { $0.id == id }) else {
                throw BackupError.invalidBackup
            }
            return backup
        }
    }

    func protectMigrationBackup(id: UUID) { protectionRegistry.protect(id) }
    func releaseMigrationBackup(id: UUID) { protectionRegistry.release(id) }
    func isMigrationBackupProtected(id: UUID) -> Bool { protectionRegistry.contains(id) }

    func delete(
        _ backup: StateBackup,
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws {
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try validateStorage()
            try validateBackupPrivacyEpochStorage(budget: budget)
            let key = try authenticationKey()
            try reconcileTransactions(key: key, budget: budget)
            let catalog = try loadBackups(key: key, budget: budget)
            guard let catalogued = catalog.first(where: { $0.id == backup.id }),
                  catalogued == backup else {
                throw BackupError.invalidBackup
            }
            guard !protectionRegistry.contains(backup.id) else {
                throw BackupError.protectedBackup
            }
            let published = Self.containerURL(for: backup.id, root: root)
            let manifest = try loadManifest(
                at: published,
                expectedID: backup.id,
                key: key,
                budget: budget
            )
            try verifyPayload(
                manifest,
                at: published.appendingPathComponent(Self.payloadName, isDirectory: true),
                budget: budget
            )
            guard let identity = boundIdentity(published), Self.securePrivateDirectory(identity) else {
                throw BackupError.integrityCheckFailed
            }
            let operationID = makeUUID()
            let quarantineName = ".deleting-\(operationID.uuidString)-\(backup.id.uuidString)"
            let quarantine = root.appendingPathComponent(quarantineName, isDirectory: true)
            guard boundKind(quarantine) == .missing else { throw BackupError.unsafeStorage }
            var journal = BackupTransactionPayload(
                formatVersion: Self.transactionFormatVersion,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
                operationID: operationID,
                kind: .delete,
                phase: .prepared,
                backup: backup,
                stagingName: quarantineName,
                publishedName: backup.id.uuidString,
                namespaceIdentity: identity,
                targetCatalog: catalog.filter { $0.id != backup.id },
                evictedBackupIDs: [],
                evictedNamespaceIdentities: [:]
            )
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterDeleteJournalDurable)
            try durableRename(
                from: published,
                to: quarantine,
                expectedIdentity: identity,
                sourceParent: root,
                destinationParent: root,
                budget: budget
            )
            journal.phase = .namespaceMoved
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterDeleteQuarantined)
            try persist(journal.targetCatalog, key: key, budget: budget)
            journal.phase = .catalogCommitted
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterDeleteCatalogCommitted)
            try removeTree(quarantine, expectedIdentity: identity, budget: budget)
            journal.phase = .retentionApplied
            try writeBackupJournal(journal, key: key, budget: budget)
            try failureInjector(.afterDeleteFinalizationDurable)
            try clearBackupJournal(budget: budget)
        }
    }

    @discardableResult
    func deleteAsync(
        _ backup: StateBackup,
        completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> StateBackupOperationCancellation {
        let cancellation = StateBackupOperationCancellation()
        worker.async { [weak self] in
            let result = Result {
                guard let self else { throw BackupError.cancelled }
                try self.delete(backup, cancellation: cancellation)
            }
            DispatchQueue.main.async { completion(result) }
        }
        return cancellation
    }

    @discardableResult
    func restore(_ backup: StateBackup) throws -> StateBackupRestoreReport {
        try restore(backup, permit: .protectedStartup)
    }

    @discardableResult
    func restore(
        _ backup: StateBackup,
        permit: StateBackupQuiescencePermit,
        cancellation: StateBackupOperationCancellation = StateBackupOperationCancellation()
    ) throws -> StateBackupRestoreReport {
        return try restoreBoundToHarnessHome(
            backup,
            permit: permit,
            cancellation: cancellation
        )
    }

    private func restoreBoundToHarnessHome(
        _ backup: StateBackup,
        permit: StateBackupQuiescencePermit,
        cancellation: StateBackupOperationCancellation
    ) throws -> StateBackupRestoreReport {
        try withLock {
            let budget = try makeBudget(cancellation: cancellation)
            try permit.validate()
            // A historical live destination must be preserved through the
            // foreground privacy migration, never folded into restore
            // quarantine as if it were current state.
            try validateCurrentProviderHistorySource(
                requireExisting: false
            )
            try validateStorage()
            try validateBackupPrivacyEpochStorage(budget: budget)
            let key = try authenticationKey()
            try reconcileTransactions(key: key, budget: budget, permit: permit)
            guard let catalogued = try loadBackups(key: key, budget: budget).first(where: { $0.id == backup.id }),
                  catalogued == backup else {
                throw BackupError.invalidBackup
            }
            let container = root.appendingPathComponent(backup.id.uuidString, isDirectory: true)
            let payloadURL = container.appendingPathComponent(Self.payloadName, isDirectory: true)
            let manifest = try loadManifest(at: container, expectedID: backup.id, key: key, budget: budget)
            guard Self.backup(from: manifest, root: root) == catalogued,
                  manifest.sourceCanonicalPath == canonicalSourcePath() else {
                throw BackupError.invalidBackup
            }
            try verifyPayload(manifest, at: payloadURL, budget: budget)

            let operationID = makeUUID()
            let sourceParent = sourceState.deletingLastPathComponent()
            try validateRestoreParent(sourceParent)
            let recoveryRoot = recoveryRootURL()
            guard try acquireRecoveryRoot(createIfAbsent: true) else {
                throw BackupError.unsafeStorage
            }
            let stagedName = ".local-harness-restore-\(operationID.uuidString)"
            let staged = sourceParent.appendingPathComponent(stagedName, isDirectory: true)
            let quarantineName = operationID.uuidString
            let quarantine = recoveryRoot.appendingPathComponent(quarantineName, isDirectory: true)
            var journalDurable = false
            var sourceWasQuarantined = false
            var replacementWasActivated = false
            defer {
                if !journalDurable,
                   let expected = activeEphemeralDirectories.first(where: {
                    $0.url == staged.standardizedFileURL
                   })?.identity {
                    releaseEphemeralDirectory(at: staged)
                    try? removeTree(staged, expectedIdentity: expected, budget: cleanupBudget())
                }
            }

            guard boundKind(staged) == .missing,
                  boundKind(quarantine) == .missing,
                  boundKind(restoreJournalURL()) == .missing else {
                throw BackupError.invalidBackup
            }
            try ensurePrivateDirectoryBound(staged)
            var stagedEntries: [ManifestEntry] = []
            var stagedBytes: Int64 = 0
            try withBoundDirectoryDescriptor(at: payloadURL, failure: .integrityCheckFailed) {
                payloadDescriptor in
                try withBoundDirectoryDescriptor(at: staged) { stagedDescriptor in
                    try copyState(
                        sourceDescriptor: payloadDescriptor,
                        destinationDescriptor: stagedDescriptor,
                        relativePath: "",
                        depth: 0,
                        entries: &stagedEntries,
                        totalBytes: &stagedBytes,
                        excludesSecrets: false,
                        budget: budget
                    )
                }
            }
            stagedEntries.sort { $0.relativePath < $1.relativePath }
            guard stagedEntries == manifest.entries, stagedBytes == manifest.totalBytes else {
                throw BackupError.integrityCheckFailed
            }
            let sourceIdentity: FileIdentity?
            if let home = activeHome {
                try permit.validate()
                try validateSourceRoot(descriptor: home.descriptor)
                try preserveExcludedState(
                    fromDescriptor: home.descriptor,
                    fallbackSource: sourceState,
                    to: staged,
                    relativePath: "",
                    depth: 0,
                    inheritedExclusion: false,
                    budget: budget
                )
                sourceIdentity = home.identity
            } else {
                sourceIdentity = nil
            }
            try syncDirectory(staged, budget: budget)
            guard let stagedIdentity = boundIdentity(staged),
                  Self.securePrivateDirectory(stagedIdentity),
                  sourceIdentity == nil || sourceIdentity.map(Self.secureSourceDirectory) == true else {
                throw BackupError.unsafeSource
            }
            try failureInjector(.afterRestoreStaging)
            try validateCurrentProviderHistorySource(
                requireExisting: false
            )
            var journal = RestoreTransactionPayload(
                formatVersion: Self.transactionFormatVersion,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
                operationID: operationID,
                backupID: backup.id,
                phase: .prepared,
                stagedName: stagedName,
                quarantineName: quarantineName,
                sourceName: sourceState.lastPathComponent,
                stagedIdentity: stagedIdentity,
                sourceIdentity: sourceIdentity
            )
            try writeRestoreJournal(journal, key: key, budget: budget)
            journalDurable = true
            try failureInjector(.afterRestoreJournalDurable)

            do {
                try permit.validate()
                try validateCurrentProviderHistorySource(
                    requireExisting: false
                )
                try validateStorage()
                try revalidateDirectoryCapability(activeRecoveryRoot)
                if let sourceIdentity {
                    try durableRename(
                        from: sourceState,
                        to: quarantine,
                        expectedIdentity: sourceIdentity,
                        sourceParent: sourceParent,
                        destinationParent: recoveryRoot,
                        budget: budget
                    )
                    sourceWasQuarantined = true
                    activeHome?.installedAtOriginalLeaf = false
                }
                journal.phase = .sourceQuarantined
                try writeRestoreJournal(journal, key: key, budget: budget)
                try failureInjector(.afterSourceQuarantined)
                try permit.validate()
                try durableRename(
                    from: staged,
                    to: sourceState,
                    expectedIdentity: stagedIdentity,
                    sourceParent: sourceParent,
                    destinationParent: sourceParent,
                    budget: budget
                )
                replacementWasActivated = true
                remapEphemeralDirectories(from: staged, to: sourceState)
                activeReplacementHome = try openReplacementHomeCapability(
                    expectedIdentity: stagedIdentity
                )
                releaseEphemeralDirectory(at: sourceState)
                journal.phase = .replacementActivated
                try writeRestoreJournal(journal, key: key, budget: budget)
                try failureInjector(.afterReplacementActivated)
                try validateRestoredPayload(manifest, at: sourceState, budget: budget)
                try failureInjector(.beforeRestoreFinalization)
                try permit.validate()
                journal.phase = .finalized
                try writeRestoreJournal(journal, key: key, budget: budget)
                try failureInjector(.afterRestoreFinalizationDurable)
                try clearRestoreJournal(budget: budget)
                journalDurable = false
                return StateBackupRestoreReport(
                    backupID: backup.id,
                    quarantineURL: sourceWasQuarantined ? quarantine : nil
                )
            } catch is StateBackupSimulatedProcessLoss {
                throw StateBackupSimulatedProcessLoss.terminate
            } catch {
                let original = error
                do {
                    try failureInjector(.beforeRollback)
                    try rollbackRestore(
                        sourceWasQuarantined: sourceWasQuarantined,
                        replacementWasActivated: replacementWasActivated,
                        staged: staged,
                        quarantine: quarantine,
                        sourceParent: sourceParent,
                        recoveryRoot: recoveryRoot,
                        stagedIdentity: stagedIdentity,
                        sourceIdentity: sourceIdentity,
                        budget: budget
                    )
                    try clearRestoreJournal(budget: budget)
                    journalDurable = false
                    throw BackupError.restoreFailed(underlying: String(describing: original))
                } catch let rollback as BackupError {
                    if case .restoreFailed = rollback { throw rollback }
                    throw BackupError.rollbackFailed(
                        recoveryDirectory: quarantine.path,
                        stagedDirectory: staged.path
                    )
                } catch {
                    throw BackupError.rollbackFailed(
                        recoveryDirectory: quarantine.path,
                        stagedDirectory: staged.path
                    )
                }
            }
        }
    }

    @discardableResult
    func restoreAsync(
        _ backup: StateBackup,
        permit: StateBackupQuiescencePermit,
        completion: @escaping @MainActor (Result<StateBackupRestoreReport, Error>) -> Void
    ) -> StateBackupOperationCancellation {
        let cancellation = StateBackupOperationCancellation()
        worker.async { [weak self] in
            let result = Result {
                guard let self else { throw BackupError.cancelled }
                return try self.restore(backup, permit: permit, cancellation: cancellation)
            }
            DispatchQueue.main.async { completion(result) }
        }
        return cancellation
    }

    private func rollbackRestore(
        sourceWasQuarantined: Bool,
        replacementWasActivated: Bool,
        staged: URL,
        quarantine: URL,
        sourceParent: URL,
        recoveryRoot: URL,
        stagedIdentity: FileIdentity,
        sourceIdentity: FileIdentity?,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        if replacementWasActivated {
            guard boundKind(staged) == .missing else { throw BackupError.unsafeSource }
            try durableRename(
                from: sourceState,
                to: staged,
                expectedIdentity: stagedIdentity,
                sourceParent: sourceParent,
                destinationParent: sourceParent,
                budget: budget
            )
            remapEphemeralDirectories(from: sourceState, to: staged)
            activeReplacementHome = nil
        }
        if sourceWasQuarantined {
            guard let sourceIdentity,
                  boundKind(quarantine) == .directory,
                  boundKind(sourceState) == .missing else {
                throw BackupError.unsafeSource
            }
            try durableRename(
                from: quarantine,
                to: sourceState,
                expectedIdentity: sourceIdentity,
                sourceParent: recoveryRoot,
                destinationParent: sourceParent,
                budget: budget
            )
            activeHome?.installedAtOriginalLeaf = true
        }
        if boundKind(staged) != .missing {
            releaseEphemeralDirectory(at: staged)
            try removeTree(staged, expectedIdentity: stagedIdentity, budget: budget)
        }
    }

    private func loadBackups(
        key: SymmetricKey,
        budget: OperationBudget
    ) throws -> [StateBackup] {
        try budget.checkpoint()
        try validateStorage()
        guard boundKind(catalogURL) != .missing else {
            return try discoverAuthenticatedBackups(key: key, budget: budget)
        }
        try forEachDirectoryEntry(at: root, catalog: true, budget: budget) { _ in }
        let data = try readRegularFile(
            at: catalogURL,
            maximumBytes: limits.maximumManifestBytes,
            budget: budget,
            storageFailure: .integrityCheckFailed
        )
        guard Self.hasExactCatalogSchema(data),
              let envelope = try? Self.decode(CatalogEnvelope.self, from: data),
              envelope.payload.formatVersion == Self.formatVersion,
              envelope.payload.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              try verify(envelope.payload, tag: envelope.authenticationTag, key: key) else {
            throw BackupError.integrityCheckFailed
        }
        guard envelope.payload.backups.count <= limits.maximumBackupCount else {
            throw BackupError.backupLimitExceeded
        }
        var seen = Set<UUID>()
        var result: [StateBackup] = []
        var aggregateBytes: Int64 = 0
        for backup in envelope.payload.backups {
            try budget.checkpoint()
            guard seen.insert(backup.id).inserted,
                  backup.path == Self.payloadURL(for: backup.id, root: root).path else {
                throw BackupError.integrityCheckFailed
            }
            let manifest = try loadManifest(
                at: Self.containerURL(for: backup.id, root: root),
                expectedID: backup.id,
                key: key,
                budget: budget
            )
            guard Self.backup(from: manifest, root: root) == backup else {
                throw BackupError.integrityCheckFailed
            }
            let (next, overflow) = aggregateBytes.addingReportingOverflow(manifest.totalBytes)
            guard !overflow, next <= limits.maximumAggregateStoredBytes else {
                throw BackupError.backupLimitExceeded
            }
            aggregateBytes = next
            result.append(backup)
        }
        return result.sorted { $0.createdAt > $1.createdAt }
    }

    private func discoverAuthenticatedBackups(
        key: SymmetricKey,
        budget: OperationBudget
    ) throws -> [StateBackup] {
        var names: [String] = []
        try forEachDirectoryEntry(at: root, catalog: true, budget: budget) { names.append($0) }
        var result: [StateBackup] = []
        var aggregateBytes: Int64 = 0
        for name in names.sorted() {
            try budget.checkpoint()
            guard let id = UUID(uuidString: name) else { continue }
            let child = root.appendingPathComponent(name, isDirectory: true)
            guard boundKind(child) == .directory else { throw BackupError.integrityCheckFailed }
            let manifest = try loadManifest(
                at: child,
                expectedID: id,
                key: key,
                budget: budget
            )
            let backup = Self.backup(from: manifest, root: root)
            let (next, overflow) = aggregateBytes.addingReportingOverflow(manifest.totalBytes)
            guard !overflow,
                  result.count < limits.maximumBackupCount,
                  next <= limits.maximumAggregateStoredBytes else {
                throw BackupError.backupLimitExceeded
            }
            aggregateBytes = next
            result.append(backup)
        }
        return result.sorted { $0.createdAt > $1.createdAt }
    }

    private func persist(
        _ catalog: [StateBackup],
        key: SymmetricKey,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        guard catalog.count <= limits.maximumBackupCount,
              Set(catalog.map(\.id)).count == catalog.count else {
            throw BackupError.backupLimitExceeded
        }
        let payload = CatalogPayload(
            formatVersion: Self.formatVersion,
            providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
            backups: catalog.sorted { $0.createdAt > $1.createdAt }
        )
        let envelope = CatalogEnvelope(
            payload: payload,
            authenticationTag: try authenticationTag(for: payload, key: key)
        )
        let data = try Self.encode(envelope)
        guard data.count <= limits.maximumManifestBytes else { throw BackupError.backupLimitExceeded }
        try durableAtomicWrite(
            data,
            to: catalogURL,
            permissions: 0o600,
            expectedParent: root,
            budget: budget
        )
    }

    private func loadManifest(
        at container: URL,
        expectedID: UUID,
        key: SymmetricKey,
        budget: OperationBudget,
        expectedReceiptOperationID: UUID? = nil
    ) throws -> ManifestPayload {
        guard container.deletingLastPathComponent().path == root.path,
              boundKind(container) == .directory,
              let containerIdentity = boundIdentity(container),
              Self.securePrivateDirectory(containerIdentity) else {
            throw BackupError.invalidBackup
        }
        let url = container.appendingPathComponent(Self.manifestName, isDirectory: false)
        let data = try readRegularFile(
            at: url,
            maximumBytes: limits.maximumManifestBytes,
            budget: budget,
            storageFailure: .invalidBackup
        )
        guard Self.hasExactManifestSchema(data),
              let envelope = try? Self.decode(ManifestEnvelope.self, from: data),
              try verify(envelope.payload, tag: envelope.authenticationTag, key: key) else {
            throw BackupError.integrityCheckFailed
        }
        try validateManifest(envelope.payload, containerID: expectedID.uuidString)
        try validateReceipt(
            at: container,
            expectedBackup: Self.backup(from: envelope.payload, root: root),
            expectedManifestData: data,
            expectedOperationID: expectedReceiptOperationID,
            key: key,
            budget: budget
        )
        return envelope.payload
    }

    private func validateManifest(_ manifest: ManifestPayload, containerID: String) throws {
        guard manifest.formatVersion == Self.formatVersion,
              manifest.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              manifest.id.uuidString == containerID,
              manifest.createdAt.timeIntervalSinceReferenceDate.isFinite,
              manifest.entries.count <= limits.maximumEntryCount,
              manifest.totalBytes >= 0,
              manifest.totalBytes <= limits.maximumBackupBytes,
              manifest.sourceCanonicalPath == canonicalSourcePath(),
              !manifest.sourceCanonicalPath.contains("\0"),
              manifest.sourceCanonicalPath.utf8.count <= limits.maximumRelativePathBytes,
              manifest.label.utf8.count <= 256,
              manifest.sourceVersion.utf8.count <= 128 else {
            throw BackupError.invalidBackup
        }
        var seen = Set<String>()
        var summedBytes: Int64 = 0
        for entry in manifest.entries {
            let components = entry.relativePath.split(separator: "/", omittingEmptySubsequences: false)
            guard Self.isValidRelativePath(entry.relativePath),
                  entry.relativePath.utf8.count <= limits.maximumRelativePathBytes,
                  components.count <= limits.maximumDirectoryDepth,
                  seen.insert(entry.relativePath).inserted,
                  entry.posixPermissions >= 0,
                  entry.posixPermissions <= 0o7777 else {
                throw BackupError.invalidBackup
            }
            switch entry.kind {
            case .directory:
                guard entry.byteCount == 0, entry.contentSHA256 == nil else { throw BackupError.invalidBackup }
            case .regular:
                guard entry.byteCount >= 0,
                      entry.byteCount <= limits.maximumFileBytes,
                      let digest = entry.contentSHA256,
                      Self.isSHA256(digest) else { throw BackupError.invalidBackup }
                let (sum, overflow) = summedBytes.addingReportingOverflow(entry.byteCount)
                guard !overflow, sum <= limits.maximumBackupBytes else { throw BackupError.invalidBackup }
                summedBytes = sum
            }
        }
        guard summedBytes == manifest.totalBytes else { throw BackupError.invalidBackup }
    }

    private func verifyPayload(
        _ manifest: ManifestPayload,
        at payloadURL: URL,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        guard boundKind(payloadURL) == .directory else { throw BackupError.integrityCheckFailed }
        let actualPaths = try collectPaths(
            in: payloadURL,
            relativePath: "",
            depth: 0,
            budget: budget
        )
        guard actualPaths == Set(manifest.entries.map(\.relativePath)) else {
            throw BackupError.integrityCheckFailed
        }
        for entry in manifest.entries {
            let url = payloadURL.appendingPathComponent(entry.relativePath)
            guard Self.isDescendant(url, of: payloadURL) else { throw BackupError.integrityCheckFailed }
            switch entry.kind {
            case .directory:
                guard boundKind(url) == .directory,
                      let identity = boundIdentity(url),
                      identity.owner == geteuid(),
                      Int(identity.mode & 0o7777) == entry.posixPermissions else {
                    throw BackupError.integrityCheckFailed
                }
            case .regular:
                guard boundKind(url) == .regular else { throw BackupError.integrityCheckFailed }
                let snapshot = try hashRegularFile(url, budget: budget)
                guard snapshot.byteCount == entry.byteCount,
                      snapshot.posixPermissions == entry.posixPermissions,
                      snapshot.contentSHA256 == entry.contentSHA256 else {
                    throw BackupError.integrityCheckFailed
                }
            }
        }
    }

    /// Restored state may include current credential files that were excluded
    /// from the snapshot, so manifested entries are verified without rejecting
    /// those deliberately preserved extras.
    private func validateRestoredPayload(
        _ manifest: ManifestPayload,
        at restoredURL: URL,
        budget: OperationBudget
    ) throws {
        for entry in manifest.entries {
            try budget.checkpoint()
            // Legacy manifests recorded the ownership receipt before it was
            // excluded from payloads. The restored tree deliberately carries
            // the preserved live receipt instead of the snapshot's copy.
            if Self.isReservedHarnessHomeReceiptName(entry.relativePath) { continue }
            let url = restoredURL.appendingPathComponent(entry.relativePath)
            guard Self.isDescendant(url, of: restoredURL) else { throw BackupError.integrityCheckFailed }
            switch entry.kind {
            case .directory:
                guard boundKind(url) == .directory,
                      let identity = boundIdentity(url),
                      identity.owner == geteuid(),
                      Int(identity.mode & 0o7777) == entry.posixPermissions else {
                    throw BackupError.integrityCheckFailed
                }
            case .regular:
                let snapshot = try hashRegularFile(url, budget: budget)
                guard snapshot.byteCount == entry.byteCount,
                      snapshot.posixPermissions == entry.posixPermissions,
                      snapshot.contentSHA256 == entry.contentSHA256 else {
                    throw BackupError.integrityCheckFailed
                }
            }
        }
    }

    private func collectPaths(
        in directory: URL,
        relativePath: String,
        depth: Int,
        budget: OperationBudget
    ) throws -> Set<String> {
        try budget.checkpoint()
        guard boundKind(directory) == .directory, let before = boundIdentity(directory) else {
            throw BackupError.integrityCheckFailed
        }
        var result = Set<String>()
        try forEachDirectoryEntry(at: directory, catalog: false, budget: budget) { name in
            let child = directory.appendingPathComponent(name)
            let relative = Self.join(relativePath, name)
            try budget.consumeEntry(relativePath: relative, depth: depth + 1)
            guard Self.isValidRelativePath(relative) else { throw BackupError.integrityCheckFailed }
            switch boundKind(child) {
            case .regular:
                result.insert(relative)
            case .directory:
                result.insert(relative)
                result.formUnion(try collectPaths(
                    in: child,
                    relativePath: relative,
                    depth: depth + 1,
                    budget: budget
                ))
            case .symbolicLink, .other, .missing:
                throw BackupError.unsafeSymbolicLink(relativePath: relative)
            }
        }
        guard boundIdentity(directory) == before else { throw BackupError.sourceChanged(relativePath: relativePath) }
        return result
    }

    private func copyState(
        fromDescriptor: Int32?,
        fallbackSource: URL,
        to destination: URL,
        relativePath: String,
        depth: Int,
        entries: inout [ManifestEntry],
        totalBytes: inout Int64,
        excludesSecrets: Bool,
        budget: OperationBudget
    ) throws {
        guard let fromDescriptor else {
            _ = fallbackSource
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        try withBoundDirectoryDescriptor(at: destination) { destinationDescriptor in
            guard let destinationIdentity = Self.identity(descriptor: destinationDescriptor),
                  Self.securePrivateDirectory(destinationIdentity),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(destinationDescriptor) else {
                throw BackupError.unsafeStorage
            }
            try copyState(
                sourceDescriptor: fromDescriptor,
                destinationDescriptor: destinationDescriptor,
                relativePath: relativePath,
                depth: depth,
                entries: &entries,
                totalBytes: &totalBytes,
                excludesSecrets: excludesSecrets,
                budget: budget
            )
        }
    }

    private func copyState(
        sourceDescriptor: Int32,
        destinationDescriptor: Int32,
        relativePath: String,
        depth: Int,
        entries: inout [ManifestEntry],
        totalBytes: inout Int64,
        excludesSecrets: Bool,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        guard let before = Self.identity(descriptor: sourceDescriptor),
              Self.secureSourceDirectory(before),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceDescriptor) else {
            throw BackupError.unsafeSource
        }
        try forEachDirectoryEntry(
            descriptor: sourceDescriptor,
            relativePath: relativePath,
            catalog: false,
            budget: budget
        ) { name in
            if excludesSecrets, Self.isSecretBearingFile(name) { return }
            // The Harness-home ownership receipt is bound to the live home's
            // device/inode identity and privacy epoch, and is budgeted under
            // its own receipt byte cap. It never enters a backup payload and
            // is never replayed out of one: restore preserves the installed
            // receipt exactly like other excluded state, so an old snapshot
            // cannot roll the privacy epoch back.
            if relativePath.isEmpty, Self.isReservedHarnessHomeReceiptName(name) { return }
            let relative = Self.join(relativePath, name)
            try budget.consumeEntry(relativePath: relative, depth: depth + 1)
            guard Self.isValidRelativePath(relative), entries.count < limits.maximumEntryCount else {
                throw BackupError.backupLimitExceeded
            }
            var declared = stat()
            guard name.withCString({
                fstatat(sourceDescriptor, $0, &declared, AT_SYMLINK_NOFOLLOW)
            }) == 0 else {
                throw BackupError.sourceChanged(relativePath: relative)
            }
            let declaredIdentity = Self.identity(declared)
            switch Self.kind(mode: declared.st_mode) {
            case .directory:
                let sourceChild = name.withCString {
                    openat(
                        sourceDescriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                }
                guard sourceChild >= 0,
                      let opened = Self.identity(descriptor: sourceChild),
                      opened == declaredIdentity,
                      Self.secureSourceDirectory(opened),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceChild) else {
                    if sourceChild >= 0 { _ = Darwin.close(sourceChild) }
                    throw BackupError.unsafeSource
                }
                guard name.withCString({ mkdirat(destinationDescriptor, $0, mode_t(0o700)) }) == 0 else {
                    _ = Darwin.close(sourceChild)
                    throw BackupError.unsafeStorage
                }
                let destinationChild = name.withCString {
                    openat(
                        destinationDescriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                }
                guard destinationChild >= 0,
                      fchmod(destinationChild, mode_t(0o700)) == 0,
                      let destinationChildIdentity = Self.identity(descriptor: destinationChild),
                      Self.securePrivateDirectory(destinationChildIdentity),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(destinationChild) else {
                    if destinationChild >= 0 { _ = Darwin.close(destinationChild) }
                    _ = Darwin.close(sourceChild)
                    _ = name.withCString { unlinkat(destinationDescriptor, $0, AT_REMOVEDIR) }
                    throw BackupError.unsafeStorage
                }
                do {
                    try failureInjector(.afterSourceDirectoryOpened(relative))
                    try failureInjector(.afterDestinationDirectoryOpened(relative))
                    entries.append(ManifestEntry(
                        relativePath: relative,
                        kind: .directory,
                        byteCount: 0,
                        posixPermissions: 0o700,
                        contentSHA256: nil
                    ))
                    try copyState(
                        sourceDescriptor: sourceChild,
                        destinationDescriptor: destinationChild,
                        relativePath: relative,
                        depth: depth + 1,
                        entries: &entries,
                        totalBytes: &totalBytes,
                        excludesSecrets: excludesSecrets,
                        budget: budget
                    )
                    guard fsync(destinationChild) == 0 else { throw BackupError.unsafeStorage }
                    _ = Darwin.close(destinationChild)
                    _ = Darwin.close(sourceChild)
                } catch {
                    _ = Darwin.close(destinationChild)
                    _ = Darwin.close(sourceChild)
                    throw error
                }
            case .regular:
                let snapshot = try copyRegularFile(
                    sourceParent: sourceDescriptor,
                    sourceName: name,
                    destinationParent: destinationDescriptor,
                    destinationName: name,
                    relativePath: relative,
                    budget: budget
                )
                let (newTotal, overflow) = totalBytes.addingReportingOverflow(snapshot.byteCount)
                guard !overflow,
                      snapshot.byteCount <= limits.maximumFileBytes,
                      newTotal <= limits.maximumBackupBytes else {
                    throw BackupError.backupLimitExceeded
                }
                totalBytes = newTotal
                entries.append(ManifestEntry(
                    relativePath: relative,
                    kind: .regular,
                    byteCount: snapshot.byteCount,
                    posixPermissions: snapshot.posixPermissions,
                    contentSHA256: snapshot.contentSHA256
                ))
            case .symbolicLink:
                throw BackupError.unsafeSymbolicLink(relativePath: relative)
            case .other:
                throw BackupError.unsupportedFilesystemItem(relativePath: relative)
            case .missing:
                throw BackupError.sourceChanged(relativePath: relative)
            }
        }
        guard Self.identity(descriptor: sourceDescriptor) == before,
              fsync(destinationDescriptor) == 0 else {
            throw BackupError.sourceChanged(relativePath: relativePath)
        }
    }

    private func copyRegularFile(
        sourceParent: Int32,
        sourceName: String,
        destinationParent: Int32,
        destinationName: String,
        relativePath: String,
        budget: OperationBudget
    ) throws -> RegularSnapshot {
        try budget.checkpoint()
        let sourceDescriptor = sourceName.withCString {
            openat(sourceParent, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard sourceDescriptor >= 0 else {
            if errno == ELOOP { throw BackupError.unsafeSymbolicLink(relativePath: relativePath) }
            throw BackupError.unsafeSource
        }
        defer { _ = Darwin.close(sourceDescriptor) }
        guard let before = Self.identity(descriptor: sourceDescriptor),
              Self.kind(mode: before.mode) == .regular,
              before.owner == geteuid(),
              before.linkCount == 1,
              before.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceDescriptor),
              before.byteCount >= 0,
              before.byteCount <= limits.maximumFileBytes else {
            throw BackupError.unsafeSource
        }
        let permissions = Self.privatePermissions(for: before.mode, directory: false)
        let destinationDescriptor = destinationName.withCString {
            openat(
                destinationParent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(permissions)
            )
        }
        guard destinationDescriptor >= 0 else { throw BackupError.unsafeStorage }
        guard let destinationBefore = Self.identity(descriptor: destinationDescriptor),
              Self.kind(mode: destinationBefore.mode) == .regular,
              destinationBefore.owner == geteuid(),
              destinationBefore.linkCount == 1,
              destinationBefore.mode & 0o077 == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(destinationDescriptor) else {
            _ = Darwin.close(destinationDescriptor)
            throw BackupError.unsafeStorage
        }
        var keepDestination = false
        defer {
            _ = Darwin.close(destinationDescriptor)
            if !keepDestination {
                var installed = stat()
                if destinationName.withCString({
                    fstatat(destinationParent, $0, &installed, AT_SYMLINK_NOFOLLOW)
                }) == 0,
                    Self.sameRegularNode(Self.identity(installed), destinationBefore) {
                    _ = destinationName.withCString { unlinkat(destinationParent, $0, 0) }
                }
            }
        }
        try failureInjector(.afterSourceFileOpened(relativePath))
        try failureInjector(.afterDestinationFileOpened(relativePath))
        var hasher = SHA256()
        var copied: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            try budget.checkpoint()
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(sourceDescriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw BackupError.sourceChanged(relativePath: relativePath)
            }
            let chunk = Data(buffer.prefix(count))
            hasher.update(data: chunk)
            try Self.writeAll(chunk, descriptor: destinationDescriptor, budget: budget)
            copied += Int64(count)
            try budget.consumeBytes(Int64(count))
            guard copied <= limits.maximumFileBytes else { throw BackupError.backupLimitExceeded }
        }
        var installed = stat()
        var installedDestination = stat()
        guard fsync(destinationDescriptor) == 0,
              fchmod(destinationDescriptor, mode_t(permissions)) == 0,
              Self.identity(descriptor: sourceDescriptor) == before,
              sourceName.withCString({
                fstatat(sourceParent, $0, &installed, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              Self.identity(installed) == before,
              destinationName.withCString({
                fstatat(destinationParent, $0, &installedDestination, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              Self.sameRegularNode(Self.identity(installedDestination), destinationBefore),
              Self.identity(descriptor: destinationDescriptor).map({
                Self.sameRegularNode($0, destinationBefore)
              }) == true,
              copied == before.byteCount else {
            throw BackupError.sourceChanged(relativePath: relativePath)
        }
        keepDestination = true
        return RegularSnapshot(
            byteCount: copied,
            posixPermissions: permissions,
            contentSHA256: hasher.finalize().map { String(format: "%02x", $0) }.joined()
        )
    }

    private func hashRegularFile(
        _ url: URL,
        budget: OperationBudget
    ) throws -> RegularSnapshot {
        try budget.checkpoint()
        return try withBoundParentDescriptor(of: url, failure: .integrityCheckFailed) {
            parent, leaf in
            let descriptor = leaf.withCString {
                openat(parent, $0, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW)
            }
            guard descriptor >= 0 else { throw BackupError.integrityCheckFailed }
            defer { _ = Darwin.close(descriptor) }
            guard let before = Self.identity(descriptor: descriptor),
                  Self.kind(mode: before.mode) == .regular,
                  before.owner == geteuid(),
                  before.linkCount == 1,
                  before.mode & 0o077 == 0,
                  before.mode & (S_ISUID | S_ISGID) == 0,
                  before.byteCount <= limits.maximumFileBytes,
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
                throw BackupError.integrityCheckFailed
            }
            var hasher = SHA256()
            var readBytes: Int64 = 0
            var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
            while true {
                try budget.checkpoint()
                let count = buffer.withUnsafeMutableBytes {
                    Darwin.read(descriptor, $0.baseAddress, $0.count)
                }
                if count == 0 { break }
                if count < 0 {
                    if errno == EINTR { continue }
                    throw BackupError.integrityCheckFailed
                }
                hasher.update(data: Data(buffer.prefix(count)))
                readBytes += Int64(count)
                try budget.consumeBytes(Int64(count))
            }
            var installed = stat()
            guard Self.identity(descriptor: descriptor) == before,
                  readBytes == before.byteCount,
                  leaf.withCString({
                    fstatat(parent, $0, &installed, AT_SYMLINK_NOFOLLOW)
                  }) == 0,
                  Self.identity(installed) == before else {
                throw BackupError.integrityCheckFailed
            }
            return RegularSnapshot(
                byteCount: readBytes,
                posixPermissions: Int(before.mode & 0o7777),
                contentSHA256: hasher.finalize().map { String(format: "%02x", $0) }.joined()
            )
        }
    }

    /// Current secret material is carried across a restore but never written
    /// into an authenticated snapshot. Secret-bearing links are rejected.
    private func preserveExcludedState(
        fromDescriptor: Int32?,
        fallbackSource: URL,
        to destination: URL,
        relativePath: String,
        depth: Int,
        inheritedExclusion: Bool,
        budget: OperationBudget
    ) throws {
        guard let fromDescriptor else {
            _ = fallbackSource
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        try withBoundDirectoryDescriptor(at: destination) { destinationDescriptor in
            try preserveExcludedState(
                sourceDescriptor: fromDescriptor,
                destinationDescriptor: destinationDescriptor,
                relativePath: relativePath,
                depth: depth,
                inheritedExclusion: inheritedExclusion,
                budget: budget
            )
        }
    }

    private func preserveExcludedState(
        sourceDescriptor: Int32,
        destinationDescriptor: Int32,
        relativePath: String,
        depth: Int,
        inheritedExclusion: Bool,
        budget: OperationBudget
    ) throws {
        guard let before = Self.identity(descriptor: sourceDescriptor),
              Self.secureSourceDirectory(before),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceDescriptor) else {
            throw BackupError.unsafeSource
        }
        try forEachDirectoryEntry(
            descriptor: sourceDescriptor,
            relativePath: relativePath,
            catalog: false,
            budget: budget
        ) { name in
            let excluded = inheritedExclusion || Self.isSecretBearingFile(name)
                || (relativePath.isEmpty && Self.isReservedHarnessHomeReceiptName(name))
            let relative = Self.join(relativePath, name)
            try budget.consumeEntry(relativePath: relative, depth: depth + 1)
            guard Self.isValidRelativePath(relative) else { throw BackupError.unsafeSource }
            var declared = stat()
            guard name.withCString({
                fstatat(sourceDescriptor, $0, &declared, AT_SYMLINK_NOFOLLOW)
            }) == 0 else {
                throw BackupError.sourceChanged(relativePath: relative)
            }
            let declaredIdentity = Self.identity(declared)
            switch Self.kind(mode: declared.st_mode) {
            case .directory:
                let sourceChild = name.withCString {
                    openat(
                        sourceDescriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                }
                guard sourceChild >= 0,
                      Self.identity(descriptor: sourceChild) == declaredIdentity,
                      Self.secureSourceDirectory(declaredIdentity),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceChild) else {
                    if sourceChild >= 0 { _ = Darwin.close(sourceChild) }
                    throw BackupError.unsafeSource
                }
                if excluded {
                    var target = stat()
                    guard name.withCString({
                        fstatat(destinationDescriptor, $0, &target, AT_SYMLINK_NOFOLLOW)
                    }) != 0,
                        errno == ENOENT,
                        name.withCString({ mkdirat(destinationDescriptor, $0, mode_t(0o700)) }) == 0 else {
                        _ = Darwin.close(sourceChild)
                        throw BackupError.integrityCheckFailed
                    }
                }
                let destinationChild = name.withCString {
                    openat(
                        destinationDescriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                }
                guard destinationChild >= 0,
                      let destinationIdentity = Self.identity(descriptor: destinationChild),
                      Self.securePrivateDirectory(destinationIdentity),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(destinationChild) else {
                    if destinationChild >= 0 { _ = Darwin.close(destinationChild) }
                    _ = Darwin.close(sourceChild)
                    throw BackupError.integrityCheckFailed
                }
                do {
                    try preserveExcludedState(
                        sourceDescriptor: sourceChild,
                        destinationDescriptor: destinationChild,
                        relativePath: relative,
                        depth: depth + 1,
                        inheritedExclusion: excluded,
                        budget: budget
                    )
                    guard fsync(destinationChild) == 0 else { throw BackupError.unsafeStorage }
                    _ = Darwin.close(destinationChild)
                    _ = Darwin.close(sourceChild)
                } catch {
                    _ = Darwin.close(destinationChild)
                    _ = Darwin.close(sourceChild)
                    throw error
                }
            case .regular where excluded:
                var target = stat()
                guard name.withCString({
                    fstatat(destinationDescriptor, $0, &target, AT_SYMLINK_NOFOLLOW)
                }) != 0, errno == ENOENT else {
                    throw BackupError.integrityCheckFailed
                }
                _ = try copyRegularFile(
                    sourceParent: sourceDescriptor,
                    sourceName: name,
                    destinationParent: destinationDescriptor,
                    destinationName: name,
                    relativePath: relative,
                    budget: budget
                )
            case .symbolicLink where excluded:
                throw BackupError.unsafeSymbolicLink(relativePath: relative)
            case .other where excluded:
                throw BackupError.unsupportedFilesystemItem(relativePath: relative)
            case .regular, .symbolicLink, .other:
                return
            case .missing:
                throw BackupError.sourceChanged(relativePath: relative)
            }
        }
        guard Self.identity(descriptor: sourceDescriptor) == before,
              fsync(destinationDescriptor) == 0 else {
            throw BackupError.sourceChanged(relativePath: relativePath)
        }
    }

    private func validateStorageIfPresent() throws -> Bool {
        if let initializationError { throw initializationError }
        guard try acquireBackupRoot(createIfAbsent: false) else { return false }
        try validateStorage()
        return true
    }

    private func ensureStorageForCreate() throws {
        if let initializationError { throw initializationError }
        guard try acquireBackupRoot(createIfAbsent: true) else {
            throw BackupError.unsafeStorage
        }
    }

    private func validateStorage() throws {
        if let initializationError { throw initializationError }
        if activeBackupRoot == nil {
            guard try acquireBackupRoot(createIfAbsent: false) else {
                throw BackupError.unsafeStorage
            }
        }
        guard let capability = activeBackupRoot,
              Self.identity(descriptor: capability.descriptor).map({
                Self.sameDirectoryNode($0, capability.identity)
                    && $0.owner == capability.identity.owner
                    && ($0.mode & 0o7777) == (capability.identity.mode & 0o7777)
              }) == true,
              Self.securePrivateDirectory(capability.identity),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(capability.descriptor) else {
            throw BackupError.unsafeStorage
        }
        try revalidateDirectoryCapability(capability)
        var catalog = stat()
        if Self.catalogName.withCString({
            fstatat(capability.descriptor, $0, &catalog, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            let catalogIdentity = Self.identity(catalog)
            guard Self.kind(mode: catalogIdentity.mode) == .regular,
                  catalogIdentity.owner == geteuid(),
                  catalogIdentity.linkCount == 1,
                  catalogIdentity.mode & 0o077 == 0,
                  catalogIdentity.mode & (S_ISUID | S_ISGID) == 0 else {
                throw BackupError.unsafeStorage
            }
        } else if errno != ENOENT {
            throw BackupError.unsafeStorage
        }
    }

    private static let catalogName = "catalog.json"

    @discardableResult
    private func acquireBackupRoot(createIfAbsent: Bool) throws -> Bool {
        if activeBackupRoot != nil { return true }
        let capability = try acquireDirectoryCapability(
            finalURL: root,
            stagingLeaf: Self.backupPublicationStagingName,
            specification: ProviderHistoryDeviceAttestation.backups,
            createIfAbsent: createIfAbsent,
            managed: managesAttestedNamespaces,
            expectedIdentity: rootIdentity
        )
        activeBackupRoot = capability
        if let capability { rootIdentity = capability.identity }
        return capability != nil
    }

    @discardableResult
    private func acquireRecoveryRoot(createIfAbsent: Bool) throws -> Bool {
        if activeRecoveryRoot != nil { return true }
        let capability = try acquireDirectoryCapability(
            finalURL: recoveryRootURL(),
            stagingLeaf: Self.recoveryPublicationStagingName,
            specification: ProviderHistoryDeviceAttestation.stateRecovery,
            createIfAbsent: createIfAbsent,
            managed: managesAttestedNamespaces,
            expectedIdentity: nil
        )
        activeRecoveryRoot = capability
        return capability != nil
    }

    private func acquireDirectoryCapability(
        finalURL: URL,
        stagingLeaf: String,
        specification: ProviderHistoryDeviceAttestation.Namespace,
        createIfAbsent: Bool,
        managed: Bool,
        expectedIdentity: FileIdentity?
    ) throws -> DirectoryCapability? {
        let finalURL = finalURL.standardizedFileURL
        let parentURL = finalURL.deletingLastPathComponent().standardizedFileURL
        guard Self.validComponent(finalURL.lastPathComponent), Self.validComponent(stagingLeaf) else {
            throw BackupError.unsafeStorage
        }
        let retainedParent = boundDirectoryBases().first(where: {
            $0.0.standardizedFileURL == parentURL
        })?.1
        let parent = retainedParent.map { fcntl($0, F_DUPFD_CLOEXEC, 0) }
            ?? Darwin.open(
                parentURL.path,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        guard parent >= 0,
              let parentIdentity = Self.identity(descriptor: parent),
              Self.kind(mode: parentIdentity.mode) == .directory,
              parentIdentity.owner == geteuid(),
              parentIdentity.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parent) else {
            if parent >= 0 { _ = Darwin.close(parent) }
            throw BackupError.unsafeStorage
        }

        var marker: ProviderHistoryNamespaceMarker?
        if managed {
            let state: ProviderHistoryNamespaceBackgroundState
            do {
                state = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                    namespaceName: specification.name,
                    expectedURL: finalURL,
                    expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                    expectedReceipt: specification.publicationReceipt,
                    configuration: ProviderHistoryDeviceAttestation.configuration(
                        applicationSupport: applicationSupport,
                        operationDuration: min(10, limits.operationDuration)
                    ),
                    keyStore: attestationKeyStore
                )
            } catch {
                _ = Darwin.close(parent)
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
            switch state {
            case .foregroundRequired:
                _ = Darwin.close(parent)
                // The shared auxiliary foreground coordinator owns explicit
                // acknowledgement and `reconcilePrepared`; a manager worker
                // must never adopt this ambiguous state silently.
                throw BackupError.providerHistoryPrivacyMigrationRequired
            case .current(let current):
                marker = current
            case .absent:
                var finalMetadata = stat()
                let finalStatus = finalURL.lastPathComponent.withCString {
                    fstatat(parent, $0, &finalMetadata, AT_SYMLINK_NOFOLLOW)
                }
                let finalErrno = errno
                var stagingMetadata = stat()
                let stagingStatus = stagingLeaf.withCString {
                    fstatat(parent, $0, &stagingMetadata, AT_SYMLINK_NOFOLLOW)
                }
                let stagingErrno = errno
                guard (finalStatus == 0 || finalErrno == ENOENT),
                      (stagingStatus == 0 || stagingErrno == ENOENT) else {
                    _ = Darwin.close(parent)
                    throw BackupError.unsafeStorage
                }
                // Evaluate both statuses independently; an unmarked final or
                // fixed staging root is preserved as historical/ambiguous.
                if finalStatus == 0 || stagingStatus == 0 {
                    _ = Darwin.close(parent)
                    throw BackupError.providerHistoryPrivacyMigrationRequired
                }
                guard createIfAbsent else {
                    _ = Darwin.close(parent)
                    return nil
                }
                guard stagingLeaf.withCString({ mkdirat(parent, $0, mode_t(0o700)) }) == 0,
                      fsync(parent) == 0 else {
                    _ = Darwin.close(parent)
                    if errno == EEXIST {
                        throw BackupError.providerHistoryPrivacyMigrationRequired
                    }
                    throw BackupError.unsafeStorage
                }
                let staging = stagingLeaf.withCString {
                    openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
                }
                guard staging >= 0,
                      let stagingIdentity = Self.identity(descriptor: staging),
                      Self.securePrivateDirectory(stagingIdentity),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(staging),
                      fsync(staging) == 0,
                      fsync(parent) == 0 else {
                    if staging >= 0 { _ = Darwin.close(staging) }
                    _ = Darwin.close(parent)
                    throw BackupError.unsafeStorage
                }
                _ = Darwin.close(staging)
                do {
                    let authority = try ProviderHistoryDeviceAttestation.openForeground(
                        applicationSupport: applicationSupport,
                        operationDuration: min(10, limits.operationDuration),
                        keyStore: attestationKeyStore
                    )
                    marker = try authority.makeProviderHistoryNamespaceMarkerStore().publish(.init(
                        sourceParent: parentURL,
                        sourceLeaf: stagingLeaf,
                        destinationParent: parentURL,
                        destinationLeaf: finalURL.lastPathComponent,
                        namespaceName: specification.name,
                        privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                        receipt: specification.publicationReceipt,
                        operationDuration: min(10, limits.operationDuration)
                    ))
                } catch {
                    // Never remove fixed staging here. It may correspond to a
                    // durable prepared marker or to the pre-marker crash gap.
                    _ = Darwin.close(parent)
                    throw BackupError.providerHistoryPrivacyMigrationRequired
                }
            }
        } else {
            var existing = stat()
            let status = finalURL.lastPathComponent.withCString {
                fstatat(parent, $0, &existing, AT_SYMLINK_NOFOLLOW)
            }
            if status != 0 {
                guard errno == ENOENT else {
                    _ = Darwin.close(parent)
                    throw BackupError.unsafeStorage
                }
                guard createIfAbsent else {
                    _ = Darwin.close(parent)
                    return nil
                }
                guard finalURL.lastPathComponent.withCString({
                    mkdirat(parent, $0, mode_t(0o700))
                }) == 0, fsync(parent) == 0 else {
                    _ = Darwin.close(parent)
                    throw BackupError.unsafeStorage
                }
            }
        }

        // A current marker must not coexist with the fixed pre-publication
        // root. Such a collision is never cleaned up by a background worker.
        if managed {
            var orphan = stat()
            if stagingLeaf.withCString({
                fstatat(parent, $0, &orphan, AT_SYMLINK_NOFOLLOW)
            }) == 0 {
                _ = Darwin.close(parent)
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
            guard errno == ENOENT else {
                _ = Darwin.close(parent)
                throw BackupError.unsafeStorage
            }
        }
        let descriptor = finalURL.lastPathComponent.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0,
              let identity = Self.identity(descriptor: descriptor),
              Self.securePrivateDirectory(identity),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            if descriptor >= 0 { _ = Darwin.close(descriptor) }
            _ = Darwin.close(parent)
            throw BackupError.unsafeStorage
        }
        if let expectedIdentity,
           !Self.sameDirectoryNode(identity, expectedIdentity) {
            _ = Darwin.close(descriptor)
            _ = Darwin.close(parent)
            throw BackupError.unsafeStorage
        }
        var installed = stat()
        guard finalURL.lastPathComponent.withCString({
            fstatat(parent, $0, &installed, AT_SYMLINK_NOFOLLOW)
        }) == 0,
            Self.identity(installed) == identity else {
            _ = Darwin.close(descriptor)
            _ = Darwin.close(parent)
            throw BackupError.unsafeStorage
        }
        if let marker {
            guard marker.state == .current,
                  marker.canonicalPath == finalURL.path,
                  marker.leafName == finalURL.lastPathComponent,
                  marker.namespaceName == specification.name,
                  marker.device == identity.device,
                  marker.inode == identity.inode,
                  marker.owner == identity.owner,
                  marker.mode == UInt16(identity.mode & 0o7777),
                  marker.privacyEpoch == UInt64(ProviderHistoryPrivacyEpoch.current),
                  marker.receiptSHA256 == Self.sha256(specification.publicationReceipt) else {
                _ = Darwin.close(descriptor)
                _ = Darwin.close(parent)
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
        } else if managed {
            _ = Darwin.close(descriptor)
            _ = Darwin.close(parent)
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        return DirectoryCapability(
            url: finalURL,
            parentDescriptor: parent,
            descriptor: descriptor,
            parentIdentity: parentIdentity,
            identity: identity,
            marker: marker
        )
    }

    /// Rejects pre-epoch and mixed backup namespaces before any authentication
    /// key is requested. The check is classification-only: current data still
    /// has to pass HMAC, identity, receipt, and payload verification below.
    private func validateBackupPrivacyEpochStorage(budget: OperationBudget) throws {
        try budget.checkpoint()
        try validateStorage()
        var names: [String] = []
        try forEachDirectoryEntry(at: root, catalog: true, budget: budget) { names.append($0) }
        let hasJournal = names.contains(Self.backupJournalName)
        let journalNamespaces = names.filter {
            $0.hasPrefix(".creating-") || $0.hasPrefix(".deleting-")
        }
        guard journalNamespaces.count <= 1,
              journalNamespaces.isEmpty || hasJournal else {
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        var journalStagingName: String?
        for name in names {
            try budget.checkpoint()
            let url = root.appendingPathComponent(name, isDirectory: UUID(uuidString: name) != nil)
            if name == "catalog.json" || name == Self.backupJournalName {
                let payload = try validatePrivacyEpochEnvelope(at: url, budget: budget)
                if name == Self.backupJournalName {
                    guard let stagingName = payload["stagingName"] as? String,
                          Self.validComponent(stagingName) else {
                        throw BackupError.integrityCheckFailed
                    }
                    journalStagingName = stagingName
                }
            } else if UUID(uuidString: name) != nil {
                guard boundKind(url) == .directory else { throw BackupError.integrityCheckFailed }
                let manifest = url.appendingPathComponent(Self.manifestName, isDirectory: false)
                guard boundKind(manifest) != .missing else {
                    throw BackupError.providerHistoryPrivacyMigrationRequired
                }
                _ = try validatePrivacyEpochEnvelope(at: manifest, budget: budget)
            } else if name != Self.backupJournalName,
                      !journalNamespaces.contains(name) {
                // Orphaned staging, legacy catalog auxiliaries, and unknown
                // root entries are a mixed namespace. Preserve them exactly
                // for foreground recovery rather than silently building a
                // fresh catalog around them.
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
        }
        guard journalNamespaces.isEmpty
                || journalStagingName.map({ journalNamespaces == [$0] }) == true else {
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        try validateRestoreJournalPrivacyEpochIfPresent(budget: budget)
        try validateStorage()
    }

    private func validateRestoreJournalPrivacyEpochIfPresent(budget: OperationBudget) throws {
        guard try acquireRecoveryRoot(createIfAbsent: false) else { return }
        let journal = restoreJournalURL()
        guard boundKind(journal) != .missing else { return }
        _ = try validatePrivacyEpochEnvelope(at: journal, budget: budget)
    }

    private func validatePrivacyEpochEnvelope(
        at url: URL,
        budget: OperationBudget
    ) throws -> [String: Any] {
        let data = try readRegularFile(
            at: url,
            maximumBytes: min(limits.maximumManifestBytes, 2 * 1_024 * 1_024),
            budget: budget,
            storageFailure: .integrityCheckFailed
        )
        guard let json = try? JSONSerialization.jsonObject(with: data) else {
            throw BackupError.integrityCheckFailed
        }
        if json is [Any] {
            // Version 1 catalogs were un-enveloped arrays.
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        guard let object = json as? [String: Any],
              Set(object.keys) == ["payload", "authenticationTag"],
              let payload = object["payload"] as? [String: Any],
              let format = Self.jsonInteger(payload["formatVersion"]) else {
            throw BackupError.integrityCheckFailed
        }
        guard format == Self.formatVersion,
              Self.jsonInteger(payload["providerHistoryPrivacyEpoch"])
                == ProviderHistoryPrivacyEpoch.current else {
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        return payload
    }

    private func validateCurrentProviderHistorySource(requireExisting: Bool) throws {
        guard let home = activeHome else {
            if requireExisting { throw BackupError.providerHistoryPrivacyMigrationRequired }
            return
        }
        try revalidateHome(home, requireInstalled: true)
        guard let object = try? JSONSerialization.jsonObject(with: home.receiptBytes) as? [String: Any],
              currentHarnessHomeReceipt(object) else {
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
    }

    private func revalidateHome(
        _ home: HarnessHomeOperationCapability,
        requireInstalled: Bool
    ) throws {
        var installedReceipt = stat()
        guard Self.identity(descriptor: home.parentDescriptor).map({
                Self.sameDirectoryNode($0, home.parentIdentity)
                    && $0.owner == home.parentIdentity.owner
                    && ($0.mode & 0o7777) == (home.parentIdentity.mode & 0o7777)
              }) == true,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.parentDescriptor),
              Self.identity(descriptor: home.descriptor) == home.identity,
              Self.identity(descriptor: home.receiptDescriptor) == home.receiptIdentity,
              Self.harnessHomeReceiptName.withCString({
                fstatat(home.descriptor, $0, &installedReceipt, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              Self.identity(installedReceipt) == home.receiptIdentity,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.descriptor),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.receiptDescriptor),
              try Self.readExactDescriptor(
                home.receiptDescriptor,
                byteCount: home.receiptIdentity.byteCount,
                maximumBytes: Self.maximumHarnessHomeReceiptBytes,
                monotonicNow: monotonicNow,
                duration: limits.operationDuration
              ) == home.receiptBytes else {
            throw BackupError.sourceChanged(relativePath: Self.harnessHomeReceiptName)
        }
        if requireInstalled {
            var installed = stat()
            guard home.leafName.withCString({
                fstatat(home.parentDescriptor, $0, &installed, AT_SYMLINK_NOFOLLOW)
            }) == 0,
                Self.identity(installed) == home.identity else {
                throw BackupError.sourceChanged(relativePath: "")
            }
        }
        if let record = home.attestationRecord {
            guard record.canonicalPath == sourceState.standardizedFileURL.path,
                  record.device == home.identity.device,
                  record.inode == home.identity.inode,
                  record.owner == home.identity.owner,
                  record.mode == UInt16(home.identity.mode & 0o7777),
                  record.privacyEpoch == UInt64(ProviderHistoryPrivacyEpoch.current),
                  record.receiptSHA256 == Self.sha256(home.receiptBytes) else {
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
        }
    }

    private func currentHarnessHomeReceipt(_ object: [String: Any]) -> Bool {
        let cleanKeys: Set<String> = [
            "version", "migratedAt", "copiedEntries", "providerHistoryPrivacyEpoch"
        ]
        let recoveredKeys = cleanKeys.union(["source", "sourceKind"])
        let keys = Set(object.keys)
        guard keys == cleanKeys || keys == recoveredKeys,
              let version = Self.jsonInteger(object["version"]),
              let epoch = Self.jsonInteger(object["providerHistoryPrivacyEpoch"]),
              ProviderHistoryPrivacyEpoch.isCurrent(receiptVersion: version, epoch: epoch),
              let migratedAt = object["migratedAt"] as? NSNumber,
              CFGetTypeID(migratedAt) == CFNumberGetTypeID(),
              migratedAt.doubleValue.isFinite,
              let entries = object["copiedEntries"] as? [String],
              entries == entries.sorted(),
              Set(entries).count == entries.count,
              Set(entries).isSubset(of: ProviderHistoryPrivacyEpoch.settingsFileNames) else {
            return false
        }
        if keys == cleanKeys { return entries.isEmpty }
        guard object["sourceKind"] as? String == "historicalProviderState",
              let source = object["source"] as? String,
              source.utf8.count <= Int(PATH_MAX),
              !source.contains("\0") else {
            return false
        }
        let sourceURL = URL(fileURLWithPath: source).standardizedFileURL
        let recovery = sourceState.deletingLastPathComponent()
            .appendingPathComponent("HarnessHomeRecovery", isDirectory: true)
            .standardizedFileURL
        let name = sourceURL.lastPathComponent
        guard sourceURL.path == source,
              sourceURL.deletingLastPathComponent() == recovery,
              name.hasPrefix("receiptless-") else {
            return false
        }
        let identifier = String(name.dropFirst("receiptless-".count))
        guard let uuid = UUID(uuidString: identifier) else { return false }
        return identifier == uuid.uuidString.lowercased()
    }

    private static func jsonInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        let double = number.doubleValue
        guard double.isFinite, double.rounded(.towardZero) == double,
              double >= Double(Int.min), double <= Double(Int.max) else {
            return nil
        }
        return Int(double)
    }

    private func validateSourceRoot(descriptor: Int32? = nil) throws {
        guard let descriptor = descriptor ?? activeHome?.descriptor,
              let identity = Self.identity(descriptor: descriptor),
              Self.secureSourceDirectory(identity),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw BackupError.unsafeSource
        }
    }

    private func validateRestoreParent(_ parent: URL) throws {
        guard parent.standardizedFileURL == sourceState.deletingLastPathComponent().standardizedFileURL,
              let descriptor = activeHome?.parentDescriptor ?? activeSourceParent?.descriptor,
              let parentIdentity = Self.identity(descriptor: descriptor),
              Self.kind(mode: parentIdentity.mode) == .directory,
              parentIdentity.owner == geteuid(),
              parentIdentity.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw BackupError.unsafeSource
        }
    }

    private func openReplacementHomeCapability(
        expectedIdentity: FileIdentity
    ) throws -> DirectoryCapability {
        guard let retainedParent = activeHome?.parentDescriptor ?? activeSourceParent?.descriptor else {
            throw BackupError.unsafeSource
        }
        let parent = fcntl(retainedParent, F_DUPFD_CLOEXEC, 0)
        guard parent >= 0,
              let parentIdentity = Self.identity(descriptor: parent) else {
            if parent >= 0 { _ = Darwin.close(parent) }
            throw BackupError.unsafeSource
        }
        let descriptor = sourceState.lastPathComponent.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0,
              let identity = Self.identity(descriptor: descriptor),
              identity == expectedIdentity,
              Self.securePrivateDirectory(identity),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            if descriptor >= 0 { _ = Darwin.close(descriptor) }
            _ = Darwin.close(parent)
            throw BackupError.unsafeSource
        }
        return DirectoryCapability(
            url: sourceState,
            parentDescriptor: parent,
            descriptor: descriptor,
            parentIdentity: parentIdentity,
            identity: identity,
            marker: nil
        )
    }

    private func canonicalSourcePath() -> String {
        sourceState.standardizedFileURL.path
    }

    private func authenticationKey() throws -> SymmetricKey {
        let data = try keyProvider()
        guard data.count == 32 else { throw BackupError.authenticationUnavailable }
        return SymmetricKey(data: data)
    }

    private func authenticate(_ payload: ManifestPayload, key: SymmetricKey) throws -> ManifestEnvelope {
        ManifestEnvelope(payload: payload, authenticationTag: try authenticationTag(for: payload, key: key))
    }

    private func authenticationTag<T: Encodable>(for payload: T, key: SymmetricKey) throws -> String {
        let data = try Self.encode(payload)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: key)).base64EncodedString()
    }

    private func verify<T: Encodable>(_ payload: T, tag: String, key: SymmetricKey) throws -> Bool {
        guard let supplied = Data(base64Encoded: tag), supplied.count == SHA256.byteCount else { return false }
        let expected = Data(HMAC<SHA256>.authenticationCode(for: try Self.encode(payload), using: key))
        return Self.constantTimeEqual(supplied, expected)
    }

    private func makeBudget(
        cancellation: StateBackupOperationCancellation
    ) throws -> OperationBudget {
        guard Self.valid(limits: limits) else { throw BackupError.invalidLimits }
        let start = monotonicNow()
        let duration = min(max(0, limits.operationDuration), 300)
        let nanoseconds = UInt64(duration * 1_000_000_000)
        let addition = start.addingReportingOverflow(nanoseconds)
        return OperationBudget(
            limits: limits,
            deadline: addition.overflow ? UInt64.max : addition.partialValue,
            monotonicNow: monotonicNow,
            cancellation: cancellation
        )
    }

    private func cleanupBudget() -> OperationBudget {
        var cleanupLimits = limits
        cleanupLimits.maximumOperationEntries = max(
            cleanupLimits.maximumOperationEntries,
            StateBackupLimits.production.maximumOperationEntries
        )
        cleanupLimits.maximumDirectoryDepth = max(
            cleanupLimits.maximumDirectoryDepth,
            StateBackupLimits.production.maximumDirectoryDepth
        )
        cleanupLimits.maximumRelativePathBytes = max(
            cleanupLimits.maximumRelativePathBytes,
            StateBackupLimits.production.maximumRelativePathBytes
        )
        cleanupLimits.maximumOperationBytes = max(
            cleanupLimits.maximumOperationBytes,
            StateBackupLimits.production.maximumBackupBytes
        )
        cleanupLimits.operationDuration = min(5, max(0.25, limits.operationDuration))
        let start = DispatchTime.now().uptimeNanoseconds
        let nanoseconds = UInt64(cleanupLimits.operationDuration * 1_000_000_000)
        let addition = start.addingReportingOverflow(nanoseconds)
        return OperationBudget(
            limits: cleanupLimits,
            deadline: addition.overflow ? UInt64.max : addition.partialValue,
            monotonicNow: { DispatchTime.now().uptimeNanoseconds },
            cancellation: StateBackupOperationCancellation()
        )
    }

    private func recoveryRootURL() -> URL {
        let parent = managesAttestedNamespaces
            ? applicationSupport
            : sourceState.deletingLastPathComponent()
        return parent.appendingPathComponent(
            ProviderHistoryDeviceAttestation.stateRecovery.leafName,
            isDirectory: true
        ).standardizedFileURL
    }

    private func restoreJournalURL() -> URL {
        recoveryRootURL().appendingPathComponent(Self.restoreJournalName, isDirectory: false)
    }

    private func backupJournalURL() -> URL {
        root.appendingPathComponent(Self.backupJournalName, isDirectory: false)
    }

    private func validateReceipt(
        at container: URL,
        expectedBackup: StateBackup,
        expectedManifestData: Data,
        expectedOperationID: UUID? = nil,
        key: SymmetricKey,
        budget: OperationBudget
    ) throws {
        let data = try readRegularFile(
            at: container.appendingPathComponent(Self.receiptName),
            maximumBytes: min(limits.maximumManifestBytes, 256 * 1_024),
            budget: budget,
            storageFailure: .invalidBackup
        )
        guard Self.hasExactBackupReceiptSchema(data),
              let envelope = try? Self.decode(BackupReceiptEnvelope.self, from: data),
              envelope.payload.formatVersion == Self.transactionFormatVersion,
              envelope.payload.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              envelope.payload.backup == expectedBackup,
              envelope.payload.manifestSHA256 == Self.sha256(expectedManifestData),
              expectedOperationID == nil || envelope.payload.operationID == expectedOperationID,
              try verify(envelope.payload, tag: envelope.authenticationTag, key: key) else {
            throw BackupError.integrityCheckFailed
        }
    }

    private func writeBackupJournal(
        _ payload: BackupTransactionPayload,
        key: SymmetricKey,
        budget: OperationBudget
    ) throws {
        try validateBackupJournal(payload)
        let envelope = BackupTransactionEnvelope(
            payload: payload,
            authenticationTag: try authenticationTag(for: payload, key: key)
        )
        try durableAtomicWrite(
            try Self.encode(envelope),
            to: backupJournalURL(),
            permissions: 0o600,
            expectedParent: root,
            budget: budget
        )
    }

    private func readBackupJournal(
        key: SymmetricKey,
        budget: OperationBudget
    ) throws -> BackupTransactionPayload? {
        let url = backupJournalURL()
        guard boundKind(url) != .missing else { return nil }
        let data = try readRegularFile(
            at: url,
            maximumBytes: min(limits.maximumManifestBytes, 2 * 1_024 * 1_024),
            budget: budget,
            storageFailure: .transactionCorrupt
        )
        guard Self.hasExactBackupTransactionSchema(data),
              let envelope = try? Self.decode(BackupTransactionEnvelope.self, from: data),
              try verify(envelope.payload, tag: envelope.authenticationTag, key: key) else {
            throw BackupError.transactionCorrupt
        }
        try validateBackupJournal(envelope.payload)
        return envelope.payload
    }

    private func validateBackupJournal(_ payload: BackupTransactionPayload) throws {
        guard payload.formatVersion == Self.transactionFormatVersion,
              payload.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              Self.validComponent(payload.stagingName),
              Self.validComponent(payload.publishedName),
              payload.backup.path == Self.payloadURL(for: payload.backup.id, root: root).path,
              payload.targetCatalog.count <= limits.maximumBackupCount,
              Set(payload.targetCatalog.map(\.id)).count == payload.targetCatalog.count,
              payload.evictedBackupIDs.count <= limits.maximumBackupCount,
              Set(payload.evictedBackupIDs).count == payload.evictedBackupIDs.count,
              Set(payload.evictedNamespaceIdentities.keys) == Set(payload.evictedBackupIDs.map(\.uuidString)) else {
            throw BackupError.transactionCorrupt
        }
        switch payload.kind {
        case .create:
            guard payload.publishedName == payload.backup.id.uuidString,
                  payload.stagingName.hasPrefix(".creating-"),
                  payload.targetCatalog.contains(payload.backup) else {
                throw BackupError.transactionCorrupt
            }
        case .delete:
            guard payload.publishedName == payload.backup.id.uuidString,
                  payload.stagingName.hasPrefix(".deleting-"),
                  !payload.targetCatalog.contains(where: { $0.id == payload.backup.id }),
                  payload.evictedBackupIDs.isEmpty,
                  payload.evictedNamespaceIdentities.isEmpty else {
                throw BackupError.transactionCorrupt
            }
        }
    }

    private func clearBackupJournal(budget: OperationBudget) throws {
        let url = backupJournalURL()
        guard let identity = boundIdentity(url) else { return }
        try durableUnlink(
            url,
            expectedParent: root,
            expectedIdentity: identity,
            budget: budget
        )
    }

    private func writeRestoreJournal(
        _ payload: RestoreTransactionPayload,
        key: SymmetricKey,
        budget: OperationBudget
    ) throws {
        try validateRestoreJournal(payload)
        let recoveryRoot = recoveryRootURL()
        guard try acquireRecoveryRoot(createIfAbsent: true),
              boundKind(recoveryRoot) == .directory else { throw BackupError.unsafeStorage }
        let envelope = RestoreTransactionEnvelope(
            payload: payload,
            authenticationTag: try authenticationTag(for: payload, key: key)
        )
        try durableAtomicWrite(
            try Self.encode(envelope),
            to: restoreJournalURL(),
            permissions: 0o600,
            expectedParent: recoveryRoot,
            budget: budget
        )
    }

    private func readRestoreJournal(
        key: SymmetricKey,
        budget: OperationBudget
    ) throws -> RestoreTransactionPayload? {
        let recoveryRoot = recoveryRootURL()
        guard try acquireRecoveryRoot(createIfAbsent: false) else { return nil }
        guard boundKind(recoveryRoot) == .directory,
              let identity = boundIdentity(recoveryRoot),
              Self.securePrivateDirectory(identity) else {
            throw BackupError.transactionCorrupt
        }
        let url = restoreJournalURL()
        guard boundKind(url) != .missing else { return nil }
        let data = try readRegularFile(
            at: url,
            maximumBytes: min(limits.maximumManifestBytes, 256 * 1_024),
            budget: budget,
            storageFailure: .transactionCorrupt
        )
        guard Self.hasExactRestoreTransactionSchema(data),
              let envelope = try? Self.decode(RestoreTransactionEnvelope.self, from: data),
              try verify(envelope.payload, tag: envelope.authenticationTag, key: key) else {
            throw BackupError.transactionCorrupt
        }
        try validateRestoreJournal(envelope.payload)
        return envelope.payload
    }

    private func validateRestoreJournal(_ payload: RestoreTransactionPayload) throws {
        guard payload.formatVersion == Self.transactionFormatVersion,
              payload.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              Self.validComponent(payload.stagedName),
              payload.stagedName.hasPrefix(".local-harness-restore-"),
              Self.validComponent(payload.quarantineName),
              UUID(uuidString: payload.quarantineName) != nil,
              payload.sourceName == sourceState.lastPathComponent,
              Self.validComponent(payload.sourceName) else {
            throw BackupError.transactionCorrupt
        }
    }

    private func clearRestoreJournal(budget: OperationBudget) throws {
        let recoveryRoot = recoveryRootURL()
        let url = restoreJournalURL()
        guard try acquireRecoveryRoot(createIfAbsent: false),
              let identity = boundIdentity(url) else { return }
        try durableUnlink(
            url,
            expectedParent: recoveryRoot,
            expectedIdentity: identity,
            budget: budget
        )
    }

    private func reconcileTransactions(
        key: SymmetricKey,
        budget: OperationBudget,
        permit: StateBackupQuiescencePermit? = nil
    ) throws {
        try reconcileBackupTransaction(key: key, budget: budget)
        guard let restore = try readRestoreJournal(key: key, budget: budget) else { return }
        guard let permit else { throw BackupError.quiescenceRequired }
        try permit.validate()
        try reconcileRestoreTransaction(restore, key: key, permit: permit, budget: budget)
    }

    private func reconcileBackupTransaction(
        key: SymmetricKey,
        budget: OperationBudget
    ) throws {
        guard let journal = try readBackupJournal(key: key, budget: budget) else { return }
        let published = root.appendingPathComponent(journal.publishedName, isDirectory: true)
        let staging = root.appendingPathComponent(journal.stagingName, isDirectory: true)
        switch journal.kind {
        case .create:
            let publishedIdentity = boundIdentity(published)
            let stagingIdentity = boundIdentity(staging)
            guard !(publishedIdentity != nil && stagingIdentity != nil) else {
                throw BackupError.transactionCorrupt
            }
            if let publishedIdentity {
                guard publishedIdentity == journal.namespaceIdentity else {
                    throw BackupError.transactionCorrupt
                }
            } else if let stagingIdentity {
                guard stagingIdentity == journal.namespaceIdentity else {
                    throw BackupError.transactionCorrupt
                }
                try durableRename(
                    from: staging,
                    to: published,
                    expectedIdentity: journal.namespaceIdentity,
                    sourceParent: root,
                    destinationParent: root,
                    budget: budget
                )
            } else {
                throw BackupError.transactionCorrupt
            }
            let manifest = try loadManifest(
                at: published,
                expectedID: journal.backup.id,
                key: key,
                budget: budget,
                expectedReceiptOperationID: journal.operationID
            )
            guard Self.backup(from: manifest, root: root) == journal.backup else {
                throw BackupError.transactionCorrupt
            }
            try verifyPayload(
                manifest,
                at: published.appendingPathComponent(Self.payloadName, isDirectory: true),
                budget: budget
            )
            try persist(journal.targetCatalog, key: key, budget: budget)
            try applyRetention(journal, budget: budget)
        case .delete:
            let publishedIdentity = boundIdentity(published)
            let stagedIdentity = boundIdentity(staging)
            guard !(publishedIdentity != nil && stagedIdentity != nil) else {
                throw BackupError.transactionCorrupt
            }
            if let publishedIdentity {
                guard publishedIdentity == journal.namespaceIdentity else {
                    throw BackupError.transactionCorrupt
                }
                try durableRename(
                    from: published,
                    to: staging,
                    expectedIdentity: journal.namespaceIdentity,
                    sourceParent: root,
                    destinationParent: root,
                    budget: budget
                )
            } else if let stagedIdentity {
                guard Self.sameDirectoryNode(stagedIdentity, journal.namespaceIdentity) else {
                    throw BackupError.transactionCorrupt
                }
            }
            try persist(journal.targetCatalog, key: key, budget: budget)
            if boundKind(staging) != .missing {
                try removeTree(staging, expectedIdentity: journal.namespaceIdentity, budget: budget)
            }
        }
        try clearBackupJournal(budget: budget)
    }

    private func reconcileRestoreTransaction(
        _ originalJournal: RestoreTransactionPayload,
        key: SymmetricKey,
        permit: StateBackupQuiescencePermit,
        budget: OperationBudget
    ) throws {
        var journal = originalJournal
        let sourceParent = sourceState.deletingLastPathComponent()
        let recoveryRoot = recoveryRootURL()
        let staged = sourceParent.appendingPathComponent(journal.stagedName, isDirectory: true)
        let quarantine = recoveryRoot.appendingPathComponent(journal.quarantineName, isDirectory: true)
        let container = Self.containerURL(for: journal.backupID, root: root)
        let manifest = try loadManifest(
            at: container,
            expectedID: journal.backupID,
            key: key,
            budget: budget
        )

        try permit.validate()
        if let sourceIdentity = journal.sourceIdentity {
            if boundKind(quarantine) == .missing {
                guard boundIdentity(sourceState) == sourceIdentity,
                      boundIdentity(staged) == journal.stagedIdentity else {
                    throw BackupError.transactionCorrupt
                }
                try durableRename(
                    from: sourceState,
                    to: quarantine,
                    expectedIdentity: sourceIdentity,
                    sourceParent: sourceParent,
                    destinationParent: recoveryRoot,
                    budget: budget
                )
                if activeHome?.identity == sourceIdentity {
                    activeHome?.installedAtOriginalLeaf = false
                }
                journal.phase = .sourceQuarantined
                try writeRestoreJournal(journal, key: key, budget: budget)
            } else {
                guard boundIdentity(quarantine) == sourceIdentity else {
                    throw BackupError.transactionCorrupt
                }
            }
        } else {
            guard boundKind(quarantine) == .missing else { throw BackupError.transactionCorrupt }
        }

        try permit.validate()
        if boundKind(sourceState) == .missing {
            guard boundIdentity(staged) == journal.stagedIdentity else {
                throw BackupError.transactionCorrupt
            }
            try durableRename(
                from: staged,
                to: sourceState,
                expectedIdentity: journal.stagedIdentity,
                sourceParent: sourceParent,
                destinationParent: sourceParent,
                budget: budget
            )
            activeReplacementHome = try openReplacementHomeCapability(
                expectedIdentity: journal.stagedIdentity
            )
            journal.phase = .replacementActivated
            try writeRestoreJournal(journal, key: key, budget: budget)
        } else {
            guard boundIdentity(sourceState) == journal.stagedIdentity,
                  boundKind(staged) == .missing else {
                throw BackupError.transactionCorrupt
            }
            if activeHome?.identity != journal.stagedIdentity {
                activeReplacementHome = try openReplacementHomeCapability(
                    expectedIdentity: journal.stagedIdentity
                )
            }
        }

        try validateRestoredPayload(manifest, at: sourceState, budget: budget)
        try permit.validate()
        journal.phase = .finalized
        try writeRestoreJournal(journal, key: key, budget: budget)
        try clearRestoreJournal(budget: budget)
    }

    private func retentionPlan(
        existing: [StateBackup],
        adding backup: StateBackup,
        newBackupBytes: Int64,
        key: SymmetricKey,
        budget: OperationBudget
    ) throws -> (catalog: [StateBackup], evicted: [UUID]) {
        guard newBackupBytes >= 0,
              newBackupBytes <= limits.maximumBackupBytes,
              newBackupBytes <= limits.maximumAggregateStoredBytes else {
            throw BackupError.backupLimitExceeded
        }
        var byteCounts: [UUID: Int64] = [backup.id: newBackupBytes]
        var aggregate = newBackupBytes
        for existingBackup in existing {
            let manifest = try loadManifest(
                at: Self.containerURL(for: existingBackup.id, root: root),
                expectedID: existingBackup.id,
                key: key,
                budget: budget
            )
            byteCounts[existingBackup.id] = manifest.totalBytes
            let (next, overflow) = aggregate.addingReportingOverflow(manifest.totalBytes)
            guard !overflow else { throw BackupError.backupLimitExceeded }
            aggregate = next
        }
        var retained = (existing + [backup]).sorted {
            if $0.createdAt != $1.createdAt { return $0.createdAt > $1.createdAt }
            return $0.id.uuidString < $1.id.uuidString
        }
        var evicted: [UUID] = []
        while retained.count > limits.maximumBackupCount || aggregate > limits.maximumAggregateStoredBytes {
            guard let index = retained.indices.reversed().first(where: {
                retained[$0].id != backup.id && !protectionRegistry.contains(retained[$0].id)
            }) else {
                throw BackupError.backupLimitExceeded
            }
            let removed = retained.remove(at: index)
            aggregate -= byteCounts[removed.id] ?? 0
            evicted.append(removed.id)
        }
        return (retained, evicted.sorted { $0.uuidString < $1.uuidString })
    }

    private func applyRetention(
        _ journal: BackupTransactionPayload,
        budget: OperationBudget
    ) throws {
        guard journal.kind == .create else { return }
        for id in journal.evictedBackupIDs {
            try budget.checkpoint()
            guard let expected = journal.evictedNamespaceIdentities[id.uuidString] else {
                throw BackupError.transactionCorrupt
            }
            let published = Self.containerURL(for: id, root: root)
            let quarantineName = ".retaining-\(journal.operationID.uuidString)-\(id.uuidString)"
            let quarantine = root.appendingPathComponent(quarantineName, isDirectory: true)
            let publishedIdentity = boundIdentity(published)
            let quarantineIdentity = boundIdentity(quarantine)
            guard !(publishedIdentity != nil && quarantineIdentity != nil) else {
                throw BackupError.transactionCorrupt
            }
            if let publishedIdentity {
                guard Self.sameDirectoryNode(publishedIdentity, expected) else {
                    throw BackupError.transactionCorrupt
                }
                try durableRename(
                    from: published,
                    to: quarantine,
                    expectedIdentity: expected,
                    sourceParent: root,
                    destinationParent: root,
                    budget: budget
                )
            } else if let quarantineIdentity {
                guard Self.sameDirectoryNode(quarantineIdentity, expected) else {
                    throw BackupError.transactionCorrupt
                }
            } else {
                continue
            }
            try removeTree(quarantine, expectedIdentity: expected, budget: budget)
        }
    }

    private func readRegularFile(
        at url: URL,
        maximumBytes: Int,
        budget: OperationBudget,
        storageFailure: BackupError
    ) throws -> Data {
        try budget.checkpoint()
        guard maximumBytes >= 0 else { throw storageFailure }
        return try withBoundParentDescriptor(of: url, failure: storageFailure) { parent, leaf in
            let descriptor = leaf.withCString {
                openat(parent, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            }
            guard descriptor >= 0 else { throw storageFailure }
            defer { _ = Darwin.close(descriptor) }
            guard let before = Self.identity(descriptor: descriptor),
                  Self.kind(mode: before.mode) == .regular,
                  before.owner == geteuid(),
                  before.linkCount == 1,
                  before.mode & 0o077 == 0,
                  before.mode & (S_ISUID | S_ISGID) == 0,
                  before.byteCount >= 0,
                  before.byteCount <= Int64(maximumBytes),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
                throw storageFailure
            }
            var data = Data()
            data.reserveCapacity(min(Int(before.byteCount), maximumBytes))
            var buffer = [UInt8](repeating: 0, count: min(64 * 1_024, max(1, maximumBytes + 1)))
            while true {
                try budget.checkpoint()
                let count = buffer.withUnsafeMutableBytes {
                    Darwin.read(descriptor, $0.baseAddress, $0.count)
                }
                if count == 0 { break }
                if count < 0 {
                    if errno == EINTR { continue }
                    throw storageFailure
                }
                guard count <= maximumBytes - data.count else { throw storageFailure }
                data.append(contentsOf: buffer.prefix(count))
                try budget.consumeBytes(Int64(count))
            }
            var installed = stat()
            guard data.count == Int(before.byteCount),
                  Self.identity(descriptor: descriptor) == before,
                  leaf.withCString({
                    fstatat(parent, $0, &installed, AT_SYMLINK_NOFOLLOW)
                  }) == 0,
                  Self.identity(installed) == before else {
                throw storageFailure
            }
            return data
        }
    }

    /// Descriptor-backed streaming enumeration. No attacker-controlled
    /// directory is materialized before the global count/deadline checks.
    private func forEachDirectoryEntry(
        descriptor: Int32,
        relativePath: String,
        catalog: Bool,
        budget: OperationBudget,
        body: (String) throws -> Void
    ) throws {
        try budget.checkpoint()
        guard let before = Self.identity(descriptor: descriptor),
              Self.kind(mode: before.mode) == .directory,
              before.owner == geteuid(),
              before.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw BackupError.unsafeSource
        }
        let iteration = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard iteration >= 0, let stream = fdopendir(iteration) else {
            if iteration >= 0 { _ = Darwin.close(iteration) }
            throw BackupError.unsafeSource
        }
        defer { _ = closedir(stream) }
        while true {
            try budget.checkpoint()
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw BackupError.unsafeSource }
                break
            }
            guard let name = Self.directoryEntryName(entry) else {
                throw BackupError.unsafeSource
            }
            if name == "." || name == ".." { continue }
            guard Self.validComponent(name) else { throw BackupError.unsafeSource }
            if catalog { try budget.consumeCatalogEntry(name: name) }
            try body(name)
        }
        guard Self.identity(descriptor: descriptor) == before else {
            throw BackupError.sourceChanged(relativePath: relativePath)
        }
    }

    private func forEachDirectoryEntry(
        at directory: URL,
        catalog: Bool,
        budget: OperationBudget,
        body: (String) throws -> Void
    ) throws {
        try withBoundDirectoryDescriptor(at: directory, failure: .unsafeSource) { descriptor in
            try forEachDirectoryEntry(
                descriptor: descriptor,
                relativePath: directory.lastPathComponent,
                catalog: catalog,
                budget: budget,
                body: body
            )
        }
    }

    private func syncDirectory(_ directory: URL, budget: OperationBudget) throws {
        try budget.checkpoint()
        try withBoundDirectoryDescriptor(at: directory) { descriptor in
            guard let before = Self.identity(descriptor: descriptor),
                  Self.kind(mode: before.mode) == .directory,
                  before.owner == geteuid(),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
                  Darwin.fsync(descriptor) == 0,
                  Self.identity(descriptor: descriptor) == before else {
                throw BackupError.unsafeStorage
            }
        }
    }

    private func durableAtomicWrite(
        _ data: Data,
        to destination: URL,
        permissions: Int,
        expectedParent: URL,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        guard destination.deletingLastPathComponent().path == expectedParent.path,
              Self.validComponent(destination.lastPathComponent),
              permissions & 0o077 == 0,
              data.count <= limits.maximumManifestBytes else {
            throw BackupError.unsafeStorage
        }
        try withBoundDirectoryDescriptor(at: expectedParent) { parent in
          guard let parentBefore = Self.identity(descriptor: parent),
                Self.securePrivateDirectory(parentBefore),
                CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parent) else {
              throw BackupError.unsafeStorage
          }
          var existing = stat()
          if fstatat(parent, destination.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            let identity = Self.identity(existing)
            guard Self.kind(mode: identity.mode) == .regular,
                  identity.owner == geteuid(),
                  identity.linkCount == 1,
                  identity.mode & 0o077 == 0,
                  identity.mode & (S_ISUID | S_ISGID) == 0 else {
                throw BackupError.unsafeStorage
            }
          } else if errno != ENOENT {
            throw BackupError.unsafeStorage
          }
          let temporaryName = ".write-\(makeUUID().uuidString)"
          let descriptor = Darwin.openat(
            parent,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(permissions)
          )
          guard descriptor >= 0 else { throw BackupError.unsafeStorage }
          var temporaryExists = true
          defer {
            _ = Darwin.close(descriptor)
            if temporaryExists { _ = unlinkat(parent, temporaryName, 0) }
          }
          try Self.writeAll(data, descriptor: descriptor, budget: budget)
          guard Darwin.fchmod(descriptor, mode_t(permissions)) == 0,
              Darwin.fsync(descriptor) == 0,
              let written = Self.identity(descriptor: descriptor),
              Self.kind(mode: written.mode) == .regular,
              written.owner == geteuid(),
              written.linkCount == 1,
              written.byteCount == Int64(data.count),
              written.mode & 0o077 == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw BackupError.unsafeStorage
          }
          guard renameat(parent, temporaryName, parent, destination.lastPathComponent) == 0 else {
            throw BackupError.unsafeStorage
          }
          temporaryExists = false
          var rebound = stat()
          guard fstatat(parent, destination.lastPathComponent, &rebound, AT_SYMLINK_NOFOLLOW) == 0,
              Self.identity(rebound) == written,
              Darwin.fsync(parent) == 0,
              Self.identity(descriptor: parent).map({
                Self.sameDirectoryNode($0, parentBefore)
              }) == true else {
            throw BackupError.unsafeStorage
          }
        }
    }

    private func durableRename(
        from source: URL,
        to destination: URL,
        expectedIdentity: FileIdentity,
        sourceParent: URL,
        destinationParent: URL,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        guard source.deletingLastPathComponent().path == sourceParent.path,
              destination.deletingLastPathComponent().path == destinationParent.path,
              Self.validComponent(source.lastPathComponent),
              Self.validComponent(destination.lastPathComponent) else {
            throw BackupError.unsafeStorage
        }
        try withBoundDirectoryDescriptor(at: sourceParent) { sourceParentDescriptor in
            try withBoundDirectoryDescriptor(at: destinationParent) { destinationParentDescriptor in
                guard let sourceParentBefore = Self.identity(descriptor: sourceParentDescriptor),
                      let destinationParentBefore = Self.identity(descriptor: destinationParentDescriptor),
                      Self.kind(mode: sourceParentBefore.mode) == .directory,
                      Self.kind(mode: destinationParentBefore.mode) == .directory,
                      sourceParentBefore.owner == geteuid(),
                      destinationParentBefore.owner == geteuid(),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceParentDescriptor),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(destinationParentDescriptor) else {
                    throw BackupError.unsafeStorage
                }
                var declared = stat()
                guard source.lastPathComponent.withCString({
                    fstatat(sourceParentDescriptor, $0, &declared, AT_SYMLINK_NOFOLLOW)
                }) == 0,
                    Self.identity(declared) == expectedIdentity else {
                    throw BackupError.unsafeStorage
                }
                var destinationMetadata = stat()
                let destinationStatus = destination.lastPathComponent.withCString {
                    fstatat(destinationParentDescriptor, $0, &destinationMetadata, AT_SYMLINK_NOFOLLOW)
                }
                guard destinationStatus != 0, errno == ENOENT else {
                    throw BackupError.unsafeStorage
                }
                let renameStatus = source.lastPathComponent.withCString { sourceLeaf in
                    destination.lastPathComponent.withCString { destinationLeaf in
                        renameat(
                            sourceParentDescriptor,
                            sourceLeaf,
                            destinationParentDescriptor,
                            destinationLeaf
                        )
                    }
                }
                guard renameStatus == 0 else { throw BackupError.unsafeStorage }
                var rebound = stat()
                guard destination.lastPathComponent.withCString({
                    fstatat(destinationParentDescriptor, $0, &rebound, AT_SYMLINK_NOFOLLOW)
                }) == 0,
                    Self.identity(rebound) == expectedIdentity,
                    Darwin.fsync(destinationParentDescriptor) == 0,
                    (sourceParentDescriptor == destinationParentDescriptor
                        || Darwin.fsync(sourceParentDescriptor) == 0),
                    Self.identity(descriptor: sourceParentDescriptor).map({
                        Self.sameDirectoryNode($0, sourceParentBefore)
                    }) == true,
                    Self.identity(descriptor: destinationParentDescriptor).map({
                        Self.sameDirectoryNode($0, destinationParentBefore)
                    }) == true else {
                    throw BackupError.unsafeStorage
                }
            }
        }
    }

    private func durableUnlink(
        _ url: URL,
        expectedParent: URL,
        expectedIdentity: FileIdentity?,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        guard url.deletingLastPathComponent().path == expectedParent.path,
              Self.validComponent(url.lastPathComponent) else {
            throw BackupError.unsafeStorage
        }
        try withBoundDirectoryDescriptor(at: expectedParent) { parent in
            guard let parentBefore = Self.identity(descriptor: parent) else {
                throw BackupError.unsafeStorage
            }
            var metadata = stat()
            guard url.lastPathComponent.withCString({
                fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }) == 0 else {
                if errno == ENOENT { return }
                throw BackupError.unsafeStorage
            }
            let identity = Self.identity(metadata)
            guard Self.kind(mode: identity.mode) == .regular,
                  identity.owner == geteuid(),
                  identity.linkCount == 1,
                  identity.mode & 0o077 == 0,
                  expectedIdentity == nil || expectedIdentity == identity,
                  url.lastPathComponent.withCString({ unlinkat(parent, $0, 0) }) == 0,
                  Darwin.fsync(parent) == 0,
                  Self.identity(descriptor: parent).map({
                    Self.sameDirectoryNode($0, parentBefore)
                  }) == true else {
                throw BackupError.unsafeStorage
            }
        }
    }

    private func removeTreeBestEffort(_ url: URL, budget: OperationBudget) throws {
        guard boundKind(url) != .missing else { return }
        try removeTree(url, expectedIdentity: nil, budget: budget)
    }

    private func removeTree(
        _ url: URL,
        expectedIdentity: FileIdentity? = nil,
        budget: OperationBudget
    ) throws {
        try budget.checkpoint()
        let parentURL = url.deletingLastPathComponent()
        guard Self.validComponent(url.lastPathComponent) else { throw BackupError.unsafeStorage }
        try withBoundDirectoryDescriptor(at: parentURL) { parent in
            guard let parentBefore = Self.identity(descriptor: parent) else {
                throw BackupError.unsafeStorage
            }
            var declared = stat()
            guard url.lastPathComponent.withCString({
                fstatat(parent, $0, &declared, AT_SYMLINK_NOFOLLOW)
            }) == 0 else {
                if errno == ENOENT { return }
                throw BackupError.unsafeStorage
            }
            let identity = Self.identity(declared)
            guard Self.securePrivateDirectory(identity) else {
                throw BackupError.unsafeStorage
            }
            if let expectedIdentity,
               !Self.sameDirectoryNode(expectedIdentity, identity) {
                throw BackupError.unsafeStorage
            }
            let descriptor = url.lastPathComponent.withCString {
                openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            }
            guard descriptor >= 0,
                  Self.identity(descriptor: descriptor) == identity,
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
                if descriptor >= 0 { _ = Darwin.close(descriptor) }
                throw BackupError.unsafeStorage
            }
            do {
                try removeDirectoryContents(
                    descriptor: descriptor,
                    relativePath: url.lastPathComponent,
                    depth: 0,
                    budget: budget
                )
                guard Darwin.fsync(descriptor) == 0 else { throw BackupError.unsafeStorage }
                _ = Darwin.close(descriptor)
            } catch {
                _ = Darwin.close(descriptor)
                throw error
            }
            var rebound = stat()
            guard url.lastPathComponent.withCString({
                fstatat(parent, $0, &rebound, AT_SYMLINK_NOFOLLOW)
            }) == 0,
                Self.sameDirectoryNode(Self.identity(rebound), identity),
                url.lastPathComponent.withCString({ unlinkat(parent, $0, AT_REMOVEDIR) }) == 0,
                Darwin.fsync(parent) == 0,
                Self.identity(descriptor: parent).map({
                    Self.sameDirectoryNode($0, parentBefore)
                }) == true else {
                throw BackupError.unsafeStorage
            }
        }
    }

    private func removeDirectoryContents(
        descriptor: Int32,
        relativePath: String,
        depth: Int,
        budget: OperationBudget
    ) throws {
        let iteration = Darwin.dup(descriptor)
        guard iteration >= 0, let stream = fdopendir(iteration) else {
            if iteration >= 0 { Darwin.close(iteration) }
            throw BackupError.unsafeStorage
        }
        defer { closedir(stream) }
        while true {
            try budget.checkpoint()
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw BackupError.unsafeStorage }
                break
            }
            guard let name = Self.directoryEntryName(entry) else { throw BackupError.unsafeStorage }
            if name == "." || name == ".." { continue }
            let childRelative = Self.join(relativePath, name)
            try budget.consumeEntry(relativePath: childRelative, depth: depth + 1)
            var metadata = stat()
            guard fstatat(descriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw BackupError.unsafeStorage
            }
            let identity = Self.identity(metadata)
            switch Self.kind(mode: identity.mode) {
            case .directory:
                guard Self.securePrivateDirectory(identity) else { throw BackupError.unsafeStorage }
                let child = Darwin.openat(
                    descriptor,
                    name,
                    O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                )
                guard child >= 0,
                      Self.identity(descriptor: child).map({ Self.sameDirectoryNode($0, identity) }) == true else {
                    if child >= 0 { Darwin.close(child) }
                    throw BackupError.unsafeStorage
                }
                do {
                    try removeDirectoryContents(
                        descriptor: child,
                        relativePath: childRelative,
                        depth: depth + 1,
                        budget: budget
                    )
                    guard Darwin.fsync(child) == 0 else { throw BackupError.unsafeStorage }
                    Darwin.close(child)
                } catch {
                    Darwin.close(child)
                    throw error
                }
                var rebound = stat()
                guard fstatat(descriptor, name, &rebound, AT_SYMLINK_NOFOLLOW) == 0,
                      Self.sameDirectoryNode(Self.identity(rebound), identity),
                      unlinkat(descriptor, name, AT_REMOVEDIR) == 0 else {
                    throw BackupError.unsafeStorage
                }
            case .regular:
                guard identity.owner == geteuid(),
                      identity.linkCount == 1,
                      identity.mode & 0o077 == 0 else {
                    throw BackupError.unsafeStorage
                }
                try budget.consumeBytes(identity.byteCount)
                guard unlinkat(descriptor, name, 0) == 0 else { throw BackupError.unsafeStorage }
            case .symbolicLink, .other, .missing:
                throw BackupError.unsafeStorage
            }
        }
        guard Darwin.fsync(descriptor) == 0 else { throw BackupError.unsafeStorage }
    }

    private func withLock<T>(_ operation: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        precondition(
            activeHome == nil && activeBackupRoot == nil
                && activeRecoveryRoot == nil && activeReplacementHome == nil
                && activeSourceParent == nil && activeEphemeralDirectories.isEmpty
        )

        func run(
            _ borrowedHome: Int32?,
            _ record: HarnessHomeAttestationRecord?,
            _ ownsHome: Bool
        ) throws -> T {
            self.activeHome = try self.makeHomeOperationCapability(
                borrowedDescriptor: borrowedHome,
                attestationRecord: record,
                ownsHomeDescriptor: ownsHome
            )
            defer {
                self.activeEphemeralDirectories.removeAll()
                self.activeReplacementHome = nil
                self.activeRecoveryRoot = nil
                self.activeBackupRoot = nil
                self.activeHome = nil
                self.activeSourceParent = nil
            }
            do {
                let value = try operation()
                try self.revalidateActiveCapabilities()
                return value
            } catch {
                let original = error
                do {
                    try self.revalidateActiveCapabilities()
                } catch {
                    throw error
                }
                throw original
            }
        }

        if let capability = harnessHomeCapabilityProvider() {
            return try capability.withBorrowedDescriptor { descriptor in
                try run(descriptor, capability.record, false)
            }
        }
        guard allowUnattestedHarnessHomeForTesting else {
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        return try run(nil, nil, true)
    }

    private func makeHomeOperationCapability(
        borrowedDescriptor: Int32?,
        attestationRecord: HarnessHomeAttestationRecord?,
        ownsHomeDescriptor: Bool
    ) throws -> HarnessHomeOperationCapability? {
        let parentURL = sourceState.deletingLastPathComponent().standardizedFileURL
        let parent = Darwin.open(
            parentURL.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard parent >= 0,
              let parentIdentity = Self.identity(descriptor: parent),
              Self.kind(mode: parentIdentity.mode) == .directory,
              parentIdentity.owner == geteuid(),
              parentIdentity.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parent) else {
            if parent >= 0 { _ = Darwin.close(parent) }
            throw BackupError.unsafeSource
        }

        var installed = stat()
        let leaf = sourceState.lastPathComponent
        let installedStatus = leaf.withCString {
            fstatat(parent, $0, &installed, AT_SYMLINK_NOFOLLOW)
        }
        if installedStatus != 0 {
            let saved = errno
            guard saved == ENOENT, borrowedDescriptor == nil else {
                _ = Darwin.close(parent)
                throw BackupError.unsafeSource
            }
            activeSourceParent = try makeRetainedDirectoryCapability(
                url: parentURL,
                alreadyOpenDescriptor: parent,
                identity: parentIdentity
            )
            return nil
        }
        guard Self.kind(mode: installed.st_mode) == .directory else {
            _ = Darwin.close(parent)
            if Self.kind(mode: installed.st_mode) == .symbolicLink {
                throw BackupError.unsafeSymbolicLink(relativePath: leaf)
            }
            throw BackupError.unsafeSource
        }

        let home: Int32
        if let borrowedDescriptor {
            home = borrowedDescriptor
        } else {
            home = leaf.withCString {
                openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            }
        }
        guard home >= 0,
              let homeIdentity = Self.identity(descriptor: home),
              homeIdentity == Self.identity(installed),
              Self.secureSourceDirectory(homeIdentity),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home) else {
            if borrowedDescriptor == nil, home >= 0 { _ = Darwin.close(home) }
            _ = Darwin.close(parent)
            throw BackupError.unsafeSource
        }

        let receipt = Self.harnessHomeReceiptName.withCString {
            openat(home, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard receipt >= 0,
              let receiptIdentity = Self.identity(descriptor: receipt),
              Self.kind(mode: receiptIdentity.mode) == .regular,
              receiptIdentity.owner == geteuid(),
              receiptIdentity.linkCount == 1,
              receiptIdentity.mode & 0o077 == 0,
              receiptIdentity.mode & (S_ISUID | S_ISGID) == 0,
              receiptIdentity.byteCount >= 0,
              receiptIdentity.byteCount <= Int64(Self.maximumHarnessHomeReceiptBytes),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(receipt) else {
            if receipt >= 0 { _ = Darwin.close(receipt) }
            if borrowedDescriptor == nil { _ = Darwin.close(home) }
            _ = Darwin.close(parent)
            throw BackupError.providerHistoryPrivacyMigrationRequired
        }
        do {
            let bytes = try Self.readExactDescriptor(
                receipt,
                byteCount: receiptIdentity.byteCount,
                maximumBytes: Self.maximumHarnessHomeReceiptBytes,
                monotonicNow: monotonicNow,
                duration: limits.operationDuration
            )
            guard Self.identity(descriptor: receipt) == receiptIdentity else {
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
            if let record = attestationRecord {
                guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                      currentHarnessHomeReceipt(object),
                      record.canonicalPath == sourceState.standardizedFileURL.path,
                      record.leafName == leaf,
                      record.device == homeIdentity.device,
                      record.inode == homeIdentity.inode,
                      record.owner == homeIdentity.owner,
                      record.mode == UInt16(homeIdentity.mode & 0o7777),
                      record.privacyEpoch == UInt64(ProviderHistoryPrivacyEpoch.current),
                      record.receiptSHA256 == Self.sha256(bytes) else {
                    throw BackupError.providerHistoryPrivacyMigrationRequired
                }
            } else if !allowUnattestedHarnessHomeForTesting {
                throw BackupError.providerHistoryPrivacyMigrationRequired
            }
            return HarnessHomeOperationCapability(
                url: sourceState,
                parentDescriptor: parent,
                descriptor: home,
                parentIdentity: parentIdentity,
                identity: homeIdentity,
                receiptDescriptor: receipt,
                receiptIdentity: receiptIdentity,
                receiptBytes: bytes,
                attestationRecord: attestationRecord,
                ownsHomeDescriptor: borrowedDescriptor == nil
            )
        } catch {
            _ = Darwin.close(receipt)
            if borrowedDescriptor == nil { _ = Darwin.close(home) }
            _ = Darwin.close(parent)
            throw error
        }
    }

    private func revalidateActiveCapabilities() throws {
        if let home = activeHome {
            var installedReceipt = stat()
            guard Self.identity(descriptor: home.parentDescriptor).map({
                    Self.sameDirectoryNode($0, home.parentIdentity)
                        && $0.owner == home.parentIdentity.owner
                        && ($0.mode & 0o7777) == (home.parentIdentity.mode & 0o7777)
                  }) == true,
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.parentDescriptor),
                  Self.identity(descriptor: home.descriptor) == home.identity,
                  Self.identity(descriptor: home.receiptDescriptor) == home.receiptIdentity,
                  Self.harnessHomeReceiptName.withCString({
                    fstatat(home.descriptor, $0, &installedReceipt, AT_SYMLINK_NOFOLLOW)
                  }) == 0,
                  Self.identity(installedReceipt) == home.receiptIdentity,
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.descriptor),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.receiptDescriptor),
                  try Self.readExactDescriptor(
                    home.receiptDescriptor,
                    byteCount: home.receiptIdentity.byteCount,
                    maximumBytes: Self.maximumHarnessHomeReceiptBytes,
                    monotonicNow: monotonicNow,
                    duration: limits.operationDuration
                  ) == home.receiptBytes else {
                throw BackupError.sourceChanged(relativePath: Self.harnessHomeReceiptName)
            }
            if home.installedAtOriginalLeaf {
                var installed = stat()
                guard home.leafName.withCString({
                    fstatat(home.parentDescriptor, $0, &installed, AT_SYMLINK_NOFOLLOW)
                }) == 0,
                    Self.identity(installed) == home.identity else {
                    throw BackupError.sourceChanged(relativePath: "")
                }
            }
            if let record = home.attestationRecord {
                guard record.receiptSHA256 == Self.sha256(home.receiptBytes),
                      record.device == home.identity.device,
                      record.inode == home.identity.inode,
                      record.owner == home.identity.owner,
                      record.mode == UInt16(home.identity.mode & 0o7777) else {
                    throw BackupError.providerHistoryPrivacyMigrationRequired
                }
            }
        }
        try revalidateDirectoryCapability(activeBackupRoot)
        try revalidateDirectoryCapability(activeRecoveryRoot)
        try revalidateDirectoryCapability(activeReplacementHome)
        try revalidateDirectoryCapability(activeSourceParent)
        for capability in activeEphemeralDirectories {
            try revalidateDirectoryCapability(capability)
        }
    }

    private func revalidateDirectoryCapability(_ capability: DirectoryCapability?) throws {
        guard let capability else { return }
        var installed = stat()
        guard Self.identity(descriptor: capability.parentDescriptor).map({
                Self.sameDirectoryNode($0, capability.parentIdentity)
                    && $0.owner == capability.parentIdentity.owner
                    && ($0.mode & 0o7777) == (capability.parentIdentity.mode & 0o7777)
              }) == true,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(capability.parentDescriptor),
              Self.identity(descriptor: capability.descriptor).map({
                Self.sameDirectoryNode($0, capability.identity)
                    && $0.owner == capability.identity.owner
                    && ($0.mode & 0o7777) == (capability.identity.mode & 0o7777)
              }) == true,
              capability.leafName.withCString({
                fstatat(capability.parentDescriptor, $0, &installed, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              Self.sameDirectoryNode(Self.identity(installed), capability.identity),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(capability.descriptor) else {
            throw BackupError.unsafeStorage
        }
        if let marker = capability.marker {
            guard marker.state == .current,
                  marker.canonicalPath == capability.url.path,
                  marker.device == capability.identity.device,
                  marker.inode == capability.identity.inode,
                  marker.owner == capability.identity.owner,
                  marker.mode == UInt16(capability.identity.mode & 0o7777),
                  marker.privacyEpoch == UInt64(ProviderHistoryPrivacyEpoch.current) else {
                throw BackupError.unsafeStorage
            }
        }
    }

    private static func readExactDescriptor(
        _ descriptor: Int32,
        byteCount: Int64,
        maximumBytes: Int,
        monotonicNow: @escaping @Sendable () -> UInt64,
        duration: TimeInterval
    ) throws -> Data {
        guard byteCount >= 0, byteCount <= Int64(maximumBytes), duration.isFinite, duration > 0 else {
            throw BackupError.backupLimitExceeded
        }
        let now = monotonicNow()
        let nanos = UInt64(min(duration, Double(UInt64.max) / 1_000_000_000) * 1_000_000_000)
        let addition = now.addingReportingOverflow(nanos)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        var result = Data()
        result.reserveCapacity(Int(byteCount))
        var offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 8 * 1_024)
        while offset < byteCount {
            guard monotonicNow() <= deadline else { throw BackupError.deadlineExceeded }
            let desired = min(buffer.count, Int(byteCount - offset))
            let count = buffer.withUnsafeMutableBytes {
                pread(descriptor, $0.baseAddress, desired, off_t(offset))
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw BackupError.unsafeSource
            }
            guard count > 0 else { throw BackupError.sourceChanged(relativePath: "") }
            result.append(contentsOf: buffer.prefix(count))
            offset += Int64(count)
        }
        var extra: UInt8 = 0
        guard pread(descriptor, &extra, 1, off_t(offset)) == 0 else {
            throw BackupError.sourceChanged(relativePath: "")
        }
        return result
    }

    private func boundDirectoryBases() -> [(URL, Int32)] {
        var result: [(URL, Int32)] = activeEphemeralDirectories.reversed().map {
            ($0.url, $0.descriptor)
        }
        if let replacement = activeReplacementHome {
            result.append((replacement.url, replacement.descriptor))
            result.append((replacement.parentURL, replacement.parentDescriptor))
        }
        if let recovery = activeRecoveryRoot {
            result.append((recovery.url, recovery.descriptor))
            result.append((recovery.parentURL, recovery.parentDescriptor))
        }
        if let backup = activeBackupRoot {
            result.append((backup.url, backup.descriptor))
            result.append((backup.parentURL, backup.parentDescriptor))
        }
        if let home = activeHome {
            result.append((home.url, home.descriptor))
            result.append((home.parentURL, home.parentDescriptor))
        }
        if let sourceParent = activeSourceParent {
            result.append((sourceParent.url, sourceParent.descriptor))
        }
        return result
    }

    private func makeRetainedDirectoryCapability(
        url: URL,
        alreadyOpenDescriptor descriptor: Int32,
        identity: FileIdentity
    ) throws -> DirectoryCapability {
        let parentURL = url.deletingLastPathComponent().standardizedFileURL
        let parent = Darwin.open(
            parentURL.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard parent >= 0,
              let parentIdentity = Self.identity(descriptor: parent),
              Self.kind(mode: parentIdentity.mode) == .directory,
              parentIdentity.owner == geteuid(),
              parentIdentity.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parent) else {
            if parent >= 0 { _ = Darwin.close(parent) }
            _ = Darwin.close(descriptor)
            throw BackupError.unsafeSource
        }
        var installed = stat()
        guard url.lastPathComponent.withCString({
            fstatat(parent, $0, &installed, AT_SYMLINK_NOFOLLOW)
        }) == 0,
            Self.identity(installed) == identity else {
            _ = Darwin.close(parent)
            _ = Darwin.close(descriptor)
            throw BackupError.unsafeSource
        }
        return DirectoryCapability(
            url: url,
            parentDescriptor: parent,
            descriptor: descriptor,
            parentIdentity: parentIdentity,
            identity: identity,
            marker: nil
        )
    }

    private func withBoundDirectoryDescriptor<T>(
        at directory: URL,
        failure: BackupError = .unsafeStorage,
        _ body: (Int32) throws -> T
    ) throws -> T {
        let target = directory.standardizedFileURL
        let candidates = boundDirectoryBases().filter {
            target.path == $0.0.path || Self.isDescendant(target, of: $0.0)
        }
        guard var base = candidates.first else {
            throw failure
        }
        // Equal-length aliases are possible while HarnessHome is being
        // replaced. Preserve capability priority (ephemeral/replacement
        // before the displaced home) rather than letting `max` pick a later
        // descriptor for the same pathname.
        for candidate in candidates.dropFirst()
        where candidate.0.path.utf8.count > base.0.path.utf8.count {
            base = candidate
        }
        let suffix: String
        if target.path == base.0.path {
            suffix = ""
        } else {
            suffix = String(target.path.dropFirst(base.0.path.count + 1))
        }
        let components = suffix.isEmpty ? [] : suffix.split(separator: "/").map(String.init)
        guard components.allSatisfy(Self.validComponent) else { throw failure }
        var opened: [Int32] = []
        var current = base.1
        defer { for descriptor in opened.reversed() { _ = Darwin.close(descriptor) } }
        for component in components {
            let next = component.withCString {
                openat(current, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            }
            guard next >= 0,
                  let identity = Self.identity(descriptor: next),
                  Self.kind(mode: identity.mode) == .directory,
                  identity.owner == geteuid(),
                  identity.mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(next) else {
                if next >= 0 { _ = Darwin.close(next) }
                throw failure
            }
            opened.append(next)
            current = next
        }
        return try body(current)
    }

    private func withBoundParentDescriptor<T>(
        of url: URL,
        failure: BackupError = .unsafeStorage,
        _ body: (Int32, String) throws -> T
    ) throws -> T {
        let normalized = url.standardizedFileURL
        guard Self.validComponent(normalized.lastPathComponent) else { throw failure }
        return try withBoundDirectoryDescriptor(
            at: normalized.deletingLastPathComponent(),
            failure: failure
        ) { parent in
            try body(parent, normalized.lastPathComponent)
        }
    }

    private func boundIdentity(_ url: URL) -> FileIdentity? {
        try? withBoundParentDescriptor(of: url) { parent, leaf in
            var metadata = stat()
            guard leaf.withCString({
                fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }) == 0 else { return nil }
            return Self.identity(metadata)
        }
    }

    private func boundKind(_ url: URL) -> FilesystemKind {
        guard let identity = boundIdentity(url) else { return .missing }
        return Self.kind(mode: identity.mode)
    }

    private func ensurePrivateDirectoryBound(_ url: URL) throws {
        try withBoundParentDescriptor(of: url) { parent, leaf in
            var metadata = stat()
            if leaf.withCString({
                fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }) != 0 {
                guard errno == ENOENT,
                      leaf.withCString({ mkdirat(parent, $0, mode_t(0o700)) }) == 0,
                      fsync(parent) == 0 else {
                    throw BackupError.unsafeStorage
                }
            } else if Self.kind(mode: metadata.st_mode) != .directory {
                throw BackupError.unsafeStorage
            }
            let descriptor = leaf.withCString {
                openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            }
            guard descriptor >= 0 else { throw BackupError.unsafeStorage }
            defer { _ = Darwin.close(descriptor) }
            guard fchmod(descriptor, mode_t(0o700)) == 0,
                  let identity = Self.identity(descriptor: descriptor),
                  Self.securePrivateDirectory(identity),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
                  fsync(descriptor) == 0,
                  fsync(parent) == 0 else {
                throw BackupError.unsafeStorage
            }
        }
        try retainEphemeralDirectory(at: url)
    }

    private func retainEphemeralDirectory(at url: URL) throws {
        let target = url.standardizedFileURL
        if activeEphemeralDirectories.contains(where: { $0.url == target }) { return }
        if activeBackupRoot?.url == target || activeRecoveryRoot?.url == target
            || activeReplacementHome?.url == target || activeHome?.url == target {
            return
        }
        let capability = try withBoundParentDescriptor(of: target) { parent, leaf in
            let retainedParent = fcntl(parent, F_DUPFD_CLOEXEC, 0)
            guard retainedParent >= 0,
                  let parentIdentity = Self.identity(descriptor: retainedParent) else {
                if retainedParent >= 0 { _ = Darwin.close(retainedParent) }
                throw BackupError.unsafeStorage
            }
            let descriptor = leaf.withCString {
                openat(
                    retainedParent,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                )
            }
            guard descriptor >= 0,
                  let identity = Self.identity(descriptor: descriptor),
                  Self.securePrivateDirectory(identity),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
                if descriptor >= 0 { _ = Darwin.close(descriptor) }
                _ = Darwin.close(retainedParent)
                throw BackupError.unsafeStorage
            }
            return DirectoryCapability(
                url: target,
                parentDescriptor: retainedParent,
                descriptor: descriptor,
                parentIdentity: parentIdentity,
                identity: identity,
                marker: nil
            )
        }
        activeEphemeralDirectories.append(capability)
    }

    private func remapEphemeralDirectories(from source: URL, to destination: URL) {
        let source = source.standardizedFileURL
        let destination = destination.standardizedFileURL
        for capability in activeEphemeralDirectories {
            let oldURL = capability.url
            guard oldURL == source || Self.isDescendant(oldURL, of: source) else { continue }
            let suffix = oldURL.path == source.path
                ? ""
                : String(oldURL.path.dropFirst(source.path.count + 1))
            capability.url = suffix.isEmpty
                ? destination
                : destination.appendingPathComponent(suffix)
            capability.parentURL = capability.url.deletingLastPathComponent().standardizedFileURL
            capability.leafName = capability.url.lastPathComponent
        }
    }

    private func releaseEphemeralDirectory(at url: URL, includingDescendants: Bool = true) {
        let target = url.standardizedFileURL
        activeEphemeralDirectories.removeAll {
            $0.url == target || (includingDescendants && Self.isDescendant($0.url, of: target))
        }
    }

    private static func backup(from manifest: ManifestPayload, root: URL) -> StateBackup {
        StateBackup(
            id: manifest.id,
            createdAt: manifest.createdAt,
            label: manifest.label,
            sourceVersion: manifest.sourceVersion,
            path: payloadURL(for: manifest.id, root: root).path
        )
    }

    private static func containerURL(for id: UUID, root: URL) -> URL {
        root.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    private static func payloadURL(for id: UUID, root: URL) -> URL {
        containerURL(for: id, root: root).appendingPathComponent(payloadName, isDirectory: true)
    }

    private static func normalizedLabel(_ value: String) -> String {
        let cleaned = value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.map(String.init).joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return utf8Prefix(cleaned.isEmpty ? "Backup" : cleaned, maximumBytes: 256)
    }

    private static func normalizedVersion(_ value: String) -> String {
        let cleaned = value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.map(String.init).joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return utf8Prefix(cleaned.isEmpty ? "Unknown" : cleaned, maximumBytes: 128)
    }

    private static func utf8Prefix(_ value: String, maximumBytes: Int) -> String {
        var result = ""
        result.reserveCapacity(min(value.count, maximumBytes))
        var byteCount = 0
        for character in value {
            let width = String(character).utf8.count
            guard byteCount + width <= maximumBytes else { break }
            result.append(character)
            byteCount += width
        }
        return result
    }

    static func isReservedHarnessHomeReceiptName(_ name: String) -> Bool {
        name.lowercased() == Self.harnessHomeReceiptName
    }

    static func isSecretBearingFile(_ name: String) -> Bool {
        let lower = name.lowercased()
        if lower == ".credentials.yaml" || lower == ".credentials.yml" || lower == ".env" || lower.hasPrefix(".env.") { return true }
        if lower == ".netrc" || lower == ".npmrc" || lower == ".pypirc" || lower == ".ssh" || lower == ".gnupg" { return true }
        if lower.contains("credential") || lower.contains("private-key") || lower.contains("private_key") ||
            lower.contains("api-key") || lower.contains("api_key") || lower.contains("auth-token") ||
            lower.contains("auth_token") || lower.contains("access-token") || lower.contains("access_token") ||
            lower.contains("refresh-token") || lower.contains("refresh_token") { return true }
        return [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"].contains { lower.hasSuffix($0) }
    }

    private static func privatePermissions(for mode: mode_t, directory: Bool) -> Int {
        if directory { return 0o700 }
        let owner = Int(mode & 0o700)
        return owner | 0o600
    }

    private static func identity(_ url: URL) -> FileIdentity? {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { return nil }
        return identity(value)
    }

    private static func identity(descriptor: Int32) -> FileIdentity? {
        var value = stat()
        guard fstat(descriptor, &value) == 0 else { return nil }
        return identity(value)
    }

    private static func identity(_ value: stat) -> FileIdentity {
        FileIdentity(
            device: UInt64(truncatingIfNeeded: value.st_dev),
            inode: UInt64(value.st_ino),
            owner: value.st_uid,
            byteCount: Int64(value.st_size),
            modificationSeconds: Int64(value.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(value.st_mtimespec.tv_nsec),
            linkCount: UInt64(value.st_nlink),
            mode: value.st_mode
        )
    }

    private static func kind(_ url: URL) -> FilesystemKind {
        guard let identity = identity(url) else { return .missing }
        return kind(mode: identity.mode)
    }

    private static func kind(mode: mode_t) -> FilesystemKind {
        switch mode & S_IFMT {
        case S_IFREG: return .regular
        case S_IFDIR: return .directory
        case S_IFLNK: return .symbolicLink
        default: return .other
        }
    }

    private static func securePrivateDirectory(_ identity: FileIdentity) -> Bool {
        kind(mode: identity.mode) == .directory &&
            identity.owner == geteuid() &&
            identity.mode & 0o077 == 0
    }

    private static func secureSourceDirectory(_ identity: FileIdentity) -> Bool {
        kind(mode: identity.mode) == .directory &&
            identity.owner == geteuid() &&
            identity.mode & 0o022 == 0
    }

    /// Directory size, mtime, and link count legitimately change while a
    /// durable deletion is in progress. Device/inode/owner/type/permissions
    /// remain the namespace identity that a relaunch must bind to.
    private static func sameDirectoryNode(_ lhs: FileIdentity, _ rhs: FileIdentity) -> Bool {
        lhs.device == rhs.device &&
            lhs.inode == rhs.inode &&
            lhs.owner == rhs.owner &&
            kind(mode: lhs.mode) == .directory &&
            kind(mode: rhs.mode) == .directory &&
            (lhs.mode & 0o7777) == (rhs.mode & 0o7777)
    }

    private static func sameRegularNode(_ lhs: FileIdentity, _ rhs: FileIdentity) -> Bool {
        lhs.device == rhs.device && lhs.inode == rhs.inode && lhs.owner == rhs.owner
            && kind(mode: lhs.mode) == .regular && kind(mode: rhs.mode) == .regular
            && lhs.linkCount == rhs.linkCount
            && (lhs.mode & 0o7777) == (rhs.mode & 0o7777)
    }

    private static func validComponent(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." &&
            !value.contains("/") && !value.contains("\0") &&
            !value.unicodeScalars.contains {
                CharacterSet.controlCharacters.contains($0) || $0.properties.generalCategory == .format
            } &&
            value.utf8.count <= Int(MAXNAMLEN)
    }

    private static func directoryEntryName(_ entry: UnsafeMutablePointer<dirent>) -> String? {
        guard let name = DarwinDirectoryEntry.name(entry),
              validComponent(name) || name == "." || name == ".." else {
            return nil
        }
        return name
    }

    private static func valid(limits: StateBackupLimits) -> Bool {
        limits.maximumManifestBytes > 0 &&
            limits.maximumManifestBytes <= 64 * 1_024 * 1_024 &&
            limits.maximumEntryCount > 0 &&
            limits.maximumOperationEntries >= limits.maximumEntryCount &&
            limits.maximumOperationEntries <= 1_000_000 &&
            limits.maximumDirectoryDepth > 0 && limits.maximumDirectoryDepth <= 256 &&
            limits.maximumRelativePathBytes > 0 && limits.maximumRelativePathBytes <= 4_096 &&
            limits.maximumFileBytes > 0 &&
            limits.maximumBackupBytes >= limits.maximumFileBytes &&
            limits.maximumOperationBytes >= limits.maximumBackupBytes &&
            limits.maximumBackupCount > 0 && limits.maximumBackupCount <= 1_024 &&
            limits.maximumCatalogEntries >= limits.maximumBackupCount &&
            limits.maximumCatalogEntries <= 4_096 &&
            limits.maximumAggregateStoredBytes >= limits.maximumBackupBytes &&
            limits.operationDuration > 0 && limits.operationDuration <= 300 &&
            limits.operationDuration.isFinite
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isDescendant(_ candidate: URL, of root: URL) -> Bool {
        let parent = root.standardizedFileURL.path
        let path = candidate.standardizedFileURL.path
        return path.hasPrefix(parent + "/")
    }

    private static func isValidRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.contains("\0"),
              !path.unicodeScalars.contains(where: {
                  CharacterSet.controlCharacters.contains($0) || $0.properties.generalCategory == .format
              }),
              path.utf8.count <= 4_096 else { return false }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        return !components.isEmpty && components.allSatisfy { component in
            !component.isEmpty && component != "." && component != ".." && component.utf8.count <= 255
        }
    }

    private static func join(_ prefix: String, _ name: String) -> String {
        prefix.isEmpty ? name : "\(prefix)/\(name)"
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    private static func writeAll(
        _ data: Data,
        descriptor: Int32,
        budget: OperationBudget
    ) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                try budget.checkpoint()
                let written = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw BackupError.unsafeStorage
                }
                guard written > 0 else { throw BackupError.unsafeStorage }
                offset += written
            }
        }
    }

    private static func exactEnvelopePayload(
        _ data: Data,
        keys: Set<String>
    ) -> [String: Any]? {
        guard let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(envelope.keys) == ["payload", "authenticationTag"],
              envelope["authenticationTag"] is String,
              let payload = envelope["payload"] as? [String: Any],
              Set(payload.keys) == keys else {
            return nil
        }
        return payload
    }

    private static func hasExactStateBackupSchema(_ object: Any) -> Bool {
        guard let backup = object as? [String: Any] else { return false }
        return Set(backup.keys) == ["id", "createdAt", "label", "sourceVersion", "path"]
    }

    private static func hasExactFileIdentitySchema(_ object: Any) -> Bool {
        guard let identity = object as? [String: Any] else { return false }
        return Set(identity.keys) == [
            "device", "inode", "owner", "byteCount", "modificationSeconds",
            "modificationNanoseconds", "linkCount", "mode"
        ]
    }

    private static func hasExactManifestSchema(_ data: Data) -> Bool {
        guard let payload = exactEnvelopePayload(data, keys: [
            "formatVersion", "providerHistoryPrivacyEpoch", "id", "createdAt", "label",
            "sourceVersion", "sourceCanonicalPath", "entries", "totalBytes"
        ]), let entries = payload["entries"] as? [Any] else {
            return false
        }
        return entries.allSatisfy { value in
            guard let entry = value as? [String: Any],
                  let kind = entry["kind"] as? String else {
                return false
            }
            let common: Set<String> = [
                "relativePath", "kind", "byteCount", "posixPermissions"
            ]
            switch kind {
            case NodeKind.directory.rawValue:
                return Set(entry.keys) == common
            case NodeKind.regular.rawValue:
                return Set(entry.keys) == common.union(["contentSHA256"])
            default:
                return false
            }
        }
    }

    private static func hasExactCatalogSchema(_ data: Data) -> Bool {
        guard let payload = exactEnvelopePayload(data, keys: [
            "formatVersion", "providerHistoryPrivacyEpoch", "backups"
        ]), let backups = payload["backups"] as? [Any] else {
            return false
        }
        return backups.allSatisfy { hasExactStateBackupSchema($0) }
    }

    private static func hasExactBackupReceiptSchema(_ data: Data) -> Bool {
        guard let payload = exactEnvelopePayload(data, keys: [
            "formatVersion", "providerHistoryPrivacyEpoch", "operationID", "backup",
            "manifestSHA256"
        ]) else {
            return false
        }
        return payload["backup"].map { hasExactStateBackupSchema($0) } == true
    }

    private static func hasExactBackupTransactionSchema(_ data: Data) -> Bool {
        guard let payload = exactEnvelopePayload(data, keys: [
            "formatVersion", "providerHistoryPrivacyEpoch", "operationID", "kind", "phase",
            "backup", "stagingName", "publishedName", "namespaceIdentity", "targetCatalog",
            "evictedBackupIDs", "evictedNamespaceIdentities"
        ]), payload["backup"].map({ hasExactStateBackupSchema($0) }) == true,
        payload["namespaceIdentity"].map({ hasExactFileIdentitySchema($0) }) == true,
        let catalog = payload["targetCatalog"] as? [Any],
        catalog.allSatisfy({ hasExactStateBackupSchema($0) }),
        let evicted = payload["evictedNamespaceIdentities"] as? [String: Any],
        evicted.values.allSatisfy({ hasExactFileIdentitySchema($0) }) else {
            return false
        }
        return true
    }

    private static func hasExactRestoreTransactionSchema(_ data: Data) -> Bool {
        let required: Set<String> = [
            "formatVersion", "providerHistoryPrivacyEpoch", "operationID", "backupID", "phase",
            "stagedName", "quarantineName", "sourceName", "stagedIdentity"
        ]
        guard let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(envelope.keys) == ["payload", "authenticationTag"],
              envelope["authenticationTag"] is String,
              let payload = envelope["payload"] as? [String: Any],
              Set(payload.keys) == required || Set(payload.keys) == required.union(["sourceIdentity"]),
              payload["stagedIdentity"].map({ hasExactFileIdentitySchema($0) }) == true else {
            return false
        }
        if let source = payload["sourceIdentity"] {
            return hasExactFileIdentitySchema(source)
        }
        return true
    }

    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return try encoder.encode(value)
    }

    private static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(type, from: data)
    }
}

enum BackupError: LocalizedError {
    case invalidLimits
    case cancelled
    case deadlineExceeded
    case quiescenceRequired
    case transactionCorrupt
    case invalidBackup
    case protectedBackup
    case unsafeStorage
    case unsafeSource
    case unsafeSymbolicLink(relativePath: String)
    case unsupportedFilesystemItem(relativePath: String)
    case sourceChanged(relativePath: String)
    case backupLimitExceeded
    case authenticationUnavailable
    case authenticationAuthorizationRequired
    case authenticationTimedOut
    case providerHistoryPrivacyMigrationRequired
    case integrityCheckFailed
    case restoreFailed(underlying: String)
    case rollbackFailed(recoveryDirectory: String, stagedDirectory: String)

    var errorDescription: String? {
        switch self {
        case .invalidLimits:
            return "Backup safety limits are invalid, so no state was read or changed."
        case .cancelled:
            return "The backup operation was cancelled before it completed."
        case .deadlineExceeded:
            return "The backup operation exceeded its safety deadline and was stopped."
        case .quiescenceRequired:
            return "A protected backup or restore transition must stop local services before recovery can continue."
        case .transactionCorrupt:
            return "An interrupted backup or restore transaction could not be authenticated or safely reconciled."
        case .invalidBackup:
            return "The selected backup is missing, unauthenticated, or outside \(ProductBrand.displayName) storage."
        case .protectedBackup:
            return "This snapshot is the active Harness migration rollback point. It cannot be deleted or removed by retention until the migration is committed or restored."
        case .unsafeStorage:
            return "Backup storage is missing, linked, replaced, or has unsafe permissions."
        case .unsafeSource:
            return "Harness state is missing, linked, or is not a normal local directory."
        case .unsafeSymbolicLink:
            return "The snapshot was stopped because Harness state contains a symbolic link. \(ProductBrand.displayName) never follows links while backing up or restoring state."
        case .unsupportedFilesystemItem:
            return "The snapshot was stopped because Harness state contains an unsupported filesystem item."
        case .sourceChanged:
            return "Harness state changed while the snapshot was being copied. Stop local services and try again."
        case .backupLimitExceeded:
            return "Harness state exceeds the protected backup size or file-count limit."
        case .authenticationUnavailable:
            return "The device-only backup authentication key could not be accessed in macOS Keychain."
        case .authenticationAuthorizationRequired:
            return "macOS requires foreground authorization to read the existing device-only backup key. No key was replaced or deleted. Open Backups & Restore and choose Authorize Backup Key."
        case .authenticationTimedOut:
            return "The bounded backup-key operation did not finish in time. No existing Keychain item was replaced or deleted."
        case .providerHistoryPrivacyMigrationRequired:
            return "Historical provider state or a pre-privacy-epoch backup was found. Runtime startup and backup access remain stopped until the foreground privacy recovery is completed."
        case .integrityCheckFailed:
            return "The backup failed its authenticated manifest or file-content integrity check and was not restored."
        case .restoreFailed:
            return "The backup could not be restored. The previous Harness state was put back."
        case .rollbackFailed(let recoveryDirectory, let stagedDirectory):
            return "Restore and automatic rollback both failed. Recovery material was preserved at \(recoveryDirectory) and \(stagedDirectory). Keep \(ProductBrand.displayName) stopped and recover those folders manually."
        }
    }
}
