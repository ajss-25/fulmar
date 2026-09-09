import Darwin
import CoreFoundation
import Foundation
import LocalHarnessDeviceAttestation

/// Detection-only result for the two app-owned namespaces which can retain
/// provider-history-derived state outside the Harness home.
enum ProviderHistoryAuxiliaryPendingState: Equatable, Sendable {
    case initial(ProviderHistoryAuxiliaryRecoveryRequest)
    case namespacePublication(ProviderHistoryAuxiliaryNamespacePublicationRequest)
    case interrupted(ProviderHistoryAuxiliaryInterruptedRequest)
    case published(ProviderHistoryAuxiliaryRecoveryReceipt)
}

struct ProviderHistoryAuxiliaryNamespacePublicationRequest: Equatable, Sendable {
    let applicationSupport: URL
    let namespaceNames: [String]
    fileprivate let markers: [ProviderHistoryNamespaceMarker]
    fileprivate let applicationSupportIdentity: ProviderHistoryAuxiliaryPromptIdentity
}

struct ProviderHistoryAuxiliaryRecoveryRequest: Equatable, Sendable {
    let applicationSupport: URL
    let preservesBackups: Bool
    let preservesMigration: Bool
    fileprivate let applicationSupportIdentity: ProviderHistoryAuxiliaryPromptIdentity
    fileprivate let backupsIdentity: ProviderHistoryAuxiliaryPromptIdentity?
    fileprivate let stateRecoveryIdentity: ProviderHistoryAuxiliaryPromptIdentity?
    fileprivate let migrationIdentity: ProviderHistoryAuxiliaryPromptIdentity?
    fileprivate let migrationStagingIdentity: ProviderHistoryAuxiliaryPromptIdentity?
}

struct ProviderHistoryAuxiliaryInterruptedRequest: Equatable, Sendable {
    let applicationSupport: URL
    let recoveryDirectory: URL
    fileprivate let operationID: UUID
    fileprivate let applicationSupportIdentity: ProviderHistoryAuxiliaryPromptIdentity
    fileprivate let transactionIdentity: ProviderHistoryAuxiliaryPromptIdentity
}

struct ProviderHistoryAuxiliaryRecoveryReceipt: Equatable, Sendable {
    let recoveryDirectory: URL
    let preservedBackups: URL?
    let preservedStateRecovery: URL?
    let preservedMigration: URL?
    let preservedMigrationStaging: URL?
    fileprivate let operationID: UUID
    fileprivate let applicationSupportIdentity: ProviderHistoryAuxiliaryStableIdentity
    fileprivate let recoveryIdentity: ProviderHistoryAuxiliaryStableIdentity
    fileprivate let transactionIdentity: ProviderHistoryAuxiliaryStableIdentity
    fileprivate let publishedPhaseIdentity: ProviderHistoryAuxiliaryPromptIdentity
}

enum ProviderHistoryAuxiliaryRecoveryPhase: Int, CaseIterable, Sendable {
    case prepared = 0
    case recoveryDirectoryReady = 1
    case backupsPreserved = 2
    case migrationPreserved = 3
    case published = 4

    fileprivate var fileName: String {
        switch self {
        case .prepared: "phase-0-prepared.json"
        case .recoveryDirectoryReady: "phase-1-recovery-directory-ready.json"
        case .backupsPreserved: "phase-2-backups-preserved.json"
        case .migrationPreserved: "phase-3-migration-preserved.json"
        case .published: "phase-4-published.json"
        }
    }
}

enum ProviderHistoryAuxiliaryTestInterruption: Error, Equatable {
    case simulatedCrash(ProviderHistoryAuxiliaryRecoveryPhase)
}

enum ProviderHistoryAuxiliaryRecoveryError: LocalizedError, Equatable {
    case unsafeApplicationSupport
    case unsafeRecoveryStorage
    case historicalStateChanged
    case recoveryInProgress
    case malformedOrFutureJournal
    case recoveryLimitExceeded
    case noHistoricalState

    var errorDescription: String? {
        switch self {
        case .unsafeApplicationSupport:
            return "Fulmar could not pin its private Application Support directory. Provider work remained blocked."
        case .unsafeRecoveryStorage:
            return "The private provider-history recovery storage is linked, permissive, changed, or on a different volume. Provider work remained blocked."
        case .historicalStateChanged:
            return "Historical Backups or Migration state changed while Fulmar was waiting for confirmation. Nothing was overwritten or deleted."
        case .recoveryInProgress:
            return "Another Fulmar process is already preserving the exact historical Backups and Migration state."
        case .malformedOrFutureJournal:
            return "The provider-history auxiliary recovery journal is missing, malformed, changed, or from a future version. Every preserved item was retained and provider work remained blocked."
        case .recoveryLimitExceeded:
            return "Provider-history auxiliary recovery exceeded its bounded startup limit. Every preserved item was retained and provider work remained blocked."
        case .noHistoricalState:
            return "No historical Backups or Migration directory remained eligible for preservation."
        }
    }
}

private struct ProviderHistoryAuxiliaryStableIdentity: Codable, Equatable, Sendable {
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

private struct ProviderHistoryAuxiliaryPromptIdentity: Codable, Equatable, Sendable {
    let stable: ProviderHistoryAuxiliaryStableIdentity
    let linkCount: UInt64
    let byteCount: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
    let changeSeconds: Int64
    let changeNanoseconds: Int64

    init(_ value: stat) {
        stable = ProviderHistoryAuxiliaryStableIdentity(value)
        linkCount = UInt64(truncatingIfNeeded: value.st_nlink)
        byteCount = Int64(value.st_size)
        modificationSeconds = Int64(value.st_mtimespec.tv_sec)
        modificationNanoseconds = Int64(value.st_mtimespec.tv_nsec)
        changeSeconds = Int64(value.st_ctimespec.tv_sec)
        changeNanoseconds = Int64(value.st_ctimespec.tv_nsec)
    }
}

/// Crash-safe, credential-free preservation of the historical Backups and
/// Migration namespaces. Source children are never listed, opened, parsed, or
/// copied. The only data operation is a same-volume rename of each whole root.
///
/// The journal is an append-only directory of exact, versioned phase records.
/// A phase record is never replaced or deleted. On acknowledgement the whole
/// journal directory is itself renamed into the private recovery directory,
/// so even completed transaction evidence remains preserved.
final class ProviderHistoryAuxiliaryStateCoordinator: @unchecked Sendable {
    struct Limits: Equatable, Sendable {
        var maximumJournalBytes = 64 * 1_024
        var maximumTransactionEntries = 8
        var operationDuration: TimeInterval = 30

        static let production = Limits()

        fileprivate var isValid: Bool {
            maximumJournalBytes >= 1_024
                && maximumJournalBytes <= 1 * 1_024 * 1_024
                && maximumTransactionEntries >= 6
                && maximumTransactionEntries <= 64
                && operationDuration.isFinite
                && operationDuration > 0
                && operationDuration <= 120
        }
    }

    private struct NamespaceRecord: Codable, Equatable {
        let sourceName: String
        let destinationName: String
        let sourceIdentity: ProviderHistoryAuxiliaryPromptIdentity
    }

    private struct Journal: Codable, Equatable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        let operationID: UUID
        let phase: Int
        let applicationSupportIdentity: ProviderHistoryAuxiliaryStableIdentity
        let recoveryDirectoryName: String
        let recoveryDirectoryIdentity: ProviderHistoryAuxiliaryStableIdentity?
        let backups: NamespaceRecord?
        let stateRecovery: NamespaceRecord?
        let migration: NamespaceRecord?
        let migrationStaging: NamespaceRecord?

        private enum CodingKeys: String, CodingKey {
            case formatVersion
            case providerHistoryPrivacyEpoch
            case operationID
            case phase
            case applicationSupportIdentity
            case recoveryDirectoryName
            case recoveryDirectoryIdentity
            case backups
            case stateRecovery
            case migration
            case migrationStaging
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(formatVersion, forKey: .formatVersion)
            try container.encode(providerHistoryPrivacyEpoch, forKey: .providerHistoryPrivacyEpoch)
            try container.encode(operationID, forKey: .operationID)
            try container.encode(phase, forKey: .phase)
            try container.encode(applicationSupportIdentity, forKey: .applicationSupportIdentity)
            try container.encode(recoveryDirectoryName, forKey: .recoveryDirectoryName)
            if let recoveryDirectoryIdentity {
                try container.encode(recoveryDirectoryIdentity, forKey: .recoveryDirectoryIdentity)
            } else {
                try container.encodeNil(forKey: .recoveryDirectoryIdentity)
            }
            if let backups {
                try container.encode(backups, forKey: .backups)
            } else {
                try container.encodeNil(forKey: .backups)
            }
            if let stateRecovery {
                try container.encode(stateRecovery, forKey: .stateRecovery)
            } else {
                try container.encodeNil(forKey: .stateRecovery)
            }
            if let migration {
                try container.encode(migration, forKey: .migration)
            } else {
                try container.encodeNil(forKey: .migration)
            }
            if let migrationStaging {
                try container.encode(migrationStaging, forKey: .migrationStaging)
            } else {
                try container.encodeNil(forKey: .migrationStaging)
            }
        }
    }

    private struct RecoveryLease {
        let descriptor: Int32
        init(descriptor: Int32) { self.descriptor = descriptor }
        func release() {
            _ = flock(descriptor, LOCK_UN)
            Darwin.close(descriptor)
        }
    }

    private struct Deadline {
        let end: UInt64

        init(duration: TimeInterval) {
            let start = DispatchTime.now().uptimeNanoseconds
            let amount = UInt64(duration * 1_000_000_000)
            let (candidate, overflow) = start.addingReportingOverflow(amount)
            end = overflow ? UInt64.max : candidate
        }

        func check() throws {
            guard DispatchTime.now().uptimeNanoseconds <= end else {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryLimitExceeded
            }
        }
    }

    private static let formatVersion = 2
    private static let transactionName = ".provider-history-auxiliary-transaction"
    private static let lockName = ".lock"
    private static let recoveryName = "ProviderHistoryAuxiliaryRecovery"
    private static let backupsName = ProviderHistoryDeviceAttestation.backups.leafName
    private static let migrationName = ProviderHistoryDeviceAttestation.migration.leafName
    private static let migrationStagingName =
        ProviderHistoryDeviceAttestation.migrationStagingLeafName
    private static let stateRecoveryName = ProviderHistoryDeviceAttestation.stateRecovery.leafName
    private static let backupDestinationPrefix = "historical-backups-"
    private static let stateRecoveryDestinationPrefix = "historical-state-recovery-"
    private static let migrationDestinationPrefix = "historical-migration-"
    private static let migrationStagingDestinationPrefix =
        "historical-migration-staging-"
    private static let archivedTransactionPrefix = "transaction-"
    private static let journalDomain =
        "com.fulmar.device-attestation/v1/provider-history-auxiliary-journal"
    private let applicationSupport: URL
    private let limits: Limits
    private let makeUUID: @Sendable () -> UUID
    private let interruption: (@Sendable (ProviderHistoryAuxiliaryRecoveryPhase) -> Bool)?
    private let descriptorHook: (@Sendable (ProviderHistoryAuxiliaryRecoveryPhase) -> Void)?
    private let attestationConfiguration: DeviceAttestationAuthority.Configuration
    private let attestationKeyStore: any DeviceAttestationKeyStore
    private let lock = NSLock()

    init(
        applicationSupport: URL,
        limits: Limits = .production,
        makeUUID: @escaping @Sendable () -> UUID = { UUID() },
        interruption: (@Sendable (ProviderHistoryAuxiliaryRecoveryPhase) -> Bool)? = nil,
        descriptorHook: (@Sendable (ProviderHistoryAuxiliaryRecoveryPhase) -> Void)? = nil,
        attestationKeyStore: (any DeviceAttestationKeyStore)? = nil
    ) {
        self.applicationSupport = applicationSupport.standardizedFileURL
        self.limits = limits
        self.makeUUID = makeUUID
        self.interruption = interruption
        self.descriptorHook = descriptorHook
        attestationConfiguration = ProviderHistoryDeviceAttestation.configuration(
            applicationSupport: applicationSupport,
            operationDuration: min(5, limits.operationDuration)
        )
        self.attestationKeyStore = attestationKeyStore
            ?? ProviderHistoryDeviceAttestation.productionKeyStore()
    }

    /// Runs the signed transaction probe first, then performs three exact
    /// namespace-marker probes. It never enumerates or opens a child of Backups,
    /// restore recovery, or Migration. An existing root without its signed,
    /// live-inode-bound current marker is historical and is offered only for an
    /// explicit whole-directory foreground preserve.
    func preflight() throws -> ProviderHistoryAuxiliaryPendingState? {
        try withLock {
            guard limits.isValid else {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryLimitExceeded
            }
            let deadline = Deadline(duration: limits.operationDuration)
            var pathMetadata = stat()
            if Darwin.lstat(applicationSupport.path, &pathMetadata) != 0 {
                guard errno == ENOENT else {
                    throw ProviderHistoryAuxiliaryRecoveryError.unsafeApplicationSupport
                }
                return nil
            }
            let support = try openApplicationSupport()
            defer { Darwin.close(support.descriptor) }
            try deadline.check()
            if let transaction = try openDirectoryIfPresent(
                named: Self.transactionName,
                beneath: support.descriptor
            ) {
                defer { Darwin.close(transaction.descriptor) }
                let verifier = try backgroundJournalVerifier()
                let latest = try readJournal(
                    transaction: transaction.descriptor,
                    deadline: deadline,
                    verifier: verifier
                )
                if latest.phase == ProviderHistoryAuxiliaryRecoveryPhase.published.rawValue {
                    return .published(try receipt(
                        journal: latest,
                        support: support,
                        transaction: transaction
                    ))
                }
                return .interrupted(ProviderHistoryAuxiliaryInterruptedRequest(
                    applicationSupport: applicationSupport,
                    recoveryDirectory: applicationSupport.appendingPathComponent(
                        Self.recoveryName,
                        isDirectory: true
                    ),
                    operationID: latest.operationID,
                    applicationSupportIdentity: ProviderHistoryAuxiliaryPromptIdentity(support.metadata),
                    transactionIdentity: ProviderHistoryAuxiliaryPromptIdentity(transaction.metadata)
                ))
            }

            let specifications = ProviderHistoryDeviceAttestation.auxiliaryNamespaces
            let markerStates: [String: ProviderHistoryNamespaceBackgroundState]
            do {
                markerStates = try ProviderHistoryNamespaceMarkerStore.backgroundStates(
                    specifications.map { specification in
                        .init(
                            namespaceName: specification.name,
                            expectedURL: applicationSupport.appendingPathComponent(
                                specification.leafName,
                                isDirectory: true
                            ),
                            expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                            expectedReceipt: specification.publicationReceipt
                        )
                    },
                    configuration: attestationConfiguration,
                    keyStore: attestationKeyStore
                )
            } catch {
                throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
            }
            var historical: [String: ProviderHistoryAuxiliaryPromptIdentity] = [:]
            var pendingMarkers: [ProviderHistoryNamespaceMarker] = []
            for specification in specifications {
                try deadline.check()
                let identity = try secureSourceIdentityIfPresent(
                    named: specification.leafName,
                    support: support.descriptor
                )
                guard let state = markerStates[specification.name] else {
                    throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
                }
                switch state {
                case .absent:
                    if let identity { historical[specification.leafName] = identity }
                case .foregroundRequired(let marker):
                    pendingMarkers.append(marker)
                case .current:
                    guard identity != nil else {
                        throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
                    }
                }
            }
            // This fixed root covers the only gap before namespace publication:
            // mkdir/write/fsync may finish before the signed `.prepared` marker
            // is durable. An unmarked root is ambiguous and is preserved whole;
            // a legitimate signed prepared marker is reconciled first and binds
            // its exact identity before any other startup work can run.
            let migrationStagingIdentity = try secureSourceIdentityIfPresent(
                named: Self.migrationStagingName,
                support: support.descriptor
            )
            try revalidateDirectory(support, url: applicationSupport)
            if !pendingMarkers.isEmpty {
                let markers = pendingMarkers.sorted { $0.namespaceName < $1.namespaceName }
                return .namespacePublication(ProviderHistoryAuxiliaryNamespacePublicationRequest(
                    applicationSupport: applicationSupport,
                    namespaceNames: markers.map(\.namespaceName),
                    markers: markers,
                    applicationSupportIdentity: ProviderHistoryAuxiliaryPromptIdentity(support.metadata)
                ))
            }
            let backupsIdentity = historical[Self.backupsName]
            let stateRecoveryIdentity = historical[Self.stateRecoveryName]
            let migrationIdentity = historical[Self.migrationName]
            let preservesBackups = backupsIdentity != nil || stateRecoveryIdentity != nil
            let preservesMigration = migrationIdentity != nil || migrationStagingIdentity != nil
            guard preservesBackups || preservesMigration else { return nil }
            return .initial(ProviderHistoryAuxiliaryRecoveryRequest(
                applicationSupport: applicationSupport,
                preservesBackups: preservesBackups,
                preservesMigration: preservesMigration,
                applicationSupportIdentity: ProviderHistoryAuxiliaryPromptIdentity(support.metadata),
                backupsIdentity: backupsIdentity,
                stateRecoveryIdentity: stateRecoveryIdentity,
                migrationIdentity: migrationIdentity,
                migrationStagingIdentity: migrationStagingIdentity
            ))
        }
    }

    /// Foreground-only completion of exact signed namespace publications which
    /// crashed while a current Backups, restore-recovery, or Migration root was
    /// first being installed. The prompt binds every signed move and the support
    /// directory identity; a peer marker cannot borrow this acknowledgement.
    func reconcileNamespacePublicationsAfterExplicitAcknowledgement(
        _ request: ProviderHistoryAuxiliaryNamespacePublicationRequest
    ) throws -> ProviderHistoryAuxiliaryPendingState? {
        try withLock {
            guard limits.isValid,
                  request.applicationSupport.standardizedFileURL == applicationSupport,
                  !request.markers.isEmpty,
                  request.namespaceNames == request.markers.map(\.namespaceName),
                  request.namespaceNames == request.namespaceNames.sorted(),
                  Set(request.namespaceNames).count == request.namespaceNames.count else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            let support = try openApplicationSupport()
            defer { Darwin.close(support.descriptor) }
            guard ProviderHistoryAuxiliaryPromptIdentity(support.metadata)
                    == request.applicationSupportIdentity else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            let authority = try foregroundJournalAuthority()
            let markerStore = authority.makeProviderHistoryNamespaceMarkerStore()
            for expected in request.markers {
                let current: ProviderHistoryNamespaceMarker
                do {
                    current = try markerStore.reconcilePrepared(
                        namespaceName: expected.namespaceName
                    )
                } catch {
                    throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
                }
                guard current.state == .current,
                      current.namespaceName == expected.namespaceName,
                      current.sourceCanonicalPath == expected.sourceCanonicalPath,
                      current.sourceLeafName == expected.sourceLeafName,
                      current.destinationCanonicalPath == expected.destinationCanonicalPath,
                      current.destinationLeafName == expected.destinationLeafName,
                      current.device == expected.device,
                      current.inode == expected.inode,
                      current.owner == expected.owner,
                      current.mode == expected.mode,
                      current.privacyEpoch == expected.privacyEpoch,
                      current.receiptSHA256 == expected.receiptSHA256 else {
                    throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
                }
            }
            try revalidateDirectory(support, url: applicationSupport)
        }
        return try preflight()
    }

    /// Called only after an explicit foreground acknowledgement of the exact
    /// initial request. It creates the append-only journal before either source
    /// directory is moved.
    func preserveAfterExplicitAcknowledgement(
        _ request: ProviderHistoryAuxiliaryRecoveryRequest
    ) throws -> ProviderHistoryAuxiliaryRecoveryReceipt {
        try withLock {
            guard limits.isValid,
                  request.applicationSupport.standardizedFileURL == applicationSupport,
                  request.preservesBackups || request.preservesMigration else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            let deadline = Deadline(duration: limits.operationDuration)
            let support = try openApplicationSupport()
            defer { Darwin.close(support.descriptor) }
            guard ProviderHistoryAuxiliaryPromptIdentity(support.metadata)
                    == request.applicationSupportIdentity,
                  try metadata(named: Self.transactionName, beneath: support.descriptor) == nil else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            if request.preservesBackups {
                guard try secureSourceIdentityIfPresent(
                    named: Self.backupsName,
                    support: support.descriptor
                ) == request.backupsIdentity,
                try secureSourceIdentityIfPresent(
                    named: Self.stateRecoveryName,
                    support: support.descriptor
                ) == request.stateRecoveryIdentity,
                request.backupsIdentity != nil || request.stateRecoveryIdentity != nil else {
                    throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
                }
            }
            if request.preservesMigration {
                guard try secureSourceIdentityIfPresent(
                    named: Self.migrationName,
                    support: support.descriptor
                ) == request.migrationIdentity,
                try secureSourceIdentityIfPresent(
                    named: Self.migrationStagingName,
                    support: support.descriptor
                ) == request.migrationStagingIdentity,
                request.migrationIdentity != nil || request.migrationStagingIdentity != nil else {
                    throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
                }
            }

            let operation = makeUUID()
            let operationText = operation.uuidString.lowercased()
            guard Self.isCanonicalUUID(operationText) else {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryLimitExceeded
            }
            let backupRecord = request.backupsIdentity.map {
                NamespaceRecord(
                    sourceName: Self.backupsName,
                    destinationName: Self.backupDestinationPrefix + operationText,
                    sourceIdentity: $0
                )
            }
            let stateRecoveryRecord = request.stateRecoveryIdentity.map {
                NamespaceRecord(
                    sourceName: Self.stateRecoveryName,
                    destinationName: Self.stateRecoveryDestinationPrefix + operationText,
                    sourceIdentity: $0
                )
            }
            let migrationRecord = request.migrationIdentity.map {
                NamespaceRecord(
                    sourceName: Self.migrationName,
                    destinationName: Self.migrationDestinationPrefix + operationText,
                    sourceIdentity: $0
                )
            }
            let migrationStagingRecord = request.migrationStagingIdentity.map {
                NamespaceRecord(
                    sourceName: Self.migrationStagingName,
                    destinationName: Self.migrationStagingDestinationPrefix + operationText,
                    sourceIdentity: $0
                )
            }
            let authority = try foregroundJournalAuthority()
            let transaction = try createTransactionDirectory(support: support.descriptor)
            defer { Darwin.close(transaction.descriptor) }
            let lease = try acquireLease(transaction: transaction.descriptor, create: true)
            defer { lease.release() }
            var journal = Journal(
                formatVersion: Self.formatVersion,
                providerHistoryPrivacyEpoch: ProviderHistoryPrivacyEpoch.current,
                operationID: operation,
                phase: ProviderHistoryAuxiliaryRecoveryPhase.prepared.rawValue,
                applicationSupportIdentity: ProviderHistoryAuxiliaryStableIdentity(support.metadata),
                recoveryDirectoryName: Self.recoveryName,
                recoveryDirectoryIdentity: nil,
                backups: backupRecord,
                stateRecovery: stateRecoveryRecord,
                migration: migrationRecord,
                migrationStaging: migrationStagingRecord
            )
            try writePhase(
                journal,
                transaction: transaction.descriptor,
                support: support.descriptor,
                authority: authority
            )
            try interruptIfRequested(.prepared)
            return try reconcile(
                journal: &journal,
                support: support,
                transaction: transaction,
                deadline: deadline,
                authority: authority
            )
        }
    }

    /// Called only after an explicit foreground confirmation to resume the
    /// exact transaction detected by `preflight`.
    func resumeAfterExplicitAcknowledgement(
        _ request: ProviderHistoryAuxiliaryInterruptedRequest
    ) throws -> ProviderHistoryAuxiliaryRecoveryReceipt {
        try withLock {
            guard limits.isValid,
                  request.applicationSupport.standardizedFileURL == applicationSupport else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            let deadline = Deadline(duration: limits.operationDuration)
            let support = try openApplicationSupport()
            defer { Darwin.close(support.descriptor) }
            guard ProviderHistoryAuxiliaryPromptIdentity(support.metadata)
                    == request.applicationSupportIdentity,
                  let transaction = try openDirectoryIfPresent(
                    named: Self.transactionName,
                    beneath: support.descriptor
                  ) else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            defer { Darwin.close(transaction.descriptor) }
            guard ProviderHistoryAuxiliaryPromptIdentity(transaction.metadata)
                    == request.transactionIdentity else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            let lease = try acquireLease(transaction: transaction.descriptor, create: false)
            defer { lease.release() }
            let authority = try foregroundJournalAuthority()
            var journal = try readJournal(
                transaction: transaction.descriptor,
                deadline: deadline,
                verifier: authority.verifier()
            )
            guard journal.operationID == request.operationID else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            return try reconcile(
                journal: &journal,
                support: support,
                transaction: transaction,
                deadline: deadline,
                authority: authority
            )
        }
    }

    /// Preserves the complete append-only transaction journal beside its
    /// quarantined roots. No journal or output is deleted.
    func acknowledgePublishedRecovery(
        _ receipt: ProviderHistoryAuxiliaryRecoveryReceipt
    ) throws {
        try withLock {
            let deadline = Deadline(duration: limits.operationDuration)
            let support = try openApplicationSupport()
            defer { Darwin.close(support.descriptor) }
            guard ProviderHistoryAuxiliaryStableIdentity(support.metadata)
                    == receipt.applicationSupportIdentity,
                  let transaction = try openDirectoryIfPresent(
                    named: Self.transactionName,
                    beneath: support.descriptor
                  ) else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            defer { Darwin.close(transaction.descriptor) }
            guard ProviderHistoryAuxiliaryStableIdentity(transaction.metadata)
                    == receipt.transactionIdentity else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            let lease = try acquireLease(transaction: transaction.descriptor, create: false)
            defer { lease.release() }
            let authority = try foregroundJournalAuthority()
            let journal = try readJournal(
                transaction: transaction.descriptor,
                deadline: deadline,
                verifier: authority.verifier()
            )
            guard journal.phase == ProviderHistoryAuxiliaryRecoveryPhase.published.rawValue,
                  journal.operationID == receipt.operationID,
                  let recovery = try openDirectoryIfPresent(
                    named: Self.recoveryName,
                    beneath: support.descriptor
                  ),
                  ProviderHistoryAuxiliaryStableIdentity(recovery.metadata)
                    == receipt.recoveryIdentity else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            defer { Darwin.close(recovery.descriptor) }
            let publishedMetadata = try requireRegularMetadata(
                named: ProviderHistoryAuxiliaryRecoveryPhase.published.fileName,
                beneath: transaction.descriptor
            )
            guard ProviderHistoryAuxiliaryPromptIdentity(publishedMetadata)
                    == receipt.publishedPhaseIdentity else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            try validatePublishedNamespaces(journal, support: support.descriptor, recovery: recovery.descriptor)
            let archiveName = Self.archivedTransactionPrefix
                + journal.operationID.uuidString.lowercased()
            guard Self.validComponent(archiveName),
                  try metadata(named: archiveName, beneath: recovery.descriptor) == nil else {
                throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
            }
            descriptorHook?(.published)
            try revalidateDirectory(support, url: applicationSupport)
            try revalidateDirectory(recovery, url: receipt.recoveryDirectory)
            guard Darwin.renameat(
                support.descriptor,
                Self.transactionName,
                recovery.descriptor,
                archiveName
            ) == 0,
            Darwin.fsync(recovery.descriptor) == 0,
            Darwin.fsync(support.descriptor) == 0 else {
                throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
            }
        }
    }

    private func reconcile(
        journal: inout Journal,
        support: (descriptor: Int32, metadata: stat),
        transaction: (descriptor: Int32, metadata: stat),
        deadline: Deadline,
        authority: DeviceAttestationAuthority
    ) throws -> ProviderHistoryAuxiliaryRecoveryReceipt {
        try validateJournal(journal)
        try deadline.check()
        if journal.phase < ProviderHistoryAuxiliaryRecoveryPhase.recoveryDirectoryReady.rawValue {
            let recovery = try openOrCreateRecoveryDirectory(support: support.descriptor)
            defer { Darwin.close(recovery.descriptor) }
            journal = updating(
                journal,
                phase: .recoveryDirectoryReady,
                recoveryIdentity: ProviderHistoryAuxiliaryStableIdentity(recovery.metadata)
            )
            try writePhase(
                journal,
                transaction: transaction.descriptor,
                support: support.descriptor,
                authority: authority
            )
            try interruptIfRequested(.recoveryDirectoryReady)
        }
        guard let recovery = try openDirectoryIfPresent(
            named: Self.recoveryName,
            beneath: support.descriptor
        ),
        let expectedRecovery = journal.recoveryDirectoryIdentity,
        ProviderHistoryAuxiliaryStableIdentity(recovery.metadata) == expectedRecovery,
        UInt64(truncatingIfNeeded: recovery.metadata.st_dev)
            == journal.applicationSupportIdentity.device else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        defer { Darwin.close(recovery.descriptor) }

        if journal.phase < ProviderHistoryAuxiliaryRecoveryPhase.backupsPreserved.rawValue {
            if let backups = journal.backups {
                try preserveNamespace(
                    backups,
                    support: support,
                    recovery: recovery,
                    deadline: deadline
                )
            }
            if let stateRecovery = journal.stateRecovery {
                try preserveNamespace(
                    stateRecovery,
                    support: support,
                    recovery: recovery,
                    deadline: deadline
                )
            }
            journal = updating(journal, phase: .backupsPreserved)
            try writePhase(
                journal,
                transaction: transaction.descriptor,
                support: support.descriptor,
                authority: authority
            )
            try interruptIfRequested(.backupsPreserved)
        }
        if journal.phase < ProviderHistoryAuxiliaryRecoveryPhase.migrationPreserved.rawValue {
            if let migration = journal.migration {
                try preserveNamespace(
                    migration,
                    support: support,
                    recovery: recovery,
                    deadline: deadline
                )
            }
            if let migrationStaging = journal.migrationStaging {
                try preserveNamespace(
                    migrationStaging,
                    support: support,
                    recovery: recovery,
                    deadline: deadline
                )
            }
            journal = updating(journal, phase: .migrationPreserved)
            try writePhase(
                journal,
                transaction: transaction.descriptor,
                support: support.descriptor,
                authority: authority
            )
            try interruptIfRequested(.migrationPreserved)
        }
        if journal.phase < ProviderHistoryAuxiliaryRecoveryPhase.published.rawValue {
            try validatePublishedNamespaces(
                journal,
                support: support.descriptor,
                recovery: recovery.descriptor
            )
            journal = updating(journal, phase: .published)
            try writePhase(
                journal,
                transaction: transaction.descriptor,
                support: support.descriptor,
                authority: authority
            )
            try interruptIfRequested(.published)
        }
        return try receipt(journal: journal, support: support, transaction: transaction)
    }

    private func preserveNamespace(
        _ namespace: NamespaceRecord,
        support: (descriptor: Int32, metadata: stat),
        recovery: (descriptor: Int32, metadata: stat),
        deadline: Deadline
    ) throws {
        try deadline.check()
        descriptorHook?(
            namespace.sourceName == Self.migrationName
                || namespace.sourceName == Self.migrationStagingName
                ? .migrationPreserved
                : .backupsPreserved
        )
        let source = try metadata(named: namespace.sourceName, beneath: support.descriptor)
        let destination = try metadata(named: namespace.destinationName, beneath: recovery.descriptor)
        if let source {
            guard ProviderHistoryAuxiliaryPromptIdentity(source) == namespace.sourceIdentity,
                  destination == nil else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
            try revalidateDirectory(support, url: applicationSupport)
            try revalidateDirectory(recovery, url: applicationSupport.appendingPathComponent(
                Self.recoveryName,
                isDirectory: true
            ))
            guard Darwin.renameat(
                support.descriptor,
                namespace.sourceName,
                recovery.descriptor,
                namespace.destinationName
            ) == 0,
            Darwin.fsync(recovery.descriptor) == 0,
            Darwin.fsync(support.descriptor) == 0 else {
                throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
            }
        } else {
            guard let destination,
                  ProviderHistoryAuxiliaryStableIdentity(destination)
                    == namespace.sourceIdentity.stable else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
        }
        guard try metadata(named: namespace.sourceName, beneath: support.descriptor) == nil,
              let installed = try metadata(named: namespace.destinationName, beneath: recovery.descriptor),
              ProviderHistoryAuxiliaryStableIdentity(installed)
                == namespace.sourceIdentity.stable else {
            throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
        }
    }

    private func validatePublishedNamespaces(
        _ journal: Journal,
        support: Int32,
        recovery: Int32
    ) throws {
        for namespace in [
            journal.backups,
            journal.stateRecovery,
            journal.migration,
            journal.migrationStaging
        ].compactMap({ $0 }) {
            guard try metadata(named: namespace.sourceName, beneath: support) == nil,
                  let destination = try metadata(named: namespace.destinationName, beneath: recovery),
                  ProviderHistoryAuxiliaryStableIdentity(destination)
                    == namespace.sourceIdentity.stable else {
                throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
            }
        }
    }

    private func receipt(
        journal: Journal,
        support: (descriptor: Int32, metadata: stat),
        transaction: (descriptor: Int32, metadata: stat)
    ) throws -> ProviderHistoryAuxiliaryRecoveryReceipt {
        guard journal.phase == ProviderHistoryAuxiliaryRecoveryPhase.published.rawValue,
              let recovery = try openDirectoryIfPresent(
                named: Self.recoveryName,
                beneath: support.descriptor
              ),
              let expectedRecovery = journal.recoveryDirectoryIdentity,
              ProviderHistoryAuxiliaryStableIdentity(recovery.metadata) == expectedRecovery else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        defer { Darwin.close(recovery.descriptor) }
        try validatePublishedNamespaces(journal, support: support.descriptor, recovery: recovery.descriptor)
        let published = try requireRegularMetadata(
            named: ProviderHistoryAuxiliaryRecoveryPhase.published.fileName,
            beneath: transaction.descriptor
        )
        let recoveryURL = applicationSupport.appendingPathComponent(Self.recoveryName, isDirectory: true)
        return ProviderHistoryAuxiliaryRecoveryReceipt(
            recoveryDirectory: recoveryURL,
            preservedBackups: journal.backups.map {
                recoveryURL.appendingPathComponent($0.destinationName, isDirectory: true)
            },
            preservedStateRecovery: journal.stateRecovery.map {
                recoveryURL.appendingPathComponent($0.destinationName, isDirectory: true)
            },
            preservedMigration: journal.migration.map {
                recoveryURL.appendingPathComponent($0.destinationName, isDirectory: true)
            },
            preservedMigrationStaging: journal.migrationStaging.map {
                recoveryURL.appendingPathComponent($0.destinationName, isDirectory: true)
            },
            operationID: journal.operationID,
            applicationSupportIdentity: ProviderHistoryAuxiliaryStableIdentity(support.metadata),
            recoveryIdentity: ProviderHistoryAuxiliaryStableIdentity(recovery.metadata),
            transactionIdentity: ProviderHistoryAuxiliaryStableIdentity(transaction.metadata),
            publishedPhaseIdentity: ProviderHistoryAuxiliaryPromptIdentity(published)
        )
    }

    private func updating(
        _ journal: Journal,
        phase: ProviderHistoryAuxiliaryRecoveryPhase,
        recoveryIdentity: ProviderHistoryAuxiliaryStableIdentity? = nil
    ) -> Journal {
        Journal(
            formatVersion: journal.formatVersion,
            providerHistoryPrivacyEpoch: journal.providerHistoryPrivacyEpoch,
            operationID: journal.operationID,
            phase: phase.rawValue,
            applicationSupportIdentity: journal.applicationSupportIdentity,
            recoveryDirectoryName: journal.recoveryDirectoryName,
            recoveryDirectoryIdentity: recoveryIdentity ?? journal.recoveryDirectoryIdentity,
            backups: journal.backups,
            stateRecovery: journal.stateRecovery,
            migration: journal.migration,
            migrationStaging: journal.migrationStaging
        )
    }

    private func readJournal(
        transaction: Int32,
        deadline: Deadline,
        verifier: DeviceAttestationVerifier
    ) throws -> Journal {
        let names = try directoryNames(transaction, deadline: deadline)
        let permitted = Set(ProviderHistoryAuxiliaryRecoveryPhase.allCases.map(\.fileName) + [Self.lockName])
        guard names.count <= limits.maximumTransactionEntries,
              Set(names).isSubset(of: permitted),
              names.contains(Self.lockName) else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        var records: [Journal] = []
        for phase in ProviderHistoryAuxiliaryRecoveryPhase.allCases {
            if names.contains(phase.fileName) {
                let data = try boundedReadRegular(
                    named: phase.fileName,
                    beneath: transaction,
                    maximumBytes: limits.maximumJournalBytes
                )
                let payload: Data
                do {
                    payload = try verifier.verify(
                        DeviceAttestationSignedEnvelope(encoded: data),
                        expectedDomain: Self.journalDomain
                    )
                } catch {
                    throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
                }
                let decoded = try decodeExactJournal(payload)
                guard decoded.phase == phase.rawValue else {
                    throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
                }
                records.append(decoded)
            } else {
                break
            }
        }
        guard !records.isEmpty,
              records.count == names.count - 1 else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        for index in records.indices.dropFirst() {
            guard consistent(records[index - 1], records[index]) else {
                throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
            }
        }
        let latest = records[records.count - 1]
        try validateJournal(latest)
        return latest
    }

    private func consistent(_ prior: Journal, _ next: Journal) -> Bool {
        prior.formatVersion == next.formatVersion
            && prior.providerHistoryPrivacyEpoch == next.providerHistoryPrivacyEpoch
            && prior.operationID == next.operationID
            && next.phase == prior.phase + 1
            && prior.applicationSupportIdentity == next.applicationSupportIdentity
            && prior.recoveryDirectoryName == next.recoveryDirectoryName
            && prior.backups == next.backups
            && prior.stateRecovery == next.stateRecovery
            && prior.migration == next.migration
            && prior.migrationStaging == next.migrationStaging
            && (prior.recoveryDirectoryIdentity == nil
                || prior.recoveryDirectoryIdentity == next.recoveryDirectoryIdentity)
            && (next.phase == ProviderHistoryAuxiliaryRecoveryPhase.recoveryDirectoryReady.rawValue
                ? next.recoveryDirectoryIdentity != nil
                : next.recoveryDirectoryIdentity == prior.recoveryDirectoryIdentity)
    }

    private func validateJournal(_ journal: Journal) throws {
        guard journal.formatVersion == Self.formatVersion,
              journal.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              ProviderHistoryAuxiliaryRecoveryPhase(rawValue: journal.phase) != nil,
              journal.recoveryDirectoryName == Self.recoveryName,
              journal.backups != nil || journal.stateRecovery != nil
                || journal.migration != nil || journal.migrationStaging != nil,
              journal.applicationSupportIdentity.kind == UInt16(S_IFDIR),
              journal.applicationSupportIdentity.owner == geteuid(),
              journal.applicationSupportIdentity.permissions & 0o077 == 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        if journal.phase == ProviderHistoryAuxiliaryRecoveryPhase.prepared.rawValue {
            guard journal.recoveryDirectoryIdentity == nil else {
                throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
            }
        } else {
            guard let recovery = journal.recoveryDirectoryIdentity,
                  recovery.kind == UInt16(S_IFDIR),
                  recovery.owner == geteuid(),
                  recovery.permissions & 0o077 == 0,
                  recovery.device == journal.applicationSupportIdentity.device else {
                throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
            }
        }
        if let backups = journal.backups {
            guard validNamespace(
                backups,
                source: Self.backupsName,
                prefix: Self.backupDestinationPrefix
            ) else { throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal }
        }
        if let stateRecovery = journal.stateRecovery {
            guard validNamespace(
                stateRecovery,
                source: Self.stateRecoveryName,
                prefix: Self.stateRecoveryDestinationPrefix
            ) else { throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal }
        }
        if let migration = journal.migration {
            guard validNamespace(
                migration,
                source: Self.migrationName,
                prefix: Self.migrationDestinationPrefix
            ) else { throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal }
        }
        if let migrationStaging = journal.migrationStaging {
            guard validNamespace(
                migrationStaging,
                source: Self.migrationStagingName,
                prefix: Self.migrationStagingDestinationPrefix
            ) else { throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal }
        }
    }

    private func validNamespace(
        _ value: NamespaceRecord,
        source: String,
        prefix: String
    ) -> Bool {
        value.sourceName == source
            && value.destinationName.hasPrefix(prefix)
            && Self.isCanonicalUUID(String(value.destinationName.dropFirst(prefix.count)))
            && value.sourceIdentity.stable.kind == UInt16(S_IFDIR)
            && value.sourceIdentity.stable.owner == geteuid()
            && value.sourceIdentity.stable.permissions & 0o077 == 0
    }

    private func writePhase(
        _ journal: Journal,
        transaction: Int32,
        support: Int32,
        authority: DeviceAttestationAuthority
    ) throws {
        try validateJournal(journal)
        let phase = try requiredPhase(journal.phase)
        let payload = try encodeExactJournal(journal)
        let data: Data
        do {
            data = try authority.sign(payload: payload, domain: Self.journalDomain).encoded
        } catch {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        guard data.count <= limits.maximumJournalBytes,
              try metadata(named: phase.fileName, beneath: transaction) == nil else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        let descriptor = Darwin.openat(
            transaction,
            phase.fileName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        // A torn file is deliberately retained. Relaunch fails closed instead
        // of deleting potentially useful transaction evidence.
        defer { Darwin.close(descriptor) }
        try writeAll(data, descriptor: descriptor)
        guard Darwin.fsync(descriptor) == 0,
              Darwin.fsync(transaction) == 0,
              Darwin.fsync(support) == 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
    }

    private func encodeExactJournal(_ journal: Journal) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(journal)
    }

    private func decodeExactJournal(_ data: Data) throws -> Journal {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == [
                "formatVersion", "providerHistoryPrivacyEpoch", "operationID", "phase",
                "applicationSupportIdentity", "recoveryDirectoryName",
                "recoveryDirectoryIdentity", "backups", "stateRecovery", "migration",
                "migrationStaging"
              ],
              exactIdentityObject(object["applicationSupportIdentity"]),
              optionalExactIdentityObject(object["recoveryDirectoryIdentity"]),
              optionalExactNamespaceObject(object["backups"]),
              optionalExactNamespaceObject(object["stateRecovery"]),
              optionalExactNamespaceObject(object["migration"]),
              optionalExactNamespaceObject(object["migrationStaging"]),
              let decoded = try? JSONDecoder().decode(Journal.self, from: data) else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        return decoded
    }

    private func exactIdentityObject(_ value: Any?) -> Bool {
        guard let identity = value as? [String: Any] else { return false }
        return Set(identity.keys) == ["device", "inode", "owner", "permissions", "kind"]
            && identity.values.allSatisfy(Self.isJSONInteger)
    }

    private func optionalExactIdentityObject(_ value: Any?) -> Bool {
        value is NSNull || exactIdentityObject(value)
    }

    private func optionalExactNamespaceObject(_ value: Any?) -> Bool {
        if value is NSNull { return true }
        guard let namespace = value as? [String: Any],
              Set(namespace.keys) == ["sourceName", "destinationName", "sourceIdentity"],
              namespace["sourceName"] is String,
              namespace["destinationName"] is String,
              let prompt = namespace["sourceIdentity"] as? [String: Any],
              Set(prompt.keys) == [
                "stable", "linkCount", "byteCount", "modificationSeconds",
                "modificationNanoseconds", "changeSeconds", "changeNanoseconds"
              ],
              exactIdentityObject(prompt["stable"]) else { return false }
        return prompt.filter { $0.key != "stable" }.values.allSatisfy(Self.isJSONInteger)
    }

    private static func isJSONInteger(_ value: Any) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return false }
        let decimal = number.doubleValue
        return decimal.isFinite && decimal.rounded(.towardZero) == decimal
    }

    private func openApplicationSupport() throws -> (descriptor: Int32, metadata: stat) {
        guard applicationSupport.path.hasPrefix("/") else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeApplicationSupport
        }
        let descriptor = Darwin.open(
            applicationSupport.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeApplicationSupport
        }
        var value = stat()
        guard Darwin.fstat(descriptor, &value) == 0,
              securePrivateDirectory(value, descriptor: descriptor) else {
            Darwin.close(descriptor)
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeApplicationSupport
        }
        return (descriptor, value)
    }

    private func openDirectoryIfPresent(
        named name: String,
        beneath parent: Int32
    ) throws -> (descriptor: Int32, metadata: stat)? {
        guard Self.validComponent(name) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        let descriptor = Darwin.openat(
            parent,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        var value = stat()
        guard Darwin.fstat(descriptor, &value) == 0,
              securePrivateDirectory(value, descriptor: descriptor) else {
            Darwin.close(descriptor)
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        return (descriptor, value)
    }

    private func createTransactionDirectory(
        support: Int32
    ) throws -> (descriptor: Int32, metadata: stat) {
        guard Darwin.mkdirat(support, Self.transactionName, 0o700) == 0 else {
            if errno == EEXIST {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryInProgress
            }
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        guard Darwin.fsync(support) == 0,
              let result = try openDirectoryIfPresent(
                named: Self.transactionName,
                beneath: support
              ) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        return result
    }

    private func openOrCreateRecoveryDirectory(
        support: Int32
    ) throws -> (descriptor: Int32, metadata: stat) {
        if let existing = try openDirectoryIfPresent(named: Self.recoveryName, beneath: support) {
            return existing
        }
        guard Darwin.mkdirat(support, Self.recoveryName, 0o700) == 0 else {
            if errno == EEXIST,
               let existing = try openDirectoryIfPresent(named: Self.recoveryName, beneath: support) {
                return existing
            }
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        guard Darwin.fsync(support) == 0,
              let created = try openDirectoryIfPresent(named: Self.recoveryName, beneath: support) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        return created
    }

    private func acquireLease(transaction: Int32, create: Bool) throws -> RecoveryLease {
        let flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0)
        let descriptor = Darwin.openat(transaction, Self.lockName, flags, 0o600)
        guard descriptor >= 0 else {
            throw create
                ? ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
                : ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        var value = stat()
        guard Darwin.fstat(descriptor, &value) == 0,
              value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == geteuid(),
              value.st_mode & 0o077 == 0,
              value.st_nlink == 1,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(descriptor)
            if errno == EWOULDBLOCK {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryInProgress
            }
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        return RecoveryLease(descriptor: descriptor)
    }

    private func secureSourceIdentity(
        named name: String,
        support: Int32
    ) throws -> ProviderHistoryAuxiliaryPromptIdentity {
        guard let value = try metadata(named: name, beneath: support),
              value.st_mode & S_IFMT == S_IFDIR,
              value.st_uid == geteuid(),
              value.st_mode & 0o077 == 0,
              value.st_nlink >= 2,
              UInt64(truncatingIfNeeded: value.st_dev)
                == (try supportIdentity(support).device) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        let descriptor = Darwin.openat(
            support,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              ProviderHistoryAuxiliaryPromptIdentity(opened)
                == ProviderHistoryAuxiliaryPromptIdentity(value),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        return ProviderHistoryAuxiliaryPromptIdentity(opened)
    }

    private func secureSourceIdentityIfPresent(
        named name: String,
        support: Int32
    ) throws -> ProviderHistoryAuxiliaryPromptIdentity? {
        guard try metadata(named: name, beneath: support) != nil else { return nil }
        return try secureSourceIdentity(named: name, support: support)
    }

    private func supportIdentity(_ descriptor: Int32) throws -> ProviderHistoryAuxiliaryStableIdentity {
        var value = stat()
        guard Darwin.fstat(descriptor, &value) == 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeApplicationSupport
        }
        return ProviderHistoryAuxiliaryStableIdentity(value)
    }

    private func securePrivateDirectory(_ value: stat, descriptor: Int32) -> Bool {
        value.st_mode & S_IFMT == S_IFDIR
            && value.st_uid == geteuid()
            && value.st_mode & 0o077 == 0
            && value.st_nlink >= 2
            && value.st_flags & UInt32(UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND) == 0
            && CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor)
    }

    private func revalidateDirectory(
        _ opened: (descriptor: Int32, metadata: stat),
        url: URL
    ) throws {
        var descriptorMetadata = stat()
        var pathMetadata = stat()
        guard Darwin.fstat(opened.descriptor, &descriptorMetadata) == 0,
              Darwin.lstat(url.path, &pathMetadata) == 0,
              ProviderHistoryAuxiliaryStableIdentity(descriptorMetadata)
                == ProviderHistoryAuxiliaryStableIdentity(opened.metadata),
              ProviderHistoryAuxiliaryStableIdentity(pathMetadata)
                == ProviderHistoryAuxiliaryStableIdentity(opened.metadata),
              securePrivateDirectory(descriptorMetadata, descriptor: opened.descriptor) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
    }

    private func metadata(named name: String, beneath parent: Int32) throws -> stat? {
        guard Self.validComponent(name) else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        var value = stat()
        if Darwin.fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) == 0 {
            return value
        }
        if errno == ENOENT { return nil }
        throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
    }

    private func requireRegularMetadata(named name: String, beneath parent: Int32) throws -> stat {
        guard let value = try metadata(named: name, beneath: parent),
              value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == geteuid(),
              value.st_mode & 0o077 == 0,
              value.st_nlink == 1 else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        return value
    }

    private func boundedReadRegular(
        named name: String,
        beneath parent: Int32,
        maximumBytes: Int
    ) throws -> Data {
        let descriptor = Darwin.openat(
            parent,
            name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        defer { Darwin.close(descriptor) }
        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_mode & 0o077 == 0,
              before.st_nlink == 1,
              before.st_size >= 0,
              before.st_size <= Int64(maximumBytes),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: 8 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
            }
            guard count <= maximumBytes - data.count else {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryLimitExceeded
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard data.count == Int(before.st_size),
              Darwin.fstat(descriptor, &after) == 0,
              ProviderHistoryAuxiliaryPromptIdentity(after)
                == ProviderHistoryAuxiliaryPromptIdentity(before) else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        return data
    }

    private func directoryNames(_ descriptor: Int32, deadline: Deadline) throws -> [String] {
        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0, let stream = Darwin.fdopendir(duplicate) else {
            if duplicate >= 0 { Darwin.close(duplicate) }
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        defer { Darwin.closedir(stream) }
        var names: [String] = []
        errno = 0
        while let entry = Darwin.readdir(stream) {
            try deadline.check()
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
            }
            if name == "." || name == ".." { continue }
            names.append(name)
            guard names.count <= limits.maximumTransactionEntries else {
                throw ProviderHistoryAuxiliaryRecoveryError.recoveryLimitExceeded
            }
        }
        guard errno == 0 else {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
        return names.sorted()
    }

    private func writeAll(_ data: Data, descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
                }
                guard count > 0 else {
                    throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
                }
                offset += count
            }
        }
    }

    private func interruptIfRequested(_ phase: ProviderHistoryAuxiliaryRecoveryPhase) throws {
        if interruption?(phase) == true {
            throw ProviderHistoryAuxiliaryTestInterruption.simulatedCrash(phase)
        }
    }

    private func requiredPhase(_ raw: Int) throws -> ProviderHistoryAuxiliaryRecoveryPhase {
        guard let phase = ProviderHistoryAuxiliaryRecoveryPhase(rawValue: raw) else {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
        return phase
    }

    private func backgroundJournalVerifier() throws -> DeviceAttestationVerifier {
        do {
            return try DeviceAttestationAuthority.openBackgroundVerifier(
                configuration: attestationConfiguration,
                keyStore: attestationKeyStore
            )
        } catch {
            throw ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal
        }
    }

    private func foregroundJournalAuthority() throws -> DeviceAttestationAuthority {
        do {
            return try DeviceAttestationAuthority.openForeground(
                configuration: attestationConfiguration,
                keyStore: attestationKeyStore
            )
        } catch {
            throw ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage
        }
    }

    private static func validComponent(_ value: String) -> Bool {
        !value.isEmpty
            && value != "."
            && value != ".."
            && !value.contains("/")
            && !value.contains("\0")
            && value.utf8.count <= Int(MAXNAMLEN)
            && !value.unicodeScalars.contains {
                CharacterSet.controlCharacters.contains($0)
                    || $0.properties.generalCategory == .format
            }
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        value.count == 36
            && value == value.lowercased()
            && UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}
