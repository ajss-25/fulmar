import Darwin
import CoreFoundation
import Foundation
import LocalHarnessDeviceAttestation

enum RuntimeLaunchPreparation: Equatable {
    case current
    case backupCreated(StateBackup)
    case recoveryNeeded(StateBackup)
}

/// Detection-only startup classification. Reading this value creates no
/// directory, file, backup, Keychain item, or protection-registry entry.
enum RuntimeMigrationPrivacyEpochPreflight: Equatable, Sendable {
    case absent
    case current
    case historical
}

enum RuntimeMigrationStateError: LocalizedError, Equatable {
    case unsafeStorage
    case corruptState
    case stateTooLarge
    case invalidVersion
    case persistenceFailed
    case providerHistoryPrivacyMigrationRequired

    var errorDescription: String? {
        switch self {
        case .unsafeStorage:
            return "The private Harness migration state is not an owner-only regular file. Runtime startup stayed blocked."
        case .corruptState:
            return "The Harness migration state is damaged or inconsistent. Runtime startup stayed blocked."
        case .stateTooLarge:
            return "The Harness migration state exceeded its safety limit. Runtime startup stayed blocked."
        case .invalidVersion:
            return "The requested Harness runtime version is invalid."
        case .persistenceFailed:
            return "The private Harness migration state could not be committed. Runtime startup stayed blocked."
        case .providerHistoryPrivacyMigrationRequired:
            return "Historical runtime migration state was found. It was preserved without linking its rollback reference into the current backup catalog, and startup stayed blocked pending foreground privacy recovery."
        }
    }
}

enum RuntimeMigrationPublicationPhase: Equatable, Sendable {
    case stagingDirectorySynced
    case stagingStateSynced
}

enum RuntimeMigrationPublicationTestInterruption: Error, Equatable {
    case simulatedCrash(RuntimeMigrationPublicationPhase)
}

final class RuntimeMigrationCoordinator: @unchecked Sendable {
    private struct State: Codable {
        let formatVersion: Int
        let providerHistoryPrivacyEpoch: Int
        var installedVersion: String?
        var pendingVersion: String?
        var pendingBackupID: UUID?
        var attemptStartedAt: Date?

        init(
            installedVersion: String? = nil,
            pendingVersion: String? = nil,
            pendingBackupID: UUID? = nil,
            attemptStartedAt: Date? = nil
        ) {
            formatVersion = RuntimeMigrationCoordinator.stateFormatVersion
            providerHistoryPrivacyEpoch = ProviderHistoryPrivacyEpoch.current
            self.installedVersion = installedVersion
            self.pendingVersion = pendingVersion
            self.pendingBackupID = pendingBackupID
            self.attemptStartedAt = attemptStartedAt
        }

        private enum CodingKeys: String, CodingKey {
            case formatVersion
            case providerHistoryPrivacyEpoch
            case installedVersion
            case pendingVersion
            case pendingBackupID
            case attemptStartedAt
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            formatVersion = try container.decode(Int.self, forKey: .formatVersion)
            providerHistoryPrivacyEpoch = try container.decode(Int.self, forKey: .providerHistoryPrivacyEpoch)
            installedVersion = try container.decodeIfPresent(String.self, forKey: .installedVersion)
            pendingVersion = try container.decodeIfPresent(String.self, forKey: .pendingVersion)
            pendingBackupID = try container.decodeIfPresent(UUID.self, forKey: .pendingBackupID)
            attemptStartedAt = try container.decodeIfPresent(Date.self, forKey: .attemptStartedAt)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(formatVersion, forKey: .formatVersion)
            try container.encode(providerHistoryPrivacyEpoch, forKey: .providerHistoryPrivacyEpoch)
            if let installedVersion {
                try container.encode(installedVersion, forKey: .installedVersion)
            } else {
                try container.encodeNil(forKey: .installedVersion)
            }
            if let pendingVersion {
                try container.encode(pendingVersion, forKey: .pendingVersion)
            } else {
                try container.encodeNil(forKey: .pendingVersion)
            }
            if let pendingBackupID {
                try container.encode(pendingBackupID, forKey: .pendingBackupID)
            } else {
                try container.encodeNil(forKey: .pendingBackupID)
            }
            if let attemptStartedAt {
                try container.encode(attemptStartedAt, forKey: .attemptStartedAt)
            } else {
                try container.encodeNil(forKey: .attemptStartedAt)
            }
        }
    }

    private let fileManager = FileManager.default
    private static let stateFormatVersion = 1
    private static let maximumStateBytes = 64 * 1_024
    private let stateURL: URL
    private let directoryURL: URL
    private let applicationSupport: URL
    private let backupManager: StateBackupManager
    private let attestationKeyStore: any DeviceAttestationKeyStore
    private let publicationInterruption: (@Sendable (RuntimeMigrationPublicationPhase) -> Bool)?
    private let lock = NSLock()
    private var initializationError: RuntimeMigrationStateError?

    init(
        applicationSupport: URL,
        backupManager: StateBackupManager,
        attestationKeyStore: (any DeviceAttestationKeyStore)? = nil,
        publicationInterruption: (@Sendable (RuntimeMigrationPublicationPhase) -> Bool)? = nil
    ) {
        self.applicationSupport = applicationSupport.standardizedFileURL
        directoryURL = applicationSupport.standardizedFileURL
            .appendingPathComponent(ProviderHistoryDeviceAttestation.migration.leafName, isDirectory: true)
        stateURL = directoryURL.appendingPathComponent("runtime-state.json")
        self.backupManager = backupManager
        self.attestationKeyStore = attestationKeyStore
            ?? ProviderHistoryDeviceAttestation.productionKeyStore()
        self.publicationInterruption = publicationInterruption
        do {
            switch try Self.signedNamespacePreflight(
                applicationSupport: self.applicationSupport,
                keyStore: self.attestationKeyStore
            ) {
            case .absent:
                // Detection-only initialization. The directory is created by
                // persist only after home and backup epoch gates succeed.
                return
            case .historical:
                initializationError = .providerHistoryPrivacyMigrationRequired
                return
            case .current:
                break
            }
        } catch {
            initializationError = (error as? RuntimeMigrationStateError) ?? .unsafeStorage
            return
        }
        // Register a durable pending rollback point before any backup UI or
        // retention operation can mutate the catalog in this process.
        do {
            let state = try load()
            if let id = state.pendingBackupID {
                backupManager.protectMigrationBackup(id: id)
            }
        } catch let error as RuntimeMigrationStateError {
            initializationError = error
        } catch {
            initializationError = .corruptState
        }
    }

    static func privacyEpochPreflight(
        applicationSupport: URL
    ) throws -> RuntimeMigrationPrivacyEpochPreflight {
        let directory = applicationSupport.appendingPathComponent("Migration", isDirectory: true)
        var pathMetadata = stat()
        if Darwin.lstat(directory.path, &pathMetadata) != 0 {
            if errno == ENOENT { return .absent }
            throw RuntimeMigrationStateError.unsafeStorage
        }
        guard pathMetadata.st_mode & S_IFMT == S_IFDIR,
              pathMetadata.st_uid == geteuid(),
              pathMetadata.st_mode & 0o077 == 0 else {
            throw RuntimeMigrationStateError.unsafeStorage
        }
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw RuntimeMigrationStateError.unsafeStorage }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              opened.st_dev == pathMetadata.st_dev,
              opened.st_ino == pathMetadata.st_ino,
              opened.st_mode == pathMetadata.st_mode,
              opened.st_uid == pathMetadata.st_uid,
              opened.st_nlink >= 2,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw RuntimeMigrationStateError.unsafeStorage
        }
        let finish: (RuntimeMigrationPrivacyEpochPreflight) throws -> RuntimeMigrationPrivacyEpochPreflight = { result in
                var afterPath = stat()
                guard Darwin.lstat(directory.path, &afterPath) == 0,
                      afterPath.st_dev == opened.st_dev,
                      afterPath.st_ino == opened.st_ino,
                      afterPath.st_mode == opened.st_mode,
                      afterPath.st_uid == opened.st_uid else {
                    throw RuntimeMigrationStateError.unsafeStorage
                }
                return result
            }

        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0 else { throw RuntimeMigrationStateError.unsafeStorage }
        guard let stream = Darwin.fdopendir(duplicate) else {
            Darwin.close(duplicate)
            throw RuntimeMigrationStateError.unsafeStorage
        }
        defer { Darwin.closedir(stream) }
        var names: [String] = []
        errno = 0
        while let entry = Darwin.readdir(stream) {
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw RuntimeMigrationStateError.corruptState
            }
            if name == "." || name == ".." { continue }
            names.append(name)
            guard names.count <= 8 else { return try finish(.historical) }
        }
        guard errno == 0 else { throw RuntimeMigrationStateError.corruptState }
        guard names.isEmpty || names == ["runtime-state.json"] else {
            return try finish(.historical)
        }
        guard names == ["runtime-state.json"] else { return try finish(.absent) }

        let stateDescriptor = Darwin.openat(
            descriptor,
            "runtime-state.json",
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard stateDescriptor >= 0 else { throw RuntimeMigrationStateError.unsafeStorage }
        defer { Darwin.close(stateDescriptor) }
        var before = stat()
        guard Darwin.fstat(stateDescriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_nlink == 1,
              before.st_mode & 0o077 == 0,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(stateDescriptor) else {
            throw RuntimeMigrationStateError.unsafeStorage
        }
        guard before.st_size >= 0, before.st_size <= Self.maximumStateBytes else {
            throw RuntimeMigrationStateError.stateTooLarge
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(stateDescriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw RuntimeMigrationStateError.corruptState
            }
            guard count <= Self.maximumStateBytes - data.count else {
                throw RuntimeMigrationStateError.stateTooLarge
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard data.count == Int(before.st_size),
              Darwin.fstat(stateDescriptor, &after) == 0,
              Self.sameIdentity(before, after),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RuntimeMigrationStateError.corruptState
        }
        let format = Self.jsonInteger(object["formatVersion"])
        let epoch = Self.jsonInteger(object["providerHistoryPrivacyEpoch"])
        guard format == Self.stateFormatVersion,
              epoch == ProviderHistoryPrivacyEpoch.current else {
            return try finish(.historical)
        }
        guard Self.hasExactCurrentStateSchema(object),
              let state = try? Self.decodeState(data),
              Self.isValid(state) else {
            throw RuntimeMigrationStateError.corruptState
        }
        return try finish(.current)
    }

    /// Production gate: exact-root and signed-marker only. Unlike the legacy
    /// state classifier above, this never lists Migration or opens its state
    /// before the externally authenticated current-namespace marker clears.
    private static func signedNamespacePreflight(
        applicationSupport: URL,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> RuntimeMigrationPrivacyEpochPreflight {
        let support = applicationSupport.standardizedFileURL
        let staging = support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.migrationStagingLeafName,
            isDirectory: true
        )
        var stagingMetadata = stat()
        if Darwin.lstat(staging.path, &stagingMetadata) == 0 {
            return .historical
        }
        guard errno == ENOENT else { throw RuntimeMigrationStateError.unsafeStorage }

        let destination = support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.migration.leafName,
            isDirectory: true
        )
        let state: ProviderHistoryNamespaceBackgroundState
        do {
            state = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: ProviderHistoryDeviceAttestation.migration.name,
                expectedURL: destination,
                expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                expectedReceipt: ProviderHistoryDeviceAttestation.migration.publicationReceipt,
                configuration: ProviderHistoryDeviceAttestation.configuration(
                    applicationSupport: support
                ),
                keyStore: keyStore
            )
        } catch {
            throw RuntimeMigrationStateError.unsafeStorage
        }
        switch state {
        case .foregroundRequired:
            return .historical
        case .current:
            return .current
        case .absent:
            var destinationMetadata = stat()
            if Darwin.lstat(destination.path, &destinationMetadata) == 0 {
                return .historical
            }
            guard errno == ENOENT else { throw RuntimeMigrationStateError.unsafeStorage }
            return .absent
        }
    }

    func prepare(targetVersion: String) throws -> RuntimeLaunchPreparation {
        try withLock {
            try prepareLocked(targetVersion: targetVersion)
        }
    }

    private func prepareLocked(targetVersion: String) throws -> RuntimeLaunchPreparation {
        guard Self.isSafeVersion(targetVersion) else { throw RuntimeMigrationStateError.invalidVersion }
        var state = try load()
        if state.pendingVersion != nil, let id = state.pendingBackupID {
            backupManager.protectMigrationBackup(id: id)
            // Never create or substitute a new rollback point when the exact
            // durable pending snapshot is missing, corrupt, or cannot be
            // authenticated. The underlying typed failure remains visible.
            let backup = try backupManager.requiredBackup(id: id)
            return .recoveryNeeded(backup)
        }
        if state.installedVersion == targetVersion, state.pendingVersion == nil { return .current }

        let previous = state.installedVersion ?? "pre-Local-Harness"
        let backup = try backupManager.create(label: "Before Harness \(targetVersion)", sourceVersion: previous)
        backupManager.protectMigrationBackup(id: backup.id)
        state.pendingVersion = targetVersion
        state.pendingBackupID = backup.id
        state.attemptStartedAt = Date()
        do {
            try persist(state)
        } catch {
            backupManager.releaseMigrationBackup(id: backup.id)
            throw error
        }
        return .backupCreated(backup)
    }

    func retryPending(targetVersion: String) throws {
        try withLock {
            guard Self.isSafeVersion(targetVersion) else { throw RuntimeMigrationStateError.invalidVersion }
            var state = try load()
            guard state.pendingVersion == targetVersion else { return }
            if let id = state.pendingBackupID {
                backupManager.protectMigrationBackup(id: id)
                _ = try backupManager.requiredBackup(id: id)
            }
            state.attemptStartedAt = Date()
            try persist(state)
        }
    }

    func markReady(version: String) throws {
        try withLock {
            guard Self.isSafeVersion(version) else { throw RuntimeMigrationStateError.invalidVersion }
            var state = try load()
            let completedBackupID = state.pendingBackupID
            state.installedVersion = version
            state.pendingVersion = nil
            state.pendingBackupID = nil
            state.attemptStartedAt = nil
            try persist(state)
            if let completedBackupID {
                backupManager.releaseMigrationBackup(id: completedBackupID)
            }
        }
    }

    private func withLock<Value>(_ body: () throws -> Value) rethrows -> Value {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private func load() throws -> State {
        if let initializationError { throw initializationError }
        switch try Self.signedNamespacePreflight(
            applicationSupport: applicationSupport,
            keyStore: attestationKeyStore
        ) {
        case .absent:
            return State()
        case .historical:
            throw RuntimeMigrationStateError.providerHistoryPrivacyMigrationRequired
        case .current:
            break
        }
        try Self.validatePrivateDirectory(directoryURL)

        let descriptor = Darwin.open(stateURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if descriptor < 0 {
            if errno == ENOENT { return State() }
            throw RuntimeMigrationStateError.unsafeStorage
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_nlink == 1,
              before.st_mode & 0o077 == 0 else {
            throw RuntimeMigrationStateError.unsafeStorage
        }
        guard before.st_size >= 0, before.st_size <= Self.maximumStateBytes else {
            throw RuntimeMigrationStateError.stateTooLarge
        }

        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw RuntimeMigrationStateError.corruptState
            }
            guard data.count <= Self.maximumStateBytes - count else {
                throw RuntimeMigrationStateError.stateTooLarge
            }
            data.append(contentsOf: buffer.prefix(count))
        }

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Self.sameIdentity(before, after) else {
            throw RuntimeMigrationStateError.corruptState
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RuntimeMigrationStateError.corruptState
        }
        let format = Self.jsonInteger(object["formatVersion"])
        let epoch = Self.jsonInteger(object["providerHistoryPrivacyEpoch"])
        guard format == Self.stateFormatVersion,
              epoch == ProviderHistoryPrivacyEpoch.current else {
            throw RuntimeMigrationStateError.providerHistoryPrivacyMigrationRequired
        }
        guard Self.hasExactCurrentStateSchema(object),
              let state = try? Self.decodeState(data),
              Self.isValid(state) else {
            throw RuntimeMigrationStateError.corruptState
        }
        return state
    }

    private func persist(_ state: State) throws {
        if let initializationError { throw initializationError }
        guard Self.isValid(state) else { throw RuntimeMigrationStateError.corruptState }
        let data = try Self.encodeState(state)
        guard data.count <= Self.maximumStateBytes else { throw RuntimeMigrationStateError.stateTooLarge }
        switch try Self.signedNamespacePreflight(
            applicationSupport: applicationSupport,
            keyStore: attestationKeyStore
        ) {
        case .historical:
            throw RuntimeMigrationStateError.providerHistoryPrivacyMigrationRequired
        case .absent:
            try publishInitialState(data)
            return
        case .current:
            break
        }
        try Self.validatePrivateDirectory(directoryURL)

        let temporary = directoryURL.appendingPathComponent(".runtime-state-\(UUID().uuidString).tmp")
        let descriptor = Darwin.open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw RuntimeMigrationStateError.persistenceFailed }
        var published = false
        defer {
            Darwin.close(descriptor)
            if !published { try? fileManager.removeItem(at: temporary) }
        }
        do {
            try data.withUnsafeBytes { rawBuffer in
                guard var address = rawBuffer.baseAddress else { return }
                var remaining = rawBuffer.count
                while remaining > 0 {
                    let written = Darwin.write(descriptor, address, remaining)
                    if written < 0 {
                        if errno == EINTR { continue }
                        throw RuntimeMigrationStateError.persistenceFailed
                    }
                    address = address.advanced(by: written)
                    remaining -= written
                }
            }
            guard Darwin.fsync(descriptor) == 0,
                  Darwin.rename(temporary.path, stateURL.path) == 0 else {
                throw RuntimeMigrationStateError.persistenceFailed
            }
            published = true
            try Self.validatePrivateStateFile(stateURL)
            let directoryDescriptor = Darwin.open(
                directoryURL.path,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
            guard directoryDescriptor >= 0 else { throw RuntimeMigrationStateError.persistenceFailed }
            defer { Darwin.close(directoryDescriptor) }
            guard Darwin.fsync(directoryDescriptor) == 0 else {
                throw RuntimeMigrationStateError.persistenceFailed
            }
        } catch let error as RuntimeMigrationStateError {
            throw error
        } catch {
            throw RuntimeMigrationStateError.persistenceFailed
        }
    }

    /// The source staging name is fixed and externally classified by
    /// `ProviderHistoryAuxiliaryStateCoordinator`. If the process dies after
    /// either fsync below but before the signed prepared marker is committed,
    /// the entire staging root is preserved opaquely on the next foreground
    /// launch; it is never deleted or automatically adopted.
    private func publishInitialState(_ data: Data) throws {
        do {
            try Self.ensurePrivateDirectory(applicationSupport, fileManager: fileManager)
            let support = Darwin.open(
                applicationSupport.path,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
            guard support >= 0 else { throw RuntimeMigrationStateError.persistenceFailed }
            defer { Darwin.close(support) }
            let stagingLeaf = ProviderHistoryDeviceAttestation.migrationStagingLeafName
            guard Darwin.mkdirat(support, stagingLeaf, 0o700) == 0,
                  Darwin.fsync(support) == 0 else {
                if errno == EEXIST {
                    throw RuntimeMigrationStateError.providerHistoryPrivacyMigrationRequired
                }
                throw RuntimeMigrationStateError.persistenceFailed
            }
            try interruptPublicationIfRequested(.stagingDirectorySynced)

            let staging = Darwin.openat(
                support,
                stagingLeaf,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
            guard staging >= 0 else { throw RuntimeMigrationStateError.persistenceFailed }
            defer { Darwin.close(staging) }
            var stagingMetadata = stat()
            guard Darwin.fstat(staging, &stagingMetadata) == 0,
                  stagingMetadata.st_mode & S_IFMT == S_IFDIR,
                  stagingMetadata.st_uid == geteuid(),
                  stagingMetadata.st_mode & 0o077 == 0,
                  stagingMetadata.st_nlink >= 2,
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(staging) else {
                throw RuntimeMigrationStateError.persistenceFailed
            }
            let stateDescriptor = Darwin.openat(
                staging,
                "runtime-state.json",
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
            guard stateDescriptor >= 0 else { throw RuntimeMigrationStateError.persistenceFailed }
            defer { Darwin.close(stateDescriptor) }
            try Self.writeAll(data, descriptor: stateDescriptor)
            guard Darwin.fsync(stateDescriptor) == 0,
                  Darwin.fsync(staging) == 0,
                  Darwin.fsync(support) == 0 else {
                throw RuntimeMigrationStateError.persistenceFailed
            }
            try interruptPublicationIfRequested(.stagingStateSynced)

            let authority = try ProviderHistoryDeviceAttestation.openForeground(
                applicationSupport: applicationSupport,
                operationDuration: 10,
                keyStore: attestationKeyStore
            )
            _ = try authority.makeProviderHistoryNamespaceMarkerStore().publish(.init(
                sourceParent: applicationSupport,
                sourceLeaf: stagingLeaf,
                destinationParent: applicationSupport,
                destinationLeaf: ProviderHistoryDeviceAttestation.migration.leafName,
                namespaceName: ProviderHistoryDeviceAttestation.migration.name,
                privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                receipt: ProviderHistoryDeviceAttestation.migration.publicationReceipt,
                operationDuration: 10
            ))
            try Self.validatePrivateDirectory(directoryURL)
            try Self.validatePrivateStateFile(stateURL)
        } catch let error as RuntimeMigrationPublicationTestInterruption {
            throw error
        } catch let error as RuntimeMigrationStateError {
            throw error
        } catch {
            throw RuntimeMigrationStateError.persistenceFailed
        }
    }

    private func interruptPublicationIfRequested(
        _ phase: RuntimeMigrationPublicationPhase
    ) throws {
        if publicationInterruption?(phase) == true {
            throw RuntimeMigrationPublicationTestInterruption.simulatedCrash(phase)
        }
    }

    private static func isValid(_ state: State) -> Bool {
        guard state.formatVersion == stateFormatVersion,
              state.providerHistoryPrivacyEpoch == ProviderHistoryPrivacyEpoch.current,
              state.installedVersion.map(isSafeVersion) ?? true,
              state.pendingVersion.map(isSafeVersion) ?? true,
              (state.pendingVersion == nil) == (state.pendingBackupID == nil),
              (state.pendingVersion == nil) == (state.attemptStartedAt == nil) else {
            return false
        }
        return state.attemptStartedAt.map { $0.timeIntervalSinceReferenceDate.isFinite } ?? true
    }

    private static func hasExactCurrentStateSchema(_ object: [String: Any]) -> Bool {
        Set(object.keys) == [
            "formatVersion", "providerHistoryPrivacyEpoch", "installedVersion",
            "pendingVersion", "pendingBackupID", "attemptStartedAt"
        ]
    }

    private static func encodeState(_ state: State) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return try encoder.encode(state)
    }

    private static func decodeState(_ data: Data) throws -> State {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(State.self, from: data)
    }

    private static func isSafeVersion(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
    }

    private static func ensurePrivateDirectory(_ url: URL, fileManager: FileManager) throws {
        var metadata = stat()
        if Darwin.lstat(url.path, &metadata) == 0 {
            guard metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == geteuid(),
                  metadata.st_nlink >= 2,
                  metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                throw RuntimeMigrationStateError.unsafeStorage
            }
        } else if errno == ENOENT {
            try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        } else {
            throw RuntimeMigrationStateError.unsafeStorage
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        try validatePrivateDirectory(url)
    }

    private static func writeAll(_ data: Data, descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard var address = rawBuffer.baseAddress else { return }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, address, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw RuntimeMigrationStateError.persistenceFailed
                }
                guard written > 0 else { throw RuntimeMigrationStateError.persistenceFailed }
                address = address.advanced(by: written)
                remaining -= written
            }
        }
    }

    private static func validatePrivateDirectory(_ url: URL) throws {
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o077 == 0 else {
            throw RuntimeMigrationStateError.unsafeStorage
        }
    }

    private static func validatePrivateStateFile(_ url: URL) throws {
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o077 == 0 else {
            throw RuntimeMigrationStateError.persistenceFailed
        }
    }

    private static func sameIdentity(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_nlink == rhs.st_nlink
            && lhs.st_mode == rhs.st_mode
    }

    private static func jsonInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let double = number.doubleValue
        guard double.isFinite, double.rounded(.towardZero) == double,
              double >= Double(Int.min), double <= Double(Int.max) else {
            return nil
        }
        return Int(double)
    }
}
