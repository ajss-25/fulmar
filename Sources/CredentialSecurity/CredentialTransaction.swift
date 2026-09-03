import CryptoKit
import Darwin
import Dispatch
import Foundation

public struct CredentialMetadata: Codable, Equatable, Sendable {
    public let version: Int
    public let account: String
    public let kind: String

    public init(version: Int = 1, account: String, kind: String) {
        self.version = version
        self.account = account
        self.kind = kind
    }
}

public enum CredentialAttentionReason: String, Codable, Sendable {
    case authorization
    case ambiguous
    case invalid
}

public struct CredentialAttention: Codable, Equatable, Sendable {
    public let account: String
    public let kind: String
    public let reason: CredentialAttentionReason
    public let token: String

    public init(account: String, kind: String, reason: CredentialAttentionReason, token: String) {
        self.account = account
        self.kind = kind
        self.reason = reason
        self.token = token
    }
}

public enum CredentialValueStoreError: Error, Equatable, Sendable {
    case duplicate
    case authorizationRequired
    case status(Int32)
}

public protocol CredentialValueStore {
    func read(account: String) throws -> Data?
    func add(account: String, value: Data) throws
    func replace(account: String, value: Data) throws
    func delete(account: String) throws
}

public enum CredentialTransactionCheckpoint: String, CaseIterable, Sendable {
    case afterJournalPrepared
    case afterValueMutation
    case afterValueVerification
    case afterMetadataCommit
    case afterFinalVerification
    case afterJournalRemoval
}

public enum CredentialFileStateArtifact: String, CaseIterable, Sendable {
    case journal
    case metadata
}

public enum CredentialFileStatePersistenceCheckpoint: String, CaseIterable, Sendable {
    case afterTemporaryWrite
    case afterFileSynchronize
    case afterRename
    case afterDirectorySynchronize
}

public enum CredentialTransactionError: Error, Equatable, Sendable {
    case invalidCredentialKind
    case invalidCredentialValue
    case unsafeState(String)
    case persistenceFailure(String)
    case lockTimedOut
    case verificationFailed
    case ambiguousRecovery
    case recoveryNotRequired
    case recoveryValueMissing
    case conflict
    case batchRollbackIncomplete
}

public enum CredentialAtomicMutation: Sendable {
    case unchanged
    case store(value: Data, kind: String)
}

/// One exact target in the first-start credential migration. The migration
/// coordinator keeps these values in memory only; durable state contains only
/// their SHA-256 digests.
public struct CredentialMigrationBatchEntry: Equatable, Sendable {
    public let account: String
    public let value: Data
    public let kind: String

    public init(account: String, value: Data, kind: String) {
        self.account = account
        self.value = value
        self.kind = kind
    }
}

/// Value-free evidence returned after all targets have been written and read
/// back while the fixed cross-process credential lock is still held.
public struct CredentialMigrationBatchEvidence: Equatable, Sendable {
    public struct Entry: Equatable, Sendable {
        public let account: String
        public let kind: String
        public let valueSHA256: String

        public init(account: String, kind: String, valueSHA256: String) {
            self.account = account
            self.kind = kind
            self.valueSHA256 = valueSHA256
        }
    }

    public let entries: [Entry]

    public init(entries: [Entry]) {
        self.entries = entries
    }
}

private enum CredentialTransactionOperation: String, Codable {
    case store
    case remove
}

private struct SupersededCredentialTransactionJournal: Codable {
    let kind: String
    let operation: CredentialTransactionOperation
    let previousMetadataKind: String?
    let previousValueSHA256: String?
    let targetValueSHA256: String?
}

private struct CredentialTransactionJournal: Codable {
    let version: Int
    let account: String
    let kind: String
    let operation: CredentialTransactionOperation
    let previousMetadataKind: String?
    let previousValueSHA256: String?
    let targetValueSHA256: String?
    let superseded: SupersededCredentialTransactionJournal?

    init(
        version: Int = 1,
        account: String,
        kind: String,
        operation: CredentialTransactionOperation,
        previousMetadataKind: String?,
        previousValueSHA256: String?,
        targetValueSHA256: String?,
        superseded: SupersededCredentialTransactionJournal? = nil
    ) {
        self.version = version
        self.account = account
        self.kind = kind
        self.operation = operation
        self.previousMetadataKind = previousMetadataKind
        self.previousValueSHA256 = previousValueSHA256
        self.targetValueSHA256 = targetValueSHA256
        self.superseded = superseded
    }

    var snapshot: SupersededCredentialTransactionJournal {
        SupersededCredentialTransactionJournal(
            kind: kind,
            operation: operation,
            previousMetadataKind: previousMetadataKind,
            previousValueSHA256: previousValueSHA256,
            targetValueSHA256: targetValueSHA256
        )
    }

    static func restoring(
        account: String,
        snapshot: SupersededCredentialTransactionJournal
    ) -> CredentialTransactionJournal {
        CredentialTransactionJournal(
            account: account,
            kind: snapshot.kind,
            operation: snapshot.operation,
            previousMetadataKind: snapshot.previousMetadataKind,
            previousValueSHA256: snapshot.previousValueSHA256,
            targetValueSHA256: snapshot.targetValueSHA256
        )
    }
}

/// Owner-only metadata and journal storage with bounded process-crash recovery.
/// This does not claim physical-power-loss durability or APFS replay coverage. The directory is
/// supplied by the caller so the helper can retain its existing legacy storage
/// location while tests use an isolated temporary home.
public final class CredentialFileStateStore {
    public typealias PersistenceCheckpointHandler = (
        CredentialFileStateArtifact,
        CredentialFileStatePersistenceCheckpoint
    ) throws -> Void

    private let directory: URL
    private let directoryDescriptor: Int32
    private let ownerID: uid_t
    private let persistenceCheckpoint: PersistenceCheckpointHandler
    private let maximumStateBytes = 16_384
    private let maximumDirectoryEntries = 4_096
    private let maximumDirectoryEnumerationNanoseconds: UInt64 = 2_000_000_000

    public init(
        directory: URL,
        ownerID: uid_t = geteuid(),
        persistenceCheckpoint: @escaping PersistenceCheckpointHandler = { _, _ in }
    ) throws {
        self.directory = directory
        self.ownerID = ownerID
        self.persistenceCheckpoint = persistenceCheckpoint
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw CredentialTransactionError.unsafeState("credential metadata directory is unsafe")
        }
        self.directoryDescriptor = descriptor
        do {
            try validateDirectory()
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    public init(
        directoryCapability: CredentialPrivateDirectoryCapability,
        ownerID: uid_t = geteuid(),
        persistenceCheckpoint: @escaping PersistenceCheckpointHandler = { _, _ in }
    ) throws {
        self.directory = directoryCapability.url
        self.ownerID = ownerID
        self.persistenceCheckpoint = persistenceCheckpoint
        let descriptor = try directoryCapability.duplicateDescriptor()
        self.directoryDescriptor = descriptor
        do {
            try validateDirectory()
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    deinit { _ = close(directoryDescriptor) }

    public func readMetadata(account: String) throws -> CredentialMetadata? {
        guard let data = try readFile(metadataURL(account: account), maximumBytes: 4_096) else { return nil }
        guard let decoded = try? JSONDecoder().decode(CredentialMetadata.self, from: data),
              decoded.version == 1,
              decoded.account == account,
              Self.validKind(decoded.kind) else {
            throw CredentialTransactionError.unsafeState("credential metadata is invalid")
        }
        return decoded
    }

    public func writeMetadata(account: String, kind: String) throws {
        guard Self.validKind(kind) else { throw CredentialTransactionError.invalidCredentialKind }
        let payload = CredentialMetadata(account: account, kind: kind)
        guard let data = try? JSONEncoder().encode(payload), data.count <= 4_096 else {
            throw CredentialTransactionError.persistenceFailure("credential metadata could not be encoded")
        }
        try atomicWrite(
            data,
            destination: metadataURL(account: account),
            temporary: metadataTemporaryURL(account: account),
            artifact: .metadata
        )
    }

    public func removeMetadata(account: String) throws {
        try removeFileIfPresent(metadataURL(account: account))
    }

    fileprivate func listMetadata() throws -> [CredentialMetadata] {
        let entries = try boundedDirectoryEntries(skippingHidden: true)
        var result: [CredentialMetadata] = []
        for entry in entries where Self.isMetadataFilename(entry.lastPathComponent) {
            guard let data = try readFile(entry, maximumBytes: 4_096),
                  let decoded = try? JSONDecoder().decode(CredentialMetadata.self, from: data),
                  decoded.version == 1,
                  Self.validKind(decoded.kind),
                  entry.lastPathComponent == metadataURL(account: decoded.account).lastPathComponent else {
                throw CredentialTransactionError.unsafeState("credential metadata is invalid")
            }
            result.append(decoded)
        }
        return result
    }

    fileprivate func listMetadataIsolatingInvalidEntries() throws -> [CredentialMetadata] {
        let entries = try boundedDirectoryEntries(skippingHidden: true)
        var result: [CredentialMetadata] = []
        for entry in entries where Self.isMetadataFilename(entry.lastPathComponent) {
            guard let data = (try? readFile(entry, maximumBytes: 4_096)) ?? nil,
                  let decoded = try? JSONDecoder().decode(CredentialMetadata.self, from: data),
                  decoded.version == 1, Self.validKind(decoded.kind),
                  entry.lastPathComponent == metadataURL(account: decoded.account).lastPathComponent else {
                continue
            }
            result.append(decoded)
        }
        return result
    }

    fileprivate func withAccountLock<T>(account: String, _ body: () throws -> T) throws -> T {
        try withTransactionLock(cleaningAccounts: [account], body)
    }

    fileprivate func withExtendedAccountLock<T>(account: String, _ body: () throws -> T) throws -> T {
        try withTransactionLock(cleaningAccounts: [account], acquisitionAttempts: 3_000, body)
    }

    fileprivate func withCatalogLock<T>(_ body: () throws -> T) throws -> T {
        try withTransactionLock(cleaningAccounts: [], body)
    }

    /// Credential mutations are infrequent and catalogue reads must observe a
    /// coherent state. One fixed owner-only lock avoids an unbounded permanent
    /// lock file for every reference while serializing recovery, enumeration,
    /// and mutation across independent helper processes.
    private func withTransactionLock<T>(
        cleaningAccounts: [String],
        acquisitionAttempts: Int = 500,
        _ body: () throws -> T
    ) throws -> T {
        try validateDirectory()
        let lock = lockURL()
        let lockName = try fileName(lock)
        var descriptor = lockName.withCString {
            openat(directoryDescriptor, $0, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        }
        var created = false
        if descriptor < 0, errno == ENOENT {
            descriptor = lockName.withCString {
                openat(
                    directoryDescriptor,
                    $0,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    S_IRUSR | S_IWUSR
                )
            }
            created = descriptor >= 0
            if descriptor < 0, errno == EEXIST {
                descriptor = lockName.withCString {
                    openat(directoryDescriptor, $0, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
                }
            }
        }
        guard descriptor >= 0 else {
            throw CredentialTransactionError.persistenceFailure("credential transaction lock could not be opened")
        }
        defer { _ = close(descriptor) }
        _ = try validateOpenFile(
            descriptor,
            name: lockName,
            maximumBytes: maximumStateBytes,
            allowEmpty: true
        )
        if created { try synchronizeDirectory() }

        var acquired = false
        for _ in 0..<acquisitionAttempts {
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                acquired = true
                break
            }
            guard errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR else {
                throw CredentialTransactionError.persistenceFailure("credential transaction lock failed")
            }
            usleep(10_000)
        }
        guard acquired else { throw CredentialTransactionError.lockTimedOut }
        defer { _ = flock(descriptor, LOCK_UN) }

        // The pathname must still identify the exact locked inode after flock.
        // Recheck again before returning so an unlink/recreate race cannot be
        // silently accepted as a successfully serialized transaction.
        _ = try validateOpenFile(
            descriptor,
            name: lockName,
            maximumBytes: maximumStateBytes,
            allowEmpty: true
        )

        // A killed writer can leave a hidden staging file before rename. The
        // fixed global lock proves no cooperating writer is live, so sweep only
        // the two exact hash-derived temporary filename forms under the same
        // bounded directory budget before any recovery or catalogue read.
        try sweepStaleTemporaryFiles()
        for account in cleaningAccounts {
            try removeTemporaryFiles(account: account)
        }
        do {
            let result = try body()
            _ = try validateOpenFile(
                descriptor,
                name: lockName,
                maximumBytes: maximumStateBytes,
                allowEmpty: true
            )
            return result
        } catch {
            do {
                _ = try validateOpenFile(
                    descriptor,
                    name: lockName,
                    maximumBytes: maximumStateBytes,
                    allowEmpty: true
                )
            } catch {
                throw error
            }
            throw error
        }
    }

    fileprivate func readJournal(account: String) throws -> CredentialTransactionJournal? {
        guard let data = try readFile(journalURL(account: account), maximumBytes: maximumStateBytes) else { return nil }
        guard let decoded = try? JSONDecoder().decode(CredentialTransactionJournal.self, from: data),
              decoded.version == 1 || decoded.version == 2,
              decoded.account == account,
              Self.validKind(decoded.kind),
              Self.validDigest(decoded.previousValueSHA256),
              Self.validDigest(decoded.targetValueSHA256),
              (decoded.operation == .store) == (decoded.targetValueSHA256 != nil),
              (decoded.version == 2) == (decoded.superseded != nil) else {
            throw CredentialTransactionError.unsafeState("credential transaction journal is invalid")
        }
        if let previousKind = decoded.previousMetadataKind, !Self.validKind(previousKind) {
            throw CredentialTransactionError.unsafeState("credential transaction journal is invalid")
        }
        if let superseded = decoded.superseded {
            guard Self.validKind(superseded.kind),
                  Self.validDigest(superseded.previousValueSHA256),
                  Self.validDigest(superseded.targetValueSHA256),
                  (superseded.operation == .store) == (superseded.targetValueSHA256 != nil),
                  superseded.previousMetadataKind.map(Self.validKind) ?? true else {
                throw CredentialTransactionError.unsafeState("credential transaction journal is invalid")
            }
        }
        return decoded
    }

    fileprivate func writeJournal(_ journal: CredentialTransactionJournal) throws {
        guard let data = try? JSONEncoder().encode(journal), data.count <= maximumStateBytes else {
            throw CredentialTransactionError.persistenceFailure("credential transaction journal could not be encoded")
        }
        try atomicWrite(
            data,
            destination: journalURL(account: journal.account),
            temporary: journalTemporaryURL(account: journal.account),
            artifact: .journal
        )
    }

    fileprivate func removeJournal(account: String) throws {
        try removeFileIfPresent(journalURL(account: account))
    }

    fileprivate func pendingAccounts() throws -> [String] {
        let entries = try boundedDirectoryEntries(skippingHidden: true)
        var result: [String] = []
        for entry in entries where Self.isJournalFilename(entry.lastPathComponent) {
            guard let data = try readFile(entry, maximumBytes: maximumStateBytes),
                  let preliminary = try? JSONDecoder().decode(
                      CredentialTransactionJournal.self,
                      from: data
                  ),
                  entry.lastPathComponent == journalURL(account: preliminary.account).lastPathComponent,
                  let journal = try readJournal(account: preliminary.account),
                  journal.account == preliminary.account else {
                throw CredentialTransactionError.unsafeState("credential transaction journal is invalid")
            }
            result.append(journal.account)
        }
        return result
    }

    fileprivate func pendingAccountsIsolatingInvalidEntries() throws -> [String] {
        let entries = try boundedDirectoryEntries(skippingHidden: true)
        var result: [String] = []
        for entry in entries where Self.isJournalFilename(entry.lastPathComponent) {
            guard let data = (try? readFile(entry, maximumBytes: maximumStateBytes)) ?? nil,
                  let preliminary = try? JSONDecoder().decode(CredentialTransactionJournal.self, from: data),
                  entry.lastPathComponent == journalURL(account: preliminary.account).lastPathComponent,
                  let journal = try? readJournal(account: preliminary.account),
                  journal.account == preliminary.account else {
                continue
            }
            result.append(journal.account)
        }
        return result
    }

    private static func validKind(_ kind: String) -> Bool {
        kind == "reference" || kind == "api-key" || kind == "grant"
    }

    private static func validDigest(_ digest: String?) -> Bool {
        guard let digest else { return true }
        return digest.count == 64 && digest.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        }
    }

    private static func isMetadataFilename(_ name: String) -> Bool {
        guard name.count == 69, name.hasSuffix(".json") else { return false }
        return validDigest(String(name.dropLast(5)))
    }

    private static func isJournalFilename(_ name: String) -> Bool {
        let suffix = ".transaction.json"
        guard name.count == 64 + suffix.count, name.hasSuffix(suffix) else { return false }
        return validDigest(String(name.dropLast(suffix.count)))
    }

    private func validateDirectory() throws {
        let standardized = directory.standardizedFileURL.path
        let resolved = directory.resolvingSymlinksInPath().standardizedFileURL.path
        guard directory.path == standardized, resolved == standardized else {
            throw CredentialTransactionError.unsafeState("credential metadata directory is unsafe")
        }
        var metadata = stat()
        var named = stat()
        guard fstat(directoryDescriptor, &metadata) == 0,
              lstat(directory.path, &named) == 0,
              metadata.st_dev == named.st_dev,
              metadata.st_ino == named.st_ino,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == ownerID,
              metadata.st_mode & 0o777 == 0o700,
              Self.descriptorHasNoExtendedACL(directoryDescriptor) else {
            throw CredentialTransactionError.unsafeState("credential metadata directory is unsafe")
        }
    }

    private func digest(for account: String) -> String {
        SHA256.hash(data: Data(account.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func metadataURL(account: String) -> URL {
        directory.appendingPathComponent(digest(for: account) + ".json", isDirectory: false)
    }

    private func journalURL(account: String) -> URL {
        directory.appendingPathComponent(digest(for: account) + ".transaction.json", isDirectory: false)
    }

    private func lockURL() -> URL {
        directory.appendingPathComponent(".credential-transactions.lock", isDirectory: false)
    }

    private func metadataTemporaryURL(account: String) -> URL {
        directory.appendingPathComponent(".\(digest(for: account)).metadata.tmp", isDirectory: false)
    }

    private func journalTemporaryURL(account: String) -> URL {
        directory.appendingPathComponent(".\(digest(for: account)).transaction.tmp", isDirectory: false)
    }

    fileprivate func removeTemporaryFiles(account: String) throws {
        try removeFileIfPresent(metadataTemporaryURL(account: account))
        try removeFileIfPresent(journalTemporaryURL(account: account))
    }

    private func readFile(_ url: URL, maximumBytes: Int) throws -> Data? {
        try validateDirectory()
        let name = try fileName(url)
        var pathMetadata = stat()
        if name.withCString({
            fstatat(directoryDescriptor, $0, &pathMetadata, AT_SYMLINK_NOFOLLOW)
        }) != 0 {
            if errno == ENOENT { return nil }
            throw CredentialTransactionError.persistenceFailure("credential state could not be inspected")
        }
        try validateFileMetadata(pathMetadata, maximumBytes: maximumBytes, allowEmpty: false)
        let descriptor = name.withCString {
            openat(directoryDescriptor, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be opened")
        }
        defer { _ = close(descriptor) }
        let openedMetadata = try validateOpenFile(
            descriptor,
            name: name,
            maximumBytes: maximumBytes,
            allowEmpty: false
        )

        // Size the read from the inode that was actually opened, not the
        // pre-open pathname observation. A concurrent atomic rename must never
        // make us read the old file's length from the new file descriptor.
        let size = Int(openedMetadata.st_size)
        var data = Data(count: size)
        var offset = 0
        let readAll = data.withUnsafeMutableBytes { storage -> Bool in
            guard let baseAddress = storage.baseAddress else { return false }
            while offset < size {
                let count = Darwin.read(descriptor, baseAddress.advanced(by: offset), size - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard readAll else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be read")
        }
        let completedMetadata = try validateOpenFile(
            descriptor,
            name: name,
            maximumBytes: maximumBytes,
            allowEmpty: false
        )
        guard completedMetadata.st_size == openedMetadata.st_size,
              completedMetadata.st_mtimespec.tv_sec == openedMetadata.st_mtimespec.tv_sec,
              completedMetadata.st_mtimespec.tv_nsec == openedMetadata.st_mtimespec.tv_nsec,
              completedMetadata.st_ctimespec.tv_sec == openedMetadata.st_ctimespec.tv_sec,
              completedMetadata.st_ctimespec.tv_nsec == openedMetadata.st_ctimespec.tv_nsec else {
            throw CredentialTransactionError.unsafeState("credential state changed while reading")
        }
        return data
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

    private func boundedDirectoryEntries(skippingHidden: Bool) throws -> [URL] {
        try validateDirectory()
        let duplicate = fcntl(directoryDescriptor, F_DUPFD_CLOEXEC, 3)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 { _ = close(duplicate) }
            throw CredentialTransactionError.persistenceFailure("credential state could not be listed")
        }
        defer { _ = closedir(stream) }
        // The duplicated descriptor shares its directory seek offset with the
        // retained state descriptor, and a previous enumeration leaves that
        // shared offset at end-of-directory. Every listing must start from
        // the first entry, so rewind the fresh stream explicitly.
        rewinddir(stream)
        let started = DispatchTime.now().uptimeNanoseconds
        var entries: [URL] = []
        errno = 0
        while let rawEntry = readdir(stream) {
            guard let name = Self.boundedDirectoryEntryName(rawEntry) else {
                throw CredentialTransactionError.unsafeState("credential state directory contains an unsafe entry")
            }
            if name == "." || name == ".." || (skippingHidden && name.hasPrefix(".")) {
                errno = 0
                continue
            }
            guard validFileName(name) else {
                throw CredentialTransactionError.unsafeState("credential state directory contains an unsafe entry")
            }
            entries.append(directory.appendingPathComponent(name, isDirectory: false))
            let elapsed = DispatchTime.now().uptimeNanoseconds - started
            guard entries.count <= maximumDirectoryEntries,
                  elapsed <= maximumDirectoryEnumerationNanoseconds else {
                throw CredentialTransactionError.unsafeState("credential state directory exceeds safe bounds")
            }
            errno = 0
        }
        guard errno == 0 else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be listed")
        }
        try validateDirectory()
        return entries
    }

    private func sweepStaleTemporaryFiles() throws {
        let entries = try boundedDirectoryEntries(skippingHidden: false)
        let stale = entries.filter { Self.isTemporaryFilename($0.lastPathComponent) }
        guard !stale.isEmpty else { return }
        for entry in stale {
            try removeFileIfPresent(entry)
        }
    }

    private static func isTemporaryFilename(_ name: String) -> Bool {
        let metadataSuffix = ".metadata.tmp"
        let journalSuffix = ".transaction.tmp"
        guard name.hasPrefix(".") else { return false }
        if name.count == 1 + 64 + metadataSuffix.count, name.hasSuffix(metadataSuffix) {
            return validDigest(String(name.dropFirst().dropLast(metadataSuffix.count)))
        }
        if name.count == 1 + 64 + journalSuffix.count, name.hasSuffix(journalSuffix) {
            return validDigest(String(name.dropFirst().dropLast(journalSuffix.count)))
        }
        return false
    }

    private func atomicWrite(
        _ data: Data,
        destination: URL,
        temporary: URL,
        artifact: CredentialFileStateArtifact
    ) throws {
        try validateDirectory()
        let destinationName = try fileName(destination)
        let temporaryName = try fileName(temporary)
        try removeFileIfPresent(temporary)
        let descriptor = temporaryName.withCString {
            openat(
                directoryDescriptor,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
        }
        guard descriptor >= 0 else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be staged")
        }
        var closed = false
        defer {
            if !closed { _ = close(descriptor) }
            _ = temporaryName.withCString { unlinkat(directoryDescriptor, $0, 0) }
        }
        var offset = 0
        let wroteAll = data.withUnsafeBytes { storage -> Bool in
            guard let baseAddress = storage.baseAddress else { return false }
            while offset < data.count {
                let count = Darwin.write(descriptor, baseAddress.advanced(by: offset), data.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard wroteAll else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be written")
        }
        try persistenceCheckpoint(artifact, .afterTemporaryWrite)
        guard fsync(descriptor) == 0 else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be synchronized")
        }
        try persistenceCheckpoint(artifact, .afterFileSynchronize)
        let staged = try validateOpenFile(
            descriptor,
            name: temporaryName,
            maximumBytes: maximumStateBytes,
            allowEmpty: false
        )
        guard staged.st_size == off_t(data.count) else {
            throw CredentialTransactionError.persistenceFailure("credential state staging size changed")
        }
        guard temporaryName.withCString({ temporaryPointer in
            destinationName.withCString({ destinationPointer in
                renameat(
                    directoryDescriptor,
                    temporaryPointer,
                    directoryDescriptor,
                    destinationPointer
                )
            })
        }) == 0 else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be committed")
        }
        let committed = try validateOpenFile(
            descriptor,
            name: destinationName,
            maximumBytes: maximumStateBytes,
            allowEmpty: false
        )
        guard committed.st_dev == staged.st_dev,
              committed.st_ino == staged.st_ino,
              committed.st_size == staged.st_size else {
            throw CredentialTransactionError.unsafeState("credential state staging inode changed")
        }
        try persistenceCheckpoint(artifact, .afterRename)
        _ = try validateOpenFile(
            descriptor,
            name: destinationName,
            maximumBytes: maximumStateBytes,
            allowEmpty: false
        )
        try synchronizeDirectory()
        try persistenceCheckpoint(artifact, .afterDirectorySynchronize)
        let durable = try validateOpenFile(
            descriptor,
            name: destinationName,
            maximumBytes: maximumStateBytes,
            allowEmpty: false
        )
        guard durable.st_dev == committed.st_dev,
              durable.st_ino == committed.st_ino,
              close(descriptor) == 0 else {
            closed = true
            throw CredentialTransactionError.persistenceFailure("credential state could not be closed")
        }
        closed = true
    }

    private func removeFileIfPresent(_ url: URL) throws {
        try validateDirectory()
        let name = try fileName(url)
        let descriptor = name.withCString {
            openat(directoryDescriptor, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        if descriptor < 0 {
            if errno == ENOENT { return }
            throw CredentialTransactionError.persistenceFailure("credential state could not be inspected")
        }
        defer { _ = close(descriptor) }
        let opened = try validateOpenFile(
            descriptor,
            name: name,
            maximumBytes: maximumStateBytes,
            allowEmpty: true
        )
        guard name.withCString({ unlinkat(directoryDescriptor, $0, 0) }) == 0 else {
            throw CredentialTransactionError.persistenceFailure("credential state could not be removed")
        }
        var unlinked = stat()
        guard fstat(descriptor, &unlinked) == 0,
              unlinked.st_dev == opened.st_dev,
              unlinked.st_ino == opened.st_ino,
              unlinked.st_nlink == 0 else {
            throw CredentialTransactionError.unsafeState("credential state name changed while removing")
        }
        try synchronizeDirectory()
    }

    @discardableResult
    private func validateOpenFile(
        _ descriptor: Int32,
        name: String,
        maximumBytes: Int,
        allowEmpty: Bool
    ) throws -> stat {
        var descriptorMetadata = stat()
        var pathMetadata = stat()
        guard fstat(descriptor, &descriptorMetadata) == 0,
              name.withCString({
                  fstatat(directoryDescriptor, $0, &pathMetadata, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              descriptorMetadata.st_dev == pathMetadata.st_dev,
              descriptorMetadata.st_ino == pathMetadata.st_ino else {
            throw CredentialTransactionError.unsafeState("credential state changed while opening")
        }
        try validateFileMetadata(descriptorMetadata, maximumBytes: maximumBytes, allowEmpty: allowEmpty)
        return descriptorMetadata
    }

    private func fileName(_ url: URL) throws -> String {
        let parent = url.deletingLastPathComponent().standardizedFileURL
        let name = url.lastPathComponent
        guard url.isFileURL,
              url.path == url.standardizedFileURL.path,
              parent == directory.standardizedFileURL,
              validFileName(name) else {
            throw CredentialTransactionError.unsafeState("credential state path is unsafe")
        }
        return name
    }

    private func validFileName(_ name: String) -> Bool {
        !name.isEmpty
            && name != "."
            && name != ".."
            && name.utf8.count <= Int(MAXNAMLEN)
            && !name.contains("/")
            && !name.contains("\0")
    }

    private func validateFileMetadata(_ metadata: stat, maximumBytes: Int, allowEmpty: Bool) throws {
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == ownerID,
              metadata.st_nlink == 1,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size >= (allowEmpty ? 0 : 1),
              metadata.st_size <= maximumBytes else {
            throw CredentialTransactionError.unsafeState("credential state is unsafe")
        }
    }

    private func synchronizeDirectory() throws {
        try validateDirectory()
        guard fsync(directoryDescriptor) == 0 else {
            throw CredentialTransactionError.persistenceFailure("credential metadata directory could not be synchronized")
        }
    }

    private static func descriptorHasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(list))
        return false
    }
}

public final class CredentialTransactionCoordinator {
    public typealias CheckpointHandler = (CredentialTransactionCheckpoint) throws -> Void

    private struct MigrationBatchSnapshot {
        let value: Data?
        let metadataKind: String?
    }

    private let stateStore: CredentialFileStateStore
    private let valueStore: any CredentialValueStore
    private let checkpoint: CheckpointHandler

    public init(
        stateStore: CredentialFileStateStore,
        valueStore: any CredentialValueStore,
        checkpoint: @escaping CheckpointHandler = { _ in }
    ) {
        self.stateStore = stateStore
        self.valueStore = valueStore
        self.checkpoint = checkpoint
    }

    public func recover(account: String) throws {
        try stateStore.withAccountLock(account: account) {
            try recoverLocked(account: account)
        }
    }

    public func recoverAll() throws {
        try stateStore.withCatalogLock {
            for account in try stateStore.pendingAccounts() {
                try stateStore.removeTemporaryFiles(account: account)
                try recoverLocked(account: account)
            }
        }
    }

    public func metadata(account: String) throws -> CredentialMetadata? {
        try stateStore.withAccountLock(account: account) {
            try recoverLocked(account: account)
            return try stateStore.readMetadata(account: account)
        }
    }

    public func readConfiguredValue(account: String) throws -> Data? {
        try stateStore.withAccountLock(account: account) {
            try recoverLocked(account: account)
            guard try stateStore.readMetadata(account: account) != nil else { return nil }
            guard let value = try valueStore.read(account: account) else {
                // A pre-transaction legacy crash can leave a marker without a
                // Keychain item. Repair that old state the first time it is
                // actually resolved; an ACL denial still throws and preserves
                // metadata for the foreground repair flow.
                try stateStore.removeMetadata(account: account)
                return nil
            }
            return value
        }
    }

    public func listCommittedMetadata() throws -> [CredentialMetadata] {
        try stateStore.withCatalogLock {
            var accountsNeedingAttention = Set<String>()
            for account in try stateStore.pendingAccounts() {
                try stateStore.removeTemporaryFiles(account: account)
                do {
                    try recoverLocked(account: account)
                } catch CredentialTransactionError.ambiguousRecovery {
                    // One externally changed credential must not hide every
                    // other provider. Keep its journal intact and omit only
                    // that account from the committed catalogue until the
                    // user completes an explicit foreground repair.
                    accountsNeedingAttention.insert(account)
                } catch CredentialValueStoreError.authorizationRequired {
                    // An ACL transition is likewise isolated to the exact
                    // affected record. Its explicit describe/read path remains
                    // fail-closed and surfaces foreground recovery.
                    accountsNeedingAttention.insert(account)
                }
            }
            return try stateStore.listMetadata().filter {
                !accountsNeedingAttention.contains($0.account)
            }
        }
    }

    /// Returns only value-free accounts that require deliberate foreground
    /// attention. The fixed catalogue lock bounds and serializes both pending
    /// journal recovery and the no-journal ACL probe; credential bytes and
    /// journal digests never leave this coordinator.
    public func listAttention(
        validateValue: ((Data, String) -> Bool)? = nil
    ) throws -> [CredentialAttention] {
        try stateStore.withCatalogLock {
            var attention: [String: CredentialAttention] = [:]
            for account in try stateStore.pendingAccountsIsolatingInvalidEntries() {
                try stateStore.removeTemporaryFiles(account: account)
                do {
                    try recoverLocked(account: account)
                } catch CredentialTransactionError.ambiguousRecovery {
                    let journal = try stateStore.readJournal(account: account)
                    let metadata = try stateStore.readMetadata(account: account)
                    if let kind = metadata?.kind ?? journal?.kind {
                        let current = try? valueStore.read(account: account)
                        attention[account] = CredentialAttention(
                            account: account,
                            kind: kind,
                            reason: .ambiguous,
                            token: Self.attentionToken(account: account, kind: kind, reason: .ambiguous, value: current ?? nil)
                        )
                    }
                } catch CredentialValueStoreError.authorizationRequired {
                    let journal = try stateStore.readJournal(account: account)
                    let metadata = try stateStore.readMetadata(account: account)
                    if let kind = metadata?.kind ?? journal?.kind {
                        attention[account] = CredentialAttention(
                            account: account,
                            kind: kind,
                            reason: .authorization,
                            token: Self.attentionToken(account: account, kind: kind, reason: .authorization, value: nil)
                        )
                    }
                }
            }
            for metadata in try stateStore.listMetadataIsolatingInvalidEntries()
            where attention[metadata.account] == nil {
                do {
                    guard let value = try valueStore.read(account: metadata.account) else {
                        // Reconcile a pre-transaction legacy marker while the
                        // same fixed catalogue lock still excludes writers.
                        try stateStore.removeMetadata(account: metadata.account)
                        continue
                    }
                    if let validateValue, !validateValue(value, metadata.kind) {
                        attention[metadata.account] = CredentialAttention(
                            account: metadata.account,
                            kind: metadata.kind,
                            reason: .invalid,
                            token: Self.attentionToken(account: metadata.account, kind: metadata.kind, reason: .invalid, value: value)
                        )
                    }
                } catch CredentialValueStoreError.authorizationRequired {
                    attention[metadata.account] = CredentialAttention(
                        account: metadata.account,
                        kind: metadata.kind,
                        reason: .authorization,
                        token: Self.attentionToken(account: metadata.account, kind: metadata.kind, reason: .authorization, value: nil)
                    )
                }
            }
            return attention.values.sorted { lhs, rhs in lhs.account < rhs.account }
        }
    }

    public static func attentionToken(
        account: String,
        kind: String,
        reason: CredentialAttentionReason,
        value: Data?
    ) -> String {
        var material = Data("fulmar-attention-v1\0\(account)\0\(kind)\0\(reason.rawValue)\0".utf8)
        if let value { material.append(contentsOf: SHA256.hash(data: value)) }
        return SHA256.hash(data: material).map { String(format: "%02x", $0) }.joined()
    }

    public func adoptUntrackedCurrentRecord(
        account: String,
        validateKind: (Data) throws -> String?
    ) throws {
        try stateStore.withAccountLock(account: account) {
            guard try stateStore.readJournal(account: account) == nil,
                  try stateStore.readMetadata(account: account) == nil,
                  let current = try valueStore.read(account: account),
                  let kind = try validateKind(current),
                  kind == "api-key" || kind == "grant" else {
                throw CredentialTransactionError.conflict
            }
            try storeLocked(
                account: account,
                value: current,
                kind: kind,
                knownPreviousValue: .some(current)
            )
        }
    }

    public func store(account: String, value: Data, kind: String) throws {
        guard !value.isEmpty, value.count <= 1_048_576 else {
            throw CredentialTransactionError.invalidCredentialValue
        }
        guard kind == "reference" || kind == "api-key" || kind == "grant" else {
            throw CredentialTransactionError.invalidCredentialKind
        }
        try stateStore.withAccountLock(account: account) {
            try recoverLocked(account: account)
            try storeLocked(account: account, value: value, kind: kind)
        }
    }

    /// Migrates a complete credential set under the same fixed catalogue lock.
    /// Raw pre-existing values (including values with no metadata) are captured
    /// immediately before their mutation and never leave memory. If validation
    /// or the caller's pre-commit boundary throws, rollback is conditional: an
    /// out-of-band third value is preserved and reported instead of overwritten.
    ///
    /// The callback must throw only while its work is still reversible. Once it
    /// has crossed an irreversible boundary (for example, truncating the legacy
    /// plaintext source), it must return a typed post-commit outcome instead.
    public func withAtomicMigrationBatch<T>(
        entries: [CredentialMigrationBatchEntry],
        afterVerification: (CredentialMigrationBatchEvidence) throws -> T
    ) throws -> T {
        guard entries.count <= 4_096 else {
            throw CredentialTransactionError.invalidCredentialValue
        }
        var seen = Set<String>()
        for entry in entries {
            guard !entry.account.isEmpty,
                  entry.account.utf8.count <= 4_096,
                  seen.insert(entry.account).inserted,
                  !entry.value.isEmpty,
                  entry.value.count <= 1_048_576,
                  entry.kind == "reference" || entry.kind == "api-key" || entry.kind == "grant" else {
                throw CredentialTransactionError.invalidCredentialValue
            }
        }

        return try stateStore.withCatalogLock {
            var snapshots: [String: MigrationBatchSnapshot] = [:]
            snapshots.reserveCapacity(entries.count)
            for entry in entries {
                try recoverLocked(account: entry.account)
                snapshots[entry.account] = MigrationBatchSnapshot(
                    value: try valueStore.read(account: entry.account),
                    metadataKind: try stateStore.readMetadata(account: entry.account)?.kind
                )
            }

            var changed: [CredentialMigrationBatchEntry] = []
            do {
                for entry in entries {
                    guard let snapshot = snapshots[entry.account] else {
                        throw CredentialTransactionError.unsafeState(
                            "credential migration snapshot is missing"
                        )
                    }
                    // Reconfirm the raw value and exact metadata presence at
                    // the last point before the cooperating Keychain writer
                    // mutates this account. The fixed catalogue lock excludes
                    // every app/helper/service writer; an out-of-band third
                    // value observed here is preserved and aborts the batch.
                    guard try valueStore.read(account: entry.account) == snapshot.value,
                          try stateStore.readMetadata(account: entry.account)?.kind
                            == snapshot.metadataKind else {
                        throw CredentialTransactionError.conflict
                    }
                    changed.append(entry)
                    try storeLocked(
                        account: entry.account,
                        value: entry.value,
                        kind: entry.kind,
                        knownPreviousValue: .some(snapshot.value)
                    )
                }
                for entry in entries {
                    guard try valueStore.read(account: entry.account) == entry.value,
                          try stateStore.readMetadata(account: entry.account)?.kind == entry.kind else {
                        throw CredentialTransactionError.verificationFailed
                    }
                }
                let evidence = CredentialMigrationBatchEvidence(entries: entries
                    .map {
                        CredentialMigrationBatchEvidence.Entry(
                            account: $0.account,
                            kind: $0.kind,
                            valueSHA256: Self.sha256($0.value)
                        )
                    }
                    .sorted { $0.account < $1.account })
                return try afterVerification(evidence)
            } catch {
                var rollbackIncomplete = false
                for entry in changed.reversed() {
                    guard let snapshot = snapshots[entry.account] else {
                        rollbackIncomplete = true
                        continue
                    }
                    do {
                        try recoverLocked(account: entry.account)
                        let current = try valueStore.read(account: entry.account)
                        if current != snapshot.value {
                            guard current == entry.value else {
                                throw CredentialTransactionError.conflict
                            }
                            if let previous = snapshot.value {
                                try valueStore.replace(account: entry.account, value: previous)
                            } else {
                                try valueStore.delete(account: entry.account)
                            }
                        }
                        guard try valueStore.read(account: entry.account) == snapshot.value else {
                            throw CredentialTransactionError.verificationFailed
                        }
                        if let kind = snapshot.metadataKind {
                            try stateStore.writeMetadata(account: entry.account, kind: kind)
                        } else {
                            try stateStore.removeMetadata(account: entry.account)
                        }
                        guard try stateStore.readMetadata(account: entry.account)?.kind
                                == snapshot.metadataKind else {
                            throw CredentialTransactionError.verificationFailed
                        }
                    } catch {
                        rollbackIncomplete = true
                    }
                }
                if rollbackIncomplete {
                    throw CredentialTransactionError.batchRollbackIncomplete
                }
                throw error
            }
        }
    }

    /// Verifies one authenticated migration receipt against both the raw
    /// Keychain bytes and committed metadata while the fixed catalogue lock
    /// excludes helper mutations. No credential bytes leave this method.
    public func verifyMigrationEvidence(_ evidence: CredentialMigrationBatchEvidence) throws -> Bool {
        guard evidence.entries.count <= 4_096,
              evidence.entries == evidence.entries.sorted(by: { $0.account < $1.account }) else {
            return false
        }
        var seen = Set<String>()
        return try stateStore.withCatalogLock {
            for entry in evidence.entries {
                guard !entry.account.isEmpty,
                      seen.insert(entry.account).inserted,
                      entry.kind == "reference" || entry.kind == "api-key" || entry.kind == "grant" else {
                    return false
                }
                try recoverLocked(account: entry.account)
                guard let value = try valueStore.read(account: entry.account),
                      Self.sha256(value) == entry.valueSHA256,
                      try stateStore.readMetadata(account: entry.account)?.kind == entry.kind else {
                    return false
                }
            }
            return true
        }
    }

    /// Runs a record's read-decide-replace transformation while the fixed
    /// cross-process credential lock remains held. This is the primitive DSH's
    /// `modifyRecord` contract requires; a per-JavaScript-instance promise
    /// queue cannot prevent two independent runtimes from losing a rotated
    /// refresh token.
    @discardableResult
    public func modifyAtomically(
        account: String,
        mutation: (Data?) throws -> CredentialAtomicMutation
    ) throws -> Data? {
        try stateStore.withExtendedAccountLock(account: account) {
            try recoverLocked(account: account)
            let observed = try valueStore.read(account: account)
            switch try mutation(observed) {
            case .unchanged:
                return observed
            case .store(let value, let kind):
                guard try valueStore.read(account: account) == observed else {
                    throw CredentialTransactionError.conflict
                }
                guard !value.isEmpty, value.count <= 1_048_576 else {
                    throw CredentialTransactionError.invalidCredentialValue
                }
                guard kind == "reference" || kind == "api-key" || kind == "grant" else {
                    throw CredentialTransactionError.invalidCredentialKind
                }
                try storeLocked(
                    account: account,
                    value: value,
                    kind: kind,
                    knownPreviousValue: .some(observed)
                )
                return value
            }
        }
    }

    private func storeLocked(
        account: String,
        value: Data,
        kind: String,
        knownPreviousValue: Data?? = nil
    ) throws {
            let previousMetadata = try stateStore.readMetadata(account: account)
            var previousValue = try knownPreviousValue ?? valueStore.read(account: account)
            var journal = CredentialTransactionJournal(
                version: 1,
                account: account,
                kind: kind,
                operation: .store,
                previousMetadataKind: previousMetadata?.kind,
                previousValueSHA256: previousValue.map(Self.sha256),
                targetValueSHA256: Self.sha256(value)
            )
            try stateStore.writeJournal(journal)
            try checkpoint(.afterJournalPrepared)

            do {
                if previousValue == nil {
                    do {
                        try valueStore.add(account: account, value: value)
                    } catch CredentialValueStoreError.duplicate {
                        guard let racedValue = try valueStore.read(account: account) else {
                            throw CredentialTransactionError.verificationFailed
                        }
                        previousValue = racedValue
                        journal = CredentialTransactionJournal(
                            version: 1,
                            account: account,
                            kind: kind,
                            operation: .store,
                            previousMetadataKind: previousMetadata?.kind,
                            previousValueSHA256: Self.sha256(racedValue),
                            targetValueSHA256: Self.sha256(value)
                        )
                        try stateStore.writeJournal(journal)
                        try checkpoint(.afterJournalPrepared)
                        try valueStore.replace(account: account, value: value)
                    }
                } else {
                    try valueStore.replace(account: account, value: value)
                }
            } catch {
                try? stateStore.removeJournal(account: account)
                throw error
            }
            try checkpoint(.afterValueMutation)

            let verified = try valueStore.read(account: account)
            guard verified == value else {
                // Security.framework mutations are atomic. If the exact old
                // value is still present, the mutation did not commit and the
                // journal can be retired. An unexpected third value indicates
                // an out-of-band writer; never overwrite or delete it while
                // attempting an unsafe rollback.
                if verified == previousValue {
                    try restorePreviousMetadata(
                        account: account,
                        previousMetadataKind: previousMetadata?.kind,
                        previousValueWasPresent: previousValue != nil
                    )
                    try stateStore.removeJournal(account: account)
                }
                throw CredentialTransactionError.verificationFailed
            }
            try checkpoint(.afterValueVerification)
            try stateStore.writeMetadata(account: account, kind: kind)
            try checkpoint(.afterMetadataCommit)
            guard try valueStore.read(account: account) == value else {
                // Metadata is not authoritative until the exact Keychain value
                // is re-read after commit. Preserve the journal so a prior
                // value can be restored safely and a third value enters the
                // explicit foreground-repair path.
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterFinalVerification)
            try stateStore.removeJournal(account: account)
            try checkpoint(.afterJournalRemoval)
    }

    public func remove(account: String) throws {
        try stateStore.withAccountLock(account: account) {
            try recoverLocked(account: account)
            guard let previousMetadata = try stateStore.readMetadata(account: account) else { return }
            guard let previousValue = try valueStore.read(account: account) else {
                try stateStore.removeMetadata(account: account)
                return
            }
            let journal = CredentialTransactionJournal(
                version: 1,
                account: account,
                kind: previousMetadata.kind,
                operation: .remove,
                previousMetadataKind: previousMetadata.kind,
                previousValueSHA256: Self.sha256(previousValue),
                targetValueSHA256: nil
            )
            try stateStore.writeJournal(journal)
            try checkpoint(.afterJournalPrepared)
            do {
                try valueStore.delete(account: account)
            } catch {
                try? stateStore.removeJournal(account: account)
                throw error
            }
            try checkpoint(.afterValueMutation)
            if let verified = try valueStore.read(account: account) {
                if verified == previousValue {
                    try stateStore.removeJournal(account: account)
                    throw CredentialTransactionError.verificationFailed
                }
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterValueVerification)
            try stateStore.removeMetadata(account: account)
            try checkpoint(.afterMetadataCommit)
            guard try valueStore.read(account: account) == nil else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterFinalVerification)
            try stateStore.removeJournal(account: account)
            try checkpoint(.afterJournalRemoval)
        }
    }

    /// Explicit foreground repair for a journal whose current Keychain value
    /// matches neither the prior nor intended digest. The caller must obtain a
    /// fresh user-authorized read through its value store; no secret bytes or
    /// digest leave this coordinator.
    public func repairAdoptingCurrentValue(account: String, kind: String) throws {
        guard kind == "reference" || kind == "api-key" || kind == "grant" else {
            throw CredentialTransactionError.invalidCredentialKind
        }
        try repairAdoptingCurrentValueLocked(account: account) { _ in kind }
    }

    /// Adopts a record only after its kind has been derived from and validated
    /// against the freshly read value while the transaction lock is held.
    public func repairAdoptingCurrentRecord(
        account: String,
        validateKind: (Data) throws -> String?
    ) throws {
        try repairAdoptingCurrentValueLocked(account: account, validateKind: validateKind)
    }

    private func repairAdoptingCurrentValueLocked(
        account: String,
        validateKind: (Data) throws -> String?
    ) throws {
        try stateStore.withAccountLock(account: account) {
            let context = try ambiguousRepairContextLocked(account: account)
            guard let currentValue = context.currentValue else {
                throw CredentialTransactionError.recoveryValueMissing
            }
            guard let kind = try validateKind(currentValue),
                  kind == "reference" || kind == "api-key" || kind == "grant" else {
                throw CredentialTransactionError.invalidCredentialKind
            }
            let digest = Self.sha256(currentValue)
            let repair = CredentialTransactionJournal(
                version: 2,
                account: account,
                kind: kind,
                operation: .store,
                previousMetadataKind: context.metadata?.kind,
                previousValueSHA256: digest,
                targetValueSHA256: digest,
                superseded: context.journal.snapshot
            )
            try stateStore.writeJournal(repair)
            try checkpoint(.afterJournalPrepared)
            try checkpoint(.afterValueMutation)
            guard try valueStore.read(account: account) == currentValue else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterValueVerification)
            try stateStore.writeMetadata(account: account, kind: kind)
            try checkpoint(.afterMetadataCommit)
            guard try valueStore.read(account: account) == currentValue else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterFinalVerification)
            try stateStore.removeJournal(account: account)
            try checkpoint(.afterJournalRemoval)
        }
    }

    public func repairReplacingCurrentValue(account: String, value: Data, kind: String) throws {
        guard !value.isEmpty, value.count <= 1_048_576 else {
            throw CredentialTransactionError.invalidCredentialValue
        }
        guard kind == "reference" || kind == "api-key" || kind == "grant" else {
            throw CredentialTransactionError.invalidCredentialKind
        }
        try stateStore.withAccountLock(account: account) {
            let context = try ambiguousRepairContextLocked(account: account)
            let repair = CredentialTransactionJournal(
                version: 2,
                account: account,
                kind: kind,
                operation: .store,
                previousMetadataKind: context.metadata?.kind,
                previousValueSHA256: context.currentValue.map(Self.sha256),
                targetValueSHA256: Self.sha256(value),
                superseded: context.journal.snapshot
            )
            try stateStore.writeJournal(repair)
            try checkpoint(.afterJournalPrepared)
            if context.currentValue == nil {
                try valueStore.add(account: account, value: value)
            } else {
                try valueStore.replace(account: account, value: value)
            }
            try checkpoint(.afterValueMutation)
            guard try valueStore.read(account: account) == value else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterValueVerification)
            try stateStore.writeMetadata(account: account, kind: kind)
            try checkpoint(.afterMetadataCommit)
            guard try valueStore.read(account: account) == value else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterFinalVerification)
            try stateStore.removeJournal(account: account)
            try checkpoint(.afterJournalRemoval)
        }
    }

    public func repairRemovingCurrentValue(account: String, kind: String) throws {
        guard kind == "reference" || kind == "api-key" || kind == "grant" else {
            throw CredentialTransactionError.invalidCredentialKind
        }
        try repairRemovingCurrentValueLocked(account: account, kind: kind)
    }

    public func repairRemovingCurrentRecord(
        account: String,
        expectedToken: String,
        validateKind: (Data) throws -> String?,
        declaredKind: ((Data) throws -> String?)? = nil
    ) throws {
        guard expectedToken.count == 64,
              expectedToken.allSatisfy({ $0.isHexDigit }) else {
            throw CredentialTransactionError.conflict
        }
        try stateStore.withAccountLock(account: account) {
            if try stateStore.readJournal(account: account) != nil {
                let context = try ambiguousRepairContextLocked(account: account)
                let kind = context.metadata?.kind ?? context.journal.kind
                let token = Self.attentionToken(
                    account: account, kind: kind, reason: .ambiguous, value: context.currentValue
                )
                guard token == expectedToken else { throw CredentialTransactionError.conflict }
                try repairRemovingCurrentValueLocked(account: account, kind: kind, context: context)
                return
            }
            let metadata = try stateStore.readMetadata(account: account)
            guard let current = try valueStore.read(account: account) else {
                throw CredentialTransactionError.conflict
            }
            let validKind = try validateKind(current)
            let observedKind: String?
            if let declaredKind { observedKind = try declaredKind(current) }
            else { observedKind = validKind }
            // `unknown` is a value-free presentation kind for a malformed,
            // metadata-less record. It must only support state-bound removal and
            // is never committed to metadata or exposed to adopt/authorize paths.
            let tokenKind = metadata?.kind ?? observedKind ?? "unknown"
            let reason: CredentialAttentionReason
            if metadata == nil {
                let ambiguousToken = Self.attentionToken(
                    account: account, kind: tokenKind, reason: .ambiguous, value: current
                )
                reason = observedKind != nil && ambiguousToken == expectedToken ? .ambiguous : .invalid
            } else {
                reason = .invalid
            }
            if let metadata, validKind == metadata.kind {
                throw CredentialTransactionError.conflict
            }
            let token = Self.attentionToken(
                account: account, kind: tokenKind, reason: reason, value: current
            )
            guard token == expectedToken else { throw CredentialTransactionError.conflict }
            // Removal journals require a schema-valid transaction kind, but that
            // kind is never committed during removal. Use a fixed internal tag
            // only when the corrupt record has no trustworthy declared kind.
            let journalKind = metadata?.kind ?? observedKind ?? "grant"
            let journal = CredentialTransactionJournal(
                account: account,
                kind: journalKind,
                operation: .remove,
                previousMetadataKind: metadata?.kind,
                previousValueSHA256: Self.sha256(current),
                targetValueSHA256: nil
            )
            try stateStore.writeJournal(journal)
            try checkpoint(.afterJournalPrepared)
            try valueStore.delete(account: account)
            try checkpoint(.afterValueMutation)
            guard try valueStore.read(account: account) == nil else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterValueVerification)
            try stateStore.removeMetadata(account: account)
            try checkpoint(.afterMetadataCommit)
            guard try valueStore.read(account: account) == nil else {
                throw CredentialTransactionError.ambiguousRecovery
            }
            try checkpoint(.afterFinalVerification)
            try stateStore.removeJournal(account: account)
            try checkpoint(.afterJournalRemoval)
        }
    }

    private func repairRemovingCurrentValueLocked(account: String, kind: String) throws {
        try stateStore.withAccountLock(account: account) {
            let context = try ambiguousRepairContextLocked(account: account)
            try repairRemovingCurrentValueLocked(account: account, kind: kind, context: context)
        }
    }

    private func repairRemovingCurrentValueLocked(
        account: String,
        kind: String,
        context: (journal: CredentialTransactionJournal, currentValue: Data?, metadata: CredentialMetadata?)
    ) throws {
        let repair = CredentialTransactionJournal(
            version: 2,
            account: account,
            kind: kind,
            operation: .remove,
            previousMetadataKind: context.metadata?.kind,
            previousValueSHA256: context.currentValue.map(Self.sha256),
            targetValueSHA256: nil,
            superseded: context.journal.snapshot
        )
        try stateStore.writeJournal(repair)
        try checkpoint(.afterJournalPrepared)
        try valueStore.delete(account: account)
        try checkpoint(.afterValueMutation)
        guard try valueStore.read(account: account) == nil else {
            throw CredentialTransactionError.ambiguousRecovery
        }
        try checkpoint(.afterValueVerification)
        try stateStore.removeMetadata(account: account)
        try checkpoint(.afterMetadataCommit)
        guard try valueStore.read(account: account) == nil else {
            throw CredentialTransactionError.ambiguousRecovery
        }
        try checkpoint(.afterFinalVerification)
        try stateStore.removeJournal(account: account)
        try checkpoint(.afterJournalRemoval)
    }

    private func ambiguousRepairContextLocked(
        account: String
    ) throws -> (journal: CredentialTransactionJournal, currentValue: Data?, metadata: CredentialMetadata?) {
        guard let journal = try stateStore.readJournal(account: account) else {
            throw CredentialTransactionError.recoveryNotRequired
        }
        let current = try valueStore.read(account: account)
        let observedDigest = current.map(Self.sha256)
        let resolvesNormally: Bool
        switch journal.operation {
        case .store:
            resolvesNormally = observedDigest == journal.targetValueSHA256
                || observedDigest == journal.previousValueSHA256
        case .remove:
            resolvesNormally = current == nil || observedDigest == journal.previousValueSHA256
        }
        if resolvesNormally {
            try recoverLocked(account: account)
            throw CredentialTransactionError.recoveryNotRequired
        }
        return (journal, current, try stateStore.readMetadata(account: account))
    }

    private func recoverLocked(account: String) throws {
        guard let journal = try stateStore.readJournal(account: account) else { return }
        let observedValue = try valueStore.read(account: account)
        let observedDigest = observedValue.map(Self.sha256)

        switch journal.operation {
        case .store:
            if observedDigest == journal.targetValueSHA256 {
                try stateStore.writeMetadata(account: account, kind: journal.kind)
            } else if observedDigest == journal.previousValueSHA256 {
                if let superseded = journal.superseded {
                    try stateStore.writeJournal(.restoring(account: account, snapshot: superseded))
                    try recoverLocked(account: account)
                    return
                }
                try restorePreviousMetadata(
                    account: account,
                    previousMetadataKind: journal.previousMetadataKind,
                    previousValueWasPresent: journal.previousValueSHA256 != nil
                )
            } else {
                throw CredentialTransactionError.ambiguousRecovery
            }
        case .remove:
            if observedValue == nil {
                try stateStore.removeMetadata(account: account)
            } else if observedDigest == journal.previousValueSHA256 {
                if let superseded = journal.superseded {
                    try stateStore.writeJournal(.restoring(account: account, snapshot: superseded))
                    try recoverLocked(account: account)
                    return
                }
                try restorePreviousMetadata(
                    account: account,
                    previousMetadataKind: journal.previousMetadataKind,
                    previousValueWasPresent: true
                )
            } else {
                throw CredentialTransactionError.ambiguousRecovery
            }
        }
        try stateStore.removeJournal(account: account)
    }

    private func restorePreviousMetadata(
        account: String,
        previousMetadataKind: String?,
        previousValueWasPresent: Bool
    ) throws {
        if previousValueWasPresent, let previousMetadataKind {
            try stateStore.writeMetadata(account: account, kind: previousMetadataKind)
        } else {
            try stateStore.removeMetadata(account: account)
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
