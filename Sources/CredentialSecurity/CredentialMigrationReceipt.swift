import CryptoKit
import Darwin
import Foundation

public enum CredentialMigrationReceiptPhase: String, Codable, Sendable {
    case prepared
    case scrubbed
}

public struct CredentialMigrationReceiptEntry: Codable, Equatable, Sendable {
    public let account: String
    public let kind: String
    public let valueSHA256: String

    public init(account: String, kind: String, valueSHA256: String) {
        self.account = account
        self.kind = kind
        self.valueSHA256 = valueSHA256
    }
}

/// Durable, value-free proof that every target was read back from Keychain
/// before the legacy plaintext source crossed its irreversible scrub boundary.
public struct CredentialMigrationReceipt: Codable, Equatable, Sendable {
    public let version: Int
    public let phase: CredentialMigrationReceiptPhase
    public let sourceDevice: UInt64
    public let sourceInode: UInt64
    public let sourceSize: Int64
    public let sourceSHA256: String
    public let references: Int
    public let records: Int
    public let entries: [CredentialMigrationReceiptEntry]

    public init(
        version: Int = 1,
        phase: CredentialMigrationReceiptPhase,
        sourceDevice: UInt64,
        sourceInode: UInt64,
        sourceSize: Int64,
        sourceSHA256: String,
        references: Int,
        records: Int,
        entries: [CredentialMigrationReceiptEntry]
    ) {
        self.version = version
        self.phase = phase
        self.sourceDevice = sourceDevice
        self.sourceInode = sourceInode
        self.sourceSize = sourceSize
        self.sourceSHA256 = sourceSHA256
        self.references = references
        self.records = records
        self.entries = entries
    }

    public func replacingPhase(_ phase: CredentialMigrationReceiptPhase) -> Self {
        Self(
            version: version,
            phase: phase,
            sourceDevice: sourceDevice,
            sourceInode: sourceInode,
            sourceSize: sourceSize,
            sourceSHA256: sourceSHA256,
            references: references,
            records: records,
            entries: entries
        )
    }
}

public enum CredentialMigrationReceiptError: Error, Equatable, Sendable {
    case unsafeDirectory
    case invalidAuthenticationKey
    case invalidReceipt
    case persistenceFailure
}

private struct AuthenticatedCredentialMigrationReceipt: Codable {
    let authentication: String
    let receipt: CredentialMigrationReceipt
}

public final class CredentialMigrationReceiptStore {
    public static let fileName = ".credential-migration-receipt-v1.json"
    private static let temporaryName = ".credential-migration-receipt-v1.tmp"
    private static let maximumBytes = 8 * 1_024 * 1_024

    private let directory: URL
    private let directoryDescriptor: Int32
    private let key: SymmetricKey
    private let ownerID: uid_t

    public init(directory: URL, authenticationKey: Data, ownerID: uid_t = geteuid()) throws {
        guard authenticationKey.count == 32 else {
            throw CredentialMigrationReceiptError.invalidAuthenticationKey
        }
        self.directory = directory.standardizedFileURL
        self.key = SymmetricKey(data: authenticationKey)
        self.ownerID = ownerID
        let descriptor = open(
            self.directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw CredentialMigrationReceiptError.unsafeDirectory
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
        authenticationKey: Data,
        ownerID: uid_t = geteuid()
    ) throws {
        guard authenticationKey.count == 32 else {
            throw CredentialMigrationReceiptError.invalidAuthenticationKey
        }
        self.directory = directoryCapability.url.standardizedFileURL
        self.key = SymmetricKey(data: authenticationKey)
        self.ownerID = ownerID
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

    public func read() throws -> CredentialMigrationReceipt? {
        try validateDirectory()
        let descriptor = Self.fileName.withCString {
            openat(
                directoryDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        defer { _ = close(descriptor) }
        var metadata = stat()
        var named = stat()
        guard fstat(descriptor, &metadata) == 0,
              Self.fileName.withCString({
                  fstatat(directoryDescriptor, $0, &named, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              secureFile(metadata),
              metadata.st_dev == named.st_dev,
              metadata.st_ino == named.st_ino else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        let bytes = try boundedRead(descriptor: descriptor, expected: metadata.st_size)
        var completed = stat()
        var completedNamed = stat()
        guard fstat(descriptor, &completed) == 0,
              Self.fileName.withCString({
                  fstatat(directoryDescriptor, $0, &completedNamed, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              secureFile(completed),
              completed.st_dev == metadata.st_dev,
              completed.st_ino == metadata.st_ino,
              completed.st_size == metadata.st_size,
              completed.st_mtimespec.tv_sec == metadata.st_mtimespec.tv_sec,
              completed.st_mtimespec.tv_nsec == metadata.st_mtimespec.tv_nsec,
              completed.st_ctimespec.tv_sec == metadata.st_ctimespec.tv_sec,
              completed.st_ctimespec.tv_nsec == metadata.st_ctimespec.tv_nsec,
              completedNamed.st_dev == completed.st_dev,
              completedNamed.st_ino == completed.st_ino else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        try validateDirectory()
        guard let document = try? JSONDecoder().decode(
            AuthenticatedCredentialMigrationReceipt.self,
            from: bytes
        ),
              valid(document.receipt),
              let receiptBytes = try? canonical(document.receipt),
              let authentication = Data(hexadecimal: document.authentication),
              authentication.count == 32,
              HMAC<SHA256>.isValidAuthenticationCode(
                authentication,
                authenticating: receiptBytes,
                using: key
              ),
              let canonicalDocument = try? canonical(document),
              canonicalDocument == bytes else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        return document.receipt
    }

    public func write(_ receipt: CredentialMigrationReceipt) throws {
        guard valid(receipt), let receiptBytes = try? canonical(receipt) else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        let authentication = Data(HMAC<SHA256>.authenticationCode(
            for: receiptBytes,
            using: key
        )).hexadecimal
        let document = AuthenticatedCredentialMigrationReceipt(
            authentication: authentication,
            receipt: receipt
        )
        guard let bytes = try? canonical(document), bytes.count <= Self.maximumBytes else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        try validateDirectory()
        if Self.temporaryName.withCString({ unlinkat(directoryDescriptor, $0, 0) }) != 0,
           errno != ENOENT {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        let descriptor = Self.temporaryName.withCString {
            openat(
                directoryDescriptor,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
        }
        guard descriptor >= 0 else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        var closed = false
        defer {
            if !closed { _ = close(descriptor) }
            _ = Self.temporaryName.withCString { unlinkat(directoryDescriptor, $0, 0) }
        }
        var offset = 0
        let wrote = bytes.withUnsafeBytes { storage -> Bool in
            guard let baseAddress = storage.baseAddress else { return false }
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard wrote, fsync(descriptor) == 0 else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        var staged = stat()
        var namedStaged = stat()
        guard fstat(descriptor, &staged) == 0,
              Self.temporaryName.withCString({
                  fstatat(directoryDescriptor, $0, &namedStaged, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              secureFile(staged),
              staged.st_size == off_t(bytes.count),
              staged.st_dev == namedStaged.st_dev,
              staged.st_ino == namedStaged.st_ino else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        guard Self.temporaryName.withCString({ temporary in
            Self.fileName.withCString({ destination in
                renameat(directoryDescriptor, temporary, directoryDescriptor, destination)
            })
        }) == 0 else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        // Keep the staged inode open across rename, then prove the destination
        // name is that exact inode. A same-user process swapping the temporary
        // name can therefore cause a fail-closed error, never a false durable
        // receipt immediately before plaintext truncation.
        var committed = stat()
        var namedCommitted = stat()
        guard fstat(descriptor, &committed) == 0,
              Self.fileName.withCString({
                  fstatat(directoryDescriptor, $0, &namedCommitted, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              secureFile(committed),
              committed.st_size == off_t(bytes.count),
              committed.st_dev == staged.st_dev,
              committed.st_ino == staged.st_ino,
              committed.st_dev == namedCommitted.st_dev,
              committed.st_ino == namedCommitted.st_ino else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        try synchronizeDirectory()
        try validateDirectory()
        var durableNamed = stat()
        guard Self.fileName.withCString({
                  fstatat(directoryDescriptor, $0, &durableNamed, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              durableNamed.st_dev == committed.st_dev,
              durableNamed.st_ino == committed.st_ino,
              close(descriptor) == 0 else {
            closed = true
            throw CredentialMigrationReceiptError.persistenceFailure
        }
        closed = true
    }

    private func valid(_ receipt: CredentialMigrationReceipt) -> Bool {
        let (entryCount, overflow) = receipt.references.addingReportingOverflow(receipt.records)
        guard receipt.version == 1,
              receipt.sourceSize > 0,
              Self.validDigest(receipt.sourceSHA256),
              receipt.references >= 0,
              receipt.records >= 0,
              !overflow,
              receipt.entries.count == entryCount,
              receipt.entries.count <= 4_096,
              receipt.entries == receipt.entries.sorted(by: { $0.account < $1.account }) else {
            return false
        }
        var accounts = Set<String>()
        let entriesAreValid = receipt.entries.allSatisfy {
            !$0.account.isEmpty
                && $0.account.utf8.count <= 4_096
                && accounts.insert($0.account).inserted
                && ($0.kind == "reference" || $0.kind == "api-key" || $0.kind == "grant")
                && Self.validDigest($0.valueSHA256)
        }
        let referenceCount = receipt.entries.lazy.filter { $0.kind == "reference" }.count
        return entriesAreValid
            && receipt.references == referenceCount
            && receipt.records == receipt.entries.count - referenceCount
    }

    private func validateDirectory() throws {
        guard directory.isFileURL,
              directory.path.hasPrefix("/"),
              directory.path == directory.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw CredentialMigrationReceiptError.unsafeDirectory
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
              hasNoExtendedACL(directoryDescriptor) else {
            throw CredentialMigrationReceiptError.unsafeDirectory
        }
    }

    private func secureFile(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == ownerID
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o777 == 0o600
            && metadata.st_size > 0
            && metadata.st_size <= off_t(Self.maximumBytes)
    }

    private func boundedRead(descriptor: Int32, expected: off_t) throws -> Data {
        guard expected > 0, expected <= off_t(Self.maximumBytes) else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        var result = Data()
        result.reserveCapacity(Int(expected))
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while result.count <= Self.maximumBytes {
            let count = buffer.withUnsafeMutableBytes { storage -> Int in
                guard let baseAddress = storage.baseAddress else { return -1 }
                return Darwin.read(
                    descriptor,
                    baseAddress,
                    min(storage.count, Self.maximumBytes + 1 - result.count)
                )
            }
            if count > 0 { result.append(contentsOf: buffer.prefix(count)); continue }
            if count == 0 { break }
            if errno == EINTR { continue }
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        guard result.count == Int(expected), result.count <= Self.maximumBytes else {
            throw CredentialMigrationReceiptError.invalidReceipt
        }
        return result
    }

    private func synchronizeDirectory() throws {
        guard fsync(directoryDescriptor) == 0 else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
    }

    private func canonical<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    private static func validDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(list))
        return false
    }
}

private extension Data {
    init?(hexadecimal: String) {
        guard hexadecimal.count.isMultiple(of: 2) else { return nil }
        var result = Data()
        result.reserveCapacity(hexadecimal.count / 2)
        var index = hexadecimal.startIndex
        while index < hexadecimal.endIndex {
            let next = hexadecimal.index(index, offsetBy: 2)
            guard let byte = UInt8(hexadecimal[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        self = result
    }

    var hexadecimal: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
