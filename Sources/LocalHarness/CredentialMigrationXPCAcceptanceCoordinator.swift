import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol

enum CredentialMigrationXPCAcceptanceError: Error, Equatable, Sendable {
    case invalidConfiguration
    case unsafeFixture
    case invalidResponse
    case cleanupFailed
}

/// One bounded packaged-service canary. Its fresh UUID namespace contains only
/// two empty files under /private/tmp, and the service's acceptance operation
/// creates and removes one empty UUID metadata canary, then returns before
/// JavaScriptCore or Keychain is reached.
/// This deliberately exercises the app/service mutual code requirement, XPC
/// class boundary, exact request schema, sandbox startup, descriptor transfer,
/// timeout gate, response schema, and post-reply inode revalidation without
/// using a provider reference or any user credential value.
enum CredentialMigrationXPCAcceptanceCoordinator {
    static let launchArgument = "--credential-migration-xpc-acceptance"
    static let defaultDeadline: TimeInterval = 5

    typealias Invocation = (
        _ sourceURL: URL,
        _ lease: CredentialMigrationInheritedDescriptor,
        _ nonce: String
    ) throws -> CredentialMigrationXPCResponse

    static func run(
        serviceBundleURL: URL,
        helperURL: URL,
        deadline: TimeInterval = defaultDeadline
    ) throws {
        guard deadline.isFinite, deadline >= 0.05, deadline <= 10 else {
            throw CredentialMigrationXPCAcceptanceError.invalidConfiguration
        }
        try exercise { sourceURL, lease, nonce in
            try CredentialMigrationXPCClient.runAcceptance(
                serviceBundleURL: serviceBundleURL,
                helperURL: helperURL,
                sourceURL: sourceURL,
                leaseDescriptor: lease,
                acceptanceNonce: nonce,
                deadline: deadline
            )
        }
    }

    /// Injection seam for deterministic isolated tests. Production calls the
    /// overload above, whose invocation is fixed to the packaged XPC client.
    static func exercise(invocation: Invocation) throws {
        let fixture = try AcceptanceFixture.create()
        do {
            let response = try invocation(fixture.sourceURL, fixture.lease, fixture.nonce)
            guard response.version == CredentialMigrationXPCConstants.protocolVersion,
                  response.status == .success,
                  response.references == 0,
                  response.records == 0 else {
                throw CredentialMigrationXPCAcceptanceError.invalidResponse
            }
            try fixture.cleanup()
        } catch {
            try? fixture.cleanup()
            throw error
        }
    }
}

private final class AcceptanceFixture {
    let rootURL: URL
    let sourceURL: URL
    let nonce: String
    let lease: CredentialMigrationInheritedDescriptor

    private let rootDescriptor: Int32
    private var leaseDescriptor: Int32
    private var cleaned = false

    private init(
        rootURL: URL,
        sourceURL: URL,
        nonce: String,
        rootDescriptor: Int32,
        leaseDescriptor: Int32,
        leaseDevice: UInt64,
        leaseInode: UInt64
    ) {
        self.rootURL = rootURL
        self.sourceURL = sourceURL
        self.nonce = nonce
        self.rootDescriptor = rootDescriptor
        self.leaseDescriptor = leaseDescriptor
        self.lease = CredentialMigrationInheritedDescriptor(
            sourceDescriptor: leaseDescriptor,
            expectedDevice: leaseDevice,
            expectedInode: leaseInode
        )
    }

    deinit {
        if leaseDescriptor >= 0 { _ = close(leaseDescriptor) }
        _ = close(rootDescriptor)
    }

    static func create() throws -> AcceptanceFixture {
        let nonce = UUID().uuidString.lowercased()
        let rootURL = URL(
            fileURLWithPath: "/private/tmp/"
                + CredentialMigrationXPCConstants.acceptanceDirectoryPrefix
                + nonce,
            isDirectory: true
        ).standardizedFileURL
        guard rootURL.path == "/private/tmp/"
                + CredentialMigrationXPCConstants.acceptanceDirectoryPrefix + nonce,
              mkdir(rootURL.path, S_IRWXU) == 0 else {
            throw CredentialMigrationXPCAcceptanceError.unsafeFixture
        }

        let root = open(rootURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else {
            _ = rmdir(rootURL.path)
            throw CredentialMigrationXPCAcceptanceError.unsafeFixture
        }
        var rootOwned = true
        defer { if rootOwned { _ = close(root) } }
        var completed = false
        defer {
            if !completed {
                _ = CredentialMigrationXPCConstants.acceptanceSourceName.withCString {
                    unlinkat(root, $0, 0)
                }
                _ = CredentialMigrationXPCConstants.leaseFileName.withCString {
                    unlinkat(root, $0, 0)
                }
                _ = fsync(root)
                _ = rmdir(rootURL.path)
            }
        }

        var rootMetadata = stat()
        var namedRoot = stat()
        guard fstat(root, &rootMetadata) == 0,
              lstat(rootURL.path, &namedRoot) == 0,
              rootMetadata.st_dev == namedRoot.st_dev,
              rootMetadata.st_ino == namedRoot.st_ino,
              rootMetadata.st_mode & S_IFMT == S_IFDIR,
              rootMetadata.st_uid == geteuid(),
              rootMetadata.st_mode & 0o777 == 0o700,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(root) else {
            _ = close(root)
            rootOwned = false
            _ = rmdir(rootURL.path)
            throw CredentialMigrationXPCAcceptanceError.unsafeFixture
        }

        let sourceName = CredentialMigrationXPCConstants.acceptanceSourceName
        let source = sourceName.withCString {
            openat(root, $0, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        }
        guard source >= 0 else {
            throw CredentialMigrationXPCAcceptanceError.unsafeFixture
        }
        var sourceOwned = true
        defer { if sourceOwned { _ = close(source) } }

        let lease = CredentialMigrationXPCConstants.leaseFileName.withCString {
            openat(root, $0, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        }
        guard lease >= 0 else {
            throw CredentialMigrationXPCAcceptanceError.unsafeFixture
        }
        var leaseOwned = true
        defer { if leaseOwned { _ = close(lease) } }

        var sourceMetadata = stat()
        var namedSource = stat()
        var leaseMetadata = stat()
        var namedLease = stat()
        guard fstat(source, &sourceMetadata) == 0,
              fstat(lease, &leaseMetadata) == 0,
              sourceName.withCString({
                  fstatat(root, $0, &namedSource, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              CredentialMigrationXPCConstants.leaseFileName.withCString({
                  fstatat(root, $0, &namedLease, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              secureEmptyFile(sourceMetadata),
              secureEmptyFile(leaseMetadata),
              sourceMetadata.st_dev == namedSource.st_dev,
              sourceMetadata.st_ino == namedSource.st_ino,
              leaseMetadata.st_dev == namedLease.st_dev,
              leaseMetadata.st_ino == namedLease.st_ino,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(source),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(lease),
              flock(lease, LOCK_EX | LOCK_NB) == 0,
              fsync(source) == 0,
              fsync(lease) == 0,
              fsync(root) == 0,
              close(source) == 0 else {
            throw CredentialMigrationXPCAcceptanceError.unsafeFixture
        }
        sourceOwned = false
        rootOwned = false
        leaseOwned = false
        completed = true
        return AcceptanceFixture(
            rootURL: rootURL,
            sourceURL: rootURL.appendingPathComponent(sourceName, isDirectory: false),
            nonce: nonce,
            rootDescriptor: root,
            leaseDescriptor: lease,
            leaseDevice: UInt64(truncatingIfNeeded: leaseMetadata.st_dev),
            leaseInode: UInt64(leaseMetadata.st_ino)
        )
    }

    func cleanup() throws {
        guard !cleaned else { return }
        var descriptorMetadata = stat()
        var namedMetadata = stat()
        guard fstat(rootDescriptor, &descriptorMetadata) == 0,
              lstat(rootURL.path, &namedMetadata) == 0,
              descriptorMetadata.st_dev == namedMetadata.st_dev,
              descriptorMetadata.st_ino == namedMetadata.st_ino,
              descriptorMetadata.st_mode & S_IFMT == S_IFDIR,
              descriptorMetadata.st_uid == geteuid(),
              descriptorMetadata.st_mode & 0o777 == 0o700,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(rootDescriptor) else {
            throw CredentialMigrationXPCAcceptanceError.cleanupFailed
        }
        guard CredentialMigrationXPCConstants.acceptanceSourceName.withCString({
                  unlinkat(rootDescriptor, $0, 0)
              }) == 0,
              CredentialMigrationXPCConstants.leaseFileName.withCString({
                  unlinkat(rootDescriptor, $0, 0)
              }) == 0,
              fsync(rootDescriptor) == 0 else {
            throw CredentialMigrationXPCAcceptanceError.cleanupFailed
        }
        _ = flock(leaseDescriptor, LOCK_UN)
        guard close(leaseDescriptor) == 0 else {
            leaseDescriptor = -1
            throw CredentialMigrationXPCAcceptanceError.cleanupFailed
        }
        leaseDescriptor = -1
        guard rmdir(rootURL.path) == 0 else {
            throw CredentialMigrationXPCAcceptanceError.cleanupFailed
        }
        cleaned = true
    }

    private static func secureEmptyFile(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o777 == 0o600
            && metadata.st_size == 0
    }
}
