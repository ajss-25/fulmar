import Darwin
import Foundation
import LocalHarnessDeviceAttestation

enum DeviceAttestationTrustRecoveryError: LocalizedError, Equatable, Sendable {
    case notRecoverable
    case unsafeApplicationSupport
    case unsafeRecoveryStorage
    case confirmedStateChanged
    case destructiveKeyStoreUnavailable
    case injectedInterruption(Int)

    var errorDescription: String? {
        switch self {
        case .notRecoverable:
            return "Device trust recovery is not applicable to this failure."
        case .unsafeApplicationSupport:
            return "The private application-support directory is linked, shared, or otherwise unsafe. No state was changed."
        case .unsafeRecoveryStorage:
            return "A private device-trust recovery directory could not be created safely. Existing data was retained."
        case .confirmedStateChanged:
            return "Private provider state changed after confirmation. Recovery stopped and every item already preserved was retained."
        case .destructiveKeyStoreUnavailable:
            return "The device-attestation Keychain store cannot perform the exact foreground repair. Provider work remained stopped."
        case .injectedInterruption:
            return "The test interrupted device-trust recovery."
        }
    }
}

private struct DeviceTrustOpaqueIdentity: Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
    let kind: UInt16
    let owner: UInt32
    let permissions: UInt16
    let linkCount: UInt64

    init(_ metadata: stat) {
        device = UInt64(truncatingIfNeeded: metadata.st_dev)
        inode = UInt64(metadata.st_ino)
        kind = UInt16(metadata.st_mode & S_IFMT)
        owner = metadata.st_uid
        permissions = UInt16(metadata.st_mode & 0o7777)
        linkCount = UInt64(metadata.st_nlink)
    }

    func matches(_ metadata: stat) -> Bool { self == Self(metadata) }
}

struct DeviceAttestationTrustRecoveryRequest: Equatable, Sendable {
    fileprivate struct Node: Equatable, Sendable {
        let leafName: String
        let identity: DeviceTrustOpaqueIdentity?
    }

    fileprivate let applicationSupport: URL
    fileprivate let applicationSupportIdentity: DeviceTrustOpaqueIdentity
    fileprivate let nodes: [Node]
    fileprivate let controlState: DeviceAttestationAuthority.BootstrapRecoveryControlState
}

struct DeviceAttestationTrustRecoveryReceipt: Equatable, Sendable {
    let recoveryOperation: URL
    let preservedLeaves: [String]
}

/// Explicit foreground repair for an interrupted or inconsistent device trust
/// bootstrap. Detection is read-only and Keychain-free. Mutation moves each
/// exact provider/history namespace whole into a new, private, same-volume
/// operation directory before the authority receives the narrow capability to
/// delete its two exact Keychain accounts. Old operations are never enumerated,
/// adopted, overwritten, acknowledged automatically, or deleted.
final class DeviceAttestationTrustRecoveryCoordinator: @unchecked Sendable {
    private static let recoveryLeafName = DeviceAttestationAuthority.recoveryGuardLeafName
    private static let sourceLeaves = [
        "HarnessHome",
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        ProviderHistoryDeviceAttestation.backups.leafName,
        ProviderHistoryDeviceAttestation.stateRecovery.leafName,
        ProviderHistoryDeviceAttestation.migration.leafName,
        ProviderHistoryDeviceAttestation.migrationStagingLeafName,
        "ProviderHistoryAuxiliaryRecovery",
        ".provider-history-auxiliary-transaction"
    ]

    private let applicationSupport: URL
    private let configuration: DeviceAttestationAuthority.Configuration
    private let keyStore: any DeviceAttestationKeyStore
    private let makeUUID: @Sendable () -> UUID
    private let interruption: (@Sendable (Int) -> Bool)?

    init(
        applicationSupport: URL,
        keyStore: any DeviceAttestationKeyStore,
        makeUUID: @escaping @Sendable () -> UUID = { UUID() },
        interruption: (@Sendable (Int) -> Bool)? = nil
    ) {
        self.applicationSupport = applicationSupport.standardizedFileURL
        configuration = ProviderHistoryDeviceAttestation.configuration(
            applicationSupport: applicationSupport.standardizedFileURL
        )
        self.keyStore = keyStore
        self.makeUUID = makeUUID
        self.interruption = interruption
    }

    static func isRecoverable(_ error: Error) -> Bool {
        guard let error = error as? DeviceAttestationError else { return false }
        switch error {
        case .privateKeyMissing, .publicAnchorMissing, .keyMaterialMismatch,
             .untrustedPreexistingPublicKey, .bootstrapRecoveryRequired:
            return true
        default:
            return false
        }
    }

    /// Detection-only. No directory creation, Keychain access, enumeration, or
    /// child read occurs. Each known whole-root name is probed exactly once.
    func inspect() throws -> DeviceAttestationTrustRecoveryRequest {
        let support = try openAbsolutePrivateDirectory(applicationSupport)
        defer { Darwin.close(support) }
        let supportIdentity = try privateDirectoryIdentity(support)
        let nodes = try Self.sourceLeaves.map { leaf in
            DeviceAttestationTrustRecoveryRequest.Node(
                leafName: leaf,
                identity: try opaqueIdentityIfPresent(leaf, beneath: support)
            )
        }
        let control = try DeviceAttestationAuthority.bootstrapRecoveryControlState(
            configuration: configuration
        )
        return DeviceAttestationTrustRecoveryRequest(
            applicationSupport: applicationSupport,
            applicationSupportIdentity: supportIdentity,
            nodes: nodes,
            controlState: control
        )
    }

    /// Must be invoked only after an exact foreground user confirmation and
    /// with local/provider runtimes stopped. A failure never removes recovery
    /// output and never resumes provider work.
    func recoverAfterExplicitConfirmation(
        _ request: DeviceAttestationTrustRecoveryRequest
    ) throws -> (DeviceAttestationTrustRecoveryReceipt, DeviceAttestationAuthority) {
        guard request.applicationSupport == applicationSupport,
              let recoverable = keyStore as? any DeviceAttestationRecoverableKeyStore else {
            throw DeviceAttestationTrustRecoveryError.destructiveKeyStoreUnavailable
        }
        let support = try openAbsolutePrivateDirectory(applicationSupport)
        defer { Darwin.close(support) }
        guard request.applicationSupportIdentity == (try privateDirectoryIdentity(support)) else {
            throw DeviceAttestationTrustRecoveryError.confirmedStateChanged
        }
        try validateNodes(request.nodes, beneath: support)

        let recovery = try openOrCreatePrivateChild(
            Self.recoveryLeafName,
            beneath: support
        )
        defer { Darwin.close(recovery) }
        let operationName = "operation-" + makeUUID().uuidString.lowercased()
        let operation = try createPrivateChild(operationName, beneath: recovery)
        defer { Darwin.close(operation) }
        guard flock(operation, LOCK_EX | LOCK_NB) == 0 else {
            throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
        }
        defer { _ = flock(operation, LOCK_UN) }

        var preserved = [String]()
        for (index, node) in request.nodes.enumerated() {
            guard let expected = node.identity else { continue }
            var current = stat()
            guard node.leafName.withCString({
                fstatat(support, $0, &current, AT_SYMLINK_NOFOLLOW)
            }) == 0,
                  expected.matches(current),
                  try opaqueIdentityIfPresent(node.leafName, beneath: operation) == nil else {
                throw DeviceAttestationTrustRecoveryError.confirmedStateChanged
            }
            let status = node.leafName.withCString { source in
                node.leafName.withCString { destination in
                    renameat(support, source, operation, destination)
                }
            }
            guard status == 0,
                  fsync(support) == 0,
                  fsync(operation) == 0,
                  let moved = try opaqueIdentityIfPresent(node.leafName, beneath: operation),
                  moved == expected else {
                throw DeviceAttestationTrustRecoveryError.confirmedStateChanged
            }
            preserved.append(node.leafName)
            if interruption?(index) == true {
                throw DeviceAttestationTrustRecoveryError.injectedInterruption(index)
            }
        }

        // All confirmed roots must now be absent, including those absent at
        // prompt time. A late writer cannot be silently carried into the new
        // trust generation.
        for node in request.nodes {
            guard try opaqueIdentityIfPresent(node.leafName, beneath: support) == nil else {
                throw DeviceAttestationTrustRecoveryError.confirmedStateChanged
            }
        }

        let recoveryURL = applicationSupport
            .appendingPathComponent(Self.recoveryLeafName, isDirectory: true)
            .appendingPathComponent(operationName, isDirectory: true)
        let authorization = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
            configuration: configuration,
            recoveryOperationRoot: recoveryURL,
            expectedControlState: request.controlState
        )
        let authority = try DeviceAttestationAuthority.recoverForeground(
            configuration: configuration,
            keyStore: recoverable,
            authorization: authorization
        )
        return (
            DeviceAttestationTrustRecoveryReceipt(
                recoveryOperation: recoveryURL,
                preservedLeaves: preserved
            ),
            authority
        )
    }

    private func validateNodes(
        _ nodes: [DeviceAttestationTrustRecoveryRequest.Node],
        beneath support: Int32
    ) throws {
        guard nodes.count == Self.sourceLeaves.count,
              nodes.map(\.leafName) == Self.sourceLeaves else {
            throw DeviceAttestationTrustRecoveryError.confirmedStateChanged
        }
        for node in nodes {
            guard try opaqueIdentityIfPresent(node.leafName, beneath: support) == node.identity else {
                throw DeviceAttestationTrustRecoveryError.confirmedStateChanged
            }
        }
    }
}

private func openAbsolutePrivateDirectory(_ url: URL) throws -> Int32 {
    guard url.isFileURL,
          url.standardizedFileURL.path == url.path,
          url.path.hasPrefix("/") else {
        throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
    }
    var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard descriptor >= 0 else {
        throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
    }
    do {
        for component in url.path.split(separator: "/").map(String.init) {
            guard validRecoveryLeaf(component) else {
                throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
            }
            let next = component.withCString {
                openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            }
            guard next >= 0 else {
                throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
            }
            Darwin.close(descriptor)
            descriptor = next
        }
        _ = try privateDirectoryIdentity(descriptor)
        return descriptor
    } catch {
        Darwin.close(descriptor)
        throw error
    }
}

private func privateDirectoryIdentity(_ descriptor: Int32) throws -> DeviceTrustOpaqueIdentity {
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFDIR,
          metadata.st_uid == geteuid(),
          metadata.st_mode & 0o077 == 0,
          metadata.st_nlink >= 2,
          recoveryHasNoExtendedACL(descriptor) else {
        throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
    }
    return DeviceTrustOpaqueIdentity(metadata)
}

private func opaqueIdentityIfPresent(_ leaf: String, beneath parent: Int32) throws -> DeviceTrustOpaqueIdentity? {
    guard validRecoveryLeaf(leaf) else {
        throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
    }
    var metadata = stat()
    if leaf.withCString({ fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW) }) != 0 {
        if errno == ENOENT { return nil }
        throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
    }
    return DeviceTrustOpaqueIdentity(metadata)
}

private func openOrCreatePrivateChild(_ leaf: String, beneath parent: Int32) throws -> Int32 {
    if let existing = try openPrivateRecoveryChildIfPresent(leaf, beneath: parent) {
        return existing
    }
    return try createPrivateChild(leaf, beneath: parent)
}

private func createPrivateChild(_ leaf: String, beneath parent: Int32) throws -> Int32 {
    guard validRecoveryLeaf(leaf),
          leaf.withCString({ mkdirat(parent, $0, 0o700) }) == 0,
          fsync(parent) == 0,
          let descriptor = try openPrivateRecoveryChildIfPresent(leaf, beneath: parent) else {
        throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
    }
    return descriptor
}

private func openPrivateRecoveryChildIfPresent(_ leaf: String, beneath parent: Int32) throws -> Int32? {
    guard validRecoveryLeaf(leaf) else {
        throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
    }
    var named = stat()
    if leaf.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) != 0 {
        if errno == ENOENT { return nil }
        throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
    }
    guard named.st_mode & S_IFMT == S_IFDIR else {
        throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
    }
    let descriptor = leaf.withCString {
        openat(parent, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    }
    guard descriptor >= 0 else {
        throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
    }
    do {
        let opened = try privateDirectoryIdentity(descriptor)
        guard opened == DeviceTrustOpaqueIdentity(named) else {
            throw DeviceAttestationTrustRecoveryError.unsafeRecoveryStorage
        }
        return descriptor
    } catch {
        Darwin.close(descriptor)
        throw error
    }
}

private func validRecoveryLeaf(_ value: String) -> Bool {
    !value.isEmpty && value != "." && value != ".." && !value.contains("/") && !value.contains("\0")
}

private func recoveryHasNoExtendedACL(_ descriptor: Int32) -> Bool {
    errno = 0
    guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
        return errno == ENOENT
    }
    _ = acl_free(UnsafeMutableRawPointer(acl))
    return false
}
