import Darwin
import Foundation
@_spi(CredentialMigrationFDCollisionProbe) import LocalHarnessCredentialMigrationProcess

private enum ProbeError: Error, CustomStringConvertible {
    case unsafeFixture(String)
    case assertionFailed(String)

    var description: String {
        switch self {
        case .unsafeFixture(let message): return "unsafe fixture: \(message)"
        case .assertionFailed(let message): return "assertion failed: \(message)"
        }
    }
}

private func fail(_ message: String) -> Never {
    let bytes = Array("CredentialMigrationFDCollisionProbe: \(message)\n".utf8)
    bytes.withUnsafeBytes { buffer in
        _ = Darwin.write(STDERR_FILENO, buffer.baseAddress, buffer.count)
    }
    _exit(64)
}

private func contenderCanAcquireMigrationLock(at url: URL) -> Bool {
    let descriptor = Darwin.open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor > STDERR_FILENO else {
        if descriptor >= 0 { _ = Darwin.close(descriptor) }
        return false
    }
    defer { _ = Darwin.close(descriptor) }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { return false }
    _ = flock(descriptor, LOCK_UN)
    return true
}

private func runProbe() throws {
    guard CommandLine.arguments.count == 1 else {
        throw ProbeError.unsafeFixture("unexpected arguments")
    }
    _ = Darwin.umask(0o077)
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarCredentialMigrationFDCollisionProbe.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    guard Darwin.chmod(root.path, 0o700) == 0 else {
        throw ProbeError.unsafeFixture("could not protect the private root")
    }

    let lock = root.appendingPathComponent("migration.lock", isDirectory: false)
    let originalDescriptor = Darwin.open(
        lock.path,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        mode_t(S_IRUSR | S_IWUSR)
    )
    guard originalDescriptor > STDERR_FILENO else {
        if originalDescriptor >= 0 { _ = Darwin.close(originalDescriptor) }
        throw ProbeError.unsafeFixture("could not create the exact lock fixture")
    }
    var ownedDescriptor = originalDescriptor
    defer {
        if ownedDescriptor >= 0 {
            _ = flock(ownedDescriptor, LOCK_UN)
            _ = Darwin.close(ownedDescriptor)
        }
    }
    guard flock(originalDescriptor, LOCK_EX | LOCK_NB) == 0 else {
        throw ProbeError.unsafeFixture("could not acquire the exact lock fixture")
    }
    var metadata = stat()
    guard Darwin.fstat(originalDescriptor, &metadata) == 0,
          metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
          metadata.st_uid == geteuid(),
          metadata.st_mode & 0o777 == 0o600,
          metadata.st_nlink == 1,
          metadata.st_size == 0 else {
        throw ProbeError.unsafeFixture("the exact lock metadata changed")
    }

    let fixedDescriptor = CredentialMigrationFixedDescriptorProbeAPI.fixedChildDescriptor
    errno = 0
    guard Darwin.fcntl(fixedDescriptor, F_GETFD) < 0, errno == EBADF else {
        throw ProbeError.unsafeFixture(
            "the dedicated process unexpectedly entered with fd \(fixedDescriptor) occupied"
        )
    }
    let collisionDescriptor = Darwin.fcntl(
        originalDescriptor,
        F_DUPFD_CLOEXEC,
        fixedDescriptor
    )
    guard collisionDescriptor == fixedDescriptor else {
        if collisionDescriptor >= 0 { _ = Darwin.close(collisionDescriptor) }
        throw ProbeError.unsafeFixture(
            "could not establish source/target collision at fd \(fixedDescriptor)"
        )
    }
    guard Darwin.close(originalDescriptor) == 0 else {
        _ = Darwin.close(collisionDescriptor)
        ownedDescriptor = -1
        throw ProbeError.unsafeFixture("could not retire the original lock descriptor")
    }
    ownedDescriptor = collisionDescriptor

    let expectedDevice = UInt64(truncatingIfNeeded: metadata.st_dev)
    let expectedInode = UInt64(truncatingIfNeeded: metadata.st_ino)
    guard !contenderCanAcquireMigrationLock(at: lock) else {
        throw ProbeError.assertionFailed("fd 198 did not retain the parent flock")
    }
    let result = try CredentialMigrationFixedDescriptorProbeAPI.run(
        sourceDescriptor: collisionDescriptor,
        expectedDevice: expectedDevice,
        expectedInode: expectedInode
    )
    guard result.exitStatus == 0,
          result.terminationSignal == nil,
          !result.reachedLimit,
          result.standardOutput.isEmpty,
          result.standardError.isEmpty else {
        throw ProbeError.assertionFailed(
            "production runner result exit=\(String(describing: result.exitStatus)) "
                + "signal=\(String(describing: result.terminationSignal)) "
                + "limited=\(result.reachedLimit) stderr="
                + String(decoding: result.standardError, as: UTF8.self)
        )
    }
    guard result.matchingParentDescriptorsAtSpawn == [fixedDescriptor] else {
        throw ProbeError.assertionFailed(
            "parent descriptors at spawn were \(result.matchingParentDescriptorsAtSpawn)"
        )
    }
    let descriptorFlags = Darwin.fcntl(collisionDescriptor, F_GETFD)
    guard descriptorFlags >= 0, descriptorFlags & FD_CLOEXEC != 0 else {
        throw ProbeError.assertionFailed("production runner cleared parent FD_CLOEXEC")
    }
    guard !contenderCanAcquireMigrationLock(at: lock) else {
        throw ProbeError.assertionFailed("production runner released the parent flock")
    }
    guard Darwin.close(collisionDescriptor) == 0 else {
        ownedDescriptor = -1
        throw ProbeError.assertionFailed("could not close the collision descriptor")
    }
    ownedDescriptor = -1
    guard contenderCanAcquireMigrationLock(at: lock) else {
        throw ProbeError.assertionFailed("the flock survived its final exact owner")
    }

    let success = Array("FULMAR_FD_198_COLLISION_OK\n".utf8)
    success.withUnsafeBytes { buffer in
        _ = Darwin.write(STDOUT_FILENO, buffer.baseAddress, buffer.count)
    }
}

do {
    try runProbe()
} catch {
    fail(String(describing: error))
}
