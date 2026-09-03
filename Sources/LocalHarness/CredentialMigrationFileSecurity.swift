import Darwin
import Foundation

/// Fail-closed filesystem primitives shared by the credential-migration
/// launcher and its bounded child runner. macOS extended ACLs can grant access
/// which is not represented by the POSIX mode bits, so a 0600/0700 mode check
/// is not an owner-private proof on its own.
enum CredentialMigrationFileSecurity {
    static func descriptorHasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(accessControlList))
        return false
    }

    static func pathHasNoExtendedACL(_ path: String, directory: Bool = false) -> Bool {
        let flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            | (directory ? O_DIRECTORY : 0)
        let descriptor = Darwin.open(path, flags)
        guard descriptor >= 0 else { return false }
        defer { _ = Darwin.close(descriptor) }
        return descriptorHasNoExtendedACL(descriptor)
    }

    /// Reads at most `maximumBytes + 1` from the current descriptor offset.
    /// The extra byte distinguishes an exact-limit file from a file which grew
    /// after its metadata was inspected without allocating attacker-sized data.
    static func boundedRead(
        descriptor: Int32,
        maximumBytes: Int
    ) throws -> Data {
        guard descriptor >= 0, maximumBytes >= 0, maximumBytes < Int.max else {
            throw CredentialMigrationError.componentsMissing
        }
        guard Darwin.lseek(descriptor, 0, SEEK_SET) >= 0 else {
            throw CredentialMigrationError.componentsMissing
        }
        var result = Data()
        result.reserveCapacity(min(maximumBytes + 1, 64 * 1_024))
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while result.count <= maximumBytes {
            let remaining = maximumBytes + 1 - result.count
            let requested = min(buffer.count, remaining)
            let count = buffer.withUnsafeMutableBytes { storage in
                Darwin.read(descriptor, storage.baseAddress, requested)
            }
            if count > 0 {
                result.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count == 0 { break }
            if errno == EINTR { continue }
            throw CredentialMigrationError.componentsMissing
        }
        guard result.count <= maximumBytes else {
            throw CredentialMigrationError.componentsMissing
        }
        return result
    }
}
