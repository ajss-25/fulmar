import Darwin
import Foundation

enum RetainedPrivateDirectoryCapabilityError: Error, Equatable {
    case unsafePath
    case unsafePermissions
    case identityChanged
}

/// Pins one owner-only directory for the lifetime of a native store.
///
/// The descriptor is opened (or the absent final leaf is created) relative to
/// the directory's parent, then every operation proves that the configured
/// pathname still names that exact inode before and after using it. Stores use
/// only the retained descriptor for child I/O. Replacing a valid 0700
/// Application Support tree between calls therefore fails closed instead of
/// redirecting private bytes into the replacement tree.
final class RetainedPrivateDirectoryCapability: @unchecked Sendable {
    struct Identity: Equatable, Sendable {
        let device: UInt64
        let inode: UInt64

        init(_ metadata: stat) {
            device = UInt64(truncatingIfNeeded: metadata.st_dev)
            inode = UInt64(metadata.st_ino)
        }
    }

    private let lock = NSLock()
    private let directoryURL: URL
    private let descriptor: Int32
    private let identity: Identity
    private var terminalError: RetainedPrivateDirectoryCapabilityError?

    init(directoryURL: URL, createIfMissing: Bool) throws {
        let normalized = directoryURL.standardizedFileURL
        guard normalized.isFileURL,
              normalized.path == directoryURL.path,
              normalized.path.hasPrefix("/"),
              let leaf = normalized.pathComponents.last,
              Self.validLeaf(leaf) else {
            throw RetainedPrivateDirectoryCapabilityError.unsafePath
        }

        let parentURL = normalized.deletingLastPathComponent()
        let parent = Darwin.open(
            parentURL.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )
        guard parent >= 0 else {
            throw RetainedPrivateDirectoryCapabilityError.unsafePath
        }
        defer { _ = Darwin.close(parent) }

        var named = stat()
        if leaf.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) != 0 {
            guard errno == ENOENT, createIfMissing,
                  leaf.withCString({ mkdirat(parent, $0, mode_t(0o700)) }) == 0,
                  fsync(parent) == 0,
                  leaf.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0
            else {
                throw RetainedPrivateDirectoryCapabilityError.unsafePath
            }
        }

        guard Self.isExactPrivateDirectory(named) else {
            throw RetainedPrivateDirectoryCapabilityError.unsafePermissions
        }
        let opened = leaf.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard opened >= 0 else {
            throw RetainedPrivateDirectoryCapabilityError.unsafePath
        }

        var descriptorMetadata = stat()
        guard fstat(opened, &descriptorMetadata) == 0,
              Self.isExactPrivateDirectory(descriptorMetadata),
              Self.hasNoExtendedACL(opened),
              Identity(descriptorMetadata) == Identity(named) else {
            _ = Darwin.close(opened)
            throw RetainedPrivateDirectoryCapabilityError.unsafePermissions
        }

        self.directoryURL = normalized
        self.descriptor = opened
        self.identity = Identity(descriptorMetadata)
    }

    deinit {
        _ = Darwin.close(descriptor)
    }

    func withValidatedDescriptor<Result>(
        _ operation: (Int32) throws -> Result
    ) throws -> Result {
        lock.lock()
        defer { lock.unlock() }
        if let terminalError { throw terminalError }

        do {
            try revalidateLocked()
            let result = try operation(descriptor)
            try revalidateLocked()
            return result
        } catch let error as RetainedPrivateDirectoryCapabilityError {
            terminalError = error
            throw error
        } catch {
            // An ordinary child-file failure does not poison the directory
            // capability, but displacement discovered while handling it does.
            do {
                try revalidateLocked()
            } catch let capabilityError as RetainedPrivateDirectoryCapabilityError {
                terminalError = capabilityError
                throw capabilityError
            }
            throw error
        }
    }

    private func revalidateLocked() throws {
        var opened = stat()
        var named = stat()
        guard fstat(descriptor, &opened) == 0,
              Darwin.lstat(directoryURL.path, &named) == 0,
              Identity(opened) == identity,
              Identity(named) == identity,
              Self.isExactPrivateDirectory(opened),
              Self.isExactPrivateDirectory(named),
              Self.hasNoExtendedACL(descriptor) else {
            throw RetainedPrivateDirectoryCapabilityError.identityChanged
        }
    }

    private static func isExactPrivateDirectory(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_mode & mode_t(0o7777) == mode_t(0o700)
            && metadata.st_nlink >= 2
    }

    private static func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(acl))
        return false
    }

    private static func validLeaf(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".."
            && !value.contains("/") && !value.contains("\0")
    }
}
