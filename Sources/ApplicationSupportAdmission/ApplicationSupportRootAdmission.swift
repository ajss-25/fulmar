import Darwin
import Foundation

public enum ApplicationSupportRootAdmissionError: LocalizedError, Equatable, Sendable {
    case unsafePath
    case unsafePermissions
    case identityChanged

    public var errorDescription: String? {
        "Fulmar could not prove that its Application Support directory is a private, owner-only, non-linked directory. No local or cloud provider work was started, and no child state was written. Repair the directory permissions or remove a preplanted link, then reopen Fulmar."
    }
}

/// Retains the descriptor and exact live identity of the one native
/// Application Support root before any child store is constructed. Existing
/// roots are never chmodded through a path; unsafe permissions, ACLs, links,
/// and replacements fail closed. Only an absent final leaf may be created,
/// descriptor-relative, mode 0700, and parent-fsynced.
public final class ApplicationSupportRootAdmission: @unchecked Sendable {
    public static let unavailableSink = URL(
        fileURLWithPath: "/dev/null/Fulmar-Unsafe-Application-Support",
        isDirectory: true
    )

    private struct Identity: Equatable {
        let device: UInt64
        let inode: UInt64
        let owner: UInt32
        let mode: UInt16

        init(_ value: stat) {
            device = UInt64(truncatingIfNeeded: value.st_dev)
            inode = UInt64(value.st_ino)
            owner = value.st_uid
            mode = UInt16(value.st_mode)
        }
    }

    private let lock = NSLock()
    private let url: URL
    private var descriptor: Int32 = -1
    private var identity: Identity?
    private var terminalError: ApplicationSupportRootAdmissionError?

    public init(url: URL) {
        self.url = url.standardizedFileURL
    }

    deinit {
        if descriptor >= 0 { Darwin.close(descriptor) }
    }

    public func admit() -> Result<URL, ApplicationSupportRootAdmissionError> {
        lock.lock()
        defer { lock.unlock() }
        if let terminalError { return .failure(terminalError) }
        do {
            if descriptor < 0 {
                let opened = try Self.openOrCreateExactPrivateRoot(url)
                descriptor = opened.descriptor
                identity = opened.identity
            }
            try revalidateLocked()
            return .success(url)
        } catch let error as ApplicationSupportRootAdmissionError {
            if descriptor >= 0 {
                Darwin.close(descriptor)
                descriptor = -1
            }
            identity = nil
            terminalError = error
            return .failure(error)
        } catch {
            if descriptor >= 0 {
                Darwin.close(descriptor)
                descriptor = -1
            }
            identity = nil
            terminalError = .unsafePath
            return .failure(.unsafePath)
        }
    }

    private func revalidateLocked() throws {
        guard descriptor >= 0, let identity else {
            throw ApplicationSupportRootAdmissionError.identityChanged
        }
        var opened = stat()
        var named = stat()
        guard fstat(descriptor, &opened) == 0,
              Darwin.lstat(url.path, &named) == 0,
              Identity(opened) == identity,
              Identity(named) == identity,
              Self.isExactPrivateDirectory(opened),
              Self.hasNoExtendedACL(descriptor) else {
            throw ApplicationSupportRootAdmissionError.identityChanged
        }
    }

    private static func openOrCreateExactPrivateRoot(
        _ url: URL
    ) throws -> (descriptor: Int32, identity: Identity) {
        guard url.isFileURL,
              url.standardizedFileURL.path == url.path,
              url.path.hasPrefix("/"),
              let leaf = url.pathComponents.last,
              validLeaf(leaf) else {
            throw ApplicationSupportRootAdmissionError.unsafePath
        }
        let parentURL = url.deletingLastPathComponent()
        let parent = try openAbsoluteDirectoryNoSymlink(parentURL)
        defer { Darwin.close(parent) }

        var named = stat()
        if leaf.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) != 0 {
            guard errno == ENOENT,
                  leaf.withCString({ mkdirat(parent, $0, 0o700) }) == 0,
                  fsync(parent) == 0 else {
                throw ApplicationSupportRootAdmissionError.unsafePath
            }
            guard leaf.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0 else {
                throw ApplicationSupportRootAdmissionError.identityChanged
            }
        }
        guard named.st_mode & S_IFMT == S_IFDIR else {
            throw ApplicationSupportRootAdmissionError.unsafePath
        }
        let descriptor = leaf.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard descriptor >= 0 else {
            throw ApplicationSupportRootAdmissionError.unsafePath
        }
        do {
            var opened = stat()
            guard fstat(descriptor, &opened) == 0,
                  Identity(opened) == Identity(named) else {
                throw ApplicationSupportRootAdmissionError.identityChanged
            }
            guard isExactPrivateDirectory(opened), hasNoExtendedACL(descriptor) else {
                throw ApplicationSupportRootAdmissionError.unsafePermissions
            }
            return (descriptor, Identity(opened))
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private static func openAbsoluteDirectoryNoSymlink(_ url: URL) throws -> Int32 {
        guard url.isFileURL,
              url.standardizedFileURL.path == url.path,
              url.path.hasPrefix("/") else {
            throw ApplicationSupportRootAdmissionError.unsafePath
        }
        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw ApplicationSupportRootAdmissionError.unsafePath }
        do {
            for component in url.path.split(separator: "/").map(String.init) {
                guard validLeaf(component) else {
                    throw ApplicationSupportRootAdmissionError.unsafePath
                }
                let next = component.withCString {
                    openat(current, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
                }
                guard next >= 0 else {
                    throw ApplicationSupportRootAdmissionError.unsafePath
                }
                Darwin.close(current)
                current = next
            }
            return current
        } catch {
            Darwin.close(current)
            throw error
        }
    }

    private static func isExactPrivateDirectory(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFDIR
            && value.st_uid == geteuid()
            && value.st_mode & 0o7777 == 0o700
            && value.st_nlink >= 2
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
        !value.isEmpty && value != "." && value != ".." && !value.contains("/") && !value.contains("\0")
    }
}
