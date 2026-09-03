import Darwin
import Foundation

public enum CredentialPrivateDirectoryError: Error, Equatable, Sendable {
    case unsafePath
    case creationFailed
}

public final class CredentialPrivateDirectoryCapability: @unchecked Sendable {
    public let url: URL
    private let descriptor: Int32

    fileprivate init(url: URL, descriptor: Int32) {
        self.url = url
        self.descriptor = descriptor
    }

    deinit { _ = close(descriptor) }

    public func duplicateDescriptor() throws -> Int32 {
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 3)
        guard duplicate >= 0 else { throw CredentialPrivateDirectoryError.unsafePath }
        return duplicate
    }
}

/// Creates and validates the credential metadata hierarchy by walking exact
/// directory descriptors. No intermediate symlink is followed and every child
/// is bound to the parent descriptor used to create/open it before that parent
/// is released.
public enum CredentialPrivateDirectory {
    public static func prepareMetadataDirectory(
        home: URL,
        productName: String = "Local Harness",
        metadataName: String = "CredentialMetadata",
        ownerID: uid_t = geteuid()
    ) throws -> URL {
        try prepareMetadataDirectoryCapability(
            home: home,
            productName: productName,
            metadataName: metadataName,
            ownerID: ownerID
        ).url
    }

    public static func prepareMetadataDirectoryCapability(
        home: URL,
        productName: String = "Local Harness",
        metadataName: String = "CredentialMetadata",
        ownerID: uid_t = geteuid()
    ) throws -> CredentialPrivateDirectoryCapability {
        guard home.isFileURL,
              home.path.hasPrefix("/"),
              !home.path.contains("\0"),
              home.path == home.standardizedFileURL.path,
              home.path == home.resolvingSymlinksInPath().standardizedFileURL.path,
              validComponent(productName),
              validComponent(metadataName) else {
            throw CredentialPrivateDirectoryError.unsafePath
        }
        var descriptor = open(home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CredentialPrivateDirectoryError.unsafePath }
        defer { if descriptor >= 0 { _ = close(descriptor) } }
        try validateDirectory(
            descriptor,
            parent: nil,
            name: nil,
            ownerID: ownerID,
            privatePermissions: false
        )

        var result = home
        let components: [(String, Bool)] = [
            ("Library", false),
            ("Application Support", false),
            (productName, true),
            (metadataName, true),
        ]
        for (name, privatePermissions) in components {
            let child = try openOrCreateDirectory(
                parent: descriptor,
                name: name,
                ownerID: ownerID,
                privatePermissions: privatePermissions
            )
            _ = close(descriptor)
            descriptor = child
            result.appendPathComponent(name, isDirectory: true)
        }

        var pathMetadata = stat()
        var descriptorMetadata = stat()
        guard lstat(result.path, &pathMetadata) == 0,
              fstat(descriptor, &descriptorMetadata) == 0,
              pathMetadata.st_dev == descriptorMetadata.st_dev,
              pathMetadata.st_ino == descriptorMetadata.st_ino,
              result.path == result.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw CredentialPrivateDirectoryError.unsafePath
        }
        let capability = CredentialPrivateDirectoryCapability(url: result, descriptor: descriptor)
        descriptor = -1
        return capability
    }

    private static func openOrCreateDirectory(
        parent: Int32,
        name: String,
        ownerID: uid_t,
        privatePermissions: Bool
    ) throws -> Int32 {
        var child = name.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        if child < 0, errno == ENOENT {
            let created = name.withCString { mkdirat(parent, $0, S_IRWXU) }
            if created != 0, errno != EEXIST {
                throw CredentialPrivateDirectoryError.creationFailed
            }
            if created == 0, fsync(parent) != 0 {
                throw CredentialPrivateDirectoryError.creationFailed
            }
            child = name.withCString {
                openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
        }
        guard child >= 0 else { throw CredentialPrivateDirectoryError.unsafePath }
        do {
            try validateDirectory(
                child,
                parent: parent,
                name: name,
                ownerID: ownerID,
                privatePermissions: privatePermissions
            )
            return child
        } catch {
            _ = close(child)
            throw error
        }
    }

    private static func validateDirectory(
        _ descriptor: Int32,
        parent: Int32?,
        name: String?,
        ownerID: uid_t,
        privatePermissions: Bool
    ) throws {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else {
            throw CredentialPrivateDirectoryError.unsafePath
        }
        let permissionsAreSafe = privatePermissions
            ? metadata.st_mode & 0o777 == 0o700
            : metadata.st_mode & 0o022 == 0
        guard metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == ownerID,
              permissionsAreSafe else {
            throw CredentialPrivateDirectoryError.unsafePath
        }
        if !hasSafeExtendedACL(
            descriptor,
            allowingStandardAncestorDeleteDeny: !privatePermissions
        ) {
            throw CredentialPrivateDirectoryError.unsafePath
        }
        if let parent, let name {
            var named = stat()
            guard name.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
                  named.st_mode & S_IFMT == S_IFDIR,
                  named.st_dev == metadata.st_dev,
                  named.st_ino == metadata.st_ino else {
                throw CredentialPrivateDirectoryError.unsafePath
            }
        }
    }

    private static func validComponent(_ value: String) -> Bool {
        !value.isEmpty
            && value != "."
            && value != ".."
            && value.utf8.count <= 255
            && !value.contains("/")
            && !value.contains("\0")
    }

    private static func hasSafeExtendedACL(
        _ descriptor: Int32,
        allowingStandardAncestorDeleteDeny: Bool
    ) -> Bool {
        errno = 0
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        defer { _ = acl_free(UnsafeMutableRawPointer(list)) }
        guard allowingStandardAncestorDeleteDeny else { return false }

        // macOS gives the user's home, Library, and Application Support this
        // exact deny-only ACL. It grants no capability, so admitting precisely
        // this canonical system entry preserves the normal home hierarchy.
        // Any additional entry, inherited flag, allow rule, or permission is
        // rejected because its text cannot equal this bounded representation.
        let standardDeleteDeny =
            "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete\n"
        var length: ssize_t = 0
        guard let text = acl_to_text(list, &length),
              length == standardDeleteDeny.utf8.count else { return false }
        defer { _ = acl_free(UnsafeMutableRawPointer(text)) }
        return String(cString: text) == standardDeleteDeny
    }
}
