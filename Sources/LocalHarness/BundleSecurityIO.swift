import Darwin
import Foundation

/// Small, fail-closed primitives for inspecting security-critical files inside
/// the signed application bundle. Directory enumeration stops after the exact
/// expected shape plus one entry, and file reads are no-follow and byte-bounded.
enum BundleSecurityIO {
    static func directoryEntryNames(
        at directory: URL,
        inside root: URL,
        maximumEntries: Int
    ) -> [String]? {
        guard maximumEntries >= 0,
              containsWithoutSymlinks(directory, inside: root) else { return nil }

        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { return nil }
        guard secureMetadata(descriptor: descriptor, expectedType: S_IFDIR, maximumBytes: nil) else {
            Darwin.close(descriptor)
            return nil
        }
        guard let stream = fdopendir(descriptor) else {
            Darwin.close(descriptor)
            return nil
        }
        defer { closedir(stream) }

        var names: [String] = []
        names.reserveCapacity(min(maximumEntries, 32))
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                return errno == 0 ? names : nil
            }
            guard let name = DarwinDirectoryEntry.name(entry) else { return nil }
            if name == "." || name == ".." { continue }
            guard names.count < maximumEntries else { return nil }
            names.append(name)
        }
    }

    static func isRegularFile(
        _ file: URL,
        inside root: URL,
        maximumBytes: Int
    ) -> Bool {
        guard maximumBytes >= 0,
              containsWithoutSymlinks(file, inside: root) else { return false }
        let descriptor = Darwin.open(file.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return false }
        defer { Darwin.close(descriptor) }
        return secureMetadata(
            descriptor: descriptor,
            expectedType: S_IFREG,
            maximumBytes: maximumBytes
        )
    }

    static func readRegularFile(
        at file: URL,
        inside root: URL,
        maximumBytes: Int
    ) -> Data? {
        guard maximumBytes > 0,
              containsWithoutSymlinks(file, inside: root) else { return nil }
        let descriptor = Darwin.open(file.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard fstat(descriptor, &before) == 0,
              metadataIsSecure(before, expectedType: S_IFREG, maximumBytes: maximumBytes) else {
            return nil
        }

        var result = Data()
        result.reserveCapacity(min(Int(before.st_size), maximumBytes))
        var buffer = [UInt8](repeating: 0, count: min(64 * 1_024, maximumBytes + 1))
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            guard count <= maximumBytes - result.count else { return nil }
            result.append(contentsOf: buffer.prefix(count))
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              result.count == Int(before.st_size) else { return nil }
        return result
    }

    private static func secureMetadata(
        descriptor: Int32,
        expectedType: mode_t,
        maximumBytes: Int?
    ) -> Bool {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { return false }
        return metadataIsSecure(metadata, expectedType: expectedType, maximumBytes: maximumBytes)
    }

    private static func metadataIsSecure(
        _ metadata: stat,
        expectedType: mode_t,
        maximumBytes: Int?
    ) -> Bool {
        guard metadata.st_mode & S_IFMT == expectedType,
              (metadata.st_uid == geteuid() || metadata.st_uid == 0),
              metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else { return false }
        if let maximumBytes {
            guard metadata.st_size >= 0, metadata.st_size <= off_t(maximumBytes) else { return false }
        }
        return true
    }

    private static func containsWithoutSymlinks(_ candidate: URL, inside root: URL) -> Bool {
        guard candidate.isFileURL, root.isFileURL else { return false }
        let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let standardized = candidate.standardizedFileURL.path
        let canonical = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        let prefix = canonicalRoot.hasSuffix("/") ? canonicalRoot : canonicalRoot + "/"
        return standardized == canonical
            && (canonical == canonicalRoot || canonical.hasPrefix(prefix))
    }
}
