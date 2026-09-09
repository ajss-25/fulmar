import Darwin
import Foundation

enum LegacyWebsiteDataCleanerError: LocalizedError, Equatable {
    case unsafeLegacyPath(String)
    case removalFailed(String)

    var errorDescription: String? {
        switch self {
        case .unsafeLegacyPath:
            return "Fulmar found an unexpected legacy browser-data path and left it untouched."
        case .removalFailed:
            return "Fulmar could not completely remove its legacy browser cache. No project, task, or credential data was changed."
        }
    }
}

/// Deletes only the two historical persistent-WebKit roots used by this exact
/// bundle identifier. Current releases use a non-persistent data store; this
/// cleanup exists solely so the user-facing clear action also removes data left
/// by older builds. Symbolic links are unlinked, never followed.
struct LegacyWebsiteDataCleaner {
    private let targets: [URL]
    private let fileManager: FileManager

    init(
        libraryDirectory: URL,
        cachesDirectory: URL,
        bundleIdentifier: String = ProductBrand.bundleIdentifier,
        fileManager: FileManager = .default
    ) {
        precondition(!bundleIdentifier.isEmpty && !bundleIdentifier.contains("/"))
        targets = [
            libraryDirectory.appendingPathComponent("WebKit", isDirectory: true)
                .appendingPathComponent(bundleIdentifier, isDirectory: true),
            cachesDirectory.appendingPathComponent(bundleIdentifier, isDirectory: true)
        ]
        self.fileManager = fileManager
    }

    static func live(fileManager: FileManager = .default) throws -> Self {
        let library = try fileManager.url(
            for: .libraryDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: false
        )
        let caches = try fileManager.url(
            for: .cachesDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: false
        )
        return Self(libraryDirectory: library, cachesDirectory: caches, fileManager: fileManager)
    }

    func clear() throws {
        for target in targets { try removeExactRoot(target) }
    }

    private func removeExactRoot(_ target: URL) throws {
        let standardized = target.standardizedFileURL
        guard standardized.path == target.path, standardized.lastPathComponent == ProductBrand.bundleIdentifier else {
            throw LegacyWebsiteDataCleanerError.unsafeLegacyPath(target.path)
        }

        var metadata = stat()
        if Darwin.lstat(target.path, &metadata) != 0 {
            if errno == ENOENT { return }
            throw LegacyWebsiteDataCleanerError.unsafeLegacyPath(target.path)
        }
        let kind = metadata.st_mode & S_IFMT
        guard metadata.st_uid == geteuid(), kind == S_IFDIR || kind == S_IFLNK else {
            throw LegacyWebsiteDataCleanerError.unsafeLegacyPath(target.path)
        }

        do { try fileManager.removeItem(at: target) }
        catch { throw LegacyWebsiteDataCleanerError.removalFailed(target.path) }

        var after = stat()
        if Darwin.lstat(target.path, &after) == 0 || errno != ENOENT {
            throw LegacyWebsiteDataCleanerError.removalFailed(target.path)
        }
    }
}
