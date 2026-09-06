import AppKit
import CoreGraphics
import Darwin
import ScreenCaptureKit

struct AppshotPurgeResult: Equatable {
    var examined = 0
    var removed = 0
    var retained = 0
    var failures = 0
}

struct AppshotRetentionLimits: Equatable {
    let maximumEntries: Int
    let maximumAggregateBytes: Int64
    let scanDuration: TimeInterval

    static let production = AppshotRetentionLimits(
        maximumEntries: 5_000,
        maximumAggregateBytes: 20 * 1_024 * 1_024 * 1_024,
        scanDuration: 2
    )
}

final class AppshotController {
    private static let maximumCaptureBytes = 256 * 1_024 * 1_024
    private static let maximumFilenameCollisionAttempts = 10_000

    private struct PurgeCandidate {
        let url: URL
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64
    }

    enum CaptureError: LocalizedError {
        case permissionRequired
        case applicationUnavailable
        case windowUnavailable
        case encodingFailed
        case applicationExcluded
        case unsafeStorage

        var errorDescription: String? {
            switch self {
            case .permissionRequired:
                return "Screen Recording permission is required. Enable \(ProductBrand.displayName) in System Settings → Privacy & Security → Screen & System Audio Recording, then try again."
            case .applicationUnavailable:
                return "No previously active application is available to capture."
            case .windowUnavailable:
                return "The previously active application does not have a visible window to capture."
            case .encodingFailed:
                return "The captured window could not be converted to an image."
            case .applicationExcluded:
                return "That application is excluded from Appshots in order to protect passwords and other sensitive content."
            case .unsafeStorage:
                return "The private Appshots folder could not be verified. No capture was saved."
            }
        }
    }

    private let fileManager = FileManager.default
    private let preferences: PreferencesStore
    private let retentionDays: () -> Int
    private let directoryOverride: URL?
    private let retentionLimits: AppshotRetentionLimits

    init(
        preferences: PreferencesStore = .shared,
        directory: URL? = nil,
        retentionDays: (() -> Int)? = nil,
        retentionLimits: AppshotRetentionLimits = .production
    ) {
        self.preferences = preferences
        self.directoryOverride = directory
        self.retentionDays = retentionDays ?? { preferences.appshotRetentionDays }
        self.retentionLimits = retentionLimits
    }

    @MainActor
    func captureFrontWindow(of application: NSRunningApplication?) async throws -> (image: NSImage, suggestedFilename: String) {
        guard CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess() else {
            throw CaptureError.permissionRequired
        }
        guard let application else { throw CaptureError.applicationUnavailable }
        if let bundleIdentifier = application.bundleIdentifier,
           preferences.excludedCaptureBundleIdentifiers.contains(bundleIdentifier) {
            throw CaptureError.applicationExcluded
        }

        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        guard let window = content.windows.first(where: {
            $0.owningApplication?.processID == application.processIdentifier &&
            $0.isOnScreen && $0.frame.width > 120 && $0.frame.height > 80
        }) else { throw CaptureError.windowUnavailable }

        let filter = SCContentFilter(desktopIndependentWindow: window)
        let configuration = SCStreamConfiguration()
        let scale = NSScreen.main?.backingScaleFactor ?? 2
        configuration.width = max(1, Int(window.frame.width * scale))
        configuration.height = max(1, Int(window.frame.height * scale))
        configuration.showsCursor = false
        configuration.capturesAudio = false

        let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        let nsImage = NSImage(cgImage: image, size: NSSize(width: image.width, height: image.height))
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return (nsImage, "Appshot \(formatter.string(from: Date())).png")
    }

    func persistReviewed(_ image: NSImage, suggestedFilename: String) throws -> URL {
        guard let tiff = image.tiffRepresentation,
              let bitmap = NSBitmapImageRep(data: tiff),
              let png = bitmap.representation(using: .png, properties: [:]),
              !png.isEmpty,
              png.count <= Self.maximumCaptureBytes else { throw CaptureError.encodingFailed }
        let directory = appshotDirectory()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        _ = purgeExpiredCaptures()
        return try persistPrivatePNG(
            png,
            in: directory,
            suggestedFilename: suggestedFilename
        )
    }

    private func persistPrivatePNG(
        _ png: Data,
        in directory: URL,
        suggestedFilename: String
    ) throws -> URL {
        let directoryDescriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else { throw CaptureError.unsafeStorage }
        defer { _ = Darwin.close(directoryDescriptor) }
        guard Darwin.fchmod(directoryDescriptor, mode_t(0o700)) == 0 else {
            throw CaptureError.unsafeStorage
        }
        var directoryMetadata = stat()
        guard Darwin.fstat(directoryDescriptor, &directoryMetadata) == 0,
              directoryMetadata.st_mode & S_IFMT == S_IFDIR,
              directoryMetadata.st_uid == geteuid(),
              directoryMetadata.st_mode & mode_t(0o7777) == mode_t(0o700),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(directoryDescriptor) else {
            throw CaptureError.unsafeStorage
        }

        let filename = try availableCaptureFilename(
            suggestedFilename,
            directoryDescriptor: directoryDescriptor
        )
        let temporaryName = ".appshot.\(UUID().uuidString).tmp"
        let fileDescriptor = temporaryName.withCString {
            Darwin.openat(
                directoryDescriptor,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard fileDescriptor >= 0 else { throw CaptureError.unsafeStorage }
        var descriptorOpen = true
        var temporaryExists = true
        var published = false
        defer {
            if descriptorOpen { _ = Darwin.close(fileDescriptor) }
            if temporaryExists {
                temporaryName.withCString { _ = Darwin.unlinkat(directoryDescriptor, $0, 0) }
            }
            if published {
                filename.withCString { _ = Darwin.unlinkat(directoryDescriptor, $0, 0) }
                _ = Darwin.fsync(directoryDescriptor)
            }
        }

        guard CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(fileDescriptor),
              Self.writeAll(png, to: fileDescriptor),
              Darwin.fsync(fileDescriptor) == 0 else {
            throw CaptureError.unsafeStorage
        }
        var fileMetadata = stat()
        guard Darwin.fstat(fileDescriptor, &fileMetadata) == 0,
              fileMetadata.st_mode & S_IFMT == S_IFREG,
              fileMetadata.st_uid == geteuid(),
              fileMetadata.st_nlink == 1,
              fileMetadata.st_mode & mode_t(0o7777) == mode_t(0o600),
              fileMetadata.st_size == png.count else {
            throw CaptureError.unsafeStorage
        }
        let closeResult = Darwin.close(fileDescriptor)
        descriptorOpen = false
        guard closeResult == 0 else { throw CaptureError.unsafeStorage }

        let renameResult = temporaryName.withCString { temporary in
            filename.withCString { destination in
                Darwin.renameatx_np(
                    directoryDescriptor,
                    temporary,
                    directoryDescriptor,
                    destination,
                    UInt32(RENAME_EXCL)
                )
            }
        }
        guard renameResult == 0 else { throw CaptureError.unsafeStorage }
        temporaryExists = false
        published = true
        guard Darwin.fsync(directoryDescriptor) == 0,
              Self.directoryPathStillMatches(directory, expected: directoryMetadata) else {
            throw CaptureError.unsafeStorage
        }
        published = false
        return directory.appendingPathComponent(filename)
    }

    private func availableCaptureFilename(
        _ suggestedFilename: String,
        directoryDescriptor: Int32
    ) throws -> String {
        let safeName = DownloadPath.safeFilename(
            suggestedFilename,
            fallback: "Appshot.png"
        )
        let base = (safeName as NSString).deletingPathExtension
        let pathExtension = (safeName as NSString).pathExtension
        for index in 1...Self.maximumFilenameCollisionAttempts {
            let name: String
            if index == 1 {
                name = safeName
            } else {
                name = pathExtension.isEmpty
                    ? "\(base) \(index)"
                    : "\(base) \(index).\(pathExtension)"
            }
            var metadata = stat()
            let result = name.withCString {
                Darwin.fstatat(directoryDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }
            if result != 0, errno == ENOENT { return name }
            if result != 0 { throw CaptureError.unsafeStorage }
        }
        throw CaptureError.unsafeStorage
    }

    private static func directoryPathStillMatches(_ directory: URL, expected: stat) -> Bool {
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { return false }
        defer { _ = Darwin.close(descriptor) }
        var current = stat()
        return Darwin.fstat(descriptor, &current) == 0
            && current.st_dev == expected.st_dev
            && current.st_ino == expected.st_ino
            && current.st_uid == expected.st_uid
            && current.st_mode & mode_t(0o7777) == mode_t(0o700)
            && CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor)
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { storage in
            guard let base = storage.baseAddress else { return data.isEmpty }
            var offset = 0
            while offset < storage.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    storage.count - offset
                )
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }

    func appshotDirectory() -> URL {
        if let directoryOverride { return directoryOverride }
        // Foundation normally supplies this location, but a damaged or highly
        // restricted account must not turn the optional lookup into an app
        // crash. The fallback is the same per-user macOS location expressed
        // beneath the current account's home directory; persistence still
        // performs the normal private-directory and symlink checks below.
        let base = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support", isDirectory: true)
        return base.appendingPathComponent("Local Harness/Appshots", isDirectory: true)
    }

    /// Removes only expired, regular files that are directly owned by the Appshots store.
    /// Symlinks, directories and unreadable entries are always retained.
    @discardableResult
    func purgeExpiredCaptures(now: Date = Date()) -> AppshotPurgeResult {
        let directory = appshotDirectory()
        guard fileManager.fileExists(atPath: directory.path) else { return AppshotPurgeResult() }
        guard let directoryValues = try? directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
              directoryValues.isDirectory == true, directoryValues.isSymbolicLink != true else {
            return AppshotPurgeResult(failures: 1)
        }
        let cutoff = now.addingTimeInterval(-Double(max(1, retentionDays())) * 86_400)
        let deadline = DispatchTime.now().uptimeNanoseconds
            &+ UInt64(max(0.05, min(retentionLimits.scanDuration, 10)) * 1_000_000_000)
        let keys: Set<URLResourceKey> = [.contentModificationDateKey, .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
        var traversalError: Error?
        guard let enumerator = fileManager.enumerator(
            at: directory,
            includingPropertiesForKeys: Array(keys),
            options: [.skipsSubdirectoryDescendants],
            errorHandler: { _, error in
                traversalError = error
                return false
            }
        ) else { return AppshotPurgeResult(failures: 1) }

        var entries = 0
        var aggregateBytes: Int64 = 0
        var retained = 0
        var candidates: [PurgeCandidate] = []
        for case let file as URL in enumerator {
            guard DispatchTime.now().uptimeNanoseconds < deadline,
                  entries < retentionLimits.maximumEntries else {
                return AppshotPurgeResult(failures: 1)
            }
            entries += 1
            var metadata = stat()
            guard Darwin.lstat(file.path, &metadata) == 0 else {
                retained += 1
                continue
            }
            if metadata.st_mode & S_IFMT == S_IFREG {
                let size = Int64(metadata.st_size)
                guard size >= 0,
                      aggregateBytes <= retentionLimits.maximumAggregateBytes - size else {
                    return AppshotPurgeResult(failures: 1)
                }
                aggregateBytes += size
            }
            guard metadata.st_mode & S_IFMT == S_IFREG,
                  metadata.st_nlink == 1,
                  metadata.st_uid == geteuid(),
                  metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
                  file.pathExtension.lowercased() == "png",
                  Date(
                    timeIntervalSince1970: TimeInterval(metadata.st_mtimespec.tv_sec)
                        + TimeInterval(metadata.st_mtimespec.tv_nsec) / 1_000_000_000
                  ) < cutoff else {
                retained += 1
                continue
            }
            candidates.append(PurgeCandidate(
                url: file,
                device: UInt64(truncatingIfNeeded: metadata.st_dev),
                inode: UInt64(metadata.st_ino),
                size: Int64(metadata.st_size),
                modifiedSeconds: Int64(metadata.st_mtimespec.tv_sec),
                modifiedNanoseconds: Int64(metadata.st_mtimespec.tv_nsec)
            ))
        }
        guard traversalError == nil, DispatchTime.now().uptimeNanoseconds < deadline else {
            return AppshotPurgeResult(failures: 1)
        }

        var result = AppshotPurgeResult(examined: entries, retained: retained)
        for candidate in candidates {
            guard DispatchTime.now().uptimeNanoseconds < deadline,
                  candidateStillMatches(candidate) else {
                result.retained += 1
                result.failures += 1
                continue
            }
            do {
                try fileManager.removeItem(at: candidate.url)
                result.removed += 1
            } catch {
                result.retained += 1
                result.failures += 1
            }
        }
        return result
    }

    private func candidateStillMatches(_ candidate: PurgeCandidate) -> Bool {
        var metadata = stat()
        guard Darwin.lstat(candidate.url.path, &metadata) == 0 else { return false }
        return metadata.st_mode & S_IFMT == S_IFREG &&
            metadata.st_nlink == 1 &&
            metadata.st_uid == geteuid() &&
            metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0 &&
            UInt64(truncatingIfNeeded: metadata.st_dev) == candidate.device &&
            UInt64(metadata.st_ino) == candidate.inode &&
            Int64(metadata.st_size) == candidate.size &&
            Int64(metadata.st_mtimespec.tv_sec) == candidate.modifiedSeconds &&
            Int64(metadata.st_mtimespec.tv_nsec) == candidate.modifiedNanoseconds
    }
}
