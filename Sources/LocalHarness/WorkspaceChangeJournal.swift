import CryptoKit
import Darwin
import Foundation

/// Hard limits applied to both live workspace scans and persisted checkpoints.
/// A scan fails closed instead of silently producing an incomplete recovery point.
struct WorkspaceJournalLimits: Codable, Equatable, Sendable {
    var maximumFileCount: Int
    var maximumEntryCount: Int
    var maximumTotalBytes: Int64
    var maximumFileBytes: Int
    var maximumDepth: Int
    var maximumCheckpointCount: Int
    var maximumStoredBytes: Int64
    var maximumManifestBytes: Int
    var maximumRelativePathBytes: Int
    var maximumScanDurationSeconds: Double

    init(
        maximumFileCount: Int = 20_000,
        maximumEntryCount: Int = 50_000,
        maximumTotalBytes: Int64 = 256 * 1_024 * 1_024,
        maximumFileBytes: Int = 16 * 1_024 * 1_024,
        maximumDepth: Int = 32,
        maximumCheckpointCount: Int = 24,
        maximumStoredBytes: Int64 = 2 * 1_024 * 1_024 * 1_024,
        maximumManifestBytes: Int = 16 * 1_024 * 1_024,
        maximumRelativePathBytes: Int = 4_096,
        maximumScanDurationSeconds: Double = 60
    ) {
        self.maximumFileCount = maximumFileCount
        self.maximumEntryCount = maximumEntryCount
        self.maximumTotalBytes = maximumTotalBytes
        self.maximumFileBytes = maximumFileBytes
        self.maximumDepth = maximumDepth
        self.maximumCheckpointCount = maximumCheckpointCount
        self.maximumStoredBytes = maximumStoredBytes
        self.maximumManifestBytes = maximumManifestBytes
        self.maximumRelativePathBytes = maximumRelativePathBytes
        self.maximumScanDurationSeconds = maximumScanDurationSeconds
    }

    var isValid: Bool {
        (1...100_000).contains(maximumFileCount) &&
            maximumEntryCount >= maximumFileCount &&
            maximumEntryCount <= 200_000 &&
            (1...(4 * 1_024 * 1_024 * 1_024)).contains(maximumTotalBytes) &&
            (1...(256 * 1_024 * 1_024)).contains(maximumFileBytes) &&
            Int64(maximumFileBytes) <= maximumTotalBytes &&
            (1...64).contains(maximumDepth) &&
            (1...100).contains(maximumCheckpointCount) &&
            maximumStoredBytes >= maximumTotalBytes &&
            maximumStoredBytes <= 16 * 1_024 * 1_024 * 1_024 &&
            (1...(64 * 1_024 * 1_024)).contains(maximumManifestBytes) &&
            (1...(64 * 1_024)).contains(maximumRelativePathBytes) &&
            maximumScanDurationSeconds.isFinite &&
            (0.001...600).contains(maximumScanDurationSeconds)
    }
}

struct WorkspaceFileSnapshot: Codable, Equatable, Sendable {
    let relativePath: String
    let byteCount: Int64
    let modificationTimeNanoseconds: Int64
    let posixPermissions: Int
    let contentSHA256: String
}

struct WorkspaceSnapshot: Codable, Equatable, Sendable {
    let workspaceCanonicalPath: String
    let files: [WorkspaceFileSnapshot]
    let totalBytes: Int64
}

enum WorkspaceCheckpointOrigin: String, Codable, Equatable, Sendable {
    case manual
    case automatic
}

struct WorkspaceCheckpoint: Codable, Equatable, Identifiable, Sendable {
    static let currentFormatVersion = 3

    let formatVersion: Int
    let id: UUID
    let createdAt: Date
    let label: String
    /// Missing only in v1 manifests, which are conservatively treated as
    /// manual so rotation can never delete a user-created checkpoint.
    let origin: WorkspaceCheckpointOrigin?
    let workspaceCanonicalPath: String
    let workspaceIdentifier: String
    let files: [WorkspaceFileSnapshot]
    let totalBytes: Int64
    /// A cheap identity of the recoverable tree, including ctime so an
    /// ordinary process cannot hide a same-sized rewrite by restoring mtime.
    let metadataFingerprint: String?

    var effectiveOrigin: WorkspaceCheckpointOrigin { origin ?? .manual }
}

struct WorkspaceCheckpointSummary: Codable, Equatable, Identifiable, Sendable {
    let id: UUID
    let createdAt: Date
    let label: String
    let origin: WorkspaceCheckpointOrigin
    let fileCount: Int
    let totalBytes: Int64
    let metadataFingerprint: String?

    init(
        id: UUID,
        createdAt: Date,
        label: String,
        origin: WorkspaceCheckpointOrigin = .manual,
        fileCount: Int,
        totalBytes: Int64,
        metadataFingerprint: String? = nil
    ) {
        self.id = id
        self.createdAt = createdAt
        self.label = label
        self.origin = origin
        self.fileCount = fileCount
        self.totalBytes = totalBytes
        self.metadataFingerprint = metadataFingerprint
    }
}

enum WorkspaceChangeKind: String, Codable, Equatable, Sendable {
    case added
    case modified
    case deleted
}

struct WorkspaceChange: Codable, Equatable, Sendable {
    let kind: WorkspaceChangeKind
    let relativePath: String
    let checkpoint: WorkspaceFileSnapshot?
    let current: WorkspaceFileSnapshot?
}

enum WorkspaceRestoreConflictKind: String, Codable, Equatable, Sendable {
    case wouldOverwriteModifiedFile
    case symbolicLinkAtDestination
    case directoryAtFileDestination
    case nonRegularDestination
    case obstructedParent
}

struct WorkspaceRestoreConflict: Codable, Equatable, Sendable {
    let kind: WorkspaceRestoreConflictKind
    let relativePath: String
}

struct WorkspaceRestorePreview: Codable, Equatable, Sendable {
    let checkpointID: UUID
    let workspaceIdentifier: String
    let changes: [WorkspaceChange]
    let conflicts: [WorkspaceRestoreConflict]
    /// Binds user approval to the exact live state that was previewed.
    let stateFingerprint: String
}

struct WorkspaceRestoreOptions: Codable, Equatable, Sendable {
    /// Must be explicitly enabled before a live, modified regular file is replaced.
    var overwriteModifiedFiles: Bool
    /// Must be explicitly enabled before files created after the checkpoint are removed.
    var removeAddedFiles: Bool

    init(overwriteModifiedFiles: Bool = false, removeAddedFiles: Bool = false) {
        self.overwriteModifiedFiles = overwriteModifiedFiles
        self.removeAddedFiles = removeAddedFiles
    }
}

struct WorkspaceRestoreReport: Codable, Equatable, Sendable {
    let restoredDeletedFiles: Int
    let overwrittenModifiedFiles: Int
    let removedAddedFiles: Int
    let unchangedFiles: Int
}

enum WorkspaceJournalError: Error, Equatable, LocalizedError {
    case invalidLimits
    case invalidWorkspace
    case workspaceRootChanged
    case unsafeStorage
    case unsafeCheckpoint
    case checkpointNotFound
    case checkpointLimitExceeded(maximum: Int)
    case storedByteLimitExceeded(maximum: Int64)
    case fileCountLimitExceeded(maximum: Int)
    case entryCountLimitExceeded(maximum: Int)
    case totalByteLimitExceeded(maximum: Int64)
    case fileTooLarge(relativePath: String, maximum: Int)
    case depthLimitExceeded(relativePath: String, maximum: Int)
    case relativePathByteLimitExceeded(maximum: Int)
    case scanDeadlineExceeded
    case cancelled
    case workspaceChangedDuringScan(relativePath: String)
    case stalePreview
    case restoreConflicts([WorkspaceRestoreConflict])
    case checkpointContentCorrupt(relativePath: String)
    case restoreFailed
    case rollbackFailed(recoveryDirectory: String)

    var errorDescription: String? {
        switch self {
        case .invalidLimits:
            return "Workspace recovery limits are invalid."
        case .invalidWorkspace:
            return "The approved workspace is not a readable local directory."
        case .workspaceRootChanged:
            return "The approved workspace changed while recovery was active."
        case .unsafeStorage:
            return "Workspace recovery storage is missing, linked, or has unsafe permissions."
        case .unsafeCheckpoint:
            return "The recovery checkpoint is malformed or does not belong to this workspace."
        case .checkpointNotFound:
            return "The selected recovery checkpoint no longer exists."
        case .checkpointLimitExceeded(let maximum):
            return "The recovery checkpoint limit of \(maximum) has been reached."
        case .storedByteLimitExceeded(let maximum):
            return "Recovery storage would exceed its \(maximum)-byte limit."
        case .fileCountLimitExceeded(let maximum):
            return "The workspace contains more than the \(maximum) recoverable files allowed."
        case .entryCountLimitExceeded(let maximum):
            return "The workspace contains more than the \(maximum) filesystem entries allowed."
        case .totalByteLimitExceeded(let maximum):
            return "Recoverable workspace content exceeds the \(maximum)-byte limit."
        case .fileTooLarge(let path, let maximum):
            return "\(path) exceeds the per-file recovery limit of \(maximum) bytes."
        case .depthLimitExceeded(let path, let maximum):
            return "\(path) exceeds the workspace recovery depth limit of \(maximum)."
        case .relativePathByteLimitExceeded(let maximum):
            return "A workspace path exceeds the recovery limit of \(maximum) UTF-8 bytes."
        case .scanDeadlineExceeded:
            return "The workspace recovery scan exceeded its monotonic time limit."
        case .cancelled:
            return "The workspace recovery scan was cancelled before anything was published."
        case .workspaceChangedDuringScan(let path):
            return "\(path) changed while the workspace was being scanned. Try again."
        case .stalePreview:
            return "The workspace changed after the restore preview. Preview it again before restoring."
        case .restoreConflicts:
            return "The restore has conflicts that require explicit approval or cannot be restored safely."
        case .checkpointContentCorrupt(let path):
            return "Stored recovery content for \(path) failed its integrity check."
        case .restoreFailed:
            return "The workspace could not be restored. Its previous files were put back."
        case .rollbackFailed(let recoveryDirectory):
            return "The restore failed and its automatic rollback could not be completed. Recovery material was preserved at \(recoveryDirectory). Stop agent work and copy that folder before retrying."
        }
    }
}

enum WorkspaceRestoreMutationPhase: Sendable {
    case apply
    case rollback
}

/// Crosses the WebKit -> native -> journal boundary without relying on the
/// caller continuing to await a reply. Cancelling a browser send therefore
/// stops the physical scan and removes its private staging tree.
final class WorkspaceJournalOperationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func check() throws {
        lock.lock()
        let value = cancelled
        lock.unlock()
        if value || Task.isCancelled { throw WorkspaceJournalError.cancelled }
    }
}

/// Deliberately narrow exclusion policy for source workspaces. Generated trees
/// and likely credential material are never read or copied into a checkpoint.
enum WorkspaceJournalExclusionPolicy {
    private static let excludedDirectoryNames: Set<String> = [
        ".git", ".hg", ".svn", ".build", "build", "deriveddata", "dist", "out",
        "node_modules", "vendor", "vendorruntime", "pods", "carthage", "target",
        ".next", ".cache", ".turbo", ".parcel-cache", ".pytest_cache", "__pycache__",
        ".gradle", ".venv", "venv", "coverage",
        ".ssh", ".gnupg", ".aws", ".azure", ".secrets", "secrets"
    ]

    private static let exactSecretFileNames: Set<String> = [
        ".env", ".credentials.yaml", ".credentials.yml", ".git-credentials",
        ".netrc", ".npmrc", ".pypirc", ".envrc", "id_rsa", "id_ed25519"
    ]

    private static let secretExtensions: Set<String> = [
        "key", "pem", "p12", "pfx", "jks", "keystore"
    ]

    static func excludesDirectory(named name: String) -> Bool {
        excludedDirectoryNames.contains(name.lowercased())
    }

    static func excludesFile(named name: String) -> Bool {
        let lower = name.lowercased()
        if lower == ".ds_store" || exactSecretFileNames.contains(lower) || lower.hasPrefix(".env.") {
            return true
        }
        let stem = URL(fileURLWithPath: lower).deletingPathExtension().lastPathComponent
        let tokens = stem.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        if lower.contains("private-key") || lower.contains("private_key") ||
            lower.contains("api-key") || lower.contains("api_key") ||
            lower.contains("auth-token") || lower.contains("auth_token") ||
            lower.contains("access-token") || lower.contains("access_token") ||
            lower.contains("refresh-token") || lower.contains("refresh_token") ||
            !Set(tokens).isDisjoint(with: Set([
                "credential", "credentials", "secret", "secrets", "privatekey", "password", "passphrase"
            ])) {
            return true
        }
        return secretExtensions.contains(URL(fileURLWithPath: lower).pathExtension)
    }
}

/// A bounded, local-only recovery journal for exactly one approved workspace.
/// Checkpoints live under Application Support and are never allowed to target a
/// different canonical workspace path.
final class WorkspaceChangeJournal: @unchecked Sendable {
    private struct FileIdentity: Equatable {
        let device: UInt64
        let inode: UInt64
        let byteCount: Int64
        let modificationTimeNanoseconds: Int64
        let changeTimeNanoseconds: Int64
        let permissions: Int
    }

    private struct ScanDeadline {
        let uptimeNanoseconds: UInt64
        let now: @Sendable () -> UInt64
        let cancellation: WorkspaceJournalOperationCancellation?

        func check() throws {
            try cancellation?.check()
            guard now() < uptimeNanoseconds else {
                throw WorkspaceJournalError.scanDeadlineExceeded
            }
        }
    }

    private enum NodeKind: Equatable {
        case missing
        case regular
        case directory
        case symbolicLink
        case other
    }

    private struct RollbackEntry {
        let relativePath: String
        let existed: Bool
        let data: Data?
        let permissions: Int
        let modificationTimeNanoseconds: Int64
    }

    private let fileManager: FileManager
    private let workspaceRoot: URL
    private let workspaceIdentifier: String
    private let workspaceDevice: UInt64
    private let workspaceInode: UInt64
    private let recoveryRoot: URL
    private let checkpointsRoot: URL
    private let limits: WorkspaceJournalLimits
    private let now: @Sendable () -> Date
    private let monotonicNow: @Sendable () -> UInt64
    private let makeUUID: @Sendable () -> UUID
    private let restoreMutationHook: (@Sendable (WorkspaceRestoreMutationPhase, String) throws -> Void)?
    private let lock = NSLock()

    init(
        approvedWorkspace: URL,
        applicationSupport: URL,
        limits: WorkspaceJournalLimits = WorkspaceJournalLimits(),
        fileManager: FileManager = .default,
        now: @escaping @Sendable () -> Date = { Date() },
        monotonicNow: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        makeUUID: @escaping @Sendable () -> UUID = { UUID() },
        restoreMutationHook: (@Sendable (WorkspaceRestoreMutationPhase, String) throws -> Void)? = nil
    ) throws {
        guard limits.isValid else { throw WorkspaceJournalError.invalidLimits }
        guard approvedWorkspace.isFileURL, applicationSupport.isFileURL else {
            throw WorkspaceJournalError.invalidWorkspace
        }
        self.fileManager = fileManager
        self.limits = limits
        self.now = now
        self.monotonicNow = monotonicNow
        self.makeUUID = makeUUID
        self.restoreMutationHook = restoreMutationHook

        let canonicalWorkspace = approvedWorkspace.resolvingSymlinksInPath().standardizedFileURL
        guard let workspaceStat = Self.lstat(canonicalWorkspace), Self.kind(of: workspaceStat) == .directory else {
            throw WorkspaceJournalError.invalidWorkspace
        }
        workspaceRoot = canonicalWorkspace
        workspaceDevice = UInt64(truncatingIfNeeded: workspaceStat.st_dev)
        workspaceInode = UInt64(workspaceStat.st_ino)
        workspaceIdentifier = Self.sha256Hex(Data(canonicalWorkspace.path.utf8))

        let prospectiveSupport = applicationSupport.resolvingSymlinksInPath().standardizedFileURL
        guard prospectiveSupport != workspaceRoot,
              !prospectiveSupport.path.hasPrefix(workspaceRoot.path + "/") else {
            throw WorkspaceJournalError.unsafeStorage
        }
        try fileManager.createDirectory(at: prospectiveSupport, withIntermediateDirectories: true)
        let support = prospectiveSupport.resolvingSymlinksInPath().standardizedFileURL
        guard support != workspaceRoot,
              !support.path.hasPrefix(workspaceRoot.path + "/") else {
            throw WorkspaceJournalError.unsafeStorage
        }
        let journalRoot = support.appendingPathComponent("WorkspaceRecovery", isDirectory: true)
        let versionRoot = journalRoot.appendingPathComponent("v1", isDirectory: true)
        recoveryRoot = versionRoot.appendingPathComponent(workspaceIdentifier, isDirectory: true)
        checkpointsRoot = recoveryRoot.appendingPathComponent("checkpoints", isDirectory: true)
        guard recoveryRoot != workspaceRoot,
              !recoveryRoot.path.hasPrefix(workspaceRoot.path + "/") else {
            throw WorkspaceJournalError.unsafeStorage
        }
        try Self.ensurePrivateDirectory(journalRoot, fileManager: fileManager)
        try Self.ensurePrivateDirectory(versionRoot, fileManager: fileManager)
        try Self.ensurePrivateDirectory(recoveryRoot, fileManager: fileManager)
        try Self.ensurePrivateDirectory(checkpointsRoot, fileManager: fileManager)
    }

    var approvedWorkspaceURL: URL { workspaceRoot }

    func currentSnapshot() throws -> WorkspaceSnapshot {
        try withLock {
            try validateWorkspaceRoot()
            return try scanWorkspace()
        }
    }

    /// Enumerates and authenticates recoverable entry metadata without
    /// opening or copying file contents. This is the only reuse proof accepted
    /// for an automatic checkpoint; ctime makes same-size/mtime rewrites
    /// observable while keeping a 10k-file no-change turn inexpensive.
    func currentMetadataFingerprint(
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) throws -> String {
        try withLock {
            try validateWorkspaceRoot()
            return try scanWorkspaceMetadata(cancellation: cancellation)
        }
    }

    func listCheckpoints(
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) throws -> [WorkspaceCheckpointSummary] {
        try withLock {
            try validateStorage()
            return try loadAllCheckpoints(cancellation: cancellation).map {
                WorkspaceCheckpointSummary(
                    id: $0.id,
                    createdAt: $0.createdAt,
                    label: $0.label,
                    origin: $0.effectiveOrigin,
                    fileCount: $0.files.count,
                    totalBytes: $0.totalBytes,
                    metadataFingerprint: $0.metadataFingerprint
                )
            }.sorted {
                if $0.createdAt == $1.createdAt { return $0.id.uuidString < $1.id.uuidString }
                return $0.createdAt > $1.createdAt
            }
        }
    }

    @discardableResult
    func captureCheckpoint(
        label: String,
        origin: WorkspaceCheckpointOrigin = .manual,
        replacing replacementID: UUID? = nil,
        expectedMetadataFingerprint: String? = nil,
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) throws -> WorkspaceCheckpoint {
        try withLock {
            try cancellation?.check()
            try validateWorkspaceRoot()
            try validateStorage()
            let existing = try loadAllCheckpoints(cancellation: cancellation)
            let replacement = replacementID.flatMap { identifier in existing.first { $0.id == identifier } }
            if replacementID != nil, replacement == nil { throw WorkspaceJournalError.checkpointNotFound }
            let retainedCount = existing.count - (replacement == nil ? 0 : 1)
            guard retainedCount < limits.maximumCheckpointCount else {
                throw WorkspaceJournalError.checkpointLimitExceeded(maximum: limits.maximumCheckpointCount)
            }

            let identifier = makeUUID()
            let finalDirectory = checkpointDirectory(identifier)
            guard Self.lstat(finalDirectory) == nil else { throw WorkspaceJournalError.unsafeStorage }
            let staging = recoveryRoot.appendingPathComponent(".staging-\(identifier.uuidString)", isDirectory: true)
            guard Self.lstat(staging) == nil else { throw WorkspaceJournalError.unsafeStorage }
            try Self.ensurePrivateDirectory(staging, fileManager: fileManager)
            let contentRoot = staging.appendingPathComponent("contents", isDirectory: true)
            try Self.ensurePrivateDirectory(contentRoot, fileManager: fileManager)
            var committed = false
            defer {
                if !committed { try? fileManager.removeItem(at: staging) }
            }

            let metadataBefore = try scanWorkspaceMetadata(cancellation: cancellation)
            if let expectedMetadataFingerprint,
               expectedMetadataFingerprint != metadataBefore {
                throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: "<workspace>")
            }
            let snapshot = try scanWorkspace(captureRoot: contentRoot, cancellation: cancellation)
            let metadataAfter = try scanWorkspaceMetadata(cancellation: cancellation)
            guard metadataAfter == metadataBefore else {
                throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: "<workspace>")
            }
            let retained = existing.filter { $0.id != replacement?.id }
            let currentStoredBytes = try retained.reduce(Int64(0)) { partial, checkpoint in
                let (sum, overflow) = partial.addingReportingOverflow(checkpoint.totalBytes)
                guard !overflow else { throw WorkspaceJournalError.unsafeCheckpoint }
                return sum
            }
            let (prospectiveStoredBytes, overflow) = currentStoredBytes.addingReportingOverflow(snapshot.totalBytes)
            guard !overflow, prospectiveStoredBytes <= limits.maximumStoredBytes else {
                throw WorkspaceJournalError.storedByteLimitExceeded(maximum: limits.maximumStoredBytes)
            }

            let checkpoint = WorkspaceCheckpoint(
                formatVersion: WorkspaceCheckpoint.currentFormatVersion,
                id: identifier,
                createdAt: now(),
                label: Self.normalizedLabel(label),
                origin: origin,
                workspaceCanonicalPath: workspaceRoot.path,
                workspaceIdentifier: workspaceIdentifier,
                files: snapshot.files,
                totalBytes: snapshot.totalBytes,
                metadataFingerprint: metadataAfter
            )
            let manifest = try Self.encodeCheckpoint(checkpoint)
            guard manifest.count <= limits.maximumManifestBytes else {
                throw WorkspaceJournalError.unsafeCheckpoint
            }
            try Self.writePrivateFile(
                manifest,
                to: staging.appendingPathComponent("manifest.json"),
                permissions: 0o600,
                fileManager: fileManager
            )
            try cancellation?.check()
            try fileManager.moveItem(at: staging, to: finalDirectory)
            try Self.setPrivatePermissions(finalDirectory, directory: true, fileManager: fileManager)
            committed = true
            if let replacement {
                // The new, fully authenticated checkpoint now exists. Only at
                // this point may rotation remove the previous automatic one.
                let oldDirectory = checkpointDirectory(replacement.id)
                let tombstone = recoveryRoot.appendingPathComponent(
                    ".delete-\(replacement.id.uuidString)-\(makeUUID().uuidString)",
                    isDirectory: true
                )
                guard Self.lstat(tombstone) == nil else { throw WorkspaceJournalError.unsafeStorage }
                try fileManager.moveItem(at: oldDirectory, to: tombstone)
                do {
                    try fileManager.removeItem(at: tombstone)
                } catch {
                    // The replacement remains valid. Restore the old entry so
                    // an operator can retry rotation without losing either.
                    try? fileManager.moveItem(at: tombstone, to: oldDirectory)
                    throw error
                }
            }
            return checkpoint
        }
    }

    func previewRestore(checkpointID: UUID) throws -> WorkspaceRestorePreview {
        try withLock {
            try validateWorkspaceRoot()
            try validateStorage()
            let checkpoint = try loadCheckpoint(checkpointID)
            return try makeRestorePreview(checkpoint)
        }
    }

    func deleteCheckpoint(checkpointID: UUID) throws {
        try withLock {
            try validateStorage()
            _ = try loadCheckpoint(checkpointID)
            let source = checkpointDirectory(checkpointID)
            let tombstone = recoveryRoot.appendingPathComponent(
                ".deleting-\(checkpointID.uuidString)-\(makeUUID().uuidString)",
                isDirectory: true
            )
            guard Self.lstat(tombstone) == nil else { throw WorkspaceJournalError.unsafeStorage }
            try fileManager.moveItem(at: source, to: tombstone)
            do {
                try fileManager.removeItem(at: tombstone)
            } catch {
                try? fileManager.moveItem(at: tombstone, to: source)
                throw error
            }
        }
    }

    /// Restores only after the caller has shown and retained a preview. Modified
    /// files require `overwriteModifiedFiles`; added files are retained unless
    /// `removeAddedFiles` is separately enabled. Symlinks and type obstructions
    /// are never replaced, even with overwrite approval.
    func restore(
        checkpointID: UUID,
        preview approvedPreview: WorkspaceRestorePreview,
        options: WorkspaceRestoreOptions = WorkspaceRestoreOptions()
    ) throws -> WorkspaceRestoreReport {
        try withLock {
            try validateWorkspaceRoot()
            try validateStorage()
            let checkpoint = try loadCheckpoint(checkpointID)
            guard approvedPreview.checkpointID == checkpointID,
                  approvedPreview.workspaceIdentifier == workspaceIdentifier else {
                throw WorkspaceJournalError.stalePreview
            }
            let preview = try makeRestorePreview(checkpoint)
            guard preview.stateFingerprint == approvedPreview.stateFingerprint else {
                throw WorkspaceJournalError.stalePreview
            }

            let hardConflicts = preview.conflicts.filter { $0.kind != .wouldOverwriteModifiedFile }
            if !hardConflicts.isEmpty {
                throw WorkspaceJournalError.restoreConflicts(hardConflicts)
            }
            let overwriteConflicts = preview.conflicts.filter { $0.kind == .wouldOverwriteModifiedFile }
            if !overwriteConflicts.isEmpty && !options.overwriteModifiedFiles {
                throw WorkspaceJournalError.restoreConflicts(overwriteConflicts)
            }

            let restoreChanges = preview.changes.filter { $0.kind == .deleted || $0.kind == .modified }
            let additionsToRemove = options.removeAddedFiles
                ? preview.changes.filter { $0.kind == .added }
                : []

            // Authenticate every checkpoint blob before changing the workspace.
            var checkpointContents: [String: Data] = [:]
            for change in restoreChanges {
                guard let record = change.checkpoint else { throw WorkspaceJournalError.unsafeCheckpoint }
                checkpointContents[record.relativePath] = try readAndValidateCheckpointContent(record, checkpointID: checkpointID)
            }

            let transactionID = makeUUID()
            let transactionRoot = recoveryRoot.appendingPathComponent(".restore-\(transactionID.uuidString)", isDirectory: true)
            guard Self.lstat(transactionRoot) == nil else { throw WorkspaceJournalError.unsafeStorage }
            try Self.ensurePrivateDirectory(transactionRoot, fileManager: fileManager)
            var rollbackEntries: [RollbackEntry] = []
            var transactionFinished = false
            defer {
                if transactionFinished { try? fileManager.removeItem(at: transactionRoot) }
            }

            do {
                for change in restoreChanges where change.kind == .modified {
                    guard let expected = change.current else { throw WorkspaceJournalError.stalePreview }
                    let (record, data) = try readCurrentRegularFile(expected.relativePath)
                    guard record == expected else { throw WorkspaceJournalError.stalePreview }
                    rollbackEntries.append(RollbackEntry(
                        relativePath: expected.relativePath,
                        existed: true,
                        data: data,
                        permissions: expected.posixPermissions,
                        modificationTimeNanoseconds: expected.modificationTimeNanoseconds
                    ))
                    let backup = try safeDescendant(expected.relativePath, of: transactionRoot)
                    try Self.writePrivateFile(data, to: backup, permissions: 0o600, fileManager: fileManager)
                }
                for change in additionsToRemove {
                    guard let expected = change.current else { throw WorkspaceJournalError.stalePreview }
                    let (record, data) = try readCurrentRegularFile(expected.relativePath)
                    guard record == expected else { throw WorkspaceJournalError.stalePreview }
                    rollbackEntries.append(RollbackEntry(
                        relativePath: expected.relativePath,
                        existed: true,
                        data: data,
                        permissions: expected.posixPermissions,
                        modificationTimeNanoseconds: expected.modificationTimeNanoseconds
                    ))
                    let backup = try safeDescendant(expected.relativePath, of: transactionRoot)
                    try Self.writePrivateFile(data, to: backup, permissions: 0o600, fileManager: fileManager)
                }
                for change in restoreChanges where change.kind == .deleted {
                    guard nodeKind(at: change.relativePath) == .missing else {
                        throw WorkspaceJournalError.stalePreview
                    }
                    rollbackEntries.append(RollbackEntry(
                        relativePath: change.relativePath,
                        existed: false,
                        data: nil,
                        permissions: 0,
                        modificationTimeNanoseconds: 0
                    ))
                }

                var restored = 0
                var overwritten = 0
                var removed = 0
                for change in restoreChanges {
                    guard let record = change.checkpoint,
                          let data = checkpointContents[record.relativePath] else {
                        throw WorkspaceJournalError.unsafeCheckpoint
                    }
                    switch change.kind {
                    case .deleted:
                        try restoreMutationHook?(.apply, record.relativePath)
                        try writeWorkspaceFile(
                            data,
                            record: record,
                            expectedCurrent: nil,
                            allowReplacement: false
                        )
                        restored += 1
                    case .modified:
                        try restoreMutationHook?(.apply, record.relativePath)
                        try writeWorkspaceFile(
                            data,
                            record: record,
                            expectedCurrent: change.current,
                            allowReplacement: true
                        )
                        overwritten += 1
                    case .added:
                        break
                    }
                }
                for change in additionsToRemove {
                    guard let expected = change.current else { throw WorkspaceJournalError.stalePreview }
                    let (live, _) = try readCurrentRegularFile(expected.relativePath)
                    guard live == expected else { throw WorkspaceJournalError.stalePreview }
                    let destination = try safeWorkspaceURL(expected.relativePath)
                    try restoreMutationHook?(.apply, expected.relativePath)
                    guard Darwin.unlink(destination.path) == 0 else { throw WorkspaceJournalError.restoreFailed }
                    removed += 1
                }
                transactionFinished = true
                return WorkspaceRestoreReport(
                    restoredDeletedFiles: restored,
                    overwrittenModifiedFiles: overwritten,
                    removedAddedFiles: removed,
                    unchangedFiles: checkpoint.files.count - restoreChanges.count
                )
            } catch {
                let rollbackSucceeded = rollback(rollbackEntries.reversed())
                if !rollbackSucceeded {
                    // Keep the owner-only transaction directory. It contains
                    // the authenticated pre-restore bytes needed for manual
                    // recovery when the automatic rollback itself fails.
                    throw WorkspaceJournalError.rollbackFailed(recoveryDirectory: transactionRoot.path)
                }
                transactionFinished = true
                if let journalError = error as? WorkspaceJournalError { throw journalError }
                throw WorkspaceJournalError.restoreFailed
            }
        }
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private func validateWorkspaceRoot() throws {
        guard workspaceRoot.resolvingSymlinksInPath().standardizedFileURL == workspaceRoot,
              let info = Self.lstat(workspaceRoot), Self.kind(of: info) == .directory,
              UInt64(truncatingIfNeeded: info.st_dev) == workspaceDevice,
              UInt64(info.st_ino) == workspaceInode else {
            throw WorkspaceJournalError.workspaceRootChanged
        }
    }

    private func validateStorage() throws {
        guard Self.isPrivateDirectory(recoveryRoot), Self.isPrivateDirectory(checkpointsRoot) else {
            throw WorkspaceJournalError.unsafeStorage
        }
    }

    private func scanWorkspace(
        captureRoot: URL? = nil,
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) throws -> WorkspaceSnapshot {
        let deadline = makeScanDeadline(cancellation: cancellation)
        var files: [WorkspaceFileSnapshot] = []
        var totalBytes: Int64 = 0
        var encounteredEntries = 0

        try deadline.check()
        let workspaceDescriptor = Darwin.open(
            workspaceRoot.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard workspaceDescriptor >= 0 else { throw WorkspaceJournalError.workspaceRootChanged }
        defer { Darwin.close(workspaceDescriptor) }
        var openedWorkspace = stat()
        guard Darwin.fstat(workspaceDescriptor, &openedWorkspace) == 0,
              openedWorkspace.st_mode & S_IFMT == S_IFDIR,
              UInt64(truncatingIfNeeded: openedWorkspace.st_dev) == workspaceDevice,
              UInt64(openedWorkspace.st_ino) == workspaceInode else {
            throw WorkspaceJournalError.workspaceRootChanged
        }

        var captureDescriptor: Int32 = -1
        if let captureRoot {
            captureDescriptor = Darwin.open(
                captureRoot.path,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            var metadata = stat()
            guard captureDescriptor >= 0,
                  Darwin.fstat(captureDescriptor, &metadata) == 0,
                  Self.isPrivateDirectoryMetadata(metadata) else {
                if captureDescriptor >= 0 { Darwin.close(captureDescriptor) }
                throw WorkspaceJournalError.unsafeStorage
            }
        }
        defer { if captureDescriptor >= 0 { Darwin.close(captureDescriptor) } }

        func visit(_ directoryDescriptor: Int32, components: [String]) throws {
            try deadline.check()
            let parentPath = components.joined(separator: "/")
            try forEachDirectoryEntry(
                descriptor: directoryDescriptor,
                relativePath: parentPath,
                deadline: deadline
            ) { name in
                encounteredEntries += 1
                guard encounteredEntries <= limits.maximumEntryCount else {
                    throw WorkspaceJournalError.entryCountLimitExceeded(maximum: limits.maximumEntryCount)
                }
                let relativeComponents = components + [name]
                let relativePath = relativeComponents.joined(separator: "/")
                guard Self.validRelativeComponents(relativeComponents) else {
                    throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                }
                guard relativePath.utf8.count <= limits.maximumRelativePathBytes else {
                    throw WorkspaceJournalError.relativePathByteLimitExceeded(
                        maximum: limits.maximumRelativePathBytes
                    )
                }
                var before = stat()
                guard fstatat(directoryDescriptor, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else {
                    throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                }
                switch Self.kind(of: before) {
                case .symbolicLink, .other, .missing:
                    return
                case .directory:
                    if WorkspaceJournalExclusionPolicy.excludesDirectory(named: name) { return }
                    guard relativeComponents.count <= limits.maximumDepth else {
                        throw WorkspaceJournalError.depthLimitExceeded(
                            relativePath: relativePath,
                            maximum: limits.maximumDepth
                        )
                    }
                    let childDescriptor = openat(
                        directoryDescriptor,
                        name,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                    guard childDescriptor >= 0 else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    defer { Darwin.close(childDescriptor) }
                    var opened = stat()
                    guard Darwin.fstat(childDescriptor, &opened) == 0,
                          opened.st_mode & S_IFMT == S_IFDIR,
                          Self.sameNode(before, opened) else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    try visit(childDescriptor, components: relativeComponents)
                    var afterDescriptor = stat()
                    var afterPath = stat()
                    guard Darwin.fstat(childDescriptor, &afterDescriptor) == 0,
                          fstatat(directoryDescriptor, name, &afterPath, AT_SYMLINK_NOFOLLOW) == 0,
                          afterDescriptor.st_mode & S_IFMT == S_IFDIR,
                          afterPath.st_mode & S_IFMT == S_IFDIR,
                          Self.sameNode(opened, afterDescriptor),
                          Self.sameNode(opened, afterPath) else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                case .regular:
                    if WorkspaceJournalExclusionPolicy.excludesFile(named: name) { return }
                    guard relativeComponents.count <= limits.maximumDepth else {
                        throw WorkspaceJournalError.depthLimitExceeded(
                            relativePath: relativePath,
                            maximum: limits.maximumDepth
                        )
                    }
                    guard files.count < limits.maximumFileCount else {
                        throw WorkspaceJournalError.fileCountLimitExceeded(maximum: limits.maximumFileCount)
                    }
                    let initial = Self.identity(before)
                    guard initial.byteCount >= 0, initial.byteCount <= Int64(limits.maximumFileBytes) else {
                        throw WorkspaceJournalError.fileTooLarge(
                            relativePath: relativePath,
                            maximum: limits.maximumFileBytes
                        )
                    }
                    let (nextTotal, overflow) = totalBytes.addingReportingOverflow(initial.byteCount)
                    guard !overflow, nextTotal <= limits.maximumTotalBytes else {
                        throw WorkspaceJournalError.totalByteLimitExceeded(maximum: limits.maximumTotalBytes)
                    }
                    let sourceDescriptor = openat(
                        directoryDescriptor,
                        name,
                        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                    guard sourceDescriptor >= 0 else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    defer { Darwin.close(sourceDescriptor) }
                    var opened = stat()
                    guard Darwin.fstat(sourceDescriptor, &opened) == 0,
                          opened.st_mode & S_IFMT == S_IFREG,
                          Self.identity(opened) == initial else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }

                    let destinationDescriptor: Int32
                    if captureDescriptor >= 0 {
                        destinationDescriptor = try openPrivateCaptureFile(
                            relativeComponents: relativeComponents,
                            rootDescriptor: captureDescriptor,
                            deadline: deadline
                        )
                    } else {
                        destinationDescriptor = -1
                    }
                    defer { if destinationDescriptor >= 0 { Darwin.close(destinationDescriptor) } }

                    var digest = SHA256()
                    var bytesRead: Int64 = 0
                    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
                    while true {
                        try deadline.check()
                        let count = buffer.withUnsafeMutableBytes { rawBuffer in
                            Darwin.read(sourceDescriptor, rawBuffer.baseAddress, rawBuffer.count)
                        }
                        if count == 0 { break }
                        if count < 0 {
                            if errno == EINTR { continue }
                            throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                        }
                        let (prospectiveBytes, readOverflow) = bytesRead.addingReportingOverflow(Int64(count))
                        guard !readOverflow, prospectiveBytes <= Int64(limits.maximumFileBytes) else {
                            throw WorkspaceJournalError.fileTooLarge(
                                relativePath: relativePath,
                                maximum: limits.maximumFileBytes
                            )
                        }
                        buffer.withUnsafeBytes { rawBuffer in
                            digest.update(bufferPointer: UnsafeRawBufferPointer(rebasing: rawBuffer[..<count]))
                        }
                        if destinationDescriptor >= 0 {
                            try Self.writeAll(
                                buffer,
                                count: count,
                                descriptor: destinationDescriptor,
                                deadline: deadline
                            )
                        }
                        bytesRead = prospectiveBytes
                    }

                    var afterDescriptor = stat()
                    var afterPath = stat()
                    guard bytesRead == initial.byteCount,
                          Darwin.fstat(sourceDescriptor, &afterDescriptor) == 0,
                          fstatat(directoryDescriptor, name, &afterPath, AT_SYMLINK_NOFOLLOW) == 0,
                          afterDescriptor.st_mode & S_IFMT == S_IFREG,
                          afterPath.st_mode & S_IFMT == S_IFREG,
                          Self.identity(afterDescriptor) == initial,
                          Self.identity(afterPath) == initial else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    if destinationDescriptor >= 0 {
                        var captured = stat()
                        guard Darwin.fchmod(destinationDescriptor, mode_t(0o600)) == 0,
                              Darwin.fsync(destinationDescriptor) == 0,
                              Darwin.fstat(destinationDescriptor, &captured) == 0,
                              captured.st_mode & S_IFMT == S_IFREG,
                              captured.st_uid == geteuid(),
                              captured.st_nlink == 1,
                              (Int(captured.st_mode) & 0o777) == 0o600,
                              Int64(captured.st_size) == bytesRead else {
                            throw WorkspaceJournalError.unsafeStorage
                        }
                    }
                    let record = WorkspaceFileSnapshot(
                        relativePath: relativePath,
                        byteCount: initial.byteCount,
                        modificationTimeNanoseconds: initial.modificationTimeNanoseconds,
                        posixPermissions: initial.permissions,
                        contentSHA256: digest.finalize().map { String(format: "%02x", $0) }.joined()
                    )
                    files.append(record)
                    totalBytes = nextTotal
                }
            }
        }

        try visit(workspaceDescriptor, components: [])
        try deadline.check()
        try validateWorkspaceRoot()
        return WorkspaceSnapshot(
            workspaceCanonicalPath: workspaceRoot.path,
            files: files.sorted { $0.relativePath < $1.relativePath },
            totalBytes: totalBytes
        )
    }

    private func scanWorkspaceMetadata(
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) throws -> String {
        let deadline = makeScanDeadline(cancellation: cancellation)
        var records: [String] = []
        records.reserveCapacity(min(limits.maximumEntryCount, 10_000))
        var fileCount = 0
        var totalBytes: Int64 = 0
        var encounteredEntries = 0

        let workspaceDescriptor = Darwin.open(
            workspaceRoot.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard workspaceDescriptor >= 0 else { throw WorkspaceJournalError.workspaceRootChanged }
        defer { Darwin.close(workspaceDescriptor) }
        var rootMetadata = stat()
        guard Darwin.fstat(workspaceDescriptor, &rootMetadata) == 0,
              rootMetadata.st_mode & S_IFMT == S_IFDIR,
              UInt64(truncatingIfNeeded: rootMetadata.st_dev) == workspaceDevice,
              UInt64(rootMetadata.st_ino) == workspaceInode else {
            throw WorkspaceJournalError.workspaceRootChanged
        }

        func appendRecord(kind: String, path: String, metadata: stat) {
            let identity = Self.identity(metadata)
            records.append([
                String(path.utf8.count), path, kind,
                String(identity.device), String(identity.inode), String(identity.byteCount),
                String(identity.modificationTimeNanoseconds), String(identity.changeTimeNanoseconds),
                String(identity.permissions)
            ].joined(separator: "\u{1F}"))
        }

        appendRecord(kind: "d", path: "", metadata: rootMetadata)

        func visit(_ descriptor: Int32, components: [String]) throws {
            try deadline.check()
            let parentPath = components.joined(separator: "/")
            try forEachDirectoryEntry(
                descriptor: descriptor,
                relativePath: parentPath,
                deadline: deadline
            ) { name in
                encounteredEntries += 1
                guard encounteredEntries <= limits.maximumEntryCount else {
                    throw WorkspaceJournalError.entryCountLimitExceeded(maximum: limits.maximumEntryCount)
                }
                let relativeComponents = components + [name]
                let relativePath = relativeComponents.joined(separator: "/")
                guard Self.validRelativeComponents(relativeComponents) else {
                    throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                }
                guard relativePath.utf8.count <= limits.maximumRelativePathBytes else {
                    throw WorkspaceJournalError.relativePathByteLimitExceeded(maximum: limits.maximumRelativePathBytes)
                }
                var before = stat()
                guard fstatat(descriptor, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else {
                    throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                }
                switch Self.kind(of: before) {
                case .directory:
                    if WorkspaceJournalExclusionPolicy.excludesDirectory(named: name) { return }
                    guard relativeComponents.count <= limits.maximumDepth else {
                        throw WorkspaceJournalError.depthLimitExceeded(
                            relativePath: relativePath,
                            maximum: limits.maximumDepth
                        )
                    }
                    let child = openat(
                        descriptor,
                        name,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                    guard child >= 0 else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    defer { Darwin.close(child) }
                    var opened = stat()
                    guard Darwin.fstat(child, &opened) == 0,
                          opened.st_mode & S_IFMT == S_IFDIR,
                          Self.identity(opened) == Self.identity(before) else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    try visit(child, components: relativeComponents)
                    var afterDescriptor = stat()
                    var afterPath = stat()
                    guard Darwin.fstat(child, &afterDescriptor) == 0,
                          fstatat(descriptor, name, &afterPath, AT_SYMLINK_NOFOLLOW) == 0,
                          Self.identity(afterDescriptor) == Self.identity(opened),
                          Self.identity(afterPath) == Self.identity(opened) else {
                        throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                    }
                    appendRecord(kind: "d", path: relativePath, metadata: opened)
                case .regular:
                    if WorkspaceJournalExclusionPolicy.excludesFile(named: name) { return }
                    guard relativeComponents.count <= limits.maximumDepth else {
                        throw WorkspaceJournalError.depthLimitExceeded(
                            relativePath: relativePath,
                            maximum: limits.maximumDepth
                        )
                    }
                    fileCount += 1
                    guard fileCount <= limits.maximumFileCount else {
                        throw WorkspaceJournalError.fileCountLimitExceeded(maximum: limits.maximumFileCount)
                    }
                    let identity = Self.identity(before)
                    guard identity.byteCount >= 0,
                          identity.byteCount <= Int64(limits.maximumFileBytes) else {
                        throw WorkspaceJournalError.fileTooLarge(
                            relativePath: relativePath,
                            maximum: limits.maximumFileBytes
                        )
                    }
                    let (nextTotal, overflow) = totalBytes.addingReportingOverflow(identity.byteCount)
                    guard !overflow, nextTotal <= limits.maximumTotalBytes else {
                        throw WorkspaceJournalError.totalByteLimitExceeded(maximum: limits.maximumTotalBytes)
                    }
                    totalBytes = nextTotal
                    appendRecord(kind: "f", path: relativePath, metadata: before)
                case .symbolicLink, .other, .missing:
                    return
                }
            }
        }

        try visit(workspaceDescriptor, components: [])
        try deadline.check()
        var rootAfter = stat()
        guard Darwin.fstat(workspaceDescriptor, &rootAfter) == 0,
              Self.identity(rootAfter) == Self.identity(rootMetadata) else {
            throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: "<workspace>")
        }
        try validateWorkspaceRoot()
        var digest = SHA256()
        for record in records.sorted() {
            digest.update(data: Data(record.utf8))
            digest.update(data: Data([0]))
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func makeScanDeadline(
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) -> ScanDeadline {
        let started = monotonicNow()
        let duration = UInt64(limits.maximumScanDurationSeconds * 1_000_000_000)
        let addition = started.addingReportingOverflow(duration)
        return ScanDeadline(
            uptimeNanoseconds: addition.overflow ? UInt64.max : addition.partialValue,
            now: monotonicNow,
            cancellation: cancellation
        )
    }

    /// Enumerates a directory one entry at a time. The global entry and time
    /// budgets are therefore charged before an attacker-controlled directory
    /// can be retained in memory.
    private func forEachDirectoryEntry(
        descriptor: Int32,
        relativePath: String,
        deadline: ScanDeadline,
        body: (String) throws -> Void
    ) throws {
        let iterationDescriptor = Darwin.dup(descriptor)
        guard iterationDescriptor >= 0 else {
            throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
        }
        guard let stream = fdopendir(iterationDescriptor) else {
            Darwin.close(iterationDescriptor)
            throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
        }
        defer { closedir(stream) }
        while true {
            try deadline.check()
            errno = 0
            guard let entry = readdir(stream) else {
                if errno != 0 {
                    throw WorkspaceJournalError.workspaceChangedDuringScan(relativePath: relativePath)
                }
                return
            }
            guard let name = Self.directoryEntryName(entry) else {
                throw WorkspaceJournalError.workspaceChangedDuringScan(
                    relativePath: relativePath.isEmpty ? "<workspace>" : relativePath
                )
            }
            if name == "." || name == ".." { continue }
            try body(name)
        }
    }

    private func openPrivateCaptureFile(
        relativeComponents: [String],
        rootDescriptor: Int32,
        deadline: ScanDeadline
    ) throws -> Int32 {
        guard Self.validRelativeComponents(relativeComponents) else {
            throw WorkspaceJournalError.unsafeStorage
        }
        var current = Darwin.dup(rootDescriptor)
        guard current >= 0 else { throw WorkspaceJournalError.unsafeStorage }
        defer { Darwin.close(current) }

        for component in relativeComponents.dropLast() {
            try deadline.check()
            if mkdirat(current, component, mode_t(0o700)) != 0, errno != EEXIST {
                throw WorkspaceJournalError.unsafeStorage
            }
            var pathMetadata = stat()
            guard fstatat(current, component, &pathMetadata, AT_SYMLINK_NOFOLLOW) == 0,
                  Self.isPrivateDirectoryMetadata(pathMetadata) else {
                throw WorkspaceJournalError.unsafeStorage
            }
            let next = openat(
                current,
                component,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
            guard next >= 0 else { throw WorkspaceJournalError.unsafeStorage }
            var opened = stat()
            guard Darwin.fstat(next, &opened) == 0,
                  Self.isPrivateDirectoryMetadata(opened),
                  Self.sameNode(pathMetadata, opened) else {
                Darwin.close(next)
                throw WorkspaceJournalError.unsafeStorage
            }
            Darwin.close(current)
            current = next
        }

        try deadline.check()
        guard let leaf = relativeComponents.last else { throw WorkspaceJournalError.unsafeStorage }
        let destination = openat(
            current,
            leaf,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard destination >= 0 else { throw WorkspaceJournalError.unsafeStorage }
        var metadata = stat()
        guard Darwin.fstat(destination, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              (Int(metadata.st_mode) & 0o077) == 0 else {
            Darwin.close(destination)
            throw WorkspaceJournalError.unsafeStorage
        }
        return destination
    }

    private static func writeAll(
        _ bytes: [UInt8],
        count: Int,
        descriptor: Int32,
        deadline: ScanDeadline
    ) throws {
        var offset = 0
        while offset < count {
            try deadline.check()
            let written = bytes.withUnsafeBytes { rawBuffer in
                Darwin.write(
                    descriptor,
                    rawBuffer.baseAddress?.advanced(by: offset),
                    count - offset
                )
            }
            if written < 0 {
                if errno == EINTR { continue }
                throw WorkspaceJournalError.unsafeStorage
            }
            guard written > 0 else { throw WorkspaceJournalError.unsafeStorage }
            offset += written
        }
    }

    private static func directoryEntryName(_ entry: UnsafeMutablePointer<dirent>) -> String? {
        DarwinDirectoryEntry.name(entry)
    }

    private static func sameNode(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }

    private static func isPrivateDirectoryMetadata(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFDIR &&
            metadata.st_uid == geteuid() &&
            (Int(metadata.st_mode) & 0o077) == 0
    }

    private func makeRestorePreview(_ checkpoint: WorkspaceCheckpoint) throws -> WorkspaceRestorePreview {
        let current = try scanWorkspace()
        let checkpointByPath = Dictionary(uniqueKeysWithValues: checkpoint.files.map { ($0.relativePath, $0) })
        let currentByPath = Dictionary(uniqueKeysWithValues: current.files.map { ($0.relativePath, $0) })
        let paths = Set(checkpointByPath.keys).union(currentByPath.keys).sorted()
        var changes: [WorkspaceChange] = []
        var conflicts: [WorkspaceRestoreConflict] = []

        for path in paths {
            switch (checkpointByPath[path], currentByPath[path]) {
            case (nil, let current?):
                changes.append(WorkspaceChange(kind: .added, relativePath: path, checkpoint: nil, current: current))
            case (let stored?, nil):
                changes.append(WorkspaceChange(kind: .deleted, relativePath: path, checkpoint: stored, current: nil))
                if let conflict = destinationConflict(for: path) { conflicts.append(conflict) }
            case (let stored?, let live?) where stored != live:
                changes.append(WorkspaceChange(kind: .modified, relativePath: path, checkpoint: stored, current: live))
                conflicts.append(WorkspaceRestoreConflict(kind: .wouldOverwriteModifiedFile, relativePath: path))
            default:
                break
            }
        }
        conflicts.sort {
            if $0.relativePath == $1.relativePath { return $0.kind.rawValue < $1.kind.rawValue }
            return $0.relativePath < $1.relativePath
        }
        let fingerprint = Self.previewFingerprint(
            checkpointID: checkpoint.id,
            workspaceIdentifier: workspaceIdentifier,
            snapshot: current,
            changes: changes,
            conflicts: conflicts
        )
        return WorkspaceRestorePreview(
            checkpointID: checkpoint.id,
            workspaceIdentifier: workspaceIdentifier,
            changes: changes,
            conflicts: conflicts,
            stateFingerprint: fingerprint
        )
    }

    private func destinationConflict(for relativePath: String) -> WorkspaceRestoreConflict? {
        let components = relativePath.split(separator: "/").map(String.init)
        guard !components.isEmpty else {
            return WorkspaceRestoreConflict(kind: .nonRegularDestination, relativePath: relativePath)
        }
        if components.count > 1 {
            var parent = workspaceRoot
            for component in components.dropLast() {
                parent.appendPathComponent(component, isDirectory: true)
                switch Self.lstat(parent).map(Self.kind) ?? .missing {
                case .missing:
                    break
                case .directory:
                    continue
                default:
                    return WorkspaceRestoreConflict(kind: .obstructedParent, relativePath: relativePath)
                }
            }
        }
        switch nodeKind(at: relativePath) {
        case .missing: return nil
        case .symbolicLink:
            return WorkspaceRestoreConflict(kind: .symbolicLinkAtDestination, relativePath: relativePath)
        case .directory:
            return WorkspaceRestoreConflict(kind: .directoryAtFileDestination, relativePath: relativePath)
        case .regular:
            return WorkspaceRestoreConflict(kind: .wouldOverwriteModifiedFile, relativePath: relativePath)
        case .other:
            return WorkspaceRestoreConflict(kind: .nonRegularDestination, relativePath: relativePath)
        }
    }

    private func readAndValidateCheckpointContent(
        _ record: WorkspaceFileSnapshot,
        checkpointID: UUID
    ) throws -> Data {
        let root = checkpointDirectory(checkpointID).appendingPathComponent("contents", isDirectory: true)
        let url = try safeDescendant(record.relativePath, of: root)
        try validateNonSymlinkPath(url, beneath: root)
        let data: Data
        do {
            data = try SecureAttachmentReader.readRegularFile(at: url, maximumBytes: limits.maximumFileBytes)
        } catch {
            throw WorkspaceJournalError.checkpointContentCorrupt(relativePath: record.relativePath)
        }
        guard Int64(data.count) == record.byteCount, Self.sha256Hex(data) == record.contentSHA256 else {
            throw WorkspaceJournalError.checkpointContentCorrupt(relativePath: record.relativePath)
        }
        return data
    }

    private func loadAllCheckpoints(
        cancellation: WorkspaceJournalOperationCancellation? = nil
    ) throws -> [WorkspaceCheckpoint] {
        let deadline = makeScanDeadline(cancellation: cancellation)
        try deadline.check()
        let descriptor = Darwin.open(
            checkpointsRoot.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw WorkspaceJournalError.unsafeStorage }
        defer { Darwin.close(descriptor) }
        var rootMetadata = stat()
        guard Darwin.fstat(descriptor, &rootMetadata) == 0,
              Self.isPrivateDirectoryMetadata(rootMetadata) else {
            throw WorkspaceJournalError.unsafeStorage
        }

        var identifiers: [UUID] = []
        do {
            try forEachDirectoryEntry(
                descriptor: descriptor,
                relativePath: "<checkpoint storage>",
                deadline: deadline
            ) { name in
                guard identifiers.count < limits.maximumCheckpointCount,
                      let identifier = UUID(uuidString: name) else {
                    throw WorkspaceJournalError.unsafeStorage
                }
                var metadata = stat()
                guard fstatat(descriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
                      Self.isPrivateDirectoryMetadata(metadata) else {
                    throw WorkspaceJournalError.unsafeStorage
                }
                identifiers.append(identifier)
            }
        } catch WorkspaceJournalError.scanDeadlineExceeded {
            throw WorkspaceJournalError.scanDeadlineExceeded
        } catch {
            throw WorkspaceJournalError.unsafeStorage
        }

        var checkpoints: [WorkspaceCheckpoint] = []
        var storedBytes: Int64 = 0
        for identifier in identifiers.sorted(by: { $0.uuidString < $1.uuidString }) {
            try deadline.check()
            let checkpoint = try loadCheckpoint(identifier, deadline: deadline)
            let (nextStoredBytes, overflow) = storedBytes.addingReportingOverflow(checkpoint.totalBytes)
            guard !overflow, nextStoredBytes <= limits.maximumStoredBytes else {
                throw WorkspaceJournalError.unsafeStorage
            }
            storedBytes = nextStoredBytes
            checkpoints.append(checkpoint)
        }
        return checkpoints
    }

    private func loadCheckpoint(
        _ identifier: UUID,
        deadline suppliedDeadline: ScanDeadline? = nil
    ) throws -> WorkspaceCheckpoint {
        let deadline = suppliedDeadline ?? makeScanDeadline()
        try deadline.check()
        let directory = checkpointDirectory(identifier)
        guard Self.lstat(directory) != nil else { throw WorkspaceJournalError.checkpointNotFound }
        guard Self.isPrivateDirectory(directory) else { throw WorkspaceJournalError.unsafeCheckpoint }
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let data: Data
        do {
            data = try SecureAttachmentReader.readRegularFile(at: manifestURL, maximumBytes: limits.maximumManifestBytes)
        } catch {
            throw WorkspaceJournalError.unsafeCheckpoint
        }
        try deadline.check()
        guard Self.isPrivateRegularFile(manifestURL),
              let checkpoint = try? Self.decodeCheckpoint(data) else {
            throw WorkspaceJournalError.unsafeCheckpoint
        }
        try deadline.check()
        try validate(checkpoint, expectedID: identifier)
        return checkpoint
    }

    private func validate(_ checkpoint: WorkspaceCheckpoint, expectedID: UUID) throws {
        guard [1, 2, WorkspaceCheckpoint.currentFormatVersion].contains(checkpoint.formatVersion),
              (checkpoint.formatVersion == 1 ? checkpoint.origin == nil : checkpoint.origin != nil),
              (checkpoint.formatVersion < 3
                ? checkpoint.metadataFingerprint == nil
                : checkpoint.metadataFingerprint.map(Self.isSHA256Hex) == true),
              checkpoint.id == expectedID,
              checkpoint.workspaceCanonicalPath == workspaceRoot.path,
              checkpoint.workspaceIdentifier == workspaceIdentifier,
              checkpoint.files.count <= limits.maximumFileCount,
              checkpoint.totalBytes >= 0,
              checkpoint.totalBytes <= limits.maximumTotalBytes,
              checkpoint.label.count <= 120,
              Self.normalizedLabel(checkpoint.label) == checkpoint.label,
              checkpoint.createdAt.timeIntervalSince1970.isFinite else {
            throw WorkspaceJournalError.unsafeCheckpoint
        }
        var paths = Set<String>()
        var total: Int64 = 0
        var previousPath: String?
        for record in checkpoint.files {
            let components = record.relativePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard Self.validRelativeComponents(components),
                  components.count <= limits.maximumDepth,
                  record.relativePath.utf8.count <= limits.maximumRelativePathBytes,
                  !WorkspaceJournalExclusionPolicy.excludesFile(named: components.last ?? ""),
                  !components.dropLast().contains(where: WorkspaceJournalExclusionPolicy.excludesDirectory),
                  paths.insert(record.relativePath).inserted,
                  previousPath.map({ $0 < record.relativePath }) ?? true,
                  record.byteCount >= 0,
                  record.byteCount <= Int64(limits.maximumFileBytes),
                  (record.posixPermissions & ~0o777) == 0,
                  record.contentSHA256.count == 64,
                  record.contentSHA256.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
                throw WorkspaceJournalError.unsafeCheckpoint
            }
            let (next, overflow) = total.addingReportingOverflow(record.byteCount)
            guard !overflow else { throw WorkspaceJournalError.unsafeCheckpoint }
            total = next
            previousPath = record.relativePath
        }
        guard total == checkpoint.totalBytes else { throw WorkspaceJournalError.unsafeCheckpoint }
    }

    private static func isSHA256Hex(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    private func checkpointDirectory(_ identifier: UUID) -> URL {
        checkpointsRoot.appendingPathComponent(identifier.uuidString, isDirectory: true)
    }

    private func safeWorkspaceURL(_ relativePath: String) throws -> URL {
        try safeDescendant(relativePath, of: workspaceRoot)
    }

    private func safeDescendant(_ relativePath: String, of root: URL) throws -> URL {
        let components = relativePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard Self.validRelativeComponents(components),
              relativePath.utf8.count <= limits.maximumRelativePathBytes else {
            throw WorkspaceJournalError.unsafeCheckpoint
        }
        return components.reduce(root) { partial, component in
            partial.appendingPathComponent(component, isDirectory: false)
        }
    }

    private func validateNonSymlinkPath(_ url: URL, beneath root: URL) throws {
        let standardizedRoot = root.standardizedFileURL
        let standardizedURL = url.standardizedFileURL
        guard Self.isPrivateDirectory(standardizedRoot),
              standardizedURL.path.hasPrefix(standardizedRoot.path + "/") else {
            throw WorkspaceJournalError.unsafeCheckpoint
        }
        var current = standardizedRoot
        let components = String(standardizedURL.path.dropFirst(standardizedRoot.path.count + 1))
            .split(separator: "/").map(String.init)
        for (index, component) in components.enumerated() {
            current.appendPathComponent(component)
            guard let info = Self.lstat(current) else { throw WorkspaceJournalError.unsafeCheckpoint }
            let expected: NodeKind = index == components.count - 1 ? .regular : .directory
            guard Self.kind(of: info) == expected,
                  info.st_uid == geteuid(),
                  (Int(info.st_mode) & 0o077) == 0 else {
                throw WorkspaceJournalError.unsafeCheckpoint
            }
        }
    }

    private func nodeKind(at relativePath: String) -> NodeKind {
        guard let url = try? safeWorkspaceURL(relativePath), let info = Self.lstat(url) else { return .missing }
        return Self.kind(of: info)
    }

    private func readCurrentRegularFile(_ relativePath: String) throws -> (WorkspaceFileSnapshot, Data) {
        try validateWorkspaceRoot()
        let url = try safeWorkspaceURL(relativePath)
        guard let before = Self.lstat(url), Self.kind(of: before) == .regular else {
            throw WorkspaceJournalError.stalePreview
        }
        let identity = Self.identity(before)
        guard identity.byteCount <= Int64(limits.maximumFileBytes) else {
            throw WorkspaceJournalError.stalePreview
        }
        let data: Data
        do {
            data = try SecureAttachmentReader.readRegularFile(at: url, maximumBytes: limits.maximumFileBytes)
        } catch {
            throw WorkspaceJournalError.stalePreview
        }
        guard let after = Self.lstat(url), Self.identity(after) == identity, Int64(data.count) == identity.byteCount else {
            throw WorkspaceJournalError.stalePreview
        }
        return (
            WorkspaceFileSnapshot(
                relativePath: relativePath,
                byteCount: identity.byteCount,
                modificationTimeNanoseconds: identity.modificationTimeNanoseconds,
                posixPermissions: identity.permissions,
                contentSHA256: Self.sha256Hex(data)
            ),
            data
        )
    }

    private func writeWorkspaceFile(
        _ data: Data,
        record: WorkspaceFileSnapshot,
        expectedCurrent: WorkspaceFileSnapshot?,
        allowReplacement: Bool
    ) throws {
        try validateWorkspaceRoot()
        let destination = try safeWorkspaceURL(record.relativePath)
        try ensureWorkspaceParents(for: record.relativePath)
        if let expectedCurrent {
            let (live, _) = try readCurrentRegularFile(record.relativePath)
            guard live == expectedCurrent, allowReplacement else { throw WorkspaceJournalError.stalePreview }
        } else {
            guard nodeKind(at: record.relativePath) == .missing else { throw WorkspaceJournalError.stalePreview }
        }
        try Self.writeFileAtomically(
            data,
            to: destination,
            permissions: record.posixPermissions,
            modificationTimeNanoseconds: record.modificationTimeNanoseconds,
            replaceExisting: allowReplacement
        )
    }

    private func ensureWorkspaceParents(for relativePath: String) throws {
        let components = relativePath.split(separator: "/").map(String.init)
        var parent = workspaceRoot
        for component in components.dropLast() {
            parent.appendPathComponent(component, isDirectory: true)
            if let info = Self.lstat(parent) {
                guard Self.kind(of: info) == .directory else { throw WorkspaceJournalError.stalePreview }
            } else {
                try fileManager.createDirectory(at: parent, withIntermediateDirectories: false)
                guard let info = Self.lstat(parent), Self.kind(of: info) == .directory else {
                    throw WorkspaceJournalError.stalePreview
                }
            }
        }
    }

    private func rollback<S: Sequence>(_ entries: S) -> Bool where S.Element == RollbackEntry {
        var succeeded = true
        for entry in entries {
            do {
                try restoreMutationHook?(.rollback, entry.relativePath)
            } catch {
                succeeded = false
                continue
            }
            do {
                try validateWorkspaceRoot()
            } catch {
                succeeded = false
                continue
            }
            guard let destination = try? safeWorkspaceURL(entry.relativePath) else {
                succeeded = false
                continue
            }
            if entry.existed, let data = entry.data {
                do {
                    try ensureWorkspaceParents(for: entry.relativePath)
                    let kind = nodeKind(at: entry.relativePath)
                    guard kind == .missing || kind == .regular else {
                        succeeded = false
                        continue
                    }
                    try Self.writeFileAtomically(
                        data,
                        to: destination,
                        permissions: entry.permissions,
                        modificationTimeNanoseconds: entry.modificationTimeNanoseconds,
                        replaceExisting: kind == .regular
                    )
                } catch {
                    succeeded = false
                }
            } else {
                switch nodeKind(at: entry.relativePath) {
                case .missing:
                    break
                case .regular:
                    if Darwin.unlink(destination.path) != 0 { succeeded = false }
                default:
                    succeeded = false
                }
            }
        }
        return succeeded
    }

    private static func writeFileAtomically(
        _ data: Data,
        to destination: URL,
        permissions: Int,
        modificationTimeNanoseconds: Int64,
        replaceExisting: Bool
    ) throws {
        let parent = destination.deletingLastPathComponent()
        let temporary = parent.appendingPathComponent(".local-harness-recovery-\(UUID().uuidString).tmp")
        let descriptor = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw WorkspaceJournalError.restoreFailed }
        var shouldRemoveTemporary = true
        defer {
            Darwin.close(descriptor)
            if shouldRemoveTemporary { _ = Darwin.unlink(temporary.path) }
        }
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var written = 0
            while written < rawBuffer.count {
                let result = Darwin.write(descriptor, base.advanced(by: written), rawBuffer.count - written)
                if result < 0 {
                    if errno == EINTR { continue }
                    throw WorkspaceJournalError.restoreFailed
                }
                written += result
            }
        }
        var seconds = modificationTimeNanoseconds / 1_000_000_000
        var nanoseconds = modificationTimeNanoseconds % 1_000_000_000
        if nanoseconds < 0 {
            seconds -= 1
            nanoseconds += 1_000_000_000
        }
        let timestamps = [
            timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)),
            timespec(tv_sec: Int(seconds), tv_nsec: Int(nanoseconds))
        ]
        let timeResult = timestamps.withUnsafeBufferPointer {
            Darwin.futimens(descriptor, $0.baseAddress)
        }
        guard Darwin.fchmod(descriptor, mode_t(permissions & 0o777)) == 0,
              timeResult == 0,
              Darwin.fsync(descriptor) == 0 else {
            throw WorkspaceJournalError.restoreFailed
        }
        if replaceExisting {
            guard Darwin.rename(temporary.path, destination.path) == 0 else {
                throw WorkspaceJournalError.restoreFailed
            }
        } else {
            guard Darwin.link(temporary.path, destination.path) == 0 else {
                throw WorkspaceJournalError.stalePreview
            }
            guard Darwin.unlink(temporary.path) == 0 else {
                _ = Darwin.unlink(destination.path)
                throw WorkspaceJournalError.restoreFailed
            }
        }
        shouldRemoveTemporary = false
    }

    private static func ensurePrivateDirectory(_ directory: URL, fileManager: FileManager) throws {
        if let info = lstat(directory) {
            guard kind(of: info) == .directory else { throw WorkspaceJournalError.unsafeStorage }
        } else {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        try setPrivatePermissions(directory, directory: true, fileManager: fileManager)
        guard isPrivateDirectory(directory) else { throw WorkspaceJournalError.unsafeStorage }
    }

    private static func writePrivateFile(
        _ data: Data,
        to destination: URL,
        permissions: Int,
        fileManager: FileManager
    ) throws {
        try ensurePrivateDirectory(destination.deletingLastPathComponent(), fileManager: fileManager)
        guard lstat(destination) == nil else { throw WorkspaceJournalError.unsafeStorage }
        try data.write(to: destination, options: .withoutOverwriting)
        try setPrivatePermissions(destination, directory: false, permissions: permissions, fileManager: fileManager)
        guard isPrivateRegularFile(destination) else { throw WorkspaceJournalError.unsafeStorage }
    }

    private static func setPrivatePermissions(
        _ url: URL,
        directory: Bool,
        permissions: Int? = nil,
        fileManager: FileManager
    ) throws {
        try fileManager.setAttributes(
            [.posixPermissions: permissions ?? (directory ? 0o700 : 0o600)],
            ofItemAtPath: url.path
        )
    }

    private static func isPrivateDirectory(_ url: URL) -> Bool {
        guard let info = lstat(url), kind(of: info) == .directory else { return false }
        return info.st_uid == geteuid() && (Int(info.st_mode) & 0o077) == 0
    }

    private static func isPrivateRegularFile(_ url: URL) -> Bool {
        guard let info = lstat(url), kind(of: info) == .regular else { return false }
        return info.st_uid == geteuid() && (Int(info.st_mode) & 0o077) == 0
    }

    private static func lstat(_ url: URL) -> stat? {
        var info = stat()
        let result = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.lstat(path, &info)
        }
        return result == 0 ? info : nil
    }

    private static func kind(of info: stat) -> NodeKind {
        switch info.st_mode & S_IFMT {
        case S_IFREG: return .regular
        case S_IFDIR: return .directory
        case S_IFLNK: return .symbolicLink
        default: return .other
        }
    }

    private static func identity(_ info: stat) -> FileIdentity {
        let seconds = Int64(info.st_mtimespec.tv_sec)
        let nanoseconds = Int64(info.st_mtimespec.tv_nsec)
        let changeSeconds = Int64(info.st_ctimespec.tv_sec)
        let changeNanoseconds = Int64(info.st_ctimespec.tv_nsec)
        return FileIdentity(
            device: UInt64(truncatingIfNeeded: info.st_dev),
            inode: UInt64(info.st_ino),
            byteCount: Int64(info.st_size),
            modificationTimeNanoseconds: seconds * 1_000_000_000 + nanoseconds,
            changeTimeNanoseconds: changeSeconds * 1_000_000_000 + changeNanoseconds,
            permissions: Int(info.st_mode & 0o777)
        )
    }

    private static func validRelativeComponents(_ components: [String]) -> Bool {
        !components.isEmpty && components.allSatisfy {
            !$0.isEmpty
                && $0 != "."
                && $0 != ".."
                && !$0.contains("/")
                && !$0.contains("\0")
                && $0.unicodeScalars.allSatisfy {
                    !CharacterSet.controlCharacters.contains($0)
                        && $0.properties.generalCategory != .format
                }
        }
    }

    private static func normalizedLabel(_ label: String) -> String {
        let stripped = label.unicodeScalars
            .filter {
                !CharacterSet.controlCharacters.contains($0)
                    && $0.properties.generalCategory != .format
            }
            .map(String.init)
            .joined()
        let trimmed = stripped.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        if trimmed.isEmpty { return "Workspace checkpoint" }
        return String(trimmed.prefix(120))
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func previewFingerprint(
        checkpointID: UUID,
        workspaceIdentifier: String,
        snapshot: WorkspaceSnapshot,
        changes: [WorkspaceChange],
        conflicts: [WorkspaceRestoreConflict]
    ) -> String {
        var digest = SHA256()
        func append(_ value: String) {
            let bytes = Data(value.utf8)
            var length = UInt64(bytes.count).bigEndian
            Swift.withUnsafeBytes(of: &length) { digest.update(data: Data($0)) }
            digest.update(data: bytes)
        }
        append(checkpointID.uuidString)
        append(workspaceIdentifier)
        for file in snapshot.files {
            append(file.relativePath)
            append(String(file.byteCount))
            append(String(file.modificationTimeNanoseconds))
            append(String(file.posixPermissions))
            append(file.contentSHA256)
        }
        for change in changes {
            append(change.kind.rawValue)
            append(change.relativePath)
            if let stored = change.checkpoint {
                append("checkpoint")
                append(String(stored.byteCount))
                append(String(stored.modificationTimeNanoseconds))
                append(String(stored.posixPermissions))
                append(stored.contentSHA256)
            } else {
                append("no-checkpoint-record")
            }
        }
        for conflict in conflicts {
            append(conflict.kind.rawValue)
            append(conflict.relativePath)
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func encodeCheckpoint(_ checkpoint: WorkspaceCheckpoint) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(checkpoint)
    }

    private static func decodeCheckpoint(_ data: Data) throws -> WorkspaceCheckpoint {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(WorkspaceCheckpoint.self, from: data)
    }
}
