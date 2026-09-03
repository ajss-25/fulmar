import Darwin
import Foundation

enum GenerationTelemetrySpoolError: LocalizedError, Equatable {
    case unsafeApplicationSupport
    case unsafeStorage
    case storageUnavailable

    var errorDescription: String? {
        switch self {
        case .unsafeApplicationSupport:
            return "Performance history is unavailable because the app storage root is not private."
        case .unsafeStorage:
            return "Performance history is unavailable because its private storage failed validation."
        case .storageUnavailable:
            return "Performance history storage could not be created."
        }
    }
}

/// A narrow, versioned bridge from the bundled DSH `llm/stream` observer to
/// the native Performance Center. The file contains only coarse timing/token
/// facts and route labels; it never accepts prompt, response, error, session,
/// workspace, tool, URL, header, or credential fields.
enum GenerationTelemetrySpool {
    static let schemaVersion = 1
    static let directoryName = "PerformanceTelemetry"
    static let fileName = "performance-telemetry.json"
    static let lockName = ".performance-telemetry.lock"
    static let maximumFileBytes = 256 * 1_024
    static let maximumRecords = 100
    static let maximumAge: TimeInterval = 24 * 60 * 60
    static let maximumFutureSkew: TimeInterval = 5 * 60
    static let maximumLabelBytes = 512

    private static let recordKeys: Set<String> = [
        "schemaVersion", "id", "provider", "model", "profile", "startedAtMilliseconds",
        "completedAtMilliseconds", "firstTokenAtMilliseconds", "elapsedMilliseconds",
        "outputTokens", "outputTokenCountSource", "outcome", "failureCategory"
    ]

    private struct Envelope: Decodable {
        let schemaVersion: Int
        let records: [StoredRecord]
    }

    private struct StoredRecord: Decodable {
        let schemaVersion: Int
        let id: String
        let provider: String?
        let model: String?
        let profile: String?
        let startedAtMilliseconds: Int64
        let completedAtMilliseconds: Int64
        let firstTokenAtMilliseconds: Int64?
        let elapsedMilliseconds: Int64
        let outputTokens: Int
        let outputTokenCountSource: OutputTokenCountSource
        let outcome: GenerationOutcome
        let failureCategory: GenerationFailureCategory?
    }

    private struct HeldLock {
        let url: URL
        let descriptor: Int32
        let device: dev_t
        let inode: ino_t
    }

    static func storageURL(applicationSupport: URL) -> URL {
        applicationSupport
            .appendingPathComponent(directoryName, isDirectory: true)
            .appendingPathComponent(fileName, isDirectory: false)
    }

    /// Creates only the fixed app-owned 0700 directory and 0600 regular file.
    /// Existing linked, hard-linked, wrong-owner, or permissive nodes fail
    /// closed; no user-selected path is accepted.
    @discardableResult
    static func prepare(
        applicationSupport: URL,
        fileManager: FileManager = .default
    ) throws -> URL {
        let directory = try prepareDirectory(applicationSupport: applicationSupport, fileManager: fileManager)

        let lock = directory.appendingPathComponent(lockName, isDirectory: false)
        if !nodeExists(lock) {
            let descriptor = Darwin.open(
                lock.path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
            guard descriptor >= 0 else { throw GenerationTelemetrySpoolError.storageUnavailable }
            let synced = Darwin.fsync(descriptor) == 0
            let closed = Darwin.close(descriptor) == 0
            guard synced, closed else { throw GenerationTelemetrySpoolError.storageUnavailable }
        }
        var lockMetadata = stat()
        guard Darwin.lstat(lock.path, &lockMetadata) == 0,
              secureLockMetadata(lockMetadata) else {
            throw GenerationTelemetrySpoolError.unsafeStorage
        }

        let file = directory.appendingPathComponent(fileName, isDirectory: false)
        if !nodeExists(file) {
            let descriptor = Darwin.open(
                file.path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
            guard descriptor >= 0 else { throw GenerationTelemetrySpoolError.storageUnavailable }
            let initial = Data(#"{"schemaVersion":1,"records":[]}"#.utf8)
            let wrote = writeAll(initial, to: descriptor)
            let synced = Darwin.fsync(descriptor) == 0
            let closed = Darwin.close(descriptor) == 0
            guard wrote, synced, closed else { throw GenerationTelemetrySpoolError.storageUnavailable }
        }
        guard secureFile(file), fileSize(file) <= maximumFileBytes else {
            throw GenerationTelemetrySpoolError.unsafeStorage
        }
        return file
    }

    /// Telemetry is diagnostic, never a prerequisite for inference. Production
    /// launch uses this contained form and simply omits the runtime observer
    /// environment when private storage cannot be established.
    static func prepareIfAvailable(
        applicationSupport: URL,
        fileManager: FileManager = .default
    ) -> URL? {
        try? prepare(applicationSupport: applicationSupport, fileManager: fileManager)
    }

    static func read(
        applicationSupport: URL,
        at referenceDate: Date = Date()
    ) -> [GenerationTelemetryRecord] {
        guard secureDirectory(applicationSupport) else { return [] }
        let directory = applicationSupport.appendingPathComponent(directoryName, isDirectory: true)
        let file = directory.appendingPathComponent(fileName, isDirectory: false)
        guard secureDirectory(directory), secureFile(file) else { return [] }

        let descriptor = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return [] }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & (S_IRWXG | S_IRWXO) == 0,
              metadata.st_size > 0,
              metadata.st_size <= maximumFileBytes,
              let data = readExactly(descriptor: descriptor, byteCount: Int(metadata.st_size)),
              data.count <= maximumFileBytes,
              exactJSONShape(data),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
              envelope.schemaVersion == schemaVersion,
              envelope.records.count <= maximumRecords else {
            return []
        }

        var seen = Set<UUID>()
        var records: [GenerationTelemetryRecord] = []
        for stored in envelope.records {
            guard let record = convert(stored, referenceDate: referenceDate), seen.insert(record.id).inserted else {
                return []
            }
            records.append(record)
        }
        records.sort {
            if $0.completedAt == $1.completedAt { return $0.id.uuidString < $1.id.uuidString }
            return $0.completedAt > $1.completedAt
        }
        return Array(records.prefix(maximumRecords))
    }

    /// User-invoked privacy action. Only the fixed node inside the exact
    /// private telemetry directory is unlinked; linked targets are never
    /// followed. A fresh empty 0600 spool is then recreated for later runs.
    @discardableResult
    static func clear(
        applicationSupport: URL,
        fileManager: FileManager = .default,
        lockContentionObserver: (() -> Void)? = nil
    ) throws -> URL {
        let directory = try prepareDirectory(applicationSupport: applicationSupport, fileManager: fileManager)
        return try withExclusiveLock(
            directory: directory,
            contentionObserver: lockContentionObserver
        ) {
            let file = directory.appendingPathComponent(fileName, isDirectory: false)
            let temporary = directory.appendingPathComponent(".\(fileName).tmp", isDirectory: false)
            try unlinkFixedNodeIfPresent(file)
            try unlinkFixedNodeIfPresent(temporary)
            let prepared = try prepare(applicationSupport: applicationSupport, fileManager: fileManager)
            try syncDirectory(directory)
            return prepared
        }
    }

    private static func prepareDirectory(
        applicationSupport: URL,
        fileManager: FileManager
    ) throws -> URL {
        guard secureDirectory(applicationSupport) else {
            throw GenerationTelemetrySpoolError.unsafeApplicationSupport
        }
        let directory = applicationSupport.appendingPathComponent(directoryName, isDirectory: true)
        if !nodeExists(directory) {
            do {
                try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
                try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            } catch {
                throw GenerationTelemetrySpoolError.storageUnavailable
            }
        }
        guard secureDirectory(directory) else { throw GenerationTelemetrySpoolError.unsafeStorage }
        return directory
    }

    private static func withExclusiveLock<T>(
        directory: URL,
        contentionObserver: (() -> Void)?,
        operation: () throws -> T
    ) throws -> T {
        let lock = try acquireExclusiveLock(
            directory: directory,
            contentionObserver: contentionObserver
        )
        let result: Result<T, Error>
        do { result = .success(try operation()) }
        catch { result = .failure(error) }
        try releaseExclusiveLock(lock, directory: directory)
        return try result.get()
    }

    private static func acquireExclusiveLock(
        directory: URL,
        contentionObserver: (() -> Void)?
    ) throws -> HeldLock {
        let lockURL = directory.appendingPathComponent(lockName, isDirectory: false)
        var descriptor = Darwin.open(lockURL.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0, errno == ENOENT {
            descriptor = Darwin.open(
                lockURL.path,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
            if descriptor < 0, errno == EEXIST {
                descriptor = Darwin.open(lockURL.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            }
        }
        guard descriptor >= 0 else {
            throw nodeExists(lockURL)
                ? GenerationTelemetrySpoolError.unsafeStorage
                : GenerationTelemetrySpoolError.storageUnavailable
        }

        var descriptorMetadata = stat()
        guard Darwin.fstat(descriptor, &descriptorMetadata) == 0,
              secureLockMetadata(descriptorMetadata),
              lockPathMatches(lockURL, descriptorMetadata) else {
            _ = Darwin.close(descriptor)
            throw GenerationTelemetrySpoolError.unsafeStorage
        }

        let maximumAttempts = 500
        var reportedContention = false
        for attempt in 0..<maximumAttempts {
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                guard lockPathMatches(lockURL, descriptorMetadata) else {
                    _ = flock(descriptor, LOCK_UN)
                    _ = Darwin.close(descriptor)
                    throw GenerationTelemetrySpoolError.unsafeStorage
                }
                return HeldLock(
                    url: lockURL,
                    descriptor: descriptor,
                    device: descriptorMetadata.st_dev,
                    inode: descriptorMetadata.st_ino
                )
            }
            guard errno == EWOULDBLOCK || errno == EAGAIN else {
                _ = Darwin.close(descriptor)
                throw GenerationTelemetrySpoolError.storageUnavailable
            }
            guard lockPathMatches(lockURL, descriptorMetadata) else {
                _ = Darwin.close(descriptor)
                throw GenerationTelemetrySpoolError.unsafeStorage
            }
            if !reportedContention {
                contentionObserver?()
                reportedContention = true
            }
            if attempt + 1 < maximumAttempts { Darwin.usleep(10_000) }
        }
        _ = Darwin.close(descriptor)
        throw GenerationTelemetrySpoolError.storageUnavailable
    }

    private static func releaseExclusiveLock(_ lock: HeldLock, directory: URL) throws {
        var descriptorMetadata = stat()
        let descriptorIsValid = Darwin.fstat(lock.descriptor, &descriptorMetadata) == 0
            && secureLockMetadata(descriptorMetadata)
            && descriptorMetadata.st_dev == lock.device
            && descriptorMetadata.st_ino == lock.inode
            && lockPathMatches(lock.url, descriptorMetadata)
        let unlocked = flock(lock.descriptor, LOCK_UN) == 0
        let closed = Darwin.close(lock.descriptor) == 0
        guard descriptorIsValid, unlocked, closed else {
            throw GenerationTelemetrySpoolError.unsafeStorage
        }
        try syncDirectory(directory)
    }

    private static func secureLockMetadata(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o777 == 0o600
    }

    private static func lockPathMatches(_ url: URL, _ descriptorMetadata: stat) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
            && secureLockMetadata(metadata)
            && metadata.st_dev == descriptorMetadata.st_dev
            && metadata.st_ino == descriptorMetadata.st_ino
    }

    private static func unlinkFixedNodeIfPresent(_ url: URL) throws {
        var metadata = stat()
        if Darwin.lstat(url.path, &metadata) != 0 {
            guard errno == ENOENT else { throw GenerationTelemetrySpoolError.unsafeStorage }
            return
        }
        guard metadata.st_uid == geteuid(),
              metadata.st_mode & S_IFMT != S_IFDIR,
              Darwin.unlink(url.path) == 0 else {
            throw GenerationTelemetrySpoolError.unsafeStorage
        }
    }

    private static func syncDirectory(_ directory: URL) throws {
        let descriptor = Darwin.open(directory.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw GenerationTelemetrySpoolError.storageUnavailable }
        let synced = Darwin.fsync(descriptor) == 0
        let closed = Darwin.close(descriptor) == 0
        guard synced, closed else { throw GenerationTelemetrySpoolError.storageUnavailable }
    }

    private static func convert(
        _ stored: StoredRecord,
        referenceDate: Date
    ) -> GenerationTelemetryRecord? {
        guard stored.schemaVersion == schemaVersion,
              canonicalUUID(stored.id) != nil,
              stored.startedAtMilliseconds >= 0,
              stored.completedAtMilliseconds >= stored.startedAtMilliseconds,
              stored.elapsedMilliseconds >= 0,
              stored.elapsedMilliseconds <= Int64(maximumAge * 1_000),
              stored.completedAtMilliseconds - stored.startedAtMilliseconds == stored.elapsedMilliseconds,
              stored.outputTokens >= 0,
              stored.outputTokens <= 10_000_000 else { return nil }

        let startedAt = Date(timeIntervalSince1970: Double(stored.startedAtMilliseconds) / 1_000)
        let completedAt = Date(timeIntervalSince1970: Double(stored.completedAtMilliseconds) / 1_000)
        let oldest = referenceDate.addingTimeInterval(-maximumAge)
        let newest = referenceDate.addingTimeInterval(maximumFutureSkew)
        // Retention and future-skew limits are enforced by both writer and
        // reader. A stale or future row invalidates the exact spool; the next
        // completed runtime call atomically replaces malformed/stale data.
        if completedAt < oldest { return nil }
        guard completedAt <= newest else { return nil }

        let firstTokenAt: Date?
        if let value = stored.firstTokenAtMilliseconds {
            guard value >= stored.startedAtMilliseconds, value <= stored.completedAtMilliseconds else { return nil }
            firstTokenAt = Date(timeIntervalSince1970: Double(value) / 1_000)
        } else {
            firstTokenAt = nil
        }

        let route: ModelRoute?
        switch (stored.provider, stored.model) {
        case (.none, .none):
            route = nil
        case (.some(let provider), .some(let model))
            where safeLabel(provider, maximumBytes: 256) && safeLabel(model, maximumBytes: maximumLabelBytes):
            route = ModelRoute(provider: ProviderID(provider), model: ModelID(model))
        default:
            return nil
        }
        if let profile = stored.profile,
           profile.range(of: #"^[a-z][a-z0-9]{0,31}$"#, options: .regularExpression) == nil {
            return nil
        }
        if stored.outcome == .failed {
            guard stored.failureCategory != nil else { return nil }
        } else if stored.failureCategory != nil {
            return nil
        }

        let generationDuration = firstTokenAt.map { max(0, completedAt.timeIntervalSince($0)) }
        let rate = generationDuration.flatMap { duration in
            duration > 0 && stored.outputTokens > 0 ? Double(stored.outputTokens) / duration : nil
        }
        return GenerationTelemetryRecord(
            id: canonicalUUID(stored.id)!,
            route: route,
            startedAt: startedAt,
            completedAt: completedAt,
            timeToFirstTokenSeconds: firstTokenAt.map { max(0, $0.timeIntervalSince(startedAt)) },
            elapsedSeconds: Double(stored.elapsedMilliseconds) / 1_000,
            outputTokens: stored.outputTokens,
            outputTokenCountSource: stored.outputTokenCountSource,
            outputTokensPerSecond: rate,
            outcome: stored.outcome,
            failureCategory: stored.failureCategory
        )
    }

    private static func exactJSONShape(_ data: Data) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let envelope = object as? [String: Any],
              Set(envelope.keys) == ["schemaVersion", "records"],
              let records = envelope["records"] as? [Any],
              records.count <= maximumRecords else { return false }
        return records.allSatisfy { value in
            guard let record = value as? [String: Any] else { return false }
            return Set(record.keys) == recordKeys
        }
    }

    private static func canonicalUUID(_ value: String) -> UUID? {
        guard value.range(
            of: #"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
            options: [.regularExpression, .caseInsensitive]
        ) != nil,
              let uuid = UUID(uuidString: value),
              uuid.uuidString.lowercased() == value.lowercased() else { return nil }
        return uuid
    }

    private static func safeLabel(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
    }

    private static func nodeExists(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
    }

    private static func secureDirectory(_ url: URL) -> Bool {
        let standardized = url.standardizedFileURL.path
        let canonical = url.resolvingSymlinksInPath().standardizedFileURL.path
        var metadata = stat()
        return standardized == canonical
            && Darwin.lstat(standardized, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_mode & (S_IRWXG | S_IRWXO) == 0
    }

    private static func secureFile(_ url: URL) -> Bool {
        let standardized = url.standardizedFileURL.path
        let canonical = url.resolvingSymlinksInPath().standardizedFileURL.path
        var metadata = stat()
        return standardized == canonical
            && Darwin.lstat(standardized, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & (S_IRWXG | S_IRWXO) == 0
    }

    private static func fileSize(_ url: URL) -> Int {
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0, metadata.st_size >= 0 else { return Int.max }
        return Int(metadata.st_size)
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { rawBuffer in
            guard var pointer = rawBuffer.baseAddress else { return data.isEmpty }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let count = Darwin.write(descriptor, pointer, remaining)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                remaining -= count
                pointer = pointer.advanced(by: count)
            }
            return true
        }
    }

    private static func readExactly(descriptor: Int32, byteCount: Int) -> Data? {
        guard byteCount > 0, byteCount <= maximumFileBytes else { return nil }
        var data = Data(count: byteCount)
        let succeeded = data.withUnsafeMutableBytes { rawBuffer -> Bool in
            guard var pointer = rawBuffer.baseAddress else { return false }
            var remaining = byteCount
            while remaining > 0 {
                let count = Darwin.read(descriptor, pointer, remaining)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                remaining -= count
                pointer = pointer.advanced(by: count)
            }
            var extra: UInt8 = 0
            return Darwin.read(descriptor, &extra, 1) == 0
        }
        return succeeded ? data : nil
    }
}
