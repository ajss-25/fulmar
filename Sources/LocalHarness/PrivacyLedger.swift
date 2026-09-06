import CryptoKit
import Darwin
import Foundation
import LocalHarnessDeviceAttestation

struct PrivacyEvent: Codable, Equatable, Identifiable {
    enum Kind: String, Codable {
        case runtimeStarted
        case runtimeStopped
        case externalLinkOpened
        case appshotCaptured
        case artifactDownloaded
        case backupCreated
        case backupRestored
        case credentialsMigrated
        case updatePrepared
        case pluginBlocked
        case privacyModeChanged
    }

    let id: UUID
    let occurredAt: Date
    let kind: Kind
    let summary: String
    let localOnly: Bool
}

struct PrivacyLedgerCounts: Equatable {
    var valid = 0
    var local = 0
    var external = 0
    var invalid = 0
    var storageIssue = false
}

struct PrivacyLedgerPurgeResult: Equatable {
    var examined = 0
    var removed = 0
    var retained = 0
    var invalidRetained = 0
    var failure: String?
}

enum PrivacyLedgerExportFormat: String {
    case json
    case jsonl
}

struct PrivacyLedgerExportResult: Equatable {
    let exported: Int
    let invalidSkipped: Int
    let destination: URL
}

struct PrivacyLedgerLimits: Equatable {
    let maximumFileBytes: Int
    let maximumRows: Int
    let maximumRowBytes: Int
    let maximumSummaryBytes: Int

    static let production = PrivacyLedgerLimits(
        maximumFileBytes: 4 * 1_024 * 1_024,
        maximumRows: 10_000,
        maximumRowBytes: 32 * 1_024,
        maximumSummaryBytes: 4 * 1_024
    )
}

enum PrivacyLedgerPersistenceStage: Equatable, Sendable {
    case beforeWrite
    case beforeRename
    case afterRename
    case beforeDirectorySync
}

private enum PrivacyLedgerPersistenceOutcome {
    case durable
    case committedButDurabilityUnverified
}

final class PrivacyLedger {
    static let defaultRetentionDays = 90

    private static let directoryName = "Privacy"
    private static let documentName = "events.jsonl"

    private struct Row {
        let raw: Data
        let event: PrivacyEvent?
    }

    private let queue = DispatchQueue(label: "app.localharness.privacy-ledger")
    private let fileManager: FileManager
    private let directoryURL: URL
    private let fileURL: URL
    private let limits: PrivacyLedgerLimits
    private let persistenceFailureInjector: ((PrivacyLedgerPersistenceStage) throws -> Void)?
    private var cachedRowCount: Int?
    private var cachedFileBytes: Int?
    private var persistenceUnavailable = false

    init(
        applicationSupport: URL,
        fileManager: FileManager = .default,
        limits: PrivacyLedgerLimits = .production,
        persistenceFailureInjector: ((PrivacyLedgerPersistenceStage) throws -> Void)? = nil
    ) {
        self.fileManager = fileManager
        self.limits = limits
        self.persistenceFailureInjector = persistenceFailureInjector
        precondition(limits.maximumFileBytes > 0)
        precondition(limits.maximumRows > 0)
        precondition(limits.maximumRowBytes > 0 && limits.maximumRowBytes < limits.maximumFileBytes)
        precondition(limits.maximumSummaryBytes > 0 && limits.maximumSummaryBytes <= limits.maximumRowBytes)
        directoryURL = applicationSupport.appendingPathComponent(Self.directoryName, isDirectory: true)
        fileURL = directoryURL.appendingPathComponent(Self.documentName)
        if let descriptor = try? openLedgerDirectory(createIfMissing: true) {
            _ = Darwin.close(descriptor)
        }
    }

    func record(
        _ kind: PrivacyEvent.Kind,
        summary: String,
        localOnly: Bool,
        occurredAt: Date = Date()
    ) {
        let event = makeEvent(kind, summary: summary, localOnly: localOnly, occurredAt: occurredAt)
        queue.async { [weak self] in
            try? self?.append(event)
        }
    }

    /// A bounded, durable append for shutdown and other ordering-sensitive audit events.
    /// The serial queue drains earlier asynchronous records before this returns.
    func recordSynchronously(
        _ kind: PrivacyEvent.Kind,
        summary: String,
        localOnly: Bool,
        occurredAt: Date = Date()
    ) throws {
        let event = makeEvent(kind, summary: summary, localOnly: localOnly, occurredAt: occurredAt)
        try queue.sync { try append(event) }
    }

    func recent(limit: Int = 200) -> [PrivacyEvent] {
        queue.sync {
            (try? loadRows())?.compactMap(\.event).suffix(max(1, limit)).reversed() ?? []
        }
    }

    func counts() -> PrivacyLedgerCounts {
        queue.sync {
            guard let rows = try? loadRows() else { return PrivacyLedgerCounts(storageIssue: true) }
            return rows.reduce(into: PrivacyLedgerCounts()) { result, row in
                guard let event = row.event else { result.invalid += 1; return }
                result.valid += 1
                if event.localOnly { result.local += 1 } else { result.external += 1 }
            }
        }
    }

    func clear() throws {
        try queue.sync {
            let outcome = try atomicWrite(Data())
            cachedRowCount = 0
            cachedFileBytes = 0
            try requireDurable(outcome)
        }
    }

    @discardableResult
    func purgeExpired(
        now: Date = Date(),
        retentionDays: Int = PrivacyLedger.defaultRetentionDays
    ) throws -> PrivacyLedgerPurgeResult {
        try queue.sync {
            let rows = try loadRows()
            let cutoff = now.addingTimeInterval(-Double(max(1, retentionDays)) * 86_400)
            var kept = Data()
            var result = PrivacyLedgerPurgeResult(examined: rows.count)
            for row in rows {
                if let event = row.event, event.occurredAt < cutoff {
                    result.removed += 1
                    continue
                }
                kept.append(row.raw)
                kept.append(0x0A)
                result.retained += 1
                if row.event == nil { result.invalidRetained += 1 }
            }
            let outcome = try atomicWrite(kept)
            cachedRowCount = result.retained
            cachedFileBytes = kept.count
            try requireDurable(outcome)
            return result
        }
    }

    @discardableResult
    func export(to destination: URL, format: PrivacyLedgerExportFormat) throws -> PrivacyLedgerExportResult {
        try queue.sync {
            let rows = try loadRows()
            let events = rows.compactMap(\.event)
            let invalid = rows.count - events.count
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data: Data
            switch format {
            case .json:
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                data = try encoder.encode(events)
            case .jsonl:
                var output = Data()
                for event in events {
                    output.append(try encoder.encode(event))
                    output.append(0x0A)
                }
                data = output
            }
            try Self.atomicPrivateWrite(data, to: destination, fileManager: fileManager, secureParent: false)
            return PrivacyLedgerExportResult(exported: events.count, invalidSkipped: invalid, destination: destination)
        }
    }

    private func append(_ event: PrivacyEvent) throws {
        guard !persistenceUnavailable else { throw CocoaError(.fileWriteUnknown) }
        var data = try JSONEncoder().encode(event)
        guard data.count <= limits.maximumRowBytes else {
            throw CocoaError(.fileWriteUnknown)
        }
        data.append(0x0A)
        if !fileManager.fileExists(atPath: fileURL.path) {
            guard data.count <= limits.maximumFileBytes else {
                throw CocoaError(.fileWriteUnknown)
            }
            let outcome = try atomicWrite(data)
            cachedRowCount = 1
            cachedFileBytes = data.count
            try requireDurable(outcome)
            return
        }
        let directoryDescriptor = try openLedgerDirectory(createIfMissing: false)
        defer { _ = Darwin.close(directoryDescriptor) }
        var pathMetadata = stat()
        let inspected = Self.documentName.withCString { name in
            fstatat(directoryDescriptor, name, &pathMetadata, AT_SYMLINK_NOFOLLOW)
        }
        guard inspected == 0,
              Self.isPrivateRegularDocument(pathMetadata),
              pathMetadata.st_size >= 0,
              pathMetadata.st_size <= off_t(limits.maximumFileBytes) else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        let size = Int(pathMetadata.st_size)
        if cachedFileBytes != size || cachedRowCount == nil {
            _ = try loadRows()
        }
        guard let rowCount = cachedRowCount, let fileBytes = cachedFileBytes else {
            throw CocoaError(.fileWriteUnknown)
        }
        if rowCount >= limits.maximumRows || fileBytes > limits.maximumFileBytes - data.count {
            try rotateAndAppend(data)
            return
        }
        let descriptor = Self.documentName.withCString { name in
            openat(
                directoryDescriptor,
                name,
                O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Self.sameIdentity(pathMetadata, metadata),
              Self.isPrivateRegularDocument(metadata),
              Int(metadata.st_size) == fileBytes else {
            Darwin.close(descriptor)
            cachedRowCount = nil
            cachedFileBytes = nil
            throw CocoaError(.fileWriteUnknown)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        try handle.write(contentsOf: data)
        try handle.synchronize()
        var after = stat()
        var installed = stat()
        let installedResult = Self.documentName.withCString { name in
            fstatat(directoryDescriptor, name, &installed, AT_SYMLINK_NOFOLLOW)
        }
        guard Darwin.fstat(descriptor, &after) == 0,
              installedResult == 0,
              Self.isPrivateRegularDocument(after),
              Self.sameIdentity(metadata, after),
              Self.sameIdentity(after, installed),
              after.st_size == off_t(fileBytes + data.count) else {
            persistenceUnavailable = true
            throw CocoaError(.fileWriteNoPermission)
        }
        do {
            try requireLedgerDirectoryStillInstalled(directoryDescriptor)
        } catch {
            persistenceUnavailable = true
            throw error
        }
        cachedRowCount = rowCount + 1
        cachedFileBytes = fileBytes + data.count
    }

    /// Retains a contiguous newest suffix and leaves headroom so a full ledger
    /// does not rewrite its entire bounded file for every subsequent event.
    private func rotateAndAppend(_ encodedEventWithNewline: Data) throws {
        let rows = try loadRows()
        let rowHeadroom = max(1, limits.maximumRows / 10)
        let targetExistingRows = max(0, limits.maximumRows - rowHeadroom - 1)
        let byteHeadroom = max(limits.maximumRowBytes + 1, limits.maximumFileBytes / 10)
        let targetTotalBytes = max(encodedEventWithNewline.count, limits.maximumFileBytes - byteHeadroom)
        var newestReversed: [Row] = []
        newestReversed.reserveCapacity(min(rows.count, targetExistingRows))
        var outputBytes = encodedEventWithNewline.count
        for row in rows.reversed() {
            let rowBytes = row.raw.count + 1
            guard newestReversed.count < targetExistingRows,
                  outputBytes <= targetTotalBytes - rowBytes else { break }
            newestReversed.append(row)
            outputBytes += rowBytes
        }
        var output = Data(capacity: outputBytes)
        for row in newestReversed.reversed() {
            output.append(row.raw)
            output.append(0x0A)
        }
        output.append(encodedEventWithNewline)
        guard output.count <= limits.maximumFileBytes,
              newestReversed.count + 1 <= limits.maximumRows else {
            throw CocoaError(.fileWriteUnknown)
        }
        let outcome = try atomicWrite(output)
        cachedRowCount = newestReversed.count + 1
        cachedFileBytes = output.count
        try requireDurable(outcome)
    }

    private func loadRows() throws -> [Row] {
        guard !persistenceUnavailable else { throw CocoaError(.fileReadUnknown) }
        let directoryDescriptor = try openLedgerDirectory(createIfMissing: true)
        defer { _ = Darwin.close(directoryDescriptor) }
        let descriptor = Self.documentName.withCString { name in
            openat(
                directoryDescriptor,
                name,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        if descriptor < 0, errno == ENOENT {
            try requireLedgerDirectoryStillInstalled(directoryDescriptor)
            cachedRowCount = 0
            cachedFileBytes = 0
            return []
        }
        guard descriptor >= 0 else { throw CocoaError(.fileReadUnknown) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              Self.isPrivateRegularDocument(before),
              before.st_size >= 0,
              before.st_size <= limits.maximumFileBytes else {
            throw CocoaError(.fileReadTooLarge)
        }
        var rows: [Row] = []
        var buffer = Data()
        var cursor = 0
        var received = 0
        while true {
            let chunk = try handle.read(upToCount: 64 * 1_024) ?? Data()
            if chunk.isEmpty { break }
            guard received <= limits.maximumFileBytes - chunk.count else {
                throw CocoaError(.fileReadTooLarge)
            }
            received += chunk.count
            buffer.append(chunk)
            while cursor < buffer.count,
                  let newline = buffer[cursor...].firstIndex(of: 0x0A) {
                let raw = Data(buffer[cursor..<newline])
                try appendLoadedRow(raw, to: &rows)
                cursor = newline + 1
                if cursor >= 256 * 1_024 {
                    buffer.removeSubrange(0..<cursor)
                    cursor = 0
                }
            }
            guard buffer.count - cursor <= limits.maximumRowBytes else {
                throw CocoaError(.fileReadTooLarge)
            }
        }
        if cursor < buffer.count {
            try appendLoadedRow(Data(buffer[cursor...]), to: &rows)
        }
        var after = stat()
        var installed = stat()
        let installedResult = Self.documentName.withCString { name in
            fstatat(directoryDescriptor, name, &installed, AT_SYMLINK_NOFOLLOW)
        }
        guard received == Int(before.st_size),
              Darwin.fstat(descriptor, &after) == 0,
              installedResult == 0,
              Self.sameIdentity(before, after),
              Self.sameIdentity(after, installed),
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw CocoaError(.fileReadCorruptFile)
        }
        try requireLedgerDirectoryStillInstalled(directoryDescriptor)
        cachedRowCount = rows.count
        cachedFileBytes = received
        return rows
    }

    private func appendLoadedRow(_ raw: Data, to rows: inout [Row]) throws {
        guard raw.count <= limits.maximumRowBytes, rows.count < limits.maximumRows else {
            throw CocoaError(.fileReadTooLarge)
        }
        rows.append(Row(raw: raw, event: try? JSONDecoder().decode(PrivacyEvent.self, from: raw)))
    }

    private func makeEvent(
        _ kind: PrivacyEvent.Kind,
        summary: String,
        localOnly: Bool,
        occurredAt: Date
    ) -> PrivacyEvent {
        let safeSummary = Self.safeSummaryForDisplay(
            summary,
            maximumCharacters: min(limits.maximumSummaryBytes, 4_096)
        )
        return PrivacyEvent(
            id: UUID(),
            occurredAt: occurredAt,
            kind: kind,
            summary: Self.utf8Prefix(safeSummary, maximumBytes: limits.maximumSummaryBytes),
            localOnly: localOnly
        )
    }

    /// Privacy rows are durable, legacy-readable data. Sanitize both before
    /// persistence and again at display so a tampered/legacy row cannot inject
    /// controls, directional text, credentials, private home paths, or an
    /// attacker-sized label into AppKit.
    static func safeSummaryForDisplay(
        _ value: String,
        maximumCharacters: Int = 512
    ) -> String {
        AuxiliaryDisplayPolicy.singleLine(
            value,
            maximumCharacters: min(max(1, maximumCharacters), 4_096),
            fallback: "Private activity"
        )
    }

    private static func utf8Prefix(_ value: String, maximumBytes: Int) -> String {
        guard maximumBytes > 0 else { return "" }
        let bytes = Data(value.utf8)
        guard bytes.count > maximumBytes else { return value }
        var prefix = Data(bytes.prefix(maximumBytes))
        while !prefix.isEmpty, String(data: prefix, encoding: .utf8) == nil {
            prefix.removeLast()
        }
        return String(data: prefix, encoding: .utf8) ?? ""
    }

    private func requireDurable(_ outcome: PrivacyLedgerPersistenceOutcome) throws {
        guard outcome == .durable else {
            persistenceUnavailable = true
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private func atomicWrite(_ data: Data) throws -> PrivacyLedgerPersistenceOutcome {
        guard !persistenceUnavailable else { throw CocoaError(.fileWriteUnknown) }
        guard data.count <= limits.maximumFileBytes else { throw CocoaError(.fileWriteUnknown) }
        let directoryDescriptor = try openLedgerDirectory(createIfMissing: true)
        defer { _ = Darwin.close(directoryDescriptor) }
        try Self.requireSafeLedgerDestinationIfPresent(directoryDescriptor)

        let temporaryName = ".events.\(UUID().uuidString).tmp"
        let descriptor = temporaryName.withCString { name in
            openat(
                directoryDescriptor,
                name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        var temporaryExists = true
        defer {
            _ = Darwin.close(descriptor)
            if temporaryExists {
                temporaryName.withCString { name in
                    _ = unlinkat(directoryDescriptor, name, 0)
                }
            }
        }

        var renamed = false
        do {
            try persistenceFailureInjector?(.beforeWrite)
            try Self.writeAll(data, to: descriptor)
            guard fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0,
                  fsync(descriptor) == 0 else {
                throw CocoaError(.fileWriteUnknown)
            }
            var staged = stat()
            guard fstat(descriptor, &staged) == 0,
                  Self.isPrivateRegularDocument(staged),
                  staged.st_size == off_t(data.count) else {
                throw CocoaError(.fileWriteUnknown)
            }

            try persistenceFailureInjector?(.beforeRename)
            try Self.requireSafeLedgerDestinationIfPresent(directoryDescriptor)
            let result = temporaryName.withCString { temporary in
                Self.documentName.withCString { destination in
                    renameat(directoryDescriptor, temporary, directoryDescriptor, destination)
                }
            }
            guard result == 0 else { throw CocoaError(.fileWriteUnknown) }
            temporaryExists = false
            renamed = true

            do {
                try persistenceFailureInjector?(.afterRename)
                try Self.requirePersistedLedgerIdentity(staged, in: directoryDescriptor)
                try persistenceFailureInjector?(.beforeDirectorySync)
                guard fsync(directoryDescriptor) == 0 else {
                    throw CocoaError(.fileWriteUnknown)
                }
                try Self.requirePersistedLedgerIdentity(staged, in: directoryDescriptor)
                try requireLedgerDirectoryStillInstalled(directoryDescriptor)
                return .durable
            } catch {
                // The namespace commit has happened. If the exact staged inode
                // remains installed, callers adopt its cache counts and enter a
                // fail-closed state until relaunch rather than retaining false old
                // state. The next process re-attests and reads the committed bytes.
                if (try? Self.requirePersistedLedgerIdentity(staged, in: directoryDescriptor)) != nil,
                   (try? requireLedgerDirectoryStillInstalled(directoryDescriptor)) != nil {
                    return .committedButDurabilityUnverified
                }
                persistenceUnavailable = true
                throw CocoaError(.fileWriteUnknown)
            }
        } catch {
            if renamed { persistenceUnavailable = true }
            throw error
        }
    }

    private func openLedgerDirectory(createIfMissing: Bool) throws -> Int32 {
        let applicationSupport = directoryURL.deletingLastPathComponent().standardizedFileURL
        let parent = applicationSupport.deletingLastPathComponent().standardizedFileURL
        let applicationSupportName = applicationSupport.lastPathComponent
        guard Self.validPathComponent(applicationSupportName) else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        let parentDescriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard parentDescriptor >= 0 else { throw CocoaError(.fileWriteInvalidFileName) }
        defer { _ = Darwin.close(parentDescriptor) }
        var parentMetadata = stat()
        guard fstat(parentDescriptor, &parentMetadata) == 0,
              Self.isPrivateDirectory(parentMetadata) else {
            throw CocoaError(.fileWriteNoPermission)
        }

        let applicationSupportDescriptor = try Self.openPrivateChildDirectory(
            named: applicationSupportName,
            beneath: parentDescriptor,
            createIfMissing: createIfMissing
        )
        defer { _ = Darwin.close(applicationSupportDescriptor) }
        return try Self.openPrivateChildDirectory(
            named: Self.directoryName,
            beneath: applicationSupportDescriptor,
            createIfMissing: createIfMissing
        )
    }

    private func requireLedgerDirectoryStillInstalled(_ descriptor: Int32) throws {
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              Self.isPrivateDirectory(opened) else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        let installedDescriptor = try openLedgerDirectory(createIfMissing: false)
        defer { _ = Darwin.close(installedDescriptor) }
        var installed = stat()
        guard fstat(installedDescriptor, &installed) == 0,
              Self.isPrivateDirectory(installed),
              Self.sameIdentity(opened, installed) else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
    }

    private static func openPrivateChildDirectory(
        named name: String,
        beneath parentDescriptor: Int32,
        createIfMissing: Bool
    ) throws -> Int32 {
        guard validPathComponent(name) else { throw CocoaError(.fileWriteInvalidFileName) }
        var pathMetadata = stat()
        var inspected = name.withCString { entry in
            fstatat(parentDescriptor, entry, &pathMetadata, AT_SYMLINK_NOFOLLOW)
        }
        if inspected != 0, errno == ENOENT, createIfMissing {
            let created = name.withCString { entry in
                mkdirat(parentDescriptor, entry, mode_t(S_IRWXU))
            }
            guard created == 0 || errno == EEXIST else { throw CocoaError(.fileWriteUnknown) }
            inspected = name.withCString { entry in
                fstatat(parentDescriptor, entry, &pathMetadata, AT_SYMLINK_NOFOLLOW)
            }
            guard inspected == 0,
                  fsync(parentDescriptor) == 0 else {
                throw CocoaError(.fileWriteUnknown)
            }
        }
        guard inspected == 0,
              isPrivateDirectory(pathMetadata) else {
            throw CocoaError(.fileWriteNoPermission)
        }
        let descriptor = name.withCString { entry in
            openat(
                parentDescriptor,
                entry,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else { throw CocoaError(.fileWriteInvalidFileName) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              isPrivateDirectory(opened),
              sameIdentity(pathMetadata, opened) else {
            _ = Darwin.close(descriptor)
            throw CocoaError(.fileWriteInvalidFileName)
        }
        return descriptor
    }

    private static func requireSafeLedgerDestinationIfPresent(_ directoryDescriptor: Int32) throws {
        var metadata = stat()
        let result = Self.documentName.withCString { name in
            fstatat(directoryDescriptor, name, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return }
            throw CocoaError(.fileWriteInvalidFileName)
        }
        guard isPrivateRegularDocument(metadata) else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
    }

    private static func requirePersistedLedgerIdentity(
        _ staged: stat,
        in directoryDescriptor: Int32
    ) throws {
        var installed = stat()
        let result = Self.documentName.withCString { name in
            fstatat(directoryDescriptor, name, &installed, AT_SYMLINK_NOFOLLOW)
        }
        guard result == 0,
              isPrivateRegularDocument(installed),
              sameIdentity(staged, installed),
              staged.st_size == installed.st_size else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private static func isPrivateDirectory(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFDIR &&
            metadata.st_uid == geteuid() &&
            (metadata.st_mode & mode_t(0o7777)) == mode_t(0o700)
    }

    private static func isPrivateRegularDocument(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFREG &&
            metadata.st_uid == geteuid() &&
            metadata.st_nlink == 1 &&
            (metadata.st_mode & mode_t(0o7777)) == mode_t(0o600)
    }

    private static func sameIdentity(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }

    private static func validPathComponent(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." &&
            !value.contains("/") && !value.contains("\0") &&
            value.utf8.count <= Int(NAME_MAX)
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        var failure: CocoaError?
        data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    bytes.count - offset
                )
                if written > 0 {
                    offset += written
                } else if written < 0, errno == EINTR {
                    continue
                } else {
                    failure = CocoaError(.fileWriteUnknown)
                    break
                }
            }
        }
        if let failure { throw failure }
    }

    private static func atomicPrivateWrite(
        _ data: Data,
        to destination: URL,
        fileManager: FileManager,
        secureParent: Bool
    ) throws {
        let directory = destination.deletingLastPathComponent()
        if !fileManager.fileExists(atPath: directory.path) {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw CocoaError(.fileWriteInvalidFileName) }
        defer { _ = Darwin.close(descriptor) }
        var directoryMetadata = stat()
        guard fstat(descriptor, &directoryMetadata) == 0,
              (directoryMetadata.st_mode & S_IFMT) == S_IFDIR,
              (!secureParent || isPrivateDirectory(directoryMetadata)) else {
            throw CocoaError(.fileWriteNoPermission)
        }
        let destinationName = destination.lastPathComponent
        guard validPathComponent(destinationName) else { throw CocoaError(.fileWriteInvalidFileName) }
        var existing = stat()
        let existingResult = destinationName.withCString { name in
            fstatat(descriptor, name, &existing, AT_SYMLINK_NOFOLLOW)
        }
        if existingResult == 0 {
            guard isPrivateRegularDocument(existing) else {
                throw CocoaError(.fileWriteInvalidFileName)
            }
        } else if errno != ENOENT {
            throw CocoaError(.fileWriteInvalidFileName)
        }

        let temporaryName = ".\(destinationName).\(UUID().uuidString).tmp"
        let temporaryDescriptor = temporaryName.withCString { name in
            openat(
                descriptor,
                name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard temporaryDescriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        var temporaryExists = true
        defer {
            _ = Darwin.close(temporaryDescriptor)
            if temporaryExists {
                temporaryName.withCString { name in _ = unlinkat(descriptor, name, 0) }
            }
        }
        try writeAll(data, to: temporaryDescriptor)
        guard fchmod(temporaryDescriptor, mode_t(S_IRUSR | S_IWUSR)) == 0,
              fsync(temporaryDescriptor) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
        var staged = stat()
        guard fstat(temporaryDescriptor, &staged) == 0,
              isPrivateRegularDocument(staged),
              staged.st_size == off_t(data.count) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let renamed = temporaryName.withCString { temporary in
            destinationName.withCString { installed in
                renameat(descriptor, temporary, descriptor, installed)
            }
        }
        guard renamed == 0 else { throw CocoaError(.fileWriteUnknown) }
        temporaryExists = false
        var installed = stat()
        let inspected = destinationName.withCString { name in
            fstatat(descriptor, name, &installed, AT_SYMLINK_NOFOLLOW)
        }
        guard inspected == 0,
              isPrivateRegularDocument(installed),
              sameIdentity(staged, installed),
              fsync(descriptor) == 0,
              directoryPathStillNames(directoryMetadata, at: directory) else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private static func directoryPathStillNames(_ expected: stat, at directory: URL) -> Bool {
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { return false }
        defer { _ = Darwin.close(descriptor) }
        var installed = stat()
        return fstat(descriptor, &installed) == 0 &&
            (installed.st_mode & S_IFMT) == S_IFDIR &&
            sameIdentity(expected, installed)
    }
}

enum AttachmentRetentionStatus: Equatable {
    case completed
    case noStore
    case deferred(String)
    case unsupported(String)
    case failed(String)
}

struct AttachmentRetentionReport: Equatable {
    var status: AttachmentRetentionStatus
    var examined = 0
    var referenced = 0
    var eligible = 0
    var deleted = 0
    var retained = 0
    var failures = 0
}

/// Deterministic descriptor-boundaries used by the focused security tests.
/// Production does not install a hook. A hook may mutate pathname state, but
/// the retention pass continues to use the already-open HarnessHome
/// capability and must fail closed before an unlink if anything was replaced.
enum AttachmentRetentionDescriptorPoint: Equatable, Sendable {
    case homeReceiptInspected
    case homeVerified
    case objectsScanned
    case referencesScanned
    case beforeCandidateQuarantine
    case beforeCandidateUnlink
}

struct AttachmentRetentionLimits: Equatable {
    let maximumDirectoryEntries: Int
    let maximumProjects: Int
    let maximumSessions: Int
    let maximumObjects: Int
    let maximumLogBytes: Int
    let maximumAggregateLogBytes: Int
    let maximumDecodedBytes: Int
    let maximumJSONLRowBytes: Int
    let maximumReferences: Int
    let maximumJSONNodesPerRow: Int
    let maximumObjectBytes: Int
    let maximumAggregateObjectBytes: Int
    let maximumChildResultBytes: Int
    let scanDuration: TimeInterval

    static let production = AttachmentRetentionLimits(
        maximumDirectoryEntries: 10_000,
        maximumProjects: 512,
        maximumSessions: 5_000,
        maximumObjects: 10_000,
        maximumLogBytes: 64 * 1_024 * 1_024,
        maximumAggregateLogBytes: 512 * 1_024 * 1_024,
        maximumDecodedBytes: 256 * 1_024 * 1_024,
        maximumJSONLRowBytes: 4 * 1_024 * 1_024,
        maximumReferences: 100_000,
        maximumJSONNodesPerRow: 100_000,
        maximumObjectBytes: 256 * 1_024 * 1_024,
        maximumAggregateObjectBytes: 2 * 1_024 * 1_024 * 1_024,
        maximumChildResultBytes: 8 * 1_024 * 1_024,
        scanDuration: 8
    )
}

final class AttachmentRetentionManager {
    typealias ZstdReferenceReader = (URL) throws -> Set<String>
    /// The descriptor is borrowed for this call and names the exact directory
    /// from which `rawReceipt` was read with `openat`. This is the single
    /// adapter point for the shared signed HarnessHome marker verifier.
    typealias HarnessHomeReceiptVerifier = (
        _ harnessHome: URL,
        _ exactHomeDescriptor: Int32,
        _ rawReceipt: Data
    ) throws -> Void

    private static let ownershipReceiptName = ProviderHistoryPrivacyEpoch.ownershipReceiptName
    private static let maximumOwnershipReceiptBytes = 64 * 1_024
    private struct OwnershipReceipt: Decodable {
        let version: Int
        let migratedAt: Date
        let source: String?
        let copiedEntries: [String]
        let sourceKind: String?
        let providerHistoryPrivacyEpoch: Int?
    }

    private struct NodeSnapshot: Equatable {
        let device: UInt64
        let inode: UInt64
        let owner: UInt32
        let mode: UInt16
        let links: UInt64
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64
        let changedSeconds: Int64
        let changedNanoseconds: Int64

        init(_ value: stat) {
            device = UInt64(truncatingIfNeeded: value.st_dev)
            inode = UInt64(truncatingIfNeeded: value.st_ino)
            owner = value.st_uid
            mode = UInt16(value.st_mode & mode_t(0o7777))
            links = UInt64(truncatingIfNeeded: value.st_nlink)
            size = Int64(value.st_size)
            modifiedSeconds = Int64(value.st_mtimespec.tv_sec)
            modifiedNanoseconds = Int64(value.st_mtimespec.tv_nsec)
            changedSeconds = Int64(value.st_ctimespec.tv_sec)
            changedNanoseconds = Int64(value.st_ctimespec.tv_nsec)
        }

        var modificationDate: Date {
            Date(
                timeIntervalSince1970: Double(modifiedSeconds)
                    + Double(modifiedNanoseconds) / 1_000_000_000
            )
        }

        func sameNode(as value: stat) -> Bool {
            device == UInt64(truncatingIfNeeded: value.st_dev)
                && inode == UInt64(truncatingIfNeeded: value.st_ino)
        }

        // rename(2) may legitimately advance ctime even though the opened
        // object and its bytes are unchanged. This comparison is used only
        // across our own verified rename; the post-rename snapshot and digest
        // are captured again before unlink.
        func sameFileAcrossRename(as value: stat) -> Bool {
            sameNode(as: value)
                && owner == value.st_uid
                && mode == UInt16(value.st_mode & mode_t(0o7777))
                && links == UInt64(truncatingIfNeeded: value.st_nlink)
                && size == Int64(value.st_size)
                && modifiedSeconds == Int64(value.st_mtimespec.tv_sec)
                && modifiedNanoseconds == Int64(value.st_mtimespec.tv_nsec)
        }
    }

    private final class HomeCapability {
        let parentDescriptor: Int32
        let homeDescriptor: Int32
        let parent: NodeSnapshot
        let home: NodeSnapshot
        let homeName: String
        let receipt: NodeSnapshot
        let receiptBytes: Data
        let ownsHomeDescriptor: Bool
        let attestationRecord: HarnessHomeAttestationRecord?

        init(
            parentDescriptor: Int32,
            homeDescriptor: Int32,
            parent: NodeSnapshot,
            home: NodeSnapshot,
            homeName: String,
            receipt: NodeSnapshot,
            receiptBytes: Data,
            ownsHomeDescriptor: Bool = true,
            attestationRecord: HarnessHomeAttestationRecord? = nil
        ) {
            self.parentDescriptor = parentDescriptor
            self.homeDescriptor = homeDescriptor
            self.parent = parent
            self.home = home
            self.homeName = homeName
            self.receipt = receipt
            self.receiptBytes = receiptBytes
            self.ownsHomeDescriptor = ownsHomeDescriptor
            self.attestationRecord = attestationRecord
        }

        deinit {
            if ownsHomeDescriptor { _ = Darwin.close(homeDescriptor) }
            _ = Darwin.close(parentDescriptor)
        }
    }

    private struct DirectoryBinding {
        let parentDescriptor: Int32
        let descriptor: Int32
        let leafName: String
        let identity: NodeSnapshot
    }

    private final class ObjectStoreCapability {
        let descriptor: Int32
        let identity: NodeSnapshot
        let bindings: [DirectoryBinding]
        init(bindings: [DirectoryBinding]) {
            self.bindings = bindings
            descriptor = bindings[bindings.count - 1].descriptor
            identity = bindings[bindings.count - 1].identity
        }
        deinit { for binding in bindings.reversed() { _ = Darwin.close(binding.descriptor) } }
    }

    private final class SessionStoreCapability {
        let descriptor: Int32
        let identity: NodeSnapshot
        let bindings: [DirectoryBinding]
        init(bindings: [DirectoryBinding]) {
            self.bindings = bindings
            descriptor = bindings[bindings.count - 1].descriptor
            identity = bindings[bindings.count - 1].identity
        }
        deinit { for binding in bindings.reversed() { _ = Darwin.close(binding.descriptor) } }
    }

    private struct ObjectSnapshot {
        let bucketName: String
        let bucket: NodeSnapshot
        let name: String
        let file: NodeSnapshot
        let digest: String
        let size: Int
        let modified: Date
    }

    private struct SessionSnapshot {
        let projectName: String
        let project: NodeSnapshot
        let sessionName: String
        let session: NodeSnapshot
        let logName: String
        let file: NodeSnapshot
        let size: Int
        let modified: Date
        let digest: String

        var key: String { "\(projectName)/\(sessionName)/\(logName)" }
    }

    private struct ObjectScan {
        let store: ObjectStoreCapability
        let objects: [ObjectSnapshot]
    }

    private struct ReferenceScan {
        let store: SessionStoreCapability
        let references: Set<String>
        let snapshots: [SessionSnapshot]
    }

    private struct ZstdScanResult {
        let references: Set<String>
        let decodedBytes: Int
    }

    private struct ZstdChildResult: Decodable {
        let decodedBytes: Int
        let references: [String]
    }

    private enum ValidationError: LocalizedError {
        case unsupported(String)
        var errorDescription: String? {
            guard case .unsupported(let detail) = self else { return nil }
            return detail
        }
    }

    private enum ChildKind {
        case missing
        case directory
        case regular
        case symbolicLink
        case other
    }

    private let fileManager: FileManager
    private let harnessHome: URL
    private let trustedNode: URL?
    private let injectedZstdReader: ZstdReferenceReader?
    private let ownershipReceiptInspectionHook: (() -> Void)?
    private let harnessHomeReceiptVerifier: HarnessHomeReceiptVerifier?
    private let descriptorInspectionHook: ((AttachmentRetentionDescriptorPoint) -> Void)?
    private let harnessHomeCapabilityProvider: @Sendable () -> HarnessHomeAttestationCapability?
    private let allowUnattestedHarnessHomeForTesting: Bool
    private let limits: AttachmentRetentionLimits

    init(
        harnessHome: URL,
        trustedNode: URL? = nil,
        fileManager: FileManager = .default,
        zstdReferenceReader: ZstdReferenceReader? = nil,
        limits: AttachmentRetentionLimits = .production,
        ownershipReceiptInspectionHook: (() -> Void)? = nil,
        harnessHomeReceiptVerifier: HarnessHomeReceiptVerifier? = nil,
        descriptorInspectionHook: ((AttachmentRetentionDescriptorPoint) -> Void)? = nil,
        harnessHomeCapabilityProvider: @escaping @Sendable () -> HarnessHomeAttestationCapability? = { nil },
        allowUnattestedHarnessHomeForTesting: Bool = false
    ) {
        self.harnessHome = harnessHome
        self.trustedNode = trustedNode
        self.fileManager = fileManager
        injectedZstdReader = zstdReferenceReader
        self.ownershipReceiptInspectionHook = ownershipReceiptInspectionHook
        self.harnessHomeReceiptVerifier = harnessHomeReceiptVerifier
        self.descriptorInspectionHook = descriptorInspectionHook
        self.harnessHomeCapabilityProvider = harnessHomeCapabilityProvider
        self.allowUnattestedHarnessHomeForTesting = allowUnattestedHarnessHomeForTesting
        self.limits = limits
    }

    func purgeExpired(retentionDays: Int, now: Date = Date()) -> AttachmentRetentionReport {
        do {
            if let attestedHarnessHome = harnessHomeCapabilityProvider() {
                return try attestedHarnessHome.withBorrowedDescriptor { descriptor in
                    try performPurge(
                        retentionDays: retentionDays,
                        now: now,
                        attestedDescriptor: descriptor,
                        attestationRecord: attestedHarnessHome.record
                    )
                }
            }
            guard allowUnattestedHarnessHomeForTesting else {
                throw ValidationError.unsupported(
                    "Attachment cleanup is unavailable until the signed Harness home capability is verified."
                )
            }
            return try performPurge(
                retentionDays: retentionDays,
                now: now,
                attestedDescriptor: nil,
                attestationRecord: nil
            )
        } catch let error as ValidationError {
            return AttachmentRetentionReport(status: .unsupported(error.localizedDescription))
        } catch {
            return AttachmentRetentionReport(status: .failed("Attachment retention could not complete safely."), failures: 1)
        }
    }

    private func performPurge(
        retentionDays: Int,
        now: Date,
        attestedDescriptor: Int32?,
        attestationRecord: HarnessHomeAttestationRecord?
    ) throws -> AttachmentRetentionReport {
        let deadline = try Self.monotonicDeadline(
            afterNanoseconds: UInt64(max(0.05, min(limits.scanDuration, 60)) * 1_000_000_000)
        )
        // The signed capability (when supplied) is borrowed for this entire
        // scope. The fallback verifier exists for tests and staged integration,
        // but it still pins one descriptor before any store leaf is inspected.
        let home = try requireOwnedHarnessHome(
            attestedDescriptor: attestedDescriptor,
            attestationRecord: attestationRecord
        )
        descriptorInspectionHook?(.homeVerified)
        guard try childKind(named: "attachments", beneath: home.homeDescriptor) != .missing else {
            try revalidate(home)
            return AttachmentRetentionReport(status: .noStore)
        }
        let objectScan = try loadObjects(home: home, deadline: deadline)
        descriptorInspectionHook?(.objectsScanned)
        if objectScan.objects.isEmpty {
            try revalidate(home)
            return AttachmentRetentionReport(status: .completed)
        }
        let referenceScan = try loadReferences(home: home, deadline: deadline)
        descriptorInspectionHook?(.referencesScanned)
        let cutoff = now.addingTimeInterval(-Double(max(1, retentionDays)) * 86_400)
        var report = AttachmentRetentionReport(status: .completed, examined: objectScan.objects.count)
        var candidates: [ObjectSnapshot] = []
        for object in objectScan.objects {
            if referenceScan.references.contains(object.digest) {
                report.referenced += 1
                report.retained += 1
            } else if object.modified < cutoff {
                report.eligible += 1
                candidates.append(object)
            } else {
                report.retained += 1
            }
        }
        guard try confirmSessionSnapshots(referenceScan, deadline: deadline) else {
            try revalidate(home)
            return AttachmentRetentionReport(
                status: .deferred("Session history changed during inspection; nothing was deleted."),
                examined: objectScan.objects.count,
                referenced: report.referenced,
                eligible: report.eligible,
                retained: objectScan.objects.count
            )
        }
        for candidate in candidates {
            try requireWithinDeadline(deadline)
            do {
                try quarantineAndDelete(
                    candidate,
                    objects: objectScan.store,
                    home: home,
                    deadline: deadline
                )
                report.deleted += 1
            } catch {
                report.retained += 1
                report.failures += 1
            }
        }
        if report.failures > 0 {
            report.status = .failed("Some eligible attachments changed or could not be removed.")
        }
        try revalidate(home)
        return report
    }

    private func requireOwnedHarnessHome(
        attestedDescriptor: Int32?,
        attestationRecord: HarnessHomeAttestationRecord?
    ) throws -> HomeCapability {
        let failure = ValidationError.unsupported(
            "Attachment cleanup is unavailable because this is not a proven app-owned Harness home."
        )
        let standardized = harnessHome.standardizedFileURL
        let parent = standardized.deletingLastPathComponent()
        let homeName = standardized.lastPathComponent
        guard Self.validPathComponent(homeName) else { throw failure }

        // The app-owned home is a private child of a private app-controlled
        // directory. Bind every subsequent check to opened descriptors so a
        // path chmod, link substitution, or receipt swap cannot redirect the
        // attestation to different bytes.
        let parentDescriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard parentDescriptor >= 0 else { throw failure }
        var parentMetadata = stat()
        guard fstat(parentDescriptor, &parentMetadata) == 0,
              Self.isOwnedPrivateDirectory(parentMetadata),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parentDescriptor) else {
            _ = Darwin.close(parentDescriptor)
            throw failure
        }

        var homePathMetadata = stat()
        let inspectedHome = homeName.withCString { name in
            fstatat(parentDescriptor, name, &homePathMetadata, AT_SYMLINK_NOFOLLOW)
        }
        guard inspectedHome == 0,
              Self.isOwnedPrivateDirectory(homePathMetadata) else {
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        let ownsHomeDescriptor = attestedDescriptor == nil
        let homeDescriptor: Int32
        if let attestedDescriptor {
            homeDescriptor = attestedDescriptor
        } else {
            homeDescriptor = homeName.withCString { name in
                openat(
                    parentDescriptor,
                    name,
                    O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                )
            }
        }
        func closeHomeIfOwned() {
            if ownsHomeDescriptor { _ = Darwin.close(homeDescriptor) }
        }
        guard homeDescriptor >= 0 else {
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        var openedHome = stat()
        guard fstat(homeDescriptor, &openedHome) == 0,
              Self.isOwnedPrivateDirectory(openedHome),
              Self.sameNode(homePathMetadata, openedHome),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(homeDescriptor) else {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        if let record = attestationRecord {
            guard record.canonicalPath == standardized.path,
                  record.leafName == homeName,
                  record.device == UInt64(truncatingIfNeeded: openedHome.st_dev),
                  record.inode == UInt64(truncatingIfNeeded: openedHome.st_ino),
                  record.owner == openedHome.st_uid,
                  record.mode == UInt16(openedHome.st_mode & mode_t(0o7777)),
                  record.privacyEpoch == UInt64(ProviderHistoryPrivacyEpoch.current) else {
                closeHomeIfOwned()
                _ = Darwin.close(parentDescriptor)
                throw failure
            }
        } else if attestedDescriptor != nil {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }

        var receiptPathMetadata = stat()
        let inspectedReceipt = Self.ownershipReceiptName.withCString { name in
            fstatat(homeDescriptor, name, &receiptPathMetadata, AT_SYMLINK_NOFOLLOW)
        }
        guard inspectedReceipt == 0,
              Self.isOwnedPrivateRegular(receiptPathMetadata),
              receiptPathMetadata.st_size > 0,
              receiptPathMetadata.st_size <= off_t(Self.maximumOwnershipReceiptBytes) else {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        ownershipReceiptInspectionHook?()
        descriptorInspectionHook?(.homeReceiptInspected)
        let receiptDescriptor = Self.ownershipReceiptName.withCString { name in
            openat(
                homeDescriptor,
                name,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard receiptDescriptor >= 0 else {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        defer { _ = Darwin.close(receiptDescriptor) }
        var openedReceipt = stat()
        guard fstat(receiptDescriptor, &openedReceipt) == 0,
              Self.isOwnedPrivateRegular(openedReceipt),
              Self.sameFileSnapshot(receiptPathMetadata, openedReceipt),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(receiptDescriptor) else {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }

        var data = Data()
        data.reserveCapacity(Int(openedReceipt.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(receiptDescriptor, bytes.baseAddress, bytes.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                closeHomeIfOwned()
                _ = Darwin.close(parentDescriptor)
                throw failure
            }
            guard count <= Self.maximumOwnershipReceiptBytes - data.count else {
                closeHomeIfOwned()
                _ = Darwin.close(parentDescriptor)
                throw failure
            }
            data.append(contentsOf: buffer.prefix(count))
        }

        var afterReceipt = stat()
        var installedReceipt = stat()
        var installedHome = stat()
        let receiptRecheck = Self.ownershipReceiptName.withCString { name in
            fstatat(homeDescriptor, name, &installedReceipt, AT_SYMLINK_NOFOLLOW)
        }
        let homeRecheck = homeName.withCString { name in
            fstatat(parentDescriptor, name, &installedHome, AT_SYMLINK_NOFOLLOW)
        }
        guard data.count == Int(openedReceipt.st_size),
              fstat(receiptDescriptor, &afterReceipt) == 0,
              receiptRecheck == 0,
              homeRecheck == 0,
              Self.sameFileSnapshot(openedReceipt, afterReceipt),
              Self.sameFileSnapshot(openedReceipt, installedReceipt),
              Self.isOwnedPrivateRegular(installedReceipt),
              Self.sameNode(openedHome, installedHome),
              Self.isOwnedPrivateDirectory(installedHome),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let decoded = try? JSONDecoder().decode(OwnershipReceipt.self, from: data) else {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }

        let requiredKeys: Set<String> = ["version", "migratedAt", "copiedEntries"]
        let copied = decoded.copiedEntries
        guard ProviderHistoryPrivacyEpoch.isCurrent(
                  receiptVersion: decoded.version,
                  epoch: decoded.providerHistoryPrivacyEpoch
              ),
              decoded.migratedAt.timeIntervalSinceReferenceDate.isFinite,
              copied == copied.sorted(),
              Set(copied).count == copied.count,
              copied.count <= ProviderHistoryPrivacyEpoch.settingsFileNames.count,
              copied.allSatisfy(ProviderHistoryPrivacyEpoch.settingsFileNames.contains) else {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        if decoded.source == nil {
            guard Set(object.keys) == requiredKeys.union(["providerHistoryPrivacyEpoch"]),
                  decoded.sourceKind == nil,
                  copied.isEmpty else {
                closeHomeIfOwned()
                _ = Darwin.close(parentDescriptor)
                throw failure
            }
        } else {
            guard Set(object.keys) == requiredKeys.union([
                "source", "sourceKind", "providerHistoryPrivacyEpoch"
            ]),
                  decoded.sourceKind == "historicalProviderState",
                  Self.validHistoricalRecoverySource(decoded.source, harnessHome: harnessHome) else {
                closeHomeIfOwned()
                _ = Darwin.close(parentDescriptor)
                throw failure
            }
        }
        do {
            try harnessHomeReceiptVerifier?(harnessHome, homeDescriptor, data)
        } catch {
            closeHomeIfOwned()
            _ = Darwin.close(parentDescriptor)
            throw failure
        }
        if let record = attestationRecord {
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard record.receiptSHA256 == digest else {
                closeHomeIfOwned()
                _ = Darwin.close(parentDescriptor)
                throw failure
            }
        }
        return HomeCapability(
            parentDescriptor: parentDescriptor,
            homeDescriptor: homeDescriptor,
            parent: NodeSnapshot(parentMetadata),
            home: NodeSnapshot(openedHome),
            homeName: homeName,
            receipt: NodeSnapshot(openedReceipt),
            receiptBytes: data,
            ownsHomeDescriptor: ownsHomeDescriptor,
            attestationRecord: attestationRecord
        )
    }

    private static func validHistoricalRecoverySource(
        _ source: String?,
        harnessHome: URL
    ) -> Bool {
        guard let source, !source.isEmpty else { return false }
        let sourceURL = URL(fileURLWithPath: source).standardizedFileURL
        let recoveryDirectory = harnessHome.deletingLastPathComponent()
            .appendingPathComponent("HarnessHomeRecovery", isDirectory: true)
            .standardizedFileURL
        let prefix = "receiptless-"
        let name = sourceURL.lastPathComponent
        guard sourceURL.path == source,
              sourceURL.deletingLastPathComponent() == recoveryDirectory,
              name.hasPrefix(prefix) else { return false }
        let identifier = String(name.dropFirst(prefix.count))
        guard let uuid = UUID(uuidString: identifier) else { return false }
        return identifier == uuid.uuidString.lowercased()
    }

    private static func isOwnedPrivateDirectory(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFDIR &&
            metadata.st_uid == geteuid() &&
            (metadata.st_mode & mode_t(0o7777)) == mode_t(0o700)
    }

    private static func isOwnedPrivateRegular(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFREG &&
            metadata.st_uid == geteuid() &&
            metadata.st_nlink == 1 &&
            (metadata.st_mode & mode_t(0o7777)) == mode_t(0o600)
    }

    private static func sameNode(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }

    private static func sameFileSnapshot(_ lhs: stat, _ rhs: stat) -> Bool {
        sameNode(lhs, rhs) &&
            lhs.st_size == rhs.st_size &&
            lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec &&
            lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec &&
            lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec &&
            lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func validPathComponent(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." &&
            !value.contains("/") && !value.contains("\0") &&
            value.utf8.count <= Int(NAME_MAX)
    }

    private func loadObjects(home: HomeCapability, deadline: UInt64) throws -> ObjectScan {
        try requireWithinDeadline(deadline)
        let attachments = try openOwnedDirectory(named: "attachments", beneath: home.homeDescriptor)
        var transfersAttachments = false
        defer { if !transfersAttachments { _ = Darwin.close(attachments.descriptor) } }
        let version = try openOwnedDirectory(named: "v1", beneath: attachments.descriptor)
        var transfersVersion = false
        defer { if !transfersVersion { _ = Darwin.close(version.descriptor) } }
        let versionEntries = try entryNames(in: version.descriptor, deadline: deadline)
        let allowed = Set(["objects", "tmp"])
        guard versionEntries.allSatisfy(allowed.contains) else {
            throw ValidationError.unsupported("The attachment store contains an unrecognised layout; nothing was deleted.")
        }
        if versionEntries.contains("tmp") {
            let temporary = try openOwnedDirectory(named: "tmp", beneath: version.descriptor)
            _ = Darwin.close(temporary.descriptor)
        }
        guard try childKind(named: "objects", beneath: version.descriptor) != .missing else {
            transfersAttachments = true
            transfersVersion = true
            return ObjectScan(
                store: ObjectStoreCapability(bindings: [
                    DirectoryBinding(
                        parentDescriptor: home.homeDescriptor,
                        descriptor: attachments.descriptor,
                        leafName: "attachments",
                        identity: NodeSnapshot(attachments.metadata)
                    ),
                    DirectoryBinding(
                        parentDescriptor: attachments.descriptor,
                        descriptor: version.descriptor,
                        leafName: "v1",
                        identity: NodeSnapshot(version.metadata)
                    )
                ]),
                objects: []
            )
        }
        let objects = try openOwnedDirectory(named: "objects", beneath: version.descriptor)
        transfersAttachments = true
        transfersVersion = true
        let store = ObjectStoreCapability(bindings: [
            DirectoryBinding(
                parentDescriptor: home.homeDescriptor,
                descriptor: attachments.descriptor,
                leafName: "attachments",
                identity: NodeSnapshot(attachments.metadata)
            ),
            DirectoryBinding(
                parentDescriptor: attachments.descriptor,
                descriptor: version.descriptor,
                leafName: "v1",
                identity: NodeSnapshot(version.metadata)
            ),
            DirectoryBinding(
                parentDescriptor: version.descriptor,
                descriptor: objects.descriptor,
                leafName: "objects",
                identity: NodeSnapshot(objects.metadata)
            )
        ])
        var result: [ObjectSnapshot] = []
        var aggregateBytes = 0
        for bucketName in try entryNames(in: objects.descriptor, deadline: deadline) {
            try requireWithinDeadline(deadline)
            guard bucketName.count == 2, Self.isLowercaseHex(bucketName) else {
                throw ValidationError.unsupported("The attachment object store contains an unrecognised bucket; nothing was deleted.")
            }
            let bucket = try openOwnedDirectory(named: bucketName, beneath: objects.descriptor)
            defer { _ = Darwin.close(bucket.descriptor) }
            let bucketSnapshot = NodeSnapshot(bucket.metadata)
            for name in try entryNames(in: bucket.descriptor, deadline: deadline) {
                try requireWithinDeadline(deadline)
                let file = try openOwnedRegularFile(named: name, beneath: bucket.descriptor)
                defer { _ = Darwin.close(file.descriptor) }
                let snapshot = NodeSnapshot(file.metadata)
                guard name.count == 64, name.hasPrefix(bucketName), Self.isLowercaseHex(name),
                      snapshot.size >= 0,
                      snapshot.size <= Int64(limits.maximumObjectBytes),
                      snapshot.size <= Int64(Int.max),
                      aggregateBytes <= limits.maximumAggregateObjectBytes - Int(snapshot.size),
                      result.count < limits.maximumObjects else {
                    throw ValidationError.unsupported("An attachment object could not be proven immutable and content-addressed; nothing was deleted.")
                }
                aggregateBytes += Int(snapshot.size)
                result.append(ObjectSnapshot(
                    bucketName: bucketName,
                    bucket: bucketSnapshot,
                    name: name,
                    file: snapshot,
                    digest: name,
                    size: Int(snapshot.size),
                    modified: snapshot.modificationDate
                ))
            }
            try requireDirectorySnapshot(bucketSnapshot, descriptor: bucket.descriptor)
        }
        try revalidateDirectoryBindings(store.bindings)
        return ObjectScan(store: store, objects: result)
    }

    private func loadReferences(home: HomeCapability, deadline: UInt64) throws -> ReferenceScan {
        try requireWithinDeadline(deadline)
        guard try childKind(named: "sessions", beneath: home.homeDescriptor) != .missing else {
            throw ValidationError.unsupported("Session history is unavailable, so attachment references cannot be proven.")
        }
        let sessions = try openOwnedDirectory(named: "sessions", beneath: home.homeDescriptor)
        let store = SessionStoreCapability(bindings: [DirectoryBinding(
            parentDescriptor: home.homeDescriptor,
            descriptor: sessions.descriptor,
            leafName: "sessions",
            identity: NodeSnapshot(sessions.metadata)
        )])
        var references = Set<String>()
        var snapshots: [SessionSnapshot] = []
        let projects = try entryNames(in: sessions.descriptor, deadline: deadline)
        guard projects.count <= limits.maximumProjects else {
            throw ValidationError.unsupported("Session history exceeds the bounded project scan; attachment cleanup was deferred.")
        }
        var aggregateLogBytes = 0
        var aggregateDecodedBytes = 0
        for projectName in projects {
            try requireWithinDeadline(deadline)
            let project = try openOwnedDirectory(named: projectName, beneath: sessions.descriptor)
            defer { _ = Darwin.close(project.descriptor) }
            let projectSnapshot = NodeSnapshot(project.metadata)
            for sessionName in try entryNames(in: project.descriptor, deadline: deadline) {
                try requireWithinDeadline(deadline)
                guard snapshots.count < limits.maximumSessions else {
                    throw ValidationError.unsupported("Session history exceeds the bounded session scan; attachment cleanup was deferred.")
                }
                let session = try openOwnedDirectory(named: sessionName, beneath: project.descriptor)
                defer { _ = Darwin.close(session.descriptor) }
                let sessionSnapshot = NodeSnapshot(session.metadata)
                let entries = try entryNames(in: session.descriptor, deadline: deadline)
                guard entries.count == 1, let logName = entries.first,
                      logName == "session.jsonl" || logName == "session.jsonl.zstd" else {
                    throw ValidationError.unsupported("A session uses an unrecognised persistence layout; nothing was deleted.")
                }
                let log = try openOwnedRegularFile(named: logName, beneath: session.descriptor)
                defer { _ = Darwin.close(log.descriptor) }
                let fileSnapshot = NodeSnapshot(log.metadata)
                guard fileSnapshot.size >= 0,
                      fileSnapshot.size <= Int64(limits.maximumLogBytes),
                      fileSnapshot.size <= Int64(Int.max),
                      aggregateLogBytes <= limits.maximumAggregateLogBytes - Int(fileSnapshot.size) else {
                    throw ValidationError.unsupported("A session log could not be verified; nothing was deleted.")
                }
                let size = Int(fileSnapshot.size)
                aggregateLogBytes += size
                let fileDigest: String
                if logName.hasSuffix(".zstd") {
                    if let injectedZstdReader {
                        let found = try injectedZstdReader(
                            URL(fileURLWithPath: "/dev/fd/\(log.descriptor)")
                        )
                        guard found.count <= limits.maximumReferences,
                              aggregateDecodedBytes <= limits.maximumDecodedBytes - size else {
                            throw ValidationError.unsupported("Compressed session history contains too many attachment references; nothing was deleted.")
                        }
                        references.formUnion(found)
                        aggregateDecodedBytes += size
                    } else {
                        let result = try readZstdReferences(
                            descriptor: log.descriptor,
                            home: home,
                            deadline: deadline
                        )
                        guard aggregateDecodedBytes <= limits.maximumDecodedBytes - result.decodedBytes else {
                            throw ValidationError.unsupported("Session history exceeds the bounded decoded-byte scan; attachment cleanup was deferred.")
                        }
                        aggregateDecodedBytes += result.decodedBytes
                        references.formUnion(result.references)
                    }
                    guard let digest = contentDigest(
                        descriptor: log.descriptor,
                        expected: fileSnapshot,
                        maximumBytes: limits.maximumLogBytes,
                        deadline: deadline
                    ) else {
                        throw ValidationError.unsupported("Compressed session history could not be fingerprinted; nothing was deleted.")
                    }
                    fileDigest = digest
                } else {
                    let result = try readJSONLReferences(
                        descriptor: log.descriptor,
                        expected: fileSnapshot,
                        deadline: deadline
                    )
                    references.formUnion(result.references)
                    fileDigest = result.digest
                    guard aggregateDecodedBytes <= limits.maximumDecodedBytes - size else {
                        throw ValidationError.unsupported("Session history exceeds the bounded decoded-byte scan; attachment cleanup was deferred.")
                    }
                    aggregateDecodedBytes += size
                }
                guard references.count <= limits.maximumReferences,
                      try currentSnapshot(of: log.descriptor) == fileSnapshot else {
                    throw ValidationError.unsupported("Session history changed during inspection; nothing was deleted.")
                }
                snapshots.append(SessionSnapshot(
                    projectName: projectName,
                    project: projectSnapshot,
                    sessionName: sessionName,
                    session: sessionSnapshot,
                    logName: logName,
                    file: fileSnapshot,
                    size: size,
                    modified: fileSnapshot.modificationDate,
                    digest: fileDigest
                ))
                try requireDirectorySnapshot(sessionSnapshot, descriptor: session.descriptor)
            }
            try requireDirectorySnapshot(projectSnapshot, descriptor: project.descriptor)
        }
        try revalidateDirectoryBindings(store.bindings)
        return ReferenceScan(store: store, references: references, snapshots: snapshots)
    }

    private func readJSONLReferences(
        descriptor: Int32,
        expected: NodeSnapshot,
        deadline: UInt64
    ) throws -> (references: Set<String>, digest: String) {
        var references = Set<String>()
        var hasher = SHA256()
        var buffer = Data()
        var cursor = 0
        var totalBytes = 0
        var offset: off_t = 0
        var readBuffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            try requireWithinDeadline(deadline)
            let count = readBuffer.withUnsafeMutableBytes { bytes in
                Darwin.pread(descriptor, bytes.baseAddress, bytes.count, offset)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw ValidationError.unsupported("A session log could not be read; nothing was deleted.")
            }
            let chunk = Data(readBuffer.prefix(count))
            guard totalBytes <= limits.maximumLogBytes - count else {
                throw ValidationError.unsupported("A session log exceeds the bounded byte scan; nothing was deleted.")
            }
            totalBytes += count
            offset += off_t(count)
            hasher.update(data: chunk)
            buffer.append(chunk)
            while cursor < buffer.count,
                  let newline = buffer[cursor...].firstIndex(of: 0x0A) {
                let row = Data(buffer[cursor..<newline])
                cursor = newline + 1
                guard row.count <= limits.maximumJSONLRowBytes,
                      let object = try? JSONSerialization.jsonObject(with: row) else {
                    throw ValidationError.unsupported("A session log contains an invalid or oversized JSONL row; nothing was deleted.")
                }
                try collectReferencesBounded(in: object, into: &references)
                if cursor >= 1 * 1_024 * 1_024 {
                    buffer.removeSubrange(0..<cursor)
                    cursor = 0
                }
            }
            guard buffer.count - cursor <= limits.maximumJSONLRowBytes else {
                throw ValidationError.unsupported("A session log contains an oversized JSONL row; nothing was deleted.")
            }
        }
        guard cursor == buffer.count else {
            throw ValidationError.unsupported("A session log is incomplete; nothing was deleted.")
        }
        guard totalBytes == expected.size,
              try currentSnapshot(of: descriptor) == expected else {
            throw ValidationError.unsupported("Session history changed during inspection; nothing was deleted.")
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return (references, digest)
    }

    private func readZstdReferences(
        descriptor inputDescriptor: Int32,
        home: HomeCapability,
        deadline: UInt64
    ) throws -> ZstdScanResult {
        try requireWithinDeadline(deadline)
        guard let trustedNode,
              fileManager.isExecutableFile(atPath: trustedNode.path),
              let nodeValues = try? trustedNode.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              nodeValues.isRegularFile == true, nodeValues.isSymbolicLink != true else {
            throw ValidationError.unsupported("Compressed session history cannot be verified with the bundled runtime; nothing was deleted.")
        }
        let sandboxExecutable = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        guard fileManager.isExecutableFile(atPath: sandboxExecutable.path) else {
            throw ValidationError.unsupported("Compressed session history isolation is unavailable; nothing was deleted.")
        }

        let temporaryName = "RetentionTemp"
        if try childKind(named: temporaryName, beneath: home.homeDescriptor) == .missing {
            guard mkdirat(home.homeDescriptor, temporaryName, mode_t(0o700)) == 0,
                  Darwin.fsync(home.homeDescriptor) == 0 else {
                throw ValidationError.unsupported("A private retention directory could not be created; nothing was deleted.")
            }
        }
        let temporary = try openOwnedDirectory(
            named: temporaryName,
            beneath: home.homeDescriptor,
            exactMode: 0o700
        )
        defer { _ = Darwin.close(temporary.descriptor) }
        let temporaryRoot = harnessHome.appendingPathComponent(temporaryName, isDirectory: true)
        let outputName = "zstd-\(UUID().uuidString).json"
        let outputDescriptor = outputName.withCString { name in
            openat(
                temporary.descriptor,
                name,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard outputDescriptor >= 0 else {
            throw ValidationError.unsupported("A private retention result could not be created; nothing was deleted.")
        }
        defer {
            _ = Darwin.close(outputDescriptor)
            _ = outputName.withCString { unlinkat(temporary.descriptor, $0, 0) }
        }
        let inputChildDescriptor = Darwin.dup(inputDescriptor)
        let outputChildDescriptor = Darwin.dup(outputDescriptor)
        guard inputChildDescriptor >= 0, outputChildDescriptor >= 0 else {
            if inputChildDescriptor >= 0 { _ = Darwin.close(inputChildDescriptor) }
            if outputChildDescriptor >= 0 { _ = Darwin.close(outputChildDescriptor) }
            throw ValidationError.unsupported("Compressed session history could not be inspected; nothing was deleted.")
        }
        let inputHandle = FileHandle(fileDescriptor: inputChildDescriptor, closeOnDealloc: true)
        let outputHandle = FileHandle(fileDescriptor: outputChildDescriptor, closeOnDealloc: true)
        defer {
            try? inputHandle.close()
            try? outputHandle.close()
        }

        let process = Process()
        process.executableURL = sandboxExecutable
        let sandboxProfile = zstdSandboxProfile(node: trustedNode, temporaryRoot: temporaryRoot)
        process.arguments = [
            "-p", sandboxProfile,
            trustedNode.path,
            "-e", Self.zstdReferenceScript,
            String(limits.maximumLogBytes),
            String(min(limits.maximumDecodedBytes, limits.maximumLogBytes)),
            String(limits.maximumReferences),
            String(limits.maximumJSONNodesPerRow),
            String(limits.maximumJSONLRowBytes)
        ]
        process.environment = [
            "HOME": temporaryRoot.path,
            "TMPDIR": temporaryRoot.path,
            "PATH": trustedNode.deletingLastPathComponent().path,
            "USER": NSUserName(),
            "LOGNAME": NSUserName(),
            "LANG": "en_US.UTF-8",
            "LC_CTYPE": "UTF-8"
        ]
        process.standardInput = inputHandle
        process.standardOutput = outputHandle
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            throw ValidationError.unsupported("Compressed session history could not be inspected; nothing was deleted.")
        }

        while process.isRunning, DispatchTime.now().uptimeNanoseconds < deadline {
            usleep(10_000)
        }
        if process.isRunning {
            process.terminate()
            let graceDeadline = try Self.monotonicDeadline(afterNanoseconds: 250_000_000)
            while process.isRunning, DispatchTime.now().uptimeNanoseconds < graceDeadline {
                usleep(10_000)
            }
            if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
        }
        // Foundation's blocking process wait pumps the current thread's run loop.
        // It has hung indefinitely in production after an async executor hop
        // even though the exact child was already dead. Reap only this PID and
        // keep the retention pass bounded. ECHILD is the benign race where
        // Foundation has already reaped the process.
        let reapDeadline = try Self.monotonicDeadline(afterNanoseconds: 2_000_000_000)
        var waitStatus: Int32 = 0
        var reapedStatus: Int32?
        while DispatchTime.now().uptimeNanoseconds < reapDeadline {
            let waited = Darwin.waitpid(process.processIdentifier, &waitStatus, WNOHANG)
            if waited == process.processIdentifier {
                reapedStatus = waitStatus
                break
            }
            if waited < 0 {
                if errno == EINTR { continue }
                if errno == ECHILD { break }
                break
            }
            Darwin.usleep(10_000)
        }
        let exitedSuccessfully: Bool
        if let reapedStatus {
            // Darwin wait status: a zero low signal field and zero exit byte
            // means a normal successful exit. Avoid the C-only wait macros.
            exitedSuccessfully = (reapedStatus & 0x7f) == 0
                && ((reapedStatus >> 8) & 0xff) == 0
        } else if !process.isRunning {
            exitedSuccessfully = process.terminationReason == .exit
                && process.terminationStatus == 0
        } else {
            exitedSuccessfully = false
        }
        try? outputHandle.close()
        guard exitedSuccessfully,
              let data = try? readBoundedRegularFile(
                descriptor: outputDescriptor,
                maximumBytes: limits.maximumChildResultBytes
              ),
              let result = try? JSONDecoder().decode(ZstdChildResult.self, from: data),
              result.decodedBytes >= 0,
              result.decodedBytes <= limits.maximumDecodedBytes,
              result.references.count <= limits.maximumReferences,
              result.references.allSatisfy({ $0.count == 64 && Self.isLowercaseHex($0) }) else {
            // Child stderr can contain private paths, hostile filenames, and
            // runtime diagnostics. It is intentionally never promoted into a
            // Privacy & Access status string.
            throw ValidationError.unsupported("Compressed session history is incomplete or invalid; nothing was deleted.")
        }
        return ZstdScanResult(references: Set(result.references), decodedBytes: result.decodedBytes)
    }

    private func requireWithinDeadline(_ deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else {
            throw ValidationError.unsupported("Attachment cleanup exceeded its bounded startup window and was deferred.")
        }
    }

    private static func monotonicDeadline(afterNanoseconds duration: UInt64) throws -> UInt64 {
        let (deadline, overflow) = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(duration)
        guard !overflow else {
            throw ValidationError.unsupported(
                "Attachment cleanup could not establish a bounded monotonic deadline and was deferred."
            )
        }
        return deadline
    }

    private func confirmSessionSnapshots(
        _ scan: ReferenceScan,
        deadline: UInt64
    ) throws -> Bool {
        try requireWithinDeadline(deadline)
        guard (try? revalidateDirectoryBindings(scan.store.bindings)) != nil else {
            return false
        }
        let expected = Dictionary(uniqueKeysWithValues: scan.snapshots.map { ($0.key, $0) })
        guard expected.count == scan.snapshots.count else { return false }
        let projects: [String]
        do { projects = try entryNames(in: scan.store.descriptor, deadline: deadline) }
        catch { return false }
        guard projects.count <= limits.maximumProjects else { return false }
        var seen = Set<String>()
        for projectName in projects {
            try requireWithinDeadline(deadline)
            guard let project = try? openOwnedDirectory(
                named: projectName,
                beneath: scan.store.descriptor
            ) else { return false }
            defer { _ = Darwin.close(project.descriptor) }
            let sessions: [String]
            do { sessions = try entryNames(in: project.descriptor, deadline: deadline) }
            catch { return false }
            for sessionName in sessions {
                try requireWithinDeadline(deadline)
                guard seen.count < limits.maximumSessions,
                      let session = try? openOwnedDirectory(
                        named: sessionName,
                        beneath: project.descriptor
                      ) else { return false }
                defer { _ = Darwin.close(session.descriptor) }
                let entries: [String]
                do { entries = try entryNames(in: session.descriptor, deadline: deadline) }
                catch { return false }
                guard entries.count == 1, let logName = entries.first,
                      logName == "session.jsonl" || logName == "session.jsonl.zstd" else {
                    return false
                }
                let key = "\(projectName)/\(sessionName)/\(logName)"
                guard let snapshot = expected[key], seen.insert(key).inserted,
                      NodeSnapshot(project.metadata) == snapshot.project,
                      NodeSnapshot(session.metadata) == snapshot.session,
                      let log = try? openOwnedRegularFile(
                        named: logName,
                        beneath: session.descriptor
                      ) else { return false }
                defer { _ = Darwin.close(log.descriptor) }
                guard NodeSnapshot(log.metadata) == snapshot.file,
                      contentDigest(
                        descriptor: log.descriptor,
                        expected: snapshot.file,
                        maximumBytes: limits.maximumLogBytes,
                        deadline: deadline
                      ) == snapshot.digest else {
                    return false
                }
            }
        }
        guard seen == Set(expected.keys),
              (try? revalidateDirectoryBindings(scan.store.bindings)) != nil else {
            return false
        }
        return true
    }

    private func quarantineAndDelete(
        _ candidate: ObjectSnapshot,
        objects: ObjectStoreCapability,
        home: HomeCapability,
        deadline: UInt64
    ) throws {
        try requireWithinDeadline(deadline)
        try revalidate(home)
        try revalidateDirectoryBindings(objects.bindings)
        let bucket = try openOwnedDirectory(
            named: candidate.bucketName,
            beneath: objects.descriptor
        )
        defer { _ = Darwin.close(bucket.descriptor) }
        guard NodeSnapshot(bucket.metadata) == candidate.bucket else {
            throw storageValidationFailure()
        }
        let file = try openOwnedRegularFile(named: candidate.name, beneath: bucket.descriptor)
        defer { _ = Darwin.close(file.descriptor) }
        guard NodeSnapshot(file.metadata) == candidate.file,
              contentDigest(
                descriptor: file.descriptor,
                expected: candidate.file,
                maximumBytes: limits.maximumObjectBytes,
                deadline: deadline
              ) == candidate.digest else {
            throw storageValidationFailure()
        }
        descriptorInspectionHook?(.beforeCandidateQuarantine)
        var installed = stat()
        guard candidate.name.withCString({
            fstatat(bucket.descriptor, $0, &installed, AT_SYMLINK_NOFOLLOW)
        }) == 0,
            NodeSnapshot(installed) == candidate.file else {
            throw storageValidationFailure()
        }

        let quarantineName = ".retention-\(UUID().uuidString.lowercased())"
        let renamed = candidate.name.withCString { source in
            quarantineName.withCString { destination in
                renameatx_np(
                    bucket.descriptor,
                    source,
                    bucket.descriptor,
                    destination,
                    UInt32(RENAME_EXCL)
                )
            }
        }
        guard renamed == 0 else { throw storageValidationFailure() }
        var unlinked = false
        do {
            guard Darwin.fsync(bucket.descriptor) == 0 else {
                throw storageValidationFailure()
            }
            let bucketAfterQuarantine = try currentSnapshot(of: bucket.descriptor)
            var quarantined = stat()
            var openedAfterQuarantine = stat()
            let quarantineInstalled = quarantineName.withCString {
                fstatat(bucket.descriptor, $0, &quarantined, AT_SYMLINK_NOFOLLOW)
            } == 0
            let openedAfterSnapshot: NodeSnapshot?
            if fstat(file.descriptor, &openedAfterQuarantine) == 0 {
                openedAfterSnapshot = NodeSnapshot(openedAfterQuarantine)
            } else {
                openedAfterSnapshot = nil
            }
            guard quarantineInstalled,
                  let openedAfterSnapshot,
                  openedAfterSnapshot == NodeSnapshot(quarantined),
                  candidate.file.sameFileAcrossRename(as: openedAfterQuarantine),
                  Self.isSafeOwnedRegular(openedAfterQuarantine),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(file.descriptor),
                  contentDigest(
                    descriptor: file.descriptor,
                    expected: openedAfterSnapshot,
                    maximumBytes: limits.maximumObjectBytes,
                    deadline: deadline
                  ) == candidate.digest else {
                throw storageValidationFailure()
            }
            descriptorInspectionHook?(.beforeCandidateUnlink)
            var final = stat()
            let finalMatches = quarantineName.withCString {
                fstatat(bucket.descriptor, $0, &final, AT_SYMLINK_NOFOLLOW)
            } == 0 && NodeSnapshot(final) == openedAfterSnapshot
            guard finalMatches,
                  try currentSnapshot(of: bucket.descriptor) == bucketAfterQuarantine else {
                throw storageValidationFailure()
            }
            try revalidate(home)
            guard quarantineName.withCString({ unlinkat(bucket.descriptor, $0, 0) }) == 0 else {
                throw storageValidationFailure()
            }
            unlinked = true
            guard Darwin.fsync(bucket.descriptor) == 0 else {
                throw storageValidationFailure()
            }
            try revalidate(home)
        } catch {
            if !unlinked {
                try? restoreQuarantine(
                    quarantineName,
                    originalName: candidate.name,
                    bucket: bucket.descriptor
                )
            }
            throw error
        }
    }

    private func restoreQuarantine(
        _ quarantineName: String,
        originalName: String,
        bucket: Int32
    ) throws {
        let status = quarantineName.withCString { source in
            originalName.withCString { destination in
                renameatx_np(bucket, source, bucket, destination, UInt32(RENAME_EXCL))
            }
        }
        guard status == 0, Darwin.fsync(bucket) == 0 else {
            throw storageValidationFailure()
        }
    }

    private func zstdSandboxProfile(node: URL, temporaryRoot: URL) -> String {
        let aliases: (URL) -> Set<String> = { item in
            var paths = Set([
                item.standardizedFileURL.path,
                item.resolvingSymlinksInPath().path
            ])
            if let canonical = Self.canonicalExistingPath(item) {
                // Preserve the realpath spelling. Foundation standardisation maps
                // /private/var back to /var, while Seatbelt evaluates both forms.
                paths.insert(canonical)
            }
            return paths
        }
        let nodePaths = aliases(node)
        let temporaryRoots = aliases(temporaryRoot)
        var literalReads = nodePaths.union(temporaryRoots)
        for path in Array(literalReads) {
            var cursor = (path as NSString).deletingLastPathComponent
            while cursor != "/" && !cursor.isEmpty {
                literalReads.insert(cursor)
                let parent = (cursor as NSString).deletingLastPathComponent
                guard parent != cursor else { break }
                cursor = parent
            }
        }
        let literals = literalReads.sorted().map { "(literal \(Self.seatbeltQuote($0)))" }.joined(separator: " ")
        let systemReads = ["/System", "/usr", "/bin", "/sbin", "/Library", "/private/etc", "/private/var/db", "/dev"]
            .map { "(subpath \(Self.seatbeltQuote($0)))" }
            .joined(separator: " ")
        let runtimeRoots = Set(nodePaths.map { ($0 as NSString).deletingLastPathComponent })
        let runtimeRead = runtimeRoots.sorted()
            .map { "(subpath \(Self.seatbeltQuote($0)))" }
            .joined(separator: " ")
        let temporaryReadRoots = temporaryRoots.sorted()
            .map { "(subpath \(Self.seatbeltQuote($0)))" }
            .joined(separator: " ")
        let writableRoots = temporaryRoots.sorted()
            .map { "(subpath \(Self.seatbeltQuote($0)))" }
            .joined(separator: " ")
        return [
            "(version 1)",
            "(allow default)",
            "(deny file-read*)",
            "(allow file-read-data (literal \(Self.seatbeltQuote("/"))))",
            "(allow file-read* \(systemReads) \(runtimeRead) \(temporaryReadRoots) \(literals))",
            "(deny file-write*)",
            "(allow file-write* (literal \(Self.seatbeltQuote("/dev/null"))) \(writableRoots))",
            "(deny network-outbound)",
            "(deny network-bind)",
            "(deny appleevent-send)",
            "(deny mach-lookup (global-name \"com.apple.SecurityServer\") (global-name \"com.apple.securityd\") (global-name \"com.apple.securityd.xpc\") (global-name \"com.apple.securityd.general\"))"
        ].joined(separator: "\n")
    }

    private static func seatbeltQuote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    private static func canonicalExistingPath(_ url: URL) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        return buffer.withUnsafeMutableBufferPointer { destination in
            url.path.withCString { source in
                guard let baseAddress = destination.baseAddress,
                      Darwin.realpath(source, baseAddress) != nil else { return nil }
                return String(cString: baseAddress)
            }
        }
    }

    private func storageValidationFailure() -> ValidationError {
        ValidationError.unsupported(
            "A retention store entry changed, is linked, or has unsafe ownership or permissions; nothing was deleted."
        )
    }

    private func childKind(named name: String, beneath parent: Int32) throws -> ChildKind {
        guard Self.validPathComponent(name) else { throw storageValidationFailure() }
        var metadata = stat()
        let status = name.withCString {
            fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        if status != 0 {
            if errno == ENOENT { return .missing }
            throw storageValidationFailure()
        }
        switch metadata.st_mode & S_IFMT {
        case S_IFDIR: return .directory
        case S_IFREG: return .regular
        case S_IFLNK: return .symbolicLink
        default: return .other
        }
    }

    private func openOwnedDirectory(
        named name: String,
        beneath parent: Int32,
        exactMode: mode_t? = nil
    ) throws -> (descriptor: Int32, metadata: stat) {
        guard Self.validPathComponent(name) else { throw storageValidationFailure() }
        var declared = stat()
        guard name.withCString({
            fstatat(parent, $0, &declared, AT_SYMLINK_NOFOLLOW)
        }) == 0,
            Self.isSafeOwnedDirectory(declared, exactMode: exactMode) else {
            throw storageValidationFailure()
        }
        let descriptor = name.withCString {
            openat(
                parent,
                $0,
                O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else { throw storageValidationFailure() }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              NodeSnapshot(opened) == NodeSnapshot(declared),
              Self.isSafeOwnedDirectory(opened, exactMode: exactMode),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            _ = Darwin.close(descriptor)
            throw storageValidationFailure()
        }
        return (descriptor, opened)
    }

    private func openOwnedRegularFile(
        named name: String,
        beneath parent: Int32
    ) throws -> (descriptor: Int32, metadata: stat) {
        guard Self.validPathComponent(name) else { throw storageValidationFailure() }
        var declared = stat()
        guard name.withCString({
            fstatat(parent, $0, &declared, AT_SYMLINK_NOFOLLOW)
        }) == 0,
            Self.isSafeOwnedRegular(declared) else {
            throw storageValidationFailure()
        }
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw storageValidationFailure() }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              NodeSnapshot(opened) == NodeSnapshot(declared),
              Self.isSafeOwnedRegular(opened),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            _ = Darwin.close(descriptor)
            throw storageValidationFailure()
        }
        return (descriptor, opened)
    }

    private func entryNames(in descriptor: Int32, deadline: UInt64) throws -> [String] {
        try requireWithinDeadline(deadline)
        let before = try currentSnapshot(of: descriptor)
        // dup(2) shares the directory offset with the retained capability.
        // Open "." beneath that exact descriptor so repeated proof scans use
        // independent open-file descriptions without reopening its pathname.
        let iteration = Darwin.openat(
            descriptor,
            ".",
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        var iterationMetadata = stat()
        guard iteration >= 0,
              fstat(iteration, &iterationMetadata) == 0,
              NodeSnapshot(iterationMetadata) == before,
              Self.isSafeOwnedDirectory(iterationMetadata, exactMode: nil),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(iteration),
              let stream = fdopendir(iteration) else {
            if iteration >= 0 { _ = Darwin.close(iteration) }
            throw storageValidationFailure()
        }
        defer { closedir(stream) }
        var result: [String] = []
        while true {
            try requireWithinDeadline(deadline)
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw storageValidationFailure() }
                break
            }
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw storageValidationFailure()
            }
            if name == "." || name == ".." { continue }
            guard Self.validPathComponent(name),
                  result.count < limits.maximumDirectoryEntries else {
                throw storageValidationFailure()
            }
            result.append(name)
        }
        guard try currentSnapshot(of: descriptor) == before else {
            throw storageValidationFailure()
        }
        return result.sorted()
    }

    private func currentSnapshot(of descriptor: Int32) throws -> NodeSnapshot {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw storageValidationFailure() }
        return NodeSnapshot(metadata)
    }

    private func requireDirectorySnapshot(
        _ expected: NodeSnapshot,
        descriptor: Int32
    ) throws {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              NodeSnapshot(metadata) == expected,
              Self.isSafeOwnedDirectory(metadata, exactMode: nil),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw storageValidationFailure()
        }
    }

    private func revalidateDirectoryBindings(_ bindings: [DirectoryBinding]) throws {
        guard !bindings.isEmpty else { throw storageValidationFailure() }
        for binding in bindings {
            var opened = stat()
            var installed = stat()
            guard fstat(binding.descriptor, &opened) == 0,
                  NodeSnapshot(opened) == binding.identity,
                  Self.isSafeOwnedDirectory(opened, exactMode: nil),
                  CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(binding.descriptor),
                  binding.leafName.withCString({
                    fstatat(binding.parentDescriptor, $0, &installed, AT_SYMLINK_NOFOLLOW)
                  }) == 0,
                  NodeSnapshot(installed) == binding.identity,
                  Self.isSafeOwnedDirectory(installed, exactMode: nil) else {
                throw storageValidationFailure()
            }
        }
    }

    private func revalidate(_ home: HomeCapability) throws {
        let failure = storageValidationFailure()
        var parent = stat()
        var openedHome = stat()
        var installedHome = stat()
        guard fstat(home.parentDescriptor, &parent) == 0,
              home.parent.sameNode(as: parent),
              Self.isOwnedPrivateDirectory(parent),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.parentDescriptor),
              fstat(home.homeDescriptor, &openedHome) == 0,
              home.home.sameNode(as: openedHome),
              Self.isOwnedPrivateDirectory(openedHome),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(home.homeDescriptor),
              home.homeName.withCString({
                fstatat(home.parentDescriptor, $0, &installedHome, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              home.home.sameNode(as: installedHome),
              Self.isOwnedPrivateDirectory(installedHome) else {
            throw failure
        }
        let receipt = try openOwnedRegularFile(
            named: Self.ownershipReceiptName,
            beneath: home.homeDescriptor
        )
        defer { _ = Darwin.close(receipt.descriptor) }
        guard NodeSnapshot(receipt.metadata) == home.receipt,
              let bytes = try? readBoundedRegularFile(
                descriptor: receipt.descriptor,
                maximumBytes: Self.maximumOwnershipReceiptBytes
              ),
              bytes == home.receiptBytes else {
            throw failure
        }
        if let record = home.attestationRecord {
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            guard record.canonicalPath == harnessHome.standardizedFileURL.path,
                  record.leafName == home.homeName,
                  record.device == UInt64(truncatingIfNeeded: openedHome.st_dev),
                  record.inode == UInt64(truncatingIfNeeded: openedHome.st_ino),
                  record.owner == openedHome.st_uid,
                  record.mode == UInt16(openedHome.st_mode & mode_t(0o7777)),
                  record.privacyEpoch == UInt64(ProviderHistoryPrivacyEpoch.current),
                  record.receiptSHA256 == digest else {
                throw failure
            }
        } else if !allowUnattestedHarnessHomeForTesting {
            throw failure
        }
        do {
            try harnessHomeReceiptVerifier?(harnessHome, home.homeDescriptor, bytes)
        } catch {
            throw failure
        }
    }

    private func readBoundedRegularFile(
        descriptor: Int32,
        maximumBytes: Int
    ) throws -> Data {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              Self.isSafeOwnedRegular(metadata),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw storageValidationFailure()
        }
        let before = NodeSnapshot(metadata)
        guard before.size >= 0,
              before.size <= Int64(maximumBytes),
              before.size <= Int64(Int.max) else {
            throw storageValidationFailure()
        }
        var result = Data()
        result.reserveCapacity(Int(before.size))
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: min(64 * 1_024, max(1, maximumBytes + 1)))
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.pread(descriptor, $0.baseAddress, $0.count, offset)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw storageValidationFailure()
            }
            guard count <= maximumBytes - result.count else {
                throw storageValidationFailure()
            }
            result.append(contentsOf: buffer.prefix(count))
            offset += off_t(count)
        }
        guard result.count == Int(before.size),
              try currentSnapshot(of: descriptor) == before else {
            throw storageValidationFailure()
        }
        return result
    }

    private func contentDigest(
        descriptor: Int32,
        expected: NodeSnapshot,
        maximumBytes: Int,
        deadline: UInt64? = nil
    ) -> String? {
        guard expected.size >= 0, expected.size <= Int64(maximumBytes) else { return nil }
        var hasher = SHA256()
        var received = 0
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            if let deadline, DispatchTime.now().uptimeNanoseconds >= deadline { return nil }
            let count = buffer.withUnsafeMutableBytes {
                Darwin.pread(descriptor, $0.baseAddress, $0.count, offset)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            guard received <= maximumBytes - count else { return nil }
            let chunk = Data(buffer.prefix(count))
            received += count
            offset += off_t(count)
            hasher.update(data: chunk)
        }
        guard received == expected.size,
              (try? currentSnapshot(of: descriptor)) == expected else { return nil }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func isSafeOwnedDirectory(_ metadata: stat, exactMode: mode_t?) -> Bool {
        guard (metadata.st_mode & S_IFMT) == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & mode_t(S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0 else {
            return false
        }
        return exactMode == nil || metadata.st_mode & mode_t(0o7777) == exactMode
    }

    private static func isSafeOwnedRegular(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_size >= 0
            && metadata.st_mode & mode_t(S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0
    }

    private func collectReferencesBounded(in value: Any, into result: inout Set<String>) throws {
        guard let referenceExpression = Self.referenceExpression else {
            throw ValidationError.unsupported("Attachment reference validation is unavailable; nothing was deleted.")
        }
        var stack: [Any] = [value]
        var visited = 0
        while let current = stack.popLast() {
            visited += 1
            guard visited <= limits.maximumJSONNodesPerRow else {
                throw ValidationError.unsupported("A session history row is too structurally complex; nothing was deleted.")
            }
            if let string = current as? String {
                let range = NSRange(string.startIndex..<string.endIndex, in: string)
                for match in referenceExpression.matches(in: string, range: range) {
                    if let digestRange = Range(match.range(at: 1), in: string) {
                        result.insert(String(string[digestRange]))
                        guard result.count <= limits.maximumReferences else {
                            throw ValidationError.unsupported("Session history contains too many attachment references; nothing was deleted.")
                        }
                    }
                }
            } else if let array = current as? [Any] {
                stack.append(contentsOf: array)
            } else if let dictionary = current as? [String: Any] {
                for (key, child) in dictionary {
                    stack.append(key)
                    stack.append(child)
                }
            }
        }
    }

    private static func isLowercaseHex(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
    }

    private static let referenceExpression = try? NSRegularExpression(
        pattern: #"sha256:([a-f0-9]{64})"#
    )

    private static let zstdReferenceScript = #"""
const fs = require('node:fs');
const { zstdDecompressSync } = require('node:zlib');
const { TextDecoder } = require('node:util');
const [compressedText, decodedText, referenceText, nodeText, rowText] = process.argv.slice(1);
const maximumCompressed = Number(compressedText);
const maximumDecoded = Number(decodedText);
const maximumReferences = Number(referenceText);
const maximumNodes = Number(nodeText);
const maximumRow = Number(rowText);
if (![maximumCompressed, maximumDecoded, maximumReferences, maximumNodes, maximumRow]
    .every((value) => Number.isSafeInteger(value) && value > 0)) throw new Error('invalid limits');
const before = fs.fstatSync(0, { bigint: true });
if (!before.isFile() || before.size > BigInt(maximumCompressed)) throw new Error('unsupported size');
const buffer = fs.readFileSync(0);
const after = fs.fstatSync(0, { bigint: true });
if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) throw new Error('changed');
const frames = [];
let offset = 0;
while (offset < buffer.length) {
  const start = offset;
  if (buffer.length - offset < 5 || buffer.readUInt32LE(offset) !== 4247762216) throw new Error('invalid frame');
  offset += 4;
  const descriptor = buffer.readUInt8(offset++);
  if ((descriptor & 24) !== 0) throw new Error('invalid header');
  const contentSizeFlag = descriptor >>> 6;
  const singleSegment = (descriptor & 32) !== 0;
  const checksum = (descriptor & 4) !== 0;
  const dictionaryFlag = descriptor & 3;
  const dictionaryBytes = dictionaryFlag === 3 ? 4 : dictionaryFlag;
  const contentSizeBytes = contentSizeFlag === 0 ? (singleSegment ? 1 : 0) : (1 << contentSizeFlag);
  const headerBytes = (singleSegment ? 0 : 1) + dictionaryBytes + contentSizeBytes;
  if (buffer.length - offset < headerBytes) throw new Error('torn header');
  offset += headerBytes;
  for (;;) {
    if (buffer.length - offset < 3) throw new Error('torn block');
    const header = buffer.readUIntLE(offset, 3); offset += 3;
    const last = (header & 1) !== 0;
    const type = (header >>> 1) & 3;
    const size = header >>> 3;
    if (type === 3) throw new Error('reserved block');
    const payload = type === 1 ? 1 : size;
    if (buffer.length - offset < payload) throw new Error('torn payload');
    offset += payload;
    if (last) break;
  }
  if (checksum) { if (buffer.length - offset < 4) throw new Error('torn checksum'); offset += 4; }
  frames.push([start, offset]);
  if (frames.length > 10000) throw new Error('too many frames');
}
if (frames.length === 0) throw new Error('empty');
const chunks = [];
let decodedBytes = 0;
for (const [start, end] of frames) {
  const remaining = maximumDecoded - decodedBytes;
  if (remaining <= 0) throw new Error('expanded size');
  const chunk = zstdDecompressSync(buffer.subarray(start, end), { maxOutputLength: remaining });
  decodedBytes += chunk.length;
  if (decodedBytes > maximumDecoded) throw new Error('expanded size');
  chunks.push(chunk);
}
const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
if (text.length && !text.endsWith('\n')) throw new Error('incomplete jsonl');
const refs = new Set();
const pattern = /sha256:([a-f0-9]{64})/g;
function walk(value) {
  const stack = [value];
  let nodes = 0;
  while (stack.length) {
    const current = stack.pop();
    if (++nodes > maximumNodes) throw new Error('too many nodes');
    if (typeof current === 'string') {
      for (const match of current.matchAll(pattern)) {
        refs.add(match[1]);
        if (refs.size > maximumReferences) throw new Error('too many references');
      }
    } else if (Array.isArray(current)) {
      for (const child of current) stack.push(child);
    } else if (current && typeof current === 'object') {
      for (const [key, child] of Object.entries(current)) { stack.push(key, child); }
    }
  }
}
for (const line of text.split('\n')) {
  if (!line) continue;
  if (Buffer.byteLength(line, 'utf8') > maximumRow) throw new Error('oversized row');
  walk(JSON.parse(line));
}
process.stdout.write(JSON.stringify({ decodedBytes, references: [...refs].sort() }));
"""#
}

struct PrivacyMaintenanceReport: Equatable {
    let ranAt: Date
    let appshots: AppshotPurgeResult
    let ledger: PrivacyLedgerPurgeResult
    let attachments: AttachmentRetentionReport
}

final class PrivacyMaintenanceCoordinator: @unchecked Sendable {
    private let runLock = NSLock()
    private let reportLock = NSLock()
    private let appshots: AppshotController
    private let ledger: PrivacyLedger
    private let attachments: AttachmentRetentionManager
    private let preferences: PreferencesStore
    private let canPurgeAttachments: () -> Bool
    private var storedLastReport: PrivacyMaintenanceReport?

    init(
        appshots: AppshotController,
        ledger: PrivacyLedger,
        attachments: AttachmentRetentionManager,
        preferences: PreferencesStore,
        canPurgeAttachments: @escaping () -> Bool
    ) {
        self.appshots = appshots
        self.ledger = ledger
        self.attachments = attachments
        self.preferences = preferences
        self.canPurgeAttachments = canPurgeAttachments
    }

    func run(now: Date = Date(), includeAttachments: Bool) -> PrivacyMaintenanceReport {
        runLock.lock()
        defer { runLock.unlock() }
        let appshotResult = appshots.purgeExpiredCaptures(now: now)
        let ledgerResult: PrivacyLedgerPurgeResult
        do {
            ledgerResult = try ledger.purgeExpired(now: now)
        } catch {
            ledgerResult = PrivacyLedgerPurgeResult(failure: "Privacy Ledger retention could not complete.")
        }
        let attachmentResult: AttachmentRetentionReport
        if !includeAttachments {
            attachmentResult = AttachmentRetentionReport(status: .deferred("Attachment cleanup runs only while Harness is stopped."))
        } else if !canPurgeAttachments() {
            attachmentResult = AttachmentRetentionReport(status: .deferred("Stop Harness before purging attachments."))
        } else {
            attachmentResult = attachments.purgeExpired(retentionDays: preferences.attachmentRetentionDays, now: now)
        }
        let report = PrivacyMaintenanceReport(ranAt: now, appshots: appshotResult, ledger: ledgerResult, attachments: attachmentResult)
        reportLock.lock()
        storedLastReport = report
        reportLock.unlock()
        return report
    }

    func lastReport() -> PrivacyMaintenanceReport? {
        reportLock.lock()
        defer { reportLock.unlock() }
        return storedLastReport
    }
}
