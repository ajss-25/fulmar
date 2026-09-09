import Darwin
import Foundation

enum ActivityStoreLimits {
    static let maximumActivities = 500
    static let maximumDocumentBytes = 4 * 1_024 * 1_024
    static let maximumTitleBytes = 512
    static let maximumDetailBytes = 16 * 1_024
}

enum ActivityStoreFailure: Error, Equatable, Sendable, LocalizedError {
    case unsafeStorage
    case oversizedDocument
    case malformedDocument
    case invalidRecord
    case persistenceFailed

    var errorDescription: String? {
        switch self {
        case .unsafeStorage:
            return "Activity history is not private or has an unsafe filesystem identity."
        case .oversizedDocument:
            return "Activity history exceeds its four-megabyte storage limit."
        case .malformedDocument:
            return "Activity history is not a valid \(ProductBrand.displayName) activity document."
        case .invalidRecord:
            return "Activity history contains an invalid or unbounded record."
        case .persistenceFailed:
            return "Activity history could not be saved privately and atomically."
        }
    }
}

enum ActivityStoreStatus: Equatable, Sendable {
    case available
    case unavailable(ActivityStoreFailure)

    var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

enum ActivityStoreError: Error, Equatable, LocalizedError {
    case unavailable(ActivityStoreFailure)

    var errorDescription: String? {
        switch self {
        case .unavailable(let failure):
            return failure.localizedDescription
        }
    }
}

enum ActivityStorePersistenceStage: Equatable, Sendable {
    case beforeWrite
    case beforeRename
    case afterRename
    case beforeDirectorySync
}

private enum ActivityStorePersistenceOutcome {
    case durable
    case committedButDurabilityUnverified
}

private struct ActivityStoreDocumentIdentity: Equatable {
    let device: UInt64
    let inode: UInt64

    init(_ metadata: stat) {
        device = UInt64(truncatingIfNeeded: metadata.st_dev)
        inode = UInt64(metadata.st_ino)
    }
}

private enum ActivityStoreDocumentState: Equatable {
    case absent
    case present(ActivityStoreDocumentIdentity)
}

private struct ActivityStorePersistenceResult {
    let outcome: ActivityStorePersistenceOutcome
    let documentState: ActivityStoreDocumentState
}

struct LocalActivity: Codable, Equatable, Identifiable {
    enum Kind: String, Codable { case runtime, chat, model, appshot, artifact, schedule, browser, backup, plugin }
    enum State: String, Codable { case queued, running, waiting, completed, failed, cancelled }

    let id: UUID
    let kind: Kind
    var title: String
    var detail: String
    var state: State
    let createdAt: Date
    var updatedAt: Date
    var progress: Double?
}

/// A bounded, owner-only activity document.
///
/// Mutations use copy-on-write semantics: the in-memory snapshot and its UI
/// observer are updated only after the replacement document is durably written
/// and atomically renamed. A hostile or unavailable store is never silently
/// treated as ordinary empty history and is never overwritten.
final class ActivityStore {
    var onChange: (([LocalActivity]) -> Void)?
    var onStatusChange: ((ActivityStoreStatus) -> Void)?

    private static let directoryName = "Activity"
    private static let documentName = "activities.json"

    private let queue = DispatchQueue(label: "app.localharness.activity-store")
    private let directoryCapability: RetainedPrivateDirectoryCapability?
    private let persistenceFailureInjector: ((ActivityStorePersistenceStage) throws -> Void)?
    private var activities: [LocalActivity] = []
    private var statusValue: ActivityStoreStatus = .available
    private var documentState: ActivityStoreDocumentState = .absent

    init(
        applicationSupport: URL,
        persistenceFailureInjector: ((ActivityStorePersistenceStage) throws -> Void)? = nil
    ) {
        let directoryURL = applicationSupport.appendingPathComponent(Self.directoryName, isDirectory: true)
        self.persistenceFailureInjector = persistenceFailureInjector

        let capability = try? RetainedPrivateDirectoryCapability(
            directoryURL: directoryURL,
            createIfMissing: true
        )
        directoryCapability = capability
        guard let capability else {
            statusValue = .unavailable(.unsafeStorage)
            return
        }

        do {
            let loaded = try Self.load(using: capability)
            activities = loaded.activities
            documentState = loaded.documentState
            let interrupted = loaded.activities.map { activity -> LocalActivity in
                guard activity.state == .running else { return activity }
                var recovered = activity
                recovered.state = .failed
                recovered.detail = "Interrupted when \(ProductBrand.displayName) last stopped."
                recovered.updatedAt = Date()
                return recovered
            }
            if interrupted != loaded.activities {
                let prepared = try Self.prepareForPersistence(interrupted)
                let result = try Self.persist(
                    prepared.data,
                    using: capability,
                    expectedDocumentState: documentState,
                    failureInjector: persistenceFailureInjector
                )
                activities = prepared.activities
                documentState = result.documentState
                if result.outcome == .committedButDurabilityUnverified {
                    statusValue = .unavailable(.persistenceFailed)
                }
            } else {
                activities = loaded.activities
            }
        } catch let failure as ActivityStoreFailure {
            statusValue = .unavailable(failure)
        } catch {
            statusValue = .unavailable(.persistenceFailed)
        }
    }

    @discardableResult
    func begin(_ kind: LocalActivity.Kind, title: String, detail: String = "") -> UUID {
        let activity = LocalActivity(
            id: UUID(),
            kind: kind,
            title: Self.boundedUTF8(title, maximumBytes: ActivityStoreLimits.maximumTitleBytes),
            detail: Self.boundedUTF8(detail, maximumBytes: ActivityStoreLimits.maximumDetailBytes),
            state: .running,
            createdAt: Date(),
            updatedAt: Date(),
            progress: nil
        )
        mutate { $0.insert(activity, at: 0) }
        return activity.id
    }

    func update(_ id: UUID, state: LocalActivity.State, detail: String? = nil, progress: Double? = nil) {
        let boundedDetail = detail.map {
            Self.boundedUTF8($0, maximumBytes: ActivityStoreLimits.maximumDetailBytes)
        }
        let boundedProgress = progress.flatMap { value -> Double? in
            guard value.isFinite else { return nil }
            return min(1, max(0, value))
        }
        mutate { activities in
            guard let index = activities.firstIndex(where: { $0.id == id }) else { return }
            activities[index].state = state
            if let boundedDetail { activities[index].detail = boundedDetail }
            activities[index].progress = boundedProgress
            activities[index].updatedAt = Date()
        }
    }

    func addCompleted(_ kind: LocalActivity.Kind, title: String, detail: String = "") {
        let now = Date()
        let activity = LocalActivity(
            id: UUID(),
            kind: kind,
            title: Self.boundedUTF8(title, maximumBytes: ActivityStoreLimits.maximumTitleBytes),
            detail: Self.boundedUTF8(detail, maximumBytes: ActivityStoreLimits.maximumDetailBytes),
            state: .completed,
            createdAt: now,
            updatedAt: now,
            progress: 1
        )
        mutate { $0.insert(activity, at: 0) }
    }

    /// A headless launch may terminate immediately after recording a blocked
    /// migration. This method returns only after an owner-only document has
    /// been fsynced and atomically replaced. A failure before rename preserves
    /// the prior bytes and snapshot. If rename commits but final directory
    /// durability cannot be verified, the observable committed snapshot is
    /// adopted and the store becomes unavailable rather than reporting stale
    /// in-memory state as authoritative.
    @discardableResult
    func addWaitingSynchronously(
        _ kind: LocalActivity.Kind,
        title: String,
        detail: String = ""
    ) throws -> UUID {
        let now = Date()
        let activity = LocalActivity(
            id: UUID(),
            kind: kind,
            title: Self.boundedUTF8(title, maximumBytes: ActivityStoreLimits.maximumTitleBytes),
            detail: Self.boundedUTF8(detail, maximumBytes: ActivityStoreLimits.maximumDetailBytes),
            state: .waiting,
            createdAt: now,
            updatedAt: now,
            progress: nil
        )
        let snapshot: [LocalActivity] = try queue.sync {
            guard case .available = statusValue else {
                throw ActivityStoreError.unavailable(statusValue.failure ?? .persistenceFailed)
            }
            guard let directoryCapability else {
                transitionToUnavailable(.unsafeStorage)
                throw ActivityStoreError.unavailable(.unsafeStorage)
            }
            var updated = activities
            updated.insert(activity, at: 0)
            do {
                let prepared = try Self.prepareForPersistence(updated)
                let result = try Self.persist(
                    prepared.data,
                    using: directoryCapability,
                    expectedDocumentState: documentState,
                    failureInjector: persistenceFailureInjector
                )
                activities = prepared.activities
                documentState = result.documentState
                if result.outcome == .committedButDurabilityUnverified {
                    publish(prepared.activities)
                    transitionToUnavailable(.persistenceFailed)
                    throw ActivityStoreError.unavailable(.persistenceFailed)
                }
                return prepared.activities
            } catch let failure as ActivityStoreFailure {
                transitionToUnavailable(failure)
                throw ActivityStoreError.unavailable(failure)
            } catch {
                transitionToUnavailable(.persistenceFailed)
                throw ActivityStoreError.unavailable(.persistenceFailed)
            }
        }
        publish(snapshot)
        return activity.id
    }

    func snapshot() -> [LocalActivity] { queue.sync { activities } }

    func status() -> ActivityStoreStatus { queue.sync { statusValue } }

    func clearFinished() {
        mutate { $0.removeAll { [.completed, .failed, .cancelled].contains($0.state) } }
    }

    private func mutate(_ body: @escaping (inout [LocalActivity]) -> Void) {
        queue.async { [weak self] in
            guard let self, case .available = self.statusValue else { return }
            guard let directoryCapability = self.directoryCapability else {
                self.transitionToUnavailable(.unsafeStorage)
                return
            }
            var updated = self.activities
            body(&updated)
            do {
                let prepared = try Self.prepareForPersistence(updated)
                let result = try Self.persist(
                    prepared.data,
                    using: directoryCapability,
                    expectedDocumentState: self.documentState,
                    failureInjector: self.persistenceFailureInjector
                )
                self.activities = prepared.activities
                self.documentState = result.documentState
                self.publish(prepared.activities)
                if result.outcome == .committedButDurabilityUnverified {
                    self.transitionToUnavailable(.persistenceFailed)
                }
            } catch let failure as ActivityStoreFailure {
                self.transitionToUnavailable(failure)
            } catch {
                self.transitionToUnavailable(.persistenceFailed)
            }
        }
    }

    private func publish(_ snapshot: [LocalActivity]) {
        DispatchQueue.main.async { [weak self] in
            self?.onChange?(snapshot)
        }
    }

    private func transitionToUnavailable(_ failure: ActivityStoreFailure) {
        let status: ActivityStoreStatus = .unavailable(failure)
        guard statusValue != status else { return }
        statusValue = status
        DispatchQueue.main.async { [weak self] in
            self?.onStatusChange?(status)
        }
    }

    private static func load(
        using capability: RetainedPrivateDirectoryCapability
    ) throws -> (activities: [LocalActivity], documentState: ActivityStoreDocumentState) {
        do {
            return try capability.withValidatedDescriptor { directoryDescriptor in
                let descriptor = documentName.withCString { name in
                    openat(
                        directoryDescriptor,
                        name,
                        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                }
                if descriptor < 0 {
                    if errno == ENOENT { return ([], .absent) }
                    throw ActivityStoreFailure.unsafeStorage
                }
                defer { _ = Darwin.close(descriptor) }

                var metadata = stat()
                guard fstat(descriptor, &metadata) == 0,
                      isPrivateRegularDocument(metadata),
                      CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor)
                else {
                    throw ActivityStoreFailure.unsafeStorage
                }
                guard metadata.st_size >= 0,
                      UInt64(metadata.st_size) <= UInt64(ActivityStoreLimits.maximumDocumentBytes)
                else {
                    throw ActivityStoreFailure.oversizedDocument
                }

                var data = Data()
                data.reserveCapacity(Int(metadata.st_size))
                var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
                while data.count <= ActivityStoreLimits.maximumDocumentBytes {
                    let remaining = ActivityStoreLimits.maximumDocumentBytes + 1 - data.count
                    let requested = min(buffer.count, remaining)
                    let count = Darwin.read(descriptor, &buffer, requested)
                    if count > 0 {
                        data.append(buffer, count: count)
                        continue
                    }
                    if count == 0 { break }
                    if errno == EINTR { continue }
                    throw ActivityStoreFailure.unsafeStorage
                }
                guard data.count <= ActivityStoreLimits.maximumDocumentBytes else {
                    throw ActivityStoreFailure.oversizedDocument
                }
                guard !data.isEmpty else { throw ActivityStoreFailure.malformedDocument }

                var after = stat()
                guard fstat(descriptor, &after) == 0,
                      ActivityStoreDocumentIdentity(after) == ActivityStoreDocumentIdentity(metadata),
                      after.st_size == metadata.st_size,
                      after.st_mtimespec.tv_sec == metadata.st_mtimespec.tv_sec,
                      after.st_mtimespec.tv_nsec == metadata.st_mtimespec.tv_nsec else {
                    throw ActivityStoreFailure.unsafeStorage
                }
                try requireExpectedDestination(
                    .present(ActivityStoreDocumentIdentity(metadata)),
                    in: directoryDescriptor
                )

                let decoded: [LocalActivity]
                do {
                    decoded = try JSONDecoder().decode([LocalActivity].self, from: data)
                } catch {
                    throw ActivityStoreFailure.malformedDocument
                }
                try validate(decoded, requireMaximumCount: true)
                return (
                    decoded.sorted { $0.updatedAt > $1.updatedAt },
                    .present(ActivityStoreDocumentIdentity(metadata))
                )
            }
        } catch is RetainedPrivateDirectoryCapabilityError {
            throw ActivityStoreFailure.unsafeStorage
        }
    }

    private static func prepareForPersistence(
        _ candidates: [LocalActivity]
    ) throws -> (activities: [LocalActivity], data: Data) {
        var retained = Array(
            candidates.sorted { $0.updatedAt > $1.updatedAt }
                .prefix(ActivityStoreLimits.maximumActivities)
        )
        try validate(retained, requireMaximumCount: true)

        let encoder = JSONEncoder()
        var data = try encoder.encode(retained)
        while data.count > ActivityStoreLimits.maximumDocumentBytes, retained.count > 1 {
            retained.removeLast()
            data = try encoder.encode(retained)
        }
        guard data.count <= ActivityStoreLimits.maximumDocumentBytes else {
            throw ActivityStoreFailure.oversizedDocument
        }
        return (retained, data)
    }

    private static func validate(
        _ candidates: [LocalActivity],
        requireMaximumCount: Bool
    ) throws {
        if requireMaximumCount, candidates.count > ActivityStoreLimits.maximumActivities {
            throw ActivityStoreFailure.invalidRecord
        }
        var identifiers = Set<UUID>()
        for activity in candidates {
            guard identifiers.insert(activity.id).inserted,
                  activity.title.utf8.count <= ActivityStoreLimits.maximumTitleBytes,
                  activity.detail.utf8.count <= ActivityStoreLimits.maximumDetailBytes,
                  activity.createdAt.timeIntervalSinceReferenceDate.isFinite,
                  activity.updatedAt.timeIntervalSinceReferenceDate.isFinite
            else {
                throw ActivityStoreFailure.invalidRecord
            }
            if let progress = activity.progress,
               (!progress.isFinite || progress < 0 || progress > 1) {
                throw ActivityStoreFailure.invalidRecord
            }
        }
    }

    private static func persist(
        _ data: Data,
        using capability: RetainedPrivateDirectoryCapability,
        expectedDocumentState: ActivityStoreDocumentState,
        failureInjector: ((ActivityStorePersistenceStage) throws -> Void)?
    ) throws -> ActivityStorePersistenceResult {
        guard data.count <= ActivityStoreLimits.maximumDocumentBytes else {
            throw ActivityStoreFailure.oversizedDocument
        }
        do {
            return try capability.withValidatedDescriptor { directoryDescriptor in
                try requireExpectedDestination(expectedDocumentState, in: directoryDescriptor)

                let temporaryName = ".activities.\(UUID().uuidString).tmp"
                let descriptor = temporaryName.withCString { name in
                    openat(
                        directoryDescriptor,
                        name,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        mode_t(S_IRUSR | S_IWUSR)
                    )
                }
                guard descriptor >= 0 else { throw ActivityStoreFailure.persistenceFailed }
                var temporaryExists = true
                defer {
                    _ = Darwin.close(descriptor)
                    if temporaryExists {
                        temporaryName.withCString { name in _ = unlinkat(directoryDescriptor, name, 0) }
                    }
                }

                do {
                    try failureInjector?(.beforeWrite)
                    try writeAll(data, to: descriptor)
                    guard fsync(descriptor) == 0 else { throw ActivityStoreFailure.persistenceFailed }

                    var staged = stat()
                    guard fstat(descriptor, &staged) == 0,
                          isPrivateRegularDocument(staged),
                          CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor)
                    else {
                        throw ActivityStoreFailure.persistenceFailed
                    }

                    try failureInjector?(.beforeRename)
                    try requireExpectedDestination(expectedDocumentState, in: directoryDescriptor)
                    let renamed = temporaryName.withCString { temporary in
                        documentName.withCString { destination in
                            renameat(directoryDescriptor, temporary, directoryDescriptor, destination)
                        }
                    }
                    guard renamed == 0 else { throw ActivityStoreFailure.persistenceFailed }
                    temporaryExists = false

                    do {
                        try failureInjector?(.afterRename)
                        let persistedState = try requirePersistedIdentity(
                            staged,
                            in: directoryDescriptor
                        )
                        try failureInjector?(.beforeDirectorySync)
                        guard fsync(directoryDescriptor) == 0 else {
                            throw ActivityStoreFailure.persistenceFailed
                        }
                        return ActivityStorePersistenceResult(
                            outcome: .durable,
                            documentState: persistedState
                        )
                    } catch {
                        // The namespace mutation has already committed. When the
                        // destination still names the exact staged inode, callers must
                        // adopt the new snapshot and expose unavailable durability;
                        // retaining the old in-memory snapshot would be false state.
                        if let persistedState = try? requirePersistedIdentity(
                            staged,
                            in: directoryDescriptor
                        ) {
                            return ActivityStorePersistenceResult(
                                outcome: .committedButDurabilityUnverified,
                                documentState: persistedState
                            )
                        }
                        throw ActivityStoreFailure.persistenceFailed
                    }
                } catch let failure as ActivityStoreFailure {
                    throw failure
                } catch {
                    throw ActivityStoreFailure.persistenceFailed
                }
            }
        } catch is RetainedPrivateDirectoryCapabilityError {
            throw ActivityStoreFailure.unsafeStorage
        }
    }

    private static func requirePersistedIdentity(
        _ staged: stat,
        in directoryDescriptor: Int32
    ) throws -> ActivityStoreDocumentState {
        let descriptor = documentName.withCString { name in
            openat(directoryDescriptor, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw ActivityStoreFailure.persistenceFailed }
        defer { _ = Darwin.close(descriptor) }
        var persisted = stat()
        guard fstat(descriptor, &persisted) == 0,
              isPrivateRegularDocument(persisted),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              persisted.st_dev == staged.st_dev,
              persisted.st_ino == staged.st_ino
        else {
            throw ActivityStoreFailure.persistenceFailed
        }
        return .present(ActivityStoreDocumentIdentity(persisted))
    }

    private static func requireExpectedDestination(
        _ expected: ActivityStoreDocumentState,
        in directoryDescriptor: Int32
    ) throws {
        let descriptor = documentName.withCString { name in
            openat(directoryDescriptor, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        if descriptor < 0 {
            if errno == ENOENT, expected == .absent { return }
            throw ActivityStoreFailure.unsafeStorage
        }
        defer { _ = Darwin.close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              isPrivateRegularDocument(metadata),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              expected == .present(ActivityStoreDocumentIdentity(metadata)) else {
            throw ActivityStoreFailure.unsafeStorage
        }
    }

    private static func isPrivateRegularDocument(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFREG &&
            metadata.st_uid == geteuid() &&
            metadata.st_nlink == 1 &&
            (metadata.st_mode & mode_t(0o7777)) == mode_t(0o600)
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        var failure: ActivityStoreFailure?
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
                    failure = .persistenceFailed
                    break
                }
            }
        }
        if let failure { throw failure }
    }

    private static func boundedUTF8(_ value: String, maximumBytes: Int) -> String {
        guard value.utf8.count > maximumBytes else { return value }
        var view = String.UnicodeScalarView()
        var retainedBytes = 0
        for scalar in value.unicodeScalars {
            let scalarBytes = String(scalar).utf8.count
            guard retainedBytes + scalarBytes <= maximumBytes else { break }
            view.append(scalar)
            retainedBytes += scalarBytes
        }
        return String(view)
    }
}

private extension ActivityStoreStatus {
    var failure: ActivityStoreFailure? {
        guard case .unavailable(let failure) = self else { return nil }
        return failure
    }
}
