import CryptoKit
import Darwin
import Foundation
#if canImport(PDFKit)
import PDFKit
#endif

enum LocalKnowledgeLimits {
    static let maximumImportBytes = 8 * 1_024 * 1_024
    static let maximumExtractedUTF8Bytes = 4 * 1_024 * 1_024
    static let maximumStoredUTF8Bytes = 128 * 1_024 * 1_024
    static let maximumDocuments = 4_096
    static let maximumChunksPerDocument = 4_096
    static let chunkCharacters = 1_400
    static let chunkOverlapCharacters = 180
    static let maximumQueryUTF8Bytes = 2_048
    static let maximumQueryTerms = 32
    static let maximumSearchResults = 100
    static let maximumSnippetCharacters = 320
    static let maximumPDFPages = 2_000
}

/// Independent work budgets for opening an existing knowledge library. The
/// semantic document/text limits remain in `LocalKnowledgeLimits`; these caps
/// bound the filesystem and indexing work required before that semantic state
/// can be trusted and published.
struct LocalKnowledgeBootstrapLimits: Equatable, Sendable {
    let maximumRootEntries: Int
    let maximumObjectEntries: Int
    let maximumRecoveryEntries: Int
    let maximumTrashEntries: Int
    let maximumTransactionEntries: Int
    let maximumRawObjectBytes: Int
    let maximumRecoveryBytes: Int
    let maximumTrashBytes: Int
    let maximumTransactionBytes: Int
    let maximumFilenameBytes: Int
    let maximumAggregateFilenameBytes: Int
    let maximumTraversalDepth: Int
    let maximumDocuments: Int
    let maximumDecodedTextBytes: Int
    let maximumTotalChunks: Int
    let maximumIndexPostings: Int
    let bootstrapDeadlineSeconds: TimeInterval
    let trashDeadlineSeconds: TimeInterval

    static let production = LocalKnowledgeBootstrapLimits()

    init(
        maximumRootEntries: Int = 32,
        maximumObjectEntries: Int = 8_192,
        maximumRecoveryEntries: Int = 8_192,
        maximumTrashEntries: Int = 8_192,
        maximumTransactionEntries: Int = 8_192,
        maximumRawObjectBytes: Int = 384 * 1_024 * 1_024,
        maximumRecoveryBytes: Int = 384 * 1_024 * 1_024,
        maximumTrashBytes: Int = 384 * 1_024 * 1_024,
        maximumTransactionBytes: Int = 384 * 1_024 * 1_024,
        maximumFilenameBytes: Int = 255,
        maximumAggregateFilenameBytes: Int = 4 * 1_024 * 1_024,
        maximumTraversalDepth: Int = 4,
        maximumDocuments: Int = LocalKnowledgeLimits.maximumDocuments,
        maximumDecodedTextBytes: Int = LocalKnowledgeLimits.maximumStoredUTF8Bytes,
        maximumTotalChunks: Int = 160_000,
        maximumIndexPostings: Int = 4_000_000,
        bootstrapDeadlineSeconds: TimeInterval = 30,
        trashDeadlineSeconds: TimeInterval = 2
    ) {
        precondition(maximumRootEntries > 0)
        precondition(maximumObjectEntries > 0)
        precondition(maximumRecoveryEntries > 0 && maximumTrashEntries > 0 && maximumTransactionEntries > 0)
        precondition(maximumRawObjectBytes > 0)
        precondition(maximumRecoveryBytes > 0 && maximumTrashBytes > 0 && maximumTransactionBytes > 0)
        precondition(maximumFilenameBytes > 0 && maximumAggregateFilenameBytes >= maximumFilenameBytes)
        precondition(maximumTraversalDepth > 0)
        precondition(maximumDocuments > 0 && maximumDecodedTextBytes > 0)
        precondition(maximumTotalChunks > 0)
        precondition(maximumIndexPostings > 0)
        precondition(bootstrapDeadlineSeconds > 0 && bootstrapDeadlineSeconds.isFinite)
        precondition(trashDeadlineSeconds > 0 && trashDeadlineSeconds.isFinite)
        self.maximumRootEntries = maximumRootEntries
        self.maximumObjectEntries = maximumObjectEntries
        self.maximumRecoveryEntries = maximumRecoveryEntries
        self.maximumTrashEntries = maximumTrashEntries
        self.maximumTransactionEntries = maximumTransactionEntries
        self.maximumRawObjectBytes = maximumRawObjectBytes
        self.maximumRecoveryBytes = maximumRecoveryBytes
        self.maximumTrashBytes = maximumTrashBytes
        self.maximumTransactionBytes = maximumTransactionBytes
        self.maximumFilenameBytes = maximumFilenameBytes
        self.maximumAggregateFilenameBytes = maximumAggregateFilenameBytes
        self.maximumTraversalDepth = maximumTraversalDepth
        self.maximumDocuments = maximumDocuments
        self.maximumDecodedTextBytes = maximumDecodedTextBytes
        self.maximumTotalChunks = maximumTotalChunks
        self.maximumIndexPostings = maximumIndexPostings
        self.bootstrapDeadlineSeconds = bootstrapDeadlineSeconds
        self.trashDeadlineSeconds = trashDeadlineSeconds
    }
}

enum KnowledgeScope: Hashable, Sendable {
    case global
    case project(String)

    var projectID: String? {
        if case .project(let projectID) = self { return projectID }
        return nil
    }
}

extension KnowledgeScope: Codable {
    private enum CodingKeys: String, CodingKey { case kind, projectID }
    private enum Kind: String, Codable { case global, project }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .global:
            guard !container.contains(.projectID) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .projectID,
                    in: container,
                    debugDescription: "A global scope cannot include a project identifier."
                )
            }
            self = .global
        case .project:
            self = .project(try container.decode(String.self, forKey: .projectID))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .global:
            try container.encode(Kind.global, forKey: .kind)
        case .project(let projectID):
            try container.encode(Kind.project, forKey: .kind)
            try container.encode(projectID, forKey: .projectID)
        }
    }
}

enum KnowledgeScopeFilter: Equatable, Sendable {
    case all
    case globalOnly
    case project(String, includeGlobal: Bool)
}

enum KnowledgeSourceKind: String, Codable, Equatable, Sendable {
    case memoryNote
    case plainText
    case markdown
    case sourceCode
    case json
    case csv
    case pdf
}

struct KnowledgeDocumentDescriptor: Codable, Equatable, Identifiable, Sendable {
    let id: UUID
    let scope: KnowledgeScope
    let sourceKind: KnowledgeSourceKind
    let title: String
    let sourceName: String?
    let sourceSHA256: String
    let contentSHA256: String
    let createdAt: Date
    let updatedAt: Date
    let characterCount: Int
    let utf8ByteCount: Int
    let chunkCount: Int
}

struct KnowledgeMemoryNote: Equatable, Sendable {
    let descriptor: KnowledgeDocumentDescriptor
    let text: String
}

struct KnowledgeContextChunk: Equatable, Sendable {
    let documentID: UUID
    let title: String
    let sourceName: String?
    let scope: KnowledgeScope
    let chunkIndex: Int
    let text: String
}

struct KnowledgeSearchResult: Equatable, Sendable {
    let documentID: UUID
    let title: String
    let sourceName: String?
    let scope: KnowledgeScope
    let sourceKind: KnowledgeSourceKind
    let chunkIndex: Int
    let score: Double
    let snippet: String
}

struct KnowledgeExportManifest: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let generatedAt: Date
    let documents: [KnowledgeDocumentDescriptor]
}

struct KnowledgeRecoveryReport: Equatable, Sendable {
    var recoveredCatalog = false
    var recoveredOrphanDocuments = 0
    var missingCatalogDocuments = 0
    var quarantinedDocuments = 0
    var preservedTemporaryFiles = 0
    var trashCleanupPending = false
    var trashCleanupIssue: String?
}

enum LocalKnowledgeStoreAvailability: Equatable, Sendable {
    case idle
    case loading
    case ready
    case unavailable(String)
}

enum LocalKnowledgeMutationBoundary: Hashable, Sendable {
    case journalDurable
    case objectEvacuated(Int)
    case catalogEvacuated
    case replacementWritten(Int)
    case objectDirectoryDurable
    case catalogWritten
    case rootDirectoryDurable
    case commitMarkerDurable
    case rollbackStarted
    case rollbackObjectRestored(Int)
    case rollbackCatalogRestored
    case committedCleanupStarted
}

/// Test-only interruption used to model process loss. Production never installs
/// a mutation hook, so this value cannot originate from an app operation.
enum LocalKnowledgeSimulatedProcessLoss: Error, Sendable {
    case interrupt
}

struct LocalKnowledgeStoreStatus: Equatable, Sendable {
    let availability: LocalKnowledgeStoreAvailability
    let recoveryReport: KnowledgeRecoveryReport
}

enum LocalKnowledgeStoreError: LocalizedError, Equatable, Sendable {
    case invalidStorageRoot
    case unsafeStoreEntry(String)
    case storageUnavailable
    case futureSchema(found: Int, supported: Int)
    case invalidProjectID
    case invalidTitle
    case invalidTimestamp
    case emptyContent
    case contentTooLarge(maximumBytes: Int)
    case tooManyChunks(maximum: Int)
    case sourceIsSymbolicLink
    case sourceIsNotRegularFile
    case sourceUnreadable
    case sourceTooLarge(maximumBytes: Int)
    case unsupportedFileType(String)
    case invalidUTF8
    case binaryContent
    case invalidJSON
    case invalidPDF
    case encryptedPDF
    case pdfHasNoExtractableText
    case pdfTooManyPages(maximum: Int)
    case documentLimitReached(maximum: Int)
    case storeCapacityExceeded(maximumBytes: Int)
    case documentNotFound
    case notMemoryNote
    case invalidSearchQuery
    case invalidSearchLimit
    case invalidChunkIndex
    case unsafeExportDestination
    case loadingCancelled
    case operationRequiresBackground
    case directoryEntryLimitExceeded(maximum: Int)
    case aggregateStorageLimitExceeded(maximumBytes: Int)
    case aggregateFilenameLimitExceeded(maximumBytes: Int)
    case storageTraversalDepthExceeded(maximum: Int)
    case storageScanTimedOut
    case indexChunkLimitExceeded(maximumChunks: Int)
    case indexCapacityExceeded(maximumPostings: Int)
    case mutationRollbackIncomplete

    var errorDescription: String? {
        switch self {
        case .invalidStorageRoot:
            return "The local knowledge store requires an absolute file-system location."
        case .unsafeStoreEntry(let name):
            return "The local knowledge store contains an unsafe entry named \(name)."
        case .storageUnavailable:
            return "The local knowledge store is unavailable."
        case .futureSchema(let found, let supported):
            return "Knowledge data uses schema \(found), but this app supports schema \(supported). No data was changed."
        case .invalidProjectID:
            return "The project identifier is invalid."
        case .invalidTitle:
            return "The knowledge title must be between 1 and 200 characters and cannot contain control characters."
        case .invalidTimestamp:
            return "The knowledge item has an invalid creation or update time."
        case .emptyContent:
            return "The knowledge item has no readable text."
        case .contentTooLarge(let maximumBytes):
            return "Extracted text exceeds the \(maximumBytes)-byte safety limit."
        case .tooManyChunks(let maximum):
            return "The knowledge item exceeds the \(maximum)-chunk safety limit."
        case .sourceIsSymbolicLink:
            return "Symbolic links cannot be imported into local knowledge."
        case .sourceIsNotRegularFile:
            return "Only regular files can be imported into local knowledge."
        case .sourceUnreadable:
            return "The selected source file could not be read safely."
        case .sourceTooLarge(let maximumBytes):
            return "The selected source exceeds the \(maximumBytes)-byte import limit."
        case .unsupportedFileType(let fileExtension):
            return "The .\(fileExtension) file type is not supported for local knowledge."
        case .invalidUTF8:
            return "The selected text file is not valid UTF-8."
        case .binaryContent:
            return "Binary content cannot be imported as text."
        case .invalidJSON:
            return "The selected JSON file is not valid JSON."
        case .invalidPDF:
            return "The selected PDF could not be read."
        case .encryptedPDF:
            return "Encrypted PDFs cannot be imported into local knowledge."
        case .pdfHasNoExtractableText:
            return "The PDF contains no extractable text."
        case .pdfTooManyPages(let maximum):
            return "The PDF exceeds the \(maximum)-page safety limit."
        case .documentLimitReached(let maximum):
            return "The local knowledge store has reached its \(maximum)-document limit."
        case .storeCapacityExceeded(let maximumBytes):
            return "The local knowledge store has reached its \(maximumBytes)-byte text limit."
        case .documentNotFound:
            return "The requested knowledge item was not found."
        case .notMemoryNote:
            return "Only user-created memory notes can be edited."
        case .invalidSearchQuery:
            return "The search query is empty or exceeds the local search limits."
        case .invalidSearchLimit:
            return "The search result limit is invalid."
        case .invalidChunkIndex:
            return "The requested knowledge chunk was not found."
        case .unsafeExportDestination:
            return "The export destination is not a safe regular file location."
        case .loadingCancelled:
            return "Loading the local knowledge store was cancelled before any in-memory index was published."
        case .operationRequiresBackground:
            return "Local knowledge is still loading. Try again when the private library is ready."
        case .directoryEntryLimitExceeded(let maximum):
            return "The local knowledge store exceeds its \(maximum)-entry scan limit. No partial index was published."
        case .aggregateStorageLimitExceeded(let maximumBytes):
            return "The local knowledge store exceeds its \(maximumBytes)-byte scan limit. No partial index was published."
        case .aggregateFilenameLimitExceeded(let maximumBytes):
            return "The local knowledge store exceeds its \(maximumBytes)-byte filename scan limit."
        case .storageTraversalDepthExceeded(let maximum):
            return "The local knowledge store exceeds its \(maximum)-level traversal limit."
        case .storageScanTimedOut:
            return "The local knowledge store could not be inspected within its bounded deadline. No partial index was published."
        case .indexChunkLimitExceeded(let maximumChunks):
            return "The local knowledge index exceeds its \(maximumChunks)-chunk safety limit."
        case .indexCapacityExceeded(let maximumPostings):
            return "The local knowledge index exceeds its \(maximumPostings)-posting safety limit."
        case .mutationRollbackIncomplete:
            return "A local knowledge change could not be durably committed or rolled back. The library is unavailable until recovery completes."
        }
    }
}

/// A bounded, offline knowledge store. It deliberately stores no source paths,
/// performs no networking, and keeps every persisted item under the app-owned
/// `Knowledge` directory. The catalog is only an index: each document is a
/// separately versioned object, allowing a damaged catalog to be reconstructed
/// without discarding valid knowledge.
final class LocalKnowledgeStore: @unchecked Sendable {
    static let schemaVersion = 1

    typealias LoadCompletion = @Sendable (Result<Void, LocalKnowledgeStoreError>) -> Void

    private struct CatalogEnvelope: Codable {
        let schemaVersion: Int
        let generation: UInt64
        let documentIDs: [UUID]
    }

    private struct DocumentEnvelope: Codable {
        let schemaVersion: Int
        let descriptor: KnowledgeDocumentDescriptor
        let text: String
    }

    private struct StoredDocument {
        let descriptor: KnowledgeDocumentDescriptor
        let text: String
        let chunks: [String]
    }

    private struct ChunkKey: Hashable {
        let documentID: UUID
        let chunkIndex: Int
    }

    private struct IndexedChunk {
        let key: ChunkKey
        let tokenCount: Int
    }

    private struct Posting {
        let key: ChunkKey
        let frequency: Int
    }

    private struct SearchIndex {
        let indexedChunks: [ChunkKey: IndexedChunk]
        let postings: [String: [Posting]]
    }

    private struct BootstrapSnapshot {
        let generation: UInt64
        let documents: [UUID: StoredDocument]
        let index: SearchIndex
        let report: KnowledgeRecoveryReport
    }

    private struct MutationJournal: Codable {
        let schemaVersion: Int
        let transactionID: UUID
        let oldGeneration: UInt64
        let newGeneration: UInt64
        let affectedObjectNames: [String]
        let previousObjectNames: [String]
        let oldCatalogSHA256: String
        let previousObjectSHA256: [String: String]
    }

    private enum ObjectMutation {
        case write(Data)
        case remove
    }

    private struct ScannedDirectoryEntry {
        let url: URL
        let name: String
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let owner: uid_t
        let links: nlink_t
        let bytes: Int
    }

    private struct ScannedDirectory {
        let device: dev_t
        let inode: ino_t
        let entries: [ScannedDirectoryEntry]
    }

    private struct RecoveryCapacity {
        var entries: Int
        var bytes: Int
    }

    private struct ScanDeadline {
        let value: UInt64
        let now: @Sendable () -> UInt64

        func check() throws {
            guard now() <= value else { throw LocalKnowledgeStoreError.storageScanTimedOut }
        }
    }

    private struct TrashNode {
        let url: URL
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let depth: Int
    }

    private struct TrashTraversalBudget {
        var entries = 0
        var bytes = 0
        var filenameBytes = 0
    }

    private enum ImportedKind {
        case text(KnowledgeSourceKind)
        case jsonLines
        case pdf
    }

    private let queue = DispatchQueue(label: "app.localharness.local-knowledge")
    private let fileManager: FileManager
    private let idGenerator: () -> UUID
    private let bootstrapLimits: LocalKnowledgeBootstrapLimits
    private let scanNow: @Sendable () -> UInt64
    private let beforeBootstrap: @Sendable () -> Void
    private let mutationBoundary: @Sendable (LocalKnowledgeMutationBoundary) throws -> Void
    private let rootURL: URL
    private let objectsURL: URL
    private let recoveryURL: URL
    private let trashURL: URL
    private let transactionsURL: URL
    private let catalogURL: URL
    private var generation: UInt64 = 0
    private var documents: [UUID: StoredDocument] = [:]
    private var indexedChunks: [ChunkKey: IndexedChunk] = [:]
    private var postings: [String: [Posting]] = [:]
    private var trashCleanupScheduled = false

    private let statusLock = NSLock()
    private var availabilityValue: LocalKnowledgeStoreAvailability = .idle
    private var recoveryReportValue = KnowledgeRecoveryReport()
    private var loadFailure: LocalKnowledgeStoreError?
    private var loadToken: UUID?
    private var loadCallbacks: [LoadCompletion] = []
    private var statusHandler: (@Sendable (LocalKnowledgeStoreStatus) -> Void)?

    init(
        applicationSupportDirectory: URL,
        fileManager: FileManager = .default,
        idGenerator: @escaping () -> UUID = UUID.init,
        bootstrapLimits: LocalKnowledgeBootstrapLimits = .production,
        scanNow: @escaping @Sendable () -> UInt64 = {
            DispatchTime.now().uptimeNanoseconds
        },
        beforeBootstrap: @escaping @Sendable () -> Void = {},
        mutationBoundary: @escaping @Sendable (LocalKnowledgeMutationBoundary) throws -> Void = { _ in }
    ) throws {
        guard applicationSupportDirectory.isFileURL,
              applicationSupportDirectory.path.hasPrefix("/") else {
            throw LocalKnowledgeStoreError.invalidStorageRoot
        }
        self.fileManager = fileManager
        self.idGenerator = idGenerator
        self.bootstrapLimits = bootstrapLimits
        self.scanNow = scanNow
        self.beforeBootstrap = beforeBootstrap
        self.mutationBoundary = mutationBoundary
        rootURL = applicationSupportDirectory.appendingPathComponent("Knowledge", isDirectory: true)
        objectsURL = rootURL.appendingPathComponent("Objects", isDirectory: true)
        recoveryURL = rootURL.appendingPathComponent("Recovery", isDirectory: true)
        trashURL = rootURL.appendingPathComponent("Trash", isDirectory: true)
        transactionsURL = rootURL.appendingPathComponent("Transactions", isDirectory: true)
        catalogURL = rootURL.appendingPathComponent("catalog.json")
    }

    var storageDirectory: URL { rootURL }

    var availability: LocalKnowledgeStoreAvailability {
        statusLock.lock()
        defer { statusLock.unlock() }
        return availabilityValue
    }

    var recoveryReport: KnowledgeRecoveryReport {
        statusLock.lock()
        defer { statusLock.unlock() }
        return recoveryReportValue
    }

    func setStatusHandler(
        _ handler: (@Sendable (LocalKnowledgeStoreStatus) -> Void)?
    ) {
        statusLock.lock()
        statusHandler = handler
        let status = LocalKnowledgeStoreStatus(
            availability: availabilityValue,
            recoveryReport: recoveryReportValue
        )
        statusLock.unlock()
        guard let handler else { return }
        DispatchQueue.main.async { handler(status) }
    }

    /// Coalesces every caller onto one serial bootstrap. Construction itself
    /// never creates directories, scans documents, or builds an index.
    func load(retry: Bool = false, completion: @escaping LoadCompletion) {
        var tokenToStart: UUID?
        var immediate: Result<Void, LocalKnowledgeStoreError>?
        statusLock.lock()
        switch availabilityValue {
        case .idle:
            let token = UUID()
            loadToken = token
            loadCallbacks.append(completion)
            availabilityValue = .loading
            loadFailure = nil
            tokenToStart = token
        case .loading:
            loadCallbacks.append(completion)
        case .ready:
            immediate = .success(())
        case .unavailable:
            if retry {
                let token = UUID()
                loadToken = token
                loadCallbacks.append(completion)
                availabilityValue = .loading
                loadFailure = nil
                tokenToStart = token
            } else {
                immediate = .failure(loadFailure ?? .storageUnavailable)
            }
        }
        statusLock.unlock()

        if tokenToStart != nil { notifyStatusChange() }
        if let immediate {
            DispatchQueue.main.async { completion(immediate) }
        }
        guard let token = tokenToStart else { return }
        queue.async { [weak self] in self?.performAsynchronousBootstrap(token: token) }
    }

    func cancelLoading() {
        var callbacks: [LoadCompletion] = []
        statusLock.lock()
        if availabilityValue == .loading {
            loadToken = nil
            availabilityValue = .idle
            loadFailure = nil
            callbacks = loadCallbacks
            loadCallbacks.removeAll()
        }
        statusLock.unlock()
        guard !callbacks.isEmpty else { return }
        notifyStatusChange()
        DispatchQueue.main.async {
            callbacks.forEach { $0(.failure(.loadingCancelled)) }
        }
    }

    /// Retries only the deferred deletion maintenance. The trusted library
    /// snapshot remains available while this bounded work runs on the store's
    /// serial authority.
    func retryDeferredMaintenance() {
        queue.async { [weak self] in
            guard let self, self.availability == .ready else { return }
            self.updateTrashCleanupReport(pending: true, issue: nil, removedEntries: 0)
            self.scheduleDeferredTrashCleanup()
        }
    }

    private func performAsynchronousBootstrap(token: UUID) {
        beforeBootstrap()
        let result: Result<BootstrapSnapshot, LocalKnowledgeStoreError>
        do {
            try requireActiveLoad(token)
            let deadline = try makeDeadline(seconds: bootstrapLimits.bootstrapDeadlineSeconds)
            result = .success(try bootstrap(deadline: deadline, loadToken: token))
        } catch let error as LocalKnowledgeStoreError {
            result = .failure(error)
        } catch {
            result = .failure(.storageUnavailable)
        }

        switch result {
        case .success(let snapshot):
            do { try requireActiveLoad(token) }
            catch { return }
            documents = snapshot.documents
            generation = snapshot.generation
            indexedChunks = snapshot.index.indexedChunks
            postings = snapshot.index.postings
            finishLoad(token: token, result: .success(()), report: snapshot.report)
            scheduleDeferredTrashCleanup()
        case .failure(let error):
            finishLoad(token: token, result: .failure(error), report: nil)
        }
    }

    private func finishLoad(
        token: UUID,
        result: Result<Void, LocalKnowledgeStoreError>,
        report: KnowledgeRecoveryReport?
    ) {
        var callbacks: [LoadCompletion] = []
        statusLock.lock()
        guard loadToken == token else {
            statusLock.unlock()
            return
        }
        loadToken = nil
        callbacks = loadCallbacks
        loadCallbacks.removeAll()
        switch result {
        case .success:
            if let report { recoveryReportValue = report }
            availabilityValue = .ready
            loadFailure = nil
        case .failure(let error):
            availabilityValue = .unavailable(error.localizedDescription)
            loadFailure = error
        }
        statusLock.unlock()
        notifyStatusChange()
        DispatchQueue.main.async { callbacks.forEach { $0(result) } }
    }

    private func requireActiveLoad(_ token: UUID) throws {
        statusLock.lock()
        let active = loadToken == token && availabilityValue == .loading
        statusLock.unlock()
        guard active else { throw LocalKnowledgeStoreError.loadingCancelled }
    }

    private func notifyStatusChange() {
        statusLock.lock()
        let handler = statusHandler
        let status = LocalKnowledgeStoreStatus(
            availability: availabilityValue,
            recoveryReport: recoveryReportValue
        )
        statusLock.unlock()
        guard let handler else { return }
        DispatchQueue.main.async { handler(status) }
    }

    /// Compatibility for non-UI callers and tests. Production UI paths first
    /// call `load`, then invoke document operations from a worker queue. A
    /// synchronous first load on the main thread fails immediately instead of
    /// turning an AppKit action into a multi-second filesystem/index build.
    private func ensureLoadedOnQueue() throws {
        statusLock.lock()
        let state = availabilityValue
        let priorFailure = loadFailure
        statusLock.unlock()
        switch state {
        case .ready:
            return
        case .unavailable:
            throw priorFailure ?? LocalKnowledgeStoreError.storageUnavailable
        case .loading:
            // The serial queue cannot execute this method concurrently with
            // its own bootstrap. Reaching this state means a cancellation or
            // state transition raced the queued operation; fail closed.
            throw LocalKnowledgeStoreError.operationRequiresBackground
        case .idle:
            break
        }
        guard !Thread.isMainThread else {
            throw LocalKnowledgeStoreError.operationRequiresBackground
        }

        let token = UUID()
        statusLock.lock()
        guard availabilityValue == .idle else {
            let failure = loadFailure
            statusLock.unlock()
            if availability == .ready { return }
            throw failure ?? LocalKnowledgeStoreError.operationRequiresBackground
        }
        availabilityValue = .loading
        loadToken = token
        loadFailure = nil
        statusLock.unlock()
        notifyStatusChange()

        beforeBootstrap()
        do {
            let deadline = try makeDeadline(seconds: bootstrapLimits.bootstrapDeadlineSeconds)
            let snapshot = try bootstrap(deadline: deadline, loadToken: token)
            try requireActiveLoad(token)
            documents = snapshot.documents
            generation = snapshot.generation
            indexedChunks = snapshot.index.indexedChunks
            postings = snapshot.index.postings
            finishLoad(token: token, result: .success(()), report: snapshot.report)
            scheduleDeferredTrashCleanup()
        } catch let error as LocalKnowledgeStoreError {
            finishLoad(token: token, result: .failure(error), report: nil)
            throw error
        } catch {
            finishLoad(token: token, result: .failure(.storageUnavailable), report: nil)
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }

    private func rejectBlockingMainThreadFirstUse() throws {
        guard Thread.isMainThread else { return }
        statusLock.lock()
        let state = availabilityValue
        let failure = loadFailure
        statusLock.unlock()
        switch state {
        case .ready:
            return
        case .unavailable:
            throw failure ?? LocalKnowledgeStoreError.storageUnavailable
        case .idle, .loading:
            throw LocalKnowledgeStoreError.operationRequiresBackground
        }
    }

    private func makeDeadline(seconds: TimeInterval) throws -> ScanDeadline {
        let raw = seconds * 1_000_000_000
        guard raw.isFinite, raw > 0 else { throw LocalKnowledgeStoreError.storageScanTimedOut }
        let duration = raw >= Double(UInt64.max) ? UInt64.max : UInt64(raw.rounded(.up))
        let start = scanNow()
        let sum = start.addingReportingOverflow(duration)
        return ScanDeadline(value: sum.overflow ? UInt64.max : sum.partialValue, now: scanNow)
    }

    func createMemoryNote(
        title: String,
        text: String,
        scope: KnowledgeScope = .global,
        createdAt: Date = Date()
    ) throws -> KnowledgeDocumentDescriptor {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            try validate(scope: scope)
            let validTitle = try validate(title: title)
            let normalized = try normalizeAndValidate(text: text)
            let bytes = Data(normalized.utf8)
            return try insert(
                title: validTitle,
                text: normalized,
                scope: scope,
                sourceKind: .memoryNote,
                sourceName: nil,
                sourceDigest: Self.sha256(bytes),
                createdAt: createdAt
            )
        }
    }

    func updateMemoryNote(
        id: UUID,
        title: String,
        text: String,
        updatedAt: Date = Date()
    ) throws -> KnowledgeDocumentDescriptor {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            guard let existing = documents[id] else { throw LocalKnowledgeStoreError.documentNotFound }
            guard existing.descriptor.sourceKind == .memoryNote else { throw LocalKnowledgeStoreError.notMemoryNote }
            let validTitle = try validate(title: title)
            let normalized = try normalizeAndValidate(text: text)
            guard updatedAt.timeIntervalSinceReferenceDate.isFinite,
                  updatedAt >= existing.descriptor.createdAt else {
                throw LocalKnowledgeStoreError.invalidTimestamp
            }
            let chunks = try Self.chunk(normalized)
            let newByteCount = normalized.utf8.count
            try validateCapacity(replacing: existing.descriptor.utf8ByteCount, with: newByteCount)
            let digest = Self.sha256(Data(normalized.utf8))
            let descriptor = KnowledgeDocumentDescriptor(
                id: id,
                scope: existing.descriptor.scope,
                sourceKind: .memoryNote,
                title: validTitle,
                sourceName: nil,
                sourceSHA256: digest,
                contentSHA256: digest,
                createdAt: existing.descriptor.createdAt,
                updatedAt: updatedAt,
                characterCount: normalized.count,
                utf8ByteCount: newByteCount,
                chunkCount: chunks.count
            )
            let stored = StoredDocument(descriptor: descriptor, text: normalized, chunks: chunks)
            var candidateDocuments = documents
            candidateDocuments[id] = stored
            let candidateIndex = try buildSearchIndex(documents: candidateDocuments)
            let encoded = try encodeDocument(descriptor: descriptor, text: normalized)
            guard generation < UInt64.max else { throw LocalKnowledgeStoreError.storageUnavailable }
            try commitMutation(
                candidateDocuments: candidateDocuments,
                replacements: [id: .write(encoded)],
                newGeneration: generation + 1
            )
            documents = candidateDocuments
            generation += 1
            indexedChunks = candidateIndex.indexedChunks
            postings = candidateIndex.postings
            markTrashCleanupPendingOnQueue()
            return descriptor
        }
    }

    func memoryNote(id: UUID) throws -> KnowledgeMemoryNote {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            guard let document = documents[id] else { throw LocalKnowledgeStoreError.documentNotFound }
            guard document.descriptor.sourceKind == .memoryNote else { throw LocalKnowledgeStoreError.notMemoryNote }
            return KnowledgeMemoryNote(descriptor: document.descriptor, text: document.text)
        }
    }

    func importFile(
        at sourceURL: URL,
        scope: KnowledgeScope = .global,
        title: String? = nil,
        importedAt: Date = Date()
    ) throws -> KnowledgeDocumentDescriptor {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            try validate(scope: scope)
            guard sourceURL.isFileURL, !sourceURL.lastPathComponent.isEmpty else {
                throw LocalKnowledgeStoreError.sourceUnreadable
            }
            guard Self.isSafeSourceName(sourceURL.lastPathComponent) else {
                throw LocalKnowledgeStoreError.sourceUnreadable
            }
            let importedKind = try classify(fileExtension: sourceURL.pathExtension)
            let sourceData = try Self.readSourceFile(at: sourceURL)
            let extracted: String
            let sourceKind: KnowledgeSourceKind
            switch importedKind {
            case .text(let kind):
                guard var decoded = String(data: sourceData, encoding: .utf8) else {
                    throw LocalKnowledgeStoreError.invalidUTF8
                }
                if decoded.first == "\u{FEFF}" { decoded.removeFirst() }
                if kind == .json {
                    guard (try? JSONSerialization.jsonObject(with: sourceData, options: [.fragmentsAllowed])) != nil else {
                        throw LocalKnowledgeStoreError.invalidJSON
                    }
                }
                extracted = try normalizeAndValidate(text: decoded)
                sourceKind = kind
            case .jsonLines:
                guard var decoded = String(data: sourceData, encoding: .utf8) else {
                    throw LocalKnowledgeStoreError.invalidUTF8
                }
                if decoded.first == "\u{FEFF}" { decoded.removeFirst() }
                let rows = decoded.split(separator: "\n", omittingEmptySubsequences: true)
                guard !rows.isEmpty, rows.allSatisfy({ row in
                    guard let data = String(row).data(using: .utf8) else { return false }
                    return (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil
                }) else {
                    throw LocalKnowledgeStoreError.invalidJSON
                }
                extracted = try normalizeAndValidate(text: decoded)
                sourceKind = .json
            case .pdf:
                extracted = try normalizeAndValidate(text: Self.extractPDFText(from: sourceData))
                sourceKind = .pdf
            }
            let resolvedTitle = try validate(
                title: title ?? sourceURL.deletingPathExtension().lastPathComponent
            )
            return try insert(
                title: resolvedTitle,
                text: extracted,
                scope: scope,
                sourceKind: sourceKind,
                sourceName: sourceURL.lastPathComponent,
                sourceDigest: Self.sha256(sourceData),
                createdAt: importedAt
            )
        }
    }

    func listDocuments(scope filter: KnowledgeScopeFilter = .all) throws -> [KnowledgeDocumentDescriptor] {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            try validate(filter: filter)
            return documents.values
                .map(\.descriptor)
                .filter { Self.matches($0.scope, filter: filter) }
                .sorted(by: Self.descriptorOrder)
        }
    }

    func context(documentID: UUID, chunkIndex: Int) throws -> KnowledgeContextChunk {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            guard let document = documents[documentID] else { throw LocalKnowledgeStoreError.documentNotFound }
            guard document.chunks.indices.contains(chunkIndex) else { throw LocalKnowledgeStoreError.invalidChunkIndex }
            return KnowledgeContextChunk(
                documentID: documentID,
                title: document.descriptor.title,
                sourceName: document.descriptor.sourceName,
                scope: document.descriptor.scope,
                chunkIndex: chunkIndex,
                text: document.chunks[chunkIndex]
            )
        }
    }

    func search(
        _ query: String,
        scope filter: KnowledgeScopeFilter = .all,
        limit: Int = 20
    ) throws -> [KnowledgeSearchResult] {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            guard (1...LocalKnowledgeLimits.maximumSearchResults).contains(limit) else {
                throw LocalKnowledgeStoreError.invalidSearchLimit
            }
            try validate(filter: filter)
            let normalizedQuery = try normalizedSearchQuery(query)
            let queryTerms = Self.uniqueTokens(in: normalizedQuery)
            guard !queryTerms.isEmpty, queryTerms.count <= LocalKnowledgeLimits.maximumQueryTerms else {
                throw LocalKnowledgeStoreError.invalidSearchQuery
            }

            let eligible = indexedChunks.values.filter { indexed in
                guard let document = documents[indexed.key.documentID] else { return false }
                return Self.matches(document.descriptor.scope, filter: filter)
            }
            guard !eligible.isEmpty else { return [] }
            let eligibleKeys = Set(eligible.map(\.key))
            let averageLength = max(1.0, Double(eligible.reduce(0) { $0 + $1.tokenCount }) / Double(eligible.count))
            let totalChunks = Double(eligible.count)
            var scores: [ChunkKey: Double] = [:]

            for term in queryTerms {
                let matchingPostings = (postings[term] ?? []).filter { eligibleKeys.contains($0.key) }
                guard !matchingPostings.isEmpty else { continue }
                let documentFrequency = Double(matchingPostings.count)
                let inverseFrequency = log(1.0 + (totalChunks - documentFrequency + 0.5) / (documentFrequency + 0.5))
                for posting in matchingPostings {
                    guard let indexed = indexedChunks[posting.key] else { continue }
                    let frequency = Double(posting.frequency)
                    let length = Double(indexed.tokenCount)
                    let k1 = 1.2
                    let b = 0.75
                    let denominator = frequency + k1 * (1.0 - b + b * length / averageLength)
                    scores[posting.key, default: 0] += inverseFrequency * (frequency * (k1 + 1.0) / denominator)
                }
            }

            var results: [KnowledgeSearchResult] = []
            for (key, rawScore) in scores where rawScore > 0 {
                guard let document = documents[key.documentID],
                      document.chunks.indices.contains(key.chunkIndex) else { continue }
                let titleTokens = Set(Self.tokens(in: document.descriptor.title))
                let titleHits = queryTerms.reduce(0) { $0 + (titleTokens.contains($1) ? 1 : 0) }
                let score = Self.roundedScore(rawScore + Double(titleHits) * 0.35)
                results.append(KnowledgeSearchResult(
                    documentID: key.documentID,
                    title: document.descriptor.title,
                    sourceName: document.descriptor.sourceName,
                    scope: document.descriptor.scope,
                    sourceKind: document.descriptor.sourceKind,
                    chunkIndex: key.chunkIndex,
                    score: score,
                    snippet: Self.snippet(from: document.chunks[key.chunkIndex], terms: queryTerms)
                ))
            }

            results.sort {
                if $0.score != $1.score { return $0.score > $1.score }
                let leftTitle = Self.stableTitleKey($0.title)
                let rightTitle = Self.stableTitleKey($1.title)
                if leftTitle != rightTitle { return leftTitle < rightTitle }
                let leftID = $0.documentID.uuidString.lowercased()
                let rightID = $1.documentID.uuidString.lowercased()
                if leftID != rightID { return leftID < rightID }
                return $0.chunkIndex < $1.chunkIndex
            }
            return Array(results.prefix(limit))
        }
    }

    @discardableResult
    func delete(id: UUID) throws -> KnowledgeDocumentDescriptor {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            guard let existing = documents[id] else { throw LocalKnowledgeStoreError.documentNotFound }
            let source = objectURL(for: id)
            try Self.requireRegularNonSymlink(source, unsafeError: .unsafeStoreEntry(source.lastPathComponent))
            guard generation < UInt64.max else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            var candidateDocuments = documents
            candidateDocuments.removeValue(forKey: id)
            let candidateIndex = try buildSearchIndex(documents: candidateDocuments)
            try commitMutation(
                candidateDocuments: candidateDocuments,
                replacements: [id: .remove],
                newGeneration: generation + 1
            )
            documents = candidateDocuments
            generation += 1
            indexedChunks = candidateIndex.indexedChunks
            postings = candidateIndex.postings
            markTrashCleanupPendingOnQueue()
            return existing.descriptor
        }
    }

    @discardableResult
    func clear(scope: KnowledgeScope? = nil) throws -> Int {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            if let scope { try validate(scope: scope) }
            let selected = documents.values.filter { scope == nil || $0.descriptor.scope == scope }
            guard !selected.isEmpty else { return 0 }
            guard generation < UInt64.max else { throw LocalKnowledgeStoreError.storageUnavailable }
            let selectedIDs = Set(selected.map { $0.descriptor.id })
            let candidateDocuments = documents.filter { !selectedIDs.contains($0.key) }
            let candidateIndex = try buildSearchIndex(documents: candidateDocuments)
            var replacements: [UUID: ObjectMutation] = [:]
            for document in selected {
                let source = objectURL(for: document.descriptor.id)
                try Self.requireRegularNonSymlink(source, unsafeError: .unsafeStoreEntry(source.lastPathComponent))
                replacements[document.descriptor.id] = .remove
            }
            try commitMutation(
                candidateDocuments: candidateDocuments,
                replacements: replacements,
                newGeneration: generation + 1
            )
            documents = candidateDocuments
            generation += 1
            indexedChunks = candidateIndex.indexedChunks
            postings = candidateIndex.postings
            markTrashCleanupPendingOnQueue()
            return selected.count
        }
    }

    func makeExportManifest(generatedAt: Date = Date()) throws -> KnowledgeExportManifest {
        try rejectBlockingMainThreadFirstUse()
        return try queue.sync {
            try ensureLoadedOnQueue()
            return KnowledgeExportManifest(
                schemaVersion: Self.schemaVersion,
                generatedAt: generatedAt,
                documents: documents.values.map(\.descriptor).sorted(by: Self.descriptorOrder)
            )
        }
    }

    func exportManifestData(generatedAt: Date = Date()) throws -> Data {
        let manifest = try makeExportManifest(generatedAt: generatedAt)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(manifest)
    }

    func exportManifest(to destination: URL, generatedAt: Date = Date()) throws {
        guard destination.isFileURL, !destination.lastPathComponent.isEmpty else {
            throw LocalKnowledgeStoreError.unsafeExportDestination
        }
        let parent = destination.deletingLastPathComponent()
        guard (try? Self.isDirectoryWithoutSymlink(parent)) == true else {
            throw LocalKnowledgeStoreError.unsafeExportDestination
        }
        if Self.entryExists(destination) {
            try Self.requireRegularNonSymlink(
                destination,
                unsafeError: .unsafeExportDestination,
                requiresPrivateOwnership: false
            )
        }
        let data = try exportManifestData(generatedAt: generatedAt)
        do {
            try Self.atomicPrivateWrite(data, to: destination, fileManager: fileManager, secureParent: false)
        } catch let error as LocalKnowledgeStoreError {
            throw error
        } catch {
            throw LocalKnowledgeStoreError.unsafeExportDestination
        }
    }

    // MARK: - Bootstrap and persistence

    private static let maximumCatalogBytes = 2 * 1_024 * 1_024
    private static let maximumObjectBytes = LocalKnowledgeLimits.maximumExtractedUTF8Bytes * 3
    private static let mutationJournalSchemaVersion = 1

    private func bootstrap(
        deadline: ScanDeadline,
        loadToken: UUID
    ) throws -> BootstrapSnapshot {
        do {
            try deadline.check()
            try requireActiveLoad(loadToken)
            try Self.ensurePrivateDirectory(rootURL, fileManager: fileManager)
            try Self.ensurePrivateDirectory(objectsURL, fileManager: fileManager)
            try Self.ensurePrivateDirectory(recoveryURL, fileManager: fileManager)
            try Self.ensurePrivateDirectory(trashURL, fileManager: fileManager)
            try Self.ensurePrivateDirectory(transactionsURL, fileManager: fileManager)
            try reconcileInterruptedMutations(deadline: deadline, loadToken: loadToken)

            let rootScan = try scanDirectory(
                rootURL,
                maximumEntries: bootstrapLimits.maximumRootEntries,
                maximumBytes: bootstrapLimits.maximumRawObjectBytes,
                deadline: deadline
            )
            try validateRootEntries(rootScan.entries)
            let objectScan = try scanDirectory(
                objectsURL,
                maximumEntries: bootstrapLimits.maximumObjectEntries,
                maximumBytes: bootstrapLimits.maximumRawObjectBytes,
                deadline: deadline
            )
            try validateObjectEntries(objectScan.entries)
            let recoveryScan = try scanDirectory(
                recoveryURL,
                maximumEntries: bootstrapLimits.maximumRecoveryEntries,
                maximumBytes: bootstrapLimits.maximumRecoveryBytes,
                deadline: deadline
            )
            try validateRecoveryEntries(recoveryScan.entries)
            try preflightFutureSchemas(
                rootEntries: rootScan.entries,
                objectEntries: objectScan.entries,
                deadline: deadline,
                loadToken: loadToken
            )

            var report = KnowledgeRecoveryReport()
            var recoveryCapacity = RecoveryCapacity(
                entries: recoveryScan.entries.count,
                bytes: recoveryScan.entries.reduce(0) { $0 + $1.bytes }
            )
            report.preservedTemporaryFiles += try preserveInterruptedTemporaryFiles(
                rootScan.entries,
                capacity: &recoveryCapacity,
                deadline: deadline,
                loadToken: loadToken
            )
            report.preservedTemporaryFiles += try preserveInterruptedTemporaryFiles(
                objectScan.entries,
                capacity: &recoveryCapacity,
                deadline: deadline,
                loadToken: loadToken
            )

            let catalog = try loadCatalogRecoveringCorruption(
                report: &report,
                capacity: &recoveryCapacity,
                deadline: deadline,
                loadToken: loadToken
            )
            let loaded = try loadDocumentObjectsRecoveringCorruption(
                entries: objectScan.entries.filter { !Self.isInterruptedTemporaryFile($0.url) },
                report: &report,
                capacity: &recoveryCapacity,
                deadline: deadline,
                loadToken: loadToken
            )
            let scanned = loaded.documents
            guard scanned.count <= bootstrapLimits.maximumDocuments else {
                throw LocalKnowledgeStoreError.documentLimitReached(maximum: bootstrapLimits.maximumDocuments)
            }
            var scannedBytes = 0
            var scannedChunks = 0
            for document in scanned.values {
                try deadline.check()
                guard document.descriptor.utf8ByteCount <= bootstrapLimits.maximumDecodedTextBytes,
                      scannedBytes <= bootstrapLimits.maximumDecodedTextBytes - document.descriptor.utf8ByteCount else {
                    throw LocalKnowledgeStoreError.storeCapacityExceeded(
                        maximumBytes: bootstrapLimits.maximumDecodedTextBytes
                    )
                }
                scannedBytes += document.descriptor.utf8ByteCount
                guard document.chunks.count <= bootstrapLimits.maximumTotalChunks,
                      scannedChunks <= bootstrapLimits.maximumTotalChunks - document.chunks.count else {
                    throw LocalKnowledgeStoreError.indexChunkLimitExceeded(
                        maximumChunks: bootstrapLimits.maximumTotalChunks
                    )
                }
                scannedChunks += document.chunks.count
            }
            guard scannedBytes <= bootstrapLimits.maximumDecodedTextBytes else {
                throw LocalKnowledgeStoreError.storeCapacityExceeded(
                    maximumBytes: bootstrapLimits.maximumDecodedTextBytes
                )
            }
            let catalogIDs = Set(catalog?.documentIDs ?? [])
            let scannedIDs = Set(scanned.keys)
            report.recoveredOrphanDocuments = scannedIDs.subtracting(catalogIDs).count
            report.missingCatalogDocuments = catalogIDs.subtracting(scannedIDs).count

            var resolvedGeneration = catalog?.generation ?? 0
            if catalog == nil || catalogIDs != scannedIDs {
                guard resolvedGeneration < UInt64.max else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                resolvedGeneration += 1
                try deadline.check()
                try requireActiveLoad(loadToken)
                try persistCatalog(ids: Array(scannedIDs), generation: resolvedGeneration)
            }
            let index = try buildSearchIndex(
                documents: scanned,
                deadline: deadline,
                loadToken: loadToken
            )
            try revalidatePublishedObjects(
                expected: loaded.identities,
                initialRoot: rootScan,
                initialObjects: objectScan,
                deadline: deadline
            )
            _ = try scanAndValidateRecovery(deadline: deadline)
            try deadline.check()
            try requireActiveLoad(loadToken)
            return BootstrapSnapshot(
                generation: resolvedGeneration,
                documents: scanned,
                index: index,
                report: report
            )
        } catch let error as LocalKnowledgeStoreError {
            throw error
        } catch {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }

    private func validateRootEntries(_ entries: [ScannedDirectoryEntry]) throws {
        let allowed = Set(["Objects", "Recovery", "Trash", "Transactions", "catalog.json"])
        for entry in entries {
            if ["Objects", "Recovery", "Trash", "Transactions"].contains(entry.name) {
                try requirePrivateDirectory(entry)
                continue
            }
            if entry.name == "catalog.json" {
                try requirePrivateRegular(entry, maximumBytes: Self.maximumCatalogBytes)
                continue
            }
            if Self.isInterruptedTemporaryFile(entry.url) {
                try requirePrivateRegular(entry, maximumBytes: Self.maximumCatalogBytes)
                continue
            }
            guard allowed.contains(entry.name) else {
                throw LocalKnowledgeStoreError.unsafeStoreEntry(entry.name)
            }
        }
    }

    private func validateObjectEntries(_ entries: [ScannedDirectoryEntry]) throws {
        for entry in entries {
            if Self.isInterruptedTemporaryFile(entry.url) {
                try requirePrivateRegular(entry, maximumBytes: Self.maximumObjectBytes)
                continue
            }
            _ = try validateObjectFilename(entry.url)
            try requirePrivateRegular(entry, maximumBytes: Self.maximumObjectBytes)
        }
    }

    private func validateRecoveryEntries(_ entries: [ScannedDirectoryEntry]) throws {
        for entry in entries {
            guard Self.isSafeStoredFilename(entry.name) else {
                throw LocalKnowledgeStoreError.unsafeStoreEntry(entry.name)
            }
            try requirePrivateRegular(entry, maximumBytes: Self.maximumObjectBytes)
        }
    }

    private func preflightFutureSchemas(
        rootEntries: [ScannedDirectoryEntry],
        objectEntries: [ScannedDirectoryEntry],
        deadline: ScanDeadline,
        loadToken: UUID
    ) throws {
        if let catalog = rootEntries.first(where: { $0.name == "catalog.json" }) {
            let version = try preflightSchemaVersion(
                at: catalog.url,
                maximumBytes: Self.maximumCatalogBytes,
                expected: catalog,
                deadline: deadline
            )
            if let version, version > Self.schemaVersion {
                throw LocalKnowledgeStoreError.futureSchema(found: version, supported: Self.schemaVersion)
            }
        }
        for entry in objectEntries {
            try deadline.check()
            try requireActiveLoad(loadToken)
            if Self.isInterruptedTemporaryFile(entry.url) { continue }
            let version = try preflightSchemaVersion(
                at: entry.url,
                maximumBytes: Self.maximumObjectBytes,
                expected: entry,
                deadline: deadline
            )
            if let version, version > Self.schemaVersion {
                throw LocalKnowledgeStoreError.futureSchema(found: version, supported: Self.schemaVersion)
            }
        }
    }

    private func preflightSchemaVersion(
        at url: URL,
        maximumBytes: Int,
        expected: ScannedDirectoryEntry,
        deadline: ScanDeadline
    ) throws -> Int? {
        do {
            return try Self.schemaVersion(
                at: url,
                maximumBytes: maximumBytes,
                expected: expected,
                deadline: deadline
            )
        } catch let error as LocalKnowledgeStoreError {
            if Self.isRecoverableCorruption(error) { return nil }
            throw error
        } catch {
            return nil
        }
    }

    private func loadCatalogRecoveringCorruption(
        report: inout KnowledgeRecoveryReport,
        capacity: inout RecoveryCapacity,
        deadline: ScanDeadline,
        loadToken: UUID
    ) throws -> CatalogEnvelope? {
        guard Self.entryExists(catalogURL) else { return nil }
        do {
            try deadline.check()
            try requireActiveLoad(loadToken)
            let data = try Self.readRegularFile(
                at: catalogURL,
                maximumBytes: Self.maximumCatalogBytes,
                oversizeError: .storageUnavailable,
                unsafeError: .unsafeStoreEntry("catalog.json"),
                deadline: deadline
            )
            if let version = Self.schemaVersion(in: data), version > Self.schemaVersion {
                throw LocalKnowledgeStoreError.futureSchema(found: version, supported: Self.schemaVersion)
            }
            let catalog = try JSONDecoder().decode(CatalogEnvelope.self, from: data)
            guard catalog.schemaVersion == Self.schemaVersion,
                  catalog.generation > 0,
                  Set(catalog.documentIDs).count == catalog.documentIDs.count else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            return catalog
        } catch let error as LocalKnowledgeStoreError {
            guard Self.isRecoverableCorruption(error) else { throw error }
            try preserveForRecovery(
                catalogURL,
                label: "catalog-corrupt",
                capacity: &capacity,
                deadline: deadline
            )
            report.recoveredCatalog = true
            return nil
        } catch {
            try preserveForRecovery(
                catalogURL,
                label: "catalog-corrupt",
                capacity: &capacity,
                deadline: deadline
            )
            report.recoveredCatalog = true
            return nil
        }
    }

    private func loadDocumentObjectsRecoveringCorruption(
        entries: [ScannedDirectoryEntry],
        report: inout KnowledgeRecoveryReport,
        capacity: inout RecoveryCapacity,
        deadline: ScanDeadline,
        loadToken: UUID
    ) throws -> (
        documents: [UUID: StoredDocument],
        identities: [UUID: ScannedDirectoryEntry]
    ) {
        var result: [UUID: StoredDocument] = [:]
        var identities: [UUID: ScannedDirectoryEntry] = [:]
        for entry in entries.sorted(by: { $0.name < $1.name }) {
            try deadline.check()
            try requireActiveLoad(loadToken)
            let id = try validateObjectFilename(entry.url)
            do {
                let data = try Self.readRegularFile(
                    at: entry.url,
                    maximumBytes: Self.maximumObjectBytes,
                    oversizeError: .storageUnavailable,
                    unsafeError: .unsafeStoreEntry(entry.name),
                    expected: entry,
                    deadline: deadline
                )
                if let version = Self.schemaVersion(in: data), version > Self.schemaVersion {
                    throw LocalKnowledgeStoreError.futureSchema(found: version, supported: Self.schemaVersion)
                }
                let envelope = try JSONDecoder().decode(DocumentEnvelope.self, from: data)
                guard envelope.schemaVersion == Self.schemaVersion,
                      envelope.descriptor.id == id else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                let stored = try validateLoadedDocument(envelope)
                guard result[id] == nil else { throw LocalKnowledgeStoreError.storageUnavailable }
                result[id] = stored
                identities[id] = entry
            } catch let error as LocalKnowledgeStoreError {
                guard Self.isRecoverableCorruption(error) else { throw error }
                try preserveForRecovery(
                    entry.url,
                    label: "document-\(id.uuidString.lowercased())-corrupt",
                    capacity: &capacity,
                    deadline: deadline
                )
                report.quarantinedDocuments += 1
            } catch {
                try preserveForRecovery(
                    entry.url,
                    label: "document-\(id.uuidString.lowercased())-corrupt",
                    capacity: &capacity,
                    deadline: deadline
                )
                report.quarantinedDocuments += 1
            }
        }
        return (result, identities)
    }

    private func validateLoadedDocument(_ envelope: DocumentEnvelope) throws -> StoredDocument {
        try validate(scope: envelope.descriptor.scope)
        guard (try? validate(title: envelope.descriptor.title)) != nil,
              envelope.descriptor.sourceName.map(Self.isSafeSourceName) ?? true,
              Self.isSHA256(envelope.descriptor.sourceSHA256),
              Self.isSHA256(envelope.descriptor.contentSHA256),
              envelope.descriptor.createdAt.timeIntervalSinceReferenceDate.isFinite,
              envelope.descriptor.updatedAt.timeIntervalSinceReferenceDate.isFinite,
              envelope.descriptor.updatedAt >= envelope.descriptor.createdAt else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        if envelope.descriptor.sourceKind == .memoryNote {
            guard envelope.descriptor.sourceName == nil,
                  envelope.descriptor.sourceSHA256 == envelope.descriptor.contentSHA256 else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        } else {
            guard envelope.descriptor.sourceName != nil else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        }
        let normalized = try normalizeAndValidate(text: envelope.text)
        guard normalized == envelope.text else { throw LocalKnowledgeStoreError.storageUnavailable }
        let chunks = try Self.chunk(normalized)
        guard envelope.descriptor.characterCount == normalized.count,
              envelope.descriptor.utf8ByteCount == normalized.utf8.count,
              envelope.descriptor.chunkCount == chunks.count,
              envelope.descriptor.contentSHA256 == Self.sha256(Data(normalized.utf8)) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        return StoredDocument(descriptor: envelope.descriptor, text: normalized, chunks: chunks)
    }

    private func persistCatalog(ids: [UUID], generation: UInt64) throws {
        let data = try encodeCatalog(ids: ids, generation: generation)
        try Self.atomicPrivateWrite(data, to: catalogURL, fileManager: fileManager, secureParent: true)
    }

    private func encodeCatalog(ids: [UUID], generation: UInt64) throws -> Data {
        let catalog = CatalogEnvelope(
            schemaVersion: Self.schemaVersion,
            generation: generation,
            documentIDs: ids.sorted { $0.uuidString.lowercased() < $1.uuidString.lowercased() }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(catalog)
        guard data.count <= Self.maximumCatalogBytes else { throw LocalKnowledgeStoreError.storageUnavailable }
        return data
    }

    /// Commits the object set and its catalog as one crash-recoverable mutation.
    /// The journal is durable before any authoritative path moves. An absent
    /// commit marker always means rollback; a durable marker means the new object
    /// set and catalog were both fsynced and must survive relaunch.
    private func commitMutation(
        candidateDocuments: [UUID: StoredDocument],
        replacements: [UUID: ObjectMutation],
        newGeneration: UInt64
    ) throws {
        guard !replacements.isEmpty,
              newGeneration == generation + 1,
              newGeneration > generation else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        try Self.ensurePrivateDirectory(transactionsURL, fileManager: fileManager)
        let transactionID = UUID()
        let transactionURL = transactionsURL.appendingPathComponent(
            transactionID.uuidString.lowercased(),
            isDirectory: true
        )
        let oldObjectsURL = transactionURL.appendingPathComponent("Objects", isDirectory: true)

        let affected = replacements.keys.sorted {
            $0.uuidString.lowercased() < $1.uuidString.lowercased()
        }
        let affectedNames = affected.map { objectURL(for: $0).lastPathComponent }
        let previousNames = affected.filter { documents[$0] != nil }.map {
            objectURL(for: $0).lastPathComponent
        }
        let oldCatalogData = try Self.readRegularFile(
            at: catalogURL,
            maximumBytes: Self.maximumCatalogBytes,
            oversizeError: .storageUnavailable,
            unsafeError: .unsafeStoreEntry("catalog.json")
        )
        let oldCatalog = try JSONDecoder().decode(CatalogEnvelope.self, from: oldCatalogData)
        guard oldCatalog.schemaVersion == Self.schemaVersion,
              oldCatalog.generation == generation else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        var previousDigests: [String: String] = [:]
        for id in affected where documents[id] != nil {
            let source = objectURL(for: id)
            let data = try Self.readRegularFile(
                at: source,
                maximumBytes: Self.maximumObjectBytes,
                oversizeError: .storageUnavailable,
                unsafeError: .unsafeStoreEntry(source.lastPathComponent)
            )
            previousDigests[source.lastPathComponent] = Self.sha256(data)
        }
        let journal = MutationJournal(
            schemaVersion: Self.mutationJournalSchemaVersion,
            transactionID: transactionID,
            oldGeneration: generation,
            newGeneration: newGeneration,
            affectedObjectNames: affectedNames,
            previousObjectNames: previousNames,
            oldCatalogSHA256: Self.sha256(oldCatalogData),
            previousObjectSHA256: previousDigests
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let journalData = try encoder.encode(journal)
        guard journalData.count <= Self.maximumCatalogBytes else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        try Self.ensurePrivateDirectory(transactionURL, fileManager: fileManager)
        try Self.ensurePrivateDirectory(oldObjectsURL, fileManager: fileManager)
        let manifestURL = transactionURL.appendingPathComponent("manifest.json")
        try Self.atomicPrivateWrite(journalData, to: manifestURL, fileManager: fileManager, secureParent: true)
        try Self.syncPrivateDirectory(transactionURL)
        try Self.syncPrivateDirectory(transactionsURL)

        var committed = false
        do {
            try mutationBoundary(.journalDurable)
            for (index, id) in affected.enumerated() where documents[id] != nil {
                let source = objectURL(for: id)
                let destination = oldObjectsURL.appendingPathComponent(source.lastPathComponent)
                try Self.requireRegularNonSymlink(
                    source,
                    unsafeError: .unsafeStoreEntry(source.lastPathComponent)
                )
                guard !Self.entryExists(destination), Darwin.rename(source.path, destination.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                try mutationBoundary(.objectEvacuated(index))
            }

            let oldCatalogURL = transactionURL.appendingPathComponent("old-catalog.json")
            try Self.requireRegularNonSymlink(
                catalogURL,
                unsafeError: .unsafeStoreEntry("catalog.json")
            )
            guard Darwin.rename(catalogURL.path, oldCatalogURL.path) == 0 else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            try mutationBoundary(.catalogEvacuated)
            try Self.syncPrivateDirectory(oldObjectsURL)
            try Self.syncPrivateDirectory(objectsURL)
            try Self.syncPrivateDirectory(transactionURL)
            try Self.syncPrivateDirectory(rootURL)

            for (index, id) in affected.enumerated() {
                guard let replacement = replacements[id] else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                switch replacement {
                case .write(let data):
                    try Self.atomicPrivateWrite(
                        data,
                        to: objectURL(for: id),
                        fileManager: fileManager,
                        secureParent: true
                    )
                case .remove:
                    guard !Self.entryExists(objectURL(for: id)) else {
                        throw LocalKnowledgeStoreError.storageUnavailable
                    }
                }
                try mutationBoundary(.replacementWritten(index))
            }
            try Self.syncPrivateDirectory(objectsURL)
            try mutationBoundary(.objectDirectoryDurable)

            let newCatalog = try encodeCatalog(
                ids: Array(candidateDocuments.keys),
                generation: newGeneration
            )
            try Self.atomicPrivateWrite(
                newCatalog,
                to: catalogURL,
                fileManager: fileManager,
                secureParent: true
            )
            try mutationBoundary(.catalogWritten)
            try Self.syncPrivateDirectory(rootURL)
            try mutationBoundary(.rootDirectoryDurable)

            let marker = transactionURL.appendingPathComponent("committed")
            try Self.atomicPrivateWrite(
                Data("committed\n".utf8),
                to: marker,
                fileManager: fileManager,
                secureParent: true
            )
            try Self.syncPrivateDirectory(transactionURL)
            committed = true
            try mutationBoundary(.commitMarkerDurable)
        } catch is LocalKnowledgeSimulatedProcessLoss {
            // A real process would be gone. Leaving the exact journal bytes lets
            // a new instance prove rollback-vs-commit deterministically.
            throw LocalKnowledgeSimulatedProcessLoss.interrupt
        } catch {
            if committed {
                // No production operation remains after the durable commit point;
                // a diagnostic hook failure cannot turn committed bytes into a
                // reported application failure.
            } else {
                do {
                    try rollbackMutation(transactionURL: transactionURL, journal: journal)
                } catch {
                    markUnavailableAfterIndeterminateMutation()
                    throw LocalKnowledgeStoreError.mutationRollbackIncomplete
                }
                if let known = error as? LocalKnowledgeStoreError { throw known }
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        }

        let deferred = trashURL.appendingPathComponent(
            "committed-mutation-\(transactionID.uuidString.lowercased())",
            isDirectory: true
        )
        do {
            try mutationBoundary(.committedCleanupStarted)
            if Darwin.rename(transactionURL.path, deferred.path) == 0 {
                try Self.syncPrivateDirectory(transactionsURL)
                try Self.syncPrivateDirectory(trashURL)
            }
        } catch {
            // The authoritative commit is already durable. Recovery accepts and
            // retires historical committed journals when a later generation is
            // fully present, so cleanup is diagnostics/space maintenance only.
        }
    }

    private func rollbackMutation(
        transactionURL: URL,
        journal: MutationJournal,
        deadline: ScanDeadline? = nil
    ) throws {
        try mutationBoundary(.rollbackStarted)
        let oldObjectsURL = transactionURL.appendingPathComponent("Objects", isDirectory: true)
        let previous = Set(journal.previousObjectNames)
        for (index, name) in journal.affectedObjectNames.enumerated() {
            let destination = objectsURL.appendingPathComponent(name)
            let preserved = oldObjectsURL.appendingPathComponent(name)
            if Self.entryExists(preserved) {
                try Self.requireRegularNonSymlink(
                    preserved,
                    unsafeError: .unsafeStoreEntry(name)
                )
                try verifyJournalDigest(
                    at: preserved,
                    expected: journal.previousObjectSHA256[name],
                    maximumBytes: Self.maximumObjectBytes
                )
                if Self.entryExists(destination) {
                    try Self.requireRegularNonSymlink(
                        destination,
                        unsafeError: .unsafeStoreEntry(name)
                    )
                    guard Darwin.unlink(destination.path) == 0 else {
                        throw LocalKnowledgeStoreError.storageUnavailable
                    }
                }
                guard Darwin.rename(preserved.path, destination.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
            } else if previous.contains(name) {
                // It may not have been evacuated yet. In that case the exact old
                // object must still be present at the authoritative path.
                guard Self.entryExists(destination) else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                try verifyJournalDigest(
                    at: destination,
                    expected: journal.previousObjectSHA256[name],
                    maximumBytes: Self.maximumObjectBytes
                )
            } else if Self.entryExists(destination) {
                try Self.requireRegularNonSymlink(
                    destination,
                    unsafeError: .unsafeStoreEntry(name)
                )
                guard Darwin.unlink(destination.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
            }
            try mutationBoundary(.rollbackObjectRestored(index))
        }
        try Self.syncPrivateDirectory(oldObjectsURL)
        try Self.syncPrivateDirectory(objectsURL)

        let preservedCatalog = transactionURL.appendingPathComponent("old-catalog.json")
        if Self.entryExists(preservedCatalog) {
            try Self.requireRegularNonSymlink(
                preservedCatalog,
                unsafeError: .unsafeStoreEntry("old-catalog.json")
            )
            try verifyJournalDigest(
                at: preservedCatalog,
                expected: journal.oldCatalogSHA256,
                maximumBytes: Self.maximumCatalogBytes
            )
            if Self.entryExists(catalogURL) {
                try Self.requireRegularNonSymlink(
                    catalogURL,
                    unsafeError: .unsafeStoreEntry("catalog.json")
                )
                guard Darwin.unlink(catalogURL.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
            }
            guard Darwin.rename(preservedCatalog.path, catalogURL.path) == 0 else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        } else {
            let data = try Self.readRegularFile(
                at: catalogURL,
                maximumBytes: Self.maximumCatalogBytes,
                oversizeError: .storageUnavailable,
                unsafeError: .unsafeStoreEntry("catalog.json")
            )
            guard Self.sha256(data) == journal.oldCatalogSHA256 else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            let catalog = try JSONDecoder().decode(CatalogEnvelope.self, from: data)
            guard catalog.schemaVersion == Self.schemaVersion,
                  catalog.generation == journal.oldGeneration else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        }
        try Self.syncPrivateDirectory(transactionURL)
        try Self.syncPrivateDirectory(rootURL)
        try mutationBoundary(.rollbackCatalogRestored)
        try removeTransactionDirectory(transactionURL, journal: journal, deadline: deadline)
    }

    private func markUnavailableAfterIndeterminateMutation() {
        statusLock.lock()
        availabilityValue = .unavailable(LocalKnowledgeStoreError.mutationRollbackIncomplete.localizedDescription)
        loadFailure = .mutationRollbackIncomplete
        statusLock.unlock()
        notifyStatusChange()
    }

    private func verifyJournalDigest(
        at url: URL,
        expected: String?,
        maximumBytes: Int
    ) throws {
        guard let expected, Self.isSHA256(expected) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        let data = try Self.readRegularFile(
            at: url,
            maximumBytes: maximumBytes,
            oversizeError: .storageUnavailable,
            unsafeError: .unsafeStoreEntry(url.lastPathComponent)
        )
        guard Self.sha256(data) == expected else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }

    private func encodeDocument(descriptor: KnowledgeDocumentDescriptor, text: String) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(DocumentEnvelope(
            schemaVersion: Self.schemaVersion,
            descriptor: descriptor,
            text: text
        ))
        guard data.count <= Self.maximumObjectBytes else {
            throw LocalKnowledgeStoreError.contentTooLarge(maximumBytes: LocalKnowledgeLimits.maximumExtractedUTF8Bytes)
        }
        return data
    }

    private func insert(
        title: String,
        text: String,
        scope: KnowledgeScope,
        sourceKind: KnowledgeSourceKind,
        sourceName: String?,
        sourceDigest: String,
        createdAt: Date
    ) throws -> KnowledgeDocumentDescriptor {
        guard createdAt.timeIntervalSinceReferenceDate.isFinite else {
            throw LocalKnowledgeStoreError.invalidTimestamp
        }
        guard documents.count < bootstrapLimits.maximumDocuments else {
            throw LocalKnowledgeStoreError.documentLimitReached(maximum: bootstrapLimits.maximumDocuments)
        }
        let chunks = try Self.chunk(text)
        try validateCapacity(replacing: 0, with: text.utf8.count)
        let id = try uniqueDocumentID()
        let contentDigest = Self.sha256(Data(text.utf8))
        let descriptor = KnowledgeDocumentDescriptor(
            id: id,
            scope: scope,
            sourceKind: sourceKind,
            title: title,
            sourceName: sourceName,
            sourceSHA256: sourceDigest,
            contentSHA256: contentDigest,
            createdAt: createdAt,
            updatedAt: createdAt,
            characterCount: text.count,
            utf8ByteCount: text.utf8.count,
            chunkCount: chunks.count
        )
        let stored = StoredDocument(descriptor: descriptor, text: text, chunks: chunks)
        var candidateDocuments = documents
        candidateDocuments[id] = stored
        let candidateIndex = try buildSearchIndex(documents: candidateDocuments)
        let data = try encodeDocument(descriptor: descriptor, text: text)
        guard generation < UInt64.max else { throw LocalKnowledgeStoreError.storageUnavailable }
        try commitMutation(
            candidateDocuments: candidateDocuments,
            replacements: [id: .write(data)],
            newGeneration: generation + 1
        )
        documents = candidateDocuments
        generation += 1
        indexedChunks = candidateIndex.indexedChunks
        postings = candidateIndex.postings
        markTrashCleanupPendingOnQueue()
        return descriptor
    }

    private func validateCapacity(replacing oldBytes: Int, with newBytes: Int) throws {
        let current = documents.values.reduce(0) { $0 + $1.descriptor.utf8ByteCount }
        guard current - oldBytes + newBytes <= bootstrapLimits.maximumDecodedTextBytes else {
            throw LocalKnowledgeStoreError.storeCapacityExceeded(
                maximumBytes: bootstrapLimits.maximumDecodedTextBytes
            )
        }
    }

    private func uniqueDocumentID() throws -> UUID {
        for _ in 0..<16 {
            let candidate = idGenerator()
            if documents[candidate] == nil, !Self.entryExists(objectURL(for: candidate)) {
                return candidate
            }
        }
        throw LocalKnowledgeStoreError.storageUnavailable
    }

    private func objectURL(for id: UUID) -> URL {
        objectsURL.appendingPathComponent("\(id.uuidString.lowercased()).json")
    }

    private func validateObjectFilename(_ url: URL) throws -> UUID {
        guard url.pathExtension == "json",
              let id = UUID(uuidString: url.deletingPathExtension().lastPathComponent),
              url.lastPathComponent == "\(id.uuidString.lowercased()).json" else {
            throw LocalKnowledgeStoreError.unsafeStoreEntry(url.lastPathComponent)
        }
        return id
    }

    private func preserveInterruptedTemporaryFiles(
        _ entries: [ScannedDirectoryEntry],
        capacity: inout RecoveryCapacity,
        deadline: ScanDeadline,
        loadToken: UUID
    ) throws -> Int {
        var preserved = 0
        for entry in entries {
            try deadline.check()
            try requireActiveLoad(loadToken)
            guard Self.isInterruptedTemporaryFile(entry.url) else { continue }
            try requirePrivateRegular(entry, maximumBytes: Self.maximumObjectBytes)
            try preserveForRecovery(
                entry.url,
                label: "interrupted-write",
                capacity: &capacity,
                deadline: deadline
            )
            preserved += 1
        }
        return preserved
    }

    private static func isInterruptedTemporaryFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return name.hasPrefix(".") && name.hasSuffix(".tmp")
    }

    private func preserveForRecovery(
        _ source: URL,
        label: String,
        capacity: inout RecoveryCapacity,
        deadline: ScanDeadline
    ) throws {
        try deadline.check()
        var value = stat()
        guard lstat(source.path, &value) == 0,
              Self.isPrivateOwnedRegular(value),
              value.st_size >= 0,
              value.st_size <= off_t(Self.maximumObjectBytes) else {
            throw LocalKnowledgeStoreError.unsafeStoreEntry(source.lastPathComponent)
        }
        let bytes = Int(value.st_size)
        guard capacity.entries < bootstrapLimits.maximumRecoveryEntries else {
            throw LocalKnowledgeStoreError.directoryEntryLimitExceeded(
                maximum: bootstrapLimits.maximumRecoveryEntries
            )
        }
        guard bytes <= bootstrapLimits.maximumRecoveryBytes,
              capacity.bytes <= bootstrapLimits.maximumRecoveryBytes - bytes else {
            throw LocalKnowledgeStoreError.aggregateStorageLimitExceeded(
                maximumBytes: bootstrapLimits.maximumRecoveryBytes
            )
        }
        let destination = recoveryURL.appendingPathComponent("\(label)-\(UUID().uuidString).json")
        do {
            try fileManager.moveItem(at: source, to: destination)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            capacity.entries += 1
            capacity.bytes += bytes
        } catch {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }

    private func scanDirectory(
        _ directory: URL,
        maximumEntries: Int,
        maximumBytes: Int,
        deadline: ScanDeadline
    ) throws -> ScannedDirectory {
        try deadline.check()
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw LocalKnowledgeStoreError.unsafeStoreEntry(directory.lastPathComponent)
        }
        var initial = stat()
        guard fstat(descriptor, &initial) == 0,
              Self.isPrivateOwnedDirectory(initial) else {
            Darwin.close(descriptor)
            throw LocalKnowledgeStoreError.unsafeStoreEntry(directory.lastPathComponent)
        }
        guard let stream = fdopendir(descriptor) else {
            Darwin.close(descriptor)
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        var streamOpen = true
        defer { if streamOpen { closedir(stream) } }

        var entries: [ScannedDirectoryEntry] = []
        entries.reserveCapacity(min(maximumEntries, 4_096))
        var aggregateBytes = 0
        var aggregateNameBytes = 0
        while true {
            try deadline.check()
            errno = 0
            guard let raw = readdir(stream) else {
                guard errno == 0 else { throw LocalKnowledgeStoreError.storageUnavailable }
                break
            }
            try deadline.check()
            guard let name = DarwinDirectoryEntry.name(raw) else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            if name == "." || name == ".." { continue }
            let nameBytes = name.utf8.count
            guard nameBytes > 0, nameBytes <= bootstrapLimits.maximumFilenameBytes else {
                throw LocalKnowledgeStoreError.unsafeStoreEntry(name)
            }
            guard aggregateNameBytes <= bootstrapLimits.maximumAggregateFilenameBytes - nameBytes else {
                throw LocalKnowledgeStoreError.aggregateFilenameLimitExceeded(
                    maximumBytes: bootstrapLimits.maximumAggregateFilenameBytes
                )
            }
            guard entries.count < maximumEntries else {
                throw LocalKnowledgeStoreError.directoryEntryLimitExceeded(maximum: maximumEntries)
            }
            var value = stat()
            guard fstatat(descriptor, name, &value, AT_SYMLINK_NOFOLLOW) == 0,
                  value.st_size >= 0 else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            let bytes = (value.st_mode & S_IFMT) == S_IFREG ? Int(value.st_size) : 0
            guard bytes <= maximumBytes, aggregateBytes <= maximumBytes - bytes else {
                throw LocalKnowledgeStoreError.aggregateStorageLimitExceeded(maximumBytes: maximumBytes)
            }
            aggregateBytes += bytes
            aggregateNameBytes += nameBytes
            entries.append(ScannedDirectoryEntry(
                url: directory.appendingPathComponent(name, isDirectory: false),
                name: name,
                device: value.st_dev,
                inode: value.st_ino,
                mode: value.st_mode,
                owner: value.st_uid,
                links: value.st_nlink,
                bytes: bytes
            ))
        }

        var final = stat()
        var current = stat()
        guard fstat(descriptor, &final) == 0,
              Self.isPrivateOwnedDirectory(final),
              final.st_dev == initial.st_dev,
              final.st_ino == initial.st_ino,
              lstat(directory.path, &current) == 0,
              Self.isPrivateOwnedDirectory(current),
              current.st_dev == initial.st_dev,
              current.st_ino == initial.st_ino else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        guard closedir(stream) == 0 else {
            streamOpen = false
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        streamOpen = false
        return ScannedDirectory(device: initial.st_dev, inode: initial.st_ino, entries: entries)
    }

    private func requirePrivateRegular(
        _ entry: ScannedDirectoryEntry,
        maximumBytes: Int
    ) throws {
        guard (entry.mode & S_IFMT) == S_IFREG,
              entry.owner == geteuid(),
              entry.links == 1,
              (entry.mode & 0o077) == 0,
              entry.bytes <= maximumBytes else {
            throw LocalKnowledgeStoreError.unsafeStoreEntry(entry.name)
        }
    }

    private func requirePrivateDirectory(_ entry: ScannedDirectoryEntry) throws {
        guard (entry.mode & S_IFMT) == S_IFDIR,
              entry.owner == geteuid(),
              entry.links >= 1,
              (entry.mode & 0o077) == 0 else {
            throw LocalKnowledgeStoreError.unsafeStoreEntry(entry.name)
        }
    }

    private func scanAndValidateRecovery(deadline: ScanDeadline) throws -> ScannedDirectory {
        let scan = try scanDirectory(
            recoveryURL,
            maximumEntries: bootstrapLimits.maximumRecoveryEntries,
            maximumBytes: bootstrapLimits.maximumRecoveryBytes,
            deadline: deadline
        )
        try validateRecoveryEntries(scan.entries)
        return scan
    }

    private func revalidatePublishedObjects(
        expected: [UUID: ScannedDirectoryEntry],
        initialRoot: ScannedDirectory,
        initialObjects: ScannedDirectory,
        deadline: ScanDeadline
    ) throws {
        let finalRoot = try scanDirectory(
            rootURL,
            maximumEntries: bootstrapLimits.maximumRootEntries,
            maximumBytes: bootstrapLimits.maximumRawObjectBytes,
            deadline: deadline
        )
        guard finalRoot.device == initialRoot.device, finalRoot.inode == initialRoot.inode else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        try validateRootEntries(finalRoot.entries)
        let finalObjects = try scanDirectory(
            objectsURL,
            maximumEntries: bootstrapLimits.maximumObjectEntries,
            maximumBytes: bootstrapLimits.maximumRawObjectBytes,
            deadline: deadline
        )
        guard finalObjects.device == initialObjects.device,
              finalObjects.inode == initialObjects.inode else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        try validateObjectEntries(finalObjects.entries)
        let current = finalObjects.entries.filter { !Self.isInterruptedTemporaryFile($0.url) }
        guard current.count == expected.count else { throw LocalKnowledgeStoreError.storageUnavailable }
        for entry in current {
            let id = try validateObjectFilename(entry.url)
            guard let trusted = expected[id],
                  entry.device == trusted.device,
                  entry.inode == trusted.inode,
                  entry.bytes == trusted.bytes else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        }
    }

    private func reconcileInterruptedMutations(
        deadline: ScanDeadline,
        loadToken: UUID
    ) throws {
        let transactions = try scanDirectory(
            transactionsURL,
            maximumEntries: bootstrapLimits.maximumTransactionEntries,
            maximumBytes: bootstrapLimits.maximumTransactionBytes,
            deadline: deadline
        )
        var aggregateEntries = transactions.entries.count
        var aggregateBytes = 0
        var aggregateNames = transactions.entries.reduce(0) { $0 + $1.name.utf8.count }
        for entry in transactions.entries.sorted(by: { $0.name < $1.name }) {
            try deadline.check()
            try requireActiveLoad(loadToken)
            try requirePrivateDirectory(entry)
            guard let id = UUID(uuidString: entry.name),
                  entry.name == id.uuidString.lowercased() else {
                throw LocalKnowledgeStoreError.unsafeStoreEntry(entry.name)
            }
            var transactionScan = try scanDirectory(
                entry.url,
                maximumEntries: 8,
                maximumBytes: Self.maximumCatalogBytes * 3,
                deadline: deadline
            )
            for temporary in transactionScan.entries where Self.isInterruptedTemporaryFile(temporary.url) {
                try requirePrivateRegular(temporary, maximumBytes: Self.maximumCatalogBytes)
                guard Darwin.unlink(temporary.url.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
            }
            if transactionScan.entries.contains(where: { Self.isInterruptedTemporaryFile($0.url) }) {
                try Self.syncPrivateDirectory(entry.url)
                transactionScan = try scanDirectory(
                    entry.url,
                    maximumEntries: 8,
                    maximumBytes: Self.maximumCatalogBytes * 3,
                    deadline: deadline
                )
            }
            let allowed = Set(["manifest.json", "old-catalog.json", "committed", "Objects"])
            guard transactionScan.entries.allSatisfy({ allowed.contains($0.name) }) else {
                throw LocalKnowledgeStoreError.unsafeStoreEntry(entry.name)
            }
            guard let objectsEntry = transactionScan.entries.first(where: { $0.name == "Objects" }) else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            try requirePrivateDirectory(objectsEntry)
            let oldObjects = try scanDirectory(
                objectsEntry.url,
                maximumEntries: bootstrapLimits.maximumTransactionEntries,
                maximumBytes: bootstrapLimits.maximumTransactionBytes,
                deadline: deadline
            )
            for old in oldObjects.entries {
                _ = try validateObjectFilename(old.url)
                try requirePrivateRegular(old, maximumBytes: Self.maximumObjectBytes)
            }
            aggregateEntries += transactionScan.entries.count + oldObjects.entries.count
            aggregateBytes += transactionScan.entries.reduce(0) { $0 + $1.bytes }
            aggregateBytes += oldObjects.entries.reduce(0) { $0 + $1.bytes }
            aggregateNames += transactionScan.entries.reduce(0) { $0 + $1.name.utf8.count }
            aggregateNames += oldObjects.entries.reduce(0) { $0 + $1.name.utf8.count }
            guard aggregateEntries <= bootstrapLimits.maximumTransactionEntries else {
                throw LocalKnowledgeStoreError.directoryEntryLimitExceeded(
                    maximum: bootstrapLimits.maximumTransactionEntries
                )
            }
            guard aggregateBytes <= bootstrapLimits.maximumTransactionBytes else {
                throw LocalKnowledgeStoreError.aggregateStorageLimitExceeded(
                    maximumBytes: bootstrapLimits.maximumTransactionBytes
                )
            }
            guard aggregateNames <= bootstrapLimits.maximumAggregateFilenameBytes else {
                throw LocalKnowledgeStoreError.aggregateFilenameLimitExceeded(
                    maximumBytes: bootstrapLimits.maximumAggregateFilenameBytes
                )
            }

            guard let manifest = transactionScan.entries.first(where: { $0.name == "manifest.json" }) else {
                // No authoritative path is ever moved before the manifest and its
                // parent directory are durable. An empty pre-manifest shell is safe
                // to remove after validating that it contains no preserved state.
                guard oldObjects.entries.isEmpty,
                      transactionScan.entries.allSatisfy({ $0.name == "Objects" }) else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                _ = rmdir(objectsEntry.url.path)
                guard rmdir(entry.url.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                try Self.syncPrivateDirectory(transactionsURL)
                continue
            }
            try requirePrivateRegular(manifest, maximumBytes: Self.maximumCatalogBytes)
            let manifestData = try Self.readRegularFile(
                at: manifest.url,
                maximumBytes: Self.maximumCatalogBytes,
                oversizeError: .storageUnavailable,
                unsafeError: .unsafeStoreEntry("manifest.json"),
                expected: manifest,
                deadline: deadline
            )
            let journal = try JSONDecoder().decode(MutationJournal.self, from: manifestData)
            try validateMutationJournal(journal, expectedID: id, oldObjects: oldObjects.entries)

            if let marker = transactionScan.entries.first(where: { $0.name == "committed" }) {
                try requirePrivateRegular(marker, maximumBytes: 32)
                let catalogData = try Self.readRegularFile(
                    at: catalogURL,
                    maximumBytes: Self.maximumCatalogBytes,
                    oversizeError: .storageUnavailable,
                    unsafeError: .unsafeStoreEntry("catalog.json"),
                    deadline: deadline
                )
                let catalog = try JSONDecoder().decode(CatalogEnvelope.self, from: catalogData)
                guard catalog.schemaVersion == Self.schemaVersion,
                      catalog.generation >= journal.newGeneration else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
                try removeTransactionDirectory(entry.url, journal: journal, deadline: deadline)
            } else {
                try rollbackMutation(transactionURL: entry.url, journal: journal, deadline: deadline)
            }
        }
        try Self.syncPrivateDirectory(transactionsURL)
    }

    private func validateMutationJournal(
        _ journal: MutationJournal,
        expectedID: UUID,
        oldObjects: [ScannedDirectoryEntry]
    ) throws {
        guard journal.schemaVersion == Self.mutationJournalSchemaVersion,
              journal.transactionID == expectedID,
              journal.oldGeneration < UInt64.max,
              journal.newGeneration == journal.oldGeneration + 1,
              !journal.affectedObjectNames.isEmpty,
              journal.affectedObjectNames.count <= bootstrapLimits.maximumDocuments,
              Set(journal.affectedObjectNames).count == journal.affectedObjectNames.count,
              Set(journal.previousObjectNames).count == journal.previousObjectNames.count,
              Set(journal.previousObjectNames).isSubset(of: Set(journal.affectedObjectNames)),
              Self.isSHA256(journal.oldCatalogSHA256),
              Set(journal.previousObjectSHA256.keys) == Set(journal.previousObjectNames),
              journal.previousObjectSHA256.values.allSatisfy(Self.isSHA256) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        for name in journal.affectedObjectNames {
            let url = objectsURL.appendingPathComponent(name)
            _ = try validateObjectFilename(url)
        }
        guard Set(oldObjects.map(\.name)).isSubset(of: Set(journal.previousObjectNames)) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }

    private func removeTransactionDirectory(
        _ transactionURL: URL,
        journal: MutationJournal,
        deadline: ScanDeadline? = nil
    ) throws {
        let boundedDeadline = try deadline ?? makeDeadline(seconds: bootstrapLimits.bootstrapDeadlineSeconds)
        let oldObjectsURL = transactionURL.appendingPathComponent("Objects", isDirectory: true)
        let objects = try scanDirectory(
            oldObjectsURL,
            maximumEntries: bootstrapLimits.maximumTransactionEntries,
            maximumBytes: bootstrapLimits.maximumTransactionBytes,
            deadline: boundedDeadline
        )
        guard Set(objects.entries.map(\.name)).isSubset(of: Set(journal.previousObjectNames)) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        for entry in objects.entries {
            try boundedDeadline.check()
            try requirePrivateRegular(entry, maximumBytes: Self.maximumObjectBytes)
            guard Darwin.unlink(entry.url.path) == 0 else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
        }
        try Self.syncPrivateDirectory(oldObjectsURL)
        guard rmdir(oldObjectsURL.path) == 0 else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        let allowedFiles = ["manifest.json", "old-catalog.json", "committed"]
        for name in allowedFiles {
            let url = transactionURL.appendingPathComponent(name)
            if Self.entryExists(url) {
                try Self.requireRegularNonSymlink(
                    url,
                    unsafeError: .unsafeStoreEntry(name)
                )
                guard Darwin.unlink(url.path) == 0 else {
                    throw LocalKnowledgeStoreError.storageUnavailable
                }
            }
        }
        let final = try scanDirectory(
            transactionURL,
            maximumEntries: 1,
            maximumBytes: 1,
            deadline: boundedDeadline
        )
        guard final.entries.isEmpty, rmdir(transactionURL.path) == 0 else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        try Self.syncPrivateDirectory(transactionsURL)
    }

    private static func isRecoverableCorruption(_ error: LocalKnowledgeStoreError) -> Bool {
        switch error {
        case .storageUnavailable, .invalidProjectID, .invalidTitle, .invalidTimestamp,
             .emptyContent, .contentTooLarge, .tooManyChunks, .invalidUTF8,
             .binaryContent, .invalidJSON:
            return true
        default:
            return false
        }
    }

    private static func isSafeStoredFilename(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 255 &&
            value == URL(fileURLWithPath: value).lastPathComponent &&
            !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    /// Trash is not part of the trusted library snapshot. It is inspected and
    /// removed only after readiness has been published, on the same serial
    /// authority as mutations, with its own much shorter work deadline.
    private func scheduleDeferredTrashCleanup() {
        guard !trashCleanupScheduled else { return }
        trashCleanupScheduled = true
        queue.asyncAfter(deadline: .now() + 0.75) { [weak self] in
            guard let self else { return }
            self.trashCleanupScheduled = false
            guard self.availability == .ready else { return }
            do {
                let deadline = try self.makeDeadline(seconds: self.bootstrapLimits.trashDeadlineSeconds)
                let removed = try self.removeBoundedTrash(deadline: deadline)
                self.updateTrashCleanupReport(
                    pending: false,
                    issue: nil,
                    removedEntries: removed
                )
            } catch {
                self.updateTrashCleanupReport(
                    pending: true,
                    issue: error.localizedDescription,
                    removedEntries: 0
                )
            }
        }
    }

    private func markTrashCleanupPendingOnQueue() {
        updateTrashCleanupReport(
            pending: true,
            issue: nil,
            removedEntries: 0
        )
        scheduleDeferredTrashCleanup()
    }

    private func updateTrashCleanupReport(
        pending: Bool,
        issue: String?,
        removedEntries: Int
    ) {
        statusLock.lock()
        let changed = recoveryReportValue.trashCleanupPending != pending ||
            recoveryReportValue.trashCleanupIssue != issue
        recoveryReportValue.trashCleanupPending = pending
        recoveryReportValue.trashCleanupIssue = issue
        statusLock.unlock()
        if changed || removedEntries > 0 { notifyStatusChange() }
    }

    private func removeBoundedTrash(deadline: ScanDeadline) throws -> Int {
        var budget = TrashTraversalBudget()
        var nodes: [TrashNode] = []
        try collectTrashNodes(
            in: trashURL,
            depth: 0,
            deadline: deadline,
            budget: &budget,
            nodes: &nodes
        )
        for node in nodes.reversed() {
            try deadline.check()
            var current = stat()
            guard lstat(node.url.path, &current) == 0,
                  current.st_dev == node.device,
                  current.st_ino == node.inode,
                  (current.st_mode & S_IFMT) == (node.mode & S_IFMT) else {
                throw LocalKnowledgeStoreError.storageUnavailable
            }
            let result: Int32
            if (node.mode & S_IFMT) == S_IFDIR {
                result = rmdir(node.url.path)
            } else {
                result = unlink(node.url.path)
            }
            guard result == 0 else { throw LocalKnowledgeStoreError.storageUnavailable }
        }
        let descriptor = Darwin.open(trashURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw LocalKnowledgeStoreError.storageUnavailable }
        defer { Darwin.close(descriptor) }
        guard fsync(descriptor) == 0 else { throw LocalKnowledgeStoreError.storageUnavailable }
        return nodes.count
    }

    private func collectTrashNodes(
        in directory: URL,
        depth: Int,
        deadline: ScanDeadline,
        budget: inout TrashTraversalBudget,
        nodes: inout [TrashNode]
    ) throws {
        try deadline.check()
        guard depth <= bootstrapLimits.maximumTraversalDepth else {
            throw LocalKnowledgeStoreError.storageTraversalDepthExceeded(
                maximum: bootstrapLimits.maximumTraversalDepth
            )
        }
        let remainingEntries = max(0, bootstrapLimits.maximumTrashEntries - budget.entries)
        let remainingBytes = max(0, bootstrapLimits.maximumTrashBytes - budget.bytes)
        let scan = try scanDirectory(
            directory,
            maximumEntries: remainingEntries,
            maximumBytes: remainingBytes,
            deadline: deadline
        )
        for entry in scan.entries {
            try deadline.check()
            let nameBytes = entry.name.utf8.count
            guard budget.entries < bootstrapLimits.maximumTrashEntries else {
                throw LocalKnowledgeStoreError.directoryEntryLimitExceeded(
                    maximum: bootstrapLimits.maximumTrashEntries
                )
            }
            guard nameBytes <= bootstrapLimits.maximumAggregateFilenameBytes,
                  budget.filenameBytes <= bootstrapLimits.maximumAggregateFilenameBytes - nameBytes else {
                throw LocalKnowledgeStoreError.aggregateFilenameLimitExceeded(
                    maximumBytes: bootstrapLimits.maximumAggregateFilenameBytes
                )
            }
            guard entry.bytes <= bootstrapLimits.maximumTrashBytes,
                  budget.bytes <= bootstrapLimits.maximumTrashBytes - entry.bytes else {
                throw LocalKnowledgeStoreError.aggregateStorageLimitExceeded(
                    maximumBytes: bootstrapLimits.maximumTrashBytes
                )
            }
            budget.entries += 1
            budget.filenameBytes += nameBytes
            budget.bytes += entry.bytes
            if (entry.mode & S_IFMT) == S_IFDIR {
                try requirePrivateDirectory(entry)
            } else {
                try requirePrivateRegular(entry, maximumBytes: Self.maximumObjectBytes)
            }
            let node = TrashNode(
                url: entry.url,
                device: entry.device,
                inode: entry.inode,
                mode: entry.mode,
                depth: depth + 1
            )
            nodes.append(node)
            if (entry.mode & S_IFMT) == S_IFDIR {
                guard depth < bootstrapLimits.maximumTraversalDepth else {
                    throw LocalKnowledgeStoreError.storageTraversalDepthExceeded(
                        maximum: bootstrapLimits.maximumTraversalDepth
                    )
                }
                try collectTrashNodes(
                    in: entry.url,
                    depth: depth + 1,
                    deadline: deadline,
                    budget: &budget,
                    nodes: &nodes
                )
            }
        }
    }

    // MARK: - Search index

    private func rebuildSearchIndex() throws {
        let index = try buildSearchIndex(documents: documents)
        indexedChunks = index.indexedChunks
        postings = index.postings
    }

    private func buildSearchIndex(
        documents: [UUID: StoredDocument],
        deadline: ScanDeadline? = nil,
        loadToken: UUID? = nil
    ) throws -> SearchIndex {
        var indexed: [ChunkKey: IndexedChunk] = [:]
        var builtPostings: [String: [Posting]] = [:]
        var totalChunks = 0
        var postingCount = 0
        let ordered = documents.values.sorted {
            $0.descriptor.id.uuidString.lowercased() < $1.descriptor.id.uuidString.lowercased()
        }
        for document in ordered {
            try deadline?.check()
            if let loadToken { try requireActiveLoad(loadToken) }
            for (index, chunk) in document.chunks.enumerated() {
                try deadline?.check()
                guard totalChunks < bootstrapLimits.maximumTotalChunks else {
                    throw LocalKnowledgeStoreError.indexChunkLimitExceeded(
                        maximumChunks: bootstrapLimits.maximumTotalChunks
                    )
                }
                totalChunks += 1
                let key = ChunkKey(documentID: document.descriptor.id, chunkIndex: index)
                let chunkTokens = Self.tokens(in: chunk)
                indexed[key] = IndexedChunk(key: key, tokenCount: chunkTokens.count)
                let frequencies = chunkTokens.reduce(into: [String: Int]()) { $0[$1, default: 0] += 1 }
                for token in frequencies.keys.sorted() {
                    guard postingCount < bootstrapLimits.maximumIndexPostings else {
                        throw LocalKnowledgeStoreError.indexCapacityExceeded(
                            maximumPostings: bootstrapLimits.maximumIndexPostings
                        )
                    }
                    postingCount += 1
                    builtPostings[token, default: []].append(Posting(
                        key: key,
                        frequency: frequencies[token] ?? 0
                    ))
                }
            }
        }
        return SearchIndex(indexedChunks: indexed, postings: builtPostings)
    }

    private static func tokens(in text: String) -> [String] {
        text.folding(
            options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        )
        .lowercased(with: Locale(identifier: "en_US_POSIX"))
        .split(whereSeparator: { !$0.isLetter && !$0.isNumber })
        .map(String.init)
        .filter { !$0.isEmpty }
    }

    private static func uniqueTokens(in text: String) -> [String] {
        var seen = Set<String>()
        return tokens(in: text).filter { seen.insert($0).inserted }
    }

    private static func roundedScore(_ value: Double) -> Double {
        (value * 1_000_000_000).rounded() / 1_000_000_000
    }

    private static func snippet(from text: String, terms: [String]) -> String {
        let characters = Array(text)
        guard characters.count > LocalKnowledgeLimits.maximumSnippetCharacters else { return text }

        let folded = text.folding(
            options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        ).lowercased(with: Locale(identifier: "en_US_POSIX"))
        var matchOffset: Int?
        for term in terms {
            if let range = folded.range(of: term) {
                let offset = folded.distance(from: folded.startIndex, to: range.lowerBound)
                matchOffset = min(matchOffset ?? offset, offset)
            }
        }
        let center = min(characters.count, matchOffset ?? 0)
        // Reserve room for both ellipses so the returned snippet, including
        // adornment, never exceeds the public bound.
        let bodyLimit = max(1, LocalKnowledgeLimits.maximumSnippetCharacters - 2)
        let half = bodyLimit / 2
        var start = max(0, center - half)
        var end = min(characters.count, start + bodyLimit)
        if end - start < bodyLimit {
            start = max(0, end - bodyLimit)
        }
        if start > 0 {
            while start < end, !characters[start].isWhitespace { start += 1 }
            while start < end, characters[start].isWhitespace { start += 1 }
        }
        if end < characters.count {
            while end > start, !characters[end - 1].isWhitespace { end -= 1 }
            while end > start, characters[end - 1].isWhitespace { end -= 1 }
        }
        let body = String(characters[start..<end])
        return (start > 0 ? "…" : "") + body + (end < characters.count ? "…" : "")
    }

    private static func matches(_ scope: KnowledgeScope, filter: KnowledgeScopeFilter) -> Bool {
        switch filter {
        case .all:
            return true
        case .globalOnly:
            return scope == .global
        case .project(let projectID, let includeGlobal):
            return scope == .project(projectID) || (includeGlobal && scope == .global)
        }
    }

    private static func descriptorOrder(
        _ lhs: KnowledgeDocumentDescriptor,
        _ rhs: KnowledgeDocumentDescriptor
    ) -> Bool {
        if lhs.updatedAt != rhs.updatedAt { return lhs.updatedAt > rhs.updatedAt }
        let leftTitle = stableTitleKey(lhs.title)
        let rightTitle = stableTitleKey(rhs.title)
        if leftTitle != rightTitle { return leftTitle < rightTitle }
        return lhs.id.uuidString.lowercased() < rhs.id.uuidString.lowercased()
    }

    private static func stableTitleKey(_ title: String) -> String {
        title.folding(
            options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        ).lowercased(with: Locale(identifier: "en_US_POSIX")) + "\u{0}" + title
    }

    // MARK: - Validation and extraction

    private func validate(scope: KnowledgeScope) throws {
        guard case .project(let projectID) = scope else { return }
        guard Self.isValidProjectID(projectID) else { throw LocalKnowledgeStoreError.invalidProjectID }
    }

    private func validate(filter: KnowledgeScopeFilter) throws {
        if case .project(let projectID, _) = filter, !Self.isValidProjectID(projectID) {
            throw LocalKnowledgeStoreError.invalidProjectID
        }
    }

    private static func isValidProjectID(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value == trimmed, !value.isEmpty, value.utf8.count <= 256, value.count <= 128 else { return false }
        return !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    private func validate(title: String) throws -> String {
        let normalized = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty,
              normalized.count <= 200,
              normalized.utf8.count <= 800,
              !normalized.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw LocalKnowledgeStoreError.invalidTitle
        }
        return normalized
    }

    private func normalizeAndValidate(text: String) throws -> String {
        var normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if normalized.first == "\u{FEFF}" { normalized.removeFirst() }
        guard !normalized.isEmpty else { throw LocalKnowledgeStoreError.emptyContent }
        for scalar in normalized.unicodeScalars where CharacterSet.controlCharacters.contains(scalar) {
            guard scalar == "\n" || scalar == "\t" else { throw LocalKnowledgeStoreError.binaryContent }
        }
        guard normalized.utf8.count <= LocalKnowledgeLimits.maximumExtractedUTF8Bytes else {
            throw LocalKnowledgeStoreError.contentTooLarge(
                maximumBytes: LocalKnowledgeLimits.maximumExtractedUTF8Bytes
            )
        }
        return normalized
    }

    private func normalizedSearchQuery(_ query: String) throws -> String {
        let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty,
              normalized.utf8.count <= LocalKnowledgeLimits.maximumQueryUTF8Bytes,
              !normalized.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw LocalKnowledgeStoreError.invalidSearchQuery
        }
        return normalized
    }

    private func classify(fileExtension: String) throws -> ImportedKind {
        let ext = fileExtension.lowercased()
        switch ext {
        case "txt", "text", "log":
            return .text(.plainText)
        case "md", "markdown", "mdown":
            return .text(.markdown)
        case "json":
            return .text(.json)
        case "jsonl":
            return .jsonLines
        case "csv", "tsv":
            return .text(.csv)
        case "swift", "m", "mm", "h", "hpp", "c", "cc", "cpp", "cs", "go", "rs", "py",
             "js", "jsx", "ts", "tsx", "java", "kt", "kts", "rb", "php", "sh", "bash", "zsh",
             "fish", "sql", "html", "htm", "css", "scss", "xml", "yaml", "yml", "toml", "ini":
            return .text(.sourceCode)
        case "pdf":
            return .pdf
        default:
            throw LocalKnowledgeStoreError.unsupportedFileType(ext.isEmpty ? "unknown" : ext)
        }
    }

    private static func chunk(_ text: String) throws -> [String] {
        let characters = Array(text)
        guard !characters.isEmpty else { throw LocalKnowledgeStoreError.emptyContent }
        var chunks: [String] = []
        var start = 0
        while start < characters.count {
            let hardEnd = min(characters.count, start + LocalKnowledgeLimits.chunkCharacters)
            var end = hardEnd
            if hardEnd < characters.count {
                let preferredFloor = start + LocalKnowledgeLimits.chunkCharacters / 2
                var candidate = hardEnd
                while candidate > preferredFloor {
                    if characters[candidate - 1].isWhitespace {
                        end = candidate - 1
                        break
                    }
                    candidate -= 1
                }
            }
            if end <= start { end = hardEnd }
            let chunk = String(characters[start..<end]).trimmingCharacters(in: .whitespacesAndNewlines)
            if !chunk.isEmpty { chunks.append(chunk) }
            guard chunks.count <= LocalKnowledgeLimits.maximumChunksPerDocument else {
                throw LocalKnowledgeStoreError.tooManyChunks(maximum: LocalKnowledgeLimits.maximumChunksPerDocument)
            }
            guard end < characters.count else { break }
            var next = max(start + 1, end - LocalKnowledgeLimits.chunkOverlapCharacters)
            while next < end, !characters[next].isWhitespace { next += 1 }
            while next < end, characters[next].isWhitespace { next += 1 }
            start = max(start + 1, next)
        }
        guard !chunks.isEmpty else { throw LocalKnowledgeStoreError.emptyContent }
        guard chunks.allSatisfy({ $0.count <= LocalKnowledgeLimits.chunkCharacters }) else {
            throw LocalKnowledgeStoreError.tooManyChunks(maximum: LocalKnowledgeLimits.maximumChunksPerDocument)
        }
        return chunks
    }

    private static func extractPDFText(from data: Data) throws -> String {
#if canImport(PDFKit)
        guard let document = PDFDocument(data: data) else { throw LocalKnowledgeStoreError.invalidPDF }
        guard !document.isEncrypted, !document.isLocked else { throw LocalKnowledgeStoreError.encryptedPDF }
        guard document.pageCount <= LocalKnowledgeLimits.maximumPDFPages else {
            throw LocalKnowledgeStoreError.pdfTooManyPages(maximum: LocalKnowledgeLimits.maximumPDFPages)
        }
        var parts: [String] = []
        var byteCount = 0
        for index in 0..<document.pageCount {
            guard let pageText = document.page(at: index)?.string, !pageText.isEmpty else { continue }
            byteCount += pageText.utf8.count + (parts.isEmpty ? 0 : 2)
            guard byteCount <= LocalKnowledgeLimits.maximumExtractedUTF8Bytes else {
                throw LocalKnowledgeStoreError.contentTooLarge(
                    maximumBytes: LocalKnowledgeLimits.maximumExtractedUTF8Bytes
                )
            }
            parts.append(pageText)
        }
        let text = parts.joined(separator: "\n\n")
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw LocalKnowledgeStoreError.pdfHasNoExtractableText }
        return text
#else
        throw LocalKnowledgeStoreError.invalidPDF
#endif
    }

    private static func isSafeSourceName(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 255 && value.utf8.count <= 1_024 &&
            value == URL(fileURLWithPath: value).lastPathComponent &&
            !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.count == 64 && value.unicodeScalars.allSatisfy {
            ("0"..."9").contains(Character(String($0))) || ("a"..."f").contains(Character(String($0)))
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Secure file operations

    private static func readSourceFile(at url: URL) throws -> Data {
        guard url.isFileURL else { throw LocalKnowledgeStoreError.sourceUnreadable }
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw LocalKnowledgeStoreError.sourceUnreadable }
        if (info.st_mode & S_IFMT) == S_IFLNK { throw LocalKnowledgeStoreError.sourceIsSymbolicLink }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw LocalKnowledgeStoreError.sourceIsNotRegularFile }
        guard info.st_size <= LocalKnowledgeLimits.maximumImportBytes else {
            throw LocalKnowledgeStoreError.sourceTooLarge(maximumBytes: LocalKnowledgeLimits.maximumImportBytes)
        }
        return try readRegularFile(
            at: url,
            maximumBytes: LocalKnowledgeLimits.maximumImportBytes,
            oversizeError: .sourceTooLarge(maximumBytes: LocalKnowledgeLimits.maximumImportBytes),
            unsafeError: .sourceUnreadable,
            requiresPrivateOwnership: false
        )
    }

    private static func readRegularFile(
        at url: URL,
        maximumBytes: Int,
        oversizeError: LocalKnowledgeStoreError,
        unsafeError: LocalKnowledgeStoreError,
        expected: ScannedDirectoryEntry? = nil,
        deadline: ScanDeadline? = nil,
        requiresPrivateOwnership: Bool = true
    ) throws -> Data {
        try deadline?.check()
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw unsafeError }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              !requiresPrivateOwnership || Self.isPrivateOwnedRegular(info) else {
            try? handle.close()
            throw unsafeError
        }
        if let expected {
            guard info.st_dev == expected.device,
                  info.st_ino == expected.inode,
                  info.st_size == off_t(expected.bytes) else {
                try? handle.close()
                throw unsafeError
            }
        }
        guard info.st_size >= 0, info.st_size <= maximumBytes else {
            try? handle.close()
            throw oversizeError
        }
        var result = Data()
        result.reserveCapacity(min(Int(info.st_size), maximumBytes))
        do {
            while result.count <= maximumBytes {
                try deadline?.check()
                let remaining = maximumBytes + 1 - result.count
                guard let piece = try handle.read(upToCount: min(64 * 1_024, remaining)), !piece.isEmpty else { break }
                result.append(piece)
            }
            try deadline?.check()
            var final = stat()
            var current = stat()
            guard fstat(descriptor, &final) == 0,
                  final.st_dev == info.st_dev,
                  final.st_ino == info.st_ino,
                  final.st_size == info.st_size,
                  lstat(url.path, &current) == 0,
                  current.st_dev == info.st_dev,
                  current.st_ino == info.st_ino,
                  current.st_size == info.st_size else {
                throw unsafeError
            }
            try handle.close()
        } catch let error as LocalKnowledgeStoreError {
            try? handle.close()
            throw error
        } catch {
            try? handle.close()
            throw unsafeError
        }
        guard result.count <= maximumBytes else { throw oversizeError }
        return result
    }

    private static func schemaVersion(
        at url: URL,
        maximumBytes: Int,
        expected: ScannedDirectoryEntry? = nil,
        deadline: ScanDeadline? = nil
    ) throws -> Int {
        let data = try readRegularFile(
            at: url,
            maximumBytes: maximumBytes,
            oversizeError: .storageUnavailable,
            unsafeError: .unsafeStoreEntry(url.lastPathComponent),
            expected: expected,
            deadline: deadline
        )
        guard let version = schemaVersion(in: data) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        return version
    }

    private static func schemaVersion(in data: Data) -> Int? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return object["schemaVersion"] as? Int
    }

    private static func ensurePrivateDirectory(_ url: URL, fileManager: FileManager) throws {
        if entryExists(url) {
            var existing = stat()
            guard lstat(url.path, &existing) == 0,
                  isPrivateOwnedDirectory(existing) else {
                throw LocalKnowledgeStoreError.unsafeStoreEntry(url.lastPathComponent)
            }
        } else {
            try fileManager.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        var secured = stat()
        guard lstat(url.path, &secured) == 0,
              isPrivateOwnedDirectory(secured) else {
            throw LocalKnowledgeStoreError.unsafeStoreEntry(url.lastPathComponent)
        }
    }

    private static func isDirectoryWithoutSymlink(_ url: URL) throws -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return false }
        return (info.st_mode & S_IFMT) == S_IFDIR
    }

    private static func requireRegularNonSymlink(
        _ url: URL,
        unsafeError: LocalKnowledgeStoreError,
        requiresPrivateOwnership: Bool = true
    ) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              !requiresPrivateOwnership || isPrivateOwnedRegular(info) else {
            throw unsafeError
        }
    }

    private static func entryExists(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0
    }

    private static func isPrivateOwnedRegular(_ value: stat) -> Bool {
        (value.st_mode & S_IFMT) == S_IFREG &&
            value.st_uid == geteuid() &&
            value.st_nlink == 1 &&
            (value.st_mode & 0o077) == 0
    }

    private static func isPrivateOwnedDirectory(_ value: stat) -> Bool {
        (value.st_mode & S_IFMT) == S_IFDIR &&
            value.st_uid == geteuid() &&
            value.st_nlink >= 1 &&
            (value.st_mode & 0o077) == 0
    }

    private static func syncPrivateDirectory(_ directory: URL) throws {
        try syncDirectory(directory, requiresPrivateOwnership: true)
    }

    private static func syncDirectory(
        _ directory: URL,
        requiresPrivateOwnership: Bool
    ) throws {
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else { throw LocalKnowledgeStoreError.storageUnavailable }
        defer { Darwin.close(descriptor) }
        var initial = stat()
        var final = stat()
        var currentPath = stat()
        guard fstat(descriptor, &initial) == 0,
              (initial.st_mode & S_IFMT) == S_IFDIR,
              !requiresPrivateOwnership || isPrivateOwnedDirectory(initial),
              fsync(descriptor) == 0,
              fstat(descriptor, &final) == 0,
              final.st_dev == initial.st_dev,
              final.st_ino == initial.st_ino,
              lstat(directory.path, &currentPath) == 0,
              (currentPath.st_mode & S_IFMT) == S_IFDIR,
              currentPath.st_dev == initial.st_dev,
              currentPath.st_ino == initial.st_ino else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }

    private static func atomicPrivateWrite(
        _ data: Data,
        to destination: URL,
        fileManager: FileManager,
        secureParent: Bool
    ) throws {
        let directory = destination.deletingLastPathComponent()
        if secureParent {
            try ensurePrivateDirectory(directory, fileManager: fileManager)
        } else {
            guard try isDirectoryWithoutSymlink(directory) else {
                throw LocalKnowledgeStoreError.unsafeExportDestination
            }
        }
        let temporary = directory.appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
        let descriptor = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw LocalKnowledgeStoreError.storageUnavailable }
        var writeError: Error?
        data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    writeError = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    break
                }
                if count == 0 {
                    writeError = POSIXError(.EIO)
                    break
                }
                offset += count
            }
        }
        if writeError == nil, fsync(descriptor) != 0 {
            writeError = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        _ = Darwin.close(descriptor)
        guard writeError == nil else {
            try? fileManager.removeItem(at: temporary)
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        guard Darwin.rename(temporary.path, destination.path) == 0 else {
            try? fileManager.removeItem(at: temporary)
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        var installed = stat()
        guard lstat(destination.path, &installed) == 0,
              isPrivateOwnedRegular(installed) else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
        try syncDirectory(directory, requiresPrivateOwnership: secureParent)
        var durable = stat()
        guard lstat(destination.path, &durable) == 0,
              isPrivateOwnedRegular(durable),
              durable.st_dev == installed.st_dev,
              durable.st_ino == installed.st_ino,
              durable.st_size == installed.st_size else {
            throw LocalKnowledgeStoreError.storageUnavailable
        }
    }
}
