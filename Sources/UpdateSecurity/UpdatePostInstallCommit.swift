import CryptoKit
import Darwin
import Foundation
import Security

public enum UpdateInstallJournalPhase: String, Codable, CaseIterable, Sendable {
    case prepared
    case rollbackRetained
    case candidateInstalled
    case healthAcknowledged
    case committed
    case rollingBack
}

public struct UpdateInstallJournalRecord: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public let schemaVersion: Int
    public let transactionID: UUID
    public let nonceHex: String
    public let currentApplicationPath: String
    public let stagedApplicationPath: String
    public let rollbackApplicationPath: String
    public let oldApplication: ValidatedUpdateApplication
    public let candidateApplication: ValidatedUpdateApplication
    public let phase: UpdateInstallJournalPhase

    public init(
        transactionID: UUID,
        nonceHex: String,
        currentApplicationPath: String,
        stagedApplicationPath: String,
        rollbackApplicationPath: String,
        oldApplication: ValidatedUpdateApplication,
        candidateApplication: ValidatedUpdateApplication,
        phase: UpdateInstallJournalPhase = .prepared
    ) {
        schemaVersion = Self.schemaVersion
        self.transactionID = transactionID
        self.nonceHex = nonceHex
        self.currentApplicationPath = currentApplicationPath
        self.stagedApplicationPath = stagedApplicationPath
        self.rollbackApplicationPath = rollbackApplicationPath
        self.oldApplication = oldApplication
        self.candidateApplication = candidateApplication
        self.phase = phase
    }

    fileprivate init(replacingPhaseOf record: Self, with phase: UpdateInstallJournalPhase) {
        schemaVersion = record.schemaVersion
        transactionID = record.transactionID
        nonceHex = record.nonceHex
        currentApplicationPath = record.currentApplicationPath
        stagedApplicationPath = record.stagedApplicationPath
        rollbackApplicationPath = record.rollbackApplicationPath
        oldApplication = record.oldApplication
        candidateApplication = record.candidateApplication
        self.phase = phase
    }

    public func validateShape() throws {
        try oldApplication.attestation.validateShape()
        try candidateApplication.attestation.validateShape()
        guard schemaVersion == Self.schemaVersion,
              nonceHex.count == 64,
              nonceHex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
              oldApplication.attestation.identifier == candidateApplication.attestation.identifier,
              oldApplication.attestation.teamIdentifier == candidateApplication.attestation.teamIdentifier,
              candidateApplication.attestation.build > oldApplication.attestation.build,
              oldApplication.identity.device == candidateApplication.identity.device,
              Self.validAbsolutePath(currentApplicationPath),
              Self.validAbsolutePath(stagedApplicationPath),
              Self.validAbsolutePath(rollbackApplicationPath),
              Set([currentApplicationPath, stagedApplicationPath, rollbackApplicationPath]).count == 3 else {
            throw UpdateInstallJournalError.invalidJournal
        }
    }

    private static func validAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), path.utf8.count <= 4_096,
              !path.contains("\\"), !path.contains("\0"),
              path == path.precomposedStringWithCanonicalMapping else { return false }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        return components.first?.isEmpty == true
            && components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    }
}

private struct AuthenticatedUpdateInstallJournal: Codable {
    let payload: UpdateInstallJournalRecord
    let authenticationTag: String
}

public enum UpdateInstallJournalError: Error, Equatable, LocalizedError {
    case unsafeStorage
    case transactionAlreadyExists
    case transactionMissing
    case invalidJournal
    case authenticationFailed
    case invalidTransition

    public var errorDescription: String? {
        switch self {
        case .unsafeStorage:
            return "The private update transaction storage is unsafe or incomplete. Rollback material was preserved for manual recovery."
        case .transactionAlreadyExists:
            return "An earlier update transaction still requires recovery. No new replacement was attempted."
        case .transactionMissing:
            return "The update transaction journal is missing."
        case .invalidJournal:
            return "The update transaction journal is malformed or does not match this update."
        case .authenticationFailed:
            return "The update transaction journal failed authentication."
        case .invalidTransition:
            return "The update transaction journal contains an impossible phase transition."
        }
    }
}

/// A single owner-private, HMAC-authenticated transaction record. The random
/// authentication key and journal are separate regular files so a torn write,
/// link, permission change, or partial cleanup fails closed. The key protects
/// against accidental/torn/stale bytes inside the private updater namespace;
/// a fully compromised login account remains outside this trust boundary.
public final class UpdateInstallJournalStore {
    public static let transactionDirectoryName = "Active Install Transaction"
    private static let keyName = "authentication-key"
    private static let journalName = "journal.json"
    private static let maximumJournalBytes = 32 * 1_024

    private let updatesRoot: URL
    private let transactionRoot: URL

    public init(updatesRoot: URL) {
        self.updatesRoot = updatesRoot
        transactionRoot = self.updatesRoot.appendingPathComponent(
            Self.transactionDirectoryName,
            isDirectory: true
        )
    }

    public var transactionURL: URL { transactionRoot }

    public func pendingTransactionExists() throws -> Bool {
        var metadata = stat()
        if lstat(transactionRoot.path, &metadata) == 0 { return true }
        guard errno == ENOENT else { throw UpdateInstallJournalError.unsafeStorage }
        return false
    }

    public func requireNoPendingTransaction() throws {
        try validateUpdatesRoot()
        var metadata = stat()
        guard lstat(transactionRoot.path, &metadata) != 0 else {
            throw UpdateInstallJournalError.transactionAlreadyExists
        }
        guard errno == ENOENT else { throw UpdateInstallJournalError.unsafeStorage }
    }

    public func create(_ record: UpdateInstallJournalRecord) throws {
        try record.validateShape()
        guard record.phase == .prepared else { throw UpdateInstallJournalError.invalidJournal }
        try requireNoPendingTransaction()
        let preparingRoot = updatesRoot.appendingPathComponent(
            ".Preparing Install Transaction \(record.transactionID.uuidString) \(UUID().uuidString)",
            isDirectory: true
        )
        guard mkdir(preparingRoot.path, 0o700) == 0 else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        try syncDirectory(updatesRoot)
        try UpdateApplicationSecurity.validatePrivateDirectory(preparingRoot)

        var key = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, key.count, &key) == errSecSuccess else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        let keyData = Data(key)
        try writeExclusive(keyData, to: keyURL(in: preparingRoot))
        try writeAuthenticated(record, key: keyData, root: preparingRoot)
        try syncDirectory(preparingRoot)
        let preparingIdentity = try UpdateApplicationSecurity.directoryIdentity(
            at: preparingRoot,
            requireCurrentUser: true
        )
        guard rename(preparingRoot.path, transactionRoot.path) == 0 else {
            throw errno == EEXIST
                ? UpdateInstallJournalError.transactionAlreadyExists
                : UpdateInstallJournalError.unsafeStorage
        }
        try syncDirectory(updatesRoot)
        guard try UpdateApplicationSecurity.directoryIdentity(
            at: transactionRoot,
            requireCurrentUser: true
        ) == preparingIdentity,
              try load() == record else {
            throw UpdateInstallJournalError.unsafeStorage
        }
    }

    public func load() throws -> UpdateInstallJournalRecord {
        try validateUpdatesRoot()
        try UpdateApplicationSecurity.validatePrivateDirectory(transactionRoot)
        _ = try validatedJournalNames(in: transactionRoot)
        let key = try readPrivateRegularFile(keyURL(in: transactionRoot), maximumBytes: 32)
        guard key.count == 32 else { throw UpdateInstallJournalError.unsafeStorage }
        let data = try readPrivateRegularFile(
            journalURL(in: transactionRoot),
            maximumBytes: Self.maximumJournalBytes
        )
        let envelope: AuthenticatedUpdateInstallJournal
        do { envelope = try JSONDecoder().decode(AuthenticatedUpdateInstallJournal.self, from: data) }
        catch { throw UpdateInstallJournalError.invalidJournal }
        try envelope.payload.validateShape()
        guard let supplied = Data(base64Encoded: envelope.authenticationTag),
              HMAC<SHA256>.isValidAuthenticationCode(
                supplied,
                authenticating: try Self.canonicalData(envelope.payload),
                using: SymmetricKey(data: key)
              ) else {
            throw UpdateInstallJournalError.authenticationFailed
        }
        return envelope.payload
    }

    @discardableResult
    public func transition(
        expectedTransactionID: UUID,
        to phase: UpdateInstallJournalPhase
    ) throws -> UpdateInstallJournalRecord {
        let current = try load()
        guard current.transactionID == expectedTransactionID else {
            throw UpdateInstallJournalError.invalidJournal
        }
        if current.phase == phase { return current }
        guard Self.allowedTransition(from: current.phase, to: phase) else {
            throw UpdateInstallJournalError.invalidTransition
        }
        let key = try readPrivateRegularFile(keyURL(in: transactionRoot), maximumBytes: 32)
        guard key.count == 32 else { throw UpdateInstallJournalError.unsafeStorage }
        let replacement = UpdateInstallJournalRecord(replacingPhaseOf: current, with: phase)
        try writeAuthenticated(replacement, key: key, root: transactionRoot)
        return replacement
    }

    /// Atomically retires the active name before deleting its two exact files.
    /// A crash after the rename cannot resurrect an active or half-authenticated
    /// transaction. Unexpected entries are never recursively removed.
    public func retire(expectedTransactionID: UUID) throws {
        let record = try load()
        guard record.transactionID == expectedTransactionID else {
            throw UpdateInstallJournalError.invalidJournal
        }
        let before = try UpdateApplicationSecurity.directoryIdentity(
            at: transactionRoot,
            requireCurrentUser: true
        )
        let retired = updatesRoot.appendingPathComponent(
            ".Retired Install Transaction \(record.transactionID.uuidString)",
            isDirectory: true
        )
        var metadata = stat()
        guard lstat(retired.path, &metadata) != 0, errno == ENOENT,
              rename(transactionRoot.path, retired.path) == 0 else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        try syncDirectory(updatesRoot)
        guard try UpdateApplicationSecurity.directoryIdentity(
            at: retired,
            requireCurrentUser: true
        ) == before else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        let names = try validatedJournalNames(in: retired)
        for name in names {
            let file = retired.appendingPathComponent(name, isDirectory: false)
            _ = try readPrivateRegularFile(file, maximumBytes: Self.maximumJournalBytes)
            guard unlink(file.path) == 0 else { throw UpdateInstallJournalError.unsafeStorage }
        }
        try syncDirectory(retired)
        guard rmdir(retired.path) == 0 else { throw UpdateInstallJournalError.unsafeStorage }
        try syncDirectory(updatesRoot)
    }

    public static func secureNonceHex() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func keyURL(in root: URL) -> URL { root.appendingPathComponent(Self.keyName) }
    private func journalURL(in root: URL) -> URL { root.appendingPathComponent(Self.journalName) }

    private func validateUpdatesRoot() throws {
        guard updatesRoot.lastPathComponent == "Updates",
              updatesRoot.deletingLastPathComponent().lastPathComponent == "Local Harness",
              transactionRoot.deletingLastPathComponent().path == updatesRoot.path else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        do {
            try UpdateApplicationSecurity.preparePrivateOwnedDirectory(updatesRoot.deletingLastPathComponent())
            try UpdateApplicationSecurity.preparePrivateOwnedDirectory(updatesRoot)
        } catch {
            throw UpdateInstallJournalError.unsafeStorage
        }
    }

    private func writeAuthenticated(
        _ record: UpdateInstallJournalRecord,
        key: Data,
        root: URL
    ) throws {
        let tag = Data(HMAC<SHA256>.authenticationCode(
            for: try Self.canonicalData(record),
            using: SymmetricKey(data: key)
        )).base64EncodedString()
        let envelope = AuthenticatedUpdateInstallJournal(payload: record, authenticationTag: tag)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(envelope)
        guard data.count <= Self.maximumJournalBytes else {
            throw UpdateInstallJournalError.invalidJournal
        }
        try atomicWrite(data, to: journalURL(in: root))
    }

    private static func canonicalData(_ record: UpdateInstallJournalRecord) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(record)
    }

    private static func allowedTransition(
        from: UpdateInstallJournalPhase,
        to: UpdateInstallJournalPhase
    ) -> Bool {
        if to == .rollingBack { return from != .committed }
        switch (from, to) {
        case (.prepared, .rollbackRetained),
             (.rollbackRetained, .candidateInstalled),
             (.candidateInstalled, .healthAcknowledged),
             (.healthAcknowledged, .committed):
            return true
        default:
            return false
        }
    }

    private func writeExclusive(_ data: Data, to url: URL) throws {
        let descriptor = Darwin.open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw UpdateInstallJournalError.unsafeStorage }
        var closeNeeded = true
        defer { if closeNeeded { Darwin.close(descriptor) } }
        try writeAll(data, descriptor: descriptor)
        guard fchmod(descriptor, 0o600) == 0,
              fsync(descriptor) == 0,
              Darwin.close(descriptor) == 0 else {
            closeNeeded = false
            throw UpdateInstallJournalError.unsafeStorage
        }
        closeNeeded = false
        try syncDirectory(url.deletingLastPathComponent())
    }

    private func atomicWrite(_ data: Data, to destination: URL) throws {
        let parent = destination.deletingLastPathComponent()
        let temporary = parent.appendingPathComponent(
            ".journal.\(UUID().uuidString).tmp",
            isDirectory: false
        )
        do {
            try writeExclusive(data, to: temporary)
            guard rename(temporary.path, destination.path) == 0 else {
                throw UpdateInstallJournalError.unsafeStorage
            }
            try syncDirectory(parent)
        } catch {
            _ = unlink(temporary.path)
            throw error
        }
    }

    private func writeAll(_ data: Data, descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    bytes.baseAddress?.advanced(by: offset),
                    bytes.count - offset
                )
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR { continue }
                throw UpdateInstallJournalError.unsafeStorage
            }
        }
    }

    private func readPrivateRegularFile(_ url: URL, maximumBytes: Int) throws -> Data {
        var before = stat()
        guard lstat(url.path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_uid == geteuid(),
              before.st_nlink == 1,
              before.st_mode & 0o7777 == 0o600,
              before.st_size >= 0,
              before.st_size <= off_t(maximumBytes) else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw UpdateInstallJournalError.unsafeStorage }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == before.st_dev,
              opened.st_ino == before.st_ino,
              opened.st_size == before.st_size else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        var data = Data(count: Int(opened.st_size))
        let dataCount = data.count
        var offset = 0
        while offset < dataCount {
            let count: Int = data.withUnsafeMutableBytes { bytes in
                pread(descriptor, bytes.baseAddress?.advanced(by: offset), dataCount - offset, off_t(offset))
            }
            if count > 0 { offset += count; continue }
            if count < 0, errno == EINTR { continue }
            throw UpdateInstallJournalError.unsafeStorage
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              after.st_dev == opened.st_dev,
              after.st_ino == opened.st_ino,
              after.st_size == opened.st_size,
              after.st_mtimespec.tv_sec == opened.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == opened.st_mtimespec.tv_nsec,
              after.st_ctimespec.tv_sec == opened.st_ctimespec.tv_sec,
              after.st_ctimespec.tv_nsec == opened.st_ctimespec.tv_nsec else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        return data
    }

    private func validatedJournalNames(in root: URL) throws -> [String] {
        let names: [String]
        do { names = try FileManager.default.contentsOfDirectory(atPath: root.path) }
        catch { throw UpdateInstallJournalError.unsafeStorage }
        guard (2...10).contains(names.count),
              names.contains(Self.keyName), names.contains(Self.journalName) else {
            throw UpdateInstallJournalError.unsafeStorage
        }
        for name in names where name != Self.keyName && name != Self.journalName {
            guard name.hasPrefix(".journal."), name.hasSuffix(".tmp"),
                  name.utf8.count <= 128 else {
                throw UpdateInstallJournalError.unsafeStorage
            }
            _ = try readPrivateRegularFile(
                root.appendingPathComponent(name),
                maximumBytes: Self.maximumJournalBytes
            )
        }
        return names
    }

    private func syncDirectory(_ url: URL) throws {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw UpdateInstallJournalError.unsafeStorage }
        defer { Darwin.close(descriptor) }
        guard fsync(descriptor) == 0 else { throw UpdateInstallJournalError.unsafeStorage }
    }
}

public enum UpdateInstallArtifactState: Equatable, Sendable {
    case missing
    case application(ValidatedUpdateApplication)
}

public enum UpdateInstallRecoveryAction: Equatable, Sendable {
    case clearUnchanged
    case rollback
    case finalizeCommit
}

public struct UpdateInstallRecoveryHooks {
    public var inspectCurrent: () throws -> UpdateInstallArtifactState
    public var inspectStaged: () throws -> UpdateInstallArtifactState
    public var inspectRollback: () throws -> UpdateInstallArtifactState
    public var stopCandidate: () throws -> Void
    public var removeCandidate: () throws -> Void
    public var restoreRollback: () throws -> Void
    public var validateRestored: () throws -> ValidatedUpdateApplication
    public var persistPhase: (UpdateInstallJournalPhase) throws -> Void
    public var retireJournal: () throws -> Void

    public init(
        inspectCurrent: @escaping () throws -> UpdateInstallArtifactState,
        inspectStaged: @escaping () throws -> UpdateInstallArtifactState,
        inspectRollback: @escaping () throws -> UpdateInstallArtifactState,
        stopCandidate: @escaping () throws -> Void,
        removeCandidate: @escaping () throws -> Void,
        restoreRollback: @escaping () throws -> Void,
        validateRestored: @escaping () throws -> ValidatedUpdateApplication,
        persistPhase: @escaping (UpdateInstallJournalPhase) throws -> Void,
        retireJournal: @escaping () throws -> Void
    ) {
        self.inspectCurrent = inspectCurrent
        self.inspectStaged = inspectStaged
        self.inspectRollback = inspectRollback
        self.stopCandidate = stopCandidate
        self.removeCandidate = removeCandidate
        self.restoreRollback = restoreRollback
        self.validateRestored = validateRestored
        self.persistPhase = persistPhase
        self.retireJournal = retireJournal
    }
}

public enum UpdateInstallRecovery {
    public static func classify(
        record: UpdateInstallJournalRecord,
        current: UpdateInstallArtifactState,
        staged: UpdateInstallArtifactState,
        rollback: UpdateInstallArtifactState
    ) throws -> UpdateInstallRecoveryAction {
        try record.validateShape()
        let old = record.oldApplication
        let candidate = record.candidateApplication
        switch record.phase {
        case .healthAcknowledged, .committed:
            guard current == .application(candidate), staged == .missing,
                  rollback == .application(old) else {
                throw UpdateInstallJournalError.invalidJournal
            }
            return .finalizeCommit
        case .prepared, .rollbackRetained, .candidateInstalled, .rollingBack:
            if current == .application(old), rollback == .missing,
               staged == .missing || staged == .application(candidate) {
                return .clearUnchanged
            }
            if current == .missing, rollback == .application(old),
               staged == .missing || staged == .application(candidate) {
                return .rollback
            }
            if current == .application(candidate), staged == .missing,
               rollback == .application(old) {
                return .rollback
            }
            throw UpdateInstallJournalError.invalidJournal
        }
    }

    /// Replays only a fully authenticated record. All inspections happen before
    /// mutation; any unexpected inode/signature/path state is preserved and
    /// surfaced. Re-running after any successful durability boundary selects
    /// the same decision.
    public static func replay(
        record: UpdateInstallJournalRecord,
        hooks: UpdateInstallRecoveryHooks
    ) throws -> UpdateInstallRecoveryAction {
        let current = try hooks.inspectCurrent()
        let staged = try hooks.inspectStaged()
        let rollback = try hooks.inspectRollback()
        let action = try classify(record: record, current: current, staged: staged, rollback: rollback)
        switch action {
        case .clearUnchanged:
            try hooks.retireJournal()
        case .finalizeCommit:
            if record.phase == .healthAcknowledged {
                try hooks.persistPhase(.committed)
            }
            try hooks.retireJournal()
        case .rollback:
            if record.phase != .rollingBack { try hooks.persistPhase(.rollingBack) }
            if current == .application(record.candidateApplication) {
                try hooks.stopCandidate()
                try hooks.removeCandidate()
            }
            if current != .application(record.oldApplication) {
                try hooks.restoreRollback()
            }
            guard try hooks.validateRestored() == record.oldApplication else {
                throw UpdateSecurityError.rollbackFailed
            }
            try hooks.retireJournal()
        }
        return action
    }
}

public enum UpdatePostInstallHealthError: Error, Equatable {
    case invalidRequest
    case invalidChannel
    case invalidChallenge
    case identityMismatch
    case acknowledgementFailed
}

public enum UpdatePostInstallHealthProtocol {
    public static let argument = "--fulmar-post-install-health-v1"
    public static let childDescriptor: Int32 = 4
    public static let maximumFrameBytes = 8 * 1_024

    public static func challenge(
        nonceHex: String,
        candidate: SignedApplicationAttestation
    ) throws -> Data {
        try candidate.validateShape()
        guard nonceHex.count == 64,
              nonceHex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        return Data("FULMAR_POST_INSTALL_CHALLENGE_V1 \(nonceHex) \(try candidate.encodedArgument())\n".utf8)
    }

    public static func acknowledgement(
        nonceHex: String,
        processIdentifier: pid_t,
        candidate: SignedApplicationAttestation
    ) throws -> Data {
        guard processIdentifier > 1 else { throw UpdatePostInstallHealthError.invalidChallenge }
        try candidate.validateShape()
        return Data("FULMAR_POST_INSTALL_HEALTHY_V1 \(nonceHex) \(processIdentifier) \(try candidate.encodedArgument())\n".utf8)
    }

    public static func parseChallenge(_ data: Data) throws -> (String, SignedApplicationAttestation) {
        guard data.count <= maximumFrameBytes,
              let text = String(data: data, encoding: .utf8), text.hasSuffix("\n") else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "FULMAR_POST_INSTALL_CHALLENGE_V1" else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        let nonce = String(fields[1])
        guard nonce.count == 64, nonce.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        do { return (nonce, try SignedApplicationAttestation.decodeArgument(String(fields[2]))) }
        catch { throw UpdatePostInstallHealthError.invalidChallenge }
    }

    public static func parseAcknowledgement(
        _ data: Data
    ) throws -> (String, pid_t, SignedApplicationAttestation) {
        guard data.count <= maximumFrameBytes,
              let text = String(data: data, encoding: .utf8), text.hasSuffix("\n") else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 4, fields[0] == "FULMAR_POST_INSTALL_HEALTHY_V1",
              let pid = pid_t(fields[2]), pid > 1 else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        let nonce = String(fields[1])
        guard nonce.count == 64, nonce.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw UpdatePostInstallHealthError.invalidChallenge
        }
        do { return (nonce, pid, try SignedApplicationAttestation.decodeArgument(String(fields[3]))) }
        catch { throw UpdatePostInstallHealthError.invalidChallenge }
    }
}

/// Candidate-side capability. The anonymous socket is inherited only by the
/// exact directly-spawned app process. It is resolved before AppKit startup,
/// but the reply is emitted only after native runtime/provider readiness.
public final class UpdatePostInstallHealthContext {
    private var descriptor: Int32
    public let nonceHex: String
    public let expectedCandidate: SignedApplicationAttestation

    deinit { if descriptor >= 0 { Darwin.close(descriptor) } }

    private init(
        descriptor: Int32,
        nonceHex: String,
        expectedCandidate: SignedApplicationAttestation
    ) {
        self.descriptor = descriptor
        self.nonceHex = nonceHex
        self.expectedCandidate = expectedCandidate
    }

    public static func resolveIfRequested(
        arguments: [String] = CommandLine.arguments,
        applicationURL: URL = Bundle.main.bundleURL,
        deadline: TimeInterval = 5
    ) throws -> UpdatePostInstallHealthContext? {
        let requests = arguments.filter { $0 == UpdatePostInstallHealthProtocol.argument }
        guard !requests.isEmpty else { return nil }
        guard requests.count == 1, deadline.isFinite, (0.05...10).contains(deadline) else {
            throw UpdatePostInstallHealthError.invalidRequest
        }
        let descriptor = UpdatePostInstallHealthProtocol.childDescriptor
        var metadata = stat()
        var socketType: Int32 = 0
        var socketTypeLength = socklen_t(MemoryLayout<Int32>.size)
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
              getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeLength) == 0,
              socketType == SOCK_STREAM,
              getpeereid(descriptor, &peerUID, &peerGID) == 0,
              peerUID == geteuid() else {
            throw UpdatePostInstallHealthError.invalidChannel
        }
        let challenge = try readFrame(descriptor: descriptor, deadline: deadline)
        let (nonce, expected) = try UpdatePostInstallHealthProtocol.parseChallenge(challenge)
        let actual: SignedApplicationAttestation
        do { actual = try UpdateApplicationSecurity.strictAttestation(at: applicationURL) }
        catch { throw UpdatePostInstallHealthError.identityMismatch }
        guard actual == expected else { throw UpdatePostInstallHealthError.identityMismatch }
        return UpdatePostInstallHealthContext(
            descriptor: descriptor,
            nonceHex: nonce,
            expectedCandidate: expected
        )
    }

    public func acknowledgeHealthy(
        applicationURL: URL = Bundle.main.bundleURL,
        processIdentifier: pid_t = getpid()
    ) throws {
        guard descriptor >= 0 else { throw UpdatePostInstallHealthError.acknowledgementFailed }
        let actual: SignedApplicationAttestation
        do { actual = try UpdateApplicationSecurity.strictAttestation(at: applicationURL) }
        catch { throw UpdatePostInstallHealthError.identityMismatch }
        guard actual == expectedCandidate else { throw UpdatePostInstallHealthError.identityMismatch }
        let frame = try UpdatePostInstallHealthProtocol.acknowledgement(
            nonceHex: nonceHex,
            processIdentifier: processIdentifier,
            candidate: actual
        )
        do {
            try frame.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(
                        descriptor,
                        bytes.baseAddress?.advanced(by: offset),
                        bytes.count - offset
                    )
                    if count > 0 { offset += count; continue }
                    if count < 0, errno == EINTR { continue }
                    throw UpdatePostInstallHealthError.acknowledgementFailed
                }
            }
            guard shutdown(descriptor, SHUT_WR) == 0 else {
                throw UpdatePostInstallHealthError.acknowledgementFailed
            }
            Darwin.close(descriptor)
            descriptor = -1
        } catch {
            throw error
        }
    }

    private static func readFrame(descriptor: Int32, deadline: TimeInterval) throws -> Data {
        let started = DispatchTime.now().uptimeNanoseconds
        let limit = UInt64(deadline * 1_000_000_000)
        var result = Data()
        var byte: UInt8 = 0
        while result.count < UpdatePostInstallHealthProtocol.maximumFrameBytes {
            let elapsed = DispatchTime.now().uptimeNanoseconds - started
            guard elapsed < limit else { throw UpdatePostInstallHealthError.invalidChallenge }
            var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let remaining = max(1, Int((limit - elapsed) / 1_000_000))
            let pollResult = Darwin.poll(&pollDescriptor, 1, Int32(min(remaining, 100)))
            if pollResult < 0, errno == EINTR { continue }
            guard pollResult >= 0 else { throw UpdatePostInstallHealthError.invalidChannel }
            if pollResult == 0 { continue }
            let count = Darwin.read(descriptor, &byte, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 1 else { throw UpdatePostInstallHealthError.invalidChallenge }
            result.append(byte)
            if byte == 0x0a { return result }
        }
        throw UpdatePostInstallHealthError.invalidChallenge
    }
}
