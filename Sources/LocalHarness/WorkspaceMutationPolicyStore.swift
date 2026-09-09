import Darwin
import Foundation

enum WorkspaceMutationPolicyMode: String, Codable, Equatable, Sendable {
    case readOnly
    case readWrite
}

enum WorkspaceMutationPolicyReason: String, Codable, Equatable, Sendable {
    case checkpointRequired
    case protectedCheckpoint
    case recoverabilityLimit
    case recoveryDeadline
}

struct WorkspaceMutationPolicy: Codable, Equatable, Sendable {
    static let schemaVersion = 1

    let schemaVersion: Int
    let mode: WorkspaceMutationPolicyMode
    let reason: WorkspaceMutationPolicyReason
}

enum WorkspaceMutationPolicyError: Error, Equatable, LocalizedError {
    case unsafeHome
    case unsafePolicy
    case writeFailed

    var errorDescription: String? {
        switch self {
        case .unsafeHome:
            return "The private Harness home could not be authenticated for workspace policy."
        case .unsafePolicy:
            return "The existing workspace mutation policy is linked, shared, or malformed."
        case .writeFailed:
            return "The workspace mutation policy could not be committed durably."
        }
    }
}

/// Writes the policy consumed synchronously by DSH's global pre-execute seam.
/// The file is owner-only and replaced atomically so a tool call observes
/// either the complete old decision or the complete new decision.
final class WorkspaceMutationPolicyStore: @unchecked Sendable {
    static let fileName = ".fulmar-workspace-mutation-policy.json"

    private let home: URL
    private let policyURL: URL
    private let lock = NSLock()

    init(harnessHome: URL) {
        home = harnessHome.standardizedFileURL
        policyURL = home.appendingPathComponent(Self.fileName, isDirectory: false)
    }

    func requireCheckpoint() throws {
        try write(mode: .readOnly, reason: .checkpointRequired)
    }

    func allowProtectedMutation() throws {
        try write(mode: .readWrite, reason: .protectedCheckpoint)
    }

    func requireReadOnly(reason: WorkspaceMutationPolicyReason) throws {
        precondition(reason == .recoverabilityLimit || reason == .recoveryDeadline)
        try write(mode: .readOnly, reason: reason)
    }

    func load() throws -> WorkspaceMutationPolicy {
        try lock.withLock {
            try validateHome()
            guard let metadata = Self.lstat(policyURL), Self.isPrivateRegularFile(metadata) else {
                throw WorkspaceMutationPolicyError.unsafePolicy
            }
            let data = try SecureAttachmentReader.readRegularFile(at: policyURL, maximumBytes: 1_024)
            let decoder = JSONDecoder()
            guard let policy = try? decoder.decode(WorkspaceMutationPolicy.self, from: data),
                  policy.schemaVersion == WorkspaceMutationPolicy.schemaVersion,
                  Self.isValid(policy) else {
                throw WorkspaceMutationPolicyError.unsafePolicy
            }
            return policy
        }
    }

    private func write(
        mode: WorkspaceMutationPolicyMode,
        reason: WorkspaceMutationPolicyReason
    ) throws {
        try lock.withLock {
            try validateHome()
            if let existing = Self.lstat(policyURL), !Self.isPrivateRegularFile(existing) {
                throw WorkspaceMutationPolicyError.unsafePolicy
            }
            let policy = WorkspaceMutationPolicy(
                schemaVersion: WorkspaceMutationPolicy.schemaVersion,
                mode: mode,
                reason: reason
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let bytes = try encoder.encode(policy)
            guard !bytes.isEmpty, bytes.count <= 1_024 else {
                throw WorkspaceMutationPolicyError.writeFailed
            }
            let temporary = home.appendingPathComponent(
                ".\(Self.fileName).\(UUID().uuidString).tmp",
                isDirectory: false
            )
            let descriptor = Darwin.open(
                temporary.path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
            guard descriptor >= 0 else { throw WorkspaceMutationPolicyError.writeFailed }
            var removeTemporary = true
            defer {
                Darwin.close(descriptor)
                if removeTemporary { _ = Darwin.unlink(temporary.path) }
            }
            do {
                try bytes.withUnsafeBytes { raw in
                    var offset = 0
                    while offset < raw.count {
                        let count = Darwin.write(
                            descriptor,
                            raw.baseAddress?.advanced(by: offset),
                            raw.count - offset
                        )
                        if count < 0, errno == EINTR { continue }
                        guard count > 0 else { throw WorkspaceMutationPolicyError.writeFailed }
                        offset += count
                    }
                }
                var temporaryMetadata = stat()
                guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
                      Darwin.fsync(descriptor) == 0,
                      Darwin.fstat(descriptor, &temporaryMetadata) == 0,
                      Self.isPrivateRegularFile(temporaryMetadata),
                      Int(temporaryMetadata.st_size) == bytes.count else {
                    throw WorkspaceMutationPolicyError.writeFailed
                }
                guard Darwin.rename(temporary.path, policyURL.path) == 0 else {
                    throw WorkspaceMutationPolicyError.writeFailed
                }
                removeTemporary = false
                let directory = Darwin.open(home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard directory >= 0 else { throw WorkspaceMutationPolicyError.writeFailed }
                defer { Darwin.close(directory) }
                guard Darwin.fsync(directory) == 0,
                      let committed = Self.lstat(policyURL),
                      Self.isPrivateRegularFile(committed) else {
                    throw WorkspaceMutationPolicyError.writeFailed
                }
            } catch let error as WorkspaceMutationPolicyError {
                throw error
            } catch {
                throw WorkspaceMutationPolicyError.writeFailed
            }
        }
    }

    private func validateHome() throws {
        guard let metadata = Self.lstat(home),
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              (Int(metadata.st_mode) & 0o077) == 0 else {
            throw WorkspaceMutationPolicyError.unsafeHome
        }
    }

    private static func isValid(_ policy: WorkspaceMutationPolicy) -> Bool {
        switch (policy.mode, policy.reason) {
        case (.readWrite, .protectedCheckpoint):
            return true
        case (.readOnly, .checkpointRequired),
             (.readOnly, .recoverabilityLimit),
             (.readOnly, .recoveryDeadline):
            return true
        case (.readWrite, .checkpointRequired),
             (.readWrite, .recoverabilityLimit),
             (.readWrite, .recoveryDeadline),
             (.readOnly, .protectedCheckpoint):
            return false
        }
    }

    private static func isPrivateRegularFile(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG &&
            metadata.st_uid == geteuid() &&
            metadata.st_nlink == 1 &&
            (Int(metadata.st_mode) & 0o077) == 0
    }

    private static func lstat(_ url: URL) -> stat? {
        var metadata = stat()
        return url.withUnsafeFileSystemRepresentation { path in
            guard let path, Darwin.lstat(path, &metadata) == 0 else { return nil }
            return metadata
        }
    }
}
