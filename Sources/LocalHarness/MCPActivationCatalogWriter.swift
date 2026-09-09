import Darwin
import Foundation

struct MCPActivationCatalog: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let plans: [MCPActivationPlan]

    init(plans: [MCPActivationPlan]) {
        schemaVersion = Self.currentSchemaVersion
        self.plans = plans
    }
}

enum MCPActivationCatalogError: Error, Equatable, LocalizedError {
    case insecureStorage
    case catalogTooLarge
    case writeFailed

    var errorDescription: String? {
        switch self {
        case .insecureStorage:
            return "The active MCP catalog is not in private owner-only storage."
        case .catalogTooLarge:
            return "The active MCP catalog exceeds its safety limit."
        case .writeFailed:
            return "The active MCP catalog could not be written atomically."
        }
    }
}

/// Materializes the already revalidated, secret-free plans consumed by the
/// guarded DSH adapter. The catalog is replaced atomically on every runtime
/// launch, including launches with no enabled servers, so stale trust can never
/// survive a provider switch or revocation.
enum MCPActivationCatalogWriter {
    static let filename = "active-mcp-v1.json"
    // Keep this identical to the independently validating JavaScript adapter.
    static let maximumBytes = 2 * 1_024 * 1_024

    @discardableResult
    static func write(
        plans: [MCPActivationPlan],
        applicationSupport: URL,
        fileManager: FileManager = .default
    ) throws -> URL {
        let directory = applicationSupport.appendingPathComponent("Security", isDirectory: true)
        if !fileManager.fileExists(atPath: directory.path) {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
        guard isPrivateDirectory(directory) else { throw MCPActivationCatalogError.insecureStorage }

        let destination = directory.appendingPathComponent(filename, isDirectory: false)
        if let existing = metadata(destination) {
            guard isPrivateRegularFile(existing), existing.st_nlink == 1 else {
                throw MCPActivationCatalogError.insecureStorage
            }
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(MCPActivationCatalog(plans: plans))
        guard data.count <= maximumBytes else { throw MCPActivationCatalogError.catalogTooLarge }

        let temporary = directory.appendingPathComponent(".\(filename).\(UUID().uuidString).tmp", isDirectory: false)
        let descriptor = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw MCPActivationCatalogError.writeFailed }
        var shouldRemoveTemporary = true
        defer {
            Darwin.close(descriptor)
            if shouldRemoveTemporary { _ = Darwin.unlink(temporary.path) }
        }

        do {
            try data.withUnsafeBytes { bytes in
                guard let base = bytes.baseAddress else { return }
                var written = 0
                while written < bytes.count {
                    let count = Darwin.write(descriptor, base.advanced(by: written), bytes.count - written)
                    if count < 0 {
                        if errno == EINTR { continue }
                        throw MCPActivationCatalogError.writeFailed
                    }
                    written += count
                }
            }
            guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
                  Darwin.fsync(descriptor) == 0,
                  Darwin.rename(temporary.path, destination.path) == 0,
                  let final = metadata(destination),
                  isPrivateRegularFile(final),
                  final.st_nlink == 1 else {
                throw MCPActivationCatalogError.writeFailed
            }
            shouldRemoveTemporary = false
            return destination
        } catch let error as MCPActivationCatalogError {
            throw error
        } catch {
            throw MCPActivationCatalogError.writeFailed
        }
    }

    private static func metadata(_ url: URL) -> stat? {
        var information = stat()
        let result = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.lstat(path, &information)
        }
        return result == 0 ? information : nil
    }

    private static func isPrivateDirectory(_ url: URL) -> Bool {
        guard let information = metadata(url),
              information.st_uid == geteuid(),
              (information.st_mode & S_IFMT) == S_IFDIR else { return false }
        return (Int(information.st_mode) & 0o077) == 0
    }

    private static func isPrivateRegularFile(_ information: stat) -> Bool {
        information.st_uid == geteuid()
            && (information.st_mode & S_IFMT) == S_IFREG
            && (Int(information.st_mode) & 0o077) == 0
    }
}

enum MCPActivationCatalogBuilder {
    /// Re-reads executable, entry-point, project, provider, and boundary state
    /// immediately before launch. Expected non-applicable records are omitted;
    /// unexpected storage failures still abort the launch.
    static func revalidatedPlans(
        store: MCPTrustStore,
        context: MCPActivationContext,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> [MCPActivationPlan] {
        var plans: [MCPActivationPlan] = []
        for record in store.records() where record.approval != nil {
            try preparationBudget?.checkpoint()
            do {
                plans.append(try store.activationPlan(
                    id: record.id,
                    context: context,
                    preparationBudget: preparationBudget
                ))
            } catch MCPTrustStoreError.providerNotAllowed {
                continue
            } catch MCPTrustStoreError.notTrusted {
                continue
            } catch MCPTrustStoreError.trustRevoked {
                continue
            } catch let error as RuntimeStartupPrerequisiteError {
                throw error
            }
        }
        try preparationBudget?.checkpoint()
        return plans.sorted { $0.serverID < $1.serverID }
    }
}
