import CryptoKit
import Darwin
import Foundation

struct StateBackupAuthenticationKeyComponents: Sendable {
    let helper: URL
    let enforceIdentity: Bool
    let requiredExecutableDirectory: URL?
    let requiresBundleIntegrity: Bool

    init(
        helper: URL,
        enforceIdentity: Bool = false,
        requiredExecutableDirectory: URL? = nil,
        requiresBundleIntegrity: Bool = false
    ) {
        self.helper = helper
        self.enforceIdentity = enforceIdentity
        self.requiredExecutableDirectory = requiredExecutableDirectory
        self.requiresBundleIntegrity = requiresBundleIntegrity
    }
}

/// Keeps the backup-authentication Keychain operation outside the AppKit
/// process. A legacy Keychain ACL can therefore neither display unattended UI
/// nor hold startup forever: the signed helper disables UI and this supervisor
/// terminates its exact private process group at a bounded deadline.
final class StateBackupAuthenticationKeyClient: @unchecked Sendable {
    private struct PinnedComponents: Sendable {
        let components: StateBackupAuthenticationKeyComponents
        let device: UInt64?
        let inode: UInt64?
        let sha256: String?
    }

    typealias ComponentLocator = @Sendable () throws -> StateBackupAuthenticationKeyComponents
    typealias IntegrityVerifier = @Sendable () -> Bool
    typealias ProcessRunner = @Sendable (
        _ executable: URL,
        _ arguments: [String],
        _ environment: [String: String],
        _ outputLimit: Int,
        _ errorLimit: Int,
        _ deadline: TimeInterval
    ) throws -> CredentialMigrationProcessResult

    static let unattendedDeadline: TimeInterval = 3
    static let foregroundAuthorizationDeadline: TimeInterval = 120
    private static let maximumKeyBytes = 32
    private static let maximumDiagnosticBytes = 4 * 1_024
    private static let maximumHelperBytes = 64 * 1_024 * 1_024

    private let componentLocator: ComponentLocator?
    private let integrityVerifier: IntegrityVerifier
    private let processRunner: ProcessRunner
    private let backgroundDeadline: TimeInterval
    private let foregroundDeadline: TimeInterval
    private let cacheLock = NSLock()
    private var cachedKey: Data?

    init(
        componentLocator: ComponentLocator? = nil,
        integrityVerifier: @escaping IntegrityVerifier = { BundleIntegrityVerifier.verify() },
        backgroundDeadline: TimeInterval = StateBackupAuthenticationKeyClient.unattendedDeadline,
        foregroundDeadline: TimeInterval = StateBackupAuthenticationKeyClient.foregroundAuthorizationDeadline,
        processRunner: @escaping ProcessRunner = { executable, arguments, environment, output, error, deadline in
            try BoundedCredentialMigrationProcess.run(
                executable: executable,
                arguments: arguments,
                environment: environment,
                maximumStandardOutputBytes: output,
                maximumStandardErrorBytes: error,
                deadline: deadline
            )
        }
    ) {
        precondition(backgroundDeadline.isFinite && (0.05...30).contains(backgroundDeadline))
        precondition(foregroundDeadline.isFinite && (1...600).contains(foregroundDeadline))
        self.componentLocator = componentLocator
        self.integrityVerifier = integrityVerifier
        self.backgroundDeadline = backgroundDeadline
        self.foregroundDeadline = foregroundDeadline
        self.processRunner = processRunner
    }

    func loadOrCreate() throws -> Data {
        if let cached = cachedAuthenticationKey() { return cached }
        let key = try run(command: "backup-load-or-create", deadline: backgroundDeadline)
        admitValidatedKey(key)
        return key
    }

    /// This is intentionally read-only. The caller must validate the exact
    /// returned bytes against the authenticated backup catalog before admitting
    /// them to the process cache.
    func authorizeExistingForForeground() throws -> Data {
        try run(command: "backup-authorize-existing", deadline: foregroundDeadline)
    }

    func admitValidatedKey(_ key: Data) {
        guard key.count == Self.maximumKeyBytes else { return }
        cacheLock.lock()
        cachedKey = key
        cacheLock.unlock()
    }

    private func cachedAuthenticationKey() -> Data? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return cachedKey
    }

    private func run(command: String, deadline: TimeInterval) throws -> Data {
        let pinned: PinnedComponents
        do {
            pinned = try pinComponents()
            try revalidate(pinned)
        } catch {
            throw BackupError.authenticationUnavailable
        }
        let result: CredentialMigrationProcessResult
        do {
            result = try processRunner(
                pinned.components.helper,
                [command],
                ChildProcessEnvironment.make(nodeBin: nil),
                Self.maximumKeyBytes,
                Self.maximumDiagnosticBytes,
                deadline
            )
        } catch {
            throw BackupError.authenticationUnavailable
        }
        // Never admit bytes from a process whose executable or containing app
        // changed while the Keychain operation was running.
        do { try revalidate(pinned) }
        catch { throw BackupError.authenticationUnavailable }
        if let limit = result.limit {
            if case .deadline = limit { throw BackupError.authenticationTimedOut }
            throw BackupError.authenticationUnavailable
        }
        guard result.terminationSignal == nil else {
            throw BackupError.authenticationUnavailable
        }
        if result.exitStatus == 5 {
            throw BackupError.authenticationAuthorizationRequired
        }
        guard result.exitStatus == 0,
              result.standardOutput.count == Self.maximumKeyBytes else {
            throw BackupError.authenticationUnavailable
        }
        return result.standardOutput
    }

    private func locateComponents() throws -> StateBackupAuthenticationKeyComponents {
        let fileManager = FileManager.default
        if let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() {
            let helper = executableDirectory.appendingPathComponent("LocalHarnessCredentialHelper")
            if fileManager.isExecutableFile(atPath: helper.path) {
                return StateBackupAuthenticationKeyComponents(
                    helper: helper,
                    enforceIdentity: true,
                    requiredExecutableDirectory: executableDirectory,
                    requiresBundleIntegrity: Bundle.main.bundleURL.pathExtension == "app"
                )
            }
        }
        guard Bundle.main.bundleURL.pathExtension != "app" else {
            throw BackupError.authenticationUnavailable
        }
        let project = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true)
        let helper = project.appendingPathComponent(".build/debug/LocalHarnessCredentialHelper")
        guard fileManager.isExecutableFile(atPath: helper.path) else {
            throw BackupError.authenticationUnavailable
        }
        return StateBackupAuthenticationKeyComponents(
            helper: helper,
            enforceIdentity: true,
            requiredExecutableDirectory: helper.deletingLastPathComponent()
        )
    }

    private func pinComponents() throws -> PinnedComponents {
        let components = try componentLocator?() ?? locateComponents()
        // Injected locators remain a lightweight test seam unless they
        // explicitly opt into the production identity boundary.
        guard components.enforceIdentity else {
            return PinnedComponents(components: components, device: nil, inode: nil, sha256: nil)
        }
        try validateLocation(components)
        let helper = components.helper
        let path = helper.path

        var before = stat()
        guard lstat(path, &before) == 0,
              Self.isTrustedExecutable(before),
              let bytes = try? Data(contentsOf: helper, options: .mappedIfSafe) else {
            throw BackupError.authenticationUnavailable
        }
        var after = stat()
        guard lstat(path, &after) == 0,
              Self.isTrustedExecutable(after),
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              bytes.count == Int(after.st_size) else {
            throw BackupError.authenticationUnavailable
        }
        return PinnedComponents(
            components: components,
            device: UInt64(truncatingIfNeeded: after.st_dev),
            inode: UInt64(after.st_ino),
            sha256: Self.sha256(bytes)
        )
    }

    private func revalidate(_ pinned: PinnedComponents) throws {
        if pinned.components.requiresBundleIntegrity,
           !integrityVerifier() {
            throw BackupError.authenticationUnavailable
        }
        guard let device = pinned.device,
              let inode = pinned.inode,
              let expectedSHA256 = pinned.sha256 else { return }
        try validateLocation(pinned.components)
        var before = stat()
        guard lstat(pinned.components.helper.path, &before) == 0,
              Self.isTrustedExecutable(before),
              UInt64(truncatingIfNeeded: before.st_dev) == device,
              UInt64(before.st_ino) == inode,
              let bytes = try? Data(contentsOf: pinned.components.helper, options: .mappedIfSafe),
              bytes.count == Int(before.st_size) else {
            throw BackupError.authenticationUnavailable
        }
        var after = stat()
        guard lstat(pinned.components.helper.path, &after) == 0,
              Self.isTrustedExecutable(after),
              UInt64(truncatingIfNeeded: after.st_dev) == device,
              UInt64(after.st_ino) == inode,
              before.st_size == after.st_size,
              Self.sha256(bytes) == expectedSHA256 else {
            throw BackupError.authenticationUnavailable
        }
    }

    private func validateLocation(_ components: StateBackupAuthenticationKeyComponents) throws {
        let helper = components.helper
        let path = helper.path
        guard helper.isFileURL,
              helper.lastPathComponent == "LocalHarnessCredentialHelper",
              path == helper.standardizedFileURL.path,
              path == helper.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw BackupError.authenticationUnavailable
        }
        if let requiredDirectory = components.requiredExecutableDirectory {
            let requiredPath = requiredDirectory.path
            guard requiredDirectory.isFileURL,
                  requiredPath == requiredDirectory.standardizedFileURL.path,
                  requiredPath == requiredDirectory.resolvingSymlinksInPath().standardizedFileURL.path,
                  helper.deletingLastPathComponent().path == requiredPath else {
                throw BackupError.authenticationUnavailable
            }
        }
    }

    private static func isTrustedExecutable(_ info: stat) -> Bool {
        info.st_mode & S_IFMT == S_IFREG
            && (info.st_uid == geteuid() || info.st_uid == 0)
            && info.st_mode & 0o022 == 0
            && info.st_mode & S_IXUSR != 0
            && info.st_size > 0
            && info.st_size <= maximumHelperBytes
    }

    private static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}
