import CryptoKit
import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol

struct CredentialMigrationResult: Codable, Equatable, Sendable {
    let references: Int
    let records: Int
}

enum CredentialMigrationStartupRequirement: Equatable, Sendable {
    case none
    case plaintextNeedsConsent
    case zeroTombstoneNeedsAutomaticVerification
}

struct CredentialMigrationComponents: Sendable {
    let node: URL
    let script: URL
    let helper: URL
    let yaml: URL
    let service: URL?
    let enforceIdentity: Bool
    let requiredExecutableDirectory: URL?
    let requiredResourceDirectory: URL?
    let requiredProjectDirectory: URL?
    let requiresBundleIntegrity: Bool

    init(
        node: URL,
        script: URL,
        helper: URL,
        yaml: URL,
        service: URL? = nil,
        enforceIdentity: Bool = false,
        requiredExecutableDirectory: URL? = nil,
        requiredResourceDirectory: URL? = nil,
        requiredProjectDirectory: URL? = nil,
        requiresBundleIntegrity: Bool = false
    ) {
        self.node = node
        self.script = script
        self.helper = helper
        self.yaml = yaml
        self.service = service
        self.enforceIdentity = enforceIdentity
        self.requiredExecutableDirectory = requiredExecutableDirectory
        self.requiredResourceDirectory = requiredResourceDirectory
        self.requiredProjectDirectory = requiredProjectDirectory
        self.requiresBundleIntegrity = requiresBundleIntegrity
    }
}

private final class CredentialMigrationCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Result<CredentialMigrationResult, Error>) -> Void)?

    init(_ completion: @escaping (Result<CredentialMigrationResult, Error>) -> Void) {
        self.completion = completion
    }

    func resolve(_ result: Result<CredentialMigrationResult, Error>) {
        lock.lock()
        let callback = completion
        completion = nil
        lock.unlock()
        guard let callback else { return }
        DispatchQueue.main.async { callback(result) }
    }
}

private final class CredentialMigrationLeaseRegistry: @unchecked Sendable {
    static let shared = CredentialMigrationLeaseRegistry()

    private let lock = NSLock()
    private var activePaths: Set<String> = []

    func reserve(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return activePaths.insert(path).inserted
    }

    func release(_ path: String) {
        lock.lock()
        activePaths.remove(path)
        lock.unlock()
    }
}

/// One persistent advisory lock serializes first-start migration across every
/// Fulmar process. The path is never unlinked after use: an unlocked stale path
/// is reusable only after its exact owner, mode, link count, device, and inode
/// have been proven again and the kernel lock has been acquired.
private final class CredentialMigrationLease: @unchecked Sendable {
    fileprivate static let fileName = ".fulmar-credential-migration.lock"
    private static let maximumAcquisitionAttempts = 25
    private static let retryDelayMicroseconds: useconds_t = 10_000

    private let url: URL
    private let device: dev_t
    private let inode: ino_t
    private let registry: CredentialMigrationLeaseRegistry
    private let lifecycleLock = NSLock()
    private var descriptor: Int32

    private init(
        url: URL,
        descriptor: Int32,
        device: dev_t,
        inode: ino_t,
        registry: CredentialMigrationLeaseRegistry
    ) {
        self.url = url
        self.descriptor = descriptor
        self.device = device
        self.inode = inode
        self.registry = registry
    }

    deinit { releaseWithoutValidation() }

    fileprivate static func leaseURL(for sourceURL: URL) throws -> URL {
        let directory = sourceURL.deletingLastPathComponent()
        var directoryMetadata = stat()
        guard sourceURL.isFileURL,
              sourceURL.path.hasPrefix("/"),
              !sourceURL.lastPathComponent.isEmpty,
              sourceURL.path == sourceURL.standardizedFileURL.path,
              directory.isFileURL,
              directory.path == directory.standardizedFileURL.path,
              directory.path == directory.resolvingSymlinksInPath().standardizedFileURL.path,
              Darwin.lstat(directory.path, &directoryMetadata) == 0,
              directoryMetadata.st_mode & S_IFMT == S_IFDIR,
              directoryMetadata.st_uid == geteuid(),
              directoryMetadata.st_mode & 0o022 == 0,
              CredentialMigrationFileSecurity.pathHasNoExtendedACL(
                directory.path,
                directory: true
              ) else {
            throw CredentialMigrationError.componentsMissing
        }
        let result = directory.appendingPathComponent(fileName, isDirectory: false)
        guard result.path == result.standardizedFileURL.path,
              result.deletingLastPathComponent().path == directory.path else {
            throw CredentialMigrationError.componentsMissing
        }
        return result
    }

    fileprivate static func withExclusiveLease<T>(
        sourceURL: URL,
        operation: (CredentialMigrationInheritedDescriptor) throws -> T
    ) throws -> T {
        let lease = try acquire(sourceURL: sourceURL)
        let operationResult: Result<T, Error>
        do {
            let inheritance = try lease.childInheritance()
            let value = try operation(inheritance)
            try lease.revalidate()
            operationResult = .success(value)
        } catch let operationError {
            do {
                try lease.revalidate()
                operationResult = .failure(operationError)
            } catch {
                operationResult = .failure(CredentialMigrationError.componentsMissing)
            }
        }

        // Validation is repeated immediately before unlock. Even a successful
        // child result has no authority after a path replacement or metadata
        // change, and release still closes the descriptor on every failure.
        try lease.release()
        return try operationResult.get()
    }

    private static func acquire(sourceURL: URL) throws -> CredentialMigrationLease {
        let url = try leaseURL(for: sourceURL)
        let registry = CredentialMigrationLeaseRegistry.shared
        guard registry.reserve(url.path) else {
            throw CredentialMigrationError.migrationInProgress
        }
        var reservationOwned = true
        var descriptor: Int32 = -1
        defer {
            if descriptor >= 0 { _ = Darwin.close(descriptor) }
            if reservationOwned { registry.release(url.path) }
        }

        descriptor = Darwin.open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        var created = false
        if descriptor < 0, errno == ENOENT {
            descriptor = Darwin.open(
                url.path,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
            created = descriptor >= 0
            if descriptor < 0, errno == EEXIST {
                descriptor = Darwin.open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            }
        }
        guard descriptor >= 0 else {
            throw CredentialMigrationError.componentsMissing
        }
        let initial = try validate(
            descriptor: descriptor,
            url: url,
            expectedDevice: nil,
            expectedInode: nil
        )
        if created { try synchronizeDirectory(url.deletingLastPathComponent()) }

        var acquired = false
        for attempt in 0..<maximumAcquisitionAttempts {
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                acquired = true
                break
            }
            let lockError = errno
            guard lockError == EWOULDBLOCK || lockError == EAGAIN || lockError == EINTR else {
                throw CredentialMigrationError.componentsMissing
            }
            _ = try validate(
                descriptor: descriptor,
                url: url,
                expectedDevice: initial.st_dev,
                expectedInode: initial.st_ino
            )
            if lockError != EINTR, attempt + 1 < maximumAcquisitionAttempts {
                Darwin.usleep(retryDelayMicroseconds)
            }
        }
        guard acquired else { throw CredentialMigrationError.migrationInProgress }
        do {
            _ = try validate(
                descriptor: descriptor,
                url: url,
                expectedDevice: initial.st_dev,
                expectedInode: initial.st_ino
            )
        } catch {
            _ = flock(descriptor, LOCK_UN)
            throw error
        }

        let result = CredentialMigrationLease(
            url: url,
            descriptor: descriptor,
            device: initial.st_dev,
            inode: initial.st_ino,
            registry: registry
        )
        descriptor = -1
        reservationOwned = false
        return result
    }

    private func revalidate() throws {
        lifecycleLock.lock()
        let descriptor = self.descriptor
        lifecycleLock.unlock()
        guard descriptor >= 0 else { throw CredentialMigrationError.componentsMissing }
        _ = try Self.validate(
            descriptor: descriptor,
            url: url,
            expectedDevice: device,
            expectedInode: inode
        )
    }

    private func childInheritance() throws -> CredentialMigrationInheritedDescriptor {
        lifecycleLock.lock()
        let descriptor = self.descriptor
        lifecycleLock.unlock()
        guard descriptor >= 0 else { throw CredentialMigrationError.componentsMissing }
        _ = try Self.validate(
            descriptor: descriptor,
            url: url,
            expectedDevice: device,
            expectedInode: inode
        )
        return CredentialMigrationInheritedDescriptor(
            sourceDescriptor: descriptor,
            expectedDevice: UInt64(truncatingIfNeeded: device),
            expectedInode: UInt64(inode)
        )
    }

    private func release() throws {
        lifecycleLock.lock()
        let descriptor = self.descriptor
        self.descriptor = -1
        lifecycleLock.unlock()
        guard descriptor >= 0 else { return }

        let validationSucceeded: Bool
        do {
            _ = try Self.validate(
                descriptor: descriptor,
                url: url,
                expectedDevice: device,
                expectedInode: inode
            )
            validationSucceeded = true
        } catch {
            validationSucceeded = false
        }
        let unlocked = flock(descriptor, LOCK_UN) == 0
        let closed = Darwin.close(descriptor) == 0
        registry.release(url.path)
        guard validationSucceeded, unlocked, closed else {
            throw CredentialMigrationError.componentsMissing
        }
    }

    private func releaseWithoutValidation() {
        lifecycleLock.lock()
        let descriptor = self.descriptor
        self.descriptor = -1
        lifecycleLock.unlock()
        guard descriptor >= 0 else { return }
        _ = flock(descriptor, LOCK_UN)
        _ = Darwin.close(descriptor)
        registry.release(url.path)
    }

    private static func validate(
        descriptor: Int32,
        url: URL,
        expectedDevice: dev_t?,
        expectedInode: ino_t?
    ) throws -> stat {
        var descriptorMetadata = stat()
        var pathMetadata = stat()
        guard url.isFileURL,
              url.path == url.standardizedFileURL.path,
              url.path == url.resolvingSymlinksInPath().standardizedFileURL.path,
              Darwin.fstat(descriptor, &descriptorMetadata) == 0,
              Darwin.lstat(url.path, &pathMetadata) == 0,
              secureMetadata(descriptorMetadata),
              secureMetadata(pathMetadata),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              descriptorMetadata.st_dev == pathMetadata.st_dev,
              descriptorMetadata.st_ino == pathMetadata.st_ino,
              expectedDevice.map({ descriptorMetadata.st_dev == $0 }) ?? true,
              expectedInode.map({ descriptorMetadata.st_ino == $0 }) ?? true else {
            throw CredentialMigrationError.componentsMissing
        }
        return descriptorMetadata
    }

    private static func secureMetadata(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o777 == 0o600
            && metadata.st_size == 0
    }

    private static func synchronizeDirectory(_ directory: URL) throws {
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw CredentialMigrationError.componentsMissing }
        defer { _ = Darwin.close(descriptor) }
        guard Darwin.fsync(descriptor) == 0 else {
            throw CredentialMigrationError.componentsMissing
        }
    }
}

final class CredentialMigrationManager: @unchecked Sendable {
    private final class PinnedFile: @unchecked Sendable {
        let url: URL
        let executable: Bool
        let maximumBytes: Int64
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let sha256: String
        let bytes: Data
        let descriptor: Int32

        init(
            url: URL,
            executable: Bool,
            maximumBytes: Int64,
            device: UInt64,
            inode: UInt64,
            size: Int64,
            sha256: String,
            bytes: Data,
            descriptor: Int32
        ) {
            self.url = url
            self.executable = executable
            self.maximumBytes = maximumBytes
            self.device = device
            self.inode = inode
            self.size = size
            self.sha256 = sha256
            self.bytes = bytes
            self.descriptor = descriptor
        }

        deinit { _ = Darwin.close(descriptor) }
    }

    private struct PinnedComponents: Sendable {
        let components: CredentialMigrationComponents
        let files: [PinnedFile]
    }

    /// Descriptor-read snapshot of the YAML package's complete executable JS
    /// graph. Production sends these reviewed bytes to the signed XPC service's
    /// JavaScriptCore realm; the injected test seam retains its legacy Node
    /// adapter. Neither path imports a mutable module pathname after pinning.
    private final class YAMLExecutionGraph: @unchecked Sendable {
        let payload: String
        let data: Data
        let sourceFiles: [PinnedFile]

        init(payload: String, data: Data, sourceFiles: [PinnedFile]) {
            self.payload = payload
            self.data = data
            self.sourceFiles = sourceFiles
        }
    }

    typealias ComponentLocator = @Sendable () throws -> CredentialMigrationComponents
    typealias IntegrityVerifier = @Sendable () -> Bool
    typealias ProcessRunner = @Sendable (
        _ executable: URL,
        _ arguments: [String],
        _ environment: [String: String],
        _ outputLimit: Int,
        _ errorLimit: Int,
        _ deadline: TimeInterval,
        _ inheritedDescriptor: CredentialMigrationInheritedDescriptor
    ) throws -> CredentialMigrationProcessResult

    static let maximumResultBytes = 64 * 1_024
    static let maximumDiagnosticBytes = 64 * 1_024
    static let defaultDeadline: TimeInterval = 60
    static let leaseEnvironmentMarkerName = "FULMAR_CREDENTIAL_MIGRATION_LEASE_FD_V1"
    static let leaseEnvironmentMarkerValue = String(
        CredentialMigrationInheritedDescriptor.fixedChildDescriptor
    )
    static let programEnvironmentMarkerName = "FULMAR_CREDENTIAL_MIGRATION_PROGRAM_V1"
    static let programEnvironmentPayloadName = "FULMAR_CREDENTIAL_MIGRATION_PROGRAM_BASE64"
    static let programEnvironmentMarkerValue = "descriptor-pinned-base64-v1"
    static let programBootstrap = "await import('data:text/javascript;base64,' + process.env.FULMAR_CREDENTIAL_MIGRATION_PROGRAM_BASE64)"
    static let yamlGraphEnvironmentMarkerName = "FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_V1"
    static let yamlGraphEnvironmentPayloadName = "FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_BASE64"
    static let yamlGraphEnvironmentMarkerValue = "descriptor-pinned-commonjs-v1"
    private static let maximumNodeBytes: Int64 = 256 * 1_024 * 1_024
    private static let maximumHelperBytes: Int64 = 64 * 1_024 * 1_024
    private static let maximumScriptBytes: Int64 = 4 * 1_024 * 1_024
    private static let maximumYAMLModuleBytes: Int64 = 8 * 1_024 * 1_024
    private static let maximumYAMLGraphFiles = 128
    private static let maximumYAMLGraphBytes: Int64 = 8 * 1_024 * 1_024

    static func credentialMigrationLeaseURL(for sourceURL: URL) throws -> URL {
        try CredentialMigrationLease.leaseURL(for: sourceURL)
    }

    private let fileManager = FileManager.default
    private let componentLocator: ComponentLocator?
    private let integrityVerifier: IntegrityVerifier
    private let processRunner: ProcessRunner
    private let deadline: TimeInterval
    let sourceURL: URL

    init(
        sourceURL: URL? = nil,
        componentLocator: ComponentLocator? = nil,
        integrityVerifier: @escaping IntegrityVerifier = { BundleIntegrityVerifier.verify() },
        deadline: TimeInterval = CredentialMigrationManager.defaultDeadline,
        processRunner: @escaping ProcessRunner = { executable, arguments, environment, output, error, deadline, inheritedDescriptor in
            try BoundedCredentialMigrationProcess.run(
                executable: executable,
                arguments: arguments,
                environment: environment,
                maximumStandardOutputBytes: output,
                maximumStandardErrorBytes: error,
                deadline: deadline,
                inheritedDescriptor: inheritedDescriptor
            )
        }
    ) {
        precondition(deadline.isFinite && deadline >= 0.05 && deadline <= 3_600)
        self.sourceURL = sourceURL
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".dsh/.credentials.yaml")
        self.componentLocator = componentLocator
        self.integrityVerifier = integrityVerifier
        self.deadline = deadline
        self.processRunner = processRunner
    }

    var startupRequirement: CredentialMigrationStartupRequirement {
        let descriptor = Darwin.open(
            sourceURL.path,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            // Only a definitely absent source can be skipped. A symlink,
            // permissions failure, or other ambiguous source must enter the
            // mandatory verification path so startup cannot offer a consent
            // prompt that lets the user bypass credential recovery.
            return errno == ENOENT ? .none : .zeroTombstoneNeedsAutomaticVerification
        }
        defer { _ = Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0 else {
            return .zeroTombstoneNeedsAutomaticVerification
        }
        guard (metadata.st_mode & S_IFMT) == S_IFREG else {
            return .zeroTombstoneNeedsAutomaticVerification
        }
        // A zero-length source is only a candidate tombstone. The signed XPC
        // service must authenticate its durable receipt and re-verify every
        // Keychain digest before startup may treat migration as complete.
        return metadata.st_size == 0
            ? .zeroTombstoneNeedsAutomaticVerification
            : .plaintextNeedsConsent
    }

    var requiresMigration: Bool {
        startupRequirement != .none
    }

    func migrate(completion: @escaping (Result<CredentialMigrationResult, Error>) -> Void) {
        let completionGate = CredentialMigrationCompletionGate(completion)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            do {
                let decoded = try CredentialMigrationLease.withExclusiveLease(sourceURL: sourceURL) { inheritance in
                    try performMigrationHoldingLease(inheritedDescriptor: inheritance)
                }
                completionGate.resolve(.success(decoded))
            } catch let error as CredentialMigrationError {
                completionGate.resolve(.failure(error))
            } catch {
                completionGate.resolve(.failure(CredentialMigrationError.componentsMissing))
            }
        }
    }

    private func performMigrationHoldingLease(
        inheritedDescriptor: CredentialMigrationInheritedDescriptor
    ) throws -> CredentialMigrationResult {
        // A contender can observe the legacy file before the winner removes it,
        // then acquire the persistent lock after that winner exits. Recheck only
        // after lease acquisition so a completed migration never launches a
        // second helper process.
        var sourceMetadata = stat()
        if Darwin.lstat(sourceURL.path, &sourceMetadata) != 0 {
            if errno == ENOENT { return CredentialMigrationResult(references: 0, records: 0) }
            throw CredentialMigrationError.componentsMissing
        }
        // An extended ACL on the plaintext source is rejected before any
        // component location, pinning, or helper launch. A preplanted grant
        // must not widen who can observe the migration boundary, and the ACL
        // itself is preserved for the owner to inspect. The parent directory
        // receives the same check during lease acquisition.
        guard CredentialMigrationFileSecurity.pathHasNoExtendedACL(sourceURL.path) else {
            throw CredentialMigrationError.componentsMissing
        }
        let pinned = try pinComponents()
        try revalidate(pinned)
        let components = pinned.components
        let yamlGraph = components.enforceIdentity
            ? try makeYAMLExecutionGraph(for: components.yaml)
            : nil
        if let yamlGraph { try revalidate(yamlGraph.sourceFiles) }
        let result: CredentialMigrationProcessResult
        if components.requiresBundleIntegrity, componentLocator == nil {
            guard let yamlGraph,
                  let service = components.service else {
                throw CredentialMigrationError.componentsMissing
            }
            do {
                let response = try CredentialMigrationXPCClient.run(
                    serviceBundleURL: service,
                    helperURL: components.helper,
                    sourceURL: sourceURL,
                    leaseDescriptor: inheritedDescriptor,
                    yamlGraph: yamlGraph.data,
                    deadline: deadline
                )
                try revalidate(pinned)
                try revalidate(yamlGraph.sourceFiles)
                guard CredentialMigrationXPCClient.validateCommittedPaths(
                    sourceURL: sourceURL,
                    leaseDescriptor: inheritedDescriptor
                ) else {
                    throw CredentialMigrationError.sourceInvalid
                }
                return CredentialMigrationResult(
                    references: response.references,
                    records: response.records
                )
            } catch let error as CredentialMigrationXPCClientError {
                throw Self.mapServiceError(error)
            }
        }
        do {
            var environment = ChildProcessEnvironment.make(
                nodeBin: components.node.deletingLastPathComponent().path
            )
            // This one versioned capability marker is consumed only by the
            // pinned migration script. That script independently proves that
            // fd 198 and the canonical sibling lease path are the same secure
            // inode before importing YAML or touching credential data.
            environment[Self.leaseEnvironmentMarkerName] = Self.leaseEnvironmentMarkerValue
            if let yamlGraph {
                guard let script = pinned.files.first(where: { $0.url == components.script }) else {
                    throw CredentialMigrationError.componentsMissing
                }
                environment[Self.programEnvironmentMarkerName]
                    = Self.programEnvironmentMarkerValue
                environment[Self.programEnvironmentPayloadName] = script.bytes.base64EncodedString()
                environment[Self.yamlGraphEnvironmentMarkerName]
                    = Self.yamlGraphEnvironmentMarkerValue
                environment[Self.yamlGraphEnvironmentPayloadName] = yamlGraph.payload
                result = try processRunner(
                    components.node,
                    [
                        "--input-type=module",
                        "--eval",
                        Self.programBootstrap,
                        sourceURL.path,
                        components.helper.path,
                        "descriptor-bound-yaml-graph",
                    ],
                    environment,
                    Self.maximumResultBytes,
                    Self.maximumDiagnosticBytes,
                    deadline,
                    inheritedDescriptor
                )
            } else {
                // Explicitly injected debug/test component sets retain their
                // existing path-based runner seam. Production components must
                // always opt into the complete descriptor identity boundary.
                result = try processRunner(
                    components.node,
                    [components.script.path, sourceURL.path, components.helper.path, components.yaml.path],
                    environment,
                    Self.maximumResultBytes,
                    Self.maximumDiagnosticBytes,
                    deadline,
                    inheritedDescriptor
                )
            }
        } catch {
            throw CredentialMigrationError.runnerUnavailable
        }
        // A successful child result has no authority if any executable or
        // imported source changed during the migration boundary. The outer
        // lease remains held throughout this post-run verification.
        try revalidate(pinned)
        if let yamlGraph { try revalidate(yamlGraph.sourceFiles) }
        if let limit = result.limit {
            switch limit {
            case .standardInputBytes:
                // Credential migration never sends stdin. Treat an input-pipe
                // failure as an unavailable trusted runner rather than
                // misreporting it as output truncation.
                throw CredentialMigrationError.runnerUnavailable
            case .deadline:
                throw CredentialMigrationError.timedOut
            case .standardOutputBytes:
                throw CredentialMigrationError.outputLimitExceeded(.standardOutput)
            case .standardErrorBytes:
                throw CredentialMigrationError.outputLimitExceeded(.standardError)
            }
        }
        guard result.terminationSignal == nil, result.exitStatus == 0 else {
            throw CredentialMigrationError.processFailed(
                exitStatus: result.exitStatus,
                signal: result.terminationSignal,
                diagnosticBytes: result.standardError.count
            )
        }
        guard result.standardOutput.count <= Self.maximumResultBytes,
              let decoded = try? JSONDecoder().decode(
                CredentialMigrationResult.self,
                from: result.standardOutput
              ),
              decoded.references >= 0,
              decoded.records >= 0,
              decoded.references <= 1_000_000,
              decoded.records <= 1_000_000 else {
            throw CredentialMigrationError.invalidResult
        }
        return decoded
    }

    private func locateComponents() throws -> CredentialMigrationComponents {
        if let resources = Bundle.main.resourceURL,
           let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() {
            let result = CredentialMigrationComponents(
                node: resources.appendingPathComponent("Runtime/node"),
                script: resources.appendingPathComponent("MigrateCredentials.mjs"),
                helper: executableDirectory.appendingPathComponent("LocalHarnessCredentialHelper"),
                yaml: resources.appendingPathComponent("Runtime/dsh/node_modules/yaml/dist/index.js"),
                service: Bundle.main.bundleURL
                    .appendingPathComponent("Contents/XPCServices", isDirectory: true)
                    .appendingPathComponent(
                        CredentialMigrationXPCConstants.serviceBundleName,
                        isDirectory: true
                    ),
                enforceIdentity: true,
                requiredExecutableDirectory: executableDirectory,
                requiredResourceDirectory: resources,
                requiresBundleIntegrity: Bundle.main.bundleURL.pathExtension == "app"
            )
            if fileManager.isExecutableFile(atPath: result.helper.path),
               fileManager.fileExists(atPath: result.yaml.path),
               result.service.map({
                    fileManager.fileExists(atPath: $0.path)
                        && Bundle(url: $0)?.bundleIdentifier
                            == CredentialMigrationXPCConstants.serviceName
               }) == true { return result }
        }
        guard Bundle.main.bundleURL.pathExtension != "app" else {
            throw CredentialMigrationError.componentsMissing
        }
        let project = URL(fileURLWithPath: fileManager.currentDirectoryPath)
        let result = CredentialMigrationComponents(
            node: project.appendingPathComponent("VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"),
            script: project.appendingPathComponent("Resources/MigrateCredentials.mjs"),
            helper: project.appendingPathComponent(".build/debug/LocalHarnessCredentialHelper"),
            yaml: project.appendingPathComponent("VendorRuntime/node_modules/yaml/dist/index.js"),
            enforceIdentity: true,
            requiredProjectDirectory: project
        )
        guard fileManager.isExecutableFile(atPath: result.node.path),
              fileManager.fileExists(atPath: result.script.path),
              fileManager.isExecutableFile(atPath: result.helper.path),
              fileManager.fileExists(atPath: result.yaml.path) else {
            throw CredentialMigrationError.componentsMissing
        }
        return result
    }

    private func pinComponents() throws -> PinnedComponents {
        let components = try componentLocator?() ?? locateComponents()
        // Injected component sets are explicitly untrusted test seams unless
        // the test opts into the complete production identity boundary.
        guard components.enforceIdentity else {
            return PinnedComponents(components: components, files: [])
        }
        try validateExpectedLayout(components)
        if components.requiresBundleIntegrity, componentLocator == nil {
            // The packaged migration never launches Node or the JavaScript
            // migration adapter. Pin only the signed helper identity used for
            // Keychain ACL continuity and the descriptor-read YAML graph.
            return PinnedComponents(components: components, files: [
                try pinFile(
                    components.helper,
                    executable: true,
                    maximumBytes: Self.maximumHelperBytes
                ),
                try pinFile(
                    components.yaml,
                    executable: false,
                    maximumBytes: Self.maximumYAMLModuleBytes
                ),
            ])
        }
        return PinnedComponents(components: components, files: [
            try pinFile(components.node, executable: true, maximumBytes: Self.maximumNodeBytes),
            try pinFile(components.script, executable: false, maximumBytes: Self.maximumScriptBytes),
            try pinFile(components.helper, executable: true, maximumBytes: Self.maximumHelperBytes),
            try pinFile(components.yaml, executable: false, maximumBytes: Self.maximumYAMLModuleBytes),
        ])
    }

    private func validateExpectedLayout(_ components: CredentialMigrationComponents) throws {
        if let executableDirectory = components.requiredExecutableDirectory,
           let resources = components.requiredResourceDirectory {
            guard Self.isCanonicalDirectory(executableDirectory),
                  Self.isCanonicalDirectory(resources),
                  components.helper.path == executableDirectory
                    .appendingPathComponent("LocalHarnessCredentialHelper").path,
                  components.node.path == resources.appendingPathComponent("Runtime/node").path,
                  components.script.path == resources.appendingPathComponent("MigrateCredentials.mjs").path,
                  components.yaml.path == resources
                    .appendingPathComponent("Runtime/dsh/node_modules/yaml/dist/index.js").path,
                  components.service?.path == executableDirectory
                    .deletingLastPathComponent()
                    .appendingPathComponent("XPCServices", isDirectory: true)
                    .appendingPathComponent(
                        CredentialMigrationXPCConstants.serviceBundleName,
                        isDirectory: true
                    ).path else {
                throw CredentialMigrationError.componentsMissing
            }
        } else if components.requiredExecutableDirectory != nil
                    || components.requiredResourceDirectory != nil {
            throw CredentialMigrationError.componentsMissing
        }
        if let project = components.requiredProjectDirectory {
            guard Self.isCanonicalDirectory(project),
                  components.node.path == project
                    .appendingPathComponent("VendorRuntime/node-v22.23.1-darwin-arm64/bin/node").path,
                  components.script.path == project.appendingPathComponent("Resources/MigrateCredentials.mjs").path,
                  components.helper.path == project
                    .appendingPathComponent(".build/debug/LocalHarnessCredentialHelper").path,
                  components.yaml.path == project
                    .appendingPathComponent("VendorRuntime/node_modules/yaml/dist/index.js").path else {
                throw CredentialMigrationError.componentsMissing
            }
        }
    }

    private func pinFile(_ url: URL, executable: Bool, maximumBytes: Int64) throws -> PinnedFile {
        let path = url.path
        guard url.isFileURL,
              path == url.standardizedFileURL.path,
              path == url.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw CredentialMigrationError.componentsMissing
        }
        let (descriptor, bytes, after) = try Self.openTrustedFile(
            url,
            executable: executable,
            maximumBytes: maximumBytes
        )
        return PinnedFile(
            url: url,
            executable: executable,
            maximumBytes: maximumBytes,
            device: UInt64(truncatingIfNeeded: after.st_dev),
            inode: UInt64(after.st_ino),
            size: after.st_size,
            sha256: Self.sha256(bytes),
            bytes: bytes,
            descriptor: descriptor
        )
    }

    private func revalidate(_ pinned: PinnedComponents) throws {
        if pinned.components.requiresBundleIntegrity,
           !integrityVerifier() {
            throw CredentialMigrationError.componentsMissing
        }
        if pinned.components.enforceIdentity {
            try validateExpectedLayout(pinned.components)
        }
        try revalidate(pinned.files)
    }

    private func revalidate(_ files: [PinnedFile]) throws {
        for file in files {
            let path = file.url.path
            guard file.url.isFileURL,
                  path == file.url.standardizedFileURL.path,
                  path == file.url.resolvingSymlinksInPath().standardizedFileURL.path else {
                throw CredentialMigrationError.componentsMissing
            }
            let (bytes, after) = try Self.readTrustedDescriptor(
                file.descriptor,
                url: file.url,
                executable: file.executable,
                maximumBytes: file.maximumBytes
            )
            guard
                  UInt64(truncatingIfNeeded: after.st_dev) == file.device,
                  UInt64(after.st_ino) == file.inode,
                  after.st_size == file.size,
                  Self.sha256(bytes) == file.sha256 else {
                throw CredentialMigrationError.componentsMissing
            }
        }
    }

    private func makeYAMLExecutionGraph(for entry: URL) throws -> YAMLExecutionGraph {
        let root = entry.deletingLastPathComponent()
        guard entry.lastPathComponent == "index.js",
              Self.isCanonicalDirectory(root) else {
            throw CredentialMigrationError.componentsMissing
        }
        var relativeURLs: [(String, URL)] = []
        var visitedDirectories = 0

        func visit(_ directory: URL, relativeDirectory: String, depth: Int) throws {
            guard depth <= 16,
                  visitedDirectories < Self.maximumYAMLGraphFiles,
                  Self.isCanonicalDirectory(directory) else {
                throw CredentialMigrationError.componentsMissing
            }
            visitedDirectories += 1
            let names = try fileManager.contentsOfDirectory(atPath: directory.path).sorted()
            for name in names {
                guard !name.isEmpty,
                      name != ".",
                      name != "..",
                      !name.contains("/"),
                      !name.contains("\0") else {
                    throw CredentialMigrationError.componentsMissing
                }
                let url = directory.appendingPathComponent(name, isDirectory: false)
                let relative = relativeDirectory.isEmpty ? name : "\(relativeDirectory)/\(name)"
                var metadata = stat()
                guard Darwin.lstat(url.path, &metadata) == 0 else {
                    throw CredentialMigrationError.componentsMissing
                }
                switch metadata.st_mode & S_IFMT {
                case S_IFDIR:
                    try visit(url, relativeDirectory: relative, depth: depth + 1)
                case S_IFREG:
                    if url.pathExtension == "js" { relativeURLs.append((relative, url)) }
                default:
                    // A symlink or device anywhere in the executable module
                    // tree makes the graph ambiguous and is rejected, even if
                    // the current package version would not import it.
                    throw CredentialMigrationError.componentsMissing
                }
            }
        }

        try visit(root, relativeDirectory: "", depth: 0)
        guard relativeURLs.count > 0,
              relativeURLs.count <= Self.maximumYAMLGraphFiles,
              relativeURLs.contains(where: { $0.0 == "index.js" }) else {
            throw CredentialMigrationError.componentsMissing
        }

        var sourceFiles: [PinnedFile] = []
        var graph: [String: String] = [:]
        var totalBytes: Int64 = 0
        for (relative, url) in relativeURLs {
            let file = try pinFile(
                url,
                executable: false,
                maximumBytes: Self.maximumYAMLModuleBytes
            )
            guard file.size <= Self.maximumYAMLGraphBytes - totalBytes,
                  let source = String(data: file.bytes, encoding: .utf8),
                  graph.updateValue(source, forKey: relative) == nil else {
                throw CredentialMigrationError.componentsMissing
            }
            totalBytes += file.size
            sourceFiles.append(file)
        }
        guard totalBytes > 0,
              JSONSerialization.isValidJSONObject(graph),
              let encoded = try? CredentialMigrationXPCSchema.encode(graph) else {
            throw CredentialMigrationError.componentsMissing
        }
        let payload = encoded.base64EncodedString()
        guard encoded.count <= CredentialMigrationXPCConstants.maximumGraphBytes,
              payload.utf8.count <= 12 * 1_024 * 1_024 else {
            throw CredentialMigrationError.componentsMissing
        }
        return YAMLExecutionGraph(payload: payload, data: encoded, sourceFiles: sourceFiles)
    }

    private static func isCanonicalDirectory(_ url: URL) -> Bool {
        guard url.isFileURL,
              url.path == url.standardizedFileURL.path,
              url.path == url.resolvingSymlinksInPath().standardizedFileURL.path else {
            return false
        }
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { return false }
        defer { _ = Darwin.close(descriptor) }
        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFDIR
            && (metadata.st_uid == geteuid() || metadata.st_uid == 0)
            && metadata.st_mode & 0o022 == 0
            && CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor)
    }

    private static func isTrustedFile(_ info: stat, executable: Bool, maximumBytes: Int64) -> Bool {
        info.st_mode & S_IFMT == S_IFREG
            && (info.st_uid == geteuid() || info.st_uid == 0)
            && info.st_nlink == 1
            && info.st_mode & 0o022 == 0
            && (!executable || info.st_mode & S_IXUSR != 0)
            && info.st_size > 0
            && info.st_size <= maximumBytes
    }

    private static func openTrustedFile(
        _ url: URL,
        executable: Bool,
        maximumBytes: Int64
    ) throws -> (Int32, Data, stat) {
        guard maximumBytes > 0, maximumBytes <= Int64(Int.max) else {
            throw CredentialMigrationError.componentsMissing
        }
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw CredentialMigrationError.componentsMissing }
        do {
            let (bytes, metadata) = try readTrustedDescriptor(
                descriptor,
                url: url,
                executable: executable,
                maximumBytes: maximumBytes
            )
            return (descriptor, bytes, metadata)
        } catch {
            _ = Darwin.close(descriptor)
            throw error
        }
    }

    private static func readTrustedDescriptor(
        _ descriptor: Int32,
        url: URL,
        executable: Bool,
        maximumBytes: Int64
    ) throws -> (Data, stat) {
        let descriptorFlags = Darwin.fcntl(descriptor, F_GETFD)
        guard maximumBytes > 0,
              maximumBytes <= Int64(Int.max),
              descriptorFlags >= 0,
              descriptorFlags & FD_CLOEXEC != 0 else {
            throw CredentialMigrationError.componentsMissing
        }
        var before = stat()
        var beforePath = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              Darwin.lstat(url.path, &beforePath) == 0,
              isTrustedFile(before, executable: executable, maximumBytes: maximumBytes),
              isTrustedFile(beforePath, executable: executable, maximumBytes: maximumBytes),
              before.st_dev == beforePath.st_dev,
              before.st_ino == beforePath.st_ino,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw CredentialMigrationError.componentsMissing
        }
        let bytes = try CredentialMigrationFileSecurity.boundedRead(
            descriptor: descriptor,
            maximumBytes: Int(maximumBytes)
        )
        var after = stat()
        var afterPath = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Darwin.lstat(url.path, &afterPath) == 0,
              isTrustedFile(after, executable: executable, maximumBytes: maximumBytes),
              isTrustedFile(afterPath, executable: executable, maximumBytes: maximumBytes),
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              after.st_dev == afterPath.st_dev,
              after.st_ino == afterPath.st_ino,
              bytes.count == Int(after.st_size),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw CredentialMigrationError.componentsMissing
        }
        return (bytes, after)
    }

    private static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func mapServiceError(
        _ error: CredentialMigrationXPCClientError
    ) -> CredentialMigrationError {
        switch error {
        case .timedOut, .service(.timedOut):
            return .timedOut
        case .serviceIdentityMismatch, .service(.identityMismatch):
            return .serviceIdentityMismatch
        case .interrupted, .service(.interrupted):
            return .serviceInterrupted
        case .sourceChanged, .service(.invalidYAML), .service(.sourceChanged):
            return .sourceInvalid
        case .service(.recoveryRequired):
            return .recoveryRequired
        case .service(.keychainFailure):
            return .keychainFailure
        case .serviceMissing, .invalidCapabilities, .service(.invalidRequest):
            return .componentsMissing
        case .unavailable, .invalidResponse, .service(.busy),
             .service(.internalFailure), .service(.success):
            return .runnerUnavailable
        }
    }
}

enum CredentialMigrationOutputStream: Equatable, Sendable {
    case standardOutput
    case standardError
}

enum CredentialMigrationError: LocalizedError, Equatable, Sendable {
    case migrationInProgress
    case componentsMissing
    case runnerUnavailable
    case timedOut
    case outputLimitExceeded(CredentialMigrationOutputStream)
    case processFailed(exitStatus: Int32?, signal: Int32?, diagnosticBytes: Int)
    case invalidResult
    case serviceIdentityMismatch
    case serviceInterrupted
    case sourceInvalid
    case keychainFailure
    case recoveryRequired

    var errorDescription: String? {
        let prefix = "Credential migration could not be completely verified, so the agent runtime remains stopped."
        switch self {
        case .migrationInProgress:
            return "Credential migration is already running in another \(ProductBrand.displayName) process."
        case .componentsMissing:
            return "The secure credential migration components are missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .runnerUnavailable:
            return "\(prefix) The bounded migration process could not be started."
        case .timedOut:
            return "\(prefix) Migration exceeded its safety deadline and its private process group was stopped."
        case .outputLimitExceeded(let stream):
            let name = stream == .standardOutput ? "result" : "diagnostic"
            return "\(prefix) The migration \(name) exceeded its safety limit."
        case .processFailed:
            return prefix
        case .invalidResult:
            return "\(prefix) The migration returned an invalid bounded result."
        case .serviceIdentityMismatch:
            return "\(prefix) The private migration service did not match this exact signed Fulmar build."
        case .serviceInterrupted:
            return "\(prefix) The private migration service was interrupted."
        case .sourceInvalid:
            return "\(prefix) The legacy credential file is invalid or changed during migration."
        case .keychainFailure:
            return "\(prefix) Keychain could not commit and verify the complete migration."
        case .recoveryRequired:
            return "Credentials were secured, but the migration receipt could not be completely verified. Keep the legacy file in place and retry recovery before starting the agent runtime."
        }
    }
}
