import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol
import Testing
@testable import LocalHarness

private final class MigrationCompletionCount: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }

    var current: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class MigrationProcessProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedInvocations = 0

    func record() {
        lock.lock()
        storedInvocations += 1
        lock.unlock()
    }

    var invocations: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedInvocations
    }
}

private final class MigrationIntegrityMutationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var performed = false
    private let mutation: () -> Void

    init(mutation: @escaping () -> Void) { self.mutation = mutation }

    func verify() -> Bool {
        lock.lock()
        let shouldPerform = !performed
        performed = true
        lock.unlock()
        if shouldPerform { mutation() }
        return true
    }
}

private enum MigrationLeaseTestOutcome: Equatable, Sendable {
    case success(CredentialMigrationResult)
    case failure(CredentialMigrationError?)
}

private enum MigrationLeaseChildTermination: Equatable, Sendable, CustomStringConvertible {
    case exited(Int32)
    case signaled(Int32)

    var description: String {
        switch self {
        case .exited(let status): return "exit status \(status)"
        case .signaled(let signal): return "signal \(signal)"
        }
    }
}

private enum MigrationLeaseChildError: Error, Equatable, Sendable, CustomStringConvertible {
    case invalidConfiguration
    case spawnSetupFailed(Int32)
    case spawnFailed(Int32)
    case signalFailed(pid_t, Int32)
    case waitFailed(pid_t, Int32)
    case waitTimedOut(pid_t, TimeInterval)

    var description: String {
        switch self {
        case .invalidConfiguration:
            return "invalid child-process configuration"
        case .spawnSetupFailed(let error):
            return "posix_spawn setup failed with errno \(error)"
        case .spawnFailed(let error):
            return "posix_spawn failed with errno \(error)"
        case .signalFailed(let pid, let error):
            return "kill(\(pid)) failed with errno \(error)"
        case .waitFailed(let pid, let error):
            return "waitpid(\(pid)) failed with errno \(error)"
        case .waitTimedOut(let pid, let timeout):
            return "waitpid(\(pid)) did not complete within \(timeout) seconds"
        }
    }
}

/// A test-only exact-child owner which never depends on Foundation Process's
/// current-thread run-loop delivery. Swift Testing may resume an async test on
/// a different executor thread after an `await`; every reap therefore uses
/// exact-PID `waitpid(..., WNOHANG)` polling with a monotonic hard deadline.
private final class BoundedMigrationLeaseChild: @unchecked Sendable {
    let processIdentifier: pid_t

    private let stateLock = NSLock()
    private var storedTermination: MigrationLeaseChildTermination?

    private init(processIdentifier: pid_t) {
        self.processIdentifier = processIdentifier
    }

    static func spawn(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        diagnosticURL: URL
    ) throws -> BoundedMigrationLeaseChild {
        guard executable.isFileURL,
              executable.path.hasPrefix("/"),
              !executable.path.contains("\0"),
              diagnosticURL.isFileURL,
              diagnosticURL.path.hasPrefix("/"),
              !diagnosticURL.path.contains("\0"),
              arguments.count <= 32,
              arguments.allSatisfy({ !$0.contains("\0") && $0.utf8.count <= 4_096 }),
              environment.count <= 64,
              environment.allSatisfy({
                  !$0.key.isEmpty && !$0.key.contains("=") && !$0.key.contains("\0")
                      && !$0.value.contains("\0") && $0.key.utf8.count <= 4_096
                      && $0.value.utf8.count <= 64 * 1_024
              }) else {
            throw MigrationLeaseChildError.invalidConfiguration
        }

        var actions: posix_spawn_file_actions_t?
        let actionsStatus = posix_spawn_file_actions_init(&actions)
        guard actionsStatus == 0 else {
            throw MigrationLeaseChildError.spawnSetupFailed(actionsStatus)
        }
        defer { posix_spawn_file_actions_destroy(&actions) }

        var attributes: posix_spawnattr_t?
        let attributesStatus = posix_spawnattr_init(&attributes)
        guard attributesStatus == 0 else {
            throw MigrationLeaseChildError.spawnSetupFailed(attributesStatus)
        }
        defer { posix_spawnattr_destroy(&attributes) }

        let setupStatuses = [
            posix_spawn_file_actions_addopen(
                &actions,
                STDIN_FILENO,
                "/dev/null",
                O_RDONLY,
                0
            ),
            posix_spawn_file_actions_addopen(
                &actions,
                STDOUT_FILENO,
                "/dev/null",
                O_WRONLY,
                0
            ),
            posix_spawn_file_actions_addopen(
                &actions,
                STDERR_FILENO,
                diagnosticURL.path,
                O_WRONLY | O_CREAT | O_TRUNC,
                mode_t(S_IRUSR | S_IWUSR)
            ),
            posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)),
        ]
        if let failure = setupStatuses.first(where: { $0 != 0 }) {
            throw MigrationLeaseChildError.spawnSetupFailed(failure)
        }

        let argumentStrings = [executable.path] + arguments
        var argumentPointers = argumentStrings.map { strdup($0) }
        argumentPointers.append(nil)
        let environmentStrings = environment.keys.sorted().map {
            "\($0)=\(environment[$0]!)"
        }
        var environmentPointers = environmentStrings.map { strdup($0) }
        environmentPointers.append(nil)
        defer {
            for pointer in argumentPointers.compactMap({ $0 }) { free(pointer) }
            for pointer in environmentPointers.compactMap({ $0 }) { free(pointer) }
        }
        guard argumentPointers.dropLast().allSatisfy({ $0 != nil }),
              environmentPointers.dropLast().allSatisfy({ $0 != nil }) else {
            throw MigrationLeaseChildError.spawnFailed(ENOMEM)
        }

        var childPID: pid_t = 0
        let spawnStatus = argumentPointers.withUnsafeMutableBufferPointer { argv in
            environmentPointers.withUnsafeMutableBufferPointer { envp in
                posix_spawn(
                    &childPID,
                    executable.path,
                    &actions,
                    &attributes,
                    argv.baseAddress,
                    envp.baseAddress
                )
            }
        }
        guard spawnStatus == 0, childPID > 1 else {
            throw MigrationLeaseChildError.spawnFailed(spawnStatus)
        }
        return BoundedMigrationLeaseChild(processIdentifier: childPID)
    }

    func pollTermination() throws -> MigrationLeaseChildTermination? {
        stateLock.lock()
        defer { stateLock.unlock() }
        if let storedTermination { return storedTermination }

        var waitStatus: Int32 = 0
        while true {
            let waited = Darwin.waitpid(processIdentifier, &waitStatus, WNOHANG)
            if waited == processIdentifier {
                let signal = waitStatus & 0x7f
                let termination: MigrationLeaseChildTermination = signal == 0
                    ? .exited((waitStatus >> 8) & 0xff)
                    : .signaled(signal)
                storedTermination = termination
                return termination
            }
            if waited == 0 { return nil }
            let failure = errno
            if waited < 0, failure == EINTR { continue }
            throw MigrationLeaseChildError.waitFailed(processIdentifier, failure)
        }
    }

    func waitForTermination(
        timeout: TimeInterval
    ) throws -> MigrationLeaseChildTermination {
        guard timeout.isFinite, (0.05...10).contains(timeout) else {
            throw MigrationLeaseChildError.invalidConfiguration
        }
        let started = DispatchTime.now().uptimeNanoseconds
        let maximumNanoseconds = UInt64(timeout * 1_000_000_000)
        while true {
            if let termination = try pollTermination() { return termination }
            if DispatchTime.now().uptimeNanoseconds - started >= maximumNanoseconds {
                throw MigrationLeaseChildError.waitTimedOut(processIdentifier, timeout)
            }
            Darwin.usleep(5_000)
        }
    }

    func signalAndReap(
        _ signal: Int32,
        timeout: TimeInterval
    ) throws -> MigrationLeaseChildTermination {
        if let termination = try pollTermination() { return termination }
        errno = 0
        if Darwin.kill(processIdentifier, signal) != 0, errno != ESRCH {
            throw MigrationLeaseChildError.signalFailed(processIdentifier, errno)
        }
        return try waitForTermination(timeout: timeout)
    }
}

private final class MigrationLeaseCompletionProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedOutcome: MigrationLeaseTestOutcome?

    func record(_ result: Result<CredentialMigrationResult, Error>) {
        let outcome: MigrationLeaseTestOutcome
        switch result {
        case .success(let value): outcome = .success(value)
        case .failure(let error): outcome = .failure(error as? CredentialMigrationError)
        }
        lock.lock()
        storedOutcome = outcome
        lock.unlock()
    }

    var outcome: MigrationLeaseTestOutcome? {
        lock.lock()
        defer { lock.unlock() }
        return storedOutcome
    }
}

private final class MigrationLeaseRunnerGate: @unchecked Sendable {
    private let started = DispatchSemaphore(value: 0)
    private let released = DispatchSemaphore(value: 0)

    func enter() {
        started.signal()
        _ = released.wait(timeout: .now() + 5)
    }

    func waitUntilStarted() -> Bool {
        started.wait(timeout: .now() + 2) == .success
    }

    func release() { released.signal() }
}

private struct TrustedMigrationFixture: Sendable {
    let root: URL
    let resources: URL
    let executables: URL
    let node: URL
    let script: URL
    let helper: URL
    let yaml: URL
    let source: URL

    var components: CredentialMigrationComponents {
        CredentialMigrationComponents(
            node: node,
            script: script,
            helper: helper,
            yaml: yaml,
            service: executables.deletingLastPathComponent()
                .appendingPathComponent("XPCServices", isDirectory: true)
                .appendingPathComponent(
                    CredentialMigrationXPCConstants.serviceBundleName,
                    isDirectory: true
                ),
            enforceIdentity: true,
            requiredExecutableDirectory: executables,
            requiredResourceDirectory: resources,
            requiresBundleIntegrity: true
        )
    }
}

private func migrationTestRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("credential-migration-process-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return root
}

private func leaseTestComponents(in root: URL) -> CredentialMigrationComponents {
    CredentialMigrationComponents(
        node: URL(fileURLWithPath: "/bin/zsh"),
        script: root.appendingPathComponent("unused-migration-script"),
        helper: root.appendingPathComponent("unused-credential-helper"),
        yaml: root.appendingPathComponent("unused-yaml-module")
    )
}

private func successfulMigrationProcessResult(
    references: Int = 1,
    records: Int = 1
) -> CredentialMigrationProcessResult {
    CredentialMigrationProcessResult(
        exitStatus: 0,
        terminationSignal: nil,
        standardOutput: Data("{\"references\":\(references),\"records\":\(records)}".utf8),
        standardError: Data(),
        limit: nil
    )
}

private func createValidMigrationLease(at url: URL) throws {
    try Data().write(to: url, options: .withoutOverwriting)
    #expect(chmod(url.path, 0o600) == 0)
}

private func addMigrationTestExtendedACL(to url: URL, directory: Bool = false) throws {
    let result = try BoundedCredentialMigrationProcess.run(
        executable: URL(fileURLWithPath: "/bin/chmod"),
        arguments: [
            "+a",
            directory ? "everyone allow list,search" : "everyone allow read",
            url.path,
        ],
        environment: migrationTestEnvironment,
        maximumStandardOutputBytes: 4 * 1_024,
        maximumStandardErrorBytes: 4 * 1_024,
        deadline: 2,
        terminationGrace: 0.05
    )
    guard result.exitStatus == 0, result.terminationSignal == nil, result.limit == nil else {
        throw CredentialMigrationError.componentsMissing
    }
}

private func awaitMigrationLeaseOutcome(
    _ probe: MigrationLeaseCompletionProbe
) async -> MigrationLeaseTestOutcome? {
    for _ in 0..<250 {
        if let outcome = probe.outcome { return outcome }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return probe.outcome
}

private func migrationScript(_ source: String, in root: URL, name: String) throws -> URL {
    let script = root.appendingPathComponent(name, isDirectory: false)
    try Data(source.utf8).write(to: script, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
    return script
}

private func trustedMigrationFixture() throws -> TrustedMigrationFixture {
    let root = FileManager.default.temporaryDirectory.standardizedFileURL
        .appendingPathComponent("fulmar-credential-components-\(UUID().uuidString)", isDirectory: true)
    let resources = root.appendingPathComponent("Resources", isDirectory: true)
    let executables = root.appendingPathComponent("MacOS", isDirectory: true)
    let yamlDirectory = resources
        .appendingPathComponent("Runtime/dsh/node_modules/yaml/dist", isDirectory: true)
    try FileManager.default.createDirectory(at: yamlDirectory, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: executables, withIntermediateDirectories: false)
    for directory in [root, resources, yamlDirectory, executables] {
        #expect(chmod(directory.path, 0o700) == 0)
    }
    let node = resources.appendingPathComponent("Runtime/node")
    let script = resources.appendingPathComponent("MigrateCredentials.mjs")
    let helper = executables.appendingPathComponent("LocalHarnessCredentialHelper")
    let yaml = yamlDirectory.appendingPathComponent("index.js")
    let source = root.appendingPathComponent("credentials.yaml")
    try Data("trusted-node-v1".utf8).write(to: node)
    try Data("trusted-script-v1".utf8).write(to: script)
    try Data("trusted-helper-v1".utf8).write(to: helper)
    try Data("trusted-yaml-v1".utf8).write(to: yaml)
    try Data("PRIVATE_KEY: preserved".utf8).write(to: source)
    #expect(chmod(node.path, 0o700) == 0)
    #expect(chmod(helper.path, 0o700) == 0)
    #expect(chmod(script.path, 0o600) == 0)
    #expect(chmod(yaml.path, 0o600) == 0)
    #expect(chmod(source.path, 0o600) == 0)
    return TrustedMigrationFixture(
        root: root,
        resources: resources,
        executables: executables,
        node: node,
        script: script,
        helper: helper,
        yaml: yaml,
        source: source
    )
}

private func awaitMigration(
    _ manager: CredentialMigrationManager
) async -> Result<CredentialMigrationResult, Error> {
    await withCheckedContinuation { continuation in
        manager.migrate { continuation.resume(returning: $0) }
    }
}

private func migrationFailure(
    _ result: Result<CredentialMigrationResult, Error>
) -> CredentialMigrationError? {
    guard case .failure(let error) = result else { return nil }
    return error as? CredentialMigrationError
}

private let migrationTestEnvironment = [
    "HOME": "/private/tmp",
    "PATH": "/usr/bin:/bin",
    "LANG": "en_US.UTF-8"
]

@Suite(.serialized)
struct CredentialMigrationManagerTests {
    @Test func startupRequirementSeparatesAbsencePlaintextAndZeroTombstone() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let manager = CredentialMigrationManager(sourceURL: source)

        #expect(manager.startupRequirement == .none)
        #expect(!manager.requiresMigration)

        try Data("version: 1\ncredentials: []\n".utf8).write(
            to: source,
            options: .withoutOverwriting
        )
        #expect(manager.startupRequirement == .plaintextNeedsConsent)
        #expect(manager.requiresMigration)

        let descriptor = Darwin.open(source.path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        #expect(descriptor >= 0)
        guard descriptor >= 0 else { return }
        #expect(Darwin.ftruncate(descriptor, 0) == 0)
        #expect(Darwin.fsync(descriptor) == 0)
        #expect(Darwin.close(descriptor) == 0)

        #expect(manager.startupRequirement == .zeroTombstoneNeedsAutomaticVerification)
        #expect(manager.requiresMigration)
    }

    @Test func ambiguousSourceNeverMasqueradesAsConsentEligiblePlaintext() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target.yaml")
        try Data("version: 1\ncredentials: []\n".utf8).write(
            to: target,
            options: .withoutOverwriting
        )
        let source = root.appendingPathComponent("credentials.yaml")
        #expect(symlink(target.path, source.path) == 0)
        let manager = CredentialMigrationManager(sourceURL: source)

        #expect(manager.startupRequirement == .zeroTombstoneNeedsAutomaticVerification)
        #expect(manager.requiresMigration)
    }

    @Test func nonRegularSourceRequiresAutomaticVerificationRatherThanConsent() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false)
        let manager = CredentialMigrationManager(sourceURL: source)

        #expect(manager.startupRequirement == .zeroTombstoneNeedsAutomaticVerification)
        #expect(manager.requiresMigration)
    }

    @Test func exactChildWaitHasAHardDeadlineAndSIGKILLCleanupReapsIt() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let diagnostic = root.appendingPathComponent("bounded-child.stderr")
        let child = try BoundedMigrationLeaseChild.spawn(
            executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["30"],
            environment: migrationTestEnvironment,
            diagnosticURL: diagnostic
        )
        defer {
            do {
                _ = try child.signalAndReap(SIGKILL, timeout: 2)
            } catch {
                Issue.record(
                    "Could not clean up bounded wait fixture \(child.processIdentifier): \(error)"
                )
            }
        }

        let started = DispatchTime.now().uptimeNanoseconds
        do {
            _ = try child.waitForTermination(timeout: 0.05)
            Issue.record("A live exact child unexpectedly completed before the wait deadline")
        } catch let error as MigrationLeaseChildError {
            guard case .waitTimedOut(let pid, let timeout) = error else {
                Issue.record("Expected a typed bounded wait timeout, got \(error)")
                return
            }
            #expect(pid == child.processIdentifier)
            #expect(timeout == 0.05)
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds - started
        #expect(elapsed < 1_000_000_000)
        #expect(try child.signalAndReap(SIGKILL, timeout: 2) == .signaled(SIGKILL))
    }

    @Test func migrationLeaseIsFixedOwnerPrivateAndReleasedAfterEveryOutcome() async throws {
        enum FirstOutcome: CaseIterable, Sendable { case success, failure, timeout, runnerThrow }

        for outcome in FirstOutcome.allCases {
            let root = try migrationTestRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            let source = root.appendingPathComponent("credentials.yaml")
            let original = Data("PRIVATE_KEY: lease-release-canary".utf8)
            try original.write(to: source, options: .withoutOverwriting)
            let components = leaseTestComponents(in: root)
            let runnerProbe = MigrationProcessProbe()
            let first = CredentialMigrationManager(
                sourceURL: source,
                componentLocator: { components },
                processRunner: { _, _, environment, _, _, _, inheritedDescriptor in
                    runnerProbe.record()
                    var leaseMetadata = stat()
                    #expect(environment[CredentialMigrationManager.leaseEnvironmentMarkerName]
                        == CredentialMigrationManager.leaseEnvironmentMarkerValue)
                    #expect(CredentialMigrationManager.leaseEnvironmentMarkerValue
                        == String(CredentialMigrationInheritedDescriptor.fixedChildDescriptor))
                    #expect(inheritedDescriptor.childDescriptor
                        == CredentialMigrationInheritedDescriptor.fixedChildDescriptor)
                    #expect(fcntl(inheritedDescriptor.sourceDescriptor, F_GETFD) & FD_CLOEXEC != 0)
                    #expect(Darwin.fstat(inheritedDescriptor.sourceDescriptor, &leaseMetadata) == 0)
                    #expect(UInt64(truncatingIfNeeded: leaseMetadata.st_dev)
                        == inheritedDescriptor.expectedDevice)
                    #expect(UInt64(leaseMetadata.st_ino) == inheritedDescriptor.expectedInode)
                    #expect(flock(inheritedDescriptor.sourceDescriptor, LOCK_EX | LOCK_NB) == 0)
                    switch outcome {
                    case .success:
                        return successfulMigrationProcessResult(references: 2, records: 3)
                    case .failure:
                        return CredentialMigrationProcessResult(
                            exitStatus: 7,
                            terminationSignal: nil,
                            standardOutput: Data(),
                            standardError: Data("fail".utf8),
                            limit: nil
                        )
                    case .timeout:
                        return CredentialMigrationProcessResult(
                            exitStatus: nil,
                            terminationSignal: SIGKILL,
                            standardOutput: Data(),
                            standardError: Data(),
                            limit: .deadline(0.05)
                        )
                    case .runnerThrow:
                        throw CredentialMigrationError.invalidResult
                    }
                }
            )

            let firstResult = await awaitMigration(first)
            switch outcome {
            case .success:
                #expect(try firstResult.get() == CredentialMigrationResult(references: 2, records: 3))
            case .failure:
                #expect(migrationFailure(firstResult) == .processFailed(
                    exitStatus: 7,
                    signal: nil,
                    diagnosticBytes: 4
                ))
            case .timeout:
                #expect(migrationFailure(firstResult) == .timedOut)
            case .runnerThrow:
                #expect(migrationFailure(firstResult) == .runnerUnavailable)
            }

            let lease = try CredentialMigrationManager.credentialMigrationLeaseURL(for: source)
            #expect(lease.deletingLastPathComponent() == source.deletingLastPathComponent())
            #expect(lease.lastPathComponent == ".fulmar-credential-migration.lock")
            var metadata = stat()
            #expect(Darwin.lstat(lease.path, &metadata) == 0)
            #expect(metadata.st_mode & S_IFMT == S_IFREG)
            #expect(metadata.st_uid == geteuid())
            #expect(metadata.st_nlink == 1)
            #expect(metadata.st_mode & 0o777 == 0o600)
            #expect(metadata.st_size == 0)

            let follower = CredentialMigrationManager(
                sourceURL: source,
                componentLocator: { components },
                processRunner: { _, _, _, _, _, _, _ in
                    runnerProbe.record()
                    return successfulMigrationProcessResult(references: 4, records: 5)
                }
            )
            let followerResult = await awaitMigration(follower)
            #expect(try followerResult.get()
                == CredentialMigrationResult(references: 4, records: 5))
            #expect(runnerProbe.invocations == 2)
            #expect(try Data(contentsOf: source) == original)
        }
    }

    @Test func realSpawnFailureReleasesManagerLeaseForAVerifiedFollower() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let original = Data("PRIVATE_KEY: spawn-failure-canary".utf8)
        try original.write(to: source, options: .withoutOverwriting)
        let missingComponents = CredentialMigrationComponents(
            node: root.appendingPathComponent("missing-node"),
            script: root.appendingPathComponent("unused-script"),
            helper: root.appendingPathComponent("unused-helper"),
            yaml: root.appendingPathComponent("unused-yaml")
        )
        let failed = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: { missingComponents },
            deadline: 1
        )

        let failedResult = await awaitMigration(failed)
        #expect(migrationFailure(failedResult) == .runnerUnavailable)
        #expect(try Data(contentsOf: source) == original)

        let followerProbe = MigrationProcessProbe()
        let follower = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: { leaseTestComponents(in: root) },
            processRunner: { _, _, _, _, _, _, inheritedDescriptor in
                followerProbe.record()
                #expect(fcntl(inheritedDescriptor.sourceDescriptor, F_GETFD) & FD_CLOEXEC != 0)
                return successfulMigrationProcessResult(references: 12, records: 13)
            }
        )
        let recovered = await awaitMigration(follower)
        #expect(try recovered.get()
            == CredentialMigrationResult(references: 12, records: 13))
        #expect(followerProbe.invocations == 1)
    }

    @Test func sameProcessContenderFailsTypedBeforeLocatingComponentsOrRunning() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let original = Data("PRIVATE_KEY: same-process-canary".utf8)
        try original.write(to: source, options: .withoutOverwriting)
        let components = leaseTestComponents(in: root)
        let gate = MigrationLeaseRunnerGate()
        let firstRunner = MigrationProcessProbe()
        let firstCompletion = MigrationLeaseCompletionProbe()
        let first = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: { components },
            processRunner: { _, _, _, _, _, _, _ in
                firstRunner.record()
                gate.enter()
                return successfulMigrationProcessResult(references: 6, records: 7)
            }
        )
        first.migrate { firstCompletion.record($0) }
        guard gate.waitUntilStarted() else {
            gate.release()
            Issue.record("The first manager never entered its leased runner")
            return
        }
        defer { gate.release() }

        let secondLocator = MigrationProcessProbe()
        let secondRunner = MigrationProcessProbe()
        let second = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: {
                secondLocator.record()
                return components
            },
            processRunner: { _, _, _, _, _, _, _ in
                secondRunner.record()
                return successfulMigrationProcessResult()
            }
        )
        let started = Date()
        let secondResult = await awaitMigration(second)
        #expect(Date().timeIntervalSince(started) < 2)
        #expect(migrationFailure(secondResult) == .migrationInProgress)
        #expect(secondLocator.invocations == 0)
        #expect(secondRunner.invocations == 0)
        #expect(try Data(contentsOf: source) == original)

        gate.release()
        let firstOutcome = await awaitMigrationLeaseOutcome(firstCompletion)
        #expect(firstOutcome
            == .success(CredentialMigrationResult(references: 6, records: 7)))
        #expect(firstRunner.invocations == 1)
    }

    @Test func poisonedLeaseNodesFailBeforeComponentLocation() async throws {
        enum Poison: CaseIterable, Equatable {
            case symlink, hardlink, wrongMode, nonempty, extendedACL
        }

        for poison in Poison.allCases {
            let root = try migrationTestRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            let source = root.appendingPathComponent("credentials.yaml")
            let original = Data("PRIVATE_KEY: poison-canary".utf8)
            try original.write(to: source, options: .withoutOverwriting)
            let lease = try CredentialMigrationManager.credentialMigrationLeaseURL(for: source)
            let outside = root.appendingPathComponent("outside-lock-canary")
            switch poison {
            case .symlink:
                try Data("OUTSIDE_LOCK_CANARY".utf8).write(to: outside)
                #expect(chmod(outside.path, 0o600) == 0)
                try FileManager.default.createSymbolicLink(at: lease, withDestinationURL: outside)
            case .hardlink:
                try createValidMigrationLease(at: outside)
                try FileManager.default.linkItem(at: outside, to: lease)
            case .wrongMode:
                try Data().write(to: lease, options: .withoutOverwriting)
                #expect(chmod(lease.path, 0o644) == 0)
            case .nonempty:
                try Data("poison".utf8).write(to: lease, options: .withoutOverwriting)
                #expect(chmod(lease.path, 0o600) == 0)
            case .extendedACL:
                try createValidMigrationLease(at: lease)
                try addMigrationTestExtendedACL(to: lease)
            }

            let locatorProbe = MigrationProcessProbe()
            let runnerProbe = MigrationProcessProbe()
            let components = leaseTestComponents(in: root)
            let manager = CredentialMigrationManager(
                sourceURL: source,
                componentLocator: {
                    locatorProbe.record()
                    return components
                },
                processRunner: { _, _, _, _, _, _, _ in
                    runnerProbe.record()
                    return successfulMigrationProcessResult()
                }
            )
            let poisonedResult = await awaitMigration(manager)
            #expect(migrationFailure(poisonedResult) == .componentsMissing)
            #expect(locatorProbe.invocations == 0)
            #expect(runnerProbe.invocations == 0)
            #expect(try Data(contentsOf: source) == original)
            if poison == .symlink {
                #expect(try String(contentsOf: outside, encoding: .utf8) == "OUTSIDE_LOCK_CANARY")
            }

            // Repairing the node does not inherit a stale in-process
            // reservation. The persistent path is admitted only after a fresh
            // metadata proof and successful kernel lock.
            try FileManager.default.removeItem(at: lease)
            try createValidMigrationLease(at: lease)
            let repairedResult = await awaitMigration(manager)
            #expect(try repairedResult.get()
                == CredentialMigrationResult(references: 1, records: 1))
            #expect(locatorProbe.invocations == 1)
            #expect(runnerProbe.invocations == 1)
        }
    }

    @Test func postRunLeaseABAFailsClosedBeforeAReplacementCanBeReused() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let original = Data("PRIVATE_KEY: aba-canary".utf8)
        try original.write(to: source, options: .withoutOverwriting)
        let lease = try CredentialMigrationManager.credentialMigrationLeaseURL(for: source)
        let components = leaseTestComponents(in: root)
        let runnerProbe = MigrationProcessProbe()
        let manager = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: { components },
            processRunner: { _, _, _, _, _, _, _ in
                runnerProbe.record()
                if runnerProbe.invocations == 1 {
                    try FileManager.default.removeItem(at: lease)
                    try Data().write(to: lease, options: .withoutOverwriting)
                    #expect(chmod(lease.path, 0o600) == 0)
                }
                return successfulMigrationProcessResult(references: 8, records: 9)
            }
        )

        let replacedResult = await awaitMigration(manager)
        #expect(migrationFailure(replacedResult) == .componentsMissing)
        #expect(runnerProbe.invocations == 1)
        #expect(try Data(contentsOf: source) == original)

        // The replacement path is not trusted merely because it is present.
        // A later attempt must reopen it, prove all metadata, acquire flock,
        // and pin its new device/inode before invoking the runner.
        let retriedResult = await awaitMigration(manager)
        #expect(try retriedResult.get()
            == CredentialMigrationResult(references: 8, records: 9))
        #expect(runnerProbe.invocations == 2)
    }

    @Test func missingSourceAfterLeaseAcquisitionIsANoOpWithoutComponentsOrRunner() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let locatorProbe = MigrationProcessProbe()
        let runnerProbe = MigrationProcessProbe()
        let components = leaseTestComponents(in: root)
        let manager = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: {
                locatorProbe.record()
                return components
            },
            processRunner: { _, _, _, _, _, _, _ in
                runnerProbe.record()
                return successfulMigrationProcessResult()
            }
        )

        let result = await awaitMigration(manager)
        #expect(try result.get()
            == CredentialMigrationResult(references: 0, records: 0))
        #expect(locatorProbe.invocations == 0)
        #expect(runnerProbe.invocations == 0)
        #expect(!FileManager.default.fileExists(atPath: source.path))
    }

    @Test func realChildFlockBlocksMigrationAndSIGKILLReleasesTheLease() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let original = Data("PRIVATE_KEY: child-lock-canary".utf8)
        try original.write(to: source, options: .withoutOverwriting)
        let lease = try CredentialMigrationManager.credentialMigrationLeaseURL(for: source)
        try createValidMigrationLease(at: lease)
        let ready = root.appendingPathComponent("child-lock.ready")
        let diagnostic = root.appendingPathComponent("child-lock.stderr")
        let child = try BoundedMigrationLeaseChild.spawn(
            executable: URL(fileURLWithPath: "/usr/bin/perl"),
            arguments: [
                "-e",
                #"""
            use strict;
            use warnings;
            use Fcntl qw(:flock O_RDWR);
            my ($lock, $ready) = @ARGV;
            sysopen(my $lock_handle, $lock, O_RDWR) or die "lock open failed: $!";
            flock($lock_handle, LOCK_EX | LOCK_NB) or die "flock failed: $!";
            open(my $ready_handle, '>', $ready) or die "ready failed: $!";
            print $ready_handle "ready\n";
            close($ready_handle);
            while (1) { sleep 1; }
            """#,
                lease.path,
                ready.path,
            ],
            environment: migrationTestEnvironment,
            diagnosticURL: diagnostic
        )
        defer {
            do {
                _ = try child.signalAndReap(SIGKILL, timeout: 2)
            } catch {
                Issue.record(
                    "Could not clean up exact lease-holder child \(child.processIdentifier): \(error)"
                )
            }
        }
        for _ in 0..<200 where !FileManager.default.fileExists(atPath: ready.path) {
            if try child.pollTermination() != nil { break }
            Darwin.usleep(10_000)
        }
        guard FileManager.default.fileExists(atPath: ready.path) else {
            let termination = try child.signalAndReap(SIGKILL, timeout: 2)
            let diagnosticText = (try? String(contentsOf: diagnostic, encoding: .utf8)) ?? ""
            Issue.record(
                "The real lease-holder child did not become ready; \(termination): \(diagnosticText)"
            )
            return
        }

        let locatorProbe = MigrationProcessProbe()
        let runnerProbe = MigrationProcessProbe()
        let components = leaseTestComponents(in: root)
        let manager = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: {
                locatorProbe.record()
                return components
            },
            processRunner: { _, _, _, _, _, _, _ in
                runnerProbe.record()
                return successfulMigrationProcessResult(references: 10, records: 11)
            }
        )
        let started = Date()
        let contended = await awaitMigration(manager)
        #expect(Date().timeIntervalSince(started) < 2)
        #expect(migrationFailure(contended) == .migrationInProgress)
        #expect(locatorProbe.invocations == 0)
        #expect(runnerProbe.invocations == 0)
        #expect(try Data(contentsOf: source) == original)

        let childTermination = try child.signalAndReap(SIGKILL, timeout: 2)
        #expect(childTermination == .signaled(SIGKILL))

        let recovered = await awaitMigration(manager)
        #expect(try recovered.get()
            == CredentialMigrationResult(references: 10, records: 11))
        #expect(locatorProbe.invocations == 1)
        #expect(runnerProbe.invocations == 1)
    }

    @Test func unsafeComponentPathSymlinkModeEmptyAndOversizedFileExecuteNothingAndPreserveSource() async throws {
        enum FixtureKind: CaseIterable {
            case wrongPath, symlink, unsafeMode, empty, oversized, extendedACL
        }

        for kind in FixtureKind.allCases {
            let fixture = try trustedMigrationFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let node = fixture.node
            var script = fixture.script
            let helper = fixture.helper
            let yaml = fixture.yaml
            switch kind {
            case .wrongPath:
                let outside = fixture.root.appendingPathComponent("outside-script")
                try Data("outside".utf8).write(to: outside)
                #expect(chmod(outside.path, 0o600) == 0)
                script = outside
            case .symlink:
                let target = fixture.root.appendingPathComponent("node-target")
                try FileManager.default.moveItem(at: node, to: target)
                try FileManager.default.createSymbolicLink(at: node, withDestinationURL: target)
            case .unsafeMode:
                #expect(chmod(node.path, 0o722) == 0)
            case .empty:
                try Data().write(to: yaml)
                #expect(chmod(yaml.path, 0o600) == 0)
            case .oversized:
                let handle = try FileHandle(forWritingTo: yaml)
                try handle.truncate(atOffset: UInt64(8 * 1_024 * 1_024 + 1))
                try handle.close()
            case .extendedACL:
                try addMigrationTestExtendedACL(to: node)
            }
            let components = CredentialMigrationComponents(
                node: node,
                script: script,
                helper: helper,
                yaml: yaml,
                enforceIdentity: true,
                requiredExecutableDirectory: fixture.executables,
                requiredResourceDirectory: fixture.resources,
                requiresBundleIntegrity: true
            )
            let processProbe = MigrationProcessProbe()
            let source = try Data(contentsOf: fixture.source)
            let manager = CredentialMigrationManager(
                sourceURL: fixture.source,
                componentLocator: { components },
                integrityVerifier: { true },
                processRunner: { _, _, _, _, _, _, _ in
                    processProbe.record()
                    return CredentialMigrationProcessResult(
                        exitStatus: 0,
                        terminationSignal: nil,
                        standardOutput: Data(#"{"references":1,"records":0}"#.utf8),
                        standardError: Data(),
                        limit: nil
                    )
                }
            )

            let result = await awaitMigration(manager)
            #expect(migrationFailure(result) == .componentsMissing)
            #expect(processProbe.invocations == 0)
            #expect(try Data(contentsOf: fixture.source) == source)
        }
    }

    @Test func sourceAndParentExtendedACLsFailBeforeComponentsOrRunner() async throws {
        enum Poison: CaseIterable { case source, parent }
        for poison in Poison.allCases {
            let root = try migrationTestRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            let source = root.appendingPathComponent("credentials.yaml")
            try Data("PRIVATE_KEY: acl-canary".utf8).write(
                to: source,
                options: .withoutOverwriting
            )
            #expect(chmod(source.path, 0o600) == 0)
            switch poison {
            case .source:
                try addMigrationTestExtendedACL(to: source)
            case .parent:
                try addMigrationTestExtendedACL(to: root, directory: true)
            }
            let locator = MigrationProcessProbe()
            let runner = MigrationProcessProbe()
            let manager = CredentialMigrationManager(
                sourceURL: source,
                componentLocator: {
                    locator.record()
                    return leaseTestComponents(in: root)
                },
                processRunner: { _, _, _, _, _, _, _ in
                    runner.record()
                    return successfulMigrationProcessResult()
                }
            )

            let result = await awaitMigration(manager)
            #expect(migrationFailure(result) == .componentsMissing)
            #expect(locator.invocations == 0)
            #expect(runner.invocations == 0)
            #expect(try Data(contentsOf: source) == Data("PRIVATE_KEY: acl-canary".utf8))
        }
    }

    @Test func failedBundleVerificationExecutesNothingAndPreservesSource() async throws {
        let fixture = try trustedMigrationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let processProbe = MigrationProcessProbe()
        let source = try Data(contentsOf: fixture.source)
        let manager = CredentialMigrationManager(
            sourceURL: fixture.source,
            componentLocator: { fixture.components },
            integrityVerifier: { false },
            processRunner: { _, _, _, _, _, _, _ in
                processProbe.record()
                return CredentialMigrationProcessResult(
                    exitStatus: 0, terminationSignal: nil,
                    standardOutput: Data(#"{"references":1,"records":0}"#.utf8),
                    standardError: Data(), limit: nil
                )
            }
        )

        let result = await awaitMigration(manager)
        #expect(migrationFailure(result) == .componentsMissing)
        #expect(processProbe.invocations == 0)
        #expect(try Data(contentsOf: fixture.source) == source)
    }

    @Test func preRunInodeAndSameInodeContentReplacementExecuteNothingAndPreserveSource() async throws {
        enum ReplacementKind: CaseIterable { case inode, content }

        for kind in ReplacementKind.allCases {
            let fixture = try trustedMigrationFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let source = try Data(contentsOf: fixture.source)
            let mutation = MigrationIntegrityMutationProbe {
                switch kind {
                case .inode:
                    try? FileManager.default.removeItem(at: fixture.script)
                    try? Data("replacement-script".utf8).write(to: fixture.script)
                    _ = chmod(fixture.script.path, 0o600)
                case .content:
                    guard let handle = try? FileHandle(forWritingTo: fixture.script) else { return }
                    try? handle.truncate(atOffset: 0)
                    try? handle.write(contentsOf: Data("same-inode-tamper".utf8))
                    try? handle.synchronize()
                    try? handle.close()
                }
            }
            let processProbe = MigrationProcessProbe()
            let manager = CredentialMigrationManager(
                sourceURL: fixture.source,
                componentLocator: { fixture.components },
                integrityVerifier: { mutation.verify() },
                processRunner: { _, _, _, _, _, _, _ in
                    processProbe.record()
                    return CredentialMigrationProcessResult(
                        exitStatus: 0, terminationSignal: nil,
                        standardOutput: Data(#"{"references":1,"records":0}"#.utf8),
                        standardError: Data(), limit: nil
                    )
                }
            )

            let result = await awaitMigration(manager)
            #expect(migrationFailure(result) == .componentsMissing)
            #expect(processProbe.invocations == 0)
            #expect(try Data(contentsOf: fixture.source) == source)
        }
    }

    @Test func postRunComponentReplacementRejectsTheResultAndPreservesSource() async throws {
        let fixture = try trustedMigrationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let processProbe = MigrationProcessProbe()
        let source = try Data(contentsOf: fixture.source)
        let manager = CredentialMigrationManager(
            sourceURL: fixture.source,
            componentLocator: { fixture.components },
            integrityVerifier: { true },
            processRunner: { _, _, _, _, _, _, _ in
                processProbe.record()
                try FileManager.default.removeItem(at: fixture.helper)
                try Data("post-run-replacement".utf8).write(to: fixture.helper)
                #expect(chmod(fixture.helper.path, 0o700) == 0)
                return CredentialMigrationProcessResult(
                    exitStatus: 0, terminationSignal: nil,
                    standardOutput: Data(#"{"references":1,"records":0}"#.utf8),
                    standardError: Data(), limit: nil
                )
            }
        )

        let result = await awaitMigration(manager)
        #expect(migrationFailure(result) == .componentsMissing)
        #expect(processProbe.invocations == 1)
        #expect(try Data(contentsOf: fixture.source) == source)
    }

    @Test func atomicScriptAndYAMLPathSwapsCannotChangeTheAdmittedProgramBytes() async throws {
        let fixture = try trustedMigrationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let trustedScript = try Data(contentsOf: fixture.script)
        let trustedYAML = try Data(contentsOf: fixture.yaml)
        let manager = CredentialMigrationManager(
            sourceURL: fixture.source,
            componentLocator: { fixture.components },
            integrityVerifier: { true },
            processRunner: { executable, arguments, environment, _, _, _, _ in
                #expect(executable == fixture.node)
                #expect(arguments.count == 6)
                #expect(Array(arguments.prefix(3)) == [
                    "--input-type=module",
                    "--eval",
                    CredentialMigrationManager.programBootstrap,
                ])
                #expect(arguments[3] == fixture.source.path)
                #expect(arguments[4] == fixture.helper.path)
                #expect(arguments[5] == "descriptor-bound-yaml-graph")

                let scriptBackup = fixture.script.appendingPathExtension("trusted-backup")
                let yamlBackup = fixture.yaml.appendingPathExtension("trusted-backup")
                try FileManager.default.moveItem(at: fixture.script, to: scriptBackup)
                try Data("malicious-script-path".utf8).write(to: fixture.script)
                #expect(chmod(fixture.script.path, 0o600) == 0)
                try FileManager.default.moveItem(at: fixture.yaml, to: yamlBackup)
                try Data("malicious-yaml-path".utf8).write(to: fixture.yaml)
                #expect(chmod(fixture.yaml.path, 0o600) == 0)

                let admittedScript = environment[
                    CredentialMigrationManager.programEnvironmentPayloadName
                ].flatMap { Data(base64Encoded: $0) }
                let graph = environment[
                    CredentialMigrationManager.yamlGraphEnvironmentPayloadName
                ]
                    .flatMap { Data(base64Encoded: $0) }
                    .flatMap { try? JSONDecoder().decode([String: String].self, from: $0) }
                #expect(environment[CredentialMigrationManager.programEnvironmentMarkerName]
                    == CredentialMigrationManager.programEnvironmentMarkerValue)
                #expect(environment[CredentialMigrationManager.yamlGraphEnvironmentMarkerName]
                    == CredentialMigrationManager.yamlGraphEnvironmentMarkerValue)
                #expect(admittedScript == trustedScript)
                #expect(graph?["index.js"] == String(decoding: trustedYAML, as: UTF8.self))
                #expect(try Data(contentsOf: fixture.script)
                    == Data("malicious-script-path".utf8))
                #expect(try Data(contentsOf: fixture.yaml)
                    == Data("malicious-yaml-path".utf8))

                try FileManager.default.removeItem(at: fixture.script)
                try FileManager.default.moveItem(at: scriptBackup, to: fixture.script)
                try FileManager.default.removeItem(at: fixture.yaml)
                try FileManager.default.moveItem(at: yamlBackup, to: fixture.yaml)
                return successfulMigrationProcessResult(references: 2, records: 3)
            }
        )

        let result = await awaitMigration(manager)
        #expect(try result.get() == CredentialMigrationResult(references: 2, records: 3))
        #expect(try Data(contentsOf: fixture.script) == trustedScript)
        #expect(try Data(contentsOf: fixture.yaml) == trustedYAML)
    }

    @Test func fixedNoisyOutputAndDiagnosticStreamsAreCappedWithoutPipeDeadlock() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let cases: [(String, CredentialMigrationProcessLimit)] = [
            ("while true; do printf '0123456789abcdef'; done", .standardOutputBytes(1_024)),
            ("while true; do printf '0123456789abcdef' >&2; done", .standardErrorBytes(1_024))
        ]
        for (body, expected) in cases {
            let script = try migrationScript("#!/bin/zsh\n\(body)\n", in: root, name: "noisy-\(UUID().uuidString).zsh")
            let started = Date()
            let result = try BoundedCredentialMigrationProcess.run(
                executable: URL(fileURLWithPath: "/bin/zsh"),
                arguments: [script.path],
                environment: migrationTestEnvironment,
                maximumStandardOutputBytes: 1_024,
                maximumStandardErrorBytes: 1_024,
                deadline: 2,
                terminationGrace: 0.05
            )
            #expect(result.limit == expected)
            #expect(result.standardOutput.count <= 1_024)
            #expect(result.standardError.count <= 1_024)
            #expect(Date().timeIntervalSince(started) < 2)
        }
    }

    @Test func termResistantContinuouslyReadableWriterCannotStarveForcedStop() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        for stream in ["", " >&2"] {
            let script = try migrationScript(
                "#!/bin/zsh\ntrap '' TERM\nwhile true; do printf '0123456789abcdef'\(stream); done\n",
                in: root,
                name: "term-resistant-\(UUID().uuidString).zsh"
            )
            let started = Date()
            let result = try BoundedCredentialMigrationProcess.run(
                executable: URL(fileURLWithPath: "/bin/zsh"),
                arguments: [script.path],
                environment: migrationTestEnvironment,
                maximumStandardOutputBytes: 1_024,
                maximumStandardErrorBytes: 1_024,
                deadline: 2,
                terminationGrace: 0.05
            )
            #expect(result.limit == (stream.isEmpty
                ? .standardOutputBytes(1_024)
                : .standardErrorBytes(1_024)))
            #expect(Date().timeIntervalSince(started) < 2)
        }
    }

    @Test func deadlineTerminatesTheExactSpawnedProcessGroupIncludingItsChild() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let childPIDFile = root.appendingPathComponent("child.pid")
        let script = try migrationScript(
            "#!/bin/zsh\n/bin/sleep 30 &\nprint -r -- $! > $1\nwait\n",
            in: root,
            name: "hung.zsh"
        )
        var spawnedPID: pid_t = 0
        let started = Date()
        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/zsh"),
            arguments: [script.path, childPIDFile.path],
            environment: migrationTestEnvironment,
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 0.15,
            terminationGrace: 0.05,
            onSpawn: { spawnedPID = $0 }
        )
        #expect(result.limit == .deadline(0.15))
        #expect(Date().timeIntervalSince(started) < 2)
        #expect(spawnedPID > 0)
        #expect(Darwin.kill(-spawnedPID, 0) == -1)
        #expect(errno == ESRCH)
        let childPID = Int32(String(decoding: try Data(contentsOf: childPIDFile), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines))
        if let childPID {
            for _ in 0..<100 where Darwin.kill(childPID, 0) == 0 { usleep(5_000) }
            #expect(Darwin.kill(childPID, 0) == -1)
            #expect(errno == ESRCH)
        } else {
            Issue.record("Hung fixture did not publish its child PID")
        }
    }

    @Test func escapedDescendantHoldingBothPipesCannotDefeatTheDeadline() throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let escapedPIDFile = root.appendingPathComponent("escaped.pid")
        var escapedPID: pid_t = 0
        defer {
            if escapedPID <= 1,
               let contents = try? String(contentsOf: escapedPIDFile, encoding: .utf8) {
                escapedPID = pid_t(contents.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            }
            if escapedPID > 1 { _ = Darwin.kill(escapedPID, SIGKILL) }
            if escapedPID > 1 {
                for _ in 0..<200 where Darwin.kill(escapedPID, 0) == 0 { usleep(5_000) }
            }
        }

        let program = #"""
        use POSIX qw(setsid);
        my $pid = fork();
        die "fork failed" unless defined $pid;
        if ($pid == 0) {
            setsid() or die "setsid failed";
            open(my $pid_file, '>', $ARGV[0]) or die "pid file failed";
            print $pid_file "$$\n";
            close($pid_file);
            $SIG{TERM} = 'IGNORE';
            $SIG{PIPE} = 'IGNORE';
            alarm 5;
            while (1) {
                print STDOUT 'escaped-output';
                print STDERR 'escaped-error';
            }
        }
        exit 0;
        """#
        let started = Date()
        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/usr/bin/perl"),
            arguments: ["-MPOSIX", "-e", program, escapedPIDFile.path],
            environment: migrationTestEnvironment,
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 1,
            terminationGrace: 0.05
        )
        let duration = Date().timeIntervalSince(started)
        if let contents = try? String(contentsOf: escapedPIDFile, encoding: .utf8) {
            escapedPID = pid_t(contents.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        }

        #expect(duration < 2)
        #expect(result.exitStatus == 0)
        #expect(result.limit == .standardOutputBytes(1_024)
            || result.limit == .standardErrorBytes(1_024))
        #expect(result.standardOutput.count <= 1_024)
        #expect(result.standardError.count <= 1_024)
        #expect(escapedPID > 1)
    }

    @Test func managerMapsBoundedFailurePreservesSourceAndCompletesExactlyOnce() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        let original = Data("PRIVATE_KEY: still-preserved".utf8)
        try original.write(to: source, options: .withoutOverwriting)
        let script = try migrationScript(
            "#!/bin/zsh\nwhile true; do printf '0123456789abcdef'; done\n",
            in: root,
            name: "manager-noisy.zsh"
        )
        let components = CredentialMigrationComponents(
            node: URL(fileURLWithPath: "/bin/zsh"),
            script: script,
            helper: root.appendingPathComponent("unused-helper"),
            yaml: root.appendingPathComponent("unused-yaml")
        )
        let manager = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: { components },
            deadline: 2
        )
        let count = MigrationCompletionCount()
        let failure: CredentialMigrationError = await withCheckedContinuation { continuation in
            manager.migrate { result in
                let invocation = count.increment()
                guard invocation == 1 else {
                    Issue.record("Migration completion was delivered more than once")
                    return
                }
                switch result {
                case .success:
                    Issue.record("Noisy migration unexpectedly succeeded")
                    continuation.resume(returning: .invalidResult)
                case .failure(let error):
                    continuation.resume(returning: (error as? CredentialMigrationError) ?? .runnerUnavailable)
                }
            }
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(failure == .outputLimitExceeded(.standardOutput))
        #expect(count.current == 1)
        #expect(try Data(contentsOf: source) == original)
    }

    @Test func managerAcceptsOnlyOneSmallTypedResult() async throws {
        let root = try migrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("credentials.yaml")
        try Data("source".utf8).write(to: source, options: .withoutOverwriting)
        let script = try migrationScript(
            "#!/bin/zsh\nprintf '{\"references\":2,\"records\":3}'\n",
            in: root,
            name: "manager-success.zsh"
        )
        let components = CredentialMigrationComponents(
            node: URL(fileURLWithPath: "/bin/zsh"),
            script: script,
            helper: root.appendingPathComponent("unused-helper"),
            yaml: root.appendingPathComponent("unused-yaml")
        )
        let manager = CredentialMigrationManager(
            sourceURL: source,
            componentLocator: { components },
            deadline: 2
        )
        let result: Result<CredentialMigrationResult, Error> = await withCheckedContinuation { continuation in
            manager.migrate { continuation.resume(returning: $0) }
        }
        #expect(try result.get() == CredentialMigrationResult(references: 2, records: 3))
    }
}
