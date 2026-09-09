import Darwin
import Foundation

public enum CredentialMigrationProcessLimit: Equatable, Sendable {
    case standardInputBytes(Int)
    case standardOutputBytes(Int)
    case standardErrorBytes(Int)
    case deadline(TimeInterval)
}

public struct CredentialMigrationProcessResult: Equatable, Sendable {
    public let exitStatus: Int32?
    public let terminationSignal: Int32?
    public let standardOutput: Data
    public let standardError: Data
    public let limit: CredentialMigrationProcessLimit?

    public init(
        exitStatus: Int32?,
        terminationSignal: Int32?,
        standardOutput: Data,
        standardError: Data,
        limit: CredentialMigrationProcessLimit?
    ) {
        self.exitStatus = exitStatus
        self.terminationSignal = terminationSignal
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.limit = limit
    }
}

public enum CredentialMigrationProcessRunnerError: Error, Equatable, Sendable {
    case invalidConfiguration
    case pipeFailed(Int32)
    case spawnFailed(Int32)
    case waitFailed(Int32)
}

public struct CredentialMigrationSpawnInitialization: @unchecked Sendable {
    let initializeFileActions: (UnsafeMutablePointer<posix_spawn_file_actions_t?>) -> Int32
    let destroyFileActions: (UnsafeMutablePointer<posix_spawn_file_actions_t?>) -> Void
    let initializeAttributes: (UnsafeMutablePointer<posix_spawnattr_t?>) -> Int32
    let destroyAttributes: (UnsafeMutablePointer<posix_spawnattr_t?>) -> Void

    public init(
        initializeFileActions: @escaping (
            UnsafeMutablePointer<posix_spawn_file_actions_t?>
        ) -> Int32,
        destroyFileActions: @escaping (
            UnsafeMutablePointer<posix_spawn_file_actions_t?>
        ) -> Void,
        initializeAttributes: @escaping (
            UnsafeMutablePointer<posix_spawnattr_t?>
        ) -> Int32,
        destroyAttributes: @escaping (
            UnsafeMutablePointer<posix_spawnattr_t?>
        ) -> Void
    ) {
        self.initializeFileActions = initializeFileActions
        self.destroyFileActions = destroyFileActions
        self.initializeAttributes = initializeAttributes
        self.destroyAttributes = destroyAttributes
    }

    public static let production = CredentialMigrationSpawnInitialization(
        initializeFileActions: { posix_spawn_file_actions_init($0) },
        destroyFileActions: { posix_spawn_file_actions_destroy($0) },
        initializeAttributes: { posix_spawnattr_init($0) },
        destroyAttributes: { posix_spawnattr_destroy($0) }
    )
}

/// Exact descriptor inheritance contract for the first-start migration lock.
/// The source remains CLOEXEC in the app. The runner makes one CLOEXEC
/// temporary duplicate after allocating its pipes, and posix_spawn maps only
/// that temporary onto the reviewed high descriptor in the exact migration
/// child. This avoids any process-wide flag change, source/target collision,
/// or race with unrelated child launches.
public struct CredentialMigrationInheritedDescriptor: Equatable, Sendable {
    public static let fixedChildDescriptor: Int32 = 198

    public let sourceDescriptor: Int32
    public let childDescriptor: Int32
    public let expectedDevice: UInt64
    public let expectedInode: UInt64

    public init(
        sourceDescriptor: Int32,
        childDescriptor: Int32 = CredentialMigrationInheritedDescriptor.fixedChildDescriptor,
        expectedDevice: UInt64,
        expectedInode: UInt64
    ) {
        self.sourceDescriptor = sourceDescriptor
        self.childDescriptor = childDescriptor
        self.expectedDevice = expectedDevice
        self.expectedInode = expectedInode
    }
}

/// Runs the trusted migration program in a fresh process group while draining
/// both result and diagnostic pipes incrementally. A noisy or hung child can
/// neither fill a pipe behind `waitpid`, allocate unbounded native memory, nor
/// keep the caller blocked by escaping the exact group with a pipe still open.
public enum BoundedCredentialMigrationProcess {
    public static func run(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        standardInput: Data? = nil,
        maximumStandardOutputBytes: Int = 64 * 1_024,
        maximumStandardErrorBytes: Int = 64 * 1_024,
        deadline: TimeInterval = 60,
        terminationGrace: TimeInterval = 0.25,
        inheritedDescriptor: CredentialMigrationInheritedDescriptor? = nil,
        spawnInitialization: CredentialMigrationSpawnInitialization = .production,
        onPipeDescriptorsAllocated: (([Int32]) -> Void)? = nil,
        onSpawn: ((pid_t) -> Void)? = nil
    ) throws -> CredentialMigrationProcessResult {
        guard executable.isFileURL,
              executable.path.hasPrefix("/"),
              !executable.path.contains("\0"),
              arguments.count <= 32,
              arguments.allSatisfy({ !$0.contains("\0") && $0.utf8.count <= 4_096 }),
              environment.count <= 4_096,
              environment.allSatisfy({
                  !$0.key.isEmpty && !$0.key.contains("=") && !$0.key.contains("\0")
                      && !$0.value.contains("\0") && $0.key.utf8.count <= 4_096
                      && $0.value.utf8.count <= 2 * 1_024 * 1_024
              }),
              standardInput.map({ $0.count <= 1_048_576 }) ?? true,
              (1...1_048_576).contains(maximumStandardOutputBytes),
              (1...1_048_576).contains(maximumStandardErrorBytes),
              deadline.isFinite, (0.05...3_600).contains(deadline),
              terminationGrace.isFinite, (0.01...5).contains(terminationGrace),
              inheritedDescriptor.map(Self.validateInheritedDescriptor) ?? true else {
            throw CredentialMigrationProcessRunnerError.invalidConfiguration
        }

        var stdinPipe = [Int32](repeating: -1, count: 2)
        var stdoutPipe = [Int32](repeating: -1, count: 2)
        var stderrPipe = [Int32](repeating: -1, count: 2)
        guard Darwin.pipe(&stdoutPipe) == 0 else {
            throw CredentialMigrationProcessRunnerError.pipeFailed(errno)
        }
        guard Darwin.pipe(&stderrPipe) == 0 else {
            let failure = errno
            _ = Darwin.close(stdoutPipe[0])
            _ = Darwin.close(stdoutPipe[1])
            throw CredentialMigrationProcessRunnerError.pipeFailed(failure)
        }
        if standardInput != nil, Darwin.pipe(&stdinPipe) != 0 {
            let failure = errno
            for descriptor in stdoutPipe + stderrPipe { _ = Darwin.close(descriptor) }
            throw CredentialMigrationProcessRunnerError.pipeFailed(failure)
        }
        let pipeDescriptors = stdoutPipe + stderrPipe + (standardInput == nil ? [] : stdinPipe)
        var openDescriptors = Set(pipeDescriptors)
        func closeDescriptor(_ descriptor: Int32) {
            guard openDescriptors.remove(descriptor) != nil else { return }
            _ = Darwin.close(descriptor)
        }
        defer { openDescriptors.forEach { _ = Darwin.close($0) } }
        // Internal, synchronous observability for exact descriptor-lifetime
        // tests. Production callers leave this nil. Report only descriptors
        // allocated by this runner, after all requested pipes exist and after
        // their cleanup defer is armed.
        onPipeDescriptorsAllocated?(pipeDescriptors)
        for descriptor in openDescriptors { _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC) }
        for descriptor in [stdoutPipe[0], stderrPipe[0]] {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw CredentialMigrationProcessRunnerError.pipeFailed(errno)
            }
        }
        if standardInput != nil {
            let flags = fcntl(stdinPipe[1], F_GETFL)
            guard flags >= 0,
                  fcntl(stdinPipe[1], F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(stdinPipe[1], F_SETNOSIGPIPE, 1) == 0 else {
                throw CredentialMigrationProcessRunnerError.pipeFailed(errno)
            }
        }

        // Duplicate only after every runner pipe has been allocated. The
        // temporary source is private to this exact spawn and always lives
        // above the reviewed child descriptor, so an otherwise valid lease
        // which happens to be fd 198 can still be mapped without a dup2/close
        // self-collision. The manager's original descriptor remains CLOEXEC
        // and owned by the lease for the whole migration boundary.
        var inheritedSpawnSource: Int32?
        if let inheritedDescriptor {
            guard Self.validateInheritedDescriptor(inheritedDescriptor) else {
                throw CredentialMigrationProcessRunnerError.invalidConfiguration
            }
            let temporary = Darwin.fcntl(
                inheritedDescriptor.sourceDescriptor,
                F_DUPFD_CLOEXEC,
                CredentialMigrationInheritedDescriptor.fixedChildDescriptor + 1
            )
            guard temporary > STDERR_FILENO,
                  temporary != inheritedDescriptor.childDescriptor else {
                if temporary >= 0 { _ = Darwin.close(temporary) }
                throw CredentialMigrationProcessRunnerError.invalidConfiguration
            }
            inheritedSpawnSource = temporary
            openDescriptors.insert(temporary)
        }

        var actions: posix_spawn_file_actions_t?
        let actionsStatus = spawnInitialization.initializeFileActions(&actions)
        guard actionsStatus == 0 else {
            throw CredentialMigrationProcessRunnerError.spawnFailed(actionsStatus)
        }
        defer { spawnInitialization.destroyFileActions(&actions) }

        var attributes: posix_spawnattr_t?
        let attributesStatus = spawnInitialization.initializeAttributes(&attributes)
        guard attributesStatus == 0 else {
            // The actions object is already owned by the defer above. Keeping
            // initialization split is important: a partial POSIX allocation
            // must not leak when attribute initialization fails.
            throw CredentialMigrationProcessRunnerError.spawnFailed(attributesStatus)
        }
        defer { spawnInitialization.destroyAttributes(&attributes) }
        guard posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO) == 0,
              posix_spawn_file_actions_addclose(&actions, stdoutPipe[0]) == 0,
              posix_spawn_file_actions_addclose(&actions, stderrPipe[0]) == 0,
              posix_spawn_file_actions_addclose(&actions, stdoutPipe[1]) == 0,
              posix_spawn_file_actions_addclose(&actions, stderrPipe[1]) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setflags(
                &attributes,
                Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
              ) == 0 else {
            throw CredentialMigrationProcessRunnerError.spawnFailed(errno)
        }
        if standardInput == nil {
            guard posix_spawn_file_actions_addopen(
                &actions,
                STDIN_FILENO,
                "/dev/null",
                O_RDONLY,
                0
            ) == 0 else {
                throw CredentialMigrationProcessRunnerError.spawnFailed(errno)
            }
        } else {
            guard posix_spawn_file_actions_adddup2(&actions, stdinPipe[0], STDIN_FILENO) == 0,
                  posix_spawn_file_actions_addclose(&actions, stdinPipe[0]) == 0,
                  posix_spawn_file_actions_addclose(&actions, stdinPipe[1]) == 0 else {
                throw CredentialMigrationProcessRunnerError.spawnFailed(errno)
            }
        }
        if let inheritedDescriptor, let inheritedSpawnSource {
            // Map only the short-lived duplicates. Closing those temporaries
            // in the child cannot close any reviewed target, including when a
            // manager-owned source already happens to use that target number.
            guard Self.validateInheritedDescriptor(inheritedDescriptor) else {
                throw CredentialMigrationProcessRunnerError.invalidConfiguration
            }
            guard posix_spawn_file_actions_adddup2(
                    &actions,
                    inheritedSpawnSource,
                    inheritedDescriptor.childDescriptor
                  ) == 0,
                posix_spawn_file_actions_addclose(
                    &actions,
                    inheritedSpawnSource
                ) == 0 else {
                throw CredentialMigrationProcessRunnerError.invalidConfiguration
            }
        }

        let argumentStrings = [executable.path] + arguments
        var argumentPointers = argumentStrings.map { strdup($0) }
        argumentPointers.append(nil)
        let environmentStrings = environment
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
        var environmentPointers = environmentStrings.map { strdup($0) }
        environmentPointers.append(nil)
        defer {
            for pointer in argumentPointers.compactMap({ $0 }) { free(pointer) }
            for pointer in environmentPointers.compactMap({ $0 }) { free(pointer) }
        }
        guard argumentPointers.dropLast().allSatisfy({ $0 != nil }),
              environmentPointers.dropLast().allSatisfy({ $0 != nil }) else {
            throw CredentialMigrationProcessRunnerError.spawnFailed(ENOMEM)
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
        // No unrelated child launch can observe this temporary descriptor,
        // and the callback never runs while it is live. On spawn failure the
        // same close happens before the error is admitted.
        if let inheritedSpawnSource { closeDescriptor(inheritedSpawnSource) }
        guard spawnStatus == 0, childPID > 0 else {
            throw CredentialMigrationProcessRunnerError.spawnFailed(spawnStatus)
        }
        closeDescriptor(stdoutPipe[1])
        closeDescriptor(stderrPipe[1])
        if standardInput != nil { closeDescriptor(stdinPipe[0]) }
        onSpawn?(childPID)

        let started = DispatchTime.now().uptimeNanoseconds
        let deadlineNanoseconds = UInt64(deadline * 1_000_000_000)
        let graceNanoseconds = UInt64(terminationGrace * 1_000_000_000)
        let postKillPipeDrainNanoseconds: UInt64 = 250_000_000
        var standardOutput = Data()
        var standardError = Data()
        standardOutput.reserveCapacity(min(maximumStandardOutputBytes, 16 * 1_024))
        standardError.reserveCapacity(min(maximumStandardErrorBytes, 16 * 1_024))
        var totalStandardOutputBytes = 0
        var totalStandardErrorBytes = 0
        var stdoutEOF = false
        var stderrEOF = false
        var stdinClosed = standardInput == nil
        var stdinOffset = 0
        var childExited = false
        var waitStatus: Int32 = 0
        var limit: CredentialMigrationProcessLimit?
        var terminationStartedAt: UInt64?
        var forceKillSent = false
        var forceKillSentAt: UInt64?
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)

        func beginLimit(_ value: CredentialMigrationProcessLimit, now: UInt64) {
            guard limit == nil else { return }
            limit = value
            terminationStartedAt = now
            _ = Darwin.kill(-childPID, SIGTERM)
        }

        func drain(_ descriptor: Int32, standardOutputStream: Bool) {
            // Keep a permanently readable writer from starving waitpid,
            // deadline checks, and SIGKILL escalation. Sixteen chunks is one
            // bounded 256 KiB quantum before the outer lifecycle loop runs.
            var drainIterations = 0
            while (standardOutputStream ? !stdoutEOF : !stderrEOF), drainIterations < 16 {
                let count = buffer.withUnsafeMutableBytes { storage in
                    Darwin.read(descriptor, storage.baseAddress, storage.count)
                }
                if count > 0 {
                    drainIterations += 1
                    let maximum = standardOutputStream
                        ? maximumStandardOutputBytes : maximumStandardErrorBytes
                    let captured = standardOutputStream ? standardOutput.count : standardError.count
                    let available = max(0, maximum - captured)
                    if available > 0 {
                        if standardOutputStream {
                            standardOutput.append(contentsOf: buffer.prefix(min(available, count)))
                        } else {
                            standardError.append(contentsOf: buffer.prefix(min(available, count)))
                        }
                    }
                    if standardOutputStream {
                        if totalStandardOutputBytes > maximum - count {
                            totalStandardOutputBytes = maximum + 1
                            beginLimit(.standardOutputBytes(maximum), now: DispatchTime.now().uptimeNanoseconds)
                        } else { totalStandardOutputBytes += count }
                    } else if totalStandardErrorBytes > maximum - count {
                        totalStandardErrorBytes = maximum + 1
                        beginLimit(.standardErrorBytes(maximum), now: DispatchTime.now().uptimeNanoseconds)
                    } else { totalStandardErrorBytes += count }
                    continue
                }
                if count == 0 {
                    if standardOutputStream { stdoutEOF = true } else { stderrEOF = true }
                    return
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                // A broken diagnostic pipe is a fail-closed bounded result.
                if standardOutputStream {
                    stdoutEOF = true
                    beginLimit(.standardOutputBytes(maximumStandardOutputBytes), now: DispatchTime.now().uptimeNanoseconds)
                } else {
                    stderrEOF = true
                    beginLimit(.standardErrorBytes(maximumStandardErrorBytes), now: DispatchTime.now().uptimeNanoseconds)
                }
                return
            }
        }

        func pumpStandardInput(now: UInt64) {
            guard !stdinClosed, let standardInput else { return }
            var iterations = 0
            while stdinOffset < standardInput.count, iterations < 16 {
                let count = standardInput.withUnsafeBytes { storage -> Int in
                    guard let baseAddress = storage.baseAddress else { return -1 }
                    return Darwin.write(
                        stdinPipe[1],
                        baseAddress.advanced(by: stdinOffset),
                        min(16 * 1_024, standardInput.count - stdinOffset)
                    )
                }
                if count > 0 {
                    stdinOffset += count
                    iterations += 1
                    continue
                }
                if count < 0, errno == EINTR { continue }
                if count < 0, errno == EAGAIN || errno == EWOULDBLOCK { return }
                if count < 0, errno == EPIPE {
                    closeDescriptor(stdinPipe[1])
                    stdinClosed = true
                    return
                }
                beginLimit(.standardInputBytes(standardInput.count), now: now)
                closeDescriptor(stdinPipe[1])
                stdinClosed = true
                return
            }
            if stdinOffset == standardInput.count {
                closeDescriptor(stdinPipe[1])
                stdinClosed = true
            }
        }

        while !childExited || !stdoutEOF || !stderrEOF {
            pumpStandardInput(now: DispatchTime.now().uptimeNanoseconds)
            drain(stdoutPipe[0], standardOutputStream: true)
            drain(stderrPipe[0], standardOutputStream: false)
            if !childExited {
                let waited = Darwin.waitpid(childPID, &waitStatus, WNOHANG)
                if waited == childPID {
                    childExited = true
                    if !stdinClosed {
                        closeDescriptor(stdinPipe[1])
                        stdinClosed = true
                    }
                } else if waited < 0, errno != EINTR {
                    let waitFailure = errno
                    _ = Darwin.kill(-childPID, SIGKILL)
                    // Do not return the lease to the manager while its exact
                    // child can still hold the inherited flock. Reap that PID
                    // even on a waitpid protocol failure; EINTR is bounded by
                    // eventual exact exit after SIGKILL.
                    var cleanupStatus: Int32 = 0
                    while Darwin.waitpid(childPID, &cleanupStatus, 0) < 0, errno == EINTR {}
                    throw CredentialMigrationProcessRunnerError.waitFailed(waitFailure)
                }
            }
            let current = DispatchTime.now().uptimeNanoseconds
            if limit == nil, current - started >= deadlineNanoseconds {
                beginLimit(.deadline(deadline), now: current)
            }
            if let terminationStartedAt,
               !forceKillSent,
               current - terminationStartedAt >= graceNanoseconds {
                _ = Darwin.kill(-childPID, SIGKILL)
                forceKillSent = true
                forceKillSentAt = current
            }
            if let forceKillSentAt, childExited {
                // A descendant can deliberately create a new session while
                // retaining either output pipe. It is outside the exact group
                // this runner may signal, so waiting for EOF would violate the
                // declared deadline. Give same-group children one bounded
                // drain allowance, then close our ends after the exact group
                // disappears (or the allowance expires) without broad process
                // discovery. Any surviving escaped writer receives EPIPE.
                let groupProbe = Darwin.kill(-childPID, 0)
                let exactGroupGone = groupProbe < 0 && errno == ESRCH
                if exactGroupGone
                    || current - forceKillSentAt >= postKillPipeDrainNanoseconds {
                    stdoutEOF = true
                    stderrEOF = true
                }
            }
            if !childExited || !stdoutEOF || !stderrEOF { usleep(5_000) }
        }

        closeDescriptor(stdoutPipe[0])
        closeDescriptor(stderrPipe[0])
        let signal = waitStatus & 0x7f
        return CredentialMigrationProcessResult(
            exitStatus: signal == 0 ? (waitStatus >> 8) & 0xff : nil,
            terminationSignal: signal == 0 ? nil : signal,
            standardOutput: standardOutput,
            standardError: standardError,
            limit: limit
        )
    }

    private static func validateInheritedDescriptor(
        _ inherited: CredentialMigrationInheritedDescriptor
    ) -> Bool {
        guard inherited.sourceDescriptor > STDERR_FILENO,
              inherited.childDescriptor == CredentialMigrationInheritedDescriptor.fixedChildDescriptor else {
            return false
        }
        let descriptorFlags = Darwin.fcntl(inherited.sourceDescriptor, F_GETFD)
        var metadata = stat()
        guard descriptorFlags >= 0,
              descriptorFlags & FD_CLOEXEC != 0,
              Darwin.fstat(inherited.sourceDescriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size == 0,
              descriptorHasNoExtendedACL(inherited.sourceDescriptor),
              UInt64(truncatingIfNeeded: metadata.st_dev) == inherited.expectedDevice,
              UInt64(truncatingIfNeeded: metadata.st_ino) == inherited.expectedInode else {
            return false
        }
        return true
    }

    private static func descriptorHasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(accessControlList))
        return false
    }
}

/// Narrow package-test SPI used by the separately launched fixed-descriptor
/// probe. The collision itself must run in a fresh process: descriptor 198 is
/// process-global, so manipulating it in the parallel Swift Testing host could
/// observe or replace an unrelated test's descriptor.
@_spi(CredentialMigrationFDCollisionProbe)
public struct CredentialMigrationFixedDescriptorProbeResult: Sendable {
    public let exitStatus: Int32?
    public let terminationSignal: Int32?
    public let standardOutput: Data
    public let standardError: Data
    public let reachedLimit: Bool
    public let matchingParentDescriptorsAtSpawn: [Int32]
}

@_spi(CredentialMigrationFDCollisionProbe)
public enum CredentialMigrationFixedDescriptorProbeAPI {
    public static let fixedChildDescriptor: Int32 =
        CredentialMigrationInheritedDescriptor.fixedChildDescriptor

    public static func run(
        sourceDescriptor: Int32,
        expectedDevice: UInt64,
        expectedInode: UInt64
    ) throws -> CredentialMigrationFixedDescriptorProbeResult {
        var matchingParentDescriptorsAtSpawn: [Int32] = []
        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: [
                "-c",
                "test -f /dev/fd/$1",
                "fixed-descriptor-collision-child",
                String(fixedChildDescriptor),
            ],
            environment: [
                "HOME": "/private/tmp",
                "PATH": "/usr/bin:/bin",
                "LANG": "en_US.UTF-8",
            ],
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 2,
            terminationGrace: 0.05,
            inheritedDescriptor: CredentialMigrationInheritedDescriptor(
                sourceDescriptor: sourceDescriptor,
                expectedDevice: expectedDevice,
                expectedInode: expectedInode
            ),
            onSpawn: { _ in
                for descriptor in Int32(STDERR_FILENO + 1)...512 {
                    var metadata = stat()
                    if Darwin.fstat(descriptor, &metadata) == 0,
                       UInt64(truncatingIfNeeded: metadata.st_dev) == expectedDevice,
                       UInt64(truncatingIfNeeded: metadata.st_ino) == expectedInode {
                        matchingParentDescriptorsAtSpawn.append(descriptor)
                    }
                }
            }
        )
        return CredentialMigrationFixedDescriptorProbeResult(
            exitStatus: result.exitStatus,
            terminationSignal: result.terminationSignal,
            standardOutput: result.standardOutput,
            standardError: result.standardError,
            reachedLimit: result.limit != nil,
            matchingParentDescriptorsAtSpawn: matchingParentDescriptorsAtSpawn
        )
    }
}
