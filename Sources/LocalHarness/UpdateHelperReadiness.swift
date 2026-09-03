import Darwin
import Foundation
import LocalHarnessUpdateSecurity

enum UpdateHelperReadinessError: Error, Equatable, Sendable {
    case invalidConfiguration
    case pipeFailed(Int32)
    case spawnFailed(Int32)
    case waitFailed(Int32)
    case protocolViolation
    case stderrLimitExceeded
    case deadlineExceeded
    case exitedBeforeReady
    case cleanupFailed
}

/// Retains the identity of the exact helper that completed the readiness
/// handshake. The app intentionally does not terminate this process on
/// deinitialization: after authorization it must survive the app's exit and
/// perform the already-attested replacement transaction.
final class UpdateHelperLaunchHandle: @unchecked Sendable {
    let processIdentifier: pid_t

    fileprivate init(processIdentifier: pid_t) {
        self.processIdentifier = processIdentifier
    }
}

/// Launches the signed update helper in a new process group and accepts it only
/// after the helper has completed all validation performed while the parent is
/// still alive. Readiness and diagnostics use parent-created pipes installed
/// atomically by `posix_spawn`; no ambient descriptor is inherited.
enum UpdateHelperReadinessSupervisor {
    private static let drainQuantum = 16
    private static let bufferBytes = 16 * 1_024

    static func launch(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        maximumStderrBytes: Int = 64 * 1_024,
        deadline: TimeInterval = 10,
        terminationGrace: TimeInterval = 0.25,
        onSpawn: ((pid_t) -> Void)? = nil
    ) throws -> UpdateHelperLaunchHandle {
        guard executable.isFileURL,
              executable.path.hasPrefix("/"),
              !executable.path.contains("\0"),
              arguments.count <= 4_096,
              arguments.allSatisfy({ !$0.contains("\0") && $0.utf8.count <= 1_048_576 }),
              environment.count <= 4_096,
              environment.allSatisfy({
                  !$0.key.isEmpty && !$0.key.contains("=") && !$0.key.contains("\0") &&
                      !$0.value.contains("\0") && $0.key.utf8.count <= 4_096 &&
                      $0.value.utf8.count <= 2 * 1_024 * 1_024
              }),
              (1...16 * 1_024 * 1_024).contains(maximumStderrBytes),
              deadline.isFinite, (0.05...60).contains(deadline),
              terminationGrace.isFinite, (0.01...5).contains(terminationGrace) else {
            throw UpdateHelperReadinessError.invalidConfiguration
        }

        var readinessPipe = [Int32](repeating: -1, count: 2)
        guard Darwin.pipe(&readinessPipe) == 0 else {
            throw UpdateHelperReadinessError.pipeFailed(errno)
        }
        var readinessReadOpen = true
        var readinessWriteOpen = true
        defer {
            if readinessReadOpen { Darwin.close(readinessPipe[0]) }
            if readinessWriteOpen { Darwin.close(readinessPipe[1]) }
        }

        var stderrPipe = [Int32](repeating: -1, count: 2)
        guard Darwin.pipe(&stderrPipe) == 0 else {
            throw UpdateHelperReadinessError.pipeFailed(errno)
        }
        var stderrReadOpen = true
        var stderrWriteOpen = true
        defer {
            if stderrReadOpen { Darwin.close(stderrPipe[0]) }
            if stderrWriteOpen { Darwin.close(stderrPipe[1]) }
        }

        for descriptor in readinessPipe + stderrPipe {
            guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
                throw UpdateHelperReadinessError.pipeFailed(errno)
            }
        }
        for descriptor in [readinessPipe[0], stderrPipe[0]] {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw UpdateHelperReadinessError.pipeFailed(errno)
            }
        }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            throw UpdateHelperReadinessError.spawnFailed(errno)
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }

        let readinessDescriptor = UpdateHelperReadinessProtocol.childDescriptor
        guard readinessDescriptor > STDERR_FILENO,
              posix_spawn_file_actions_adddup2(
                  &actions,
                  readinessPipe[1],
                  readinessDescriptor
              ) == 0,
              posix_spawn_file_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO) == 0,
              posix_spawn_file_actions_addopen(
                  &actions,
                  STDIN_FILENO,
                  "/dev/null",
                  O_RDONLY,
                  0
              ) == 0,
              posix_spawn_file_actions_addopen(
                  &actions,
                  STDOUT_FILENO,
                  "/dev/null",
                  O_WRONLY,
                  0
              ) == 0 else {
            throw UpdateHelperReadinessError.spawnFailed(errno)
        }
        for descriptor in Set(readinessPipe + stderrPipe)
            where descriptor != readinessDescriptor && descriptor != STDERR_FILENO {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
                throw UpdateHelperReadinessError.spawnFailed(errno)
            }
        }

        var defaultSignals = sigset_t()
        var childSignalMask = sigset_t()
        let spawnFlags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF |
            POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT
        guard sigemptyset(&defaultSignals) == 0,
              sigaddset(&defaultSignals, SIGINT) == 0,
              sigaddset(&defaultSignals, SIGTERM) == 0,
              sigaddset(&defaultSignals, SIGHUP) == 0,
              sigaddset(&defaultSignals, SIGPIPE) == 0,
              sigemptyset(&childSignalMask) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaultSignals) == 0,
              posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0,
              posix_spawnattr_setflags(&attributes, Int16(spawnFlags)) == 0 else {
            throw UpdateHelperReadinessError.spawnFailed(errno)
        }

        let argumentStrings = [executable.path] + arguments + [UpdateHelperReadinessProtocol.argument]
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
            throw UpdateHelperReadinessError.spawnFailed(ENOMEM)
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
            throw UpdateHelperReadinessError.spawnFailed(spawnStatus)
        }
        Darwin.close(readinessPipe[1])
        readinessWriteOpen = false
        Darwin.close(stderrPipe[1])
        stderrWriteOpen = false
        onSpawn?(childPID)

        // POSIX_SPAWN_SETPGROUP with pgroup zero is the cleanup authority. Do
        // not ever signal a negative PID unless that exact relationship holds.
        guard getpgid(childPID) == childPID else {
            _ = terminateAndReap(
                childPID,
                ownsProcessGroup: false,
                terminationGrace: terminationGrace
            )
            throw UpdateHelperReadinessError.spawnFailed(EPERM)
        }

        var childReaped = false
        do {
            try awaitReadiness(
                childPID: childPID,
                readinessDescriptor: readinessPipe[0],
                stderrDescriptor: stderrPipe[0],
                maximumStderrBytes: maximumStderrBytes,
                deadline: deadline,
                childReaped: &childReaped
            )
        } catch let error as UpdateHelperReadinessError {
            let cleaned = terminateAndReap(
                childPID,
                ownsProcessGroup: true,
                terminationGrace: terminationGrace,
                childAlreadyReaped: childReaped
            )
            guard cleaned else { throw UpdateHelperReadinessError.cleanupFailed }
            throw error
        } catch {
            let cleaned = terminateAndReap(
                childPID,
                ownsProcessGroup: true,
                terminationGrace: terminationGrace,
                childAlreadyReaped: childReaped
            )
            guard cleaned else { throw UpdateHelperReadinessError.cleanupFailed }
            throw error
        }

        Darwin.close(readinessPipe[0])
        readinessReadOpen = false
        Darwin.close(stderrPipe[0])
        stderrReadOpen = false
        return UpdateHelperLaunchHandle(processIdentifier: childPID)
    }

    /// Disposes a helper that completed readiness but can no longer be granted
    /// the matching install authorization (and deterministic test fixtures).
    static func terminateReadyProcess(
        _ handle: UpdateHelperLaunchHandle,
        terminationGrace: TimeInterval = 0.1
    ) -> Bool {
        terminateAndReap(
            handle.processIdentifier,
            ownsProcessGroup: true,
            terminationGrace: terminationGrace
        )
    }

    private static func awaitReadiness(
        childPID: pid_t,
        readinessDescriptor: Int32,
        stderrDescriptor: Int32,
        maximumStderrBytes: Int,
        deadline: TimeInterval,
        childReaped: inout Bool
    ) throws {
        let expected = UpdateHelperReadinessProtocol.frame
        let started = DispatchTime.now().uptimeNanoseconds
        let deadlineNanos = UInt64(deadline * 1_000_000_000)
        var readiness = Data()
        readiness.reserveCapacity(expected.count)
        var stderr = Data()
        stderr.reserveCapacity(min(maximumStderrBytes, 64 * 1_024))
        var totalStderrBytes = 0
        var readinessEOF = false
        var stderrEOF = false
        var waitStatus: Int32 = 0
        var buffer = [UInt8](repeating: 0, count: bufferBytes)

        while true {
            try drain(
                descriptor: readinessDescriptor,
                eof: &readinessEOF,
                buffer: &buffer
            ) { bytes in
                guard readiness.count <= expected.count - bytes.count else {
                    throw UpdateHelperReadinessError.protocolViolation
                }
                readiness.append(contentsOf: bytes)
                guard expected.starts(with: readiness) else {
                    throw UpdateHelperReadinessError.protocolViolation
                }
            }

            try drain(
                descriptor: stderrDescriptor,
                eof: &stderrEOF,
                buffer: &buffer
            ) { bytes in
                guard totalStderrBytes <= maximumStderrBytes - bytes.count else {
                    throw UpdateHelperReadinessError.stderrLimitExceeded
                }
                totalStderrBytes += bytes.count
                stderr.append(contentsOf: bytes)
            }

            let waited = Darwin.waitpid(childPID, &waitStatus, WNOHANG)
            if waited == childPID {
                childReaped = true
            } else if waited < 0, errno != EINTR {
                throw UpdateHelperReadinessError.waitFailed(errno)
            }

            if readinessEOF {
                guard readiness == expected else {
                    throw UpdateHelperReadinessError.protocolViolation
                }
            }
            if readinessEOF, stderrEOF {
                guard stderr.isEmpty else {
                    throw UpdateHelperReadinessError.protocolViolation
                }
                guard !childReaped, kill(childPID, 0) == 0 else {
                    throw UpdateHelperReadinessError.exitedBeforeReady
                }
                return
            }
            if childReaped, readinessEOF, stderrEOF {
                throw UpdateHelperReadinessError.exitedBeforeReady
            }
            if DispatchTime.now().uptimeNanoseconds - started >= deadlineNanos {
                throw UpdateHelperReadinessError.deadlineExceeded
            }
            usleep(2_000)
        }
    }

    private static func drain(
        descriptor: Int32,
        eof: inout Bool,
        buffer: inout [UInt8],
        consume: (ArraySlice<UInt8>) throws -> Void
    ) throws {
        guard !eof else { return }
        var iterations = 0
        while iterations < drainQuantum {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress, bytes.count)
            }
            if count > 0 {
                iterations += 1
                try consume(buffer.prefix(count))
                continue
            }
            if count == 0 {
                eof = true
                return
            }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            throw UpdateHelperReadinessError.pipeFailed(errno)
        }
    }

    @discardableResult
    private static func terminateAndReap(
        _ childPID: pid_t,
        ownsProcessGroup: Bool,
        terminationGrace: TimeInterval,
        childAlreadyReaped: Bool = false
    ) -> Bool {
        guard childPID > 1 else { return false }
        var childReaped = childAlreadyReaped
        let signalTarget = ownsProcessGroup ? -childPID : childPID
        _ = Darwin.kill(signalTarget, SIGTERM)
        let started = DispatchTime.now().uptimeNanoseconds
        let graceNanos = UInt64(terminationGrace * 1_000_000_000)
        let hardNanos = graceNanos + 2_000_000_000
        var forceKillSent = false
        var waitStatus: Int32 = 0

        while true {
            if !childReaped {
                let waited = Darwin.waitpid(childPID, &waitStatus, WNOHANG)
                if waited == childPID || (waited < 0 && errno == ECHILD) {
                    childReaped = true
                } else if waited < 0, errno != EINTR {
                    return false
                }
            }
            let elapsed = DispatchTime.now().uptimeNanoseconds - started
            if !forceKillSent, elapsed >= graceNanos {
                _ = Darwin.kill(signalTarget, SIGKILL)
                forceKillSent = true
            }
            let groupGone: Bool
            if ownsProcessGroup {
                groupGone = Darwin.kill(-childPID, 0) != 0 && errno == ESRCH
            } else {
                groupGone = childReaped
            }
            if childReaped, groupGone { return true }
            if elapsed >= hardNanos { return false }
            usleep(2_000)
        }
    }
}
