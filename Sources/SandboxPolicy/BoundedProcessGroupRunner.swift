import Darwin
import Foundation

public enum BoundedProcessGroupRunnerError: Error, Equatable, Sendable {
    case invalidConfiguration
    case pipeFailed(Int32)
    case spawnFailed(Int32)
    case waitFailed(Int32)
}

public enum BoundedProcessGroupLimit: Equatable, Sendable {
    case stderrBytes(Int)
    case deadline(TimeInterval)
}

public struct BoundedProcessGroupResult: Equatable, Sendable {
    public let exitStatus: Int32?
    public let terminationSignal: Int32?
    public let stderr: Data
    public let stderrWasTruncated: Bool
    public let limit: BoundedProcessGroupLimit?

    public init(
        exitStatus: Int32?,
        terminationSignal: Int32?,
        stderr: Data,
        stderrWasTruncated: Bool,
        limit: BoundedProcessGroupLimit?
    ) {
        self.exitStatus = exitStatus
        self.terminationSignal = terminationSignal
        self.stderr = stderr
        self.stderrWasTruncated = stderrWasTruncated
        self.limit = limit
    }
}

/// Spawns one exact child process group and drains stderr incrementally.
/// Neither a fixed-length burst nor a descendant that keeps the pipe open can
/// allocate beyond `maximumStderrBytes` or keep the caller blocked past the
/// deadline and termination grace. Limit termination targets only the newly
/// spawned group; the runner and unrelated siblings are never discovered or
/// killed by name. A descendant that deliberately escapes that group may
/// survive, but its inherited diagnostic pipe is closed once the exact child
/// has been reaped and group termination has escalated.
public enum BoundedProcessGroupRunner {
    public static func run(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        maximumStderrBytes: Int,
        deadline: TimeInterval,
        terminationGrace: TimeInterval = 0.25,
        currentDirectory: URL? = nil,
        standardInputDescriptor: Int32? = nil,
        standardOutputDescriptor: Int32? = nil,
        discardStandardOutput: Bool = false,
        onSpawn: ((pid_t) -> Void)? = nil
    ) throws -> BoundedProcessGroupResult {
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
              deadline.isFinite, (0.05...86_400).contains(deadline),
              terminationGrace.isFinite, (0.01...5).contains(terminationGrace),
              currentDirectory.map({
                  $0.isFileURL && $0.path.hasPrefix("/") && !$0.path.contains("\0")
              }) ?? true,
              standardInputDescriptor.map({ fcntl($0, F_GETFD) >= 0 }) ?? true,
              standardOutputDescriptor.map({ fcntl($0, F_GETFD) >= 0 }) ?? true else {
            throw BoundedProcessGroupRunnerError.invalidConfiguration
        }
        guard !discardStandardOutput || standardOutputDescriptor == nil else {
            throw BoundedProcessGroupRunnerError.invalidConfiguration
        }

        var pipeDescriptors = [Int32](repeating: -1, count: 2)
        guard Darwin.pipe(&pipeDescriptors) == 0 else {
            throw BoundedProcessGroupRunnerError.pipeFailed(errno)
        }
        let readDescriptor = pipeDescriptors[0]
        let writeDescriptor = pipeDescriptors[1]
        var readOpen = true
        var writeOpen = true
        defer {
            if readOpen { close(readDescriptor) }
            if writeOpen { close(writeDescriptor) }
        }
        _ = fcntl(readDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(writeDescriptor, F_SETFD, FD_CLOEXEC)
        let existingFlags = fcntl(readDescriptor, F_GETFL)
        guard existingFlags >= 0,
              fcntl(readDescriptor, F_SETFL, existingFlags | O_NONBLOCK) == 0 else {
            throw BoundedProcessGroupRunnerError.pipeFailed(errno)
        }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            throw BoundedProcessGroupRunnerError.spawnFailed(errno)
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        var defaultSignals = sigset_t()
        var childSignalMask = sigset_t()
        let spawnFlags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
        if let currentDirectory {
            guard posix_spawn_file_actions_addchdir_np(&actions, currentDirectory.path) == 0 else {
                throw BoundedProcessGroupRunnerError.spawnFailed(errno)
            }
        }
        if let standardInputDescriptor {
            guard posix_spawn_file_actions_adddup2(
                &actions,
                standardInputDescriptor,
                STDIN_FILENO
            ) == 0 else { throw BoundedProcessGroupRunnerError.spawnFailed(errno) }
        }
        if discardStandardOutput {
            guard posix_spawn_file_actions_addopen(
                &actions,
                STDOUT_FILENO,
                "/dev/null",
                O_WRONLY,
                0
            ) == 0 else { throw BoundedProcessGroupRunnerError.spawnFailed(errno) }
        } else if let standardOutputDescriptor {
            guard posix_spawn_file_actions_adddup2(
                &actions,
                standardOutputDescriptor,
                STDOUT_FILENO
            ) == 0 else { throw BoundedProcessGroupRunnerError.spawnFailed(errno) }
        }
        var inheritedDescriptors = Set(
            [standardInputDescriptor, standardOutputDescriptor].compactMap { $0 }
        )
        inheritedDescriptors.subtract([STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO])
        for descriptor in inheritedDescriptors {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
                throw BoundedProcessGroupRunnerError.spawnFailed(errno)
            }
        }
        guard posix_spawn_file_actions_adddup2(&actions, writeDescriptor, STDERR_FILENO) == 0,
              posix_spawn_file_actions_addclose(&actions, readDescriptor) == 0,
              posix_spawn_file_actions_addclose(&actions, writeDescriptor) == 0,
              sigemptyset(&defaultSignals) == 0,
              sigaddset(&defaultSignals, SIGINT) == 0,
              sigaddset(&defaultSignals, SIGTERM) == 0,
              sigaddset(&defaultSignals, SIGHUP) == 0,
              sigemptyset(&childSignalMask) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaultSignals) == 0,
              posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0,
              posix_spawnattr_setflags(&attributes, Int16(spawnFlags)) == 0 else {
            throw BoundedProcessGroupRunnerError.spawnFailed(errno)
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
            throw BoundedProcessGroupRunnerError.spawnFailed(ENOMEM)
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
        guard spawnStatus == 0, childPID > 0 else {
            throw BoundedProcessGroupRunnerError.spawnFailed(spawnStatus)
        }
        close(writeDescriptor)
        writeOpen = false
        onSpawn?(childPID)

        let started = DispatchTime.now().uptimeNanoseconds
        let deadlineNanos = UInt64(deadline * 1_000_000_000)
        let graceNanos = UInt64(terminationGrace * 1_000_000_000)
        let postKillPipeDrainNanos: UInt64 = 250_000_000
        var captured = Data()
        captured.reserveCapacity(min(maximumStderrBytes, 64 * 1_024))
        var totalBytes = 0
        var limit: BoundedProcessGroupLimit?
        var terminationStartedAt: UInt64?
        var forceKillSent = false
        var forceKillSentAt: UInt64?
        var childExited = false
        var pipeEOF = false
        var waitStatus: Int32 = 0
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)

        func beginLimit(_ newLimit: BoundedProcessGroupLimit, now: UInt64) {
            guard limit == nil else { return }
            limit = newLimit
            terminationStartedAt = now
            _ = Darwin.kill(-childPID, SIGTERM)
        }

        while !childExited || !pipeEOF {
            // Never let an adversarial writer keep the pipe perpetually
            // readable and starve the deadline/escalation checks below.
            // Sixteen chunks is a bounded 256 KiB drain quantum.
            var drainIterations = 0
            while !pipeEOF, drainIterations < 16 {
                let count = buffer.withUnsafeMutableBytes { bytes in
                    Darwin.read(readDescriptor, bytes.baseAddress, bytes.count)
                }
                if count > 0 {
                    drainIterations += 1
                    let available = max(0, maximumStderrBytes - captured.count)
                    if available > 0 {
                        captured.append(contentsOf: buffer.prefix(min(available, count)))
                    }
                    if totalBytes > maximumStderrBytes - count {
                        totalBytes = maximumStderrBytes + 1
                        beginLimit(.stderrBytes(maximumStderrBytes), now: DispatchTime.now().uptimeNanoseconds)
                    } else {
                        totalBytes += count
                    }
                    continue
                }
                if count == 0 { pipeEOF = true; break }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { break }
                beginLimit(.stderrBytes(maximumStderrBytes), now: DispatchTime.now().uptimeNanoseconds)
                pipeEOF = true
                break
            }

            if !childExited {
                let waited = Darwin.waitpid(childPID, &waitStatus, WNOHANG)
                if waited == childPID {
                    childExited = true
                } else if waited < 0, errno != EINTR {
                    _ = Darwin.kill(-childPID, SIGKILL)
                    throw BoundedProcessGroupRunnerError.waitFailed(errno)
                }
            }

            let current = DispatchTime.now().uptimeNanoseconds
            if limit == nil, current - started >= deadlineNanos {
                beginLimit(.deadline(deadline), now: current)
            }
            if let terminationStartedAt,
               !forceKillSent,
               current - terminationStartedAt >= graceNanos {
                // Send this even if the group leader already exited: a
                // same-group descendant may still own the diagnostic pipe.
                _ = Darwin.kill(-childPID, SIGKILL)
                forceKillSent = true
                forceKillSentAt = current
            }
            if let forceKillSentAt, childExited, !pipeEOF {
                // A hostile descendant can create a new process group/session
                // while retaining stderr. It is then intentionally outside the
                // exact group we are allowed to signal, so waiting for EOF here
                // would turn a bounded probe/update into an unbounded hang.
                // First allow same-group children to disappear and finish the
                // pipe naturally. If the exact group is already gone, or that
                // bounded drain allowance expires, close our end and give any
                // escaped writer EPIPE without broad process discovery.
                let groupProbe = Darwin.kill(-childPID, 0)
                let exactGroupGone = groupProbe < 0 && errno == ESRCH
                if exactGroupGone || current - forceKillSentAt >= postKillPipeDrainNanos {
                    pipeEOF = true
                }
            }
            if !childExited || !pipeEOF { usleep(5_000) }
        }

        close(readDescriptor)
        readOpen = false
        let signal = waitStatus & 0x7f
        let exitStatus: Int32? = signal == 0 ? (waitStatus >> 8) & 0xff : nil
        let terminationSignal: Int32? = signal == 0 ? nil : signal
        return BoundedProcessGroupResult(
            exitStatus: exitStatus,
            terminationSignal: terminationSignal,
            stderr: captured,
            stderrWasTruncated: totalBytes > maximumStderrBytes,
            limit: limit
        )
    }
}
