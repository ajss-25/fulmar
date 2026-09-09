import Darwin
import Foundation

/// Starts one exact runtime as the process-group leader while a tiny sibling
/// guardian retains kernel exit watches for both the host app and that exact
/// runtime generation. Normal Quit still signals the Process object owned by
/// AppKit. If the host is killed or crashes, the guardian drains only this
/// generation's process group and then exits.

private let guardianArgument = "--fulmar-runtime-guardian-v1"
private let runtimeAuthenticationArgument = "--fulmar-runtime-auth-stdin-v1"
/// Publishes only the chosen descriptor NUMBER, never authentication material.
/// The runtime preloader consumes and closes exactly that descriptor.
private let runtimeAuthenticationDescriptorVariable = "LOCAL_HARNESS_RUNTIME_AUTH_FD"
private let maximumRuntimeAuthenticationBytes: off_t = 384
private let guardianReadyFrame = Data("FULMAR_RUNTIME_GUARDIAN_READY_V1\n".utf8)
private let guardianReadyDeadline: TimeInterval = 2
private let gracefulShutdownDelay: TimeInterval = 1

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("fulmar-runtime-lease: \(message)\n".utf8))
    Darwin.exit(125)
}

private func exactPositivePID(_ value: String) -> pid_t? {
    guard !value.isEmpty,
          value.allSatisfy(\.isNumber),
          let parsed = Int32(value),
          parsed > 1,
          String(parsed) == value else { return nil }
    return parsed
}

private func runtimeGuardian(arguments: [String]) -> Never {
    guard arguments.count == 4,
          arguments[1] == guardianArgument,
          let hostPID = exactPositivePID(arguments[2]),
          let runtimePID = exactPositivePID(arguments[3]),
          hostPID != runtimePID else {
        fail("guardian arguments are invalid")
    }
    guard Darwin.getppid() == runtimePID else {
        fail("guardian does not have the exact runtime parent")
    }
    // Foundation's Process launcher may place the helper in its own process
    // group. Rejoin the already-established runtime group only after proving
    // the exact direct-parent relationship.
    guard Darwin.setpgid(0, runtimePID) == 0 || Darwin.getpgrp() == runtimePID else {
        fail("guardian could not join the exact runtime process group")
    }

    // The guardian belongs to the leased runtime group. Ignore its graceful
    // shutdown signals so it can enforce the bounded SIGKILL escalation.
    _ = Darwin.signal(SIGTERM, SIG_IGN)
    _ = Darwin.signal(SIGINT, SIG_IGN)
    _ = Darwin.signal(SIGHUP, SIG_IGN)

    let queue = DispatchQueue(label: "app.fulmar.runtime-guardian", qos: .userInitiated)
    let hostExit = DispatchSource.makeProcessSource(identifier: hostPID, eventMask: .exit, queue: queue)
    let runtimeExit = DispatchSource.makeProcessSource(identifier: runtimePID, eventMask: .exit, queue: queue)
    let lock = NSLock()
    var shutdownStarted = false
    let beginShutdown = {
        lock.lock()
        guard !shutdownStarted else { lock.unlock(); return }
        shutdownStarted = true
        lock.unlock()

        let exactGroup = -runtimePID
        _ = Darwin.kill(exactGroup, SIGTERM)
        queue.asyncAfter(deadline: .now() + gracefulShutdownDelay) {
            _ = Darwin.kill(exactGroup, SIGKILL)
        }
    }
    hostExit.setEventHandler(handler: beginShutdown)
    runtimeExit.setEventHandler(handler: beginShutdown)
    hostExit.resume()
    runtimeExit.resume()

    // Close the registration race before granting exec authority. The helper
    // is still the direct child of the exact host at this point.
    guard Darwin.getppid() == runtimePID,
          Darwin.kill(hostPID, 0) == 0,
          Darwin.kill(runtimePID, 0) == 0 else {
        beginShutdown()
        dispatchMain()
    }
    FileHandle.standardOutput.write(guardianReadyFrame)
    try? FileHandle.standardOutput.close()
    dispatchMain()
}

private func validateTarget(_ value: String) -> String {
    guard value.hasPrefix("/"),
          value.utf8.count <= 4_096,
          !value.contains("\0"),
          value == URL(fileURLWithPath: value).standardizedFileURL.path else {
        fail("target path is not canonical")
    }
    var metadata = stat()
    guard Darwin.lstat(value, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == 0 || metadata.st_uid == geteuid(),
          metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
          metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0 else {
        fail("target executable has unsafe ownership, type, or permissions")
    }
    return value
}

private func validateRuntimeAuthenticationInput() {
    var metadata = stat()
    guard Darwin.fstat(STDIN_FILENO, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_nlink == 0,
          metadata.st_uid == Darwin.geteuid(),
          metadata.st_mode & 0o777 == 0o600,
          metadata.st_size >= 64,
          metadata.st_size <= maximumRuntimeAuthenticationBytes,
          Darwin.lseek(STDIN_FILENO, 0, SEEK_CUR) == 0 else {
        fail("runtime authentication input is unsafe")
    }
}

/// Moves the validated authentication record onto a dedicated descriptor above
/// stderr, atomically installs a verified `/dev/null` on stdin, and publishes
/// only the chosen descriptor number. The runtime preloader then consumes and
/// closes exactly that descriptor. Descriptor 0 is never left vacant: libuv
/// reuses the lowest free descriptor while initialising a stream and then
/// aborts in `uv__close` when that number is a standard descriptor.
private func handOffRuntimeAuthentication(cleanup: () -> Void) {
    func refuse(_ message: String) -> Never {
        cleanup()
        fail(message)
    }

    var original = stat()
    guard Darwin.fstat(STDIN_FILENO, &original) == 0 else {
        refuse("the runtime authentication input could not be inspected")
    }

    // The kernel picks the lowest free descriptor at or above stderr + 1, so
    // no live Foundation, guardian, or dispatch handle can be overwritten.
    let preserved = Darwin.fcntl(STDIN_FILENO, F_DUPFD, STDERR_FILENO + 1)
    guard preserved > STDERR_FILENO else {
        refuse("the runtime authentication input could not be preserved")
    }

    // Prove the duplicate is the same unlinked record on the same shared open
    // file description, still unread, rather than a same-numbered lookalike.
    var duplicated = stat()
    guard Darwin.fstat(preserved, &duplicated) == 0,
          duplicated.st_mode & S_IFMT == S_IFREG,
          duplicated.st_nlink == 0,
          duplicated.st_uid == Darwin.geteuid(),
          duplicated.st_mode & 0o777 == 0o600,
          duplicated.st_size >= 64,
          duplicated.st_size <= maximumRuntimeAuthenticationBytes,
          duplicated.st_dev == original.st_dev,
          duplicated.st_ino == original.st_ino,
          duplicated.st_mode == original.st_mode,
          duplicated.st_nlink == original.st_nlink,
          duplicated.st_uid == original.st_uid,
          duplicated.st_gid == original.st_gid,
          duplicated.st_size == original.st_size,
          Darwin.lseek(preserved, 0, SEEK_CUR) == 0 else {
        _ = Darwin.close(preserved)
        refuse("the preserved runtime authentication descriptor is not the exact input")
    }

    // `F_DUPFD` clears close-on-exec. Prove that rather than assume it: the
    // preloader must still find this exact record after the runtime exec.
    guard Darwin.fcntl(preserved, F_SETFD, 0) == 0,
          Darwin.fcntl(preserved, F_GETFD) == 0 else {
        _ = Darwin.close(preserved)
        refuse("the preserved runtime authentication descriptor is not inheritable")
    }

    var nullPath = stat()
    var nullOpened = stat()
    let nullDescriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard nullDescriptor > STDERR_FILENO else {
        if nullDescriptor >= 0 { _ = Darwin.close(nullDescriptor) }
        _ = Darwin.close(preserved)
        refuse("the null device could not be opened for stdin")
    }
    guard Darwin.fstat(nullDescriptor, &nullOpened) == 0,
          Darwin.lstat("/dev/null", &nullPath) == 0,
          nullOpened.st_mode & S_IFMT == S_IFCHR,
          nullPath.st_mode & S_IFMT == S_IFCHR,
          nullOpened.st_dev == nullPath.st_dev,
          nullOpened.st_ino == nullPath.st_ino,
          nullOpened.st_rdev == nullPath.st_rdev else {
        _ = Darwin.close(nullDescriptor)
        _ = Darwin.close(preserved)
        refuse("the null device is not the expected character device")
    }

    // One atomic replacement. Descriptor 0 is never vacant, so no later
    // allocation in this process or the runtime can claim that slot.
    guard Darwin.dup2(nullDescriptor, STDIN_FILENO) == STDIN_FILENO else {
        _ = Darwin.close(nullDescriptor)
        _ = Darwin.close(preserved)
        refuse("stdin could not be replaced by the null device")
    }
    _ = Darwin.close(nullDescriptor)

    var installed = stat()
    guard Darwin.fstat(STDIN_FILENO, &installed) == 0,
          installed.st_mode & S_IFMT == S_IFCHR,
          installed.st_dev == nullPath.st_dev,
          installed.st_ino == nullPath.st_ino,
          installed.st_rdev == nullPath.st_rdev,
          Darwin.fcntl(STDIN_FILENO, F_GETFD) == 0 else {
        _ = Darwin.close(preserved)
        refuse("stdin does not hold the verified null device")
    }

    guard Darwin.setenv(runtimeAuthenticationDescriptorVariable, String(preserved), 1) == 0 else {
        _ = Darwin.close(preserved)
        refuse("the runtime authentication descriptor could not be published")
    }
}

private func awaitGuardianReadiness(
    _ pipe: Pipe,
    guardian: Process,
    hostPID: pid_t,
    runtimePID: pid_t
) -> Bool {
    let descriptor = pipe.fileHandleForReading.fileDescriptor
    let currentFlags = Darwin.fcntl(descriptor, F_GETFL)
    guard currentFlags >= 0,
          Darwin.fcntl(descriptor, F_SETFL, currentFlags | O_NONBLOCK) == 0 else {
        return false
    }
    let deadline = Date().addingTimeInterval(guardianReadyDeadline)
    var received = Data()
    while Date() < deadline {
        var bytes = [UInt8](repeating: 0, count: 128)
        let count = Darwin.read(descriptor, &bytes, bytes.count)
        if count > 0 {
            received.append(contentsOf: bytes.prefix(count))
            if received == guardianReadyFrame {
                return Darwin.getppid() == hostPID
                    && Darwin.kill(hostPID, 0) == 0
                    && Darwin.kill(runtimePID, 0) == 0
            }
            guard guardianReadyFrame.starts(with: received) else { return false }
        } else if count == 0 {
            return false
        } else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
            return false
        }
        if !guardian.isRunning { return false }
        usleep(2_000)
    }
    return false
}

let arguments = CommandLine.arguments
if arguments.dropFirst().first == guardianArgument {
    runtimeGuardian(arguments: arguments)
}

let hasRuntimeAuthentication = arguments.dropFirst().first == runtimeAuthenticationArgument
let targetIndex = hasRuntimeAuthentication ? 2 : 1
guard arguments.count > targetIndex else { fail("an exact executable and arguments are required") }
if hasRuntimeAuthentication {
    validateRuntimeAuthenticationInput()
} else {
    // A stale or injected descriptor number must never reach an unauthenticated
    // runtime. Only this lease may publish the authentication descriptor.
    _ = Darwin.unsetenv(runtimeAuthenticationDescriptorVariable)
}
let target = validateTarget(arguments[targetIndex])
let hostPID = Darwin.getppid()
let runtimePID = Darwin.getpid()
guard hostPID > 1, runtimePID > 1, hostPID != runtimePID else {
    fail("host process identity is invalid")
}

// The leased runtime keeps its PID across exec and owns a unique process
// group. This lets the guardian terminate descendants without name matching,
// port discovery, or a PID scan.
guard Darwin.setpgid(0, 0) == 0 || (errno == EACCES && Darwin.getpgrp() == runtimePID) else {
    fail("could not establish the exact runtime process group")
}

let executable = URL(fileURLWithPath: arguments[0]).standardizedFileURL
guard executable.path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable.path) else {
    fail("guardian executable path is invalid")
}
let readiness = Pipe()
let guardian = Process()
guardian.executableURL = executable
guardian.arguments = [guardianArgument, String(hostPID), String(runtimePID)]
guardian.environment = [
    "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
    "PATH": "/usr/bin:/bin"
]
guardian.standardInput = FileHandle.nullDevice
guardian.standardOutput = readiness
guardian.standardError = FileHandle.standardError
do { try guardian.run() }
catch { fail("could not create the bounded runtime guardian") }
try? readiness.fileHandleForWriting.close()

guard awaitGuardianReadiness(
    readiness,
    guardian: guardian,
    hostPID: hostPID,
    runtimePID: runtimePID
) else {
    if guardian.isRunning { guardian.terminate() }
    fail("runtime guardian did not prove readiness")
}
try? readiness.fileHandleForReading.close()

// Only authenticated DSH launches carry the already-unlinked record across this
// exec, and they carry it on a dedicated descriptor above stderr while stdin
// holds a verified null device. Performed last, after every other descriptor
// this lease owns has been closed.
if hasRuntimeAuthentication {
    handOffRuntimeAuthentication(cleanup: {
        if guardian.isRunning { guardian.terminate() }
    })
}

// The selected target becomes argv[0], so it sees the conventional argument
// layout and no Fulmar-only lease or authentication marker.
Darwin.execv(target, CommandLine.unsafeArgv.advanced(by: targetIndex))
if guardian.isRunning { guardian.terminate() }
fail("could not execute the exact runtime target")
