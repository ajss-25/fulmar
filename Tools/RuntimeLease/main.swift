import Darwin
import Foundation

/// Starts one exact runtime as the process-group leader while a tiny sibling
/// guardian retains kernel exit watches for both the host app and that exact
/// runtime generation. Normal Quit still signals the Process object owned by
/// AppKit. If the host is killed or crashes, the guardian drains only this
/// generation's process group and then exits.

private let guardianArgument = "--fulmar-runtime-guardian-v1"
private let runtimeAuthenticationArgument = "--fulmar-runtime-auth-stdin-v1"
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
if hasRuntimeAuthentication { validateRuntimeAuthenticationInput() }
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

// The selected target becomes argv[0], so it sees the conventional argument
// layout and no Fulmar-only lease or authentication marker. Only authenticated
// DSH launches retain the already-unlinked stdin record across this exec.
Darwin.execv(target, CommandLine.unsafeArgv.advanced(by: targetIndex))
if guardian.isRunning { guardian.terminate() }
fail("could not execute the exact runtime target")
