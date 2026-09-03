import Darwin
import Foundation
import LocalHarnessUpdateSecurity

private func fail(_ message: String) -> Never {
    let diagnostic = Array("Update helper: \(message)\n".utf8)
    diagnostic.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(
                STDERR_FILENO,
                bytes.baseAddress?.advanced(by: offset),
                bytes.count - offset
            )
            if written > 0 { offset += written; continue }
            if written < 0, errno == EINTR { continue }
            break
        }
    }
    exit(2)
}

private enum ReadinessEmissionError: Error {
    case invalidPipe
    case writeFailed
}

/// Emits readiness only to the anonymous pipe installed by the parent. The
/// descriptor and stderr are closed before the parent-wait begins so the app
/// can prove both streams are complete rather than accepting a merely-live
/// process.
private func emitReadiness() throws {
    let descriptor = UpdateHelperReadinessProtocol.childDescriptor
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFIFO else {
        throw ReadinessEmissionError.invalidPipe
    }
    try UpdateHelperReadinessProtocol.frame.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(
                descriptor,
                bytes.baseAddress?.advanced(by: offset),
                bytes.count - offset
            )
            if written > 0 { offset += written; continue }
            if written < 0, errno == EINTR { continue }
            throw ReadinessEmissionError.writeFailed
        }
    }
    guard Darwin.close(descriptor) == 0 else {
        throw ReadinessEmissionError.writeFailed
    }
    _ = Darwin.close(STDERR_FILENO)
}

private func waitForExit(_ process: pid_t) throws {
    guard process > 1, process != getpid() else { throw UpdateSecurityError.parentDidNotExit }
    for _ in 0..<UpdateHelperReadinessProtocol.parentExitMaximumPolls {
        if kill(process, 0) != 0 {
            guard errno == ESRCH else { throw UpdateSecurityError.parentDidNotExit }
            return
        }
        usleep(UpdateHelperReadinessProtocol.parentExitPollMicroseconds)
    }
    throw UpdateSecurityError.parentDidNotExit
}

private func standardizedAbsoluteURL(_ value: String, directory: Bool) throws -> URL {
    guard value.hasPrefix("/"), value.utf8.count <= 4_096 else {
        throw UpdateSecurityError.invalidPath
    }
    let original = URL(fileURLWithPath: value, isDirectory: directory)
    let standardized = original.standardizedFileURL
    guard standardized.path == value else { throw UpdateSecurityError.invalidPath }
    return standardized
}

private func launchApplication(_ application: URL, fileManager: FileManager) throws {
    let opener = Process()
    opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    opener.arguments = [application.path]
    opener.environment = [
        "HOME": fileManager.homeDirectoryForCurrentUser.path,
        "PATH": "/usr/bin:/bin"
    ]
    try opener.run()
}

private final class CandidateLaunch {
    let processIdentifier: pid_t
    var healthDescriptor: Int32

    init(processIdentifier: pid_t, healthDescriptor: Int32) {
        self.processIdentifier = processIdentifier
        self.healthDescriptor = healthDescriptor
    }
}

private func closeCandidateLaunch(_ launch: CandidateLaunch) {
    if launch.healthDescriptor >= 0 {
        _ = Darwin.close(launch.healthDescriptor)
        launch.healthDescriptor = -1
    }
}

private func stopCandidate(_ launch: CandidateLaunch) throws {
    closeCandidateLaunch(launch)
    guard launch.processIdentifier > 1,
          getpgid(launch.processIdentifier) == launch.processIdentifier else {
        throw UpdateSecurityError.rollbackFailed
    }
    _ = Darwin.kill(-launch.processIdentifier, SIGTERM)
    var status: Int32 = 0
    let started = DispatchTime.now().uptimeNanoseconds
    var forced = false
    while DispatchTime.now().uptimeNanoseconds - started < 4_000_000_000 {
        let waited = Darwin.waitpid(launch.processIdentifier, &status, WNOHANG)
        if waited == launch.processIdentifier || (waited < 0 && errno == ECHILD) { return }
        if waited < 0, errno != EINTR { throw UpdateSecurityError.rollbackFailed }
        if !forced, DispatchTime.now().uptimeNanoseconds - started >= 2_000_000_000 {
            _ = Darwin.kill(-launch.processIdentifier, SIGKILL)
            forced = true
        }
        usleep(5_000)
    }
    throw UpdateSecurityError.rollbackFailed
}

private func launchCandidate(
    _ application: URL,
    expected: SignedApplicationAttestation,
    nonceHex: String,
    fileManager: FileManager
) throws -> CandidateLaunch {
    _ = try UpdateApplicationSecurity.stableValidatedApplication(at: application, expected: expected)
    let executable = try UpdateApplicationSecurity.executableURL(at: application)
    var sockets = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else {
        throw UpdateSecurityError.installFailed
    }
    var parentOpen = true
    var childOpen = true
    defer {
        if parentOpen { Darwin.close(sockets[0]) }
        if childOpen { Darwin.close(sockets[1]) }
    }
    for descriptor in sockets {
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            throw UpdateSecurityError.installFailed
        }
    }

    var actions: posix_spawn_file_actions_t?
    var attributes: posix_spawnattr_t?
    guard posix_spawn_file_actions_init(&actions) == 0,
          posix_spawnattr_init(&attributes) == 0 else {
        throw UpdateSecurityError.installFailed
    }
    defer {
        posix_spawn_file_actions_destroy(&actions)
        posix_spawnattr_destroy(&attributes)
    }
    let childDescriptor = UpdatePostInstallHealthProtocol.childDescriptor
    guard posix_spawn_file_actions_adddup2(&actions, sockets[1], childDescriptor) == 0,
          posix_spawn_file_actions_addclose(&actions, sockets[0]) == 0,
          (sockets[1] == childDescriptor || posix_spawn_file_actions_addclose(&actions, sockets[1]) == 0),
          posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0,
          posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0,
          posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 else {
        throw UpdateSecurityError.installFailed
    }

    var defaultSignals = sigset_t()
    var childSignalMask = sigset_t()
    let flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF |
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
          posix_spawnattr_setflags(&attributes, Int16(flags)) == 0 else {
        throw UpdateSecurityError.installFailed
    }

    let argumentStrings = [executable.path, UpdatePostInstallHealthProtocol.argument]
    var argumentPointers = argumentStrings.map { strdup($0) }
    argumentPointers.append(nil)
    let environment = [
        "HOME": fileManager.homeDirectoryForCurrentUser.path,
        "PATH": "/usr/bin:/bin",
        "TMPDIR": NSTemporaryDirectory()
    ]
    let environmentStrings = environment.keys.sorted().map { "\($0)=\(environment[$0]!)" }
    var environmentPointers = environmentStrings.map { strdup($0) }
    environmentPointers.append(nil)
    defer {
        for pointer in argumentPointers.compactMap({ $0 }) { free(pointer) }
        for pointer in environmentPointers.compactMap({ $0 }) { free(pointer) }
    }
    guard argumentPointers.dropLast().allSatisfy({ $0 != nil }),
          environmentPointers.dropLast().allSatisfy({ $0 != nil }) else {
        throw UpdateSecurityError.installFailed
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
    guard spawnStatus == 0, childPID > 1 else { throw UpdateSecurityError.installFailed }
    Darwin.close(sockets[1])
    childOpen = false
    guard getpgid(childPID) == childPID else {
        let launch = CandidateLaunch(processIdentifier: childPID, healthDescriptor: sockets[0])
        parentOpen = false
        try? stopCandidate(launch)
        throw UpdateSecurityError.installFailed
    }
    let launch = CandidateLaunch(processIdentifier: childPID, healthDescriptor: sockets[0])
    parentOpen = false
    do {
        let challenge = try UpdatePostInstallHealthProtocol.challenge(
            nonceHex: nonceHex,
            candidate: expected
        )
        try challenge.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    launch.healthDescriptor,
                    bytes.baseAddress?.advanced(by: offset),
                    bytes.count - offset
                )
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR { continue }
                throw UpdateSecurityError.installFailed
            }
        }
        guard shutdown(launch.healthDescriptor, SHUT_WR) == 0 else {
            throw UpdateSecurityError.installFailed
        }
        return launch
    } catch {
        try? stopCandidate(launch)
        throw error
    }
}

private func awaitCandidateHealth(
    _ launch: CandidateLaunch,
    nonceHex: String,
    expected: SignedApplicationAttestation,
    deadline: TimeInterval = 120
) throws {
    guard deadline.isFinite, (1...300).contains(deadline) else {
        throw UpdateSecurityError.installFailed
    }
    let started = DispatchTime.now().uptimeNanoseconds
    let deadlineNanos = UInt64(deadline * 1_000_000_000)
    var frame = Data()
    var byte: UInt8 = 0
    var status: Int32 = 0
    while frame.count < UpdatePostInstallHealthProtocol.maximumFrameBytes {
        let waited = Darwin.waitpid(launch.processIdentifier, &status, WNOHANG)
        if waited == launch.processIdentifier || (waited < 0 && errno == ECHILD) {
            throw UpdateSecurityError.installFailed
        }
        if waited < 0, errno != EINTR { throw UpdateSecurityError.installFailed }
        let elapsed = DispatchTime.now().uptimeNanoseconds - started
        guard elapsed < deadlineNanos else { throw UpdateSecurityError.installFailed }
        var polled = pollfd(fd: launch.healthDescriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        let pollResult = Darwin.poll(&polled, 1, 100)
        if pollResult < 0, errno == EINTR { continue }
        guard pollResult >= 0 else { throw UpdateSecurityError.installFailed }
        if pollResult == 0 { continue }
        let count = Darwin.read(launch.healthDescriptor, &byte, 1)
        if count < 0, errno == EINTR { continue }
        guard count == 1 else { throw UpdateSecurityError.installFailed }
        frame.append(byte)
        if byte == 0x0a {
            let acknowledgement = try UpdatePostInstallHealthProtocol.parseAcknowledgement(frame)
            guard acknowledgement.0 == nonceHex,
                  acknowledgement.1 == launch.processIdentifier,
                  acknowledgement.2 == expected,
                  kill(launch.processIdentifier, 0) == 0 else {
                throw UpdateSecurityError.installFailed
            }
            closeCandidateLaunch(launch)
            return
        }
    }
    throw UpdateSecurityError.installFailed
}

do {
    _ = Darwin.signal(SIGPIPE, SIG_IGN)
    let arguments = CommandLine.arguments
    guard arguments.count == 8,
          arguments[7] == UpdateHelperReadinessProtocol.argument,
          let parentPID = Int32(arguments[4]),
          parentPID > 1,
          getppid() == parentPID,
          getpgrp() == getpid() else {
        throw UpdateSecurityError.invalidPath
    }
    let current = try standardizedAbsoluteURL(arguments[1], directory: true)
    let staged = try standardizedAbsoluteURL(arguments[2], directory: true)
    let backup = try standardizedAbsoluteURL(arguments[3], directory: true)
    let expectedCurrent = try SignedApplicationAttestation.decodeArgument(arguments[5])
    let expectedStaged = try SignedApplicationAttestation.decodeArgument(arguments[6])
    guard expectedCurrent.identifier == expectedStaged.identifier,
          expectedCurrent.teamIdentifier == expectedStaged.teamIdentifier,
          expectedStaged.build > expectedCurrent.build else {
        throw UpdateSecurityError.invalidAttestation
    }

    let fileManager = FileManager.default
    let updates = fileManager.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Local Harness/Updates", isDirectory: true)
        .standardizedFileURL
    let journalStore = UpdateInstallJournalStore(updatesRoot: updates)

    // Fail fast while the parent is still alive, then repeat every security
    // check after it exits. The early result is never trusted for installation.
    try UpdateApplicationSecurity.requireCanonical(current)
    try UpdateApplicationSecurity.validatePrivateStagedPath(staged, updatesRoot: updates)
    try UpdateApplicationSecurity.preparePrivateBackupPath(backup, updatesRoot: updates)
    _ = try UpdateApplicationSecurity.stableValidatedApplication(at: current, expected: expectedCurrent)
    _ = try UpdateApplicationSecurity.stableValidatedApplication(at: staged, expected: expectedStaged)
    try journalStore.requireNoPendingTransaction()

    // This is the sole successful readiness boundary. Everything above can
    // fail while the app remains alive; everything below starts by waiting for
    // that exact parent to exit and then repeats all security validation.
    try emitReadiness()

    let transactionID = UUID()
    var candidateLaunch: CandidateLaunch?
    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: { try waitForExit(parentPID) },
        validateCurrent: {
            try UpdateApplicationSecurity.requireCanonical(current)
            return try UpdateApplicationSecurity.stableValidatedApplication(
                at: current,
                expected: expectedCurrent
            )
        },
        validateStaged: {
            try UpdateApplicationSecurity.validatePrivateStagedPath(staged, updatesRoot: updates)
            return try UpdateApplicationSecurity.stableValidatedApplication(
                at: staged,
                expected: expectedStaged
            )
        },
        prepareBackup: {
            try UpdateApplicationSecurity.preparePrivateBackupPath(backup, updatesRoot: updates)
        },
        createNonce: { try UpdateInstallJournalStore.secureNonceHex() },
        beginJournal: { oldApplication, candidateApplication, nonceHex in
            try journalStore.create(UpdateInstallJournalRecord(
                transactionID: transactionID,
                nonceHex: nonceHex,
                currentApplicationPath: current.path,
                stagedApplicationPath: staged.path,
                rollbackApplicationPath: backup.path,
                oldApplication: oldApplication,
                candidateApplication: candidateApplication
            ))
        },
        persistJournalPhase: { phase in
            _ = try journalStore.transition(expectedTransactionID: transactionID, to: phase)
        },
        retireJournal: {
            try journalStore.retire(expectedTransactionID: transactionID)
        },
        moveCurrentToBackup: {
            _ = try UpdateApplicationSecurity.stableValidatedApplication(
                at: current,
                expected: expectedCurrent
            )
            try fileManager.moveItem(at: current, to: backup)
        },
        validateBackup: {
            try UpdateApplicationSecurity.requireCanonical(backup)
            return try UpdateApplicationSecurity.stableValidatedApplication(
                at: backup,
                expected: expectedCurrent
            )
        },
        moveStagedToCurrent: {
            try UpdateApplicationSecurity.validatePrivateStagedPath(staged, updatesRoot: updates)
            _ = try UpdateApplicationSecurity.stableValidatedApplication(
                at: staged,
                expected: expectedStaged
            )
            try fileManager.moveItem(at: staged, to: current)
        },
        validateInstalled: {
            try UpdateApplicationSecurity.requireCanonical(current)
            return try UpdateApplicationSecurity.stableValidatedApplication(
                at: current,
                expected: expectedStaged
            )
        },
        removeInstalled: {
            try fileManager.removeItem(at: current)
        },
        restoreBackup: {
            _ = try UpdateApplicationSecurity.stableValidatedApplication(
                at: backup,
                expected: expectedCurrent
            )
            try fileManager.moveItem(at: backup, to: current)
        },
        validateRestored: {
            try UpdateApplicationSecurity.requireCanonical(current)
            return try UpdateApplicationSecurity.stableValidatedApplication(
                at: current,
                expected: expectedCurrent
            )
        },
        launchInstalled: { nonceHex in
            _ = try UpdateApplicationSecurity.stableValidatedApplication(
                at: current,
                expected: expectedStaged
            )
            let launched = try launchCandidate(
                current,
                expected: expectedStaged,
                nonceHex: nonceHex,
                fileManager: fileManager
            )
            candidateLaunch = launched
            return launched.processIdentifier
        },
        awaitInstalledHealth: { processIdentifier, nonceHex, candidate in
            guard let launched = candidateLaunch,
                  launched.processIdentifier == processIdentifier,
                  candidate.attestation == expectedStaged else {
                throw UpdateSecurityError.installFailed
            }
            try awaitCandidateHealth(
                launched,
                nonceHex: nonceHex,
                expected: expectedStaged
            )
        },
        stopInstalled: { processIdentifier in
            guard let launched = candidateLaunch,
                  launched.processIdentifier == processIdentifier else {
                throw UpdateSecurityError.rollbackFailed
            }
            try stopCandidate(launched)
            candidateLaunch = nil
        }
    )
    do {
        try UpdateInstallTransaction.execute(
            expectedCurrent: expectedCurrent,
            expectedStaged: expectedStaged,
            hooks: hooks
        )
        candidateLaunch = nil
        _ = UpdateApplicationSecurity.pruneAutomaticApplicationBackups(
            updatesRoot: updates,
            preserving: backup,
            teamIdentifier: expectedCurrent.teamIdentifier
        )
        try? UpdateApplicationSecurity.removeEmptyPrivateStagedOperation(
            stagedApplication: staged,
            updatesRoot: updates
        )
    } catch {
        let rollbackFailed = (error as? UpdateSecurityError) == .rollbackFailed
        if !rollbackFailed {
            try? UpdateApplicationSecurity.discardPrivateStagedOperation(
                stagedApplication: staged,
                updatesRoot: updates
            )
            if kill(parentPID, 0) != 0, errno == ESRCH,
               (try? UpdateApplicationSecurity.stableValidatedApplication(
                   at: current,
                   expected: expectedCurrent
               )) != nil {
                try? launchApplication(current, fileManager: fileManager)
            }
        }
        throw error
    }
} catch {
    fail("install rejected; no unverified update was launched")
}
