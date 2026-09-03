import Darwin
import Foundation
import Testing
@testable import LocalHarness

private final class BackupKeyClientProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedCommands: [[String]] = []
    private var storedDeadlines: [TimeInterval] = []

    func record(arguments: [String], deadline: TimeInterval) {
        lock.lock()
        storedCommands.append(arguments)
        storedDeadlines.append(deadline)
        lock.unlock()
    }

    var commands: [[String]] {
        lock.lock()
        defer { lock.unlock() }
        return storedCommands
    }

    var deadlines: [TimeInterval] {
        lock.lock()
        defer { lock.unlock() }
        return storedDeadlines
    }
}

private final class BackupIntegrityProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedCalls = 0
    var result = true

    func verify() -> Bool {
        lock.lock()
        storedCalls += 1
        let result = self.result
        lock.unlock()
        return result
    }

    var calls: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedCalls
    }
}

private func backupKeyResult(
    status: Int32? = 0,
    key: Data = Data(repeating: 0x71, count: 32),
    limit: CredentialMigrationProcessLimit? = nil
) -> CredentialMigrationProcessResult {
    CredentialMigrationProcessResult(
        exitStatus: status,
        terminationSignal: nil,
        standardOutput: key,
        standardError: Data(),
        limit: limit
    )
}

private func backupKeyClient(
    backgroundDeadline: TimeInterval = 0.25,
    foregroundDeadline: TimeInterval = 2,
    runner: @escaping StateBackupAuthenticationKeyClient.ProcessRunner
) -> StateBackupAuthenticationKeyClient {
    StateBackupAuthenticationKeyClient(
        componentLocator: {
            StateBackupAuthenticationKeyComponents(helper: URL(fileURLWithPath: "/usr/bin/true"))
        },
        backgroundDeadline: backgroundDeadline,
        foregroundDeadline: foregroundDeadline,
        processRunner: runner
    )
}

private func securedBackupKeyClient(
    components: StateBackupAuthenticationKeyComponents,
    integrityVerifier: @escaping StateBackupAuthenticationKeyClient.IntegrityVerifier = { true },
    runner: @escaping StateBackupAuthenticationKeyClient.ProcessRunner
) -> StateBackupAuthenticationKeyClient {
    StateBackupAuthenticationKeyClient(
        componentLocator: { components },
        integrityVerifier: integrityVerifier,
        backgroundDeadline: 0.25,
        foregroundDeadline: 2,
        processRunner: runner
    )
}

private func makeTrustedBackupHelperFixture() throws -> (directory: URL, helper: URL) {
    let directory = FileManager.default.temporaryDirectory.standardizedFileURL
        .appendingPathComponent("fulmar-backup-helper-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    #expect(chmod(directory.path, 0o700) == 0)
    let helper = directory.appendingPathComponent("LocalHarnessCredentialHelper")
    try Data("trusted-helper-v1".utf8).write(to: helper)
    #expect(chmod(helper.path, 0o700) == 0)
    return (directory, helper)
}

@Test func unattendedBackupKeyAccessUsesExactBoundedHelperCommandAndCachesOnlyValidKey() throws {
    let probe = BackupKeyClientProbe()
    let expected = Data(repeating: 0x41, count: 32)
    let client = backupKeyClient { _, arguments, _, outputLimit, errorLimit, deadline in
        probe.record(arguments: arguments, deadline: deadline)
        #expect(outputLimit == 32)
        #expect(errorLimit == 4 * 1_024)
        return backupKeyResult(key: expected)
    }

    #expect(try client.loadOrCreate() == expected)
    #expect(try client.loadOrCreate() == expected)
    #expect(probe.commands == [["backup-load-or-create"]])
    #expect(probe.deadlines == [0.25])
}

@Test func unattendedBackupKeyAuthorizationDenialIsTypedAndDoesNotRetryOrMutate() {
    let probe = BackupKeyClientProbe()
    let client = backupKeyClient { _, arguments, _, _, _, deadline in
        probe.record(arguments: arguments, deadline: deadline)
        return backupKeyResult(status: 5, key: Data())
    }

    do {
        _ = try client.loadOrCreate()
        Issue.record("Authorization denial was unexpectedly admitted")
    } catch let error as BackupError {
        guard case .authenticationAuthorizationRequired = error else {
            Issue.record("Expected a typed authorization-required result, got \(error)")
            return
        }
    } catch {
        Issue.record("Expected BackupError, got \(error)")
    }
    #expect(probe.commands == [["backup-load-or-create"]])
}

@Test func unattendedBackupKeyDeadlineIsTypedAndUsesTheConfiguredHardBound() {
    let probe = BackupKeyClientProbe()
    let client = backupKeyClient(backgroundDeadline: 0.05) { _, arguments, _, _, _, deadline in
        probe.record(arguments: arguments, deadline: deadline)
        return backupKeyResult(
            status: nil,
            key: Data(),
            limit: .deadline(deadline)
        )
    }

    do {
        _ = try client.loadOrCreate()
        Issue.record("A timed-out helper was unexpectedly admitted")
    } catch let error as BackupError {
        guard case .authenticationTimedOut = error else {
            Issue.record("Expected a typed timeout result, got \(error)")
            return
        }
    } catch {
        Issue.record("Expected BackupError, got \(error)")
    }
    #expect(probe.deadlines == [0.05])
}

@Test func foregroundAuthorizationIsASeparateBoundedReadAndCannotSilentlyReplaceCachedKey() throws {
    let probe = BackupKeyClientProbe()
    let unattended = Data(repeating: 0x51, count: 32)
    let authorized = Data(repeating: 0x52, count: 32)
    let client = backupKeyClient(foregroundDeadline: 7) { _, arguments, _, _, _, deadline in
        probe.record(arguments: arguments, deadline: deadline)
        return arguments == ["backup-authorize-existing"]
            ? backupKeyResult(key: authorized)
            : backupKeyResult(key: unattended)
    }

    #expect(try client.loadOrCreate() == unattended)
    #expect(try client.authorizeExistingForForeground() == authorized)
    // Merely reading an interactively authorized candidate cannot retarget the
    // process cache. StateBackupManager admits it only after catalog validation.
    #expect(try client.loadOrCreate() == unattended)
    client.admitValidatedKey(authorized)
    #expect(try client.loadOrCreate() == authorized)
    #expect(probe.commands == [["backup-load-or-create"], ["backup-authorize-existing"]])
    #expect(probe.deadlines == [0.25, 7])
}

@Test func malformedSuccessfulBackupKeyPayloadFailsClosedWithoutCaching() {
    let probe = BackupKeyClientProbe()
    let client = backupKeyClient { _, arguments, _, _, _, deadline in
        probe.record(arguments: arguments, deadline: deadline)
        return backupKeyResult(key: Data(repeating: 0x61, count: 31))
    }

    for _ in 0..<2 {
        do {
            _ = try client.loadOrCreate()
            Issue.record("A malformed key payload was unexpectedly admitted")
        } catch let error as BackupError {
            guard case .authenticationUnavailable = error else {
                Issue.record("Expected authenticationUnavailable, got \(error)")
                return
            }
        } catch {
            Issue.record("Expected BackupError, got \(error)")
        }
    }
    #expect(probe.commands.count == 2)
}

@Suite(.serialized)
struct StateBackupAuthenticationKeyIdentityTests {
    @Test func wrongDirectorySymlinkUnsafeModeEmptyAndOversizedHelperExecuteNothing() throws {
        enum FixtureKind: CaseIterable { case wrongDirectory, symlink, unsafeMode, empty, oversized }

        for kind in FixtureKind.allCases {
            let fixture = try makeTrustedBackupHelperFixture()
            defer { try? FileManager.default.removeItem(at: fixture.directory) }
            let helper = fixture.helper
            var requiredDirectory: URL? = fixture.directory
            switch kind {
            case .wrongDirectory:
                requiredDirectory = fixture.directory.appendingPathComponent("not-the-executable-directory")
            case .symlink:
                let target = fixture.directory.appendingPathComponent("trusted-target")
                try FileManager.default.moveItem(at: helper, to: target)
                try FileManager.default.createSymbolicLink(at: helper, withDestinationURL: target)
            case .unsafeMode:
                #expect(chmod(helper.path, 0o722) == 0)
            case .empty:
                try Data().write(to: helper)
                #expect(chmod(helper.path, 0o700) == 0)
            case .oversized:
                let handle = try FileHandle(forWritingTo: helper)
                try handle.truncate(atOffset: UInt64(64 * 1_024 * 1_024 + 1))
                try handle.close()
            }
            let probe = BackupKeyClientProbe()
            let client = securedBackupKeyClient(
                components: StateBackupAuthenticationKeyComponents(
                    helper: helper,
                    enforceIdentity: true,
                    requiredExecutableDirectory: requiredDirectory
                )
            ) { _, arguments, _, _, _, deadline in
                probe.record(arguments: arguments, deadline: deadline)
                return backupKeyResult()
            }

            #expect(throws: BackupError.self) {
                try client.loadOrCreate()
            }
            #expect(probe.commands.isEmpty)
        }
    }

    @Test func failedBundleIntegrityVerificationExecutesNothingAndCachesNothing() throws {
        let fixture = try makeTrustedBackupHelperFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let processProbe = BackupKeyClientProbe()
        let integrityProbe = BackupIntegrityProbe()
        integrityProbe.result = false
        let client = securedBackupKeyClient(
            components: StateBackupAuthenticationKeyComponents(
                helper: fixture.helper,
                enforceIdentity: true,
                requiredExecutableDirectory: fixture.directory,
                requiresBundleIntegrity: true
            ),
            integrityVerifier: { integrityProbe.verify() }
        ) { _, arguments, _, _, _, deadline in
            processProbe.record(arguments: arguments, deadline: deadline)
            return backupKeyResult()
        }

        for _ in 0..<2 {
            #expect(throws: BackupError.self) {
                try client.loadOrCreate()
            }
        }
        #expect(processProbe.commands.isEmpty)
        #expect(integrityProbe.calls == 2)
    }

    @Test func postRunInodeReplacementFailsClosedAndDoesNotPopulateCache() throws {
        let fixture = try makeTrustedBackupHelperFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let processProbe = BackupKeyClientProbe()
        let client = securedBackupKeyClient(
            components: StateBackupAuthenticationKeyComponents(
                helper: fixture.helper,
                enforceIdentity: true,
                requiredExecutableDirectory: fixture.directory
            )
        ) { _, arguments, _, _, _, deadline in
            processProbe.record(arguments: arguments, deadline: deadline)
            if processProbe.commands.count == 1 {
                try FileManager.default.removeItem(at: fixture.helper)
                try Data("replacement-helper".utf8).write(to: fixture.helper)
                #expect(chmod(fixture.helper.path, 0o700) == 0)
            }
            return backupKeyResult()
        }

        #expect(throws: BackupError.self) {
            try client.loadOrCreate()
        }
        #expect(try client.loadOrCreate() == Data(repeating: 0x71, count: 32))
        #expect(processProbe.commands.count == 2)
    }

    @Test func postRunSameInodeContentReplacementFailsClosedAndDoesNotPopulateCache() throws {
        let fixture = try makeTrustedBackupHelperFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var initial = stat()
        #expect(lstat(fixture.helper.path, &initial) == 0)
        let processProbe = BackupKeyClientProbe()
        let client = securedBackupKeyClient(
            components: StateBackupAuthenticationKeyComponents(
                helper: fixture.helper,
                enforceIdentity: true,
                requiredExecutableDirectory: fixture.directory
            )
        ) { _, arguments, _, _, _, deadline in
            processProbe.record(arguments: arguments, deadline: deadline)
            if processProbe.commands.count == 1 {
                let handle = try FileHandle(forWritingTo: fixture.helper)
                try handle.truncate(atOffset: 0)
                try handle.write(contentsOf: Data("tampered-same-inode".utf8))
                try handle.synchronize()
                try handle.close()
            }
            return backupKeyResult()
        }

        #expect(throws: BackupError.self) {
            try client.loadOrCreate()
        }
        var replaced = stat()
        #expect(lstat(fixture.helper.path, &replaced) == 0)
        #expect(initial.st_dev == replaced.st_dev)
        #expect(initial.st_ino == replaced.st_ino)
        #expect(try client.loadOrCreate() == Data(repeating: 0x71, count: 32))
        #expect(processProbe.commands.count == 2)
    }
}
