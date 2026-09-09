import Darwin
import Foundation
import Testing
@testable import LocalHarness

private let boundedInputTestEnvironment = [
    "HOME": "/private/tmp",
    "PATH": "/usr/bin:/bin",
    "LANG": "en_US.UTF-8"
]

private final class SpawnInitializationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var actionsDestroyedValue = 0
    private var attributesDestroyedValue = 0

    func actionsDestroyed() {
        lock.lock()
        actionsDestroyedValue += 1
        lock.unlock()
    }

    func attributesDestroyed() {
        lock.lock()
        attributesDestroyedValue += 1
        lock.unlock()
    }

    var counts: (Int, Int) {
        lock.lock()
        defer { lock.unlock() }
        return (actionsDestroyedValue, attributesDestroyedValue)
    }
}

private func addInheritedLockACL(at url: URL) throws {
    let result = try BoundedCredentialMigrationProcess.run(
        executable: URL(fileURLWithPath: "/bin/chmod"),
        arguments: ["+a", "everyone allow read", url.path],
        environment: boundedInputTestEnvironment,
        maximumStandardOutputBytes: 4 * 1_024,
        maximumStandardErrorBytes: 4 * 1_024,
        deadline: 2,
        terminationGrace: 0.05
    )
    guard result.exitStatus == 0, result.terminationSignal == nil, result.limit == nil else {
        throw CredentialMigrationProcessRunnerError.invalidConfiguration
    }
}

private struct InheritedMigrationLockFixture {
    let url: URL
    var descriptor: Int32
    let inheritance: CredentialMigrationInheritedDescriptor
}

private func inheritedMigrationTestRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("inherited-migration-lock-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return root
}

private func inheritedMigrationLock(in root: URL) throws -> InheritedMigrationLockFixture {
    let url = root.appendingPathComponent("migration.lock", isDirectory: false)
    try Data().write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, 0o600) == 0 else {
        throw CredentialMigrationProcessRunnerError.invalidConfiguration
    }
    let descriptor = Darwin.open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor > STDERR_FILENO else {
        if descriptor >= 0 { _ = Darwin.close(descriptor) }
        throw CredentialMigrationProcessRunnerError.invalidConfiguration
    }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
        _ = Darwin.close(descriptor)
        throw CredentialMigrationProcessRunnerError.invalidConfiguration
    }
    var metadata = stat()
    guard Darwin.fstat(descriptor, &metadata) == 0 else {
        _ = Darwin.close(descriptor)
        throw CredentialMigrationProcessRunnerError.invalidConfiguration
    }
    return InheritedMigrationLockFixture(
        url: url,
        descriptor: descriptor,
        inheritance: CredentialMigrationInheritedDescriptor(
            sourceDescriptor: descriptor,
            expectedDevice: UInt64(truncatingIfNeeded: metadata.st_dev),
            expectedInode: UInt64(truncatingIfNeeded: metadata.st_ino)
        )
    )
}

private func contenderCanAcquireMigrationLock(at url: URL) -> Bool {
    let descriptor = Darwin.open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { return false }
    defer { _ = Darwin.close(descriptor) }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { return false }
    _ = flock(descriptor, LOCK_UN)
    return true
}

private func parentDescriptorsMatchingMigrationLock(
    _ inheritance: CredentialMigrationInheritedDescriptor
) -> [Int32] {
    var matches: [Int32] = []
    for descriptor in Int32(STDERR_FILENO + 1)...512 {
        var metadata = stat()
        if Darwin.fstat(descriptor, &metadata) == 0,
           UInt64(truncatingIfNeeded: metadata.st_dev) == inheritance.expectedDevice,
           UInt64(truncatingIfNeeded: metadata.st_ino) == inheritance.expectedInode {
            matches.append(descriptor)
        }
    }
    return matches
}

private func bundledMigrationNode() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("VendorRuntime/node-v22.23.1-darwin-arm64/bin/node")
}

private func credentialMigrationFDCollisionProbe() throws -> URL {
    var candidates: [URL] = []
    if let isolation = ProcessInfo.processInfo.environment[
        "LOCAL_HARNESS_SWIFT_TEST_ISOLATION_ROOT"
    ], isolation.hasPrefix("/tmp/fulmar-swift-tests.") {
        let root = URL(fileURLWithPath: isolation, isDirectory: true)
        candidates.append(
            root.appendingPathComponent(
                "build/arm64-apple-macosx/debug/CredentialMigrationFDCollisionProbe"
            )
        )
        candidates.append(
            root.appendingPathComponent("build/debug/CredentialMigrationFDCollisionProbe")
        )
    }
    for bundle in Bundle.allBundles where bundle.bundleURL.pathExtension == "xctest" {
        candidates.append(
            bundle.bundleURL.deletingLastPathComponent()
                .appendingPathComponent("CredentialMigrationFDCollisionProbe")
        )
    }
    candidates.append(
        Bundle.main.bundleURL.deletingLastPathComponent()
            .appendingPathComponent("CredentialMigrationFDCollisionProbe")
    )
    var cursor = URL(fileURLWithPath: CommandLine.arguments[0], isDirectory: false)
        .deletingLastPathComponent()
    for _ in 0..<8 {
        candidates.append(cursor.appendingPathComponent("CredentialMigrationFDCollisionProbe"))
        cursor.deleteLastPathComponent()
    }
    let project = URL(fileURLWithPath: #filePath, isDirectory: false)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    candidates.append(
        project.appendingPathComponent(
            ".build/arm64-apple-macosx/debug/CredentialMigrationFDCollisionProbe"
        )
    )
    candidates.append(
        project.appendingPathComponent(".build/debug/CredentialMigrationFDCollisionProbe")
    )

    for candidate in candidates {
        var metadata = stat()
        if Darwin.lstat(candidate.path, &metadata) == 0,
           metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
           metadata.st_uid == geteuid(),
           metadata.st_mode & 0o022 == 0,
           metadata.st_mode & 0o111 != 0,
           metadata.st_nlink == 1 {
            return candidate
        }
    }
    throw CredentialMigrationProcessRunnerError.invalidConfiguration
}

@Suite(.serialized)
struct BoundedCredentialMigrationProcessInputTests {
    @Test func partialSpawnInitializationDestroysActionsAndReturnsTheExactFailure() throws {
        let probe = SpawnInitializationProbe()
        var runnerPipeDescriptors: [Int32] = []
        let initialization = CredentialMigrationSpawnInitialization(
            initializeFileActions: { posix_spawn_file_actions_init($0) },
            destroyFileActions: {
                probe.actionsDestroyed()
                posix_spawn_file_actions_destroy($0)
            },
            initializeAttributes: { _ in ENOMEM },
            destroyAttributes: { _ in probe.attributesDestroyed() }
        )

        do {
            _ = try BoundedCredentialMigrationProcess.run(
                executable: URL(fileURLWithPath: "/usr/bin/true"),
                arguments: [],
                environment: boundedInputTestEnvironment,
                spawnInitialization: initialization,
                onPipeDescriptorsAllocated: { runnerPipeDescriptors = $0 }
            )
            Issue.record("Partial spawn initialization unexpectedly succeeded")
        } catch let error as CredentialMigrationProcessRunnerError {
            #expect(error == .spawnFailed(ENOMEM))
        }
        let counts = probe.counts
        #expect(counts.0 == 1)
        #expect(counts.1 == 0)
        #expect(runnerPipeDescriptors.count == 4)
        #expect(Set(runnerPipeDescriptors).count == runnerPipeDescriptors.count)
        for descriptor in runnerPipeDescriptors {
            errno = 0
            let flags = Darwin.fcntl(descriptor, F_GETFD)
            let failure = errno
            #expect(flags == -1)
            #expect(failure == EBADF)
        }
    }

    @Test func boundedDescriptorReadStopsAtTheDeclaredLimitPlusOne() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("growing-component")
        try Data(repeating: 0x61, count: 128 * 1_024).write(to: file)
        let descriptor = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        #expect(descriptor >= 0)
        defer { if descriptor >= 0 { _ = Darwin.close(descriptor) } }

        do {
            _ = try CredentialMigrationFileSecurity.boundedRead(
                descriptor: descriptor,
                maximumBytes: 64 * 1_024
            )
            Issue.record("An oversized descriptor unexpectedly passed its read bound")
        } catch let error as CredentialMigrationError {
            #expect(error == .componentsMissing)
        }
    }

    @Test func inheritedDescriptorWithExtendedACLIsRejectedBeforeSpawn() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 {
                _ = flock(fixture.descriptor, LOCK_UN)
                _ = Darwin.close(fixture.descriptor)
            }
        }
        try addInheritedLockACL(at: fixture.url)
        var spawned = false

        do {
            _ = try BoundedCredentialMigrationProcess.run(
                executable: URL(fileURLWithPath: "/usr/bin/true"),
                arguments: [],
                environment: boundedInputTestEnvironment,
                inheritedDescriptor: fixture.inheritance,
                onSpawn: { _ in spawned = true }
            )
            Issue.record("An ACL-bearing inherited descriptor unexpectedly spawned")
        } catch let error as CredentialMigrationProcessRunnerError {
            #expect(error == .invalidConfiguration)
        }
        #expect(!spawned)
    }

    @Test func deliversTheExactBinaryStandardInputWithoutTruncation() throws {
        let input = Data((0..<(384 * 1_024)).map { UInt8(truncatingIfNeeded: $0) })
        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/cat"),
            arguments: [],
            environment: boundedInputTestEnvironment,
            standardInput: input,
            maximumStandardOutputBytes: 1_048_576,
            maximumStandardErrorBytes: 1_024,
            deadline: 5
        )

        #expect(result.exitStatus == 0)
        #expect(result.terminationSignal == nil)
        #expect(result.limit == nil)
        #expect(result.standardOutput == input)
        #expect(result.standardError.isEmpty)
    }

    @Test func rejectsStandardInputLargerThanOneMiBBeforeSpawning() {
        let input = Data(repeating: 0x61, count: 1_048_577)
        do {
            _ = try BoundedCredentialMigrationProcess.run(
                executable: URL(fileURLWithPath: "/usr/bin/true"),
                arguments: [],
                environment: boundedInputTestEnvironment,
                standardInput: input
            )
            Issue.record("An oversized stdin payload was unexpectedly accepted")
        } catch let error as CredentialMigrationProcessRunnerError {
            #expect(error == .invalidConfiguration)
        } catch {
            Issue.record("Expected invalidConfiguration, got \(error)")
        }
    }

    @Test func drainsNoisyOutputAndErrorWhilePumpingLargeStandardInput() throws {
        let input = Data(repeating: 0x71, count: 600_000)
        let program = #"""
        print STDOUT "o" x 600000;
        print STDERR "e" x 600000;
        local $/;
        my $input = <STDIN>;
        print STDOUT length($input);
        """#
        let started = Date()
        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/usr/bin/perl"),
            arguments: ["-e", program],
            environment: boundedInputTestEnvironment,
            standardInput: input,
            maximumStandardOutputBytes: 1_048_576,
            maximumStandardErrorBytes: 1_048_576,
            deadline: 5
        )

        #expect(Date().timeIntervalSince(started) < 5)
        #expect(result.exitStatus == 0)
        #expect(result.terminationSignal == nil)
        #expect(result.limit == nil)
        #expect(result.standardOutput.count == 600_006)
        #expect(result.standardOutput.prefix(600_000) == Data(repeating: 0x6f, count: 600_000))
        #expect(result.standardOutput.suffix(6) == Data("600000".utf8))
        #expect(result.standardError == Data(repeating: 0x65, count: 600_000))
    }

    @Test func earlyChildExitClosesTheInputPipeWithoutKillingOrHangingTheCaller() throws {
        let started = Date()
        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", "exit 0"],
            environment: boundedInputTestEnvironment,
            standardInput: Data(repeating: 0x78, count: 1_048_576),
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 2,
            terminationGrace: 0.05
        )

        #expect(Date().timeIntervalSince(started) < 1)
        #expect(result.exitStatus == 0)
        #expect(result.terminationSignal == nil)
        #expect(result.limit == nil)
        #expect(result.standardOutput.isEmpty)
        #expect(result.standardError.isEmpty)
    }

    @Test func exactChildRetainsFlockAfterParentDescriptorClosesWithoutUnlock() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        var fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 { _ = Darwin.close(fixture.descriptor) }
        }
        var contenderWasBlocked = false

        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["0.25"],
            environment: boundedInputTestEnvironment,
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 2,
            inheritedDescriptor: fixture.inheritance,
            onSpawn: { _ in
                // This is the kernel-FD effect of app SIGKILL: close without
                // LOCK_UN. The exact child's duplicate must keep the same
                // open-file-description lock alive.
                #expect(Darwin.close(fixture.descriptor) == 0)
                fixture.descriptor = -1
                contenderWasBlocked = !contenderCanAcquireMigrationLock(at: fixture.url)
            }
        )

        #expect(contenderWasBlocked)
        #expect(result.exitStatus == 0)
        #expect(result.terminationSignal == nil)
        #expect(contenderCanAcquireMigrationLock(at: fixture.url))
    }

    @Test func deadlineKillsInheritedLockChildThenReleasesFlock() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        var fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 { _ = Darwin.close(fixture.descriptor) }
        }
        var contenderWasBlocked = false

        let result = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["30"],
            environment: boundedInputTestEnvironment,
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 0.1,
            terminationGrace: 0.05,
            inheritedDescriptor: fixture.inheritance,
            onSpawn: { _ in
                #expect(Darwin.close(fixture.descriptor) == 0)
                fixture.descriptor = -1
                contenderWasBlocked = !contenderCanAcquireMigrationLock(at: fixture.url)
            }
        )

        #expect(contenderWasBlocked)
        #expect(result.limit == .deadline(0.1))
        #expect(result.terminationSignal == SIGTERM || result.terminationSignal == SIGKILL)
        #expect(contenderCanAcquireMigrationLock(at: fixture.url))
    }

    @Test func spawnFailureCreatesNoLockHolderAndParentCloseReleasesFlock() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        var fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 { _ = Darwin.close(fixture.descriptor) }
        }
        let descriptorsBeforeSpawn = parentDescriptorsMatchingMigrationLock(fixture.inheritance)
        var spawned = false

        do {
            _ = try BoundedCredentialMigrationProcess.run(
                executable: root.appendingPathComponent("missing-executable"),
                arguments: [],
                environment: boundedInputTestEnvironment,
                inheritedDescriptor: fixture.inheritance,
                onSpawn: { _ in spawned = true }
            )
            Issue.record("A missing executable unexpectedly spawned")
        } catch let error as CredentialMigrationProcessRunnerError {
            guard case .spawnFailed = error else {
                Issue.record("Expected spawnFailed, got \(error)")
                return
            }
        }
        #expect(!spawned)
        #expect(parentDescriptorsMatchingMigrationLock(fixture.inheritance)
            == descriptorsBeforeSpawn)
        #expect(!contenderCanAcquireMigrationLock(at: fixture.url))
        #expect(Darwin.close(fixture.descriptor) == 0)
        fixture.descriptor = -1
        #expect(contenderCanAcquireMigrationLock(at: fixture.url))
    }

    @Test func bundledNodeRetainsTheExactInheritedDescriptor() throws {
        let node = bundledMigrationNode()
        guard FileManager.default.isExecutableFile(atPath: node.path) else {
            Issue.record("The bundled migration Node executable is missing: \(node.path)")
            return
        }
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        var fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 { _ = Darwin.close(fixture.descriptor) }
        }
        var contenderWasBlocked = false
        let program = #"""
        const fs = require("node:fs");
        const descriptor = Number(process.argv[1]);
        const info = fs.fstatSync(descriptor, { bigint: true });
        if (!info.isFile()) process.exit(9);
        const inherited = fs.readdirSync("/dev/fd").filter((name) => {
          if (!/^\d+$/.test(name)) return false;
          try {
            const candidate = fs.fstatSync(Number(name), { bigint: true });
            return candidate.dev === info.dev && candidate.ino === info.ino;
          } catch { return false; }
        });
        if (inherited.length !== 1 || Number(inherited[0]) !== descriptor) process.exit(10);
        process.stdout.write("inherited-lock-ok");
        setTimeout(() => {}, 250);
        """#

        let result = try BoundedCredentialMigrationProcess.run(
            executable: node,
            arguments: ["-e", program, String(CredentialMigrationInheritedDescriptor.fixedChildDescriptor)],
            environment: boundedInputTestEnvironment,
            maximumStandardOutputBytes: 1_024,
            maximumStandardErrorBytes: 1_024,
            deadline: 2,
            inheritedDescriptor: fixture.inheritance,
            onSpawn: { _ in
                #expect(Darwin.close(fixture.descriptor) == 0)
                fixture.descriptor = -1
                contenderWasBlocked = !contenderCanAcquireMigrationLock(at: fixture.url)
            }
        )

        #expect(contenderWasBlocked)
        #expect(result.exitStatus == 0)
        #expect(result.standardOutput == Data("inherited-lock-ok".utf8))
        #expect(result.standardError.isEmpty)
        #expect(contenderCanAcquireMigrationLock(at: fixture.url))
    }

    @Test func inheritedMappingDoesNotClearParentCLOEXECOrReachUnrelatedChild() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 {
                _ = flock(fixture.descriptor, LOCK_UN)
                _ = Darwin.close(fixture.descriptor)
            }
        }

        var descriptorsVisibleAtSpawn: [Int32] = []
        let exact = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/usr/bin/true"),
            arguments: [],
            environment: boundedInputTestEnvironment,
            inheritedDescriptor: fixture.inheritance,
            onSpawn: { _ in
                descriptorsVisibleAtSpawn = parentDescriptorsMatchingMigrationLock(
                    fixture.inheritance
                )
            }
        )
        #expect(exact.exitStatus == 0)
        #expect(descriptorsVisibleAtSpawn == [fixture.descriptor])
        let parentFlags = fcntl(fixture.descriptor, F_GETFD)
        #expect(parentFlags >= 0)
        #expect(parentFlags & FD_CLOEXEC != 0)

        let unrelated = try BoundedCredentialMigrationProcess.run(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: [
                "-c",
                "test ! -e /dev/fd/$1",
                "unrelated-child",
                String(fixture.descriptor)
            ],
            environment: boundedInputTestEnvironment
        )
        #expect(unrelated.exitStatus == 0)
        #expect(!contenderCanAcquireMigrationLock(at: fixture.url))
    }

    @Test func sourceCollisionAtFixedChildDescriptorUsesAndCleansATemporaryDuplicate() throws {
        let probe = try credentialMigrationFDCollisionProbe()
        let result = try BoundedCredentialMigrationProcess.run(
            executable: probe,
            arguments: [],
            environment: boundedInputTestEnvironment,
            maximumStandardOutputBytes: 4 * 1_024,
            maximumStandardErrorBytes: 16 * 1_024,
            deadline: 5,
            terminationGrace: 0.1
        )
        let diagnostics = String(decoding: result.standardError, as: UTF8.self)
        guard result.exitStatus == 0,
              result.terminationSignal == nil,
              result.limit == nil else {
            Issue.record(
                "The isolated fd-198 collision probe failed: exit=\(String(describing: result.exitStatus)), signal=\(String(describing: result.terminationSignal)), limit=\(String(describing: result.limit)); \(diagnostics)"
            )
            return
        }
        #expect(result.standardOutput == Data("FULMAR_FD_198_COLLISION_OK\n".utf8))
        #expect(result.standardError.isEmpty)
    }

    @Test func invalidInheritedSourceAndTargetFailBeforeSpawn() throws {
        let root = try inheritedMigrationTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try inheritedMigrationLock(in: root)
        defer {
            if fixture.descriptor >= 0 {
                _ = flock(fixture.descriptor, LOCK_UN)
                _ = Darwin.close(fixture.descriptor)
            }
        }
        let invalidCases = [
            CredentialMigrationInheritedDescriptor(
                sourceDescriptor: -1,
                expectedDevice: fixture.inheritance.expectedDevice,
                expectedInode: fixture.inheritance.expectedInode
            ),
            CredentialMigrationInheritedDescriptor(
                sourceDescriptor: fixture.descriptor,
                childDescriptor: CredentialMigrationInheritedDescriptor.fixedChildDescriptor - 1,
                expectedDevice: fixture.inheritance.expectedDevice,
                expectedInode: fixture.inheritance.expectedInode
            )
        ]

        for inherited in invalidCases {
            var spawned = false
            do {
                _ = try BoundedCredentialMigrationProcess.run(
                    executable: URL(fileURLWithPath: "/usr/bin/true"),
                    arguments: [],
                    environment: boundedInputTestEnvironment,
                    inheritedDescriptor: inherited,
                    onSpawn: { _ in spawned = true }
                )
                Issue.record("Invalid inherited descriptor unexpectedly spawned")
            } catch let error as CredentialMigrationProcessRunnerError {
                #expect(error == .invalidConfiguration)
            }
            #expect(!spawned)
        }
        #expect(!contenderCanAcquireMigrationLock(at: fixture.url))
    }
}
