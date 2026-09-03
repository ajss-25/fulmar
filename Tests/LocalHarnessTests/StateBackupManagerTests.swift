import Darwin
import Foundation
import Testing
@_spi(Testing) import LocalHarnessDeviceAttestation
@testable import LocalHarness

private enum InjectedBackupFailure: Error {
    case stop
}

private enum StateBackupACLFixtureError: Error {
    case chmodFailed(Int32)
}

private func addStateBackupExtendedACL(to url: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "everyone allow read", url.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 2),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        if process.isRunning { process.terminate() }
        throw StateBackupACLFixtureError.chmodFailed(process.terminationStatus)
    }
}

private enum BackupFailureMode {
    case ordinary
    case processLoss
}

private final class BackupFailureScript: @unchecked Sendable {
    private let lock = NSLock()
    private let points: Set<StateBackupFailurePoint>
    private let mode: BackupFailureMode

    init(
        _ points: Set<StateBackupFailurePoint>,
        mode: BackupFailureMode = .ordinary
    ) {
        self.points = points
        self.mode = mode
    }

    func inject(_ point: StateBackupFailurePoint) throws {
        lock.lock()
        defer { lock.unlock() }
        guard points.contains(point) else { return }
        switch mode {
        case .ordinary: throw InjectedBackupFailure.stop
        case .processLoss: throw StateBackupSimulatedProcessLoss.terminate
        }
    }
}

private final class BackupDescriptorMutation: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    private let target: StateBackupFailurePoint
    private let body: @Sendable () throws -> Void

    init(
        target: StateBackupFailurePoint,
        body: @escaping @Sendable () throws -> Void
    ) {
        self.target = target
        self.body = body
    }

    func run(_ point: StateBackupFailurePoint) throws {
        lock.lock()
        guard point == target, !fired else {
            lock.unlock()
            return
        }
        do {
            try body()
            fired = true
            lock.unlock()
        } catch {
            lock.unlock()
            throw error
        }
    }
}

private struct BackupFixture {
    let root: URL
    let source: URL
    let support: URL
    let backups: URL

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        source = root.appendingPathComponent("state", isDirectory: true)
        support = root.appendingPathComponent("support", isDirectory: true)
        backups = root.appendingPathComponent("backups", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try writeCurrentProviderHistoryPrivacyReceipt(at: source)
        try FileManager.default.createDirectory(
            at: backups,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    func manager(
        key: UInt8 = 0x51,
        failureScript: BackupFailureScript? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        makeUUID: @escaping @Sendable () -> UUID = { UUID() },
        monotonicNow: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        limits: StateBackupLimits = .production,
        failureInjector: @escaping @Sendable (StateBackupFailurePoint) throws -> Void = { _ in }
    ) -> StateBackupManager {
        StateBackupManager(
            applicationSupport: support,
            sourceState: source,
            backupRoot: backups,
            authenticationKey: Data(repeating: key, count: 32),
            now: now,
            makeUUID: makeUUID,
            monotonicNow: monotonicNow,
            limits: limits,
            failureInjector: { point in
                try failureScript?.inject(point)
                try failureInjector(point)
            },
            allowUnattestedHarnessHomeForTesting: true
        )
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private struct AttestedBackupFixture {
    let root: URL
    let support: URL
    let home: URL
    let keyStore: LocalHarnessTestDeviceAttestationKeyStore
    let homeCapability: HarnessHomeAttestationCapability

    init() throws {
        guard let account = getpwuid(geteuid()),
              let homePointer = account.pointee.pw_dir else {
            throw CocoaError(.fileNoSuchFile)
        }
        let caches = URL(fileURLWithPath: String(cString: homePointer), isDirectory: true)
            .appendingPathComponent("Library/Caches", isDirectory: true)
        let candidateRoot = caches.appendingPathComponent(
            "attested-backup-\(UUID().uuidString)",
            isDirectory: true
        )
        let candidateSupport = candidateRoot.appendingPathComponent(
            "Application Support",
            isDirectory: true
        )
        let candidateHome = candidateRoot.appendingPathComponent("HarnessHome", isDirectory: true)
        let candidateKeyStore = LocalHarnessTestDeviceAttestationKeyStore()
        let candidateHomeCapability: HarnessHomeAttestationCapability
        do {
            try FileManager.default.createDirectory(
                at: candidateSupport,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.createDirectory(
                at: candidateHome,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateRoot.path
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateSupport.path
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateHome.path
            )
            try writeCurrentProviderHistoryPrivacyReceipt(at: candidateHome)
            let authority = try ProviderHistoryDeviceAttestation.openForeground(
                applicationSupport: candidateSupport,
                keyStore: candidateKeyStore
            )
            candidateHomeCapability = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: candidateHome,
                receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current)
            )
        } catch {
            try? FileManager.default.removeItem(at: candidateRoot)
            throw error
        }
        root = candidateRoot
        support = candidateSupport
        home = candidateHome
        keyStore = candidateKeyStore
        homeCapability = candidateHomeCapability
    }

    func manager(
        failureInjector: @escaping @Sendable (StateBackupFailurePoint) throws -> Void = { _ in }
    ) -> StateBackupManager {
        StateBackupManager(
            applicationSupport: support,
            sourceState: home,
            authenticationKey: Data(repeating: 0x73, count: 32),
            failureInjector: failureInjector,
            harnessHomeCapabilityProvider: { homeCapability },
            attestationKeyStore: keyStore
        )
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

@Test func stateBackupAuthenticatesFilesAndPreservesCurrentSecretsOnRestore() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try FileManager.default.createDirectory(at: fixture.source.appendingPathComponent("profiles"), withIntermediateDirectories: true)
    try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    try Data("old-secret".utf8).write(to: fixture.source.appendingPathComponent(".credentials.yaml"))
    try Data("old-env".utf8).write(to: fixture.source.appendingPathComponent("profiles/.env"))

    let manager = fixture.manager()
    let backup = try manager.create(label: " Manual\nBackup ", sourceVersion: " 1.0\t")
    #expect(backup.label == "ManualBackup")
    #expect(backup.sourceVersion == "1.0")
    #expect(FileManager.default.fileExists(atPath: URL(fileURLWithPath: backup.path).appendingPathComponent("session.json").path))
    #expect(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: backup.path).appendingPathComponent(".credentials.yaml").path))

    try Data("new-state".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    try Data("current-secret".utf8).write(to: fixture.source.appendingPathComponent(".credentials.yaml"), options: .atomic)
    try Data("current-env".utf8).write(to: fixture.source.appendingPathComponent("profiles/.env"), options: .atomic)
    let report = try manager.restore(backup)

    #expect(try String(contentsOf: fixture.source.appendingPathComponent("session.json"), encoding: .utf8) == "snapshot")
    #expect(try String(contentsOf: fixture.source.appendingPathComponent(".credentials.yaml"), encoding: .utf8) == "current-secret")
    #expect(try String(contentsOf: fixture.source.appendingPathComponent("profiles/.env"), encoding: .utf8) == "current-env")
    let quarantine = try #require(report.quarantineURL)
    #expect(FileManager.default.fileExists(atPath: quarantine.path))
    #expect(try String(contentsOf: quarantine.appendingPathComponent("session.json"), encoding: .utf8) == "new-state")
}

@Test func stateBackupRejectsSourceSymlinksWithoutReadingTheirTarget() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let external = fixture.root.appendingPathComponent("outside-secret")
    try Data("do-not-copy".utf8).write(to: external)
    try FileManager.default.createSymbolicLink(
        at: fixture.source.appendingPathComponent("linked.txt"),
        withDestinationURL: external
    )
    let manager = fixture.manager()
    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "unsafe", sourceVersion: "1")
    }
    #expect(try manager.list().isEmpty)
    let children = (try? FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)) ?? []
    #expect(!children.contains { $0.hasPrefix(".creating-") })
}

@Test func stateBackupRejectsExtendedACLsOnSourceAndNamespaceDescriptors() throws {
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        let session = fixture.source.appendingPathComponent("session.json")
        try Data("private-session".utf8).write(to: session)
        try addStateBackupExtendedACL(to: session)

        #expect(throws: BackupError.self) {
            _ = try fixture.manager().create(label: "source-acl", sourceVersion: "1")
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path).isEmpty)
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        try Data("private-session".utf8).write(
            to: fixture.source.appendingPathComponent("session.json")
        )
        let manager = fixture.manager()
        try addStateBackupExtendedACL(to: fixture.backups)

        #expect(throws: BackupError.self) {
            _ = try manager.create(label: "namespace-acl", sourceVersion: "1")
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path).isEmpty)
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        try Data("private-session".utf8).write(
            to: fixture.source.appendingPathComponent("session.json")
        )
        let receipt = fixture.source.appendingPathComponent(
            ProviderHistoryPrivacyEpoch.ownershipReceiptName
        )
        let mutation = BackupDescriptorMutation(target: .afterStagedBackupCopy) {
            try addStateBackupExtendedACL(to: receipt)
        }

        #expect(throws: BackupError.self) {
            _ = try fixture.manager(failureInjector: { try mutation.run($0) })
                .create(label: "receipt-acl", sourceVersion: "1")
        }
        let entries = try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)
        #expect(entries.allSatisfy { UUID(uuidString: $0) == nil })
    }
}

@Test func stateBackupRejectsInvisiblePathNamesAndNeverPresentsRawPathDiagnostics() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let hostileName = "api_key=sk-backup-secret-123456789\u{202E}\u{0007}.txt"
    try Data("do-not-copy".utf8).write(to: fixture.source.appendingPathComponent(hostileName))

    #expect(throws: BackupError.self) {
        _ = try fixture.manager().create(label: "unsafe-name", sourceVersion: "1")
    }
    #expect(try fixture.manager().list().isEmpty)

    let presentations = [
        BackupError.unsafeSymbolicLink(relativePath: hostileName).localizedDescription,
        BackupError.unsupportedFilesystemItem(relativePath: hostileName).localizedDescription,
        BackupError.sourceChanged(relativePath: hostileName).localizedDescription
    ]
    for message in presentations {
        #expect(!message.contains("sk-backup-secret"))
        #expect(!message.contains("\u{202E}"))
        #expect(!message.contains("\u{0007}"))
        #expect(message.count < 300)
    }
}

@Test func stateBackupRejectsHardLinkedSourceAliases() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let outside = fixture.root.appendingPathComponent("outside-secret")
    try Data("do-not-copy".utf8).write(to: outside)
    try FileManager.default.linkItem(at: outside, to: fixture.source.appendingPathComponent("innocent.txt"))
    let manager = fixture.manager()

    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "unsafe", sourceVersion: "1")
    }
    #expect(try manager.list().isEmpty)
}

@Test func stateBackupContentTamperingFailsBeforeLiveStateMutation() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "trusted", sourceVersion: "1")
    try Data("tampered".utf8).write(
        to: URL(fileURLWithPath: backup.path).appendingPathComponent("session.json"),
        options: .atomic
    )
    try Data("live".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)

    #expect(throws: BackupError.self) { _ = try manager.restore(backup) }
    #expect(try String(contentsOf: fixture.source.appendingPathComponent("session.json"), encoding: .utf8) == "live")
}

@Test func stateBackupManifestTamperingInvalidatesCatalogAndRestore() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "trusted", sourceVersion: "1")
    let manifest = URL(fileURLWithPath: backup.path).deletingLastPathComponent().appendingPathComponent("manifest.json")
    var bytes = try Data(contentsOf: manifest)
    bytes[bytes.startIndex] ^= 0x01
    try bytes.write(to: manifest, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifest.path)

    #expect(throws: BackupError.self) { _ = try manager.list() }
    #expect(throws: BackupError.self) { _ = try manager.validatedList() }
    #expect(throws: BackupError.self) { _ = try manager.restore(backup) }
}

@Test func stateBackupCatalogTamperingFailsClosed() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "trusted", sourceVersion: "1")
    let catalog = fixture.backups.appendingPathComponent("catalog.json")
    var bytes = try Data(contentsOf: catalog)
    bytes[bytes.index(before: bytes.endIndex)] ^= 0x01
    try bytes.write(to: catalog, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: catalog.path)

    #expect(throws: BackupError.self) { _ = try manager.list() }
    #expect(throws: BackupError.self) { _ = try manager.validatedList() }
    #expect(manager.backup(id: backup.id) == nil)
    #expect(throws: BackupError.self) { _ = try manager.restore(backup) }
}

@Test func stateBackupWrongAuthenticationKeyCannotListOrRestore() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let original = fixture.manager(key: 0x31)
    let backup = try original.create(label: "trusted", sourceVersion: "1")
    let wrongKey = fixture.manager(key: 0x32)
    #expect(throws: BackupError.self) { _ = try wrongKey.list() }
    #expect(throws: BackupError.self) { _ = try wrongKey.restore(backup) }
}

@Test func stateBackupPublicationFailureLeavesNoPartialBackup() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let script = BackupFailureScript([.beforeBackupPublication])
    let manager = fixture.manager(failureScript: script)

    #expect(throws: InjectedBackupFailure.self) {
        _ = try manager.create(label: "will fail", sourceVersion: "1")
    }
    #expect(try manager.list().isEmpty)
    let children = try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)
    #expect(!children.contains { $0.hasPrefix(".creating-") })
    #expect(!children.contains { UUID(uuidString: $0) != nil })
}

@Test func stateBackupRestoreFailureRollsBackOriginalState() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let creator = fixture.manager()
    let backup = try creator.create(label: "trusted", sourceVersion: "1")
    try Data("live".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    let script = BackupFailureScript([.afterSourceQuarantined])
    let restorer = fixture.manager(failureScript: script)

    #expect(throws: BackupError.self) { _ = try restorer.restore(backup) }
    #expect(try String(contentsOf: fixture.source.appendingPathComponent("session.json"), encoding: .utf8) == "live")
    let recoveryRoot = fixture.root.appendingPathComponent(".local-harness-state-recovery")
    let children = (try? FileManager.default.contentsOfDirectory(atPath: recoveryRoot.path)) ?? []
    #expect(children.isEmpty)
}

@Test func stateBackupFailuresAfterActivationStillRollbackOriginalState() throws {
    for point in [StateBackupFailurePoint.afterReplacementActivated, .beforeRestoreFinalization] {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
        let backup = try fixture.manager().create(label: "trusted", sourceVersion: "1")
        try Data("live".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
        let restorer = fixture.manager(failureScript: BackupFailureScript([point]))

        #expect(throws: BackupError.self) { _ = try restorer.restore(backup) }
        #expect(try String(contentsOf: fixture.source.appendingPathComponent("session.json"), encoding: .utf8) == "live")
        let recoveryRoot = fixture.root.appendingPathComponent(".local-harness-state-recovery")
        let children = (try? FileManager.default.contentsOfDirectory(atPath: recoveryRoot.path)) ?? []
        #expect(children.isEmpty)
    }
}

@Test func stateBackupRollbackFailurePreservesRecoveryMaterial() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let creator = fixture.manager()
    let backup = try creator.create(label: "trusted", sourceVersion: "1")
    try Data("live".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    let script = BackupFailureScript([.afterSourceQuarantined, .beforeRollback])
    let restorer = fixture.manager(failureScript: script)

    do {
        _ = try restorer.restore(backup)
        Issue.record("Expected rollback failure")
    } catch BackupError.rollbackFailed(let recovery, let staged) {
        #expect(FileManager.default.fileExists(atPath: recovery))
        #expect(FileManager.default.fileExists(atPath: staged))
        #expect(try String(contentsOf: URL(fileURLWithPath: recovery).appendingPathComponent("session.json"), encoding: .utf8) == "live")
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func stateBackupRejectsSymlinkedBackupRoot() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let realRoot = fixture.root.appendingPathComponent("real-backups", isDirectory: true)
    try FileManager.default.createDirectory(at: realRoot, withIntermediateDirectories: true)
    try FileManager.default.removeItem(at: fixture.backups)
    try FileManager.default.createSymbolicLink(at: fixture.backups, withDestinationURL: realRoot)
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()

    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "unsafe", sourceVersion: "1")
    }
    #expect(throws: BackupError.self) { _ = try manager.list() }
}

@Test func stateBackupRejectsSymlinkedSourceRoot() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let realSource = fixture.root.appendingPathComponent("real-state", isDirectory: true)
    let linkedSource = fixture.root.appendingPathComponent("linked-state", isDirectory: true)
    try FileManager.default.createDirectory(at: realSource, withIntermediateDirectories: true)
    try Data("outside".utf8).write(to: realSource.appendingPathComponent("session.json"))
    try FileManager.default.createSymbolicLink(at: linkedSource, withDestinationURL: realSource)
    let manager = StateBackupManager(
        applicationSupport: fixture.support,
        sourceState: linkedSource,
        backupRoot: fixture.backups,
        authenticationKey: Data(repeating: 0x51, count: 32),
        allowUnattestedHarnessHomeForTesting: true
    )
    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "unsafe", sourceVersion: "1")
    }
}

@Test func stateBackupStorageAndPayloadAreOwnerOnly() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "trusted", sourceVersion: "1")
    let container = URL(fileURLWithPath: backup.path).deletingLastPathComponent()
    for url in [
        fixture.backups,
        fixture.backups.appendingPathComponent("catalog.json"),
        container,
        container.appendingPathComponent("manifest.json"),
        URL(fileURLWithPath: backup.path),
        URL(fileURLWithPath: backup.path).appendingPathComponent("session.json")
    ] {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let permissions = try #require((attributes[.posixPermissions] as? NSNumber)?.intValue)
        #expect(permissions & 0o077 == 0)
    }
}

@Test func stateBackupPreservesAndExplicitlyBlocksLegacyCatalogs() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try FileManager.default.createDirectory(at: fixture.backups, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.backups.path)
    let legacyID = UUID()
    let legacyDirectory = fixture.backups.appendingPathComponent(legacyID.uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: legacyDirectory, withIntermediateDirectories: true)
    let legacy = StateBackup(
        id: legacyID,
        createdAt: Date(timeIntervalSince1970: 1),
        label: "Unauthenticated legacy backup",
        sourceVersion: "1.0",
        path: legacyDirectory.path
    )
    // Encode exactly once: JSONEncoder key order is not deterministic across
    // encodes, and the invariant is byte-preservation of the written file.
    let legacyCatalogBytes = try JSONEncoder().encode([legacy])
    try legacyCatalogBytes.write(to: fixture.backups.appendingPathComponent("catalog.json"), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fixture.backups.appendingPathComponent("catalog.json").path)
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()

    #expect(try manager.privacyEpochPreflight() == .historical)
    do {
        _ = try manager.validatedList()
        Issue.record("Expected historical backup classification")
    } catch let error as BackupError {
        guard case .providerHistoryPrivacyMigrationRequired = error else {
            Issue.record("Unexpected backup error: \(error)")
            return
        }
    }
    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "must-not-link", sourceVersion: "2.0")
    }
    #expect(FileManager.default.fileExists(atPath: legacyDirectory.path))
    #expect(try Data(contentsOf: fixture.backups.appendingPathComponent("catalog.json"))
        == legacyCatalogBytes)
}

@Test func historicalProviderHomeBlocksBeforeBackupRootCreation() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("backup-privacy-source-\(UUID().uuidString)", isDirectory: true)
    let source = root.appendingPathComponent("state", isDirectory: true)
    let support = root.appendingPathComponent("support", isDirectory: true)
    let backups = root.appendingPathComponent("backups", isDirectory: true)
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    let historical: [String: Any] = [
        "version": 2,
        "migratedAt": 0.0,
        "copiedEntries": [String]()
    ]
    let receipt = source.appendingPathComponent(".local-harness-home.json")
    try JSONSerialization.data(withJSONObject: historical, options: [.sortedKeys]).write(to: receipt)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
    try Data("historical-session".utf8).write(to: source.appendingPathComponent("session.json"))
    defer { try? FileManager.default.removeItem(at: root) }

    let manager = StateBackupManager(
        applicationSupport: support,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 0x44, count: 32),
        allowUnattestedHarnessHomeForTesting: true
    )
    #expect(try manager.privacyEpochPreflight() == .absent)
    do {
        _ = try manager.create(label: "blocked", sourceVersion: "legacy")
        Issue.record("Expected privacy migration requirement")
    } catch let error as BackupError {
        guard case .providerHistoryPrivacyMigrationRequired = error else {
            Issue.record("Unexpected backup error: \(error)")
            return
        }
    }
    #expect(!FileManager.default.fileExists(atPath: backups.path))
    #expect(try String(contentsOf: source.appendingPathComponent("session.json"), encoding: .utf8)
        == "historical-session")
}

@Test func providerHistoryReceiptRejectsForgedRecoverySourceAndUnsortedSettings() throws {
    let cases: [[String: Any]] = [
        [
            "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
            "migratedAt": 0.0,
            "copiedEntries": ["settings.json"],
            "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current,
            "source": "/private/tmp/receiptless-00000000-0000-0000-0000-000000000000",
            "sourceKind": "historicalProviderState"
        ],
        [
            "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
            "migratedAt": 0.0,
            "copiedEntries": ["settings.yaml", "settings.json"],
            "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current
        ],
        [
            "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion + 1,
            "migratedAt": 0.0,
            "copiedEntries": [String](),
            "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current + 1
        ],
        [
            "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
            "migratedAt": true,
            "copiedEntries": [String](),
            "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current
        ]
    ]
    for object in cases {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-receipt-schema-\(UUID().uuidString)", isDirectory: true)
        let source = root.appendingPathComponent("HarnessHome", isDirectory: true)
        let backups = root.appendingPathComponent("backups", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        let receipt = source.appendingPathComponent(".local-harness-home.json")
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: receipt)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = StateBackupManager(
            applicationSupport: root,
            sourceState: source,
            backupRoot: backups,
            authenticationKey: Data(repeating: 0x45, count: 32),
            allowUnattestedHarnessHomeForTesting: true
        )
        do {
            _ = try manager.create(label: "blocked", sourceVersion: "legacy")
            Issue.record("Expected exact receipt rejection")
        } catch let error as BackupError {
            guard case .providerHistoryPrivacyMigrationRequired = error else {
                Issue.record("Unexpected backup error: \(error)")
                continue
            }
        }
        #expect(!FileManager.default.fileExists(atPath: backups.path))
    }
}

@Test func exactRecoveredProviderHistoryReceiptAdmitsSettingsOnlyBackup() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("backup-recovered-receipt-\(UUID().uuidString)", isDirectory: true)
    let source = root.appendingPathComponent("HarnessHome", isDirectory: true)
    let recovery = root.appendingPathComponent("HarnessHomeRecovery", isDirectory: true)
    let recoverySource = recovery.appendingPathComponent(
        "receiptless-\(UUID().uuidString.lowercased())",
        isDirectory: true
    )
    let backups = root.appendingPathComponent("backups", isDirectory: true)
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: recoverySource, withIntermediateDirectories: true)
    let receiptObject: [String: Any] = [
        "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
        "migratedAt": 0.0,
        "copiedEntries": ["settings.json", "settings.yaml"],
        "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current,
        "source": recoverySource.standardizedFileURL.path,
        "sourceKind": "historicalProviderState"
    ]
    let receipt = source.appendingPathComponent(".local-harness-home.json")
    try JSONSerialization.data(withJSONObject: receiptObject, options: [.sortedKeys]).write(to: receipt)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
    try Data("{}".utf8).write(to: source.appendingPathComponent("settings.json"))
    try Data("models: {}".utf8).write(to: source.appendingPathComponent("settings.yaml"))
    defer { try? FileManager.default.removeItem(at: root) }

    let manager = StateBackupManager(
        applicationSupport: root,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 0x46, count: 32),
        allowUnattestedHarnessHomeForTesting: true
    )
    let backup = try manager.create(label: "settings", sourceVersion: "4")
    #expect(FileManager.default.fileExists(
        atPath: URL(fileURLWithPath: backup.path).appendingPathComponent("settings.json").path
    ))
}

@Test func backupFormatFourBindsManifestCatalogAndTransactionsToPrivacyEpochOne() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("current".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let backup = try fixture.manager().create(label: "epoch", sourceVersion: "4")
    let container = URL(fileURLWithPath: backup.path).deletingLastPathComponent()

    for url in [
        fixture.backups.appendingPathComponent("catalog.json"),
        container.appendingPathComponent("manifest.json"),
        container.appendingPathComponent("receipt.json")
    ] {
        let object = try #require(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
        #expect(Set(object.keys) == ["payload", "authenticationTag"])
        let payload = try #require(object["payload"] as? [String: Any])
        #expect((payload["formatVersion"] as? NSNumber)?.intValue == 4)
        #expect((payload["providerHistoryPrivacyEpoch"] as? NSNumber)?.intValue
            == ProviderHistoryPrivacyEpoch.current)
    }
}

@Test func oldBackupJournalFailsTypedWithoutNamespaceMutation() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let journal = fixture.backups.appendingPathComponent(".backup-transaction.json")
    let bytes = try JSONSerialization.data(withJSONObject: [
        "payload": ["formatVersion": 1],
        "authenticationTag": Data(repeating: 0, count: 32).base64EncodedString()
    ], options: [.sortedKeys])
    try bytes.write(to: journal)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)

    do {
        _ = try fixture.manager().validatedList()
        Issue.record("Expected historical transaction classification")
    } catch let error as BackupError {
        guard case .providerHistoryPrivacyMigrationRequired = error else {
            Issue.record("Unexpected backup error: \(error)")
            return
        }
    }
    #expect(try Data(contentsOf: journal) == bytes)
}

@Test func futureBackupCatalogFailsClosedAndRemainsByteIdentical() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let catalog = fixture.backups.appendingPathComponent("catalog.json")
    let bytes = try JSONSerialization.data(withJSONObject: [
        "payload": [
            "formatVersion": 5,
            "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current + 1,
            "backups": [Any]()
        ],
        "authenticationTag": Data(repeating: 0, count: 32).base64EncodedString()
    ], options: [.sortedKeys])
    try bytes.write(to: catalog)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: catalog.path)

    #expect(try fixture.manager().privacyEpochPreflight() == .historical)
    #expect(try Data(contentsOf: catalog) == bytes)
}

@Test func orphanedBackupNamespaceIsHistoricalRatherThanAnEmptyCatalog() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let orphan = fixture.backups.appendingPathComponent(".creating-orphan", isDirectory: true)
    try FileManager.default.createDirectory(at: orphan, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: orphan.path)
    #expect(try fixture.manager().privacyEpochPreflight() == .historical)
    #expect(FileManager.default.fileExists(atPath: orphan.path))
}

@Test func restorePreservesHistoricalDestinationAndPerformsNoQuarantine() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "current", sourceVersion: "4")
    try Data("historical-live".utf8).write(
        to: fixture.source.appendingPathComponent("session.json"),
        options: .atomic
    )
    let historical: [String: Any] = [
        "version": 2,
        "migratedAt": 0.0,
        "copiedEntries": [String]()
    ]
    let receipt = fixture.source.appendingPathComponent(".local-harness-home.json")
    try JSONSerialization.data(withJSONObject: historical, options: [.sortedKeys])
        .write(to: receipt, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)

    do {
        _ = try manager.restore(backup)
        Issue.record("Expected destination privacy migration requirement")
    } catch let error as BackupError {
        guard case .providerHistoryPrivacyMigrationRequired = error else {
            Issue.record("Unexpected backup error: \(error)")
            return
        }
    }
    #expect(try String(contentsOf: fixture.source.appendingPathComponent("session.json"), encoding: .utf8)
        == "historical-live")
    #expect(!FileManager.default.fileExists(
        atPath: fixture.root.appendingPathComponent(".local-harness-state-recovery").path
    ))
}

@Test func stateBackupRejectsForgedMetadataPath() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "trusted", sourceVersion: "1")
    let forged = StateBackup(
        id: backup.id,
        createdAt: backup.createdAt,
        label: backup.label,
        sourceVersion: backup.sourceVersion,
        path: fixture.root.appendingPathComponent("outside").path
    )
    #expect(throws: BackupError.self) { _ = try manager.restore(forged) }
}

@Test func stateBackupRejectsExtraPayloadFilesAndLinks() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("trusted".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "trusted", sourceVersion: "1")
    let payload = URL(fileURLWithPath: backup.path)
    try Data("extra".utf8).write(to: payload.appendingPathComponent("unexpected.txt"))
    #expect(throws: BackupError.self) { _ = try manager.restore(backup) }
    try FileManager.default.removeItem(at: payload.appendingPathComponent("unexpected.txt"))
    try FileManager.default.createSymbolicLink(
        at: payload.appendingPathComponent("link"),
        withDestinationURL: fixture.source.appendingPathComponent("session.json")
    )
    #expect(throws: BackupError.self) { _ = try manager.restore(backup) }
}

private final class BackupDateSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var seconds: TimeInterval = 1

    func next() -> Date {
        lock.lock()
        defer {
            seconds += 1
            lock.unlock()
        }
        return Date(timeIntervalSince1970: seconds)
    }
}

private final class AdvancingBackupClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 0
    private let step: UInt64

    init(step: UInt64) { self.step = step }

    func now() -> UInt64 {
        lock.lock()
        defer {
            value &+= step
            lock.unlock()
        }
        return value
    }
}

private enum BackupPermitTestError: Error {
    case revoked
}

private final class BackupPermitGate: @unchecked Sendable {
    private let lock = NSLock()
    private var valid = true

    func revoke() {
        lock.lock()
        valid = false
        lock.unlock()
    }

    func validate() throws {
        lock.lock()
        let current = valid
        lock.unlock()
        if !current { throw BackupPermitTestError.revoked }
    }
}

@Test func stateBackupEmptyTreeIsAuthenticatedAndRestorable() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let manager = fixture.manager()
    let backup = try manager.create(label: "Empty", sourceVersion: "1")
    #expect(try manager.validatedList() == [backup])
    try Data("new".utf8).write(to: fixture.source.appendingPathComponent("later.txt"))
    _ = try manager.restore(backup)
    #expect(!FileManager.default.fileExists(atPath: fixture.source.appendingPathComponent("later.txt").path))
}

@Test func stateBackupCreateTransactionsRollForwardAfterEveryDurableCrashPhase() throws {
    let phases: [StateBackupFailurePoint] = [
        .afterBackupJournalDurable,
        .afterBackupPublished,
        .afterBackupCatalogCommitted,
        .afterRetentionApplied
    ]
    for phase in phases {
        let fixture = try BackupFixture()
        do {
            try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
            let script = BackupFailureScript([phase], mode: .processLoss)
            #expect(throws: StateBackupSimulatedProcessLoss.self) {
                _ = try fixture.manager(failureScript: script).create(label: "crash", sourceVersion: "1")
            }
            let relaunched = fixture.manager()
            let recovered = try relaunched.validatedList()
            #expect(recovered.count == 1)
            let backup = try #require(recovered.first)
            #expect(try String(
                contentsOf: URL(fileURLWithPath: backup.path).appendingPathComponent("session.json"),
                encoding: .utf8
            ) == "snapshot")
            let children = try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)
            #expect(!children.contains { $0.hasPrefix(".creating-") })
            #expect(!children.contains(".backup-transaction.json"))
        }
        fixture.cleanup()
    }
}

@Test func stateBackupDeleteTransactionsFinishAfterEveryDurableCrashPhase() throws {
    let phases: [StateBackupFailurePoint] = [
        .afterDeleteJournalDurable,
        .afterDeleteQuarantined,
        .afterDeleteCatalogCommitted,
        .afterDeleteFinalizationDurable
    ]
    for phase in phases {
        let fixture = try BackupFixture()
        do {
            try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
            let backup = try fixture.manager().create(label: "delete", sourceVersion: "1")
            let script = BackupFailureScript([phase], mode: .processLoss)
            #expect(throws: StateBackupSimulatedProcessLoss.self) {
                try fixture.manager(failureScript: script).delete(backup)
            }
            #expect(try fixture.manager().validatedList().isEmpty)
            let children = try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)
            #expect(!children.contains { $0.hasPrefix(".deleting-") })
            #expect(!children.contains(".backup-transaction.json"))
            #expect(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: backup.path).deletingLastPathComponent().path))
        }
        fixture.cleanup()
    }
}

@Test func stateBackupRestoreTransactionsRequireQuiescenceAndFinishAfterEveryCrashPhase() throws {
    let phases: [StateBackupFailurePoint] = [
        .afterRestoreJournalDurable,
        .afterSourceQuarantined,
        .afterReplacementActivated,
        .afterRestoreFinalizationDurable
    ]
    for phase in phases {
        let fixture = try BackupFixture()
        do {
            try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
            let backup = try fixture.manager().create(label: "restore", sourceVersion: "1")
            try Data("live".utf8).write(
                to: fixture.source.appendingPathComponent("session.json"),
                options: .atomic
            )
            let script = BackupFailureScript([phase], mode: .processLoss)
            #expect(throws: StateBackupSimulatedProcessLoss.self) {
                _ = try fixture.manager(failureScript: script).restore(backup)
            }
            let relaunched = fixture.manager()
            #expect(throws: BackupError.self) { _ = try relaunched.validatedList() }
            try relaunched.reconcilePendingTransactions(permit: .protectedStartup)
            #expect(try String(
                contentsOf: fixture.source.appendingPathComponent("session.json"),
                encoding: .utf8
            ) == "snapshot")
            #expect(try relaunched.validatedList() == [backup])
            let recoveryRoot = fixture.root.appendingPathComponent(".local-harness-state-recovery")
            let children = try FileManager.default.contentsOfDirectory(atPath: recoveryRoot.path)
            #expect(!children.contains(".restore-transaction.json"))
        }
        fixture.cleanup()
    }
}

@Test func stateBackupRetentionIsBoundedAndDeleteIsAuthenticated() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let dates = BackupDateSequence()
    var limits = StateBackupLimits.production
    limits.maximumBackupCount = 2
    limits.maximumCatalogEntries = 8
    let manager = fixture.manager(now: { dates.next() }, limits: limits)

    try Data("one".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let first = try manager.create(label: "one", sourceVersion: "1")
    try Data("two".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    let second = try manager.create(label: "two", sourceVersion: "1")
    try Data("three".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    let third = try manager.create(label: "three", sourceVersion: "1")

    #expect(try manager.validatedList() == [third, second])
    #expect(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: first.path).deletingLastPathComponent().path))
    let forged = StateBackup(
        id: second.id,
        createdAt: second.createdAt,
        label: "forged",
        sourceVersion: second.sourceVersion,
        path: second.path
    )
    #expect(throws: BackupError.self) { try manager.delete(forged) }
    #expect(try manager.validatedList() == [third, second])
    try manager.delete(second)
    #expect(try manager.validatedList() == [third])
}

@Test func stateBackupAggregateQuotaEvictsOldestAuthenticatedSnapshot() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let dates = BackupDateSequence()
    var limits = StateBackupLimits.production
    limits.maximumFileBytes = 10
    limits.maximumBackupBytes = 10
    // The operation budget also covers authenticated catalog, manifest, and
    // transaction-journal I/O. Keep that independent from the deliberately
    // tiny payload quota exercised by this test.
    limits.maximumOperationBytes = 1_024 * 1_024
    limits.maximumAggregateStoredBytes = 10
    limits.maximumBackupCount = 4
    limits.maximumCatalogEntries = 16
    let manager = fixture.manager(now: { dates.next() }, limits: limits)

    try Data("123456".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let first = try manager.create(label: "one", sourceVersion: "1")
    try Data("abcdef".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    let second = try manager.create(label: "two", sourceVersion: "1")
    #expect(try manager.validatedList() == [second])
    #expect(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: first.path).deletingLastPathComponent().path))
}

@Test func stateBackupRetentionCrashRemovesEvictedNamespaceOnRelaunch() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let dates = BackupDateSequence()
    var limits = StateBackupLimits.production
    limits.maximumBackupCount = 1
    limits.maximumCatalogEntries = 8
    try Data("one".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let first = try fixture.manager(now: { dates.next() }, limits: limits)
        .create(label: "one", sourceVersion: "1")
    try Data("two".utf8).write(to: fixture.source.appendingPathComponent("session.json"), options: .atomic)
    let script = BackupFailureScript([.afterBackupCatalogCommitted], mode: .processLoss)
    #expect(throws: StateBackupSimulatedProcessLoss.self) {
        _ = try fixture.manager(failureScript: script, now: { dates.next() }, limits: limits)
            .create(label: "two", sourceVersion: "1")
    }
    let recovered = try fixture.manager(limits: limits).validatedList()
    #expect(recovered.count == 1)
    #expect(recovered.first?.label == "two")
    #expect(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: first.path).deletingLastPathComponent().path))
}

@Test func stateBackupBoundsFilesTreesPathsCatalogsAndDeadline() throws {
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        var limits = StateBackupLimits.production
        limits.maximumFileBytes = 4
        limits.maximumBackupBytes = 4
        limits.maximumOperationBytes = 128
        limits.maximumAggregateStoredBytes = 8
        try Data("12345".utf8).write(to: fixture.source.appendingPathComponent("large.bin"))
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(limits: limits).create(label: "large", sourceVersion: "1")
        }
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        var limits = StateBackupLimits.production
        limits.maximumEntryCount = 2
        limits.maximumOperationEntries = 2
        for index in 0..<3 {
            try Data([UInt8(index)]).write(to: fixture.source.appendingPathComponent("f\(index)"))
        }
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(limits: limits).create(label: "wide", sourceVersion: "1")
        }
        let children = try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)
        #expect(!children.contains { $0.hasPrefix(".creating-") })
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        let nested = fixture.source.appendingPathComponent("a/b/c", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        var limits = StateBackupLimits.production
        limits.maximumDirectoryDepth = 2
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(limits: limits).create(label: "deep", sourceVersion: "1")
        }
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        try Data("x".utf8).write(to: fixture.source.appendingPathComponent("long-name"))
        var limits = StateBackupLimits.production
        limits.maximumRelativePathBytes = 8
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(limits: limits).create(label: "path", sourceVersion: "1")
        }
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        try Data("x".utf8).write(to: fixture.source.appendingPathComponent("file"))
        let clock = AdvancingBackupClock(step: 2_000_000)
        var limits = StateBackupLimits.production
        limits.operationDuration = 0.001
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(monotonicNow: { clock.now() }, limits: limits)
                .create(label: "deadline", sourceVersion: "1")
        }
    }
}

@Test func stateBackupCatalogEnumerationRejectsFloodSymlinkAndSpecialObject() throws {
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        var limits = StateBackupLimits.production
        limits.maximumCatalogEntries = 4
        limits.maximumBackupCount = 2
        let manager = fixture.manager(limits: limits)
        for _ in 0..<5 {
            let child = fixture.backups.appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: child.path)
        }
        #expect(throws: BackupError.self) { _ = try manager.validatedList() }
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        let manager = fixture.manager()
        let target = fixture.root.appendingPathComponent("target", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(
            at: fixture.backups.appendingPathComponent(UUID().uuidString),
            withDestinationURL: target
        )
        #expect(throws: BackupError.self) { _ = try manager.validatedList() }
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        let manager = fixture.manager()
        let fifo = fixture.backups.appendingPathComponent(UUID().uuidString)
        #expect(Darwin.mkfifo(fifo.path, 0o600) == 0)
        #expect(throws: BackupError.self) { _ = try manager.validatedList() }
    }
}

@Test func stateBackupCancellationAndStalePermitFailBeforePublication() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("snapshot".utf8).write(to: fixture.source.appendingPathComponent("session.json"))
    let cancellation = StateBackupOperationCancellation()
    cancellation.cancel()
    #expect(throws: BackupError.self) {
        _ = try fixture.manager().create(
            label: "cancelled",
            sourceVersion: "1",
            permit: .protectedStartup,
            cancellation: cancellation
        )
    }

    let gate = BackupPermitGate()
    let permit = StateBackupQuiescencePermit(validation: { try gate.validate() })
    let manager = fixture.manager(failureInjector: { point in
        if point == .afterStagedBackupCopy { gate.revoke() }
    })
    #expect(throws: BackupPermitTestError.self) {
        _ = try manager.create(label: "stale", sourceVersion: "1", permit: permit)
    }
    #expect(try manager.list().isEmpty)
    let children = try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path)
    #expect(!children.contains { $0.hasPrefix(".creating-") })
}

@Test func stateBackupRetainedRootDescriptorNeverWritesIntoAReplacementRoot() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    try Data("private-session".utf8).write(
        to: fixture.source.appendingPathComponent("session.json")
    )
    let displaced = fixture.root.appendingPathComponent("displaced-backups", isDirectory: true)
    let mutation = BackupDescriptorMutation(target: .afterStagedBackupCopy) {
        try FileManager.default.moveItem(at: fixture.backups, to: displaced)
        try FileManager.default.createDirectory(
            at: fixture.backups,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
    }
    let manager = fixture.manager(failureInjector: { try mutation.run($0) })

    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "swap", sourceVersion: "1")
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path).isEmpty)
    #expect(FileManager.default.fileExists(atPath: displaced.path))
}

@Test func stateBackupRestoreRejectsBackupRootDisplacementBeforeLiveMutation() throws {
    let fixture = try BackupFixture()
    defer { fixture.cleanup() }
    let session = fixture.source.appendingPathComponent("session.json")
    try Data("snapshot".utf8).write(to: session)
    let backup = try fixture.manager().create(label: "snapshot", sourceVersion: "1")
    try Data("live-must-remain".utf8).write(to: session, options: .atomic)
    let displaced = fixture.root.appendingPathComponent("displaced-restore-backups", isDirectory: true)
    let mutation = BackupDescriptorMutation(target: .afterRestoreStaging) {
        try FileManager.default.moveItem(at: fixture.backups, to: displaced)
        try FileManager.default.createDirectory(
            at: fixture.backups,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
    }

    #expect(throws: BackupError.self) {
        _ = try fixture.manager(failureInjector: { try mutation.run($0) }).restore(backup)
    }
    #expect(try String(contentsOf: session, encoding: .utf8) == "live-must-remain")
    #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.backups.path).isEmpty)
    #expect(FileManager.default.fileExists(atPath: displaced.path))
}

@Test func stateBackupRetainedSourceDescriptorsRejectDirectoryAndFileDisplacement() throws {
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        let directory = fixture.source.appendingPathComponent("nested", isDirectory: true)
        let displaced = fixture.source.appendingPathComponent("nested-original", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try Data("original-private".utf8).write(to: directory.appendingPathComponent("session.json"))
        let mutation = BackupDescriptorMutation(
            target: .afterSourceDirectoryOpened("nested")
        ) {
            try FileManager.default.moveItem(at: directory, to: displaced)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            try Data("replacement-must-not-copy".utf8).write(
                to: directory.appendingPathComponent("session.json")
            )
        }
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(failureInjector: { try mutation.run($0) })
                .create(label: "directory-swap", sourceVersion: "1")
        }
        #expect(try fixture.manager().validatedList().isEmpty)
        #expect(try String(
            contentsOf: directory.appendingPathComponent("session.json"),
            encoding: .utf8
        ) == "replacement-must-not-copy")
    }
    do {
        let fixture = try BackupFixture()
        defer { fixture.cleanup() }
        let file = fixture.source.appendingPathComponent("session.json")
        let displaced = fixture.source.appendingPathComponent("session-original.json")
        try Data("original-private".utf8).write(to: file)
        let mutation = BackupDescriptorMutation(
            target: .afterSourceFileOpened("session.json")
        ) {
            try FileManager.default.moveItem(at: file, to: displaced)
            try Data("replacement-must-not-copy".utf8).write(to: file)
        }
        #expect(throws: BackupError.self) {
            _ = try fixture.manager(failureInjector: { try mutation.run($0) })
                .create(label: "file-swap", sourceVersion: "1")
        }
        #expect(try fixture.manager().validatedList().isEmpty)
        #expect(try String(contentsOf: file, encoding: .utf8) == "replacement-must-not-copy")
    }
}

@Test func stateBackupSignedNamespacesPublishAndRecoveryIsCurrentBeforeRestoreMutation() throws {
    let fixture = try AttestedBackupFixture()
    defer { fixture.cleanup() }
    try Data("snapshot".utf8).write(to: fixture.home.appendingPathComponent("session.json"))
    let manager = fixture.manager()
    let backup = try manager.create(label: "signed", sourceVersion: "1")

    let backupState = try ProviderHistoryNamespaceMarkerStore.backgroundState(
        namespaceName: ProviderHistoryDeviceAttestation.backups.name,
        expectedURL: fixture.support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.backups.leafName,
            isDirectory: true
        ),
        expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
        expectedReceipt: ProviderHistoryDeviceAttestation.backups.publicationReceipt,
        configuration: ProviderHistoryDeviceAttestation.configuration(applicationSupport: fixture.support),
        keyStore: fixture.keyStore
    )
    guard case .current = backupState else {
        Issue.record("Backups namespace was not signed current")
        return
    }

    try Data("live".utf8).write(
        to: fixture.home.appendingPathComponent("session.json"),
        options: .atomic
    )
    _ = try manager.restore(backup)
    let recoveryState = try ProviderHistoryNamespaceMarkerStore.backgroundState(
        namespaceName: ProviderHistoryDeviceAttestation.stateRecovery.name,
        expectedURL: fixture.support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.stateRecovery.leafName,
            isDirectory: true
        ),
        expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
        expectedReceipt: ProviderHistoryDeviceAttestation.stateRecovery.publicationReceipt,
        configuration: ProviderHistoryDeviceAttestation.configuration(applicationSupport: fixture.support),
        keyStore: fixture.keyStore
    )
    guard case .current = recoveryState else {
        Issue.record("State-recovery namespace was not signed current")
        return
    }
}

@Test func stateBackupPreservesUnmarkedAndPreparedNamespaceCrashStates() throws {
    do {
        let fixture = try AttestedBackupFixture()
        defer { fixture.cleanup() }
        let backups = fixture.support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.backups.leafName,
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: backups,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let sentinel = backups.appendingPathComponent("preserve-me")
        try Data("opaque".utf8).write(to: sentinel)
        #expect(throws: BackupError.self) { _ = try fixture.manager().validatedList() }
        #expect(try Data(contentsOf: sentinel) == Data("opaque".utf8))
    }

    for phase in [
        ProviderHistoryNamespacePublicationPhase.preparedWritten,
        .rootRenamedAndSynced,
        .currentWritten
    ] {
        let fixture = try AttestedBackupFixture()
        defer { fixture.cleanup() }
        let stagingLeaf = ".fulmar-backups-installing"
        let staging = fixture.support.appendingPathComponent(stagingLeaf, isDirectory: true)
        try FileManager.default.createDirectory(
            at: staging,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let authority = try ProviderHistoryDeviceAttestation.openForeground(
            applicationSupport: fixture.support,
            keyStore: fixture.keyStore
        )
        let crashingStore = ProviderHistoryNamespaceMarkerStore(
            authority: authority,
            interruption: { $0 == phase }
        )
        #expect(throws: DeviceAttestationError.self) {
            _ = try crashingStore.publish(.init(
                sourceParent: fixture.support,
                sourceLeaf: stagingLeaf,
                destinationParent: fixture.support,
                destinationLeaf: ProviderHistoryDeviceAttestation.backups.leafName,
                namespaceName: ProviderHistoryDeviceAttestation.backups.name,
                privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                receipt: ProviderHistoryDeviceAttestation.backups.publicationReceipt
            ))
        }
        #expect(throws: BackupError.self) { _ = try fixture.manager().validatedList() }
        let published = fixture.support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.backups.leafName,
            isDirectory: true
        )
        #expect(
            FileManager.default.fileExists(atPath: staging.path)
                != FileManager.default.fileExists(atPath: published.path)
        )
    }
}
