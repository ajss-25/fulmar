import Darwin
import Foundation
@_spi(Testing) import LocalHarnessDeviceAttestation
import LocalHarnessSandboxPolicy
import Testing
@testable import LocalHarness

private final class AuxiliaryAttestationKeyStore: DeviceAttestationKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    private var reads: [String] = []
    private var inserts: [String] = []

    func read(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        reads.append(account)
        return values[account]
    }

    func insert(_ data: Data, account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard values[account] == nil else {
            throw DeviceAttestationError.invalidConfiguration
        }
        values[account] = data
        inserts.append(account)
    }

    func resetObservations() {
        lock.lock()
        reads = []
        inserts = []
        lock.unlock()
    }

    func observations() -> (reads: [String], inserts: [String]) {
        lock.lock()
        defer { lock.unlock() }
        return (reads, inserts)
    }
}

private struct AuxiliaryPrivacyFixture {
    let root: URL
    let support: URL
    let keyStore = AuxiliaryAttestationKeyStore()

    init(createSupport: Bool = true) throws {
        // Device attestation deliberately rejects symlinked or world-writable
        // control-path ancestors. The isolated Swift runner's TMPDIR lives
        // below `/private/tmp`, so use the real user's private Caches directory
        // just like the other foreground-attestation fixtures and remove the
        // unique root at test completion.
        guard let account = getpwuid(geteuid()),
              let home = account.pointee.pw_dir else {
            throw DeviceAttestationError.unsafeControlPath
        }
        let candidateRoot = URL(fileURLWithPath: String(cString: home), isDirectory: true)
            .appendingPathComponent("Library/Caches", isDirectory: true)
            .appendingPathComponent("fulmar-auxiliary-privacy-\(UUID().uuidString)", isDirectory: true)
        let candidateSupport = candidateRoot.appendingPathComponent("support", isDirectory: true)
        if createSupport {
            do {
                try FileManager.default.createDirectory(
                    at: candidateSupport,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o700],
                    ofItemAtPath: candidateSupport.path
                )
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o700],
                    ofItemAtPath: candidateRoot.path
                )
            } catch {
                try? FileManager.default.removeItem(at: candidateRoot)
                throw error
            }
        }
        root = candidateRoot
        support = candidateSupport
    }

    func directory(_ name: String, child: String = "opaque-provider-data") throws -> URL {
        let directory = support.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try Data(child.utf8).write(to: directory.appendingPathComponent("do-not-open.bin"))
        return directory
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private let auxiliaryFixedOperation = UUID(
    uuidString: "a0b1c2d3-e4f5-4678-9abc-def012345678"
)!

private func auxiliaryCoordinator(
    _ fixture: AuxiliaryPrivacyFixture,
    interruption: (@Sendable (ProviderHistoryAuxiliaryRecoveryPhase) -> Bool)? = nil,
    descriptorHook: (@Sendable (ProviderHistoryAuxiliaryRecoveryPhase) -> Void)? = nil,
    limits: ProviderHistoryAuxiliaryStateCoordinator.Limits = .production
) -> ProviderHistoryAuxiliaryStateCoordinator {
    ProviderHistoryAuxiliaryStateCoordinator(
        applicationSupport: fixture.support,
        limits: limits,
        makeUUID: { auxiliaryFixedOperation },
        interruption: interruption,
        descriptorHook: descriptorHook,
        attestationKeyStore: fixture.keyStore
    )
}

@discardableResult
private func publishAuxiliaryNamespace(
    _ namespace: ProviderHistoryDeviceAttestation.Namespace,
    fixture: AuxiliaryPrivacyFixture,
    interruption: (@Sendable (ProviderHistoryNamespacePublicationPhase) -> Bool)? = nil
) throws -> ProviderHistoryNamespaceMarker {
    let sourceLeaf = ".test-installing-\(UUID().uuidString.lowercased())"
    _ = try fixture.directory(sourceLeaf, child: namespace.name)
    let authority = try DeviceAttestationAuthority.openForeground(
        configuration: ProviderHistoryDeviceAttestation.configuration(
            applicationSupport: fixture.support
        ),
        keyStore: fixture.keyStore
    )
    let store: ProviderHistoryNamespaceMarkerStore
    if let interruption {
        store = ProviderHistoryNamespaceMarkerStore(
            authority: authority,
            interruption: interruption
        )
    } else {
        store = authority.makeProviderHistoryNamespaceMarkerStore()
    }
    return try store.publish(.init(
        sourceParent: fixture.support,
        sourceLeaf: sourceLeaf,
        destinationParent: fixture.support,
        destinationLeaf: namespace.leafName,
        namespaceName: namespace.name,
        privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
        receipt: namespace.publicationReceipt
    ))
}

@Test func auxiliaryPrivacyPreflightOnMissingSupportIsCredentialFreeAndMutationFree() throws {
    let fixture = try AuxiliaryPrivacyFixture(createSupport: false)
    defer { fixture.cleanup() }
    let pending = try auxiliaryCoordinator(fixture).preflight()
    #expect(pending == nil)
    let observations = fixture.keyStore.observations()
    #expect(observations.reads.isEmpty)
    #expect(observations.inserts.isEmpty)
    #expect(!FileManager.default.fileExists(atPath: fixture.support.path))
}

@Test func auxiliaryPrivacyInitialDetectionDoesNotMutateOrOpenOpaqueChildren() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    let backups = try fixture.directory("Backups")
    let stateRecovery = try fixture.directory(".local-harness-state-recovery")
    let migration = try fixture.directory("Migration")
    let before = try Set(FileManager.default.contentsOfDirectory(atPath: fixture.support.path))

    let pending = try auxiliaryCoordinator(fixture).preflight()
    guard case .initial(let request) = pending else {
        Issue.record("Expected an initial auxiliary recovery request")
        return
    }
    #expect(request.preservesBackups)
    #expect(request.preservesMigration)
    #expect(try Set(FileManager.default.contentsOfDirectory(atPath: fixture.support.path)) == before)
    #expect(FileManager.default.fileExists(atPath: backups.appendingPathComponent("do-not-open.bin").path))
    #expect(FileManager.default.fileExists(atPath: stateRecovery.appendingPathComponent("do-not-open.bin").path))
    #expect(FileManager.default.fileExists(atPath: migration.appendingPathComponent("do-not-open.bin").path))
}

@Test func auxiliaryPrivacyPreservesAllWholeRootsAndArchivesJournalWithoutDeletion() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    _ = try fixture.directory("Backups", child: "backup-secret")
    _ = try fixture.directory(".local-harness-state-recovery", child: "restore-secret")
    _ = try fixture.directory("Migration", child: "migration-secret")
    let coordinator = auxiliaryCoordinator(fixture)
    let pending = try coordinator.preflight()
    guard case .initial(let request) = pending else {
        Issue.record("Expected an initial request")
        return
    }

    let receipt = try coordinator.preserveAfterExplicitAcknowledgement(request)
    #expect(!FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent("Backups").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent(".local-harness-state-recovery").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent("Migration").path))
    let preservedBackups = try #require(receipt.preservedBackups)
    let preservedStateRecovery = try #require(receipt.preservedStateRecovery)
    let preservedMigration = try #require(receipt.preservedMigration)
    #expect(try String(contentsOf: preservedBackups.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "backup-secret")
    #expect(try String(contentsOf: preservedStateRecovery.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "restore-secret")
    #expect(try String(contentsOf: preservedMigration.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "migration-secret")

    let published = try coordinator.preflight()
    guard case .published(let rediscovered) = published else {
        Issue.record("Expected a published receipt")
        return
    }
    #expect(rediscovered == receipt)
    try coordinator.acknowledgePublishedRecovery(rediscovered)
    let archived = receipt.recoveryDirectory.appendingPathComponent(
        "transaction-\(auxiliaryFixedOperation.uuidString.lowercased())",
        isDirectory: true
    )
    #expect(FileManager.default.fileExists(atPath: archived.path))
    #expect(FileManager.default.fileExists(atPath: archived.appendingPathComponent("phase-4-published.json").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent(".provider-history-auxiliary-transaction").path))

    let clear = try coordinator.preflight()
    #expect(clear == nil)
}

@Test func auxiliaryPrivacyMovesOpaqueFIFOWithoutOpeningOrEnumeratingIt() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    let backups = try fixture.directory("Backups")
    let fifo = backups.appendingPathComponent("must-not-open.fifo")
    #expect(Darwin.mkfifo(fifo.path, 0o600) == 0)
    let coordinator = auxiliaryCoordinator(fixture)
    let pending = try coordinator.preflight()
    guard case .initial(let request) = pending else {
        Issue.record("Expected an initial request")
        return
    }
    let receipt = try coordinator.preserveAfterExplicitAcknowledgement(request)
    let destination = try #require(receipt.preservedBackups)
        .appendingPathComponent("must-not-open.fifo")
    var metadata = stat()
    #expect(Darwin.lstat(destination.path, &metadata) == 0)
    #expect(metadata.st_mode & S_IFMT == S_IFIFO)
}

@Test func everyAuxiliaryPrivacyCrashPhaseResumesWithoutReplacingPreservedOutput() throws {
    for phase in ProviderHistoryAuxiliaryRecoveryPhase.allCases {
        let fixture = try AuxiliaryPrivacyFixture()
        defer { fixture.cleanup() }
        _ = try fixture.directory("Backups", child: "backup-\(phase.rawValue)")
        _ = try fixture.directory("Migration", child: "migration-\(phase.rawValue)")
        let crashing = auxiliaryCoordinator(
            fixture,
            interruption: { $0 == phase }
        )
        let initial = try crashing.preflight()
        guard case .initial(let request) = initial else {
            Issue.record("Expected initial request for phase \(phase)")
            continue
        }
        #expect(throws: ProviderHistoryAuxiliaryTestInterruption.self) {
            _ = try crashing.preserveAfterExplicitAcknowledgement(request)
        }

        let relaunched = auxiliaryCoordinator(fixture)
        let detected = try relaunched.preflight()
        let receipt: ProviderHistoryAuxiliaryRecoveryReceipt
        switch detected {
        case .interrupted(let interrupted):
            receipt = try relaunched.resumeAfterExplicitAcknowledgement(interrupted)
        case .published(let published):
            receipt = published
        default:
            Issue.record("Expected interrupted or published state for phase \(phase)")
            continue
        }
        let preservedBackups = try #require(receipt.preservedBackups)
        let preservedMigration = try #require(receipt.preservedMigration)
        #expect(try String(contentsOf: preservedBackups.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "backup-\(phase.rawValue)")
        #expect(try String(contentsOf: preservedMigration.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "migration-\(phase.rawValue)")
        try relaunched.acknowledgePublishedRecovery(receipt)
    }
}

@Test func auxiliaryPrivacyRejectsSourceSymlinkBeforeTransactionCreation() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    let outside = try fixture.directory("outside")
    let link = fixture.support.appendingPathComponent("Backups")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)

    #expect(throws: ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage) {
        _ = try auxiliaryCoordinator(fixture).preflight()
    }
    #expect(!FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent(".provider-history-auxiliary-transaction").path))
}

@Test func auxiliaryPrivacyRejectsExtendedACLBeforeTransactionCreation() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    let backups = try fixture.directory("Backups")
    let chmod = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/chmod"),
        arguments: ["+a", "everyone allow read", backups.path],
        environment: ["PATH": "/usr/bin:/bin"],
        maximumStderrBytes: 4_096,
        deadline: 2,
        discardStandardOutput: true
    )
    #expect(chmod.exitStatus == 0)
    #expect(throws: ProviderHistoryAuxiliaryRecoveryError.unsafeRecoveryStorage) {
        _ = try auxiliaryCoordinator(fixture).preflight()
    }
    #expect(!FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent(".provider-history-auxiliary-transaction").path))
}

@Test func auxiliaryPrivacyRejectsIdentityReplacementAfterPrompt() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    let original = try fixture.directory("Backups", child: "original")
    let coordinator = auxiliaryCoordinator(fixture)
    let pending = try coordinator.preflight()
    guard case .initial(let request) = pending else {
        Issue.record("Expected an initial request")
        return
    }
    let replacement = try fixture.directory("replacement", child: "replacement")
    let displaced = fixture.support.appendingPathComponent("displaced")
    try FileManager.default.moveItem(at: original, to: displaced)
    try FileManager.default.moveItem(at: replacement, to: original)

    #expect(throws: ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged) {
        _ = try coordinator.preserveAfterExplicitAcknowledgement(request)
    }
    #expect(try String(contentsOf: displaced.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "original")
    #expect(try String(contentsOf: original.appendingPathComponent("do-not-open.bin"), encoding: .utf8) == "replacement")
}

@Test func auxiliaryPrivacyUnexpectedOrFutureJournalStateFailsClosedAndIsRetained() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    _ = try fixture.directory("Backups")
    let coordinator = auxiliaryCoordinator(fixture)
    let pending = try coordinator.preflight()
    guard case .initial(let request) = pending else {
        Issue.record("Expected an initial request")
        return
    }
    let crashing = auxiliaryCoordinator(
        fixture,
        interruption: { $0 == .prepared }
    )
    #expect(throws: ProviderHistoryAuxiliaryTestInterruption.self) {
        _ = try crashing.preserveAfterExplicitAcknowledgement(request)
    }
    let transaction = fixture.support.appendingPathComponent(
        ".provider-history-auxiliary-transaction",
        isDirectory: true
    )
    let future = transaction.appendingPathComponent("phase-99-future.json")
    try Data("{}".utf8).write(to: future)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: future.path)

    #expect(throws: ProviderHistoryAuxiliaryRecoveryError.malformedOrFutureJournal) {
        _ = try coordinator.preflight()
    }
    #expect(FileManager.default.fileExists(atPath: future.path))
    #expect(FileManager.default.fileExists(atPath: fixture.support.appendingPathComponent("Backups").path))
}

@Test func auxiliaryPrivacyAcceptsOnlyLiveSignedCurrentNamespacesWithOneAnchorRead() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    for namespace in ProviderHistoryDeviceAttestation.auxiliaryNamespaces {
        _ = try publishAuxiliaryNamespace(namespace, fixture: fixture)
    }
    fixture.keyStore.resetObservations()

    #expect(try auxiliaryCoordinator(fixture).preflight() == nil)
    let observations = fixture.keyStore.observations()
    #expect(observations.reads.count == 1)
    #expect(observations.inserts.isEmpty)
}

@Test func auxiliaryPrivacyPreservesUnmarkedMigrationStagingWhole() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    let staging = try fixture.directory(
        ProviderHistoryDeviceAttestation.migrationStagingLeafName,
        child: "pre-prepared-state"
    )
    let coordinator = auxiliaryCoordinator(fixture)
    guard case .initial(let request) = try coordinator.preflight() else {
        Issue.record("Expected unmarked staging to require opaque preservation")
        return
    }
    #expect(request.preservesMigration)

    let receipt = try coordinator.preserveAfterExplicitAcknowledgement(request)
    let preserved = try #require(receipt.preservedMigrationStaging)
    #expect(try String(
        contentsOf: preserved.appendingPathComponent("do-not-open.bin"),
        encoding: .utf8
    ) == "pre-prepared-state")
    #expect(!FileManager.default.fileExists(atPath: staging.path))
}

@Test func auxiliaryPrivacyReconcilesEverySignedNamespacePublicationCrashWindow() throws {
    for phase: ProviderHistoryNamespacePublicationPhase in [
        .preparedWritten,
        .rootRenamedAndSynced,
        .currentWritten
    ] {
        let fixture = try AuxiliaryPrivacyFixture()
        defer { fixture.cleanup() }
        #expect(throws: DeviceAttestationError.injectedInterruption(phase)) {
            _ = try publishAuxiliaryNamespace(
                ProviderHistoryDeviceAttestation.migration,
                fixture: fixture,
                interruption: { $0 == phase }
            )
        }

        let coordinator = auxiliaryCoordinator(fixture)
        guard case .namespacePublication(let request) = try coordinator.preflight() else {
            Issue.record("Expected signed foreground reconciliation for \(phase)")
            continue
        }
        #expect(request.namespaceNames == [ProviderHistoryDeviceAttestation.migration.name])
        #expect(try coordinator
            .reconcileNamespacePublicationsAfterExplicitAcknowledgement(request) == nil)
        #expect(FileManager.default.fileExists(
            atPath: fixture.support.appendingPathComponent("Migration").path
        ))
    }
}

@Test func auxiliaryPrivacyInvalidLimitsFailBeforeClassifiersOrMutation() throws {
    let fixture = try AuxiliaryPrivacyFixture()
    defer { fixture.cleanup() }
    var limits = ProviderHistoryAuxiliaryStateCoordinator.Limits.production
    limits.maximumTransactionEntries = 1
    #expect(throws: ProviderHistoryAuxiliaryRecoveryError.recoveryLimitExceeded) {
        _ = try auxiliaryCoordinator(fixture, limits: limits).preflight()
    }
    let observations = fixture.keyStore.observations()
    #expect(observations.reads.isEmpty)
    #expect(observations.inserts.isEmpty)
}
