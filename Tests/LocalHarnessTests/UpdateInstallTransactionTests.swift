import Darwin
import Foundation
@testable import LocalHarnessUpdateSecurity
import Testing
@testable import LocalHarness

private func updateAttestation(build: Int, hashByte: Character) -> SignedApplicationAttestation {
    SignedApplicationAttestation(
        identifier: "com.angadjairath.localharness",
        teamIdentifier: "TESTTEAM",
        cdHashHex: String(repeating: hashByte, count: 40),
        version: "1.\(build)",
        build: build
    )
}

private func validatedUpdate(
    inode: UInt64,
    attestation: SignedApplicationAttestation,
    device: UInt64 = 1
) -> ValidatedUpdateApplication {
    ValidatedUpdateApplication(
        identity: UpdateFileIdentity(device: device, inode: inode, mode: 0o040755, owner: UInt32(geteuid())),
        attestation: attestation
    )
}

private enum UpdateTransactionTestFailure: Error {
    case injected
}

private final class WeakUpdateManagerReference {
    weak var value: UpdateManager?
    init(_ value: UpdateManager?) { self.value = value }
}

private func updateJournalRecord(
    phase: UpdateInstallJournalPhase,
    old: ValidatedUpdateApplication? = nil,
    candidate: ValidatedUpdateApplication? = nil
) -> UpdateInstallJournalRecord {
    UpdateInstallJournalRecord(
        transactionID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
        nonceHex: String(repeating: "a", count: 64),
        currentApplicationPath: "/Applications/Fulmar.app",
        stagedApplicationPath: "/private/tmp/Local Harness/Updates/Staged/11111111-2222-3333-4444-555555555555/Expanded/Fulmar.app",
        rollbackApplicationPath: "/private/tmp/Local Harness/Updates/App Backups/Fulmar backup build 1 11111111-2222-3333-4444-555555555555.app",
        oldApplication: old ?? validatedUpdate(
            inode: 10,
            attestation: updateAttestation(build: 1, hashByte: "a")
        ),
        candidateApplication: candidate ?? validatedUpdate(
            inode: 20,
            attestation: updateAttestation(build: 2, hashByte: "b")
        ),
        phase: phase
    )
}

private func makePrivateUpdateStage(
    prefix: String
) throws -> (root: URL, updates: URL, operation: URL, expanded: URL, app: URL) {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("\(prefix).\(UUID().uuidString)", isDirectory: true)
    let support = root.appendingPathComponent("Local Harness", isDirectory: true)
    let updates = support.appendingPathComponent("Updates", isDirectory: true)
    let stagedBase = updates.appendingPathComponent("Staged", isDirectory: true)
    let operation = stagedBase.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let expanded = operation.appendingPathComponent("Expanded", isDirectory: true)
    for directory in [root, support, updates, stagedBase, operation, expanded] {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    return (
        root,
        updates,
        operation,
        expanded,
        expanded.appendingPathComponent("Fulmar.app", isDirectory: true)
    )
}

@Test func updateInstallRejectsStagedReplacementDuringParentWaitBeforeAnyMove() throws {
    let current = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let expectedStaged = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    let replacement = validatedUpdate(inode: 30, attestation: updateAttestation(build: 2, hashByte: "c"))
    var staged = expectedStaged
    var moveCount = 0
    var launched = false

    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: { staged = replacement },
        validateCurrent: { current },
        validateStaged: { staged },
        prepareBackup: {},
        createNonce: { String(repeating: "0", count: 64) },
        beginJournal: { _, _, _ in },
        persistJournalPhase: { _ in },
        retireJournal: {},
        moveCurrentToBackup: { moveCount += 1 },
        validateBackup: { current },
        moveStagedToCurrent: { moveCount += 1 },
        validateInstalled: { staged },
        removeInstalled: {},
        restoreBackup: {},
        validateRestored: { current },
        launchInstalled: { _ in launched = true; return 99 },
        awaitInstalledHealth: { _, _, _ in },
        stopInstalled: { _ in }
    )

    #expect(throws: UpdateSecurityError.self) {
        try UpdateInstallTransaction.execute(
            expectedCurrent: current.attestation,
            expectedStaged: expectedStaged.attestation,
            hooks: hooks
        )
    }
    #expect(moveCount == 0)
    #expect(!launched)
}

@Test func updateInstallRejectsMoveBoundaryReplacementAndRestoresCurrent() throws {
    let current = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let expectedStaged = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    let replacement = validatedUpdate(inode: 30, attestation: updateAttestation(build: 2, hashByte: "c"))
    var stageValidationCount = 0
    var movedStaged = false
    var restored = false
    var launched = false

    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: {},
        validateCurrent: { current },
        validateStaged: {
            stageValidationCount += 1
            return stageValidationCount == 1 ? expectedStaged : replacement
        },
        prepareBackup: {},
        createNonce: { String(repeating: "0", count: 64) },
        beginJournal: { _, _, _ in },
        persistJournalPhase: { _ in },
        retireJournal: {},
        moveCurrentToBackup: {},
        validateBackup: { current },
        moveStagedToCurrent: { movedStaged = true },
        validateInstalled: { replacement },
        removeInstalled: {},
        restoreBackup: { restored = true },
        validateRestored: { current },
        launchInstalled: { _ in launched = true; return 99 },
        awaitInstalledHealth: { _, _, _ in },
        stopInstalled: { _ in }
    )

    #expect(throws: UpdateSecurityError.self) {
        try UpdateInstallTransaction.execute(
            expectedCurrent: current.attestation,
            expectedStaged: expectedStaged.attestation,
            hooks: hooks
        )
    }
    #expect(stageValidationCount == 2)
    #expect(!movedStaged)
    #expect(restored)
    #expect(!launched)
}

@Test func updateInstallRejectsPostMoveReplacementBeforeLaunchAndRollsBack() throws {
    let current = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let expectedStaged = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    let replacement = validatedUpdate(inode: 30, attestation: updateAttestation(build: 2, hashByte: "c"))
    var removed = false
    var restored = false
    var launched = false

    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: {},
        validateCurrent: { current },
        validateStaged: { expectedStaged },
        prepareBackup: {},
        createNonce: { String(repeating: "0", count: 64) },
        beginJournal: { _, _, _ in },
        persistJournalPhase: { _ in },
        retireJournal: {},
        moveCurrentToBackup: {},
        validateBackup: { current },
        moveStagedToCurrent: {},
        validateInstalled: { replacement },
        removeInstalled: { removed = true },
        restoreBackup: { restored = true },
        validateRestored: { current },
        launchInstalled: { _ in launched = true; return 99 },
        awaitInstalledHealth: { _, _, _ in },
        stopInstalled: { _ in }
    )

    #expect(throws: UpdateSecurityError.self) {
        try UpdateInstallTransaction.execute(
            expectedCurrent: current.attestation,
            expectedStaged: expectedStaged.attestation,
            hooks: hooks
        )
    }
    #expect(removed)
    #expect(restored)
    #expect(!launched)
}

@Test func updateInstallLaunchesOnlyAfterAllThreeCandidateValidationsAgree() throws {
    let current = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let staged = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    var stageValidationCount = 0
    var installedValidationCount = 0
    var launched = false
    var healthAcknowledged = false

    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: {},
        validateCurrent: { current },
        validateStaged: { stageValidationCount += 1; return staged },
        prepareBackup: {},
        createNonce: { String(repeating: "0", count: 64) },
        beginJournal: { _, _, _ in },
        persistJournalPhase: { _ in },
        retireJournal: {},
        moveCurrentToBackup: {},
        validateBackup: { current },
        moveStagedToCurrent: {},
        validateInstalled: { installedValidationCount += 1; return staged },
        removeInstalled: {},
        restoreBackup: {},
        validateRestored: { current },
        launchInstalled: { _ in launched = true; return 99 },
        awaitInstalledHealth: { pid, nonce, candidate in
            #expect(pid == 99)
            #expect(nonce == String(repeating: "0", count: 64))
            #expect(candidate == staged)
            healthAcknowledged = true
        },
        stopInstalled: { _ in }
    )

    try UpdateInstallTransaction.execute(
        expectedCurrent: current.attestation,
        expectedStaged: staged.attestation,
        hooks: hooks
    )
    #expect(stageValidationCount == 2)
    #expect(installedValidationCount == 2)
    #expect(launched)
    #expect(healthAcknowledged)
}

@Test func updateInstallRejectsCrossDeviceMovesBeforeCreatingAnyRollback() throws {
    let current = validatedUpdate(
        inode: 10,
        attestation: updateAttestation(build: 1, hashByte: "a"),
        device: 1
    )
    let staged = validatedUpdate(
        inode: 20,
        attestation: updateAttestation(build: 2, hashByte: "b"),
        device: 2
    )
    var preparedBackup = false
    var moveCount = 0
    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: {},
        validateCurrent: { current },
        validateStaged: { staged },
        prepareBackup: { preparedBackup = true },
        createNonce: { String(repeating: "0", count: 64) },
        beginJournal: { _, _, _ in },
        persistJournalPhase: { _ in },
        retireJournal: {},
        moveCurrentToBackup: { moveCount += 1 },
        validateBackup: { current },
        moveStagedToCurrent: { moveCount += 1 },
        validateInstalled: { staged },
        removeInstalled: {},
        restoreBackup: {},
        validateRestored: { current },
        launchInstalled: { _ in 99 },
        awaitInstalledHealth: { _, _, _ in },
        stopInstalled: { _ in }
    )

    #expect(throws: UpdateSecurityError.self) {
        try UpdateInstallTransaction.execute(
            expectedCurrent: current.attestation,
            expectedStaged: staged.attestation,
            hooks: hooks
        )
    }
    #expect(!preparedBackup)
    #expect(moveCount == 0)
}

@Test func updateAttestationArgumentRoundTripsAndRejectsMalformedValues() throws {
    let attestation = updateAttestation(build: 2, hashByte: "b")
    #expect(try SignedApplicationAttestation.decodeArgument(attestation.encodedArgument()) == attestation)
    #expect(throws: UpdateSecurityError.self) {
        _ = try SignedApplicationAttestation.decodeArgument("not base64")
    }
}

@Test func updateHelperParentExitWaitExceedsTheCompleteProtectedQuitFailureBound() {
    let waitSeconds = Double(UpdateHelperReadinessProtocol.parentExitMaximumPolls)
        * Double(UpdateHelperReadinessProtocol.parentExitPollMicroseconds)
        / 1_000_000
    // ApplicationTerminationBarrier can take 40 seconds before forcing stop,
    // followed by its 12-second forced-stop deadline. The verified helper must
    // still be alive after that entire path, with ample scheduling margin.
    #expect(waitSeconds >= 90)
}

@Test func updateInstallPathPolicyRequiresExactPrivateNoSymlinkTopology() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("local-harness-update-install.\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }
    let support = root.appendingPathComponent("Local Harness", isDirectory: true)
    let updates = support.appendingPathComponent("Updates", isDirectory: true)
    let stagedBase = updates.appendingPathComponent("Staged", isDirectory: true)
    let operation = stagedBase.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let expanded = operation.appendingPathComponent("Expanded", isDirectory: true)
    let app = expanded.appendingPathComponent("Fulmar.app", isDirectory: true)
    for directory in [root, support, updates, stagedBase, operation, expanded] {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    try fileManager.createDirectory(at: app, withIntermediateDirectories: false)
    try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: app.path)

    try UpdateApplicationSecurity.validatePrivateStagedPath(app, updatesRoot: updates)
    let backup = updates
        .appendingPathComponent("App Backups", isDirectory: true)
        .appendingPathComponent("Local Harness backup build 1.app", isDirectory: true)
    try UpdateApplicationSecurity.preparePrivateBackupPath(backup, updatesRoot: updates)

    try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: expanded.path)
    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.validatePrivateStagedPath(app, updatesRoot: updates)
    }
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: expanded.path)

    let realExpanded = operation.appendingPathComponent("RealExpanded", isDirectory: true)
    try fileManager.moveItem(at: expanded, to: realExpanded)
    try fileManager.createSymbolicLink(at: expanded, withDestinationURL: realExpanded)
    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.validatePrivateStagedPath(
            expanded.appendingPathComponent("Fulmar.app", isDirectory: true),
            updatesRoot: updates
        )
    }
}

@Test func updateInstallSafelyTightensLegacyOwnerOnlyUpdateDirectories() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("local-harness-update-permissions.\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }
    let support = root.appendingPathComponent("Local Harness", isDirectory: true)
    let updates = support.appendingPathComponent("Updates", isDirectory: true)
    let backups = updates.appendingPathComponent("App Backups", isDirectory: true)
    for directory in [root, support, updates, backups] {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
    }
    let backup = backups.appendingPathComponent("Fulmar backup build 1.app", isDirectory: true)

    try UpdateApplicationSecurity.preparePrivateBackupPath(backup, updatesRoot: updates)

    for directory in [support, updates, backups] {
        let attributes = try fileManager.attributesOfItem(atPath: directory.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o700)
    }
}

@Test func updateInstallRefusesToRepairWritableLegacyUpdateDirectories() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("local-harness-update-hostile-permissions.\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }
    let support = root.appendingPathComponent("Local Harness", isDirectory: true)
    let updates = support.appendingPathComponent("Updates", isDirectory: true)
    for directory in [root, support, updates] {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    try fileManager.setAttributes([.posixPermissions: 0o775], ofItemAtPath: updates.path)
    let backup = updates
        .appendingPathComponent("App Backups", isDirectory: true)
        .appendingPathComponent("Fulmar backup build 1.app", isDirectory: true)

    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.preparePrivateBackupPath(backup, updatesRoot: updates)
    }
    let attributes = try fileManager.attributesOfItem(atPath: updates.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o775)
}

@Test func updatePrivateDirectoryPreparationRejectsLinksAndSpecialBits() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("local-harness-update-linked-permissions.\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }
    let real = root.appendingPathComponent("Real", isDirectory: true)
    let link = root.appendingPathComponent("Linked", isDirectory: true)
    for directory in [root, real] {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
    }
    try fileManager.createSymbolicLink(at: link, withDestinationURL: real)

    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.preparePrivateOwnedDirectory(link)
    }
    var attributes = try fileManager.attributesOfItem(atPath: real.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o755)

    try fileManager.setAttributes([.posixPermissions: 0o1755], ofItemAtPath: real.path)
    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.preparePrivateOwnedDirectory(real)
    }
    attributes = try fileManager.attributesOfItem(atPath: real.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o1755)
}

@Test func updatePrivateDirectoryPreparationRejectsForeignOwnedSystemDirectory() throws {
    let systemLibrary = URL(fileURLWithPath: "/System/Library", isDirectory: true)
    var metadata = stat()
    #expect(lstat(systemLibrary.path, &metadata) == 0)
    #expect(metadata.st_uid != geteuid())
    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.preparePrivateOwnedDirectory(systemLibrary)
    }
}

@Test func updatePrivateDirectoryPreparationRejectsInodeReplacementAfterOpen() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("local-harness-update-inode-swap.\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }
    let target = root.appendingPathComponent("Target", isDirectory: true)
    let displaced = root.appendingPathComponent("Displaced", isDirectory: true)
    for directory in [root, target] {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
    }

    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.preparePrivateOwnedDirectory(
            target,
            afterOpeningForTesting: { _ in
                try fileManager.moveItem(at: target, to: displaced)
                try fileManager.createDirectory(at: target, withIntermediateDirectories: false)
                try fileManager.setAttributes(
                    [.posixPermissions: 0o755],
                    ofItemAtPath: target.path
                )
            }
        )
    }

    let replacementAttributes = try fileManager.attributesOfItem(atPath: target.path)
    let openedAttributes = try fileManager.attributesOfItem(atPath: displaced.path)
    #expect((replacementAttributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o755)
    #expect((openedAttributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o700)
}

@Test func updateStageDiscardDoesNotFollowNestedOrTopLevelLinks() throws {
    let fileManager = FileManager.default
    let fixture = try makePrivateUpdateStage(prefix: "local-harness-update-discard-links")
    defer { try? fileManager.removeItem(at: fixture.root) }
    let external = fixture.root.appendingPathComponent("External", isDirectory: true)
    let sentinel = external.appendingPathComponent("sentinel.txt", isDirectory: false)
    try fileManager.createDirectory(at: external, withIntermediateDirectories: false)
    try Data("keep".utf8).write(to: sentinel)
    try fileManager.createSymbolicLink(
        at: fixture.expanded.appendingPathComponent("external-link"),
        withDestinationURL: external
    )

    try UpdateApplicationSecurity.discardPrivateStagedOperation(
        stagedApplication: fixture.app,
        updatesRoot: fixture.updates
    )
    #expect(!fileManager.fileExists(atPath: fixture.operation.path))
    #expect(try Data(contentsOf: sentinel) == Data("keep".utf8))

    let linkedFixture = try makePrivateUpdateStage(prefix: "local-harness-update-discard-top-link")
    defer { try? fileManager.removeItem(at: linkedFixture.root) }
    let displaced = linkedFixture.root.appendingPathComponent("Displaced", isDirectory: true)
    try fileManager.moveItem(at: linkedFixture.operation, to: displaced)
    try fileManager.createSymbolicLink(at: linkedFixture.operation, withDestinationURL: displaced)
    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.discardPrivateStagedOperation(
            stagedApplication: linkedFixture.app,
            updatesRoot: linkedFixture.updates
        )
    }
    #expect(fileManager.fileExists(atPath: displaced.path))
}

@Test func updateStageDiscardRejectsPathReplacementAfterValidation() throws {
    let fileManager = FileManager.default
    let fixture = try makePrivateUpdateStage(prefix: "local-harness-update-discard-race")
    defer { try? fileManager.removeItem(at: fixture.root) }
    let displaced = fixture.root.appendingPathComponent("Displaced", isDirectory: true)
    let marker = fixture.expanded.appendingPathComponent("original.txt")
    try Data("original".utf8).write(to: marker)

    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.discardPrivateStagedOperation(
            stagedApplication: fixture.app,
            updatesRoot: fixture.updates,
            afterValidationForTesting: {
                try fileManager.moveItem(at: fixture.operation, to: displaced)
                try fileManager.createDirectory(at: fixture.operation, withIntermediateDirectories: false)
                try fileManager.setAttributes(
                    [.posixPermissions: 0o700],
                    ofItemAtPath: fixture.operation.path
                )
            }
        )
    }
    #expect(fileManager.fileExists(atPath: fixture.operation.path))
    #expect(try Data(contentsOf: displaced.appendingPathComponent("Expanded/original.txt")) == Data("original".utf8))
}

@Test func updateStageEmptyCleanupRequiresAnActuallyEmptyExpandedDirectory() throws {
    let fileManager = FileManager.default
    let fixture = try makePrivateUpdateStage(prefix: "local-harness-update-empty-cleanup")
    defer { try? fileManager.removeItem(at: fixture.root) }
    let unexpected = fixture.expanded.appendingPathComponent("unexpected")
    try Data("preserve".utf8).write(to: unexpected)
    #expect(throws: UpdateSecurityError.self) {
        try UpdateApplicationSecurity.removeEmptyPrivateStagedOperation(
            stagedApplication: fixture.app,
            updatesRoot: fixture.updates
        )
    }
    #expect(try Data(contentsOf: unexpected) == Data("preserve".utf8))
    try fileManager.removeItem(at: unexpected)
    try UpdateApplicationSecurity.removeEmptyPrivateStagedOperation(
        stagedApplication: fixture.app,
        updatesRoot: fixture.updates
    )
    #expect(!fileManager.fileExists(atPath: fixture.operation.path))
}

@Test func updateManagerDiscardRemovesACancelledPreparedOperationOffTheCallerThread() throws {
    let fileManager = FileManager.default
    let fixture = try makePrivateUpdateStage(prefix: "local-harness-update-manager-discard")
    defer { try? fileManager.removeItem(at: fixture.root) }
    let applicationSupport = fixture.updates.deletingLastPathComponent()
    let state = fixture.root.appendingPathComponent("HarnessState", isDirectory: true)
    try fileManager.createDirectory(at: state, withIntermediateDirectories: false)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: state.path)
    try writeCurrentProviderHistoryPrivacyReceipt(at: state)
    let backupManager = StateBackupManager(
        applicationSupport: applicationSupport,
        sourceState: state,
        authenticationKey: Data(repeating: 0x42, count: 32)
    )
    let manager = UpdateManager(applicationSupport: applicationSupport, backupManager: backupManager)
    manager.discard(PreparedUpdate(
        stageRoot: fixture.operation,
        appURL: fixture.app,
        version: "1.2.15",
        build: 135,
        attestation: updateAttestation(build: 135, hashByte: "a")
    ))

    let deadline = Date().addingTimeInterval(2)
    while fileManager.fileExists(atPath: fixture.operation.path), Date() < deadline {
        usleep(5_000)
    }
    #expect(!fileManager.fileExists(atPath: fixture.operation.path))
}

@Test func updateAutomaticBackupRetentionAlwaysKeepsTheCurrentRollbackAndTwoMore() {
    let parent = URL(fileURLWithPath: "/private/tmp/App Backups", isDirectory: true)
    let candidates = (1...5).map { index in
        UpdateAutomaticBackupCandidate(
            url: parent.appendingPathComponent("candidate-\(index).app", isDirectory: true),
            build: index,
            modifiedSeconds: Int64(index),
            modifiedNanoseconds: 0
        )
    }
    let preserving = candidates[0].url
    let victims = UpdateApplicationSecurity.automaticBackupVictims(
        candidates: candidates,
        preserving: preserving,
        retentionCount: UpdateApplicationSecurity.automaticApplicationBackupRetentionCount
    )
    #expect(Set(victims.map(\.url.path)) == Set([candidates[1].url.path, candidates[2].url.path]))
    #expect(!victims.contains(where: { $0.url.path == preserving.path }))
    #expect(UpdateApplicationSecurity.automaticBackupVictims(
        candidates: candidates,
        preserving: parent.appendingPathComponent("missing.app"),
        retentionCount: 3
    ).isEmpty)

    let uuid = UUID().uuidString
    #expect(UpdateApplicationSecurity.automaticBackupBuild(from: "Fulmar backup build 135 \(uuid).app") == 135)
    #expect(UpdateApplicationSecurity.automaticBackupBuild(from: "Fulmar 1.2.15 manual.app") == nil)
    #expect(UpdateApplicationSecurity.automaticBackupBuild(from: "Fulmar backup build 0 \(uuid).app") == nil)
    #expect(UpdateApplicationSecurity.automaticBackupBuild(from: "Fulmar backup build 135 not-a-uuid.app") == nil)
}

@Test func updateInstallQuitGateRequiresExactGenerationAndAuthorizesOnlyOnce() throws {
    let gate = UpdateInstallAuthorizationGate()
    let generation = try gate.begin()
    #expect(gate.isPreparing(generation))
    #expect(!gate.authorizeQuit(generation))
    #expect(throws: UpdateError.self) { _ = try gate.begin() }
    #expect(throws: UpdateError.self) { try gate.markHelperLaunched(UUID()) }
    try gate.markHelperLaunched(generation)
    #expect(!gate.authorizeQuit(UUID()))
    #expect(gate.authorizeQuit(generation))
    #expect(!gate.authorizeQuit(generation))
    #expect(throws: UpdateError.self) { _ = try gate.begin() }
}

@Test func updateInstallFailureGateReopensOnlyForItsExactPreparingGeneration() throws {
    let gate = UpdateInstallAuthorizationGate()
    let generation = try gate.begin()
    gate.fail(UUID())
    #expect(throws: UpdateError.self) { _ = try gate.begin() }
    gate.fail(generation)
    let replacement = try gate.begin()
    #expect(replacement != generation)
    #expect(gate.isPreparing(replacement))
}

@Test func updateInstallHealthCommitPersistsEveryPhaseInOrderAndRetiresLast() throws {
    let old = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let candidate = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    var phases: [UpdateInstallJournalPhase] = []
    var events: [String] = []
    let nonce = String(repeating: "c", count: 64)
    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: { events.append("parent-exited") },
        validateCurrent: { old },
        validateStaged: { candidate },
        prepareBackup: { events.append("backup-prepared") },
        createNonce: { nonce },
        beginJournal: { boundOld, boundCandidate, boundNonce in
            #expect(boundOld == old)
            #expect(boundCandidate == candidate)
            #expect(boundNonce == nonce)
            events.append("journal-prepared")
        },
        persistJournalPhase: { phase in phases.append(phase); events.append(phase.rawValue) },
        retireJournal: { events.append("journal-retired") },
        moveCurrentToBackup: { events.append("old-moved") },
        validateBackup: { old },
        moveStagedToCurrent: { events.append("candidate-moved") },
        validateInstalled: { candidate },
        removeInstalled: { Issue.record("committed candidate must not be removed") },
        restoreBackup: { Issue.record("committed candidate must not be rolled back") },
        validateRestored: { old },
        launchInstalled: { suppliedNonce in
            #expect(suppliedNonce == nonce)
            events.append("candidate-launched")
            return 4242
        },
        awaitInstalledHealth: { pid, suppliedNonce, installed in
            #expect(pid == 4242)
            #expect(suppliedNonce == nonce)
            #expect(installed == candidate)
            events.append("native-health")
        },
        stopInstalled: { _ in Issue.record("healthy candidate must remain running") }
    )
    try UpdateInstallTransaction.execute(
        expectedCurrent: old.attestation,
        expectedStaged: candidate.attestation,
        hooks: hooks
    )
    #expect(phases == [.rollbackRetained, .candidateInstalled, .healthAcknowledged, .committed])
    #expect(events.firstIndex(of: "journal-prepared")! < events.firstIndex(of: "old-moved")!)
    #expect(events.firstIndex(of: "native-health")! < events.firstIndex(of: "healthAcknowledged")!)
    #expect(events.last == "journal-retired")
}

@Test func updateInstallMissingOrInvalidNativeHealthStopsExactCandidateAndRestoresOldApp() throws {
    let old = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let candidate = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    var stoppedPID: pid_t?
    var removed = false
    var restored = false
    var retired = false
    var phases: [UpdateInstallJournalPhase] = []
    let hooks = UpdateInstallTransactionHooks(
        waitForParentExit: {},
        validateCurrent: { old },
        validateStaged: { candidate },
        prepareBackup: {},
        createNonce: { String(repeating: "d", count: 64) },
        beginJournal: { _, _, _ in },
        persistJournalPhase: { phases.append($0) },
        retireJournal: { retired = true },
        moveCurrentToBackup: {},
        validateBackup: { old },
        moveStagedToCurrent: {},
        validateInstalled: { candidate },
        removeInstalled: { removed = true },
        restoreBackup: { restored = true },
        validateRestored: { old },
        launchInstalled: { _ in 5252 },
        awaitInstalledHealth: { _, _, _ in throw UpdateTransactionTestFailure.injected },
        stopInstalled: { stoppedPID = $0 }
    )
    #expect(throws: UpdateTransactionTestFailure.self) {
        try UpdateInstallTransaction.execute(
            expectedCurrent: old.attestation,
            expectedStaged: candidate.attestation,
            hooks: hooks
        )
    }
    #expect(stoppedPID == 5252)
    #expect(removed)
    #expect(restored)
    #expect(retired)
    #expect(phases == [.rollbackRetained, .candidateInstalled, .rollingBack])
}

@Test func updateInstallJournalPersistenceFaultsChooseRollbackUntilDurableHealthThenCommit() throws {
    let old = validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a"))
    let candidate = validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
    for failingPhase in UpdateInstallJournalPhase.allCases where failingPhase != .prepared && failingPhase != .rollingBack {
        var stopped = false
        var removed = false
        var restored = false
        var retired = false
        var durableHealth = false
        let hooks = UpdateInstallTransactionHooks(
            waitForParentExit: {},
            validateCurrent: { old },
            validateStaged: { candidate },
            prepareBackup: {},
            createNonce: { String(repeating: "e", count: 64) },
            beginJournal: { _, _, _ in },
            persistJournalPhase: { phase in
                if phase == failingPhase { throw UpdateTransactionTestFailure.injected }
                if phase == .healthAcknowledged { durableHealth = true }
            },
            retireJournal: { retired = true },
            moveCurrentToBackup: {},
            validateBackup: { old },
            moveStagedToCurrent: {},
            validateInstalled: { candidate },
            removeInstalled: { removed = true },
            restoreBackup: { restored = true },
            validateRestored: { old },
            launchInstalled: { _ in 6262 },
            awaitInstalledHealth: { _, _, _ in },
            stopInstalled: { _ in stopped = true }
        )
        #expect(throws: Error.self) {
            try UpdateInstallTransaction.execute(
                expectedCurrent: old.attestation,
                expectedStaged: candidate.attestation,
                hooks: hooks
            )
        }
        if failingPhase == .committed {
            #expect(durableHealth)
            #expect(!stopped)
            #expect(!removed)
            #expect(!restored)
            #expect(!retired)
        } else {
            #expect(!durableHealth)
            #expect(stopped == (failingPhase == .healthAcknowledged))
            #expect(removed || failingPhase == .rollbackRetained)
            #expect(restored)
            #expect(retired)
        }
    }
}

@Test func updateInstallRecoveryClassificationCoversEveryDurableCrashBoundary() throws {
    let prepared = updateJournalRecord(phase: .prepared)
    let old = prepared.oldApplication
    let candidate = prepared.candidateApplication
    #expect(try UpdateInstallRecovery.classify(
        record: prepared,
        current: .application(old),
        staged: .application(candidate),
        rollback: .missing
    ) == .clearUnchanged)

    for phase in [UpdateInstallJournalPhase.rollbackRetained, .candidateInstalled, .rollingBack] {
        let record = updateJournalRecord(phase: phase, old: old, candidate: candidate)
        #expect(try UpdateInstallRecovery.classify(
            record: record,
            current: phase == .rollbackRetained ? .missing : .application(candidate),
            staged: phase == .rollbackRetained ? .application(candidate) : .missing,
            rollback: .application(old)
        ) == .rollback)
    }
    for phase in [UpdateInstallJournalPhase.healthAcknowledged, .committed] {
        #expect(try UpdateInstallRecovery.classify(
            record: updateJournalRecord(phase: phase, old: old, candidate: candidate),
            current: .application(candidate),
            staged: .missing,
            rollback: .application(old)
        ) == .finalizeCommit)
    }
}

@Test func updateInstallRecoveryReplayIsIdempotentAcrossRollbackAndCommitFinalization() throws {
    let rollbackRecord = updateJournalRecord(phase: .candidateInstalled)
    var current: UpdateInstallArtifactState = .application(rollbackRecord.candidateApplication)
    var staged: UpdateInstallArtifactState = .missing
    var rollback: UpdateInstallArtifactState = .application(rollbackRecord.oldApplication)
    var phases: [UpdateInstallJournalPhase] = []
    var retirements = 0
    func hooks() -> UpdateInstallRecoveryHooks {
        UpdateInstallRecoveryHooks(
            inspectCurrent: { current },
            inspectStaged: { staged },
            inspectRollback: { rollback },
            stopCandidate: {},
            removeCandidate: { current = .missing },
            restoreRollback: { current = rollback; rollback = .missing },
            validateRestored: {
                guard case .application(let application) = current else {
                    throw UpdateTransactionTestFailure.injected
                }
                return application
            },
            persistPhase: { phases.append($0) },
            retireJournal: { retirements += 1 }
        )
    }
    #expect(try UpdateInstallRecovery.replay(record: rollbackRecord, hooks: hooks()) == .rollback)
    #expect(current == .application(rollbackRecord.oldApplication))
    #expect(phases == [.rollingBack])
    #expect(try UpdateInstallRecovery.replay(record: rollbackRecord, hooks: hooks()) == .clearUnchanged)
    #expect(retirements == 2)

    let commitRecord = updateJournalRecord(
        phase: .healthAcknowledged,
        old: rollbackRecord.oldApplication,
        candidate: rollbackRecord.candidateApplication
    )
    current = .application(commitRecord.candidateApplication)
    staged = .missing
    rollback = .application(commitRecord.oldApplication)
    phases.removeAll()
    #expect(try UpdateInstallRecovery.replay(record: commitRecord, hooks: hooks()) == .finalizeCommit)
    #expect(phases == [.committed])
}

@Test func updateInstallRecoveryRejectsStaleOrSubstitutedArtifactIdentityWithoutMutation() throws {
    let record = updateJournalRecord(phase: .candidateInstalled)
    let replacement = validatedUpdate(inode: 999, attestation: record.candidateApplication.attestation)
    var mutated = false
    #expect(throws: UpdateInstallJournalError.self) {
        _ = try UpdateInstallRecovery.replay(
            record: record,
            hooks: UpdateInstallRecoveryHooks(
                inspectCurrent: { .application(replacement) },
                inspectStaged: { .missing },
                inspectRollback: { .application(record.oldApplication) },
                stopCandidate: { mutated = true },
                removeCandidate: { mutated = true },
                restoreRollback: { mutated = true },
                validateRestored: { record.oldApplication },
                persistPhase: { _ in mutated = true },
                retireJournal: { mutated = true }
            )
        )
    }
    #expect(!mutated)
}

@Test func updateInstallJournalAuthenticatesTransitionsAndRejectsForgedTornOrLinkedBytes() throws {
    let fileManager = FileManager.default
    for attack in ["forged", "torn", "linked"] {
        let fixture = try makePrivateUpdateStage(prefix: "local-harness-update-journal-\(attack)")
        defer { try? fileManager.removeItem(at: fixture.root) }
        let store = UpdateInstallJournalStore(updatesRoot: fixture.updates)
        let record = UpdateInstallJournalRecord(
            transactionID: UUID(),
            nonceHex: String(repeating: "f", count: 64),
            currentApplicationPath: fixture.root.appendingPathComponent("Current/Fulmar.app").path,
            stagedApplicationPath: fixture.app.path,
            rollbackApplicationPath: fixture.updates.appendingPathComponent("App Backups/Rollback.app").path,
            oldApplication: validatedUpdate(inode: 10, attestation: updateAttestation(build: 1, hashByte: "a")),
            candidateApplication: validatedUpdate(inode: 20, attestation: updateAttestation(build: 2, hashByte: "b"))
        )
        try store.create(record)
        let keyAttributes = try fileManager.attributesOfItem(
            atPath: store.transactionURL.appendingPathComponent("authentication-key").path
        )
        #expect((keyAttributes[.size] as? NSNumber)?.intValue == 32)
        #expect(try store.load() == record)
        _ = try store.transition(expectedTransactionID: record.transactionID, to: .rollbackRetained)
        let journal = store.transactionURL.appendingPathComponent("journal.json")
        switch attack {
        case "forged":
            let original = try String(contentsOf: journal, encoding: .utf8)
            let forged = original.replacingOccurrences(of: "rollbackRetained", with: "candidateInstalled")
            try Data(forged.utf8).write(to: journal)
            #expect(throws: UpdateInstallJournalError.authenticationFailed) { _ = try store.load() }
        case "torn":
            let original = try Data(contentsOf: journal)
            try original.prefix(max(1, original.count / 2)).write(to: journal)
            #expect(throws: UpdateInstallJournalError.self) { _ = try store.load() }
        default:
            let external = fixture.root.appendingPathComponent("external-journal")
            try Data("not trusted".utf8).write(to: external)
            try fileManager.removeItem(at: journal)
            try fileManager.createSymbolicLink(at: journal, withDestinationURL: external)
            #expect(throws: UpdateInstallJournalError.unsafeStorage) { _ = try store.load() }
        }
    }
}

@Test func updatePostInstallHealthFramesBindNoncePIDAndCompleteSignedAttestation() throws {
    let candidate = updateAttestation(build: 2, hashByte: "b")
    let nonce = String(repeating: "1", count: 64)
    let challenge = try UpdatePostInstallHealthProtocol.challenge(nonceHex: nonce, candidate: candidate)
    let parsedChallenge = try UpdatePostInstallHealthProtocol.parseChallenge(challenge)
    #expect(parsedChallenge.0 == nonce)
    #expect(parsedChallenge.1 == candidate)
    let acknowledgement = try UpdatePostInstallHealthProtocol.acknowledgement(
        nonceHex: nonce,
        processIdentifier: 7373,
        candidate: candidate
    )
    let parsedAcknowledgement = try UpdatePostInstallHealthProtocol.parseAcknowledgement(acknowledgement)
    #expect(parsedAcknowledgement.0 == nonce)
    #expect(parsedAcknowledgement.1 == 7373)
    #expect(parsedAcknowledgement.2 == candidate)
    var forged = acknowledgement
    forged.append(0x00)
    #expect(throws: UpdatePostInstallHealthError.self) {
        _ = try UpdatePostInstallHealthProtocol.parseAcknowledgement(forged)
    }
}

@Test @MainActor
func updateManagerRetainsAcquiredPermitUntilGuaranteedTerminalFinishCallback() async throws {
    let fileManager = FileManager.default
    let fixture = try makePrivateUpdateStage(prefix: "local-harness-update-manager-lifetime")
    defer { try? fileManager.removeItem(at: fixture.root) }
    let state = fixture.root.appendingPathComponent("HarnessState", isDirectory: true)
    try fileManager.createDirectory(at: state, withIntermediateDirectories: false)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: state.path)
    try writeCurrentProviderHistoryPrivacyReceipt(at: state)
    let backupManager = StateBackupManager(
        applicationSupport: fixture.updates.deletingLastPathComponent(),
        sourceState: state,
        authenticationKey: Data(repeating: 0x55, count: 32)
    )
    var manager: UpdateManager? = UpdateManager(
        applicationSupport: fixture.updates.deletingLastPathComponent(),
        backupManager: backupManager
    )
    let retainedManager = WeakUpdateManagerReference(manager)
    var terminalCallback: (@MainActor () -> Void)?
    var terminalDisposition: StateBackupTransitionDisposition?
    var completionObserved = false
    let update = PreparedUpdate(
        stageRoot: fixture.operation,
        appURL: fixture.app,
        version: "1.2",
        build: 2,
        attestation: updateAttestation(build: 2, hashByte: "b")
    )
    manager?.install(
        update,
        currentVersion: "1.1",
        acquireTransition: { operation, completion in
            #expect(operation == .updateInstall)
            completion(.success(StateBackupQuiescencePermit(validation: {})))
        },
        finishTransition: { _, disposition, result, completion in
            terminalDisposition = disposition
            if case .success = result { Issue.record("test-bundle helper lookup must fail") }
            terminalCallback = completion
        },
        authorizedQuit: { Issue.record("failed helper preparation must never authorize Quit") },
        completion: { result in
            if case .success = result { Issue.record("test-bundle helper lookup must fail") }
            completionObserved = true
        }
    )
    manager = nil

    let terminalDeadline = Date().addingTimeInterval(3)
    while terminalCallback == nil, Date() < terminalDeadline {
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(terminalDisposition == .restartAndReopen)
    #expect(retainedManager.value != nil)
    #expect(!completionObserved)
    terminalCallback?()
    terminalCallback = nil

    let releaseDeadline = Date().addingTimeInterval(3)
    while retainedManager.value != nil, Date() < releaseDeadline {
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(completionObserved)
    #expect(retainedManager.value == nil)
}
