import Foundation
import Testing
@testable import LocalHarness

private func makeWorkspacePolicy(at support: URL) throws -> WorkspaceMutationPolicyStore {
    let home = support.appendingPathComponent("HarnessHome", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    return WorkspaceMutationPolicyStore(harnessHome: home)
}

private func makeRecoveryFixture(
    name: String,
    limits: WorkspaceJournalLimits = WorkspaceJournalLimits()
) throws -> (root: URL, workspace: URL, support: URL, journal: WorkspaceChangeJournal, policy: WorkspaceMutationPolicyStore) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("\(name)-\(UUID().uuidString)", isDirectory: true)
    let workspace = root.appendingPathComponent("Workspace", isDirectory: true)
    let support = root.appendingPathComponent("Support", isDirectory: true)
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    return (
        root,
        workspace,
        support,
        try WorkspaceChangeJournal(
            approvedWorkspace: workspace,
            applicationSupport: support,
            limits: limits
        ),
        try makeWorkspacePolicy(at: support)
    )
}

@Test func automaticRecoveryRotationNeverEvictsManualCheckpoints() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("LocalHarnessRecoveryCoordinator-\(UUID().uuidString)", isDirectory: true)
    let workspace = root.appendingPathComponent("Workspace", isDirectory: true)
    let support = root.appendingPathComponent("Support", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    try Data("one".utf8).write(to: workspace.appendingPathComponent("file.txt"))
    let journal = try WorkspaceChangeJournal(
        approvedWorkspace: workspace,
        applicationSupport: support,
        limits: WorkspaceJournalLimits(
            maximumFileCount: 100,
            maximumEntryCount: 200,
            maximumTotalBytes: 1_048_576,
            maximumFileBytes: 1_048_576,
            maximumDepth: 8,
            maximumCheckpointCount: 3,
            maximumStoredBytes: 4 * 1_048_576,
            maximumManifestBytes: 1_048_576
        )
    )
    let coordinator = WorkspaceRecoveryCoordinator(
        journal: journal,
        policy: try makeWorkspacePolicy(at: support),
        maximumAutomaticCheckpoints: 2,
        maximumTotalCheckpoints: 3
    )

    let first = try await coordinator.captureBeforeTurn(reason: "First")
    _ = try journal.captureCheckpoint(label: "Manual safety point")
    try Data("two".utf8).write(to: workspace.appendingPathComponent("file.txt"))
    _ = try await coordinator.captureBeforeTurn(reason: "Second")
    try Data("three".utf8).write(to: workspace.appendingPathComponent("file.txt"))
    _ = try await coordinator.captureBeforeTurn(reason: "Third")

    let checkpoints = try journal.listCheckpoints()
    #expect(checkpoints.count == 3)
    #expect(checkpoints.contains { $0.label == "Manual safety point" })
    #expect(!checkpoints.contains { $0.id == first.checkpoint?.id })
    #expect(checkpoints.filter { $0.origin == .automatic }.count == 2)
}

@Test func rotationUsesOriginMetadataAndNeverEvictsAManualAutomaticLookingLabel() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("LocalHarnessRecoveryOriginRotation-\(UUID().uuidString)", isDirectory: true)
    let workspace = root.appendingPathComponent("Workspace", isDirectory: true)
    let support = root.appendingPathComponent("Support", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    try Data("one".utf8).write(to: workspace.appendingPathComponent("file.txt"))
    let journal = try WorkspaceChangeJournal(
        approvedWorkspace: workspace,
        applicationSupport: support,
        limits: WorkspaceJournalLimits(
            maximumFileCount: 100,
            maximumEntryCount: 200,
            maximumTotalBytes: 1_048_576,
            maximumFileBytes: 1_048_576,
            maximumDepth: 8,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 4 * 1_048_576,
            maximumManifestBytes: 1_048_576
        )
    )
    let automaticWithoutPrefix = try journal.captureCheckpoint(
        label: "Background safety point",
        origin: .automatic
    )
    let manualWithPrefix = try journal.captureCheckpoint(
        label: "Automatic · user named this manually",
        origin: .manual
    )
    let coordinator = WorkspaceRecoveryCoordinator(
        journal: journal,
        policy: try makeWorkspacePolicy(at: support),
        maximumAutomaticCheckpoints: 1,
        maximumTotalCheckpoints: 2
    )

    try Data("two".utf8).write(to: workspace.appendingPathComponent("file.txt"), options: .atomic)
    let successor = try await coordinator.captureBeforeTurn(reason: "Next turn")
    let checkpoints = try journal.listCheckpoints()

    #expect(checkpoints.count == 2)
    #expect(!checkpoints.contains { $0.id == automaticWithoutPrefix.id })
    #expect(checkpoints.contains {
        $0.id == manualWithPrefix.id &&
            $0.label == "Automatic · user named this manually" &&
            $0.origin == .manual
    })
    #expect(checkpoints.contains { $0.id == successor.checkpoint?.id && $0.origin == .automatic })
}

@Test func automaticRecoveryFailsWithoutDeletingManualOnlyCatalog() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("LocalHarnessRecoveryManualOnly-\(UUID().uuidString)", isDirectory: true)
    let workspace = root.appendingPathComponent("Workspace", isDirectory: true)
    let support = root.appendingPathComponent("Support", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    try Data("content".utf8).write(to: workspace.appendingPathComponent("file.txt"))
    let journal = try WorkspaceChangeJournal(
        approvedWorkspace: workspace,
        applicationSupport: support,
        limits: WorkspaceJournalLimits(
            maximumFileCount: 100,
            maximumEntryCount: 200,
            maximumTotalBytes: 1_048_576,
            maximumFileBytes: 1_048_576,
            maximumDepth: 8,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 4 * 1_048_576,
            maximumManifestBytes: 1_048_576
        )
    )
    _ = try journal.captureCheckpoint(label: "Manual one")
    _ = try journal.captureCheckpoint(label: "Manual two")
    let coordinator = WorkspaceRecoveryCoordinator(
        journal: journal,
        policy: try makeWorkspacePolicy(at: support),
        maximumAutomaticCheckpoints: 1,
        maximumTotalCheckpoints: 2
    )

    let protection = try await coordinator.captureBeforeTurn(reason: "Must not evict")
    #expect(protection == .readOnly(.recoverabilityLimit))
    #expect(Set(try journal.listCheckpoints().map(\.label)) == ["Manual one", "Manual two"])
}

@Test func unchangedTenThousandFileWorkspaceReusesOnePhysicalCheckpoint() async throws {
    let fixture = try makeRecoveryFixture(name: "FulmarRecoveryDedup10k")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    for directoryIndex in 0..<100 {
        let directory = fixture.workspace.appendingPathComponent("group-\(directoryIndex)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        for fileIndex in 0..<100 {
            #expect(FileManager.default.createFile(
                atPath: directory.appendingPathComponent("file-\(fileIndex).txt").path,
                contents: Data()
            ))
        }
    }
    let coordinator = WorkspaceRecoveryCoordinator(journal: fixture.journal, policy: fixture.policy)

    let first = try await coordinator.captureBeforeTurn(reason: "New Task")
    let second = try await coordinator.captureBeforeTurn(reason: "First prompt")
    let checkpoints = try fixture.journal.listCheckpoints()

    guard case .checkpoint(let firstCheckpoint, reused: false) = first,
          case .checkpoint(let secondCheckpoint, reused: true) = second else {
        Issue.record("Expected one physical checkpoint followed by metadata reuse")
        return
    }
    #expect(firstCheckpoint.id == secondCheckpoint.id)
    #expect(firstCheckpoint.fileCount == 10_000)
    #expect(checkpoints.count == 1)
    #expect(checkpoints.first?.id == firstCheckpoint.id)
    #expect(try fixture.policy.load().mode == .readWrite)
}

@Test func sameSizeRewriteWithRestoredMTimeDoesNotReuseCheckpoint() async throws {
    let fixture = try makeRecoveryFixture(name: "FulmarRecoveryCtime")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let file = fixture.workspace.appendingPathComponent("source.txt")
    try Data("first".utf8).write(to: file)
    let originalDate = try #require(
        FileManager.default.attributesOfItem(atPath: file.path)[.modificationDate] as? Date
    )
    let coordinator = WorkspaceRecoveryCoordinator(journal: fixture.journal, policy: fixture.policy)
    let first = try await coordinator.captureBeforeTurn(reason: "First")

    try Data("other".utf8).write(to: file)
    try FileManager.default.setAttributes([.modificationDate: originalDate], ofItemAtPath: file.path)
    let second = try await coordinator.captureBeforeTurn(reason: "Second")

    guard case .checkpoint(let firstCheckpoint, reused: false) = first,
          case .checkpoint(let secondCheckpoint, reused: false) = second else {
        Issue.record("A same-size rewrite with restored mtime was incorrectly reused")
        return
    }
    #expect(firstCheckpoint.id != secondCheckpoint.id)
    #expect(try fixture.journal.listCheckpoints().count == 2)
}

@Test func twentyMiBAssetAllowsReadOnlyTurnAndPublishesNoPartialCheckpoint() async throws {
    let fixture = try makeRecoveryFixture(name: "FulmarRecovery20MiB")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let asset = fixture.workspace.appendingPathComponent("common-video-asset.bin")
    #expect(FileManager.default.createFile(atPath: asset.path, contents: Data()))
    let handle = try FileHandle(forWritingTo: asset)
    try handle.truncate(atOffset: 20 * 1_024 * 1_024)
    try handle.close()
    let coordinator = WorkspaceRecoveryCoordinator(journal: fixture.journal, policy: fixture.policy)

    let protection = try await coordinator.captureBeforeTurn(reason: "Inspect large project")

    #expect(protection == .readOnly(.recoverabilityLimit))
    #expect(try fixture.journal.listCheckpoints().isEmpty)
    #expect(try fixture.policy.load() == WorkspaceMutationPolicy(
        schemaVersion: 1,
        mode: .readOnly,
        reason: .recoverabilityLimit
    ))
}

@Test func metadataDeadlineAllowsAReadOnlyTurnAndPublishesNoCheckpoint() async throws {
    var limits = WorkspaceJournalLimits()
    limits.maximumScanDurationSeconds = 0.001
    let fixture = try makeRecoveryFixture(name: "FulmarRecoveryDeadline", limits: limits)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    try Data("content".utf8).write(to: fixture.workspace.appendingPathComponent("source.txt"))
    let clock = ImmediateDeadlineClock()
    let journal = try WorkspaceChangeJournal(
        approvedWorkspace: fixture.workspace,
        applicationSupport: fixture.support,
        limits: limits,
        monotonicNow: { clock.next() }
    )
    let coordinator = WorkspaceRecoveryCoordinator(journal: journal, policy: fixture.policy)

    let protection = try await coordinator.captureBeforeTurn(reason: "Deadline fallback")

    #expect(protection == .readOnly(.recoveryDeadline))
    #expect(try fixture.policy.load() == WorkspaceMutationPolicy(
        schemaVersion: 1,
        mode: .readOnly,
        reason: .recoveryDeadline
    ))
    #expect(!containsCheckpointManifest(beneath: fixture.support))
}

@Test func corruptCheckpointStorageStillBlocksAndClosesMutationPolicy() async throws {
    let fixture = try makeRecoveryFixture(name: "FulmarRecoveryCorruptStorage")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    try Data("content".utf8).write(to: fixture.workspace.appendingPathComponent("source.txt"))
    let coordinator = WorkspaceRecoveryCoordinator(journal: fixture.journal, policy: fixture.policy)
    _ = try await coordinator.captureBeforeTurn(reason: "Initial")
    let manifest = try #require(firstCheckpointManifest(beneath: fixture.support))
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: manifest.path)

    await #expect(throws: WorkspaceJournalError.unsafeCheckpoint) {
        _ = try await coordinator.captureBeforeTurn(reason: "Must block")
    }
    #expect(try fixture.policy.load() == WorkspaceMutationPolicy(
        schemaVersion: 1,
        mode: .readOnly,
        reason: .checkpointRequired
    ))
}

@Test func cancelledCapturePublishesNothingAndImmediateRetrySucceeds() async throws {
    let fixture = try makeRecoveryFixture(name: "FulmarRecoveryCancellation")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    for index in 0..<2_000 {
        #expect(FileManager.default.createFile(
            atPath: fixture.workspace.appendingPathComponent("file-\(index).txt").path,
            contents: Data(repeating: UInt8(index % 251), count: 64)
        ))
    }
    let coordinator = WorkspaceRecoveryCoordinator(journal: fixture.journal, policy: fixture.policy)
    let cancellation = WorkspaceJournalOperationCancellation()
    cancellation.cancel()

    await #expect(throws: WorkspaceJournalError.cancelled) {
        _ = try await coordinator.captureBeforeTurn(reason: "Cancelled", cancellation: cancellation)
    }
    #expect(try fixture.journal.listCheckpoints().isEmpty)

    let retry = try await coordinator.captureBeforeTurn(reason: "Immediate retry")
    guard case .checkpoint(let checkpoint, reused: false) = retry else {
        Issue.record("Immediate retry did not publish its complete checkpoint")
        return
    }
    #expect(checkpoint.fileCount == 2_000)
    #expect(try fixture.journal.listCheckpoints().map(\.id) == [checkpoint.id])
}

private final class ImmediateDeadlineClock: @unchecked Sendable {
    private let lock = NSLock()
    private var first = true

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        if first {
            first = false
            return 0
        }
        return 2_000_000
    }
}

private func firstCheckpointManifest(beneath root: URL) -> URL? {
    guard let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: nil
    ) else { return nil }
    while let entry = enumerator.nextObject() as? URL {
        if entry.lastPathComponent == "manifest.json" { return entry }
    }
    return nil
}

private func containsCheckpointManifest(beneath root: URL) -> Bool {
    firstCheckpointManifest(beneath: root) != nil
}
