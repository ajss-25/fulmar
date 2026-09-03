import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Test func workspaceCheckpointIsBoundedPrivateAtomicAndExcludesUnsafeTrees() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("Sources/main.swift", "print(\"safe\")")
    try fixture.write("README.md", "hello")
    try fixture.write(".git/config", "must not leave workspace")
    try fixture.write("build/result.bin", "generated")
    try fixture.write("Vendor/library.js", "vendored")
    try fixture.write(".env.local", "TOKEN=not-copied")
    try fixture.write("service-credentials.json", "not-copied")
    try fixture.write("identity.pem", "not-copied")
    let outside = fixture.root.appendingPathComponent("outside.txt")
    try Data("outside-secret".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(
        at: fixture.workspace.appendingPathComponent("linked-outside.txt"),
        withDestinationURL: outside
    )
    let outsideDirectory = fixture.root.appendingPathComponent("outside-directory", isDirectory: true)
    try FileManager.default.createDirectory(at: outsideDirectory, withIntermediateDirectories: true)
    try Data("directory-secret".utf8).write(to: outsideDirectory.appendingPathComponent("secret.txt"))
    try FileManager.default.createSymbolicLink(
        at: fixture.workspace.appendingPathComponent("linked-directory", isDirectory: true),
        withDestinationURL: outsideDirectory
    )
    let fifo = fixture.workspace.appendingPathComponent("untrusted.fifo")
    guard Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0 else {
        throw CocoaError(.fileWriteUnknown)
    }

    let journal = try fixture.journal()
    let checkpoint = try journal.captureCheckpoint(label: "  Before agent changes\n")

    #expect(checkpoint.label == "Before agent changes")
    #expect(checkpoint.files.map(\.relativePath) == ["README.md", "Sources/main.swift"])
    #expect(checkpoint.totalBytes == 18)
    #expect(checkpoint.files.allSatisfy { $0.contentSHA256.count == 64 })
    #expect(try journal.listCheckpoints() == [
        WorkspaceCheckpointSummary(
            id: fixture.checkpointID,
            createdAt: fixture.date,
            label: "Before agent changes",
            fileCount: 2,
            totalBytes: 18,
            metadataFingerprint: checkpoint.metadataFingerprint
        )
    ])

    let recovery = fixture.support.appendingPathComponent("WorkspaceRecovery", isDirectory: true)
    let storedEntries = try allEntries(beneath: recovery)
    #expect(!storedEntries.contains { $0.lastPathComponent.hasPrefix(".staging-") })
    for entry in storedEntries + [recovery] {
        let attributes = try FileManager.default.attributesOfItem(atPath: entry.path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
        #expect((mode & 0o077) == 0)
    }
    var storedText = Data()
    for entry in storedEntries where !isDirectory(entry) {
        storedText.append(try Data(contentsOf: entry))
    }
    #expect(!String(decoding: storedText, as: UTF8.self).contains("outside-secret"))
    #expect(!String(decoding: storedText, as: UTF8.self).contains("directory-secret"))
    #expect(!String(decoding: storedText, as: UTF8.self).contains("TOKEN=not-copied"))
}

@Test func workspaceCheckpointRejectsControlAndBidirectionalPathNamesAndNormalizesLabels() throws {
    for hostileName in ["line\nbreak.txt", "safe\u{202E}gpj.txt", "zero\u{200D}width.txt"] {
        let fixture = try WorkspaceJournalFixture()
        defer { fixture.cleanup() }
        try fixture.write(hostileName, "content")
        let journal = try fixture.journal()
        #expect(throws: WorkspaceJournalError.workspaceChangedDuringScan(relativePath: hostileName)) {
            _ = try journal.captureCheckpoint(label: "baseline")
        }
        #expect(try journal.listCheckpoints().isEmpty)
    }

    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("safe.txt", "content")
    let checkpoint = try fixture.journal().captureCheckpoint(label: "Safe\u{202E}\u{200D} label\n")
    #expect(checkpoint.label == "Safe label")
}

@Test func workspacePreviewDetectsAddedModifiedDeletedAndMetadataChangesDeterministically() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("a.txt", "before")
    try fixture.write("b.txt", "delete me")
    try fixture.write("c.sh", "#!/bin/sh\n", permissions: 0o600)
    let journal = try fixture.journal()
    let checkpoint = try journal.captureCheckpoint(label: "baseline")

    try fixture.write("a.txt", "after")
    try FileManager.default.removeItem(at: fixture.workspace.appendingPathComponent("b.txt"))
    try fixture.write("d.txt", "added")
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: fixture.workspace.appendingPathComponent("c.sh").path
    )

    let preview = try journal.previewRestore(checkpointID: checkpoint.id)
    #expect(preview.changes.map { "\($0.relativePath):\($0.kind.rawValue)" } == [
        "a.txt:modified",
        "b.txt:deleted",
        "c.sh:modified",
        "d.txt:added"
    ])
    #expect(preview.conflicts == [
        WorkspaceRestoreConflict(kind: .wouldOverwriteModifiedFile, relativePath: "a.txt"),
        WorkspaceRestoreConflict(kind: .wouldOverwriteModifiedFile, relativePath: "c.sh")
    ])
    #expect(preview.stateFingerprint.count == 64)
    #expect(try journal.previewRestore(checkpointID: checkpoint.id) == preview)
}

@Test func workspaceRestoreRequiresExplicitOverwriteAndSeparateAddedFileDeletion() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("keep.txt", "checkpoint")
    try fixture.write("nested/lost.txt", "recover me", permissions: 0o640)
    let journal = try fixture.journal()
    let checkpoint = try journal.captureCheckpoint(label: "baseline")

    try fixture.write("keep.txt", "live work")
    try FileManager.default.removeItem(at: fixture.workspace.appendingPathComponent("nested/lost.txt"))
    try fixture.write("new.txt", "new work")
    let preview = try journal.previewRestore(checkpointID: checkpoint.id)

    #expect(throws: WorkspaceJournalError.restoreConflicts([
        WorkspaceRestoreConflict(kind: .wouldOverwriteModifiedFile, relativePath: "keep.txt")
    ])) {
        _ = try journal.restore(checkpointID: checkpoint.id, preview: preview)
    }
    #expect(try fixture.read("keep.txt") == "live work")
    #expect(try fixture.read("new.txt") == "new work")
    #expect(!fixture.exists("nested/lost.txt"))

    let restored = try journal.restore(
        checkpointID: checkpoint.id,
        preview: preview,
        options: WorkspaceRestoreOptions(overwriteModifiedFiles: true)
    )
    #expect(restored == WorkspaceRestoreReport(
        restoredDeletedFiles: 1,
        overwrittenModifiedFiles: 1,
        removedAddedFiles: 0,
        unchangedFiles: 0
    ))
    #expect(try fixture.read("keep.txt") == "checkpoint")
    #expect(try fixture.read("nested/lost.txt") == "recover me")
    #expect(try fixture.read("new.txt") == "new work")
    #expect(fileMode(fixture.workspace.appendingPathComponent("nested/lost.txt")) == 0o640)

    let removalPreview = try journal.previewRestore(checkpointID: checkpoint.id)
    #expect(removalPreview.changes.map { "\($0.relativePath):\($0.kind.rawValue)" } == ["new.txt:added"])
    let removed = try journal.restore(
        checkpointID: checkpoint.id,
        preview: removalPreview,
        options: WorkspaceRestoreOptions(removeAddedFiles: true)
    )
    #expect(removed.removedAddedFiles == 1)
    #expect(!fixture.exists("new.txt"))
    #expect(try journal.previewRestore(checkpointID: checkpoint.id).changes.isEmpty)
}

@Test func injectedMidApplyFailureRollsBackExactBytesPermissionsAndModificationTimes() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("a.bin", "checkpoint-a", permissions: 0o600)
    try fixture.write("b.bin", "checkpoint-b", permissions: 0o600)
    let injector = WorkspaceRestoreFailureInjector(applyFailurePath: "b.bin")
    let journal = try fixture.journal(restoreMutationHook: { @Sendable phase, relativePath in
        try injector.hook(phase: phase, relativePath: relativePath)
    })
    let checkpoint = try journal.captureCheckpoint(label: "baseline")

    let liveA = Data([0x00, 0xFF, 0x41, 0x0A, 0x7F])
    let liveB = Data([0xDE, 0xAD, 0xBE, 0xEF])
    try fixture.writeData("a.bin", liveA, permissions: 0o640)
    try fixture.writeData("b.bin", liveB, permissions: 0o751)
    try setModificationTimeNanoseconds(
        fixture.workspace.appendingPathComponent("a.bin"),
        1_701_234_567_123_456_789
    )
    try setModificationTimeNanoseconds(
        fixture.workspace.appendingPathComponent("b.bin"),
        1_702_345_678_234_567_890
    )
    let beforeA = try exactFileState(fixture.workspace.appendingPathComponent("a.bin"))
    let beforeB = try exactFileState(fixture.workspace.appendingPathComponent("b.bin"))
    let preview = try journal.previewRestore(checkpointID: checkpoint.id)

    #expect(throws: WorkspaceJournalError.restoreFailed) {
        _ = try journal.restore(
            checkpointID: checkpoint.id,
            preview: preview,
            options: WorkspaceRestoreOptions(overwriteModifiedFiles: true)
        )
    }

    #expect(try exactFileState(fixture.workspace.appendingPathComponent("a.bin")) == beforeA)
    #expect(try exactFileState(fixture.workspace.appendingPathComponent("b.bin")) == beforeB)
    #expect(try allEntries(beneath: fixture.support).allSatisfy {
        !$0.lastPathComponent.hasPrefix(".restore-")
    })
}

@Test func injectedRollbackFailurePreservesOwnerOnlyRecoveryMaterialAndReportsItsPath() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("a.txt", "checkpoint-a")
    try fixture.write("b.txt", "checkpoint-b")
    let injector = WorkspaceRestoreFailureInjector(
        applyFailurePath: "b.txt",
        rollbackFailurePaths: ["a.txt"]
    )
    let journal = try fixture.journal(restoreMutationHook: { @Sendable phase, relativePath in
        try injector.hook(phase: phase, relativePath: relativePath)
    })
    let checkpoint = try journal.captureCheckpoint(label: "baseline")

    try fixture.write("a.txt", "live-original-a", permissions: 0o640)
    try fixture.write("b.txt", "live-original-b", permissions: 0o700)
    let preview = try journal.previewRestore(checkpointID: checkpoint.id)

    var recoveryDirectory: String?
    do {
        _ = try journal.restore(
            checkpointID: checkpoint.id,
            preview: preview,
            options: WorkspaceRestoreOptions(overwriteModifiedFiles: true)
        )
        Issue.record("Expected rollbackFailed")
    } catch WorkspaceJournalError.rollbackFailed(let preservedPath) {
        recoveryDirectory = preservedPath
    } catch {
        Issue.record("Expected rollbackFailed, received \(error)")
    }

    let preserved = URL(fileURLWithPath: try #require(recoveryDirectory), isDirectory: true)
    #expect(FileManager.default.fileExists(atPath: preserved.path))
    #expect((fileMode(preserved) & 0o077) == 0)
    #expect(try Data(contentsOf: preserved.appendingPathComponent("a.txt")) == Data("live-original-a".utf8))
    #expect(try Data(contentsOf: preserved.appendingPathComponent("b.txt")) == Data("live-original-b".utf8))
    #expect(try Data(contentsOf: fixture.workspace.appendingPathComponent("a.txt")) == Data("checkpoint-a".utf8))
}

@Test func workspaceRestoreRejectsStalePreviewBeforeMakingAnyChange() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("lost.txt", "checkpoint")
    let journal = try fixture.journal()
    let checkpoint = try journal.captureCheckpoint(label: "baseline")
    try FileManager.default.removeItem(at: fixture.workspace.appendingPathComponent("lost.txt"))
    let preview = try journal.previewRestore(checkpointID: checkpoint.id)
    try fixture.write("arrived-later.txt", "must remain")

    #expect(throws: WorkspaceJournalError.stalePreview) {
        _ = try journal.restore(checkpointID: checkpoint.id, preview: preview)
    }
    #expect(!fixture.exists("lost.txt"))
    #expect(try fixture.read("arrived-later.txt") == "must remain")
}

@Test func workspaceRestoreNeverFollowsOrReplacesASymlinkObstruction() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("victim.txt", "checkpoint")
    let journal = try fixture.journal()
    let checkpoint = try journal.captureCheckpoint(label: "baseline")
    try FileManager.default.removeItem(at: fixture.workspace.appendingPathComponent("victim.txt"))
    let outside = fixture.root.appendingPathComponent("outside.txt")
    try Data("outside-must-remain".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(
        at: fixture.workspace.appendingPathComponent("victim.txt"),
        withDestinationURL: outside
    )

    let preview = try journal.previewRestore(checkpointID: checkpoint.id)
    #expect(preview.conflicts == [
        WorkspaceRestoreConflict(kind: .symbolicLinkAtDestination, relativePath: "victim.txt")
    ])
    #expect(throws: WorkspaceJournalError.restoreConflicts(preview.conflicts)) {
        _ = try journal.restore(
            checkpointID: checkpoint.id,
            preview: preview,
            options: WorkspaceRestoreOptions(overwriteModifiedFiles: true, removeAddedFiles: true)
        )
    }
    #expect(try String(contentsOf: outside, encoding: .utf8) == "outside-must-remain")
    #expect(try FileManager.default.destinationOfSymbolicLink(
        atPath: fixture.workspace.appendingPathComponent("victim.txt").path
    ) == outside.path)
}

@Test func workspaceCheckpointEnforcesEveryScanAndStorageLimit() throws {
    try withJournalFixture { fixture in
        try fixture.write(".git/config", "ignored")
        try fixture.write("build/output", "ignored")
        try fixture.write("vendor/dependency", "ignored")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 2,
            maximumEntryCount: 2,
            maximumTotalBytes: 8,
            maximumFileBytes: 8,
            maximumDepth: 4,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 16
        )
        #expect(throws: WorkspaceJournalError.entryCountLimitExceeded(maximum: 2)) {
            _ = try fixture.journal(limits: limits).captureCheckpoint(label: "too many entries")
        }
    }

    try withJournalFixture { fixture in
        try fixture.write("one", "1")
        try fixture.write("two", "2")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 1,
            maximumTotalBytes: 8,
            maximumFileBytes: 8,
            maximumDepth: 4,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 16
        )
        #expect(throws: WorkspaceJournalError.fileCountLimitExceeded(maximum: 1)) {
            _ = try fixture.journal(limits: limits).captureCheckpoint(label: "too many")
        }
    }

    try withJournalFixture { fixture in
        try fixture.write("large", "12345")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 4,
            maximumTotalBytes: 8,
            maximumFileBytes: 4,
            maximumDepth: 4,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 16
        )
        #expect(throws: WorkspaceJournalError.fileTooLarge(relativePath: "large", maximum: 4)) {
            _ = try fixture.journal(limits: limits).captureCheckpoint(label: "too large")
        }
    }

    try withJournalFixture { fixture in
        try fixture.write("one", "123")
        try fixture.write("two", "456")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 4,
            maximumTotalBytes: 5,
            maximumFileBytes: 5,
            maximumDepth: 4,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 10
        )
        #expect(throws: WorkspaceJournalError.totalByteLimitExceeded(maximum: 5)) {
            _ = try fixture.journal(limits: limits).captureCheckpoint(label: "too much")
        }
    }

    try withJournalFixture { fixture in
        try fixture.write("a/b/c.txt", "x")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 4,
            maximumTotalBytes: 8,
            maximumFileBytes: 8,
            maximumDepth: 2,
            maximumCheckpointCount: 2,
            maximumStoredBytes: 16
        )
        #expect(throws: WorkspaceJournalError.depthLimitExceeded(relativePath: "a/b/c.txt", maximum: 2)) {
            _ = try fixture.journal(limits: limits).captureCheckpoint(label: "too deep")
        }
    }

    try withJournalFixture { fixture in
        try fixture.write("file", "1234")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 4,
            maximumTotalBytes: 4,
            maximumFileBytes: 4,
            maximumDepth: 4,
            maximumCheckpointCount: 1,
            maximumStoredBytes: 4
        )
        let journal = try fixture.journal(limits: limits)
        _ = try journal.captureCheckpoint(label: "only")
        #expect(throws: WorkspaceJournalError.checkpointLimitExceeded(maximum: 1)) {
            _ = try journal.captureCheckpoint(label: "extra")
        }
        try journal.deleteCheckpoint(checkpointID: fixture.checkpointID)
        #expect(try journal.listCheckpoints().isEmpty)
        _ = try journal.captureCheckpoint(label: "replacement")
        #expect(try journal.listCheckpoints().count == 1)
    }

    try withJournalFixture(uuidSequence: UUIDSequence([
        UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    ])) { fixture in
        try fixture.write("file", "1234")
        let limits = WorkspaceJournalLimits(
            maximumFileCount: 4,
            maximumTotalBytes: 4,
            maximumFileBytes: 4,
            maximumDepth: 4,
            maximumCheckpointCount: 3,
            maximumStoredBytes: 6
        )
        let journal = try fixture.journal(limits: limits)
        _ = try journal.captureCheckpoint(label: "first")
        #expect(throws: WorkspaceJournalError.storedByteLimitExceeded(maximum: 6)) {
            _ = try journal.captureCheckpoint(label: "second")
        }
        #expect(try journal.listCheckpoints().count == 1)
    }
}

@Test func workspaceScanStreamsEmptyDirectoryFloodAndCapsBeforeCapture() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    for index in 0..<17 {
        try FileManager.default.createDirectory(
            at: fixture.workspace.appendingPathComponent("empty-\(index)", isDirectory: true),
            withIntermediateDirectories: false
        )
    }
    let limits = WorkspaceJournalLimits(
        maximumFileCount: 8,
        maximumEntryCount: 16,
        maximumTotalBytes: 64,
        maximumFileBytes: 64,
        maximumDepth: 4,
        maximumCheckpointCount: 2,
        maximumStoredBytes: 128
    )
    let journal = try fixture.journal(limits: limits)

    #expect(throws: WorkspaceJournalError.entryCountLimitExceeded(maximum: 16)) {
        _ = try journal.captureCheckpoint(label: "empty flood")
    }
    #expect(try allEntries(beneath: fixture.support).allSatisfy {
        !$0.lastPathComponent.hasPrefix(".staging-")
    })
}

@Test func workspaceScanCapsRelativePathBytesBeforeOpeningLeaf() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("long-directory/file.txt", "x")
    let limits = WorkspaceJournalLimits(
        maximumFileCount: 4,
        maximumEntryCount: 8,
        maximumTotalBytes: 8,
        maximumFileBytes: 8,
        maximumDepth: 4,
        maximumCheckpointCount: 2,
        maximumStoredBytes: 16,
        maximumRelativePathBytes: 8
    )

    #expect(throws: WorkspaceJournalError.relativePathByteLimitExceeded(maximum: 8)) {
        _ = try fixture.journal(limits: limits).currentSnapshot()
    }
}

@Test func workspaceScanUsesOneInjectedMonotonicDeadline() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("file.txt", "content")
    let clock = MonotonicStepClock(step: 2_000_000_000)
    let limits = WorkspaceJournalLimits(
        maximumFileCount: 4,
        maximumEntryCount: 8,
        maximumTotalBytes: 16,
        maximumFileBytes: 16,
        maximumDepth: 4,
        maximumCheckpointCount: 2,
        maximumStoredBytes: 32,
        maximumScanDurationSeconds: 1
    )
    let journal = try fixture.journal(limits: limits, monotonicNow: { clock.next() })

    #expect(throws: WorkspaceJournalError.scanDeadlineExceeded) {
        _ = try journal.currentSnapshot()
    }
}

@Test func checkpointCatalogStreamsAndRejectsExcessEntriesBeforeLoading() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    let journal = try fixture.journal(limits: WorkspaceJournalLimits(maximumCheckpointCount: 2))
    let checkpoints = fixture.support
        .appendingPathComponent("WorkspaceRecovery", isDirectory: true)
        .appendingPathComponent("v1", isDirectory: true)
    let workspaceStore = try #require(
        try FileManager.default.contentsOfDirectory(
            at: checkpoints,
            includingPropertiesForKeys: nil
        ).first
    )
    let catalog = workspaceStore.appendingPathComponent("checkpoints", isDirectory: true)
    for identifier in [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333"
    ] {
        let directory = catalog.appendingPathComponent(identifier, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    #expect(throws: WorkspaceJournalError.unsafeStorage) {
        _ = try journal.listCheckpoints()
    }
}

@Test func workspaceCheckpointPersistenceReopensOnlyForTheSameCanonicalWorkspace() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("file.txt", "checkpoint")
    let first = try fixture.journal()
    let checkpoint = try first.captureCheckpoint(label: "persisted")
    try fixture.write("file.txt", "changed")

    let reopened = try fixture.journal()
    #expect(try reopened.listCheckpoints().map(\.id) == [checkpoint.id])
    let preview = try reopened.previewRestore(checkpointID: checkpoint.id)
    _ = try reopened.restore(
        checkpointID: checkpoint.id,
        preview: preview,
        options: WorkspaceRestoreOptions(overwriteModifiedFiles: true)
    )
    #expect(try fixture.read("file.txt") == "checkpoint")

    let manifest = try onlyManifest(beneath: fixture.support)
    var json = try #require(
        try JSONSerialization.jsonObject(with: Data(contentsOf: manifest)) as? [String: Any]
    )
    json["workspaceCanonicalPath"] = fixture.root.appendingPathComponent("other").path
    try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]).write(to: manifest, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifest.path)
    #expect(throws: WorkspaceJournalError.unsafeCheckpoint) {
        _ = try reopened.previewRestore(checkpointID: checkpoint.id)
    }
}

@Test func failedCaptureAndReplaceLeavesThePredecessorFullyUsable() throws {
    let firstID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let secondID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    let fixture = try WorkspaceJournalFixture(uuidSequence: UUIDSequence([firstID, secondID]))
    defer { fixture.cleanup() }
    let limits = WorkspaceJournalLimits(
        maximumFileCount: 10,
        maximumEntryCount: 20,
        maximumTotalBytes: 16,
        maximumFileBytes: 4,
        maximumDepth: 4,
        maximumCheckpointCount: 1,
        maximumStoredBytes: 16,
        maximumManifestBytes: 1_048_576
    )
    try fixture.write("file", "old!")
    let journal = try fixture.journal(limits: limits)
    let predecessor = try journal.captureCheckpoint(label: "predecessor", origin: .automatic)
    try fixture.write("file", "too-large")

    #expect(throws: WorkspaceJournalError.fileTooLarge(relativePath: "file", maximum: 4)) {
        _ = try journal.captureCheckpoint(
            label: "successor",
            origin: .automatic,
            replacing: predecessor.id
        )
    }

    #expect(try journal.listCheckpoints() == [
        WorkspaceCheckpointSummary(
            id: firstID,
            createdAt: fixture.date,
            label: "predecessor",
            origin: .automatic,
            fileCount: 1,
            totalBytes: 4,
            metadataFingerprint: predecessor.metadataFingerprint
        )
    ])
    let manifest = try onlyManifest(beneath: fixture.support)
    #expect(manifest.deletingLastPathComponent().lastPathComponent == firstID.uuidString)
    #expect(try Data(contentsOf: manifest.deletingLastPathComponent().appendingPathComponent("contents/file")) == Data("old!".utf8))
    #expect(try allEntries(beneath: fixture.support).allSatisfy {
        !$0.lastPathComponent.hasPrefix(".staging-")
    })
}

@Test func cancellationAfterStagingBeginsRemovesPrivateTreeAndReleasesJournalImmediately() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    for index in 0..<200 {
        try fixture.write("group/file-\(index).txt", String(repeating: "x", count: 512))
    }
    let cancellation = WorkspaceJournalOperationCancellation()
    let clock = CancelWhenStagingAppearsClock(
        support: fixture.support,
        cancellation: cancellation
    )
    let journal = try fixture.journal(monotonicNow: { clock.next() })

    #expect(throws: WorkspaceJournalError.cancelled) {
        _ = try journal.captureCheckpoint(
            label: "cancel while staged",
            cancellation: cancellation
        )
    }
    #expect(clock.didObserveStaging)
    #expect(try journal.listCheckpoints().isEmpty)
    #expect(try allEntries(beneath: fixture.support).allSatisfy {
        !$0.lastPathComponent.hasPrefix(".staging-")
    })

    let retry = try journal.captureCheckpoint(label: "immediate retry")
    #expect(retry.files.count == 200)
    #expect(try journal.listCheckpoints().map(\.id) == [retry.id])
}

@Test func corruptCheckpointContentIsRejectedBeforeAnyWorkspaceMutation() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("a.txt", "restore a")
    try fixture.write("b.txt", "leave b")
    let journal = try fixture.journal()
    let checkpoint = try journal.captureCheckpoint(label: "baseline")
    try FileManager.default.removeItem(at: fixture.workspace.appendingPathComponent("a.txt"))
    try fixture.write("b.txt", "live b")
    let preview = try journal.previewRestore(checkpointID: checkpoint.id)

    let manifest = try onlyManifest(beneath: fixture.support)
    let checkpointRoot = manifest.deletingLastPathComponent()
    let blob = checkpointRoot.appendingPathComponent("contents/a.txt")
    try Data("corrupt".utf8).write(to: blob, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blob.path)

    #expect(throws: WorkspaceJournalError.checkpointContentCorrupt(relativePath: "a.txt")) {
        _ = try journal.restore(
            checkpointID: checkpoint.id,
            preview: preview,
            options: WorkspaceRestoreOptions(overwriteModifiedFiles: true)
        )
    }
    #expect(!fixture.exists("a.txt"))
    #expect(try fixture.read("b.txt") == "live b")
}

@Test func tamperedCheckpointPathsAndLinkedBlobsCannotEscapeRecoveryStorage() throws {
    try withJournalFixture { fixture in
        try fixture.write("safe.txt", "checkpoint")
        let journal = try fixture.journal()
        let checkpoint = try journal.captureCheckpoint(label: "baseline")
        let manifest = try onlyManifest(beneath: fixture.support)
        var json = try #require(
            try JSONSerialization.jsonObject(with: Data(contentsOf: manifest)) as? [String: Any]
        )
        var files = try #require(json["files"] as? [[String: Any]])
        files[0]["relativePath"] = "../escape.txt"
        json["files"] = files
        try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]).write(to: manifest, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifest.path)

        #expect(throws: WorkspaceJournalError.unsafeCheckpoint) {
            _ = try journal.previewRestore(checkpointID: checkpoint.id)
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("escape.txt").path))
    }

    try withJournalFixture { fixture in
        try fixture.write("safe.txt", "checkpoint")
        let journal = try fixture.journal()
        let checkpoint = try journal.captureCheckpoint(label: "baseline")
        try FileManager.default.removeItem(at: fixture.workspace.appendingPathComponent("safe.txt"))
        let preview = try journal.previewRestore(checkpointID: checkpoint.id)
        let manifest = try onlyManifest(beneath: fixture.support)
        let blob = manifest.deletingLastPathComponent().appendingPathComponent("contents/safe.txt")
        try FileManager.default.removeItem(at: blob)
        let outside = fixture.root.appendingPathComponent("outside.txt")
        try Data("checkpoint".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(at: blob, withDestinationURL: outside)

        #expect(throws: WorkspaceJournalError.unsafeCheckpoint) {
            _ = try journal.restore(checkpointID: checkpoint.id, preview: preview)
        }
        #expect(!fixture.exists("safe.txt"))
        #expect(try String(contentsOf: outside, encoding: .utf8) == "checkpoint")
    }
}

@Test func replacingTheApprovedWorkspaceRootInvalidatesTheJournal() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    try fixture.write("file.txt", "original")
    let journal = try fixture.journal()
    let moved = fixture.root.appendingPathComponent("moved-workspace", isDirectory: true)
    try FileManager.default.moveItem(at: fixture.workspace, to: moved)
    try FileManager.default.createDirectory(at: fixture.workspace, withIntermediateDirectories: false)
    try fixture.write("file.txt", "replacement")

    #expect(throws: WorkspaceJournalError.workspaceRootChanged) {
        _ = try journal.currentSnapshot()
    }
}

@Test func recoveryStorageCannotBePlacedInsideTheApprovedWorkspace() throws {
    let fixture = try WorkspaceJournalFixture()
    defer { fixture.cleanup() }
    let nestedSupport = fixture.workspace.appendingPathComponent("Recovery", isDirectory: true)

    #expect(throws: WorkspaceJournalError.unsafeStorage) {
        _ = try WorkspaceChangeJournal(
            approvedWorkspace: fixture.workspace,
            applicationSupport: nestedSupport
        )
    }
    #expect(!FileManager.default.fileExists(atPath: nestedSupport.path))
}

private final class UUIDSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [UUID]

    init(_ values: [UUID]) { self.values = values }

    func next() -> UUID {
        lock.lock()
        defer { lock.unlock() }
        return values.isEmpty ? UUID() : values.removeFirst()
    }
}

private final class MonotonicStepClock: @unchecked Sendable {
    private let lock = NSLock()
    private let step: UInt64
    private var value: UInt64 = 0

    init(step: UInt64) { self.step = step }

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let current = value
        value &+= step
        return current
    }
}

private final class CancelWhenStagingAppearsClock: @unchecked Sendable {
    private let lock = NSLock()
    private let support: URL
    private let cancellation: WorkspaceJournalOperationCancellation
    private(set) var didObserveStaging = false

    init(support: URL, cancellation: WorkspaceJournalOperationCancellation) {
        self.support = support
        self.cancellation = cancellation
    }

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        guard !didObserveStaging,
              let enumerator = FileManager.default.enumerator(
                  at: support,
                  includingPropertiesForKeys: nil
              ) else { return 0 }
        while let entry = enumerator.nextObject() as? URL {
            if entry.lastPathComponent.hasPrefix(".staging-") {
                didObserveStaging = true
                cancellation.cancel()
                break
            }
        }
        return 0
    }
}

private final class WorkspaceJournalFixture {
    let root: URL
    let workspace: URL
    let support: URL
    let checkpointID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
    let date = Date(timeIntervalSince1970: 1_700_000_000)
    private let uuidSequence: UUIDSequence?

    init(uuidSequence: UUIDSequence? = nil) throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("workspace-journal-\(UUID().uuidString)", isDirectory: true)
        workspace = root.appendingPathComponent("workspace", isDirectory: true)
        support = root.appendingPathComponent("Application Support", isDirectory: true)
        self.uuidSequence = uuidSequence
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }

    func journal(
        limits: WorkspaceJournalLimits = WorkspaceJournalLimits(),
        monotonicNow: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        restoreMutationHook: (@Sendable (WorkspaceRestoreMutationPhase, String) throws -> Void)? = nil
    ) throws -> WorkspaceChangeJournal {
        let sequence = uuidSequence
        let fixed = checkpointID
        let fixedDate = date
        return try WorkspaceChangeJournal(
            approvedWorkspace: workspace,
            applicationSupport: support,
            limits: limits,
            now: { fixedDate },
            monotonicNow: monotonicNow,
            makeUUID: { sequence?.next() ?? fixed },
            restoreMutationHook: restoreMutationHook
        )
    }

    func write(_ relativePath: String, _ text: String, permissions: Int = 0o644) throws {
        try writeData(relativePath, Data(text.utf8), permissions: permissions)
    }

    func writeData(_ relativePath: String, _ data: Data, permissions: Int = 0o644) throws {
        let url = workspace.appendingPathComponent(relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
    }

    func read(_ relativePath: String) throws -> String {
        try String(contentsOf: workspace.appendingPathComponent(relativePath), encoding: .utf8)
    }

    func exists(_ relativePath: String) -> Bool {
        FileManager.default.fileExists(atPath: workspace.appendingPathComponent(relativePath).path)
    }
}

private func withJournalFixture(
    uuidSequence: UUIDSequence? = nil,
    _ body: (WorkspaceJournalFixture) throws -> Void
) throws {
    let fixture = try WorkspaceJournalFixture(uuidSequence: uuidSequence)
    defer { fixture.cleanup() }
    try body(fixture)
}

private func onlyManifest(beneath root: URL) throws -> URL {
    let manifests = try allEntries(beneath: root).filter { $0.lastPathComponent == "manifest.json" }
    #expect(manifests.count == 1)
    return try #require(manifests.first)
}

private func allEntries(beneath root: URL) throws -> [URL] {
    guard let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isDirectoryKey],
        options: []
    ) else { return [] }
    var entries: [URL] = []
    while let entry = enumerator.nextObject() as? URL { entries.append(entry) }
    return entries.sorted { $0.path < $1.path }
}

private func isDirectory(_ url: URL) -> Bool {
    (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
}

private func fileMode(_ url: URL) -> Int {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes?[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

private struct ExactFileState: Equatable {
    let data: Data
    let permissions: Int
    let modificationTimeNanoseconds: Int64
}

private func exactFileState(_ url: URL) throws -> ExactFileState {
    var info = stat()
    guard Darwin.lstat(url.path, &info) == 0 else {
        throw CocoaError(.fileReadNoSuchFile)
    }
    return ExactFileState(
        data: try Data(contentsOf: url),
        permissions: Int(info.st_mode & 0o777),
        modificationTimeNanoseconds: Int64(info.st_mtimespec.tv_sec) * 1_000_000_000 +
            Int64(info.st_mtimespec.tv_nsec)
    )
}

private func setModificationTimeNanoseconds(_ url: URL, _ value: Int64) throws {
    let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw CocoaError(.fileReadNoPermission) }
    defer { Darwin.close(descriptor) }
    let timestamps = [
        timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)),
        timespec(
            tv_sec: Int(value / 1_000_000_000),
            tv_nsec: Int(value % 1_000_000_000)
        )
    ]
    let result = timestamps.withUnsafeBufferPointer { Darwin.futimens(descriptor, $0.baseAddress) }
    guard result == 0 else { throw CocoaError(.fileWriteUnknown) }
}

private enum InjectedWorkspaceRestoreFailure: Error {
    case requested
}

private final class WorkspaceRestoreFailureInjector: @unchecked Sendable {
    private let applyFailurePath: String
    private let rollbackFailurePaths: Set<String>

    init(applyFailurePath: String, rollbackFailurePaths: Set<String> = []) {
        self.applyFailurePath = applyFailurePath
        self.rollbackFailurePaths = rollbackFailurePaths
    }

    func hook(phase: WorkspaceRestoreMutationPhase, relativePath: String) throws {
        switch phase {
        case .apply where relativePath == applyFailurePath:
            throw InjectedWorkspaceRestoreFailure.requested
        case .rollback where rollbackFailurePaths.contains(relativePath):
            throw InjectedWorkspaceRestoreFailure.requested
        default:
            break
        }
    }
}
