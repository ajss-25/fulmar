import Darwin
import Foundation
import Testing
@testable import LocalHarness

private enum ActivityStoreInjectedFailure: Error {
    case requested
}

private enum ActivityStoreACLFixtureError: Error {
    case chmodFailed(Int32)
}

private func addActivityStoreExtendedACL(to url: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "everyone allow read", url.path]
    try process.run()
    process.waitUntilExit()
    guard process.terminationReason == .exit, process.terminationStatus == 0 else {
        throw ActivityStoreACLFixtureError.chmodFailed(process.terminationStatus)
    }
}

private func makeActivityRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("activity-store-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
}

private func activityDirectory(_ root: URL) -> URL {
    root.appendingPathComponent("Activity", isDirectory: true)
}

private func activityDocument(_ root: URL) -> URL {
    activityDirectory(root).appendingPathComponent("activities.json")
}

private func activityFixture(
    id: UUID = UUID(),
    title: String = "Stored activity",
    detail: String = "Stored privately",
    state: LocalActivity.State = .completed,
    createdAt: Date = Date(timeIntervalSinceReferenceDate: 1_000),
    updatedAt: Date = Date(timeIntervalSinceReferenceDate: 2_000),
    progress: Double? = 1
) -> LocalActivity {
    LocalActivity(
        id: id,
        kind: .runtime,
        title: title,
        detail: detail,
        state: state,
        createdAt: createdAt,
        updatedAt: updatedAt,
        progress: progress
    )
}

private func installActivityFixture(_ activities: [LocalActivity], at root: URL) throws {
    let directory = activityDirectory(root)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    let document = activityDocument(root)
    try JSONEncoder().encode(activities).write(to: document)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: document.path)
}

@Test
func activityStorePersistsOwnerOnlyBoundedHistoryAndRetainsNewestFiveHundred() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let activities = (0..<ActivityStoreLimits.maximumActivities).map { index in
        activityFixture(
            title: "Activity \(index)",
            updatedAt: Date(timeIntervalSinceReferenceDate: TimeInterval(index))
        )
    }
    try installActivityFixture(activities, at: root)

    let store = ActivityStore(applicationSupport: root)
    store.addCompleted(.runtime, title: "Newest retained activity")
    let snapshot = store.snapshot()

    #expect(store.status() == .available)
    #expect(snapshot.count == ActivityStoreLimits.maximumActivities)
    #expect(snapshot.first?.title == "Newest retained activity")
    #expect(snapshot.contains(where: { $0.title == "Activity 0" }) == false)

    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: activityDirectory(root).path)
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: activityDocument(root).path)
    #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
    #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    #expect((fileAttributes[.referenceCount] as? NSNumber)?.intValue == 1)
    #expect(try Data(contentsOf: activityDocument(root)).count <= ActivityStoreLimits.maximumDocumentBytes)
}

@Test
func activityStorePersistsInterruptedStateRecoveryExactlyOnce() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let id = UUID()
    try installActivityFixture([activityFixture(id: id, state: .running, progress: 0.5)], at: root)

    let reopened = ActivityStore(applicationSupport: root)
    let recovered = try #require(reopened.snapshot().first)
    #expect(reopened.status() == .available)
    #expect(recovered.id == id)
    #expect(recovered.state == .failed)
    #expect(recovered.detail == "Interrupted when Fulmar last stopped.")
    let recoveredBytes = try Data(contentsOf: activityDocument(root))

    let reopenedAgain = ActivityStore(applicationSupport: root)
    #expect(reopenedAgain.snapshot() == reopened.snapshot())
    #expect(try Data(contentsOf: activityDocument(root)) == recoveredBytes)
}

@Test
func activityStoreSynchronousHeadlessMutationIsDurableBeforeReturn() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ActivityStore(applicationSupport: root)
    let id = try store.addWaitingSynchronously(
        .backup,
        title: "Recovery needs review",
        detail: "No background runtime was started."
    )

    let reopened = ActivityStore(applicationSupport: root)
    let persisted = try #require(reopened.snapshot().first(where: { $0.id == id }))
    #expect(persisted.state == .waiting)
    #expect(persisted.detail == "No background runtime was started.")
}

@Test
func activityStoreRejectsSparseOversizedDocumentBeforeLoadingIt() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = activityDirectory(root)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    let document = activityDocument(root)
    let descriptor = Darwin.open(document.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o600))
    #expect(descriptor >= 0)
    guard descriptor >= 0 else { return }
    #expect(ftruncate(descriptor, off_t(ActivityStoreLimits.maximumDocumentBytes + 1)) == 0)
    _ = Darwin.close(descriptor)

    let store = ActivityStore(applicationSupport: root)
    #expect(store.status() == .unavailable(.oversizedDocument))
    #expect(store.snapshot().isEmpty)
}

@Test
func activityStoreRejectsAggregateEncodedHistoryAboveFourMegabytes() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let detail = String(repeating: "d", count: ActivityStoreLimits.maximumDetailBytes)
    let activities = (0..<300).map { index in
        activityFixture(
            title: "Bounded row \(index)",
            detail: detail,
            updatedAt: Date(timeIntervalSinceReferenceDate: TimeInterval(index))
        )
    }
    try installActivityFixture(activities, at: root)
    #expect(try Data(contentsOf: activityDocument(root)).count > ActivityStoreLimits.maximumDocumentBytes)

    let store = ActivityStore(applicationSupport: root)
    #expect(store.status() == .unavailable(.oversizedDocument))
    #expect(store.snapshot().isEmpty)
}

@Test
func activityStoreRejectsTooManyRowsAndUnboundedOrInvalidRecords() throws {
    for issue in [
        (0...ActivityStoreLimits.maximumActivities).map { index in
            activityFixture(
                title: "Row \(index)",
                updatedAt: Date(timeIntervalSinceReferenceDate: TimeInterval(index))
            )
        },
        [activityFixture(title: String(repeating: "x", count: ActivityStoreLimits.maximumTitleBytes + 1))],
        [activityFixture(detail: String(repeating: "x", count: ActivityStoreLimits.maximumDetailBytes + 1))],
        [activityFixture(progress: 1.01)]
    ] {
        let root = try makeActivityRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try installActivityFixture(issue, at: root)
        let store = ActivityStore(applicationSupport: root)
        #expect(store.status() == .unavailable(.invalidRecord))
        #expect(store.snapshot().isEmpty)
    }
}

@Test
func activityStoreRejectsMalformedAndEmptyDocumentsAsUnavailable() throws {
    for payload in [Data(), Data("{not-json".utf8)] {
        let root = try makeActivityRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = activityDirectory(root)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        try payload.write(to: activityDocument(root))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: activityDocument(root).path)

        let store = ActivityStore(applicationSupport: root)
        #expect(store.status() == .unavailable(.malformedDocument))
    }
}

@Test
func activityStoreNeverFollowsDocumentOrDirectorySymlinks() throws {
    let fileRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: fileRoot) }
    let outside = fileRoot.appendingPathComponent("outside.json")
    let outsideBytes = try JSONEncoder().encode([activityFixture(title: "Outside")])
    try outsideBytes.write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    try FileManager.default.createDirectory(at: activityDirectory(fileRoot), withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: activityDirectory(fileRoot).path)
    try FileManager.default.createSymbolicLink(at: activityDocument(fileRoot), withDestinationURL: outside)

    let linkedFileStore = ActivityStore(applicationSupport: fileRoot)
    #expect(linkedFileStore.status() == .unavailable(.unsafeStorage))
    linkedFileStore.addCompleted(.runtime, title: "Must not escape")
    _ = linkedFileStore.snapshot()
    #expect(try Data(contentsOf: outside) == outsideBytes)

    let directoryRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: directoryRoot) }
    let outsideDirectory = directoryRoot.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(at: outsideDirectory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: outsideDirectory.path)
    try FileManager.default.createSymbolicLink(
        at: activityDirectory(directoryRoot),
        withDestinationURL: outsideDirectory
    )

    let linkedDirectoryStore = ActivityStore(applicationSupport: directoryRoot)
    #expect(linkedDirectoryStore.status() == .unavailable(.unsafeStorage))
    #expect(FileManager.default.fileExists(atPath: outsideDirectory.appendingPathComponent("activities.json").path) == false)
}

@Test
func activityStoreRejectsHardLinkedAndPermissiveStorage() throws {
    let hardLinkRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: hardLinkRoot) }
    let outside = hardLinkRoot.appendingPathComponent("outside.json")
    try JSONEncoder().encode([activityFixture()]).write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    try FileManager.default.createDirectory(at: activityDirectory(hardLinkRoot), withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: activityDirectory(hardLinkRoot).path)
    #expect(Darwin.link(outside.path, activityDocument(hardLinkRoot).path) == 0)
    #expect(ActivityStore(applicationSupport: hardLinkRoot).status() == .unavailable(.unsafeStorage))

    let permissiveFileRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: permissiveFileRoot) }
    try installActivityFixture([activityFixture()], at: permissiveFileRoot)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: activityDocument(permissiveFileRoot).path)
    #expect(ActivityStore(applicationSupport: permissiveFileRoot).status() == .unavailable(.unsafeStorage))

    let permissiveDirectoryRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: permissiveDirectoryRoot) }
    try FileManager.default.createDirectory(at: activityDirectory(permissiveDirectoryRoot), withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: activityDirectory(permissiveDirectoryRoot).path)
    #expect(ActivityStore(applicationSupport: permissiveDirectoryRoot).status() == .unavailable(.unsafeStorage))
}

@Test
func activityStoreRejectsExtendedACLsOnItsDirectoryAndDocument() throws {
    let directoryRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: directoryRoot) }
    try FileManager.default.createDirectory(
        at: activityDirectory(directoryRoot),
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try addActivityStoreExtendedACL(to: activityDirectory(directoryRoot))
    #expect(ActivityStore(applicationSupport: directoryRoot).status() == .unavailable(.unsafeStorage))

    let documentRoot = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: documentRoot) }
    try installActivityFixture([activityFixture()], at: documentRoot)
    try addActivityStoreExtendedACL(to: activityDocument(documentRoot))
    #expect(ActivityStore(applicationSupport: documentRoot).status() == .unavailable(.unsafeStorage))
}

@Test(arguments: [ActivityStorePersistenceStage.beforeWrite, .beforeRename])
func activityStoreFailurePreservesExactBytesMemoryAndPublication(
    stage: ActivityStorePersistenceStage
) throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let baseline = ActivityStore(applicationSupport: root)
    _ = try baseline.addWaitingSynchronously(.backup, title: "Authoritative old row")
    let oldSnapshot = baseline.snapshot()
    let oldBytes = try Data(contentsOf: activityDocument(root))

    let store = ActivityStore(applicationSupport: root) { candidate in
        if candidate == stage { throw ActivityStoreInjectedFailure.requested }
    }
    var published = false
    store.onChange = { _ in published = true }
    store.addCompleted(.runtime, title: "Unpersisted new row")
    let after = store.snapshot()

    #expect(after == oldSnapshot)
    #expect(store.status() == .unavailable(.persistenceFailed))
    #expect(try Data(contentsOf: activityDocument(root)) == oldBytes)
    #expect(published == false)
    let temporaryNames = try FileManager.default.contentsOfDirectory(atPath: activityDirectory(root).path)
        .filter { $0.hasPrefix(".activities.") && $0.hasSuffix(".tmp") }
    #expect(temporaryNames.isEmpty)
}

@Test(arguments: [ActivityStorePersistenceStage.afterRename, .beforeDirectorySync])
func activityStorePostRenameFailureAdoptsCommittedBytesAndFailsClosed(
    stage: ActivityStorePersistenceStage
) throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let baseline = ActivityStore(applicationSupport: root)
    _ = try baseline.addWaitingSynchronously(.backup, title: "Authoritative old row")
    let oldBytes = try Data(contentsOf: activityDocument(root))

    let store = ActivityStore(applicationSupport: root) { candidate in
        if candidate == stage { throw ActivityStoreInjectedFailure.requested }
    }
    store.addCompleted(.runtime, title: "Namespace-committed new row")

    let snapshot = store.snapshot()
    let newBytes = try Data(contentsOf: activityDocument(root))
    #expect(store.status() == .unavailable(.persistenceFailed))
    #expect(snapshot.first?.title == "Namespace-committed new row")
    #expect(newBytes != oldBytes)

    let reopened = ActivityStore(applicationSupport: root)
    #expect(reopened.status() == .available)
    #expect(reopened.snapshot() == snapshot)
}

@Test
func activityStoreSynchronousFailureLeavesOldBytesAndMemoryUnchanged() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let baseline = ActivityStore(applicationSupport: root)
    _ = try baseline.addWaitingSynchronously(.backup, title: "Existing row")
    let oldBytes = try Data(contentsOf: activityDocument(root))
    let oldSnapshot = baseline.snapshot()

    let store = ActivityStore(applicationSupport: root) { stage in
        if stage == .beforeRename { throw ActivityStoreInjectedFailure.requested }
    }
    do {
        _ = try store.addWaitingSynchronously(.backup, title: "Must not appear")
        Issue.record("Expected the injected persistence failure")
    } catch let error as ActivityStoreError {
        #expect(error == .unavailable(.persistenceFailed))
    }

    #expect(store.snapshot() == oldSnapshot)
    #expect(try Data(contentsOf: activityDocument(root)) == oldBytes)
    #expect(store.status() == .unavailable(.persistenceFailed))
}

@Test
func activityStoreSynchronousPostRenameFailureNeverReportsStaleMemory() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let baseline = ActivityStore(applicationSupport: root)
    _ = try baseline.addWaitingSynchronously(.backup, title: "Existing row")

    let store = ActivityStore(applicationSupport: root) { stage in
        if stage == .beforeDirectorySync { throw ActivityStoreInjectedFailure.requested }
    }
    do {
        _ = try store.addWaitingSynchronously(.backup, title: "Committed but not durable")
        Issue.record("Expected the injected post-rename durability failure")
    } catch let error as ActivityStoreError {
        #expect(error == .unavailable(.persistenceFailed))
    }

    #expect(store.status() == .unavailable(.persistenceFailed))
    #expect(store.snapshot().first?.title == "Committed but not durable")
    let reopened = ActivityStore(applicationSupport: root)
    #expect(reopened.snapshot() == store.snapshot())
}

@Test
func activityStoreInterruptedRepairFailurePreservesOriginalRunningRecordAndBytes() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let running = activityFixture(state: .running, progress: 0.25)
    try installActivityFixture([running], at: root)
    let oldBytes = try Data(contentsOf: activityDocument(root))

    let store = ActivityStore(applicationSupport: root) { stage in
        if stage == .beforeRename { throw ActivityStoreInjectedFailure.requested }
    }
    #expect(store.status() == .unavailable(.persistenceFailed))
    #expect(store.snapshot() == [running])
    #expect(try Data(contentsOf: activityDocument(root)) == oldBytes)
}

@Test
func activityStoreDetectsDestinationReplacementBeforeMutation() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ActivityStore(applicationSupport: root)
    _ = try store.addWaitingSynchronously(.backup, title: "Persisted row")
    let oldSnapshot = store.snapshot()
    try FileManager.default.removeItem(at: activityDocument(root))
    let outside = root.appendingPathComponent("outside.json")
    let outsideBytes = Data("outside must remain exact".utf8)
    try outsideBytes.write(to: outside)
    try FileManager.default.createSymbolicLink(at: activityDocument(root), withDestinationURL: outside)

    store.addCompleted(.runtime, title: "Must not replace link")
    #expect(store.snapshot() == oldSnapshot)
    #expect(store.status() == .unavailable(.unsafeStorage))
    #expect(try Data(contentsOf: outside) == outsideBytes)
}

@Test
func activityStoreFailsClosedWhenApplicationSupportIsDisplacedBetweenCalls() throws {
    let root = try makeActivityRoot()
    let displaced = root.deletingLastPathComponent()
        .appendingPathComponent("activity-store-displaced-\(UUID().uuidString)", isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: displaced)
    }
    let store = ActivityStore(applicationSupport: root)
    _ = try store.addWaitingSynchronously(.backup, title: "Pinned original history")
    let oldSnapshot = store.snapshot()

    try FileManager.default.moveItem(at: root, to: displaced)
    try FileManager.default.createDirectory(
        at: activityDirectory(root),
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: root.path
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: activityDirectory(root).path
    )
    let replacement = activityDocument(root)
    FileManager.default.createFile(
        atPath: replacement.path,
        contents: Data(),
        attributes: [.posixPermissions: 0o600]
    )

    store.addCompleted(.runtime, title: "Must not enter replacement root")

    #expect(store.snapshot() == oldSnapshot)
    #expect(store.status() == .unavailable(.unsafeStorage))
    #expect(try Data(contentsOf: replacement).isEmpty)
    let displacedBytes = try Data(contentsOf: activityDocument(displaced))
    #expect(!String(decoding: displacedBytes, as: UTF8.self).contains("Must not enter replacement root"))
}

@Test
func activityStoreRejectsAZeroByteDocumentReplacementBetweenCalls() throws {
    let root = try makeActivityRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ActivityStore(applicationSupport: root)
    _ = try store.addWaitingSynchronously(.backup, title: "Pinned document")
    let oldSnapshot = store.snapshot()

    try FileManager.default.removeItem(at: activityDocument(root))
    let replacementDescriptor = Darwin.open(
        activityDocument(root).path,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        mode_t(0o600)
    )
    #expect(replacementDescriptor >= 0)
    guard replacementDescriptor >= 0 else { return }
    defer { _ = Darwin.close(replacementDescriptor) }

    store.addCompleted(.runtime, title: "Must not enter replacement document")

    var replacementMetadata = stat()
    #expect(Darwin.fstat(replacementDescriptor, &replacementMetadata) == 0)
    #expect(replacementMetadata.st_size == 0)
    #expect(store.snapshot() == oldSnapshot)
    #expect(store.status() == .unavailable(.unsafeStorage))
    #expect(try Data(contentsOf: activityDocument(root)).isEmpty)
}

@Test
func activityCenterPresentationDisclosesUnavailableUnpersistedHistory() {
    let ready = ActivityCenterStoragePresentation.make(status: .available)
    #expect(ready.allowsClearing)
    #expect(ready.isFailure == false)

    let failed = ActivityCenterStoragePresentation.make(status: .unavailable(.persistenceFailed))
    #expect(failed.allowsClearing == false)
    #expect(failed.isFailure)
    #expect(failed.message.contains("unavailable"))
    #expect(failed.message.contains("not being saved"))
}
