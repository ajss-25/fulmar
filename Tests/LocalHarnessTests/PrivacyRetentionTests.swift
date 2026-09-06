import AppKit
import CryptoKit
import Darwin
import Foundation
import Testing
import LocalHarnessDeviceAttestation
@testable import LocalHarness

@Test func appshotRetentionPurgesExpiredRegularFilesAndRetainsUnknownEntries() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let appshots = root.appendingPathComponent("Appshots", isDirectory: true)
    try FileManager.default.createDirectory(at: appshots, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let old = appshots.appendingPathComponent("old.png")
    let fresh = appshots.appendingPathComponent("fresh.png")
    let directory = appshots.appendingPathComponent("not-an-appshot", isDirectory: true)
    let outside = root.appendingPathComponent("outside.png")
    let link = appshots.appendingPathComponent("linked.png")
    try Data("old".utf8).write(to: old)
    try Data("fresh".utf8).write(to: fresh)
    try Data("outside".utf8).write(to: outside)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
    try FileManager.default.setAttributes([.modificationDate: now.addingTimeInterval(-8 * 86_400)], ofItemAtPath: old.path)
    try FileManager.default.setAttributes([.modificationDate: now.addingTimeInterval(-2 * 86_400)], ofItemAtPath: fresh.path)

    let result = AppshotController(directory: appshots, retentionDays: { 7 }).purgeExpiredCaptures(now: now)

    #expect(result == AppshotPurgeResult(examined: 4, removed: 1, retained: 3, failures: 0))
    #expect(!FileManager.default.fileExists(atPath: old.path))
    #expect(FileManager.default.fileExists(atPath: fresh.path))
    #expect(FileManager.default.fileExists(atPath: link.path))
    #expect(FileManager.default.fileExists(atPath: directory.path))
}

@Test func appshotRetentionRefusesASymlinkedStore() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let outside = root.appendingPathComponent("outside", isDirectory: true)
    let link = root.appendingPathComponent("Appshots", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let capture = outside.appendingPathComponent("old.png")
    try Data("must remain".utf8).write(to: capture)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)

    let result = AppshotController(directory: link, retentionDays: { 1 })
        .purgeExpiredCaptures(now: Date.distantFuture)

    #expect(result == AppshotPurgeResult(failures: 1))
    #expect(try String(contentsOf: capture, encoding: .utf8) == "must remain")
}

@Test func appshotRetentionFailsClosedWhenEntryOrByteBudgetIsExceeded() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let appshots = root.appendingPathComponent("Appshots", isDirectory: true)
    try FileManager.default.createDirectory(at: appshots, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let first = appshots.appendingPathComponent("first.png")
    let second = appshots.appendingPathComponent("second.png")
    try Data(repeating: 1, count: 8).write(to: first)
    try Data(repeating: 2, count: 8).write(to: second)
    try FileManager.default.setAttributes([.modificationDate: now.addingTimeInterval(-30 * 86_400)], ofItemAtPath: first.path)
    try FileManager.default.setAttributes([.modificationDate: now.addingTimeInterval(-30 * 86_400)], ofItemAtPath: second.path)

    let entryBound = AppshotController(
        directory: appshots,
        retentionDays: { 1 },
        retentionLimits: AppshotRetentionLimits(maximumEntries: 1, maximumAggregateBytes: 1_024, scanDuration: 1)
    ).purgeExpiredCaptures(now: now)
    #expect(entryBound.failures == 1)
    #expect(FileManager.default.fileExists(atPath: first.path))
    #expect(FileManager.default.fileExists(atPath: second.path))

    let byteBound = AppshotController(
        directory: appshots,
        retentionDays: { 1 },
        retentionLimits: AppshotRetentionLimits(maximumEntries: 10, maximumAggregateBytes: 12, scanDuration: 1)
    ).purgeExpiredCaptures(now: now)
    #expect(byteBound.failures == 1)
    #expect(FileManager.default.fileExists(atPath: first.path))
    #expect(FileManager.default.fileExists(atPath: second.path))
}

@Test func appshotPersistencePublishesPrivateNoReplacePNGs() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let appshots = root.appendingPathComponent("Appshots", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let image = NSImage(size: NSSize(width: 4, height: 4), flipped: false) { bounds in
        NSColor.systemBlue.setFill()
        bounds.fill()
        return true
    }
    let controller = AppshotController(directory: appshots, retentionDays: { 7 })

    let first = try controller.persistReviewed(
        image,
        suggestedFilename: "../\u{202E} private/appshot.png"
    )
    let second = try controller.persistReviewed(
        image,
        suggestedFilename: "../\u{202E} private/appshot.png"
    )

    #expect(first.deletingLastPathComponent() == appshots)
    #expect(second.deletingLastPathComponent() == appshots)
    #expect(first != second)
    #expect(first.pathExtension == "png")
    #expect(second.pathExtension == "png")
    #expect(privateMode(of: appshots) == 0o700)
    #expect(privateMode(of: first) == 0o600)
    #expect(privateMode(of: second) == 0o600)
    #expect(try Data(contentsOf: first).starts(with: [0x89, 0x50, 0x4E, 0x47]))
    #expect(try FileManager.default.contentsOfDirectory(atPath: appshots.path)
        .filter { $0.hasPrefix(".appshot.") }.isEmpty)
}

@Test func appshotPersistenceRejectsASymlinkedStoreWithoutWritingOutside() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let outside = root.appendingPathComponent("outside", isDirectory: true)
    let appshots = root.appendingPathComponent("Appshots", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: appshots, withDestinationURL: outside)
    defer { try? FileManager.default.removeItem(at: root) }
    let image = NSImage(size: NSSize(width: 2, height: 2), flipped: false) { bounds in
        NSColor.systemRed.setFill()
        bounds.fill()
        return true
    }

    #expect(throws: AppshotController.CaptureError.self) {
        _ = try AppshotController(directory: appshots)
            .persistReviewed(image, suggestedFilename: "private.png")
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
}

@Test func privacyLedgerPurgesExportsAndClearsWithPrivatePermissions() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let ledger = PrivacyLedger(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    ledger.record(.runtimeStarted, summary: "old local", localOnly: true, occurredAt: now.addingTimeInterval(-100 * 86_400))
    ledger.record(.externalLinkOpened, summary: "new external", localOnly: false, occurredAt: now.addingTimeInterval(-2 * 86_400))
    #expect(ledger.counts().valid == 2) // Flushes the ledger's serial writer.

    let ledgerURL = root.appendingPathComponent("Privacy/events.jsonl")
    let handle = try FileHandle(forWritingTo: ledgerURL)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("{malformed}\n".utf8))
    try handle.close()

    #expect(ledger.counts() == PrivacyLedgerCounts(valid: 2, local: 1, external: 1, invalid: 1))
    let purge = try ledger.purgeExpired(now: now, retentionDays: 90)
    #expect(purge == PrivacyLedgerPurgeResult(examined: 3, removed: 1, retained: 2, invalidRetained: 1, failure: nil))
    #expect(ledger.counts() == PrivacyLedgerCounts(valid: 1, local: 0, external: 1, invalid: 1))

    let jsonURL = root.appendingPathComponent("exports/ledger.json")
    let jsonResult = try ledger.export(to: jsonURL, format: .json)
    #expect(jsonResult.exported == 1)
    #expect(jsonResult.invalidSkipped == 1)
    #expect(try JSONDecoder().decode([PrivacyEvent].self, from: Data(contentsOf: jsonURL)).count == 1)
    #expect(privateMode(of: jsonURL) == 0o600)

    let jsonlURL = root.appendingPathComponent("exports/ledger.jsonl")
    let jsonlResult = try ledger.export(to: jsonlURL, format: .jsonl)
    #expect(jsonlResult.exported == 1)
    #expect(String(decoding: try Data(contentsOf: jsonlURL), as: UTF8.self).split(separator: "\n").count == 1)
    #expect(privateMode(of: jsonlURL) == 0o600)

    try ledger.clear()
    #expect(ledger.counts() == PrivacyLedgerCounts())
    #expect(privateMode(of: ledgerURL) == 0o600)
}

@Test func privacyLedgerAutomaticPurgeRefusesASymlinkedStore() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let privacy = root.appendingPathComponent("Privacy", isDirectory: true)
    let outside = root.appendingPathComponent("outside.jsonl")
    try preparePrivateLedgerDirectory(root)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("must remain\n".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(at: privacy.appendingPathComponent("events.jsonl"), withDestinationURL: outside)
    let ledger = PrivacyLedger(applicationSupport: root)

    #expect(ledger.counts().storageIssue)
    #expect(throws: CocoaError.self) {
        _ = try ledger.purgeExpired(now: Date.distantFuture)
    }
    #expect(try String(contentsOf: outside, encoding: .utf8) == "must remain\n")
}

@Test func privacyLedgerBoundsStorageRowsAndDurablyFlushesShutdownRecord() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let limits = PrivacyLedgerLimits(
        maximumFileBytes: 1_024,
        maximumRows: 8,
        maximumRowBytes: 512,
        maximumSummaryBytes: 7
    )
    let ledger = PrivacyLedger(applicationSupport: root, limits: limits)
    try ledger.recordSynchronously(
        .runtimeStopped,
        summary: "🔐private-finish",
        localOnly: true,
        occurredAt: Date(timeIntervalSinceReferenceDate: 800_000_000)
    )

    let reopened = PrivacyLedger(applicationSupport: root, limits: limits)
    let event = try #require(reopened.recent(limit: 1).first)
    #expect(event.kind == .runtimeStopped)
    #expect(event.summary == "🔐pri")
    #expect(Data(event.summary.utf8).count == 7)

    let ledgerURL = root.appendingPathComponent("Privacy/events.jsonl")
    let handle = try FileHandle(forWritingTo: ledgerURL)
    try handle.truncate(atOffset: 2_048)
    try handle.close()
    #expect(reopened.counts().storageIssue)
    #expect(throws: CocoaError.self) {
        _ = try reopened.purgeExpired(now: Date.distantFuture)
    }
}

@Test func privacyLedgerSanitizesHostileSummariesBeforePersistenceAndAfterLegacyDecode() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let ledger = PrivacyLedger(applicationSupport: root)
    let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
    let hostile = "api_key=sk-privacy-secret-123456789 \(home)/SecretProject \u{202E}\u{0007}" +
        String(repeating: "HOSTILE-PRIVACY-DIAGNOSTIC", count: 4_000)

    try ledger.recordSynchronously(.externalLinkOpened, summary: hostile, localOnly: false)
    let recorded = try #require(ledger.recent(limit: 1).first)
    #expect(!recorded.summary.contains("sk-privacy-secret"))
    #expect(!recorded.summary.contains(home))
    #expect(!recorded.summary.contains("\u{202E}"))
    #expect(!recorded.summary.contains("\u{0007}"))
    #expect(recorded.summary.count <= 4_096)

    let ledgerURL = root.appendingPathComponent("Privacy/events.jsonl")
    let persisted = String(decoding: try Data(contentsOf: ledgerURL), as: UTF8.self)
    #expect(!persisted.contains("sk-privacy-secret"))
    #expect(!persisted.contains(home))
    #expect(!persisted.contains(String(repeating: "HOSTILE-PRIVACY-DIAGNOSTIC", count: 4_000)))
    #expect(Data(recorded.summary.utf8).count <= PrivacyLedgerLimits.production.maximumSummaryBytes)

    // A legacy row must still satisfy the ledger's fail-closed row-size contract.
    // Legacy means it predates write-time sanitization, not that an attacker-sized
    // row is accepted into otherwise bounded persistent storage.
    let legacyHostile = "api_key=sk-legacy-privacy-secret-123456789 \(home)/LegacySecret \u{202E}\u{0007}" +
        String(repeating: "HOSTILE-LEGACY-DIAGNOSTIC", count: 64)

    let legacy = PrivacyEvent(
        id: UUID(),
        occurredAt: Date(),
        kind: .externalLinkOpened,
        summary: legacyHostile,
        localOnly: false
    )
    let encodedLegacy = try JSONEncoder().encode(legacy)
    #expect(encodedLegacy.count <= PrivacyLedgerLimits.production.maximumRowBytes)
    let handle = try FileHandle(forWritingTo: ledgerURL)
    try handle.seekToEnd()
    try handle.write(contentsOf: encodedLegacy + Data("\n".utf8))
    try handle.close()

    let decodedLegacy = try #require(ledger.recent(limit: 2).first { $0.id == legacy.id })
    let displayed = PrivacyLedger.safeSummaryForDisplay(decodedLegacy.summary)
    #expect(!displayed.contains("sk-legacy-privacy-secret"))
    #expect(!displayed.contains(home))
    #expect(!displayed.contains("\u{202E}"))
    #expect(!displayed.contains("\u{0007}"))
    #expect(displayed.count <= 512)
}

@Test func privacyLedgerAtomicallyRotatesAtProductionRowLimitAndByteCap() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let privacy = root.appendingPathComponent("Privacy", isDirectory: true)
    try preparePrivateLedgerDirectory(root)
    let ledgerURL = privacy.appendingPathComponent("events.jsonl")
    let encoder = JSONEncoder()
    let seed = PrivacyEvent(
        id: UUID(),
        occurredAt: Date(timeIntervalSinceReferenceDate: 800_000_000),
        kind: .runtimeStarted,
        summary: "seed",
        localOnly: true
    )
    var productionRows = Data()
    let encodedSeed = try encoder.encode(seed)
    for _ in 0..<PrivacyLedgerLimits.production.maximumRows {
        productionRows.append(encodedSeed)
        productionRows.append(0x0A)
    }
    #expect(productionRows.count < PrivacyLedgerLimits.production.maximumFileBytes)
    try productionRows.write(to: ledgerURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ledgerURL.path)

    let productionLedger = PrivacyLedger(applicationSupport: root)
    try productionLedger.recordSynchronously(.runtimeStopped, summary: "row-limit", localOnly: true)
    let productionCounts = productionLedger.counts()
    #expect(!productionCounts.storageIssue)
    #expect(productionCounts.valid < PrivacyLedgerLimits.production.maximumRows)
    #expect(productionLedger.recent(limit: 1).first?.kind == .runtimeStopped)

    let byteRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: byteRoot) }
    let bytePrivacy = byteRoot.appendingPathComponent("Privacy", isDirectory: true)
    try preparePrivateLedgerDirectory(byteRoot)
    let byteURL = bytePrivacy.appendingPathComponent("events.jsonl")
    let byteLimits = PrivacyLedgerLimits(
        maximumFileBytes: 4_096,
        maximumRows: 100,
        maximumRowBytes: 512,
        maximumSummaryBytes: 64
    )
    var full = Data()
    for _ in 0..<8 {
        full.append(Data(repeating: 0x78, count: 511))
        full.append(0x0A)
    }
    #expect(full.count == byteLimits.maximumFileBytes)
    try full.write(to: byteURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: byteURL.path)

    let byteLedger = PrivacyLedger(applicationSupport: byteRoot, limits: byteLimits)
    try byteLedger.recordSynchronously(.runtimeStopped, summary: "byte-limit", localOnly: true)
    #expect(!byteLedger.counts().storageIssue)
    #expect(byteLedger.recent(limit: 1).first?.kind == .runtimeStopped)
    let size = try #require(byteURL.resourceValues(forKeys: [.fileSizeKey]).fileSize)
    #expect(size <= byteLimits.maximumFileBytes)
}

@Test(arguments: [
    PrivacyLedgerPersistenceStage.beforeWrite,
    .beforeRename,
    .afterRename,
    .beforeDirectorySync
])
func privacyLedgerFirstCreateDistinguishesPrecommitFromCommittedFailureAndRelaunch(
    stage: PrivacyLedgerPersistenceStage
) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let ledger = PrivacyLedger(applicationSupport: root) { candidate in
        if candidate == stage { throw PrivacyLedgerInjectedFailure.requested }
    }
    var failed = false
    do {
        try ledger.recordSynchronously(.runtimeStopped, summary: "first durable row", localOnly: true)
    } catch {
        failed = true
    }
    #expect(failed)

    let ledgerURL = root.appendingPathComponent("Privacy/events.jsonl")
    let postCommit = stage == .afterRename || stage == .beforeDirectorySync
    #expect(FileManager.default.fileExists(atPath: ledgerURL.path) == postCommit)
    #expect(ledger.counts().storageIssue == postCommit)
    let temporaryNames = try FileManager.default.contentsOfDirectory(atPath: ledgerURL.deletingLastPathComponent().path)
        .filter { $0.hasPrefix(".events.") && $0.hasSuffix(".tmp") }
    #expect(temporaryNames.isEmpty)

    let reopened = PrivacyLedger(applicationSupport: root)
    #expect(!reopened.counts().storageIssue)
    #expect(reopened.recent(limit: 1).first?.summary == (postCommit ? "first durable row" : nil))
}

@Test(arguments: [
    PrivacyLedgerPersistenceStage.beforeWrite,
    .beforeRename,
    .afterRename,
    .beforeDirectorySync
])
func privacyLedgerFullRotationPreservesOrAdoptsExactNamespaceCommitAndRelaunch(
    stage: PrivacyLedgerPersistenceStage
) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let limits = PrivacyLedgerLimits(
        maximumFileBytes: 4_096,
        maximumRows: 3,
        maximumRowBytes: 1_024,
        maximumSummaryBytes: 128
    )
    let baseline = PrivacyLedger(applicationSupport: root, limits: limits)
    for index in 1...3 {
        try baseline.recordSynchronously(
            .runtimeStarted,
            summary: "authoritative old row \(index)",
            localOnly: true
        )
    }
    let ledgerURL = root.appendingPathComponent("Privacy/events.jsonl")
    let oldBytes = try Data(contentsOf: ledgerURL)
    let oldEvents = baseline.recent(limit: 10)

    let ledger = PrivacyLedger(
        applicationSupport: root,
        limits: limits,
        persistenceFailureInjector: { candidate in
            if candidate == stage { throw PrivacyLedgerInjectedFailure.requested }
        }
    )
    var failed = false
    do {
        try ledger.recordSynchronously(.runtimeStopped, summary: "rotated committed row", localOnly: true)
    } catch {
        failed = true
    }
    #expect(failed)

    let postCommit = stage == .afterRename || stage == .beforeDirectorySync
    let currentBytes = try Data(contentsOf: ledgerURL)
    #expect((currentBytes != oldBytes) == postCommit)
    #expect(ledger.counts().storageIssue == postCommit)
    let reopened = PrivacyLedger(applicationSupport: root, limits: limits)
    #expect(!reopened.counts().storageIssue)
    if postCommit {
        #expect(reopened.recent(limit: 1).first?.summary == "rotated committed row")
        #expect(reopened.recent(limit: 10) != oldEvents)
    } else {
        #expect(reopened.recent(limit: 10) == oldEvents)
    }
}

@Test func privacyLedgerRefusesPermissiveOrLinkedStorageWithoutPathBasedRepair() throws {
    let permissiveRoot = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: permissiveRoot) }
    try preparePrivateLedgerDirectory(permissiveRoot)
    let privacy = permissiveRoot.appendingPathComponent("Privacy", isDirectory: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: privacy.path)
    let permissive = PrivacyLedger(applicationSupport: permissiveRoot)
    #expect(throws: (any Error).self) {
        try permissive.recordSynchronously(.runtimeStarted, summary: "must not save", localOnly: true)
    }
    #expect(privateMode(of: privacy) == 0o755)

    let linkedRoot = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: linkedRoot) }
    try FileManager.default.createDirectory(
        at: linkedRoot,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    let outside = linkedRoot.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(
        at: outside,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.createSymbolicLink(
        at: linkedRoot.appendingPathComponent("Privacy", isDirectory: true),
        withDestinationURL: outside
    )
    let linked = PrivacyLedger(applicationSupport: linkedRoot)
    #expect(throws: (any Error).self) {
        try linked.recordSynchronously(.runtimeStarted, summary: "must not escape", localOnly: true)
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
}

@Test func attachmentRetentionDeletesOnlyExpiredUnreferencedObjects() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let referenced = try addAttachment(Data("referenced".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let expired = try addAttachment(Data("expired".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let fresh = try addAttachment(Data("fresh".utf8), to: root, modified: now.addingTimeInterval(-2 * 86_400))
    try addRawSession(to: root, jsonObject: ["attachmentId": "sha256:\(referenced.digest)"])

    let report = AttachmentRetentionManager(
        harnessHome: root,
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)

    #expect(report == AttachmentRetentionReport(status: .completed, examined: 3, referenced: 1, eligible: 1, deleted: 1, retained: 2, failures: 0))
    #expect(FileManager.default.fileExists(atPath: referenced.url.path))
    #expect(!FileManager.default.fileExists(atPath: expired.url.path))
    #expect(FileManager.default.fileExists(atPath: fresh.url.path))
}

@Test func attachmentRetentionAcceptsExactCurrentPrivacyEpochReceipt() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let source = root.deletingLastPathComponent()
        .appendingPathComponent("HarnessHomeRecovery", isDirectory: true)
        .appendingPathComponent(
            "receiptless-00000000-0000-0000-0000-000000000001",
            isDirectory: true
        ).path
    try prepareOwnedHarnessHome(
        root,
        source: source,
        copiedEntries: ["settings.yaml"]
    )
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("strict-valid-expired".utf8),
        to: root,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: root, jsonObject: ["type": "header"])

    let report = AttachmentRetentionManager(
        harnessHome: root,
        allowUnattestedHarnessHomeForTesting: true
    )
        .purgeExpired(retentionDays: 30, now: now)

    #expect(report.deleted == 1)
    #expect(!FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionAttestationRejectsPermissiveDirectoryChainAndLinkedReceipt() throws {
    try assertHarnessHomeAttestationRejected { root in
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
    }
    try assertHarnessHomeAttestationRejected { root in
        let receipt = root.appendingPathComponent(".local-harness-home.json")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: receipt.path)
    }
    try assertHarnessHomeAttestationRejected { root in
        let receipt = root.appendingPathComponent(".local-harness-home.json")
        let bytes = try Data(contentsOf: receipt)
        let outside = root.appendingPathComponent("hard-link-source.json")
        try bytes.write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
        try FileManager.default.removeItem(at: receipt)
        guard Darwin.link(outside.path, receipt.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
    try assertHarnessHomeAttestationRejected { root in
        let receipt = root.appendingPathComponent(".local-harness-home.json")
        let outside = root.appendingPathComponent("symlink-source.json")
        try Data("{}".utf8).write(to: outside)
        try FileManager.default.removeItem(at: receipt)
        try FileManager.default.createSymbolicLink(at: receipt, withDestinationURL: outside)
    }

    let container = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let root = container.appendingPathComponent("HarnessHome", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: container) }
    try FileManager.default.createDirectory(
        at: container,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("parent-permission-expired".utf8),
        to: root,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: root, jsonObject: ["type": "header"])
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: container.path)
    let report = AttachmentRetentionManager(
        harnessHome: root,
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)
    guard case .unsupported = report.status else {
        Issue.record("Expected a permissive ownership-chain parent to fail closed")
        return
    }
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionAttestationRejectsSparseOversizeAndStrictSchemaViolations() throws {
    try assertHarnessHomeAttestationRejected { root in
        let receipt = root.appendingPathComponent(".local-harness-home.json")
        try FileManager.default.removeItem(at: receipt)
        let descriptor = Darwin.open(
            receipt.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { _ = Darwin.close(descriptor) }
        guard ftruncate(descriptor, off_t(64 * 1_024 + 1)) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    let invalidReceipts: [[String: Any]] = [
        [
            "version": 1,
            "migratedAt": 0.0,
            "copiedEntries": [String](),
            "unexpected": true
        ],
        [
            "version": 1,
            "migratedAt": 0.0,
            "copiedEntries": ["sessions"],
            "source": "/not/the/reviewed/legacy/home"
        ],
        [
            "version": 1,
            "migratedAt": 0.0,
            "copiedEntries": ["storages", "sessions"],
            "source": FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".dsh", isDirectory: true).path
        ],
        [
            "version": 2,
            "migratedAt": 0.0,
            "copiedEntries": [String]()
        ]
    ]
    for object in invalidReceipts {
        try assertHarnessHomeAttestationRejected { root in
            let receipt = root.appendingPathComponent(".local-harness-home.json")
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: receipt)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
        }
    }
}

@Test func attachmentRetentionAttestationRejectsDeterministicReceiptSymlinkSwap() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("swap-expired".utf8),
        to: root,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: root, jsonObject: ["type": "header"])
    let receipt = root.appendingPathComponent(".local-harness-home.json")
    let outside = root.appendingPathComponent("replacement.json")
    try Data(contentsOf: receipt).write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    var swapped = false

    let report = AttachmentRetentionManager(
        harnessHome: root,
        ownershipReceiptInspectionHook: {
            guard !swapped else { return }
            do {
                try FileManager.default.removeItem(at: receipt)
                try FileManager.default.createSymbolicLink(at: receipt, withDestinationURL: outside)
                swapped = true
            } catch {
                swapped = false
            }
        },
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)

    #expect(swapped)
    guard case .unsupported = report.status else {
        Issue.record("Expected the attestation receipt swap to fail closed")
        return
    }
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionFailsClosedForUnknownLayout() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(Data("expired".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    try addRawSession(to: root, jsonObject: ["type": "header"])
    try Data("unknown".utf8).write(to: root.appendingPathComponent("attachments/v1/metadata.bin"))

    let report = AttachmentRetentionManager(
        harnessHome: root,
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)

    guard case .unsupported = report.status else {
        Issue.record("Expected unsupported retention status")
        return
    }
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionNeverDeletesWhenCompressedHistoryCannotBeVerified() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(Data("expired".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let session = root.appendingPathComponent("sessions/project/session", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    try Data([0x28, 0xB5, 0x2F, 0xFD]).write(to: session.appendingPathComponent("session.jsonl.zstd"))

    let report = AttachmentRetentionManager(
        harnessHome: root,
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)

    guard case .unsupported = report.status else {
        Issue.record("Expected unsupported retention status")
        return
    }
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionNeverPromotesIsolatedDecoderStderrIntoPrivacyStatus() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("expired".utf8),
        to: root,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    let session = root.appendingPathComponent("sessions/project/session", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    try Data([0x28, 0xB5, 0x2F, 0xFD]).write(to: session.appendingPathComponent("session.jsonl.zstd"))

    let fakeNode = root.appendingPathComponent("hostile-node")
    let stderr = "sk-decoder-secret-123456789 /Users/private/decoder \u{202E}\u{0007}" +
        String(repeating: "HOSTILE-DECODER-DIAGNOSTIC", count: 1_000)
    try Data("#!/bin/sh\nprintf '%s' '\(stderr)' >&2\nexit 23\n".utf8).write(to: fakeNode)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeNode.path)

    let report = AttachmentRetentionManager(
        harnessHome: root,
        trustedNode: fakeNode,
        allowUnattestedHarnessHomeForTesting: true
    )
        .purgeExpired(retentionDays: 30, now: now)
    guard case .unsupported(let message) = report.status else {
        Issue.record("Expected a closed compressed-history failure")
        return
    }
    #expect(message == "Compressed session history is incomplete or invalid; nothing was deleted.")
    #expect(!message.contains("sk-decoder-secret"))
    #expect(!message.contains("/Users/private"))
    #expect(!message.contains("HOSTILE-DECODER-DIAGNOSTIC"))
    #expect(!message.contains("\u{202E}"))
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionReadsEveryConcatenatedZstdFrame() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let referenced = try addAttachment(Data("referenced-zstd".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let expired = try addAttachment(Data("expired-zstd".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let session = root.appendingPathComponent("sessions/project/session", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    let log = session.appendingPathComponent("session.jsonl.zstd")
    let node = projectRoot()
        .appendingPathComponent("VendorRuntime/node-v22.23.1-darwin-arm64/bin/node")
    #expect(FileManager.default.isExecutableFile(atPath: node.path))
    try writeConcatenatedZstdLog(to: log, reference: referenced.digest, node: node)

    let report = AttachmentRetentionManager(
        harnessHome: root,
        trustedNode: node,
        allowUnattestedHarnessHomeForTesting: true
    )
        .purgeExpired(retentionDays: 30, now: now)

    #expect(report == AttachmentRetentionReport(status: .completed, examined: 2, referenced: 1, eligible: 1, deleted: 1, retained: 1, failures: 0))
    #expect(FileManager.default.fileExists(atPath: referenced.url.path))
    #expect(!FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionRejectsOversizedRawLogsWithoutDeleting() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(Data("expired".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let session = root.appendingPathComponent("sessions/project/session", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    let log = session.appendingPathComponent("session.jsonl")
    FileManager.default.createFile(atPath: log.path, contents: nil)
    let handle = try FileHandle(forWritingTo: log)
    try handle.truncate(atOffset: 4_096)
    try handle.close()

    let report = AttachmentRetentionManager(
        harnessHome: root,
        limits: testAttachmentLimits(maximumLogBytes: 512),
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)
    guard case .unsupported = report.status else {
        Issue.record("Expected a bounded unsupported result")
        return
    }
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionCountsUTF8BytesAndHonoursWholeScanDeadline() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(Data("expired".utf8), to: root, modified: now.addingTimeInterval(-45 * 86_400))
    let session = root.appendingPathComponent("sessions/project/session", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    try Data("{\"value\":\"😀😀😀😀😀😀😀😀\"}\n".utf8)
        .write(to: session.appendingPathComponent("session.jsonl"))

    let byteReport = AttachmentRetentionManager(
        harnessHome: root,
        limits: testAttachmentLimits(maximumJSONLRowBytes: 24),
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)
    guard case .unsupported = byteReport.status else {
        Issue.record("Expected an oversized UTF-8 row to be rejected")
        return
    }
    #expect(byteReport.deleted == 0)

    try FileManager.default.removeItem(at: session.appendingPathComponent("session.jsonl"))
    try Data([0x28, 0xB5, 0x2F, 0xFD]).write(to: session.appendingPathComponent("session.jsonl.zstd"))
    let deadlineReport = AttachmentRetentionManager(
        harnessHome: root,
        zstdReferenceReader: { _ in
            Thread.sleep(forTimeInterval: 0.08)
            return []
        },
        limits: testAttachmentLimits(scanDuration: 0.05),
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)
    guard case .unsupported = deadlineReport.status else {
        Issue.record("Expected the whole-scan deadline to fail closed")
        return
    }
    #expect(deadlineReport.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionUsesTheSignedBorrowedHarnessHomeCapability() throws {
    guard let account = getpwuid(geteuid()),
          let homePointer = account.pointee.pw_dir else {
        throw CocoaError(.fileNoSuchFile)
    }
    let caches = URL(fileURLWithPath: String(cString: homePointer), isDirectory: true)
        .appendingPathComponent("Library/Caches", isDirectory: true)
    let container = caches.appendingPathComponent(
        "signed-retention-\(UUID().uuidString)",
        isDirectory: true
    )
    let home = container.appendingPathComponent("HarnessHome", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: container) }
    try FileManager.default.createDirectory(
        at: container,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try prepareOwnedHarnessHome(home)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("signed-expired".utf8),
        to: home,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: home, jsonObject: ["type": "header"])
    let keyStore = LocalHarnessTestDeviceAttestationKeyStore()
    let authority = try ProviderHistoryDeviceAttestation.openForeground(
        applicationSupport: container,
        keyStore: keyStore
    )
    let capability = try authority.makeHarnessHomeAttestationStore().establishCurrent(
        rootURL: home,
        receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
        privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current)
    )

    let report = AttachmentRetentionManager(
        harnessHome: home,
        harnessHomeCapabilityProvider: { capability }
    ).purgeExpired(retentionDays: 30, now: now)

    #expect(report.deleted == 1)
    #expect(!FileManager.default.fileExists(atPath: expired.url.path))
}

@Test func attachmentRetentionRejectsRootAndObjectStoreDisplacementWithoutDeletingReplacement() throws {
    do {
        let container = FileManager.default.temporaryDirectory.appendingPathComponent(
            "retention-root-swap-\(UUID().uuidString)",
            isDirectory: true
        )
        let home = container.appendingPathComponent("HarnessHome", isDirectory: true)
        let displaced = container.appendingPathComponent("HarnessHome-original", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: container) }
        try FileManager.default.createDirectory(
            at: container,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try prepareOwnedHarnessHome(home)
        let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
        let expired = try addAttachment(
            Data("root-swap-expired".utf8),
            to: home,
            modified: now.addingTimeInterval(-45 * 86_400)
        )
        try addRawSession(to: home, jsonObject: ["type": "header"])
        var swapped = false
        let report = AttachmentRetentionManager(
            harnessHome: home,
            descriptorInspectionHook: { point in
                guard point == .homeVerified, !swapped else { return }
                do {
                    try FileManager.default.moveItem(at: home, to: displaced)
                    try FileManager.default.createDirectory(
                        at: home,
                        withIntermediateDirectories: false,
                        attributes: [.posixPermissions: 0o700]
                    )
                    swapped = true
                } catch {}
            },
            allowUnattestedHarnessHomeForTesting: true
        ).purgeExpired(retentionDays: 30, now: now)
        #expect(swapped)
        #expect(report.deleted == 0)
        #expect(FileManager.default.fileExists(
            atPath: displaced.appendingPathComponent(
                expired.url.path.replacingOccurrences(of: home.path + "/", with: "")
            ).path
        ))
        #expect(try FileManager.default.contentsOfDirectory(atPath: home.path).isEmpty)
    }
    do {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(
            "retention-store-swap-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: home) }
        try prepareOwnedHarnessHome(home)
        let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
        let expired = try addAttachment(
            Data("store-swap-expired".utf8),
            to: home,
            modified: now.addingTimeInterval(-45 * 86_400)
        )
        try addRawSession(to: home, jsonObject: ["type": "header"])
        let version = home.appendingPathComponent("attachments/v1", isDirectory: true)
        let objects = version.appendingPathComponent("objects", isDirectory: true)
        let displaced = version.appendingPathComponent("objects-original", isDirectory: true)
        var swapped = false
        let report = AttachmentRetentionManager(
            harnessHome: home,
            descriptorInspectionHook: { point in
                guard point == .objectsScanned, !swapped else { return }
                do {
                    try FileManager.default.moveItem(at: objects, to: displaced)
                    try FileManager.default.createDirectory(
                        at: objects,
                        withIntermediateDirectories: false,
                        attributes: [.posixPermissions: 0o700]
                    )
                    swapped = true
                } catch {}
            },
            allowUnattestedHarnessHomeForTesting: true
        ).purgeExpired(retentionDays: 30, now: now)
        #expect(swapped)
        #expect(report.deleted == 0)
        #expect(FileManager.default.fileExists(
            atPath: displaced
                .appendingPathComponent(expired.digest.prefix(2).description, isDirectory: true)
                .appendingPathComponent(expired.digest).path
        ))
        #expect(try FileManager.default.contentsOfDirectory(atPath: objects.path).isEmpty)
    }
}

@Test func attachmentRetentionRejectsCandidateAndReceiptSwapBeforeUnlink() throws {
    do {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(
            "retention-file-swap-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: home) }
        try prepareOwnedHarnessHome(home)
        let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
        let expired = try addAttachment(
            Data("file-swap-expired".utf8),
            to: home,
            modified: now.addingTimeInterval(-45 * 86_400)
        )
        try addRawSession(to: home, jsonObject: ["type": "header"])
        let displaced = expired.url.deletingLastPathComponent().appendingPathComponent("original-object")
        var swapped = false
        let replacement = Data("replacement-must-remain".utf8)
        let report = AttachmentRetentionManager(
            harnessHome: home,
            descriptorInspectionHook: { point in
                guard point == .beforeCandidateQuarantine, !swapped else { return }
                do {
                    try FileManager.default.moveItem(at: expired.url, to: displaced)
                    try replacement.write(to: expired.url)
                    swapped = true
                } catch {}
            },
            allowUnattestedHarnessHomeForTesting: true
        ).purgeExpired(retentionDays: 30, now: now)
        #expect(swapped)
        #expect(report.deleted == 0)
        #expect(try Data(contentsOf: expired.url) == replacement)
        #expect(FileManager.default.fileExists(atPath: displaced.path))
    }
    do {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(
            "retention-receipt-swap-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: home) }
        try prepareOwnedHarnessHome(home)
        let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
        let expired = try addAttachment(
            Data("receipt-swap-expired".utf8),
            to: home,
            modified: now.addingTimeInterval(-45 * 86_400)
        )
        try addRawSession(to: home, jsonObject: ["type": "header"])
        let receipt = home.appendingPathComponent(ProviderHistoryPrivacyEpoch.ownershipReceiptName)
        var swapped = false
        let report = AttachmentRetentionManager(
            harnessHome: home,
            descriptorInspectionHook: { point in
                guard point == .beforeCandidateUnlink, !swapped else { return }
                do {
                    try Data("changed-receipt".utf8).write(to: receipt, options: .atomic)
                    try FileManager.default.setAttributes(
                        [.posixPermissions: 0o600],
                        ofItemAtPath: receipt.path
                    )
                    swapped = true
                } catch {}
            },
            allowUnattestedHarnessHomeForTesting: true
        ).purgeExpired(retentionDays: 30, now: now)
        #expect(swapped)
        #expect(report.deleted == 0)
        #expect(FileManager.default.fileExists(atPath: expired.url.path))
    }
}

@Test func attachmentRetentionRejectsHardlinkedObjects() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(
        "retention-hardlink-\(UUID().uuidString)",
        isDirectory: true
    )
    defer { try? FileManager.default.removeItem(at: home) }
    try prepareOwnedHarnessHome(home)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("hardlinked-expired".utf8),
        to: home,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: home, jsonObject: ["type": "header"])
    let alias = home.appendingPathComponent("hardlink-alias")
    #expect(Darwin.link(expired.url.path, alias.path) == 0)

    let report = AttachmentRetentionManager(
        harnessHome: home,
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
    #expect(FileManager.default.fileExists(atPath: alias.path))
}

@Test func attachmentRetentionRejectsExtendedACLsWithoutDeleting() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(
        "retention-acl-\(UUID().uuidString)",
        isDirectory: true
    )
    defer { try? FileManager.default.removeItem(at: home) }
    try prepareOwnedHarnessHome(home)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("acl-expired".utf8),
        to: home,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: home, jsonObject: ["type": "header"])
    try addExtendedTestACL(to: expired.url)

    let report = AttachmentRetentionManager(
        harnessHome: home,
        allowUnattestedHarnessHomeForTesting: true
    ).purgeExpired(retentionDays: 30, now: now)
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

private func prepareOwnedHarnessHome(
    _ root: URL,
    source: String? = nil,
    copiedEntries: [String] = []
) throws {
    try FileManager.default.createDirectory(at: root.appendingPathComponent("attachments/v1/objects", isDirectory: true), withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    var receipt: [String: Any] = [
        "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
        "migratedAt": 0.0,
        "copiedEntries": copiedEntries,
        "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current
    ]
    if let source {
        receipt["source"] = source
        receipt["sourceKind"] = "historicalProviderState"
    }
    let receiptURL = root.appendingPathComponent(".local-harness-home.json")
    try JSONSerialization.data(withJSONObject: receipt).write(to: receiptURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
}

private func addExtendedTestACL(to url: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "everyone deny delete", url.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 2),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        if process.isRunning { process.terminate() }
        throw CocoaError(.fileWriteUnknown)
    }
}

private func assertHarnessHomeAttestationRejected(
    mutation: (URL) throws -> Void
) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try prepareOwnedHarnessHome(root)
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let expired = try addAttachment(
        Data("attestation-expired-\(UUID().uuidString)".utf8),
        to: root,
        modified: now.addingTimeInterval(-45 * 86_400)
    )
    try addRawSession(to: root, jsonObject: ["type": "header"])
    try mutation(root)

    let report = AttachmentRetentionManager(
        harnessHome: root,
        allowUnattestedHarnessHomeForTesting: true
    )
        .purgeExpired(retentionDays: 30, now: now)
    guard case .unsupported = report.status else {
        Issue.record("Expected hostile Harness-home attestation to fail closed")
        return
    }
    #expect(report.deleted == 0)
    #expect(FileManager.default.fileExists(atPath: expired.url.path))
}

private func preparePrivateLedgerDirectory(_ root: URL) throws {
    let privacy = root.appendingPathComponent("Privacy", isDirectory: true)
    try FileManager.default.createDirectory(
        at: privacy,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: privacy.path)
}

private enum PrivacyLedgerInjectedFailure: Error {
    case requested
}

private func testAttachmentLimits(
    maximumLogBytes: Int = 64 * 1_024,
    maximumJSONLRowBytes: Int = 4 * 1_024,
    scanDuration: TimeInterval = 2
) -> AttachmentRetentionLimits {
    AttachmentRetentionLimits(
        maximumDirectoryEntries: 100,
        maximumProjects: 10,
        maximumSessions: 20,
        maximumObjects: 100,
        maximumLogBytes: maximumLogBytes,
        maximumAggregateLogBytes: 1 * 1_024 * 1_024,
        maximumDecodedBytes: 1 * 1_024 * 1_024,
        maximumJSONLRowBytes: maximumJSONLRowBytes,
        maximumReferences: 100,
        maximumJSONNodesPerRow: 1_000,
        maximumObjectBytes: 1 * 1_024 * 1_024,
        maximumAggregateObjectBytes: 10 * 1_024 * 1_024,
        maximumChildResultBytes: 64 * 1_024,
        scanDuration: scanDuration
    )
}

private func addAttachment(_ data: Data, to root: URL, modified: Date) throws -> (url: URL, digest: String) {
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let bucket = root.appendingPathComponent("attachments/v1/objects/\(digest.prefix(2))", isDirectory: true)
    try FileManager.default.createDirectory(at: bucket, withIntermediateDirectories: true)
    let url = bucket.appendingPathComponent(digest)
    try data.write(to: url)
    try FileManager.default.setAttributes([.modificationDate: modified], ofItemAtPath: url.path)
    return (url, digest)
}

private func addRawSession(to root: URL, jsonObject: [String: Any]) throws {
    let session = root.appendingPathComponent("sessions/project/session", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    var row = try JSONSerialization.data(withJSONObject: jsonObject, options: [.sortedKeys])
    row.append(0x0A)
    try row.write(to: session.appendingPathComponent("session.jsonl"))
}

private func privateMode(of url: URL) -> Int {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes?[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

private func projectRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}

private func writeConcatenatedZstdLog(to destination: URL, reference: String, node: URL) throws {
    let script = #"""
const fs = require('node:fs');
const { zstdCompressSync } = require('node:zlib');
const destination = process.argv[1];
const reference = process.argv[2];
const first = Buffer.from(JSON.stringify({ type: 'header' }) + '\n');
const second = Buffer.from(JSON.stringify({ attachmentId: 'sha256:' + reference }) + '\n');
fs.writeFileSync(destination, Buffer.concat([zstdCompressSync(first), zstdCompressSync(second)]));
"""#
    let process = Process()
    process.executableURL = node
    process.arguments = ["-e", script, destination.path, reference]
    process.environment = ["PATH": node.deletingLastPathComponent().path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 10),
          process.terminationStatus == 0 else { throw CocoaError(.fileWriteUnknown) }
}
