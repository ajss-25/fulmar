import Darwin
import CryptoKit
import Foundation
import Testing
@testable import LocalHarness

private final class RecoveryKeyAccessCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func key() -> Data {
        lock.lock()
        value += 1
        lock.unlock()
        return Data(repeating: 0x5a, count: 32)
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class RetryingRecoveryKeyProvider: @unchecked Sendable {
    private let lock = NSLock()
    private let keyBytes: Data
    private var attempts = 0

    init(key: Data) { keyBytes = key }

    func key() throws -> Data {
        lock.lock()
        attempts += 1
        let attempt = attempts
        lock.unlock()
        if attempt == 1 {
            throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
        }
        return keyBytes
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return attempts
    }
}

private final class ForegroundAuthorizationRecoveryKeyProvider: @unchecked Sendable {
    private let lock = NSLock()
    private let keyBytes: Data
    private var attempts = 0

    init(key: Data) { keyBytes = key }

    func key() throws -> Data {
        lock.lock()
        attempts += 1
        let attempt = attempts
        lock.unlock()
        if attempt == 1 {
            throw HarnessHomeError.receiptlessRecoveryAuthenticationRequired
        }
        return keyBytes
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return attempts
    }
}

private final class JournalPublicationRace: @unchecked Sendable {
    private let lock = NSLock()
    private let journal: URL
    private let bytes: Data
    private var invocation = 0

    init(journal: URL, bytes: Data) {
        self.journal = journal
        self.bytes = bytes
    }

    func uuid() -> UUID {
        lock.lock()
        invocation += 1
        let shouldPublish = invocation == 2
        lock.unlock()
        if shouldPublish {
            try? bytes.write(to: journal, options: .withoutOverwriting)
            _ = chmod(journal.path, mode_t(0o600))
        }
        return UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    }
}

private final class RecoveryUUIDPathSwap: @unchecked Sendable {
    private let lock = NSLock()
    private let operation: () throws -> Void
    private var invoked = false
    private var operationError: Error?

    init(operation: @escaping () throws -> Void) {
        self.operation = operation
    }

    func uuid() -> UUID {
        lock.lock()
        let shouldInvoke = !invoked
        invoked = true
        lock.unlock()
        if shouldInvoke {
            do { try operation() }
            catch {
                lock.lock()
                operationError = error
                lock.unlock()
            }
        }
        return UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!
    }

    func requireSucceeded() throws {
        lock.lock()
        let error = operationError
        let didInvoke = invoked
        lock.unlock()
        if let error { throw error }
        guard didInvoke else { throw HarnessHomeError.receiptlessRecoveryStateChanged }
    }
}

private enum ReceiptDescriptorHookError: Error, Equatable {
    case injected(HarnessHomeReceiptlessRecoveryDescriptorPoint)
}

private final class ReceiptDescriptorTracker: @unchecked Sendable {
    private let lock = NSLock()
    private let target: HarnessHomeReceiptlessRecoveryDescriptorPoint
    private var captured: [Int32] = []

    init(target: HarnessHomeReceiptlessRecoveryDescriptorPoint) { self.target = target }

    func inspect(_ point: HarnessHomeReceiptlessRecoveryDescriptorPoint, descriptor: Int32) throws {
        guard point == target else { return }
        lock.lock()
        captured.append(descriptor)
        lock.unlock()
        throw ReceiptDescriptorHookError.injected(point)
    }

    func takeLast() -> Int32? {
        lock.lock()
        defer { lock.unlock() }
        return captured.popLast()
    }
}

private struct OpenDescriptorNodeIdentity: Hashable {
    let device: UInt64
    let inode: UInt64

    init(_ value: stat) {
        device = UInt64(truncatingIfNeeded: value.st_dev)
        inode = UInt64(truncatingIfNeeded: value.st_ino)
    }
}

private func descriptorNodeIdentities(in treeRoot: URL) throws -> Set<OpenDescriptorNodeIdentity> {
    var urls = [treeRoot]
    if let enumerator = FileManager.default.enumerator(
        at: treeRoot,
        includingPropertiesForKeys: nil,
        options: [],
        errorHandler: { _, _ in false }
    ) {
        for case let url as URL in enumerator { urls.append(url) }
    }
    return try Set(urls.map { url in
        var value = stat()
        guard lstat(url.path, &value) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        return OpenDescriptorNodeIdentity(value)
    })
}

private func openDescriptorCount(matching targets: Set<OpenDescriptorNodeIdentity>) -> Int {
    guard !targets.isEmpty else { return 0 }
    let descriptorLimit = getdtablesize()
    guard descriptorLimit > 0 else { return 0 }
    var count = 0
    for descriptor in 0..<descriptorLimit {
        var opened = stat()
        if fstat(descriptor, &opened) == 0,
           targets.contains(OpenDescriptorNodeIdentity(opened)) {
            count += 1
        }
    }
    return count
}

private enum ReceiptlessRecoveryFixtureError: Error {
    case requestWasNotProduced
    case interruptedRequestWasNotProduced
}

private struct ReceiptlessTreeSnapshotNode: Equatable {
    let relativePath: String
    let device: UInt64
    let inode: UInt64
    let mode: UInt16
    let linkCount: UInt64
    let byteCount: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
    let changeSeconds: Int64
    let changeNanoseconds: Int64
    let bytes: Data?
}

private func receiptlessTreeSnapshot(at root: URL) throws -> [ReceiptlessTreeSnapshotNode] {
    guard FileManager.default.fileExists(atPath: root.path) else { return [] }
    var urls = [root]
    if let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: nil,
        options: [],
        errorHandler: { _, _ in false }
    ) {
        for case let url as URL in enumerator { urls.append(url) }
    }
    return try urls.sorted { $0.path < $1.path }.map { url in
        var value = stat()
        guard lstat(url.path, &value) == 0 else {
            throw HarnessHomeError.receiptlessRecoveryStateChanged
        }
        let relative = url == root
            ? "."
            : String(url.path.dropFirst(root.path.count + 1))
        let bytes = value.st_mode & S_IFMT == S_IFREG ? try Data(contentsOf: url) : nil
        return ReceiptlessTreeSnapshotNode(
            relativePath: relative,
            device: UInt64(truncatingIfNeeded: value.st_dev),
            inode: UInt64(truncatingIfNeeded: value.st_ino),
            mode: UInt16(truncatingIfNeeded: value.st_mode),
            linkCount: UInt64(truncatingIfNeeded: value.st_nlink),
            byteCount: Int64(value.st_size),
            modificationSeconds: Int64(value.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(value.st_mtimespec.tv_nsec),
            changeSeconds: Int64(value.st_ctimespec.tv_sec),
            changeNanoseconds: Int64(value.st_ctimespec.tv_nsec),
            bytes: bytes
        )
    }
}

private func receiptlessRequest(
    from manager: HarnessHomeManager
) throws -> HarnessHomeReceiptlessRecoveryRequest {
    do {
        try manager.prepare()
        throw ReceiptlessRecoveryFixtureError.requestWasNotProduced
    } catch HarnessHomeError.receiptlessRecoveryRequired(let request) {
        return request
    }
}

private func interruptedReceiptlessRequest(
    from manager: HarnessHomeManager
) throws -> HarnessHomeInterruptedRecoveryRequest {
    do {
        try manager.prepare()
        throw ReceiptlessRecoveryFixtureError.interruptedRequestWasNotProduced
    } catch HarnessHomeError.receiptlessRecoveryInterrupted(let request) {
        return request
    }
}

private func authenticatedInterruptedIntent(
    from manager: HarnessHomeManager,
    request: HarnessHomeInterruptedRecoveryRequest
) throws -> HarnessHomeInterruptedRecoveryIntent {
    try #require(try manager.authorizeReceiptlessRecoveryKeyForForeground(
        interruptedRequest: request
    ))
}

private func preflightReceiptlessPendingState(
    from manager: HarnessHomeManager
) throws -> HarnessHomeRecoveryPendingState {
    do {
        _ = try manager.preflightHarnessHomeRecovery()
        throw ReceiptlessRecoveryFixtureError.requestWasNotProduced
    } catch HarnessHomeError.receiptlessRecoveryRequired(let request) {
        return .initial(request)
    } catch HarnessHomeError.receiptlessRecoveryInterrupted(let request) {
        return .interrupted(request)
    }
}

private func makeReceiptlessFixture(prefix: String = "receiptless-home") throws -> (
    parent: URL,
    home: URL,
    missingLegacy: URL
) {
    let parent = FileManager.default.temporaryDirectory
        .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
    let home = parent.appendingPathComponent("HarnessHome", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    return (parent, home, parent.appendingPathComponent("missing-legacy", isDirectory: true))
}

private func makeReceiptlessAncestorACLFixture(prefix: String) throws -> (
    container: URL,
    ancestor: URL,
    support: URL,
    home: URL,
    missingLegacy: URL
) {
    let container = FileManager.default.temporaryDirectory.appendingPathComponent(
        "\(prefix)-\(UUID().uuidString)",
        isDirectory: true
    )
    let ancestor = container.appendingPathComponent("ancestor", isDirectory: true)
    let support = ancestor.appendingPathComponent("support", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            at: support,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        for directory in [container, ancestor, support] {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )
        }
    } catch {
        try? FileManager.default.removeItem(at: container)
        throw error
    }
    return (
        container,
        ancestor,
        support,
        support.appendingPathComponent("HarnessHome", isDirectory: true),
        support.appendingPathComponent("missing-legacy", isDirectory: true)
    )
}

@Test func directoryBindingIdentityIgnoresUnrelatedChildNamespaceChurn() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        "directory-binding-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }

    var before = stat()
    guard lstat(directory.path, &before) == 0 else {
        throw HarnessHomeError.receiptlessRecoveryStateChanged
    }
    let unrelatedChild = directory.appendingPathComponent("unrelated", isDirectory: true)
    try FileManager.default.createDirectory(at: unrelatedChild, withIntermediateDirectories: false)
    var after = stat()
    guard lstat(directory.path, &after) == 0 else {
        throw HarnessHomeError.receiptlessRecoveryStateChanged
    }

    #expect(before.st_nlink != after.st_nlink || before.st_size != after.st_size)
    #expect(HarnessHomeManager.sameDirectoryBindingIdentity(before, after))
}

private func recoveryQuarantines(in parent: URL) throws -> [URL] {
    let recovery = parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    guard FileManager.default.fileExists(atPath: recovery.path) else { return [] }
    return try FileManager.default.contentsOfDirectory(
        at: recovery,
        includingPropertiesForKeys: nil
    ).filter { $0.lastPathComponent.hasPrefix("receiptless-") }
        .map { URL(fileURLWithPath: $0.path, isDirectory: true) }
}

private func recoveryStagingDirectories(in parent: URL) throws -> [URL] {
    let recovery = parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    guard FileManager.default.fileExists(atPath: recovery.path) else { return [] }
    return try FileManager.default.contentsOfDirectory(
        at: recovery,
        includingPropertiesForKeys: nil
    ).filter { $0.lastPathComponent.hasPrefix(".repairing-") }
}

private func legacyRecoveryOutputs(in parent: URL) throws -> [URL] {
    let recovery = parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    guard FileManager.default.fileExists(atPath: recovery.path) else { return [] }
    return try FileManager.default.contentsOfDirectory(
        at: recovery,
        includingPropertiesForKeys: nil
    ).filter { $0.lastPathComponent.hasPrefix(".historical-output-") }
}

@discardableResult
private func rewriteCurrentRecoveryJournalAsAuthenticatedLegacyV1(
    in parent: URL,
    key: Data,
    copiedEntries: [String]
) throws -> UUID {
    let recovery = parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let journal = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    let current = try #require(
        try JSONSerialization.jsonObject(with: Data(contentsOf: journal)) as? [String: Any]
    )
    var payload = try #require(current["payload"] as? [String: Any])
    payload["formatVersion"] = 1
    payload["copiedEntries"] = copiedEntries.sorted()
    payload.removeValue(forKey: "providerHistoryRecoveryChoice")
    let operationIDString = try #require(payload["operationID"] as? String)
    let operationID = try #require(UUID(uuidString: operationIDString))
    let payloadData = try JSONSerialization.data(
        withJSONObject: payload,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
    let tag = Data(HMAC<SHA256>.authenticationCode(
        for: payloadData,
        using: SymmetricKey(data: key)
    )).base64EncodedString()
    let envelope: [String: Any] = ["payload": payload, "authenticationTag": tag]
    let data = try JSONSerialization.data(
        withJSONObject: envelope,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
    try data.write(to: journal)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)
    return operationID
}

private func runReceiptlessRecoveryChmod(_ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = arguments
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 5),
          process.terminationReason == .exit, process.terminationStatus == 0 else {
        throw HarnessHomeError.receiptlessRecoveryStateChanged
    }
}

private func addReceiptlessRecoveryReadACL(to url: URL) throws {
    guard let passwordEntry = getpwuid(geteuid()) else {
        throw HarnessHomeError.receiptlessRecoveryStateChanged
    }
    try runReceiptlessRecoveryChmod([
        "+a",
        "\(String(cString: passwordEntry.pointee.pw_name)) allow read",
        url.path
    ])
}

@Test func receiptlessDetectionAndCancelPerformNoKeyAccessOrMutation() throws {
    let fixture = try makeReceiptlessFixture()
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    let retained = fixture.home.appendingPathComponent("user-data.txt")
    try Data("retained".utf8).write(to: retained)
    let keyAccess = RecoveryKeyAccessCounter()
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKeyProvider: { keyAccess.key() }
    )

    let before = try receiptlessTreeSnapshot(at: fixture.parent)
    let first = try preflightReceiptlessPendingState(from: manager)
    let second = try preflightReceiptlessPendingState(from: manager)
    #expect(first == second)
    let request = try receiptlessRequest(from: manager)
    #expect(first == .initial(request))

    #expect(keyAccess.count == 0)
    #expect(try receiptlessTreeSnapshot(at: fixture.parent) == before)
    #expect(try String(contentsOf: retained, encoding: .utf8) == "retained")
    #expect(!(FileManager.default.fileExists(atPath: fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName
    ).path)))
}

@Test func recoveryPreflightLeavesAbsentAndValidHomesByteForByteUnchanged() throws {
    do {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent(
            "receiptless-preflight-absent-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: parent) }
        let keyAccess = RecoveryKeyAccessCounter()
        let manager = HarnessHomeManager(
            root: parent.appendingPathComponent("HarnessHome", isDirectory: true),
            legacyRoot: parent.appendingPathComponent("missing-legacy", isDirectory: true),
            recoveryAuthenticationKeyProvider: { keyAccess.key() }
        )
        _ = try manager.preflightHarnessHomeRecovery()
        _ = try manager.preflightHarnessHomeRecovery()
        #expect(keyAccess.count == 0)
        #expect(!FileManager.default.fileExists(atPath: parent.path))
    }

    do {
        let fixture = try makeReceiptlessFixture(prefix: "receiptless-preflight-valid")
        defer { try? FileManager.default.removeItem(at: fixture.parent) }
        // Remove the receiptless fixture root, then let full preparation create
        // one valid receipted home before taking the no-op snapshot.
        try FileManager.default.removeItem(at: fixture.home)
        let keyAccess = RecoveryKeyAccessCounter()
        let manager = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKeyProvider: { keyAccess.key() }
        )
        try manager.prepare()
        let before = try receiptlessTreeSnapshot(at: fixture.parent)
        _ = try manager.preflightHarnessHomeRecovery()
        _ = try manager.preflightHarnessHomeRecovery()
        #expect(keyAccess.count == 0)
        #expect(try receiptlessTreeSnapshot(at: fixture.parent) == before)
    }

    do {
        let fixture = try makeReceiptlessAncestorACLFixture(
            prefix: "receiptless-preflight-canonical-ancestor"
        )
        defer {
            try? runReceiptlessRecoveryChmod(["-N", fixture.ancestor.path])
            try? FileManager.default.removeItem(at: fixture.container)
        }
        try runReceiptlessRecoveryChmod([
            "+a", "group:everyone deny delete", fixture.ancestor.path
        ])
        let keyAccess = RecoveryKeyAccessCounter()
        let manager = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKeyProvider: { keyAccess.key() }
        )
        try manager.prepare()
        let before = try receiptlessTreeSnapshot(at: fixture.container)
        _ = try manager.preflightHarnessHomeRecovery()
        _ = try manager.preflightHarnessHomeRecovery()
        #expect(keyAccess.count == 0)
        #expect(try receiptlessTreeSnapshot(at: fixture.container) == before)
    }

    let rejectedAncestorACLs: [(label: String, entries: [(mode: String, value: String)])] = [
        ("noncanonical", [("+a", "group:everyone deny writeattr")]),
        ("granting", [("+a", "group:everyone allow readsecurity")]),
        ("mixed", [
            ("+a", "group:everyone deny delete"),
            ("+a", "group:everyone allow readsecurity")
        ]),
        ("extra-permission", [("+a", "group:everyone deny delete,writeattr")]),
        ("inheritable", [(
            "+a", "group:everyone deny delete,file_inherit,directory_inherit"
        )])
    ]
    for rejected in rejectedAncestorACLs {
        let fixture = try makeReceiptlessAncestorACLFixture(
            prefix: "receiptless-preflight-\(rejected.label)"
        )
        defer {
            try? runReceiptlessRecoveryChmod(["-N", fixture.ancestor.path])
            try? FileManager.default.removeItem(at: fixture.container)
        }
        for entry in rejected.entries {
            try runReceiptlessRecoveryChmod([
                entry.mode, entry.value, fixture.ancestor.path
            ])
        }
        let manager = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: Data(repeating: 0x5b, count: 32)
        )
        #expect(throws: HarnessHomeError.receiptlessRecoveryStateChanged) {
            try manager.prepare()
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.home.path))
    }

    do {
        let fixture = try makeReceiptlessAncestorACLFixture(
            prefix: "receiptless-preflight-private-parent-acl"
        )
        defer {
            try? runReceiptlessRecoveryChmod(["-N", fixture.support.path])
            try? FileManager.default.removeItem(at: fixture.container)
        }
        try runReceiptlessRecoveryChmod([
            "+a", "group:everyone deny delete", fixture.support.path
        ])
        let manager = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: Data(repeating: 0x5c, count: 32)
        )
        #expect(throws: HarnessHomeError.receiptlessRecoveryStateChanged) {
            try manager.prepare()
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.home.path))
    }
}

@Test func explicitReceiptlessRecoveryCopiesOnlyReviewedEntriesAndPreservesEverything() throws {
    let fixture = try makeReceiptlessFixture()
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("reviewed".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    try FileManager.default.createDirectory(
        at: fixture.home.appendingPathComponent("sessions/one", isDirectory: true),
        withIntermediateDirectories: true
    )
    try Data("event".utf8).write(to: fixture.home.appendingPathComponent("sessions/one/events.jsonl"))
    for path in ["profiles/web", "skills/Packages/user-skill", "unknown/private"] {
        try FileManager.default.createDirectory(
            at: fixture.home.appendingPathComponent(path, isDirectory: true),
            withIntermediateDirectories: true
        )
    }
    try Data("profile".utf8).write(to: fixture.home.appendingPathComponent("profiles/web/package.json"))
    try Data("skill".utf8).write(to: fixture.home.appendingPathComponent("skills/Packages/user-skill/data"))
    try Data("unknown".utf8).write(to: fixture.home.appendingPathComponent("unknown/private/data"))
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x11, count: 32)
    )
    let request = try receiptlessRequest(from: manager)

    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()

    #expect(receipt.copiedEntries == ["settings.yaml"])
    #expect(try String(
        contentsOf: fixture.home.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "reviewed")
    #expect(!FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("sessions").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("profiles").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("skills").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("unknown").path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("profiles/web/package.json").path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("sessions/one/events.jsonl").path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("skills/Packages/user-skill/data").path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("unknown/private/data").path))
}

@Test func receiptlessStartCleanPreservesWholeHomeWithoutCopyingSettingsOrHistory() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-start-clean")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("private-setting".utf8).write(
        to: fixture.home.appendingPathComponent("settings.yaml")
    )
    try FileManager.default.createDirectory(
        at: fixture.home.appendingPathComponent("sessions/private", isDirectory: true),
        withIntermediateDirectories: true
    )
    try Data("private-history".utf8).write(
        to: fixture.home.appendingPathComponent("sessions/private/events.jsonl")
    )
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x7a, count: 32)
    )
    let request = try receiptlessRequest(from: manager)

    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
        request,
        choice: .startClean
    )
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()

    #expect(receipt.copiedEntries.isEmpty)
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("sessions").path
    ))
    #expect(try String(
        contentsOf: receipt.quarantine.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "private-setting")
    #expect(try String(
        contentsOf: receipt.quarantine.appendingPathComponent("sessions/private/events.jsonl"),
        encoding: .utf8
    ) == "private-history")
}

@Test func startCleanAuthorizationRetryNeverProbesOrCopiesSettings() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-start-clean-auth-retry")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    let outside = fixture.parent.appendingPathComponent("outside-setting")
    try Data("must-remain-outside".utf8).write(to: outside)
    let settings = fixture.home.appendingPathComponent("settings.yaml")
    try FileManager.default.createSymbolicLink(at: settings, withDestinationURL: outside)
    let keyProvider = ForegroundAuthorizationRecoveryKeyProvider(
        key: Data(repeating: 0x79, count: 32)
    )
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKeyProvider: { try keyProvider.key() }
    )
    let request = try receiptlessRequest(from: manager)

    #expect(throws: HarnessHomeError.receiptlessRecoveryAuthenticationRequired) {
        try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
            request,
            choice: .startClean
        )
    }
    #expect(keyProvider.count == 1)
    #expect(FileManager.default.fileExists(atPath: fixture.home.path))
    #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: settings.path)) != nil)

    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
        request,
        choice: .startClean
    )
    #expect(keyProvider.count == 2)
    #expect(receipt.copiedEntries.isEmpty)
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
    #expect((try? FileManager.default.destinationOfSymbolicLink(
        atPath: receipt.quarantine.appendingPathComponent("settings.yaml").path
    )) != nil)
    #expect(try String(contentsOf: outside, encoding: .utf8) == "must-remain-outside")
}

@Test func receiptlessRecoveryTreatsUnknownAndHistoryChildrenAsOpaque() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-opaque-history")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    let outside = fixture.parent.appendingPathComponent("outside-secret")
    try Data("must-not-be-opened".utf8).write(to: outside)
    try FileManager.default.createDirectory(
        at: fixture.home.appendingPathComponent("sessions", isDirectory: true),
        withIntermediateDirectories: true
    )
    try FileManager.default.createSymbolicLink(
        at: fixture.home.appendingPathComponent("sessions/provider-link"),
        withDestinationURL: outside
    )
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x7b, count: 32)
    )
    let request = try receiptlessRequest(from: manager)

    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
        request,
        choice: .startClean
    )
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()

    #expect((try? FileManager.default.destinationOfSymbolicLink(
        atPath: receipt.quarantine.appendingPathComponent("sessions/provider-link").path
    )) != nil)
    #expect(try String(contentsOf: outside, encoding: .utf8) == "must-not-be-opened")
}

@Test func v1AndV2ReceiptsAreHistoricalAndUpgradeOnlyExactSettings() throws {
    for version in [1, 2] {
        let fixture = try makeReceiptlessFixture(prefix: "historical-receipt-v\(version)")
        defer { try? FileManager.default.removeItem(at: fixture.parent) }
        try Data("keep-setting-v\(version)".utf8).write(
            to: fixture.home.appendingPathComponent("settings.yaml")
        )
        try FileManager.default.createDirectory(
            at: fixture.home.appendingPathComponent("sessions/private", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("history-v\(version)".utf8).write(
            to: fixture.home.appendingPathComponent("sessions/private/events.jsonl")
        )
        var legacyReceipt: [String: Any] = [
            "version": version,
            "migratedAt": 0.0,
            "copiedEntries": ["sessions", "settings.yaml"]
        ]
        if version == 1 {
            legacyReceipt["source"] = fixture.missingLegacy.path
        } else {
            legacyReceipt["source"] = fixture.parent
                .appendingPathComponent("HarnessHomeRecovery", isDirectory: true)
                .appendingPathComponent(
                    "receiptless-00000000-0000-0000-0000-00000000000\(version)",
                    isDirectory: true
                ).path
            legacyReceipt["sourceKind"] = "receiptlessRecovery"
        }
        let receiptURL = fixture.home.appendingPathComponent(".local-harness-home.json")
        try JSONSerialization.data(withJSONObject: legacyReceipt, options: [.sortedKeys])
            .write(to: receiptURL)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: receiptURL.path
        )
        let manager = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: Data(repeating: UInt8(0x70 + version), count: 32)
        )
        let request = try receiptlessRequest(from: manager)

        let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
            request,
            choice: .settingsOnly
        )
        try manager.acknowledgePublishedReceiptlessRecovery(receipt)
        try manager.prepare()

        #expect(receipt.copiedEntries == ["settings.yaml"])
        #expect(try String(
            contentsOf: fixture.home.appendingPathComponent("settings.yaml"),
            encoding: .utf8
        ) == "keep-setting-v\(version)")
        #expect(!FileManager.default.fileExists(
            atPath: fixture.home.appendingPathComponent("sessions").path
        ))
        #expect(try String(
            contentsOf: receipt.quarantine.appendingPathComponent(
                "sessions/private/events.jsonl"
            ),
            encoding: .utf8
        ) == "history-v\(version)")
    }
}

@Test func absentHomeCreatesCurrentEpochWithoutLegacyOrCredentialAccess() throws {
    let fixture = try makeReceiptlessFixture(prefix: "clean-current-epoch")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try FileManager.default.removeItem(at: fixture.home)
    let legacy = fixture.parent.appendingPathComponent("machine-wide-dsh", isDirectory: true)
    try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
    try Data("must-stay-machine-wide".utf8).write(
        to: legacy.appendingPathComponent("settings.yaml")
    )
    enum UnexpectedCredentialAccess: Error { case accessed }
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: legacy,
        recoveryAuthenticationKeyProvider: { throw UnexpectedCredentialAccess.accessed }
    )

    try manager.prepare()
    try manager.prepare()

    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
    #expect(try String(
        contentsOf: legacy.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "must-stay-machine-wide")
    let receipt = try JSONSerialization.jsonObject(
        with: Data(contentsOf: fixture.home.appendingPathComponent(".local-harness-home.json"))
    ) as? [String: Any]
    #expect(receipt?["version"] as? Int == ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion)
    #expect(receipt?["providerHistoryPrivacyEpoch"] as? Int == ProviderHistoryPrivacyEpoch.current)
    #expect(receipt?["copiedEntries"] as? [String] == [])
}

@Test func receiptlessRecoveryReconcilesEveryCrashBoundaryWithoutDeletingQuarantine() throws {
    for phase in HarnessHomeReceiptlessRecoveryPhase.allCases {
        let fixture = try makeReceiptlessFixture(prefix: "receiptless-crash-\(phase.rawValue)")
        defer { try? FileManager.default.removeItem(at: fixture.parent) }
        try Data("durable".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
        try FileManager.default.createDirectory(
            at: fixture.home.appendingPathComponent("profiles/retained", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("only-in-quarantine".utf8).write(
            to: fixture.home.appendingPathComponent("profiles/retained/data")
        )
        let key = Data(repeating: UInt8(phase.rawValue.utf8.first ?? 0x31), count: 32)
        let interrupted = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: key,
            receiptlessRecoveryCrashHook: { $0 == phase }
        )
        let request = try receiptlessRequest(from: interrupted)
        if phase == .journalCleared {
            let receipt = try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
            #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(phase)) {
                try interrupted.acknowledgePublishedReceiptlessRecovery(receipt)
            }
        } else {
            #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(phase)) {
                try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
            }
        }

        let resumed = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: key
        )
        if phase != .journalCleared {
            let receipt: HarnessHomeReceiptlessRecoveryReceipt
            if phase == .initialStagingDurable {
                let pending = try receiptlessRequest(from: resumed)
                receipt = try resumed.recoverReceiptlessHomeAfterExplicitConfirmation(pending, choice: .settingsOnly)
            } else {
                let pending = try interruptedReceiptlessRequest(from: resumed)
                receipt = try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
                    pending,
                    intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
                )
            }
            try resumed.acknowledgePublishedReceiptlessRecovery(receipt)
        }
        try resumed.prepare()
        try resumed.prepare()

        #expect(try String(
            contentsOf: fixture.home.appendingPathComponent("settings.yaml"),
            encoding: .utf8
        ) == "durable")
        let quarantines = try recoveryQuarantines(in: fixture.parent)
        #expect(quarantines.count == 1)
        let quarantine = try #require(quarantines.first)
        #expect(FileManager.default.fileExists(atPath: quarantine.appendingPathComponent("profiles/retained/data").path))
        #expect(!FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("profiles").path))
    }
}

@Test func authenticatedLegacyPrepublicationJournalUpgradesStartCleanAndPreservesOldOutput() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-legacy-v1-prepublication")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("former-setting".utf8).write(
        to: fixture.home.appendingPathComponent("settings.yaml")
    )
    let key = Data(repeating: 0x4b, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .contentRecorded }
    )
    let request = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }

    let oldStaging = try #require(try recoveryStagingDirectories(in: fixture.parent).first)
    try FileManager.default.createDirectory(
        at: oldStaging.appendingPathComponent("sessions/private", isDirectory: true),
        withIntermediateDirectories: true
    )
    try Data("old-staged-history".utf8).write(
        to: oldStaging.appendingPathComponent("sessions/private/events.jsonl")
    )
    _ = try rewriteCurrentRecoveryJournalAsAuthenticatedLegacyV1(
        in: fixture.parent,
        key: key,
        copiedEntries: ["sessions", "settings.yaml"]
    )

    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let pending = try interruptedReceiptlessRequest(from: resumed)
    let receipt = try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
        pending,
        intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
    )
    #expect(receipt.copiedEntries.isEmpty)
    let oldOutput = try #require(try legacyRecoveryOutputs(in: fixture.parent).first)
    #expect(try String(
        contentsOf: oldOutput.appendingPathComponent("sessions/private/events.jsonl"),
        encoding: .utf8
    ) == "old-staged-history")
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("sessions").path
    ))
    #expect(try String(
        contentsOf: receipt.quarantine.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "former-setting")
    try resumed.acknowledgePublishedReceiptlessRecovery(receipt)
    try resumed.prepare()
    #expect(FileManager.default.fileExists(atPath: oldOutput.path))
}

@Test func authenticatedLegacyPublishedJournalPreservesPublishedRootBeforeCleanRepublish() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-legacy-v1-published")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("former-setting".utf8).write(
        to: fixture.home.appendingPathComponent("settings.yaml")
    )
    let key = Data(repeating: 0x4c, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .publicationRecorded }
    )
    let request = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    try FileManager.default.createDirectory(
        at: fixture.home.appendingPathComponent("sessions/private", isDirectory: true),
        withIntermediateDirectories: true
    )
    try Data("old-published-history".utf8).write(
        to: fixture.home.appendingPathComponent("sessions/private/events.jsonl")
    )
    _ = try rewriteCurrentRecoveryJournalAsAuthenticatedLegacyV1(
        in: fixture.parent,
        key: key,
        copiedEntries: ["sessions", "settings.yaml"]
    )

    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let pending = try interruptedReceiptlessRequest(from: resumed)
    let receipt = try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
        pending,
        intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
    )
    #expect(receipt.copiedEntries.isEmpty)
    let oldOutput = try #require(try legacyRecoveryOutputs(in: fixture.parent).first)
    #expect(try String(
        contentsOf: oldOutput.appendingPathComponent("sessions/private/events.jsonl"),
        encoding: .utf8
    ) == "old-published-history")
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
    #expect(!FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("sessions").path
    ))
    #expect(try String(
        contentsOf: receipt.quarantine.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "former-setting")
    try resumed.acknowledgePublishedReceiptlessRecovery(receipt)
    try resumed.prepare()
    #expect(FileManager.default.fileExists(atPath: oldOutput.path))
}

@Test func relaunchReclaimsOnlyEmptyPrivatePreJournalStagingBeforeExactRecovery() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-prejournal-orphan")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x2c, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .initialStagingDurable }
    )
    let initial = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(
        .initialStagingDurable
    )) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(initial, choice: .settingsOnly)
    }
    #expect(try recoveryStagingDirectories(in: fixture.parent).count == 1)
    #expect(try recoveryQuarantines(in: fixture.parent).isEmpty)

    let relaunched = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let representedInitial = try receiptlessRequest(from: relaunched)
    let receipt = try relaunched.recoverReceiptlessHomeAfterExplicitConfirmation(representedInitial, choice: .settingsOnly)
    #expect(try recoveryStagingDirectories(in: fixture.parent).isEmpty)
    #expect(
        try recoveryQuarantines(in: fixture.parent).map(\.standardizedFileURL.path)
            == [receipt.quarantine.standardizedFileURL.path]
    )
    try relaunched.acknowledgePublishedReceiptlessRecovery(receipt)
    try relaunched.prepare()
}

@Test func repeatingExplicitRecoveryResumesTheSameAuthenticatedTransaction() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-idempotent")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x22, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .contentRecorded }
    )
    let request = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }

    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let pending = try interruptedReceiptlessRequest(from: resumed)
    let receipt = try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
        pending,
        intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
    )

    // Publication remains durable until the exact foreground receipt is
    // acknowledged, so a relaunch must re-present the same result.
    let relaunched = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let representedPending = try interruptedReceiptlessRequest(from: relaunched)
    let represented = try relaunched.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
        representedPending,
        intent: try authenticatedInterruptedIntent(from: relaunched, request: representedPending)
    )
    #expect(represented == receipt)
    try relaunched.acknowledgePublishedReceiptlessRecovery(represented)
    try relaunched.prepare()
    try relaunched.prepare()

    #expect(
        try recoveryQuarantines(in: fixture.parent).map(\.standardizedFileURL.path)
            == [receipt.quarantine.standardizedFileURL.path]
    )
    #expect(try String(
        contentsOf: fixture.home.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "source")
}

@Test func receiptInstallThrowPathsCloseEveryOpenedDescriptorWithoutGrowth() throws {
    for point in [
        HarnessHomeReceiptlessRecoveryDescriptorPoint.receiptProbe,
        .receiptInstall,
        .receiptRevalidation
    ] {
        let fixture = try makeReceiptlessFixture(prefix: "receiptless-descriptor-\(point)")
        defer { try? FileManager.default.removeItem(at: fixture.parent) }
        try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
        let key = Data(repeating: 0x2d, count: 32)
        let setupBoundary: HarnessHomeReceiptlessRecoveryPhase = point == .receiptRevalidation
            ? .receiptDurable
            : .contentRecorded
        let interrupted = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: key,
            receiptlessRecoveryCrashHook: { $0 == setupBoundary }
        )
        let initial = try receiptlessRequest(from: interrupted)
        #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(setupBoundary)) {
            try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(initial, choice: .settingsOnly)
        }

        let tracker = ReceiptDescriptorTracker(target: point)
        let resumed = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: key,
            receiptlessRecoveryDescriptorTestHook: { hookPoint, descriptor in
                try tracker.inspect(hookPoint, descriptor: descriptor)
            }
        )
        let pending = try interruptedReceiptlessRequest(from: resumed)
        let descriptorTargets = try descriptorNodeIdentities(in: fixture.parent)
        for _ in 0..<16 {
            let descriptorsBefore = openDescriptorCount(matching: descriptorTargets)
            #expect(descriptorsBefore == 0)
            #expect(throws: ReceiptDescriptorHookError.injected(point)) {
                try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
                    pending,
                    intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
                )
            }
            let descriptor = try #require(tracker.takeLast())
            errno = 0
            #expect(fcntl(descriptor, F_GETFD) == -1)
            #expect(errno == EBADF)
            let descriptorsAfter = openDescriptorCount(matching: descriptorTargets)
            #expect(descriptorsAfter == descriptorsBefore)
            #expect(descriptorsAfter == 0)
        }
    }
}

@Test func tamperedAuthenticatedRecoveryJournalFailsClosed() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-tamper")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("retained".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x33, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .sourceQuarantineRecorded }
    )
    let request = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let journal = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    var bytes = try Data(contentsOf: journal)
    bytes[bytes.startIndex] ^= 0x01
    try bytes.write(to: journal)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)

    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let pending = try interruptedReceiptlessRequest(from: resumed)
    #expect(throws: HarnessHomeError.receiptlessRecoveryJournalInvalid) {
        try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
            pending,
            intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
        )
    }
    let quarantine = try #require(try recoveryQuarantines(in: fixture.parent).first)
    #expect(FileManager.default.fileExists(atPath: quarantine.appendingPathComponent("settings.yaml").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.home.path))
}

@Test func unavailableRecoveryKeyLeavesInterruptedSourceAndJournalUntouched() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-key-unavailable")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("retained".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x34, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .sourceQuarantineRecorded }
    )
    let request = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let journal = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    let journalBefore = try Data(contentsOf: journal)
    let quarantine = try #require(try recoveryQuarantines(in: fixture.parent).first)

    let keyAccess = RecoveryKeyAccessCounter()
    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKeyProvider: {
            _ = keyAccess.key()
            throw HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable
        }
    )
    let pending = try interruptedReceiptlessRequest(from: resumed)
    #expect(keyAccess.count == 0)
    #expect(throws: HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable) {
        try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
            pending,
            intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
        )
    }
    #expect(keyAccess.count == 1)

    #expect(try Data(contentsOf: journal) == journalBefore)
    #expect(FileManager.default.fileExists(atPath: quarantine.appendingPathComponent("settings.yaml").path))
    #expect(!FileManager.default.fileExists(atPath: fixture.home.path))
}

@Test func receiptlessRecoveryRejectsPathSwapAndUnsafeSettingsWithoutLosingOpaqueHome() throws {
    enum Adversary: Equatable {
        case pathSwap
        case symbolicLink
        case hardLink
        case writable
        case extendedACL
        case oversized
    }
    for adversary in [
        Adversary.pathSwap, .symbolicLink, .hardLink, .writable, .extendedACL, .oversized
    ] {
        let fixture = try makeReceiptlessFixture(prefix: "receiptless-adversary")
        defer { try? FileManager.default.removeItem(at: fixture.parent) }
        let settings = fixture.home.appendingPathComponent("settings.yaml")
        try Data(repeating: 0x41, count: adversary == .oversized ? 9 : 4).write(to: settings)
        let manager = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            limits: .init(maximumMigrationFileBytes: 8, maximumMigrationBytes: 8),
            recoveryAuthenticationKey: Data(repeating: 0x44, count: 32)
        )
        let request = try receiptlessRequest(from: manager)
        switch adversary {
        case .pathSwap:
            let moved = fixture.parent.appendingPathComponent("moved", isDirectory: true)
            try FileManager.default.moveItem(at: fixture.home, to: moved)
            try FileManager.default.createDirectory(at: fixture.home, withIntermediateDirectories: false)
        case .symbolicLink:
            let outside = fixture.parent.appendingPathComponent("outside")
            try Data("outside".utf8).write(to: outside)
            try FileManager.default.removeItem(at: settings)
            try FileManager.default.createSymbolicLink(at: settings, withDestinationURL: outside)
        case .hardLink:
            try FileManager.default.linkItem(
                at: settings,
                to: fixture.parent.appendingPathComponent("second-link")
            )
        case .writable:
            try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: settings.path)
        case .extendedACL:
            try addReceiptlessRecoveryReadACL(to: settings)
        case .oversized:
            break
        }
        #expect(throws: (any Error).self) {
            try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
        }
        if adversary == .pathSwap {
            #expect(FileManager.default.fileExists(atPath: fixture.home.path))
            #expect(try recoveryQuarantines(in: fixture.parent).isEmpty)
        } else {
            #expect(!FileManager.default.fileExists(atPath: fixture.home.path))
            let preserved = try #require(recoveryQuarantines(in: fixture.parent).first)
            #expect(FileManager.default.fileExists(
                atPath: preserved.appendingPathComponent("settings.yaml").path
            ))
        }
    }
}

@Test func receiptlessRecoveryNeverOverwritesAnExistingQuarantineName() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-exclusive")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let operation = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let existing = recovery.appendingPathComponent(
        "receiptless-\(operation.uuidString.lowercased())",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: existing, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: recovery.path)
    try Data("do-not-overwrite".utf8).write(to: existing.appendingPathComponent("marker"))
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x55, count: 32),
        makeUUID: { operation }
    )
    let request = try receiptlessRequest(from: manager)

    #expect(throws: HarnessHomeError.receiptlessRecoveryStateChanged) {
        try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    #expect(try String(contentsOf: existing.appendingPathComponent("marker"), encoding: .utf8) == "do-not-overwrite")
    #expect(FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("settings.yaml").path))
}

@Test func initialJournalPublicationNeverReplacesAConcurrentPrivateEntry() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-journal-exclusive")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: recovery.path)
    let journal = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    let adversaryBytes = Data("concurrent-private-entry".utf8)
    let race = JournalPublicationRace(journal: journal, bytes: adversaryBytes)
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x56, count: 32),
        makeUUID: { race.uuid() }
    )
    let request = try receiptlessRequest(from: manager)

    #expect(throws: HarnessHomeError.receiptlessRecoveryJournalInvalid) {
        try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    #expect(try Data(contentsOf: journal) == adversaryBytes)
    #expect(FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
    #expect(try recoveryQuarantines(in: fixture.parent).isEmpty)
}

@Test func parentPathSwapAtUUIDFailsBeforeSourceMoveAndReturnsNoFalseReceipt() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-parent-swap")
    let displaced = fixture.parent.deletingLastPathComponent().appendingPathComponent(
        "\(fixture.parent.lastPathComponent)-displaced",
        isDirectory: true
    )
    defer {
        try? FileManager.default.removeItem(at: fixture.parent)
        try? FileManager.default.removeItem(at: displaced)
    }
    let original = fixture.home.appendingPathComponent("settings.yaml")
    try Data("configured-original".utf8).write(to: original)
    let swap = RecoveryUUIDPathSwap {
        try FileManager.default.moveItem(at: fixture.parent, to: displaced)
        try FileManager.default.createDirectory(at: fixture.home, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: fixture.parent.path
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: fixture.home.path
        )
        try Data("canonical-replacement".utf8).write(
            to: fixture.home.appendingPathComponent("settings.yaml")
        )
    }
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x68, count: 32),
        makeUUID: { swap.uuid() }
    )
    let request = try receiptlessRequest(from: manager)

    #expect(throws: HarnessHomeError.receiptlessRecoveryStateChanged) {
        try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    try swap.requireSucceeded()
    #expect(try String(
        contentsOf: displaced.appendingPathComponent("HarnessHome/settings.yaml"),
        encoding: .utf8
    ) == "configured-original")
    #expect(try String(
        contentsOf: fixture.home.appendingPathComponent("settings.yaml"),
        encoding: .utf8
    ) == "canonical-replacement")
    #expect(try recoveryQuarantines(in: fixture.parent).isEmpty)
    _ = try receiptlessRequest(from: HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x68, count: 32)
    ))
}

@Test func recoveryDirectorySwapAtUUIDFailsBeforeSourceMoveAndRelaunchRemainsPending() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-recovery-swap")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    let source = fixture.home.appendingPathComponent("settings.yaml")
    try Data("configured-original".utf8).write(to: source)
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let displaced = fixture.parent.appendingPathComponent(
        "\(HarnessHomeManager.receiptlessRecoveryDirectoryName)-displaced",
        isDirectory: true
    )
    let swap = RecoveryUUIDPathSwap {
        try FileManager.default.moveItem(at: recovery, to: displaced)
        try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: false)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: recovery.path
        )
    }
    let key = Data(repeating: 0x69, count: 32)
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        makeUUID: { swap.uuid() }
    )
    let request = try receiptlessRequest(from: manager)

    #expect(throws: HarnessHomeError.receiptlessRecoveryStateChanged) {
        try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    try swap.requireSucceeded()
    #expect(try String(contentsOf: source, encoding: .utf8) == "configured-original")
    #expect(try recoveryQuarantines(in: fixture.parent).isEmpty)
    #expect(!FileManager.default.fileExists(atPath: recovery.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryJournalName
    ).path))

    let relaunched = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let represented = try receiptlessRequest(from: relaunched)
    let exactReceipt = try relaunched.recoverReceiptlessHomeAfterExplicitConfirmation(represented, choice: .settingsOnly)
    #expect(exactReceipt.quarantine.deletingLastPathComponent() == recovery)
    try relaunched.acknowledgePublishedReceiptlessRecovery(exactReceipt)
    try relaunched.prepare()
}

@Test func interruptedLegacyJournalCreatesFixedLockAndRetainsExactRetryRequest() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-legacy-lock")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x57, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .sourceQuarantineRecorded }
    )
    let initial = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(initial, choice: .settingsOnly)
    }
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let lockFile = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryLockName)
    try FileManager.default.removeItem(at: lockFile)

    let retryingKey = RetryingRecoveryKeyProvider(key: key)
    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKeyProvider: { try retryingKey.key() }
    )
    let journal = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    let journalBefore = try Data(contentsOf: journal)
    let before = try receiptlessTreeSnapshot(at: recovery)
    let firstPending = try preflightReceiptlessPendingState(from: resumed)
    let secondPending = try preflightReceiptlessPendingState(from: resumed)
    #expect(firstPending == secondPending)
    guard case .interrupted(let pending) = firstPending else {
        Issue.record("Expected the exact interrupted recovery preflight state")
        return
    }
    #expect(retryingKey.count == 0)
    #expect(!FileManager.default.fileExists(atPath: lockFile.path))
    #expect(try receiptlessTreeSnapshot(at: recovery) == before)
    #expect(try Data(contentsOf: journal) == journalBefore)

    #expect(throws: HarnessHomeError.receiptlessRecoveryAuthenticationUnavailable) {
        try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
            pending,
            intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
        )
    }
    #expect(FileManager.default.fileExists(atPath: lockFile.path))
    let lockMode = try #require(
        FileManager.default.attributesOfItem(atPath: lockFile.path)[.posixPermissions] as? NSNumber
    )
    #expect(lockMode.intValue == 0o600)

    // The exact pre-lock prompt remains a valid retry alias in this manager;
    // no generic re-detection or replacement request is substituted.
    let receipt = try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
        pending,
        intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
    )
    #expect(retryingKey.count == 2)
    try resumed.acknowledgePublishedReceiptlessRecovery(receipt)
    try resumed.prepare()
}

@Test func foregroundAuthorizationClosesParentWhenRecoveryDirectoryOpenThrows() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-authorization-parent-fd")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x67, count: 32),
        receiptlessRecoveryCrashHook: { $0 == .journalPrepared }
    )
    let initial = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(.journalPrepared)) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(initial, choice: .settingsOnly)
    }

    // Use the production existing-key client branch, but force the recovery
    // directory lookup to fail before any helper or Keychain operation can run.
    let authorizing = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy
    )
    let pending = try interruptedReceiptlessRequest(from: authorizing)
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    try addReceiptlessRecoveryReadACL(to: recovery)
    let descriptorTargets = try descriptorNodeIdentities(in: fixture.parent)
    let descriptorsBefore = openDescriptorCount(matching: descriptorTargets)
    #expect(descriptorsBefore == 0)
    for _ in 0..<64 {
        #expect(throws: (any Error).self) {
            try authorizing.authorizeReceiptlessRecoveryKeyForForeground(
                interruptedRequest: pending
            )
        }
        let descriptorsAfterAttempt = openDescriptorCount(matching: descriptorTargets)
        #expect(descriptorsAfterAttempt == descriptorsBefore)
        #expect(descriptorsAfterAttempt == 0)
    }
    let descriptorsAfter = openDescriptorCount(matching: descriptorTargets)
    #expect(descriptorsAfter == descriptorsBefore)
    #expect(descriptorsAfter == 0)
}

@Test func authenticatedForegroundIntentCannotResumeAPeerJournal() throws {
    let first = try makeReceiptlessFixture(prefix: "receiptless-intent-first")
    let second = try makeReceiptlessFixture(prefix: "receiptless-intent-second")
    defer {
        try? FileManager.default.removeItem(at: first.parent)
        try? FileManager.default.removeItem(at: second.parent)
    }
    let key = Data(repeating: 0x6d, count: 32)
    func interrupt(_ fixture: (
        parent: URL,
        home: URL,
        missingLegacy: URL
    )) throws -> (HarnessHomeManager, HarnessHomeInterruptedRecoveryRequest) {
        try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
        let crashing = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: key,
            receiptlessRecoveryCrashHook: { $0 == .journalPrepared }
        )
        let initial = try receiptlessRequest(from: crashing)
        #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
            try crashing.recoverReceiptlessHomeAfterExplicitConfirmation(
                initial,
                choice: .settingsOnly
            )
        }
        let resumed = HarnessHomeManager(
            root: fixture.home,
            legacyRoot: fixture.missingLegacy,
            recoveryAuthenticationKey: key
        )
        return (resumed, try interruptedReceiptlessRequest(from: resumed))
    }

    let (firstManager, firstRequest) = try interrupt(first)
    let (secondManager, secondRequest) = try interrupt(second)
    let firstIntent = try authenticatedInterruptedIntent(
        from: firstManager,
        request: firstRequest
    )
    let secondJournal = second.parent
        .appendingPathComponent(HarnessHomeManager.receiptlessRecoveryDirectoryName)
        .appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    let before = try Data(contentsOf: secondJournal)

    #expect(throws: HarnessHomeError.receiptlessRecoveryStateChanged) {
        try secondManager.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
            secondRequest,
            intent: firstIntent
        )
    }
    #expect(try Data(contentsOf: secondJournal) == before)
}

@Test func receiptlessRecoveryLeaseRejectsConcurrentResumeWithoutMutation() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-lock-contention")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x58, count: 32)
    let interrupted = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .sourceQuarantineRecorded }
    )
    let initial = try receiptlessRequest(from: interrupted)
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.self) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(initial, choice: .settingsOnly)
    }
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    let journal = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryJournalName)
    let journalBefore = try Data(contentsOf: journal)
    let lockPath = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryLockName)
    let competingDescriptor = Darwin.open(lockPath.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard competingDescriptor >= 0 else { throw HarnessHomeError.receiptlessRecoveryStateChanged }
    defer {
        _ = flock(competingDescriptor, LOCK_UN)
        Darwin.close(competingDescriptor)
    }
    guard flock(competingDescriptor, LOCK_EX | LOCK_NB) == 0 else {
        throw HarnessHomeError.receiptlessRecoveryStateChanged
    }

    let resumed = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: key
    )
    let pending = try interruptedReceiptlessRequest(from: resumed)
    #expect(throws: HarnessHomeError.receiptlessRecoveryInProgress) {
        try resumed.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
            pending,
            intent: try authenticatedInterruptedIntent(from: resumed, request: pending)
        )
    }
    #expect(try Data(contentsOf: journal) == journalBefore)
}

@Test func receiptlessRecoveryRejectsExtendedACLOnFixedLockBeforeKeyAccess() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-lock-acl")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let recovery = fixture.parent.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName,
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: recovery.path)
    let lockFile = recovery.appendingPathComponent(HarnessHomeManager.receiptlessRecoveryLockName)
    try Data().write(to: lockFile, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: lockFile.path)
    try addReceiptlessRecoveryReadACL(to: lockFile)
    let keyAccess = RecoveryKeyAccessCounter()
    let manager = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKeyProvider: { keyAccess.key() }
    )
    let request = try receiptlessRequest(from: manager)

    #expect(throws: HarnessHomeError.receiptlessRecoveryJournalInvalid) {
        try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    #expect(keyAccess.count == 0)
    #expect(FileManager.default.fileExists(
        atPath: fixture.home.appendingPathComponent("settings.yaml").path
    ))
}

@Test func receiptlessRecoveryHonorsOneMonotonicDeadlineBeforeMutation() throws {
    let fixture = try makeReceiptlessFixture(prefix: "receiptless-deadline")
    defer { try? FileManager.default.removeItem(at: fixture.parent) }
    try Data("source".utf8).write(to: fixture.home.appendingPathComponent("settings.yaml"))
    let request = try receiptlessRequest(from: HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        recoveryAuthenticationKey: Data(repeating: 0x66, count: 32)
    ))
    let bounded = HarnessHomeManager(
        root: fixture.home,
        legacyRoot: fixture.missingLegacy,
        limits: .init(preparationDuration: 0),
        recoveryAuthenticationKey: Data(repeating: 0x66, count: 32)
    )

    #expect(throws: HarnessHomeError.preparationLimitExceeded("monotonic deadline")) {
        try bounded.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }
    #expect(FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("settings.yaml").path))
    #expect(try recoveryQuarantines(in: fixture.parent).isEmpty)
}
