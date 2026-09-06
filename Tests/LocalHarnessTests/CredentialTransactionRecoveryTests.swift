import Dispatch
import Darwin
import CryptoKit
import Foundation
@testable import LocalHarnessCredentialSecurity
import Testing

private enum SimulatedCredentialProcessKill: Error {
    case at(CredentialTransactionCheckpoint)
}

private enum SimulatedCredentialPersistenceFault: Error {
    case at(CredentialFileStateArtifact, CredentialFileStatePersistenceCheckpoint)
}

private final class FakeCredentialValueStore: CredentialValueStore {
    var values: [String: Data] = [:]
    var readErrors: [String: CredentialValueStoreError] = [:]
    var readError: CredentialValueStoreError?
    var addError: CredentialValueStoreError?
    var replaceError: CredentialValueStoreError?
    var deleteError: CredentialValueStoreError?

    func read(account: String) throws -> Data? {
        if let error = readErrors[account] { throw error }
        if let readError { throw readError }
        return values[account]
    }

    func add(account: String, value: Data) throws {
        if let addError { throw addError }
        guard values[account] == nil else { throw CredentialValueStoreError.duplicate }
        values[account] = value
    }

    func replace(account: String, value: Data) throws {
        if let replaceError { throw replaceError }
        guard values[account] != nil else { throw CredentialValueStoreError.status(-25300) }
        values[account] = value
    }

    func delete(account: String) throws {
        if let deleteError { throw deleteError }
        values[account] = nil
    }
}

private final class BlockingCredentialValueStore: CredentialValueStore {
    private let lock = NSLock()
    private var storage: [String: Data]
    private var reads = 0
    let firstReplacementEntered = DispatchSemaphore(value: 0)
    let allowFirstReplacement = DispatchSemaphore(value: 0)
    let firstReplacement: Data

    init(account: String, initial: Data, firstReplacement: Data) {
        storage = [account: initial]
        self.firstReplacement = firstReplacement
    }

    func read(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        reads += 1
        return storage[account]
    }

    func add(account: String, value: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        guard storage[account] == nil else { throw CredentialValueStoreError.duplicate }
        storage[account] = value
    }

    func replace(account: String, value: Data) throws {
        if value == firstReplacement {
            firstReplacementEntered.signal()
            _ = allowFirstReplacement.wait(timeout: .now() + 5)
        }
        lock.lock()
        defer { lock.unlock() }
        storage[account] = value
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage[account] = nil
    }

    func snapshot(account: String) -> (value: Data?, readCount: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (storage[account], reads)
    }
}

private final class DuplicateAddRaceCredentialValueStore: CredentialValueStore {
    private(set) var value: Data?
    private let racedValue: Data

    init(racedValue: Data) {
        self.racedValue = racedValue
    }

    func read(account: String) throws -> Data? { value }

    func add(account: String, value: Data) throws {
        self.value = racedValue
        throw CredentialValueStoreError.duplicate
    }

    func replace(account: String, value: Data) throws { self.value = value }
    func delete(account: String) throws { value = nil }
}

private final class PreStoreThirdValueCredentialValueStore: CredentialValueStore {
    private(set) var value: Data?
    private let third: Data
    private var reads = 0

    init(initial: Data, third: Data) {
        value = initial
        self.third = third
    }

    func read(account: String) throws -> Data? {
        reads += 1
        if reads == 2 { value = third }
        return value
    }

    func add(account: String, value: Data) throws {
        guard self.value == nil else { throw CredentialValueStoreError.duplicate }
        self.value = value
    }

    func replace(account: String, value: Data) throws { self.value = value }
    func delete(account: String) throws { value = nil }
}

private struct CredentialCrashFixture {
    let root: URL
    let state: CredentialFileStateStore

    init(label: String) throws {
        root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-credential-\(label)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        state = try CredentialFileStateStore(directory: root)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }

    func stateFiles() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
    }
}

private func isMutationDurable(at checkpoint: CredentialTransactionCheckpoint) -> Bool {
    switch checkpoint {
    case .afterJournalPrepared:
        false
    case .afterValueMutation, .afterValueVerification, .afterMetadataCommit,
         .afterFinalVerification, .afterJournalRemoval:
        true
    }
}

private func assertNoPendingCredentialJournal(_ fixture: CredentialCrashFixture) throws {
    #expect(try fixture.stateFiles().allSatisfy { !$0.lastPathComponent.hasSuffix(".transaction.json") })
}

private func assertNoCredentialTemporaryFile(_ fixture: CredentialCrashFixture) throws {
    #expect(try fixture.stateFiles().allSatisfy { !$0.lastPathComponent.hasSuffix(".tmp") })
}

private func credentialStateURL(
    fixture: CredentialCrashFixture,
    account: String,
    journal: Bool
) -> URL {
    let digest = SHA256.hash(data: Data(account.utf8))
        .map { String(format: "%02x", $0) }
        .joined()
    return fixture.root.appendingPathComponent(
        digest + (journal ? ".transaction.json" : ".json"),
        isDirectory: false
    )
}

private func prepareAmbiguousCredential(
    fixture: CredentialCrashFixture,
    values: FakeCredentialValueStore,
    account: String,
    previous: Data,
    third: Data
) throws {
    values.values[account] = previous
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let interrupted = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterJournalPrepared {
                throw SimulatedCredentialProcessKill.at(reached)
            }
        }
    )
    #expect(throws: SimulatedCredentialProcessKill.self) {
        try interrupted.store(
            account: account,
            value: Data("uncommitted-target".utf8),
            kind: "api-key"
        )
    }
    values.values[account] = third
}

@Test func newCredentialRecoversAtEveryKillBoundaryWithoutKeychainAccess() throws {
    let account = "ref:FULMAR_CRASH_NEW"
    let target = Data("new-private-value".utf8)

    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "new")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        let interrupted = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )

        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.store(account: account, value: target, kind: "reference")
        }

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        try restarted.recover(account: account)

        if isMutationDurable(at: checkpoint) {
            #expect(values.values[account] == target)
            #expect(try restarted.metadata(account: account)?.kind == "reference")
            #expect(try restarted.readConfiguredValue(account: account) == target)
        } else {
            #expect(values.values[account] == nil)
            #expect(try restarted.metadata(account: account) == nil)
        }
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func replacementRecoversAtEveryKillBoundaryWithoutCredentialLoss() throws {
    let account = "ref:FULMAR_CRASH_REPLACE"
    let previous = Data("old-private-value".utf8)
    let target = Data("replacement-private-value".utf8)

    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "replace")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        values.values[account] = previous
        try fixture.state.writeMetadata(account: account, kind: "reference")
        let interrupted = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )

        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.store(account: account, value: target, kind: "reference")
        }

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        try restarted.recover(account: account)
        let expected = isMutationDurable(at: checkpoint) ? target : previous
        #expect(values.values[account] == expected)
        #expect(try restarted.metadata(account: account)?.kind == "reference")
        #expect(try restarted.readConfiguredValue(account: account) == expected)
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func metadataLessCredentialAdoptionRecoversAtEveryKillBoundary() throws {
    let account = "ref:FULMAR_CRASH_ORPHAN"
    let previous = Data("orphan-private-value".utf8)
    let target = Data("adopted-private-value".utf8)

    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "orphan")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        values.values[account] = previous
        let interrupted = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )

        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.store(account: account, value: target, kind: "reference")
        }

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        try restarted.recover(account: account)
        if isMutationDurable(at: checkpoint) {
            #expect(values.values[account] == target)
            #expect(try restarted.metadata(account: account)?.kind == "reference")
        } else {
            #expect(values.values[account] == previous)
            #expect(try restarted.metadata(account: account) == nil)
        }
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func credentialRemovalRecoversAtEveryKillBoundaryWithoutFalseConfiguredState() throws {
    let account = "ref:FULMAR_CRASH_REMOVE"
    let previous = Data("remove-private-value".utf8)

    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "remove")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        values.values[account] = previous
        try fixture.state.writeMetadata(account: account, kind: "reference")
        let interrupted = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )

        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.remove(account: account)
        }

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        try restarted.recover(account: account)
        if isMutationDurable(at: checkpoint) {
            #expect(values.values[account] == nil)
            #expect(try restarted.metadata(account: account) == nil)
        } else {
            #expect(values.values[account] == previous)
            #expect(try restarted.metadata(account: account)?.kind == "reference")
        }
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func journalPersistenceFaultsRecoverTheExactPriorStateAtEveryDurabilityCheckpoint() throws {
    let account = "ref:FULMAR_PERSISTENCE_JOURNAL"
    let target = Data("journal-target-value".utf8)

    for checkpoint in CredentialFileStatePersistenceCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "journal-persistence")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        var injected = false
        let interruptedState = try CredentialFileStateStore(
            directory: fixture.root,
            persistenceCheckpoint: { artifact, reached in
                guard !injected, artifact == .journal, reached == checkpoint else { return }
                injected = true
                throw SimulatedCredentialPersistenceFault.at(artifact, reached)
            }
        )
        let interrupted = CredentialTransactionCoordinator(
            stateStore: interruptedState,
            valueStore: values
        )

        #expect(throws: SimulatedCredentialPersistenceFault.self) {
            try interrupted.store(account: account, value: target, kind: "api-key")
        }
        #expect(injected)

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        try restarted.recover(account: account)
        #expect(values.values[account] == nil)
        #expect(try restarted.metadata(account: account) == nil)
        try assertNoPendingCredentialJournal(fixture)
        try assertNoCredentialTemporaryFile(fixture)
    }
}

@Test func metadataPersistenceFaultsRecoverTheExactCommittedStateAtEveryDurabilityCheckpoint() throws {
    let account = "ref:FULMAR_PERSISTENCE_METADATA"
    let previous = Data("metadata-prior-value".utf8)
    let target = Data("metadata-target-value".utf8)

    for checkpoint in CredentialFileStatePersistenceCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "metadata-persistence")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        values.values[account] = previous
        try fixture.state.writeMetadata(account: account, kind: "reference")
        var injected = false
        let interruptedState = try CredentialFileStateStore(
            directory: fixture.root,
            persistenceCheckpoint: { artifact, reached in
                guard !injected, artifact == .metadata, reached == checkpoint else { return }
                injected = true
                throw SimulatedCredentialPersistenceFault.at(artifact, reached)
            }
        )
        let interrupted = CredentialTransactionCoordinator(
            stateStore: interruptedState,
            valueStore: values
        )

        #expect(throws: SimulatedCredentialPersistenceFault.self) {
            try interrupted.store(account: account, value: target, kind: "api-key")
        }
        #expect(injected)

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        try restarted.recover(account: account)
        #expect(values.values[account] == target)
        #expect(try restarted.metadata(account: account)?.kind == "api-key")
        #expect(try restarted.readConfiguredValue(account: account) == target)
        try assertNoPendingCredentialJournal(fixture)
        try assertNoCredentialTemporaryFile(fixture)
    }
}

@Test func stagedStatePathSubstitutionCannotBecomeAFalseCommit() throws {
    let fixture = try CredentialCrashFixture(label: "staged-path-substitution")
    defer { fixture.remove() }
    let account = "ref:FULMAR_STAGED_PATH_SUBSTITUTION"
    var swapped = false
    let state = try CredentialFileStateStore(
        directory: fixture.root,
        persistenceCheckpoint: { artifact, reached in
            guard !swapped, artifact == .metadata, reached == .afterFileSynchronize else {
                return
            }
            let temporary = try #require(
                FileManager.default.contentsOfDirectory(
                    at: fixture.root,
                    includingPropertiesForKeys: nil
                ).first { $0.lastPathComponent.hasSuffix(".metadata.tmp") }
            )
            let displaced = fixture.root.appendingPathComponent(
                ".displaced-staged-inode",
                isDirectory: false
            )
            try FileManager.default.moveItem(at: temporary, to: displaced)
            #expect(FileManager.default.createFile(
                atPath: temporary.path,
                contents: Data(#"{"account":"attacker","kind":"reference","version":1}"#.utf8),
                attributes: [.posixPermissions: 0o600]
            ))
            swapped = true
        }
    )

    #expect(throws: CredentialTransactionError.self) {
        try state.writeMetadata(account: account, kind: "reference")
    }
    #expect(swapped)
    #expect(try fixture.state.readMetadata(account: account) == nil)
}

@Test func transactionJournalContainsNoCredentialBytesAndUsesPrivateFiles() throws {
    let fixture = try CredentialCrashFixture(label: "privacy")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_PRIVACY"
    let secret = Data("literal-secret-must-never-enter-journal".utf8)
    let values = FakeCredentialValueStore()
    let interrupted = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterJournalPrepared { throw SimulatedCredentialProcessKill.at(reached) }
        }
    )

    #expect(throws: SimulatedCredentialProcessKill.self) {
        try interrupted.store(account: account, value: secret, kind: "reference")
    }
    let files = try fixture.stateFiles()
    let journal = try #require(files.first { $0.lastPathComponent.hasSuffix(".transaction.json") })
    let bytes = try Data(contentsOf: journal)
    #expect(bytes.range(of: secret) == nil)
    let attributes = try FileManager.default.attributesOfItem(atPath: journal.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}

@Test func authorizationFailureLeavesPriorCredentialAndMetadataUntouched() throws {
    let fixture = try CredentialCrashFixture(label: "authorization")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_AUTH"
    let previous = Data("authorized-old-value".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = previous
    values.replaceError = .authorizationRequired
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    #expect(throws: CredentialValueStoreError.authorizationRequired) {
        try coordinator.store(account: account, value: Data("new-value".utf8), kind: "reference")
    }
    #expect(values.values[account] == previous)
    #expect(try coordinator.metadata(account: account)?.kind == "reference")
    try assertNoPendingCredentialJournal(fixture)

    // A catalogue refresh must not read a committed secret just to report
    // configuration. Actual resolution still requires Keychain authorization.
    values.readError = .authorizationRequired
    for kind in ["reference", "api-key", "grant"] {
        try fixture.state.writeMetadata(account: account, kind: kind)
        #expect(try coordinator.metadata(account: account)?.kind == kind)
        #expect(throws: CredentialValueStoreError.authorizationRequired) {
            try coordinator.readConfiguredValue(account: account)
        }
        #expect(try fixture.state.readMetadata(account: account)?.kind == kind)
        #expect(values.values[account] == previous)
        try assertNoPendingCredentialJournal(fixture)
    }
    try fixture.state.removeMetadata(account: account)
    #expect(try coordinator.metadata(account: account) == nil)
    #expect(values.values[account] == previous)
}

@Test func legacyMarkerWithoutCredentialIsReconciledOnResolution() throws {
    let fixture = try CredentialCrashFixture(label: "legacy-marker")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_LEGACY"
    let values = FakeCredentialValueStore()
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    #expect(try coordinator.readConfiguredValue(account: account) == nil)
    #expect(try coordinator.metadata(account: account) == nil)
}

@Test func unexpectedOutOfBandReplacementIsNeverOverwrittenDuringRollback() throws {
    let fixture = try CredentialCrashFixture(label: "out-of-band-replace")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_EXTERNAL_REPLACE"
    let previous = Data("previous-owned-value".utf8)
    let unrelated = Data("out-of-band-owned-value".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = previous
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterValueMutation { values.values[account] = unrelated }
        }
    )

    #expect(throws: CredentialTransactionError.verificationFailed) {
        try coordinator.store(account: account, value: Data("requested-value".utf8), kind: "reference")
    }
    #expect(values.values[account] == unrelated)
    #expect(try fixture.stateFiles().contains { $0.lastPathComponent.hasSuffix(".transaction.json") })
    let restarted = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    #expect(throws: CredentialTransactionError.ambiguousRecovery) {
        try restarted.recover(account: account)
    }
    #expect(values.values[account] == unrelated)
}

@Test func unexpectedOutOfBandValueAfterDeleteFailsClosedWithJournalIntact() throws {
    let fixture = try CredentialCrashFixture(label: "out-of-band-delete")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_EXTERNAL_DELETE"
    let previous = Data("previous-delete-value".utf8)
    let unrelated = Data("out-of-band-delete-value".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = previous
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterValueMutation { values.values[account] = unrelated }
        }
    )

    #expect(throws: CredentialTransactionError.ambiguousRecovery) {
        try coordinator.remove(account: account)
    }
    #expect(values.values[account] == unrelated)
    #expect(try fixture.stateFiles().contains { $0.lastPathComponent.hasSuffix(".transaction.json") })
}

@Test func concurrentCoordinatorsSerializeOneAccountAcrossIndependentFileDescriptors() throws {
    let fixture = try CredentialCrashFixture(label: "concurrent")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_CONCURRENT"
    let initial = Data("concurrent-initial".utf8)
    let first = Data("concurrent-first".utf8)
    let second = Data("concurrent-second".utf8)
    let values = BlockingCredentialValueStore(account: account, initial: initial, firstReplacement: first)
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let firstCoordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values
    )
    let secondCoordinator = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    let group = DispatchGroup()
    let errorLock = NSLock()
    var errors: [Error] = []

    group.enter()
    DispatchQueue.global().async {
        defer { group.leave() }
        do {
            try firstCoordinator.store(account: account, value: first, kind: "reference")
        } catch {
            errorLock.lock()
            errors.append(error)
            errorLock.unlock()
        }
    }
    #expect(values.firstReplacementEntered.wait(timeout: .now() + 2) == .success)

    group.enter()
    DispatchQueue.global().async {
        defer { group.leave() }
        do {
            try secondCoordinator.store(account: account, value: second, kind: "reference")
        } catch {
            errorLock.lock()
            errors.append(error)
            errorLock.unlock()
        }
    }
    usleep(100_000)
    #expect(values.snapshot(account: account).readCount == 1)
    values.allowFirstReplacement.signal()
    #expect(group.wait(timeout: .now() + 5) == .success)

    errorLock.lock()
    let recordedErrors = errors
    errorLock.unlock()
    #expect(recordedErrors.isEmpty)
    #expect(values.snapshot(account: account).value == second)
    #expect(try secondCoordinator.metadata(account: account)?.kind == "reference")
    try assertNoPendingCredentialJournal(fixture)
}

@Test func atomicRecordMutationHoldsTheCrossProcessLockAcrossReadDecideReplace() throws {
    let fixture = try CredentialCrashFixture(label: "atomic-record")
    defer { fixture.remove() }
    let account = "record:atomic"
    let initial = Data(#"{"kind":"grant","payload":{"generation":0}}"#.utf8)
    let first = Data(#"{"kind":"grant","payload":{"generation":1}}"#.utf8)
    let second = Data(#"{"kind":"grant","payload":{"generation":2}}"#.utf8)
    let values = BlockingCredentialValueStore(
        account: account,
        initial: initial,
        firstReplacement: Data("not-used".utf8)
    )
    try fixture.state.writeMetadata(account: account, kind: "grant")
    let firstCoordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)
    let secondCoordinator = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    let firstMutationEntered = DispatchSemaphore(value: 0)
    let releaseFirstMutation = DispatchSemaphore(value: 0)
    let secondMutationEntered = DispatchSemaphore(value: 0)
    let group = DispatchGroup()
    let errorLock = NSLock()
    var errors: [Error] = []
    var secondObserved: Data?

    group.enter()
    DispatchQueue.global().async {
        defer { group.leave() }
        do {
            _ = try firstCoordinator.modifyAtomically(account: account) { observed in
                #expect(observed == initial)
                firstMutationEntered.signal()
                _ = releaseFirstMutation.wait(timeout: .now() + 5)
                return .store(value: first, kind: "grant")
            }
        } catch {
            errorLock.lock(); errors.append(error); errorLock.unlock()
        }
    }
    #expect(firstMutationEntered.wait(timeout: .now() + 2) == .success)

    group.enter()
    DispatchQueue.global().async {
        defer { group.leave() }
        do {
            _ = try secondCoordinator.modifyAtomically(account: account) { observed in
                errorLock.lock(); secondObserved = observed; errorLock.unlock()
                secondMutationEntered.signal()
                return .store(value: second, kind: "grant")
            }
        } catch {
            errorLock.lock(); errors.append(error); errorLock.unlock()
        }
    }
    #expect(secondMutationEntered.wait(timeout: .now() + 0.1) == .timedOut)
    releaseFirstMutation.signal()
    #expect(group.wait(timeout: .now() + 5) == .success)

    errorLock.lock()
    let recordedErrors = errors
    let recordedSecondObserved = secondObserved
    errorLock.unlock()
    #expect(recordedErrors.isEmpty)
    #expect(recordedSecondObserved == first)
    #expect(values.snapshot(account: account).value == second)
    try assertNoPendingCredentialJournal(fixture)
}

@Test func replacingTheLockPathDuringATransactionFailsClosed() throws {
    let fixture = try CredentialCrashFixture(label: "lock-replacement")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CRASH_LOCK_REPLACEMENT"
    let values = FakeCredentialValueStore()
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            guard reached == .afterValueVerification else { return }
            let lock = try #require(fixture.stateFiles().first { $0.pathExtension == "lock" })
            try FileManager.default.removeItem(at: lock)
            #expect(FileManager.default.createFile(
                atPath: lock.path,
                contents: Data(),
                attributes: [.posixPermissions: 0o600]
            ))
        }
    )

    #expect(throws: CredentialTransactionError.self) {
        try coordinator.store(
            account: account,
            value: Data("lock-replacement-value".utf8),
            kind: "reference"
        )
    }
}

@Test func absentCredentialDescriptionsReuseOneFixedTransactionLock() throws {
    let fixture = try CredentialCrashFixture(label: "fixed-lock")
    defer { fixture.remove() }
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: FakeCredentialValueStore()
    )

    for index in 0..<1_000 {
        #expect(try coordinator.metadata(account: "ref:ABSENT_\(index)") == nil)
    }

    let files = try fixture.stateFiles()
    #expect(files.map(\.lastPathComponent) == [".credential-transactions.lock"])
}

@Test func valueFreeAttentionCatalogueIsolatesAuthorizationAmbiguityAndInvalidRecords() throws {
    let fixture = try CredentialCrashFixture(label: "attention-catalogue")
    defer { fixture.remove() }
    let values = FakeCredentialValueStore()
    let authorizationAccount = "record:authorization"
    let ambiguousAccount = "record:ambiguous"
    let invalidAccount = "record:invalid"
    let missingAccount = "record:missing"
    values.values[authorizationAccount] = Data(#"{"kind":"grant","payload":null}"#.utf8)
    try fixture.state.writeMetadata(account: authorizationAccount, kind: "grant")
    values.readErrors[authorizationAccount] = .authorizationRequired
    try prepareAmbiguousCredential(
        fixture: fixture,
        values: values,
        account: ambiguousAccount,
        previous: Data(#"{"kind":"grant","payload":"prior"}"#.utf8),
        third: Data(#"{"kind":"grant","payload":"third"}"#.utf8)
    )
    values.values[invalidAccount] = Data("not-json".utf8)
    try fixture.state.writeMetadata(account: invalidAccount, kind: "grant")
    try fixture.state.writeMetadata(account: missingAccount, kind: "grant")
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    let attention = try coordinator.listAttention { value, kind in
        kind != "grant" || (try? JSONSerialization.jsonObject(with: value)) != nil
    }
    #expect(attention.map { "\($0.account)|\($0.kind)|\($0.reason.rawValue)" } == [
        "\(ambiguousAccount)|reference|ambiguous",
        "\(authorizationAccount)|grant|authorization",
        "\(invalidAccount)|grant|invalid"
    ].sorted())
    #expect(attention.allSatisfy { $0.token.count == 64 && $0.token.allSatisfy(\.isHexDigit) })
    #expect(try fixture.state.readMetadata(account: missingAccount) == nil)
}

@Test func staleInvalidRecordAttentionCannotDeleteANewlyValidRecord() throws {
    let fixture = try CredentialCrashFixture(label: "stale-record-attention")
    defer { fixture.remove() }
    let account = "record:stale"
    let invalid = Data("not-json".utf8)
    let valid = Data(#"{"kind":"grant","payload":{"fresh":true}}"#.utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = invalid
    try fixture.state.writeMetadata(account: account, kind: "grant")
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)
    let attention = try coordinator.listAttention { value, _ in value != invalid }
    let token = try #require(attention.first?.token)

    values.values[account] = valid
    #expect(throws: CredentialTransactionError.conflict) {
        try coordinator.repairRemovingCurrentRecord(
            account: account,
            expectedToken: token,
            validateKind: { $0 == valid ? "grant" : nil }
        )
    }
    #expect(values.values[account] == valid)
    #expect(try coordinator.metadata(account: account)?.kind == "grant")
}

@Test func metadataLessRecordCanBeAdoptedWithoutOverwritingItsCurrentValue() throws {
    let fixture = try CredentialCrashFixture(label: "untracked-record")
    defer { fixture.remove() }
    let account = "record:untracked"
    let current = Data(#"{"kind":"api-key","key":"secret"}"#.utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = current
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    try coordinator.adoptUntrackedCurrentRecord(account: account) { value in
        value == current ? "api-key" : nil
    }
    #expect(values.values[account] == current)
    #expect(try coordinator.metadata(account: account)?.kind == "api-key")
}

@Test func malformedMetadataLessRecordCanOnlyBeRemovedWithItsExactAttentionToken() throws {
    let fixture = try CredentialCrashFixture(label: "unknown-untracked-record")
    defer { fixture.remove() }
    let account = "record:unknown-untracked"
    let malformed = Data([0xff, 0x00, 0x7b, 0x01])
    let replacement = Data(#"{"kind":"future-record","payload":"changed"}"#.utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = malformed
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)
    let token = CredentialTransactionCoordinator.attentionToken(
        account: account, kind: "unknown", reason: .invalid, value: malformed
    )

    // A token is bound to the exact hidden value, so a stale recovery prompt
    // cannot remove a record that changed after it was listed.
    values.values[account] = replacement
    #expect(throws: CredentialTransactionError.conflict) {
        try coordinator.repairRemovingCurrentRecord(
            account: account,
            expectedToken: token,
            validateKind: { _ in nil },
            declaredKind: { _ in nil }
        )
    }
    #expect(values.values[account] == replacement)

    values.values[account] = malformed
    try coordinator.repairRemovingCurrentRecord(
        account: account,
        expectedToken: token,
        validateKind: { _ in nil },
        declaredKind: { _ in nil }
    )
    #expect(values.values[account] == nil)
    #expect(try coordinator.metadata(account: account) == nil)
}

@Test func ambiguousAccountDoesNotHideOtherCommittedCredentialMetadata() throws {
    let fixture = try CredentialCrashFixture(label: "isolated-attention")
    defer { fixture.remove() }
    let ambiguousAccount = "ref:FULMAR_AMBIGUOUS_ACCOUNT"
    let healthyAccount = "ref:FULMAR_HEALTHY_ACCOUNT"
    let values = FakeCredentialValueStore()
    values.values[ambiguousAccount] = Data("ambiguous-prior".utf8)
    values.values[healthyAccount] = Data("healthy-value".utf8)
    try fixture.state.writeMetadata(account: ambiguousAccount, kind: "reference")
    try fixture.state.writeMetadata(account: healthyAccount, kind: "reference")

    let interrupted = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterJournalPrepared {
                throw SimulatedCredentialProcessKill.at(reached)
            }
        }
    )
    #expect(throws: SimulatedCredentialProcessKill.self) {
        try interrupted.store(
            account: ambiguousAccount,
            value: Data("ambiguous-target".utf8),
            kind: "api-key"
        )
    }
    values.values[ambiguousAccount] = Data("unexpected-third-value".utf8)

    let restarted = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    let listed = try restarted.listCommittedMetadata()
    #expect(listed == [CredentialMetadata(account: healthyAccount, kind: "reference")])
    #expect(try fixture.stateFiles().contains { $0.lastPathComponent.hasSuffix(".transaction.json") })
}

@Test func concurrentCatalogueReadsAndCredentialMutationsRemainCoherent() throws {
    let fixture = try CredentialCrashFixture(label: "catalogue-concurrency")
    defer { fixture.remove() }
    let account = "ref:FULMAR_CATALOGUE_CONCURRENCY"
    let values = FakeCredentialValueStore()
    let writer = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values
    )
    let reader = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    let group = DispatchGroup()
    let errorLock = NSLock()
    var errors: [Error] = []

    group.enter()
    DispatchQueue.global().async {
        defer { group.leave() }
        do {
            for iteration in 0..<100 {
                try writer.store(
                    account: account,
                    value: Data("catalogue-value-\(iteration)".utf8),
                    kind: "reference"
                )
                try writer.remove(account: account)
            }
        } catch {
            errorLock.lock(); errors.append(error); errorLock.unlock()
        }
    }
    group.enter()
    DispatchQueue.global().async {
        defer { group.leave() }
        do {
            for _ in 0..<200 {
                let metadata = try reader.listCommittedMetadata()
                guard metadata.isEmpty
                    || metadata == [CredentialMetadata(account: account, kind: "reference")] else {
                    throw CredentialTransactionError.unsafeState("catalogue returned an incoherent state")
                }
            }
        } catch {
            errorLock.lock(); errors.append(error); errorLock.unlock()
        }
    }

    #expect(group.wait(timeout: .now() + 15) == .success)
    errorLock.lock(); let recordedErrors = errors; errorLock.unlock()
    #expect(recordedErrors.isEmpty)
}

@Test func oversizedCredentialStateDirectoryFailsClosedAtAnExplicitEntryBound() throws {
    let fixture = try CredentialCrashFixture(label: "directory-bound")
    defer { fixture.remove() }
    for index in 0...4_096 {
        let path = fixture.root.appendingPathComponent("unrelated-\(index).entry")
        #expect(FileManager.default.createFile(
            atPath: path.path,
            contents: Data([0]),
            attributes: [.posixPermissions: 0o600]
        ))
    }
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: FakeCredentialValueStore()
    )
    #expect(throws: CredentialTransactionError.self) {
        _ = try coordinator.listCommittedMetadata()
    }
}

@Test func storeReverifiesAfterMetadataCommitAndNeverRetiresAThirdValueJournal() throws {
    let fixture = try CredentialCrashFixture(label: "store-final-verification")
    defer { fixture.remove() }
    let account = "ref:FULMAR_STORE_FINAL_VERIFICATION"
    let previous = Data("store-final-previous".utf8)
    let target = Data("store-final-target".utf8)
    let third = Data("store-final-third".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = previous
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterMetadataCommit { values.values[account] = third }
        }
    )

    #expect(throws: CredentialTransactionError.ambiguousRecovery) {
        try coordinator.store(account: account, value: target, kind: "api-key")
    }
    #expect(values.values[account] == third)
    #expect(try fixture.stateFiles().contains { $0.lastPathComponent.hasSuffix(".transaction.json") })
    #expect(throws: CredentialTransactionError.ambiguousRecovery) {
        try CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        ).recover(account: account)
    }
}

@Test func finalStoreVerificationRestoresPriorStateWhenPriorValueReappears() throws {
    let fixture = try CredentialCrashFixture(label: "store-final-prior")
    defer { fixture.remove() }
    let account = "ref:FULMAR_STORE_FINAL_PRIOR"
    let previous = Data("store-prior-value".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = previous
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(
        stateStore: fixture.state,
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterMetadataCommit { values.values[account] = previous }
        }
    )
    #expect(throws: CredentialTransactionError.ambiguousRecovery) {
        try coordinator.store(
            account: account,
            value: Data("store-new-value".utf8),
            kind: "api-key"
        )
    }

    let restarted = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    try restarted.recover(account: account)
    #expect(try restarted.metadata(account: account)?.kind == "reference")
    #expect(values.values[account] == previous)
    try assertNoPendingCredentialJournal(fixture)
}

@Test func removeReverifiesAfterMetadataCommitAndRecoversPriorOrRejectsThirdValue() throws {
    for restoreThirdValue in [false, true] {
        let fixture = try CredentialCrashFixture(label: "remove-final-\(restoreThirdValue)")
        defer { fixture.remove() }
        let account = "ref:FULMAR_REMOVE_FINAL_\(restoreThirdValue)"
        let previous = Data("remove-final-previous".utf8)
        let third = Data("remove-final-third".utf8)
        let values = FakeCredentialValueStore()
        values.values[account] = previous
        try fixture.state.writeMetadata(account: account, kind: "reference")
        let coordinator = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == .afterMetadataCommit {
                    values.values[account] = restoreThirdValue ? third : previous
                }
            }
        )
        #expect(throws: CredentialTransactionError.ambiguousRecovery) {
            try coordinator.remove(account: account)
        }
        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        if restoreThirdValue {
            #expect(throws: CredentialTransactionError.ambiguousRecovery) {
                try restarted.recover(account: account)
            }
            #expect(try fixture.stateFiles().contains { $0.lastPathComponent.hasSuffix(".transaction.json") })
        } else {
            try restarted.recover(account: account)
            #expect(try restarted.metadata(account: account)?.kind == "reference")
            #expect(values.values[account] == previous)
            try assertNoPendingCredentialJournal(fixture)
        }
    }
}

@Test func foregroundRepairCanAdoptReplaceOrRemoveOnlyTheFreshAmbiguousValue() throws {
    for action in ["adopt", "replace", "remove"] {
        let fixture = try CredentialCrashFixture(label: "repair-\(action)")
        defer { fixture.remove() }
        let account = "ref:FULMAR_REPAIR_\(action.uppercased())"
        let previous = Data("repair-previous".utf8)
        let third = Data("repair-third-\(action)".utf8)
        let replacement = Data("repair-replacement".utf8)
        let values = FakeCredentialValueStore()
        try prepareAmbiguousCredential(
            fixture: fixture,
            values: values,
            account: account,
            previous: previous,
            third: third
        )
        let coordinator = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )

        switch action {
        case "adopt":
            try coordinator.repairAdoptingCurrentValue(account: account, kind: "api-key")
            #expect(values.values[account] == third)
            #expect(try coordinator.metadata(account: account)?.kind == "api-key")
        case "replace":
            try coordinator.repairReplacingCurrentValue(
                account: account,
                value: replacement,
                kind: "api-key"
            )
            #expect(values.values[account] == replacement)
            #expect(try coordinator.metadata(account: account)?.kind == "api-key")
        default:
            try coordinator.repairRemovingCurrentValue(account: account, kind: "reference")
            #expect(values.values[account] == nil)
            #expect(try coordinator.metadata(account: account) == nil)
        }
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func interruptedForegroundReplacementNeverSilentlyAdoptsTheAmbiguousValue() throws {
    let account = "ref:FULMAR_REPAIR_INTERRUPTED"
    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "repair-interrupted")
        defer { fixture.remove() }
        let previous = Data("repair-interrupted-previous".utf8)
        let third = Data("repair-interrupted-third".utf8)
        let replacement = Data("repair-interrupted-replacement".utf8)
        let values = FakeCredentialValueStore()
        try prepareAmbiguousCredential(
            fixture: fixture,
            values: values,
            account: account,
            previous: previous,
            third: third
        )
        let interrupted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )
        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.repairReplacingCurrentValue(
                account: account,
                value: replacement,
                kind: "api-key"
            )
        }
        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        if checkpoint == .afterJournalPrepared {
            #expect(throws: CredentialTransactionError.ambiguousRecovery) {
                try restarted.recover(account: account)
            }
            #expect(values.values[account] == third)
        } else {
            try restarted.recover(account: account)
            #expect(values.values[account] == replacement)
            #expect(try restarted.metadata(account: account)?.kind == "api-key")
            try assertNoPendingCredentialJournal(fixture)
        }
    }
}

@Test func foregroundRepairAuthorizationDenialAndConcurrentThirdValueStayFailClosed() throws {
    let fixture = try CredentialCrashFixture(label: "repair-denied")
    defer { fixture.remove() }
    let account = "ref:FULMAR_REPAIR_DENIED"
    let previous = Data("repair-denied-previous".utf8)
    let third = Data("repair-denied-third".utf8)
    let values = FakeCredentialValueStore()
    try prepareAmbiguousCredential(
        fixture: fixture,
        values: values,
        account: account,
        previous: previous,
        third: third
    )
    values.readError = .authorizationRequired
    let denied = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values
    )
    let journalBefore = try Data(contentsOf: credentialStateURL(fixture: fixture, account: account, journal: true))
    let metadataBefore = try Data(contentsOf: credentialStateURL(fixture: fixture, account: account, journal: false))
    // Metadata lookup must still recover pending transactions, never turn an
    // authorization failure into a configured result or discard its journal.
    #expect(throws: CredentialValueStoreError.authorizationRequired) {
        try denied.metadata(account: account)
    }
    #expect(try Data(contentsOf: credentialStateURL(fixture: fixture, account: account, journal: true)) == journalBefore)
    #expect(try Data(contentsOf: credentialStateURL(fixture: fixture, account: account, journal: false)) == metadataBefore)
    #expect(values.values[account] == third)
    #expect(throws: CredentialValueStoreError.authorizationRequired) {
        try denied.repairAdoptingCurrentValue(account: account, kind: "reference")
    }
    values.readError = nil

    let changedAgain = Data("repair-denied-fourth".utf8)
    let concurrent = CredentialTransactionCoordinator(
        stateStore: try CredentialFileStateStore(directory: fixture.root),
        valueStore: values,
        checkpoint: { reached in
            if reached == .afterMetadataCommit { values.values[account] = changedAgain }
        }
    )
    #expect(throws: CredentialTransactionError.ambiguousRecovery) {
        try concurrent.repairAdoptingCurrentValue(account: account, kind: "reference")
    }
    #expect(values.values[account] == changedAgain)
    #expect(try fixture.stateFiles().contains { $0.lastPathComponent.hasSuffix(".transaction.json") })
}

@Test func missingAmbiguousValueCanBeExplicitlyReplacedOrRemovedButNotAdopted() throws {
    for action in ["replace", "remove"] {
        let fixture = try CredentialCrashFixture(label: "repair-missing-\(action)")
        defer { fixture.remove() }
        let account = "ref:FULMAR_REPAIR_MISSING_\(action.uppercased())"
        let values = FakeCredentialValueStore()
        try prepareAmbiguousCredential(
            fixture: fixture,
            values: values,
            account: account,
            previous: Data("repair-missing-previous".utf8),
            third: Data("repair-missing-third".utf8)
        )
        values.values[account] = nil
        let coordinator = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )

        #expect(throws: CredentialTransactionError.recoveryValueMissing) {
            try coordinator.repairAdoptingCurrentValue(account: account, kind: "reference")
        }
        if action == "replace" {
            let replacement = Data("repair-missing-replacement".utf8)
            try coordinator.repairReplacingCurrentValue(
                account: account,
                value: replacement,
                kind: "api-key"
            )
            #expect(values.values[account] == replacement)
            #expect(try coordinator.metadata(account: account)?.kind == "api-key")
        } else {
            try coordinator.repairRemovingCurrentValue(account: account, kind: "reference")
            #expect(values.values[account] == nil)
            #expect(try coordinator.metadata(account: account) == nil)
        }
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func interruptedMissingValueReplacementNeverSilentlyCommitsBeforeTheAdd() throws {
    let account = "ref:FULMAR_REPAIR_MISSING_INTERRUPTED"
    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "repair-missing-interrupted")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        try prepareAmbiguousCredential(
            fixture: fixture,
            values: values,
            account: account,
            previous: Data("repair-missing-interrupted-previous".utf8),
            third: Data("repair-missing-interrupted-third".utf8)
        )
        values.values[account] = nil
        let replacement = Data("repair-missing-interrupted-replacement".utf8)
        let interrupted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )
        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.repairReplacingCurrentValue(
                account: account,
                value: replacement,
                kind: "api-key"
            )
        }
        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        if checkpoint == .afterJournalPrepared {
            #expect(throws: CredentialTransactionError.ambiguousRecovery) {
                try restarted.recover(account: account)
            }
            #expect(values.values[account] == nil)
        } else {
            try restarted.recover(account: account)
            #expect(values.values[account] == replacement)
            #expect(try restarted.metadata(account: account)?.kind == "api-key")
            try assertNoPendingCredentialJournal(fixture)
        }
    }
}

@Test func interruptedVersionTwoRepairJournalNeverBreaksTheHealthyCredentialCatalogue() throws {
    for checkpoint in [
        CredentialTransactionCheckpoint.afterJournalPrepared,
        .afterValueMutation,
    ] {
        let fixture = try CredentialCrashFixture(label: "repair-catalogue-\(checkpoint.rawValue)")
        defer { fixture.remove() }
        let account = "ref:FULMAR_REPAIR_CATALOGUE_\(checkpoint.rawValue)"
        let healthyAccount = "ref:FULMAR_REPAIR_CATALOGUE_HEALTHY_\(checkpoint.rawValue)"
        let values = FakeCredentialValueStore()
        try prepareAmbiguousCredential(
            fixture: fixture,
            values: values,
            account: account,
            previous: Data("repair-catalogue-previous".utf8),
            third: Data("repair-catalogue-third".utf8)
        )
        values.values[healthyAccount] = Data("repair-catalogue-healthy".utf8)
        try fixture.state.writeMetadata(account: healthyAccount, kind: "reference")
        let replacement = Data("repair-catalogue-replacement".utf8)
        let interrupted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )
        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.repairReplacingCurrentValue(
                account: account,
                value: replacement,
                kind: "api-key"
            )
        }

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        let listed = try restarted.listCommittedMetadata()
        if checkpoint == .afterJournalPrepared {
            #expect(listed == [CredentialMetadata(account: healthyAccount, kind: "reference")])
            #expect(try fixture.stateFiles().contains {
                $0.lastPathComponent.hasSuffix(".transaction.json")
            })
        } else {
            #expect(listed.map { "\($0.account):\($0.kind)" }.sorted() == [
                "\(account):api-key",
                "\(healthyAccount):reference",
            ].sorted())
            #expect(values.values[account] == replacement)
            try assertNoPendingCredentialJournal(fixture)
        }
    }
}

@Test func duplicateAddRaceIsRecoverableBeforeAndAfterTheRewrittenJournal() throws {
    let account = "ref:FULMAR_DUPLICATE_ADD_RACE"
    let raced = Data("independent-raced-value".utf8)
    let target = Data("requested-race-value".utf8)

    for stopAfterPreparedJournal in [1, 2] {
        let fixture = try CredentialCrashFixture(label: "duplicate-race-\(stopAfterPreparedJournal)")
        defer { fixture.remove() }
        let values = DuplicateAddRaceCredentialValueStore(racedValue: raced)
        var preparedCount = 0
        let interrupted = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                guard reached == .afterJournalPrepared else { return }
                preparedCount += 1
                if preparedCount == stopAfterPreparedJournal {
                    throw SimulatedCredentialProcessKill.at(reached)
                }
            }
        )
        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.store(account: account, value: target, kind: "api-key")
        }

        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        #expect(try restarted.metadata(account: account) == nil)
        #expect(values.value == (stopAfterPreparedJournal == 1 ? nil : raced))
        try assertNoPendingCredentialJournal(fixture)
    }

    let fixture = try CredentialCrashFixture(label: "duplicate-race-complete")
    defer { fixture.remove() }
    let values = DuplicateAddRaceCredentialValueStore(racedValue: raced)
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)
    try coordinator.store(account: account, value: target, kind: "api-key")
    #expect(values.value == target)
    #expect(try coordinator.metadata(account: account)?.kind == "api-key")
    try assertNoPendingCredentialJournal(fixture)
}

@Test func sameValueDifferentKindReplacementHasDeterministicCrashRecovery() throws {
    let account = "ref:FULMAR_SAME_VALUE_DIFFERENT_KIND"
    let value = Data("same-value-kind-change".utf8)
    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "same-value-kind-\(checkpoint.rawValue)")
        defer { fixture.remove() }
        let values = FakeCredentialValueStore()
        values.values[account] = value
        try fixture.state.writeMetadata(account: account, kind: "reference")
        let interrupted = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )
        #expect(throws: SimulatedCredentialProcessKill.self) {
            try interrupted.store(account: account, value: value, kind: "api-key")
        }
        let restarted = CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directory: fixture.root),
            valueStore: values
        )
        try restarted.recover(account: account)
        #expect(values.values[account] == value)
        #expect(try restarted.metadata(account: account)?.kind == "api-key")
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func journalAndMetadataRejectCorruptTruncatedLinkedPublicAndOversizedFiles() throws {
    enum Mutation: CaseIterable {
        case corrupt, truncated, symbolicLink, hardLink, publicMode, oversized
    }

    for journal in [false, true] {
        for mutation in Mutation.allCases {
            let fixture = try CredentialCrashFixture(
                label: "unsafe-\(journal ? "journal" : "metadata")-\(mutation)"
            )
            defer { fixture.remove() }
            let account = "ref:FULMAR_UNSAFE_STATE_\(journal)_\(mutation)"
            let stateURL = credentialStateURL(fixture: fixture, account: account, journal: journal)
            let payload: Data
            switch mutation {
            case .corrupt:
                payload = Data("not-json".utf8)
            case .truncated:
                payload = Data("{\"version\":".utf8)
            case .oversized:
                payload = Data(repeating: 0x41, count: journal ? 16_385 : 4_097)
            default:
                payload = Data("{}".utf8)
            }

            if mutation == .symbolicLink || mutation == .hardLink {
                let target = fixture.root.appendingPathComponent("target-\(UUID().uuidString)")
                #expect(FileManager.default.createFile(
                    atPath: target.path,
                    contents: payload,
                    attributes: [.posixPermissions: 0o600]
                ))
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: target.path
                )
                if mutation == .symbolicLink {
                    try FileManager.default.createSymbolicLink(
                        at: stateURL,
                        withDestinationURL: target
                    )
                } else {
                    #expect(Darwin.link(target.path, stateURL.path) == 0)
                }
            } else {
                #expect(FileManager.default.createFile(
                    atPath: stateURL.path,
                    contents: payload,
                    attributes: [.posixPermissions: mutation == .publicMode ? 0o644 : 0o600]
                ))
                try FileManager.default.setAttributes(
                    [.posixPermissions: mutation == .publicMode ? 0o644 : 0o600],
                    ofItemAtPath: stateURL.path
                )
            }

            let coordinator = CredentialTransactionCoordinator(
                stateStore: fixture.state,
                valueStore: FakeCredentialValueStore()
            )
            #expect(throws: CredentialTransactionError.self) {
                if journal {
                    try coordinator.recover(account: account)
                } else {
                    _ = try coordinator.metadata(account: account)
                }
            }
        }
    }
}

private enum SimulatedMigrationCommitFailure: Error {
    case beforeScrub
}

@Test func migrationBatchRollbackRestoresUntrackedRawValueAndExactMetadataAbsence() throws {
    let fixture = try CredentialCrashFixture(label: "migration-batch-untracked")
    defer { fixture.remove() }
    let account = "record:untracked-existing"
    let prior = Data("prior-untracked-value".utf8)
    let target = Data("migration-target".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = prior
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    #expect(throws: SimulatedMigrationCommitFailure.beforeScrub) {
        try coordinator.withAtomicMigrationBatch(entries: [
            CredentialMigrationBatchEntry(account: account, value: target, kind: "api-key"),
        ]) { _ in
            throw SimulatedMigrationCommitFailure.beforeScrub
        }
    }
    #expect(values.values[account] == prior)
    #expect(try coordinator.metadata(account: account) == nil)
    try assertNoPendingCredentialJournal(fixture)
}

@Test func migrationBatchRollbackRestoresTrackedValueAndKindExactly() throws {
    let fixture = try CredentialCrashFixture(label: "migration-batch-tracked")
    defer { fixture.remove() }
    let account = "ref:TRACKED_EXISTING"
    let prior = Data("prior-tracked-value".utf8)
    let target = Data("migration-target".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = prior
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    #expect(throws: SimulatedMigrationCommitFailure.beforeScrub) {
        try coordinator.withAtomicMigrationBatch(entries: [
            CredentialMigrationBatchEntry(account: account, value: target, kind: "api-key"),
        ]) { _ in
            throw SimulatedMigrationCommitFailure.beforeScrub
        }
    }
    #expect(values.values[account] == prior)
    #expect(try coordinator.metadata(account: account)?.kind == "reference")
    try assertNoPendingCredentialJournal(fixture)
}

@Test func migrationBatchNeverOverwritesConcurrentThirdValueDuringRollback() throws {
    let fixture = try CredentialCrashFixture(label: "migration-batch-third-value")
    defer { fixture.remove() }
    let account = "ref:CONCURRENT_THIRD_VALUE"
    let prior = Data("prior".utf8)
    let target = Data("target".utf8)
    let third = Data("concurrent-third".utf8)
    let values = FakeCredentialValueStore()
    values.values[account] = prior
    try fixture.state.writeMetadata(account: account, kind: "reference")
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    #expect(throws: CredentialTransactionError.batchRollbackIncomplete) {
        try coordinator.withAtomicMigrationBatch(entries: [
            CredentialMigrationBatchEntry(account: account, value: target, kind: "api-key"),
        ]) { _ in
            values.values[account] = third
            throw SimulatedMigrationCommitFailure.beforeScrub
        }
    }
    #expect(values.values[account] == third)
}

@Test func migrationBatchCrashAtEveryCredentialCheckpointRestoresWholeSnapshot() throws {
    for checkpoint in CredentialTransactionCheckpoint.allCases {
        let fixture = try CredentialCrashFixture(label: "migration-batch-kill-\(checkpoint.rawValue)")
        defer { fixture.remove() }
        let first = "ref:MIGRATION_KILL_FIRST"
        let second = "record:migration-kill-second"
        let firstPrior = Data("first-prior".utf8)
        let secondPrior = Data("second-prior".utf8)
        let values = FakeCredentialValueStore()
        values.values[first] = firstPrior
        values.values[second] = secondPrior
        try fixture.state.writeMetadata(account: first, kind: "reference")
        let coordinator = CredentialTransactionCoordinator(
            stateStore: fixture.state,
            valueStore: values,
            checkpoint: { reached in
                if reached == checkpoint { throw SimulatedCredentialProcessKill.at(reached) }
            }
        )
        #expect(throws: SimulatedCredentialProcessKill.self) {
            try coordinator.withAtomicMigrationBatch(entries: [
                CredentialMigrationBatchEntry(
                    account: first, value: Data("first-target".utf8), kind: "reference"
                ),
                CredentialMigrationBatchEntry(
                    account: second, value: Data("second-target".utf8), kind: "grant"
                ),
            ]) { _ in () }
        }
        #expect(values.values[first] == firstPrior)
        #expect(values.values[second] == secondPrior)
        #expect(try fixture.state.readMetadata(account: first)?.kind == "reference")
        #expect(try fixture.state.readMetadata(account: second) == nil)
        try assertNoPendingCredentialJournal(fixture)
    }
}

@Test func migrationEvidenceVerifiesEveryCurrentValueDigestAndMetadataKind() throws {
    let fixture = try CredentialCrashFixture(label: "migration-evidence")
    defer { fixture.remove() }
    let values = FakeCredentialValueStore()
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)
    let entries = [
        CredentialMigrationBatchEntry(
            account: "ref:EVIDENCE_ONE", value: Data("one".utf8), kind: "reference"
        ),
        CredentialMigrationBatchEntry(
            account: "record:evidence-two", value: Data("two".utf8), kind: "grant"
        ),
    ]
    let evidence = try coordinator.withAtomicMigrationBatch(entries: entries) { $0 }
    #expect(try coordinator.verifyMigrationEvidence(evidence))
    values.values["record:evidence-two"] = Data("third".utf8)
    #expect(!(try coordinator.verifyMigrationEvidence(evidence)))
}

@Test func migrationBatchPreservesAThirdValueObservedAfterItsSnapshot() throws {
    let fixture = try CredentialCrashFixture(label: "migration-pre-store-third-value")
    defer { fixture.remove() }
    let account = "ref:MIGRATION_PRE_STORE_THIRD"
    let initial = Data("initial".utf8)
    let third = Data("third".utf8)
    let values = PreStoreThirdValueCredentialValueStore(initial: initial, third: third)
    let coordinator = CredentialTransactionCoordinator(stateStore: fixture.state, valueStore: values)

    #expect(throws: CredentialTransactionError.conflict) {
        try coordinator.withAtomicMigrationBatch(entries: [
            CredentialMigrationBatchEntry(
                account: account,
                value: Data("migration-target".utf8),
                kind: "reference"
            ),
        ]) { _ in () }
    }
    #expect(values.value == third)
    #expect(try fixture.state.readMetadata(account: account) == nil)
    try assertNoPendingCredentialJournal(fixture)
}
