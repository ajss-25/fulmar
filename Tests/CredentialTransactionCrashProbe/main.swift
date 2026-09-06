import CryptoKit
import Darwin
import Foundation
import LocalHarnessCredentialSecurity

private enum ProbeScenario: String, CaseIterable {
    case create
    case replace
    case adopt
    case remove
    case repairAdopt = "repair-adopt"
    case repairReplace = "repair-replace"
    case repairRemove = "repair-remove"
    case unknownRecordRemove = "unknown-record-remove"
}

private enum ProbeFailure: Error, CustomStringConvertible {
    case invalidArguments
    case unsafeFixture(String)
    case failed(String)

    var description: String {
        switch self {
        case .invalidArguments:
            "invalid arguments"
        case let .unsafeFixture(message), let .failed(message):
            message
        }
    }
}

private let account = "ref:FULMAR_PROCESS_CRASH_FIXTURE"

private func priorValue(for scenario: ProbeScenario) -> Data {
    Data("fake-prior-\(scenario.rawValue)-value".utf8)
}

private func targetValue(for scenario: ProbeScenario) -> Data {
    Data("fake-target-\(scenario.rawValue)-value".utf8)
}

private func thirdValue(for scenario: ProbeScenario) -> Data {
    Data("fake-third-\(scenario.rawValue)-value".utf8)
}

private func repairValue(for scenario: ProbeScenario) -> Data {
    Data("fake-repair-\(scenario.rawValue)-value".utf8)
}

private let malformedUnknownRecord = Data([0xff, 0x00, 0x7b, 0x01])

private func digest(_ text: String) -> String {
    SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
}

private func writeAll(_ text: String, descriptor: Int32) {
    let bytes = Array(text.utf8)
    bytes.withUnsafeBytes { storage in
        var offset = 0
        while offset < storage.count {
            let count = Darwin.write(
                descriptor,
                storage.baseAddress!.advanced(by: offset),
                storage.count - offset
            )
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return }
            offset += count
        }
    }
}

private func validatePrivateDirectory(_ directory: URL, requireGateRoot: Bool = false) throws {
    let standardized = directory.standardizedFileURL.path
    let resolved = directory.resolvingSymlinksInPath().standardizedFileURL.path
    guard directory.path == standardized, resolved == standardized else {
        throw ProbeFailure.unsafeFixture("fixture directory aliases or traverses a symlink")
    }
    if requireGateRoot {
        guard standardized.hasPrefix("/tmp/fulmar-credential-crash-gate.") else {
            throw ProbeFailure.unsafeFixture("fixture is outside the dedicated /tmp gate root")
        }
    }
    var metadata = stat()
    guard lstat(standardized, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFDIR,
          metadata.st_uid == geteuid(),
          metadata.st_mode & 0o777 == 0o700 else {
        throw ProbeFailure.unsafeFixture("fixture directory is not owner-only")
    }
}

private func createPrivateDirectory(_ directory: URL) throws {
    guard mkdir(directory.path, S_IRWXU) == 0 else {
        throw ProbeFailure.failed("could not create private probe directory")
    }
    try validatePrivateDirectory(directory)
}

/// A deliberately test-only, file-backed CredentialValueStore. It does not
/// import Security or call Keychain APIs. Each mutation is durable before the
/// coordinator checkpoint is announced to the parent gate.
private final class FileBackedFakeCredentialValueStore: CredentialValueStore {
    private let directory: URL
    private let maximumValueBytes = 1_048_576

    init(directory: URL) throws {
        self.directory = directory
        try validatePrivateDirectory(directory)
    }

    func read(account: String) throws -> Data? {
        try validatePrivateDirectory(directory)
        let path = valueURL(account: account)
        var pathMetadata = stat()
        if lstat(path.path, &pathMetadata) != 0 {
            if errno == ENOENT { return nil }
            throw CredentialValueStoreError.status(errno)
        }
        try validateFile(pathMetadata)
        let descriptor = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CredentialValueStoreError.status(errno) }
        defer { _ = close(descriptor) }
        var descriptorMetadata = stat()
        var secondPathMetadata = stat()
        guard fstat(descriptor, &descriptorMetadata) == 0,
              lstat(path.path, &secondPathMetadata) == 0,
              descriptorMetadata.st_dev == secondPathMetadata.st_dev,
              descriptorMetadata.st_ino == secondPathMetadata.st_ino else {
            throw ProbeFailure.unsafeFixture("fake value changed while opening")
        }
        try validateFile(descriptorMetadata)
        let size = Int(descriptorMetadata.st_size)
        var value = Data(count: size)
        var offset = 0
        let complete = value.withUnsafeMutableBytes { storage -> Bool in
            while offset < size {
                let count = Darwin.read(
                    descriptor,
                    storage.baseAddress!.advanced(by: offset),
                    size - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard complete else { throw ProbeFailure.failed("fake value could not be read") }
        return value
    }

    func add(account: String, value: Data) throws {
        guard try read(account: account) == nil else { throw CredentialValueStoreError.duplicate }
        try atomicWrite(value, destination: valueURL(account: account))
    }

    func replace(account: String, value: Data) throws {
        guard try read(account: account) != nil else {
            throw CredentialValueStoreError.status(-25_300)
        }
        try atomicWrite(value, destination: valueURL(account: account))
    }

    func delete(account: String) throws {
        try validatePrivateDirectory(directory)
        let path = valueURL(account: account)
        var metadata = stat()
        if lstat(path.path, &metadata) != 0 {
            if errno == ENOENT { return }
            throw CredentialValueStoreError.status(errno)
        }
        try validateFile(metadata)
        guard unlink(path.path) == 0 else { throw CredentialValueStoreError.status(errno) }
        try synchronizeDirectory()
    }

    private func valueURL(account: String) -> URL {
        directory.appendingPathComponent(digest(account) + ".fake-value", isDirectory: false)
    }

    private func temporaryURL(accountDestination: URL) -> URL {
        directory.appendingPathComponent(".\(accountDestination.lastPathComponent).tmp", isDirectory: false)
    }

    private func validateFile(_ metadata: stat) throws {
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size > 0,
              metadata.st_size <= maximumValueBytes else {
            throw ProbeFailure.unsafeFixture("fake value file is unsafe")
        }
    }

    private func atomicWrite(_ value: Data, destination: URL) throws {
        guard !value.isEmpty, value.count <= maximumValueBytes else {
            throw ProbeFailure.failed("fake value is out of bounds")
        }
        try validatePrivateDirectory(directory)
        let temporary = temporaryURL(accountDestination: destination)
        if unlink(temporary.path) != 0, errno != ENOENT {
            throw CredentialValueStoreError.status(errno)
        }
        let descriptor = open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else { throw CredentialValueStoreError.status(errno) }
        var closed = false
        defer {
            if !closed { _ = close(descriptor) }
            _ = unlink(temporary.path)
        }
        var offset = 0
        let complete = value.withUnsafeBytes { storage -> Bool in
            while offset < value.count {
                let count = Darwin.write(
                    descriptor,
                    storage.baseAddress!.advanced(by: offset),
                    value.count - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard complete, fsync(descriptor) == 0 else {
            throw ProbeFailure.failed("fake value could not be synchronized")
        }
        guard close(descriptor) == 0 else {
            closed = true
            throw ProbeFailure.failed("fake value could not be closed")
        }
        closed = true
        guard rename(temporary.path, destination.path) == 0 else {
            throw ProbeFailure.failed("fake value could not be committed")
        }
        try synchronizeDirectory()
    }

    private func synchronizeDirectory() throws {
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CredentialValueStoreError.status(errno) }
        defer { _ = close(descriptor) }
        guard fsync(descriptor) == 0 else { throw CredentialValueStoreError.status(errno) }
    }
}

private func fixtureDirectories(root: URL) -> (state: URL, values: URL) {
    (
        root.appendingPathComponent("state", isDirectory: true),
        root.appendingPathComponent("values", isDirectory: true)
    )
}

private func prepare(root: URL, scenario: ProbeScenario) throws {
    try validatePrivateDirectory(root, requireGateRoot: true)
    let directories = fixtureDirectories(root: root)
    try createPrivateDirectory(directories.state)
    try createPrivateDirectory(directories.values)
    let state = try CredentialFileStateStore(directory: directories.state)
    let values = try FileBackedFakeCredentialValueStore(directory: directories.values)

    switch scenario {
    case .create:
        break
    case .replace:
        try values.add(account: account, value: priorValue(for: scenario))
        try state.writeMetadata(account: account, kind: "reference")
    case .adopt:
        try values.add(account: account, value: priorValue(for: scenario))
    case .remove:
        try values.add(account: account, value: priorValue(for: scenario))
        try state.writeMetadata(account: account, kind: "reference")
    case .repairAdopt, .repairReplace, .repairRemove:
        try values.add(account: account, value: priorValue(for: scenario))
        try state.writeMetadata(account: account, kind: "reference")
        let interrupted = CredentialTransactionCoordinator(
            stateStore: state,
            valueStore: values,
            checkpoint: { reached in
                if reached == .afterValueMutation {
                    throw ProbeFailure.failed("prepared original ambiguous transaction")
                }
            }
        )
        do {
            try interrupted.store(
                account: account,
                value: targetValue(for: scenario),
                kind: "api-key"
            )
            throw ProbeFailure.failed("ambiguous fixture transaction unexpectedly completed")
        } catch ProbeFailure.failed(let message) where message == "prepared original ambiguous transaction" {
            try values.replace(account: account, value: thirdValue(for: scenario))
        }
    case .unknownRecordRemove:
        try values.add(account: account, value: malformedUnknownRecord)
    }
    writeAll("PREPARED \(scenario.rawValue)\n", descriptor: STDOUT_FILENO)
}

private func mutate(
    root: URL,
    scenario: ProbeScenario,
    checkpoint selectedCheckpoint: CredentialTransactionCheckpoint
) throws {
    try validatePrivateDirectory(root, requireGateRoot: true)
    let directories = fixtureDirectories(root: root)
    let state = try CredentialFileStateStore(directory: directories.state)
    let values = try FileBackedFakeCredentialValueStore(directory: directories.values)
    let coordinator = CredentialTransactionCoordinator(
        stateStore: state,
        valueStore: values,
        checkpoint: { reached in
            guard reached == selectedCheckpoint else { return }
            writeAll("CHECKPOINT \(reached.rawValue)\n", descriptor: STDOUT_FILENO)
            while true { _ = Darwin.pause() }
        }
    )

    switch scenario {
    case .create, .replace, .adopt:
        try coordinator.store(
            account: account,
            value: targetValue(for: scenario),
            kind: "api-key"
        )
    case .remove:
        try coordinator.remove(account: account)
    case .repairAdopt:
        try coordinator.repairAdoptingCurrentValue(account: account, kind: "api-key")
    case .repairReplace:
        try coordinator.repairReplacingCurrentValue(
            account: account,
            value: repairValue(for: scenario),
            kind: "api-key"
        )
    case .repairRemove:
        try coordinator.repairRemovingCurrentValue(account: account, kind: "reference")
    case .unknownRecordRemove:
        let token = CredentialTransactionCoordinator.attentionToken(
            account: account,
            kind: "unknown",
            reason: .invalid,
            value: malformedUnknownRecord
        )
        try coordinator.repairRemovingCurrentRecord(
            account: account,
            expectedToken: token,
            validateKind: { _ in nil },
            declaredKind: { _ in nil }
        )
    }
    throw ProbeFailure.failed("mutation completed without reaching its selected checkpoint")
}

private func mutatePersistence(
    root: URL,
    scenario: ProbeScenario,
    artifact selectedArtifact: CredentialFileStateArtifact,
    checkpoint selectedCheckpoint: CredentialFileStatePersistenceCheckpoint
) throws {
    guard scenario == .replace || scenario == .unknownRecordRemove,
          scenario == .replace || selectedArtifact == .journal else {
        throw ProbeFailure.invalidArguments
    }
    try validatePrivateDirectory(root, requireGateRoot: true)
    let directories = fixtureDirectories(root: root)
    let state = try CredentialFileStateStore(
        directory: directories.state,
        persistenceCheckpoint: { artifact, checkpoint in
            guard artifact == selectedArtifact, checkpoint == selectedCheckpoint else { return }
            writeAll(
                "PERSISTENCE_CHECKPOINT \(artifact.rawValue) \(checkpoint.rawValue)\n",
                descriptor: STDOUT_FILENO
            )
            while true { _ = Darwin.pause() }
        }
    )
    let values = try FileBackedFakeCredentialValueStore(directory: directories.values)
    let coordinator = CredentialTransactionCoordinator(stateStore: state, valueStore: values)
    if scenario == .replace {
        try coordinator.store(
            account: account,
            value: targetValue(for: scenario),
            kind: "api-key"
        )
    } else {
        let token = CredentialTransactionCoordinator.attentionToken(
            account: account,
            kind: "unknown",
            reason: .invalid,
            value: malformedUnknownRecord
        )
        try coordinator.repairRemovingCurrentRecord(
            account: account,
            expectedToken: token,
            validateKind: { _ in nil },
            declaredKind: { _ in nil }
        )
    }
    throw ProbeFailure.failed("mutation completed without reaching its persistence checkpoint")
}

private func verifyKernelLockIsAvailable(stateDirectory: URL) throws {
    let lock = stateDirectory.appendingPathComponent(".credential-transactions.lock", isDirectory: false)
    let descriptor = open(lock.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw ProbeFailure.failed("credential lock could not be reopened") }
    defer { _ = close(descriptor) }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
        throw ProbeFailure.failed("kernel flock remained held after the probe was killed")
    }
    _ = flock(descriptor, LOCK_UN)
}

private func recoverAndVerify(
    root: URL,
    scenario: ProbeScenario,
    checkpoint: CredentialTransactionCheckpoint
) throws {
    try validatePrivateDirectory(root, requireGateRoot: true)
    let directories = fixtureDirectories(root: root)
    let state = try CredentialFileStateStore(directory: directories.state)
    let values = try FileBackedFakeCredentialValueStore(directory: directories.values)
    let coordinator = CredentialTransactionCoordinator(stateStore: state, valueStore: values)

    let repairNeedsAttention = checkpoint == .afterJournalPrepared
        && (scenario == .repairReplace || scenario == .repairRemove)
    let mutationCommitted = checkpoint != .afterJournalPrepared || scenario == .repairAdopt
    if repairNeedsAttention {
        do {
            try coordinator.recover(account: account)
            throw ProbeFailure.failed("pre-mutation v2 repair did not restore foreground attention")
        } catch CredentialTransactionError.ambiguousRecovery {
            guard try values.read(account: account) == thirdValue(for: scenario),
                  try state.readMetadata(account: account)?.kind == "reference" else {
                throw ProbeFailure.failed("pre-mutation v2 repair lost its exact ambiguous state")
            }
            try verifyKernelLockIsAvailable(stateDirectory: directories.state)
            writeAll(
                "RECOVERY_ATTENTION \(scenario.rawValue) \(checkpoint.rawValue) LOCK_RELEASED\n",
                descriptor: STDOUT_FILENO
            )
            return
        }
    }
    try coordinator.recover(account: account)
    try coordinator.recover(account: account)
    let expectedValue: Data?
    let expectedKind: String?
    switch (scenario, mutationCommitted) {
    case (.create, false):
        expectedValue = nil
        expectedKind = nil
    case (.replace, false), (.remove, false):
        expectedValue = priorValue(for: scenario)
        expectedKind = "reference"
    case (.adopt, false):
        expectedValue = priorValue(for: scenario)
        expectedKind = nil
    case (.create, true), (.replace, true), (.adopt, true):
        expectedValue = targetValue(for: scenario)
        expectedKind = "api-key"
    case (.remove, true):
        expectedValue = nil
        expectedKind = nil
    case (.repairAdopt, true):
        expectedValue = thirdValue(for: scenario)
        expectedKind = "api-key"
    case (.repairReplace, true):
        expectedValue = repairValue(for: scenario)
        expectedKind = "api-key"
    case (.repairRemove, true):
        expectedValue = nil
        expectedKind = nil
    case (.unknownRecordRemove, false):
        expectedValue = malformedUnknownRecord
        expectedKind = nil
    case (.unknownRecordRemove, true):
        expectedValue = nil
        expectedKind = nil
    case (.repairAdopt, false), (.repairReplace, false), (.repairRemove, false):
        throw ProbeFailure.failed("unreachable foreground attention expectation")
    }

    guard try values.read(account: account) == expectedValue else {
        throw ProbeFailure.failed("recovery did not preserve the exact prior-or-committed fake value")
    }
    guard try coordinator.metadata(account: account)?.kind == expectedKind else {
        throw ProbeFailure.failed("recovery did not preserve the exact prior-or-committed metadata")
    }
    let entries = try FileManager.default.contentsOfDirectory(
        at: directories.state,
        includingPropertiesForKeys: nil
    )
    guard entries.allSatisfy({
        !$0.lastPathComponent.hasSuffix(".transaction.json")
            && !$0.lastPathComponent.hasSuffix(".tmp")
    }) else {
        throw ProbeFailure.failed("recovery left a transaction or temporary file")
    }
    try verifyKernelLockIsAvailable(stateDirectory: directories.state)
    writeAll(
        "RECOVERED \(scenario.rawValue) \(checkpoint.rawValue) LOCK_RELEASED\n",
        descriptor: STDOUT_FILENO
    )
}

private func recoverPersistenceAndVerify(
    root: URL,
    scenario: ProbeScenario,
    artifact: CredentialFileStateArtifact,
    checkpoint: CredentialFileStatePersistenceCheckpoint
) throws {
    guard scenario == .replace || scenario == .unknownRecordRemove,
          scenario == .replace || artifact == .journal else {
        throw ProbeFailure.invalidArguments
    }
    try validatePrivateDirectory(root, requireGateRoot: true)
    let directories = fixtureDirectories(root: root)
    let state = try CredentialFileStateStore(directory: directories.state)
    let values = try FileBackedFakeCredentialValueStore(directory: directories.values)
    let coordinator = CredentialTransactionCoordinator(stateStore: state, valueStore: values)
    try coordinator.recover(account: account)
    try coordinator.recover(account: account)

    let expectedValue: Data
    let expectedKind: String?
    if scenario == .unknownRecordRemove {
        expectedValue = malformedUnknownRecord
        expectedKind = nil
    } else {
        expectedValue = artifact == .metadata
            ? targetValue(for: scenario)
            : priorValue(for: scenario)
        expectedKind = artifact == .metadata ? "api-key" : "reference"
    }
    guard try values.read(account: account) == expectedValue,
          try coordinator.metadata(account: account)?.kind == expectedKind else {
        throw ProbeFailure.failed("persistence-boundary recovery did not preserve exact state")
    }
    let entries = try FileManager.default.contentsOfDirectory(
        at: directories.state,
        includingPropertiesForKeys: nil
    )
    guard entries.allSatisfy({
        !$0.lastPathComponent.hasSuffix(".transaction.json")
            && !$0.lastPathComponent.hasSuffix(".tmp")
    }) else {
        throw ProbeFailure.failed("persistence-boundary recovery left a transaction or temporary file")
    }
    try verifyKernelLockIsAvailable(stateDirectory: directories.state)
    writeAll(
        "PERSISTENCE_RECOVERED \(artifact.rawValue) \(checkpoint.rawValue) LOCK_RELEASED\n",
        descriptor: STDOUT_FILENO
    )
}

private func run() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard arguments.count >= 3,
          let scenario = ProbeScenario(rawValue: arguments[1]) else {
        throw ProbeFailure.invalidArguments
    }
    let command = arguments[0]
    let root = URL(fileURLWithPath: arguments[2], isDirectory: true)
    switch command {
    case "prepare":
        guard arguments.count == 3 else { throw ProbeFailure.invalidArguments }
        try prepare(root: root, scenario: scenario)
    case "mutate":
        guard arguments.count == 4,
              let checkpoint = CredentialTransactionCheckpoint(rawValue: arguments[3]) else {
            throw ProbeFailure.invalidArguments
        }
        try mutate(root: root, scenario: scenario, checkpoint: checkpoint)
    case "mutate-persistence":
        guard arguments.count == 5,
              let artifact = CredentialFileStateArtifact(rawValue: arguments[3]),
              let checkpoint = CredentialFileStatePersistenceCheckpoint(rawValue: arguments[4]) else {
            throw ProbeFailure.invalidArguments
        }
        try mutatePersistence(
            root: root,
            scenario: scenario,
            artifact: artifact,
            checkpoint: checkpoint
        )
    case "recover":
        guard arguments.count == 4,
              let checkpoint = CredentialTransactionCheckpoint(rawValue: arguments[3]) else {
            throw ProbeFailure.invalidArguments
        }
        try recoverAndVerify(root: root, scenario: scenario, checkpoint: checkpoint)
    case "recover-persistence":
        guard arguments.count == 5,
              let artifact = CredentialFileStateArtifact(rawValue: arguments[3]),
              let checkpoint = CredentialFileStatePersistenceCheckpoint(rawValue: arguments[4]) else {
            throw ProbeFailure.invalidArguments
        }
        try recoverPersistenceAndVerify(
            root: root,
            scenario: scenario,
            artifact: artifact,
            checkpoint: checkpoint
        )
    default:
        throw ProbeFailure.invalidArguments
    }
}

do {
    try run()
} catch {
    writeAll("credential-crash-probe: \(error)\n", descriptor: STDERR_FILENO)
    exit(1)
}
