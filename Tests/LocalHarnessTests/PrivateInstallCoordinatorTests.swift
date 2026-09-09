import Darwin
import Foundation
import LocalHarnessAtomicInstallSwap
import Security
import Testing
@_spi(PrivateInstallCrashProbe) @testable import LocalHarnessPrivateInstallCoordinator

private let privateInstallTestNonce = String(repeating: "c", count: 64)

private enum PrivateInstallTestFailure: Error {
    case expectedFailure
    case fixtureFailure
}

private func privateInstallRequirement(_ marker: String = "") throws -> Data {
    let source = "identifier \"com.angadjairath.localharness\"\(marker)"
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess,
          let requirement else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    var bytes: CFData?
    guard SecRequirementCopyData(requirement, [], &bytes) == errSecSuccess,
          let bytes else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    return bytes as Data
}

private func privateInstallAttestation(
    version: String,
    build: Int,
    marker: Character,
    certificateMarker: Character = "a"
) throws -> PrivateStableApplicationAttestation {
    PrivateStableApplicationAttestation(
        identifier: "com.angadjairath.localharness",
        version: version,
        build: build,
        cdHashHex: String(repeating: String(marker), count: 40),
        leafCertificateSHA256Hex: String(repeating: String(certificateMarker), count: 64),
        designatedRequirement: try privateInstallRequirement()
    )
}

private func expectPrivateInstallError(
    _ expected: PrivateInstallCoordinatorError,
    operation: () throws -> Void
) {
    do {
        try operation()
        Issue.record("Expected \(expected), but the operation succeeded")
    } catch let error as PrivateInstallCoordinatorError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), received \(error)")
    }
}

private func addPrivateInstallReadACL(to url: URL) throws {
    guard let passwordEntry = getpwuid(geteuid()) else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    let userName = String(cString: passwordEntry.pointee.pw_name)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "\(userName) allow read", url.path]
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 5),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
}

private func makePrivateInstallRecordDirectory() throws -> URL {
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: directory.path
    )
    return directory
}

private func privateInstallDarwinUserCacheDirectory() throws -> URL {
    let required = confstr(_CS_DARWIN_USER_CACHE_DIR, nil, 0)
    guard required > 1, required <= 4_096 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    var bytes = [CChar](repeating: 0, count: required)
    let copied = bytes.withUnsafeMutableBufferPointer { buffer in
        confstr(_CS_DARWIN_USER_CACHE_DIR, buffer.baseAddress, required)
    }
    guard copied == required else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    let path = String(cString: bytes)
    guard let canonical = Darwin.realpath(path, nil) else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    defer { Darwin.free(canonical) }
    return URL(
        fileURLWithPath: String(cString: canonical),
        isDirectory: true
    )
}

private func privateInstallCrashProbeURL() throws -> URL {
    var candidates: [URL] = []
    if let isolation = ProcessInfo.processInfo.environment[
        "LOCAL_HARNESS_SWIFT_TEST_ISOLATION_ROOT"
    ], isolation.hasPrefix("/tmp/fulmar-swift-tests.")
        || isolation.hasPrefix("/tmp/FulmarInstallerIntegration.") {
        let root = URL(fileURLWithPath: isolation, isDirectory: true)
        candidates.append(
            root.appendingPathComponent(
                "build/arm64-apple-macosx/debug/PrivateInstallCrashProbe"
            )
        )
        candidates.append(root.appendingPathComponent("build/debug/PrivateInstallCrashProbe"))
    }
    for bundle in Bundle.allBundles where bundle.bundleURL.pathExtension == "xctest" {
        candidates.append(
            bundle.bundleURL.deletingLastPathComponent()
                .appendingPathComponent("PrivateInstallCrashProbe")
        )
    }
    let bundleParent = Bundle.main.bundleURL.deletingLastPathComponent()
    candidates.append(bundleParent.appendingPathComponent("PrivateInstallCrashProbe"))
    var cursor = URL(fileURLWithPath: CommandLine.arguments[0], isDirectory: false)
        .deletingLastPathComponent()
    for _ in 0..<8 {
        candidates.append(cursor.appendingPathComponent("PrivateInstallCrashProbe"))
        cursor.deleteLastPathComponent()
    }
    let project = URL(fileURLWithPath: #filePath, isDirectory: false)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    candidates.append(
        project.appendingPathComponent(".build/arm64-apple-macosx/debug/PrivateInstallCrashProbe")
    )
    candidates.append(project.appendingPathComponent(".build/debug/PrivateInstallCrashProbe"))
    for candidate in candidates {
        var metadata = stat()
        if lstat(candidate.path, &metadata) == 0,
           metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
           metadata.st_uid == geteuid(),
           metadata.st_mode & 0o022 == 0,
           metadata.st_mode & 0o111 != 0,
           metadata.st_nlink == 1 {
            return candidate
        }
    }
    throw PrivateInstallTestFailure.fixtureFailure
}

private func privateInstallCrashProbeRoot() throws -> URL {
    let suffix = (UUID().uuidString + UUID().uuidString)
        .replacingOccurrences(of: "-", with: "")
        .lowercased()
    guard suffix.utf8.count == 64 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("FulmarPrivateInstallCrashProbe.\(suffix)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return root
}

private final class PrivateInstallPhysicalBackend {
    let root: URL
    let installed: URL
    let candidate: URL
    let stage: URL
    let originalAttestation: PrivateStableApplicationAttestation
    var candidateAttestation: PrivateStableApplicationAttestation
    var running = false
    var mutateCandidateAfterStage = false
    var mutateStageAfterCopy = false
    var failBeforeFirstSwap = false
    var throwAfterFirstSwap = false
    var failOnSwapNumber: Int?
    var postBoundaryFails = false
    var receiptFails = false
    var swapCount = 0
    var stoppedProofCount = 0
    var persistedJournal: PrivateInstallRecoveryJournal?
    var persistedReceipt: PrivateInstallCoordinatorReceipt?
    var journalSink: ((PrivateInstallRecoveryJournal) throws -> Void)?
    var receiptSink: ((PrivateInstallCoordinatorReceipt) throws -> Void)?
    var postBoundarySink: (() throws -> Void)?

    init() throws {
        root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent(
                "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
                isDirectory: true
            )
        installed = root.appendingPathComponent("Fulmar.app", isDirectory: true)
        candidate = root.appendingPathComponent("FrozenCandidate.app", isDirectory: true)
        stage = root.appendingPathComponent(
            try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce),
            isDirectory: true
        )
        originalAttestation = try privateInstallAttestation(
            version: "1.0.0",
            build: 100,
            marker: "1"
        )
        candidateAttestation = try privateInstallAttestation(
            version: "1.1.0",
            build: 110,
            marker: "2"
        )
        try originalAttestation.validateShape()
        try candidateAttestation.validateShape()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        try makeBundle(at: installed, payload: "old")
        try makeBundle(at: candidate, payload: "new")
    }

    deinit {
        try? FileManager.default.removeItem(at: root)
    }

    func hooks() -> PrivateInstallCoordinatorHooks {
        PrivateInstallCoordinatorHooks(
            proveApplicationsStopped: { [self] in
                stoppedProofCount += 1
                if running { throw PrivateInstallCoordinatorError.applicationRunning }
            },
            inspectInstalled: { [self] in try inspect(installed) },
            inspectCandidate: { [self] in try inspect(candidate) },
            stageCandidate: { [self] in
                if FileManager.default.fileExists(atPath: stage.path) {
                    throw PrivateInstallCoordinatorError.stageAlreadyExists
                }
                try FileManager.default.copyItem(at: candidate, to: stage)
                if mutateStageAfterCopy {
                    try Data("changed stage".utf8).write(
                        to: stage.appendingPathComponent("nested/payload.txt")
                    )
                }
                if mutateCandidateAfterStage {
                    try Data("changed candidate".utf8).write(
                        to: candidate.appendingPathComponent("nested/payload.txt")
                    )
                }
            },
            inspectStage: { [self] in try inspect(stage) },
            invokeAtomicSwap: { [self] _, _, _ in
                let nextSwap = swapCount + 1
                if failBeforeFirstSwap, nextSwap == 1 {
                    throw PrivateInstallTestFailure.expectedFailure
                }
                if failOnSwapNumber == nextSwap {
                    throw PrivateInstallTestFailure.expectedFailure
                }
                try exchangeInstalledAndStage()
                swapCount = nextSwap
                if throwAfterFirstSwap, nextSwap == 1 {
                    throw PrivateInstallTestFailure.expectedFailure
                }
            },
            postInstallBoundary: { [self] in
                if postBoundaryFails {
                    throw PrivateInstallCoordinatorError.postInstallProofFailed
                }
                try postBoundarySink?()
            },
            persistJournal: { [self] journal in
                try journalSink?(journal)
                persistedJournal = journal
            },
            persistReceipt: { [self] receipt in
                if receiptFails { throw PrivateInstallCoordinatorError.receiptFailed }
                try receiptSink?(receipt)
                persistedReceipt = receipt
            },
            nowUnixSeconds: { 1_788_221_234 }
        )
    }

    func payload(at bundle: URL) throws -> String {
        try String(
            contentsOf: bundle.appendingPathComponent("nested/payload.txt"),
            encoding: .utf8
        )
    }

    private func makeBundle(at url: URL, payload: String) throws {
        let nested = url.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data(payload.utf8).write(to: nested.appendingPathComponent("payload.txt"))
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: nested.path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: nested.appendingPathComponent("payload.txt").path
        )
    }

    func inspect(_ url: URL) throws -> PrivateInstallBundleProof {
        let payload = try payload(at: url)
        let attestation: PrivateStableApplicationAttestation
        switch payload {
        case "old":
            attestation = originalAttestation
        case "new":
            attestation = candidateAttestation
        default:
            attestation = candidateAttestation
        }
        return PrivateInstallBundleProof(
            identity: try PrivateInstallCoordinator.identityForTesting(at: url),
            treeSHA256Hex: try PrivateInstallCoordinator.treeSHA256ForTesting(at: url),
            attestation: attestation
        )
    }

    private func exchangeInstalledAndStage() throws {
        let descriptor = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw PrivateInstallTestFailure.fixtureFailure }
        defer { _ = Darwin.close(descriptor) }
        let result = installed.lastPathComponent.withCString { currentPointer in
            stage.lastPathComponent.withCString { stagePointer in
                renameatx_np(
                    descriptor,
                    currentPointer,
                    descriptor,
                    stagePointer,
                    UInt32(RENAME_SWAP)
                )
            }
        }
        guard result == 0 else { throw PrivateInstallTestFailure.fixtureFailure }
    }
}

private func privateRollbackInspectionHooks(
    backend: PrivateInstallPhysicalBackend,
    receipt: PrivateInstallCoordinatorReceipt?,
    stageLeaves: @escaping () throws -> [String] = {
        [try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce)]
    },
    installed: (() throws -> PrivateInstallBundleProof)? = nil,
    stage: (() throws -> PrivateInstallBundleProof)? = nil,
    candidate: (() throws -> PrivateInstallBundleProof?)? = nil,
    loadReceipt: (() throws -> PrivateInstallCoordinatorReceipt?)? = nil
) -> PrivateRollbackInspectionHooks {
    PrivateRollbackInspectionHooks(
        loadReceipt: loadReceipt ?? { receipt },
        stageLeaves: stageLeaves,
        inspectInstalled: installed ?? { try backend.inspect(backend.installed) },
        inspectStage: { _ in
            try stage?() ?? backend.inspect(backend.stage)
        },
        inspectCandidateIfPresent: candidate ?? { try backend.inspect(backend.candidate) }
    )
}

private func privateInstallRecoveryHooks(
    backend: PrivateInstallPhysicalBackend,
    journal: PrivateInstallRecoveryJournal?,
    receipt: PrivateInstallCoordinatorReceipt?,
    lifecycleJournal: PrivateInstallLifecycleJournal? = nil,
    stageLeaves: @escaping () throws -> [String] = {
        [try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce)]
    },
    archiveLeaves: @escaping () throws -> [String] = { [] },
    installed: (() throws -> PrivateInstallBundleProof)? = nil,
    stage: (() throws -> PrivateInstallBundleProof)? = nil,
    archive: (() throws -> PrivateInstallBundleProof)? = nil,
    candidate: (() throws -> PrivateInstallBundleProof?)? = nil,
    loadJournal: (() throws -> PrivateInstallRecoveryJournal?)? = nil,
    loadReceipt: (() throws -> PrivateInstallCoordinatorReceipt?)? = nil,
    loadLifecycleJournal: (() throws -> PrivateInstallLifecycleJournal?)? = nil,
    persistReceipt: ((PrivateInstallCoordinatorReceipt) throws -> Void)? = nil,
    persistLifecycleJournal: ((PrivateInstallLifecycleJournal) throws -> Void)? = nil,
    proveApplicationsStopped: (() throws -> Void)? = nil,
    invokeAtomicSwap: ((
        AtomicInstallIdentity,
        AtomicInstallIdentity,
        PrivateStableApplicationAttestation
    ) throws -> Void)? = nil,
    archiveStage: ((String, String, PrivateInstallBundleProof) throws -> Void)? = nil,
    proveArchiveDurable: ((String, PrivateInstallBundleProof) throws -> Void)? = nil,
    archiveRecordDirectory: ((PrivateInstallLifecycleJournal) throws -> Void)? = nil
) -> PrivateInstallRecoveryHooks {
    PrivateInstallRecoveryHooks(
        loadJournal: loadJournal ?? { journal },
        loadReceipt: loadReceipt ?? { receipt },
        loadLifecycleJournal: loadLifecycleJournal ?? { lifecycleJournal },
        stageLeaves: stageLeaves,
        archiveLeaves: archiveLeaves,
        inspectInstalled: installed ?? { try backend.inspect(backend.installed) },
        inspectStage: { _ in
            try stage?() ?? backend.inspect(backend.stage)
        },
        inspectArchive: { _ in
            guard let archive else {
                throw PrivateInstallCoordinatorError.rollbackInspectionFailed
            }
            return try archive()
        },
        inspectCandidateIfPresent: candidate ?? { try backend.inspect(backend.candidate) },
        proveApplicationsStopped: proveApplicationsStopped ?? {},
        invokeAtomicSwap: invokeAtomicSwap ?? { _, _, _ in
            throw PrivateInstallCoordinatorError.helperUnavailable
        },
        persistReceipt: persistReceipt ?? { _ in },
        persistLifecycleJournal: persistLifecycleJournal ?? { _ in
            throw PrivateInstallCoordinatorError.lifecycleFailed
        },
        archiveStage: archiveStage ?? { _, _, _ in
            throw PrivateInstallCoordinatorError.lifecycleFailed
        },
        proveArchiveDurable: proveArchiveDurable ?? { _, _ in
            throw PrivateInstallCoordinatorError.lifecycleFailed
        },
        archiveRecordDirectory: archiveRecordDirectory ?? { _ in
            throw PrivateInstallCoordinatorError.lifecycleFailed
        },
        nowUnixSeconds: { 1_788_221_235 }
    )
}

private final class PrivateInstallLifecycleBackend {
    let backend: PrivateInstallPhysicalBackend
    let journal: PrivateInstallRecoveryJournal
    let receipt: PrivateInstallCoordinatorReceipt?
    let operation: PrivateInstallLifecycleOperation
    var lifecycleJournal: PrivateInstallLifecycleJournal?
    var recordsPresent = true
    var stagePresent = true
    var archivePresent = false
    var candidatePresent = true
    var failLifecycleAfterWrite = false
    var failArchiveAfterRename = false
    var failRecordArchiveAfterRename = false
    var stoppedProofs = 0
    var archiveRenames = 0
    var recordArchiveRenames = 0
    var durableArchiveProofs = 0

    init(
        backend: PrivateInstallPhysicalBackend,
        journal: PrivateInstallRecoveryJournal,
        receipt: PrivateInstallCoordinatorReceipt?,
        operation: PrivateInstallLifecycleOperation
    ) {
        self.backend = backend
        self.journal = journal
        self.receipt = receipt
        self.operation = operation
    }

    var archiveLeaf: String {
        let disposition = operation == .cancelOriginalActive ? "cancelled" : "retired"
        return ".Fulmar.private-\(disposition).\(privateInstallTestNonce).app"
    }

    func hooks() -> PrivateInstallRecoveryHooks {
        PrivateInstallRecoveryHooks(
            loadJournal: { [self] in recordsPresent ? journal : nil },
            loadReceipt: { [self] in recordsPresent ? receipt : nil },
            loadLifecycleJournal: { [self] in
                recordsPresent ? lifecycleJournal : nil
            },
            stageLeaves: { [self] in
                guard stagePresent else { return [] }
                return [try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce)]
            },
            archiveLeaves: { [self] in archivePresent ? [archiveLeaf] : [] },
            inspectInstalled: { [self] in try backend.inspect(backend.installed) },
            inspectStage: { [self] _ in
                guard stagePresent else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                return try backend.inspect(backend.stage)
            },
            inspectArchive: { [self] leaf in
                guard archivePresent, leaf == archiveLeaf else {
                    throw PrivateInstallCoordinatorError.rollbackInspectionFailed
                }
                return try backend.inspect(backend.stage)
            },
            inspectCandidateIfPresent: { [self] in
                candidatePresent ? try backend.inspect(backend.candidate) : nil
            },
            proveApplicationsStopped: { [self] in stoppedProofs += 1 },
            invokeAtomicSwap: { _, _, _ in
                throw PrivateInstallCoordinatorError.helperUnavailable
            },
            persistReceipt: { _ in
                throw PrivateInstallCoordinatorError.receiptFailed
            },
            persistLifecycleJournal: { [self] lifecycle in
                guard lifecycleJournal == nil else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                lifecycleJournal = lifecycle
                if failLifecycleAfterWrite {
                    throw PrivateInstallTestFailure.expectedFailure
                }
            },
            archiveStage: { [self] stageLeaf, requestedArchiveLeaf, expected in
                let expectedStageLeaf = try AtomicInstallSwap.stageLeaf(
                    nonce: privateInstallTestNonce
                )
                guard stageLeaf == expectedStageLeaf,
                requestedArchiveLeaf == archiveLeaf,
                expected == lifecycleJournal?.retainedStage,
                stagePresent,
                !archivePresent else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                stagePresent = false
                archivePresent = true
                archiveRenames += 1
                if failArchiveAfterRename {
                    throw PrivateInstallTestFailure.expectedFailure
                }
            },
            proveArchiveDurable: { [self] leaf, expected in
                guard archivePresent,
                      leaf == archiveLeaf,
                      expected == lifecycleJournal?.retainedStage else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                durableArchiveProofs += 1
            },
            archiveRecordDirectory: { [self] lifecycle in
                guard recordsPresent,
                      lifecycle == lifecycleJournal,
                      archivePresent,
                      !stagePresent else {
                    throw PrivateInstallCoordinatorError.lifecycleFailed
                }
                recordsPresent = false
                recordArchiveRenames += 1
                if failRecordArchiveAfterRename {
                    throw PrivateInstallTestFailure.expectedFailure
                }
            },
            nowUnixSeconds: { 1_788_221_236 }
        )
    }
}

@Test func privateInstallCoordinatorCommitsAndRetainsExactRollbackBundle() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )

    #expect(backend.swapCount == 1)
    #expect(backend.stoppedProofCount == 4)
    #expect(try backend.payload(at: backend.installed) == "new")
    #expect(try backend.payload(at: backend.stage) == "old")
    let journal = try #require(backend.persistedJournal)
    #expect(journal.phase == .preparedForAtomicSwap)
    #expect(journal.nonce == privateInstallTestNonce)
    #expect(journal.originalInstalled == receipt.retainedRollback)
    #expect(journal.stagedCandidate == receipt.installed)
    #expect(receipt == backend.persistedReceipt)
    #expect(receipt.nonce == privateInstallTestNonce)
    #expect(receipt.committedAtUnixSeconds == 1_788_221_234)
    #expect(receipt.installed.identity != receipt.retainedRollback.identity)
}

@Test func privateRollbackInspectorProvesReceiptInstalledRollbackAndCandidateTwice() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    var receiptReads = 0
    var stageEnumerations = 0
    var installedReads = 0
    var rollbackReads = 0
    var candidateReads = 0
    let hooks = privateRollbackInspectionHooks(
        backend: backend,
        receipt: receipt,
        stageLeaves: {
            stageEnumerations += 1
            return [try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce)]
        },
        installed: {
            installedReads += 1
            return try backend.inspect(backend.installed)
        },
        stage: {
            rollbackReads += 1
            return try backend.inspect(backend.stage)
        },
        candidate: {
            candidateReads += 1
            return try backend.inspect(backend.candidate)
        },
        loadReceipt: {
            receiptReads += 1
            return receipt
        }
    )
    let inspected = try PrivateInstallCoordinator.inspectRollback(hooks: hooks)
    let result = try #require(inspected)

    #expect(result.receipt == receipt)
    #expect(result.stagePath == "/Applications/.Fulmar.install-stage.\(privateInstallTestNonce).app")
    #expect(result.candidateState == .exact)
    #expect(receiptReads == 2)
    #expect(stageEnumerations == 2)
    #expect(installedReads == 2)
    #expect(rollbackReads == 2)
    #expect(candidateReads == 2)
}

@Test func privateRollbackInspectorAllowsAbsentFrozenCandidateButStillRepeatsProofs() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    var candidateReads = 0
    let hooks = privateRollbackInspectionHooks(
        backend: backend,
        receipt: receipt,
        candidate: {
            candidateReads += 1
            return nil
        }
    )
    let inspected = try PrivateInstallCoordinator.inspectRollback(hooks: hooks)
    let result = try #require(inspected)
    #expect(result.candidateState == .absent)
    #expect(candidateReads == 2)
}

@Test func privateRollbackInspectorAcceptsOnlyAStableEmptyReceiptAndStageState() throws {
    let backend = try PrivateInstallPhysicalBackend()
    var receiptReads = 0
    var stageReads = 0
    let empty = privateRollbackInspectionHooks(
        backend: backend,
        receipt: nil,
        stageLeaves: {
            stageReads += 1
            return []
        },
        loadReceipt: {
            receiptReads += 1
            return nil
        }
    )
    #expect(try PrivateInstallCoordinator.inspectRollback(hooks: empty) == nil)
    #expect(receiptReads == 2)
    #expect(stageReads == 2)

    let orphanedStage = privateRollbackInspectionHooks(
        backend: backend,
        receipt: nil
    )
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRollback(hooks: orphanedStage)
    }
}

@Test func privateRollbackInspectorRejectsEveryProofMismatch() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let wrongInstalled = PrivateInstallBundleProof(
        identity: receipt.installed.identity,
        treeSHA256Hex: String(repeating: "e", count: 64),
        attestation: receipt.installed.attestation
    )
    let wrongRollback = PrivateInstallBundleProof(
        identity: receipt.retainedRollback.identity,
        treeSHA256Hex: String(repeating: "d", count: 64),
        attestation: receipt.retainedRollback.attestation
    )
    for hooks in [
        privateRollbackInspectionHooks(
            backend: backend,
            receipt: receipt,
            installed: { wrongInstalled }
        ),
        privateRollbackInspectionHooks(
            backend: backend,
            receipt: receipt,
            stage: { wrongRollback }
        ),
        privateRollbackInspectionHooks(
            backend: backend,
            receipt: receipt,
            candidate: { wrongInstalled }
        ),
        privateRollbackInspectionHooks(
            backend: backend,
            receipt: receipt,
            stageLeaves: { [".Fulmar.install-stage.not-the-receipt.app"] }
        )
    ] {
        expectPrivateInstallError(.rollbackInspectionFailed) {
            _ = try PrivateInstallCoordinator.inspectRollback(hooks: hooks)
        }
    }
}

@Test func privateRollbackInspectorRejectsChangesDuringRepeatedProof() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let changedReceipt = PrivateInstallCoordinatorReceipt(
        nonce: receipt.nonce,
        committedAtUnixSeconds: receipt.committedAtUnixSeconds + 1,
        installed: receipt.installed,
        retainedRollback: receipt.retainedRollback
    )
    var receiptRead = 0
    let rewrittenReceipt = privateRollbackInspectionHooks(
        backend: backend,
        receipt: receipt,
        loadReceipt: {
            receiptRead += 1
            return receiptRead == 1 ? receipt : changedReceipt
        }
    )
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRollback(hooks: rewrittenReceipt)
    }

    var stageRead = 0
    let renamedStage = privateRollbackInspectionHooks(
        backend: backend,
        receipt: receipt,
        stageLeaves: {
            stageRead += 1
            return stageRead == 1
                ? [try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce)]
                : []
        }
    )
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRollback(hooks: renamedStage)
    }
}

@Test func privateRollbackReceiptReaderRejectsNoncanonicalLinksExtrasAndOversize() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let receiptDirectory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(at: receiptDirectory, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: receiptDirectory.path)
    defer { try? FileManager.default.removeItem(at: receiptDirectory) }
    let receiptURL = receiptDirectory.appendingPathComponent("latest-private-install.json")
    try PrivateInstallCoordinator.persistReceiptForTesting(receipt, in: receiptDirectory)
    #expect(try PrivateInstallCoordinator.readReceiptForTesting(in: receiptDirectory) == receipt)

    let extra = receiptDirectory.appendingPathComponent("unexpected")
    try Data().write(to: extra)
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.readReceiptForTesting(in: receiptDirectory)
    }
    try FileManager.default.removeItem(at: extra)

    let hardLink = receiptDirectory.deletingLastPathComponent()
        .appendingPathComponent("FulmarPrivateInstallCoordinatorTests.link.\(UUID().uuidString)")
    guard link(receiptURL.path, hardLink.path) == 0 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.readReceiptForTesting(in: receiptDirectory)
    }
    try FileManager.default.removeItem(at: hardLink)

    try FileManager.default.removeItem(at: receiptURL)
    guard symlink("missing-receipt", receiptURL.path) == 0 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.readReceiptForTesting(in: receiptDirectory)
    }
    try FileManager.default.removeItem(at: receiptURL)

    try Data(repeating: 0x20, count: 24_577).write(to: receiptURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.readReceiptForTesting(in: receiptDirectory)
    }
}

@Test func privateInstallJournalIsExclusiveOwnerPrivateDurableAndReceiptCompatible() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let journal = try #require(backend.persistedJournal)
    let directory = try makePrivateInstallRecordDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }

    try PrivateInstallCoordinator.persistJournalForTesting(journal, in: directory)
    #expect(try PrivateInstallCoordinator.readJournalForTesting(in: directory) == journal)
    #expect(try PrivateInstallCoordinator.readReceiptForTesting(in: directory) == nil)
    let journalURL = directory.appendingPathComponent("pending-private-install.json")
    var journalMetadata = stat()
    #expect(lstat(journalURL.path, &journalMetadata) == 0)
    #expect(journalMetadata.st_mode & 0o7777 == 0o600)
    #expect(journalMetadata.st_uid == geteuid())
    #expect(journalMetadata.st_nlink == 1)
    #expect(journalMetadata.st_size > 0 && journalMetadata.st_size <= 49_152)

    try PrivateInstallCoordinator.persistReceiptForTesting(receipt, in: directory)
    #expect(try PrivateInstallCoordinator.readJournalForTesting(in: directory) == journal)
    #expect(try PrivateInstallCoordinator.readReceiptForTesting(in: directory) == receipt)
    #expect(Set(try FileManager.default.contentsOfDirectory(atPath: directory.path)) == [
        "pending-private-install.json",
        "latest-private-install.json"
    ])
    expectPrivateInstallError(.journalFailed) {
        try PrivateInstallCoordinator.persistJournalForTesting(journal, in: directory)
    }
    expectPrivateInstallError(.receiptFailed) {
        try PrivateInstallCoordinator.persistReceiptForTesting(receipt, in: directory)
    }
}

@Test func privateInstallJournalReaderRejectsMalformedLinksModesExtrasAndABA() throws {
    let backend = try PrivateInstallPhysicalBackend()
    _ = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let journal = try #require(backend.persistedJournal)

    do {
        let directory = try makePrivateInstallRecordDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try PrivateInstallCoordinator.persistJournalForTesting(journal, in: directory)
        let journalURL = directory.appendingPathComponent("pending-private-install.json")
        let hardLink = directory.deletingLastPathComponent()
            .appendingPathComponent("FulmarPrivateInstallCoordinatorTests.link.\(UUID().uuidString)")
        guard link(journalURL.path, hardLink.path) == 0 else {
            throw PrivateInstallTestFailure.fixtureFailure
        }
        defer { try? FileManager.default.removeItem(at: hardLink) }
        expectPrivateInstallError(.rollbackInspectionFailed) {
            _ = try PrivateInstallCoordinator.readJournalForTesting(in: directory)
        }
    }

    for fixture in ["symlink", "mode", "malformed", "extra"] {
        let directory = try makePrivateInstallRecordDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let journalURL = directory.appendingPathComponent("pending-private-install.json")
        switch fixture {
        case "symlink":
            guard symlink("missing-journal", journalURL.path) == 0 else {
                throw PrivateInstallTestFailure.fixtureFailure
            }
        case "mode":
            try Data("{}".utf8).write(to: journalURL)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: journalURL.path
            )
        case "malformed":
            try Data("{\"schemaVersion\":1}".utf8).write(to: journalURL)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: journalURL.path
            )
        default:
            try PrivateInstallCoordinator.persistJournalForTesting(journal, in: directory)
            try Data().write(to: directory.appendingPathComponent("unexpected"))
        }
        expectPrivateInstallError(.rollbackInspectionFailed) {
            _ = try PrivateInstallCoordinator.readJournalForTesting(in: directory)
        }
    }

    let swapped = try PrivateInstallPhysicalBackend()
    _ = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: swapped.hooks()
    )
    let stableJournal = try #require(swapped.persistedJournal)
    var journalReads = 0
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRecovery(
            hooks: privateInstallRecoveryHooks(
                backend: swapped,
                journal: stableJournal,
                receipt: nil,
                loadJournal: {
                    journalReads += 1
                    if journalReads == 1 { return stableJournal }
                    return PrivateInstallRecoveryJournal(
                        nonce: stableJournal.nonce,
                        preparedAtUnixSeconds: stableJournal.preparedAtUnixSeconds + 1,
                        originalInstalled: stableJournal.originalInstalled,
                        frozenCandidate: stableJournal.frozenCandidate,
                        stagedCandidate: stableJournal.stagedCandidate
                    )
                }
            )
        )
    }
}

@Test func privateInstallInterruptedRecordArchiverRejectsLinksModesHardlinksDuplicatesAndExtras() throws {
    let fixtures = ["symlink", "mode", "hardlink", "duplicate", "extra", "malformed"]
    for fixture in fixtures {
        let root = try privateInstallCrashProbeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let records = root.appendingPathComponent("records", isDirectory: true)
        try FileManager.default.createDirectory(at: records, withIntermediateDirectories: false)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: records.path
        )
        let journalLeaf = ".pending-private-install.\(privateInstallTestNonce).tmp"
        let journalURL = records.appendingPathComponent(journalLeaf)
        switch fixture {
        case "symlink":
            guard symlink("missing", journalURL.path) == 0 else {
                throw PrivateInstallTestFailure.fixtureFailure
            }
        case "mode":
            try Data("partial".utf8).write(to: journalURL)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: journalURL.path
            )
        case "hardlink":
            let source = root.appendingPathComponent("source")
            try Data("partial".utf8).write(to: source)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: source.path
            )
            guard link(source.path, journalURL.path) == 0 else {
                throw PrivateInstallTestFailure.fixtureFailure
            }
        case "duplicate":
            try Data("partial".utf8).write(to: journalURL)
            let receiptURL = records.appendingPathComponent(
                ".latest-private-install.\(privateInstallTestNonce).tmp"
            )
            try Data("partial".utf8).write(to: receiptURL)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: receiptURL.path
            )
        case "extra":
            try Data("partial".utf8).write(to: journalURL)
            try Data().write(to: records.appendingPathComponent("unexpected"))
        default:
            try Data("partial".utf8).write(
                to: records.appendingPathComponent(".pending-private-install.bad.tmp")
            )
        }
        if fixture != "symlink" && fixture != "mode" && fixture != "hardlink" {
            if FileManager.default.fileExists(atPath: journalURL.path) {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: journalURL.path
                )
            }
        }
        expectPrivateInstallError(.interruptedRecordWrite) {
            _ = try PrivateInstallCoordinator.archiveInterruptedRecordWriteForTesting(
                in: records
            )
        }
        #expect(FileManager.default.fileExists(atPath: records.path))
    }
}

@Test func privateInstallInterruptedRecordMetadataPolicyRejectsWrongOwnerAndUnsafeShape() {
    let expectedOwner = geteuid()
    let wrongOwner = expectedOwner == uid_t.max ? expectedOwner - 1 : expectedOwner + 1
    let regularPrivate = mode_t(S_IFREG) | 0o600
    #expect(
        PrivateInstallCoordinator.interruptedRecordMetadataIsSafeForTesting(
            mode: regularPrivate,
            owner: expectedOwner,
            expectedOwner: expectedOwner,
            linkCount: 1,
            size: 0,
            maximumBytes: 49_152
        )
    )
    #expect(
        !PrivateInstallCoordinator.interruptedRecordMetadataIsSafeForTesting(
            mode: regularPrivate,
            owner: wrongOwner,
            expectedOwner: expectedOwner,
            linkCount: 1,
            size: 0,
            maximumBytes: 49_152
        )
    )
    #expect(
        !PrivateInstallCoordinator.interruptedRecordMetadataIsSafeForTesting(
            mode: mode_t(S_IFLNK) | 0o600,
            owner: expectedOwner,
            expectedOwner: expectedOwner,
            linkCount: 1,
            size: 0,
            maximumBytes: 49_152
        )
    )
    #expect(
        !PrivateInstallCoordinator.interruptedRecordMetadataIsSafeForTesting(
            mode: regularPrivate,
            owner: expectedOwner,
            expectedOwner: expectedOwner,
            linkCount: 2,
            size: 0,
            maximumBytes: 49_152
        )
    )
}

@Test func privateInstallPreparationOrdinaryENOSPCPreservesReconcilableTempBeforeStaging() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let preparation = PrivateInstallPreparationJournal(
        nonce: privateInstallTestNonce,
        stageLeaf: try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce),
        preparedAtUnixSeconds: 1_788_221_241,
        originalInstalled: try backend.inspect(backend.installed),
        frozenCandidate: try backend.inspect(backend.candidate)
    )
    let root = try privateInstallCrashProbeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let records = root.appendingPathComponent("records", isDirectory: true)
    try FileManager.default.createDirectory(at: records, withIntermediateDirectories: false)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: records.path
    )
    expectPrivateInstallError(.journalFailed) {
        try PrivateInstallCoordinator.persistPreparationForTesting(
            preparation,
            in: records,
            boundaryHook: { boundary in
                if boundary == .afterTemporaryCreate {
                    throw POSIXError(.ENOSPC)
                }
            }
        )
    }
    #expect(
        try PrivateInstallCoordinator.hasInterruptedRecordWriteForTesting(in: records)
    )
    #expect(!FileManager.default.fileExists(atPath: backend.stage.path))
}

@Test func privateInstallAbandonmentOrdinaryEIOPreservesExactReconcilableEvidence() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let preparation = PrivateInstallPreparationJournal(
        nonce: privateInstallTestNonce,
        stageLeaf: try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce),
        preparedAtUnixSeconds: 1_788_221_241,
        originalInstalled: try backend.inspect(backend.installed),
        frozenCandidate: try backend.inspect(backend.candidate)
    )
    let abandonment = PrivateInstallAbandonmentJournal(
        nonce: privateInstallTestNonce,
        preparedAtUnixSeconds: 1_788_221_242,
        preparation: preparation,
        activeInstalled: preparation.originalInstalled,
        opaqueStage: nil
    )
    let root = try privateInstallCrashProbeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let records = root.appendingPathComponent("records", isDirectory: true)
    try FileManager.default.createDirectory(at: records, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: records.path)
    try PrivateInstallCoordinator.persistPreparationForTesting(preparation, in: records)
    expectPrivateInstallError(.lifecycleFailed) {
        try PrivateInstallCoordinator.persistAbandonmentForTesting(
            abandonment,
            in: records,
            boundaryHook: { boundary in
                if boundary == .afterPartialFileSync { throw POSIXError(.EIO) }
            }
        )
    }
    #expect(try PrivateInstallCoordinator.hasInterruptedRecordWriteForTesting(in: records))
    #expect(try PrivateInstallCoordinator.readPreparationForTesting(in: records) == preparation)
    #expect(try PrivateInstallCoordinator.readAbandonmentForTesting(in: records) == nil)
    #expect(!FileManager.default.fileExists(atPath: backend.stage.path))
}

@Test func privateInstallOpaqueStageInspectionRejectsLinksAndUnsafeModesWithoutTraversal() throws {
    let root = try makePrivateInstallRecordDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let stage = root.appendingPathComponent("opaque.app", isDirectory: true)
    try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stage.path)
    #expect(try PrivateInstallCoordinator.opaqueStageIdentityForTesting(at: stage) != nil)

    try FileManager.default.setAttributes([.posixPermissions: 0o722], ofItemAtPath: stage.path)
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.opaqueStageIdentityForTesting(at: stage)
    }
    try FileManager.default.removeItem(at: stage)
    try FileManager.default.createSymbolicLink(at: stage, withDestinationURL: root)
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.opaqueStageIdentityForTesting(at: stage)
    }
}

@Test func privateInstallInterruptedRecordReconciliationArchivesStaleEvidenceReadOnlyFirst() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    let journal = try #require(backend.persistedJournal)
    let root = try privateInstallCrashProbeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let records = root.appendingPathComponent("records", isDirectory: true)
    try FileManager.default.createDirectory(at: records, withIntermediateDirectories: false)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: records.path
    )
    try PrivateInstallCoordinator.persistJournalForTesting(journal, in: records)
    let temporaryLeaf = ".pending-private-install.\(privateInstallTestNonce).tmp"
    let temporary = records.appendingPathComponent(temporaryLeaf)
    let staleBytes = Data("stale-but-preserved".utf8)
    try staleBytes.write(to: temporary)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: temporary.path
    )
    let leavesBeforeReadOnlyCheck = try FileManager.default.contentsOfDirectory(
        atPath: records.path
    ).sorted()
    #expect(try PrivateInstallCoordinator.hasInterruptedRecordWriteForTesting(in: records))
    #expect(
        try FileManager.default.contentsOfDirectory(atPath: records.path).sorted()
            == leavesBeforeReadOnlyCheck
    )

    let hooks = privateInstallRecoveryHooks(
        backend: backend,
        journal: journal,
        receipt: nil,
        loadJournal: {
            try PrivateInstallCoordinator.readJournalForTesting(in: records)
        },
        loadReceipt: {
            try PrivateInstallCoordinator.readReceiptForTesting(in: records)
        },
        loadLifecycleJournal: {
            try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: records)
        }
    )
    try PrivateInstallCoordinator.reconcileInterruptedRecordWrite(
        in: records,
        hooks: hooks
    )
    let archive = root.appendingPathComponent(
        ".Fulmar.private-install-interrupted-record.journal.\(privateInstallTestNonce)"
    )
    #expect(!FileManager.default.fileExists(atPath: temporary.path))
    #expect(try Data(contentsOf: archive) == staleBytes)
    #expect(try PrivateInstallCoordinator.readJournalForTesting(in: records) == journal)
    try PrivateInstallCoordinator.reconcileInterruptedRecordWrite(
        in: records,
        hooks: hooks
    )
    #expect(try Data(contentsOf: archive) == staleBytes)
}

@Test func privateInstallInterruptedRecordArchiveCollisionPreservesBothFiles() throws {
    let root = try privateInstallCrashProbeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let records = root.appendingPathComponent("records", isDirectory: true)
    try FileManager.default.createDirectory(at: records, withIntermediateDirectories: false)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: records.path
    )
    let temporary = records.appendingPathComponent(
        ".pending-private-install.\(privateInstallTestNonce).tmp"
    )
    let archive = root.appendingPathComponent(
        ".Fulmar.private-install-interrupted-record.journal.\(privateInstallTestNonce)"
    )
    let temporaryBytes = Data("temporary-evidence".utf8)
    let archiveBytes = Data("preexisting-evidence".utf8)
    try temporaryBytes.write(to: temporary)
    try archiveBytes.write(to: archive)
    for url in [temporary, archive] {
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }
    expectPrivateInstallError(.interruptedRecordWrite) {
        _ = try PrivateInstallCoordinator.archiveInterruptedRecordWriteForTesting(
            in: records
        )
    }
    #expect(try Data(contentsOf: temporary) == temporaryBytes)
    #expect(try Data(contentsOf: archive) == archiveBytes)
}

@Test func privateInstallLifecycleJournalIsExclusiveBoundedAndRejectsUnsafeRecords() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    let journal = try #require(backend.persistedJournal)
    let lifecycle = PrivateInstallLifecycleJournal(
        operation: .cancelOriginalActive,
        nonce: journal.nonce,
        preparedAtUnixSeconds: 1_788_221_236,
        activeInstalled: journal.originalInstalled,
        retainedStage: journal.stagedCandidate,
        recoveryJournal: journal,
        receipt: nil
    )
    do {
        let directory = try makePrivateInstallRecordDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try PrivateInstallCoordinator.persistJournalForTesting(journal, in: directory)
        try PrivateInstallCoordinator.persistLifecycleJournalForTesting(
            lifecycle,
            in: directory
        )
        #expect(
            try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: directory)
                == lifecycle
        )
        let url = directory.appendingPathComponent("pending-lifecycle.json")
        var metadata = stat()
        #expect(lstat(url.path, &metadata) == 0)
        #expect(metadata.st_mode & 0o7777 == 0o600)
        #expect(metadata.st_uid == geteuid())
        #expect(metadata.st_nlink == 1)
        #expect(metadata.st_size > 0 && metadata.st_size <= 98_304)
        expectPrivateInstallError(.lifecycleFailed) {
            try PrivateInstallCoordinator.persistLifecycleJournalForTesting(
                lifecycle,
                in: directory
            )
        }

        let hardLink = directory.deletingLastPathComponent()
            .appendingPathComponent("FulmarPrivateInstallCoordinatorTests.link.\(UUID().uuidString)")
        guard link(url.path, hardLink.path) == 0 else {
            throw PrivateInstallTestFailure.fixtureFailure
        }
        defer { try? FileManager.default.removeItem(at: hardLink) }
        expectPrivateInstallError(.rollbackInspectionFailed) {
            _ = try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: directory)
        }
    }

    for fixture in ["symlink", "mode", "malformed", "extra"] {
        let directory = try makePrivateInstallRecordDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try PrivateInstallCoordinator.persistJournalForTesting(journal, in: directory)
        let url = directory.appendingPathComponent("pending-lifecycle.json")
        switch fixture {
        case "symlink":
            guard symlink("missing-lifecycle", url.path) == 0 else {
                throw PrivateInstallTestFailure.fixtureFailure
            }
        case "mode":
            try Data("{}".utf8).write(to: url)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: url.path
            )
        case "malformed":
            try Data("{\"schemaVersion\":1}".utf8).write(to: url)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        default:
            try PrivateInstallCoordinator.persistLifecycleJournalForTesting(
                lifecycle,
                in: directory
            )
            try Data().write(to: directory.appendingPathComponent("unexpected"))
        }
        expectPrivateInstallError(.rollbackInspectionFailed) {
            _ = try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: directory)
        }
    }
}

@Test func privateInstallCoordinatorRejectsDifferentPrivateSignerBeforeStaging() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.candidateAttestation = try privateInstallAttestation(
        version: "1.1.0",
        build: 110,
        marker: "2",
        certificateMarker: "b"
    )

    expectPrivateInstallError(.signerMismatch) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(!FileManager.default.fileExists(atPath: backend.stage.path))
    #expect(backend.swapCount == 0)
}

@Test func privateInstallCoordinatorRejectsRunningProcessesBeforeMutation() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.running = true

    expectPrivateInstallError(.applicationRunning) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(!FileManager.default.fileExists(atPath: backend.stage.path))
    #expect(backend.swapCount == 0)
}

@Test func privateInstallCoordinatorDetectsCandidateMutationAfterCopy() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.mutateCandidateAfterStage = true

    expectPrivateInstallError(.candidateChanged) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 0)
    #expect(try backend.payload(at: backend.installed) == "old")
}

@Test func privateInstallCoordinatorRejectsAlteredStageBeforeHelper() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.mutateStageAfterCopy = true

    expectPrivateInstallError(.stageProofFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 0)
    #expect(try backend.payload(at: backend.installed) == "old")
}

@Test func privateInstallCoordinatorNeverRequestsSwapWithoutDurableJournal() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.journalSink = { _ in
        throw PrivateInstallTestFailure.expectedFailure
    }
    expectPrivateInstallError(.journalFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 0)
    #expect(backend.persistedReceipt == nil)
    #expect(try backend.payload(at: backend.installed) == "old")
    #expect(try backend.payload(at: backend.stage) == "new")
}

@Test func privateInstallCoordinatorProvesNoMutationWhenHelperFailsBeforeSwap() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.failBeforeFirstSwap = true

    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 0)
    #expect(try backend.payload(at: backend.installed) == "old")
    #expect(try backend.payload(at: backend.stage) == "new")
}

@Test func privateInstallCoordinatorRecoversWhenHelperReportsFailureAfterSwap() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.throwAfterFirstSwap = true

    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 2)
    #expect(try backend.payload(at: backend.installed) == "old")
    #expect(try backend.payload(at: backend.stage) == "new")
}

@Test func privateInstallRecoveryClassifiesOriginalActiveAndSwappedStatesFromProofs() throws {
    let originalActive = try PrivateInstallPhysicalBackend()
    originalActive.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: originalActive.hooks()
        )
    }
    let preparedJournal = try #require(originalActive.persistedJournal)
    let prepared = try PrivateInstallCoordinator.inspectRecovery(
        hooks: privateInstallRecoveryHooks(
            backend: originalActive,
            journal: preparedJournal,
            receipt: nil
        )
    )
    #expect(prepared.state == .originalActive)
    #expect(prepared.receipt == nil)

    let swapped = try PrivateInstallPhysicalBackend()
    _ = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: swapped.hooks()
    )
    let swappedJournal = try #require(swapped.persistedJournal)
    let interrupted = try PrivateInstallCoordinator.inspectRecovery(
        hooks: privateInstallRecoveryHooks(
            backend: swapped,
            journal: swappedJournal,
            receipt: nil
        )
    )
    #expect(interrupted.state == .swappedAwaitingCommit)
    #expect(interrupted.journal == swappedJournal)
    #expect(interrupted.receipt == nil)
}

@Test func privateInstallRecoveryAcceptsCommittedJournalAndCandidateAbsence() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let journal = try #require(backend.persistedJournal)
    let present = try PrivateInstallCoordinator.inspectRecovery(
        hooks: privateInstallRecoveryHooks(
            backend: backend,
            journal: journal,
            receipt: receipt
        )
    )
    #expect(present.state == .committed)
    #expect(present.candidateState == .exact)

    let absent = try PrivateInstallCoordinator.inspectRecovery(
        hooks: privateInstallRecoveryHooks(
            backend: backend,
            journal: journal,
            receipt: receipt,
            candidate: { nil }
        )
    )
    #expect(absent.state == .committed)
    #expect(absent.candidateState == .absent)
}

@Test func privateInstallInterruptedCommitIsExplicitVerifiedAndIdempotent() throws {
    let backend = try PrivateInstallPhysicalBackend()
    _ = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let journal = try #require(backend.persistedJournal)
    var durableReceipt: PrivateInstallCoordinatorReceipt?
    var writes = 0
    var stoppedProofs = 0
    let hooks = privateInstallRecoveryHooks(
        backend: backend,
        journal: journal,
        receipt: nil,
        loadReceipt: { durableReceipt },
        persistReceipt: { receipt in
            writes += 1
            durableReceipt = receipt
        },
        proveApplicationsStopped: {
            stoppedProofs += 1
        }
    )
    let first = try PrivateInstallCoordinator.commitInterruptedInstall(hooks: hooks)
    #expect(first == durableReceipt)
    #expect(first.committedAtUnixSeconds == 1_788_221_235)
    #expect(writes == 1)
    #expect(stoppedProofs == 2)

    let second = try PrivateInstallCoordinator.commitInterruptedInstall(hooks: hooks)
    #expect(second == first)
    #expect(writes == 1)
    #expect(stoppedProofs == 3)
}

@Test func privateInstallInterruptedCommitRefusesOriginalActiveAndMutableProofs() throws {
    let originalActive = try PrivateInstallPhysicalBackend()
    originalActive.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: originalActive.hooks()
        )
    }
    let journal = try #require(originalActive.persistedJournal)
    var writes = 0
    expectPrivateInstallError(.interruptedInstallNotSwapped) {
        _ = try PrivateInstallCoordinator.commitInterruptedInstall(
            hooks: privateInstallRecoveryHooks(
                backend: originalActive,
                journal: journal,
                receipt: nil,
                persistReceipt: { _ in writes += 1 }
            )
        )
    }
    #expect(writes == 0)

    let swapped = try PrivateInstallPhysicalBackend()
    _ = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: swapped.hooks()
    )
    let swappedJournal = try #require(swapped.persistedJournal)
    var journalReads = 0
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRecovery(
            hooks: privateInstallRecoveryHooks(
                backend: swapped,
                journal: swappedJournal,
                receipt: nil,
                loadJournal: {
                    journalReads += 1
                    return journalReads == 1 ? swappedJournal : nil
                }
            )
        )
    }
}

@Test func privateInstallOriginalActiveCanBeExplicitlyResumedAndIsIdempotent() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    let journal = try #require(backend.persistedJournal)
    backend.failBeforeFirstSwap = false
    let transactionHooks = backend.hooks()
    var durableReceipt: PrivateInstallCoordinatorReceipt?
    var receiptWrites = 0
    let recoveryHooks = privateInstallRecoveryHooks(
        backend: backend,
        journal: journal,
        receipt: nil,
        candidate: { nil },
        loadReceipt: { durableReceipt },
        persistReceipt: { receipt in
            receiptWrites += 1
            durableReceipt = receipt
        },
        invokeAtomicSwap: { current, stage, attestation in
            try transactionHooks.invokeAtomicSwap(current, stage, attestation)
        }
    )
    let resumed = try PrivateInstallCoordinator.resumeInterruptedInstall(hooks: recoveryHooks)
    #expect(resumed == durableReceipt)
    #expect(backend.swapCount == 1)
    #expect(receiptWrites == 1)
    #expect(try backend.payload(at: backend.installed) == "new")
    #expect(try backend.payload(at: backend.stage) == "old")

    let repeated = try PrivateInstallCoordinator.resumeInterruptedInstall(hooks: recoveryHooks)
    #expect(repeated == resumed)
    #expect(backend.swapCount == 1)
    #expect(receiptWrites == 1)
}

@Test func privateInstallOriginalActiveCancellationArchivesWithoutDeletingAndIsIdempotent() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    let lifecycle = PrivateInstallLifecycleBackend(
        backend: backend,
        journal: try #require(backend.persistedJournal),
        receipt: nil,
        operation: .cancelOriginalActive
    )
    lifecycle.candidatePresent = false
    let result = try PrivateInstallCoordinator.performLifecycle(
        operation: .cancelOriginalActive,
        hooks: lifecycle.hooks()
    )
    #expect(result?.operation == .cancelOriginalActive)
    #expect(lifecycle.archiveRenames == 1)
    #expect(lifecycle.recordArchiveRenames == 1)
    #expect(lifecycle.durableArchiveProofs == 1)
    #expect(lifecycle.stoppedProofs == 4)
    #expect(!lifecycle.stagePresent)
    #expect(lifecycle.archivePresent)
    #expect(!lifecycle.recordsPresent)
    #expect(try backend.payload(at: backend.installed) == "old")
    #expect(try backend.payload(at: backend.stage) == "new")

    let repeated = try PrivateInstallCoordinator.performLifecycle(
        operation: .cancelOriginalActive,
        hooks: lifecycle.hooks()
    )
    #expect(repeated == nil)
    #expect(lifecycle.archiveRenames == 1)
    #expect(lifecycle.recordArchiveRenames == 1)
}

@Test func privateInstallCommittedRetirementArchivesRollbackAndUnblocksNextTransaction() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let lifecycle = PrivateInstallLifecycleBackend(
        backend: backend,
        journal: try #require(backend.persistedJournal),
        receipt: receipt,
        operation: .retireCommitted
    )
    let result = try PrivateInstallCoordinator.performLifecycle(
        operation: .retireCommitted,
        hooks: lifecycle.hooks()
    )
    #expect(result?.operation == .retireCommitted)
    #expect(lifecycle.archiveRenames == 1)
    #expect(lifecycle.recordArchiveRenames == 1)
    #expect(try backend.payload(at: backend.installed) == "new")
    #expect(try backend.payload(at: backend.stage) == "old")
    let clean = try PrivateInstallCoordinator.inspectRecovery(hooks: lifecycle.hooks())
    #expect(clean.state == .none)
}

@Test func privateInstallLifecycleReplaysEveryUncertainDurabilityBoundary() throws {
    do {
        let backend = try PrivateInstallPhysicalBackend()
        backend.failBeforeFirstSwap = true
        expectPrivateInstallError(.helperFailed) {
            _ = try PrivateInstallCoordinator.perform(
                nonce: privateInstallTestNonce,
                hooks: backend.hooks()
            )
        }
        let lifecycle = PrivateInstallLifecycleBackend(
            backend: backend,
            journal: try #require(backend.persistedJournal),
            receipt: nil,
            operation: .cancelOriginalActive
        )
        lifecycle.failLifecycleAfterWrite = true
        expectPrivateInstallError(.lifecycleFailed) {
            _ = try PrivateInstallCoordinator.performLifecycle(
                operation: .cancelOriginalActive,
                hooks: lifecycle.hooks()
            )
        }
        #expect(lifecycle.lifecycleJournal != nil)
        #expect(lifecycle.stagePresent)
        lifecycle.failLifecycleAfterWrite = false
        _ = try PrivateInstallCoordinator.performLifecycle(
            operation: .cancelOriginalActive,
            hooks: lifecycle.hooks()
        )
        #expect(!lifecycle.recordsPresent)
    }

    do {
        let backend = try PrivateInstallPhysicalBackend()
        let receipt = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
        let lifecycle = PrivateInstallLifecycleBackend(
            backend: backend,
            journal: try #require(backend.persistedJournal),
            receipt: receipt,
            operation: .retireCommitted
        )
        lifecycle.failArchiveAfterRename = true
        let result = try PrivateInstallCoordinator.performLifecycle(
            operation: .retireCommitted,
            hooks: lifecycle.hooks()
        )
        #expect(result?.operation == .retireCommitted)
        #expect(lifecycle.archiveRenames == 1)
        #expect(!lifecycle.recordsPresent)
    }

    do {
        let backend = try PrivateInstallPhysicalBackend()
        let receipt = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
        let lifecycle = PrivateInstallLifecycleBackend(
            backend: backend,
            journal: try #require(backend.persistedJournal),
            receipt: receipt,
            operation: .retireCommitted
        )
        lifecycle.failRecordArchiveAfterRename = true
        expectPrivateInstallError(.lifecycleFailed) {
            _ = try PrivateInstallCoordinator.performLifecycle(
                operation: .retireCommitted,
                hooks: lifecycle.hooks()
            )
        }
        #expect(!lifecycle.recordsPresent)
        let repeated = try PrivateInstallCoordinator.performLifecycle(
            operation: .retireCommitted,
            hooks: lifecycle.hooks()
        )
        #expect(repeated == nil)
    }
}

@Test func privateInstallLifecycleRejectsCollisionMissingArchiveABAAndWrongOperation() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.failBeforeFirstSwap = true
    expectPrivateInstallError(.helperFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    let lifecycle = PrivateInstallLifecycleBackend(
        backend: backend,
        journal: try #require(backend.persistedJournal),
        receipt: nil,
        operation: .cancelOriginalActive
    )
    lifecycle.failLifecycleAfterWrite = true
    expectPrivateInstallError(.lifecycleFailed) {
        _ = try PrivateInstallCoordinator.performLifecycle(
            operation: .cancelOriginalActive,
            hooks: lifecycle.hooks()
        )
    }
    lifecycle.failLifecycleAfterWrite = false
    expectPrivateInstallError(.lifecycleOperationMismatch) {
        _ = try PrivateInstallCoordinator.performLifecycle(
            operation: .retireCommitted,
            hooks: lifecycle.hooks()
        )
    }

    lifecycle.archivePresent = true
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRecovery(hooks: lifecycle.hooks())
    }
    lifecycle.stagePresent = false
    lifecycle.archivePresent = false
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRecovery(hooks: lifecycle.hooks())
    }

    lifecycle.archivePresent = true
    var lifecycleReads = 0
    let stableLifecycle = try #require(lifecycle.lifecycleJournal)
    expectPrivateInstallError(.rollbackInspectionFailed) {
        _ = try PrivateInstallCoordinator.inspectRecovery(
            hooks: privateInstallRecoveryHooks(
                backend: backend,
                journal: lifecycle.journal,
                receipt: nil,
                lifecycleJournal: stableLifecycle,
                stageLeaves: { [] },
                archiveLeaves: { [lifecycle.archiveLeaf] },
                archive: { try backend.inspect(backend.stage) },
                loadLifecycleJournal: {
                    lifecycleReads += 1
                    return lifecycleReads == 1 ? stableLifecycle : nil
                }
            )
        )
    }
}

@Test func privateInstallReceiptDurabilityFailureNeverCreatesOppositeReceiptPair() throws {
    let backend = try PrivateInstallPhysicalBackend()
    var durableReceipt: PrivateInstallCoordinatorReceipt?
    backend.receiptSink = { receipt in
        durableReceipt = receipt
        throw PrivateInstallTestFailure.expectedFailure
    }
    expectPrivateInstallError(.receiptFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    let journal = try #require(backend.persistedJournal)
    let receipt = try #require(durableReceipt)
    #expect(backend.swapCount == 1)
    #expect(try backend.payload(at: backend.installed) == "new")
    #expect(try backend.payload(at: backend.stage) == "old")
    let committed = try PrivateInstallCoordinator.inspectRecovery(
        hooks: privateInstallRecoveryHooks(
            backend: backend,
            journal: journal,
            receipt: receipt
        )
    )
    #expect(committed.state == .committed)
}

@Test func privateInstallRealSIGKILLBoundariesRemainDeterministicallyRecoverable() throws {
    let probe = try privateInstallCrashProbeURL()
    for boundary in ["after-journal", "after-swap", "after-receipt"] {
        let root = try privateInstallCrashProbeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let process = Process()
        process.executableURL = probe
        process.arguments = ["--root", root.path, "--boundary", boundary]
        process.environment = ["PATH": "/usr/bin:/bin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(20)
        while process.isRunning, Date() < deadline {
            usleep(10_000)
        }
        if process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL)
        }
        #expect(boundedTestWaitForExit(process, timeout: 3))
        #expect(process.terminationReason == .uncaughtSignal)
        #expect(process.terminationStatus == SIGKILL)

        let installed = root.appendingPathComponent("Fulmar.app", isDirectory: true)
        let stage = root.appendingPathComponent(
            try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce),
            isDirectory: true
        )
        let records = root.appendingPathComponent("records", isDirectory: true)
        let loadedJournal = try PrivateInstallCoordinator.readJournalForTesting(in: records)
        let journal = try #require(loadedJournal)
        let receipt = try PrivateInstallCoordinator.readReceiptForTesting(in: records)
        let installedIdentity = try PrivateInstallCoordinator.identityForTesting(at: installed)
        let stageIdentity = try PrivateInstallCoordinator.identityForTesting(at: stage)
        switch boundary {
        case "after-journal":
            #expect(installedIdentity == journal.originalInstalled.identity)
            #expect(stageIdentity == journal.stagedCandidate.identity)
            #expect(receipt == nil)
        case "after-swap":
            #expect(installedIdentity == journal.stagedCandidate.identity)
            #expect(stageIdentity == journal.originalInstalled.identity)
            #expect(receipt == nil)
        default:
            let committed = try #require(receipt)
            #expect(installedIdentity == committed.installed.identity)
            #expect(stageIdentity == committed.retainedRollback.identity)
            #expect(committed.nonce == journal.nonce)
            #expect(committed.installed == journal.stagedCandidate)
            #expect(committed.retainedRollback == journal.originalInstalled)
        }
    }
}

@Test func privateInstallLifecycleRealSIGKILLBoundariesPreserveActiveAndArchivedBundles() throws {
    let probe = try privateInstallCrashProbeURL()
    let boundaries = [
        "after-cancel-marker",
        "after-cancel-stage-archive",
        "after-cancel-record-archive",
        "after-retire-marker",
        "after-retire-stage-archive",
        "after-retire-record-archive"
    ]
    for boundary in boundaries {
        let root = try privateInstallCrashProbeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let process = Process()
        process.executableURL = probe
        process.arguments = ["--root", root.path, "--boundary", boundary]
        process.environment = ["PATH": "/usr/bin:/bin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(20)
        while process.isRunning, Date() < deadline { usleep(10_000) }
        if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
        #expect(boundedTestWaitForExit(process, timeout: 3))
        #expect(process.terminationReason == .uncaughtSignal)
        #expect(process.terminationStatus == SIGKILL)

        let isCancel = boundary.contains("cancel")
        let disposition = isCancel ? "cancelled" : "retired"
        let records = root.appendingPathComponent("records", isDirectory: true)
        let archivedRecords = root.appendingPathComponent(
            "records.\(disposition).\(privateInstallTestNonce)",
            isDirectory: true
        )
        let recordLocation = boundary.contains("record-archive")
            ? archivedRecords
            : records
        let lifecycle = try #require(
            try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: recordLocation)
        )
        #expect(
            lifecycle.operation
                == (isCancel ? .cancelOriginalActive : .retireCommitted)
        )
        let installed = root.appendingPathComponent("Fulmar.app", isDirectory: true)
        #expect(
            try PrivateInstallCoordinator.identityForTesting(at: installed)
                == lifecycle.activeInstalled.identity
        )
        let stage = root.appendingPathComponent(
            try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce),
            isDirectory: true
        )
        let archive = root.appendingPathComponent(
            ".Fulmar.private-\(disposition).\(privateInstallTestNonce).app",
            isDirectory: true
        )
        if boundary.contains("marker") {
            #expect(
                try PrivateInstallCoordinator.identityForTesting(at: stage)
                    == lifecycle.retainedStage.identity
            )
            #expect(!FileManager.default.fileExists(atPath: archive.path))
        } else {
            #expect(!FileManager.default.fileExists(atPath: stage.path))
            #expect(
                try PrivateInstallCoordinator.identityForTesting(at: archive)
                    == lifecycle.retainedStage.identity
            )
        }
        if boundary.contains("record-archive") {
            #expect(!FileManager.default.fileExists(atPath: records.path))
            #expect(FileManager.default.fileExists(atPath: archivedRecords.path))
        } else {
            #expect(FileManager.default.fileExists(atPath: records.path))
            #expect(!FileManager.default.fileExists(atPath: archivedRecords.path))
        }
    }
}

@Test func privateInstallRecordPersistenceSIGKILLBoundariesArchiveEvidenceAndRetryIdempotently() throws {
    let probe = try privateInstallCrashProbeURL()
    let phases = [
        "after-temporary-create",
        "after-partial-file-sync",
        "after-complete-file-sync",
        "before-exclusive-rename",
        "after-rename-before-directory-sync"
    ]
    for kind in ["preparation", "abandonment", "journal", "receipt", "lifecycle"] {
        for phase in phases {
            let boundary = "\(kind)-\(phase)"
            let root = try privateInstallCrashProbeRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            let process = Process()
            process.executableURL = probe
            process.arguments = ["--root", root.path, "--boundary", boundary]
            process.environment = ["PATH": "/usr/bin:/bin"]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            let deadline = Date().addingTimeInterval(20)
            while process.isRunning, Date() < deadline { usleep(10_000) }
            if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
            #expect(boundedTestWaitForExit(process, timeout: 3))
            #expect(
                process.terminationReason == .uncaughtSignal,
                Comment(rawValue: "SIGKILL boundary did not signal: \(boundary); probe=\(probe.path)")
            )
            #expect(
                process.terminationStatus == SIGKILL,
                Comment(rawValue: "SIGKILL boundary returned \(process.terminationStatus): \(boundary)")
            )

            let records = root.appendingPathComponent("records", isDirectory: true)
            let installed = root.appendingPathComponent("Fulmar.app", isDirectory: true)
            let candidate = root.appendingPathComponent("FrozenCandidate.app", isDirectory: true)
            let stage = root.appendingPathComponent(
                try AtomicInstallSwap.stageLeaf(nonce: privateInstallTestNonce),
                isDirectory: true
            )
            let oldAttestation = try privateInstallAttestation(
                version: "1.0.0",
                build: 100,
                marker: "1"
            )
            let newAttestation = try privateInstallAttestation(
                version: "1.1.0",
                build: 110,
                marker: "2"
            )
            func proof(_ url: URL) throws -> PrivateInstallBundleProof {
                let payload = try String(
                    contentsOf: url.appendingPathComponent("nested/payload.txt"),
                    encoding: .utf8
                )
                return PrivateInstallBundleProof(
                    identity: try PrivateInstallCoordinator.identityForTesting(at: url),
                    treeSHA256Hex: try PrivateInstallCoordinator.treeSHA256ForTesting(at: url),
                    attestation: payload == "old" ? oldAttestation : newAttestation
                )
            }

            let postRename = phase == "after-rename-before-directory-sync"
            func makeRecoveryHooks(
                candidateProof: @escaping () throws -> PrivateInstallBundleProof?
            ) -> PrivateInstallRecoveryHooks {
                PrivateInstallRecoveryHooks(
                    loadJournal: {
                        try PrivateInstallCoordinator.readJournalForTesting(in: records)
                    },
                    loadReceipt: {
                        try PrivateInstallCoordinator.readReceiptForTesting(in: records)
                    },
                    loadLifecycleJournal: {
                        try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: records)
                    },
                    stageLeaves: {
                        FileManager.default.fileExists(atPath: stage.path)
                            ? [stage.lastPathComponent] : []
                    },
                    archiveLeaves: { [] },
                    inspectInstalled: { try proof(installed) },
                    inspectStage: { _ in try proof(stage) },
                    inspectArchive: { _ in throw PrivateInstallTestFailure.expectedFailure },
                    inspectCandidateIfPresent: candidateProof,
                    proveApplicationsStopped: {},
                    invokeAtomicSwap: { _, _, _ in
                        throw PrivateInstallTestFailure.expectedFailure
                    },
                    persistReceipt: { value in
                        try PrivateInstallCoordinator.persistReceiptForTesting(
                            value,
                            in: records
                        )
                    },
                    persistLifecycleJournal: { value in
                        try PrivateInstallCoordinator.persistLifecycleJournalForTesting(
                            value,
                            in: records
                        )
                    },
                    archiveStage: { _, _, _ in
                        throw PrivateInstallTestFailure.expectedFailure
                    },
                    proveArchiveDurable: { _, _ in
                        throw PrivateInstallTestFailure.expectedFailure
                    },
                    archiveRecordDirectory: { _ in
                        throw PrivateInstallTestFailure.expectedFailure
                    },
                    loadPreparation: {
                        try PrivateInstallCoordinator.readPreparationForTesting(in: records)
                    },
                    nowUnixSeconds: { 1_788_221_240 }
                )
            }
            let recoveryHooks = makeRecoveryHooks {
                try proof(candidate)
            }
            if boundary == "journal-after-partial-file-sync" {
                let leavesBefore = try FileManager.default.contentsOfDirectory(
                    atPath: records.path
                ).sorted()
                expectPrivateInstallError(.interruptedRecordWrite) {
                    try PrivateInstallCoordinator.reconcileInterruptedRecordWrite(
                        in: records,
                        hooks: makeRecoveryHooks { nil }
                    )
                }
                #expect(
                    try FileManager.default.contentsOfDirectory(atPath: records.path).sorted()
                        == leavesBefore
                )
                #expect(
                    !(try FileManager.default.contentsOfDirectory(atPath: root.path))
                        .contains {
                            $0.hasPrefix(
                                ".Fulmar.private-install-interrupted-record.journal."
                            )
                        }
                )
            }
            if boundary == "preparation-after-temporary-create" {
                // Exercise a second process starting after the exact temp was
                // already archived but before canonical reconstruction.
                #expect(
                    try PrivateInstallCoordinator.archiveInterruptedRecordWriteForTesting(
                        in: records
                    ) == "preparation:\(privateInstallTestNonce)"
                )
            }
            try PrivateInstallCoordinator.reconcileInterruptedRecordWrite(
                in: records,
                hooks: recoveryHooks
            )
            #expect(
                try PrivateInstallCoordinator.archiveInterruptedRecordWriteForTesting(
                    in: records
                ) == nil
            )
            try PrivateInstallCoordinator.reconcileInterruptedRecordWrite(
                in: records,
                hooks: recoveryHooks
            )
            switch kind {
            case "preparation":
                #expect(
                    try PrivateInstallCoordinator.readPreparationForTesting(in: records) != nil,
                    Comment(rawValue: "preparation was not reconstructed: \(boundary)")
                )
            case "abandonment":
                #expect(
                    try PrivateInstallCoordinator.readAbandonmentForTesting(in: records) != nil
                )
            case "journal":
                #expect(try PrivateInstallCoordinator.readJournalForTesting(in: records) != nil)
            case "receipt":
                #expect(try PrivateInstallCoordinator.readReceiptForTesting(in: records) != nil)
            default:
                #expect(
                    try PrivateInstallCoordinator.readLifecycleJournalForTesting(
                        in: records
                    ) != nil
                )
            }
            if !postRename {
                let archivePrefix = ".Fulmar.private-install-interrupted-record.\(kind)."
                #expect(
                    try FileManager.default.contentsOfDirectory(atPath: root.path)
                        .contains { $0.hasPrefix(archivePrefix) }
                )
            }
        }
    }
}

@Test func privateInstallCoordinatorRollsBackPostInstallBoundaryFailure() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.postBoundaryFails = true

    expectPrivateInstallError(.postInstallProofFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 2)
    #expect(try backend.payload(at: backend.installed) == "old")
    #expect(try backend.payload(at: backend.stage) == "new")
}

@Test func privateInstallCoordinatorPreservesSwappedPairWhenReceiptWriteFails() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.receiptFails = true

    expectPrivateInstallError(.receiptFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 1)
    #expect(try backend.payload(at: backend.installed) == "new")
    #expect(try backend.payload(at: backend.stage) == "old")
    let journal = try #require(backend.persistedJournal)
    let recoverable = try PrivateInstallCoordinator.inspectRecovery(
        hooks: privateInstallRecoveryHooks(
            backend: backend,
            journal: journal,
            receipt: nil
        )
    )
    #expect(recoverable.state == .swappedAwaitingCommit)
}

@Test func privateInstallCoordinatorFailsClosedWhenAutomaticRollbackCannotSwap() throws {
    let backend = try PrivateInstallPhysicalBackend()
    backend.postBoundaryFails = true
    backend.failOnSwapNumber = 2

    expectPrivateInstallError(.rollbackFailed) {
        _ = try PrivateInstallCoordinator.perform(
            nonce: privateInstallTestNonce,
            hooks: backend.hooks()
        )
    }
    #expect(backend.swapCount == 1)
    #expect(try backend.payload(at: backend.installed) == "new")
    #expect(try backend.payload(at: backend.stage) == "old")
}

@Test func privateInstallCoordinatorTreeDigestBindsNestedBytesModesAndSymlinkTargets() throws {
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    defer { try? FileManager.default.removeItem(at: root) }
    let first = root.appendingPathComponent("first.txt")
    let second = root.appendingPathComponent("second.txt")
    try Data("one".utf8).write(to: first)
    try Data("two".utf8).write(to: second)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: first.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: second.path)
    let link = root.appendingPathComponent("selected")
    guard symlink("first.txt", link.path) == 0 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }

    let baseline = try PrivateInstallCoordinator.treeSHA256ForTesting(at: root)
    try Data("changed".utf8).write(to: first)
    let contentChanged = try PrivateInstallCoordinator.treeSHA256ForTesting(at: root)
    #expect(contentChanged != baseline)

    try Data("one".utf8).write(to: first)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: first.path)
    let modeChanged = try PrivateInstallCoordinator.treeSHA256ForTesting(at: root)
    #expect(modeChanged != baseline)

    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: first.path)
    guard unlink(link.path) == 0,
          symlink("second.txt", link.path) == 0 else {
        throw PrivateInstallTestFailure.fixtureFailure
    }
    let linkChanged = try PrivateInstallCoordinator.treeSHA256ForTesting(at: root)
    #expect(linkChanged != baseline)
}

@Test func privateInstallCoordinatorRejectsEscapingAndAbsoluteSymlinks() throws {
    for target in ["../outside", "/private/tmp/outside"] {
        let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent(
                "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
                isDirectory: true
            )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        defer { try? FileManager.default.removeItem(at: root) }
        let link = root.appendingPathComponent("escape")
        guard symlink(target, link.path) == 0 else {
            throw PrivateInstallTestFailure.fixtureFailure
        }
        expectPrivateInstallError(.unsafeCandidate) {
            _ = try PrivateInstallCoordinator.treeSHA256ForTesting(at: root)
        }
    }
}

@Test func privateInstallCoordinatorWritesBoundedOwnerPrivateDurableReceipt() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let receiptDirectory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(
        at: receiptDirectory,
        withIntermediateDirectories: false
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: receiptDirectory.path
    )
    defer { try? FileManager.default.removeItem(at: receiptDirectory) }

    try PrivateInstallCoordinator.persistReceiptForTesting(receipt, in: receiptDirectory)
    let receiptURL = receiptDirectory.appendingPathComponent("latest-private-install.json")
    let bytes = try Data(contentsOf: receiptURL)
    #expect(bytes.count <= 24_576)
    #expect(try JSONDecoder().decode(PrivateInstallCoordinatorReceipt.self, from: bytes) == receipt)
    var metadata = stat()
    #expect(lstat(receiptURL.path, &metadata) == 0)
    #expect(metadata.st_mode & 0o7777 == 0o600)
    #expect(metadata.st_uid == geteuid())
    #expect(metadata.st_nlink == 1)
    #expect(try FileManager.default.contentsOfDirectory(atPath: receiptDirectory.path)
        == ["latest-private-install.json"])
}

@Test func privateInstallCoordinatorRejectsReceiptDirectoryWithExtendedACL() throws {
    let backend = try PrivateInstallPhysicalBackend()
    let receipt = try PrivateInstallCoordinator.perform(
        nonce: privateInstallTestNonce,
        hooks: backend.hooks()
    )
    let receiptDirectory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarPrivateInstallCoordinatorTests.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(
        at: receiptDirectory,
        withIntermediateDirectories: false
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: receiptDirectory.path
    )
    defer { try? FileManager.default.removeItem(at: receiptDirectory) }
    try addPrivateInstallReadACL(to: receiptDirectory)

    expectPrivateInstallError(.receiptFailed) {
        try PrivateInstallCoordinator.persistReceiptForTesting(receipt, in: receiptDirectory)
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: receiptDirectory.path).isEmpty)
}

@Test(.disabled(
    if: ProcessInfo.processInfo.environment["LOCAL_HARNESS_TEST_APP_PATH"] == nil,
    "Requires the release runner's exact extracted application fixture."
))
func privateInstallCoordinatorHashesRealPrivateStableFixtureDeterministically() throws {
    let fixturePath = try #require(
        ProcessInfo.processInfo.environment["LOCAL_HARNESS_TEST_APP_PATH"]
    )
    let fixture = URL(fileURLWithPath: fixturePath, isDirectory: true)
    let identityBefore = try PrivateInstallCoordinator.identityForTesting(at: fixture)
    let first = try PrivateInstallCoordinator.treeSHA256ForTesting(at: fixture)
    let attestation = try AtomicInstallSwap.privateStableAttestation(at: fixture)
    let second = try PrivateInstallCoordinator.treeSHA256ForTesting(at: fixture)
    let identityAfter = try PrivateInstallCoordinator.identityForTesting(at: fixture)

    #expect(first == second)
    #expect(first.count == 64)
    #expect(identityBefore == identityAfter)
    #expect(attestation.identifier == "com.angadjairath.localharness")
    try attestation.validateShape()
}

@Test func privateInstallCoordinatorRejectsInvalidNonceWithoutInspectingOrStaging() throws {
    let backend = try PrivateInstallPhysicalBackend()
    expectPrivateInstallError(.invalidInvocation) {
        _ = try PrivateInstallCoordinator.perform(nonce: "not-a-nonce", hooks: backend.hooks())
    }
    #expect(backend.stoppedProofCount == 0)
    #expect(!FileManager.default.fileExists(atPath: backend.stage.path))
}

@Test func privateInstallCoordinatorProductionTopologyIsFixedAndPrivateOnly() throws {
    #expect(PrivateInstallCoordinator.frozenCandidatePath
        == "/private/tmp/LocalHarnessBuild/Fulmar.app")
    #expect(PrivateInstallCoordinator.installedApplicationPath == "/Applications/Fulmar.app")
    #expect(PrivateInstallCoordinator.receiptRelativePath
        == "Library/Application Support/.Fulmar Private Install Receipts/latest-private-install.json")
    #expect(PrivateInstallCoordinator.journalRelativePath
        == "Library/Application Support/.Fulmar Private Install Receipts/pending-private-install.json")
    #expect(PrivateInstallCoordinator.lifecycleJournalRelativePath
        == "Library/Application Support/.Fulmar Private Install Receipts/pending-lifecycle.json")

    // A securely provisioned macOS login home need not live below /Users.
    // Build one under Darwin's canonical owner-private cache hierarchy so the
    // test exercises the production ancestry proof without changing HOME.
    let cache = try privateInstallDarwinUserCacheDirectory()
    let portableHome = cache.appendingPathComponent(
        "FulmarPrivateInstallPortableHome.\(UUID().uuidString)",
        isDirectory: true
    )
    let applicationSupport = portableHome.appendingPathComponent(
        "Library/Application Support",
        isDirectory: true
    )
    try FileManager.default.createDirectory(
        at: applicationSupport,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    for directory in [portableHome, portableHome.appendingPathComponent("Library"), applicationSupport] {
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directory.path
        )
    }
    defer { try? FileManager.default.removeItem(at: portableHome) }
    #expect(!portableHome.path.hasPrefix("/Users/"))
    #expect(try PrivateInstallCoordinator.productionApplicationSupportDirectoryForTesting(
        homeDirectory: portableHome
    ) == applicationSupport)

    let linkedHome = cache.appendingPathComponent(
        "FulmarPrivateInstallLinkedHome.\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createSymbolicLink(at: linkedHome, withDestinationURL: portableHome)
    defer { try? FileManager.default.removeItem(at: linkedHome) }
    expectPrivateInstallError(.receiptFailed) {
        _ = try PrivateInstallCoordinator.productionApplicationSupportDirectoryForTesting(
            homeDirectory: linkedHome
        )
    }

    try FileManager.default.setAttributes(
        [.posixPermissions: 0o770],
        ofItemAtPath: portableHome.path
    )
    expectPrivateInstallError(.receiptFailed) {
        _ = try PrivateInstallCoordinator.productionApplicationSupportDirectoryForTesting(
            homeDirectory: portableHome
        )
    }
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: portableHome.path
    )
    try addPrivateInstallReadACL(to: portableHome)
    expectPrivateInstallError(.receiptFailed) {
        _ = try PrivateInstallCoordinator.productionApplicationSupportDirectoryForTesting(
            homeDirectory: portableHome
        )
    }

    let writableAncestorHome = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            "FulmarPrivateInstallUnsafeHome.\(UUID().uuidString)",
            isDirectory: true
        )
    try FileManager.default.createDirectory(
        at: writableAncestorHome.appendingPathComponent(
            "Library/Application Support",
            isDirectory: true
        ),
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: writableAncestorHome) }
    for directory in [
        writableAncestorHome,
        writableAncestorHome.appendingPathComponent("Library"),
        writableAncestorHome.appendingPathComponent("Library/Application Support")
    ] {
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directory.path
        )
    }
    expectPrivateInstallError(.receiptFailed) {
        _ = try PrivateInstallCoordinator.productionApplicationSupportDirectoryForTesting(
            homeDirectory: writableAncestorHome
        )
    }
}
