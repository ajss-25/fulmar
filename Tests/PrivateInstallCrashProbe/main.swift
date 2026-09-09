import Darwin
import Foundation
@_spi(PrivateInstallCrashProbe) import LocalHarnessPrivateInstallCoordinator
import LocalHarnessAtomicInstallSwap
import Security

private enum ProbeError: Error {
    case invalidInvocation
    case unsafeFixture
    case fixtureFailure
}

private enum Boundary: String {
    case afterJournal = "after-journal"
    case afterSwap = "after-swap"
    case afterReceipt = "after-receipt"
    case afterCancelMarker = "after-cancel-marker"
    case afterCancelStageArchive = "after-cancel-stage-archive"
    case afterCancelRecordArchive = "after-cancel-record-archive"
    case afterRetireMarker = "after-retire-marker"
    case afterRetireStageArchive = "after-retire-stage-archive"
    case afterRetireRecordArchive = "after-retire-record-archive"
    case journalAfterTemporaryCreate = "journal-after-temporary-create"
    case journalAfterPartialFileSync = "journal-after-partial-file-sync"
    case journalAfterCompleteFileSync = "journal-after-complete-file-sync"
    case journalBeforeExclusiveRename = "journal-before-exclusive-rename"
    case journalAfterRenameBeforeDirectorySync = "journal-after-rename-before-directory-sync"
    case receiptAfterTemporaryCreate = "receipt-after-temporary-create"
    case receiptAfterPartialFileSync = "receipt-after-partial-file-sync"
    case receiptAfterCompleteFileSync = "receipt-after-complete-file-sync"
    case receiptBeforeExclusiveRename = "receipt-before-exclusive-rename"
    case receiptAfterRenameBeforeDirectorySync = "receipt-after-rename-before-directory-sync"
    case lifecycleAfterTemporaryCreate = "lifecycle-after-temporary-create"
    case lifecycleAfterPartialFileSync = "lifecycle-after-partial-file-sync"
    case lifecycleAfterCompleteFileSync = "lifecycle-after-complete-file-sync"
    case lifecycleBeforeExclusiveRename = "lifecycle-before-exclusive-rename"
    case lifecycleAfterRenameBeforeDirectorySync = "lifecycle-after-rename-before-directory-sync"
    case preparationAfterTemporaryCreate = "preparation-after-temporary-create"
    case preparationAfterPartialFileSync = "preparation-after-partial-file-sync"
    case preparationAfterCompleteFileSync = "preparation-after-complete-file-sync"
    case preparationBeforeExclusiveRename = "preparation-before-exclusive-rename"
    case preparationAfterRenameBeforeDirectorySync = "preparation-after-rename-before-directory-sync"
    case abandonmentAfterTemporaryCreate = "abandonment-after-temporary-create"
    case abandonmentAfterPartialFileSync = "abandonment-after-partial-file-sync"
    case abandonmentAfterCompleteFileSync = "abandonment-after-complete-file-sync"
    case abandonmentBeforeExclusiveRename = "abandonment-before-exclusive-rename"
    case abandonmentAfterRenameBeforeDirectorySync = "abandonment-after-rename-before-directory-sync"

    var lifecycleOperation: PrivateInstallLifecycleOperation? {
        switch self {
        case .afterCancelMarker, .afterCancelStageArchive, .afterCancelRecordArchive,
             .lifecycleAfterTemporaryCreate, .lifecycleAfterPartialFileSync,
             .lifecycleAfterCompleteFileSync, .lifecycleBeforeExclusiveRename,
             .lifecycleAfterRenameBeforeDirectorySync:
            return .cancelOriginalActive
        case .afterRetireMarker, .afterRetireStageArchive, .afterRetireRecordArchive:
            return .retireCommitted
        default:
            return nil
        }
    }

    var recordKind: String? {
        if rawValue.hasPrefix("preparation-") { return "preparation" }
        if rawValue.hasPrefix("abandonment-") { return "abandonment" }
        if rawValue.hasPrefix("journal-") { return "journal" }
        if rawValue.hasPrefix("receipt-") { return "receipt" }
        if rawValue.hasPrefix("lifecycle-") { return "lifecycle" }
        return nil
    }

    var recordPersistenceBoundary: PrivateInstallRecordPersistenceBoundary? {
        if rawValue.hasSuffix("after-temporary-create") { return .afterTemporaryCreate }
        if rawValue.hasSuffix("after-partial-file-sync") { return .afterPartialFileSync }
        if rawValue.hasSuffix("after-complete-file-sync") { return .afterCompleteFileSync }
        if rawValue.hasSuffix("before-exclusive-rename") { return .beforeExclusiveRename }
        if rawValue.hasSuffix("after-rename-before-directory-sync") {
            return .afterRenameBeforeDirectorySync
        }
        return nil
    }
}

private let nonce = String(repeating: "c", count: 64)

private func fail(_ message: String) -> Never {
    let bytes = Array("PrivateInstallCrashProbe: \(message)\n".utf8)
    bytes.withUnsafeBytes { buffer in
        _ = Darwin.write(STDERR_FILENO, buffer.baseAddress, buffer.count)
    }
    _exit(64)
}

private func parse() throws -> (URL, Boundary) {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard arguments.count == 4,
          arguments[0] == "--root",
          arguments[2] == "--boundary",
          let boundary = Boundary(rawValue: arguments[3]) else {
        throw ProbeError.invalidInvocation
    }
    let root = URL(fileURLWithPath: arguments[1], isDirectory: true)
    let prefix = "/private/tmp/FulmarPrivateInstallCrashProbe."
    let suffix = String(root.path.dropFirst(prefix.count))
    guard root.path.hasPrefix(prefix),
          root.deletingLastPathComponent().path == "/private/tmp",
          suffix.utf8.count == 64,
          suffix.utf8.allSatisfy({ byte in
              (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                  || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
          }),
          let canonical = realpath(root.path, nil) else {
        throw ProbeError.unsafeFixture
    }
    defer { free(canonical) }
    guard String(cString: canonical) == root.path else {
        throw ProbeError.unsafeFixture
    }
    var metadata = stat()
    guard lstat(root.path, &metadata) == 0,
          metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
          metadata.st_mode & 0o7777 == 0o700,
          metadata.st_uid == geteuid(),
          try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty else {
        throw ProbeError.unsafeFixture
    }
    return (root, boundary)
}

private func requirement() throws -> Data {
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(
        "identifier \"com.angadjairath.localharness\"" as CFString,
        [],
        &requirement
    ) == errSecSuccess,
    let requirement else {
        throw ProbeError.fixtureFailure
    }
    var bytes: CFData?
    guard SecRequirementCopyData(requirement, [], &bytes) == errSecSuccess,
          let bytes else {
        throw ProbeError.fixtureFailure
    }
    return bytes as Data
}

private func attestation(
    version: String,
    build: Int,
    marker: Character
) throws -> PrivateStableApplicationAttestation {
    PrivateStableApplicationAttestation(
        identifier: "com.angadjairath.localharness",
        version: version,
        build: build,
        cdHashHex: String(repeating: String(marker), count: 40),
        leafCertificateSHA256Hex: String(repeating: "a", count: 64),
        designatedRequirement: try requirement()
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

private func stopAt(_ selected: Boundary, _ reached: Boundary) -> Void {
    guard selected == reached else { return }
    _ = Darwin.kill(getpid(), SIGKILL)
    // SIGKILL cannot be caught or ignored. Keep a fail-closed fallback in case
    // the kernel call itself unexpectedly fails.
    _exit(125)
}

private func stopAtRecordBoundary(
    _ selected: Boundary,
    kind: String,
    reached: PrivateInstallRecordPersistenceBoundary
) {
    guard selected.recordKind == kind,
          selected.recordPersistenceBoundary == reached else { return }
    _ = Darwin.kill(getpid(), SIGKILL)
    _exit(125)
}

do {
    let (root, boundary) = try parse()
    let installed = root.appendingPathComponent("Fulmar.app", isDirectory: true)
    let candidate = root.appendingPathComponent("FrozenCandidate.app", isDirectory: true)
    let stage = root.appendingPathComponent(
        try AtomicInstallSwap.stageLeaf(nonce: nonce),
        isDirectory: true
    )
    let records = root.appendingPathComponent("records", isDirectory: true)
    try makeBundle(at: installed, payload: "old")
    try makeBundle(at: candidate, payload: "new")
    try FileManager.default.createDirectory(at: records, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: records.path)
    let oldAttestation = try attestation(version: "1.0.0", build: 100, marker: "1")
    let newAttestation = try attestation(version: "1.1.0", build: 110, marker: "2")

    func payload(at bundle: URL) throws -> String {
        try String(
            contentsOf: bundle.appendingPathComponent("nested/payload.txt"),
            encoding: .utf8
        )
    }

    func inspect(_ bundle: URL) throws -> PrivateInstallBundleProof {
        let current = try payload(at: bundle)
        return PrivateInstallBundleProof(
            identity: try PrivateInstallCoordinator.identityForTesting(at: bundle),
            treeSHA256Hex: try PrivateInstallCoordinator.treeSHA256ForTesting(at: bundle),
            attestation: current == "old" ? oldAttestation : newAttestation
        )
    }

    if boundary.recordKind == "abandonment" {
        let preparation = PrivateInstallPreparationJournal(
            nonce: nonce,
            stageLeaf: stage.lastPathComponent,
            preparedAtUnixSeconds: 1_788_221_233,
            originalInstalled: try inspect(installed),
            frozenCandidate: try inspect(candidate)
        )
        try PrivateInstallCoordinator.persistPreparationForTesting(preparation, in: records)
        let abandonment = PrivateInstallAbandonmentJournal(
            nonce: nonce,
            preparedAtUnixSeconds: 1_788_221_234,
            preparation: preparation,
            activeInstalled: preparation.originalInstalled,
            opaqueStage: nil
        )
        try PrivateInstallCoordinator.persistAbandonmentForTesting(
            abandonment,
            in: records,
            boundaryHook: {
                stopAtRecordBoundary(boundary, kind: "abandonment", reached: $0)
            }
        )
        fail("the selected abandonment persistence boundary was not reached")
    }

    let hooks = PrivateInstallCoordinatorHooks(
        proveApplicationsStopped: {},
        inspectInstalled: { try inspect(installed) },
        inspectCandidate: { try inspect(candidate) },
        stageCandidate: {
            try FileManager.default.copyItem(at: candidate, to: stage)
        },
        inspectStage: { try inspect(stage) },
        invokeAtomicSwap: { expectedCurrent, expectedStage, _ in
            if boundary.lifecycleOperation == .cancelOriginalActive {
                throw PrivateInstallCoordinatorError.helperFailed
            }
            guard try PrivateInstallCoordinator.identityForTesting(at: installed) == expectedCurrent,
                  try PrivateInstallCoordinator.identityForTesting(at: stage) == expectedStage else {
                throw ProbeError.fixtureFailure
            }
            let descriptor = Darwin.open(
                root.path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard descriptor >= 0 else { throw ProbeError.fixtureFailure }
            defer { _ = Darwin.close(descriptor) }
            guard installed.lastPathComponent.withCString({ installedPointer in
                stage.lastPathComponent.withCString { stagePointer in
                    renameatx_np(
                        descriptor,
                        installedPointer,
                        descriptor,
                        stagePointer,
                        UInt32(RENAME_SWAP)
                    )
                }
            }) == 0,
            Darwin.fsync(descriptor) == 0 else {
                throw ProbeError.fixtureFailure
            }
        },
        postInstallBoundary: {
            stopAt(boundary, .afterSwap)
        },
        persistPreparation: { preparation in
            try PrivateInstallCoordinator.persistPreparationForTesting(
                preparation,
                in: records,
                boundaryHook: {
                    stopAtRecordBoundary(boundary, kind: "preparation", reached: $0)
                }
            )
        },
        persistJournal: { journal in
            try PrivateInstallCoordinator.persistJournalForTesting(
                journal,
                in: records,
                boundaryHook: {
                    stopAtRecordBoundary(boundary, kind: "journal", reached: $0)
                }
            )
            stopAt(boundary, .afterJournal)
        },
        persistReceipt: { receipt in
            try PrivateInstallCoordinator.persistReceiptForTesting(
                receipt,
                in: records,
                boundaryHook: {
                    stopAtRecordBoundary(boundary, kind: "receipt", reached: $0)
                }
            )
            stopAt(boundary, .afterReceipt)
        },
        nowUnixSeconds: { 1_788_221_234 }
    )
    if boundary.lifecycleOperation == .cancelOriginalActive {
        do {
            _ = try PrivateInstallCoordinator.perform(nonce: nonce, hooks: hooks)
            throw ProbeError.fixtureFailure
        } catch let error as PrivateInstallCoordinatorError {
            guard error == .helperFailed else { throw error }
        }
    } else {
        _ = try PrivateInstallCoordinator.perform(nonce: nonce, hooks: hooks)
    }

    if let operation = boundary.lifecycleOperation {
        let archiveDisposition = operation == .cancelOriginalActive ? "cancelled" : "retired"
        let archiveLeaf = ".Fulmar.private-\(archiveDisposition).\(nonce).app"
        let archive = root.appendingPathComponent(archiveLeaf, isDirectory: true)
        let recordArchive = root.appendingPathComponent(
            "records.\(archiveDisposition).\(nonce)",
            isDirectory: true
        )

        func exists(_ url: URL) -> Bool {
            var metadata = stat()
            return lstat(url.path, &metadata) == 0
        }

        let recoveryHooks = PrivateInstallRecoveryHooks(
            loadJournal: {
                guard exists(records) else { return nil }
                return try PrivateInstallCoordinator.readJournalForTesting(in: records)
            },
            loadReceipt: {
                guard exists(records) else { return nil }
                return try PrivateInstallCoordinator.readReceiptForTesting(in: records)
            },
            loadLifecycleJournal: {
                guard exists(records) else { return nil }
                return try PrivateInstallCoordinator.readLifecycleJournalForTesting(in: records)
            },
            stageLeaves: { exists(stage) ? [stage.lastPathComponent] : [] },
            archiveLeaves: { exists(archive) ? [archiveLeaf] : [] },
            inspectInstalled: { try inspect(installed) },
            inspectStage: { _ in try inspect(stage) },
            inspectArchive: { _ in try inspect(archive) },
            inspectCandidateIfPresent: { try inspect(candidate) },
            proveApplicationsStopped: {},
            invokeAtomicSwap: { _, _, _ in throw ProbeError.fixtureFailure },
            persistReceipt: { receipt in
                try PrivateInstallCoordinator.persistReceiptForTesting(receipt, in: records)
            },
            persistLifecycleJournal: { lifecycle in
                try PrivateInstallCoordinator.persistLifecycleJournalForTesting(
                    lifecycle,
                    in: records,
                    boundaryHook: {
                        stopAtRecordBoundary(boundary, kind: "lifecycle", reached: $0)
                    }
                )
                if operation == .cancelOriginalActive {
                    stopAt(boundary, .afterCancelMarker)
                } else {
                    stopAt(boundary, .afterRetireMarker)
                }
            },
            archiveStage: { stageLeaf, destinationLeaf, expected in
                guard stageLeaf == stage.lastPathComponent,
                      destinationLeaf == archiveLeaf,
                      try inspect(stage) == expected else {
                    throw ProbeError.fixtureFailure
                }
                let descriptor = Darwin.open(
                    root.path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
                guard descriptor >= 0 else { throw ProbeError.fixtureFailure }
                defer { _ = Darwin.close(descriptor) }
                guard stageLeaf.withCString({ sourcePointer in
                    destinationLeaf.withCString { destinationPointer in
                        renameatx_np(
                            descriptor,
                            sourcePointer,
                            descriptor,
                            destinationPointer,
                            UInt32(RENAME_EXCL)
                        )
                    }
                }) == 0,
                Darwin.fsync(descriptor) == 0,
                try inspect(archive) == expected else {
                    throw ProbeError.fixtureFailure
                }
                if operation == .cancelOriginalActive {
                    stopAt(boundary, .afterCancelStageArchive)
                } else {
                    stopAt(boundary, .afterRetireStageArchive)
                }
            },
            proveArchiveDurable: { _, expected in
                guard try inspect(archive) == expected else {
                    throw ProbeError.fixtureFailure
                }
                let descriptor = Darwin.open(
                    root.path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
                guard descriptor >= 0 else { throw ProbeError.fixtureFailure }
                defer { _ = Darwin.close(descriptor) }
                guard Darwin.fsync(descriptor) == 0 else {
                    throw ProbeError.fixtureFailure
                }
            },
            archiveRecordDirectory: { lifecycle in
                guard try PrivateInstallCoordinator.readLifecycleJournalForTesting(
                    in: records
                ) == lifecycle else {
                    throw ProbeError.fixtureFailure
                }
                let descriptor = Darwin.open(
                    root.path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
                guard descriptor >= 0 else { throw ProbeError.fixtureFailure }
                defer { _ = Darwin.close(descriptor) }
                guard records.lastPathComponent.withCString({ sourcePointer in
                    recordArchive.lastPathComponent.withCString { destinationPointer in
                        renameatx_np(
                            descriptor,
                            sourcePointer,
                            descriptor,
                            destinationPointer,
                            UInt32(RENAME_EXCL)
                        )
                    }
                }) == 0,
                Darwin.fsync(descriptor) == 0 else {
                    throw ProbeError.fixtureFailure
                }
                if operation == .cancelOriginalActive {
                    stopAt(boundary, .afterCancelRecordArchive)
                } else {
                    stopAt(boundary, .afterRetireRecordArchive)
                }
            },
            nowUnixSeconds: { 1_788_221_236 }
        )
        _ = try PrivateInstallCoordinator.performLifecycle(
            operation: operation,
            hooks: recoveryHooks
        )
    }
    fail("the selected SIGKILL boundary was not reached")
} catch {
    fail("fixture execution failed")
}
