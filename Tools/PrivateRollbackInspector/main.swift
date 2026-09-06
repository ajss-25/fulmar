import Darwin
import Foundation
import LocalHarnessPrivateInstallCoordinator

private func writeAll(_ message: String, descriptor: Int32) {
    let bytes = Array(message.utf8)
    bytes.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let count = Darwin.write(
                descriptor,
                buffer.baseAddress?.advanced(by: offset),
                buffer.count - offset
            )
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else {
                return
            }
        }
    }
}

private func safeDisplayVersion(_ value: String) -> String {
    let bytes = Array(value.utf8)
    guard !bytes.isEmpty,
          bytes.count <= 128,
          bytes.allSatisfy({ byte in
              (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                  || byte == UInt8(ascii: ".")
                  || byte == UInt8(ascii: "-")
                  || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                  || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
          }) else {
        return "unavailable"
    }
    return value
}

private enum Command: String {
    case resumeInterrupted = "--resume-interrupted"
    case finalizeInterrupted = "--finalize-interrupted"
    case cancelInterrupted = "--cancel-interrupted"
    case retireCommitted = "--retire-committed"
    case reconcileRecords = "--reconcile-records"
}

private let arguments = Array(CommandLine.arguments.dropFirst())
private let command: Command?
if arguments.isEmpty {
    command = nil
} else if arguments.count == 1, let parsed = Command(rawValue: arguments[0]) {
    command = parsed
} else {
    writeAll(
        "usage: LocalHarnessPrivateRollbackInspectorTool "
            + "[--resume-interrupted|--finalize-interrupted|"
            + "--cancel-interrupted|--retire-committed|--reconcile-records]\n",
        descriptor: STDERR_FILENO
    )
    exit(64)
}

private func reportCommitted(_ inspection: PrivateInstallRecoveryInspection) {
    guard let receipt = inspection.receipt,
          let stagePath = inspection.stagePath else {
        writeAll("Fulmar rollback inspector: invalid committed state.\n", descriptor: STDERR_FILENO)
        exit(2)
    }
    let rollbackVersion = safeDisplayVersion(receipt.retainedRollback.attestation.version)
    let installedVersion = safeDisplayVersion(receipt.installed.attestation.version)
    let candidateDescription = inspection.candidateState == .exact
        ? "present and byte/signature exact"
        : "absent (permitted after installation)"
    writeAll(
        "Retained rollback: Fulmar \(rollbackVersion) "
            + "(\(receipt.retainedRollback.attestation.build))\n"
            + "Path: \(stagePath)\n"
            + "Installed: Fulmar \(installedVersion) "
            + "(\(receipt.installed.attestation.build)), exact to receipt\n"
            + "Frozen candidate: \(candidateDescription)\n"
            + "Receipt: ~/\(PrivateInstallCoordinator.receiptRelativePath)\n"
            + "Recovery journal: "
            + (inspection.journal == nil
                ? "legacy receipt-only transaction\n"
                : "durable and exact\n")
            + "Proof: complete bounded byte tree, bundle identity, strict nested signature, "
            + "CDHash, certificate, designated requirement and bundle metadata all match.\n"
            + "Keep the rollback until several real tasks pass, then run the explicit "
            + "--retire-committed operation. Retirement archives the rollback and records; "
            + "it does not delete them.\n",
        descriptor: STDOUT_FILENO
    )
}

private func reportRecovery(_ inspection: PrivateInstallRecoveryInspection) {
    switch inspection.state {
    case .none:
        writeAll(
            "No active Fulmar private-install transaction is present. "
                + "Previously retired or cancelled archives, if any, are retained on disk.\n",
            descriptor: STDOUT_FILENO
        )
    case .stagingPrepared:
        writeAll(
            "Private install preparation is durable and no stage exists. Run "
                + "--resume-interrupted to repeat proofs and stage, or "
                + "--cancel-interrupted to archive the preparation. Status changed nothing.\n",
            descriptor: STDOUT_FILENO
        )
    case .stagedAwaitingJournal:
        writeAll(
            "The staged candidate is exact and durable, but its final pre-swap journal "
                + "is missing. Run --resume-interrupted to reconstruct the exact journal "
                + "and continue. Status changed nothing.\n",
            descriptor: STDOUT_FILENO
        )
    case .stagingInterrupted:
        writeAll(
            "Staging was interrupted and the opaque stage cannot be trusted or resumed. "
                + "Run --cancel-interrupted to archive it without traversal or deletion. "
                + "Status changed nothing.\n",
            descriptor: STDOUT_FILENO
        )
    case .abandonmentPrepared:
        writeAll(
            "Opaque-stage abandonment is prepared. Run --cancel-interrupted again to "
                + "resume the exact archive-only transaction.\n",
            descriptor: STDOUT_FILENO
        )
    case .abandonmentArchived:
        writeAll(
            "The opaque stage is archived and the retained records still require their "
                + "final exclusive archive. Run --cancel-interrupted again.\n",
            descriptor: STDOUT_FILENO
        )
    case .committed:
        reportCommitted(inspection)
    case .originalActive:
        let candidateDescription = inspection.candidateState == .exact
            ? "present and exact"
            : "absent (the journal and staged copy remain sufficient)"
        writeAll(
            "Interrupted private install: the original Fulmar app is still active and exact.\n"
                + "Staged candidate: \(inspection.stagePath ?? "unavailable")\n"
                + "Frozen candidate: \(candidateDescription)\n"
                + "No swap or receipt is committed. Choose exactly one explicit operation: "
                + "--resume-interrupted to repeat every proof and finish the atomic swap, "
                + "or --cancel-interrupted to archive the staged candidate and records.\n"
                + "This status command changed nothing.\n",
            descriptor: STDOUT_FILENO
        )
    case .swappedAwaitingCommit:
        writeAll(
            "Interrupted private install: the candidate is active and the exact original "
                + "is retained at \(inspection.stagePath ?? "unavailable"), but the durable "
                + "receipt is missing. Run --finalize-interrupted to write only the proven "
                + "receipt. This status command changed nothing.\n",
            descriptor: STDOUT_FILENO
        )
    case .cancellationPrepared, .cancellationArchived:
        writeAll(
            "Explicit cancellation is incomplete. The exact staged candidate is "
                + (inspection.state == .cancellationPrepared
                    ? "still staged at \(inspection.stagePath ?? "unavailable"). "
                    : "archived at \(inspection.archivePath ?? "unavailable"). ")
                + "Run --cancel-interrupted again to resume the same proven archive-only "
                + "transaction. No active app will be removed.\n",
            descriptor: STDOUT_FILENO
        )
    case .retirementPrepared, .retirementArchived:
        writeAll(
            "Explicit rollback retirement is incomplete. The exact rollback is "
                + (inspection.state == .retirementPrepared
                    ? "still staged at \(inspection.stagePath ?? "unavailable"). "
                    : "archived at \(inspection.archivePath ?? "unavailable"). ")
                + "Run --retire-committed again to resume the same proven archive-only "
                + "transaction. The active app is unchanged.\n",
            descriptor: STDOUT_FILENO
        )
    }
}

do {
    switch command {
    case nil:
        reportRecovery(try PrivateInstallCoordinator.inspectProductionRecovery())
    case .resumeInterrupted:
        let receipt = try PrivateInstallCoordinator.resumeProductionInterruptedInstall()
        writeAll(
            "Interrupted install resumed and committed: Fulmar "
                + "\(safeDisplayVersion(receipt.installed.attestation.version)) "
                + "(\(receipt.installed.attestation.build)).\n",
            descriptor: STDOUT_FILENO
        )
    case .finalizeInterrupted:
        let receipt = try PrivateInstallCoordinator.commitProductionInterruptedInstall()
        writeAll(
            "Interrupted install receipt finalized for Fulmar "
                + "\(safeDisplayVersion(receipt.installed.attestation.version)) "
                + "(\(receipt.installed.attestation.build)); no app bundle was moved.\n",
            descriptor: STDOUT_FILENO
        )
    case .cancelInterrupted:
        if let lifecycle = try PrivateInstallCoordinator.cancelProductionInterruptedInstall() {
            writeAll(
                "Interrupted install cancelled safely. The staged candidate and exact records "
                    + "were archived under nonce \(lifecycle.nonce); nothing was deleted.\n",
                descriptor: STDOUT_FILENO
            )
        } else {
            writeAll(
                "No active private-install transaction remains. Any interrupted opaque "
                    + "stage and its exact records were archived without traversal or deletion.\n",
                descriptor: STDOUT_FILENO
            )
        }
    case .retireCommitted:
        if let lifecycle = try PrivateInstallCoordinator.retireProductionCommittedInstall() {
            writeAll(
                "Committed rollback retired safely. The rollback and exact records were "
                    + "archived under nonce \(lifecycle.nonce); nothing was deleted.\n",
                descriptor: STDOUT_FILENO
            )
        } else {
            writeAll("No active private-install transaction; nothing changed.\n", descriptor: STDOUT_FILENO)
        }
    case .reconcileRecords:
        let inspection = try PrivateInstallCoordinator.reconcileProductionInterruptedRecordWrite()
        writeAll(
            "Interrupted record evidence was archived without deletion and the proven "
                + "record state was restored. Current state: \(inspection.state.rawValue).\n",
            descriptor: STDOUT_FILENO
        )
    }
    exit(0)
} catch let error as PrivateInstallCoordinatorError {
    if error == .interruptedRecordWrite {
        writeAll(
            "Fulmar rollback inspector: \(error.localizedDescription) "
                + "Run --reconcile-records explicitly; ambiguous evidence is never deleted.\n",
            descriptor: STDERR_FILENO
        )
        exit(2)
    }
    writeAll("Fulmar rollback inspector: \(error.localizedDescription)\n", descriptor: STDERR_FILENO)
    exit(2)
} catch {
    writeAll(
        "Fulmar rollback inspector: The retained private rollback could not be proven. "
            + "No application data was changed.\n",
        descriptor: STDERR_FILENO
    )
    exit(2)
}
