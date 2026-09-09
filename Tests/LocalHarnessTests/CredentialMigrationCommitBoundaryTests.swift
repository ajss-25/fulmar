import Darwin
import Foundation
@testable import LocalHarnessCredentialSecurity
import Testing

private enum SimulatedCommitBoundaryFailure: Error, Equatable {
    case truncate
    case synchronize
    case hardKill(CredentialMigrationCommitCheckpoint)
}

private struct CredentialCommitBoundaryFixture {
    let root: URL
    let source: URL
    let store: CredentialMigrationReceiptStore
    let receipt: CredentialMigrationReceipt

    init(_ label: String) throws {
        root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-commit-\(label)-\(UUID().uuidString)", isDirectory: true)
        guard mkdir(root.path, 0o700) == 0 else {
            throw SimulatedCommitBoundaryFailure.truncate
        }
        source = root.appendingPathComponent("source", isDirectory: false)
        try Data("legacy-plaintext-canary".utf8).write(to: source, options: .withoutOverwriting)
        #expect(chmod(source.path, 0o600) == 0)
        store = try CredentialMigrationReceiptStore(
            directory: root,
            authenticationKey: Data(repeating: 0x7c, count: 32)
        )
        receipt = CredentialMigrationReceipt(
            phase: .prepared,
            sourceDevice: 1,
            sourceInode: 2,
            sourceSize: 23,
            sourceSHA256: String(repeating: "a", count: 64),
            references: 1,
            records: 0,
            entries: [CredentialMigrationReceiptEntry(
                account: "ref:COMMIT_TEST",
                kind: "reference",
                valueSHA256: String(repeating: "b", count: 64)
            )]
        )
    }

    func remove() { try? FileManager.default.removeItem(at: root) }

    func descriptor() throws -> Int32 {
        let descriptor = open(source.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw SimulatedCommitBoundaryFailure.truncate }
        return descriptor
    }
}

struct CredentialMigrationCommitBoundaryTests {
    @Test func killAfterDurablePreparedReceiptNeverScrubsOrCommits() throws {
        let fixture = try CredentialCommitBoundaryFixture("prepared-kill")
        defer { fixture.remove() }
        var truncateCalled = false
        #expect(throws: SimulatedCommitBoundaryFailure.hardKill(.preparedReceiptDurable)) {
            _ = try CredentialMigrationCommitBoundary.commit(
                receiptStore: fixture.store,
                preparedReceipt: fixture.receipt,
                validateBeforeScrub: {},
                truncate: { truncateCalled = true },
                synchronizeAndValidateScrubbedSource: {},
                checkpoint: { reached in
                    if reached == .preparedReceiptDurable {
                        throw SimulatedCommitBoundaryFailure.hardKill(reached)
                    }
                }
            )
        }
        #expect(!truncateCalled)
        #expect(try Data(contentsOf: fixture.source) == Data("legacy-plaintext-canary".utf8))
        #expect(try fixture.store.read()?.phase == .prepared)
    }

    @Test func truncateFailureRemainsReversibleWithPreparedReceiptAndPlaintext() throws {
        let fixture = try CredentialCommitBoundaryFixture("truncate-failure")
        defer { fixture.remove() }
        let descriptor = try fixture.descriptor()
        defer { _ = close(descriptor) }
        #expect(throws: SimulatedCommitBoundaryFailure.truncate) {
            _ = try CredentialMigrationCommitBoundary.commit(
                receiptStore: fixture.store,
                preparedReceipt: fixture.receipt,
                validateBeforeScrub: {},
                truncate: { throw SimulatedCommitBoundaryFailure.truncate },
                synchronizeAndValidateScrubbedSource: {}
            )
        }
        #expect(try Data(contentsOf: fixture.source) == Data("legacy-plaintext-canary".utf8))
        #expect(try fixture.store.read()?.phase == .prepared)
    }

    @Test func fsyncFailureAfterTruncateRequiresRecoveryAndNeverUnwinds() throws {
        let fixture = try CredentialCommitBoundaryFixture("fsync-failure")
        defer { fixture.remove() }
        let descriptor = try fixture.descriptor()
        defer { _ = close(descriptor) }
        let outcome = try CredentialMigrationCommitBoundary.commit(
            receiptStore: fixture.store,
            preparedReceipt: fixture.receipt,
            validateBeforeScrub: {},
            truncate: {
                guard ftruncate(descriptor, 0) == 0 else {
                    throw SimulatedCommitBoundaryFailure.truncate
                }
            },
            synchronizeAndValidateScrubbedSource: {
                throw SimulatedCommitBoundaryFailure.synchronize
            }
        )
        #expect(outcome == .recoveryRequired)
        #expect(try Data(contentsOf: fixture.source).isEmpty)
        #expect(try fixture.store.read()?.phase == .prepared)
    }

    @Test func hardKillAtEveryPostTruncatePhaseHasDeterministicReceiptRecovery() throws {
        for checkpoint in [
            CredentialMigrationCommitCheckpoint.sourceTruncated,
            .sourceSynchronized,
            .scrubbedReceiptDurable,
        ] {
            let fixture = try CredentialCommitBoundaryFixture("kill-\(checkpoint.rawValue)")
            defer { fixture.remove() }
            let descriptor = try fixture.descriptor()
            defer { _ = close(descriptor) }
            let outcome = try CredentialMigrationCommitBoundary.commit(
                receiptStore: fixture.store,
                preparedReceipt: fixture.receipt,
                validateBeforeScrub: {},
                truncate: {
                    guard ftruncate(descriptor, 0) == 0 else {
                        throw SimulatedCommitBoundaryFailure.truncate
                    }
                },
                synchronizeAndValidateScrubbedSource: {
                    guard fsync(descriptor) == 0 else {
                        throw SimulatedCommitBoundaryFailure.synchronize
                    }
                },
                checkpoint: { reached in
                    if reached == checkpoint {
                        throw SimulatedCommitBoundaryFailure.hardKill(reached)
                    }
                }
            )
            #expect(outcome == .recoveryRequired)
            #expect(try Data(contentsOf: fixture.source).isEmpty)
            let retained = try #require(try fixture.store.read())
            if checkpoint == .scrubbedReceiptDurable {
                #expect(retained.phase == .scrubbed)
            } else {
                #expect(retained.phase == .prepared)
                let finalized = try CredentialMigrationCommitBoundary.finalizePreparedReceipt(
                    retained,
                    receiptStore: fixture.store,
                    synchronizeAndValidateScrubbedSource: {
                        guard fsync(descriptor) == 0 else {
                            throw SimulatedCommitBoundaryFailure.synchronize
                        }
                    }
                )
                #expect(finalized.phase == .scrubbed)
            }
            #expect(try fixture.store.read()?.phase == .scrubbed)
        }
    }

    @Test func replyLossRetryObservesAlreadyScrubbedAuthenticatedReceipt() throws {
        let fixture = try CredentialCommitBoundaryFixture("reply-loss")
        defer { fixture.remove() }
        let descriptor = try fixture.descriptor()
        defer { _ = close(descriptor) }
        #expect(try CredentialMigrationCommitBoundary.commit(
            receiptStore: fixture.store,
            preparedReceipt: fixture.receipt,
            validateBeforeScrub: {},
            truncate: {
                guard ftruncate(descriptor, 0) == 0 else {
                    throw SimulatedCommitBoundaryFailure.truncate
                }
            },
            synchronizeAndValidateScrubbedSource: {
                guard fsync(descriptor) == 0 else {
                    throw SimulatedCommitBoundaryFailure.synchronize
                }
            }
        ) == .success)

        let retryReceipt = try #require(try fixture.store.read())
        var unexpectedFinalize = false
        let finalized = try CredentialMigrationCommitBoundary.finalizePreparedReceipt(
            retryReceipt,
            receiptStore: fixture.store,
            synchronizeAndValidateScrubbedSource: { unexpectedFinalize = true }
        )
        #expect(finalized.phase == .scrubbed)
        #expect(!unexpectedFinalize)
    }
}
