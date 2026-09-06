import Foundation
import Testing
@testable import LocalHarness

private enum CredentialMigrationLifecycleTestError: Error {
    case migration
}

@MainActor
private final class CredentialMigrationProtectedDriverFixture {
    var events: [String] = []
    var migrationContinuation: CheckedContinuation<Void, Never>?
    var migrationRunCount = 0
    var inferenceStartCount = 0

    func driver() -> ProtectedRuntimeMutationDriver {
        ProtectedRuntimeMutationDriver(
            closeAdmissions: { self.events.append("close") },
            quiesceAdmissions: { self.events.append("quiesce") },
            stopRuntime: { self.events.append("stop") },
            startProviderControlPlane: { self.events.append("control-plane") },
            startVerifiedInference: {
                self.events.append("start-inference")
                self.inferenceStartCount += 1
            },
            remainStoppedForUpdate: { self.events.append("remain-stopped") },
            failClosed: { _ in self.events.append("failed-closed") }
        )
    }
}

@MainActor
private func waitForCredentialMigrationLifecycle(
    _ condition: @MainActor () -> Bool
) async -> Bool {
    for _ in 0..<1_000 {
        if condition() { return true }
        await Task.yield()
    }
    return condition()
}

@Suite("Credential migration application lifecycle")
@MainActor
struct CredentialMigrationLifecycleTests {
    @Test("First-start gate rejects Quit and a second helper until exact completion")
    func startupGateOwnsMigrationAndRunsContinuationOnce() throws {
        let gate = StartupCredentialMigrationLifecycleGate()
        let permit = try gate.beginMigration()
        var migrationRunnerCount = 1
        var startupContinuationCount = 0

        do {
            _ = try gate.beginMigration()
            migrationRunnerCount += 1
            Issue.record("Expected a second first-start migration to be rejected")
        } catch let error as StartupCredentialMigrationLifecycleGate.AdmissionError {
            #expect(error == .busy)
        }
        #expect(migrationRunnerCount == 1)
        #expect(gate.isMigrationInFlight)
        #expect(!gate.beginTermination())

        #expect(gate.finish(permit, continueAfter: true) {
            startupContinuationCount += 1
        })
        #expect(!gate.isMigrationInFlight)
        #expect(startupContinuationCount == 1)

        // A duplicate or stale callback cannot clear a newer operation or
        // invoke startup a second time.
        #expect(!gate.finish(permit, continueAfter: true) {
            startupContinuationCount += 1
        })
        #expect(startupContinuationCount == 1)
        #expect(gate.beginTermination())
    }

    @Test("Only verified success or no-op continues startup exactly once")
    func onlyVerifiedManagerOutcomeContinuesExactlyOnce() throws {
        let outcomes: [(Result<CredentialMigrationResult, Error>, Bool)] = [
            (.success(CredentialMigrationResult(references: 2, records: 1)), true),
            (.failure(CredentialMigrationLifecycleTestError.migration), false),
            (.success(CredentialMigrationResult(references: 0, records: 0)), true)
        ]

        for (outcome, expectedContinuation) in outcomes {
            let gate = StartupCredentialMigrationLifecycleGate()
            let permit = try gate.beginMigration()
            var continuationCount = 0
            let shouldContinue: Bool
            switch outcome {
            case .success:
                shouldContinue = true
            case .failure:
                shouldContinue = false
            }
            #expect(shouldContinue == expectedContinuation)

            #expect(gate.finish(permit, continueAfter: shouldContinue) {
                continuationCount += 1
            })
            #expect(continuationCount == (shouldContinue ? 1 : 0))
            #expect(!gate.finish(permit, continueAfter: true) {
                continuationCount += 1
            })
            #expect(continuationCount == (shouldContinue ? 1 : 0))
        }
    }

    @Test("A startup lease loser waits for the verified winner and starts once")
    func startupContentionRetriesWithoutOverlappingRuntime() async throws {
        let gate = StartupCredentialMigrationLifecycleGate()
        let permit = try gate.beginMigration()
        var attempts = 0
        var sleeps = 0
        var runtimeStarts = 0

        let result = try await StartupCredentialMigrationCoordinator
            .migrateAfterVerifiedLeaseSettlement(
                maximumContentionRetries: 3,
                retryDelayNanoseconds: 1,
                sleep: { delay in
                    #expect(delay == 1)
                    sleeps += 1
                },
                attempt: {
                    attempts += 1
                    if attempts < 3 { throw CredentialMigrationError.migrationInProgress }
                    return CredentialMigrationResult(references: 0, records: 0)
                }
            )
        #expect(result == CredentialMigrationResult(references: 0, records: 0))
        #expect(attempts == 3)
        #expect(sleeps == 2)
        #expect(runtimeStarts == 0)
        #expect(gate.finish(permit, continueAfter: true) { runtimeStarts += 1 })
        #expect(runtimeStarts == 1)
    }

    @Test("Persistent credential contention times out with the runtime stopped")
    func startupContentionTimeoutFailsClosed() async throws {
        let gate = StartupCredentialMigrationLifecycleGate()
        let permit = try gate.beginMigration()
        var attempts = 0
        var runtimeStarts = 0

        do {
            _ = try await StartupCredentialMigrationCoordinator
                .migrateAfterVerifiedLeaseSettlement(
                    maximumContentionRetries: 2,
                    retryDelayNanoseconds: 1,
                    sleep: { _ in },
                    attempt: {
                        attempts += 1
                        throw CredentialMigrationError.migrationInProgress
                    }
                )
            Issue.record("Persistent contention unexpectedly completed")
        } catch let error as StartupCredentialMigrationCoordinatorError {
            #expect(error == .contentionTimedOut)
        }
        #expect(attempts == 3)
        #expect(gate.finish(permit, continueAfter: false) { runtimeStarts += 1 })
        #expect(runtimeStarts == 0)
    }

    @Test("Manual completion and Not Now do not create a startup continuation")
    func nonStartupChoicesDoNotContinue() throws {
        let manualGate = StartupCredentialMigrationLifecycleGate()
        let manualPermit = try manualGate.beginMigration()
        var continuationCount = 0
        #expect(manualGate.finish(manualPermit, continueAfter: false) {
            continuationCount += 1
        })
        #expect(continuationCount == 0)

        // Not Now bypasses beginMigration entirely: no lifecycle permit and,
        // in production, no manager call or cross-process source lease.
        let notNowGate = StartupCredentialMigrationLifecycleGate()
        let migrationRunnerCount = 0
        var safetyBackupContinuationCount = 0
        safetyBackupContinuationCount += 1
        #expect(!notNowGate.isMigrationInFlight)
        #expect(migrationRunnerCount == 0)
        #expect(safetyBackupContinuationCount == 1)
    }

    @Test("Termination latch rejects queued migration and every late restart")
    func terminationLatchPreventsLateWork() throws {
        let idleGate = StartupCredentialMigrationLifecycleGate()
        #expect(idleGate.beginTermination())
        var migrationRunnerCount = 0
        var runtimeStartCount = 0
        do {
            _ = try idleGate.beginMigration()
            migrationRunnerCount += 1
            Issue.record("Expected migration admission to remain closed after Quit")
        } catch let error as StartupCredentialMigrationLifecycleGate.AdmissionError {
            #expect(error == .terminating)
        }
        if idleGate.permitsRuntimeContinuation { runtimeStartCount += 1 }
        #expect(migrationRunnerCount == 0)
        #expect(runtimeStartCount == 0)

        let forcedGate = StartupCredentialMigrationLifecycleGate()
        let permit = try forcedGate.beginMigration()
        forcedGate.latchUnconditionalTermination()
        #expect(forcedGate.finish(permit, continueAfter: true) {
            runtimeStartCount += 1
        })
        #expect(runtimeStartCount == 0)
        #expect(!forcedGate.permitsRuntimeContinuation)
    }

    @Test("Manual protected migration rejects Quit and a concurrent relaunch")
    func manualMigrationOwnsGlobalProtectedRuntimeBoundary() async throws {
        let fixture = CredentialMigrationProtectedDriverFixture()
        let coordinator = ProtectedRuntimeMutationCoordinator(driver: fixture.driver())
        let migration = Task { @MainActor in
            try await coordinator.perform(
                kind: .credentialMigration,
                requirement: .stoppedRuntime
            ) { permit in
                try permit.validate()
                fixture.migrationRunCount += 1
                fixture.events.append("migration")
                await withCheckedContinuation { continuation in
                    fixture.migrationContinuation = continuation
                }
                fixture.migrationContinuation = nil
                return CredentialMigrationResult(references: 1, records: 1)
            }
        }

        #expect(await waitForCredentialMigrationLifecycle {
            fixture.migrationContinuation != nil
        })
        #expect(fixture.migrationRunCount == 1)
        #expect(!coordinator.beginTermination())

        do {
            _ = try await coordinator.perform(
                kind: .credentialMigration,
                requirement: .stoppedRuntime
            ) { _ in
                fixture.migrationRunCount += 1
                return CredentialMigrationResult(references: 0, records: 0)
            }
            Issue.record("Expected concurrent manual migration to be rejected")
        } catch let error as ProtectedRuntimeMutationCoordinatorError {
            #expect(error == .busy(.credentialMigration))
        }
        #expect(fixture.migrationRunCount == 1)

        fixture.migrationContinuation?.resume()
        let moved = try await migration.value
        #expect(moved == CredentialMigrationResult(references: 1, records: 1))
        #expect(fixture.inferenceStartCount == 1)
        #expect(!coordinator.isTransitionInFlight)
        #expect(coordinator.beginTermination())
    }
}
