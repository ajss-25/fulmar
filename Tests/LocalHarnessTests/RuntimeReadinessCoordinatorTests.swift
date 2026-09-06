import Darwin
import Foundation
import Testing
@testable import LocalHarness

private enum BackgroundLifecycleFixtureError: Error {
    case failed
}

private final class BackgroundRecoveryKeyCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var accesses = 0

    func key() -> Data {
        lock.lock()
        accesses += 1
        lock.unlock()
        return Data(repeating: 0x71, count: 32)
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return accesses
    }
}

private actor RuntimeQuiescenceGate {
    private var entered = false
    private var opened = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var openWaiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if !entered {
            entered = true
            let current = entryWaiters
            entryWaiters.removeAll()
            current.forEach { $0.resume() }
        }
        if opened { return }
        await withCheckedContinuation { openWaiters.append($0) }
    }

    func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func open() {
        opened = true
        let current = openWaiters
        openWaiters.removeAll()
        current.forEach { $0.resume() }
    }
}

private actor RuntimeQuiescenceCompletionProbe {
    private var completed = false
    func markCompleted() { completed = true }
    func value() -> Bool { completed }
}

@Test func runtimeAdmissionBarrierWaitsForAllDrainsAndPropagatesHistoryFailure() async throws {
    let schedules = RuntimeQuiescenceGate()
    let conversations = RuntimeQuiescenceGate()
    let history = RuntimeQuiescenceGate()
    let completion = RuntimeQuiescenceCompletionProbe()
    let barrier = RuntimeAdmissionQuiescenceBarrier(
        schedules: { await schedules.wait() },
        conversations: { await conversations.wait() },
        history: {
            await history.wait()
            throw BackgroundLifecycleFixtureError.failed
        }
    )
    let task = Task { () -> Bool in
        do {
            try await barrier.quiesce()
            await completion.markCompleted()
            return false
        } catch is BackgroundLifecycleFixtureError {
            await completion.markCompleted()
            return true
        } catch {
            await completion.markCompleted()
            return false
        }
    }

    await schedules.waitUntilEntered()
    await conversations.waitUntilEntered()
    await history.waitUntilEntered()
    await schedules.open()
    await conversations.open()
    try await Task.sleep(for: .milliseconds(50))
    #expect(!(await completion.value()))

    await history.open()
    #expect(await task.value)
    #expect(await completion.value())
}

@Test func runtimeAdmissionBarrierDoesNotAwaitACancellationIgnoringDrainAfterTimeout() async throws {
    let cancellationIgnoringDrain = RuntimeQuiescenceGate()
    let barrier = RuntimeAdmissionQuiescenceBarrier(
        schedules: { await cancellationIgnoringDrain.wait() },
        conversations: {},
        history: {},
        timeout: 0.05
    )
    let clock = ContinuousClock()
    let started = clock.now
    let operation = Task {
        try await barrier.quiesce()
    }

    await cancellationIgnoringDrain.waitUntilEntered()
    try await operation.value
    let elapsed = started.duration(to: clock.now)
    #expect(elapsed >= .milliseconds(40))
    #expect(elapsed < .seconds(1))

    // Release the deliberately cancellation-ignoring continuation only after
    // proving the barrier returned. The detached drain may settle later, but it
    // can no longer resume or otherwise affect the completed barrier.
    await cancellationIgnoringDrain.open()
}

private struct BackgroundMigrationFixture {
    let root: URL
    let source: URL
    let support: URL
    let manager: StateBackupManager
    let migration: RuntimeMigrationCoordinator

    init() throws {
        guard let account = getpwuid(geteuid()),
              let homePointer = account.pointee.pw_dir else {
            throw CocoaError(.fileNoSuchFile)
        }
        // Device-attestation traversal rejects writable temporary ancestors by
        // design. Use a unique owner-controlled cache root beneath the real
        // account home, matching the same safe-ancestor contract as the live
        // Application Support tree while keeping the fixture disposable.
        let candidateRoot = URL(fileURLWithPath: String(cString: homePointer), isDirectory: true)
            .appendingPathComponent("Library/Caches", isDirectory: true)
            .appendingPathComponent(
                "fulmar-background-lifecycle-\(UUID().uuidString)",
                isDirectory: true
            )
        let candidateSource = candidateRoot.appendingPathComponent("state", isDirectory: true)
        let candidateSupport = candidateRoot.appendingPathComponent("support", isDirectory: true)
        let backups = candidateRoot.appendingPathComponent("backups", isDirectory: true)
        let candidateManager: StateBackupManager
        let candidateMigration: RuntimeMigrationCoordinator
        do {
            try FileManager.default.createDirectory(at: candidateSource, withIntermediateDirectories: true)
            // Production admits and retains the owner-only Application Support
            // root before RuntimeMigrationCoordinator performs its signed-marker
            // background preflight. Model that prerequisite explicitly: treating
            // a missing support root as an ordinary migration fixture is stale and
            // correctly fails closed as unsafe storage.
            try FileManager.default.createDirectory(at: candidateSupport, withIntermediateDirectories: true)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateRoot.path
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateSource.path
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateSupport.path
            )
            try writeCurrentProviderHistoryPrivacyReceipt(at: candidateSource)
            try Data("reviewed-state".utf8).write(
                to: candidateSource.appendingPathComponent("session.json")
            )
            candidateManager = StateBackupManager(
                applicationSupport: candidateSupport,
                sourceState: candidateSource,
                backupRoot: backups,
                authenticationKey: Data(repeating: 0x6A, count: 32),
                allowUnattestedHarnessHomeForTesting: true
            )
            candidateMigration = RuntimeMigrationCoordinator(
                applicationSupport: candidateSupport,
                backupManager: candidateManager,
                attestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
            )
        } catch {
            try? FileManager.default.removeItem(at: candidateRoot)
            throw error
        }
        root = candidateRoot
        source = candidateSource
        support = candidateSupport
        manager = candidateManager
        migration = candidateMigration
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private func backgroundPreparation(
    _ preparation: RuntimeLaunchPreparation,
    version: String
) -> BackgroundRuntimeMigrationPreparation {
    switch preparation {
    case .current:
        return .current(version: version)
    case .backupCreated:
        return .backupCreated(version: version)
    case .recoveryNeeded(let backup):
        return .recoveryNeeded(version: version, backupID: backup.id)
    }
}

@Test @MainActor
func backgroundHomePreflightCompletesBeforeMigrationAndRuntimeLaunch() throws {
    var trace: [String] = []
    var settlePreflight: ((Result<Void, Error>) -> Void)?
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        preflightHarnessHome: { completion in
            trace.append("preflight")
            settlePreflight = completion
        },
        prepareMigration: { completion in
            trace.append("migration")
            completion(.success(.current(version: "1")))
        },
        launchRuntime: { trace.append("launch") },
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected migration recovery") },
        probe: { _ in },
        reportIdentityReady: {},
        verifyTopology: { _, _ in },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { false },
        runDueSchedules: {},
        stopRuntime: { _ in },
        exitApplication: { trace.append("exit") }
    )

    coordinator.prepareAndLaunch()
    #expect(trace == ["preflight"])
    #expect(coordinator.phase == .preflightingHarnessHome)
    let completion = try #require(settlePreflight)
    completion(.success(()))
    #expect(trace == ["preflight", "migration", "launch"])
    #expect(coordinator.phase == .waitingForRuntimeStart)
}

@Test @MainActor
func interruptedHomePreflightSignalsActivityAndNotificationBeforeSingleExit() throws {
    let migrationFixture = try BackgroundMigrationFixture()
    defer { migrationFixture.cleanup() }
    let homeParent = migrationFixture.root.appendingPathComponent(
        "home-support",
        isDirectory: true
    )
    let home = homeParent.appendingPathComponent("HarnessHome", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: homeParent.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    try Data("source".utf8).write(to: home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x70, count: 32)
    let interrupted = HarnessHomeManager(
        root: home,
        legacyRoot: homeParent.appendingPathComponent("missing-legacy", isDirectory: true),
        recoveryAuthenticationKey: key,
        receiptlessRecoveryCrashHook: { $0 == .journalPrepared }
    )
    let request: HarnessHomeReceiptlessRecoveryRequest
    do {
        try interrupted.prepare()
        Issue.record("Expected initial receiptless recovery")
        return
    } catch HarnessHomeError.receiptlessRecoveryRequired(let pending) {
        request = pending
    }
    #expect(throws: HarnessHomeReceiptlessRecoveryTestInterruption.simulatedCrash(.journalPrepared)) {
        try interrupted.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    }

    let keyAccess = BackgroundRecoveryKeyCounter()
    let preflight = HarnessHomeManager(
        root: home,
        legacyRoot: homeParent.appendingPathComponent("missing-legacy", isDirectory: true),
        recoveryAuthenticationKeyProvider: { keyAccess.key() }
    )
    var trace: [String] = []
    var migrationCalls = 0
    var runtimeLaunches = 0
    var catalogCommits = 0
    var exits = 0
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        preflightHarnessHome: { completion in
            trace.append("preflight")
            do {
                _ = try preflight.preflightHarnessHomeRecovery()
                completion(.success(()))
            } catch {
                // Models the production controller/App ordering: the pending
                // callback persists its activity and dispatches notification
                // before the preflight completion can authorize process exit.
                trace.append("activity")
                trace.append("notification")
                completion(.failure(error))
            }
        },
        prepareMigration: { completion in
            migrationCalls += 1
            let result = Result {
                try migrationFixture.migration.prepare(targetVersion: "version-mismatch")
            }.map { backgroundPreparation($0, version: "version-mismatch") }
            completion(result)
        },
        launchRuntime: { runtimeLaunches += 1 },
        recordRecoveryNeeded: { _, _ in Issue.record("Migration must remain unopened") },
        probe: { _ in Issue.record("Runtime probe must remain unopened") },
        reportIdentityReady: { Issue.record("Runtime identity must remain unpublished") },
        verifyTopology: { _, _ in Issue.record("Topology must remain unopened") },
        markMigrationReady: { _ in
            catalogCommits += 1
            return .success(())
        },
        promoteToFullInference: { false },
        runDueSchedules: { Issue.record("Schedules must remain stopped") },
        stopRuntime: { _ in Issue.record("No runtime exists to stop") },
        exitApplication: {
            exits += 1
            trace.append("exit")
        }
    )

    coordinator.prepareAndLaunch()
    coordinator.prepareAndLaunch()
    #expect(trace == ["preflight", "activity", "notification", "exit"])
    #expect(exits == 1)
    #expect(migrationCalls == 0)
    #expect(runtimeLaunches == 0)
    #expect(catalogCommits == 0)
    #expect(keyAccess.count == 0)
    #expect(try migrationFixture.manager.list().isEmpty)
    #expect(coordinator.phase == .finished)
}

@Test @MainActor
func firstBackgroundLaunchAfterVersionChangeBacksUpVerifiesMarksReadyRunsAndStopsExactly() throws {
    let fixture = try BackgroundMigrationFixture()
    defer { fixture.cleanup() }
    let homeSupport = fixture.root.appendingPathComponent("valid-home-support", isDirectory: true)
    let harnessHome = homeSupport.appendingPathComponent("HarnessHome", isDirectory: true)
    let homeManager = HarnessHomeManager(
        root: harnessHome,
        legacyRoot: homeSupport.appendingPathComponent("missing-legacy", isDirectory: true),
        recoveryAuthenticationKey: Data(repeating: 0x72, count: 32)
    )
    try homeManager.prepare()
    let disposable = harnessHome.appendingPathComponent(
        "Temp/dsh-spill-preflight-order",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: disposable, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: disposable.path)
    let version = "9.7.1"
    let generation = UUID()
    var trace: [String] = []
    var probeResults = [false, true]
    var probeCount = 0
    var scheduled: [() -> Void] = []
    var stopReply: ((Result<Void, Error>) -> Void)?

    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 3,
        delay: 1,
        preflightHarnessHome: { completion in
            trace.append("home-preflight")
            completion(Result { _ = try homeManager.preflightHarnessHomeRecovery() })
        },
        prepareMigration: { completion in
            trace.append("migration-prepare")
            do {
                let prepared = try fixture.migration.prepare(targetVersion: version)
                completion(.success(backgroundPreparation(prepared, version: version)))
            } catch {
                let supportEntries = (try? FileManager.default.contentsOfDirectory(
                    atPath: fixture.support.path
                ).sorted()) ?? ["<unreadable>"]
                Issue.record("Background migration preparation unexpectedly failed as \(String(reflecting: type(of: error))): \(error); support entries: \(supportEntries)")
                completion(.failure(error))
            }
        },
        launchRuntime: {
            trace.append("launch-runtime")
            do { try homeManager.prepare() }
            catch { Issue.record("Full home preparation should succeed after backup: \(error)") }
        },
        recordRecoveryNeeded: { _, _ in trace.append("unexpected-recovery") },
        probe: { completion in
            trace.append("probe-identity")
            probeCount += 1
            guard let result = probeResults.first else {
                Issue.record("Unexpected identity probe \(probeCount) after the bounded fixture was exhausted")
                completion(false)
                return
            }
            probeResults.removeFirst()
            completion(result)
        },
        schedule: { _, action in
            trace.append("retry-scheduled")
            scheduled.append(action)
        },
        reportIdentityReady: { trace.append("publish-ready") },
        verifyTopology: { suppliedGeneration, completion in
            #expect(suppliedGeneration == generation)
            trace.append("verify-topology")
            completion(.success(()))
        },
        markMigrationReady: { suppliedVersion in
            trace.append("mark-migration-ready")
            return Result { try fixture.migration.markReady(version: suppliedVersion) }
        },
        promoteToFullInference: {
            trace.append("promote-inference")
            return true
        },
        runDueSchedules: { trace.append("run-due") },
        stopRuntime: { completion in
            trace.append("stop-began")
            stopReply = completion
        },
        exitApplication: { trace.append("exit") }
    )

    coordinator.prepareAndLaunch()
    #expect(trace == ["home-preflight", "migration-prepare", "launch-runtime"])
    #expect(!FileManager.default.fileExists(atPath: disposable.path))
    coordinator.runtimeStarted(generation: generation)
    #expect(trace == [
        "home-preflight", "migration-prepare", "launch-runtime", "probe-identity", "retry-scheduled"
    ])

    let scheduledRetry = try #require(scheduled.first)
    scheduledRetry()
    #expect(Array(trace.suffix(2)) == ["mark-migration-ready", "publish-ready"])
    #expect(probeCount == 2)
    #expect(probeResults.isEmpty)
    #expect(coordinator.phase == .waitingForReadyPublication(generation: generation))

    // A publication from any replacement generation is inert.
    coordinator.runtimePublishedReady(generation: UUID())
    #expect(trace.last == "publish-ready")
    coordinator.runtimePublishedReady(generation: generation)
    #expect(Array(trace.suffix(3)) == [
        "verify-topology", "promote-inference", "run-due"
    ])
    #expect(coordinator.phase == .runningSchedules(generation: generation))

    coordinator.scheduledWorkBecameIdle()
    #expect(trace.last == "stop-began")
    #expect(!trace.contains("exit"))
    #expect(coordinator.phase == .stopping(generation: generation))
    let completion = try #require(stopReply)
    completion(.success(()))
    #expect(trace.last == "exit")
    #expect(coordinator.phase == .finished)

    // Mark-ready was committed after authenticated DSH identity but before
    // provider topology. Provider repair is independent of schema migration,
    // so a later wake creates no second safety snapshot.
    #expect(try fixture.migration.prepare(targetVersion: version) == .current)
}

@Test @MainActor
func duplicateRuntimeAndRetryCallbacksCannotCreateAnExtraIdentityProbe() throws {
    let generation = UUID()
    let replacementGeneration = UUID()
    var probes: [(Bool) -> Void] = []
    var retries: [() -> Void] = []
    var publishedReadyCount = 0
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 2,
        delay: 0,
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: {},
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected recovery") },
        probe: { probes.append($0) },
        schedule: { _, action in retries.append(action) },
        reportIdentityReady: { publishedReadyCount += 1 },
        verifyTopology: { _, _ in Issue.record("Topology is outside this identity-poll fixture") },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { false },
        runDueSchedules: { Issue.record("Schedules are outside this identity-poll fixture") },
        stopRuntime: { _ in Issue.record("The successful bounded poll must not stop the runtime") },
        exitApplication: { Issue.record("The successful bounded poll must not exit") }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    coordinator.runtimeStarted(generation: generation)
    coordinator.runtimeStarted(generation: replacementGeneration)
    #expect(probes.count == 1)

    let firstProbe = try #require(probes.first)
    firstProbe(false)
    firstProbe(false)
    #expect(retries.count == 1)

    let retry = try #require(retries.first)
    retry()
    retry()
    #expect(probes.count == 2)

    let secondProbe = try #require(probes.last)
    secondProbe(true)
    secondProbe(true)
    retry()
    coordinator.runtimeStarted(generation: generation)
    coordinator.runtimeStarted(generation: replacementGeneration)

    #expect(probes.count == 2)
    #expect(publishedReadyCount == 1)
    #expect(coordinator.phase == .waitingForReadyPublication(generation: generation))
}

@Test @MainActor
func pendingLocalThermalAdmissionStopsBackgroundBeforeInferencePromotionOrSchedules() throws {
    let generation = UUID()
    var trace: [String] = []
    var quiescenceReply: ((Result<Void, Error>) -> Void)?
    var stopReply: ((Result<Void, Error>) -> Void)?
    let localBlocked = ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
        localRuntimeSelected: true,
        normalModeRecoveryPending: true,
        phase: .ready,
        memoryPressureBlocksNewLocalGeneration: false
    )
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 1,
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: { trace.append("launch") },
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected recovery") },
        probe: { $0(true) },
        reportIdentityReady: { trace.append("identity-ready") },
        verifyTopology: { suppliedGeneration, completion in
            #expect(suppliedGeneration == generation)
            trace.append("verify-topology")
            completion(.success(()))
        },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: {
            trace.append("promotion-gate")
            return ThermalRuntimeAdmissionPolicy.promoteIfAdmitted(
                selectedLocalRuntimeBlocked: localBlocked
            ) {
                trace.append("inference-promoted")
                return true
            }
        },
        runDueSchedules: { trace.append("schedules-ran") },
        quiesceSchedules: {
            trace.append("quiesce-began")
            quiescenceReply = $0
        },
        stopRuntime: {
            trace.append("stop-began")
            stopReply = $0
        },
        exitApplication: { trace.append("exit") }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    coordinator.runtimePublishedReady(generation: generation)

    #expect(trace == [
        "launch", "identity-ready", "verify-topology", "promotion-gate", "quiesce-began"
    ])
    #expect(!trace.contains("inference-promoted"))
    #expect(!trace.contains("schedules-ran"))
    #expect(coordinator.phase == .quiescingSchedules(generation: generation))

    let settleQuiescence = try #require(quiescenceReply)
    settleQuiescence(.success(()))
    #expect(trace.last == "stop-began")
    #expect(coordinator.phase == .stopping(generation: generation))

    let settleStop = try #require(stopReply)
    settleStop(.success(()))
    #expect(trace.last == "exit")
    #expect(coordinator.phase == .finished)
}

@Test @MainActor
func deferredBackgroundLaunchResumesFromWaitingForRuntimeStart() {
    let generation = UUID()
    var trace: [String] = []
    var probeReply: ((Bool) -> Void)?
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 1,
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: { trace.append("launch-attempt") },
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected recovery") },
        probe: { probeReply = $0 },
        reportIdentityReady: { trace.append("identity-ready") },
        verifyTopology: { _, _ in Issue.record("Topology cannot run before resumed launch is ready") },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { false },
        runDueSchedules: { Issue.record("Schedules cannot run before resumed launch is ready") },
        stopRuntime: { _ in },
        exitApplication: {}
    )

    coordinator.prepareAndLaunch()
    #expect(trace == ["launch-attempt"])
    #expect(coordinator.phase == .waitingForRuntimeStart)
    #expect(coordinator.resumeDeferredRuntimeLaunch())
    #expect(trace == ["launch-attempt", "launch-attempt"])
    #expect(coordinator.phase == .waitingForRuntimeStart)

    coordinator.runtimeStarted(generation: generation)
    #expect(coordinator.phase == .probing(generation: generation, attempt: 1))
    #expect(probeReply != nil)
}

@Test @MainActor
func backgroundMigrationCommitFailureStopsBeforeReadyPublicationOrProviderUse() throws {
    let generation = UUID()
    var stopReply: ((Result<Void, Error>) -> Void)?
    var trace: [String] = []
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 1,
        prepareMigration: { $0(.success(.backupCreated(version: "2.0"))) },
        launchRuntime: { trace.append("launch") },
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected recovery") },
        probe: { $0(true) },
        reportIdentityReady: { trace.append("ready-published") },
        verifyTopology: { _, _ in trace.append("topology") },
        markMigrationReady: { _ in
            trace.append("migration-commit-failed")
            return .failure(BackgroundLifecycleFixtureError.failed)
        },
        promoteToFullInference: {
            trace.append("inference-promoted")
            return true
        },
        runDueSchedules: { trace.append("schedules-ran") },
        stopRuntime: {
            trace.append("stop-began")
            stopReply = $0
        },
        exitApplication: { trace.append("exit") }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)

    #expect(trace == ["launch", "migration-commit-failed", "stop-began"])
    #expect(coordinator.phase == .stopping(generation: generation))
    #expect(!trace.contains("ready-published"))
    #expect(!trace.contains("topology"))
    #expect(!trace.contains("inference-promoted"))
    #expect(!trace.contains("schedules-ran"))
    let completion = try #require(stopReply)
    completion(.success(()))
    #expect(trace.last == "exit")
}

@Test @MainActor
func providerTopologyFailureAfterAuthenticatedIdentityDoesNotBecomeFailedMigration() throws {
    let fixture = try BackgroundMigrationFixture()
    defer { fixture.cleanup() }
    let version = "9.7.3"
    let generation = UUID()
    var stopReply: ((Result<Void, Error>) -> Void)?
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 1,
        prepareMigration: { completion in
            completion(Result {
                backgroundPreparation(
                    try fixture.migration.prepare(targetVersion: version),
                    version: version
                )
            })
        },
        launchRuntime: {},
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected recovery") },
        probe: { $0(true) },
        reportIdentityReady: {},
        verifyTopology: { _, completion in
            completion(.failure(BackgroundLifecycleFixtureError.failed))
        },
        markMigrationReady: { suppliedVersion in
            Result { try fixture.migration.markReady(version: suppliedVersion) }
        },
        promoteToFullInference: { false },
        runDueSchedules: { Issue.record("Unavailable provider cannot run schedules") },
        stopRuntime: { stopReply = $0 },
        exitApplication: {}
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    coordinator.runtimePublishedReady(generation: generation)
    #expect(coordinator.phase == .stopping(generation: generation))
    #expect(try fixture.migration.prepare(targetVersion: version) == .current)
    let completion = try #require(stopReply)
    completion(.success(()))
}

@Test @MainActor
func pendingBackgroundMigrationRecoveryPersistsResultAndStartsNoService() throws {
    let fixture = try BackgroundMigrationFixture()
    defer { fixture.cleanup() }
    let version = "9.7.2"
    guard case .backupCreated(let pendingBackup) = try fixture.migration.prepare(targetVersion: version) else {
        Issue.record("Expected the fixture to establish a pending migration")
        return
    }

    var launchCount = 0
    var probeCount = 0
    var stopCount = 0
    var exitCount = 0
    var persistedRecovery: (String, UUID)?
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        prepareMigration: { completion in
            do {
                let prepared = try fixture.migration.prepare(targetVersion: version)
                completion(.success(backgroundPreparation(prepared, version: version)))
            } catch {
                completion(.failure(error))
            }
        },
        launchRuntime: { launchCount += 1 },
        recordRecoveryNeeded: { persistedRecovery = ($0, $1) },
        probe: { _ in probeCount += 1 },
        reportIdentityReady: {},
        verifyTopology: { _, _ in Issue.record("Topology cannot run during pending recovery") },
        markMigrationReady: { _ in .failure(BackgroundLifecycleFixtureError.failed) },
        promoteToFullInference: { false },
        runDueSchedules: { Issue.record("Schedules cannot run during pending recovery") },
        stopRuntime: { _ in stopCount += 1 },
        exitApplication: { exitCount += 1 }
    )

    coordinator.prepareAndLaunch()

    #expect(persistedRecovery?.0 == version)
    #expect(persistedRecovery?.1 == pendingBackup.id)
    #expect(launchCount == 0) // no DSH and therefore no Ollama launch path
    #expect(probeCount == 0)
    #expect(stopCount == 0)
    #expect(exitCount == 1)
    #expect(coordinator.phase == .finished)
    guard case .recoveryNeeded(let stillPending) = try fixture.migration.prepare(targetVersion: version) else {
        Issue.record("The headless recovery result must preserve the pending snapshot")
        return
    }
    #expect(stillPending.id == pendingBackup.id)
}

@Test @MainActor
func neverReadyBackgroundRuntimeWaitsForExactCleanupBeforeExitAndRejectsStaleCallbacks() throws {
    let generation = UUID()
    var probes: [(Bool) -> Void] = []
    var scheduled: [() -> Void] = []
    var stopReply: ((Result<Void, Error>) -> Void)?
    var trace: [String] = []
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 2,
        delay: 0,
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: { trace.append("launch") },
        recordRecoveryNeeded: { _, _ in Issue.record("Unexpected recovery") },
        probe: { probes.append($0) },
        schedule: { _, action in scheduled.append(action) },
        reportIdentityReady: { trace.append("unexpected-ready") },
        verifyTopology: { _, _ in Issue.record("Never-ready runtime cannot verify topology") },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { false },
        runDueSchedules: { Issue.record("Never-ready runtime cannot run schedules") },
        stopRuntime: {
            trace.append("stop-began")
            stopReply = $0
        },
        exitApplication: { trace.append("exit") }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    let staleFirstProbe = probes.removeFirst()
    staleFirstProbe(false)
    scheduled.removeFirst()()
    probes.removeFirst()(false)

    #expect(trace == ["launch", "stop-began"])
    #expect(coordinator.phase == .stopping(generation: generation))
    staleFirstProbe(true)
    #expect(trace == ["launch", "stop-began"])

    let completion = try #require(stopReply)
    completion(.success(()))
    #expect(trace == ["launch", "stop-began", "exit"])
    #expect(coordinator.phase == .finished)
}

@Test @MainActor
func backgroundCleanupFailureNeverExitsAndCannotRestart() throws {
    let generation = UUID()
    var launchCount = 0
    var exitCount = 0
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 1,
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: { launchCount += 1 },
        recordRecoveryNeeded: { _, _ in },
        probe: { $0(false) },
        reportIdentityReady: {},
        verifyTopology: { _, _ in },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { false },
        runDueSchedules: {},
        stopRuntime: { $0(.failure(BackgroundLifecycleFixtureError.failed)) },
        exitApplication: { exitCount += 1 }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    coordinator.prepareAndLaunch()

    #expect(launchCount == 1)
    #expect(exitCount == 0)
    #expect(coordinator.phase == .cleanupFailed(generation: generation))
}

@Test @MainActor
func backgroundRuntimeFailureWaitsForScheduleQuiescenceBeforeStoppingOrExiting() throws {
    let generation = UUID()
    var probeReply: ((Bool) -> Void)?
    var topologyReply: ((Result<Void, Error>) -> Void)?
    var quiescenceReply: ((Result<Void, Error>) -> Void)?
    var stopReply: ((Result<Void, Error>) -> Void)?
    var trace: [String] = []
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: { trace.append("launch") },
        recordRecoveryNeeded: { _, _ in },
        probe: { probeReply = $0 },
        reportIdentityReady: { trace.append("identity-ready") },
        verifyTopology: { _, completion in topologyReply = completion },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { true },
        runDueSchedules: { trace.append("run-due") },
        quiesceSchedules: { completion in
            trace.append("quiesce-began")
            quiescenceReply = completion
        },
        stopRuntime: { completion in
            trace.append("stop-began")
            stopReply = completion
        },
        exitApplication: { trace.append("exit") }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    let publishProbe = try #require(probeReply)
    publishProbe(true)
    coordinator.runtimePublishedReady(generation: generation)
    let publishTopology = try #require(topologyReply)
    publishTopology(.success(()))
    #expect(coordinator.phase == .runningSchedules(generation: generation))

    coordinator.runtimeFailed(generation: generation)
    #expect(coordinator.phase == .quiescingSchedules(generation: generation))
    #expect(trace.suffix(2) == ["run-due", "quiesce-began"])
    #expect(stopReply == nil)
    #expect(!trace.contains("exit"))

    // A late idle callback from the invalidated run cannot skip the barrier.
    coordinator.scheduledWorkBecameIdle()
    #expect(stopReply == nil)
    let settleQuiescence = try #require(quiescenceReply)
    settleQuiescence(.success(()))
    #expect(coordinator.phase == .stopping(generation: generation))
    #expect(trace.last == "stop-began")
    let settleStop = try #require(stopReply)
    settleStop(.success(()))
    #expect(coordinator.phase == .finished)
    #expect(trace.last == "exit")
}

@Test @MainActor
func backgroundCancellationFailureStopsExactRuntimeButNeverClaimsCleanExit() throws {
    let generation = UUID()
    var stopReply: ((Result<Void, Error>) -> Void)?
    var exitCount = 0
    let coordinator = BackgroundScheduleLifecycleCoordinator(
        maximumAttempts: 1,
        prepareMigration: { $0(.success(.current(version: "1"))) },
        launchRuntime: {},
        recordRecoveryNeeded: { _, _ in },
        probe: { $0(false) },
        reportIdentityReady: {},
        verifyTopology: { _, _ in },
        markMigrationReady: { _ in .success(()) },
        promoteToFullInference: { false },
        runDueSchedules: {},
        quiesceSchedules: { $0(.failure(BackgroundLifecycleFixtureError.failed)) },
        stopRuntime: { stopReply = $0 },
        exitApplication: { exitCount += 1 }
    )

    coordinator.prepareAndLaunch()
    coordinator.runtimeStarted(generation: generation)
    #expect(coordinator.phase == .stopping(generation: generation))
    let settleStop = try #require(stopReply)
    settleStop(.success(()))
    #expect(coordinator.phase == .cleanupFailed(generation: generation))
    #expect(exitCount == 0)
}

@Test
func pendingBackgroundRecoveryActivityIsDurableBeforeReturn() throws {
    let root = try makeAdmissibleApplicationSupportTestRoot(
        prefix: "FulmarBackgroundActivity"
    )
    defer { try? FileManager.default.removeItem(at: root) }
    let first = ActivityStore(applicationSupport: root)
    #expect(first.status() == .available)
    let id = try first.addWaitingSynchronously(
        .backup,
        title: "Harness upgrade recovery required",
        detail: "No background service was started."
    )

    // Re-open immediately, with no queue drain or process-lifetime grace.
    let reopened = ActivityStore(applicationSupport: root)
    let persisted = try #require(reopened.snapshot().first(where: { $0.id == id }))
    #expect(persisted.state == .waiting)
    #expect(persisted.kind == .backup)
    #expect(persisted.detail == "No background service was started.")

    let activityFile = root.appendingPathComponent("Activity/activities.json")
    let attributes = try FileManager.default.attributesOfItem(atPath: activityFile.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}
