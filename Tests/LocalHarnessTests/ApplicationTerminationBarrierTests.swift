import Foundation
import Darwin
import Testing
@testable import LocalHarness

private enum TerminationFixtureError: Error, Equatable { case stop }

private final class ManualTerminationScheduler {
    private struct Entry { let identifier: Int; let delay: TimeInterval; let action: () -> Void }
    private var nextIdentifier = 0
    private var entries: [Entry] = []

    func schedule(_ delay: TimeInterval, _ action: @escaping () -> Void) -> () -> Void {
        let identifier = nextIdentifier
        nextIdentifier += 1
        entries.append(.init(identifier: identifier, delay: delay, action: action))
        return { [weak self] in self?.entries.removeAll { $0.identifier == identifier } }
    }

    func fireNext() {
        guard !entries.isEmpty else { return }
        entries.sort { left, right in
            left.delay == right.delay ? left.identifier < right.identifier : left.delay < right.delay
        }
        let entry = entries.removeFirst()
        entry.action()
    }

    func fireAll() {
        while !entries.isEmpty { fireNext() }
    }
}

@Test func terminationWithoutUnloadWaitsForOwnedServiceBarrier() throws {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(scheduler: scheduler.schedule)
    var stopCompletion: ((Result<Void, Error>) -> Void)?
    var result: Result<Void, Error>?
    barrier.begin(
        unloadRequested: false,
        unload: { _ in Issue.record("Unload should not run") },
        stop: { stopCompletion = $0 },
        completion: { result = $0 }
    )
    #expect(result == nil)
    let stopReply = try #require(stopCompletion)
    stopReply(.success(()))
    #expect(result != nil)
    _ = try result?.get()
    scheduler.fireAll()
    #expect(result != nil)
    _ = try result?.get()
}

@Test func terminationWaitsForScheduleQuiescenceBeforeStoppingServices() throws {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(scheduler: scheduler.schedule)
    var quiesceCompletion: ((Result<Void, Error>) -> Void)?
    var stopCompletion: ((Result<Void, Error>) -> Void)?
    var stopCalls = 0
    var result: Result<Void, Error>?
    barrier.begin(
        quiesce: { quiesceCompletion = $0 },
        unloadRequested: false,
        unload: { _ in Issue.record("Unload should not run") },
        stop: { stopCalls += 1; stopCompletion = $0 },
        completion: { result = $0 }
    )

    #expect(stopCalls == 0)
    #expect(result == nil)
    let quiesceReply = try #require(quiesceCompletion)
    quiesceReply(.success(()))
    #expect(stopCalls == 1)
    #expect(result == nil)
    let stopReply = try #require(stopCompletion)
    stopReply(.success(()))
    _ = try result?.get()

    // Duplicate/late scheduler callbacks can never start a second stop.
    quiesceCompletion?(.success(()))
    scheduler.fireAll()
    #expect(stopCalls == 1)
    _ = try result?.get()
}

@Test func terminationNeverUnloadsOrStopsWhileCombinedConversationDrainIsBlocked() throws {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(scheduler: scheduler.schedule)
    var combinedQuiesce: ((Result<Void, Error>) -> Void)?
    var unloadCalls = 0
    var stopCalls = 0
    var result: Result<Void, Error>?
    barrier.begin(
        quiesce: { combinedQuiesce = $0 },
        unloadRequested: true,
        unload: { _ in unloadCalls += 1 },
        stop: { completion in stopCalls += 1; completion(.success(())) },
        completion: { result = $0 }
    )

    #expect(unloadCalls == 0)
    #expect(stopCalls == 0)
    #expect(result == nil)
    let drainReply = try #require(combinedQuiesce)
    drainReply(.success(()))
    #expect(unloadCalls == 1)
    #expect(stopCalls == 0)
    scheduler.fireNext()
    #expect(stopCalls == 1)
    _ = try result?.get()
}

@Test func terminationTimeoutDuringQuiescenceForcesExactServiceStopAndIgnoresLateDrain() throws {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(
        unloadGrace: 1,
        totalTimeout: 5,
        forcedStopTimeout: 2,
        scheduler: scheduler.schedule
    )
    var quiesceCompletion: ((Result<Void, Error>) -> Void)?
    var stopCalls = 0
    var results: [Result<Void, Error>] = []
    barrier.begin(
        quiesce: { quiesceCompletion = $0 },
        unloadRequested: false,
        unload: { _ in },
        stop: { completion in stopCalls += 1; completion(.success(())) },
        completion: { results.append($0) }
    )

    scheduler.fireNext()
    #expect(results.count == 1)
    _ = try results[0].get()
    quiesceCompletion?(.success(()))
    #expect(stopCalls == 1)
    #expect(results.count == 1)
}

@Test func terminationQuiescenceFailureSkipsUnloadAndForcesStop() throws {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(
        unloadGrace: 1,
        totalTimeout: 5,
        forcedStopTimeout: 2,
        scheduler: scheduler.schedule
    )
    var unloadCalls = 0
    var stopCalls = 0
    var result: Result<Void, Error>?
    barrier.begin(
        quiesce: { $0(.failure(TerminationFixtureError.stop)) },
        unloadRequested: true,
        unload: { _ in unloadCalls += 1 },
        stop: { completion in stopCalls += 1; completion(.success(())) },
        completion: { result = $0 }
    )

    #expect(unloadCalls == 0)
    #expect(stopCalls == 1)
    _ = try result?.get()
    scheduler.fireAll()
    #expect(stopCalls == 1)
}

@Test func terminationUnloadCompletionStartsStopBeforeReply() throws {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(scheduler: scheduler.schedule)
    var unloadCompletion: (() -> Void)?
    var stopCalls = 0
    var result: Result<Void, Error>?
    barrier.begin(
        unloadRequested: true,
        unload: { unloadCompletion = $0 },
        stop: { completion in stopCalls += 1; completion(.success(())) },
        completion: { result = $0 }
    )
    #expect(stopCalls == 0)
    let unloadReply = try #require(unloadCompletion)
    unloadReply()
    #expect(stopCalls == 1)
    #expect(result != nil)
    _ = try result?.get()
}

@Test func terminationUnloadGraceCannotBlockStopAndLateCallbackCannotDuplicateIt() {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(unloadGrace: 1, totalTimeout: 5, scheduler: scheduler.schedule)
    var unloadCompletion: (() -> Void)?
    var stopCalls = 0
    var replyCalls = 0
    barrier.begin(
        unloadRequested: true,
        unload: { unloadCompletion = $0 },
        stop: { completion in stopCalls += 1; completion(.success(())) },
        completion: { _ in replyCalls += 1 }
    )
    scheduler.fireNext()
    #expect(stopCalls == 1)
    #expect(replyCalls == 1)
    unloadCompletion?()
    scheduler.fireAll()
    #expect(stopCalls == 1)
    #expect(replyCalls == 1)
}

@Test func terminationStopFailureCancelsQuitExactlyOnce() {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(scheduler: scheduler.schedule)
    var results: [Result<Void, Error>] = []
    barrier.begin(
        unloadRequested: false,
        unload: { _ in },
        stop: { completion in completion(.failure(TerminationFixtureError.stop)); completion(.success(())) },
        completion: { results.append($0) }
    )
    #expect(results.count == 1)
    #expect(throws: TerminationFixtureError.self) { try results[0].get() }
    scheduler.fireAll()
    #expect(results.count == 1)
}

@Test func terminationOverallTimeoutFailsClosedAndIgnoresLateStop() {
    let scheduler = ManualTerminationScheduler()
    let barrier = ApplicationTerminationBarrier(unloadGrace: 1, totalTimeout: 5, scheduler: scheduler.schedule)
    var stopCompletion: ((Result<Void, Error>) -> Void)?
    var results: [Result<Void, Error>] = []
    barrier.begin(
        unloadRequested: false,
        unload: { _ in },
        stop: { stopCompletion = $0 },
        completion: { results.append($0) }
    )
    scheduler.fireNext()
    #expect(results.count == 1)
    #expect(throws: ApplicationTerminationBarrierError.self) { try results[0].get() }
    stopCompletion?(.success(()))
    #expect(results.count == 1)
}

@Test @MainActor func ownedProcessShutdownEscalatesOnlyTheCapturedProcess() async throws {
    let owned = Process()
    owned.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
    owned.arguments = ["-e", "$|=1; $SIG{TERM}='IGNORE'; print qq(READY\\n); while (1) { select(undef, undef, undef, 1); }"]
    let readiness = Pipe()
    owned.standardOutput = readiness
    owned.standardError = FileHandle.nullDevice
    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/bin/sleep")
    unrelated.arguments = ["30"]
    unrelated.standardOutput = FileHandle.nullDevice
    unrelated.standardError = FileHandle.nullDevice
    try owned.run()
    try unrelated.run()
    let maybeReadyBytes = try readiness.fileHandleForReading.read(upToCount: 6)
    let readyBytes = try #require(maybeReadyBytes)
    #expect(String(decoding: readyBytes, as: UTF8.self) == "READY\n")
    defer {
        for process in [owned, unrelated] where process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL)
        }
        let deadline = Date().addingTimeInterval(2)
        while (owned.isRunning || unrelated.isRunning), Date() < deadline {
            usleep(10_000)
        }
        #expect(boundedTestWaitForExit(owned, timeout: 2))
        #expect(boundedTestWaitForExit(unrelated, timeout: 2))
    }

    let controller = HarnessController()
    let result = await withCheckedContinuation { continuation in
        controller.stopOwnedProcess(owned, forceKillAfter: 0.1, failAfter: 2) {
            continuation.resume(returning: $0)
        }
    }
    try result.get()
    #expect(!owned.isRunning)
    #expect(owned.terminationReason == .uncaughtSignal)
    #expect(owned.terminationStatus == SIGKILL)
    #expect(unrelated.isRunning)
}
