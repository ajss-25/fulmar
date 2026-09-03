import Foundation
import Testing
@testable import LocalHarness

@Test @MainActor
func startupPrerequisitesRemainSerializedOffMainAndCancelWithTypedResult() async throws {
    let worker = RuntimeStartupPrerequisiteWorker()
    let firstEntered = LockedStartupValue<Bool>()
    let releaseFirst = DispatchSemaphore(value: 0)
    let secondEntered = LockedStartupValue<Bool>()
    let firstResult = LockedStartupValue<Result<Void, Error>>()
    let secondResult = LockedStartupValue<Result<Void, Error>>()

    // Safety release prevents a regression from hanging the test process if
    // submit ever becomes synchronous.
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1) {
        releaseFirst.signal()
    }
    let submittedAt = ContinuousClock.now
    let cancellation = worker.submit(
        operation: { _ in
            firstEntered.set(true)
            releaseFirst.wait()
        },
        isGenerationCurrent: { true },
        completion: { firstResult.set($0) }
    )
    #expect(ContinuousClock.now - submittedAt < .milliseconds(250))
    try await waitForStartupValue(firstEntered)

    _ = worker.submit(
        operation: { _ in secondEntered.set(true) },
        isGenerationCurrent: { true },
        completion: { secondResult.set($0) }
    )
    try await Task.sleep(for: .milliseconds(100))
    #expect(secondEntered.value == nil)

    var mainQueueTurnRan = false
    DispatchQueue.main.async { mainQueueTurnRan = true }
    try await Task.sleep(for: .milliseconds(30))
    #expect(mainQueueTurnRan)

    cancellation.cancel()
    releaseFirst.signal()
    try await waitForStartupValue(firstResult)
    try await waitForStartupValue(secondResult)
    guard case .failure(let error)? = firstResult.value else {
        Issue.record("Cancelled prerequisites must complete with a typed failure")
        return
    }
    #expect(error as? RuntimeStartupPrerequisiteError == .cancelled)
    try secondResult.value?.get()
}

@Test @MainActor
func staleStartupGenerationCannotCommitAfterPrerequisitesFinish() async throws {
    let worker = RuntimeStartupPrerequisiteWorker()
    let entered = LockedStartupValue<Bool>()
    let release = DispatchSemaphore(value: 0)
    let result = LockedStartupValue<Result<Void, Error>>()
    var generation: UInt64 = 41
    var successfulCommits = 0

    _ = worker.submit(
        operation: { _ in
            entered.set(true)
            release.wait()
        },
        isGenerationCurrent: { generation == 41 },
        completion: { completion in
            result.set(completion)
            if case .success = completion { successfulCommits += 1 }
        }
    )
    try await waitForStartupValue(entered)
    generation = 42
    release.signal()

    try await waitForStartupValue(result)
    guard case .failure(let error)? = result.value else {
        Issue.record("A stale generation must be cancelled before commit")
        return
    }
    #expect(error as? RuntimeStartupPrerequisiteError == .cancelled)
    #expect(successfulCommits == 0)
}

private final class LockedStartupValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?

    var value: Value? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func set(_ value: Value) {
        lock.lock()
        stored = value
        lock.unlock()
    }
}

@MainActor
private func waitForStartupValue<Value>(
    _ value: LockedStartupValue<Value>,
    timeout: Duration = .seconds(2)
) async throws {
    let deadline = ContinuousClock.now + timeout
    while value.value == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(value.value != nil)
}
