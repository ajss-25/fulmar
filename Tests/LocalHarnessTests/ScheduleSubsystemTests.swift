import Darwin
import Foundation
import Testing
@testable import LocalHarness
@testable import LocalHarnessSchedulerWake

private struct LegacyScheduleFixture: Codable {
    let id: UUID
    let title: String
    let prompt: String
    let model: String
    let intervalSeconds: TimeInterval
    let nextRun: Date
    let enabled: Bool
    let lastRun: Date?
}

private struct LegacyExternalConsentFixture: Codable {
    let schemaVersion: Int
    let provider: ProviderID
    let model: ModelID
    let boundary: DataBoundary
    let grantedAt: Date
}

private struct LegacyScheduledResultFixture: Codable {
    let id: UUID
    let scheduleID: UUID
    let title: String
    let completedAt: Date
    let model: String
    let response: String
    let error: String
}

private func makeScheduledResult(
    id: UUID = UUID(),
    completedAt: Date,
    response: String = "result",
    title: String = "Retained task"
) -> ScheduledResult {
    ScheduledResult(
        id: id,
        scheduleID: UUID(),
        title: title,
        completedAt: completedAt,
        selection: .defaultLocal,
        boundary: .onDevice,
        sessionID: HarnessSessionID("retention-test-session"),
        response: response,
        failure: nil,
        truncated: false
    )
}

private enum SchedulePreparationTestError: Error, LocalizedError, Sendable {
    case checkpointUnavailable

    var errorDescription: String? {
        "api_key=sk-schedule-secret-123456789 /Users/private/schedule \u{202E}\u{0007}" +
            String(repeating: "HOSTILE-CHECKPOINT-DIAGNOSTIC", count: 4_000)
    }
}

private enum ScheduleDurabilityInjectedError: Error {
    case simulatedCrash
}

private final class ScheduleDurabilityFailureScript: @unchecked Sendable {
    private let lock = NSLock()
    private let point: ScheduleDurabilityFailurePoint
    private var fired = false

    init(point: ScheduleDurabilityFailurePoint) {
        self.point = point
    }

    func inject(_ candidate: ScheduleDurabilityFailurePoint) throws {
        lock.lock()
        defer { lock.unlock() }
        guard candidate == point, !fired else { return }
        fired = true
        throw ScheduleDurabilityInjectedError.simulatedCrash
    }
}

private final class FakeScheduleExecutor: ScheduleConversationExecuting, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requests: [UUID: ScheduleConversationRequest] = [:]
    private var completions: [UUID: ScheduleConversationExecuting.Completion] = [:]
    private var requestOrder: [UUID] = []
    private var maximumConcurrentRequests = 0
    private(set) var cancelled: [UUID] = []

    @discardableResult
    func execute(
        _ request: ScheduleConversationRequest,
        completion: @escaping ScheduleConversationExecuting.Completion
    ) -> UUID {
        let id = UUID()
        lock.lock()
        requests[id] = request
        completions[id] = completion
        requestOrder.append(id)
        maximumConcurrentRequests = max(maximumConcurrentRequests, completions.count)
        lock.unlock()
        return id
    }

    func cancel(_ identifier: UUID) {
        lock.lock()
        cancelled.append(identifier)
        let completion = completions.removeValue(forKey: identifier)
        lock.unlock()
        completion?(.failure(.cancelled))
    }

    func cancelAll() {
        lock.lock()
        let pending = completions
        completions.removeAll()
        cancelled.append(contentsOf: pending.keys)
        lock.unlock()
        pending.values.forEach { $0(.failure(.cancelled)) }
    }

    func snapshotRequests() -> [UUID: ScheduleConversationRequest] {
        lock.lock(); defer { lock.unlock() }
        return requests
    }

    func complete(_ identifier: UUID, with result: Result<ScheduleConversationOutput, ScheduleExecutionError>) {
        lock.lock()
        let completion = completions.removeValue(forKey: identifier)
        lock.unlock()
        completion?(result)
    }

    func cancelledIDs() -> [UUID] {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func orderedRequests() -> [ScheduleConversationRequest] {
        lock.lock(); defer { lock.unlock() }
        return requestOrder.compactMap { requests[$0] }
    }

    func activeRequests() -> [(UUID, ScheduleConversationRequest)] {
        lock.lock(); defer { lock.unlock() }
        return requestOrder.compactMap { identifier in
            guard completions[identifier] != nil, let request = requests[identifier] else { return nil }
            return (identifier, request)
        }
    }

    func maximumConcurrentRequestCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        return maximumConcurrentRequests
    }
}

private final class FakeSchedulePreparation: @unchecked Sendable {
    typealias Completion = @Sendable (Result<Void, Error>) -> Void

    private let lock = NSLock()
    private var pending: [UUID: Completion] = [:]
    private var order: [UUID] = []

    func prepare(_ schedule: LocalSchedule, completion: @escaping Completion) {
        lock.lock()
        pending[schedule.id] = completion
        order.append(schedule.id)
        lock.unlock()
    }

    func pendingScheduleIDs() -> [UUID] {
        lock.lock(); defer { lock.unlock() }
        return order.filter { pending[$0] != nil }
    }

    func complete(scheduleID: UUID, with result: Result<Void, Error>) {
        lock.lock()
        let completion = pending.removeValue(forKey: scheduleID)
        lock.unlock()
        completion?(result)
    }
}

private final class ScheduleTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ value: Date) { self.value = value }

    func now() -> Date {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    func set(_ value: Date) {
        lock.lock(); self.value = value; lock.unlock()
    }
}

private final class ScheduleDirectoryScanClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64
    private var step: UInt64

    init(value: UInt64 = 0, step: UInt64 = 0) {
        self.value = value
        self.step = step
    }

    func now() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let current = value
        let advanced = value.addingReportingOverflow(step)
        value = advanced.overflow ? UInt64.max : advanced.partialValue
        return current
    }

    func setStep(_ value: UInt64) {
        lock.lock()
        step = value
        lock.unlock()
    }
}

private final class ScheduleIdleRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func record() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

private final class FakeHarnessScheduleService: ScheduleHarnessConversationServicing, @unchecked Sendable {
    enum Behavior {
        case success
        case automaticContinuation
        case automaticContinuationAggregateOverflow
        case pending
        case approval
        case oversized
        case admissionRejected
        case creationFailure(Error)
    }

    private let lock = NSLock()
    private let behavior: Behavior
    private let normalizedSelection: HarnessWireModelSelection
    private let createGate: ScheduleCreationGate?
    private let discardFails: Bool
    private(set) var prompts: [[HarnessPromptContentPart]] = []
    private(set) var creations = 0
    private(set) var cancellations: [(UUID, HarnessSessionID)] = []
    private(set) var discardedSessions: [HarnessSessionID] = []
    private(set) var rejectedApprovals = 0
    private(set) var cancelledQuestions = 0
    private var pendingCompletion: HarnessConversationService.Completion?

    init(
        behavior: Behavior,
        normalizedSelection: HarnessWireModelSelection,
        createGate: ScheduleCreationGate? = nil,
        discardFails: Bool = false
    ) {
        self.behavior = behavior
        self.normalizedSelection = normalizedSelection
        self.createGate = createGate
        self.discardFails = discardFails
    }

    func createSession(
        selection: ModelSelection,
        workspace: URL,
        agentPreset: String
    ) async throws -> HarnessConversationSession {
        withLockedState { creations += 1 }
        if let createGate { await createGate.wait() }
        if case .creationFailure(let error) = behavior { throw error }
        return HarnessConversationSession(
            id: HarnessSessionID("schedule/session:1"),
            selection: normalizedSelection,
            agentPreset: agentPreset
        )
    }

    @discardableResult
    func sendIfAdmitted(
        sessionID: HarnessSessionID,
        content: [HarnessPromptContentPart],
        since lastSequence: Int,
        timeout: TimeInterval,
        onEvent: @escaping HarnessConversationService.EventHandler,
        completion: @escaping HarnessConversationService.Completion
    ) -> UUID? {
        if case .admissionRejected = behavior { return nil }
        withLockedState { prompts.append(content) }
        let operationID = UUID()
        switch behavior {
        case .success:
            Task { @MainActor in
                onEvent(.assistantTextDelta(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 1, time: 1,
                    turn: 1, step: 1, blockIndex: 0, text: "streamed"
                )))
                onEvent(.assistantFinalMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 2, time: 2,
                    turn: 1, step: 1, messageID: "message", textBlocks: ["final answer"],
                    provider: normalizedSelection.provider, model: normalizedSelection.model, interrupted: false
                )))
                onEvent(.turnCompleted(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 3, time: 3,
                    turn: 1, reason: .completed
                )))
                completion(.success(()))
            }
        case .automaticContinuation:
            Task { @MainActor in
                onEvent(.assistantTextDelta(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 1, time: 1,
                    turn: 1, step: 1, blockIndex: 0, text: "first segment"
                )))
                onEvent(.assistantFinalMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 2, time: 2,
                    turn: 1, step: 1, messageID: "message-1", textBlocks: ["first segment"],
                    provider: normalizedSelection.provider, model: normalizedSelection.model,
                    interrupted: false
                )))
                onEvent(.turnCompleted(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 3, time: 3,
                    turn: 1, reason: .maxTokens
                )))
                onEvent(.userMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 4, time: 4,
                    messageID: "continued", sourceRPCID: nil,
                    automaticContinuation: .init(
                        round: 1, maximum: 12, isTerminalBudgetNotice: false
                    )
                )))
                onEvent(.assistantTextDelta(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 5, time: 5,
                    turn: 2, step: 1, blockIndex: 0, text: "second segment"
                )))
                onEvent(.assistantFinalMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 6, time: 6,
                    turn: 2, step: 1, messageID: "message-2", textBlocks: ["second segment"],
                    provider: normalizedSelection.provider, model: normalizedSelection.model,
                    interrupted: false
                )))
                onEvent(.turnCompleted(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 7, time: 7,
                    turn: 2, reason: .completed
                )))
                completion(.success(()))
            }
        case .automaticContinuationAggregateOverflow:
            Task { @MainActor in
                let firstSegment = String(
                    repeating: "x",
                    count: HarnessScheduleConversationExecutor.maximumResponseBytes - 1
                )
                onEvent(.assistantFinalMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 1, time: 1,
                    turn: 1, step: 1, messageID: "message-1", textBlocks: [firstSegment],
                    provider: normalizedSelection.provider, model: normalizedSelection.model,
                    interrupted: false
                )))
                onEvent(.turnCompleted(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 2, time: 2,
                    turn: 1, reason: .maxTokens
                )))
                onEvent(.userMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 3, time: 3,
                    messageID: "continued", sourceRPCID: nil,
                    automaticContinuation: .init(
                        round: 1, maximum: 12, isTerminalBudgetNotice: false
                    )
                )))
                onEvent(.assistantFinalMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 4, time: 4,
                    turn: 2, step: 1, messageID: "message-2", textBlocks: ["y"],
                    provider: normalizedSelection.provider, model: normalizedSelection.model,
                    interrupted: false
                )))
                onEvent(.turnCompleted(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 5, time: 5,
                    turn: 2, reason: .completed
                )))
                completion(.success(()))
            }
        case .pending:
            withLockedState { pendingCompletion = completion }
        case .approval:
            Task { @MainActor in
                onEvent(.approvalRequested(.init(
                    rpcID: "approval-rpc", sessionID: sessionID, approvalID: "approval:1",
                    toolName: "filesystem.write", callID: "call:1", reason: "Needs permission"
                )))
            }
            withLockedState { pendingCompletion = completion }
        case .oversized:
            Task { @MainActor in
                onEvent(.assistantFinalMessage(.init(
                    rpcID: "rpc", sessionID: sessionID, sequence: 1, time: 1,
                    turn: 1, step: 1, messageID: "large",
                    textBlocks: [String(repeating: "x", count: HarnessScheduleConversationExecutor.maximumResponseBytes + 1)],
                    provider: nil, model: nil, interrupted: false
                )))
            }
            withLockedState { pendingCompletion = completion }
        case .admissionRejected:
            break
        case .creationFailure:
            break
        }
        return operationID
    }

    func cancel(_ identifier: UUID, sessionID: HarnessSessionID) {
        withLockedState { cancellations.append((identifier, sessionID)) }
    }

    func discardUnsubmittedSession(_ sessionID: HarnessSessionID) async throws {
        withLockedState { discardedSessions.append(sessionID) }
        if discardFails { throw HarnessConversationError.sessionCleanupUnverified }
    }

    func respond(to request: HarnessApprovalRequest, decision: HarnessApprovalDecision) async throws {
        withLockedState { rejectedApprovals += decision == .rejected ? 1 : 0 }
    }

    func cancel(_ request: HarnessQuestionRequest) async throws {
        withLockedState { cancelledQuestions += 1 }
    }

    func promptSnapshot() -> [[HarnessPromptContentPart]] {
        withLockedState { prompts }
    }

    func creationCount() -> Int {
        withLockedState { creations }
    }

    func cancellationCount() -> Int {
        withLockedState { cancellations.count }
    }

    func discardedSessionSnapshot() -> [HarnessSessionID] {
        withLockedState { discardedSessions }
    }

    func rejectedApprovalCount() -> Int {
        withLockedState { rejectedApprovals }
    }

    /// Keep the lock-taking operation synchronous. Calling `NSLock.lock()`
    /// directly from an async protocol requirement is unavailable in Swift 6.
    private func withLockedState<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

private actor ScheduleCreationGate {
    private var opened = false
    private var entered = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if !entered {
            entered = true
            let current = entryWaiters
            entryWaiters.removeAll()
            current.forEach { $0.resume() }
        }
        if opened { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func open() {
        opened = true
        let current = waiters
        waiters.removeAll()
        current.forEach { $0.resume() }
    }
}

@Test func legacySchedulesMigrateToTypedOllamaRoutesAndPrivateV2Storage() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let id = UUID()
    let date = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let legacy = LegacyScheduleFixture(
        id: id,
        title: "Legacy local task",
        prompt: "Keep this exact prompt",
        model: "qwen3:27b/custom:q5",
        intervalSeconds: 30,
        nextRun: date,
        enabled: true,
        lastRun: nil
    )
    try JSONEncoder().encode([legacy]).write(to: store.schedulesURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.schedulesURL.path)

    let loaded = try store.load()

    #expect(loaded.migratedLegacySchema)
    let migrated = try #require(loaded.schedules.first)
    #expect(migrated.schemaVersion == LocalSchedule.currentSchemaVersion)
    #expect(migrated.id == id)
    #expect(migrated.prompt == legacy.prompt)
    #expect(migrated.selection.route == ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: ModelID(legacy.model)
    ))
    #expect(migrated.boundary == .onDevice)
    #expect(migrated.unattendedConsent == nil)
    #expect(migrated.intervalSeconds == 60)
    #expect(migrated.timeoutSeconds == LocalSchedule.defaultTimeoutSeconds)

    try store.save(loaded.schedules)
    let rewritten = try store.load()
    #expect(!rewritten.migratedLegacySchema)
    #expect(rewritten.schedules == loaded.schedules)
    #expect(privateMode(at: store.schedulesURL) == 0o600)
    let json = String(decoding: try Data(contentsOf: store.schedulesURL), as: UTF8.self)
    #expect(json.contains(#""schemaVersion":2"#))
    #expect(json.contains(#""provider":"ollama""#))
}

@Test func legacyScheduledResultErrorsCollapseToAnAppOwnedFailure() throws {
    let credential = ["sk", "legacy", String(repeating: "s", count: 48)].joined(separator: "-")
    let hostile = "\u{001B}[2Jprovider said \(credential) at /Users/private/key\u{0000}"
        + String(repeating: "X", count: 32 * 1_024)
    let fixture = LegacyScheduledResultFixture(
        id: UUID(),
        scheduleID: UUID(),
        title: "Legacy task",
        completedAt: Date(timeIntervalSinceReferenceDate: 700_000_001),
        model: "qwen3.8:27b-hermes",
        response: "",
        error: hostile
    )

    let decoded = try JSONDecoder().decode(ScheduledResult.self, from: JSONEncoder().encode(fixture))
    #expect(decoded.failure == ScheduleResultFailure(code: .legacy))
    let display = try #require(decoded.error)
    #expect(display == "The legacy scheduled task failed.")
    #expect(!display.contains(credential))
    #expect(!display.contains("/Users/private"))

    let rewritten = String(decoding: try JSONEncoder().encode(decoded), as: UTF8.self)
    #expect(!rewritten.contains(credential))
    #expect(!rewritten.contains("/Users/private"))
    #expect(!rewritten.contains("\u{001B}"))
}

@Test func futureScheduleDocumentsFailClosedWithoutOverwritingBytes() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let original = Data(#"[{"schemaVersion":999,"id":"00000000-0000-0000-0000-000000000001"}]"#.utf8)
    try original.write(to: store.schedulesURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.schedulesURL.path)

    #expect(throws: ScheduleValidationError.invalidSchemaVersion) { _ = try store.load() }
    #expect(try Data(contentsOf: store.schedulesURL) == original)

    let activity = scheduleActivityStore(applicationSupport: root)
    let manager = ScheduleManager(applicationSupport: root, executor: FakeScheduleExecutor(), activities: activity)
    #expect(manager.snapshot().isEmpty)
    #expect(manager.storageIssue() != nil)
    #expect(throws: ScheduleManagerError.storageUnavailable) {
        try manager.add(
            title: "Must not overwrite",
            prompt: "Prompt",
            selection: .defaultLocal,
            intervalSeconds: 0
        )
    }
    #expect(try Data(contentsOf: store.schedulesURL) == original)
    _ = activity.snapshot()
}

@Test func scheduleStorageRejectsSymlinkedDocumentsAndLeavesTargetsUntouched() throws {
    let root = temporaryScheduleRoot()
    let outside = root.appendingPathComponent("outside.json")
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let original = Data("private target".utf8)
    try original.write(to: outside)
    try FileManager.default.createSymbolicLink(at: store.schedulesURL, withDestinationURL: outside)

    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { _ = try store.load() }
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { try store.save([]) }
    #expect(try Data(contentsOf: outside) == original)
}

@Test func scheduleStoreRejectsPublicHardlinkedAndSpecialDocumentsWithoutBlocking() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let valid = try LocalSchedule(
        title: "Private task",
        prompt: "Stay private",
        selection: .defaultLocal,
        boundary: .onDevice,
        intervalSeconds: 0,
        nextRun: Date()
    )

    try JSONEncoder().encode([valid]).write(to: store.schedulesURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: store.schedulesURL.path)
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { _ = try store.load() }

    try FileManager.default.removeItem(at: store.schedulesURL)
    let outside = root.appendingPathComponent("outside-private.json")
    try JSONEncoder().encode([valid]).write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    try FileManager.default.linkItem(at: outside, to: store.schedulesURL)
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { _ = try store.load() }

    try FileManager.default.removeItem(at: store.schedulesURL)
    #expect(mkfifo(store.schedulesURL.path, 0o600) == 0)
    let started = ContinuousClock.now
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { _ = try store.load() }
    #expect(started.duration(to: .now) < .seconds(1))
}

@Test func taskInboxRetentionKeepsTheNewestResultsByCompletionTime() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(
        applicationSupport: root,
        inboxRetentionPolicy: ScheduleInboxRetentionPolicy(
            maximumRecords: 3,
            maximumBytes: 20 * 1_024 * 1_024,
            maximumAge: 30 * 86_400
        ),
        now: { now }
    )
    let dates = [now.addingTimeInterval(-20), now.addingTimeInterval(-50), now.addingTimeInterval(-10), now.addingTimeInterval(-40), now.addingTimeInterval(-30)]
    let results = dates.enumerated().map {
        makeScheduledResult(completedAt: $0.element, title: "Result \($0.offset)")
    }
    for result in results { try store.write(result: result) }

    let retained = store.inbox()
    #expect(retained.map(\.completedAt) == Array(dates.sorted(by: >).prefix(3)))
    #expect((try FileManager.default.contentsOfDirectory(atPath: store.inboxDirectory.path)).count == 3)
}

@Test func taskInboxRetentionEnforcesAgeAndAggregateBytes() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(
        applicationSupport: root,
        inboxRetentionPolicy: ScheduleInboxRetentionPolicy(
            maximumRecords: 20,
            maximumBytes: 5 * 1_024 * 1_024,
            maximumAge: 86_400
        ),
        now: { now }
    )
    try store.write(result: makeScheduledResult(
        completedAt: now.addingTimeInterval(-86_401),
        title: "Expired"
    ))
    let large = String(repeating: "x", count: 2 * 1_024 * 1_024)
    let newest = makeScheduledResult(completedAt: now.addingTimeInterval(-1), response: large, title: "Newest")
    let middle = makeScheduledResult(completedAt: now.addingTimeInterval(-2), response: large, title: "Middle")
    let oldest = makeScheduledResult(completedAt: now.addingTimeInterval(-3), response: large, title: "Oldest")
    try store.write(result: oldest)
    try store.write(result: newest)
    try store.write(result: middle)

    let retained = store.inbox()
    #expect(retained.map(\.id) == [newest.id, middle.id])
    let bytes = try FileManager.default.contentsOfDirectory(at: store.inboxDirectory, includingPropertiesForKeys: [.fileSizeKey])
        .reduce(0) { total, url in
            total + ((try url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        }
    #expect(bytes <= 5 * 1_024 * 1_024)
}

@Test func taskInboxSupportsPrivatePerResultDeleteAndClear() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(applicationSupport: root, now: { now })
    let first = makeScheduledResult(completedAt: now.addingTimeInterval(-2), title: "First")
    let second = makeScheduledResult(completedAt: now.addingTimeInterval(-1), title: "Second")
    try store.write(result: first)
    try store.write(result: second)

    try store.deleteInboxResult(id: first.id)
    #expect(store.inbox().map(\.id) == [second.id])
    #expect(privateMode(at: store.inboxDirectory.appendingPathComponent("\(second.id.uuidString).json")) == 0o600)
    try store.clearInbox()
    #expect(store.inbox().isEmpty)
    #expect(try FileManager.default.contentsOfDirectory(atPath: store.inboxDirectory.path).isEmpty)
}

@Test func taskInboxNeverFollowsOrClearsSymlinkAndHardlinkTargets() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(applicationSupport: root, now: { now })
    let safe = makeScheduledResult(completedAt: now, title: "Safe")
    try store.write(result: safe)

    let symlinkID = UUID()
    let outside = root.appendingPathComponent("outside-inbox-target.json")
    let original = Data("outside target must remain unchanged".utf8)
    try original.write(to: outside)
    let symlink = store.inboxDirectory.appendingPathComponent("\(symlinkID.uuidString).json")
    try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: outside)
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { try store.deleteInboxResult(id: symlinkID) }
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { try store.clearInbox() }
    #expect(try Data(contentsOf: outside) == original)
    #expect(FileManager.default.fileExists(atPath: store.inboxDirectory.appendingPathComponent("\(safe.id.uuidString).json").path))

    try FileManager.default.removeItem(at: symlink)
    let hardlinkResult = makeScheduledResult(id: UUID(), completedAt: now, title: "Linked")
    let encoded = try JSONEncoder().encode(hardlinkResult)
    try encoded.write(to: outside, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    let hardlink = store.inboxDirectory.appendingPathComponent("\(hardlinkResult.id.uuidString).json")
    try FileManager.default.linkItem(at: outside, to: hardlink)
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { try store.clearInbox() }
    #expect(try Data(contentsOf: outside) == encoded)
    #expect(FileManager.default.fileExists(atPath: store.inboxDirectory.appendingPathComponent("\(safe.id.uuidString).json").path))
}

@Test func taskInboxRemovesOnlyCanonicalPrivateCrashTemporaryFiles() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(applicationSupport: root, now: { now })
    let temporary = store.inboxDirectory.appendingPathComponent(".writing-\(UUID().uuidString)")
    try Data("partial".utf8).write(to: temporary)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)

    #expect(store.inbox().isEmpty)
    #expect(!FileManager.default.fileExists(atPath: temporary.path))

    let unknown = store.inboxDirectory.appendingPathComponent(".writing-not-a-uuid")
    try Data("do not guess ownership".utf8).write(to: unknown)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: unknown.path)
    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) { try store.clearInbox() }
    #expect(FileManager.default.fileExists(atPath: unknown.path))
}

@Test func taskInboxStatusCountNeverDecodesResponseBodies() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let inbox = root.appendingPathComponent("Schedules/Inbox", isDirectory: true)
    try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.appendingPathComponent("Schedules").path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: inbox.path)
    let invalid = inbox.appendingPathComponent("\(UUID().uuidString).json")
    try Data(repeating: 0x78, count: ScheduleDocumentStore.maximumDocumentBytes).write(to: invalid)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: invalid.path)

    let store = try ScheduleDocumentStore(applicationSupport: root)
    #expect(store.inboxCount() == 1)
    #expect(FileManager.default.fileExists(atPath: invalid.path))
}

@Test func asynchronousTaskInboxLoadDistinguishesUnavailableFromEmpty() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(applicationSupport: root, now: { now })
    let retained = makeScheduledResult(completedAt: now, title: "Must remain on disk")
    try store.write(result: retained)
    let retainedURL = store.inboxDirectory.appendingPathComponent("\(retained.id.uuidString).json")
    let retainedBytes = try Data(contentsOf: retainedURL)
    let unknown = store.inboxDirectory.appendingPathComponent("unknown-entry")
    try Data("unsafe topology".utf8).write(to: unknown)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: unknown.path)

    let manager = ScheduleManager(
        applicationSupport: root,
        executor: FakeScheduleExecutor(),
        activities: scheduleActivityStore(applicationSupport: root),
        now: { now }
    )
    let outcome = await manager.inboxAsync()
    guard case .unavailable(let message) = outcome else {
        Issue.record("A hostile Inbox entry must not be presented as an empty Inbox")
        return
    }
    #expect(message.contains("unavailable"))
    #expect(FileManager.default.fileExists(atPath: retainedURL.path))
    #expect(try Data(contentsOf: retainedURL) == retainedBytes)
    #expect(await eventually { manager.storageIssue()?.contains("Inbox is unavailable") == true })
}

@Test func scheduleInboxStartupScanBoundsEveryDirectoryEntryAndFailsTyped() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let bootstrap = try ScheduleDocumentStore(applicationSupport: root)
    for _ in 0..<4 {
        try writePrivateScheduleFixture(
            Data(),
            to: bootstrap.inboxDirectory.appendingPathComponent("\(UUID().uuidString).json")
        )
    }

    #expect(throws: ScheduleDocumentStoreError.directoryEntryLimitExceeded(3)) {
        _ = try ScheduleDocumentStore(
            applicationSupport: root,
            directoryScanLimits: ScheduleDirectoryScanLimits(
                maximumInboxEntries: 3,
                maximumOccurrenceEntries: 3,
                deadlineSeconds: 1
            )
        )
    }
}

@Test func failedInboxRescanPreservesLastAuthoritativeCountAndBytes() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(
        applicationSupport: root,
        now: { now },
        directoryScanLimits: ScheduleDirectoryScanLimits(
            maximumInboxEntries: 3,
            maximumOccurrenceEntries: 3,
            deadlineSeconds: 1
        )
    )
    let retained = makeScheduledResult(completedAt: now, title: "Authoritative count")
    try store.write(result: retained)
    let retainedURL = store.inboxDirectory.appendingPathComponent("\(retained.id.uuidString).json")
    let retainedBytes = try Data(contentsOf: retainedURL)
    for _ in 0..<3 {
        try writePrivateScheduleFixture(
            Data(),
            to: store.inboxDirectory.appendingPathComponent("\(UUID().uuidString).json")
        )
    }

    #expect(throws: ScheduleDocumentStoreError.directoryEntryLimitExceeded(3)) {
        _ = try store.inboxChecked()
    }
    #expect(store.inboxCount() == 1)
    #expect(try Data(contentsOf: retainedURL) == retainedBytes)
}

@Test func inboxDirectoryReadFailureIsUnavailableAndNeverBecomesAnEmptyCount() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let store = try ScheduleDocumentStore(applicationSupport: root, now: { now })
    try store.write(result: makeScheduledResult(completedAt: now, title: "Still counted"))
    #expect(store.inboxCount() == 1)

    let preserved = store.directory.appendingPathComponent("PreservedInbox", isDirectory: true)
    try FileManager.default.moveItem(at: store.inboxDirectory, to: preserved)
    try writePrivateScheduleFixture(Data("not a directory".utf8), to: store.inboxDirectory)

    #expect(throws: ScheduleDocumentStoreError.unsafeStorage) {
        _ = try store.inboxChecked()
    }
    #expect(store.inboxCount() == 1)
}

@Test func inboxAndOccurrenceScansEnforceMonotonicDeadlines() throws {
    let startupRoot = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: startupRoot) }
    let startupClock = ScheduleDirectoryScanClock(step: 2_000_000_000)
    #expect(throws: ScheduleDocumentStoreError.directoryScanTimedOut) {
        _ = try ScheduleDocumentStore(
            applicationSupport: startupRoot,
            directoryScanLimits: ScheduleDirectoryScanLimits(
                maximumInboxEntries: 10,
                maximumOccurrenceEntries: 10,
                deadlineSeconds: 1
            ),
            directoryScanNow: { startupClock.now() }
        )
    }

    let runtimeRoot = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: runtimeRoot) }
    let runtimeClock = ScheduleDirectoryScanClock()
    let runtimeStore = try ScheduleDocumentStore(
        applicationSupport: runtimeRoot,
        directoryScanLimits: ScheduleDirectoryScanLimits(
            maximumInboxEntries: 10,
            maximumOccurrenceEntries: 10,
            deadlineSeconds: 1
        ),
        directoryScanNow: { runtimeClock.now() }
    )
    try runtimeStore.beginOccurrence(id: UUID(), scheduleID: UUID(), startedAt: Date())
    runtimeClock.setStep(2_000_000_000)
    #expect(throws: ScheduleDocumentStoreError.directoryScanTimedOut) {
        _ = try runtimeStore.pendingOccurrenceCount()
    }
}

@Test func occurrenceReconciliationScanBoundsDirectoryFloodsBeforeMutation() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(
        applicationSupport: root,
        directoryScanLimits: ScheduleDirectoryScanLimits(
            maximumInboxEntries: 10,
            maximumOccurrenceEntries: 3,
            deadlineSeconds: 5
        )
    )
    for _ in 0..<4 {
        try store.beginOccurrence(id: UUID(), scheduleID: UUID(), startedAt: Date())
    }

    #expect(throws: ScheduleDocumentStoreError.directoryEntryLimitExceeded(3)) {
        _ = try store.reconcilePendingOccurrences(in: [])
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: store.occurrenceDirectory.path).count == 4)
}

@Test func occurrenceReceiptSemanticLimitRemainsExactlyOneThousand() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(
        applicationSupport: root,
        directoryScanLimits: ScheduleDirectoryScanLimits(
            maximumInboxEntries: 10,
            maximumOccurrenceEntries: 2_048,
            deadlineSeconds: 20
        )
    )
    let encoder = JSONEncoder()
    for _ in 0..<ScheduleDocumentStore.maximumScheduleCount {
        let receipt = try ScheduleOccurrenceReceipt(
            id: UUID(),
            scheduleID: UUID(),
            startedAt: Date(timeIntervalSinceReferenceDate: 800_000_000)
        )
        try writePrivateScheduleFixture(
            encoder.encode(receipt),
            to: store.occurrenceDirectory.appendingPathComponent("\(receipt.id.uuidString).json")
        )
    }
    #expect(try store.pendingOccurrenceCount() == ScheduleDocumentStore.maximumScheduleCount)

    let overflow = try ScheduleOccurrenceReceipt(
        id: UUID(),
        scheduleID: UUID(),
        startedAt: Date(timeIntervalSinceReferenceDate: 800_000_001)
    )
    try writePrivateScheduleFixture(
        encoder.encode(overflow),
        to: store.occurrenceDirectory.appendingPathComponent("\(overflow.id.uuidString).json")
    )
    #expect(throws: ScheduleDocumentStoreError.documentTooLarge) {
        _ = try store.pendingOccurrenceCount()
    }
}

@Test func scheduleLimitRejectsTheNextAddWithoutCorruptingReadableStorage() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    #expect(ScheduleDocumentStore.maximumScheduleCount == SchedulerWakePolicy.maximumScheduleCount)

    let schedules = try (0..<ScheduleDocumentStore.maximumScheduleCount).map { index in
        try LocalSchedule(
            title: "Task \(index)",
            prompt: "Keep the schedule file readable",
            selection: .defaultLocal,
            boundary: .onDevice,
            intervalSeconds: 3_600,
            nextRun: Date(timeIntervalSinceReferenceDate: 700_000_000 + Double(index))
        )
    }
    try store.save(schedules)
    let original = try Data(contentsOf: store.schedulesURL)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: FakeScheduleExecutor(),
        activities: scheduleActivityStore(applicationSupport: root)
    )

    #expect(manager.snapshot().count == ScheduleDocumentStore.maximumScheduleCount)
    #expect(throws: ScheduleManagerError.scheduleLimitReached) {
        try manager.add(
            title: "One too many",
            prompt: "This must not be persisted",
            selection: .defaultLocal,
            intervalSeconds: 3_600
        )
    }
    #expect(try Data(contentsOf: store.schedulesURL) == original)
    #expect(try store.load().schedules.count == ScheduleDocumentStore.maximumScheduleCount)

    let extra = try LocalSchedule(
        title: "Direct-store overflow",
        prompt: "This must also be rejected",
        selection: .defaultLocal,
        boundary: .onDevice,
        intervalSeconds: 3_600,
        nextRun: Date(timeIntervalSinceReferenceDate: 800_000_000)
    )
    #expect(throws: ScheduleDocumentStoreError.tooManySchedules) {
        try store.save(schedules + [extra])
    }
    #expect(try Data(contentsOf: store.schedulesURL) == original)
}

@Test func schedulerWakePolicyRequiresAValidDueScheduleInPrivateBoundedStorage() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let due = try LocalSchedule(
        title: "Wake once",
        prompt: "Run the due task",
        selection: .defaultLocal,
        boundary: .onDevice,
        intervalSeconds: 0,
        nextRun: now
    )
    try store.save([due])

    #expect(SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    var disabled = due
    disabled.enabled = false
    try store.save([disabled])
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    var future = due
    future.nextRun = now.addingTimeInterval(1)
    try store.save([future])
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
}

@Test func schedulerWakePolicyAcceptsPersistedCompatibilityModelSchedules() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let compatibilitySelection = ModelSelection(
        route: ModelRoute(
            provider: BuiltInProviderDescriptors.ollama.id,
            model: ModelID("alternate-local-model")
        ),
        performanceProfile: .balanced
    )
    #expect(compatibilitySelection.performanceProfile == .compatibility)
    let due = try LocalSchedule(
        title: "Wake compatibility model",
        prompt: "Run the admitted alternate local model",
        selection: compatibilitySelection,
        boundary: .onDevice,
        intervalSeconds: 0,
        nextRun: now
    )

    try store.save([due])
    #expect(SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    var future = due
    future.nextRun = now.addingTimeInterval(1)
    try store.save([future])
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    var disabled = due
    disabled.enabled = false
    try store.save([disabled])
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
}

@Test func schedulerWakePolicyBindsV2ExternalConsentToExactDecodedSelectionAndBoundary() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let selection = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-chat")
    let origin = try #require(ProviderEndpointOrigin(url: URL(string: "https://api.deepseek.com")!))
    let consent = try ScheduleUnattendedConsent(
        selection: selection,
        boundary: .cloud,
        origin: origin,
        grantedAt: now.addingTimeInterval(-60)
    )
    let localNetworkConsent = try ScheduleUnattendedConsent(
        selection: selection,
        boundary: .localNetwork,
        origin: origin,
        grantedAt: now.addingTimeInterval(-60)
    )
    let local = try LocalSchedule(
        title: "Local wake", prompt: "Stay on this Mac", selection: .defaultLocal,
        boundary: .onDevice, intervalSeconds: 0, nextRun: now
    )
    let external = try LocalSchedule(
        title: "Cloud wake", prompt: "Use the exact reviewed route", selection: selection,
        boundary: .cloud, unattendedConsent: consent, intervalSeconds: 0, nextRun: now
    )
    let localNetwork = try LocalSchedule(
        title: "Network wake", prompt: "Use the exact reviewed LAN route", selection: selection,
        boundary: .localNetwork, unattendedConsent: localNetworkConsent,
        intervalSeconds: 0, nextRun: now
    )

    func document(_ schedule: LocalSchedule) throws -> [[String: Any]] {
        let data = try JSONEncoder().encode([schedule])
        return try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
    }
    func evaluate(_ value: Any) throws -> Bool {
        try? FileManager.default.removeItem(at: store.schedulesURL)
        let data = try JSONSerialization.data(withJSONObject: value)
        try writePrivateScheduleFixture(data, to: store.schedulesURL)
        return SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now)
    }
    func mutated(
        _ schedule: LocalSchedule,
        _ change: (inout [String: Any]) -> Void
    ) throws -> [[String: Any]] {
        var result = try document(schedule)
        change(&result[0])
        return result
    }

    #expect(try evaluate(document(local)))
    #expect(try evaluate(document(external)))
    #expect(try evaluate(document(localNetwork)))

    let legacy = LegacyScheduleFixture(
        id: UUID(), title: "Legacy local wake", prompt: "Remain on device",
        model: "qwen3:27b", intervalSeconds: 60, nextRun: now,
        enabled: true, lastRun: nil
    )
    #expect(try evaluate(JSONSerialization.jsonObject(with: JSONEncoder().encode([legacy]))))

    let externalDocument = try document(external)
    let externalConsent = try #require(externalDocument[0]["unattendedConsent"])
    #expect(!(try evaluate(mutated(local) { item in
        item["unattendedConsent"] = externalConsent
    })))
    #expect(!(try evaluate(mutated(external) { $0.removeValue(forKey: "unattendedConsent") })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        grant["schemaVersion"] = 1
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        grant["provider"] = "different-provider"
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        grant["model"] = "different-model"
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        grant["boundary"] = "localNetwork"
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        grant.removeValue(forKey: "origin")
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        var invalidOrigin = grant["origin"] as? [String: Any] ?? [:]
        invalidOrigin["scheme"] = "file"
        grant["origin"] = invalidOrigin
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { item in
        var grant = item["unattendedConsent"] as? [String: Any] ?? [:]
        var invalidOrigin = grant["origin"] as? [String: Any] ?? [:]
        invalidOrigin["host"] = "not:an-ipv6-literal"
        grant["origin"] = invalidOrigin
        item["unattendedConsent"] = grant
    })))
    #expect(!(try evaluate(mutated(external) { $0["enabled"] = false })))
    #expect(!(try evaluate(mutated(external) {
        $0["nextRun"] = now.addingTimeInterval(1).timeIntervalSinceReferenceDate
    })))
    #expect(!(try evaluate([try document(local)[0], "malformed-array-member"])))

    var revokedExternal = try document(external)[0]
    revokedExternal["enabled"] = false
    revokedExternal.removeValue(forKey: "unattendedConsent")
    #expect(!(try evaluate([revokedExternal])))
    #expect(try evaluate([revokedExternal, try document(local)[0]]))

    var disabledWithStaleConsent = try document(external)[0]
    disabledWithStaleConsent["enabled"] = false
    var staleGrant = disabledWithStaleConsent["unattendedConsent"] as? [String: Any] ?? [:]
    staleGrant["provider"] = "retired-provider"
    staleGrant["boundary"] = "localNetwork"
    disabledWithStaleConsent["unattendedConsent"] = staleGrant
    #expect(try evaluate([disabledWithStaleConsent, try document(local)[0]]))

    var reenabledWithStaleConsent = disabledWithStaleConsent
    reenabledWithStaleConsent["enabled"] = true
    #expect(!(try evaluate([reenabledWithStaleConsent, try document(local)[0]])))

    var disabledWithMalformedConsent = disabledWithStaleConsent
    var malformedGrant = disabledWithMalformedConsent["unattendedConsent"] as? [String: Any] ?? [:]
    malformedGrant["provider"] = 7
    disabledWithMalformedConsent["unattendedConsent"] = malformedGrant
    #expect(!(try evaluate([disabledWithMalformedConsent, try document(local)[0]])))

    var malformedEnabled = try document(external)[0]
    malformedEnabled["enabled"] = "false"
    #expect(!(try evaluate([malformedEnabled, try document(local)[0]])))
}

@Test func schedulerWakePolicyAcceptsCanonicalIPv6ULAConsentOrigin() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let selection = makeScheduleSelection(provider: "lan-provider", model: "lan-model")
    let origin = try #require(
        ProviderEndpointOrigin(url: URL(string: "http://[fd00::1]:8080/v1")!)
    )
    #expect(origin.host == "fd00::1")
    let consent = try ScheduleUnattendedConsent(
        selection: selection,
        boundary: .localNetwork,
        origin: origin,
        grantedAt: now.addingTimeInterval(-60)
    )
    let due = try LocalSchedule(
        title: "IPv6 LAN wake",
        prompt: "Use the reviewed ULA origin",
        selection: selection,
        boundary: .localNetwork,
        unattendedConsent: consent,
        intervalSeconds: 0,
        nextRun: now
    )

    try store.save([due])
    #expect(SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
}

@Test func schedulerHelperLaunchPlanTargetsItsExactEnclosingCopyNotBundleRegistration() throws {
    let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        .appendingPathComponent("scheduler-helper-plan-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try makeSchedulerHelperFixture(root: root, appName: "First Copy.app")
    let second = try makeSchedulerHelperFixture(root: root, appName: "Second Copy.app")

    let plan = try SchedulerWakePolicy.launchPlan(helperExecutable: second.helper) { app, helper in
        #expect(app == second.app)
        #expect(helper == second.helper)
        return true
    }

    #expect(plan.applicationURL == second.app)
    #expect(plan.applicationURL != first.app)
    #expect(plan.openArguments == [
        "-gj", second.app.path, "--args", "--background-schedule"
    ])
    #expect(!plan.openArguments.contains(SchedulerWakePolicy.applicationBundleIdentifier))
    try SchedulerWakePolicy.revalidate(plan, helperExecutable: second.helper) { app, helper in
        app == second.app && helper == second.helper
    }

    // A path swap after planning is detected before `/usr/bin/open` runs.
    try Data("changed plist bytes".utf8).write(
        to: second.app.appendingPathComponent("Contents/Info.plist"),
        options: .atomic
    )
    #expect(throws: SchedulerHelperLaunchError.applicationChanged) {
        try SchedulerWakePolicy.revalidate(plan, helperExecutable: second.helper) { _, _ in true }
    }
}

@Test func schedulerHelperLaunchPlanRejectsInvalidPlacementLinksAndWritableTopology() throws {
    let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        .appendingPathComponent("scheduler-helper-invalid-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let outside = root.appendingPathComponent("LocalHarnessSchedulerHelper")
    try Data("outside".utf8).write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: outside.path)
    #expect(throws: SchedulerHelperLaunchError.invalidBundleTopology) {
        try SchedulerWakePolicy.launchPlan(helperExecutable: outside) { _, _ in true }
    }

    let linked = try makeSchedulerHelperFixture(root: root, appName: "Linked.app")
    try FileManager.default.removeItem(at: linked.helper)
    try FileManager.default.createSymbolicLink(at: linked.helper, withDestinationURL: outside)
    #expect(throws: SchedulerHelperLaunchError.invalidBundleTopology) {
        try SchedulerWakePolicy.launchPlan(helperExecutable: linked.helper) { _, _ in true }
    }

    let writable = try makeSchedulerHelperFixture(root: root, appName: "Writable.app")
    let macOS = writable.app.appendingPathComponent("Contents/MacOS", isDirectory: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: macOS.path)
    #expect(throws: SchedulerHelperLaunchError.invalidBundleTopology) {
        try SchedulerWakePolicy.launchPlan(helperExecutable: writable.helper) { _, _ in true }
    }
}

@Test func schedulerHelperLaunchProcessBoundsHungOpenAndPreservesUnrelatedProcesses() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "scheduler-open-deadline-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executable = root.appendingPathComponent("hung-open")
    try Data("#!/bin/sh\ntrap '' TERM INT HUP\nwhile :; do /bin/sleep 1; done\n".utf8)
        .write(to: executable, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/bin/sleep")
    unrelated.arguments = ["30"]
    try unrelated.run()
    defer {
        if unrelated.isRunning { _ = Darwin.kill(unrelated.processIdentifier, SIGKILL) }
        #expect(boundedTestWaitForExit(unrelated, timeout: 3))
    }

    var processGroup: pid_t = 0
    let started = Date()
    let status = SchedulerWakePolicy.runLaunchProcess(
        executable: executable,
        arguments: ["ignored"],
        environment: ["PATH": "/usr/bin:/bin"],
        deadline: 0.1,
        terminationGrace: 0.05,
        onSpawn: { processGroup = $0 }
    )
    #expect(status == 1)
    #expect(Date().timeIntervalSince(started) < 2)
    #expect(processGroup > 1)
    let cleanupDeadline = Date().addingTimeInterval(2)
    while Date() < cleanupDeadline, Darwin.kill(-processGroup, 0) == 0 { usleep(10_000) }
    #expect(Darwin.kill(-processGroup, 0) != 0 && errno == ESRCH)
    #expect(unrelated.isRunning)

    #expect(SchedulerWakePolicy.runLaunchProcess(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "exit 7"],
        environment: ["PATH": "/usr/bin:/bin"],
        deadline: 1
    ) == 7)
}

@Test(.disabled(
    if: ProcessInfo.processInfo.environment["LOCAL_HARNESS_TEST_APP_PATH"] == nil,
    "Requires the release runner's exact extracted application fixture."
))
func extractedCandidateSchedulerHelperPassesStrictNestedAttestationWhenProvided() throws {
    let path = try #require(
        ProcessInfo.processInfo.environment["LOCAL_HARNESS_TEST_APP_PATH"]
    )
    let app = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
    let helper = app.appendingPathComponent(
        "Contents/MacOS/LocalHarnessSchedulerHelper",
        isDirectory: false
    )
    let plan = try SchedulerWakePolicy.validatedLaunchPlan(helperExecutable: helper)
    #expect(plan.applicationURL == app)
    #expect(plan.openArguments == ["-gj", app.path, "--args", "--background-schedule"])
    try SchedulerWakePolicy.revalidate(plan, helperExecutable: helper)
}

@Test func schedulerWakePolicyRejectsLinkedPublicMalformedOversizedAndExcessiveInputs() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let due = try LocalSchedule(
        title: "Wake securely", prompt: "Validate storage", selection: .defaultLocal,
        boundary: .onDevice, intervalSeconds: 0, nextRun: now
    )
    let encoded = try JSONEncoder().encode([due])

    try encoded.write(to: store.schedulesURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: store.schedulesURL.path)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    try FileManager.default.removeItem(at: store.schedulesURL)
    let outside = root.appendingPathComponent("wake-outside.json")
    try encoded.write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    try FileManager.default.createSymbolicLink(at: store.schedulesURL, withDestinationURL: outside)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    try FileManager.default.removeItem(at: store.schedulesURL)
    try FileManager.default.linkItem(at: outside, to: store.schedulesURL)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    try FileManager.default.removeItem(at: store.schedulesURL)
    try Data("not-json".utf8).write(to: store.schedulesURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.schedulesURL.path)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    try FileManager.default.removeItem(at: store.schedulesURL)
    try Data(repeating: 0x20, count: SchedulerWakePolicy.maximumDocumentBytes + 1).write(to: store.schedulesURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.schedulesURL.path)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))

    try FileManager.default.removeItem(at: store.schedulesURL)
    try JSONEncoder().encode(Array(repeating: due, count: SchedulerWakePolicy.maximumScheduleCount + 1))
        .write(to: store.schedulesURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.schedulesURL.path)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
}

@Test func schedulerWakePolicyRejectsPublicAncestorsAndSpecialFilesWithoutBlocking() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let due = try LocalSchedule(
        title: "Ancestor test", prompt: "Stay private", selection: .defaultLocal,
        boundary: .onDevice, intervalSeconds: 0, nextRun: now
    )
    try store.save([due])
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: store.directory.path)
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: store.directory.path)

    try FileManager.default.removeItem(at: store.schedulesURL)
    #expect(mkfifo(store.schedulesURL.path, 0o600) == 0)
    let started = ContinuousClock.now
    #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
    #expect(started.duration(to: .now) < .seconds(1))
}

@Test func schedulerWakePolicyRejectsExtendedACLsOnEveryStorageNode() throws {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let due = try LocalSchedule(
        title: "ACL test", prompt: "Reject non-private storage", selection: .defaultLocal,
        boundary: .onDevice, intervalSeconds: 0, nextRun: now
    )

    func expectRejection(_ target: (ScheduleDocumentStore) -> URL) throws {
        let root = temporaryScheduleRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ScheduleDocumentStore(applicationSupport: root)
        try store.save([due])
        try addScheduleReadACL(to: target(store))
        #expect(!SchedulerWakePolicy.shouldWake(schedulesURL: store.schedulesURL, now: now))
    }

    try expectRejection { $0.schedulesURL.deletingLastPathComponent().deletingLastPathComponent() }
    try expectRejection { $0.directory }
    try expectRejection { $0.schedulesURL }
}

@Test func schedulerWakePolicyRejectsDirectoryAndFileSwapsAfterOpening() throws {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let due = try LocalSchedule(
        title: "Identity test", prompt: "Bind every opened node", selection: .defaultLocal,
        boundary: .onDevice, intervalSeconds: 0, nextRun: now
    )
    let encoded = try JSONEncoder().encode([due])

    do {
        let root = temporaryScheduleRoot()
        let displaced = root.deletingLastPathComponent().appendingPathComponent(
            "\(root.lastPathComponent).displaced",
            isDirectory: true
        )
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: displaced)
        }
        let store = try ScheduleDocumentStore(applicationSupport: root)
        try store.save([due])
        let hooks = SchedulerWakePolicyTestHooks(afterOpeningScheduleDirectory: {
            try FileManager.default.moveItem(at: root, to: displaced)
            try FileManager.default.createDirectory(
                at: store.directory,
                withIntermediateDirectories: true
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: root.path
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: store.directory.path
            )
            try writePrivateScheduleFixture(encoded, to: store.schedulesURL)
        })
        #expect(!SchedulerWakePolicy.shouldWake(
            schedulesURL: store.schedulesURL,
            now: now,
            hooks: hooks
        ))
    }

    do {
        let root = temporaryScheduleRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ScheduleDocumentStore(applicationSupport: root)
        try store.save([due])
        let displaced = root.appendingPathComponent("Schedules.displaced", isDirectory: true)
        let hooks = SchedulerWakePolicyTestHooks(afterOpeningScheduleDirectory: {
            try FileManager.default.moveItem(at: store.directory, to: displaced)
            try FileManager.default.createDirectory(
                at: store.directory,
                withIntermediateDirectories: false
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: store.directory.path
            )
            try writePrivateScheduleFixture(encoded, to: store.schedulesURL)
        })
        #expect(!SchedulerWakePolicy.shouldWake(
            schedulesURL: store.schedulesURL,
            now: now,
            hooks: hooks
        ))
    }

    do {
        let root = temporaryScheduleRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ScheduleDocumentStore(applicationSupport: root)
        try store.save([due])
        let displaced = store.directory.appendingPathComponent("schedules.displaced.json")
        let hooks = SchedulerWakePolicyTestHooks(afterOpeningSchedulesFile: {
            try FileManager.default.moveItem(at: store.schedulesURL, to: displaced)
            try writePrivateScheduleFixture(encoded, to: store.schedulesURL)
        })
        #expect(!SchedulerWakePolicy.shouldWake(
            schedulesURL: store.schedulesURL,
            now: now,
            hooks: hooks
        ))
    }
}

@Test func unattendedConsentIsExactAndUnknownProvidersFailClosedAsCloud() throws {
    let selection = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-chat")
    let origin = try #require(ProviderEndpointOrigin(url: URL(string: "https://api.deepseek.com")!))
    let consent = try ScheduleUnattendedConsent(
        selection: selection,
        boundary: .cloud,
        origin: origin,
        grantedAt: Date(timeIntervalSinceReferenceDate: 700_000_000)
    )
    let schedule = try LocalSchedule(
        title: "Cloud task",
        prompt: "Send only after consent",
        selection: selection,
        boundary: .cloud,
        unattendedConsent: consent,
        intervalSeconds: 3_600,
        nextRun: Date()
    )

    #expect(schedule.isAuthorized(for: .cloud, origin: origin))
    #expect(!schedule.isAuthorized(for: .localNetwork, origin: origin))
    #expect(!schedule.isAuthorized(
        for: .cloud,
        origin: ProviderEndpointOrigin(url: URL(string: "https://api.deepseek.example")!)
    ))
    var changed = schedule
    changed.selection = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-reasoner")
    #expect(!changed.isAuthorized(for: .cloud, origin: origin))

    let policy = ScheduleBoundaryPolicy(descriptors: [
        BuiltInProviderDescriptors.openAICompatible(
            id: ProviderID("lab-server"), displayName: "Lab", baseURL: URL(string: "http://192.168.1.2:8080")!,
            boundary: .localNetwork
        ),
        BuiltInProviderDescriptors.openAICompatible(
            id: BuiltInProviderDescriptors.openAI.id, displayName: "Unsafe override",
            baseURL: URL(string: "http://127.0.0.1:9000")!, boundary: .onDevice
        )
    ])
    #expect(policy.boundary(for: ProviderID("unknown-provider")) == .cloud)
    #expect(policy.boundary(for: ProviderID("lab-server")) == .localNetwork)
    #expect(policy.boundary(for: BuiltInProviderDescriptors.openAI.id) == .onDevice)
    #expect(throws: ScheduleValidationError.invalidConsent) {
        _ = try ScheduleUnattendedConsent(
            selection: .defaultLocal,
            boundary: .onDevice,
            origin: ProviderEndpointOrigin(url: URL(string: "http://127.0.0.1:11434")!)!
        )
    }
}

@Test func versionOneExternalConsentDecodesButCanNeverAuthorizeARequest() throws {
    let selection = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-chat")
    let origin = try #require(ProviderEndpointOrigin(url: URL(string: "https://api.deepseek.com")!))
    let fixture = LegacyExternalConsentFixture(
        schemaVersion: 1,
        provider: selection.route.provider,
        model: selection.route.model,
        boundary: .cloud,
        grantedAt: Date(timeIntervalSinceReferenceDate: 700_000_000)
    )

    let consent = try JSONDecoder().decode(
        ScheduleUnattendedConsent.self,
        from: JSONEncoder().encode(fixture)
    )
    let schedule = try LocalSchedule(
        title: "Legacy cloud grant",
        prompt: "This must require renewed consent",
        selection: selection,
        boundary: .cloud,
        unattendedConsent: consent,
        intervalSeconds: 3_600,
        nextRun: Date()
    )

    #expect(consent.schemaVersion == 1)
    #expect(consent.origin == nil)
    #expect(!consent.permits(selection: selection, effectiveBoundary: .cloud, effectiveOrigin: origin))
    #expect(!schedule.isAuthorized(for: .cloud, origin: origin))
}

@Test func changingAnExternalProviderOriginRevokesTheExactScheduleGrant() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let selection = makeScheduleSelection(provider: "private-cloud", model: "private-model")
    let initialDescriptor = BuiltInProviderDescriptors.openAICompatible(
        id: selection.route.provider,
        displayName: "Private cloud",
        baseURL: URL(string: "https://first.example/v1")!,
        boundary: .cloud
    )
    let changedDescriptor = BuiltInProviderDescriptors.openAICompatible(
        id: selection.route.provider,
        displayName: "Private cloud",
        baseURL: URL(string: "https://second.example/v1")!,
        boundary: .cloud
    )
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        boundaryPolicy: ScheduleBoundaryPolicy(descriptors: [initialDescriptor], includeBuiltInDefaults: false),
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Origin-bound task",
        prompt: "Only use the reviewed endpoint",
        selection: selection,
        intervalSeconds: 3_600,
        firstRun: now,
        allowUnattendedExternal: true
    )
    let originallyAuthorized = try #require(manager.snapshot().first { $0.id == scheduleID })
    #expect(manager.authorizationStatus(for: originallyAuthorized) == .authorized)
    #expect(originallyAuthorized.unattendedConsent?.origin?.host == "first.example")

    manager.updateVerifiedProviderCatalog(descriptors: [changedDescriptor], activeRoute: selection.route)
    let originChanged = try #require(manager.snapshot().first { $0.id == scheduleID })
    #expect(manager.authorizationStatus(for: originChanged) == .consentRequired(.cloud))
    #expect(manager.origin(for: selection)?.host == "second.example")

    manager.runNow(id: scheduleID)
    #expect(await eventually { manager.inbox().first?.failure?.code == .consentRequired })
    #expect(executor.snapshotRequests().isEmpty)
    #expect(manager.snapshot().first { $0.id == scheduleID }?.enabled == false)
    _ = activity.snapshot()
}

@Test func verifiedScheduleCatalogRejectsAStaleLocalModelBehindTheActiveProvider() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let activity = scheduleActivityStore(applicationSupport: root)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: FakeScheduleExecutor(),
        activities: activity,
        boundaryPolicy: ScheduleBoundaryPolicy(descriptors: [], includeBuiltInDefaults: false),
        enforceActiveProvider: true
    )
    let originallyActive = makeScheduleSelection(provider: "ollama", model: "local-model-b")
    let newlyActive = makeScheduleSelection(provider: "ollama", model: "local-model-a")
    manager.updateVerifiedProviderCatalog(
        descriptors: [BuiltInProviderDescriptors.ollama],
        activeRoute: originallyActive.route
    )
    let id = try manager.add(
        title: "Exact local route",
        prompt: "Never silently use another local model",
        selection: originallyActive,
        intervalSeconds: 3_600
    )

    manager.updateVerifiedProviderCatalog(
        descriptors: [BuiltInProviderDescriptors.ollama],
        activeRoute: newlyActive.route
    )
    let stored = try #require(manager.snapshot().first { $0.id == id })
    #expect(manager.authorizationStatus(for: stored) == .routeInactive(active: newlyActive.route))
    #expect(throws: ScheduleManagerError.routeInactive(active: newlyActive.route)) {
        try manager.authorizeAndEnable(id: id)
    }
    _ = activity.snapshot()
}

@Test func verifiedScheduleCatalogAllowsAnotherCloudModelOnlyWithinTheActiveProvider() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let activity = scheduleActivityStore(applicationSupport: root)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: FakeScheduleExecutor(),
        activities: activity,
        boundaryPolicy: ScheduleBoundaryPolicy(descriptors: [], includeBuiltInDefaults: false),
        enforceActiveProvider: true
    )
    let active = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-chat")
    let alternate = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-reasoner")
    manager.updateVerifiedProviderCatalog(
        descriptors: [BuiltInProviderDescriptors.deepSeekOfficial],
        activeRoute: active.route
    )
    let id = try manager.add(
        title: "Cloud route",
        prompt: "Use another model from the same verified provider",
        selection: alternate,
        intervalSeconds: 3_600,
        allowUnattendedExternal: true
    )
    let stored = try #require(manager.snapshot().first { $0.id == id })
    #expect(manager.authorizationStatus(for: stored) == .authorized)

    let otherProvider = makeScheduleSelection(provider: "openai", model: "gpt-test")
    #expect(throws: ScheduleManagerError.providerInactive(active: active.route.provider)) {
        try manager.add(
            title: "Wrong provider",
            prompt: "Must be rejected",
            selection: otherProvider,
            intervalSeconds: 3_600,
            allowUnattendedExternal: true
        )
    }
    _ = activity.snapshot()
}

@Test func suspendedScheduleAdmissionsBlockRunNowDueWorkAndLateCheckpointCompletion() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let preparation = FakeSchedulePreparation()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        prepareExecution: { schedule, completion in
            preparation.prepare(schedule, completion: completion)
        },
        now: { now }
    )
    let id = try manager.add(
        title: "Admission barrier",
        prompt: "Do not checkpoint or execute across a protected transition",
        selection: .defaultLocal,
        intervalSeconds: 3_600,
        firstRun: now.addingTimeInterval(3_600)
    )

    manager.suspendAdmissionsSynchronously()
    manager.runNow(id: id)
    manager.runDueNow()
    #expect(await remainsTrue { preparation.pendingScheduleIDs().isEmpty })
    #expect(executor.snapshotRequests().isEmpty)
    #expect(manager.admissionsAreSuspended())

    manager.start()
    manager.runNow(id: id)
    #expect(await eventually { preparation.pendingScheduleIDs() == [id] })
    manager.suspendAdmissionsSynchronously()
    preparation.complete(scheduleID: id, with: .success(()))
    #expect(await remainsTrue { executor.snapshotRequests().isEmpty })
    #expect(manager.inbox().isEmpty)
    #expect(manager.admissionsAreSuspended())
    _ = activity.snapshot()
}

@Test func memoryWarningPauseBlocksNewSchedulesWithoutCancellingTheActiveRun() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { now }
    )
    let activeID = try manager.add(
        title: "Already running", prompt: "Finish safely", selection: .defaultLocal,
        intervalSeconds: 3_600, firstRun: now.addingTimeInterval(3_600)
    )
    let waitingID = try manager.add(
        title: "Wait for memory", prompt: "Do not start yet", selection: .defaultLocal,
        intervalSeconds: 3_600, firstRun: now.addingTimeInterval(3_600)
    )

    manager.runNow(id: activeID)
    #expect(await eventually { executor.activeRequests().count == 1 })
    let activeRequest = try #require(executor.activeRequests().first)

    manager.pauseNewAdmissionsSynchronously()
    manager.runNow(id: waitingID)
    #expect(await remainsTrue {
        executor.snapshotRequests().count == 1 && executor.cancelledIDs().isEmpty
    })
    #expect(executor.activeRequests().map(\.0) == [activeRequest.0])

    executor.complete(activeRequest.0, with: .success(ScheduleConversationOutput(
        sessionID: HarnessSessionID("memory-warning-active"),
        selection: .defaultLocal,
        response: "Finished under Eco mode",
        truncated: false
    )))
    #expect(await eventually { manager.inbox().contains { $0.scheduleID == activeID } })
    manager.runNow(id: waitingID)
    #expect(await remainsTrue { executor.snapshotRequests().count == 1 })

    manager.resumeAdmissionsAndRunDue()
    manager.runNow(id: waitingID)
    #expect(await eventually { executor.snapshotRequests().count == 2 })
    _ = activity.snapshot()
}

@Test func managerRequiresExplicitExternalConsentAndPersistsExactGrant() throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { now }
    )
    let selection = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-chat")

    #expect(throws: ScheduleManagerError.consentRequired(.cloud)) {
        try manager.add(
            title: "Cloud task", prompt: "External prompt", selection: selection,
            intervalSeconds: 3_600, firstRun: now
        )
    }
    #expect(manager.snapshot().isEmpty)

    let id = try manager.add(
        title: "Cloud task", prompt: "External prompt", selection: selection,
        intervalSeconds: 3_600, firstRun: now, allowUnattendedExternal: true
    )
    let stored = try #require(manager.snapshot().first { $0.id == id })
    #expect(stored.boundary == .cloud)
    #expect(stored.unattendedConsent?.provider == selection.route.provider)
    #expect(stored.unattendedConsent?.model == selection.route.model)
    #expect(manager.authorizationStatus(for: stored) == .authorized)

    try manager.revokeUnattendedConsent(id: id)
    let revoked = try #require(manager.snapshot().first { $0.id == id })
    #expect(!revoked.enabled)
    #expect(revoked.unattendedConsent == nil)
    #expect(manager.authorizationStatus(for: revoked) == .consentRequired(.cloud))
    _ = activity.snapshot()
}

@Test func managerExecutesTypedRouteThroughInjectedHarnessExecutorAndWritesInbox() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen3:27b")
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Local Harness task",
        prompt: "Use the typed Harness route",
        selection: selection,
        intervalSeconds: 0,
        timeoutSeconds: 120,
        firstRun: now
    )

    manager.runNow(id: scheduleID)
    #expect(await eventually { executor.snapshotRequests().count == 1 })
    let requestEntry = try #require(executor.snapshotRequests().first)
    #expect(requestEntry.value.selection == selection)
    #expect(requestEntry.value.prompt == "Use the typed Harness route")
    #expect(requestEntry.value.timeoutSeconds == 120)
    #expect(requestEntry.value.workspace.lastPathComponent == scheduleID.uuidString)

    let output = ScheduleConversationOutput(
        sessionID: HarnessSessionID("scheduled/session:opaque"),
        selection: selection,
        response: "Harness result",
        truncated: false
    )
    executor.complete(requestEntry.key, with: .success(output))
    #expect(await eventually { manager.inbox().count == 1 })

    let result = try #require(manager.inbox().first)
    #expect(result.scheduleID == scheduleID)
    #expect(result.selection == selection)
    #expect(result.boundary == .onDevice)
    #expect(result.sessionID == output.sessionID)
    #expect(result.response == "Harness result")
    #expect(result.failure == nil)
    #expect(manager.snapshot().first?.enabled == false)
    _ = activity.snapshot()
}

@Test func completedScheduleNeverClaimsAnUnsavedInboxResult() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Unsavable result",
        prompt: "Complete but fail the Inbox append",
        selection: .defaultLocal,
        intervalSeconds: 0,
        firstRun: now
    )
    manager.runNow(id: scheduleID)
    #expect(await eventually { executor.snapshotRequests().count == 1 })
    let request = try #require(executor.snapshotRequests().first)

    let inbox = root.appendingPathComponent("Schedules/Inbox", isDirectory: true)
    let unknown = inbox.appendingPathComponent("unowned-entry.txt")
    try Data("must block mutation".utf8).write(to: unknown)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: unknown.path)
    executor.complete(request.key, with: .success(ScheduleConversationOutput(
        sessionID: HarnessSessionID("unsaved-session"),
        selection: .defaultLocal,
        response: "This response must not be falsely reported as saved.",
        truncated: false
    )))

    #expect(await eventually {
        activity.snapshot().contains {
            $0.kind == .schedule && $0.title == "Unsavable result" && $0.state == .failed
        }
    })
    let finalActivity = try #require(activity.snapshot().first {
        $0.kind == .schedule && $0.title == "Unsavable result"
    })
    #expect(finalActivity.state == .failed)
    #expect(finalActivity.detail.contains("could not be saved"))
    #expect(!finalActivity.detail.contains("Result saved"))
    #expect(manager.storageIssue() != nil)
    #expect(manager.inbox().isEmpty)
}

@Test func crashAfterExternalModelSuccessBeforeAnyResultWriteNeverRepeatsOccurrence() async throws {
    try await assertExternalOccurrenceIsReconciledAtMostOnce(
        failurePoint: .afterExecutionCompletionBeforeReceiptCommit,
        expectsCommittedResponse: false
    )
}

@Test func crashAfterInboxCommitBeforeScheduleCommitNeverRepeatsExternalOccurrence() async throws {
    try await assertExternalOccurrenceIsReconciledAtMostOnce(
        failurePoint: .afterResultCommitBeforeScheduleCommit,
        expectsCommittedResponse: true
    )
}

private func assertExternalOccurrenceIsReconciledAtMostOnce(
    failurePoint: ScheduleDurabilityFailurePoint,
    expectsCommittedResponse: Bool
) async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let startedAt = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let completedAt = startedAt.addingTimeInterval(10)
    let clock = ScheduleTestClock(startedAt)
    let firstExecutor = FakeScheduleExecutor()
    let failureScript = ScheduleDurabilityFailureScript(point: failurePoint)
    let selection = makeScheduleSelection(provider: "deepseek-official", model: "deepseek-chat")
    var firstManager: ScheduleManager? = ScheduleManager(
        applicationSupport: root,
        executor: firstExecutor,
        activities: scheduleActivityStore(applicationSupport: root),
        now: { clock.now() },
        durabilityFailureInjector: { try failureScript.inject($0) }
    )
    let scheduleID = try #require(firstManager).add(
        title: "At-most-once external task",
        prompt: "This provider-backed occurrence must never be billed twice",
        selection: selection,
        intervalSeconds: 0,
        firstRun: startedAt,
        allowUnattendedExternal: true
    )
    // The persisted nextRun is overdue when the injected crash boundary
    // fires; without journal reconciliation a fresh manager would dispatch it.
    clock.set(completedAt)
    firstManager?.runNow(id: scheduleID)
    #expect(await eventually { firstExecutor.activeRequests().count == 1 })
    let request = try #require(firstExecutor.activeRequests().first)
    firstExecutor.complete(
        request.0,
        with: .success(ScheduleConversationOutput(
            sessionID: HarnessSessionID("external/charged-once"),
            selection: request.1.selection,
            response: "billable provider result",
            truncated: false
        ))
    )
    #expect(await eventually { firstManager?.storageIssue()?.contains("will not be sent") == true })
    #expect(firstExecutor.orderedRequests().count == 1)

    let journalStore = try ScheduleDocumentStore(applicationSupport: root, now: { clock.now() })
    #expect(try journalStore.pendingOccurrenceCount() == 1)
    firstManager = nil // model a fresh process using only durable bytes

    let secondExecutor = FakeScheduleExecutor()
    let relaunched = ScheduleManager(
        applicationSupport: root,
        executor: secondExecutor,
        activities: scheduleActivityStore(applicationSupport: root),
        now: { clock.now() }
    )
    let reconciled = try #require(relaunched.snapshot().first { $0.id == scheduleID })
    #expect(!reconciled.enabled)
    #expect(reconciled.lastRun == completedAt)
    #expect(try journalStore.pendingOccurrenceCount() == 0)

    relaunched.runDueNow()
    #expect(await remainsTrue { secondExecutor.snapshotRequests().isEmpty })
    #expect(firstExecutor.orderedRequests().count + secondExecutor.orderedRequests().count == 1)
    let inbox = relaunched.inbox()
    #expect(inbox.count == 1)
    if expectsCommittedResponse {
        #expect(inbox.first?.response == "billable provider result")
        #expect(inbox.first?.failure == nil)
    } else {
        #expect(inbox.first?.response.isEmpty == true)
        #expect(inbox.first?.failure?.code == .interrupted)
    }
}

@Test func failedExecutionPreparationNeverReachesExecutorAndRecordsCheckpointFailure() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        prepareExecution: { _, completion in
            completion(.failure(SchedulePreparationTestError.checkpointUnavailable))
        },
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Protected task",
        prompt: "Do not run without a checkpoint",
        selection: .defaultLocal,
        intervalSeconds: 3_600,
        firstRun: now
    )

    manager.runNow(id: scheduleID)
    #expect(await eventually { manager.inbox().first?.failure?.code == .checkpointFailed })

    let result = try #require(manager.inbox().first)
    #expect(executor.snapshotRequests().isEmpty)
    #expect(result.scheduleID == scheduleID)
    #expect(result.failure?.code == .checkpointFailed)
    #expect(result.failure?.detail == nil)
    #expect(result.failure?.displayMessage == "A recovery point could not be created, so the task did not run.")
    let rescheduled = try #require(manager.snapshot().first { $0.id == scheduleID })
    #expect(rescheduled.enabled)
    #expect(rescheduled.lastRun == now)
    #expect(rescheduled.nextRun == now.addingTimeInterval(60))
    let activityText = activity.snapshot().map { "\($0.title) \($0.detail)" }.joined(separator: "\n")
    #expect(!activityText.contains("sk-schedule-secret"))
    #expect(!activityText.contains("/Users/private/schedule"))
    #expect(!activityText.contains("HOSTILE-CHECKPOINT-DIAGNOSTIC"))

    let persistedText = ((FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]))?
        .compactMap { $0 as? URL }
        .filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
        .compactMap { try? String(contentsOf: $0, encoding: .utf8) } ?? [])
        .joined(separator: "\n")
    #expect(!persistedText.contains("sk-schedule-secret"))
    #expect(!persistedText.contains("/Users/private/schedule"))
    #expect(!persistedText.contains("HOSTILE-CHECKPOINT-DIAGNOSTIC"))
}

@Test func backgroundScheduleIdleCallbackIsOneShotWhenNothingIsDue() async {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let recorder = ScheduleIdleRecorder()
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: FakeScheduleExecutor(),
        activities: scheduleActivityStore(applicationSupport: root)
    )
    manager.onIdleAfterRun = { recorder.record() }

    manager.runDueNow()
    #expect(await eventually { recorder.count == 1 })
    manager.runDueNow()
    manager.stop()
    try? await Task.sleep(for: .milliseconds(100))
    #expect(recorder.count == 1)
}

@Test func schedulerStopThenImmediateStartPreservesTheLatestReadyIntent() {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: FakeScheduleExecutor(),
        activities: scheduleActivityStore(applicationSupport: root)
    )

    manager.start()
    #expect(manager.pollingEnabled())
    manager.stop()
    manager.start()

    // pollingEnabled synchronizes behind both queued lifecycle requests. The
    // later Ready/start intent must win even when Stop has not drained yet.
    #expect(manager.pollingEnabled())
    manager.stop()
    #expect(!manager.pollingEnabled())
}

@Test func backgroundScheduleWaitsForTheDueResultThenPublishesIdleExactlyOnce() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let recorder = ScheduleIdleRecorder()
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let clock = ScheduleTestClock(now)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: scheduleActivityStore(applicationSupport: root),
        now: { clock.now() }
    )
    _ = try manager.add(
        title: "One-shot background task",
        prompt: "Finish before quitting",
        selection: .defaultLocal,
        intervalSeconds: 0,
        firstRun: now
    )
    clock.set(now.addingTimeInterval(5))
    manager.onIdleAfterRun = { recorder.record() }

    manager.runDueNow()
    #expect(await eventually { executor.activeRequests().count == 1 })
    #expect(recorder.count == 0)
    let request = try #require(executor.activeRequests().first)
    executor.complete(
        request.0,
        with: .success(ScheduleConversationOutput(
            sessionID: HarnessSessionID("background/one-shot"),
            selection: request.1.selection,
            response: "finished",
            truncated: false
        ))
    )
    #expect(await eventually { recorder.count == 1 })
    manager.runDueNow()
    manager.stop()
    try? await Task.sleep(for: .milliseconds(100))
    #expect(recorder.count == 1)
    #expect(manager.inbox().count == 1)
}

@Test func manualAndDueSchedulesDrainSeriallyInFifoThenNextRunOrder() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let start = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let clock = ScheduleTestClock(start)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { clock.now() }
    )
    _ = try manager.add(
        title: "Due early", prompt: "due-early", selection: .defaultLocal,
        intervalSeconds: 60, firstRun: start.addingTimeInterval(5)
    )
    _ = try manager.add(
        title: "Due late", prompt: "due-late", selection: .defaultLocal,
        intervalSeconds: 60, firstRun: start.addingTimeInterval(10)
    )
    let manualFirst = try manager.add(
        title: "Manual first", prompt: "manual-first", selection: .defaultLocal,
        intervalSeconds: 60, firstRun: start.addingTimeInterval(1_000)
    )
    let manualSecond = try manager.add(
        title: "Manual second", prompt: "manual-second", selection: .defaultLocal,
        intervalSeconds: 60, firstRun: start.addingTimeInterval(1_100)
    )
    let completionTime = start.addingTimeInterval(30)
    clock.set(completionTime)

    manager.runNow(id: manualFirst)
    manager.runNow(id: manualSecond)
    manager.runDueNow()

    let expectedPrompts = ["manual-first", "manual-second", "due-early", "due-late"]
    for (index, expectedPrompt) in expectedPrompts.enumerated() {
        #expect(await eventually { executor.orderedRequests().count == index + 1 })
        let active = executor.activeRequests()
        #expect(active.count == 1)
        let request = try #require(active.first)
        #expect(request.1.prompt == expectedPrompt)
        #expect(executor.maximumConcurrentRequestCount() == 1)
        executor.complete(
            request.0,
            with: .success(ScheduleConversationOutput(
                sessionID: HarnessSessionID("serial/\(index)"),
                selection: request.1.selection,
                response: "completed \(expectedPrompt)",
                truncated: false
            ))
        )
    }

    #expect(await eventually { manager.inbox().count == expectedPrompts.count })
    #expect(await eventually { manager.runningScheduleIDs().isEmpty })
    #expect(executor.orderedRequests().map(\.prompt) == expectedPrompts)
    #expect(executor.maximumConcurrentRequestCount() == 1)
    #expect(manager.snapshot().allSatisfy { $0.lastRun == completionTime })
    #expect(manager.snapshot().allSatisfy { $0.nextRun == completionTime.addingTimeInterval(60) })
    _ = activity.snapshot()
}

@Test func quiescingDuringPreparationInvalidatesAndIgnoresLateSuccess() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let preparation = FakeSchedulePreparation()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        prepareExecution: { schedule, completion in
            preparation.prepare(schedule, completion: completion)
        },
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Quiesce preparation",
        prompt: "This must never start after the barrier",
        selection: .defaultLocal,
        intervalSeconds: 3_600,
        firstRun: now
    )

    manager.runNow(id: scheduleID)
    #expect(await eventually { preparation.pendingScheduleIDs() == [scheduleID] })
    #expect(manager.runningScheduleIDs() == [scheduleID])

    await withCheckedContinuation { continuation in
        manager.quiesce { continuation.resume() }
    }
    #expect(manager.runningScheduleIDs().isEmpty)
    #expect(executor.snapshotRequests().isEmpty)

    preparation.complete(scheduleID: scheduleID, with: .success(()))
    #expect(await remainsTrue { executor.snapshotRequests().isEmpty })
    #expect(manager.inbox().isEmpty)
    #expect(manager.snapshot().first { $0.id == scheduleID }?.lastRun == nil)
    _ = activity.snapshot()
}

@Test func managerUsesAuthoritativeSandboxWorkspaceWhenHostSuppliesIt() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let sharedWorkspace = root.appendingPathComponent("Authoritative Workspace", isDirectory: true)
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        executionWorkspace: sharedWorkspace,
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Shared workspace route",
        prompt: "Create a file",
        selection: .defaultLocal,
        intervalSeconds: 3_600,
        firstRun: now
    )

    manager.runNow(id: scheduleID)
    #expect(await eventually { executor.snapshotRequests().count == 1 })
    let request = executor.snapshotRequests().first?.value

    #expect(request?.workspace.standardizedFileURL == sharedWorkspace.standardizedFileURL)
    #expect(FileManager.default.fileExists(atPath: sharedWorkspace.path))
    _ = activity.snapshot()
}

@Test func managerBlocksTamperedBoundaryBeforeExecutorAndDisablesSchedule() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try ScheduleDocumentStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let selection = makeScheduleSelection(provider: "unknown-provider", model: "private-model")
    let tampered = try LocalSchedule(
        title: "Tampered boundary",
        prompt: "Must not leave this Mac",
        selection: selection,
        boundary: .onDevice,
        intervalSeconds: 3_600,
        nextRun: now
    )
    try store.save([tampered])
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { now }
    )

    manager.runNow(id: tampered.id)
    #expect(await eventually { manager.inbox().count == 1 })

    #expect(executor.snapshotRequests().isEmpty)
    #expect(manager.snapshot().first?.enabled == false)
    #expect(manager.inbox().first?.failure?.code == .consentRequired)
    #expect(manager.inbox().first?.boundary == .cloud)
    _ = activity.snapshot()
}

@Test func managerCancellationPropagatesToExecutorAndProducesSanitizedResult() async throws {
    let root = temporaryScheduleRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = FakeScheduleExecutor()
    let activity = scheduleActivityStore(applicationSupport: root)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let manager = ScheduleManager(
        applicationSupport: root,
        executor: executor,
        activities: activity,
        now: { now }
    )
    let scheduleID = try manager.add(
        title: "Cancel me", prompt: "Wait", selection: .defaultLocal,
        intervalSeconds: 3_600, firstRun: now
    )
    manager.runNow(id: scheduleID)
    #expect(await eventually { manager.runningScheduleIDs().contains(scheduleID) })

    manager.cancelRun(id: scheduleID)
    #expect(await eventually { manager.inbox().first?.failure?.code == .cancelled })
    #expect(executor.cancelledIDs().count == 1)
    #expect(!manager.runningScheduleIDs().contains(scheduleID))
    _ = activity.snapshot()
}

@Test func harnessScheduleExecutorUsesNormalizedSessionRouteAndFinalMessage() async throws {
    let requestSelection = makeScheduleSelection(provider: "ollama", model: "requested")
    let normalized = HarnessWireModelSelection(
        provider: ProviderID("deepseek"), model: ModelID("deepseek-chat"), reasoningEffort: "high"
    )
    let service = FakeHarnessScheduleService(behavior: .success, normalizedSelection: normalized)
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let request = ScheduleConversationRequest(
        selection: requestSelection,
        prompt: "Scheduled private prompt",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )

    let result = await execute(executor, request: request)
    let output = try result.get()

    #expect(output.sessionID == HarnessSessionID("schedule/session:1"))
    #expect(output.selection.route == normalized.route)
    #expect(output.selection.reasoningEffort == "high")
    #expect(output.selection.performanceProfile == requestSelection.performanceProfile)
    #expect(output.response == "final answer")
    #expect(!output.truncated)
    #expect(service.promptSnapshot() == [[.text("Scheduled private prompt")]])
}

@Test func harnessScheduleExecutorRetainsEveryAutomaticContinuationSegment() async throws {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let normalized = HarnessWireModelSelection(route: selection.route)
    let service = FakeHarnessScheduleService(
        behavior: .automaticContinuation,
        normalizedSelection: normalized
    )
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let output = try await execute(executor, request: ScheduleConversationRequest(
        selection: selection,
        prompt: "Finish without manual continue",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )).get()

    #expect(output.response == "first segment\n\nsecond segment")
    #expect(!output.truncated)
    #expect(service.cancellationCount() == 0)
}

@Test func harnessScheduleExecutorRejectsAggregateAutomaticContinuationOverflowIncludingSeparator() async {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let service = FakeHarnessScheduleService(
        behavior: .automaticContinuationAggregateOverflow,
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let result = await execute(executor, request: ScheduleConversationRequest(
        selection: selection,
        prompt: "Keep every segment inside the aggregate persistence boundary",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    ))

    #expect(result == .failure(.responseTooLarge))
    #expect(await eventually { service.cancellationCount() == 1 })
    try? await Task.sleep(for: .milliseconds(50))
    #expect(service.cancellationCount() == 1)
}

@Test func harnessScheduleExecutorForcesUnknownLocalModelsIntoNonReasoningCompatibilityMode() async throws {
    let requestSelection = makeScheduleSelection(provider: "ollama", model: "requested")
    let normalized = HarnessWireModelSelection(
        provider: ProviderID("ollama"), model: ModelID("another-tool-model"), reasoningEffort: "high"
    )
    let service = FakeHarnessScheduleService(behavior: .success, normalizedSelection: normalized)
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let request = ScheduleConversationRequest(
        selection: requestSelection,
        prompt: "Scheduled private prompt",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )

    let output = try await execute(executor, request: request).get()
    #expect(output.selection.route == normalized.route)
    #expect(output.selection.reasoningEffort == nil)
    #expect(output.selection.performanceProfile == .compatibility)
}

@Test func harnessScheduleExecutorRejectsUnattendedInteractionAndCancelsTransport() async {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let service = FakeHarnessScheduleService(
        behavior: .approval,
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let request = ScheduleConversationRequest(
        selection: selection,
        prompt: "Do not approve tools",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )

    let result = await execute(executor, request: request)

    #expect(result == .failure(.interactionRequired))
    #expect(await eventually { service.rejectedApprovalCount() == 1 })
    #expect(service.cancellationCount() == 1)
}

@Test func harnessScheduleExecutorTimeoutAndCancellationCompleteExactlyOnce() async {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let service = FakeHarnessScheduleService(
        behavior: .pending,
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let request = ScheduleConversationRequest(
        selection: selection,
        prompt: "Wait forever",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 0.1
    )
    let recorder = ScheduleCompletionRecorder()
    let identifier = executor.execute(request) { result in recorder.record(result) }
    #expect(await eventually { recorder.count == 1 })
    #expect(recorder.first == .failure(.timedOut))
    executor.cancel(identifier)
    try? await Task.sleep(for: .milliseconds(50))
    #expect(recorder.count == 1)
    #expect(service.cancellationCount() == 1)

    let secondService = FakeHarnessScheduleService(
        behavior: .pending,
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let secondExecutor = HarnessScheduleConversationExecutor(conversation: secondService)
    let secondRecorder = ScheduleCompletionRecorder()
    let secondID = secondExecutor.execute(request) { result in secondRecorder.record(result) }
    #expect(await eventually { !secondService.promptSnapshot().isEmpty })
    secondExecutor.cancel(secondID)
    #expect(await eventually { secondRecorder.count == 1 })
    #expect(secondRecorder.first == .failure(.cancelled))
    try? await Task.sleep(for: .milliseconds(150))
    #expect(secondRecorder.count == 1)
}

@Test func harnessScheduleExecutorArchivesCancellationInsensitiveLateSessionsExactlyOnce() async throws {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let request = ScheduleConversationRequest(
        selection: selection,
        prompt: "This must never be submitted",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 0.1
    )

    let timeoutGate = ScheduleCreationGate()
    let timeoutService = FakeHarnessScheduleService(
        behavior: .pending,
        normalizedSelection: HarnessWireModelSelection(route: selection.route),
        createGate: timeoutGate
    )
    let timeoutExecutor = HarnessScheduleConversationExecutor(conversation: timeoutService)
    let timeoutRecorder = ScheduleCompletionRecorder()
    _ = timeoutExecutor.execute(request) { timeoutRecorder.record($0) }
    await timeoutGate.waitUntilEntered()
    #expect(await eventually { timeoutRecorder.count == 1 })
    #expect(timeoutRecorder.first == .failure(.timedOut))

    let overlappingRecorder = ScheduleCompletionRecorder()
    _ = timeoutExecutor.execute(request) { overlappingRecorder.record($0) }
    #expect(await eventually { overlappingRecorder.count == 1 })
    #expect(overlappingRecorder.first == .failure(.runtimeUnavailable))
    #expect(timeoutService.creationCount() == 1)

    await timeoutGate.open()
    try await timeoutExecutor.quiesce()
    #expect(timeoutRecorder.count == 1)
    #expect(timeoutService.promptSnapshot().isEmpty)
    #expect(timeoutService.discardedSessionSnapshot() == [HarnessSessionID("schedule/session:1")])

    let cancelGate = ScheduleCreationGate()
    let cancelService = FakeHarnessScheduleService(
        behavior: .pending,
        normalizedSelection: HarnessWireModelSelection(route: selection.route),
        createGate: cancelGate
    )
    let cancelExecutor = HarnessScheduleConversationExecutor(conversation: cancelService)
    let cancelRecorder = ScheduleCompletionRecorder()
    let cancelID = cancelExecutor.execute(request) { cancelRecorder.record($0) }
    await cancelGate.waitUntilEntered()
    cancelExecutor.cancel(cancelID)
    #expect(await eventually { cancelRecorder.count == 1 })
    #expect(cancelRecorder.first == .failure(.cancelled))
    await cancelGate.open()
    try await cancelExecutor.quiesce()
    #expect(cancelRecorder.count == 1)
    #expect(cancelService.promptSnapshot().isEmpty)
    #expect(cancelService.discardedSessionSnapshot() == [HarnessSessionID("schedule/session:1")])
}

@Test func harnessScheduleExecutorArchivesAJustCreatedSessionWhenSendAdmissionCloses() async throws {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let request = ScheduleConversationRequest(
        selection: selection,
        prompt: "Admission closes after create",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )
    let service = FakeHarnessScheduleService(
        behavior: .admissionRejected,
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let executor = HarnessScheduleConversationExecutor(conversation: service)

    #expect(await execute(executor, request: request) == .failure(.runtimeUnavailable))
    try await executor.quiesce()
    #expect(service.promptSnapshot().isEmpty)
    #expect(service.discardedSessionSnapshot() == [HarnessSessionID("schedule/session:1")])

    let unverified = FakeHarnessScheduleService(
        behavior: .admissionRejected,
        normalizedSelection: HarnessWireModelSelection(route: selection.route),
        discardFails: true
    )
    let poisonedExecutor = HarnessScheduleConversationExecutor(conversation: unverified)
    #expect(await execute(poisonedExecutor, request: request) == .failure(.runtimeUnavailable))
    do {
        try await poisonedExecutor.quiesce()
        Issue.record("Unverified post-create admission cleanup unexpectedly crossed quiescence")
    } catch let error as HarnessConversationError {
        #expect(error == .sessionCleanupUnverified)
    } catch {
        Issue.record("Unexpected post-create admission cleanup result: \(error)")
    }
    #expect(unverified.discardedSessionSnapshot() == [HarnessSessionID("schedule/session:1")])
}

@Test func harnessScheduleExecutorQuiescenceFailsClosedWhenLateSessionCleanupIsUnverified() async {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let gate = ScheduleCreationGate()
    let service = FakeHarnessScheduleService(
        behavior: .pending,
        normalizedSelection: HarnessWireModelSelection(route: selection.route),
        createGate: gate,
        discardFails: true
    )
    let executor = HarnessScheduleConversationExecutor(conversation: service)
    let recorder = ScheduleCompletionRecorder()
    _ = executor.execute(ScheduleConversationRequest(
        selection: selection,
        prompt: "Do not submit after timeout",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 0.1
    )) { recorder.record($0) }
    await gate.waitUntilEntered()
    #expect(await eventually { recorder.count == 1 })
    await gate.open()

    do {
        try await executor.quiesce()
        Issue.record("Unverified late-session cleanup unexpectedly crossed quiescence")
    } catch let error as HarnessConversationError {
        #expect(error == .sessionCleanupUnverified)
    } catch {
        Issue.record("Unexpected late-session cleanup error: \(error)")
    }
    #expect(recorder.count == 1)
    #expect(service.promptSnapshot().isEmpty)
    #expect(service.discardedSessionSnapshot() == [HarnessSessionID("schedule/session:1")])

    let blockedRecorder = ScheduleCompletionRecorder()
    _ = executor.execute(ScheduleConversationRequest(
        selection: selection,
        prompt: "A cleanup failure must lock later scheduled work",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )) { blockedRecorder.record($0) }
    #expect(await eventually { blockedRecorder.count == 1 })
    #expect(blockedRecorder.first == .failure(.runtimeUnavailable))
    #expect(service.promptSnapshot().isEmpty)
}

@Test func harnessScheduleExecutorBoundsResponsesAndNeverPersistsProviderMessages() async {
    let selection = makeScheduleSelection(provider: "ollama", model: "qwen")
    let oversizedService = FakeHarnessScheduleService(
        behavior: .oversized,
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let oversizedExecutor = HarnessScheduleConversationExecutor(conversation: oversizedService)
    let request = ScheduleConversationRequest(
        selection: selection,
        prompt: "Bound output",
        workspace: temporaryScheduleRoot(),
        timeoutSeconds: 30
    )
    #expect(await execute(oversizedExecutor, request: request) == .failure(.responseTooLarge))

    let secretMessage = "credential-body-that-must-not-be-retained"
    let failingService = FakeHarnessScheduleService(
        behavior: .creationFailure(HarnessConversationError.turnFailed(ProviderFailurePresentation.classify(
            code: "AUTH-FAILED",
            status: nil,
            requestID: secretMessage
        ))),
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let failure = await execute(HarnessScheduleConversationExecutor(conversation: failingService), request: request)
    #expect(failure == .failure(.providerFailed(category: .credentialRejected)))
    if case .failure(let error) = failure {
        #expect(!error.localizedDescription.contains(secretMessage))
        #expect(!error.resultFailure.displayMessage.contains(secretMessage))
    }

    let hostileSecret = ["sk", "schedule", String(repeating: "h", count: 48)].joined(separator: "-")
    let hostile = "\u{001B}[2J\u{202E}\(hostileSecret)" + String(repeating: "Z", count: 64 * 1_024)
    let rawFailureService = FakeHarnessScheduleService(
        behavior: .creationFailure(HarnessRPCClientError.remote(.init(
            code: .other(hostile),
            message: hostile,
            details: ["reason": .string(hostile)]
        ))),
        normalizedSelection: HarnessWireModelSelection(route: selection.route)
    )
    let rawFailure = await execute(
        HarnessScheduleConversationExecutor(conversation: rawFailureService),
        request: request
    )
    #expect(rawFailure == .failure(.providerFailed(category: .generic)))
    if case .failure(let error) = rawFailure {
        #expect(error.resultFailure.detail == ScheduleProviderFailureCategory.generic.rawValue)
        #expect(error.resultFailure.displayMessage == "The provider failed this task.")
        #expect(!error.localizedDescription.contains(hostileSecret))
    }

    let decodedLegacyProviderDetail = try? JSONDecoder().decode(
        ScheduleResultFailure.self,
        from: Data(#"{"code":"providerFailed","detail":"credential sk-hostile should not survive"}"#.utf8)
    )
    #expect(decodedLegacyProviderDetail == ScheduleResultFailure(code: .providerFailed))
    #expect(decodedLegacyProviderDetail?.displayMessage == "The provider failed this task.")
}

private final class ScheduleCompletionRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var results: [Result<ScheduleConversationOutput, ScheduleExecutionError>] = []

    func record(_ result: Result<ScheduleConversationOutput, ScheduleExecutionError>) {
        lock.lock(); results.append(result); lock.unlock()
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return results.count }
    var first: Result<ScheduleConversationOutput, ScheduleExecutionError>? {
        lock.lock(); defer { lock.unlock() }; return results.first
    }
}

private func execute(
    _ executor: HarnessScheduleConversationExecutor,
    request: ScheduleConversationRequest
) async -> Result<ScheduleConversationOutput, ScheduleExecutionError> {
    await withCheckedContinuation { continuation in
        executor.execute(request) { result in continuation.resume(returning: result) }
    }
}

private func eventually(_ condition: @escaping () -> Bool) async -> Bool {
    for _ in 0..<100 {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

private func remainsTrue(_ condition: @escaping () -> Bool) async -> Bool {
    for _ in 0..<25 {
        if !condition() { return false }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

private func makeScheduleSelection(provider: String, model: String) -> ModelSelection {
    ModelSelection(
        route: ModelRoute(provider: ProviderID(provider), model: ModelID(model)),
        reasoningEffort: nil,
        performanceProfile: .balanced
    )
}

private func makeSchedulerHelperFixture(
    root: URL,
    appName: String
) throws -> (app: URL, helper: URL) {
    let app = root.appendingPathComponent(appName, isDirectory: true).standardizedFileURL
    let contents = app.appendingPathComponent("Contents", isDirectory: true)
    let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
    try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
    for directory in [app, contents, macOS] {
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
    }
    let info = contents.appendingPathComponent("Info.plist")
    try Data("fixture plist".utf8).write(to: info)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: info.path)
    let helper = macOS.appendingPathComponent("LocalHarnessSchedulerHelper")
    try Data("fixture helper".utf8).write(to: helper)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
    return (app, helper)
}

private func temporaryScheduleRoot() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("LocalHarnessSchedules-\(UUID().uuidString)", isDirectory: true)
}

/// ScheduleManager tests must not accidentally exercise an unavailable
/// ActivityStore merely because they construct that store before the schedule
/// document store creates the shared Application Support fixture. Production
/// already supplies an admitted, existing root; make that precondition explicit
/// here so activity assertions cannot pass vacuously.
private func scheduleActivityStore(applicationSupport root: URL) -> ActivityStore {
    do {
        if !FileManager.default.fileExists(atPath: root.path) {
            try FileManager.default.createDirectory(
                at: root,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
        }
        guard chmod(root.path, 0o700) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
    } catch {
        Issue.record("Could not create a private schedule ActivityStore fixture: \(error)")
    }
    let store = ActivityStore(applicationSupport: root)
    #expect(store.status() == .available)
    return store
}

private func writePrivateScheduleFixture(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, 0o600) == 0 else {
        throw ScheduleDocumentStoreError.unsafeStorage
    }
}

private func addScheduleReadACL(to url: URL) throws {
    guard let passwordEntry = getpwuid(geteuid()) else {
        throw ScheduleDocumentStoreError.unsafeStorage
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
        throw ScheduleDocumentStoreError.unsafeStorage
    }
}

private func privateMode(at url: URL) -> Int {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes?[.posixPermissions] as? NSNumber)?.intValue ?? -1
}
