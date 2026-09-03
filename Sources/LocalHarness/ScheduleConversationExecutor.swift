import Foundation

struct ScheduleConversationRequest: Equatable, Sendable {
    let selection: ModelSelection
    let prompt: String
    let workspace: URL
    let timeoutSeconds: TimeInterval
}

struct ScheduleConversationOutput: Equatable, Sendable {
    let sessionID: HarnessSessionID
    let selection: ModelSelection
    let response: String
    let truncated: Bool
}

enum ScheduleExecutionError: Error, Equatable, LocalizedError, Sendable {
    case runtimeUnavailable
    case providerFailed(category: ScheduleProviderFailureCategory)
    case timedOut
    case cancelled
    case interactionRequired
    case responseTooLarge
    case filesystem
    case unknown

    var resultFailure: ScheduleResultFailure {
        switch self {
        case .runtimeUnavailable: return ScheduleResultFailure(code: .runtimeUnavailable)
        case .providerFailed(let category): return ScheduleResultFailure(code: .providerFailed, detail: category.rawValue)
        case .timedOut: return ScheduleResultFailure(code: .timedOut)
        case .cancelled: return ScheduleResultFailure(code: .cancelled)
        case .interactionRequired: return ScheduleResultFailure(code: .interactionRequired)
        case .responseTooLarge: return ScheduleResultFailure(code: .responseTooLarge)
        case .filesystem: return ScheduleResultFailure(code: .filesystem)
        case .unknown: return ScheduleResultFailure(code: .unknown)
        }
    }

    var errorDescription: String? { resultFailure.displayMessage }
}

enum ScheduleProviderFailureCategory: String, Codable, Equatable, Sendable {
    case credentialMissing
    case credentialRecoveryRequired
    case credentialRejected
    case insufficientCredit
    case rateLimited
    case temporarilyUnavailable
    case modelUnavailable
    case contextWindowExceeded
    case toolFailure
    case blocked
    case interrupted
    case invalidResponse
    case generic

    init(_ providerKind: ProviderFailureKind) {
        switch providerKind {
        case .credentialMissing: self = .credentialMissing
        case .credentialRecoveryRequired: self = .credentialRecoveryRequired
        case .credentialRejected: self = .credentialRejected
        case .insufficientCredit: self = .insufficientCredit
        case .rateLimited: self = .rateLimited
        case .temporarilyUnavailable: self = .temporarilyUnavailable
        case .modelUnavailable: self = .modelUnavailable
        case .contextWindowExceeded: self = .contextWindowExceeded
        case .toolFailure: self = .toolFailure
        case .generic: self = .generic
        }
    }

    var displayMessage: String {
        switch self {
        case .credentialMissing: "No API key is configured for the selected provider."
        case .credentialRecoveryRequired: "The provider credential needs repair in Models & Providers."
        case .credentialRejected: "The provider rejected its configured credential."
        case .insufficientCredit: "The provider reported insufficient credit or an unpaid balance."
        case .rateLimited: "The provider rate limit was reached."
        case .temporarilyUnavailable: "The provider service was temporarily unavailable."
        case .modelUnavailable: "The selected model route was unavailable."
        case .contextWindowExceeded: "The scheduled task exceeded the model context window."
        case .toolFailure: "The provider could not complete a requested tool operation."
        case .blocked: "The provider blocked this scheduled task."
        case .interrupted: "The provider response was interrupted."
        case .invalidResponse: "The provider returned an invalid or incomplete response."
        case .generic: "The provider failed this task."
        }
    }
}

protocol ScheduleConversationExecuting: Sendable {
    typealias Completion = @Sendable (Result<ScheduleConversationOutput, ScheduleExecutionError>) -> Void

    @discardableResult
    func execute(_ request: ScheduleConversationRequest, completion: @escaping Completion) -> UUID
    func cancel(_ identifier: UUID)
    func cancelAll()
    func quiesce() async throws
}

extension ScheduleConversationExecuting {
    func quiesce() async throws { cancelAll() }
}

protocol ScheduleHarnessConversationServicing: Sendable {
    func createSession(
        selection: ModelSelection,
        workspace: URL,
        agentPreset: String
    ) async throws -> HarnessConversationSession
    @discardableResult
    func sendIfAdmitted(
        sessionID: HarnessSessionID,
        content: [HarnessPromptContentPart],
        since lastSequence: Int,
        timeout: TimeInterval,
        onEvent: @escaping HarnessConversationService.EventHandler,
        completion: @escaping HarnessConversationService.Completion
    ) -> UUID?
    func cancel(_ identifier: UUID, sessionID: HarnessSessionID)
    func discardUnsubmittedSession(_ sessionID: HarnessSessionID) async throws
    func respond(to request: HarnessApprovalRequest, decision: HarnessApprovalDecision) async throws
    func cancel(_ request: HarnessQuestionRequest) async throws
}

extension HarnessConversationService: ScheduleHarnessConversationServicing {}

/// Bounded adapter for unattended work. It creates a real DSH session with the
/// exact typed provider/model selection and rejects every interactive approval
/// or question; a schedule never grants capabilities on the user's behalf.
final class HarnessScheduleConversationExecutor: ScheduleConversationExecuting, @unchecked Sendable {
    static let maximumResponseBytes = 2 * 1_024 * 1_024

    private final class Operation: @unchecked Sendable {
        let id: UUID
        let request: ScheduleConversationRequest
        let completion: ScheduleConversationExecuting.Completion
        private let lock = NSLock()
        private var task: Task<Void, Never>?
        private var sessionID: HarnessSessionID?
        private var selected: HarnessWireModelSelection?
        private var sendID: UUID?
        private var streamedText = ""
        private var streamedBytes = 0
        private var finalText: String?
        private var completedResponseSegments: [String] = []
        private var completedResponseBytes = 0
        private var completionReason: HarnessTurnCompletionReason?
        private var finalInterrupted = false
        private var finished = false
        private var cancelWhenInstalled = false

        init(
            id: UUID,
            request: ScheduleConversationRequest,
            completion: @escaping ScheduleConversationExecuting.Completion
        ) {
            self.id = id
            self.request = request
            self.completion = completion
        }

        func install(task: Task<Void, Never>) -> Bool {
            lock.withScheduleLock {
                self.task = task
                return finished && cancelWhenInstalled
            }
        }

        func install(session: HarnessConversationSession) -> Bool {
            lock.withScheduleLock {
                sessionID = session.id
                selected = session.selection
                return finished && cancelWhenInstalled
            }
        }

        func install(sendID: UUID) -> (Bool, HarnessSessionID?) {
            lock.withScheduleLock {
                self.sendID = sendID
                return (finished && cancelWhenInstalled, sessionID)
            }
        }

        func ingest(_ event: HarnessMuxEvent) -> ScheduleExecutionError? {
            lock.withScheduleLock { () -> ScheduleExecutionError? in
                guard !finished else { return nil }
                switch event {
                case .commandResponse(let command):
                    let text = command.text ?? "Command completed."
                    guard text.utf8.count <= HarnessScheduleConversationExecutor.maximumResponseBytes else { return .responseTooLarge }
                    completedResponseSegments.removeAll(keepingCapacity: false)
                    completedResponseBytes = 0
                    finalText = text
                    streamedText.removeAll(keepingCapacity: false)
                    streamedBytes = 0
                    completionReason = .completed
                case .assistantTextDelta(let delta):
                    let bytes = delta.text.utf8.count
                    if finalText != nil {
                        // A later assistant step has started. Its eventual
                        // final message is authoritative for this segment.
                        finalText = nil
                        streamedText.removeAll(keepingCapacity: false)
                        streamedBytes = 0
                    }
                    let separatorBytes = completedResponseSegments.isEmpty ? 0 : 2
                    let retainedPrefix = completedResponseBytes + separatorBytes
                    guard retainedPrefix <= HarnessScheduleConversationExecutor.maximumResponseBytes,
                          streamedBytes <= HarnessScheduleConversationExecutor.maximumResponseBytes - retainedPrefix,
                          bytes <= HarnessScheduleConversationExecutor.maximumResponseBytes - retainedPrefix - streamedBytes else {
                        return .responseTooLarge
                    }
                    streamedBytes += bytes
                    streamedText.append(delta.text)
                case .assistantFinalMessage(let message):
                    let bytes = message.text.utf8.count
                    let separatorBytes = completedResponseSegments.isEmpty ? 0 : 2
                    let retainedPrefix = completedResponseBytes + separatorBytes
                    guard retainedPrefix <= HarnessScheduleConversationExecutor.maximumResponseBytes,
                          bytes <= HarnessScheduleConversationExecutor.maximumResponseBytes - retainedPrefix else {
                        return .responseTooLarge
                    }
                    finalText = message.text
                    streamedText.removeAll(keepingCapacity: false)
                    streamedBytes = 0
                    finalInterrupted = message.interrupted
                case .turnCompleted(let completion):
                    completionReason = completion.reason
                    if completion.reason == .maxTokens, !commitCurrentSegment() {
                        return .responseTooLarge
                    }
                default:
                    break
                }
                return nil
            }
        }

        func makeOutput() -> Result<ScheduleConversationOutput, ScheduleExecutionError> {
            lock.withScheduleLock {
                guard let sessionID else { return .failure(.runtimeUnavailable) }
                if finalInterrupted { return .failure(.providerFailed(category: .interrupted)) }
                let truncated: Bool
                switch completionReason {
                case .completed?: truncated = false
                case .maxTokens?: truncated = true
                case .aborted?: return .failure(.providerFailed(category: .generic))
                case .blocked?: return .failure(.providerFailed(category: .blocked))
                case .interrupted?: return .failure(.providerFailed(category: .interrupted))
                case .other?: return .failure(.providerFailed(category: .generic))
                case nil: return .failure(.providerFailed(category: .invalidResponse))
                }
                var segments = completedResponseSegments
                let current = finalText ?? streamedText
                if !current.isEmpty { segments.append(current) }
                let response = segments.joined(separator: "\n\n")
                guard response.utf8.count <= HarnessScheduleConversationExecutor.maximumResponseBytes else {
                    return .failure(.responseTooLarge)
                }
                let wire = selected ?? HarnessWireModelSelection(
                    route: request.selection.route,
                    reasoningEffort: request.selection.reasoningEffort
                )
                return .success(ScheduleConversationOutput(
                    sessionID: sessionID,
                    selection: ModelSelection(
                        route: wire.route,
                        reasoningEffort: wire.reasoningEffort,
                        performanceProfile: request.selection.performanceProfile
                    ),
                    response: response,
                    truncated: truncated
                ))
            }
        }

        /// Commits the completed max-token segment before the identified
        /// follow-up starts. Delimiters are charged to the same aggregate
        /// response cap so twelve individually safe segments cannot exceed the
        /// schedule persistence boundary when joined.
        private func commitCurrentSegment() -> Bool {
            let segment = finalText ?? streamedText
            defer {
                finalText = nil
                streamedText.removeAll(keepingCapacity: false)
                streamedBytes = 0
            }
            guard !segment.isEmpty else { return true }
            let bytes = segment.utf8.count
            let separatorBytes = completedResponseSegments.isEmpty ? 0 : 2
            guard completedResponseBytes <= HarnessScheduleConversationExecutor.maximumResponseBytes,
                  separatorBytes <= HarnessScheduleConversationExecutor.maximumResponseBytes - completedResponseBytes,
                  bytes <= HarnessScheduleConversationExecutor.maximumResponseBytes
                    - completedResponseBytes - separatorBytes else { return false }
            completedResponseSegments.append(segment)
            completedResponseBytes += separatorBytes + bytes
            return true
        }

        func claimFinish(cancelUnderlying: Bool) -> Bool {
            lock.withScheduleLock {
                guard !finished else { return false }
                finished = true
                cancelWhenInstalled = cancelUnderlying
                return true
            }
        }

        func cancellationResources() -> (Task<Void, Never>?, UUID?, HarnessSessionID?) {
            lock.withScheduleLock { (task, sendID, sessionID) }
        }
    }

    private let conversation: any ScheduleHarnessConversationServicing
    private let lock = NSLock()
    private var operations: [UUID: Operation] = [:]
    private var workerTasks: [UUID: Task<Void, Never>] = [:]
    private var cleanupFailures: Set<UUID> = []

    init(conversation: any ScheduleHarnessConversationServicing) {
        self.conversation = conversation
    }

    @discardableResult
    func execute(
        _ request: ScheduleConversationRequest,
        completion: @escaping ScheduleConversationExecuting.Completion
    ) -> UUID {
        let id = UUID()
        let operation = Operation(id: id, request: request, completion: completion)
        lock.lock()
        // A worker remains live only while create -> prompt admission ownership
        // is unresolved (normal submitted turns release it immediately). Do not
        // admit a later occurrence after a timeout/cancel has published but
        // before a late-created session is either handed off or archived.
        guard cleanupFailures.isEmpty, workerTasks.isEmpty else {
            lock.unlock()
            DispatchQueue.main.async { completion(.failure(.runtimeUnavailable)) }
            return id
        }
        operations[id] = operation
        let task = Task { [weak self, weak operation] in
            guard let self, let operation else { return }
            defer { self.workerDidSettle(id) }
            var unsubmittedSession: HarnessConversationSession?
            do {
                try Task.checkCancellation()
                let session = try await conversation.createSession(
                    selection: request.selection,
                    workspace: request.workspace,
                    agentPreset: "standard"
                )
                unsubmittedSession = session
                if operation.install(session: session) {
                    unsubmittedSession = nil
                    try await conversation.discardUnsubmittedSession(session.id)
                    return
                }
                try Task.checkCancellation()
                let sendID = conversation.sendIfAdmitted(
                    sessionID: session.id,
                    content: [.text(request.prompt)],
                    since: 0,
                    timeout: max(1, request.timeoutSeconds),
                    onEvent: { [weak self, weak operation] event in
                        guard let self, let operation else { return }
                        self.handle(event, operation: operation)
                    },
                    completion: { [weak self, weak operation] result in
                        guard let self, let operation else { return }
                        switch result {
                        case .success:
                            self.finish(operation, result: operation.makeOutput(), cancelUnderlying: false)
                        case .failure(let error):
                            self.finish(operation, result: .failure(Self.map(error)), cancelUnderlying: false)
                        }
                    }
                )
                guard let sendID else {
                    // Conversation admission can close between successful
                    // creation and the synchronous send handoff (for example,
                    // warning-memory pressure pauses new work without cancelling
                    // the active schedule). The session is still app-owned and
                    // unsubmitted, so settle exact cleanup before publishing the
                    // failure or permitting another occurrence.
                    unsubmittedSession = nil
                    do {
                        try await conversation.discardUnsubmittedSession(session.id)
                    } catch {
                        recordCleanupFailure(id)
                    }
                    finish(operation, result: .failure(.runtimeUnavailable), cancelUnderlying: false)
                    return
                }
                unsubmittedSession = nil
                let installed = operation.install(sendID: sendID)
                if installed.0, let sessionID = installed.1 {
                    conversation.cancel(sendID, sessionID: sessionID)
                }
            } catch is CancellationError {
                if let session = unsubmittedSession {
                    do { try await conversation.discardUnsubmittedSession(session.id) }
                    catch { recordCleanupFailure(id) }
                }
                finish(operation, result: .failure(.cancelled), cancelUnderlying: true)
            } catch {
                if let session = unsubmittedSession {
                    do { try await conversation.discardUnsubmittedSession(session.id) }
                    catch { recordCleanupFailure(id) }
                } else if error as? HarnessConversationError == .sessionCleanupUnverified {
                    recordCleanupFailure(id)
                }
                finish(operation, result: .failure(Self.map(error)), cancelUnderlying: true)
            }
        }
        workerTasks[id] = task
        lock.unlock()
        if operation.install(task: task) { task.cancel() }

        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + max(0.1, request.timeoutSeconds)
        ) { [weak self, weak operation] in
            guard let self, let operation else { return }
            self.finish(operation, result: .failure(.timedOut), cancelUnderlying: true)
        }
        return id
    }

    func cancel(_ identifier: UUID) {
        let operation = lock.withScheduleLock { operations[identifier] }
        guard let operation else { return }
        finish(operation, result: .failure(.cancelled), cancelUnderlying: true)
    }

    func cancelAll() {
        let current = lock.withScheduleLock { Array(operations.values) }
        current.forEach { finish($0, result: .failure(.cancelled), cancelUnderlying: true) }
    }

    func quiesce() async throws {
        cancelAll()
        while true {
            let tasks = lock.withScheduleLock { Array(workerTasks.values) }
            guard !tasks.isEmpty else { break }
            for task in tasks { await task.value }
        }
        let failed = lock.withScheduleLock { !cleanupFailures.isEmpty }
        guard !failed else { throw HarnessConversationError.sessionCleanupUnverified }
    }

    private func workerDidSettle(_ identifier: UUID) {
        _ = lock.withScheduleLock { workerTasks.removeValue(forKey: identifier) }
    }

    private func recordCleanupFailure(_ identifier: UUID) {
        _ = lock.withScheduleLock { cleanupFailures.insert(identifier) }
    }

    private func handle(_ event: HarnessMuxEvent, operation: Operation) {
        switch event {
        case .approvalRequested(let request):
            Task { [conversation] in try? await conversation.respond(to: request, decision: .rejected) }
            finish(operation, result: .failure(.interactionRequired), cancelUnderlying: true)
        case .questionRequested(let request):
            Task { [conversation] in try? await conversation.cancel(request) }
            finish(operation, result: .failure(.interactionRequired), cancelUnderlying: true)
        default:
            if let failure = operation.ingest(event) {
                finish(operation, result: .failure(failure), cancelUnderlying: true)
            }
        }
    }

    private func finish(
        _ operation: Operation,
        result: Result<ScheduleConversationOutput, ScheduleExecutionError>,
        cancelUnderlying: Bool
    ) {
        guard operation.claimFinish(cancelUnderlying: cancelUnderlying) else { return }
        _ = lock.withScheduleLock { operations.removeValue(forKey: operation.id) }
        if cancelUnderlying {
            let resources = operation.cancellationResources()
            resources.0?.cancel()
            if let sendID = resources.1, let sessionID = resources.2 {
                conversation.cancel(sendID, sessionID: sessionID)
            }
        }
        DispatchQueue.main.async { operation.completion(result) }
    }

    private static func map(_ error: Error) -> ScheduleExecutionError {
        if let error = error as? ScheduleExecutionError { return error }
        if let error = error as? HarnessConversationError {
            switch error {
            case .timedOut: return .timedOut
            case .cancelled: return .cancelled
            case .turnFailed(let failure): return .providerFailed(category: .init(failure.kind))
            case .promptRejected, .streamEnded, .streamLimitExceeded,
                 .turnAborted, .turnBlocked, .turnInterrupted, .unsupportedTurnCompletion,
                 .automaticContinuationSuperseded, .automaticContinuationUnavailable,
                 .automaticContinuationLimitReached,
                 .automaticContinuationProtocolViolation:
                return .providerFailed(category: .invalidResponse)
            case .cancellationUnverified, .sessionCleanupUnverified: return .runtimeUnavailable
            }
        }
        if let error = error as? HarnessRPCClientError {
            switch error {
            case .endpointUnavailable, .endpointChanged, .invalidEndpoint, .transport:
                return .runtimeUnavailable
            case .timedOut: return .timedOut
            case .cancelled: return .cancelled
            case .remote(let remote):
                let failure = ProviderFailurePresentation.classify(code: remote.code.rawValue, status: nil)
                return .providerFailed(category: .init(failure.kind))
            default: return .providerFailed(category: .generic)
            }
        }
        return .unknown
    }
}

/// Compile-safe transition used only until AppDelegate injects the authenticated
/// Harness conversation service. It never falls back to direct Ollama traffic.
final class UnconfiguredScheduleConversationExecutor: ScheduleConversationExecuting, @unchecked Sendable {
    @discardableResult
    func execute(
        _ request: ScheduleConversationRequest,
        completion: @escaping ScheduleConversationExecuting.Completion
    ) -> UUID {
        let id = UUID()
        DispatchQueue.main.async { completion(.failure(.runtimeUnavailable)) }
        return id
    }

    func cancel(_ identifier: UUID) {}
    func cancelAll() {}
}

private extension NSLock {
    func withScheduleLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
