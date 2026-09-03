import Foundation

protocol HarnessConversationRPCServicing: Sendable {
    func createSession(_ request: HarnessSessionCreateRequest) async throws -> HarnessSessionCreateResult
    func selectModel(sessionID: HarnessSessionID, selection: HarnessWireModelSelection) async throws -> HarnessWireModelSelection
    func archiveSession(_ sessionID: HarnessSessionID) async throws -> HarnessArchivedSessionsResult
    func prompt(
        sessionID: HarnessSessionID,
        mode: HarnessPromptMode,
        content: [HarnessPromptContentPart],
        clientTimeZone: String?
    ) async throws -> HarnessPromptSubmission
    func cancel(sessionID: HarnessSessionID) async throws -> HarnessCancelResult
    func respondToApproval(
        rpcID: String,
        sessionID: HarnessSessionID,
        approvalID: String,
        decision: HarnessApprovalDecision
    ) async throws -> HarnessRPCReceipt
    func respondToQuestion(
        rpcID: String,
        sessionID: HarnessSessionID,
        answer: HarnessQuestionAnswer
    ) async throws -> HarnessRPCReceipt
    func cancelQuestion(rpcID: String) async throws -> HarnessRPCReceipt
    func muxEvents(since: [HarnessSessionID: Int]) throws -> HarnessMuxSubscription
}

extension HarnessRPCClient: HarnessConversationRPCServicing {}

struct HarnessConversationSession: Equatable, Sendable {
    let id: HarnessSessionID
    let selection: HarnessWireModelSelection
    let agentPreset: String?
}

enum HarnessConversationError: LocalizedError, Equatable {
    case promptRejected
    case turnFailed(ProviderFailureContext)
    case streamEnded
    case timedOut
    case cancelled
    case streamLimitExceeded
    case cancellationUnverified
    case sessionCleanupUnverified
    case turnAborted
    case turnBlocked
    case turnInterrupted
    case unsupportedTurnCompletion
    case automaticContinuationSuperseded
    case automaticContinuationUnavailable
    case automaticContinuationLimitReached
    case automaticContinuationProtocolViolation

    var errorDescription: String? {
        switch self {
        case .promptRejected: return "Harness did not accept the prompt."
        case .turnFailed(let failure): return ProviderFailurePresentation.message(for: failure)
        case .streamEnded: return "The Harness event stream ended before the answer completed."
        case .timedOut: return "The model exceeded the selected task time limit."
        case .cancelled: return "The response was stopped."
        case .streamLimitExceeded: return "Harness exceeded the bounded response stream. The exact task was cancelled."
        case .cancellationUnverified: return "Harness did not confirm that every active task was cancelled. Provider changes remain blocked."
        case .sessionCleanupUnverified: return "Harness did not confirm removal of an unfinished task. Runtime changes remain blocked."
        case .turnAborted: return "Harness aborted the task before it completed. Completed work remains saved."
        case .turnBlocked: return "Harness blocked the task before it completed. Review the task history and any pending approval."
        case .turnInterrupted: return "Harness reported that the task was interrupted. Completed work remains saved."
        case .unsupportedTurnCompletion: return "Harness ended the task in an unsupported state. Completed work remains saved."
        case .automaticContinuationSuperseded:
            return "A newer queued task took priority after the output limit. Completed work remains saved in Task History."
        case .automaticContinuationUnavailable:
            return "Fulmar could not start the automatic continuation promptly. Completed work remains saved; restart the agent service and try again."
        case .automaticContinuationLimitReached:
            return "Fulmar reached its bounded automatic-continuation safety limit. Completed work remains saved; send a new message if more work is needed."
        case .automaticContinuationProtocolViolation:
            return "Fulmar blocked an invalid automatic-continuation sequence. Completed work remains saved."
        }
    }
}

/// Session creation transfers ownership only after model selection succeeds.
/// Cleanup runs in an unstructured task so cancellation of the caller cannot
/// cancel the compensating archive request. The authenticated RPC client owns
/// the request deadline; an exact ID in the response is the commit receipt.
enum HarnessSessionCleanup {
    static func archive(
        sessionID: HarnessSessionID,
        operation: @escaping @Sendable () async throws -> HarnessArchivedSessionsResult
    ) async -> Bool {
        await Task.detached(priority: .utility) {
            do {
                let result = try await operation()
                return result.archivedSessionIds.contains(sessionID)
            } catch {
                return false
            }
        }.value
    }

    /// A create request with an app-preallocated session ID can have committed
    /// remotely even when the client never receives a decodable success reply.
    /// Deterministic local/preflight rejections are the only failures that prove
    /// no compensating archive is required.
    static func requiresCompensation(after error: Error) -> Bool {
        if error is CancellationError { return true }
        guard let error = error as? HarnessRPCClientError else { return true }
        switch error {
        case .endpointUnavailable, .controlPlaneOnly, .invalidEndpoint, .invalidArgument,
             .requestTooLarge:
            return false
        case .remote(let remote):
            return remote.code.rawValue == "workspace-attach-failed"
        case .endpointChanged, .responseTooLarge, .httpStatus, .responseViolation,
             .rpcIDMismatch, .timedOut, .cancelled, .transport:
            return true
        }
    }
}

enum ProviderFailureKind: String, Codable, Equatable, Sendable {
    case credentialMissing
    case credentialRecoveryRequired
    case credentialRejected
    case insufficientCredit
    case rateLimited
    case temporarilyUnavailable
    case modelUnavailable
    case contextWindowExceeded
    case toolFailure
    case generic
}

struct ProviderFailureContext: Equatable, Sendable {
    let kind: ProviderFailureKind
    let status: Int?
    let retryAfterMilliseconds: Int?
    let requestID: String?
}

/// The only native presentation boundary for provider-owned failures. Raw
/// provider messages and codes are classification inputs only and never leave
/// this boundary. Numeric HTTP claims are made only for an actual wire status.
enum ProviderFailurePresentation {
    private static let missingCredentialCodes: Set<String> = [
        "missing-credential"
    ]
    private static let credentialRecoveryCodes: Set<String> = [
        "credential-record-protocol-failed", "credential-recovery-required",
        "credential-state-unavailable", "credential-state-unsafe",
        "credential-transaction-busy", "credential-verification-failed",
        "keychain-authorization-required"
    ]
    private static let credentialCodes: Set<String> = [
        "auth", "auth-error", "auth-failed", "authentication-error", "authentication-failed",
        "credential-rejected", "invalid-api-key", "invalid-credential", "unauthorized"
    ]
    private static let creditCodes: Set<String> = [
        "billing-error", "credit-balance-exhausted", "insufficient-balance",
        "insufficient-credit", "insufficient-quota", "organization-spend-limit-exceeded",
        "organization-usage-limit-exceeded", "payment-required", "project-spend-limit-exceeded",
        "quota"
    ]
    private static let rateCodes: Set<String> = [
        "rate-limit", "rate-limit-exceeded", "rate-limited", "too-many-requests"
    ]
    private static let temporaryCodes: Set<String> = [
        "empty-response", "provider-unavailable", "server", "service-unavailable",
        "stream-closed", "timeout", "transport", "upstream-unavailable"
    ]
    private static let unavailableModelCodes: Set<String> = [
        "model-configuration", "no-adapter", "unknown-model"
    ]
    private static let toolCodes: Set<String> = [
        "tool-call-error", "tool-error", "tool-failed", "tool-failure"
    ]
    private static let maximumRetryAfterMilliseconds = 86_400_000

    static func classify(
        code: String,
        status rawStatus: Int?,
        retryAfterMilliseconds rawRetryAfter: Int? = nil,
        requestID rawRequestID: String? = nil
    ) -> ProviderFailureContext {
        let status = rawStatus.flatMap { (100...599).contains($0) ? $0 : nil }
        let retryAfter = rawRetryAfter.flatMap {
            (0...maximumRetryAfterMilliseconds).contains($0) ? $0 : nil
        }
        let requestID = rawRequestID.flatMap { value -> String? in
            try? HarnessCatalogWirePolicy.opaqueIdentifier(
                value,
                codingPath: [],
                label: "provider request identifier",
                maximumScalars: 128,
                maximumUTF8Bytes: 512
            )
        }
        let canonicalCode = canonical(code)
        let kind: ProviderFailureKind
        // Unambiguous authentication/payment wire statuses remain authoritative.
        // For overloaded or otherwise ambiguous statuses, a bounded machine code
        // is more specific: OpenAI uses 429 for both transient rate limits and
        // exhausted credit/spend quotas. Unknown 429s retain the conservative
        // rate-limit fallback without projecting raw provider text.
        if missingCredentialCodes.contains(canonicalCode) { kind = .credentialMissing }
        else if credentialRecoveryCodes.contains(canonicalCode) { kind = .credentialRecoveryRequired }
        else if status == 401 || status == 403 { kind = .credentialRejected }
        else if status == 402 { kind = .insufficientCredit }
        else if credentialCodes.contains(canonicalCode) { kind = .credentialRejected }
        else if creditCodes.contains(canonicalCode) { kind = .insufficientCredit }
        else if rateCodes.contains(canonicalCode) { kind = .rateLimited }
        else if temporaryCodes.contains(canonicalCode) { kind = .temporarilyUnavailable }
        else if unavailableModelCodes.contains(canonicalCode) { kind = .modelUnavailable }
        else if canonicalCode == "context-window-exceeded" { kind = .contextWindowExceeded }
        else if toolCodes.contains(canonicalCode) { kind = .toolFailure }
        else if status == 429 { kind = .rateLimited }
        else if let status, (500...599).contains(status) { kind = .temporarilyUnavailable }
        else { kind = .generic }
        return ProviderFailureContext(
            kind: kind,
            status: status,
            retryAfterMilliseconds: retryAfter,
            requestID: requestID
        )
    }

    static func message(for failure: ProviderFailureContext) -> String {
        switch failure.kind {
        case .credentialMissing:
            return "No API key is configured for this model. Add one in Models & Providers."
        case .credentialRecoveryRequired:
            return "The provider credential needs attention. Open Models & Providers to repair it."
        case .credentialRejected:
            let status = failure.status.flatMap { [401, 403].contains($0) ? " (HTTP \($0))" : nil } ?? ""
            return "The provider rejected the API credential\(status). Check or replace the API key in Models & Providers."
        case .insufficientCredit:
            let status = failure.status == 402 ? " (HTTP 402)" : ""
            return "The provider reported insufficient credit or an unpaid balance\(status). Add credit with the provider or select another model."
        case .rateLimited:
            let status = failure.status == 429 ? " (HTTP 429)" : ""
            let retry = failure.retryAfterMilliseconds.map {
                " Try again in \(max(1, Int(ceil(Double($0) / 1_000)))) seconds."
            } ?? " Wait a moment and try again."
            return "The provider rate limit was reached\(status).\(retry)"
        case .temporarilyUnavailable:
            let status = failure.status.map { " (HTTP \($0))" } ?? ""
            return "The provider service is temporarily unavailable\(status). Try again later or select another model."
        case .modelUnavailable:
            return "The selected model route is unavailable. Choose another model or repair it in Models & Providers."
        case .contextWindowExceeded:
            return "This task is too large for the model context. Shorten it or start a fresh session."
        case .toolFailure:
            return "The provider could not complete the requested tool operation. Review the task and try again."
        case .generic:
            let status = failure.status.map { " (HTTP \($0))" } ?? ""
            return "The provider could not complete this request\(status). Review Models & Providers or try again."
        }
    }

    private static func canonical(_ rawValue: String) -> String {
        let scalars = rawValue.unicodeScalars.prefix(128)
        var output = ""
        output.reserveCapacity(scalars.count)
        var pendingSeparator = false
        for scalar in scalars {
            guard scalar.isASCII else { return "" }
            if CharacterSet.alphanumerics.contains(scalar) {
                if pendingSeparator, !output.isEmpty { output.append("-") }
                pendingSeparator = false
                output.append(Character(String(scalar).lowercased()))
            } else if scalar == "-" || scalar == "_" || scalar == " " || scalar == "." {
                pendingSeparator = !output.isEmpty
            } else {
                return ""
            }
        }
        return output
    }
}

struct HarnessConversationLimits: Equatable, Sendable {
    let maximumEvents: Int
    let maximumAssistantTextBytes: Int
    let maximumToolCalls: Int
    let maximumToolBytes: Int
    let maximumInteractionEvents: Int
    let maximumInteractionBytes: Int
    let maximumPendingMainEvents: Int
    /// A packaged continuation is a local queue operation, so its identified
    /// user/message must appear promptly even when model inference is slow.
    /// This prevents a missing or failed plugin from displaying “Continuing”
    /// until the much longer whole-task timeout.
    let automaticContinuationGraceSeconds: TimeInterval

    init(
        maximumEvents: Int,
        maximumAssistantTextBytes: Int,
        maximumToolCalls: Int,
        maximumToolBytes: Int,
        maximumInteractionEvents: Int,
        maximumInteractionBytes: Int,
        maximumPendingMainEvents: Int,
        automaticContinuationGraceSeconds: TimeInterval = 15
    ) {
        self.maximumEvents = maximumEvents
        self.maximumAssistantTextBytes = maximumAssistantTextBytes
        self.maximumToolCalls = maximumToolCalls
        self.maximumToolBytes = maximumToolBytes
        self.maximumInteractionEvents = maximumInteractionEvents
        self.maximumInteractionBytes = maximumInteractionBytes
        self.maximumPendingMainEvents = maximumPendingMainEvents
        self.automaticContinuationGraceSeconds = automaticContinuationGraceSeconds
    }

    static let production = HarnessConversationLimits(
        maximumEvents: 50_000,
        maximumAssistantTextBytes: 8 * 1_024 * 1_024,
        maximumToolCalls: 512,
        maximumToolBytes: 8 * 1_024 * 1_024,
        maximumInteractionEvents: 256,
        maximumInteractionBytes: 2 * 1_024 * 1_024,
        maximumPendingMainEvents: 1_024,
        automaticContinuationGraceSeconds: 15
    )
}

/// Runs native chat and schedule turns through DSH rather than bypassing its
/// provider, session, tool, and persistence layers. Each operation opens an
/// authenticated bounded event stream before submitting the prompt, filters it
/// to one opaque session ID, and has a deterministic timeout/cancellation gate.
final class HarnessConversationService: @unchecked Sendable {
    typealias EventHandler = @MainActor @Sendable (HarnessMuxEvent) -> Void
    typealias Completion = @MainActor @Sendable (Result<Void, Error>) -> Void

    private final class MainEventDispatcher: @unchecked Sendable {
        private let lock = NSLock()
        private let handler: EventHandler
        private let maximumPendingEvents: Int
        private var pending: [HarnessMuxEvent] = []
        private var terminal: (@MainActor () -> Void)?
        private var drainScheduled = false
        private var accepting = true

        init(handler: @escaping EventHandler, maximumPendingEvents: Int) {
            self.handler = handler
            self.maximumPendingEvents = maximumPendingEvents
        }

        func enqueue(_ event: HarnessMuxEvent) -> Bool {
            lock.lock()
            guard accepting, pending.count < maximumPendingEvents else {
                lock.unlock()
                return false
            }
            pending.append(event)
            scheduleDrainLocked()
            lock.unlock()
            return true
        }

        func complete(_ closure: @escaping @MainActor () -> Void) {
            lock.lock()
            guard terminal == nil else { lock.unlock(); return }
            accepting = false
            terminal = closure
            scheduleDrainLocked()
            lock.unlock()
        }

        private func scheduleDrainLocked() {
            guard !drainScheduled else { return }
            drainScheduled = true
            Task { @MainActor [weak self] in self?.drain() }
        }

        @MainActor
        private func drain() {
            lock.lock()
            drainScheduled = false
            let batchCount = min(64, pending.count)
            let batch = Array(pending.prefix(batchCount))
            if batchCount > 0 { pending.removeFirst(batchCount) }
            let completion: (@MainActor () -> Void)?
            if pending.isEmpty {
                completion = terminal
                terminal = nil
            } else {
                completion = nil
            }
            lock.unlock()

            batch.forEach(handler)
            if let completion { completion() }

            lock.lock()
            if !pending.isEmpty || terminal != nil { scheduleDrainLocked() }
            lock.unlock()
        }
    }

    private struct TurnBudget {
        let limits: HarnessConversationLimits
        var events = 0
        var deltaBytes = 0
        var finalBytes = 0
        var toolCalls = 0
        var toolBytes = 0
        var interactionEvents = 0
        var interactionBytes = 0

        mutating func admit(_ event: HarnessMuxEvent) throws {
            try Self.add(1, to: &events, maximum: limits.maximumEvents)
            switch event {
            case .assistantTextDelta(let value):
                try Self.add(value.text.utf8.count, to: &deltaBytes, maximum: limits.maximumAssistantTextBytes)
            case .assistantFinalMessage(let value):
                try Self.add(value.text.utf8.count, to: &finalBytes, maximum: limits.maximumAssistantTextBytes)
                try Self.add(value.provider?.rawValue.utf8.count ?? 0, to: &finalBytes, maximum: limits.maximumAssistantTextBytes)
                try Self.add(value.model?.rawValue.utf8.count ?? 0, to: &finalBytes, maximum: limits.maximumAssistantTextBytes)
            case .toolCall(let value):
                try Self.add(1, to: &toolCalls, maximum: limits.maximumToolCalls)
                try Self.add(
                    value.callID.utf8.count + value.toolName.utf8.count + value.argumentsJSON.utf8.count,
                    to: &toolBytes,
                    maximum: limits.maximumToolBytes
                )
            case .approvalRequested(let value):
                try addInteraction(bytes:
                    value.rpcID.utf8.count + value.approvalID.utf8.count + value.toolName.utf8.count
                        + (value.callID?.utf8.count ?? 0) + (value.reason?.utf8.count ?? 0)
                )
            case .approvalResolved(let value):
                try addInteraction(bytes: value.rpcID.utf8.count + value.approvalID.utf8.count)
            case .questionRequested(let value):
                var bytes = value.rpcID.utf8.count
                for question in value.questions {
                    bytes += question.id.utf8.count + question.question.utf8.count
                        + (question.detail?.utf8.count ?? 0) + (question.header?.utf8.count ?? 0)
                    for option in question.options ?? [] {
                        bytes += option.label.utf8.count + (option.description?.utf8.count ?? 0)
                    }
                }
                try addInteraction(bytes: bytes)
            case .questionResolved(let value):
                try addInteraction(bytes: value.rpcID.utf8.count + value.questionRPCID.utf8.count)
            case .commandResponse(let value):
                try addInteraction(bytes: value.kind.utf8.count + (value.text?.utf8.count ?? 0))
            case .turnFailed(let value):
                try addInteraction(bytes: value.failure.code.utf8.count + value.failure.message.utf8.count)
            case .streamError(let value):
                try addInteraction(bytes: value.code.rawValue.utf8.count + value.message.utf8.count)
            default:
                break
            }
        }

        private mutating func addInteraction(bytes: Int) throws {
            try Self.add(1, to: &interactionEvents, maximum: limits.maximumInteractionEvents)
            try Self.add(bytes, to: &interactionBytes, maximum: limits.maximumInteractionBytes)
        }

        private static func add(_ amount: Int, to value: inout Int, maximum: Int) throws {
            guard amount >= 0, value <= maximum - amount else {
                throw HarnessConversationError.streamLimitExceeded
            }
            value += amount
        }
    }

    private final class Operation: @unchecked Sendable {
        let sessionID: HarnessSessionID
        let completion: Completion
        let lock = NSLock()
        var task: Task<Void, Never>?
        var subscription: HarnessMuxSubscription?
        var cancellationRequested = false
        var promptMayHaveReachedServer = false
        var serverSettled = false
        var terminalClaimed = false
        var finished = false
        var settlementWaiters: [CheckedContinuation<Void, Never>] = []
        var remoteCancellationTask: Task<Bool, Never>?
        private var automaticContinuationWaitID: UUID?
        let dispatcher: MainEventDispatcher

        init(sessionID: HarnessSessionID, dispatcher: MainEventDispatcher, completion: @escaping Completion) {
            self.sessionID = sessionID
            self.dispatcher = dispatcher
            self.completion = completion
        }

        func install(task: Task<Void, Never>) {
            lock.lock(); self.task = task; let shouldCancel = cancellationRequested || terminalClaimed; lock.unlock()
            if shouldCancel { task.cancel() }
        }

        func install(subscription: HarnessMuxSubscription) {
            lock.lock()
            let shouldCancel = cancellationRequested || terminalClaimed
            if !shouldCancel { self.subscription = subscription }
            lock.unlock()
            if shouldCancel { subscription.cancel() }
        }

        func enterPromptAmbiguity() -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard !cancellationRequested, !terminalClaimed, !finished else { return false }
            promptMayHaveReachedServer = true
            return true
        }

        func claimTerminal() -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard !terminalClaimed, !finished else { return false }
            terminalClaimed = true
            return true
        }

        func markServerSettled() {
            lock.lock()
            serverSettled = true
            automaticContinuationWaitID = nil
            lock.unlock()
        }

        func beginAutomaticContinuationWait() -> UUID? {
            lock.lock(); defer { lock.unlock() }
            guard !cancellationRequested, !terminalClaimed, !finished else { return nil }
            let identifier = UUID()
            automaticContinuationWaitID = identifier
            return identifier
        }

        func endAutomaticContinuationWait() {
            lock.lock(); automaticContinuationWaitID = nil; lock.unlock()
        }

        /// Atomically consumes only the exact still-current wait. A notice at
        /// the deadline either invalidates this token first or the deadline
        /// wins and exact-session cancellation owns terminal settlement.
        func expireAutomaticContinuationWait(_ identifier: UUID) -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard automaticContinuationWaitID == identifier,
                  !cancellationRequested, !terminalClaimed, !finished else { return false }
            automaticContinuationWaitID = nil
            return true
        }

        func requestCancellation() {
            lock.lock()
            cancellationRequested = true
            automaticContinuationWaitID = nil
            let task = task
            let subscription = subscription
            self.subscription = nil
            lock.unlock()
            subscription?.cancel()
            task?.cancel()
        }

        func ensureRemoteCancellationTask(
            _ makeTask: () -> Task<Bool, Never>
        ) -> Task<Bool, Never>? {
            lock.lock(); defer { lock.unlock() }
            guard promptMayHaveReachedServer, !serverSettled else { return nil }
            if let remoteCancellationTask { return remoteCancellationTask }
            let task = makeTask()
            remoteCancellationTask = task
            return task
        }

        func waitUntilSettled() async {
            await withCheckedContinuation { continuation in
                lock.lock()
                if finished {
                    lock.unlock()
                    continuation.resume()
                } else {
                    settlementWaiters.append(continuation)
                    lock.unlock()
                }
            }
        }

        func settle() {
            lock.lock()
            guard !finished else { lock.unlock(); return }
            finished = true
            let waiters = settlementWaiters
            settlementWaiters.removeAll()
            lock.unlock()
            waiters.forEach { $0.resume() }
        }

        func cancelTransports() {
            lock.lock()
            let task = task
            let subscription = subscription
            self.subscription = nil
            lock.unlock()
            subscription?.cancel(); task?.cancel()
        }

        func cancelSubscription() {
            lock.lock(); let subscription = subscription; self.subscription = nil; lock.unlock()
            subscription?.cancel()
        }
    }

    private let rpc: any HarnessConversationRPCServicing
    private let limits: HarnessConversationLimits
    private let lock = NSLock()
    private var operations: [UUID: Operation] = [:]
    private var acceptingOperations = true
    private var quiescenceHolds = 0
    /// An unfinished app-owned session that could not be proven archived is a
    /// process-lifetime safety failure. Runtime restart must not silently reopen
    /// ordinary work while that opaque session may still exist in DSH.
    private var cleanupFailureRecorded = false
    private var activeAncillaryRPCs = 0
    private var ancillarySettlementWaiters: [CheckedContinuation<Void, Never>] = []

    private struct CancellationItem: @unchecked Sendable {
        let identifier: UUID
        let operation: Operation
        let ownsTerminal: Bool
        let requestedResult: Result<Void, Error>
        let remoteCancellation: Task<Bool, Never>?
    }

    init(
        rpc: any HarnessConversationRPCServicing,
        limits: HarnessConversationLimits = .production
    ) {
        precondition(limits.maximumEvents > 0)
        precondition(limits.maximumAssistantTextBytes > 0)
        precondition(limits.maximumToolCalls > 0 && limits.maximumToolBytes > 0)
        precondition(limits.maximumInteractionEvents > 0 && limits.maximumInteractionBytes > 0)
        precondition(limits.maximumPendingMainEvents > 0)
        precondition(
            limits.automaticContinuationGraceSeconds > 0
                && limits.automaticContinuationGraceSeconds <= 60
        )
        self.rpc = rpc
        self.limits = limits
    }

    func createSession(
        selection: ModelSelection,
        workspace: URL,
        agentPreset: String = "standard"
    ) async throws -> HarnessConversationSession {
        guard beginAncillaryRPC() else { throw HarnessConversationError.cancelled }
        defer { endAncillaryRPC() }
        try Task.checkCancellation()
        let requestedSessionID = PerformanceSessionIdentity.make(profile: selection.performanceProfile)
        let request = HarnessSessionCreateRequest(
            cwd: workspace.path,
            sessionId: requestedSessionID,
            agentPreset: agentPreset
        )
        let result: HarnessSessionCreateResult
        do {
            result = try await rpc.createSession(request)
        } catch {
            if HarnessSessionCleanup.requiresCompensation(after: error) {
                let archived = await HarnessSessionCleanup.archive(sessionID: requestedSessionID) { [rpc] in
                    try await rpc.archiveSession(requestedSessionID)
                }
                guard archived else {
                    recordUnverifiedSessionCleanup()
                    throw HarnessConversationError.sessionCleanupUnverified
                }
            }
            throw error
        }
        guard result.sessionId == requestedSessionID else {
            let archived = await HarnessSessionCleanup.archive(sessionID: requestedSessionID) { [rpc] in
                try await rpc.archiveSession(requestedSessionID)
            }
            guard archived else {
                recordUnverifiedSessionCleanup()
                throw HarnessConversationError.sessionCleanupUnverified
            }
            throw HarnessRPCClientError.responseViolation(.invalidPayload)
        }
        do {
            try Task.checkCancellation()
            let selected = try await rpc.selectModel(
                sessionID: result.sessionId,
                selection: HarnessWireModelSelection(
                    route: selection.route,
                    reasoningEffort: selection.reasoningEffort
                )
            )
            try Task.checkCancellation()
            return HarnessConversationSession(id: result.sessionId, selection: selected, agentPreset: result.agentPreset)
        } catch {
            let archived = await HarnessSessionCleanup.archive(sessionID: result.sessionId) { [rpc] in
                try await rpc.archiveSession(result.sessionId)
            }
            guard archived else {
                recordUnverifiedSessionCleanup()
                throw HarnessConversationError.sessionCleanupUnverified
            }
            throw error
        }
    }

    /// Removes a session which was created for a caller that lost ownership
    /// before it could submit a prompt. Cleanup is admitted even while ordinary
    /// work is suspended, and participates in the ancillary-RPC drain.
    func discardUnsubmittedSession(_ sessionID: HarnessSessionID) async throws {
        beginAncillaryCleanupRPC()
        defer { endAncillaryRPC() }
        let archived = await HarnessSessionCleanup.archive(sessionID: sessionID) { [rpc] in
            try await rpc.archiveSession(sessionID)
        }
        guard archived else {
            recordUnverifiedSessionCleanup()
            throw HarnessConversationError.sessionCleanupUnverified
        }
    }

    @discardableResult
    func send(
        sessionID: HarnessSessionID,
        content: [HarnessPromptContentPart],
        since lastSequence: Int = 0,
        timeout: TimeInterval,
        onEvent: @escaping EventHandler,
        completion: @escaping Completion
    ) -> UUID {
        beginSend(
            sessionID: sessionID,
            content: content,
            since: lastSequence,
            timeout: timeout,
            completeWhenAdmissionIsClosed: true,
            onEvent: onEvent,
            completion: completion
        ).identifier
    }

    /// Scheduled work owns a newly-created session until prompt admission has
    /// been accepted locally. Returning `nil` without invoking `completion`
    /// lets that owner archive the still-unsubmitted exact session before it
    /// publishes a terminal result or admits another occurrence.
    @discardableResult
    func sendIfAdmitted(
        sessionID: HarnessSessionID,
        content: [HarnessPromptContentPart],
        since lastSequence: Int = 0,
        timeout: TimeInterval,
        onEvent: @escaping EventHandler,
        completion: @escaping Completion
    ) -> UUID? {
        let result = beginSend(
            sessionID: sessionID,
            content: content,
            since: lastSequence,
            timeout: timeout,
            completeWhenAdmissionIsClosed: false,
            onEvent: onEvent,
            completion: completion
        )
        return result.admitted ? result.identifier : nil
    }

    private func beginSend(
        sessionID: HarnessSessionID,
        content: [HarnessPromptContentPart],
        since lastSequence: Int,
        timeout: TimeInterval,
        completeWhenAdmissionIsClosed: Bool,
        onEvent: @escaping EventHandler,
        completion: @escaping Completion
    ) -> (identifier: UUID, admitted: Bool) {
        let identifier = UUID()
        let dispatcher = MainEventDispatcher(
            handler: onEvent,
            maximumPendingEvents: limits.maximumPendingMainEvents
        )
        let operation = Operation(sessionID: sessionID, dispatcher: dispatcher, completion: completion)
        lock.lock()
        let admitted = acceptingOperations
        if admitted { operations[identifier] = operation }
        lock.unlock()
        guard admitted else {
            if completeWhenAdmissionIsClosed {
                operation.dispatcher.complete {
                    operation.completion(.failure(HarnessConversationError.cancelled))
                    operation.settle()
                }
            }
            return (identifier, false)
        }

        let task = Task { [weak self, weak operation] in
            guard let self, let operation else { return }
            do {
                var budget = TurnBudget(limits: limits)
                let subscription = try rpc.muxEvents(since: [sessionID: max(0, lastSequence)])
                operation.install(subscription: subscription)
                try await subscription.waitUntilOpen()
                try Task.checkCancellation()
                // From this point through response decoding, a transport error
                // cannot prove that DSH did not accept the request. Cancel the
                // exact session on every abnormal exit from this ambiguity
                // window so a "failed" UI turn cannot continue in the server.
                guard operation.enterPromptAmbiguity() else { throw CancellationError() }
                let submission = try await rpc.prompt(
                    sessionID: sessionID,
                    mode: .queue,
                    content: content,
                    clientTimeZone: TimeZone.current.identifier
                )
                guard submission.accepted else {
                    operation.markServerSettled()
                    throw HarnessConversationError.promptRejected
                }
                if let command = submission.command {
                    let event = HarnessMuxEvent.commandResponse(.init(
                        sessionID: sessionID,
                        kind: command.kind,
                        text: command.text
                    ))
                    try budget.admit(event)
                    guard operation.dispatcher.enqueue(event) else {
                        throw HarnessConversationError.streamLimitExceeded
                    }
                    operation.markServerSettled()
                    self.finish(identifier, operation: operation, result: .success(()))
                    return
                }

                var openTurn: Int?
                var submittedTurn: Int?
                var awaitingAutomaticContinuation = false
                var automaticContinuationRound = 0
                var automaticContinuationMaximum: Int?
                var terminalBudgetTurn: Int?

                for try await event in subscription.events {
                    try Task.checkCancellation()
                    guard Self.belongs(event, to: sessionID) else { continue }
                    try budget.admit(event)
                    switch event {
                    case .turnStarted(let start):
                        openTurn = start.turn
                    case .userMessage(let message):
                        if message.sourceRPCID == submission.rpcID {
                            guard let openTurn else {
                                throw HarnessConversationError.streamEnded
                            }
                            submittedTurn = openTurn
                        } else if awaitingAutomaticContinuation {
                            if message.isDirectUserMessage {
                                // The packaged controller deliberately yields to
                                // newer human work. The original max-token turn
                                // is already settled; stop observing without
                                // cancelling the unrelated new task.
                                operation.endAutomaticContinuationWait()
                                operation.markServerSettled()
                                self.finish(
                                    identifier,
                                    operation: operation,
                                    result: .failure(HarnessConversationError.automaticContinuationSuperseded)
                                )
                                return
                            }
                            guard let notice = message.automaticContinuation else { continue }
                            guard let openTurn, submittedTurn == nil else {
                                throw HarnessConversationError.automaticContinuationProtocolViolation
                            }
                            if notice.isTerminalBudgetNotice {
                                guard let maximum = automaticContinuationMaximum,
                                      automaticContinuationRound == maximum else {
                                    throw HarnessConversationError.automaticContinuationProtocolViolation
                                }
                                terminalBudgetTurn = openTurn
                            } else {
                                guard let round = notice.round,
                                      let maximum = notice.maximum,
                                      round == automaticContinuationRound + 1,
                                      automaticContinuationMaximum == nil
                                        || automaticContinuationMaximum == maximum else {
                                    throw HarnessConversationError.automaticContinuationProtocolViolation
                                }
                                automaticContinuationRound = round
                                automaticContinuationMaximum = maximum
                            }
                            submittedTurn = openTurn
                            awaitingAutomaticContinuation = false
                            operation.endAutomaticContinuationWait()
                            guard operation.dispatcher.enqueue(event) else {
                                throw HarnessConversationError.streamLimitExceeded
                            }
                        }
                    case .assistantTextDelta(let value):
                        guard submittedTurn == value.turn else { continue }
                        guard operation.dispatcher.enqueue(event) else {
                            throw HarnessConversationError.streamLimitExceeded
                        }
                    case .assistantFinalMessage(let value):
                        guard submittedTurn == value.turn else { continue }
                        guard operation.dispatcher.enqueue(event) else {
                            throw HarnessConversationError.streamLimitExceeded
                        }
                    case .toolCall(let value):
                        guard submittedTurn == value.turn else { continue }
                        guard operation.dispatcher.enqueue(event) else {
                            throw HarnessConversationError.streamLimitExceeded
                        }
                    case .turnCompleted(let value):
                        guard submittedTurn == value.turn else { continue }
                        guard operation.dispatcher.enqueue(event) else {
                            throw HarnessConversationError.streamLimitExceeded
                        }
                        switch value.reason {
                        case .completed:
                            operation.markServerSettled()
                            self.finish(identifier, operation: operation, result: .success(()))
                            return
                        case .maxTokens:
                            if terminalBudgetTurn == value.turn {
                                operation.markServerSettled()
                                self.finish(
                                    identifier,
                                    operation: operation,
                                    result: .failure(HarnessConversationError.automaticContinuationLimitReached)
                                )
                                return
                            }
                            submittedTurn = nil
                            openTurn = nil
                            awaitingAutomaticContinuation = true
                            guard let waitID = operation.beginAutomaticContinuationWait() else {
                                throw CancellationError()
                            }
                            DispatchQueue.global(qos: .utility).asyncAfter(
                                deadline: .now() + limits.automaticContinuationGraceSeconds
                            ) { [weak self, weak operation] in
                                guard let self, let operation,
                                      operation.expireAutomaticContinuationWait(waitID) else { return }
                                Task {
                                    _ = await self.finishAfterCancellation(
                                        identifier,
                                        operation: operation,
                                        requestedResult: .failure(
                                            HarnessConversationError.automaticContinuationUnavailable
                                        )
                                    )
                                }
                            }
                        case .aborted:
                            operation.markServerSettled()
                            self.finish(identifier, operation: operation, result: .failure(HarnessConversationError.turnAborted))
                            return
                        case .blocked:
                            operation.markServerSettled()
                            self.finish(identifier, operation: operation, result: .failure(HarnessConversationError.turnBlocked))
                            return
                        case .interrupted:
                            operation.markServerSettled()
                            self.finish(identifier, operation: operation, result: .failure(HarnessConversationError.turnInterrupted))
                            return
                        case .other:
                            operation.markServerSettled()
                            self.finish(
                                identifier,
                                operation: operation,
                                result: .failure(HarnessConversationError.unsupportedTurnCompletion)
                            )
                            return
                        }
                    case .turnFailed(let failure) where submittedTurn == failure.turn:
                        operation.markServerSettled()
                        throw HarnessConversationError.turnFailed(ProviderFailurePresentation.classify(
                            code: failure.failure.code,
                            status: failure.failure.status,
                            retryAfterMilliseconds: failure.failure.providerRetryAfterMs,
                            requestID: failure.failure.requestId
                        ))
                    case .streamError(let failure):
                        throw HarnessConversationError.turnFailed(ProviderFailurePresentation.classify(
                            code: failure.code.rawValue,
                            status: nil
                        ))
                    case .approvalRequested, .approvalResolved, .questionRequested, .questionResolved:
                        guard submittedTurn != nil else { continue }
                        guard operation.dispatcher.enqueue(event) else {
                            throw HarnessConversationError.streamLimitExceeded
                        }
                    default:
                        break
                    }
                }
                throw HarnessConversationError.streamEnded
            } catch is CancellationError {
                _ = await self.finishAfterCancellation(
                    identifier,
                    operation: operation,
                    requestedResult: .failure(HarnessConversationError.cancelled)
                )
            } catch {
                _ = await self.finishAfterCancellation(
                    identifier,
                    operation: operation,
                    requestedResult: .failure(error)
                )
            }
        }
        operation.install(task: task)

        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + max(1, timeout)) { [weak self, weak operation] in
            guard let self, let operation else { return }
            Task {
                _ = await self.finishAfterCancellation(
                    identifier,
                    operation: operation,
                    requestedResult: .failure(HarnessConversationError.timedOut)
                )
            }
        }
        return (identifier, true)
    }

    func cancel(_ identifier: UUID, sessionID: HarnessSessionID) {
        lock.lock(); let operation = operations[identifier]; lock.unlock()
        guard let operation else { return }
        // The operation owns the authoritative opaque session identity. Never
        // let a stale caller-provided value redirect cancellation elsewhere.
        _ = sessionID
        Task { [weak self, weak operation] in
            guard let self, let operation else { return }
            _ = await self.finishAfterCancellation(
                identifier,
                operation: operation,
                requestedResult: .failure(HarnessConversationError.cancelled)
            )
        }
    }

    func respond(to request: HarnessApprovalRequest, decision: HarnessApprovalDecision) async throws {
        guard beginAncillaryRPC() else { throw HarnessConversationError.cancelled }
        defer { endAncillaryRPC() }
        let receipt = try await rpc.respondToApproval(
            rpcID: request.rpcID,
            sessionID: request.sessionID,
            approvalID: request.approvalID,
            decision: decision
        )
        guard receipt.accepted else { throw HarnessConversationError.promptRejected }
    }

    func respond(to request: HarnessQuestionRequest, answer: HarnessQuestionAnswer) async throws {
        guard beginAncillaryRPC() else { throw HarnessConversationError.cancelled }
        defer { endAncillaryRPC() }
        let receipt = try await rpc.respondToQuestion(
            rpcID: request.rpcID,
            sessionID: request.sessionID,
            answer: answer
        )
        guard receipt.accepted else { throw HarnessConversationError.promptRejected }
    }

    func cancel(_ request: HarnessQuestionRequest) async throws {
        guard beginAncillaryRPC() else { throw HarnessConversationError.cancelled }
        defer { endAncillaryRPC() }
        let receipt = try await rpc.cancelQuestion(rpcID: request.rpcID)
        guard receipt.accepted else { throw HarnessConversationError.promptRejected }
    }

    func cancelAll() {
        let items = beginCancellation(
            suspendAdmissions: false,
            requestedResult: .failure(HarnessConversationError.cancelled)
        )
        Task { [weak self] in _ = await self?.completeCancellation(items) }
    }

    /// Closes admission first, then waits for every local operation to settle
    /// and every possibly-submitted DSH session to acknowledge exact-session
    /// cancellation. Provider, credential, workspace, backup, and update
    /// mutations must not proceed unless this barrier succeeds.
    func quiesce() async throws {
        closeAdmissions()
        try await quiesceSuspendedAdmissions()
    }

    /// Synchronously closes admission at an application lifecycle boundary.
    /// The caller must subsequently await `quiesceSuspendedAdmissions()` and
    /// retain the hold until the protected transition has settled.
    func suspendAdmissionsForQuiescence() {
        closeAdmissions()
    }

    /// Drains a hold established synchronously by
    /// `suspendAdmissionsForQuiescence()`. Ancillary RPC settlement and exact
    /// turn cancellation run concurrently so the barrier remains bounded by
    /// the slower RPC deadline rather than their sum.
    func quiesceSuspendedAdmissions() async throws {
        guard hasSuspendedAdmissions() else {
            throw HarnessConversationError.cancellationUnverified
        }

        async let ancillarySettlement: Void = waitForAncillaryRPCs()
        let items = beginCancellation(
            suspendAdmissions: false,
            requestedResult: .failure(HarnessConversationError.cancelled)
        )
        async let cancellationVerified: Bool = completeCancellation(items)
        await ancillarySettlement
        if hasUnverifiedSessionCleanup() {
            throw HarnessConversationError.sessionCleanupUnverified
        }
        guard await cancellationVerified else {
            throw HarnessConversationError.cancellationUnverified
        }
    }

    /// Reopens admission only after the protected mutation has either finished
    /// or failed and the host has restored a coherent runtime configuration.
    func resumeAfterQuiescence() {
        lock.lock()
        guard quiescenceHolds > 0 else { lock.unlock(); return }
        quiescenceHolds -= 1
        if quiescenceHolds == 0, !cleanupFailureRecorded { acceptingOperations = true }
        lock.unlock()
    }

    @discardableResult
    private func finish(
        _ identifier: UUID,
        operation: Operation,
        result: Result<Void, Error>
    ) -> Bool {
        guard operation.claimTerminal() else { return false }
        finishClaimed(identifier, operation: operation, result: result)
        return true
    }

    private func finishClaimed(
        _ identifier: UUID,
        operation: Operation,
        result: Result<Void, Error>
    ) {
        operation.cancelTransports()
        operation.dispatcher.complete {
            operation.completion(result)
            self.lock.lock()
            if self.operations[identifier] === operation {
                self.operations.removeValue(forKey: identifier)
            }
            self.lock.unlock()
            operation.settle()
        }
    }

    @discardableResult
    private func finishAfterCancellation(
        _ identifier: UUID,
        operation: Operation,
        requestedResult: Result<Void, Error>
    ) async -> Bool {
        let ownsTerminal = operation.claimTerminal()
        operation.requestCancellation()
        let remoteCancellation = makeRemoteCancellationIfNeeded(for: operation)
        let verified = await remoteCancellation?.value ?? true
        if ownsTerminal {
            let result = verified
                ? requestedResult
                : .failure(HarnessConversationError.cancellationUnverified)
            finishClaimed(identifier, operation: operation, result: result)
        }
        await operation.waitUntilSettled()
        return verified
    }

    private func beginCancellation(
        suspendAdmissions: Bool,
        requestedResult: Result<Void, Error>
    ) -> [CancellationItem] {
        lock.lock()
        if suspendAdmissions { acceptingOperations = false }
        let active = operations.map { ($0.key, $0.value) }
        lock.unlock()

        return active.map { identifier, operation in
            let ownsTerminal = operation.claimTerminal()
            operation.requestCancellation()
            return CancellationItem(
                identifier: identifier,
                operation: operation,
                ownsTerminal: ownsTerminal,
                requestedResult: requestedResult,
                remoteCancellation: makeRemoteCancellationIfNeeded(for: operation)
            )
        }
    }

    private func completeCancellation(_ items: [CancellationItem]) async -> Bool {
        var allVerified = true
        for item in items {
            let verified = await item.remoteCancellation?.value ?? true
            allVerified = allVerified && verified
            if item.ownsTerminal {
                let result = verified
                    ? item.requestedResult
                    : .failure(HarnessConversationError.cancellationUnverified)
                finishClaimed(item.identifier, operation: item.operation, result: result)
            }
            await item.operation.waitUntilSettled()
        }
        return allVerified
    }

    private func makeRemoteCancellationIfNeeded(for operation: Operation) -> Task<Bool, Never>? {
        operation.ensureRemoteCancellationTask { [rpc, sessionID = operation.sessionID] in
            Task.detached(priority: .utility) {
                do { return try await rpc.cancel(sessionID: sessionID).accepted }
                catch { return false }
            }
        }
    }

    private func closeAdmissions() {
        lock.lock()
        quiescenceHolds += 1
        acceptingOperations = false
        lock.unlock()
    }

    private func hasSuspendedAdmissions() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return quiescenceHolds > 0 && !acceptingOperations
    }

    private func beginAncillaryRPC() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard acceptingOperations, !cleanupFailureRecorded else { return false }
        activeAncillaryRPCs += 1
        return true
    }

    private func recordUnverifiedSessionCleanup() {
        lock.lock()
        cleanupFailureRecorded = true
        acceptingOperations = false
        lock.unlock()
    }

    private func hasUnverifiedSessionCleanup() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return cleanupFailureRecorded
    }

    private func beginAncillaryCleanupRPC() {
        lock.lock()
        activeAncillaryRPCs += 1
        lock.unlock()
    }

    private func endAncillaryRPC() {
        lock.lock()
        precondition(activeAncillaryRPCs > 0)
        activeAncillaryRPCs -= 1
        let waiters: [CheckedContinuation<Void, Never>]
        if activeAncillaryRPCs == 0 {
            waiters = ancillarySettlementWaiters
            ancillarySettlementWaiters.removeAll()
        } else {
            waiters = []
        }
        lock.unlock()
        waiters.forEach { $0.resume() }
    }

    private func waitForAncillaryRPCs() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if activeAncillaryRPCs == 0 {
                lock.unlock()
                continuation.resume()
            } else {
                ancillarySettlementWaiters.append(continuation)
                lock.unlock()
            }
        }
    }

    private static func belongs(_ event: HarnessMuxEvent, to sessionID: HarnessSessionID) -> Bool {
        switch event {
        case .subscribed(let value): return value.sessionID == sessionID
        case .turnStarted(let value): return value.sessionID == sessionID
        case .userMessage(let value): return value.sessionID == sessionID
        case .commandResponse(let value): return value.sessionID == sessionID
        case .toolCall(let value): return value.sessionID == sessionID
        case .assistantTextDelta(let value): return value.sessionID == sessionID
        case .assistantFinalMessage(let value): return value.sessionID == sessionID
        case .turnCompleted(let value): return value.sessionID == sessionID
        case .turnFailed(let value): return value.sessionID == sessionID
        case .approvalRequested(let value): return value.sessionID == sessionID
        case .approvalResolved(let value): return value.sessionID == sessionID
        case .questionRequested(let value): return value.sessionID == sessionID
        case .questionResolved(let value): return value.sessionID == sessionID
        case .streamError: return true
        }
    }
}
