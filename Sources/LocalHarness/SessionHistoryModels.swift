import Foundation

/// The narrow DSH session surface consumed by native history. Keeping the UI on
/// this seam makes it testable and prevents it from reaching around the
/// authenticated Harness transport.
protocol HarnessSessionHistoryRPCServicing: Sendable {
    func listSessions(cursor: String?) async throws -> HarnessSessionList
    func searchSessions(query: String) async throws -> HarnessSessionSearchResult
    func createSession(_ request: HarnessSessionCreateRequest) async throws -> HarnessSessionCreateResult
    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection
    func renameSession(_ sessionID: HarnessSessionID, title: String) async throws -> HarnessSessionRenameResult
    func forkSession(_ sessionID: HarnessSessionID, atSequence: Int?) async throws -> HarnessSessionForkResult
    func archiveSession(_ sessionID: HarnessSessionID) async throws -> HarnessArchivedSessionsResult
    func sessionHistory(
        _ sessionID: HarnessSessionID,
        beforeSequence: Int?,
        maximumMessages: Int?
    ) async throws -> HarnessSessionHistoryPage
    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels
}

extension HarnessRPCClient: HarnessSessionHistoryRPCServicing {}

struct SessionHistoryRepositoryLimits: Equatable, Sendable {
    let pageMessages: Int
    let maximumPageMessages: Int
    let titleCharacters: Int
    let snippetCharacters: Int
    let messageCharacters: Int

    init(
        pageMessages: Int = 50,
        maximumPageMessages: Int = 100,
        titleCharacters: Int = 160,
        snippetCharacters: Int = 320,
        messageCharacters: Int = 100_000
    ) {
        precondition(pageMessages > 0 && maximumPageMessages >= pageMessages)
        precondition(titleCharacters > 0 && snippetCharacters > 0 && messageCharacters > 0)
        self.pageMessages = pageMessages
        self.maximumPageMessages = maximumPageMessages
        self.titleCharacters = titleCharacters
        self.snippetCharacters = snippetCharacters
        self.messageCharacters = messageCharacters
    }
}

struct SessionHistoryRow: Equatable, Sendable, Identifiable {
    let id: HarnessSessionID
    let title: String
    /// A basename-only project label. The native history surface never exposes
    /// an absolute workspace path.
    let projectLabel: String?
    let updatedAt: Date
    let running: Bool
    let searchSnippet: String?
}

struct SessionHistoryBrowseSnapshot: Equatable, Sendable {
    let rows: [SessionHistoryRow]
    let query: String?
    let hasMoreSearchResults: Bool
}

enum SessionTranscriptRole: String, Equatable, Sendable {
    case user
    case assistant

    var displayName: String {
        switch self {
        case .user: return "You"
        case .assistant: return "Assistant"
        }
    }
}

struct SessionTranscriptMessage: Equatable, Sendable, Identifiable {
    let sequence: Int
    let role: SessionTranscriptRole
    let text: String
    let date: Date
    let interrupted: Bool
    /// Exact provenance for model-produced messages. This may differ from the
    /// session's current route when a user switched models mid-conversation.
    let source: SessionTranscriptSource?

    var id: Int { sequence }
}

struct SessionTranscriptSource: Equatable, Sendable {
    let route: ModelRoute
    let boundary: DataBoundary
}

enum SessionTranscriptSourcePolicy {
    static func source(
        provider rawProvider: String,
        model rawModel: String,
        boundary: DataBoundary
    ) -> SessionTranscriptSource? {
        guard let provider = validated(rawProvider, label: "transcript provider identifier"),
              let model = validated(rawModel, label: "transcript model identifier") else {
            return nil
        }
        return SessionTranscriptSource(
            route: ModelRoute(provider: ProviderID(provider), model: ModelID(model)),
            boundary: boundary
        )
    }

    static func acceptedAssistantSource(
        provider: ProviderID?,
        model: ModelID?,
        expectedRoute: ModelRoute?
    ) -> ModelRoute? {
        guard let provider, let model, let expectedRoute else { return nil }
        let route = ModelRoute(provider: provider, model: model)
        return route == expectedRoute ? route : nil
    }

    static func retainedByteCount(
        content: String,
        provider: String?,
        model: String?,
        source: SessionTranscriptSource?
    ) -> Int {
        var result = content.utf8.count
        for count in [
            provider?.utf8.count ?? 0,
            model?.utf8.count ?? 0,
            source?.route.provider.rawValue.utf8.count ?? 0,
            source?.route.model.rawValue.utf8.count ?? 0
        ] {
            let addition = result.addingReportingOverflow(count)
            if addition.overflow { return Int.max }
            result = addition.partialValue
        }
        return result
    }

    private static func validated(_ value: String, label: String) -> String? {
        try? HarnessCatalogWirePolicy.opaqueIdentifier(value, codingPath: [], label: label)
    }
}

struct SessionTranscriptPage: Equatable, Sendable {
    let messages: [SessionTranscriptMessage]
    /// Pass this value back as `beforeSequence` to read the next older page.
    let olderBeforeSequence: Int?
}

struct SessionTranscriptMergeResult: Equatable, Sendable {
    let messages: [SessionTranscriptMessage]
    let truncated: Bool
}

enum SessionTranscriptAccumulator {
    /// Merges backward pages while retaining the newest bounded transcript.
    /// Sequence identity de-duplicates an overlapping page boundary.
    static func merge(
        older: [SessionTranscriptMessage],
        newer: [SessionTranscriptMessage],
        maximumMessages: Int = 1_000,
        maximumCharacters: Int = 2_000_000
    ) -> SessionTranscriptMergeResult {
        precondition(maximumMessages > 0 && maximumCharacters > 0)
        var bySequence: [Int: SessionTranscriptMessage] = [:]
        for message in older + newer { bySequence[message.sequence] = message }
        let ordered = bySequence.values.sorted { $0.sequence < $1.sequence }

        var retained: [SessionTranscriptMessage] = []
        retained.reserveCapacity(min(ordered.count, maximumMessages))
        var retainedBytes = 0
        for message in ordered.reversed() {
            guard retained.count < maximumMessages else { break }
            let nextCount = SessionTranscriptSourcePolicy.retainedByteCount(
                content: message.text,
                provider: nil,
                model: nil,
                source: message.source
            )
            let addition = retainedBytes.addingReportingOverflow(nextCount)
            guard retained.isEmpty || (!addition.overflow && addition.partialValue <= maximumCharacters) else {
                break
            }
            retained.append(message)
            retainedBytes = addition.overflow ? Int.max : addition.partialValue
        }
        retained.reverse()
        return SessionTranscriptMergeResult(
            messages: retained,
            truncated: retained.count < ordered.count
        )
    }
}

struct SessionRouteMetadata: Equatable, Sendable {
    /// Exact opaque identifiers remain separate even when they contain `/` or
    /// `:`. Display labels are independent presentation values.
    let route: ModelRoute
    let providerName: String
    let modelName: String
    let reasoningEffort: String?
    let boundary: DataBoundary
    let routable: Bool
}

enum SessionRouteMetadataState: Equatable, Sendable {
    case available(SessionRouteMetadata)
    /// History remains readable if model discovery is temporarily unavailable;
    /// the UI must not guess a provider or data boundary in that state.
    case unavailable
}

struct SessionHistoryDetailSnapshot: Equatable, Sendable {
    let sessionID: HarnessSessionID
    let transcript: SessionTranscriptPage
    let route: SessionRouteMetadataState
}

protocol SessionHistoryDataProviding: Sendable {
    func browse(query: String?) async throws -> SessionHistoryBrowseSnapshot
    func detail(for sessionID: HarnessSessionID) async throws -> SessionHistoryDetailSnapshot
    func olderPage(for sessionID: HarnessSessionID, beforeSequence: Int) async throws -> SessionTranscriptPage
    func createSession(
        _ request: HarnessSessionCreateRequest,
        selection: ModelSelection
    ) async throws -> HarnessSessionID
    func renameSession(_ sessionID: HarnessSessionID, title: String) async throws
    func forkSession(_ sessionID: HarnessSessionID, atSequence: Int?) async throws -> HarnessSessionID
    func archiveSession(_ sessionID: HarnessSessionID) async throws
    /// Compensates a newly created task whose UI owner disappeared before the
    /// session ID could be handed off. Production implementations must make
    /// this caller-cancellation-insensitive and verify the exact archive ID.
    func discardUnownedSession(_ sessionID: HarnessSessionID) async throws
}

extension SessionHistoryDataProviding {
    func discardUnownedSession(_ sessionID: HarnessSessionID) async throws {
        try await archiveSession(sessionID)
    }
}

/// Shared synchronous admission gate for every native Task History RPC. An
/// outer UI ownership lease can span create -> handoff/cleanup, which prevents a
/// protected transition from observing a false zero between those phases.
final class SessionHistoryLifecycleGate: @unchecked Sendable {
    private let lock = NSLock()
    private var activeOperations = 0
    private var quiescenceHolds = 0
    private var cleanupPoisoned = false
    private var settlementWaiters: [CheckedContinuation<Void, Never>] = []

    func beginOperation() throws {
        lock.lock(); defer { lock.unlock() }
        guard !cleanupPoisoned else { throw HarnessConversationError.sessionCleanupUnverified }
        guard quiescenceHolds == 0 else { throw HarnessConversationError.cancelled }
        activeOperations += 1
    }

    /// Cleanup is allowed after admission closes, but its owning outer lease is
    /// already active. Therefore a quiescence waiter cannot cross the cleanup's
    /// admission edge.
    func beginCleanupOperation() {
        lock.lock()
        activeOperations += 1
        lock.unlock()
    }

    func endOperation() {
        lock.lock()
        precondition(activeOperations > 0)
        activeOperations -= 1
        let waiters: [CheckedContinuation<Void, Never>]
        if activeOperations == 0 {
            waiters = settlementWaiters
            settlementWaiters.removeAll()
        } else {
            waiters = []
        }
        lock.unlock()
        waiters.forEach { $0.resume() }
    }

    func recordCleanupFailure() {
        lock.lock()
        cleanupPoisoned = true
        lock.unlock()
    }

    func suspendAdmissionsForQuiescence() {
        lock.lock()
        quiescenceHolds += 1
        lock.unlock()
    }

    func quiesceSuspendedAdmissions() async throws {
        let suspended = lock.withSessionHistoryLifecycleLock {
            quiescenceHolds > 0
        }
        guard suspended else { throw HarnessConversationError.cancellationUnverified }
        await withCheckedContinuation { continuation in
            lock.lock()
            if activeOperations == 0 {
                lock.unlock()
                continuation.resume()
            } else {
                settlementWaiters.append(continuation)
                lock.unlock()
            }
        }
        let poisoned = lock.withSessionHistoryLifecycleLock { cleanupPoisoned }
        guard !poisoned else { throw HarnessConversationError.sessionCleanupUnverified }
    }

    func resumeAfterQuiescence() {
        lock.lock()
        guard quiescenceHolds > 0 else { lock.unlock(); return }
        quiescenceHolds -= 1
        lock.unlock()
    }

    func cleanupFailureRecorded() -> Bool {
        lock.withSessionHistoryLifecycleLock { cleanupPoisoned }
    }
}

/// Repository calls made inside the controller's create-ownership lease must
/// not acquire a second admission after a protected boundary has closed.
enum SessionHistoryLifecycleContext {
    @TaskLocal static var ownsOuterAdmission = false
}

/// Authenticated, bounded projection of DSH session data for native history.
/// DSH remains authoritative for ordering, search ranking, persistence, and the
/// currently selected model route.
actor SessionHistoryRepository: SessionHistoryDataProviding {
    private let service: any HarnessSessionHistoryRPCServicing
    private let limits: SessionHistoryRepositoryLimits
    private let lifecycle: SessionHistoryLifecycleGate
    private var descriptors: [ProviderID: ProviderDescriptor]

    init(
        service: any HarnessSessionHistoryRPCServicing,
        descriptors: [ProviderDescriptor] = BuiltInProviderDescriptors.all,
        limits: SessionHistoryRepositoryLimits = .init(),
        lifecycle: SessionHistoryLifecycleGate = .init()
    ) {
        self.service = service
        self.limits = limits
        self.lifecycle = lifecycle
        self.descriptors = descriptors.reduce(into: [:]) { values, descriptor in
            values[descriptor.id] = descriptor
        }
    }

    /// Replaces static fallbacks with the just-verified live endpoint topology.
    /// History and per-message provenance must classify a remote `ollama`
    /// endpoint as LAN/cloud rather than trusting its opaque provider ID.
    func updateProviderDescriptors(_ descriptors: [ProviderDescriptor]) {
        self.descriptors = descriptors.reduce(into: [:]) { values, descriptor in
            values[descriptor.id] = descriptor
        }
    }

    func browse(query: String? = nil) async throws -> SessionHistoryBrowseSnapshot {
        let normalizedQuery = query?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard normalizedQuery.utf16.count <= 500, !normalizedQuery.contains("\0") else {
            throw HarnessRPCClientError.invalidArgument
        }
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }

        let summaries = try await service.listSessions(cursor: nil).items
        // Match DSH's own top-level workspace browser: provisional blank tasks
        // and subagent implementation sessions are not independent history rows.
        let visible = summaries.filter { !$0.blank && $0.origin != "subagent" }
        let summariesByID = Dictionary(visible.map { ($0.sessionId, $0) }, uniquingKeysWith: { first, _ in first })

        guard !normalizedQuery.isEmpty else {
            let rows = visible.map { row(from: $0, snippet: nil) }.sorted(by: Self.moreRecent)
            return SessionHistoryBrowseSnapshot(rows: rows, query: nil, hasMoreSearchResults: false)
        }

        let result = try await service.searchSessions(query: normalizedQuery)
        let rows = result.items.compactMap { item -> SessionHistoryRow? in
            guard let summary = summariesByID[item.sessionId] else { return nil }
            return row(from: summary, snippet: item.snippet)
        }
        return SessionHistoryBrowseSnapshot(
            rows: rows,
            query: normalizedQuery,
            hasMoreSearchResults: result.hasMore
        )
    }

    func detail(for sessionID: HarnessSessionID) async throws -> SessionHistoryDetailSnapshot {
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }
        async let history = service.sessionHistory(
            sessionID,
            beforeSequence: nil,
            maximumMessages: limits.pageMessages
        )
        async let routeResult = loadRoute(for: sessionID)

        return try await SessionHistoryDetailSnapshot(
            sessionID: sessionID,
            transcript: transcript(from: history),
            route: routeResult
        )
    }

    func olderPage(for sessionID: HarnessSessionID, beforeSequence: Int) async throws -> SessionTranscriptPage {
        guard beforeSequence >= 0 else { throw HarnessRPCClientError.invalidArgument }
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }
        let page = try await service.sessionHistory(
            sessionID,
            beforeSequence: beforeSequence,
            maximumMessages: limits.pageMessages
        )
        return transcript(from: page)
    }

    func createSession(
        _ request: HarnessSessionCreateRequest = .init(),
        selection: ModelSelection = .defaultLocal
    ) async throws -> HarnessSessionID {
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }
        let ownsNewSession = request.reuseWorkspaceBlank != true
        let preallocatedSessionID = ownsNewSession
            ? (request.sessionId ?? PerformanceSessionIdentity.make(profile: selection.performanceProfile))
            : request.sessionId
        let effectiveRequest = HarnessSessionCreateRequest(
            workspaceId: request.workspaceId,
            cwd: request.cwd,
            sessionId: preallocatedSessionID,
            agentPreset: request.agentPreset,
            reuseWorkspaceBlank: request.reuseWorkspaceBlank
        )
        let created: HarnessSessionCreateResult
        do {
            created = try await service.createSession(effectiveRequest)
        } catch {
            if ownsNewSession,
               let preallocatedSessionID,
               HarnessSessionCleanup.requiresCompensation(after: error) {
                let archived = await HarnessSessionCleanup.archive(sessionID: preallocatedSessionID) { [service] in
                    try await service.archiveSession(preallocatedSessionID)
                }
                guard archived else {
                    lifecycle.recordCleanupFailure()
                    throw HarnessConversationError.sessionCleanupUnverified
                }
            }
            throw error
        }
        if ownsNewSession, let preallocatedSessionID, created.sessionId != preallocatedSessionID {
            let archived = await HarnessSessionCleanup.archive(sessionID: preallocatedSessionID) { [service] in
                try await service.archiveSession(preallocatedSessionID)
            }
            guard archived else {
                lifecycle.recordCleanupFailure()
                throw HarnessConversationError.sessionCleanupUnverified
            }
            throw HarnessRPCClientError.responseViolation(.invalidPayload)
        }
        do {
            try Task.checkCancellation()
            _ = try await service.selectModel(
                sessionID: created.sessionId,
                selection: HarnessWireModelSelection(
                    route: selection.route,
                    reasoningEffort: selection.reasoningEffort
                )
            )
            try Task.checkCancellation()
            return created.sessionId
        } catch {
            // `reuseWorkspaceBlank` deliberately adopts an existing Harness
            // task rather than creating an app-owned session. A failed model
            // selection must never let an untrusted/mismatched create response
            // redirect compensation onto that existing opaque session ID.
            guard ownsNewSession else { throw error }
            let archived = await HarnessSessionCleanup.archive(sessionID: created.sessionId) { [service] in
                try await service.archiveSession(created.sessionId)
            }
            guard archived else {
                lifecycle.recordCleanupFailure()
                throw HarnessConversationError.sessionCleanupUnverified
            }
            throw error
        }
    }

    func renameSession(_ sessionID: HarnessSessionID, title: String) async throws {
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }
        _ = try await service.renameSession(sessionID, title: title)
    }

    func forkSession(_ sessionID: HarnessSessionID, atSequence: Int? = nil) async throws -> HarnessSessionID {
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }
        let forked = try await service.forkSession(sessionID, atSequence: atSequence)
        return forked.sessionId
    }

    func archiveSession(_ sessionID: HarnessSessionID) async throws {
        let ownsAdmission = try beginTrackedOperation()
        defer { endTrackedOperation(ifOwned: ownsAdmission) }
        let result = try await service.archiveSession(sessionID)
        guard result.archivedSessionIds.contains(sessionID) else {
            throw HarnessConversationError.sessionCleanupUnverified
        }
    }

    func discardUnownedSession(_ sessionID: HarnessSessionID) async throws {
        if SessionHistoryLifecycleContext.ownsOuterAdmission {
            lifecycle.beginCleanupOperation()
        } else {
            // Defensive fallback for any future caller that does not own the UI
            // handoff lease: it may clean up only while ordinary admission is
            // still open, so it cannot appear after a completed barrier.
            try lifecycle.beginOperation()
        }
        defer { lifecycle.endOperation() }
        let archived = await HarnessSessionCleanup.archive(sessionID: sessionID) { [service] in
            try await service.archiveSession(sessionID)
        }
        guard archived else {
            lifecycle.recordCleanupFailure()
            throw HarnessConversationError.sessionCleanupUnverified
        }
    }

    private func beginTrackedOperation() throws -> Bool {
        guard !SessionHistoryLifecycleContext.ownsOuterAdmission else { return false }
        try lifecycle.beginOperation()
        return true
    }

    private func endTrackedOperation(ifOwned ownsAdmission: Bool) {
        if ownsAdmission { lifecycle.endOperation() }
    }

    private func loadRoute(for sessionID: HarnessSessionID) async -> SessionRouteMetadataState {
        do {
            let state = try await service.sessionModels(sessionID)
            let providerGroup = state.groups.first { $0.id == state.current.provider }
            let model = providerGroup?.models.first { $0.id == state.current.model }
            let descriptor = descriptors[state.current.provider]
            let providerName = SessionHistorySafeText.inline(
                providerGroup?.name ?? descriptor?.displayName ?? state.current.provider.rawValue,
                limit: limits.titleCharacters
            )
            let modelName = SessionHistorySafeText.inline(
                model?.name ?? state.current.model.rawValue,
                limit: limits.titleCharacters
            )
            return .available(SessionRouteMetadata(
                route: state.current.route,
                providerName: providerName,
                modelName: modelName,
                reasoningEffort: state.current.reasoningEffort.map {
                    SessionHistorySafeText.inline($0, limit: limits.titleCharacters)
                },
                // Unknown providers fail closed: their content boundary is cloud
                // until the app has an explicit descriptor for that exact ID.
                boundary: descriptor?.boundary ?? .cloud,
                routable: state.routable
            ))
        } catch {
            return .unavailable
        }
    }

    private func row(from summary: HarnessSessionSummary, snippet: String?) -> SessionHistoryRow {
        let projectedTitle = summary.projections?.values["title"]?.stringValue
        let projectLabel = Self.projectLabel(from: summary.cwd).map {
            SessionHistorySafeText.inline($0, limit: limits.titleCharacters)
        }
        let fallback = projectLabel ?? summary.sessionId.rawValue
        let title = SessionHistorySafeText.inline(
            projectedTitle.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 } ?? fallback,
            limit: limits.titleCharacters
        )
        return SessionHistoryRow(
            id: summary.sessionId,
            title: title.isEmpty ? "Untitled Task" : title,
            projectLabel: projectLabel?.isEmpty == false ? projectLabel : nil,
            updatedAt: Self.date(fromWireTime: summary.updatedAt),
            running: summary.running,
            searchSnippet: snippet.map {
                SessionHistorySafeText.inline($0, limit: limits.snippetCharacters)
            }
        )
    }

    private func transcript(from page: HarnessSessionHistoryPage) -> SessionTranscriptPage {
        let projected = page.events
            .compactMap { message(from: $0.event) }
            .sorted { $0.sequence < $1.sequence }
        let messages = Array(projected.suffix(limits.maximumPageMessages))
        let earliestSequence = messages.first?.sequence
        return SessionTranscriptPage(
            messages: messages,
            olderBeforeSequence: (page.hasMore || messages.count < projected.count) ? earliestSequence : nil
        )
    }

    private func message(from event: HarnessSessionEventRecord) -> SessionTranscriptMessage? {
        guard Self.isAppendSurface(event.surfaceOp),
              let eventData = event.data.objectValue else { return nil }

        let role: SessionTranscriptRole
        let message: [String: HarnessJSONValue]
        let interrupted: Bool
        switch event.type {
        case "user/message":
            guard eventData["role"]?.stringValue == "user",
                  eventData["source"]?.objectValue?["kind"]?.stringValue == "user" else { return nil }
            role = .user
            message = eventData
            interrupted = false
        case "assistant/message":
            guard let assistant = eventData["message"]?.objectValue,
                  assistant["role"]?.stringValue == "assistant" else { return nil }
            role = .assistant
            message = assistant
            if case .bool(true)? = eventData["interrupted"] { interrupted = true } else { interrupted = false }
        default:
            return nil
        }

        guard case .array(let blocks)? = message["content"] else { return nil }
        let text = blocks.compactMap { block -> String? in
            guard let object = block.objectValue,
                  object["type"]?.stringValue == "text" else { return nil }
            return object["text"]?.stringValue
        }.joined(separator: "\n")
        let rendered = SessionHistorySafeText.multiline(text, limit: limits.messageCharacters)
        guard !rendered.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        let source: SessionTranscriptSource?
        if role == .assistant,
           let sourceObject = message["source"]?.objectValue,
           let provider = sourceObject["provider"]?.stringValue,
           let model = sourceObject["model"]?.stringValue,
           let validated = SessionTranscriptSourcePolicy.source(
               provider: provider,
               model: model,
               boundary: descriptors[ProviderID(provider)]?.boundary ?? .cloud
           ) {
            source = validated
        } else {
            source = nil
        }
        return SessionTranscriptMessage(
            sequence: event.seq,
            role: role,
            text: rendered,
            date: Self.date(fromWireTime: event.time),
            interrupted: interrupted,
            source: source
        )
    }

    private static func isAppendSurface(_ value: HarnessJSONValue?) -> Bool {
        guard let value else { return true }
        return value.stringValue == "append"
    }

    private static func projectLabel(from path: String?) -> String? {
        guard let path else { return nil }
        let trimmed = path.trimmingCharacters(in: CharacterSet(charactersIn: "/\\"))
        guard !trimmed.isEmpty else { return nil }
        return trimmed.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init)
    }

    private static func date(fromWireTime value: Double) -> Date {
        // DSH currently emits JavaScript milliseconds. Accept seconds as well so
        // older or alternate compatible runtimes remain readable.
        let seconds = abs(value) > 100_000_000_000 ? value / 1_000 : value
        return Date(timeIntervalSince1970: seconds)
    }

    private static func moreRecent(_ lhs: SessionHistoryRow, _ rhs: SessionHistoryRow) -> Bool {
        if lhs.updatedAt != rhs.updatedAt { return lhs.updatedAt > rhs.updatedAt }
        return lhs.id.rawValue < rhs.id.rawValue
    }
}

private extension NSLock {
    func withSessionHistoryLifecycleLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}

/// Text arriving from session logs and provider catalogs is always rendered as
/// inert native text. These helpers additionally remove terminal controls and
/// bidi overrides, normalize line endings, and enforce UI memory bounds.
enum SessionHistorySafeText {
    static func inline(_ value: String, limit: Int) -> String {
        let flattened = sanitized(value)
            .split(whereSeparator: \Character.isWhitespace)
            .joined(separator: " ")
        return bounded(flattened, limit: limit)
    }

    static func multiline(_ value: String, limit: Int) -> String {
        bounded(sanitized(value), limit: limit)
    }

    private static func sanitized(_ value: String) -> String {
        let normalized = value.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        var result = ""
        result.reserveCapacity(min(normalized.utf8.count, 100_000))
        for scalar in normalized.unicodeScalars {
            if scalar == "\n" || scalar == "\t" {
                result.unicodeScalars.append(scalar)
                continue
            }
            guard !CharacterSet.controlCharacters.contains(scalar), !isBidirectionalControl(scalar.value) else {
                continue
            }
            result.unicodeScalars.append(scalar)
        }
        return result
    }

    private static func bounded(_ value: String, limit: Int) -> String {
        precondition(limit > 0)
        guard value.count > limit else { return value }
        guard limit > 1 else { return "…" }
        return String(value.prefix(limit - 1)) + "…"
    }

    private static func isBidirectionalControl(_ value: UInt32) -> Bool {
        value == 0x061C || value == 0x200E || value == 0x200F
            || (0x202A...0x202E).contains(value)
            || (0x2066...0x2069).contains(value)
    }
}

/// Deliberately does not surface adapter-owned error messages: provider errors
/// can contain echoed input or endpoint details. Diagnostics retain the typed
/// underlying error while the history window presents bounded neutral copy.
enum SessionHistoryErrorMessage {
    static func message(for error: Error) -> String {
        guard let error = error as? HarnessRPCClientError else {
            return "Task history could not be loaded."
        }
        switch error {
        case .endpointUnavailable, .endpointChanged, .controlPlaneOnly, .invalidEndpoint:
            return "The private Harness runtime is not connected."
        case .invalidArgument:
            return "That history request is not valid."
        case .requestTooLarge, .responseTooLarge:
            return "This history item exceeds the app’s safety limit."
        case .timedOut:
            return "The history request timed out."
        case .cancelled:
            return "The history request was cancelled."
        case .remote(let remote) where remote.code == .sessionNotFound:
            return "This task is no longer available."
        case .remote, .httpStatus, .responseViolation, .rpcIDMismatch, .transport:
            return "The private Harness runtime could not load task history."
        }
    }
}
