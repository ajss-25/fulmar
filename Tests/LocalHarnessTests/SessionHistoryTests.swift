import AppKit
import Foundation
import Testing
@testable import LocalHarness

private actor FakeSessionHistoryRPC: HarnessSessionHistoryRPCServicing {
    var sessions: HarnessSessionList
    var searchResult: HarnessSessionSearchResult
    var tailHistory: HarnessSessionHistoryPage
    var olderHistories: [Int: HarnessSessionHistoryPage]
    var models: HarnessSessionModels
    var modelError: HarnessRPCClientError?
    var selectionError: HarnessRPCClientError?
    var createFailureAfterPersistence: HarnessRPCClientError?
    var forceCreatedResponse = false
    var archiveIncludesRequestedSession = true
    var created: HarnessSessionCreateResult

    private(set) var listCursors: [String?] = []
    private(set) var searchQueries: [String] = []
    private(set) var historyCalls: [(HarnessSessionID, Int?, Int?)] = []
    private(set) var modelCalls: [HarnessSessionID] = []
    private(set) var createRequests: [HarnessSessionCreateRequest] = []
    private(set) var selections: [(HarnessSessionID, HarnessWireModelSelection)] = []
    private(set) var renames: [(HarnessSessionID, String)] = []
    private(set) var forks: [(HarnessSessionID, Int?)] = []
    private(set) var archives: [HarnessSessionID] = []

    init(
        sessions: HarnessSessionList = .init(items: []),
        searchResult: HarnessSessionSearchResult = .init(items: [], hasMore: false),
        tailHistory: HarnessSessionHistoryPage = .init(events: [], hasMore: false, projections: nil),
        olderHistories: [Int: HarnessSessionHistoryPage] = [:],
        models: HarnessSessionModels = .init(
            current: .init(provider: ProviderID("ollama"), model: ModelID("qwen:27b")),
            routable: true,
            groups: [],
            failures: []
        ),
        created: HarnessSessionCreateResult = .init(sessionId: HarnessSessionID("created/session:1"), agentPreset: nil)
    ) {
        self.sessions = sessions
        self.searchResult = searchResult
        self.tailHistory = tailHistory
        self.olderHistories = olderHistories
        self.models = models
        self.created = created
    }

    func listSessions(cursor: String?) async throws -> HarnessSessionList {
        listCursors.append(cursor)
        return sessions
    }

    func searchSessions(query: String) async throws -> HarnessSessionSearchResult {
        searchQueries.append(query)
        return searchResult
    }

    func createSession(_ request: HarnessSessionCreateRequest) async throws -> HarnessSessionCreateResult {
        createRequests.append(request)
        if let createFailureAfterPersistence { throw createFailureAfterPersistence }
        if forceCreatedResponse { return created }
        return HarnessSessionCreateResult(
            sessionId: request.sessionId ?? created.sessionId,
            agentPreset: created.agentPreset
        )
    }

    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection {
        selections.append((sessionID, selection))
        if let selectionError { throw selectionError }
        return selection
    }

    func renameSession(_ sessionID: HarnessSessionID, title: String) async throws -> HarnessSessionRenameResult {
        renames.append((sessionID, title))
        return .init(title: title, seq: 42)
    }

    func forkSession(_ sessionID: HarnessSessionID, atSequence: Int?) async throws -> HarnessSessionForkResult {
        forks.append((sessionID, atSequence))
        return .init(sessionId: HarnessSessionID("forked/session:1"))
    }

    func archiveSession(_ sessionID: HarnessSessionID) async throws -> HarnessArchivedSessionsResult {
        archives.append(sessionID)
        return .init(archivedSessionIds: archiveIncludesRequestedSession ? [sessionID] : [])
    }

    func sessionHistory(
        _ sessionID: HarnessSessionID,
        beforeSequence: Int?,
        maximumMessages: Int?
    ) async throws -> HarnessSessionHistoryPage {
        historyCalls.append((sessionID, beforeSequence, maximumMessages))
        if let beforeSequence, let page = olderHistories[beforeSequence] { return page }
        return tailHistory
    }

    func sessionModels(_ sessionID: HarnessSessionID) async throws -> HarnessSessionModels {
        modelCalls.append(sessionID)
        if let modelError { throw modelError }
        return models
    }

    func setModelError(_ error: HarnessRPCClientError?) { modelError = error }
    func setSelectionError(_ error: HarnessRPCClientError?) { selectionError = error }
    func setCreateFailureAfterPersistence(_ error: HarnessRPCClientError?) { createFailureAfterPersistence = error }
    func setForceCreatedResponse(_ value: Bool) { forceCreatedResponse = value }
    func setArchiveIncludesRequestedSession(_ value: Bool) { archiveIncludesRequestedSession = value }

    func calls() -> (
        lists: [String?],
        searches: [String],
        histories: [(HarnessSessionID, Int?, Int?)],
        models: [HarnessSessionID],
        creates: [HarnessSessionCreateRequest],
        selections: [(HarnessSessionID, HarnessWireModelSelection)]
    ) {
        (listCursors, searchQueries, historyCalls, modelCalls, createRequests, selections)
    }

    func actionCalls() -> (
        renames: [(HarnessSessionID, String)],
        forks: [(HarnessSessionID, Int?)],
        archives: [HarnessSessionID]
    ) {
        (renames, forks, archives)
    }
}

private func projection(title: String) -> HarnessSessionProjectionBlock {
    .init(asOfSeq: 12, values: ["title": .string(title)])
}

private func summary(
    _ id: String,
    updatedAt: Double,
    running: Bool = false,
    blank: Bool = false,
    origin: String? = nil,
    cwd: String? = nil,
    title: String? = nil
) -> HarnessSessionSummary {
    .init(
        sessionId: HarnessSessionID(id),
        updatedAt: updatedAt,
        running: running,
        blank: blank,
        parentSessionId: nil,
        origin: origin,
        cwd: cwd,
        agentPreset: "standard",
        projections: title.map(projection)
    )
}

private func textBlock(_ text: String) -> HarnessJSONValue {
    .object(["type": .string("text"), "text": .string(text)])
}

private func userEvent(
    sequence: Int,
    text: String,
    sourceKind: String = "user",
    surface: HarnessJSONValue? = .string("append")
) -> HarnessSessionHistoryEntry {
    .init(event: .init(
        type: "user/message",
        seq: sequence,
        time: 1_800_000_000_000 + Double(sequence * 1_000),
        data: .object([
            "id": .string("user-\(sequence)"),
            "role": .string("user"),
            "content": .array([textBlock(text)]),
            "source": .object(["kind": .string(sourceKind)])
        ]),
        sourceEventSeqs: nil,
        surfaceOp: surface,
        ignorable: nil
    ), view: nil)
}

private func assistantEvent(
    sequence: Int,
    text: String,
    provider: String,
    model: String,
    interrupted: Bool = false,
    surface: HarnessJSONValue? = .string("append")
) -> HarnessSessionHistoryEntry {
    .init(event: .init(
        type: "assistant/message",
        seq: sequence,
        time: 1_800_000_000_000 + Double(sequence * 1_000),
        data: .object([
            "turn": .integer(1),
            "step": .integer(0),
            "interrupted": .bool(interrupted),
            "message": .object([
                "id": .string("assistant-\(sequence)"),
                "role": .string("assistant"),
                "content": .array([
                    .object(["type": .string("reasoning"), "text": .string("private chain of thought")]),
                    textBlock(text),
                    .object(["type": .string("tool-call"), "arguments": .string("{\"secret\":true}")])
                ]),
                "source": .object([
                    "kind": .string("model"),
                    "provider": .string(provider),
                    "model": .string(model)
                ])
            ])
        ]),
        sourceEventSeqs: nil,
        surfaceOp: surface,
        ignorable: nil
    ), view: nil)
}

private enum SessionHistoryControllerProbeError: LocalizedError, Sendable {
    case sensitiveFailure

    var errorDescription: String? {
        "sensitive provider detail sk-history-probe must never reach native UI"
    }
}

private struct SessionHistoryControllerPlan<Value: Sendable>: Sendable {
    let value: Value
    let delayNanoseconds: UInt64
    let fails: Bool

    init(_ value: Value, delayNanoseconds: UInt64 = 0, fails: Bool = false) {
        self.value = value
        self.delayNanoseconds = delayNanoseconds
        self.fails = fails
    }

    func resolve() async throws -> Value {
        if delayNanoseconds > 0 {
            try await Task.sleep(nanoseconds: delayNanoseconds)
        }
        try Task.checkCancellation()
        if fails { throw SessionHistoryControllerProbeError.sensitiveFailure }
        return value
    }
}

private actor SessionHistoryControllerSource: SessionHistoryDataProviding {
    private var browsePlans: [SessionHistoryControllerPlan<SessionHistoryBrowseSnapshot>]
    private let browseFallback: SessionHistoryBrowseSnapshot
    private var detailPlans: [HarnessSessionID: SessionHistoryControllerPlan<SessionHistoryDetailSnapshot>]
    private var olderPlans: [Int: [SessionHistoryControllerPlan<SessionTranscriptPage>]]
    private var createPlan: SessionHistoryControllerPlan<HarnessSessionID>
    private let createGate: SessionHistoryCreateGate?
    private var renamePlan = SessionHistoryControllerPlan(())
    private var forkPlan = SessionHistoryControllerPlan(HarnessSessionID("forked/controller-probe"))
    private var archivePlan = SessionHistoryControllerPlan(())

    private(set) var browseQueries: [String?] = []
    private(set) var detailCalls: [HarnessSessionID] = []
    private(set) var olderCalls: [(HarnessSessionID, Int)] = []
    private(set) var createCalls: [(HarnessSessionCreateRequest, ModelSelection)] = []
    private(set) var renameCalls: [(HarnessSessionID, String)] = []
    private(set) var forkCalls: [(HarnessSessionID, Int?)] = []
    private(set) var archiveCalls: [HarnessSessionID] = []

    init(
        browsePlans: [SessionHistoryControllerPlan<SessionHistoryBrowseSnapshot>],
        detailPlans: [HarnessSessionID: SessionHistoryControllerPlan<SessionHistoryDetailSnapshot>],
        olderPlans: [Int: [SessionHistoryControllerPlan<SessionTranscriptPage>]] = [:],
        createPlan: SessionHistoryControllerPlan<HarnessSessionID> = .init(HarnessSessionID("created/controller-probe")),
        createGate: SessionHistoryCreateGate? = nil
    ) {
        self.browsePlans = browsePlans
        self.browseFallback = browsePlans.last?.value
            ?? SessionHistoryBrowseSnapshot(rows: [], query: nil, hasMoreSearchResults: false)
        self.detailPlans = detailPlans
        self.olderPlans = olderPlans
        self.createPlan = createPlan
        self.createGate = createGate
    }

    func browse(query: String?) async throws -> SessionHistoryBrowseSnapshot {
        browseQueries.append(query)
        let plan = browsePlans.isEmpty ? SessionHistoryControllerPlan(browseFallback) : browsePlans.removeFirst()
        return try await plan.resolve()
    }

    func detail(for sessionID: HarnessSessionID) async throws -> SessionHistoryDetailSnapshot {
        detailCalls.append(sessionID)
        let fallback = SessionHistoryDetailSnapshot(
            sessionID: sessionID,
            transcript: .init(messages: [], olderBeforeSequence: nil),
            route: .unavailable
        )
        return try await (detailPlans[sessionID] ?? .init(fallback)).resolve()
    }

    func olderPage(for sessionID: HarnessSessionID, beforeSequence: Int) async throws -> SessionTranscriptPage {
        olderCalls.append((sessionID, beforeSequence))
        var plans = olderPlans[beforeSequence] ?? []
        let plan = plans.isEmpty
            ? SessionHistoryControllerPlan(SessionTranscriptPage(messages: [], olderBeforeSequence: nil), fails: true)
            : plans.removeFirst()
        olderPlans[beforeSequence] = plans
        return try await plan.resolve()
    }

    func createSession(
        _ request: HarnessSessionCreateRequest,
        selection: ModelSelection
    ) async throws -> HarnessSessionID {
        createCalls.append((request, selection))
        if let createGate {
            await createGate.wait()
            return createPlan.value
        }
        return try await createPlan.resolve()
    }

    func renameSession(_ sessionID: HarnessSessionID, title: String) async throws {
        renameCalls.append((sessionID, title))
        _ = try await renamePlan.resolve()
    }

    func forkSession(_ sessionID: HarnessSessionID, atSequence: Int?) async throws -> HarnessSessionID {
        forkCalls.append((sessionID, atSequence))
        return try await forkPlan.resolve()
    }

    func archiveSession(_ sessionID: HarnessSessionID) async throws {
        archiveCalls.append(sessionID)
        _ = try await archivePlan.resolve()
    }

    func setRenamePlan(_ plan: SessionHistoryControllerPlan<Void>) { renamePlan = plan }
    func setForkPlan(_ plan: SessionHistoryControllerPlan<HarnessSessionID>) { forkPlan = plan }
    func setArchivePlan(_ plan: SessionHistoryControllerPlan<Void>) { archivePlan = plan }

    func calls() -> (
        browse: [String?],
        detail: [HarnessSessionID],
        older: [(HarnessSessionID, Int)],
        create: [(HarnessSessionCreateRequest, ModelSelection)],
        rename: [(HarnessSessionID, String)],
        fork: [(HarnessSessionID, Int?)],
        archive: [HarnessSessionID]
    ) {
        (browseQueries, detailCalls, olderCalls, createCalls, renameCalls, forkCalls, archiveCalls)
    }
}

private actor SessionHistoryCreateGate {
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

private actor SessionHistoryBooleanProbe {
    private var stored = false
    func set() { stored = true }
    func value() -> Bool { stored }
}

@MainActor
private final class SessionHistoryInteractionProbe {
    var renameResponses: [String?] = []
    var archiveResponses: [Bool] = []
    var exportResponses: [SessionHistoryExportSelection?] = []
    var destinations: [URL?] = []
    private(set) var renamePrompts: [String] = []
    private(set) var archivePromptCount = 0
    private(set) var exportPromptCount = 0
    private(set) var artifacts: [ConversationExportArtifact] = []
    private(set) var revealed: [URL] = []

    var interactions: SessionHistoryWindowInteractions {
        SessionHistoryWindowInteractions(
            requestRename: { [self] title in
                renamePrompts.append(title)
                return renameResponses.isEmpty ? nil : renameResponses.removeFirst()
            },
            confirmArchive: { [self] in
                archivePromptCount += 1
                return archiveResponses.isEmpty ? false : archiveResponses.removeFirst()
            },
            requestExport: { [self] in
                exportPromptCount += 1
                return exportResponses.isEmpty ? nil : exportResponses.removeFirst()
            },
            chooseExportDestination: { [self] artifact in
                artifacts.append(artifact)
                return destinations.isEmpty ? nil : destinations.removeFirst()
            },
            revealExport: { [self] url in revealed.append(url) }
        )
    }
}

private func controllerRow(
    _ rawID: String,
    title: String,
    running: Bool = false
) -> SessionHistoryRow {
    SessionHistoryRow(
        id: HarnessSessionID(rawID),
        title: title,
        projectLabel: "ProbeProject",
        updatedAt: Date(timeIntervalSince1970: 1_800_000_000),
        running: running,
        searchSnippet: nil
    )
}

private func controllerMessage(_ sequence: Int, _ text: String) -> SessionTranscriptMessage {
    SessionTranscriptMessage(
        sequence: sequence,
        role: sequence.isMultiple(of: 2) ? .assistant : .user,
        text: text,
        date: Date(timeIntervalSince1970: Double(sequence)),
        interrupted: false,
        source: nil
    )
}

private func controllerDetail(
    _ row: SessionHistoryRow,
    messages: [SessionTranscriptMessage],
    olderBeforeSequence: Int? = nil
) -> SessionHistoryDetailSnapshot {
    SessionHistoryDetailSnapshot(
        sessionID: row.id,
        transcript: .init(messages: messages, olderBeforeSequence: olderBeforeSequence),
        route: .available(.init(
            route: .init(provider: ProviderID("ollama"), model: ModelID("qwen:27b")),
            providerName: "Ollama",
            modelName: "Qwen",
            reasoningEffort: nil,
            boundary: .onDevice,
            routable: true
        ))
    )
}

@MainActor
private func sessionHistoryDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(sessionHistoryDescendants(of:))
}

@MainActor
private func sessionHistoryButton(_ title: String, in root: NSView) throws -> NSButton {
    try #require(sessionHistoryDescendants(of: root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func sessionHistoryTable(in root: NSView) throws -> NSTableView {
    try #require(sessionHistoryDescendants(of: root).compactMap { $0 as? NSTableView }.first)
}

@MainActor
private func sessionHistoryStatus(in root: NSView) throws -> NSTextField {
    try #require(sessionHistoryDescendants(of: root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == "Task history status"
    })
}

@MainActor
private func sessionHistoryTranscript(in root: NSView) throws -> NSTextView {
    try #require(sessionHistoryDescendants(of: root).compactMap { $0 as? NSTextView }.first {
        $0.accessibilityLabel() == "Task conversation"
    })
}

private enum SessionHistoryTestTimeout: Error { case timedOut }

@MainActor
private func sessionHistoryEventually(
    attempts: Int = 300,
    _ condition: @escaping @MainActor () async -> Bool
) async throws {
    for _ in 0..<attempts {
        if await condition() { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    throw SessionHistoryTestTimeout.timedOut
}

@Suite(.serialized)
struct SessionHistoryTests {
    @Test func browseUsesSafeTitlesBasenamesRecencyAndServerSearchRanking() async throws {
        let first = summary(
            "session/first:1",
            updatedAt: 1_800_000_000_000,
            running: true,
            cwd: "/Users/private/TopSecretProject",
            title: "  Important\nTask\u{202E}\0  "
        )
        let second = summary(
            "session/second:2",
            updatedAt: 1_700_000_000,
            cwd: "C:\\private\\VisibleProject"
        )
        let service = FakeSessionHistoryRPC(
            sessions: .init(items: [
                second,
                summary("blank", updatedAt: 9_000_000_000_000, blank: true, cwd: "/do/not/show"),
                summary("child", updatedAt: 8_000_000_000_000, origin: "subagent", cwd: "/do/not/show"),
                first
            ]),
            searchResult: .init(items: [
                .init(sessionId: second.sessionId, snippet: "match\nwith\u{202D} control\0"),
                .init(sessionId: first.sessionId, snippet: "other match"),
                .init(sessionId: HarnessSessionID("not-authorized"), snippet: "must be dropped")
            ], hasMore: true)
        )
        let repository = SessionHistoryRepository(service: service)

        let all = try await repository.browse()
        #expect(all.rows.map(\.id) == [first.sessionId, second.sessionId])
        #expect(all.rows[0].title == "Important Task")
        #expect(all.rows[0].projectLabel == "TopSecretProject")
        #expect(all.rows[1].title == "VisibleProject")
        #expect(all.rows[1].projectLabel == "VisibleProject")
        #expect(!all.rows.map(\.title).joined().contains("/Users/private"))
        #expect(all.rows[0].updatedAt.timeIntervalSince1970 == 1_800_000_000)
        #expect(all.rows[1].updatedAt.timeIntervalSince1970 == 1_700_000_000)

        let matches = try await repository.browse(query: "  needle  ")
        #expect(matches.rows.map(\.id) == [second.sessionId, first.sessionId])
        #expect(matches.rows[0].searchSnippet == "match with control")
        #expect(matches.hasMoreSearchResults)
        #expect(matches.query == "needle")
        let calls = await service.calls()
        #expect(calls.lists.count == 2)
        #expect(calls.searches == ["needle"])
    }

    @Test func detailShowsOnlyDirectHumanAndAssistantTextWithExactRouteProvenance() async throws {
        let routeProvider = ProviderID("lab/gateway:8443")
        let routeModel = ModelID("org/qwen:27b/q5")
        let descriptor = BuiltInProviderDescriptors.openAICompatible(
            id: routeProvider,
            displayName: "Private Lab",
            baseURL: URL(string: "https://192.168.1.20:8443/v1")!,
            boundary: .localNetwork
        )
        let entries: [HarnessSessionHistoryEntry] = [
            assistantEvent(
                sequence: 5,
                text: "partial response",
                provider: routeProvider.rawValue,
                model: routeModel.rawValue,
                interrupted: true
            ),
            userEvent(sequence: 2, text: "injected system content", sourceKind: "plugin"),
            assistantEvent(
                sequence: 4,
                text: "model-only replacement",
                provider: "cloud/other",
                model: "hidden",
                surface: .object(["replace": .integer(3)])
            ),
            userEvent(sequence: 1, text: "Hello\r\nworld\0"),
            assistantEvent(
                sequence: 3,
                text: "<script>alert(1)</script> **literal markdown**",
                provider: routeProvider.rawValue,
                model: routeModel.rawValue
            ),
            .init(event: .init(
                type: "tool/result", seq: 6, time: 1_800_000_006_000,
                data: .object(["secret": .string("must not render")]), sourceEventSeqs: nil,
                surfaceOp: .string("append"), ignorable: nil
            ), view: nil),
            .init(event: .init(
                type: "turn/end", seq: 7, time: 1_800_000_007_000,
                data: .object([
                    "turn": .integer(1),
                    "reason": .object([
                        "kind": .string("error"),
                        "error": .object([
                            "code": .string("PROVIDER_PRIVATE_CODE"),
                            "message": .string("sk-raw-provider-error https://provider.invalid /Users/example/private"),
                            "requestId": .string("provider-request-secret")
                        ])
                    ])
                ]), sourceEventSeqs: nil,
                surfaceOp: .string("append"), ignorable: nil
            ), view: nil)
        ]
        let service = FakeSessionHistoryRPC(
            tailHistory: .init(events: entries, hasMore: true, projections: nil),
            models: .init(
                current: .init(provider: routeProvider, model: routeModel, reasoningEffort: "reason/deep:max"),
                routable: false,
                groups: [.init(id: routeProvider, name: "Lab Route", models: [
                    .init(id: routeModel, name: "Qwen 27B", description: nil, reasoning: nil)
                ])],
                failures: []
            )
        )
        let repository = SessionHistoryRepository(
            service: service,
            descriptors: [descriptor],
            limits: .init(pageMessages: 2, maximumPageMessages: 3, messageCharacters: 200)
        )
        let id = HarnessSessionID("session/opaque:1")

        let detail = try await repository.detail(for: id)
        #expect(detail.transcript.messages.map(\.sequence) == [1, 3, 5])
        #expect(detail.transcript.messages.map(\.role) == [.user, .assistant, .assistant])
        #expect(detail.transcript.messages[0].text == "Hello\nworld")
        #expect(detail.transcript.messages[1].text == "<script>alert(1)</script> **literal markdown**")
        #expect(!detail.transcript.messages.map(\.text).joined().contains("private chain of thought"))
        #expect(!detail.transcript.messages.map(\.text).joined().contains("secret"))
        #expect(!detail.transcript.messages.map(\.text).joined().contains("raw-provider-error"))
        #expect(!detail.transcript.messages.map(\.text).joined().contains("provider.invalid"))
        #expect(detail.transcript.messages[2].interrupted)
        #expect(detail.transcript.messages[1].source == .init(
            route: ModelRoute(provider: routeProvider, model: routeModel),
            boundary: .localNetwork
        ))
        #expect(detail.transcript.olderBeforeSequence == 1)

        guard case .available(let route) = detail.route else {
            Issue.record("Expected explicit route metadata")
            return
        }
        #expect(route.route == ModelRoute(provider: routeProvider, model: routeModel))
        #expect(route.providerName == "Lab Route")
        #expect(route.modelName == "Qwen 27B")
        #expect(route.reasoningEffort == "reason/deep:max")
        #expect(route.boundary == .localNetwork)
        #expect(!route.routable)
        let calls = await service.calls()
        #expect(calls.histories.count == 1)
        #expect(calls.histories[0].0 == id)
        #expect(calls.histories[0].1 == nil)
        #expect(calls.histories[0].2 == 2)
        #expect(calls.models == [id])
    }

    @Test func olderPagingAndCreationPreserveOpaqueValuesAndTypedRequests() async throws {
        let id = HarnessSessionID("session/team:history/one")
        let older = HarnessSessionHistoryPage(
            events: [userEvent(sequence: 7, text: "older")],
            hasMore: false,
            projections: nil
        )
        let service = FakeSessionHistoryRPC(
            olderHistories: [10: older],
            created: .init(sessionId: HarnessSessionID("session/new:opaque/path"), agentPreset: "secure")
        )
        let repository = SessionHistoryRepository(service: service)

        let page = try await repository.olderPage(for: id, beforeSequence: 10)
        #expect(page.messages.map(\.text) == ["older"])
        #expect(page.olderBeforeSequence == nil)
        let request = HarnessSessionCreateRequest(
            cwd: "/private/project",
            sessionId: HarnessSessionID("session/new:opaque/path"),
            agentPreset: "secure"
        )
        let created = try await repository.createSession(request)
        #expect(created == HarnessSessionID("session/new:opaque/path"))
        let calls = await service.calls()
        #expect(calls.histories.count == 1)
        #expect(calls.histories[0].0 == id)
        #expect(calls.histories[0].1 == 10)
        #expect(calls.histories[0].2 == 50)
        #expect(calls.creates == [request])
        #expect(calls.selections.count == 1)
        #expect(calls.selections[0].0 == created)
        #expect(calls.selections[0].1.route == ModelSelection.defaultLocal.route)
    }

    @Test func failedNativeTaskSelectionArchivesTheCreatedSessionAndFailsClosedIfUnverified() async {
        let service = FakeSessionHistoryRPC()
        await service.setSelectionError(.cancelled)
        let repository = SessionHistoryRepository(service: service)

        do {
            _ = try await repository.createSession()
            Issue.record("Selection failure unexpectedly retained a blank native task")
        } catch let error as HarnessRPCClientError {
            #expect(error == .cancelled)
        } catch {
            Issue.record("Unexpected native task selection failure: \(error)")
        }
        let failedSelectionID = (await service.calls()).creates.first?.sessionId
        #expect((await service.actionCalls()).archives == [failedSelectionID].compactMap { $0 })

        let unverified = FakeSessionHistoryRPC()
        await unverified.setSelectionError(.cancelled)
        await unverified.setArchiveIncludesRequestedSession(false)
        let unverifiedRepository = SessionHistoryRepository(service: unverified)
        do {
            _ = try await unverifiedRepository.createSession()
            Issue.record("Unverified native task cleanup unexpectedly succeeded")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected unverified native cleanup result: \(error)")
        }
        let unverifiedID = (await unverified.calls()).creates.first?.sessionId
        #expect((await unverified.actionCalls()).archives == [unverifiedID].compactMap { $0 })
    }

    @Test func ambiguousNativeTaskCreationCompensatesOnlyAppOwnedPreallocatedIDs() async throws {
        let service = FakeSessionHistoryRPC()
        await service.setCreateFailureAfterPersistence(.transport(.networkConnectionLost))
        let repository = SessionHistoryRepository(service: service)

        do {
            _ = try await repository.createSession(
                HarnessSessionCreateRequest(cwd: "/private/ambiguous-new"),
                selection: .defaultLocal
            )
            Issue.record("Ambiguous native task creation unexpectedly succeeded")
        } catch let error as HarnessRPCClientError {
            #expect(error == .transport(.networkConnectionLost))
        } catch {
            Issue.record("Unexpected ambiguous native create result: \(error)")
        }
        let newCalls = await service.calls()
        let preallocated = try #require(newCalls.creates.first?.sessionId)
        #expect((await service.actionCalls()).archives == [preallocated])

        let reusedService = FakeSessionHistoryRPC()
        await reusedService.setCreateFailureAfterPersistence(.transport(.networkConnectionLost))
        let reusedRepository = SessionHistoryRepository(service: reusedService)
        let existing = HarnessSessionID("existing/workspace-blank")
        do {
            _ = try await reusedRepository.createSession(HarnessSessionCreateRequest(
                workspaceId: "workspace-1",
                sessionId: existing,
                reuseWorkspaceBlank: true
            ))
            Issue.record("Ambiguous blank-task reuse unexpectedly succeeded")
        } catch let error as HarnessRPCClientError {
            #expect(error == .transport(.networkConnectionLost))
        } catch {
            Issue.record("Unexpected blank-task reuse result: \(error)")
        }
        #expect((await reusedService.actionCalls()).archives.isEmpty)
    }

    @Test func mismatchedNativeCreateResponseCannotTransferArbitrarySessionButReuseIsExempt() async throws {
        let arbitrary = HarnessSessionID("arbitrary/existing-task")
        let service = FakeSessionHistoryRPC(created: .init(sessionId: arbitrary, agentPreset: nil))
        await service.setForceCreatedResponse(true)
        let repository = SessionHistoryRepository(service: service)
        let requested = HarnessSessionID("owned/preallocated-task")

        do {
            _ = try await repository.createSession(HarnessSessionCreateRequest(
                cwd: "/private/mismatched-native-create",
                sessionId: requested
            ))
            Issue.record("Mismatched native create response unexpectedly transferred ownership")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseViolation(.invalidPayload))
        } catch {
            Issue.record("Unexpected mismatched native-create result: \(error)")
        }
        #expect((await service.actionCalls()).archives == [requested])
        #expect((await service.calls()).selections.isEmpty)

        let reusedService = FakeSessionHistoryRPC(created: .init(sessionId: arbitrary, agentPreset: nil))
        await reusedService.setForceCreatedResponse(true)
        let reusedRepository = SessionHistoryRepository(service: reusedService)
        let reused = try await reusedRepository.createSession(HarnessSessionCreateRequest(
            workspaceId: "workspace-1",
            sessionId: HarnessSessionID("workspace/blank"),
            reuseWorkspaceBlank: true
        ))
        #expect(reused == arbitrary)
        #expect((await reusedService.actionCalls()).archives.isEmpty)
        #expect((await reusedService.calls()).selections.map(\.0) == [arbitrary])
    }

    @Test func failedBlankReuseSelectionNeverArchivesTheUnownedReturnedSession() async {
        let arbitrary = HarnessSessionID("arbitrary/existing-task")
        let service = FakeSessionHistoryRPC(created: .init(sessionId: arbitrary, agentPreset: nil))
        await service.setForceCreatedResponse(true)
        await service.setSelectionError(.cancelled)
        let lifecycle = SessionHistoryLifecycleGate()
        let repository = SessionHistoryRepository(service: service, lifecycle: lifecycle)

        do {
            _ = try await repository.createSession(HarnessSessionCreateRequest(
                workspaceId: "workspace-1",
                sessionId: HarnessSessionID("workspace/blank"),
                reuseWorkspaceBlank: true
            ))
            Issue.record("Failed blank-task reuse unexpectedly transferred ownership")
        } catch let error as HarnessRPCClientError {
            #expect(error == .cancelled)
        } catch {
            Issue.record("Unexpected blank-task reuse selection result: \(error)")
        }

        #expect((await service.calls()).selections.map(\.0) == [arbitrary])
        #expect((await service.actionCalls()).archives.isEmpty)
        #expect(!lifecycle.cleanupFailureRecorded())
    }

    @Test func unverifiedAmbiguousCreationPoisonsHistoryAndFailsQuiescenceClosed() async {
        let service = FakeSessionHistoryRPC()
        await service.setCreateFailureAfterPersistence(.timedOut)
        await service.setArchiveIncludesRequestedSession(false)
        let lifecycle = SessionHistoryLifecycleGate()
        let repository = SessionHistoryRepository(service: service, lifecycle: lifecycle)

        do {
            _ = try await repository.createSession()
            Issue.record("Unverified ambiguous-create cleanup unexpectedly succeeded")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected ambiguous cleanup result: \(error)")
        }
        #expect(lifecycle.cleanupFailureRecorded())

        lifecycle.suspendAdmissionsForQuiescence()
        do {
            try await lifecycle.quiesceSuspendedAdmissions()
            Issue.record("Poisoned Task History unexpectedly crossed quiescence")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected poisoned quiescence error: \(error)")
        }
        do {
            _ = try await repository.browse(query: nil)
            Issue.record("Poisoned Task History admitted new RPC work")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected poisoned admission error: \(error)")
        }
    }

    @Test func nativeTaskActionsRemainTypedAndPreserveOpaqueSessionIdentity() async throws {
        let rpc = FakeSessionHistoryRPC()
        let repository = SessionHistoryRepository(service: rpc)
        let sessionID = HarnessSessionID("session/opaque:path/with/slashes")

        try await repository.renameSession(sessionID, title: "Private project")
        let forked = try await repository.forkSession(sessionID, atSequence: nil)
        try await repository.archiveSession(sessionID)

        #expect(forked == HarnessSessionID("forked/session:1"))
        let actions = await rpc.actionCalls()
        #expect(actions.renames.count == 1)
        #expect(actions.renames[0].0 == sessionID)
        #expect(actions.renames[0].1 == "Private project")
        #expect(actions.forks.count == 1)
        #expect(actions.forks[0].0 == sessionID)
        #expect(actions.forks[0].1 == nil)
        #expect(actions.archives == [sessionID])
    }

    @Test func ordinaryArchiveFailureDoesNotPoisonHistoryLifecycle() async throws {
        let service = FakeSessionHistoryRPC()
        await service.setArchiveIncludesRequestedSession(false)
        let lifecycle = SessionHistoryLifecycleGate()
        let repository = SessionHistoryRepository(service: service, lifecycle: lifecycle)
        let sessionID = HarnessSessionID("ordinary/archive-failure")

        do {
            try await repository.archiveSession(sessionID)
            Issue.record("Unacknowledged ordinary archive unexpectedly succeeded")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected ordinary archive error: \(error)")
        }
        #expect(!lifecycle.cleanupFailureRecorded())

        _ = try await repository.browse(query: nil)
        lifecycle.suspendAdmissionsForQuiescence()
        try await lifecycle.quiesceSuspendedAdmissions()
    }

    @Test func routeFailureKeepsTranscriptReadableAndUnknownProvidersFailClosedToCloud() async throws {
        let unknown = "future/provider:1"
        let service = FakeSessionHistoryRPC(
            tailHistory: .init(events: [
                assistantEvent(sequence: 1, text: "still visible", provider: unknown, model: "model/path:2")
            ], hasMore: false, projections: nil)
        )
        await service.setModelError(.remote(.init(
            code: .modelDiscoveryFailed,
            message: "secret endpoint token should never surface",
            details: [:]
        )))
        let repository = SessionHistoryRepository(service: service)

        let detail = try await repository.detail(for: HarnessSessionID("session"))
        #expect(detail.transcript.messages.map(\.text) == ["still visible"])
        #expect(detail.transcript.messages[0].source?.boundary == .cloud)
        #expect(detail.route == .unavailable)
        let presentation = SessionHistoryErrorMessage.message(for: HarnessRPCClientError.remote(.init(
            code: .internalError,
            message: "credential sk-do-not-echo",
            details: [:]
        )))
        #expect(!presentation.contains("sk-do-not-echo"))
    }

    @Test func safeTextAndTranscriptAccumulatorEnforceSpoofingAndMemoryBounds() {
        #expect(SessionHistorySafeText.inline(" A\nB\u{202E}\0\tC ", limit: 20) == "A B C")
        #expect(SessionHistorySafeText.multiline("A\r\nB\u{2066}C", limit: 20) == "A\nBC")
        #expect(SessionHistorySafeText.inline("123456", limit: 5) == "1234…")

        let expectedRoute = ModelRoute(provider: ProviderID("ollama"), model: ModelID("qwen:27b"))
        #expect(SessionTranscriptSourcePolicy.acceptedAssistantSource(
            provider: expectedRoute.provider,
            model: expectedRoute.model,
            expectedRoute: expectedRoute
        ) == expectedRoute)
        #expect(SessionTranscriptSourcePolicy.acceptedAssistantSource(
            provider: ProviderID("other"),
            model: expectedRoute.model,
            expectedRoute: expectedRoute
        ) == nil)
        #expect(SessionTranscriptSourcePolicy.acceptedAssistantSource(
            provider: expectedRoute.provider,
            model: nil,
            expectedRoute: expectedRoute
        ) == nil)

        func message(
            _ sequence: Int,
            _ text: String,
            source: SessionTranscriptSource? = nil
        ) -> SessionTranscriptMessage {
            .init(
                sequence: sequence,
                role: .assistant,
                text: text,
                date: Date(timeIntervalSince1970: Double(sequence)),
                interrupted: false,
                source: source
            )
        }
        let merged = SessionTranscriptAccumulator.merge(
            older: [message(1, "1111"), message(2, "old duplicate")],
            newer: [message(2, "2222"), message(3, "3333")],
            maximumMessages: 3,
            maximumCharacters: 8
        )
        #expect(merged.messages.map(\.sequence) == [2, 3])
        #expect(merged.messages.map(\.text) == ["2222", "3333"])
        #expect(merged.truncated)

        let source = SessionTranscriptSource(
            route: ModelRoute(provider: ProviderID("abcde"), model: ModelID("fghij")),
            boundary: .onDevice
        )
        let metadataBounded = SessionTranscriptAccumulator.merge(
            older: [message(1, "1111")],
            newer: [message(2, "x", source: source)],
            maximumMessages: 3,
            maximumCharacters: 12
        )
        #expect(metadataBounded.messages.map(\.sequence) == [2])
        #expect(metadataBounded.truncated)
    }

    @Test func invalidSearchAndPaginationArgumentsFailBeforeTransport() async throws {
        let service = FakeSessionHistoryRPC()
        let repository = SessionHistoryRepository(service: service)

        await #expect(throws: HarnessRPCClientError.invalidArgument) {
            _ = try await repository.browse(query: "bad\0query")
        }
        await #expect(throws: HarnessRPCClientError.invalidArgument) {
            _ = try await repository.browse(query: String(repeating: "😀", count: 251))
        }
        await #expect(throws: HarnessRPCClientError.invalidArgument) {
            _ = try await repository.olderPage(for: HarnessSessionID("s"), beforeSequence: -1)
        }
        let calls = await service.calls()
        #expect(calls.lists.isEmpty)
        #expect(calls.histories.isEmpty)
    }

    @Test @MainActor func controllerWiresOpenDoubleClickRefreshAndTypedNewTask() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let row = controllerRow("session/controller:open/path", title: "Open probe")
        let snapshot = SessionHistoryBrowseSnapshot(rows: [row], query: nil, hasMoreSearchResults: false)
        let detail = controllerDetail(row, messages: [controllerMessage(1, "Visible transcript")])
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot), .init(snapshot), .init(snapshot)],
            detailPlans: [row.id: .init(detail)]
        )
        let request = HarnessSessionCreateRequest(
            cwd: "/private/probe",
            sessionId: HarnessSessionID("preallocated/controller:id"),
            agentPreset: "secure"
        )
        let selection = ModelSelection(
            route: .init(provider: ProviderID("ollama"), model: ModelID("qwen:27b")),
            reasoningEffort: "high"
        )
        let controller = SessionHistoryWindowController(
            dataSource: source,
            newSessionRequest: { request },
            newSessionSelection: { selection },
            interactions: SessionHistoryInteractionProbe().interactions
        )
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try sessionHistoryTable(in: root)
        let open = try sessionHistoryButton("Open Task", in: root)
        let refresh = try sessionHistoryButton("Refresh", in: root)
        let create = try sessionHistoryButton("New Task", in: root)
        var opened: [HarnessSessionID] = []
        controller.onSessionSelected = { opened.append($0) }

        for button in [open, refresh, create,
                       try sessionHistoryButton("Rename", in: root),
                       try sessionHistoryButton("Branch", in: root),
                       try sessionHistoryButton("Archive", in: root),
                       try sessionHistoryButton("Export…", in: root),
                       try sessionHistoryButton("Load Earlier Messages", in: root)] {
            #expect(button.target != nil)
            #expect(button.action != nil)
        }
        #expect(table.target != nil)
        #expect(table.doubleAction != nil)

        controller.refresh()
        try await sessionHistoryEventually {
            table.numberOfRows == 1
                && (try? sessionHistoryTranscript(in: root).string.contains("Visible transcript")) == true
        }
        open.performClick(nil)
        #expect(opened == [row.id])
        let doubleAction = try #require(table.doubleAction)
        #expect(NSApp.sendAction(doubleAction, to: table.target, from: table))
        #expect(opened == [row.id, row.id])

        refresh.performClick(nil)
        try await sessionHistoryEventually { await source.calls().browse.count >= 2 && refresh.isEnabled }

        create.performClick(nil)
        try await sessionHistoryEventually {
            await source.calls().create.count == 1
                && opened.last == HarnessSessionID("created/controller-probe")
                && create.isEnabled
        }
        let calls = await source.calls()
        #expect(calls.create.count == 1)
        #expect(calls.create[0].0 == request)
        #expect(calls.create[0].1 == selection)
        #expect(calls.browse.count >= 3)

        let cancelledSource = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot)],
            detailPlans: [row.id: .init(detail)]
        )
        let cancelled = SessionHistoryWindowController(
            dataSource: cancelledSource,
            newSessionRequest: { nil },
            newSessionSelection: { selection },
            interactions: SessionHistoryInteractionProbe().interactions
        )
        defer { cancelled.close() }
        let cancelledRoot = try #require(cancelled.window?.contentViewController?.view)
        try sessionHistoryButton("New Task", in: cancelledRoot).performClick(nil)
        #expect(await cancelledSource.calls().create.isEmpty)
    }

    @Test @MainActor func controllerArchivesACancellationInsensitiveTaskCreatedAfterWindowClose() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let gate = SessionHistoryCreateGate()
        let createdID = HarnessSessionID("created/after-window-close")
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(.init(rows: [], query: nil, hasMoreSearchResults: false))],
            detailPlans: [:],
            createPlan: .init(createdID),
            createGate: gate
        )
        let controller = SessionHistoryWindowController(
            dataSource: source,
            newSessionRequest: { HarnessSessionCreateRequest(cwd: "/private/probe") },
            newSessionSelection: { .defaultLocal },
            interactions: SessionHistoryInteractionProbe().interactions
        )
        let root = try #require(controller.window?.contentViewController?.view)
        let create = try sessionHistoryButton("New Task", in: root)
        var opened: [HarnessSessionID] = []
        controller.onSessionSelected = { opened.append($0) }

        create.performClick(nil)
        await gate.waitUntilEntered()
        controller.close()
        await gate.open()
        try await sessionHistoryEventually {
            await source.calls().archive == [createdID]
        }

        #expect(opened.isEmpty)
        #expect((await source.calls()).create.count == 1)
        #expect((await source.calls()).archive == [createdID])
    }

    @Test @MainActor func historyQuiescenceWaitsForStaleCreateCleanupAndFailsClosedWhenUnverified() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let createGate = SessionHistoryCreateGate()
        let lifecycle = SessionHistoryLifecycleGate()
        let createdID = HarnessSessionID("created/quiescence-race")
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(.init(rows: [], query: nil, hasMoreSearchResults: false))],
            detailPlans: [:],
            createPlan: .init(createdID),
            createGate: createGate
        )
        await source.setArchivePlan(.init((), fails: true))
        let controller = SessionHistoryWindowController(
            dataSource: source,
            newSessionRequest: { HarnessSessionCreateRequest(cwd: "/private/quiescence-race") },
            newSessionSelection: { .defaultLocal },
            interactions: SessionHistoryInteractionProbe().interactions,
            lifecycle: lifecycle
        )
        let root = try #require(controller.window?.contentViewController?.view)
        let create = try sessionHistoryButton("New Task", in: root)
        create.performClick(nil)
        await createGate.waitUntilEntered()
        controller.close()

        lifecycle.suspendAdmissionsForQuiescence()
        let settled = SessionHistoryBooleanProbe()
        let barrier = Task { () -> HarnessConversationError? in
            do {
                try await lifecycle.quiesceSuspendedAdmissions()
                await settled.set()
                return nil
            } catch let error as HarnessConversationError {
                await settled.set()
                return error
            } catch {
                await settled.set()
                return .cancellationUnverified
            }
        }
        try await Task.sleep(for: .milliseconds(50))
        #expect(!(await settled.value()))

        await createGate.open()
        #expect(await barrier.value == .sessionCleanupUnverified)
        #expect((await source.calls()).archive == [createdID])
        #expect(lifecycle.cleanupFailureRecorded())
    }

    @Test @MainActor func controllerRenameBranchArchiveCancellationsAndSuccessUseSelectedOpaqueID() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let row = controllerRow("session/actions:opaque/path", title: "Original title")
        let snapshot = SessionHistoryBrowseSnapshot(rows: [row], query: nil, hasMoreSearchResults: false)
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot)],
            detailPlans: [row.id: .init(controllerDetail(row, messages: [controllerMessage(1, "Message")]))]
        )
        let probe = SessionHistoryInteractionProbe()
        probe.renameResponses = [nil, "  Renamed\nprivately\u{202E}\0  "]
        probe.archiveResponses = [false, true]
        let controller = SessionHistoryWindowController(dataSource: source, interactions: probe.interactions)
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let rename = try sessionHistoryButton("Rename", in: root)
        let branch = try sessionHistoryButton("Branch", in: root)
        let archive = try sessionHistoryButton("Archive", in: root)
        var opened: [HarnessSessionID] = []
        controller.onSessionSelected = { opened.append($0) }

        controller.refresh()
        try await sessionHistoryEventually { rename.isEnabled && branch.isEnabled && archive.isEnabled }

        rename.performClick(nil)
        #expect(probe.renamePrompts == ["Original title"])
        #expect(await source.calls().rename.isEmpty)
        rename.performClick(nil)
        try await sessionHistoryEventually { await source.calls().rename.count == 1 && rename.isEnabled }
        var calls = await source.calls()
        #expect(calls.rename[0].0 == row.id)
        #expect(calls.rename[0].1 == "Renamed privately")

        branch.performClick(nil)
        try await sessionHistoryEventually { await source.calls().fork.count == 1 && branch.isEnabled }
        calls = await source.calls()
        #expect(calls.fork[0].0 == row.id)
        #expect(calls.fork[0].1 == nil)
        #expect(opened.last == HarnessSessionID("forked/controller-probe"))

        archive.performClick(nil)
        #expect(probe.archivePromptCount == 1)
        #expect(await source.calls().archive.isEmpty)
        archive.performClick(nil)
        try await sessionHistoryEventually { await source.calls().archive.count == 1 }
        #expect(await source.calls().archive == [row.id])
    }

    @Test @MainActor func controllerActionFailureUsesSafeCopyAndRestoresRunningTaskControls() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let row = controllerRow("session/running", title: "Running", running: true)
        let snapshot = SessionHistoryBrowseSnapshot(rows: [row], query: nil, hasMoreSearchResults: false)
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot)],
            detailPlans: [row.id: .init(controllerDetail(row, messages: [controllerMessage(1, "Message")]))]
        )
        await source.setRenamePlan(.init((), fails: true))
        let probe = SessionHistoryInteractionProbe()
        probe.renameResponses = ["Still private"]
        let controller = SessionHistoryWindowController(dataSource: source, interactions: probe.interactions)
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let rename = try sessionHistoryButton("Rename", in: root)
        let branch = try sessionHistoryButton("Branch", in: root)
        let archive = try sessionHistoryButton("Archive", in: root)
        let status = try sessionHistoryStatus(in: root)

        controller.refresh()
        try await sessionHistoryEventually { rename.isEnabled }
        #expect(!branch.isEnabled)
        #expect(!archive.isEnabled)
        let branchAction = try #require(branch.action)
        let archiveAction = try #require(archive.action)
        #expect(NSApp.sendAction(branchAction, to: branch.target, from: branch))
        #expect(NSApp.sendAction(archiveAction, to: archive.target, from: archive))
        #expect(await source.calls().fork.isEmpty)
        #expect(await source.calls().archive.isEmpty)
        #expect(probe.archivePromptCount == 0)
        rename.performClick(nil)
        try await sessionHistoryEventually {
            rename.isEnabled && status.stringValue == "Task history could not be loaded."
        }
        #expect(!branch.isEnabled)
        #expect(!archive.isEnabled)
        #expect(!status.stringValue.contains("sk-history-probe"))
    }

    @Test @MainActor func controllerBrowseDetailAndCreateFailuresRestoreControlsWithoutLeakingErrors() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let row = controllerRow("session/failure", title: "Failure probe")
        let snapshot = SessionHistoryBrowseSnapshot(rows: [row], query: nil, hasMoreSearchResults: false)
        let failedDetail = SessionHistoryControllerPlan(
            controllerDetail(row, messages: [controllerMessage(1, "must not render")]),
            fails: true
        )
        let source = SessionHistoryControllerSource(
            browsePlans: [
                .init(snapshot, fails: true),
                .init(snapshot)
            ],
            detailPlans: [row.id: failedDetail],
            createPlan: .init(HarnessSessionID("created/never"), fails: true)
        )
        let controller = SessionHistoryWindowController(
            dataSource: source,
            interactions: SessionHistoryInteractionProbe().interactions
        )
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try sessionHistoryTable(in: root)
        let refresh = try sessionHistoryButton("Refresh", in: root)
        let create = try sessionHistoryButton("New Task", in: root)
        let export = try sessionHistoryButton("Export…", in: root)
        let status = try sessionHistoryStatus(in: root)
        let transcript = try sessionHistoryTranscript(in: root)

        controller.refresh()
        try await sessionHistoryEventually {
            refresh.isEnabled && status.stringValue == "Task history could not be loaded."
        }
        #expect(table.numberOfRows == 0)
        #expect(!status.stringValue.contains("sk-history-probe"))

        refresh.performClick(nil)
        try await sessionHistoryEventually {
            table.numberOfRows == 1 && transcript.string.contains("Task history could not be loaded.")
        }
        #expect(!export.isEnabled)
        #expect(!transcript.string.contains("sk-history-probe"))

        create.performClick(nil)
        try await sessionHistoryEventually {
            create.isEnabled && status.stringValue == "Task history could not be loaded."
        }
        #expect(!status.stringValue.contains("sk-history-probe"))
    }

    @Test @MainActor func controllerLoadsEarlierPagesAndRestoresRetryStateAfterSafeFailure() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let row = controllerRow("session/paging", title: "Paging")
        let snapshot = SessionHistoryBrowseSnapshot(rows: [row], query: nil, hasMoreSearchResults: false)
        let detail = controllerDetail(
            row,
            messages: [controllerMessage(20, "newest")],
            olderBeforeSequence: 20
        )
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot)],
            detailPlans: [row.id: .init(detail)],
            olderPlans: [
                20: [.init(.init(messages: [controllerMessage(10, "older")], olderBeforeSequence: 10))],
                10: [.init(.init(messages: [], olderBeforeSequence: nil), fails: true)]
            ]
        )
        let controller = SessionHistoryWindowController(
            dataSource: source,
            interactions: SessionHistoryInteractionProbe().interactions
        )
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let older = try sessionHistoryButton("Load Earlier Messages", in: root)
        let transcript = try sessionHistoryTranscript(in: root)
        let status = try sessionHistoryStatus(in: root)

        controller.refresh()
        try await sessionHistoryEventually { older.isEnabled && transcript.string.contains("newest") }
        older.performClick(nil)
        try await sessionHistoryEventually {
            transcript.string.contains("older") && older.isEnabled && older.title == "Load Earlier Messages"
        }
        let olderRange = try #require(transcript.string.range(of: "older"))
        let newestRange = try #require(transcript.string.range(of: "newest"))
        #expect(olderRange.lowerBound < newestRange.lowerBound)
        older.performClick(nil)
        try await sessionHistoryEventually {
            older.isEnabled && older.title == "Try Loading Earlier Messages Again"
        }
        #expect(status.stringValue == "Task history could not be loaded.")
        #expect(!status.stringValue.contains("sk-history-probe"))
        let calls = await source.calls()
        #expect(calls.older.count == 2)
        #expect(calls.older[0].1 == 20)
        #expect(calls.older[1].1 == 10)
    }

    @Test @MainActor func controllerExportCancellationPagingWriteAndRevealAreBoundedAndSafe() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let row = controllerRow("session/private:export/id", title: "Private export")
        let secret = "sk-abcdefghijklmnop"
        let snapshot = SessionHistoryBrowseSnapshot(rows: [row], query: nil, hasMoreSearchResults: false)
        let detail = controllerDetail(
            row,
            messages: [controllerMessage(20, "newer \(secret)")],
            olderBeforeSequence: 20
        )
        let olderSuccess = SessionHistoryControllerPlan(SessionTranscriptPage(
            messages: [controllerMessage(10, "older message")],
            olderBeforeSequence: nil
        ))
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot)],
            detailPlans: [row.id: .init(detail)],
            olderPlans: [20: [
                olderSuccess,
                olderSuccess,
                olderSuccess,
                .init(.init(messages: [], olderBeforeSequence: nil), fails: true)
            ]]
        )
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FulmarHistoryExportTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("conversation.json")
        let invalidDestination = directory.appendingPathComponent("wrong-extension.txt")
        let probe = SessionHistoryInteractionProbe()
        probe.exportResponses = [
            nil,
            .init(format: .json, redaction: .recommended),
            .init(format: .json, redaction: .recommended),
            .init(format: .json, redaction: .recommended),
            .init(format: .json, redaction: .recommended)
        ]
        probe.destinations = [destination, nil, invalidDestination]
        let controller = SessionHistoryWindowController(dataSource: source, interactions: probe.interactions)
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let export = try sessionHistoryButton("Export…", in: root)
        let status = try sessionHistoryStatus(in: root)

        controller.refresh()
        try await sessionHistoryEventually { export.isEnabled }

        export.performClick(nil)
        #expect(probe.exportPromptCount == 1)
        #expect(probe.artifacts.isEmpty)
        #expect(export.isEnabled)

        export.performClick(nil)
        try await sessionHistoryEventually {
            FileManager.default.fileExists(atPath: destination.path)
                && probe.revealed == [destination]
                && export.isEnabled
        }
        let written = try String(contentsOf: destination, encoding: .utf8)
        #expect(written.contains("older message"))
        #expect(!written.contains(secret))
        #expect(!written.contains(row.id.rawValue))
        #expect(status.stringValue == "Exported 2 messages")
        #expect(probe.artifacts[0].redaction == .recommended)

        export.performClick(nil)
        try await sessionHistoryEventually { probe.artifacts.count == 2 && status.stringValue == "Export cancelled" }
        #expect(export.isEnabled)
        #expect(probe.revealed == [destination])

        export.performClick(nil)
        try await sessionHistoryEventually {
            probe.artifacts.count == 3
                && status.stringValue == "Choose a safe local file destination with the correct extension."
        }
        #expect(export.isEnabled)
        #expect(!status.stringValue.contains("sk-history-probe"))

        export.performClick(nil)
        try await sessionHistoryEventually {
            status.stringValue == "The conversation could not be prepared for export." && export.isEnabled
        }
        #expect(probe.artifacts.count == 3)
        #expect(!status.stringValue.contains("sk-history-probe"))
        #expect(await source.calls().older.count == 4)
    }

    @Test @MainActor func controllerCancelsAndRejectsExportPreparedForAPreviouslySelectedTask() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let first = controllerRow("session/export:first", title: "First")
        let second = controllerRow("session/export:second", title: "Second")
        let snapshot = SessionHistoryBrowseSnapshot(
            rows: [first, second],
            query: nil,
            hasMoreSearchResults: false
        )
        let source = SessionHistoryControllerSource(
            browsePlans: [.init(snapshot)],
            detailPlans: [
                first.id: .init(controllerDetail(
                    first,
                    messages: [controllerMessage(20, "first task")],
                    olderBeforeSequence: 20
                )),
                second.id: .init(controllerDetail(
                    second,
                    messages: [controllerMessage(30, "second task")]
                ))
            ],
            olderPlans: [20: [.init(
                .init(messages: [controllerMessage(10, "late first page")], olderBeforeSequence: nil),
                delayNanoseconds: 300_000_000
            )]]
        )
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FulmarStaleExportTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("must-not-exist.json")
        let probe = SessionHistoryInteractionProbe()
        probe.exportResponses = [.init(format: .json, redaction: .recommended)]
        probe.destinations = [destination]
        let controller = SessionHistoryWindowController(dataSource: source, interactions: probe.interactions)
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try sessionHistoryTable(in: root)
        let transcript = try sessionHistoryTranscript(in: root)
        let export = try sessionHistoryButton("Export…", in: root)
        let status = try sessionHistoryStatus(in: root)

        controller.refresh()
        try await sessionHistoryEventually { export.isEnabled && transcript.string.contains("first task") }
        export.performClick(nil)
        try await sessionHistoryEventually { await source.calls().older.count == 1 && !export.isEnabled }

        table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
        try await sessionHistoryEventually {
            transcript.string.contains("second task")
                && export.isEnabled
                && status.stringValue == "Export cancelled after switching tasks"
        }
        try await Task.sleep(nanoseconds: 350_000_000)
        #expect(probe.exportPromptCount == 1)
        #expect(probe.artifacts.isEmpty)
        #expect(probe.revealed.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: destination.path))
        #expect(transcript.string.contains("second task"))
        #expect(!transcript.string.contains("late first page"))
    }

    @Test @MainActor func controllerRejectsStaleBrowseAndDetailResultsAndRestoresCancelledWork() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let stale = controllerRow("session/stale", title: "Stale")
        let current = controllerRow("session/current", title: "Current")
        let staleSnapshot = SessionHistoryBrowseSnapshot(rows: [stale], query: nil, hasMoreSearchResults: false)
        let currentSnapshot = SessionHistoryBrowseSnapshot(rows: [stale, current], query: nil, hasMoreSearchResults: false)
        let source = SessionHistoryControllerSource(
            browsePlans: [
                .init(staleSnapshot, delayNanoseconds: 300_000_000),
                .init(currentSnapshot)
            ],
            detailPlans: [
                stale.id: .init(
                    controllerDetail(stale, messages: [controllerMessage(1, "stale detail")]),
                    delayNanoseconds: 300_000_000
                ),
                current.id: .init(controllerDetail(current, messages: [controllerMessage(2, "current detail")]))
            ],
            createPlan: .init(HarnessSessionID("created/too-late"), delayNanoseconds: 1_000_000_000)
        )
        let controller = SessionHistoryWindowController(
            dataSource: source,
            interactions: SessionHistoryInteractionProbe().interactions
        )
        defer { controller.close() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try sessionHistoryTable(in: root)
        let transcript = try sessionHistoryTranscript(in: root)
        let create = try sessionHistoryButton("New Task", in: root)
        var opened: [HarnessSessionID] = []
        controller.onSessionSelected = { opened.append($0) }

        controller.refresh()
        controller.refresh()
        try await sessionHistoryEventually { table.numberOfRows == 2 }
        table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
        try await sessionHistoryEventually { transcript.string.contains("current detail") }
        try await Task.sleep(nanoseconds: 350_000_000)
        #expect(transcript.string.contains("current detail"))
        #expect(!transcript.string.contains("stale detail"))

        create.performClick(nil)
        try await sessionHistoryEventually { await source.calls().create.count == 1 && !create.isEnabled }
        controller.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: controller.window))
        #expect(create.isEnabled)
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(opened.isEmpty)
    }

    @Test @MainActor func nativeWindowBuildsWithoutStartingNetworkWork() {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let service = FakeSessionHistoryRPC()
        let controller = SessionHistoryWindowController(dataSource: SessionHistoryRepository(service: service))
        #expect(controller.window?.title == "Task History")
        #expect(controller.window?.subtitle == "Private Harness conversations")
        #expect(controller.window?.minSize.width == 820)
        controller.close()
    }
}
