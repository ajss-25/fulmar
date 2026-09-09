import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct QuickChatHostileError: LocalizedError {
    var errorDescription: String? {
        "QUICK_CHAT_SECRET_CANARY sk-private /Users/private/provider \(String(repeating: "X", count: 32_000))"
    }
}

@MainActor
private final class QuickChatOperationProbe {
    struct ApprovalCall {
        let request: HarnessApprovalRequest
        let decision: HarnessApprovalDecision
        let completion: QuickChatOperations.Completion
    }

    struct QuestionCall {
        let request: HarnessQuestionRequest
        let answer: HarnessQuestionAnswer
        let completion: QuickChatOperations.Completion
    }

    struct CancellationCall {
        let request: HarnessQuestionRequest
        let completion: QuickChatOperations.Completion
    }

    var catalog: HarnessModelCatalogSnapshot
    var catalogError: (any Error)?
    var approvalCalls: [ApprovalCall] = []
    var questionCalls: [QuestionCall] = []
    var cancellationCalls: [CancellationCall] = []
    var writtenExports: [(ConversationExportArtifact, URL)] = []
    var revealedExports: [URL] = []
    var exportError: (any Error)?
    var dictating = false
    var dictationText: ((String) -> Void)?
    var dictationCompletion: QuickChatOperations.Completion?
    var dictationStarts = 0
    var dictationStops = 0
    var spoken: [String] = []

    init(catalog: HarnessModelCatalogSnapshot) { self.catalog = catalog }

    var operations: QuickChatOperations {
        QuickChatOperations(
            loadCatalog: { [unowned self] in
                if let catalogError { throw catalogError }
                return catalog
            },
            respondApproval: { [unowned self] request, decision, completion in
                approvalCalls.append(.init(request: request, decision: decision, completion: completion))
            },
            respondQuestion: { [unowned self] request, answer, completion in
                questionCalls.append(.init(request: request, answer: answer, completion: completion))
            },
            cancelQuestion: { [unowned self] request, completion in
                cancellationCalls.append(.init(request: request, completion: completion))
            },
            writeExport: { [unowned self] artifact, destination in
                if let exportError { throw exportError }
                writtenExports.append((artifact, destination))
                return destination
            },
            revealExport: { [unowned self] in revealedExports.append($0) },
            isDictating: { [unowned self] in dictating },
            startDictation: { [unowned self] text, completion in
                dictationStarts += 1
                dictating = true
                dictationText = text
                dictationCompletion = completion
            },
            stopDictation: { [unowned self] in
                dictationStops += 1
                dictating = false
            },
            speak: { [unowned self] in spoken.append($0) }
        )
    }
}

@MainActor
private final class QuickChatInteractionProbe {
    var externalChoices: [Bool] = []
    var knowledgeChoices: [QuickChatKnowledgeDisclosureChoice] = []
    var approvalChoices: [QuickChatApprovalChoice] = []
    var approvalRetryChoices: [QuickChatRetryChoice] = []
    var questionChoices: [QuickChatQuestionChoice] = []
    var questionRetryChoices: [QuickChatRetryChoice] = []
    var imageChoices: [[URL]?] = []
    var exportChoices: [QuickChatExportSelection?] = []
    var exportDestinations: [URL?] = []

    var externalPresentations: [QuickChatExternalBoundaryPresentation] = []
    var knowledgePresentations: [QuickChatKnowledgeDisclosurePresentation] = []
    var approvalPresentations: [QuickChatApprovalPresentation] = []
    var questionPresentations: [QuickChatQuestionPresentation] = []
    var exportArtifacts: [ConversationExportArtifact] = []
    var imageChooserCount = 0
    var onExternal: (() -> Void)?
    var onKnowledge: (() -> Void)?
    var onApproval: (() -> Void)?
    var onQuestion: (() -> Void)?
    var onImages: (() -> Void)?
    var onExport: (() -> Void)?

    var interactions: QuickChatInteractions {
        QuickChatInteractions(
            confirmExternalBoundary: { [unowned self] presentation in
                externalPresentations.append(presentation)
                onExternal?()
                return externalChoices.isEmpty ? false : externalChoices.removeFirst()
            },
            chooseKnowledgeDisclosure: { [unowned self] presentation in
                knowledgePresentations.append(presentation)
                onKnowledge?()
                return knowledgeChoices.isEmpty ? .cancel : knowledgeChoices.removeFirst()
            },
            chooseApproval: { [unowned self] presentation in
                approvalPresentations.append(presentation)
                onApproval?()
                return approvalChoices.isEmpty ? .leavePending : approvalChoices.removeFirst()
            },
            chooseApprovalRetry: { [unowned self] in
                approvalRetryChoices.isEmpty ? .leavePending : approvalRetryChoices.removeFirst()
            },
            answerQuestions: { [unowned self] presentation in
                questionPresentations.append(presentation)
                onQuestion?()
                return questionChoices.isEmpty ? .leavePending : questionChoices.removeFirst()
            },
            chooseQuestionRetry: { [unowned self] _ in
                questionRetryChoices.isEmpty ? .leavePending : questionRetryChoices.removeFirst()
            },
            chooseImages: { [unowned self] in
                imageChooserCount += 1
                onImages?()
                return imageChoices.isEmpty ? nil : imageChoices.removeFirst()
            },
            chooseExport: { [unowned self] in
                onExport?()
                return exportChoices.isEmpty ? nil : exportChoices.removeFirst()
            },
            chooseExportDestination: { [unowned self] artifact in
                exportArtifacts.append(artifact)
                return exportDestinations.isEmpty ? nil : exportDestinations.removeFirst()
            }
        )
    }
}

private final class QuickChatContinuationRPCFake: HarnessConversationRPCServicing, @unchecked Sendable {
    private let lock = NSLock()
    private let promptRPCID = "quick-chat-prompt-rpc"
    private var selected: HarnessWireModelSelection?
    private var promptedContent: [HarnessPromptContentPart]?
    private var cancellations = 0

    func createSession(_ request: HarnessSessionCreateRequest) async throws -> HarnessSessionCreateResult {
        HarnessSessionCreateResult(
            sessionId: request.sessionId ?? HarnessSessionID("quick-chat-continuation-session"),
            agentPreset: request.agentPreset
        )
    }

    func selectModel(
        sessionID: HarnessSessionID,
        selection: HarnessWireModelSelection
    ) async throws -> HarnessWireModelSelection {
        withStateLock { selected = selection }
        return selection
    }

    func archiveSession(_ sessionID: HarnessSessionID) async throws -> HarnessArchivedSessionsResult {
        HarnessArchivedSessionsResult(archivedSessionIds: [sessionID])
    }

    func prompt(
        sessionID: HarnessSessionID,
        mode: HarnessPromptMode,
        content: [HarnessPromptContentPart],
        clientTimeZone: String?
    ) async throws -> HarnessPromptSubmission {
        withStateLock { promptedContent = content }
        return HarnessPromptSubmission(
            rpcID: promptRPCID,
            result: HarnessPromptResult(accepted: true, command: nil)
        )
    }

    func cancel(sessionID: HarnessSessionID) async throws -> HarnessCancelResult {
        withStateLock { cancellations += 1 }
        return HarnessCancelResult(accepted: true)
    }

    func respondToApproval(
        rpcID: String,
        sessionID: HarnessSessionID,
        approvalID: String,
        decision: HarnessApprovalDecision
    ) async throws -> HarnessRPCReceipt {
        try acceptedReceipt()
    }

    func respondToQuestion(
        rpcID: String,
        sessionID: HarnessSessionID,
        answer: HarnessQuestionAnswer
    ) async throws -> HarnessRPCReceipt {
        try acceptedReceipt()
    }

    func cancelQuestion(rpcID: String) async throws -> HarnessRPCReceipt {
        try acceptedReceipt()
    }

    func muxEvents(since: [HarnessSessionID: Int]) throws -> HarnessMuxSubscription {
        let sessionID = try #require(since.keys.first)
        lock.lock()
        let selection = selected
        lock.unlock()
        let events: [HarnessMuxEvent] = [
            .turnStarted(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 1, time: 1, turn: 1
            )),
            .userMessage(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: promptRPCID,
                isDirectUserMessage: true
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, blockIndex: 0, text: "segment-one"
            )),
            .assistantFinalMessage(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 4, time: 4,
                turn: 1, step: 1, messageID: "assistant-one", textBlocks: ["segment-one"],
                provider: selection?.provider, model: selection?.model, interrupted: false
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 5, time: 5,
                turn: 1, reason: .maxTokens
            )),
            .turnStarted(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 6, time: 6, turn: 2
            )),
            .userMessage(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 7, time: 7,
                messageID: "continued", sourceRPCID: nil,
                automaticContinuation: .init(
                    round: 1,
                    maximum: HarnessAutomaticContinuationNotice.packagedMaximumRounds,
                    isTerminalBudgetNotice: false
                )
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 8, time: 8,
                turn: 2, step: 1, blockIndex: 0, text: "segment-two"
            )),
            .assistantFinalMessage(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 9, time: 9,
                turn: 2, step: 1, messageID: "assistant-two", textBlocks: ["segment-two"],
                provider: selection?.provider, model: selection?.model, interrupted: false
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: sessionID, sequence: 10, time: 10,
                turn: 2, reason: .completed
            ))
        ]
        let stream = AsyncThrowingStream<HarnessMuxEvent, Error> { continuation in
            events.forEach { continuation.yield($0) }
            continuation.finish()
        }
        return HarnessMuxSubscription(
            events: stream,
            waitUntilOpen: {},
            cancellation: {}
        )
    }

    func promptSnapshot() -> [HarnessPromptContentPart]? {
        lock.lock()
        defer { lock.unlock() }
        return promptedContent
    }

    func cancellationCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return cancellations
    }

    /// `NSLock.lock()` is unavailable directly from Swift 6 asynchronous
    /// contexts. Keep the critical section wholly synchronous so the fake
    /// remains race-safe without ever holding a lock across suspension.
    private func withStateLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try operation()
    }

    private func acceptedReceipt() throws -> HarnessRPCReceipt {
        try JSONDecoder().decode(
            HarnessRPCReceipt.self,
            from: Data(#"{"accepted":true}"#.utf8)
        )
    }
}

@MainActor
private final class QuickChatFixture {
    let suiteName: String
    let defaults: UserDefaults
    let root: URL
    let descriptor: ProviderDescriptor
    let route: ModelRoute
    let operationProbe: QuickChatOperationProbe
    let interactionProbe: QuickChatInteractionProbe
    let controller: QuickChatViewController

    init(
        descriptor: ProviderDescriptor = BuiltInProviderDescriptors.ollama,
        modelID: ModelID = BuiltInProviderDescriptors.qwenLocalModel.id,
        modelName: String = "Qwen Local",
        modalities: [ModelInputModality] = [.text, .image],
        withKnowledge: Bool = false,
        conversationRPC: (any HarnessConversationRPCServicing)? = nil
    ) throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        suiteName = "FulmarQuickChatBehavior.\(UUID().uuidString)"
        defaults = try #require(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FulmarQuickChatBehavior-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        self.descriptor = descriptor
        route = ModelRoute(provider: descriptor.id, model: modelID)
        let catalog = HarnessModelCatalogSnapshot(providers: [
            ProviderView(
                descriptor: descriptor,
                configurationState: .ready,
                models: [ModelView(
                    id: modelID,
                    displayName: modelName,
                    capabilities: ModelCapabilities(
                        inputModalities: modalities,
                        toolUse: .supported,
                        reasoning: .supported,
                        reasoningEfforts: [ReasoningEffortView(id: "off", displayName: "Off")]
                    )
                )],
                failureMessage: nil
            )
        ])
        operationProbe = QuickChatOperationProbe(catalog: catalog)
        interactionProbe = QuickChatInteractionProbe()
        let rpc = HarnessRPCClient()
        let coordinator = ModelSelectionCoordinator(service: rpc)
        let settings = ModelProviderSettingsStore(defaults: defaults)
        try settings.save(ModelProviderSettings(defaultSelection: ModelSelection(route: route)))
        let consent = ProviderConsentStore(defaults: defaults)
        if descriptor.boundary.requiresExplicitConsent { try consent.activate(descriptor) }
        let preferences = PreferencesStore(defaults: defaults)
        let transaction = ProviderSelectionTransaction(
            coordinator: coordinator,
            settingsStore: settings,
            consentStore: consent,
            preferences: preferences
        )
        let knowledge = withKnowledge
            ? try LocalKnowledgeStore(applicationSupportDirectory: root.appendingPathComponent("Knowledge"))
            : nil
        let conversationRPCService: any HarnessConversationRPCServicing
        if let conversationRPC {
            conversationRPCService = conversationRPC
        } else {
            conversationRPCService = rpc
        }
        controller = QuickChatViewController(
            conversationService: HarnessConversationService(rpc: conversationRPCService),
            modelCoordinator: coordinator,
            settingsStore: settings,
            selectionTransaction: transaction,
            preferences: preferences,
            telemetry: GenerationTelemetryAccumulator(),
            knowledgeStore: knowledge,
            workspace: root,
            operations: operationProbe.operations,
            interactions: interactionProbe.interactions
        )
        _ = controller.view
    }

    func cleanup() {
        controller.viewWillDisappear()
        defaults.removePersistentDomain(forName: suiteName)
        try? FileManager.default.removeItem(at: root)
    }

    func loadModel() async {
        controller.refreshModels()
        await quickChatWait("model catalogue") {
            (try? quickChatModelPicker(self.controller).numberOfItems) == 1
        }
    }

    func openConversation(boundary: DataBoundary? = nil) async -> QuickChatOpenSessionResult {
        let source = SessionTranscriptSource(route: route, boundary: boundary ?? descriptor.boundary)
        return await controller.openSession(SessionHistoryDetailSnapshot(
            sessionID: HarnessSessionID("session-1"),
            transcript: SessionTranscriptPage(messages: [
                SessionTranscriptMessage(
                    sequence: 1,
                    role: .user,
                    text: "Hello",
                    date: Date(timeIntervalSince1970: 1_700_000_000),
                    interrupted: false,
                    source: source
                ),
                SessionTranscriptMessage(
                    sequence: 2,
                    role: .assistant,
                    text: "Hi",
                    date: Date(timeIntervalSince1970: 1_700_000_001),
                    interrupted: false,
                    source: source
                )
            ], olderBeforeSequence: nil),
            route: .available(SessionRouteMetadata(
                route: route,
                providerName: descriptor.displayName,
                modelName: "Saved Model",
                reasoningEffort: "off",
                boundary: boundary ?? descriptor.boundary,
                routable: true
            ))
        ))
    }
}

@MainActor
private func quickChatDescendants(_ root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(quickChatDescendants)
}

@MainActor
private func quickChatButton(_ label: String, _ controller: QuickChatViewController) throws -> NSButton {
    try #require(quickChatDescendants(controller.view).compactMap { $0 as? NSButton }.first {
        $0.accessibilityLabel() == label || $0.title == label
    })
}

@MainActor
private func quickChatText(_ label: String, _ controller: QuickChatViewController) throws -> NSTextField {
    try #require(quickChatDescendants(controller.view).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == label
    })
}

@MainActor
private func quickChatTextView(_ label: String, _ controller: QuickChatViewController) throws -> NSTextView {
    try #require(quickChatDescendants(controller.view).compactMap { $0 as? NSTextView }.first {
        $0.accessibilityLabel() == label
    })
}

@MainActor
private func quickChatModelPicker(_ controller: QuickChatViewController) throws -> NSPopUpButton {
    try #require(quickChatDescendants(controller.view).compactMap { $0 as? NSPopUpButton }.first {
        $0.accessibilityLabel() == "Provider and model"
    })
}

@MainActor
private func quickChatStatus(_ controller: QuickChatViewController) throws -> String {
    try quickChatText("Chat status", controller).stringValue
}

@MainActor
private func quickChatForceSelector(_ button: NSButton) throws {
    let action = try #require(button.action)
    #expect(NSApp.sendAction(action, to: button.target, from: button))
}

@MainActor
private func quickChatWait(
    _ description: String,
    until condition: @escaping @MainActor () -> Bool
) async {
    // Streaming renders coalesce on a 33 ms main-queue timer. A yield count
    // can expire before that timer is eligible, so wait in elapsed time and
    // suspend between checks instead of depending on executor throughput.
    let deadline = ContinuousClock.now + .seconds(2)
    while ContinuousClock.now < deadline {
        if condition() { return }
        do {
            try await Task.sleep(for: .milliseconds(10))
        } catch {
            Issue.record("Cancelled waiting for \(description)")
            return
        }
    }
    if condition() { return }
    Issue.record("Timed out waiting for \(description)")
}

private func quickChatApproval(
    id: String = "approval-1",
    tool: String = "Bash",
    reason: String? = "Run one reviewed command",
    callID: String? = nil
) -> HarnessApprovalRequest {
    HarnessApprovalRequest(
        rpcID: "approval-rpc-\(id)",
        sessionID: HarnessSessionID("session-1"),
        approvalID: id,
        toolName: tool,
        callID: callID,
        reason: reason
    )
}

private func quickChatQuestion(
    rpcID: String = "question-rpc-1",
    options: [HarnessQuestionOption]? = [
        HarnessQuestionOption(label: "Yes", description: "Continue"),
        HarnessQuestionOption(label: "No", description: "Stop")
    ]
) -> HarnessQuestionRequest {
    HarnessQuestionRequest(
        rpcID: rpcID,
        sessionID: HarnessSessionID("session-1"),
        questions: [HarnessQuestion(
            id: "question-1",
            question: "Continue?",
            detail: "Choose one option",
            header: nil,
            options: options,
            multiSelect: false,
            intent: nil
        )]
    )
}

private func quickChatAnswer(_ value: String = "Yes") -> HarnessQuestionAnswer {
    HarnessQuestionAnswer(answers: [HarnessQuestionAnswerItem(id: "question-1", selected: [value])])
}

private func quickChatCloudDescriptor(name: String = "Cloud Provider") -> ProviderDescriptor {
    ProviderDescriptor(
        id: ProviderID("quick-chat-cloud"),
        displayName: name,
        settingsNamespace: "llm",
        settingsPath: ["providers", "quick-chat-cloud"],
        adapterKind: .piAI,
        wireProtocol: .openAICompletions,
        defaultBaseURL: URL(string: "https://api.example.test/v1"),
        boundary: .cloud,
        credentialReference: nil
    )
}

@Suite(.serialized)
struct QuickChatWindowBehaviorTests {
    @Test @MainActor func presentationPolicyStripsControlsBidiAndBoundsAllNativeText() {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let hostile = "  Safe\u{202E}\u{2066}\u{0000}\n  Name  " + String(repeating: "Z", count: 1_000)
        let text = QuickChatPresentationPolicy.text(hostile, limit: 32)
        #expect(text.hasPrefix("Safe Name"))
        #expect(text.unicodeScalars.count <= 32)
        #expect(!text.unicodeScalars.contains { $0.properties.generalCategory == .format })
        #expect(!text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) })
        #expect(QuickChatPresentationPolicy.filename("\u{202E}\u{0000}") == "attachment")
    }

    @Test @MainActor func failurePresentationPreservesOnlyKnownSafeErrors() {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        for context in [
            QuickChatFailureContext.catalog,
            .dictation,
            .approvalResponse,
            .questionResponse,
            .questionCancellation,
            .turn,
            .export
        ] {
            let message = context.message(for: QuickChatHostileError())
            #expect(!message.contains("QUICK_CHAT_SECRET_CANARY"))
            #expect(!message.contains("/Users/private"))
            #expect(message.count < 500)
        }
        #expect(QuickChatFailureContext.dictation.message(for: LocalVoiceController.VoiceError.permissionsDenied)
            .contains("Microphone"))
        #expect(QuickChatFailureContext.turn.message(for: HarnessConversationError.timedOut)
            .contains("time limit"))
        #expect(QuickChatFailureContext.turn.message(for: HarnessConversationError.automaticContinuationLimitReached)
            .contains("safety limit"))
        #expect(QuickChatFailureContext.turn.message(for: HarnessConversationError.automaticContinuationUnavailable)
            .contains("restart the agent service"))
        #expect(QuickChatFailureContext.export.message(for: ConversationExportError.invalidDestination)
            .contains("safe regular file"))
    }

    @Test @MainActor func approvalAllowIsSingleFlightAndDuplicateCallbacksAndEventsAreIgnored() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.approvalChoices = [.allowOnce]
        let request = quickChatApproval()
        fixture.controller.handle(.approvalRequested(request))
        fixture.controller.handle(.approvalRequested(request))
        #expect(fixture.interactionProbe.approvalPresentations.count == 1)
        #expect(fixture.operationProbe.approvalCalls.count == 1)
        #expect(fixture.operationProbe.approvalCalls[0].decision == .allowedOnce)

        let completion = fixture.operationProbe.approvalCalls[0].completion
        completion(.success(()))
        let delivered = try quickChatStatus(fixture.controller)
        completion(.failure(QuickChatHostileError()))
        fixture.controller.handle(.approvalRequested(request))
        #expect(try quickChatStatus(fixture.controller) == delivered)
        #expect(fixture.interactionProbe.approvalPresentations.count == 1)
        #expect(!delivered.contains("CANARY"))
    }

    @Test @MainActor func approvalFailureRetryAndLeavePendingAreRecoverableWithoutErrorLeakage() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.approvalChoices = [.reject]
        fixture.interactionProbe.approvalRetryChoices = [.retry]
        fixture.controller.handle(.approvalRequested(quickChatApproval()))
        let first = fixture.operationProbe.approvalCalls[0].completion
        first(.failure(QuickChatHostileError()))
        first(.failure(QuickChatHostileError()))
        #expect(fixture.operationProbe.approvalCalls.count == 2)
        #expect(!((try? quickChatStatus(fixture.controller)) ?? "").contains("QUICK_CHAT_SECRET_CANARY"))
        fixture.operationProbe.approvalCalls[1].completion(.success(()))
        #expect(try quickChatStatus(fixture.controller) == "Tool request rejected")
    }

    @Test @MainActor func unresolvedApprovalSurvivesCloseAndStaleCompletionCannotMutateReopenedUI() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.approvalChoices = [.allowOnce, .reject]
        fixture.controller.handle(.approvalRequested(quickChatApproval()))
        let stale = fixture.operationProbe.approvalCalls[0].completion
        fixture.controller.viewWillDisappear()
        stale(.failure(QuickChatHostileError()))
        #expect(fixture.operationProbe.approvalCalls.count == 1)
        fixture.controller.viewDidAppear()
        #expect(fixture.interactionProbe.approvalPresentations.count == 2)
        #expect(fixture.operationProbe.approvalCalls.count == 2)
        fixture.operationProbe.approvalCalls[1].completion(.success(()))
        #expect(try quickChatStatus(fixture.controller) == "Tool request rejected")
    }

    @Test @MainActor func malformedAndOversizedApprovalsFailClosedWithoutShowingUntrustedText() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        let oversized = quickChatApproval(tool: "QUICK_CHAT_TOOL_CANARY" + String(repeating: "X", count: 5_000))
        fixture.controller.handle(.approvalRequested(oversized))
        #expect(fixture.interactionProbe.approvalPresentations.isEmpty)
        #expect(fixture.operationProbe.approvalCalls.count == 1)
        #expect(fixture.operationProbe.approvalCalls[0].decision == .rejected)
        #expect(!((try? quickChatStatus(fixture.controller)) ?? "").contains("TOOL_CANARY"))

        let malformed = HarnessApprovalRequest(
            rpcID: "bad\u{202E}",
            sessionID: HarnessSessionID("session-1"),
            approvalID: "bad",
            toolName: "Bash",
            callID: nil,
            reason: nil
        )
        fixture.controller.handle(.approvalRequested(malformed))
        #expect(try quickChatStatus(fixture.controller).contains("task was stopped safely"))
    }

    @Test @MainActor func approvalPresentationSanitizesAndBoundsToolReasonAndArguments() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.approvalChoices = [.leavePending]
        let callID = "call-1"
        fixture.controller.handle(.toolCall(HarnessToolCall(
            rpcID: "tool-rpc",
            sessionID: HarnessSessionID("session-1"),
            sequence: 1,
            time: 0,
            turn: 1,
            step: 1,
            callID: callID,
            toolName: "tool",
            argumentsJSON: "{\"path\":\"/tmp\"}\u{202E}" + String(repeating: "A", count: 10_000)
        )))
        fixture.controller.handle(.approvalRequested(quickChatApproval(
            tool: "Bash\u{202E}" + String(repeating: "T", count: 500),
            reason: "Reason\u{2066}" + String(repeating: "R", count: 2_000),
            callID: callID
        )))
        let presentation = try #require(fixture.interactionProbe.approvalPresentations.last)
        #expect(presentation.toolName.unicodeScalars.count <= 120)
        #expect(presentation.reason.unicodeScalars.count <= 800)
        #expect(presentation.arguments?.unicodeScalars.count ?? 0 <= 6_000)
        let all = presentation.toolName + presentation.reason + (presentation.arguments ?? "")
        #expect(!all.unicodeScalars.contains { $0.properties.generalCategory == .format })
    }

    @Test @MainActor func questionAnswerFailureRetryDuplicateAndSuccessAreSingleFlight() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        let answer = quickChatAnswer()
        fixture.interactionProbe.questionChoices = [.answer(answer)]
        fixture.interactionProbe.questionRetryChoices = [.retry]
        let request = quickChatQuestion()
        fixture.controller.handle(.questionRequested(request))
        fixture.controller.handle(.questionRequested(request))
        #expect(fixture.interactionProbe.questionPresentations.count == 1)
        #expect(fixture.operationProbe.questionCalls.count == 1)
        let first = fixture.operationProbe.questionCalls[0].completion
        first(.failure(QuickChatHostileError()))
        first(.success(()))
        #expect(fixture.operationProbe.questionCalls.count == 2)
        #expect(!((try? quickChatStatus(fixture.controller)) ?? "").contains("SECRET_CANARY"))
        fixture.operationProbe.questionCalls[1].completion(.success(()))
        fixture.controller.handle(.questionRequested(request))
        #expect(fixture.interactionProbe.questionPresentations.count == 1)
    }

    @Test @MainActor func questionCancelFailureLeavePendingAndReopenPreserveRequest() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.questionChoices = [.cancelTask, .cancelTask]
        fixture.interactionProbe.questionRetryChoices = [.leavePending]
        fixture.controller.handle(.questionRequested(quickChatQuestion()))
        fixture.operationProbe.cancellationCalls[0].completion(.failure(QuickChatHostileError()))
        #expect(try quickChatStatus(fixture.controller).contains("remain pending"))
        fixture.controller.viewWillDisappear()
        fixture.controller.viewDidAppear()
        #expect(fixture.interactionProbe.questionPresentations.count == 2)
        #expect(fixture.operationProbe.cancellationCalls.count == 2)
        fixture.operationProbe.cancellationCalls[1].completion(.success(()))
        #expect(try quickChatStatus(fixture.controller) == "Question request cancelled")
    }

    @Test @MainActor func invalidQuestionAnswersAndAmbiguousOrOversizedRequestsFailClosed() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.questionChoices = [.answer(quickChatAnswer("Unknown"))]
        fixture.controller.handle(.questionRequested(quickChatQuestion()))
        #expect(fixture.operationProbe.questionCalls.isEmpty)
        #expect(try quickChatStatus(fixture.controller).contains("request remains pending"))

        let ambiguous = quickChatQuestion(
            rpcID: "ambiguous",
            options: [
                HarnessQuestionOption(label: "Allow\u{202E}", description: nil),
                HarnessQuestionOption(label: "Allow", description: nil)
            ]
        )
        fixture.controller.handle(.questionRequested(ambiguous))
        #expect(fixture.operationProbe.cancellationCalls.count == 1)

        let oversized = HarnessQuestionRequest(
            rpcID: "oversized",
            sessionID: HarnessSessionID("session-1"),
            questions: (0..<21).map {
                HarnessQuestion(
                    id: "q-\($0)", question: "Question", detail: nil, header: nil,
                    options: nil, multiSelect: false, intent: nil
                )
            }
        )
        fixture.controller.handle(.questionRequested(oversized))
        #expect(fixture.operationProbe.cancellationCalls.count == 2)
        #expect(fixture.interactionProbe.questionPresentations.count == 1)
    }

    @Test @MainActor func questionPresentationBoundsAndSanitizesEveryVisibleString() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.questionChoices = [.leavePending]
        let request = HarnessQuestionRequest(
            rpcID: "present",
            sessionID: HarnessSessionID("session-1"),
            questions: [HarnessQuestion(
                id: "question-1",
                question: "Question\u{202E}" + String(repeating: "Q", count: 3_000),
                detail: "Detail\u{2066}" + String(repeating: "D", count: 3_000),
                header: nil,
                options: [HarnessQuestionOption(
                    label: "Option\u{202E}" + String(repeating: "O", count: 1_000),
                    description: "Description\u{2066}" + String(repeating: "E", count: 2_000)
                )],
                multiSelect: false,
                intent: nil
            )]
        )
        fixture.controller.handle(.questionRequested(request))
        let presentation = try #require(fixture.interactionProbe.questionPresentations.last)
        let question = presentation.questions[0]
        #expect(question.question.unicodeScalars.count <= 500)
        #expect(question.detail?.unicodeScalars.count ?? 0 <= 700)
        #expect(question.options[0].label.unicodeScalars.count <= 120)
        #expect(question.options[0].detail?.unicodeScalars.count ?? 0 <= 500)
        let text = question.question + (question.detail ?? "") + question.options[0].label + (question.options[0].detail ?? "")
        #expect(!text.unicodeScalars.contains { $0.properties.generalCategory == .format })
    }

    @Test @MainActor func newChatExplicitlyRejectsAndCancelsEveryUnresolvedRequest() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        fixture.interactionProbe.approvalChoices = [.leavePending]
        fixture.interactionProbe.questionChoices = [.leavePending]
        fixture.controller.handle(.approvalRequested(quickChatApproval()))
        fixture.controller.handle(.questionRequested(quickChatQuestion()))
        fixture.controller.newChat()
        #expect(fixture.operationProbe.approvalCalls.count == 1)
        #expect(fixture.operationProbe.approvalCalls[0].decision == .rejected)
        #expect(fixture.operationProbe.cancellationCalls.count == 1)
        #expect(try quickChatStatus(fixture.controller) == "New chat")
    }

    @Test @MainActor func externalConsentIsBoundToSanitizedExactOriginAndInvalidationDeclines() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let descriptor = quickChatCloudDescriptor(name: "Cloud\u{202E} Provider" + String(repeating: "P", count: 300))
        let fixture = try QuickChatFixture(
            descriptor: descriptor,
            modelID: ModelID("cloud-model"),
            modelName: "Model\u{2066}" + String(repeating: "M", count: 300)
        )
        defer { fixture.cleanup() }
        await fixture.loadModel()
        fixture.interactionProbe.externalChoices = [true, true]
        fixture.interactionProbe.onExternal = { fixture.controller.newChat() }
        #expect(await fixture.openConversation() == .boundaryDeclined)
        fixture.interactionProbe.onExternal = nil
        #expect(await fixture.openConversation() == .opened)
        let presentation = try #require(fixture.interactionProbe.externalPresentations.last)
        #expect(presentation.origin == "https://api.example.test")
        #expect(presentation.providerName.unicodeScalars.count <= 120)
        #expect(presentation.modelName.unicodeScalars.count <= 160)
        #expect(!presentation.providerName.unicodeScalars.contains { $0.properties.generalCategory == .format })
    }

    @Test @MainActor func knowledgeDisclosureCancelWithoutAndIncludeUseSingleNativeInteraction() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture(
            descriptor: quickChatCloudDescriptor(),
            modelID: ModelID("cloud-model"),
            withKnowledge: true
        )
        defer { fixture.cleanup() }
        await fixture.loadModel()
        fixture.interactionProbe.externalChoices = [true]
        #expect(await fixture.openConversation() == .opened)
        fixture.controller.onWillStartTurn = { throw QuickChatHostileError() }
        let input = try quickChatTextView("Message", fixture.controller)
        let send = try quickChatButton("Send message", fixture.controller)

        fixture.interactionProbe.knowledgeChoices = [.cancel, .withoutKnowledge, .include]
        fixture.interactionProbe.onKnowledge = { try? quickChatForceSelector(send) }
        input.string = "private draft"
        send.performClick(nil)
        #expect(input.string == "private draft")
        #expect(fixture.interactionProbe.knowledgePresentations.count == 1)

        fixture.interactionProbe.onKnowledge = nil
        send.performClick(nil)
        await quickChatWait("without-knowledge preparation failure") {
            (try? quickChatStatus(fixture.controller).contains("did not finish safely")) == true
        }
        #expect(input.string == "private draft")
        send.performClick(nil)
        await quickChatWait("knowledge preparation failure") {
            fixture.interactionProbe.knowledgePresentations.count == 3
        }
        #expect(!((try? quickChatStatus(fixture.controller)) ?? "").contains("SECRET_CANARY"))
    }

    @Test @MainActor func imageChooserCancelInvalidCapacityReentryAndClearUseRealControls() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        await fixture.loadModel()
        let attach = try quickChatButton("Attach images", fixture.controller)
        let clear = try quickChatButton("Remove attachments", fixture.controller)
        let imageURL = fixture.root.appendingPathComponent("reviewed\u{202E}.png")
        let bitmap = try #require(NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: 2,
            pixelsHigh: 2,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ))
        bitmap.setColor(NSColor(calibratedRed: 0.1, green: 0.3, blue: 0.8, alpha: 1), atX: 0, y: 0)
        try #require(bitmap.representation(using: .png, properties: [:])).write(to: imageURL)
        fixture.interactionProbe.imageChoices = [nil, [imageURL, imageURL, imageURL, imageURL, imageURL]]
        fixture.interactionProbe.onImages = { try? quickChatForceSelector(attach) }
        attach.performClick(nil)
        #expect(fixture.interactionProbe.imageChooserCount == 1)
        fixture.interactionProbe.onImages = nil
        attach.performClick(nil)
        #expect(fixture.interactionProbe.imageChooserCount == 2)
        #expect(try quickChatStatus(fixture.controller).contains("images were skipped"))
        #expect(!clear.isHidden)
        let attachmentText = try quickChatText("Pending attachments", fixture.controller).stringValue
        #expect(!attachmentText.unicodeScalars.contains { $0.properties.generalCategory == .format })
        #expect(!attachmentText.contains("\u{202E}"))
        clear.performClick(nil)
        #expect(clear.isHidden)
        #expect(try quickChatStatus(fixture.controller) == "Attachments removed")
    }

    @Test @MainActor func dictationCompletionIsFirstWinsAndNewChatInvalidatesLateTextAndErrors() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        let dictate = try quickChatButton("On-device dictation", fixture.controller)
        let input = try quickChatTextView("Message", fixture.controller)
        dictate.performClick(nil)
        #expect(fixture.operationProbe.dictationStarts == 1)
        fixture.operationProbe.dictationText?("first text")
        let completion = try #require(fixture.operationProbe.dictationCompletion)
        completion(.success(()))
        #expect(input.string == "first text")
        #expect(try quickChatStatus(fixture.controller) == "Dictation ready to send")
        fixture.operationProbe.dictationText?("late text")
        completion(.failure(QuickChatHostileError()))
        #expect(input.string == "first text")
        #expect(try quickChatStatus(fixture.controller) == "Dictation ready to send")

        dictate.performClick(nil)
        let staleText = try #require(fixture.operationProbe.dictationText)
        let staleCompletion = try #require(fixture.operationProbe.dictationCompletion)
        fixture.controller.newChat()
        staleText("stale")
        staleCompletion(.failure(QuickChatHostileError()))
        #expect(input.string.isEmpty)
        #expect(try quickChatStatus(fixture.controller) == "New chat")
        #expect(fixture.operationProbe.dictationStops >= 1)
    }

    @Test @MainActor func exportCancelDestinationCancelSuccessFailureAndReentryAreDeterministic() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        await fixture.loadModel()
        #expect(await fixture.openConversation() == .opened)
        fixture.interactionProbe.exportChoices = [nil]
        fixture.controller.exportConversation(nil)
        #expect(try quickChatStatus(fixture.controller) == "Export cancelled")
        #expect(fixture.operationProbe.writtenExports.isEmpty)

        fixture.interactionProbe.exportChoices = [
            QuickChatExportSelection(format: .markdown, redaction: .recommended),
            QuickChatExportSelection(format: .json, redaction: .structureOnly),
            QuickChatExportSelection(format: .markdown, redaction: .recommended)
        ]
        let destination = fixture.root.appendingPathComponent("conversation.md")
        fixture.interactionProbe.exportDestinations = [nil, destination, destination]
        fixture.controller.exportConversation(nil)
        #expect(try quickChatStatus(fixture.controller) == "Export cancelled")
        fixture.controller.exportConversation(nil)
        #expect(fixture.operationProbe.writtenExports.count == 1)
        #expect(fixture.operationProbe.revealedExports == [destination])
        #expect(try quickChatStatus(fixture.controller) == "Exported 2 messages")

        fixture.operationProbe.exportError = QuickChatHostileError()
        fixture.interactionProbe.onExport = { fixture.controller.exportConversation(nil) }
        fixture.controller.exportConversation(nil)
        #expect(fixture.operationProbe.writtenExports.count == 1)
        let failure = try quickChatStatus(fixture.controller)
        #expect(failure.contains("could not be completed safely"))
        #expect(!failure.contains("SECRET_CANARY"))
    }

    @Test @MainActor func maxTokenSegmentsRemainVisibleWhileQuickChatContinuesAutomatically() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture()
        defer { fixture.cleanup() }
        await fixture.loadModel()

        fixture.controller.handle(.assistantTextDelta(.init(
            rpcID: "mux", sessionID: HarnessSessionID("session-1"), sequence: 1, time: 1,
            turn: 1, step: 1, blockIndex: 0, text: "first bounded segment"
        )))
        fixture.controller.handle(.turnCompleted(.init(
            rpcID: "mux", sessionID: HarnessSessionID("session-1"), sequence: 2, time: 2,
            turn: 1, reason: .maxTokens
        )))
        #expect(try quickChatStatus(fixture.controller) == "Continuing automatically…")

        fixture.controller.handle(.userMessage(.init(
            rpcID: "mux", sessionID: HarnessSessionID("session-1"), sequence: 3, time: 3,
            messageID: "continuation", sourceRPCID: nil,
            automaticContinuation: .init(round: 1, maximum: 12, isTerminalBudgetNotice: false)
        )))
        #expect(try quickChatStatus(fixture.controller) == "Continuing automatically · 1/12")
        fixture.controller.handle(.assistantTextDelta(.init(
            rpcID: "mux", sessionID: HarnessSessionID("session-1"), sequence: 4, time: 4,
            turn: 2, step: 1, blockIndex: 0, text: "second bounded segment"
        )))
        await quickChatWait("both automatic-continuation segments") {
            guard let conversation = try? quickChatTextView("Conversation", fixture.controller).string else { return false }
            return conversation.contains("first bounded segment")
                && conversation.contains("second bounded segment")
        }
        let conversation = try quickChatTextView("Conversation", fixture.controller).string
        #expect(conversation.contains("first bounded segment\n\nsecond bounded segment"))

        fixture.controller.handle(.userMessage(.init(
            rpcID: "mux", sessionID: HarnessSessionID("session-1"), sequence: 5, time: 5,
            messageID: "budget-summary", sourceRPCID: nil,
            automaticContinuation: .init(round: nil, maximum: nil, isTerminalBudgetNotice: true)
        )))
        #expect(try quickChatStatus(fixture.controller) == "Finishing with a bounded safety summary…")
    }

    @Test @MainActor func completedAutomaticContinuationIsRetainedSpokenAndExportedAsOneReply() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let rpc = QuickChatContinuationRPCFake()
        let fixture = try QuickChatFixture(conversationRPC: rpc)
        defer { fixture.cleanup() }
        await fixture.loadModel()

        let combinedReply = "segment-one\n\nsegment-two"
        let speakReplies = try quickChatButton("Speak replies", fixture.controller)
        speakReplies.state = .on
        let input = try quickChatTextView("Message", fixture.controller)
        input.string = "Complete this without asking me to continue"
        try quickChatButton("Send message", fixture.controller).performClick(nil)

        await quickChatWait("automatic continuation terminal assembly") {
            fixture.operationProbe.spoken == [combinedReply]
        }
        #expect(rpc.promptSnapshot() == [
            .text("Complete this without asking me to continue")
        ])
        #expect(rpc.cancellationCount() == 0)
        let conversation = try quickChatTextView("Conversation", fixture.controller).string
        #expect(conversation.contains(combinedReply))
        #expect(conversation.components(separatedBy: combinedReply).count - 1 == 1)
        #expect(fixture.operationProbe.spoken == [combinedReply])

        fixture.interactionProbe.exportChoices = [QuickChatExportSelection(
            format: .markdown,
            redaction: .none
        )]
        let destination = fixture.root.appendingPathComponent("continued-conversation.md")
        fixture.interactionProbe.exportDestinations = [destination]
        fixture.controller.exportConversation(nil)

        let artifact = try #require(fixture.interactionProbe.exportArtifacts.last)
        #expect(artifact.messageCount == 2)
        #expect(artifact.format == .markdown)
        let markdown = try #require(String(data: artifact.data, encoding: .utf8))
        #expect(markdown.contains(combinedReply))
        #expect(markdown.components(separatedBy: combinedReply).count - 1 == 1)
        #expect(fixture.operationProbe.writtenExports.map(\.0) == [artifact])
        #expect(fixture.operationProbe.revealedExports == [destination])
        #expect(try quickChatStatus(fixture.controller) == "Exported 2 messages")
    }

    @Test @MainActor func everyProductionControlIsAccessibleWiredAndFitsDarkAndLightMinimumLayout() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let fixture = try QuickChatFixture(withKnowledge: true)
        defer { fixture.cleanup() }
        await fixture.loadModel()
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 600, height: 480),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.contentViewController = fixture.controller
        defer { window.orderOut(nil) }
        let views = quickChatDescendants(fixture.controller.view)
        for label in [
            "Send message", "Stop response", "Attach images", "Remove attachments",
            "On-device dictation", "Reason deeply", "Use local knowledge", "Speak replies"
        ] {
            let button = try quickChatButton(label, fixture.controller)
            #expect(button.target != nil)
            #expect(button.action != nil)
            #expect(button.accessibilityLabel()?.isEmpty == false)
        }
        let picker = try quickChatModelPicker(fixture.controller)
        #expect(picker.target != nil)
        #expect(picker.action != nil)
        #expect(try quickChatText("Chat status", fixture.controller).accessibilityLabel() == "Chat status")
        #expect(try quickChatText("Pending attachments", fixture.controller).accessibilityLabel() == "Pending attachments")
        #expect(try quickChatTextView("Message", fixture.controller).isEditable)
        #expect(try quickChatTextView("Conversation", fixture.controller).isSelectable)

        for name in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: name)
            window.layoutIfNeeded()
            for view in views where !view.isHidden && view.window === window {
                #expect(view.frame.isFinite)
                #expect(view.frame.width >= 0 && view.frame.height >= 0)
            }
        }
    }
}

private extension NSRect {
    var isFinite: Bool {
        origin.x.isFinite && origin.y.isFinite && width.isFinite && height.isFinite
    }
}
