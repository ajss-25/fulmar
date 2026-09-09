import Foundation
import Testing
@testable import LocalHarness

@Suite("Harness conversation service")
struct HarnessConversationServiceTests {
    @Test("Creates a Standard Harness session and selects the exact opaque route")
    func createsAndSelects() async throws {
        let fake = ConversationRPCFake()
        let service = HarnessConversationService(rpc: fake)
        let selection = ModelSelection(
            route: .init(provider: .init("provider/opaque"), model: .init("model:opaque")),
            reasoningEffort: "high",
            performanceProfile: .deep
        )
        let workspace = URL(fileURLWithPath: "/private/tmp/conversation-test")

        let result = try await service.createSession(selection: selection, workspace: workspace)

        #expect(result.id == fake.createdRequest?.sessionId)
        #expect(result.selection.route == selection.route)
        #expect(fake.createdRequest?.cwd == workspace.path)
        #expect(fake.createdRequest?.agentPreset == "standard")
        #expect(fake.createdRequest?.sessionId.flatMap(PerformanceSessionIdentity.profile(from:)) == .deep)
        #expect(fake.selected?.route == selection.route)
    }

    @Test("Cancellation after DSH creates a session archives the exact unfinished session")
    func cancelledCreationArchivesExactSession() async {
        let fake = ConversationRPCFake()
        let gate = ConversationOpenGate()
        fake.createGate = gate
        let service = HarnessConversationService(rpc: fake)
        let creation = Task {
            try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-cancelled-create")
            )
        }
        await gate.waitUntilEntered()
        creation.cancel()
        await gate.open()

        do {
            _ = try await creation.value
            Issue.record("A cancelled creation must not transfer session ownership")
        } catch is CancellationError {
            // Expected after the exact created session has been archived.
        } catch {
            Issue.record("Unexpected cancellation result: \(error)")
        }
        #expect(fake.archiveSnapshot() == [fake.createdRequest?.sessionId].compactMap { $0 })
    }

    @Test("Selection failure archives the exact newly created session")
    func selectionFailureArchivesExactSession() async {
        let fake = ConversationRPCFake()
        fake.selectFailure = HarnessRPCClientError.cancelled
        let service = HarnessConversationService(rpc: fake)

        do {
            _ = try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-selection-failure")
            )
            Issue.record("Selection failure unexpectedly transferred the session")
        } catch let error as HarnessRPCClientError {
            #expect(error == .cancelled)
        } catch {
            Issue.record("Unexpected selection failure: \(error)")
        }
        #expect(fake.archiveSnapshot() == [fake.createdRequest?.sessionId].compactMap { $0 })
    }

    @Test("Ambiguous create failure archives the exact preallocated session ID")
    func ambiguousCreateFailureArchivesPreallocatedSession() async throws {
        let fake = ConversationRPCFake()
        fake.createFailureAfterPersistence = HarnessRPCClientError.transport(.networkConnectionLost)
        let service = HarnessConversationService(rpc: fake)

        do {
            _ = try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-ambiguous-create")
            )
            Issue.record("Ambiguous create unexpectedly transferred session ownership")
        } catch let error as HarnessRPCClientError {
            #expect(error == .transport(.networkConnectionLost))
        } catch {
            Issue.record("Unexpected ambiguous-create result: \(error)")
        }

        let requestedID = try #require(fake.createdRequest?.sessionId)
        #expect(fake.archiveSnapshot() == [requestedID])
        #expect(requestedID != fake.sessionID)
    }

    @Test("Published workspace-attach failure compensates, while pre-publication remote rejection does not")
    func remoteCreateFailureCompensationUsesPublicationContract() async throws {
        let published = ConversationRPCFake()
        published.createFailureAfterPersistence = HarnessRPCClientError.remote(.init(
            code: .other("workspace-attach-failed"),
            message: "not presented",
            details: [:]
        ))
        let publishedService = HarnessConversationService(rpc: published)
        do {
            _ = try await publishedService.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-workspace-attach")
            )
            Issue.record("Published workspace-attach failure unexpectedly succeeded")
        } catch let error as HarnessRPCClientError {
            guard case .remote(let remote) = error else {
                Issue.record("Unexpected published remote error: \(error)")
                return
            }
            #expect(remote.code.rawValue == "workspace-attach-failed")
        } catch {
            Issue.record("Unexpected published create result: \(error)")
        }
        let publishedID = try #require(published.createdRequest?.sessionId)
        #expect(published.archiveSnapshot() == [publishedID])

        let rejected = ConversationRPCFake()
        rejected.createFailureAfterPersistence = HarnessRPCClientError.remote(.init(
            code: .badRequest,
            message: "not presented",
            details: [:]
        ))
        let rejectedService = HarnessConversationService(rpc: rejected)
        do {
            _ = try await rejectedService.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-prepublication-rejection")
            )
            Issue.record("Pre-publication rejection unexpectedly succeeded")
        } catch let error as HarnessRPCClientError {
            guard case .remote(let remote) = error else {
                Issue.record("Unexpected pre-publication error: \(error)")
                return
            }
            #expect(remote.code == .badRequest)
        } catch {
            Issue.record("Unexpected pre-publication result: \(error)")
        }
        #expect(rejected.archiveSnapshot().isEmpty)
    }

    @Test("Mismatched create response archives only the preallocated owned ID")
    func mismatchedCreateResponseCannotTransferArbitrarySession() async throws {
        let fake = ConversationRPCFake()
        fake.returnedSessionIDOverride = fake.sessionID
        let service = HarnessConversationService(rpc: fake)

        do {
            _ = try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-mismatched-create")
            )
            Issue.record("Mismatched create response unexpectedly transferred ownership")
        } catch let error as HarnessRPCClientError {
            #expect(error == .responseViolation(.invalidPayload))
        } catch {
            Issue.record("Unexpected mismatched-create result: \(error)")
        }
        let requestedID = try #require(fake.createdRequest?.sessionId)
        #expect(requestedID != fake.sessionID)
        #expect(fake.archiveSnapshot() == [requestedID])
        #expect(fake.selected == nil)
    }

    @Test("Cancellation while model selection is suspended archives exactly once")
    func cancelledSelectionArchivesExactlyOnce() async {
        let fake = ConversationRPCFake()
        let gate = ConversationOpenGate()
        fake.selectGate = gate
        let service = HarnessConversationService(rpc: fake)
        let creation = Task {
            try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-cancelled-select")
            )
        }
        await gate.waitUntilEntered()
        creation.cancel()
        await gate.open()

        do {
            _ = try await creation.value
            Issue.record("Cancelled selection unexpectedly transferred the session")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected cancelled-selection result: \(error)")
        }
        #expect(fake.archiveSnapshot() == [fake.createdRequest?.sessionId].compactMap { $0 })
    }

    @Test("Unverified unfinished-session cleanup fails closed")
    func failedCreationCleanupFailsClosed() async {
        let fake = ConversationRPCFake()
        fake.selectFailure = HarnessRPCClientError.cancelled
        fake.archiveIncludesExactSession = false
        let service = HarnessConversationService(rpc: fake)

        do {
            _ = try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-cleanup-failure")
            )
            Issue.record("Unverified cleanup unexpectedly succeeded")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected cleanup failure: \(error)")
        }
        #expect(fake.archiveSnapshot() == [fake.createdRequest?.sessionId].compactMap { $0 })
    }

    @Test("Thermal-style immediate stop cannot reopen after unverified create cleanup")
    @MainActor
    func thermalStopCreateCleanupFailurePoisonsAdmissionAndQuiescence() async throws {
        let fake = ConversationRPCFake()
        let createGate = ConversationOpenGate()
        fake.createGate = createGate
        fake.createFailureAfterPersistence = HarnessRPCClientError.transport(.networkConnectionLost)
        fake.archiveIncludesExactSession = false
        let service = HarnessConversationService(rpc: fake)
        let creation = Task {
            try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-thermal-cleanup-failure")
            )
        }
        await createGate.waitUntilEntered()

        // Thermal/critical-memory shutdown closes admission and stops the owned
        // runtime immediately rather than waiting for the normal drain first.
        service.suspendAdmissionsForQuiescence()
        service.cancelAll()
        await createGate.open()

        do {
            _ = try await creation.value
            Issue.record("An unverified thermal-race cleanup unexpectedly transferred ownership")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected thermal-race cleanup result: \(error)")
        }
        let requestedID = try #require(fake.createdRequest?.sessionId)
        #expect(fake.archiveSnapshot() == [requestedID])

        do {
            try await service.quiesceSuspendedAdmissions()
            Issue.record("Sticky cleanup poison unexpectedly crossed quiescence")
        } catch let error as HarnessConversationError {
            #expect(error == .sessionCleanupUnverified)
        } catch {
            Issue.record("Unexpected poisoned-quiescence result: \(error)")
        }

        service.resumeAfterQuiescence()
        do {
            _ = try await service.createSession(
                selection: .defaultLocal,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-must-remain-blocked")
            )
            Issue.record("Resume reopened session creation after sticky cleanup poison")
        } catch let error as HarnessConversationError {
            #expect(error == .cancelled)
        } catch {
            Issue.record("Unexpected post-poison admission result: \(error)")
        }

        let sendResult: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("must remain blocked")],
                timeout: 5,
                onEvent: { _ in },
                completion: { continuation.resume(returning: $0) }
            )
        }
        #expect(sendResult.failure as? HarnessConversationError == .cancelled)
        #expect(fake.promptedSession == nil)
    }

    @Test("Schedule admission rejection is synchronous and leaves cleanup ownership with the caller")
    @MainActor
    func scheduledSendAdmissionRejectionDoesNotPublishACompletion() async {
        let fake = ConversationRPCFake()
        let service = HarnessConversationService(rpc: fake)
        let completionCalled = ConversationBooleanProbe()
        service.suspendAdmissionsForQuiescence()

        let identifier = service.sendIfAdmitted(
            sessionID: fake.sessionID,
            content: [.text("must remain unsubmitted")],
            timeout: 5,
            onEvent: { _ in },
            completion: { _ in completionCalled.set() }
        )
        await Task.yield()

        #expect(identifier == nil)
        #expect(!completionCalled.value)
        #expect(fake.promptedSession == nil)
        try? await service.quiesceSuspendedAdmissions()
        service.resumeAfterQuiescence()
    }

    @Test("Streams only the requested session and completes exactly once")
    @MainActor
    func filtersMuxStream() async {
        let fake = ConversationRPCFake()
        let other = HarnessSessionID("other-session")
        fake.events = [
            .assistantTextDelta(.init(rpcID: "mux", sessionID: other, sequence: 1, time: 1, turn: 1, step: 1, blockIndex: 0, text: "secret-other")),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2, turn: 1)),
            .userMessage(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3, messageID: "m1", sourceRPCID: fake.promptRPCID)),
            .toolCall(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 3.5,
                turn: 1, step: 1, callID: "call-1", toolName: "Bash", argumentsJSON: #"{"cmd":"pwd"}"#
            )),
            .assistantTextDelta(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4, turn: 1, step: 1, blockIndex: 0, text: "hello")),
            .turnCompleted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5, turn: 1, reason: .completed))
        ]
        let service = HarnessConversationService(rpc: fake)
        let received = ConversationEventRecorder()

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("hi")],
                timeout: 5,
                onEvent: { event in received.append(event) },
                completion: { continuation.resume(returning: $0) }
            )
        }

        if case .failure(let error) = result { Issue.record("Unexpected failure: \(error)") }
        let eventSnapshot = received.snapshot()
        #expect(eventSnapshot.count == 3)
        #expect(eventSnapshot.allSatisfy {
            switch $0 {
            case .toolCall(let value): return value.sessionID == fake.sessionID && value.callID == "call-1"
            case .assistantTextDelta(let value): return value.sessionID == fake.sessionID
            case .turnCompleted(let value): return value.sessionID == fake.sessionID
            default: return false
            }
        })
        #expect(fake.promptedSession == fake.sessionID)
        #expect(fake.promptedContent == [.text("hi")])
        #expect(fake.subscriptionCancelledCount == 1)
    }

    @Test("Keeps one native operation open through authenticated automatic-continuation turns")
    @MainActor
    func followsAuthenticatedAutomaticContinuationUntilFinalCompletion() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: fake.promptRPCID,
                isDirectUserMessage: true
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, blockIndex: 0, text: "segment-one"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4,
                turn: 1, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5, turn: 2)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 6, time: 6,
                messageID: "continued", sourceRPCID: nil,
                automaticContinuation: .init(round: 1, maximum: 1, isTerminalBudgetNotice: false)
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 7, time: 7,
                turn: 2, step: 1, blockIndex: 0, text: "segment-two"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 8, time: 8,
                turn: 2, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 9, time: 9, turn: 3)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 10, time: 10,
                messageID: "budget-summary", sourceRPCID: nil,
                automaticContinuation: .init(round: nil, maximum: nil, isTerminalBudgetNotice: true)
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 11, time: 11,
                turn: 3, step: 1, blockIndex: 0, text: "final-summary"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 12, time: 12,
                turn: 3, reason: .completed
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let received = ConversationEventRecorder()

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("complete this without asking me to continue")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }

        if case .failure(let error) = result { Issue.record("Unexpected continuation failure: \(error)") }
        let snapshot = received.snapshot()
        #expect(snapshot.compactMap { event -> String? in
            guard case .assistantTextDelta(let value) = event else { return nil }
            return value.text
        } == ["segment-one", "segment-two", "final-summary"])
        #expect(snapshot.filter {
            if case .turnCompleted = $0 { return true }
            return false
        }.count == 3)
        #expect(snapshot.compactMap { event -> HarnessAutomaticContinuationNotice? in
            guard case .userMessage(let value) = event else { return nil }
            return value.automaticContinuation
        }.count == 2)
        #expect(fake.cancelledSessions.isEmpty)
        #expect(fake.subscriptionCancelledCount == 1)
    }

    @Test("A missing or stalled continuation plugin fails promptly and cancels only the owned session")
    @MainActor
    func stalledAutomaticContinuationHasItsOwnDeadline() async {
        let fake = ConversationRPCFake()
        fake.holdMuxOpen = true
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: fake.promptRPCID,
                isDirectUserMessage: true
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, blockIndex: 0, text: "completed segment"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4,
                turn: 1, reason: .maxTokens
            ))
        ]
        let service = HarnessConversationService(
            rpc: fake,
            limits: HarnessConversationLimits(
                maximumEvents: 100,
                maximumAssistantTextBytes: 1_024,
                maximumToolCalls: 8,
                maximumToolBytes: 1_024,
                maximumInteractionEvents: 8,
                maximumInteractionBytes: 1_024,
                maximumPendingMainEvents: 16,
                automaticContinuationGraceSeconds: 0.05
            )
        )
        let received = ConversationEventRecorder()
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("continue without asking me")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(result.failure as? HarnessConversationError == .automaticContinuationUnavailable)
        #expect(fake.cancelledSessions == [fake.sessionID])
        #expect(fake.subscriptionCancelledCount == 1)
        #expect(received.snapshot().contains { event in
            if case .turnCompleted(let value) = event { return value.reason == .maxTokens }
            return false
        })
    }

    @Test("Approvals and questions remain attached to an automatic-continuation turn")
    @MainActor
    func continuationPreservesNativeInteractions() async {
        let fake = ConversationRPCFake()
        let approval = HarnessApprovalRequest(
            rpcID: "approval-rpc", sessionID: fake.sessionID,
            approvalID: "approval-id", toolName: "Bash", callID: "call-id", reason: "review"
        )
        let question = HarnessQuestionRequest(
            rpcID: "question-rpc", sessionID: fake.sessionID,
            questions: [.init(
                id: "q1", question: "Continue safely?", detail: nil, header: "Review",
                options: nil, multiSelect: nil, intent: nil
            )]
        )
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: fake.promptRPCID,
                isDirectUserMessage: true
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4, turn: 2)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5,
                messageID: "continued", sourceRPCID: nil,
                automaticContinuation: .init(round: 1, maximum: 2, isTerminalBudgetNotice: false)
            )),
            .approvalRequested(approval),
            .questionRequested(question),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 8, time: 8,
                turn: 2, step: 1, blockIndex: 0, text: "continued after native interactions"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 9, time: 9,
                turn: 2, reason: .completed
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let received = ConversationEventRecorder()
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("continue with reviewed interactions")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }
        if case .failure(let error) = result { Issue.record("Unexpected interaction failure: \(error)") }
        #expect(received.snapshot().contains(.approvalRequested(approval)))
        #expect(received.snapshot().contains(.questionRequested(question)))
    }

    @Test("Newer direct user work wins without native cancellation of the unrelated turn")
    @MainActor
    func directUserWorkSupersedesStagedContinuation() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: fake.promptRPCID,
                isDirectUserMessage: true
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, blockIndex: 0, text: "saved partial work"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4,
                turn: 1, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5, turn: 2)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 6, time: 6,
                messageID: "new-user-work", sourceRPCID: "newer-rpc",
                isDirectUserMessage: true
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 7, time: 7,
                turn: 2, step: 1, blockIndex: 0, text: "must-not-be-adopted"
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let received = ConversationEventRecorder()
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("original")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }
        #expect(result.failure as? HarnessConversationError == .automaticContinuationSuperseded)
        #expect(fake.cancelledSessions.isEmpty)
        #expect(!received.snapshot().contains { event in
            if case .assistantTextDelta(let value) = event { return value.text == "must-not-be-adopted" }
            return false
        })
    }

    @Test("Out-of-order continuation provenance cancels the exact session")
    @MainActor
    func invalidContinuationSequenceFailsClosed() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: fake.promptRPCID,
                isDirectUserMessage: true
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4, turn: 2)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5,
                messageID: "skipped-round", sourceRPCID: nil,
                automaticContinuation: .init(round: 2, maximum: 12, isTerminalBudgetNotice: false)
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("reject invalid continuation")],
                timeout: 5,
                onEvent: { _ in },
                completion: { continuation.resume(returning: $0) }
            )
        }
        #expect(result.failure as? HarnessConversationError == .automaticContinuationProtocolViolation)
        #expect(fake.cancelledSessions == [fake.sessionID])
    }

    @Test("A terminal safety-summary truncation is surfaced and never loops")
    @MainActor
    func terminalContinuationCannotLoopPastItsBound() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "original", sourceRPCID: fake.promptRPCID,
                isDirectUserMessage: true
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4, turn: 2)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5,
                messageID: "continued", sourceRPCID: nil,
                automaticContinuation: .init(round: 1, maximum: 1, isTerminalBudgetNotice: false)
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 6, time: 6,
                turn: 2, reason: .maxTokens
            )),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 7, time: 7, turn: 3)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 8, time: 8,
                messageID: "budget-summary", sourceRPCID: nil,
                automaticContinuation: .init(round: nil, maximum: nil, isTerminalBudgetNotice: true)
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 9, time: 9,
                turn: 3, step: 1, blockIndex: 0, text: "bounded partial summary"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 10, time: 10,
                turn: 3, reason: .maxTokens
            ))
        ]
        let service = HarnessConversationService(rpc: fake)

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("bounded task")],
                timeout: 5,
                onEvent: { _ in },
                completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(result.failure as? HarnessConversationError == .automaticContinuationLimitReached)
        #expect(fake.cancelledSessions.isEmpty)
    }

    @Test("Every non-success turn end is typed instead of presented as Ready")
    @MainActor
    func nonSuccessTurnEndReasonsFailClosed() async {
        let cases: [(HarnessTurnCompletionReason, HarnessConversationError)] = [
            (.aborted(nil), .turnAborted),
            (.blocked, .turnBlocked),
            (.interrupted, .turnInterrupted),
            (.other, .unsupportedTurnCompletion)
        ]
        for (reason, expected) in cases {
            let fake = ConversationRPCFake()
            fake.events = [
                .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
                .userMessage(.init(
                    rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                    messageID: "original", sourceRPCID: fake.promptRPCID,
                    isDirectUserMessage: true
                )),
                .turnCompleted(.init(
                    rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                    turn: 1, reason: reason
                ))
            ]
            let service = HarnessConversationService(rpc: fake)
            let result: Result<Void, Error> = await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("do not misreport this")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
            #expect(result.failure as? HarnessConversationError == expected)
            #expect(fake.cancelledSessions.isEmpty)
        }
    }

    @Test("Waits for the authenticated event stream before submitting a prompt")
    @MainActor
    func waitsForStreamOpen() async throws {
        let fake = ConversationRPCFake()
        let gate = ConversationOpenGate()
        fake.openGate = gate
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2, messageID: "m1", sourceRPCID: fake.promptRPCID)),
            .turnCompleted(.init(
                rpcID: "mux",
                sessionID: fake.sessionID,
                sequence: 3,
                time: 3,
                turn: 1,
                reason: .completed
            ))
        ]
        let service = HarnessConversationService(rpc: fake)

        let resultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("fast local turn")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
        }

        try await Task.sleep(for: .milliseconds(80))
        #expect(fake.promptedSession == nil)
        await gate.open()
        let result = await resultTask.value
        if case .failure(let error) = result { Issue.record("Unexpected failure: \(error)") }
        #expect(fake.promptedSession == fake.sessionID)
    }

    @Test("Maps Harness turn failures without exposing unrelated stream data")
    @MainActor
    func failsClosed() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2, turn: 1)),
            .userMessage(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3, messageID: "m1", sourceRPCID: fake.promptRPCID)),
            .turnFailed(.init(
                rpcID: "mux",
                sessionID: fake.sessionID,
                sequence: 4,
                time: 4,
                turn: 1,
                failure: .init(message: "provider unavailable", code: "provider", status: nil, providerRetryAfterMs: nil, requestId: nil)
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("hi")],
                timeout: 5,
                onEvent: { _ in },
                completion: { continuation.resume(returning: $0) }
            )
        }
        guard case .failure(let error as HarnessConversationError) = result else {
            Issue.record("Expected a typed failure")
            return
        }
        #expect(error == .turnFailed(ProviderFailureContext(
            kind: .generic,
            status: nil,
            retryAfterMilliseconds: nil,
            requestID: nil
        )))
    }

    @Test("Provider failure presentation is bounded, secret-safe, and app-owned")
    func providerFailurePresentationIsSafe() {
        let credential = ["sk", "release", "secret", String(repeating: "x", count: 40)].joined(separator: "-")
        let hostileCode = "provider\u{001B}[2J\(credential)" + String(repeating: "A", count: 2 * 1_024 * 1_024)
        let generic = ProviderFailurePresentation.message(for: ProviderFailurePresentation.classify(
            code: hostileCode,
            status: nil
        ))
        #expect(generic == "The provider could not complete this request. Review Models & Providers or try again.")
        #expect(!generic.contains(credential))
        #expect(!generic.contains("\u{001B}"))
        #expect(generic.utf8.count < 256)

        let unauthorized = ProviderFailurePresentation.message(for: ProviderFailurePresentation.classify(
            code: "provider",
            status: 401
        ))
        #expect(unauthorized == "The provider rejected the API credential (HTTP 401). Check or replace the API key in Models & Providers.")
        #expect(!unauthorized.contains(credential))

        let forbidden = ProviderFailurePresentation.message(for: ProviderFailurePresentation.classify(
            code: "AUTH",
            status: 403
        ))
        #expect(forbidden == "The provider rejected the API credential (HTTP 403). Check or replace the API key in Models & Providers.")

        let missing = ProviderFailurePresentation.classify(code: "MISSING_CREDENTIAL", status: nil)
        #expect(missing.kind == .credentialMissing)
        #expect(ProviderFailurePresentation.message(for: missing)
            == "No API key is configured for this model. Add one in Models & Providers.")

        for recoveryCode in [
            "KEYCHAIN_AUTHORIZATION_REQUIRED", "CREDENTIAL_RECOVERY_REQUIRED",
            "CREDENTIAL_STATE_UNSAFE", "CREDENTIAL_TRANSACTION_BUSY",
            "CREDENTIAL_VERIFICATION_FAILED"
        ] {
            let recovery = ProviderFailurePresentation.classify(code: recoveryCode, status: nil)
            #expect(recovery.kind == .credentialRecoveryRequired)
            #expect(ProviderFailurePresentation.message(for: recovery)
                == "The provider credential needs attention. Open Models & Providers to repair it.")
        }

        let noCredit = ProviderFailurePresentation.message(for: ProviderFailurePresentation.classify(
            code: "provider",
            status: 402
        ))
        #expect(noCredit == "The provider reported insufficient credit or an unpaid balance (HTTP 402). Add credit with the provider or select another model.")
        #expect(!noCredit.contains(credential))

        for falsePositive in ["authoring", "accredited", "moderate"] {
            let classified = ProviderFailurePresentation.classify(code: falsePositive, status: nil)
            #expect(classified.kind == .generic)
            #expect(ProviderFailurePresentation.message(for: classified)
                == "The provider could not complete this request. Review Models & Providers or try again.")
        }

        let codeOnlyCredit = ProviderFailurePresentation.classify(code: "insufficient-credit", status: nil)
        #expect(codeOnlyCredit.kind == .insufficientCredit)
        #expect(!ProviderFailurePresentation.message(for: codeOnlyCredit).contains("HTTP 402"))

        let exactQuota = ProviderFailurePresentation.classify(code: "QUOTA", status: 429)
        #expect(exactQuota.kind == .insufficientCredit)
        #expect(!ProviderFailurePresentation.message(for: exactQuota).contains("rate limit"))

        // OpenAI uses HTTP 429 for both transient rate pressure and durable
        // credit/spend exhaustion. The bounded code must win without exposing
        // the provider-owned message; an unknown 429 retains the rate fallback.
        for quotaCode in [
            "insufficient_quota", "credit_balance_exhausted",
            "organization_usage_limit_exceeded", "organization_spend_limit_exceeded",
            "project_spend_limit_exceeded"
        ] {
            let quota = ProviderFailurePresentation.classify(code: quotaCode, status: 429)
            #expect(quota.kind == .insufficientCredit)
            #expect(ProviderFailurePresentation.message(for: quota).contains("insufficient credit"))
            #expect(!ProviderFailurePresentation.message(for: quota).contains("rate limit"))
        }
        let unknown429 = ProviderFailurePresentation.classify(code: "provider", status: 429)
        #expect(unknown429.kind == .rateLimited)
        #expect(ProviderFailurePresentation.message(for: unknown429).contains("HTTP 429"))
        #expect(ProviderFailurePresentation.classify(
            code: "service-unavailable",
            status: 401
        ).kind == .credentialRejected)
        #expect(ProviderFailurePresentation.classify(
            code: "rate-limit-exceeded",
            status: 402
        ).kind == .insufficientCredit)

        for temporaryCode in ["SERVER", "TRANSPORT", "TIMEOUT", "STREAM_CLOSED", "EMPTY_RESPONSE"] {
            #expect(ProviderFailurePresentation.classify(
                code: temporaryCode,
                status: nil
            ).kind == .temporarilyUnavailable)
        }
        #expect(ProviderFailurePresentation.classify(
            code: "NO_ADAPTER",
            status: nil
        ).kind == .modelUnavailable)
        #expect(ProviderFailurePresentation.classify(
            code: "CONTEXT_WINDOW_EXCEEDED",
            status: nil
        ).kind == .contextWindowExceeded)

        let codeOnlyRate = ProviderFailurePresentation.classify(
            code: "rate-limit-exceeded",
            status: nil,
            retryAfterMilliseconds: 1_001
        )
        #expect(codeOnlyRate.kind == .rateLimited)
        #expect(!ProviderFailurePresentation.message(for: codeOnlyRate).contains("HTTP 429"))
        #expect(ProviderFailurePresentation.message(for: codeOnlyRate).contains("2 seconds"))

        let bounded = ProviderFailurePresentation.classify(
            code: "service-unavailable",
            status: 999,
            retryAfterMilliseconds: 86_400_001,
            requestID: "request\n\u{202E}" + String(repeating: "R", count: 2_048)
        )
        #expect(bounded.kind == .temporarilyUnavailable)
        #expect(bounded.status == nil)
        #expect(bounded.retryAfterMilliseconds == nil)
        #expect(bounded.requestID == nil)
        #expect(!ProviderFailurePresentation.message(for: bounded).contains("HTTP"))

        let accepted = ProviderFailurePresentation.classify(
            code: "provider",
            status: 503,
            retryAfterMilliseconds: 86_400_000,
            requestID: "request/id:west@1"
        )
        #expect(accepted.kind == .temporarilyUnavailable)
        #expect(accepted.status == 503)
        #expect(accepted.retryAfterMilliseconds == 86_400_000)
        #expect(accepted.requestID == "request/id:west@1")
        #expect(ProviderFailurePresentation.message(for: accepted).contains("HTTP 503"))
    }

    @Test("Ignores an older running turn and completes only the submitted prompt")
    @MainActor
    func correlatesExactPromptTurn() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 7)),
            .userMessage(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2, messageID: "old", sourceRPCID: "older-prompt")),
            .assistantTextDelta(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3, turn: 7, step: 1, blockIndex: 0, text: "old-secret")),
            .turnCompleted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4, turn: 7, reason: .completed)),
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 5, time: 5, turn: 8)),
            .userMessage(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 6, time: 6, messageID: "ours", sourceRPCID: fake.promptRPCID)),
            .assistantTextDelta(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 7, time: 7, turn: 8, step: 1, blockIndex: 0, text: "ours")),
            .turnCompleted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 8, time: 8, turn: 8, reason: .completed))
        ]
        let service = HarnessConversationService(rpc: fake)
        let received = ConversationEventRecorder()

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("new")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }

        if case .failure(let error) = result { Issue.record("Unexpected failure: \(error)") }
        let texts = received.snapshot().compactMap { event -> String? in
            guard case .assistantTextDelta(let delta) = event else { return nil }
            return delta.text
        }
        #expect(texts == ["ours"])
    }

    @Test("Completes slash commands without waiting for a model turn")
    @MainActor
    func completesCommandImmediately() async {
        let fake = ConversationRPCFake()
        fake.promptResult = HarnessPromptResult(
            accepted: true,
            command: .init(kind: "success", text: "Model changed")
        )
        let service = HarnessConversationService(rpc: fake)
        let received = ConversationEventRecorder()

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("/model")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }

        if case .failure(let error) = result { Issue.record("Unexpected failure: \(error)") }
        #expect(received.snapshot().contains(.commandResponse(.init(
            sessionID: fake.sessionID,
            kind: "success",
            text: "Model changed"
        ))))
    }

    @Test("Forwards one-time approvals and question answers through authenticated RPC")
    func interactions() async throws {
        let fake = ConversationRPCFake()
        let service = HarnessConversationService(rpc: fake)
        let approval = HarnessApprovalRequest(
            rpcID: "approval-rpc",
            sessionID: fake.sessionID,
            approvalID: "approval-id",
            toolName: "read",
            callID: nil,
            reason: nil
        )
        let question = HarnessQuestionRequest(
            rpcID: "question-rpc",
            sessionID: fake.sessionID,
            questions: [.init(id: "q1", question: "Continue?", detail: nil, header: nil, options: nil, multiSelect: nil, intent: nil)]
        )
        let answer = HarnessQuestionAnswer(answers: [.init(id: "q1", selected: [], custom: "yes")])

        try await service.respond(to: approval, decision: .allowedOnce)
        try await service.respond(to: question, answer: answer)
        try await service.cancel(question)

        #expect(fake.approvalResponse?.0 == "approval-id")
        #expect(fake.approvalResponse?.1 == .allowedOnce)
        #expect(fake.questionAnswer == answer)
        #expect(fake.cancelledQuestionRPC == "question-rpc")
    }

    @Test("Cancels the exact session when many small deltas exceed the whole-turn budget")
    @MainActor
    func boundsAggregateTextAndEventFloods() async {
        let fake = ConversationRPCFake()
        var events: [HarnessMuxEvent] = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "m1", sourceRPCID: fake.promptRPCID
            ))
        ]
        for sequence in 3...100 {
            events.append(.assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: sequence, time: Double(sequence),
                turn: 1, step: 1, blockIndex: 0, text: "12345"
            )))
        }
        fake.events = events
        let limits = HarnessConversationLimits(
            maximumEvents: 100,
            maximumAssistantTextBytes: 32,
            maximumToolCalls: 8,
            maximumToolBytes: 1_024,
            maximumInteractionEvents: 8,
            maximumInteractionBytes: 1_024,
            maximumPendingMainEvents: 16
        )
        let service = HarnessConversationService(rpc: fake, limits: limits)
        let received = ConversationEventRecorder()

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("bounded")],
                timeout: 5,
                onEvent: { received.append($0) },
                completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(result.failure as? HarnessConversationError == .streamLimitExceeded)
        #expect(fake.cancelledSessions == [fake.sessionID])
        let deliveredBytes = received.snapshot().reduce(into: 0) { count, event in
            if case .assistantTextDelta(let value) = event { count += value.text.utf8.count }
        }
        #expect(deliveredBytes <= limits.maximumAssistantTextBytes)
    }

    @Test("Charges assistant provider and model provenance to the whole-turn byte budget")
    @MainActor
    func boundsAssistantSourceMetadata() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "m1", sourceRPCID: fake.promptRPCID
            )),
            .assistantFinalMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, messageID: "assistant/1", textBlocks: ["ok"],
                provider: ProviderID(String(repeating: "p", count: 24)),
                model: ModelID(String(repeating: "m", count: 24)), interrupted: false
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4,
                turn: 1, reason: .completed
            ))
        ]
        let service = HarnessConversationService(
            rpc: fake,
            limits: HarnessConversationLimits(
                maximumEvents: 20, maximumAssistantTextBytes: 32,
                maximumToolCalls: 2, maximumToolBytes: 1_024,
                maximumInteractionEvents: 2, maximumInteractionBytes: 1_024,
                maximumPendingMainEvents: 8
            )
        )
        let received = ConversationEventRecorder()
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID, content: [.text("metadata")], timeout: 5,
                onEvent: { received.append($0) }, completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(result.failure as? HarnessConversationError == .streamLimitExceeded)
        #expect(fake.cancelledSessions == [fake.sessionID])
        #expect(!received.snapshot().contains { event in
            if case .assistantFinalMessage = event { return true }
            return false
        })
    }

    @Test("Bounds tool and interactive payloads before main-queue dispatch")
    @MainActor
    func boundsToolAndQuestionPayloads() async {
        let toolFake = ConversationRPCFake()
        toolFake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: toolFake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: toolFake.sessionID, sequence: 2, time: 2,
                messageID: "m1", sourceRPCID: toolFake.promptRPCID
            )),
            .toolCall(.init(
                rpcID: "mux", sessionID: toolFake.sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, callID: "call", toolName: "Bash",
                argumentsJSON: String(repeating: "x", count: 80)
            ))
        ]
        let toolService = HarnessConversationService(
            rpc: toolFake,
            limits: HarnessConversationLimits(
                maximumEvents: 20, maximumAssistantTextBytes: 1_024,
                maximumToolCalls: 2, maximumToolBytes: 32,
                maximumInteractionEvents: 4, maximumInteractionBytes: 1_024,
                maximumPendingMainEvents: 8
            )
        )
        let toolResult: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = toolService.send(
                sessionID: toolFake.sessionID, content: [.text("tool")], timeout: 5,
                onEvent: { _ in }, completion: { continuation.resume(returning: $0) }
            )
        }
        #expect(toolResult.failure as? HarnessConversationError == .streamLimitExceeded)
        #expect(toolFake.cancelledSessions == [toolFake.sessionID])

        let questionFake = ConversationRPCFake()
        questionFake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: questionFake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: questionFake.sessionID, sequence: 2, time: 2,
                messageID: "m1", sourceRPCID: questionFake.promptRPCID
            )),
            .questionRequested(.init(
                rpcID: "question-rpc", sessionID: questionFake.sessionID,
                questions: [.init(
                    id: "q1", question: String(repeating: "?", count: 100), detail: nil,
                    header: nil, options: nil, multiSelect: nil, intent: nil
                )]
            ))
        ]
        let questionService = HarnessConversationService(
            rpc: questionFake,
            limits: HarnessConversationLimits(
                maximumEvents: 20, maximumAssistantTextBytes: 1_024,
                maximumToolCalls: 2, maximumToolBytes: 1_024,
                maximumInteractionEvents: 2, maximumInteractionBytes: 32,
                maximumPendingMainEvents: 8
            )
        )
        let questionResult: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = questionService.send(
                sessionID: questionFake.sessionID, content: [.text("question")], timeout: 5,
                onEvent: { _ in }, completion: { continuation.resume(returning: $0) }
            )
        }
        #expect(questionResult.failure as? HarnessConversationError == .streamLimitExceeded)
        #expect(questionFake.cancelledSessions == [questionFake.sessionID])
    }

    @Test("Cancels a submitted turn when the authenticated transport overflows")
    @MainActor
    func cancelsAfterTransportOverflow() async {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "m1", sourceRPCID: fake.promptRPCID
            ))
        ]
        fake.muxFailure = HarnessRPCClientError.responseTooLarge(limit: 8)
        let service = HarnessConversationService(rpc: fake)

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID, content: [.text("overflow")], timeout: 5,
                onEvent: { _ in }, completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(result.failure as? HarnessRPCClientError == .responseTooLarge(limit: 8))
        #expect(fake.cancelledSessions == [fake.sessionID])
    }

    @Test("Cancels the exact session when prompt acknowledgement is ambiguous")
    @MainActor
    func cancelsAfterAmbiguousPromptFailure() async {
        let fake = ConversationRPCFake()
        fake.promptFailure = ConversationPromptFixtureError.acknowledgementLost
        let service = HarnessConversationService(rpc: fake)

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID, content: [.text("ambiguous")], timeout: 5,
                onEvent: { _ in }, completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(result.failure is ConversationPromptFixtureError)
        #expect(fake.cancelledSessions == [fake.sessionID])
    }

    @Test("Quiescence prevents a prompt that has not crossed the submission boundary")
    @MainActor
    func quiesceBeforePromptSubmission() async throws {
        let fake = ConversationRPCFake()
        let openGate = ConversationOpenGate()
        fake.openGate = openGate
        let service = HarnessConversationService(rpc: fake)

        let resultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("must not submit")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
        }
        await openGate.waitUntilEntered()

        try await service.quiesce()
        let result = await resultTask.value

        #expect(result.failure as? HarnessConversationError == .cancelled)
        #expect(fake.promptedSession == nil)
        #expect(fake.cancelledSessions.isEmpty)
        service.resumeAfterQuiescence()
        await openGate.open()
    }

    @Test("A synchronous lifecycle suspension closes admission before its async drain starts")
    @MainActor
    func suspendedAdmissionCannotAcceptALateTerminationTurn() async throws {
        let fake = ConversationRPCFake()
        let service = HarnessConversationService(rpc: fake)

        service.suspendAdmissionsForQuiescence()
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("must be rejected during quit")],
                timeout: 5,
                onEvent: { _ in },
                completion: { continuation.resume(returning: $0) }
            )
        }
        try await service.quiesceSuspendedAdmissions()

        #expect(result.failure as? HarnessConversationError == .cancelled)
        #expect(fake.promptedSession == nil)
        #expect(fake.cancelledSessions.isEmpty)
        service.resumeAfterQuiescence()
    }

    @Test("A memory-warning admission hold rejects new work without cancelling the active turn")
    @MainActor
    func softAdmissionHoldLetsActiveTurnSettle() async throws {
        let fake = ConversationRPCFake()
        let promptGate = ConversationOpenGate()
        fake.promptGate = promptGate
        fake.events = [
            .turnStarted(.init(
                rpcID: "mux", sessionID: fake.sessionID,
                sequence: 1, time: 1, turn: 1
            )),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID,
                sequence: 2, time: 2, messageID: "m1",
                sourceRPCID: fake.promptRPCID
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID,
                sequence: 3, time: 3, turn: 1, reason: .completed
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let activeFinished = ConversationBooleanProbe()

        let activeResultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("finish under Eco")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: {
                        activeFinished.set()
                        continuation.resume(returning: $0)
                    }
                )
            }
        }
        await promptGate.waitUntilEntered()

        service.suspendAdmissionsForQuiescence()
        let lateResult: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("must wait for normal memory")],
                timeout: 5,
                onEvent: { _ in },
                completion: { continuation.resume(returning: $0) }
            )
        }
        #expect(lateResult.failure as? HarnessConversationError == .cancelled)
        #expect(!activeFinished.value)
        #expect(fake.cancelledSessions.isEmpty)

        await promptGate.open()
        let activeResult = await activeResultTask.value
        if case .failure(let error) = activeResult {
            Issue.record("Active Eco turn failed unexpectedly: \(error)")
        }
        #expect(activeFinished.value)
        #expect(fake.cancelledSessions.isEmpty)
        service.resumeAfterQuiescence()
    }

    @Test("Critical resource pressure cancels every active local turn by its owned session identity")
    @MainActor
    func criticalPressureCancellationStopsActiveTurn() async {
        let fake = ConversationRPCFake()
        let promptGate = ConversationOpenGate()
        fake.promptGate = promptGate
        let service = HarnessConversationService(rpc: fake)

        let resultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("cancel under critical pressure")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
        }
        await promptGate.waitUntilEntered()

        service.cancelAll()
        let result = await resultTask.value
        #expect(result.failure as? HarnessConversationError == .cancelled)
        #expect(fake.cancelledSessions == [fake.sessionID])
        await promptGate.open()
    }

    @Test("Quiescence waits for in-flight session setup before provider mutation")
    func quiesceWaitsForAncillarySessionRPCs() async throws {
        let fake = ConversationRPCFake()
        let createGate = ConversationOpenGate()
        fake.createGate = createGate
        let service = HarnessConversationService(rpc: fake)
        let finished = ConversationBooleanProbe()
        let selection = ModelSelection(
            route: .init(provider: .init("provider"), model: .init("model")),
            reasoningEffort: nil,
            performanceProfile: .balanced
        )

        let creation = Task {
            try await service.createSession(
                selection: selection,
                workspace: URL(fileURLWithPath: "/private/tmp/conversation-ancillary")
            )
        }
        await createGate.waitUntilEntered()
        let barrier = Task {
            try await service.quiesce()
            finished.set()
        }
        try await Task.sleep(for: .milliseconds(50))
        #expect(!finished.value)

        await createGate.open()
        _ = try await creation.value
        try await barrier.value
        #expect(finished.value)
        service.resumeAfterQuiescence()
    }

    @Test("Quiescence waits for exact remote cancellation acknowledgement")
    @MainActor
    func quiesceWaitsForRemoteAcknowledgement() async throws {
        let fake = ConversationRPCFake()
        let promptGate = ConversationOpenGate()
        let cancelGate = ConversationOpenGate()
        fake.promptGate = promptGate
        fake.cancelGate = cancelGate
        let service = HarnessConversationService(rpc: fake)
        let completionProbe = ConversationBooleanProbe()

        let resultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("submitted")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
        }
        await promptGate.waitUntilEntered()

        let quiescence = Task {
            try await service.quiesce()
            completionProbe.set()
        }
        await cancelGate.waitUntilEntered()
        try await Task.sleep(for: .milliseconds(50))
        #expect(!completionProbe.value)

        await cancelGate.open()
        try await quiescence.value
        let result = await resultTask.value
        #expect(completionProbe.value)
        #expect(result.failure as? HarnessConversationError == .cancelled)
        #expect(fake.cancelledSessions == [fake.sessionID])

        service.resumeAfterQuiescence()
        await promptGate.open()
    }

    @Test("Quiescence waits for queued main-actor events and terminal completion")
    @MainActor
    func quiesceWaitsForDispatcherSettlement() async throws {
        let fake = ConversationRPCFake()
        fake.events = [
            .turnStarted(.init(rpcID: "mux", sessionID: fake.sessionID, sequence: 1, time: 1, turn: 1)),
            .userMessage(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 2, time: 2,
                messageID: "m1", sourceRPCID: fake.promptRPCID
            )),
            .assistantTextDelta(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 3, time: 3,
                turn: 1, step: 1, blockIndex: 0, text: "queued"
            )),
            .turnCompleted(.init(
                rpcID: "mux", sessionID: fake.sessionID, sequence: 4, time: 4,
                turn: 1, reason: .completed
            ))
        ]
        let service = HarnessConversationService(rpc: fake)
        let handlerBlock = ConversationHandlerBlock()
        let quiescenceFinished = ConversationBooleanProbe()

        let observer = Task.detached {
            while !handlerBlock.hasEntered { await Task.yield() }
            let barrier = Task {
                try await service.quiesce()
                quiescenceFinished.set()
            }
            try await Task.sleep(for: .milliseconds(50))
            let returnedBeforeRelease = quiescenceFinished.value
            handlerBlock.release()
            try await barrier.value
            return returnedBeforeRelease
        }

        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            _ = service.send(
                sessionID: fake.sessionID,
                content: [.text("finish while UI is busy")],
                timeout: 5,
                onEvent: { _ in handlerBlock.enterAndWait() },
                completion: { continuation.resume(returning: $0) }
            )
        }

        #expect(!((try? await observer.value) ?? true))
        if case .failure(let error) = result { Issue.record("Unexpected failure: \(error)") }
        #expect(quiescenceFinished.value)
        service.resumeAfterQuiescence()
    }

    @Test("Quiescence fails closed when remote cancellation is rejected")
    @MainActor
    func quiesceRejectsUnverifiedCancellation() async {
        let fake = ConversationRPCFake()
        let promptGate = ConversationOpenGate()
        fake.promptGate = promptGate
        fake.cancelAccepted = false
        let service = HarnessConversationService(rpc: fake)

        let resultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                _ = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("ambiguous remote work")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
        }
        await promptGate.waitUntilEntered()

        do {
            try await service.quiesce()
            Issue.record("Expected quiescence to fail closed")
        } catch let error as HarnessConversationError {
            #expect(error == .cancellationUnverified)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        let result = await resultTask.value
        #expect(result.failure as? HarnessConversationError == .cancellationUnverified)
        #expect(fake.cancelledSessions == [fake.sessionID])
        service.resumeAfterQuiescence()
        await promptGate.open()
    }

    @Test("Explicit cancellation cannot be redirected to a stale session identity")
    @MainActor
    func cancellationUsesOwnedSessionIdentity() async {
        let fake = ConversationRPCFake()
        let promptGate = ConversationOpenGate()
        fake.promptGate = promptGate
        let service = HarnessConversationService(rpc: fake)

        var operationID: UUID?
        let resultTask = Task<Result<Void, Error>, Never> {
            await withCheckedContinuation { continuation in
                operationID = service.send(
                    sessionID: fake.sessionID,
                    content: [.text("cancel me")],
                    timeout: 5,
                    onEvent: { _ in },
                    completion: { continuation.resume(returning: $0) }
                )
            }
        }
        await promptGate.waitUntilEntered()
        guard let operationID else {
            Issue.record("Missing operation identity")
            return
        }

        service.cancel(operationID, sessionID: HarnessSessionID("stale-wrong-session"))
        let result = await resultTask.value
        #expect(result.failure as? HarnessConversationError == .cancelled)
        #expect(fake.cancelledSessions == [fake.sessionID])
        await promptGate.open()
    }
}

private enum ConversationPromptFixtureError: Error {
    case acknowledgementLost
}

private extension Result where Success == Void, Failure == Error {
    var failure: Error? {
        guard case .failure(let error) = self else { return nil }
        return error
    }
}

private final class ConversationRPCFake: HarnessConversationRPCServicing, @unchecked Sendable {
    let sessionID = HarnessSessionID("session-1")
    let promptRPCID = "prompt-rpc"
    var promptResult = HarnessPromptResult(accepted: true, command: nil)
    var promptFailure: Error?
    var events: [HarnessMuxEvent] = []
    var createdRequest: HarnessSessionCreateRequest?
    var selected: HarnessWireModelSelection?
    var promptedSession: HarnessSessionID?
    var promptedContent: [HarnessPromptContentPart]?
    var approvalResponse: (String, HarnessApprovalDecision)?
    var questionAnswer: HarnessQuestionAnswer?
    var cancelledQuestionRPC: String?
    var subscriptionCancelledCount = 0
    var cancelledSessions: [HarnessSessionID] = []
    var archivedSessions: [HarnessSessionID] = []
    var openGate: ConversationOpenGate?
    var promptGate: ConversationOpenGate?
    var cancelGate: ConversationOpenGate?
    var createGate: ConversationOpenGate?
    var createFailureAfterPersistence: Error?
    var returnedSessionIDOverride: HarnessSessionID?
    var selectGate: ConversationOpenGate?
    var selectFailure: Error?
    var cancelAccepted = true
    var archiveIncludesExactSession = true
    var muxFailure: Error?
    var holdMuxOpen = false
    private var liveMuxContinuation: AsyncThrowingStream<HarnessMuxEvent, Error>.Continuation?
    private let lock = NSLock()

    func createSession(_ request: HarnessSessionCreateRequest) async throws -> HarnessSessionCreateResult {
        lock.withConversationLock { createdRequest = request }
        if let gate = lock.withConversationLock({ createGate }) { await gate.wait() }
        if let failure = lock.withConversationLock({ createFailureAfterPersistence }) { throw failure }
        return .init(
            sessionId: lock.withConversationLock { returnedSessionIDOverride } ?? request.sessionId ?? sessionID,
            agentPreset: request.agentPreset
        )
    }

    func selectModel(sessionID: HarnessSessionID, selection: HarnessWireModelSelection) async throws -> HarnessWireModelSelection {
        lock.withConversationLock { selected = selection }
        if let gate = lock.withConversationLock({ selectGate }) { await gate.wait() }
        if let failure = lock.withConversationLock({ selectFailure }) { throw failure }
        return selection
    }

    func archiveSession(_ sessionID: HarnessSessionID) async throws -> HarnessArchivedSessionsResult {
        lock.withConversationLock { archivedSessions.append(sessionID) }
        let includesExact = lock.withConversationLock { archiveIncludesExactSession }
        return HarnessArchivedSessionsResult(archivedSessionIds: includesExact ? [sessionID] : [])
    }

    func archiveSnapshot() -> [HarnessSessionID] {
        lock.withConversationLock { archivedSessions }
    }

    func prompt(
        sessionID: HarnessSessionID,
        mode: HarnessPromptMode,
        content: [HarnessPromptContentPart],
        clientTimeZone: String?
    ) async throws -> HarnessPromptSubmission {
        lock.withConversationLock { promptedSession = sessionID; promptedContent = content }
        if let gate = lock.withConversationLock({ promptGate }) { await gate.wait() }
        if let failure = lock.withConversationLock({ self.promptFailure }) { throw failure }
        return HarnessPromptSubmission(rpcID: promptRPCID, result: lock.withConversationLock { promptResult })
    }

    func cancel(sessionID: HarnessSessionID) async throws -> HarnessCancelResult {
        lock.withConversationLock { cancelledSessions.append(sessionID) }
        if let gate = lock.withConversationLock({ cancelGate }) { await gate.wait() }
        return HarnessCancelResult(accepted: lock.withConversationLock { cancelAccepted })
    }

    func respondToApproval(
        rpcID: String,
        sessionID: HarnessSessionID,
        approvalID: String,
        decision: HarnessApprovalDecision
    ) async throws -> HarnessRPCReceipt {
        lock.withConversationLock { approvalResponse = (approvalID, decision) }
        return try receipt()
    }

    func respondToQuestion(
        rpcID: String,
        sessionID: HarnessSessionID,
        answer: HarnessQuestionAnswer
    ) async throws -> HarnessRPCReceipt {
        lock.withConversationLock { questionAnswer = answer }
        return try receipt()
    }

    func cancelQuestion(rpcID: String) async throws -> HarnessRPCReceipt {
        lock.withConversationLock { cancelledQuestionRPC = rpcID }
        return try receipt()
    }

    func muxEvents(since: [HarnessSessionID: Int]) throws -> HarnessMuxSubscription {
        let snapshot = lock.withConversationLock { events }
        let failure = lock.withConversationLock { muxFailure }
        let shouldHold = lock.withConversationLock { holdMuxOpen }
        let stream = AsyncThrowingStream<HarnessMuxEvent, Error> { continuation in
            snapshot.forEach { continuation.yield($0) }
            if let failure { continuation.finish(throwing: failure) }
            else if shouldHold {
                lock.withConversationLock { liveMuxContinuation = continuation }
            } else { continuation.finish() }
        }
        let gate = lock.withConversationLock { openGate }
        return HarnessMuxSubscription(
            events: stream,
            waitUntilOpen: { if let gate { await gate.wait() } },
            cancellation: { [weak self] in
                let continuation = self?.lock.withConversationLock { () -> AsyncThrowingStream<HarnessMuxEvent, Error>.Continuation? in
                    self?.subscriptionCancelledCount += 1
                    let continuation = self?.liveMuxContinuation
                    self?.liveMuxContinuation = nil
                    return continuation
                }
                continuation?.finish()
            }
        )
    }

    private func receipt() throws -> HarnessRPCReceipt {
        try JSONDecoder().decode(HarnessRPCReceipt.self, from: Data(#"{"accepted":true}"#.utf8))
    }
}

private actor ConversationOpenGate {
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
        guard !opened else { return }
        await withCheckedContinuation { continuation in waiters.append(continuation) }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { continuation in entryWaiters.append(continuation) }
    }

    func open() {
        guard !opened else { return }
        opened = true
        let current = waiters
        waiters.removeAll()
        current.forEach { $0.resume() }
    }
}

private final class ConversationBooleanProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue = false

    var value: Bool { lock.withConversationLock { storedValue } }
    func set() { lock.withConversationLock { storedValue = true } }
}

private final class ConversationHandlerBlock: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false
    private var released = false

    var hasEntered: Bool {
        condition.lock(); defer { condition.unlock() }
        return entered
    }

    func enterAndWait() {
        condition.lock()
        entered = true
        condition.broadcast()
        while !released { condition.wait() }
        condition.unlock()
    }

    func release() {
        condition.lock()
        released = true
        condition.broadcast()
        condition.unlock()
    }
}

private final class ConversationEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [HarnessMuxEvent] = []

    func append(_ event: HarnessMuxEvent) { lock.withConversationLock { values.append(event) } }
    func snapshot() -> [HarnessMuxEvent] { lock.withConversationLock { values } }
}

private extension NSLock {
    func withConversationLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }
        return try body()
    }
}
