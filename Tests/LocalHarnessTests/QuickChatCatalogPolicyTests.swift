import Testing
@testable import LocalHarness

@Suite("Quick Chat catalogue policy")
struct QuickChatCatalogPolicyTests {
    private let local = ModelRoute(
        provider: ProviderID(rawValue: "ollama"),
        model: ModelID(rawValue: "qwen3.8:27b")
    )
    private let cloudA = ModelRoute(
        provider: ProviderID(rawValue: "provider-a"),
        model: ModelID(rawValue: "model-a")
    )
    private let cloudB = ModelRoute(
        provider: ProviderID(rawValue: "provider-b"),
        model: ModelID(rawValue: "model-b")
    )

    @Test("Only the exact committed route is selected")
    func exactCommittedRoute() {
        #expect(QuickChatCatalogPolicy.authoritativeSelectionIndex(
            routes: [local, cloudA, cloudB],
            committedRoute: cloudB,
            activeSessionRoute: nil
        ) == 2)
    }

    @Test("A missing or unreadable committed route never falls back to row zero")
    func missingCommittedRouteFailsClosed() {
        #expect(QuickChatCatalogPolicy.authoritativeSelectionIndex(
            routes: [cloudA, cloudB],
            committedRoute: local,
            activeSessionRoute: nil
        ) == nil)
        #expect(QuickChatCatalogPolicy.authoritativeSelectionIndex(
            routes: [cloudA, cloudB],
            committedRoute: nil,
            activeSessionRoute: nil
        ) == nil)
    }

    @Test("A continued History session outranks the default and never falls through")
    func activeSessionRouteIsAuthoritative() {
        #expect(QuickChatCatalogPolicy.authoritativeSelectionIndex(
            routes: [local, cloudA, cloudB],
            committedRoute: local,
            activeSessionRoute: cloudB
        ) == 2)
        #expect(QuickChatCatalogPolicy.authoritativeSelectionIndex(
            routes: [local, cloudA],
            committedRoute: local,
            activeSessionRoute: cloudB
        ) == nil)
    }

    @Test("Queued images survive only an explicitly image-capable route")
    func queuedImageCapability() {
        #expect(QuickChatCatalogPolicy.acceptsQueuedImages(inputModalities: [.text, .image]))
        #expect(!QuickChatCatalogPolicy.acceptsQueuedImages(inputModalities: [.text]))
        #expect(!QuickChatCatalogPolicy.acceptsQueuedImages(inputModalities: []))
        #expect(!QuickChatCatalogPolicy.acceptsQueuedImages(inputModalities: nil))
    }

    @Test("History preserves exact medium and xhigh effort until explicit change")
    func exactHistoryReasoningIsPreserved() {
        for effort in ["medium", "xhigh"] {
            let active = HarnessWireModelSelection(route: cloudA, reasoningEffort: effort)
            #expect(QuickChatReasoningPolicy.effort(
                choiceRoute: cloudA,
                activeSessionSelection: active,
                controlWasExplicitlyChanged: false,
                controlEnabled: true,
                advertisedEfforts: [
                    ReasoningEffortView(id: "medium", displayName: "Medium"),
                    ReasoningEffortView(id: "high", displayName: "High"),
                    ReasoningEffortView(id: "xhigh", displayName: "Extra High")
                ],
                storedSelection: ModelSelection(route: cloudA, reasoningEffort: "high")
            ) == effort)
        }
    }

    @Test("An explicit reasoning change uses this model's catalogue")
    func explicitReasoningChangeUsesAdvertisedChoice() {
        let active = HarnessWireModelSelection(route: cloudA, reasoningEffort: "medium")
        #expect(QuickChatReasoningPolicy.effort(
            choiceRoute: cloudA,
            activeSessionSelection: active,
            controlWasExplicitlyChanged: true,
            controlEnabled: true,
            advertisedEfforts: [
                ReasoningEffortView(id: "low", displayName: "Low"),
                ReasoningEffortView(id: "high", displayName: "High")
            ],
            storedSelection: ModelSelection(route: cloudA, reasoningEffort: "medium")
        ) == "high")
    }

    @Test("Reasoning never falls back to another route's stored effort")
    func unrelatedStoredEffortIsNotInherited() {
        #expect(QuickChatReasoningPolicy.effort(
            choiceRoute: cloudA,
            activeSessionSelection: HarnessWireModelSelection(route: cloudA, reasoningEffort: nil),
            controlWasExplicitlyChanged: true,
            controlEnabled: true,
            advertisedEfforts: [],
            storedSelection: ModelSelection(route: cloudB, reasoningEffort: "xhigh")
        ) == nil)
    }

    @Test("Unchecked reasoning sends an exact advertised off effort")
    func uncheckedReasoningUsesExactOff() {
        let efforts = [
            ReasoningEffortView(id: "off", displayName: "Off"),
            ReasoningEffortView(id: "high", displayName: "High")
        ]
        #expect(QuickChatReasoningPolicy.effort(
            choiceRoute: cloudA,
            activeSessionSelection: nil,
            controlWasExplicitlyChanged: false,
            controlEnabled: false,
            advertisedEfforts: efforts,
            storedSelection: ModelSelection(route: cloudA, reasoningEffort: "high")
        ) == "off")
        #expect(QuickChatReasoningPolicy.effort(
            choiceRoute: cloudA,
            activeSessionSelection: HarnessWireModelSelection(route: cloudA, reasoningEffort: "high"),
            controlWasExplicitlyChanged: true,
            controlEnabled: false,
            advertisedEfforts: efforts,
            storedSelection: ModelSelection(route: cloudA, reasoningEffort: "high")
        ) == "off")
    }
}
