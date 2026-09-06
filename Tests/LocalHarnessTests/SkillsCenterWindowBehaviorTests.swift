import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct HostileSkillsCenterError: LocalizedError {
    var errorDescription: String? {
        "HOSTILE_SKILL_ERROR_CANARY /Users/private/skill-source"
    }
}

@MainActor
private final class SkillsCenterOperationProbe {
    struct PolicyState: Equatable {
        var enabled: Bool
        var disclosure: SkillCloudDisclosure
    }

    var skills: [InstalledSkill]
    var policies: [String: PolicyState] = [:]
    var inspection: SkillBundleInspection
    var importedSkill: InstalledSkill
    var findings: [SkillTrustFinding] = []
    var throwingActions: Set<String> = []
    var calls: [String: Int] = [:]
    var importCalls: [(URL, Bool)] = []
    var setPolicyCalls: [(String, String, Bool, SkillCloudDisclosure)] = []
    var onAction: ((String) -> Void)?

    init(skills: [InstalledSkill]) {
        self.skills = skills
        let initial = skills.first ?? skillsCenterInstalledSkill(name: "imported-probe")
        importedSkill = initial
        inspection = SkillBundleInspection(
            name: initial.name,
            description: initial.description,
            fingerprint: initial.fingerprint,
            sourceLabel: initial.sourceLabel,
            fileCount: initial.fileCount,
            totalBytes: initial.totalBytes,
            riskFlags: initial.riskFlags
        )
    }

    func count(_ action: String) -> Int { calls[action, default: 0] }

    func operations(basedOn store: SkillsTrustStore) -> SkillsCenterOperations {
        var value = SkillsCenterOperations(store: store)
        value.installedSkills = { [self] in
            recordWithoutThrowing("snapshot")
            return skills
        }
        value.policy = { [self] skillID, projectID in
            let state = policies[skillID] ?? PolicyState(enabled: false, disclosure: .localOnly)
            let fingerprint = skills.first(where: { $0.id == skillID })?.fingerprint ?? ""
            return SkillProjectPolicy(
                skillID: skillID,
                projectID: projectID,
                approvedFingerprint: fingerprint,
                enabled: state.enabled,
                cloudDisclosure: state.disclosure,
                updatedAt: Date(timeIntervalSince1970: 1_900_000_000)
            )
        }
        value.inspect = { [self] _ in
            try record("inspect")
            return inspection
        }
        value.importBundle = { [self] url, replacing in
            try record("import")
            importCalls.append((url, replacing))
            skills.removeAll { $0.id == importedSkill.id }
            skills.append(importedSkill)
            skills.sort { $0.name < $1.name }
            return importedSkill
        }
        value.remove = { [self] skillID in
            try record("remove")
            skills.removeAll { $0.id == skillID }
            policies.removeValue(forKey: skillID)
        }
        value.setPolicy = { [self] skillID, projectID, enabled, disclosure in
            try record("policy")
            setPolicyCalls.append((skillID, projectID, enabled, disclosure))
            policies[skillID] = PolicyState(enabled: enabled, disclosure: disclosure)
        }
        value.audit = { [self] in
            recordWithoutThrowing("audit")
            return findings
        }
        return value
    }

    private func record(_ action: String) throws {
        calls[action, default: 0] += 1
        onAction?(action)
        if throwingActions.contains(action) { throw HostileSkillsCenterError() }
    }

    private func recordWithoutThrowing(_ action: String) {
        calls[action, default: 0] += 1
        onAction?(action)
    }
}

@MainActor
private final class SkillsCenterInteractionProbe {
    var importSources: [URL?] = []
    var importConfirmations: [Bool] = []
    var removeConfirmations: [Bool] = []
    var disclosureConfirmations: [Bool] = []
    private(set) var importReviews: [(SkillBundleInspection, Bool)] = []
    private(set) var removePrompts: [String] = []
    private(set) var disclosurePrompts: [String] = []
    private(set) var audits: [SkillsAuditPresentation] = []
    private(set) var failures: [SkillsCenterFailure] = []

    var interactions: SkillsCenterInteractions {
        SkillsCenterInteractions(
            chooseImportSource: { [self] in
                importSources.isEmpty ? nil : importSources.removeFirst()
            },
            confirmImport: { [self] inspection, replacing in
                importReviews.append((inspection, replacing))
                return importConfirmations.isEmpty ? false : importConfirmations.removeFirst()
            },
            confirmRemove: { [self] skill in
                removePrompts.append(skill.id)
                return removeConfirmations.isEmpty ? false : removeConfirmations.removeFirst()
            },
            confirmExternalDisclosure: { [self] skill in
                disclosurePrompts.append(skill.id)
                return disclosureConfirmations.isEmpty ? false : disclosureConfirmations.removeFirst()
            },
            presentAudit: { [self] in audits.append($0) },
            showFailure: { [self] in failures.append($0) }
        )
    }
}

@MainActor
private final class SkillsApplyGate {
    private(set) var boundaries: [SkillExecutionBoundary] = []
    private var continuations: [CheckedContinuation<Void, Error>?] = []

    func run(_ boundary: SkillExecutionBoundary) async throws {
        boundaries.append(boundary)
        try await withCheckedThrowingContinuation { continuation in
            continuations.append(continuation)
        }
    }

    func succeed(_ index: Int) {
        guard continuations.indices.contains(index), let continuation = continuations[index] else { return }
        continuations[index] = nil
        continuation.resume()
    }

    func fail(_ index: Int) {
        guard continuations.indices.contains(index), let continuation = continuations[index] else { return }
        continuations[index] = nil
        continuation.resume(throwing: HostileSkillsCenterError())
    }
}

private enum SkillsCenterBehaviorTimeout: Error { case timedOut }

@MainActor
private func skillsCenterEventually(
    attempts: Int = 300,
    _ condition: @escaping @MainActor () async -> Bool
) async throws {
    for _ in 0..<attempts {
        if await condition() { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    throw SkillsCenterBehaviorTimeout.timedOut
}

private func skillsCenterInstalledSkill(
    name: String,
    fingerprint: String? = nil,
    riskFlags: [SkillRiskFlag] = [],
    description: String? = nil
) -> InstalledSkill {
    InstalledSkill(
        name: name,
        description: description ?? "Reviewed behavior probe for \(name).",
        fingerprint: fingerprint ?? String(repeating: name.first ?? "a", count: 64),
        sourceLabel: "SkillSource",
        fileCount: 2,
        totalBytes: 1_024,
        riskFlags: riskFlags,
        importedAt: Date(timeIntervalSince1970: 1_900_000_000)
    )
}

@MainActor
private func skillsCenterDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(skillsCenterDescendants(of:))
}

@MainActor
private func skillsCenterButton(_ title: String, in root: NSView) throws -> NSButton {
    try #require(skillsCenterDescendants(of: root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func skillsCenterTable(in root: NSView) throws -> NSTableView {
    try #require(skillsCenterDescendants(of: root).compactMap { $0 as? NSTableView }.first)
}

@MainActor
private func skillsCenterDisclosure(in root: NSView) throws -> NSPopUpButton {
    try #require(skillsCenterDescendants(of: root).compactMap { $0 as? NSPopUpButton }.first {
        $0.accessibilityLabel() == "External model disclosure"
    })
}

@MainActor
private func skillsCenterStatus(in root: NSView) throws -> NSTextField {
    try #require(skillsCenterDescendants(of: root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == "Skills status"
    })
}

@MainActor
private func skillsCenterPolicyExplanation(in root: NSView) throws -> NSTextField {
    try #require(skillsCenterDescendants(of: root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == "Skill policy explanation"
    })
}

@MainActor
private func invokeSkillsControlIgnoringEnabled(_ control: NSControl) throws {
    let action = try #require(control.action)
    #expect(NSApplication.shared.sendAction(action, to: control.target, from: control))
}

@MainActor
private func skillsCenterFixture() throws -> (SkillsTrustStore, URL, () -> Void) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarSkillsCenterBehavior-\(UUID().uuidString)", isDirectory: true)
    let support = root.appendingPathComponent("Support", isDirectory: true)
    let harness = root.appendingPathComponent("Harness", isDirectory: true)
    let project = root.appendingPathComponent("Project", isDirectory: true)
    try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
    let store = try SkillsTrustStore(applicationSupport: support, harnessHome: harness)
    return (store, project, { try? FileManager.default.removeItem(at: root) })
}

@MainActor
private func makeSkillsController(
    probe: SkillsCenterOperationProbe,
    interactions: SkillsCenterInteractionProbe,
    boundary: @escaping () -> SkillExecutionBoundary = { .local }
) throws -> (SkillsCenterWindowController, () -> Void) {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let (store, project, cleanup) = try skillsCenterFixture()
    let controller = SkillsCenterWindowController(
        operations: probe.operations(basedOn: store),
        projectURL: project,
        currentBoundary: boundary,
        interactions: interactions.interactions
    )
    return (controller, cleanup)
}

@Suite(.serialized)
struct SkillsCenterWindowBehaviorTests {
    @Test @MainActor func emptyStateAndVerifyUseRealControlsAndTypedPresentation() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = SkillsCenterOperationProbe(skills: [])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let verify = try skillsCenterButton("Verify All", in: root)

        verify.performClick(nil)

        #expect(probe.count("audit") == 1)
        #expect(interactions.audits == [SkillsAuditPresentation(outcome: .empty, problemSummaries: [])])
        #expect(try skillsCenterStatus(in: root).stringValue == "There are no imported skills to verify.")
        #expect(try skillsCenterButton("Import & Review…", in: root).isEnabled)
        for title in ["Enable for this workspace", "Remove", "Apply & Restart"] {
            #expect(try !skillsCenterButton(title, in: root).isEnabled)
        }
    }

    @Test @MainActor func importCancelReviewCancelSuccessAndReplacementAreExact() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let imported = skillsCenterInstalledSkill(name: "imported-probe")
        let probe = SkillsCenterOperationProbe(skills: [])
        probe.importedSkill = imported
        probe.inspection = SkillBundleInspection(
            name: imported.name,
            description: imported.description,
            fingerprint: imported.fingerprint,
            sourceLabel: imported.sourceLabel,
            fileCount: imported.fileCount,
            totalBytes: imported.totalBytes,
            riskFlags: [.containsScript]
        )
        let interactions = SkillsCenterInteractionProbe()
        let source = URL(fileURLWithPath: "/private/import-probe")
        interactions.importSources = [nil, source, source, source]
        interactions.importConfirmations = [false, true, true]
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let button = try skillsCenterButton("Import & Review…", in: root)

        button.performClick(nil)
        #expect(probe.count("inspect") == 0)
        button.performClick(nil)
        #expect(probe.count("inspect") == 1)
        #expect(probe.count("import") == 0)
        button.performClick(nil)
        #expect(probe.count("import") == 1)
        #expect(probe.importCalls.first?.1 == false)
        #expect(try skillsCenterTable(in: root).numberOfRows == 1)
        #expect(try skillsCenterButton("Apply & Restart", in: root).isEnabled)
        button.performClick(nil)
        #expect(probe.count("import") == 2)
        #expect(probe.importCalls.last?.1 == true)
        #expect(interactions.importReviews.map(\.1) == [false, false, true])
    }

    @Test @MainActor func importFailuresAreAppOwnedSingleFlightAndRestoreControls() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let probe = SkillsCenterOperationProbe(skills: [])
        let interactions = SkillsCenterInteractionProbe()
        let source = URL(fileURLWithPath: "/private/import-failure")
        interactions.importSources = [source, source]
        interactions.importConfirmations = [true]
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let button = try skillsCenterButton("Import & Review…", in: root)

        probe.throwingActions.insert("inspect")
        probe.onAction = { action in
            if action == "inspect" { try? invokeSkillsControlIgnoringEnabled(button) }
        }
        button.performClick(nil)
        #expect(probe.count("inspect") == 1)
        #expect(interactions.failures == [.importSkill])
        #expect(button.isEnabled)

        probe.onAction = nil
        probe.throwingActions.remove("inspect")
        probe.throwingActions.insert("import")
        button.performClick(nil)
        #expect(probe.count("import") == 1)
        #expect(interactions.failures == [.importSkill, .importSkill])
        #expect(button.isEnabled)
        #expect(!SkillsCenterFailure.importSkill.message.contains("HOSTILE_SKILL_ERROR_CANARY"))
    }

    @Test @MainActor func enableDisableAndDisclosurePoliciesPersistExactChoices() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "policy-probe")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let enabled = try skillsCenterButton("Enable for this workspace", in: root)
        let disclosure = try skillsCenterDisclosure(in: root)

        enabled.performClick(nil)
        #expect(probe.policies[skill.id] == .init(enabled: true, disclosure: .localOnly))
        #expect(disclosure.isEnabled)
        #expect(try skillsCenterPolicyExplanation(in: root).stringValue.contains("local models only"))

        disclosure.selectItem(at: 1)
        try invokeSkillsControlIgnoringEnabled(disclosure)
        #expect(probe.policies[skill.id] == .init(enabled: true, disclosure: .askEveryTime))
        #expect(try skillsCenterPolicyExplanation(in: root).stringValue.contains("asks whether"))

        enabled.performClick(nil)
        #expect(probe.policies[skill.id] == .init(enabled: false, disclosure: .askEveryTime))
        #expect(!disclosure.isEnabled)
        #expect(try skillsCenterPolicyExplanation(in: root).stringValue.contains("invisible"))
        #expect(try skillsCenterButton("Apply & Restart", in: root).isEnabled)
        #expect(probe.setPolicyCalls.allSatisfy { $0.1.count == 64 })
    }

    @Test @MainActor func allowedExternalDisclosureRequiresConsentAndCancellationFallsBackLocal() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "cloud-policy")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        probe.policies[skill.id] = .init(enabled: true, disclosure: .localOnly)
        let interactions = SkillsCenterInteractionProbe()
        interactions.disclosureConfirmations = [false, true]
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let disclosure = try skillsCenterDisclosure(in: root)

        disclosure.selectItem(at: 2)
        try invokeSkillsControlIgnoringEnabled(disclosure)
        #expect(probe.policies[skill.id] == .init(enabled: true, disclosure: .localOnly))
        #expect(disclosure.indexOfSelectedItem == 0)

        disclosure.selectItem(at: 2)
        try invokeSkillsControlIgnoringEnabled(disclosure)
        #expect(probe.policies[skill.id] == .init(enabled: true, disclosure: .allowed))
        #expect(interactions.disclosurePrompts == [skill.id, skill.id])

        disclosure.selectItem(at: 2)
        try invokeSkillsControlIgnoringEnabled(disclosure)
        #expect(interactions.disclosurePrompts == [skill.id, skill.id])
        #expect(try skillsCenterPolicyExplanation(in: root).stringValue.contains("external models"))
    }

    @Test @MainActor func policyFailureRestoresLastPersistedStateWithoutRawError() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "failed-policy")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        probe.throwingActions.insert("policy")
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let enabled = try skillsCenterButton("Enable for this workspace", in: root)

        enabled.performClick(nil)

        #expect(probe.count("policy") == 1)
        #expect(interactions.failures == [.savePolicy])
        #expect(enabled.state == .off)
        #expect(enabled.isEnabled)
        #expect(try !skillsCenterButton("Apply & Restart", in: root).isEnabled)
        #expect(!SkillsCenterFailure.savePolicy.message.contains("HOSTILE_SKILL_ERROR_CANARY"))
    }

    @Test @MainActor func verifyBoundsAndSanitizesHostileFindings() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "verified-skill")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let verify = try skillsCenterButton("Verify All", in: root)

        probe.findings = [SkillTrustFinding(
            id: skill.id,
            status: .trusted,
            expectedFingerprint: skill.fingerprint,
            observedFingerprint: skill.fingerprint,
            detail: "Fingerprint verified."
        )]
        verify.performClick(nil)
        #expect(interactions.audits.last == SkillsAuditPresentation(outcome: .trusted, problemSummaries: []))

        probe.findings = (0..<25).map { index in
            SkillTrustFinding(
                id: index == 0 ? skill.id : "HOSTILE_UNKNOWN_SKILL_\(index)",
                status: index.isMultiple(of: 2) ? .modified : .invalid,
                expectedFingerprint: nil,
                observedFingerprint: nil,
                detail: "HOSTILE_AUDIT_DETAIL_CANARY /Users/private/\(index)"
            )
        }
        verify.performClick(nil)
        let audit = try #require(interactions.audits.last)
        #expect(audit.outcome == .attention)
        #expect(audit.problemSummaries.count == 20)
        #expect(audit.problemSummaries.first?.contains(skill.id) == true)
        #expect(audit.problemSummaries.dropFirst().allSatisfy { $0.hasPrefix("Imported skill:") })
        #expect(audit.problemSummaries.allSatisfy { !$0.contains("HOSTILE_AUDIT_DETAIL_CANARY") })
        #expect(try skillsCenterStatus(in: root).stringValue == "Changed or invalid skills will remain unavailable.")
    }

    @Test @MainActor func removeCancelFailureAndSuccessPreserveSelectionAndRejectReentry() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let first = skillsCenterInstalledSkill(name: "alpha")
        let second = skillsCenterInstalledSkill(name: "beta")
        let probe = SkillsCenterOperationProbe(skills: [first, second])
        let interactions = SkillsCenterInteractionProbe()
        interactions.removeConfirmations = [false, true, true]
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try skillsCenterTable(in: root)
        let remove = try skillsCenterButton("Remove", in: root)

        remove.performClick(nil)
        #expect(probe.count("remove") == 0)
        probe.throwingActions.insert("remove")
        probe.onAction = { action in
            if action == "remove" { try? invokeSkillsControlIgnoringEnabled(remove) }
        }
        remove.performClick(nil)
        #expect(probe.count("remove") == 1)
        #expect(interactions.failures == [.removeSkill])
        #expect(table.selectedRow == 0)
        #expect(remove.isEnabled)

        probe.onAction = nil
        probe.throwingActions.remove("remove")
        remove.performClick(nil)
        #expect(probe.count("remove") == 2)
        #expect(table.numberOfRows == 1)
        #expect(probe.skills == [second])
        #expect(table.selectedRow == 0)
        #expect(try skillsCenterStatus(in: root).stringValue.contains("alpha was removed"))
    }

    @Test @MainActor func showWindowReloadPreservesSelectionByStableSkillIDAcrossReordering() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let first = skillsCenterInstalledSkill(name: "alpha")
        let second = skillsCenterInstalledSkill(name: "beta")
        let probe = SkillsCenterOperationProbe(skills: [first, second])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        let table = try skillsCenterTable(in: root)
        table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
        probe.skills = [second, first]

        controller.showWindow(nil)

        #expect(table.selectedRow == 0)
        #expect(probe.skills[table.selectedRow].id == second.id)
    }

    @Test @MainActor func applyWithoutProtectedCoordinatorFailsClosedAndRemainsRetryable() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "missing-coordinator")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        try skillsCenterButton("Enable for this workspace", in: root).performClick(nil)
        let apply = try skillsCenterButton("Apply & Restart", in: root)

        apply.performClick(nil)

        #expect(try skillsCenterStatus(in: root).stringValue == "Skills were not applied because protected runtime coordination is unavailable.")
        #expect(apply.isEnabled)
        #expect(try skillsCenterButton("Import & Review…", in: root).isEnabled)
    }

    @Test @MainActor func applyIsSingleFlightSurvivesCloseReopenAndAcceptsLateSuccess() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "apply-success")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(
            probe: probe,
            interactions: interactions,
            boundary: { .external }
        )
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        try skillsCenterButton("Enable for this workspace", in: root).performClick(nil)
        let apply = try skillsCenterButton("Apply & Restart", in: root)
        let gate = SkillsApplyGate()
        controller.onApplyAndRestart = { boundary in try await gate.run(boundary) }

        apply.performClick(nil)
        try await skillsCenterEventually { gate.boundaries.count == 1 }
        #expect(gate.boundaries == [.external])
        #expect(!apply.isEnabled)
        #expect(try !skillsCenterButton("Import & Review…", in: root).isEnabled)
        #expect(try !skillsCenterButton("Verify All", in: root).isEnabled)
        #expect(try !skillsCenterTable(in: root).isEnabled)
        try invokeSkillsControlIgnoringEnabled(apply)
        #expect(gate.boundaries.count == 1)

        let snapshotsBeforeReopen = probe.count("snapshot")
        controller.close()
        controller.showWindow(nil)
        #expect(!apply.isEnabled)
        #expect(probe.count("snapshot") == snapshotsBeforeReopen)
        gate.succeed(0)
        try await skillsCenterEventually {
            (try? skillsCenterStatus(in: root).stringValue.contains("active in a fresh")) == true
                && !apply.isEnabled
        }
        #expect(try skillsCenterButton("Import & Review…", in: root).isEnabled)
        #expect(try skillsCenterTable(in: root).isEnabled)
    }

    @Test @MainActor func applyFailureIsAppOwnedKeepsDirtyStateAndCanRetry() async throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(name: "apply-failure")
        let probe = SkillsCenterOperationProbe(skills: [skill])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let root = try #require(controller.window?.contentViewController?.view)
        try skillsCenterButton("Enable for this workspace", in: root).performClick(nil)
        let apply = try skillsCenterButton("Apply & Restart", in: root)
        var attempts = 0
        controller.onApplyAndRestart = { _ in
            attempts += 1
            if attempts == 1 { throw HostileSkillsCenterError() }
        }

        apply.performClick(nil)
        try await skillsCenterEventually {
            (try? skillsCenterStatus(in: root).stringValue.contains("previous active catalog")) == true
                && apply.isEnabled
        }
        #expect(!((try skillsCenterStatus(in: root).stringValue).contains("HOSTILE_SKILL_ERROR_CANARY")))

        apply.performClick(nil)
        try await skillsCenterEventually { attempts == 2 && !apply.isEnabled }
        #expect(try skillsCenterStatus(in: root).stringValue.contains("active in a fresh"))
    }

    @Test @MainActor func minimumWindowKeepsAllActionsAccessibleInLightAndDark() throws {
        ensureAppKitTestHostSurvivesAutomaticTermination()
        let skill = skillsCenterInstalledSkill(
            name: "layout-skill",
            riskFlags: [.containsBinaryResource],
            description: "Visible\u{202E}\0\nreviewed description"
        )
        let probe = SkillsCenterOperationProbe(skills: [skill])
        let interactions = SkillsCenterInteractionProbe()
        let (controller, cleanup) = try makeSkillsController(probe: probe, interactions: interactions)
        defer { controller.close(); cleanup() }
        let window = try #require(controller.window)
        let root = try #require(window.contentView)
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)

        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearance)
            window.layoutIfNeeded()
            root.layoutSubtreeIfNeeded()
            for title in ["Import & Review…", "Verify All", "Enable for this workspace", "Remove", "Apply & Restart"] {
                let button = try skillsCenterButton(title, in: root)
                let frame = button.convert(button.bounds, to: root)
                #expect(root.bounds.insetBy(dx: -0.5, dy: -0.5).contains(frame))
                #expect(button.target != nil)
                #expect(button.action != nil)
            }
            let disclosure = try skillsCenterDisclosure(in: root)
            #expect(disclosure.target != nil)
            #expect(disclosure.action != nil)
            #expect(try skillsCenterStatus(in: root).accessibilityLabel() == "Skills status")
            #expect(try skillsCenterPolicyExplanation(in: root).accessibilityLabel() == "Skill policy explanation")
            let description = try #require(skillsCenterDescendants(of: root).compactMap { $0 as? NSTextField }.first {
                $0.accessibilityLabel() == "Skill description"
            })
            #expect(description.stringValue == "Visible reviewed description")
            #expect(!description.stringValue.contains("\u{202E}"))
        }
    }
}
