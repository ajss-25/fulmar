import Foundation
import Testing
@testable import LocalHarness

private func disclosureSkill(_ name: String) -> InstalledSkill {
    InstalledSkill(
        name: name,
        description: "Reviewed test skill",
        fingerprint: String(repeating: "a", count: 64),
        sourceLabel: "Test fixture",
        fileCount: 1,
        totalBytes: 128,
        riskFlags: [],
        importedAt: Date(timeIntervalSince1970: 1)
    )
}

@Test func skillSessionDisclosurePresentationStripsInvisibleControlsAndBoundsNames() {
    let raw = "  Alpha\n\u{202E}hidden\u{2066}\t" + String(repeating: "x", count: 300)
    let presented = SkillSessionDisclosurePresentation.safeName(raw)

    #expect(presented.hasPrefix("Alpha hidden "))
    #expect(presented.count == SkillSessionDisclosurePresentation.maximumNameCharacters)
    #expect(!presented.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains))
    #expect(!presented.unicodeScalars.contains { $0.properties.generalCategory == .format })
    #expect(SkillSessionDisclosurePresentation.safeName("\u{202E}\n\t") == "Unnamed reviewed skill")
}

@Test func skillSessionDisclosurePromptShowsOnlyTheBoundedReviewedSubset() {
    let skills = (0..<17).map { disclosureSkill("Skill \($0)") }
    let prompt = SkillSessionDisclosurePresentation.prompt(for: skills)

    #expect(prompt.displayedNames == (0..<12).map { "Skill \($0)" })
    #expect(prompt.additionalCount == 5)
}

@MainActor
@Test func skillSessionDisclosureCoordinatorIsFailClosedAndOneSessionOnly() {
    var prompts: [SkillSessionDisclosurePrompt] = []
    var allow = false
    let interactions = SkillSessionDisclosureInteractions { prompt in
        prompts.append(prompt)
        return allow
    }

    #expect(SkillSessionDisclosureCoordinator.approvals(for: [], interactions: interactions).isEmpty)
    #expect(prompts.isEmpty)

    let skills = [disclosureSkill("First"), disclosureSkill("Second")]
    #expect(SkillSessionDisclosureCoordinator.approvals(for: skills, interactions: interactions).isEmpty)
    #expect(prompts.count == 1)

    allow = true
    #expect(
        SkillSessionDisclosureCoordinator.approvals(for: skills, interactions: interactions)
            == Set(["First", "Second"])
    )
    #expect(prompts.count == 2)

    // The coordinator returns a value for only this activation call; it keeps
    // no remembered approval that a later external session could inherit.
    allow = false
    #expect(SkillSessionDisclosureCoordinator.approvals(for: skills, interactions: interactions).isEmpty)
    #expect(prompts.count == 3)
}
