import Foundation
import Testing
@testable import LocalHarness

private let hostilePresentationSecret = "sk-presentation-secret-123456789"

@Test
func checkpointFailureDropsHostileLegacyDetailDuringConstructionAndDecode() throws {
    let hostile = "api_key=\(hostilePresentationSecret) /Users/private/checkpoint \u{202E}\u{0007}" +
        String(repeating: "HOSTILE-CHECKPOINT-DIAGNOSTIC", count: 4_000)

    let constructed = ScheduleResultFailure(code: .checkpointFailed, detail: hostile)
    #expect(constructed.detail == nil)
    #expect(constructed.displayMessage == "A recovery point could not be created, so the task did not run.")

    let payload = try JSONSerialization.data(withJSONObject: [
        "code": "checkpointFailed",
        "detail": hostile
    ])
    let decoded = try JSONDecoder().decode(ScheduleResultFailure.self, from: payload)
    #expect(decoded.detail == nil)
    #expect(!decoded.displayMessage.contains(hostilePresentationSecret))
    #expect(!decoded.displayMessage.contains("/Users/private"))
    #expect(!decoded.displayMessage.contains("\u{202E}"))
    #expect(decoded.displayMessage.count < 200)
}

@Test @MainActor
func workspaceAndMCPPathLabelsSanitizeSecretsHomeControlsBidiAndOversizeText() {
    let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL
    let hostileComponent = "api_key=\(hostilePresentationSecret)\u{202E}\u{0007}" +
        String(repeating: "HOSTILE-PATH-DIAGNOSTIC", count: 4_000)
    let url = home.appendingPathComponent(hostileComponent, isDirectory: true)

    let workspaceName = WorkspaceRecoveryWindowController.safeWorkspaceName(url)
    let projectName = MCPCenterWindowController.safeProjectName(url)
    for value in [workspaceName, projectName] {
        #expect(!value.contains(hostilePresentationSecret))
        #expect(!value.contains(home.path))
        #expect(!value.contains("\u{202E}"))
        #expect(!value.contains("\u{0007}"))
        #expect(value.hasSuffix("…"))
        #expect(value.count <= 180)
    }
    #expect(workspaceName.count <= 180)
    #expect(projectName.count <= 180)

    let nested = home.appendingPathComponent("PrivateParent/ApprovedProject", isDirectory: true)
    #expect(WorkspaceRecoveryWindowController.safeWorkspaceName(nested) == "ApprovedProject")
    #expect(MCPCenterWindowController.safeProjectName(nested) == "ApprovedProject")
    #expect(!WorkspaceRecoveryWindowController.safeWorkspaceName(nested).contains("PrivateParent"))
    #expect(!MCPCenterWindowController.safeProjectName(nested).contains("PrivateParent"))
}
