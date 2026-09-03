import Darwin
import Foundation
import Testing
@testable import LocalHarness

private struct MCPTestFixture {
    let root: URL
    let support: URL
    let project: URL
    let bin: URL
    let executable: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("mcp-trust-\(UUID().uuidString)", isDirectory: true)
        support = root.appendingPathComponent("Support", isDirectory: true)
        project = root.appendingPathComponent("Project", isDirectory: true)
        bin = root.appendingPathComponent("bin", isDirectory: true)
        executable = bin.appendingPathComponent("mcp-server")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }

    func draft(
        id: String = "safe-local",
        serverName: String = "safe_local",
        executablePath: String? = nil,
        arguments: [String] = ["--stdio"],
        reviewedFileArgumentIndexes: [Int] = [],
        workingDirectory: String? = nil,
        environment: [MCPEnvironmentBinding] = [],
        providers: [MCPProviderEnablement] = [
            MCPProviderEnablement(provider: ProviderID("ollama"), boundary: .onDevice)
        ],
        disclosure: MCPDisclosureProfile = MCPDisclosureProfile(
            boundary: .onDevice,
            dataKinds: [.toolArguments, .toolResults]
        ),
        limits: MCPExecutionLimits = .default
    ) -> MCPServerDraft {
        MCPServerDraft(
            id: id,
            displayName: "Safe Local Server",
            serverName: serverName,
            executablePath: executablePath ?? executable.path,
            arguments: arguments,
            reviewedFileArgumentIndexes: reviewedFileArgumentIndexes,
            projectRelativeWorkingDirectory: workingDirectory,
            environment: environment,
            allowedProviders: providers,
            disclosure: disclosure,
            limits: limits
        )
    }
}

private final class MCPBudgetClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 0
    private let step: UInt64

    init(step: UInt64) { self.step = step }

    func read() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let current = value
        value &+= step
        return current
    }
}

@Test func mcpLaunchRevalidationPropagatesSharedCancellationAndDeadlineWithoutRevokingTrust() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    _ = try store.saveDraft(fixture.draft(), projectRoot: fixture.project)
    _ = try store.approve(id: "safe-local")
    let context = MCPActivationContext(
        projectRoot: fixture.project,
        provider: ProviderID("ollama"),
        providerBoundary: .onDevice
    )

    let cancellation = RuntimeStartupPrerequisiteCancellation()
    cancellation.cancel()
    let cancelledBudget = RuntimeStartupPrerequisiteBudget(
        cancellation: cancellation,
        duration: 60
    )
    #expect(throws: RuntimeStartupPrerequisiteError.cancelled) {
        _ = try MCPActivationCatalogBuilder.revalidatedPlans(
            store: store,
            context: context,
            preparationBudget: cancelledBudget
        )
    }
    #expect(store.record(id: "safe-local")?.approval != nil)

    let liveCancellation = RuntimeStartupPrerequisiteCancellation()
    let clock = MCPBudgetClock(step: 2_000_000_000)
    let expiredBudget = RuntimeStartupPrerequisiteBudget(
        cancellation: liveCancellation,
        duration: 1,
        now: { clock.read() }
    )
    #expect(throws: RuntimeStartupPrerequisiteError.timedOut) {
        _ = try MCPActivationCatalogBuilder.revalidatedPlans(
            store: store,
            context: context,
            preparationBudget: expiredBudget
        )
    }
    #expect(store.record(id: "safe-local")?.approval != nil)
}

@Test func mcpApprovalProducesSecretFreeDSHActivationPlan() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let draft = fixture.draft()

    let saved = try store.saveDraft(draft, projectRoot: fixture.project)
    #expect(saved.approval == nil)
    #expect(try store.status(id: draft.id) == .unreviewed)
    let approved = try store.approve(id: draft.id)
    #expect(approved.approval != nil)
    #expect(try store.status(id: draft.id) == .trusted)

    let plan = try store.activationPlan(
        id: draft.id,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("ollama"),
            providerBoundary: .onDevice
        )
    )
    #expect(plan.dsh.packageName == "@deepseek-ai/dsh-mcp-client")
    #expect(plan.dsh.transport == .stdio)
    #expect(plan.dsh.command == plan.executable.canonicalPath)
    #expect(plan.dsh.arguments == ["--stdio"])
    #expect(plan.dsh.failOnStartupError)
    #expect(plan.dsh.toolCallTimeoutMilliseconds == 30_000)
    #expect(plan.wrapper.startupTimeoutMilliseconds == 30_000)
    #expect(plan.wrapper.maximumDiscoveredTools == 32)
    #expect(plan.wrapper.maximumOutputBytes == 1_048_576)
    #expect(!plan.wrapper.inheritAmbientEnvironment)
    #expect(!plan.disclosure.sendsToolMaterialOffDevice)
}

@Test func mcpLaunchCatalogIncludesOnlyRevalidatedRecordsForTheExactBoundary() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    _ = try store.saveDraft(fixture.draft(), projectRoot: fixture.project)
    _ = try store.approve(id: "safe-local")
    _ = try store.saveDraft(
        fixture.draft(id: "unreviewed", serverName: "unreviewed"),
        projectRoot: fixture.project
    )

    let local = try MCPActivationCatalogBuilder.revalidatedPlans(
        store: store,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("ollama"),
            providerBoundary: .onDevice
        )
    )
    #expect(local.map(\.serverID) == ["safe-local"])

    let otherProvider = try MCPActivationCatalogBuilder.revalidatedPlans(
        store: store,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("deepseek"),
            providerBoundary: .cloud
        )
    )
    #expect(otherProvider.isEmpty)
    #expect(store.record(id: "safe-local")?.approval != nil)

    let handle = try FileHandle(forWritingTo: fixture.executable)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("tampered".utf8))
    try handle.close()
    let afterTamper = try MCPActivationCatalogBuilder.revalidatedPlans(
        store: store,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("ollama"),
            providerBoundary: .onDevice
        )
    )
    #expect(afterTamper.isEmpty)
    #expect(store.record(id: "safe-local")?.approval == nil)
}

@Test func mcpCredentialEnvironmentPersistsReferencesNeverValues() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let draft = fixture.draft(
        id: "github-cloud",
        serverName: "github",
        environment: [
            MCPEnvironmentBinding(
                variableName: "GITHUB_TOKEN",
                credential: CredentialReference("GITHUB_TOKEN")
            )
        ],
        providers: [
            MCPProviderEnablement(provider: ProviderID("deepseek"), boundary: .cloud)
        ],
        disclosure: MCPDisclosureProfile(
            boundary: .onDevice,
            dataKinds: [.authenticationMetadata, .accountData, .toolArguments, .toolResults]
        )
    )
    _ = try store.saveDraft(draft, projectRoot: fixture.project)
    _ = try store.approve(id: draft.id)
    let plan = try store.activationPlan(
        id: draft.id,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("deepseek"),
            providerBoundary: .cloud
        )
    )
    #expect(plan.dsh.environment == [
        MCPDSHEnvironmentReference(variableName: "GITHUB_TOKEN", credential: CredentialReference("GITHUB_TOKEN"))
    ])
    #expect(plan.disclosure.sendsToolMaterialOffDevice)

    let state = try Data(contentsOf: fixture.support.appendingPathComponent("Security/\(MCPTrustStore.stateFilename)"))
    let text = try #require(String(data: state, encoding: .utf8))
    #expect(text.contains("GITHUB_TOKEN"))
    #expect(!text.contains("super-secret-value"))
}

@Test func mcpExecutableMutationRevokesPersistedTrust() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let draft = fixture.draft()
    _ = try store.saveDraft(draft, projectRoot: fixture.project)
    _ = try store.approve(id: draft.id)

    let handle = try FileHandle(forWritingTo: fixture.executable)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("changed".utf8))
    try handle.close()

    #expect(try store.status(id: draft.id) == .changed)
    #expect(store.record(id: draft.id)?.approval == nil)
    #expect(throws: MCPTrustStoreError.self) {
        try store.activationPlan(
            id: draft.id,
            context: MCPActivationContext(
                projectRoot: fixture.project,
                provider: ProviderID("ollama"),
                providerBoundary: .onDevice
            )
        )
    }
}

@Test func mcpSymlinkRetargetRevokesTrust() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let replacement = fixture.bin.appendingPathComponent("replacement")
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/false"), to: replacement)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: replacement.path)
    let link = fixture.bin.appendingPathComponent("selected-server")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fixture.executable)

    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let draft = fixture.draft(executablePath: link.path)
    _ = try store.saveDraft(draft, projectRoot: fixture.project)
    _ = try store.approve(id: draft.id)
    try FileManager.default.removeItem(at: link)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: replacement)

    #expect(throws: MCPTrustStoreError.self) {
        try store.activationPlan(
            id: draft.id,
            context: MCPActivationContext(
                projectRoot: fixture.project,
                provider: ProviderID("ollama"),
                providerBoundary: .onDevice
            )
        )
    }
    #expect(store.record(id: draft.id)?.approval == nil)
}

@Test func mcpRuntimeEntrypointIsFingerprintBound() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let runtime = fixture.bin.appendingPathComponent("node")
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: runtime)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: runtime.path)
    let entrypoint = fixture.bin.appendingPathComponent("server.mjs")
    try Data("export {};".utf8).write(to: entrypoint)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: entrypoint.path)

    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let draft = fixture.draft(
        executablePath: runtime.path,
        arguments: [entrypoint.path, "--stdio"],
        reviewedFileArgumentIndexes: [0]
    )
    _ = try store.saveDraft(draft, projectRoot: fixture.project)
    _ = try store.approve(id: draft.id)
    let original = try store.activationPlan(
        id: draft.id,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("ollama"),
            providerBoundary: .onDevice
        )
    )
    #expect(original.reviewedArgumentFiles.map(\.argumentIndex) == [0])

    try Data("export const changed = true;".utf8).write(to: entrypoint)
    #expect(throws: MCPTrustStoreError.self) {
        try store.activationPlan(
            id: draft.id,
            context: MCPActivationContext(
                projectRoot: fixture.project,
                provider: ProviderID("ollama"),
                providerBoundary: .onDevice
            )
        )
    }
}

@Test func mcpRuntimeRequiresExplicitEntrypointReview() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let runtime = fixture.bin.appendingPathComponent("node")
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: runtime)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: runtime.path)
    let entrypoint = fixture.bin.appendingPathComponent("server.mjs")
    try Data("export {};".utf8).write(to: entrypoint)
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(executablePath: runtime.path, arguments: [entrypoint.path]),
            projectRoot: fixture.project
        )
    }
}

@Test func mcpRejectsRelativeCodeBearingArguments() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let runtime = fixture.bin.appendingPathComponent("node")
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: runtime)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: runtime.path)
    let store = try MCPTrustStore(applicationSupport: fixture.support)

    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(
                executablePath: runtime.path,
                arguments: ["server.mjs"],
                reviewedFileArgumentIndexes: []
            ),
            projectRoot: fixture.project
        )
    }
}

@Test func mcpRejectsShellAndEnvironmentSelectedScripts() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(fixture.draft(executablePath: "/bin/sh"), projectRoot: fixture.project)
    }

    let script = fixture.bin.appendingPathComponent("dynamic-server")
    try Data("#!/usr/bin/env node\n".utf8).write(to: script)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(fixture.draft(executablePath: script.path), projectRoot: fixture.project)
    }
}

@Test func mcpRejectsSecretsAndProcessInjectionEnvironment() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let disclosure = MCPDisclosureProfile(
        boundary: .onDevice,
        dataKinds: [.authenticationMetadata, .toolArguments]
    )
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(
                arguments: ["--token", "not-safe"],
                disclosure: disclosure
            ),
            projectRoot: fixture.project
        )
    }
    for variableName in ["LANG", "LOGNAME", "USER", "LOCAL_HARNESS_MCP_GUARD_PLAN"] {
        #expect(throws: MCPTrustStoreError.self) {
            try store.saveDraft(
                fixture.draft(
                    environment: [
                        MCPEnvironmentBinding(
                            variableName: variableName,
                            credential: CredentialReference("GITHUB_TOKEN")
                        )
                    ],
                    disclosure: disclosure
                ),
                projectRoot: fixture.project
            )
        }
    }
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(
                environment: [
                    MCPEnvironmentBinding(variableName: "NODE_OPTIONS", credential: CredentialReference("GITHUB_TOKEN"))
                ],
                disclosure: disclosure
            ),
            projectRoot: fixture.project
        )
    }
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(
                environment: [
                    MCPEnvironmentBinding(variableName: "GITHUB_TOKEN", credential: CredentialReference("literal secret"))
                ],
                disclosure: disclosure
            ),
            projectRoot: fixture.project
        )
    }
}

@Test func mcpActivationIsProjectAndProviderBound() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let otherProject = fixture.root.appendingPathComponent("OtherProject", isDirectory: true)
    try FileManager.default.createDirectory(at: otherProject, withIntermediateDirectories: true)
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    let draft = fixture.draft()
    _ = try store.saveDraft(draft, projectRoot: fixture.project)
    _ = try store.approve(id: draft.id)

    #expect(throws: MCPTrustStoreError.self) {
        try store.activationPlan(
            id: draft.id,
            context: MCPActivationContext(
                projectRoot: otherProject,
                provider: ProviderID("ollama"),
                providerBoundary: .onDevice
            )
        )
    }
    #expect(store.record(id: draft.id)?.approval != nil)
    #expect(throws: MCPTrustStoreError.self) {
        try store.activationPlan(
            id: draft.id,
            context: MCPActivationContext(
                projectRoot: fixture.project,
                provider: ProviderID("deepseek"),
                providerBoundary: .cloud
            )
        )
    }
    #expect(store.record(id: draft.id)?.approval != nil)

    let cloudDraft = fixture.draft(
        id: "cloud-model",
        serverName: "cloud_model",
        providers: [
            MCPProviderEnablement(provider: ProviderID("deepseek"), boundary: .cloud)
        ]
    )
    _ = try store.saveDraft(cloudDraft, projectRoot: fixture.project)
    _ = try store.approve(id: cloudDraft.id)
    let cloudPlan = try store.activationPlan(
        id: cloudDraft.id,
        context: MCPActivationContext(
            projectRoot: fixture.project,
            provider: ProviderID("deepseek"),
            providerBoundary: .cloud
        )
    )
    #expect(cloudPlan.disclosure.mcpServer.boundary == .onDevice)
    #expect(cloudPlan.disclosure.modelProvider == ProviderID("deepseek"))
    #expect(cloudPlan.disclosure.modelBoundary == .cloud)
    #expect(cloudPlan.disclosure.sendsToolMaterialOffDevice)
    #expect(throws: MCPTrustStoreError.self) {
        try store.activationPlan(
            id: cloudDraft.id,
            context: MCPActivationContext(
                projectRoot: fixture.project,
                provider: ProviderID("deepseek"),
                providerBoundary: .localNetwork
            )
        )
    }
}

@Test func mcpWorkingDirectoryCannotEscapeProjectThroughSymlink() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let outside = fixture.root.appendingPathComponent("Outside", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(
        at: fixture.project.appendingPathComponent("escape"),
        withDestinationURL: outside
    )
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(workingDirectory: "escape"),
            projectRoot: fixture.project
        )
    }
}

@Test func mcpLimitsAndCloudDisclosureFailClosed() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(
                limits: MCPExecutionLimits(
                    startupTimeoutMilliseconds: 500,
                    toolCallTimeoutMilliseconds: 30_000,
                    maximumDiscoveredTools: 32,
                    maximumOutputBytes: 1_048_576
                )
            ),
            projectRoot: fixture.project
        )
    }
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(
                disclosure: MCPDisclosureProfile(
                    boundary: .cloud,
                    destinationName: "GitHub",
                    dataKinds: [.toolArguments]
                )
            ),
            projectRoot: fixture.project
        )
    }
}

@Test func mcpChangedArgumentsClearApproval() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    _ = try store.saveDraft(fixture.draft(), projectRoot: fixture.project)
    _ = try store.approve(id: "safe-local")
    let changed = try store.saveDraft(
        fixture.draft(arguments: ["--stdio", "--read-only"]),
        projectRoot: fixture.project
    )
    #expect(changed.approval == nil)
}

@Test func mcpTrustPersistenceIsVersionedAtomicAndOwnerOnly() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    var store = try MCPTrustStore(applicationSupport: fixture.support)
    _ = try store.saveDraft(fixture.draft(), projectRoot: fixture.project)
    _ = try store.approve(id: "safe-local")
    let stateURL = fixture.support.appendingPathComponent("Security/\(MCPTrustStore.stateFilename)")
    let statePermissions = try #require(
        FileManager.default.attributesOfItem(atPath: stateURL.path)[.posixPermissions] as? NSNumber
    )
    let directoryPermissions = try #require(
        FileManager.default.attributesOfItem(atPath: stateURL.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber
    )
    #expect(statePermissions.intValue & 0o777 == 0o600)
    #expect(directoryPermissions.intValue & 0o777 == 0o700)

    store = try MCPTrustStore(applicationSupport: fixture.support)
    #expect(try store.status(id: "safe-local") == .trusted)
}

@Test func mcpTrustStoreRejectsFutureSchemaAndSymlinkState() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let security = fixture.support.appendingPathComponent("Security", isDirectory: true)
    try FileManager.default.createDirectory(
        at: security,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: security.path)
    let state = security.appendingPathComponent(MCPTrustStore.stateFilename)
    try Data(#"{"schemaVersion":99,"records":{}}"#.utf8).write(to: state)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: state.path)
    #expect(throws: MCPTrustStoreError.self) {
        try MCPTrustStore(applicationSupport: fixture.support)
    }

    try FileManager.default.removeItem(at: state)
    let target = fixture.root.appendingPathComponent("attacker-state")
    try Data(#"{"schemaVersion":1,"records":{}}"#.utf8).write(to: target)
    try FileManager.default.createSymbolicLink(at: state, withDestinationURL: target)
    #expect(throws: MCPTrustStoreError.self) {
        try MCPTrustStore(applicationSupport: fixture.support)
    }
}

@Test func mcpRejectsWorldWritableExecutablesAndDuplicateNamespaces() throws {
    let fixture = try MCPTestFixture()
    defer { fixture.cleanup() }
    let store = try MCPTrustStore(applicationSupport: fixture.support)
    try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: fixture.executable.path)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(fixture.draft(), projectRoot: fixture.project)
    }

    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.executable.path)
    _ = try store.saveDraft(fixture.draft(), projectRoot: fixture.project)
    #expect(throws: MCPTrustStoreError.self) {
        try store.saveDraft(
            fixture.draft(id: "another", serverName: "safe_local"),
            projectRoot: fixture.project
        )
    }
}
