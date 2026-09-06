import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Test("App-owned generation accepts only a private canonical temp directory")
func appOwnedGenerationSupportDirectoryValidation() throws {
    let manager = FileManager.default
    let name = "local-harness-ollama-generation.\(UUID().uuidString)"
    let privatePath = "/private/tmp/\(name)"
    let privateURL = URL(fileURLWithPath: privatePath, isDirectory: true)
    try manager.createDirectory(at: privateURL, withIntermediateDirectories: false)
    defer { try? manager.removeItem(at: privateURL) }
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: privatePath)

    #expect(AppOwnedOllamaGenerationCanary.supportDirectoryIsSafe(privateURL))
    #expect(AppOwnedOllamaGenerationCanary.supportDirectoryIsSafe(
        URL(fileURLWithPath: "/tmp/\(name)", isDirectory: true)
    ))

    try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: privatePath)
    #expect(!AppOwnedOllamaGenerationCanary.supportDirectoryIsSafe(privateURL))
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: privatePath)

    let link = URL(fileURLWithPath: "/private/tmp/local-harness-ollama-generation.\(UUID().uuidString)")
    try manager.createSymbolicLink(at: link, withDestinationURL: privateURL)
    defer { try? manager.removeItem(at: link) }
    #expect(!AppOwnedOllamaGenerationCanary.supportDirectoryIsSafe(link))
    #expect(!AppOwnedOllamaGenerationCanary.supportDirectoryIsSafe(
        URL(fileURLWithPath: "/private/tmp/not-a-generation-directory", isDirectory: true)
    ))
}

@Test func ollamaLaunchBoundaryMapsOnlyContentFreeProviderRecoveryReasons() {
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        OllamaRuntimeSecurityError.executableNotFound
    ) == .notInstalled)
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        OllamaRuntimeSecurityError.executableUntrusted
    ) == .untrustedInstallation)
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        OllamaRuntimeSecurityError.executableChanged
    ) == .installationChanged)
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        OllamaRuntimeSecurityError.unsafeModelStore
    ) == .unsafeModelStore)
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        OllamaRuntimeSecurityError.unsafePrivateDirectory
    ) == .unsafeRuntimeDirectory)
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        AppOwnedOllamaEndpointError.portReservationFailed(EMFILE)
    ) == .privatePortUnavailable)

    // Arbitrary launch-boundary diagnostics collapse to a fixed message; no
    // filesystem path, command, or provider content enters the UI/log reason.
    #expect(OllamaPrerequisiteRecoveryIssue.launchBoundary(
        NSError(domain: "private-path", code: 7)
    ) == .launchFailed)
}

private final class OllamaSecurityFixture {
    let root: URL
    let modelStore: URL

    init() throws {
        root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("LocalHarness-OllamaSecurity-\(UUID().uuidString)", isDirectory: true)
        modelStore = root.appendingPathComponent("models", isDirectory: true)
        try FileManager.default.createDirectory(at: modelStore, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: modelStore.path)
    }

    deinit { try? FileManager.default.removeItem(at: root) }

    func file(_ name: String, permissions: Int = 0o600) throws -> URL {
        let url = modelStore.appendingPathComponent(name)
        try Data("fixture".utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
        return url
    }
}

private final class AdvancingOllamaValidationClock: @unchecked Sendable {
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

private func qualifiedQwenLaunchConfiguration(
    profile: PerformanceProfile = .balanced
) throws -> AppOwnedOllamaModelConfiguration {
    try #require(AppOwnedOllamaModelConfiguration(selection: ModelSelection(
        route: ModelSelection.defaultLocal.route,
        performanceProfile: profile
    )))
}

@Test func ollamaModelStoreTraversalHasWideDepthPathDeadlineAndCancellationBounds() throws {
    do {
        let fixture = try OllamaSecurityFixture()
        for index in 0..<4 { _ = try fixture.file("wide-\(index)") }
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(
                fixture.modelStore,
                limits: .init(maximumEntries: 3)
            )
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        let first = fixture.modelStore.appendingPathComponent("first", isDirectory: true)
        let second = first.appendingPathComponent("second", isDirectory: true)
        try FileManager.default.createDirectory(at: second, withIntermediateDirectories: true)
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(
                fixture.modelStore,
                limits: .init(maximumDepth: 1)
            )
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        _ = try fixture.file(String(repeating: "p", count: 48))
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(
                fixture.modelStore,
                limits: .init(maximumRelativePathBytes: 32)
            )
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        _ = try fixture.file("deadline")
        let clock = AdvancingOllamaValidationClock(step: 2_000_000_000)
        do {
            _ = try AppOwnedOllamaSandbox.validateModelStore(
                fixture.modelStore,
                limits: .init(duration: 1),
                now: { clock.read() }
            )
            Issue.record("The model-store scan exceeded its monotonic deadline")
        } catch {
            #expect(error as? RuntimeStartupPrerequisiteError == .timedOut)
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        for index in 0..<8 { _ = try fixture.file("cancel-\(index)") }
        var checks = 0
        do {
            _ = try AppOwnedOllamaSandbox.validateModelStore(
                fixture.modelStore,
                cancellationCheck: {
                    checks += 1
                    if checks >= 4 { throw RuntimeStartupPrerequisiteError.cancelled }
                }
            )
            Issue.record("A cancelled model-store scan continued")
        } catch {
            #expect(error as? RuntimeStartupPrerequisiteError == .cancelled)
        }
    }
}

@Test func ollamaModelStoreValidationRejectsLinksHardlinksAndWritableEntries() throws {
    do {
        let fixture = try OllamaSecurityFixture()
        _ = try fixture.file("safe")
        #expect(try AppOwnedOllamaSandbox.validateModelStore(fixture.modelStore) == fixture.modelStore)
    }

    do {
        let fixture = try OllamaSecurityFixture()
        _ = try fixture.file("group-writable", permissions: 0o620)
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(fixture.modelStore)
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        let original = try fixture.file("original")
        try FileManager.default.linkItem(at: original, to: fixture.modelStore.appendingPathComponent("alias"))
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(fixture.modelStore)
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        try FileManager.default.createSymbolicLink(
            at: fixture.modelStore.appendingPathComponent("escape"),
            withDestinationURL: URL(fileURLWithPath: "/etc/passwd")
        )
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(fixture.modelStore)
        }
    }

    do {
        let fixture = try OllamaSecurityFixture()
        let linkedStore = fixture.root.appendingPathComponent("linked-models")
        try FileManager.default.createSymbolicLink(at: linkedStore, withDestinationURL: fixture.modelStore)
        #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
            _ = try AppOwnedOllamaSandbox.validateModelStore(linkedStore)
        }
    }
}

@Test func ollamaModelStoreIdentityMustStillMatchAtProcessLaunchBoundary() throws {
    let fixture = try OllamaSecurityFixture()
    _ = try fixture.file("model")
    var metadata = stat()
    #expect(Darwin.lstat(fixture.modelStore.path, &metadata) == 0)
    let sandbox = AppOwnedOllamaSandbox(
        runtimeRoot: fixture.root,
        homeDirectory: fixture.root,
        temporaryDirectory: fixture.root,
        modelStore: fixture.modelStore,
        modelStoreIdentity: .init(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino),
            owner: metadata.st_uid,
            permissions: UInt16(metadata.st_mode & 0o7777)
        ),
        profile: ""
    )
    try sandbox.revalidateModelStoreIdentity()

    // A same-path replacement or metadata mutation after the worker scan must
    // not survive the cheap main-thread pre-spawn identity gate.
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o750],
        ofItemAtPath: fixture.modelStore.path
    )
    #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
        try sandbox.revalidateModelStoreIdentity()
    }
}

@Test func ollamaSandboxProfileIsPrivateReadOnlyAndLoopbackOnly() throws {
    let fixture = try OllamaSecurityFixture()
    let runtime = fixture.root.appendingPathComponent("runtime", isDirectory: true)
    let profile = AppOwnedOllamaSandbox.makeProfile(runtimeRoot: runtime, modelStore: fixture.modelStore)

    #expect(profile.contains("(deny file-read*)"))
    #expect(profile.contains("(deny file-write*)"))
    #expect(profile.contains("(subpath \"\(fixture.modelStore.path)\")"))
    #expect(profile.contains("(subpath \"\(runtime.path)\")"))
    #expect(profile.contains("(deny network-outbound (require-not (remote ip \"localhost:*\")))"))
    #expect(profile.contains("(deny network-bind (require-not (local ip \"localhost:*\")))"))
    #expect(!profile.contains(FileManager.default.homeDirectoryForCurrentUser.path + "\")"))
}

@Test func ollamaSandboxUsesOnlyAnExplicitlyValidatedModelStoreOverride() throws {
    #expect(OllamaExecutableTrust.candidatePaths(posixHomePath: "/Users/reviewed-user") == [
        "/Applications/Ollama.app/Contents/Resources/ollama",
        "/Users/reviewed-user/Applications/Ollama.app/Contents/Resources/ollama",
        "/usr/local/bin/ollama",
        "/opt/homebrew/bin/ollama"
    ])
    #expect(OllamaExecutableTrust.candidatePaths(posixHomePath: nil) == [
        "/Applications/Ollama.app/Contents/Resources/ollama",
        "/usr/local/bin/ollama",
        "/opt/homebrew/bin/ollama"
    ])
    for unsafeHome in ["", ".", "/", "/Users/reviewed-user/..", "/Users/reviewed\0-user"] {
        #expect(!OllamaExecutableTrust.candidatePaths(posixHomePath: unsafeHome).contains {
            $0.contains("/Applications/Ollama.app") && $0 != "/Applications/Ollama.app/Contents/Resources/ollama"
        })
    }
    #expect(OllamaModelStoreConfigurationError.userSelectionUnavailable.localizedDescription.contains(
        "not yet supported"
    ))

    let fixture = try OllamaSecurityFixture()
    _ = try fixture.file("model")
    let endpoint = try #require(AppOwnedOllamaEndpoint(port: 49_153))
    let qualifiedEnvironment = AppOwnedOllamaLaunchPlan.environmentAdditions(
        endpoint: endpoint,
        modelStore: fixture.modelStore,
        modelConfiguration: try qualifiedQwenLaunchConfiguration()
    )
    #expect(qualifiedEnvironment["OLLAMA_FLASH_ATTENTION"] == "1")
    #expect(qualifiedEnvironment["OLLAMA_KV_CACHE_TYPE"] == "q8_0")

    let compatibilitySelection = ModelSelection(route: ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: ModelID("community-tools:latest")
    ))
    let compatibilityConfiguration = try #require(
        AppOwnedOllamaModelConfiguration(selection: compatibilitySelection)
    )
    let compatibilityEnvironment = AppOwnedOllamaLaunchPlan.environmentAdditions(
        endpoint: endpoint,
        modelStore: fixture.modelStore,
        modelConfiguration: compatibilityConfiguration
    )
    #expect(compatibilityConfiguration.performance == .compatibilityLocalModel)
    #expect(compatibilityEnvironment["OLLAMA_CONTEXT_LENGTH"] == "8192")
    #expect(compatibilityEnvironment["OLLAMA_FLASH_ATTENTION"] == nil)
    #expect(compatibilityEnvironment["OLLAMA_KV_CACHE_TYPE"] == nil)

    let support = fixture.root.appendingPathComponent("support", isDirectory: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)

    let sandbox = try AppOwnedOllamaSandbox.prepare(
        applicationSupport: support,
        modelStoreDirectory: fixture.modelStore
    )
    #expect(sandbox.modelStore == fixture.modelStore)
    #expect(sandbox.profile.contains("(subpath \"\(fixture.modelStore.path)\")"))

    try FileManager.default.setAttributes(
        [.posixPermissions: 0o720],
        ofItemAtPath: fixture.modelStore.path
    )
    #expect(throws: OllamaRuntimeSecurityError.unsafeModelStore) {
        _ = try AppOwnedOllamaSandbox.prepare(
            applicationSupport: support,
            modelStoreDirectory: fixture.modelStore
        )
    }
}

private let installedOfficialOllamaIsAvailable = OllamaExecutableTrust.fixedCandidates.contains {
    FileManager.default.fileExists(atPath: $0)
}

private let liveUserOllamaRuntimeTestsAreAvailable = installedOfficialOllamaIsAvailable
    && ProcessInfo.processInfo.environment["LOCAL_HARNESS_SWIFT_TEST_ISOLATION_ROOT"] == nil

@Test(.disabled(
    if: !installedOfficialOllamaIsAvailable,
    "Requires an installed official Ollama executable."
))
func appOwnedOllamaLaunchPlanPropagatesAValidatedExplicitExternalModelStore() throws {

    let fixture = try OllamaSecurityFixture()
    _ = try fixture.file("external-model-manifest")
    let support = fixture.root.appendingPathComponent("support", isDirectory: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: false)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: support.path
    )
    let endpoint = try #require(AppOwnedOllamaEndpoint(port: 49_153))

    let plan = try AppOwnedOllamaLaunchPlan.prepare(
        applicationSupport: support,
        endpoint: endpoint,
        modelConfiguration: try qualifiedQwenLaunchConfiguration(),
        modelStoreDirectory: fixture.modelStore
    )

    #expect(plan.sandbox.modelStore == fixture.modelStore)
    #expect(!fixture.modelStore.path.hasPrefix(plan.currentDirectory.path + "/"))
    #expect(plan.environment["OLLAMA_MODELS"] == fixture.modelStore.path)
    #expect(plan.sandbox.profile.contains("(subpath \"\(fixture.modelStore.path)\")"))
    #expect(plan.currentDirectory == support.appendingPathComponent("OllamaRuntime", isDirectory: true))
    #expect(plan.sandbox.homeDirectory == plan.currentDirectory.appendingPathComponent(
        "Home",
        isDirectory: true
    ))
    #expect(plan.sandbox.temporaryDirectory == plan.currentDirectory.appendingPathComponent(
        "Temporary",
        isDirectory: true
    ))
    #expect(plan.environment["HOME"] == plan.sandbox.homeDirectory.path)
    #expect(plan.environment["TMPDIR"] == plan.sandbox.temporaryDirectory.path)
    #expect(plan.environment["OLLAMA_MODELS"] != plan.sandbox.homeDirectory
        .appendingPathComponent(".ollama/models", isDirectory: true).path)
    try plan.sandbox.revalidateModelStoreIdentity()
}

@Suite(.serialized)
struct LiveOllamaRuntimeSecurityTests {
@Test func controllerReadinessBudgetSurvivesWarmResourceReclamation() {
    #expect(HarnessController.ownedOllamaReadinessTimeout == 90)
    #expect(HarnessController.ownedOllamaReadinessTimeout <= 120)
}

@Test(.disabled(
    if: !liveUserOllamaRuntimeTestsAreAvailable,
    "Requires installed official Ollama and the non-isolated user model store."
))
func installedOllamaResolvesToOneStrictOfficialIdentityWhenPresent() throws {

    let identity = try OllamaExecutableTrust.resolve()
        #expect(OllamaExecutableTrust.fixedCandidates.contains { candidate in
            URL(fileURLWithPath: candidate).resolvingSymlinksInPath().standardizedFileURL
                == identity.executableURL
        })
    #expect(identity.codeIdentifier == OllamaExecutableTrust.expectedIdentifier)
    #expect(identity.teamIdentifier == OllamaExecutableTrust.expectedTeamIdentifier)
    #expect(identity.cdHashHex.count >= 40)
    try OllamaExecutableTrust.revalidate(identity)
    #expect(!OllamaExecutableTrust.process(getpid(), matches: identity))

    let support = FileManager.default.temporaryDirectory
        .appendingPathComponent("LocalHarness-OllamaSupport-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
    defer { try? FileManager.default.removeItem(at: support) }
    let sandbox = try AppOwnedOllamaSandbox.prepare(applicationSupport: support)
    #expect(sandbox.homeDirectory.deletingLastPathComponent() == sandbox.runtimeRoot)
    #expect(sandbox.temporaryDirectory.deletingLastPathComponent() == sandbox.runtimeRoot)
    #expect(sandbox.modelStore.path.hasSuffix("/.ollama/models"))
    for directory in [sandbox.runtimeRoot, sandbox.homeDirectory, sandbox.temporaryDirectory] {
        var metadata = stat()
        #expect(Darwin.lstat(directory.path, &metadata) == 0)
        #expect(metadata.st_mode & 0o777 == 0o700)
    }

    let endpoint = try #require(AppOwnedOllamaEndpoint(port: 49_152))
    let plan = try AppOwnedOllamaLaunchPlan.prepare(
        applicationSupport: support,
        endpoint: endpoint,
        modelConfiguration: try qualifiedQwenLaunchConfiguration()
    )
    #expect(plan.identity == identity)
    #expect(plan.processExecutable.path == "/usr/bin/sandbox-exec")
    #expect(plan.arguments == ["-p", plan.sandbox.profile, identity.executableURL.path, "serve"])
    #expect(plan.environment["HOME"] == plan.sandbox.homeDirectory.path)
    #expect(plan.environment["TMPDIR"] == plan.sandbox.temporaryDirectory.path)
    #expect(plan.environment["OLLAMA_MODELS"] == plan.sandbox.modelStore.path)
    #expect(plan.environment["OLLAMA_HOST"] == "127.0.0.1:49152")
    #expect(plan.environment["OLLAMA_NO_CLOUD"] == "1")
    #expect(plan.environment["OLLAMA_DEBUG_LOG_REQUESTS"] == "0")
    #expect(plan.environment["SHELL"] == nil)
    for inheritedSecret in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "SSH_AUTH_SOCK"] {
        #expect(plan.environment[inheritedSecret] == nil)
    }
}

@Test(.disabled(
    if: !liveUserOllamaRuntimeTestsAreAvailable,
    "Requires installed official Ollama and the non-isolated user model store."
))
func appOwnedOllamaPlanLaunchesOneAttestedSandboxedListenerWhenInstalled() async throws {

    let support = FileManager.default.temporaryDirectory
        .appendingPathComponent("LocalHarness-OllamaLaunch-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: support, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
    defer { try? FileManager.default.removeItem(at: support) }

    let reservation = try LoopbackPortReservation.reserve()
    let plan = try AppOwnedOllamaLaunchPlan.prepare(
        applicationSupport: support,
        endpoint: reservation.endpoint,
        modelConfiguration: try qualifiedQwenLaunchConfiguration()
    )
    let process = Process()
    process.executableURL = plan.processExecutable
    process.arguments = plan.arguments
    process.currentDirectoryURL = plan.currentDirectory
    process.environment = plan.environment
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    reservation.releaseForLaunch()
    try process.run()
    defer {
        if process.isRunning { process.terminate() }
        for _ in 0..<100 where process.isRunning { usleep(20_000) }
        if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
        #expect(boundedTestWaitForExit(process, timeout: 3))
    }

    var attested = false
    for _ in 0..<150 {
        if process.isRunning,
           OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: plan.endpoint),
           OllamaExecutableTrust.process(process.processIdentifier, matches: plan.identity) {
            attested = true
            break
        }
        try await Task.sleep(for: .milliseconds(100))
    }
    #expect(attested)
    guard attested else { return }

    let catalogOutcome = await withCheckedContinuation { continuation in
        LocalRuntimeReadinessProbe.ollamaCatalogUntilReady(
            endpoint: plan.endpoint,
            totalTimeout: 30,
            attemptTimeout: 2,
            retryDelay: 0.5,
            boundaryStatus: {
                guard process.isRunning else { return .invalid }
                return OllamaExecutableTrust.process(process.processIdentifier, matches: plan.identity)
                    && OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: plan.endpoint)
                    ? .valid
                    : .pending
            }
        ) {
            continuation.resume(returning: $0)
        }
    }
    #expect(catalogOutcome == .ready)
    #expect(OllamaExecutableTrust.process(process.processIdentifier, matches: plan.identity))
    #expect(OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: plan.endpoint))
}

@Test(.disabled(
    if: !liveUserOllamaRuntimeTestsAreAvailable,
    "Requires installed official Ollama and the non-isolated user model store."
))
@MainActor
func harnessControllerUsesAttestedSandboxPlanAndReapsItWhenInstalled() async throws {
    let support = try makeAdmissibleApplicationSupportTestRoot(prefix: "Fulmar-ControllerOllama")
    defer { try? FileManager.default.removeItem(at: support) }
    let controller = HarnessController(applicationSupportDirectory: support)

    let startResult = await withCheckedContinuation { continuation in
        controller.prepareOllamaOnly { continuation.resume(returning: $0) }
    }
    guard case .success = startResult else {
        if case .failure(let error) = startResult {
            Issue.record("Controller did not start its sandboxed Ollama: \(error)")
        }
        return
    }

    #expect(controller.ollamaBaseURL != nil)
    #expect(controller.ollamaProviderBaseURL != nil)
    #expect(controller.verifiedOllamaExecutableIdentity?.codeIdentifier == OllamaExecutableTrust.expectedIdentifier)

    let stopResult = await withCheckedContinuation { continuation in
        controller.stopOwnedServicesAndWait { continuation.resume(returning: $0) }
    }
    if case .failure(let error) = stopResult {
        Issue.record("Controller did not reap its exact Ollama child: \(error)")
    }
    #expect(controller.ollamaBaseURL == nil)
    #expect(controller.ollamaProviderBaseURL == nil)
    #expect(controller.verifiedOllamaExecutableIdentity == nil)
}
}
