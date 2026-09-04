import Foundation
import Darwin
import Testing
@testable import LocalHarness

private typealias LifecycleStopReply = (Result<Void, Error>) -> Void
private enum LifecycleFixtureError: LocalizedError {
    case harnessLaunchFailed
    case readinessTimedOut
    var errorDescription: String? {
        switch self {
        case .harnessLaunchFailed: return "fixture harness launch failed"
        case .readinessTimedOut: return "fixture readiness timed out"
        }
    }
}

private final class StartupPhaseRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [RuntimeStartupPrerequisitePhase] = []

    func record(_ phase: RuntimeStartupPrerequisitePhase) {
        lock.lock()
        values.append(phase)
        lock.unlock()
    }

    func snapshot() -> [RuntimeStartupPrerequisitePhase] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }
}

private func runHarnessControllerFixtureChmod(_ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = arguments
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 5),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        throw CocoaError(.fileWriteUnknown)
    }
}

private func makeHarnessControllerSecureSupportRoot(prefix: String) throws -> URL {
    guard !prefix.isEmpty, prefix.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }),
          let account = getpwuid(geteuid()),
          let home = account.pointee.pw_dir else {
        throw CocoaError(.fileNoSuchFile)
    }
    let root = URL(fileURLWithPath: String(cString: home), isDirectory: true)
        .appendingPathComponent("Library/Caches", isDirectory: true)
        .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return root
}

private func launchLifecycleFixture() throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sleep")
    process.arguments = ["30"]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    return process
}

private func reapLifecycleFixture(_ process: Process) {
    if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
    #expect(boundedTestWaitForExit(process, timeout: 3))
}

@Test
func runtimeRestartCircuitIsBoundedBackedOffAndRejectsSparseCrashChurn() {
    let origin = Date(timeIntervalSince1970: 1_000)
    var circuit = BoundedRuntimeRestartCircuit(window: 60, delays: [1, 3, 8])

    #expect(circuit.recordFailure(at: origin) == .retry(after: 1))
    #expect(circuit.recordFailure(at: origin.addingTimeInterval(1)) == .retry(after: 3))
    #expect(circuit.recordFailure(at: origin.addingTimeInterval(2)) == .retry(after: 8))
    #expect(circuit.recordFailure(at: origin.addingTimeInterval(3)) == .exhausted)

    // Wall-clock spacing does not imply stability. A service that reaches
    // readiness and crashes every 31 seconds is still one consecutive crash
    // sequence and must exhaust rather than churn forever.
    var sparse = BoundedRuntimeRestartCircuit(window: 60, delays: [1, 3, 8])
    #expect(sparse.recordFailure(at: origin) == .retry(after: 1))
    #expect(sparse.recordFailure(at: origin.addingTimeInterval(31)) == .retry(after: 3))
    #expect(sparse.recordFailure(at: origin.addingTimeInterval(62)) == .retry(after: 8))
    #expect(sparse.recordFailure(at: origin.addingTimeInterval(93)) == .exhausted)
}

@Test
func runtimeRestartCircuitResetsOnlyAfterStableReadinessWindow() {
    let origin = Date(timeIntervalSince1970: 2_000)
    var circuit = BoundedRuntimeRestartCircuit(window: 60, delays: [1, 3, 8])
    _ = circuit.recordFailure(at: origin)
    _ = circuit.recordFailure(at: origin.addingTimeInterval(1))

    circuit.resetAfterStableReadiness(
        startedAt: origin.addingTimeInterval(2),
        now: origin.addingTimeInterval(61)
    )
    #expect(circuit.failures.count == 2)

    circuit.resetAfterStableReadiness(
        startedAt: origin.addingTimeInterval(2),
        now: origin.addingTimeInterval(62)
    )
    #expect(circuit.failures.isEmpty)
    #expect(circuit.recordFailure(at: origin.addingTimeInterval(63)) == .retry(after: 1))
}

@Test
func explicitStopQuitOrThermalIntentInvalidatesDelayedAutomaticRestart() {
    var gate = AutomaticRuntimeRestartGate()
    let first = gate.begin()
    #expect(gate.admits(first))

    gate.cancel()
    #expect(!gate.admits(first))

    let replacement = gate.begin()
    #expect(gate.admits(replacement))
    #expect(!gate.admits(first))
}

@Test
func productionRuntimeLocatorNeverConsultsAmbientNVM() throws {
    let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("runtime-locator-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let bundle = root.appendingPathComponent("Candidate.app", isDirectory: true)
    let resources = bundle.appendingPathComponent("Contents/Resources", isDirectory: true)
    let runtime = resources.appendingPathComponent("Runtime", isDirectory: true)
    let dsh = runtime.appendingPathComponent("dsh", isDirectory: true)
    try FileManager.default.createDirectory(at: dsh.appendingPathComponent("lib", isDirectory: true), withIntermediateDirectories: true)
    let node = runtime.appendingPathComponent("node")
    let script = dsh.appendingPathComponent("lib/bin.js")
    let package = dsh.appendingPathComponent("package.json")
    try Data("#!/bin/sh\n".utf8).write(to: node)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: node.path)
    try Data("// pinned fixture\n".utf8).write(to: script)
    try Data(#"{"name":"@deepseek-ai/dsh","version":"0.1.1-rc.1"}"#.utf8).write(to: package)
    try Data(#"{"productDisplayName":"Fulmar","bundleIdentifier":"com.angadjairath.localharness","runtime":{"deepseekHarnessVersion":"0.1.1-rc.1"}}"#.utf8)
        .write(to: resources.appendingPathComponent("ReleaseIdentity.json"))

    var ambientRead = false
    let location = try HarnessRuntimeLocator.locate(
        bundleURL: bundle,
        resources: resources,
        home: root.appendingPathComponent("hostile-home", isDirectory: true),
        ambientDirectoryReader: { _ in
            ambientRead = true
            throw CocoaError(.fileReadNoPermission)
        }
    )

    #expect(!ambientRead)
    #expect(location.bundled)
    #expect(location.node == node)
    #expect(location.script == script)
    #expect(location.dshVersion == "0.1.1-rc.1")
}

@Test @MainActor
func harnessLaunchFailureReapsOwnedOllamaBeforePublishingFailure() throws {
    let ollama = try launchLifecycleFixture()
    defer { reapLifecycleFixture(ollama) }
    var stopReply: LifecycleStopReply?
    var finished = false
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: nil,
        ollamaProcess: ollama,
        initialState: .startingHarness,
        stopProcess: { process, reply in
            #expect(process === ollama)
            stopReply = reply
        },
        startReplacement: { Issue.record("A failed launch must not start a replacement") }
    ))

    controller.failRuntimeStartAfterCleaningOwnedServices(LifecycleFixtureError.harnessLaunchFailed) {
        finished = true
    }

    #expect(stopReply != nil)
    #expect(!finished)
    #expect(controller.currentState == .startingHarness)
    #expect(controller.ownsOllama)

    reapLifecycleFixture(ollama)
    let reply = try #require(stopReply)
    reply(.success(()))

    #expect(finished)
    #expect(!controller.ownsOllama)
    #expect(!controller.ownsHarness)
    guard case .failed(let message) = controller.currentState else {
        Issue.record("Failure must be published after owned cleanup")
        return
    }
    #expect(message.contains("failed without a safe public diagnostic"))
    #expect(!message.contains("fixture harness launch failed"))
}

@Test @MainActor
func receiptlessHomePromptWaitsForExactOwnedServiceStopBarrier() async throws {
    let support = try makeHarnessControllerSecureSupportRoot(prefix: "fulmar-controller-receiptless")
    defer { try? FileManager.default.removeItem(at: support) }
    let home = support.appendingPathComponent("HarnessHome", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    try Data("existing".utf8).write(to: home.appendingPathComponent("settings.yaml"))

    let ollama = try launchLifecycleFixture()
    defer { reapLifecycleFixture(ollama) }
    var stopReply: LifecycleStopReply?
    var promptCount = 0
    var observedRequest: HarnessHomeReceiptlessRecoveryRequest?
    let controller = HarnessController(
        lifecycleTestConfiguration: .init(
            harnessProcess: nil,
            ollamaProcess: ollama,
            initialState: .stopped,
            stopProcess: { process, reply in
                #expect(process === ollama)
                stopReply = reply
            },
            startReplacement: { Issue.record("Recovery review must not start a replacement") },
            bundleIntegrityVerification: { true },
            harnessHomeRecoveryAuthenticationKey: Data(repeating: 0x71, count: 32),
            deviceAttestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
        ),
        applicationSupportDirectory: support
    )
    controller.onHarnessHomeRecoveryRequired = { request in
        promptCount += 1
        observedRequest = request
        #expect(controller.currentState == .stopped)
        #expect(!controller.ownsHarness)
        #expect(!controller.ownsOllama)
    }

    controller.prepareProviderRecovery()
    let stopDeadline = ContinuousClock.now + .seconds(3)
    while stopReply == nil, ContinuousClock.now < stopDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(stopReply != nil)
    #expect(promptCount == 0)
    #expect(controller.ownsOllama)
    #expect(controller.pendingHarnessHomeRecoveryRequest != nil)
    #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent("settings.yaml").path))
    #expect(!FileManager.default.fileExists(atPath: support.appendingPathComponent(
        HarnessHomeManager.receiptlessRecoveryDirectoryName
    ).path))

    reapLifecycleFixture(ollama)
    let reply = try #require(stopReply)
    reply(.success(()))
    let promptDeadline = ContinuousClock.now + .seconds(1)
    while promptCount == 0, ContinuousClock.now < promptDeadline {
        await Task.yield()
    }

    #expect(promptCount == 1)
    #expect(observedRequest?.root == home)
    #expect(controller.currentState == .stopped)
    #expect(!controller.ownsOllama)
    #expect(!controller.ownsHarness)

    var recoveryResults: [Result<HarnessHomeReceiptlessRecoveryReceipt, Error>] = []
    controller.preserveAndRepairPendingHarnessHome(
        choice: .settingsOnly,
        interruptedIntent: nil
    ) { recoveryResults.append($0) }
    let recoveryDeadline = ContinuousClock.now + .seconds(3)
    while recoveryResults.isEmpty, ContinuousClock.now < recoveryDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(recoveryResults.count == 1)
    if case .success(let receipt) = try #require(recoveryResults.first) {
        #expect(FileManager.default.fileExists(atPath: receipt.quarantine.path))
        #expect(controller.pendingHarnessHomeRecoveryState == .published(receipt))
    } else {
        Issue.record("Explicit recovery should succeed with the deterministic test key")
    }
    #expect(controller.pendingHarnessHomeRecoveryRequest == nil)
    #expect(controller.currentState == .stopped)

    var acknowledgement: Result<Void, Error>?
    controller.acknowledgePendingHarnessHomeRecovery { acknowledgement = $0 }
    let acknowledgementDeadline = ContinuousClock.now + .seconds(3)
    while acknowledgement == nil, ContinuousClock.now < acknowledgementDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    try #require(acknowledgement).get()
    #expect(controller.pendingHarnessHomeRecoveryState == nil)
}

@Test @MainActor
func terminalShutdownCannotAcknowledgeALatePublishedRecoveryReceipt() async throws {
    let support = try makeHarnessControllerSecureSupportRoot(prefix: "fulmar-controller-receiptless-quit")
    defer { try? FileManager.default.removeItem(at: support) }
    let home = support.appendingPathComponent("HarnessHome", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    try Data("existing".utf8).write(to: home.appendingPathComponent("settings.yaml"))
    let key = Data(repeating: 0x72, count: 32)
    let controller = HarnessController(
        lifecycleTestConfiguration: .init(
            harnessProcess: nil,
            ollamaProcess: nil,
            initialState: .stopped,
            stopProcess: { _, reply in
                Issue.record("No owned child should exist in this fixture")
                reply(.success(()))
            },
            startReplacement: { Issue.record("Terminal recovery must not start a replacement") },
            bundleIntegrityVerification: { true },
            harnessHomeRecoveryAuthenticationKey: key,
            deviceAttestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
        ),
        applicationSupportDirectory: support
    )
    var observedPending: HarnessHomeRecoveryPendingState?
    controller.onHarnessHomeRecoveryPending = { observedPending = $0 }
    controller.prepareProviderRecovery()
    let promptDeadline = ContinuousClock.now + .seconds(3)
    while observedPending == nil, ContinuousClock.now < promptDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    guard case .initial? = observedPending else {
        Issue.record("Expected the exact initial recovery state")
        return
    }

    var recovery: Result<HarnessHomeReceiptlessRecoveryReceipt, Error>?
    controller.preserveAndRepairPendingHarnessHome(
        choice: .settingsOnly,
        interruptedIntent: nil
    ) { recovery = $0 }
    let recoveryDeadline = ContinuousClock.now + .seconds(3)
    while recovery == nil, ContinuousClock.now < recoveryDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    let receipt = try #require(recovery).get()
    #expect(controller.pendingHarnessHomeRecoveryState == .published(receipt))

    var termination: Result<Void, Error>?
    controller.stopOwnedServicesForApplicationTermination { termination = $0 }
    let terminationDeadline = ContinuousClock.now + .seconds(1)
    while termination == nil, ContinuousClock.now < terminationDeadline {
        await Task.yield()
    }
    try #require(termination).get()

    var acknowledgement: Result<Void, Error>?
    controller.acknowledgePendingHarnessHomeRecovery { acknowledgement = $0 }
    guard case .failure? = acknowledgement else {
        Issue.record("A late receipt acknowledgement must be rejected after terminal shutdown")
        return
    }
    #expect(controller.pendingHarnessHomeRecoveryState == .published(receipt))

    let relaunched = HarnessHomeManager(
        root: home,
        legacyRoot: support.appendingPathComponent("missing-legacy", isDirectory: true),
        recoveryAuthenticationKey: key
    )
    do {
        try relaunched.prepare()
        Issue.record("The durable published journal must be presented again after relaunch")
    } catch HarnessHomeError.receiptlessRecoveryInterrupted(_) {
        // Expected: Quit never acknowledged the exact published receipt.
    } catch {
        Issue.record("Expected an interrupted published journal, got \(error)")
    }
}

@Test @MainActor
func receiptlessHomeStopsBeforeOllamaAdmissionOrAnyOwnedChildLifecycle() async throws {
    let support = try makeHarnessControllerSecureSupportRoot(prefix: "fulmar-controller-home-preflight")
    defer { try? FileManager.default.removeItem(at: support) }
    let home = support.appendingPathComponent("HarnessHome", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    try Data("existing".utf8).write(to: home.appendingPathComponent("settings.yaml"))

    let phases = StartupPhaseRecorder()
    var stopCalls = 0
    var replacementLaunches = 0
    var pending: HarnessHomeRecoveryPendingState?
    var states: [HarnessController.State] = []
    let controller = HarnessController(
        lifecycleTestConfiguration: .init(
            harnessProcess: nil,
            ollamaProcess: nil,
            initialState: .stopped,
            stopProcess: { _, reply in
                stopCalls += 1
                reply(.success(()))
            },
            startReplacement: { replacementLaunches += 1 },
            startupPrerequisitePhaseHook: { phase, _ in phases.record(phase) },
            bundleIntegrityVerification: { true },
            physicalMemoryBytes: 64 * 1_073_741_824,
            harnessHomeRecoveryAuthenticationKey: Data(repeating: 0x73, count: 32),
            deviceAttestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
        ),
        applicationSupportDirectory: support
    )
    controller.onStateChange = { states.append($0) }
    controller.onHarnessHomeRecoveryPending = { pending = $0 }

    controller.prepareAndStart()
    let deadline = ContinuousClock.now + .seconds(3)
    while pending == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    guard case .initial? = pending else {
        Issue.record("Expected the exact initial receiptless-home pending state")
        return
    }
    #expect(phases.snapshot() == [.bundleIntegrity, .harnessHomePreflight])
    #expect(!states.contains(.startingOllama))
    #expect(!states.contains(.startingHarness))
    #expect(stopCalls == 0)
    #expect(replacementLaunches == 0)
    #expect(!controller.ownsOllama)
    #expect(!controller.ownsHarness)
    #expect(controller.currentState == .stopped)
}

@Test @MainActor
func backgroundHomePreflightPublishesBlockedAttentionBeforeGenericFailureCompletion() async throws {
    let support = try makeHarnessControllerSecureSupportRoot(
        prefix: "fulmar-controller-home-preflight-blocked"
    )
    defer { try? FileManager.default.removeItem(at: support) }
    try Data("wrong node type".utf8).write(
        to: support.appendingPathComponent("HarnessHome", isDirectory: false)
    )

    let controller = HarnessController(
        lifecycleTestConfiguration: .init(
            harnessProcess: nil,
            ollamaProcess: nil,
            initialState: .stopped,
            stopProcess: { _, _ in Issue.record("Preflight owns no child process") },
            startReplacement: { Issue.record("Preflight must not launch a runtime") }
        ),
        applicationSupportDirectory: support,
        forbidCredentialHelper: true
    )
    var trace: [String] = []
    var observedPending: HarnessHomeRecoveryPendingState?
    var completion: Result<HarnessHomeRecoveryPreflightStatus, Error>?
    controller.onHarnessHomeRecoveryPending = { pending in
        observedPending = pending
        trace.append("pending")
    }
    controller.preflightHarnessHomeRecoveryForBackgroundSchedule { result in
        completion = result
        trace.append("completion")
    }

    let deadline = ContinuousClock.now + .seconds(2)
    while completion == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    guard case .blocked? = observedPending else {
        Issue.record("An untyped unsafe-home failure must become foreground attention")
        return
    }
    guard case .failure? = completion else {
        Issue.record("The unsafe preflight must fail closed")
        return
    }
    #expect(trace == ["pending", "completion"])
    #expect(controller.pendingHarnessHomeRecoveryState == observedPending)
    #expect(!controller.ownsHarness)
    #expect(!controller.ownsOllama)
}

@Test @MainActor
func foregroundReadinessTimeoutReapsBothExactChildrenBeforePublishingFailure() throws {
    let harness = try launchLifecycleFixture()
    let ollama = try launchLifecycleFixture()
    defer {
        reapLifecycleFixture(harness)
        reapLifecycleFixture(ollama)
    }
    var stopReplies: [Int32: LifecycleStopReply] = [:]
    var completionCount = 0
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: harness,
        ollamaProcess: ollama,
        initialState: .startingHarness,
        stopProcess: { process, reply in
            stopReplies[process.processIdentifier] = reply
        },
        startReplacement: { Issue.record("A readiness timeout must not launch a replacement") }
    ))

    controller.failRuntimeStartAfterCleaningOwnedServices(LifecycleFixtureError.readinessTimedOut) {
        completionCount += 1
    }

    #expect(stopReplies.count == 2)
    #expect(controller.currentState == .startingHarness)
    #expect(completionCount == 0)

    reapLifecycleFixture(harness)
    let harnessReply = try #require(stopReplies[harness.processIdentifier])
    harnessReply(.success(()))
    #expect(controller.currentState == .startingHarness)
    #expect(controller.ownsHarness)
    #expect(controller.ownsOllama)
    #expect(completionCount == 0)

    reapLifecycleFixture(ollama)
    let ollamaReply = try #require(stopReplies[ollama.processIdentifier])
    ollamaReply(.success(()))

    #expect(completionCount == 1)
    #expect(!controller.ownsHarness)
    #expect(!controller.ownsOllama)
    guard case .failed(let message) = controller.currentState else {
        Issue.record("The timeout failure must publish only after both exact PIDs exit")
        return
    }
    #expect(message.contains("failed without a safe public diagnostic"))
    #expect(!message.contains("fixture readiness timed out"))
}

@Test @MainActor
func hostileLifecycleErrorNeverEntersPublishedRuntimeState() {
    struct HostileLifecycleError: LocalizedError {
        var errorDescription: String? {
            "password=sk-runtime-secret-123456789 /Users/private/runtime \u{202E}\u{0007}" +
                String(repeating: "HOSTILE-RUNTIME-DIAGNOSTIC", count: 4_000)
        }
    }

    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: nil,
        ollamaProcess: nil,
        initialState: .startingHarness,
        stopProcess: { _, _ in Issue.record("No process should need stopping") },
        startReplacement: { Issue.record("A failed launch must not start a replacement") }
    ))
    controller.failRuntimeStartAfterCleaningOwnedServices(HostileLifecycleError())

    guard case .failed(let message) = controller.currentState else {
        Issue.record("Expected a closed lifecycle failure")
        return
    }
    #expect(message.contains("failed without a safe public diagnostic"))
    #expect(!message.contains("sk-runtime"))
    #expect(!message.contains("/Users/private"))
    #expect(!message.contains("HOSTILE-RUNTIME-DIAGNOSTIC"))
    #expect(!message.contains("\u{202E}"))
    #expect(message.count < 500)
}

@Test @MainActor
func overlappingControllerStopsUseOneExactProcessBarrier() throws {
    let harness = try launchLifecycleFixture()
    let ollama = try launchLifecycleFixture()
    defer {
        reapLifecycleFixture(harness)
        reapLifecycleFixture(ollama)
    }

    var stopRequests: [Int32] = []
    var stopReplies: [Int32: LifecycleStopReply] = [:]
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: harness,
        ollamaProcess: ollama,
        initialState: .ready(managedByApp: true),
        stopProcess: { process, reply in
            stopRequests.append(process.processIdentifier)
            #expect(stopReplies[process.processIdentifier] == nil)
            stopReplies[process.processIdentifier] = reply
        },
        startReplacement: { Issue.record("A plain stop must not start a replacement") }
    ))
    var results: [Result<Void, Error>] = []

    controller.stopOwnedServicesAndWait { results.append($0) }
    controller.stopOwnedServicesAndWait { results.append($0) }

    #expect(stopRequests.count == 2)
    #expect(Set(stopRequests) == Set([harness.processIdentifier, ollama.processIdentifier]))
    #expect(results.isEmpty)
    #expect(controller.currentState == .ready(managedByApp: true))
    #expect(controller.ownsHarness)
    #expect(controller.ownsOllama)

    reapLifecycleFixture(harness)
    let harnessReply = try #require(stopReplies[harness.processIdentifier])
    harnessReply(.success(()))

    #expect(results.isEmpty)
    #expect(controller.currentState == .ready(managedByApp: true))
    #expect(controller.ownsHarness)
    #expect(controller.ownsOllama)

    reapLifecycleFixture(ollama)
    let ollamaReply = try #require(stopReplies[ollama.processIdentifier])
    ollamaReply(.success(()))

    #expect(results.count == 2)
    for result in results { try result.get() }
    #expect(controller.currentState == .stopped)
    #expect(!controller.ownsHarness)
    #expect(!controller.ownsOllama)
}

@Test @MainActor
func controllerStopWaitsForExactStartupPrerequisiteSettlementBeforePublishingStopped() async throws {
    let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("startup-stop-barrier-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let firstMutation = root.appendingPathComponent("first-mutation")
    let forbiddenLateMutation = root.appendingPathComponent("late-mutation")
    let releasePreparation = DispatchSemaphore(value: 0)
    let worker = RuntimeStartupPrerequisiteWorker()

    // Prevent an assertion failure from stranding the serial test worker.
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
        releasePreparation.signal()
    }
    let prerequisite = worker.submit(
        operation: { cancellation in
            try Data("durable first mutation".utf8).write(to: firstMutation, options: .atomic)
            releasePreparation.wait()
            try cancellation.checkCancellation()
            try Data("forbidden late mutation".utf8).write(to: forbiddenLateMutation, options: .atomic)
        },
        isGenerationCurrent: { true },
        completion: { _ in }
    )
    let mutationDeadline = ContinuousClock.now + .seconds(1)
    while !FileManager.default.fileExists(atPath: firstMutation.path),
          ContinuousClock.now < mutationDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(FileManager.default.fileExists(atPath: firstMutation.path))

    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: nil,
        ollamaProcess: nil,
        initialState: .startingHarness,
        stopProcess: { _, _ in Issue.record("No child process should exist in this fixture") },
        startReplacement: { Issue.record("A plain stop must not start a replacement") },
        startupPrerequisiteCancellation: prerequisite
    ))
    var stopResult: Result<Void, Error>?
    controller.stopOwnedServicesAndWait { stopResult = $0 }

    // Cancellation is cooperative. The public stop barrier must remain open
    // while the exact worker closure is paused inside its filesystem pass.
    #expect(prerequisite.isCancelled)
    #expect(!prerequisite.isSettled)
    #expect(stopResult == nil)
    #expect(controller.currentState == .startingHarness)

    releasePreparation.signal()
    let deadline = ContinuousClock.now + .seconds(2)
    while stopResult == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    let completed = try #require(stopResult)
    try completed.get()
    #expect(prerequisite.isSettled)
    #expect(controller.currentState == .stopped)
    #expect(!FileManager.default.fileExists(atPath: forbiddenLateMutation.path))

    // Once completion grants exclusive authority, the settled worker cannot
    // perform a delayed write into a home a restore may now rename.
    try await Task.sleep(for: .milliseconds(30))
    #expect(!FileManager.default.fileExists(atPath: forbiddenLateMutation.path))
}

@Test @MainActor
func bundleIntegrityVerificationRunsOffMainAndStopAwaitsItsExactSettlement() async throws {
    try await exercisePausedStartupPhase(.bundleIntegrity)
}

@Test @MainActor
func completeHarnessLaunchPreparationRunsOffMainAndStopAwaitsItsExactSettlement() async throws {
    try await exercisePausedStartupPhase(.harnessLaunchPlan)
}

@Test @MainActor
func harnessHomeDetectionPreflightRunsOffMainAndStopAwaitsItsExactSettlement() async throws {
    try await exercisePausedStartupPhase(.harnessHomePreflight)
}

@Test @MainActor
func cleanStateUndersizedHostEntersZeroInferenceProviderRecoveryBeforeOllama() async throws {
    let root = try makeHarnessControllerSecureSupportRoot(
        prefix: "fulmar-controller-undersized-host"
    )
    let support = root.appendingPathComponent("support", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            at: support,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: support.path
        )
        try runHarnessControllerFixtureChmod([
            "+a", "group:everyone deny delete", root.path
        ])
    } catch {
        try? runHarnessControllerFixtureChmod(["-N", root.path])
        try? FileManager.default.removeItem(at: root)
        throw error
    }
    defer {
        try? runHarnessControllerFixtureChmod(["-N", root.path])
        try? FileManager.default.removeItem(at: root)
    }
    let suite = "FulmarLifecycle.UndersizedHost.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }
    let settings = ModelProviderSettingsStore(defaults: defaults)
    #expect(try settings.load() == nil)

    var observedIssue: OllamaPrerequisiteRecoveryIssue?
    var states: [HarnessController.State] = []
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: nil,
        ollamaProcess: nil,
        initialState: .stopped,
        stopProcess: { _, _ in Issue.record("No child may exist before host admission") },
        startReplacement: { Issue.record("Host recovery must not request inference") },
        startOllamaPrerequisiteRecovery: { observedIssue = $0 },
        bundleIntegrityVerification: { true },
        physicalMemoryBytes: 8 * 1_073_741_824,
        modelSettingsStore: settings,
        deviceAttestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
    ), applicationSupportDirectory: support)
    controller.onStateChange = { states.append($0) }

    try await prepareHarnessHomeForLifecycleTest(controller)

    controller.prepareAndStart()
    let deadline = ContinuousClock.now + .seconds(2)
    while observedIssue == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    while !states.contains(.providerRecovery), ContinuousClock.now < deadline {
        await Task.yield()
    }

    let expected = OllamaPrerequisiteRecoveryIssue.insufficientPhysicalMemory(
        requiredBytes: QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes,
        availableBytes: 8 * 1_073_741_824
    )
    #expect(observedIssue == expected)
    #expect(controller.ollamaPrerequisiteRecoveryIssue == expected)
    #expect(controller.currentState == .providerRecovery)
    #expect(!states.contains(.startingOllama))
    #expect(states.contains(.checking))
    #expect(states.contains(.providerRecovery))
    #expect(controller.endpoint == nil)
    #expect(!controller.ownsHarness)
    #expect(!controller.ownsOllama)
    #expect(try settings.load()?.defaultSelection == .defaultLocal)
}

@MainActor
private func exercisePausedStartupPhase(_ targetPhase: RuntimeStartupPrerequisitePhase) async throws {
    let support = try makeHarnessControllerSecureSupportRoot(
        prefix: "fulmar-startup-phase-\(targetPhase.rawValue)"
    )
    defer { try? FileManager.default.removeItem(at: support) }
    let entered = support.appendingPathComponent("entered")
    let release = DispatchSemaphore(value: 0)
    let keyStore = LocalHarnessTestDeviceAttestationKeyStore()
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { release.signal() }

    let controller = HarnessController(
        lifecycleTestConfiguration: .init(
            harnessProcess: nil,
            ollamaProcess: nil,
            initialState: .stopped,
            stopProcess: { _, _ in Issue.record("No child process should exist in this fixture") },
            startReplacement: { Issue.record("A cancelled preparation must not launch") },
            startupPrerequisitePhaseHook: { phase, cancellation in
                guard phase == targetPhase else { return }
                try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
                try Data("entered".utf8).write(to: entered, options: .atomic)
                release.wait()
                try cancellation.checkCancellation()
            },
            bundleIntegrityVerification: { true },
            deviceAttestationKeyStore: keyStore
        ),
        applicationSupportDirectory: support
    )

    if targetPhase == .harnessLaunchPlan {
        try await prepareHarnessHomeForLifecycleTest(controller)
    }

    let startedAt = ContinuousClock.now
    controller.prepareProviderRecovery()
    #expect(ContinuousClock.now - startedAt < .milliseconds(250))
    let enteredDeadline = ContinuousClock.now + .seconds(1)
    while !FileManager.default.fileExists(atPath: entered.path),
          ContinuousClock.now < enteredDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(FileManager.default.fileExists(atPath: entered.path))

    var mainTurnRan = false
    DispatchQueue.main.async { mainTurnRan = true }
    try await Task.sleep(for: .milliseconds(30))
    #expect(mainTurnRan)

    var stopResult: Result<Void, Error>?
    controller.stopOwnedServicesAndWait { stopResult = $0 }
    #expect(stopResult == nil)
    #expect(controller.currentState != .stopped)

    release.signal()
    let stopDeadline = ContinuousClock.now + .seconds(2)
    while stopResult == nil, ContinuousClock.now < stopDeadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    try #require(stopResult).get()
    #expect(controller.currentState == .stopped)
    try await Task.sleep(for: .milliseconds(30))
    #expect(controller.currentState == .stopped)
}

@MainActor
private func prepareHarnessHomeForLifecycleTest(_ controller: HarnessController) async throws {
    var preparation: Result<Void, Error>?
    controller.prepareHarnessHomeForForegroundProviderHistoryGate { preparation = $0 }
    let deadline = ContinuousClock.now + .seconds(2)
    while preparation == nil, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    try #require(preparation).get()
}

@Test @MainActor
func overlappingControllerStopAndRestartsLatchOneReplacementAfterBothExits() throws {
    let harness = try launchLifecycleFixture()
    let ollama = try launchLifecycleFixture()
    defer {
        reapLifecycleFixture(harness)
        reapLifecycleFixture(ollama)
    }

    var stopRequests: [Int32] = []
    var stopReplies: [Int32: LifecycleStopReply] = [:]
    var replacementLaunches = 0
    var replacementObservedAfterBothExits = false
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: harness,
        ollamaProcess: ollama,
        initialState: .ready(managedByApp: true),
        stopProcess: { process, reply in
            stopRequests.append(process.processIdentifier)
            stopReplies[process.processIdentifier] = reply
        },
        startReplacement: {
            replacementLaunches += 1
            replacementObservedAfterBothExits = !harness.isRunning && !ollama.isRunning
        }
    ))
    var results: [Result<Void, Error>] = []

    // All three calls overlap the same in-flight two-process stop. The stop
    // completion is queued, while both restart requests coalesce into one
    // replacement latch owned by that generation.
    controller.stopOwnedServicesAndWait { results.append($0) }
    controller.restartServices { results.append($0) }
    controller.restartServices { results.append($0) }
    controller.prepareAndStart()

    #expect(stopRequests.count == 2)
    #expect(results.isEmpty)
    #expect(replacementLaunches == 0)

    reapLifecycleFixture(ollama)
    let ollamaReply = try #require(stopReplies[ollama.processIdentifier])
    ollamaReply(.success(()))

    #expect(results.isEmpty)
    #expect(replacementLaunches == 0)
    #expect(controller.ownsHarness)
    #expect(controller.ownsOllama)

    reapLifecycleFixture(harness)
    let harnessReply = try #require(stopReplies[harness.processIdentifier])
    harnessReply(.success(()))

    #expect(replacementLaunches == 1)
    #expect(replacementObservedAfterBothExits)
    #expect(results.count == 3)
    for result in results { try result.get() }
    #expect(controller.currentState == .stopped)
    #expect(!controller.ownsHarness)
    #expect(!controller.ownsOllama)
}

@Test @MainActor
func stopBarrierPreservesTheLatestExactInferenceOrRecoveryLaunchMode() throws {
    func run(latestIsRecovery: Bool) throws -> Bool? {
        // The replacement latch sits behind Application Support admission,
        // which rejects the isolated qualification home's `/tmp` alias and
        // must never touch this account's real state. Admit an exact private
        // root instead, as the other controller tests do.
        let support = try makeHarnessControllerSecureSupportRoot(prefix: "fulmar-controller-launch-mode")
        defer { try? FileManager.default.removeItem(at: support) }
        let harness = try launchLifecycleFixture()
        defer { reapLifecycleFixture(harness) }
        var stopReply: LifecycleStopReply?
        var observedRecovery: Bool?
        let controller = HarnessController(
            lifecycleTestConfiguration: .init(
                harnessProcess: harness,
                ollamaProcess: nil,
                initialState: .ready(managedByApp: true),
                stopProcess: { process, reply in
                    #expect(process === harness)
                    stopReply = reply
                },
                startReplacement: {}
            ),
            applicationSupportDirectory: support
        )
        controller.lifecycleReplacementModeObserver = { observedRecovery = $0 }

        controller.stopOwnedServicesAndWait { result in
            if case .failure(let error) = result { Issue.record("Unexpected stop failure: \(error)") }
        }
        if latestIsRecovery {
            controller.prepareAndStart()
            controller.prepareProviderRecovery()
        } else {
            controller.prepareProviderRecovery()
            controller.prepareAndStart()
        }

        reapLifecycleFixture(harness)
        let reply = try #require(stopReply)
        reply(.success(()))
        return observedRecovery
    }

    #expect(try run(latestIsRecovery: true) == true)
    #expect(try run(latestIsRecovery: false) == false)
}

@Test @MainActor
func explicitStopCancelsAnInFlightRestartBeforeApplicationExit() throws {
    let harness = try launchLifecycleFixture()
    let ollama = try launchLifecycleFixture()
    defer {
        reapLifecycleFixture(harness)
        reapLifecycleFixture(ollama)
    }

    var stopReplies: [Int32: LifecycleStopReply] = [:]
    var replacementLaunches = 0
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: harness,
        ollamaProcess: ollama,
        initialState: .ready(managedByApp: true),
        stopProcess: { process, reply in stopReplies[process.processIdentifier] = reply },
        startReplacement: { replacementLaunches += 1 }
    ))
    var results: [Result<Void, Error>] = []

    controller.restartServices { results.append($0) }
    // This is the ordering used when Quit arrives during an in-flight UI
    // restart. The application stop is authoritative and must prevent a new
    // child from escaping the termination barrier's exact captured PID set.
    controller.stopOwnedServicesAndWait { results.append($0) }

    reapLifecycleFixture(harness)
    let harnessReply = try #require(stopReplies[harness.processIdentifier])
    harnessReply(.success(()))
    #expect(replacementLaunches == 0)
    #expect(results.isEmpty)

    reapLifecycleFixture(ollama)
    let ollamaReply = try #require(stopReplies[ollama.processIdentifier])
    ollamaReply(.success(()))

    #expect(replacementLaunches == 0)
    #expect(results.count == 2)
    for result in results { try result.get() }
    #expect(controller.currentState == .stopped)
    #expect(!controller.ownsHarness)
    #expect(!controller.ownsOllama)
}

@Test @MainActor
func terminalShutdownMakesConcurrentRestartsAndLateStartCallbacksInert() throws {
    let harness = try launchLifecycleFixture()
    let ollama = try launchLifecycleFixture()
    defer {
        reapLifecycleFixture(harness)
        reapLifecycleFixture(ollama)
    }

    var stopRequests: [Int32] = []
    var stopReplies: [Int32: LifecycleStopReply] = [:]
    var replacementLaunches = 0
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: harness,
        ollamaProcess: ollama,
        initialState: .ready(managedByApp: true),
        stopProcess: { process, reply in
            stopRequests.append(process.processIdentifier)
            stopReplies[process.processIdentifier] = reply
        },
        startReplacement: { replacementLaunches += 1 }
    ))
    var queuedRestartResult: Result<Void, Error>?
    var terminationResult: Result<Void, Error>?
    var concurrentRestartResult: Result<Void, Error>?
    var ollamaOnlyResult: Result<Void, Error>?

    controller.restartServices { queuedRestartResult = $0 }
    controller.stopOwnedServicesForApplicationTermination { terminationResult = $0 }
    controller.restartServices { concurrentRestartResult = $0 }
    controller.prepareAndStart() // Simulates a late startup/migration callback.
    controller.prepareOllamaOnly { ollamaOnlyResult = $0 }

    #expect(stopRequests.count == 2)
    #expect(replacementLaunches == 0)
    #expect(queuedRestartResult == nil)
    #expect(terminationResult == nil)
    guard case .failure? = concurrentRestartResult else {
        Issue.record("A concurrent restart must fail after terminal shutdown latches")
        return
    }
    guard case .failure? = ollamaOnlyResult else {
        Issue.record("Ollama-only startup must fail after terminal shutdown latches")
        return
    }

    reapLifecycleFixture(harness)
    let harnessReply = try #require(stopReplies[harness.processIdentifier])
    harnessReply(.success(()))
    #expect(replacementLaunches == 0)
    #expect(queuedRestartResult == nil)
    #expect(terminationResult == nil)

    reapLifecycleFixture(ollama)
    let ollamaReply = try #require(stopReplies[ollama.processIdentifier])
    ollamaReply(.success(()))

    let completedQueuedRestart = try #require(queuedRestartResult)
    let completedTermination = try #require(terminationResult)
    try completedQueuedRestart.get()
    try completedTermination.get()
    #expect(replacementLaunches == 0)
    #expect(controller.currentState == .stopped)

    // The latch is process-lifetime irreversible. Callbacks arriving after the
    // exact stop barrier and new UI restart requests remain unable to launch.
    controller.prepareAndStart()
    var lateRestartResult: Result<Void, Error>?
    controller.restartServices { lateRestartResult = $0 }
    #expect(replacementLaunches == 0)
    guard case .failure? = lateRestartResult else {
        Issue.record("A late restart must remain rejected after terminal shutdown")
        return
    }
}

@Test @MainActor
func controllerRejectsPrematureStopRepliesAndKeepsOwnedProcesses() throws {
    let harness = try launchLifecycleFixture()
    let ollama = try launchLifecycleFixture()
    defer {
        reapLifecycleFixture(harness)
        reapLifecycleFixture(ollama)
    }

    var stopReplies: [Int32: LifecycleStopReply] = [:]
    var replacementLaunches = 0
    let controller = HarnessController(lifecycleTestConfiguration: .init(
        harnessProcess: harness,
        ollamaProcess: ollama,
        initialState: .ready(managedByApp: true),
        stopProcess: { process, reply in stopReplies[process.processIdentifier] = reply },
        startReplacement: { replacementLaunches += 1 }
    ))
    var result: Result<Void, Error>?

    controller.restartServices { result = $0 }
    let harnessReply = try #require(stopReplies[harness.processIdentifier])
    let ollamaReply = try #require(stopReplies[ollama.processIdentifier])
    harnessReply(.success(()))
    ollamaReply(.success(()))

    #expect(replacementLaunches == 0)
    #expect(controller.ownsHarness)
    #expect(controller.ownsOllama)
    guard case .failure? = result else {
        Issue.record("A stopper reply while the captured PIDs are alive must fail closed")
        return
    }
    if case .failed = controller.currentState {} else {
        Issue.record("Premature stop replies must publish a failed state, never stopped")
    }
}
