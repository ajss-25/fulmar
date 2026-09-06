import AppKit
import Carbon
import Darwin
import LocalHarnessApplicationSupportAdmission
import LocalHarnessUpdateSecurity
import UniformTypeIdentifiers
import WebKit

private final class RuntimeAdmissionQuiescenceState: @unchecked Sendable {
    typealias Drain = @Sendable () async throws -> Void

    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var drainTasks: [Task<Void, Never>] = []
    private var timeoutTask: Task<Void, Never>?
    private var remaining = 3
    private var firstError: Error?
    private var terminalCancellation = false
    private var completed = false

    func start(
        continuation: CheckedContinuation<Void, Error>,
        drains: [Drain],
        timeoutNanoseconds: UInt64
    ) {
        precondition(drains.count == remaining)
        lock.lock()
        if completed {
            let cancelled = terminalCancellation
            lock.unlock()
            if cancelled {
                continuation.resume(throwing: CancellationError())
            } else {
                continuation.resume()
            }
            return
        }
        self.continuation = continuation
        drainTasks = drains.map { drain in
            Task.detached(priority: .userInitiated) { [weak self] in
                do {
                    try await drain()
                    self?.settled(error: nil)
                } catch {
                    self?.settled(error: error)
                }
            }
        }
        timeoutTask = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
            } catch {
                return
            }
            self?.timedOut()
        }
        lock.unlock()
    }

    func cancel() {
        finish(cancelled: true, ignoreDrainErrors: true)
    }

    private func settled(error: Error?) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        if firstError == nil { firstError = error }
        remaining -= 1
        guard remaining == 0 else {
            lock.unlock()
            return
        }
        completed = true
        let continuation = self.continuation
        self.continuation = nil
        let timeoutTask = self.timeoutTask
        self.timeoutTask = nil
        drainTasks.removeAll()
        let firstError = self.firstError
        lock.unlock()
        timeoutTask?.cancel()
        if let firstError {
            continuation?.resume(throwing: firstError)
        } else {
            continuation?.resume()
        }
    }

    private func timedOut() {
        // The exact owned-process stop which follows this admission barrier is
        // authoritative. A cancellation-ignoring RPC drain must not prevent it
        // from running, so timeout completes the barrier normally after asking
        // the detached drains to cancel; it never awaits those tasks.
        finish(cancelled: false, ignoreDrainErrors: true)
    }

    private func finish(cancelled: Bool, ignoreDrainErrors: Bool) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        terminalCancellation = cancelled
        let continuation = self.continuation
        self.continuation = nil
        let tasks = drainTasks
        drainTasks.removeAll()
        let timeoutTask = self.timeoutTask
        self.timeoutTask = nil
        let firstError = self.firstError
        lock.unlock()
        timeoutTask?.cancel()
        tasks.forEach { $0.cancel() }
        if cancelled {
            continuation?.resume(throwing: CancellationError())
        } else if !ignoreDrainErrors, let firstError {
            continuation?.resume(throwing: firstError)
        } else {
            continuation?.resume()
        }
    }
}

/// One shared, monotonic-bounded barrier for every runtime-stop path that can
/// overlap native task creation. All three drains begin together. If a drain
/// ignores cancellation, the barrier yields after twenty seconds so the exact
/// owned-process stop can remain the authoritative cleanup boundary.
struct RuntimeAdmissionQuiescenceBarrier: Sendable {
    let schedules: @Sendable () async throws -> Void
    let conversations: @Sendable () async throws -> Void
    let history: @Sendable () async throws -> Void
    private let timeoutNanoseconds: UInt64

    init(
        schedules: @escaping @Sendable () async throws -> Void,
        conversations: @escaping @Sendable () async throws -> Void,
        history: @escaping @Sendable () async throws -> Void,
        timeout: TimeInterval = 20
    ) {
        self.schedules = schedules
        self.conversations = conversations
        self.history = history
        let bounded = timeout.isFinite && timeout > 0 ? min(timeout, 20) : 20
        timeoutNanoseconds = UInt64(bounded * 1_000_000_000)
    }

    func quiesce() async throws {
        let state = RuntimeAdmissionQuiescenceState()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                state.start(
                    continuation: continuation,
                    drains: [schedules, conversations, history],
                    timeoutNanoseconds: timeoutNanoseconds
                )
            }
        } onCancel: {
            state.cancel()
        }
    }
}

enum ProtectedThermalRecoveryDecision: Equatable, Sendable {
    case restartRuntime
    case deferToProtectedTransition
}

enum ThermalNormalModeRecoveryBoundary: String, Equatable, Sendable {
    case startup
    case ecoCleared
    case cooldownRecovered
}

struct ThermalNormalModeRecoveryFailure: Error, Equatable, LocalizedError, Sendable {
    let boundary: ThermalNormalModeRecoveryBoundary
    let reason: String

    var errorDescription: String? {
        switch boundary {
        case .startup:
            return "Fulmar could not verify its Normal workload policy at startup. New local work remains blocked until policy repair succeeds. \(reason)"
        case .ecoCleared:
            return "Fulmar could not verify its Normal workload policy after Eco recovery. New local work and any memory-pressure hold remain blocked until policy repair succeeds. \(reason)"
        case .cooldownRecovered:
            return "Fulmar could not verify its Normal workload policy after cooldown. Local AI remains paused and will not restart yet. \(reason)"
        }
    }
}

struct ThermalWorkloadModeWriter {
    let write: @MainActor (ThermalWorkloadMode, URL) throws -> Void

    static let live = ThermalWorkloadModeWriter { mode, applicationSupport in
        try ThermalWorkloadPolicyStore.setMode(
            mode,
            applicationSupport: applicationSupport
        )
    }
}

/// One route-aware decision shared by foreground startup, foreground Ready
/// publication, and background inference promotion. Retained local thermal
/// state can never block a cloud/custom route, while an unverified Normal
/// policy or memory-pressure hold closes every new app-owned local admission.
enum ThermalRuntimeAdmissionPolicy {
    static func blocksSelectedLocalRuntime(
        localRuntimeSelected: Bool,
        normalModeRecoveryPending: Bool,
        phase: ThermalSafetyPhase,
        memoryPressureBlocksNewLocalGeneration: Bool
    ) -> Bool {
        localRuntimeSelected && (
            normalModeRecoveryPending
                || phase.blocksNewLocalGeneration
                || memoryPressureBlocksNewLocalGeneration
        )
    }

    @discardableResult
    static func promoteIfAdmitted(
        selectedLocalRuntimeBlocked: Bool,
        promote: () -> Bool
    ) -> Bool {
        guard !selectedLocalRuntimeBlocked else { return false }
        return promote()
    }

    static func permitsRuntimeStart(
        selectedLocalRuntimeBlocked: Bool,
        providerControlPlaneOnly: Bool
    ) -> Bool {
        providerControlPlaneOnly || !selectedLocalRuntimeBlocked
    }
}

/// Keeps every Ready-only side effect behind one auditable branch. Tests can
/// inject an ordered effect trace without constructing AppKit windows or a
/// real runtime, while production passes the complete Ready publication as
/// the admitted closure.
enum ThermalReadyStateAdmissionGate {
    @discardableResult
    static func perform(
        selectedLocalRuntimeBlocked: Bool,
        onBlocked: () -> Void,
        onAdmitted: () -> Void
    ) -> Bool {
        guard !selectedLocalRuntimeBlocked else {
            onBlocked()
            return false
        }
        onAdmitted()
        return true
    }
}

struct ThermalReadyFinalizationGate {
    enum RecoveryDecision: Equatable {
        case none
        case awaitTopology
        case finalizeVerifiedRuntime
        case restartAfterIdentityChange
    }

    private enum Verification: Equatable {
        case awaitingTopology
        case verified
    }

    private struct Token: Equatable {
        let generation: UUID
        let endpoint: HarnessEndpoint
        var verification: Verification
        var identityChanged: Bool
    }

    private var token: Token?

    var isPending: Bool { token != nil }

    mutating func deferAwaitingTopology(
        generation: UUID,
        endpoint: HarnessEndpoint
    ) {
        if var token {
            guard token.generation == generation,
                  token.endpoint == endpoint,
                  !token.identityChanged else {
                token.identityChanged = true
                self.token = token
                return
            }
            token.verification = .awaitingTopology
            self.token = token
            return
        }
        token = Token(
            generation: generation,
            endpoint: endpoint,
            verification: .awaitingTopology,
            identityChanged: false
        )
    }

    mutating func deferVerifiedTopology(
        generation: UUID,
        endpoint: HarnessEndpoint
    ) {
        if var token {
            guard token.generation == generation,
                  token.endpoint == endpoint,
                  !token.identityChanged else {
                token.identityChanged = true
                self.token = token
                return
            }
            token.verification = .verified
            self.token = token
            return
        }
        token = Token(
            generation: generation,
            endpoint: endpoint,
            verification: .verified,
            identityChanged: false
        )
    }

    mutating func endpointDidChange(to endpoint: HarnessEndpoint?) {
        guard var token, token.endpoint != endpoint else { return }
        // Keep the token so verified recovery takes the exact-stop/restart path.
        // Clearing it here would strand a replacement endpoint in control-plane
        // mode, while accepting a later change back could promote an identity
        // that was not continuously bound to the verified topology result.
        token.identityChanged = true
        self.token = token
    }

    mutating func clear() {
        token = nil
    }

    mutating func recoveryDecision(
        currentGeneration: UUID,
        currentEndpoint: HarnessEndpoint?,
        runtimeIsReady: Bool
    ) -> RecoveryDecision {
        guard let token else { return .none }
        guard runtimeIsReady,
              !token.identityChanged,
              token.generation == currentGeneration,
              token.endpoint == currentEndpoint else {
            self.token = nil
            return .restartAfterIdentityChange
        }
        switch token.verification {
        case .awaitingTopology:
            return .awaitTopology
        case .verified:
            self.token = nil
            return .finalizeVerifiedRuntime
        }
    }
}

/// Thermal protection may stop the runtime immediately while a protected
/// provider/state mutation still owns its exact permit. Cooldown must not
/// launch or publish an independent inference runtime underneath that permit;
/// the protected coordinator's verified inference waiter is the only allowed
/// reopening path until the transition settles.
enum ProtectedThermalRecoveryPolicy {
    static func recoveryDecision(
        protectedTransitionInFlight: Bool
    ) -> ProtectedThermalRecoveryDecision {
        protectedTransitionInFlight ? .deferToProtectedTransition : .restartRuntime
    }

    static func mayPublishReady(
        protectedTransitionInFlight: Bool,
        protectedInferenceStartIsWaiting: Bool
    ) -> Bool {
        !protectedTransitionInFlight || protectedInferenceStartIsWaiting
    }
}

@MainActor
enum ApplicationLaunchPolicy {
    static func activationPolicy(arguments: [String]) -> NSApplication.ActivationPolicy {
        arguments.contains("--background-schedule")
            || arguments.contains("--headless-handoff-acceptance")
            ? .accessory
            : .regular
    }
}

/// Serialises the one exceptional transition from the scheduler's accessory
/// process into a fresh foreground application. The foreground process is
/// never launched until the existing protected termination barrier has
/// quiesced schedules/conversations and stopped every exact owned runtime.
struct HeadlessForegroundHandoff: Equatable {
    enum Phase: Equatable {
        case idle
        case stoppingOwnedWork
        case relaunchingAfterStop(deferredTerminationReply: Bool)
        case stoppedAwaitingRetry
    }

    enum RequestAction: Equatable {
        case beginProtectedTermination
        case relaunchStoppedProcess
        case none
    }

    enum StopAction: Equatable {
        case relaunchBeforeTerminationReply
        case none
    }

    enum RelaunchAction: Equatable {
        case finishDeferredTermination
        case terminatePreparedProcess
        case remainStoppedForRetry
        case none
    }

    private(set) var phase: Phase = .idle

    mutating func requestForeground() -> RequestAction {
        switch phase {
        case .idle:
            phase = .stoppingOwnedWork
            return .beginProtectedTermination
        case .stoppedAwaitingRetry:
            phase = .relaunchingAfterStop(deferredTerminationReply: false)
            return .relaunchStoppedProcess
        case .stoppingOwnedWork, .relaunchingAfterStop:
            return .none
        }
    }

    mutating func protectedStopSucceeded() -> StopAction {
        guard phase == .stoppingOwnedWork else { return .none }
        phase = .relaunchingAfterStop(deferredTerminationReply: true)
        return .relaunchBeforeTerminationReply
    }

    @discardableResult
    mutating func protectedStopFailed() -> Bool {
        guard phase == .stoppingOwnedWork else { return false }
        phase = .idle
        return true
    }

    mutating func relaunchCompleted(succeeded: Bool) -> RelaunchAction {
        guard case .relaunchingAfterStop(let deferred) = phase else { return .none }
        if succeeded {
            phase = .idle
            return deferred ? .finishDeferredTermination : .terminatePreparedProcess
        }
        phase = .stoppedAwaitingRetry
        return .remainStoppedForRetry
    }

    mutating func lateRelaunchSucceeded() -> RelaunchAction {
        guard phase == .stoppedAwaitingRetry else { return .none }
        phase = .idle
        return .terminatePreparedProcess
    }
}

@main
@MainActor
enum LocalHarnessApp {
    // NSApplication.delegate is weak. The optimized production binary must
    // retain its application delegate for the entire event-loop lifetime;
    // otherwise every window and owned runtime controller can disappear after
    // applicationDidFinishLaunching returns, leaving a headless idle process.
    static func main() {
        if let status = CredentialMigrationXPCAcceptanceLaunch.runIfRequested(
            arguments: CommandLine.arguments,
            executableURL: Bundle.main.executableURL
                ?? URL(
                    fileURLWithPath: CommandLine.arguments.first ?? "",
                    isDirectory: false
                )
        ) {
            Darwin.exit(status)
        }
        let postInstallHealthContext: UpdatePostInstallHealthContext?
        do {
            postInstallHealthContext = try UpdatePostInstallHealthContext.resolveIfRequested()
        } catch {
            fputs("Fulmar post-install health channel refused: \(error.localizedDescription)\n", stderr)
            Darwin.exit(EX_CONFIG)
        }
        if postInstallHealthContext == nil {
            let updates = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(
                    "Library/Application Support/Local Harness/Updates",
                    isDirectory: true
                )
                .standardizedFileURL
            let journalStore = UpdateInstallJournalStore(updatesRoot: updates)
            let pendingDetected: Bool
            do { pendingDetected = try journalStore.pendingTransactionExists() }
            catch { pendingDetected = true }
            if pendingDetected {
                let recoveryDetail: String
                if let record = try? journalStore.load() {
                    recoveryDetail = "The authenticated transaction is in phase \(record.phase.rawValue). The exact prior app remains at \(record.rollbackApplicationPath)."
                } else {
                    recoveryDetail = "The private transaction journal is torn, linked, or unauthenticated. Preserve the Updates directory for manual recovery."
                }
                let message = "An interrupted Fulmar replacement was detected. No runtime or agent work was started. \(recoveryDetail)"
                fputs("\(message)\n", stderr)
                let app = NSApplication.shared
                app.setActivationPolicy(.regular)
                app.activate(ignoringOtherApps: true)
                let alert = NSAlert()
                alert.alertStyle = .critical
                alert.messageText = "Fulmar update recovery is required"
                alert.informativeText = message
                alert.addButton(withTitle: "Quit")
                alert.runModal()
                Darwin.exit(EX_TEMPFAIL)
            }
        }
        let physicalHandoffAcceptance: PhysicalHandoffAcceptanceEnvironment?
        do {
            physicalHandoffAcceptance = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested()
        } catch {
            fputs("Fulmar physical handoff acceptance refused: \(error.localizedDescription)\n", stderr)
            Darwin.exit(EX_CONFIG)
        }
        if AppOwnedOllamaGenerationCanary.isRequested() {
            Darwin.exit(AppOwnedOllamaGenerationCanary.run())
        }
        let app = NSApplication.shared
        // Establish the final activation policy before AppKit starts its event
        // loop. Creating a status item during a late prohibited -> regular
        // transition can strand its window below the screen even when the menu
        // bar has room.
        app.setActivationPolicy(ApplicationLaunchPolicy.activationPolicy(arguments: CommandLine.arguments))
        let delegate = AppDelegate(
            physicalHandoffAcceptance: physicalHandoffAcceptance,
            postInstallHealthContext: postInstallHealthContext
        )
        app.delegate = delegate
        withExtendedLifetime(delegate) {
            app.run()
        }
    }
}

enum ProviderRecoveryContext: Equatable {
    case nativeState(NativeProviderStateInspection)
    case routeVerification(String?)
    case ollamaPrerequisite(OllamaPrerequisiteRecoveryIssue)
    case localModelSelectionRequired(String?)

    var inspection: NativeProviderStateInspection? {
        guard case .nativeState(let inspection) = self else { return nil }
        return inspection
    }

    var allowsInstalledLocalModelChoice: Bool {
        switch self {
        case .ollamaPrerequisite, .localModelSelectionRequired: return true
        case .nativeState, .routeVerification: return false
        }
    }

    var userMessage: String {
        switch self {
        case .nativeState(let inspection):
            if !inspection.issues.isEmpty {
                return "Provider settings need recovery. Agent tasks, Chat, history, and schedules remain blocked. You can preserve and reset only the damaged records, or repair the provider configuration first."
            }
            return "The selected cloud provider no longer has matching endpoint consent. Agent work remains blocked while you repair or choose a provider."
        case .routeVerification(let diagnostic):
            let summary = "The selected provider, credential, model, or endpoint could not be verified. Agent work remains blocked while you repair or choose a provider."
            guard let diagnostic, !diagnostic.isEmpty else { return summary }
            return "\(summary) Verification detail: \(diagnostic)"
        case .ollamaPrerequisite(let issue):
            if case .insufficientPhysicalMemory = issue {
                return "The release-qualified local model is not supported on this Mac: \(issue.localizedDescription) Agent tasks, Chat, history, schedules, skills, and MCP remain blocked. Choose an installed compatibility model or explicitly configure and consent to a cloud or custom provider in Models & Providers."
            }
            return "Your selected local model runtime is unavailable: \(issue.localizedDescription) Agent tasks, Chat, history, schedules, skills, and MCP remain blocked. You can repair Ollama or choose and verify a cloud or custom provider in Models & Providers."
        case .localModelSelectionRequired(let diagnostic):
            let summary = "The selected local model is missing or is not compatible with Fulmar's agent requirements. Agent work remains blocked. Choose an installed tool-capable local model, or configure an API provider."
            guard let diagnostic, !diagnostic.isEmpty else { return summary }
            return "\(summary) Verification detail: \(diagnostic)"
        }
    }
}

struct SkillSessionDisclosurePrompt: Equatable {
    let displayedNames: [String]
    let additionalCount: Int
}

enum SkillSessionDisclosurePresentation {
    static let maximumDisplayedSkills = 12
    static let maximumNameCharacters = 120

    static func prompt(for skills: [InstalledSkill]) -> SkillSessionDisclosurePrompt {
        let displayed = skills.prefix(maximumDisplayedSkills).map { safeName($0.name) }
        return SkillSessionDisclosurePrompt(
            displayedNames: displayed,
            additionalCount: max(0, skills.count - displayed.count)
        )
    }

    static func safeName(_ value: String) -> String {
        var scalars: [UnicodeScalar] = []
        scalars.reserveCapacity(min(value.unicodeScalars.count, maximumNameCharacters * 2))
        for scalar in value.unicodeScalars.prefix(maximumNameCharacters * 4) {
            switch scalar.value {
            case 0x09, 0x0A, 0x0D:
                scalars.append(" ")
            default:
                guard !CharacterSet.controlCharacters.contains(scalar),
                      scalar.properties.generalCategory != .format else { continue }
                scalars.append(scalar)
            }
        }
        let flattened = String(String.UnicodeScalarView(scalars))
            .split(whereSeparator: \.isWhitespace)
            .joined(separator: " ")
        let bounded = String(flattened.prefix(maximumNameCharacters))
        return bounded.isEmpty ? "Unnamed reviewed skill" : bounded
    }
}

@MainActor
struct SkillSessionDisclosureInteractions {
    var confirm: (SkillSessionDisclosurePrompt) -> Bool

    static let live = SkillSessionDisclosureInteractions { prompt in
        let names = prompt.displayedNames.joined(separator: ", ")
        let extra = prompt.additionalCount > 0 ? " and \(prompt.additionalCount) more" : ""
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Share reviewed skills with this external session?"
        alert.informativeText = "These skills are set to Ask Every Time: \(names)\(extra). Their instructions and selected resources may be sent to the active network or cloud model. This permission lasts only for the current app session."
        alert.addButton(withTitle: "Allow This Session")
        alert.addButton(withTitle: "Keep Skills Local")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

@MainActor
enum SkillSessionDisclosureCoordinator {
    static func approvals(
        for skills: [InstalledSkill],
        interactions: SkillSessionDisclosureInteractions
    ) -> Set<String> {
        guard !skills.isEmpty,
              interactions.confirm(SkillSessionDisclosurePresentation.prompt(for: skills)) else {
            return []
        }
        return Set(skills.map(\.id))
    }
}

enum HarnessHomeRecoveryInitialChoice: Equatable {
    case preserveSettingsAndRepair
    case preserveAndStartClean
    case keepStopped
}

enum HarnessHomeRecoveryAuthorizationChoice: Equatable {
    case authorizeAndRetry
    case openRecoveryFolder
    case keepStopped
}

enum HarnessHomeRecoveryPresentation {
    static func initialChoice(for response: NSApplication.ModalResponse) -> HarnessHomeRecoveryInitialChoice {
        switch response {
        case .alertFirstButtonReturn: return .preserveSettingsAndRepair
        case .alertSecondButtonReturn: return .preserveAndStartClean
        default: return .keepStopped
        }
    }

    static func authorizationChoice(
        for response: NSApplication.ModalResponse
    ) -> HarnessHomeRecoveryAuthorizationChoice {
        switch response {
        case .alertFirstButtonReturn: return .authorizeAndRetry
        case .alertSecondButtonReturn: return .openRecoveryFolder
        default: return .keepStopped
        }
    }
}

struct HarnessHomeRecoveryCompletionGate {
    private(set) var completed = false

    @discardableResult
    mutating func finish(
        receipt: HarnessHomeReceiptlessRecoveryReceipt,
        openPreservedCopy: Bool,
        reveal: (URL) -> Void,
        restart: () -> Void
    ) -> Bool {
        guard !completed else { return false }
        completed = true
        if openPreservedCopy { reveal(receipt.quarantine) }
        restart()
        return true
    }

    mutating func reset() { completed = false }
}

/// One main-actor token spans the complete prompt → authorization → recovery →
/// receipt presentation → acknowledgement sequence. Quit invalidates it before
/// the termination barrier can await, making every nested-modal response and
/// asynchronous completion from the old sequence inert.
@MainActor
struct HarnessHomeRecoveryPresentationGate {
    struct Token: Equatable {
        fileprivate let id: UUID
    }

    private var activeToken: Token?
    private var boundInitialChoice: ProviderHistoryRecoveryChoice?
    private var boundInterruptedIntent: HarnessHomeInterruptedRecoveryIntent?
    private var terminationBegun = false

    mutating func begin() -> Token? {
        guard !terminationBegun, activeToken == nil else { return nil }
        let token = Token(id: UUID())
        activeToken = token
        boundInitialChoice = nil
        boundInterruptedIntent = nil
        return token
    }

    func admits(_ token: Token) -> Bool {
        !terminationBegun && activeToken == token
    }

    @discardableResult
    mutating func bindInitialChoice(
        _ choice: ProviderHistoryRecoveryChoice,
        to token: Token
    ) -> Bool {
        guard admits(token), boundInitialChoice == nil else { return false }
        boundInitialChoice = choice
        return true
    }

    func initialChoice(for token: Token) -> ProviderHistoryRecoveryChoice? {
        admits(token) ? boundInitialChoice : nil
    }

    @discardableResult
    mutating func bindInterruptedIntent(
        _ intent: HarnessHomeInterruptedRecoveryIntent,
        to token: Token
    ) -> Bool {
        guard admits(token), boundInterruptedIntent == nil else { return false }
        boundInterruptedIntent = intent
        return true
    }

    func interruptedIntent(for token: Token) -> HarnessHomeInterruptedRecoveryIntent? {
        admits(token) ? boundInterruptedIntent : nil
    }

    @discardableResult
    mutating func finish(_ token: Token) -> Bool {
        guard admits(token) else { return false }
        activeToken = nil
        boundInitialChoice = nil
        boundInterruptedIntent = nil
        return true
    }

    mutating func latchTermination() {
        terminationBegun = true
        activeToken = nil
        boundInitialChoice = nil
        boundInterruptedIntent = nil
    }
}

/// Main-actor admission owned by the first-start credential migration before
/// its asynchronous helper can be dispatched. The protected-runtime
/// coordinator cannot own this startup path without starting inference ahead
/// of the mandatory pre-upgrade backup/recovery flow, so Quit observes this
/// narrower gate until migration settles. A monotonic token prevents a stale
/// completion from releasing a newer migration or starting the runtime.
@MainActor
final class StartupCredentialMigrationLifecycleGate {
    struct Permit: Equatable {
        fileprivate let id: UUID
    }

    enum AdmissionError: Error, Equatable {
        case busy
        case terminating
    }

    private var activePermit: Permit?
    private var terminationBegun = false

    var isMigrationInFlight: Bool { activePermit != nil }
    var permitsRuntimeContinuation: Bool { !terminationBegun }

    func beginMigration() throws -> Permit {
        guard !terminationBegun else { throw AdmissionError.terminating }
        guard activePermit == nil else { throw AdmissionError.busy }
        let permit = Permit(id: UUID())
        activePermit = permit
        return permit
    }

    /// Returns false for a stale/duplicate completion. The continuation runs
    /// synchronously on the main actor only after the exact permit is released,
    /// so Quit cannot interleave between release and startup continuation.
    @discardableResult
    func finish(
        _ permit: Permit,
        continueAfter: Bool,
        continuation: () -> Void
    ) -> Bool {
        guard activePermit == permit else { return false }
        activePermit = nil
        guard continueAfter, !terminationBegun else { return true }
        continuation()
        return true
    }

    /// Ordinary Quit is rejected while migration is active. Once idle, this
    /// latch is irreversible for the process lifetime, matching the global
    /// protected-runtime coordinator's termination admission boundary.
    @discardableResult
    func beginTermination() -> Bool {
        guard activePermit == nil else { return false }
        terminationBegun = true
        return true
    }

    /// AppKit can deliver applicationWillTerminate through a nonstandard path
    /// that did not consult applicationShouldTerminate. It is too late to delay
    /// exit there, but late callbacks must still be unable to launch a runtime.
    func latchUnconditionalTermination() {
        terminationBegun = true
    }
}

@MainActor
struct HarnessHomeRecoveryInteractions {
    var chooseInitial: (URL, URL) -> HarnessHomeRecoveryInitialChoice
    var chooseInterrupted: (URL) -> HarnessHomeRecoveryAuthorizationChoice
    var chooseAuthorization: (URL) -> HarnessHomeRecoveryAuthorizationChoice
    var showSuccess: (HarnessHomeReceiptlessRecoveryReceipt) -> Bool
    var showFailure: (String, URL) -> Bool
    var reveal: (URL) -> Void

    static let live = HarnessHomeRecoveryInteractions(
        chooseInitial: { existingHome, recoveryFolder in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Preserve historical provider data before starting?"
            alert.informativeText = "Fulmar found a Harness home from an older provider-history privacy epoch. Nothing inside it has been listed, parsed, or changed, and all agent work is stopped. Fulmar can preserve that whole home opaquely, then either copy only the two exact settings files into a fresh home or start completely clean. Sessions, storage, attachments, profiles, Skills, and unknown entries always remain only in the preserved copy.\n\nExisting home: \(existingHome.path)\nRecovery folder: \(recoveryFolder.path)"
            alert.addButton(withTitle: "Preserve, Keep Settings, and Start")
            alert.addButton(withTitle: "Preserve and Start Clean")
            alert.addButton(withTitle: "Keep Stopped")
            return HarnessHomeRecoveryPresentation.initialChoice(for: alert.runModal())
        },
        chooseInterrupted: { recoveryFolder in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Resume the interrupted Harness-home recovery?"
            alert.informativeText = "Fulmar found an authenticated recovery transaction that did not finish. Detection accessed no credential and changed no data. To resume the exact transaction, explicitly authorize the existing device-only key so Fulmar can authenticate the journal before continuing.\n\nRecovery folder: \(recoveryFolder.path)"
            alert.addButton(withTitle: "Authorize Existing Key and Resume")
            alert.addButton(withTitle: "Open Recovery Folder")
            alert.addButton(withTitle: "Keep Stopped")
            return HarnessHomeRecoveryPresentation.authorizationChoice(for: alert.runModal())
        },
        chooseAuthorization: { recoveryFolder in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Authorize the existing recovery key?"
            alert.informativeText = "macOS must authorize Fulmar's existing device-only key before the authenticated recovery journal can be verified. This happens only because you chose a preserve-and-start option. Keeping the runtime stopped performs no recovery.\n\nRecovery folder: \(recoveryFolder.path)"
            alert.addButton(withTitle: "Authorize and Retry")
            alert.addButton(withTitle: "Open Recovery Folder")
            alert.addButton(withTitle: "Keep Stopped")
            return HarnessHomeRecoveryPresentation.authorizationChoice(for: alert.runModal())
        },
        showSuccess: { receipt in
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = "Historical provider state was preserved"
            alert.informativeText = "Fulmar created and verified a privacy-epoch-current Harness home. The historical provider state remains opaque and preserved at:\n\n\(receipt.quarantine.path)\n\nCopied settings files: \(receipt.copiedEntries.isEmpty ? "None — started clean" : receipt.copiedEntries.joined(separator: ", ")). Sessions, storage, attachments, profiles, Skills, and unknown entries were not opened or copied. The repaired runtime can now start."
            alert.addButton(withTitle: "Start Repaired Runtime")
            alert.addButton(withTitle: "Open Preserved Copy, Then Start")
            return alert.runModal() == .alertSecondButtonReturn
        },
        showFailure: { message, recoveryFolder in
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Harness-home recovery remains stopped"
            alert.informativeText = "\(message) Fulmar did not delete the older home or any preserved copy. Open the private recovery folder for manual inspection, or keep the runtime stopped and retry from Diagnostics.\n\n\(recoveryFolder.path)"
            alert.addButton(withTitle: "Open Recovery Folder")
            alert.addButton(withTitle: "Keep Stopped")
            return alert.runModal() == .alertFirstButtonReturn
        },
        reveal: { url in NSWorkspace.shared.activateFileViewerSelecting([url]) }
    )
}

enum ProviderHistoryAuxiliaryRecoveryPresentation {
    enum InitialChoice { case preserve, keepStopped }
    enum InterruptedChoice { case resume, openRecoveryFolder, keepStopped }
    enum PublishedChoice { case acknowledge, openAndAcknowledge, keepStopped }

    static func initialChoice(for response: NSApplication.ModalResponse) -> InitialChoice {
        response == .alertFirstButtonReturn ? .preserve : .keepStopped
    }

    static func interruptedChoice(
        for response: NSApplication.ModalResponse
    ) -> InterruptedChoice {
        switch response {
        case .alertFirstButtonReturn: .resume
        case .alertSecondButtonReturn: .openRecoveryFolder
        default: .keepStopped
        }
    }

    static func publishedChoice(
        for response: NSApplication.ModalResponse
    ) -> PublishedChoice {
        switch response {
        case .alertFirstButtonReturn: .acknowledge
        case .alertSecondButtonReturn: .openAndAcknowledge
        default: .keepStopped
        }
    }
}

@MainActor
struct ProviderHistoryAuxiliaryRecoveryInteractions {
    var chooseInitial: (ProviderHistoryAuxiliaryRecoveryRequest) -> ProviderHistoryAuxiliaryRecoveryPresentation.InitialChoice
    var chooseNamespacePublication: (ProviderHistoryAuxiliaryNamespacePublicationRequest) -> ProviderHistoryAuxiliaryRecoveryPresentation.InitialChoice
    var chooseInterrupted: (ProviderHistoryAuxiliaryInterruptedRequest) -> ProviderHistoryAuxiliaryRecoveryPresentation.InterruptedChoice
    var acknowledgePublished: (ProviderHistoryAuxiliaryRecoveryReceipt) -> ProviderHistoryAuxiliaryRecoveryPresentation.PublishedChoice
    var showFailure: (String, URL) -> Bool
    var reveal: (URL) -> Void

    static let live = ProviderHistoryAuxiliaryRecoveryInteractions(
        chooseInitial: { request in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Preserve historical backup state before starting?"
            let names = [
                request.preservesBackups ? "Backups and restore recovery" : nil,
                request.preservesMigration ? "runtime migration state" : nil
            ].compactMap { $0 }.joined(separator: " and ")
            alert.informativeText = "Fulmar found \(names) from an older provider-history privacy epoch. Agent work, credentials, privacy maintenance, model services, and network providers are stopped. Fulmar can move each whole directory, without listing or opening its children, into a private same-volume recovery area before starting with current state. No historical output is deleted or overwritten."
            alert.addButton(withTitle: "Preserve Whole Directories and Continue")
            alert.addButton(withTitle: "Keep Fulmar Stopped")
            return ProviderHistoryAuxiliaryRecoveryPresentation.initialChoice(
                for: alert.runModal()
            )
        },
        chooseNamespacePublication: { request in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Finish interrupted private-state installation?"
            alert.informativeText = "Fulmar found signed installation records for \(request.namespaceNames.joined(separator: ", ")). A previous foreground write stopped between durable phases. Detection changed no data. Fulmar can resume only those exact signed whole-directory moves and will fail closed on any identity change."
            alert.addButton(withTitle: "Resume Exact Signed Installation")
            alert.addButton(withTitle: "Keep Fulmar Stopped")
            return ProviderHistoryAuxiliaryRecoveryPresentation.initialChoice(
                for: alert.runModal()
            )
        },
        chooseInterrupted: { request in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Resume interrupted provider-state preservation?"
            alert.informativeText = "Fulmar found an exact append-only recovery journal. Detection changed no data and accessed no credential. Resume will only finish the same whole-directory moves recorded before the interruption.\n\nRecovery folder: \(request.recoveryDirectory.path)"
            alert.addButton(withTitle: "Resume Exact Preservation")
            alert.addButton(withTitle: "Open Recovery Folder")
            alert.addButton(withTitle: "Keep Fulmar Stopped")
            return ProviderHistoryAuxiliaryRecoveryPresentation.interruptedChoice(
                for: alert.runModal()
            )
        },
        acknowledgePublished: { receipt in
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = "Historical auxiliary state was preserved"
            let outputs = [
                receipt.preservedBackups?.path,
                receipt.preservedStateRecovery?.path,
                receipt.preservedMigration?.path
            ].compactMap { $0 }.joined(separator: "\n")
            alert.informativeText = "The whole historical directories remain opaque and preserved at:\n\n\(outputs)\n\nAcknowledging archives the complete transaction journal beside them; it deletes no recovery output. Fulmar can then apply retention and continue startup."
            alert.addButton(withTitle: "Acknowledge and Continue")
            alert.addButton(withTitle: "Open Folder, Acknowledge, and Continue")
            alert.addButton(withTitle: "Keep Fulmar Stopped")
            return ProviderHistoryAuxiliaryRecoveryPresentation.publishedChoice(
                for: alert.runModal()
            )
        },
        showFailure: { message, recoveryFolder in
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Provider-state preservation remains stopped"
            alert.informativeText = "\(message) No historical directory or transaction evidence was deleted or overwritten.\n\n\(recoveryFolder.path)"
            alert.addButton(withTitle: "Open Recovery Folder")
            alert.addButton(withTitle: "Keep Fulmar Stopped")
            return alert.runModal() == .alertFirstButtonReturn
        },
        reveal: { NSWorkspace.shared.activateFileViewerSelecting([$0]) }
    )
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, HarnessWebViewControllerDelegate {
    /// Public builds must not expose the current launch-only replacement path.
    /// Flip this only with the two-phase health/journal implementation and its
    /// complete signed, notarized two-version qualification evidence.
    private static let verifiedInAppUpdatesEnabled = false

    private struct ActiveBrowserTurnPreparation {
        let cancellation: WorkspaceJournalOperationCancellation
        let task: Task<Void, Never>
    }

    private let controller: HarnessController
    private var postInstallHealthContext: UpdatePostInstallHealthContext?
    private let preferences = PreferencesStore.shared
    private lazy var notifications = NotificationManager(preferences: preferences)
    private let appshotController = AppshotController(preferences: .shared)
    private lazy var ollamaClient = OllamaClient { [weak controller] in
        controller?.ollamaBaseURL
    }
    private let rpcClient = HarnessRPCClient()
    private lazy var conversationService = HarnessConversationService(rpc: rpcClient)
    private let modelSettingsStore = ModelProviderSettingsStore()
    private let providerConsentStore = ProviderConsentStore()
    private let sessionHistoryLifecycle = SessionHistoryLifecycleGate()
    private lazy var nativeProviderStateRecovery = NativeProviderStateRecovery(
        applicationSupport: controller.diagnosticsDirectory().standardizedFileURL
    )
    private lazy var modelCoordinator = ModelSelectionCoordinator(
        service: rpcClient,
        credentialService: rpcClient
    )
    private lazy var localModelSelectionPreflight = LocalModelSelectionPreflight(
        service: ollamaClient
    )
    private lazy var providerSelectionTransaction = ProviderSelectionTransaction(
        coordinator: modelCoordinator,
        settingsStore: modelSettingsStore,
        consentStore: providerConsentStore,
        preferences: preferences,
        runtimeMutations: protectedRuntimeMutations,
        localModelPreflight: { [weak self] selection, descriptor in
            guard let self else {
                throw LocalModelSelectionPreflightError.unavailable
            }
            try await self.localModelSelectionPreflight.validate(
                selection: selection,
                descriptor: descriptor
            )
        },
        beforeFreshRuntime: { [weak self] result in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            self.companionWindow.quickChat.runtimeDidRestart()
            self.mainWindow.surface.requireFreshSessionAfterNextLoad()
            self.prepareSkillsForBoundary(result.boundary == .onDevice ? .local : .external)
        }
    )
    private lazy var sessionHistoryRepository = SessionHistoryRepository(
        service: rpcClient,
        lifecycle: sessionHistoryLifecycle
    )
    private lazy var knowledgeStore = try? LocalKnowledgeStore(applicationSupportDirectory: controller.diagnosticsDirectory())
    private let performanceTelemetry = GenerationTelemetryAccumulator()
    private let hostPerformanceCollector = HostPerformanceSnapshotCollector()
    private let memoryPressureObserver: any MemoryPressureObserving
    private let thermalWorkloadModeWriter: ThermalWorkloadModeWriter
    private let physicalHandoffAcceptance: PhysicalHandoffAcceptanceEnvironment?
    private let skillSessionDisclosureInteractions: SkillSessionDisclosureInteractions
    private let harnessHomeRecoveryInteractions: HarnessHomeRecoveryInteractions
    private let auxiliaryRecoveryInteractions: ProviderHistoryAuxiliaryRecoveryInteractions
    private var memoryPressureCondition: HostMemoryPressureCondition = .normal
    private var memoryPressureRouteGate = MemoryPressureRouteGate(
        recoverySeconds: ThermalSafetyPolicy.production.memoryPressureRecoverySeconds
    )
    private var memoryPressureConversationHoldOutstanding = false
    private var thermalSafety = ThermalSafetyStateMachine()
    private var thermalSafetyTimer: Timer?
    private var thermalSafetyObserver: NSObjectProtocol?
    private var thermalSafetySampleInFlight = false
    private var thermalStopInFlight = false
    private var thermalRecoveryPending = false
    private var thermalRuntimeRestartRequested = false
    private var thermalInitialStartupDeferred = false
    private var thermalShutdownEstablished = false
    private var thermalReadyFinalization = ThermalReadyFinalizationGate()
    private var thermalCooldownPersistence = ThermalCooldownPersistenceGate()
    private(set) var pendingThermalNormalModeRecovery: ThermalNormalModeRecoveryFailure?
    private var thermalHeadlessMode = false
    private var statusItemAcceptanceMode = false
    private var headlessHandoffAcceptanceMode = false
    private var headlessForegroundHandoff = HeadlessForegroundHandoff()
    private var foregroundRelaunchAttemptID: UUID?
    private var foregroundRelaunchInitialOutcomeDelivered = false
    private var thermalActivity: UUID?
    private lazy var performanceHistoryClearCoordinator = PerformanceHistoryClearCoordinator(
        applicationSupport: controller.diagnosticsDirectory().standardizedFileURL
    )
    private let webDataStore = WKWebsiteDataStore.nonPersistent()
    private lazy var activityStore = ActivityStore(applicationSupport: controller.diagnosticsDirectory())
    private lazy var privacyLedger = PrivacyLedger(applicationSupport: controller.diagnosticsDirectory())
    private lazy var attachmentRetention: AttachmentRetentionManager = {
        let runtime = controller.runtimeInfo()
        let trustedNode = runtime?.bundled == true && BundleIntegrityVerifier.verify() ? runtime?.node : nil
        return AttachmentRetentionManager(
            harnessHome: controller.harnessHomeDirectory(),
            trustedNode: trustedNode,
            harnessHomeCapabilityProvider: { [weak controller] in
                controller?.verifiedHarnessHomeCapability
            }
        )
    }()
    private lazy var privacyMaintenance = PrivacyMaintenanceCoordinator(
        appshots: appshotController,
        ledger: privacyLedger,
        attachments: attachmentRetention,
        preferences: preferences,
        canPurgeAttachments: { [weak controller] in
            controller?.attachmentPurgeAdmissionPermitted() == true
        }
    )
    private let privacyMaintenanceQueue = DispatchQueue(label: "app.localharness.privacy-maintenance", qos: .utility)
    private var privacyMaintenanceTimer: DispatchSourceTimer?
    private lazy var backupManager = StateBackupManager(
        applicationSupport: controller.diagnosticsDirectory(),
        sourceState: controller.harnessHomeDirectory(),
        harnessHomeCapabilityProvider: { [weak controller] in
            controller?.verifiedHarnessHomeCapability
        }
    )
    private lazy var auxiliaryStateCoordinator = ProviderHistoryAuxiliaryStateCoordinator(
        applicationSupport: controller.diagnosticsDirectory().standardizedFileURL
    )
    private lazy var migrationCoordinator = RuntimeMigrationCoordinator(applicationSupport: controller.diagnosticsDirectory(), backupManager: backupManager)
    private lazy var updateManager = UpdateManager(applicationSupport: controller.diagnosticsDirectory(), backupManager: backupManager)
    private let credentialMigration = CredentialMigrationManager()
    private let startupCredentialMigrationLifecycle = StartupCredentialMigrationLifecycleGate()
    private var providerHistoryStartupGateToken: UUID?
    private var deviceAttestationTrustRecoveryPresentationInFlight = false
    private var auxiliaryRecoveryPresentationToken: UUID?
    private var auxiliaryRecoveryMutationInFlight = false
    private lazy var artifactAnnotations = ArtifactAnnotationStore(applicationSupport: controller.diagnosticsDirectory())
    private lazy var scheduleExecutor = HarnessScheduleConversationExecutor(conversation: conversationService)
    private lazy var scheduleManager = ScheduleManager(
        applicationSupport: controller.diagnosticsDirectory(),
        executor: scheduleExecutor,
        activities: activityStore,
        boundaryPolicy: ScheduleBoundaryPolicy(descriptors: [], includeBuiltInDefaults: false),
        enforceActiveProvider: true,
        admissionsInitiallySuspended: true,
        executionWorkspace: controller.workspaceDirectory(),
        prepareExecution: { [weak self] schedule, completion in
            Task { [weak self] in
                guard let self, let coordinator = self.workspaceRecoveryCoordinator else {
                    completion(.failure(WorkspaceJournalError.unsafeStorage))
                    return
                }
                do {
                    _ = try await coordinator.captureBeforeTurn(
                        reason: "Before scheduled task: \(schedule.title)"
                    )
                    await MainActor.run { self.recoveryWindow?.refresh() }
                    completion(.success(()))
                } catch {
                    completion(.failure(error))
                }
            }
        }
    )
    private lazy var workspaceJournal: WorkspaceChangeJournal? = {
        let workspace = controller.workspaceDirectory()
        do {
            try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: workspace.path)
            return try WorkspaceChangeJournal(
                approvedWorkspace: workspace,
                applicationSupport: controller.diagnosticsDirectory()
            )
        } catch {
            return nil
        }
    }()
    private lazy var workspaceMutationPolicy = WorkspaceMutationPolicyStore(
        harnessHome: controller.harnessHomeDirectory()
    )
    private lazy var workspaceRecoveryCoordinator: WorkspaceRecoveryCoordinator? = {
        guard let workspaceJournal else { return nil }
        return WorkspaceRecoveryCoordinator(
            journal: workspaceJournal,
            policy: workspaceMutationPolicy
        )
    }()

    private var mainWindow: HarnessWindowController!
    private var companionWindow: CompanionWindowController!
    private var settingsWindow: SettingsWindowController!
    private var diagnosticsWindow: DiagnosticsWindowController?
    private var commandCenterWindow: CommandCenterWindowController!
    private var activityWindow: ActivityCenterWindowController!
    private var modelWindow: ModelManagerWindowController!
    private var providerWindow: ProviderCenterWindowController!
    private var historyWindow: SessionHistoryWindowController!
    private var knowledgeWindow: KnowledgeCenterWindowController?
    private var skillsWindow: SkillsCenterWindowController?
    private var mcpWindow: MCPCenterWindowController?
    private var recoveryWindow: WorkspaceRecoveryWindowController?
    private var performanceWindow: PerformanceCenterWindowController?
    private var privacyWindow: PrivacyDashboardWindowController!
    private var pluginTrustWindow: PluginTrustWindowController!
    private var backupWindow: BackupWindowController!
    private var scheduleWindow: ScheduleWindowController!
    private var statusItem: NSStatusItem?
    private var statusMenuItem: NSMenuItem?
    private var retryStatusItemPlacementAfterSystemSettings = false
    private var statusMenuTitle = "Checking local services…"
    private var activeBrowserTurnPreparations: [UUID: ActiveBrowserTurnPreparation] = [:]
    private let browserTurnPreparationAdmission = BrowserTurnPreparationAdmissionGate()
    private var hotKey: GlobalHotKey?
    private var hotKeyAvailability: GlobalHotKeyAvailability = .notAttempted
    private var readinessAttempts = 0
    private var startDate = Date()
    private var lastExternalApplication: NSRunningApplication?
    private var runtimeActivity: UUID?
    private var harnessHomeRecoveryCompletion = HarnessHomeRecoveryCompletionGate()
    private var harnessHomeRecoveryPresentation = HarnessHomeRecoveryPresentationGate()
    private var artifactWindows: [ArtifactPreviewWindowController] = []
    private var terminationDeferred = false
    private var terminationPrepared = false
    private var updateTerminationRequested = false
    private var terminationBarrier: ApplicationTerminationBarrier?
    private var terminationConversationAdmissionSuspended = false
    private var backgroundLifecycleCoordinator: BackgroundScheduleLifecycleCoordinator?
    private var providerCatalog: HarnessModelCatalogSnapshot?
    private var sessionOpenGeneration = UUID()
    /// Invalidates readiness probes and catalog validations from a previous
    /// runtime instance. Protected transitions rotate this synchronously
    /// before their first await so stale readiness cannot reopen admissions.
    private let runtimeReadinessEpoch = RuntimeReadinessEpoch()
    private var runtimeGeneration: UUID { runtimeReadinessEpoch.current }
    private var providerRecoveryContext: ProviderRecoveryContext?
    private var providerRecoveryTransitionInFlight = false
    private let protectedControlPlaneStartWaiter = ProtectedRuntimeReadinessWaiter()
    private let protectedInferenceStartWaiter = ProtectedRuntimeReadinessWaiter()
    private var providerProtectedMutationPermit: (
        request: ProviderProtectedMutation,
        permit: ProtectedRuntimeMutationPermit,
        priorConsent: ProviderConsentState?
    )?
    private var workspaceRestorePermit: ProtectedRuntimeMutationPermit?
    private var stateBackupTransitionPermits: [UUID: ProtectedRuntimeMutationPermit] = [:]
    private var protectedRuntimeConversationHoldOutstanding = false
    private lazy var protectedRuntimeMutations = ProtectedRuntimeMutationCoordinator(
        driver: ProtectedRuntimeMutationDriver(
            closeAdmissions: { [weak self] in self?.closeAllRuntimeAdmissionsSynchronously() },
            quiesceAdmissions: { [weak self] in
                guard let self else { throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded) }
                let schedules = self.scheduleManager
                let conversations = self.conversationService
                let history = self.sessionHistoryLifecycle
                try await RuntimeAdmissionQuiescenceBarrier(
                    schedules: { try await schedules.quiesce() },
                    conversations: { try await conversations.quiesceSuspendedAdmissions() },
                    history: { try await history.quiesceSuspendedAdmissions() }
                ).quiesce()
            },
            stopRuntime: { [weak self] in
                guard let self else { throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded) }
                try await self.stopOwnedRuntimeForProtectedMutation()
            },
            startProviderControlPlane: { [weak self] in
                guard let self else { throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded) }
                try await self.startProviderControlPlaneForProtectedMutation()
            },
            startVerifiedInference: { [weak self] in
                guard let self else { throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded) }
                try await self.startVerifiedInferenceForProtectedMutation()
            },
            remainStoppedForUpdate: { [weak self] in
                self?.mainWindow.updateStatus("Verified update ready · Runtime stopped", color: .systemOrange)
            },
            failClosed: { [weak self] error in
                guard let self else { return }
                self.mainWindow.surface.suspendTurnAdmissions()
                self.mainWindow.surface.configure(endpoint: nil)
                self.mainWindow.surface.showFailure("Agent work remains blocked because a protected runtime transition could not be verified. \(error.localizedDescription)")
                self.mainWindow.updateStatus("Protected change failed closed", color: .systemRed)
            }
        )
    )

    init(
        physicalHandoffAcceptance: PhysicalHandoffAcceptanceEnvironment? = nil,
        skillSessionDisclosureInteractions: SkillSessionDisclosureInteractions? = nil,
        harnessHomeRecoveryInteractions: HarnessHomeRecoveryInteractions? = nil,
        auxiliaryRecoveryInteractions: ProviderHistoryAuxiliaryRecoveryInteractions? = nil,
        postInstallHealthContext: UpdatePostInstallHealthContext? = nil
    ) {
        memoryPressureObserver = DispatchMemoryPressureObserver()
        thermalWorkloadModeWriter = .live
        self.physicalHandoffAcceptance = physicalHandoffAcceptance
        self.skillSessionDisclosureInteractions = skillSessionDisclosureInteractions ?? .live
        self.harnessHomeRecoveryInteractions = harnessHomeRecoveryInteractions ?? .live
        self.auxiliaryRecoveryInteractions = auxiliaryRecoveryInteractions ?? .live
        self.postInstallHealthContext = postInstallHealthContext
        controller = HarnessController(
            applicationSupportDirectory: physicalHandoffAcceptance?.applicationSupport,
            modelStoreDirectory: physicalHandoffAcceptance?.modelStore,
            forbidCredentialHelper: physicalHandoffAcceptance != nil
        )
        super.init()
    }

    /// Deterministic injection seam for lifecycle tests. Production always uses
    /// one Dispatch-backed observer created by the default initializer.
    init(
        memoryPressureObserver: any MemoryPressureObserving,
        thermalWorkloadModeWriter: ThermalWorkloadModeWriter = .live,
        physicalHandoffAcceptance: PhysicalHandoffAcceptanceEnvironment? = nil,
        skillSessionDisclosureInteractions: SkillSessionDisclosureInteractions? = nil,
        harnessHomeRecoveryInteractions: HarnessHomeRecoveryInteractions? = nil,
        auxiliaryRecoveryInteractions: ProviderHistoryAuxiliaryRecoveryInteractions? = nil,
        postInstallHealthContext: UpdatePostInstallHealthContext? = nil
    ) {
        self.memoryPressureObserver = memoryPressureObserver
        self.thermalWorkloadModeWriter = thermalWorkloadModeWriter
        self.physicalHandoffAcceptance = physicalHandoffAcceptance
        self.skillSessionDisclosureInteractions = skillSessionDisclosureInteractions ?? .live
        self.harnessHomeRecoveryInteractions = harnessHomeRecoveryInteractions ?? .live
        self.auxiliaryRecoveryInteractions = auxiliaryRecoveryInteractions ?? .live
        self.postInstallHealthContext = postInstallHealthContext
        controller = HarnessController(
            applicationSupportDirectory: physicalHandoffAcceptance?.applicationSupport,
            modelStoreDirectory: physicalHandoffAcceptance?.modelStore,
            forbidCredentialHelper: physicalHandoffAcceptance != nil
        )
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains("--headless-handoff-acceptance") {
            // Release-only gate for the exact lifecycle that previously left
            // a reused scheduler process with no window or menu-bar item. It
            // creates no WebKit/runtime/schedule work; the acceptance driver
            // activates this accessory instance and verifies the protected
            // two-process foreground handoff end to end.
            thermalHeadlessMode = true
            headlessHandoffAcceptanceMode = true
            return
        }
        switch controller.admitApplicationSupportRoot() {
        case .success:
            break
        case .failure(let error):
            failUnsafeApplicationSupportStartup(error)
            return
        }
        if CommandLine.arguments.contains("--background-schedule") {
            guard physicalHandoffAcceptance?.mode != .foreground else {
                NSApp.terminate(nil)
                return
            }
            thermalHeadlessMode = true
            let lifecycle = BackgroundScheduleLifecycleCoordinator(
                preflightHarnessHome: { [weak controller] completion in
                    guard let controller else {
                        completion(.failure(BackgroundScheduleLifecycleError.runtimeUnavailable))
                        return
                    }
                    controller.preflightHarnessHomeRecoveryForBackgroundSchedule(
                        completion: { completion($0.map { _ in () }) }
                    )
                },
                prepareMigration: { [weak self] completion in
                    guard let self,
                          let version = self.controller.runtimeInfo()?.dshVersion else {
                        completion(.failure(BackgroundScheduleLifecycleError.runtimeUnavailable))
                        return
                    }
                    let migrationCoordinator = self.migrationCoordinator
                    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                        guard let self else {
                            DispatchQueue.main.async {
                                completion(.failure(BackgroundScheduleLifecycleError.runtimeUnavailable))
                            }
                            return
                        }
                        let result = Result { try migrationCoordinator.prepare(targetVersion: version) }
                        DispatchQueue.main.async {
                            switch result {
                            case .success(.current):
                                completion(.success(.current(version: version)))
                            case .success(.backupCreated(let backup)):
                                self.activityStore.addCompleted(
                                    .backup,
                                    title: "Prepared Harness \(version) for background schedules",
                                    detail: "Safety snapshot \(backup.id.uuidString) was created; secrets were excluded."
                                )
                                self.privacyLedger.record(
                                    .backupCreated,
                                    summary: "Pre-upgrade Harness snapshot created",
                                    localOnly: true
                                )
                                completion(.success(.backupCreated(version: version)))
                            case .success(.recoveryNeeded(let backup)):
                                completion(.success(.recoveryNeeded(
                                    version: version,
                                    backupID: backup.id
                                )))
                            case .failure(let error):
                                if let backupError = error as? BackupError {
                                    switch backupError {
                                    case .authenticationAuthorizationRequired, .authenticationTimedOut:
                                        _ = try? self.activityStore.addWaitingSynchronously(
                                            .backup,
                                            title: "Backup key needs foreground attention",
                                            detail: "Background schedules remained stopped. Open Backups & Restore to authorize the exact existing Keychain item; Fulmar did not replace or delete it."
                                        )
                                    default:
                                        break
                                    }
                                }
                                completion(.failure(error))
                            }
                        }
                    }
                },
                launchRuntime: { [weak self] in
                    guard let self else { return }
                    guard !self.thermalSafetyBlocksSelectedLocalRuntime else {
                        self.thermalInitialStartupDeferred = true
                        return
                    }
                    self.controller.prepareAndStart()
                },
                recordRecoveryNeeded: { [weak self] version, backupID in
                    guard let self else { return }
                    _ = try? self.activityStore.addWaitingSynchronously(
                        .backup,
                        title: "Harness upgrade recovery required",
                        detail: "Background schedules were kept stopped for Harness \(version). Open \(ProductBrand.displayName) to review safety snapshot \(backupID.uuidString)."
                    )
                    self.notifications.send(
                        title: "Open \(ProductBrand.displayName) to finish the upgrade",
                        body: "Background schedules stayed stopped because Harness \(version) has a pending safety snapshot.",
                        identifier: "background-migration-recovery"
                    )
                },
                probe: { [weak controller] completion in
                    guard let controller else { completion(false); return }
                    controller.probeHarness(completion: completion)
                },
                reportIdentityReady: { [weak controller] in controller?.reportReady() },
                verifyTopology: { [weak self] generation, completion in
                    guard let self, generation == self.runtimeGeneration else {
                        completion(.failure(RuntimeTopologyValidationError.runtimeChanged))
                        return
                    }
                    self.verifyLiveProviderTopology(generation: generation) { result in
                        completion(result.map { _ in () })
                    }
                },
                markMigrationReady: { [weak self] version in
                    guard let self else {
                        return .failure(BackgroundScheduleLifecycleError.runtimeUnavailable)
                    }
                    return Result { try self.migrationCoordinator.markReady(version: version) }
                },
                promoteToFullInference: { [weak self] in
                    guard let self, let endpoint = self.controller.endpoint else { return false }
                    return ThermalRuntimeAdmissionPolicy.promoteIfAdmitted(
                        selectedLocalRuntimeBlocked: self.thermalSafetyBlocksSelectedLocalRuntime
                    ) {
                        self.rpcClient.promoteToFullInference(expected: endpoint)
                    }
                },
                runDueSchedules: { [weak self] in
                    guard let self, !self.thermalSafetyBlocksSelectedLocalRuntime else { return }
                    self.scheduleManager.resumeAdmissionsAndRunDue()
                },
                quiesceSchedules: { [weak self] completion in
                    guard let self else {
                        completion(.failure(BackgroundScheduleLifecycleError.quiescenceUnavailable))
                        return
                    }
                    // Close synchronously before the lifecycle coordinator can
                    // reach its first await. Then settle the authenticated DSH
                    // cancellation barrier before exact process stop/exit.
                    self.scheduleManager.suspendAdmissionsSynchronously()
                    self.conversationService.suspendAdmissionsForQuiescence()
                    self.sessionHistoryLifecycle.suspendAdmissionsForQuiescence()
                    Task { @MainActor [weak self] in
                        guard let self else {
                            completion(.failure(BackgroundScheduleLifecycleError.quiescenceUnavailable))
                            return
                        }
                        do {
                            let schedules = self.scheduleManager
                            let conversations = self.conversationService
                            let history = self.sessionHistoryLifecycle
                            try await RuntimeAdmissionQuiescenceBarrier(
                                schedules: { try await schedules.quiesce() },
                                conversations: { try await conversations.quiesceSuspendedAdmissions() },
                                history: { try await history.quiesceSuspendedAdmissions() }
                            ).quiesce()
                            completion(.success(()))
                        } catch {
                            completion(.failure(error))
                        }
                    }
                },
                stopRuntime: { [weak controller] completion in
                    guard let controller else {
                        completion(.failure(BackgroundScheduleLifecycleError.runtimeUnavailable))
                        return
                    }
                    controller.stopOwnedServicesForApplicationTermination(completion: completion)
                },
                exitApplication: { NSApp.terminate(nil) }
            )
            backgroundLifecycleCoordinator = lifecycle
            scheduleManager.onIdleAfterRun = { [weak lifecycle] in lifecycle?.scheduledWorkBecameIdle() }
            controller.onEndpointChange = { [weak self] endpoint in self?.rpcClient.setControlPlaneEndpoint(endpoint) }
            controller.onStateChange = { [weak self] eventState in
                guard let self else { return }
                switch eventState {
                case .startingHarness:
                    self.runtimeReadinessEpoch.rotate()
                    self.backgroundLifecycleCoordinator?.runtimeStarted(generation: self.runtimeGeneration)
                case .ready:
                    self.backgroundLifecycleCoordinator?.runtimePublishedReady(generation: self.runtimeGeneration)
                case .providerRecovery, .failed:
                    self.backgroundLifecycleCoordinator?.runtimeFailed(generation: self.runtimeGeneration)
                case .stopped:
                    // Full preparation can discover recovery after the early
                    // preflight (for example, a path changed during backup). The
                    // controller records the typed pending state before its stop
                    // barrier publishes `.stopped`; wait for the pending callback
                    // to persist activity/notification before asking the
                    // background lifecycle to stop and exit.
                    if self.controller.pendingHarnessHomeRecoveryState == nil {
                        self.backgroundLifecycleCoordinator?.runtimeStopped(
                            generation: self.runtimeGeneration
                        )
                    }
                    self.runtimeReadinessEpoch.rotate()
                default:
                    break
                }
            }
            controller.onHarnessHomeRecoveryPending = { [weak self] pending in
                guard let self else { return }
                let title: String
                let detail: String
                let notificationTitle: String
                let notificationBody: String
                switch pending {
                case .initial:
                    title = "Older Harness home needs foreground review"
                    detail = "Background schedules remained stopped. Open Fulmar to preserve the older home and start a repaired copy; no credential was accessed during detection."
                    notificationTitle = "Open Fulmar to review older Harness data"
                    notificationBody = "Background schedules stayed stopped and the existing Harness home was not changed."
                case .interrupted:
                    title = "Interrupted Harness-home recovery needs foreground review"
                    detail = "Background schedules remained stopped. Open Fulmar to authorize the existing recovery key and resume the exact journal; no credential was accessed during detection."
                    notificationTitle = "Open Fulmar to resume Harness recovery"
                    notificationBody = "No credential or recovery work ran during this background launch."
                case .published:
                    title = "Harness-home recovery receipt needs acknowledgement"
                    detail = "Background schedules remained stopped. Open Fulmar to review the exact preserved copy before its authenticated completion marker is acknowledged."
                    notificationTitle = "Open Fulmar to review preserved Harness data"
                    notificationBody = "The preserved copy remains pending foreground review and acknowledgement."
                case .blocked:
                    title = "Harness-home recovery needs manual inspection"
                    detail = "Background schedules remained stopped. Open Fulmar to inspect the private recovery folder; no credential was accessed during detection."
                    notificationTitle = "Open Fulmar to inspect Harness recovery"
                    notificationBody = "No credential or recovery work ran during this background launch."
                }
                _ = try? self.activityStore.addWaitingSynchronously(
                    .runtime,
                    title: title,
                    detail: detail
                )
                self.notifications.send(
                    title: notificationTitle,
                    body: notificationBody,
                    identifier: "harness-home-recovery-required"
                )
                // The activity write and notification dispatch above own the
                // user-visible recovery signal. Only after both calls return may
                // a late full-prepare failure enter stop-and-exit; the initial
                // preflight phase ignores this call and exits from its completion.
                self.backgroundLifecycleCoordinator?.runtimeFailed(
                    generation: self.runtimeGeneration
                )
            }
            startThermalSafetyMonitoring()
            beginProviderHistoryStartupGate(background: true) { [weak self] admitted in
                guard let self else { return }
                guard admitted else {
                    NSApp.terminate(nil)
                    return
                }
                self.runStartupPrivacyMaintenance { [weak self] in
                    guard let self else { return }
                    guard !self.thermalSafetyBlocksSelectedLocalRuntime else {
                        self.thermalInitialStartupDeferred = true
                        return
                    }
                    self.backgroundLifecycleCoordinator?.prepareAndLaunch()
                }
            }
            return
        }
        if CommandLine.arguments.contains("--status-item-acceptance") {
            // The local release gate exercises the exact production status
            // item and menu without starting DSH, Ollama, WebKit, schedules,
            // notifications, or thermal polling. This keeps repeated menu-bar
            // acceptance cycles fast and prevents avoidable local-model heat.
            thermalHeadlessMode = false
            statusItemAcceptanceMode = true
            buildMainMenu()
            scheduleInitialStatusItemCreation()
            return
        }
        thermalHeadlessMode = false
        lastExternalApplication = NSWorkspace.shared.frontmostApplication
        buildMainMenu()
        buildWindows()
        scheduleInitialStatusItemCreation()
        observeApplicationChanges()
        installGlobalHotKey()

        controller.onEndpointChange = { [weak self] endpoint in
            self?.thermalReadyFinalization.endpointDidChange(to: endpoint)
            // Every new runtime begins control-plane-only. The authenticated
            // browser and every session RPC stay disconnected until native
            // topology verification promotes this exact endpoint identity.
            self?.mainWindow.surface.configure(endpoint: nil)
            self?.rpcClient.setControlPlaneEndpoint(endpoint)
            if endpoint == nil {
                self?.conversationService.cancelAll()
                self?.refreshToolbarCatalog(catalog: nil)
            }
        }
        controller.onStateChange = { [weak self] state in self?.handle(state) }
        controller.onHarnessHomeRecoveryPending = { [weak self] pending in
            self?.presentHarnessHomeRecovery(pending)
        }
        // Install lifecycle callbacks before the first thermal sample. An
        // immediate serious/critical sample can stop the runtime, and every
        // state publication from that stop must already have an owner.
        startThermalSafetyMonitoring()
        showMainWindow(nil)
        startDate = Date()
        showLoading("Applying private data retention…")
        beginProviderHistoryStartupGate(background: false) { [weak self] admitted in
            guard let self, admitted else { return }
            self.runStartupPrivacyMaintenance { [weak self] in
                self?.startPeriodicPrivacyMaintenance()
                self?.beginProtectedStartup()
            }
        }
    }

    /// Application Support admission is deliberately handled without touching
    /// ActivityStore, plugin state, logs, notifications, WebKit, or any other
    /// lazy child store. The background form is noninteractive and exits; the
    /// foreground form presents only the typed fail-closed explanation.
    private func failUnsafeApplicationSupportStartup(
        _ error: ApplicationSupportRootAdmissionError
    ) {
        let message = error.localizedDescription
        if CommandLine.arguments.contains("--background-schedule") {
            fputs("Fulmar startup blocked: unsafe Application Support directory.\n", stderr)
            NSApp.terminate(nil)
            return
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Fulmar could not safely open its private data"
        alert.informativeText = message
        alert.addButton(withTitle: "Quit")
        alert.runModal()
        NSApp.terminate(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationDidBecomeActive(_ notification: Notification) {
        if thermalHeadlessMode {
            requestForegroundRelaunchFromHeadlessProcess()
            return
        }
        if retryStatusItemPlacementAfterSystemSettings {
            retryStatusItemPlacementAfterSystemSettings = false
            retryStatusItemPlacementFromUserAction()
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if statusItemAcceptanceMode { return .terminateNow }
        if terminationPrepared { return .terminateNow }
        if terminationDeferred { return .terminateLater }
        if controller.harnessHomeRecoveryIsInFlight {
            showAlert(
                title: "Harness-home recovery is still finishing",
                message: "Fulmar will not overlap Quit with the authenticated preserve-and-repair transaction. Wait for the preserved-copy confirmation or the fail-closed recovery message, then choose Quit again."
            )
            return .terminateCancel
        }
        if providerHistoryStartupGateToken != nil
            || auxiliaryRecoveryPresentationToken != nil
            || auxiliaryRecoveryMutationInFlight {
            showAlert(
                title: "Provider-state privacy review is still active",
                message: "Fulmar will not overlap Quit with the explicit preserve, resume, or journal-archive sequence. Finish or keep the recovery stopped, then choose Quit again."
            )
            return .terminateCancel
        }
        if startupCredentialMigrationLifecycle.isMigrationInFlight {
            showAlert(
                title: "Credential protection is still finishing",
                message: "Fulmar will not overlap Quit with the first-start Keychain migration. Wait for the verified success or failure message, then choose Quit again."
            )
            return .terminateCancel
        }
        let terminationAuthorized = updateTerminationRequested
            ? protectedRuntimeMutations.validateClaimedUpdateTermination()
            : protectedRuntimeMutations.beginTermination()
        if !terminationAuthorized {
            if headlessForegroundHandoff.protectedStopFailed() {
                recordHeadlessForegroundHandoffFailure(
                    "Foreground handoff could not begin because a protected runtime change was still active."
                )
                return .terminateCancel
            }
            showAlert(
                title: "A protected change is still finishing",
                message: "\(ProductBrand.displayName) will not overlap Quit with a provider, backup, restore, security, or update transaction. Wait for Ready or the fail-closed message, then choose Quit again."
            )
            return .terminateCancel
        }
        // The active-migration check above and this latch execute on the main
        // actor with no suspension between them. A queued first-start task can
        // therefore neither dispatch the helper nor restart inference after
        // the global protected-runtime termination latch is accepted.
        guard startupCredentialMigrationLifecycle.beginTermination() else {
            showAlert(
                title: "Credential protection is still finishing",
                message: "Fulmar kept Quit blocked because the first-start Keychain migration acquired its lifecycle permit. Wait for it to settle, then choose Quit again."
            )
            return .terminateCancel
        }
        terminationDeferred = true
        prepareForTermination()
        let barrier = ApplicationTerminationBarrier()
        terminationBarrier = barrier
        barrier.begin(
            quiesce: { [weak self] completion in
                guard let self else { completion(.success(())); return }
                Task { @MainActor [weak self] in
                    guard let self else { completion(.success(())); return }
                    do {
                        let schedules = self.scheduleManager
                        let conversations = self.conversationService
                        let history = self.sessionHistoryLifecycle
                        try await RuntimeAdmissionQuiescenceBarrier(
                            schedules: { try await schedules.quiesce() },
                            conversations: { try await conversations.quiesceSuspendedAdmissions() },
                            history: { try await history.quiesceSuspendedAdmissions() }
                        ).quiesce()
                        completion(.success(()))
                    } catch {
                        completion(.failure(error))
                    }
                }
            },
            unloadRequested: preferences.unloadModelWhenIdle,
            unload: { [weak self] completion in
                guard let self else { completion(); return }
                self.ollamaClient.unloadAllRunning(completion: completion)
            },
            stop: { [weak self] completion in
                guard let self else { completion(.success(())); return }
                self.controller.stopOwnedServicesForApplicationTermination(completion: completion)
            },
            completion: { [weak self] result in
                guard let self else {
                    sender.reply(toApplicationShouldTerminate: false)
                    return
                }
                self.terminationDeferred = false
                self.terminationBarrier = nil
                switch result {
                case .success:
                    do {
                        try self.privacyLedger.recordSynchronously(
                            .runtimeStopped,
                            summary: "App-owned local services stopped",
                            localOnly: true
                        )
                    } catch {
                        // Terminal shutdown is irreversible. Once every exact
                        // owned process is confirmed stopped, a secondary
                        // ledger failure must not strand an open, unusable app.
                        // The ledger will surface its unavailable state on the
                        // next launch without weakening the process boundary.
                    }
                    self.terminationPrepared = true
                    if self.headlessForegroundHandoff.protectedStopSucceeded()
                        == .relaunchBeforeTerminationReply {
                        self.launchFreshForegroundInstance { [weak self, weak sender] succeeded in
                            guard let self, let sender else { return }
                            switch self.headlessForegroundHandoff.relaunchCompleted(succeeded: succeeded) {
                            case .finishDeferredTermination:
                                self.tearDownStatusItem()
                                sender.reply(toApplicationShouldTerminate: true)
                            case .remainStoppedForRetry:
                                sender.reply(toApplicationShouldTerminate: false)
                                self.recordHeadlessForegroundHandoffFailure(
                                    "Owned background work stopped safely, but Launch Services did not open the exact foreground Fulmar app. Open Fulmar again to retry."
                                )
                            case .terminatePreparedProcess, .none:
                                sender.reply(toApplicationShouldTerminate: false)
                            }
                        }
                    } else {
                        self.tearDownStatusItem()
                        sender.reply(toApplicationShouldTerminate: true)
                    }
                case .failure(let error):
                    let headlessHandoffFailed = self.headlessForegroundHandoff.protectedStopFailed()
                    sender.reply(toApplicationShouldTerminate: false)
                    if headlessHandoffFailed {
                        // A modal alert would activate the accessory process
                        // and recursively request another handoff. Persist a
                        // bounded diagnostic instead; a later explicit open
                        // can safely retry the existing stop barrier.
                        self.recordHeadlessForegroundHandoffFailure(
                            "Foreground handoff stayed headless because exact shutdown could not be verified. Open Fulmar again to retry."
                        )
                    } else {
                        self.showAlert(
                            title: "\(ProductBrand.displayName) is locked pending shutdown",
                            message: "Quit was cancelled because one or more exact app-owned processes could not be confirmed stopped. Agent work and schedules remain locked; retry Quit to retry stopping only those captured processes. \(error.localizedDescription)"
                        )
                    }
                }
            }
        )
        return .terminateLater
    }
    func applicationWillTerminate(_ notification: Notification) {
        startupCredentialMigrationLifecycle.latchUnconditionalTermination()
        providerHistoryStartupGateToken = nil
        auxiliaryRecoveryPresentationToken = nil
        tearDownStatusItem()
        if statusItemAcceptanceMode { return }
        prepareForTermination()
        scheduleManager.stop()
        // AppKit normally reaches this only after the deferred barrier replies
        // yes. Keep a best-effort fallback for nonstandard termination paths,
        // while the ordinary Quit path never relies on asynchronous will-quit.
        if !terminationPrepared {
            controller.stopOwnedServicesForApplicationTermination { _ in }
        }
    }

    private func prepareForTermination() {
        // Quit is itself a protected runtime transition. Invalidate controller
        // publications and every already-running readiness completion before
        // the deferred termination barrier performs its first await.
        // Carbon may already have queued its callback onto the main queue. Close
        // the action gate synchronously before any await and deliberately leave
        // the shortcut disabled if protected shutdown later fails: that terminal
        // failure state remains admission-locked until Quit is retried or Fulmar
        // is relaunched.
        harnessHomeRecoveryPresentation.latchTermination()
        hotKey?.invalidate()
        hotKey = nil
        hotKeyAvailability = .disabledForShutdown
        controller.suspendLifecycleStatePublications()
        runtimeReadinessEpoch.rotate()
        privacyMaintenanceTimer?.cancel()
        privacyMaintenanceTimer = nil
        thermalSafetyTimer?.invalidate()
        thermalSafetyTimer = nil
        if let thermalSafetyObserver {
            NotificationCenter.default.removeObserver(thermalSafetyObserver)
            self.thermalSafetyObserver = nil
        }
        memoryPressureObserver.stop()
        memoryPressureObserver.onConditionChange = nil
        scheduleManager.suspendAdmissionsSynchronously()
        mainWindow?.surface.suspendTurnAdmissions()
        if !terminationConversationAdmissionSuspended {
            conversationService.suspendAdmissionsForQuiescence()
            sessionHistoryLifecycle.suspendAdmissionsForQuiescence()
            terminationConversationAdmissionSuspended = true
        }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if statusItemAcceptanceMode { return true }
        if thermalHeadlessMode {
            // Launch Services can reuse the scheduler's accessory process when
            // the user opens Fulmar while a due task is still finishing. That
            // process deliberately has no windows or status item, so touching
            // the foreground IUOs here would trap. Hand off only after the
            // existing exact-process shutdown barrier succeeds.
            requestForegroundRelaunchFromHeadlessProcess()
            return false
        }
        // `activate` can be delivered before Launch Services has made this
        // process frontmost (notably after a protected provider restart or a
        // scheduler wake).  Always reassert the main window and defer one
        // second foreground request to the next AppKit turn.  This also makes
        // a Dock click recover an app that is alive with every window closed.
        if !flag { showMainWindow(nil) }
        else { activateForUserInteraction(window: mainWindow?.window) }
        return true
    }

    private func requestForegroundRelaunchFromHeadlessProcess() {
        guard thermalHeadlessMode, !statusItemAcceptanceMode else { return }
        if headlessForegroundHandoff.phase == .stoppedAwaitingRetry {
            if let expected = canonicalCurrentApplicationURL(),
               exactForegroundPeers(at: expected).count == 1 {
                handleLateExactForegroundLaunch()
                return
            }
            // The first Launch Services request remains authoritative during
            // its bounded late-callback grace. Do not issue a second request
            // that could create two foreground instances.
            if foregroundRelaunchAttemptID != nil { return }
        }
        switch headlessForegroundHandoff.requestForeground() {
        case .beginProtectedTermination:
            NSApp.terminate(nil)
        case .relaunchStoppedProcess:
            launchFreshForegroundInstance { [weak self] succeeded in
                guard let self else { return }
                switch self.headlessForegroundHandoff.relaunchCompleted(succeeded: succeeded) {
                case .terminatePreparedProcess:
                    NSApp.terminate(nil)
                case .remainStoppedForRetry:
                    self.recordHeadlessForegroundHandoffFailure(
                        "Launch Services did not open the exact foreground Fulmar app. Open Fulmar again to retry."
                    )
                case .finishDeferredTermination, .none:
                    break
                }
            }
        case .none:
            break
        }
    }

    private func launchFreshForegroundInstance(completion: @escaping (Bool) -> Void) {
        guard let expected = canonicalCurrentApplicationURL() else {
            completion(false)
            return
        }

        let attemptID = UUID()
        foregroundRelaunchAttemptID = attemptID
        foregroundRelaunchInitialOutcomeDelivered = false
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.createsNewApplicationInstance = true
        if headlessHandoffAcceptanceMode {
            configuration.arguments = ["--status-item-acceptance"]
        } else if let physicalHandoffAcceptance,
                  physicalHandoffAcceptance.mode == .background {
            configuration.arguments = physicalHandoffAcceptance.foregroundArguments
            configuration.environment = physicalHandoffAcceptance.foregroundEnvironment
        } else {
            configuration.arguments = []
        }

        NSWorkspace.shared.openApplication(at: expected, configuration: configuration) { application, error in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    let launchedURL = application?.bundleURL?
                        .standardizedFileURL
                        .resolvingSymlinksInPath()
                    let succeeded = error == nil
                        && application?.isTerminated == false
                        && application?.processIdentifier != getpid()
                        && launchedURL == expected
                    guard self.foregroundRelaunchAttemptID == attemptID else {
                        if succeeded,
                           self.foregroundRelaunchAttemptID == nil {
                            self.handleLateExactForegroundLaunch()
                        }
                        return
                    }
                    self.foregroundRelaunchAttemptID = nil
                    if self.foregroundRelaunchInitialOutcomeDelivered {
                        self.foregroundRelaunchInitialOutcomeDelivered = false
                        if succeeded { self.handleLateExactForegroundLaunch() }
                    } else {
                        completion(succeeded)
                    }
                }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            MainActor.assumeIsolated {
                guard let self, self.foregroundRelaunchAttemptID == attemptID else { return }
                // A delayed Launch Services callback must not turn a successful
                // exact launch into a false failure. Accept only one live peer
                // from this same canonical app bundle, never a bundle-ID match.
                if self.exactForegroundPeers(at: expected).count == 1 {
                    self.foregroundRelaunchAttemptID = nil
                    completion(true)
                    return
                }
                // Report the bounded initial failure so the deferred Quit does
                // not hang, but retain this attempt for one additional bounded
                // callback grace. A late exact success can then terminate the
                // already-stopped headless process without a duplicate launch.
                self.foregroundRelaunchInitialOutcomeDelivered = true
                completion(false)
                DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                    MainActor.assumeIsolated {
                        guard let self, self.foregroundRelaunchAttemptID == attemptID else { return }
                        self.foregroundRelaunchAttemptID = nil
                        self.foregroundRelaunchInitialOutcomeDelivered = false
                        if self.exactForegroundPeers(at: expected).count == 1 {
                            self.handleLateExactForegroundLaunch()
                        }
                    }
                }
            }
        }
    }

    private func canonicalCurrentApplicationURL() -> URL? {
        let expected = Bundle.main.bundleURL.standardizedFileURL.resolvingSymlinksInPath()
        var isDirectory: ObjCBool = false
        guard expected.pathExtension == "app",
              expected.path.hasPrefix("/"),
              FileManager.default.fileExists(atPath: expected.path, isDirectory: &isDirectory),
              isDirectory.boolValue else { return nil }
        return expected
    }

    private func exactForegroundPeers(at expected: URL) -> [NSRunningApplication] {
        NSWorkspace.shared.runningApplications.filter { application in
            guard !application.isTerminated,
                  application.processIdentifier != getpid() else { return false }
            return application.bundleURL?
                .standardizedFileURL
                .resolvingSymlinksInPath() == expected
        }
    }

    private func handleLateExactForegroundLaunch() {
        if headlessForegroundHandoff.lateRelaunchSucceeded() == .terminatePreparedProcess {
            NSApp.terminate(nil)
        }
    }

    private func recordHeadlessForegroundHandoffFailure(_ detail: String) {
        let bounded = String(detail.prefix(1_024))
        NSLog("Fulmar foreground handoff: %@", bounded)
        _ = try? activityStore.addWaitingSynchronously(
            .runtime,
            title: "Foreground launch needs another attempt",
            detail: bounded
        )
        notifications.send(
            title: "Fulmar could not open its window",
            body: bounded,
            identifier: "fulmar-headless-foreground-handoff"
        )
    }

    private func buildWindows() {
        let sharedWorkspace = controller.workspaceDirectory()
        // Runtime migration state is intentionally not constructed here. The
        // Harness-home and signed auxiliary privacy gates must clear before it
        // may read or bind Migration to the current backup catalog.
        mainWindow = HarnessWindowController(dataStore: webDataStore, preferences: preferences, actionTarget: self)
        companionWindow = CompanionWindowController(
            conversationService: conversationService,
            modelCoordinator: modelCoordinator,
            settingsStore: modelSettingsStore,
            selectionTransaction: providerSelectionTransaction,
            preferences: preferences,
            telemetry: performanceTelemetry,
            knowledgeStore: knowledgeStore,
            workspace: sharedWorkspace,
            actionTarget: self
        )
        settingsWindow = SettingsWindowController(preferences: preferences)
        settingsWindow.onNotificationsEnabled = { [weak self] in
            self?.notifications.prepare()
        }
        activityWindow = ActivityCenterWindowController(store: activityStore)
        modelWindow = ModelManagerWindowController(
            client: ollamaClient,
            activities: activityStore,
            ensureLocalService: { [weak self, weak controller] completion in
                guard let self, let controller else {
                    completion(.failure(ModelSelectionCoordinatorError.localProviderBootstrapUnavailable))
                    return
                }
                do {
                    try self.protectedRuntimeMutations.validateAuxiliaryServiceStart()
                } catch {
                    completion(.failure(error))
                    return
                }
                controller.prepareOllamaOnly(completion: completion)
            },
            currentSelection: { [weak self] in
                guard let self else { return nil }
                return try? self.modelSettingsStore.loadOrMigrate().settings.defaultSelection
            },
            useModelForNewTasks: { [weak self] model, completion in
                Task { @MainActor [weak self] in
                    guard let self else {
                        completion(.failure(ModelSelectionCoordinatorError.settingsUnavailable))
                        return
                    }
                    self.useLocalModelForNewTasks(model, completion: completion)
                }
            },
            releaseModelMemory: { [weak self] _, completion in
                guard let self else {
                    completion(.failure(ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)))
                    return
                }
                Task { @MainActor in
                    do {
                        try await self.protectedRuntimeMutations.perform(
                            kind: .modelMemory,
                            requirement: .stoppedRuntime
                        ) { permit in try permit.validate() }
                        completion(.success(()))
                    } catch {
                        completion(.failure(error))
                    }
                }
            }
        )
        providerWindow = ProviderCenterWindowController(
            coordinator: modelCoordinator,
            credentials: rpcClient,
            settingsStore: modelSettingsStore,
            consentStore: providerConsentStore,
            selectionTransaction: providerSelectionTransaction,
            providerActivation: ProviderActivationTransaction(service: rpcClient, catalog: modelCoordinator),
            customProfileEditor: CustomProviderProfileTransaction(service: rpcClient, catalog: modelCoordinator),
            preferences: preferences,
            providerRecoveryCatalogAllowed: { [weak self] in
                self?.controller.currentState == .providerRecovery
            }
        )
        historyWindow = SessionHistoryWindowController(
            dataSource: sessionHistoryRepository,
            newSessionRequest: { HarnessSessionCreateRequest(cwd: sharedWorkspace.path, agentPreset: "standard") },
            newSessionSelection: { [weak self] in
                try? self?.modelSettingsStore.loadOrMigrate().settings.defaultSelection
            },
            lifecycle: sessionHistoryLifecycle
        )
        if let knowledgeStore {
            knowledgeWindow = KnowledgeCenterWindowController(
                store: knowledgeStore,
                projects: [.init(id: "quick-chat", displayName: "Chat")]
            )
            knowledgeWindow?.onOpenStorage = { url in
                NSWorkspace.shared.activateFileViewerSelecting([url])
            }
        }
        if let workspaceJournal {
            recoveryWindow = WorkspaceRecoveryWindowController(journal: workspaceJournal)
            recoveryWindow?.onCheckpointCaptured = { [weak self] checkpoint in
                self?.activityStore.addCompleted(
                    .backup,
                    title: "Workspace checkpoint",
                    detail: "Protected \(checkpoint.files.count) recoverable files before further agent work."
                )
            }
            recoveryWindow?.onPrepareRestore = { [weak self] completion in
                guard let self else {
                    completion(.failure(HarnessConversationError.cancellationUnverified))
                    return
                }
                Task { @MainActor in
                    do {
                        guard self.workspaceRestorePermit == nil else {
                            throw ProtectedRuntimeMutationCoordinatorError.busy(.workspaceRestore)
                        }
                        let permit = try await self.protectedRuntimeMutations.acquire(
                            kind: .workspaceRestore,
                            requirement: .stoppedRuntime
                        )
                        self.workspaceRestorePermit = permit
                        completion(.success(()))
                    } catch { completion(.failure(error)) }
                }
            }
            recoveryWindow?.onRestoreCompleted = { [weak self] report in
                guard let self else { return }
                self.activityStore.addCompleted(
                    .backup,
                    title: "Workspace restored",
                    detail: "Restored \(report.restoredDeletedFiles) missing, replaced \(report.overwrittenModifiedFiles) modified, and removed \(report.removedAddedFiles) added files."
                )
                self.privacyLedger.record(.backupRestored, summary: "Workspace recovery checkpoint restored", localOnly: true)
            }
            recoveryWindow?.onRestoreAttemptFinished = { [weak self] restoreSucceeded in
                guard let self, let permit = self.workspaceRestorePermit else { return }
                self.workspaceRestorePermit = nil
                Task { @MainActor in
                    do {
                        try await self.protectedRuntimeMutations.finish(
                            permit,
                            mutationCommitted: restoreSucceeded
                        )
                    }
                    catch {
                        self.showAlert(
                            title: restoreSucceeded ? "Workspace restored; runtime blocked" : "Runtime recovery is blocked",
                            message: error.localizedDescription
                        )
                    }
                }
            }
        }
        performanceWindow = PerformanceCenterWindowController(snapshot: performanceSnapshot(ollama: .unavailable()))
        performanceWindow?.onClearHistory = { [weak self] in
            Task { @MainActor in self?.clearPerformanceHistory() }
        }
        privacyWindow = PrivacyDashboardWindowController(ledger: privacyLedger, preferences: preferences, maintenance: privacyMaintenance)
        pluginTrustWindow = PluginTrustWindowController(controller: controller)
        backupWindow = BackupWindowController(manager: backupManager) { [weak controller] in
            controller?.runtimeInfo()?.dshVersion ?? "Unknown"
        }
        scheduleWindow = ScheduleWindowController(manager: scheduleManager, preferences: preferences)
        commandCenterWindow = CommandCenterWindowController(
            commands: commandCenterCommands(),
            actionTarget: self
        )

        providerWindow.onSelectionCommitted = { [weak self] _, _ in
            guard let self else { return }
            self.refreshProviderCatalog()
        }
        providerWindow.onPrepareProtectedMutation = { [weak self] mutation in
            guard let self else { throw NativeProviderStateRecoveryError.stateChanged }
            guard self.providerProtectedMutationPermit == nil else {
                throw ProtectedRuntimeMutationCoordinatorError.busy(.providerCredential)
            }
            let kind: ProtectedRuntimeMutationKind
            switch mutation.kind {
            case .profile: kind = .providerProfile
            case .credential: kind = .providerCredential
            case .activation: kind = .providerActivation
            }
            let permit = try await self.protectedRuntimeMutations.acquire(
                kind: kind,
                requirement: .providerControlPlane
            )
            var priorConsent: ProviderConsentState?
            do {
                if mutation.kind == .profile {
                    priorConsent = try self.providerConsentStore.load()
                    try self.providerConsentStore.deactivate(mutation.providerID)
                }
                self.providerProtectedMutationPermit = (mutation, permit, priorConsent)
            } catch let mutationError {
                var stateRecoveryError: Error?
                if let priorConsent {
                    do { try self.providerConsentStore.restore(priorConsent) }
                    catch { stateRecoveryError = error }
                }
                do { try await self.protectedRuntimeMutations.finish(permit) }
                catch {
                    throw ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(kind: kind)
                }
                if stateRecoveryError != nil {
                    throw ProtectedRuntimeMutationCoordinatorError.mutationAndRecoveryFailed(kind: kind)
                }
                throw mutationError
            }
        }
        providerWindow.onProtectedMutationFinished = { [weak self] mutation, mutationEffect in
            guard let self,
                  let owned = self.providerProtectedMutationPermit,
                  owned.request == mutation else {
                throw ProtectedRuntimeMutationCoordinatorError.invalidPermit
            }
            self.providerProtectedMutationPermit = nil
            var effectiveMutationEffect = mutationEffect
            var stateRecoveryError: Error?
            if mutationEffect == .notCommitted, let priorConsent = owned.priorConsent {
                do { try self.providerConsentStore.restore(priorConsent) }
                catch {
                    effectiveMutationEffect = .uncertain
                    stateRecoveryError = error
                }
            }
            do {
                let defaultProvider = (try? self.modelSettingsStore.loadOrMigrate()
                    .settings.defaultSelection.route.provider) ?? ModelSelection.defaultLocal.route.provider
                let disposition = ProviderMutationCompletionPolicy.disposition(
                    for: mutation,
                    effect: effectiveMutationEffect,
                    defaultProvider: defaultProvider
                )
                try await self.protectedRuntimeMutations.finish(
                    owned.permit,
                    disposition: disposition,
                    mutationCommitted: effectiveMutationEffect == .committed
                )
            } catch {
                if effectiveMutationEffect == .uncertain {
                    throw ProtectedRuntimeMutationCoordinatorError.mutationOutcomeUncertainAndRecoveryFailed(
                        kind: owned.permit.kind
                    )
                }
                throw error
            }
            if let stateRecoveryError { throw stateRecoveryError }
        }
        providerWindow.onOpenHarnessProviderSettings = { [weak self] in self?.openHarnessProviderSettings(nil) }
        providerWindow.onPerformanceProfileRequested = { [weak self] profile in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            try await self.applyPerformanceProfile(profile)
        }
        historyWindow.onSessionSelected = { [weak self] sessionID in self?.continueSession(sessionID) }
        companionWindow.quickChat.onDefaultSelectionChanged = { [weak self] _, _ in
            guard let self else { return }
            self.refreshProviderCatalog()
        }
        companionWindow.quickChat.onWillStartTurn = { [weak self] in
            guard let self else {
                throw WorkspaceJournalError.unsafeStorage
            }
            guard !self.thermalSafetyBlocksSelectedLocalRuntime else {
                throw self.currentLocalRuntimeAdmissionError
            }
            guard let coordinator = self.workspaceRecoveryCoordinator else {
                throw WorkspaceJournalError.unsafeStorage
            }
            let protection = try await coordinator.captureBeforeTurn(reason: "Before Chat turn")
            await MainActor.run { [weak self] in self?.recoveryWindow?.refresh() }
            return protection
        }

        mainWindow.surface.delegate = self
        settingsWindow.onRestartServicesRequested = { [weak self] in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            if let boundary = self.pendingThermalNormalModeRecovery?.boundary {
                guard self.retryPendingThermalNormalModeRecoveryIfPossible() else {
                    throw self.pendingThermalNormalModeRecovery
                        ?? ThermalNormalModeRecoveryFailure(
                            boundary: boundary,
                            reason: "The private adaptive-performance policy could not be saved and verified."
                        )
                }
                if boundary == .cooldownRecovered { return }
            }
            guard !self.thermalSafetyBlocksSelectedLocalRuntime else {
                throw self.currentLocalRuntimeAdmissionError
            }
            try await self.protectedRuntimeMutations.perform(
                kind: .manualRestart,
                requirement: .stoppedRuntime
            ) { permit in
                try permit.validate()
            }
        }
        settingsWindow.onPerformanceProfileRequested = { [weak self] profile in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            try await self.applyPerformanceProfile(profile)
        }
        settingsWindow.onSSHAgentAccessRequested = { [weak self] allowed in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            try await self.protectedRuntimeMutations.perform(
                kind: .sshAgentAccess,
                requirement: .stoppedRuntime
            ) { permit in
                try permit.validate()
                self.preferences.allowSSHAgent = allowed
            }
        }
        settingsWindow.onOpenDiagnostics = { [weak self] in self?.showDiagnostics(nil) }
        settingsWindow.onClearWebDataRequested = { [weak self] in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            try await self.protectedRuntimeMutations.perform(
                kind: .websiteData,
                requirement: .stoppedRuntime
            ) { permit in
                try permit.validate()
                let callback = ProtectedRuntimeReadinessWaiter()
                try await callback.wait(
                    label: "WebKit to clear Harness website data",
                    timeout: .seconds(30)
                ) {
                    self.mainWindow.surface.clearWebData { [weak callback] in
                        do {
                            try LegacyWebsiteDataCleaner.live().clear()
                            _ = callback?.resume(with: .success(()))
                        } catch {
                            _ = callback?.resume(with: .failure(error))
                        }
                    }
                }
            }
        }
        settingsWindow.onOpenPrivacy = { [weak self] in self?.showPrivacyDashboard(nil) }
        settingsWindow.onOpenPluginTrust = { [weak self] in self?.showPluginTrust(nil) }
        settingsWindow.onOpenBackups = { [weak self] in self?.showBackups(nil) }
        settingsWindow.onOpenMenuBarSettings = { [weak self] in self?.showMenuBarSettings(nil) }
        settingsWindow.onMigrateCredentials = { [weak self] in self?.offerCredentialMigration(continueAfter: false) }
        backupWindow.onAcquireProtectedTransition = { [weak self] operation, completion in
            guard let self else {
                completion(.failure(HarnessConversationError.cancellationUnverified))
                return
            }
            self.acquireStateBackupTransition(operation, completion: completion)
        }
        backupWindow.onFinishProtectedTransition = { [weak self] permit, disposition, result, completion in
            guard let self else { completion(); return }
            self.finishStateBackupTransition(
                permit,
                disposition: disposition,
                result: result,
                completion: completion
            )
        }
        backupWindow.onRestoreCompleted = { [weak self] report in
            self?.privacyLedger.record(.backupRestored, summary: "Harness state backup restored", localOnly: true)
            if let quarantine = report.quarantineURL {
                self?.activityStore.addCompleted(
                    .backup,
                    title: "Harness state restored",
                    detail: "The previous state remains quarantined at \(quarantine.path)."
                )
            }
        }
    }

    private func commandCenterCommands() -> [CommandCenterCommand] {
        [
            .init(
                title: "Chat", detail: "Open the fast native conversation window",
                symbolName: "bubble.left.and.bubble.right", keywords: ["quick", "ask", "option space"],
                action: #selector(showQuickChat(_:))
            ),
            .init(
                title: "Agent Workspace", detail: "Use the full coding agent, tools and trajectory",
                symbolName: "hammer", keywords: ["dsh", "code", "tools", "project"],
                action: #selector(showMainWindow(_:))
            ),
            .init(
                title: "New Task", detail: "Start a fresh task after a recovery checkpoint",
                symbolName: "square.and.pencil", keywords: ["session", "conversation", "agent"],
                action: #selector(newSession(_:))
            ),
            .init(
                title: "Task History", detail: "Search, continue, rename, branch, archive or export tasks",
                symbolName: "clock.arrow.circlepath", keywords: ["sessions", "conversations", "export"],
                action: #selector(showTaskHistory(_:))
            ),
            .init(
                title: "Models & Providers", detail: "Choose local Qwen, DeepSeek or another API",
                symbolName: "memorychip", keywords: ["ollama", "cloud", "api", "private", "key"],
                action: #selector(showProviderCenter(_:))
            ),
            .init(
                title: "Local Model Memory", detail: "Inspect installed models and release local memory",
                symbolName: "gauge.with.dots.needle.67percent", keywords: ["ollama", "ram", "resident", "unload"],
                action: #selector(showModelManager(_:))
            ),
            .init(
                title: "Knowledge & Memory", detail: "Manage private context stored on this Mac",
                symbolName: "books.vertical", keywords: ["documents", "retrieval", "local"],
                action: #selector(showKnowledgeCenter(_:))
            ),
            .init(
                title: "Capture Appshot", detail: "Capture, redact and review a window before attaching it",
                symbolName: "viewfinder", keywords: ["screenshot", "screen", "ocr", "image"],
                action: #selector(captureAppshot(_:))
            ),
            .init(
                title: "Activity Center", detail: "See current and completed work in one place",
                symbolName: "list.bullet.rectangle", keywords: ["jobs", "progress", "tasks"],
                action: #selector(showActivityCenter(_:))
            ),
            .init(
                title: "Schedules & Task Inbox", detail: "Run recurring work and review its results",
                symbolName: "calendar.badge.clock", keywords: ["automation", "background", "recurring"],
                action: #selector(showSchedules(_:))
            ),
            .init(
                title: "Skills", detail: "Review and control reusable agent instructions",
                symbolName: "puzzlepiece.extension", keywords: ["plugins", "instructions", "trust"],
                action: #selector(showSkillsCenter(_:))
            ),
            .init(
                title: "MCP Servers", detail: "Review local tool integrations and every approval",
                symbolName: "point.3.connected.trianglepath.dotted", keywords: ["tools", "plugins", "integration"],
                action: #selector(showMCPServers(_:))
            ),
            .init(
                title: "Workspace Recovery", detail: "Preview checkpoints and safely restore files",
                symbolName: "arrow.counterclockwise.circle", keywords: ["backup", "restore", "files"],
                action: #selector(showWorkspaceRecovery(_:))
            ),
            .init(
                title: "Performance Center", detail: "See speed, memory, thermal state and recommendations",
                symbolName: "speedometer", keywords: ["temperature", "heat", "tokens", "ram"],
                action: #selector(showPerformanceCenter(_:))
            ),
            .init(
                title: "Privacy Dashboard", detail: "Review data boundaries, retention and disclosures",
                symbolName: "hand.raised", keywords: ["local", "cloud", "security", "ledger"],
                action: #selector(showPrivacyDashboard(_:))
            ),
            .init(
                title: "Backups & Restore", detail: "Protect or restore private agent state",
                symbolName: "externaldrive.badge.timemachine", keywords: ["recovery", "dsh", "upgrade"],
                action: #selector(showBackups(_:))
            ),
            .init(
                title: "Diagnostics", detail: "Copy a sanitized support report or restart services",
                symbolName: "stethoscope", keywords: ["logs", "error", "support", "runtime"],
                action: #selector(showDiagnostics(_:))
            ),
            .init(
                title: "Settings", detail: "General, models, privacy and advanced controls",
                symbolName: "gearshape", keywords: ["preferences", "thermal", "login"],
                action: #selector(showSettings(_:))
            )
        ]
    }

    @MainActor
    private func useLocalModelForNewTasks(
        _ modelName: String,
        completion: @escaping (Result<ModelSelection, Error>) -> Void
    ) {
        Task { @MainActor [weak self] in
            guard let self else {
                completion(.failure(ModelSelectionCoordinatorError.settingsUnavailable))
                return
            }
            do {
                guard OllamaModelNamePolicy.isSafe(modelName) else {
                    throw ModelSelectionCoordinatorError.invalidSelection
                }
                let previousSelection = try modelSettingsStore.loadOrMigrate().settings.defaultSelection
                let selection = ModelSelection(
                    route: ModelRoute(
                        provider: BuiltInProviderDescriptors.ollama.id,
                        model: ModelID(modelName)
                    ),
                    performanceProfile: previousSelection.performanceProfile
                )
                // The shared provider transaction first performs the bounded,
                // read-only model preflight. Only an admitted model may stop
                // the exact old DSH/Ollama generation, write the default
                // through the zero-egress control plane, and start a fresh
                // Ollama on a new private port. Topology verification then
                // rechecks that exact endpoint before exposing any session.
                let result = try await providerSelectionTransaction.commit(
                    selection: selection,
                    descriptor: BuiltInProviderDescriptors.ollama
                )
                completion(.success(result.selection))
                refreshProviderCatalog()
            } catch {
                completion(.failure(error))
            }
        }
    }

    private func runStartupPrivacyMaintenance(completion: @escaping () -> Void) {
        let maintenance = privacyMaintenance
        privacyMaintenanceQueue.async {
            _ = maintenance.run(includeAttachments: true)
            DispatchQueue.main.async(execute: completion)
        }
    }

    /// The mandatory startup order is Harness-home detection first, signed
    /// auxiliary-namespace detection second, and only then retention,
    /// credentials, backup reconciliation, Ollama, DSH, or provider egress.
    /// Background launch uses this same route but never accepts a prompt or
    /// performs a recovery mutation.
    private func beginProviderHistoryStartupGate(
        background: Bool,
        completion: @escaping (Bool) -> Void
    ) {
        guard providerHistoryStartupGateToken == nil,
              startupRuntimeContinuationPermitted else {
            completion(false)
            return
        }
        let gateToken = UUID()
        providerHistoryStartupGateToken = gateToken
        let finish: (Bool) -> Void = { [weak self] admitted in
            guard let self,
                  self.providerHistoryStartupGateToken == gateToken else { return }
            self.providerHistoryStartupGateToken = nil
            completion(admitted)
        }
        let inspectAuxiliary: () -> Void = { [weak self] in
            guard let self, self.startupRuntimeContinuationPermitted else {
                finish(false)
                return
            }
            let auxiliary = self.auxiliaryStateCoordinator
            let support = self.controller.diagnosticsDirectory().standardizedFileURL
            let backups = self.backupManager
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { () throws -> ProviderHistoryAuxiliaryPendingState? in
                    let pending = try auxiliary.preflight()
                    guard pending == nil else { return pending }
                    // The opaque whole-root auxiliary gate is authoritative and
                    // must run first. Only after it verifies absent/current
                    // signed namespaces may these component-specific readers
                    // inspect manifests or migration state.
                    guard try backups.privacyEpochPreflight() != .historical,
                          try RuntimeMigrationCoordinator.privacyEpochPreflight(
                            applicationSupport: support
                          ) != .historical else {
                        throw ProviderHistoryAuxiliaryRecoveryError.historicalStateChanged
                    }
                    return nil
                }
                DispatchQueue.main.async {
                    guard self.startupRuntimeContinuationPermitted else {
                        finish(false)
                        return
                    }
                    switch result {
                    case .success(nil):
                        finish(true)
                    case .success(.some(let pending)):
                        if background {
                            self.recordBackgroundAuxiliaryRecoveryPending(pending)
                            finish(false)
                        } else {
                            self.presentAuxiliaryRecovery(pending, completion: finish)
                        }
                    case .failure(let error):
                        if background {
                            self.recordBackgroundAuxiliaryRecoveryFailure(error)
                        } else {
                            self.presentAuxiliaryRecoveryFailure(
                                error,
                                recoveryFolder: support.appendingPathComponent(
                                    "ProviderHistoryAuxiliaryRecovery",
                                    isDirectory: true
                                ),
                                token: nil
                            )
                        }
                        finish(false)
                    }
                }
            }
        }
        controller.preflightHarnessHomeRecoveryForBackgroundSchedule(
            backgroundDetectionOnly: background
        ) { [weak self] homeResult in
            guard let self, self.startupRuntimeContinuationPermitted else {
                finish(false)
                return
            }
            guard case .success(let homeStatus) = homeResult else {
                if !background,
                   case .failure(let error) = homeResult,
                   DeviceAttestationTrustRecoveryCoordinator.isRecoverable(error) {
                    self.presentDeviceAttestationTrustRecovery(
                        after: error,
                        resume: inspectAuxiliary,
                        stop: { finish(false) }
                    )
                    return
                }
                // The controller publishes the exact home pending state before
                // delivering failure. Background owns only a durable
                // activity/notification signal and never receives a prompt.
                finish(false)
                return
            }
            if background, homeStatus != .current {
                self.recordBackgroundHarnessHomeInitializationRequired()
                finish(false)
                return
            }
            if background {
                inspectAuxiliary()
            } else {
                self.controller.prepareHarnessHomeForForegroundProviderHistoryGate { result in
                    guard self.startupRuntimeContinuationPermitted else {
                        finish(false)
                        return
                    }
                    switch result {
                    case .success:
                        inspectAuxiliary()
                    case .failure(let error)
                        where DeviceAttestationTrustRecoveryCoordinator.isRecoverable(error):
                        self.presentDeviceAttestationTrustRecovery(
                            after: error,
                            resume: inspectAuxiliary,
                            stop: { finish(false) }
                        )
                    case .failure:
                        // Typed recovery state was published before completion.
                        // No auxiliary namespace, retention, credential, backup,
                        // runtime, or provider boundary was touched.
                        finish(false)
                    }
                }
            }
        }
    }

    private func presentDeviceAttestationTrustRecovery(
        after error: Error,
        resume: @escaping () -> Void,
        stop: @escaping () -> Void
    ) {
        precondition(Thread.isMainThread)
        guard !deviceAttestationTrustRecoveryPresentationInFlight else {
            stop()
            return
        }
        deviceAttestationTrustRecoveryPresentationInFlight = true
        controller.inspectDeviceAttestationTrustRecovery(after: error) { [weak self] result in
            guard let self else {
                stop()
                return
            }
            switch result {
            case .failure:
                self.deviceAttestationTrustRecoveryPresentationInFlight = false
                self.presentDeviceAttestationTrustRecoveryFailure()
                stop()
            case .success(let request):
                let alert = NSAlert()
                alert.alertStyle = .critical
                alert.messageText = "Repair this Mac's private trust record?"
                alert.informativeText = "Fulmar found an interrupted, incomplete, or inconsistent device-attestation record. Local and cloud provider work is stopped. If you continue, every existing Harness home, recovery journal, backup, migration namespace, and attestation-control namespace will first be moved whole into a new private recovery folder. Fulmar will then reset only its two exact device-attestation Keychain items and create a clean, newly attested Harness home. Nothing in an older recovery folder is deleted or overwritten."
                alert.addButton(withTitle: "Preserve all private state and repair")
                alert.addButton(withTitle: "Keep stopped")
                guard alert.runModal() == .alertFirstButtonReturn else {
                    self.controller.cancelDeviceAttestationTrustRecovery(request)
                    self.deviceAttestationTrustRecoveryPresentationInFlight = false
                    stop()
                    return
                }
                self.showLoading("Preserving private state and repairing device trust…")
                self.controller.recoverDeviceAttestationTrustAfterExplicitConfirmation(request) {
                    [weak self] repairResult in
                    guard let self else {
                        stop()
                        return
                    }
                    self.deviceAttestationTrustRecoveryPresentationInFlight = false
                    switch repairResult {
                    case .success(let receipt):
                        self.activityStore.addCompleted(
                            .runtime,
                            title: "Repaired private device trust",
                            detail: "All previous provider and history namespaces were retained in \(receipt.recoveryOperation.lastPathComponent)."
                        )
                        resume()
                    case .failure:
                        self.presentDeviceAttestationTrustRecoveryFailure()
                        stop()
                    }
                }
            }
        }
    }

    private func presentDeviceAttestationTrustRecoveryFailure() {
        precondition(Thread.isMainThread)
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Private trust repair could not be verified"
        alert.informativeText = "Fulmar kept local and cloud provider work stopped. Any state already preserved remains under DeviceTrustRecovery and was not deleted or overwritten. Close other Fulmar copies, then retry from the foreground."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func recordBackgroundHarnessHomeInitializationRequired() {
        _ = try? activityStore.addWaitingSynchronously(
            .runtime,
            title: "Foreground initialization required",
            detail: "Background schedules remained stopped because this Mac has no authenticated Harness home yet. Detection created no files and accessed no credential."
        )
        notifications.send(
            title: "Open \(ProductBrand.displayName) to finish private setup",
            body: "No local or cloud model work started during this background wake.",
            identifier: "harness-home-foreground-initialization-required"
        )
    }

    private func recordBackgroundAuxiliaryRecoveryPending(
        _ pending: ProviderHistoryAuxiliaryPendingState
    ) {
        let detail: String
        switch pending {
        case .initial:
            detail = "Historical Backups, restore recovery, or Migration state needs an explicit foreground preserve decision. Detection changed no data and accessed no credential."
        case .namespacePublication:
            detail = "An interrupted signed Backups, restore-recovery, or Migration installation needs explicit foreground reconciliation. Detection changed no data and accessed no provider credential."
        case .interrupted:
            detail = "An interrupted whole-directory provider-state preservation needs explicit foreground resume. Detection changed no data and accessed no credential."
        case .published:
            detail = "Preserved provider-state directories and their append-only journal need foreground acknowledgement before startup."
        }
        _ = try? activityStore.addWaitingSynchronously(
            .runtime,
            title: "Provider-state privacy review required",
            detail: "Background schedules remained stopped. \(detail)"
        )
        notifications.send(
            title: "Open \(ProductBrand.displayName) to review preserved state",
            body: "Background schedules stayed stopped; local and cloud model work did not start.",
            identifier: "provider-history-auxiliary-recovery-required"
        )
    }

    private func recordBackgroundAuxiliaryRecoveryFailure(_ error: Error) {
        let detail = AuxiliaryDisplayPolicy.singleLine(
            error.localizedDescription,
            maximumCharacters: 800,
            fallback: "Provider-history auxiliary state could not be verified."
        )
        _ = try? activityStore.addWaitingSynchronously(
            .runtime,
            title: "Provider-state privacy verification failed closed",
            detail: "Background schedules remained stopped. \(detail)"
        )
        notifications.send(
            title: "Open \(ProductBrand.displayName) to inspect provider state",
            body: "No model, credential migration, retention, or provider work was admitted.",
            identifier: "provider-history-auxiliary-recovery-failed"
        )
    }

    private func presentAuxiliaryRecovery(
        _ pending: ProviderHistoryAuxiliaryPendingState,
        completion: @escaping (Bool) -> Void
    ) {
        guard auxiliaryRecoveryPresentationToken == nil,
              !auxiliaryRecoveryMutationInFlight,
              startupRuntimeContinuationPermitted else {
            completion(false)
            return
        }
        let token = UUID()
        auxiliaryRecoveryPresentationToken = token
        switch pending {
        case .initial(let request):
            switch auxiliaryRecoveryInteractions.chooseInitial(request) {
            case .preserve:
                guard auxiliaryRecoveryPresentationToken == token,
                      startupRuntimeContinuationPermitted else {
                    completion(false)
                    return
                }
                let coordinator = auxiliaryStateCoordinator
                performAuxiliaryRecovery(
                    token: token,
                    completion: completion
                ) {
                    try coordinator
                        .preserveAfterExplicitAcknowledgement(request)
                }
            case .keepStopped:
                keepAuxiliaryRecoveryStopped(token: token, completion: completion)
            }
        case .namespacePublication(let request):
            switch auxiliaryRecoveryInteractions.chooseNamespacePublication(request) {
            case .preserve:
                guard auxiliaryRecoveryPresentationToken == token,
                      startupRuntimeContinuationPermitted else {
                    completion(false)
                    return
                }
                performAuxiliaryNamespacePublicationRecovery(
                    request,
                    token: token,
                    completion: completion
                )
            case .keepStopped:
                keepAuxiliaryRecoveryStopped(token: token, completion: completion)
            }
        case .interrupted(let request):
            switch auxiliaryRecoveryInteractions.chooseInterrupted(request) {
            case .resume:
                guard auxiliaryRecoveryPresentationToken == token,
                      startupRuntimeContinuationPermitted else {
                    completion(false)
                    return
                }
                let coordinator = auxiliaryStateCoordinator
                performAuxiliaryRecovery(
                    token: token,
                    completion: completion
                ) {
                    try coordinator
                        .resumeAfterExplicitAcknowledgement(request)
                }
            case .openRecoveryFolder:
                auxiliaryRecoveryInteractions.reveal(request.recoveryDirectory)
                keepAuxiliaryRecoveryStopped(token: token, completion: completion)
            case .keepStopped:
                keepAuxiliaryRecoveryStopped(token: token, completion: completion)
            }
        case .published(let receipt):
            presentPublishedAuxiliaryRecovery(
                receipt,
                token: token,
                completion: completion
            )
        }
    }

    private func performAuxiliaryNamespacePublicationRecovery(
        _ request: ProviderHistoryAuxiliaryNamespacePublicationRequest,
        token: UUID,
        completion: @escaping (Bool) -> Void
    ) {
        guard auxiliaryRecoveryPresentationToken == token,
              !auxiliaryRecoveryMutationInFlight,
              startupRuntimeContinuationPermitted else {
            completion(false)
            return
        }
        auxiliaryRecoveryMutationInFlight = true
        showLoading("Reconciling exact signed private-state installation…")
        let coordinator = auxiliaryStateCoordinator
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result {
                try coordinator.reconcileNamespacePublicationsAfterExplicitAcknowledgement(request)
            }
            DispatchQueue.main.async {
                guard let self else {
                    completion(false)
                    return
                }
                self.auxiliaryRecoveryMutationInFlight = false
                guard self.auxiliaryRecoveryPresentationToken == token,
                      self.startupRuntimeContinuationPermitted else {
                    completion(false)
                    return
                }
                switch result {
                case .success(let next):
                    self.auxiliaryRecoveryPresentationToken = nil
                    if let next {
                        self.presentAuxiliaryRecovery(next, completion: completion)
                    } else {
                        self.showLoading("Signed private state is current. Continuing protected startup…")
                        completion(true)
                    }
                case .failure(let error):
                    self.presentAuxiliaryRecoveryFailure(
                        error,
                        recoveryFolder: request.applicationSupport,
                        token: token
                    )
                    completion(false)
                }
            }
        }
    }

    private func performAuxiliaryRecovery(
        token: UUID,
        completion: @escaping (Bool) -> Void,
        operation: @escaping @Sendable () throws -> ProviderHistoryAuxiliaryRecoveryReceipt
    ) {
        guard auxiliaryRecoveryPresentationToken == token,
              !auxiliaryRecoveryMutationInFlight,
              startupRuntimeContinuationPermitted else {
            completion(false)
            return
        }
        auxiliaryRecoveryMutationInFlight = true
        showLoading("Preserving whole historical provider-state directories…")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try operation() }
            DispatchQueue.main.async {
                guard let self else {
                    completion(false)
                    return
                }
                self.auxiliaryRecoveryMutationInFlight = false
                guard self.auxiliaryRecoveryPresentationToken == token,
                      self.startupRuntimeContinuationPermitted else {
                    completion(false)
                    return
                }
                switch result {
                case .success(let receipt):
                    self.presentPublishedAuxiliaryRecovery(
                        receipt,
                        token: token,
                        completion: completion
                    )
                case .failure(let error):
                    self.presentAuxiliaryRecoveryFailure(
                        error,
                        recoveryFolder: self.controller.diagnosticsDirectory()
                            .appendingPathComponent(
                                "ProviderHistoryAuxiliaryRecovery",
                                isDirectory: true
                            ),
                        token: token
                    )
                    completion(false)
                }
            }
        }
    }

    private func presentPublishedAuxiliaryRecovery(
        _ receipt: ProviderHistoryAuxiliaryRecoveryReceipt,
        token: UUID,
        completion: @escaping (Bool) -> Void
    ) {
        guard auxiliaryRecoveryPresentationToken == token,
              startupRuntimeContinuationPermitted else {
            completion(false)
            return
        }
        let choice = auxiliaryRecoveryInteractions.acknowledgePublished(receipt)
        guard auxiliaryRecoveryPresentationToken == token,
              startupRuntimeContinuationPermitted else {
            completion(false)
            return
        }
        switch choice {
        case .keepStopped:
            keepAuxiliaryRecoveryStopped(token: token, completion: completion)
            return
        case .openAndAcknowledge:
            auxiliaryRecoveryInteractions.reveal(receipt.recoveryDirectory)
        case .acknowledge:
            break
        }
        auxiliaryRecoveryMutationInFlight = true
        showLoading("Archiving the verified provider-state recovery journal…")
        let coordinator = auxiliaryStateCoordinator
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try coordinator.acknowledgePublishedRecovery(receipt) }
            DispatchQueue.main.async {
                guard let self else {
                    completion(false)
                    return
                }
                self.auxiliaryRecoveryMutationInFlight = false
                guard self.auxiliaryRecoveryPresentationToken == token,
                      self.startupRuntimeContinuationPermitted else {
                    completion(false)
                    return
                }
                switch result {
                case .success:
                    self.auxiliaryRecoveryPresentationToken = nil
                    self.showLoading("Historical provider state is preserved. Continuing protected startup…")
                    completion(true)
                case .failure(let error):
                    self.presentAuxiliaryRecoveryFailure(
                        error,
                        recoveryFolder: receipt.recoveryDirectory,
                        token: token
                    )
                    completion(false)
                }
            }
        }
    }

    private func presentAuxiliaryRecoveryFailure(
        _ error: Error,
        recoveryFolder: URL,
        token: UUID?
    ) {
        if let token, auxiliaryRecoveryPresentationToken != token { return }
        let message = AuxiliaryDisplayPolicy.singleLine(
            error.localizedDescription,
            maximumCharacters: 800,
            fallback: "Provider-history auxiliary state could not be verified."
        )
        if auxiliaryRecoveryInteractions.showFailure(message, recoveryFolder) {
            auxiliaryRecoveryInteractions.reveal(recoveryFolder)
        }
        if token == nil || auxiliaryRecoveryPresentationToken == token {
            auxiliaryRecoveryPresentationToken = nil
        }
        closeAllRuntimeAdmissionsSynchronously()
        mainWindow.surface.showFailure(
            "Provider-state recovery remains stopped. No historical output was deleted or overwritten."
        )
        mainWindow.updateStatus("Provider privacy review · Runtime stopped", color: .systemOrange)
    }

    private func keepAuxiliaryRecoveryStopped(
        token: UUID,
        completion: @escaping (Bool) -> Void
    ) {
        guard auxiliaryRecoveryPresentationToken == token else {
            completion(false)
            return
        }
        auxiliaryRecoveryPresentationToken = nil
        closeAllRuntimeAdmissionsSynchronously()
        mainWindow.surface.showFailure(
            "Fulmar remains stopped. Historical provider-state directories and transaction evidence were left unchanged. Restart Local Services when you are ready to review them."
        )
        mainWindow.updateStatus("Provider privacy review paused", color: .systemOrange)
        completion(false)
    }

    @MainActor
    private func applyPerformanceProfile(_ profile: PerformanceProfile) async throws {
        try await protectedRuntimeMutations.perform(
            kind: .performanceProfile,
            requirement: .stoppedRuntime
        ) { permit in
            try permit.validate()
            var settings = try self.modelSettingsStore.loadOrMigrate().settings
            guard settings.defaultSelection.isReleaseQualifiedLocalQwen else {
                throw LocalModelAdmissionError.variableProfilesRequireQualifiedLocalModel
            }
            try QualifiedLocalModelHostAdmissionPolicy.validate(
                selection: settings.defaultSelection,
                physicalMemoryBytes: self.hostPerformanceCollector.capture().physicalMemoryBytes
            )
            settings.defaultSelection.performanceProfile = profile
            try self.modelSettingsStore.save(settings)
        }
    }

    private func startPeriodicPrivacyMaintenance() {
        guard privacyMaintenanceTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: privacyMaintenanceQueue)
        timer.schedule(deadline: .now() + 3_600, repeating: 21_600, leeway: .seconds(300))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            _ = self.privacyMaintenance.run(includeAttachments: false)
        }
        timer.resume()
        privacyMaintenanceTimer = timer
    }

    private func buildMainMenu() {
        let main = NSMenu()

        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: ProductBrand.displayName)
        appItem.submenu = appMenu
        addItem(to: appMenu, title: "About \(ProductBrand.displayName)", action: #selector(showAbout(_:)))
        appMenu.addItem(.separator())
        addItem(to: appMenu, command: MainMenuShortcutCatalog.settings)
        addItem(to: appMenu, title: "Privacy Dashboard…", action: #selector(showPrivacyDashboard(_:)))
        appMenu.addItem(.separator())
        let servicesMenu = NSMenu(title: "Services")
        appMenu.addItem(withTitle: "Services", action: nil, keyEquivalent: "").submenu = servicesMenu
        NSApp.servicesMenu = servicesMenu
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide \(ProductBrand.displayName)", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = appMenu.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Show All", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit \(ProductBrand.displayName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        main.addItem(appItem)

        let fileItem = NSMenuItem()
        let file = NSMenu(title: "File")
        fileItem.submenu = file
        addItem(to: file, command: MainMenuShortcutCatalog.newSession)
        addItem(to: file, command: MainMenuShortcutCatalog.chat)
        addItem(to: file, command: MainMenuShortcutCatalog.commandCenter)
        addItem(to: file, command: MainMenuShortcutCatalog.appshot)
        file.addItem(.separator())
        addItem(to: file, command: MainMenuShortcutCatalog.activity)
        addItem(to: file, command: MainMenuShortcutCatalog.history)
        addItem(to: file, title: "Models & Providers", action: #selector(showProviderCenter(_:)))
        addItem(to: file, title: "Local Model Memory", action: #selector(showModelManager(_:)))
        addItem(to: file, title: "Knowledge & Memory", action: #selector(showKnowledgeCenter(_:)))
        addItem(to: file, title: "Skills", action: #selector(showSkillsCenter(_:)))
        addItem(to: file, title: "MCP Servers", action: #selector(showMCPServers(_:)))
        addItem(to: file, title: "Workspace Recovery", action: #selector(showWorkspaceRecovery(_:)))
        addItem(to: file, title: "Performance Center", action: #selector(showPerformanceCenter(_:)))
        addItem(to: file, title: "Schedules & Task Inbox", action: #selector(showSchedules(_:)))
        file.addItem(.separator())
        file.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        main.addItem(fileItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        editItem.submenu = edit
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        edit.addItem(.separator())
        addItem(to: edit, command: MainMenuShortcutCatalog.find)
        edit.addItem(.separator())
        edit.addItem(withTitle: "Start Dictation…", action: Selector(("startDictation:")), keyEquivalent: "")
        let characters = edit.addItem(withTitle: "Emoji & Symbols", action: #selector(NSApplication.orderFrontCharacterPalette(_:)), keyEquivalent: " ")
        characters.keyEquivalentModifierMask = [.control, .command]
        main.addItem(editItem)

        let viewItem = NSMenuItem()
        let view = NSMenu(title: "View")
        viewItem.submenu = view
        addItem(to: view, command: MainMenuShortcutCatalog.back)
        addItem(to: view, command: MainMenuShortcutCatalog.forward)
        addItem(to: view, command: MainMenuShortcutCatalog.reload)
        view.addItem(.separator())
        addItem(to: view, command: MainMenuShortcutCatalog.actualSize)
        addItem(to: view, command: MainMenuShortcutCatalog.zoomIn)
        addItem(to: view, command: MainMenuShortcutCatalog.zoomOut)
        view.addItem(withTitle: "Enter Full Screen", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f").keyEquivalentModifierMask = [.control, .command]
        main.addItem(viewItem)

        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowItem.submenu = windowMenu
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowMenu.addItem(.separator())
        addItem(to: windowMenu, command: MainMenuShortcutCatalog.mainWindow)
        addItem(to: windowMenu, title: "Chat", action: #selector(showQuickChat(_:)))
        addItem(to: windowMenu, title: "Command Center", action: #selector(showCommandCenter(_:)))
        addItem(to: windowMenu, title: "Activity Center", action: #selector(showActivityCenter(_:)))
        addItem(to: windowMenu, title: "Task History", action: #selector(showTaskHistory(_:)))
        addItem(to: windowMenu, title: "Models & Providers", action: #selector(showProviderCenter(_:)))
        addItem(to: windowMenu, title: "Local Model Memory", action: #selector(showModelManager(_:)))
        addItem(to: windowMenu, title: "Knowledge & Memory", action: #selector(showKnowledgeCenter(_:)))
        addItem(to: windowMenu, title: "Skills", action: #selector(showSkillsCenter(_:)))
        addItem(to: windowMenu, title: "MCP Servers", action: #selector(showMCPServers(_:)))
        addItem(to: windowMenu, title: "Workspace Recovery", action: #selector(showWorkspaceRecovery(_:)))
        addItem(to: windowMenu, title: "Performance Center", action: #selector(showPerformanceCenter(_:)))
        addItem(to: windowMenu, title: "Schedules & Task Inbox", action: #selector(showSchedules(_:)))
        main.addItem(windowItem)
        NSApp.windowsMenu = windowMenu

        let helpItem = NSMenuItem()
        let help = NSMenu(title: "Help")
        helpItem.submenu = help
        // In-app replacement remains intentionally absent from the user-facing
        // application until the updater has a durable two-phase journal and the
        // exact replacement proves nonce-bound app identity plus authenticated
        // Harness health. Keep the implementation available for that redesign,
        // but do not expose a launch-only transaction as a safe public update.
        addItem(to: help, title: "Show Fulmar in the Menu Bar…", action: #selector(showMenuBarSettings(_:)))
        help.addItem(.separator())
        addItem(to: help, title: "\(ProductBrand.displayName) Diagnostics", action: #selector(showDiagnostics(_:)))
        addItem(to: help, title: "DeepSeek Harness Project", action: #selector(openHarnessProject(_:)))
        main.addItem(helpItem)
        precondition(
            MainMenuShortcutCatalog.builtMenuConsumesEveryCommandExactlyOnce(main, target: self),
            "The built main menu must consume every Fulmar shortcut descriptor exactly once."
        )
        NSApp.helpMenu = help
        NSApp.mainMenu = main
    }

    private func addItem(to menu: NSMenu, title: String, action: Selector, key: String = "",
                         modifiers: NSEvent.ModifierFlags = [.command]) {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.target = self
        item.keyEquivalentModifierMask = modifiers
        menu.addItem(item)
    }

    private func addItem(to menu: NSMenu, command: MainMenuCommandDescriptor) {
        addItem(
            to: menu,
            title: command.title,
            action: command.action,
            key: command.shortcut.keyEquivalent,
            modifiers: command.shortcut.modifiers
        )
    }

    private func scheduleInitialStatusItemCreation() {
        DispatchQueue.main.asyncAfter(deadline: .now() + StatusItemIcon.initialCreationDelay) { [weak self] in
            guard let self, !self.thermalHeadlessMode else { return }
            self.buildStatusItem()
        }
    }

    private func buildStatusItem(placementRecoveryAttempt: Int = 0) {
        guard statusItem == nil else { return }
        StatusItemIcon.beginPlacementVerification(recoveryAttempt: placementRecoveryAttempt)
        statusItem = StatusItemIcon.makeStatusItem()
        statusItem?.autosaveName = StatusItemIcon.autosaveName
        if placementRecoveryAttempt > 0 {
            // isVisible can remain true while Control Center parks an item.
            // Reassert it only inside a physically proven, bounded recovery;
            // an ordinary later launch continues to restore the user choice.
            statusItem?.isVisible = true
        } else {
            StatusItemIcon.initializeVisibilityIfNeeded { [weak self] in
                self?.statusItem?.isVisible = true
            }
        }
        if let button = statusItem?.button {
            StatusItemIcon.configure(button: button)
        }
        let menu = NSMenu()
        addItem(to: menu, title: "Open \(ProductBrand.displayName)", action: #selector(showMainWindow(_:)))
        addItem(
            to: menu,
            title: hotKeyAvailability == .available ? "Chat  ⌥Space" : "Chat",
            action: #selector(showQuickChat(_:))
        )
        if let fallback = hotKeyAvailability.statusMenuDetail {
            let item = NSMenuItem(title: fallback, action: nil, keyEquivalent: "")
            item.isEnabled = false
            item.setAccessibilityLabel("Global Chat shortcut unavailable")
            item.setAccessibilityHelp("Open Chat from this menu or press Command-Option-Space while Fulmar is active.")
            menu.addItem(item)
        }
        addItem(to: menu, title: "Command Center…  ⌘K", action: #selector(showCommandCenter(_:)))
        let serviceStatus = NSMenuItem(title: statusMenuTitle, action: nil, keyEquivalent: "")
        serviceStatus.isEnabled = false
        statusMenuItem = serviceStatus
        menu.addItem(serviceStatus)
        menu.addItem(.separator())
        addItem(to: menu, title: "Capture Appshot", action: #selector(captureAppshot(_:)))
        addItem(to: menu, title: "Activity Center…", action: #selector(showActivityCenter(_:)))
        addItem(to: menu, title: "Task History…", action: #selector(showTaskHistory(_:)))
        addItem(to: menu, title: "Models & Providers…", action: #selector(showProviderCenter(_:)))
        addItem(to: menu, title: "Local Model Memory…", action: #selector(showModelManager(_:)))
        addItem(to: menu, title: "Knowledge & Memory…", action: #selector(showKnowledgeCenter(_:)))
        addItem(to: menu, title: "Skills…", action: #selector(showSkillsCenter(_:)))
        addItem(to: menu, title: "MCP Servers…", action: #selector(showMCPServers(_:)))
        addItem(to: menu, title: "Workspace Recovery…", action: #selector(showWorkspaceRecovery(_:)))
        addItem(to: menu, title: "Performance Center…", action: #selector(showPerformanceCenter(_:)))
        addItem(to: menu, title: "Schedules…", action: #selector(showSchedules(_:)))
        addItem(to: menu, title: "Restart Local Services", action: #selector(restartServices(_:)))
        addItem(to: menu, title: "Diagnostics…", action: #selector(showDiagnostics(_:)))
        addItem(to: menu, title: "Settings…", action: #selector(showSettings(_:)))
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit \(ProductBrand.displayName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        if statusItemAcceptanceMode {
            // The shipped acceptance entry point is intentionally inert apart
            // from Quit. It proves production menu construction and placement
            // without exposing actions whose normal windows/runtime were not
            // initialized in this lightweight test launch.
            menu.autoenablesItems = false
            for item in menu.items where item.action != #selector(NSApplication.terminate(_:)) {
                item.isEnabled = false
            }
        }
        statusItem?.menu = menu
        if let item = statusItem {
            scheduleStatusItemPlacementVerification(
                for: item,
                attempt: placementRecoveryAttempt
            )
        }
    }

    private func scheduleStatusItemPlacementVerification(
        for item: NSStatusItem,
        attempt: Int
    ) {
        DispatchQueue.main.asyncAfter(deadline: .now() + StatusItemIcon.placementRecoveryDelay) { [weak self, weak item] in
            guard let self, let item else { return }
            let menuBarHeight = max(NSStatusBar.system.thickness + 12, 40)
            let decision = StatusItemIcon.placementDecision(
                isCurrentItem: self.statusItem === item,
                isVisible: item.isVisible,
                frame: item.button?.window?.frame,
                screenFrames: NSScreen.screens.map(\.frame),
                menuBarHeight: menuBarHeight,
                attempt: attempt
            )
            StatusItemIcon.recordPlacementDecision(decision, recoveryAttempt: attempt)
            switch decision {
            case .ignoreStaleCallback, .respectPersistedHidden,
                 .acceptVisiblePlacement, .giveUpAfterBoundedAttempts:
                return
            case .recreate(let nextAttempt):
                self.removeStatusItem(item)
                self.statusItem = nil
                self.statusMenuItem = nil
                self.buildStatusItem(placementRecoveryAttempt: nextAttempt)
            }
        }
    }

    private func removeStatusItem(_ item: NSStatusItem) {
        item.menu = nil
        item.autosaveName = nil
        if let owningStatusBar = item.statusBar {
            owningStatusBar.removeStatusItem(item)
        } else {
            NSStatusBar.system.removeStatusItem(item)
        }
    }

    private func tearDownStatusItem() {
        guard let item = statusItem else {
            statusMenuItem = nil
            return
        }
        // Once termination is irreversible, synchronously deregister the
        // retained item. This prevents a rapid relaunch from overlapping a
        // stale Control Center host. Detach the autosave identity first:
        // removeStatusItem is a programmatic lifecycle operation, not a user
        // visibility choice, and must not let an asynchronous Control Center
        // save restore the next launch at its hidden parking coordinate. A
        // user's removal while Fulmar is running remains persisted normally.
        removeStatusItem(item)
        statusItem = nil
        statusMenuItem = nil
    }

    private func updateStatusMenuTitle(_ title: String) {
        statusMenuTitle = title
        statusMenuItem?.title = title
    }

    private var selectedRuntimeIsAppOwnedLocal: Bool {
        guard let selection = try? modelSettingsStore.loadOrMigrate().settings.defaultSelection else {
            // A missing or unreadable native selection must never be used to
            // bypass a safety hold. The product default is the local route.
            return true
        }
        return selection.route.provider == BuiltInProviderDescriptors.ollama.id
    }

    func mayPublishReadyStatusForThermalPolicy(
        localRuntimeSelected: Bool
    ) -> Bool {
        mayAdmitWorkForThermalPolicy(localRuntimeSelected: localRuntimeSelected)
    }

    func mayAdmitWorkForThermalPolicy(
        localRuntimeSelected: Bool
    ) -> Bool {
        !localRuntimeSelected || pendingThermalNormalModeRecovery == nil
    }

    private var thermalSafetyBlocksSelectedLocalRuntime: Bool {
        let localRuntimeRelevant = selectedRuntimeIsAppOwnedLocal
        return ThermalRuntimeAdmissionPolicy.blocksSelectedLocalRuntime(
            localRuntimeSelected: localRuntimeRelevant,
            normalModeRecoveryPending: pendingThermalNormalModeRecovery != nil,
            phase: thermalSafety.phase,
            memoryPressureBlocksNewLocalGeneration: memoryPressureRouteGate.blocksNewLocalGeneration(
                localRuntimeRelevant: localRuntimeRelevant,
                uptime: ProcessInfo.processInfo.systemUptime
            )
        )
    }

    private var thermalSafetyRequiresSelectedLocalShutdown: Bool {
        let localRuntimeRelevant = selectedRuntimeIsAppOwnedLocal
        return localRuntimeRelevant && (
            pendingThermalNormalModeRecovery?.boundary == .cooldownRecovered
                || thermalSafety.blocksLocalGeneration
                || memoryPressureRouteGate.requiresImmediateLocalShutdown(
                    localRuntimeRelevant: localRuntimeRelevant
                )
        )
    }

    private var currentLocalRuntimeSafetyError: ThermalSafetyError {
        if memoryPressureRouteGate.blocksNewLocalGeneration(
            localRuntimeRelevant: true,
            uptime: ProcessInfo.processInfo.systemUptime
        ) {
            return .memoryPressure
        }
        switch thermalSafety.phase {
        case .eco(reason: .memoryPressure): return .memoryPressure
        case .cooling(trigger: .criticalMemoryPressure, cooldownUntil: _): return .memoryPressure
        case .locked: return .runtimeLocked
        case .ready, .eco, .cooling: return .coolingDown
        }
    }

    var currentLocalRuntimeAdmissionError: any Error {
        if memoryPressureRouteGate.blocksNewLocalGeneration(
            localRuntimeRelevant: true,
            uptime: ProcessInfo.processInfo.systemUptime
        ) {
            return ThermalSafetyError.memoryPressure
        }
        switch thermalSafety.phase {
        case .eco(reason: .memoryPressure):
            return ThermalSafetyError.memoryPressure
        case .cooling(trigger: .criticalMemoryPressure, cooldownUntil: _):
            return ThermalSafetyError.memoryPressure
        case .cooling:
            return ThermalSafetyError.coolingDown
        case .locked:
            return ThermalSafetyError.runtimeLocked
        case .ready, .eco:
            if let pendingThermalNormalModeRecovery {
                return pendingThermalNormalModeRecovery
            }
            return ThermalSafetyError.coolingDown
        }
    }

    @discardableResult
    private func enforceCurrentThermalBlockIfNeeded() -> Bool {
        guard thermalSafetyBlocksSelectedLocalRuntime else { return false }
        let admissionError = currentLocalRuntimeAdmissionError
        _ = protectedInferenceStartWaiter.resume(with: .failure(admissionError))
        switch thermalSafety.phase {
        case .ready, .eco:
            if !presentThermalStatusInsteadOfReadyIfNeeded(),
               currentLocalRuntimeSafetyError == .memoryPressure {
                presentThermalEco(reason: .memoryPressure)
            }
        case .cooling(let trigger, let cooldownUntil):
            beginThermalRuntimeShutdown(trigger: trigger, cooldownUntil: cooldownUntil)
        case .locked(let trigger):
            presentThermalLock(trigger: trigger)
        }
        return true
    }

    private func startThermalSafetyMonitoring() {
        guard thermalSafetyTimer == nil, thermalSafetyObserver == nil else { return }
        _ = applyNormalThermalWorkloadMode(at: .startup) {}
        let now = Date()
        if let persisted = preferences.thermalSafetyCooldown(now: now) {
            thermalSafety.restoreCooling(
                trigger: persisted.trigger,
                cooldownUntil: persisted.until,
                now: now
            )
            thermalCooldownPersistence.markPersisted(
                trigger: persisted.trigger,
                cooldownUntil: persisted.until
            )
            presentThermalCooling(trigger: persisted.trigger, secondsRemaining: Int(ceil(persisted.until.timeIntervalSince(now))))
        }
        thermalSafetyObserver = NotificationCenter.default.addObserver(
            forName: ProcessInfo.thermalStateDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.sampleThermalSafety() }
        }
        memoryPressureObserver.onConditionChange = { [weak self] condition in
            self?.memoryPressureConditionDidChange(condition)
        }
        memoryPressureObserver.start()
        let timer = Timer(timeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.sampleThermalSafety() }
        }
        RunLoop.main.add(timer, forMode: .common)
        thermalSafetyTimer = timer
        sampleThermalSafety()
    }

    private func sampleThermalSafety() {
        guard !thermalSafetySampleInFlight else { return }
        let snapshot = hostPerformanceCollector.capture()
        let relevant = selectedRuntimeIsAppOwnedLocal
        let urgent = snapshot.thermalCondition == .serious || snapshot.thermalCondition == .critical
        if !relevant || urgent || thermalSafety.blocksLocalGeneration || rpcClient.currentAccessMode() == nil {
            processThermalSample(
                condition: snapshot.thermalCondition,
                localRuntimeRelevant: relevant,
                localGenerationActive: false
            )
            return
        }

        thermalSafetySampleInFlight = true
        Task { @MainActor [weak self] in
            guard let self else { return }
            let active: Bool
            do {
                active = try await self.rpcClient.listSessions().items.contains(where: \.running)
            } catch {
                // At an elevated thermal state, inability to prove that DSH is
                // idle is treated conservatively. At nominal temperature an
                // isolated transient RPC failure does not invent activity.
                active = snapshot.thermalCondition == .fair && self.controller.ownsOllama
            }
            self.thermalSafetySampleInFlight = false
            self.processThermalSample(
                condition: snapshot.thermalCondition,
                localRuntimeRelevant: relevant,
                localGenerationActive: active
            )
        }
    }

    private func memoryPressureConditionDidChange(_ condition: HostMemoryPressureCondition) {
        memoryPressureRouteGate.observe(
            condition,
            uptime: ProcessInfo.processInfo.systemUptime
        )
        memoryPressureCondition = condition
        switch condition {
        case .warning, .critical:
            // Warning and critical transitions must close admission without
            // waiting for the next periodic session RPC. Neither path retains
            // prompt or response content.
            let snapshot = hostPerformanceCollector.capture()
            processThermalSample(
                condition: snapshot.thermalCondition,
                localRuntimeRelevant: selectedRuntimeIsAppOwnedLocal,
                localGenerationActive: false
            )
        case .normal:
            // Recovery needs both the normal-memory hysteresis window and the
            // ordinary thermal sample. The existing two-second monitor supplies
            // subsequent deterministic samples until that window is proven.
            sampleThermalSafety()
        }
    }

    private func processThermalSample(
        condition: HostThermalCondition,
        localRuntimeRelevant: Bool,
        localGenerationActive: Bool
    ) {
        if !localRuntimeRelevant, memoryPressureConversationHoldOutstanding {
            // A reviewed provider switch is the explicit escape hatch from
            // local memory pressure. Release only the memory hold; any active
            // provider-mutation hold remains independently reference-counted.
            releaseMemoryPressureAdmissionHold(
                resumeSchedules: !protectedRuntimeConversationHoldOutstanding
            )
        }
        let sample = ThermalSafetySample(
            wallTime: Date(),
            uptime: ProcessInfo.processInfo.systemUptime,
            condition: condition,
            localRuntimeRelevant: localRuntimeRelevant,
            localGenerationActive: localGenerationActive,
            memoryPressure: memoryPressureCondition
        )
        var attemptedNormalModeRecovery = false
        for action in thermalSafety.evaluate(sample) {
            switch action {
            case .ecoStarted(let reason):
                do {
                    try applyThermalWorkloadMode(.eco)
                    if pendingThermalNormalModeRecovery?.boundary != .cooldownRecovered {
                        pendingThermalNormalModeRecovery = nil
                    }
                    if reason == .memoryPressure { beginMemoryPressureAdmissionHold() }
                    presentThermalEco(reason: reason)
                } catch {
                    failSafeAfterThermalPolicyFailure(error)
                }
            case .ecoCleared:
                attemptedNormalModeRecovery = true
                let boundary: ThermalNormalModeRecoveryBoundary =
                    pendingThermalNormalModeRecovery?.boundary == .cooldownRecovered
                        ? .cooldownRecovered
                        : .ecoCleared
                _ = applyNormalThermalWorkloadMode(at: boundary) {
                    completeThermalNormalModeRecovery(at: boundary)
                }
            case .trip(let trigger, let cooldownUntil):
                if trigger == .criticalMemoryPressure { beginMemoryPressureAdmissionHold() }
                preferences.recordThermalSafetyCooldown(trigger: trigger, until: cooldownUntil)
                thermalCooldownPersistence.markPersisted(
                    trigger: trigger,
                    cooldownUntil: cooldownUntil
                )
                beginThermalRuntimeShutdown(trigger: trigger, cooldownUntil: cooldownUntil)
            case .cooling(let trigger, let secondsRemaining):
                if case .cooling(_, let until) = thermalSafety.phase {
                    // Cooling samples arrive every two seconds. Persist only
                    // when a serious/critical sample actually extends the
                    // deadline; otherwise this would create needless disk I/O.
                    if thermalCooldownPersistence.shouldPersist(
                        trigger: trigger,
                        cooldownUntil: until
                    ) {
                        preferences.recordThermalSafetyCooldown(trigger: trigger, until: until)
                    }
                }
                presentThermalCooling(trigger: trigger, secondsRemaining: secondsRemaining)
            case .recovered:
                attemptedNormalModeRecovery = true
                _ = applyNormalThermalWorkloadMode(at: .cooldownRecovered) {
                    completeThermalNormalModeRecovery(at: .cooldownRecovered)
                }
            case .locked(let trigger):
                presentThermalLock(trigger: trigger)
            }
        }
        if !attemptedNormalModeRecovery {
            _ = retryPendingThermalNormalModeRecoveryIfPossible()
        }
        if !thermalSafetyBlocksSelectedLocalRuntime,
           pendingThermalNormalModeRecovery == nil {
            _ = continueDeferredThermalReadyFinalizationIfPossible()
        }
    }

    /// Warning pressure pauses only *new* work: current local turns can finish
    /// under Eco limits. Critical pressure subsequently uses the normal exact
    /// cancellation and process-stop barrier without losing this independent
    /// hold. ConversationService reference-counts overlapping protected holds.
    private func beginMemoryPressureAdmissionHold() {
        guard selectedRuntimeIsAppOwnedLocal,
              !memoryPressureConversationHoldOutstanding else { return }
        memoryPressureConversationHoldOutstanding = true
        conversationService.suspendAdmissionsForQuiescence()
        sessionHistoryLifecycle.suspendAdmissionsForQuiescence()
        scheduleManager.pauseNewAdmissionsSynchronously()
        mainWindow?.surface.suspendTurnAdmissions()
    }

    private func releaseMemoryPressureAdmissionHold(resumeSchedules: Bool) {
        guard memoryPressureConversationHoldOutstanding,
              !thermalSafetyBlocksSelectedLocalRuntime else { return }
        memoryPressureConversationHoldOutstanding = false
        conversationService.resumeAfterQuiescence()
        sessionHistoryLifecycle.resumeAfterQuiescence()
        if resumeSchedules { scheduleManager.resumeAdmissionsAndRunDue() }
        if !protectedRuntimeConversationHoldOutstanding {
            mainWindow?.surface.resumeTurnAdmissionsAfterResourcePressure()
        }
        restoreRuntimeStatusAfterThermalEco()
    }

    private func beginThermalRuntimeShutdown(
        trigger: ThermalSafetyTrigger,
        cooldownUntil: Date
    ) {
        thermalReadyFinalization.clear()
        let runtimeWasActive: Bool
        switch controller.currentState {
        case .checking, .startingOllama, .startingHarness, .ready, .providerRecovery:
            runtimeWasActive = true
        case .stopped, .failed:
            runtimeWasActive = controller.ownsHarness || controller.ownsOllama
        }
        if runtimeWasActive { thermalRuntimeRestartRequested = true }
        else { thermalInitialStartupDeferred = true }

        if !thermalShutdownEstablished {
            thermalShutdownEstablished = true
            if mainWindow != nil {
                closeAllRuntimeAdmissionsSynchronously()
            } else {
                controller.suspendLifecycleStatePublications()
                runtimeReadinessEpoch.rotate()
                scheduleManager.suspendAdmissionsSynchronously()
                if !protectedRuntimeConversationHoldOutstanding {
                    conversationService.suspendAdmissionsForQuiescence()
                    sessionHistoryLifecycle.suspendAdmissionsForQuiescence()
                    protectedRuntimeConversationHoldOutstanding = true
                }
            }
            presentThermalCooling(
                trigger: trigger,
                secondsRemaining: max(0, Int(ceil(cooldownUntil.timeIntervalSinceNow)))
            )
            if thermalActivity == nil {
                let protection = trigger == .criticalMemoryPressure
                    ? "Memory protection"
                    : "Thermal protection"
                thermalActivity = activityStore.begin(
                    .runtime,
                    title: "\(protection) stopped local AI",
                    detail: "\(trigger.displayName) triggered an exact-process shutdown and cooldown. No prompt or response content was retained."
                )
            }
            if !thermalHeadlessMode {
                let recovery = trigger == .criticalMemoryPressure
                    ? "stable normal memory pressure"
                    : "a stable nominal temperature"
                notifications.send(
                    title: "Local AI paused to protect this Mac",
                    body: ThermalSafetyPresentation.restartNotificationBody(
                        trigger: trigger,
                        recoveryCondition: recovery
                    ),
                    identifier: "thermal-safety-trip"
                )
            }
        }
        if trigger == .criticalMemoryPressure {
            // Stop every client-side stream and issue exact-session
            // cancellation immediately. The exact owned-process barrier below
            // remains authoritative even if a severely pressured runtime
            // cannot acknowledge cancellation in time; stopping app-owned
            // Ollama releases the model allocation without waiting on unload.
            conversationService.cancelAll()
        }
        guard !thermalStopInFlight else { return }
        thermalStopInFlight = true
        // Deliberate hardware-safety exception to the normal three-way runtime
        // quiescence barrier: thermal/critical-memory shutdown must release the
        // local model allocation immediately. Admissions are already closed
        // above. Any interrupted native create then follows its exact-ID
        // compensation path; an unverified History compensation records sticky
        // poison, while scheduled cleanup poisons its executor before recovery.
        controller.stopOwnedServicesAndWait { [weak self] result in
            guard let self else { return }
            self.thermalStopInFlight = false
            switch result {
            case .success:
                if self.thermalHeadlessMode {
                    NSApp.terminate(nil)
                    return
                }
                if self.thermalRecoveryPending {
                    self.thermalRecoveryPending = false
                    self.recoverFromThermalCooldown()
                }
            case .failure:
                for action in self.thermalSafety.lock(trigger: trigger) {
                    if case .locked(let lockedTrigger) = action {
                        self.presentThermalLock(trigger: lockedTrigger)
                    }
                }
                if let thermalActivity = self.thermalActivity {
                    self.activityStore.update(
                        thermalActivity,
                        state: .failed,
                        detail: "Thermal protection could not verify exact-process shutdown. The runtime remains locked."
                    )
                    self.thermalActivity = nil
                }
            }
        }
    }

    private func recoverFromThermalCooldown() {
        guard !thermalStopInFlight else {
            thermalRecoveryPending = true
            return
        }
        if thermalHeadlessMode {
            // A scheduled launch that found a persisted cooldown never started
            // the runtime. Keep the lightweight host alive through verified
            // recovery, then resume the same lifecycle exactly once.
            guard thermalInitialStartupDeferred else {
                NSApp.terminate(nil)
                return
            }
            thermalInitialStartupDeferred = false
            thermalShutdownEstablished = false
            if backgroundLifecycleCoordinator?.resumeDeferredRuntimeLaunch() != true {
                backgroundLifecycleCoordinator?.prepareAndLaunch()
            }
            return
        }
        if let thermalActivity {
            activityStore.update(
                thermalActivity,
                state: .completed,
                detail: "Stable normal memory and thermal conditions were verified; the local runtime may restart.",
                progress: 1
            )
            self.thermalActivity = nil
        }
        mainWindow?.surface.clearThermalCooldownPresentation()
        mainWindow?.updateStatus("Local protection cleared · Restarting", color: .systemGreen)
        updateStatusMenuTitle("Local protection cleared · Restarting")
        let deferredStartup = thermalInitialStartupDeferred
        let restartRuntime = thermalRuntimeRestartRequested
        thermalInitialStartupDeferred = false
        thermalRuntimeRestartRequested = false
        thermalShutdownEstablished = false
        if deferredStartup {
            beginProtectedStartup()
        } else if restartRuntime {
            guard ProtectedThermalRecoveryPolicy.recoveryDecision(
                protectedTransitionInFlight: protectedRuntimeMutations.isTransitionInFlight
            ) == .restartRuntime else {
                mainWindow?.surface.suspendTurnAdmissions()
                mainWindow?.updateStatus(
                    "Local protection cleared · Protected change remains blocked",
                    color: .systemOrange
                )
                updateStatusMenuTitle("Protected change · Agent work blocked")
                return
            }
            startDate = Date()
            controller.prepareAndStart()
        } else {
            restoreRuntimeStatusAfterThermalEco()
        }
    }

    private func presentThermalEco(reason: ThermalEcoReason) {
        guard !thermalSafety.blocksLocalGeneration else { return }
        let status: String
        switch reason {
        case .thermalPressure: status = "Eco mode · Managing heat"
        case .memoryPressure: status = "Eco mode · New local work paused"
        case .sustainedLocalGeneration: status = "Eco mode · Sustained local work"
        }
        mainWindow?.updateStatus(status, color: .systemOrange)
        updateStatusMenuTitle(status)
    }

    private func presentThermalCooling(trigger: ThermalSafetyTrigger, secondsRemaining: Int) {
        guard selectedRuntimeIsAppOwnedLocal else { return }
        let status: String
        let estimate: String
        let memoryPressure = trigger == .criticalMemoryPressure
        if secondsRemaining > 0 {
            let minutes = max(1, Int(ceil(Double(secondsRemaining) / 60)))
            status = memoryPressure
                ? "Memory protection · about \(minutes) min"
                : "Cooling · about \(minutes) min"
            estimate = memoryPressure
                ? "About \(minutes) minute\(minutes == 1 ? "" : "s") remain before Fulmar checks for stable normal memory pressure."
                : "About \(minutes) minute\(minutes == 1 ? "" : "s") remain before Fulmar checks for a stable normal temperature."
        } else {
            status = memoryPressure
                ? "Memory protection · Waiting for normal pressure"
                : "Cooling · Waiting for normal temperature"
            estimate = memoryPressure
                ? "The minimum pause has finished. Fulmar is waiting for macOS to report stable normal memory and thermal conditions."
                : "The minimum pause has finished. Fulmar is waiting for macOS to report a stable normal thermal state."
        }
        mainWindow?.updateStatus(status, color: .systemOrange)
        updateStatusMenuTitle(status)
        mainWindow?.surface.showThermalCooldown(
            headline: memoryPressure ? "Local AI paused to free memory" : "Local AI paused safely",
            detail: ThermalSafetyPresentation.cooldownDetail(
                trigger: trigger,
                estimate: estimate
            ),
            openProviders: { [weak self] in self?.showProviderCenter(nil) },
            openPerformance: { [weak self] in self?.showPerformanceCenter(nil) }
        )
    }

    private func presentThermalLock(trigger: ThermalSafetyTrigger) {
        thermalReadyFinalization.clear()
        let status = "Local safety lock · Restart required"
        mainWindow?.surface.suspendTurnAdmissions()
        mainWindow?.surface.showFailure(
            "\(trigger.displayName) triggered local protection, but exact local-runtime shutdown could not be verified. Quit Fulmar, let memory and temperature return to normal, and reopen it before using a local model."
        )
        mainWindow?.updateStatus(status, color: .systemRed)
        updateStatusMenuTitle(status)
    }

    private func presentThermalNormalModeRecoveryFailure(
        _ failure: ThermalNormalModeRecoveryFailure,
        announce: Bool
    ) {
        let status: String
        switch failure.boundary {
        case .startup, .ecoCleared:
            status = "Local AI blocked · Policy repair retrying"
        case .cooldownRecovered:
            status = "Local AI paused · Policy repair retrying"
        }
        mainWindow?.updateStatus(status, color: .systemOrange)
        updateStatusMenuTitle(status)

        if failure.boundary == .cooldownRecovered {
            mainWindow?.surface.showThermalCooldown(
                headline: "Local AI remains paused safely",
                detail: ThermalSafetyPresentation.normalModeRecoveryDetail(
                    reason: failure.reason
                ),
                openProviders: { [weak self] in self?.showProviderCenter(nil) },
                openPerformance: { [weak self] in self?.showPerformanceCenter(nil) }
            )
        }

        let canNotifyUser = mainWindow != nil
            || (thermalHeadlessMode && backgroundLifecycleCoordinator != nil)
        guard announce, canNotifyUser else { return }
        let body = failure.boundary == .cooldownRecovered
            ? ThermalSafetyPresentation.normalModeRecoveryNotification
            : "New local work remains blocked. Fulmar will retry automatically; open Performance Center for details or use Restart Local Services after repairing app-data permissions."
        notifications.send(
            title: "Adaptive performance needs attention",
            body: body,
            identifier: "thermal-normal-policy-recovery"
        )
    }

    @discardableResult
    private func presentThermalStatusInsteadOfReadyIfNeeded() -> Bool {
        guard selectedRuntimeIsAppOwnedLocal else { return false }
        if let failure = pendingThermalNormalModeRecovery {
            presentThermalNormalModeRecoveryFailure(failure, announce: false)
            return true
        }
        if case .eco(let reason) = thermalSafety.phase {
            presentThermalEco(reason: reason)
            return true
        }
        return false
    }

    private func restoreRuntimeStatusAfterThermalEco() {
        guard !thermalSafety.blocksLocalGeneration else { return }
        if selectedRuntimeIsAppOwnedLocal,
           let failure = pendingThermalNormalModeRecovery {
            presentThermalNormalModeRecoveryFailure(failure, announce: false)
            return
        }
        let state = controller.currentState
        let color: NSColor
        switch state {
        case .ready: color = .systemGreen
        case .checking, .startingOllama, .startingHarness, .providerRecovery: color = .systemOrange
        case .failed: color = .systemRed
        case .stopped: color = .secondaryLabelColor
        }
        mainWindow?.updateStatus(state.summary, color: color)
        updateStatusMenuTitle(state.summary)
    }

    private func applyThermalWorkloadMode(_ mode: ThermalWorkloadMode) throws {
        try thermalWorkloadModeWriter.write(
            mode,
            controller.diagnosticsDirectory().standardizedFileURL
        )
    }

    @discardableResult
    func applyNormalThermalWorkloadMode(
        at boundary: ThermalNormalModeRecoveryBoundary,
        onSuccess: () -> Void
    ) -> Result<Void, ThermalNormalModeRecoveryFailure> {
        do {
            try applyThermalWorkloadMode(.normal)
            pendingThermalNormalModeRecovery = nil
            onSuccess()
            return .success(())
        } catch {
            let reason = AuxiliaryDisplayPolicy.singleLine(
                error.localizedDescription,
                maximumCharacters: 600,
                fallback: "The private adaptive-performance policy could not be saved and verified."
            )
            let failure = ThermalNormalModeRecoveryFailure(
                boundary: boundary,
                reason: reason
            )
            let shouldAnnounce = pendingThermalNormalModeRecovery?.boundary != boundary
            pendingThermalNormalModeRecovery = failure
            suspendAdmissionsForPendingThermalNormalModeRecoveryIfNeeded()
            presentThermalNormalModeRecoveryFailure(failure, announce: shouldAnnounce)
            return .failure(failure)
        }
    }

    private func completeThermalNormalModeRecovery(
        at boundary: ThermalNormalModeRecoveryBoundary
    ) {
        if continueDeferredThermalReadyFinalizationIfPossible() { return }
        switch boundary {
        case .startup:
            if thermalInitialStartupDeferred {
                recoverFromThermalCooldown()
            } else {
                restoreRuntimeStatusAfterThermalEco()
                resumeAdmissionsAfterThermalNormalModeRecoveryIfPossible()
            }
        case .ecoCleared:
            if memoryPressureConversationHoldOutstanding {
                let deferredStartup = thermalInitialStartupDeferred
                releaseMemoryPressureAdmissionHold(resumeSchedules: !deferredStartup)
                if deferredStartup { recoverFromThermalCooldown() }
            } else {
                restoreRuntimeStatusAfterThermalEco()
                resumeAdmissionsAfterThermalNormalModeRecoveryIfPossible()
            }
        case .cooldownRecovered:
            preferences.clearThermalSafetyCooldown()
            thermalCooldownPersistence.clear()
            recoverFromThermalCooldown()
        }
    }

    @discardableResult
    private func continueDeferredThermalReadyFinalizationIfPossible() -> Bool {
        guard thermalReadyFinalization.isPending else { return false }
        guard !thermalSafetyBlocksSelectedLocalRuntime else { return true }
        // A protected transition whose waiter just received the exact thermal
        // failure still owns cleanup. It will clear this token when it closes
        // the runtime boundary; recovery must not publish Ready underneath it.
        guard !protectedRuntimeMutations.isTransitionInFlight else { return true }
        let runtimeIsReady: Bool
        if case .ready = controller.currentState { runtimeIsReady = true }
        else { runtimeIsReady = false }
        switch thermalReadyFinalization.recoveryDecision(
            currentGeneration: runtimeGeneration,
            currentEndpoint: controller.endpoint,
            runtimeIsReady: runtimeIsReady
        ) {
        case .none:
            return false
        case .awaitTopology:
            // The generation-bound topology callback will either finish Ready
            // now that the hold is clear or enter the ordinary fail-closed path.
            return true
        case .finalizeVerifiedRuntime:
            finishReadyState()
            return true
        case .restartAfterIdentityChange:
            restartAfterStaleThermalReadyFinalization()
            return true
        }
    }

    private func restartAfterStaleThermalReadyFinalization() {
        closeAllRuntimeAdmissionsSynchronously()
        mainWindow.surface.showLoading(
            "The deferred runtime identity changed. Restarting local services safely…"
        )
        controller.stopOwnedServicesAndWait { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                self.startDate = Date()
                self.startSelectedRuntimeMode()
            case .failure(let error):
                self.mainWindow.surface.showFailure(
                    "The deferred runtime identity changed, and exact shutdown could not be verified. Agent work remains blocked. \(error.localizedDescription)"
                )
                self.mainWindow.updateStatus(
                    "Deferred runtime restart failed closed",
                    color: .systemRed
                )
                self.updateStatusMenuTitle("Deferred runtime restart failed closed")
            }
        }
    }

    private func suspendAdmissionsForPendingThermalNormalModeRecoveryIfNeeded() {
        let lifecycleIsActive = mainWindow != nil || backgroundLifecycleCoordinator != nil
        guard lifecycleIsActive, selectedRuntimeIsAppOwnedLocal else { return }
        scheduleManager.pauseNewAdmissionsSynchronously()
        mainWindow?.surface.suspendTurnAdmissions()
    }

    private func resumeAdmissionsAfterThermalNormalModeRecoveryIfPossible() {
        guard selectedRuntimeIsAppOwnedLocal,
              case .ready = controller.currentState,
              !thermalSafetyBlocksSelectedLocalRuntime,
              !memoryPressureConversationHoldOutstanding,
              !protectedRuntimeConversationHoldOutstanding else { return }
        scheduleManager.resumeAdmissionsAndRunDue()
        mainWindow?.surface.resumeTurnAdmissionsAfterResourcePressure()
    }

    @discardableResult
    private func retryPendingThermalNormalModeRecoveryIfPossible() -> Bool {
        guard let pendingThermalNormalModeRecovery,
              case .ready = thermalSafety.phase else { return false }
        let boundary = pendingThermalNormalModeRecovery.boundary
        let result = applyNormalThermalWorkloadMode(at: boundary) {
            completeThermalNormalModeRecovery(at: boundary)
        }
        if case .success = result { return true }
        return false
    }

    private func failSafeAfterThermalPolicyFailure(_ error: Error) {
        let now = Date()
        let until = now.addingTimeInterval(ThermalSafetyPolicy.production.sustainedLoadCooldownSeconds)
        thermalSafety.restoreCooling(
            trigger: .sustainedLocalGeneration,
            cooldownUntil: until,
            now: now
        )
        preferences.recordThermalSafetyCooldown(trigger: .sustainedLocalGeneration, until: until)
        thermalCooldownPersistence.markPersisted(
            trigger: .sustainedLocalGeneration,
            cooldownUntil: until
        )
        beginThermalRuntimeShutdown(trigger: .sustainedLocalGeneration, cooldownUntil: until)
        if let thermalActivity {
            activityStore.update(
                thermalActivity,
                state: .running,
                detail: "Fulmar could not verify the Eco workload policy, so it stopped the local runtime and entered the bounded safety cooldown. \(error.localizedDescription)"
            )
        }
    }

    private func observeApplicationChanges() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  app.bundleIdentifier != Bundle.main.bundleIdentifier else { return }
            MainActor.assumeIsolated {
                self?.lastExternalApplication = app
            }
        }
    }

    private func installGlobalHotKey() {
        switch GlobalHotKey.register(
            keyCode: UInt32(kVK_Space),
            modifiers: UInt32(optionKey),
            action: { [weak self] in self?.toggleCompanion() }
        ) {
        case .success(let registration):
            hotKey = registration
            hotKeyAvailability = .available
        case .failure(let failure):
            hotKey = nil
            hotKeyAvailability = .unavailable(failure)
        }
    }

    private func handle(_ state: HarnessController.State) {
        if thermalSafetyRequiresSelectedLocalShutdown {
            switch state {
            case .checking, .startingOllama, .startingHarness, .ready:
                _ = enforceCurrentThermalBlockIfNeeded()
                return
            case .providerRecovery, .stopped, .failed:
                break
            }
        }
        if let issue = controller.ollamaPrerequisiteRecoveryIssue,
           providerRecoveryContext == nil {
            // The controller creates this issue only at the exact Ollama
            // prerequisite boundary. It is therefore safe to authorize the
            // no-egress provider repair UI, while all Harness/app integrity
            // failures continue to the ordinary terminal error state.
            providerRecoveryContext = .ollamaPrerequisite(issue)
        }
        let color: NSColor
        switch state {
        case .checking, .startingOllama, .startingHarness: color = .systemOrange
        case .ready: color = .systemGreen
        case .providerRecovery: color = .systemOrange
        case .stopped: color = .secondaryLabelColor
        case .failed: color = .systemRed
        }
        let replacedReadyStatus: Bool
        if case .ready = state {
            replacedReadyStatus = presentThermalStatusInsteadOfReadyIfNeeded()
        } else {
            replacedReadyStatus = false
        }
        if !replacedReadyStatus {
            mainWindow.updateStatus(state.summary, color: color)
            updateStatusMenuTitle(state.summary)
        }

        switch state {
        case .checking:
            showLoading("Checking your local workspace…")
        case .startingOllama:
            showLoading("Starting Ollama…")
        case .startingHarness:
            thermalReadyFinalization.clear()
            scheduleManager.stop()
            showLoading(providerRecoveryContext == nil
                ? "Starting DeepSeek Harness…"
                : "Starting the locked provider-repair controls…")
            if runtimeActivity == nil {
                runtimeActivity = activityStore.begin(.runtime, title: "Start private Harness", detail: "Applying authentication, Strict Local policy and plugin trust checks.")
            }
            readinessAttempts = 0
            let generation = runtimeReadinessEpoch.rotate()
            pollUntilReady(generation: generation)
        case .ready:
            guard ProtectedThermalRecoveryPolicy.mayPublishReady(
                protectedTransitionInFlight: protectedRuntimeMutations.isTransitionInFlight,
                protectedInferenceStartIsWaiting: protectedInferenceStartWaiter.isWaiting
            ) else {
                // A runtime that becomes Ready without the protected
                // coordinator's inference waiter cannot take ownership from a
                // still-live mutation permit (notably after an emergency
                // thermal stop). Keep every admission closed and remove that
                // unexpected exact child; the permit owner can explicitly
                // finish or repair the transition afterward.
                closeAllRuntimeAdmissionsSynchronously()
                mainWindow.surface.showFailure(
                    "A protected change still owns the runtime boundary. The unexpected runtime was stopped and agent work remains blocked."
                )
                controller.stopOwnedServicesAndWait { [weak self] result in
                    guard let self, case .failure = result else { return }
                    self.mainWindow.surface.showFailure(
                        "A protected change still owns the runtime boundary, and exact shutdown could not be verified. Agent work remains blocked."
                    )
                }
                return
            }
            configureSkillsWindowIfPrepared()
            let generation = runtimeGeneration
            if thermalSafetyBlocksSelectedLocalRuntime,
               let endpoint = controller.endpoint {
                thermalReadyFinalization.deferAwaitingTopology(
                    generation: generation,
                    endpoint: endpoint
                )
            }
            showLoading("Verifying the live provider and endpoint boundary…")
            verifyLiveProviderTopology(generation: generation) { [weak self] result in
                guard let self else { return }
                self.runtimeReadinessEpoch.performIfCurrent(generation) {
                    switch result {
                    case .success:
                        self.finishReadyState()
                    case .failure(let error):
                        self.failClosedAfterTopologyValidation(error)
                    }
                }
            }
        case .providerRecovery:
            thermalReadyFinalization.clear()
            configureSkillsWindowIfPrepared()
            runtimeReadinessEpoch.rotate()
            scheduleManager.stop()
            conversationService.cancelAll()
            sessionOpenGeneration = UUID()
            if protectedControlPlaneStartWaiter.resume(with: .success(())) {
                return
            } else if protectedInferenceStartWaiter.resume(with: .failure(
                ProtectedRuntimeMutationCoordinatorError.transitionFailed(.providerRecoveryPending)
            )) {
                return
            } else if protectedRuntimeMutations.isTransitionInFlight {
                // A timed-out/failed protected start still owns exact cleanup.
                return
            } else {
                presentProviderRecovery()
                refreshProviderCatalog()
            }
        case .stopped:
            thermalReadyFinalization.clear()
            runtimeReadinessEpoch.rotate()
            scheduleManager.stop()
            showLoading("Local services are stopped.")
        case .failed(let message):
            thermalReadyFinalization.clear()
            runtimeReadinessEpoch.rotate()
            scheduleManager.stop()
            let safeMessage = AuxiliaryDisplayPolicy.singleLine(
                message,
                maximumCharacters: 800,
                fallback: "The private runtime failed safely. Open Diagnostics for private, redacted details."
            )
            let transitionError = ProtectedRuntimeMutationCoordinatorError.transitionFailed(.runtimeFailed)
            _ = protectedControlPlaneStartWaiter.resume(with: .failure(transitionError))
            _ = protectedInferenceStartWaiter.resume(with: .failure(transitionError))
            mainWindow.surface.showFailure(safeMessage)
            if let runtimeActivity {
                activityStore.update(runtimeActivity, state: .failed, detail: safeMessage)
                self.runtimeActivity = nil
            }
            notifications.send(title: "\(ProductBrand.displayName) needs attention", body: safeMessage, identifier: "service-failed")
        }
    }

    private func showLoading(_ message: String) {
        mainWindow.surface.showLoading(message)
    }

    private func presentHarnessHomeRecovery(
        _ pending: HarnessHomeRecoveryPendingState
    ) {
        guard controller.pendingHarnessHomeRecoveryState == pending,
              startupRuntimeContinuationPermitted,
              let token = harnessHomeRecoveryPresentation.begin() else { return }
        harnessHomeRecoveryCompletion.reset()
        closeAllRuntimeAdmissionsSynchronously()
        let statusMessage: String
        let activityDetail: String
        switch pending {
        case .initial:
            statusMessage = "Historical provider state needs review. Agent work remains stopped and no child data has been inspected or changed."
            activityDetail = "Waiting for an explicit settings-only, start-clean, or Keep Stopped decision. No provider-history child or credential was accessed during detection."
        case .interrupted:
            statusMessage = "An interrupted Harness-home recovery needs foreground review. Agent work remains stopped."
            activityDetail = "Waiting for explicit authorization of the existing recovery key before resuming the exact journal. No credential was accessed during detection."
        case .published:
            statusMessage = "Harness-home recovery completed and its exact preserved copy needs acknowledgement before restart."
            activityDetail = "Waiting for foreground review of the exact preserved-copy receipt before clearing the authenticated completion marker."
        case .blocked:
            statusMessage = "Harness-home recovery could not be verified automatically. Agent work remains stopped for manual inspection."
            activityDetail = "Waiting for manual inspection of the private recovery folder. No background credential access or recovery mutation was admitted."
        }
        mainWindow.surface.showFailure(statusMessage)
        if let runtimeActivity {
            activityStore.update(
                runtimeActivity,
                state: .waiting,
                detail: activityDetail
            )
        }
        let recoveryFolder = pending.recoveryFolder
        switch pending {
        case .initial(let request):
            let choice = harnessHomeRecoveryInteractions.chooseInitial(request.root, recoveryFolder)
            guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
            switch choice {
            case .preserveSettingsAndRepair:
                guard harnessHomeRecoveryPresentation.bindInitialChoice(
                    .settingsOnly,
                    to: token
                ) else { return }
                attemptHarnessHomeRecovery(
                    pending,
                    choice: .settingsOnly,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            case .preserveAndStartClean:
                guard harnessHomeRecoveryPresentation.bindInitialChoice(
                    .startClean,
                    to: token
                ) else { return }
                attemptHarnessHomeRecovery(
                    pending,
                    choice: .startClean,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            case .keepStopped:
                keepHarnessHomeRecoveryStopped(pending, token: token)
            }
        case .interrupted:
            let choice = harnessHomeRecoveryInteractions.chooseInterrupted(recoveryFolder)
            guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
            switch choice {
            case .authorizeAndRetry:
                authorizePendingHarnessHomeRecovery(
                    pending,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            case .openRecoveryFolder:
                revealRecoveryFolderOrExistingHome(
                    recoveryFolder: recoveryFolder,
                    existingHome: pending.root
                )
                keepHarnessHomeRecoveryStopped(pending, token: token)
            case .keepStopped:
                keepHarnessHomeRecoveryStopped(pending, token: token)
            }
        case .published(let receipt):
            presentPublishedHarnessHomeRecovery(
                receipt,
                pending: pending,
                recoveryFolder: recoveryFolder,
                token: token
            )
        case .blocked(_, let message):
            presentHarnessHomeRecoveryFailureMessage(
                message,
                pending: pending,
                recoveryFolder: recoveryFolder,
                token: token
            )
        }
    }

    private func harnessHomeRecoveryPresentationAdmits(
        _ token: HarnessHomeRecoveryPresentationGate.Token,
        pending: HarnessHomeRecoveryPendingState? = nil
    ) -> Bool {
        guard startupRuntimeContinuationPermitted,
              harnessHomeRecoveryPresentation.admits(token) else { return false }
        if let pending {
            return controller.pendingHarnessHomeRecoveryState == pending
        }
        return true
    }

    private func attemptHarnessHomeRecovery(
        _ pending: HarnessHomeRecoveryPendingState,
        choice: ProviderHistoryRecoveryChoice,
        recoveryFolder: URL,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
        switch pending {
        case .initial:
            showLoading("Preserving historical provider state and verifying a privacy-epoch-current home…")
        case .interrupted:
            showLoading("Authenticating and resuming the exact Harness-home recovery journal…")
        case .published, .blocked:
            presentHarnessHomeRecoveryFailureMessage(
                HarnessHomeError.receiptlessRecoveryStateChanged.localizedDescription,
                pending: pending,
                recoveryFolder: recoveryFolder,
                token: token
            )
            return
        }
        let interruptedIntent: HarnessHomeInterruptedRecoveryIntent?
        switch pending {
        case .initial:
            interruptedIntent = nil
        case .interrupted:
            guard let bound = harnessHomeRecoveryPresentation.interruptedIntent(for: token),
                  bound.choice == choice else {
                presentHarnessHomeRecoveryFailure(
                    HarnessHomeError.receiptlessRecoveryStateChanged,
                    pending: pending,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
                return
            }
            interruptedIntent = bound
        case .published, .blocked:
            return
        }
        controller.preserveAndRepairPendingHarnessHome(
            choice: choice,
            interruptedIntent: interruptedIntent
        ) { [weak self] result in
            guard let self,
                  self.harnessHomeRecoveryPresentationAdmits(token) else { return }
            switch result {
            case .success(let receipt):
                let published = HarnessHomeRecoveryPendingState.published(receipt)
                guard self.controller.pendingHarnessHomeRecoveryState == published else {
                    self.presentHarnessHomeRecoveryFailureMessage(
                        HarnessHomeError.receiptlessRecoveryStateChanged.localizedDescription,
                        pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                        recoveryFolder: recoveryFolder,
                        token: token
                    )
                    return
                }
                self.presentPublishedHarnessHomeRecovery(
                    receipt,
                    pending: published,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            case .failure(let error as HarnessHomeError):
                switch error {
                case .receiptlessRecoveryInterrupted:
                    guard let updated = self.controller.pendingHarnessHomeRecoveryState,
                          case .interrupted = updated else {
                        self.presentHarnessHomeRecoveryFailure(
                            HarnessHomeError.receiptlessRecoveryStateChanged,
                            pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                            recoveryFolder: recoveryFolder,
                            token: token
                        )
                        return
                    }
                    self.presentHarnessHomeRecoveryAuthorization(
                        updated,
                        recoveryFolder: updated.recoveryFolder,
                        token: token
                    )
                case .receiptlessRecoveryAuthenticationRequired:
                    self.presentHarnessHomeRecoveryAuthorization(
                        pending,
                        recoveryFolder: recoveryFolder,
                        token: token
                    )
                default:
                    self.presentHarnessHomeRecoveryFailure(
                        error,
                        pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                        recoveryFolder: recoveryFolder,
                        token: token
                    )
                }
            case .failure(let error):
                self.presentHarnessHomeRecoveryFailure(
                    error,
                    pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            }
        }
    }

    private func presentHarnessHomeRecoveryAuthorization(
        _ pending: HarnessHomeRecoveryPendingState,
        recoveryFolder: URL,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
        let choice = harnessHomeRecoveryInteractions.chooseAuthorization(recoveryFolder)
        guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
        switch choice {
        case .authorizeAndRetry:
            authorizePendingHarnessHomeRecovery(
                pending,
                recoveryFolder: recoveryFolder,
                token: token
            )
        case .openRecoveryFolder:
            revealRecoveryFolderOrExistingHome(
                recoveryFolder: recoveryFolder,
                existingHome: pending.root
            )
            keepHarnessHomeRecoveryStopped(pending, token: token)
        case .keepStopped:
            keepHarnessHomeRecoveryStopped(pending, token: token)
        }
    }

    private func authorizePendingHarnessHomeRecovery(
        _ pending: HarnessHomeRecoveryPendingState,
        recoveryFolder: URL,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
        showLoading("Waiting for macOS to authorize the existing recovery key…")
        controller.authorizePendingHarnessHomeRecoveryKey { [weak self] result in
            guard let self,
                  self.harnessHomeRecoveryPresentationAdmits(token) else { return }
            switch result {
            case .success(let authenticatedIntent):
                guard self.controller.pendingHarnessHomeRecoveryState == pending else {
                    self.presentHarnessHomeRecoveryFailureMessage(
                        HarnessHomeError.receiptlessRecoveryStateChanged.localizedDescription,
                        pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                        recoveryFolder: recoveryFolder,
                        token: token
                    )
                    return
                }
                let retryChoice: ProviderHistoryRecoveryChoice
                switch pending {
                case .initial:
                    guard let bound = self.harnessHomeRecoveryPresentation.initialChoice(
                        for: token
                    ) else {
                        self.presentHarnessHomeRecoveryFailure(
                            HarnessHomeError.receiptlessRecoveryStateChanged,
                            pending: pending,
                            recoveryFolder: recoveryFolder,
                            token: token
                        )
                        return
                    }
                    retryChoice = bound
                case .interrupted:
                    guard let authenticatedIntent,
                          self.harnessHomeRecoveryPresentation.bindInterruptedIntent(
                              authenticatedIntent,
                              to: token
                          ) else {
                        self.presentHarnessHomeRecoveryFailure(
                            HarnessHomeError.receiptlessRecoveryStateChanged,
                            pending: pending,
                            recoveryFolder: recoveryFolder,
                            token: token
                        )
                        return
                    }
                    retryChoice = authenticatedIntent.choice
                case .published, .blocked:
                    self.presentHarnessHomeRecoveryFailure(
                        HarnessHomeError.receiptlessRecoveryStateChanged,
                        pending: pending,
                        recoveryFolder: recoveryFolder,
                        token: token
                    )
                    return
                }
                self.attemptHarnessHomeRecovery(
                    pending,
                    choice: retryChoice,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            case .failure(let error):
                self.presentHarnessHomeRecoveryFailure(
                    error,
                    pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            }
        }
    }

    private func presentPublishedHarnessHomeRecovery(
        _ receipt: HarnessHomeReceiptlessRecoveryReceipt,
        pending: HarnessHomeRecoveryPendingState,
        recoveryFolder: URL,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        guard case .published(let expectedReceipt) = pending,
              expectedReceipt == receipt,
              harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
        let openPreservedCopy = harnessHomeRecoveryInteractions.showSuccess(receipt)
        // `runModal` spins a nested event loop. Quit may have irreversibly
        // invalidated this token while the receipt was visible; in that case the
        // authenticated published marker remains durable for the next launch.
        guard harnessHomeRecoveryPresentationAdmits(token, pending: pending) else { return }
        showLoading("Acknowledging the verified preserved-copy receipt…")
        controller.acknowledgePendingHarnessHomeRecovery { [weak self] result in
            guard let self,
                  self.harnessHomeRecoveryPresentationAdmits(token) else { return }
            switch result {
            case .success:
                self.harnessHomeRecoveryCompletion.finish(
                    receipt: receipt,
                    openPreservedCopy: openPreservedCopy,
                    reveal: self.harnessHomeRecoveryInteractions.reveal,
                    restart: { [weak self] in
                        guard let self,
                              self.harnessHomeRecoveryPresentation.finish(token),
                              self.startupRuntimeContinuationPermitted else { return }
                        self.showLoading("Verifying repaired private state before startup…")
                        self.beginProviderHistoryStartupGate(background: false) { [weak self] admitted in
                            guard let self, admitted else { return }
                            self.runStartupPrivacyMaintenance { [weak self] in
                                self?.startPeriodicPrivacyMaintenance()
                                self?.beginProtectedStartup()
                            }
                        }
                    }
                )
            case .failure(let error):
                self.presentHarnessHomeRecoveryFailure(
                    error,
                    pending: self.controller.pendingHarnessHomeRecoveryState ?? pending,
                    recoveryFolder: recoveryFolder,
                    token: token
                )
            }
        }
    }

    private func presentHarnessHomeRecoveryFailure(
        _ error: Error,
        pending: HarnessHomeRecoveryPendingState,
        recoveryFolder: URL,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        let message = AuxiliaryDisplayPolicy.singleLine(
            error.localizedDescription,
            maximumCharacters: 800,
            fallback: "The authenticated recovery could not be verified."
        )
        presentHarnessHomeRecoveryFailureMessage(
            message,
            pending: pending,
            recoveryFolder: recoveryFolder,
            token: token
        )
    }

    private func presentHarnessHomeRecoveryFailureMessage(
        _ message: String,
        pending: HarnessHomeRecoveryPendingState,
        recoveryFolder: URL,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        guard harnessHomeRecoveryPresentationAdmits(token) else { return }
        let safeMessage = AuxiliaryDisplayPolicy.singleLine(
            message,
            maximumCharacters: 800,
            fallback: "The authenticated recovery could not be verified."
        )
        let shouldReveal = harnessHomeRecoveryInteractions.showFailure(safeMessage, recoveryFolder)
        guard harnessHomeRecoveryPresentationAdmits(token) else { return }
        if shouldReveal {
            revealRecoveryFolderOrExistingHome(
                recoveryFolder: recoveryFolder,
                existingHome: pending.root
            )
        }
        keepHarnessHomeRecoveryStopped(pending, token: token)
    }

    private func revealRecoveryFolderOrExistingHome(recoveryFolder: URL, existingHome: URL) {
        let target = FileManager.default.fileExists(atPath: recoveryFolder.path)
            ? recoveryFolder
            : existingHome
        harnessHomeRecoveryInteractions.reveal(target)
    }

    private func keepHarnessHomeRecoveryStopped(
        _ pending: HarnessHomeRecoveryPendingState,
        token: HarnessHomeRecoveryPresentationGate.Token
    ) {
        guard harnessHomeRecoveryPresentation.finish(token) else { return }
        closeAllRuntimeAdmissionsSynchronously()
        let message: String
        let detail: String
        switch pending {
        case .initial:
            message = "Harness remains stopped. The older home is untouched. Choose Restart Local Services when you are ready to review recovery again."
            detail = "Older Harness-home recovery was left stopped by request; existing data was not changed."
        case .interrupted:
            message = "Harness remains stopped. The interrupted transaction and every preserved recovery item remain in place for an explicit foreground retry."
            detail = "Interrupted Harness-home recovery was left stopped by request; no new recovery work was admitted."
        case .published:
            message = "Harness remains stopped. The exact preserved-copy receipt is still durably pending acknowledgement and will be shown again on retry."
            detail = "Published Harness-home recovery remains pending explicit receipt acknowledgement."
        case .blocked:
            message = "Harness remains stopped. The private recovery folder was retained for manual inspection."
            detail = "Harness-home recovery remained blocked and no automatic retry was admitted."
        }
        mainWindow.surface.showFailure(message)
        mainWindow.updateStatus("Harness recovery paused · Runtime stopped", color: .systemOrange)
        if let runtimeActivity {
            activityStore.update(
                runtimeActivity,
                state: .cancelled,
                detail: detail
            )
            self.runtimeActivity = nil
        }
    }

    private func beginProtectedStartup() {
        guard startupRuntimeContinuationPermitted else { return }
        let inspection = nativeProviderStateRecovery.inspect()
        if inspection.requiresRecovery {
            providerRecoveryContext = .nativeState(inspection)
        }
        guard ThermalRuntimeAdmissionPolicy.permitsRuntimeStart(
            selectedLocalRuntimeBlocked: thermalSafetyBlocksSelectedLocalRuntime,
            providerControlPlaneOnly: providerRecoveryContext != nil
        ) else {
            _ = enforceCurrentThermalBlockIfNeeded()
            thermalInitialStartupDeferred = true
            return
        }
        switch credentialMigration.startupRequirement {
        case .none:
            prepareRuntimeWithSafetyBackup()
        case .plaintextNeedsConsent:
            offerCredentialMigration(continueAfter: true)
        case .zeroTombstoneNeedsAutomaticVerification:
            // A zero-byte file is only a candidate tombstone. It is never an
            // opt-out prompt and never reaches backup/runtime until the signed
            // helper revalidates its receipt and every Keychain digest.
            migrateCredentialsThroughProtectedStop(
                continueAfter: true,
                automaticVerification: true
            )
        }
    }

    private func offerCredentialMigration(continueAfter: Bool) {
        switch credentialMigration.startupRequirement {
        case .none:
            if continueAfter { prepareRuntimeWithSafetyBackup() }
            else { showAlert(title: "Secrets are already protected", message: "No plaintext Harness credential file was found. New secrets are stored in your macOS Keychain.") }
            return
        case .zeroTombstoneNeedsAutomaticVerification:
            migrateCredentialsThroughProtectedStop(
                continueAfter: continueAfter,
                automaticVerification: true
            )
            return
        case .plaintextNeedsConsent:
            break
        }
        let alert = NSAlert()
        alert.messageText = "Move Harness secrets to macOS Keychain?"
        alert.informativeText = "Values are transferred directly to Keychain and verified without being shown or logged. Only after verification succeeds is the plaintext credential file removed."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Move and Verify")
        alert.addButton(withTitle: continueAfter ? "Not Now" : "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { if continueAfter { prepareRuntimeWithSafetyBackup() }; return }
        migrateCredentialsThroughProtectedStop(
            continueAfter: continueAfter,
            automaticVerification: false
        )
    }

    @MainActor
    private func migrateCredentialsThroughProtectedStop(
        continueAfter: Bool,
        automaticVerification: Bool
    ) {
        let lifecyclePermit: StartupCredentialMigrationLifecycleGate.Permit
        do {
            lifecyclePermit = try startupCredentialMigrationLifecycle.beginMigration()
        } catch StartupCredentialMigrationLifecycleGate.AdmissionError.busy {
            showAlert(
                title: "Credential protection is already running",
                message: "Wait for the current Keychain migration to finish before trying again. A second helper was not started."
            )
            return
        } catch {
            // Termination admission is irreversible. A prompt or menu action
            // queued before Quit must not dispatch the migration helper or a
            // later startup continuation after the latch closes.
            return
        }

        showLoading(
            automaticVerification
                ? "Verifying the completed Keychain migration…"
                : continueAfter
                ? "Moving existing secrets to macOS Keychain…"
                : "Stopping the exact runtime before moving secrets to Keychain…"
        )
        let activity = activityStore.begin(
            .plugin,
            title: "Protect Harness credentials",
            detail: automaticVerification
                ? "Authenticating the tombstone receipt and every Keychain record."
                : continueAfter
                ? "Migrating secrets to this Mac’s Keychain."
                : "Stopping agent work before migrating secrets."
        )
        Task { @MainActor [weak self] in
            guard let self else { return }
            let result: Result<CredentialMigrationResult, Error>
            if continueAfter {
                // No runtime has started yet. The dedicated first-start gate
                // owns Quit admission while the cross-process manager lease
                // owns the exact plaintext source/helper transaction. Using
                // ProtectedRuntimeMutationCoordinator here would restart
                // inference before the mandatory safety-backup flow.
                do {
                    let moved = try await StartupCredentialMigrationCoordinator
                        .migrateAfterVerifiedLeaseSettlement {
                            try await withCheckedThrowingContinuation { continuation in
                                self.credentialMigration.migrate {
                                    continuation.resume(with: $0)
                                }
                            }
                        }
                    result = .success(moved)
                } catch {
                    result = .failure(error)
                }
            } else {
                do {
                    let moved = try await self.protectedRuntimeMutations.perform(
                        kind: .credentialMigration,
                        requirement: .stoppedRuntime
                    ) { permit in
                        try permit.validate()
                        return try await withCheckedThrowingContinuation { continuation in
                            self.credentialMigration.migrate { continuation.resume(with: $0) }
                        }
                    }
                    result = .success(moved)
                } catch {
                    result = .failure(error)
                }
            }

            var migrationVerified = false
            switch result {
            case .success(let moved):
                migrationVerified = true
                let detail = if moved.references == 0 && moved.records == 0 {
                    "No remaining plaintext credential records required migration."
                } else {
                    "Moved \(moved.references) references and \(moved.records) authorization records."
                }
                self.activityStore.update(activity, state: .completed, detail: detail, progress: 1)
                if moved.references > 0 || moved.records > 0 {
                    self.privacyLedger.record(.credentialsMigrated, summary: "Harness credentials moved to macOS Keychain", localOnly: true)
                }
                // A durable zero-byte tombstone is verified on every startup.
                // That routine integrity check must remain silent when it
                // succeeds; otherwise every ordinary launch presents a modal
                // migration dialog even though no user action is needed.
                if !automaticVerification {
                    self.showAlert(
                        title: "Secrets are protected",
                        message: moved.references == 0 && moved.records == 0
                            ? "No plaintext credential file remains. New secrets are stored in your macOS Keychain."
                            : "The Keychain copy was verified and the old plaintext credential file was removed."
                    )
                }
            case .failure(let error):
                self.activityStore.update(activity, state: .failed, detail: error.localizedDescription)
                let committed = if case .mutationCommittedButRecoveryFailed = error as? ProtectedRuntimeMutationCoordinatorError { true } else { false }
                self.mainWindow.surface.showFailure(
                    "Credential recovery is required. Agent work and all model providers remain stopped until the signed migration receipt and Keychain records verify. \(error.localizedDescription)"
                )
                self.mainWindow.updateStatus("Credential recovery required · Runtime stopped", color: .systemRed)
                self.showAlert(
                    title: committed
                        ? "Secrets moved; runtime blocked"
                        : automaticVerification
                            ? "Credential verification did not complete"
                            : "Credential migration did not complete",
                    message: error.localizedDescription
                )
            }

            self.startupCredentialMigrationLifecycle.finish(
                lifecyclePermit,
                continueAfter: continueAfter && migrationVerified
            ) {
                self.prepareRuntimeWithSafetyBackup()
            }
        }
    }

    private func prepareRuntimeWithSafetyBackup() {
        guard startupRuntimeContinuationPermitted else { return }
        guard let version = controller.runtimeInfo()?.dshVersion else {
            continueStartupRuntimeAfterSafetyPreparation()
            return
        }
        showLoading("Creating a recoverable pre-upgrade snapshot…")
        let activity = activityStore.begin(.backup, title: "Prepare Harness \(version)", detail: "Protecting local state before runtime migration.")
        let migrationCoordinator = self.migrationCoordinator
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = Result { try migrationCoordinator.prepare(targetVersion: version) }
            DispatchQueue.main.async {
                guard self.startupRuntimeContinuationPermitted else {
                    self.activityStore.update(
                        activity,
                        state: .cancelled,
                        detail: "Startup ended before runtime preparation completed."
                    )
                    return
                }
                switch result {
                case .success(.current):
                    self.activityStore.update(activity, state: .completed, detail: "Runtime state is current.", progress: 1)
                    self.continueStartupRuntimeAfterSafetyPreparation()
                case .success(.backupCreated):
                    self.activityStore.update(activity, state: .completed, detail: "Safety snapshot created; secrets were excluded.", progress: 1)
                    self.privacyLedger.record(.backupCreated, summary: "Pre-upgrade Harness snapshot created", localOnly: true)
                    self.continueStartupRuntimeAfterSafetyPreparation()
                case .success(.recoveryNeeded(let backup)):
                    self.activityStore.update(activity, state: .waiting, detail: "Waiting for upgrade recovery choice.")
                    self.presentUpgradeRecovery(version: version, backup: backup, activity: activity)
                case .failure(let error):
                    self.activityStore.update(activity, state: .failed, detail: error.localizedDescription)
                    self.mainWindow.surface.showFailure("A safety snapshot could not be created. Harness was not started, so your state was not migrated.")
                    if case .authenticationAuthorizationRequired = error as? BackupError {
                        let alert = NSAlert()
                        alert.messageText = "Backup-key authorization is required"
                        alert.informativeText = "Harness remains stopped. Fulmar did not replace or delete the existing Keychain item. Open Backups & Restore to deliberately authorize that exact key and verify it against your authenticated backups."
                        alert.alertStyle = .warning
                        alert.addButton(withTitle: "Open Backups & Restore")
                        alert.addButton(withTitle: "Keep Runtime Stopped")
                        if alert.runModal() == .alertFirstButtonReturn {
                            self.showBackups(nil)
                        }
                    } else {
                        self.showAlert(title: "Upgrade paused safely", message: error.localizedDescription)
                    }
                }
            }
        }
    }

    private func presentUpgradeRecovery(version: String, backup: StateBackup, activity: UUID) {
        let alert = NSAlert()
        alert.messageText = "The previous Harness upgrade did not finish"
        alert.informativeText = "You can restore the automatic safety snapshot before retrying, or retry with the current state. No service will start until you choose."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Restore Snapshot and Retry")
        alert.addButton(withTitle: "Retry Current State")
        alert.addButton(withTitle: "Keep Stopped")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            let backupManager = self.backupManager
            let migrationCoordinator = self.migrationCoordinator
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                let result = Result {
                    try backupManager.restore(backup)
                    try migrationCoordinator.retryPending(targetVersion: version)
                }
                DispatchQueue.main.async {
                    guard self.startupRuntimeContinuationPermitted else {
                        self.activityStore.update(
                            activity,
                            state: .cancelled,
                            detail: "Startup ended before snapshot recovery completed."
                        )
                        return
                    }
                    switch result {
                    case .success:
                        self.privacyLedger.record(.backupRestored, summary: "Pre-upgrade Harness snapshot restored", localOnly: true)
                        self.activityStore.update(activity, state: .completed, detail: "Snapshot restored; retrying the runtime.", progress: 1)
                        self.continueStartupRuntimeAfterSafetyPreparation()
                    case .failure(let error):
                        self.activityStore.update(activity, state: .failed, detail: error.localizedDescription)
                        self.showAlert(title: "Snapshot could not be restored", message: error.localizedDescription)
                    }
                }
            }
        case .alertSecondButtonReturn:
            do { try migrationCoordinator.retryPending(targetVersion: version); activityStore.update(activity, state: .completed, detail: "Retrying with current state.", progress: 1); continueStartupRuntimeAfterSafetyPreparation() }
            catch { activityStore.update(activity, state: .failed, detail: error.localizedDescription); showAlert(title: "Retry could not be prepared", message: error.localizedDescription) }
        default:
            activityStore.update(activity, state: .cancelled, detail: "Runtime kept stopped by request.")
            mainWindow.surface.showFailure("Harness is stopped. Open Diagnostics and restart when you are ready.")
        }
    }

    private var startupRuntimeContinuationPermitted: Bool {
        startupCredentialMigrationLifecycle.permitsRuntimeContinuation
            && !terminationDeferred
            && !terminationPrepared
    }

    /// Every asynchronous first-start backup/recovery callback funnels through
    /// this terminal-latch check. It is deliberately separate from ordinary
    /// manual restarts, which already require a fresh protected-runtime permit.
    private func continueStartupRuntimeAfterSafetyPreparation() {
        guard startupRuntimeContinuationPermitted else { return }
        startSelectedRuntimeMode()
    }

    private func startSelectedRuntimeMode() {
        guard startupRuntimeContinuationPermitted else { return }
        let providerControlPlaneOnly = providerRecoveryContext != nil
        guard ThermalRuntimeAdmissionPolicy.permitsRuntimeStart(
            selectedLocalRuntimeBlocked: thermalSafetyBlocksSelectedLocalRuntime,
            providerControlPlaneOnly: providerControlPlaneOnly
        ) else {
            _ = enforceCurrentThermalBlockIfNeeded()
            thermalInitialStartupDeferred = true
            return
        }
        if providerControlPlaneOnly {
            controller.prepareProviderRecovery()
        } else {
            controller.prepareAndStart()
        }
    }

    private func pollUntilReady(generation: UUID) {
        guard generation == runtimeGeneration else { return }
        readinessAttempts += 1
        controller.probeHarness { [weak self] ready in
            guard let self, generation == self.runtimeGeneration else { return }
            if ready {
                do {
                    // Authenticated DSH identity is the migration boundary.
                    // Missing provider/model configuration may still open the
                    // isolated repair UI without becoming a fake failed
                    // upgrade on the next launch.
                    if let version = self.controller.runtimeInfo()?.dshVersion {
                        try self.migrationCoordinator.markReady(version: version)
                    }
                    self.controller.reportReady()
                } catch {
                    self.controller.failRuntimeStartAfterCleaningOwnedServices(error)
                }
            }
            else if self.readinessAttempts < 100 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                    self.pollUntilReady(generation: generation)
                }
            } else {
                self.controller.failRuntimeStartAfterCleaningOwnedServices(
                    RuntimeTopologyValidationError.readinessTimedOut
                )
            }
        }
    }

    private func verifyLiveProviderTopology(
        generation: UUID,
        completion: @escaping (Result<HarnessModelCatalogSnapshot, Error>) -> Void
    ) {
        Task { [weak self] in
            guard let self else { return }
            var stage = ProviderTopologyVerificationStage.loadSelection
            var selectedRoute: ModelRoute?
            do {
                let selection = try self.modelSettingsStore.loadOrMigrate().settings.defaultSelection
                selectedRoute = selection.route
                // The pinned pi-ai adapter is deliberately dormant in a clean
                // DSH home. Reconcile its Ollama/Qwen profile to the exact
                // process-owned endpoint before any session can observe it.
                if selection.route.provider == BuiltInProviderDescriptors.ollama.id {
                    stage = .resolveOwnedOllamaEndpoint
                    guard let providerBaseURL = self.controller.ollamaProviderBaseURL else {
                        throw RuntimeTopologyValidationError.endpointUnavailable
                    }
                    stage = .validateLocalRuntimeVersion
                    _ = try await self.ollamaClient.fetchCompatibleVersion()
                    stage = .inspectInstalledLocalModels
                    let installed = try await self.ollamaClient.fetchModels()
                    guard installed.filter({ $0.name == selection.route.model.rawValue }).count == 1 else {
                        throw RuntimeTopologyValidationError.modelUnavailable(selection.route.model)
                    }
                    try LocalModelCompatibilityPolicy.validateInstalledIdentity(
                        selection: selection,
                        installedModels: installed
                    )
                    try LocalModelCompatibilityPolicy.validateHostMemory(
                        selection: selection,
                        installedModels: installed,
                        physicalMemoryBytes: ProcessInfo.processInfo.physicalMemory
                    )
                    let assessment = try await self.ollamaClient.inspectModelCompatibility(
                        model: selection.route.model.rawValue
                    )
                    _ = try LocalModelCompatibilityPolicy.validate(
                        selection: selection,
                        assessment: assessment
                    )
                    stage = .synchronizeLocalProvider
                    _ = try await self.modelCoordinator.synchronizeAppOwnedLocalProvider(
                        selection,
                        providerBaseURL: providerBaseURL
                    )
                }
                stage = .loadProviderCatalog
                var catalog = try await self.modelCoordinator.loadCatalog()
                guard generation == self.runtimeGeneration else { return }
                stage = .validateSelectedRoute
                guard var active = catalog.provider(selection.route.provider),
                      active.configurationState == .ready else {
                    throw RuntimeTopologyValidationError.providerUnavailable(selection.route.provider)
                }
                guard active.models.contains(where: { $0.id == selection.route.model }) else {
                    throw RuntimeTopologyValidationError.modelUnavailable(selection.route.model)
                }
                guard let endpointURL = active.descriptor.defaultBaseURL,
                      let networkOrigin = ProviderNetworkOrigin(url: endpointURL) else {
                    throw RuntimeTopologyValidationError.endpointUnavailable
                }

                if active.boundary == .onDevice {
                    stage = .validateOnDeviceBoundary
                    let host = networkOrigin.host
                    guard host == "localhost" || host == "::1" || host.hasPrefix("127.") else {
                        throw RuntimeTopologyValidationError.boundaryMismatch
                    }
                    if selection.route.provider == BuiltInProviderDescriptors.ollama.id {
                        guard let ownedURL = self.controller.ollamaProviderBaseURL,
                              let ownedOrigin = ProviderNetworkOrigin(url: ownedURL),
                              networkOrigin == ownedOrigin else {
                            throw RuntimeTopologyValidationError.boundaryMismatch
                        }
                        // DSH context capacity belongs to the exact adapter/model
                        // route, not to process environment. Commit and re-read
                        // it before the browser or scheduler can create a session.
                        stage = .synchronizeLocalPerformance
                        _ = try await self.modelCoordinator.synchronizeLocalPerformanceCapability(selection)
                        stage = .reloadLocalProviderCatalog
                        catalog = try await self.modelCoordinator.loadCatalog()
                        guard generation == self.runtimeGeneration else { return }
                        guard let refreshed = catalog.provider(selection.route.provider),
                              refreshed.configurationState == .ready,
                              refreshed.boundary == .onDevice,
                              refreshed.models.contains(where: { $0.id == selection.route.model }),
                              let refreshedURL = refreshed.descriptor.defaultBaseURL,
                              let refreshedOrigin = ProviderNetworkOrigin(url: refreshedURL),
                              refreshedOrigin == ownedOrigin else {
                            throw RuntimeTopologyValidationError.boundaryMismatch
                        }
                        active = refreshed
                    }
                    // On-device activation needs no disclosure prompt, but it
                    // records the live endpoint classification so no code path
                    // later relies on the provider's opaque ID.
                    stage = .recordEndpointConsent
                    _ = try self.providerConsentStore.activate(active.descriptor)
                } else {
                    stage = .validateExternalConsent
                    let consent = try self.providerConsentStore.load()
                    guard let grant = consent.activeGrant(for: selection.route.provider),
                          grant.permits(active.descriptor) else {
                        throw RuntimeTopologyValidationError.consentRequired(
                            boundary: active.boundary,
                            origin: ProviderEndpointOrigin(url: endpointURL)
                        )
                    }
                }

                // Native preferences are the product default, but a clean DSH
                // home ships with its own cloud default. Synchronize and verify
                // the exact native route before any browser, Quick Chat, or
                // scheduled session is allowed to exist. This also repairs
                // external edits on every authenticated runtime start.
                stage = .synchronizeDefaultRoute
                _ = try await self.modelCoordinator.synchronizeDefault(selection)
                guard generation == self.runtimeGeneration else { return }

                let finalizedCatalog = catalog
                let descriptors = finalizedCatalog.providers.map(\.descriptor)
                await self.sessionHistoryRepository.updateProviderDescriptors(descriptors)
                await MainActor.run {
                    guard generation == self.runtimeGeneration else { return }
                    self.scheduleManager.updateVerifiedProviderCatalog(
                        descriptors: descriptors,
                        activeRoute: selection.route
                    )
                    self.providerCatalog = finalizedCatalog
                    self.refreshToolbarCatalog(catalog: finalizedCatalog)
                    if self.providerWindow?.window?.isVisible == true { self.providerWindow.refresh() }
                    completion(.success(finalizedCatalog))
                }
            } catch {
                let failure = ProviderTopologyVerificationFailure(
                    stage: stage,
                    reason: providerTopologyFailureReason(error),
                    allowsInstalledLocalModelChoice: selectedRoute?.provider == BuiltInProviderDescriptors.ollama.id
                        && stage.allowsInstalledLocalModelChoice
                )
                await MainActor.run {
                    guard generation == self.runtimeGeneration else { return }
                    completion(.failure(failure))
                }
            }
        }
    }

    private func finishReadyState() {
        ThermalReadyStateAdmissionGate.perform(
            selectedLocalRuntimeBlocked: thermalSafetyBlocksSelectedLocalRuntime,
            onBlocked: { [self] in
                if let endpoint = controller.endpoint {
                    thermalReadyFinalization.deferVerifiedTopology(
                        generation: runtimeGeneration,
                        endpoint: endpoint
                    )
                } else {
                    thermalReadyFinalization.clear()
                }
                _ = enforceCurrentThermalBlockIfNeeded()
            },
            onAdmitted: { [self] in
                finishThermallyAdmittedReadyState()
            }
        )
    }

    private func finishThermallyAdmittedReadyState() {
        guard let endpoint = controller.endpoint,
              rpcClient.promoteToFullInference(expected: endpoint) else {
            failClosedAfterTopologyValidation(RuntimeTopologyValidationError.runtimeChanged)
            return
        }
        thermalReadyFinalization.clear()
        providerRecoveryContext = nil
        providerRecoveryTransitionInFlight = false
        if !selectedRuntimeIsAppOwnedLocal {
            // A deliberate cloud/custom switch is immediately usable even if
            // the prior local route remains in a memory/thermal recovery phase.
            // Do not let that old local restart intent touch the cloud runtime
            // when the host later reports recovery.
            thermalRuntimeRestartRequested = false
            thermalInitialStartupDeferred = false
            thermalShutdownEstablished = false
        }
        if protectedRuntimeConversationHoldOutstanding {
            conversationService.resumeAfterQuiescence()
            sessionHistoryLifecycle.resumeAfterQuiescence()
            protectedRuntimeConversationHoldOutstanding = false
        }
        if memoryPressureConversationHoldOutstanding,
           !thermalSafetyBlocksSelectedLocalRuntime,
           mayPublishReadyStatusForThermalPolicy(
               localRuntimeSelected: selectedRuntimeIsAppOwnedLocal
           ) {
            releaseMemoryPressureAdmissionHold(resumeSchedules: false)
        }
        mainWindow.surface.configure(endpoint: endpoint)
        if memoryPressureConversationHoldOutstanding {
            mainWindow.surface.suspendTurnAdmissions()
        } else {
            mainWindow.surface.resumeTurnAdmissionsForFreshRuntime()
        }
        scheduleManager.start()
        if memoryPressureConversationHoldOutstanding {
            scheduleManager.pauseNewAdmissionsSynchronously()
            if case .eco(reason: .memoryPressure) = thermalSafety.phase {
                presentThermalEco(reason: .memoryPressure)
            }
        }
        // Every newly launched/restarted runtime gets a host-created session;
        // persisted browser selection is never trusted across the boundary.
        mainWindow.surface.requireFreshSessionAfterNextLoad()
        mainWindow.surface.loadHarness()
        companionWindow.quickChat.runtimeDidRestart()
        if historyWindow.window?.isVisible == true { historyWindow.refresh() }
        if let runtimeActivity {
            let detail = !mayPublishReadyStatusForThermalPolicy(
                localRuntimeSelected: selectedRuntimeIsAppOwnedLocal
            )
                ? "Authenticated runtime and exact provider endpoint are unavailable for new local work until Normal policy repair succeeds."
                : "Authenticated runtime and exact provider endpoint are ready."
            activityStore.update(runtimeActivity, state: .completed, detail: detail, progress: 1)
            self.runtimeActivity = nil
        }
        privacyLedger.record(
            .runtimeStarted,
            summary: preferences.strictLocalMode ? "Strict Local runtime started" : "Runtime started with exact provider-origin access",
            localOnly: preferences.strictLocalMode
        )
        diagnosticsWindow?.refresh()
        if Date().timeIntervalSince(startDate) > 4,
           mayPublishReadyStatusForThermalPolicy(
               localRuntimeSelected: selectedRuntimeIsAppOwnedLocal
           ) {
            let selection = (try? modelSettingsStore.loadOrMigrate().settings.defaultSelection) ?? .defaultLocal
            notifications.send(
                title: "\(ProductBrand.displayName) is ready",
                body: "\(selection.route.model.rawValue) is available through \(selection.route.provider.rawValue).",
                identifier: "service-ready"
            )
        }
        if let physicalHandoffAcceptance,
           physicalHandoffAcceptance.mode == .foreground {
            do {
                let selection = try modelSettingsStore.loadOrMigrate().settings.defaultSelection
                try physicalHandoffAcceptance.publishForegroundReady(
                    selection: selection,
                    boundary: .onDevice
                )
            } catch {
                failClosedAfterTopologyValidation(error)
                return
            }
        }
        if let postInstallHealthContext {
            do {
                try postInstallHealthContext.acknowledgeHealthy()
                self.postInstallHealthContext = nil
            } catch {
                failClosedAfterTopologyValidation(error)
                return
            }
        }
        _ = protectedInferenceStartWaiter.resume(with: .success(()))
    }

    /// The only synchronous entry into a protected runtime transition. Every
    /// subsequent mutation waits for the controller's exact stop generation.
    @MainActor
    private func closeAllRuntimeAdmissionsSynchronously() {
        thermalReadyFinalization.clear()
        // The controller queues state delivery on the main actor. Suspend its
        // publication generation first so a `.ready` produced before this
        // boundary cannot be delivered afterward and rebound to our new app
        // epoch.
        controller.suspendLifecycleStatePublications()
        // Invalidate every in-flight readiness/catalog completion before any
        // admission surface is closed. Since both publication and transition
        // run on the main actor, an older runtime can never re-promote itself
        // between this rotation and exact process shutdown.
        runtimeReadinessEpoch.rotate()
        mainWindow.surface.suspendTurnAdmissions()
        mainWindow.surface.requireFreshSessionAfterNextLoad()
        mainWindow.surface.configure(endpoint: nil)
        companionWindow.quickChat.runtimeDidRestart()
        sessionOpenGeneration = UUID()
        scheduleManager.suspendAdmissionsSynchronously()
        if !protectedRuntimeConversationHoldOutstanding {
            conversationService.suspendAdmissionsForQuiescence()
            sessionHistoryLifecycle.suspendAdmissionsForQuiescence()
            protectedRuntimeConversationHoldOutstanding = true
        }
        mainWindow.updateStatus("Protected change · Agent work blocked", color: .systemOrange)
    }

    @MainActor
    private func stopOwnedRuntimeForProtectedMutation() async throws {
        try await withCheckedThrowingContinuation { continuation in
            controller.stopOwnedServicesAndWait { result in
                continuation.resume(with: result)
            }
        }
    }

    @MainActor
    private func startProviderControlPlaneForProtectedMutation() async throws {
        guard !protectedControlPlaneStartWaiter.isWaiting,
              !protectedInferenceStartWaiter.isWaiting else {
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.readinessWaiterBusy)
        }
        providerRecoveryContext = .routeVerification(nil)
        providerRecoveryTransitionInFlight = true
        try await protectedControlPlaneStartWaiter.wait(label: "the isolated provider control plane") {
            controller.prepareProviderRecovery()
        }
    }

    @MainActor
    private func startVerifiedInferenceForProtectedMutation() async throws {
        guard !protectedControlPlaneStartWaiter.isWaiting,
              !protectedInferenceStartWaiter.isWaiting else {
            throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.readinessWaiterBusy)
        }
        providerRecoveryContext = nil
        providerRecoveryTransitionInFlight = false
        if thermalSafetyBlocksSelectedLocalRuntime {
            throw currentLocalRuntimeAdmissionError
        }
        startDate = Date()
        try await protectedInferenceStartWaiter.wait(label: "a fresh verified inference runtime") {
            controller.prepareAndStart()
        }
    }

    @MainActor
    private func acquireStateBackupTransition(
        _ operation: StateBackupProtectedOperation,
        completion: @escaping @MainActor (Result<StateBackupQuiescencePermit, Error>) -> Void
    ) {
        let kind: ProtectedRuntimeMutationKind
        let status: String
        switch operation {
        case .manualCreate:
            kind = .stateBackup
            status = "Creating coherent backup · Agent work blocked"
        case .restore:
            kind = .stateRestore
            status = "State restore · Agent work blocked"
        case .updateInstall:
            kind = .updateInstall
            status = "Verified update · Agent work blocked"
        }
        mainWindow.updateStatus(status, color: .systemOrange)
        Task { @MainActor [weak self] in
            guard let self else {
                completion(.failure(HarnessConversationError.cancellationUnverified))
                return
            }
            do {
                let protectedPermit = try await self.protectedRuntimeMutations.acquire(
                    kind: kind,
                    requirement: .stoppedRuntime
                )
                guard self.stateBackupTransitionPermits[protectedPermit.id] == nil else {
                    try await self.protectedRuntimeMutations.finish(
                        protectedPermit,
                        disposition: .remainStopped
                    )
                    throw ProtectedRuntimeMutationCoordinatorError.invalidPermit
                }
                self.stateBackupTransitionPermits[protectedPermit.id] = protectedPermit
                completion(.success(StateBackupQuiescencePermit(
                    id: protectedPermit.id,
                    validation: { try protectedPermit.validate() }
                )))
            } catch {
                completion(.failure(error))
            }
        }
    }

    @MainActor
    private func finishStateBackupTransition(
        _ permit: StateBackupQuiescencePermit,
        disposition: StateBackupTransitionDisposition,
        result: Result<Void, Error>,
        completion: @escaping @MainActor () -> Void
    ) {
        guard let protectedPermit = stateBackupTransitionPermits[permit.id] else {
            showAlert(
                title: "Protected transition identity was lost",
                message: "\(ProductBrand.displayName) kept agent work blocked because the backup or update permit could not be matched to the stopped runtime."
            )
            return
        }

        let rollbackFailure: (String, String)?
        if case .failure(let error) = result,
           let backupError = error as? BackupError,
           case .rollbackFailed(let recovery, let staged) = backupError {
            rollbackFailure = (recovery, staged)
        } else {
            rollbackFailure = nil
        }

        let resultSucceeded: Bool
        switch result {
        case .success: resultSucceeded = true
        case .failure: resultSucceeded = false
        }
        let protectedDisposition: ProtectedRuntimeMutationDisposition
        switch disposition {
        case .terminateForUpdate where resultSucceeded:
            protectedDisposition = .terminateForUpdate
        case .terminateForUpdate:
            // A failed installer preparation never earns terminal authority.
            protectedDisposition = .restartInference
        case .restartAndReopen where rollbackFailure != nil:
            protectedDisposition = .remainStopped
        case .restartAndReopen:
            protectedDisposition = .restartInference
        }
        let mutationCommitted = resultSucceeded || rollbackFailure != nil

        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await self.protectedRuntimeMutations.finish(
                    protectedPermit,
                    disposition: protectedDisposition,
                    mutationCommitted: mutationCommitted
                )
                self.stateBackupTransitionPermits.removeValue(forKey: permit.id)
                if let rollbackFailure {
                    self.showAlert(
                        title: "Harness remains stopped for recovery",
                        message: "Automatic rollback could not restore a safe state. Recovery material was preserved at \(rollbackFailure.0) and \(rollbackFailure.1). Copy those folders before attempting another launch."
                    )
                }
                completion()
            } catch {
                self.stateBackupTransitionPermits.removeValue(forKey: permit.id)
                self.showAlert(
                    title: protectedDisposition == .terminateForUpdate
                        ? "Update handoff remained blocked"
                        : "Protected runtime recovery remained blocked",
                    message: error.localizedDescription
                )
                // Never acknowledge a failed terminal update handoff: the
                // helper may only trigger Quit after the irreversible latch.
                if protectedDisposition != .terminateForUpdate { completion() }
            }
        }
    }

    @MainActor
    private func requestAuthorizedUpdateTermination() {
        guard protectedRuntimeMutations.claimAuthorizedUpdateTermination() else {
            showAlert(
                title: "Update quit was not authorized",
                message: "The verified installer did not receive terminal ownership of the stopped runtime. \(ProductBrand.displayName) will remain open and blocked."
            )
            return
        }
        updateTerminationRequested = true
        NSApp.terminate(nil)
    }

    private func failClosedAfterTopologyValidation(_ error: Error) {
        // A protected start owns its own exact-child cleanup and optional
        // compensation. Settle it before the ordinary autonomous repair path
        // can launch a sibling control-plane process underneath the gate.
        if protectedInferenceStartWaiter.resume(with: .failure(error)) { return }
        if protectedRuntimeMutations.isTransitionInFlight { return }
        guard !providerRecoveryTransitionInFlight else { return }
        let diagnostic = providerTopologyFailureReason(error)
        closeAllRuntimeAdmissionsSynchronously()
        providerRecoveryTransitionInFlight = true
        if let failure = error as? ProviderTopologyVerificationFailure,
           failure.allowsInstalledLocalModelChoice {
            providerRecoveryContext = .localModelSelectionRequired(diagnostic)
        } else {
            providerRecoveryContext = .routeVerification(diagnostic)
        }
        mainWindow.updateStatus("Provider verification required", color: .systemOrange)
        showLoading("Locking agent work and opening provider repair…")
        let schedules = scheduleManager
        let conversations = conversationService
        let history = sessionHistoryLifecycle
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await RuntimeAdmissionQuiescenceBarrier(
                    schedules: { try await schedules.quiesce() },
                    conversations: { try await conversations.quiesceSuspendedAdmissions() },
                    history: { try await history.quiesceSuspendedAdmissions() }
                ).quiesce()
            } catch {
                self.providerRecoveryTransitionInFlight = false
                self.mainWindow.surface.showFailure(
                    "Fulmar could not verify cleanup of unfinished agent work. Provider repair remained blocked."
                )
                return
            }
            self.controller.stopOwnedServicesAndWait { [weak self] result in
                guard let self else { return }
                switch result {
                case .success:
                    if let runtimeActivity = self.runtimeActivity {
                        self.activityStore.update(
                            runtimeActivity,
                            state: .waiting,
                            detail: "Agent work is blocked pending provider repair. \(diagnostic)"
                        )
                    }
                    self.notifications.send(
                        title: "Provider verification required",
                        body: "Open Models & Providers to repair the selected route.",
                        identifier: "provider-boundary-failed"
                    )
                    self.controller.prepareProviderRecovery()
                case .failure(let stopError):
                    self.providerRecoveryTransitionInFlight = false
                    self.mainWindow.surface.showFailure(
                        "\(ProductBrand.displayName) could not safely stop the previous runtime. Provider repair was not opened. \(stopError.localizedDescription)"
                    )
                }
            }
        }
    }

    private func presentProviderRecovery() {
        guard let context = providerRecoveryContext else {
            mainWindow.surface.showFailure("Provider recovery was not authorized for this runtime state.")
            return
        }
        providerRecoveryTransitionInFlight = false
        let inspection = context.inspection
        mainWindow.surface.showProviderRecovery(
            context.userMessage,
            allowsNativeStateReset: inspection?.permitsStateReset == true,
            retry: { [weak self] in self?.retryProviderVerification() },
            chooseLocalModel: context.allowsInstalledLocalModelChoice
                ? { [weak self] in self?.showModelManager(nil) }
                : nil,
            openProviders: { [weak self] in self?.showProviderCenter(nil) },
            resetNativeState: inspection?.permitsStateReset == true
                ? { [weak self] in self?.confirmNativeProviderStateReset() }
                : nil
        )
    }

    private func retryProviderVerification() {
        let inspection = nativeProviderStateRecovery.inspect()
        if inspection.requiresRecovery {
            providerRecoveryContext = .nativeState(inspection)
            presentProviderRecovery()
            return
        }
        showLoading("Restarting with the repaired provider route…")
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await self.protectedRuntimeMutations.perform(
                    kind: .manualRestart,
                    requirement: .stoppedRuntime
                ) { permit in try permit.validate() }
            } catch {
                self.presentProviderRecovery()
                self.showAlert(title: "Provider verification could not restart", message: error.localizedDescription)
            }
        }
    }

    private func confirmNativeProviderStateReset() {
        guard case .nativeState(let inspection) = providerRecoveryContext,
              inspection.permitsStateReset else { return }
        let names = inspection.affectedDocuments
            .map { $0 == .modelSettings ? "model selection" : "provider consent" }
            .sorted()
            .joined(separator: " and ")
        let alert = NSAlert()
        alert.messageText = "Preserve and reset damaged provider state?"
        alert.informativeText = "\(ProductBrand.displayName) will first create exact owner-only recovery copies of the damaged \(names). It will then reset only those records. Agent work stays blocked until the resulting local or cloud route passes verification."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Preserve and Reset")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        performNativeProviderStateReset(inspection, allowsResetWithoutCopy: false)
    }

    private func confirmOversizedNativeProviderStateReset(
        _ inspection: NativeProviderStateInspection
    ) {
        let oversized = inspection.issues
            .filter(NativeProviderStateRecovery.requiresResetWithoutRecoveryCopy)
            .sorted { $0.document.rawValue < $1.document.rawValue }
        guard !oversized.isEmpty else {
            presentProviderRecovery()
            showAlert(
                title: "Provider state was not reset",
                message: NativeProviderStateRecoveryError.stateChanged.localizedDescription
            )
            return
        }
        let exactValues = oversized.map { issue in
            let name = issue.document == .modelSettings ? "Model selection" : "Provider consent"
            let bytes = ByteCountFormatter.string(
                fromByteCount: Int64(issue.fingerprint.byteCount),
                countStyle: .file
            )
            return "\(name): \(issue.fingerprint.encoding.rawValue), \(bytes), SHA-256 \(issue.fingerprint.sha256)"
        }.joined(separator: "\n")
        let alert = NSAlert()
        alert.messageText = "Reset oversized state without a recovery copy?"
        alert.informativeText = "The exact state below exceeds \(ProductBrand.displayName)'s 64 MiB per-copy safety limit. It cannot be retained in the bounded private recovery folder. Resetting it is irreversible. Any other damaged record will still be copied first.\n\n\(exactValues)"
        alert.alertStyle = .critical
        alert.addButton(withTitle: "Reset Without Copy")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            presentProviderRecovery()
            return
        }

        performNativeProviderStateReset(inspection, allowsResetWithoutCopy: true)
    }

    private func performNativeProviderStateReset(
        _ inspection: NativeProviderStateInspection,
        allowsResetWithoutCopy: Bool
    ) {
        showLoading(allowsResetWithoutCopy
            ? "Resetting explicitly confirmed oversized provider state…"
            : "Creating private recovery copies…")
        Task { @MainActor [weak self] in
            guard let self else { return }
            let permit: ProtectedRuntimeMutationPermit
            do {
                permit = try await self.protectedRuntimeMutations.acquire(
                    kind: .nativeProviderStateReset,
                    requirement: .stoppedRuntime
                )
            } catch {
                self.presentProviderRecovery()
                self.showAlert(title: "Provider state reset could not start", message: error.localizedDescription)
                return
            }

            let result: Result<NativeProviderStateRecoveryReceipt, Error> = await withCheckedContinuation { continuation in
                let recovery = self.nativeProviderStateRecovery
                DispatchQueue.global(qos: .utility).async {
                    continuation.resume(returning: Result {
                        if allowsResetWithoutCopy {
                            return try recovery
                                .resetOversizedAfterExplicitDoubleConfirmation(
                                    expected: inspection,
                                    validateBeforeCommit: { try permit.validate() }
                                )
                        }
                        return try recovery
                            .resetAfterExplicitConfirmation(
                                expected: inspection,
                                validateBeforeCommit: { try permit.validate() }
                            )
                    })
                }
            }

            let committed: Bool
            let disposition: ProtectedRuntimeMutationDisposition
            switch result {
            case .success:
                committed = true
                disposition = .restartInference
            case .failure:
                committed = false
                disposition = .remainStopped
            }

            var recoveryError: Error?
            do {
                try await self.protectedRuntimeMutations.finish(
                    permit,
                    disposition: disposition,
                    mutationCommitted: committed
                )
            } catch {
                recoveryError = error
            }

            switch result {
            case .success(let receipt):
                let next = self.nativeProviderStateRecovery.inspect()
                if next.requiresRecovery { self.providerRecoveryContext = .nativeState(next) }
                if recoveryError != nil || next.requiresRecovery { self.presentProviderRecovery() }

                let completed = NSAlert()
                completed.messageText = recoveryError == nil
                    ? "Damaged state was preserved, reset, and verified"
                    : "Damaged state was reset; runtime verification is blocked"
                let omitted = receipt.resetWithoutRecoveryCopy
                    .map { $0 == .modelSettings ? "model selection" : "provider consent" }
                    .sorted()
                    .joined(separator: " and ")
                let retainedMessage = receipt.quarantinedFiles.isEmpty
                    ? "No recovery copy was created."
                    : "Exact private copies were retained in:\n\(receipt.recoveryDirectory.path)\n\nReview or remove them when you no longer need recovery."
                let omittedMessage = omitted.isEmpty
                    ? ""
                    : "\n\nAs explicitly confirmed, no recovery copy was created for the oversized \(omitted)."
                let recoveryMessage = recoveryError.map { "\n\n\($0.localizedDescription)" } ?? ""
                completed.informativeText = retainedMessage + omittedMessage + recoveryMessage
                completed.addButton(withTitle: "Done")
                if !receipt.quarantinedFiles.isEmpty {
                    completed.addButton(withTitle: "Reveal Recovery Copies")
                }
                if completed.runModal() == .alertSecondButtonReturn,
                   !receipt.quarantinedFiles.isEmpty {
                    NSWorkspace.shared.open(receipt.recoveryDirectory)
                }
            case .failure(let error as NativeProviderStateRecoveryError)
                where error == .oversizedConfirmationRequired && !allowsResetWithoutCopy:
                self.confirmOversizedNativeProviderStateReset(inspection)
            case .failure(let error as NativeProviderStateRecoveryError)
                where error == .quarantineCapacityReached:
                self.presentProviderRecovery()
                self.manageProviderRecoveryCopies()
            case .failure(let error):
                self.presentProviderRecovery()
                self.showAlert(
                    title: "Provider state was not reset",
                    message: recoveryError.map {
                        "\(error.localizedDescription)\n\nRuntime boundary: \($0.localizedDescription)"
                    } ?? error.localizedDescription
                )
            }
        }
    }

    private func manageProviderRecoveryCopies() {
        do {
            let archives = try nativeProviderStateRecovery.recoveryArchives()
            let bytes = archives.reduce(0) { $0 + $1.byteCount }
            let directory = controller.diagnosticsDirectory()
                .appendingPathComponent(NativeProviderStateRecovery.directoryName, isDirectory: true)
            let alert = NSAlert()
            alert.messageText = "Provider recovery copies"
            alert.informativeText = "The private folder contains \(archives.count) retained copies (\(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file))). Nothing will be deleted automatically.\n\n\(directory.path)"
            alert.addButton(withTitle: "Reveal Folder")
            alert.addButton(withTitle: "Delete Copies…")
            alert.addButton(withTitle: "Cancel")
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                NSWorkspace.shared.open(directory)
            case .alertSecondButtonReturn:
                confirmDeleteProviderRecoveryCopies(archives)
            default:
                break
            }
        } catch {
            showAlert(title: "Recovery copies could not be inspected", message: error.localizedDescription)
        }
    }

    private func confirmDeleteProviderRecoveryCopies(_ archives: [NativeProviderStateRecoveryArchive]) {
        guard let oldest = archives.first else { return }
        let alert = NSAlert()
        alert.messageText = "Delete private recovery copies?"
        alert.informativeText = "Deleting a recovery copy cannot be undone. You can delete only the oldest attested copy (\(oldest.url.lastPathComponent)) or clear all \(archives.count) copies."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete Oldest")
        alert.addButton(withTitle: "Delete All")
        alert.addButton(withTitle: "Cancel")
        do {
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                try nativeProviderStateRecovery.deleteRecoveryArchiveAfterExplicitConfirmation(oldest)
            case .alertSecondButtonReturn:
                try nativeProviderStateRecovery.clearRecoveryArchivesAfterExplicitConfirmation(expected: archives)
            default:
                return
            }
            showAlert(title: "Recovery copies updated", message: "You can now retry the preserve-and-reset operation.")
        } catch {
            showAlert(title: "Recovery copies were not deleted", message: error.localizedDescription)
        }
    }

    private func toggleCompanion() {
        if companionWindow.window?.isVisible == true && companionWindow.window?.isKeyWindow == true {
            companionWindow.close()
        } else {
            showQuickChat(nil)
        }
    }

    @objc func showMainWindow(_ sender: Any?) {
        mainWindow.showWindow(sender)
        activateForUserInteraction(window: mainWindow.window, sender: sender)
    }

    /// Makes user-requested windows recoverable even when Launch Services has
    /// just reused a non-frontmost process. `orderFrontRegardless` is bounded
    /// to an explicit user-facing action; background schedule launches never
    /// build these windows and therefore never call this helper.
    private func activateForUserInteraction(window: NSWindow?, sender: Any? = nil) {
        guard let window else { return }
        _ = NSApp.setActivationPolicy(.regular)
        window.orderFrontRegardless()
        window.makeKeyAndOrderFront(sender)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async { [weak window] in
            guard let window else { return }
            window.orderFrontRegardless()
            window.makeKey()
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    @objc func showCommandCenter(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        commandCenterWindow.showWindow(sender)
        commandCenterWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showQuickChat(_ sender: Any?) {
        guard providerRecoveryContext == nil else {
            showMainWindow(sender)
            presentProviderRecovery()
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        companionWindow.showWindow(sender)
        companionWindow.window?.makeKeyAndOrderFront(sender)
        companionWindow.quickChat.refreshModels()
    }

    @objc func showActivityCenter(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        activityWindow.showWindow(sender)
        activityWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showTaskHistory(_ sender: Any?) {
        guard providerRecoveryContext == nil else {
            showMainWindow(sender)
            presentProviderRecovery()
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        historyWindow.showWindow(sender)
        historyWindow.window?.makeKeyAndOrderFront(sender)
    }

    private func continueSession(_ sessionID: HarnessSessionID) {
        let requestGeneration = UUID()
        sessionOpenGeneration = requestGeneration
        Task { [weak self] in
            guard let self else { return }
            do {
                let detail = try await sessionHistoryRepository.detail(for: sessionID)
                guard self.sessionOpenGeneration == requestGeneration else { return }
                await MainActor.run { self.showQuickChat(nil) }
                let openResult = await self.companionWindow.quickChat.openSession(detail)
                await MainActor.run {
                    guard self.sessionOpenGeneration == requestGeneration else { return }
                    switch openResult {
                    case .opened, .boundaryDeclined:
                        break
                    case .routeUnavailable:
                        self.showAlert(
                            title: "Task cannot be continued yet",
                            message: "Its transcript remains available in Task History, but Harness could not confirm a routable provider and model."
                        )
                    }
                }
            } catch {
                await MainActor.run {
                    guard self.sessionOpenGeneration == requestGeneration else { return }
                    self.showAlert(title: "Task could not be opened", message: error.localizedDescription)
                }
            }
        }
    }

    @objc func showModelManager(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        modelWindow.showWindow(sender)
        modelWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showProviderCenter(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        providerWindow.showWindow(sender)
        providerWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showKnowledgeCenter(_ sender: Any?) {
        guard let knowledgeWindow else {
            showAlert(title: "Knowledge store unavailable", message: "\(ProductBrand.displayName) could not safely open its private knowledge directory. No data was changed; check Diagnostics for storage permissions.")
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        knowledgeWindow.showWindow(sender)
        knowledgeWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showSkillsCenter(_ sender: Any?) {
        configureSkillsWindowIfPrepared()
        guard let skillsWindow else {
            showAlert(title: "Skills unavailable", message: "The private skill store becomes available after the Harness home has been securely prepared. If startup has failed, review Diagnostics; no skill was exposed.")
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        skillsWindow.showWindow(sender)
        skillsWindow.window?.makeKeyAndOrderFront(sender)
    }

    private func configureSkillsWindowIfPrepared() {
        guard skillsWindow == nil,
              let skillStore = try? controller.skillsTrustStore() else { return }
        let window = SkillsCenterWindowController(
            store: skillStore,
            projectURL: controller.workspaceDirectory(),
            currentBoundary: { [weak self] in self?.currentSkillBoundary() ?? .local }
        )
        window.onApplyAndRestart = { [weak self] boundary in
            guard let self else {
                throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
            }
            try await self.protectedRuntimeMutations.perform(
                kind: .skillActivation,
                requirement: .stoppedRuntime
            ) { permit in
                try permit.validate()
                self.prepareSkillsForBoundary(boundary)
            }
        }
        skillsWindow = window
    }

    @MainActor @objc func showMCPServers(_ sender: Any?) {
        if providerCatalog == nil {
            mainWindow.updateStatus("Loading the live provider catalog…", color: .systemOrange)
            Task { [weak self] in
                guard let self else { return }
                do {
                    let catalog = try await self.modelCoordinator.loadCatalog()
                    await MainActor.run {
                        self.providerCatalog = catalog
                        self.refreshToolbarCatalog(catalog: catalog)
                        self.presentMCPServers(sender)
                    }
                } catch {
                    await MainActor.run {
                        self.showAlert(
                            title: "MCP Servers unavailable",
                            message: "The live Harness provider catalog could not be verified. MCP remained disabled: \(error.localizedDescription)"
                        )
                    }
                }
            }
            return
        }
        presentMCPServers(sender)
    }

    @MainActor private func presentMCPServers(_ sender: Any?) {
        guard let catalog = providerCatalog else { return }
        do {
            let store = try controller.mcpTrustStore()
            let choices = catalog.providers.map {
                MCPProviderChoice(provider: $0.id, displayName: $0.displayName, boundary: $0.boundary)
            }
            let window = MCPCenterWindowController(
                store: store,
                projectRoot: controller.workspaceDirectory(),
                providerChoices: choices
            )
            window.onApplyAndRestart = { [weak self] in
                guard let self else {
                    throw ProtectedRuntimeMutationCoordinatorError.transitionFailed(.applicationLifecycleEnded)
                }
                try await self.protectedRuntimeMutations.perform(
                    kind: .mcpActivation,
                    requirement: .stoppedRuntime
                ) { permit in try permit.validate() }
            }
            mcpWindow = window
            NSApp.activate(ignoringOtherApps: true)
            window.showWindow(sender)
            window.window?.makeKeyAndOrderFront(sender)
        } catch {
            showAlert(
                title: "MCP Servers unavailable",
                message: "The private MCP trust store could not be opened safely. No tool server was enabled: \(error.localizedDescription)"
            )
        }
    }

    @objc func showWorkspaceRecovery(_ sender: Any?) {
        guard let recoveryWindow else {
            showAlert(
                title: "Workspace Recovery unavailable",
                message: "The private recovery journal could not safely open the approved Workspace. Harness files were not changed; review Diagnostics for storage permissions."
            )
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        recoveryWindow.showWindow(sender)
        recoveryWindow.window?.makeKeyAndOrderFront(sender)
    }

    private func currentSkillBoundary() -> SkillExecutionBoundary {
        guard let selection = try? modelSettingsStore.loadOrMigrate().settings.defaultSelection else { return .external }
        guard let consent = try? providerConsentStore.load(),
              let boundary = consent.activeGrant(for: selection.route.provider)?.boundary else { return .external }
        return boundary == .onDevice ? .local : .external
    }

    /// Resolves ask-every-time skill disclosure before the new runtime starts.
    /// Declining never blocks the provider switch; the affected skills are
    /// simply withheld from that external session.
    private func prepareSkillsForBoundary(_ boundary: SkillExecutionBoundary) {
        guard boundary == .external else {
            controller.prepareSkillActivation(for: .local)
            return
        }
        do {
            let plan = try controller.skillActivationPlan(for: .external)
            let approvals = SkillSessionDisclosureCoordinator.approvals(
                for: plan.needsCloudConsent,
                interactions: skillSessionDisclosureInteractions
            )
            controller.prepareSkillActivation(for: .external, oneTimeCloudApprovals: approvals)
        } catch {
            controller.prepareSkillActivation(for: .external)
            showAlert(
                title: "Skills kept unavailable",
                message: "The provider switch can continue, but \(ProductBrand.displayName) could not safely prepare the reviewed skill catalog. Reviewed skills remain unavailable for this external session."
            )
        }
    }

    @objc func showPerformanceCenter(_ sender: Any?) {
        guard let performanceWindow else { return }
        NSApp.activate(ignoringOtherApps: true)
        performanceWindow.update(snapshot: performanceSnapshot(ollama: .unavailable()))
        performanceWindow.showWindow(sender)
        performanceWindow.window?.makeKeyAndOrderFront(sender)
        guard let endpoint = controller.ollamaBaseURL,
              let identity = controller.verifiedOllamaExecutableIdentity,
              let ollamaInspector = try? OllamaRuntimeInspector(
                endpoint: endpoint,
                locator: AppOwnedOllamaInstallationLocator(identity: identity)
              ) else { return }
        Task { @MainActor [weak self, weak performanceWindow] in
            let ollama = await ollamaInspector.capture()
            guard let self else { return }
            performanceWindow?.update(snapshot: self.performanceSnapshot(ollama: ollama))
        }
    }

    private func performanceSnapshot(ollama: OllamaRuntimeSnapshot) -> PerformanceCenterSnapshot {
        let now = Date()
        let host = hostPerformanceCollector.capture(at: now)
        let persistedTelemetry = GenerationTelemetrySpool.read(
            applicationSupport: controller.diagnosticsDirectory().standardizedFileURL,
            at: now
        )
        // The runtime observer covers main Harness, Quick Chat, schedules,
        // compaction, and subagents. Keep the older in-memory Quick Chat path
        // only as a graceful fallback if private spool storage is unavailable.
        let telemetry = persistedTelemetry.isEmpty
            ? performanceTelemetry.history(at: now)
            : persistedTelemetry
        let selection = try? modelSettingsStore.loadOrMigrate().settings.defaultSelection
        return PerformanceCenterSnapshot(
            capturedAt: now,
            host: host,
            ollama: ollama,
            recommendation: AdaptivePerformanceRecommender.recommend(
                host: host,
                ollama: ollama,
                recentTelemetry: telemetry,
                selection: selection
            ),
            telemetry: telemetry,
            selection: selection
        )
    }

    @MainActor private func clearPerformanceHistory() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Clear private performance history?"
        alert.informativeText = "This removes the retained timing, token-count, outcome, and route-label records from this Mac. It does not delete conversations or models."
        alert.addButton(withTitle: "Clear History")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let started = performanceHistoryClearCoordinator.clear { [weak self] outcome in
            guard let self else { return }
            self.performanceWindow?.setHistoryClearPending(false)
            switch outcome {
            case .success:
                self.performanceTelemetry.clear()
                self.privacyLedger.record(
                    .privacyModeChanged,
                    summary: "Private performance history cleared",
                    localOnly: true
                )
                self.performanceWindow?.update(snapshot: self.performanceSnapshot(ollama: .unavailable()))
            case .failure:
                self.showAlert(
                    title: "Performance history was not cleared",
                    message: "Fulmar could not clear the private performance records safely. No conversation or model data was changed. Try again, or review Privacy & Access if the problem continues."
                )
            }
        }
        if started { performanceWindow?.setHistoryClearPending(true) }
    }

    @objc func selectToolbarModel(_ sender: NSMenuItem) {
        guard let choice = sender.representedObject as? ToolbarModelRouteChoice else { return }
        if choice.boundary.requiresExplicitConsent {
            guard let origin = choice.descriptor.defaultBaseURL.flatMap(ProviderEndpointOrigin.init(url:)) else {
                showAlert(
                    title: "Provider endpoint is unresolved",
                    message: "\(ProductBrand.displayName) kept network access blocked. Refresh Models & Providers and verify the configured endpoint."
                )
                return
            }
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = choice.boundary == .cloud ? "Use \(choice.providerName) in the cloud?" : "Use \(choice.providerName) on your network?"
            alert.informativeText = "Prompts, files, tool results, and conversation context for new tasks using \(choice.modelName) may leave this Mac. \(ProductBrand.displayName) will permit exactly \(origin.displayName); an endpoint change requires new consent."
            alert.addButton(withTitle: choice.boundary == .cloud ? "Use Cloud Provider" : "Use Network Provider")
            alert.addButton(withTitle: "Keep Work on This Mac")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }
        do {
            let settings = try modelSettingsStore.loadOrMigrate().settings
            let selection = ModelSelection(
                route: choice.route,
                reasoningEffort: nil,
                performanceProfile: settings.defaultSelection.performanceProfile
            )
            let progress = choice.route.provider == BuiltInProviderDescriptors.ollama.id
                ? "Checking \(choice.modelName) fits this Mac…"
                : "Securing \(choice.providerName)…"
            mainWindow.updateStatus(progress, color: .systemOrange)
            Task { [weak self] in
                guard let self else { return }
                do {
                    _ = try await self.providerSelectionTransaction.commit(
                        selection: selection,
                        descriptor: choice.descriptor
                    )
                    await MainActor.run {
                        self.refreshToolbarCatalog(catalog: self.providerCatalog)
                    }
                } catch {
                    await MainActor.run {
                        self.refreshToolbarCatalog(catalog: self.providerCatalog)
                        self.showAlert(title: "Model choice was not changed", message: error.localizedDescription)
                    }
                }
            }
        } catch {
            showAlert(title: "Model choice was not saved", message: error.localizedDescription)
        }
    }

    @objc func openHarnessProviderSettings(_ sender: Any?) {
        // Embedded DSH settings can mutate routes and credentials without the
        // native stop/control-plane gate. Production therefore exposes only
        // the provider-neutral native editor, whose writes are all protected.
        showProviderCenter(sender)
        showAlert(
            title: "Use the protected provider controls",
            message: "Direct provider changes inside the embedded Harness page are disabled. Add or repair built-in and custom providers here so \(ProductBrand.displayName) can stop the old runtime, verify the change in an isolated control plane, and start a fresh session."
        )
    }

    private func refreshProviderCatalog() {
        Task { [weak self] in
            guard let self else { return }
            do {
                let catalog = try await modelCoordinator.loadCatalog()
                await MainActor.run {
                    self.providerCatalog = catalog
                    self.refreshToolbarCatalog(catalog: catalog)
                    if self.providerWindow.window?.isVisible == true { self.providerWindow.refresh() }
                }
            } catch {
                await MainActor.run { self.refreshToolbarCatalog(catalog: nil) }
            }
        }
    }

    private func refreshToolbarCatalog(catalog: HarnessModelCatalogSnapshot?) {
        let selection = (try? modelSettingsStore.loadOrMigrate().settings.defaultSelection) ?? .defaultLocal
        mainWindow?.updateRouteMenu(catalog: catalog, selection: selection)
    }

    @objc func showPrivacyDashboard(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        privacyWindow.showWindow(sender)
        privacyWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showPluginTrust(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        pluginTrustWindow.showWindow(sender)
        pluginTrustWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showBackups(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        backupWindow.showWindow(sender)
        backupWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showSchedules(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        scheduleWindow.showWindow(sender)
        scheduleWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func newSession(_ sender: Any?) {
        if companionWindow.window?.isKeyWindow == true {
            companionWindow.quickChat.newChat()
            return
        }
        guard let coordinator = workspaceRecoveryCoordinator else {
            mainWindow.surface.startNewSession()
            return
        }
        mainWindow.updateStatus("Creating workspace checkpoint…", color: .systemOrange)
        Task { [weak self] in
            guard let self else { return }
            do {
                let protection = try await coordinator.captureBeforeTurn(reason: "Before main Harness task")
                await MainActor.run {
                    self.recoveryWindow?.refresh()
                    if case .readOnly = protection {
                        self.mainWindow.updateStatus("Read-only · Workspace safety", color: .systemOrange)
                    }
                    self.mainWindow.surface.startNewSession()
                }
            } catch {
                await MainActor.run {
                    self.showAlert(
                        title: "New task paused safely",
                        message: "\(ProductBrand.displayName) could not create a recovery point before the task, so it did not start a new session: \(error.localizedDescription)"
                    )
                }
            }
        }
    }
    @objc func goBack(_ sender: Any?) { mainWindow.surface.goBack() }
    @objc func goForward(_ sender: Any?) { mainWindow.surface.goForward() }
    @objc func actualSize(_ sender: Any?) { mainWindow.surface.actualSize() }
    @objc func zoomIn(_ sender: Any?) { mainWindow.surface.zoomIn() }
    @objc func zoomOut(_ sender: Any?) { mainWindow.surface.zoomOut() }
    @objc func findInPage(_ sender: Any?) { mainWindow.surface.performFindAction(sender) }

    @objc func reloadHarness(_ sender: Any?) {
        showLoading("Reloading your local workspace…")
        controller.probeHarness { [weak self] ready in
            guard let self else { return }
            if ready {
                self.mainWindow.surface.reload()
            } else { self.restartServices(nil) }
        }
    }

    @objc func openHarnessProject(_ sender: Any?) {
        guard let url = URL(string: "https://github.com/deepseek-ai/DeepSeek-Harness"),
              NSWorkspace.shared.open(url) else {
            showAlert(title: "Could not open the project page", message: "macOS could not open the verified HTTPS address in your default browser.")
            return
        }
        privacyLedger.record(.externalLinkOpened, summary: "github.com", localOnly: false)
    }

    @objc func showMenuBarSettings(_ sender: Any?) {
        let alert = NSAlert()
        alert.messageText = "Allow Fulmar in the Menu Bar"
        alert.informativeText = "macOS controls whether third-party menu-bar items are displayed. In System Settings → Menu Bar, find Allow in the Menu Bar and select Fulmar. The Dock icon, app menus, and main window remain available even when macOS hides the menu-bar item."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Open Menu Bar Settings")
        alert.addButton(withTitle: "Retry Placement Now")
        alert.addButton(withTitle: "Not Now")
        switch alert.runModal() {
        case .alertSecondButtonReturn:
            retryStatusItemPlacementFromUserAction(assertVisibility: true)
            return
        case .alertFirstButtonReturn:
            break
        default:
            return
        }

        let destinations = [
            "x-apple.systempreferences:com.apple.ControlCenter-Settings.extension",
            "x-apple.systempreferences:"
        ].compactMap(URL.init(string:))
        guard destinations.contains(where: { NSWorkspace.shared.open($0) }) else {
            showAlert(
                title: "Menu Bar settings could not be opened",
                message: "Open System Settings manually, choose Menu Bar, then select Fulmar under Allow in the Menu Bar."
            )
            return
        }
        // On return from System Settings, re-run the same bounded, geometry-
        // based verification. If macOS persisted the item as hidden, the first
        // check respects that choice and performs no recreation.
        retryStatusItemPlacementAfterSystemSettings = true
    }

    private func retryStatusItemPlacementFromUserAction(assertVisibility: Bool = false) {
        guard !thermalHeadlessMode else { return }
        if let item = statusItem {
            if assertVisibility { item.isVisible = true }
            StatusItemIcon.beginPlacementVerification(recoveryAttempt: 0)
            scheduleStatusItemPlacementVerification(for: item, attempt: 0)
        } else {
            buildStatusItem()
            if assertVisibility { statusItem?.isVisible = true }
        }
    }

    @objc func installVerifiedUpdate(_ sender: Any?) {
        guard Self.verifiedInAppUpdatesEnabled else {
            showAlert(
                title: "In-app updates are not available in this build",
                message: "Install only a complete, independently verified Fulmar application. The in-app updater will remain unavailable until interrupted installs and failed first launches can roll back automatically."
            )
            return
        }
        let panel = NSOpenPanel(); panel.title = "Choose a \(ProductBrand.displayName) Update"; panel.message = "Select a notarized update archive from a trusted release source."; panel.allowedContentTypes = [.zip]; panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let archive = panel.url else { return }
        let activity = activityStore.begin(.runtime, title: "Verify \(ProductBrand.displayName) update", detail: archive.lastPathComponent)
        updateManager.prepare(archive: archive) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let update):
                self.activityStore.update(activity, state: .waiting, detail: "Signature, notarization and build number verified.")
                self.privacyLedger.record(.updatePrepared, summary: "Verified \(ProductBrand.displayName) \(update.version) build \(update.build)", localOnly: true)
                let alert = NSAlert(); alert.messageText = "Install \(ProductBrand.displayName) \(update.version)?"; alert.informativeText = "Harness state will be backed up first. The current app is retained as a rollback copy, then the verified update is installed and reopened."; alert.alertStyle = .warning; alert.addButton(withTitle: "Back Up and Install"); alert.addButton(withTitle: "Cancel")
                guard alert.runModal() == .alertFirstButtonReturn else {
                    self.updateManager.discard(update)
                    self.activityStore.update(activity, state: .cancelled, detail: "Update installation cancelled.")
                    return
                }
                let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown"
                self.updateManager.install(
                    update,
                    currentVersion: current,
                    acquireTransition: { [weak self] operation, completion in
                        guard let self else {
                            completion(.failure(HarnessConversationError.cancellationUnverified))
                            return
                        }
                        self.acquireStateBackupTransition(operation, completion: completion)
                    },
                    finishTransition: { [weak self] permit, disposition, result, completion in
                        guard let self else { return }
                        self.finishStateBackupTransition(
                            permit,
                            disposition: disposition,
                            result: result,
                            completion: completion
                        )
                    },
                    authorizedQuit: { [weak self] in
                        self?.requestAuthorizedUpdateTermination()
                    },
                    completion: { [weak self] result in
                        guard let self else { return }
                        switch result {
                        case .success:
                            self.activityStore.update(
                                activity,
                                state: .completed,
                                detail: "Verified installer launched; quitting the stopped runtime."
                            )
                        case .failure(let error):
                            self.activityStore.update(activity, state: .failed, detail: error.localizedDescription)
                            self.showAlert(title: "Update could not be installed", message: error.localizedDescription)
                        }
                    }
                )
            case .failure(let error):
                self.activityStore.update(activity, state: .failed, detail: error.localizedDescription)
                self.showAlert(title: "Update was not accepted", message: error.localizedDescription)
            }
        }
    }

    @objc func captureAppshot(_ sender: Any?) {
        let application = lastExternalApplication
        let destinationSurface = mainWindow.surface
        let destinationIsQuickChat = companionWindow.window?.isKeyWindow == true
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let capture = try await self.appshotController.captureFrontWindow(of: application)
                guard let reviewed = AppshotReviewWindowController(image: capture.image).runModal() else { return }
                let reviewedURL = try self.appshotController.persistReviewed(reviewed.image, suggestedFilename: capture.suggestedFilename)
                if destinationIsQuickChat {
                    if self.companionWindow.quickChat.attachReviewedImage(
                        reviewed.image,
                        filename: reviewedURL.lastPathComponent,
                        accessibleText: reviewed.accessibleText
                    ) {
                        self.activityStore.addCompleted(.appshot, title: "Added reviewed Appshot to Chat", detail: "The cropped/redacted image was attached directly without using the global clipboard.")
                        self.privacyLedger.record(.appshotCaptured, summary: "Reviewed Appshot attached directly to Chat", localOnly: true)
                        self.notifications.send(title: "Appshot added", body: "Review it in Chat before sending.")
                    }
                    return
                }
                destinationSurface.attachImage(reviewed.image, filename: reviewedURL.lastPathComponent, accessibleText: reviewed.accessibleText) { [weak self] attached in
                    guard let self else { return }
                    if attached {
                        self.activityStore.addCompleted(.appshot, title: "Added reviewed appshot", detail: "The cropped/redacted image was attached directly without using the global clipboard.")
                        self.privacyLedger.record(.appshotCaptured, summary: "Reviewed appshot attached directly", localOnly: true)
                        self.notifications.send(title: "Appshot added", body: "Review it in the composer before sending.")
                    } else {
                        self.showAlert(title: "Could not attach appshot", message: "Harness did not expose an attachment target. Reload the workspace and try again.")
                    }
                }
            } catch {
                self.showAlert(title: "Appshot unavailable", message: error.localizedDescription)
            }
        }
    }

    @objc func restartServices(_ sender: Any?) {
        if let boundary = pendingThermalNormalModeRecovery?.boundary {
            guard retryPendingThermalNormalModeRecoveryIfPossible() else {
                showAlert(
                    title: "Adaptive performance still needs attention",
                    message: pendingThermalNormalModeRecovery?.localizedDescription
                        ?? "Fulmar could not save and verify its Normal workload policy."
                )
                return
            }
            if boundary == .cooldownRecovered { return }
        }
        guard !thermalSafetyBlocksSelectedLocalRuntime else {
            let safetyError = currentLocalRuntimeSafetyError
            showAlert(
                title: safetyError == .memoryPressure ? "New local work is paused" : "Local AI is cooling down",
                message: safetyError.localizedDescription
            )
            return
        }
        showLoading("Restarting local services…")
        beginProviderHistoryStartupGate(background: false) { [weak self] admitted in
            guard let self, admitted else { return }
            Task { @MainActor [weak self] in
                guard let self else { return }
                do {
                    try await self.protectedRuntimeMutations.perform(
                        kind: .manualRestart,
                        requirement: .stoppedRuntime
                    ) { permit in try permit.validate() }
                } catch {
                    self.showAlert(title: "Local services could not restart safely", message: error.localizedDescription)
                }
            }
        }
    }

    @objc func showSettings(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        settingsWindow.showWindow(sender)
        settingsWindow.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showDiagnostics(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        if diagnosticsWindow == nil {
            let window = DiagnosticsWindowController(
                controller: controller,
                globalHotKeyStatus: { [weak self] in
                    self?.hotKeyAvailability.diagnosticSummary ?? "Unavailable"
                }
            )
            window.onRestart = { [weak self] in self?.restartServices(nil) }
            diagnosticsWindow = window
        }
        diagnosticsWindow?.showWindow(sender)
        diagnosticsWindow?.window?.makeKeyAndOrderFront(sender)
    }

    @objc func showAbout(_ sender: Any?) {
        let credits = NSMutableAttributedString(string: "A private, provider-neutral macOS workbench for DeepSeek Harness, local Qwen models, and explicitly approved cloud APIs.\n\nDeepSeek describes Harness as experimental developer-preview software that has not undergone a security audit. Fulmar adds native safeguards, but no sandbox or approval system guarantees isolation. Keep backups and review every permission, plugin, Skill, MCP server, and command.\n\nIndependent software. Not affiliated with or endorsed by DeepSeek or any model provider.")
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: ProductBrand.displayName,
            .applicationVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") ?? "Development",
            .credits: credits
        ])
    }

    private func showAlert(title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func webSurface(_ surface: HarnessWebViewController, didOpenExternalURL url: URL) {
        guard NSWorkspace.shared.open(url) else {
            showAlert(title: "Could not open external link", message: "macOS could not open this address in your default browser.")
            return
        }
        privacyLedger.record(.externalLinkOpened, summary: url.host ?? "External website", localOnly: false)
    }
    func webSurface(_ surface: HarnessWebViewController, didCompleteDownload artifact: StagedDownloadArtifact, action: StagedDownloadUserAction) {
        let verb = action == .saved ? "Saved" : "Reviewed"
        activityStore.addCompleted(
            .artifact,
            title: "\(verb) \(artifact.displayFilename)",
            detail: "\(artifact.fileURL.path) · SHA-256 \(artifact.sha256)"
        )
        privacyLedger.record(.artifactDownloaded, summary: "\(verb): \(artifact.displayFilename)", localOnly: true)
        if action == .saved {
            notifications.send(title: "Download saved", body: artifact.displayFilename)
            return
        }
        guard artifact.allowsManualPreview else {
            webSurface(surface, didFailWith: "Preview was blocked for \(artifact.displayFilename).")
            return
        }
        let preview = ArtifactPreviewWindowController(artifact: artifact.fileURL, annotations: artifactAnnotations)
        artifactWindows.removeAll { $0.window == nil }
        artifactWindows.append(preview)
        preview.showWindow(nil)
        preview.window?.makeKeyAndOrderFront(nil)
    }
    func webSurface(_ surface: HarnessWebViewController, didFailWith message: String) {
        mainWindow.updateStatus("Display error", color: .systemRed)
    }

    func performanceSessionID(for surface: HarnessWebViewController) -> HarnessSessionID? {
        guard let profile = try? modelSettingsStore.loadOrMigrate()
            .settings.defaultSelection.performanceProfile else { return nil }
        return PerformanceSessionIdentity.make(profile: profile)
    }

    func approvedWorkspacePath(for surface: HarnessWebViewController) -> String? {
        controller.workspaceDirectory()
            .resolvingSymlinksInPath()
            .standardizedFileURL.path
    }

    func webSurface(
        _ surface: HarnessWebViewController,
        prepareTurnIn sessionID: HarnessSessionID,
        operationID: UUID,
        completion: @escaping (Result<TurnPreparationBridgeResult, Error>) -> Void
    ) {
        switch browserTurnPreparationAdmission.admit(operationID) {
        case .duplicateOperation:
            completion(.failure(TurnPreparationError.duplicateOperation))
            return
        case .atCapacity:
            completion(.failure(TurnPreparationError.capacityExceeded))
            return
        case .accepted:
            break
        }
        guard !thermalSafetyBlocksSelectedLocalRuntime else {
            browserTurnPreparationAdmission.release(operationID)
            completion(.failure(currentLocalRuntimeAdmissionError))
            return
        }
        let generation = runtimeGeneration
        let cancellation = WorkspaceJournalOperationCancellation()
        let task = Task { [weak self] in
            guard let self else { return }
            let finish: @MainActor (Result<TurnPreparationBridgeResult, Error>) -> Void = { result in
                if self.activeBrowserTurnPreparations[operationID]?.cancellation === cancellation {
                    self.activeBrowserTurnPreparations.removeValue(forKey: operationID)
                    self.browserTurnPreparationAdmission.release(operationID)
                }
                completion(result)
            }
            do {
                try Task.checkCancellation()
                async let listRequest = self.rpcClient.listSessions(cursor: nil)
                async let modelRequest = self.rpcClient.sessionModels(sessionID)
                let (list, models) = try await (listRequest, modelRequest)
                try Task.checkCancellation()
                let expected = try self.modelSettingsStore.loadOrMigrate().settings.defaultSelection
                let expectedWorkspace = self.controller.workspaceDirectory()
                    .resolvingSymlinksInPath().standardizedFileURL.path
                guard generation == self.runtimeGeneration,
                      let summary = list.items.first(where: { $0.sessionId == sessionID }),
                      summary.parentSessionId == nil,
                      summary.origin != "subagent",
                      summary.cwd.map({ URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path }) == expectedWorkspace,
                      models.routable,
                      models.current.route == expected.route,
                      let coordinator = self.workspaceRecoveryCoordinator else {
                    throw TurnPreparationError.authoritativeStateMismatch
                }
                let protection = try await coordinator.captureBeforeTurn(
                    reason: "Before main Harness turn",
                    cancellation: cancellation
                )
                try Task.checkCancellation()
                guard generation == self.runtimeGeneration else {
                    throw TurnPreparationError.runtimeChanged
                }
                await MainActor.run {
                    self.recoveryWindow?.refresh()
                    switch protection {
                    case .checkpoint(_, let reused):
                        if !self.presentThermalStatusInsteadOfReadyIfNeeded() {
                            self.mainWindow.updateStatus(
                                reused ? "Ready · Recovery point reused" : "Ready · Recovery protected",
                                color: .systemGreen
                            )
                        }
                        finish(.success(TurnPreparationBridgeResult(
                            mode: .protected,
                            message: reused ? "An unchanged recovery point was reused." : nil
                        )))
                    case .readOnly(let reason):
                        self.mainWindow.updateStatus("Read-only · Workspace safety", color: .systemOrange)
                        self.activityStore.addCompleted(
                            .backup,
                            title: "Read-only agent turn",
                            detail: reason.userMessage
                        )
                        finish(.success(TurnPreparationBridgeResult(
                            mode: .readOnly,
                            message: reason.userMessage
                        )))
                    }
                }
            } catch {
                await MainActor.run {
                    if (error as? WorkspaceJournalError) == .cancelled {
                        if !self.presentThermalStatusInsteadOfReadyIfNeeded() {
                            self.mainWindow.updateStatus("Ready · Prompt cancelled", color: .secondaryLabelColor)
                        }
                    } else {
                        self.mainWindow.updateStatus("Recovery blocked · No prompt sent", color: .systemRed)
                        self.activityStore.addCompleted(
                            .backup,
                            title: "Agent turn blocked safely",
                            detail: error.localizedDescription
                        )
                    }
                    finish(.failure(error))
                }
            }
        }
        activeBrowserTurnPreparations[operationID] = ActiveBrowserTurnPreparation(
            cancellation: cancellation,
            task: task
        )
    }

    func webSurface(
        _ surface: HarnessWebViewController,
        cancelTurnPreparation operationID: UUID
    ) {
        guard let active = activeBrowserTurnPreparations[operationID] else { return }
        active.cancellation.cancel()
        active.task.cancel()
    }

    func webSurface(
        _ surface: HarnessWebViewController,
        validateFreshSession sessionID: HarnessSessionID,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        Task { [weak self] in
            guard let self else { return }
            do {
                async let listRequest = self.rpcClient.listSessions(cursor: nil)
                async let modelRequest = self.rpcClient.sessionModels(sessionID)
                let (list, models) = try await (listRequest, modelRequest)
                let expected = try self.modelSettingsStore.loadOrMigrate().settings.defaultSelection
                let expectedWorkspace = self.controller.workspaceDirectory()
                    .resolvingSymlinksInPath().standardizedFileURL.path
                guard let summary = list.items.first(where: { $0.sessionId == sessionID }),
                      summary.blank,
                      summary.parentSessionId == nil,
                      summary.origin != "subagent",
                      PerformanceSessionIdentity.profile(from: sessionID) == expected.performanceProfile,
                      summary.cwd.map({ URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path }) == expectedWorkspace,
                      models.routable,
                      models.current.route == expected.route else {
                    throw FreshSessionValidationError.authoritativeStateMismatch
                }
                await MainActor.run { completion(.success(())) }
            } catch {
                await MainActor.run { completion(.failure(error)) }
            }
        }
    }
}

enum ProviderTopologyVerificationStage: String, Sendable {
    case loadSelection = "Loading the saved model selection"
    case resolveOwnedOllamaEndpoint = "Resolving the app-owned Ollama endpoint"
    case validateLocalRuntimeVersion = "Checking the Ollama version"
    case inspectInstalledLocalModels = "Checking installed Ollama models"
    case synchronizeLocalProvider = "Synchronizing the Ollama provider profile"
    case loadProviderCatalog = "Loading the Harness provider catalogue"
    case validateSelectedRoute = "Validating the selected provider and model"
    case validateOnDeviceBoundary = "Validating the private on-device boundary"
    case synchronizeLocalPerformance = "Synchronizing local context and output limits"
    case reloadLocalProviderCatalog = "Revalidating the local provider catalogue"
    case recordEndpointConsent = "Recording the verified on-device endpoint"
    case validateExternalConsent = "Validating external-provider consent"
    case synchronizeDefaultRoute = "Synchronizing the default Harness route"

    /// A failure at one of these stages means the configured on-device route
    /// can be repaired by choosing another already-installed Ollama model.
    /// Consent and cloud-provider failures must never expose that shortcut.
    var allowsInstalledLocalModelChoice: Bool {
        switch self {
        case .resolveOwnedOllamaEndpoint,
             .inspectInstalledLocalModels,
             .synchronizeLocalProvider,
             .validateSelectedRoute,
             .synchronizeLocalPerformance,
             .reloadLocalProviderCatalog:
            return true
        case .loadSelection,
             .validateLocalRuntimeVersion,
             .loadProviderCatalog,
             .validateOnDeviceBoundary,
             .recordEndpointConsent,
             .validateExternalConsent,
             .synchronizeDefaultRoute:
            return false
        }
    }
}

struct ProviderTopologyVerificationFailure: LocalizedError, Sendable {
    let stage: ProviderTopologyVerificationStage
    let reason: String
    let allowsInstalledLocalModelChoice: Bool

    var errorDescription: String? {
        "\(stage.rawValue) failed: \(reason)"
    }
}

/// Provider verification diagnostics are displayed to the user and retained in
/// local activity history. Only closed, typed error descriptions may cross this
/// boundary; remote payloads and local-service message bodies are deliberately
/// reduced to non-sensitive summaries.
private func providerTopologyFailureReason(_ error: Error) -> String {
    let message: String
    switch error {
    case let failure as ProviderTopologyVerificationFailure:
        message = failure.localizedDescription
    case let validation as RuntimeTopologyValidationError:
        message = validation.localizedDescription
    case let settings as ModelProviderSettingsStoreError:
        message = settings.localizedDescription
    case let selection as ModelSelectionCoordinatorError:
        message = selection.localizedDescription
    case let consent as ProviderConsentStoreError:
        message = consent.localizedDescription
    case let rpc as HarnessRPCClientError:
        if case .remote = rpc {
            message = "DeepSeek Harness rejected the provider operation."
        } else {
            message = rpc.localizedDescription
        }
    case let ollama as OllamaError:
        if case .server = ollama {
            message = "The app-owned Ollama service rejected the request."
        } else {
            message = ollama.localizedDescription
        }
    case let version as OllamaVersionCompatibilityError:
        message = version.localizedDescription
    default:
        message = "The provider operation returned an unexpected \(String(reflecting: type(of: error))) error."
    }

    let flattened = message.unicodeScalars.map { scalar -> Character in
        CharacterSet.controlCharacters.contains(scalar) ? " " : Character(String(scalar))
    }
    return String(String(flattened).split(whereSeparator: \.isWhitespace).joined(separator: " ").prefix(512))
}

private enum RuntimeTopologyValidationError: LocalizedError {
    case providerUnavailable(ProviderID)
    case modelUnavailable(ModelID)
    case endpointUnavailable
    case boundaryMismatch
    case consentRequired(boundary: DataBoundary, origin: ProviderEndpointOrigin?)
    case runtimeChanged
    case readinessTimedOut
    case providerProfileChanged

    var errorDescription: String? {
        switch self {
        case .providerUnavailable(let provider):
            return "Harness did not report \(provider.rawValue) as a ready provider."
        case .modelUnavailable(let model):
            return "Harness did not report the selected model \(model.rawValue) on the active provider."
        case .endpointUnavailable:
            return "The active provider did not expose a safe, normalized HTTP(S) endpoint."
        case .boundaryMismatch:
            return "An endpoint classified as on-device was not actually bound to this Mac's loopback interface."
        case .consentRequired(let boundary, let origin):
            let destination = origin?.displayName ?? "an unresolved endpoint"
            return "The \(boundary.displayName.lowercased()) endpoint \(destination) does not match the active consent. Choose the provider again in Models & Providers."
        case .runtimeChanged:
            return "The authenticated Harness runtime changed before verification could be committed."
        case .readinessTimedOut:
            return "Harness did not become ready before the bounded startup deadline."
        case .providerProfileChanged:
            return "The active custom provider profile changed and requires a fresh exact-origin consent and runtime."
        }
    }
}

private enum FreshSessionValidationError: LocalizedError {
    case authoritativeStateMismatch

    var errorDescription: String? {
        "Harness did not confirm an empty top-level session in the approved Workspace using the selected provider/model route."
    }
}

private enum TurnPreparationError: LocalizedError {
    case authoritativeStateMismatch
    case runtimeChanged
    case duplicateOperation
    case capacityExceeded

    var errorDescription: String? {
        switch self {
        case .authoritativeStateMismatch:
            return "Harness did not confirm a top-level task in the approved Workspace using the selected provider/model route."
        case .runtimeChanged:
            return "The private runtime changed while the recovery point was being created."
        case .duplicateOperation:
            return "Harness repeated a workspace recovery operation identity. The prompt was blocked."
        case .capacityExceeded:
            return "Too many workspace recovery preparations are already active. The additional prompt was blocked."
        }
    }
}
