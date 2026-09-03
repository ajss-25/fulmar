import Foundation
import Darwin
import LocalHarnessApplicationSupportAdmission
import LocalHarnessSandboxPolicy
import LocalHarnessDeviceAttestation

enum SandboxBoundaryProbeProcessError: Error, Equatable {
    case resourceLimit
}

enum SandboxBoundaryProbeProcess {
    static func run(
        executable: URL,
        arguments: [String],
        currentDirectory: URL,
        environment: [String: String],
        deadline: TimeInterval = 5,
        terminationGrace: TimeInterval = 0.25,
        onSpawn: ((pid_t) -> Void)? = nil
    ) throws -> Int32 {
        let result = try BoundedProcessGroupRunner.run(
            executable: executable,
            arguments: arguments,
            environment: environment,
            maximumStderrBytes: 64 * 1_024,
            deadline: deadline,
            terminationGrace: terminationGrace,
            currentDirectory: currentDirectory,
            discardStandardOutput: true,
            onSpawn: onSpawn
        )
        guard result.limit == nil else { throw SandboxBoundaryProbeProcessError.resourceLimit }
        if let status = result.exitStatus { return status }
        if let signal = result.terminationSignal { return 128 + signal }
        throw SandboxBoundaryProbeProcessError.resourceLimit
    }
}

/// Resolves the executable runtime without consulting ambient package-manager
/// state in a production application bundle.  This keeps a hostile or stalled
/// `~/.nvm` tree off the synchronous launch path and makes the pinned runtime
/// an invariant rather than merely the first candidate in a fallback list.
enum HarnessRuntimeLocator {
    struct Location: Equatable {
        let node: URL
        let script: URL
        let dshVersion: String
        let bundled: Bool
    }

    private static let expectedPackageName = "@deepseek-ai/dsh"
    private static let maximumPackageBytes = 64 * 1_024

    static func locate(
        bundleURL: URL,
        resources: URL?,
        home: URL,
        fileManager: FileManager = .default,
        ambientDirectoryReader: ((URL) throws -> [URL])? = nil
    ) throws -> Location {
        if bundleURL.pathExtension.lowercased() == "app" {
            guard let resources else { throw LocalHarnessError.harnessNotFound }
            let expectedBundledVersion = try ProductBrand.reviewedDSHVersion(resources: resources)
            return try validatedLocation(
                node: resources.appendingPathComponent("Runtime/node"),
                script: resources.appendingPathComponent("Runtime/dsh/lib/bin.js"),
                bundled: true,
                requiredVersion: expectedBundledVersion,
                fileManager: fileManager
            )
        }

        var candidates: [(node: URL, script: URL, bundled: Bool)] = []
        if let resources {
            candidates.append((
                resources.appendingPathComponent("Runtime/node"),
                resources.appendingPathComponent("Runtime/dsh/lib/bin.js"),
                true
            ))
        }

        let nvmRoot = home.appendingPathComponent(".nvm/versions/node", isDirectory: true)
        let readAmbient = ambientDirectoryReader ?? { directory in
            try fileManager.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
        }
        if let versions = try? readAmbient(nvmRoot) {
            for version in versions.sorted(by: { $0.lastPathComponent > $1.lastPathComponent }) {
                candidates.append((
                    version.appendingPathComponent("bin/node"),
                    version.appendingPathComponent("lib/node_modules/@deepseek-ai/dsh/lib/bin.js"),
                    false
                ))
            }
        }
        for prefix in ["/opt/homebrew", "/usr/local"] {
            candidates.append((
                URL(fileURLWithPath: "\(prefix)/bin/node"),
                URL(fileURLWithPath: "\(prefix)/lib/node_modules/@deepseek-ai/dsh/lib/bin.js"),
                false
            ))
        }

        for candidate in candidates {
            if let location = try? validatedLocation(
                node: candidate.node,
                script: candidate.script,
                bundled: candidate.bundled,
                requiredVersion: nil,
                fileManager: fileManager
            ) {
                return location
            }
        }
        throw LocalHarnessError.harnessNotFound
    }

    private static func validatedLocation(
        node: URL,
        script: URL,
        bundled: Bool,
        requiredVersion: String?,
        fileManager: FileManager
    ) throws -> Location {
        guard fileManager.isExecutableFile(atPath: node.path),
              fileManager.fileExists(atPath: script.path) else {
            throw LocalHarnessError.harnessNotFound
        }
        let packageURL = script.deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("package.json")
        let data = try SecureAttachmentReader.readRegularFile(
            at: packageURL,
            maximumBytes: maximumPackageBytes
        )
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["name"] as? String == expectedPackageName,
              let version = object["version"] as? String,
              !version.isEmpty,
              version.utf8.count <= 64,
              requiredVersion.map({ $0 == version }) ?? true else {
            throw LocalHarnessError.harnessNotFound
        }
        return Location(node: node, script: script, dshVersion: version, bundled: bundled)
    }
}

/// Polls an owned `Process` on a private serial queue so a busy AppKit main
/// queue cannot prevent TERM/KILL escalation.  Completion is marshalled back
/// to the main queue because callers mutate controller state there.
private final class OwnedProcessStopMonitor {
    private let process: Process
    private let pid: Int32
    private let forceKillAfter: TimeInterval
    private let failAfter: TimeInterval
    private let completion: (Result<Void, Error>) -> Void
    private let queue: DispatchQueue
    private let startedAt = DispatchTime.now().uptimeNanoseconds
    private var forceKillIssuedAt: UInt64?
    private var timer: DispatchSourceTimer?
    private var finished = false

    init(
        process: Process,
        forceKillAfter: TimeInterval,
        failAfter: TimeInterval,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        self.process = process
        pid = process.processIdentifier
        self.forceKillAfter = max(0, forceKillAfter)
        self.failAfter = max(failAfter, self.forceKillAfter + 0.25)
        self.completion = completion
        queue = DispatchQueue(label: "app.localharness.owned-process-stop.\(pid)", qos: .userInitiated)
    }

    func start() {
        // A child can exit in the short interval between capture on the main
        // queue and this monitor starting. Never send TERM through a stale
        // `Process` state in that case; the first poll will complete normally.
        if process.isRunning { process.terminate() }
        queue.async { self.installTimer() }
    }

    private func installTimer() {
        guard process.isRunning else {
            finish(.success(()))
            return
        }
        let source = DispatchSource.makeTimerSource(queue: queue)
        timer = source
        // The strong capture deliberately keeps this one-shot monitor alive;
        // `finish` cancels and releases the source to break the cycle.
        source.setEventHandler { self.poll() }
        source.schedule(deadline: .now() + .milliseconds(25), repeating: .milliseconds(25), leeway: .milliseconds(5))
        source.resume()
    }

    private func poll() {
        guard !finished else { return }
        guard process.isRunning else {
            finish(.success(()))
            return
        }

        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = Double(now - startedAt) / 1_000_000_000
        if forceKillIssuedAt == nil, elapsed >= forceKillAfter {
            // The PID is taken only from the still-running Process captured by
            // the caller. Never discover or terminate processes by name/port.
            _ = Darwin.kill(pid, SIGKILL)
            forceKillIssuedAt = now
            return
        }

        // Even if the queue was delayed beyond the nominal deadline, always
        // give a just-issued SIGKILL one poll window to be observed/reaped.
        let killGraceElapsed = forceKillIssuedAt.map { now - $0 >= 250_000_000 } ?? false
        if elapsed >= failAfter, killGraceElapsed {
            if process.isRunning {
                finish(.failure(LocalHarnessError.serviceShutdownTimedOut([pid])))
            } else {
                finish(.success(()))
            }
        }
    }

    private func finish(_ result: Result<Void, Error>) {
        guard !finished else { return }
        finished = true
        timer?.cancel()
        timer = nil
        DispatchQueue.main.async { [completion] in completion(result) }
    }
}

/// One controller-owned shutdown generation. It retains the exact `Process`
/// objects captured at the stop boundary until every one has been reaped, and
/// coalesces all stop/restart callers onto that single barrier.
private final class OwnedServicesStopGeneration {
    typealias Completion = (Result<Void, Error>) -> Void

    let identifier: UInt64
    let harnessProcess: Process?
    let ollamaProcess: Process?
    let startupPrerequisite: RuntimeStartupPrerequisiteCancellation?
    let processes: [Process]
    var pendingProcesses: Set<ObjectIdentifier>
    var startupPrerequisiteSettled: Bool
    var failedPIDs = Set<Int32>()
    var completions: [Completion]
    var restartRequested: Bool

    init(
        identifier: UInt64,
        harnessProcess: Process?,
        ollamaProcess: Process?,
        startupPrerequisite: RuntimeStartupPrerequisiteCancellation?,
        restartRequested: Bool,
        completion: @escaping Completion
    ) {
        self.identifier = identifier
        self.harnessProcess = harnessProcess
        self.ollamaProcess = ollamaProcess
        self.startupPrerequisite = startupPrerequisite
        startupPrerequisiteSettled = startupPrerequisite?.isSettled ?? true
        self.restartRequested = restartRequested
        completions = [completion]

        var seen = Set<ObjectIdentifier>()
        var unique: [Process] = []
        for process in [harnessProcess, ollamaProcess].compactMap({ $0 }) {
            let identity = ObjectIdentifier(process)
            guard seen.insert(identity).inserted else { continue }
            unique.append(process)
        }
        processes = unique
        pendingProcesses = Set(unique.filter(\.isRunning).map(ObjectIdentifier.init))
    }

    func captures(_ process: Process) -> Bool {
        processes.contains { $0 === process }
    }
}

/// A bounded, content-free reason why the selected on-device provider could
/// not be prepared. These failures may open the authenticated provider repair
/// control plane because that runtime has no provider egress, sessions,
/// skills, or MCP activation. Failures in the app bundle, Harness runtime,
/// security preloader, inventory, or tool sandbox are deliberately never
/// converted into this type and therefore remain terminal.
enum OllamaPrerequisiteRecoveryIssue: Error, Equatable, LocalizedError {
    case insufficientPhysicalMemory(requiredBytes: UInt64, availableBytes: UInt64)
    case notInstalled
    case untrustedInstallation
    case installationChanged
    case unsafeModelStore
    case unsafeRuntimeDirectory
    case privatePortUnavailable
    case launchFailed
    case readinessTimedOut
    case ownershipVerificationFailed

    var errorDescription: String? {
        switch self {
        case .insufficientPhysicalMemory(let requiredBytes, let availableBytes):
            let requiredGiB = requiredBytes / 1_073_741_824
            let availableGiB = availableBytes / 1_073_741_824
            return "The release-qualified local model requires at least \(requiredGiB) GiB of physical memory; this Mac reports \(availableGiB) GiB."
        case .notInstalled:
            return "The official Ollama app is not installed."
        case .untrustedInstallation:
            return "The installed Ollama executable could not be verified as the official signed app."
        case .installationChanged:
            return "The Ollama installation changed while its private runtime was starting."
        case .unsafeModelStore:
            return "The local Ollama model store did not pass its private, read-only safety checks."
        case .unsafeRuntimeDirectory:
            return "The private Ollama runtime directory could not be secured."
        case .privatePortUnavailable:
            return "A private loopback port could not be reserved for Ollama."
        case .launchFailed:
            return "The isolated Ollama process could not be launched."
        case .readinessTimedOut:
            return "The isolated Ollama process did not become ready in time."
        case .ownershipVerificationFailed:
            return "The private Ollama listener could not be verified as belonging to the process started by \(ProductBrand.displayName)."
        }
    }

    /// Wraps errors only at the exact Ollama launch boundary. This is what
    /// prevents an unrelated integrity or Harness startup error from being
    /// misclassified as recoverable merely because it has similar prose.
    static func launchBoundary(_ error: Error) -> OllamaPrerequisiteRecoveryIssue {
        if let issue = error as? OllamaPrerequisiteRecoveryIssue { return issue }
        if let security = error as? OllamaRuntimeSecurityError {
            switch security {
            case .executableNotFound: return .notInstalled
            case .executableUntrusted: return .untrustedInstallation
            case .executableChanged: return .installationChanged
            case .unsafeModelStore: return .unsafeModelStore
            case .unsafePrivateDirectory: return .unsafeRuntimeDirectory
            }
        }
        if error is AppOwnedOllamaEndpointError { return .privatePortUnavailable }
        return .launchFailed
    }

    /// Converts only the exact qualified-model host-admission failure. No
    /// generic startup, bundle-integrity, or runtime error may enter provider
    /// recovery through this boundary.
    static func hostAdmissionBoundary(
        _ error: QualifiedLocalModelHostAdmissionError
    ) -> OllamaPrerequisiteRecoveryIssue {
        switch error {
        case .insufficientPhysicalMemory(let requiredBytes, let availableBytes):
            return .insufficientPhysicalMemory(
                requiredBytes: requiredBytes,
                availableBytes: availableBytes
            )
        }
    }
}

private enum RuntimeBundleIntegrityError: Error, LocalizedError {
    case verificationFailed

    var errorDescription: String? {
        "The signed application bundle failed integrity verification."
    }
}

private enum OwnedOllamaPreparation: Sendable {
    case existing(OllamaExecutableIdentity)
    case launch(AppOwnedOllamaLaunchPlan, lease: RuntimeLaunchPathIdentity)
}

private struct RuntimeLaunchPathIdentity: Sendable {
    enum Kind: Equatable, Sendable { case regular, directory }

    let url: URL
    let kind: Kind
    let device: UInt64
    let inode: UInt64
    let owner: UInt32
    let permissions: UInt16
    let byteCount: Int64
    let modifiedSeconds: Int64
    let modifiedNanoseconds: Int64

    static func capture(_ url: URL, kind: Kind) throws -> RuntimeLaunchPathIdentity {
        var metadata = stat()
        let expectedType: mode_t = kind == .regular ? S_IFREG : S_IFDIR
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == expectedType,
              metadata.st_uid == 0 || metadata.st_uid == geteuid(),
              metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              kind != .regular || metadata.st_nlink == 1 else {
            throw LocalHarnessError.runtimeIntegrityChanged
        }
        return RuntimeLaunchPathIdentity(
            url: url,
            kind: kind,
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino),
            owner: metadata.st_uid,
            permissions: UInt16(metadata.st_mode & 0o7777),
            byteCount: metadata.st_size,
            modifiedSeconds: Int64(metadata.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(metadata.st_mtimespec.tv_nsec)
        )
    }

    func revalidate() throws {
        let current = try Self.capture(url, kind: kind)
        guard current.device == device,
              current.inode == inode,
              current.owner == owner,
              current.permissions == permissions,
              current.byteCount == byteCount,
              current.modifiedSeconds == modifiedSeconds,
              current.modifiedNanoseconds == modifiedNanoseconds else {
            throw LocalHarnessError.runtimeIntegrityChanged
        }
    }
}

private struct RequiredOwnedOllamaSnapshot: Sendable {
    let endpoint: AppOwnedOllamaEndpoint
    let processIdentifier: Int32
    let executableIdentity: OllamaExecutableIdentity
    let modelConfiguration: AppOwnedOllamaModelConfiguration
}

private struct PreparedHarnessLaunch: @unchecked Sendable {
    let executable: URL
    let arguments: [String]
    let runtimeWriteSandbox: HarnessRuntimeWriteSandbox
    let currentDirectory: URL
    let environment: [String: String]
    let authenticationInput: RuntimeAuthenticationInput
    let authToken: String
    let nonce: String
    let strictLocal: Bool
    let telemetryUnavailable: Bool
    let pathIdentities: [RuntimeLaunchPathIdentity]
    let requiredOllama: RequiredOwnedOllamaSnapshot?
    let skillStore: SkillsTrustStore
    let mcpStore: MCPTrustStore?
    let harnessHomeCapability: HarnessHomeAttestationCapability
}

enum AutomaticRuntimeRestartDecision: Equatable, Sendable {
    case retry(after: TimeInterval)
    case exhausted
}

/// Bounds crash recovery independently from launch/readiness retries. A local
/// service that repeatedly reaches readiness and then exits must not churn
/// processes, memory, and heat indefinitely.
struct BoundedRuntimeRestartCircuit: Equatable, Sendable {
    static let productionWindow: TimeInterval = 60
    static let productionDelays: [TimeInterval] = [1.2, 3, 8]

    private(set) var failures: [Date] = []
    let window: TimeInterval
    let delays: [TimeInterval]

    init(
        window: TimeInterval = Self.productionWindow,
        delays: [TimeInterval] = Self.productionDelays
    ) {
        precondition(window > 0 && !delays.isEmpty && delays.allSatisfy { $0 >= 0 })
        self.window = window
        self.delays = delays
    }

    mutating func recordFailure(at now: Date) -> AutomaticRuntimeRestartDecision {
        // A failure is consecutive until the replacement runtime has remained
        // genuinely ready for a complete stability window. Pruning failures by
        // wall-clock age here lets a service that crashes every 20-40 seconds
        // restart forever without ever proving stability.
        guard failures.count < delays.count else { return .exhausted }
        let delay = delays[failures.count]
        failures.append(now)
        return .retry(after: delay)
    }

    mutating func resetAfterStableReadiness(startedAt: Date, now: Date) {
        guard now.timeIntervalSince(startedAt) >= window else { return }
        failures.removeAll(keepingCapacity: true)
    }
}

/// Invalidates a delayed automatic restart without broad process discovery.
/// Quit, thermal shutdown, provider changes, and explicit Stop all advance this
/// token before their exact child barrier begins.
struct AutomaticRuntimeRestartGate: Equatable, Sendable {
    private(set) var generation: UInt64 = 0

    mutating func begin() -> UInt64 {
        generation &+= 1
        return generation
    }

    mutating func cancel() { generation &+= 1 }

    func admits(_ token: UInt64) -> Bool { generation == token }
}

/// A single lock-backed publication point for every cross-queue consumer of
/// the signed Harness-home capability.  The generation changes whenever the
/// capability or either purge-admission fact changes, so a worker never reads
/// a capability concurrently with a recovery/runtime transition.
private final class HarnessHomeAdmissionVault: @unchecked Sendable {
    struct Snapshot {
        let generation: UInt64
        let capability: HarnessHomeAttestationCapability?
        let ownsHarness: Bool
        let recoveryInFlight: Bool
    }

    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var capability: HarnessHomeAttestationCapability?
    private var ownsHarness = false
    private var recoveryInFlight = false

    func snapshot() -> Snapshot {
        lock.withLock {
            Snapshot(
                generation: generation,
                capability: capability,
                ownsHarness: ownsHarness,
                recoveryInFlight: recoveryInFlight
            )
        }
    }

    @discardableResult
    func replaceCapability(_ value: HarnessHomeAttestationCapability?) -> UInt64 {
        lock.withLock {
            generation &+= 1
            capability = value
            return generation
        }
    }

    func setOwnsHarness(_ value: Bool) {
        lock.withLock {
            generation &+= 1
            ownsHarness = value
        }
    }

    func setRecoveryInFlight(_ value: Bool) {
        lock.withLock {
            generation &+= 1
            recoveryInFlight = value
        }
    }
}

final class HarnessController {
    /// Starting the signed, sandboxed Ollama service can take over thirty
    /// seconds while macOS is reclaiming GPU/model resources from a prior
    /// process. Waiting is cheap and cancellable; failing early forces a full
    /// restart and produces a worse thermal/user experience.
    static let ownedOllamaReadinessTimeout: TimeInterval = 90
    private enum LaunchMode: Equatable {
        case inference
        case providerRecovery
    }

    enum State: Equatable {
        case checking
        case startingOllama
        case startingHarness
        case ready(managedByApp: Bool)
        case providerRecovery
        case stopped
        case failed(String)

        var summary: String {
            switch self {
            case .checking: return "Checking local services"
            case .startingOllama: return "Starting Ollama"
            case .startingHarness: return "Starting secure Harness"
            case .ready: return PreferencesStore.shared.strictLocalMode ? "Ready · On this Mac" : "Ready · Connected runtime"
            case .providerRecovery: return "Provider recovery · Agent work blocked"
            case .stopped: return "Stopped"
            case .failed: return "Needs attention"
            }
        }
    }

    /// Binds every asynchronously delivered controller state to the exact
    /// publication generation that produced it. A protected App transition
    /// suspends this gate before its first await; queued or subsequently
    /// produced events from the old runtime then remain inert until an actual
    /// replacement startup begins a fresh generation.
    final class StatePublicationGate {
        typealias Dispatcher = (@escaping () -> Void) -> Void

        private var generation: UInt64 = 0
        private var suspended = false

        func beginGeneration() {
            generation &+= 1
            suspended = false
        }

        func suspend() {
            generation &+= 1
            suspended = true
        }

        func enqueue(
            state: State,
            currentState: @escaping () -> State?,
            dispatcher: @escaping Dispatcher = { action in
                DispatchQueue.main.async(execute: action)
            },
            delivery: @escaping (State) -> Void
        ) {
            let capturedGeneration = generation
            dispatcher { [weak self] in
                guard let self,
                      !self.suspended,
                      self.generation == capturedGeneration,
                      currentState() == state else { return }
                delivery(state)
            }
        }
    }

    struct RuntimeInfo {
        let node: URL
        let script: URL
        let dshVersion: String
        let bundled: Bool
    }

    /// Internal deterministic seam used by the release tests. Production uses
    /// the exact PID-bound monitor and the normal secure startup path.
    struct LifecycleTestConfiguration {
        let harnessProcess: Process?
        let ollamaProcess: Process?
        let initialState: State
        let stopProcess: (Process, @escaping (Result<Void, Error>) -> Void) -> Void
        let startReplacement: () -> Void
        /// Test-only terminal for the otherwise real recovery transition. It
        /// lets the state-machine suite stop before launching the bundled DSH
        /// process while exercising the same production decision point.
        var startOllamaPrerequisiteRecovery: ((OllamaPrerequisiteRecoveryIssue) -> Void)? = nil
        /// Exact in-flight prerequisite token used only to exercise the public
        /// stop barrier without launching the production runtime in tests.
        var startupPrerequisiteCancellation: RuntimeStartupPrerequisiteCancellation? = nil
        /// Pauses or observes exact worker phases in deterministic lifecycle
        /// tests. Production never supplies this closure.
        var startupPrerequisitePhaseHook: ((RuntimeStartupPrerequisitePhase, RuntimeStartupPrerequisiteCancellation) throws -> Void)? = nil
        /// Deterministic, test-only inputs for the signed-bundle and host
        /// admission phases. Production never supplies either override.
        var bundleIntegrityVerification: (() throws -> Bool)? = nil
        var physicalMemoryBytes: UInt64? = nil
        var modelSettingsStore: ModelProviderSettingsStore? = nil
        /// Test-only deterministic recovery key. Production always uses the
        /// app-owned Keychain helper after an explicit recovery action.
        var harnessHomeRecoveryAuthenticationKey: Data? = nil
        /// Process-local authority store for deterministic tests. Production
        /// always uses the shared noninteractive device-attestation Keychain.
        var deviceAttestationKeyStore: (any DeviceAttestationKeyStore)? = nil
    }

    var onStateChange: ((State) -> Void)?
    var onEndpointChange: ((HarnessEndpoint?) -> Void)?
    var onHarnessHomeRecoveryPending: ((HarnessHomeRecoveryPendingState) -> Void)?
    var onDeviceAttestationTrustRecoveryRequired: ((DeviceAttestationTrustRecoveryRequest) -> Void)?
    /// Compatibility seam for initial receiptless-home tests and callers. New
    /// lifecycle code must consume `onHarnessHomeRecoveryPending` so interrupted,
    /// published, and blocked states cannot be collapsed into an initial prompt.
    var onHarnessHomeRecoveryRequired: ((HarnessHomeReceiptlessRecoveryRequest) -> Void)?
    private(set) var currentState: State = .stopped
    private(set) var endpoint: HarnessEndpoint?
    private let harnessHomeAdmissionVault = HarnessHomeAdmissionVault()
    var ownsHarness: Bool { harnessHomeAdmissionVault.snapshot().ownsHarness }
    private(set) var ownsOllama = false
    private(set) var ollamaEndpoint: AppOwnedOllamaEndpoint?
    private var ollamaExecutableIdentity: OllamaExecutableIdentity?
    private var ollamaModelConfiguration: AppOwnedOllamaModelConfiguration?
    private(set) var ollamaPrerequisiteRecoveryIssue: OllamaPrerequisiteRecoveryIssue?

    var verifiedOllamaExecutableIdentity: OllamaExecutableIdentity? {
        guard let process = ollamaProcess,
              let endpoint = ollamaEndpoint,
              verifiedOwnedOllama(process: process, endpoint: endpoint) else { return nil }
        return ollamaExecutableIdentity
    }

    var harnessURL: URL? { endpoint?.baseURL }
    var ollamaBaseURL: URL? {
        guard let process = ollamaProcess,
              let endpoint = ollamaEndpoint,
              verifiedOwnedOllama(process: process, endpoint: endpoint) else { return nil }
        return endpoint.baseURL
    }
    var ollamaProviderBaseURL: URL? {
        guard let process = ollamaProcess,
              let endpoint = ollamaEndpoint,
              verifiedOwnedOllama(process: process, endpoint: endpoint) else { return nil }
        return endpoint.providerBaseURL
    }

    private let fileManager = FileManager.default
    private let applicationSupportOverride: URL?
    private let applicationSupportRootAdmission: ApplicationSupportRootAdmission
    private let modelStoreOverride: URL?
    private let forbidCredentialHelper: Bool
    private let preferences = PreferencesStore.shared
    private let modelSettingsStore: ModelProviderSettingsStore
    private let providerConsentStore = ProviderConsentStore()
    private lazy var logStore = ServiceLogStore(directory: diagnosticsDirectory())
    private lazy var homeManager = HarnessHomeManager(
        root: harnessHomeDirectory(),
        recoveryAuthenticationKey: lifecycleHarnessHomeRecoveryAuthenticationKey
    )
    private lazy var pluginTrustStore = PluginTrustStore(
        applicationSupport: diagnosticsDirectory(),
        profileRoot: harnessHomeDirectory().appendingPathComponent("profiles", isDirectory: true)
    )
    private var skillsTrustStoreInstance: SkillsTrustStore?
    private var mcpTrustStoreInstance: MCPTrustStore?
    private var preparedSkillBoundary: SkillExecutionBoundary?
    private var oneTimeSkillCloudApprovals = Set<String>()
    private let outputParsingQueue = DispatchQueue(label: "app.localharness.runtime-output")
    private var stdoutBuffer = ""
    private var harnessProcess: Process?
    private var ollamaProcess: Process?
    private var isStarting = false
    private var isStartingOllamaOnly = false
    private var ollamaOnlyStartCompletions: [(Result<Void, Error>) -> Void] = []
    private var intentionalStop = false
    private var harnessRestartCircuit = BoundedRuntimeRestartCircuit()
    private var harnessAutomaticRestartGate = AutomaticRuntimeRestartGate()
    private var harnessStableReadinessBeganAt: Date?
    private var ollamaRestartCircuit = BoundedRuntimeRestartCircuit()
    private var ollamaAutomaticRestartGate = AutomaticRuntimeRestartGate()
    private var ollamaStableReadinessBeganAt: Date?
    private var startupGeneration: UInt64 = 0
    private let startupPrerequisiteWorker = RuntimeStartupPrerequisiteWorker()
    private var startupPrerequisiteCancellation: RuntimeStartupPrerequisiteCancellation?
    private var nextStopGeneration: UInt64 = 0
    private var stopGeneration: OwnedServicesStopGeneration?
    private var terminalShutdownRequested = false
    private var activeLaunchMode: LaunchMode = .inference
    /// Exact latest-wins replacement intent for the one active stop barrier.
    /// A provider-recovery request must never be silently widened to inference
    /// merely because it arrived while an older runtime was still draining.
    private var pendingRestartLaunchMode: LaunchMode = .inference
    private var pendingOllamaPrerequisiteRecoveryIssue: OllamaPrerequisiteRecoveryIssue?
    private(set) var pendingHarnessHomeRecoveryState: HarnessHomeRecoveryPendingState?
    private(set) var pendingDeviceAttestationTrustRecoveryRequest: DeviceAttestationTrustRecoveryRequest?
    var pendingHarnessHomeRecoveryRequest: HarnessHomeReceiptlessRecoveryRequest? {
        guard case .initial(let request) = pendingHarnessHomeRecoveryState else { return nil }
        return request
    }
    private var harnessHomeRecoveryInFlight: Bool {
        get { harnessHomeAdmissionVault.snapshot().recoveryInFlight }
        set { harnessHomeAdmissionVault.setRecoveryInFlight(newValue) }
    }
    var harnessHomeRecoveryIsInFlight: Bool { harnessHomeRecoveryInFlight }
    var verifiedHarnessHomeCapability: HarnessHomeAttestationCapability? {
        harnessHomeAdmissionVault.snapshot().capability
    }

    func attachmentPurgeAdmissionPermitted() -> Bool {
        let snapshot = harnessHomeAdmissionVault.snapshot()
        return !snapshot.ownsHarness
            && !snapshot.recoveryInFlight
            && snapshot.capability != nil
    }

    @discardableResult
    private func publishVerifiedHarnessHomeCapability(
        _ capability: HarnessHomeAttestationCapability?
    ) -> UInt64 {
        harnessHomeAdmissionVault.replaceCapability(capability)
    }

    private func setOwnsHarness(_ value: Bool) {
        harnessHomeAdmissionVault.setOwnsHarness(value)
    }
    private let statePublicationGate = StatePublicationGate()
    var lifecycleReplacementModeObserver: ((Bool) -> Void)?
    private let lifecycleStopProcess: ((Process, @escaping (Result<Void, Error>) -> Void) -> Void)?
    private let lifecycleStartReplacement: (() -> Void)?
    private let lifecycleStartOllamaPrerequisiteRecovery: ((OllamaPrerequisiteRecoveryIssue) -> Void)?
    private let lifecycleStartupPrerequisitePhaseHook: ((RuntimeStartupPrerequisitePhase, RuntimeStartupPrerequisiteCancellation) throws -> Void)?
    private let lifecycleBundleIntegrityVerification: (() throws -> Bool)?
    private let lifecycleHarnessHomeRecoveryAuthenticationKey: Data?
    private let deviceAttestationKeyStore: any DeviceAttestationKeyStore
    private lazy var deviceAttestationTrustRecovery = DeviceAttestationTrustRecoveryCoordinator(
        applicationSupport: applicationSupportDirectoryURL(),
        keyStore: deviceAttestationKeyStore
    )
    private let physicalMemoryBytes: UInt64

    init(
        lifecycleTestConfiguration: LifecycleTestConfiguration? = nil,
        applicationSupportDirectory: URL? = nil,
        modelStoreDirectory: URL? = nil,
        forbidCredentialHelper: Bool = false
    ) {
        applicationSupportOverride = applicationSupportDirectory
        applicationSupportRootAdmission = ApplicationSupportRootAdmission(
            url: Self.resolvedApplicationSupportDirectory(
                override: applicationSupportDirectory
            )
        )
        modelStoreOverride = modelStoreDirectory
        self.forbidCredentialHelper = forbidCredentialHelper
        lifecycleStopProcess = lifecycleTestConfiguration?.stopProcess
        lifecycleStartReplacement = lifecycleTestConfiguration?.startReplacement
        lifecycleStartOllamaPrerequisiteRecovery = lifecycleTestConfiguration?.startOllamaPrerequisiteRecovery
        lifecycleStartupPrerequisitePhaseHook = lifecycleTestConfiguration?.startupPrerequisitePhaseHook
        lifecycleBundleIntegrityVerification = lifecycleTestConfiguration?.bundleIntegrityVerification
        lifecycleHarnessHomeRecoveryAuthenticationKey = lifecycleTestConfiguration?
            .harnessHomeRecoveryAuthenticationKey
        deviceAttestationKeyStore = lifecycleTestConfiguration?.deviceAttestationKeyStore
            ?? ProviderHistoryDeviceAttestation.productionKeyStore()
        physicalMemoryBytes = lifecycleTestConfiguration?.physicalMemoryBytes
            ?? ProcessInfo.processInfo.physicalMemory
        modelSettingsStore = lifecycleTestConfiguration?.modelSettingsStore
            ?? ModelProviderSettingsStore()
        startupPrerequisiteCancellation = lifecycleTestConfiguration?.startupPrerequisiteCancellation
        if let lifecycleTestConfiguration {
            harnessProcess = lifecycleTestConfiguration.harnessProcess
            ollamaProcess = lifecycleTestConfiguration.ollamaProcess
            setOwnsHarness(lifecycleTestConfiguration.harnessProcess != nil)
            ownsOllama = lifecycleTestConfiguration.ollamaProcess != nil
            currentState = lifecycleTestConfiguration.initialState
        }
    }

    func prepareAndStart() {
        prepareAndStart(mode: .inference, ollamaRecoveryIssue: nil)
    }

    /// Starts the authenticated provider/settings/credential control plane
    /// with no provider origin, skill, or MCP activation. Only the app's typed
    /// recoverable provider/native-state paths may call this; integrity,
    /// preloader, sandbox, bundle, and inventory failures remain terminal.
    func prepareProviderRecovery() {
        prepareAndStart(mode: .providerRecovery, ollamaRecoveryIssue: nil)
    }

    private func prepareAndStart(
        mode: LaunchMode,
        ollamaRecoveryIssue: OllamaPrerequisiteRecoveryIssue?
    ) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.prepareAndStart(mode: mode, ollamaRecoveryIssue: ollamaRecoveryIssue)
            }
            return
        }
        if case .failure(let error) = admitApplicationSupportRoot() {
            publish(.failed(error.localizedDescription))
            return
        }
        guard !terminalShutdownRequested, !harnessHomeRecoveryInFlight else { return }
        // A start requested while exact old children are still draining is a
        // restart intent, never permission to overlap a replacement runtime.
        if let stopGeneration {
            stopGeneration.restartRequested = true
            pendingRestartLaunchMode = mode
            pendingOllamaPrerequisiteRecoveryIssue = mode == .providerRecovery ? ollamaRecoveryIssue : nil
            return
        }
        guard !isStarting, !isStartingOllamaOnly, harnessProcess?.isRunning != true else { return }
        statePublicationGate.beginGeneration()
        intentionalStop = false
        isStarting = true
        activeLaunchMode = mode
        pendingRestartLaunchMode = mode
        self.ollamaPrerequisiteRecoveryIssue = mode == .providerRecovery ? ollamaRecoveryIssue : nil
        pendingOllamaPrerequisiteRecoveryIssue = self.ollamaPrerequisiteRecoveryIssue
        startupGeneration &+= 1
        let generation = startupGeneration
        publish(.checking)

        verifyBundleIntegrity(generation: generation) { [weak self] result in
            guard let self,
                  self.startupGeneration == generation,
                  self.stopGeneration == nil,
                  !self.intentionalStop,
                  !self.terminalShutdownRequested else { return }
            switch result {
            case .success:
                self.prepareHarnessHomeBeforeRuntimeAdmission(
                    generation: generation,
                    mode: mode
                )
            case .failure(let error as RuntimeStartupPrerequisiteError)
                where error == .cancelled:
                return
            case .failure:
                self.isStarting = false
                self.publish(.failed("\(ProductBrand.displayName) did not start because its signed application bundle failed integrity verification. Reinstall from a trusted build."))
            }
        }
    }

    /// Strictly detection-only preparation runs before local-provider admission
    /// or Ollama launch. It is safe for every direct controller caller because it
    /// creates, cleans, migrates, and authenticates nothing. The launch-plan
    /// worker retains the sole full `homeManager.prepare` immediately before DSH
    /// construction, after the app/background migration-backup gate.
    private func prepareHarnessHomeBeforeRuntimeAdmission(
        generation: UInt64,
        mode: LaunchMode
    ) {
        let phaseHook = lifecycleStartupPrerequisitePhaseHook
        let root = harnessHomeDirectory()
        let support = applicationSupportDirectoryURL()
        let keyStore = deviceAttestationKeyStore
        startupPrerequisiteCancellation = startupPrerequisiteWorker.submitValue(
            operation: { [weak self] cancellation in
                guard let self else { throw RuntimeStartupPrerequisiteError.cancelled }
                let budget = RuntimeStartupPrerequisiteBudget(
                    cancellation: cancellation,
                    duration: 60
                )
                try phaseHook?(.harnessHomePreflight, cancellation)
                try budget.checkpoint()
                let status = try self.homeManager.preflightHarnessHomeRecovery(
                    cancellationCheck: { try budget.checkpoint() }
                )
                guard status == .current else {
                    throw DeviceAttestationError.foregroundRequired
                }
                switch try HarnessHomeAttestationStore.backgroundState(
                    rootURL: root,
                    receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                    expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                    configuration: ProviderHistoryDeviceAttestation.configuration(
                        applicationSupport: support
                    ),
                    keyStore: keyStore
                ) {
                case .current(let capability):
                    return capability
                case .absent, .foregroundRequired:
                    throw DeviceAttestationError.foregroundRequired
                }
            },
            isGenerationCurrent: { [weak self] in
                guard let self else { return false }
                return self.startupGeneration == generation
                    && self.stopGeneration == nil
                    && !self.intentionalStop
                    && !self.terminalShutdownRequested
            },
            completion: { [weak self] result in
                guard let self,
                      self.startupGeneration == generation,
                      self.stopGeneration == nil,
                      !self.intentionalStop,
                      !self.terminalShutdownRequested else { return }
                self.startupPrerequisiteCancellation = nil
                switch result {
                case .success(let capability):
                    self.publishVerifiedHarnessHomeCapability(capability)
                    self.continueStartupAfterBundleIntegrity(
                        generation: generation,
                        mode: mode
                    )
                case .failure(let error as RuntimeStartupPrerequisiteError)
                    where error == .cancelled:
                    return
                case .failure(let error as HarnessHomeError):
                    if let pending = self.harnessHomeRecoveryPendingState(for: error) {
                        self.pauseForHarnessHomeRecovery(pending)
                    } else {
                        self.failRuntimeStartAfterCleaningOwnedServices(error)
                    }
                case .failure(let error):
                    self.failRuntimeStartAfterCleaningOwnedServices(error)
                }
            }
        )
    }

    private func continueStartupAfterBundleIntegrity(generation: UInt64, mode: LaunchMode) {
        guard startupGeneration == generation,
              stopGeneration == nil,
              !intentionalStop,
              !terminalShutdownRequested else { return }
        guard mode == .inference, selectedProviderNeedsOllama else {
            startHarnessAfterPrerequisites(generation: generation, mode: mode)
            return
        }

        do {
            let selection = try modelSettingsStore.loadOrMigrate().settings.defaultSelection
            try QualifiedLocalModelHostAdmissionPolicy.validate(
                selection: selection,
                physicalMemoryBytes: physicalMemoryBytes
            )
        } catch let error as QualifiedLocalModelHostAdmissionError {
            transitionToProviderRecovery(
                after: OllamaPrerequisiteRecoveryIssue.hostAdmissionBoundary(error)
            )
            return
        } catch {
            isStarting = false
            publish(.failed("Could not validate the selected local model against this Mac before starting inference."))
            return
        }

        publish(.startingOllama)
        ensureOwnedOllama(generation: generation) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                guard self.startupGeneration == generation,
                      self.stopGeneration == nil,
                      !self.intentionalStop else { return }
                self.startHarnessAfterPrerequisites(generation: generation, mode: mode)
            case .failure(let error):
                guard !self.terminalShutdownRequested else { return }
                if let issue = error as? OllamaPrerequisiteRecoveryIssue {
                    self.transitionToProviderRecovery(after: issue)
                } else if let localError = error as? LocalHarnessError,
                          case .serviceStartCancelled = localError {
                    // A concurrent stop owns the lifecycle now. It will publish
                    // the resulting stopped/failed state and must not race a
                    // replacement repair runtime.
                    self.isStarting = false
                } else {
                    self.isStarting = false
                    self.publish(.failed("Could not start the isolated Ollama service safely. Open Diagnostics for private, redacted details."))
                }
            }
        }
    }

    private func verifyBundleIntegrity(
        generation: UInt64,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        let phaseHook = lifecycleStartupPrerequisitePhaseHook
        let bundleIntegrityVerification = lifecycleBundleIntegrityVerification
        startupPrerequisiteCancellation = startupPrerequisiteWorker.submit(
            operation: { cancellation in
                let budget = RuntimeStartupPrerequisiteBudget(
                    cancellation: cancellation,
                    duration: 30
                )
                try phaseHook?(.bundleIntegrity, cancellation)
                try budget.checkpoint()
                let verified: Bool
                if let bundleIntegrityVerification {
                    verified = try bundleIntegrityVerification()
                } else {
                    verified = try BundleIntegrityVerifier.verify(
                        cancellationCheck: { try budget.checkpoint() }
                    )
                }
                guard verified else {
                    throw RuntimeBundleIntegrityError.verificationFailed
                }
            },
            isGenerationCurrent: { [weak self] in
                guard let self else { return false }
                return self.startupGeneration == generation
                    && self.stopGeneration == nil
                    && !self.intentionalStop
                    && !self.terminalShutdownRequested
            },
            completion: { [weak self] result in
                guard let self else { return }
                if self.startupGeneration == generation,
                   self.stopGeneration == nil,
                   !self.intentionalStop,
                   !self.terminalShutdownRequested {
                    self.startupPrerequisiteCancellation = nil
                }
                completion(result)
            }
        )
    }

    /// The sole downgrade from inference startup into provider repair. The
    /// caller must provide a typed on-device prerequisite issue; all other
    /// startup and security failures remain on the terminal path.
    func transitionToProviderRecovery(after issue: OllamaPrerequisiteRecoveryIssue) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in self?.transitionToProviderRecovery(after: issue) }
            return
        }
        guard !terminalShutdownRequested, stopGeneration == nil else { return }
        isStarting = false
        intentionalStop = false
        ollamaPrerequisiteRecoveryIssue = issue
        pendingOllamaPrerequisiteRecoveryIssue = issue
        if let lifecycleStartOllamaPrerequisiteRecovery {
            activeLaunchMode = .providerRecovery
            pendingRestartLaunchMode = .providerRecovery
            publish(.providerRecovery)
            lifecycleStartOllamaPrerequisiteRecovery(issue)
            return
        }
        prepareAndStart(mode: .providerRecovery, ollamaRecoveryIssue: issue)
    }

    private var selectedProviderNeedsOllama: Bool {
        guard let loaded = try? modelSettingsStore.loadOrMigrate() else { return true }
        return loaded.settings.defaultSelection.route.provider == BuiltInProviderDescriptors.ollama.id
    }

    private var selectedOllamaModelConfiguration: AppOwnedOllamaModelConfiguration {
        guard let loaded = try? modelSettingsStore.loadOrMigrate(),
              let configuration = AppOwnedOllamaModelConfiguration(
                selection: loaded.settings.defaultSelection
              ) else {
            // A cloud route may start Ollama only to display its local catalog.
            // Unknown/corrupt settings must likewise never unlock Qwen-specific
            // process optimizations.
            return .catalogueInspection
        }
        return configuration
    }

    private func startHarnessAfterPrerequisites(generation: UInt64, mode: LaunchMode) {
        guard startupGeneration == generation,
              stopGeneration == nil,
              !intentionalStop,
              !terminalShutdownRequested else { return }
        publish(.startingHarness)

        // Resolve UI-owned state on main. Every disk-heavy validation,
        // fingerprint, materialization, and child probe below runs as one
        // cancellable, deadline-bounded worker operation.
        let applicationSupport = diagnosticsDirectory().standardizedFileURL
        let harnessHome = applicationSupport.appendingPathComponent("HarnessHome", isDirectory: true)
        let workspace = applicationSupport.appendingPathComponent("Workspace", isDirectory: true)
        let allowSSHAgent = preferences.allowSSHAgent
        let preparedBoundary = preparedSkillBoundary
        let cloudApprovals = oneTimeSkillCloudApprovals
        let existingSkillStore = skillsTrustStoreInstance
        let existingMCPStore = mcpTrustStoreInstance
        let phaseHook = lifecycleStartupPrerequisitePhaseHook
        let ownedOllamaSnapshot: RequiredOwnedOllamaSnapshot?
        if let process = ollamaProcess,
           process.isRunning,
           ownsOllama,
           let endpoint = ollamaEndpoint,
           let identity = ollamaExecutableIdentity,
           let modelConfiguration = ollamaModelConfiguration {
            ownedOllamaSnapshot = RequiredOwnedOllamaSnapshot(
                endpoint: endpoint,
                processIdentifier: process.processIdentifier,
                executableIdentity: identity,
                modelConfiguration: modelConfiguration
            )
        } else {
            ownedOllamaSnapshot = nil
        }
        startupPrerequisiteCancellation = startupPrerequisiteWorker.submitValue(
            operation: { [weak self] cancellation -> PreparedHarnessLaunch in
                guard let self else { throw RuntimeStartupPrerequisiteError.cancelled }
                let budget = RuntimeStartupPrerequisiteBudget(
                    cancellation: cancellation,
                    duration: 60
                )
                try phaseHook?(.harnessLaunchPlan, cancellation)
                try budget.checkpoint()
                try self.homeManager.prepare(
                    cancellationCheck: { try budget.checkpoint() }
                )
                let harnessHomeCapability: HarnessHomeAttestationCapability
                switch try HarnessHomeAttestationStore.backgroundState(
                    rootURL: harnessHome,
                    receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                    expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                    configuration: ProviderHistoryDeviceAttestation.configuration(
                        applicationSupport: applicationSupport
                    ),
                    keyStore: self.deviceAttestationKeyStore
                ) {
                case .current(let capability):
                    harnessHomeCapability = capability
                case .absent, .foregroundRequired:
                    throw DeviceAttestationError.foregroundRequired
                }
                // Every fresh runtime starts with workspace mutation closed.
                // Only a native checkpoint (or the typed read-only fallback)
                // may publish the policy observed by DSH's pre-execute gate.
                try WorkspaceMutationPolicyStore(harnessHome: harnessHome).requireCheckpoint()
                try budget.checkpoint()
                let externalPlugins = PluginTrustStore(
                    applicationSupport: applicationSupport,
                    profileRoot: harnessHome.appendingPathComponent("profiles", isDirectory: true)
                ).audit().filter { $0.status != .builtIn }
                guard externalPlugins.isEmpty else {
                    throw LocalHarnessError.untrustedPlugins(externalPlugins.map(\.name))
                }
                try budget.checkpoint()
                return try self.prepareHarnessLaunch(
                    mode: mode,
                    applicationSupport: applicationSupport,
                    harnessHome: harnessHome,
                    harnessHomeCapability: harnessHomeCapability,
                    workspace: workspace,
                    allowSSHAgent: allowSSHAgent,
                    preparedBoundary: preparedBoundary,
                    cloudApprovals: cloudApprovals,
                    existingSkillStore: existingSkillStore,
                    existingMCPStore: existingMCPStore,
                    ownedOllama: ownedOllamaSnapshot,
                    cancellation: cancellation,
                    budget: budget,
                    phaseHook: phaseHook
                )
            },
            isGenerationCurrent: { [weak self] in
                guard let self else { return false }
                return self.startupGeneration == generation &&
                    self.stopGeneration == nil &&
                    !self.intentionalStop &&
                    !self.terminalShutdownRequested
            },
            completion: { [weak self] result in
                guard let self,
                      self.startupGeneration == generation,
                      self.stopGeneration == nil,
                      !self.intentionalStop,
                      !self.terminalShutdownRequested else { return }
                self.startupPrerequisiteCancellation = nil
                switch result {
                case .success(let prepared):
                    do {
                        guard self.startupGeneration == generation,
                              self.stopGeneration == nil,
                              !self.intentionalStop,
                              !self.terminalShutdownRequested else { return }
                        let capabilityGeneration = self.publishVerifiedHarnessHomeCapability(
                            prepared.harnessHomeCapability
                        )
                        try self.commitHarnessLaunch(
                            prepared,
                            generation: generation,
                            capabilityGeneration: capabilityGeneration
                        )
                        self.isStarting = false
                    } catch let issue as OllamaPrerequisiteRecoveryIssue {
                        self.requestOwnedServicesStop(
                            restartAfterStop: false,
                            terminalShutdown: false
                        ) { [weak self] stopResult in
                            guard let self else { return }
                            if case .success = stopResult {
                                self.transitionToProviderRecovery(after: issue)
                            }
                            // A failed exact-child stop already published the
                            // terminal lifecycle failure and cannot launch a sibling.
                        }
                    } catch {
                        self.failRuntimeStartAfterCleaningOwnedServices(error)
                    }
                case .failure(let error as RuntimeStartupPrerequisiteError)
                    where error == .cancelled:
                    // Lifecycle cancellation already owns state publication and
                    // exact-child cleanup; this stale completion is intentionally inert.
                    return
                case .failure(let error as HarnessHomeError):
                    if let pending = self.harnessHomeRecoveryPendingState(for: error) {
                        self.pauseForHarnessHomeRecovery(pending)
                    } else {
                        self.failRuntimeStartAfterCleaningOwnedServices(error)
                    }
                case .failure(let error):
                    self.failRuntimeStartAfterCleaningOwnedServices(error)
                }
            }
        )
    }

    private func harnessHomeRecoveryPendingState(
        for error: HarnessHomeError
    ) -> HarnessHomeRecoveryPendingState? {
        switch error {
        case .receiptlessRecoveryRequired(let request):
            return .initial(request)
        case .receiptlessRecoveryInterrupted(let request):
            return .interrupted(request)
        case .receiptlessRecoveryStateChanged,
             .receiptlessRecoveryInProgress,
             .receiptlessRecoveryAuthenticationRequired,
             .receiptlessRecoveryAuthenticationUnavailable,
             .receiptlessRecoveryJournalInvalid:
            return .blocked(root: harnessHomeDirectory(), message: error.localizedDescription)
        default:
            return nil
        }
    }

    private func backgroundHarnessHomeRecoveryPendingState(
        for error: Error
    ) -> HarnessHomeRecoveryPendingState {
        if let error = error as? HarnessHomeError,
           let pending = harnessHomeRecoveryPendingState(for: error) {
            return pending
        }
        let message: String
        if let error = error as? HarnessHomeError {
            message = error.localizedDescription
        } else {
            message = "Harness-home recovery state could not be verified without foreground inspection."
        }
        return .blocked(root: harnessHomeDirectory(), message: message)
    }

    private func publishBackgroundHarnessHomeRecoveryPending(
        for error: Error
    ) {
        precondition(Thread.isMainThread)
        guard !terminalShutdownRequested else { return }
        let pending = backgroundHarnessHomeRecoveryPendingState(for: error)
        pendingHarnessHomeRecoveryState = pending
        if let presentation = onHarnessHomeRecoveryPending {
            presentation(pending)
        } else if case .initial(let request) = pending {
            onHarnessHomeRecoveryRequired?(request)
        }
    }

    /// Background-scheduler admission performs only the manager's read-only,
    /// credential-free recovery detection. A pending signal is published
    /// synchronously on main before completion is delivered, so the lifecycle
    /// coordinator cannot terminate the process ahead of its activity and user
    /// notification owner.
    func preflightHarnessHomeRecoveryForBackgroundSchedule(
        backgroundDetectionOnly: Bool = true,
        completion: @escaping (Result<HarnessHomeRecoveryPreflightStatus, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        if case .failure(let error) = admitApplicationSupportRoot() {
            publishVerifiedHarnessHomeCapability(nil)
            completion(.failure(error))
            return
        }
        guard !terminalShutdownRequested,
              !harnessHomeRecoveryInFlight,
              !isStarting,
              stopGeneration == nil else {
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        harnessHomeRecoveryInFlight = true
        let manager = homeManager
        let root = harnessHomeDirectory()
        let support = applicationSupportDirectoryURL()
        let keyStore = deviceAttestationKeyStore
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result: Result<(
                HarnessHomeRecoveryPreflightStatus,
                HarnessHomeAttestationCapability?
            ), Error> = Result {
                let status = try manager.preflightHarnessHomeRecovery()
                guard status == .current else { return (status, nil) }
                let attestation = try HarnessHomeAttestationStore.backgroundState(
                    rootURL: root,
                    receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                    expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current),
                    configuration: ProviderHistoryDeviceAttestation.configuration(
                        applicationSupport: support
                    ),
                    keyStore: keyStore
                )
                switch attestation {
                case .absent, .foregroundRequired:
                    return (.foregroundAttestationRequired, nil)
                case .current(let capability):
                    return (.current, capability)
                }
            }
            DispatchQueue.main.async {
                guard let self else {
                    completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
                    return
                }
                self.harnessHomeRecoveryInFlight = false
                if case .failure(let error) = result,
                   backgroundDetectionOnly
                    || !DeviceAttestationTrustRecoveryCoordinator.isRecoverable(error) {
                    // Unsafe-profile, bound, and unexpected I/O failures are
                    // not typed initial/interrupted prompts, but a background
                    // wake still needs a durable foreground-attention signal.
                    // Production's pending callback writes that signal before
                    // this completion can authorize process exit.
                    self.publishBackgroundHarnessHomeRecoveryPending(for: error)
                }
                switch result {
                case .success(let (status, capability)):
                    self.publishVerifiedHarnessHomeCapability(capability)
                    completion(.success(status))
                case .failure(let error):
                    self.publishVerifiedHarnessHomeCapability(nil)
                    completion(.failure(error))
                }
            }
        }
    }

    /// Foreground-only completion of Harness-home preparation. Callers must run
    /// the credential-free preflight first. This can create and attest a new
    /// home, so it is deliberately unavailable to background schedule wakes.
    func prepareHarnessHomeForForegroundProviderHistoryGate(
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        if case .failure(let error) = admitApplicationSupportRoot() {
            publishVerifiedHarnessHomeCapability(nil)
            completion(.failure(error))
            return
        }
        guard !terminalShutdownRequested,
              !harnessHomeRecoveryInFlight,
              !isStarting,
              stopGeneration == nil,
              !ownsHarness,
              !ownsOllama else {
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        harnessHomeRecoveryInFlight = true
        let manager = homeManager
        let root = harnessHomeDirectory()
        let support = applicationSupportDirectoryURL()
        let keyStore = deviceAttestationKeyStore
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result: Result<HarnessHomeAttestationCapability, Error> = Result {
                let authority = try ProviderHistoryDeviceAttestation.openForeground(
                    applicationSupport: support,
                    keyStore: keyStore
                )
                // Establish device trust before any full Harness-home
                // preparation can migrate or normalize provider state. A
                // partial/mismatched bootstrap therefore reaches only the
                // explicit opaque-preservation recovery path.
                try manager.prepare()
                return try authority.makeHarnessHomeAttestationStore().establishCurrent(
                    rootURL: root,
                    receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                    privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current)
                )
            }
            DispatchQueue.main.async {
                guard let self else {
                    completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
                    return
                }
                self.harnessHomeRecoveryInFlight = false
                if case .success(let capability) = result {
                    self.publishVerifiedHarnessHomeCapability(capability)
                } else {
                    self.publishVerifiedHarnessHomeCapability(nil)
                }
                if case .failure(let error as HarnessHomeError) = result,
                   let pending = self.harnessHomeRecoveryPendingState(for: error) {
                    self.pendingHarnessHomeRecoveryState = pending
                    if let presentation = self.onHarnessHomeRecoveryPending {
                        presentation(pending)
                    } else if case .initial(let request) = pending {
                        self.onHarnessHomeRecoveryRequired?(request)
                    }
                } else if case .failure(let error) = result,
                          !DeviceAttestationTrustRecoveryCoordinator.isRecoverable(error) {
                    self.publishBackgroundHarnessHomeRecoveryPending(for: error)
                }
                completion(result.map { _ in () })
            }
        }
    }

    /// Creates an exact, detection-only request for a foreground trust repair.
    /// It is intentionally separate from the failing startup operation so a
    /// modal can never authorize a later or substituted filesystem snapshot.
    func inspectDeviceAttestationTrustRecovery(
        after error: Error,
        completion: @escaping (Result<DeviceAttestationTrustRecoveryRequest, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        if case .failure(let admissionError) = admitApplicationSupportRoot() {
            completion(.failure(admissionError))
            return
        }
        guard DeviceAttestationTrustRecoveryCoordinator.isRecoverable(error),
              !terminalShutdownRequested,
              !harnessHomeRecoveryInFlight,
              !isStarting,
              stopGeneration == nil,
              !ownsHarness,
              !ownsOllama else {
            completion(.failure(DeviceAttestationTrustRecoveryError.notRecoverable))
            return
        }
        let coordinator = deviceAttestationTrustRecovery
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try coordinator.inspect() }
            DispatchQueue.main.async {
                guard let self else {
                    completion(.failure(DeviceAttestationTrustRecoveryError.confirmedStateChanged))
                    return
                }
                if case .success(let request) = result {
                    self.pendingDeviceAttestationTrustRecoveryRequest = request
                    self.onDeviceAttestationTrustRecoveryRequired?(request)
                }
                completion(result)
            }
        }
    }

    /// Foreground-only mutation after exact confirmation. Every provider and
    /// history root is preserved whole before the two attestation accounts are
    /// reset. A new Harness home is created and attested only after that
    /// preservation and reset complete.
    func recoverDeviceAttestationTrustAfterExplicitConfirmation(
        _ request: DeviceAttestationTrustRecoveryRequest,
        completion: @escaping (Result<DeviceAttestationTrustRecoveryReceipt, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        if case .failure(let error) = admitApplicationSupportRoot() {
            publishVerifiedHarnessHomeCapability(nil)
            completion(.failure(error))
            return
        }
        guard pendingDeviceAttestationTrustRecoveryRequest == request,
              !terminalShutdownRequested,
              !harnessHomeRecoveryInFlight,
              !isStarting,
              stopGeneration == nil,
              !ownsHarness,
              !ownsOllama else {
            completion(.failure(DeviceAttestationTrustRecoveryError.confirmedStateChanged))
            return
        }
        publishVerifiedHarnessHomeCapability(nil)
        harnessHomeRecoveryInFlight = true
        let coordinator = deviceAttestationTrustRecovery
        let manager = homeManager
        let root = harnessHomeDirectory()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result: Result<(
                DeviceAttestationTrustRecoveryReceipt,
                HarnessHomeAttestationCapability
            ), Error> = Result {
                let (receipt, authority) = try coordinator.recoverAfterExplicitConfirmation(request)
                try manager.prepare()
                let capability = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                    rootURL: root,
                    receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                    privacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current)
                )
                return (receipt, capability)
            }
            DispatchQueue.main.async {
                guard let self else {
                    completion(.failure(DeviceAttestationTrustRecoveryError.confirmedStateChanged))
                    return
                }
                self.harnessHomeRecoveryInFlight = false
                guard self.pendingDeviceAttestationTrustRecoveryRequest == request else {
                    self.publishVerifiedHarnessHomeCapability(nil)
                    completion(.failure(DeviceAttestationTrustRecoveryError.confirmedStateChanged))
                    return
                }
                switch result {
                case .success(let (receipt, capability)):
                    self.publishVerifiedHarnessHomeCapability(capability)
                    self.pendingDeviceAttestationTrustRecoveryRequest = nil
                    self.pendingHarnessHomeRecoveryState = nil
                    completion(.success(receipt))
                case .failure(let error):
                    self.publishVerifiedHarnessHomeCapability(nil)
                    completion(.failure(error))
                }
            }
        }
    }

    func cancelDeviceAttestationTrustRecovery(
        _ request: DeviceAttestationTrustRecoveryRequest
    ) {
        precondition(Thread.isMainThread)
        guard pendingDeviceAttestationTrustRecoveryRequest == request,
              !harnessHomeRecoveryInFlight else { return }
        pendingDeviceAttestationTrustRecoveryRequest = nil
        publishVerifiedHarnessHomeCapability(nil)
    }

    private func pauseForHarnessHomeRecovery(
        _ pending: HarnessHomeRecoveryPendingState
    ) {
        precondition(Thread.isMainThread)
        guard !terminalShutdownRequested else { return }
        pendingHarnessHomeRecoveryState = pending
        requestOwnedServicesStop(
            restartAfterStop: false,
            terminalShutdown: false
        ) { [weak self] stopResult in
            guard let self else { return }
            self.isStarting = false
            switch stopResult {
            case .success:
                // `publish(.stopped)` enqueues its UI delivery before the stop
                // completion. Present on the next main turn so stale loading UI
                // cannot overwrite the exact typed recovery state.
                DispatchQueue.main.async { [weak self] in
                    guard let self,
                          !self.terminalShutdownRequested,
                          self.stopGeneration == nil,
                          self.currentState == .stopped,
                          self.pendingHarnessHomeRecoveryState == pending else { return }
                    if let presentation = self.onHarnessHomeRecoveryPending {
                        presentation(pending)
                    } else if case .initial(let request) = pending,
                              let presentation = self.onHarnessHomeRecoveryRequired {
                        presentation(request)
                    } else {
                        self.publish(.failed(
                            "Private Harness-home recovery needs foreground review. Agent work remains stopped; open \(ProductBrand.displayName) to continue safely."
                        ))
                    }
                }
            case .failure:
                // The stop barrier already published the exact-child failure.
                // Never offer a filesystem repair beside an unverified child.
                break
            }
        }
    }

    private func canBeginHarnessHomeRecoveryOperation(
        for pending: HarnessHomeRecoveryPendingState
    ) -> Bool {
        !terminalShutdownRequested &&
            stopGeneration == nil &&
            !harnessHomeRecoveryInFlight &&
            !isStarting &&
            !isStartingOllamaOnly &&
            currentState == .stopped &&
            !ownsHarness &&
            !ownsOllama &&
            pendingHarnessHomeRecoveryState == pending
    }

    private func blockedHarnessHomeRecoveryState(
        after error: Error,
        root: URL
    ) -> HarnessHomeRecoveryPendingState? {
        if let error = error as? HarnessHomeError,
           error == .receiptlessRecoveryAuthenticationRequired {
            return nil
        }
        if let error = error as? HarnessHomeError,
           case .receiptlessRecoveryInterrupted(let request) = error {
            return .interrupted(request)
        }
        let message: String
        if let error = error as? HarnessHomeError {
            message = error.localizedDescription
        } else {
            message = "The authenticated Harness-home recovery could not be verified."
        }
        return .blocked(root: root, message: message)
    }

    func preserveAndRepairPendingHarnessHome(
        choice: ProviderHistoryRecoveryChoice,
        interruptedIntent: HarnessHomeInterruptedRecoveryIntent?,
        completion: @escaping (Result<HarnessHomeReceiptlessRecoveryReceipt, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        guard let pending = pendingHarnessHomeRecoveryState,
              canBeginHarnessHomeRecoveryOperation(for: pending) else {
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        switch pending {
        case .initial, .interrupted:
            break
        case .published, .blocked:
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        publishVerifiedHarnessHomeCapability(nil)
        harnessHomeRecoveryInFlight = true
        let manager = homeManager
        let support = applicationSupportDirectoryURL()
        let root = harnessHomeDirectory()
        let keyStore = deviceAttestationKeyStore
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result: Result<(
                HarnessHomeReceiptlessRecoveryReceipt,
                HarnessHomeAttestationCapability
            ), Error> = Result {
                let authority = try ProviderHistoryDeviceAttestation.openForeground(
                    applicationSupport: support,
                    keyStore: keyStore
                )
                let rotation = try authority.makeHarnessHomeAttestationStore()
                    .makeRotationSession(
                        rootURL: root,
                        receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                        targetPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current)
                    )
                let receipt: HarnessHomeReceiptlessRecoveryReceipt
                switch pending {
                case .initial(let request):
                    guard interruptedIntent == nil else {
                        throw HarnessHomeError.receiptlessRecoveryStateChanged
                    }
                    receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
                        request,
                        choice: choice,
                        attestationRotation: rotation
                    )
                case .interrupted(let request):
                    guard let interruptedIntent,
                          interruptedIntent.choice == choice else {
                        throw HarnessHomeError.receiptlessRecoveryStateChanged
                    }
                    receipt = try manager.resumeInterruptedReceiptlessRecoveryAfterExplicitConfirmation(
                        request,
                        intent: interruptedIntent,
                        attestationRotation: rotation
                    )
                case .published, .blocked:
                    throw HarnessHomeError.receiptlessRecoveryStateChanged
                }
                guard let operationID = receipt.operationID else {
                    throw HarnessHomeError.receiptlessRecoveryJournalInvalid
                }
                let capability = try rotation.finalize(
                    operationID: operationID,
                    choice: choice.attestationChoice
                )
                return (receipt, capability)
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.harnessHomeRecoveryInFlight = false
                guard self.pendingHarnessHomeRecoveryState == pending else {
                    completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
                    return
                }
                if case .success(let (receipt, capability)) = result {
                    self.publishVerifiedHarnessHomeCapability(capability)
                    self.pendingHarnessHomeRecoveryState = .published(receipt)
                } else if case .failure(let error) = result,
                          let blocked = self.blockedHarnessHomeRecoveryState(
                              after: error,
                              root: pending.root
                          ) {
                    self.pendingHarnessHomeRecoveryState = blocked
                }
                completion(result.map(\.0))
            }
        }
    }

    func authorizePendingHarnessHomeRecoveryKey(
        completion: @escaping (Result<HarnessHomeInterruptedRecoveryIntent?, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        guard let pending = pendingHarnessHomeRecoveryState,
              canBeginHarnessHomeRecoveryOperation(for: pending) else {
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        let interruptedRequest: HarnessHomeInterruptedRecoveryRequest?
        switch pending {
        case .initial:
            interruptedRequest = nil
        case .interrupted(let request):
            interruptedRequest = request
        case .published, .blocked:
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        harnessHomeRecoveryInFlight = true
        let manager = homeManager
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result {
                try manager.authorizeReceiptlessRecoveryKeyForForeground(
                    interruptedRequest: interruptedRequest
                )
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.harnessHomeRecoveryInFlight = false
                guard self.pendingHarnessHomeRecoveryState == pending else {
                    completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
                    return
                }
                if case .failure(let error) = result,
                   let blocked = self.blockedHarnessHomeRecoveryState(
                       after: error,
                       root: pending.root
                   ) {
                    self.pendingHarnessHomeRecoveryState = blocked
                }
                completion(result)
            }
        }
    }

    func acknowledgePendingHarnessHomeRecovery(
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        precondition(Thread.isMainThread)
        guard let pending = pendingHarnessHomeRecoveryState,
              case .published(let receipt) = pending,
              canBeginHarnessHomeRecoveryOperation(for: pending) else {
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        harnessHomeRecoveryInFlight = true
        let manager = homeManager
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result {
                try manager.acknowledgePublishedReceiptlessRecovery(receipt)
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.harnessHomeRecoveryInFlight = false
                guard self.pendingHarnessHomeRecoveryState == pending else {
                    completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
                    return
                }
                if case .success = result {
                    self.pendingHarnessHomeRecoveryState = nil
                }
                completion(result)
            }
        }
    }

    /// A Harness launch failure after Ollama became ready must not strand the
    /// large owned local-model process. Failure is published only after every
    /// exact child captured at the boundary has exited.
    func failRuntimeStartAfterCleaningOwnedServices(
        _ error: Error,
        completion: (() -> Void)? = nil
    ) {
        let originalMessage = Self.startupFailureMessage(for: error)
        requestOwnedServicesStop(restartAfterStop: false, terminalShutdown: false) { [weak self] stopResult in
            guard let self else { return }
            self.isStarting = false
            let cleanupSuffix: String
            if case .failure = stopResult {
                cleanupSuffix = " The partial runtime also could not be confirmed stopped; agent work remains blocked."
            } else {
                cleanupSuffix = ""
            }
            self.publish(.failed("Could not start DeepSeek Harness securely: \(originalMessage)\(cleanupSuffix)"))
            completion?()
        }
    }

    /// Only errors owned by this module may cross into lifecycle state. Process,
    /// provider, filesystem, or injected Error descriptions can contain private
    /// paths and credentials and are retained only by the redacted diagnostics
    /// stream, never by UI state, notifications, or Activity persistence.
    private static func startupFailureMessage(for error: Error) -> String {
        if let failure = error as? RuntimeStartupPrerequisiteError {
            return failure.localizedDescription
        }
        if let failure = error as? RuntimeBundleIntegrityError {
            return failure.localizedDescription
        }
        if let failure = error as? OllamaPrerequisiteRecoveryIssue {
            return failure.localizedDescription
        }
        if let failure = error as? LocalHarnessError {
            switch failure {
            case .untrustedPlugins:
                return "One or more Harness plugins have not been reviewed. Open Plugin Trust before retrying."
            default:
                return failure.localizedDescription
            }
        }
        return "A launch component failed without a safe public diagnostic. Open Diagnostics for private, redacted details."
    }

    func prepareOllamaOnly(completion: @escaping (Result<Void, Error>) -> Void) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [self] in prepareOllamaOnly(completion: completion) }
            return
        }
        if isStartingOllamaOnly {
            ollamaOnlyStartCompletions.append(completion)
            return
        }
        guard !terminalShutdownRequested,
              stopGeneration == nil,
              !isStarting,
              !isStartingOllamaOnly else {
            completion(.failure(LocalHarnessError.serviceStartCancelled))
            return
        }
        intentionalStop = false
        isStartingOllamaOnly = true
        ollamaOnlyStartCompletions = [completion]
        startupGeneration &+= 1
        let generation = startupGeneration
        verifyBundleIntegrity(generation: generation) { [weak self] verification in
            guard let self else { return }
            guard self.startupGeneration == generation,
                  self.stopGeneration == nil,
                  !self.intentionalStop,
                  !self.terminalShutdownRequested else {
                self.finishOllamaOnly(.failure(LocalHarnessError.serviceStartCancelled))
                return
            }
            switch verification {
            case .success:
                self.ensureOwnedOllama(generation: generation) { [weak self] result in
                    self?.finishOllamaOnly(result)
                }
            case .failure(let error):
                self.finishOllamaOnly(.failure(error))
            }
        }
    }

    private func finishOllamaOnly(_ result: Result<Void, Error>) {
        isStartingOllamaOnly = false
        let completions = ollamaOnlyStartCompletions
        ollamaOnlyStartCompletions.removeAll()
        for completion in completions { completion(result) }
    }

    private func ensureOwnedOllama(
        generation: UInt64,
        launchAttempt: Int = 0,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard startupGeneration == generation,
              !terminalShutdownRequested,
              stopGeneration == nil,
              !intentionalStop else {
            completion(.failure(LocalHarnessError.serviceStartCancelled))
            return
        }
        let modelConfiguration = selectedOllamaModelConfiguration

        let existingIdentity: OllamaExecutableIdentity?
        if let existing = ollamaProcess, existing.isRunning {
            guard ownsOllama,
                  ollamaEndpoint != nil,
                  let identity = ollamaExecutableIdentity,
                  ollamaModelConfiguration == modelConfiguration else {
                completion(.failure(OllamaPrerequisiteRecoveryIssue.ownershipVerificationFailed))
                return
            }
            existingIdentity = identity
        } else {
            if let stale = ollamaProcess {
                stale.terminationHandler = nil
                ollamaProcess = nil
                ownsOllama = false
                ollamaEndpoint = nil
                ollamaExecutableIdentity = nil
                ollamaModelConfiguration = nil
            }
            existingIdentity = nil
        }

        let reservation: LoopbackPortReservation?
        do {
            reservation = existingIdentity == nil ? try LoopbackPortReservation.reserve() : nil
        } catch {
            completion(.failure(OllamaPrerequisiteRecoveryIssue.launchBoundary(error)))
            return
        }
        let applicationSupport = diagnosticsDirectory().standardizedFileURL
        let phaseHook = lifecycleStartupPrerequisitePhaseHook
        startupPrerequisiteCancellation = startupPrerequisiteWorker.submitValue(
            operation: { cancellation -> OwnedOllamaPreparation in
                let budget = RuntimeStartupPrerequisiteBudget(
                    cancellation: cancellation,
                    duration: 20
                )
                try phaseHook?(.ollamaLaunchPlan, cancellation)
                try budget.checkpoint()
                if let existingIdentity {
                    try OllamaExecutableTrust.revalidate(existingIdentity)
                    try budget.checkpoint()
                    return .existing(existingIdentity)
                }
                guard let reservation else {
                    throw OllamaRuntimeSecurityError.unsafePrivateDirectory
                }
                let runtimeLease = try self.locateRuntimeLease()
                let leaseIdentity = try RuntimeLaunchPathIdentity.capture(
                    runtimeLease,
                    kind: .regular
                )
                let plan = try AppOwnedOllamaLaunchPlan.prepare(
                    applicationSupport: applicationSupport,
                    endpoint: reservation.endpoint,
                    modelConfiguration: modelConfiguration,
                    modelStoreDirectory: self.modelStoreOverride,
                    cancellationCheck: { try budget.checkpoint() }
                )
                return .launch(plan, lease: leaseIdentity)
            },
            isGenerationCurrent: { [weak self] in
                guard let self else { return false }
                return self.startupGeneration == generation
                    && self.stopGeneration == nil
                    && !self.intentionalStop
                    && !self.terminalShutdownRequested
            },
            completion: { [weak self] result in
                guard let self else { return }
                guard self.startupGeneration == generation,
                      self.stopGeneration == nil,
                      !self.intentionalStop,
                      !self.terminalShutdownRequested else {
                    completion(.failure(LocalHarnessError.serviceStartCancelled))
                    return
                }
                self.startupPrerequisiteCancellation = nil
                do {
                    switch result {
                    case .success(.existing(let identity)):
                        guard let process = self.ollamaProcess,
                              process.isRunning,
                              self.ownsOllama,
                              self.ollamaEndpoint != nil,
                              self.ollamaExecutableIdentity == identity else {
                            throw LocalHarnessError.ollamaOwnershipVerificationFailed
                        }
                        try OllamaExecutableTrust.revalidateFilesystemIdentity(identity)
                    case .success(.launch(let plan, let leaseIdentity)):
                        guard let reservation else {
                            throw OllamaRuntimeSecurityError.unsafePrivateDirectory
                        }
                        try self.launchPreparedOllama(
                            plan,
                            leaseIdentity: leaseIdentity,
                            reservation: reservation,
                            generation: generation
                        )
                    case .failure(let error as RuntimeStartupPrerequisiteError)
                        where error == .cancelled:
                        completion(.failure(LocalHarnessError.serviceStartCancelled))
                        return
                    case .failure(let error):
                        throw error
                    }
                    self.waitForOllama(
                        launchAttempt: launchAttempt,
                        generation: generation,
                        completion: completion
                    )
                } catch {
                    completion(.failure(OllamaPrerequisiteRecoveryIssue.launchBoundary(error)))
                }
            }
        )
    }

    private func waitForOllama(
        launchAttempt: Int,
        generation: UInt64,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard let process = ollamaProcess,
              process.isRunning,
              ownsOllama,
              ollamaEndpoint != nil else {
            retryOwnedOllamaLaunch(
                launchAttempt: launchAttempt,
                generation: generation,
                completion: completion
            )
            return
        }
        guard let ownedEndpoint = ollamaEndpoint else {
            retryOwnedOllamaLaunch(
                launchAttempt: launchAttempt,
                generation: generation,
                completion: completion
            )
            return
        }
        LocalRuntimeReadinessProbe.ollamaCatalogUntilReady(
            endpoint: ownedEndpoint,
            totalTimeout: Self.ownedOllamaReadinessTimeout,
            attemptTimeout: 2,
            retryDelay: 0.5,
            boundaryStatus: { [weak self, weak process] in
                guard let self, let process,
                      self.startupGeneration == generation,
                      !self.terminalShutdownRequested,
                      self.stopGeneration == nil,
                      !self.intentionalStop,
                      self.ollamaProcess === process,
                      self.ollamaEndpoint == ownedEndpoint,
                      self.ownsOllama,
                      process.isRunning else { return .invalid }
                // `sandbox-exec` can exist briefly before it execs the signed
                // Ollama image and binds the reserved listener. Treat that as
                // pending, but never send HTTP until both proofs are true.
                return self.verifiedOwnedOllama(process: process, endpoint: ownedEndpoint)
                    ? .valid
                    : .pending
            }
        ) { [weak self, weak process] outcome in
            guard let self else { return }
            guard self.startupGeneration == generation,
                  !self.terminalShutdownRequested,
                  self.stopGeneration == nil,
                  !self.intentionalStop else {
                completion(.failure(LocalHarnessError.serviceStartCancelled))
                return
            }
            switch outcome {
            case .ready:
                completion(.success(()))
            case .timedOut:
                self.stopFailedOllamaStartup(
                    error: OllamaPrerequisiteRecoveryIssue.readinessTimedOut,
                    completion: completion
                )
            case .boundaryInvalid:
                guard let process,
                      self.ollamaProcess === process,
                      process.isRunning else {
                    self.retryOwnedOllamaLaunch(
                        launchAttempt: launchAttempt,
                        generation: generation,
                        completion: completion
                    )
                    return
                }
                self.stopFailedOllamaStartup(
                    error: OllamaPrerequisiteRecoveryIssue.ownershipVerificationFailed,
                    completion: completion
                )
            }
        }
    }

    private func retryOwnedOllamaLaunch(
        launchAttempt: Int,
        generation: UInt64,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard startupGeneration == generation,
              !terminalShutdownRequested,
              stopGeneration == nil,
              !intentionalStop else {
            completion(.failure(LocalHarnessError.serviceStartCancelled))
            return
        }
        guard launchAttempt < 2 else {
            stopFailedOllamaStartup(
                error: OllamaPrerequisiteRecoveryIssue.ownershipVerificationFailed,
                completion: completion
            )
            return
        }
        ensureOwnedOllama(
            generation: generation,
            launchAttempt: launchAttempt + 1,
            completion: completion
        )
    }

    private func stopFailedOllamaStartup(
        error: Error,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        requestOwnedServicesStop(restartAfterStop: false, terminalShutdown: false) { result in
            switch result {
            case .success:
                completion(.failure(error))
            case .failure(let cleanupError):
                // A still-running exact child is a hard lifecycle failure. Do
                // not open even the no-egress repair runtime beside it.
                completion(.failure(cleanupError))
            }
        }
    }

    func stopOwnedServices() {
        stopOwnedServicesAndWait { _ in }
    }

    /// Synchronously invalidates both already queued and not-yet-delivered
    /// lifecycle events from the current runtime. Only a subsequently accepted
    /// `prepareAndStart` call reopens publication for its fresh generation.
    func suspendLifecycleStatePublications() {
        precondition(Thread.isMainThread)
        statePublicationGate.suspend()
    }

    /// Stops only processes launched and still owned by this controller, then
    /// waits for those exact `Process` instances to exit before reporting
    /// completion. Filesystem recovery and provider restarts use this barrier
    /// so an old agent or Ollama process cannot overlap a replacement runtime.
    func stopOwnedServicesAndWait(completion: @escaping (Result<Void, Error>) -> Void) {
        requestOwnedServicesStop(
            restartAfterStop: false,
            terminalShutdown: false,
            completion: completion
        )
    }

    /// Irreversibly closes this controller's launch boundary for true process
    /// termination. Ordinary backup/recovery stops deliberately do not use
    /// this API because they are expected to restart in the same app process.
    func stopOwnedServicesForApplicationTermination(
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        requestOwnedServicesStop(
            restartAfterStop: false,
            terminalShutdown: true,
            completion: completion
        )
    }

    private func requestOwnedServicesStop(
        restartAfterStop: Bool,
        terminalShutdown: Bool,
        preservePendingAutomaticRestart: Bool = false,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [self] in
                requestOwnedServicesStop(
                    restartAfterStop: restartAfterStop,
                    terminalShutdown: terminalShutdown,
                    preservePendingAutomaticRestart: preservePendingAutomaticRestart,
                    completion: completion
                )
            }
            return
        }

        // Any explicit stop (including provider mutation, thermal shutdown,
        // and Quit) supersedes a delayed Harness crash recovery. Ollama's own
        // stop-and-recover path may preserve only its separately gated retry.
        harnessAutomaticRestartGate.cancel()
        harnessStableReadinessBeganAt = nil
        if !preservePendingAutomaticRestart {
            ollamaAutomaticRestartGate.cancel()
            ollamaStableReadinessBeganAt = nil
        }
        if terminalShutdown { terminalShutdownRequested = true }
        if restartAfterStop, terminalShutdownRequested {
            completion(.failure(LocalHarnessError.applicationTerminationInProgress))
            return
        }

        intentionalStop = true
        isStarting = false
        isStartingOllamaOnly = false
        let capturedStartupPrerequisite = startupPrerequisiteCancellation
        capturedStartupPrerequisite?.cancel()
        startupPrerequisiteCancellation = nil
        startupGeneration &+= 1
        setEndpoint(nil)

        if let stopGeneration {
            stopGeneration.completions.append(completion)
            // Latest explicit intent wins. In particular, Quit's plain stop
            // must cancel a restart already waiting on this same generation;
            // otherwise the barrier could launch a new child just before the
            // application exits and leave it outside the captured PID set.
            stopGeneration.restartRequested = terminalShutdownRequested ? false : restartAfterStop
            if restartAfterStop, !terminalShutdownRequested {
                pendingRestartLaunchMode = .inference
                pendingOllamaPrerequisiteRecoveryIssue = nil
            }
            return
        }

        let ownedHarness = ownsHarness ? harnessProcess : nil
        let ownedOllama = ownsOllama ? ollamaProcess : nil
        ownedHarness?.terminationHandler = nil
        ownedOllama?.terminationHandler = nil

        nextStopGeneration &+= 1
        let generation = OwnedServicesStopGeneration(
            identifier: nextStopGeneration,
            harnessProcess: ownedHarness,
            ollamaProcess: ownedOllama,
            startupPrerequisite: capturedStartupPrerequisite,
            restartRequested: restartAfterStop,
            completion: completion
        )
        stopGeneration = generation
        if restartAfterStop {
            pendingRestartLaunchMode = .inference
            pendingOllamaPrerequisiteRecoveryIssue = nil
        }

        if let startupPrerequisite = generation.startupPrerequisite,
           !generation.startupPrerequisiteSettled {
            startupPrerequisite.notifyWhenSettled { [weak self, weak generation] in
                guard let self, let generation else { return }
                self.recordStartupPrerequisiteSettlement(generation)
            }
        }

        // Iterate the captured pending identities, not a second `isRunning`
        // snapshot. If a child exits between capture and this loop, its monitor
        // still observes that exit and releases the generation instead of
        // leaving an unfulfilled pending entry behind.
        for process in generation.processes
        where generation.pendingProcesses.contains(ObjectIdentifier(process)) {
            stopOwnedProcess(process) { result in
                self.recordProcessStop(result, process: process, generation: generation)
            }
        }
        finishStopGenerationIfReady(generation)
    }

    private func recordStartupPrerequisiteSettlement(_ generation: OwnedServicesStopGeneration) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self, weak generation] in
                guard let self, let generation else { return }
                self.recordStartupPrerequisiteSettlement(generation)
            }
            return
        }
        guard stopGeneration === generation else { return }
        generation.startupPrerequisiteSettled = true
        finishStopGenerationIfReady(generation)
    }

    private func recordProcessStop(
        _ result: Result<Void, Error>,
        process: Process,
        generation: OwnedServicesStopGeneration
    ) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [self] in
                recordProcessStop(result, process: process, generation: generation)
            }
            return
        }
        guard stopGeneration === generation else { return }
        let identity = ObjectIdentifier(process)
        guard generation.pendingProcesses.remove(identity) != nil else { return }
        if case .failure = result { generation.failedPIDs.insert(process.processIdentifier) }
        finishStopGenerationIfReady(generation)
    }

    private func finishStopGenerationIfReady(_ generation: OwnedServicesStopGeneration) {
        guard stopGeneration === generation,
              generation.pendingProcesses.isEmpty,
              generation.startupPrerequisiteSettled else { return }

        // A stopper cannot authorize a replacement merely by replying success:
        // the captured Process objects themselves must all report reaped first.
        for process in generation.processes where process.isRunning {
            generation.failedPIDs.insert(process.processIdentifier)
        }

        let completions = generation.completions
        guard generation.failedPIDs.isEmpty else {
            stopGeneration = nil
            let error = LocalHarnessError.serviceShutdownTimedOut(generation.failedPIDs.sorted())
            publish(.failed("The previous local runtime did not stop safely: \(error.localizedDescription)"))
            for completion in completions { completion(.failure(error)) }
            return
        }

        // Clear ownership only after every exact captured child has exited. An
        // unrelated or later Process object can never be cleared by this pass.
        if let captured = generation.harnessProcess, harnessProcess === captured {
            harnessProcess = nil
            setOwnsHarness(false)
        }
        if let captured = generation.ollamaProcess, ollamaProcess === captured {
            ollamaProcess = nil
            ownsOllama = false
            ollamaEndpoint = nil
            ollamaExecutableIdentity = nil
            ollamaModelConfiguration = nil
        }
        stopGeneration = nil
        publish(.stopped)

        if generation.restartRequested, !terminalShutdownRequested {
            intentionalStop = false
            let replacementMode = pendingRestartLaunchMode
            lifecycleReplacementModeObserver?(replacementMode == .providerRecovery)
            if let lifecycleStartReplacement {
                lifecycleStartReplacement()
            } else {
                prepareAndStart(
                    mode: replacementMode,
                    ollamaRecoveryIssue: replacementMode == .providerRecovery
                        ? pendingOllamaPrerequisiteRecoveryIssue
                        : nil
                )
            }
        }
        for completion in completions { completion(.success(())) }
    }

    func restartServices(completion: @escaping (Result<Void, Error>) -> Void) {
        guard !harnessHomeRecoveryInFlight else {
            completion(.failure(HarnessHomeError.receiptlessRecoveryStateChanged))
            return
        }
        requestOwnedServicesStop(
            restartAfterStop: true,
            terminalShutdown: false,
            completion: completion
        )
    }

    /// Terminates the exact captured Process and escalates only that PID. Kept
    /// internal so the release suite can prove a TERM-resistant owned process
    /// is reaped without touching an unrelated sibling process.
    func stopOwnedProcess(
        _ process: Process,
        forceKillAfter: TimeInterval = 4,
        failAfter: TimeInterval = 7,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        if let lifecycleStopProcess {
            lifecycleStopProcess(process, completion)
            return
        }
        OwnedProcessStopMonitor(
            process: process,
            forceKillAfter: forceKillAfter,
            failAfter: failAfter,
            completion: completion
        ).start()
    }

    func probeHarness(completion: @escaping (Bool) -> Void) {
        guard let endpoint else {
            DispatchQueue.main.async { completion(false) }
            return
        }
        probeIdentity(endpoint, completion: completion)
    }

    func reportReady() {
        guard stopGeneration == nil,
              !intentionalStop,
              harnessProcess?.isRunning == true,
              endpoint != nil else { return }
        publish(activeLaunchMode == .providerRecovery ? .providerRecovery : .ready(managedByApp: true))
        beginStableHarnessReadinessWindow()
        if activeLaunchMode == .inference,
           selectedProviderNeedsOllama,
           ollamaProcess?.isRunning == true {
            beginStableOllamaReadinessWindow()
        }
    }

    private func beginStableHarnessReadinessWindow() {
        let began = Date()
        harnessStableReadinessBeganAt = began
        let token = harnessAutomaticRestartGate.generation
        DispatchQueue.main.asyncAfter(
            deadline: .now() + BoundedRuntimeRestartCircuit.productionWindow
        ) { [weak self] in
            guard let self,
                  self.harnessAutomaticRestartGate.admits(token),
                  self.harnessStableReadinessBeganAt == began,
                  self.stopGeneration == nil,
                  !self.intentionalStop,
                  !self.terminalShutdownRequested,
                  self.harnessProcess?.isRunning == true,
                  self.endpoint != nil,
                  self.currentState == .providerRecovery || {
                      if case .ready = self.currentState { return true }
                      return false
                  }() else { return }
            self.harnessRestartCircuit.resetAfterStableReadiness(startedAt: began, now: Date())
        }
    }

    private func beginStableOllamaReadinessWindow() {
        let began = Date()
        ollamaStableReadinessBeganAt = began
        let token = ollamaAutomaticRestartGate.generation
        DispatchQueue.main.asyncAfter(
            deadline: .now() + BoundedRuntimeRestartCircuit.productionWindow
        ) { [weak self] in
            guard let self,
                  self.ollamaAutomaticRestartGate.admits(token),
                  self.ollamaStableReadinessBeganAt == began,
                  self.stopGeneration == nil,
                  !self.intentionalStop,
                  !self.terminalShutdownRequested,
                  self.harnessProcess?.isRunning == true,
                  self.ollamaProcess?.isRunning == true,
                  case .ready = self.currentState else { return }
            self.ollamaRestartCircuit.resetAfterStableReadiness(startedAt: began, now: Date())
        }
    }
    func runtimeInfo() -> RuntimeInfo? { try? locateHarnessRuntime() }
    func pluginFindings() -> [PluginTrustFinding] { pluginTrustStore.audit() }
    func approvePlugin(_ finding: PluginTrustFinding) throws { throw LocalHarnessError.communityPluginsDisabled }
    func revokePlugin(name: String) throws { try pluginTrustStore.revoke(name: name) }

    /// Returns the single process-lifetime skill store after the startup worker
    /// has atomically prepared HarnessHome. UI construction must never create
    /// directories inside an uncommitted former home.
    func skillsTrustStore() throws -> SkillsTrustStore {
        guard let skillsTrustStoreInstance else {
            throw LocalHarnessError.harnessHomeNotPrepared
        }
        return skillsTrustStoreInstance
    }

    /// Returns the process-lifetime MCP trust store. Definitions contain no
    /// credential values; approval remains bound to exact project, executable,
    /// reviewed files, provider, and data-boundary fingerprints.
    func mcpTrustStore() throws -> MCPTrustStore {
        if let mcpTrustStoreInstance { return mcpTrustStoreInstance }
        let store = try MCPTrustStore(applicationSupport: diagnosticsDirectory())
        mcpTrustStoreInstance = store
        return store
    }

    func skillActivationPlan(for boundary: SkillExecutionBoundary) throws -> SkillActivationPlan {
        try skillsTrustStore().activationPlan(
            projectID: SkillsProjectIdentity.identifier(for: workspaceDirectory()),
            boundary: boundary
        )
    }

    /// Stores only process-lifetime approval. It is never written to disk and
    /// is ignored unless the next runtime uses the exact same boundary.
    func prepareSkillActivation(
        for boundary: SkillExecutionBoundary,
        oneTimeCloudApprovals: Set<String> = []
    ) {
        preparedSkillBoundary = boundary
        self.oneTimeSkillCloudApprovals = boundary == .external ? oneTimeCloudApprovals : []
    }

    private static func resolvedApplicationSupportDirectory(
        override: URL?,
        fileManager: FileManager = .default
    ) -> URL {
        if let override {
            return override.standardizedFileURL
        }
        let base = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
        return base.appendingPathComponent("Local Harness", isDirectory: true)
    }

    private func applicationSupportDirectoryURL() -> URL {
        Self.resolvedApplicationSupportDirectory(
            override: applicationSupportOverride,
            fileManager: fileManager
        )
    }

    /// The first native-state admission gate. It retains and revalidates the
    /// exact private Application Support root before any child store may be
    /// constructed. A failure is terminal for this controller instance.
    func admitApplicationSupportRoot() -> Result<URL, ApplicationSupportRootAdmissionError> {
        applicationSupportRootAdmission.admit()
    }

    func diagnosticsDirectory() -> URL {
        switch admitApplicationSupportRoot() {
        case .success(let directory):
            return directory
        case .failure:
            // Every legacy/lazy caller remains unable to write through an
            // unsafe user path. `/dev/null` is a character device, so this
            // child can never resolve to or alias user state and every child
            // write fails with ENOTDIR. Startup surfaces the typed failure.
            return ApplicationSupportRootAdmission.unavailableSink
        }
    }

    func harnessHomeDirectory() -> URL {
        applicationSupportDirectoryURL().appendingPathComponent("HarnessHome", isDirectory: true)
    }

    /// The single user-workspace root shared by DSH sessions and the per-tool
    /// sandbox. Keeping this path authoritative prevents a conversation from
    /// being created somewhere the tool runner cannot read or write.
    func workspaceDirectory() -> URL {
        diagnosticsDirectory().appendingPathComponent("Workspace", isDirectory: true)
    }

    func recentLogs(maxCharacters: Int = 16_000) -> String {
        logStore.recentLogs(maxCharacters: maxCharacters)
    }

    private func prepareHarnessLaunch(
        mode: LaunchMode,
        applicationSupport: URL,
        harnessHome: URL,
        harnessHomeCapability: HarnessHomeAttestationCapability,
        workspace: URL,
        allowSSHAgent: Bool,
        preparedBoundary: SkillExecutionBoundary?,
        cloudApprovals: Set<String>,
        existingSkillStore: SkillsTrustStore?,
        existingMCPStore: MCPTrustStore?,
        ownedOllama: RequiredOwnedOllamaSnapshot?,
        cancellation: RuntimeStartupPrerequisiteCancellation,
        budget: RuntimeStartupPrerequisiteBudget,
        phaseHook: ((RuntimeStartupPrerequisitePhase, RuntimeStartupPrerequisiteCancellation) throws -> Void)?
    ) throws -> PreparedHarnessLaunch {
        try budget.checkpoint()
        let performanceTelemetryFile = GenerationTelemetrySpool.prepareIfAvailable(
            applicationSupport: applicationSupport
        )
        let thermalWorkloadPolicyFile = try ThermalWorkloadPolicyStore.prepare(
            applicationSupport: applicationSupport
        )
        try budget.checkpoint()
        let runtime = try locateHarnessRuntime()
        try budget.checkpoint()
        let preloader = try locateSecurityPreloader()
        let credentialRuntime = try locateCredentialRuntime(for: runtime)
        let sandboxHelper = try locateSandboxHelper()
        let runtimeLease = try locateRuntimeLease()
        try budget.checkpoint()
        let token = try SecureTokenGenerator.generate()
        let nonce = try SecureTokenGenerator.generate(byteCount: 24)
        let selected = mode == .providerRecovery
            ? ModelSelection.defaultLocal
            : try ModelProviderSettingsStore().loadOrMigrate().settings.defaultSelection
        let consent = mode == .providerRecovery ? ProviderConsentState() : try ProviderConsentStore().load()
        try budget.checkpoint()
        let allowedProviderOrigins = mode == .providerRecovery
            ? Set<ProviderNetworkOrigin>()
            : ProviderEgressPolicy.allowedOrigins(selection: selected, consent: consent)
        let selectedBoundary = mode == .providerRecovery
            ? nil
            : consent.activeGrant(for: selected.route.provider)?.boundary
        // First-run Ollama starts in a loopback-only bootstrap. The native host
        // verifies the live catalog before exposing the UI or starting
        // schedules. A configured remote Ollama therefore cannot inherit the
        // opaque ID's historical on-device classification.
        let isFirstRunLoopbackBootstrap = mode == .inference
            && selected.route.provider == BuiltInProviderDescriptors.ollama.id
            && selectedBoundary == nil
        let isOnDevice = selectedBoundary == .onDevice || isFirstRunLoopbackBootstrap
        if mode == .inference, !isOnDevice, allowedProviderOrigins.isEmpty {
            throw LocalHarnessError.providerConsentUnavailable
        }
        let strictLocal = allowedProviderOrigins.isEmpty
        var runtimeProviderOrigins = allowedProviderOrigins
        var localOllamaAvailable = false
        if mode == .inference,
           isOnDevice,
           selected.route.provider == BuiltInProviderDescriptors.ollama.id {
            guard let ownedOllama,
                  let expectedConfiguration = AppOwnedOllamaModelConfiguration(selection: selected),
                  ownedOllama.modelConfiguration == expectedConfiguration else {
                throw OllamaPrerequisiteRecoveryIssue.ownershipVerificationFailed
            }
            runtimeProviderOrigins.insert(ownedOllama.endpoint.networkOrigin)
            localOllamaAvailable = true
        }
        let providerOrigins: String
        if runtimeProviderOrigins.isEmpty {
            providerOrigins = "[]"
        } else {
            guard let runtimeBoundary = isOnDevice ? DataBoundary.onDevice : selectedBoundary else {
                throw LocalHarnessError.providerConsentUnavailable
            }
            providerOrigins = ProviderEgressPolicy.serializedAllowlist(
                origins: runtimeProviderOrigins,
                boundary: runtimeBoundary
            )
        }
        let nodeArguments = [
            "--import", preloader.path,
            runtime.script.path, "web", "--patch", credentialRuntime.patch.path,
            "--no-open", "--host", "127.0.0.1", "--port", "0"
        ]
        let workingDirectory = workspace
        try fileManager.createDirectory(at: workingDirectory, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: workingDirectory.path)
        let privateTemp = harnessHome.appendingPathComponent("Temp", isDirectory: true)
        try fileManager.createDirectory(at: privateTemp, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: privateTemp.path)
        try budget.checkpoint()
        let canonicalWorkspace = workingDirectory.resolvingSymlinksInPath().standardizedFileURL
        let workspaceRootsData = try JSONEncoder().encode([canonicalWorkspace.path])
        guard let workspaceRootsJSON = String(data: workspaceRootsData, encoding: .utf8) else {
            throw LocalHarnessError.sandboxUnavailable
        }
        let skillStore = try existingSkillStore ?? SkillsTrustStore(
            applicationSupport: applicationSupport,
            harnessHome: harnessHome
        )
        let skillBoundary: SkillExecutionBoundary = isOnDevice ? .local : .external
        let skillActivation: SkillActivationResult
        try phaseHook?(.skillActivation, cancellation)
        try budget.checkpoint()
        if mode == .providerRecovery {
            try skillStore.deactivateAll()
            skillActivation = SkillActivationResult(
                projectID: SkillsProjectIdentity.identifier(for: canonicalWorkspace),
                boundary: .local,
                activeSkills: [],
                runtimeRoot: skillStore.runtimeRoot
            )
        } else {
            let approvals = preparedBoundary == skillBoundary ? cloudApprovals : []
            skillActivation = try skillStore.activate(
                projectID: SkillsProjectIdentity.identifier(for: canonicalWorkspace),
                boundary: skillBoundary,
                oneTimeCloudApprovals: approvals,
                preparationBudget: budget
            )
        }
        try skillStore.validateActiveCatalog(
            against: skillActivation,
            preparationBudget: budget
        )
        let canonicalSkillRoot = skillActivation.runtimeRoot.resolvingSymlinksInPath().standardizedFileURL
        let readOnlyRootsData = try JSONEncoder().encode([canonicalSkillRoot.path])
        guard let readOnlyRootsJSON = String(data: readOnlyRootsData, encoding: .utf8) else {
            throw LocalHarnessError.sandboxUnavailable
        }
        try budget.checkpoint()
        try phaseHook?(.sandboxBoundary, cancellation)
        try verifySandboxBoundary(
            helper: sandboxHelper,
            workspace: canonicalWorkspace,
            privateTemp: privateTemp,
            workspaceRootsJSON: workspaceRootsJSON,
            readOnlySkillRoot: canonicalSkillRoot,
            readOnlyRootsJSON: readOnlyRootsJSON,
            applicationSupport: applicationSupport,
            harnessHome: harnessHome,
            budget: budget
        )
        // The boundary probe briefly creates an inert hidden sentinel in the
        // exposed root. Re-verify the exact catalog after it has been removed.
        try skillStore.validateActiveCatalog(
            against: skillActivation,
            preparationBudget: budget
        )
        let providerBoundary: DataBoundary = isOnDevice ? .onDevice : (selectedBoundary ?? .cloud)
        try budget.checkpoint()
        try phaseHook?(.mcpActivation, cancellation)
        let preparedMCPStore: MCPTrustStore?
        let mcpCatalog: URL
        if mode == .providerRecovery {
            preparedMCPStore = existingMCPStore
            mcpCatalog = try MCPActivationCatalogWriter.write(
                plans: [],
                applicationSupport: applicationSupport
            )
        } else {
            let store = try existingMCPStore ?? MCPTrustStore(applicationSupport: applicationSupport)
            preparedMCPStore = store
            let context = MCPActivationContext(
                projectRoot: canonicalWorkspace,
                provider: selected.route.provider,
                providerBoundary: providerBoundary
            )
            let plans = try MCPActivationCatalogBuilder.revalidatedPlans(
                store: store,
                context: context,
                preparationBudget: budget
            )
            mcpCatalog = try MCPActivationCatalogWriter.write(
                plans: plans,
                applicationSupport: applicationSupport
            )
        }
        try budget.checkpoint()
        let environment = ChildProcessEnvironment.make(
            nodeBin: runtime.node.deletingLastPathComponent().path,
            allowSSHAgent: allowSSHAgent,
            homeDirectory: harnessHome,
            temporaryDirectory: privateTemp,
            additions: HarnessProcessEnvironment.additions(
                credentialPlugin: credentialRuntime.credentialPlugin.path,
                mcpPlugin: credentialRuntime.mcpPlugin.path,
                clientSecurityPlugin: credentialRuntime.clientSecurityPlugin.path,
                performancePlugin: credentialRuntime.performancePlugin.path,
                credentialHelper: credentialRuntime.helper.path,
                sandboxHelper: sandboxHelper.path,
                strictLocal: strictLocal,
                localOllamaAvailable: localOllamaAvailable,
                performanceProfile: selected.performanceProfile,
                performanceSettings: selected.effectivePerformanceSettings,
                activeProvider: mode == .inference ? selected.route.provider : nil,
                contextEnforcementRoute: mode == .inference
                    && isOnDevice
                    && selected.route.provider == BuiltInProviderDescriptors.ollama.id
                    ? selected.route
                    : nil,
                providerOriginsJSON: providerOrigins,
                runtimeRoot: runtime.script.deletingLastPathComponent().deletingLastPathComponent().path,
                workspaceRootsJSON: workspaceRootsJSON,
                readOnlyRootsJSON: readOnlyRootsJSON,
                sandboxTempPath: privateTemp.path,
                confinedFilesystemPlugin: credentialRuntime.filesystemPlugin.path,
                mcpCatalogPath: mcpCatalog.path,
                applicationSupportRoot: applicationSupport.path,
                performanceTelemetryFile: performanceTelemetryFile?.path,
                thermalWorkloadPolicyFile: thermalWorkloadPolicyFile.path,
                forbidCredentialHelper: forbidCredentialHelper
            ).merging([
                "DSH_HOME": harnessHome.path,
                "DSH_AGENTS_HOME": harnessHome.appendingPathComponent("Agents", isDirectory: true).path
            ]) { _, isolated in isolated }
        )

        if let ownedOllama,
           mode == .inference,
           isOnDevice,
           selected.route.provider == BuiltInProviderDescriptors.ollama.id {
            guard OllamaExecutableTrust.process(
                ownedOllama.processIdentifier,
                matches: ownedOllama.executableIdentity
            ), OwnedLoopbackListenerVerifier.process(
                ownedOllama.processIdentifier,
                owns: ownedOllama.endpoint
            ) else {
                throw OllamaPrerequisiteRecoveryIssue.ownershipVerificationFailed
            }
        }
        try budget.checkpoint()

        var identities: [RuntimeLaunchPathIdentity] = []
        for url in [
            runtime.node, runtime.script, preloader, credentialRuntime.patch,
            credentialRuntime.credentialPlugin, credentialRuntime.filesystemPlugin,
            credentialRuntime.mcpPlugin, credentialRuntime.clientSecurityPlugin,
            credentialRuntime.performancePlugin, credentialRuntime.webFetchPlugin,
            credentialRuntime.helper,
            sandboxHelper, runtimeLease, mcpCatalog
        ] {
            identities.append(try RuntimeLaunchPathIdentity.capture(url, kind: .regular))
        }
        for url in [harnessHome, canonicalWorkspace, privateTemp, canonicalSkillRoot] {
            identities.append(try RuntimeLaunchPathIdentity.capture(url, kind: .directory))
        }
        if let performanceTelemetryFile {
            identities.append(try RuntimeLaunchPathIdentity.capture(performanceTelemetryFile, kind: .regular))
        }
        let runtimeWriteSandbox = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: applicationSupport,
            harnessHome: harnessHome,
            workspace: canonicalWorkspace,
            telemetryDirectory: performanceTelemetryFile?.deletingLastPathComponent()
        )
        try budget.checkpoint()
        let authenticationInput = try RuntimeAuthenticationInput(authToken: token, nonce: nonce)
        try budget.checkpoint()
        return PreparedHarnessLaunch(
            executable: runtimeLease,
            arguments: ["--fulmar-runtime-auth-stdin-v1", runtime.node.path] + nodeArguments,
            runtimeWriteSandbox: runtimeWriteSandbox,
            currentDirectory: workingDirectory,
            environment: environment,
            authenticationInput: authenticationInput,
            authToken: token,
            nonce: nonce,
            strictLocal: strictLocal,
            telemetryUnavailable: performanceTelemetryFile == nil,
            pathIdentities: identities,
            requiredOllama: localOllamaAvailable ? ownedOllama : nil,
            skillStore: skillStore,
            mcpStore: preparedMCPStore,
            harnessHomeCapability: harnessHomeCapability
        )
    }

    private func commitHarnessLaunch(
        _ prepared: PreparedHarnessLaunch,
        generation: UInt64,
        capabilityGeneration: UInt64
    ) throws {
        guard Thread.isMainThread,
              startupGeneration == generation,
              stopGeneration == nil,
              !intentionalStop,
              !terminalShutdownRequested,
              harnessProcess?.isRunning != true else {
            throw LocalHarnessError.serviceStartCancelled
        }
        let capabilitySnapshot = harnessHomeAdmissionVault.snapshot()
        guard capabilitySnapshot.generation == capabilityGeneration,
              capabilitySnapshot.capability === prepared.harnessHomeCapability,
              !capabilitySnapshot.recoveryInFlight,
              !capabilitySnapshot.ownsHarness else {
            throw LocalHarnessError.serviceStartCancelled
        }
        try HarnessHomeAttestationStore.revalidateCapability(
            prepared.harnessHomeCapability,
            rootURL: harnessHomeDirectory(),
            receiptLeafName: ProviderHistoryPrivacyEpoch.ownershipReceiptName,
            expectedPrivacyEpoch: UInt64(ProviderHistoryPrivacyEpoch.current)
        )
        for identity in prepared.pathIdentities { try identity.revalidate() }
        if let required = prepared.requiredOllama {
            guard let process = ollamaProcess,
                  process.isRunning,
                  process.processIdentifier == required.processIdentifier,
                  ownsOllama,
                  ollamaEndpoint == required.endpoint,
                  ollamaExecutableIdentity == required.executableIdentity,
                  ollamaModelConfiguration == required.modelConfiguration,
                  OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: required.endpoint) else {
                throw OllamaPrerequisiteRecoveryIssue.ownershipVerificationFailed
            }
            try OllamaExecutableTrust.revalidateFilesystemIdentity(required.executableIdentity)
        }

        preferences.strictLocalMode = prepared.strictLocal
        skillsTrustStoreInstance = prepared.skillStore
        if let mcpStore = prepared.mcpStore { mcpTrustStoreInstance = mcpStore }
        if prepared.telemetryUnavailable {
            appendLog(
                Data("Performance telemetry is unavailable; inference will continue without persistent metrics.\n".utf8),
                label: "supervisor"
            )
        }

        let process = Process()
        let authenticationInput = try prepared.authenticationInput.takeForLaunch()
        defer { try? authenticationInput.close() }
        let wrapped = try prepared.runtimeWriteSandbox.wrappedLaunch(
            executable: prepared.executable,
            arguments: prepared.arguments
        )
        process.executableURL = wrapped.executable
        process.arguments = wrapped.arguments
        process.currentDirectoryURL = prepared.currentDirectory
        process.environment = prepared.environment
        process.standardInput = authenticationInput
        attachLogging(to: process, label: "dsh", parseRuntimeURL: true) { [weak self, weak process] port in
            guard let self,
                  let process,
                  process.isRunning,
                  self.harnessProcess === process,
                  !self.terminalShutdownRequested,
                  self.stopGeneration == nil,
                  !self.intentionalStop else { return }
            guard let baseURL = URL(string: "http://127.0.0.1:\(port)/") else {
                self.failRuntimeStartAfterCleaningOwnedServices(
                    LocalHarnessError.runtimeIntegrityChanged
                )
                return
            }
            self.setEndpoint(HarnessEndpoint(
                baseURL: baseURL,
                token: prepared.authToken,
                nonce: prepared.nonce,
                processIdentifier: process.processIdentifier
            ))
        }
        process.terminationHandler = { [weak self] process in
            DispatchQueue.main.async {
                guard let self, self.harnessProcess === process else { return }
                // A termination notification may already be queued when a
                // stop generation detaches the handler. The generation owns
                // all clearing/reaping in that case; this late callback must
                // not publish stopped or discard the exact retained process.
                if self.stopGeneration?.captures(process) == true { return }
                self.harnessProcess = nil
                self.setOwnsHarness(false)
                self.setEndpoint(nil)
                guard !self.intentionalStop else { return }
                self.handleUnexpectedHarnessExit(status: process.terminationStatus)
            }
        }
        try process.run()
        harnessProcess = process
        setOwnsHarness(true)
    }

    private func handleUnexpectedHarnessExit(status: Int32) {
        appendLog(Data("Harness exited with status \(status).\n".utf8), label: "supervisor")
        harnessStableReadinessBeganAt = nil
        let decision = preferences.autoRestartHarness
            ? harnessRestartCircuit.recordFailure(at: Date())
            : .exhausted
        let token = harnessAutomaticRestartGate.begin()
        guard case .retry(let delay) = decision else {
            publish(.failed("Harness stopped unexpectedly. Automatic recovery was exhausted; open Diagnostics for details."))
            return
        }
        publish(.startingHarness)
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self,
                  self.harnessAutomaticRestartGate.admits(token),
                  !self.intentionalStop,
                  !self.terminalShutdownRequested,
                  self.stopGeneration == nil,
                  self.harnessProcess == nil else { return }
            if self.activeLaunchMode == .providerRecovery {
                self.prepareAndStart(
                    mode: .providerRecovery,
                    ollamaRecoveryIssue: self.ollamaPrerequisiteRecoveryIssue
                )
            } else {
                self.prepareAndStart()
            }
        }
    }

    private func launchPreparedOllama(
        _ plan: AppOwnedOllamaLaunchPlan,
        leaseIdentity: RuntimeLaunchPathIdentity,
        reservation: LoopbackPortReservation,
        generation: UInt64
    ) throws {
        guard Thread.isMainThread,
              startupGeneration == generation,
              !terminalShutdownRequested,
              stopGeneration == nil,
              !intentionalStop,
              ollamaProcess?.isRunning != true,
              reservation.endpoint == plan.endpoint else {
            throw LocalHarnessError.serviceStartCancelled
        }
        try leaseIdentity.revalidate()
        try OllamaExecutableTrust.revalidateFilesystemIdentity(plan.identity)
        try plan.sandbox.revalidateModelStoreIdentity()
        let process = Process()
        process.executableURL = leaseIdentity.url
        process.arguments = [plan.processExecutable.path] + plan.arguments
        process.currentDirectoryURL = plan.currentDirectory
        process.environment = plan.environment
        attachLogging(to: process, label: "ollama", parseRuntimeURL: false, onPort: nil)
        process.terminationHandler = { [weak self] process in
            DispatchQueue.main.async {
                guard let self, self.ollamaProcess === process else { return }
                if self.stopGeneration?.captures(process) == true { return }
                self.ollamaProcess = nil
                self.ownsOllama = false
                self.ollamaEndpoint = nil
                self.ollamaExecutableIdentity = nil
                self.ollamaModelConfiguration = nil
                self.ollamaStableReadinessBeganAt = nil
                guard !self.isStarting,
                      !self.isStartingOllamaOnly,
                      !self.intentionalStop,
                      !self.terminalShutdownRequested,
                      self.activeLaunchMode == .inference,
                      self.selectedProviderNeedsOllama else { return }
                self.handleUnexpectedOllamaExit(status: process.terminationStatus)
            }
        }
        reservation.releaseForLaunch()
        do {
            try process.run()
        } catch {
            process.terminationHandler = nil
            throw error
        }
        ollamaProcess = process
        ownsOllama = true
        ollamaEndpoint = plan.endpoint
        ollamaExecutableIdentity = plan.identity
        ollamaModelConfiguration = plan.modelConfiguration
    }

    private func handleUnexpectedOllamaExit(status: Int32) {
        let decision = preferences.autoRestartHarness
            ? ollamaRestartCircuit.recordFailure(at: Date())
            : .exhausted
        let token = ollamaAutomaticRestartGate.begin()
        let detail: String
        switch decision {
        case .retry(let delay):
            detail = "Owned Ollama exited with status \(status); bounded recovery will retry after \(delay) seconds."
        case .exhausted:
            detail = "Owned Ollama exited with status \(status); bounded automatic recovery is exhausted."
        }
        appendLog(Data("\(detail)\n".utf8), label: "supervisor")

        requestOwnedServicesStop(
            restartAfterStop: false,
            terminalShutdown: false,
            preservePendingAutomaticRestart: true
        ) { [weak self] stopResult in
            guard let self, self.ollamaAutomaticRestartGate.admits(token) else { return }
            guard case .success = stopResult else { return }
            switch decision {
            case .exhausted:
                self.publish(.failed("The local model service stopped repeatedly. Automatic recovery was stopped to protect this Mac. Repair or update Ollama, choose a different admitted model, or use an API provider."))
            case .retry(let delay):
                self.publish(.checking)
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                    guard let self,
                          self.ollamaAutomaticRestartGate.admits(token),
                          !self.terminalShutdownRequested,
                          self.stopGeneration == nil,
                          self.currentState == .checking else { return }
                    self.prepareAndStart()
                }
            }
        }
    }

    private func locateHarnessRuntime() throws -> RuntimeInfo {
        let location = try HarnessRuntimeLocator.locate(
            bundleURL: Bundle.main.bundleURL,
            resources: Bundle.main.resourceURL,
            home: fileManager.homeDirectoryForCurrentUser,
            fileManager: fileManager
        )
        return RuntimeInfo(
            node: location.node,
            script: location.script,
            dshVersion: location.dshVersion,
            bundled: location.bundled
        )
    }

    private func locateSecurityPreloader() throws -> URL {
        if let bundled = Bundle.main.url(forResource: "RuntimeSecurityPreload", withExtension: "mjs") { return bundled }
        let development = URL(fileURLWithPath: fileManager.currentDirectoryPath)
            .appendingPathComponent("Resources/RuntimeSecurityPreload.mjs")
        if fileManager.fileExists(atPath: development.path) { return development }
        throw RuntimeSecurityError.securityPreloaderMissing
    }

    private func locateCredentialRuntime(
        for runtime: RuntimeInfo
    ) throws -> (
        patch: URL,
        credentialPlugin: URL,
        filesystemPlugin: URL,
        mcpPlugin: URL,
        clientSecurityPlugin: URL,
        performancePlugin: URL,
        webFetchPlugin: URL,
        helper: URL
    ) {
        if runtime.bundled,
           let resources = Bundle.main.resourceURL,
           let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() {
            let runtimeRoot = runtime.script.deletingLastPathComponent().deletingLastPathComponent()
            let result = (
                patch: resources.appendingPathComponent("LocalHarness.patch.yml"),
                credentialPlugin: runtimeRoot
                    .appendingPathComponent("node_modules/@local-harness/dsh-credentials-keychain/index.mjs"),
                filesystemPlugin: runtimeRoot
                    .appendingPathComponent("node_modules/@local-harness/dsh-fs-confined/index.mjs"),
                mcpPlugin: runtimeRoot
                    .appendingPathComponent("node_modules/@local-harness/dsh-mcp-guarded/index.mjs"),
                clientSecurityPlugin: runtimeRoot
                    .appendingPathComponent("node_modules/@local-harness/dsh-client-security-bridge/index.mjs"),
                performancePlugin: runtimeRoot
                    .appendingPathComponent("node_modules/@local-harness/dsh-performance-profile/index.mjs"),
                webFetchPlugin: runtimeRoot
                    .appendingPathComponent("node_modules/@local-harness/dsh-web-fetch-safe/index.mjs"),
                helper: executableDirectory.appendingPathComponent("LocalHarnessCredentialHelper")
            )
            if fileManager.fileExists(atPath: result.patch.path),
               fileManager.fileExists(atPath: result.credentialPlugin.path),
               fileManager.fileExists(atPath: result.filesystemPlugin.path),
               fileManager.fileExists(atPath: result.mcpPlugin.path),
               fileManager.fileExists(atPath: result.clientSecurityPlugin.path),
               fileManager.fileExists(atPath: result.performancePlugin.path),
               fileManager.fileExists(atPath: result.webFetchPlugin.path),
               fileManager.isExecutableFile(atPath: result.helper.path) { return result }
        }

        let project = URL(fileURLWithPath: fileManager.currentDirectoryPath)
        let result = (
            patch: project.appendingPathComponent("Resources/LocalHarness.patch.yml"),
            credentialPlugin: project.appendingPathComponent("Resources/DSHPlugins/credentials-keychain/index.mjs"),
            filesystemPlugin: project.appendingPathComponent("Resources/DSHPlugins/fs-confined/index.mjs"),
            mcpPlugin: project.appendingPathComponent("Resources/DSHPlugins/mcp-guarded/index.mjs"),
            clientSecurityPlugin: project.appendingPathComponent("Resources/DSHPlugins/client-security-bridge/index.mjs"),
            performancePlugin: project.appendingPathComponent("Resources/DSHPlugins/performance-profile/index.mjs"),
            webFetchPlugin: project.appendingPathComponent("Resources/DSHPlugins/web-fetch-safe/index.mjs"),
            helper: project.appendingPathComponent(".build/debug/LocalHarnessCredentialHelper")
        )
        guard fileManager.fileExists(atPath: result.patch.path),
              fileManager.fileExists(atPath: result.credentialPlugin.path),
              fileManager.fileExists(atPath: result.filesystemPlugin.path),
              fileManager.fileExists(atPath: result.mcpPlugin.path),
              fileManager.fileExists(atPath: result.clientSecurityPlugin.path),
              fileManager.fileExists(atPath: result.performancePlugin.path),
              fileManager.fileExists(atPath: result.webFetchPlugin.path),
              fileManager.isExecutableFile(atPath: result.helper.path) else {
            throw LocalHarnessError.credentialRuntimeMissing
        }
        return result
    }

    private func locateSandboxHelper() throws -> URL {
        if let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() {
            let bundled = executableDirectory.appendingPathComponent("LocalHarnessSandboxRunner")
            if fileManager.isExecutableFile(atPath: bundled.path) { return bundled }
        }
        let development = URL(fileURLWithPath: fileManager.currentDirectoryPath)
            .appendingPathComponent(".build/debug/LocalHarnessSandboxRunner")
        if fileManager.isExecutableFile(atPath: development.path) { return development }
        throw LocalHarnessError.sandboxHelperMissing
    }

    private func locateRuntimeLease() throws -> URL {
        if let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() {
            let bundled = executableDirectory.appendingPathComponent("LocalHarnessRuntimeLease")
            if fileManager.isExecutableFile(atPath: bundled.path) { return bundled }
        }
        let development = URL(fileURLWithPath: fileManager.currentDirectoryPath)
            .appendingPathComponent(".build/debug/LocalHarnessRuntimeLease")
        if fileManager.isExecutableFile(atPath: development.path) { return development }
        throw LocalHarnessError.runtimeLeaseMissing
    }

    /// Refuses to start the agent runtime unless macOS Seatbelt proves the
    /// exact shipped contract: workspace reads work, reviewed skill resources
    /// are read-only, and a same-owner sentinel outside both remains private.
    private func verifySandboxBoundary(
        helper: URL,
        workspace: URL,
        privateTemp: URL,
        workspaceRootsJSON: String,
        readOnlySkillRoot: URL,
        readOnlyRootsJSON: String,
        applicationSupport: URL,
        harnessHome: URL,
        budget: RuntimeStartupPrerequisiteBudget
    ) throws {
        try budget.checkpoint()
        let allowed = workspace.appendingPathComponent(".local-harness-sandbox-read-probe")
        let readOnly = readOnlySkillRoot.appendingPathComponent(".local-harness-skill-read-probe")
        let deniedDirectory = applicationSupport.appendingPathComponent("SandboxProbe", isDirectory: true)
        try fileManager.createDirectory(at: deniedDirectory, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: deniedDirectory.path)
        let denied = deniedDirectory.appendingPathComponent("outside-workspace-sentinel")
        try Data("LOCAL_HARNESS_OUTSIDE_WORKSPACE_SENTINEL".utf8).write(to: allowed, options: .atomic)
        try Data("LOCAL_HARNESS_READ_ONLY_SKILL_SENTINEL".utf8).write(to: readOnly, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: readOnly.path)
        try Data("LOCAL_HARNESS_OUTSIDE_WORKSPACE_SENTINEL".utf8).write(to: denied, options: .atomic)
        defer {
            try? fileManager.removeItem(at: allowed)
            try? fileManager.removeItem(at: readOnly)
            try? fileManager.removeItem(at: denied)
            try? fileManager.removeItem(at: deniedDirectory)
        }

        func runRead(_ target: URL) throws -> Int32 {
            let deadline = try budget.remainingTimeInterval(maximum: 5)
            guard deadline > 0 else { throw RuntimeStartupPrerequisiteError.timedOut }
            let status = try SandboxBoundaryProbeProcess.run(
                executable: helper,
                arguments: [
                "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
                "--", "/bin/cat", target.path
                ],
                currentDirectory: workspace,
                environment: ChildProcessEnvironment.make(
                    nodeBin: nil,
                    homeDirectory: harnessHome,
                    temporaryDirectory: privateTemp,
                    additions: [
                        "LOCAL_HARNESS_STRICT_LOCAL": "1",
                        "LOCAL_HARNESS_WORKSPACE_ROOTS": workspaceRootsJSON,
                        "LOCAL_HARNESS_READONLY_ROOTS": readOnlyRootsJSON,
                        "LOCAL_HARNESS_SANDBOX_TEMP": privateTemp.path
                    ]
                ),
                deadline: deadline
            )
            try budget.checkpoint()
            return status
        }

        func runWorkspaceWrite(_ target: URL) throws -> Int32 {
            let deadline = try budget.remainingTimeInterval(maximum: 5)
            guard deadline > 0 else { throw RuntimeStartupPrerequisiteError.timedOut }
            let status = try SandboxBoundaryProbeProcess.run(
                executable: helper,
                arguments: [
                    "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
                    "--tmpfs", "/tmp", "--bind", workspace.path, workspace.path,
                    "--", "/usr/bin/touch", target.path
                ],
                currentDirectory: workspace,
                environment: ChildProcessEnvironment.make(
                    nodeBin: nil,
                    homeDirectory: harnessHome,
                    temporaryDirectory: privateTemp,
                    additions: [
                        "LOCAL_HARNESS_STRICT_LOCAL": "1",
                        "LOCAL_HARNESS_WORKSPACE_ROOTS": workspaceRootsJSON,
                        "LOCAL_HARNESS_READONLY_ROOTS": readOnlyRootsJSON,
                        "LOCAL_HARNESS_SANDBOX_TEMP": privateTemp.path
                    ]
                ),
                deadline: deadline
            )
            try budget.checkpoint()
            return status
        }

        guard try runRead(allowed) == 0,
              try runRead(readOnly) == 0,
              try runRead(denied) != 0,
              try runWorkspaceWrite(readOnly) != 0 else {
            throw LocalHarnessError.sandboxUnavailable
        }
    }

    private func attachLogging(
        to process: Process,
        label: String,
        parseRuntimeURL: Bool,
        onPort: ((Int) -> Void)?
    ) {
        let output = Pipe()
        let error = Pipe()
        let outputLogStream = logStore.openStream(label: label)
        let errorLogStream = logStore.openStream(label: "\(label)-error")
        process.standardOutput = output
        process.standardError = error
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self else { return }
            if data.isEmpty {
                handle.readabilityHandler = nil
                self.logStore.finish(outputLogStream)
                return
            }
            self.logStore.append(data, to: outputLogStream)
            if parseRuntimeURL { self.parseRuntimePort(from: data, onPort: onPort) }
        }
        error.fileHandleForReading.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                self.logStore.finish(errorLogStream)
                return
            }
            self.logStore.append(data, to: errorLogStream)
        }
    }

    private func parseRuntimePort(from data: Data, onPort: ((Int) -> Void)?) {
        guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
        outputParsingQueue.async { [weak self] in
            guard let self else { return }
            self.stdoutBuffer.append(text)
            if self.stdoutBuffer.count > 16_384 { self.stdoutBuffer.removeFirst(self.stdoutBuffer.count - 8_192) }
            let pattern = #"dsh web:\s+http://127\.0\.0\.1:(\d{1,5})"#
            guard let expression = try? NSRegularExpression(pattern: pattern),
                  let match = expression.firstMatch(in: self.stdoutBuffer, range: NSRange(self.stdoutBuffer.startIndex..., in: self.stdoutBuffer)),
                  let range = Range(match.range(at: 1), in: self.stdoutBuffer),
                  let port = Int(self.stdoutBuffer[range]), (1...65_535).contains(port) else { return }
            self.stdoutBuffer = ""
            DispatchQueue.main.async { onPort?(port) }
        }
    }

    private func appendLog(_ data: Data, label: String) { logStore.append(data, label: label) }

    private func probeIdentity(_ endpoint: HarnessEndpoint, completion: @escaping (Bool) -> Void) {
        LocalRuntimeReadinessProbe.harnessIdentity(endpoint: endpoint, completion: completion)
    }

    private func verifiedOwnedOllama(process: Process, endpoint: AppOwnedOllamaEndpoint) -> Bool {
        guard ollamaProcess === process,
              ollamaEndpoint == endpoint,
              ownsOllama,
              process.isRunning,
              let identity = ollamaExecutableIdentity,
              OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: endpoint) else {
            return false
        }
        return OllamaExecutableTrust.process(process.processIdentifier, matches: identity)
    }

    private func setEndpoint(_ newEndpoint: HarnessEndpoint?) {
        guard endpoint != newEndpoint else { return }
        endpoint = newEndpoint
        DispatchQueue.main.async { [weak self] in self?.onEndpointChange?(newEndpoint) }
    }

    private func publish(_ state: State) {
        currentState = state
        // Lifecycle failures must remain diagnosable even when WebKit cannot
        // render the error surface (for example while the login session is
        // inactive). ServiceLogStore bounds and redacts this message before it
        // reaches disk, so Diagnostics never depends on a working web view.
        switch state {
        case .failed(let message):
            appendLog(Data((message + "\n").utf8), label: "lifecycle-failure")
        case .providerRecovery:
            appendLog(Data((state.summary + "\n").utf8), label: "lifecycle-recovery")
        default:
            break
        }
        statePublicationGate.enqueue(
            state: state,
            currentState: { [weak self] in self?.currentState },
            delivery: { [weak self] in self?.onStateChange?($0) }
        )
    }
}

enum LocalHarnessError: LocalizedError {
    case harnessNotFound
    case ollamaNotFound
    case credentialRuntimeMissing
    case sandboxHelperMissing
    case runtimeLeaseMissing
    case sandboxUnavailable
    case providerConsentUnavailable
    case untrustedPlugins([String])
    case communityPluginsDisabled
    case ollamaStartupTimedOut
    case ollamaOwnershipVerificationFailed
    case applicationTerminationInProgress
    case serviceStartCancelled
    case runtimeIntegrityChanged
    case harnessHomeNotPrepared
    case serviceShutdownTimedOut([Int32])

    var errorDescription: String? {
        switch self {
        case .harnessNotFound: return "The bundled DeepSeek Harness runtime is missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .ollamaNotFound: return "Ollama was not found. Install Ollama so \(ProductBrand.displayName) can start its own isolated local-model service."
        case .credentialRuntimeMissing: return "The Keychain credential component is missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .sandboxHelperMissing: return "The tool-sandbox component is missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .runtimeLeaseMissing: return "The runtime safety component is missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .sandboxUnavailable: return "\(ProductBrand.displayName) stopped before loading a model because macOS process isolation could not prove the workspace and read-only skill boundaries. Restart macOS; if this persists, reinstall the signed app."
        case .providerConsentUnavailable: return "The selected external provider has no matching endpoint consent. Choose it again in Models & Providers; \(ProductBrand.displayName) kept network access blocked."
        case .untrustedPlugins(let names): return "Harness was kept in Safe Mode because these plugins have not been reviewed: \(names.joined(separator: ", ")). Open Plugin Trust in Settings to review them."
        case .communityPluginsDisabled: return "Community plugins remain disabled until capability isolation is available. Built-in reviewed Harness features continue to work."
        case .ollamaStartupTimedOut: return "Ollama did not become ready in time."
        case .ollamaOwnershipVerificationFailed: return "The private Ollama listener could not be verified as belonging to the process started by \(ProductBrand.displayName). No prompt data was sent."
        case .applicationTerminationInProgress: return "\(ProductBrand.displayName) is closing and cannot start another service process."
        case .serviceStartCancelled: return "The local service start was cancelled because another start or stop operation took ownership."
        case .runtimeIntegrityChanged: return "A launch-critical runtime file changed after secure preparation. \(ProductBrand.displayName) kept the replacement process stopped."
        case .harnessHomeNotPrepared: return "The private Harness home is still being prepared. Skills remain unavailable until startup completes."
        case .serviceShutdownTimedOut(let pids):
            return "App-owned service process \(pids.map(String.init).joined(separator: ", ")) did not exit after a forced shutdown. \(ProductBrand.displayName) kept the replacement runtime stopped."
        }
    }
}
