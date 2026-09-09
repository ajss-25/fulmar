import AppKit
import ApplicationServices
import CoreGraphics
import CryptoKit
import Darwin
import Foundation
import Security

private enum AcceptanceError: LocalizedError {
    case failed(String)
    case thermallyDeferred(String)
    case environmentallyDeferred(String)
    case launchRequestUnsettled(String)

    var errorDescription: String? {
        switch self {
        case let .failed(message),
             let .thermallyDeferred(message),
             let .environmentallyDeferred(message),
             let .launchRequestUnsettled(message):
            return message
        }
    }
}

private struct FilesystemBoundaryFingerprint: Equatable {
    let exists: Bool
    let nodeCount: Int
    let metadataSHA256: String
}

private struct FilesystemNodeIdentity: Equatable {
    let device: UInt64
    let inode: UInt64
}

private struct PhysicalOccurrenceReceipt: Decodable {
    let schemaVersion: Int
    let id: UUID
    let scheduleID: UUID
    let state: String
    let result: PhysicalScheduledResult?
    let disable: Bool?
    let retrySoon: Bool?
}

private struct PhysicalScheduledResult: Decodable {
    struct Selection: Decodable {
        struct Route: Decodable {
            let provider: String
            let model: String
        }
        let schemaVersion: Int
        let route: Route
        let performanceProfile: String
    }

    struct Failure: Decodable {
        let code: String
        let detail: String?
    }

    let schemaVersion: Int
    let id: UUID
    let scheduleID: UUID
    let title: String
    let selection: Selection
    let boundary: String
    let sessionID: String?
    let response: String
    let failure: Failure?
    let truncated: Bool
}

private struct PhysicalForegroundReadyEvidence: Decodable {
    let schemaVersion: Int
    let state: String
    let provider: String
    let model: String
    let boundary: String
}

private struct PhysicalHandoffFixture {
    static let rootEnvironmentKey = "LOCAL_HARNESS_PHYSICAL_HANDOFF_ROOT"
    static let modelStoreEnvironmentKey = "LOCAL_HARNESS_PHYSICAL_HANDOFF_MODEL_STORE"
    static let rootLeafPrefix = "fulmar-physical-handoff."
    static let backgroundArgument = "--physical-background-handoff-acceptance"

    let root: URL
    let home: URL
    let temporaryDirectory: URL
    let applicationSupport: URL
    let occurrenceDirectory: URL
    let modelStore: URL
    let scheduleID: UUID
    let rootIdentity: FilesystemNodeIdentity

    var foregroundReadyFile: URL {
        root.appendingPathComponent("foreground-ready.json", isDirectory: false)
    }

    var launchEnvironment: [String: String] {
        [
            Self.rootEnvironmentKey: root.path,
            Self.modelStoreEnvironmentKey: modelStore.path,
            "HOME": home.path,
            "CFFIXED_USER_HOME": home.path,
            "TMPDIR": temporaryDirectory.path
        ]
    }
}

private struct ElementSnapshot {
    let element: AXUIElement
    let role: String
    let names: [String]
    let frame: CGRect?

    var name: String { names.first ?? "" }
}

private struct StableStatusItemObservation {
    let item: ElementSnapshot
    let frames: [CGRect]
}

private struct ProcessCPUObservation {
    let wallSeconds: TimeInterval
    let cpuSeconds: TimeInterval

    var oneCorePercent: Double {
        guard wallSeconds > 0 else { return .infinity }
        return cpuSeconds / wallSeconds * 100
    }
}

private struct ProcessIdentity: Hashable {
    let pid: pid_t
    let startSeconds: UInt64
    let startMicroseconds: UInt64
}

private struct BundleProcess: Hashable {
    let pid: pid_t
    let executablePath: String
}

private struct InteractiveSessionObservation {
    let state: StatusItemAcceptanceSupport.InteractiveSessionState
    let frontmostBundleIdentifier: String?
    let menuBarOwnerBundleIdentifier: String?
}

private struct SettledOpenRequest {
    let application: NSRunningApplication?
    let errorDescription: String?
    let safetyDeferral: AcceptanceError?
}

private final class StatusItemAcceptance {
    private let appURL: URL
    private let cycles: Int
    private let targetBundleIdentifier: String
    private let targetMainExecutablePath: String
    private let productName = "Fulmar"
    private let expectedStatusName = "Fulmar menu"
    private let expectedMenuTitles = ["Open Fulmar", "Chat", "Settings…", "Quit Fulmar"]
    private let accessibilityPollInterval: TimeInterval = 0.25
    private let stableVisibilityDwell: TimeInterval = 5
    private let statusItemSettlement: TimeInterval = 2.5
    private let interactiveSessionStabilizationTimeout: TimeInterval = 0.75
    private let openRequestSettlementTimeout: TimeInterval = 60
    private let headlessHandoffCycles = 20
    private var launchedProcessIdentities: [pid_t: ProcessIdentity] = [:]
    private var physicalOllamaExecutablePaths: Set<String> = []
    // The historical failure held roughly 95% of one core for 94 seconds in
    // the target while the acceptance client forced unrelated NSTable rows to
    // materialise. Measure the complete post-launch AX proof and fail if the
    // exact candidate averages more than half a core. This adds a performance
    // requirement; it never substitutes for geometry, menu, or Quit proof.
    private let maximumTargetOneCorePercent = 50.0
    private let maximumCycles = 50

    init(appPath: String, cycles: Int) throws {
        let supplied = URL(fileURLWithPath: appPath)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: supplied.path, isDirectory: &isDirectory),
              isDirectory.boolValue,
              supplied.pathExtension == "app" else {
            throw AcceptanceError.failed("Expected an exact path to an existing .app bundle, got: \(appPath)")
        }
        guard cycles > 0, cycles <= maximumCycles else {
            throw AcceptanceError.failed("The cycle count must be between 1 and \(maximumCycles).")
        }
        guard let bundle = Bundle(url: supplied),
              let bundleIdentifier = bundle.bundleIdentifier,
              !bundleIdentifier.isEmpty,
              let executableURL = bundle.executableURL else {
            throw AcceptanceError.failed("The target app has no readable bundle identifier: \(supplied.path)")
        }
        appURL = supplied
        self.cycles = cycles
        targetBundleIdentifier = bundleIdentifier
        targetMainExecutablePath = executableURL
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
    }

    func run() throws {
        guard AXIsProcessTrusted() else {
            throw AcceptanceError.failed(
                "Accessibility access is required for the live status-item test. "
                + "In System Settings > Privacy & Security > Accessibility, enable the terminal or automation host running this command, then run the test again. "
                + "The test never requests the permission prompt itself."
            )
        }
        try requireUnlockedInteractiveSession()

        try ensureNoTargetBundleIsRunning()
        print("Status-item live acceptance")
        print("  app: \(appURL.path)")
        print("  cycles: \(cycles)")

        for cycle in 1...cycles {
            print("\n[\(cycle)/\(cycles)] Cold launch")
            try runCycle(cycle)
        }
        try ensureNoTargetBundleIsRunning()

        print("\nPASS: all \(cycles) cold launches exposed one stable, visible, pressable Fulmar status item and Quit Fulmar terminated the exact launched PID.")
    }

    func runHeadlessForegroundHandoff() throws {
        guard AXIsProcessTrusted() else {
            throw AcceptanceError.failed(
                "Accessibility access is required for the live headless-handoff test. "
                + "Enable the terminal or automation host in System Settings > Privacy & Security > Accessibility, then run the test again."
            )
        }
        try requireUnlockedInteractiveSession()
        try ensureNoTargetBundleIsRunning()
        print("Headless-to-foreground live acceptance")
        print("  app: \(appURL.path)")
        print("  cycles: \(headlessHandoffCycles)")

        for cycle in 1...headlessHandoffCycles {
            print("\n[\(cycle)/\(headlessHandoffCycles)] Accessory-to-foreground handoff")
            try runHeadlessForegroundHandoffCycle(cycle)
        }
        try ensureNoTargetBundleIsRunning()
        print("\nPASS: all \(headlessHandoffCycles) protected handoffs produced one exact foreground app, one identity-stable status menu, and no duplicate or orphan target process.")
    }

    /// Runs the ordinary background scheduler, bundled DSH runtime and exact
    /// app-owned Ollama route inside an owner-only disposable HOME. A real due
    /// schedule must reach its durable occurrence boundary before the gate
    /// activates the accessory process. Fulmar then has to cancel that work,
    /// reap every exact child, launch one ordinary foreground process with the
    /// same isolated boundary, expose its full native UI and complete protected
    /// Quit. The signed-in user's Fulmar filesystem metadata must not change.
    func runPhysicalBackgroundForegroundHandoff() throws {
        guard AXIsProcessTrusted() else {
            throw AcceptanceError.failed(
                "Accessibility access is required for the physical background-handoff test. "
                + "Enable the terminal or automation host in System Settings > Privacy & Security > Accessibility, then run the test again."
            )
        }
        try requireUnlockedInteractiveSession()
        guard ProcessInfo.processInfo.thermalState == .nominal else {
            throw AcceptanceError.thermallyDeferred(
                "The physical background-handoff gate was safely deferred because macOS thermal state is not nominal."
            )
        }
        physicalOllamaExecutablePaths = try resolvePhysicalOllamaExecutablePaths()
        try ensureNoTargetBundleOwnedProcessIsRunning()
        try ensureNoOllamaCLIProcessIsRunning()

        let loginHome = try loginHomeDirectory()
        let liveBoundaries = liveUserStateBoundaries(home: loginHome)
        try requireNominalThermalState()
        let before = try liveBoundaries.map(metadataFingerprint)
        try requireNominalThermalState()
        let modelStore = try liveUserModelStore(home: loginHome)
        let modelStoreBefore = try metadataFingerprint(modelStore)
        try requireNominalThermalState()
        let fixture = try createPhysicalHandoffFixture(modelStore: modelStore)
        var fixtureWasRemoved = false
        var capturedChildren: [ProcessIdentity] = []
        defer {
            if !fixtureWasRemoved {
                print("  disposable state was retained for protected-shutdown diagnosis: \(fixture.root.path)")
            }
        }

        print("Physical background-schedule-to-foreground acceptance")
        print("  app: \(appURL.path)")
        print("  state boundary: private disposable HOME (live Fulmar state fingerprinted read-only)")
        print("  workload: one fast, on-device due schedule cancelled through the protected handoff")

        do {
            let background = try launchExactTarget(
                arguments: ["--background-schedule", PhysicalHandoffFixture.backgroundArgument],
                activates: false,
                environment: fixture.launchEnvironment,
                protectedCleanup: true
            )
            let oldPID = background.processIdentifier
            let oldApplication = AXUIElementCreateApplication(oldPID)
            print("  launched real accessory scheduler PID \(oldPID)")

            try waitForAccessoryLaunchState(
                of: background,
                application: oldApplication,
                pid: oldPID,
                timeout: 10
            )
            let occurrenceID = try waitForPhysicalScheduleOccurrence(
                fixture: fixture,
                application: oldApplication,
                pid: oldPID,
                timeout: 150
            )
            print("  real due schedule reached the durable occurrence boundary after native provider/topology promotion")
            capturedChildren.append(contentsOf: try requireExpectedRuntimeChildren(of: oldPID))
            try requireStartedPhysicalOccurrence(fixture: fixture, occurrenceID: occurrenceID)
            capturedChildren.append(contentsOf: try captureDescendantProcessIdentities(of: oldPID))
            capturedChildren = Array(Set(capturedChildren))

            try requestNormalOpenOfAccessory(
                background,
                pid: oldPID,
                requiresNominalThermalState: true,
                protectedCleanup: true
            )

            let foreground = try waitForPhysicalForegroundReplacement(
                oldPID: oldPID,
                capturedChildren: &capturedChildren,
                timeout: 75
            )
            let newPID = foreground.processIdentifier
            try recordProcessIdentity(pid: newPID)
            print("  protected stop reaped scheduler PID \(oldPID); exact regular foreground PID \(newPID) launched")

            guard try waitForActivation(of: foreground, pid: newPID, timeout: 15) else {
                throw AcceptanceError.failed("Exact foreground PID \(newPID) did not become active.")
            }
            let foregroundApplication = AXUIElementCreateApplication(newPID)
            let foregroundWindow = try waitForVisibleWindow(
                named: productName,
                in: foregroundApplication,
                pid: newPID,
                timeout: 30
            )
            try waitForPhysicalForegroundReadyEvidence(fixture: fixture, pid: newPID, timeout: 120)
            try waitForExactLocalReadyStatus(
                in: foregroundWindow,
                pid: newPID,
                timeout: 15
            )
            capturedChildren.append(contentsOf: try captureDescendantProcessIdentities(of: newPID))
            let settlementDeadline = Date().addingTimeInterval(statusItemSettlement)
            while Date() < settlementDeadline {
                try requireUnlockedInteractiveSession()
                try requireNominalThermalState()
                if processHasExited(newPID) {
                    throw AcceptanceError.failed("Foreground PID \(newPID) exited during status-item settlement.")
                }
                RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
            }
            try requireInteractiveTerminalBoundary(
                requiresNominalThermalState: true
            )
            let statusItem = try waitForSingleStatusItem(
                in: foregroundApplication,
                pid: newPID,
                timeout: 20
            )
            let stable = try collectStableGeometry(
                initial: statusItem,
                application: foregroundApplication,
                pid: newPID
            )
            let fresh = try waitForSingleStatusItem(
                in: foregroundApplication,
                pid: newPID,
                timeout: 2
            )
            guard CFEqual(fresh.element, stable.item.element) else {
                throw AcceptanceError.failed(
                    "Foreground PID \(newPID) replaced its status item after the stable-identity dwell."
                )
            }
            try openNormalMenuVerifyAndQuit(
                item: fresh,
                pid: newPID,
                capturedChildren: &capturedChildren
            )
            try ensureCapturedProcessesExited(capturedChildren, timeout: 15)
            try ensureNoTargetBundleOwnedProcessIsRunning()
            try ensureNoOllamaCLIProcessIsRunning()
            try ensureNoCandidateRuntimeProcessIsRunning()
            try verifyDisposablePhysicalEvidence(fixture, occurrenceID: occurrenceID)

            // Let cfprefsd and filesystem metadata publication settle before
            // proving that the ordinary user profile was never selected.
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(1.0))
            try requireInteractiveTerminalBoundary(
                requiresNominalThermalState: true
            )
            let after = try liveBoundaries.map(metadataFingerprint)
            guard before == after else {
                throw AcceptanceError.failed(
                    "The physical gate changed metadata inside the signed-in user's Fulmar state boundary. The disposable-home qualification failed closed."
                )
            }
            guard modelStoreBefore == (try metadataFingerprint(modelStore)) else {
                throw AcceptanceError.failed(
                    "The physical gate changed metadata inside the read-only Ollama model store."
                )
            }
            try requireNominalThermalState()
            try removeDisposablePhysicalFixture(fixture)
            fixtureWasRemoved = true
            print("PASS: real scheduler, DSH, local Qwen topology, protected cancellation, isolated foreground handoff, full UI, status menu, protected Quit, child cleanup, and unchanged live-user state were all verified.")
        } catch {
            let requestIsSettled: Bool
            if let acceptanceError = error as? AcceptanceError,
               case .launchRequestUnsettled = acceptanceError {
                requestIsSettled = false
            } else {
                requestIsSettled = true
            }
            for application in exactTargetApplications() {
                _ = cleanupNormalLaunchedProcess(pid: application.processIdentifier)
            }
            let cleanupComplete = physicalCleanupIsComplete(capturedChildren: capturedChildren)
            // A physical fixture carries the exact launch environment. Never
            // delete it while Launch Services still owns an unresolved request:
            // a late callback must not launch into a boundary we already removed.
            if requestIsSettled && cleanupComplete && !fixtureWasRemoved {
                do {
                    try removeDisposablePhysicalFixture(fixture)
                    fixtureWasRemoved = true
                } catch {
                    print("  protected cleanup completed, but disposable-state removal failed and the state was retained")
                }
            }
            if let acceptanceError = error as? AcceptanceError {
                let isSafetyDeferral: Bool
                switch acceptanceError {
                case .thermallyDeferred, .environmentallyDeferred:
                    isSafetyDeferral = true
                case .failed, .launchRequestUnsettled:
                    isSafetyDeferral = false
                }
                if isSafetyDeferral,
                   StatusItemAcceptanceSupport.safetyExitDisposition(
                       openRequestSettled: requestIsSettled,
                       cleanupComplete: cleanupComplete,
                       disposableStateRemoved: fixtureWasRemoved
                   ) == .hardFailure {
                    throw AcceptanceError.failed(
                        "Safety deferral requested protected shutdown, but exact process cleanup and disposable-state deletion could not both be verified."
                    )
                }
            }
            throw error
        }
    }

    private func createPhysicalHandoffFixture(modelStore: URL) throws -> PhysicalHandoffFixture {
        var template = Array("/private/tmp/fulmar-physical-handoff.XXXXXX".utf8CString)
        let created: UnsafeMutablePointer<CChar>? = template.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return nil }
            return Darwin.mkdtemp(base)
        }
        guard let created else {
            throw AcceptanceError.failed("Could not create the private physical-handoff root.")
        }
        let root = URL(fileURLWithPath: String(cString: created), isDirectory: true)
        var rootMetadata = stat()
        guard Darwin.lstat(root.path, &rootMetadata) == 0,
              rootMetadata.st_mode & S_IFMT == S_IFDIR,
              rootMetadata.st_uid == geteuid(),
              rootMetadata.st_nlink >= 2,
              rootMetadata.st_mode & 0o777 == 0o700 else {
            throw AcceptanceError.failed("The newly created physical-handoff root was not private and owner-controlled.")
        }
        let rootIdentity = FilesystemNodeIdentity(
            device: UInt64(truncatingIfNeeded: rootMetadata.st_dev),
            inode: UInt64(rootMetadata.st_ino)
        )
        var succeeded = false
        defer {
            if !succeeded { try? removeDisposableRoot(root, identity: rootIdentity) }
        }
        let home = root.appendingPathComponent("home", isDirectory: true)
        let temporaryDirectory = root.appendingPathComponent("temp", isDirectory: true)
        let library = home.appendingPathComponent("Library", isDirectory: true)
        let supportParent = library.appendingPathComponent("Application Support", isDirectory: true)
        let applicationSupport = supportParent.appendingPathComponent("Local Harness", isDirectory: true)
        let preferences = library.appendingPathComponent("Preferences", isDirectory: true)
        let migration = applicationSupport.appendingPathComponent("Migration", isDirectory: true)
        let schedules = applicationSupport.appendingPathComponent("Schedules", isDirectory: true)
        let occurrenceDirectory = schedules.appendingPathComponent("Occurrences", isDirectory: true)
        for directory in [
            home, temporaryDirectory, library, supportParent,
            applicationSupport, preferences, migration, schedules, occurrenceDirectory
        ] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        for directory in [
            root, home, temporaryDirectory, library, supportParent, applicationSupport,
            preferences, migration, schedules, occurrenceDirectory
        ] {
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }

        let runtimeVersion = try packagedHarnessVersion()
        let migrationState = try JSONSerialization.data(
            withJSONObject: ["installedVersion": runtimeVersion],
            options: [.sortedKeys]
        )
        let migrationStateURL = migration.appendingPathComponent("runtime-state.json")
        try writePrivate(migrationState, to: migrationStateURL)

        let preferencesData = try PropertyListSerialization.data(
            fromPropertyList: ["Fulmar.MenuBar.v2.VisibilityInitialized": true],
            format: .binary,
            options: 0
        )
        try writePrivate(
            preferencesData,
            to: preferences.appendingPathComponent("\(targetBundleIdentifier).plist")
        )

        let due = Date().addingTimeInterval(-5).timeIntervalSinceReferenceDate
        let scheduleID = UUID()
        let schedule: [String: Any] = [
            "schemaVersion": 2,
            "id": scheduleID.uuidString,
            "title": "Physical handoff release probe",
            "prompt": "Reply with exactly FULMAR_PHYSICAL_HANDOFF_OK",
            "model": "qwen3.8:27b-mlx",
            "selection": [
                "schemaVersion": 1,
                "route": ["provider": "ollama", "model": "qwen3.8:27b-mlx"],
                "performanceProfile": "fast"
            ],
            "boundary": "onDevice",
            "intervalSeconds": 0,
            "timeoutSeconds": 30,
            "nextRun": due,
            "enabled": true
        ]
        let scheduleData = try JSONSerialization.data(withJSONObject: [schedule], options: [.sortedKeys])
        try writePrivate(scheduleData, to: schedules.appendingPathComponent("schedules.json"))

        succeeded = true
        return PhysicalHandoffFixture(
            root: root,
            home: home,
            temporaryDirectory: temporaryDirectory,
            applicationSupport: applicationSupport,
            occurrenceDirectory: occurrenceDirectory,
            modelStore: modelStore,
            scheduleID: scheduleID,
            rootIdentity: rootIdentity
        )
    }

    private func packagedHarnessVersion() throws -> String {
        let identityURL = appURL
            .appendingPathComponent("Contents/Resources/ReleaseIdentity.json", isDirectory: false)
        let data = try Data(contentsOf: identityURL, options: [.mappedIfSafe])
        guard data.count <= 64 * 1_024,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let runtime = root["runtime"] as? [String: Any],
              let version = runtime["deepseekHarnessVersion"] as? String,
              !version.isEmpty,
              version.utf8.count <= 128,
              !version.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw AcceptanceError.failed("The candidate's packaged Harness version could not be resolved safely.")
        }
        return version
    }

    private func writePrivate(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o777 == 0o600 else {
            throw AcceptanceError.failed("A physical-handoff fixture file was not private and owner-controlled.")
        }
    }

    private func waitForPhysicalScheduleOccurrence(
        fixture: PhysicalHandoffFixture,
        application: AXUIElement,
        pid: pid_t,
        timeout: TimeInterval
    ) throws -> UUID {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            try requireNominalThermalState()
            if processHasExited(pid) {
                throw AcceptanceError.failed(
                    "The real scheduler PID \(pid) exited before a due occurrence began."
                )
            }
            guard statusItems(in: application).isEmpty,
                  visibleApplicationWindows(in: application).isEmpty else {
                throw AcceptanceError.failed(
                    "The real background scheduler exposed a window or menu-bar item while its due task was running."
                )
            }
            let entries = try FileManager.default.contentsOfDirectory(
                at: fixture.occurrenceDirectory,
                includingPropertiesForKeys: nil,
                options: []
            )
            guard entries.count <= 1,
                  entries.first?.pathExtension == "json" || entries.isEmpty else {
                throw AcceptanceError.failed(
                    "The disposable scheduler occurrence directory contained unexpected or duplicate evidence."
                )
            }
            if let receiptURL = entries.first {
                let receipt = try decodePrivatePhysicalJSON(
                    PhysicalOccurrenceReceipt.self,
                    at: receiptURL,
                    maximumBytes: 64 * 1_024
                )
                guard receiptURL.lastPathComponent == "\(receipt.id.uuidString).json",
                      receipt.schemaVersion == 1,
                      receipt.scheduleID == fixture.scheduleID,
                      receipt.state == "started",
                      receipt.result == nil,
                      receipt.disable == nil,
                      receipt.retrySoon == nil else {
                    throw AcceptanceError.failed(
                        "The durable occurrence was not the exact still-running physical handoff task."
                    )
                }
                return receipt.id
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        try throwInteractiveTimeout(
            "The real scheduler did not reach its durable due-occurrence boundary within \(Int(timeout)) seconds.",
            requiresNominalThermalState: true
        )
    }

    private func requireStartedPhysicalOccurrence(
        fixture: PhysicalHandoffFixture,
        occurrenceID: UUID
    ) throws {
        let receipt = try decodePrivatePhysicalJSON(
            PhysicalOccurrenceReceipt.self,
            at: fixture.occurrenceDirectory.appendingPathComponent("\(occurrenceID.uuidString).json"),
            maximumBytes: 64 * 1_024
        )
        guard receipt.schemaVersion == 1,
              receipt.id == occurrenceID,
              receipt.scheduleID == fixture.scheduleID,
              receipt.state == "started",
              receipt.result == nil,
              receipt.disable == nil,
              receipt.retrySoon == nil else {
            throw AcceptanceError.failed(
                "The physical task completed or changed before the user-open handoff was requested."
            )
        }
    }

    private func decodePrivatePhysicalJSON<Value: Decodable>(
        _ type: Value.Type,
        at url: URL,
        maximumBytes: Int
    ) throws -> Value {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw AcceptanceError.failed("Physical-handoff evidence could not be opened without following links.")
        }
        defer { _ = Darwin.close(descriptor) }
        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_nlink == 1,
              before.st_mode & 0o077 == 0,
              before.st_size >= 0,
              before.st_size <= maximumBytes else {
            throw AcceptanceError.failed("Physical-handoff evidence was missing or not private.")
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var remaining = Int(before.st_size)
        var buffer = [UInt8](repeating: 0, count: min(max(remaining, 1), 64 * 1_024))
        while remaining > 0 {
            let amount = buffer.withUnsafeMutableBytes { storage in
                Darwin.read(descriptor, storage.baseAddress, min(storage.count, remaining))
            }
            if amount < 0, errno == EINTR { continue }
            guard amount > 0 else {
                throw AcceptanceError.failed("Physical-handoff evidence ended before its verified byte count.")
            }
            data.append(buffer, count: amount)
            remaining -= amount
        }
        var trailing = UInt8.zero
        var trailingCount: Int
        repeat { trailingCount = Darwin.read(descriptor, &trailing, 1) }
        while trailingCount < 0 && errno == EINTR
        var after = stat()
        var pathAfter = stat()
        guard trailingCount == 0,
              data.count == Int(before.st_size),
              Darwin.fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_mode == after.st_mode,
              before.st_nlink == after.st_nlink,
              before.st_uid == after.st_uid,
              before.st_gid == after.st_gid,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              Darwin.lstat(url.path, &pathAfter) == 0,
              pathAfter.st_dev == before.st_dev,
              pathAfter.st_ino == before.st_ino else {
            throw AcceptanceError.failed("Physical-handoff evidence changed while it was being read.")
        }
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw AcceptanceError.failed("Physical-handoff evidence was malformed.") }
    }

    private func settleOpenRequest(
        _ barrier: StatusItemAcceptanceSupport.OpenRequestBarrier<NSRunningApplication>,
        requiresNominalThermalState: Bool
    ) throws -> SettledOpenRequest {
        let deadline = Date().addingTimeInterval(openRequestSettlementTimeout)
        var safetyDeferral: AcceptanceError?

        while Date() < deadline {
            if safetyDeferral == nil {
                safetyDeferral = try openRequestSafetyDeferral(
                    requiresNominalThermalState: requiresNominalThermalState
                )
            }
            switch barrier.snapshot() {
            case let .completed(application, errorDescription):
                return SettledOpenRequest(
                    application: application,
                    errorDescription: errorDescription,
                    safetyDeferral: safetyDeferral
                )
            case .pending:
                break
            }

            // A lock or thermal transition invalidates the interactive proof,
            // but it must not abandon the in-flight Launch Services callback.
            // Remember the deferral and keep pumping the run loop until this
            // exact generation settles so any returned target can be verified
            // and cleaned before exit 75 is even considered.
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }

        // Close the boundary race: a callback that acquired the barrier as the
        // deadline expired is settled and must be consumed, not misclassified.
        switch barrier.snapshot() {
        case let .completed(application, errorDescription):
            if safetyDeferral == nil {
                safetyDeferral = try openRequestSafetyDeferral(
                    requiresNominalThermalState: requiresNominalThermalState
                )
            }
            return SettledOpenRequest(
                application: application,
                errorDescription: errorDescription,
                safetyDeferral: safetyDeferral
            )
        case .pending:
            throw AcceptanceError.launchRequestUnsettled(
                "Launch Services did not settle request generation \(barrier.generation.uuidString) "
                + "within \(Int(openRequestSettlementTimeout)) seconds. This is a hard qualification failure; "
                + "the request remains unresolved and cannot be reported as an environmental deferral."
            )
        }
    }

    private func openRequestSafetyDeferral(
        requiresNominalThermalState: Bool
    ) throws -> AcceptanceError? {
        do {
            try requireUnlockedInteractiveSession()
            if requiresNominalThermalState {
                try requireNominalThermalState()
            }
            return nil
        } catch let acceptanceError as AcceptanceError {
            switch acceptanceError {
            case .thermallyDeferred, .environmentallyDeferred:
                return acceptanceError
            case .failed, .launchRequestUnsettled:
                throw acceptanceError
            }
        }
    }

    private func requestNormalOpenOfAccessory(
        _ background: NSRunningApplication,
        pid: pid_t,
        requiresNominalThermalState: Bool,
        protectedCleanup: Bool
    ) throws {
        try requireUnlockedInteractiveSession()
        if requiresNominalThermalState {
            try requireNominalThermalState()
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.createsNewApplicationInstance = false
        let barrier = StatusItemAcceptanceSupport.OpenRequestBarrier<NSRunningApplication>()
        let generation = barrier.generation
        NSWorkspace.shared.openApplication(at: appURL, configuration: configuration) { application, error in
            _ = barrier.resolve(
                generation: generation,
                payload: application,
                errorDescription: error?.localizedDescription
            )
        }

        var requestSettled = false
        var authenticatedApplication: NSRunningApplication?
        do {
            let settled = try settleOpenRequest(
                barrier,
                requiresNominalThermalState: requiresNominalThermalState
            )
            requestSettled = true
            if let reopened = settled.application {
                guard canonicalBundleURL(for: reopened) == appURL else {
                    throw AcceptanceError.failed(
                        "Launch Services returned PID \(reopened.processIdentifier) for a different bundle path: "
                        + "\(reopened.bundleURL?.path ?? "unknown"). The gate did not terminate that foreign process."
                    )
                }
                authenticatedApplication = reopened
                try recordProcessIdentity(pid: reopened.processIdentifier)
            }
            if let safetyDeferral = settled.safetyDeferral {
                throw safetyDeferral
            }
            if let errorDescription = settled.errorDescription {
                throw AcceptanceError.failed(
                    "Launch Services rejected the normal user Open request: \(errorDescription)"
                )
            }
            guard let reopened = authenticatedApplication else {
                throw AcceptanceError.failed(
                    "Launch Services settled the normal Open request without returning the exact target bundle."
                )
            }

            try requireUnlockedInteractiveSession()
            if requiresNominalThermalState {
                try requireNominalThermalState()
            }
            if !processHasExited(pid) {
                guard reopened.processIdentifier == pid,
                      reopened.processIdentifier == background.processIdentifier else {
                    throw AcceptanceError.failed(
                        "The normal Open request spawned a peer before the accessory scheduler began its protected replacement."
                    )
                }
                print("  normal Launch Services Open reused accessory PID \(pid) before protected replacement")
            } else {
                print("  Launch Services acknowledged normal Open after accessory PID \(pid) completed its protected exit")
            }
        } catch {
            if let authenticatedApplication,
               launchedProcessIdentities[authenticatedApplication.processIdentifier] == nil {
                _ = authenticatedApplication.terminate()
            }
            let cleanupComplete = cleanupAllLaunchedTargetProcesses(
                protected: protectedCleanup
            )
            if let safetyDeferral = safetyDeferral(in: error) {
                switch StatusItemAcceptanceSupport.safetyExitDisposition(
                    openRequestSettled: requestSettled,
                    cleanupComplete: cleanupComplete,
                    disposableStateRemoved: true
                ) {
                case .deferred:
                    throw safetyDeferral
                case .hardFailure:
                    throw AcceptanceError.failed(
                        "A safety deferral occurred after normal Open dispatch, but request settlement and exact process cleanup were not both verified."
                    )
                }
            }
            if let acceptanceError = error as? AcceptanceError,
               case let .launchRequestUnsettled(message) = acceptanceError {
                let cleanupSuffix = cleanupComplete
                    ? " Current exact-process inventory was quiescent, but the callback can still arrive."
                    : " Current exact-process cleanup was also incomplete."
                throw AcceptanceError.launchRequestUnsettled(message + cleanupSuffix)
            }
            if !cleanupComplete {
                throw AcceptanceError.failed(
                    "The normal Open request failed (\(error.localizedDescription)), and exact post-dispatch process cleanup could not be verified."
                )
            }
            if let acceptanceError = error as? AcceptanceError {
                throw acceptanceError
            }
            throw error
        }
    }

    private func waitForPhysicalForegroundReplacement(
        oldPID: pid_t,
        capturedChildren: inout [ProcessIdentity],
        timeout: TimeInterval
    ) throws -> NSRunningApplication {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            try requireNominalThermalState()
            if !processHasExited(oldPID) {
                capturedChildren.append(contentsOf: try captureDescendantProcessIdentities(of: oldPID))
                capturedChildren = Array(Set(capturedChildren))
            }
            let exact = exactTargetApplications()
            if exact.count > 2 {
                throw AcceptanceError.failed(
                    "The physical handoff produced more than one foreground peer."
                )
            }
            if processHasExited(oldPID),
               exact.count == 1,
               exact[0].processIdentifier != oldPID,
               exact[0].activationPolicy == .regular {
                return exact[0]
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        try requireInteractiveTerminalBoundary(
            requiresNominalThermalState: true
        )
        let peers = exactTargetApplications()
            .map { "PID \($0.processIdentifier), policy \($0.activationPolicy.rawValue)" }
            .joined(separator: "; ")
        throw AcceptanceError.failed(
            "The real scheduler PID \(oldPID) was not replaced by exactly one regular foreground peer. Observed: \(peers.isEmpty ? "none" : peers)."
        )
    }

    private func openNormalMenuVerifyAndQuit(
        item: ElementSnapshot,
        pid: pid_t,
        capturedChildren: inout [ProcessIdentity]
    ) throws {
        try requireUnlockedInteractiveSession()
        try requireNominalThermalState()
        _ = try performInteractiveAXAction(
            item.element,
            action: kAXPressAction as CFString,
            failureMessage: {
                "AXPress on '\(expectedStatusName)' failed for physical foreground PID \(pid): \(describe($0))."
            }
        )
        let menu = try waitForStatusMenu(from: item.element, pid: pid, timeout: 5)
        try requireUnlockedInteractiveSession()
        let items = menuItems(in: menu)
        for expected in expectedMenuTitles where !items.contains(where: {
            canonicalMenuTitle($0.name) == expected
        }) {
            throw AcceptanceError.failed(
                "The physical foreground menu for PID \(pid) is missing '\(expected)'."
            )
        }
        try waitForEnabledCoreMenuItems(items, pid: pid, timeout: 10)
        try ensureNoTargetBundlePeer(excluding: pid)
        capturedChildren.append(contentsOf: try captureDescendantProcessIdentities(of: pid))
        capturedChildren = Array(Set(capturedChildren))
        try requireNominalThermalState()
        guard let quit = items.first(where: {
            canonicalMenuTitle($0.name) == "Quit \(productName)"
        }) else {
            throw AcceptanceError.failed("Could not resolve exact protected Quit for PID \(pid).")
        }
        try performMenuItem(quit, title: "Quit \(productName)", pid: pid)
        guard try waitForProtectedExitCapturingDescendants(
            pid: pid,
            capturedChildren: &capturedChildren,
            timeout: 60
        ) else {
            try throwInteractiveTimeout(
                "Protected Quit was activated, but physical foreground PID \(pid) remained after 60 seconds.",
                requiresNominalThermalState: true
            )
        }
        print("  full foreground window/menu verified; protected Quit terminated exact PID \(pid)")
    }

    private func waitForPhysicalForegroundReadyEvidence(
        fixture: PhysicalHandoffFixture,
        pid: pid_t,
        timeout: TimeInterval
    ) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            try requireNominalThermalState()
            if processHasExited(pid) {
                throw AcceptanceError.failed(
                    "Foreground PID \(pid) exited before publishing exact ready evidence."
                )
            }
            var metadata = stat()
            if Darwin.lstat(fixture.foregroundReadyFile.path, &metadata) == 0 {
                let evidence = try decodePrivatePhysicalJSON(
                    PhysicalForegroundReadyEvidence.self,
                    at: fixture.foregroundReadyFile,
                    maximumBytes: 16 * 1_024
                )
                guard evidence.schemaVersion == 1,
                      evidence.state == "ready",
                      evidence.provider == "ollama",
                      evidence.model == "qwen3.8:27b-mlx",
                      evidence.boundary == "onDevice" else {
                    throw AcceptanceError.failed(
                        "Foreground PID \(pid) published ready evidence for the wrong provider, model, or data boundary."
                    )
                }
                print("  foreground published exact ready evidence for Ollama / qwen3.8:27b-mlx / on-device")
                return
            }
            guard errno == ENOENT else {
                throw AcceptanceError.failed("The foreground ready-evidence path could not be inspected safely.")
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        try throwInteractiveTimeout(
            "Foreground PID \(pid) did not publish exact ready evidence within \(Int(timeout)) seconds.",
            requiresNominalThermalState: true
        )
    }

    private func waitForExactLocalReadyStatus(
        in window: ElementSnapshot,
        pid: pid_t,
        timeout: TimeInterval
    ) throws {
        let expected = "Ready · On this Mac"
        let deadline = Date().addingTimeInterval(timeout)
        var observed: Set<String> = []
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            try requireNominalThermalState()
            let windowHierarchy = descendants(
                of: window.element,
                maximumDepth: 3,
                maximumCount: 128,
                childAttributes: [kAXChildrenAttribute as String]
            )
            let directToolbars = elements(
                for: window.element,
                attributes: ["AXToolbar"],
                maximumCount: 4
            ).map(snapshot)
            let toolbars = uniqueSnapshots(
                directToolbars + windowHierarchy.filter { $0.role == (kAXToolbarRole as String) }
            )
            let toolbarHierarchy = uniqueSnapshots(toolbars.flatMap {
                descendants(
                    of: $0.element,
                    maximumDepth: 5,
                    maximumCount: 256,
                    childAttributes: [kAXChildrenAttribute as String]
                )
            })
            for snapshot in toolbarHierarchy {
                observed.formUnion(snapshot.names.filter { !$0.isEmpty })
            }
            let matches = toolbarHierarchy.filter { $0.names.contains(expected) }
            if matches.count == 1 {
                print("  foreground toolbar exposed exact service state '\(expected)'")
                return
            }
            if matches.count > 1 {
                throw AcceptanceError.failed(
                    "Foreground PID \(pid) exposed duplicate exact local-ready toolbar statuses."
                )
            }
            if processHasExited(pid) {
                throw AcceptanceError.failed(
                    "Foreground PID \(pid) exited before its exact local-ready toolbar status appeared."
                )
            }
            RunLoop.current.run(
                mode: .default,
                before: Date().addingTimeInterval(accessibilityPollInterval)
            )
        }
        try requireInteractiveTerminalBoundary(
            requiresNominalThermalState: true
        )
        let relevant = observed.filter { $0.contains("Ready") || $0.contains("local") }
            .sorted()
            .joined(separator: " | ")
        throw AcceptanceError.failed(
            "Foreground PID \(pid) never exposed exactly '\(expected)' in its toolbar. Observed: \(relevant.isEmpty ? "none" : relevant)."
        )
    }

    private func verifyDisposablePhysicalEvidence(
        _ fixture: PhysicalHandoffFixture,
        occurrenceID: UUID
    ) throws {
        let homeReceipt = fixture.applicationSupport
            .appendingPathComponent("HarnessHome/.local-harness-home.json")
        guard isPrivateRegularFile(homeReceipt) else {
            throw AcceptanceError.failed("The disposable Harness home did not publish its private migration receipt.")
        }
        let migrationState = fixture.applicationSupport
            .appendingPathComponent("Migration/runtime-state.json")
        let stateData = try Data(contentsOf: migrationState, options: [.mappedIfSafe])
        guard stateData.count <= 64 * 1_024,
              let state = try JSONSerialization.jsonObject(with: stateData) as? [String: Any],
              state["installedVersion"] as? String == (try packagedHarnessVersion()),
              state["pendingVersion"] == nil || state["pendingVersion"] is NSNull,
              state["pendingBackupID"] == nil || state["pendingBackupID"] is NSNull else {
            throw AcceptanceError.failed("The disposable migration state did not remain current and non-pending.")
        }
        let backupRoot = fixture.applicationSupport.appendingPathComponent("Backups", isDirectory: true)
        if FileManager.default.fileExists(atPath: backupRoot.path) {
            let backupEntries = try FileManager.default.contentsOfDirectory(atPath: backupRoot.path)
            guard backupEntries.isEmpty else {
                throw AcceptanceError.failed(
                    "The pre-seeded current migration unexpectedly created an authenticated backup or touched Keychain-backed backup state."
                )
            }
        }
        let credentialMetadata = fixture.applicationSupport
            .appendingPathComponent("CredentialMetadata", isDirectory: true)
        if FileManager.default.fileExists(atPath: credentialMetadata.path) {
            let credentialEntries = try FileManager.default.contentsOfDirectory(atPath: credentialMetadata.path)
            guard credentialEntries.isEmpty else {
                throw AcceptanceError.failed(
                    "The on-device physical route unexpectedly invoked Keychain credential metadata storage."
                )
            }
        }
        let occurrenceEntries = try FileManager.default.contentsOfDirectory(
            at: fixture.occurrenceDirectory,
            includingPropertiesForKeys: nil,
            options: []
        )
        guard occurrenceEntries.isEmpty else {
            throw AcceptanceError.failed(
                "The exact started occurrence receipt was not removed after foreground reconciliation."
            )
        }

        let inbox = fixture.applicationSupport.appendingPathComponent("Schedules/Inbox", isDirectory: true)
        let results = try FileManager.default.contentsOfDirectory(
            at: inbox,
            includingPropertiesForKeys: nil,
            options: []
        )
        let expectedResultURL = inbox.appendingPathComponent("\(occurrenceID.uuidString).json")
        guard results.count == 1,
              results[0].standardizedFileURL == expectedResultURL.standardizedFileURL else {
            throw AcceptanceError.failed(
                "The protected handoff did not publish exactly one result for the captured occurrence identity."
            )
        }
        let result = try decodePrivatePhysicalJSON(
            PhysicalScheduledResult.self,
            at: expectedResultURL,
            maximumBytes: 2 * 1_024 * 1_024
        )
        guard result.schemaVersion == 2,
              result.id == occurrenceID,
              result.scheduleID == fixture.scheduleID,
              result.title == "Physical handoff release probe",
              result.selection.schemaVersion == 1,
              result.selection.route.provider == "ollama",
              result.selection.route.model == "qwen3.8:27b-mlx",
              result.selection.performanceProfile == "fast",
              result.boundary == "onDevice",
              result.sessionID == nil,
              result.response.isEmpty,
              result.failure?.code == "interrupted",
              result.failure?.detail == nil,
              result.truncated == false else {
            throw AcceptanceError.failed(
                "The reconciled physical result was not the exact deterministic interrupted result for the captured local occurrence."
            )
        }
        print("  exact started receipt reconciled to one deterministic interrupted Inbox result")
    }

    private func removeDisposablePhysicalFixture(_ fixture: PhysicalHandoffFixture) throws {
        try removeDisposableRoot(fixture.root, identity: fixture.rootIdentity)
    }

    private func removeDisposableRoot(
        _ root: URL,
        identity: FilesystemNodeIdentity
    ) throws {
        var metadata = stat()
        var canonicalBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard root.deletingLastPathComponent().path == "/private/tmp",
              root.lastPathComponent.hasPrefix(PhysicalHandoffFixture.rootLeafPrefix),
              root.lastPathComponent.utf8.count > PhysicalHandoffFixture.rootLeafPrefix.utf8.count,
              Darwin.lstat(root.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_nlink >= 2,
              metadata.st_mode & 0o777 == 0o700,
              UInt64(truncatingIfNeeded: metadata.st_dev) == identity.device,
              UInt64(metadata.st_ino) == identity.inode,
              Darwin.realpath(root.path, &canonicalBuffer) != nil,
              String(cString: canonicalBuffer) == root.path else {
            throw AcceptanceError.failed(
                "Disposable-state deletion was refused because the exact private root identity could not be revalidated."
            )
        }
        try FileManager.default.removeItem(at: root)
        errno = 0
        var removedMetadata = stat()
        guard Darwin.lstat(root.path, &removedMetadata) != 0, errno == ENOENT else {
            throw AcceptanceError.failed(
                "Disposable-state deletion did not end at a verified ENOENT boundary."
            )
        }
        print("  verified exact disposable fixture deletion (ENOENT)")
    }

    private func isPrivateRegularFile(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o077 == 0
    }

    private func requireNominalThermalState() throws {
        guard ProcessInfo.processInfo.thermalState == .nominal else {
            throw AcceptanceError.thermallyDeferred(
                "macOS left nominal thermal state during the physical handoff gate; Fulmar's protected shutdown was requested and the gate was safely deferred."
            )
        }
    }

    private func runHeadlessForegroundHandoffCycle(_ cycle: Int) throws {
        try requireUnlockedInteractiveSession()
        let headless = try launchExactTarget(arguments: ["--headless-handoff-acceptance"])
        let oldPID = headless.processIdentifier
        print("  launched accessory PID \(oldPID)")
        do {
            let oldApplication = AXUIElementCreateApplication(oldPID)
            try waitForAccessoryLaunchState(
                of: headless,
                application: oldApplication,
                pid: oldPID,
                timeout: 5
            )
            let settleDeadline = Date().addingTimeInterval(1.5)
            while Date() < settleDeadline {
                try requireUnlockedInteractiveSession()
                if processHasExited(oldPID) {
                    throw AcceptanceError.failed("Accessory PID \(oldPID) exited before the reopen probe.")
                }
                guard NSRunningApplication(processIdentifier: oldPID)?.activationPolicy == .accessory else {
                    throw AcceptanceError.failed("Accessory PID \(oldPID) changed activation policy before the reopen probe.")
                }
                guard statusItems(in: oldApplication).isEmpty,
                      visibleApplicationWindows(in: oldApplication).isEmpty else {
                    throw AcceptanceError.failed(
                        "Accessory PID \(oldPID) exposed a window or status item before the reopen probe."
                    )
                }
                RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
            }
            try requireInteractiveTerminalBoundary()
            guard statusItems(in: oldApplication).isEmpty else {
                throw AcceptanceError.failed(
                    "The release-only accessory probe unexpectedly exposed a status item before foreground handoff."
                )
            }

            // This is the user-visible failure path: a normal open request is
            // delivered while the same exact bundle already has an accessory
            // process. Fulmar must stop that process's owned work, launch one
            // exact foreground peer, and terminate the old PID.
            try requestNormalOpenOfAccessory(
                headless,
                pid: oldPID,
                requiresNominalThermalState: false,
                protectedCleanup: false
            )

            let handoffDeadline = Date().addingTimeInterval(35)
            var foreground: NSRunningApplication?
            while Date() < handoffDeadline {
                try requireUnlockedInteractiveSession()
                let exact = exactTargetApplications()
                if processHasExited(oldPID),
                   exact.count == 1,
                   exact[0].processIdentifier != oldPID,
                   exact[0].activationPolicy == .regular {
                    foreground = exact[0]
                    break
                }
                RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
            }
            try requireInteractiveTerminalBoundary()
            guard let foreground else {
                let peers = exactTargetApplications()
                    .map { "PID \($0.processIdentifier), policy \($0.activationPolicy.rawValue)" }
                    .joined(separator: "; ")
                throw AcceptanceError.failed(
                    "The bounded handoff did not replace accessory PID \(oldPID) with one exact regular peer. Observed: \(peers.isEmpty ? "none" : peers)."
                )
            }

            let newPID = foreground.processIdentifier
            try recordProcessIdentity(pid: newPID)
            let application = AXUIElementCreateApplication(newPID)
            let settlementDeadline = Date().addingTimeInterval(statusItemSettlement)
            while Date() < settlementDeadline {
                try requireUnlockedInteractiveSession()
                if processHasExited(newPID) {
                    throw AcceptanceError.failed("Foreground PID \(newPID) exited during the status-item settlement window.")
                }
                RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
            }
            try requireInteractiveTerminalBoundary()
            let initialItem = try waitForSingleStatusItem(in: application, pid: newPID, timeout: 15)
            let stable = try collectStableGeometry(
                initial: initialItem,
                application: application,
                pid: newPID
            )
            let freshItem = try waitForSingleStatusItem(in: application, pid: newPID, timeout: 2)
            guard CFEqual(freshItem.element, stable.item.element) else {
                throw AcceptanceError.failed(
                    "Foreground PID \(newPID) replaced its status item after the stable-identity dwell."
                )
            }
            print("  old PID \(oldPID) exited; exact foreground PID \(newPID) exposed one identity-stable top-visible Fulmar menu")
            try openMenuVerifyAndQuit(item: freshItem, pid: newPID)
            try ensureNoTargetBundleIsRunning()
        } catch {
            let environmentalError = environmentalDeferral(in: error)
            let cleanupComplete = cleanupAllLaunchedTargetProcesses(protected: false)
            if let environmentalError {
                switch StatusItemAcceptanceSupport.safetyExitDisposition(
                    openRequestSettled: true,
                    cleanupComplete: cleanupComplete,
                    disposableStateRemoved: true
                ) {
                case .deferred:
                    throw environmentalError
                case .hardFailure:
                    throw AcceptanceError.failed(
                        "The interactive session became unavailable, but exact headless-handoff process cleanup could not be verified."
                    )
                }
            }
            throw AcceptanceError.failed("Headless handoff cycle \(cycle) failed: \(error.localizedDescription)")
        }
    }

    /// Exercises the user-facing status menu in an ordinary foreground launch.
    /// Unlike `--status-item-acceptance`, this starts the app without a test
    /// argument, so the production window graph and menu actions are enabled.
    /// The gate never creates a task or sends a model prompt; it only opens and
    /// closes already-constructed native windows before using the real Quit
    /// action and protected shutdown path.
    func runNormalMenuActions() throws {
        guard AXIsProcessTrusted() else {
            throw AcceptanceError.failed(
                "Accessibility access is required for the normal status-menu action test. "
                + "Enable the terminal or automation host in System Settings > Privacy & Security > Accessibility, then run the test again."
            )
        }
        try requireUnlockedInteractiveSession()
        try ensureNoTargetBundleIsRunning()
        print("Normal status-menu action acceptance")
        print("  app: \(appURL.path)")
        print("  model work: none (no task or generation request is made)")

        let running = try launchExactTarget(
            arguments: [],
            activates: true,
            protectedCleanup: true
        )
        let pid = running.processIdentifier
        let application = AXUIElementCreateApplication(pid)
        print("  launched ordinary foreground PID \(pid) with no acceptance argument")

        do {
            guard try waitForActivation(of: running, pid: pid, timeout: 10) else {
                throw AcceptanceError.failed(
                    "LaunchServices opened ordinary PID \(pid), but it did not become the active foreground app within 10 seconds."
                )
            }
            let statusItem = try waitForSingleStatusItem(in: application, pid: pid, timeout: 20)
            _ = try collectStableGeometry(
                initial: statusItem,
                application: application,
                pid: pid
            )
            try closeVisibleWindow(
                named: productName,
                in: application,
                pid: pid,
                timeout: 20
            )
            print("  closed the initially visible Agent Workspace")

            try activateStatusMenuAction(
                "Open \(productName)",
                expectingWindow: productName,
                in: application,
                pid: pid
            )
            try closeVisibleWindow(named: productName, in: application, pid: pid, timeout: 10)

            try activateStatusMenuAction(
                "Chat",
                expectingWindow: "Chat",
                in: application,
                pid: pid
            )
            try closeVisibleWindow(named: "Chat", in: application, pid: pid, timeout: 10)

            try activateStatusMenuAction(
                "Settings…",
                expectingWindow: "\(productName) Settings",
                in: application,
                pid: pid
            )
            try closeVisibleWindow(
                named: "\(productName) Settings",
                in: application,
                pid: pid,
                timeout: 10
            )

            let items = try openStatusMenu(in: application, pid: pid)
            try waitForEnabledCoreMenuItems(items, pid: pid, timeout: 5)
            guard let quit = items.first(where: { canonicalMenuTitle($0.name) == "Quit \(productName)" }) else {
                throw AcceptanceError.failed("Could not resolve the exact Quit \(productName) menu item for PID \(pid).")
            }
            try performMenuItem(quit, title: "Quit \(productName)", pid: pid)
            guard waitForExit(pid: pid, timeout: 45) else {
                try throwInteractiveTimeout(
                    "Quit \(productName) was activated in normal mode, but exact PID \(pid) was still running after 45 seconds."
                )
            }
            try ensureNoTargetBundleIsRunning()
            print("PASS: the ordinary app exposed one visible menu-bar icon; Open Fulmar, Chat, Settings, and protected Quit all completed on the exact PID.")
        } catch {
            let environmentalError = environmentalDeferral(in: error)
            if environmentalError == nil {
                printDiagnostics(pid: pid)
            }
            let cleanupComplete = cleanupAllLaunchedTargetProcesses(protected: true)
            if let environmentalError {
                switch StatusItemAcceptanceSupport.safetyExitDisposition(
                    openRequestSettled: true,
                    cleanupComplete: cleanupComplete,
                    disposableStateRemoved: true
                ) {
                case .deferred:
                    throw environmentalError
                case .hardFailure:
                    throw AcceptanceError.failed(
                        "The interactive session became unavailable, but protected normal-app cleanup could not be verified. No raw termination signal was sent."
                    )
                }
            }
            throw error
        }
    }

    private func runCycle(_ cycle: Int) throws {
        try requireUnlockedInteractiveSession()
        let running = try launchExactTarget(arguments: ["--status-item-acceptance"])
        let pid = running.processIdentifier
        let cpuWallStart = ProcessInfo.processInfo.systemUptime
        guard let cpuStart = processCPUSeconds(pid: pid) else {
            _ = cleanupExactLaunchedProcess(pid: pid)
            throw AcceptanceError.failed("Could not read the exact target PID \(pid) CPU baseline.")
        }
        print("  launched PID \(pid) with --status-item-acceptance")

        do {
            // Let Control Center restore the item's stable autosaved identity
            // before strict geometry observation begins.
            let settlementDeadline = Date().addingTimeInterval(statusItemSettlement)
            while Date() < settlementDeadline {
                try requireUnlockedInteractiveSession()
                if processHasExited(pid) {
                    throw AcceptanceError.failed("PID \(pid) exited during the status-item settlement window.")
                }
                RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
            }
            try requireInteractiveTerminalBoundary()
            let application = AXUIElementCreateApplication(pid)
            let first = try waitForSingleStatusItem(in: application, pid: pid, timeout: 15)
            let stable = try collectStableGeometry(
                initial: first,
                application: application,
                pid: pid
            )
            let frame = stable.frames.last!
            let geometries = currentDisplayGeometries()
            let display = geometries.first {
                $0.displayID == StatusItemVisibilityGeometry.topDisplay(
                    containing: frame,
                    displays: geometries
                )?.displayID
            }
            let displayDescription = display.map {
                "display \($0.displayID) \(describe($0.bounds))"
            } ?? "an unknown display"
            let dwellText = String(format: "%.1f", stableVisibilityDwell)
            print("  one '\(expectedStatusName)' at \(describe(frame)) (top-visible for \(dwellText)s on \(displayDescription))")

            let pressError = try performInteractiveAXAction(
                stable.item.element,
                action: kAXPressAction as CFString,
                failureMessage: {
                    "AXPress on '\(expectedStatusName)' failed for PID \(pid): \(describe($0))."
                }
            )
            // A status-item press can enter AppKit's modal menu-tracking loop.
            // Some macOS builds then return cannotComplete to the AX caller
            // even though the menu is visibly open. Accept only that specific
            // transport result, and still require the opened menu below.
            let menu = try waitForStatusMenu(from: stable.item.element, pid: pid, timeout: 5)
            if pressError == .success {
                print("  AXPress succeeded")
            } else {
                print("  AXPress opened the menu (AppKit returned cannotComplete after entering menu tracking)")
            }
            try requireUnlockedInteractiveSession()
            let items = menuItems(in: menu)
            for expected in expectedMenuTitles {
                guard items.contains(where: { canonicalMenuTitle($0.name) == expected }) else {
                    let titles = items.map(\.name).filter { !$0.isEmpty }.joined(separator: " | ")
                    throw AcceptanceError.failed(
                        "The opened status menu for PID \(pid) is missing '\(expected)'. Visible menu titles: \(titles)"
                    )
                }
            }
            try verifyLightweightMenuEnablement(items, pid: pid)
            print("  menu verified: \(expectedMenuTitles.joined(separator: ", "))")

            let cpu = try processCPUObservation(
                pid: pid,
                wallStart: cpuWallStart,
                cpuStart: cpuStart
            )
            print(String(
                format: "  target CPU during complete AX proof: %.1f%% of one core (%.3fs CPU / %.3fs wall)",
                cpu.oneCorePercent,
                cpu.cpuSeconds,
                cpu.wallSeconds
            ))
           guard cpu.oneCorePercent <= maximumTargetOneCorePercent else {
               throw AcceptanceError.failed(String(
                   format: "Exact PID %d averaged %.1f%% of one core during the accessibility proof; the release ceiling is %.1f%%.",
                   pid,
                   cpu.oneCorePercent,
                   maximumTargetOneCorePercent
               ))
           }
            try ensureNoTargetBundlePeer(excluding: pid)

           guard let quit = items.first(where: { canonicalMenuTitle($0.name) == "Quit Fulmar" }) else {
                throw AcceptanceError.failed("Could not resolve the exact Quit Fulmar menu item for PID \(pid).")
            }
            _ = try performInteractiveAXAction(
                quit.element,
                action: kAXPressAction as CFString,
                failureMessage: {
                    "AXPress on Quit Fulmar failed for PID \(pid): \(describe($0))."
                }
            )
            guard waitForExit(pid: pid, timeout: 15) else {
                try throwInteractiveTimeout(
                    "Quit Fulmar was activated, but exact PID \(pid) was still running after 15 seconds."
                )
            }
            try ensureNoTargetBundleIsRunning()
            print("  Quit Fulmar terminated exact PID \(pid)")
        } catch {
            let environmentalError = environmentalDeferral(in: error)
            if environmentalError == nil {
                printDiagnostics(pid: pid)
            }
            let cleanupComplete = cleanupAllLaunchedTargetProcesses(protected: false)
            if let environmentalError {
                switch StatusItemAcceptanceSupport.safetyExitDisposition(
                    openRequestSettled: true,
                    cleanupComplete: cleanupComplete,
                    disposableStateRemoved: true
                ) {
                case .deferred:
                    throw environmentalError
                case .hardFailure:
                    throw AcceptanceError.failed(
                        "The interactive session became unavailable, but exact status-acceptance process cleanup could not be verified."
                    )
                }
            }
            throw AcceptanceError.failed("Cycle \(cycle) failed: \(error.localizedDescription)")
        }
    }

    private func openMenuVerifyAndQuit(
        item: ElementSnapshot,
        pid: pid_t
    ) throws {
        _ = try performInteractiveAXAction(
            item.element,
            action: kAXPressAction as CFString,
            failureMessage: {
                "AXPress on '\(expectedStatusName)' failed for PID \(pid): \(describe($0))."
            }
        )
        let menu = try waitForStatusMenu(from: item.element, pid: pid, timeout: 5)
        try requireUnlockedInteractiveSession()
        let items = menuItems(in: menu)
        try ensureNoTargetBundlePeer(excluding: pid)
       for expected in expectedMenuTitles {
            guard items.contains(where: { canonicalMenuTitle($0.name) == expected }) else {
                let titles = items.map(\.name).filter { !$0.isEmpty }.joined(separator: " | ")
                throw AcceptanceError.failed(
                    "The opened status menu for PID \(pid) is missing '\(expected)'. Visible menu titles: \(titles)"
                )
            }
        }
        try verifyLightweightMenuEnablement(items, pid: pid)
        guard let quit = items.first(where: { canonicalMenuTitle($0.name) == "Quit Fulmar" }) else {
            throw AcceptanceError.failed("Could not resolve the exact Quit Fulmar menu item for PID \(pid).")
        }
        _ = try performInteractiveAXAction(
            quit.element,
            action: kAXPressAction as CFString,
            failureMessage: {
                "AXPress on Quit Fulmar failed for PID \(pid): \(describe($0))."
            }
        )
        guard waitForExit(pid: pid, timeout: 15) else {
            try throwInteractiveTimeout(
                "Quit Fulmar was activated, but exact PID \(pid) was still running after 15 seconds."
            )
        }
        try ensureNoTargetBundleIsRunning()
        print("  menu verified and Quit Fulmar terminated exact PID \(pid)")
    }

    private func verifyLightweightMenuEnablement(
        _ items: [ElementSnapshot],
        pid: pid_t
    ) throws {
        for title in expectedMenuTitles {
            try requireUnlockedInteractiveSession()
            guard let item = items.first(where: { canonicalMenuTitle($0.name) == title }) else {
                throw AcceptanceError.failed("The lightweight menu for PID \(pid) is missing '\(title)'.")
            }
            let shouldBeEnabled = title == "Quit \(productName)"
            guard booleanValue(item.element, kAXEnabledAttribute as String) == shouldBeEnabled else {
                throw AcceptanceError.failed(
                    "The lightweight menu action '\(title)' for PID \(pid) did not preserve its reviewed \(shouldBeEnabled ? "enabled" : "disabled") state."
                )
            }
        }
    }

    private func openStatusMenu(
        in application: AXUIElement,
        pid: pid_t
    ) throws -> [ElementSnapshot] {
        let item = try waitForSingleStatusItem(in: application, pid: pid, timeout: 10)
        _ = try performInteractiveAXAction(
            item.element,
            action: kAXPressAction as CFString,
            failureMessage: {
                "AXPress on '\(expectedStatusName)' failed for PID \(pid): \(describe($0))."
            }
        )
        let menu = try waitForStatusMenu(from: item.element, pid: pid, timeout: 5)
        try requireUnlockedInteractiveSession()
        return menuItems(in: menu)
    }

    private func waitForEnabledCoreMenuItems(
        _ items: [ElementSnapshot],
        pid: pid_t,
        timeout: TimeInterval
    ) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            for expected in expectedMenuTitles where !items.contains(where: {
                canonicalMenuTitle($0.name) == expected
            }) {
                throw AcceptanceError.failed("The normal status menu for PID \(pid) is missing '\(expected)'.")
            }
            let disabled = expectedMenuTitles.filter { expected in
                guard let item = items.first(where: { canonicalMenuTitle($0.name) == expected }) else {
                    return true
                }
                return booleanValue(item.element, kAXEnabledAttribute as String) != true
            }
            if disabled.isEmpty { return }
            if processHasExited(pid) {
                throw AcceptanceError.failed(
                    "PID \(pid) exited while waiting for its production status-menu actions to become enabled."
                )
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(accessibilityPollInterval))
        }
        try requireInteractiveTerminalBoundary()
        let disabled = expectedMenuTitles.filter { expected in
            guard let item = items.first(where: { canonicalMenuTitle($0.name) == expected }) else {
                return true
            }
            return booleanValue(item.element, kAXEnabledAttribute as String) != true
        }
        throw AcceptanceError.failed(
            "The normal status menu for PID \(pid) did not enable its production actions within \(timeout) seconds: \(disabled.joined(separator: ", "))."
        )
    }

    private func activateStatusMenuAction(
        _ title: String,
        expectingWindow windowTitle: String,
        in application: AXUIElement,
        pid: pid_t
    ) throws {
        let items = try openStatusMenu(in: application, pid: pid)
        try waitForEnabledCoreMenuItems(items, pid: pid, timeout: 5)
        guard let action = items.first(where: { canonicalMenuTitle($0.name) == title }) else {
            throw AcceptanceError.failed("Could not resolve the exact normal status-menu action '\(title)' for PID \(pid).")
        }
        try performMenuItem(action, title: title, pid: pid)
        _ = try waitForVisibleWindow(named: windowTitle, in: application, pid: pid, timeout: 10)
        try ensureNoTargetBundlePeer(excluding: pid)
        print("  \(title) opened one visible, frontmost '\(windowTitle)' window")
    }

    private func performMenuItem(
        _ item: ElementSnapshot,
        title: String,
        pid: pid_t
    ) throws {
        try requireUnlockedInteractiveSession()
        guard booleanValue(item.element, kAXEnabledAttribute as String) == true else {
            throw AcceptanceError.failed("The normal status-menu action '\(title)' is disabled for PID \(pid).")
        }
        _ = try performInteractiveAXAction(
            item.element,
            action: kAXPressAction as CFString,
            failureMessage: {
                "AXPress on normal status-menu action '\(title)' failed for PID \(pid): \(describe($0))."
            }
        )
    }

    /// Reads only the application's direct AXWindows array. It deliberately
    /// does not descend through a window's children, which avoids the runaway
    /// table materialisation that motivated the bounded status-item traversal.
    private func visibleApplicationWindows(in application: AXUIElement) -> [ElementSnapshot] {
        uniqueSnapshots(
            elements(
                for: application,
                attributes: [kAXWindowsAttribute as String],
                maximumCount: 16
            )
            .map(snapshot)
            .filter { snapshot in
                snapshot.role == (kAXWindowRole as String)
                    && (snapshot.frame?.width ?? 0) > 0
                    && (snapshot.frame?.height ?? 0) > 0
                    && booleanValue(snapshot.element, kAXMinimizedAttribute as String) != true
            }
        )
    }

    private func waitForVisibleWindow(
        named title: String,
        in application: AXUIElement,
        pid: pid_t,
        timeout: TimeInterval
    ) throws -> ElementSnapshot {
        let deadline = Date().addingTimeInterval(timeout)
        var observed: [String] = []
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            let windows = visibleApplicationWindows(in: application)
            observed = windows.map(\.name)
            if let match = windows.first(where: {
                StatusItemAcceptanceSupport.windowNames(
                    $0.names,
                    matchExpectedTitle: title,
                    productName: productName
                )
            }),
               let frame = match.frame,
               booleanValue(match.element, kAXMainAttribute as String) == true,
               StatusItemAcceptanceSupport.frameIntersectsVisibleDisplay(
                   frame,
                   displays: currentDisplayGeometries().map(\.bounds)
               ),
               let focused = elements(
                   for: application,
                   attributes: [kAXFocusedWindowAttribute as String],
                   maximumCount: 1
               ).first,
               CFEqual(focused, match.element),
               NSRunningApplication(processIdentifier: pid)?.isActive == true {
                return match
            }
            if processHasExited(pid) {
                throw AcceptanceError.failed("PID \(pid) exited before '\(title)' became a visible main window.")
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(accessibilityPollInterval))
        }
        try throwInteractiveTimeout(
            "The normal menu action did not expose an onscreen, active, focused main window named '\(title)' for PID \(pid). Observed: \(observed.joined(separator: " | "))"
        )
    }

    private func closeVisibleWindow(
        named title: String,
        in application: AXUIElement,
        pid: pid_t,
        timeout: TimeInterval
    ) throws {
        let window = try waitForVisibleWindow(named: title, in: application, pid: pid, timeout: timeout)
        try requireUnlockedInteractiveSession()
        guard let closeButton = elements(
            for: window.element,
            attributes: [kAXCloseButtonAttribute as String],
            maximumCount: 1
        ).first else {
            throw AcceptanceError.failed("The visible '\(title)' window for PID \(pid) exposed no close button.")
        }
        _ = try performInteractiveAXAction(
            closeButton,
            action: kAXPressAction as CFString,
            failureMessage: {
                "Closing '\(title)' failed for PID \(pid): \(describe($0))."
            }
        )

        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            if !visibleApplicationWindows(in: application).contains(where: {
                StatusItemAcceptanceSupport.windowNames(
                    $0.names,
                    matchExpectedTitle: title,
                    productName: productName
                )
            }) {
                return
            }
            if processHasExited(pid) {
                throw AcceptanceError.failed("PID \(pid) exited while closing '\(title)'.")
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(accessibilityPollInterval))
        }
        try throwInteractiveTimeout(
            "The visible '\(title)' window did not close for PID \(pid)."
        )
    }

    private func launchExactTarget(
        arguments: [String],
        activates: Bool = false,
        environment: [String: String] = [:],
        protectedCleanup: Bool = false
    ) throws -> NSRunningApplication {
        try requireUnlockedInteractiveSession()
        try ensureNoTargetBundleIsRunning()

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = activates
        configuration.createsNewApplicationInstance = true
        configuration.arguments = arguments
        configuration.environment = environment

        let barrier = StatusItemAcceptanceSupport.OpenRequestBarrier<NSRunningApplication>()
        let generation = barrier.generation
        NSWorkspace.shared.openApplication(at: appURL, configuration: configuration) { application, error in
            _ = barrier.resolve(
                generation: generation,
                payload: application,
                errorDescription: error?.localizedDescription
            )
        }

        var requestSettled = false
        var authenticatedApplication: NSRunningApplication?
        do {
            let settled = try settleOpenRequest(
                barrier,
                requiresNominalThermalState: false
            )
            requestSettled = true

            if let application = settled.application {
                guard canonicalBundleURL(for: application) == appURL else {
                    throw AcceptanceError.failed(
                        "LaunchServices returned PID \(application.processIdentifier) for a different bundle path: "
                        + "\(application.bundleURL?.path ?? "unknown"). The gate did not terminate that foreign process."
                    )
                }
                authenticatedApplication = application
            }

            // Authenticate before considering a deferral. A late callback that
            // returned the exact app is owned by the catch path below and must
            // be stopped and proven absent before exit 75 is possible.
            if let safetyDeferral = settled.safetyDeferral {
                throw safetyDeferral
            }
            if let errorDescription = settled.errorDescription {
                throw AcceptanceError.failed(
                    "LaunchServices could not open \(appURL.path): \(errorDescription)"
                )
            }
            guard let launched = authenticatedApplication else {
                throw AcceptanceError.failed(
                    "LaunchServices settled the request without returning an application for \(appURL.path)."
                )
            }

            try recordProcessIdentity(pid: launched.processIdentifier)
            try ensureNoTargetBundlePeer(excluding: launched.processIdentifier)
            try requireUnlockedInteractiveSession()
            return launched
        } catch {
            // Identity capture can itself fail after dispatch. The callback has
            // still authenticated this NSRunningApplication by canonical bundle
            // URL, so an AppKit termination request is safe. Raw signals remain
            // forbidden for protected normal-app cleanup.
            if let authenticatedApplication,
               launchedProcessIdentities[authenticatedApplication.processIdentifier] == nil {
                _ = authenticatedApplication.terminate()
            }
            let cleanupComplete = cleanupAllLaunchedTargetProcesses(
                protected: protectedCleanup
            )

            if let safetyDeferral = safetyDeferral(in: error) {
                switch StatusItemAcceptanceSupport.safetyExitDisposition(
                    openRequestSettled: requestSettled,
                    cleanupComplete: cleanupComplete,
                    disposableStateRemoved: true
                ) {
                case .deferred:
                    throw safetyDeferral
                case .hardFailure:
                    throw AcceptanceError.failed(
                        "A safety deferral occurred after Launch Services dispatch, but request settlement and exact process cleanup were not both verified."
                    )
                }
            }

            if let acceptanceError = error as? AcceptanceError,
               case let .launchRequestUnsettled(message) = acceptanceError {
                let cleanupSuffix = cleanupComplete
                    ? " Current exact-process inventory was quiescent, but the callback can still arrive."
                    : " Current exact-process cleanup was also incomplete."
                throw AcceptanceError.launchRequestUnsettled(message + cleanupSuffix)
            }
            if !cleanupComplete {
                throw AcceptanceError.failed(
                    "Launch Services startup failed (\(error.localizedDescription)), and exact post-dispatch process cleanup could not be verified."
                )
            }
            if let acceptanceError = error as? AcceptanceError {
                throw acceptanceError
            }
            throw error
        }
    }

    /// Live AppKit/Accessibility qualification is invalid while the console is
    /// locked or displaying the login window: macOS will correctly refuse an
    /// automated foreground request even when the target is a healthy regular
    /// application. Detect that public NSWorkspace state before launching any
    /// candidate so the gate reports an environmental precondition instead of
    /// misclassifying it as a Fulmar activation failure.
    private func interactiveSessionObservation() -> InteractiveSessionObservation {
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        let onConsole = session?["kCGSSessionOnConsoleKey"] as? Bool
        let loginDone = session?["kCGSessionLoginDoneKey"] as? Bool
        let sessionUserID = (session?["kCGSSessionUserIDKey"] as? NSNumber)?.uint32Value
        let workspace = NSWorkspace.shared
        let frontmost = workspace.frontmostApplication
        let menuBarOwner = workspace.menuBarOwningApplication
        let frontmostIdentifier = frontmost?.bundleIdentifier
        let menuBarOwnerIdentifier = menuBarOwner?.bundleIdentifier
        return InteractiveSessionObservation(
            state: StatusItemAcceptanceSupport.interactiveSessionState(
                onConsole: onConsole,
                loginDone: loginDone,
                sessionUserID: sessionUserID,
                effectiveUserID: UInt32(geteuid()),
                frontmostBundleIdentifier: frontmostIdentifier,
                menuBarOwnerBundleIdentifier: menuBarOwnerIdentifier
            ),
            frontmostBundleIdentifier: frontmostIdentifier,
            menuBarOwnerBundleIdentifier: menuBarOwnerIdentifier
        )
    }

    private func requireUnlockedInteractiveSession() throws {
        let deadline = Date().addingTimeInterval(interactiveSessionStabilizationTimeout)
        var observation = interactiveSessionObservation()
        while observation.state == .indeterminate, Date() < deadline {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
            observation = interactiveSessionObservation()
        }
        guard observation.state == .ready else {
            let frontmostDescription = observation.frontmostBundleIdentifier ?? "none"
            let menuBarDescription = observation.menuBarOwnerBundleIdentifier ?? "none"
            let reason = observation.state == .secureOrWrongUser
                ? "a secure, logged-out, off-console, or wrong-user desktop"
                : "a stable interactive desktop"
            throw AcceptanceError.environmentallyDeferred(
                "Live UI qualification was safely deferred because macOS does not expose \(reason) for this user "
                + "(frontmost: \(frontmostDescription); menu bar owner: \(menuBarDescription)). "
                + "Unlock the Mac, leave an ordinary app visible, and rerun the gate."
            )
        }
    }

    /// Revalidates the desktop after the final polling sleep and before any
    /// timeout-derived candidate observation or hard failure. This closes the
    /// boundary where the last loop iteration could see an unlocked session,
    /// sleep, then time out after the Mac locked.
    private func requireInteractiveTerminalBoundary(
        requiresNominalThermalState: Bool = false
    ) throws {
        try requireUnlockedInteractiveSession()
        if requiresNominalThermalState {
            try requireNominalThermalState()
        }
        switch StatusItemAcceptanceSupport.interactiveTimeoutDisposition(
            postSleepSessionState: interactiveSessionObservation().state
        ) {
        case .candidateFailure:
            return
        case .environmentallyDeferred:
            throw AcceptanceError.environmentallyDeferred(
                "Live UI qualification was safely deferred because the interactive session changed at a polling timeout boundary. Unlock the Mac and rerun the gate."
            )
        }
    }

    private func throwInteractiveTimeout(
        _ message: @autoclosure () -> String,
        requiresNominalThermalState: Bool = false
    ) throws -> Never {
        try requireInteractiveTerminalBoundary(
            requiresNominalThermalState: requiresNominalThermalState
        )
        throw AcceptanceError.failed(message())
    }

    private func environmentalDeferral(in error: Error) -> AcceptanceError? {
        guard let acceptanceError = error as? AcceptanceError,
              case .environmentallyDeferred = acceptanceError else { return nil }
        return acceptanceError
    }

    private func safetyDeferral(in error: Error) -> AcceptanceError? {
        guard let acceptanceError = error as? AcceptanceError else { return nil }
        switch acceptanceError {
        case .thermallyDeferred, .environmentallyDeferred:
            return acceptanceError
        case .failed, .launchRequestUnsettled:
            return nil
        }
    }

    private func performInteractiveAXAction(
        _ element: AXUIElement,
        action: CFString,
        failureMessage: (AXError) -> String
    ) throws -> AXError {
        try requireUnlockedInteractiveSession()
        let error = AXUIElementPerformAction(element, action)
        // Stabilise once, then classify the transport result against an
        // immediately injected post-action session observation. A lock race
        // must remain an environmental deferral even when AX also failed.
        try requireUnlockedInteractiveSession()
        let postActionSessionState = interactiveSessionObservation().state
        switch StatusItemAcceptanceSupport.interactiveTransportDisposition(
            transportAccepted: error == .success || error == .cannotComplete,
            postActionSessionState: postActionSessionState
        ) {
        case .accepted:
            return error
        case .candidateFailure:
            throw AcceptanceError.failed(failureMessage(error))
        case .environmentallyDeferred:
            throw AcceptanceError.environmentallyDeferred(
                "Live UI qualification was safely deferred because the interactive session changed during an Accessibility action. Unlock the Mac and rerun the gate."
            )
        }
    }

    private func waitForActivation(
        of application: NSRunningApplication,
        pid: pid_t,
        timeout: TimeInterval
    ) throws -> Bool {
        try requireUnlockedInteractiveSession()
        _ = application.activate(options: [.activateAllWindows])
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            if application.isActive { return true }
            if processHasExited(pid) { return false }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(accessibilityPollInterval))
        }
        try requireInteractiveTerminalBoundary()
        return application.isActive
    }

    private func waitForAccessoryLaunchState(
        of application: NSRunningApplication,
        application accessibilityApplication: AXUIElement,
        pid: pid_t,
        timeout: TimeInterval
    ) throws {
        let deadline = Date().addingTimeInterval(timeout)
        var lastPolicy = application.activationPolicy
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            if processHasExited(pid) {
                throw AcceptanceError.failed("PID \(pid) exited before accessory activation settled.")
            }
            guard statusItems(in: accessibilityApplication).isEmpty,
                  visibleApplicationWindows(in: accessibilityApplication).isEmpty else {
                throw AcceptanceError.failed(
                    "PID \(pid) exposed a window or status item before accessory activation settled."
                )
            }
            guard let current = NSRunningApplication(processIdentifier: pid) else {
                throw AcceptanceError.failed("PID \(pid) disappeared before accessory activation settled.")
            }
            lastPolicy = current.activationPolicy
            if lastPolicy == .accessory { return }
            RunLoop.current.run(
                mode: .default,
                before: Date().addingTimeInterval(accessibilityPollInterval)
            )
        }
        try throwInteractiveTimeout(
            "Expected PID \(pid) to settle as an accessory app within \(timeout) seconds; last observed policy was \(lastPolicy.rawValue)."
        )
    }

    private func ensureNoTargetBundlePeer(excluding pid: pid_t) throws {
        let peers = try runningTargetBundleProcesses().filter { $0.pid != pid }
        guard peers.isEmpty else {
            throw AcceptanceError.failed(
                "A second process with bundle identifier '\(targetBundleIdentifier)' appeared: "
                + describeBundleProcesses(peers) + ". No peer process was killed."
            )
        }
    }

    private func ensureNoTargetBundleIsRunning() throws {
        let matches = try runningTargetBundleProcesses()
        guard matches.isEmpty else {
            throw AcceptanceError.failed(
                "A process with target bundle identifier '\(targetBundleIdentifier)' is already running: "
                + describeBundleProcesses(matches)
                + ". Quit every installed, candidate, and source-build copy before running the cold-launch gate. No process was killed."
            )
        }
    }

    private func ensureNoTargetBundleOwnedProcessIsRunning() throws {
        let matches = try targetBundleOwnedProcesses()
        guard matches.isEmpty else {
            throw AcceptanceError.failed(
                "A process owned by bundle identifier '\(targetBundleIdentifier)' is already running: "
                + describeBundleProcesses(matches)
                + ". Quit every app/helper copy before the physical gate. No process was killed."
            )
        }
    }

    private func targetBundleOwnedProcesses() throws -> [BundleProcess] {
        var matches = Set(try allBSDProcesses().filter { process in
            isExecutableOwnedByTargetBundle(process.executablePath)
        })
        for application in NSWorkspace.shared.runningApplications
            where !application.isTerminated
                && application.bundleIdentifier == targetBundleIdentifier
                && kernelProcessExists(application.processIdentifier) {
            if let path = application.executableURL?
                .standardizedFileURL
                .resolvingSymlinksInPath()
                .path {
                matches.insert(BundleProcess(pid: application.processIdentifier, executablePath: path))
            }
        }
        return matches.sorted {
            $0.pid == $1.pid ? $0.executablePath < $1.executablePath : $0.pid < $1.pid
        }
    }

    private func isExecutableOwnedByTargetBundle(_ path: String) -> Bool {
        var cursor = URL(fileURLWithPath: path).deletingLastPathComponent()
        while cursor.path != "/" {
            if cursor.pathExtension == "app",
               Bundle(url: cursor)?.bundleIdentifier == targetBundleIdentifier {
                return true
            }
            cursor.deleteLastPathComponent()
        }
        return false
    }

    private func runningTargetBundleProcesses() throws -> [BundleProcess] {
        var matches: Set<BundleProcess> = []
        for application in NSWorkspace.shared.runningApplications
            where !application.isTerminated
                && application.bundleIdentifier == targetBundleIdentifier
                && kernelProcessExists(application.processIdentifier) {
            guard let path = application.executableURL?
                .standardizedFileURL
                .resolvingSymlinksInPath()
                .path,
                isMainExecutableOfTargetBundle(path) else { continue }
            matches.insert(BundleProcess(pid: application.processIdentifier, executablePath: path))
        }
        for process in try allBSDProcesses() {
            if isMainExecutableOfTargetBundle(process.executablePath) {
                matches.insert(process)
            }
        }
        return matches.sorted {
            $0.pid == $1.pid ? $0.executablePath < $1.executablePath : $0.pid < $1.pid
        }
    }

    private func allBSDProcesses() throws -> [BundleProcess] {
        let estimatedCount = max(0, Int(proc_listallpids(nil, 0)))
        guard estimatedCount > 0 else {
            throw AcceptanceError.failed("The BSD process inventory estimate failed; refusing a potentially incomplete peer check.")
        }
        var capacity = estimatedCount + 64
        for attempt in 0..<3 {
            var pids = [pid_t](repeating: 0, count: capacity)
            let reportedCount = pids.withUnsafeMutableBytes { buffer in
                proc_listallpids(buffer.baseAddress, Int32(buffer.count))
            }
            switch StatusItemAcceptanceSupport.pidBufferDisposition(
                reportedCount: reportedCount,
                capacity: pids.count,
                canRetry: attempt < 2
            ) {
            case .complete(let copiedCount):
                return pids.prefix(copiedCount).compactMap { pid in
                    guard pid > 0, let path = processExecutablePath(pid: pid) else { return nil }
                    return BundleProcess(pid: pid, executablePath: path)
                }
            case .grow(let nextCapacity):
                capacity = nextCapacity
            case .invalid:
                throw AcceptanceError.failed(
                    "The BSD process inventory was unavailable or truncated; refusing a potentially incomplete peer check."
                )
            }
        }
        throw AcceptanceError.failed("The BSD process inventory did not converge within its bounded retries.")
    }

    private func resolvePhysicalOllamaExecutablePaths() throws -> Set<String> {
        let fixedCandidates = [
            "/Applications/Ollama.app/Contents/Resources/ollama",
            "/usr/local/bin/ollama",
            "/opt/homebrew/bin/ollama"
        ]
        var exactPaths = Set<String>()
        for candidate in fixedCandidates {
            var sourceMetadata = stat()
            guard Darwin.lstat(candidate, &sourceMetadata) == 0 else { continue }
            var canonicalBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
            guard Darwin.realpath(candidate, &canonicalBuffer) != nil else { continue }
            let canonical = String(cString: canonicalBuffer)
            var metadata = stat()
            guard Darwin.lstat(canonical, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFREG,
                  metadata.st_nlink == 1,
                  metadata.st_uid == 0 || metadata.st_uid == geteuid(),
                  metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
                  metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0,
                  officialOllamaStaticCodeIsValid(URL(fileURLWithPath: canonical)) else {
                continue
            }
            exactPaths.insert(canonical)
        }
        guard !exactPaths.isEmpty else {
            throw AcceptanceError.failed(
                "No exact official Ollama executable could be resolved from Fulmar's fixed trusted installation paths."
            )
        }
        return exactPaths
    }

    private func officialOllamaRequirement() -> SecRequirement? {
        let text = "anchor apple generic and identifier \"ai.ollama.ollama\" and certificate leaf[subject.OU] = \"3MU9H2V9Y9\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }

    private func officialOllamaStaticCodeIsValid(_ executable: URL) -> Bool {
        guard let requirement = officialOllamaRequirement() else { return false }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(executable as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        return SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
            requirement
        ) == errSecSuccess
    }

    private func officialOllamaProcessIsValid(_ process: BundleProcess) -> Bool {
        guard physicalOllamaExecutablePaths.contains(process.executablePath),
              let requirement = officialOllamaRequirement() else { return false }
        let attributes = [
            kSecGuestAttributePid as String: NSNumber(value: process.pid)
        ] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code,
              SecCodeCheckValidity(
                code,
                SecCSFlags(rawValue: kSecCSStrictValidate),
                requirement
              ) == errSecSuccess else { return false }
        return officialOllamaStaticCodeIsValid(URL(fileURLWithPath: process.executablePath))
    }

    private func ensureNoOllamaCLIProcessIsRunning() throws {
        guard !physicalOllamaExecutablePaths.isEmpty else {
            throw AcceptanceError.failed("The exact official Ollama executable identity was not initialized.")
        }
        let matches = try allBSDProcesses().filter {
            physicalOllamaExecutablePaths.contains($0.executablePath)
        }
        guard matches.isEmpty else {
            throw AcceptanceError.failed(
                "An exact trusted-path Ollama process is already running, so app ownership cannot be proven: "
                + describeBundleProcesses(matches) + ". No process was killed."
            )
        }
    }

    private func candidateRuntimeProcesses() throws -> [BundleProcess] {
        let prefix = appURL.path + "/Contents/"
        return try allBSDProcesses().filter {
            $0.executablePath.hasPrefix(prefix) && $0.executablePath != targetMainExecutablePath
        }
    }

    private func ensureNoCandidateRuntimeProcessIsRunning() throws {
        let matches = try candidateRuntimeProcesses()
        guard matches.isEmpty else {
            throw AcceptanceError.failed(
                "A candidate-bundled runtime/helper remained after protected Quit: \(describeBundleProcesses(matches))."
            )
        }
    }

    private func requireExpectedRuntimeChildren(of ancestor: pid_t) throws -> [ProcessIdentity] {
        let processes = try allBSDProcesses()
        let nodePath = appURL
            .appendingPathComponent("Contents/Resources/Runtime/node", isDirectory: false)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
        let descendants = processes.filter { isDescendant($0.pid, of: ancestor) }
        guard descendants.contains(where: { $0.executablePath == nodePath }) else {
            throw AcceptanceError.failed(
                "The durable scheduled occurrence had no exact bundled DSH Node descendant of scheduler PID \(ancestor)."
            )
        }
        guard descendants.contains(where: officialOllamaProcessIsValid) else {
            throw AcceptanceError.failed(
                "The durable scheduled occurrence had no exact app-owned Ollama descendant of scheduler PID \(ancestor)."
            )
        }
        return try captureDescendantProcessIdentities(of: ancestor)
    }

    private func captureDescendantProcessIdentities(of ancestor: pid_t) throws -> [ProcessIdentity] {
        var captured = Set<ProcessIdentity>()
        for attempt in 0..<3 {
            let descendants = try allBSDProcesses().filter { isDescendant($0.pid, of: ancestor) }
            for descendant in descendants {
                if let identity = processIdentity(pid: descendant.pid) {
                    captured.insert(identity)
                } else if kernelProcessExists(descendant.pid) {
                    throw AcceptanceError.failed(
                        "Could not capture a kernel identity for live descendant PID \(descendant.pid)."
                    )
                }
            }
            if attempt < 2 {
                RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.025))
            }
        }
        return Array(captured)
    }

    private func capturedProcessIsRunning(_ identity: ProcessIdentity) -> Bool {
        guard kernelProcessExists(identity.pid) else { return false }
        return processIdentity(pid: identity.pid) == identity
    }

    private func ensureCapturedProcessesExited(
        _ identities: [ProcessIdentity],
        timeout: TimeInterval
    ) throws {
        let exact = Set(identities)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            try requireNominalThermalState()
            if exact.allSatisfy({ !capturedProcessIsRunning($0) }) { return }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        try requireInteractiveTerminalBoundary(
            requiresNominalThermalState: true
        )
        let survivors = exact.filter(capturedProcessIsRunning).sorted { $0.pid < $1.pid }
        guard survivors.isEmpty else {
            throw AcceptanceError.failed(
                "Protected Quit left captured descendant identities running: "
                + survivors.map { "PID \($0.pid)" }.joined(separator: ", ")
            )
        }
    }

    private func waitForProtectedExitCapturingDescendants(
        pid: pid_t,
        capturedChildren: inout [ProcessIdentity],
        timeout: TimeInterval
    ) throws -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            try requireNominalThermalState()
            if processHasExited(pid) { return true }
            capturedChildren.append(contentsOf: try captureDescendantProcessIdentities(of: pid))
            capturedChildren = Array(Set(capturedChildren))
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        try requireInteractiveTerminalBoundary(
            requiresNominalThermalState: true
        )
        return processHasExited(pid)
    }

    private func physicalCleanupIsComplete(capturedChildren: [ProcessIdentity]) -> Bool {
        func inventoryIsQuiescent() -> Bool {
            let capturedGone = Set(capturedChildren).allSatisfy { !capturedProcessIsRunning($0) }
            let bundleGone = (try? targetBundleOwnedProcesses().isEmpty) == true
            let candidateRuntimeGone = (try? candidateRuntimeProcesses().isEmpty) == true
            let exactOllamaGone = (try? allBSDProcesses().allSatisfy {
                !physicalOllamaExecutablePaths.contains($0.executablePath)
            }) == true
            return capturedGone && bundleGone && candidateRuntimeGone && exactOllamaGone
        }
        let deadline = Date().addingTimeInterval(5)
        repeat {
            if inventoryIsQuiescent() { return true }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        } while Date() < deadline
        return inventoryIsQuiescent()
    }

    private func isDescendant(_ pid: pid_t, of ancestor: pid_t) -> Bool {
        var current = pid
        var visited = Set<pid_t>()
        for _ in 0..<64 {
            guard current > 1, visited.insert(current).inserted,
                  let parent = parentPID(of: current) else { return false }
            if parent == ancestor { return true }
            current = parent
        }
        return false
    }

    private func parentPID(of pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let expectedSize = MemoryLayout<proc_bsdinfo>.size
        let copied = withUnsafeMutablePointer(to: &info) { pointer in
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pointer, Int32(expectedSize))
        }
        guard copied == expectedSize else { return nil }
        return pid_t(info.pbi_ppid)
    }

    private func loginHomeDirectory() throws -> URL {
        guard getuid() == geteuid(), geteuid() != 0 else {
            throw AcceptanceError.failed(
                "The physical handoff gate must run as the signed-in, non-root login user."
            )
        }
        let requested = sysconf(_SC_GETPW_R_SIZE_MAX)
        let capacity = requested > 0
            ? min(max(Int(requested), 16 * 1_024), 1 * 1_024 * 1_024)
            : 16 * 1_024
        var record = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: capacity)
        let status = buffer.withUnsafeMutableBufferPointer { storage in
            getpwuid_r(
                geteuid(),
                &record,
                storage.baseAddress,
                storage.count,
                &result
            )
        }
        guard status == 0,
              result != nil,
              record.pw_uid == geteuid(),
              let directory = record.pw_dir,
              directory.pointee != 0 else {
            throw AcceptanceError.failed("The actual login user's home directory could not be resolved safely.")
        }
        let rawPath = String(cString: directory)
        guard rawPath.hasPrefix("/"), rawPath.utf8.count <= Int(PATH_MAX) else {
            throw AcceptanceError.failed("The login database returned an invalid home-directory path.")
        }
        let home = URL(fileURLWithPath: rawPath, isDirectory: true).standardizedFileURL
        var metadata = stat()
        var canonicalBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard Darwin.lstat(home.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & (S_IWGRP | S_IWOTH) == 0,
              Darwin.realpath(home.path, &canonicalBuffer) != nil,
              String(cString: canonicalBuffer) == home.path else {
            throw AcceptanceError.failed(
                "The login user's home directory is missing, linked, or not owner-controlled."
            )
        }
        return home
    }

    private func liveUserModelStore(home: URL) throws -> URL {
        let configured = home
            .appendingPathComponent(".ollama", isDirectory: true)
            .appendingPathComponent("models", isDirectory: true)
        var metadata = stat()
        var canonicalBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard configured.lastPathComponent == "models",
              configured.deletingLastPathComponent().lastPathComponent == ".ollama",
              Darwin.lstat(configured.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_nlink >= 2,
              metadata.st_mode & (S_IWGRP | S_IWOTH) == 0,
              Darwin.realpath(configured.path, &canonicalBuffer) != nil,
              String(cString: canonicalBuffer) == configured.path else {
            throw AcceptanceError.failed(
                "The live Ollama model store is missing, linked, or not owner-controlled; the physical Qwen handoff gate cannot run safely."
            )
        }
        return configured
    }

    private func liveUserStateBoundaries(home: URL) -> [URL] {
        return [
            home.appendingPathComponent("Library/Application Support/Local Harness", isDirectory: true),
            home.appendingPathComponent("Library/Preferences/\(targetBundleIdentifier).plist"),
            home.appendingPathComponent("Library/Caches/\(targetBundleIdentifier)", isDirectory: true),
            home.appendingPathComponent("Library/WebKit/\(targetBundleIdentifier)", isDirectory: true),
            home.appendingPathComponent("Library/Saved Application State/\(targetBundleIdentifier).savedState", isDirectory: true),
            home.appendingPathComponent(".dsh", isDirectory: true),
            home.appendingPathComponent("Library/Keychains", isDirectory: true)
        ]
    }

    /// Fingerprints names and stat metadata only; file contents and credential
    /// values are never opened. ctime makes an in-place write observable even
    /// when a file retains its original byte count.
    private func metadataFingerprint(_ boundary: URL) throws -> FilesystemBoundaryFingerprint {
        var rootMetadata = stat()
        if Darwin.lstat(boundary.path, &rootMetadata) != 0 {
            guard errno == ENOENT else {
                throw AcceptanceError.failed("A live-user state boundary could not be inspected safely.")
            }
            return FilesystemBoundaryFingerprint(exists: false, nodeCount: 0, metadataSHA256: "")
        }
        let rootType = rootMetadata.st_mode & S_IFMT
        guard rootType == S_IFDIR || rootType == S_IFREG else {
            throw AcceptanceError.failed(
                "A live-user state boundary had an unsupported or linked root node type."
            )
        }

        let deadline = Date().addingTimeInterval(30)
        var nodes: [(relative: String, url: URL)] = [(".", boundary)]
        if rootType == S_IFDIR {
            var enumerationFailure: String?
            guard let enumerator = FileManager.default.enumerator(
                at: boundary,
                includingPropertiesForKeys: nil,
                options: [],
                errorHandler: { url, error in
                    enumerationFailure = "\(url.path): \(error.localizedDescription)"
                    return false
                }
            ) else {
                throw AcceptanceError.failed("A live-user state directory could not be enumerated safely.")
            }
            while let url = enumerator.nextObject() as? URL {
                guard Date() <= deadline, nodes.count < 250_000 else {
                    throw AcceptanceError.failed("The live-user state fingerprint exceeded its bounded scan budget.")
                }
                let relative = String(url.path.dropFirst(boundary.path.count + 1))
                guard !relative.isEmpty, relative.utf8.count <= Int(PATH_MAX) else {
                    throw AcceptanceError.failed("A live-user state entry had an invalid relative path.")
                }
                nodes.append((relative, url))
                if nodes.count % 256 == 0 { try requireNominalThermalState() }
            }
            if let enumerationFailure {
                throw AcceptanceError.failed(
                    "A live-user state directory enumeration failed closed: \(enumerationFailure)"
                )
            }
        }
        nodes.sort { $0.relative < $1.relative }

        var hasher = SHA256()
        var capturedRecords: [String: String] = [:]
        capturedRecords.reserveCapacity(nodes.count)
        for (index, node) in nodes.enumerated() {
            let record = try filesystemMetadataRecord(relative: node.relative, url: node.url)
            capturedRecords[node.relative] = record
            hasher.update(data: Data(record.utf8))
            if index % 256 == 0 { try requireNominalThermalState() }
        }
        for (index, node) in nodes.enumerated() {
            guard capturedRecords[node.relative] == (try filesystemMetadataRecord(
                relative: node.relative,
                url: node.url
            )) else {
                throw AcceptanceError.failed(
                    "Live-user state changed while its read-only fingerprint was being captured."
                )
            }
            if index % 256 == 0 { try requireNominalThermalState() }
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return FilesystemBoundaryFingerprint(
            exists: true,
            nodeCount: nodes.count,
            metadataSHA256: digest
        )
    }

    private func filesystemMetadataRecord(relative: String, url: URL) throws -> String {
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0 else {
            throw AcceptanceError.failed(
                "Live-user state changed while its read-only fingerprint was being captured."
            )
        }
        let type = metadata.st_mode & S_IFMT
        guard type == S_IFREG || type == S_IFDIR || type == S_IFLNK else {
            throw AcceptanceError.failed(
                "A live-user state boundary contained an unsupported filesystem node type."
            )
        }

        var fields = [
            String(relative.utf8.count), relative,
            String(metadata.st_dev), String(metadata.st_ino),
            String(metadata.st_mode), String(metadata.st_nlink),
            String(metadata.st_uid), String(metadata.st_gid),
            String(metadata.st_size),
            String(metadata.st_mtimespec.tv_sec), String(metadata.st_mtimespec.tv_nsec),
            String(metadata.st_ctimespec.tv_sec), String(metadata.st_ctimespec.tv_nsec)
        ]
        if type == S_IFLNK {
            var linkBuffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let length = linkBuffer.withUnsafeMutableBufferPointer { storage in
                Darwin.readlink(url.path, storage.baseAddress, storage.count - 1)
            }
            guard length > 0, length < Int(PATH_MAX) else {
                throw AcceptanceError.failed("A live-user state symlink target could not be read safely.")
            }
            let targetBytes = linkBuffer.prefix(length).map { UInt8(bitPattern: $0) }
            guard let target = String(bytes: targetBytes, encoding: .utf8),
                  !target.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                throw AcceptanceError.failed("A live-user state symlink target was malformed.")
            }
            var targetMetadata = stat()
            guard Darwin.fstatat(AT_FDCWD, url.path, &targetMetadata, 0) == 0,
                  targetMetadata.st_mode & S_IFMT == S_IFREG else {
                throw AcceptanceError.failed(
                    "A live-user state symlink was dangling or targeted an unenumerated non-regular node."
                )
            }
            fields.append(contentsOf: [
                "symlink", String(target.utf8.count), target,
                String(targetMetadata.st_dev), String(targetMetadata.st_ino),
                String(targetMetadata.st_mode), String(targetMetadata.st_nlink),
                String(targetMetadata.st_uid), String(targetMetadata.st_gid),
                String(targetMetadata.st_size),
                String(targetMetadata.st_mtimespec.tv_sec), String(targetMetadata.st_mtimespec.tv_nsec),
                String(targetMetadata.st_ctimespec.tv_sec), String(targetMetadata.st_ctimespec.tv_nsec)
            ])
        }
        return fields.joined(separator: "\u{1f}") + "\u{1e}"
    }

    private func processExecutablePath(pid: pid_t) -> String? {
        // proc_pidpath's public C macro is not imported by every Swift SDK.
        // Darwin paths are bounded to 4 KiB here; reject an exactly-full result
        // rather than decoding bytes whose termination cannot be proved.
        let maximumProcessPathBytes = 4_096
        var buffer = [CChar](repeating: 0, count: maximumProcessPathBytes)
        let length = buffer.withUnsafeMutableBufferPointer { pointer in
            proc_pidpath(pid, pointer.baseAddress, UInt32(pointer.count))
        }
        guard let path = StatusItemAcceptanceSupport.decodeProcessPath(
            buffer: buffer,
            reportedLength: length
        ) else { return nil }
        return URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    }

    private func enclosingApplicationBundle(forExecutablePath path: String) -> URL? {
        var candidate = URL(fileURLWithPath: path).deletingLastPathComponent()
        while candidate.path != "/" {
            if candidate.pathExtension == "app" {
                return candidate.standardizedFileURL.resolvingSymlinksInPath()
            }
            candidate.deleteLastPathComponent()
        }
        return nil
    }

    private func isMainExecutableOfTargetBundle(_ path: String) -> Bool {
        guard let bundleURL = enclosingApplicationBundle(forExecutablePath: path),
              let bundle = Bundle(url: bundleURL),
              bundle.bundleIdentifier == targetBundleIdentifier,
              let executableName = bundle.object(forInfoDictionaryKey: "CFBundleExecutable") as? String else {
            return false
        }
        return StatusItemAcceptanceSupport.isBundleMainExecutable(
            executablePath: path,
            bundlePath: bundleURL.path,
            executableName: executableName
        )
    }

    private func describeBundleProcesses(_ processes: [BundleProcess]) -> String {
        processes.map { "PID \($0.pid) [\($0.executablePath)]" }.joined(separator: "; ")
    }

    private func exactTargetApplications() -> [NSRunningApplication] {
        NSWorkspace.shared.runningApplications.filter {
            !$0.isTerminated
                && kernelProcessExists($0.processIdentifier)
                && canonicalBundleURL(for: $0) == appURL
        }
    }

    private func waitForSingleStatusItem(
        in application: AXUIElement,
        pid: pid_t,
        timeout: TimeInterval
    ) throws -> ElementSnapshot {
        let deadline = Date().addingTimeInterval(timeout)
        var lastCount = 0
        var lastFrame: CGRect?
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            let matches = statusItems(in: application)
            lastCount = matches.count
            lastFrame = matches.count == 1 ? matches[0].frame : nil
            // Control Center may publish the AX element at its previous hidden
            // coordinate before finishing placement. Availability is not the
            // release contract; wait boundedly for the one item to occupy a
            // physically visible menu-bar region before stability sampling.
            if matches.count == 1,
               let frame = matches[0].frame,
               isTopVisible(frame) {
                return matches[0]
            }
            if processHasExited(pid) {
                throw AcceptanceError.failed("PID \(pid) exited before its status item became available.")
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(accessibilityPollInterval))
        }
        try requireInteractiveTerminalBoundary()
        let geometry = lastFrame.map(describe) ?? "unavailable"
        throw AcceptanceError.failed(
            "Expected exactly one top-visible accessibility item named '\(expectedStatusName)' for PID \(pid); last observed count was \(lastCount), frame was \(geometry)."
        )
    }

    private func collectStableGeometry(
        initial: ElementSnapshot,
        application: AXUIElement,
        pid: pid_t
    ) throws -> StableStatusItemObservation {
        var frames: [CGRect] = []
        var current = initial
        let stableIdentity = initial.element
        let sampleCount = max(2, Int(ceil(stableVisibilityDwell / accessibilityPollInterval)) + 1)
        for sample in 1...sampleCount {
            try requireUnlockedInteractiveSession()
            if sample == 1 || sample % 4 == 0 {
                try ensureNoTargetBundlePeer(excluding: pid)
            }
            guard CFEqual(current.element, stableIdentity) else {
                throw AcceptanceError.failed(
                    "Status-item identity changed during stability sample \(sample) for PID \(pid)."
                )
            }
            guard let frame = current.frame, frame.width > 0, frame.height > 0 else {
                throw AcceptanceError.failed("Geometry sample \(sample) for PID \(pid) was missing or zero-sized.")
            }
            guard isTopVisible(frame) else {
                throw AcceptanceError.failed(
                    "Geometry sample \(sample) for PID \(pid) was not in a visible menu-bar region: \(describe(frame))."
                )
            }
            frames.append(frame)
            if sample < sampleCount {
                RunLoop.current.run(
                    mode: .default,
                    before: Date().addingTimeInterval(accessibilityPollInterval)
                )
                // The desktop can lock while the run loop sleeps. Recheck
                // immediately before the next AX traversal so that transition
                // is never reported as candidate geometry corruption.
                try requireUnlockedInteractiveSession()
                let matches = statusItems(in: application)
                guard matches.count == 1 else {
                    throw AcceptanceError.failed(
                        "Status-item count changed during stability sampling for PID \(pid): expected 1, got \(matches.count)."
                    )
                }
                guard CFEqual(matches[0].element, stableIdentity) else {
                    throw AcceptanceError.failed(
                        "Status-item identity changed during the stable-geometry dwell for PID \(pid)."
                    )
                }
                current = matches[0]
            }
        }

        let anchor = frames[0]
        guard frames.dropFirst().allSatisfy({ approximatelyEqual($0, anchor, tolerance: 1) }) else {
            throw AcceptanceError.failed(
                "Status-item geometry moved during stability sampling for PID \(pid): \(frames.map(describe).joined(separator: ", "))."
            )
        }
        return StableStatusItemObservation(item: current, frames: frames)
    }

    private func statusItems(in application: AXUIElement) -> [ElementSnapshot] {
        let roots = elements(for: application, attributes: [kAXExtrasMenuBarAttribute as String])
        // Never fall back to the application hierarchy here. Its AXChildren
        // include windows and lazy table rows; repeatedly walking them can make
        // the target app spend an entire core materialising unrelated UI.
        // During launch AXExtrasMenuBar may be absent briefly, so an empty
        // result simply lets the bounded poll try the exact attribute again.
        return uniqueSnapshots(
            roots.flatMap {
                descendants(
                    of: $0,
                    maximumDepth: 1,
                    maximumCount: 16,
                    childAttributes: [kAXChildrenAttribute as String]
                )
            }
                .filter {
                    $0.role == (kAXMenuBarItemRole as String)
                        && $0.names.contains(expectedStatusName)
                }
        )
    }

    private func waitForStatusMenu(
        from statusItem: AXUIElement,
        pid: pid_t,
        timeout: TimeInterval
    ) throws -> AXUIElement {
        let deadline = Date().addingTimeInterval(timeout)
        var lastMenus: [[String]] = []
        while Date() < deadline {
            try requireUnlockedInteractiveSession()
            // NSStatusItem exposes its menu as a direct child. A closed menu
            // has a zero-size off-screen AX frame; after a real AXPress the
            // same element gains its visible on-screen geometry. Restrict the
            // search to that pressed item and its menu descendants—never the
            // application or any window/table hierarchy.
            let menus = descendants(
                of: statusItem,
                maximumDepth: 2,
                maximumCount: 64,
                childAttributes: [
                    kAXChildrenAttribute as String,
                    kAXShownMenuUIElementAttribute as String,
                ]
            ).filter { snapshot in
                snapshot.role == (kAXMenuRole as String)
                    && (snapshot.frame?.width ?? 0) > 0
                    && (snapshot.frame?.height ?? 0) > 0
            }
            let inspected = menus.map { snapshot in
                (snapshot: snapshot, items: menuItems(in: snapshot.element))
            }
            lastMenus = inspected.map { $0.items.map(\.name) }
            if let match = inspected.first(where: { candidate in
                let titles = Set(candidate.items.map { canonicalMenuTitle($0.name) })
                return Set(expectedMenuTitles).isSubset(of: titles)
            }) {
                return match.snapshot.element
            }
            if processHasExited(pid) {
                throw AcceptanceError.failed("PID \(pid) exited after AXPress and before its status menu could be inspected.")
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(accessibilityPollInterval))
        }
        try requireInteractiveTerminalBoundary()
        let observed = lastMenus
            .map { $0.filter { !$0.isEmpty }.joined(separator: " | ") }
            .filter { !$0.isEmpty }
            .joined(separator: " || ")
        throw AcceptanceError.failed(
            "No opened AXMenu for PID \(pid) contained the required status-menu entries. Observed menus: \(observed.isEmpty ? "none" : observed)"
        )
    }

    private func menuItems(in menu: AXUIElement) -> [ElementSnapshot] {
        descendants(
            of: menu,
            maximumDepth: 3,
            maximumCount: 64,
            childAttributes: [kAXChildrenAttribute as String]
        )
            .filter { $0.role == (kAXMenuItemRole as String) }
    }

    private func descendants(
        of root: AXUIElement,
        maximumDepth: Int,
        maximumCount: Int,
        childAttributes: [String]
    ) -> [ElementSnapshot] {
        var queue: [(AXUIElement, Int)] = [(root, 0)]
        var cursor = 0
        var result: [ElementSnapshot] = []
        var seen: [AXUIElement] = []

        while cursor < queue.count, result.count < maximumCount {
            let (element, depth) = queue[cursor]
            cursor += 1
            guard !seen.contains(where: { CFEqual($0, element) }) else { continue }
            seen.append(element)

            result.append(snapshot(element))
            guard depth < maximumDepth else { continue }
            let queued = queue.count - cursor
            let remaining = max(0, maximumCount - result.count - queued)
            guard remaining > 0 else { continue }
            let children = elements(
                for: element,
                attributes: childAttributes,
                maximumCount: remaining
            )
            queue.append(contentsOf: children.map { ($0, depth + 1) })
        }
        return result
    }

    private func elements(
        for element: AXUIElement,
        attributes: [String],
        maximumCount: Int = 64
    ) -> [AXUIElement] {
        var result: [AXUIElement] = []
        for attribute in attributes where result.count < maximumCount {
            guard let value = attributeValue(element, attribute) else { continue }
            if CFGetTypeID(value) == AXUIElementGetTypeID() {
                result.append(unsafeBitCast(value, to: AXUIElement.self))
            } else if CFGetTypeID(value) == CFArrayGetTypeID(), let values = value as? [Any] {
                for candidate in values.prefix(maximumCount - result.count)
                    where CFGetTypeID(candidate as CFTypeRef) == AXUIElementGetTypeID() {
                    result.append(unsafeBitCast(candidate as CFTypeRef, to: AXUIElement.self))
                }
            }
        }
        return result
    }

    private func snapshot(_ element: AXUIElement) -> ElementSnapshot {
        let role = stringValue(element, kAXRoleAttribute as String) ?? ""
        let names = accessibleNames(element)
        return ElementSnapshot(element: element, role: role, names: names, frame: frameValue(element))
    }

    private func accessibleNames(_ element: AXUIElement) -> [String] {
        [
            kAXTitleAttribute as String,
            kAXDescriptionAttribute as String,
            kAXHelpAttribute as String,
            kAXValueAttribute as String,
        ].compactMap { stringValue(element, $0) }.filter { !$0.isEmpty }
    }

    private func uniqueSnapshots(_ snapshots: [ElementSnapshot]) -> [ElementSnapshot] {
        var seen: [AXUIElement] = []
        return snapshots.filter { snapshot in
            guard !seen.contains(where: { CFEqual($0, snapshot.element) }) else { return false }
            seen.append(snapshot.element)
            return true
        }
    }

    private func attributeValue(_ element: AXUIElement, _ attribute: String) -> CFTypeRef? {
        var value: CFTypeRef?
        let error = AXUIElementCopyAttributeValue(element, attribute as CFString, &value)
        return error == .success ? value : nil
    }

    private func stringValue(_ element: AXUIElement, _ attribute: String) -> String? {
        guard let value = attributeValue(element, attribute), CFGetTypeID(value) == CFStringGetTypeID() else {
            return nil
        }
        return value as? String
    }

    private func booleanValue(_ element: AXUIElement, _ attribute: String) -> Bool? {
        guard let value = attributeValue(element, attribute),
              CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return CFBooleanGetValue(unsafeBitCast(value, to: CFBoolean.self))
    }

    private func frameValue(_ element: AXUIElement) -> CGRect? {
        guard let positionReference = attributeValue(element, kAXPositionAttribute as String),
              let sizeReference = attributeValue(element, kAXSizeAttribute as String),
              CFGetTypeID(positionReference) == AXValueGetTypeID(),
              CFGetTypeID(sizeReference) == AXValueGetTypeID() else {
            return nil
        }
        let positionValue = unsafeBitCast(positionReference, to: AXValue.self)
        let sizeValue = unsafeBitCast(sizeReference, to: AXValue.self)
        var position = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(positionValue, .cgPoint, &position),
              AXValueGetValue(sizeValue, .cgSize, &size) else {
            return nil
        }
        return CGRect(origin: position, size: size)
    }

    private func isTopVisible(_ frame: CGRect) -> Bool {
        StatusItemVisibilityGeometry.isTopVisible(
            frame,
            displays: currentDisplayGeometries()
        )
    }

    private func currentDisplayGeometries() -> [MenuBarDisplayGeometry] {
        NSScreen.screens.compactMap { screen in
            guard let number = screen.deviceDescription[
                NSDeviceDescriptionKey("NSScreenNumber")
            ] as? NSNumber else { return nil }
            let displayID = CGDirectDisplayID(number.uint32Value)
            let bounds = CGDisplayBounds(displayID)
            guard bounds.width > 0, bounds.height > 0 else { return nil }
            let menuBarHeight = max(
                NSStatusBar.system.thickness + 12,
                screen.frame.maxY - screen.visibleFrame.maxY + 12,
                40
            )
            return MenuBarDisplayGeometry(
                displayID: displayID,
                bounds: bounds,
                menuBarHeight: menuBarHeight
            )
        }
    }

    private func approximatelyEqual(_ lhs: CGRect, _ rhs: CGRect, tolerance: CGFloat) -> Bool {
        abs(lhs.minX - rhs.minX) <= tolerance
            && abs(lhs.minY - rhs.minY) <= tolerance
            && abs(lhs.width - rhs.width) <= tolerance
            && abs(lhs.height - rhs.height) <= tolerance
    }

    private func canonicalMenuTitle(_ title: String) -> String {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let expression = try? NSRegularExpression(pattern: #"\s{2,}[⌘⌥⇧⌃].*$"#) else {
            return trimmed
        }
        let range = NSRange(trimmed.startIndex..<trimmed.endIndex, in: trimmed)
        return expression.stringByReplacingMatches(in: trimmed, range: range, withTemplate: "")
    }

    private func canonicalBundleURL(for application: NSRunningApplication) -> URL? {
        application.bundleURL?.standardizedFileURL.resolvingSymlinksInPath()
    }

    private func waitForExit(pid: pid_t, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if processHasExited(pid) { return true }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        return processHasExited(pid)
    }

    private func processHasExited(_ pid: pid_t) -> Bool {
        if !kernelProcessExists(pid) { return true }
        guard let expected = launchedProcessIdentities[pid],
              let current = processIdentity(pid: pid) else { return false }
        return current != expected
    }

    private func kernelProcessExists(_ pid: pid_t) -> Bool {
        errno = 0
        if kill(pid, 0) == 0 { return true }
        return errno != ESRCH
    }

    private func recordProcessIdentity(pid: pid_t) throws {
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            if let identity = processIdentity(pid: pid) {
                launchedProcessIdentities[pid] = identity
                return
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
        }
        if let identity = processIdentity(pid: pid) {
            launchedProcessIdentities[pid] = identity
            return
        }
        throw AcceptanceError.failed("Could not capture a kernel process identity for exact PID \(pid).")
    }

    private func processIdentity(pid: pid_t) -> ProcessIdentity? {
        var info = proc_bsdinfo()
        let expectedSize = MemoryLayout<proc_bsdinfo>.size
        let copied = withUnsafeMutablePointer(to: &info) { pointer in
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pointer, Int32(expectedSize))
        }
        guard copied == expectedSize else { return nil }
        return ProcessIdentity(
            pid: pid,
            startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec
        )
    }

    private func processCPUSeconds(pid: pid_t) -> TimeInterval? {
        var info = proc_taskinfo()
        let expectedSize = MemoryLayout<proc_taskinfo>.size
        let copied = withUnsafeMutablePointer(to: &info) { pointer in
            proc_pidinfo(pid, PROC_PIDTASKINFO, 0, pointer, Int32(expectedSize))
        }
        guard copied == expectedSize else { return nil }
        return TimeInterval(info.pti_total_user + info.pti_total_system) / 1_000_000_000
    }

    private func processCPUObservation(
        pid: pid_t,
        wallStart: TimeInterval,
        cpuStart: TimeInterval
    ) throws -> ProcessCPUObservation {
        guard let cpuEnd = processCPUSeconds(pid: pid), cpuEnd >= cpuStart else {
            throw AcceptanceError.failed("Could not read a monotonic CPU result for exact PID \(pid).")
        }
        let wallSeconds = ProcessInfo.processInfo.systemUptime - wallStart
        guard wallSeconds > 0 else {
            throw AcceptanceError.failed("The monotonic wall-clock interval for exact PID \(pid) was invalid.")
        }
        return ProcessCPUObservation(
            wallSeconds: wallSeconds,
            cpuSeconds: cpuEnd - cpuStart
        )
    }

    private func cleanupAllLaunchedTargetProcesses(protected: Bool) -> Bool {
        var inventoryComplete = true
        var capturedChildren: [ProcessIdentity] = []
        var pids = Set(launchedProcessIdentities.keys.filter { !processHasExited($0) })

        for application in exactTargetApplications() {
            let pid = application.processIdentifier
            pids.insert(pid)
            if launchedProcessIdentities[pid] == nil {
                do {
                    try recordProcessIdentity(pid: pid)
                } catch {
                    inventoryComplete = false
                }
            }
        }
        for pid in pids where !processHasExited(pid) {
            do {
                capturedChildren.append(contentsOf: try captureDescendantProcessIdentities(of: pid))
            } catch {
                inventoryComplete = false
            }
        }
        capturedChildren = Array(Set(capturedChildren))

        var terminationRequestsCompleted = true
        for pid in pids {
            let completed = protected
                ? cleanupNormalLaunchedProcess(pid: pid)
                : cleanupExactLaunchedProcess(pid: pid)
            terminationRequestsCompleted = completed && terminationRequestsCompleted
        }
        return inventoryComplete
            && terminationRequestsCompleted
            && nonPhysicalCleanupIsComplete(capturedChildren: capturedChildren)
    }

    private func nonPhysicalCleanupIsComplete(capturedChildren: [ProcessIdentity]) -> Bool {
        func currentObservation() -> StatusItemAcceptanceSupport.ProcessInventoryObservation {
            let targetProcesses = try? targetBundleOwnedProcesses()
            let runtimeProcesses = try? candidateRuntimeProcesses()
            return StatusItemAcceptanceSupport.ProcessInventoryObservation(
                launchedIdentityRunning: launchedProcessIdentities.values.contains {
                    capturedProcessIsRunning($0)
                },
                capturedChildRunning: Set(capturedChildren).contains {
                    capturedProcessIsRunning($0)
                },
                targetInventoryComplete: targetProcesses != nil,
                targetOwnedProcessCount: targetProcesses?.count ?? -1,
                runtimeInventoryComplete: runtimeProcesses != nil,
                candidateRuntimeProcessCount: runtimeProcesses?.count ?? -1
            )
        }
        let deadline = Date().addingTimeInterval(5)
        repeat {
            if StatusItemAcceptanceSupport.processInventoryIsQuiescent(currentObservation()) {
                return true
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        } while Date() < deadline
        return StatusItemAcceptanceSupport.processInventoryIsQuiescent(currentObservation())
    }

    private func cleanupExactLaunchedProcess(pid: pid_t) -> Bool {
        guard !processHasExited(pid) else { return true }
        guard let expected = launchedProcessIdentities[pid],
              processIdentity(pid: pid) == expected,
              let executablePath = processExecutablePath(pid: pid),
              isExactTargetMainExecutable(executablePath) else {
            print("  cleanup refused: PID \(pid) does not have the recorded identity and exact target executable path")
            return false
        }
        if let running = NSRunningApplication(processIdentifier: pid),
           canonicalBundleURL(for: running) == appURL {
            print("  cleanup: requesting termination of exact PID \(pid)")
            _ = running.terminate()
            if waitForExit(pid: pid, timeout: 3) { return true }
        }
        guard !processHasExited(pid) else { return true }
        print("  cleanup: sending SIGTERM to exact PID \(pid)")
        _ = Darwin.kill(pid, SIGTERM)
        if waitForExit(pid: pid, timeout: 3) { return true }

        guard !processHasExited(pid) else { return true }
        print("  cleanup: sending SIGKILL to exact PID \(pid)")
        _ = Darwin.kill(pid, SIGKILL)
        return waitForExit(pid: pid, timeout: 2)
    }

    /// A normal app can own DSH and Ollama subprocesses. Never use the
    /// lightweight acceptance gate's SIGTERM/SIGKILL fallback here, because
    /// killing the UI process could strand those owned services. Request the
    /// app's real protected termination path and leave an explicit diagnostic
    /// if it cannot finish safely.
    private func cleanupNormalLaunchedProcess(pid: pid_t) -> Bool {
        guard !processHasExited(pid) else { return true }
        guard let expected = launchedProcessIdentities[pid],
              processIdentity(pid: pid) == expected,
              let executablePath = processExecutablePath(pid: pid),
              isExactTargetMainExecutable(executablePath),
              let running = NSRunningApplication(processIdentifier: pid),
              canonicalBundleURL(for: running) == appURL else {
            print("  normal cleanup refused: PID \(pid) does not match the recorded exact app identity")
            return false
        }
        print("  normal cleanup: requesting Fulmar's protected termination path for exact PID \(pid)")
        _ = running.terminate()
        if waitForExit(pid: pid, timeout: 45) {
            print("  normal cleanup: exact PID \(pid) completed protected termination")
            return true
        }
        print(
            "  normal cleanup stopped without sending a raw signal: exact PID \(pid) is still running so Fulmar can retain ownership of its services."
        )
        return false
    }

    private func isExactTargetMainExecutable(_ path: String) -> Bool {
        let executable = URL(fileURLWithPath: path)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
        return executable == targetMainExecutablePath
    }

    private func printDiagnostics(pid: pid_t) {
        guard !processHasExited(pid) else {
            print("  diagnostics: exact PID \(pid) has already exited")
            return
        }
        let workspace = NSWorkspace.shared
        if let target = NSRunningApplication(processIdentifier: pid) {
            print(
                "  diagnostics: target policy=\(target.activationPolicy.rawValue) "
                + "finished=\(target.isFinishedLaunching) hidden=\(target.isHidden) active=\(target.isActive)"
            )
        }
        let frontmost = workspace.frontmostApplication
        let menuBarOwner = workspace.menuBarOwningApplication
        print(
            "  diagnostics: frontmost pid=\(frontmost?.processIdentifier ?? 0) "
            + "bundle=\(frontmost?.bundleIdentifier ?? "none"); menu-bar owner pid=\(menuBarOwner?.processIdentifier ?? 0) "
            + "bundle=\(menuBarOwner?.bundleIdentifier ?? "none")"
        )
        guard interactiveSessionObservation().state == .ready else {
            print("  diagnostics: skipped locked or indeterminate accessibility traversal")
            return
        }
        let application = AXUIElementCreateApplication(pid)
        let roots = elements(for: application, attributes: [kAXExtrasMenuBarAttribute as String])
        let snapshots = roots.flatMap {
            descendants(
                of: $0,
                maximumDepth: 2,
                maximumCount: 64,
                childAttributes: [kAXChildrenAttribute as String]
            )
        }
        if snapshots.isEmpty {
            print("  diagnostics: no accessible extras-menu hierarchy was exposed by PID \(pid)")
            return
        }
        print("  diagnostics: extras-menu accessibility snapshot")
        for item in uniqueSnapshots(snapshots).filter({ !$0.name.isEmpty || $0.frame != nil }) {
            print("    role=\(item.role.isEmpty ? "unknown" : item.role) name='\(item.name)' frame=\(item.frame.map(describe) ?? "unavailable")")
        }
    }

    private func describe(_ frame: CGRect) -> String {
        String(format: "x=%.1f y=%.1f w=%.1f h=%.1f", frame.origin.x, frame.origin.y, frame.width, frame.height)
    }

    private func describe(_ error: AXError) -> String {
        "AXError(rawValue: \(error.rawValue))"
    }
}

private func usage() -> Never {
    fputs("Usage: fulmar-status-item-acceptance /exact/path/Fulmar.app [cycles|--headless-handoff|--physical-background-handoff|--normal-actions]\n", stderr)
    exit(64)
}

guard CommandLine.arguments.count == 2 || CommandLine.arguments.count == 3 else {
    usage()
}

do {
    if CommandLine.arguments.count == 3,
       CommandLine.arguments[2] == "--headless-handoff" {
        let acceptance = try StatusItemAcceptance(appPath: CommandLine.arguments[1], cycles: 1)
        try acceptance.runHeadlessForegroundHandoff()
    } else if CommandLine.arguments.count == 3,
              CommandLine.arguments[2] == "--physical-background-handoff" {
        let acceptance = try StatusItemAcceptance(appPath: CommandLine.arguments[1], cycles: 1)
        try acceptance.runPhysicalBackgroundForegroundHandoff()
    } else if CommandLine.arguments.count == 3,
              CommandLine.arguments[2] == "--normal-actions" {
        let acceptance = try StatusItemAcceptance(appPath: CommandLine.arguments[1], cycles: 1)
        try acceptance.runNormalMenuActions()
    } else {
        let requestedCycles: Int
        if CommandLine.arguments.count == 3 {
            guard let parsed = Int(CommandLine.arguments[2]) else { usage() }
            requestedCycles = parsed
        } else {
            requestedCycles = 3
        }
        let acceptance = try StatusItemAcceptance(appPath: CommandLine.arguments[1], cycles: requestedCycles)
        try acceptance.run()
    }
} catch let error as AcceptanceError {
    switch error {
    case .failed, .launchRequestUnsettled:
        fputs("FAIL: \(error.localizedDescription)\n", stderr)
        exit(1)
    case .thermallyDeferred, .environmentallyDeferred:
        fputs("DEFERRED: \(error.localizedDescription)\n", stderr)
        exit(75)
    }
} catch {
    fputs("FAIL: \(error.localizedDescription)\n", stderr)
    exit(1)
}
