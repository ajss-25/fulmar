import AppKit
import Darwin
import Foundation
import LocalHarnessSandboxPolicy
import LocalHarnessUpdateSecurity

struct PreparedUpdate: Sendable {
    let stageRoot: URL
    let appURL: URL
    let version: String
    let build: Int
    let attestation: SignedApplicationAttestation
}

/// Thread-safe one-generation latch shared by the asynchronous install worker
/// and the main-actor lifecycle callbacks. A quit is authorized exactly once,
/// only after a verified helper launch has been recorded for that generation.
final class UpdateInstallAuthorizationGate: @unchecked Sendable {
    private enum State: Equatable {
        case idle
        case preparing(UUID)
        case helperLaunched(UUID)
        case quitAuthorized(UUID)
    }

    private let lock = NSLock()
    private var state: State = .idle

    func begin() throws -> UUID {
        lock.lock()
        defer { lock.unlock() }
        guard state == .idle else { throw UpdateError.installInProgress }
        let generation = UUID()
        state = .preparing(generation)
        return generation
    }

    func isPreparing(_ generation: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .preparing(generation)
    }

    func markHelperLaunched(_ generation: UUID) throws {
        lock.lock()
        defer { lock.unlock() }
        guard state == .preparing(generation) else { throw UpdateError.staleInstallCompletion }
        state = .helperLaunched(generation)
    }

    func authorizeQuit(_ generation: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard state == .helperLaunched(generation) else { return false }
        state = .quitAuthorized(generation)
        return true
    }

    func fail(_ generation: UUID) {
        lock.lock()
        if state == .preparing(generation) { state = .idle }
        lock.unlock()
    }
}

final class UpdateManager: @unchecked Sendable {
    private struct ExecutableIdentity: Equatable {
        let device: UInt64
        let inode: UInt64
        let owner: UInt32
        let mode: mode_t
        let linkCount: UInt64
    }

    private let fileManager = FileManager.default
    private let root: URL
    private let backupManager: StateBackupManager
    private let archiveStager: UpdateArchiveStager
    private let installWorker = DispatchQueue(
        label: "app.localharness.update-install",
        qos: .userInitiated
    )
    private let preparationWorker = DispatchQueue(
        label: "app.localharness.update-preparation",
        qos: .utility
    )
    private let authorizationGate = UpdateInstallAuthorizationGate()
    private let helperLock = NSLock()
    private var launchedUpdateHelper: UpdateHelperLaunchHandle?

    init(applicationSupport: URL, backupManager: StateBackupManager) {
        let updateRoot = applicationSupport.appendingPathComponent("Updates", isDirectory: true)
        root = updateRoot
        self.backupManager = backupManager
        archiveStager = UpdateArchiveStager(root: updateRoot)
    }

    func prepare(archive: URL, completion: @escaping (Result<PreparedUpdate, Error>) -> Void) {
        preparationWorker.async {
            self.archiveStager.discardOrphanedStages()
            do { let prepared = try self.prepareSynchronously(archive: archive); DispatchQueue.main.async { completion(.success(prepared)) } }
            catch { DispatchQueue.main.async { completion(.failure(error)) } }
        }
    }

    func discard(_ update: PreparedUpdate) {
        preparationWorker.async {
            self.archiveStager.discard(
                StagedUpdateArchive(stageRoot: update.stageRoot, appURL: update.appURL)
            )
        }
    }

    /// Compatibility shim for callers not yet wired to the application-wide
    /// lifecycle gate. It is deliberately unavailable as an install path.
    func install(_ update: PreparedUpdate, currentVersion: String) throws {
        _ = update
        _ = currentVersion
        throw UpdateError.protectedTransitionRequired
    }

    /// Installs only through the shared stopped-runtime transition. The helper
    /// launch and app termination are intentionally split: `authorizedQuit`
    /// runs only after `finishTransition(.terminateForUpdate)` acknowledges
    /// that the coordinator has irreversibly latched admissions/restarts shut.
    @MainActor
    func install(
        _ update: PreparedUpdate,
        currentVersion: String,
        acquireTransition: @escaping AcquireStateBackupTransition,
        finishTransition: @escaping FinishStateBackupTransition,
        authorizedQuit: @escaping @MainActor () -> Void,
        completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) {
        let generation: UUID
        do { generation = try authorizationGate.begin() }
        catch {
            discard(update)
            completion(.failure(error))
            return
        }
        // Once a permit is issued, retain this coordinator through the exact
        // terminal finish callback. Losing a weak owner between acquisition,
        // worker dispatch, and finish would strand the stopped-runtime latch.
        acquireTransition(.updateInstall) { [self] acquisition in
            switch acquisition {
            case .failure(let error):
                self.authorizationGate.fail(generation)
                self.discard(update)
                completion(.failure(error))
            case .success(let permit):
                self.installWorker.async { [self] in
                    let result = Result {
                        let helper = try self.prepareAndLaunchHelper(
                            update,
                            currentVersion: currentVersion,
                            permit: permit
                        )
                        do {
                            try self.authorizationGate.markHelperLaunched(generation)
                        } catch {
                            _ = UpdateHelperReadinessSupervisor.terminateReadyProcess(helper)
                            throw error
                        }
                        self.helperLock.lock()
                        self.launchedUpdateHelper = helper
                        self.helperLock.unlock()
                    }
                    DispatchQueue.main.async { [self] in
                        self.finishInstallWorkerResult(
                            result,
                            update: update,
                            generation: generation,
                            permit: permit,
                            finishTransition: finishTransition,
                            authorizedQuit: authorizedQuit,
                            completion: completion
                        )
                    }
                }
            }
        }
    }

    @MainActor
    private func finishInstallWorkerResult(
        _ result: Result<Void, Error>,
        update: PreparedUpdate,
        generation: UUID,
        permit: StateBackupQuiescencePermit,
        finishTransition: @escaping FinishStateBackupTransition,
        authorizedQuit: @escaping @MainActor () -> Void,
        completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) {
        switch result {
        case .failure(let error):
            finishTransition(permit, .restartAndReopen, .failure(error)) {
                self.authorizationGate.fail(generation)
                self.discard(update)
                completion(.failure(error))
            }
        case .success:
            finishTransition(permit, .terminateForUpdate, .success(())) { [self] in
                guard self.authorizationGate.authorizeQuit(generation) else { return }
                completion(.success(()))
                authorizedQuit()
            }
        }
    }

    private func prepareAndLaunchHelper(
        _ update: PreparedUpdate,
        currentVersion: String,
        permit: StateBackupQuiescencePermit
    ) throws -> UpdateHelperLaunchHandle {
        try permit.validate()
        guard let currentApp = Bundle.main.bundleURL.pathExtension == "app" ? Optional(Bundle.main.bundleURL) : nil,
              let helper = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("LocalHarnessUpdateHelper"),
              fileManager.isExecutableFile(atPath: helper.path) else {
            throw UpdateError.helperMissing
        }
        let helperIdentity = try Self.executableIdentity(helper)
        let currentAttestation: SignedApplicationAttestation
        do {
            currentAttestation = try UpdateApplicationSecurity.strictAttestation(at: currentApp)
        } catch {
            throw UpdateError.signatureMismatch
        }
        guard currentAttestation.teamIdentifier == update.attestation.teamIdentifier,
              currentAttestation.identifier == update.attestation.identifier else {
            throw UpdateError.signatureMismatch
        }
        try UpdateApplicationSecurity.validatePrivateStagedPath(update.appURL, updatesRoot: root)
        let stagedBefore = try UpdateApplicationSecurity.stableValidatedApplication(
            at: update.appURL,
            expected: update.attestation
        )
        guard update.version == update.attestation.version,
              update.build == update.attestation.build else {
            throw UpdateError.signatureMismatch
        }
        _ = try backupManager.create(
            label: "Before \(ProductBrand.displayName) \(update.version)",
            sourceVersion: currentVersion,
            permit: permit
        )
        try permit.validate()
        let currentRevalidated: SignedApplicationAttestation
        do { currentRevalidated = try UpdateApplicationSecurity.strictAttestation(at: currentApp) }
        catch { throw UpdateError.signatureMismatch }
        guard currentRevalidated == currentAttestation else { throw UpdateError.signatureMismatch }
        try UpdateApplicationSecurity.validatePrivateStagedPath(update.appURL, updatesRoot: root)
        guard try UpdateApplicationSecurity.stableValidatedApplication(
            at: update.appURL,
            expected: update.attestation
        ) == stagedBefore else {
            throw UpdateError.signatureMismatch
        }
        guard try Self.executableIdentity(helper) == helperIdentity else {
            throw UpdateError.helperMissing
        }
        let backups = root.appendingPathComponent("App Backups", isDirectory: true)
        let backup = backups.appendingPathComponent(
            "Fulmar backup build \(currentAttestation.build) \(UUID().uuidString).app",
            isDirectory: true
        )
        try UpdateApplicationSecurity.preparePrivateBackupPath(backup, updatesRoot: root)
        let helperArguments = [
            currentApp.path,
            update.appURL.path,
            backup.path,
            String(ProcessInfo.processInfo.processIdentifier),
            try currentAttestation.encodedArgument(),
            try update.attestation.encodedArgument()
        ]
        try permit.validate()
        guard try Self.executableIdentity(helper) == helperIdentity else {
            throw UpdateError.helperMissing
        }
        do {
            return try UpdateHelperReadinessSupervisor.launch(
                executable: helper,
                arguments: helperArguments,
                environment: ChildProcessEnvironment.make(nodeBin: nil),
                maximumStderrBytes: 64 * 1_024,
                deadline: 30,
                terminationGrace: 0.25
            )
        } catch is UpdateHelperReadinessError {
            throw UpdateError.helperExitedEarly
        }
    }

    private static func executableIdentity(_ url: URL) throws -> ExecutableIdentity {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw UpdateError.helperMissing }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_nlink == 1,
              metadata.st_uid == geteuid() || metadata.st_uid == 0,
              metadata.st_mode & 0o111 != 0 else {
            throw UpdateError.helperMissing
        }
        return ExecutableIdentity(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(metadata.st_ino),
            owner: metadata.st_uid,
            mode: metadata.st_mode,
            linkCount: UInt64(metadata.st_nlink)
        )
    }

    private func prepareSynchronously(archive: URL) throws -> PreparedUpdate {
        guard archive.pathExtension.lowercased() == "zip", archive.isFileURL else { throw UpdateError.invalidArchive }
        let currentAttestation: SignedApplicationAttestation
        do {
            currentAttestation = try UpdateApplicationSecurity.strictAttestation(at: Bundle.main.bundleURL)
        } catch {
            throw UpdateError.developerIDRequired
        }
        let staged = try archiveStager.stage(archive: archive)
        var accepted = false
        defer { if !accepted { archiveStager.discard(staged) } }
        let candidate = staged.appURL
        let candidateAttestation: SignedApplicationAttestation
        do {
            candidateAttestation = try UpdateApplicationSecurity.strictAttestation(at: candidate)
        } catch {
            throw UpdateError.signatureMismatch
        }
        guard candidateAttestation.identifier == currentAttestation.identifier,
              candidateAttestation.teamIdentifier == currentAttestation.teamIdentifier else {
            throw UpdateError.signatureMismatch
        }
        guard Self.gatekeeperAccepts(candidate) else { throw UpdateError.notarizationRequired }
        guard candidateAttestation.build > currentAttestation.build else { throw UpdateError.notNewer }
        accepted = true
        return PreparedUpdate(
            stageRoot: staged.stageRoot,
            appURL: candidate,
            version: candidateAttestation.version,
            build: candidateAttestation.build,
            attestation: candidateAttestation
        )
    }

    static func gatekeeperAccepts(
        _ app: URL,
        executable: URL = URL(fileURLWithPath: "/usr/sbin/spctl"),
        deadline: TimeInterval = 30,
        terminationGrace: TimeInterval = 0.25,
        onSpawn: ((pid_t) -> Void)? = nil
    ) -> Bool {
        guard let result = try? BoundedProcessGroupRunner.run(
            executable: executable,
            arguments: ["--assess", "--type", "execute", app.path],
            environment: ChildProcessEnvironment.make(nodeBin: nil),
            maximumStderrBytes: 64 * 1_024,
            deadline: deadline,
            terminationGrace: terminationGrace,
            discardStandardOutput: true,
            onSpawn: onSpawn
        ) else { return false }
        return result.limit == nil
            && result.exitStatus == 0
            && result.terminationSignal == nil
    }
}

enum UpdateError: LocalizedError {
    case invalidArchive, developerIDRequired, signatureMismatch, notarizationRequired, notNewer, helperMissing
    case protectedTransitionRequired, installInProgress, staleInstallCompletion, helperExitedEarly
    var errorDescription: String? {
        switch self {
        case .invalidArchive: return "The update archive is damaged or does not contain exactly one \(ProductBrand.displayName) application."
        case .developerIDRequired: return "Secure in-app updates require a Developer ID signed build. This private ad-hoc build must be replaced manually after running the release verifier."
        case .signatureMismatch: return "The update was not signed by the same Developer Team as this copy of \(ProductBrand.displayName)."
        case .notarizationRequired: return "macOS did not accept the update as notarized software."
        case .notNewer: return "The selected update is not newer than the installed build."
        case .helperMissing: return "The signed update helper is missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .protectedTransitionRequired: return "The update was not started because the protected runtime transition coordinator is not connected."
        case .installInProgress: return "A verified update installation is already in progress."
        case .staleInstallCompletion: return "A stale update callback was rejected before it could authorize application termination."
        case .helperExitedEarly: return "The verified update helper did not complete its bounded pre-install validation handshake. \(ProductBrand.displayName) remains open and no update was installed."
        }
    }
}
