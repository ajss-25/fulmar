import Foundation
import ServiceManagement

typealias ScheduleExecutionPreparation = (
    _ schedule: LocalSchedule,
    _ completion: @escaping @Sendable (Result<Void, Error>) -> Void
) -> Void

enum ScheduleManagerError: Error, Equatable, LocalizedError {
    case storageUnavailable
    case scheduleLimitReached
    case consentRequired(DataBoundary)
    case boundaryMismatch(expected: DataBoundary, supplied: DataBoundary)
    case providerCatalogUnavailable
    case providerInactive(active: ProviderID?)
    case routeInactive(active: ModelRoute?)
    case providerEndpointUnavailable

    var errorDescription: String? {
        switch self {
        case .storageUnavailable:
            return "Private schedule storage is unavailable. Existing data was preserved."
        case .scheduleLimitReached:
            return "The 1,000-schedule safety limit has been reached. Remove a schedule before adding another."
        case .consentRequired(let boundary):
            return "Explicit unattended-use consent is required for the \(boundary.displayName) provider."
        case .boundaryMismatch:
            return "The provider's data boundary changed. Review the schedule before enabling it."
        case .providerCatalogUnavailable:
            return "The live provider catalog has not been verified yet. Wait for Harness to become ready."
        case .providerInactive(let active):
            return active.map { "Select the schedule's provider first. The active runtime is restricted to \($0.rawValue)." }
                ?? "Select the schedule's provider before enabling this task."
        case .routeInactive(let active):
            return active.map {
                "Select the schedule's exact local model first. The active runtime is restricted to \($0.provider.rawValue) / \($0.model.rawValue)."
            } ?? "Select the schedule's exact local model before enabling this task."
        case .providerEndpointUnavailable:
            return "The provider's exact endpoint origin is unresolved. Unattended use remains blocked."
        }
    }
}

enum ScheduleInboxLoadOutcome: Equatable, Sendable {
    case loaded([ScheduledResult])
    case unavailable(String)
}

enum ScheduleDurabilityFailurePoint: Hashable, Sendable {
    /// The provider has completed, while only the pre-dispatch lease is
    /// durable. Startup must conservatively consume the occurrence.
    case afterExecutionCompletionBeforeReceiptCommit
    /// The exact Inbox result is durable but schedules.json is still stale.
    case afterResultCommitBeforeScheduleCommit
}

final class ScheduleManager: @unchecked Sendable {
    private struct ActiveRun {
        let token: UUID
        var executorID: UUID?
        let activityID: UUID
    }

    var onChange: (() -> Void)?
    var onIdleAfterRun: (() -> Void)?

    private let store: ScheduleDocumentStore?
    private let executor: any ScheduleConversationExecuting
    private let activities: ActivityStore
    private var boundaryPolicy: ScheduleBoundaryPolicy
    private let enforceActiveProvider: Bool
    private var verifiedActiveRoute: ModelRoute?
    private var providerCatalogVerified: Bool
    private let defaultSelectionProvider: @Sendable () throws -> ModelSelection
    /// When supplied by the native host, scheduled sessions use the exact same
    /// canonical workspace admitted by the tool sandbox. The per-schedule
    /// storage directory remains responsible only for inbox/result state.
    private let executionWorkspace: URL?
    /// Native recovery barrier invoked before an unattended prompt can reach
    /// Harness. A failed checkpoint is a fail-closed run failure.
    private let prepareExecution: ScheduleExecutionPreparation?
    private let now: @Sendable () -> Date
    private let durabilityFailureInjector: @Sendable (ScheduleDurabilityFailurePoint) throws -> Void
    private let queue = DispatchQueue(label: "app.localharness.scheduler")
    private let inboxReadQueue = DispatchQueue(label: "app.localharness.scheduler-inbox", qos: .userInitiated)
    private var schedules: [LocalSchedule]
    private var active: [UUID: ActiveRun] = [:]
    private var pendingManualRuns: [UUID] = []
    private var timer: DispatchSourceTimer?
    private var storageWritable: Bool
    private var storageFailure: String?
    /// A native lifecycle boundary, not merely timer state. When set, no UI,
    /// timer, background wake, checkpoint callback, or queue drain may admit a
    /// new scheduled operation until a freshly verified runtime reopens it.
    private var admissionsSuspended: Bool
    /// Invalidates late callbacks from runs cancelled during a runtime or
    /// workspace-recovery boundary.
    private var executionGeneration: UInt64 = 0

    init(
        applicationSupport: URL,
        executor: any ScheduleConversationExecuting,
        activities: ActivityStore,
        boundaryPolicy: ScheduleBoundaryPolicy = ScheduleBoundaryPolicy(),
        enforceActiveProvider: Bool = false,
        admissionsInitiallySuspended: Bool = false,
        executionWorkspace: URL? = nil,
        prepareExecution: ScheduleExecutionPreparation? = nil,
        defaultSelection: @escaping @Sendable () throws -> ModelSelection = {
            try ModelProviderSettingsStore().loadOrMigrate().settings.defaultSelection
        },
        now: @escaping @Sendable () -> Date = { Date() },
        durabilityFailureInjector: @escaping @Sendable (ScheduleDurabilityFailurePoint) throws -> Void = { _ in }
    ) {
        self.executor = executor
        self.activities = activities
        self.boundaryPolicy = boundaryPolicy
        self.enforceActiveProvider = enforceActiveProvider
        admissionsSuspended = admissionsInitiallySuspended
        providerCatalogVerified = !enforceActiveProvider
        self.executionWorkspace = executionWorkspace
        self.prepareExecution = prepareExecution
        defaultSelectionProvider = defaultSelection
        self.now = now
        self.durabilityFailureInjector = durabilityFailureInjector

        var openedStore: ScheduleDocumentStore?
        var loadedSchedules: [LocalSchedule] = []
        var writable = true
        var failure: String?
        do {
            let candidate = try ScheduleDocumentStore(
                applicationSupport: applicationSupport,
                now: now
            )
            let loaded = try candidate.load()
            openedStore = candidate
            loadedSchedules = try candidate.reconcilePendingOccurrences(in: loaded.schedules)
            if loaded.migratedLegacySchema {
                do { try candidate.save(loadedSchedules) }
                catch {
                    writable = false
                    failure = "Legacy schedules were loaded but could not be migrated safely."
                }
            }
        } catch {
            writable = false
            failure = error.localizedDescription
        }
        store = openedStore
        schedules = loadedSchedules
        storageWritable = writable
        storageFailure = failure
    }

    /// Transitional source compatibility only. It intentionally ignores the
    /// Ollama client and fails closed until AppDelegate injects Harness RPC.
    @available(*, deprecated, message: "Inject HarnessScheduleConversationExecutor instead.")
    convenience init(applicationSupport: URL, client: OllamaClient, activities: ActivityStore) {
        self.init(
            applicationSupport: applicationSupport,
            executor: UnconfiguredScheduleConversationExecutor(),
            activities: activities
        )
    }

    deinit {
        timer?.cancel()
        executor.cancelAll()
    }

    func start() {
        queue.async { [weak self] in
            guard let self else { return }
            admissionsSuspended = false
            guard timer == nil else { return }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 2, repeating: 30)
            timer.setEventHandler { [weak self] in self?.runDue() }
            timer.resume()
            self.timer = timer
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            admissionsSuspended = true
            quiesceLocked()
        }
    }

    /// The protected runtime coordinator calls this before its first await.
    /// Synchronous closure is required so a Run Now click already queued on
    /// the main thread cannot begin a workspace checkpoint in the gap.
    func suspendAdmissionsSynchronously() {
        queue.sync {
            admissionsSuspended = true
            quiesceLocked()
        }
    }

    /// Memory warning is deliberately softer than a protected mutation: it
    /// prevents a new scheduled occurrence from starting but lets an already
    /// running local occurrence settle under the Eco workload.
    func pauseNewAdmissionsSynchronously() {
        queue.sync { admissionsSuspended = true }
    }

    /// Background one-shot execution reopens admissions only after the same
    /// authenticated topology checks used by the foreground app have passed.
    func resumeAdmissionsAndRunDue() {
        queue.async { [weak self] in
            guard let self else { return }
            admissionsSuspended = false
            runDue()
        }
    }

    /// Cancels every unattended run and publishes the barrier only after the
    /// scheduler queue has invalidated their callbacks. The host then stops the
    /// exact Harness process before mutating workspace state.
    func quiesceResult(completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                DispatchQueue.main.async { completion(.success(())) }
                return
            }
            self.quiesceLocked()
            Task {
                let result: Result<Void, Error>
                do {
                    try await self.executor.quiesce()
                    result = .success(())
                } catch {
                    result = .failure(error)
                }
                DispatchQueue.main.async { completion(result) }
            }
        }
    }

    func quiesce(completion: @escaping () -> Void) {
        quiesceResult { _ in completion() }
    }

    func quiesce() async throws {
        try await withCheckedThrowingContinuation { continuation in
            quiesceResult { continuation.resume(with: $0) }
        }
    }

    private func quiesceLocked() {
        timer?.cancel()
        timer = nil
        executionGeneration &+= 1
        executor.cancelAll()
        pendingManualRuns.removeAll()
        for run in active.values {
            activities.update(run.activityID, state: .cancelled, detail: "Cancelled before a protected runtime or workspace transition.")
        }
        active.removeAll()
        if let store {
            do {
                schedules = try store.reconcilePendingOccurrences(in: schedules)
            } catch {
                storageWritable = false
                storageFailure = "Interrupted scheduled work could not be reconciled safely and will not be sent again."
            }
        }
        notifyIdleIfNeeded()
    }

    func runDueNow() {
        queue.async { [weak self] in
            guard let self, !admissionsSuspended else { return }
            runDue()
        }
    }

    func snapshot() -> [LocalSchedule] {
        queue.sync { schedules.sorted { $0.nextRun < $1.nextRun } }
    }

    func storageIssue() -> String? { queue.sync { storageFailure } }

    /// Queue-synchronized lifecycle state used by readiness diagnostics and
    /// ordering tests. It never exposes or transfers timer ownership.
    func pollingEnabled() -> Bool { queue.sync { timer != nil } }

    func admissionsAreSuspended() -> Bool { queue.sync { admissionsSuspended } }

    func defaultModelSelection() -> ModelSelection {
        (try? defaultSelectionProvider()) ?? .defaultLocal
    }

    func boundary(for selection: ModelSelection) -> DataBoundary {
        queue.sync { boundaryPolicy.boundary(for: selection.route.provider) }
    }

    func origin(for selection: ModelSelection) -> ProviderEndpointOrigin? {
        queue.sync { boundaryPolicy.origin(for: selection.route.provider) }
    }

    func authorizationStatus(for schedule: LocalSchedule) -> ScheduleAuthorizationStatus {
        queue.sync { authorizationStatusLocked(for: schedule) }
    }

    func updateVerifiedProviderCatalog(
        descriptors: [ProviderDescriptor],
        activeRoute: ModelRoute
    ) {
        queue.sync {
            boundaryPolicy = ScheduleBoundaryPolicy(
                descriptors: descriptors,
                includeBuiltInDefaults: false
            )
            verifiedActiveRoute = activeRoute
            providerCatalogVerified = true
        }
        notifyChange()
    }

    private func authorizationStatusLocked(for schedule: LocalSchedule) -> ScheduleAuthorizationStatus {
        if enforceActiveProvider {
            guard providerCatalogVerified else { return .providerInactive(active: nil) }
            guard verifiedActiveRoute?.provider == schedule.selection.route.provider else {
                return .providerInactive(active: verifiedActiveRoute?.provider)
            }
        }
        let effective = boundaryPolicy.boundary(for: schedule.selection.route.provider)
        if enforceActiveProvider, effective == .onDevice,
           verifiedActiveRoute != schedule.selection.route {
            return .routeInactive(active: verifiedActiveRoute)
        }
        guard schedule.boundary == effective else {
            return .boundaryChanged(stored: schedule.boundary, effective: effective)
        }
        let origin = boundaryPolicy.origin(for: schedule.selection.route.provider)
        if effective.requiresExplicitConsent, origin == nil { return .endpointUnavailable }
        return schedule.isAuthorized(for: effective, origin: origin) ? .authorized : .consentRequired(effective)
    }

    func runningScheduleIDs() -> Set<UUID> { queue.sync { Set(active.keys) } }

    @discardableResult
    func add(
        title: String,
        prompt: String,
        selection: ModelSelection,
        intervalSeconds: TimeInterval,
        timeoutSeconds: TimeInterval = LocalSchedule.defaultTimeoutSeconds,
        firstRun: Date? = nil,
        allowUnattendedExternal: Bool = false
    ) throws -> UUID {
        try queue.sync {
            guard storageWritable, let store else { throw ScheduleManagerError.storageUnavailable }
            guard schedules.count < ScheduleDocumentStore.maximumScheduleCount else {
                throw ScheduleManagerError.scheduleLimitReached
            }
            if enforceActiveProvider, !providerCatalogVerified { throw ScheduleManagerError.providerCatalogUnavailable }
            if enforceActiveProvider, verifiedActiveRoute?.provider != selection.route.provider {
                throw ScheduleManagerError.providerInactive(active: verifiedActiveRoute?.provider)
            }
            let boundary = boundaryPolicy.boundary(for: selection.route.provider)
            if enforceActiveProvider, boundary == .onDevice, verifiedActiveRoute != selection.route {
                throw ScheduleManagerError.routeInactive(active: verifiedActiveRoute)
            }
            let origin = boundaryPolicy.origin(for: selection.route.provider)
            let consent: ScheduleUnattendedConsent?
            if boundary.requiresExplicitConsent {
                guard let origin else { throw ScheduleManagerError.providerEndpointUnavailable }
                guard allowUnattendedExternal else { throw ScheduleManagerError.consentRequired(boundary) }
                consent = try ScheduleUnattendedConsent(
                    selection: selection,
                    boundary: boundary,
                    origin: origin,
                    grantedAt: now()
                )
            } else {
                consent = nil
            }
            let current = now()
            let next = max(firstRun ?? current.addingTimeInterval(max(60, intervalSeconds)), current.addingTimeInterval(5))
            let schedule = try LocalSchedule(
                title: title,
                prompt: prompt,
                selection: selection,
                boundary: boundary,
                unattendedConsent: consent,
                intervalSeconds: intervalSeconds,
                timeoutSeconds: timeoutSeconds,
                nextRun: next
            )
            var updated = schedules
            updated.append(schedule)
            try store.save(updated)
            schedules = updated
            notifyChange()
            return schedule.id
        }
    }

    /// Compatibility for callers that still present a local-model text field.
    /// The request still runs through DSH, never through OllamaClient directly.
    @discardableResult
    func add(
        title: String,
        prompt: String,
        model: String,
        intervalSeconds: TimeInterval,
        firstRun: Date? = nil
    ) throws -> UUID {
        try add(
            title: title,
            prompt: prompt,
            selection: ModelSelection(
                route: ModelRoute(provider: BuiltInProviderDescriptors.ollama.id, model: ModelID(model)),
                performanceProfile: .balanced
            ),
            intervalSeconds: intervalSeconds,
            firstRun: firstRun
        )
    }

    func remove(id: UUID) throws {
        try queue.sync {
            guard storageWritable, let store else { throw ScheduleManagerError.storageUnavailable }
            var updated = schedules
            updated.removeAll { $0.id == id }
            try store.save(updated)
            pendingManualRuns.removeAll { $0 == id }
            if let run = active.removeValue(forKey: id) {
                if let executorID = run.executorID { executor.cancel(executorID) }
                activities.update(run.activityID, state: .cancelled, detail: "Cancelled because the schedule was removed.")
            }
            schedules = updated
            notifyChange()
            drainExecutionQueue()
        }
    }

    func toggle(id: UUID) throws {
        try queue.sync {
            guard storageWritable, let store else { throw ScheduleManagerError.storageUnavailable }
            guard let index = schedules.firstIndex(where: { $0.id == id }) else { return }
            var updated = schedules
            if !updated[index].enabled {
                switch authorizationStatusLocked(for: updated[index]) {
                case .authorized: break
                case .consentRequired(let boundary): throw ScheduleManagerError.consentRequired(boundary)
                case .boundaryChanged(let stored, let effective):
                    throw ScheduleManagerError.boundaryMismatch(expected: effective, supplied: stored)
                case .providerInactive(let active): throw ScheduleManagerError.providerInactive(active: active)
                case .routeInactive(let active): throw ScheduleManagerError.routeInactive(active: active)
                case .endpointUnavailable: throw ScheduleManagerError.providerEndpointUnavailable
                }
            }
            updated[index].enabled.toggle()
            if updated[index].enabled && updated[index].nextRun < now() { updated[index].nextRun = now() }
            try store.save(updated)
            if !updated[index].enabled {
                pendingManualRuns.removeAll { $0 == id }
                if let run = active.removeValue(forKey: id) {
                    if let executorID = run.executorID { executor.cancel(executorID) }
                    activities.update(run.activityID, state: .cancelled, detail: "Cancelled because the schedule was disabled.")
                }
            }
            schedules = updated
            notifyChange()
            drainExecutionQueue()
        }
    }

    func authorizeAndEnable(id: UUID) throws {
        try queue.sync {
            guard storageWritable, let store else { throw ScheduleManagerError.storageUnavailable }
            guard let index = schedules.firstIndex(where: { $0.id == id }) else { return }
            var updated = schedules
            if enforceActiveProvider {
                guard providerCatalogVerified else { throw ScheduleManagerError.providerCatalogUnavailable }
                guard verifiedActiveRoute?.provider == updated[index].selection.route.provider else {
                    throw ScheduleManagerError.providerInactive(active: verifiedActiveRoute?.provider)
                }
            }
            let effective = boundaryPolicy.boundary(for: updated[index].selection.route.provider)
            if enforceActiveProvider, effective == .onDevice,
               verifiedActiveRoute != updated[index].selection.route {
                throw ScheduleManagerError.routeInactive(active: verifiedActiveRoute)
            }
            let origin = boundaryPolicy.origin(for: updated[index].selection.route.provider)
            updated[index].boundary = effective
            if effective.requiresExplicitConsent {
                guard let origin else { throw ScheduleManagerError.providerEndpointUnavailable }
                updated[index].unattendedConsent = try ScheduleUnattendedConsent(
                    selection: updated[index].selection,
                    boundary: effective,
                    origin: origin,
                    grantedAt: now()
                )
            } else {
                updated[index].unattendedConsent = nil
            }
            updated[index].enabled = true
            if updated[index].nextRun < now() { updated[index].nextRun = now() }
            try store.save(updated)
            schedules = updated
            notifyChange()
            drainExecutionQueue()
        }
    }

    func revokeUnattendedConsent(id: UUID) throws {
        try queue.sync {
            guard storageWritable, let store else { throw ScheduleManagerError.storageUnavailable }
            guard let index = schedules.firstIndex(where: { $0.id == id }) else { return }
            var updated = schedules
            updated[index].unattendedConsent = nil
            updated[index].enabled = false
            try store.save(updated)
            pendingManualRuns.removeAll { $0 == id }
            if let run = active.removeValue(forKey: id) {
                if let executorID = run.executorID { executor.cancel(executorID) }
                activities.update(run.activityID, state: .cancelled, detail: "Cancelled because unattended consent was revoked.")
            }
            schedules = updated
            notifyChange()
            drainExecutionQueue()
        }
    }

    func runNow(id: UUID) {
        queue.async { [weak self] in
            guard let self, !admissionsSuspended,
                  schedules.contains(where: { $0.id == id }) else { return }
            if !pendingManualRuns.contains(id), active[id] == nil { pendingManualRuns.append(id) }
            drainExecutionQueue()
        }
    }

    func cancelRun(id: UUID) {
        queue.async { [weak self] in
            guard let self, let run = active[id] else { return }
            if let executorID = run.executorID {
                executor.cancel(executorID)
            } else {
                active.removeValue(forKey: id)
                activities.update(run.activityID, state: .cancelled, detail: "Cancelled before the scheduled prompt started.")
                drainExecutionQueue()
            }
        }
    }

    func inbox() -> [ScheduledResult] { store?.inbox() ?? [] }

    func inboxCount() -> Int { store?.inboxCount() ?? 0 }

    func inboxAsync() async -> ScheduleInboxLoadOutcome {
        await withCheckedContinuation { continuation in
            inboxReadQueue.async { [weak self, store] in
                let outcome: ScheduleInboxLoadOutcome
                do {
                    guard let store else { throw ScheduleManagerError.storageUnavailable }
                    outcome = .loaded(try store.inboxChecked())
                } catch {
                    let message = "The private Task Inbox is unavailable. Existing result files were preserved."
                    outcome = .unavailable(message)
                    self?.queue.async { [weak self] in
                        self?.storageFailure = message
                        self?.notifyChange()
                    }
                }
                continuation.resume(returning: outcome)
            }
        }
    }

    func deleteInboxResult(id: UUID) throws {
        guard let store else { throw ScheduleManagerError.storageUnavailable }
        try store.deleteInboxResult(id: id)
        notifyChange()
    }

    func clearInbox() throws {
        guard let store else { throw ScheduleManagerError.storageUnavailable }
        try store.clearInbox()
        notifyChange()
    }

    var backgroundServiceEnabled: Bool {
        SMAppService.agent(plistName: "com.angadjairath.localharness.scheduler.plist").status == .enabled
    }

    func setBackgroundService(enabled: Bool) throws {
        let service = SMAppService.agent(plistName: "com.angadjairath.localharness.scheduler.plist")
        if enabled {
            if service.status != .enabled { try service.register() }
        } else if service.status == .enabled {
            try service.unregister()
        }
        notifyChange()
    }

    private func runDue() {
        guard !admissionsSuspended else { return }
        drainExecutionQueue()
    }

    /// Exactly one unattended execution may own the approved workspace at a
    /// time. Manual requests retain FIFO order; due tasks use next-run order.
    private func drainExecutionQueue() {
        guard !admissionsSuspended else {
            pendingManualRuns.removeAll()
            notifyIdleIfNeeded()
            return
        }
        guard active.isEmpty else { return }
        guard storageWritable, store != nil else {
            notifyIdleIfNeeded()
            return
        }
        while active.isEmpty {
            let schedule: LocalSchedule?
            if !pendingManualRuns.isEmpty {
                let id = pendingManualRuns.removeFirst()
                schedule = schedules.first(where: { $0.id == id })
            } else {
                let current = now()
                schedule = schedules
                    .filter { $0.enabled && $0.nextRun <= current }
                    .min { left, right in
                        if left.nextRun == right.nextRun { return left.id.uuidString < right.id.uuidString }
                        return left.nextRun < right.nextRun
                    }
            }
            guard let schedule else {
                notifyIdleIfNeeded()
                return
            }
            if prepareAndExecute(schedule) { return }
        }
    }

    /// Returns true once an asynchronous checkpoint/execution owns the queue;
    /// false means the candidate failed synchronously and draining may continue.
    private func prepareAndExecute(_ schedule: LocalSchedule) -> Bool {
        guard !admissionsSuspended, active.isEmpty, active[schedule.id] == nil else { return false }
        let generation = executionGeneration
        let effectiveBoundary = boundaryPolicy.boundary(for: schedule.selection.route.provider)
        let authorization = authorizationStatusLocked(for: schedule)
        guard authorization == .authorized else {
            if case .providerInactive = authorization {
                recordFailureWithoutExecution(
                    schedule,
                    failure: ScheduleResultFailure(code: .runtimeUnavailable, detail: "provider inactive"),
                    disable: false
                )
                return false
            }
            if case .routeInactive = authorization {
                recordFailureWithoutExecution(
                    schedule,
                    failure: ScheduleResultFailure(code: .runtimeUnavailable, detail: "local model route inactive"),
                    disable: false
                )
                return false
            }
            recordBlocked(schedule, effectiveBoundary: effectiveBoundary)
            return false
        }
        guard let store else {
            recordFailureWithoutExecution(schedule, failure: ScheduleResultFailure(code: .filesystem), disable: false)
            return false
        }
        let workspace: URL
        if let executionWorkspace {
            do {
                try FileManager.default.createDirectory(at: executionWorkspace, withIntermediateDirectories: true)
                workspace = executionWorkspace
            } catch {
                recordFailureWithoutExecution(schedule, failure: ScheduleResultFailure(code: .filesystem), disable: false)
                return false
            }
        } else if let privateWorkspace = try? store.workspace(for: schedule.id) {
            workspace = privateWorkspace
        } else {
            recordFailureWithoutExecution(schedule, failure: ScheduleResultFailure(code: .filesystem), disable: false)
            return false
        }

        let token = UUID()
        let activityID = activities.begin(
            .schedule,
            title: schedule.title,
            detail: "Creating a protected recovery point before unattended work."
        )
        active[schedule.id] = ActiveRun(token: token, executorID: nil, activityID: activityID)

        let prepared: @Sendable (Result<Void, Error>) -> Void = { [weak self] result in
            guard let self else { return }
            self.queue.async {
                guard generation == self.executionGeneration,
                      self.active[schedule.id]?.token == token else { return }
                switch result {
                case .success:
                    self.beginExecution(
                        schedule: schedule,
                        workspace: workspace,
                        generation: generation,
                        token: token,
                        activityID: activityID
                    )
                case .failure:
                    self.active.removeValue(forKey: schedule.id)
                    let failure = ScheduleResultFailure(
                        code: .checkpointFailed,
                        // Preparation callbacks are an extensibility boundary.
                        // Their Error may contain credentials or private paths;
                        // checkpoint failures deliberately persist no detail.
                        detail: nil
                    )
                    self.activities.update(activityID, state: .failed, detail: failure.displayMessage)
                    self.recordResult(
                        schedule: schedule,
                        completedAt: self.now(),
                        selection: schedule.selection,
                        boundary: effectiveBoundary,
                        sessionID: nil,
                        response: "",
                        failure: failure,
                        truncated: false,
                        disable: false,
                        retrySoon: true
                    )
                    self.drainExecutionQueue()
                }
            }
        }
        if let prepareExecution {
            prepareExecution(schedule, prepared)
        } else {
            prepared(.success(()))
        }
        return true
    }

    private func beginExecution(
        schedule: LocalSchedule,
        workspace: URL,
        generation: UInt64,
        token: UUID,
        activityID: UUID
    ) {
        guard generation == executionGeneration,
              !admissionsSuspended,
              active[schedule.id]?.token == token,
              schedules.contains(where: { $0.id == schedule.id }),
              authorizationStatusLocked(for: schedule) == .authorized else {
            active.removeValue(forKey: schedule.id)
            activities.update(activityID, state: .cancelled, detail: "The route changed before the scheduled prompt started.")
            drainExecutionQueue()
            return
        }

        guard let store else {
            active.removeValue(forKey: schedule.id)
            storageWritable = false
            storageFailure = "The at-most-once schedule journal is unavailable. No provider request was sent."
            activities.update(
                activityID,
                state: .failed,
                detail: "The private occurrence journal was unavailable, so the scheduled prompt was not sent."
            )
            drainExecutionQueue()
            return
        }
        do {
            try store.beginOccurrence(id: token, scheduleID: schedule.id, startedAt: now())
        } catch {
            active.removeValue(forKey: schedule.id)
            storageWritable = false
            storageFailure = "The at-most-once schedule journal could not be written safely. No provider request was sent."
            activities.update(
                activityID,
                state: .failed,
                detail: "The private occurrence journal could not be committed, so the scheduled prompt was not sent."
            )
            notifyChange()
            drainExecutionQueue()
            return
        }

        let effectiveBoundary = boundaryPolicy.boundary(for: schedule.selection.route.provider)
        activities.update(
            activityID,
            state: .running,
            detail: "Scheduled task running with \(schedule.provider) / \(schedule.model) · \(effectiveBoundary.displayName)."
        )
        let request = ScheduleConversationRequest(
            selection: schedule.selection,
            prompt: schedule.prompt,
            workspace: workspace,
            timeoutSeconds: schedule.timeoutSeconds
        )
        let executorID = executor.execute(request) { [weak self] result in
            guard let self else { return }
            queue.async {
                guard generation == self.executionGeneration,
                      self.active[schedule.id]?.token == token else { return }
                self.complete(
                    schedule: schedule,
                    token: token,
                    activityID: activityID,
                    boundary: effectiveBoundary,
                    result: result
                )
            }
        }
        guard var run = active[schedule.id], run.token == token else {
            executor.cancel(executorID)
            return
        }
        run.executorID = executorID
        active[schedule.id] = run
    }

    private func recordBlocked(_ schedule: LocalSchedule, effectiveBoundary: DataBoundary) {
        let failure = ScheduleResultFailure(code: .consentRequired)
        let activityID = activities.begin(.schedule, title: schedule.title, detail: failure.displayMessage)
        activities.update(activityID, state: .failed, detail: failure.displayMessage)
        recordResult(
            schedule: schedule,
            completedAt: now(),
            selection: schedule.selection,
            boundary: effectiveBoundary,
            sessionID: nil,
            response: "",
            failure: failure,
            truncated: false,
            disable: true,
            retrySoon: false
        )
    }

    private func recordFailureWithoutExecution(
        _ schedule: LocalSchedule,
        failure: ScheduleResultFailure,
        disable: Bool
    ) {
        let activityID = activities.begin(.schedule, title: schedule.title, detail: failure.displayMessage)
        activities.update(activityID, state: .failed, detail: failure.displayMessage)
        recordResult(
            schedule: schedule,
            completedAt: now(),
            selection: schedule.selection,
            boundary: schedule.boundary,
            sessionID: nil,
            response: "",
            failure: failure,
            truncated: false,
            disable: disable,
            retrySoon: failure.code == .runtimeUnavailable
        )
    }

    private func complete(
        schedule: LocalSchedule,
        token: UUID,
        activityID: UUID,
        boundary: DataBoundary,
        result: Result<ScheduleConversationOutput, ScheduleExecutionError>
    ) {
        guard active[schedule.id]?.token == token else { return }
        active.removeValue(forKey: schedule.id)
        let completed = now()
        switch result {
        case .success(let output):
            let detail = output.truncated
                ? "Partial result saved to Task Inbox because the model reached its output limit."
                : "Result saved to Task Inbox."
            let saved = recordExecutedResult(
                occurrenceID: token,
                schedule: schedule,
                completedAt: completed,
                selection: output.selection,
                boundary: boundary,
                sessionID: output.sessionID,
                response: output.response,
                failure: nil,
                truncated: output.truncated,
                disable: false,
                retrySoon: false
            )
            if saved {
                activities.update(activityID, state: .completed, detail: detail, progress: 1)
            } else {
                activities.update(
                    activityID,
                    state: .failed,
                    detail: "The model completed, but its result could not be saved to the private Task Inbox.",
                    progress: nil
                )
            }
        case .failure(let error):
            let failure = error.resultFailure
            activities.update(activityID, state: error == .cancelled ? .cancelled : .failed, detail: failure.displayMessage)
            _ = recordExecutedResult(
                occurrenceID: token,
                schedule: schedule,
                completedAt: completed,
                selection: schedule.selection,
                boundary: boundary,
                sessionID: nil,
                response: "",
                failure: failure,
                truncated: false,
                disable: error == .interactionRequired,
                retrySoon: error == .runtimeUnavailable
            )
        }
        drainExecutionQueue()
    }

    /// Commits an executed occurrence as an idempotent three-document
    /// transaction: completed receipt, deterministic Inbox result, then the
    /// schedules document. The receipt is removed only after all three durable
    /// boundaries succeed. On any failure the in-memory schedule is still
    /// advanced once, while the durable receipt makes startup reconcile the
    /// stale document without dispatching the provider request again.
    @discardableResult
    private func recordExecutedResult(
        occurrenceID: UUID,
        schedule: LocalSchedule,
        completedAt: Date,
        selection: ModelSelection,
        boundary: DataBoundary,
        sessionID: HarnessSessionID?,
        response: String,
        failure: ScheduleResultFailure?,
        truncated: Bool,
        disable: Bool,
        retrySoon: Bool
    ) -> Bool {
        let result = ScheduledResult(
            id: occurrenceID,
            scheduleID: schedule.id,
            title: schedule.title,
            completedAt: completedAt,
            selection: selection,
            boundary: boundary,
            sessionID: sessionID,
            response: response,
            failure: failure,
            truncated: truncated
        )
        do {
            guard let store else { throw ScheduleManagerError.storageUnavailable }
            try durabilityFailureInjector(.afterExecutionCompletionBeforeReceiptCommit)
            try store.completeOccurrence(
                id: occurrenceID,
                result: result,
                disable: disable,
                retrySoon: retrySoon
            )
            try store.ensure(result: result)
            try durabilityFailureInjector(.afterResultCommitBeforeScheduleCommit)
            _ = applyScheduleOccurrenceTransition(
                schedules: &schedules,
                scheduleID: schedule.id,
                completedAt: completedAt,
                disable: disable,
                retrySoon: retrySoon
            )
            try store.save(schedules)
            try store.finishOccurrence(id: occurrenceID)
            notifyChange()
            return true
        } catch {
            _ = applyScheduleOccurrenceTransition(
                schedules: &schedules,
                scheduleID: schedule.id,
                completedAt: completedAt,
                disable: disable,
                retrySoon: retrySoon
            )
            storageWritable = false
            storageFailure = "A completed scheduled occurrence is awaiting private journal recovery. It will not be sent to the provider again."
            notifyChange()
            return false
        }
    }

    @discardableResult
    private func recordResult(
        schedule: LocalSchedule,
        completedAt: Date,
        selection: ModelSelection,
        boundary: DataBoundary,
        sessionID: HarnessSessionID?,
        response: String,
        failure: ScheduleResultFailure?,
        truncated: Bool,
        disable: Bool,
        retrySoon: Bool
    ) -> Bool {
        let result = ScheduledResult(
            scheduleID: schedule.id,
            title: schedule.title,
            completedAt: completedAt,
            selection: selection,
            boundary: boundary,
            sessionID: sessionID,
            response: response,
            failure: failure,
            truncated: truncated
        )
        let resultSaved: Bool
        do {
            guard let store else { throw ScheduleManagerError.storageUnavailable }
            try store.write(result: result)
            resultSaved = true
        } catch {
            storageFailure = "A scheduled result could not be written safely."
            resultSaved = false
        }

        if schedules.contains(where: { $0.id == schedule.id }) {
            _ = applyScheduleOccurrenceTransition(
                schedules: &schedules,
                scheduleID: schedule.id,
                completedAt: completedAt,
                disable: disable,
                retrySoon: retrySoon
            )
            persistCurrentSchedules()
        } else {
            notifyChange()
        }
        return resultSaved
    }

    private func persistCurrentSchedules() {
        guard storageWritable, let store else { notifyChange(); return }
        do { try store.save(schedules) }
        catch {
            storageWritable = false
            storageFailure = "Schedule updates could not be written safely. Existing data was preserved."
        }
        notifyChange()
    }

    private func notifyChange() { DispatchQueue.main.async { self.onChange?() } }

    private func notifyIdleIfNeeded() {
        guard active.isEmpty, pendingManualRuns.isEmpty else { return }
        if storageWritable {
            let current = now()
            guard !schedules.contains(where: { $0.enabled && $0.nextRun <= current }) else { return }
        }
        // Enter background-app termination only once. Quiescing the scheduler
        // is part of that termination barrier and must not recursively request
        // a second termination while the first one is deferred.
        guard let callback = onIdleAfterRun else { return }
        onIdleAfterRun = nil
        DispatchQueue.main.async(execute: callback)
    }
}
