import AppKit
import Darwin
import Foundation
import Testing
@testable import LocalHarness

private func withPerformanceSpool(
    _ body: (URL, URL) throws -> Void
) throws {
    let provisional = FileManager.default.temporaryDirectory
        .appendingPathComponent("local-harness-spool-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: provisional, withIntermediateDirectories: false)
    let container = provisional.resolvingSymlinksInPath().standardizedFileURL
    let applicationSupport = container.appendingPathComponent("Local Harness", isDirectory: true)
    try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: applicationSupport.path)
    defer { try? FileManager.default.removeItem(at: container) }
    try body(applicationSupport, GenerationTelemetrySpool.storageURL(applicationSupport: applicationSupport))
}

private func makePerformanceSpool() throws -> (container: URL, applicationSupport: URL, file: URL) {
    let provisional = FileManager.default.temporaryDirectory
        .appendingPathComponent("local-harness-spool-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: provisional, withIntermediateDirectories: false)
    let container = provisional.resolvingSymlinksInPath().standardizedFileURL
    let applicationSupport = container.appendingPathComponent("Local Harness", isDirectory: true)
    try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: applicationSupport.path)
    return (container, applicationSupport, GenerationTelemetrySpool.storageURL(applicationSupport: applicationSupport))
}

private func performanceProjectRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}

private func launchPausedTelemetryWriter(
    applicationSupport: URL,
    file: URL,
    ready: URL,
    release: URL,
    stage: String
) throws -> (process: Process, errors: Pipe) {
    let project = performanceProjectRoot()
    let node = project.appendingPathComponent("VendorRuntime/node-v22.23.1-darwin-arm64/bin/node")
    let helper = project.appendingPathComponent(".build/debug/LocalHarnessCredentialHelper")
    let fixture = project.appendingPathComponent("Tests/Fixtures/PerformanceTelemetryPausedWriter.mjs")
    guard FileManager.default.isExecutableFile(atPath: node.path),
          FileManager.default.isExecutableFile(atPath: helper.path),
          FileManager.default.fileExists(atPath: fixture.path) else {
        throw GenerationTelemetrySpoolError.storageUnavailable
    }
    let process = Process()
    let errors = Pipe()
    process.executableURL = node
    process.arguments = [
        fixture.path, helper.path, applicationSupport.path, file.path,
        ready.path, release.path, stage
    ]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = errors
    try process.run()
    return (process, errors)
}

private func waitForTelemetryTestFile(
    _ url: URL,
    process: Process? = nil,
    timeout: TimeInterval = 5
) throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if FileManager.default.fileExists(atPath: url.path) { return }
        if let process, !process.isRunning {
            throw GenerationTelemetrySpoolError.storageUnavailable
        }
        Darwin.usleep(10_000)
    }
    throw GenerationTelemetrySpoolError.storageUnavailable
}

private func assertSuccessfulTelemetryWriter(_ process: Process, errors: Pipe) {
    #expect(boundedTestWaitForExit(process, timeout: 10))
    let errorText = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    #expect(process.terminationReason == .exit)
    #expect(process.terminationStatus == 0, Comment(rawValue: errorText))
}

private final class PerformanceClearTestGate: @unchecked Sendable {
    private let lock = NSLock()
    private let releaseSemaphore = DispatchSemaphore(value: 0)
    private var started = false

    var hasStarted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return started
    }

    func startAndWaitForRelease() {
        lock.lock()
        started = true
        lock.unlock()
        _ = releaseSemaphore.wait(timeout: .now() + 5)
    }

    func release() {
        releaseSemaphore.signal()
    }
}

private func performanceRecord(
    id: String = "12345678-1234-4abc-8def-1234567890ab",
    provider: Any = "ollama",
    model: Any = "qwen3.8:27b-mlx",
    profile: Any = "balanced",
    started: Int64,
    completed: Int64,
    firstToken: Any,
    tokens: Int = 42,
    source: String = "providerReported",
    outcome: String = "completed",
    failure: Any = NSNull()
) -> [String: Any] {
    [
        "schemaVersion": 1,
        "id": id,
        "provider": provider,
        "model": model,
        "profile": profile,
        "startedAtMilliseconds": started,
        "completedAtMilliseconds": completed,
        "firstTokenAtMilliseconds": firstToken,
        "elapsedMilliseconds": completed - started,
        "outputTokens": tokens,
        "outputTokenCountSource": source,
        "outcome": outcome,
        "failureCategory": failure
    ]
}

private func writePerformanceEnvelope(_ records: [[String: Any]], to file: URL) throws {
    let data = try JSONSerialization.data(
        withJSONObject: ["schemaVersion": 1, "records": records],
        options: [.sortedKeys]
    )
    try data.write(to: file, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
}

private struct StubHostEnvironment: HostEnvironmentReading {
    let physicalMemory: UInt64
    let thermalCondition: HostThermalCondition
    let lowPowerModeEnabled: Bool
    let processorArchitecture: HostProcessorArchitecture
    let logicalProcessorCount: Int
    let activeProcessorCount: Int
}

private struct StubOllamaLocator: OllamaInstallationLocating {
    let url: URL?
    let issue: OllamaProbeIssue?

    init(url: URL?, issue: OllamaProbeIssue? = nil) {
        self.url = url
        self.issue = issue
    }

    func locateInstallation() -> OllamaInstallationSnapshot {
        OllamaInstallationSnapshot(executableURL: url, issue: issue)
    }
}

private actor StubLoopbackTransport: LoopbackHTTPTransport {
    struct Reply {
        let status: Int
        let data: Data
    }

    enum StubError: Error { case missingReply }

    private let replies: [String: Reply]
    private(set) var paths: [String] = []

    init(replies: [String: Reply]) {
        self.replies = replies
    }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let path = request.url?.path ?? ""
        paths.append(path)
        guard let reply = replies[path], let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: reply.status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
              ) else {
            throw StubError.missingReply
        }
        return (reply.data, response)
    }
}

@Test func hostPerformanceSnapshotUsesOnlyInjectedSystemReadings() {
    let date = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let environment = StubHostEnvironment(
        physicalMemory: 48 * 1_073_741_824,
        thermalCondition: .fair,
        lowPowerModeEnabled: true,
        processorArchitecture: .appleSilicon,
        logicalProcessorCount: 0,
        activeProcessorCount: -2
    )

    let snapshot = HostPerformanceSnapshotCollector(environment: environment).capture(at: date)

    #expect(snapshot.capturedAt == date)
    #expect(snapshot.physicalMemoryGiB == 48)
    #expect(snapshot.thermalCondition == .fair)
    #expect(snapshot.lowPowerModeEnabled)
    #expect(snapshot.processorArchitecture == .appleSilicon)
    #expect(snapshot.logicalProcessorCount == 1)
    #expect(snapshot.activeProcessorCount == 1)
}

@Test func telemetryReducesOutputToCountsAndNeverRetainsContent() throws {
    let accumulator = GenerationTelemetryAccumulator()
    let start = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let route = ModelRoute(provider: ProviderID("ollama"), model: ModelID("qwen-local"))
    let id = accumulator.begin(route: route, at: start)
    let secret = "TOP SECRET CUSTOMER PROMPT AND RESPONSE"

    #expect(accumulator.recordOutput(secret, for: id, at: start.addingTimeInterval(2)))
    let record = try #require(accumulator.finish(id, at: start.addingTimeInterval(6)))

    #expect(record.route == route)
    #expect(record.timeToFirstTokenSeconds == 2)
    #expect(record.elapsedSeconds == 6)
    #expect(record.outputTokenCountSource == .estimated)
    #expect(record.outputTokens == (secret.utf8.count + 3) / 4)
    #expect(record.outputTokensPerSecond == Double(record.outputTokens) / 4)
    #expect(record.outcome == .completed)
    let encoded = String(decoding: try JSONEncoder().encode(record), as: UTF8.self)
    #expect(!encoded.contains(secret))
    #expect(!encoded.lowercased().contains("prompt"))
    #expect(accumulator.activeGenerationCount == 0)
}

@Test func telemetryPrefersProviderTokenCountsAndSanitizesFailures() throws {
    let accumulator = GenerationTelemetryAccumulator()
    let start = Date(timeIntervalSinceReferenceDate: 700_000_000)

    let completedID = accumulator.begin(at: start)
    _ = accumulator.recordOutput("abc", for: completedID, at: start.addingTimeInterval(1))
    let completed = try #require(accumulator.finish(
        completedID,
        reportedOutputTokens: 120,
        at: start.addingTimeInterval(5)
    ))
    #expect(completed.outputTokens == 120)
    #expect(completed.outputTokenCountSource == .providerReported)
    #expect(completed.outputTokensPerSecond == 30)

    let failedID = accumulator.begin(at: start.addingTimeInterval(6))
    let failed = try #require(accumulator.fail(
        failedID,
        category: .providerUnavailable,
        at: start.addingTimeInterval(7)
    ))
    #expect(failed.outcome == .failed)
    #expect(failed.failureCategory == .providerUnavailable)

    let cancelledID = accumulator.begin(at: start.addingTimeInterval(8))
    let cancelled = try #require(accumulator.cancel(cancelledID, at: start.addingTimeInterval(9)))
    #expect(cancelled.outcome == .cancelled)
    #expect(cancelled.failureCategory == nil)
    #expect(accumulator.finish(UUID(), at: start) == nil)
}

@Test func telemetryRetentionIsStrictlyBoundedByAgeAndCount() throws {
    #expect(throws: GenerationTelemetryRetentionPolicy.ValidationError.invalidRecordCount) {
        try GenerationTelemetryRetentionPolicy(maximumRecords: 501, maximumAge: 3_600)
    }
    #expect(throws: GenerationTelemetryRetentionPolicy.ValidationError.invalidMaximumAge) {
        try GenerationTelemetryRetentionPolicy(maximumRecords: 1, maximumAge: 8 * 86_400)
    }

    let retention = try GenerationTelemetryRetentionPolicy(maximumRecords: 2, maximumAge: 3_600)
    let accumulator = GenerationTelemetryAccumulator(retention: retention)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    for offset in [-7_200.0, -20.0, -10.0, 0.0] {
        let id = accumulator.begin(at: now.addingTimeInterval(offset - 1))
        _ = accumulator.finish(id, at: now.addingTimeInterval(offset))
    }

    let history = accumulator.history(at: now)
    #expect(history.count == 2)
    #expect(history.map(\.completedAt) == [now, now.addingTimeInterval(-10)])

    let active = accumulator.begin(at: now)
    #expect(accumulator.activeGenerationCount == 1)
    accumulator.clear()
    #expect(accumulator.history(at: now).isEmpty)
    #expect(accumulator.activeGenerationCount == 0)
    #expect(!accumulator.recordOutput("discarded", for: active, at: now))
}

@Test func telemetryCapsInFlightStateAndRejectsUnsafeRouteLabels() throws {
    let retention = try GenerationTelemetryRetentionPolicy(maximumRecords: 100, maximumAge: 3_600)
    let accumulator = GenerationTelemetryAccumulator(retention: retention)
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    for index in 0...GenerationTelemetryAccumulator.absoluteMaximumActiveGenerations {
        _ = accumulator.begin(at: now.addingTimeInterval(Double(index)))
    }
    #expect(accumulator.activeGenerationCount == GenerationTelemetryAccumulator.absoluteMaximumActiveGenerations)

    let unsafeRoute = ModelRoute(
        provider: ProviderID("ollama"),
        model: ModelID("qwen\nspoofed-row")
    )
    let id = accumulator.begin(route: unsafeRoute, at: now.addingTimeInterval(100))
    let record = try #require(accumulator.finish(id, at: now.addingTimeInterval(101)))
    #expect(record.route == nil)

    _ = accumulator.history(at: now.addingTimeInterval(3_800))
    #expect(accumulator.activeGenerationCount == 0)
}

@Test func persistedTelemetryUsesExactPrivateSchemaAndNeverNeedsContent() throws {
    try withPerformanceSpool { applicationSupport, file in
        let prepared = try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        #expect(prepared == file)
        var directoryMetadata = stat()
        var fileMetadata = stat()
        var lockMetadata = stat()
        let lock = file.deletingLastPathComponent()
            .appendingPathComponent(GenerationTelemetrySpool.lockName)
        #expect(Darwin.lstat(file.deletingLastPathComponent().path, &directoryMetadata) == 0)
        #expect(Darwin.lstat(file.path, &fileMetadata) == 0)
        #expect(Darwin.lstat(lock.path, &lockMetadata) == 0)
        #expect(directoryMetadata.st_mode & 0o777 == 0o700)
        #expect(fileMetadata.st_mode & 0o777 == 0o600)
        #expect(fileMetadata.st_nlink == 1)
        #expect(lockMetadata.st_mode & S_IFMT == S_IFREG)
        #expect(lockMetadata.st_mode & 0o777 == 0o600)
        #expect(lockMetadata.st_nlink == 1)
        #expect(lockMetadata.st_size == 0)

        let reference = Date(timeIntervalSince1970: 1_700_000_000)
        let completed = Int64(reference.timeIntervalSince1970 * 1_000)
        try writePerformanceEnvelope([
            performanceRecord(
                started: completed - 6_000,
                completed: completed,
                firstToken: completed - 4_000
            )
        ], to: file)

        let records = GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference)
        let record = try #require(records.first)
        #expect(records.count == 1)
        #expect(record.id == UUID(uuidString: "12345678-1234-4abc-8def-1234567890ab"))
        #expect(record.route == ModelRoute(provider: ProviderID("ollama"), model: ModelID("qwen3.8:27b-mlx")))
        #expect(record.timeToFirstTokenSeconds == 2)
        #expect(record.elapsedSeconds == 6)
        #expect(record.outputTokens == 42)
        #expect(record.outputTokenCountSource == .providerReported)
        #expect(record.outputTokensPerSecond == 10.5)
        #expect(record.outcome == .completed)
        #expect(record.failureCategory == nil)

        let encoded = try Data(contentsOf: file)
        #expect(!String(decoding: encoded, as: UTF8.self).lowercased().contains("prompt"))
        #expect(encoded.count <= GenerationTelemetrySpool.maximumFileBytes)
    }
}

@Test func persistedTelemetryRejectsUnknownCorruptStaleFutureDuplicateAndExcessRows() throws {
    try withPerformanceSpool { applicationSupport, file in
        _ = try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        let reference = Date(timeIntervalSince1970: 1_700_000_000)
        let completed = Int64(reference.timeIntervalSince1970 * 1_000)
        let valid = performanceRecord(
            started: completed - 1_000,
            completed: completed,
            firstToken: completed - 500
        )

        var unknown = valid
        unknown["prompt"] = "PRIVATE_PROMPT_CANARY"
        try writePerformanceEnvelope([unknown], to: file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)

        try Data("{partial".utf8).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)

        let stale = performanceRecord(
            started: completed - Int64(GenerationTelemetrySpool.maximumAge * 1_000) - 2_000,
            completed: completed - Int64(GenerationTelemetrySpool.maximumAge * 1_000) - 1_000,
            firstToken: NSNull()
        )
        try writePerformanceEnvelope([stale], to: file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)

        let future = performanceRecord(
            started: completed + Int64(GenerationTelemetrySpool.maximumFutureSkew * 1_000) + 1,
            completed: completed + Int64(GenerationTelemetrySpool.maximumFutureSkew * 1_000) + 1_001,
            firstToken: NSNull()
        )
        try writePerformanceEnvelope([future], to: file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)

        try writePerformanceEnvelope([valid, valid], to: file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)

        let excessive = (0...GenerationTelemetrySpool.maximumRecords).map { index in
            performanceRecord(
                id: String(format: "12345678-1234-4abc-8def-%012d", index),
                started: completed - Int64(index + 1),
                completed: completed - Int64(index),
                firstToken: NSNull()
            )
        }
        try writePerformanceEnvelope(excessive, to: file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)

        try writePerformanceEnvelope([valid], to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)
    }
}

@Test func persistedTelemetryNeverFollowsLinkedOrHardLinkedStorage() throws {
    try withPerformanceSpool { applicationSupport, file in
        let directory = file.deletingLastPathComponent()
        let outside = applicationSupport.deletingLastPathComponent().appendingPathComponent("outside-canary")
        try Data("OUTSIDE_CANARY".utf8).write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)

        try FileManager.default.createSymbolicLink(at: directory, withDestinationURL: outside)
        #expect(throws: GenerationTelemetrySpoolError.unsafeStorage) {
            try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        }
        #expect(GenerationTelemetrySpool.prepareIfAvailable(applicationSupport: applicationSupport) == nil)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport).isEmpty)
        try FileManager.default.removeItem(at: directory)

        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        #expect(Darwin.link(outside.path, file.path) == 0)
        #expect(throws: GenerationTelemetrySpoolError.unsafeStorage) {
            try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        }
        #expect(GenerationTelemetrySpool.prepareIfAvailable(applicationSupport: applicationSupport) == nil)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport).isEmpty)
        #expect(try String(contentsOf: outside, encoding: .utf8) == "OUTSIDE_CANARY")
    }
}

@Test func clearingPersistedTelemetryNeverFollowsLinksAndRecreatesAnEmptyPrivateSpool() throws {
    try withPerformanceSpool { applicationSupport, file in
        _ = try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        let reference = Date(timeIntervalSince1970: 1_700_000_000)
        let completed = Int64(reference.timeIntervalSince1970 * 1_000)
        try writePerformanceEnvelope([
            performanceRecord(started: completed - 1_000, completed: completed, firstToken: completed - 500)
        ], to: file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).count == 1)

        let recreated = try GenerationTelemetrySpool.clear(applicationSupport: applicationSupport)
        #expect(recreated == file)
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)
        var metadata = stat()
        #expect(Darwin.lstat(file.path, &metadata) == 0)
        #expect(metadata.st_mode & 0o777 == 0o600)
        #expect(metadata.st_nlink == 1)

        let outside = applicationSupport.deletingLastPathComponent().appendingPathComponent("telemetry-clear-outside")
        try Data("DO_NOT_DELETE_OR_CHANGE".utf8).write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
        try FileManager.default.removeItem(at: file)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: outside)

        _ = try GenerationTelemetrySpool.clear(applicationSupport: applicationSupport)
        #expect(try String(contentsOf: outside, encoding: .utf8) == "DO_NOT_DELETE_OR_CHANGE")
        #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport, at: reference).isEmpty)
        #expect(Darwin.lstat(file.path, &metadata) == 0)
        #expect(metadata.st_mode & S_IFMT == S_IFREG)
        #expect(metadata.st_nlink == 1)
    }
}

@Test func telemetryClearSerializesWithAWriterPausedAfterLoad() async throws {
    let storage = try makePerformanceSpool()
    defer { try? FileManager.default.removeItem(at: storage.container) }
    _ = try GenerationTelemetrySpool.prepare(applicationSupport: storage.applicationSupport)
    try writePerformanceEnvelope([
        performanceRecord(
            started: 3_999_998,
            completed: 3_999_999,
            firstToken: 3_999_999
        )
    ], to: storage.file)

    let ready = storage.container.appendingPathComponent("writer-after-load.ready")
    let release = storage.container.appendingPathComponent("writer-after-load.release")
    let contention = storage.container.appendingPathComponent("clear-after-load.contended")
    let writer = try launchPausedTelemetryWriter(
        applicationSupport: storage.applicationSupport,
        file: storage.file,
        ready: ready,
        release: release,
        stage: "after-load"
    )
    try waitForTelemetryTestFile(ready, process: writer.process)

    let clearTask = Task.detached {
        try GenerationTelemetrySpool.clear(
            applicationSupport: storage.applicationSupport,
            lockContentionObserver: {
                _ = FileManager.default.createFile(atPath: contention.path, contents: Data("contended".utf8))
            }
        )
    }
    try waitForTelemetryTestFile(contention, process: writer.process)
    try Data("release".utf8).write(to: release, options: .withoutOverwriting)
    assertSuccessfulTelemetryWriter(writer.process, errors: writer.errors)
    _ = try await clearTask.value

    #expect(GenerationTelemetrySpool.read(
        applicationSupport: storage.applicationSupport,
        at: Date(timeIntervalSince1970: 4_000)
    ).isEmpty)
    let decoded = try JSONSerialization.jsonObject(with: Data(contentsOf: storage.file)) as? [String: Any]
    #expect((decoded?["records"] as? [Any])?.isEmpty == true)
}

@Test func telemetryClearRecoversAfterKilledWriterAndRemovesItsRetainedTemporary() async throws {
    let storage = try makePerformanceSpool()
    defer { try? FileManager.default.removeItem(at: storage.container) }
    _ = try GenerationTelemetrySpool.prepare(applicationSupport: storage.applicationSupport)
    try writePerformanceEnvelope([
        performanceRecord(
            started: 3_999_998,
            completed: 3_999_999,
            firstToken: 3_999_999
        )
    ], to: storage.file)

    let ready = storage.container.appendingPathComponent("writer-before-rename.ready")
    let release = storage.container.appendingPathComponent("writer-before-rename.release")
    let contention = storage.container.appendingPathComponent("clear-before-rename.contended")
    let temporary = storage.file.deletingLastPathComponent()
        .appendingPathComponent(".performance-telemetry.json.tmp")
    let writer = try launchPausedTelemetryWriter(
        applicationSupport: storage.applicationSupport,
        file: storage.file,
        ready: ready,
        release: release,
        stage: "before-rename"
    )
    try waitForTelemetryTestFile(ready, process: writer.process)
    #expect(FileManager.default.fileExists(atPath: temporary.path))

    let clearTask = Task.detached {
        try GenerationTelemetrySpool.clear(
            applicationSupport: storage.applicationSupport,
            lockContentionObserver: {
                _ = FileManager.default.createFile(atPath: contention.path, contents: Data("contended".utf8))
            }
        )
    }
    try waitForTelemetryTestFile(contention, process: writer.process)
    #expect(Darwin.kill(writer.process.processIdentifier, SIGKILL) == 0)
    #expect(boundedTestWaitForExit(writer.process, timeout: 5))
    _ = writer.errors.fileHandleForReading.readDataToEndOfFile()
    #expect(writer.process.terminationReason == .uncaughtSignal)
    #expect(writer.process.terminationStatus == SIGKILL)
    _ = try await clearTask.value

    #expect(!FileManager.default.fileExists(atPath: temporary.path))
    #expect(GenerationTelemetrySpool.read(
        applicationSupport: storage.applicationSupport,
        at: Date(timeIntervalSince1970: 4_000)
    ).isEmpty)
    let lock = storage.file.deletingLastPathComponent()
        .appendingPathComponent(GenerationTelemetrySpool.lockName)
    var lockMetadata = stat()
    #expect(Darwin.lstat(lock.path, &lockMetadata) == 0)
    #expect(lockMetadata.st_mode & S_IFMT == S_IFREG)
    #expect(lockMetadata.st_mode & 0o777 == 0o600)
    #expect(lockMetadata.st_nlink == 1)
}

@Test func telemetryClearRejectsPoisonedAdvisoryLockNodes() throws {
    try withPerformanceSpool { applicationSupport, file in
        _ = try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        let lock = file.deletingLastPathComponent()
            .appendingPathComponent(GenerationTelemetrySpool.lockName)
        let outside = applicationSupport.deletingLastPathComponent().appendingPathComponent("lock-outside")
        try Data("LOCK_OUTSIDE_CANARY".utf8).write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)

        try FileManager.default.removeItem(at: lock)
        try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: outside)
        #expect(throws: GenerationTelemetrySpoolError.unsafeStorage) {
            try GenerationTelemetrySpool.clear(applicationSupport: applicationSupport)
        }
        try FileManager.default.removeItem(at: lock)

        #expect(Darwin.link(outside.path, lock.path) == 0)
        #expect(throws: GenerationTelemetrySpoolError.unsafeStorage) {
            try GenerationTelemetrySpool.clear(applicationSupport: applicationSupport)
        }
        try FileManager.default.removeItem(at: lock)

        try Data().write(to: lock)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: lock.path)
        #expect(throws: GenerationTelemetrySpoolError.unsafeStorage) {
            try GenerationTelemetrySpool.clear(applicationSupport: applicationSupport)
        }
        #expect(try String(contentsOf: outside, encoding: .utf8) == "LOCK_OUTSIDE_CANARY")
    }
}

@Test @MainActor func performanceHistoryClearCoordinatorIsPendingDuplicateSafeAndReportsBothOutcomes() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let gate = PerformanceClearTestGate()
    var successOutcome: PerformanceHistoryClearOutcome?
    let success = PerformanceHistoryClearCoordinator(
        applicationSupport: URL(fileURLWithPath: "/private/tmp/Local Harness", isDirectory: true),
        storageClear: { _ in
            gate.startAndWaitForRelease()
        }
    )

    #expect(success.clear { successOutcome = $0 })
    #expect(success.state == .clearing)
    #expect(!success.clear { _ in Issue.record("duplicate clear unexpectedly completed") })
    for _ in 0..<200 where !gate.hasStarted {
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(gate.hasStarted)
    #expect(success.state == .clearing)
    gate.release()
    for _ in 0..<200 where successOutcome == nil {
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(successOutcome == .success)
    #expect(success.state == .idle)

    struct ExpectedFailure: LocalizedError {
        var errorDescription: String? {
            "secret-token=must-not-surface /Users/private/Performance/telemetry.json"
        }
    }
    var failureOutcome: PerformanceHistoryClearOutcome?
    let failure = PerformanceHistoryClearCoordinator(
        applicationSupport: URL(fileURLWithPath: "/private/tmp/Local Harness", isDirectory: true),
        storageClear: { _ in throw ExpectedFailure() }
    )
    #expect(failure.clear { failureOutcome = $0 })
    for _ in 0..<200 where failureOutcome == nil {
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(failureOutcome == .failure)
    #expect(failure.state == .idle)
}

@Test func persistedTelemetryRejectsPublicStorageDirectoriesAndRandomParserInput() throws {
    try withPerformanceSpool { applicationSupport, file in
        let directory = file.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        #expect(throws: GenerationTelemetrySpoolError.unsafeStorage) {
            try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        }

        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        _ = try GenerationTelemetrySpool.prepare(applicationSupport: applicationSupport)
        for length in 1...128 {
            let bytes = Data((0..<length).map { UInt8(($0 * 31 + length * 17) & 0xff) })
            try bytes.write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            #expect(GenerationTelemetrySpool.read(applicationSupport: applicationSupport).isEmpty)
        }
    }
}

@Test func ollamaInspectorIsExplicitLoopbackOnlyAndNormalizesSnapshots() async throws {
    let tags = Data(#"{"models":[{"name":"qwen3:27b","size":18000000000},{"name":" qwen3:27b ","size":19000000000},{"name":"","size":4}]}"#.utf8)
    let running = Data(#"{"models":[{"name":"qwen3:27b","size":19000000000,"size_vram":17500000000,"context_length":32768},{"name":"bad-size","size":-2,"size_vram":-3,"context_length":-4}]}"#.utf8)
    let transport = StubLoopbackTransport(replies: [
        "/api/tags": .init(status: 200, data: tags),
        "/api/ps": .init(status: 200, data: running)
    ])
    let executable = URL(fileURLWithPath: "/opt/homebrew/bin/ollama")
    let inspector = try OllamaRuntimeInspector(
        endpoint: URL(string: "http://127.0.0.1:49152")!,
        transport: transport,
        locator: StubOllamaLocator(url: executable)
    )
    #expect(await transport.paths.isEmpty)

    let date = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let snapshot = await inspector.capture(at: date)

    #expect(snapshot.capturedAt == date)
    #expect(snapshot.availability == .online)
    #expect(snapshot.executablePath == executable.path)
    #expect(snapshot.issue == nil)
    #expect(snapshot.installedModels == [.init(name: "qwen3:27b", sizeBytes: 18_000_000_000)])
    #expect(snapshot.runningModels == [
        .init(name: "bad-size", sizeBytes: 0, sizeVRAMBytes: 0, contextLength: 0),
        .init(name: "qwen3:27b", sizeBytes: 19_000_000_000, sizeVRAMBytes: 17_500_000_000, contextLength: 32_768)
    ])
    #expect(await transport.paths == ["/api/tags", "/api/ps"])

    #expect(throws: OllamaRuntimeInspectorError.endpointMustBeLoopbackHTTP) {
        _ = try OllamaRuntimeInspector(
            endpoint: URL(string: "https://ollama.example.test:11434")!,
            transport: transport,
            locator: StubOllamaLocator(url: nil)
        )
    }
    #expect(throws: OllamaRuntimeInspectorError.endpointMustBeLoopbackHTTP) {
        _ = try OllamaRuntimeInspector(
            endpoint: URL(string: "http://user:secret@127.0.0.1:11434")!,
            transport: transport,
            locator: StubOllamaLocator(url: nil)
        )
    }
    #expect(throws: OllamaRuntimeInspectorError.endpointMustBeLoopbackHTTP) {
        _ = try OllamaRuntimeInspector(
            endpoint: URL(string: "http://127.0.0.1:11434/proxy?target=remote")!,
            transport: transport,
            locator: StubOllamaLocator(url: nil)
        )
    }
}

@Test func ollamaInspectorFailsSafelyWithoutLeakingTransportErrors() async throws {
    let transport = StubLoopbackTransport(replies: [
        "/api/tags": .init(status: 200, data: Data("not-json secret-response-body".utf8)),
        "/api/ps": .init(status: 503, data: Data("provider secret".utf8))
    ])
    let inspector = try OllamaRuntimeInspector(
        endpoint: URL(string: "http://127.0.0.1:49152")!,
        transport: transport,
        locator: StubOllamaLocator(url: URL(fileURLWithPath: "/mock/ollama"))
    )

    let snapshot = await inspector.capture(at: Date(timeIntervalSinceReferenceDate: 700_000_000))

    #expect(snapshot.availability == .installedOffline)
    #expect(snapshot.issue == .malformedPayload)
    #expect(snapshot.installedModels.isEmpty)
    #expect(snapshot.runningModels.isEmpty)
    let encoded = String(decoding: try JSONEncoder().encode(snapshot), as: UTF8.self)
    #expect(!encoded.contains("secret-response-body"))
    #expect(!encoded.contains("provider secret"))
}

@Test func ollamaInspectorDistinguishesAnUntrustedInstallFromAnAbsentOne() async throws {
    let transport = StubLoopbackTransport(replies: [:])
    let inspector = try OllamaRuntimeInspector(
        endpoint: URL(string: "http://127.0.0.1:49152")!,
        transport: transport,
        locator: StubOllamaLocator(url: nil, issue: .untrustedInstallation)
    )

    let snapshot = await inspector.capture(at: Date(timeIntervalSinceReferenceDate: 700_000_000))
    #expect(snapshot.availability == .untrusted)
    #expect(snapshot.issue == .untrustedInstallation)
    #expect(snapshot.executablePath == nil)
}

@Test func adaptiveRecommendationUses48GBHardwareWorkloadAndHealth() {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let host = makeHost(now: now)
    let ollama = OllamaRuntimeSnapshot(
        capturedAt: now,
        availability: .online,
        executablePath: "/mock/ollama",
        installedModels: [.init(name: "qwen3:27b", sizeBytes: 19_000_000_000)],
        runningModels: [],
        issue: nil
    )

    let everyday = AdaptivePerformanceRecommender.recommend(
        host: host,
        ollama: ollama,
        recentTelemetry: [],
        workload: .general
    )
    #expect(everyday.recommendedProfile == PerformanceProfile.balanced)
    #expect(everyday.assessments.map(\.profile) == [.fast, .balanced, .deep])
    #expect(everyday.assessments.filter(\.isRecommended).count == 1)
    #expect(everyday.reasons.contains { $0.contains("48 GB") })

    let longContext = AdaptivePerformanceRecommender.recommend(
        host: host,
        ollama: ollama,
        recentTelemetry: [],
        workload: .longContext
    )
    #expect(longContext.recommendedProfile == PerformanceProfile.deep)

    let lowPower = HostPerformanceSnapshot(
        capturedAt: now,
        physicalMemoryBytes: host.physicalMemoryBytes,
        thermalCondition: .nominal,
        lowPowerModeEnabled: true,
        processorArchitecture: .appleSilicon,
        logicalProcessorCount: 14,
        activeProcessorCount: 14
    )
    let constrained = AdaptivePerformanceRecommender.recommend(
        host: lowPower,
        ollama: ollama,
        recentTelemetry: [],
        workload: .longContext
    )
    #expect(constrained.recommendedProfile == PerformanceProfile.fast)
    #expect(constrained.reasons.first?.contains("Low Power Mode") == true)

    let warm = HostPerformanceSnapshot(
        capturedAt: now,
        physicalMemoryBytes: host.physicalMemoryBytes,
        thermalCondition: .fair,
        lowPowerModeEnabled: false,
        processorArchitecture: .appleSilicon,
        logicalProcessorCount: 14,
        activeProcessorCount: 14
    )
    let warmRecommendation = AdaptivePerformanceRecommender.recommend(
        host: warm,
        ollama: ollama,
        recentTelemetry: [],
        workload: .general
    )
    #expect(warmRecommendation.recommendedProfile == PerformanceProfile.fast)
    #expect(warmRecommendation.reasons.first?.contains("warm") == true)
}

@Test func adaptiveRecommendationRespondsToTelemetryAndModelMemoryPressure() {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let host = makeHost(now: now)
    let records = (0..<4).map { index in
        GenerationTelemetryRecord(
            id: UUID(),
            route: nil,
            startedAt: now.addingTimeInterval(Double(-40 + index)),
            completedAt: now.addingTimeInterval(Double(-30 + index)),
            timeToFirstTokenSeconds: 25,
            elapsedSeconds: 30,
            outputTokens: 10,
            outputTokenCountSource: .providerReported,
            outputTokensPerSecond: 4,
            outcome: .completed,
            failureCategory: nil
        )
    }
    let loaded = OllamaRuntimeSnapshot(
        capturedAt: now,
        availability: .online,
        executablePath: "/mock/ollama",
        installedModels: [],
        runningModels: [
            .init(name: "one", sizeBytes: 18_000_000_000, sizeVRAMBytes: 18_000_000_000, contextLength: 32_768),
            .init(name: "two", sizeBytes: 12_000_000_000, sizeVRAMBytes: 12_000_000_000, contextLength: 16_384)
        ],
        issue: nil
    )

    let recommendation = AdaptivePerformanceRecommender.recommend(
        host: host,
        ollama: loaded,
        recentTelemetry: records,
        workload: .longContext
    )

    #expect(recommendation.recommendedProfile == PerformanceProfile.fast)
    #expect(recommendation.reasons.contains { $0.contains("Loaded local models") })
    #expect(recommendation.reasons.contains { $0.contains("Recent local generations are slow") })
}

@Test func cloudTelemetryDoesNotDistortLocalPerformanceAdvice() {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let host = makeHost(now: now)
    let ollama = OllamaRuntimeSnapshot(
        capturedAt: now,
        availability: .online,
        executablePath: "/mock/ollama",
        installedModels: [],
        runningModels: [],
        issue: nil
    )
    let cloudRecords = (0..<4).map { index in
        GenerationTelemetryRecord(
            id: UUID(),
            route: ModelRoute(provider: ProviderID("deepseek-official"), model: ModelID("deepseek-chat")),
            startedAt: now.addingTimeInterval(Double(-50 + index)),
            completedAt: now.addingTimeInterval(Double(-40 + index)),
            timeToFirstTokenSeconds: 60,
            elapsedSeconds: 90,
            outputTokens: 3,
            outputTokenCountSource: .providerReported,
            outputTokensPerSecond: 0.1,
            outcome: .failed,
            failureCategory: .providerUnavailable
        )
    }

    let recommendation = AdaptivePerformanceRecommender.recommend(
        host: host,
        ollama: ollama,
        recentTelemetry: cloudRecords,
        workload: .longContext
    )

    #expect(recommendation.recommendedProfile == PerformanceProfile.deep)
    #expect(!recommendation.reasons.contains { $0.contains("recent generations failed") })
}

@Test func performanceGuidanceIsRouteAwareAcrossCloudCompatibilityAndHardwareTiers() {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let ollama = OllamaRuntimeSnapshot.unavailable(at: now)
    let cloudProviders = [
        BuiltInProviderDescriptors.deepSeekOfficial.id,
        BuiltInProviderDescriptors.openAI.id,
        BuiltInProviderDescriptors.anthropic.id,
        ProviderID("custom-openai-compatible")
    ]

    for provider in cloudProviders {
        for hostGiB in [8, 16, 24, 32, 48, 64, 96] {
            let recommendation = AdaptivePerformanceRecommender.recommend(
                host: makeHost(now: now, memoryGiB: UInt64(hostGiB)),
                ollama: ollama,
                recentTelemetry: [],
                selection: ModelSelection(
                    route: ModelRoute(provider: provider, model: ModelID("fixture-model"))
                )
            )
            #expect(recommendation.recommendedProfile == nil)
            #expect(recommendation.assessments.isEmpty)
            #expect(recommendation.reasons == [
                "Cloud and network-provider requests keep their provider-defined limits and are not changed by this Mac's memory, power, or thermal state."
            ])
        }
    }

    let compatibility = ModelSelection(
        route: ModelRoute(
            provider: BuiltInProviderDescriptors.ollama.id,
            model: ModelID("small-tools-model")
        )
    )
    for hostGiB in [8, 16, 24, 32, 48, 64, 96] {
        let recommendation = AdaptivePerformanceRecommender.recommend(
            host: makeHost(now: now, memoryGiB: UInt64(hostGiB)),
            ollama: ollama,
            recentTelemetry: [],
            selection: compatibility
        )
        #expect(recommendation.recommendedProfile == PerformanceProfile.compatibility)
        #expect(recommendation.assessments.map { $0.profile } == [PerformanceProfile.compatibility])
        #expect(recommendation.assessments.first?.settings == ModelPerformanceSettings.compatibilityLocalModel)
    }

    for hostGiB in [8, 16, 24, 32] {
        let recommendation = AdaptivePerformanceRecommender.recommend(
            host: makeHost(now: now, memoryGiB: UInt64(hostGiB)),
            ollama: ollama,
            recentTelemetry: [],
            selection: .defaultLocal
        )
        #expect(recommendation.recommendedProfile == nil)
        #expect(recommendation.assessments.isEmpty)
        #expect(recommendation.reasons.first?.contains("at least 48 GB") == true)
    }
    for hostGiB in [48, 64, 96] {
        let recommendation = AdaptivePerformanceRecommender.recommend(
            host: makeHost(now: now, memoryGiB: UInt64(hostGiB)),
            ollama: ollama,
            recentTelemetry: [],
            selection: .defaultLocal
        )
        #expect(recommendation.recommendedProfile == PerformanceProfile.balanced)
        #expect(recommendation.assessments.map { $0.profile } == [
            PerformanceProfile.fast, .balanced, .deep
        ])
    }
}

@Test func unavailableRouteNeverReceivesLocalProfileAdvice() {
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let recommendation = AdaptivePerformanceRecommender.recommend(
        host: makeHost(now: now),
        ollama: .unavailable(at: now),
        recentTelemetry: [],
        selection: nil
    )

    #expect(recommendation.recommendedProfile == nil)
    #expect(recommendation.assessments.isEmpty)
    #expect(recommendation.reasons.first?.contains("could not be verified") == true)
}

@Test @MainActor func performanceCenterWindowRendersAndUpdatesOnlySuppliedSnapshots() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let now = Date(timeIntervalSinceReferenceDate: 700_000_000)
    let host = makeHost(now: now)
    let ollama = OllamaRuntimeSnapshot.unavailable(at: now)
    let recommendation = AdaptivePerformanceRecommender.recommend(
        host: host,
        ollama: ollama,
        recentTelemetry: [],
        workload: .general
    )
    let firstSnapshot = PerformanceCenterSnapshot(
        capturedAt: now,
        host: host,
        ollama: ollama,
        recommendation: recommendation,
        telemetry: []
    )

    let controller = PerformanceCenterWindowController(snapshot: firstSnapshot)
    let firstContent = try #require(controller.window?.contentViewController)
    #expect(controller.window?.title == "Performance Center")
    #expect(controller.window?.isVisible == false)

    let firstScroll = try #require(performanceScrollView(in: controller.window?.contentView))
    controller.window?.contentView?.layoutSubtreeIfNeeded()
    let requestedOrigin = NSPoint(x: 0, y: 120)
    let expectedOrigin = firstScroll.contentView.constrainBoundsRect(
        NSRect(origin: requestedOrigin, size: firstScroll.contentView.bounds.size)
    ).origin
    firstScroll.contentView.setBoundsOrigin(expectedOrigin)
    firstScroll.reflectScrolledClipView(firstScroll.contentView)

    controller.setHistoryClearPending(true)
    #expect(controller.historyClearPending)
    let pendingButton = try #require(performanceButtons(in: controller.window?.contentView).first {
        $0.title == "Clearing…"
    })
    #expect(!pendingButton.isEnabled)
    #expect(controller.window?.makeFirstResponder(pendingButton) == true)

    let secondSnapshot = PerformanceCenterSnapshot(
        capturedAt: now.addingTimeInterval(1),
        host: host,
        ollama: ollama,
        recommendation: recommendation,
        telemetry: []
    )
    controller.update(snapshot: secondSnapshot)
    #expect(controller.window?.contentViewController !== firstContent)
    #expect(controller.window?.isVisible == false)
    let updatedScroll = try #require(performanceScrollView(in: controller.window?.contentView))
    #expect(abs(updatedScroll.contentView.bounds.origin.y - expectedOrigin.y) < 0.5)
    #expect((controller.window?.firstResponder as? NSView)?.identifier == pendingButton.identifier)
    #expect(performanceButtons(in: controller.window?.contentView).contains {
        $0.title == "Clearing…" && !$0.isEnabled
    })

    controller.setHistoryClearPending(false)
    #expect(!controller.historyClearPending)
    #expect(performanceButtons(in: controller.window?.contentView).contains {
        $0.title == "Clear Performance History" && $0.isEnabled
    })
}

private func performanceButtons(in view: NSView?) -> [NSButton] {
    guard let view else { return [] }
    return (view as? NSButton).map { [$0] } ?? view.subviews.flatMap { performanceButtons(in: $0) }
}

private func performanceScrollView(in view: NSView?) -> NSScrollView? {
    guard let view else { return nil }
    if let scroll = view as? NSScrollView { return scroll }
    return view.subviews.lazy.compactMap { performanceScrollView(in: $0) }.first
}

private func makeHost(now: Date, memoryGiB: UInt64 = 48) -> HostPerformanceSnapshot {
    HostPerformanceSnapshot(
        capturedAt: now,
        physicalMemoryBytes: memoryGiB * 1_073_741_824,
        thermalCondition: .nominal,
        lowPowerModeEnabled: false,
        processorArchitecture: .appleSilicon,
        logicalProcessorCount: 14,
        activeProcessorCount: 14
    )
}
