import Darwin
import Foundation

/// Candidate-only release gate entered before AppKit starts. It exercises the
/// same official executable attestation, private model-store validation,
/// Seatbelt profile, random loopback reservation, and PID/listener checks as
/// the product, then performs one tiny real generation. Generated text is
/// validated in memory and never emitted into qualification evidence.
enum AppOwnedOllamaGenerationCanary {
    static let argument = "--qualify-app-owned-ollama-generation"
    static let marker = "LOCAL_HARNESS_APP_OWNED_QWEN_OK"

    private enum Failure: String, Error {
        case invalidArguments = "invalid-arguments"
        case unsafeSupportDirectory = "unsafe-support-directory"
        case launchBoundary = "launch-boundary"
        case readinessTimeout = "readiness-timeout"
        case versionIncompatible = "ollama-version-incompatible"
        case modelUnavailable = "model-unavailable"
        case modelIdentityMismatch = "model-identity-mismatch"
        case generationFailed = "generation-failed"
        case gpuNotUsed = "gpu-not-used"
        case ownershipChanged = "ownership-changed"
    }

    private final class ResponseBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Result<BoundedOllamaHTTPResponse, Error>?

        func store(_ result: Result<BoundedOllamaHTTPResponse, Error>) {
            lock.lock(); value = result; lock.unlock()
        }

        func take() -> Result<BoundedOllamaHTTPResponse, Error>? {
            lock.lock(); defer { lock.unlock() }
            return value
        }
    }

    static func isRequested(in arguments: [String] = CommandLine.arguments) -> Bool {
        arguments.dropFirst().first == argument
    }

    static func run(arguments: [String] = CommandLine.arguments) -> Int32 {
        do {
            guard arguments.count == 4,
                  arguments[1] == argument,
                  arguments[2] == BuiltInProviderDescriptors.qwenLocalModel.id.rawValue,
                  OllamaModelNamePolicy.isSafe(arguments[2]) else {
                throw Failure.invalidArguments
            }
            let model = arguments[2]
            let support = URL(fileURLWithPath: arguments[3], isDirectory: true)
            try validateSupportDirectory(support)
            let ollamaVersion = try qualify(model: model, applicationSupport: support)
            let evidence: [String: Any] = [
                "schema": "local-harness-app-owned-ollama-generation-v1",
                "model": model,
                "manifestDigest": BuiltInProviderDescriptors.qwenLocalModelManifestDigest,
                "ollamaVersion": ollamaVersion.rawValue,
                "officialSignature": true,
                "randomLoopbackEndpoint": true,
                "seatbeltIsolated": true,
                "realGeneration": true,
                "gpuResident": true,
                "generatedTextRetained": false
            ]
            let data = try JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys])
            FileHandle.standardOutput.write(data + Data([0x0A]))
            return 0
        } catch let failure as Failure {
            writeFailure(failure.rawValue)
            return 1
        } catch {
            writeFailure(Failure.launchBoundary.rawValue)
            return 1
        }
    }

    private static func validateSupportDirectory(_ url: URL) throws {
        guard supportDirectoryIsSafe(url) else {
            throw Failure.unsafeSupportDirectory
        }
    }

    /// Foundation canonicalizes `/private/tmp` to `/tmp` on macOS even though
    /// `realpath(3)` reports the same directory as `/private/tmp`. Validate the
    /// trusted root and final component independently so that the expected
    /// system alias is accepted without admitting an arbitrary parent symlink
    /// or a symlink in place of the private test directory itself.
    static func supportDirectoryIsSafe(_ url: URL) -> Bool {
        let standardized = url.standardizedFileURL
        let parent = standardized.deletingLastPathComponent().path
        let leaf = standardized.lastPathComponent
        guard (parent == "/tmp" || parent == "/private/tmp"),
              leaf.hasPrefix("local-harness-ollama-generation."),
              let resolved = standardized.path.withCString({ Darwin.realpath($0, nil) }) else {
            return false
        }
        defer { free(resolved) }
        let resolvedPath = String(cString: resolved)
        guard (resolvedPath as NSString).deletingLastPathComponent == "/private/tmp",
              (resolvedPath as NSString).lastPathComponent == leaf else {
            return false
        }
        var metadata = stat()
        guard Darwin.lstat(standardized.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o777 == 0o700 else {
            return false
        }
        return true
    }

    private static func qualify(
        model: String,
        applicationSupport: URL
    ) throws -> OllamaStableVersion {
        let reservation = try LoopbackPortReservation.reserve()
        let selection = ModelSelection(
            route: ModelSelection.defaultLocal.route,
            performanceProfile: .fast
        )
        guard let modelConfiguration = AppOwnedOllamaModelConfiguration(selection: selection) else {
            throw Failure.invalidArguments
        }
        let plan = try AppOwnedOllamaLaunchPlan.prepare(
            applicationSupport: applicationSupport,
            endpoint: reservation.endpoint,
            modelConfiguration: modelConfiguration
        )
        let process = Process()
        process.executableURL = plan.processExecutable
        process.arguments = plan.arguments
        process.currentDirectoryURL = plan.currentDirectory
        process.environment = plan.environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try OllamaExecutableTrust.revalidate(plan.identity)
        reservation.releaseForLaunch()
        do { try process.run() } catch { throw Failure.launchBoundary }
        defer { stopExact(process, endpoint: plan.endpoint) }

        let ollamaVersion = try awaitCatalog(
            model: model,
            process: process,
            plan: plan,
            timeout: 90
        )
        try requireOwnedBoundary(process: process, plan: plan)

        let generationBody: [String: Any] = [
            "model": model,
            "prompt": "Reply with exactly \(marker) and nothing else.",
            "stream": false,
            "think": false,
            "keep_alive": 60,
            "options": [
                "temperature": 0,
                "num_ctx": 2_048,
                "num_predict": 32,
                "seed": 7
            ]
        ]
        let generation = try post(
            endpoint: plan.endpoint,
            path: "api/generate",
            body: generationBody,
            maximumBytes: 1 * 1_024 * 1_024,
            timeout: 60
        )
        try requireOwnedBoundary(process: process, plan: plan)
        guard generation.response.statusCode == 200,
              let object = try? JSONSerialization.jsonObject(with: generation.data) as? [String: Any],
              object["done"] as? Bool == true,
              object["model"] as? String == model,
              let text = object["response"] as? String,
              text.utf8.count <= 4_096,
              text.trimmingCharacters(in: .whitespacesAndNewlines).contains(marker),
              let evaluationCount = (object["eval_count"] as? NSNumber)?.intValue,
              evaluationCount > 0 else {
            throw Failure.generationFailed
        }

        var psRequest = URLRequest(url: plan.endpoint.baseURL.appendingPathComponent("api/ps"))
        psRequest.httpMethod = "GET"
        psRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        guard let running = perform(psRequest, maximumBytes: 1 * 1_024 * 1_024, timeout: 5),
              case .success(let runningResponse) = running,
              runningResponse.response.statusCode == 200,
              let runningObject = try? JSONSerialization.jsonObject(with: runningResponse.data) as? [String: Any],
              let models = runningObject["models"] as? [[String: Any]],
              models.contains(where: { entry in
                  let name = (entry["name"] as? String) ?? (entry["model"] as? String)
                  let gpuBytes = (entry["size_vram"] as? NSNumber)?.int64Value ?? 0
                  return name == model && gpuBytes > 0
              }) else {
            throw Failure.gpuNotUsed
        }
        try requireOwnedBoundary(process: process, plan: plan)

        _ = try? post(
            endpoint: plan.endpoint,
            path: "api/generate",
            body: ["model": model, "prompt": "", "stream": false, "keep_alive": 0],
            maximumBytes: 1 * 1_024 * 1_024,
            timeout: 10
        )
        return ollamaVersion
    }

    private static func awaitCatalog(
        model: String,
        process: Process,
        plan: AppOwnedOllamaLaunchPlan,
        timeout: TimeInterval
    ) throws -> OllamaStableVersion {
        let deadline = DispatchTime.now().uptimeNanoseconds
            &+ UInt64(timeout * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            guard process.isRunning else { throw Failure.launchBoundary }
            let signed = OllamaExecutableTrust.process(process.processIdentifier, matches: plan.identity)
            let ownsListener = OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: plan.endpoint)
            if ownsListener && !signed { throw Failure.ownershipChanged }
            if signed && ownsListener {
                var versionRequest = URLRequest(url: plan.endpoint.versionURL)
                versionRequest.httpMethod = "GET"
                versionRequest.setValue("application/json", forHTTPHeaderField: "Accept")
                guard let versionResult = perform(
                    versionRequest,
                    maximumBytes: OllamaVersionCompatibilityPolicy.maximumResponseBytes,
                    timeout: 3
                ), case .success(let versionResponse) = versionResult,
                   versionResponse.response.statusCode == 200 else {
                    usleep(200_000)
                    continue
                }
                try requireOwnedBoundary(process: process, plan: plan)
                let ollamaVersion: OllamaStableVersion
                do {
                    ollamaVersion = try OllamaVersionCompatibilityPolicy.parseResponse(
                        versionResponse.data
                    )
                } catch {
                    throw Failure.versionIncompatible
                }

                var request = URLRequest(url: plan.endpoint.tagsURL)
                request.httpMethod = "GET"
                request.setValue("application/json", forHTTPHeaderField: "Accept")
                if let result = perform(request, maximumBytes: 5 * 1_024 * 1_024, timeout: 3),
                   case .success(let response) = result,
                   response.response.statusCode == 200,
                   let object = try? JSONSerialization.jsonObject(with: response.data) as? [String: Any],
                   let models = object["models"] as? [[String: Any]] {
                    try requireOwnedBoundary(process: process, plan: plan)
                    let matches = models.filter {
                        (($0["name"] as? String) ?? ($0["model"] as? String)) == model
                    }
                    guard matches.count == 1 else { throw Failure.modelUnavailable }
                    guard matches[0]["digest"] as? String
                        == BuiltInProviderDescriptors.qwenLocalModelManifestDigest else {
                        throw Failure.modelIdentityMismatch
                    }
                    return ollamaVersion
                }
            }
            usleep(200_000)
        }
        throw Failure.readinessTimeout
    }

    private static func requireOwnedBoundary(process: Process, plan: AppOwnedOllamaLaunchPlan) throws {
        guard process.isRunning,
              OllamaExecutableTrust.process(process.processIdentifier, matches: plan.identity),
              OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: plan.endpoint) else {
            throw Failure.ownershipChanged
        }
    }

    private static func post(
        endpoint: AppOwnedOllamaEndpoint,
        path: String,
        body: [String: Any],
        maximumBytes: Int,
        timeout: TimeInterval
    ) throws -> BoundedOllamaHTTPResponse {
        let data = try JSONSerialization.data(withJSONObject: body)
        guard data.count <= 64 * 1_024 else { throw Failure.generationFailed }
        var request = URLRequest(url: endpoint.baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = data
        guard let result = perform(request, maximumBytes: maximumBytes, timeout: timeout),
              case .success(let response) = result else {
            throw Failure.generationFailed
        }
        return response
    }

    private static func perform(
        _ request: URLRequest,
        maximumBytes: Int,
        timeout: TimeInterval
    ) -> Result<BoundedOllamaHTTPResponse, Error>? {
        let box = ResponseBox()
        let semaphore = DispatchSemaphore(value: 0)
        let task = BoundedOllamaHTTPTask(
            request: request,
            maximumBytes: maximumBytes,
            timeout: timeout
        ) { result in
            box.store(result)
            semaphore.signal()
        }
        task.start()
        guard semaphore.wait(timeout: .now() + min(max(timeout, 0.25), 60) + 2) == .success else {
            return nil
        }
        withExtendedLifetime(task) {}
        return box.take()
    }

    private static func stopExact(_ process: Process, endpoint: AppOwnedOllamaEndpoint) {
        if process.isRunning { process.terminate() }
        let graceful = DispatchTime.now().uptimeNanoseconds &+ 2_000_000_000
        while process.isRunning, DispatchTime.now().uptimeNanoseconds < graceful { usleep(20_000) }
        if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
        // Foundation's blocking process wait polls the current thread's run loop and can
        // wait forever after an async executor hop even when the exact child is
        // already gone. Reap this PID directly under a hard bound; ECHILD means
        // Foundation won the benign reaping race.
        let reapDeadline = DispatchTime.now().uptimeNanoseconds &+ 2_000_000_000
        var status: Int32 = 0
        while DispatchTime.now().uptimeNanoseconds < reapDeadline {
            let waited = Darwin.waitpid(process.processIdentifier, &status, WNOHANG)
            if waited == process.processIdentifier || (waited < 0 && errno == ECHILD) { break }
            if waited < 0, errno != EINTR { break }
            Darwin.usleep(20_000)
        }
        let listenerDeadline = DispatchTime.now().uptimeNanoseconds &+ 2_000_000_000
        while OwnedLoopbackListenerVerifier.process(process.processIdentifier, owns: endpoint),
              DispatchTime.now().uptimeNanoseconds < listenerDeadline { usleep(20_000) }
    }

    private static func writeFailure(_ category: String) {
        FileHandle.standardError.write(
            Data("\(ProductBrand.displayName) app-owned generation qualification failed: \(category)\n".utf8)
        )
    }
}
