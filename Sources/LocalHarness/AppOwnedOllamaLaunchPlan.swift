import Darwin
import Foundation

enum OllamaRuntimeOptimizationQualification: Equatable, Sendable {
    case releaseQualifiedQwen
    case compatibilityModel
}

struct AppOwnedOllamaModelConfiguration: Equatable, Sendable {
    let performance: ModelPerformanceSettings
    let optimizationQualification: OllamaRuntimeOptimizationQualification

    init?(selection: ModelSelection) {
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else { return nil }
        performance = selection.effectivePerformanceSettings
        optimizationQualification = selection.isReleaseQualifiedLocalQwen
            ? .releaseQualifiedQwen
            : .compatibilityModel
    }

    /// Used only to inspect the Ollama catalog while the selected inference
    /// route is external. No model-specific optimization may be inferred.
    static let catalogueInspection = AppOwnedOllamaModelConfiguration(
        performance: .compatibilityLocalModel,
        optimizationQualification: .compatibilityModel
    )

    private init(
        performance: ModelPerformanceSettings,
        optimizationQualification: OllamaRuntimeOptimizationQualification
    ) {
        self.performance = performance
        self.optimizationQualification = optimizationQualification
    }
}

struct AppOwnedOllamaLaunchPlan: Sendable {
    static let sandboxExecutable = URL(fileURLWithPath: "/usr/bin/sandbox-exec")

    let identity: OllamaExecutableIdentity
    let sandbox: AppOwnedOllamaSandbox
    let endpoint: AppOwnedOllamaEndpoint
    let processExecutable: URL
    let arguments: [String]
    let environment: [String: String]
    let currentDirectory: URL
    let modelConfiguration: AppOwnedOllamaModelConfiguration

    static func prepare(
        applicationSupport: URL,
        endpoint: AppOwnedOllamaEndpoint,
        modelConfiguration: AppOwnedOllamaModelConfiguration,
        modelStoreDirectory: URL? = nil,
        modelStoreLimits: AppOwnedOllamaSandbox.ModelStoreValidationLimits = .production,
        cancellationCheck: @escaping () throws -> Void = {},
        now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) throws -> AppOwnedOllamaLaunchPlan {
        try cancellationCheck()
        try validateSandboxExecutable()
        try cancellationCheck()
        let identity = try OllamaExecutableTrust.resolve()
        try cancellationCheck()
        try OllamaExecutableTrust.revalidate(identity)
        try cancellationCheck()
        let sandbox = try AppOwnedOllamaSandbox.prepare(
            applicationSupport: applicationSupport,
            modelStoreDirectory: modelStoreDirectory,
            modelStoreLimits: modelStoreLimits,
            cancellationCheck: cancellationCheck,
            now: now
        )
        try cancellationCheck()
        var environment = ChildProcessEnvironment.make(
            nodeBin: nil,
            homeDirectory: sandbox.homeDirectory,
            temporaryDirectory: sandbox.temporaryDirectory,
            additions: environmentAdditions(
                endpoint: endpoint,
                modelStore: sandbox.modelStore,
                modelConfiguration: modelConfiguration
            )
        )
        environment.removeValue(forKey: "SHELL")
        return AppOwnedOllamaLaunchPlan(
            identity: identity,
            sandbox: sandbox,
            endpoint: endpoint,
            processExecutable: sandboxExecutable,
            arguments: ["-p", sandbox.profile, identity.executableURL.path, "serve"],
            environment: environment,
            currentDirectory: sandbox.runtimeRoot,
            modelConfiguration: modelConfiguration
        )
    }

    /// Builds only the explicitly reviewed Ollama variables. Flash Attention
    /// and q8 KV cache are release claims for the exact immutable Qwen route;
    /// a community Compatibility model must inherit neither merely because it
    /// uses the same provider process.
    static func environmentAdditions(
        endpoint: AppOwnedOllamaEndpoint,
        modelStore: URL,
        modelConfiguration: AppOwnedOllamaModelConfiguration
    ) -> [String: String] {
        let performance = modelConfiguration.performance
        var additions = [
            "OLLAMA_HOST": "\(AppOwnedOllamaEndpoint.host):\(endpoint.port)",
            "OLLAMA_MODELS": modelStore.path,
            "OLLAMA_NO_CLOUD": "1",
            "OLLAMA_NOHISTORY": "1",
            "OLLAMA_NOPRUNE": "1",
            "OLLAMA_DEBUG_LOG_REQUESTS": "0",
            "OLLAMA_ORIGINS": "http://127.0.0.1",
            "OLLAMA_MAX_LOADED_MODELS": "1",
            "OLLAMA_NUM_PARALLEL": String(performance.maxConcurrentGenerations),
            "OLLAMA_MAX_QUEUE": "32",
            "OLLAMA_CONTEXT_LENGTH": String(performance.contextWindowTokens),
            "OLLAMA_KEEP_ALIVE": String(performance.keepAliveSeconds)
        ]
        if modelConfiguration.optimizationQualification == .releaseQualifiedQwen {
            additions["OLLAMA_FLASH_ATTENTION"] = "1"
            additions["OLLAMA_KV_CACHE_TYPE"] = "q8_0"
        }
        return additions
    }

    private static func validateSandboxExecutable() throws {
        var metadata = stat()
        guard Darwin.lstat(sandboxExecutable.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == 0,
              metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0 else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }
    }
}
