import Foundation
import Security
import Darwin

struct HarnessEndpoint: Equatable {
    static let serviceIdentifier = "app.localharness.runtime"
    static let protocolVersion = 1

    let baseURL: URL
    let token: String
    let nonce: String
    let processIdentifier: Int32

    var healthURL: URL { baseURL.appendingPathComponent("_local_harness/health") }
    var bootstrapURL: URL { baseURL.appendingPathComponent("_local_harness/bootstrap") }

    func authenticatedRequest(to url: URL? = nil) -> URLRequest {
        var request = URLRequest(url: url ?? baseURL)
        request.setValue(token, forHTTPHeaderField: "X-Local-Harness-Token")
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return request
    }
}

struct RuntimeHealth: Decodable, Equatable {
    let service: String
    let protocolVersion: Int
    let nonce: String
    let pid: Int32
}

enum SecureTokenGenerator {
    static func generate(byteCount: Int = 32) throws -> String {
        precondition(byteCount >= 16)
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw RuntimeSecurityError.randomGenerationFailed(status) }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

enum RuntimeSecurityError: LocalizedError {
    case randomGenerationFailed(OSStatus)
    case securityPreloaderMissing
    case runtimeAuthenticationInputFailed

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed(let status):
            return "Secure random generation failed with status \(status)."
        case .securityPreloaderMissing:
            return "The authenticated runtime component is missing or damaged. Reinstall \(ProductBrand.displayName)."
        case .runtimeAuthenticationInputFailed:
            return "The private runtime authentication channel could not be prepared safely."
        }
    }
}

/// Owns the one-shot authentication record passed to the leased DSH runtime as
/// standard input. The backing object is a 0600 regular file that is unlinked
/// before this initializer returns, so it has no pathname to discover, race,
/// reopen, or retain. FD_CLOEXEC prevents unrelated app children from
/// inheriting the parent's copy; Foundation explicitly duplicates it onto the
/// intended runtime's stdin during `Process.run()`.
final class RuntimeAuthenticationInput: @unchecked Sendable {
    static let version = "FULMAR_RUNTIME_AUTH_V1"
    static let maximumFrameBytes = 384

    private let lock = NSLock()
    private var handle: FileHandle?

    init(
        authToken: String,
        nonce: String,
        beforeWriteForTesting: ((String) -> Void)? = nil
    ) throws {
        var frame = try Self.frame(authToken: authToken, nonce: nonce)
        defer {
            let byteCount = frame.count
            frame.resetBytes(in: 0..<byteCount)
        }
        var template = Array("/private/tmp/fulmar-runtime-auth.XXXXXX".utf8CString)
        let descriptor = Darwin.mkstemp(&template)
        guard descriptor >= 0 else { throw RuntimeSecurityError.runtimeAuthenticationInputFailed }
        let path = String(cString: template)
        var completed = false
        defer {
            if !completed {
                _ = Darwin.close(descriptor)
                _ = Darwin.unlink(path)
            }
        }

        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0,
              Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              Darwin.unlink(path) == 0 else {
            throw RuntimeSecurityError.runtimeAuthenticationInputFailed
        }
        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_nlink == 0,
              before.st_uid == Darwin.geteuid(),
              before.st_mode & 0o777 == 0o600,
              before.st_size == 0 else {
            throw RuntimeSecurityError.runtimeAuthenticationInputFailed
        }
        // The test hook is deliberately after unlink + fstat and before the
        // first write. Production never receives a pathname for this record;
        // qualification can deterministically prove the transient name is
        // already ENOENT before authentication bytes enter the descriptor.
        beforeWriteForTesting?(path)

        let wroteAllBytes = frame.withUnsafeBytes { storage -> Bool in
            guard let baseAddress = storage.baseAddress else { return false }
            var written = 0
            while written < storage.count {
                let count = Darwin.pwrite(
                    descriptor,
                    baseAddress.advanced(by: written),
                    storage.count - written,
                    off_t(written)
                )
                if count > 0 { written += count; continue }
                if count < 0 && errno == EINTR { continue }
                return false
            }
            return true
        }
        guard wroteAllBytes,
              Darwin.fsync(descriptor) == 0,
              Darwin.lseek(descriptor, 0, SEEK_CUR) == 0 else {
            throw RuntimeSecurityError.runtimeAuthenticationInputFailed
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              after.st_dev == before.st_dev,
              after.st_ino == before.st_ino,
              after.st_mode & S_IFMT == S_IFREG,
              after.st_nlink == 0,
              after.st_uid == before.st_uid,
              after.st_mode & 0o777 == 0o600,
              after.st_size == off_t(frame.count) else {
            throw RuntimeSecurityError.runtimeAuthenticationInputFailed
        }

        handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        completed = true
    }

    static func frame(authToken: String, nonce: String) throws -> Data {
        guard validMaterial(authToken), validMaterial(nonce) else {
            throw RuntimeSecurityError.runtimeAuthenticationInputFailed
        }
        let bytes = Data("\(version):\(authToken):\(nonce)\n".utf8)
        guard bytes.count <= maximumFrameBytes else {
            throw RuntimeSecurityError.runtimeAuthenticationInputFailed
        }
        return bytes
    }

    private static func validMaterial(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (22...128).contains(bytes.count) else { return false }
        return bytes.allSatisfy { byte in
            (48...57).contains(byte) || (65...90).contains(byte)
                || (97...122).contains(byte) || byte == 45 || byte == 95
        }
    }

    /// Transfers ownership exactly once. The caller closes its copy
    /// immediately after `Process.run()` has duplicated it into the child.
    func takeForLaunch() throws -> FileHandle {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw RuntimeSecurityError.runtimeAuthenticationInputFailed }
        self.handle = nil
        return handle
    }

    func close() {
        lock.lock()
        let retained = handle
        handle = nil
        lock.unlock()
        try? retained?.close()
    }

    deinit { close() }
}

enum ChildProcessEnvironment {
    static func make(
        nodeBin: String?,
        allowSSHAgent: Bool = false,
        homeDirectory: URL? = nil,
        temporaryDirectory: URL? = nil,
        additions: [String: String] = [:]
    ) -> [String: String] {
        let inherited = ProcessInfo.processInfo.environment
        var paths = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"]
        if let nodeBin, !nodeBin.isEmpty { paths.insert(nodeBin, at: 0) }

        var environment: [String: String] = [
            "HOME": (homeDirectory ?? FileManager.default.homeDirectoryForCurrentUser).path,
            "USER": NSUserName(),
            "LOGNAME": NSUserName(),
            "PATH": paths.joined(separator: ":"),
            "TMPDIR": (temporaryDirectory ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)).path,
            "LANG": inherited["LANG"] ?? "en_US.UTF-8",
            "LC_CTYPE": inherited["LC_CTYPE"] ?? "UTF-8",
            "DSH_TELEMETRY_MODE": "DISABLED"
        ]
        for key in ["SHELL"] {
            if let value = inherited[key], !value.isEmpty { environment[key] = value }
        }
        if allowSSHAgent, let socket = inherited["SSH_AUTH_SOCK"], !socket.isEmpty { environment["SSH_AUTH_SOCK"] = socket }
        additions.forEach { environment[$0.key] = $0.value }
        return environment
    }
}

enum HarnessProcessEnvironment {
    // Ollama's OpenAI-compatible local endpoint accepts any bearer value. DSH uses
    // the presence of this named reference to decide whether the local provider is
    // usable, so this marker is intentionally non-secret and never reaches a cloud.
    static let localOllamaCredential = "local-ollama"

    /// A single exact on-device route whose adapter-owned context capacity was
    /// synchronized before the app exposes a session. The DSH plugin resolves
    /// this route again at every real agent request and fails closed on drift.
    static func contextEnforcementJSON(
        route: ModelRoute,
        performanceSettings: ModelPerformanceSettings
    ) -> String {
        struct Enforcement: Encodable {
            let provider: String
            let model: String
            let contextWindowTokens: Int
        }
        let value = Enforcement(
            provider: route.provider.rawValue,
            model: route.model.rawValue,
            contextWindowTokens: performanceSettings.contextWindowTokens
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try! encoder.encode(value), as: UTF8.self)
    }

    static func additions(
        credentialPlugin: String,
        credentialHome: String = FileManager.default.homeDirectoryForCurrentUser.path,
        mcpPlugin: String,
        clientSecurityPlugin: String,
        performancePlugin: String,
        credentialHelper: String,
        sandboxHelper: String,
        strictLocal: Bool,
        localOllamaAvailable: Bool = false,
        performanceProfile: PerformanceProfile = .balanced,
        performanceSettings: ModelPerformanceSettings? = nil,
        activeProvider: ProviderID? = nil,
        contextEnforcementRoute: ModelRoute? = nil,
        providerOriginsJSON: String = "[]",
        runtimeRoot: String? = nil,
        workspaceRootsJSON: String = "[]",
        readOnlyRootsJSON: String = "[]",
        sandboxTempPath: String? = nil,
        confinedFilesystemPlugin: String? = nil,
        mcpCatalogPath: String? = nil,
        applicationSupportRoot: String? = nil,
        performanceTelemetryFile: String? = nil,
        thermalWorkloadPolicyFile: String? = nil,
        forbidCredentialHelper: Bool = false
    ) -> [String: String] {
        let performance = performanceSettings ?? performanceProfile.settingsFor48GBAppleSilicon
        var result = [
            "LOCAL_HARNESS_CREDENTIAL_PLUGIN": credentialPlugin,
            // DSH itself keeps a private HOME. The reviewed native credential
            // helper alone receives this login-home boundary so macOS resolves
            // the user's normal Keychain instead of an empty private search
            // list. The runtime preloader captures and removes this value
            // before model-facing code starts.
            "LOCAL_HARNESS_CREDENTIAL_HOME": credentialHome,
            "LOCAL_HARNESS_MCP_PLUGIN": mcpPlugin,
            "LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN": clientSecurityPlugin,
            "LOCAL_HARNESS_PERFORMANCE_PLUGIN": performancePlugin,
            "LOCAL_HARNESS_CREDENTIAL_HELPER": credentialHelper,
            "LOCAL_HARNESS_SANDBOX_HELPER": sandboxHelper,
            "LOCAL_HARNESS_STRICT_LOCAL": strictLocal ? "1" : "0",
            "LOCAL_HARNESS_PROVIDER_ORIGINS": providerOriginsJSON,
            "LOCAL_HARNESS_WORKSPACE_ROOTS": workspaceRootsJSON,
            "LOCAL_HARNESS_READONLY_ROOTS": readOnlyRootsJSON,
            "LOCAL_HARNESS_PERFORMANCE_PROFILE": performanceProfile.rawValue,
            "LOCAL_HARNESS_PERFORMANCE_PROFILES": PerformanceProfile.runtimeCatalogJSON,
            "LOCAL_HARNESS_CONTEXT_WINDOW_TOKENS": String(performance.contextWindowTokens),
            "LOCAL_HARNESS_MAX_OUTPUT_TOKENS": String(performance.maxOutputTokens),
            "LOCAL_HARNESS_KEEP_ALIVE_SECONDS": String(performance.keepAliveSeconds),
            // Keep the reviewed internal-loader native addon at its signed,
            // bundled path. Its optional temp-cache copy is intentionally not
            // admitted by the native-module integrity guard.
            "NARB_DISABLE_NATIVE_CACHE": "1"
        ]
        // DSH treats credential presence as provider readiness. Install this
        // fixed non-secret marker only after the native supervisor has proved
        // the exact owned Ollama PID/listener. Cloud and provider-recovery
        // runtimes must never make the dormant Ollama profile appear usable.
        if localOllamaAvailable { result["OLLAMA_API_KEY"] = localOllamaCredential }
        // Release qualification can prove that the exact on-device route never
        // consults macOS Keychain. The credentials plugin captures and removes
        // this marker before model-facing code starts, and rejects before
        // spawning the native helper if any unexpected credential path is used.
        if forbidCredentialHelper {
            result["LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER"] = "1"
        }
        if let activeProvider {
            result["LOCAL_HARNESS_ACTIVE_PROVIDER"] = activeProvider.rawValue
        }
        if let runtimeRoot, !runtimeRoot.isEmpty { result["LOCAL_HARNESS_RUNTIME_ROOT"] = runtimeRoot }
        if let sandboxTempPath, !sandboxTempPath.isEmpty { result["LOCAL_HARNESS_SANDBOX_TEMP"] = sandboxTempPath }
        if let confinedFilesystemPlugin, !confinedFilesystemPlugin.isEmpty { result["LOCAL_HARNESS_FS_PLUGIN"] = confinedFilesystemPlugin }
        if let mcpCatalogPath, !mcpCatalogPath.isEmpty { result["LOCAL_HARNESS_MCP_CATALOG"] = mcpCatalogPath }
        let hasPerformanceTelemetry = performanceTelemetryFile?.isEmpty == false
        let hasThermalPolicy = thermalWorkloadPolicyFile?.isEmpty == false
        if let applicationSupportRoot, !applicationSupportRoot.isEmpty,
           hasPerformanceTelemetry || hasThermalPolicy {
            result["LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT"] = applicationSupportRoot
        }
        if let performanceTelemetryFile, !performanceTelemetryFile.isEmpty,
           result["LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT"] != nil {
            result["LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE"] = performanceTelemetryFile
            result["LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER"] = credentialHelper
        }
        if let thermalWorkloadPolicyFile, !thermalWorkloadPolicyFile.isEmpty,
           result["LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT"] != nil {
            result["LOCAL_HARNESS_THERMAL_POLICY_FILE"] = thermalWorkloadPolicyFile
        }
        if let contextEnforcementRoute {
            precondition(activeProvider == contextEnforcementRoute.provider)
            result["LOCAL_HARNESS_CONTEXT_ENFORCEMENT"] = contextEnforcementJSON(
                route: contextEnforcementRoute,
                performanceSettings: performance
            )
        }
        return result
    }
}
